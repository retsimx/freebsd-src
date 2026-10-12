/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * Hibernate image decoder and interval iterator.
 *
 * hibernate_image_decode() accepts an immutable image-relative metadata
 * prefix [0, payload_start) and performs fully checked ABI 1 structural
 * validation.  It is allocation-free, performs no I/O, reads no kernel
 * globals, and executes no CPUID or XGETBV.  The result is identical
 * in the kernel and offline tool for identical bytes.
 *
 * hibernate_image_interval_next() lazily walks the decoded image,
 * returning strictly increasing non-overlapping image-relative intervals
 * covering [0, image_length) exactly once.
 */

#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * Narrow portability seam: substitute kernel-only headers with
 * userland equivalents.  No layout or validation policy here.
 * sys/param.h, sys/types.h, sys/endian.h, sys/elf64.h, and
 * sys/elf_common.h are all safe in userland; only sys/systm.h
 * is kernel-only and is omitted.  bool/size_t/errno come from
 * the standard headers pulled in by hibernate_compat.h (via
 * -include in the Makefile).
 */
#include <sys/param.h>
#include <sys/elf64.h>
#include <sys/elf_common.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/hibernate.h>
#else
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/_maxphys.h>
#include <sys/callout.h>
#include <sys/conf.h>
#include <sys/elf64.h>
#include <sys/elf_common.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/hibernate.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

#include <machine/atomic.h>
#include <machine/hibernate.h>

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt.h>
#include <cam/cam_xpt_sim.h>
#include <cam/cam_queue.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#endif /* _HIBERNATE_USERLAND_BUILD */

/* ELF magic bytes. */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

/*
 * ELF header field byte offsets.  We load all fields explicitly with
 * le16dec/le32dec/le64dec rather than casting the buffer to a struct.
 */
#define EHDR_OFF_EI_MAG0     0
#define EHDR_OFF_EI_MAG1     1
#define EHDR_OFF_EI_MAG2     2
#define EHDR_OFF_EI_MAG3     3
#define EHDR_OFF_EI_CLASS    4
#define EHDR_OFF_EI_DATA     5
#define EHDR_OFF_EI_VERSION  6
#define EHDR_OFF_E_TYPE	     16
#define EHDR_OFF_E_MACHINE   18
#define EHDR_OFF_E_VERSION   20
#define EHDR_OFF_E_PHOFF     32
#define EHDR_OFF_E_EHSIZE    52
#define EHDR_OFF_E_PHENTSIZE 54
#define EHDR_OFF_E_PHNUM     56

/* ELF program header field byte offsets within each 56-byte entry. */
#define PHDR_OFF_P_TYPE	  0
#define PHDR_OFF_P_OFFSET 8
#define PHDR_OFF_P_FILESZ 32
#define PHDR_OFF_P_MEMSZ  40
#define PHDR_OFF_P_PADDR  24

#define EHDR_SIZE	  64
#define PHDR_SIZE	  56

/* HIB_PAGE_SIZE (4096) is defined in sys/sys/hibernate.h. */

/*
 * align_up_checked: compute align_up(v, align) into *out.
 * align must be a power of two.  Returns EOVERFLOW on overflow.
 */
static int
align_up_checked(uint64_t v, uint64_t align, uint64_t *out)
{
	uint64_t mask, result;

	mask = align - 1;
	if (__builtin_add_overflow(v, mask, &result))
		return (EOVERFLOW);
	result &= ~mask;
	*out = result;
	return (0);
}

/*
 * is_all_zero: return true iff every byte in buf[0..len) is zero.
 */
static bool
is_all_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i] != 0)
			return (false);
	}
	return (true);
}

/*
 * Validate an attempt's marker-sector binding and callback requirements.
 * mediasize is the byte length of the provider extent beginning at
 * mediaoffset.
 *
 * The caller must own the attempt-bound dumper's admission regime and keep it
 * closed against competing image and marker writers for the complete
 * read-modify-write sequence through its flush.  Dump execution owns the
 * operation through dumping; hibernation additionally marks
 * hibernate_writing.  K-3 adds no lock (design sections 3.3 and 11.7).
 *
 * No invariant assertion is safe here: legitimate restore and completion
 * callers can hold admission closed without both global flags being set.
 */
static int
hibernate_marker_binding(struct hibernate_attempt *ha, bool need_read,
    bool need_write, struct dumperinfo **dip, off_t *offsetp)
{
	struct dumperinfo *di;
	off_t media_end, marker_end, offset;

	if (ha == NULL || ha->ha_dumper == NULL)
		return (EINVAL);
	di = ha->ha_dumper;
	if ((need_read && di->dumper_read == NULL) ||
	    (need_write && di->dumper == NULL))
		return (EOPNOTSUPP);
	if (di->blocksize != DEV_BSIZE)
		return (EINVAL);
	if (di->mediaoffset < 0 || di->mediasize <= 0)
		return (EINVAL);
	if (__builtin_add_overflow(di->mediaoffset, di->mediasize, &media_end))
		return (EOVERFLOW);

	offset = ha->ha_marker_offset;
	if (offset < di->mediaoffset || offset % DEV_BSIZE != 0)
		return (EINVAL);
	if (__builtin_add_overflow(offset, (off_t)DEV_BSIZE, &marker_end))
		return (EOVERFLOW);
	if (marker_end > media_end)
		return (EINVAL);

	*dip = di;
	*offsetp = offset;
	return (0);
}

static int
hibernate_marker_image_valid(const struct dumperinfo *di,
    const struct hibernate_marker *m)
{
	uint64_t image_end, media_end, mediaoffset;

	if (di->mediaoffset < 0 || di->mediasize <= 0)
		return (EINVAL);
	mediaoffset = (uint64_t)di->mediaoffset;
	if (__builtin_add_overflow(mediaoffset, (uint64_t)di->mediasize,
		&media_end))
		return (EOVERFLOW);
	if (m->hm_image_length == 0 ||
	    __builtin_add_overflow(m->hm_image_offset, m->hm_image_length,
		&image_end))
		return (EINVAL);
	if (m->hm_image_offset < mediaoffset || image_end > media_end)
		return (EINVAL);
	return (0);
}

static int
hibernate_marker_decode(const struct dumperinfo *di, const uint8_t *buf,
    struct hibernate_marker *out)
{
	struct hibernate_marker m;
	uint32_t reserved;
	int error;

	m.hm_magic = le64dec(buf + HIBERNATE_MARKER_OFF_MAGIC);
	m.hm_version = le32dec(buf + HIBERNATE_MARKER_OFF_VERSION);
	m.hm_state = le32dec(buf + HIBERNATE_MARKER_OFF_STATE);
	m.hm_image_offset = le64dec(buf + HIBERNATE_MARKER_OFF_IMAGE_OFFSET);
	m.hm_image_length = le64dec(buf + HIBERNATE_MARKER_OFF_IMAGE_LENGTH);
	m.hm_crc32c = le32dec(buf + HIBERNATE_MARKER_OFF_CRC32C);
	reserved = le32dec(buf + HIBERNATE_MARKER_OFF_RESERVED_024);

	if (m.hm_magic == 0) {
		if (m.hm_version != 0 || m.hm_state != 0 ||
		    m.hm_image_offset != 0 || m.hm_image_length != 0 ||
		    m.hm_crc32c != 0 || reserved != 0)
			return (EINVAL);
		*out = m;
		return (0);
	}
	if (m.hm_version != HIBERNATE_MARKER_VERSION || reserved != 0)
		return (EINVAL);
	switch (m.hm_state) {
	case HIBERNATE_MARKER_STATE_PENDING:
	case HIBERNATE_MARKER_STATE_CONSUMING:
	case HIBERNATE_MARKER_STATE_CONSUMED:
		break;
	default:
		return (EINVAL);
	}
	error = hibernate_marker_image_valid(di, &m);
	if (error != 0)
		return (error);
	*out = m;
	return (0);
}

static void
hibernate_marker_encode(uint8_t *buf, const struct hibernate_marker *m)
{
	le64enc(buf + HIBERNATE_MARKER_OFF_MAGIC, m->hm_magic);
	le32enc(buf + HIBERNATE_MARKER_OFF_VERSION, m->hm_version);
	le32enc(buf + HIBERNATE_MARKER_OFF_STATE, m->hm_state);
	le64enc(buf + HIBERNATE_MARKER_OFF_IMAGE_OFFSET, m->hm_image_offset);
	le64enc(buf + HIBERNATE_MARKER_OFF_IMAGE_LENGTH, m->hm_image_length);
	le32enc(buf + HIBERNATE_MARKER_OFF_CRC32C, m->hm_crc32c);
	le32enc(buf + HIBERNATE_MARKER_OFF_RESERVED_024, 0);
}

static bool
hibernate_marker_immutable_equal(const struct hibernate_marker *a,
    const struct hibernate_marker *b)
{
	return (a->hm_magic == b->hm_magic && a->hm_version == b->hm_version &&
	    a->hm_image_offset == b->hm_image_offset &&
	    a->hm_image_length == b->hm_image_length &&
	    a->hm_crc32c == b->hm_crc32c);
}

int
hibernate_marker_read(struct hibernate_attempt *ha,
    struct hibernate_marker *out)
{
	struct hibernate_marker m;
	struct dumperinfo *di;
	uint8_t sector[DEV_BSIZE];
	off_t offset;
	int error;

	if (out == NULL)
		return (EINVAL);
	error = hibernate_marker_binding(ha, true, false, &di, &offset);
	if (error != 0)
		return (error);
	error = di->dumper_read(di->priv, sector, offset, sizeof(sector));
	if (error != 0)
		return (error);
	error = hibernate_marker_decode(di, sector, &m);
	if (error != 0)
		return (error);
	*out = m;
	return (0);
}

int
hibernate_marker_write(struct hibernate_attempt *ha,
    const struct hibernate_marker *m)
{
	struct hibernate_marker current;
	struct dumperinfo *di;
	uint8_t sector[DEV_BSIZE];
	uint64_t image_offset;
	off_t offset;
	int error;

	if (m == NULL)
		return (EINVAL);
	error = hibernate_marker_binding(ha, true, true, &di, &offset);
	if (error != 0)
		return (error);

	switch (m->hm_state) {
	case HIBERNATE_MARKER_STATE_PENDING:
		if (m->hm_magic == 0 ||
		    m->hm_version != HIBERNATE_MARKER_VERSION)
			return (EINVAL);
		if (__builtin_add_overflow((uint64_t)di->mediaoffset,
			HIBERNATE_METADATA_SIZE, &image_offset))
			return (EOVERFLOW);
		if (m->hm_image_offset != image_offset)
			return (EINVAL);
		error = hibernate_marker_image_valid(di, m);
		if (error != 0)
			return (error);
		break;
	case HIBERNATE_MARKER_STATE_CONSUMING:
	case HIBERNATE_MARKER_STATE_CONSUMED:
		break;
	default:
		return (EINVAL);
	}

	error = di->dumper_read(di->priv, sector, offset, sizeof(sector));
	if (error != 0)
		return (error);

	if (m->hm_state == HIBERNATE_MARKER_STATE_PENDING) {
		hibernate_marker_encode(sector, m);
	} else {
		error = hibernate_marker_decode(di, sector, &current);
		if (error != 0)
			return (error);
		if (!hibernate_marker_immutable_equal(&current, m))
			return (EINVAL);
		if ((m->hm_state == HIBERNATE_MARKER_STATE_CONSUMING &&
			current.hm_state != HIBERNATE_MARKER_STATE_PENDING) ||
		    (m->hm_state == HIBERNATE_MARKER_STATE_CONSUMED &&
			current.hm_state != HIBERNATE_MARKER_STATE_CONSUMING))
			return (EINVAL);
		le32enc(sector + HIBERNATE_MARKER_OFF_STATE, m->hm_state);
	}

	return (di->dumper(di->priv, sector, offset, sizeof(sector)));
}

int
hibernate_marker_clear(struct hibernate_attempt *ha)
{
	struct dumperinfo *di;
	uint8_t sector[DEV_BSIZE];
	off_t offset;
	int error;

	error = hibernate_marker_binding(ha, true, true, &di, &offset);
	if (error != 0)
		return (error);
	error = di->dumper_read(di->priv, sector, offset, sizeof(sector));
	if (error != 0)
		return (error);
	__builtin_memset(sector, 0, HIBERNATE_MARKER_ENCODED_SIZE);
	return (di->dumper(di->priv, sector, offset, sizeof(sector)));
}

int
hibernate_marker_flush(struct hibernate_attempt *ha)
{
	struct dumperinfo *di;

	if (ha == NULL || ha->ha_dumper == NULL)
		return (EINVAL);
	di = ha->ha_dumper;
	if (di->dumper_flush == NULL)
		return (EOPNOTSUPP);
	return (di->dumper_flush(di));
}

void
hibernate_marker_decode_complete(const uint8_t *buf,
    struct hibernate_marker *marker, uint32_t *reserved)
{
	memset(marker, 0, sizeof(*marker));
	marker->hm_magic = le64dec(buf + HIBERNATE_MARKER_OFF_MAGIC);
	marker->hm_version = le32dec(buf + HIBERNATE_MARKER_OFF_VERSION);
	marker->hm_state = le32dec(buf + HIBERNATE_MARKER_OFF_STATE);
	marker->hm_image_offset = le64dec(
	    buf + HIBERNATE_MARKER_OFF_IMAGE_OFFSET);
	marker->hm_image_length = le64dec(
	    buf + HIBERNATE_MARKER_OFF_IMAGE_LENGTH);
	marker->hm_crc32c = le32dec(buf + HIBERNATE_MARKER_OFF_CRC32C);
	*reserved = le32dec(buf + HIBERNATE_MARKER_OFF_RESERVED_024);
}

enum hibernate_marker_class
hibernate_marker_classify(uint64_t marker_offset, uint64_t media_size,
    const struct hibernate_marker *marker, uint32_t reserved)
{
	uint64_t expected, image_end, media_end;

	if (marker->hm_magic == 0)
		return (HMC_ABSENT);
	if (marker->hm_magic != HIBERNATE_MARKER_MAGIC ||
	    marker->hm_version != HIBERNATE_MARKER_VERSION || reserved != 0)
		return (HMC_MALFORMED);
	if (media_size == 0 ||
	    __builtin_add_overflow(marker_offset, media_size, &media_end) ||
	    __builtin_add_overflow(marker_offset, HIBERNATE_METADATA_SIZE,
		&expected) ||
	    marker->hm_image_offset != expected ||
	    marker->hm_image_length == 0 ||
	    __builtin_add_overflow(marker->hm_image_offset,
		marker->hm_image_length, &image_end) ||
	    image_end > media_end)
		return (HMC_MALFORMED);

	switch (marker->hm_state) {
	case HIBERNATE_MARKER_STATE_PENDING:
		return (HMC_PENDING);
	case HIBERNATE_MARKER_STATE_CONSUMING:
		return (HMC_STALE_CONSUMING);
	case HIBERNATE_MARKER_STATE_CONSUMED:
		return (HMC_CONSUMED);
	default:
		return (HMC_MALFORMED);
	}
}

/*
 * Map a raw transfer outcome to a complete typed result.  This is shared so
 * the probe and userland tests use one authoritative path.
 */
int
hibernate_marker_result_from_transfer(int error, size_t transferred,
    const uint8_t *sector, uint64_t provider_offset, uint64_t provider_size,
    struct hibernate_marker_result *out)
{
	uint32_t reserved;

	memset(out, 0, sizeof(*out));
	if (error != 0 || transferred != DEV_BSIZE) {
		out->class = HMC_IO_ERROR;
		out->error = error != 0 ? error : EIO;
		return (out->error);
	}

	hibernate_marker_decode_complete(sector, &out->marker, &reserved);
	out->class = hibernate_marker_classify(provider_offset, provider_size,
	    &out->marker, reserved);
	return (0);
}

/*
 * hibernate_restore_footprint_compute: pure arithmetic core of footprint
 * derivation.  Takes destination_union_pages and an explicit wired_pages
 * argument (instead of calling vm_wire_count() directly) so that
 * host-runnable tests can exercise the production formula without kernel
 * dependencies (N7: exercise production derivation, not a copy).
 *
 * This function is compiled in both kernel and userland modes
 * (_HIBERNATE_USERLAND_BUILD) and contains no kernel-only calls.
 *
 * Components (all rounded up to whole pages):
 *   1. wired_pages (caller-supplied; kernel passes vm_wire_count()).
 *   2. Metadata prefix storage: HIB_METADATA_MAX_BYTES.
 *   3. Source-vector: destination_union_pages * 8 bytes.
 *   4. One maximum BIO/backend transfer buffer: HIB_MAXPHYS_BYTES.
 *   5. Arena-external MD workspace: HIB_SCRATCH_STACK_BYTES.
 *   6. Reservation-record bytes: destination_union_pages * record_size + 1 page.
 *   7. 25% fragmentation margin (checked ceiling division).
 *
 * Returns 0 with *derived_pages_out set on success, EOVERFLOW on
 * arithmetic overflow, or ENOMEM if the result exceeds HIB_FOOTPRINT_MAX.
 */
/*
 * hib_compute_pages_roundup: inline page-size roundup for use in the
 * userland-buildable compute function (avoids dependency on hib_pages_roundup
 * which is defined inside the #ifndef _HIBERNATE_USERLAND_BUILD block).
 * Returns EOVERFLOW when the rounded result would overflow uint64_t.
 */
static inline int
hib_compute_pages_roundup(uint64_t bytes, uint64_t *pages_out)
{
	uint64_t rounded;

	if (bytes == 0) {
		*pages_out = 0;
		return (0);
	}
	if (__builtin_add_overflow(bytes, HIB_PAGE_SIZE - 1, &rounded))
		return (EOVERFLOW);
	*pages_out = rounded / HIB_PAGE_SIZE;
	return (0);
}

int
hibernate_restore_footprint_compute(uint64_t destination_union_pages,
    uint64_t wired_pages, uint64_t *derived_pages_out)
{
	uint64_t total, pg, bytes, margin, margin_ceil;

	total = 0;

	/* 1. Wired kernel pages (caller-supplied; kernel passes vm_wire_count()). */
	if (__builtin_add_overflow(total, wired_pages, &total))
		return (EOVERFLOW);

	/* 2. Metadata prefix (at most HIB_METADATA_MAX_BYTES). */
	if (hib_compute_pages_roundup(HIB_METADATA_MAX_BYTES, &pg) != 0)
		return (EOVERFLOW);
	if (__builtin_add_overflow(total, pg, &total))
		return (EOVERFLOW);

	/* 3. Source-vector: destination_union_pages * 8 bytes, checked. */
	if (__builtin_mul_overflow(destination_union_pages, (uint64_t)8,
	    &bytes))
		return (EOVERFLOW);
	if (hib_compute_pages_roundup(bytes, &pg) != 0)
		return (EOVERFLOW);
	if (__builtin_add_overflow(total, pg, &total))
		return (EOVERFLOW);

	/*
	 * 4. One maximum BIO/backend transfer buffer.
	 * Use HIB_MAXPHYS_BYTES (defined in hibernate.h) to avoid
	 * depending on MAXPHYS (kernel-only via sys/_maxphys.h).
	 */
	if (hib_compute_pages_roundup(HIB_MAXPHYS_BYTES, &pg) != 0)
		return (EOVERFLOW);
	if (__builtin_add_overflow(total, pg, &total))
		return (EOVERFLOW);

	/*
	 * 5. Arena-external MD workspace.
	 * Use HIB_SCRATCH_STACK_BYTES (defined in hibernate.h) to avoid
	 * depending on HIBERNATE_SCRATCH_STACK_SIZE (machine-dependent).
	 */
	if (hib_compute_pages_roundup(HIB_SCRATCH_STACK_BYTES, &pg) != 0)
		return (EOVERFLOW);
	if (__builtin_add_overflow(total, pg, &total))
		return (EOVERFLOW);

	/*
	 * 6. Reservation-record bytes + allocation/alignment overhead.
	 * Record size: HIB_RESERVATION_RECORD_BYTES (16 bytes on amd64 LP64).
	 */
	if (__builtin_mul_overflow(destination_union_pages,
	    (uint64_t)HIB_RESERVATION_RECORD_BYTES, &bytes))
		return (EOVERFLOW);
	/* Add one page for alignment/allocation overhead. */
	if (__builtin_add_overflow(bytes, HIB_PAGE_SIZE, &bytes))
		return (EOVERFLOW);
	if (hib_compute_pages_roundup(bytes, &pg) != 0)
		return (EOVERFLOW);
	if (__builtin_add_overflow(total, pg, &total))
		return (EOVERFLOW);

	/*
	 * 7. 25% fragmentation margin: ceil(total * 25 / 100).
	 * Computed as checked ceiling division: (total * 25 + 99) / 100.
	 */
	if (__builtin_mul_overflow(total, HIB_FRAG_PCT, &margin))
		return (EOVERFLOW);
	if (__builtin_add_overflow(margin, HIB_FRAG_DIV - 1, &margin_ceil))
		return (EOVERFLOW);
	margin_ceil /= HIB_FRAG_DIV;
	if (__builtin_add_overflow(total, margin_ceil, &total))
		return (EOVERFLOW);

	if (total > HIB_FOOTPRINT_MAX)
		return (ENOMEM);

	*derived_pages_out = total;
	return (0);
}

#ifndef _HIBERNATE_USERLAND_BUILD

struct hibernate_provider_owner {
	struct hibernate_provider_id id;
	struct mtx lock;
	uint64_t extent_offset;
	uint64_t extent_length;
	volatile u_int published;
	volatile u_int active;
	bool extent_held;
};

static struct hibernate_provider_owner hibernate_owner;
MTX_SYSINIT(hibernate_owner, &hibernate_owner.lock, "hibernate owner", MTX_DEF);

static struct hibernate_config hibernate_config;
static volatile u_int hibernate_config_state;
static volatile u_int hibernate_probe_pending;

static bool
hibernate_provider_id_valid(const struct hibernate_provider_id *id)
{
	size_t length;

	if (id == NULL || id->media_size == 0)
		return (false);
	length = strnlen(id->name, sizeof(id->name));
	return (length != 0 && length < sizeof(id->name));
}

static bool
hibernate_provider_id_equal(const struct hibernate_provider_id *a,
    const struct hibernate_provider_id *b)
{
	return (a->media_size == b->media_size &&
	    memcmp(a->name, b->name, sizeof(a->name)) == 0);
}

int
hibernate_config_get(struct hibernate_config *config)
{
	char *dev, *resume, *wait;
	unsigned long value;
	bool resume_enabled;
	char *end;
	size_t length;
	int error;

	if (config == NULL)
		return (EINVAL);
	if (atomic_load_acq_int(&hibernate_config_state) == 0) {
		memset(&hibernate_config, 0, sizeof(hibernate_config));
		hibernate_config.hc_wait_ms = 15000;
		error = 0;
		resume_enabled = true;

		resume = kern_getenv("kern.hibernate.resume");
		if (resume != NULL) {
			if (strcmp(resume, "0") == 0)
				resume_enabled = false;
			else if (strcmp(resume, "1") != 0)
				error = EINVAL;
			freeenv(resume);
		}

		dev = kern_getenv("kern.hibernate.dev");
		if (dev != NULL) {
			length = strnlen(dev, SPECNAMELEN);
			if (length == 0) {
				hibernate_config.hc_enabled = false;
			} else if (length == SPECNAMELEN ||
			    strncmp(dev, "/dev/", 5) == 0 || dev[0] == ' ' ||
			    dev[length - 1] == ' ') {
				error = length == SPECNAMELEN ? ENAMETOOLONG :
								EINVAL;
			} else {
				memcpy(hibernate_config.hc_name, dev,
				    length + 1);
				hibernate_config.hc_enabled = resume_enabled;
			}
			freeenv(dev);
		}

		wait = kern_getenv("kern.hibernate.wait_ms");
		if (wait != NULL) {
			end = NULL;
			value = strtoul(wait, &end, 10);
			if (end == wait || *end != '\0' || value == 0 ||
			    value > UINT_MAX)
				error = EINVAL;
			else
				hibernate_config.hc_wait_ms = (unsigned int)
				    value;
			freeenv(wait);
		}
		if (error != 0) {
			hibernate_config.hc_enabled = true;
			hibernate_config.hc_wait_ms = 0;
		}
		atomic_store_rel_int(&hibernate_config_state,
		    error == 0 ? 1 : (u_int)error + 1);
	}
	error = atomic_load_acq_int(&hibernate_config_state);
	*config = hibernate_config;
	return (error == 1 ? 0 : error - 1);
}

int
hibernate_owner_publish(const struct hibernate_provider_id *id)
{
	if (!hibernate_provider_id_valid(id))
		return (EINVAL);
	mtx_lock(&hibernate_owner.lock);
	if (hibernate_owner.published != 0) {
		mtx_unlock(&hibernate_owner.lock);
		return (hibernate_provider_id_equal(&hibernate_owner.id, id) ?
			EALREADY :
			EBUSY);
	}
	hibernate_owner.id = *id;
	atomic_store_rel_int(&hibernate_owner.active, 1);
	atomic_store_rel_int(&hibernate_owner.published, 1);
	mtx_unlock(&hibernate_owner.lock);
	return (0);
}

void
hibernate_owner_deactivate(const struct hibernate_provider_id *id)
{
	if (!hibernate_provider_id_valid(id) ||
	    atomic_load_acq_int(&hibernate_owner.published) == 0)
		return;
	mtx_lock(&hibernate_owner.lock);
	if (hibernate_provider_id_equal(&hibernate_owner.id, id))
		atomic_store_rel_int(&hibernate_owner.active, 0);
	mtx_unlock(&hibernate_owner.lock);
}

void
hibernate_probe_begin(void)
{
	atomic_store_rel_int(&hibernate_probe_pending, 1);
}

void
hibernate_probe_complete(void)
{
	atomic_store_rel_int(&hibernate_probe_pending, 0);
}

bool
hibernate_probe_active(void)
{
	return (atomic_load_acq_int(&hibernate_probe_pending) != 0 ||
	    (atomic_load_acq_int(&hibernate_owner.published) != 0 &&
		atomic_load_acq_int(&hibernate_owner.active) != 0));
}

bool
hibernate_provider_conflicts(const struct hibernate_provider_id *id)
{
	if (!hibernate_provider_id_valid(id) ||
	    atomic_load_acq_int(&hibernate_owner.published) == 0 ||
	    atomic_load_acq_int(&hibernate_owner.active) == 0)
		return (false);
	return (hibernate_provider_id_equal(&hibernate_owner.id, id));
}

int
hibernate_extent_hold(const struct hibernate_provider_id *id, uint64_t offset,
    uint64_t length)
{
	uint64_t end;
	int error;

	if (!hibernate_provider_conflicts(id))
		return (ENOENT);
	if (length == 0)
		return (EINVAL);
	if (__builtin_add_overflow(offset, length, &end))
		return (EOVERFLOW);
	if (end > id->media_size)
		return (EINVAL);

	error = 0;
	mtx_lock(&hibernate_owner.lock);
	if (!hibernate_provider_id_equal(&hibernate_owner.id, id))
		error = ENOENT;
	else if (hibernate_owner.extent_held)
		error = EBUSY;
	else {
		hibernate_owner.extent_offset = offset;
		hibernate_owner.extent_length = length;
		hibernate_owner.extent_held = true;
	}
	mtx_unlock(&hibernate_owner.lock);
	return (error);
}

void
hibernate_extent_release(const struct hibernate_provider_id *id)
{
	bool match;

	if (!hibernate_provider_id_valid(id))
		return;
	mtx_lock(&hibernate_owner.lock);
	match = hibernate_provider_id_equal(&hibernate_owner.id, id) &&
	    hibernate_owner.extent_held;
	KASSERT(match, ("hibernate extent release mismatch"));
	if (match) {
		hibernate_owner.extent_held = false;
		hibernate_owner.extent_offset = 0;
		hibernate_owner.extent_length = 0;
		wakeup(&hibernate_owner);
	}
	mtx_unlock(&hibernate_owner.lock);
}

int
hibernate_dumper_lookup(const struct hibernate_provider_id *id,
    struct dumperinfo **dip)
{
	struct dumperinfo *di;
	int error;

	if (!hibernate_provider_id_valid(id) || dip == NULL)
		return (EINVAL);
	*dip = NULL;
	error = ENXIO;
	mtx_lock(&dumpconf_list_lk);
	TAILQ_FOREACH(di, &dumper_configs, di_next) {
		if (!di->provider_valid ||
		    di->provider_media_size != id->media_size ||
		    strncmp(di->provider_name, id->name,
			sizeof(di->provider_name)) != 0)
			continue;
		if (dumper_hold(di)) {
			*dip = di;
			error = 0;
		}
		break;
	}
	mtx_unlock(&dumpconf_list_lk);
	return (error);
}

struct hibernate_raw_marker {
	uint8_t sector[DEV_BSIZE];
	size_t transferred;
	int error;
};

static void
hibernate_marker_read_raw(struct hibernate_attempt *ha,
    struct hibernate_raw_marker *raw)
{
	struct dumperinfo *di;
	off_t offset;
	int error;

	memset(raw, 0, sizeof(*raw));
	error = hibernate_marker_binding(ha, true, false, &di, &offset);
	if (error != 0) {
		raw->error = error;
		return;
	}
	error = di->dumper_read(di->priv, raw->sector, offset,
	    sizeof(raw->sector));
	if (error != 0) {
		raw->error = error;
		return;
	}
	raw->transferred = sizeof(raw->sector);
	if (raw->transferred != sizeof(raw->sector))
		raw->error = EIO;
}

int
hibernate_probe(struct hibernate_attempt *ha)
{
	struct hibernate_raw_marker raw;
	int error;

	if (ha == NULL)
		return (EINVAL);

	if (ha->ha_dumper == NULL) {
		error = hibernate_marker_result_from_transfer(ENXIO, 0, NULL,
		    ha->ha_provider_offset, ha->ha_provider_size,
		    &ha->ha_marker_result);
		return (error);
	}
	hibernate_marker_read_raw(ha, &raw);
	error = hibernate_marker_result_from_transfer(raw.error,
	    raw.transferred, raw.sector, ha->ha_provider_offset,
	    ha->ha_provider_size, &ha->ha_marker_result);
	return (error);
}

/*
 * K-5 capacity check and restore-footprint derivation.
 *
 * hibernate_capacity_check() performs sequential checked subtraction of
 * arena, destination-union, and restore-footprint budget from physmem.
 * It returns 0 when eligible >= required (including equality), ENOMEM on
 * a valid shortfall, EOVERFLOW on arithmetic overflow, and EINVAL on
 * null pointers, zero required cardinalities, or impossible set sizes.
 * The result struct is zeroed before any validation so no failing return
 * leaks partial output.
 *
 * hibernate_page_is_destination() tests whether the physical address of
 * page m falls within the validated destination-interval view stored in
 * the current hibernate attempt.  It reads only attempt-owned, pre-
 * validated state; it does not reparse ELF headers or inspect page queues.
 *
 * hibernate_restore_footprint_derive() computes the checked minimum
 * restore-kernel footprint in pages from system constants.  It is called
 * once at the start of a save attempt before any freeze.
 *
 * kern.hibernate.restore_footprint_pages is a boot-time configured floor.
 * The effective budget is max(configured_floor, derived_minimum).
 * The default is 262144 pages (1 GiB at 4 KiB/page).
 * The maximum is 16777216 pages (64 GiB at 4 KiB/page).
 */

/* HIB_FOOTPRINT_*, HIB_METADATA_MAX_BYTES, HIB_FRAG_*, HIB_MAXPHYS_BYTES,
 * HIB_SCRATCH_STACK_BYTES, HIB_RESERVATION_RECORD_BYTES, HIB_PAGE_SIZE
 * are defined in sys/sys/hibernate.h for dual-build (kernel + userland). */

static SYSCTL_NODE(_kern, OID_AUTO, hibernate, CTLFLAG_RW | CTLFLAG_MPSAFE,
    0, "Hibernate parameters");

/*
 * Configured restore-footprint floor.  Read once at boot; protected by
 * CTLFLAG_RDTUN so it cannot be changed at runtime.
 */
static u_long hibernate_restore_footprint_pages = HIB_FOOTPRINT_DEFAULT;
SYSCTL_ULONG(_kern_hibernate, OID_AUTO, restore_footprint_pages,
    CTLFLAG_RDTUN, &hibernate_restore_footprint_pages, 0,
    "Restore-kernel footprint floor in pages (default 262144, max 16777216)");

/*
 * Derived footprint in pages, set by hibernate_restore_footprint_derive().
 * Exposed read-only for diagnostics.
 */
static u_long hibernate_restore_footprint_derived;
SYSCTL_ULONG(_kern_hibernate, OID_AUTO, restore_footprint_derived,
    CTLFLAG_RD, &hibernate_restore_footprint_derived, 0,
    "Derived minimum restore-kernel footprint in pages (computed at boot)");

/*
 * Effective footprint budget (max of configured floor and derived minimum).
 */
static u_long hibernate_restore_footprint_effective;
SYSCTL_ULONG(_kern_hibernate, OID_AUTO, restore_footprint_effective,
    CTLFLAG_RD, &hibernate_restore_footprint_effective, 0,
    "Effective restore-kernel footprint budget in pages");

/*
 * hib_pages_roundup: round byte count up to whole pages.
 * Returns EOVERFLOW when the result would overflow uint64_t.
 */
static int
hib_pages_roundup(uint64_t bytes, uint64_t *pages_out)
{
	uint64_t pg, rounded;

	if (bytes == 0) {
		*pages_out = 0;
		return (0);
	}
	/* Round up: (bytes + PAGE_SIZE - 1) / PAGE_SIZE */
	if (__builtin_add_overflow(bytes, (uint64_t)PAGE_SIZE - 1, &rounded))
		return (EOVERFLOW);
	pg = rounded / PAGE_SIZE;
	*pages_out = pg;
	return (0);
}

/*
 * hibernate_capacity_check: sequential checked subtraction capacity test.
 *
 * Inputs (all in pages):
 *   b->physmem_pages                  Total physical pages.
 *   b->arena_pages                    Transition-arena pages (disjoint).
 *   b->destination_union_pages        Union of all PT_LOAD destination pages.
 *   b->restore_kernel_footprint_budget Conservative restore footprint.
 *
 * Outputs (filled only on success):
 *   r->eligible_source_pages   Residual after arena + dst + footprint.
 *   r->required_source_pages   destination_union_pages (one copy needed).
 *   r->shortfall_pages         max(required - eligible, 0).
 *
 * Return codes:
 *   0         Sufficient (eligible >= required), including equality.
 *   EINVAL    Null pointer, zero required cardinality, or impossible sizes.
 *   EOVERFLOW Checked arithmetic failure.
 *   ENOMEM    Valid cardinalities but insufficient eligible sources.
 */
int
hibernate_capacity_check(const struct hibernate_capacity_budget *b,
    struct hibernate_capacity_result *r)
{
	uint64_t eligible;

	/*
	 * Zero the result struct unconditionally so no failing return
	 * leaks partial output.
	 */
	if (r != NULL)
		memset(r, 0, sizeof(*r));

	if (b == NULL || r == NULL)
		return (EINVAL);

	/* Required cardinalities must be non-zero. */
	if (b->physmem_pages == 0 || b->destination_union_pages == 0)
		return (EINVAL);

	/*
	 * Each individual set size must not exceed physmem; if any single
	 * deduction already exceeds physmem the sets cannot be pairwise
	 * disjoint.
	 */
	if (b->arena_pages > b->physmem_pages ||
	    b->destination_union_pages > b->physmem_pages)
		return (EINVAL);

	/*
	 * The restore footprint is a valid capacity requirement, not a PFN set
	 * whose standalone size must fit physmem for the input to be meaningful.
	 * A representable configured footprint larger than available physical
	 * memory is therefore an ordinary capacity shortage.  Populate the result
	 * consistently and return ENOMEM rather than classifying it as EINVAL.
	 */
	if (b->restore_kernel_footprint_budget > b->physmem_pages) {
		r->eligible_source_pages = 0;
		r->required_source_pages = b->destination_union_pages;
		r->shortfall_pages = b->destination_union_pages;
		return (ENOMEM);
	}

	/*
	 * Sequential checked subtraction.  Each step proves the deduction
	 * does not exceed the current residual; arena overflow is EINVAL
	 * (mathematically impossible disjoint set), destination and
	 * footprint overflow are ENOMEM (valid shortfall).
	 */
	eligible = b->physmem_pages;

	/* Deduct arena. */
	if (b->arena_pages > eligible)
		return (EINVAL);
	eligible -= b->arena_pages;

	/* Deduct destination union. */
	if (b->destination_union_pages > eligible) {
		r->required_source_pages = b->destination_union_pages;
		r->shortfall_pages = b->destination_union_pages - eligible;
		return (ENOMEM);
	}
	eligible -= b->destination_union_pages;

	/* Deduct restore-kernel footprint. */
	if (b->restore_kernel_footprint_budget > eligible) {
		/*
		 * The footprint itself consumes remaining space; no sources
		 * remain.  Eligible is now 0 after footprint deduction would
		 * underflow, so shortfall is required - 0 = required.
		 */
		r->eligible_source_pages = 0;
		r->required_source_pages = b->destination_union_pages;
		r->shortfall_pages = b->destination_union_pages;
		return (ENOMEM);
	}
	eligible -= b->restore_kernel_footprint_budget;

	r->eligible_source_pages = eligible;
	r->required_source_pages = b->destination_union_pages;

	if (eligible < b->destination_union_pages) {
		r->shortfall_pages = b->destination_union_pages - eligible;
		return (ENOMEM);
	}

	r->shortfall_pages = 0;
	return (0);
}

/*
 * hibernate_page_is_destination: test whether page m's physical address
 * falls within the validated destination-interval view of the current
 * hibernate attempt.
 *
 * The attempt pointer is obtained from the global hibernate_current_attempt,
 * set only while a save attempt is active.  If no attempt is active or the
 * destination view has not been published, the function returns false.
 *
 * ha_dst_intervals holds ha_dst_count sorted, strictly increasing
 * [start, end) physical-address pairs.  Membership is tested with a
 * linear scan; the interval count is bounded by PT_LOAD count.
 *
 * This function does not reparse ELF headers and does not inspect page
 * queues or page flags.
 */

/*
 * Hibernate coordinator mutex: serialises concurrent save attempts.
 * Acquired before setting HIB_STAGE_COORDINATOR; released during unwind.
 * MTX_DEF is sufficient — the lock is held only in thread context before
 * APs are stopped, never under a spin lock or with interrupts disabled.
 */
static struct mtx hibernate_coordinator_mtx;
MTX_SYSINIT(hibernate_coordinator, &hibernate_coordinator_mtx,
    "hibernate coordinator", MTX_DEF);

/* Pointer to the active hibernate attempt, set/cleared by the coordinator. */
static struct hibernate_attempt *hibernate_current_attempt;

/*
 * Footprint derivation/configuration status, set by hibernate_footprint_sysinit.
 * 0 = valid (hibernate_restore_footprint_effective is usable).
 * EOVERFLOW = arithmetic overflow during derivation.
 * ENOMEM    = derived minimum exceeded HIB_FOOTPRINT_MAX.
 * EINVAL    = configured floor was invalid (already corrected to default,
 *             but save attempts must still re-validate).
 */
static int hibernate_footprint_status;

bool
hibernate_page_is_destination(vm_page_t m)
{
	const struct hibernate_attempt *ha;
	vm_paddr_t pa;
	uint64_t i;

	ha = atomic_load_ptr(&hibernate_current_attempt);
	if (ha == NULL || !ha->ha_dst_valid ||
	    ha->ha_dst_intervals == NULL || ha->ha_dst_count == 0)
		return (false);

	pa = VM_PAGE_TO_PHYS(m);

	/*
	 * Linear scan over validated [start, end) pairs.
	 * Intervals are sorted and non-overlapping; we could binary-search
	 * but the count is small and linear scan is simpler and correct.
	 */
	for (i = 0; i < ha->ha_dst_count; i++) {
		vm_paddr_t start, end;

		start = ha->ha_dst_intervals[i * 2];
		end   = ha->ha_dst_intervals[i * 2 + 1];
		if (pa >= start && pa < end)
			return (true);
		/* Intervals are sorted; stop early if past pa. */
		if (start > pa)
			break;
	}
	return (false);
}

/*
 * hibernate_restore_footprint_derive: compute the checked minimum restore-
 * kernel footprint in pages from system constants.  Called once before any
 * hibernate freeze.
 *
 * Components (all rounded up to whole pages):
 *   1. Page-rounded fresh-kernel wired pages (vm_wire_count()).
 *   2. Metadata prefix storage (at most HIB_METADATA_MAX_BYTES).
 *   3. Source-vector bytes: destination_union_pages * 8, checked.
 *   4. One maximum BIO/backend transfer buffer (MAXPHYS bytes).
 *   5. Arena-external MD workspace (HIBERNATE_SCRATCH_STACK_SIZE bytes).
 *   6. Reservation-record bytes + allocation/alignment overhead.
 *   7. 25% fragmentation margin (checked ceiling division).
 *
 * Returns 0 on success and writes *derived_pages_out.
 * Returns EOVERFLOW on any arithmetic overflow.
 * Returns ENOMEM when the derived minimum exceeds HIB_FOOTPRINT_MAX.
 *
 * destination_union_pages is the number of destination pages the caller
 * has computed; it is used only for the source-vector size estimate.
 * Callers that do not yet know the exact count should pass a conservative
 * upper bound (e.g. physmem).
 */
int
hibernate_restore_footprint_derive(uint64_t destination_union_pages,
    uint64_t *derived_pages_out)
{
	/*
	 * N7: delegate to hibernate_restore_footprint_compute() so the
	 * pure arithmetic is testable from userland without vm_wire_count().
	 * The kernel wrapper supplies the live wired-page count.
	 */
	return (hibernate_restore_footprint_compute(destination_union_pages,
	    (uint64_t)vm_wire_count(), derived_pages_out));
}

/*
 * hibernate_footprint_sysinit: validate the configured floor and derive
 * the minimum footprint at boot, before any freeze.
 *
 * Reads hibernate_restore_footprint_pages (the RDTUN sysctl/tunable),
 * validates it, derives the minimum, and computes the effective budget.
 * Results are stored in the read-only diagnostic sysctls.
 *
 * Errors are recorded in hibernate_footprint_status and must be consumed
 * by the save path before the freeze via hibernate_footprint_check().
 */
static void
hibernate_footprint_sysinit(void *unused __unused)
{
	uint64_t derived, effective;
	u_long configured;
	int error;

	/*
	 * Fetch the tunable value (CTLFLAG_RDTUN copies it into the static
	 * at early boot; we read it directly).
	 */
	configured = hibernate_restore_footprint_pages;

	if (configured == 0 || configured > HIB_FOOTPRINT_MAX) {
		printf("hibernate: restore_footprint_pages %lu invalid "
		    "(range 1..%lu); using default %lu\n",
		    configured, HIB_FOOTPRINT_MAX, HIB_FOOTPRINT_DEFAULT);
		/*
		 * Record EINVAL so the save path can refuse; reset to the
		 * default so the effective value remains useful for diagnostics.
		 */
		hibernate_footprint_status = EINVAL;
		configured = HIB_FOOTPRINT_DEFAULT;
		hibernate_restore_footprint_pages = configured;
		/* Fall through to derive with the default so effective is set. */
	}

	/*
	 * Derive using physmem as a conservative upper bound for the
	 * destination_union_pages argument (worst case: all pages are
	 * destinations).
	 */
	error = hibernate_restore_footprint_derive((uint64_t)physmem,
	    &derived);
	if (error == EOVERFLOW) {
		printf("hibernate: footprint derivation overflow; "
		    "save attempts will be refused\n");
		hibernate_footprint_status = EOVERFLOW;
		hibernate_restore_footprint_derived = 0;
		hibernate_restore_footprint_effective =
		    (u_long)HIB_FOOTPRINT_MAX;
		return;
	}
	if (error == ENOMEM) {
		printf("hibernate: derived footprint exceeds maximum "
		    "(%lu pages); save attempts will be refused\n",
		    HIB_FOOTPRINT_MAX);
		hibernate_footprint_status = ENOMEM;
		hibernate_restore_footprint_derived = (u_long)HIB_FOOTPRINT_MAX;
		hibernate_restore_footprint_effective =
		    (u_long)HIB_FOOTPRINT_MAX;
		return;
	}

	hibernate_restore_footprint_derived = (u_long)derived;

	effective = (derived > (uint64_t)configured) ? derived :
	    (uint64_t)configured;
	if (effective > HIB_FOOTPRINT_MAX)
		effective = HIB_FOOTPRINT_MAX;
	hibernate_restore_footprint_effective = (u_long)effective;
	/*
	 * If hibernate_footprint_status was set to EINVAL above (invalid
	 * configured floor), leave it set so the save path refuses.
	 * Otherwise the derivation succeeded: status remains 0.
	 */
}
SYSINIT(hibernate_footprint, SI_SUB_KMEM, SI_ORDER_ANY,
    hibernate_footprint_sysinit, NULL);

/*
 * hibernate_barrier_publish_attempt / hibernate_barrier_retract_attempt:
 * expose or withdraw the active hibernate attempt for
 * hibernate_page_is_destination().
 *
 * hibernate_current_attempt is declared static above; these two functions
 * are the only write paths.  Reads use atomic_load_ptr() so no lock is
 * required on the read side.
 */
void
hibernate_barrier_publish_attempt(struct hibernate_attempt *ha)
{
	KASSERT(ha != NULL, ("%s: null attempt", __func__));
	atomic_store_ptr(&hibernate_current_attempt, ha);
}

void
hibernate_barrier_retract_attempt(void)
{
	atomic_store_ptr(&hibernate_current_attempt, NULL);
}

/*
 * hibernate_footprint_check: enforce the footprint status recorded at boot.
 *
 * Returns 0 when the footprint configuration and derivation are valid.
 * Returns EINVAL when the configured floor was invalid.
 * Returns EOVERFLOW when derivation overflowed.
 * Returns ENOMEM when the derived minimum exceeds HIB_FOOTPRINT_MAX.
 *
 * Must be called before the freeze (before AP stop) so refusal is clean.
 */
int
hibernate_footprint_check(void)
{
	return (hibernate_footprint_status);
}

/*
 * hibernate_footprint_effective: return the effective restore-kernel
 * footprint budget in pages.  Valid only when hibernate_footprint_check()
 * returns 0.
 */
u_long
hibernate_footprint_effective(void)
{
	return (hibernate_restore_footprint_effective);
}

/*
 * hibernate_coordinator_acquire: acquire the hibernate coordinator lock,
 * blocking concurrent save attempts.  Must be called before setting
 * HIB_STAGE_COORDINATOR and before any resource preallocation.
 *
 * Returns 0 on success.  Currently always succeeds; the lock is a mutex
 * that serialises attempts without a try-acquire timeout.
 */
int
hibernate_coordinator_acquire(void)
{
	mtx_lock(&hibernate_coordinator_mtx);
	return (0);
}

/*
 * hibernate_coordinator_release: release the hibernate coordinator lock.
 * Called during unwind after all other acquired stages have been released.
 */
void
hibernate_coordinator_release(void)
{
	mtx_unlock(&hibernate_coordinator_mtx);
}

/*
 * hibernate_barrier_unwind: release acquired barrier stages in strict
 * reverse order.  Idempotent for bits that are not set.
 *
 * Full reverse order (descending bit value):
 *   HIB_STAGE_RESERVED    (7) — vm_phys_hibernate_release
 *   HIB_STAGE_CAM         (6) — xpt_release_simq (via ha->ha_cam_sim)
 *   HIB_STAGE_CALLOUTS    (5) — callout_hibernate_exit
 *   HIB_STAGE_BSP_INTRS   (4) — clear bit; caller calls intr_restore()
 *   HIB_STAGE_BSP_PREEMPT (3) — clear bit; caller calls sched_unpin()
 *   HIB_STAGE_APS_STOPPED (2) — clear bit; caller calls resume_other_cpus()
 *   HIB_STAGE_RESOURCES   (1) — clear bit; caller frees preallocated buffers
 *   HIB_STAGE_COORDINATOR (0) — release hibernate_coordinator_mtx
 *
 * Stages 1, 2, 3, and 4 involve caller-owned objects or CPU state; the bit
 * is cleared here so the caller's unwind loop is driven by a single stages
 * variable, but the actual resource free, AP resume, interrupt restore, and
 * preemption restore remain caller-side in strict reverse order:
 *   intr_restore() before sched_unpin() (reverse of sched_pin/intr_disable).
 * After returning, the caller must:
 *   - call intr_restore() if HIB_STAGE_BSP_INTRS was set before the call;
 *   - call sched_unpin() if HIB_STAGE_BSP_PREEMPT was set before the call,
 *     AFTER intr_restore() to avoid mi_switch in a critical section;
 *   - call resume_other_cpus() if HIB_STAGE_APS_STOPPED was set;
 *   - free preallocated buffers if HIB_STAGE_RESOURCES was set.
 */
void
hibernate_barrier_unwind(struct hibernate_attempt *ha,
    struct vm_phys_reservation *res, unsigned int *stages)
{
	unsigned int s;

	s = *stages;

	/* Stage 7: release page reservation. */
	if (s & HIB_STAGE_RESERVED) {
		hibernate_barrier_retract_attempt();
		vm_phys_hibernate_release(res);
		s &= ~HIB_STAGE_RESERVED;
	}

	/*
	 * Stage 6: thaw CAM admission.  xpt_release_simq() is the symmetric
	 * pair to xpt_freeze_simq().  Pass run_queue=0 because interrupts
	 * may still be disabled at this depth.
	 */
	if (s & HIB_STAGE_CAM) {
		if (ha->ha_cam_sim != NULL)
			xpt_release_simq(ha->ha_cam_sim, /*run_queue*/0);
		s &= ~HIB_STAGE_CAM;
	}

	/* Stage 5: release callout freeze. */
	if (s & HIB_STAGE_CALLOUTS) {
		callout_hibernate_exit();
		s &= ~HIB_STAGE_CALLOUTS;
	}

	/*
	 * Stage 4a: clear interrupt-state bit.  The caller restores the
	 * interrupt state via intr_restore() after AP resume (if needed),
	 * since re-enabling interrupts before APs are running can deadlock
	 * on SMP systems.
	 */
	if (s & HIB_STAGE_BSP_INTRS)
		s &= ~HIB_STAGE_BSP_INTRS;

	/*
	 * Stage 4b: clear BSP preemption bit.  The caller calls sched_unpin()
	 * AFTER intr_restore() to preserve the strict reverse order of
	 * barrier_prepare (sched_pin then intr_disable → reverse: intr_restore
	 * then sched_unpin).  Calling sched_unpin() here with interrupts still
	 * disabled would allow a timer interrupt to fire and call mi_switch()
	 * in a critical section immediately after intr_restore().
	 */
	if (s & HIB_STAGE_BSP_PREEMPT)
		s &= ~HIB_STAGE_BSP_PREEMPT;

	/*
	 * Stage 3: clear AP-stopped bit.  The caller performs the actual
	 * resume_other_cpus() because it holds the cpuset.
	 */
	if (s & HIB_STAGE_APS_STOPPED)
		s &= ~HIB_STAGE_APS_STOPPED;

	/*
	 * Stage 2: clear resources bit.  The caller frees preallocated
	 * buffers (hib_res_pages, hpcb, hcb) after this function returns.
	 */
	if (s & HIB_STAGE_RESOURCES)
		s &= ~HIB_STAGE_RESOURCES;

	/*
	 * Stage 1: clear the coordinator bit.  The caller MUST call
	 * hibernate_coordinator_release() after completing all physical
	 * cleanup (AP resume, interrupt restore, resource free) so that
	 * the coordinator lock is released LAST in strict reverse order.
	 * Releasing the coordinator here would allow a new save attempt
	 * to proceed while this attempt's APs are still stopped or its
	 * reservation array is still live.
	 */
	if (s & HIB_STAGE_COORDINATOR)
		s &= ~HIB_STAGE_COORDINATOR;

	*stages = s;
}

/*
 * hibernate_barrier_prepare: acquire barrier stages 4–7 of the K-5
 * eight-stage SAVE stability barrier.
 *
 * Stages 1 (coordinator lock), 2 (resource preallocation), and 3 (AP
 * stop) are caller-owned and must already be set in *stages before this
 * function is called.  Step 3 (suspend_other_cpus) is static in acpi.c
 * and is invoked by the ACPI caller directly.
 *
 * Steps performed here:
 *   4. BSP preemption disable (sched_pin), then interrupt disable.
 *   5. Callout freeze (callout_hibernate_enter).
 *   6. CAM admission freeze (xpt_freeze_simq) + finite drain
 *      (xpt_sim_poll, bounded by HIB_CAM_POLL_MAX iterations).
 *   7. vm_phys_hibernate_reserve_all — from this point no allocation
 *      may occur.
 *
 * On success returns 0, *stages has all eight bits set, and *intr_statep
 * holds the register_t from intr_disable() for the caller to restore.
 *
 * On failure returns errno; all stages set by this call are released via
 * hibernate_barrier_unwind() before returning, and the caller must still
 * restore interrupt state if HIB_STAGE_BSP_INTRS was set.
 *
 * K-5 performs no marker I/O.
 */
int
hibernate_barrier_prepare(struct hibernate_attempt *ha,
    struct vm_phys_reservation *res, unsigned int *stages,
    register_t *intr_statep)
{
	register_t intr_state;
	int error;

	KASSERT(ha != NULL, ("%s: null attempt", __func__));
	KASSERT(res != NULL, ("%s: null reservation", __func__));
	KASSERT(stages != NULL, ("%s: null stages", __func__));
	KASSERT(intr_statep != NULL, ("%s: null intr_statep", __func__));
	KASSERT((*stages & HIB_STAGE_COORDINATOR) != 0,
	    ("%s: coordinator stage not set", __func__));
	KASSERT((*stages & HIB_STAGE_RESOURCES) != 0,
	    ("%s: resources stage not set", __func__));
	KASSERT((*stages & HIB_STAGE_APS_STOPPED) != 0,
	    ("%s: APs not stopped", __func__));

	/*
	 * Step 4 is acquired by the ACPI worker immediately before this call.
	 * The worker owns the saved interrupt state and performs the physical
	 * intr_restore()/sched_unpin() after logical barrier unwind.
	 */
	KASSERT((*stages & HIB_STAGE_BSP_PREEMPT) != 0,
	    ("%s: BSP preemption stage not set", __func__));
	KASSERT((*stages & HIB_STAGE_BSP_INTRS) != 0,
	    ("%s: BSP interrupt stage not set", __func__));
	(void)intr_state;

	/*
	 * Step 5: freeze callouts.
	 * callout_hibernate_enter() sets hibernate_writing so that
	 * callout_process() diverts handlers through callout_hibernate_block()
	 * rather than executing them.
	 */
	callout_hibernate_enter();
	*stages |= HIB_STAGE_CALLOUTS;

	/*
	 * Step 6: freeze CAM admission and drain in-flight work.
	 *
	 * CAM audit result (approved decision 3 -- audit-first):
	 * Existing seam covers all required K-5 semantics:
	 *   xpt_freeze_simq(): increments devq->send_queue.qfrozen_cnt
	 *   under devq->send_mtx; prevents new CCBs from dispatching.
	 *   xpt_sim_poll(): calls sim->sim_poll() to drain in-flight
	 *   work; during hibernate_writing (set in step 5) it skips
	 *   the sim mutex, making drain progress finite.
	 *   xpt_release_simq(): symmetric unfreeze on unwind.
	 * No new CAM API is needed.  K-5 does not claim xpt_sim_poll()
	 * alone freezes admission.
	 *
	 * N2: ha_cam_sim must be non-NULL.  If no pollable CAM SIM can be
	 * associated with the dump path, K-5 refuses here rather than
	 * silently declaring stage 6 complete without freezing admission.
	 * The caller (acpi.c) must populate ha_cam_sim before calling
	 * hibernate_barrier_prepare(); if no SIM is available it must
	 * refuse before reaching this point.
	 */
	if (ha->ha_cam_sim == NULL) {
		/*
		 * N2: no dump-path CAM SIM associated.  Refuse rather than
		 * declaring CAM admission frozen without actually freezing it.
		 * Unwind stages already acquired (callouts, preempt, intrs)
		 * before returning.
		 */
		hibernate_barrier_unwind(ha, res, stages);
		return (ENXIO);
	}
	xpt_freeze_simq(ha->ha_cam_sim, /*count*/1);
	*stages |= HIB_STAGE_CAM;
	/*
	 * H3: drain in-flight CAM work using the real quiescence predicate:
	 * devq->send_active == 0 (no CCBs outstanding on this SIM).
	 *
	 * cam_sim_pollable() is a CAPABILITY flag (SIM supports polling)
	 * that never becomes false after the SIM is frozen — using it as
	 * a loop exit condition causes false timeout on every pollable SIM.
	 *
	 * Correct approach: after xpt_freeze_simq(), new CCBs cannot be
	 * dispatched.  xpt_sim_poll() makes forward progress by completing
	 * in-flight work.  We poll until send_active drops to zero
	 * (genuine quiescence) or HIB_CAM_POLL_MAX iterations (bounded
	 * refusal with EBUSY).
	 *
	 * send_active is read under devq->send_mtx to avoid torn reads.
	 */
#define	HIB_CAM_POLL_MAX	256
	{
		struct cam_devq *_devq = ha->ha_cam_sim->devq;
		int _i;
		int _active;

		for (_i = 0; _i < HIB_CAM_POLL_MAX; _i++) {
			mtx_lock(&_devq->send_mtx);
			_active = _devq->send_active;
			mtx_unlock(&_devq->send_mtx);
			if (_active == 0)
				break;	/* Quiescent: no outstanding CCBs. */
			xpt_sim_poll(ha->ha_cam_sim);
		}
		if (_i == HIB_CAM_POLL_MAX) {
			/* Re-check after final poll. */
			mtx_lock(&_devq->send_mtx);
			_active = _devq->send_active;
			mtx_unlock(&_devq->send_mtx);
			if (_active != 0) {
				/* Drain did not reach quiescence. */
				hibernate_barrier_unwind(ha, res, stages);
				return (EBUSY);
			}
		}
	}
#undef	HIB_CAM_POLL_MAX

	/*
	 * Step 7: reserve all eligible FREE pages.
	 * Publish the attempt pointer so hibernate_page_is_destination() is
	 * live during classification under each domain free lock.
	 * From this point no allocation may occur.
	 */
	hibernate_barrier_publish_attempt(ha);
	error = vm_phys_hibernate_reserve_all(ha, res);
	if (error != 0) {
		hibernate_barrier_retract_attempt();
		hibernate_barrier_unwind(ha, res, stages);
		return (error);
	}
	*stages |= HIB_STAGE_RESERVED;

	return (0);
}

#endif /* !_HIBERNATE_USERLAND_BUILD */

/*
 * decode_cb: decode and validate the CB from buf at cb_offset.
 * All integer fields are loaded with explicit little-endian helpers.
 */
static int
decode_cb(const uint8_t *buf, uint64_t cb_offset, struct hibernate_cb *cb)
{
	const uint8_t *p;
	uint64_t crc64;

	p = buf + cb_offset;

	cb->hc_magic = le64dec(p + HIBERNATE_CB_OFF_MAGIC);
	cb->hc_version = le32dec(p + HIBERNATE_CB_OFF_VERSION);
	cb->hc_encoded_size = le32dec(p + HIBERNATE_CB_OFF_ENCODED_SIZE);
	cb->hc_page_size = le64dec(p + HIBERNATE_CB_OFF_PAGE_SIZE);
	cb->hc_physmem_bytes = le64dec(p + HIBERNATE_CB_OFF_PHYSMEM_BYTES);
	cb->hc_image_length = le64dec(p + HIBERNATE_CB_OFF_IMAGE_LENGTH);
	cb->hc_payload_start = le64dec(p + HIBERNATE_CB_OFF_PAYLOAD_START);
	cb->hc_destination_pages = le64dec(
	    p + HIBERNATE_CB_OFF_DESTINATION_PAGES);
	cb->hc_source_vector_bytes = le64dec(
	    p + HIBERNATE_CB_OFF_SOURCE_VECTOR_BYTES);
	cb->hc_arena_start = le64dec(p + HIBERNATE_CB_OFF_ARENA_START);
	cb->hc_arena_size = le64dec(p + HIBERNATE_CB_OFF_ARENA_SIZE);
	cb->hc_facs_hardware_signature = le64dec(
	    p + HIBERNATE_CB_OFF_FACS_HARDWARE_SIGNATURE);
	cb->hc_saved_pcb_offset = le64dec(
	    p + HIBERNATE_CB_OFF_SAVED_PCB_OFFSET);
	cb->hc_saved_pcb_size = le64dec(p + HIBERNATE_CB_OFF_SAVED_PCB_SIZE);
	cb->hc_elf_phnum = le64dec(p + HIBERNATE_CB_OFF_ELF_PHNUM);
	cb->hc_metadata_length = le64dec(p + HIBERNATE_CB_OFF_METADATA_LENGTH);

	/* CRC field: low 32 bits = stored CRC; high 32 bits must be zero. */
	crc64 = le64dec(p + HIBERNATE_CB_OFF_CRC32C);
	if ((crc64 >> 32) != 0)
		return (EINVAL);
	cb->hc_crc32c = (uint32_t)crc64;

	cb->hc_restore_footprint_pages = le64dec(
	    p + HIBERNATE_CB_OFF_RESTORE_FOOTPRINT_PAGES);
	cb->hc_machine_flags = le64dec(p + HIBERNATE_CB_OFF_MACHINE_FLAGS);
	cb->hc_destination_bytes = le64dec(
	    p + HIBERNATE_CB_OFF_DESTINATION_BYTES);
	cb->hc_copy_list_bound = le64dec(p + HIBERNATE_CB_OFF_COPY_LIST_BOUND);

	/* Structural field validation. */
	if (cb->hc_version != HCB_VERSION)
		return (EINVAL);
	if (cb->hc_encoded_size != HIBERNATE_CB_ENCODED_SIZE)
		return (EINVAL);
	if (cb->hc_page_size != HIB_PAGE_SIZE)
		return (EINVAL);

	/* ABI 1 machine_flags mask is 0: no defined bits. */
	if ((cb->hc_machine_flags & ~HIBERNATE_MACHINE_FLAGS_MASK) != 0)
		return (EINVAL);

	/* Reserved ranges must be zero. */
	if (!is_all_zero(p + HIBERNATE_CB_OFF_RESERVED_0A0,
		HIBERNATE_CB_WIDTH_RESERVED_0A0))
		return (EINVAL);
	if (!is_all_zero(p + HIBERNATE_CB_OFF_RESERVED_0C0,
		HIBERNATE_CB_WIDTH_RESERVED_0C0))
		return (EINVAL);

	return (0);
}

/*
 * decode_pcb: decode and validate the PCB from buf at pcb_offset.
 * All integer fields are loaded with explicit little-endian helpers.
 * No CPUID or XGETBV is executed; validation is structural only.
 */
static int
decode_pcb(const uint8_t *buf, uint64_t pcb_offset, struct hibernate_pcb *pcb)
{
	const uint8_t *p;
	uint64_t xcr0;
	uint32_t xsave_len, xsave_fmt;

	p = buf + pcb_offset;

	pcb->hp_version = le32dec(p + HIBERNATE_PCB_OFF_VERSION);
	pcb->hp_encoded_size = le32dec(p + HIBERNATE_PCB_OFF_ENCODED_SIZE);

	if (pcb->hp_version != 1)
		return (EINVAL);
	if (pcb->hp_encoded_size != HIBERNATE_PCB_ENCODED_SIZE)
		return (EINVAL);

	pcb->hp_cr0 = le64dec(p + HIBERNATE_PCB_OFF_CR0);
	pcb->hp_cr3 = le64dec(p + HIBERNATE_PCB_OFF_CR3);
	pcb->hp_cr4 = le64dec(p + HIBERNATE_PCB_OFF_CR4);
	pcb->hp_efer = le64dec(p + HIBERNATE_PCB_OFF_EFER);
	pcb->hp_pat = le64dec(p + HIBERNATE_PCB_OFF_PAT);
	xcr0 = le64dec(p + HIBERNATE_PCB_OFF_XCR0);
	pcb->hp_xcr0 = xcr0;
	pcb->hp_rflags = le64dec(p + HIBERNATE_PCB_OFF_RFLAGS);
	pcb->hp_rsp = le64dec(p + HIBERNATE_PCB_OFF_RSP);
	pcb->hp_rip = le64dec(p + HIBERNATE_PCB_OFF_RIP);
	pcb->hp_r12_pcb_pa = le64dec(p + HIBERNATE_PCB_OFF_R12_PCB_PA);
	pcb->hp_gdtr_limit = le16dec(p + HIBERNATE_PCB_OFF_GDTR_LIMIT);
	pcb->hp_gdtr_base = le64dec(p + HIBERNATE_PCB_OFF_GDTR_BASE);
	pcb->hp_idtr_limit = le16dec(p + HIBERNATE_PCB_OFF_IDTR_LIMIT);
	pcb->hp_idtr_base = le64dec(p + HIBERNATE_PCB_OFF_IDTR_BASE);
	pcb->hp_fsbase = le64dec(p + HIBERNATE_PCB_OFF_FSBASE);
	pcb->hp_gsbase = le64dec(p + HIBERNATE_PCB_OFF_GSBASE);
	pcb->hp_kgsbase = le64dec(p + HIBERNATE_PCB_OFF_KGSBASE);
	pcb->hp_star = le64dec(p + HIBERNATE_PCB_OFF_STAR);
	pcb->hp_lstar = le64dec(p + HIBERNATE_PCB_OFF_LSTAR);
	pcb->hp_cstar = le64dec(p + HIBERNATE_PCB_OFF_CSTAR);
	pcb->hp_sfmask = le64dec(p + HIBERNATE_PCB_OFF_SFMASK);
	pcb->hp_kernel_gsbase = le64dec(p + HIBERNATE_PCB_OFF_KERNEL_GSBASE);

	xsave_len = le32dec(p + HIBERNATE_PCB_OFF_XSAVE_LENGTH);
	xsave_fmt = le32dec(p + HIBERNATE_PCB_OFF_XSAVE_FORMAT);
	pcb->hp_xsave_length = xsave_len;
	pcb->hp_xsave_format = xsave_fmt;

	/* xcr0 must contain only ABI-defined bits. */
	if ((xcr0 & ~HIBERNATE_XCR0_MASK) != 0)
		return (EINVAL);
	/* x87 and SSE are mandatory. */
	if ((xcr0 & HIBERNATE_XCR0_REQUIRED_MASK) !=
	    HIBERNATE_XCR0_REQUIRED_MASK)
		return (EINVAL);

	/* XSAVE format must be HIBERNATE_XSAVE_FORMAT. */
	if (xsave_fmt != HIBERNATE_XSAVE_FORMAT)
		return (EINVAL);

	/*
	 * ABI 1 XSAVE length range (structural, no CPUID):
	 *   x87 + SSE only (AVX excluded in ABI 1).
	 *   Canonical minimum: 512-byte legacy region + 64-byte XSAVE
	 *   header = HIBERNATE_PCB_XSAVE_MIN (576) bytes.
	 *   Maximum: HIBERNATE_PCB_XSAVE_SIZE (768) bytes.
	 *   Tail bytes [xsave_len, 768) must be zero (checked below).
	 */
	if (xsave_len < HIBERNATE_PCB_XSAVE_MIN)
		return (EINVAL);
	if (xsave_len > HIBERNATE_PCB_XSAVE_SIZE)
		return (EINVAL);

	/* Copy canonical XSAVE bytes from the encoded region. */
	__builtin_memcpy(pcb->hp_xsave, p + HIBERNATE_PCB_OFF_XSAVE,
	    HIBERNATE_PCB_XSAVE_SIZE);

	/* Bytes hp_xsave[xsave_len..XSAVE_SIZE) must be zero. */
	if (!is_all_zero(pcb->hp_xsave + xsave_len,
		HIBERNATE_PCB_XSAVE_SIZE - xsave_len))
		return (EINVAL);

	/* Reserved ranges must be zero. */
	if (!is_all_zero(p + HIBERNATE_PCB_OFF_RESERVED_05A,
		HIBERNATE_PCB_WIDTH_RESERVED_05A))
		return (EINVAL);
	if (!is_all_zero(p + HIBERNATE_PCB_OFF_RESERVED_06A,
		HIBERNATE_PCB_WIDTH_RESERVED_06A))
		return (EINVAL);
	if (!is_all_zero(p + HIBERNATE_PCB_OFF_RESERVED_3C0,
		HIBERNATE_PCB_WIDTH_RESERVED_3C0))
		return (EINVAL);

	return (0);
}

/*
 * hibernate_image_decode: decode and validate an ABI 1 hibernate image prefix.
 *
 * buf  - image-relative [0, payload_start), exactly len bytes
 * len  - exact byte count supplied (must equal derived payload_start)
 * out  - written only after all checks pass
 *
 * Returns 0 on success, or an errno on any validation failure.
 * On failure *out is not modified.
 */
int
hibernate_image_decode(const void *buf, size_t len, struct hibernate_image *out)
{
	const uint8_t *b;
	struct hibernate_image img;
	uint16_t phnum, i;
	uint64_t phoff, phdr_table_end;
	uint64_t cb_offset, pcb_offset;
	uint64_t cb_aligned, pcb_aligned, payload_aligned, payload_start;
	uint64_t prev_file_end, prev_dest_end, prev_load_file_end;
	uint64_t load_count, cb_count, pcb_count;
	uint64_t load_bytes, load_pages;
	uint64_t first_load_index, last_load_index;
	uint64_t tmp;
	int error;

	/* Step 1: validate non-null arguments and minimum ELF header length. */
	if (buf == NULL || out == NULL)
		return (EINVAL);
	if (len < EHDR_SIZE)
		return (EINVAL);

	b = (const uint8_t *)buf;

	/* Step 2: ELF identity and header fields. */
	if (b[EHDR_OFF_EI_MAG0] != ELFMAG0 || b[EHDR_OFF_EI_MAG1] != ELFMAG1 ||
	    b[EHDR_OFF_EI_MAG2] != ELFMAG2 || b[EHDR_OFF_EI_MAG3] != ELFMAG3)
		return (EINVAL);
	if (b[EHDR_OFF_EI_CLASS] != ELFCLASS64)
		return (EINVAL);
	if (b[EHDR_OFF_EI_DATA] != ELFDATA2LSB)
		return (EINVAL);
	if (b[EHDR_OFF_EI_VERSION] != EV_CURRENT)
		return (EINVAL);

	{
		uint16_t e_type, e_machine, e_ehsize, e_phentsize;
		uint32_t e_version;

		e_type = le16dec(b + EHDR_OFF_E_TYPE);
		e_machine = le16dec(b + EHDR_OFF_E_MACHINE);
		e_version = le32dec(b + EHDR_OFF_E_VERSION);
		e_ehsize = le16dec(b + EHDR_OFF_E_EHSIZE);
		e_phentsize = le16dec(b + EHDR_OFF_E_PHENTSIZE);
		phnum = le16dec(b + EHDR_OFF_E_PHNUM);
		phoff = le64dec(b + EHDR_OFF_E_PHOFF);

		if (e_type != ET_FREEBSD_HIBERNATE_IMAGE)
			return (EINVAL);
		if (e_machine != EM_X86_64)
			return (EINVAL);
		if (e_version != EV_CURRENT)
			return (EINVAL);
		if (e_ehsize != EHDR_SIZE)
			return (EINVAL);
		if (e_phentsize != PHDR_SIZE)
			return (EINVAL);
	}

	/* Step 3: phnum range and phdr table bounds. */
	if (phnum < 1 || phnum > HIBERNATE_MAX_PHDRS)
		return (EINVAL);
	if (phoff != EHDR_SIZE)
		return (EINVAL);

	/* checked: phdr_table_end = EHDR_SIZE + phnum * PHDR_SIZE */
	if (__builtin_mul_overflow((uint64_t)phnum, (uint64_t)PHDR_SIZE, &tmp))
		return (EOVERFLOW);
	if (__builtin_add_overflow((uint64_t)EHDR_SIZE, tmp, &phdr_table_end))
		return (EOVERFLOW);
	if (phdr_table_end > len)
		return (EINVAL);
	/* ELF header + phdr table must fit within 50,464 bytes. */
	if (phdr_table_end > 50464)
		return (E2BIG);

	/* Step 4+5: walk phdrs, classify, check monotonicity. */
	cb_count = 0;
	pcb_count = 0;
	load_count = 0;
	load_bytes = 0;
	load_pages = 0;
	cb_offset = 0;
	pcb_offset = 0;
	prev_file_end = phdr_table_end;
	prev_dest_end = 0;
	prev_load_file_end = 0;
	first_load_index = (uint64_t)-1;
	last_load_index = (uint64_t)-1;

	for (i = 0; i < phnum; i++) {
		const uint8_t *ph;
		uint32_t p_type;
		uint64_t p_offset, p_filesz, p_memsz, p_paddr, seg_end;

		ph = b + phoff + (uint64_t)i * PHDR_SIZE;
		p_type = le32dec(ph + PHDR_OFF_P_TYPE);
		p_offset = le64dec(ph + PHDR_OFF_P_OFFSET);
		p_filesz = le64dec(ph + PHDR_OFF_P_FILESZ);
		p_memsz = le64dec(ph + PHDR_OFF_P_MEMSZ);
		p_paddr = le64dec(ph + PHDR_OFF_P_PADDR);

		/* Closed type set. */
		if (p_type != PT_FREEBSD_HIBERNATE_CB &&
		    p_type != PT_FREEBSD_HIBERNATE_PCB && p_type != PT_LOAD)
			return (EINVAL);

		/* Strictly increasing image-relative file offsets. */
		if (p_offset < prev_file_end)
			return (EINVAL);

		/* Checked segment end; metadata must fit within the prefix. */
		if (__builtin_add_overflow(p_offset, p_filesz, &seg_end))
			return (EOVERFLOW);
		if (p_type != PT_LOAD && seg_end > len)
			return (EINVAL);

		if (p_type == PT_FREEBSD_HIBERNATE_CB) {
			if (cb_count++ > 0)
				return (EINVAL);
			cb_offset = p_offset;
			if (p_filesz != HIBERNATE_CB_ENCODED_SIZE)
				return (EINVAL);

		} else if (p_type == PT_FREEBSD_HIBERNATE_PCB) {
			if (pcb_count++ > 0)
				return (EINVAL);
			pcb_offset = p_offset;
			if (p_filesz != HIBERNATE_PCB_ENCODED_SIZE)
				return (EINVAL);

		} else {
			/* PT_LOAD */
			if (p_filesz != p_memsz)
				return (EINVAL);
			if (p_filesz == 0)
				return (EINVAL);
			if ((p_paddr & (HIB_PAGE_SIZE - 1)) != 0)
				return (EINVAL);
			if ((p_filesz & (HIB_PAGE_SIZE - 1)) != 0)
				return (EINVAL);

			/* Strictly increasing non-overlapping destinations. */
			if (load_count > 0 && p_paddr < prev_dest_end)
				return (EINVAL);
			if (__builtin_add_overflow(p_paddr, p_filesz,
				&prev_dest_end))
				return (EOVERFLOW);

			/* Strictly increasing non-overlapping file ranges. */
			if (load_count > 0 && p_offset < prev_load_file_end)
				return (EINVAL);
			prev_load_file_end = seg_end;

			if (__builtin_add_overflow(load_bytes, p_filesz,
				&load_bytes))
				return (EOVERFLOW);
			if (__builtin_add_overflow(load_pages,
				p_filesz / HIB_PAGE_SIZE, &load_pages))
				return (EOVERFLOW);

			if (first_load_index == (uint64_t)-1)
				first_load_index = i;
			last_load_index = i;
			load_count++;
		}

		prev_file_end = seg_end;
	}

	/* Require exactly one CB, one PCB, and at least one PT_LOAD. */
	if (cb_count != 1 || pcb_count != 1 || load_count < 1)
		return (EINVAL);

	/*
	 * Step 6: derive page-aligned positions for CB, PCB, payload.
	 * Layout: phdr_table_end -> [pad] -> CB(256) -> [pad] ->
	 *         PCB(1024) -> [pad] -> payload.
	 */
	error = align_up_checked(phdr_table_end, HIB_PAGE_SIZE, &cb_aligned);
	if (error != 0)
		return (error);

	if (__builtin_add_overflow(cb_aligned,
		(uint64_t)HIBERNATE_CB_ENCODED_SIZE, &tmp))
		return (EOVERFLOW);
	error = align_up_checked(tmp, HIB_PAGE_SIZE, &pcb_aligned);
	if (error != 0)
		return (error);

	if (__builtin_add_overflow(pcb_aligned,
		(uint64_t)HIBERNATE_PCB_ENCODED_SIZE, &tmp))
		return (EOVERFLOW);
	error = align_up_checked(tmp, HIB_PAGE_SIZE, &payload_aligned);
	if (error != 0)
		return (error);

	payload_start = payload_aligned;

	/* Verify phdr p_offset values match derived positions. */
	if (cb_offset != cb_aligned)
		return (EINVAL);
	if (pcb_offset != pcb_aligned)
		return (EINVAL);

	/* Step 7: metadata bounds. */
	if (payload_start == 0 || payload_start > 64029)
		return (EINVAL);
	if (payload_start > HIBERNATE_META_BUF_MAX)
		return (EINVAL);
	/* buf must be exactly the metadata prefix. */
	if (len != payload_start)
		return (EINVAL);

	/* Step 8: all metadata padding bytes must be zero. */
	/* Padding: phdr_table_end to cb_aligned. */
	if (!is_all_zero(b + phdr_table_end,
		(size_t)(cb_aligned - phdr_table_end)))
		return (EINVAL);

	{
		uint64_t cb_end, pcb_end;

		if (__builtin_add_overflow(cb_aligned,
			(uint64_t)HIBERNATE_CB_ENCODED_SIZE, &cb_end))
			return (EOVERFLOW);
		/* Padding: cb_end to pcb_aligned. */
		if (!is_all_zero(b + cb_end, (size_t)(pcb_aligned - cb_end)))
			return (EINVAL);

		if (__builtin_add_overflow(pcb_aligned,
			(uint64_t)HIBERNATE_PCB_ENCODED_SIZE, &pcb_end))
			return (EOVERFLOW);
		/* Padding: pcb_end to payload_start. */
		if (!is_all_zero(b + pcb_end,
			(size_t)(payload_start - pcb_end)))
			return (EINVAL);
	}

	/* Steps 9-10: decode CB and PCB. */
	__builtin_memset(&img, 0, sizeof(img));

	error = decode_cb(b, cb_aligned, &img.hi_cb);
	if (error != 0)
		return (error);

	error = decode_pcb(b, pcb_aligned, &img.hi_pcb);
	if (error != 0)
		return (error);

	/* Cross-validate CB duplicated fields. */
	if (img.hi_cb.hc_payload_start != payload_start)
		return (EINVAL);
	if (img.hi_cb.hc_elf_phnum != phnum)
		return (EINVAL);
	if (img.hi_cb.hc_image_length < payload_start)
		return (EINVAL);
	if (img.hi_cb.hc_metadata_length != payload_start)
		return (EINVAL);
	if (img.hi_cb.hc_metadata_length > 64029)
		return (EINVAL);
	if (img.hi_cb.hc_saved_pcb_size != HIBERNATE_PCB_ENCODED_SIZE)
		return (EINVAL);
	if (img.hi_cb.hc_saved_pcb_offset != pcb_aligned)
		return (EINVAL);
	if (img.hi_cb.hc_destination_bytes != load_bytes)
		return (EINVAL);
	if (img.hi_cb.hc_destination_pages != load_pages)
		return (EINVAL);

	/*
	 * Step 11: verify PT_LOAD file ranges lie within image and
	 * start at or after payload_start.
	 */
	for (i = 0; i < phnum; i++) {
		const uint8_t *ph;
		uint32_t p_type;
		uint64_t p_offset, p_filesz, seg_end;

		ph = b + phoff + (uint64_t)i * PHDR_SIZE;
		p_type = le32dec(ph + PHDR_OFF_P_TYPE);
		if (p_type != PT_LOAD)
			continue;

		p_offset = le64dec(ph + PHDR_OFF_P_OFFSET);
		p_filesz = le64dec(ph + PHDR_OFF_P_FILESZ);

		if (p_offset < payload_start)
			return (EINVAL);

		if (__builtin_add_overflow(p_offset, p_filesz, &seg_end))
			return (EOVERFLOW);
		if (seg_end > img.hi_cb.hc_image_length)
			return (EINVAL);
	}

	/* Step 12: ABI-fixed arithmetic bounds. */
	/* destination_bytes == destination_pages * PAGE_SIZE (checked). */
	if (__builtin_mul_overflow(img.hi_cb.hc_destination_pages,
		(uint64_t)HIB_PAGE_SIZE, &tmp))
		return (EOVERFLOW);
	if (img.hi_cb.hc_destination_bytes != tmp)
		return (EINVAL);

	/* Step 13: publish decoded image atomically. */
	img.hi_prefix = b;
	img.hi_prefix_length = len;
	img.hi_phnum = phnum;
	img.hi_load_count = (uint32_t)load_count;
	img.hi_cb_count = 1;
	img.hi_pcb_count = 1;
	img.hi_cb_offset = cb_aligned;
	img.hi_pcb_offset = pcb_aligned;
	img.hi_payload_start = payload_start;
	img.hi_image_length = img.hi_cb.hc_image_length;
	img.hi_destination_pages = img.hi_cb.hc_destination_pages;
	img.hi_destination_bytes = img.hi_cb.hc_destination_bytes;
	img.hi_source_vector_bytes = img.hi_cb.hc_source_vector_bytes;

	/*
	 * CRC virtual-zero interval: the 8 bytes of hc_crc32c at
	 * cb_aligned + HIBERNATE_CB_OFF_CRC32C.
	 */
	img.hi_crc_zero_offset = cb_aligned + HIBERNATE_CB_OFF_CRC32C;
	img.hi_crc_zero_length = HIBERNATE_CB_WIDTH_CRC32C;

	if (first_load_index != (uint64_t)-1)
		img.hi_first_load_index = (uint32_t)first_load_index;
	if (last_load_index != (uint64_t)-1)
		img.hi_last_load_index = (uint32_t)last_load_index;

	*out = img;
	return (0);
}

/*
 * hibernate_image_interval_next: advance the iterator by one interval.
 *
 * Returns:
 *   0       - *out contains a valid nonempty interval
 *   ENOENT  - complete coverage of [0, image_length) reached
 *   errno   - invariant failure (sticky; all subsequent calls return same)
 */
int
hibernate_image_interval_next(struct hibernate_image_iterator *it,
    struct hibernate_image_interval *out)
{
	const struct hibernate_image *img;
	uint64_t cursor, image_length, payload_start;
	uint64_t phdr_table_end, cb_offset, cb_end, pcb_offset, pcb_end;
	uint32_t idx, phnum;
	uint64_t tmp;

	if (it == NULL || out == NULL)
		return (EINVAL);

	/* Sticky error propagation. */
	if (it->hii_error != 0)
		return (it->hii_error);

	if (it->hii_phase == HIIP_DONE)
		return (ENOENT);

	img = it->hii_image;
	if (img == NULL) {
		it->hii_error = EINVAL;
		return (EINVAL);
	}

	image_length = img->hi_image_length;
	payload_start = img->hi_payload_start;
	cursor = it->hii_cursor;

	if (it->hii_phase == HIIP_METADATA) {
		/*
		 * Metadata phase: emit intervals covering [0, payload_start).
		 * Emit one region per call in this order:
		 *   [0, phdr_table_end)         STORED  (ELF header + phdrs)
		 *   [phdr_table_end, cb_offset) ZERO_GAP (padding)
		 *   [cb_offset, cb_end)         STORED  (encoded CB)
		 *   [cb_end, pcb_offset)        ZERO_GAP (padding)
		 *   [pcb_offset, pcb_end)       STORED  (encoded PCB)
		 *   [pcb_end, payload_start)    ZERO_GAP (padding)
		 *
		 * Zero-length gaps are skipped automatically because cursor
		 * will equal the next region start.
		 */

		/* Compute metadata boundaries from the decoded image. */
		if (__builtin_mul_overflow((uint64_t)img->hi_phnum,
			(uint64_t)PHDR_SIZE, &tmp)) {
			it->hii_error = EOVERFLOW;
			return (EOVERFLOW);
		}
		if (__builtin_add_overflow((uint64_t)EHDR_SIZE, tmp,
			&phdr_table_end)) {
			it->hii_error = EOVERFLOW;
			return (EOVERFLOW);
		}
		cb_offset = img->hi_cb_offset;
		if (__builtin_add_overflow(cb_offset,
			(uint64_t)HIBERNATE_CB_ENCODED_SIZE, &cb_end)) {
			it->hii_error = EOVERFLOW;
			return (EOVERFLOW);
		}
		pcb_offset = img->hi_pcb_offset;
		if (__builtin_add_overflow(pcb_offset,
			(uint64_t)HIBERNATE_PCB_ENCODED_SIZE, &pcb_end)) {
			it->hii_error = EOVERFLOW;
			return (EOVERFLOW);
		}

		/* ELF header + phdr table. */
		if (cursor < phdr_table_end) {
			out->hii_offset = cursor;
			out->hii_length = phdr_table_end - cursor;
			out->hii_class = HIIC_STORED;
			it->hii_cursor = phdr_table_end;
			return (0);
		}
		/* Padding before CB. */
		if (cursor < cb_offset) {
			out->hii_offset = cursor;
			out->hii_length = cb_offset - cursor;
			out->hii_class = HIIC_ZERO_GAP;
			it->hii_cursor = cb_offset;
			return (0);
		}
		/* Encoded CB. */
		if (cursor < cb_end) {
			out->hii_offset = cursor;
			out->hii_length = cb_end - cursor;
			out->hii_class = HIIC_STORED;
			it->hii_cursor = cb_end;
			return (0);
		}
		/* Padding before PCB. */
		if (cursor < pcb_offset) {
			out->hii_offset = cursor;
			out->hii_length = pcb_offset - cursor;
			out->hii_class = HIIC_ZERO_GAP;
			it->hii_cursor = pcb_offset;
			return (0);
		}
		/* Encoded PCB. */
		if (cursor < pcb_end) {
			out->hii_offset = cursor;
			out->hii_length = pcb_end - cursor;
			out->hii_class = HIIC_STORED;
			it->hii_cursor = pcb_end;
			return (0);
		}
		/* Padding before payload. */
		if (cursor < payload_start) {
			out->hii_offset = cursor;
			out->hii_length = payload_start - cursor;
			out->hii_class = HIIC_ZERO_GAP;
			it->hii_cursor = payload_start;
			return (0);
		}

		/* Transition to payload phase. */
		it->hii_phase = HIIP_PAYLOAD;
		it->hii_next_index = img->hi_first_load_index;
		cursor = it->hii_cursor;
	}

	/* Payload phase: walk PT_LOAD entries in order. */
	if (it->hii_phase == HIIP_PAYLOAD) {
		const uint8_t *b;
		const uint8_t *ph;
		uint32_t p_type;
		uint64_t p_offset, p_filesz, seg_end;

		b = img->hi_prefix;
		phnum = img->hi_phnum;
		idx = it->hii_next_index;
		cursor = it->hii_cursor;

		/* Find the next PT_LOAD. */
		while (idx < phnum) {
			ph = b + EHDR_SIZE + (uint64_t)idx * PHDR_SIZE;
			p_type = le32dec(ph + PHDR_OFF_P_TYPE);
			if (p_type == PT_LOAD)
				break;
			idx++;
		}

		if (idx >= phnum) {
			/* No more PT_LOADs; emit trailing gap if any. */
			if (cursor < image_length) {
				out->hii_offset = cursor;
				out->hii_length = image_length - cursor;
				out->hii_class = HIIC_ZERO_GAP;
				it->hii_cursor = image_length;
				it->hii_next_index = idx;
				return (0);
			}
			it->hii_phase = HIIP_DONE;
			return (ENOENT);
		}

		ph = b + EHDR_SIZE + (uint64_t)idx * PHDR_SIZE;
		p_offset = le64dec(ph + PHDR_OFF_P_OFFSET);
		p_filesz = le64dec(ph + PHDR_OFF_P_FILESZ);
		if (__builtin_add_overflow(p_offset, p_filesz, &seg_end)) {
			it->hii_error = EOVERFLOW;
			return (EOVERFLOW);
		}

		/* Gap before this PT_LOAD (encoded zero gap). */
		if (cursor < p_offset) {
			out->hii_offset = cursor;
			out->hii_length = p_offset - cursor;
			out->hii_class = HIIC_ZERO_GAP;
			it->hii_cursor = p_offset;
			return (0);
		}

		/* cursor must equal p_offset now. */
		if (cursor != p_offset) {
			it->hii_error = EINVAL;
			return (EINVAL);
		}

		/* Emit the PT_LOAD stored interval. */
		out->hii_offset = p_offset;
		out->hii_length = p_filesz;
		out->hii_class = HIIC_STORED;
		it->hii_cursor = seg_end;
		it->hii_next_index = idx + 1;
		return (0);
	}

	/* Unreachable; treat as invariant failure. */
	it->hii_error = EINVAL;
	return (EINVAL);
}

/*
 * CRC32C implementation — reflected Castagnoli polynomial 0x82f63b78.
 *
 * A compact bitwise loop: no large generated table, no allocation, no
 * external dependency beyond the standard headers already included.
 *
 * Convention (same as RFC 3720 / iSCSI CRC32C):
 *   caller passes crc = 0xffffffff on entry to the first call;
 *   caller applies final XOR 0xffffffff to the last returned value.
 *
 * Verified vectors (initial 0xffffffff, final XOR 0xffffffff applied):
 *   empty              -> 0x00000000
 *   "123456789" (9 B)  -> 0xe3069283
 */
#define CRC32C_POLY_REFLECTED UINT32_C(0x82f63b78)

uint32_t
hibernate_crc32c_update(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p;
	size_t i;
	int bit;

	p = (const uint8_t *)buf;
	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (bit = 0; bit < 8; bit++) {
			if (crc & 1)
				crc = (crc >> 1) ^ CRC32C_POLY_REFLECTED;
			else
				crc >>= 1;
		}
	}
	return (crc);
}
