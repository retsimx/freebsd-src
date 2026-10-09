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

#include <machine/atomic.h>
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

/* Page alignment for CB, PCB, and payload. */
#define HIB_PAGE_SIZE 4096

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
	atomic_store_rel_int(&hibernate_owner.published, 1);
	atomic_store_rel_int(&hibernate_owner.active, 1);
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
	struct hibernate_marker_result result;
	struct hibernate_raw_marker raw;
	uint32_t reserved;
	int error;

	memset(&result, 0, sizeof(result));
	result.class = HMC_ABSENT;
	if (ha == NULL)
		return (EINVAL);

	if (ha->ha_dumper == NULL) {
		result.class = HMC_IO_ERROR;
		result.error = ENXIO;
		ha->ha_marker_result = result;
		return (ENXIO);
	}
	hibernate_marker_read_raw(ha, &raw);
	if (raw.error != 0 || raw.transferred != sizeof(raw.sector)) {
		error = raw.error != 0 ? raw.error : EIO;
		result.class = HMC_IO_ERROR;
		result.error = error;
		ha->ha_marker_result = result;
		return (error);
	}

	hibernate_marker_decode_complete(raw.sector, &result.marker, &reserved);
	result.class = hibernate_marker_classify(ha->ha_provider_offset,
	    ha->ha_provider_size, &result.marker, reserved);
	result.error = 0;
	ha->ha_marker_result = result;
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
