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
#include <sys/cpuset.h>
#include <sys/elf64.h>
#include <sys/elf_common.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/hibernate.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

#include <machine/atomic.h>
#include <machine/hibernate.h>
#include <machine/md_var.h>
#include <machine/vmparam.h>

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

static struct hibernate_early_arena g_hibernate_early_arena;
static struct hibernate_attempt *g_hibernate_arena_owner;

/*
 * These buffers are used only by serial early-boot arena derivation.
 * Each active range is fully written before it is read.
 */
static vm_paddr_t hibernate_arena_endpoints[HIBERNATE_ARENA_INTERVAL_MAX * 2];
static struct hibernate_arena_interval
    hibernate_arena_sorted[HIBERNATE_ARENA_INTERVAL_MAX];
static struct hibernate_arena_interval
    hibernate_arena_excluded[HIBERNATE_ARENA_INTERVAL_MAX];

static int
hibernate_arena_add(uint64_t a, uint64_t b, uint64_t *result)
{
	if (__builtin_add_overflow(a, b, result))
		return (EOVERFLOW);
	return (0);
}

static int
hibernate_arena_mul(uint64_t a, uint64_t b, uint64_t *result)
{
	if (__builtin_mul_overflow(a, b, result))
		return (EOVERFLOW);
	return (0);
}

int
hibernate_arena_required(struct hibernate_arena_sizing *sizing)
{
	struct hibernate_arena_sizing local;
	uint64_t descriptor_unaligned, raw;
	int error;

	if (sizing == NULL)
		return (EINVAL);
	__builtin_memset(&local, 0, sizeof(local));

	error = hibernate_arena_mul(HIBERNATE_ARENA_PRIVATE_PT_PAGES,
	    HIBERNATE_ARENA_ALIGNMENT, &local.has_private_page_tables);
	if (error != 0)
		goto out;
	error = hibernate_arena_mul(HIBERNATE_ARENA_COPY_RUN_MAX,
	    HIBERNATE_ARENA_COPY_RUN_BYTES, &local.has_copy_run_storage);
	if (error != 0)
		goto out;
	error = hibernate_arena_mul(HIBERNATE_ARENA_AUX_DESCRIPTOR_MAX,
	    HIBERNATE_ARENA_AUX_DESCRIPTOR_BYTES,
	    &local.has_aux_descriptor_storage);
	if (error != 0)
		goto out;
	error = hibernate_arena_add(local.has_copy_run_storage,
	    local.has_aux_descriptor_storage, &descriptor_unaligned);
	if (error != 0)
		goto out;
	error = align_up_checked(descriptor_unaligned,
	    HIBERNATE_ARENA_ALIGNMENT, &local.has_descriptor_storage);
	if (error != 0)
		goto out;
	error = hibernate_arena_mul(HIBERNATE_ARENA_OBJECT_ALIGNMENTS,
	    HIBERNATE_ARENA_ALIGNMENT - 1, &local.has_alignment_allowance);
	if (error != 0)
		goto out;

	raw = 0;
#define HIBERNATE_ARENA_ADD_COMPONENT(component)                     \
	do {                                                         \
		error = hibernate_arena_add(raw, (component), &raw); \
		if (error != 0)                                      \
			goto out;                                    \
	} while (0)
	HIBERNATE_ARENA_ADD_COMPONENT(HIBERNATE_ARENA_HEADER_BYTES);
	HIBERNATE_ARENA_ADD_COMPONENT(HIBERNATE_ARENA_TRAMPOLINE_BYTES);
	HIBERNATE_ARENA_ADD_COMPONENT(HIBERNATE_ARENA_STACK_BYTES);
	HIBERNATE_ARENA_ADD_COMPONENT(local.has_private_page_tables);
	HIBERNATE_ARENA_ADD_COMPONENT(HIBERNATE_ARENA_HANDOFF_BYTES);
	HIBERNATE_ARENA_ADD_COMPONENT(local.has_descriptor_storage);
	HIBERNATE_ARENA_ADD_COMPONENT(local.has_alignment_allowance);
	HIBERNATE_ARENA_ADD_COMPONENT(HIBERNATE_ARENA_BOUNDED_SLACK_BYTES);
#undef HIBERNATE_ARENA_ADD_COMPONENT

	local.has_raw_required = raw;
	error = align_up_checked(raw, HIBERNATE_ARENA_ALIGNMENT,
	    &local.has_required);
	if (error != 0)
		goto out;
	if (local.has_required == 0 ||
	    local.has_required > HIBERNATE_ARENA_PHYS_LIMIT ||
	    (vm_size_t)local.has_required != local.has_required)
		error = EOVERFLOW;
out:
	if (error != 0)
		__builtin_memset(&local, 0, sizeof(local));
	*sizing = local;
	return (error);
}

static int
hibernate_arena_interval_cmp(const struct hibernate_arena_interval *a,
    const struct hibernate_arena_interval *b)
{
	if (a->hai_start < b->hai_start)
		return (-1);
	if (a->hai_start > b->hai_start)
		return (1);
	if (a->hai_end < b->hai_end)
		return (-1);
	if (a->hai_end > b->hai_end)
		return (1);
	if (a->hai_class < b->hai_class)
		return (-1);
	if (a->hai_class > b->hai_class)
		return (1);
	return (0);
}

static enum hibernate_arena_interval_class
hibernate_arena_restrictive_class(enum hibernate_arena_interval_class left,
    enum hibernate_arena_interval_class right)
{
	return (left > right ? left : right);
}

int
hibernate_arena_normalize(const struct hibernate_arena_interval *input,
    size_t input_count, struct hibernate_arena_interval *output,
    size_t output_capacity, size_t *output_count)
{
	enum hibernate_arena_interval_class class;
	vm_paddr_t *endpoints;
	struct hibernate_arena_interval *sorted;
	size_t endpoint_count, i, j, n;
	bool covered;

	endpoints = hibernate_arena_endpoints;
	sorted = hibernate_arena_sorted;
	if (output_count == NULL)
		return (EINVAL);
	*output_count = 0;
	if (input == NULL || output == NULL || input_count == 0 ||
	    input_count > HIBERNATE_ARENA_INTERVAL_MAX)
		return (EINVAL);

	endpoint_count = input_count * 2;
	for (i = 0; i < input_count; i++) {
		if (input[i].hai_start >= input[i].hai_end ||
		    input[i].hai_class < HAIC_ELIGIBLE ||
		    input[i].hai_class > HAIC_INELIGIBLE_LIVE)
			return (EINVAL);
		sorted[i] = input[i];
		endpoints[i * 2] = input[i].hai_start;
		endpoints[i * 2 + 1] = input[i].hai_end;
	}
	for (i = 1; i < input_count; i++) {
		struct hibernate_arena_interval value;

		value = sorted[i];
		for (j = i; j > 0 &&
		    hibernate_arena_interval_cmp(&value, &sorted[j - 1]) < 0;
		    j--)
			sorted[j] = sorted[j - 1];
		sorted[j] = value;
	}
	for (i = 1; i < endpoint_count; i++) {
		vm_paddr_t value;

		value = endpoints[i];
		for (j = i; j > 0 && value < endpoints[j - 1]; j--)
			endpoints[j] = endpoints[j - 1];
		endpoints[j] = value;
	}
	for (i = 0, j = 0; i < endpoint_count; i++) {
		if (j == 0 || endpoints[i] != endpoints[j - 1])
			endpoints[j++] = endpoints[i];
	}
	endpoint_count = j;

	n = 0;
	for (i = 0; i + 1 < endpoint_count; i++) {
		if (endpoints[i] == endpoints[i + 1])
			continue;
		covered = false;
		class = HAIC_ELIGIBLE;
		for (j = 0; j < input_count; j++) {
			if (sorted[j].hai_start > endpoints[i] ||
			    sorted[j].hai_end < endpoints[i + 1])
				continue;
			if (!covered) {
				class = sorted[j].hai_class;
				covered = true;
			} else {
				class = hibernate_arena_restrictive_class(class,
				    sorted[j].hai_class);
			}
		}
		if (!covered)
			continue;
		if (n != 0 && output[n - 1].hai_end == endpoints[i] &&
		    output[n - 1].hai_class == class) {
			output[n - 1].hai_end = endpoints[i + 1];
			continue;
		}
		if (n == output_capacity)
			return (EOVERFLOW);
		output[n].hai_start = endpoints[i];
		output[n].hai_end = endpoints[i + 1];
		output[n].hai_class = class;
		n++;
	}
	*output_count = n;
	return (n == 0 ? EINVAL : 0);
}

int
hibernate_arena_exclude_live(struct hibernate_arena_interval *intervals,
    size_t *count, size_t capacity, vm_paddr_t start, vm_paddr_t end)
{
	struct hibernate_arena_interval *output;
	size_t i, n;

	output = hibernate_arena_excluded;
	if (intervals == NULL || count == NULL || start >= end ||
	    *count > capacity || capacity > HIBERNATE_ARENA_INTERVAL_MAX)
		return (EINVAL);
	n = 0;
	for (i = 0; i < *count; i++) {
		struct hibernate_arena_interval current;

		current = intervals[i];
		if (current.hai_start >= current.hai_end)
			return (EINVAL);
		if (current.hai_class != HAIC_ELIGIBLE ||
		    end <= current.hai_start || start >= current.hai_end) {
			if (n == capacity)
				return (EOVERFLOW);
			output[n++] = current;
			continue;
		}
		if (current.hai_start < start) {
			if (n == capacity)
				return (EOVERFLOW);
			output[n] = current;
			output[n++].hai_end = start;
		}
		if (end < current.hai_end) {
			if (n == capacity)
				return (EOVERFLOW);
			output[n] = current;
			output[n].hai_start = end;
			n++;
		}
	}
	__builtin_memcpy(intervals, output, n * sizeof(output[0]));
	*count = n;
	return (0);
}

int
hibernate_arena_select(const struct hibernate_arena_interval *intervals,
    size_t count, uint64_t policy_bound, vm_paddr_t *pa, vm_size_t *size)
{
	struct hibernate_arena_sizing sizing;
	vm_paddr_t best_start, best_end, candidate, candidate_end;
	size_t i;
	int error;

	if (intervals == NULL || count == 0 || pa == NULL || size == NULL)
		return (EINVAL);
	*pa = 0;
	*size = 0;
	if (policy_bound == 0 ||
	    (policy_bound & (HIBERNATE_ARENA_ALIGNMENT - 1)) != 0 ||
	    policy_bound > HIBERNATE_ARENA_PHYS_LIMIT)
		return (EINVAL);
	error = hibernate_arena_required(&sizing);
	if (error != 0)
		return (error);
	if (sizing.has_required > policy_bound)
		return (ENOMEM);

	best_start = 0;
	best_end = 0;
	for (i = 0; i < count; i++) {
		if (intervals[i].hai_start >= intervals[i].hai_end)
			return (EINVAL);
		if (intervals[i].hai_class != HAIC_ELIGIBLE ||
		    intervals[i].hai_end > HIBERNATE_ARENA_PHYS_LIMIT)
			continue;
		if (intervals[i].hai_end - intervals[i].hai_start <
		    sizing.has_required)
			continue;
		candidate = (intervals[i].hai_end - sizing.has_required) &
		    ~(HIBERNATE_ARENA_ALIGNMENT - 1);
		if (candidate < intervals[i].hai_start ||
		    __builtin_add_overflow(candidate, sizing.has_required,
			&candidate_end) ||
		    candidate_end > intervals[i].hai_end ||
		    candidate_end > HIBERNATE_ARENA_PHYS_LIMIT)
			continue;
		if (best_end == 0 || intervals[i].hai_end > best_end ||
		    (intervals[i].hai_end == best_end &&
			candidate > best_start)) {
			best_start = candidate;
			best_end = intervals[i].hai_end;
		}
	}
	if (best_end == 0)
		return (ENOMEM);
	*pa = best_start;
	*size = (vm_size_t)sizing.has_required;
	return (0);
}

int
hibernate_arena_split_pairs(const vm_paddr_t *input, size_t input_count,
    vm_paddr_t arena_start, vm_paddr_t arena_end, vm_paddr_t *output,
    size_t output_capacity, size_t *output_count)
{
	vm_paddr_t start, end;
	size_t i, n;

	if (output_count == NULL)
		return (EINVAL);
	*output_count = 0;
	if (input == NULL || output == NULL || input_count % 2 != 0 ||
	    arena_start >= arena_end)
		return (EINVAL);
	n = 0;
	for (i = 0; i < input_count; i += 2) {
		start = input[i];
		end = input[i + 1];
		if (start >= end || (i != 0 && input[i - 1] > start))
			return (EINVAL);
#define HIBERNATE_ARENA_EMIT(pair_start, pair_end)                  \
	do {                                                        \
		if (n > output_capacity || output_capacity - n < 2) \
			return (EOVERFLOW);                         \
		output[n++] = (pair_start);                         \
		output[n++] = (pair_end);                           \
	} while (0)
		if (end <= arena_start || start >= arena_end) {
			HIBERNATE_ARENA_EMIT(start, end);
		} else {
			if (start < arena_start)
				HIBERNATE_ARENA_EMIT(start, arena_start);
			if (end > arena_end)
				HIBERNATE_ARENA_EMIT(arena_end, end);
		}
#undef HIBERNATE_ARENA_EMIT
	}
	*output_count = n;
	return (0);
}

void
hibernate_arena_reset(void)
{
	__builtin_memset(&g_hibernate_early_arena, 0,
	    sizeof(g_hibernate_early_arena));
	g_hibernate_arena_owner = NULL;
}

int
hibernate_arena_reserve(vm_paddr_t pa, vm_size_t size)
{
	vm_paddr_t end;

	if (size == 0 || (pa & (HIBERNATE_ARENA_ALIGNMENT - 1)) != 0 ||
	    ((uint64_t)size & (HIBERNATE_ARENA_ALIGNMENT - 1)) != 0)
		return (EINVAL);
	if (__builtin_add_overflow(pa, size, &end))
		return (EOVERFLOW);
	if (end > HIBERNATE_ARENA_PHYS_LIMIT)
		return (EINVAL);
	if (g_hibernate_early_arena.hea_valid) {
		if (!g_hibernate_early_arena.hea_claimed &&
		    g_hibernate_early_arena.hea_start == pa &&
		    g_hibernate_early_arena.hea_size == size &&
		    g_hibernate_early_arena.hea_rule_version ==
			HIBERNATE_ARENA_RULE_VERSION)
			return (0);
		return (EBUSY);
	}
	g_hibernate_early_arena.hea_start = pa;
	g_hibernate_early_arena.hea_size = size;
	g_hibernate_early_arena.hea_rule_version = HIBERNATE_ARENA_RULE_VERSION;
	g_hibernate_early_arena.hea_claimed = false;
	g_hibernate_early_arena.hea_valid = true;
	return (0);
}

int
hibernate_arena_claim(struct hibernate_attempt *ha)
{
	if (ha == NULL)
		return (EINVAL);
	if (!g_hibernate_early_arena.hea_valid ||
	    g_hibernate_early_arena.hea_rule_version !=
		HIBERNATE_ARENA_RULE_VERSION)
		return (EINVAL);
	if (ha->ha_arena_start != 0 || ha->ha_arena_size != 0) {
		if (g_hibernate_early_arena.hea_claimed &&
		    g_hibernate_arena_owner == ha &&
		    ha->ha_arena_start == g_hibernate_early_arena.hea_start &&
		    ha->ha_arena_size == g_hibernate_early_arena.hea_size)
			return (0);
		return (EINVAL);
	}
	if (g_hibernate_early_arena.hea_claimed)
		return (EBUSY);
	ha->ha_arena_start = g_hibernate_early_arena.hea_start;
	ha->ha_arena_size = g_hibernate_early_arena.hea_size;
	g_hibernate_arena_owner = ha;
	g_hibernate_early_arena.hea_claimed = true;
	return (0);
}

void
hibernate_arena_release(struct hibernate_attempt *ha)
{
	if (ha == NULL || !g_hibernate_early_arena.hea_valid ||
	    !g_hibernate_early_arena.hea_claimed)
		return;
	if (g_hibernate_arena_owner != ha ||
	    ha->ha_arena_start != g_hibernate_early_arena.hea_start ||
	    ha->ha_arena_size != g_hibernate_early_arena.hea_size)
		return;
	ha->ha_arena_start = 0;
	ha->ha_arena_size = 0;
	g_hibernate_arena_owner = NULL;
	g_hibernate_early_arena.hea_claimed = false;
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

	if (derived_pages_out == NULL)
		return (EINVAL);

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

/*
 * hibernate_dst_interval_contains: test whether physical address pa falls
 * within ha's published [start, end) destination-interval view.
 *
 * This is the pure, dual-build-compiled core shared by
 * hibernate_page_is_destination() (the kernel-only vm_page_t-based public
 * predicate, below) and the production publish-then-verify gate in
 * hibernate_writer_runs_verify().  Factoring the interval scan out of
 * hibernate_page_is_destination() lets the identical logic run in
 * userland tests, which cannot construct a real vm_page_t.
 *
 * Returns false when ha is NULL, no view has been published
 * (ha_dst_valid == false), or the interval array/count is empty.
 */
bool
hibernate_dst_interval_contains(const struct hibernate_attempt *ha,
    vm_paddr_t pa)
{
	uint64_t i;

	if (ha == NULL || !ha->ha_dst_valid ||
	    ha->ha_dst_intervals == NULL || ha->ha_dst_count == 0)
		return (false);

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
 * hibernate_dst_page_agrees: compare two independently derived
 * classifications for the single physical page at pa and report whether
 * they agree.
 *
 *   1. "expected": FREE-set/arena exclusion, recomputed from sorted_free
 *      and [arena_start, arena_end) using the identical merge-scan rule
 *      hibernate_writer_runs_build() applies while constructing runs.
 *   2. "predicate": hibernate_dst_interval_contains(ha, pa) -- the exact
 *      logic hibernate_page_is_destination() evaluates against the
 *      *published* view (ha->ha_dst_intervals / ha->ha_dst_valid).
 *
 * This is the pure, dual-build-compiled comparator shared by the
 * production hibernate_writer_runs_verify() gate and host-runnable tests,
 * which cannot walk vm_phys_segs[] directly.
 *
 * *free_idx is a monotonic merge-scan cursor the caller must carry across
 * strictly ascending pa values drawn from one sorted_free array; sorted_free
 * must already be sorted ascending (the same array hibernate_writer_runs_
 * build() produces via qsort(free_scratch, ...)).  arena_end == 0 means no
 * arena is in effect.
 *
 * Returns true when the expected classification and the predicate verdict
 * agree, false on any disagreement.
 */
bool
hibernate_dst_page_agrees(const struct hibernate_attempt *ha,
    const vm_paddr_t *sorted_free, size_t free_count, size_t *free_idx,
    vm_paddr_t arena_start, vm_paddr_t arena_end, vm_paddr_t pa)
{
	bool excluded, expected_dst, predicate_dst;

	while (*free_idx < free_count && sorted_free[*free_idx] < pa)
		(*free_idx)++;
	excluded = (*free_idx < free_count && sorted_free[*free_idx] == pa);
	if (excluded)
		(*free_idx)++;
	if (!excluded && arena_end != 0 &&
	    pa >= arena_start && pa < arena_end)
		excluded = true;

	expected_dst = !excluded;
	predicate_dst = hibernate_dst_interval_contains(ha, pa);
	return (expected_dst == predicate_dst);
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

	/*
	 * H-1 fix: delegate to the shared dual-build predicate core
	 * (hibernate_dst_interval_contains()) instead of duplicating the
	 * interval scan here.  This is the SAME function the production
	 * publish-then-verify gate (hibernate_writer_runs_verify(), via
	 * hibernate_dst_page_agrees()) calls once per ingested physical
	 * page, so this public entry point and the construction-time
	 * verification path are now provably evaluating identical logic.
	 */
	ha = atomic_load_ptr(&hibernate_current_attempt);
	return (hibernate_dst_interval_contains(ha, VM_PAGE_TO_PHYS(m)));
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

	/*
	 * K-9 arena ownership is attempt-scoped and independent of the barrier
	 * stage mask.  Keep the tuple valid through reservation unwind, then
	 * release it last.  Release is idempotent for refusal paths that never
	 * acquired ownership and for repeated common-unwind calls.
	 */
	hibernate_arena_release(ha);
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

/*
 * hib_vm_paddr_cmp: ascending vm_paddr_t comparator for qsort().
 */
static int
hib_vm_paddr_cmp(const void *a, const void *b)
{
	vm_paddr_t pa, pb;

	pa = *(const vm_paddr_t *)a;
	pb = *(const vm_paddr_t *)b;
	if (pa < pb)
		return (-1);
	if (pa > pb)
		return (1);
	return (0);
}

/*
 * hibernate_writer_runs_build: see declaration in sys/sys/hibernate.h.
 *
 * Single forward merge pass: segments are walked in increasing physical
 * address order (asserted non-overlapping and sorted as they are produced);
 * the locked FREE reservation is pre-sorted into free_scratch and consumed
 * with one monotonic cursor.  A destination page continues the open run
 * only when it is exactly one page above the previous destination page,
 * so a run closes at every FREE/arena exclusion and at every true gap
 * between segments, but spans adjacent segments transparently.
 */
int
hibernate_writer_runs_build(struct hibernate_attempt *ha,
    const struct vm_phys_reservation *res, vm_paddr_t *free_scratch,
    size_t free_scratch_capacity, uint64_t payload_cursor,
    struct hibernate_writer_run *runs, size_t runs_capacity,
    size_t *run_count_out)
{
	struct hibernate_writer_run *run;
	vm_paddr_t arena_end, pa, seg_start, seg_end, last_seg_end;
	vm_paddr_t run_start, prev_dest_pa;
	uint64_t cursor, run_pages, run_bytes;
	size_t free_idx, count, i;
	int segind;
	bool run_open;

	if (run_count_out == NULL)
		return (EINVAL);
	*run_count_out = 0;

	/*
	 * runs == NULL (with runs_capacity == 0) is a dry-run count pass:
	 * classification is identical, but no run is stored and runs_capacity
	 * is never consulted.  Callers use this to size the real runs[]
	 * array before a second, storing pass.  payload_cursor is ignored
	 * in dry-run mode (file offsets are not meaningful without it).
	 */
	if (ha == NULL || res == NULL ||
	    (runs == NULL) != (runs_capacity == 0))
		return (EINVAL);
	if (res->vr_count != 0 && free_scratch == NULL)
		return (EINVAL);
	if (res->vr_count > free_scratch_capacity)
		return (EINVAL);
	if (ha->ha_arena_size != 0 &&
	    __builtin_add_overflow(ha->ha_arena_start, ha->ha_arena_size,
		&arena_end))
		return (EOVERFLOW);
	if (ha->ha_arena_size == 0)
		arena_end = 0;

	for (i = 0; i < res->vr_count; i++)
		free_scratch[i] = VM_PAGE_TO_PHYS(res->vr_pages[i].vrp_page);
	if (res->vr_count > 1)
		qsort(free_scratch, res->vr_count, sizeof(free_scratch[0]),
		    hib_vm_paddr_cmp);

	if (align_up_checked(payload_cursor, HIB_PAGE_SIZE, &cursor) != 0)
		return (EOVERFLOW);

	count = 0;
	free_idx = 0;
	run_open = false;
	run_start = 0;
	run_pages = 0;
	prev_dest_pa = 0;
	last_seg_end = 0;

#define HIB_RUN_CLOSE()							\
	do {								\
		if (__builtin_mul_overflow(run_pages,			\
			(uint64_t)HIB_PAGE_SIZE, &run_bytes))		\
			return (EOVERFLOW);				\
		if (runs != NULL) {					\
			if (count >= runs_capacity)			\
				return (E2BIG);				\
			run = &runs[count];				\
			run->hwr_destination = run_start;		\
			run->hwr_file_offset = cursor;			\
			run->hwr_length = run_bytes;			\
			run->hwr_source = 0;				\
			run->hwr_source_offset = (uint64_t)run_start;	\
			if (__builtin_add_overflow(cursor, run_bytes,	\
				&cursor))				\
				return (EOVERFLOW);			\
		}							\
		count++;						\
	} while (0)

	for (segind = 0; segind < vm_phys_nsegs; segind++) {
		seg_start = vm_phys_segs[segind].start;
		seg_end = vm_phys_segs[segind].end;
		if (seg_start >= seg_end)
			return (EINVAL);
		if (segind != 0 && seg_start < last_seg_end)
			return (EINVAL);
		last_seg_end = seg_end;

		for (pa = seg_start; pa < seg_end; pa += HIB_PAGE_SIZE) {
			bool excluded;

			while (free_idx < res->vr_count &&
			    free_scratch[free_idx] < pa)
				free_idx++;
			excluded = (free_idx < res->vr_count &&
			    free_scratch[free_idx] == pa);
			if (excluded)
				free_idx++;
			if (!excluded && arena_end != 0 &&
			    pa >= ha->ha_arena_start && pa < arena_end)
				excluded = true;

			if (excluded) {
				if (run_open) {
					HIB_RUN_CLOSE();
					run_open = false;
				}
				continue;
			}

			if (run_open &&
			    pa == prev_dest_pa + HIB_PAGE_SIZE) {
				run_pages++;
			} else {
				if (run_open)
					HIB_RUN_CLOSE();
				run_open = true;
				run_start = pa;
				run_pages = 1;
			}
			prev_dest_pa = pa;
		}
	}

	if (run_open)
		HIB_RUN_CLOSE();

#undef HIB_RUN_CLOSE

	*run_count_out = count;
	return (0);
}

/*
 * hibernate_writer_runs_verify: H-1 fix -- publish-then-verify gate.
 *
 * issue #8 mandates that PT_LOAD destinations be selected "using
 * hibernate_page_is_destination()".  hibernate_writer_runs_build() builds
 * the maximal destination-run set directly from live state (FREE-set/arena
 * merge-scan) because the predicate cannot classify anything until a view
 * has been published -- there is no destination view before construction.
 *
 * This function closes that gap with publish-then-verify: the caller
 * (hibernate_writer_plan_live()) publishes the just-built run-derived view
 * (ha_dst_intervals / ha_dst_count / ha_dst_valid) FIRST, and then calls
 * this function, which walks every ingested physical page in
 * vm_phys_segs[] EXACTLY ONCE and checks each one through
 * hibernate_dst_page_agrees() -- which in turn evaluates
 * hibernate_dst_interval_contains(), the IDENTICAL logic
 * hibernate_page_is_destination() uses against hibernate_current_attempt.
 * The independently recomputed FREE/arena classification is compared
 * against the predicate's verdict for every page; any single mismatch
 * invalidates the view (ha_dst_valid = false) and the function returns
 * EINVAL, which the caller propagates as a refusal of the image.
 *
 * This makes the mandated predicate genuinely live and material: the
 * production path cannot publish a passing view without the predicate
 * itself agreeing, page for page, with the construction logic.
 *
 * Preconditions: ha->ha_dst_valid must already be true and
 * ha->ha_dst_intervals/ha_dst_count must already describe the exact view
 * being verified (the caller publishes before calling, per the function
 * name).  res and free_scratch are the same reservation and scratch buffer
 * passed to the preceding hibernate_writer_runs_build() call.
 *
 * Returns 0 when every ingested page's predicate verdict agrees with the
 * expected FREE/arena classification.  Returns EINVAL on any argument
 * problem, on disagreement, or if ha_dst_valid is not already true (the
 * view must be published before verification, not after).  On EINVAL from
 * disagreement, ha_dst_valid is forced false before returning so no later
 * reader can observe a partially-trusted view.
 */
int
hibernate_writer_runs_verify(struct hibernate_attempt *ha,
    const struct vm_phys_reservation *res, vm_paddr_t *free_scratch,
    size_t free_scratch_capacity)
{
	vm_paddr_t arena_end, pa, seg_start, seg_end, last_seg_end;
	size_t free_idx, i;
	int segind;

	if (ha == NULL || res == NULL || !ha->ha_dst_valid)
		return (EINVAL);
	if (res->vr_count != 0 && free_scratch == NULL)
		return (EINVAL);
	if (res->vr_count > free_scratch_capacity)
		return (EINVAL);
	if (ha->ha_arena_size != 0 &&
	    __builtin_add_overflow(ha->ha_arena_start, ha->ha_arena_size,
		&arena_end))
		return (EOVERFLOW);
	if (ha->ha_arena_size == 0)
		arena_end = 0;

	/*
	 * Re-sort a fresh copy of the FREE set into free_scratch.  This is
	 * the same caller-owned scratch buffer hibernate_writer_runs_build()
	 * just used; re-populating it here keeps this function independently
	 * correct (it does not rely on the scratch buffer's contents having
	 * survived unmodified) at the cost of one more O(n log n) sort.
	 */
	for (i = 0; i < res->vr_count; i++)
		free_scratch[i] = VM_PAGE_TO_PHYS(res->vr_pages[i].vrp_page);
	if (res->vr_count > 1)
		qsort(free_scratch, res->vr_count, sizeof(free_scratch[0]),
		    hib_vm_paddr_cmp);

	free_idx = 0;
	last_seg_end = 0;
	for (segind = 0; segind < vm_phys_nsegs; segind++) {
		seg_start = vm_phys_segs[segind].start;
		seg_end = vm_phys_segs[segind].end;
		if (seg_start >= seg_end) {
			ha->ha_dst_valid = false;
			return (EINVAL);
		}
		if (segind != 0 && seg_start < last_seg_end) {
			ha->ha_dst_valid = false;
			return (EINVAL);
		}
		last_seg_end = seg_end;

		for (pa = seg_start; pa < seg_end; pa += HIB_PAGE_SIZE) {
			if (!hibernate_dst_page_agrees(ha, free_scratch,
				res->vr_count, &free_idx, ha->ha_arena_start,
				arena_end, pa)) {
				/*
				 * The mandated predicate disagrees with the
				 * independently recomputed classification for
				 * this page: refuse to trust the published
				 * view and refuse the image.
				 */
				ha->ha_dst_valid = false;
				return (EINVAL);
			}
		}
	}

	return (0);
}

#endif /* !_HIBERNATE_USERLAND_BUILD */

/*
 * Encode the fixed ABI 1 control block into its canonical little-endian wire
 * representation.  The complete destination is cleared first, so every
 * reserved byte and the high half of hc_crc32c remain zero.
 *
 * The initial image stream always carries eight zero CRC bytes.  K-6 rewrites
 * only the low four bytes after completing whole-image CRC calculation.
 */
int
hibernate_cb_encode(uint8_t *buf, size_t len, const struct hibernate_cb *cb)
{
	if (buf == NULL || cb == NULL || len != HIBERNATE_CB_ENCODED_SIZE)
		return (EINVAL);
	if (cb->hc_version != HCB_VERSION ||
	    cb->hc_encoded_size != HIBERNATE_CB_ENCODED_SIZE ||
	    cb->hc_page_size != HIB_PAGE_SIZE ||
	    cb->hc_machine_flags != 0 ||
	    cb->hc_saved_pcb_size != HIBERNATE_PCB_ENCODED_SIZE ||
	    cb->hc_payload_start == 0 ||
	    cb->hc_payload_start > 64029 ||
	    cb->hc_payload_start > HIBERNATE_META_BUF_MAX ||
	    cb->hc_metadata_length != cb->hc_payload_start ||
	    cb->hc_payload_start > cb->hc_image_length)
		return (EINVAL);

	__builtin_memset(buf, 0, HIBERNATE_CB_ENCODED_SIZE);
	le64enc(buf + HIBERNATE_CB_OFF_MAGIC, cb->hc_magic);
	le32enc(buf + HIBERNATE_CB_OFF_VERSION, cb->hc_version);
	le32enc(buf + HIBERNATE_CB_OFF_ENCODED_SIZE, cb->hc_encoded_size);
	le64enc(buf + HIBERNATE_CB_OFF_PAGE_SIZE, cb->hc_page_size);
	le64enc(buf + HIBERNATE_CB_OFF_PHYSMEM_BYTES,
	    cb->hc_physmem_bytes);
	le64enc(buf + HIBERNATE_CB_OFF_IMAGE_LENGTH,
	    cb->hc_image_length);
	le64enc(buf + HIBERNATE_CB_OFF_PAYLOAD_START,
	    cb->hc_payload_start);
	le64enc(buf + HIBERNATE_CB_OFF_DESTINATION_PAGES,
	    cb->hc_destination_pages);
	le64enc(buf + HIBERNATE_CB_OFF_SOURCE_VECTOR_BYTES,
	    cb->hc_source_vector_bytes);
	le64enc(buf + HIBERNATE_CB_OFF_ARENA_START, cb->hc_arena_start);
	le64enc(buf + HIBERNATE_CB_OFF_ARENA_SIZE, cb->hc_arena_size);
	le64enc(buf + HIBERNATE_CB_OFF_FACS_HARDWARE_SIGNATURE,
	    cb->hc_facs_hardware_signature);
	le64enc(buf + HIBERNATE_CB_OFF_SAVED_PCB_OFFSET,
	    cb->hc_saved_pcb_offset);
	le64enc(buf + HIBERNATE_CB_OFF_SAVED_PCB_SIZE,
	    cb->hc_saved_pcb_size);
	le64enc(buf + HIBERNATE_CB_OFF_ELF_PHNUM, cb->hc_elf_phnum);
	le64enc(buf + HIBERNATE_CB_OFF_METADATA_LENGTH,
	    cb->hc_metadata_length);
	/*
	 * HIBERNATE_CB_WIDTH_CRC32C is eight bytes.  Both halves stay zero
	 * during the forward stream, irrespective of the host-order field.
	 */
	le64enc(buf + HIBERNATE_CB_OFF_RESTORE_FOOTPRINT_PAGES,
	    cb->hc_restore_footprint_pages);
	le64enc(buf + HIBERNATE_CB_OFF_MACHINE_FLAGS,
	    cb->hc_machine_flags);
	le64enc(buf + HIBERNATE_CB_OFF_DESTINATION_BYTES,
	    cb->hc_destination_bytes);
	le64enc(buf + HIBERNATE_CB_OFF_COPY_LIST_BOUND,
	    cb->hc_copy_list_bound);
	return (0);
}

/*
 * Derive the exact standard-format XSAVE extent from an enabled XCR0 mask and
 * synthetic CPUID leaf 0xD component facts.
 *
 * The architectural legacy region and XSAVE header occupy the first 576
 * bytes.  Each enabled component numbered 2 or above must have exactly one
 * nonempty fact.  Disabled, duplicate, legacy-region, out-of-mask and
 * unrepresentable facts are rejected rather than ignored.
 */
int
hibernate_xsave_extent(uint64_t enabled_mask,
    const struct hibernate_xsave_component_fact *facts, size_t fact_count,
    uint32_t *extentp)
{
	const struct hibernate_xsave_component_fact *fact;
	uint64_t bit, seen;
	uint32_t end, extent;
	size_t i;

	if (extentp == NULL)
		return (EINVAL);
	*extentp = 0;

	if ((enabled_mask & HIBERNATE_XCR0_REQUIRED_MASK) !=
	    HIBERNATE_XCR0_REQUIRED_MASK ||
	    (enabled_mask & ~HIBERNATE_XCR0_SUPPORTED_MASK) != 0)
		return (EINVAL);
	if (fact_count != 0 && facts == NULL)
		return (EINVAL);

	extent = HIBERNATE_PCB_XSAVE_MIN;
	seen = 0;
	for (i = 0; i < fact_count; i++) {
		fact = &facts[i];
		if (fact->hxcf_component < 2 ||
		    fact->hxcf_component >= 64 ||
		    fact->hxcf_size == 0)
			return (EINVAL);

		bit = UINT64_C(1) << fact->hxcf_component;
		if ((enabled_mask & bit) == 0 || (seen & bit) != 0)
			return (EINVAL);
		if (fact->hxcf_offset < HIBERNATE_PCB_XSAVE_MIN)
			return (EINVAL);
		if (__builtin_add_overflow(fact->hxcf_offset,
			fact->hxcf_size, &end))
			return (EOVERFLOW);

		seen |= bit;
		if (end > extent)
			extent = end;
	}

	/*
	 * Components 0 and 1 are represented by the fixed legacy region.
	 * Every other enabled component must have exactly one supplied fact.
	 */
	if (seen !=
	    (enabled_mask & ~HIBERNATE_XCR0_REQUIRED_MASK))
		return (EINVAL);

	*extentp = extent;
	return (0);
}

/*
 * Encode the fixed ABI 1 amd64 PCB descriptor.  XSAVE bytes are not inline:
 * one standard-format, 64-byte-aligned payload object is described here and
 * emitted separately by the portable writer.
 */
int
hibernate_pcb_encode(uint8_t *buf, size_t len,
    const struct hibernate_pcb *pcb)
{
	uint64_t required;

	if (buf == NULL || pcb == NULL ||
	    len != HIBERNATE_PCB_ENCODED_SIZE)
		return (EINVAL);
	if (pcb->hp_version != 1 ||
	    pcb->hp_encoded_size != HIBERNATE_PCB_ENCODED_SIZE)
		return (EINVAL);
	if ((pcb->hp_xcr0 & ~HIBERNATE_XCR0_SUPPORTED_MASK) != 0)
		return (EINVAL);
	required = HIBERNATE_XCR0_REQUIRED_MASK;
	if ((pcb->hp_xcr0 & required) != required ||
	    pcb->hp_xsave_enabled_mask != pcb->hp_xcr0)
		return (EINVAL);
	if (pcb->hp_xsave_format != HIBERNATE_XSAVE_FORMAT ||
	    pcb->hp_xsave_length < HIBERNATE_PCB_XSAVE_MIN ||
	    pcb->hp_xsave_offset == 0 ||
	    (pcb->hp_xsave_offset &
		(HIBERNATE_PCB_ALIGNMENT - 1)) != 0)
		return (EINVAL);

	__builtin_memset(buf, 0, HIBERNATE_PCB_ENCODED_SIZE);
	le32enc(buf + HIBERNATE_PCB_OFF_VERSION, pcb->hp_version);
	le32enc(buf + HIBERNATE_PCB_OFF_ENCODED_SIZE,
	    pcb->hp_encoded_size);
	le64enc(buf + HIBERNATE_PCB_OFF_CR0, pcb->hp_cr0);
	le64enc(buf + HIBERNATE_PCB_OFF_CR3, pcb->hp_cr3);
	le64enc(buf + HIBERNATE_PCB_OFF_CR4, pcb->hp_cr4);
	le64enc(buf + HIBERNATE_PCB_OFF_EFER, pcb->hp_efer);
	le64enc(buf + HIBERNATE_PCB_OFF_PAT, pcb->hp_pat);
	le64enc(buf + HIBERNATE_PCB_OFF_XCR0, pcb->hp_xcr0);
	le64enc(buf + HIBERNATE_PCB_OFF_RFLAGS, pcb->hp_rflags);
	le64enc(buf + HIBERNATE_PCB_OFF_RSP, pcb->hp_rsp);
	le64enc(buf + HIBERNATE_PCB_OFF_RIP, pcb->hp_rip);
	le64enc(buf + HIBERNATE_PCB_OFF_R12_PCB_PA,
	    pcb->hp_r12_pcb_pa);
	le16enc(buf + HIBERNATE_PCB_OFF_GDTR_LIMIT,
	    pcb->hp_gdtr_limit);
	le64enc(buf + HIBERNATE_PCB_OFF_GDTR_BASE,
	    pcb->hp_gdtr_base);
	le16enc(buf + HIBERNATE_PCB_OFF_IDTR_LIMIT,
	    pcb->hp_idtr_limit);
	le64enc(buf + HIBERNATE_PCB_OFF_IDTR_BASE,
	    pcb->hp_idtr_base);
	le64enc(buf + HIBERNATE_PCB_OFF_FSBASE, pcb->hp_fsbase);
	le64enc(buf + HIBERNATE_PCB_OFF_GSBASE, pcb->hp_gsbase);
	le64enc(buf + HIBERNATE_PCB_OFF_KGSBASE, pcb->hp_kgsbase);
	le64enc(buf + HIBERNATE_PCB_OFF_STAR, pcb->hp_star);
	le64enc(buf + HIBERNATE_PCB_OFF_LSTAR, pcb->hp_lstar);
	le64enc(buf + HIBERNATE_PCB_OFF_CSTAR, pcb->hp_cstar);
	le64enc(buf + HIBERNATE_PCB_OFF_SFMASK, pcb->hp_sfmask);
	le64enc(buf + HIBERNATE_PCB_OFF_KERNEL_GSBASE,
	    pcb->hp_kernel_gsbase);
	le32enc(buf + HIBERNATE_PCB_OFF_XSAVE_LENGTH,
	    pcb->hp_xsave_length);
	le32enc(buf + HIBERNATE_PCB_OFF_XSAVE_FORMAT,
	    pcb->hp_xsave_format);
	le64enc(buf + HIBERNATE_PCB_OFF_XSAVE_OFFSET,
	    pcb->hp_xsave_offset);
	le64enc(buf + HIBERNATE_PCB_OFF_XSAVE_ENABLED_MASK,
	    pcb->hp_xsave_enabled_mask);
	return (0);
}

/*
 * Encode one ELF64 program header without relying on a native ELF layout.
 */
static void
hibernate_writer_phdr_encode(uint8_t *ph, uint32_t type, uint64_t offset,
    uint64_t filesz, uint64_t paddr, uint64_t alignment)
{
	__builtin_memset(ph, 0, PHDR_SIZE);
	le32enc(ph + PHDR_OFF_P_TYPE, type);
	le64enc(ph + PHDR_OFF_P_OFFSET, offset);
	le64enc(ph + PHDR_OFF_P_PADDR, paddr);
	le64enc(ph + PHDR_OFF_P_FILESZ, filesz);
	le64enc(ph + PHDR_OFF_P_MEMSZ, filesz);
	le64enc(ph + 48, alignment);
}

/*
 * hibernate_writer_payload_start: see declaration in sys/sys/hibernate.h.
 * Shares the exact prefix-geometry arithmetic hibernate_writer_plan_assemble()
 * performs, so a caller computing run file offsets before assembly cannot
 * drift from what assembly itself will require.
 */
int
hibernate_writer_payload_start(size_t run_count, uint64_t *payload_start_out)
{
	uint64_t phdr_bytes, phdr_end, cb_offset, cb_end;
	uint64_t pcb_offset, pcb_end, payload_start;
	uint64_t phnum64;
	int error;

	if (payload_start_out == NULL)
		return (EINVAL);
	*payload_start_out = 0;
	if (run_count == 0 || run_count > HIBERNATE_MAX_PHDRS - 3)
		return (EINVAL);

	if (__builtin_add_overflow((uint64_t)run_count, UINT64_C(3),
		&phnum64) ||
	    phnum64 > HIBERNATE_MAX_PHDRS || phnum64 > UINT16_MAX)
		return (EOVERFLOW);
	if (__builtin_mul_overflow(phnum64, (uint64_t)PHDR_SIZE,
		&phdr_bytes) ||
	    __builtin_add_overflow((uint64_t)EHDR_SIZE, phdr_bytes,
		&phdr_end))
		return (EOVERFLOW);
	if (phdr_end > 50464)
		return (E2BIG);

	error = align_up_checked(phdr_end, HIB_PAGE_SIZE, &cb_offset);
	if (error != 0)
		return (error);
	if (__builtin_add_overflow(cb_offset,
		(uint64_t)HIBERNATE_CB_ENCODED_SIZE, &cb_end))
		return (EOVERFLOW);
	error = align_up_checked(cb_end, HIB_PAGE_SIZE, &pcb_offset);
	if (error != 0)
		return (error);
	if (__builtin_add_overflow(pcb_offset,
		(uint64_t)HIBERNATE_PCB_ENCODED_SIZE, &pcb_end))
		return (EOVERFLOW);
	error = align_up_checked(pcb_end, HIB_PAGE_SIZE, &payload_start);
	if (error != 0)
		return (error);
	if (payload_start == 0 || payload_start > 64029 ||
	    payload_start > HIBERNATE_META_BUF_MAX)
		return (E2BIG);

	*payload_start_out = payload_start;
	return (0);
}

/*
 * Assemble and self-decode the immutable ABI 1 writer plan.
 *
 * The caller supplies the exact intended payload file offsets.  Requiring
 * each object to begin at the cursor's canonical aligned position detects
 * omitted gaps, interleaving, backward motion, and duplicate slices before
 * any provider operation can begin.
 */
int
hibernate_writer_plan_assemble(struct hibernate_writer_plan *plan,
    const struct hibernate_cb *input_cb,
    const struct hibernate_pcb *input_pcb)
{
	struct hibernate_cb cb;
	struct hibernate_pcb pcb;
	struct hibernate_image image;
	const struct hibernate_writer_run *run, *other;
	uint8_t *prefix, *ph;
	uint64_t phdr_bytes, phdr_end, cb_offset, cb_end;
	uint64_t pcb_offset, pcb_end, payload_start;
	uint64_t cursor, image_length, destination_bytes;
	uint64_t destination_pages, destination_end, arena_end;
	uint64_t source_end, other_source_end, xsave_end;
	uint64_t phnum64;
	uint16_t phnum;
	size_t i, j;
	int error;

	if (plan == NULL || input_cb == NULL || input_pcb == NULL)
		return (EINVAL);
	plan->hwp_prefix_length = 0;
	__builtin_memset(&plan->hwp_image, 0, sizeof(plan->hwp_image));
	__builtin_memset(&plan->hwp_iterator, 0, sizeof(plan->hwp_iterator));

	if (plan->hwp_prefix == NULL ||
	    (plan->hwp_run_count != 0 && plan->hwp_runs == NULL) ||
	    plan->hwp_run_count == 0 ||
	    plan->hwp_run_count > HIBERNATE_MAX_PHDRS - 3)
		return (EINVAL);

	if (__builtin_add_overflow((uint64_t)plan->hwp_run_count,
		UINT64_C(3), &phnum64) ||
	    phnum64 > HIBERNATE_MAX_PHDRS || phnum64 > UINT16_MAX)
		return (EOVERFLOW);
	phnum = (uint16_t)phnum64;

	if (__builtin_mul_overflow(phnum64, (uint64_t)PHDR_SIZE,
		&phdr_bytes) ||
	    __builtin_add_overflow((uint64_t)EHDR_SIZE, phdr_bytes,
		&phdr_end))
		return (EOVERFLOW);
	if (phdr_end > 50464)
		return (E2BIG);

	error = align_up_checked(phdr_end, HIB_PAGE_SIZE, &cb_offset);
	if (error != 0)
		return (error);
	if (__builtin_add_overflow(cb_offset,
		(uint64_t)HIBERNATE_CB_ENCODED_SIZE, &cb_end))
		return (EOVERFLOW);
	error = align_up_checked(cb_end, HIB_PAGE_SIZE, &pcb_offset);
	if (error != 0)
		return (error);
	if (__builtin_add_overflow(pcb_offset,
		(uint64_t)HIBERNATE_PCB_ENCODED_SIZE, &pcb_end))
		return (EOVERFLOW);
	error = align_up_checked(pcb_end, HIB_PAGE_SIZE, &payload_start);
	if (error != 0)
		return (error);
	if (payload_start == 0 || payload_start > 64029 ||
	    payload_start > HIBERNATE_META_BUF_MAX ||
	    payload_start > plan->hwp_prefix_capacity)
		return (E2BIG);

	cb = *input_cb;
	pcb = *input_pcb;
	destination_bytes = 0;
	destination_pages = 0;
	destination_end = 0;

	if (__builtin_add_overflow(cb.hc_arena_start, cb.hc_arena_size,
		&arena_end))
		return (EOVERFLOW);

	cursor = payload_start;
	if (pcb.hp_xsave_length < HIBERNATE_PCB_XSAVE_MIN)
		return (EINVAL);
	if (pcb.hp_xsave_offset != cursor ||
	    (pcb.hp_xsave_offset &
		(HIBERNATE_PCB_ALIGNMENT - 1)) != 0)
		return (EINVAL);
	if (__builtin_add_overflow(cursor, pcb.hp_xsave_length, &xsave_end))
		return (EOVERFLOW);
	cursor = xsave_end;

	for (i = 0; i < plan->hwp_run_count; i++) {
		run = &plan->hwp_runs[i];
		if (run->hwr_length == 0 ||
		    (run->hwr_destination & (HIB_PAGE_SIZE - 1)) != 0 ||
		    (run->hwr_file_offset & (HIB_PAGE_SIZE - 1)) != 0 ||
		    (run->hwr_length & (HIB_PAGE_SIZE - 1)) != 0)
			return (EINVAL);

		error = align_up_checked(cursor, HIB_PAGE_SIZE, &cursor);
		if (error != 0)
			return (error);
		if (run->hwr_file_offset != cursor)
			return (EINVAL);
		if (i != 0 && run->hwr_destination < destination_end)
			return (EINVAL);
		if (__builtin_add_overflow(run->hwr_destination,
			run->hwr_length, &destination_end))
			return (EOVERFLOW);

		if (cb.hc_arena_size != 0 &&
		    run->hwr_destination < arena_end &&
		    destination_end > cb.hc_arena_start)
			return (EINVAL);

		if (__builtin_add_overflow(run->hwr_source_offset,
			run->hwr_length, &source_end))
			return (EOVERFLOW);
		for (j = 0; j < i; j++) {
			other = &plan->hwp_runs[j];
			if (run->hwr_source != other->hwr_source)
				continue;
			if (__builtin_add_overflow(other->hwr_source_offset,
				other->hwr_length, &other_source_end))
				return (EOVERFLOW);
			if (run->hwr_source_offset < other_source_end &&
			    source_end > other->hwr_source_offset)
				return (EINVAL);
		}

		if (__builtin_add_overflow(destination_bytes,
			run->hwr_length, &destination_bytes) ||
		    __builtin_add_overflow(destination_pages,
			run->hwr_length / HIB_PAGE_SIZE,
			&destination_pages) ||
		    __builtin_add_overflow(cursor, run->hwr_length,
			&cursor))
			return (EOVERFLOW);
	}
	image_length = cursor;
	if (input_cb->hc_image_length != image_length ||
	    payload_start > image_length)
		return (EINVAL);

	cb.hc_payload_start = payload_start;
	cb.hc_metadata_length = payload_start;
	cb.hc_saved_pcb_offset = pcb_offset;
	cb.hc_saved_pcb_size = HIBERNATE_PCB_ENCODED_SIZE;
	cb.hc_elf_phnum = phnum;
	cb.hc_destination_pages = destination_pages;
	cb.hc_destination_bytes = destination_bytes;
	cb.hc_crc32c = 0;

	prefix = plan->hwp_prefix;
	__builtin_memset(prefix, 0, payload_start);
	prefix[EHDR_OFF_EI_MAG0] = ELFMAG0;
	prefix[EHDR_OFF_EI_MAG1] = ELFMAG1;
	prefix[EHDR_OFF_EI_MAG2] = ELFMAG2;
	prefix[EHDR_OFF_EI_MAG3] = ELFMAG3;
	prefix[EHDR_OFF_EI_CLASS] = ELFCLASS64;
	prefix[EHDR_OFF_EI_DATA] = ELFDATA2LSB;
	prefix[EHDR_OFF_EI_VERSION] = EV_CURRENT;
	le16enc(prefix + EHDR_OFF_E_TYPE, ET_FREEBSD_HIBERNATE_IMAGE);
	le16enc(prefix + EHDR_OFF_E_MACHINE, EM_X86_64);
	le32enc(prefix + EHDR_OFF_E_VERSION, EV_CURRENT);
	le64enc(prefix + EHDR_OFF_E_PHOFF, EHDR_SIZE);
	le16enc(prefix + EHDR_OFF_E_EHSIZE, EHDR_SIZE);
	le16enc(prefix + EHDR_OFF_E_PHENTSIZE, PHDR_SIZE);
	le16enc(prefix + EHDR_OFF_E_PHNUM, phnum);

	ph = prefix + EHDR_SIZE;
	hibernate_writer_phdr_encode(ph, PT_FREEBSD_HIBERNATE_CB,
	    cb_offset, HIBERNATE_CB_ENCODED_SIZE, 0,
	    HIBERNATE_CB_ALIGNMENT);
	ph += PHDR_SIZE;
	hibernate_writer_phdr_encode(ph, PT_FREEBSD_HIBERNATE_PCB,
	    pcb_offset, HIBERNATE_PCB_ENCODED_SIZE, 0,
	    HIBERNATE_PCB_ALIGNMENT);
	ph += PHDR_SIZE;
	hibernate_writer_phdr_encode(ph, PT_FREEBSD_HIBERNATE_XSAVE,
	    pcb.hp_xsave_offset, pcb.hp_xsave_length, 0,
	    HIBERNATE_PCB_ALIGNMENT);
	ph += PHDR_SIZE;
	for (i = 0; i < plan->hwp_run_count; i++) {
		run = &plan->hwp_runs[i];
		hibernate_writer_phdr_encode(ph, PT_LOAD,
		    run->hwr_file_offset, run->hwr_length,
		    run->hwr_destination, HIB_PAGE_SIZE);
		ph += PHDR_SIZE;
	}

	error = hibernate_cb_encode(prefix + cb_offset,
	    HIBERNATE_CB_ENCODED_SIZE, &cb);
	if (error != 0)
		return (error);
	error = hibernate_pcb_encode(prefix + pcb_offset,
	    HIBERNATE_PCB_ENCODED_SIZE, &pcb);
	if (error != 0)
		return (error);

	error = hibernate_image_decode(prefix, (size_t)payload_start, &image);
	if (error != 0)
		return (error);
	if (image.hi_phnum != phnum ||
	    image.hi_load_count != plan->hwp_run_count ||
	    image.hi_payload_start != payload_start ||
	    image.hi_image_length != image_length ||
	    image.hi_destination_bytes != destination_bytes ||
	    image.hi_destination_pages != destination_pages ||
	    image.hi_xsave_offset != pcb.hp_xsave_offset ||
	    image.hi_xsave_length != pcb.hp_xsave_length)
		return (EINVAL);

	plan->hwp_prefix_length = (size_t)payload_start;
	plan->hwp_image = image;
	plan->hwp_iterator.hii_image = &plan->hwp_image;
	plan->hwp_iterator.hii_phase = HIIP_METADATA;
	return (0);
}

/*
 * Forward-only seam for the later provider-streaming chunk.
 */
int
hibernate_writer_plan_interval_next(struct hibernate_writer_plan *plan,
    struct hibernate_image_interval *interval)
{
	if (plan == NULL || interval == NULL ||
	    plan->hwp_prefix_length == 0 ||
	    plan->hwp_iterator.hii_image != &plan->hwp_image)
		return (EINVAL);
	return (hibernate_image_interval_next(&plan->hwp_iterator, interval));
}

/*
 * hibernate_writer_plan_stream: the task-4 forward-stream driver.
 *
 * hibernate_writer_plan_interval_next() is the sole source of coverage
 * intervals; this function performs no phdr reparse and builds no second
 * interval plan.  Each interval is dispatched to exactly one of
 * write_stored/write_zero in strictly increasing file-offset order (the
 * iterator itself already enforces forward-only, non-overlapping,
 * gap-complete coverage).  The running CRC is threaded through *crc by
 * value across calls: each callback receives the CRC accumulated so far,
 * folds in its own logical bytes only after they are confirmed complete,
 * and returns the updated value through the same pointer.  A callback
 * that fails leaves the CRC and the iterator cursor exactly as they were
 * before the call, so no partial interval can be double-counted on a
 * caller-level retry of the whole stream (there is none: a single failed
 * interval aborts the entire stream, per the K-6 transaction contract).
 *
 * After the iterator reports ENOENT, the cursor must equal
 * hi_image_length exactly; any other cursor value is an uncovered or
 * over-covered image and is refused.  The CRC is then finalized with the
 * closing XOR 0xffffffff and passed, together with the image-relative
 * offset of the low half of hc_crc32c (hi_crc_zero_offset), to exactly
 * one call to rewrite().  No byte outside that bounded four-byte field is
 * touched by this function.
 */
int
hibernate_writer_plan_stream(struct hibernate_writer_plan *plan,
    hibernate_writer_write_t *write_stored, hibernate_writer_zero_t *write_zero,
    hibernate_writer_rewrite_t *rewrite, void *arg)
{
	struct hibernate_image_interval interval;
	uint32_t crc;
	int error;

	if (plan == NULL || write_stored == NULL || write_zero == NULL ||
	    rewrite == NULL)
		return (EINVAL);

	crc = 0xffffffffU;
	for (;;) {
		struct hibernate_image_iterator checkpoint;
		uint32_t checkpoint_crc;

		/*
		 * interval_next() advances before the logical callback runs.
		 * Snapshot the complete iterator and CRC so a failed logical write
		 * remains retryable from the last completed boundary.
		 */
		checkpoint = plan->hwp_iterator;
		checkpoint_crc = crc;
		error = hibernate_writer_plan_interval_next(plan, &interval);
		if (error == ENOENT)
			break;
		if (error != 0)
			return (error);
		if (interval.hii_length == 0) {
			plan->hwp_iterator = checkpoint;
			return (EINVAL);
		}

		if (interval.hii_class == HIIC_STORED)
			error = write_stored(arg, interval.hii_offset,
			    interval.hii_length, &crc);
		else
			error = write_zero(arg, interval.hii_offset,
			    interval.hii_length, &crc);
		if (error != 0) {
			plan->hwp_iterator = checkpoint;
			crc = checkpoint_crc;
			return (error);
		}
	}

	if (plan->hwp_iterator.hii_cursor != plan->hwp_image.hi_image_length)
		return (EINVAL);

	crc ^= 0xffffffffU;
	return (rewrite(arg, plan->hwp_image.hi_crc_zero_offset, crc));
}

/*
 * Execute the K-6 durable-PENDING transaction around one already-planned image
 * operation.  The image callback owns dump start, forward streaming, and the
 * bounded CRC rewrite.  This helper owns only the durability order:
 *
 *   clear, clear flush, image operation, image flush,
 *   PENDING write, PENDING flush.
 *
 * image_committed is cleared before any operation and becomes true only after
 * the final PENDING flush succeeds.  Thus every callback, write, and flush
 * failure leaves the S4 gate closed.
 */
int
hibernate_commit_pending(struct hibernate_attempt *ha,
    hibernate_image_write_t *write_image, void *write_arg,
    const struct hibernate_marker *pending, bool *image_committed)
{
	int error;

	if (image_committed == NULL)
		return (EINVAL);
	*image_committed = false;

	if (ha == NULL || write_image == NULL || pending == NULL)
		return (EINVAL);
	if (pending->hm_magic != HIBERNATE_MARKER_MAGIC ||
	    pending->hm_version != HIBERNATE_MARKER_VERSION ||
	    pending->hm_state != HIBERNATE_MARKER_STATE_PENDING)
		return (EINVAL);

	error = hibernate_marker_clear(ha);
	if (error != 0)
		return (error);
	error = hibernate_marker_flush(ha);
	if (error != 0)
		return (error);

	error = write_image(write_arg);
	if (error != 0)
		return (error);
	error = hibernate_marker_flush(ha);
	if (error != 0)
		return (error);

	error = hibernate_marker_write(ha, pending);
	if (error != 0)
		return (error);
	error = hibernate_marker_flush(ha);
	if (error != 0)
		return (error);

	*image_committed = true;
	return (0);
}

/*
 * K-7 resume coordinator landmarks.  The append-only trace is reset for each
 * serial resume attempt and records every stage as it is entered.
 */
#ifndef _HIBERNATE_USERLAND_BUILD
enum hibernate_resume_stage {
	HIB_RESUME_PROBE = 0,
	HIB_RESUME_READ_METADATA,
	HIB_RESUME_VALIDATE,
	HIB_RESUME_ALLOCATE,
	HIB_RESUME_READ_PAYLOAD,
	HIB_RESUME_VERIFY,
	HIB_RESUME_MD_PREPARE,
	HIB_RESUME_CONSUMING,
	HIB_RESUME_QUIESCE,
	HIB_RESUME_STOP_CPUS,
	HIB_RESUME_RESTORE,
	HIB_RESUME_ENTER_SAVED,
	HIB_RESUME_STAGE_COUNT
};
#endif

#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * TEST-ONLY stage trace seam.  External linkage lets the production-source
 * host test verify coordinator ordering without changing the kernel ABI.
 */
volatile enum hibernate_resume_stage
    hibernate_resume_stage_log[HIB_RESUME_STAGE_COUNT];
volatile size_t hibernate_resume_stage_log_length;
#else
static volatile enum hibernate_resume_stage
    hibernate_resume_stage_log[HIB_RESUME_STAGE_COUNT];
static volatile size_t hibernate_resume_stage_log_length;
#endif

/*
 * STOP_CPUS changes only the BSP interrupt-enable state.  Its saved value is
 * coordinator-local because cleanup's public interface is fixed.  This path
 * does not change APIC TPR state.
 */
static register_t hibernate_resume_intr_state;
static bool hibernate_resume_intr_state_valid;

static void
hibernate_resume_stage_record(enum hibernate_resume_stage stage)
{
	if (hibernate_resume_stage_log_length < HIB_RESUME_STAGE_COUNT) {
		hibernate_resume_stage_log
		    [hibernate_resume_stage_log_length++] = stage;
	}
}

#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * TEST-ONLY allocation-failure injection for hib_malloc().  Zero (the
 * default) never fails.  A positive value counts down on every call and
 * forces exactly one NULL return when it reaches zero; it then stays at
 * zero (disabled) until a test resets it.
 */
unsigned int hibernate_test_alloc_fail_after;
#endif

/*
 * hib_malloc / hib_free: the single K-8 allocation wrapper used for the
 * metadata block (H5).  _KERNEL uses M_TEMP (already MALLOC_DECLARE()d
 * elsewhere in the tree; no new malloc type).  The userland branch uses
 * calloc()/free() with the injectable failure counter above.
 */
static void *
hib_malloc(size_t size)
{
#ifdef _KERNEL
	return (malloc(size, M_TEMP, M_NOWAIT | M_ZERO));
#else
	if (hibernate_test_alloc_fail_after != 0) {
		if (--hibernate_test_alloc_fail_after == 0)
			return (NULL);
	}
	return (calloc(1, size));
#endif
}

static void
hib_free(void *p)
{
#ifdef _KERNEL
	free(p, M_TEMP);
#else
	free(p);
#endif
}

/*
 * hibernate_image_rel_offset: H2 -- translate an image-relative range
 * [rel, rel+length) into a checked provider-relative byte offset.
 *
 * I = marker.hm_image_offset and L = marker.hm_image_length are in the
 * dumper's address space (di->mediaoffset-based); hibernate_provider_
 * read()'s offsets are provider-relative, so prov_off = (I - mediaoffset)
 * + rel.  Resolves gap G5 (design 035 SS0.3); exercised with a non-zero
 * mediaoffset (design 035 SS6.4, risk R1).
 */
static int
hibernate_image_rel_offset(struct hibernate_attempt *ha, uint64_t rel,
    uint64_t length, uint64_t *prov_off)
{
	struct dumperinfo *di;
	uint64_t hm_offset, hm_length, mediaoffset, off, end;

	if (ha == NULL || ha->ha_dumper == NULL || prov_off == NULL)
		return (EINVAL);
	di = ha->ha_dumper;
	if (di->mediaoffset < 0)
		return (EINVAL);
	mediaoffset = (uint64_t)di->mediaoffset;
	hm_offset = ha->ha_marker_result.marker.hm_image_offset;
	hm_length = ha->ha_marker_result.marker.hm_image_length;
	if (mediaoffset > hm_offset)
		return (EINVAL);
	if (__builtin_add_overflow(rel, length, &end))
		return (EOVERFLOW);
	if (end > hm_length)
		return (EINVAL);
	if (__builtin_sub_overflow(hm_offset, mediaoffset, &off))
		return (EOVERFLOW);
	if (__builtin_add_overflow(off, rel, &off))
		return (EOVERFLOW);
	if (__builtin_add_overflow(off, length, &end))
		return (EOVERFLOW);
	if (end > ha->ha_provider_size)
		return (EINVAL);
	*prov_off = off;
	return (0);
}

#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * TEST-ONLY K-8 provider-read seam.  NULL means "not wired"; the
 * production body below returns ENOTSUP in that case, matching the
 * landed hibernate_test_probe_fn pattern.  The test seam records every
 * (rel_offset, length) pair it is called with.
 */
int (*hibernate_test_provider_read_fn)(struct hibernate_attempt *, uint64_t,
    void *, size_t);
#endif

/*
 * hibernate_stage_read: the sole read primitive used by H6.  Translates
 * an image-relative range to a provider offset (H2) and issues exactly
 * one logical read through the dual-build backend: hibernate_provider_
 * read() (geom_hibernate.c) in the kernel, the injectable TEST-ONLY seam
 * in userland.
 */
static int
hibernate_stage_read(struct hibernate_attempt *ha, uint64_t rel, void *buf,
    size_t length)
{
	uint64_t prov_off;
	int error;

	error = hibernate_image_rel_offset(ha, rel, length, &prov_off);
	if (error != 0)
		return (error);
#ifdef _KERNEL
	return (hibernate_provider_read(ha, prov_off, buf, length));
#else
	if (hibernate_test_provider_read_fn == NULL)
		return (ENOTSUP);
	return (hibernate_test_provider_read_fn(ha, prov_off, buf, length));
#endif
}

/*
 * hibernate_meta_check_phdr_end: H3 -- pure bound on the ELF header plus
 * program-header table length.  The 50,464-byte limit applies only to
 * this length, never to total metadata.
 */
int
hibernate_meta_check_phdr_end(uint64_t phdr_end)
{
	if (phdr_end > 50464)
		return (E2BIG);
	return (0);
}

/*
 * hibernate_meta_check_total: H3 -- pure bound on the derived total
 * metadata prefix length (payload_start).  Order matches the design:
 * reject zero/above the 64029-byte prototype ceiling first, then the
 * buffer-capacity bound, then the image-length bound.
 */
int
hibernate_meta_check_total(uint64_t total, size_t buf_max,
    uint64_t image_length)
{
	if (total == 0 || total > 64029)
		return (EINVAL);
	if (total > HIBERNATE_META_BUF_MAX || total > buf_max)
		return (E2BIG);
	if (total > image_length)
		return (EINVAL);
	return (0);
}

/*
 * hibernate_dst_view_build: H4 -- build the restore-side destination view
 * directly from the already-decoded, already-validated PT_LOAD headers
 * (gap G1; no restore-side code otherwise publishes ha_dst_*).  Reads
 * only p_type/p_paddr/p_filesz; hibernate_image_decode() has already
 * proven every PT_LOAD page aligned, non-overlapping and strictly
 * increasing.  Touching intervals (p_paddr == previous end) are
 * coalesced because hibernate_image_validate() step 4 refuses
 * start <= prev_end.  Intervals are written into the metadata block's
 * tail (ha_meta_buf + HIBERNATE_META_BUF_MAX, capacity
 * 2 * HIBERNATE_MAX_PHDRS vm_paddr_t entries == HIBERNATE_MAX_PHDRS
 * pairs); no page queue is ever consulted.  ha_dst_valid is set last.
 */
static int
hibernate_dst_view_build(struct hibernate_attempt *ha)
{
	const uint8_t *b;
	vm_paddr_t *intervals;
	uint64_t count, total_pages, i, phnum;

	if (ha == NULL || ha->ha_meta_buf == NULL ||
	    ha->ha_image.hi_prefix == NULL)
		return (EINVAL);

	b = ha->ha_image.hi_prefix;
	phnum = ha->ha_image.hi_phnum;
	intervals = (vm_paddr_t *)((uint8_t *)ha->ha_meta_buf +
	    HIBERNATE_META_BUF_MAX);
	count = 0;
	total_pages = 0;

	for (i = 0; i < phnum; i++) {
		const uint8_t *ph;
		uint32_t p_type;
		uint64_t p_paddr, p_filesz, end, pages;

		/* decode() already requires e_phoff == EHDR_SIZE. */
		ph = b + EHDR_SIZE + i * PHDR_SIZE;
		p_type = le32dec(ph + PHDR_OFF_P_TYPE);
		if (p_type != PT_LOAD)
			continue;

		p_paddr = le64dec(ph + PHDR_OFF_P_PADDR);
		p_filesz = le64dec(ph + PHDR_OFF_P_FILESZ);
		if (p_filesz == 0 || (p_filesz & (HIB_PAGE_SIZE - 1)) != 0)
			return (EINVAL);
		if (__builtin_add_overflow(p_paddr, p_filesz, &end))
			return (EOVERFLOW);
		pages = p_filesz / HIB_PAGE_SIZE;
		if (__builtin_add_overflow(total_pages, pages, &total_pages))
			return (EOVERFLOW);

		if (count > 0 && p_paddr == intervals[(count - 1) * 2 + 1]) {
			/* Touching interval: extend the open one. */
			intervals[(count - 1) * 2 + 1] = end;
			continue;
		}
		if (count >= HIBERNATE_MAX_PHDRS)
			return (E2BIG);
		intervals[count * 2] = p_paddr;
		intervals[count * 2 + 1] = end;
		count++;
	}

	if (total_pages != ha->ha_image.hi_destination_pages)
		return (EINVAL);

	ha->ha_dst_intervals = intervals;
	ha->ha_dst_count = count;
	ha->ha_dst_valid = true;
	return (0);
}

/*
 * hibernate_resume_meta_acquire: H5 -- allocate the one metadata block
 * (the HIBERNATE_META_BUF_MAX prefix plus its destination-interval tail)
 * and populate it via hibernate_meta_read().  On any failure the block
 * is freed locally and ha_has_metadata stays false; on success ownership
 * transfers to the attempt.
 */
static int
hibernate_resume_meta_acquire(struct hibernate_attempt *ha,
    size_t *meta_len_out)
{
	void *blk;
	size_t blk_size, meta_len;
	int error;

	if (ha == NULL || meta_len_out == NULL)
		return (EINVAL);
	*meta_len_out = 0;

	blk_size = HIBERNATE_META_BUF_MAX +
	    2 * HIBERNATE_MAX_PHDRS * sizeof(vm_paddr_t);
	blk = hib_malloc(blk_size);
	if (blk == NULL)
		return (ENOMEM);

	meta_len = 0;
	error = hibernate_meta_read(ha, blk, HIBERNATE_META_BUF_MAX, &meta_len);
	if (error != 0) {
		hib_free(blk);
		return (error);
	}

	ha->ha_meta_buf = blk;
	ha->ha_meta_len = meta_len;
	ha->ha_has_metadata = true;
	*meta_len_out = meta_len;
	return (0);
}

/*
 * hibernate_meta_read: H6 -- the bounded two-step metadata read.
 *
 * Step 1 reads exactly 64 bytes at image-relative 0 and validates just
 * enough (ELF identity/class/endianness/header sizes, checked e_phnum)
 * to size the program-header table.  Step 2g derives the page-aligned
 * CB/PCB/payload_start chain and bounds it with the exported predicates.
 * Step 2 reads [64, payload_start) in one I/O, ending exactly at
 * payload_start; no payload byte is ever requested.  Step 2v hands the
 * complete prefix to hibernate_image_decode(), the single authority for
 * padding, CB/PCB cross-checks and destination counts.
 */
int
hibernate_meta_read(struct hibernate_attempt *ha, void *meta_buf,
    size_t meta_buf_max, size_t *meta_len_out)
{
	uint8_t *mb;
	struct hibernate_image scratch;
	uint64_t hm_length, phdr_end, tmp;
	uint64_t cb_offset, cb_end, pcb_offset, pcb_end, payload_start;
	size_t limit;
	uint16_t phnum;
	int error;

	if (ha == NULL || meta_buf == NULL || meta_len_out == NULL)
		return (EINVAL);
	*meta_len_out = 0;
	if (!ha->ha_has_provider)
		return (EINVAL);
	if (ha->ha_marker_result.class != HMC_PENDING)
		return (EINVAL);

	hm_length = ha->ha_marker_result.marker.hm_image_length;
	if (hm_length < DEV_BSIZE)
		return (EINVAL);
	limit = (meta_buf_max < (size_t)HIBERNATE_META_BUF_MAX) ?
	    meta_buf_max :
	    (size_t)HIBERNATE_META_BUF_MAX;

	mb = meta_buf;

	/* Step 1: exactly 64 bytes at image-relative 0. */
	error = hibernate_stage_read(ha, 0, mb, EHDR_SIZE);
	if (error != 0)
		return (error);

	/* Step 1v: minimal identity/size validation to size the phdr table. */
	if (mb[EHDR_OFF_EI_MAG0] != ELFMAG0 ||
	    mb[EHDR_OFF_EI_MAG1] != ELFMAG1 ||
	    mb[EHDR_OFF_EI_MAG2] != ELFMAG2 || mb[EHDR_OFF_EI_MAG3] != ELFMAG3)
		return (EINVAL);
	if (mb[EHDR_OFF_EI_CLASS] != ELFCLASS64)
		return (EINVAL);
	if (mb[EHDR_OFF_EI_DATA] != ELFDATA2LSB)
		return (EINVAL);
	if (mb[EHDR_OFF_EI_VERSION] != EV_CURRENT)
		return (EINVAL);
	if (le16dec(mb + EHDR_OFF_E_EHSIZE) != EHDR_SIZE)
		return (EINVAL);
	if (le16dec(mb + EHDR_OFF_E_PHENTSIZE) != PHDR_SIZE)
		return (EINVAL);
	if (le64dec(mb + EHDR_OFF_E_PHOFF) != EHDR_SIZE)
		return (EINVAL);

	phnum = le16dec(mb + EHDR_OFF_E_PHNUM);
	if (phnum < 1 || phnum > HIBERNATE_MAX_PHDRS)
		return (EINVAL);

	if (__builtin_mul_overflow((uint64_t)phnum, (uint64_t)PHDR_SIZE, &tmp))
		return (EOVERFLOW);
	if (__builtin_add_overflow((uint64_t)EHDR_SIZE, tmp, &phdr_end))
		return (EOVERFLOW);
	error = hibernate_meta_check_phdr_end(phdr_end);
	if (error != 0)
		return (error);

	/* Step 2g: derive the page-aligned CB/PCB/payload_start chain. */
	error = align_up_checked(phdr_end, HIB_PAGE_SIZE, &cb_offset);
	if (error != 0)
		return (error);
	if (__builtin_add_overflow(cb_offset,
		(uint64_t)HIBERNATE_CB_ENCODED_SIZE, &cb_end))
		return (EOVERFLOW);
	error = align_up_checked(cb_end, HIB_PAGE_SIZE, &pcb_offset);
	if (error != 0)
		return (error);
	if (__builtin_add_overflow(pcb_offset,
		(uint64_t)HIBERNATE_PCB_ENCODED_SIZE, &pcb_end))
		return (EOVERFLOW);
	error = align_up_checked(pcb_end, HIB_PAGE_SIZE, &payload_start);
	if (error != 0)
		return (error);

	error = hibernate_meta_check_total(payload_start, limit, hm_length);
	if (error != 0)
		return (error);

	/* Step 2: [I+64, I+payload_start) in one I/O; never beyond it. */
	error = hibernate_stage_read(ha, EHDR_SIZE, mb + EHDR_SIZE,
	    (size_t)(payload_start - EHDR_SIZE));
	if (error != 0)
		return (error);

	/* Step 2v: the single decode authority for the whole prefix. */
	__builtin_memset(&scratch, 0, sizeof(scratch));
	error = hibernate_image_decode(mb, (size_t)payload_start, &scratch);
	if (error != 0)
		return (error);

	/*
	 * The marker's hm_image_length is a separate scalar, never inferred
	 * from the buffer; cross-check it against the CB's own encoded
	 * image length here so any disagreement refuses READ_METADATA
	 * directly rather than being deferred to VALIDATE.
	 */
	if (scratch.hi_image_length != hm_length)
		return (EINVAL);

	*meta_len_out = (size_t)payload_start;
	return (0);
}

/*
 * struct hib_page_set: K-8's page-backend record.  It operates on PA
 * lists so the portable ALLOCATE logic (H7) never sees vm_page_t.
 * hp_pa/hp_count/hp_wired are shared by both builds; hp_res (the K-5
 * reservation record proper) is kernel-only.
 *
 * In the userland build, the portable fields (hp_pa/hp_count/hp_wired)
 * are defined once in hibernate_compat.h (force-included before this
 * point) so production-source host tests share the identical layout;
 * only the _KERNEL extension is added here.
 */
#ifdef _KERNEL
struct hib_page_set {
	vm_paddr_t *hp_pa; /* hp_count checked 64-bit PAs (owned). */
	u_long hp_count;   /* Number of PAs recorded. */
	u_long hp_wired;   /* Number of PAs actually wired. */
	struct vm_phys_reservation hp_res;
};
#endif

#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * TEST-ONLY K-8 page-backend seams.  NULL means "not wired"; each
 * production body below returns ENOTSUP in that case, matching the
 * landed hibernate_test_probe_fn convention.
 */
int (*hibernate_test_pages_reserve_fn)(struct hibernate_attempt *, size_t,
    struct hib_page_set *);
void *(*hibernate_test_pages_map_fn)(vm_paddr_t);
void (*hibernate_test_pages_release_fn)(struct hib_page_set *);
#endif

/*
 * hib_pages_reserve: H1 -- reserve exactly count destination- and
 * arena-disjoint pages from the fresh RESTORE boot's vm_phys free pool,
 * wire each one, and collect its PA into set->hp_pa.
 *
 * The caller preallocates set->hp_res.vr_pages (_KERNEL) with capacity
 * count before calling this function; hib_pages_reserve sets
 * vr_capacity/vr_count and performs the literal
 * vm_phys_hibernate_reserve_count(ha, count, &set->hp_res) call.  On
 * any reservation failure the primitive has already rolled back
 * (vr_count == 0); hib_pages_reserve adds no further release.  On a
 * post-reservation hp_pa allocation failure, the already-reserved
 * pages are released here before returning ENOMEM, so no caller ever
 * observes a committed reservation without a matching hp_pa array.
 */
static int
hib_pages_reserve(struct hibernate_attempt *ha, size_t count,
    struct hib_page_set *set)
{
#ifdef _KERNEL
	uint64_t vecbytes;
	u_long i, want;
	int error;

	if (ha == NULL || set == NULL || count == 0)
		return (EINVAL);
	if (count > (size_t)(u_long)-1)
		return (EOVERFLOW);
	want = (u_long)count;
	if (__builtin_mul_overflow((uint64_t)count,
		(uint64_t)sizeof(vm_paddr_t), &vecbytes))
		return (EOVERFLOW);

	set->hp_res.vr_capacity = want;
	set->hp_res.vr_count = 0;
	error = vm_phys_hibernate_reserve_count(ha, count, &set->hp_res);
	if (error != 0)
		return (error);
	/* Literal success predicate: 0 && vr_count == count. */
	if (set->hp_res.vr_count != want) {
		vm_phys_hibernate_release(&set->hp_res);
		return (EINVAL);
	}

	set->hp_pa = hib_malloc((size_t)vecbytes);
	if (set->hp_pa == NULL) {
		vm_phys_hibernate_release(&set->hp_res);
		return (ENOMEM);
	}

	set->hp_count = 0;
	set->hp_wired = 0;
	for (i = 0; i < want; i++) {
		vm_page_t m;

		m = set->hp_res.vr_pages[i].vrp_page;
		set->hp_pa[i] = VM_PAGE_TO_PHYS(m);
		vm_page_wire(m);
		set->hp_wired++;
	}
	set->hp_count = want;
	return (0);
#else
	if (hibernate_test_pages_reserve_fn == NULL)
		return (ENOTSUP);
	return (hibernate_test_pages_reserve_fn(ha, count, set));
#endif
}

/*
 * hib_pages_map: H1 -- the one temporary-mapping primitive.  amd64 has
 * a direct map at ALLOCATE time (design 035 A5), so no mapping is
 * created and hib_pages_release() removes none.
 */
static void *
hib_pages_map(vm_paddr_t pa)
{
#ifdef _KERNEL
	return (PHYS_TO_DMAP(pa));
#else
	if (hibernate_test_pages_map_fn == NULL)
		return (NULL);
	return (hibernate_test_pages_map_fn(pa));
#endif
}

/*
 * hib_pages_release: H1 -- wipe every recorded page through the direct
 * map, unwire exactly hp_wired of them, then release the K-5 record.
 * Safe on an all-zero (never-reserved) set.  Does not free hp_pa or
 * hp_res.vr_pages; the owning hibernate_safe_pages_free() does that.
 */
static void
hib_pages_release(struct hib_page_set *set)
{
#ifdef _KERNEL
	u_long i;

	if (set == NULL)
		return;
	for (i = 0; i < set->hp_count; i++)
		pagezero(PHYS_TO_DMAP(set->hp_pa[i]));
	for (i = 0; i < set->hp_wired; i++)
		vm_page_unwire_noq(PHYS_TO_VM_PAGE(set->hp_pa[i]));
	vm_phys_hibernate_release(&set->hp_res);
	set->hp_count = 0;
	set->hp_wired = 0;
#else
	if (hibernate_test_pages_release_fn != NULL)
		hibernate_test_pages_release_fn(set);
#endif
}

/*
 * struct hibernate_staging: H7's private ALLOCATE-stage record, owned
 * through ha_staging.  hs_src is the P-page accepted source-page
 * reservation (S); hs_aux is the second, distinct A-page reservation
 * (V vector pages + X XSAVE pages + 1 bounce page).
 */
struct hibernate_staging {
	struct hib_page_set hs_src;
	struct hib_page_set hs_aux;
	u_long hs_vector_pages; /* V */
	u_long hs_xsave_pages;	/* X (always 1; X > 1 refuses E2BIG). */
};

/*
 * hib_pa_in_dst: binary search over the sorted, strictly increasing,
 * non-adjacent ha_dst_intervals pairs.  False when no view is
 * published (mirrors vm_phys.c's hib_page_is_destination()).
 */
static bool
hib_pa_in_dst(const struct hibernate_attempt *ha, vm_paddr_t pa)
{
	uint64_t lo, hi, mid, start, end;

	if (!ha->ha_dst_valid || ha->ha_dst_intervals == NULL ||
	    ha->ha_dst_count == 0)
		return (false);

	lo = 0;
	hi = ha->ha_dst_count;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		start = ha->ha_dst_intervals[mid * 2];
		end = ha->ha_dst_intervals[mid * 2 + 1];
		if (pa < start)
			hi = mid;
		else if (pa >= end)
			lo = mid + 1;
		else
			return (true);
	}
	return (false);
}

/*
 * hib_pa_in_arena: membership test against the validated transition
 * arena.  Wrap-safe, mirroring vm_phys.c's hib_page_in_arena().
 */
static bool
hib_pa_in_arena(const struct hibernate_attempt *ha, vm_paddr_t pa)
{
	vm_paddr_t end;

	if (ha->ha_arena_size == 0)
		return (false);
	if (pa < ha->ha_arena_start)
		return (false);
	end = ha->ha_arena_start + ha->ha_arena_size;
	if (end < ha->ha_arena_start)
		return (true);
	return (pa < end);
}

/*
 * hib_pages_verify: H7 steps 6 and 8 -- direct verification of an
 * accepted page set (no page-queue traversal; only vm_page_wire()/
 * PHYS_TO_VM_PAGE()/VM_PAGE_TO_PHYS()).  Checks
 * cardinality, page alignment, PHYS_TO_VM_PAGE(pa) == the recorded
 * vrp_page (_KERNEL only), disjointness from the destination union and
 * the arena, and uniqueness via a transient sorted copy, freed before
 * return.  When other != NULL (the aux call), the transient copy
 * covers both sets, so one adjacent-duplicate scan proves aux's own
 * uniqueness and aux-intersect-src == empty together.
 */
static int
hib_staging_pa_cmp(const void *a, const void *b)
{
	vm_paddr_t pa, pb;

	pa = *(const vm_paddr_t *)a;
	pb = *(const vm_paddr_t *)b;
	if (pa < pb)
		return (-1);
	if (pa > pb)
		return (1);
	return (0);
}

static int
hib_pages_verify(const struct hibernate_attempt *ha,
    const struct hib_page_set *set, const struct hib_page_set *other,
    uint64_t expect)
{
	vm_paddr_t *sorted;
	size_t total, n, i;
	int error;

	if (set->hp_count != expect)
		return (EINVAL);

	for (i = 0; i < set->hp_count; i++) {
		vm_paddr_t pa = set->hp_pa[i];

		if ((pa & (HIB_PAGE_SIZE - 1)) != 0)
			return (EINVAL);
#ifdef _KERNEL
		if (PHYS_TO_VM_PAGE(pa) != set->hp_res.vr_pages[i].vrp_page)
			return (EINVAL);
#endif
		if (hib_pa_in_dst(ha, pa))
			return (EINVAL);
		if (hib_pa_in_arena(ha, pa))
			return (EINVAL);
	}

	total = set->hp_count + (other != NULL ? other->hp_count : 0);
	if (total == 0)
		return (0);
	sorted = hib_malloc(total * sizeof(vm_paddr_t));
	if (sorted == NULL)
		return (ENOMEM);

	n = 0;
	for (i = 0; i < set->hp_count; i++)
		sorted[n++] = set->hp_pa[i];
	if (other != NULL)
		for (i = 0; i < other->hp_count; i++)
			sorted[n++] = other->hp_pa[i];

	qsort(sorted, total, sizeof(vm_paddr_t), hib_staging_pa_cmp);
	error = 0;
	for (i = 1; i < total; i++) {
		if (sorted[i] == sorted[i - 1]) {
			error = EINVAL;
			break;
		}
	}
	hib_free(sorted);
	return (error);
}

/*
 * hibernate_safe_pages_alloc: H7 -- the measured-capacity,
 * reserve-as-measured ALLOCATE stage.  See design 035 SS4.2 for the ten
 * ordered steps.  Every return before step 3 leaves ha_has_safe_pages
 * false (nothing was published); every return at or after step 3
 * leaves it true, so K-7's hibernate_safe_pages_free() owns the rest
 * regardless of where ALLOCATE stopped.
 */
int
hibernate_safe_pages_alloc(struct hibernate_attempt *ha)
{
	struct hibernate_staging *st;
	uint64_t P, pbytes, src16, aux16, v_aligned, V, x_aligned, X, A;
	size_t i;
	int error;

	/* Step 1: preconditions. */
	if (ha == NULL || !ha->ha_has_metadata || !ha->ha_dst_valid ||
	    ha->ha_image.hi_prefix == NULL || ha->ha_has_safe_pages ||
	    ha->ha_staging != NULL || ha->ha_image.hi_destination_pages == 0)
		return (EINVAL);

	/*
	 * Step 2: size P, checked P*8 / P*16, V = ceil(P*8/4096),
	 * X = ceil(hi_xsave_length/4096), A = V + X + 1 checked.  X > 1
	 * refuses E2BIG here, before any allocation or reservation.
	 */
	P = ha->ha_image.hi_destination_pages;

	if (__builtin_mul_overflow(P, (uint64_t)8, &pbytes))
		return (EOVERFLOW);
	if (__builtin_mul_overflow(P, (uint64_t)HIB_RESERVATION_RECORD_BYTES,
		&src16))
		return (EOVERFLOW);

	error = align_up_checked(pbytes, HIB_PAGE_SIZE, &v_aligned);
	if (error != 0)
		return (error);
	V = v_aligned / HIB_PAGE_SIZE;

	error = align_up_checked(ha->ha_image.hi_xsave_length, HIB_PAGE_SIZE,
	    &x_aligned);
	if (error != 0)
		return (error);
	X = x_aligned / HIB_PAGE_SIZE;
	if (X > 1)
		return (E2BIG);

	if (__builtin_add_overflow(V, X, &A))
		return (EOVERFLOW);
	if (__builtin_add_overflow(A, (uint64_t)1, &A))
		return (EOVERFLOW);
	if (__builtin_mul_overflow(A, (uint64_t)HIB_RESERVATION_RECORD_BYTES,
		&aux16))
		return (EOVERFLOW);

	/*
	 * Step 3: hib_malloc the staging struct; publish
	 * ha_has_safe_pages as soon as it exists.
	 */
	st = hib_malloc(sizeof(*st));
	if (st == NULL)
		return (ENOMEM);
	ha->ha_staging = st;
	ha->ha_has_safe_pages = true;
	st->hs_vector_pages = V;
	st->hs_xsave_pages = X;

	/* Step 4: hib_malloc the two vr_pages arrays (sizes checked above). */
#ifdef _KERNEL
	st->hs_src.hp_res.vr_pages = hib_malloc((size_t)src16);
	if (st->hs_src.hp_res.vr_pages == NULL)
		return (ENOMEM);
	st->hs_aux.hp_res.vr_pages = hib_malloc((size_t)aux16);
	if (st->hs_aux.hp_res.vr_pages == NULL)
		return (ENOMEM);
#endif

	/* Step 5: reserve exactly P source pages (and wire them). */
	error = hib_pages_reserve(ha, (size_t)P, &st->hs_src);
	if (error != 0)
		return (error);

	/* Step 6: direct verification of S. */
	error = hib_pages_verify(ha, &st->hs_src, NULL, P);
	if (error != 0)
		return (error);

	/* Step 7: wiring is performed inside hib_pages_reserve (step 5). */

	/*
	 * Step 8: a second distinct reserve_count() instance for aux,
	 * plus the same verification, plus aux-intersect-src == empty.
	 */
	error = hib_pages_reserve(ha, (size_t)A, &st->hs_aux);
	if (error != 0)
		return (error);
	error = hib_pages_verify(ha, &st->hs_aux, &st->hs_src, A);
	if (error != 0)
		return (error);

	/*
	 * Step 9: zero every aux page, then fill the source-PA vector
	 * (one checked 64-bit PA per destination page) across the
	 * vector sub-range of aux, in i = 0..P-1 order.
	 */
	for (i = 0; i < (size_t)A; i++) {
		void *va;

		va = hib_pages_map(st->hs_aux.hp_pa[i]);
		if (va == NULL)
			return (EINVAL);
		__builtin_memset(va, 0, HIB_PAGE_SIZE);
	}
	for (i = 0; i < (size_t)P; i++) {
		size_t per_page, page_idx, off;
		vm_paddr_t *vec;

		per_page = HIB_PAGE_SIZE / sizeof(vm_paddr_t);
		page_idx = i / per_page;
		off = i % per_page;
		vec = hib_pages_map(st->hs_aux.hp_pa[page_idx]);
		if (vec == NULL)
			return (EINVAL);
		vec[off] = st->hs_src.hp_pa[i];
	}
	if (i != (size_t)P)
		return (EINVAL);

	/* Step 10. */
	return (0);
}

#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * TEST-ONLY K-8 coverage-refusal seam.  NULL means "use the real
 * iterator" (hibernate_image_walk() remains the sole production
 * caller of hibernate_image_interval_next()); when set, this seam
 * replaces that one call site so malformed interval sequences
 * (overlapping, backward, gapped, repeated, interleaved, zero-length,
 * overshooting, short-of-end) can be injected directly, since the real
 * iterator cannot produce them.
 */
int (*hibernate_test_interval_next_fn)(struct hibernate_image_iterator *,
    struct hibernate_image_interval *);
#endif

/*
 * hib_image_interval_next: the walker's one call site.  Dual-build:
 * the kernel body always calls the real K-2 iterator; the userland
 * body calls the TEST-ONLY seam when installed, else the real
 * iterator, matching every other K-8 seam's NULL convention.
 */
static int
hib_image_interval_next(struct hibernate_image_iterator *it,
    struct hibernate_image_interval *out)
{
#ifdef _HIBERNATE_USERLAND_BUILD
	if (hibernate_test_interval_next_fn != NULL)
		return (hibernate_test_interval_next_fn(it, out));
#endif
	return (hibernate_image_interval_next(it, out));
}

/*
 * hib_zero_page: the static all-zero buffer used both to feed the one
 * 8-byte virtual-zero hc_crc32c run (hib_crc_feed()) and to fold
 * payload ZERO_GAP bytes into the CRC without touching the image
 * (design 035 SS5.2).  File-scope static with no initializer is
 * zero-filled by the C standard.
 */
static const uint8_t hib_zero_page[HIB_PAGE_SIZE];

/*
 * hib_crc_feed: fold [off, off+len) into *crc, splitting any piece
 * that overlaps the one 8-byte virtual-zero range [zo, zo+zl) into up
 * to three updates: before, a zero run supplied from hib_zero_page
 * rather than buf, after.  Only the CB interval can ever overlap;
 * every other call degenerates to a single plain update.
 */
static void
hib_crc_feed(uint32_t *crc, uint64_t off, const uint8_t *buf, uint64_t len,
    uint64_t zo, uint64_t zl)
{
	uint64_t piece_end, zend, ov_start, ov_end, pre_len, post_off, post_len;

	piece_end = off + len;
	if (zl == 0 || piece_end <= zo || off >= zo + zl) {
		*crc = hibernate_crc32c_update(*crc, buf, (size_t)len);
		return;
	}

	zend = zo + zl;

	pre_len = (off < zo) ? zo - off : 0;
	if (pre_len != 0)
		*crc = hibernate_crc32c_update(*crc, buf, (size_t)pre_len);

	ov_start = (off > zo) ? off : zo;
	ov_end = (piece_end < zend) ? piece_end : zend;
	*crc = hibernate_crc32c_update(*crc, hib_zero_page,
	    (size_t)(ov_end - ov_start));

	if (piece_end > zend) {
		post_off = zend - off;
		post_len = piece_end - zend;
		*crc = hibernate_crc32c_update(*crc, buf + post_off,
		    (size_t)post_len);
	}
}

/*
 * hibernate_image_walk: H8 -- the sole caller of
 * hib_image_interval_next() (and therefore, in the production kernel
 * body, of hibernate_image_interval_next() itself) in K-8.  Drives one
 * forward pass over [0, hi_image_length) and folds every covered byte
 * into a running CRC32C with the one 8-byte hc_crc32c field virtually
 * zeroed (design 035 SS5).  do_read selects READ_PAYLOAD (true: each
 * payload byte is fetched through hibernate_stage_read() before being
 * CRC'd) or VERIFY (false: every payload byte is read from the
 * already-staged source/XSAVE pages, zero provider reads).  Never
 * reparses a program header; file ranges and classes come exclusively
 * from the iterator and from ha_image scalars.
 *
 * *crc_out is zeroed on entry and is written only on success.
 */
static int
hibernate_image_walk(struct hibernate_attempt *ha, bool do_read,
    uint32_t *crc_out)
{
	struct hibernate_image_iterator it;
	struct hibernate_image_interval iv;
	struct hibernate_image *img;
	struct hibernate_staging *st;
	uint64_t cursor, end, vec, P;
	uint32_t crc;
	int error;

	if (crc_out != NULL)
		*crc_out = 0;
	if (ha == NULL || crc_out == NULL || ha->ha_meta_buf == NULL ||
	    ha->ha_staging == NULL) {
		return (EINVAL);
	}

	img = &ha->ha_image;
	st = ha->ha_staging;
	P = img->hi_destination_pages;

	__builtin_memset(&it, 0, sizeof(it));
	it.hii_image = img;
	it.hii_phase = HIIP_METADATA;

	crc = 0xffffffffU;
	cursor = 0;
	vec = 0;

	for (;;) {
		error = hib_image_interval_next(&it, &iv);
		if (error == ENOENT)
			break;
		if (error != 0) {
			return (EINVAL);
		}
		if (iv.hii_length == 0 || iv.hii_offset != cursor) {
			return (EINVAL);
		}
		if (__builtin_add_overflow(cursor, iv.hii_length, &end) ||
		    end > img->hi_image_length) {
			return (EINVAL);
		}

		if (end <= img->hi_payload_start) {
			/* Metadata: STORED or ZERO_GAP bytes from ha_meta_buf.
			 */
			hib_crc_feed(&crc, cursor,
			    (const uint8_t *)ha->ha_meta_buf + cursor,
			    iv.hii_length, img->hi_crc_zero_offset,
			    img->hi_crc_zero_length);
		} else if (iv.hii_class == HIIC_STORED &&
		    iv.hii_offset == img->hi_xsave_offset) {
			/* The sole XSAVE object -> the single aux XSAVE page.
			 */
			void *xva;

			if (iv.hii_length > HIB_PAGE_SIZE) {
				return (EINVAL);
			}
			xva = hib_pages_map(
			    st->hs_aux.hp_pa[st->hs_vector_pages]);
			if (xva == NULL) {
				return (EINVAL);
			}
			if (do_read) {
				error = hibernate_stage_read(ha, cursor, xva,
				    (size_t)iv.hii_length);
				if (error != 0) {
					return (error);
				}
			}
			hib_crc_feed(&crc, cursor, xva, iv.hii_length,
			    img->hi_crc_zero_offset, img->hi_crc_zero_length);
		} else if (iv.hii_class == HIIC_STORED) {
			/* PT_LOAD: page-by-page into the source-PA vector. */
			uint64_t pages, pg;

			if ((iv.hii_length & (HIB_PAGE_SIZE - 1)) != 0) {
				return (EINVAL);
			}
			pages = iv.hii_length / HIB_PAGE_SIZE;
			for (pg = 0; pg < pages; pg++) {
				void *pva;
				uint64_t poff;

				if (vec >= P) {
					return (EINVAL);
				}
				pva = hib_pages_map(st->hs_src.hp_pa[vec]);
				if (pva == NULL) {
					return (EINVAL);
				}
				poff = cursor + pg * HIB_PAGE_SIZE;
				if (do_read) {
					error = hibernate_stage_read(ha, poff,
					    pva, HIB_PAGE_SIZE);
					if (error != 0) {
						return (error);
					}
				}
				hib_crc_feed(&crc, poff, pva, HIB_PAGE_SIZE,
				    img->hi_crc_zero_offset,
				    img->hi_crc_zero_length);
				vec++;
			}
		} else {
			/* Payload ZERO_GAP: routed through the bounce page. */
			uint64_t remaining, coff, bidx;
			void *bva;

			bidx = st->hs_vector_pages + st->hs_xsave_pages;
			bva = hib_pages_map(st->hs_aux.hp_pa[bidx]);
			if (bva == NULL)
				return (EINVAL);
			remaining = iv.hii_length;
			coff = 0;
			while (remaining > 0) {
				uint64_t chunk;

				chunk = (remaining < HIB_PAGE_SIZE) ?
				    remaining :
				    HIB_PAGE_SIZE;
				if (do_read) {
					error = hibernate_stage_read(ha,
					    cursor + coff, bva, (size_t)chunk);
					if (error != 0) {
						return (error);
					}
					if (!is_all_zero(bva, (size_t)chunk)) {
						return (EINVAL);
					}
				}
				hib_crc_feed(&crc, cursor + coff, hib_zero_page,
				    chunk, img->hi_crc_zero_offset,
				    img->hi_crc_zero_length);
				coff += chunk;
				remaining -= chunk;
			}
		}

		cursor = end;
	}

	if (cursor != img->hi_image_length || vec != P) {
		return (EINVAL);
	}

	*crc_out = crc ^ 0xffffffffU;
	return (0);
}

/*
 * hibernate_payload_read: H9 -- preconditions, then one forward
 * hibernate_image_walk() pass that streams every payload byte directly
 * into its accepted source/XSAVE page through hibernate_stage_read();
 * no full-image buffer is allocated.  The XSAVE bound is re-checked
 * here, before any provider read, independent of whether ALLOCATE
 * published a staging record (design 035 SS6.4 "XSAVE bound" row).
 */
int
hibernate_payload_read(struct hibernate_attempt *ha, uint32_t *crc_out)
{
	uint64_t x_aligned;
	int error;

	if (crc_out != NULL)
		*crc_out = 0;
	if (ha == NULL || crc_out == NULL)
		return (EINVAL);

	error = align_up_checked(ha->ha_image.hi_xsave_length, HIB_PAGE_SIZE,
	    &x_aligned);
	if (error != 0) {
		*crc_out = 0;
		return (error);
	}
	if (x_aligned / HIB_PAGE_SIZE > 1) {
		*crc_out = 0;
		return (E2BIG);
	}

	if (!ha->ha_has_safe_pages || ha->ha_staging == NULL) {
		*crc_out = 0;
		return (EINVAL);
	}

	error = hibernate_image_walk(ha, true, crc_out);
	if (error != 0) {
		*crc_out = 0;
		return (error);
	}
	return (0);
}

/*
 * hibernate_image_crc32c_verify: H10 -- an independent recomputation
 * of the whole-image CRC32C from staged memory (zero provider reads),
 * compared against both the decoded CB hc_crc32c and the streamed crc
 * argument.  No state is changed on any path.
 */
int
hibernate_image_crc32c_verify(struct hibernate_attempt *ha, uint32_t crc)
{
	uint32_t recomputed;
	int error;

	if (ha == NULL)
		return (EINVAL);

	error = hibernate_image_walk(ha, false, &recomputed);
	if (error != 0)
		return (error);

	if (recomputed != ha->ha_image.hi_cb.hc_crc32c)
		return (EINVAL);
	if (recomputed != crc)
		return (EINVAL);

	return (0);
}

int
hibernate_quiesce(struct hibernate_attempt *ha)
{
	(void)ha;
	return (ENOTSUP);
}

#ifdef _HIBERNATE_USERLAND_BUILD
/* TEST-ONLY K-12 cleanup seam; NULL preserves the temporary ENOTSUP body. */
int (*hibernate_test_quiesce_rollback_fn)(struct hibernate_attempt *);
#endif

int
hibernate_quiesce_rollback(struct hibernate_attempt *ha)
{
#ifdef _HIBERNATE_USERLAND_BUILD
	if (hibernate_test_quiesce_rollback_fn != NULL)
		return (hibernate_test_quiesce_rollback_fn(ha));
#endif
	(void)ha;
	return (ENOTSUP);
}

int
hibernate_stop_cpus(cpuset_t target, cpuset_t *acknowledged)
{
	(void)target;
	(void)acknowledged;
	return (ENOTSUP);
}

#ifdef _HIBERNATE_USERLAND_BUILD
/* TEST-ONLY K-12 AP-restart seam; NULL preserves temporary ENOTSUP. */
int (*hibernate_test_restart_cpus_fn)(cpuset_t);
#endif

int
hibernate_restart_cpus(cpuset_t acknowledged)
{
#ifdef _HIBERNATE_USERLAND_BUILD
	if (hibernate_test_restart_cpus_fn != NULL)
		return (hibernate_test_restart_cpus_fn(acknowledged));
#endif
	(void)acknowledged;
	return (ENOTSUP);
}

#ifdef _KERNEL
static int
hibernate_coordinator_probe(struct hibernate_attempt *ha)
{
	return (hibernate_probe(ha));
}

static void
hibernate_coordinator_provider_release(struct hibernate_attempt *ha)
{
	hibernate_provider_release(ha);
}
#else
/*
 * TEST-ONLY injectable coordinator seams.  They have external linkage only
 * in the userland build so the host test can drive and observe cleanup.
 */
int (*hibernate_test_probe_fn)(struct hibernate_attempt *) = NULL;
void (*hibernate_test_provider_release_fn)(
    struct hibernate_attempt *) = NULL;

static int
hibernate_coordinator_probe(struct hibernate_attempt *ha)
{
	if (hibernate_test_probe_fn != NULL)
		return (hibernate_test_probe_fn(ha));
	ha->ha_marker_result.class = HMC_ABSENT;
	ha->ha_marker_result.error = 0;
	return (0);
}

static void
hibernate_coordinator_provider_release(struct hibernate_attempt *ha)
{
	if (hibernate_test_provider_release_fn != NULL)
		hibernate_test_provider_release_fn(ha);
}
#endif

/*
 * hibernate_safe_pages_free: H11 -- owner-local release of ALLOCATE's
 * staging.  External, idempotent, and ha == NULL tolerant.  Releases
 * aux then src (reverse acquisition order): wipe, unwire exactly
 * hp_wired, vm_phys_hibernate_release().  Performs no marker operation,
 * provider release, arena release, or destination write.  Only K-7's
 * hibernate_attempt_cleanup() step 7 calls this.
 */
void
hibernate_safe_pages_free(struct hibernate_attempt *ha)
{
	struct hibernate_staging *st;

	if (ha == NULL)
		return;
	st = ha->ha_staging;
	if (st == NULL) {
		ha->ha_has_safe_pages = false;
		return;
	}

	hib_pages_release(&st->hs_aux);
	hib_pages_release(&st->hs_src);

#ifdef _KERNEL
	hib_free(st->hs_aux.hp_res.vr_pages);
	hib_free(st->hs_src.hp_res.vr_pages);
#endif
	hib_free(st->hs_aux.hp_pa);
	hib_free(st->hs_src.hp_pa);
	hib_free(st);

	ha->ha_staging = NULL;
	ha->ha_has_safe_pages = false;
}

/*
 * hibernate_metadata_free: H11 -- static, idempotent.  Invalidates the
 * decoded image and the destination view it backs (ha_dst_intervals
 * points into the metadata block's tail), then frees the block.
 */
static void
hibernate_metadata_free(struct hibernate_attempt *ha)
{
	__builtin_memset(&ha->ha_image, 0, sizeof(ha->ha_image));
	ha->ha_dst_valid = false;
	ha->ha_dst_intervals = NULL;
	ha->ha_dst_count = 0;
	hib_free(ha->ha_meta_buf);
	ha->ha_meta_buf = NULL;
	ha->ha_meta_len = 0;
	ha->ha_has_metadata = false;
}

/*
 * K-12 replaces this body when it implements admission closure.  Until then
 * no K-7 path can acquire admission ownership.
 */
static int
hibernate_admission_reopen(struct hibernate_attempt *ha)
{
	ha->ha_has_admission_closed = false;
	return (0);
}

static void
hibernate_cleanup_terminal(const char *reason)
{
#ifdef _KERNEL
	panic("hibernate cleanup failed: %s", reason);
#else
	(void)reason;
	__builtin_trap();
#endif
}

static void
hibernate_attempt_cleanup_marker(struct hibernate_attempt *ha)
{
	int error;

	if (ha->ha_marker_owned == HM_OWNED_NONE)
		return;
	error = hibernate_marker_clear(ha);
	if (error == 0)
		error = hibernate_marker_flush(ha);
	if (error == 0)
		ha->ha_marker_owned = HM_OWNED_NONE;
#ifdef _KERNEL
	else
		printf("hibernate: marker cleanup failed: %d\n", error);
#endif
}

/*
 * K-12/K-14 replace this verified no-owner default with selected transport
 * rollback.  It does not reopen admission, perform marker I/O, or restore
 * interrupts.
 */
#ifdef _HIBERNATE_USERLAND_BUILD
/*
 * TEST-ONLY selected-owner rollback seam.  NULL retains the verified no-owner
 * K-7 default while an injected function makes exact-once cleanup observable.
 */
int (*hibernate_test_owner_rollback_fn)(struct hibernate_attempt *,
    enum hibernate_owner_rollback_outcome *);
#endif

static int
hibernate_selected_owner_rollback(struct hibernate_attempt *ha,
    enum hibernate_owner_rollback_outcome *outcome)
{
#ifdef _HIBERNATE_USERLAND_BUILD
	if (hibernate_test_owner_rollback_fn != NULL)
		return (hibernate_test_owner_rollback_fn(ha, outcome));
#endif
	(void)ha;
	*outcome = HIBERNATE_OWNER_ROLLBACK_VERIFIED;
	return (0);
}

void
hibernate_attempt_cleanup(struct hibernate_attempt *ha)
{
	enum hibernate_owner_rollback_outcome outcome;
	cpuset_t empty_set;
	int error;

	if (ha == NULL)
		return;

	/* Step 1: admission remains closed if this attempt acquired it. */

	/* Step 2: restart exactly the APs which acknowledged STOP_CPUS. */
	__builtin_memset(&empty_set, 0, sizeof(empty_set));
	if (ha->ha_has_stopped_cpus ||
	    __builtin_memcmp(&ha->ha_acknowledged_cpus, &empty_set,
	    sizeof(empty_set)) != 0) {
		error = hibernate_restart_cpus(ha->ha_acknowledged_cpus);
		if (error != 0)
			hibernate_cleanup_terminal("AP restart");
		ha->ha_has_stopped_cpus = false;
	}

	/* Step 3: roll back the selected owner unconditionally. */
	outcome = HIBERNATE_OWNER_ROLLBACK_UNKNOWN;
	error = hibernate_selected_owner_rollback(ha, &outcome);
	if (error != 0 ||
	    outcome != HIBERNATE_OWNER_ROLLBACK_VERIFIED)
		hibernate_cleanup_terminal("owner rollback");

	/* Step 4: roll back the coordinator while admission remains closed. */
	if (ha->ha_has_quiesce) {
		error = hibernate_quiesce_rollback(ha);
		if (error != 0)
			hibernate_cleanup_terminal("coordinator rollback");
		ha->ha_has_quiesce = false;
	}

	/* Step 5: restore only the BSP IF state captured at STOP_CPUS. */
	if (hibernate_resume_intr_state_valid) {
#ifdef _KERNEL
		intr_restore(hibernate_resume_intr_state);
#endif
		hibernate_resume_intr_state_valid = false;
	}

	/* Step 6: the sole owned-marker clear and flush action. */
	hibernate_attempt_cleanup_marker(ha);

	/* Step 7: release resources in reverse acquisition order. */
	if (ha->ha_has_arena) {
		hibernate_arena_release(ha);
		ha->ha_has_arena = false;
	}
	if (ha->ha_has_safe_pages)
		hibernate_safe_pages_free(ha);
	if (ha->ha_has_metadata)
		hibernate_metadata_free(ha);
	if (ha->ha_has_provider || ha->ha_has_extent ||
	    ha->ha_has_root_hold)
		hibernate_coordinator_provider_release(ha);

	/* Step 8: reopening and verification are the final action. */
	if (ha->ha_has_admission_closed &&
	    hibernate_admission_reopen(ha) != 0)
		hibernate_cleanup_terminal("admission reopen");
}

int
hibernate_resume_attempt(struct hibernate_attempt *ha)
{
	const void *meta;
	size_t meta_len;
	uint32_t crc;
	struct hibernate_marker consuming_marker;
	cpuset_t target, empty_set;
	enum hibernate_resume_stage stage;
	int error;

	if (ha == NULL)
		return (EINVAL);

	crc = 0;

	hibernate_resume_stage_log_length = 0;
	stage = HIB_RESUME_PROBE;
	error = hibernate_coordinator_probe(ha);
	hibernate_resume_stage_record(stage);
	if (error != 0 || ha->ha_marker_result.class != HMC_PENDING)
		goto classify_non_pending;
	ha->ha_marker_owned = HM_OWNED_PENDING;

	stage = HIB_RESUME_READ_METADATA;
	error = hibernate_resume_meta_acquire(ha, &meta_len);
	hibernate_resume_stage_record(stage);
	if (error != 0)
		goto cleanup;
	meta = ha->ha_meta_buf;

	stage = HIB_RESUME_VALIDATE;
	error = hibernate_image_decode(meta, meta_len, &ha->ha_image);
	if (error == 0)
		error = hibernate_dst_view_build(ha);
	if (error == 0) {
		/*
		 * Claim the K-9 transition arena before validating its tuple
		 * so ha_arena_start/size hold the restore boot's immutable
		 * range, which hibernate_image_validate() cross-checks against
		 * the decoded CB fields.  Cleanup step 7 releases the claim on
		 * any failure.
		 */
		error = hibernate_arena_claim(ha);
		if (error == 0)
			ha->ha_has_arena = true;
	}
	if (error == 0)
		error = hibernate_image_validate(ha);
	hibernate_resume_stage_record(stage);
	if (error != 0)
		goto cleanup;

	stage = HIB_RESUME_ALLOCATE;
	error = hibernate_safe_pages_alloc(ha);
	hibernate_resume_stage_record(stage);
	if (error != 0)
		goto cleanup;

	stage = HIB_RESUME_READ_PAYLOAD;
	error = hibernate_payload_read(ha, &crc);
	hibernate_resume_stage_record(stage);
	if (error != 0)
		goto cleanup;

	stage = HIB_RESUME_VERIFY;
	error = hibernate_image_crc32c_verify(ha, crc);
	hibernate_resume_stage_record(stage);
	if (error != 0)
		goto cleanup;

	/*
	 * MD_PREPARE: K-10 inserts hibernate_machdep_prepare() at this seam.
	 */
	stage = HIB_RESUME_MD_PREPARE;
	hibernate_resume_stage_record(stage);

	consuming_marker = ha->ha_marker_result.marker;
	consuming_marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMING;
	stage = HIB_RESUME_CONSUMING;
	hibernate_resume_stage_record(stage);
	error = hibernate_marker_write(ha, &consuming_marker);
	if (error == 0)
		error = hibernate_marker_flush(ha);
	if (error != 0)
		goto cleanup;
	ha->ha_marker_owned = HM_OWNED_CONSUMING;

	stage = HIB_RESUME_QUIESCE;
	hibernate_resume_stage_record(stage);
	error = hibernate_quiesce(ha);
	if (error == 0)
		ha->ha_has_quiesce = true;
	if (error != 0)
		goto cleanup;

	stage = HIB_RESUME_STOP_CPUS;
	hibernate_resume_stage_record(stage);
	__builtin_memset(&empty_set, 0, sizeof(empty_set));
	__builtin_memset(&ha->ha_acknowledged_cpus, 0,
	    sizeof(ha->ha_acknowledged_cpus));
#ifdef _KERNEL
	target = all_cpus;
	CPU_CLR(PCPU_GET(cpuid), &target);
#else
	target = empty_set;
#endif
	error = hibernate_stop_cpus(target, &ha->ha_acknowledged_cpus);
	if (error == 0 && __builtin_memcmp(&ha->ha_acknowledged_cpus,
	    &empty_set, sizeof(empty_set)) != 0)
		ha->ha_has_stopped_cpus = true;
	if (error != 0)
		goto cleanup;
	/*
	 * BSP interrupt state is captured only after every targeted AP has
	 * acknowledged the stop (the STOP_CPUS stage's required result).
	 */
	hibernate_resume_intr_state_valid = false;
#ifdef _KERNEL
	hibernate_resume_intr_state = intr_disable();
#else
	hibernate_resume_intr_state = 0;
#endif
	hibernate_resume_intr_state_valid = true;

	/*
	 * RESTORE and ENTER_SAVED: K-10, K-11, and K-13 insert their
	 * no-return destructive restore and saved-context entry here.
	 */
	stage = HIB_RESUME_RESTORE;
	hibernate_resume_stage_record(stage);
	stage = HIB_RESUME_ENTER_SAVED;
	hibernate_resume_stage_record(stage);
	return (0);

classify_non_pending:
	switch (ha->ha_marker_result.class) {
	case HMC_STALE_CONSUMING:
	case HMC_CONSUMED:
	case HMC_MALFORMED:
		/*
		 * The issue gates this narrow classification clear on K-4
		 * having acquired the exact safely writable provider, not on
		 * an image extent (a malformed marker has no known extent).
		 */
		if (ha->ha_has_provider) {
			error = hibernate_marker_clear(ha);
			if (error == 0)
				error = hibernate_marker_flush(ha);
		}
		break;
	case HMC_ABSENT:
	case HMC_IO_ERROR:
	case HMC_PENDING:
		break;
	}
	if (error == 0)
		error = ENOENT;

cleanup:
	hibernate_attempt_cleanup(ha);
	return (error);
}

/*
 * Pure fail-closed predicate shared by the ACPI gate and host fixtures.
 * Only a successfully flushed PENDING marker may supply true.
 */
bool
hibernate_s4_commit_gate(bool image_committed)
{
	return (image_committed);
}

#ifdef _KERNEL
static uint64_t
hibernate_facs_signature(void)
{
	return (acpi_hibernate_facs_signature());
}

static uint64_t
hibernate_live_physmem_bytes(void)
{
	return ((uint64_t)physmem * PAGE_SIZE);
}
#else
/* TEST-ONLY deterministic live-platform values for host validation. */
uint64_t hibernate_test_facs_signature;
uint64_t hibernate_test_physmem_bytes;

static uint64_t
hibernate_facs_signature(void)
{
	return (hibernate_test_facs_signature);
}

static uint64_t
hibernate_live_physmem_bytes(void)
{
	return (hibernate_test_physmem_bytes);
}

static int
hibernate_test_amd64_cpu_validate_default(const struct hibernate_pcb *pcb,
    bool *refuse_la57, bool *refuse_mtrr)
{
	(void)pcb;
	*refuse_la57 = false;
	*refuse_mtrr = false;
	return (0);
}

int (*hibernate_test_amd64_cpu_validate)(
    const struct hibernate_pcb *, bool *, bool *) =
    hibernate_test_amd64_cpu_validate_default;

static int
hibernate_amd64_cpu_validate(const struct hibernate_pcb *pcb,
    bool *refuse_la57, bool *refuse_mtrr)
{
	return (hibernate_test_amd64_cpu_validate(pcb, refuse_la57,
	    refuse_mtrr));
}
#endif

int
hibernate_image_validate(struct hibernate_attempt *ha)
{
	const struct hibernate_image *image;
	const struct hibernate_cb *cb;
	vm_paddr_t arena_start, arena_end, start, end;
	bool refuse_la57, refuse_mtrr;
	uint64_t i, count;
	int error;

	if (ha == NULL)
		return (EINVAL);
	image = &ha->ha_image;
	cb = &image->hi_cb;

	/* 1. FACS hardware signature. */
	if (hibernate_facs_signature() != cb->hc_facs_hardware_signature)
		return (EINVAL);

	/* 2. Saved physical-memory size. */
	if (cb->hc_physmem_bytes != hibernate_live_physmem_bytes())
		return (EINVAL);

	/* 3. Arena tuple agreement (K-9). */
	if (cb->hc_arena_start != ha->ha_arena_start ||
	    cb->hc_arena_size != ha->ha_arena_size)
		return (EINVAL);

	/*
	 * 4. Destination union: published K-5 view, checked arithmetic,
	 * strictly increasing non-overlapping, disjoint from the arena.
	 */
	if (!ha->ha_dst_valid || ha->ha_dst_intervals == NULL ||
	    ha->ha_dst_count == 0)
		return (EINVAL);
	arena_start = ha->ha_arena_start;
	if (__builtin_add_overflow((uint64_t)arena_start,
	    ha->ha_arena_size, &end))
		return (EOVERFLOW);
	arena_end = end;
	count = ha->ha_dst_count;
	for (i = 0; i < count; i++) {
		start = ha->ha_dst_intervals[i * 2];
		end = ha->ha_dst_intervals[i * 2 + 1];
		if (end <= start)
			return (EINVAL);
		if (i > 0 &&
		    start <= ha->ha_dst_intervals[(i - 1) * 2 + 1])
			return (EINVAL);
		if (start < arena_end && end > arena_start)
			return (EINVAL);
	}

	/* 5-7. Live CPU/paging + LA57/MTRR refusal via the MD helper. */
	error = hibernate_amd64_cpu_validate(&image->hi_pcb, &refuse_la57,
	    &refuse_mtrr);
	if (error != 0)
		return (error);
	if (refuse_la57 || refuse_mtrr)
		return (EINVAL);

	return (0);
}

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
	uint64_t xsave_off, xsave_mask;

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
	xsave_off = le64dec(p + HIBERNATE_PCB_OFF_XSAVE_OFFSET);
	xsave_mask = le64dec(p + HIBERNATE_PCB_OFF_XSAVE_ENABLED_MASK);
	pcb->hp_xsave_length = xsave_len;
	pcb->hp_xsave_format = xsave_fmt;
	pcb->hp_xsave_offset = xsave_off;
	pcb->hp_xsave_enabled_mask = xsave_mask;

	/* xcr0 must contain only ABI-supported bits. */
	if ((xcr0 & ~HIBERNATE_XCR0_SUPPORTED_MASK) != 0)
		return (EINVAL);
	/* x87 and SSE are mandatory. */
	if ((xcr0 & HIBERNATE_XCR0_REQUIRED_MASK) !=
	    HIBERNATE_XCR0_REQUIRED_MASK)
		return (EINVAL);
	/* The enabled-component mask must equal xcr0. */
	if (xsave_mask != xcr0)
		return (EINVAL);

	/* XSAVE format must be HIBERNATE_XSAVE_FORMAT. */
	if (xsave_fmt != HIBERNATE_XSAVE_FORMAT)
		return (EINVAL);

	/*
	 * ABI 1 XSAVE length is a variable payload extent with no fixed
	 * maximum.  Only the canonical minimum is structural here; the
	 * exact extent and its file placement are enforced against the
	 * sole PT_FREEBSD_HIBERNATE_XSAVE program header below.
	 */
	if (xsave_len < HIBERNATE_PCB_XSAVE_MIN)
		return (EINVAL);

	/* Reserved ranges must be zero. */
	if (!is_all_zero(p + HIBERNATE_PCB_OFF_RESERVED_05A,
		HIBERNATE_PCB_WIDTH_RESERVED_05A))
		return (EINVAL);
	if (!is_all_zero(p + HIBERNATE_PCB_OFF_RESERVED_06A,
		HIBERNATE_PCB_WIDTH_RESERVED_06A))
		return (EINVAL);
	if (!is_all_zero(p + HIBERNATE_PCB_OFF_RESERVED_0D0,
		HIBERNATE_PCB_WIDTH_RESERVED_0D0))
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
	uint64_t load_count, cb_count, pcb_count, xsave_count;
	uint64_t load_bytes, load_pages;
	uint64_t first_load_index, last_load_index;
	uint64_t xsave_index, xsave_offset, xsave_length;
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
	xsave_count = 0;
	xsave_index = (uint64_t)-1;
	xsave_offset = 0;
	xsave_length = 0;
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
		    p_type != PT_FREEBSD_HIBERNATE_PCB &&
		    p_type != PT_FREEBSD_HIBERNATE_XSAVE &&
		    p_type != PT_LOAD)
			return (EINVAL);

		/* Strictly increasing image-relative file offsets. */
		if (p_offset < prev_file_end)
			return (EINVAL);

		/* Checked segment end; metadata must fit within the prefix. */
		if (__builtin_add_overflow(p_offset, p_filesz, &seg_end))
			return (EOVERFLOW);
		if (p_type != PT_LOAD &&
		    p_type != PT_FREEBSD_HIBERNATE_XSAVE && seg_end > len)
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

		} else if (p_type == PT_FREEBSD_HIBERNATE_XSAVE) {
			if (xsave_count++ > 0)
				return (EINVAL);
			xsave_index = i;
			xsave_offset = p_offset;
			xsave_length = p_filesz;
			if (p_filesz != p_memsz)
				return (EINVAL);
			if (p_paddr != 0)
				return (EINVAL);
			if (p_filesz < HIBERNATE_PCB_XSAVE_MIN)
				return (EINVAL);
			if ((p_offset & 63) != 0)
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
	if (cb_count != 1 || pcb_count != 1 || xsave_count != 1 || load_count < 1)
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

	/*
	 * Step 11b: verify the sole XSAVE payload object's placement and
	 * cross-check it against the decoded PCB descriptor.
	 */
	{
		uint64_t xsave_end;

		if (xsave_offset < payload_start)
			return (EINVAL);
		if (__builtin_add_overflow(xsave_offset, xsave_length,
			&xsave_end))
			return (EOVERFLOW);
		if (xsave_end > img.hi_cb.hc_image_length)
			return (EINVAL);
		if (img.hi_pcb.hp_xsave_offset != xsave_offset)
			return (EINVAL);
		if (img.hi_pcb.hp_xsave_length != xsave_length)
			return (EINVAL);
		if (img.hi_pcb.hp_xsave_enabled_mask != img.hi_pcb.hp_xcr0)
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
	if (xsave_index != (uint64_t)-1)
		img.hi_xsave_index = (uint32_t)xsave_index;
	img.hi_xsave_offset = xsave_offset;
	img.hi_xsave_length = xsave_length;
	img.hi_xsave_enabled_mask = img.hi_pcb.hp_xsave_enabled_mask;
	img.hi_xsave_format = img.hi_pcb.hp_xsave_format;

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
		it->hii_next_index = 0;
		cursor = it->hii_cursor;
	}

	/* Payload phase: walk stored payload objects in file order. */
	if (it->hii_phase == HIIP_PAYLOAD) {
		const uint8_t *b;
		const uint8_t *ph;
		uint32_t p_type;
		uint64_t p_offset, p_filesz, seg_end;

		b = img->hi_prefix;
		phnum = img->hi_phnum;
		idx = it->hii_next_index;
		cursor = it->hii_cursor;

		/*
		 * Find the next file-backed stored payload object.  Both
		 * PT_LOAD and the sole PT_FREEBSD_HIBERNATE_XSAVE object
		 * are emitted as HIIC_STORED in file-offset order; the
		 * metadata CB/PCB objects live before payload_start and
		 * are already covered by the metadata phase.
		 */
		while (idx < phnum) {
			ph = b + EHDR_SIZE + (uint64_t)idx * PHDR_SIZE;
			p_type = le32dec(ph + PHDR_OFF_P_TYPE);
			if ((p_type == PT_LOAD ||
			    p_type == PT_FREEBSD_HIBERNATE_XSAVE) &&
			    le64dec(ph + PHDR_OFF_P_OFFSET) >= payload_start)
				break;
			idx++;
		}

		if (idx >= phnum) {
			/* No more stored objects; emit trailing gap if any. */
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
