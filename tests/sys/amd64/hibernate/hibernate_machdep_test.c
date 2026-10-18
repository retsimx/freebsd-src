/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * MD testability boundary
 * -----------------------
 * hibernate_machdep_prepare() cannot execute in an unprivileged process.  It
 * depends on PHYS_TO_DMAP, kernel_pmap, privileged control registers and
 * MSRs, live pmap mutation, and the assembly transition entry.
 *
 * The fixtures below do not fake those operations.  They exercise faithful
 * pure models of prepare's refusal predicates: synthetic page-table lookup,
 * arena geometry and destination intersection, run-table cardinality, and
 * checked arithmetic.  Live saved-domain insertion and the final privileged
 * walk still require kernel/QEMU evidence; the synthetic walker tests the
 * same missing-mapping refusal without claiming to execute kernel pmap code.
 *
 * Header and handoff fixtures call the production codecs through the existing
 * _HIBERNATE_USERLAND_BUILD seam.
 */

#include <sys/param.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define HANDOFF_RESERVED_OFF (HIBERNATE_HANDOFF_ENCODED_SIZE - 6)
#define TEST_PAGE_SIZE	     UINT64_C(4096)
#define TEST_RUN_MAX	     UINT64_C(4)

struct test_mapping {
	uint64_t tm_va;
	uint64_t tm_pa;
	bool tm_valid;
};

static int
prepare_saved_mapping_validate(const struct test_mapping *mappings,
    size_t count, uint64_t va, uint64_t expected_pa)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (mappings[i].tm_valid && mappings[i].tm_va == va)
			return (mappings[i].tm_pa == expected_pa ? 0 : EINVAL);
	}
	return (EINVAL);
}

static int
prepare_arena_validate(uint64_t arena_start, uint64_t arena_size,
    uint64_t required, uint64_t destination_start, uint64_t destination_end)
{
	uint64_t arena_end;

	if ((arena_start % HIBERNATE_ARENA_ALIGNMENT) != 0 ||
	    arena_size < required ||
	    (arena_size % HIBERNATE_ARENA_ALIGNMENT) != 0)
		return (EINVAL);
	if (__builtin_add_overflow(arena_start, arena_size, &arena_end))
		return (EOVERFLOW);
	if (destination_end <= destination_start)
		return (EINVAL);
	if (destination_start < arena_end && destination_end > arena_start)
		return (EINVAL);
	return (0);
}

static int
prepare_run_table_validate(const vm_paddr_t *pairs, size_t pair_count,
    uint64_t run_max, uint64_t *pages_out)
{
	uint64_t count, pages, total;
	size_t i;

	total = 0;
	for (i = 0; i < pair_count; i++) {
		if (i >= run_max)
			return (ENOMEM);
		if (pairs[i * 2 + 1] <= pairs[i * 2] ||
		    (pairs[i * 2] % TEST_PAGE_SIZE) != 0 ||
		    (pairs[i * 2 + 1] % TEST_PAGE_SIZE) != 0)
			return (EINVAL);
		count = (pairs[i * 2 + 1] - pairs[i * 2]) / TEST_PAGE_SIZE;
		if (__builtin_add_overflow(total, count, &pages))
			return (EOVERFLOW);
		total = pages;
	}
	*pages_out = total;
	return (0);
}

static int
prepare_run_extent_validate(uint64_t start, uint64_t page_count)
{
	uint64_t bytes, end;

	if (__builtin_mul_overflow(page_count, TEST_PAGE_SIZE, &bytes) ||
	    __builtin_add_overflow(start, bytes, &end))
		return (EOVERFLOW);
	return (end > start ? 0 : EINVAL);
}

static struct hibernate_handoff_record
golden_handoff(void)
{
	struct hibernate_handoff_record hhr;

	memset(&hhr, 0, sizeof(hhr));
	hhr.hhr_magic = HIBERNATE_HANDOFF_MAGIC;
	hhr.hhr_version = HIBERNATE_HANDOFF_VERSION;
	hhr.hhr_encoded_size = HIBERNATE_HANDOFF_ENCODED_SIZE;
	memcpy(hhr.hhr_provider_name, "swap-test", sizeof("swap-test"));
	hhr.hhr_provider_media_size = UINT64_C(0x100000000);
	hhr.hhr_provider_writable = 1;
	hhr.hhr_marker_offset = UINT64_C(0x2000);
	hhr.hhr_image_offset = UINT64_C(0x10000);
	hhr.hhr_image_length = UINT64_C(0x800000);
	hhr.hhr_marker_sequence = 7;
	hhr.hhr_marker_state = HIBERNATE_MARKER_STATE_CONSUMING;
	hhr.hhr_completion_provider_acquired = 1;
	return (hhr);
}

ATF_TC_WITHOUT_HEAD(missing_saved_domain_mapping);
ATF_TC_BODY(missing_saved_domain_mapping, tc)
{
	const struct test_mapping mappings[] = {
		{ UINT64_C(0x1000), UINT64_C(0x2000), true },
		{ UINT64_C(0x3000), UINT64_C(0x4000), false },
	};

	ATF_CHECK_EQ(EINVAL,
	    prepare_saved_mapping_validate(mappings, nitems(mappings),
		UINT64_C(0x3000), UINT64_C(0x4000)));
	ATF_CHECK_EQ(EINVAL,
	    prepare_saved_mapping_validate(mappings, nitems(mappings),
		UINT64_C(0x5000), UINT64_C(0x6000)));
}

ATF_TC_WITHOUT_HEAD(arena_destination_overlap);
ATF_TC_BODY(arena_destination_overlap, tc)
{
	struct hibernate_arena_sizing sizing;
	uint64_t arena_start, arena_end;

	ATF_REQUIRE_EQ(0, hibernate_arena_required(&sizing));
	arena_start = UINT64_C(0x100000);
	ATF_REQUIRE(!__builtin_add_overflow(arena_start, sizing.has_required,
	    &arena_end));

	ATF_CHECK_EQ(EINVAL,
	    prepare_arena_validate(arena_start, sizing.has_required,
		sizing.has_required, arena_start + TEST_PAGE_SIZE,
		arena_end + TEST_PAGE_SIZE));
	ATF_CHECK_EQ(0,
	    prepare_arena_validate(arena_start, sizing.has_required,
		sizing.has_required, arena_end, arena_end + TEST_PAGE_SIZE));
}

ATF_TC_WITHOUT_HEAD(unaligned_or_undersized_arena);
ATF_TC_BODY(unaligned_or_undersized_arena, tc)
{
	struct hibernate_arena_sizing sizing;
	uint64_t destination;

	ATF_REQUIRE_EQ(0, hibernate_arena_required(&sizing));
	destination = UINT64_C(0x800000);

	ATF_CHECK_EQ(EINVAL,
	    prepare_arena_validate(UINT64_C(0x100001), sizing.has_required,
		sizing.has_required, destination,
		destination + TEST_PAGE_SIZE));
	ATF_CHECK_EQ(EINVAL,
	    prepare_arena_validate(UINT64_C(0x100000),
		sizing.has_required - HIBERNATE_ARENA_ALIGNMENT,
		sizing.has_required, destination,
		destination + TEST_PAGE_SIZE));
}

ATF_TC_WITHOUT_HEAD(run_table_overflow);
ATF_TC_BODY(run_table_overflow, tc)
{
	const vm_paddr_t pairs[] = {
		UINT64_C(0x1000),
		UINT64_C(0x2000),
		UINT64_C(0x3000),
		UINT64_C(0x4000),
		UINT64_C(0x5000),
		UINT64_C(0x6000),
		UINT64_C(0x7000),
		UINT64_C(0x8000),
		UINT64_C(0x9000),
		UINT64_C(0xa000),
	};
	uint64_t pages;

	ATF_CHECK_EQ(ENOMEM,
	    prepare_run_table_validate(pairs, nitems(pairs) / 2, TEST_RUN_MAX,
		&pages));
}

ATF_TC_WITHOUT_HEAD(checked_arithmetic_overflow);
ATF_TC_BODY(checked_arithmetic_overflow, tc)
{
	ATF_CHECK_EQ(EOVERFLOW,
	    prepare_arena_validate(UINT64_MAX - HIBERNATE_ARENA_ALIGNMENT + 1,
		HIBERNATE_ARENA_ALIGNMENT, HIBERNATE_ARENA_ALIGNMENT, 0,
		TEST_PAGE_SIZE));
	ATF_CHECK_EQ(EOVERFLOW,
	    prepare_run_extent_validate(0, UINT64_MAX / TEST_PAGE_SIZE + 1));
	ATF_CHECK_EQ(EOVERFLOW,
	    prepare_run_extent_validate(UINT64_MAX - TEST_PAGE_SIZE + 1, 1));
}

ATF_TC_WITHOUT_HEAD(reserved_byte_rejection);
ATF_TC_BODY(reserved_byte_rejection, tc)
{
	struct hibernate_arena_header hah, decoded_hah;
	struct hibernate_handoff_record hhr, decoded_hhr;
	uint8_t arena_buf[HIBERNATE_ARENA_HEADER_ENCODED_SIZE];
	uint8_t handoff_buf[HIBERNATE_HANDOFF_ENCODED_SIZE];
	size_t i;

	memset(&hah, 0, sizeof(hah));
	hah.hah_magic = HIBERNATE_ARENA_HEADER_MAGIC;
	hah.hah_version = HIBERNATE_ARENA_HEADER_VERSION;
	hah.hah_header_size = HIBERNATE_ARENA_HEADER_ENCODED_SIZE;
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_header_encode(arena_buf, sizeof(arena_buf), &hah));
	for (i = HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0; i < sizeof(arena_buf);
	    i++) {
		arena_buf[i] = 1;
		ATF_CHECK_EQ_MSG(EINVAL,
		    hibernate_arena_header_decode(arena_buf, sizeof(arena_buf),
			&decoded_hah),
		    "arena reserved byte %zu accepted", i);
		arena_buf[i] = 0;
	}

	hhr = golden_handoff();
	ATF_REQUIRE_EQ(0,
	    hibernate_handoff_record_encode(handoff_buf, sizeof(handoff_buf),
		&hhr));
	for (i = HANDOFF_RESERVED_OFF; i < sizeof(handoff_buf); i++) {
		handoff_buf[i] = 1;
		ATF_CHECK_EQ_MSG(EINVAL,
		    hibernate_handoff_record_decode(handoff_buf,
			sizeof(handoff_buf), &decoded_hhr),
		    "handoff reserved byte %zu accepted", i);
		handoff_buf[i] = 0;
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, missing_saved_domain_mapping);
	ATF_TP_ADD_TC(tp, arena_destination_overlap);
	ATF_TP_ADD_TC(tp, unaligned_or_undersized_arena);
	ATF_TP_ADD_TC(tp, run_table_overflow);
	ATF_TP_ADD_TC(tp, checked_arithmetic_overflow);
	ATF_TP_ADD_TC(tp, reserved_byte_rejection);
	return (atf_no_error());
}
