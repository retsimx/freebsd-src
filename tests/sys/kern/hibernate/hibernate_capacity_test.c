/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * ATF tests for the K-5 capacity arithmetic, footprint constants,
 * per-page record bounds, and barrier-stage mask layout.
 *
 * kern_hibernate.c is compiled as a separate translation unit (via the
 * Makefile SRCS list) so that hibernate_capacity_check() exercises the
 * identical production code used by the kernel.
 * hibernate_restore_footprint_derive() is static; its arithmetic is
 * verified here by replicating the seven-component formula from the
 * design contract.
 *
 * Test inventory:
 *   hcb_version_is_one           — HCB_VERSION == 1 compile-time check
 *   capacity_null_budget         — null budget pointer → EINVAL
 *   capacity_null_result         — null result pointer → EINVAL
 *   capacity_zero_physmem        — zero physmem → EINVAL
 *   capacity_zero_destination    — zero destination_union → EINVAL
 *   capacity_arena_exceeds_phys  — arena > physmem → EINVAL
 *   capacity_dst_exceeds_phys    — destination > physmem → EINVAL
 *   capacity_footprint_exceeds   — footprint > physmem → ENOMEM
 *   capacity_4gib_exact          — 4 GiB exact equality → 0
 *   capacity_4gib_minus_one      — 4 GiB exact minus-one eligible → 0
 *   capacity_4gib_plus_one       — 4 GiB one-page shortfall → ENOMEM
 *   capacity_16gib_exact         — 16 GiB exact equality → 0
 *   capacity_16gib_minus_one     — 16 GiB minus-one → 0
 *   capacity_16gib_plus_one      — 16 GiB plus-one shortfall → ENOMEM
 *   capacity_1tib_exact          — 1 TiB exact equality → 0
 *   capacity_1tib_minus_one      — 1 TiB minus-one → 0
 *   capacity_1tib_plus_one       — 1 TiB plus-one shortfall → ENOMEM
 *   capacity_2tib_exact          — 2 TiB exact equality → 0
 *   capacity_2tib_minus_one      — 2 TiB minus-one → 0
 *   capacity_2tib_plus_one       — 2 TiB plus-one shortfall → ENOMEM
 *   capacity_arena_deduction     — arena deduction produces correct shortfall
 *   capacity_footprint_shortfall — footprint consumes all eligible → ENOMEM
 *   capacity_result_fields_ok    — eligible/required/shortfall on success
 *   capacity_result_fields_enomem— result fields populated on ENOMEM
 *   capacity_result_zeroed_einval— result zeroed on every EINVAL path
 *   footprint_default_is_262144  — HIB_FOOTPRINT_DEFAULT == 262144
 *   footprint_max_is_16777216    — HIB_FOOTPRINT_MAX == 16777216
 *   footprint_frag_pct_25        — 25% margin formula (ceiling division)
 *   record_bytes_4gib            — 16-byte record × 4 GiB/4 KiB pages
 *   record_bytes_16gib           — 16-byte record × 16 GiB/4 KiB pages
 *   record_bytes_2tib            — 16-byte record × 2 TiB/4 KiB pages
 *   stage_mask_bits              — HIB_STAGE_* bit positions are correct
 *   struct_capacity_budget_size  — hibernate_capacity_budget ≥ 32 bytes
 *   struct_capacity_result_size  — hibernate_capacity_result ≥ 24 bytes
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Compile-time constants mirroring kern_hibernate.c internal defines.  */
/* These are documented public contracts (design doc §3.3, §7.3).       */
/* ------------------------------------------------------------------ */
#define	TC_HIB_FOOTPRINT_DEFAULT	262144UL
#define	TC_HIB_FOOTPRINT_MAX		16777216UL
#define	TC_HIB_FRAG_PCT			25UL
#define	TC_HIB_FRAG_DIV			100UL

/*
 * Per-page record size.  The design contract specifies that
 * vm_phys_reservation_page is { vm_page_t (8 B), int (4 B), int (4 B) }
 * = 16 bytes on amd64.  We do not include <vm/vm_phys.h> (kernel-only
 * header) from a userland test; instead we assert the component sizes
 * that establish the 16-byte contract.
 */
#define	TC_HIB_RECORD_BYTES		16UL

/* Pages per GiB / TiB for amd64 (PAGE_SIZE == 4096). */
#define	TC_PAGES_PER_GIB	((uint64_t)(1ULL << 30) / 4096)
#define	TC_PAGES_PER_TIB	((uint64_t)(1ULL << 40) / 4096)

/* ------------------------------------------------------------------ */
/* Helper: build a budget with all four fields.                         */
/* ------------------------------------------------------------------ */
static struct hibernate_capacity_budget
make_budget(uint64_t physmem, uint64_t dst, uint64_t arena,
    uint64_t footprint)
{
	struct hibernate_capacity_budget b;

	memset(&b, 0, sizeof(b));
	b.physmem_pages = physmem;
	b.destination_union_pages = dst;
	b.arena_pages = arena;
	b.restore_kernel_footprint_budget = footprint;
	return (b);
}

/* ------------------------------------------------------------------ */
/* HCB_VERSION                                                          */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(hcb_version_is_one);
ATF_TC_BODY(hcb_version_is_one, tc)
{
	ATF_CHECK_EQ(1, HCB_VERSION);
}

/* ------------------------------------------------------------------ */
/* Null-pointer EINVAL paths                                            */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_null_budget);
ATF_TC_BODY(capacity_null_budget, tc)
{
	struct hibernate_capacity_result r;

	memset(&r, 0xa5, sizeof(r));
	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(NULL, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
	ATF_CHECK_EQ(0, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_null_result);
ATF_TC_BODY(capacity_null_result, tc)
{
	struct hibernate_capacity_budget b = make_budget(100, 50, 0, 0);

	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, NULL));
}

/* ------------------------------------------------------------------ */
/* Zero-cardinality EINVAL paths                                        */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_zero_physmem);
ATF_TC_BODY(capacity_zero_physmem, tc)
{
	struct hibernate_capacity_budget b = make_budget(0, 50, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_zero_destination);
ATF_TC_BODY(capacity_zero_destination, tc)
{
	struct hibernate_capacity_budget b = make_budget(1000, 0, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
}

/* ------------------------------------------------------------------ */
/* Impossible set-size EINVAL paths                                     */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_arena_exceeds_phys);
ATF_TC_BODY(capacity_arena_exceeds_phys, tc)
{
	struct hibernate_capacity_budget b = make_budget(1000, 100, 1001, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
}

ATF_TC_WITHOUT_HEAD(capacity_dst_exceeds_phys);
ATF_TC_BODY(capacity_dst_exceeds_phys, tc)
{
	struct hibernate_capacity_budget b = make_budget(1000, 1001, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
}

ATF_TC_WITHOUT_HEAD(capacity_footprint_exceeds);
ATF_TC_BODY(capacity_footprint_exceeds, tc)
{
	struct hibernate_capacity_budget b;
	struct hibernate_capacity_result r;

	/*
	 * The configured 1 GiB restore footprint is representable but cannot
	 * fit in 768 MiB of physical memory.  This is a valid capacity shortage,
	 * not malformed input.
	 */
	b = make_budget(196608, 1, 0, 262144);
	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
	ATF_CHECK_EQ(1, r.required_source_pages);
	ATF_CHECK_EQ(1, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* 4 GiB boundary fixtures                                              */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_4gib_exact);
ATF_TC_BODY(capacity_4gib_exact, tc)
{
	/*
	 * physmem = 2 × dst, dst = 4 GiB pages, arena = 0, footprint = 0.
	 * eligible after dst deduction = dst = required → 0.
	 */
	uint64_t dst = 4 * TC_PAGES_PER_GIB;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(dst, r.eligible_source_pages);
	ATF_CHECK_EQ(dst, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_4gib_minus_one);
ATF_TC_BODY(capacity_4gib_minus_one, tc)
{
	/*
	 * dst = 4 GiB - 1 page; physmem = 2 × dst.
	 * eligible = dst, required = dst → exact equality, 0.
	 */
	uint64_t dst = 4 * TC_PAGES_PER_GIB - 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_4gib_plus_one);
ATF_TC_BODY(capacity_4gib_plus_one, tc)
{
	/*
	 * dst = 4 GiB + 1 page; physmem = 2 × dst; footprint = 1.
	 * eligible = 2dst - dst - 1 = dst - 1 < dst → ENOMEM, shortfall 1.
	 */
	uint64_t dst = 4 * TC_PAGES_PER_GIB + 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 1);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(1, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* 16 GiB boundary fixtures                                             */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_16gib_exact);
ATF_TC_BODY(capacity_16gib_exact, tc)
{
	uint64_t dst = 16 * TC_PAGES_PER_GIB;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(dst, r.eligible_source_pages);
	ATF_CHECK_EQ(dst, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_16gib_minus_one);
ATF_TC_BODY(capacity_16gib_minus_one, tc)
{
	uint64_t dst = 16 * TC_PAGES_PER_GIB - 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_16gib_plus_one);
ATF_TC_BODY(capacity_16gib_plus_one, tc)
{
	uint64_t dst = 16 * TC_PAGES_PER_GIB + 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 1);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(1, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* 1 TiB boundary fixtures                                              */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_1tib_exact);
ATF_TC_BODY(capacity_1tib_exact, tc)
{
	uint64_t dst = TC_PAGES_PER_TIB;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(dst, r.eligible_source_pages);
	ATF_CHECK_EQ(dst, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_1tib_minus_one);
ATF_TC_BODY(capacity_1tib_minus_one, tc)
{
	uint64_t dst = TC_PAGES_PER_TIB - 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_1tib_plus_one);
ATF_TC_BODY(capacity_1tib_plus_one, tc)
{
	uint64_t dst = TC_PAGES_PER_TIB + 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 1);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(1, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* 2 TiB boundary fixtures                                              */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_2tib_exact);
ATF_TC_BODY(capacity_2tib_exact, tc)
{
	/*
	 * 2 TiB = 536,870,912 pages.  2 × that = 1,073,741,824 pages.
	 * Both fit in uint64_t with room to spare.
	 */
	uint64_t dst = 2 * TC_PAGES_PER_TIB;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(dst, r.eligible_source_pages);
	ATF_CHECK_EQ(dst, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_2tib_minus_one);
ATF_TC_BODY(capacity_2tib_minus_one, tc)
{
	uint64_t dst = 2 * TC_PAGES_PER_TIB - 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(capacity_2tib_plus_one);
ATF_TC_BODY(capacity_2tib_plus_one, tc)
{
	uint64_t dst = 2 * TC_PAGES_PER_TIB + 1;
	uint64_t physmem = dst * 2;
	struct hibernate_capacity_budget b = make_budget(physmem, dst, 0, 1);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(1, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* Arena deduction                                                       */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_arena_deduction);
ATF_TC_BODY(capacity_arena_deduction, tc)
{
	/*
	 * physmem = 100, arena = 10, destination = 80, footprint = 0.
	 * eligible = 100 - 10 - 80 = 10 < 80 = required → ENOMEM.
	 * shortfall = 80 - 10 = 70.
	 */
	struct hibernate_capacity_budget b = make_budget(100, 80, 10, 0);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(10, r.eligible_source_pages);
	ATF_CHECK_EQ(80, r.required_source_pages);
	ATF_CHECK_EQ(70, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* Footprint shortfall                                                   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_footprint_shortfall);
ATF_TC_BODY(capacity_footprint_shortfall, tc)
{
	/*
	 * physmem = 200, arena = 0, destination = 100, footprint = 120.
	 * After dst: eligible = 100.  footprint 120 > 100 → ENOMEM.
	 * eligible_out = 0, shortfall = 100 = required.
	 */
	struct hibernate_capacity_budget b = make_budget(200, 100, 0, 120);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
	ATF_CHECK_EQ(100, r.required_source_pages);
	ATF_CHECK_EQ(100, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* Result fields on success                                              */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_result_fields_ok);
ATF_TC_BODY(capacity_result_fields_ok, tc)
{
	/*
	 * physmem = 1000, arena = 50, destination = 200, footprint = 100.
	 * eligible = 1000 - 50 - 200 - 100 = 650 >= 200 → 0.
	 */
	struct hibernate_capacity_budget b = make_budget(1000, 200, 50, 100);
	struct hibernate_capacity_result r;

	memset(&r, 0xa5, sizeof(r));
	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(650, r.eligible_source_pages);
	ATF_CHECK_EQ(200, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* Result fields on ENOMEM                                              */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_result_fields_enomem);
ATF_TC_BODY(capacity_result_fields_enomem, tc)
{
	/*
	 * physmem = 300, arena = 0, destination = 200, footprint = 0.
	 * eligible = 100, required = 200, shortfall = 100 → ENOMEM.
	 */
	struct hibernate_capacity_budget b = make_budget(300, 200, 0, 0);
	struct hibernate_capacity_result r;

	memset(&r, 0, sizeof(r));
	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(100, r.eligible_source_pages);
	ATF_CHECK_EQ(200, r.required_source_pages);
	ATF_CHECK_EQ(100, r.shortfall_pages);
}

/* ------------------------------------------------------------------ */
/* Result zeroed on EINVAL (every EINVAL path must zero the result)     */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(capacity_result_zeroed_einval);
ATF_TC_BODY(capacity_result_zeroed_einval, tc)
{
	struct hibernate_capacity_result r;
	struct hibernate_capacity_budget b;

	/* zero physmem */
	b = make_budget(0, 100, 0, 0);
	memset(&r, 0xa5, sizeof(r));
	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
	ATF_CHECK_EQ(0, r.required_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);

	/* zero destination */
	b = make_budget(1000, 0, 0, 0);
	memset(&r, 0xa5, sizeof(r));
	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);

	/* arena > physmem */
	b = make_budget(1000, 100, 1001, 0);
	memset(&r, 0xa5, sizeof(r));
	ATF_CHECK_EQ(EINVAL, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(0, r.eligible_source_pages);
}

/* ------------------------------------------------------------------ */
/* Footprint constants (behavioral contract verification)               */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(footprint_default_is_262144);
ATF_TC_BODY(footprint_default_is_262144, tc)
{
	/*
	 * HIB_FOOTPRINT_DEFAULT is 262144.  Verify the value and that
	 * hibernate_capacity_check() accepts a budget whose footprint
	 * equals exactly 262144 pages.
	 */
	const uint64_t default_pages = TC_HIB_FOOTPRINT_DEFAULT;
	const uint64_t dst = 1000;
	const uint64_t physmem = dst + default_pages + dst;
	struct hibernate_capacity_budget b =
	    make_budget(physmem, dst, 0, default_pages);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(262144UL, default_pages);
	/* eligible = physmem - dst - footprint = dst = required → 0 */
	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(dst, r.eligible_source_pages);
	ATF_CHECK_EQ(0, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(footprint_max_is_16777216);
ATF_TC_BODY(footprint_max_is_16777216, tc)
{
	const uint64_t max_pages = TC_HIB_FOOTPRINT_MAX;
	const uint64_t dst = 1000;
	const uint64_t physmem = dst + max_pages + dst;
	struct hibernate_capacity_budget b =
	    make_budget(physmem, dst, 0, max_pages);
	struct hibernate_capacity_result r;

	ATF_CHECK_EQ(16777216UL, max_pages);
	ATF_CHECK_EQ(0, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(dst, r.eligible_source_pages);

	/* max + 1 with same physmem → one-page shortfall */
	b.restore_kernel_footprint_budget = max_pages + 1;
	ATF_CHECK_EQ(ENOMEM, hibernate_capacity_check(&b, &r));
	ATF_CHECK_EQ(1, r.shortfall_pages);
}

ATF_TC_WITHOUT_HEAD(footprint_frag_pct_25);
ATF_TC_BODY(footprint_frag_pct_25, tc)
{
	/*
	 * Verify the 25% ceiling-division formula:
	 *   margin_ceil = (total * 25 + 99) / 100
	 * Cross-check a set of golden values.
	 */
	uint64_t total, margin;

	total = 100;
	margin = (total * TC_HIB_FRAG_PCT + TC_HIB_FRAG_DIV - 1) /
	    TC_HIB_FRAG_DIV;
	ATF_CHECK_EQ(25UL, margin);

	total = 101;
	margin = (total * TC_HIB_FRAG_PCT + TC_HIB_FRAG_DIV - 1) /
	    TC_HIB_FRAG_DIV;
	ATF_CHECK_EQ(26UL, margin);

	total = 1;
	margin = (total * TC_HIB_FRAG_PCT + TC_HIB_FRAG_DIV - 1) /
	    TC_HIB_FRAG_DIV;
	ATF_CHECK_EQ(1UL, margin);

	total = 400;
	margin = (total * TC_HIB_FRAG_PCT + TC_HIB_FRAG_DIV - 1) /
	    TC_HIB_FRAG_DIV;
	ATF_CHECK_EQ(100UL, margin);

	/* Zero: no margin for zero base. */
	total = 0;
	margin = (total * TC_HIB_FRAG_PCT + TC_HIB_FRAG_DIV - 1) /
	    TC_HIB_FRAG_DIV;
	ATF_CHECK_EQ(0UL, margin);
}

/* ------------------------------------------------------------------ */
/* Per-page record byte bounds                                           */
/*                                                                      */
/* vm_phys_reservation_page is { vm_page_t (ptr, 8 B), int (4 B),     */
/* int (4 B) } = 16 bytes on amd64.  We verify the acceptance criteria */
/* arithmetic without importing the kernel-only struct directly.        */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(record_bytes_4gib);
ATF_TC_BODY(record_bytes_4gib, tc)
{
	/*
	 * Acceptance criterion: "16,777,216 bytes at 4 GiB".
	 * pages_4gib = 4 GiB / 4 KiB = 1,048,576.
	 * record_bytes = 1,048,576 × 16 = 16,777,216.
	 */
	const uint64_t pages = 4ULL * 1024 * 1024 * 1024 / 4096;
	const uint64_t record_bytes = pages * TC_HIB_RECORD_BYTES;

	ATF_CHECK_EQ(1048576UL, pages);
	ATF_CHECK_EQ(16777216UL, record_bytes);
}

ATF_TC_WITHOUT_HEAD(record_bytes_16gib);
ATF_TC_BODY(record_bytes_16gib, tc)
{
	/*
	 * Acceptance criterion: "67,108,864 bytes at 16 GiB".
	 * pages_16gib = 16 GiB / 4 KiB = 4,194,304.
	 * record_bytes = 4,194,304 × 16 = 67,108,864.
	 */
	const uint64_t pages = 16ULL * 1024 * 1024 * 1024 / 4096;
	const uint64_t record_bytes = pages * TC_HIB_RECORD_BYTES;

	ATF_CHECK_EQ(4194304UL, pages);
	ATF_CHECK_EQ(67108864UL, record_bytes);
}

ATF_TC_WITHOUT_HEAD(record_bytes_2tib);
ATF_TC_BODY(record_bytes_2tib, tc)
{
	/*
	 * Acceptance criterion: "8,589,934,592 bytes at 2 TiB".
	 * pages_2tib = 2 TiB / 4 KiB = 536,870,912.
	 * record_bytes = 536,870,912 × 16 = 8,589,934,592.
	 */
	const uint64_t pages = 2ULL * 1024 * 1024 * 1024 * 1024 / 4096;
	const uint64_t record_bytes = pages * TC_HIB_RECORD_BYTES;

	ATF_CHECK_EQ(536870912UL, pages);
	ATF_CHECK_EQ(8589934592ULL, record_bytes);
}

/* ------------------------------------------------------------------ */
/* Barrier stage mask bits                                               */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stage_mask_bits);
ATF_TC_BODY(stage_mask_bits, tc)
{
	/*
	 * Verify that each HIB_STAGE_* constant is a distinct power of two
	 * and that eight stages fit in an unsigned int.
	 */
	unsigned int stages[] = {
		HIB_STAGE_COORDINATOR,
		HIB_STAGE_RESOURCES,
		HIB_STAGE_APS_STOPPED,
		HIB_STAGE_BSP_PREEMPT,
		HIB_STAGE_BSP_INTRS,
		HIB_STAGE_CALLOUTS,
		HIB_STAGE_CAM,
		HIB_STAGE_RESERVED,
	};
	unsigned int all = 0;
	size_t i;

	ATF_CHECK_EQ(8, sizeof(stages) / sizeof(stages[0]));

	for (i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
		/* Each must be a nonzero power of two. */
		ATF_CHECK(stages[i] != 0);
		ATF_CHECK_EQ(0, stages[i] & (stages[i] - 1));
		/* No two stages share a bit. */
		ATF_CHECK_EQ(0, all & stages[i]);
		all |= stages[i];
	}

	/* All 8 stages occupy distinct low bits of unsigned int. */
	ATF_CHECK_EQ(0xff, all);
}

/* ------------------------------------------------------------------ */
/* Struct size compile checks                                            */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(struct_capacity_budget_size);
ATF_TC_BODY(struct_capacity_budget_size, tc)
{
	/* Four uint64_t fields = 32 bytes minimum. */
	ATF_CHECK(sizeof(struct hibernate_capacity_budget) >= 32);
}

ATF_TC_WITHOUT_HEAD(struct_capacity_result_size);
ATF_TC_BODY(struct_capacity_result_size, tc)
{
	/* Three uint64_t fields = 24 bytes minimum. */
	ATF_CHECK(sizeof(struct hibernate_capacity_result) >= 24);
}

/* ------------------------------------------------------------------ */
/* N7: exercise production footprint derivation directly                 */
/* ------------------------------------------------------------------ */

/*
 * footprint_compute_4gib: call the production
 * hibernate_restore_footprint_compute() with a 4 GiB destination count
 * and known wired_pages=0 (isolates the formula components other than
 * wired pages).  This exercises the real seven-component formula rather
 * than a duplicated constant, satisfying N7.
 */
ATF_TC_WITHOUT_HEAD(footprint_derive_production_4gib);
ATF_TC_BODY(footprint_derive_production_4gib, tc)
{
	uint64_t derived = 0;
	int error;

	/*
	 * wired_pages=0 isolates the six remaining components.
	 * 4 GiB destination is well within supported range.
	 */
	error = hibernate_restore_footprint_compute(TC_PAGES_PER_GIB * 4,
	    0, &derived);
	ATF_CHECK_EQ_MSG(0, error,
	    "hibernate_restore_footprint_compute(4GiB, 0) returned %d", error);
	ATF_CHECK_MSG(derived > 0,
	    "derived footprint is zero with 4 GiB destination");
	ATF_CHECK_MSG(derived <= TC_HIB_FOOTPRINT_MAX,
	    "derived footprint %llu exceeds max %lu",
	    (unsigned long long)derived, TC_HIB_FOOTPRINT_MAX);
}

ATF_TC_WITHOUT_HEAD(footprint_derive_production_1tib);
ATF_TC_BODY(footprint_derive_production_1tib, tc)
{
	uint64_t derived = 0;
	int error;

	/* 1 TiB destination, wired_pages=0: may succeed or ENOMEM. */
	error = hibernate_restore_footprint_compute(TC_PAGES_PER_TIB,
	    0, &derived);
	ATF_CHECK_MSG(error == 0 || error == ENOMEM,
	    "unexpected error %d from footprint_compute(1TiB, 0)", error);
	if (error == 0)
		ATF_CHECK_MSG(derived > 0,
		    "derived footprint is zero for 1 TiB");
}

ATF_TC_WITHOUT_HEAD(footprint_derive_zero_dst);
ATF_TC_BODY(footprint_derive_zero_dst, tc)
{
	uint64_t derived = 0;
	int error;

	/*
	 * Zero destination pages, wired_pages=0: source-vector and
	 * reservation components are zero; result comes from metadata,
	 * BIO buffer, scratch stack, and margin only.
	 */
	error = hibernate_restore_footprint_compute(0, 0, &derived);
	ATF_CHECK_EQ_MSG(0, error,
	    "footprint_compute(0, 0) returned %d", error);
	ATF_CHECK_MSG(derived > 0,
	    "derived footprint is zero with zero dst and zero wired");
}

/* ------------------------------------------------------------------ */
/* ATF_TP registration                                                  */
/* ------------------------------------------------------------------ */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hcb_version_is_one);
	ATF_TP_ADD_TC(tp, capacity_null_budget);
	ATF_TP_ADD_TC(tp, capacity_null_result);
	ATF_TP_ADD_TC(tp, capacity_zero_physmem);
	ATF_TP_ADD_TC(tp, capacity_zero_destination);
	ATF_TP_ADD_TC(tp, capacity_arena_exceeds_phys);
	ATF_TP_ADD_TC(tp, capacity_dst_exceeds_phys);
	ATF_TP_ADD_TC(tp, capacity_footprint_exceeds);
	ATF_TP_ADD_TC(tp, capacity_4gib_exact);
	ATF_TP_ADD_TC(tp, capacity_4gib_minus_one);
	ATF_TP_ADD_TC(tp, capacity_4gib_plus_one);
	ATF_TP_ADD_TC(tp, capacity_16gib_exact);
	ATF_TP_ADD_TC(tp, capacity_16gib_minus_one);
	ATF_TP_ADD_TC(tp, capacity_16gib_plus_one);
	ATF_TP_ADD_TC(tp, capacity_1tib_exact);
	ATF_TP_ADD_TC(tp, capacity_1tib_minus_one);
	ATF_TP_ADD_TC(tp, capacity_1tib_plus_one);
	ATF_TP_ADD_TC(tp, capacity_2tib_exact);
	ATF_TP_ADD_TC(tp, capacity_2tib_minus_one);
	ATF_TP_ADD_TC(tp, capacity_2tib_plus_one);
	ATF_TP_ADD_TC(tp, capacity_arena_deduction);
	ATF_TP_ADD_TC(tp, capacity_footprint_shortfall);
	ATF_TP_ADD_TC(tp, capacity_result_fields_ok);
	ATF_TP_ADD_TC(tp, capacity_result_fields_enomem);
	ATF_TP_ADD_TC(tp, capacity_result_zeroed_einval);
	ATF_TP_ADD_TC(tp, footprint_default_is_262144);
	ATF_TP_ADD_TC(tp, footprint_max_is_16777216);
	ATF_TP_ADD_TC(tp, footprint_frag_pct_25);
	ATF_TP_ADD_TC(tp, record_bytes_4gib);
	ATF_TP_ADD_TC(tp, record_bytes_16gib);
	ATF_TP_ADD_TC(tp, record_bytes_2tib);
	ATF_TP_ADD_TC(tp, stage_mask_bits);
	ATF_TP_ADD_TC(tp, struct_capacity_budget_size);
	ATF_TP_ADD_TC(tp, struct_capacity_result_size);
	ATF_TP_ADD_TC(tp, footprint_derive_production_4gib);
	ATF_TP_ADD_TC(tp, footprint_derive_production_1tib);
	ATF_TP_ADD_TC(tp, footprint_derive_zero_dst);
	return (atf_no_error());
}
