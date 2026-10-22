/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Direct regression coverage of the authoritative production
 * hibernate_md_private_leaf_requirement() calculation in
 * sys/amd64/amd64/hibernate_machdep.c (issue #15, item e).
 *
 * This file compiles the real production function by defining
 * _HIBERNATE_LEAF_REQUIREMENT_TEST and including hibernate_machdep.c
 * directly.  No copy of the arithmetic lives here; the test exercises
 * the identical code path the kernel uses to size the private CR3
 * tree's leaf-page budget before any page-table allocation.
 *
 * hibernate_compat.h (force-included via the Makefile, same seam
 * hibernate_arena_test.c and friends already use) supplies struct
 * hibernate_attempt, vm_paddr_t, and every other type this function
 * needs; hibernate_machdep.c itself needs nothing beyond that under
 * _HIBERNATE_LEAF_REQUIREMENT_TEST, since every other declaration in
 * the file is skipped by the test-seam guard added for this issue.
 */

#include <machine/param.h> /* NBPDR: 2 MiB region size, host-safe. */

#define _HIBERNATE_LEAF_REQUIREMENT_TEST
#include <atf-c.h>

#include "hibernate_machdep.c"

/*
 * Build a minimal, valid struct hibernate_attempt destination-interval
 * view: ha_dst_valid, ha_dst_intervals, ha_dst_count set directly, every
 * other field left zeroed (HIBERNATE_ATTEMPT_INIT), matching the real
 * caller's contract documented at hibernate_md_private_leaf_requirement()
 * itself ("callers must not reach here before VALIDATE has published
 * it").
 */
static void
make_attempt(struct hibernate_attempt *ha, vm_paddr_t *intervals,
    uint64_t count, vm_paddr_t arena_start)
{
	*ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	ha->ha_dst_valid = true;
	ha->ha_dst_intervals = intervals;
	ha->ha_dst_count = count;
	ha->ha_arena_start = arena_start;
}

ATF_TC_WITHOUT_HEAD(unpublished_view_refused);
ATF_TC_BODY(unpublished_view_refused, tc)
{
	struct hibernate_attempt ha = HIBERNATE_ATTEMPT_INIT;
	vm_paddr_t intervals[2] = { 0x100000, 0x200000 };
	uint64_t out;

	/* ha_dst_valid left false: must refuse, not read ha_dst_intervals. */
	ATF_CHECK_EQ(EINVAL,
	    hibernate_md_private_leaf_requirement(&ha, 0x400000, NULL, 0,
		0x300000, 1, 0x380000, &out));

	/* ha_dst_valid true but intervals NULL: must still refuse. */
	ha.ha_dst_valid = true;
	ha.ha_dst_count = 1;
	ATF_CHECK_EQ(EINVAL,
	    hibernate_md_private_leaf_requirement(&ha, 0x400000, NULL, 0,
		0x300000, 1, 0x380000, &out));

	/* ha_dst_valid true, intervals set, but count zero: must refuse. */
	ha.ha_dst_intervals = intervals;
	ha.ha_dst_count = 0;
	ATF_CHECK_EQ(EINVAL,
	    hibernate_md_private_leaf_requirement(&ha, 0x400000, NULL, 0,
		0x300000, 1, 0x380000, &out));
}

ATF_TC_WITHOUT_HEAD(malformed_interval_refused);
ATF_TC_BODY(malformed_interval_refused, tc)
{
	struct hibernate_attempt ha;
	/* end <= start: a zero-length or backward interval. */
	vm_paddr_t intervals[2] = { 0x200000, 0x200000 };
	uint64_t out;

	make_attempt(&ha, intervals, 1, 0x400000);
	ATF_CHECK_EQ(EINVAL,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
}

ATF_TC_WITHOUT_HEAD(single_region_minimum);
ATF_TC_BODY(single_region_minimum, tc)
{
	struct hibernate_attempt ha;
	/* One page, entirely inside one 2 MiB region. */
	vm_paddr_t intervals[2] = { 0x200000, 0x201000 };
	uint64_t out;

	make_attempt(&ha, intervals, 1, 0x400000);
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
	/*
	 * Four independently-counted regions, never deduplicated: the one
	 * destination region, the arena's one region, the one-page vector
	 * range's one region, and the XSAVE page's own region.
	 */
	ATF_CHECK_EQ(4, out);
}

ATF_TC_WITHOUT_HEAD(destination_spans_two_regions);
ATF_TC_BODY(destination_spans_two_regions, tc)
{
	struct hibernate_attempt ha;
	/* [0x1ff000, 0x201000) straddles the 0x200000 2 MiB boundary. */
	vm_paddr_t intervals[2] = { 0x1ff000, 0x201000 };
	uint64_t out;

	make_attempt(&ha, intervals, 1, 0x400000);
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
	/* 2 destination regions + arena + vector + XSAVE = 5. */
	ATF_CHECK_EQ(5, out);
}

ATF_TC_WITHOUT_HEAD(contiguous_destination_regions_not_double_counted);
ATF_TC_BODY(contiguous_destination_regions_not_double_counted, tc)
{
	struct hibernate_attempt ha;
	/*
	 * Two separate destination runs that both land in the SAME 2 MiB
	 * region: must count as one region, not two, proving the
	 * "region != last_region" de-duplication within one pass.
	 */
	vm_paddr_t intervals[4] = {
		0x100000,
		0x101000, /* first page of the region */
		0x1ff000,
		0x200000, /* last page of the SAME region */
	};
	uint64_t out;

	make_attempt(&ha, intervals, 2, 0x400000);
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
	/* 1 destination region (shared) + arena + vector + XSAVE = 4. */
	ATF_CHECK_EQ(4, out);
}

#define REGION_COUNT 502

/*
 * Construct a destination-interval fixture spanning 502 distinct,
 * non-adjacent 2 MiB regions -- matching this issue's own cited
 * real-world QEMU measurement at 4 GiB RAM, entirely host-runnable and
 * QEMU-free.  Every entry is skipped by one full 2 MiB region, so no
 * two consecutive one-page intervals ever land in the same leaf region.
 * Shared by both tests below, which differ only in what they check
 * about the resulting measured count.
 */
static void
fill_many_regions(struct hibernate_attempt *ha, vm_paddr_t *intervals)
{
	uint64_t i;

	for (i = 0; i < REGION_COUNT; i++) {
		vm_paddr_t base = 0x10000000 + i * (vm_paddr_t)(2 * NBPDR);
		intervals[i * 2] = base;
		intervals[i * 2 + 1] = base + HIB_PAGE_SIZE;
	}
	make_attempt(ha, intervals, REGION_COUNT, 0x400000);
}

ATF_TC_WITHOUT_HEAD(five_hundred_plus_regions_measured);
ATF_TC_BODY(five_hundred_plus_regions_measured, tc)
{
	static struct hibernate_attempt ha;
	static vm_paddr_t intervals[REGION_COUNT * 2];
	uint64_t out;

	fill_many_regions(&ha, intervals);
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
	/* 502 destination regions + arena + vector + XSAVE = 505. */
	ATF_CHECK_EQ(REGION_COUNT + 3, out);
}

ATF_TC_WITHOUT_HEAD(budget_refusal_fail_closed);
ATF_TC_BODY(budget_refusal_fail_closed, tc)
{
	/*
	 * Exercise the production builder refusal predicate at its boundary:
	 * requirements at and below budget are accepted, while a requirement
	 * strictly above budget is refused.
	 */
	static struct hibernate_attempt ha;
	static vm_paddr_t intervals[REGION_COUNT * 2];
	uint64_t out;
	const uint64_t measured = REGION_COUNT + 3;

	fill_many_regions(&ha, intervals);
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
	ATF_REQUIRE_EQ(measured, out);

	ATF_CHECK(
	    hibernate_md_leaf_budget_ok(out, HIBERNATE_ARENA_PT_LEAF_PAGES));
	ATF_CHECK(hibernate_md_leaf_budget_ok(out, measured));
	ATF_CHECK(!hibernate_md_leaf_budget_ok(out, measured - 1));
}
#undef REGION_COUNT

ATF_TC_WITHOUT_HEAD(overflow_checked_arithmetic);
ATF_TC_BODY(overflow_checked_arithmetic, tc)
{
	struct hibernate_attempt ha;
	/* An interval ending at the top of the address space. */
	vm_paddr_t intervals[2] = { UINT64_MAX - HIB_PAGE_SIZE, UINT64_MAX };
	uint64_t out;

	make_attempt(&ha, intervals, 1, 0x400000);
	/*
	 * The region-stepping loop will overflow stepping past UINT64_MAX;
	 * must return EOVERFLOW, never wrap silently into a small count.
	 */
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &out));
}

ATF_TC_WITHOUT_HEAD(scattered_vector_increases_requirement);
ATF_TC_BODY(scattered_vector_increases_requirement, tc)
{
	struct hibernate_attempt ha;
	vm_paddr_t intervals[2] = { 0x200000, 0x201000 };
	vm_paddr_t vector[3] = { 0x800000, 0xa00000, 0xc00000 };
	uint64_t without_vector, with_vector;

	make_attempt(&ha, intervals, 1, 0x400000);
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 1, 0x580000, &without_vector));
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, vector,
		nitems(vector), 0x500000, 1, 0x580000, &with_vector));
	ATF_CHECK_EQ(without_vector + nitems(vector), with_vector);
}

ATF_TC_WITHOUT_HEAD(zero_vector_pages_skips_vector_region);
ATF_TC_BODY(zero_vector_pages_skips_vector_region, tc)
{
	struct hibernate_attempt ha;
	vm_paddr_t intervals[2] = { 0x200000, 0x201000 };
	uint64_t out;

	make_attempt(&ha, intervals, 1, 0x400000);
	/* vector_pages == 0: the vector-range region must not be counted. */
	ATF_REQUIRE_EQ(0,
	    hibernate_md_private_leaf_requirement(&ha, 0x600000, NULL, 0,
		0x500000, 0, 0x580000, &out));
	/* 1 destination region + arena + XSAVE = 3 (no vector region). */
	ATF_CHECK_EQ(3, out);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unpublished_view_refused);
	ATF_TP_ADD_TC(tp, malformed_interval_refused);
	ATF_TP_ADD_TC(tp, single_region_minimum);
	ATF_TP_ADD_TC(tp, destination_spans_two_regions);
	ATF_TP_ADD_TC(tp, contiguous_destination_regions_not_double_counted);
	ATF_TP_ADD_TC(tp, five_hundred_plus_regions_measured);
	ATF_TP_ADD_TC(tp, budget_refusal_fail_closed);
	ATF_TP_ADD_TC(tp, overflow_checked_arithmetic);
	ATF_TP_ADD_TC(tp, scattered_vector_increases_requirement);
	ATF_TP_ADD_TC(tp, zero_vector_pages_skips_vector_region);
	return (atf_no_error());
}
