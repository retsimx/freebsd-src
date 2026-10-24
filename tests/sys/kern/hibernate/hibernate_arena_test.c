/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

#include <sys/param.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

ATF_TC_WITHOUT_HEAD(required_golden);
ATF_TC_BODY(required_golden, tc)
{
	struct hibernate_arena_sizing sizing;

	ATF_REQUIRE_EQ(0, hibernate_arena_required(&sizing));
	ATF_CHECK_EQ(UINT64_C(17321984), sizing.has_private_page_tables);
	ATF_CHECK_EQ(UINT64_C(28800), sizing.has_copy_run_storage);
	ATF_CHECK_EQ(UINT64_C(1024), sizing.has_aux_descriptor_storage);
	ATF_CHECK_EQ(UINT64_C(32768), sizing.has_descriptor_storage);
	ATF_CHECK_EQ(UINT64_C(28665), sizing.has_alignment_allowance);
	ATF_CHECK_EQ(UINT64_C(17539065), sizing.has_raw_required);
	ATF_CHECK_EQ(UINT64_C(17539072), sizing.has_required);
	ATF_CHECK_EQ(3, HIBERNATE_ARENA_RULE_VERSION);
	ATF_CHECK_EQ(1, HCB_VERSION);
	ATF_CHECK_EQ(0x040, HIBERNATE_CB_OFF_ARENA_START);
	ATF_CHECK_EQ(0x048, HIBERNATE_CB_OFF_ARENA_SIZE);
}

ATF_TC_WITHOUT_HEAD(normalize_precedence);
ATF_TC_BODY(normalize_precedence, tc)
{
	struct hibernate_arena_interval input[] = {
		{ 0x3000, 0x9000, HAIC_ELIGIBLE },
		{ 0x1000, 0x5000, HAIC_ELIGIBLE },
		{ 0x4000, 0x6000, HAIC_INELIGIBLE_FIRMWARE },
	};
	struct hibernate_arena_interval output[8];
	size_t count;

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_normalize(input, nitems(input), output,
		nitems(output), &count));
	ATF_REQUIRE_EQ(3, count);
	ATF_CHECK_EQ(0x1000, output[0].hai_start);
	ATF_CHECK_EQ(0x4000, output[0].hai_end);
	ATF_CHECK_EQ(HAIC_ELIGIBLE, output[0].hai_class);
	ATF_CHECK_EQ(0x4000, output[1].hai_start);
	ATF_CHECK_EQ(0x6000, output[1].hai_end);
	ATF_CHECK_EQ(HAIC_INELIGIBLE_FIRMWARE, output[1].hai_class);
	ATF_CHECK_EQ(0x6000, output[2].hai_start);
	ATF_CHECK_EQ(0x9000, output[2].hai_end);
	ATF_CHECK_EQ(HAIC_ELIGIBLE, output[2].hai_class);
}

ATF_TC_WITHOUT_HEAD(live_exclusion);
ATF_TC_BODY(live_exclusion, tc)
{
	struct hibernate_arena_interval intervals[4] = {
		{ 0x1000, 0x9000, HAIC_ELIGIBLE },
	};
	size_t count;

	count = 1;
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_exclude_live(intervals, &count, nitems(intervals),
		0x3000, 0x5000));
	ATF_REQUIRE_EQ(2, count);
	ATF_CHECK_EQ(0x1000, intervals[0].hai_start);
	ATF_CHECK_EQ(0x3000, intervals[0].hai_end);
	ATF_CHECK_EQ(0x5000, intervals[1].hai_start);
	ATF_CHECK_EQ(0x9000, intervals[1].hai_end);
}

ATF_TC_WITHOUT_HEAD(selection_highest);
ATF_TC_BODY(selection_highest, tc)
{
	/*
	 * Intervals sized well above the rule-version-3 required bytes
	 * (17,539,072, driven by HIBERNATE_ARENA_PT_LEAF_PAGES=4096 plus the
	 * K-23 arena park-stack component; see hibernate.h), unlike rule
	 * version 1's much smaller requirement.
	 */
	struct hibernate_arena_interval intervals[] = {
		{ 0x1000000, 0x3000000, HAIC_ELIGIBLE },
		{ 0x8000000, 0xa000000, HAIC_ELIGIBLE },
		{ 0xb000000, 0xc000000, HAIC_INELIGIBLE_FIRMWARE },
	};
	vm_paddr_t pa;
	vm_size_t size;

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_select(intervals, nitems(intervals),
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa, &size));
	ATF_CHECK_EQ(UINT64_C(17539072), size);
	ATF_CHECK_EQ(UINT64_C(0x8f46000), pa);
	ATF_CHECK_EQ(ENOMEM,
	    hibernate_arena_select(intervals, nitems(intervals),
		UINT64_C(17534976), &pa, &size));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_select(intervals, nitems(intervals),
		UINT64_C(17539073), &pa, &size));
}

static void
check_split(const vm_paddr_t *input, size_t input_count, vm_paddr_t arena_start,
    vm_paddr_t arena_end, const vm_paddr_t *expected, size_t expected_count)
{
	vm_paddr_t output[12];
	size_t count;

	memset(output, 0, sizeof(output));
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_split_pairs(input, input_count, arena_start,
		arena_end, output, nitems(output), &count));
	ATF_REQUIRE_EQ(expected_count, count);
	ATF_CHECK_EQ(0,
	    memcmp(output, expected, expected_count * sizeof(expected[0])));
}

ATF_TC_WITHOUT_HEAD(split_five_cases);
ATF_TC_BODY(split_five_cases, tc)
{
	const vm_paddr_t disjoint_in[] = { 0x1000, 0x2000 };
	const vm_paddr_t disjoint_out[] = { 0x1000, 0x2000 };
	const vm_paddr_t exact_in[] = { 0x3000, 0x5000 };
	const vm_paddr_t left_out[] = { 0x4000, 0x5000 };
	const vm_paddr_t right_out[] = { 0x3000, 0x4000 };
	const vm_paddr_t interior_in[] = { 0x2000, 0x6000 };
	const vm_paddr_t interior_out[] = { 0x2000, 0x3000, 0x5000, 0x6000 };
	vm_paddr_t output[2];
	size_t count;

	check_split(disjoint_in, nitems(disjoint_in), 0x3000, 0x5000,
	    disjoint_out, nitems(disjoint_out));
	check_split(exact_in, nitems(exact_in), 0x3000, 0x5000, NULL, 0);
	check_split(exact_in, nitems(exact_in), 0x3000, 0x4000, left_out,
	    nitems(left_out));
	check_split(exact_in, nitems(exact_in), 0x4000, 0x5000, right_out,
	    nitems(right_out));
	check_split(interior_in, nitems(interior_in), 0x3000, 0x5000,
	    interior_out, nitems(interior_out));
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_arena_split_pairs(interior_in, nitems(interior_in),
		0x3000, 0x5000, output, nitems(output), &count));
}

ATF_TC_WITHOUT_HEAD(ownership);
ATF_TC_BODY(ownership, tc)
{
	struct hibernate_attempt first = HIBERNATE_ATTEMPT_INIT;
	struct hibernate_attempt second = HIBERNATE_ATTEMPT_INIT;

	hibernate_arena_reset();
	ATF_CHECK_EQ(EINVAL, hibernate_arena_claim(&first));
	ATF_CHECK_EQ(EINVAL, hibernate_arena_reserve(0x1000, 0));
	ATF_REQUIRE_EQ(0, hibernate_arena_reserve(0x100000, 323584));
	ATF_CHECK_EQ(0, hibernate_arena_reserve(0x100000, 323584));
	ATF_CHECK_EQ(EBUSY, hibernate_arena_reserve(0x200000, 323584));
	ATF_REQUIRE_EQ(0, hibernate_arena_claim(&first));
	ATF_CHECK_EQ(0, hibernate_arena_claim(&first));
	ATF_CHECK_EQ(EBUSY, hibernate_arena_claim(&second));
	hibernate_arena_release(&second);
	ATF_CHECK_EQ(UINT64_C(0x100000), first.ha_arena_start);
	hibernate_arena_release(&first);
	ATF_CHECK_EQ(0, first.ha_arena_start);
	ATF_CHECK_EQ(0, first.ha_arena_size);
	hibernate_arena_release(&first);
	ATF_REQUIRE_EQ(0, hibernate_arena_claim(&second));
	hibernate_arena_release(&second);
}

static uint64_t
pair_bytes(const vm_paddr_t *pairs, size_t count)
{
	uint64_t total;
	size_t i;

	if (count % 2 != 0)
		return (UINT64_MAX);
	total = 0;
	for (i = 0; i < count; i += 2) {
		if (pairs[i] >= pairs[i + 1] ||
		    __builtin_add_overflow(total, pairs[i + 1] - pairs[i],
			&total))
			return (UINT64_MAX);
	}
	return (total);
}

static bool
pairs_overlap(const vm_paddr_t *pairs, size_t count, vm_paddr_t start,
    vm_paddr_t end)
{
	size_t i;

	for (i = 0; i < count; i += 2) {
		if (pairs[i] < end && start < pairs[i + 1])
			return (true);
	}
	return (false);
}

ATF_TC_WITHOUT_HEAD(normalize_matrix);
ATF_TC_BODY(normalize_matrix, tc)
{
	const struct hibernate_arena_interval ordered[] = {
		{ 0x1000, 0x3000, HAIC_ELIGIBLE },
		{ 0x3000, 0x5000, HAIC_ELIGIBLE },
		{ 0x7000, 0x9000, HAIC_INELIGIBLE_FIRMWARE },
	};
	const struct hibernate_arena_interval reordered[] = {
		{ 0x7000, 0x9000, HAIC_INELIGIBLE_FIRMWARE },
		{ 0x3000, 0x5000, HAIC_ELIGIBLE },
		{ 0x1000, 0x3000, HAIC_ELIGIBLE },
	};
	struct hibernate_arena_interval a[8], b[8], malformed[1];
	size_t ac, bc;

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_normalize(ordered, nitems(ordered), a, nitems(a),
		&ac));
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_normalize(reordered, nitems(reordered), b,
		nitems(b), &bc));
	ATF_REQUIRE_EQ(ac, bc);
	for (size_t i = 0; i < ac; i++) {
		ATF_CHECK_EQ(a[i].hai_start, b[i].hai_start);
		ATF_CHECK_EQ(a[i].hai_end, b[i].hai_end);
		ATF_CHECK_EQ(a[i].hai_class, b[i].hai_class);
	}
	ATF_REQUIRE_EQ(2, ac);
	ATF_CHECK_EQ(UINT64_C(0x1000), a[0].hai_start);
	ATF_CHECK_EQ(UINT64_C(0x5000), a[0].hai_end);

	malformed[0] = (struct hibernate_arena_interval) { 0x1000, 0x1000,
		HAIC_ELIGIBLE };
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_normalize(malformed, 1, a, nitems(a), &ac));
	malformed[0] = (struct hibernate_arena_interval) { 0x1000, 0x2000,
		(enum hibernate_arena_interval_class)(
		    HAIC_INELIGIBLE_LIVE + 1) };
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_normalize(malformed, 1, a, nitems(a), &ac));
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_arena_normalize(ordered, nitems(ordered), a, 1, &ac));
}

ATF_TC_WITHOUT_HEAD(live_range_matrix);
ATF_TC_BODY(live_range_matrix, tc)
{
	struct hibernate_arena_interval intervals[8];
	size_t count;

	intervals[0] = (struct hibernate_arena_interval) { 0x1000, 0x9000,
		HAIC_ELIGIBLE };
	count = 1;
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_exclude_live(intervals, &count, nitems(intervals),
		0x1000, 0x3000));
	ATF_REQUIRE_EQ(1, count);
	ATF_CHECK_EQ(UINT64_C(0x3000), intervals[0].hai_start);

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_exclude_live(intervals, &count, nitems(intervals),
		0x7000, 0x9000));
	ATF_REQUIRE_EQ(1, count);
	ATF_CHECK_EQ(UINT64_C(0x7000), intervals[0].hai_end);

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_exclude_live(intervals, &count, nitems(intervals),
		0x4000, 0x5000));
	ATF_REQUIRE_EQ(2, count);
	ATF_CHECK_EQ(UINT64_C(0x4000), intervals[0].hai_end);
	ATF_CHECK_EQ(UINT64_C(0x5000), intervals[1].hai_start);
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_exclude_live(intervals, &count, nitems(intervals),
		UINT64_MAX - 1, 0));
}

ATF_TC_WITHOUT_HEAD(selection_boundaries);
ATF_TC_BODY(selection_boundaries, tc)
{
	/*
	 * Rule version 3's required bytes (hibernate.h, PT_LEAF_PAGES=4096
	 * plus the K-23 arena park-stack component).
	 */
	const uint64_t required = UINT64_C(17539072);
	struct hibernate_arena_interval interval;
	vm_paddr_t pa;
	vm_size_t size;

	interval = (struct hibernate_arena_interval) { 0x100000,
		0x100000 + required, HAIC_ELIGIBLE };
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_select(&interval, 1,
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa, &size));
	ATF_CHECK_EQ(UINT64_C(0x100000), pa);
	ATF_CHECK_EQ(required, size);

	interval.hai_end--;
	ATF_CHECK_EQ(ENOMEM,
	    hibernate_arena_select(&interval, 1,
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa, &size));

	interval = (struct hibernate_arena_interval) {
		HIBERNATE_ARENA_PHYS_LIMIT - required,
		HIBERNATE_ARENA_PHYS_LIMIT, HAIC_ELIGIBLE
	};
	ATF_CHECK_EQ(0,
	    hibernate_arena_select(&interval, 1,
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa, &size));
	interval.hai_end++;
	ATF_CHECK_EQ(ENOMEM,
	    hibernate_arena_select(&interval, 1,
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa, &size));

	interval = (struct hibernate_arena_interval) { 0x100000,
		0x100000 + required, HAIC_ELIGIBLE };
	ATF_CHECK_EQ(0,
	    hibernate_arena_select(&interval, 1, required, &pa, &size));
	ATF_CHECK_EQ(0,
	    hibernate_arena_select(&interval, 1,
		required + HIBERNATE_ARENA_ALIGNMENT, &pa, &size));
	ATF_CHECK_EQ(ENOMEM,
	    hibernate_arena_select(&interval, 1,
		required - HIBERNATE_ARENA_ALIGNMENT, &pa, &size));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_select(&interval, 1, 0, &pa, &size));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_select(&interval, 1, required + 1, &pa, &size));
}

ATF_TC_WITHOUT_HEAD(selection_reorder_equivalence);
ATF_TC_BODY(selection_reorder_equivalence, tc)
{
	/*
	 * Intervals sized well above the rule-version-3 required bytes
	 * (17,539,072; see hibernate.h's HIBERNATE_ARENA_PT_LEAF_PAGES
	 * rationale), unlike rule version 1's much smaller requirement.
	 */
	const struct hibernate_arena_interval a[] = {
		{ 0x1000000, 0x3000000, HAIC_ELIGIBLE },
		{ 0x8000000, 0xa000000, HAIC_ELIGIBLE },
	};
	const struct hibernate_arena_interval b[] = {
		{ 0x8000000, 0xa000000, HAIC_ELIGIBLE },
		{ 0x1000000, 0x3000000, HAIC_ELIGIBLE },
	};
	vm_paddr_t pa_a, pa_b;
	vm_size_t size_a, size_b;

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_select(a, nitems(a),
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa_a, &size_a));
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_select(b, nitems(b),
		HIBERNATE_ARENA_POLICY_DEFAULT_BYTES * 8, &pa_b, &size_b));
	ATF_CHECK_EQ(pa_a, pa_b);
	ATF_CHECK_EQ(size_a, size_b);
}

ATF_TC_WITHOUT_HEAD(both_map_accounting);
ATF_TC_BODY(both_map_accounting, tc)
{
	const vm_paddr_t phys[] = { 0x100000, 0x500000, 0x800000, 0xc00000 };
	const vm_paddr_t dump[] = { 0x100000, 0x300000, 0x400000, 0xc00000 };
	const vm_paddr_t arena_start = 0x480000;
	const vm_paddr_t arena_end = 0x4c0000;
	vm_paddr_t phys_out[8], dump_out[8];
	size_t phys_count, dump_count;
	uint64_t arena_size;

	arena_size = arena_end - arena_start;
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_split_pairs(phys, nitems(phys), arena_start,
		arena_end, phys_out, nitems(phys_out), &phys_count));
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_split_pairs(dump, nitems(dump), arena_start,
		arena_end, dump_out, nitems(dump_out), &dump_count));
	ATF_CHECK_EQ(arena_size,
	    pair_bytes(phys, nitems(phys)) - pair_bytes(phys_out, phys_count));
	ATF_CHECK_EQ(arena_size,
	    pair_bytes(dump, nitems(dump)) - pair_bytes(dump_out, dump_count));
	ATF_CHECK(!pairs_overlap(phys_out, phys_count, arena_start, arena_end));
	ATF_CHECK(!pairs_overlap(dump_out, dump_count, arena_start, arena_end));
	/* Post-split dump pairs are the PT_LOAD source seam. */
	ATF_CHECK_EQ(phys[nitems(phys) - 1],
	    phys_out[phys_count - 1]); /* Maxmem invariant. */
	ATF_CHECK_EQ(pair_bytes(phys, nitems(phys)),
	    pair_bytes(phys_out, phys_count) + arena_size);
}

ATF_TC_WITHOUT_HEAD(complete_removal_refusal);
ATF_TC_BODY(complete_removal_refusal, tc)
{
	const vm_paddr_t map[] = { 0x1000, 0x9000 };
	vm_paddr_t output[4];
	size_t count;

	ATF_REQUIRE_EQ(0,
	    hibernate_arena_split_pairs(map, nitems(map), 0x1000, 0x9000,
		output, nitems(output), &count));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_arena_split_pairs(map, nitems(map), 0x3000, 0x5000,
		output, 2, &count));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_split_pairs(map, 1, 0x3000, 0x5000, output,
		nitems(output), &count));
}

ATF_TC_WITHOUT_HEAD(ownership_boundaries);
ATF_TC_BODY(ownership_boundaries, tc)
{
	struct hibernate_attempt owner = HIBERNATE_ATTEMPT_INIT;
	struct hibernate_attempt malformed = HIBERNATE_ATTEMPT_INIT;

	hibernate_arena_reset();
	ATF_CHECK_EQ(EINVAL, hibernate_arena_reserve(0, 0));
	ATF_CHECK_EQ(EINVAL, hibernate_arena_reserve(0x1001, 0x1000));
	ATF_CHECK_EQ(EINVAL, hibernate_arena_reserve(0x1000, 0x1001));
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_arena_reserve(UINT64_MAX - UINT64_C(0xfff), 0x2000));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_reserve(HIBERNATE_ARENA_PHYS_LIMIT, 0x1000));
	ATF_CHECK_EQ(EINVAL, hibernate_arena_claim(NULL));
	hibernate_arena_release(NULL);
	hibernate_arena_release(&owner);

	ATF_REQUIRE_EQ(0, hibernate_arena_reserve(0x100000, 323584));
	malformed.ha_arena_start = 0x100000;
	ATF_CHECK_EQ(EINVAL, hibernate_arena_claim(&malformed));
	ATF_REQUIRE_EQ(0, hibernate_arena_claim(&owner));
	hibernate_arena_release(&owner);
	hibernate_arena_release(&owner);
	ATF_REQUIRE_EQ(0, hibernate_arena_claim(&owner));
	hibernate_arena_release(&owner);
}

/*
 * OVMF's QEMU q35 EFI map can exceed 128 descriptors.  Exercise the shared
 * normalisation storage beyond that former limit without placing the fixture
 * arrays on the test stack.
 */
#define MANY_INTERVAL_COUNT 129
static struct hibernate_arena_interval many_interval_input[MANY_INTERVAL_COUNT];
static struct hibernate_arena_interval
    many_interval_output[MANY_INTERVAL_COUNT];

ATF_TC_WITHOUT_HEAD(normalize_more_than_128_intervals);
ATF_TC_BODY(normalize_more_than_128_intervals, tc)
{
	size_t count, i;

	for (i = 0; i < nitems(many_interval_input); i++) {
		many_interval_input[i].hai_start = UINT64_C(0x1000) +
		    i * UINT64_C(0x2000);
		many_interval_input[i].hai_end =
		    many_interval_input[i].hai_start + UINT64_C(0x1000);
		many_interval_input[i].hai_class = HAIC_ELIGIBLE;
	}
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_normalize(many_interval_input,
		nitems(many_interval_input), many_interval_output,
		nitems(many_interval_output), &count));
	ATF_REQUIRE_EQ(nitems(many_interval_input), count);
	for (i = 0; i < count; i++) {
		ATF_CHECK_EQ(many_interval_input[i].hai_start,
		    many_interval_output[i].hai_start);
		ATF_CHECK_EQ(many_interval_input[i].hai_end,
		    many_interval_output[i].hai_end);
		ATF_CHECK_EQ(many_interval_input[i].hai_class,
		    many_interval_output[i].hai_class);
	}
}
#undef MANY_INTERVAL_COUNT

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, required_golden);
	ATF_TP_ADD_TC(tp, normalize_precedence);
	ATF_TP_ADD_TC(tp, live_exclusion);
	ATF_TP_ADD_TC(tp, selection_highest);
	ATF_TP_ADD_TC(tp, split_five_cases);
	ATF_TP_ADD_TC(tp, ownership);
	ATF_TP_ADD_TC(tp, normalize_matrix);
	ATF_TP_ADD_TC(tp, live_range_matrix);
	ATF_TP_ADD_TC(tp, selection_boundaries);
	ATF_TP_ADD_TC(tp, selection_reorder_equivalence);
	ATF_TP_ADD_TC(tp, both_map_accounting);
	ATF_TP_ADD_TC(tp, complete_removal_refusal);
	ATF_TP_ADD_TC(tp, ownership_boundaries);
	ATF_TP_ADD_TC(tp, normalize_more_than_128_intervals);
	return (atf_no_error());
}
