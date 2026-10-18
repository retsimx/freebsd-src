/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Reduced fixture for the K-5 vm_phys hibernate reservation model.
 *
 * Scope: bounded-termination / no-recapture (arena exclusion, boundary
 * exactness) and reserve_count/reserve_all ENOSPC/ENOMEM rollback
 * equivalence.  Exhaustive topology (domains × freelists × pools × orders)
 * and happy-path traversal coverage are superseded by K-22 (issue #29),
 * which tests the production vm_phys traversal path directly.
 *
 * Monotonic-cursor discipline:
 *   Re-enqueued excluded pages go to TAIL; the outer loop drains from a
 *   snapshot count taken at entry, so excluded pages cannot be recaptured
 *   during the same call.  This matches the production guarantee in
 *   hib_process_block_all() / vm_phys_enq_range().
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Fixture dimensions                                                   */
/* ------------------------------------------------------------------ */

#define	FX_NDOMAINS	2
#define	FX_NFREELIST	1
#define	FX_NFREEPOOL	3
#define	FX_NFREEORDER	4
#define	FX_ORDER_NONE	FX_NFREEORDER
#define	FX_MAX_PAGES	64
#define	FX_PA_BASE	((uint64_t)0x100000)
#define	FX_PAGE_SIZE	4096UL

/* ------------------------------------------------------------------ */
/* Model page                                                           */
/* ------------------------------------------------------------------ */

struct fx_page {
	uint64_t	 pa;
	int		 order;
	int		 domain;
	int		 pool;
	struct fx_page	*next;
};

/* ------------------------------------------------------------------ */
/* Simple singly-linked free queue (head-dequeue / tail-enqueue)       */
/* ------------------------------------------------------------------ */

struct fx_queue {
	struct fx_page	*head;
	struct fx_page	*tail;
	int		 lcnt;
};

static void
fxq_init(struct fx_queue *q)
{
	q->head = NULL;
	q->tail = NULL;
	q->lcnt = 0;
}

static struct fx_page *
fxq_dequeue(struct fx_queue *q)
{
	struct fx_page *m = q->head;

	if (m != NULL) {
		q->head = m->next;
		if (q->head == NULL)
			q->tail = NULL;
		m->next = NULL;
		q->lcnt--;
	}
	return (m);
}

static void
fxq_enqueue_tail(struct fx_queue *q, struct fx_page *m)
{
	m->next = NULL;
	if (q->tail != NULL)
		q->tail->next = m;
	else
		q->head = m;
	q->tail = m;
	q->lcnt++;
}

/* ------------------------------------------------------------------ */
/* Global fixture state                                                 */
/* ------------------------------------------------------------------ */

static struct fx_page  fx_pages[FX_MAX_PAGES];
static int             fx_npages;
static int             fx_ndomains;
/* queues[domain][freelist][pool][order] */
static struct fx_queue fx_queues[FX_NDOMAINS][FX_NFREELIST][FX_NFREEPOOL]
    [FX_NFREEORDER];

/* Arena: [fx_arena_pa, fx_arena_pa + fx_arena_size). */
static uint64_t fx_arena_pa;
static uint64_t fx_arena_size;

/*
 * Destination set: a small list of [start, end) PA ranges, mirroring
 * hib_page_is_destination()'s interval-membership test.  Empty by
 * default (fx_dst_count == 0), so callers that never populate it see
 * unchanged pre-existing behaviour.
 */
#define	FX_DST_MAX	16
static uint64_t fx_dst_start[FX_DST_MAX];
static uint64_t fx_dst_end[FX_DST_MAX];
static int      fx_dst_count;

static void
fx_dst_reset(void)
{
	fx_dst_count = 0;
}

static void
fx_dst_add(uint64_t start, uint64_t end)
{
	if (fx_dst_count < FX_DST_MAX) {
		fx_dst_start[fx_dst_count] = start;
		fx_dst_end[fx_dst_count] = end;
		fx_dst_count++;
	}
}

static bool
fx_in_destination(uint64_t pa)
{
	int i;

	for (i = 0; i < fx_dst_count; i++) {
		if (pa >= fx_dst_start[i] && pa < fx_dst_end[i])
			return (true);
	}
	return (false);
}

/* ------------------------------------------------------------------ */
/* Reservation record                                                   */
/* ------------------------------------------------------------------ */

#define	FX_RES_MAX	FX_MAX_PAGES

struct fx_res_entry {
	int	page_idx;
	int	pool;
	int	domain;
};

struct fx_res {
	struct fx_res_entry	entries[FX_RES_MAX];
	int			count;
	int			capacity;
};

/* ------------------------------------------------------------------ */
/* Fixture initialisation                                               */
/* ------------------------------------------------------------------ */

static void
fx_reset(void)
{
	int d, f, p, o;

	memset(fx_pages, 0, sizeof(fx_pages));
	fx_npages  = 0;
	fx_ndomains = 2;
	for (d = 0; d < FX_NDOMAINS; d++)
		for (f = 0; f < FX_NFREELIST; f++)
			for (p = 0; p < FX_NFREEPOOL; p++)
				for (o = 0; o < FX_NFREEORDER; o++)
					fxq_init(&fx_queues[d][f][p][o]);
	fx_arena_pa   = 0;
	fx_arena_size = 0;
	fx_dst_reset();
}

static int
fx_alloc_page(int idx, uint64_t pa, int domain, int pool, int order,
    bool enqueue_head)
{
	struct fx_page *m;

	if (idx >= FX_MAX_PAGES)
		return (-1);
	m = &fx_pages[idx];
	m->pa     = pa;
	m->order  = order;
	m->domain = domain;
	m->pool   = pool;
	m->next   = NULL;
	if (enqueue_head)
		fxq_enqueue_tail(&fx_queues[domain][0][pool][order], m);
	if (idx >= fx_npages)
		fx_npages = idx + 1;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Classification predicate                                             */
/* ------------------------------------------------------------------ */

static bool
fx_in_arena(uint64_t pa)
{
	return (fx_arena_size > 0 &&
	    pa >= fx_arena_pa && pa < fx_arena_pa + fx_arena_size);
}

/* ------------------------------------------------------------------ */
/* Reservation helpers                                                  */
/* ------------------------------------------------------------------ */

static int
fx_append(struct fx_res *res, struct fx_page *m, int pool, int domain)
{
	if (res->count >= res->capacity)
		return (ENOSPC);
	res->entries[res->count].page_idx = (int)(m - fx_pages);
	res->entries[res->count].pool     = pool;
	res->entries[res->count].domain   = domain;
	res->count++;
	return (0);
}

static void
fx_rollback(struct fx_res *res)
{
	int i;

	for (i = res->count - 1; i >= 0; i--) {
		struct fx_page *m = &fx_pages[res->entries[i].page_idx];
		int p = res->entries[i].pool;
		int d = res->entries[i].domain;

		m->order = 0;
		fxq_enqueue_tail(&fx_queues[d][0][p][0], m);
	}
	res->count = 0;
}

/* ------------------------------------------------------------------ */
/* Block-classification helper                                          */
/*                                                                      */
/* The block [m_block, m_block + block_pages) has been removed from    */
/* its queue.  Excluded pages are re-enqueued at TAIL (order 0).       */
/* Monotonic cursor: re-enqueued pages go to TAIL and are NOT visited  */
/* again because the outer loop works from a pre-entry snapshot count. */
/* ------------------------------------------------------------------ */

static int
fx_process_block_all(struct fx_res *res, struct fx_page *m_block,
    int block_pages, int domain, int pool)
{
	struct fx_page *excl_head = NULL;
	int excl_count = 0;
	int k, error;

	for (k = 0; k < block_pages; k++) {
		struct fx_page *m = m_block + k;

		if (fx_in_arena(m->pa)) {
			if (excl_head == NULL)
				excl_head = m;
			excl_count++;
		} else {
			if (excl_head != NULL) {
				int j;

				for (j = 0; j < excl_count; j++) {
					struct fx_page *em = excl_head + j;

					em->order = 0;
					fxq_enqueue_tail(
					    &fx_queues[domain][0][pool][0],
					    em);
				}
				excl_head = NULL;
				excl_count = 0;
			}
			error = fx_append(res, m, pool, domain);
			if (error != 0) {
				for (; k < block_pages; k++) {
					struct fx_page *rm = m_block + k;

					rm->order = 0;
					fxq_enqueue_tail(
					    &fx_queues[domain][0][pool][0],
					    rm);
				}
				return (error);
			}
		}
	}
	if (excl_head != NULL) {
		int j;

		for (j = 0; j < excl_count; j++) {
			struct fx_page *em = excl_head + j;

			em->order = 0;
			fxq_enqueue_tail(&fx_queues[domain][0][pool][0], em);
		}
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* Top-level reserve_all                                                */
/*                                                                      */
/* Snapshot count at entry; re-enqueued excluded pages (TAIL) are not  */
/* revisited, matching the production no-recapture guarantee.           */
/* ------------------------------------------------------------------ */

static int
fx_reserve_all(struct fx_res *res)
{
	int dom, fl, pool, ord, error;

	if (res == NULL || res->count != 0)
		return (EINVAL);

	for (dom = 0; dom < fx_ndomains; dom++) {
		for (fl = 0; fl < FX_NFREELIST; fl++) {
			for (pool = 0; pool < FX_NFREEPOOL; pool++) {
				for (ord = 0; ord < FX_NFREEORDER; ord++) {
					struct fx_queue *q =
					    &fx_queues[dom][fl][pool][ord];
					int snap = q->lcnt;
					int i;

					for (i = 0; i < snap; i++) {
						struct fx_page *m_block =
						    fxq_dequeue(q);

						if (m_block == NULL)
							break;
						m_block->order = FX_ORDER_NONE;
						error = fx_process_block_all(
						    res, m_block, 1 << ord,
						    dom, pool);
						if (error != 0) {
							fx_rollback(res);
							return (error);
						}
					}
				}
			}
		}
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* Top-level reserve_count                                              */
/* ------------------------------------------------------------------ */

static int
fx_reserve_count(struct fx_res *res, int want)
{
	int dom, fl, pool, ord;

	if (res == NULL || res->count != 0 || want < 0)
		return (EINVAL);

	for (dom = 0; dom < fx_ndomains && res->count < want; dom++) {
		for (fl = 0; fl < FX_NFREELIST && res->count < want; fl++) {
			for (pool = 0; pool < FX_NFREEPOOL &&
			    res->count < want; pool++) {
				for (ord = 0; ord < FX_NFREEORDER &&
				    res->count < want; ord++) {
					struct fx_queue *q =
					    &fx_queues[dom][fl][pool][ord];
					int snap = q->lcnt;
					int i;

					for (i = 0; i < snap &&
					    res->count < want; i++) {
						struct fx_page *m_block =
						    fxq_dequeue(q);

						if (m_block == NULL)
							break;
						m_block->order = FX_ORDER_NONE;
						/*
						 * Destination-colliding pages
						 * are ineligible; re-enqueue
						 * at TAIL (order 0), matching
						 * hib_process_block_count()'s
						 * return-run behaviour.  Not
						 * revisited this call: i < snap
						 * is a pre-entry snapshot
						 * (monotonic-cursor
						 * discipline).
						 */
						if (fx_in_destination(
						    m_block->pa)) {
							m_block->order = 0;
							fxq_enqueue_tail(
							    &fx_queues[dom][0]
							    [pool][0],
							    m_block);
							continue;
						}
						if (fx_append(res, m_block,
						    pool, dom) != 0) {
							fx_rollback(res);
							return (ENOSPC);
						}
					}
				}
			}
		}
	}

	if (res->count < want) {
		fx_rollback(res);
		return (ENOMEM);
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* Snapshot helpers                                                     */
/* ------------------------------------------------------------------ */

static int
fx_total_queued(void)
{
	int d, f, p, o, total = 0;

	for (d = 0; d < FX_NDOMAINS; d++)
		for (f = 0; f < FX_NFREELIST; f++)
			for (p = 0; p < FX_NFREEPOOL; p++)
				for (o = 0; o < FX_NFREEORDER; o++)
					total += fx_queues[d][f][p][o].lcnt;
	return (total);
}

static int
fx_collect_free_set(int out[], int maxn)
{
	int d, f, p, o, n = 0;

	for (d = 0; d < FX_NDOMAINS; d++) {
		for (f = 0; f < FX_NFREELIST; f++) {
			for (p = 0; p < FX_NFREEPOOL; p++) {
				for (o = 0; o < FX_NFREEORDER; o++) {
					struct fx_page *m =
					    fx_queues[d][f][p][o].head;

					while (m != NULL) {
						if (n < maxn)
							out[n++] =
							    (int)(m - fx_pages);
						m = m->next;
					}
				}
			}
		}
	}
	return (n);
}

static void
fx_sort(int arr[], int n)
{
	int i, j, t;

	for (i = 0; i < n - 1; i++) {
		for (j = i + 1; j < n; j++) {
			if (arr[j] < arr[i]) {
				t = arr[i];
				arr[i] = arr[j];
				arr[j] = t;
			}
		}
	}
}

/* ------------------------------------------------------------------ */
/* ATF test cases                                                       */
/* ------------------------------------------------------------------ */

/*
 * arena_exclusion: arena pages are not captured; they are re-enqueued
 * at TAIL and not revisited (no-recapture / monotonic-cursor property).
 */
ATF_TC_WITHOUT_HEAD(arena_exclusion);
ATF_TC_BODY(arena_exclusion, tc)
{
	struct fx_res res;

	fx_reset();
	fx_arena_pa   = FX_PA_BASE;
	fx_arena_size = FX_PAGE_SIZE;
	/* Page 0: in arena (excluded). */
	fx_alloc_page(0, FX_PA_BASE, 0, 0, 0, true);
	/* Page 1: outside arena (eligible). */
	fx_alloc_page(1, FX_PA_BASE + FX_PAGE_SIZE, 0, 0, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	/* Only page 1 captured; page 0 re-enqueued at tail. */
	ATF_CHECK_EQ(1, res.count);
	ATF_CHECK_EQ(1, res.entries[0].page_idx);
	ATF_CHECK_EQ(1, fx_total_queued());
}

/*
 * arena_boundary_pfns: the first and last page of the arena are
 * excluded; the pages immediately before and after are eligible.
 */
ATF_TC_WITHOUT_HEAD(arena_boundary_pfns);
ATF_TC_BODY(arena_boundary_pfns, tc)
{
	struct fx_res res;

	fx_reset();
	/* Arena = [PA_BASE, PA_BASE + 3*PAGE). */
	fx_arena_pa   = FX_PA_BASE;
	fx_arena_size = 3 * FX_PAGE_SIZE;

	/* Just before arena: eligible. */
	fx_alloc_page(0, FX_PA_BASE - FX_PAGE_SIZE, 0, 0, 0, true);
	/* First page of arena: excluded. */
	fx_alloc_page(1, FX_PA_BASE, 0, 0, 0, true);
	/* Last page of arena: excluded. */
	fx_alloc_page(2, FX_PA_BASE + 2 * FX_PAGE_SIZE, 0, 0, 0, true);
	/* First page after arena: eligible. */
	fx_alloc_page(3, FX_PA_BASE + 3 * FX_PAGE_SIZE, 0, 0, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(2, res.count);
	ATF_CHECK_EQ(2, fx_total_queued());
}

/*
 * enospc_reserve_all: reserve_all with capacity < eligible pages →
 * ENOSPC; rollback restores the exact pre-call free-page set.
 */
ATF_TC_WITHOUT_HEAD(enospc_reserve_all);
ATF_TC_BODY(enospc_reserve_all, tc)
{
	struct fx_res res;
	int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
	int nb, na, i;

	fx_reset();
	for (i = 0; i < 5; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);

	nb = fx_collect_free_set(before, FX_MAX_PAGES);
	fx_sort(before, nb);

	memset(&res, 0, sizeof(res));
	res.capacity = 3;	/* capacity < 5 eligible pages */

	ATF_CHECK_EQ(ENOSPC, fx_reserve_all(&res));
	ATF_CHECK_EQ(0, res.count);

	na = fx_collect_free_set(after, FX_MAX_PAGES);
	ATF_CHECK_EQ(nb, na);
	fx_sort(after, na);
	ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
}

/*
 * shortage_reserve: reserve_count with want > available pages →
 * ENOMEM; rollback leaves count==0 and restores the free-page set.
 */
ATF_TC_WITHOUT_HEAD(shortage_reserve);
ATF_TC_BODY(shortage_reserve, tc)
{
	struct fx_res res;
	int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
	int nb, na, i;

	fx_reset();
	for (i = 0; i < 3; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);

	nb = fx_collect_free_set(before, FX_MAX_PAGES);
	fx_sort(before, nb);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(ENOMEM, fx_reserve_count(&res, 5));
	ATF_CHECK_EQ(0, res.count);

	na = fx_collect_free_set(after, FX_MAX_PAGES);
	ATF_CHECK_EQ(nb, na);
	fx_sort(after, na);
	ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
}

/*
 * fault_after_nth_append: for N in 1..5, capacity=N-1 triggers ENOSPC
 * at the Nth append; rollback always restores the original free set.
 */
ATF_TC_WITHOUT_HEAD(fault_after_nth_append);
ATF_TC_BODY(fault_after_nth_append, tc)
{
	int n;

	for (n = 1; n <= 5; n++) {
		struct fx_res res;
		int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
		int nb, na, i;

		fx_reset();
		for (i = 0; i < 5; i++)
			fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
			    0, 0, 0, true);

		nb = fx_collect_free_set(before, FX_MAX_PAGES);
		fx_sort(before, nb);

		memset(&res, 0, sizeof(res));
		res.capacity = n - 1;

		ATF_CHECK_EQ(ENOSPC, fx_reserve_all(&res));
		ATF_CHECK_EQ(0, res.count);

		na = fx_collect_free_set(after, FX_MAX_PAGES);
		ATF_CHECK_EQ(nb, na);
		fx_sort(after, na);
		ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
	}
}

/*
 * shortage_reserve_count_zero_eligible: reserve_count(want=N>0) against
 * zero eligible pages -> ENOMEM, count==0, free set unchanged (design
 * 035 SS6.3 "Shortage at 0").
 */
ATF_TC_WITHOUT_HEAD(shortage_reserve_count_zero_eligible);
ATF_TC_BODY(shortage_reserve_count_zero_eligible, tc)
{
	struct fx_res res;

	fx_reset();	/* no pages allocated at all */

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(ENOMEM, fx_reserve_count(&res, 3));
	ATF_CHECK_EQ(0, res.count);
	ATF_CHECK_EQ(0, fx_total_queued());
}

/*
 * shortage_reserve_count_p_minus_one: a request for P pages with exactly
 * P - 1 eligible pages must roll back every partial acquisition.
 */
ATF_TC_WITHOUT_HEAD(shortage_reserve_count_p_minus_one);
ATF_TC_BODY(shortage_reserve_count_p_minus_one, tc)
{
	struct fx_res res;
	int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
	int nb, na, i;

	fx_reset();
	for (i = 0; i < 3; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);

	nb = fx_collect_free_set(before, FX_MAX_PAGES);
	fx_sort(before, nb);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(ENOMEM, fx_reserve_count(&res, 4));
	ATF_CHECK_EQ(0, res.count);

	na = fx_collect_free_set(after, FX_MAX_PAGES);
	ATF_CHECK_EQ(nb, na);
	fx_sort(after, na);
	ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
}

/*
 * exact_count_reserve_count: reserve_count(want=P) against exactly P
 * eligible pages succeeds with count==P (design 035 SS6.3 "Exactly P").
 */
ATF_TC_WITHOUT_HEAD(exact_count_reserve_count);
ATF_TC_BODY(exact_count_reserve_count, tc)
{
	struct fx_res res;
	int i;

	fx_reset();
	for (i = 0; i < 4; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_count(&res, 4));
	ATF_CHECK_EQ(4, res.count);
	ATF_CHECK_EQ(0, fx_total_queued());
}

/*
 * multi_domain_ascending_order: eligible pages split across domain 0
 * and domain 1; reserve_count(want) drains domain 0 before domain 1
 * ever contributes, matching the mandated ascending-domain order
 * (design 035 SS6.3 "Multi-domain / pools / orders").
 */
ATF_TC_WITHOUT_HEAD(multi_domain_ascending_order);
ATF_TC_BODY(multi_domain_ascending_order, tc)
{
	struct fx_res res;

	fx_reset();
	/* Domain 0: 2 pages.  Domain 1: 2 pages. */
	fx_alloc_page(0, FX_PA_BASE + 0 * FX_PAGE_SIZE, 0, 0, 0, true);
	fx_alloc_page(1, FX_PA_BASE + 1 * FX_PAGE_SIZE, 0, 0, 0, true);
	fx_alloc_page(2, FX_PA_BASE + 2 * FX_PAGE_SIZE, 1, 1, 0, true);
	fx_alloc_page(3, FX_PA_BASE + 3 * FX_PAGE_SIZE, 1, 1, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	/* want=3: both domain-0 pages plus exactly one from domain 1. */
	ATF_CHECK_EQ(0, fx_reserve_count(&res, 3));
	ATF_CHECK_EQ(3, res.count);
	ATF_CHECK_EQ(0, res.entries[0].domain);
	ATF_CHECK_EQ(0, res.entries[1].domain);
	ATF_CHECK_EQ(1, res.entries[2].domain);
	/* One domain-1 page remains queued; domain 0 is fully drained. */
	ATF_CHECK_EQ(1, fx_total_queued());

	/* Rollback on shortage spans both domains in reverse order. */
	fx_reset();
	fx_alloc_page(0, FX_PA_BASE + 0 * FX_PAGE_SIZE, 0, 0, 0, true);
	fx_alloc_page(1, FX_PA_BASE + 1 * FX_PAGE_SIZE, 1, 0, 0, true);
	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;
	ATF_CHECK_EQ(ENOMEM, fx_reserve_count(&res, 5));
	ATF_CHECK_EQ(0, res.count);
	ATF_CHECK_EQ(2, fx_total_queued());
}

/*
 * reserve_count_destination_run_precedes_eligible: a long run of
 * destination-colliding pages precedes P eligible pages in queue order;
 * reserve_count(want=P) still succeeds because |E| >= P (no horizon),
 * and the accepted set is disjoint from D (design 035 SS6.3 "Long
 * destination-colliding run first").
 */
ATF_TC_WITHOUT_HEAD(reserve_count_destination_run_precedes_eligible);
ATF_TC_BODY(reserve_count_destination_run_precedes_eligible, tc)
{
	struct fx_res res;
	int i, idx;

	fx_reset();
	idx = 0;
	/* 10 destination-colliding pages, enqueued first. */
	for (i = 0; i < 10; i++, idx++)
		fx_alloc_page(idx, FX_PA_BASE + idx * FX_PAGE_SIZE,
		    0, 0, 0, true);
	fx_dst_add(FX_PA_BASE, FX_PA_BASE + 10 * FX_PAGE_SIZE);
	/* 4 eligible pages follow. */
	for (i = 0; i < 4; i++, idx++)
		fx_alloc_page(idx, FX_PA_BASE + idx * FX_PAGE_SIZE,
		    0, 0, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_count(&res, 4));
	ATF_CHECK_EQ(4, res.count);
	for (i = 0; i < res.count; i++) {
		struct fx_page *m = &fx_pages[res.entries[i].page_idx];

		ATF_CHECK(!fx_in_destination(m->pa));
	}
	/* All 10 destination pages remain queued (re-enqueued at tail). */
	ATF_CHECK_EQ(10, fx_total_queued());
}

/*
 * reserve_count_adversarial_destination_interleave: destination and
 * eligible pages interleaved at every order 0..3; the accepted set is
 * exactly the eligible pages, disjoint from D, and count==want (design
 * 035 SS6.3 "Adversarial overlap").
 */
ATF_TC_WITHOUT_HEAD(reserve_count_adversarial_destination_interleave);
ATF_TC_BODY(reserve_count_adversarial_destination_interleave, tc)
{
	struct fx_res res;
	int i;

	fx_reset();
	/*
	 * idx : pa offset : order : role
	 *  0  : 0          : 0     : destination
	 *  1  : 1          : 0     : eligible
	 *  2  : 2          : 1     : destination
	 *  3  : 3          : 1     : eligible
	 *  4  : 4          : 2     : destination
	 *  5  : 5          : 2     : eligible
	 *  6  : 6          : 3     : destination
	 *  7  : 7          : 3     : eligible
	 */
	fx_alloc_page(0, FX_PA_BASE + 0 * FX_PAGE_SIZE, 0, 0, 0, true);
	fx_alloc_page(1, FX_PA_BASE + 1 * FX_PAGE_SIZE, 0, 0, 0, true);
	fx_alloc_page(2, FX_PA_BASE + 2 * FX_PAGE_SIZE, 0, 0, 1, true);
	fx_alloc_page(3, FX_PA_BASE + 3 * FX_PAGE_SIZE, 0, 0, 1, true);
	fx_alloc_page(4, FX_PA_BASE + 4 * FX_PAGE_SIZE, 0, 0, 2, true);
	fx_alloc_page(5, FX_PA_BASE + 5 * FX_PAGE_SIZE, 0, 0, 2, true);
	fx_alloc_page(6, FX_PA_BASE + 6 * FX_PAGE_SIZE, 0, 0, 3, true);
	fx_alloc_page(7, FX_PA_BASE + 7 * FX_PAGE_SIZE, 0, 0, 3, true);

	fx_dst_add(FX_PA_BASE + 0 * FX_PAGE_SIZE,
	    FX_PA_BASE + 1 * FX_PAGE_SIZE);
	fx_dst_add(FX_PA_BASE + 2 * FX_PAGE_SIZE,
	    FX_PA_BASE + 3 * FX_PAGE_SIZE);
	fx_dst_add(FX_PA_BASE + 4 * FX_PAGE_SIZE,
	    FX_PA_BASE + 5 * FX_PAGE_SIZE);
	fx_dst_add(FX_PA_BASE + 6 * FX_PAGE_SIZE,
	    FX_PA_BASE + 7 * FX_PAGE_SIZE);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_count(&res, 4));
	ATF_CHECK_EQ(4, res.count);
	for (i = 0; i < res.count; i++) {
		struct fx_page *m = &fx_pages[res.entries[i].page_idx];

		ATF_CHECK(!fx_in_destination(m->pa));
	}
	/* The 4 destination pages remain queued (re-enqueued at tail). */
	ATF_CHECK_EQ(4, fx_total_queued());
}

/* ------------------------------------------------------------------ */
/* ATF_TP registration                                                  */
/* ------------------------------------------------------------------ */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, arena_exclusion);
	ATF_TP_ADD_TC(tp, arena_boundary_pfns);
	ATF_TP_ADD_TC(tp, enospc_reserve_all);
	ATF_TP_ADD_TC(tp, shortage_reserve);
	ATF_TP_ADD_TC(tp, fault_after_nth_append);
	ATF_TP_ADD_TC(tp, shortage_reserve_count_zero_eligible);
	ATF_TP_ADD_TC(tp, shortage_reserve_count_p_minus_one);
	ATF_TP_ADD_TC(tp, exact_count_reserve_count);
	ATF_TP_ADD_TC(tp, multi_domain_ascending_order);
	ATF_TP_ADD_TC(tp, reserve_count_destination_run_precedes_eligible);
	ATF_TP_ADD_TC(tp, reserve_count_adversarial_destination_interleave);
	return (atf_no_error());
}
