/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Deterministic fixture for the K-5 vm_phys hibernate reservation
 * traversal policy.
 *
 * This file is a host-runnable (userland, ATF) model of the
 * classification loop in hib_process_block_all() and
 * hib_process_block_count() from sys/vm/vm_phys.c.  It uses a
 * self-contained mini page array and TAILQ-based free queues that
 * mirror the real production dimensions:
 *
 *   domain × freelist × pool × order
 *   (amd64: 8 × 3 × 3 × 13; fixture uses 2 × 1 × 3 × 4)
 *
 * Monotonic-cursor discipline:
 *   The production comment states that re-enqueued excluded pages
 *   "cannot be recaptured during the same call."  This is because
 *   vm_phys_enq_range inserts at TAIL and the outer while loop drains
 *   from HEAD.  Once a block is removed from the HEAD, subsequent
 *   re-enqueues go to TAIL and the loop only terminates when the
 *   queue becomes empty.  In a real system the arena pages occupy a
 *   contiguous physical range; in the model we implement the same
 *   guarantee by draining a snapshot of queue entries captured before
 *   processing begins, so re-enqueued pages are not revisited.
 *
 * Test inventory (ATF test cases):
 *   zero_free_pages        — reserve_all on empty queues → 0, count=0
 *   one_free_page          — reserve_all with one page → 0, count=1
 *   many_free_pages        — reserve_all captures all eligible pages
 *   arena_exclusion        — arena pages are not captured, re-enqueued
 *   arena_boundary_pfns    — first and last arena page excluded exactly
 *   exact_capacity_reserve — reserve_count gets exact count → 0
 *   shortage_reserve       — reserve_count shortage → ENOMEM, count=0
 *   enospc_reserve_all     — reserve_all capacity < pages → ENOSPC, rollback
 *   rollback_set_identity  — after explicit rollback: same free PFN set
 *   rollback_count_identity— after ENOMEM: count==0, pages restored
 *   adversarial_dst_prefix — long excluded prefix before eligible pages
 *   multi_domain_order     — domains visited ascending (0 before 1)
 *   multi_pool_coverage    — pages from all pools captured
 *   multi_order_coverage   — order-0 and order-1 blocks processed
 *   fault_after_nth_append — capacity=N-1 for N in 1..5 → ENOSPC+rollback
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Fixture dimensions (subset of amd64 production values)               */
/* ------------------------------------------------------------------ */

#define	FX_NDOMAINS	2
#define	FX_NFREELIST	1	/* single freelist (DEFAULT) in fixture */
#define	FX_NFREEPOOL	3
#define	FX_NFREEORDER	4	/* orders 0..3; block sizes 1,2,4,8 */
#define	FX_ORDER_NONE	FX_NFREEORDER	/* page not on any queue */
#define	FX_MAX_PAGES	64
#define	FX_PA_BASE	((uint64_t)0x100000)
#define	FX_PAGE_SIZE	4096UL

/* ------------------------------------------------------------------ */
/* Model page (mirrors vm_page fields used by traversal)                */
/* ------------------------------------------------------------------ */

struct fx_page {
	uint64_t	 pa;
	int		 order;		/* current order, FX_ORDER_NONE if off-queue */
	int		 domain;
	int		 pool;
	/* singly-linked list for simple queues */
	struct fx_page	*next;
};

/* ------------------------------------------------------------------ */
/* Simple singly-linked free queue (head-insert / tail-append)          */
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

/* Destination intervals (sorted, non-overlapping [start, end) pairs). */
#define	FX_MAX_DST	8
static uint64_t fx_dst[FX_MAX_DST * 2];
static int      fx_ndst;

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
	fx_ndst       = 0;
}

/*
 * Allocate a model page and enqueue it.  The page array is indexed by
 * the caller; pages in a higher-order block must be allocated
 * contiguously (idx, idx+1, ..., idx+block_pages-1) and only the head
 * (idx) is enqueued; the rest are "in the block" and classified by
 * fx_process_block_all when the head is removed.
 */
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
/* Classification predicates                                            */
/* ------------------------------------------------------------------ */

static bool
fx_in_arena(uint64_t pa)
{
	return (fx_arena_size > 0 &&
	    pa >= fx_arena_pa && pa < fx_arena_pa + fx_arena_size);
}

static bool
fx_is_dst(uint64_t pa)
{
	int i;

	for (i = 0; i < fx_ndst; i++) {
		uint64_t s = fx_dst[i * 2], e = fx_dst[i * 2 + 1];

		if (pa >= s && pa < e)
			return (true);
		if (s > pa)
			break;
	}
	return (false);
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
/* Block-classification helpers                                         */
/*                                                                      */
/* The block [m_block, m_block + block_pages) has already been removed  */
/* from its queue.  Pages are classified in order; excluded pages are   */
/* re-enqueued at TAIL of fl[domain][0][pool][0] (order 0).            */
/*                                                                      */
/* Monotonic cursor: re-enqueued pages go to TAIL and are NOT visited   */
/* again in the same pass because the outer loop works from a snapshot  */
/* taken before processing.                                             */
/* ------------------------------------------------------------------ */

/*
 * fx_process_block_all: reserve_all classification.
 * Returns 0, ENOSPC (tail re-enqueued), or EOVERFLOW.
 */
static int
fx_process_block_all(struct fx_res *res, struct fx_page *m_block,
    int block_pages, int domain, int pool)
{
	/* Accumulate contiguous excluded run before re-enqueueing. */
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
			/* Flush excluded run before appending eligible. */
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
				/* Re-enqueue tail of block and return. */
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
	/* Trailing excluded run. */
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

/*
 * fx_process_block_count: reserve_count classification.
 * Returns 0 or EOVERFLOW; ENOMEM is detected by the caller.
 */
static int
fx_process_block_count(struct fx_res *res, struct fx_page *m_block,
    int block_pages, int domain, int pool, int want)
{
	struct fx_page *ret_head = NULL;
	int ret_count = 0;
	int k, error;

	for (k = 0; k < block_pages; k++) {
		struct fx_page *m = m_block + k;

		if (res->count == want ||
		    fx_in_arena(m->pa) ||
		    fx_is_dst(m->pa)) {
			if (ret_head == NULL)
				ret_head = m;
			ret_count++;
		} else {
			if (ret_head != NULL) {
				int j;

				for (j = 0; j < ret_count; j++) {
					struct fx_page *rm = ret_head + j;

					rm->order = 0;
					fxq_enqueue_tail(
					    &fx_queues[domain][0][pool][0],
					    rm);
				}
				ret_head = NULL;
				ret_count = 0;
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
	if (ret_head != NULL) {
		int j;

		for (j = 0; j < ret_count; j++) {
			struct fx_page *rm = ret_head + j;

			rm->order = 0;
			fxq_enqueue_tail(&fx_queues[domain][0][pool][0], rm);
		}
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* Top-level reserve_all                                                */
/*                                                                      */
/* Monotonic cursor: for each (domain, freelist, pool, order), we       */
/* snapshot the queue count at entry and process exactly that many      */
/* blocks.  Re-enqueued excluded pages (at TAIL) are not revisited in  */
/* the same (domain, pool, order) pass, matching the production         */
/* "cannot be recaptured" guarantee.                                    */
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
					/*
					 * Snapshot count: only process blocks
					 * present at entry, not re-enqueued
					 * excluded pages.
					 */
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
	int dom, fl, pool, ord, error;

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
						error =
						    fx_process_block_count(
						    res, m_block, 1 << ord,
						    dom, pool, want);
						if (error != 0) {
							fx_rollback(res);
							return (error);
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
/* ATF test cases                                                        */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(zero_free_pages);
ATF_TC_BODY(zero_free_pages, tc)
{
	struct fx_res res;

	fx_reset();
	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(0, res.count);
	ATF_CHECK_EQ(0, fx_total_queued());
}

ATF_TC_WITHOUT_HEAD(one_free_page);
ATF_TC_BODY(one_free_page, tc)
{
	struct fx_res res;
	int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
	int nb, na;

	fx_reset();
	fx_alloc_page(0, FX_PA_BASE, 0, 0, 0, true);

	nb = fx_collect_free_set(before, FX_MAX_PAGES);
	ATF_CHECK_EQ(1, nb);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(1, res.count);
	ATF_CHECK_EQ(0, fx_total_queued());
	ATF_CHECK_EQ(0, res.entries[0].page_idx);
	ATF_CHECK_EQ(0, res.entries[0].domain);
	ATF_CHECK_EQ(0, res.entries[0].pool);

	/* Rollback restores the free set. */
	fx_rollback(&res);
	ATF_CHECK_EQ(0, res.count);
	na = fx_collect_free_set(after, FX_MAX_PAGES);
	ATF_CHECK_EQ(nb, na);
	fx_sort(before, nb);
	fx_sort(after, na);
	ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
}

ATF_TC_WITHOUT_HEAD(many_free_pages);
ATF_TC_BODY(many_free_pages, tc)
{
	struct fx_res res;
	int i;

	fx_reset();
	for (i = 0; i < 4; i++) {
		fx_alloc_page(i,     FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, i % FX_NFREEPOOL, 0, true);
		fx_alloc_page(i + 4,
		    FX_PA_BASE + (i + 100) * FX_PAGE_SIZE,
		    1, i % FX_NFREEPOOL, 0, true);
	}

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(8, res.count);
	ATF_CHECK_EQ(0, fx_total_queued());
}

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
	/* Only page 1 captured; page 0 re-enqueued. */
	ATF_CHECK_EQ(1, res.count);
	ATF_CHECK_EQ(1, res.entries[0].page_idx);
	ATF_CHECK_EQ(1, fx_total_queued());
}

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

ATF_TC_WITHOUT_HEAD(exact_capacity_reserve);
ATF_TC_BODY(exact_capacity_reserve, tc)
{
	struct fx_res res;
	int i;

	fx_reset();
	for (i = 0; i < 5; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_count(&res, 5));
	ATF_CHECK_EQ(5, res.count);
}

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

ATF_TC_WITHOUT_HEAD(rollback_set_identity);
ATF_TC_BODY(rollback_set_identity, tc)
{
	struct fx_res res;
	int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
	int nb, na, i;

	fx_reset();
	for (i = 0; i < 10; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, i % FX_NFREEPOOL, 0, true);

	nb = fx_collect_free_set(before, FX_MAX_PAGES);
	fx_sort(before, nb);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(10, res.count);

	fx_rollback(&res);
	ATF_CHECK_EQ(0, res.count);

	na = fx_collect_free_set(after, FX_MAX_PAGES);
	ATF_CHECK_EQ(nb, na);
	fx_sort(after, na);
	ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
}

ATF_TC_WITHOUT_HEAD(rollback_count_identity);
ATF_TC_BODY(rollback_count_identity, tc)
{
	struct fx_res res;
	int before[FX_MAX_PAGES], after[FX_MAX_PAGES];
	int nb, na, i;

	fx_reset();
	for (i = 0; i < 6; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);

	nb = fx_collect_free_set(before, FX_MAX_PAGES);
	fx_sort(before, nb);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(ENOMEM, fx_reserve_count(&res, 10));
	ATF_CHECK_EQ(0, res.count);

	na = fx_collect_free_set(after, FX_MAX_PAGES);
	ATF_CHECK_EQ(nb, na);
	fx_sort(after, na);
	ATF_CHECK(memcmp(before, after, nb * sizeof(int)) == 0);
}

ATF_TC_WITHOUT_HEAD(adversarial_dst_prefix);
ATF_TC_BODY(adversarial_dst_prefix, tc)
{
	struct fx_res res;
	int i;

	fx_reset();
	/* Destination covers pages 0..7. */
	fx_dst[0] = FX_PA_BASE;
	fx_dst[1] = FX_PA_BASE + 8 * FX_PAGE_SIZE;
	fx_ndst = 1;

	for (i = 0; i < 8; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);
	/* Page 8: eligible. */
	fx_alloc_page(8, FX_PA_BASE + 8 * FX_PAGE_SIZE, 0, 0, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_count(&res, 1));
	ATF_CHECK_EQ(1, res.count);
	ATF_CHECK_EQ(8, res.entries[0].page_idx);
	/* Destination pages must still be queued. */
	ATF_CHECK_EQ(8, fx_total_queued());
}

ATF_TC_WITHOUT_HEAD(multi_domain_order);
ATF_TC_BODY(multi_domain_order, tc)
{
	struct fx_res res;
	int i, last_dom = -1;

	fx_reset();
	fx_ndomains = 2;
	for (i = 0; i < 3; i++) {
		fx_alloc_page(i,     FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, 0, 0, true);
		fx_alloc_page(i + 3,
		    FX_PA_BASE + (i + 100) * FX_PAGE_SIZE,
		    1, 0, 0, true);
	}

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(6, res.count);

	/* Domain 0 pages must precede domain 1 pages in record. */
	for (i = 0; i < res.count; i++) {
		int d = res.entries[i].domain;

		ATF_CHECK(d >= last_dom);
		last_dom = d;
	}
	ATF_CHECK_EQ(0, res.entries[0].domain);
	ATF_CHECK_EQ(1, res.entries[res.count - 1].domain);
}

ATF_TC_WITHOUT_HEAD(multi_pool_coverage);
ATF_TC_BODY(multi_pool_coverage, tc)
{
	struct fx_res res;
	bool seen[FX_NFREEPOOL];
	int i;

	fx_reset();
	for (i = 0; i < FX_NFREEPOOL; i++)
		fx_alloc_page(i, FX_PA_BASE + i * FX_PAGE_SIZE,
		    0, i, 0, true);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	ATF_CHECK_EQ(FX_NFREEPOOL, res.count);

	memset(seen, 0, sizeof(seen));
	for (i = 0; i < res.count; i++) {
		int p = res.entries[i].pool;

		ATF_CHECK(p >= 0 && p < FX_NFREEPOOL);
		seen[p] = true;
	}
	for (i = 0; i < FX_NFREEPOOL; i++)
		ATF_CHECK(seen[i]);
}

ATF_TC_WITHOUT_HEAD(multi_order_coverage);
ATF_TC_BODY(multi_order_coverage, tc)
{
	struct fx_res res;

	fx_reset();
	/*
	 * Order-0 block (1 page) at page 0.
	 * Order-1 block (2 contiguous pages) at pages 1..2.
	 * Only the head (page 1) is enqueued; page 2 is processed as
	 * part of the block by fx_process_block_all (block_pages = 2).
	 */
	fx_alloc_page(0, FX_PA_BASE, 0, 0, 0, true);

	/* Order-1 block head. */
	fx_alloc_page(1, FX_PA_BASE + 4 * FX_PAGE_SIZE, 0, 0, 1, true);
	/* Order-1 block tail (contiguous, not enqueued separately). */
	fx_alloc_page(2, FX_PA_BASE + 5 * FX_PAGE_SIZE, 0, 0, 1, false);

	memset(&res, 0, sizeof(res));
	res.capacity = FX_RES_MAX;

	ATF_CHECK_EQ(0, fx_reserve_all(&res));
	/* 1 (order-0) + 2 (order-1 block) = 3 pages captured. */
	ATF_CHECK_EQ(3, res.count);
}

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

/* ------------------------------------------------------------------ */
/* ATF_TP registration                                                  */
/* ------------------------------------------------------------------ */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, zero_free_pages);
	ATF_TP_ADD_TC(tp, one_free_page);
	ATF_TP_ADD_TC(tp, many_free_pages);
	ATF_TP_ADD_TC(tp, arena_exclusion);
	ATF_TP_ADD_TC(tp, arena_boundary_pfns);
	ATF_TP_ADD_TC(tp, exact_capacity_reserve);
	ATF_TP_ADD_TC(tp, shortage_reserve);
	ATF_TP_ADD_TC(tp, enospc_reserve_all);
	ATF_TP_ADD_TC(tp, rollback_set_identity);
	ATF_TP_ADD_TC(tp, rollback_count_identity);
	ATF_TP_ADD_TC(tp, adversarial_dst_prefix);
	ATF_TP_ADD_TC(tp, multi_domain_order);
	ATF_TP_ADD_TC(tp, multi_pool_coverage);
	ATF_TP_ADD_TC(tp, multi_order_coverage);
	ATF_TP_ADD_TC(tp, fault_after_nth_append);
	return (atf_no_error());
}
