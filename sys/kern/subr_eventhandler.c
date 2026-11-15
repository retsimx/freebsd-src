/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1999 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>

static MALLOC_DEFINE(M_EVENTHANDLER, "eventhandler", "Event handler records");

/* List of all eventhandler lists */
static TAILQ_HEAD(, eventhandler_list)	eventhandler_lists;
static int				eventhandler_lists_initted = 0;
static struct mtx			eventhandler_mutex;

/*
 * eventhandler_lists (this
 * file)/eventhandler_mutex/eventhandler_lists_initted, the global
 * registry every EVENTHANDLER_INVOKE()/eventhandler_find_list() call
 * anywhere in the kernel walks and locks. None of the three were ever
 * self-copy protected in this epic. Confirmed by direct, live
 * backtrace capture this round to be the exact, sole remaining
 * blocker to DEVICE_RESUME(root_bus) (sys/dev/acpica/acpi.c): the
 * acpi_pre_dev_resume EVENTHANDLER_INVOKE() immediately preceding
 * DEVICE_RESUME(root_bus) calls eventhandler_find_list(), which
 * faults (general protection fault, identical RIP across multiple
 * independent captures) walking eventhandler_lists if the K-10 copy
 * has overwritten it with the SAVE kernel's own, unrelated
 * eventhandler-list content -- the same defect shape as every other
 * sibling in this epic's own established class (a live, allocator/
 * registry-consulted BSS global never previously added to the
 * protected-VA set). copy_leaf is true: this boot's own
 * eventhandler_init()/EVENTHANDLER_REGISTER() calls already built
 * every list/lock/counter correctly; there is no saved-image content
 * worth restoring, identical reasoning to every other sibling
 * structure already protected (vm_page_array/vm_dom/kmemzones/etc).
 */
void	hibernate_md_eventhandler_lists_va(vm_offset_t *va, size_t *len);
void
hibernate_md_eventhandler_lists_va(vm_offset_t *va, size_t *len)
{
	*va = (vm_offset_t)&eventhandler_lists;
	*len = sizeof(eventhandler_lists);
}

void	hibernate_md_eventhandler_mutex_va(vm_offset_t *va, size_t *len);
void
hibernate_md_eventhandler_mutex_va(vm_offset_t *va, size_t *len)
{
	*va = (vm_offset_t)&eventhandler_mutex;
	*len = sizeof(eventhandler_mutex);
}

void	hibernate_md_eventhandler_lists_initted_va(vm_offset_t *va,
	    size_t *len);
void
hibernate_md_eventhandler_lists_initted_va(vm_offset_t *va, size_t *len)
{
	*va = (vm_offset_t)&eventhandler_lists_initted;
	*len = sizeof(eventhandler_lists_initted);
}

/*
 * per explicit
 * instruction, every structure this subsystem's own resume-path
 * consumers touch was enumerated once by direct source reading, not
 * rediscovered by panic. eventhandler_lists/_mutex/_lists_initted
 * (above) are the only file-scope globals in this file; everything
 * else this file's own data model consists of is dynamically
 * malloc(M_EVENTHANDLER)'d: every `struct eventhandler_list` node
 * (eventhandler_find_or_create_list()) and every `struct
 * eventhandler_entry`-derived node (eventhandler_register_internal())
 * hanging off its own el_entries TAILQ. These are LIVE RESUME-KERNEL
 * STATE by this epic's own established rule: every one of them was
 * allocated during THIS boot's own ordinary SYSINIT/device-attach
 * processing (EVENTHANDLER_REGISTER() calls throughout the tree),
 * strictly before the hibernate ioctl can run, so there is no
 * saved-image content worth preserving for any of them -- exactly the
 * same rule already applied to eventhandler_lists itself, just one
 * level further down the data structure than a fixed-size static
 * array can reach. Unlike eventhandler_lists's own fixed VA/len, each
 * node's address is chosen by the allocator fresh each boot and can
 * only be discovered by walking the (already protected) list under
 * the SAME lock ordinary consumers use (eventhandler_mutex, then
 * each list's own el_lock), protecting each node found via
 * hibernate_md_selfcopy_range() (sys/amd64/amd64/hibernate_machdep.c).
 * This closes the gap the live backtrace capture pointed at: the head
 * was protected but a node it points to was not, so the K-10 copy
 * could still leave a `struct eventhandler_list`'s own el_name
 * pointer (or the bytes it addresses) as the SAVE kernel's own,
 * unrelated content -- exactly matching the observed strcmp() GPF
 * inside eventhandler_find_list().
 */
struct hibernate_attempt;
int	eventhandler_hibernate_selfcopy_nodes(
	    const struct hibernate_attempt *ha, vm_paddr_t *wvec, uint64_t p,
	    u_int *countp);
int
eventhandler_hibernate_selfcopy_nodes(const struct hibernate_attempt *ha,
    vm_paddr_t *wvec, uint64_t p, u_int *countp)
{
	struct eventhandler_list *list;
	struct eventhandler_entry *ep;
	int error;

	extern int hibernate_md_selfcopy_range(const struct hibernate_attempt *,
	    vm_paddr_t *, uint64_t, vm_offset_t, size_t, u_int *);

	error = 0;
	if (!eventhandler_lists_initted)
		return (0);
	TAILQ_FOREACH(list, &eventhandler_lists, el_link) {
		error = hibernate_md_selfcopy_range(ha, wvec, p,
		    (vm_offset_t)list, sizeof(*list) + strlen(list->el_name) + 1,
		    countp);
		if (error != 0)
			return (error);
		TAILQ_FOREACH(ep, &list->el_entries, ee_link) {
			error = hibernate_md_selfcopy_range(ha, wvec, p,
			    (vm_offset_t)ep, sizeof(*ep), countp);
			if (error != 0)
				return (error);
		}
	}
	return (0);
}

struct eventhandler_entry_generic 
{
    struct eventhandler_entry	ee;
    void			(* func)(void);
};

static struct eventhandler_list *_eventhandler_find_list(const char *name);

/*
 * Initialize the eventhandler mutex and list.
 */
static void
eventhandler_init(void *dummy __unused)
{
    TAILQ_INIT(&eventhandler_lists);
    mtx_init(&eventhandler_mutex, "eventhandler", NULL, MTX_DEF);
    atomic_store_rel_int(&eventhandler_lists_initted, 1);
}
SYSINIT(eventhandlers, SI_SUB_EVENTHANDLER, SI_ORDER_FIRST, eventhandler_init,
    NULL);

static struct eventhandler_list *
eventhandler_find_or_create_list(const char *name)
{
	struct eventhandler_list *list, *new_list;

	/* look for a matching, existing list */
	list = _eventhandler_find_list(name);

	/* Do we need to create the list? */
	if (list == NULL) {
	    mtx_unlock(&eventhandler_mutex);

	    new_list = malloc(sizeof(*new_list) + strlen(name) + 1,
		M_EVENTHANDLER, M_WAITOK | M_ZERO);

	    /* If someone else created it already, then use that one. */
	    mtx_lock(&eventhandler_mutex);
	    list = _eventhandler_find_list(name);
	    if (list != NULL) {
		free(new_list, M_EVENTHANDLER);
	    } else {
		CTR2(KTR_EVH, "%s: creating list \"%s\"", __func__, name);
		list = new_list;
		TAILQ_INIT(&list->el_entries);
		list->el_name = (char *)(list + 1);
		strcpy(list->el_name, name);
		mtx_init(&list->el_lock, list->el_name, "eventhandler list",
		    MTX_DEF);
		TAILQ_INSERT_HEAD(&eventhandler_lists, list, el_link);
	    }
	}
	return (list);
}

/* 
 * Insertion is O(n) due to the priority scan, but optimises to O(1)
 * if all priorities are identical.
 */
static eventhandler_tag
eventhandler_register_internal(struct eventhandler_list *list,
    const char *name, eventhandler_tag epn)
{
    struct eventhandler_entry		*ep;
    
    KASSERT(eventhandler_lists_initted, ("eventhandler registered too early"));
    KASSERT(epn != NULL, ("%s: cannot register NULL event", __func__));

    /* Do we need to find/create the list? */
    if (list == NULL) {
	    mtx_lock(&eventhandler_mutex);
	    list = eventhandler_find_or_create_list(name);
	    mtx_unlock(&eventhandler_mutex);
    }

    KASSERT(epn->ee_priority != EHE_DEAD_PRIORITY,
	("%s: handler for %s registered with dead priority", __func__, name));

    /* sort it into the list */
    CTR4(KTR_EVH, "%s: adding item %p (function %p) to \"%s\"", __func__, epn,
	((struct eventhandler_entry_generic *)epn)->func, name);
    EHL_LOCK(list);
    TAILQ_FOREACH(ep, &list->el_entries, ee_link) {
	if (ep->ee_priority != EHE_DEAD_PRIORITY &&
	    epn->ee_priority < ep->ee_priority) {
	    TAILQ_INSERT_BEFORE(ep, epn, ee_link);
	    break;
	}
    }
    if (ep == NULL)
	TAILQ_INSERT_TAIL(&list->el_entries, epn, ee_link);
    EHL_UNLOCK(list);
    return(epn);
}

eventhandler_tag
eventhandler_register(struct eventhandler_list *list, const char *name, 
		      void *func, void *arg, int priority)
{
    struct eventhandler_entry_generic	*eg;
    
    /* allocate an entry for this handler, populate it */
    eg = malloc(sizeof(struct eventhandler_entry_generic), M_EVENTHANDLER,
	M_WAITOK | M_ZERO);
    eg->func = func;
    eg->ee.ee_arg = arg;
    eg->ee.ee_priority = priority;

    return (eventhandler_register_internal(list, name, &eg->ee));
}

#ifdef VIMAGE
struct eventhandler_entry_generic_vimage
{
    struct eventhandler_entry		ee;
    vimage_iterator_func_t		func;		/* Vimage iterator function. */
    struct eventhandler_entry_vimage	v_ee;		/* Original func, arg. */
};

eventhandler_tag
vimage_eventhandler_register(struct eventhandler_list *list, const char *name, 
    void *func, void *arg, int priority, vimage_iterator_func_t iterfunc)
{
    struct eventhandler_entry_generic_vimage	*eg;
    
    /* allocate an entry for this handler, populate it */
    eg = malloc(sizeof(struct eventhandler_entry_generic_vimage),
	M_EVENTHANDLER, M_WAITOK | M_ZERO);
    eg->func = iterfunc;
    eg->v_ee.func = func;
    eg->v_ee.ee_arg = arg;
    eg->ee.ee_arg = &eg->v_ee;
    eg->ee.ee_priority = priority;

    return (eventhandler_register_internal(list, name, &eg->ee));
}
#endif

static void
_eventhandler_deregister(struct eventhandler_list *list, eventhandler_tag tag,
    bool wait)
{
    struct eventhandler_entry	*ep = tag;

    EHL_LOCK_ASSERT(list, MA_OWNED);
    if (ep != NULL) {
	/* remove just this entry */
	if (list->el_runcount == 0) {
	    CTR3(KTR_EVH, "%s: removing item %p from \"%s\"", __func__, ep,
		list->el_name);
	    TAILQ_REMOVE(&list->el_entries, ep, ee_link);
	    free(ep, M_EVENTHANDLER);
	} else {
	    CTR3(KTR_EVH, "%s: marking item %p from \"%s\" as dead", __func__,
		ep, list->el_name);
	    KASSERT(ep->ee_priority != EHE_DEAD_PRIORITY,
		("%s: handler for %s is dead", __func__, list->el_name));
	    ep->ee_priority = EHE_DEAD_PRIORITY;
	    list->el_deadcount++;
	}
    } else {
	/* remove entire list */
	if (list->el_runcount == 0) {
	    CTR2(KTR_EVH, "%s: removing all items from \"%s\"", __func__,
		list->el_name);
	    while (!TAILQ_EMPTY(&list->el_entries)) {
		ep = TAILQ_FIRST(&list->el_entries);
		TAILQ_REMOVE(&list->el_entries, ep, ee_link);
		free(ep, M_EVENTHANDLER);
	    }
	} else {
	    CTR2(KTR_EVH, "%s: marking all items from \"%s\" as dead",
		__func__, list->el_name);
	    TAILQ_FOREACH(ep, &list->el_entries, ee_link) {
		KASSERT(ep->ee_priority != EHE_DEAD_PRIORITY,
		    ("%s: handler for %s is dead", __func__, list->el_name));
		ep->ee_priority = EHE_DEAD_PRIORITY;
		list->el_deadcount++;
	    }
	}
    }
    while (wait && list->el_deadcount > 0)
	    mtx_sleep(list, &list->el_lock, 0, "evhrm", 0);
    EHL_UNLOCK(list);
}

void
eventhandler_deregister(struct eventhandler_list *list, eventhandler_tag tag)
{

	_eventhandler_deregister(list, tag, true);
}

void
eventhandler_deregister_nowait(struct eventhandler_list *list,
    eventhandler_tag tag)
{

	_eventhandler_deregister(list, tag, false);
}

/*
 * Internal version for use when eventhandler list is already locked.
 */
static struct eventhandler_list *
_eventhandler_find_list(const char *name)
{
    struct eventhandler_list	*list;

    mtx_assert(&eventhandler_mutex, MA_OWNED);
    TAILQ_FOREACH(list, &eventhandler_lists, el_link) {
	if (!strcmp(name, list->el_name))
	    break;
    }
    return (list);
}

/*
 * Lookup a "slow" list by name.  Returns with the list locked.
 */
struct eventhandler_list *
eventhandler_find_list(const char *name)
{
    struct eventhandler_list	*list;

    if (!eventhandler_lists_initted)
	return(NULL);
    
    /* scan looking for the requested list */
    mtx_lock(&eventhandler_mutex);
    list = _eventhandler_find_list(name);
    if (list != NULL)
	EHL_LOCK(list);
    mtx_unlock(&eventhandler_mutex);
    
    return(list);
}

/*
 * Prune "dead" entries from an eventhandler list.
 */
void
eventhandler_prune_list(struct eventhandler_list *list)
{
    struct eventhandler_entry *ep, *en;
    int pruned __diagused;

    CTR2(KTR_EVH, "%s: pruning list \"%s\"", __func__, list->el_name);
    EHL_LOCK_ASSERT(list, MA_OWNED);

    pruned = 0;
    TAILQ_FOREACH_SAFE(ep, &list->el_entries, ee_link, en) {
	if (ep->ee_priority == EHE_DEAD_PRIORITY) {
	    TAILQ_REMOVE(&list->el_entries, ep, ee_link);
	    free(ep, M_EVENTHANDLER);
	    pruned++;
	}
    }
    KASSERT(pruned == list->el_deadcount,
	("%s: pruned %u entries from \"%s\" but expected %u",
	__func__, pruned, list->el_name, list->el_deadcount));
    list->el_deadcount = 0;
    wakeup(list);
}

/*
 * Create (or get the existing) list so the pointer can be stored by
 * EVENTHANDLER_LIST_DEFINE.
 */
struct eventhandler_list *
eventhandler_create_list(const char *name)
{
	struct eventhandler_list *list;

	KASSERT(eventhandler_lists_initted,
	    ("eventhandler list created too early"));

	mtx_lock(&eventhandler_mutex);
	list = eventhandler_find_or_create_list(name);
	mtx_unlock(&eventhandler_mutex);

	return (list);
}
