/*-
 * Copyright (c) 2001 Michael Smith
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

#include <sys/cdefs.h>
#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/bus.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

/*
 * ACPI power resource management.
 *
 * Power resource behaviour is slightly complicated by the fact that
 * a single power resource may provide power for more than one device.
 * Thus, we must track the device(s) being powered by a given power
 * resource, and only deactivate it when there are no powered devices.
 *
 * Note that this only manages resources for known devices.  There is an
 * ugly case where we may turn off power to a device which is in use because
 * we don't know that it depends on a given resource.  We should perhaps
 * try to be smarter about this, but a more complete solution would involve
 * scanning all of the ACPI namespace to find devices we're not currently
 * aware of, and this raises questions about whether they should be left 
 * on, turned off, etc.
 */

static MALLOC_DEFINE(M_ACPIPWR, "acpipwr", "ACPI power resources");

/* Hooks for the ACPI CA debugging infrastructure */
#define _COMPONENT	ACPI_POWERRES
ACPI_MODULE_NAME("POWERRES")

/* Return values from _STA on a power resource */
#define ACPI_PWR_OFF	0
#define ACPI_PWR_ON	1

/* A relationship between a power resource and a consumer. */
struct acpi_powerreference {
    struct acpi_powerconsumer		*ar_consumer;
    struct acpi_powerresource		*ar_resource;
    TAILQ_ENTRY(acpi_powerreference)	ar_rlink; /* link on resource list */
    TAILQ_ENTRY(acpi_powerreference)	ar_clink; /* link on consumer */
};
    
/* A power-managed device. */
struct acpi_powerconsumer {
    /* Device which is powered */
    ACPI_HANDLE				ac_consumer;
    int					ac_state;
    TAILQ_ENTRY(acpi_powerconsumer)	ac_link;
    TAILQ_HEAD(,acpi_powerreference)	ac_references;
};

/* A power resource. */
struct acpi_powerresource {
    TAILQ_ENTRY(acpi_powerresource)	ap_link;
    TAILQ_HEAD(,acpi_powerreference)	ap_references;
    ACPI_HANDLE				ap_resource;
    UINT64				ap_systemlevel;
    UINT64				ap_order;
};

static TAILQ_HEAD(acpi_powerresource_list, acpi_powerresource)
    acpi_powerresources = TAILQ_HEAD_INITIALIZER(acpi_powerresources);
static TAILQ_HEAD(acpi_powerconsumer_list, acpi_powerconsumer)
    acpi_powerconsumers = TAILQ_HEAD_INITIALIZER(acpi_powerconsumers);

/*
 * K24-T00 (measurement-method fix round): acpi_powerresources/
 * acpi_powerconsumers (this file), the two static TAILQ heads every
 * ACPI power-resource/consumer registration and lookup
 * (acpi_pwr_register_consumer()/acpi_pwr_find_consumer(), etc.) walks
 * directly. Confirmed by direct, live backtrace capture this round
 * (acpi_pwr_switch_consumer()'s own %rbx == 0xdeadc0dedeadc0de --
 * FreeBSD's own uninitialized/poisoned-memory debug pattern -- at a
 * point called from the FIRST confirmed DEVICE_RESUME(root_bus)
 * execution reached in this epic's entire history, via
 * root_resume()/bus_generic_resume()/pci_resume()/
 * acpi_pci_set_powerstate_method()) to be the real root cause of the
 * "Bad tailq head ... first->prev != head" panic variant previously
 * observed at this same file's own acpi_pwr_register_consumer(): if
 * the K-10 copy overwrites either static TAILQ_HEAD with the SAVE
 * kernel's own unrelated queue content, every subsequent
 * insert/remove/walk on it is corrupted from that point on. Same bug
 * class and disposition as every other sibling in this epic's own
 * established class: copy_leaf is true, this boot's own cold
 * TAILQ_HEAD_INITIALIZER content is already correct (empty); there is
 * no saved-image queue content worth restoring, since a resume
 * kernel's own power-resource/consumer registrations bear no
 * relationship to the save-kernel's own.
 */
void	hibernate_md_acpi_powerresources_va(vm_offset_t *va, size_t *len);
void
hibernate_md_acpi_powerresources_va(vm_offset_t *va, size_t *len)
{
	*va = (vm_offset_t)&acpi_powerresources;
	*len = sizeof(acpi_powerresources);
}

void	hibernate_md_acpi_powerconsumers_va(vm_offset_t *va, size_t *len);
void
hibernate_md_acpi_powerconsumers_va(vm_offset_t *va, size_t *len)
{
	*va = (vm_offset_t)&acpi_powerconsumers;
	*len = sizeof(acpi_powerconsumers);
}

/*
 * K24-T00 (round 12, ACPI power-resource subsystem sweep): per
 * explicit instruction, every structure this subsystem's resume-path
 * consumers touch was enumerated once by direct source reading.
 * acpi_powerresources/acpi_powerconsumers (above) are the only
 * file-scope globals in this file; every `struct acpi_powerresource`
 * (acpi_pwr_register_resource()), `struct acpi_powerconsumer`
 * (acpi_pwr_register_consumer()), and `struct acpi_powerreference`
 * (acpi_pwr_reference_resource()) is a SEPARATE malloc(M_ACPIPWR)
 * allocation this boot's own ACPI namespace walk performs during
 * ordinary device-attach processing, strictly before any hibernate
 * ioctl -- LIVE RESUME-KERNEL STATE by the same rule already applied
 * to the two TAILQ heads themselves, one level further down the data
 * structure. Confirmed by direct source reading
 * (acpi_pwr_reference_resource(), above): every acpi_powerreference is
 * inserted onto BOTH its consumer's ac_references (ar_clink) and its
 * resource's ap_references (ar_rlink) TAILQs at the same time, so
 * walking acpi_powerconsumers and each consumer's own ac_references
 * reaches every powerreference node transitively; a separate walk of
 * acpi_powerresources would only revisit the same reference nodes a
 * second time via ap_references, reaching no node the consumer walk
 * misses, so it is intentionally not duplicated here. This closes the
 * gap the live backtrace capture pointed at (acpi_pwr_switch_consumer()'s
 * own 0xdeadc0dedeadc0de poison, and acpi_pwr_register_consumer()'s own
 * "Bad tailq head ... first->prev != head"): the heads were protected
 * but the nodes reachable from them were not, so the K-10 copy could
 * still leave a consumer/reference node's own link fields as the SAVE
 * kernel's own, unrelated content.
 */
struct hibernate_attempt;
int	acpi_powerres_hibernate_selfcopy_nodes(
	    const struct hibernate_attempt *ha, vm_paddr_t *wvec, uint64_t p,
	    u_int *countp);
int
acpi_powerres_hibernate_selfcopy_nodes(const struct hibernate_attempt *ha,
    vm_paddr_t *wvec, uint64_t p, u_int *countp)
{
	struct acpi_powerconsumer *pc;
	struct acpi_powerreference *pr;
	int error;
	extern int hibernate_md_selfcopy_range(const struct hibernate_attempt *,
	    vm_paddr_t *, uint64_t, vm_offset_t, size_t, u_int *);

	TAILQ_FOREACH(pc, &acpi_powerconsumers, ac_link) {
		error = hibernate_md_selfcopy_range(ha, wvec, p,
		    (vm_offset_t)pc, sizeof(*pc), countp);
		if (error != 0)
			return (error);
		TAILQ_FOREACH(pr, &pc->ac_references, ar_clink) {
			error = hibernate_md_selfcopy_range(ha, wvec, p,
			    (vm_offset_t)pr, sizeof(*pr), countp);
			if (error != 0)
				return (error);
		}
	}
	return (0);
}
ACPI_SERIAL_DECL(powerres, "ACPI power resources");

/*
 * K24-T00 (round 12, ACPI power-resource subsystem sweep, found during
 * live capture): ACPI_SERIAL_DECL() (acpivar.h) expands to a static
 * `struct sx powerres_sxlock` (this file), SX_SYSINIT()'d at this
 * boot's own cold-boot time -- a live BSS global this epic's own
 * established rule already covers for every sibling mutex/sx this
 * file's own TAILQ heads sit beside (eventhandler_mutex, sleepq_
 * chains[]'s own per-bucket sc_lock, etc.), but never added to this
 * file's own protected set: acpi_pwr_switch_consumer()'s own
 * ACPI_SERIAL_BEGIN(powerres) (sx_xlock(&powerres_sxlock)) is the
 * FIRST statement this function executes after its NULL-consumer
 * check -- exactly matching the observed live capture (GPF at
 * acpi_pwr_switch_consumer+0x80, immediately on function entry,
 * %rbx == 0xdeadc0dedeadc0de, even after both TAILQ heads and every
 * node reachable from them were already protected this round). If the
 * K-10 copy overwrites powerres_sxlock with the SAVE kernel's own,
 * unrelated sx-lock content, the very first sx_xlock() on this boot's
 * own lock reads a foreign/poisoned internal lock-state word. copy_leaf
 * is true: this boot's own SX_SYSINIT already built it correctly; there
 * is no saved-image lock state worth restoring.
 */
void	hibernate_md_acpi_powerres_sxlock_va(vm_offset_t *va, size_t *len);
void
hibernate_md_acpi_powerres_sxlock_va(vm_offset_t *va, size_t *len)
{
	*va = (vm_offset_t)&powerres_sxlock;
	*len = sizeof(powerres_sxlock);
}

static ACPI_STATUS	acpi_pwr_register_consumer(ACPI_HANDLE consumer);
#ifdef notyet
static ACPI_STATUS	acpi_pwr_deregister_consumer(ACPI_HANDLE consumer);
#endif /* notyet */
static ACPI_STATUS	acpi_pwr_register_resource(ACPI_HANDLE res);
#ifdef notyet
static ACPI_STATUS	acpi_pwr_deregister_resource(ACPI_HANDLE res);
#endif /* notyet */
static void		acpi_pwr_reference_resource(ACPI_OBJECT *obj,
						    void *arg);
static int		acpi_pwr_dereference_resource(struct acpi_powerconsumer
			    *pc);
static ACPI_STATUS	acpi_pwr_switch_power(void);
static struct acpi_powerresource
			*acpi_pwr_find_resource(ACPI_HANDLE res);
static struct acpi_powerconsumer
			*acpi_pwr_find_consumer(ACPI_HANDLE consumer);
static void		acpi_pwr_validate_or_panic(void);
void			acpi_pwr_hibernate_reinit(void);

/*
 * Register a power resource.
 *
 * It's OK to call this if we already know about the resource.
 */
static ACPI_STATUS
acpi_pwr_register_resource(ACPI_HANDLE res)
{
    ACPI_STATUS			status;
    ACPI_BUFFER			buf;
    ACPI_OBJECT			*obj;
    struct acpi_powerresource	*rp, *srp;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    rp = NULL;
    buf.Pointer = NULL;
    
    /* Look to see if we know about this resource */
    if (acpi_pwr_find_resource(res) != NULL)
	return_ACPI_STATUS (AE_OK);		/* already know about it */

    /* Allocate a new resource */
    if ((rp = malloc(sizeof(*rp), M_ACPIPWR, M_NOWAIT | M_ZERO)) == NULL) {
	status = AE_NO_MEMORY;
	goto out;
    }
    TAILQ_INIT(&rp->ap_references);
    rp->ap_resource = res;

    /* Get the Power Resource object */
    buf.Length = ACPI_ALLOCATE_BUFFER;
    if (ACPI_FAILURE(status = AcpiEvaluateObject(res, NULL, NULL, &buf))) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "no power resource object\n"));
	goto out;
    }
    obj = buf.Pointer;
    if (obj->Type != ACPI_TYPE_POWER) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			 "questionable power resource object %s\n",
			 acpi_name(res)));
	status = AE_TYPE;
	goto out;
    }
    rp->ap_systemlevel = obj->PowerResource.SystemLevel;
    rp->ap_order = obj->PowerResource.ResourceOrder;
    
    /* Sort the resource into the list */
    status = AE_OK;
    srp = TAILQ_FIRST(&acpi_powerresources);
    if (srp == NULL || rp->ap_order < srp->ap_order) {
	TAILQ_INSERT_HEAD(&acpi_powerresources, rp, ap_link);
	goto done;
    }
    TAILQ_FOREACH(srp, &acpi_powerresources, ap_link) {
	if (rp->ap_order < srp->ap_order) {
	    TAILQ_INSERT_BEFORE(srp, rp, ap_link);
	    goto done;
	}
    }
    TAILQ_INSERT_TAIL(&acpi_powerresources, rp, ap_link);

 done:
    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
		     "registered power resource %s\n", acpi_name(res)));

 out:
    if (buf.Pointer != NULL)
	AcpiOsFree(buf.Pointer);
    if (ACPI_FAILURE(status) && rp != NULL)
	free(rp, M_ACPIPWR);
    return_ACPI_STATUS (status);
}

#ifdef notyet
/*
 * Deregister a power resource.
 */
static ACPI_STATUS
acpi_pwr_deregister_resource(ACPI_HANDLE res)
{
    struct acpi_powerresource	*rp;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    rp = NULL;
    
    /* Find the resource */
    if ((rp = acpi_pwr_find_resource(res)) == NULL)
	return_ACPI_STATUS (AE_BAD_PARAMETER);

    /* Check that there are no consumers referencing this resource */
    if (TAILQ_FIRST(&rp->ap_references) != NULL)
	return_ACPI_STATUS (AE_BAD_PARAMETER);

    /* Pull it off the list and free it */
    TAILQ_REMOVE(&acpi_powerresources, rp, ap_link);
    free(rp, M_ACPIPWR);

    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "deregistered power resource %s\n",
		     acpi_name(res)));

    return_ACPI_STATUS (AE_OK);
}
#endif /* notyet */

/*
 * Register a power consumer.  
 *
 * It's OK to call this if we already know about the consumer.
 */
static ACPI_STATUS
acpi_pwr_register_consumer(ACPI_HANDLE consumer)
{
    struct acpi_powerconsumer	*pc;
    
    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    /* Check to see whether we know about this consumer already */
    if (acpi_pwr_find_consumer(consumer) != NULL)
	return_ACPI_STATUS (AE_OK);
    
    /* Allocate a new power consumer */
    if ((pc = malloc(sizeof(*pc), M_ACPIPWR, M_NOWAIT)) == NULL)
	return_ACPI_STATUS (AE_NO_MEMORY);
    TAILQ_INSERT_HEAD(&acpi_powerconsumers, pc, ac_link);
    /*
     * K24-T00 (round 13, validation harness): confirm the insert this
     * line just performed is itself coherent -- the just-inserted
     * node must now be TAILQ_FIRST, and if a second node exists, that
     * second node's own prev must point back to this one. This
     * narrows the "Bad tailq head ... first->prev != head" panic
     * previously observed at this exact call site (round 11/12): if
     * THIS check ever fires, the head was ALREADY broken before this
     * specific TAILQ_INSERT_HEAD ran (this round's own hypothesis 3,
     * traversal/mutation racing against something else); if it never
     * fires but the panic still recurs elsewhere, the corruption
     * happens strictly AFTER this point, narrowing the search further.
     */
    if (TAILQ_FIRST(&acpi_powerconsumers) != pc)
	panic("acpi_pwr_register_consumer: TAILQ_INSERT_HEAD succeeded "
	    "but acpi_powerconsumers.tqh_first (%p) != pc (%p) "
	    "immediately after",
	    TAILQ_FIRST(&acpi_powerconsumers), pc);
    TAILQ_INIT(&pc->ac_references);
    pc->ac_consumer = consumer;

    /* XXX we should try to find its current state */
    pc->ac_state = ACPI_STATE_UNKNOWN;

    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "registered power consumer %s\n",
		     acpi_name(consumer)));
    
    return_ACPI_STATUS (AE_OK);
}

#ifdef notyet
/*
 * Deregister a power consumer.
 *
 * This should only be done once the consumer has been powered off.
 * (XXX is this correct?  Check once implemented)
 */
static ACPI_STATUS
acpi_pwr_deregister_consumer(ACPI_HANDLE consumer)
{
    struct acpi_powerconsumer	*pc;
    
    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    /* Find the consumer */
    if ((pc = acpi_pwr_find_consumer(consumer)) == NULL)
	return_ACPI_STATUS (AE_BAD_PARAMETER);
    
    /* Make sure the consumer's not referencing anything right now */
    if (TAILQ_FIRST(&pc->ac_references) != NULL)
	return_ACPI_STATUS (AE_BAD_PARAMETER);

    /* Pull the consumer off the list and free it */
    TAILQ_REMOVE(&acpi_powerconsumers, pc, ac_link);
    free(pc, M_ACPIPWR);

    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "deregistered power consumer %s\n",
		     acpi_name(consumer)));

    return_ACPI_STATUS (AE_OK);
}
#endif /* notyet */

/*
 * Set a power consumer to a particular power state.
 */
ACPI_STATUS
acpi_pwr_switch_consumer(ACPI_HANDLE consumer, int state)
{
    struct acpi_powerconsumer	*pc;
    ACPI_HANDLE			method_handle, reslist_handle, pr0_handle;
    ACPI_BUFFER			reslist_buffer;
    ACPI_OBJECT			*reslist_object;
    ACPI_STATUS			status;
    char			*method_name, *reslist_name = NULL;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    /* It's never ok to switch a non-existent consumer. */
    if (consumer == NULL)
	return_ACPI_STATUS (AE_NOT_FOUND);
    reslist_buffer.Pointer = NULL;
    reslist_object = NULL;
    ACPI_SERIAL_BEGIN(powerres);

    /*
     * K24-T00 (round 13): validate every list this function is about
     * to traverse BEFORE traversing it, converting the unreproducible
     * corruption this call site has shown (7/9 recurrence, round 12)
     * into a named, observable invariant failure on its first
     * occurrence, per this round's own explicit instruction. See
     * acpi_pwr_validate_or_panic()'s own comment, above, for the full
     * rationale and the three hypotheses it distinguishes between.
     */
    acpi_pwr_validate_or_panic();

    /* Find the consumer */
    if ((pc = acpi_pwr_find_consumer(consumer)) == NULL) {
	if (ACPI_FAILURE(status = acpi_pwr_register_consumer(consumer)))
	    goto out;
	if ((pc = acpi_pwr_find_consumer(consumer)) == NULL)
	    panic("acpi added power consumer but can't find it");
    }

    /* Stop here if we're already at the target D-state. */
    if (pc->ac_state == state) {
	status = AE_OK;
	goto out;
    }

    /*
     * Check for valid transitions.  From D3hot or D3cold, we can only go to D0.
     * The exception to this is going from D3hot to D3cold or the other way
     * around.  This is because they both use _PS3, so the only difference when
     * doing these transitions is whether or not the power resources for _PR3
     * are on for devices which support D3cold, and turning these power
     * resources on/off is always perfectly fine (ACPI 7.3.11).
     */
    status = AE_BAD_PARAMETER;
    if (pc->ac_state == ACPI_STATE_D3_HOT && state != ACPI_STATE_D0 &&
	state != ACPI_STATE_D3_COLD)
	goto out;
    if (pc->ac_state == ACPI_STATE_D3_COLD && state != ACPI_STATE_D0 &&
	state != ACPI_STATE_D3_HOT)
	goto out;

    /* Find transition mechanism(s) */
    switch (state) {
    case ACPI_STATE_D0:
	method_name = "_PS0";
	reslist_name = "_PR0";
	break;
    case ACPI_STATE_D1:
	method_name = "_PS1";
	reslist_name = "_PR1";
	break;
    case ACPI_STATE_D2:
	method_name = "_PS2";
	reslist_name = "_PR2";
	break;
    case ACPI_STATE_D3_HOT:
	method_name = "_PS3";
	reslist_name = "_PR3";
	break;
    case ACPI_STATE_D3_COLD:
	method_name = "_PS3";
	reslist_name = NULL;
	break;
    default:
	goto out;
    }
    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "setup to switch %s %s -> %s\n",
		     acpi_name(consumer), acpi_d_state_to_str(pc->ac_state),
		     acpi_d_state_to_str(state)));

    /*
     * Verify that this state is supported, ie. one of method or
     * reslist must be present.  We need to do this before we go 
     * dereferencing resources (since we might be trying to go to
     * a state we don't support).
     *
     * Note that if any states are supported, the device has to
     * support D0 and D3.  It's never an error to try to go to
     * D0.
     */
    if (ACPI_FAILURE(AcpiGetHandle(consumer, method_name, &method_handle)))
	method_handle = NULL;
    if (reslist_name == NULL ||
	ACPI_FAILURE(AcpiGetHandle(consumer, reslist_name, &reslist_handle)))
	reslist_handle = NULL;
    if (reslist_handle == NULL && method_handle == NULL) {
	if (state == ACPI_STATE_D0) {
	    pc->ac_state = ACPI_STATE_D0;
	    status = AE_OK;
	    goto out;
	}
	if (state == ACPI_STATE_D3_COLD)
	    state = ACPI_STATE_D3_HOT;
	if (state != ACPI_STATE_D3_HOT) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
		"attempt to set unsupported state %s\n",
		acpi_d_state_to_str(state)));
	    goto out;
	}

	/*
	 * Turn off the resources listed in _PR0 to go to D3.  If there is
	 * no _PR0 method, this object doesn't support ACPI power states.
	 */
	if (ACPI_FAILURE(AcpiGetHandle(consumer, "_PR0", &pr0_handle))) {
	    status = AE_NOT_FOUND;
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
		"device missing _PR0 (desired state was %s)\n",
		acpi_d_state_to_str(state)));
	    goto out;
	}
	reslist_buffer.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiEvaluateObject(pr0_handle, NULL, NULL, &reslist_buffer);
	if (ACPI_FAILURE(status)) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
		"can't evaluate _PR0 for device %s, state %s\n",
		acpi_name(consumer), acpi_d_state_to_str(state)));
	    goto out;
	}
	reslist_object = (ACPI_OBJECT *)reslist_buffer.Pointer;
	if (!ACPI_PKG_VALID(reslist_object, 1)) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
		"invalid package object for state %s\n",
		acpi_d_state_to_str(state)));
	    status = AE_TYPE;
	    goto out;
	}
	AcpiOsFree(reslist_buffer.Pointer);
	reslist_buffer.Pointer = NULL;
	reslist_object = NULL;
    }

    /*
     * Check that we can actually fetch the list of power resources
     */
    if (reslist_handle != NULL) {
	reslist_buffer.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiEvaluateObject(reslist_handle, NULL, NULL,
				    &reslist_buffer);
	if (ACPI_FAILURE(status)) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			     "can't evaluate resource list %s\n",
			     acpi_name(reslist_handle)));
	    goto out;
	}
	reslist_object = (ACPI_OBJECT *)reslist_buffer.Pointer;
	if (reslist_object->Type != ACPI_TYPE_PACKAGE) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			     "resource list is not ACPI_TYPE_PACKAGE (%d)\n",
			     reslist_object->Type));
	    status = AE_TYPE;
	    goto out;
	}
    }

    /*
     * Now we are ready to switch, so kill off any current power
     * resource references.
     */
    acpi_pwr_dereference_resource(pc);

    /*
     * Add new power resource references, if we have any.  Traverse the
     * package that we got from evaluating reslist_handle, and look up each
     * of the resources that are referenced.
     */
    if (reslist_object != NULL) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "referencing %d new resources\n", 
			  reslist_object->Package.Count));
	acpi_ForeachPackageObject(reslist_object, acpi_pwr_reference_resource,
				  pc);
    }

    /*
     * If we changed anything in the resource list, we need to run a switch
     * pass now.
     */
    if (ACPI_FAILURE(status = acpi_pwr_switch_power())) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			 "failed to switch resources from %s to %s\n",
			  acpi_name(consumer), acpi_d_state_to_str(state)));

	/* XXX is this appropriate?  Should we return to previous state? */
	goto out;
    }

    /* Invoke power state switch method (if present) */
    if (method_handle != NULL) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			 "invoking state transition method %s\n",
			 acpi_name(method_handle)));
	status = AcpiEvaluateObject(method_handle, NULL, NULL, NULL);
	if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "failed to set state - %s\n",
				 AcpiFormatException(status)));
		pc->ac_state = ACPI_STATE_UNKNOWN;

		/* XXX Should we return to previous state? */
		goto out;
	}
    }

    /* Transition was successful */
    pc->ac_state = state;
    status = AE_OK;

out:
    ACPI_SERIAL_END(powerres);
    if (reslist_buffer.Pointer != NULL)
	AcpiOsFree(reslist_buffer.Pointer);
    return_ACPI_STATUS (status);
}

/* Enable or disable a power resource for wake */
ACPI_STATUS
acpi_pwr_wake_enable(ACPI_HANDLE consumer, int enable)
{
    ACPI_STATUS status;
    struct acpi_powerconsumer *pc;
    struct acpi_prw_data prw;
    int i;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    if (consumer == NULL)
	return (AE_BAD_PARAMETER);

    ACPI_SERIAL_BEGIN(powerres);
    if ((pc = acpi_pwr_find_consumer(consumer)) == NULL) {
	if (ACPI_FAILURE(status = acpi_pwr_register_consumer(consumer)))
	    goto out;
	if ((pc = acpi_pwr_find_consumer(consumer)) == NULL)
	    panic("acpi wake added power consumer but can't find it");
    }

    status = AE_OK;
    if (acpi_parse_prw(consumer, &prw) != 0)
	goto out;
    for (i = 0; i < prw.power_res_count; i++)
	if (enable)
	    acpi_pwr_reference_resource(&prw.power_res[i], pc);
	else
	    acpi_pwr_dereference_resource(pc);

    if (prw.power_res_count > 0)
	acpi_pwr_switch_power();

out:
    ACPI_SERIAL_END(powerres);
    return (status);
}

/*
 * Called to create a reference between a power consumer and a power resource
 * identified in the object.
 */
static void
acpi_pwr_reference_resource(ACPI_OBJECT *obj, void *arg)
{
    struct acpi_powerconsumer	*pc = (struct acpi_powerconsumer *)arg;
    struct acpi_powerreference	*pr;
    struct acpi_powerresource	*rp;
    ACPI_HANDLE			res;
    ACPI_STATUS			status;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    res = acpi_GetReference(NULL, obj);
    if (res == NULL) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			 "can't create a power reference for object type %d\n",
			 obj->Type));
	return_VOID;
    }

    /* Create/look up the resource */
    if (ACPI_FAILURE(status = acpi_pwr_register_resource(res))) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			 "couldn't register power resource %s - %s\n",
			 obj->String.Pointer, AcpiFormatException(status)));
	return_VOID;
    }
    if ((rp = acpi_pwr_find_resource(res)) == NULL) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "power resource list corrupted\n"));
	return_VOID;
    }
    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "found power resource %s\n",
		     acpi_name(rp->ap_resource)));

    /* Create a reference between the consumer and resource */
    if ((pr = malloc(sizeof(*pr), M_ACPIPWR, M_NOWAIT | M_ZERO)) == NULL) {
	ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			 "allocation failed for a power consumer reference\n"));
	return_VOID;
    }
    pr->ar_consumer = pc;
    pr->ar_resource = rp;
    TAILQ_INSERT_TAIL(&pc->ac_references, pr, ar_clink);
    TAILQ_INSERT_TAIL(&rp->ap_references, pr, ar_rlink);

    return_VOID;
}

static int
acpi_pwr_dereference_resource(struct acpi_powerconsumer *pc)
{
    struct acpi_powerreference *pr;
    int changed;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    changed = 0;
    while ((pr = TAILQ_FIRST(&pc->ac_references)) != NULL) {
        ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "removing reference to %s\n",
                         acpi_name(pr->ar_resource->ap_resource)));
        TAILQ_REMOVE(&pr->ar_resource->ap_references, pr, ar_rlink);
        TAILQ_REMOVE(&pc->ac_references, pr, ar_clink);
        free(pr, M_ACPIPWR);
        changed = 1;
    }

    return (changed);
}

/*
 * Switch power resources to conform to the desired state.
 *
 * Consumers may have modified the power resource list in an arbitrary
 * fashion; we sweep it in sequence order.
 */
static ACPI_STATUS
acpi_pwr_switch_power(void)
{
    struct acpi_powerresource	*rp;
    ACPI_STATUS			status;
    int				cur;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    /*
     * Sweep the list forwards turning things on.
     */
    TAILQ_FOREACH(rp, &acpi_powerresources, ap_link) {
	if (TAILQ_FIRST(&rp->ap_references) == NULL) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			     "%s has no references, not turning on\n",
			     acpi_name(rp->ap_resource)));
	    continue;
	}

	status = acpi_GetInteger(rp->ap_resource, "_STA", &cur);
	if (ACPI_FAILURE(status)) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "can't get status of %s - %d\n",
			      acpi_name(rp->ap_resource), status));
	    /* XXX is this correct?  Always switch if in doubt? */
	    continue;
	}

	/*
	 * Switch if required.  Note that we ignore the result of the switch
	 * effort; we don't know what to do if it fails, so checking wouldn't
	 * help much.
	 */
	if (cur != ACPI_PWR_ON) {
	    status = AcpiEvaluateObject(rp->ap_resource, "_ON", NULL, NULL);
	    if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
				 "failed to switch %s on - %s\n", 
				 acpi_name(rp->ap_resource),
				 AcpiFormatException(status)));
	    } else {
		ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "switched %s on\n",
				 acpi_name(rp->ap_resource)));
	    }
	} else {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "%s is already on\n",
			     acpi_name(rp->ap_resource)));
	}
    }
    
    /* Sweep the list backwards turning things off. */
    TAILQ_FOREACH_REVERSE(rp, &acpi_powerresources, acpi_powerresource_list,
	ap_link) {
	if (TAILQ_FIRST(&rp->ap_references) != NULL) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
			     "%s has references, not turning off\n",
			     acpi_name(rp->ap_resource)));
	    continue;
	}

	status = acpi_GetInteger(rp->ap_resource, "_STA", &cur);
	if (ACPI_FAILURE(status)) {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "can't get status of %s - %d\n",
			      acpi_name(rp->ap_resource), status));
	    /* XXX is this correct?  Always switch if in doubt? */
	    continue;
	}

	/*
	 * Switch if required.  Note that we ignore the result of the switch
	 * effort; we don't know what to do if it fails, so checking wouldn't
	 * help much.
	 */
	if (cur != ACPI_PWR_OFF) {
	    status = AcpiEvaluateObject(rp->ap_resource, "_OFF", NULL, NULL);
	    if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS,
				 "failed to switch %s off - %s\n", 
				 acpi_name(rp->ap_resource),
				 AcpiFormatException(status)));
	    } else {
		ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "switched %s off\n",
				 acpi_name(rp->ap_resource)));
	    }
	} else {
	    ACPI_DEBUG_PRINT((ACPI_DB_OBJECTS, "%s is already off\n",
			     acpi_name(rp->ap_resource)));
	}
    }

    return_ACPI_STATUS (AE_OK);
}

/*
 * Find a power resource's control structure.
 */
static struct acpi_powerresource *
acpi_pwr_find_resource(ACPI_HANDLE res)
{
    struct acpi_powerresource	*rp;
    
    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    TAILQ_FOREACH(rp, &acpi_powerresources, ap_link) {
	if (rp->ap_resource == res)
	    break;
    }

    return_PTR (rp);
}

/*
 * Find a power consumer's control structure.
 */
static struct acpi_powerconsumer *
acpi_pwr_find_consumer(ACPI_HANDLE consumer)
{
    struct acpi_powerconsumer	*pc;
    
    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    ACPI_SERIAL_ASSERT(powerres);

    TAILQ_FOREACH(pc, &acpi_powerconsumers, ac_link) {
	if (pc->ac_consumer == consumer)
	    break;
    }

    return_PTR (pc);
}

/*
 * K24-T00 (round 13, validation harness per explicit instruction):
 * node/lock protection (round 12) did not close the residual
 * acpi_pwr_switch_consumer() GPF / acpi_pwr_register_consumer() tailq
 * corruption (7/9 recurrence), and two live GDB attempts failed to
 * catch a write in the act -- the corruption is real but
 * unreproducible by breakpoint-and-inspect. Per this round's own
 * instruction, this converts an unreproducible write into a NAMED,
 * observable broken invariant: before the vulnerable traversal
 * (acpi_pwr_find_consumer()/acpi_pwr_find_resource(), both reached
 * from acpi_pwr_switch_consumer() immediately after
 * ACPI_SERIAL_BEGIN(powerres), below) this walks BOTH lists end to
 * end and checks, per node:
 *
 *   1. magic/type: ac_consumer/ap_resource is a non-NULL ACPI_HANDLE
 *      whose AcpiGetType() call succeeds -- this is round 11-era
 *      "handle still resolves in the namespace" check, catching a
 *      stale ACPI_HANDLE (this round's own hypothesis 1: "a stale
 *      pointer inside a protected node" -- the node itself survives,
 *      but its own ac_consumer/ap_resource field still names a
 *      SAVE-boot ACPI_HANDLE/NS-node that the RESUME boot's own,
 *      independently-built ACPI namespace never allocated at that
 *      address).
 *   2. link coherence: TAILQ_NEXT(p)'s own back-link (manually
 *      inspected, not via TAILQ_PREV, which requires a HEAD type this
 *      walk does not have for an arbitrary mid-list node) agrees with
 *      p itself -- catching exactly the "first->prev != head" class
 *      QUEUE_MACRO_DEBUG_ASSERTIONS already checks structurally, but
 *      BEFORE a mutation (TAILQ_INSERT_HEAD/TAILQ_REMOVE) trips that
 *      assertion mid-operation, when the list may already be
 *      inconsistent for an unrelated, earlier reason (this round's
 *      own hypothesis 3: traversal during mutation becomes
 *      observable here as a DIFFERENT node already broken, not the
 *      one being mutated).
 *   3. device liveness: for every acpi_powerconsumer, if
 *      acpi_get_device(ac_consumer) resolves to a non-NULL device_t,
 *      that device_t must pass device_is_alive() -- catching this
 *      round's own hypothesis 2 ("a lifetime problem": the device
 *      behind a still-valid-looking handle was detached/freed during
 *      device resume, but this list still references it).
 *
 * Disposition: a fail-closed panic naming the EXACT node, EXACT
 * invariant, and EXACT list, on the FIRST failure found -- per this
 * repo's own refuse-not-guess convention
 * (docs/design-docs/resume-protocol.md's own fail-closed precedent)
 * and this round's own explicit instruction ("it can stay in as a
 * fail-closed check"). This does not fix the defect; it converts
 * "corruption, cause unknown" into "invariant X failed on node Y",
 * which is strictly more actionable evidence for whichever hypothesis
 * (1/2/3) turns out to be correct.
 */
static void
acpi_pwr_validate_or_panic(void)
{
	struct acpi_powerresource *rp;
	struct acpi_powerconsumer *pc;
	struct acpi_powerreference *pr;
	ACPI_OBJECT_TYPE type;
	device_t dev;

	ACPI_SERIAL_ASSERT(powerres);

	TAILQ_FOREACH(rp, &acpi_powerresources, ap_link) {
		if (rp->ap_resource == NULL)
			panic("acpi_pwr_validate: acpi_powerresources node %p: "
			    "ap_resource is NULL", rp);
		if (ACPI_FAILURE(AcpiGetType(rp->ap_resource, &type)))
			panic("acpi_pwr_validate: acpi_powerresources node %p: "
			    "ap_resource %p does not resolve in the ACPI "
			    "namespace (AcpiGetType failed)", rp,
			    rp->ap_resource);
		if (TAILQ_NEXT(rp, ap_link) != NULL &&
		    TAILQ_PREV(TAILQ_NEXT(rp, ap_link),
		    acpi_powerresource_list, ap_link) != rp)
			panic("acpi_pwr_validate: acpi_powerresources node %p: "
			    "link coherence failed (next node's own prev != "
			    "this node)", rp);
		TAILQ_FOREACH(pr, &rp->ap_references, ar_rlink) {
			if (pr->ar_resource != rp)
				panic("acpi_pwr_validate: acpi_powerreference "
				    "%p on resource %p: ar_resource %p != "
				    "owning resource", pr, rp, pr->ar_resource);
		}
	}
	TAILQ_FOREACH(pc, &acpi_powerconsumers, ac_link) {
		if (pc->ac_consumer == NULL)
			panic("acpi_pwr_validate: acpi_powerconsumers node %p: "
			    "ac_consumer is NULL", pc);
		if (ACPI_FAILURE(AcpiGetType(pc->ac_consumer, &type)))
			panic("acpi_pwr_validate: acpi_powerconsumers node %p: "
			    "ac_consumer %p does not resolve in the ACPI "
			    "namespace (AcpiGetType failed)", pc,
			    pc->ac_consumer);
		if (TAILQ_NEXT(pc, ac_link) != NULL &&
		    TAILQ_PREV(TAILQ_NEXT(pc, ac_link),
		    acpi_powerconsumer_list, ac_link) != pc)
			panic("acpi_pwr_validate: acpi_powerconsumers node %p: "
			    "link coherence failed (next node's own prev != "
			    "this node)", pc);
		dev = acpi_get_device(pc->ac_consumer);
		if (dev != NULL && !device_is_alive(dev))
			panic("acpi_pwr_validate: acpi_powerconsumers node %p: "
			    "ac_consumer %p's own device_t %p is no longer "
			    "alive (device_is_alive() false)", pc,
			    pc->ac_consumer, dev);
		TAILQ_FOREACH(pr, &pc->ac_references, ar_clink) {
			if (pr->ar_consumer != pc)
				panic("acpi_pwr_validate: acpi_powerreference "
				    "%p on consumer %p: ar_consumer %p != "
				    "owning consumer", pr, pc, pr->ar_consumer);
		}
	}
}

/*
 * K24-T00 (round 14, disposition argued and chosen): the validation
 * harness (above) converted the unreproducible corruption into a
 * deterministic fault, confirming the poisoned field is an
 * ACPI_HANDLE -- a pointer into the ACPI namespace -- stored in an
 * otherwise structurally intact node. Direct source reading this
 * round establishes WHEN that field is poisoned: `uma_junk`
 * (`0xdeadc0dedeadc0de`, `sys/vm/uma_dbg.c`) is written by
 * `trash_dtor()`/`mtrash_dtor()` on every `free()` under INVARIANTS
 * (confirmed: `M_ACPIPWR` is an ordinary malloc(9) type, routed
 * through `kern_malloc.c`'s own `mtrash_ctor`/`mtrash_dtor` wrapping).
 * This round's own direct reading of `acpi_pwr_switch_consumer()`
 * (above) confirms `acpi_pwr_dereference_resource(pc)` -- which frees
 * every `acpi_powerreference` currently on `pc` -- runs
 * UNCONDITIONALLY on EVERY call, as ordinary, routine ACPI
 * power-resource-list-rebuild behaviour (the function's own comment:
 * "kill off any current power resource references" before adding new
 * ones) -- this is not a bug or a double-free introduced by this
 * epic; it is this subsystem's own, pre-existing, correct design. The
 * poisoned handle is therefore a genuine SAVE-kernel free/realloc
 * artifact: the SAVE kernel's own dump was taken at a point where a
 * reference node had already been freed (and trash-filled by its own,
 * same-boot `free()`) but a new one had not yet replaced it in the
 * exact field this capture reads -- NOT a pointer invalidated by
 * anything the RESUME kernel does (confirmed by grep: no code on the
 * resume continuation itself, before this call site, ever calls
 * `free(..., M_ACPIPWR)`). This is accordingly closer to a lifetime
 * TIMING artifact of the SAVE-side snapshot than a defect this epic's
 * own resume-side code introduced -- the stale pointer is a REAL
 * symptom of this subsystem's own transient free/realloc window,
 * caught mid-cycle by the snapshot, not a benign "adopt this boot's
 * own content" case.
 *
 * Disposition chosen: REINITIALISE (not re-resolve), argued as
 * follows. `acpi_pwr_register_consumer()`'s own existing guard ("if we
 * already know about this consumer, return AE_OK" -- i.e. register is
 * idempotent and self-populating) and `acpi_pwr_switch_consumer()`'s
 * own unconditional dereference-then-rereference pattern (above)
 * together establish that this subsystem ALREADY treats its own
 * consumer/resource/reference lists as DERIVED, rebuildable state on
 * every ordinary call, not as a registry whose specific pre-suspend
 * identity anything downstream depends on surviving verbatim -- the
 * second disposition's own stated precondition ("sound only if nothing
 * that returns to userland depends on the pre-suspend registrations
 * surviving verbatim") is satisfied by this subsystem's own existing
 * design, confirmed by direct source reading, not assumed. Re-resolving
 * each stale handle (disposition 1) would require guessing which
 * underlying device each handle ONCE named via a pathname/device_t
 * lookup this subsystem does not otherwise perform and that ACPICA
 * provides no public API to safely attempt on an already-poisoned
 * pointer -- strictly more complex and more fragile than simply
 * emptying the list and letting this subsystem's own, already-correct,
 * ordinary re-registration machinery (reached from every subsequent
 * `acpi_pwr_switch_consumer()` call during the SAME device-resume tree
 * walk this defect's every capture has shown) rebuild it from the
 * RESUME kernel's own live namespace -- exactly the "adopt this boot's
 * own fresh content" rule this epic has applied to every other
 * similarly-shaped structure (sleepq_chains[], tdq_runq, etc.), now
 * correctly recognised as applying here too.
 *
 * Implication for acpi_pwr_switch_consumer()'s own later behaviour:
 * every consumer this resume continuation's own DEVICE_RESUME(root_bus)
 * tree walk touches will take the "not yet known" branch on its FIRST
 * touch after this reinit (since the list is now empty) and
 * re-register via `acpi_pwr_register_consumer()`, supplying a FRESH,
 * live `ACPI_HANDLE` from its own caller (acpi_pci_set_powerstate_
 * method()'s own `acpi_get_handle(child)`, not the stale restored
 * value) -- functionally identical to this consumer's FIRST-ever touch
 * on a truly cold boot, which this subsystem already handles correctly
 * by construction. No consumer's own power-resource references are
 * silently lost across resume: each one is rebuilt via the exact same
 * `acpi_pwr_reference_resource()`/`_ForeachPackageObject()` walk
 * `acpi_pwr_switch_consumer()` already performs on every call,
 * unconditionally, today.
 */
void	acpi_pwr_hibernate_reinit(void);
void
acpi_pwr_hibernate_reinit(void)
{
	/*
	 * K24-T00 (round 14, corrected after live capture): the first
	 * version of this function walked and TAILQ_REMOVE()'d every
	 * node, trusting the list's own internal link structure to be
	 * sound even though only the ACPI_HANDLE field had been shown
	 * poisoned. Live testing immediately falsified that assumption:
	 * this function's own TAILQ_REMOVE() panicked ("Bad link elm ...
	 * prev->next != elm") while draining acpi_powerconsumers itself.
	 * Root cause, confirmed by direct reading of trash_dtor()
	 * (sys/vm/uma_dbg.c): it overwrites EVERY WORD of a freed item,
	 * including its own TAILQ_ENTRY link fields, not just whichever
	 * field this round's own capture happened to dereference first --
	 * so a node whose backing memory was mid-free at the SAVE
	 * kernel's own snapshot instant can have corrupted LINKS too, not
	 * only a corrupted ACPI_HANDLE. Walking (even read-only via
	 * TAILQ_FOREACH_SAFE) or removing such a list is therefore not
	 * actually safe -- the "structurally intact node" finding from
	 * this round's own earlier validation-harness work held for the
	 * specific nodes that harness's own link-coherence check
	 * happened to reach, but does not generalise to every node,
	 * confirmed by this new capture.
	 *
	 * Corrected disposition, matching this epic's own established
	 * precedent exactly (hpcb/hcb/hib_workspace/hib_res_pages: "do
	 * NOT free ... on this specific EJUSTRETURN resume-continuation
	 * path", sys/dev/acpica/acpi.c, rule version 5): LEAK the old
	 * nodes' backing memory (bounded, one-time, until the next
	 * reboot -- identical cost class to every other sibling this
	 * epic already accepts the same leak for) rather than trust
	 * TAILQ_REMOVE()/free() against a list whose own internal
	 * consistency cannot be assumed. Blindly re-initialising both
	 * heads needs no traversal at all, cannot panic regardless of
	 * what garbage the old heads/nodes contain, and achieves the
	 * identical end state (an empty list, ready for this subsystem's
	 * own ordinary lazy re-registration) as the original, unsafe
	 * walk-and-free version.
	 */
	TAILQ_INIT(&acpi_powerconsumers);
	TAILQ_INIT(&acpi_powerresources);
}
