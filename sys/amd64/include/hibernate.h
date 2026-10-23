/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>, and
 * Olivier Certner <olce@FreeBSD.org> at Kumacom SARL, under sponsorship from
 * the FreeBSD Foundation.
 */

#ifndef _MACHINE_HIBERNATE_H
#define _MACHINE_HIBERNATE_H

#include <sys/types.h>
#include <sys/_null.h>
#include <sys/_stdint.h>
#include <sys/cdefs.h>
#include <sys/hibernate.h>

/*
 * Native save-side state retained during the transition to the canonical
 * machine-independent hibernate image format.
 */
struct hibernate_save_cb {
	uint64_t hc_version;	/* Version number. */
	/* ACPI FACS signature in the lower 32 bits. 0 if not filled. */
	uint64_t hc_hardware_signature;
	/* Spare contiguous physical pages. */
	uint64_t hc_contig_spare_start;
	uint64_t hc_contig_spare_size;
	/* Spare non-contiguous physical pages. */
	uint64_t hc_spare_pages_nb;
	uint64_t hc_spare_pages[];
};

/*
 * Native amd64 context consumed by hibernate_switch.S.
 */
struct hibernate_save_pcb {
	uint64_t cr0;
	uint64_t cr3;		/* Kernel page table root. */
	uint64_t cr4;
	uint64_t rsp;		/* Stack for the entry point */
	uint64_t rip;		/* Entry point. */
	uint64_t r12;		/* Parameter for the entry point. */
};

static inline size_t __pure
hcb_size_spec(const uint64_t spare_pages_nb)
{
	return (offsetof(struct hibernate_save_cb, hc_spare_pages) +
	    spare_pages_nb *
	    sizeof(*((struct hibernate_save_cb *)NULL)->hc_spare_pages));
}

static inline size_t __pure
hcb_size(const struct hibernate_save_cb *hcb)
{
	return (hcb_size_spec(hcb->hc_spare_pages_nb));
}

#ifdef _KERNEL

/*
 * ABI 1 amd64 XSAVE policy and the terminal descriptor consumed by K-10.
 * Construction and publication of this validated tuple belong to K-7.
 */
#define HIBERNATE_AMD64_XSAVE_FORMAT_STANDARD	HIBERNATE_XSAVE_FORMAT
#define HIBERNATE_AMD64_XCR0_SUPPORTED_MASK	HIBERNATE_XCR0_SUPPORTED_MASK
#define HIBERNATE_AMD64_XSAVE_MIN_LENGTH	576U
#define HIBERNATE_AMD64_XSAVE_ALIGNMENT		64U

struct hibernate_xsave_terminal {
	const void *hxt_staged_address;
	uint64_t hxt_length;
	uint64_t hxt_enabled_mask;
	uint32_t hxt_format;
};

struct pcb;

#define	HIBERNATE_SCRATCH_STACK_SIZE	(32 * 1024)

/*
 * dumpsys_hibernate_savectx_preinit: one-time machine-dependent setup
 * (the low-page contigmalloc and identity mapping) that must run BEFORE
 * the K-5 FREE-page reservation drains vm_phys.  dumpsys_hibernate_savectx()
 * panics if preinit was not called, so every caller must preinit first;
 * acpi_EnterSleepState() does so before the stability barrier.
 */
int dumpsys_hibernate_savectx_preinit(void);
int dumpsys_hibernate_savectx(struct hibernate_save_pcb *hpcb, void *stack_top,
    int (*dump_fn)(void *, void *), void *dump_arg) __returns_twice;
int hibernate_savectx(struct hibernate_save_pcb *hpcb, struct pcb *pcb,
    uint64_t low_entry, uint64_t low_stack) __returns_twice;
int hibernate_call_on_stack(void *stack_top, int (*fn)(void *, void *),
    void *arg1, void *arg2);
void hibernate_resume_tramp(void);
extern uint32_t hibernate_resume_tramp_size;
extern uint64_t hibernate_tramp_cr3;

/*
 * K-10 arena-resident transition object (sys/amd64/amd64/hibernate_tramp.S).
 * hibernate_machdep_prepare() sizes its arena copy from
 * [hibernate_tramp_entry, hibernate_tramp_end) and derives the arena offsets
 * of the two interior pages from these labels, so the copy geometry is bound
 * to the real linked object rather than assumed.
 */
void hibernate_tramp_entry(void) __dead2;
extern char hibernate_tramp_end[];
extern char hibernate_tramp_both_domain_page[];
extern char hibernate_tramp_saved_domain_stub[];

/*
 * K-23 AP park stub (sys/amd64/amd64/hibernate_park_tramp.S).
 * hibernate_machdep_prepare() copies [hibernate_park_tramp_start,
 * hibernate_park_tramp_end) into the claimed below-1-MiB park-stub page
 * (ha_park_stub_pa) and patches the fixed HIBERNATE_PARK_TRAMP_PARAM_*
 * parameter block below at its documented offsets.
 */
extern char hibernate_park_tramp_start[];
extern char hibernate_park_tramp_end[];
extern uint32_t hibernate_park_tramp_size;

/*
 * K-23 AP park-stub parameter-block ABI.  hibernate_park_tramp.S documents
 * and .set-defines these identical offsets (relative to
 * hibernate_park_tramp_start); keep both definitions in sync.
 */
#define	HIBERNATE_PARK_TRAMP_PARAM_STATE_PA		0xf00
#define	HIBERNATE_PARK_TRAMP_PARAM_STACK_TOP_PA	0xf08
#define	HIBERNATE_PARK_TRAMP_PARAM_HEADER_PA		0xf10
#define	HIBERNATE_PARK_TRAMP_PARAM_SAVED_CR3_PA	0xf18
#define	HIBERNATE_PARK_TRAMP_PARAM_EXPECTED_SEQ	0xf20
#define	HIBERNATE_PARK_TRAMP_PARAM_CPU			0xf24
#define	HIBERNATE_PARK_TRAMP_PARAM_END			0xf28

/*
 * hibernate_resume_ap_entry: the park stub's post-release C entry (K23-T08).
 * Establishes exactly the fields the K23-T00 precondition audit marks
 * "must be established" (saved CR3 already loaded by the caller; GDTR,
 * IDTR, FSBASE/GSBASE/KGSBASE, TR, and pc_curthread = pc_idlethread), then
 * transfers to the existing, already-safe sched_ap_entry() tail of AP
 * bring-up.  Never returns.
 */
void hibernate_resume_ap_entry(u_int cpu) __dead2;

/*
 * K-6: live amd64 XSAVE fact collection and canonical PCB population.
 *
 * hibernate_amd64_xsave_collect() validates the live XCR0 against
 * HIBERNATE_XCR0_SUPPORTED_MASK (fail closed on any unsupported or
 * inconsistent bit), derives the exact standard-format extent via
 * hibernate_xsave_extent() fed by live CPUID leaf 0xD facts, and captures
 * the complete non-compacted XSAVE image into the caller's 64-byte-aligned
 * preallocated buffer.  No allocation occurs; buf/buf_capacity must already
 * satisfy the derived extent.  Returns 0 on success with *out populated
 * (hxt_staged_address == buf, hxt_length == derived extent, hxt_enabled_mask
 * == live XCR0, hxt_format == HIBERNATE_XSAVE_FORMAT), EINVAL on
 * unsupported/inconsistent XCR0 or a misaligned/undersized buffer, or the
 * error propagated from hibernate_xsave_extent().
 */
int hibernate_amd64_xsave_collect(void *buf, size_t buf_capacity,
    struct hibernate_xsave_terminal *out);

/*
 * hibernate_amd64_pcb_populate: populate every host-order canonical PCB
 * field from the saved machine context (hpcb), the live control/MSR/
 * descriptor-table state, and the already-captured XSAVE terminal
 * descriptor (xt).  Does not encode; the caller passes *pcb to
 * hibernate_pcb_encode().  Returns 0 on success, EINVAL on a null
 * argument or an xt that fails hibernate_pcb_encode()'s own checks.
 */
int hibernate_amd64_pcb_populate(const struct hibernate_save_pcb *hpcb,
    const struct hibernate_xsave_terminal *xt, struct hibernate_pcb *pcb);
int hibernate_amd64_cpu_validate(const struct hibernate_pcb *pcb,
    bool *refuse_la57, bool *refuse_mtrr);

#endif


#endif /* _MACHINE_HIBERNATE_H */
