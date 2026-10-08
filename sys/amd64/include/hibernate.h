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

struct pcb;

#define	HIBERNATE_SCRATCH_STACK_SIZE	(32 * 1024)

int dumpsys_hibernate_savectx(struct hibernate_save_pcb *hpcb, void *stack_top,
    int (*dump_fn)(void *, void *), void *dump_arg) __returns_twice;
int hibernate_savectx(struct hibernate_save_pcb *hpcb, struct pcb *pcb,
    uint64_t low_entry, uint64_t low_stack) __returns_twice;
int hibernate_call_on_stack(void *stack_top, int (*fn)(void *, void *),
    void *arg1, void *arg2);
void hibernate_resume_tramp(void);
extern uint32_t hibernate_resume_tramp_size;
extern uint64_t hibernate_tramp_cr3;

#endif


#endif /* _MACHINE_HIBERNATE_H */
