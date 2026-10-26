/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org> at Kumacom
 * SARL under sponsorship from the FreeBSD Foundation.
 */

#include <machine/asmacros.h>
#include <machine/specialreg.h>
#include "assym.inc"

	.text

/*
 * int hibernate_savectx(struct hibernate_save_pcb *hpcb, struct pcb *pcb,
 *     uint64_t low_entry, uint64_t low_stack)
 *
 * Saves CPU context using savectx(), fills the hibernate_save_pcb with register
 * state and low transition entry/stack pointers, and returns twice:
 *   - returns 0 on initial save (when savectx returns 1)
 *   - returns EJUSTRETURN on resume (when resumectx returns 0)
 */
ENTRY(hibernate_savectx)
	/*
	 * %rdi = struct hibernate_save_pcb *hpcb
	 * %rsi = struct pcb *pcb
	 * %rdx = uint64_t low_entry (physical address < 4 GiB)
	 * %rcx = uint64_t low_stack (physical address < 4 GiB)
	 */
	pushq	%rdi
	pushq	%rdx
	pushq	%rcx
	movq	%rsi, %rdi
	call	savectx
	popq	%rcx
	popq	%rdx
	popq	%rdi

	testl	%eax, %eax
	jz	.Lhibernate_resumed

	/* Save path: savectx returned 1 */
	movq	%cr0, %rax
	movq	%rax, HPCB_CR0(%rdi)
	movq	%cr3, %rax
	movq	%rax, HPCB_CR3(%rdi)
	movq	%cr4, %rax
	movq	%rax, HPCB_CR4(%rdi)

	movq	%rdx, HPCB_RIP(%rdi)
	movq	%rcx, HPCB_RSP(%rdi)
	movq	%rsi, HPCB_R12(%rdi)

	xorl	%eax, %eax		/* Return 0 to dumpsys_hibernate_savectx */
	ret

.Lhibernate_resumed:
	/* Resume path: resumectx() restored context and returned here with %eax == 0 */
	movl	$EJUSTRETURN, %eax
	ret
END(hibernate_savectx)

/*
 * Low-memory resume trampoline (< 4 GiB).
 *
 * Position-independent code copied to low page (< 4 GiB).
 * Entered from the loader under physical 1:1 identity paging.
 */
ENTRY(hibernate_resume_tramp)
	/* 1. Reload kernel page-table root (safe: low page is 1:1 mapped in kernel_pmap) */
	movq	hibernate_tramp_cr3(%rip), %rax
	movq	%rax, %cr3

	/* 2. Jump to canonical high kernel virtual address */
	movabsq	$hibernate_restore_kernel, %rax
	jmp	*%rax

	ALIGN_DATA
	.globl	hibernate_tramp_cr3
hibernate_tramp_cr3:
	.quad	0
END(hibernate_resume_tramp)

	.globl	hibernate_resume_tramp_size
hibernate_resume_tramp_size:
	.long	. - hibernate_resume_tramp

/*
 * High kernel restore entry.
 *
 * Running in canonical high virtual memory on kernel page tables.
 * %r12 holds struct pcb *.
 */
ENTRY(hibernate_restore_kernel)
	/* Reload kernel GDTR and segment registers before calling resumectx */
	leaq	PCB_GDT(%r12), %rdi
	call	lgdt

	/*
	 * resumectx() (sys/amd64/amd64/cpu_switch.S) unconditionally reloads
	 * %cr3 from PCB_CR3(%rdi) as its very first act, on the ordinary
	 * suspend/resume path where the saved and live kernel are the exact
	 * same running instance and that physical address is still valid.
	 * Across a hibernate image restore the saved PCB's pcb_cr3 is a
	 * save-time physical address of the suspended thread's own PML4,
	 * captured on a prior boot whose physical memory layout need not
	 * match this one: reloading it verbatim can point %cr3 at an
	 * unrelated or incoherent page, losing the kernel-half mappings
	 * every subsequent instruction fetch depends on, with no trap
	 * deliverable because the fault happens before any consistent IDT
	 * is guaranteed under the bogus tree.  Captured and confirmed this
	 * session: with the saved pcb_cr3 reloaded as-is, the very next
	 * kernel-half PML4 entries read back incoherent relative to the
	 * live, correct kernel_pmap tree, and the guest resets with no
	 * trap moments into resumectx().
	 *
	 * %cr3 right here is already the correct, live, resume-boot
	 * kernel_pmap->pm_cr3 (the K-10 trampoline's terminal CR3 load
	 * before the jump into this function): overwrite the saved PCB's
	 * pcb_cr3 with that live value so resumectx()'s own reload is a
	 * safe no-op, exactly mirroring how hibernate_machdep_prepare()
	 * already substitutes the live kernel_pmap->pm_cr3 for
	 * hah_saved_cr3_pa rather than trusting the saved image's own
	 * captured CR3 value.
	 */
	movq	%cr3, %rax
	movq	%rax, PCB_CR3(%r12)

	movq	%r12, %rdi
	call	resumectx
	/* NOTREACHED - resumectx returns directly to .Lhibernate_resumed */
END(hibernate_restore_kernel)

/*
 * int hibernate_call_on_stack(void *stack_top, int (*fn)(void *, void *),
 *     void *arg1, void *arg2)
 *
 * Switches %rsp to stack_top, enforces 16-byte alignment, invokes fn(arg1, arg2),
 * and restores original %rsp.
 */
ENTRY(hibernate_call_on_stack)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12

	movq	%rsp, %r12		/* Preserve thread stack %rsp in %r12 */
	movq	%rdi, %rsp		/* Switch %rsp to scratch stack_top */
	andq	$~0xf, %rsp		/* Enforce 16-byte stack alignment */

	movq	%rsi, %rax		/* Save fn pointer in %rax */
	movq	%rdx, %rdi		/* arg1 -> %rdi */
	movq	%rcx, %rsi		/* arg2 -> %rsi */
	call	*%rax			/* Call worker function */

	movq	%r12, %rsp		/* Restore thread stack %rsp */
	popq	%r12
	popq	%rbp
	ret
END(hibernate_call_on_stack)

	.section .note.GNU-stack,"",%progbits
