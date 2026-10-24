/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * AP hibernate park trampoline.
 *
 * The BSP copies this image to one page below 1 MiB and patches the parameter
 * block at the fixed HPK_* offsets through PHYS_TO_DMAP().  A SIPI enters at
 * hibernate_park_tramp_start in real mode with only %cs established.  The
 * trampoline constructs its physical addresses from %cs, enters 32-bit
 * protected mode with paging disabled, and parks with interrupts disabled.
 *
 * Parameter block ABI (all offsets are from hibernate_park_tramp_start):
 *
 *   HPK_PARK_STATE_PA  uint64_t  physical address of hibernate_park_state
 *   HPK_STACK_TOP_PA   uint64_t  arena park-stack top, below 4 GiB
 *   HPK_HEADER_PA      uint64_t  physical address of the arena header
 *   HPK_SAVED_CR3_PA   uint64_t  saved page-table root, below 4 GiB
 *   HPK_EXPECTED_SEQ   uint32_t  sequence expected on initial arrival
 *   HPK_CPU             uint32_t  logical CPU number passed to C
 *
 * HPK_HEADER_PA supplies the saved CR0, CR4, EFER, PAT, and XCR0 values
 * through the generated HAH_* offsets.  The park-state word itself is the
 * first eight bytes of the header's hah_reserved_0f0 field, but its address
 * remains explicit in this ABI so the polling contract is independent of
 * that containing-object detail.
 *
 * The only external code symbol referenced here is
 * hibernate_resume_ap_entry(), a strong, non-weak, no-return symbol defined
 * in sys/amd64/amd64/hibernate_machdep.c.  An unresolved reference here must
 * be a link error, never a weak zero target.
 */

#include <machine/asmacros.h>
#include <machine/specialreg.h>

#include "assym.inc"

	.set	HPK_PARK_STATE_PA, 0xf00
	.set	HPK_STACK_TOP_PA, 0xf08
	.set	HPK_HEADER_PA, 0xf10
	.set	HPK_SAVED_CR3_PA, 0xf18
	.set	HPK_EXPECTED_SEQ, 0xf20
	.set	HPK_CPU, 0xf24
	.set	HPK_PARAM_END, 0xf28

	.set	HPK_STATE_SEQUENCE, 0
	.set	HPK_STATE_STATE, 4

	.set	HPK_PARK_WAITING, 0
	.set	HPK_PARK_READY, 1
	.set	HPK_PARK_RELEASE, 2

	.set	HPK_SEL_CODE32, hpk_code32-hpk_gdt
	.set	HPK_SEL_DATA32, hpk_data32-hpk_gdt
	.set	HPK_SEL_CODE64, hpk_code64-hpk_gdt

	.globl	HPK_PARK_STATE_PA
	.globl	HPK_STACK_TOP_PA
	.globl	HPK_HEADER_PA
	.globl	HPK_SAVED_CR3_PA
	.globl	HPK_EXPECTED_SEQ
	.globl	HPK_CPU
	.globl	HPK_PARAM_END

	.data
	.p2align 12, 0
	.globl	hibernate_park_tramp_start
	.type	hibernate_park_tramp_start,@object
hibernate_park_tramp_start:
	.code16
	cli
	mov	%cs, %ax
	mov	%ax, %ds
	mov	%ax, %ss

	/*
	 * %ebx is the physical relocation base.  Patch only the copied image:
	 * no link-time absolute address is consumed by the real-mode entry.
	 */
	xorl	%ebx, %ebx
	mov	%cs, %bx
	sall	$4, %ebx
	movl	%ebx, %eax
	addl	$(hpk_gdt-hibernate_park_tramp_start), %eax
	movl	%eax, hpk_gdtr-hibernate_park_tramp_start+2
	movl	%ebx, %eax
	addl	$(hpk_protected-hibernate_park_tramp_start), %eax
	movl	%eax, hpk_jump32-hibernate_park_tramp_start+2
	movl	%ebx, %eax
	addl	$(hpk_long-hibernate_park_tramp_start), %eax
	movl	%eax, hpk_jump64-hibernate_park_tramp_start+1

	/*
	 * Patch the one-entry-safe protected-mode IDT's base address and its
	 * sole present gate's (vector 2, NMI) target offset.  See the
	 * hpk_idt/hpk_idtr definitions below and the lidt in hpk_protected.
	 */
	movl	%ebx, %eax
	addl	$(hpk_idt-hibernate_park_tramp_start), %eax
	movl	%eax, hpk_idtr-hibernate_park_tramp_start+2
	movl	%ebx, %eax
	addl	$(.Lhpk_nmi_halt-hibernate_park_tramp_start), %eax
	movw	%ax, hpk_idt_nmi_off_lo-hibernate_park_tramp_start
	shrl	$16, %eax
	movw	%ax, hpk_idt_nmi_off_hi-hibernate_park_tramp_start

	lgdt	hpk_gdtr-hibernate_park_tramp_start
	movl	%cr0, %eax
	orl	$CR0_PE, %eax
	movl	%eax, %cr0

hpk_jump32:
	.byte	0x66
	.byte	0xea
	.long	0
	.word	HPK_SEL_CODE32

	.code32
hpk_protected:
	movl	$HPK_SEL_DATA32, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss

	/* The arena stack and park-state object are physically addressable. */
	movl	HPK_STACK_TOP_PA(%ebx), %esp
	movl	HPK_PARK_STATE_PA(%ebx), %edi
	movl	HPK_EXPECTED_SEQ(%ebx), %esi

	/*
	 * Publish READY once, and only while the arrival sequence is still the
	 * BSP-patched expected value.  Any stale/mismatched dispatch parks
	 * forever with interrupts disabled.
	 */
	cmpl	%esi, HPK_STATE_SEQUENCE(%edi)
	jne	.Lhpk_bad_sequence
	movl	$HPK_PARK_READY, HPK_STATE_STATE(%edi)

	/*
	 * Close the NMI window (K23-T06 arbitration verdict, "Ordered
	 * changes required" item 7): from SIPI until this lidt, IDTR holds
	 * its post-INIT reset value, so any NMI delivered during the park
	 * poll below -- which spans the whole K-10 destructive copy --
	 * would triple-fault this AP; cli does not mask NMIs.  Load the
	 * one-entry-safe IDT below: every vector below 2 is left absent
	 * (not expected to fire -- interrupts are masked and no fault-
	 * generating instruction executes in the poll loop), and vector 2
	 * (NMI) targets a halt loop inside this stub page rather than
	 * faulting through the stale real-mode IVT.
	 */
	lidt	hpk_idtr-hibernate_park_tramp_start(%ebx)

	/* RELEASE is valid only with the next monotonic sequence value. */
	leal	1(%esi), %edx
.Lhpk_poll:
	pause
	cmpl	%edx, HPK_STATE_SEQUENCE(%edi)
	jne	.Lhpk_poll
	cmpl	$HPK_PARK_RELEASE, HPK_STATE_STATE(%edi)
	jne	.Lhpk_poll

	/*
	 * Restore the saved architectural control state while constructing the
	 * protected-to-long-mode transition.  CR4 precedes XCR0, EFER.LME and
	 * CR0.PG are explicitly guaranteed, and CR0 remains the final control
	 * register write.  CR4.PCIDE and CR4.CET are masked out of this 32-bit
	 * write because both require IA-32e mode (EFER.LMA) or CR0.WP already
	 * set, neither of which holds yet; the full, unmasked CR4 -- minus
	 * CR4_FRED, which stays off until the C entry configures FRED -- is
	 * restored again in 64-bit mode below, after EFER.LMA and CR0.WP are
	 * both legitimately set.  EFER.LMA is processor-controlled and is
	 * masked out of the saved value before OR'ing in EFER.LME, matching
	 * the live read-modify-write convention mpboot.S uses.  CR3's low
	 * 12 bits are cleared because the saved value carries only the PML4
	 * physical frame.
	 */
	movl	HPK_HEADER_PA(%ebx), %esi

	movl	HAH_SAVED_PAT(%esi), %eax
	movl	HAH_SAVED_PAT+4(%esi), %edx
	movl	$MSR_PAT, %ecx
	wrmsr

	movl	HAH_SAVED_CR4(%esi), %eax
	andl	$~(CR4_PCIDE | CR4_CET), %eax
	orl	$CR4_PAE, %eax
	movl	%eax, %cr4

	movl	HAH_SAVED_XCR0(%esi), %eax
	movl	HAH_SAVED_XCR0+4(%esi), %edx
	xorl	%ecx, %ecx
	xsetbv

	movl	HAH_SAVED_EFER(%esi), %eax
	movl	HAH_SAVED_EFER+4(%esi), %edx
	andl	$~EFER_LMA, %eax
	orl	$EFER_LME, %eax
	movl	$MSR_EFER, %ecx
	wrmsr

	movl	HPK_SAVED_CR3_PA(%ebx), %eax
	andl	$~0xfff, %eax
	movl	%eax, %cr3

	movl	HAH_SAVED_CR0(%esi), %eax
	orl	$(CR0_PE | CR0_PG), %eax
	movl	%eax, %cr0

hpk_jump64:
	.byte	0xea
	.long	0
	.word	HPK_SEL_CODE64

.Lhpk_bad_sequence:
	pause
	jmp	.Lhpk_bad_sequence

	/*
	 * Landing pad for the NMI gate below.  Reached only if an NMI is
	 * delivered during the park poll despite the documented no-NMI-to-
	 * parked-AP constraint; halts rather than triple-faulting through
	 * the stale real-mode IVT, matching the project's terminal
	 * halt/reset semantics for an unrecoverable condition.  Never
	 * returns -- does not iret back into the poll loop.
	 */
.Lhpk_nmi_halt:
	cli
.Lhpk_nmi_halt_loop:
	hlt
	jmp	.Lhpk_nmi_halt_loop

	.code64
hpk_long:
	/*
	 * GPR bits 63:32 are architecturally undefined across the
	 * compatibility-to-64-bit-mode transition.  %rbx is the sole such
	 * value 64-bit code still depends on; zero-extend it before any
	 * other instruction uses it.
	 */
	movl	%ebx, %ebx

	movl	$HPK_SEL_DATA32, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss

	/*
	 * Restore the full-width saved CR4, less CR4_FRED (bit 32; FRED
	 * stays off until the C entry configures it).  EFER.LMA and CR0.WP
	 * are both legitimately set now, so CR4.PCIDE and CR4.CET -- masked
	 * out of the earlier 32-bit write above -- may be written here.  The
	 * header is re-read through HPK_HEADER_PA(%rbx) rather than reusing
	 * %esi/%rsi from 32-bit code, whose upper bits are equally
	 * undefined across the transition.
	 */
	movl	HPK_HEADER_PA(%rbx), %esi
	movq	HAH_SAVED_CR4(%rsi), %rax
	btrq	$32, %rax
	movq	%rax, %cr4

	/* Re-establish the full-width stack and satisfy the amd64 call ABI. */
	movq	HPK_STACK_TOP_PA(%rbx), %rsp
	andq	$~0xf, %rsp
	movl	HPK_CPU(%rbx), %edi
	movabsq	$hibernate_resume_ap_entry, %rax
	call	*%rax

	/* The C entry is a no-return scheduler handoff. */
	cli
.Lhpk_returned:
	pause
	jmp	.Lhpk_returned

	.p2align 3, 0
hpk_gdt:
	.quad	0x0000000000000000
hpk_code32:
	.quad	0x00cf9b000000ffff
hpk_data32:
	.quad	0x00cf93000000ffff
hpk_code64:
	.quad	0x00209b0000000000
hpk_gdt_end:

hpk_gdtr:
	.word	hpk_gdt_end-hpk_gdt-1
	.long	0

	/*
	 * One-entry-safe protected-mode IDT (K23-T06 arbitration verdict item
	 * 7): vectors 0 and 1 are absent (not expected to fire -- interrupts
	 * are masked throughout and no fault-generating instruction executes
	 * in the poll loop); vector 2 (NMI, which cli cannot mask) is the
	 * sole present gate, a 32-bit interrupt gate targeting
	 * .Lhpk_nmi_halt.  hpk_idt_nmi_off_lo/_hi are patched with the
	 * linear target address at real-mode entry, above.
	 */
	.p2align 3, 0
hpk_idt:
	.space	16, 0
hpk_idt_nmi_off_lo:
	.word	0
	.word	HPK_SEL_CODE32
	.byte	0
	.byte	0x8e
hpk_idt_nmi_off_hi:
	.word	0
hpk_idt_end:

hpk_idtr:
	.word	hpk_idt_end-hpk_idt-1
	.long	0

	/*
	 * Keep code and descriptors clear of the fixed parameter block.  The
	 * .org assertion fails assembly if the trampoline grows into its ABI.
	 */
	.org	HPK_PARK_STATE_PA, 0
hibernate_park_tramp_params:
	.quad	0
	.quad	0
	.quad	0
	.quad	0
	.long	0
	.long	0
hibernate_park_tramp_end:
	.size	hibernate_park_tramp_start, .-hibernate_park_tramp_start

	.globl	hibernate_park_tramp_end
	.globl	hibernate_park_tramp_size
	.type	hibernate_park_tramp_size,@object
hibernate_park_tramp_size:
	.long	hibernate_park_tramp_end-hibernate_park_tramp_start
	.size	hibernate_park_tramp_size, 4

	.section .note.GNU-stack,"",%progbits
