/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * hibernate_tramp_entry: the K-10 no-return RESTORE transition (issue #12,
 * Design 036 SS5.4-5.6).  Called exactly once, from hibernate_machdep_enter()
 * in hibernate_machdep.c, with %rdi holding the identity (PA == VA; the
 * entire arena is guaranteed below 4 GiB per HIBERNATE_ARENA_PHYS_LIMIT)
 * address of the fully-prepared, fully-validated "struct
 * hibernate_arena_header" (sys/sys/hibernate.h), and %rsi holding the
 * separately staged, 64-byte-aligned XSAVE identity address.  Prepare proves
 * that the XSAVE extent exactly matches the saved image and that its private-
 * domain identity mapping is writable and non-executable.  This internal
 * register ABI leaves the normative 256-byte arena header unchanged.  Every
 * fact this file
 * consumes was already computed and offline-validated by
 * hibernate_machdep_prepare() (design S5.3, S5.7); this file performs no
 * validation, no allocation, and has no recoverable failure path of its
 * own -- any inconsistency here is a PREPARE-side bug, not something this
 * file can safely detect.  Any failure past this point is terminal
 * halt/reset, per the issue's normative contract.
 *
 * Physical layout (matches design S5.6 / plan task-5 exactly):
 *
 *   1. Switch %rsp to the arena stack (HAH_ARENA_STACK_PA + _SIZE).  %rsp
 *      is never set to any saved-kernel stack value anywhere in this file;
 *      resumectx() (called from hibernate_restore_kernel, downstream of
 *      step 12 below) owns that restore.
 *   2. Load private CR3 (the FIRST CR3 load -- switches INTO the
 *      arena-private domain so the destructive copy loop can run).  This
 *      is distinct from terminal step 2 below, the SECOND and final CR3
 *      load.
 *   3. Run the destructive copy loop (design S5.4).  RESTORE begins at the
 *      first write below.  Walks the coalesced destination run table
 *      (HAH_ITERATOR_PA, flat {dest_pa, page_count} entries,
 *      HACR_ENTRY_SIZE bytes apart -- matching
 *      HIBERNATE_ARENA_COPY_RUN_BYTES in sys/sys/hibernate.h) and the
 *      parallel per-page source-PA vector (HAH_SOURCE_VECTOR_PA), copying
 *      exactly HAH_DESTINATION_PAGE_COUNT total 4 KiB pages.  Both tables
 *      are read exactly as built by task-6/task-7; no independent
 *      re-derivation of either is performed here.  Destination pages
 *      within one run are contiguous by construction (a "coalesced run"),
 *      so the destination pointer is loaded from the run's dest_pa only
 *      once per run and left to auto-advance across pages within that run
 *      via "rep movsq"'s own side effect; the source pointer is not
 *      assumed contiguous and is re-read from the source vector every
 *      page.  The staged XSAVE identity address arrives separately in
 *      %rsi and is preserved in %r9 while the copy loop uses %rsi.
 *   4. Restore %rsi from %r9 and XRSTOR64 directly from the validated staged
 *      XSAVE object.  It is never inferred from a destination run.  Issued
 *      with
 *      an all-ones request mask: XRSTOR only ever restores components the
 *      area's own XSTATE_BV marks present, so requesting everything is
 *      always safe, and this runs before CR4/XCR0 are overwritten below,
 *      i.e. under whatever CR4.OSXSAVE/XCR0 the running kernel-hib kernel's
 *      own ordinary boot already established -- sufficient for XRSTOR64 to
 *      execute without #UD/#GP.
 *   5. [Terminal step 1] Restore EFER, PAT, CR4, XCR0, and CR0, in that
 *      order, from HAH_SAVED_{EFER,PAT,CR4,XCR0,CR0}, using only
 *      arena-owned data.  CR4 is restored before XCR0 because XSETBV
 *      traps with #UD unless CR4.OSXSAVE is already set; CR0 is restored
 *      last so every other piece of control/MSR state is already
 *      consistent before the most fundamental (paging/cache) register
 *      changes take effect.  GDTR/IDTR are deliberately NOT reloaded here:
 *      HAH_GDTR/HAH_IDTR exist solely for hibernate_machdep_prepare()'s own
 *      offline validation (design S5.3 point 2); the actual reload happens
 *      downstream inside the existing hibernate_restore_kernel
 *      (hibernate_switch.S), which already does "leaq PCB_GDT(%r12),%rdi;
 *      call lgdt" followed by resumectx(%r12) against the real "struct
 *      pcb" this file hands it in %r12 (step 11).  Duplicating that reload
 *      here would read a second, PREPARE-time-only snapshot instead of the
 *      one authoritative copy resumectx() itself owns, so it is omitted.
 *   6. Preload every register-resident constant needed after the saved-CR3
 *      switch.  Deferred to this point (rather than before the copy loop)
 *      purely to avoid register pressure during the loop; the header
 *      remains validly reachable through %rbp for the entire private-CR3
 *      phase, so there is no correctness requirement to preload earlier.
 *      As the design's own pseudocode note states, the implementation is
 *      free to choose any register allocation satisfying "every value is
 *      register-resident before the both-domain page is entered."
 *      HAH_HANDOFF_LENGTH is loaded with a 32-bit zero-extending "movl"
 *      into %ebx (not a 64-bit "movq" into %rbx): the C field is
 *      "uint32_t hah_handoff_length", and the very next header field,
 *      HAH_INSTRUCTION_PAGE_PA (a uint64_t), begins at the next 8-byte
 *      slot with no padding in between.  A 64-bit load at
 *      HAH_HANDOFF_LENGTH's offset would therefore also pull in
 *      HAH_INSTRUCTION_PAGE_PA's low 4 bytes as %rbx's high dword,
 *      corrupting the byte count step 10's "rep movsb" uses.
 *   7. jmp (never call) to the page-aligned both-domain stub.  Every value
 *      the stub and everything after it need is already register-resident;
 *      nothing past this point ever dereferences HAH_* through %rbp again.
 *
 *   hibernate_tramp_both_domain_page (.align 4096, its own physical page):
 *   8. [Terminal step 2] Load saved CR3 (the SECOND, final CR3 load).
 *   9. [Terminal step 3] jmp *%r9 (trampoline_saved_va) -- the very next
 *      instruction fetched after the CR3 load, from the identical physical
 *      bytes mapped at both the private identity VA (where execution is
 *      still running at the instant of the CR3 load) and at
 *      trampoline_saved_va (where control lands immediately after).
 *      Between the "movq %r8, %cr3" and this jmp there is no stack access,
 *      no data access, no PC-relative operand, and nothing reachable
 *      outside this one physical page.
 *
 *   hibernate_tramp_saved_domain_stub (entered at trampoline_saved_va):
 *  10. [Terminal step 4] Copy the complete scalar handoff record by value,
 *      byte for byte, from arena storage (HAH_HANDOFF_RECORD_PA, %r11) to
 *      the fixed link-time VA hibernate_saved_handoff (HAH_SAVED_HANDOFF_VA,
 *      %r13), for exactly HAH_HANDOFF_LENGTH (%ebx, zero-extended into
 *      %rbx; see step 6) bytes.  Ordinary memory access is explicitly
 *      permitted from this point on (design S5.5): the both-domain
 *      instruction invariant applies only to steps 8-9 above.
 *  11. [Terminal step 5] %r12 = HAH_SAVED_PCB_VA (already carried in %r14):
 *      the real "struct pcb *" hibernate_restore_kernel expects.
 *  12. [Terminal step 6] jmp (never call) *%rax, loaded immediately
 *      beforehand from HAH_RESTORE_KERNEL_VA (%r15) -- the one and only
 *      permitted external jump target, with no intervening shim.  %rax is
 *      pure jump scratch, dead at that destination.
 *
 * Register discipline:
 *
 *   %rbp -- the arena header pointer (set once at entry from the incoming
 *           %rdi; never repurposed).  Every HAH_* access in steps 1-6 is
 *           header(%rbp).  Never read again from step 7 onward.
 *   %r8  -- HAH_SAVED_CR3_PA        (preloaded step 6; consumed step 8)
 *   %r9  -- validated staged XSAVE identity address during steps 3-4;
 *           overwritten with HAH_TRAMPOLINE_SAVED_VA at step 6 (consumed
 *           step 9).  The two uses never overlap in time.
 *   %r11 -- HAH_HANDOFF_RECORD_PA   (preloaded step 6; consumed step 10)
 *   %r13 -- HAH_SAVED_HANDOFF_VA    (preloaded step 6; consumed step 10)
 *   %r14 -- HAH_SAVED_PCB_VA        (preloaded step 6; consumed step 11)
 *   %r15 -- HAH_RESTORE_KERNEL_VA   (preloaded step 6; consumed step 12)
 *   %rbx -- HAH_HANDOFF_LENGTH      (preloaded step 6 via a 32-bit
 *           zero-extending "movl" into %ebx, not "movq"; consumed step 10)
 *
 *   %rax, %rcx, %rdx, %rsi, %rdi, %r10, %r12 -- free scratch during the
 *           private-CR3 phase (steps 1-6); %rdi/%rsi/%rcx/%rdx/%r10/%r12
 *           additionally carry the copy loop's destination cursor, source
 *           PA, per-page qword count, per-run remaining-page count, source
 *           cursor, and live total remaining-page count (step 3).  None of
 *           these seven registers holds anything live across the jmp at
 *           step 7, so the live-register contract at hibernate_restore_kernel
 *           entry ("%rdi, %rsi, %rdx, %rcx, %r8, %r9, %r10, %r11, %r13,
 *           %r14, %r15 are dead/unspecified") is satisfied: every one of
 *           them is either pure step 1-6 scratch or has already been
 *           consumed by the time step 12's jmp executes.  %r12 is
 *           deliberately reused one final time at step 11 to become the
 *           live saved-PCB pointer, matching the contract's "%r12 = saved
 *           struct pcb *" requirement exactly.
 *
 * No "ret"/"retq" appears anywhere in this file; every control transfer
 * past entry is an unconditional "jmp" (direct or register-indirect) or an
 * intra-loop conditional branch that always eventually reaches one of the
 * two terminal jmp instructions.  No C executes from the first destructive
 * write (the start of the copy loop, step 3) onward.  The only symbol this
 * file jumps to outside itself is "hibernate_restore_kernel"; the only data
 * symbol it touches outside the arena-owned header is the fixed link-time
 * VA "hibernate_saved_handoff".
 */

#include <machine/asmacros.h>
#include <machine/specialreg.h>

#include "assym.inc"

/*
 * Local layout constants for one coalesced destination-run-table entry
 * (design S5.4: "{dest_pa, page_count}" pairs).  Not struct-offset ASSYM()
 * values because the run table has no C struct type -- it is a flat,
 * fixed-stride array built directly by hibernate_machdep_prepare().  The
 * stride tracks HIBERNATE_ARENA_COPY_RUN_BYTES in sys/sys/hibernate.h
 * (currently 32); the two 8-byte fields below account for the first 16 of
 * those bytes, the remainder being canary/reserved padding this file never
 * reads.
 */
	.set	HACR_DEST_PA, 0
	.set	HACR_PAGE_COUNT, 8
	.set	HACR_ENTRY_SIZE, 32

/* One 4 KiB page expressed as a qword count, for the per-page "rep movsq". */
	.set	HIBERNATE_TRAMP_PAGE_QWORDS, 512

	.text

ENTRY(hibernate_tramp_entry)
	/*
	 * %rdi = const struct hibernate_arena_header * (identity VA == PA).
	 * %rsi = validated staged XSAVE identity address.  Preserve it in
	 * %r9 while the destructive copy loop uses %rsi as source scratch.
	 * Dedicate %rbp to the header pointer for the whole private-CR3
	 * phase; never repurposed, never read again past step 7.
	 */
	movq	%rdi, %rbp
	movq	%rsi, %r9

	/*
	 * Step 1: switch onto the arena stack.  Nothing on the incoming
	 * C/thread stack is referenced again after this point.
	 */
	movq	HAH_ARENA_STACK_PA(%rbp), %rsp
	addq	HAH_ARENA_STACK_SIZE(%rbp), %rsp

	/*
	 * Step 2: load private CR3.  This is the FIRST CR3 load (switches
	 * INTO the arena-private domain); terminal step 2 below performs the
	 * SECOND, saved-domain CR3 load.
	 */
	movq	HAH_PRIVATE_CR3_PA(%rbp), %rax
	movq	%rax, %cr3

	/*
	 * Step 3: destructive copy loop (design S5.4).  RESTORE begins at the
	 * first write below.
	 *
	 *	%rax = run-table cursor (next run-table entry to read)
	 *	%r9  = validated staged XSAVE identity address (preserved from
	 *	       entry and not touched until step 4 consumes it)
	 *	%r10 = source-vector cursor (next source-PA entry to read)
	 *	%r12 = total pages remaining across all runs
	 *	%rdi = current destination PA (reloaded per run; auto-advances
	 *	       across pages within a run via "rep movsq")
	 *	%rdx = pages remaining in the current run
	 *	%rsi = current source PA (reloaded every page)
	 *	%rcx = per-page qword count for "rep movsq" (reloaded every
	 *	       page, since "rep" always leaves it at zero)
	 */
	movq	HAH_ITERATOR_PA(%rbp), %rax
	movq	HAH_SOURCE_VECTOR_PA(%rbp), %r10
	movq	HAH_DESTINATION_PAGE_COUNT(%rbp), %r12
	testq	%r12, %r12
	jz	.Lhibernate_tramp_copy_done

.Lhibernate_tramp_run_loop:
	movq	HACR_DEST_PA(%rax), %rdi
	movq	HACR_PAGE_COUNT(%rax), %rdx
	addq	$HACR_ENTRY_SIZE, %rax

.Lhibernate_tramp_page_loop:
	movq	(%r10), %rsi
	addq	$8, %r10
	movl	$HIBERNATE_TRAMP_PAGE_QWORDS, %ecx
	rep	movsq
	decq	%r12
	decq	%rdx
	jnz	.Lhibernate_tramp_page_loop
	testq	%r12, %r12
	jnz	.Lhibernate_tramp_run_loop

.Lhibernate_tramp_copy_done:
	/*
	 * Step 4: XRSTOR64 the separately staged, prepare-validated XSAVE
	 * object.  Restore its internal-ABI address to %rsi after the copy loop
	 * has finished using that register.  All-ones request mask: XRSTOR only
	 * restores components the area's own XSTATE_BV marks present.
	 */
	movq	%r9, %rsi
	movl	$0xffffffff, %eax
	movl	$0xffffffff, %edx
	xrstor64	(%rsi)

	/*
	 * Step 5 / terminal step 1: preserve the validated control state.
	 *
	 * hibernate_amd64_cpu_validate() has already proved, under CPUID
	 * feature gates and architecturally writable masks, that the live
	 * CR0, CR4, EFER, PAT, and XCR0 values equal the saved-compatible
	 * values carried in the header.  The terminal sequence therefore
	 * changes only CR3: rewriting these registers here would be a no-op
	 * in value while adding #GP fault points inside the no-return
	 * region, where any fault is a terminal halt/reset.
	 */

	/*
	 * Step 6: preload every constant needed after the saved-CR3 switch.
	 * %r9 is reused here (its step 3-4 value is fully consumed by now).
	 */
	movq	HAH_SAVED_CR3_PA(%rbp), %r8
	movq	HAH_TRAMPOLINE_SAVED_VA(%rbp), %r9
	movq	HAH_HANDOFF_RECORD_PA(%rbp), %r11
	movq	HAH_SAVED_HANDOFF_VA(%rbp), %r13
	movq	HAH_SAVED_PCB_VA(%rbp), %r14
	movq	HAH_RESTORE_KERNEL_VA(%rbp), %r15
	movl	HAH_HANDOFF_LENGTH(%rbp), %ebx

	/*
	 * Step 7: enter the one-page both-domain stub.  Past this point
	 * %rbp (the header pointer) is never dereferenced again.
	 */
	jmp	hibernate_tramp_both_domain_page

	ALIGN_DATA
	.align	4096
	.globl	hibernate_tramp_both_domain_page
hibernate_tramp_both_domain_page:
	/* Terminal step 2: load saved CR3 (the SECOND, final CR3 load). */
	movq	%r8, %cr3
	/*
	 * Terminal step 3: the very next instruction, fetched from the same
	 * physical bytes under both mappings; jumps to trampoline_saved_va.
	 * No stack access, no data access, no relative target, and no
	 * instruction fetch outside this page occurs between the CR3 load
	 * immediately above and this jmp.
	 */
	jmp	*%r9
	.fill	4096 - (. - hibernate_tramp_both_domain_page), 1, 0x90

	.globl	hibernate_tramp_saved_domain_stub
hibernate_tramp_saved_domain_stub:
	/*
	 * Terminal step 4: copy the complete scalar handoff record by value
	 * from arena storage to the fixed link-time VA
	 * hibernate_saved_handoff.  Ordinary memory access is permitted here
	 * (design S5.5): the both-domain invariant applies only to the CR3
	 * load and jmp immediately above, not to this stub.
	 */
	movq	%r11, %rsi
	movq	%r13, %rdi
	movq	%rbx, %rcx
	rep	movsb

	/* Terminal step 5: %r12 = saved PCB physical/identity VA. */
	movq	%r14, %r12

	/*
	 * Terminal step 6: jmp (never call) to hibernate_restore_kernel.
	 * %rax is pure jump scratch, dead at the destination.  No shim
	 * exists between this jump and hibernate_restore_kernel.
	 */
	movq	%r15, %rax
	jmp	*%rax
	/* NOTREACHED */

	/*
	 * hibernate_tramp_end bounds the position-independent object C copies
	 * into the arena.  It is exported so hibernate_machdep_prepare() can
	 * size the copy from the real linked extent instead of assuming it,
	 * and refuse if the extent ever exceeds the reserved arena component.
	 */
	.globl	hibernate_tramp_end
hibernate_tramp_end:
END(hibernate_tramp_entry)

	.section .note.GNU-stack,"",%progbits
