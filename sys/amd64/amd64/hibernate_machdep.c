/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org> at Kumacom
 * SARL under sponsorship from the FreeBSD Foundation.
 */

#include <sys/param.h>
/*
 * _HIBERNATE_LEAF_REQUIREMENT_TEST: narrow test-build mode, matching the
 * precedent already established by sys/kern/kern_dump.c's
 * _HIBERNATE_DUMP_EXTENT_TEST.  Defining this macro before including this
 * file compiles only hibernate_md_private_leaf_requirement() and
 * hibernate_md_leaf_budget_ok() -- self-contained functions with no
 * CR3/page-table/MD
 * dependency beyond the numeric constant NBPDR (sys/amd64/include/param.h,
 * already userland-safe) -- and skips every other declaration, include,
 * and function in this file, none of which are needed by or safe to
 * compile in a userland test build.
 */
#ifndef _HIBERNATE_LEAF_REQUIREMENT_TEST
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/hibernate.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/hibernate.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/pmap.h>
#include <machine/psl.h>
#include <machine/segments.h>
#include <machine/specialreg.h>

#include <x86/apicvar.h>
#include <x86/mca.h>
#include <x86/x86_var.h>
#else
#include <sys/hibernate.h>
#endif /* !_HIBERNATE_LEAF_REQUIREMENT_TEST */

#ifndef _HIBERNATE_LEAF_REQUIREMENT_TEST
/*
 * XXX
 *
 * Code below currently requires susppcbs[] to have been allocated in advance,
 * which is currently always the case as ACPI does the allocation and hibernate
 * cannot be triggered without ACPI.
 */
extern struct susppcb **susppcbs;

/*
 * Setup transient 1:1 mapping of low 4 GiB in kernel_pmap
 * mirroring mp_machdep.c:355-399.
 *
 * ha is NULL on the SAVE path (no destination-run concept exists there,
 * and no transition arena exists yet): the PML4/PDPT/PD backing pages are
 * drawn from the ordinary below-4GiB pool, exactly as before K23-T13.
 *
 * On the RESUME path ha must already have ha_dst_valid true (guaranteed by
 * hibernate_machdep_prepare()'s own step-1 preconditions) and
 * identity_map_pa must be the HIBERNATE_ARENA_IDENTITY_MAP_BYTES-byte
 * arena offset hibernate_md_arena_layout_compute() assigned for this
 * component (one PML4 page, one PDPT page, four PD pages, in that order).
 *
 * K23-T13 root cause: the destructive K-10 copy that runs later in the
 * same no-return window (sys/kern/kern_hibernate.c,
 * hibernate_resume_attempt() -> hibernate_machdep_enter() ->
 * hibernate_tramp.S) overwrites every destination-run physical page with
 * saved-image payload bytes.  These backing pages were previously drawn
 * from the ordinary below-4GiB pool and proven disjoint from the K-10
 * destination set only by a bounded retrying search
 * (hibernate_md_identity_backing_alloc(), removed) -- unlike every other
 * structure that must survive the copy (trampoline, arena header, handoff
 * record, private CR3 tree, run table), which all live inside the K-9
 * transition arena and are disjoint from the destination set by
 * construction.  A full-memory hibernate's destination set covers
 * essentially all of RAM, so that search could not succeed and
 * deterministically returned ENOMEM at stage 6 (HIB_RESUME_MD_PREPARE).
 * Rule version 4 closes this by carving these pages from the arena
 * instead, the same rule every other copy-surviving structure already
 * follows.
 */
static int
hibernate_setup_identity_map(const struct hibernate_attempt *ha,
    vm_paddr_t identity_map_pa)
{
	static vm_page_t m_pml4, m_pdp, m_pd[4];
	static bool map_initialized = false;
	pml4_entry_t *v_pml4;
	pdp_entry_t *v_pdp;
	pd_entry_t *v_pd;
	vm_paddr_t pml4_pa, pdp_pa, pd_pa[4];
	int i, j;

	if (map_initialized)
		return (0);

	pml4_pa = 0;
	if (ha != NULL) {
		if (identity_map_pa == 0)
			return (EINVAL);
		pml4_pa = identity_map_pa;
		pdp_pa = pml4_pa +
		    HIBERNATE_ARENA_IDENTITY_PML4_PAGES * HIB_PAGE_SIZE;
		for (i = 0; i < 4; i++)
			pd_pa[i] = pdp_pa +
			    HIBERNATE_ARENA_IDENTITY_PDPT_PAGES *
				HIB_PAGE_SIZE +
			    (vm_paddr_t)i * HIB_PAGE_SIZE;
		if (la57)
			__builtin_memset(PHYS_TO_DMAP(pml4_pa), 0,
			    HIB_PAGE_SIZE);
		__builtin_memset(PHYS_TO_DMAP(pdp_pa), 0, HIB_PAGE_SIZE);
	} else {
		if (la57) {
			m_pml4 = pmap_page_alloc_below_4g(true);
			if (m_pml4 == NULL)
				return (ENOMEM);
			pml4_pa = VM_PAGE_TO_PHYS(m_pml4);
		}
		m_pdp = pmap_page_alloc_below_4g(true);
		if (m_pdp == NULL)
			return (ENOMEM);
		pdp_pa = VM_PAGE_TO_PHYS(m_pdp);
		for (i = 0; i < 4; i++) {
			m_pd[i] = pmap_page_alloc_below_4g(false);
			if (m_pd[i] == NULL)
				return (ENOMEM);
			pd_pa[i] = VM_PAGE_TO_PHYS(m_pd[i]);
		}
	}

	if (la57)
		v_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(pml4_pa);
	else
		v_pml4 = &kernel_pmap->pm_pmltop[0];
	v_pdp = (pdp_entry_t *)PHYS_TO_DMAP(pdp_pa);

	for (i = 0; i < 4; i++) {
		v_pd = (pd_entry_t *)PHYS_TO_DMAP(pd_pa[i]);
		for (j = 0; j < NPDEPG; j++) {
			v_pd[j] = ((vm_paddr_t)i * NBPDP +
				      ((vm_paddr_t)j << PDRSHIFT)) |
			    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M | PG_PS;
		}
		v_pdp[i] = pd_pa[i] | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
	}

	if (la57) {
		kernel_pmap->pm_pmltop[0] = pml4_pa | X86_PG_V | X86_PG_RW |
		    X86_PG_A | X86_PG_M;
	}
	v_pml4[0] = pdp_pa | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;

	if ((read_rflags() & PSL_I) != 0)
		pmap_invalidate_all(kernel_pmap);
	else
		invltlb_glob();

	map_initialized = true;
	return (0);
}

/*
 * low_page: one contiguous physical page < 4 GiB for the resume trampoline
 * and low stack.  Allocated once by dumpsys_hibernate_savectx_preinit()
 * before the K-5 page reservation drains vm_phys; reused on every save.
 */
static void *low_page = NULL;

/*
 * dumpsys_hibernate_savectx_preinit: force the one-time MD allocations that
 * dumpsys_hibernate_savectx() needs before the K-5 stability barrier drains
 * all FREE pages from vm_phys.
 *
 * Must be called before hibernate_barrier_prepare() (step 7).  Safe to call
 * more than once; both the low_page allocation and the identity map setup are
 * idempotent after the first call.
 *
 * Returns 0 on success, ENOMEM if the low trampoline page cannot be allocated.
 */
int
dumpsys_hibernate_savectx_preinit(void)
{
	int error;

	if (low_page == NULL) {
		low_page = contigmalloc(PAGE_SIZE, M_DEVBUF, M_WAITOK, 0,
		    0xfffffffful, PAGE_SIZE, 0ul);
		if (low_page == NULL)
			return (ENOMEM);
	}
	/*
	 * K23-T13: ha is NULL on the SAVE path -- no destination-run or
	 * transition-arena concept exists here, so the backing pages are
	 * drawn from the ordinary below-4GiB pool, exactly as before rule
	 * version 4.
	 */
	error = hibernate_setup_identity_map(NULL, 0);
	if (error != 0)
		return (error);
	return (0);
}

/*
 * Save the current context in the hibernate PCB.
 *
 * Returns twice, the second time with EJUSTRETURN (on restore).
 */
int
dumpsys_hibernate_savectx(struct hibernate_save_pcb *hpcb, void *stack_top,
    int (*dump_fn)(void *, void *), void *dump_arg)
{
	struct pcb *pcb;
	uint64_t low_entry_pa, low_stack_pa;
	size_t cr3_offset;
	int error;

	/*
	 * 1 & 2. low_page and the identity map are preallocated by
	 * dumpsys_hibernate_savectx_preinit() before the K-5 stability
	 * barrier drains vm_phys.  Both must be non-NULL here.
	 */
	if (low_page == NULL)
		panic("hibernate: low trampoline page not preallocated");

	/*
	 * 3. Copy trampoline code to offset 0 and record kernel CR3.
	 */
	bcopy(hibernate_resume_tramp, low_page, hibernate_resume_tramp_size);
	cr3_offset = (uintptr_t)&hibernate_tramp_cr3 -
	    (uintptr_t)hibernate_resume_tramp;
	*(uint64_t *)((char *)low_page + cr3_offset) = kernel_pmap->pm_cr3;

	/*
	 * 4. Calculate entry and stack physical addresses.
	 */
	low_entry_pa = vtophys(low_page);
	low_stack_pa = low_entry_pa + PAGE_SIZE - 8;

	pcb = &susppcbs[0]->sp_pcb;

	/*
	 * Capture FPU state before hibernate_savectx so subsequent stack
	 * growth cannot overwrite the return-address slot savectx saved.
	 */
	fpususpend(susppcbs[0]->sp_fpususpend);

	error = hibernate_savectx(hpcb, pcb, low_entry_pa, low_stack_pa);
	if (error != 0) {
		/*
		 * Restore the BSP FPU state (and XCR0) later, in
		 * acpi_s4_resume_bsp_cpu() after initializecpu(): the CPU
		 * reset on resume leaves XCR0 at its x87-only reset value,
		 * so an early restore does not survive.
		 */
		return (EJUSTRETURN);
	}

	/*
	 * Save path: hibernate_savectx returned 0.
	 * Do not return to the caller or unwind this frame. The suspended
	 * thread's stack frame (including the return-address slot into
	 * acpi_EnterSleepState) must remain completely unperturbed.
	 * Execute the dump worker on the isolated scratch stack.
	 */
	if (stack_top != NULL && dump_fn != NULL)
		error = hibernate_call_on_stack(stack_top, dump_fn, dump_arg,
		    NULL);

	return (error);
}

int
hibernate_amd64_xsave_collect(void *buf, size_t buf_capacity,
    struct hibernate_xsave_terminal *out)
{
	struct hibernate_xsave_component_fact facts[64];
	size_t nfacts;
	uint64_t live_xcr0;
	uint32_t extent;
	u_int cp[4];
	int bit, error;

	if (buf == NULL || out == NULL)
		return (EINVAL);
	if (((uintptr_t)buf & (HIBERNATE_AMD64_XSAVE_ALIGNMENT - 1)) != 0)
		return (EINVAL);
	if (!use_xsave)
		return (EINVAL);

	live_xcr0 = rxcr(XCR0);
	if ((live_xcr0 & HIBERNATE_XCR0_REQUIRED_MASK) !=
	    HIBERNATE_XCR0_REQUIRED_MASK ||
	    (live_xcr0 & ~HIBERNATE_AMD64_XCR0_SUPPORTED_MASK) != 0)
		return (EINVAL);
	if (live_xcr0 != xsave_mask)
		return (EINVAL);

	nfacts = 0;
	for (bit = 2; bit < 64; bit++) {
		if ((live_xcr0 & (UINT64_C(1) << bit)) == 0)
			continue;
		if (nfacts >= nitems(facts))
			return (EINVAL);
		cpuid_count(0xd, bit, cp);
		facts[nfacts].hxcf_component = (uint32_t)bit;
		facts[nfacts].hxcf_size = cp[0];
		facts[nfacts].hxcf_offset = cp[1];
		nfacts++;
	}

	error = hibernate_xsave_extent(live_xcr0, facts, nfacts, &extent);
	if (error != 0)
		return (error);
	if (buf_capacity < (size_t)extent)
		return (EINVAL);

	memset(buf, 0, extent);
	fpusave(buf);

	out->hxt_staged_address = buf;
	out->hxt_length = extent;
	out->hxt_enabled_mask = live_xcr0;
	out->hxt_format = HIBERNATE_AMD64_XSAVE_FORMAT_STANDARD;
	return (0);
}

int
hibernate_amd64_pcb_populate(const struct hibernate_save_pcb *hpcb,
    const struct hibernate_xsave_terminal *xt, struct hibernate_pcb *pcb)
{
	struct region_descriptor rd;
	uint64_t kgsbase;

	if (hpcb == NULL || xt == NULL || pcb == NULL)
		return (EINVAL);
	if (xt->hxt_staged_address == NULL ||
	    xt->hxt_length < HIBERNATE_PCB_XSAVE_MIN ||
	    xt->hxt_length > UINT32_MAX ||
	    xt->hxt_format != HIBERNATE_AMD64_XSAVE_FORMAT_STANDARD)
		return (EINVAL);

	memset(pcb, 0, sizeof(*pcb));
	pcb->hp_version = 1;
	pcb->hp_encoded_size = HIBERNATE_PCB_ENCODED_SIZE;

	pcb->hp_cr0 = hpcb->cr0;
	pcb->hp_cr3 = hpcb->cr3;
	pcb->hp_cr4 = hpcb->cr4;
	pcb->hp_efer = rdmsr(MSR_EFER);
	pcb->hp_pat = rdmsr(MSR_PAT);
	pcb->hp_xcr0 = xt->hxt_enabled_mask;
	pcb->hp_rflags = (uint64_t)read_rflags();
	pcb->hp_rsp = hpcb->rsp;
	pcb->hp_rip = hpcb->rip;
	pcb->hp_r12_pcb_pa = vtophys((void *)(uintptr_t)hpcb->r12);

	sgdt(&rd);
	pcb->hp_gdtr_limit = (uint16_t)rd.rd_limit;
	pcb->hp_gdtr_base = (uint64_t)rd.rd_base;
	sidt(&rd);
	pcb->hp_idtr_limit = (uint16_t)rd.rd_limit;
	pcb->hp_idtr_base = (uint64_t)rd.rd_base;

	pcb->hp_fsbase = rdmsr(MSR_FSBASE);
	pcb->hp_gsbase = rdmsr(MSR_GSBASE);
	kgsbase = rdmsr(MSR_KGSBASE);
	pcb->hp_kgsbase = kgsbase;
	pcb->hp_star = rdmsr(MSR_STAR);
	pcb->hp_lstar = rdmsr(MSR_LSTAR);
	pcb->hp_cstar = rdmsr(MSR_CSTAR);
	pcb->hp_sfmask = rdmsr(MSR_SF_MASK);
	pcb->hp_kernel_gsbase = kgsbase;

	pcb->hp_xsave_length = (uint32_t)xt->hxt_length;
	pcb->hp_xsave_format = xt->hxt_format;
	pcb->hp_xsave_offset = 0;
	pcb->hp_xsave_enabled_mask = xt->hxt_enabled_mask;
	return (0);
}

/*
 * Compare the decoded saved CPU state with the live restore CPU.  CR0_TS is
 * excluded because normal lazy-FPU handling may legitimately change it.
 * CR4_DE (debugging extensions) is excluded for the same reason: it tracks
 * transient hardware-watchpoint/debug-register use during the live save
 * session (e.g. ptrace(2) PT_SETDBREGS), not a CPU paging/feature
 * capability the restore kernel needs to match -- it was observed set in
 * every save-side snapshot and clear on every freshly booted resume
 * kernel, with no in-tree code ever setting it explicitly.  The EFER mask
 * contains every bit currently defined by specialreg.h.  Each PAT entry
 * has three architecturally defined memory-type bits.
 */
#define HIBERNATE_CR0_MASK                                              \
	(CR0_PE | CR0_MP | CR0_EM | CR0_NE | CR0_WP | CR0_AM | CR0_NW | \
	    CR0_CD | CR0_PG)
#define HIBERNATE_CR4_MASK                                                     \
	(CR4_VME | CR4_PVI | CR4_TSD | CR4_PSE | CR4_PAE | CR4_MCE | CR4_PGE | \
	    CR4_PCE | CR4_FXSR | CR4_XMM | CR4_UMIP | CR4_LA57 | CR4_VMXE |    \
	    CR4_FSGSBASE | CR4_PCIDE | CR4_XSAVE | CR4_SMEP | CR4_SMAP |       \
	    CR4_PKE | CR4_CET | CR4_PKS | CR4_UINTR | CR4_LASS | CR4_LAM_SUP | \
	    CR4_FRED)
#define HIBERNATE_EFER_MASK                                                  \
	(EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE | EFER_SVM | EFER_LMSLE | \
	    EFER_FFXSR | EFER_TCE | EFER_MCOMMIT | EFER_INTWB | EFER_UAIE |  \
	    EFER_AIBRSE)
#define	HIBERNATE_PAT_MASK	UINT64_C(0x0707070707070707)

int
hibernate_amd64_cpu_validate(const struct hibernate_pcb *pcb, bool *refuse_la57,
    bool *refuse_mtrr)
{
	struct hibernate_xsave_component_fact facts[64];
	uint64_t live_xcr0;
	uint32_t extent;
	size_t nfacts;
	u_int cp[4];
	int bit, error;

	if (pcb == NULL || refuse_la57 == NULL || refuse_mtrr == NULL)
		return (EINVAL);

	*refuse_la57 = la57 != 0;
	*refuse_mtrr = x86_hibernate_mtrr_transition_required();
	if (*refuse_la57 || *refuse_mtrr)
		return (EINVAL);

	if (((uint64_t)rcr0() & HIBERNATE_CR0_MASK) !=
	    (pcb->hp_cr0 & HIBERNATE_CR0_MASK) ||
	    ((uint64_t)rcr4() & HIBERNATE_CR4_MASK) !=
	    (pcb->hp_cr4 & HIBERNATE_CR4_MASK) ||
	    (rdmsr(MSR_EFER) & HIBERNATE_EFER_MASK) !=
	    (pcb->hp_efer & HIBERNATE_EFER_MASK) ||
	    (rdmsr(MSR_PAT) & HIBERNATE_PAT_MASK) !=
	    (pcb->hp_pat & HIBERNATE_PAT_MASK))
		return (EINVAL);

	live_xcr0 = rxcr(XCR0);
	if (live_xcr0 != pcb->hp_xcr0 ||
	    live_xcr0 != pcb->hp_xsave_enabled_mask)
		return (EINVAL);

	nfacts = 0;
	for (bit = 2; bit < 64; bit++) {
		if ((live_xcr0 & (UINT64_C(1) << bit)) == 0)
			continue;
		if (nfacts >= nitems(facts))
			return (EINVAL);
		cpuid_count(0xd, bit, cp);
		facts[nfacts].hxcf_component = (uint32_t)bit;
		facts[nfacts].hxcf_size = cp[0];
		facts[nfacts].hxcf_offset = cp[1];
		nfacts++;
	}

	error = hibernate_xsave_extent(live_xcr0, facts, nfacts, &extent);
	if (error != 0)
		return (error);
	if (extent != pcb->hp_xsave_length ||
	    pcb->hp_xsave_format != HIBERNATE_AMD64_XSAVE_FORMAT_STANDARD)
		return (EINVAL);
	return (0);
}

/*
 * K23-T08: hibernate_resume_ap_entry() -- the AP park stub's post-release
 * C entry (K23-T06 arbitration verdict item 1; K23-T00's "smallest
 * sufficient register/field list").  Called by hibernate_park_tramp.S on
 * the arena park stack, after CR0/CR3/CR4/EFER/PAT/XCR0 have already been
 * restored from the saved domain and execution has reached 64-bit mode
 * under hah_saved_cr3_pa.
 *
 * Establishes exactly the fields K23-T00 marks "must be established":
 * GDTR, IDTR, FSBASE/GSBASE/KGSBASE, TR, and pc_curthread = pc_idlethread.
 * Every other field pcpu_find(cpu) exposes is already valid post-copy,
 * restored by the K-10 destructive copy itself, and must not be
 * reinitialised here: this function must never call pcpu_init(),
 * dpcpu_init(), sched_init_ap(), fpuinit(), cpu_setregs(),
 * initializecpu(), pmap_activate_boot(), init_secondary(), or
 * init_secondary_tail().
 *
 * K23-T06 arbitration verdict item 6 (and its addendum to the K23-T00
 * audit): INIT/SIPI resets per-CPU hardware state beyond what T00's list
 * restores.  The following idempotent, register/MSR-only writes repair
 * that state: the SYSCALL MSRs (amd64_conf_fast_syscall()), the
 * memory-control MSRs (amd64_cpu_init_msr_memctl()), the FRED stack/
 * config MSRs plus CR4.FRED when the saved kernel ran with FRED
 * (amd64_cpu_init_fred() -- the park stub deliberately withheld
 * CR4.FRED from its own 32-bit control-state restore, per the verdict's
 * item 2 and D040 SS14.1 item 2; amd64_cpu_init_fred() is the first and
 * only place CR4.FRED is set), and LAPIC re-enable (lapic_xapic_mode(),
 * lapic_setup(1) -- INIT software-disables the LAPIC) plus mca_init()
 * (MCA banks, also reset by INIT).  Without these the AP gets no timer
 * and no IPIs, so sched_ap_entry() cannot make progress.  None of these
 * writes pc_sched, the idle thread's td_lock or machine context, run
 * queues, curpcb, fpcurthread, scheduler_stopped, stopped_cpus,
 * started_cpus, smp_cpus, or smp_started -- T00's prohibition on
 * re-initialising those is unextended by this addition.
 *
 * pc_curthread is set immediately after GSBASE is valid (matching
 * init_secondary_tail()'s own relative ordering, sys/x86/x86/mp_x86.c)
 * so mca_init()/lapic_setup(1) observe a valid curthread, exactly as
 * they do on ordinary AP bring-up.
 *
 * Also owned by K23-T09, elsewhere: the NMI window
 * (sys/amd64/amd64/hibernate_park_tramp.S) and the acquire/release
 * discipline on the BSP side (sys/kern/kern_hibernate.c).
 *
 * Never returns.
 */
void
hibernate_resume_ap_entry(u_int cpu)
{
	struct pcpu *pc;
	struct region_descriptor gdtr;

	pc = pcpu_find(cpu);
	if (pc == NULL)
		panic("hibernate: resume AP %u has no pcpu", cpu);

	gdtr.rd_limit = NGDT * sizeof(pc->pc_gdt[0]) - 1;
	gdtr.rd_base = (u_long)pc->pc_gdt;
	lgdt(&gdtr);

	wrmsr(MSR_FSBASE, 0);
	wrmsr(MSR_GSBASE, (uint64_t)pc);
	wrmsr(MSR_KGSBASE, 0);

	pc->pc_curthread = pc->pc_idlethread;

	if (fred)
		amd64_cpu_init_fred();
	else
		lidt(&r_idt);

	amd64_cpu_init_msr_memctl();

	ltr(GSEL(GPROC0_SEL, SEL_KPL));

	amd64_conf_fast_syscall();

	lapic_xapic_mode();
	mca_init();
	lapic_setup(1);

	sched_ap_entry();
	panic("hibernate: sched_ap_entry returned to %s", __func__);
}

/*
 * K-10: hibernate_machdep_prepare() (issue #12, Design 036 SS5.3-5.8).
 *
 * hibernate_tramp_entry is the no-return assembly entry point task-5 (new
 * file sys/amd64/amd64/hibernate_tramp.S) provides; hibernate_restore_kernel
 * is the existing K-11-ported high-half restore entry already defined in
 * sys/amd64/amd64/hibernate_switch.S.  Neither is declared in any header
 * reachable from this file, so both are declared locally, matching this
 * file's existing convention of declaring low-level asm entry points
 * (hibernate_resume_tramp, hibernate_call_on_stack) via machine/hibernate.h
 * -- these two are declared here instead because hibernate_tramp.S has not
 * yet landed and hibernate_restore_kernel's prototype lives nowhere public.
 */
extern void hibernate_restore_kernel(void) __dead2;

static vm_paddr_t hibernate_md_arena_header_pa;
static vm_paddr_t hibernate_md_xsave_pa;
static vm_offset_t hibernate_md_trampoline_entry_va;

/*
 * K-10's dedicated low-memory PML4 slot for trampoline_saved_va, distinct
 * from hibernate_setup_identity_map()'s slot 0 (Design 036 S5.3, S7 Q2).
 * trampoline_saved_va = HIBERNATE_MD_SAVED_SLOT * NBPML4 + trampoline_pa;
 * since the transition arena is always below HIBERNATE_ARENA_PHYS_LIMIT
 * (4 GiB), this VA never collides with slot 0's own identity range or with
 * ordinary high-half kernel VAs.
 */
#define HIBERNATE_MD_SAVED_SLOT 1
_Static_assert(HIBERNATE_MD_SAVED_SLOT != 0,
    "K-10 saved-domain slot must differ from hibernate_setup_identity_map()'s slot 0");

/*
 * One coalesced destination run, read by hibernate_tramp.S's copy loop
 * under private CR3 (Design 036 S5.4).  Exactly HIBERNATE_ARENA_COPY_RUN_BYTES
 * (32) bytes; hmr_reserved is zero-filled and must stay zero so a future
 * field can be added without an ABI break.  This is the sole definition of
 * the run-table wire format; hibernate_tramp.S (task-5) must match it
 * exactly.
 */
struct hibernate_md_run {
	uint64_t hmr_pa;    /* First destination PA in the run. */
	uint64_t hmr_count; /* Page count in the run. */
	uint64_t hmr_reserved0;
	uint64_t hmr_reserved1;
};
_Static_assert(sizeof(struct hibernate_md_run) ==
	HIBERNATE_ARENA_COPY_RUN_BYTES,
    "run-table entry width must match "
    "HIBERNATE_ARENA_COPY_RUN_BYTES");

/*
 * Fixed 64-bit guard pattern used only in storage that remains unused after
 * prepare: the inactive run-table tail and inactive private-page-table tail.
 * Live header, trampoline, stack, handoff, run, and paging bytes never carry
 * in-band guards.  The unused-tail guards are checked after all encoders, and
 * the live trampoline is independently compared byte-for-byte with its linked
 * source through the direct, private-identity, and saved-domain aliases.
 */
#define HIBERNATE_MD_CANARY UINT64_C(0x4b31304341524e59) /* "K10CARNY" */

/*
 * hibernate_md_arena_layout: byte offsets of every K-10-owned sub-object
 * within the claimed arena, derived by mirroring hibernate_arena_required()'s
 * exact component summing order (kern_hibernate.c).  This file does not
 * modify hibernate_arena_required(); it only reads the public
 * struct hibernate_arena_sizing fields it already returns and reapplies the
 * same, already-landed component order to locate each sub-object.
 */
struct hibernate_md_arena_layout {
	vm_paddr_t header_pa; /* 256 B: struct hibernate_arena_header. */
	vm_paddr_t
	    trampoline_pa;   /* HIBERNATE_ARENA_TRAMPOLINE_BYTES: copied code. */
	vm_paddr_t stack_pa; /* 65536 B: arena stack. */
	/* HIBERNATE_ARENA_PARK_STACK_BYTES: AP park stack. */
	vm_paddr_t park_stack_pa;
	vm_paddr_t private_pt_pa; /* 29 pages: private CR3 PML4/PDPT/PD. */
	/*
	 * HIBERNATE_ARENA_IDENTITY_MAP_BYTES: hibernate_setup_identity_map()'s
	 * PML4/PDPT/PD backing pages (RESUME path only; K23-T13).
	 */
	vm_paddr_t identity_map_pa;
	vm_paddr_t handoff_pa;	  /* 4096 B: encoded handoff record. */
	vm_paddr_t run_table_pa;  /* Coalesced destination run table. */
	uint64_t run_table_max;	  /* HIBERNATE_ARENA_COPY_RUN_MAX. */
};

/*
 * hibernate_md_arena_layout_compute: derive every K-10 sub-object's byte
 * offset by reapplying hibernate_arena_required()'s own, already-landed
 * component summing order (kern_hibernate.c) -- header, trampoline, stack,
 * park stack, private page tables, identity-map backing pages, handoff,
 * then descriptor storage (the run table lives in the copy-run sub-range
 * of has_descriptor_storage; the aux-descriptor sub-range that follows it
 * is K-9 headroom this file does not use).
 */
static int
hibernate_md_arena_layout_compute(const struct hibernate_attempt *ha,
    struct hibernate_md_arena_layout *out)
{
	struct hibernate_arena_sizing sizing;
	vm_paddr_t off;
	int error;

	error = hibernate_arena_required(&sizing);
	if (error != 0)
		return (error);
	if (sizing.has_required != ha->ha_arena_size)
		return (EINVAL);

	off = ha->ha_arena_start;
	out->header_pa = off;
	off += HIBERNATE_ARENA_HEADER_BYTES;
	out->trampoline_pa = off;
	off += HIBERNATE_ARENA_TRAMPOLINE_BYTES;
	out->stack_pa = off;
	off += HIBERNATE_ARENA_STACK_BYTES;
	out->park_stack_pa = off;
	off += HIBERNATE_ARENA_PARK_STACK_BYTES;
	out->private_pt_pa = off;
	off += sizing.has_private_page_tables;
	out->identity_map_pa = off;
	off += sizing.has_identity_map_pages;
	out->handoff_pa = off;
	off += HIBERNATE_ARENA_HANDOFF_BYTES;
	out->run_table_pa = off;
	out->run_table_max = HIBERNATE_ARENA_COPY_RUN_MAX;
	return (0);
}

/*
 * hibernate_md_canary_write: write the fixed canary pattern at the first
 * and last 8 bytes of the len-byte arena-owned object at pa.  len must be
 * at least 16.  No-op (defensive) if len < 16.
 */
static void
hibernate_md_canary_write(vm_paddr_t pa, uint64_t len)
{
	uint8_t *va;

	if (len < 16)
		return;
	va = (uint8_t *)PHYS_TO_DMAP(pa);
	le64enc(va, HIBERNATE_MD_CANARY);
	le64enc(va + len - 8, HIBERNATE_MD_CANARY);
}

static bool
hibernate_md_canary_check(vm_paddr_t pa, uint64_t len)
{
	const uint8_t *va;

	if (len < 16)
		return (true);
	va = (const uint8_t *)PHYS_TO_DMAP(pa);
	return (le64dec(va) == HIBERNATE_MD_CANARY &&
	    le64dec(va + len - 8) == HIBERNATE_MD_CANARY);
}

/*
 * hibernate_md_build_run_table: coalesce ha->ha_dst_intervals (already
 * K-5/K-7-validated sorted, non-overlapping [start,end) pairs) into the
 * run table at layout->run_table_pa, and prove the resulting total page
 * count equals ha->ha_image.hi_destination_pages (Design 036 S5.7 step 4,
 * acceptance: "Destination-union total, run-table total, and
 * hi_destination_pages are proven equal").  hibernate_tramp.S's copy loop
 * reads exactly HAH_DESTINATION_PAGE_COUNT (== hi_destination_pages)
 * source-vector entries and copies exactly that many pages; this run
 * table and the K-8-built source vector are therefore already 1:1 aligned
 * by construction (P entries, P pages) with no synthetic entry needed.
 *
 * Returns 0 on success with *run_count_out set; ENOMEM if the run count
 * would exceed layout->run_table_max; EOVERFLOW on checked-arithmetic
 * failure; EINVAL if the recomputed total disagrees with
 * hi_destination_pages.
 */
static int
hibernate_md_build_run_table(struct hibernate_attempt *ha,
    const struct hibernate_md_arena_layout *layout, uint64_t *run_count_out)
{
	struct hibernate_md_run *runs;
	uint64_t i, n, total, start, end, count;

	runs = (struct hibernate_md_run *)PHYS_TO_DMAP(layout->run_table_pa);
	n = 0;
	total = 0;
	for (i = 0; i < ha->ha_dst_count; i++) {
		start = ha->ha_dst_intervals[i * 2];
		end = ha->ha_dst_intervals[i * 2 + 1];
		if (end <= start)
			return (EINVAL);
		if (((end - start) % HIB_PAGE_SIZE) != 0 ||
		    (start % HIB_PAGE_SIZE) != 0)
			return (EINVAL);
		count = (end - start) / HIB_PAGE_SIZE;
		if (n >= layout->run_table_max)
			return (ENOMEM);
		runs[n].hmr_pa = start;
		runs[n].hmr_count = count;
		runs[n].hmr_reserved0 = 0;
		runs[n].hmr_reserved1 = 0;
		n++;
		if (__builtin_add_overflow(total, count, &total))
			return (EOVERFLOW);
	}
	if (total != ha->ha_image.hi_destination_pages)
		return (EINVAL);
	*run_count_out = n;
	return (0);
}

/*
 * hib_pa_in_dst_md: local re-derivation of destination-union membership
 * for exactly one physical page, independent of hibernate_dst_interval_
 * contains() (which K-10 does not call here, per the issue's "K-10 is the
 * sole owner of ... all copy, overlap, canary ... proof fixtures" --
 * re-deriving via ha_dst_intervals directly, the same validated published
 * array, but with K-10's own scan rather than reusing K-5/K-7's predicate
 * function).
 */
static bool
hib_pa_in_dst_md(const struct hibernate_attempt *ha, vm_paddr_t pa)
{
	uint64_t i;
	vm_paddr_t start, end;

	for (i = 0; i < ha->ha_dst_count; i++) {
		start = ha->ha_dst_intervals[i * 2];
		end = ha->ha_dst_intervals[i * 2 + 1];
		if (pa >= start && pa < end)
			return (true);
		if (start > pa)
			break;
	}
	return (false);
}

/*
 * hibernate_md_source_disjoint: K-10-owned canary (Design 036 S5.4 step 2):
 * independently re-derive that the P source-vector PAs are pairwise
 * distinct and disjoint from every destination run, rather than trusting
 * K-8's hib_pages_verify() result.  O(P log P) via an insertion sort of a
 * caller-owned scratch copy; P == hi_destination_pages, already bounded by
 * the K-5 capacity check, so this is not unbounded.
 *
 * scratch must have capacity for at least p entries.  Returns 0 if every
 * entry is unique and no entry falls within [arena_start, arena_end) or
 * any destination run; EINVAL otherwise.
 */
static int
hibernate_md_source_disjoint(const vm_paddr_t *vector, uint64_t p,
    vm_paddr_t *scratch, const struct hibernate_attempt *ha,
    vm_paddr_t arena_start, vm_paddr_t arena_end)
{
	uint64_t i, j;
	vm_paddr_t value, pa;

	for (i = 0; i < p; i++)
		scratch[i] = vector[i];
	for (i = 1; i < p; i++) {
		value = scratch[i];
		for (j = i; j > 0 && scratch[j - 1] > value; j--)
			scratch[j] = scratch[j - 1];
		scratch[j] = value;
	}
	for (i = 0; i < p; i++) {
		pa = scratch[i];
		if (i > 0 && scratch[i - 1] == pa)
			return (EINVAL);
		if (pa >= arena_start && pa < arena_end)
			return (EINVAL);
		if (hib_pa_in_dst_md(ha, pa))
			return (EINVAL);
	}
	return (0);
}

/*
 * The private tree has three independently bounded levels below its PML4:
 * four PDPT pages, eight PD pages, and sixteen leaf PT pages.  PD and leaf
 * records are keyed by their natural physical range so only entries that
 * cover transition data are installed.
 */
struct hibernate_md_private_pd {
	vm_paddr_t hmp_base;
	pd_entry_t *hmp_entries;
	u_int hmp_super;
};

struct hibernate_md_private_leaf {
	vm_paddr_t hml_base;
	pt_entry_t *hml_entries;
	u_int hml_pd;
};

struct hibernate_md_private_builder {
	const struct hibernate_md_arena_layout *hmb_layout;
	pml4_entry_t *hmb_pml4;
	pdp_entry_t *hmb_pdpt[HIBERNATE_ARENA_PT_PDPT_PAGES];
	vm_paddr_t hmb_superbase[HIBERNATE_ARENA_PT_PDPT_PAGES];
	struct hibernate_md_private_pd hmb_pd[HIBERNATE_ARENA_PT_PD_PAGES];
	/*
	 * hmb_leaf[] is heap-allocated (M_TEMP, M_NOWAIT), not a fixed
	 * stack array: HIBERNATE_ARENA_PT_LEAF_PAGES (rule version 2) is
	 * sized from a measured real-world destination-fragmentation
	 * count (see hibernate.h's rationale comment and design-039 SS12),
	 * not a small compile-time constant, so it no longer fits safely
	 * on the kernel stack (struct hibernate_md_private_builder is
	 * itself stack-resident in hibernate_md_private_tree_build()).
	 * hmb_leaf_capacity is the number of allocated-and-usable entries
	 * (HIBERNATE_ARENA_PT_LEAF_PAGES unless allocation is truncated;
	 * truncation is itself a fail-closed refusal, never a silent
	 * smaller budget -- see hibernate_md_private_tree_build()).
	 */
	struct hibernate_md_private_leaf *hmb_leaf;
	u_int hmb_leaf_capacity;
	vm_paddr_t hmb_pml4_pa;
	vm_paddr_t hmb_pdpt_base;
	vm_paddr_t hmb_pd_base;
	vm_paddr_t hmb_leaf_base;
	vm_paddr_t hmb_end;
	u_int hmb_nsuper;
	u_int hmb_npd;
	u_int hmb_nleaf;
};

static int
hibernate_md_private_page_at(struct hibernate_md_private_builder *builder,
    vm_paddr_t base, u_int index, uint64_t budget, vm_paddr_t *pa)
{
	vm_paddr_t offset;

	if (index >= budget ||
	    __builtin_mul_overflow((vm_paddr_t)index, (vm_paddr_t)HIB_PAGE_SIZE,
		&offset) ||
	    __builtin_add_overflow(base, offset, pa) ||
	    *pa > builder->hmb_end || builder->hmb_end - *pa < HIB_PAGE_SIZE)
		return (ENOMEM);
	__builtin_memset((void *)PHYS_TO_DMAP(*pa), 0, HIB_PAGE_SIZE);
	return (0);
}

static int
hibernate_md_private_super_get(struct hibernate_md_private_builder *builder,
    vm_paddr_t pa, u_int *index)
{
	vm_paddr_t base, table_pa;
	u_int i, pml4_index;
	int error;

	base = pa & ~(vm_paddr_t)(NBPML4 - 1);
	for (i = 0; i < builder->hmb_nsuper; i++) {
		if (builder->hmb_superbase[i] == base) {
			*index = i;
			return (0);
		}
	}
	if (builder->hmb_nsuper >= HIBERNATE_ARENA_PT_PDPT_PAGES)
		return (ENOMEM);
	i = builder->hmb_nsuper;
	error = hibernate_md_private_page_at(builder, builder->hmb_pdpt_base, i,
	    HIBERNATE_ARENA_PT_PDPT_PAGES, &table_pa);
	if (error != 0)
		return (error);
	builder->hmb_nsuper++;
	builder->hmb_superbase[i] = base;
	builder->hmb_pdpt[i] = (pdp_entry_t *)PHYS_TO_DMAP(table_pa);
	pml4_index = (u_int)((base >> PML4SHIFT) & (NPML4EPG - 1));
	if ((builder->hmb_pml4[pml4_index] & X86_PG_V) != 0)
		return (EINVAL);
	builder->hmb_pml4[pml4_index] = table_pa | X86_PG_V | X86_PG_RW;
	*index = i;
	return (0);
}

static int
hibernate_md_private_pd_get(struct hibernate_md_private_builder *builder,
    vm_paddr_t pa, u_int *index)
{
	vm_paddr_t base, table_pa;
	u_int i, super, pdpt_index;
	int error;

	base = pa & ~(vm_paddr_t)(NBPDP - 1);
	for (i = 0; i < builder->hmb_npd; i++) {
		if (builder->hmb_pd[i].hmp_base == base) {
			*index = i;
			return (0);
		}
	}
	if (builder->hmb_npd >= HIBERNATE_ARENA_PT_PD_PAGES)
		return (ENOMEM);
	error = hibernate_md_private_super_get(builder, pa, &super);
	if (error != 0)
		return (error);
	i = builder->hmb_npd;
	error = hibernate_md_private_page_at(builder, builder->hmb_pd_base, i,
	    HIBERNATE_ARENA_PT_PD_PAGES, &table_pa);
	if (error != 0)
		return (error);
	builder->hmb_npd++;
	builder->hmb_pd[i].hmp_base = base;
	builder->hmb_pd[i].hmp_entries = (pd_entry_t *)PHYS_TO_DMAP(table_pa);
	builder->hmb_pd[i].hmp_super = super;
	pdpt_index = (u_int)((base >> PDPSHIFT) & (NPDPEPG - 1));
	if ((builder->hmb_pdpt[super][pdpt_index] & X86_PG_V) != 0)
		return (EINVAL);
	builder->hmb_pdpt[super][pdpt_index] = table_pa | X86_PG_V | X86_PG_RW;
	*index = i;
	return (0);
}

static int
hibernate_md_private_leaf_get(struct hibernate_md_private_builder *builder,
    vm_paddr_t pa, u_int *index)
{
	vm_paddr_t base, table_pa;
	u_int i, pd, pde_index;
	int error;

	base = pa & ~(vm_paddr_t)(NBPDR - 1);
	for (i = 0; i < builder->hmb_nleaf; i++) {
		if (builder->hmb_leaf[i].hml_base == base) {
			*index = i;
			return (0);
		}
	}
	if (builder->hmb_nleaf >= builder->hmb_leaf_capacity)
		return (ENOMEM);
	error = hibernate_md_private_pd_get(builder, pa, &pd);
	if (error != 0)
		return (error);
	pde_index = (u_int)((base >> PDRSHIFT) & (NPDEPG - 1));
	if ((builder->hmb_pd[pd].hmp_entries[pde_index] & X86_PG_V) != 0)
		return (EINVAL);
	i = builder->hmb_nleaf;
	error = hibernate_md_private_page_at(builder, builder->hmb_leaf_base, i,
	    builder->hmb_leaf_capacity, &table_pa);
	if (error != 0)
		return (error);
	builder->hmb_nleaf++;
	builder->hmb_leaf[i].hml_base = base;
	builder->hmb_leaf[i].hml_entries = (pt_entry_t *)PHYS_TO_DMAP(table_pa);
	builder->hmb_leaf[i].hml_pd = pd;
	builder->hmb_pd[pd].hmp_entries[pde_index] = table_pa | X86_PG_V |
	    X86_PG_RW;
	*index = i;
	return (0);
}

/*
 * Add one exact 4 KiB identity mapping.  Repeated requests are harmless only
 * when both the frame and executable permission agree.
 */
static int
hibernate_md_private_page_map_flags(
    struct hibernate_md_private_builder *builder, vm_paddr_t pa,
    pt_entry_t flags)
{
	pt_entry_t entry, *pt, pde;
	vm_paddr_t super_base, super_pa;
	u_int leaf, pte_index, pd;
	int error;

	if ((pa & PAGE_MASK) != 0)
		return (EINVAL);

	/*
	 * hibernate_md_private_arena_map() installs 2 MiB identity
	 * superpages for every 2 MiB-aligned chunk intersecting the
	 * arena's byte range (Design 036 S5.3's "minimum set of 2 MiB
	 * superpages").  Because the arena's byte range is not itself
	 * 2 MiB-aligned, the first/last superpage can cover physical
	 * memory outside the literal arena bytes -- and a destination,
	 * source-vector, or XSAVE page can legitimately fall in that
	 * already-mapped padding (observed: arena_start 0x7d1c4000's
	 * covering superpage at 0x7d000000 also covers an unrelated
	 * destination page at the same address).  Detect an existing,
	 * permission-compatible superpage translation here and treat the
	 * request as already satisfied, mirroring the PTE-level
	 * idempotent-if-compatible check below one level down, rather
	 * than reporting a hard EINVAL collision for a mapping the
	 * superpage already grants.  A real permission mismatch (e.g. the
	 * XSAVE page's required NX bit against a non-NX arena superpage)
	 * still correctly refuses.
	 */
	error = hibernate_md_private_pd_get(builder, pa, &pd);
	if (error != 0)
		return (error);
	pde = builder->hmb_pd[pd]
		  .hmp_entries[(u_int)((pa >> PDRSHIFT) & (NPDEPG - 1))];
	if ((pde & X86_PG_V) != 0 && (pde & PG_PS) != 0) {
		super_base = pde & PG_PS_FRAME;
		super_pa = super_base | (pa & PDRMASK);
		if (super_pa == pa &&
		    (pde & (X86_PG_V | X86_PG_RW)) == (X86_PG_V | X86_PG_RW) &&
		    (pde & X86_PG_NX) == (flags & X86_PG_NX))
			return (0);
		return (EINVAL);
	}

	error = hibernate_md_private_leaf_get(builder, pa, &leaf);
	if (error != 0)
		return (error);
	pt = builder->hmb_leaf[leaf].hml_entries;
	pte_index = (u_int)((pa >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = pa | X86_PG_V | X86_PG_RW | flags;
	if ((pt[pte_index] & X86_PG_V) != 0) {
		if ((pt[pte_index] & (PG_FRAME | X86_PG_NX)) !=
		    (entry & (PG_FRAME | X86_PG_NX)))
			return (EINVAL);
		return (0);
	}
	pt[pte_index] = entry;
	return (0);
}

static int
hibernate_md_private_page_map(struct hibernate_md_private_builder *builder,
    vm_paddr_t pa)
{
	return (hibernate_md_private_page_map_flags(builder, pa, 0));
}

/*
 * Map only the 2 MiB chunks intersecting the arena.  The first and last
 * chunks may include padding outside the arena, but untouched PDEs in the
 * same 1 GiB PD remain zero.
 */
static int
hibernate_md_private_arena_map(struct hibernate_md_private_builder *builder,
    vm_paddr_t start, vm_paddr_t end)
{
	vm_paddr_t pa;
	pd_entry_t *pd_entries;
	u_int pd, pde_index;
	int error;

	pa = start & ~(vm_paddr_t)(NBPDR - 1);
	while (pa < end) {
		error = hibernate_md_private_pd_get(builder, pa, &pd);
		if (error != 0)
			return (error);
		pd_entries = builder->hmb_pd[pd].hmp_entries;
		pde_index = (u_int)((pa >> PDRSHIFT) & (NPDEPG - 1));
		if ((pd_entries[pde_index] & X86_PG_V) != 0)
			return (EINVAL);
		pd_entries[pde_index] = pa | X86_PG_V | X86_PG_RW | PG_PS;
		if (__builtin_add_overflow(pa, (vm_paddr_t)NBPDR, &pa))
			return (EOVERFLOW);
	}
	return (0);
}

/*
 * hibernate_md_private_leaf_requirement: compute, with checked arithmetic
 * and no page-table side effects, the exact number of distinct 2 MiB-
 * aligned leaf regions hibernate_md_private_tree_build() will need to
 * identity-map: the arena, every coalesced destination run, every
 * scattered source page, the contiguous source-vector storage range,
 * and the single staged XSAVE page.
 *
 * ha->ha_dst_intervals is already K-5/K-7-validated sorted and strictly
 * non-overlapping (hibernate_image_validate() step 4), so the destination
 * contribution is computed in a single linear pass with no scratch array
 * and no dependence on ha_dst_count's bound beyond
 * HIBERNATE_ARENA_COPY_RUN_MAX (the run-table capacity
 * hibernate_md_build_run_table() already enforces).  The arena, vector
 * storage, and XSAVE contributions are each counted independently (never
 * deduplicated against the destination count or each other): this can
 * only overcount, never undercount, so the computed requirement is a
 * safe upper bound on the true distinct-region count the real pass will
 * need -- it must still be correct, but it is deliberately allowed to be
 * conservative rather than exact, since exact cross-term deduplication
 * would need the same O(n) scratch structure this function is designed
 * to avoid.
 *
 * Returns 0 with *out set on success; EOVERFLOW on checked-arithmetic
 * failure; EINVAL if ha_dst_intervals is unpublished or empty (callers
 * must not reach here before VALIDATE has published it).
 */
#endif /* !_HIBERNATE_LEAF_REQUIREMENT_TEST */
#ifdef _HIBERNATE_LEAF_REQUIREMENT_TEST
int
#else
static int
#endif
hibernate_md_private_leaf_requirement(const struct hibernate_attempt *ha,
    vm_paddr_t arena_end, const vm_paddr_t *vector, uint64_t vector_count,
    vm_paddr_t vector_pa, uint64_t vector_pages, vm_paddr_t xsave_pa,
    uint64_t *out)
{
	vm_paddr_t region, last_region, start, end, bytes, vector_end;
	uint64_t count, i;

	if (!ha->ha_dst_valid || ha->ha_dst_intervals == NULL ||
	    ha->ha_dst_count == 0)
		return (EINVAL);

	count = 0;
	last_region = 0;
	for (i = 0; i < ha->ha_dst_count; i++) {
		start = ha->ha_dst_intervals[i * 2];
		end = ha->ha_dst_intervals[i * 2 + 1];
		if (end <= start)
			return (EINVAL);
		region = start & ~(vm_paddr_t)(NBPDR - 1);
		if (i == 0 || region != last_region) {
			if (__builtin_add_overflow(count, 1, &count))
				return (EOVERFLOW);
		}
		while (region < end) {
			last_region = region;
			if (__builtin_add_overflow(region, (vm_paddr_t)NBPDR,
				&region))
				return (EOVERFLOW);
			if (region >= end)
				break;
			if (__builtin_add_overflow(count, 1, &count))
				return (EOVERFLOW);
		}
	}

	/* Arena: always counted, never deduplicated against destination. */
	region = ha->ha_arena_start & ~(vm_paddr_t)(NBPDR - 1);
	if (__builtin_add_overflow(count, 1, &count))
		return (EOVERFLOW);
	while (region < arena_end) {
		if (__builtin_add_overflow(region, (vm_paddr_t)NBPDR, &region))
			return (EOVERFLOW);
		if (region >= arena_end)
			break;
		if (__builtin_add_overflow(count, 1, &count))
			return (EOVERFLOW);
	}

	/*
	 * Scattered source pages: count the distinct 2 MiB regions the
	 * vector's source PAs fall in, not the pages themselves.  The budget
	 * (HIBERNATE_ARENA_PT_LEAF_PAGES) is a count of hmb_leaf[] entries,
	 * and hibernate_md_private_leaf_get() allocates exactly one per
	 * distinct 2 MiB base, so counting pages over-counts by up to the
	 * 512-way PTE packing factor: a real 4 GiB image has ~255k source
	 * pages but only ~0.5k regions, which made every real restore refuse
	 * against a 4096 budget.
	 *
	 * hibernate_staging_source_pages() documents the vector as one
	 * source PA per destination page, in destination order, and the
	 * destination intervals are validated sorted and strictly
	 * non-overlapping, so the source PAs ascend and one pass counts the
	 * regions exactly.  If that ordering assumption is ever violated,
	 * fall back to the previous page-counting over-count: it can only
	 * over-state the requirement and refuse, never under-count and
	 * overrun the budget mid-build.
	 */
	if (vector_count != 0) {
		if (vector == NULL)
			return (EINVAL);
		last_region = ~(vm_paddr_t)(NBPDR - 1);
		for (i = 0; i < vector_count; i++) {
			if (i != 0 && vector[i] < vector[i - 1]) {
				if (__builtin_add_overflow(count, vector_count,
					&count))
					return (EOVERFLOW);
				break;
			}
			region = vector[i] & ~(vm_paddr_t)(NBPDR - 1);
			if (region != last_region) {
				last_region = region;
				if (__builtin_add_overflow(count, 1, &count))
					return (EOVERFLOW);
			}
		}
	}

	/* Contiguous source-vector storage range. */
	if (__builtin_mul_overflow(vector_pages, (uint64_t)HIB_PAGE_SIZE,
		&bytes) ||
	    __builtin_add_overflow(vector_pa, bytes, &vector_end))
		return (EOVERFLOW);
	if (vector_pages != 0) {
		region = vector_pa & ~(vm_paddr_t)(NBPDR - 1);
		if (__builtin_add_overflow(count, 1, &count))
			return (EOVERFLOW);
		while (region < vector_end) {
			if (__builtin_add_overflow(region, (vm_paddr_t)NBPDR,
				&region))
				return (EOVERFLOW);
			if (region >= vector_end)
				break;
			if (__builtin_add_overflow(count, 1, &count))
				return (EOVERFLOW);
		}
	}

	/* Staged XSAVE page: single page, its own region. */
	(void)xsave_pa;
	if (__builtin_add_overflow(count, 1, &count))
		return (EOVERFLOW);

	*out = count;
	return (0);
}

#ifdef _HIBERNATE_LEAF_REQUIREMENT_TEST
bool
#else
static bool
#endif
hibernate_md_leaf_budget_ok(uint64_t required, uint64_t budget)
{
	return (required <= budget);
}
#ifndef _HIBERNATE_LEAF_REQUIREMENT_TEST

/*
 * Construct the arena-owned private CR3.  Arena execution/data is covered
 * by the minimum set of 2 MiB superpages.  Destination pages, source pages,
 * source-vector pages, and the staged XSAVE page use exact 4 KiB PTEs from
 * the leaf budget (HIBERNATE_ARENA_PT_LEAF_PAGES, rule version 2; see
 * hibernate.h).  No untouched PDE in a referenced 1 GiB region is
 * populated.
 *
 * hmb_leaf[] is heap-allocated here (not stack-resident) and freed on
 * every return path: HIBERNATE_ARENA_PT_LEAF_PAGES is sized from a
 * measured real-world requirement, not a small compile-time constant, so
 * it no longer fits safely in struct hibernate_md_private_builder's
 * stack frame.
 */
static int
hibernate_md_private_tree_build(struct hibernate_attempt *ha,
    const struct hibernate_md_arena_layout *layout,
    const struct hibernate_md_run *runs, uint64_t run_count,
    const vm_paddr_t *vector, uint64_t vector_count, vm_paddr_t vector_pa,
    uint64_t vector_pages, vm_paddr_t xsave_pa, vm_paddr_t *private_cr3_out,
    uint64_t *leaf_pages_out)
{
	struct hibernate_md_private_builder builder;
	vm_paddr_t arena_end, pa, run_end, root_pa;
	uint64_t bytes, i, j, leaf_required;
	int error;

	if (__builtin_add_overflow(ha->ha_arena_start, ha->ha_arena_size,
		&arena_end))
		return (EOVERFLOW);

	/*
	 * Fail closed with a named, measured refusal before any allocation
	 * or page-table construction, rather than letting a generic ENOMEM
	 * surface deep inside hibernate_md_private_leaf_get() once the
	 * budget is already exhausted.
	 */
	error = hibernate_md_private_leaf_requirement(ha, arena_end, vector,
	    vector_count, vector_pa, vector_pages, xsave_pa, &leaf_required);
	if (error != 0)
		return (error);
	if (!hibernate_md_leaf_budget_ok(leaf_required,
		HIBERNATE_ARENA_PT_LEAF_PAGES)) {
		printf("hibernate: private-tree leaf-page budget exceeded: "
		       "measured requirement %ju distinct 2 MiB regions, "
		       "budget %ju (HIBERNATE_ARENA_PT_LEAF_PAGES); refusing\n",
		    (uintmax_t)leaf_required,
		    (uintmax_t)HIBERNATE_ARENA_PT_LEAF_PAGES);
		return (ENOMEM);
	}

	__builtin_memset(&builder, 0, sizeof(builder));
	builder.hmb_layout = layout;
	builder.hmb_pml4_pa = layout->private_pt_pa;
	if (__builtin_add_overflow(builder.hmb_pml4_pa,
		(vm_paddr_t)(HIBERNATE_ARENA_PT_PML4_PAGES * HIB_PAGE_SIZE),
		&builder.hmb_pdpt_base) ||
	    __builtin_add_overflow(builder.hmb_pdpt_base,
		(vm_paddr_t)(HIBERNATE_ARENA_PT_PDPT_PAGES * HIB_PAGE_SIZE),
		&builder.hmb_pd_base) ||
	    __builtin_add_overflow(builder.hmb_pd_base,
		(vm_paddr_t)(HIBERNATE_ARENA_PT_PD_PAGES * HIB_PAGE_SIZE),
		&builder.hmb_leaf_base) ||
	    __builtin_mul_overflow((vm_paddr_t)HIBERNATE_ARENA_PRIVATE_PT_PAGES,
		(vm_paddr_t)HIB_PAGE_SIZE, &bytes) ||
	    __builtin_add_overflow(layout->private_pt_pa, bytes,
		&builder.hmb_end))
		return (EOVERFLOW);

	builder.hmb_leaf_capacity = HIBERNATE_ARENA_PT_LEAF_PAGES;
	builder.hmb_leaf = (struct hibernate_md_private_leaf *)malloc(
	    (size_t)HIBERNATE_ARENA_PT_LEAF_PAGES * sizeof(*builder.hmb_leaf),
	    M_TEMP, M_NOWAIT | M_ZERO);
	if (builder.hmb_leaf == NULL)
		return (ENOMEM);

	root_pa = builder.hmb_pml4_pa;
	__builtin_memset((void *)PHYS_TO_DMAP(root_pa), 0, HIB_PAGE_SIZE);
	builder.hmb_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(root_pa);
	*private_cr3_out = root_pa;

	error = hibernate_md_private_arena_map(&builder, ha->ha_arena_start,
	    arena_end);
	if (error != 0)
		goto out;

	for (i = 0; i < run_count; i++) {
		if (runs[i].hmr_count == 0) {
			error = EINVAL;
			goto out;
		}
		if (__builtin_mul_overflow(runs[i].hmr_count,
			(uint64_t)HIB_PAGE_SIZE, &bytes) ||
		    __builtin_add_overflow(runs[i].hmr_pa, bytes, &run_end)) {
			error = EOVERFLOW;
			goto out;
		}
		for (pa = runs[i].hmr_pa; pa < run_end; pa += HIB_PAGE_SIZE) {
			error = hibernate_md_private_page_map(&builder, pa);
			if (error != 0)
				goto out;
		}
	}
	for (i = 0; i < vector_count; i++) {
		error = hibernate_md_private_page_map(&builder, vector[i]);
		if (error != 0)
			goto out;
	}
	for (j = 0; j < vector_pages; j++) {
		if (__builtin_mul_overflow(j, (uint64_t)HIB_PAGE_SIZE,
			&bytes) ||
		    __builtin_add_overflow(vector_pa, bytes, &pa)) {
			error = EOVERFLOW;
			goto out;
		}
		error = hibernate_md_private_page_map(&builder, pa);
		if (error != 0)
			goto out;
	}
	/*
	 * The staged XSAVE object is data-only.  Its exact private-domain
	 * identity mapping must therefore be writable and non-executable.
	 */
	error = hibernate_md_private_page_map_flags(&builder, xsave_pa,
	    X86_PG_NX);
	if (error != 0)
		goto out;

	KASSERT(builder.hmb_nleaf <= builder.hmb_leaf_capacity,
	    ("hibernate private leaf-page budget exceeded"));
	KASSERT(builder.hmb_npd <= HIBERNATE_ARENA_PT_PD_PAGES,
	    ("hibernate private PD-page budget exceeded"));
	KASSERT(builder.hmb_nsuper <= HIBERNATE_ARENA_PT_PDPT_PAGES,
	    ("hibernate private PDPT-page budget exceeded"));
	*leaf_pages_out = builder.hmb_nleaf;
	error = 0;
out:
	free(builder.hmb_leaf, M_TEMP);
	return (error);
}

/*
 * Result of an independent software page-table walk.  hmw_flags contains
 * the effective V/RW/U permissions accumulated across every traversed
 * level, rather than merely the terminal entry's bits.
 */
struct hibernate_md_walk {
	vm_paddr_t hmw_pa;
	uint64_t hmw_flags;
};

/*
 * Walk an arbitrary four-level amd64 page table rooted at root_pa.
 * This is deliberately independent of the private-tree constructor.
 */
static bool
hibernate_md_tree_walk(vm_paddr_t root_pa, vm_offset_t va,
    struct hibernate_md_walk *walk)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	pt_entry_t *pt;
	uint64_t entry, flags;
	u_int index;

	flags = X86_PG_V | X86_PG_RW | X86_PG_U;
	pml4 = (pml4_entry_t *)PHYS_TO_DMAP(root_pa & PG_FRAME);
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	entry = pml4[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	flags &= entry | ~(X86_PG_V | X86_PG_RW | X86_PG_U);
	flags |= entry & X86_PG_NX;

	pdp = (pdp_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdp[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	flags &= entry | ~(X86_PG_V | X86_PG_RW | X86_PG_U);
	flags |= entry & X86_PG_NX;
	if ((entry & PG_PS) != 0) {
		walk->hmw_pa = (entry & PG_PS_PDP_FRAME) | (va & PDPMASK);
		walk->hmw_flags = flags;
		return (true);
	}

	pd = (pd_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pd[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	flags &= entry | ~(X86_PG_V | X86_PG_RW | X86_PG_U);
	flags |= entry & X86_PG_NX;
	if ((entry & PG_PS) != 0) {
		walk->hmw_pa = (entry & PG_PS_FRAME) | (va & PDRMASK);
		walk->hmw_flags = flags;
		return (true);
	}

	pt = (pt_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = pt[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	flags &= entry | ~(X86_PG_V | X86_PG_RW | X86_PG_U);
	flags |= entry & X86_PG_NX;
	walk->hmw_pa = (entry & PG_FRAME) | (va & PAGE_MASK);
	walk->hmw_flags = flags;
	return (true);
}

static bool
hibernate_md_walk_matches(vm_paddr_t root_pa, vm_offset_t va,
    vm_paddr_t expected_pa, uint64_t expected_flags)
{
	struct hibernate_md_walk walk;
	const uint64_t permission_mask = X86_PG_V | X86_PG_RW | X86_PG_U;

	if (!hibernate_md_tree_walk(root_pa, va, &walk))
		return (false);
	return (walk.hmw_pa == expected_pa &&
	    (walk.hmw_flags & permission_mask) == expected_flags);
}

static vm_paddr_t
hibernate_md_identity_walk(vm_offset_t va)
{
	struct hibernate_md_walk walk;

	if (!hibernate_md_tree_walk(kernel_pmap->pm_cr3, va, &walk))
		return (0);
	return (walk.hmw_pa);
}

/*
 * hibernate_md_saved_domain_table_disjoint: K23-T13 (criterion 13) --
 * prove that every page-table PAGE traversed while resolving va under
 * kernel_pmap (the saved domain) is itself disjoint from the K-10
 * destination set, not merely that the final translation is valid.
 *
 * Root cause this closes: hibernate_md_saved_domain_validate() (above)
 * already proves each of the four saved-domain VAs (trampoline stub,
 * handoff source/destination, saved PCB, restore-kernel entry) resolves
 * to the expected PA with the expected permissions -- but that walk reads
 * kernel_pmap's page-table PAGES themselves only to find the next-level
 * entry; it never checks whether those backing pages are destination-run
 * members.  Observed directly this session: kernel_pmap's own permanent
 * PML4[KPML4I]-rooted PDPT page (the single PDPT page backing the whole
 * kernel .text/.data/.bss region, and therefore every one of these four
 * VAs at once) fell inside a K-10 destination run and was destructively
 * overwritten by the terminal copy with saved-image bytes that left that
 * page's governing PDE entry zero -- i.e. kernel_pmap itself lost its own
 * mapping for hibernate_restore_kernel moments after the terminal CR3
 * reload, with no trap, panic, or double fault: the CPU simply fetched
 * from an unmapped page immediately after jmp *%rax and reset.  This is
 * architecturally identical to the two already-fixed defects this issue
 * closed (K-23-T06's park-stub/park-stack identity-map backing pages,
 * and this same K23-T13's own identity-map-backing-page fix): a resume-
 * side structure that must survive the destructive copy was not proven
 * disjoint from the copy's own destination set before the no-return
 * boundary.  Unlike those two cases, the colliding structure here is not
 * something hibernate_machdep.c itself allocates -- it is the resume
 * kernel's own bootstrap-built kernel_pmap, whose physical page-table
 * pages land wherever this boot's own page-table bootstrap put them, with
 * no existing code proving them disjoint from an arbitrary saved image's
 * destination set.  This function supplies that missing proof so a
 * collision refuses here, before the no-return boundary, instead of
 * crashing silently inside it.
 *
 * Walks root_pa (always kernel_pmap->pm_cr3 in practice) for va exactly
 * like hibernate_md_tree_walk(), but additionally checks, at every level
 * including the top-level root itself, whether the page-table page just
 * read is a hib_pa_in_dst_md() member.  Returns true only if every
 * traversed table page is disjoint from the destination set AND the
 * final entry is valid (present); false on any collision or any missing
 * translation.
 */
static bool
hibernate_md_saved_domain_table_disjoint(const struct hibernate_attempt *ha,
    vm_paddr_t root_pa, vm_offset_t va)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	pt_entry_t *pt;
	vm_paddr_t table_pa;
	uint64_t entry;
	u_int index;

	table_pa = root_pa & PG_FRAME;
	if (hib_pa_in_dst_md(ha, table_pa))
		return (false);
	pml4 = (pml4_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	entry = pml4[index];
	if ((entry & X86_PG_V) == 0)
		return (false);

	table_pa = entry & PG_FRAME;
	if (hib_pa_in_dst_md(ha, table_pa))
		return (false);
	pdp = (pdp_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdp[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	if ((entry & PG_PS) != 0)
		return (true);

	table_pa = entry & PG_FRAME;
	if (hib_pa_in_dst_md(ha, table_pa))
		return (false);
	pd = (pd_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pd[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	if ((entry & PG_PS) != 0)
		return (true);

	table_pa = entry & PG_FRAME;
	if (hib_pa_in_dst_md(ha, table_pa))
		return (false);
	pt = (pt_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = pt[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	return (true);
}

/*
 * K23-T13: map a destination physical page to its index in the source-vector
 * order (one entry per destination page, in ascending destination-interval
 * order).
 */
static int
hibernate_md_dst_page_index(const struct hibernate_attempt *ha, vm_paddr_t pa,
    uint64_t *idx)
{
	uint64_t i, acc, start, end;

	acc = 0;
	for (i = 0; i < ha->ha_dst_count; i++) {
		start = ha->ha_dst_intervals[i * 2];
		end = ha->ha_dst_intervals[i * 2 + 1];
		if (pa >= start && pa < end) {
			*idx = acc + (pa - start) / HIB_PAGE_SIZE;
			return (0);
		}
		acc += (end - start) / HIB_PAGE_SIZE;
	}
	return (ENOENT);
}

/*
 * K23-T13: make the destructive copy skip a resume-side page-table page by
 * pointing its source-vector entry at the destination page itself.  The
 * trampoline copies one page per entry, so a self-copy is a no-op and the
 * page's contents survive; destination/source/run-table counts stay exactly
 * as the image declares them.
 */
static int
hibernate_md_selfcopy_page(const struct hibernate_attempt *ha,
    vm_paddr_t *vector, uint64_t vector_count, vm_paddr_t page, bool *did)
{
	uint64_t idx;
	int error;

	if (!hib_pa_in_dst_md(ha, page))
		return (0);
	error = hibernate_md_dst_page_index(ha, page, &idx);
	if (error != 0)
		return (error);
	if (idx >= vector_count)
		return (EINVAL);
	if (vector[idx] != page) {
		vector[idx] = page;
		*did = true;
	}
	return (0);
}

/*
 * K23-T13: walk va under root_pa and self-copy every page-table page
 * traversed.  Returns the number of pages made self-referential in *countp.
 *
 * copy_leaf controls whether the terminal leaf frame (the page va itself
 * resolves to, as opposed to the page-table pages used to reach it) is also
 * made self-referential.  This must be false for saved_pcb_va: that leaf is
 * the live struct pcb page resumectx() reads to resume the saved context,
 * and it must come back from the image's own saved content, not the resume
 * kernel's current, meaningless bytes at that physical address.  Making the
 * leaf self-referential there silently discards the saved PCB and produces
 * a bogus resume context with no trap.  Every other VA's leaf is either
 * arena-owned (categorically outside the destination set already),
 * overwritten again by the trampoline's own handoff copy regardless of its
 * pre-existing content, or an ordinary .text page whose bytes are expected
 * identical between the saved and resume kernel images, so self-copying
 * those leaves is harmless and keeps the fix narrowly scoped.
 */
static int
hibernate_md_selfcopy_walk(const struct hibernate_attempt *ha,
    vm_paddr_t *vector, uint64_t vector_count, vm_paddr_t root_pa,
    vm_offset_t va, bool copy_leaf, u_int *countp)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	pt_entry_t *pt;
	vm_paddr_t table_pa;
	uint64_t entry;
	u_int index;
	int error;
	bool did;

	did = false;
	table_pa = root_pa & PG_FRAME;
	if ((error = hibernate_md_selfcopy_page(ha, vector, vector_count,
		 table_pa, &did)) != 0)
		return (error);
	pml4 = (pml4_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	entry = pml4[index];
	if ((entry & X86_PG_V) == 0)
		return (0);
	table_pa = entry & PG_FRAME;
	if ((error = hibernate_md_selfcopy_page(ha, vector, vector_count,
		 table_pa, &did)) != 0)
		return (error);
	pdp = (pdp_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdp[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (0);
	table_pa = entry & PG_FRAME;
	if ((error = hibernate_md_selfcopy_page(ha, vector, vector_count,
		 table_pa, &did)) != 0)
		return (error);
	pd = (pd_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pd[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (0);
	table_pa = entry & PG_FRAME;
	if ((error = hibernate_md_selfcopy_page(ha, vector, vector_count,
		 table_pa, &did)) != 0)
		return (error);
	pt = (pt_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = pt[index];
	if ((entry & X86_PG_V) == 0)
		return (0);
	if (copy_leaf) {
		if ((error = hibernate_md_selfcopy_page(ha, vector,
			 vector_count, entry & PG_FRAME, &did)) != 0)
			return (error);
	}
	if (did)
		(*countp)++;
	return (0);
}

/*
 * Independently prove every mapping the private-domain trampoline may touch.
 * All arithmetic used to enumerate runs and arena/vector pages is checked.
 */
static int
hibernate_md_private_tree_validate(const struct hibernate_attempt *ha,
    const struct hibernate_md_run *runs, uint64_t run_count,
    const vm_paddr_t *vector, uint64_t vector_count, vm_paddr_t vector_pa,
    uint64_t vector_pages, vm_paddr_t xsave_pa, vm_paddr_t private_cr3)
{
	vm_paddr_t arena_end, pa, run_end;
	uint64_t bytes, i, j;

	if (__builtin_add_overflow(ha->ha_arena_start, ha->ha_arena_size,
		&arena_end))
		return (EOVERFLOW);
	for (pa = ha->ha_arena_start; pa < arena_end; pa += HIB_PAGE_SIZE) {
		if (!hibernate_md_walk_matches(private_cr3, pa, pa,
			X86_PG_V | X86_PG_RW))
			return (EINVAL);
	}

	for (i = 0; i < run_count; i++) {
		if (__builtin_mul_overflow(runs[i].hmr_count,
			(uint64_t)HIB_PAGE_SIZE, &bytes) ||
		    __builtin_add_overflow(runs[i].hmr_pa, bytes, &run_end))
			return (EOVERFLOW);
		for (pa = runs[i].hmr_pa; pa < run_end; pa += HIB_PAGE_SIZE) {
			if (!hibernate_md_walk_matches(private_cr3, pa, pa,
				X86_PG_V | X86_PG_RW))
				return (EINVAL);
		}
	}

	for (i = 0; i < vector_count; i++) {
		if (!hibernate_md_walk_matches(private_cr3, vector[i],
			vector[i], X86_PG_V | X86_PG_RW))
			return (EINVAL);
	}
	for (j = 0; j < vector_pages; j++) {
		if (__builtin_mul_overflow(j, (uint64_t)HIB_PAGE_SIZE,
			&bytes) ||
		    __builtin_add_overflow(vector_pa, bytes, &pa))
			return (EOVERFLOW);
		if (!hibernate_md_walk_matches(private_cr3, pa, pa,
			X86_PG_V | X86_PG_RW))
			return (EINVAL);
	}
	{
		struct hibernate_md_walk walk;

		if (!hibernate_md_tree_walk(private_cr3, xsave_pa, &walk) ||
		    walk.hmw_pa != xsave_pa ||
		    (walk.hmw_flags &
			(X86_PG_V | X86_PG_RW | X86_PG_U | X86_PG_NX)) !=
			(X86_PG_V | X86_PG_RW | X86_PG_NX))
			return (EINVAL);
	}
	return (0);
}

/* Independently re-walk and verify every saved-domain mapping. */
static int
hibernate_md_saved_domain_validate(vm_offset_t trampoline_saved_va,
    vm_paddr_t trampoline_stub_pa, vm_paddr_t handoff_source_pa,
    vm_offset_t saved_handoff_va, vm_offset_t saved_pcb_va,
    vm_offset_t restore_kernel_va)
{
	vm_paddr_t expected_pa[5];
	vm_offset_t va[5];
	uint64_t expected_flags[5];
	u_int i;

	/*
	 * Compute each expected PA independently of the page-table walk.
	 * The transition stub page, the handoff source and destination, and
	 * the PCB are writable kernel data.  hibernate_restore_kernel is
	 * kernel text and must be read-only.  All mappings must remain
	 * supervisor-only.
	 */
	va[0] = trampoline_saved_va;
	expected_pa[0] = trampoline_stub_pa;
	expected_flags[0] = X86_PG_V | X86_PG_RW;

	/*
	 * The post-CR3 rep movsb reads the encoded handoff record through its
	 * arena identity VA.  Prove that translation exists under the saved
	 * domain before the no-return boundary, rather than assuming slot 0
	 * covers it.
	 */
	va[1] = (vm_offset_t)handoff_source_pa;
	expected_pa[1] = handoff_source_pa;
	expected_flags[1] = X86_PG_V | X86_PG_RW;

	va[2] = saved_handoff_va;
	expected_pa[2] = vtophys((const void *)saved_handoff_va);
	expected_flags[2] = X86_PG_V | X86_PG_RW;

	va[3] = saved_pcb_va;
	expected_pa[3] = vtophys(&susppcbs[0]->sp_pcb);
	expected_flags[3] = X86_PG_V | X86_PG_RW;

	va[4] = restore_kernel_va;
	expected_pa[4] = vtophys((const void *)restore_kernel_va);
	expected_flags[4] = X86_PG_V;

	for (i = 0; i < nitems(va); i++) {
		if (!hibernate_md_walk_matches(kernel_pmap->pm_cr3, va[i],
			expected_pa[i], expected_flags[i])) {
			return (EINVAL);
		}
	}
	return (0);
}

/*
 * Compare a leaf page before and after one insertion.  The selected target
 * entry may change; every unrelated PTE must remain bit-for-bit identical.
 */
static bool
hibernate_md_leaf_diff_is_target_only(const pt_entry_t *before,
    const pt_entry_t *after, u_int target)
{
	u_int i;

	for (i = 0; i < NPTEPG; i++) {
		if (i != target && before[i] != after[i])
			return (false);
	}
	return (true);
}

/*
 * Replace one unmanaged 2 MiB identity PDE with a leaf table containing the
 * same 512 physical translations and effective leaf attributes.  This is
 * needed for the SAVE-side slot-0 identity map, which was deliberately built
 * from 2 MiB superpages before the stability barrier.
 *
 * The table is completely populated and checked before publication.  After
 * publication, an independent software walk proves that every VA in the
 * former superpage still resolves to the same PA.  Thus, demotion changes
 * only the representation of the mapping, not any translation.
 */
static int
hibernate_md_identity_demote(pd_entry_t *pde, vm_offset_t va,
    pt_entry_t **pte_out)
{
	struct hibernate_md_walk walk;
	pt_entry_t *pte;
	vm_page_t m_pt;
	vm_offset_t base_va, page_va;
	vm_paddr_t base_pa, expected_pa, table_pa;
	uint64_t leaf_flags, oldpde;
	u_int i;

	oldpde = *pde;
	if ((oldpde & (X86_PG_V | PG_PS)) != (X86_PG_V | PG_PS))
		return (EINVAL);
	if ((oldpde & PG_MANAGED) != 0)
		return (EINVAL);

	m_pt = pmap_page_alloc_below_4g(true);
	if (m_pt == NULL)
		return (ENOMEM);
	table_pa = VM_PAGE_TO_PHYS(m_pt);
	pte = (pt_entry_t *)PHYS_TO_DMAP(table_pa);

	base_va = va & ~(vm_offset_t)PDRMASK;
	base_pa = oldpde & PG_PS_FRAME;
	leaf_flags = oldpde &
	    ~(uint64_t)(PG_PS_FRAME | PG_PS | X86_PG_PDE_PAT | PG_PROMOTED);
	if ((oldpde & X86_PG_PDE_PAT) != 0)
		leaf_flags |= X86_PG_PTE_PAT;

	for (i = 0; i < NPTEPG; i++) {
		expected_pa = base_pa + (vm_paddr_t)i * PAGE_SIZE;
		pte[i] = expected_pa | leaf_flags;
		if ((pte[i] & PG_FRAME) != expected_pa ||
		    (pte[i] & ~PG_FRAME) != leaf_flags)
			return (EINVAL);
	}

	/*
	 * Intermediate PDE permissions must not narrow any former superpage
	 * access.  Leaf permissions and cache/PAT attributes remain in each
	 * PTE.
	 */
	*pde = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M |
	    (oldpde & X86_PG_U);

	if ((read_rflags() & PSL_I) != 0)
		pmap_invalidate_all(kernel_pmap);
	else
		invltlb_glob();

	for (i = 0; i < NPTEPG; i++) {
		page_va = base_va + (vm_offset_t)i * PAGE_SIZE;
		expected_pa = base_pa + (vm_paddr_t)i * PAGE_SIZE;
		if (!hibernate_md_tree_walk(kernel_pmap->pm_cr3, page_va,
			&walk) ||
		    walk.hmw_pa != expected_pa ||
		    (pte[i] & PG_FRAME) != expected_pa ||
		    (pte[i] & ~PG_FRAME) != leaf_flags)
			return (EINVAL);
	}

	*pte_out = pte;
	return (0);
}

/*
 * Install one exact 4 KiB mapping at
 *
 *     VA = slot * NBPML4 + pa
 *
 * in the saved kernel_pmap.  Missing intermediate tables are allocated.  A
 * pre-existing unmanaged identity superpage is first demoted into 512
 * translation-equivalent 4 KiB leaves; a conflicting mapping is rejected.
 * A complete before/after copy of the resulting leaf page proves that the
 * target insertion changes no unrelated PTE.
 */
static int
hibernate_md_identity_ensure(vm_paddr_t pa, u_int slot, vm_offset_t *va_out)
{
	pt_entry_t before[NPTEPG];
	vm_offset_t va;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	pt_entry_t *pte;
	vm_page_t m_pdp, m_pd, m_pt;
	vm_paddr_t table_pa;
	uint64_t entry;
	u_int pml4_idx, pdpt_idx, pd_idx, pt_idx;

	if ((pa & PAGE_MASK) != 0)
		return (EINVAL);
	if (__builtin_mul_overflow((vm_offset_t)slot, (vm_offset_t)NBPML4,
		&va) ||
	    __builtin_add_overflow(va, (vm_offset_t)pa, &va))
		return (EOVERFLOW);

	pml4_idx = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	pml4e = kernel_pmap->pm_pmltop;
	entry = pml4e[pml4_idx];
	if ((entry & X86_PG_V) == 0) {
		m_pdp = pmap_page_alloc_below_4g(true);
		if (m_pdp == NULL)
			return (ENOMEM);
		table_pa = VM_PAGE_TO_PHYS(m_pdp);
		pml4e[pml4_idx] = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
		entry = pml4e[pml4_idx];
	}
	if ((entry & PG_PS) != 0)
		return (EINVAL);
	pdpe = (pdp_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);

	pdpt_idx = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdpe[pdpt_idx];
	if ((entry & X86_PG_V) == 0) {
		m_pd = pmap_page_alloc_below_4g(true);
		if (m_pd == NULL)
			return (ENOMEM);
		table_pa = VM_PAGE_TO_PHYS(m_pd);
		pdpe[pdpt_idx] = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
		entry = pdpe[pdpt_idx];
	}
	if ((entry & PG_PS) != 0)
		return (EINVAL);
	pde = (pd_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);

	pd_idx = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pde[pd_idx];
	if ((entry & X86_PG_V) == 0) {
		m_pt = pmap_page_alloc_below_4g(true);
		if (m_pt == NULL)
			return (ENOMEM);
		table_pa = VM_PAGE_TO_PHYS(m_pt);
		pde[pd_idx] = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
		entry = pde[pd_idx];
	}
	if ((entry & PG_PS) != 0) {
		if ((entry & PG_PS_FRAME) != (pa & ~(vm_paddr_t)PDRMASK))
			return (EINVAL);
		int error;

		error = hibernate_md_identity_demote(&pde[pd_idx], va, &pte);
		if (error != 0)
			return (error);
	} else {
		pte = (pt_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);
	}

	pt_idx = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	__builtin_memcpy(before, pte, sizeof(before));
	entry = pte[pt_idx];
	if ((entry & X86_PG_V) != 0) {
		if ((entry & PG_FRAME) != pa)
			return (EINVAL);
		*va_out = va;
		return (0);
	}

	pte[pt_idx] = pa | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
	if (!hibernate_md_leaf_diff_is_target_only(before, pte, pt_idx)) {
		pte[pt_idx] = before[pt_idx];
		return (EINVAL);
	}
	if ((pte[pt_idx] & PG_FRAME) != pa ||
	    (pte[pt_idx] & (X86_PG_V | X86_PG_RW | X86_PG_U)) !=
		(X86_PG_V | X86_PG_RW)) {
		pte[pt_idx] = before[pt_idx];
		return (EINVAL);
	}

	if ((read_rflags() & PSL_I) != 0)
		pmap_invalidate_all(kernel_pmap);
	else
		invltlb_glob();

	*va_out = va;
	return (0);
}

/*
 * hibernate_md_patch_saved_domain: perform exactly the four saved-domain
 * lookups/insertions the issue requires (Design 036 S5.3).  trampoline_
 * saved_va and the saved PCB identity VA are inserted (if not already
 * present); hibernate_saved_handoff's VA and hibernate_restore_kernel's VA
 * are confirmed only, never inserted (ordinary kernel .bss/.text symbols,
 * already resident under the normal higher-half kernel map).
 */
static int
hibernate_md_patch_saved_domain(const struct hibernate_md_arena_layout *layout,
    vm_paddr_t trampoline_stub_pa, vm_offset_t *trampoline_saved_va,
    vm_offset_t *saved_pcb_va, vm_offset_t *saved_handoff_va,
    vm_offset_t *restore_kernel_va)
{
	vm_paddr_t pcb_pa;
	int error;

	/*
	 * 1. trampoline_saved_va: inserted.  This aliases the saved-domain
	 * *stub* page, not the entry page: the both-domain jump transfers
	 * control to this VA, and the stub is the page that must be executing
	 * there.
	 */
	error = hibernate_md_identity_ensure(trampoline_stub_pa,
	    HIBERNATE_MD_SAVED_SLOT, trampoline_saved_va);
	if (error != 0)
		return (error);

	/* 2. hibernate_saved_handoff's VA: confirmed only. */
	*saved_handoff_va = (vm_offset_t)&hibernate_saved_handoff;
	if (hibernate_md_identity_walk(*saved_handoff_va) == 0)
		return (EINVAL);

	/* 3. Saved PCB physical/identity VA: inserted. */
	if (susppcbs == NULL || susppcbs[0] == NULL)
		return (EINVAL);
	pcb_pa = vtophys(&susppcbs[0]->sp_pcb);
	/*
	 * hibernate_md_identity_ensure() maps one exact 4 KiB page and
	 * requires a page-aligned input PA; &susppcbs[0]->sp_pcb is an
	 * arbitrary field offset within its containing allocation, not
	 * page-aligned in general.  Ensure the *containing page* is
	 * identity-mapped (slot 0 contributes a zero VA offset, so the
	 * mapped page's VA equals its PA either way); the exact,
	 * sub-page-offset identity VA/PA equivalence below then holds for
	 * every address within that mapped page, including the unaligned
	 * pcb_pa itself.
	 */
	error = hibernate_md_identity_ensure(pcb_pa & ~(vm_paddr_t)PAGE_MASK, 0,
	    saved_pcb_va);
	if (error != 0)
		return (error);
	/*
	 * Slot 0 is the SAME slot hibernate_setup_identity_map() uses for its
	 * own low-4GiB map; reusing it here for a true identity VA (VA == PA,
	 * slot 0 contributes a zero offset) is deliberate -- the saved PCB's
	 * identity VA must equal its literal PA, not a slot-offset alias.
	 */
	*saved_pcb_va = pcb_pa;

	/* 4. hibernate_restore_kernel's VA: confirmed only. */
	*restore_kernel_va = (vm_offset_t)&hibernate_restore_kernel;
	if (hibernate_md_identity_walk(*restore_kernel_va) == 0)
		return (EINVAL);

	return (0);
}

/*
 * Validate one saved descriptor-table register value.  Issue #12 requires an
 * invalid descriptor table to be refused before the no-return boundary.  The
 * base must be canonical in the kernel half and the limit must describe at
 * least the mandatory descriptors; the covered range must not wrap.
 */
static bool
hibernate_md_dtr_valid(uint16_t limit, uint64_t base)
{
	uint64_t end;

	if (base >> 48 != 0xffff)
		return (false);
	if (limit < 7)
		return (false);
	if (__builtin_add_overflow(base, (uint64_t)limit, &end))
		return (false);
	return (end >= base);
}

int
hibernate_machdep_prepare(struct hibernate_attempt *ha)
{
	struct hibernate_md_arena_layout layout;
	struct hibernate_arena_header hah;
	struct hibernate_handoff_record hhr;
	struct hibernate_md_run *runs;
	vm_paddr_t vector_pa, xsave_pa, private_cr3, arena_end;
	vm_paddr_t trampoline_stub_pa;
	const vm_paddr_t *vector_va;
	vm_paddr_t *scratch;
	size_t vector_pages;
	uintptr_t trampoline_size;
	vm_offset_t trampoline_saved_va, saved_pcb_va, saved_handoff_va,
	    restore_kernel_va, trampoline_identity_va;
	uint64_t private_canary_len, private_canary_off;
	uint64_t private_leaf_pages;
	uint64_t run_canary_len, run_canary_off;
	uint64_t run_count, p;
	uint64_t di, phys_limit;
	bool refuse_la57, refuse_mtrr;
	uint8_t *header_buf, *handoff_buf, *trampoline_buf;
	int error;

	/* 1. Preconditions. */
	if (ha == NULL)
		return (EINVAL);
	if (!ha->ha_has_arena || !ha->ha_dst_valid)
		return (EINVAL);
	if (!ha->ha_has_safe_pages || ha->ha_staging == NULL)
		return (EINVAL);

	/* 2. Arena-bridge-boundary proof (Design 036 S5.8). */
	error = hibernate_md_arena_layout_compute(ha, &layout);
	if (error != 0)
		return (error);
	if (ha->ha_image.hi_cb.hc_arena_start != ha->ha_arena_start ||
	    ha->ha_image.hi_cb.hc_arena_size != ha->ha_arena_size) {
		return (EINVAL);
	}
	if (__builtin_add_overflow(ha->ha_arena_start, ha->ha_arena_size,
		&arena_end))
		return (EOVERFLOW);

	/*
	 * hibernate_setup_identity_map() is idempotent (its own
	 * map_initialized guard) and was previously only reached via the
	 * SAVE path's dumpsys_hibernate_savectx_preinit().  The RESUME
	 * path's kernel_pmap is a freshly booted kernel's own page tables
	 * and never otherwise gets this low-4GiB identity range: later
	 * identity-VA proofs in this function (hibernate_md_patch_saved_
	 * domain()/hibernate_md_saved_domain_validate(), which walk
	 * kernel_pmap directly, not the private CR3) require it to already
	 * exist.
	 *
	 * K23-T13: pass ha and layout.identity_map_pa (now computed just
	 * above) so every backing-page allocation below is drawn from the
	 * K-9 transition arena, disjoint from the K-10 destination set by
	 * construction, before the destructive copy can run; see
	 * hibernate_setup_identity_map()'s own comment for the root cause
	 * this closes (rule version 4).
	 */
	error = hibernate_setup_identity_map(ha, layout.identity_map_pa);
	if (error != 0)
		return (error);

	/* 3. CPU-state compatibility (unchanged call). */
	error = hibernate_amd64_cpu_validate(&ha->ha_image.hi_pcb, &refuse_la57,
	    &refuse_mtrr);
	if (error != 0)
		return (error);
	if (refuse_la57 || refuse_mtrr)
		return (EINVAL);

	/*
	 * K23-T06 arbitration verdict, "Ordered changes required" item 4:
	 * refuse unless this is the exact 2-vCPU topology K-23's AP park
	 * stub is scoped to (D040 SS1; verdict Q6 item 1).  Per-AP park
	 * slots are a separate design change this task does not implement.
	 * This refusal, and the one that follows, run pre-jump (inside
	 * hibernate_machdep_prepare()) and before any ipi_startup()
	 * dispatch, so both are phase-1 "goto cleanup" refusals, never a
	 * terminal halt/reset.
	 */
	if (mp_ncpus != 2) {
		printf("hibernate: K-23 AP park stub requires exactly 2 "
		       "CPUs (mp_ncpus %d); refusing\n",
		    mp_ncpus);
		return (ENOTSUP);
	}

	/*
	 * K23-T06 arbitration verdict item 5 (Q6 item 3): prove the claimed
	 * below-1-MiB park-stub page does not intersect any K-10 destination
	 * run.  The stub executes from this page while the BSP's K-10 copy
	 * is in flight; if the saved image's own destination set includes
	 * this physical page, the copy would overwrite live, currently
	 * executing AP code.  ha_park_stub_pa is claimed by
	 * hibernate_park_stub_claim(), called by the resume stage machine
	 * alongside hibernate_arena_claim() before this function runs.
	 */
	if (!ha->ha_has_park_stub || ha->ha_park_stub_pa == 0)
		return (EINVAL);
	for (di = 0; di < ha->ha_dst_count; di++) {
		if (ha->ha_park_stub_pa <
			ha->ha_dst_intervals[di * 2 + 1] &&
		    ha->ha_dst_intervals[di * 2] <
			ha->ha_park_stub_pa + HIBERNATE_PARK_STUB_BYTES) {
			printf("hibernate: K-23 park-stub page %#jx "
			       "intersects destination run [%#jx, %#jx); "
			       "refusing\n",
			    (uintmax_t)ha->ha_park_stub_pa,
			    (uintmax_t)ha->ha_dst_intervals[di * 2],
			    (uintmax_t)ha->ha_dst_intervals[di * 2 + 1]);
			return (EINVAL);
		}
	}

	/*
	 * K-10 source-page accessor (companion amendment,
	 * sys/kern/kern_hibernate.c).
	 */
	error = hibernate_staging_source_pages(ha, &vector_pa, &vector_va,
	    &vector_pages, &xsave_pa);
	if (error != 0)
		return (error);
	p = ha->ha_image.hi_destination_pages;

	/*
	 * The internal entry ABI carries the separately staged XSAVE identity
	 * address in %rsi.  Prove that it names the complete saved object: it
	 * is non-empty, 64-byte aligned, no larger than its sole staging page,
	 * and exactly matches both decoded-image and saved-PCB lengths.
	 */
	if ((xsave_pa & 63) != 0 || ha->ha_image.hi_xsave_length == 0 ||
	    ha->ha_image.hi_xsave_length > HIB_PAGE_SIZE ||
	    ha->ha_image.hi_xsave_length !=
		ha->ha_image.hi_pcb.hp_xsave_length) {
		return (EINVAL);
	}

	/*
	 * Physical-address-width compatibility (issue #12 refusal list).  Every
	 * physical address K-10 maps or dereferences must be representable in
	 * the CPU's supported physical-address width, so that no mapping or
	 * access is silently truncated by the hardware.
	 */
	if (cpu_maxphyaddr == 0 || cpu_maxphyaddr > 64)
		return (EINVAL);
	phys_limit = UINT64_C(1) << cpu_maxphyaddr;
	if ((uint64_t)arena_end > phys_limit ||
	    (uint64_t)xsave_pa >= phys_limit ||
	    (uint64_t)vector_pa + (uint64_t)vector_pages * HIB_PAGE_SIZE >
		phys_limit) {
		return (EINVAL);
	}
	for (di = 0; di < ha->ha_dst_count; di++) {
		if ((uint64_t)ha->ha_dst_intervals[di * 2 + 1] > phys_limit)
			return (EINVAL);
	}

	/*
	 * Descriptor-table validity (issue #12 refusal list): reject an
	 * invalid saved GDTR/IDTR before publishing it to the restore path.
	 */
	if (!hibernate_md_dtr_valid(ha->ha_image.hi_pcb.hp_gdtr_limit,
		ha->ha_image.hi_pcb.hp_gdtr_base) ||
	    !hibernate_md_dtr_valid(ha->ha_image.hi_pcb.hp_idtr_limit,
		ha->ha_image.hi_pcb.hp_idtr_base)) {
		return (EINVAL);
	}

	/* 4. Coalesced destination run table. */
	error = hibernate_md_build_run_table(ha, &layout, &run_count);
	if (error != 0)
		return (error);
	runs = (struct hibernate_md_run *)PHYS_TO_DMAP(layout.run_table_pa);

	/* 5.4 steps 1-3: overlap/disjointness canaries. */
	if (p > SIZE_MAX / sizeof(vm_paddr_t))
		return (EOVERFLOW);
	scratch = (vm_paddr_t *)malloc((size_t)p * sizeof(vm_paddr_t), M_TEMP,
	    M_NOWAIT);
	if (scratch == NULL)
		return (ENOMEM);
	error = hibernate_md_source_disjoint(vector_va, p, scratch, ha,
	    ha->ha_arena_start, arena_end);
	free(scratch, M_TEMP);
	if (error != 0)
		return (error);
	if (vector_pa >= ha->ha_arena_start && vector_pa < arena_end)
		return (EINVAL);
	if (xsave_pa >= ha->ha_arena_start && xsave_pa < arena_end)
		return (EINVAL);

	/* 5. Build the private CR3 tree. */
	error = hibernate_md_private_tree_build(ha, &layout, runs, run_count,
	    vector_va, p, vector_pa, (uint64_t)vector_pages, xsave_pa,
	    &private_cr3, &private_leaf_pages);
	if (error != 0)
		return (error);

	/*
	 * Copy the complete position-independent object into the arena.  The
	 * object spans three pages (entry page, both-domain CR3-load/jump page,
	 * saved-domain stub page); sizing the copy from the real linked extent
	 * binds C and assembly to one geometry instead of assuming a page
	 * count.  Any mismatch is refused here, before the first destructive
	 * write, rather than faulting inside the no-return region.
	 */
	trampoline_buf = (uint8_t *)PHYS_TO_DMAP(layout.trampoline_pa);
	if (__builtin_add_overflow(
		(uintptr_t)hibernate_tramp_end - (uintptr_t)hibernate_tramp_entry,
		(uintptr_t)(HIBERNATE_ARENA_ALIGNMENT - 1), &trampoline_size))
		return (EOVERFLOW);
	trampoline_size &= ~(uintptr_t)(HIBERNATE_ARENA_ALIGNMENT - 1);
	if (trampoline_size == 0 ||
	    trampoline_size > (uintptr_t)HIBERNATE_ARENA_TRAMPOLINE_BYTES) {
		return (E2BIG);
	}
	if ((uintptr_t)hibernate_tramp_both_domain_page <=
		(uintptr_t)hibernate_tramp_entry ||
	    (uintptr_t)hibernate_tramp_saved_domain_stub <=
		(uintptr_t)hibernate_tramp_both_domain_page ||
	    (uintptr_t)hibernate_tramp_end <=
		(uintptr_t)hibernate_tramp_saved_domain_stub) {
		return (EINVAL);
	}
	bcopy((const void *)hibernate_tramp_entry, trampoline_buf,
	    trampoline_size);
	trampoline_identity_va = (vm_offset_t)layout.trampoline_pa;
	trampoline_stub_pa = layout.trampoline_pa +
	    (vm_paddr_t)((uintptr_t)hibernate_tramp_saved_domain_stub -
	    (uintptr_t)hibernate_tramp_entry);
	if (trampoline_stub_pa + HIB_PAGE_SIZE >
	    layout.trampoline_pa + HIBERNATE_ARENA_TRAMPOLINE_BYTES) {
		return (E2BIG);
	}

	/*
	 * hibernate_md_patch_saved_domain(): exactly four lookups/insertions.
	 */
	error = hibernate_md_patch_saved_domain(&layout, trampoline_stub_pa,
	    &trampoline_saved_va, &saved_pcb_va, &saved_handoff_va,
	    &restore_kernel_va);
	if (error != 0)
		return (error);

	/* 6. Independently walk and validate both page-table domains. */
	error = hibernate_md_private_tree_validate(ha, runs, run_count,
	    vector_va, p, vector_pa, (uint64_t)vector_pages, xsave_pa,
	    private_cr3);
	if (error != 0)
		return (error);
	error = hibernate_md_saved_domain_validate(trampoline_saved_va,
	    trampoline_stub_pa, layout.handoff_pa, saved_handoff_va,
	    saved_pcb_va, restore_kernel_va);
	if (error != 0)
		return (error);

	/*
	 * K23-T13 (criterion 13): hibernate_md_saved_domain_validate() above
	 * proves each saved-domain VA's final translation, but not that the
	 * page-table PAGES kernel_pmap itself uses to reach that translation
	 * are disjoint from the K-10 destination set.  Directly observed
	 * this session: kernel_pmap's own permanent PML4[KPML4I]-rooted PDPT
	 * page -- the single PDPT page backing ALL FOUR of these VAs at
	 * once, since they are all ordinary kernel .text/.data/.bss symbols
	 * -- fell inside a K-10 destination run and was destructively
	 * overwritten before the terminal jump, silently losing kernel_
	 * pmap's own mapping for hibernate_restore_kernel with no trap,
	 * panic, or double fault (see hibernate_md_saved_domain_table_
	 * disjoint()'s own comment for the full root-cause account).  Prove
	 * the whole page-table path disjoint for every one of the four VAs,
	 * here, before the no-return boundary, instead of refusing nothing
	 * and crashing silently inside it.
	 */
	{
		vm_paddr_t *wvec;
		u_int selfcopied;

		/*
		 * K23-T13: the resume kernel's own page-table pages backing
		 * the handoff VAs can fall inside the destination set, which
		 * means the destructive copy would replace the tables the
		 * terminal step executes under (observed: kernel_pmap's own
		 * PML4[KPML4I] PDPT page going to an all-zero PDE, then a
		 * silent reset on the next fetch).  Destination counts are
		 * fixed by the image, so the pages cannot be dropped from the
		 * view; instead each such page is made self-referential in
		 * the source vector, which turns its copy into a no-op and
		 * leaves both the counts and the page's contents intact.
		 */
		wvec = (vm_paddr_t *)(uintptr_t)vector_va;
		selfcopied = 0;
		error = hibernate_md_selfcopy_walk(ha, wvec, p,
		    kernel_pmap->pm_cr3, trampoline_saved_va, true,
		    &selfcopied);
		if (error == 0)
			error = hibernate_md_selfcopy_walk(ha, wvec, p,
			    kernel_pmap->pm_cr3, (vm_offset_t)layout.handoff_pa,
			    true, &selfcopied);
		if (error == 0)
			error = hibernate_md_selfcopy_walk(ha, wvec, p,
			    kernel_pmap->pm_cr3, saved_handoff_va, true,
			    &selfcopied);
		if (error == 0)
			/*
			 * saved_pcb_va's leaf is the live struct pcb page
			 * resumectx() reads to resume the saved context: it
			 * must come back from the image, not be discarded in
			 * favour of the resume kernel's own current bytes at
			 * that PA.  Prove/self-copy its page-table path only.
			 */
			error = hibernate_md_selfcopy_walk(ha, wvec, p,
			    kernel_pmap->pm_cr3, saved_pcb_va, false,
			    &selfcopied);
		if (error == 0)
			error = hibernate_md_selfcopy_walk(ha, wvec, p,
			    kernel_pmap->pm_cr3, restore_kernel_va, true,
			    &selfcopied);
		if (error != 0)
			return (error);
		printf("hibernate: k23: %u saved-domain page-table page(s) "
		    "self-copied\n", selfcopied);
	}

	/*
	 * K23-T06 arbitration verdict item 3 (Q3): prove, rather than
	 * assume, that the K-23 park stub and arena park stack are both
	 * identity-mapped V|RW under the saved domain (kernel_pmap->pm_cr3)
	 * before the park stub can ever rely on either translation.  Both
	 * pages are expected to be covered by hibernate_setup_identity_map()'s
	 * PML4[0] 2 MiB identity leaves (installed on the save path and
	 * restored verbatim by the K-10 copy), but -- exactly as this
	 * function already does for the trampoline stub, handoff source,
	 * saved PCB, and restore-kernel VAs above -- that coverage is proven
	 * here, not assumed.  These are checks on the existing saved-domain
	 * tree built by hibernate_setup_identity_map(); no new mapping is
	 * installed for either page.  The stub page additionally must show
	 * PG_NX clear, since the park stub executes there.
	 */
	if (!hibernate_md_walk_matches(kernel_pmap->pm_cr3,
		(vm_offset_t)ha->ha_park_stub_pa, ha->ha_park_stub_pa,
		X86_PG_V | X86_PG_RW)) {
		printf("hibernate: K-23 park-stub page %#jx is not "
		       "identity-mapped V|RW under the saved domain; "
		       "refusing\n",
		    (uintmax_t)ha->ha_park_stub_pa);
		return (EIO);
	}
	{
		struct hibernate_md_walk stub_walk;

		if (!hibernate_md_tree_walk(kernel_pmap->pm_cr3,
			(vm_offset_t)ha->ha_park_stub_pa, &stub_walk) ||
		    (stub_walk.hmw_flags & X86_PG_NX) != 0) {
			printf("hibernate: K-23 park-stub page %#jx is "
			       "NX under the saved domain; refusing\n",
			    (uintmax_t)ha->ha_park_stub_pa);
			return (EIO);
		}
	}
	if (!hibernate_md_walk_matches(kernel_pmap->pm_cr3,
		(vm_offset_t)layout.park_stack_pa, layout.park_stack_pa,
		X86_PG_V | X86_PG_RW)) {
		printf("hibernate: K-23 arena park-stack page %#jx is not "
		       "identity-mapped V|RW under the saved domain; "
		       "refusing\n",
		    (uintmax_t)layout.park_stack_pa);
		return (EIO);
	}

	/*
	 * Compare through the actual private identity and saved-domain virtual
	 * aliases.  Mapping validation above independently proved the identity
	 * alias resolves to layout.trampoline_pa and the saved alias resolves
	 * to the stub page, both with kernel RW permissions.
	 */
	if (bcmp((const void *)hibernate_tramp_entry, trampoline_buf,
		trampoline_size) != 0 ||
	    bcmp((const void *)hibernate_tramp_entry,
		(const void *)trampoline_identity_va, trampoline_size) != 0 ||
	    bcmp((const void *)hibernate_tramp_saved_domain_stub,
		(const void *)trampoline_saved_va, HIB_PAGE_SIZE) != 0) {
		return (EINVAL);
	}

	/*
	 * Compute both additional canary ranges before any canary write.
	 * The active run entries and active page-table pages remain untouched.
	 */
	if (__builtin_mul_overflow(run_count, (uint64_t)sizeof(*runs),
		&run_canary_off) ||
	    __builtin_mul_overflow(layout.run_table_max - run_count,
		(uint64_t)sizeof(*runs), &run_canary_len))
		return (EOVERFLOW);
	if (private_leaf_pages > HIBERNATE_ARENA_PT_LEAF_PAGES)
		return (EINVAL);
	if (__builtin_add_overflow((uint64_t)(HIBERNATE_ARENA_PT_PML4_PAGES +
				       HIBERNATE_ARENA_PT_PDPT_PAGES +
				       HIBERNATE_ARENA_PT_PD_PAGES),
		private_leaf_pages, &private_canary_off) ||
	    __builtin_mul_overflow(private_canary_off, (uint64_t)HIB_PAGE_SIZE,
		&private_canary_off) ||
	    __builtin_mul_overflow((uint64_t)HIBERNATE_ARENA_PT_LEAF_PAGES -
		    private_leaf_pages,
		(uint64_t)HIB_PAGE_SIZE, &private_canary_len))
		return (EOVERFLOW);

	/*
	 * 7. Guard only unused storage tails.  Header, trampoline, stack,
	 * handoff, active runs, and active paging structures remain pristine
	 * because they are subsequently encoded, executed, or consumed.
	 */
	if (run_canary_len >= 16)
		hibernate_md_canary_write(layout.run_table_pa + run_canary_off,
		    run_canary_len);
	if (private_canary_len >= 16)
		hibernate_md_canary_write(layout.private_pt_pa +
			private_canary_off,
		    private_canary_len);

	/*
	 * All fallible preconditions and validation checks precede header
	 * encoding, including the dumper requirement used by the handoff.
	 */
	if (ha->ha_dumper == NULL)
		return (EINVAL);

	/* 8. Encode the handoff record, then the arena header last. */
	__builtin_memset(&hhr, 0, sizeof(hhr));
	hhr.hhr_magic = HIBERNATE_HANDOFF_MAGIC;
	hhr.hhr_version = HIBERNATE_HANDOFF_VERSION;
	hhr.hhr_encoded_size = HIBERNATE_HANDOFF_ENCODED_SIZE;
	__builtin_memcpy(hhr.hhr_provider_name, ha->ha_dumper->provider_name,
	    sizeof(hhr.hhr_provider_name));
	hhr.hhr_provider_media_size = ha->ha_provider_size;
	hhr.hhr_provider_writable = 1;
	hhr.hhr_marker_offset = (uint64_t)ha->ha_marker_offset;
	hhr.hhr_image_offset = ha->ha_image.hi_cb.hc_payload_start;
	hhr.hhr_image_length = ha->ha_image.hi_cb.hc_image_length;
	hhr.hhr_marker_sequence = 0;
	hhr.hhr_marker_state = (uint32_t)ha->ha_marker_result.marker.hm_state;
	hhr.hhr_completion_provider_acquired = ha->ha_has_provider ? 1 : 0;
	hhr.hhr_completion_consumer_attached = 0;

	handoff_buf = (uint8_t *)PHYS_TO_DMAP(layout.handoff_pa);
	error = hibernate_handoff_record_encode(handoff_buf,
	    HIBERNATE_HANDOFF_ENCODED_SIZE, &hhr);
	if (error != 0)
		return (error);

	__builtin_memset(&hah, 0, sizeof(hah));
	hah.hah_magic = HIBERNATE_ARENA_HEADER_MAGIC;
	hah.hah_version = HIBERNATE_ARENA_HEADER_VERSION;
	hah.hah_header_size = HIBERNATE_ARENA_HEADER_ENCODED_SIZE;
	hah.hah_arena_pa = ha->ha_arena_start;
	hah.hah_arena_size = ha->ha_arena_size;
	hah.hah_private_cr3_pa = private_cr3;
	hah.hah_saved_cr3_pa = kernel_pmap->pm_cr3;
	hah.hah_trampoline_pa = layout.trampoline_pa;
	hah.hah_trampoline_identity_va = trampoline_identity_va;
	hah.hah_trampoline_saved_va = trampoline_saved_va;
	hah.hah_arena_stack_pa = layout.stack_pa;
	hah.hah_arena_stack_size = HIBERNATE_ARENA_STACK_BYTES;
	hah.hah_source_vector_pa = vector_pa;
	hah.hah_first_destination_pa = run_count != 0 ? runs[0].hmr_pa : 0;
	hah.hah_destination_page_count = p;
	hah.hah_iterator_pa = layout.run_table_pa;
	hah.hah_handoff_record_pa = layout.handoff_pa;
	hah.hah_saved_handoff_va = saved_handoff_va;
	hah.hah_saved_pcb_va = saved_pcb_va;
	hah.hah_restore_kernel_va = restore_kernel_va;
	hah.hah_saved_cr0 = ha->ha_image.hi_pcb.hp_cr0;
	hah.hah_saved_cr4 = ha->ha_image.hi_pcb.hp_cr4;
	hah.hah_saved_efer = ha->ha_image.hi_pcb.hp_efer;
	hah.hah_saved_pat = ha->ha_image.hi_pcb.hp_pat;
	hah.hah_saved_xcr0 = ha->ha_image.hi_pcb.hp_xcr0;
	hah.hah_gdtr.hap_limit = ha->ha_image.hi_pcb.hp_gdtr_limit;
	hah.hah_gdtr.hap_base = ha->ha_image.hi_pcb.hp_gdtr_base;
	hah.hah_idtr.hap_limit = ha->ha_image.hi_pcb.hp_idtr_limit;
	hah.hah_idtr.hap_base = ha->ha_image.hi_pcb.hp_idtr_base;
	hah.hah_instruction_page_pa = layout.trampoline_pa;
	hah.hah_terminal_flags = 0;
	hah.hah_saved_entry_rsp = 0;
	/*
	 * The terminal assembly copies exactly this many bytes into
	 * hibernate_saved_handoff.  Leaving it zero silently suppressed the
	 * whole by-value handoff, so it is set from the canonical encoded
	 * width and is the only accepted value.
	 */
	hah.hah_handoff_length = HIBERNATE_HANDOFF_ENCODED_SIZE;

	header_buf = (uint8_t *)PHYS_TO_DMAP(layout.header_pa);
	error = hibernate_arena_header_encode(header_buf,
	    HIBERNATE_ARENA_HEADER_ENCODED_SIZE, &hah);
	if (error != 0)
		return (error);

	/*
	 * K23-T06 arbitration verdict item 6 (D040 SS8.3): write the K-23 AP
	 * park stub image and its parameter block into the reserved,
	 * already-claimed, already-identity-proven below-1-MiB stub page via
	 * PHYS_TO_DMAP(), mirroring this function's own trampoline-copy
	 * pattern above.  Initialise the park-state word -- the first 8
	 * bytes of the just-encoded header's hah_reserved_0f0 -- to
	 * {sequence = 1, state = WAITING}, leaving bytes [8:16] zero exactly
	 * as hibernate_arena_header_encode() already left them via its own
	 * initial zero-fill (that function does not itself encode
	 * hah_reserved_0f0; this is the sole writer of its first 8 bytes).
	 */
	{
		uint8_t *park_buf;
		uint64_t park_state_pa, park_stack_top;
		u_int park_cpu;

		if (hibernate_park_tramp_size == 0 ||
		    hibernate_park_tramp_size > HIBERNATE_PARK_STUB_BYTES)
			return (E2BIG);
		park_buf = (uint8_t *)PHYS_TO_DMAP(ha->ha_park_stub_pa);
		bcopy((const void *)hibernate_park_tramp_start, park_buf,
		    hibernate_park_tramp_size);

		/*
		 * mp_ncpus == 2 is already enforced above; the sole AP is
		 * the one cpu id below mp_ncpus that is not this, currently
		 * executing, BSP.
		 */
		for (park_cpu = 0; park_cpu < (u_int)mp_ncpus; park_cpu++) {
			if (park_cpu != PCPU_GET(cpuid))
				break;
		}
		if (park_cpu >= (u_int)mp_ncpus)
			return (EINVAL);

		park_state_pa = layout.header_pa +
		    HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0;
		park_stack_top = layout.park_stack_pa +
		    HIBERNATE_ARENA_PARK_STACK_BYTES;

		le64enc(park_buf + HIBERNATE_PARK_TRAMP_PARAM_STATE_PA,
		    park_state_pa);
		le64enc(park_buf + HIBERNATE_PARK_TRAMP_PARAM_STACK_TOP_PA,
		    park_stack_top);
		le64enc(park_buf + HIBERNATE_PARK_TRAMP_PARAM_HEADER_PA,
		    layout.header_pa);
		le64enc(park_buf + HIBERNATE_PARK_TRAMP_PARAM_SAVED_CR3_PA,
		    kernel_pmap->pm_cr3);
		le32enc(park_buf + HIBERNATE_PARK_TRAMP_PARAM_EXPECTED_SEQ, 1);
		le32enc(park_buf + HIBERNATE_PARK_TRAMP_PARAM_CPU, park_cpu);

		le32enc(header_buf + HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0,
		    1);
		le32enc(header_buf + HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0 +
			4,
		    HIBERNATE_PARK_WAITING);
	}

	/*
	 * Final prepare-to-enter integrity proof.  The executable page must
	 * equal the linked source through the direct map and both validated
	 * aliases.  Check unused-tail guards only after all encoders and
	 * page-table writes have completed.
	 */
	if (bcmp((const void *)hibernate_tramp_entry, trampoline_buf,
		trampoline_size) != 0 ||
	    bcmp((const void *)hibernate_tramp_entry,
		(const void *)trampoline_identity_va, trampoline_size) != 0 ||
	    bcmp((const void *)hibernate_tramp_saved_domain_stub,
		(const void *)trampoline_saved_va, HIB_PAGE_SIZE) != 0 ||
	    (run_canary_len >= 16 &&
		!hibernate_md_canary_check(layout.run_table_pa + run_canary_off,
		    run_canary_len)) ||
	    (private_canary_len >= 16 &&
		!hibernate_md_canary_check(layout.private_pt_pa +
			private_canary_off,
		    private_canary_len)))
		return (EINVAL);

	hibernate_md_xsave_pa = xsave_pa;
	hibernate_md_arena_header_pa = layout.header_pa;
	/*
	 * Publish the arena identity address of the entry only now that every
	 * check has passed: the terminal jump must land in the prepared arena
	 * copy, not in linked high-half text that the private tree does not map.
	 */
	hibernate_md_trampoline_entry_va = trampoline_identity_va;

	/* 9. Success. */
	return (0);
}

void
hibernate_machdep_enter(void)
{
	/*
	 * hibernate_amd64_cpu_validate() deliberately excludes CR0_TS from
	 * its saved/live CR0 comparison (ordinary lazy-FPU handling may
	 * legitimately leave it set).  The K-10 trampoline's XRSTOR64 never
	 * touches CR0 and has no fault recovery, so a live TS=1 here raises
	 * #NM at that XRSTOR64 with no IDT mapped under the private tree,
	 * producing a triple fault.  Clear it unconditionally right before
	 * the no-return jump so the trampoline's XRSTOR64 always executes
	 * with TS=0, regardless of what state hibernate_stop_cpus()/
	 * intr_disable() left behind.
	 */
	clts();

	__asm__ __volatile__("movq %0, %%rdi\n\t"
			     "movq %1, %%rsi\n\t"
			     "jmp *%2"
	    :
	    : "m"(hibernate_md_arena_header_pa), "m"(hibernate_md_xsave_pa),
	      "r"(hibernate_md_trampoline_entry_va)
	    : "rdi", "rsi");
	__builtin_unreachable();
}
#endif /* !_HIBERNATE_LEAF_REQUIREMENT_TEST */
