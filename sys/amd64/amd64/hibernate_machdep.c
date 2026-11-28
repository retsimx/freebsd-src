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
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/timetc.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <vm/vm_pagequeue.h>
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
 * __stack_chk_guard's own genuine
 * staged-image content, captured by hibernate_machdep_prepare() (this
 * file) immediately after its own source vector becomes valid, for
 * hibernate_resume_attempt() (sys/kern/kern_hibernate.c) to install
 * into the live __stack_chk_guard[0] AFTER hibernate_machdep_prepare()
 * has itself already returned -- see hibernate_machdep_prepare()'s own
 * hib_guard_image_value local-variable comment for why installing it
 * from inside that function's own body panicked that function's own
 * currently-executing frame (reproduced 3/3) and was reverted there.
 */
uint64_t hib_guard_image_value_g;
bool hib_guard_captured_g;

/*
 * DSA00 "keg topology" round: staged (saved-image) copies of every
 * keg's own three per-domain slab-list HEAD pointers (ud_part_slab.
 * lh_first / ud_free_slab.lh_first / ud_full_slab.lh_first,
 * sys/vm/uma_int.h's LIST_HEAD(slabhead, uma_slab) -- lh_first is the
 * ONLY field in a list head), captured during hibernate_machdep_prepare()
 * (this function, below) via hibernate_md_staged_read() -- the existing,
 * already-proven staged-byte accessor the K-10 copy loop itself uses --
 * strictly BEFORE the destructive copy runs, so the read itself takes no
 * lock and calls nothing that could (same safety class as the
 * __stack_chk_guard capture immediately above). Published to these
 * file-scope globals for uma_hibernate_reinit_plinks() (sys/vm/
 * uma_core.c) to consume AFTER the jump, on the resume continuation,
 * exactly mirroring the hib_guard_image_value_g/hib_guard_captured_g
 * publish-then-install split this file already establishes for the
 * identical "must read image content at MD_PREPARE time, must use it
 * only after the jump" shape.
 *
 * Bounded by HIB_KEG_TOPO_MAX_KEGS * MAXMEMDOM * 3 uintptr_t slots -- a
 * fixed-size array, no allocation, matching the "no allocation in the
 * hot path" requirement. A keg beyond this bound, or a domain beyond
 * vm_ndomains, is simply not captured (hib_keg_topo_captured_n records
 * exactly how many kegs WERE captured, so the consumer can detect and
 * report the shortfall rather than silently using stale/zero data).
 */
/*
 * DSA00 "keg topology" round, correction (N=1 re-verification): the
 * initial bound of 64 was too small -- live testing showed topo_oob=125
 * (100% of consumer calls falling back), i.e. this boot's own actual
 * VTOSLAB keg count exceeds 64 (inline_skipped=80 alone, from a SEPARATE,
 * non-VTOSLAB keg class, already proves this kernel has well over 100
 * kegs total). Raised to 512, a generous bound for any GENERIC-class
 * kernel config, still only 512*8*3*8 = 98304 bytes = 24 pages -- small,
 * fixed-size, no allocation.
 */
#define	HIB_KEG_TOPO_MAX_KEGS	512
uintptr_t hib_keg_topo_head_g[HIB_KEG_TOPO_MAX_KEGS][MAXMEMDOM][3];
u_int hib_keg_topo_captured_n_g;
bool hib_keg_topo_captured_g;

/*
 * K24-T00 thread provenance: every staged thread's own td_pcb page
 * number (vm_offset_t >> PAGE_SHIFT), captured pre-copy in
 * hibernate_machdep_prepare() from the SAME enumeration pass that
 * already walks pidhashtbl (hibernate_md_enumerate_staged_threads()),
 * deduplicated. Bounded by HIB_STAGED_MAX_THREADS (256) -- the same
 * cap the enumeration itself already uses, so this array can never be
 * smaller than the set it is built from. Self-copy-protected
 * (copy_leaf=true) immediately after being populated, for the same
 * reason as hib_keg_topo_head_g above: the correct content is THIS
 * boot's own just-captured values (the image's thread set as this
 * resume continuation enumerated it), never the saved image's stale
 * content for these same global addresses.
 *
 * hibernate_k24t00_pcb_is_staged() is the sole reader, called from the
 * switch-time marker site (cpu_switch.S) with the PCB page number
 * already being loaded for done_load_dr's existing marker -- answering
 * exactly one question: is the thread about to be switched to one this
 * boot's own enumeration accepted as part of the image, or not.
 */
#define HIB_STAGED_PCB_PAGE_MAX 256	/* Matches HIB_STAGED_MAX_THREADS. */
u_long k24t00_staged_pcb_page_g[HIB_STAGED_PCB_PAGE_MAX];
u_int k24t00_staged_pcb_page_n_g;

int hibernate_k24t00_pcb_is_staged(u_long pcb_page_number);
int
hibernate_k24t00_pcb_is_staged(u_long pcb_page_number)
{
	u_int i;

	for (i = 0; i < k24t00_staged_pcb_page_n_g; i++) {
		if (k24t00_staged_pcb_page_g[i] == pcb_page_number)
			return (1);
	}
	return (0);
}

/*
 * K24-T00: the switch-time 'c' marker (cpu_switch.S) already compares
 * %cr3 against PCPU(KCR3)/PCPU(UCR3), but a prior round proved both
 * read the "PTI disabled" sentinel (~0) on the faulting AP -- those
 * fields were never populated on this CPU, so the comparison proved
 * nothing about where %cr3 actually points. The one root known to be
 * correctly configured is kernel_pmap->pm_cr3 itself; this accessor
 * hands the marker site its page number (not the raw value, to match
 * the page-number-only values the marker already emits for %cr3),
 * called exactly once per burst so the marker's own cost stays
 * bounded.
 */
u_long hibernate_k24t00_kern_pmap_cr3_page(void);
u_long
hibernate_k24t00_kern_pmap_cr3_page(void)
{
	return (kernel_pmap->pm_cr3 >> 12);
}

/*
 * K24-T00 round 4: CR3 was proven correct and the verifier proved the
 * target kstack page present, yet the write at "movq %rax,(%rsp)"
 * still not-present-faults. The next instruction after that write is
 * "movq %gs:0x0,%rdi" (PCPU(CURTHREAD)) -- a GS-relative read. This
 * kernel loads the ACTIVE gs base directly via
 * wrmsr(MSR_GSBASE,(u_int64_t)pc) for every CPU (see mp_machdep.c's
 * init_secondary() and machdep.c's initializecpu() call sites); there
 * is no intervening swapgs between done_load_dr and this read, so
 * rdmsr(MSR_GSBASE) here returns exactly the base %gs:0x0 would use.
 * Three bounded accessors, each called once per burst:
 *   - this AP's own active GS-base page number;
 *   - whether that GS-base VA resolves through kernel_pmap (reuses
 *     hib_md_safe_resolve(), the same walker the kstack verifier
 *     itself already relies on -- not a new resolution mechanism);
 *   - the BSP's own GS-base page number, for contrast: since GSBASE is
 *     set to the PCPU pointer itself on every CPU (including the
 *     BSP), cpuid_to_pcpu[0] IS that value -- no cross-CPU MSR read
 *     needed, none is possible without an IPI anyway.
 */
u_long hibernate_k24t00_gsbase_page(void);
u_long
hibernate_k24t00_gsbase_page(void)
{
	return (rdmsr(MSR_GSBASE) >> 12);
}

static bool hib_md_safe_resolve(vm_paddr_t root_pa, vm_offset_t va,
    vm_paddr_t *pa_out);

int hibernate_k24t00_gsbase_present(void);
int
hibernate_k24t00_gsbase_present(void)
{
	vm_paddr_t pa;

	return (hib_md_safe_resolve(kernel_pmap->pm_cr3,
	    (vm_offset_t)rdmsr(MSR_GSBASE), &pa) ? 1 : 0);
}

u_long hibernate_k24t00_bsp_gsbase_page(void);
u_long
hibernate_k24t00_bsp_gsbase_page(void)
{
	return ((u_long)cpuid_to_pcpu[0] >> 12);
}

/*
 * K24-T00 round 3: independent pid/tid staged-set lookups, built from
 * the SAME enumeration pass (threads[]/nthreads in hibernate_machdep_
 * prepare(), below) but keyed differently (pid, tid) instead of PCB
 * page number. This is the decisive cross-check the task asks for: if
 * a thread's pid/tid show up here as staged while
 * hibernate_k24t00_pcb_is_staged() says its PCB page is NOT staged,
 * the two lookups were built from the identical source list but
 * disagree -- proving the bug is in the PCB-page bookkeeping
 * specifically (an off-by-one, wrong page shift, or divergent
 * dedup/bounds logic), not in the enumeration or in whether the
 * thread is genuinely part of the image.
 */
/*
 * K24-T00 round 3: sized with HIB_STAGED_PCB_PAGE_MAX, not
 * HIB_STAGED_MAX_THREADS directly -- the latter is #defined later in
 * this file (hibernate_md_enumerate_staged_threads()'s own region),
 * after this point; HIB_STAGED_PCB_PAGE_MAX is already in scope here
 * and is documented above as matching it (both are 256).
 */
pid_t k24t00_staged_pid_g[HIB_STAGED_PCB_PAGE_MAX];
u_int k24t00_staged_pid_n_g;
lwpid_t k24t00_staged_tid_g[HIB_STAGED_PCB_PAGE_MAX];
u_int k24t00_staged_tid_n_g;
lwpid_t k24t00_staged_tid_max_g;

int hibernate_k24t00_pid_is_staged(pid_t pid);
int
hibernate_k24t00_pid_is_staged(pid_t pid)
{
	u_int i;

	for (i = 0; i < k24t00_staged_pid_n_g; i++) {
		if (k24t00_staged_pid_g[i] == pid)
			return (1);
	}
	return (0);
}

int hibernate_k24t00_tid_is_staged(lwpid_t tid);
int
hibernate_k24t00_tid_is_staged(lwpid_t tid)
{
	u_int i;

	for (i = 0; i < k24t00_staged_tid_n_g; i++) {
		if (k24t00_staged_tid_g[i] == tid)
			return (1);
	}
	return (0);
}

/*
 * K24-T00: post-copy PTE probe sample set. Captured pre-copy, during
 * hibernate_machdep_prepare() (this file, below) -- slot 0 is the BSP's
 * own continuation stack VA (the known-good control: if this one reads
 * wrong post-copy, something is broken everywhere, not just for
 * ordinary threads); slots 1/2 are two ordinary staged threads'
 * (syslogd/devd) kstack VAs, the same two pids already targeted by the
 * existing per-thread instrumentation above. Published to these
 * file-scope globals, self-copy-protected below exactly like
 * hib_guard_image_value_g/hib_keg_topo_head_g above, so the resume
 * continuation can read them AFTER the destructive copy to decide what
 * each sampled VA's live page table actually contains at that point --
 * a question never asked post-copy before this round.
 */
vm_offset_t k24t00_probe_va_g[3];
vm_paddr_t k24t00_probe_expected_pa_g[3];
bool k24t00_probe_set_g[3];
pid_t k24t00_probe_pid_g[3];

/*
 * K24-T00: switch-time CR3/stack marker budget. A plain global, not
 * self-copy-protected and not relied upon to survive the destructive
 * copy with any particular pre-copy value -- it is reinitialised
 * fresh, post-copy, in hibernate_resume_ap_entry() below (the same
 * "dynamic state must be reinitialised, not trusted across the
 * discontinuity" discipline already applied to tdq_runq/td_lock/
 * tdq_curthread in this same function), so its content before that
 * reinit is irrelevant. Shared between the cpu_switch.S marker site
 * and the pmap_activate_sw() skip/load marker site (sys/amd64/amd64/
 * pmap.c) purely to bound total emission volume across both; each
 * site's own gate (cpuid != 0) already restricts emission to the
 * sole AP on this mp_ncpus==2 harness.
 */
volatile u_int k24t00_swmark_budget_g;

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
void	tdq_curthread_reseed(struct thread *td);
void	tdq_runq_hibernate_reinit(void);

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
	/*
	 * The idle thread entering here is not continuing a captured
	 * snapshot context -- unlike the BSP's own continuing thread,
	 * which does carry a stale, mid-dump-worker nesting count that
	 * must be discarded (acpi_s4_resume_bsp_cpu(), acpi.c;
	 * hibernate_barrier_unwind() Stage 7, kern_hibernate.c) -- this AP
	 * is deliberately treated as entering fresh, exactly like
	 * init_secondary_tail()'s own cold-boot path, and should inherit
	 * that path's own invariant instead of the BSP's.  A direct,
	 * physical-marker-based comparison of a genuine cold-boot AP
	 * against this resumed AP, both captured at the identical point
	 * (sched_ap_entry() entry), found every other field identical
	 * except these two: a working cold-boot AP reads td_critnest == 1
	 * and td_md.md_spinlock_count == 1 here, matching the universal
	 * thread-creation invariant every idle thread is given at
	 * cpu_fork() time ("Setup to release spin count in fork_exit()",
	 * sys/amd64/amd64/vm_machdep.c) and which persists untouched until
	 * the thread's own first real scheduler entry.  sched_ap_entry()
	 * (called a few lines below) ends in sched_throw(NULL), whose
	 * first-CPU-entry path unconditionally asserts
	 * KASSERT(curthread->td_md.md_spinlock_count == 1, ...) -- not
	 * optional cleanup, but the exact precondition this call requires.
	 * Confirmed by direct test: with these fields at 0, "panic: invalid
	 * count 0" fired inside this exact first-entry path on a genuine,
	 * physically-verified correct AP; with 1, the assert is satisfied
	 * by construction.
	 */
	curthread->td_critnest = 1;
	curthread->td_md.md_spinlock_count = 1;

	if (fred)
		amd64_cpu_init_fred();
	else
		lidt(&r_idt);

	amd64_cpu_init_msr_memctl();

	/*
	 * LTR sets the loaded TSS descriptor's busy bit, and this CPU's
	 * descriptor was already ltr()'d once by init_secondary() at its own
	 * cold boot: INIT resets the processor, not the GDT page.  Clear the
	 * busy bit first, matching cpu_switch.S's "Clear task busy bit and
	 * reload TR" idiom, or this second LTR raises #GP.
	 */
	pc->pc_tss->sd_type = SDT_SYSTSS;
	ltr(GSEL(GPROC0_SEL, SEL_KPL));

	amd64_conf_fast_syscall();

	lapic_xapic_mode();
	mca_init();
	lapic_setup(1);

	/*
	 * The idle thread's td_pcb still holds the switch-out context
	 * recorded in the saved image.  At save time the AP was stopped by
	 * IPI while running its idle thread (that context went to
	 * stoppcbs/susppcbs, not td_pcb), so td_pcb names an older
	 * cpu_switch() return inside sched_switch() whose stack frames the
	 * idle loop has since reused; cpu_throw() would resume there.
	 * Re-seed the pcb as cpu_fork() + cpu_fork_kthread_handler() did at
	 * idle-thread creation, so the AP enters sched_idletd() fresh via
	 * fork_trampoline, as a cold-boot AP does.
	 */
	{
		struct thread *itd;
		struct pcb *ipcb;

		itd = pc->pc_idlethread;
		ipcb = itd->td_pcb;
		ipcb->pcb_r12 = (register_t)sched_idletd;
		ipcb->pcb_rbx = 0;
		ipcb->pcb_rbp = 0;
		ipcb->pcb_rsp = (register_t)itd->td_frame - sizeof(void *);
		ipcb->pcb_rip = (register_t)fork_trampoline;
		clear_pcb_flags(ipcb, PCB_FPUINITDONE | PCB_USERFPUINITDONE |
		    PCB_KERNFPU | PCB_KERNFPU_THR);
	}
	/*
	 * Sibling defect to the pcb reseed above.  pc_monitorbuf.idle_state
	 * lives in this same one-page per-CPU leaf as pc_gdt, which this
	 * file's own copy_leaf=true fix correctly preserves as this boot's
	 * own, already-live value -- but that value is whatever this exact
	 * physical AP's idle_state held at the instant
	 * hibernate_park_dispatch()'s ipi_startup() (an INIT-SIPI-SIPI,
	 * which resets the AP's registers but not its pcpu memory) pulled
	 * it out of its own normal cpu_idle_acpi()/cpu_idle_mwait() loop on
	 * this same boot -- not necessarily STATE_RUNNING.
	 * cpu_idle_enter()'s own KASSERT requires STATE_RUNNING on entry;
	 * the path below is, matching the pcb reseed just above, a fresh
	 * scheduler entry exactly like init_secondary_tail()'s own
	 * cold-boot path, which never calls cpu_idle_enter() with anything
	 * but a freshly zero-initialized (STATE_RUNNING) monitorbuf.
	 * Confirmed by direct test: "panic: cpu_idle_enter: state 2" fired
	 * immediately downstream of the pcb reseed above succeeding --
	 * state 2 is STATE_SLEEPING, consistent with this AP having been
	 * mid-"hlt" in its own pre-park cpu_idle_acpi() call when the SIPI
	 * redirected it.
	 */
	pc->pc_monitorbuf.idle_state = 0; /* STATE_RUNNING, cpu_machdep.c */
	/*
	 * Reproduce the cold-boot scheduler-entry invariant this path was
	 * missing: init_secondary_tail() calls sched_init_ap() immediately
	 * before sched_ap_entry(), which (via sched_ule_init_ap())
	 * establishes PCPU(sched) and derives the idle thread's own
	 * td_lock from it (TDQ_LOCKPTR(TDQ_SELF())).  td_lock is per-thread
	 * saved-image content, restored byte-for-byte by the K-10 copy,
	 * carrying whichever lock (if any) the SAVE kernel's own idle
	 * thread happened to be blocked on at suspend time, not this
	 * boot's own tdq lock -- sched_ule_ap_entry()'s own comment
	 * documents this exact precondition ("This should have been setup
	 * in sched_init_ap()") immediately before an assert that otherwise
	 * fails.  sched_init_ap() is two idempotent pointer writes with no
	 * allocation and no hardware side effect; calling it here, once,
	 * before sched_ap_entry(), reproduces the missing cold-boot step.
	 */
	sched_init_ap();
	/*
	 * the
	 * BSP-side fix (sys/dev/acpica/acpi.c's EJUSTRETURN branch,
	 * tdq_curthread_reseed(saved_td) immediately after
	 * PCPU_SET(curthread, saved_td)) has an exact AP-side twin here:
	 * tdq->tdq_curthread (sys/kern/sched_ule.c, DPCPU-backed,
	 * preserved copy_leaf=true per round 41's own disposition) is a
	 * SEPARATE field from pc_curthread, and every subsequent
	 * sched_switch()/mi_switch() on THIS cpu asserts
	 * td == tdq->tdq_curthread before choosing a new thread.
	 *
	 * This call was ORIGINALLY placed immediately after
	 * pc->pc_curthread = pc->pc_idlethread above (several hundred
	 * lines earlier in this same function) and is MOVED here after
	 * direct testing found the residual "mutex sleepq chain not
	 * owned"/"mutex callout not owned" panic (cpuid=1) still
	 * recurring: TDQ_SELF() (PCPU_GET(sched)) is only guaranteed
	 * valid AFTER sched_init_ap()'s own PCPU_SET(sched,
	 * DPCPU_PTR(tdq)) call immediately above -- calling
	 * tdq_curthread_reseed() any earlier risks reading/deriving
	 * TDQ_SELF() from a PCPU(sched) value this exact resume cycle has
	 * not yet established, the identical "must run after, not before,
	 * sched_init_ap()" ordering constraint sched_ule_ap_entry()'s own
	 * existing comment ("This should have been setup in
	 * sched_init_ap()") already documents for td_lock itself.
	 */
	tdq_curthread_reseed(pc->pc_idlethread);
	/*
	 * K24-T00: the AP-side twin of the same fix already applied on
	 * the BSP path (acpi.c, immediately after its own
	 * tdq_curthread_reseed(saved_td) call): pc->pc_idlethread->td_lock
	 * is per-thread saved-image content, restored byte-for-byte by
	 * the K-10 destructive copy, so it still names whatever lock
	 * object (if any) the SAVE kernel's own idle thread happened to
	 * be using at suspend time -- not this boot's own TDQ lock.
	 * Confirmed by direct reproduction this round: "Assertion mtx ==
	 * TDQ_LOCKPTR(tdq) failed at sched_ule.c:2474", inside
	 * sched_ule_switch() -> mi_switch() -> sched_ule_idletd(), on
	 * pid 11 tid 100003 (the idle thread), the first time this AP's
	 * own idle thread is scheduled post-resume. Placed here, after
	 * sched_init_ap() (which this file's own existing comment,
	 * several lines above, already establishes as the point where
	 * TDQ_SELF() first becomes valid on this CPU -- the identical
	 * ordering constraint tdq_curthread_reseed()'s own call site
	 * required), immediately alongside the existing
	 * tdq_curthread_reseed() call it is the direct counterpart of.
	 */
	extern void td_lock_hibernate_reseed(struct thread *td);
	td_lock_hibernate_reseed(pc->pc_idlethread);
	/*
	 * tdq_runq's own stale,
	 * saved-image entries -- traversal analysis this round proved
	 * sched_ap_entry() (immediately below) reaches
	 * sched_throw_grab() -> choosethread() -> tdq_choose(), which
	 * traverses THIS cpu's own tdq_runq as its very first action,
	 * strictly before anything else. Called here, after
	 * sched_init_ap() (so TDQ_SELF() is already valid -- the same
	 * ordering fix tdq_curthread_reseed()'s own call site needed)
	 * and strictly before that first traversal. See
	 * sys/kern/sched_ule.c's own tdq_runq_hibernate_reinit() for
	 * the full root-cause/scope account (runq_init() only -- NOT
	 * tdq_lock, which remains the demonstrated-unsafe part from the
	 * already-rejected wider attempt).
	 */
	tdq_runq_hibernate_reinit();
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

void	callout_cpu_hibernate_selfcopy_range(int cpu, uintptr_t *va_out,
	    size_t *len_out);
void	dumpsys_hibernate_selfcopy_range(uintptr_t *va_out, size_t *len_out);
void	sleepq_hibernate_selfcopy_range(uintptr_t *va_out, size_t *len_out);
void	turnstile_hibernate_selfcopy_range(uintptr_t *va_out,
	    size_t *len_out);
void	witness_hibernate_selfcopy_range(uintptr_t *va_out, size_t *len_out);
void	sched_idletd(void *);

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
 * dedicated low-memory PML4 slot for the source-PA vector's
 * private-domain-only virtual window.  The vector's backing pages
 * (hs_aux.hp_pa[0..vector_pages-1]) are an ordinary count-based, possibly
 * SCATTERED reservation (ENOMEM under fragmentation is the whole problem
 * this slot removes); this window maps them at consecutive 4 KiB VAs
 * regardless of their physical scatter, so hibernate_tramp.S's flat
 * "movq (%r10),%rsi; addq $8,%r10" source-vector read (HAH_SOURCE_VECTOR_PA)
 * keeps working completely unmodified -- it already runs under the
 * private CR3, so it never needs vector_pa to equal a real physical
 * address, only a valid private-domain VA.  Distinct from both slot 0
 * (identity) and HIBERNATE_MD_SAVED_SLOT (saved-domain stub/PCB).
 */
#define HIBERNATE_MD_VECTOR_SLOT 2
_Static_assert(HIBERNATE_MD_VECTOR_SLOT != 0 &&
    HIBERNATE_MD_VECTOR_SLOT != HIBERNATE_MD_SAVED_SLOT,
    "K-10 vector window slot must differ from slot 0 and HIBERNATE_MD_SAVED_SLOT");

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
/*
 * K24-T00 round 19: pre-copy -> post-copy kstack-mapping stash. Each
 * entry is exactly 24 bytes (va:8, leaf_pa:8, flags:8); the arena's
 * own HIBERNATE_ARENA_BOUNDED_SLACK_BYTES (64 KiB) comfortably holds
 * K24T00_KSTACK_STASH_MAX * 24 bytes for any reasonable
 * HIB_STAGED_MAX_THREADS-bounded thread count. Moved here (ahead of
 * struct hibernate_md_arena_layout, which references
 * K24T00_KSTACK_STASH_MAX in its own stash_max field) after the first
 * build attempt this round caught the original, later placement as a
 * genuine use-before-declaration error.
 */
/*
 * K24-T00 round 24: capacity sized to the real worst case, not an
 * arbitrary round number. Every one of up to HIB_STAGED_MAX_THREADS
 * (256) staged threads can need up to KSTACK_PAGES (4 on this
 * platform's non-FreeBSD_bdhwpadding configuration; see
 * sys/amd64/include/param.h) stash entries -- one per kstack page,
 * per this loop's own comment a few hundred lines below ("One entry
 * per PAGE, not per thread"). 256 was silently truncating: 87 live
 * threads at up to 4 pages each can require up to 348 entries, well
 * past the old 256-entry cap, and entries past the cap were simply
 * never written (the populate loop's own existing bounds check
 * already guards the write, so nothing overflowed memory -- the
 * threads whose pages didn't fit were the ones kstack_verify kept
 * reporting missing). 1024 * 24 bytes/entry = 24576 bytes, well
 * within the arena's existing 64 KiB HIBERNATE_ARENA_BOUNDED_SLACK_
 * BYTES slack component (see hibernate_md_arena_layout_compute()'s
 * own stash_pa placement, below) -- no arena resize is needed.
 */
/*
 * K24-T31: fixed byte offset, from stash_pa, for the double-buffer
 * mirror copy of every stash entry. 32 KiB lands comfortably inside
 * the arena's own 64 KiB HIBERNATE_ARENA_BOUNDED_SLACK_BYTES region
 * (same confirmed-in_run=0 region the primary stash itself occupies),
 * on a different physical page from the primary copy for any
 * realistic entry count this bench produces (a few hundred entries at
 * 56 bytes each is well under 32 KiB), while leaving enough headroom
 * after it for the mirror's own entries before the slack region ends.
 */
#define K24T31_MIRROR_OFFSET ((vm_paddr_t)0x8000)
#define K24T00_KSTACK_STASH_MAX (256 * KSTACK_PAGES)	/* 256 matches
	    HIB_STAGED_MAX_THREADS, #defined later in this file (see
	    HIB_STAGED_PCB_PAGE_MAX immediately above for the same
	    existing forward-reference-by-literal convention); a
	    _Static_assert immediately after HIB_STAGED_MAX_THREADS's
	    own definition, below, catches any future drift. */
struct k24t00_kstack_stash_entry {
	vm_offset_t va;
	vm_paddr_t leaf_pa;
	uint64_t flags;
	/*
	 * K24-T00 round 25: diagnostic-only fields, added to trace the
	 * 13 deterministic reason-1 (misaligned va/leaf_pa) install
	 * failures back to their originating thread and source field,
	 * per this round's own task. Populated at the same populate-
	 * pass write site as va/leaf_pa/flags above, from the identical
	 * threads[i]/pg values already in scope there -- no new
	 * resolution path, no new install logic.
	 */
	pid_t pid;
	char comm[MAXCOMLEN + 1];
	u_int page_index;
	/*
	 * K24-T00 round 31: true for an entry resolved from a thread's
	 * pcb->pcb_save (FPU/XSAVE save area) rather than its td_kstack.
	 * Lets the post-copy install pass and verifier report FPU-area
	 * installs/checks separately from kstack ones using the same
	 * stash array and install mechanism, rather than inventing a
	 * second parallel one.
	 */
	bool is_fpu;
};
/*
 * K24-T00 round 24: k24t00_kstack_stash_n was never self-copy-
 * protected, unlike every sibling "populated pre-copy, read post-
 * copy" global in this file (k24t00_staged_pcb_page_g, k24t00_
 * staged_pid_g, k24t00_staged_tid_g, hib_keg_topo_head_g,
 * hib_guard_image_value_g). This address is inside kernel_pmap's
 * ordinary BSS, i.e. a destination-set member: without protection
 * the K-10 destructive copy overwrites it with the SAVED image's own
 * stale content for this same address, not the value this boot's own
 * populate pass just wrote. The post-copy install loop (acpi.c) reads
 * this count directly as its own loop bound; a stale, larger count
 * exposes stash slots past the real end of this boot's own writes --
 * the deterministic garbage entries (fixed VA, same every run)
 * reason-1 failures are exactly that signature. Protected the
 * identical way as k24t00_staged_pcb_page_g, immediately after the
 * final write, below.
 */
u_int k24t00_kstack_stash_n;
#define K24T00_KSTACK_STASH_MAX_PAGES \
	((K24T00_KSTACK_STASH_MAX * (u_int)sizeof(struct \
	    k24t00_kstack_stash_entry) + PAGE_SIZE - 1) / PAGE_SIZE)

/*
 * K24-T00 round 29: pre-copy -> post-copy unsupported-thread exclusion
 * list. A thread with at least one kstack page the saved image's own
 * tables genuinely do not contain (round 28's confirmed verdict: a
 * zero terminal PTE, not a walker bug) can never be made runnable
 * post-copy -- there is no mapping to install for it. Recorded here,
 * pre-copy, in the same arena-backed, copy-excluded stash region as
 * k24t00_kstack_stash_n above, so the list survives the destructive
 * copy; consumed post-copy in acpi.c to stop exactly these threads
 * before acpi_s4_resume_scheduler_aps(), and by the verifier to
 * exclude them from the fail-closed miss count. One entry per
 * THREAD (not per page), since the action taken (stop the thread) is
 * thread-granular regardless of how many of its pages are missing.
 */
#define K24T00_EXCLUDE_MAX 64
struct k24t00_exclude_entry {
	struct thread *td;
	pid_t pid;
	char comm[MAXCOMLEN + 1];
	u_int missing_pages;
};
/*
 * K24-T00 round 29 fix: plain static array (self-copy-protected
 * below, after the final write), not an arena sub-region. The arena-
 * backed placement (an offset inside HIBERNATE_ARENA_BOUNDED_SLACK_
 * BYTES, immediately past the stash table) produced garbage reads
 * post-copy (corrupted pid/comm/va bytes resembling unrelated code),
 * indicating a layout/offset error this round's scope does not
 * justify debugging further -- K24T00_EXCLUDE_MAX (64) entries is
 * trivially small, and every sibling "populate pre-copy, read post-
 * copy" list in this file that is NOT the kstack stash itself
 * (k24t00_accepted_first[], k24t00_rej_proc_first[], etc.) already
 * uses exactly this plain-static-array + self-copy-protect pattern,
 * not the arena. Following the existing, already-proven convention
 * instead of repeating the new one that just failed.
 */
struct k24t00_exclude_entry k24t00_exclude_list[K24T00_EXCLUDE_MAX];
u_int k24t00_exclude_n;

/*
 * K24-T31: the recorded staged-thread list. Every post-copy, pre-
 * release pass that needs "every live staged thread" (the kstack
 * verifier, the FPU-area presence check, the FPU-area replacement
 * pass) previously walked the kernel's own allproc/p_list -- which is
 * documented, pre-existing, post-copy IMAGE CONTENT, not corrected
 * until hibernate_resume_rebuild_allproc() runs, much later, inside
 * acpi_EnterSleepState() (see that call site's own "whole-graph
 * corruption... recurring at a different node pair each round"
 * comment). Walking allproc before that rebuild runs is walking a
 * known-corrupt list; this is what produced acpi_s4_resume_bsp+0x4e7
 * (the FPU-replacement block's own allproc walk) and, in earlier
 * rounds, hibernate_k24t00_kstack_verify()'s own crash inside its own
 * walk.
 *
 * Fix: record this exact same thread set -- the populate pass already
 * enumerates it into threads[] via hibernate_md_enumerate_staged_
 * threads() -- into this protected, persistent array, PRE-copy, and
 * have every post-copy walk iterate THIS array instead of allproc.
 * The pointers were valid at capture (pre-copy, read from the staged
 * image's own tables, same source hibernate_md_enumerate_staged_
 * threads() already proves correct for every other per-thread use in
 * this file) and the array itself is self-copy-protected (below),
 * exactly like k24t00_kstack_stash_n/k24t00_exclude_list -- so this
 * traversal is immune to the allproc corruption class regardless of
 * when it runs relative to hibernate_resume_rebuild_allproc().
 */
struct k24t31_recorded_thread {
	struct thread *td;
	pid_t pid;
	lwpid_t tid;
	char comm[MAXCOMLEN + 1];
	vm_offset_t fpu_save_va;
};
struct k24t31_recorded_thread
    k24t31_recorded_threads[HIB_STAGED_PCB_PAGE_MAX];
u_int k24t31_recorded_n;


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
	vm_paddr_t handoff_pa;	 /* 4096 B: encoded handoff record. */
	vm_paddr_t run_table_pa; /* Coalesced destination run table. */
	uint64_t run_table_max;	 /* HIBERNATE_ARENA_COPY_RUN_MAX. */
	/*
	 * K24-T00 round 19: kstack-mapping stash table. Placed inside
	 * HIBERNATE_ARENA_BOUNDED_SLACK_BYTES (64 KiB), the existing,
	 * already-sized slack component hibernate_arena_required() adds
	 * AFTER has_alignment_allowance -- this placement adds NO new
	 * sized component to the arena sum (sizing.has_required is
	 * unchanged), only a new address WITHIN an already-reserved,
	 * already-copy-excluded region. Computed directly from the same
	 * `sizing` struct hibernate_arena_required() already returns
	 * (has_descriptor_storage, has_alignment_allowance), not
	 * re-derived or guessed, so it cannot drift from the real layout
	 * either boot computes.
	 */
	vm_paddr_t stash_pa;	 /* K24T00_KSTACK_STASH_MAX entries. */
	uint64_t stash_max;	 /* K24T00_KSTACK_STASH_MAX. */
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
/*
 * K24-T31: bounds-only variant. hibernate_md_arena_layout_compute()
 * below uses only ha->ha_arena_start/ha_arena_size from the attempt
 * struct -- confirmed by inspection, nothing else in *ha is read here.
 * Those two fields are themselves just a copy of this boot's own
 * g_hibernate_early_arena.hea_start/hea_size (hibernate_arena_claim(),
 * kern_hibernate.c), values the RESUMING kernel re-derives independently
 * and correctly from the firmware memory map on its own cold boot --
 * confirmed by this project's own design doc ("Save and restore boots
 * derive the identical arena tuple deterministically from the firmware
 * memory map", resume-protocol.md "Arena"). Post-copy accessors
 * (k24t00_kstack_stash_ptr(), its mirror) have no live struct
 * hibernate_attempt to read on the resume continuation -- that pointer
 * is published only by the SAVE boot's own coordinator and is never
 * valid on a cold-booted resume continuation -- so they must call this
 * bounds-only form directly with g_hibernate_early_arena's own fields,
 * never the ha-taking wrapper below.
 */
static int
hibernate_md_arena_layout_compute_from_bounds(vm_paddr_t arena_start,
    vm_size_t arena_size, struct hibernate_md_arena_layout *out)
{
	struct hibernate_arena_sizing sizing;
	vm_paddr_t off;
	int error;

	error = hibernate_arena_required(&sizing);
	if (error != 0)
		return (error);
	if (sizing.has_required != arena_size)
		return (EINVAL);

	off = arena_start;
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
	/*
	 * K24-T00 round 19: the stash sits past has_descriptor_storage
	 * (which covers the copy-run range run_table_pa already starts
	 * at, plus the aux-descriptor sub-range immediately after it)
	 * and past has_alignment_allowance -- both already computed by
	 * hibernate_arena_required() into `sizing` above, so this offset
	 * can never drift from whatever hibernate_arena_required() (the
	 * one function both save and restore boots call identically)
	 * actually decided. What remains after this point, up to
	 * arena_size, is exactly HIBERNATE_ARENA_BOUNDED_SLACK_BYTES
	 * (64 KiB) -- more than K24T00_KSTACK_STASH_MAX entries require.
	 */
	off = arena_start + HIBERNATE_ARENA_HEADER_BYTES +
	    HIBERNATE_ARENA_TRAMPOLINE_BYTES + HIBERNATE_ARENA_STACK_BYTES +
	    HIBERNATE_ARENA_PARK_STACK_BYTES + sizing.has_private_page_tables +
	    sizing.has_identity_map_pages + HIBERNATE_ARENA_HANDOFF_BYTES +
	    sizing.has_descriptor_storage + sizing.has_alignment_allowance;
	out->stash_pa = off;
	out->stash_max = K24T00_KSTACK_STASH_MAX;
	return (0);
}

static int
hibernate_md_arena_layout_compute(const struct hibernate_attempt *ha,
    struct hibernate_md_arena_layout *out)
{
	return (hibernate_md_arena_layout_compute_from_bounds(
	    ha->ha_arena_start, ha->ha_arena_size, out));
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
 * map one exact 4 KiB PRIVATE-DOMAIN-ONLY translation at an
 * explicit virtual address distinct from the mapped physical frame.
 * hibernate_md_private_pd_get()/_leaf_get()/_super_get() key every
 * table lookup purely off the address passed to them (to choose which
 * PML4/PDPT/PD/leaf slot to install into); they never read or write the
 * mapped frame value, so passing a window VA in place of the identity PA
 * they were written for is already correct and needs no change there.
 * Only the terminal PTE write must name the real (possibly scattered)
 * physical frame separately from the VA used to key the walk.  This is
 * the sole helper that may legitimately set VA != PA; every other
 * private-domain mapping in this file remains a strict identity map.
 */
static int
hibernate_md_private_window_map(struct hibernate_md_private_builder *builder,
    vm_offset_t va, vm_paddr_t frame_pa, pt_entry_t flags)
{
	pt_entry_t entry, *pt, pde;
	vm_paddr_t key, super_base, super_pa;
	u_int leaf, pte_index, pd;
	int error;

	if ((va & PAGE_MASK) != 0 || (frame_pa & PAGE_MASK) != 0)
		return (EINVAL);
	key = (vm_paddr_t)va;

	error = hibernate_md_private_pd_get(builder, key, &pd);
	if (error != 0)
		return (error);
	pde = builder->hmb_pd[pd]
		  .hmp_entries[(u_int)((key >> PDRSHIFT) & (NPDEPG - 1))];
	if ((pde & X86_PG_V) != 0 && (pde & PG_PS) != 0) {
		super_base = pde & PG_PS_FRAME;
		super_pa = super_base | (key & PDRMASK);
		if (super_pa == frame_pa &&
		    (pde & (X86_PG_V | X86_PG_RW)) == (X86_PG_V | X86_PG_RW) &&
		    (pde & X86_PG_NX) == (flags & X86_PG_NX))
			return (0);
		return (EINVAL);
	}

	error = hibernate_md_private_leaf_get(builder, key, &leaf);
	if (error != 0)
		return (error);
	pt = builder->hmb_leaf[leaf].hml_entries;
	pte_index = (u_int)((key >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = frame_pa | X86_PG_V | X86_PG_RW | flags;
	if ((pt[pte_index] & X86_PG_V) != 0) {
		if ((pt[pte_index] & (PG_FRAME | X86_PG_NX)) !=
		    (entry & (PG_FRAME | X86_PG_NX)))
			return (EINVAL);
		return (0);
	}
	pt[pte_index] = entry;
	return (0);
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
    const vm_paddr_t *vector, uint64_t vector_count, vm_paddr_t window_va,
    const vm_paddr_t *storage_pa, uint64_t vector_pages, vm_paddr_t xsave_pa,
    vm_paddr_t *private_cr3_out, uint64_t *leaf_pages_out)
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
	    vector_count, window_va, vector_pages, xsave_pa, &leaf_required);
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
	/*
	 * the V source-vector BACKING pages (storage_pa[0..V-1])
	 * are an ordinary scattered, count-based reservation -- they need
	 * not be, and in general are not, physically contiguous.  Map each
	 * one at a deterministic, private-domain-only, VA-contiguous window
	 * (window_va + j*PAGE_SIZE, frame storage_pa[j]) instead of
	 * identity-mapping a contiguous physical run.  hibernate_tramp.S's
	 * copy loop reads HAH_SOURCE_VECTOR_PA (== window_va) as a flat
	 * pointer entirely under the private CR3, so it never observes or
	 * needs the physical scatter.
	 */
	for (j = 0; j < vector_pages; j++) {
		if (__builtin_mul_overflow(j, (uint64_t)HIB_PAGE_SIZE,
			&bytes) ||
		    __builtin_add_overflow(window_va, bytes, &pa)) {
			error = EOVERFLOW;
			goto out;
		}
		error = hibernate_md_private_window_map(&builder, pa,
		    storage_pa[j], 0);
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
 * round 63 and round 64 both measured the LIVE
 * kernel_pmap at hibernate_machdep_prepare() time and both found the walk
 * (hibernate_md_tree_walk()/hib_md_safe_resolve()) returns false for
 * kstack_va -- reported loosely as "no page-table entry at all". A precise,
 * per-level capture (k24-t00-resumectx-fault-diagnosis.md, reconciliation
 * round) proves this is imprecise: the live tree's PML4, PDPT, and PD
 * entries for kstack_va's slot are ALL present and valid, and the PD
 * entry's frame (the PT page itself) is a genuine member of this image's
 * destination set. Only the single terminal PTE slot inside that PT page
 * is absent (raw value 0x0) -- exactly what hibernate_md_tree_walk()
 * reports back as an overall "not present" result, since it does not
 * distinguish "no entry at any level" from "every level down to PD
 * present, only the terminal leaf missing". Round 64's own separate
 * finding -- that the STAGED image's PT-page slot (the same PT page,
 * addressed via its destination-set index) holds a valid, present,
 * writable leaf PTE -- is the fix pointer: the needed leaf value already
 * exists in the staged image, reachable by walking the LIVE tree down to
 * the PT-page level (which works, unlike walking the SAVED tree from its
 * own PML4 root via hibernate_md_staged_tree_walk() above, whose entry
 * for this VA does not correspond to a real destination-set frame on any
 * captured cycle) and reading the STAGED content for that exact PT page's
 * slot.
 *
 * Returns false, failing closed, if any live level above the terminal PTE
 * is not present/valid, if that level is a superpage (never true for a
 * kstack VA in current builds, but refused rather than assumed), or if
 * the live PT page is not itself a member of the destination set (either
 * would mean this reconciliation's own precondition -- intermediate
 * levels present -- does not hold this cycle, and no assumption is made
 * about a different failure shape instead).
 */
static bool
hib_md_safe_resolve(vm_paddr_t root_pa, vm_offset_t va, vm_paddr_t *pa_out)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	pt_entry_t *pt;
	vm_paddr_t table_pa;
	uint64_t entry;
	u_int index;

	table_pa = root_pa & PG_FRAME;
	pml4 = (pml4_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	entry = pml4[index];
	if ((entry & X86_PG_V) == 0)
		return (false);

	table_pa = entry & PG_FRAME;
	pdp = (pdp_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdp[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	if ((entry & PG_PS) != 0) {
		*pa_out = ((entry & PG_PS_PDP_FRAME) | (va & PDPMASK)) &
		    PG_FRAME;
		return (true);
	}

	table_pa = entry & PG_FRAME;
	pd = (pd_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pd[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	if ((entry & PG_PS) != 0) {
		*pa_out = ((entry & PG_PS_FRAME) | (va & PDRMASK)) & PG_FRAME;
		return (true);
	}

	table_pa = entry & PG_FRAME;
	pt = (pt_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = pt[index];
	if ((entry & X86_PG_V) == 0)
		return (false);
	*pa_out = (entry & PG_FRAME) | (va & PAGE_MASK);
	return (true);
}

u_int k24t00_kv_excluded_threads;
static bool k24t00_live_pte_read(vm_offset_t va, uint64_t *pte_out);
/*
 * K24-T00 round 31: present-but-not-writable counter. Round 30's live
 * DDB capture proved a distinct failure mode from "missing":
 * fpu_activate_sw()'s write into pcb_save faulted "supervisor write
 * data, protection violation" on a page hib_md_safe_resolve() already
 * reports present. Tracked separately from `missing` so the two
 * failure classes are never conflated in the summary line.
 */
u_int k24t00_kv_readonly;

struct k24t00_exclude_entry *k24t00_exclude_ptr(void);

static bool
k24t00_td_is_excluded(struct thread *td)
{
	struct k24t00_exclude_entry *list;
	u_int i, n;

	list = k24t00_exclude_ptr();
	if (list == NULL)
		return (false);
	/*
	 * K24-T00 round 29 fix: bound by K24T00_EXCLUDE_MAX
	 * unconditionally. k24t00_exclude_n is self-copy-protected only
	 * AFTER the populate pass's own per-thread loop runs to
	 * completion (hibernate_machdep_prepare()); a degenerate run
	 * where that loop is skipped or aborts early leaves this count
	 * holding the SAVED image's stale content for this address,
	 * which can be arbitrarily large -- an unbounded loop here then
	 * reads past the 64-entry k24t00_exclude_list[] array on every
	 * single call (this function runs once per live thread, so the
	 * out-of-bounds read is essentially guaranteed to fault). The
	 * array's own fixed capacity is the one value this function can
	 * always trust regardless of k24t00_exclude_n's own validity.
	 */
	n = k24t00_exclude_n;
	if (n > K24T00_EXCLUDE_MAX)
		n = K24T00_EXCLUDE_MAX;
	for (i = 0; i < n; i++) {
		if (list[i].td == td)
			return (true);
	}
	return (false);
}

u_int	hibernate_k24t00_kstack_verify(void);
u_int
hibernate_k24t00_kstack_verify(void)
{
	extern void hibernate_k24t04_raw_marker(int c);
	struct proc *p;
	struct thread *td, *self;
	u_int threads_checked, pages_checked, pages_missing;

	threads_checked = 0;
	pages_checked = 0;
	pages_missing = 0;
	k24t00_kv_offender_n = 0;
	k24t00_kv_superpage_covered = 0;
	k24t00_kv_excluded_threads = 0;
	k24t00_kv_readonly = 0;
	self = curthread;

	/*
	 * K24-T31: iterate the RECORDED staged-thread list, not allproc/
	 * p_list directly -- allproc's own chain is documented, pre-
	 * existing, post-copy IMAGE CONTENT, not corrected until
	 * hibernate_resume_rebuild_allproc() runs, much later, inside
	 * acpi_EnterSleepState(). This function previously crashed
	 * inside this exact walk for that reason. k24t31_recorded_
	 * threads[] (populated pre-copy from the identical staged-
	 * thread enumeration this file already trusts for every other
	 * per-thread use, self-copy-protected like every other
	 * populate-pre-copy/read-post-copy global here) is immune to
	 * that corruption regardless of when this function runs. Each
	 * entry's own td pointer was valid at capture; td->td_proc is
	 * dereferenced directly (not re-looked-up via allproc) for the
	 * identical reason. Still single-BSP-actor, no-sleepable-lock --
	 * safe by exclusion, same reasoning as before, over a
	 * trustworthy list now. The former double loop (LIST_FOREACH +
	 * FOREACH_THREAD_IN_PROC) collapses to one flat loop since the
	 * recorded list is already per-THREAD, not per-proc.
	 */
	k24t00_kv_fpu_offender_n = 0;
	k24t00_kv_fpu_pages_checked = 0;
	k24t00_kv_fpu_pages_missing = 0;
	k24t00_kv_fpu_threads_checked = 0;

	{
		extern struct k24t31_recorded_thread *
		    k24t31_recorded_threads_ptr(void);
		extern u_int k24t31_recorded_threads_count(void);
		struct k24t31_recorded_thread *k24t31_rlist;
		u_int k24t31_rn, k24t31_ri;

		k24t31_rlist = k24t31_recorded_threads_ptr();
		k24t31_rn = k24t31_recorded_threads_count();
		/*
		 * K24-T31: fail closed if pages were stashed but no
		 * threads were recorded -- that means the recording
		 * itself failed (a logic bug), not that there are
		 * genuinely zero staged threads with a kstack to check.
		 */
		if (k24t31_rn == 0 && k24t00_kstack_stash_n != 0) {
			panic("hibernate: k24t31: recorded thread list "
			    "empty but k24t00_kstack_stash_n=%u -- "
			    "recording failed, refusing to verify "
			    "against an empty list",
			    k24t00_kstack_stash_n);
		}
	for (k24t31_ri = 0; k24t31_ri < k24t31_rn; k24t31_ri++) {
		td = k24t31_rlist[k24t31_ri].td;
		p = td->td_proc;
		{
			vm_offset_t va, kstack_lo, kstack_hi;
			u_int pg;

			/*
			 * K24-T00 round 29: a thread recorded in the
			 * exclusion list was already stopped post-copy
			 * (k24t00_exclude_stop_threads(), called by
			 * acpi.c strictly before this verifier) precisely
			 * because its own kstack page(s) are confirmed
			 * absent from the saved image's own tables (round
			 * 28). It is deliberately non-runnable, not an
			 * undiagnosed gap -- count it separately and skip
			 * the page-level check entirely so its known,
			 * already-accounted-for gap can never surface as
			 * a fail-closed panic.
			 */
			if (k24t00_td_is_excluded(td)) {
				k24t00_kv_excluded_threads++;
				continue;
			}
			threads_checked++;
			kstack_lo = (vm_offset_t)td->td_kstack;
			kstack_hi = kstack_lo +
			    (vm_offset_t)td->td_kstack_pages * PAGE_SIZE;
			for (pg = 0; pg < td->td_kstack_pages; pg++) {
				vm_paddr_t live_pa;
				vm_paddr_t sp_pa;
				bool sp_covered;

				va = kstack_lo + (vm_offset_t)pg * PAGE_SIZE;
				pages_checked++;
				/*
				 * K24-T00 round 20: superpage-aware check.
				 * hib_md_safe_resolve() itself already
				 * follows a PD-level PG_PS entry down to a
				 * resolved PA (see its own PG_PS_FRAME
				 * branch) and returns true -- so a VA
				 * covered by a superpage was NEVER actually
				 * misreported as missing by the ORIGINAL
				 * hib_md_safe_resolve()-based check above.
				 * The new k24t00_pd_superpage_check() call
				 * below exists only to DISTINGUISH, for
				 * every VA hib_md_safe_resolve() already
				 * resolved successfully, whether that
				 * resolution went through a superpage or an
				 * ordinary 4 KiB leaf -- the count this
				 * round's task asks for -- without changing
				 * which VAs count as present/missing at all
				 * (that classification is, and remains,
				 * hib_md_safe_resolve()'s own true/false
				 * return, read first, unmodified).
				 */
				if (hib_md_safe_resolve(kernel_pmap->pm_cr3,
				    va, &live_pa)) {
					uint64_t kv_live_pte;

					if (k24t00_pd_superpage_check(
					    kernel_pmap->pm_cr3, va, &sp_pa,
					    &sp_covered) && sp_covered)
						k24t00_kv_superpage_covered++;
					/*
					 * K24-T00 round 31: present does not
					 * imply writable. Round 30 proved a
					 * kstack/FPU page can be mapped yet
					 * read-only at this exact instant,
					 * which a later write (e.g.
					 * fpu_activate_sw()'s restore)
					 * faults on identically to a missing
					 * page. Count it, do not panic here
					 * (distinct from `missing`'s own
					 * fail-closed contract; this is the
					 * new, additive check this round
					 * adds).
					 */
					if (k24t00_live_pte_read(va,
					    &kv_live_pte) &&
					    (kv_live_pte & X86_PG_RW) == 0)
						k24t00_kv_readonly++;
					continue;
				}
				pages_missing++;
				if (k24t00_kv_offender_n <
				    K24T00_KV_OFFENDER_MAX) {
					struct k24t00_kv_offender *o;
					bool pt_present, pte_ok;

					o = &k24t00_kv_offenders[
					    k24t00_kv_offender_n++];
					o->pid = p->p_pid;
					memcpy(o->comm, p->p_comm,
					    sizeof(o->comm) - 1);
					o->comm[sizeof(o->comm) - 1] =
					    '\0';
					o->td = td;
					o->td_tid = td->td_tid;
					o->va = va;
					o->va_in_kstack_range =
					    (va >= kstack_lo &&
					    va < kstack_hi);
					o->is_curthread = (td == self);
					k24t00_pt_page_state(
					    kernel_pmap->pm_cr3, va,
					    &pt_present, &pte_ok);
					o->pt_page_present = pt_present;
					o->pte_valid_recheck = pte_ok;
				}
			}

			/*
			 * K24-T00 round 21: FPU/XSAVE save area presence
			 * check. pcb->pcb_save (struct savefpu *) is a
			 * SEPARATE allocation from fpu_save_area_alloc()
			 * (sys/amd64/amd64/vm_machdep.c
			 * cpu_thread_alloc()), never part of td_kstack --
			 * it is exactly the pointer restore_fpu_curthread()
			 * (inlined into fpu_activate_sw(), the call
			 * immediately following done_load_dr's own stack
			 * write) dereferences via bcopy()/fpurestore().
			 * Allocated for every thread regardless of
			 * TDP_KTHREAD (cpu_thread_alloc() runs
			 * unconditionally), so checked for every thread
			 * here, matching the kstack check's own
			 * unconditional scope. May span more than one page
			 * (cpu_max_ext_state_size, not sizeof(struct
			 * savefpu)); the area is only
			 * XSAVE_AREA_ALIGN(64)-aligned, not necessarily
			 * page-aligned, so every page it touches is walked
			 * from trunc_page(start) to trunc_page(end - 1)
			 * inclusive.
			 */
			{
				struct pcb *pcb;
				vm_offset_t fpu_lo, fpu_hi, fva;

				pcb = td->td_pcb;
				if (pcb != NULL && pcb->pcb_save != NULL) {
					k24t00_kv_fpu_threads_checked++;
					fpu_lo = trunc_page(
					    (vm_offset_t)pcb->pcb_save);
					fpu_hi = trunc_page(
					    (vm_offset_t)pcb->pcb_save +
					    cpu_max_ext_state_size - 1);
					for (fva = fpu_lo; fva <= fpu_hi;
					    fva += PAGE_SIZE) {
						vm_paddr_t fpu_live_pa;

						k24t00_kv_fpu_pages_checked++;
						if (hib_md_safe_resolve(
						    kernel_pmap->pm_cr3, fva,
						    &fpu_live_pa)) {
							uint64_t
							    fpu_live_pte;

							/*
							 * K24-T00 round 31:
							 * same present-but-
							 * read-only check as
							 * the kstack loop
							 * above -- this is
							 * exactly the
							 * content class
							 * round 30's live
							 * fault was
							 * reproduced
							 * against.
							 */
							if (k24t00_live_pte_read(
							    fva,
							    &fpu_live_pte) &&
							    (fpu_live_pte &
								X86_PG_RW) ==
							    0)
								k24t00_kv_readonly++;
							continue;
						}
						k24t00_kv_fpu_pages_missing++;
						if (k24t00_kv_fpu_offender_n <
						    K24T00_KV_FPU_OFFENDER_MAX) {
							struct k24t00_kv_fpu_offender *fo;
							bool pt_present, pte_ok;

							fo = &k24t00_kv_fpu_offenders[
							    k24t00_kv_fpu_offender_n++];
							fo->pid = p->p_pid;
							memcpy(fo->comm,
							    p->p_comm,
							    sizeof(fo->comm) - 1);
							fo->comm[
							    sizeof(fo->comm) - 1] =
							    '\0';
							fo->td = td;
							fo->td_tid = td->td_tid;
							fo->va = fva;
							fo->page_index =
							    (u_int)((fva -
							    fpu_lo) /
							    PAGE_SIZE);
							fo->va_in_kstack_range =
							    (fva >= kstack_lo &&
							    fva < kstack_hi);
							fo->is_curthread =
							    (td == self);
							k24t00_pt_page_state(
							    kernel_pmap->pm_cr3,
							    fva, &pt_present,
							    &pte_ok);
							fo->pt_page_present =
							    pt_present;
							fo->pte_valid_recheck =
							    pte_ok;
						}
					}
				}
			}
		}
	}
	}

	hibernate_k24t04_raw_marker('K');
	hibernate_k24t04_raw_uint((uint64_t)threads_checked);
	hibernate_k24t04_raw_marker('L');
	hibernate_k24t04_raw_uint((uint64_t)pages_checked);
	hibernate_k24t04_raw_marker('M');
	hibernate_k24t04_raw_uint((uint64_t)pages_missing);
	return (pages_missing);
}

#define K24T00_EARLY_KSTACK_CACHE_MAX 8
static vm_offset_t k24t00_early_kstack_va[K24T00_EARLY_KSTACK_CACHE_MAX];
static struct hibernate_md_walk
    k24t00_early_kstack_walk[K24T00_EARLY_KSTACK_CACHE_MAX];
static bool k24t00_early_kstack_valid[K24T00_EARLY_KSTACK_CACHE_MAX];
static u_int k24t00_early_kstack_count;

static bool
hibernate_md_staged_leaf_for_live_slot(const struct hibernate_attempt *ha,
    const vm_paddr_t *vector, uint64_t vector_count, vm_offset_t va,
    struct hibernate_md_walk *walk)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	const uint64_t *staged_pt;
	vm_paddr_t pt_page_pa;
	uint64_t entry, sidx, staged_pte;
	u_int index;

	{
		u_int ci;

		for (ci = 0; ci < k24t00_early_kstack_count; ci++) {
			if (k24t00_early_kstack_valid[ci] &&
			    k24t00_early_kstack_va[ci] == va) {
				*walk = k24t00_early_kstack_walk[ci];
				return (true);
			}
		}
	}

	pml4 = (pml4_entry_t *)PHYS_TO_DMAP(kernel_pmap->pm_cr3 & PG_FRAME);
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	entry = pml4[index];
	if ((entry & X86_PG_V) == 0)
		return (false);

	pdp = (pdp_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdp[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (false);

	pd = (pd_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pd[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (false);

	pt_page_pa = entry & PG_FRAME;
	if (hibernate_md_dst_page_index(ha, pt_page_pa, &sidx) != 0 ||
	    sidx >= vector_count)
		return (false);

	staged_pt = (const uint64_t *)PHYS_TO_DMAP(vector[sidx]);
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	staged_pte = staged_pt[index];
	if ((staged_pte & X86_PG_V) == 0)
		return (false);

	walk->hmw_pa = staged_pte & PG_FRAME;
	walk->hmw_flags = staged_pte & (X86_PG_V | X86_PG_RW | X86_PG_U |
	    X86_PG_NX);
	return (true);
}

/*
 * install one exact 4 KiB mapping, VA va -> leaf_pa,
 * into the LIVE kernel_pmap -- Design 041's option 1, "installed in the
 * live kernel_pmap ... before resumectx() runs". Missing intermediate
 * tables are allocated via pmap_page_alloc_below_4g(), the identical
 * machinery hibernate_md_identity_ensure() already uses; no parallel
 * mapping scheme is invented. Each freshly allocated table page is
 * checked disjoint from the image's own destination set (a genuinely
 * free page was never claimed by any in-use kernel structure, so it
 * cannot legitimately appear there; this makes that assumption an
 * explicit, fail-closed check rather than an implicit one). A
 * pre-existing leaf entry is refused rather than overwritten by
 * default -- Step 1's capture proved none should exist for most
 * callers' class of VA. After writing the leaf, the full PTE chain is
 * read back via hibernate_md_walk_matches() and the insertion is
 * undone (EINVAL returned) if it does not resolve to exactly the
 * intended frame and permissions: "proven present with the required
 * permissions", not assumed.
 *
 * K24-T00 stack disposition fix: the "none should exist" premise is
 * false for exactly one caller -- the resuming thread's OWN kernel
 * stack VA (the stack this very restore continuation is executing
 * on). That VA is necessarily already live-mapped: it is the resume
 * kernel's own thread0/current-thread kstack allocation, mapped by the
 * ordinary resume-boot thread-creation path before hibernate resume
 * ever runs. Empirically confirmed this round (N=12 baseline, runs
 * 9-10/12): the live leaf frame (0x7fed8000 region) differs from the
 * image's own saved leaf (0x7ed30000 region) at this VA, so the
 * default refuse-on-mismatch path (reason=8) fires and blocks every
 * other lower page of the same KSTACK_PAGES range from ever being
 * installed, because the per-page loop aborts on the first fatal
 * error. The resuming thread's stack is the IMAGE's stack by
 * construction (resumectx() switches %rsp to the saved pcb_rsp and
 * returns into the saved call frames) -- the live resume-boot mapping
 * at this VA is a false positive, not a conflicting real claim, and
 * must be overwritten with the image's leaf, not refused. force_overwrite
 * is true at exactly that one call site (the resuming-stack install
 * loop) and false everywhere else (e.g. other staged threads' own
 * kernel stacks, where a mismatched pre-existing live leaf remains a
 * genuine conflict and must still fail closed).
 */
static u_int hib_kva_install_reason;
static vm_offset_t hib_kva_install_va;
static vm_paddr_t hib_kva_install_leaf_pa;
static uint64_t hib_kva_install_entry;
static uint64_t hib_kva_install_leaf_flags;
static vm_paddr_t hib_kva_install_table_pa;

/*
 * K24-T00 round 19: cross-file accessors so acpi.c's post-copy stash
 * install pass can report WHY an install failed (hib_kva_install_reason
 * is a HIB_KVA_FAIL reason code 1-8, set by hibernate_md_kva_install()
 * itself on every failing return) without this file needing to expose
 * its full static diagnostic surface.
 */
u_int k24t00_kva_install_last_reason(void);
u_int
k24t00_kva_install_last_reason(void)
{
	return (hib_kva_install_reason);
}

uint64_t k24t00_kva_install_last_entry(void);
uint64_t
k24t00_kva_install_last_entry(void)
{
	return (hib_kva_install_entry);
}

#define HIB_KVA_FAIL(_reason, _entry, _table_pa)         \
	do {                                             \
		hib_kva_install_reason = (_reason);      \
		hib_kva_install_va = va;                 \
		hib_kva_install_leaf_pa = leaf_pa;       \
		hib_kva_install_entry = (_entry);        \
		hib_kva_install_leaf_flags = leaf_flags; \
		hib_kva_install_table_pa = (_table_pa);  \
		return (EINVAL);                         \
	} while (0)

static int
hibernate_md_kva_install(const struct hibernate_attempt *ha, vm_offset_t va,
    vm_paddr_t leaf_pa, uint64_t saved_flags, bool force_overwrite)
{
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	pt_entry_t *pte;
	vm_page_t m_pdp, m_pd, m_pt;
	vm_paddr_t table_pa;
	uint64_t entry, leaf_flags;
	u_int pml4_idx, pdpt_idx, pd_idx, pt_idx;

	leaf_flags = X86_PG_V | X86_PG_A | X86_PG_M |
	    (saved_flags & (X86_PG_RW | X86_PG_U | X86_PG_NX));
	hib_kva_install_reason = 0;
	hib_kva_install_va = va;
	hib_kva_install_leaf_pa = leaf_pa;
	hib_kva_install_entry = 0;
	hib_kva_install_leaf_flags = leaf_flags;
	hib_kva_install_table_pa = 0;

	if ((va & PAGE_MASK) != 0 || (leaf_pa & PAGE_MASK) != 0)
		HIB_KVA_FAIL(1, 0, 0);

	pml4_idx = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	pml4e = kernel_pmap->pm_pmltop;
	entry = pml4e[pml4_idx];
	if ((entry & X86_PG_V) == 0) {
		m_pdp = pmap_page_alloc_below_4g(true);
		if (m_pdp == NULL)
			return (ENOMEM);
		table_pa = VM_PAGE_TO_PHYS(m_pdp);
		if (hib_pa_in_dst_md(ha, table_pa))
			HIB_KVA_FAIL(2, entry, table_pa);
		pml4e[pml4_idx] = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
		entry = pml4e[pml4_idx];
	}
	if ((entry & PG_PS) != 0)
		HIB_KVA_FAIL(3, entry, entry & PG_FRAME);
	pdpe = (pdp_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);

	pdpt_idx = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = pdpe[pdpt_idx];
	if ((entry & X86_PG_V) == 0) {
		m_pd = pmap_page_alloc_below_4g(true);
		if (m_pd == NULL)
			return (ENOMEM);
		table_pa = VM_PAGE_TO_PHYS(m_pd);
		if (hib_pa_in_dst_md(ha, table_pa))
			HIB_KVA_FAIL(4, entry, table_pa);
		pdpe[pdpt_idx] = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
		entry = pdpe[pdpt_idx];
	}
	if ((entry & PG_PS) != 0)
		HIB_KVA_FAIL(5, entry, entry & PG_FRAME);
	pde = (pd_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);

	pd_idx = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pde[pd_idx];
	if ((entry & X86_PG_V) == 0) {
		m_pt = pmap_page_alloc_below_4g(true);
		if (m_pt == NULL)
			return (ENOMEM);
		table_pa = VM_PAGE_TO_PHYS(m_pt);
		if (hib_pa_in_dst_md(ha, table_pa))
			HIB_KVA_FAIL(6, entry, table_pa);
		pde[pd_idx] = table_pa | X86_PG_V | X86_PG_RW | X86_PG_A |
		    X86_PG_M;
		entry = pde[pd_idx];
	}
	if ((entry & PG_PS) != 0) {
		/*
		 * K24-T00 round 22: superpage split. Post-copy install
		 * pass; APs are still parked (acpi_s4_resume_scheduler_
		 * aps() has not run) and the BSP is the only CPU able to
		 * touch kernel_pmap right now -- no lock is taken here,
		 * identical to every other direct kernel_pmap mutation
		 * already performed by this function (the PML4/PDPT/PD
		 * allocate-on-demand branches above take none either).
		 * A live 2 MiB PD-level superpage covering this VA is
		 * the exact "failed_reason=7" case the post-copy stash
		 * install pass hit 256/256 times this round: the image's
		 * own 4 KiB leaf cannot be placed underneath a live
		 * superpage without first demoting it to an ordinary PT.
		 * This mirrors the kernel's own pmap_demote_pde() in
		 * effect (same PT-page-per-512-PTEs reproduction of the
		 * superpage's mapping), but is written out manually here
		 * rather than calling it: pmap_demote_pde() assumes
		 * ordinary locking and VM-subsystem state this no-return
		 * resume continuation does not guarantee, whereas this
		 * function already has its own narrower, already-proven
		 * allocator (pmap_page_alloc_below_4g()) and destination-
		 * set disjointness check (hib_pa_in_dst_md()) for exactly
		 * this situation.
		 */
		vm_page_t m_split;
		vm_paddr_t split_pa, split_base_pa;
		pt_entry_t *split_pte;
		uint64_t split_pte_flags, split_pde_flags;
		u_int si;

		split_base_pa = entry & PG_PS_FRAME;
		m_split = pmap_page_alloc_below_4g(true);
		if (m_split == NULL)
			return (ENOMEM);
		split_pa = VM_PAGE_TO_PHYS(m_split);
		if (hib_pa_in_dst_md(ha, split_pa))
			HIB_KVA_FAIL(10, entry, split_pa);
		split_pte = (pt_entry_t *)PHYS_TO_DMAP(split_pa);
		/*
		 * Reproduce the existing 2 MiB mapping exactly: same
		 * physical base, stepping by 4 KiB, same flags. V/RW/U/
		 * A/M/NX are preserved from the superpage's own PDE (the
		 * template the task asks for); PG_PS itself is excluded
		 * -- it has no meaning at the PT level and would corrupt
		 * the PAT bit position there (PDE bit 12 vs PTE bit 7)
		 * if left set.
		 */
		split_pte_flags = entry &
		    (X86_PG_V | X86_PG_RW | X86_PG_U | X86_PG_A |
			X86_PG_M | X86_PG_NX);
		for (si = 0; si < NPTEPG; si++) {
			split_pte[si] = (split_base_pa +
			    (vm_paddr_t)si * PAGE_SIZE) | split_pte_flags;
		}
		/*
		 * Replace the PD entry with the new PT page's own PTE,
		 * preserving the PD entry's own flag bits (everything
		 * outside the frame, minus PG_PS itself -- PG_PS is what
		 * made this a leaf; the replacement is a table pointer).
		 */
		split_pde_flags = (entry & ~PG_PS_FRAME) & ~(uint64_t)PG_PS;
		pde[pd_idx] = split_pa | split_pde_flags | X86_PG_V;

		/*
		 * Invalidate the affected range before retrying the
		 * install: a huge-page TLB entry can cover any address
		 * within the whole 2 MiB region, not just va, so the
		 * existing full kernel_pmap invalidate idiom this same
		 * function already uses below (after the real leaf
		 * install, and on its own rollback path) is reused here
		 * rather than inventing a narrower, riskier one.
		 */
		if ((read_rflags() & PSL_I) != 0)
			pmap_invalidate_all(kernel_pmap);
		else
			invltlb_glob();

		/*
		 * Retry: re-read the now-demoted PD entry and fall
		 * through exactly as the ordinary "PT just allocated"
		 * case above does.
		 */
		entry = pde[pd_idx];
	}
	pte = (pt_entry_t *)PHYS_TO_DMAP(entry & PG_FRAME);

	pt_idx = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = pte[pt_idx];
	leaf_flags = X86_PG_V | X86_PG_A | X86_PG_M |
	    (saved_flags & (X86_PG_RW | X86_PG_U | X86_PG_NX));
	if ((entry & X86_PG_V) != 0) {
		/*
		 * a pre-existing leaf here is not
		 * automatically a conflict. The live PT page can already,
		 * via ordinary deterministic early-boot allocation order,
		 * hold exactly the frame+permissions the image needs at this
		 * slot (observed directly: diag_install_err=EINVAL alongside
		 * a live terminal PTE already bit-identical to the staged
		 * value, k24-t00-resumectx-fault-diagnosis.md reconciliation
		 * round) -- refusing unconditionally here is refusing a
		 * no-op. Accept only an EXACT match (same frame, same
		 * V|RW|U bits) as success with no write; any other
		 * pre-existing leaf is still refused, unchanged from before.
		 */
		if ((entry & PG_FRAME) == leaf_pa &&
		    (entry & (X86_PG_V | X86_PG_RW | X86_PG_U)) ==
		    (leaf_flags & (X86_PG_V | X86_PG_RW | X86_PG_U)))
			return (0);
		/*
		 * K24-T00 stack disposition fix: a pre-existing, mismatched
		 * live leaf at this VA is a genuine conflict for ordinary
		 * callers, but is the EXPECTED case for the resuming
		 * thread's own kstack VA (see the function's own comment
		 * above) -- the live resume-boot mapping there is a false
		 * positive that must be replaced with the image's leaf, not
		 * refused. Only force_overwrite callers take this path.
		 */
		if (!force_overwrite)
			HIB_KVA_FAIL(8, entry, entry & PG_FRAME);
	}

	pte[pt_idx] = leaf_pa | leaf_flags;

	if ((read_rflags() & PSL_I) != 0)
		pmap_invalidate_all(kernel_pmap);
	else
		invltlb_glob();

	if (!hibernate_md_walk_matches(kernel_pmap->pm_cr3, va, leaf_pa,
	    leaf_flags & (X86_PG_V | X86_PG_RW | X86_PG_U))) {
		pte[pt_idx] = entry;
		if ((read_rflags() & PSL_I) != 0)
			pmap_invalidate_all(kernel_pmap);
		else
			invltlb_glob();
		HIB_KVA_FAIL(9, failed_entry, failed_entry & PG_FRAME);
	}

	return (0);
}
/*
 * K24-T00 round 19: cross-file accessor for acpi.c's post-copy install
 * pass. The stash itself lives in the arena at a PA computed by
 * hibernate_md_arena_layout_compute() (not a plain static array), so
 * acpi.c cannot reach it without first recomputing the layout -- this
 * wrapper does that once, using the live hibernate_current_attempt
 * (the same global hibernate_page_is_destination() itself already
 * reads, proven safe post-copy by every prior round's own use of it
 * at this identical call site).
 */
struct k24t00_kstack_stash_entry *k24t00_kstack_stash_ptr(void);
struct k24t00_kstack_stash_entry *
k24t00_kstack_stash_ptr(void)
{
	extern bool k24t00_hibernate_early_arena_bounds(vm_paddr_t *,
	    vm_size_t *);
	struct hibernate_md_arena_layout layout;
	vm_paddr_t arena_start;
	vm_size_t arena_size;

	/*
	 * K24-T31: derive from THIS boot's own early-boot arena
	 * reservation (g_hibernate_early_arena), not from
	 * hibernate_current_attempt -- that pointer is published only
	 * by the save-side coordinator and is confirmed NULL on the
	 * resume continuation, which never runs that coordinator (it is
	 * a fresh cold boot, not "the save boot after a copy clobbered
	 * one page"). hibernate_md_arena_layout_compute()'s own ha-
	 * taking form only ever read ha->ha_arena_start/ha_arena_size
	 * -- both just a copy of g_hibernate_early_arena's own fields --
	 * so this bounds-only call is both sufficient and correct on
	 * every boot. Fails closed and loud if the early arena was
	 * never validly populated this boot.
	 */
	if (!k24t00_hibernate_early_arena_bounds(&arena_start,
	    &arena_size))
		return (NULL);
	if (hibernate_md_arena_layout_compute_from_bounds(arena_start,
	    arena_size, &layout) != 0)
		return (NULL);
	return ((struct k24t00_kstack_stash_entry *)
	    PHYS_TO_DMAP(layout.stash_pa));
}

/*
 * K24-T31: cross-file accessor for acpi.c's post-copy double-buffer
 * comparison. Returns the mirror copy's own base pointer, at the
 * fixed K24T31_MIRROR_OFFSET from the primary stash's own stash_pa
 * (see that constant's own declaration comment) -- same arena, same
 * confirmed-in_run=0 region, different page.
 */
struct k24t00_kstack_stash_entry *k24t00_kstack_stash_mirror_ptr(void);
struct k24t00_kstack_stash_entry *
k24t00_kstack_stash_mirror_ptr(void)
{
	extern bool k24t00_hibernate_early_arena_bounds(vm_paddr_t *,
	    vm_size_t *);
	struct hibernate_md_arena_layout layout;
	vm_paddr_t arena_start, mirror_pa;
	vm_size_t arena_size;

	/*
	 * K24-T31: same early-arena derivation as k24t00_kstack_stash_
	 * ptr() immediately above -- see its own comment for the full
	 * account.
	 */
	if (!k24t00_hibernate_early_arena_bounds(&arena_start,
	    &arena_size))
		return (NULL);
	if (hibernate_md_arena_layout_compute_from_bounds(arena_start,
	    arena_size, &layout) != 0)
		return (NULL);
	mirror_pa = layout.stash_pa + K24T31_MIRROR_OFFSET;
	return ((struct k24t00_kstack_stash_entry *)
	    PHYS_TO_DMAP(mirror_pa));
}

/*
 * K24-T00 round 29: cross-file accessor for acpi.c's post-copy
 * exclusion-stop pass. k24t00_exclude_list is a plain, self-copy-
 * protected static array (see its own declaration comment), so this
 * accessor is a trivial address-of, not an arena-layout lookup.
 */
struct k24t00_exclude_entry *k24t00_exclude_ptr(void);
struct k24t00_exclude_entry *
k24t00_exclude_ptr(void)
{
	return (k24t00_exclude_list);
}

/*
 * K24-T31: cross-file accessor for every post-copy pass that needs
 * "every live staged thread" without walking the kernel's own
 * (documented-corrupt-at-that-point) allproc/p_list. k24t31_
 * recorded_threads[] is a plain, self-copy-protected static array
 * (see its own declaration comment), so this accessor is a trivial
 * address-of, not an arena-layout lookup.
 */
struct k24t31_recorded_thread *k24t31_recorded_threads_ptr(void);
struct k24t31_recorded_thread *
k24t31_recorded_threads_ptr(void)
{
	return (k24t31_recorded_threads);
}

u_int k24t31_recorded_threads_count(void);
u_int
k24t31_recorded_threads_count(void)
{
	return (k24t31_recorded_n);
}

/*
 * K24-T00 td_contested reseed support: the direct struct thread *
 * twin of k24t31_recorded_thread_proc_pub() above, for
 * sys/dev/acpica/acpi.c's own td_contested reseed sweep (see that
 * call site's own comment for the full root-cause account). Returns
 * the recorded thread pointer itself rather than its td_proc, since
 * the reseed writes directly to struct thread.td_contested, not
 * anything process-level.
 */
struct thread *k24t31_recorded_thread_td_pub(u_int idx);
struct thread *
k24t31_recorded_thread_td_pub(u_int idx)
{
	if (idx >= k24t31_recorded_n)
		return (NULL);
	return (k24t31_recorded_threads[idx].td);
}

/*
 * K24-T00 round 29: post-copy consumer. For each recorded excluded
 * thread, stop it using the kernel's own existing, already-proven
 * thread_suspend_one() -- the identical primitive thread_single()
 * itself calls to stop a thread it does not want released -- instead
 * of inventing new state-manipulation logic. Requires only the two
 * spin locks thread_suspend_one() itself asserts (PROC_SLOCK, thread
 * lock), never a sleepable lock, matching this call site's own single-
 * actor, APs-still-parked constraint (identical reasoning already
 * documented at this function's call site in acpi.c). curthread is
 * always skipped: it is this resume continuation itself and must
 * complete the restore. A thread already suspended, exited, or not
 * yet schedulable (TDS_INACTIVE, e.g. not fully constructed) is left
 * alone -- thread_suspend_one() itself only handles a thread that can
 * actually be suspended; forcing it onto every possible td_state would
 * be inventing cases this task does not ask for.
 */
u_int	k24t00_exclude_stop_threads(void);
u_int
k24t00_exclude_stop_threads(void)
{
	struct k24t00_exclude_entry *list;
	struct thread *self;
	u_int i, n, stopped;

	list = k24t00_exclude_ptr();
	if (list == NULL)
		return (0);
	self = curthread;
	stopped = 0;
	/*
	 * K24-T00 round 29 fix: bound by K24T00_EXCLUDE_MAX
	 * unconditionally -- same reasoning as k24t00_td_is_excluded()'s
	 * own identical fix (a stale, unprotected k24t00_exclude_n can
	 * exceed the array's real 64-entry capacity).
	 */
	n = k24t00_exclude_n;
	if (n > K24T00_EXCLUDE_MAX)
		n = K24T00_EXCLUDE_MAX;
	for (i = 0; i < n; i++) {
		struct thread *td;
		struct proc *p;

		td = list[i].td;
		if (td == NULL || td == self)
			continue;
		p = td->td_proc;
		if (p == NULL)
			continue;
		PROC_SLOCK(p);
		thread_lock(td);
		/*
		 * K24-T00 round 29 fix: thread_suspend_one() itself
		 * suspends a thread from ANY schedulable state -- it is
		 * not limited to RUNQ/CAN_RUN/RUNNING (see thread_
		 * single()'s own unconditional call to it for every
		 * other thread in a process, sys/kern/kern_thread.c).
		 * The original, narrower condition here incorrectly
		 * skipped a thread already TD_IS_INHIBITED (e.g.
		 * TDI_SLEEPING, the common state for a blocked daemon
		 * like devd/syslogd/sh) as if it were already handled --
		 * it was not, which is why the first live run recorded
		 * 13 candidates but stopped 0. The only state that must
		 * be excluded is TD_IS_SUSPENDED itself
		 * (thread_suspend_one() KASSERTs against double-
		 * suspending).
		 */
		if (!TD_IS_SUSPENDED(td)) {
			thread_suspend_one(td);
			stopped++;
		}
		thread_unlock(td);
		PROC_SUNLOCK(p);
	}
	return (stopped);
}

/*
 * K24-T00 round 19: thin public wrapper around the existing, already-
 * proven hibernate_md_kva_install() (static to this file) so acpi.c's
 * post-copy install pass can call it without this file needing to
 * expose its full static surface. ha is likewise taken from
 * hibernate_current_attempt -- hibernate_md_kva_install() itself only
 * uses ha for hib_pa_in_dst_md()'s own destination-set check on freshly
 * allocated table pages, read-only, identical semantics to every
 * existing pre-copy caller.
 */
int hibernate_md_kva_install_pub(vm_offset_t va, vm_paddr_t leaf_pa,
    uint64_t flags, bool force_overwrite);
int
hibernate_md_kva_install_pub(vm_offset_t va, vm_paddr_t leaf_pa,
    uint64_t flags, bool force_overwrite)
{
	extern struct hibernate_attempt *k24t00_hibernate_current_attempt(void);

	return (hibernate_md_kva_install(k24t00_hibernate_current_attempt(),
	    va, leaf_pa, flags, force_overwrite));
}
#undef HIB_KVA_FAIL

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
	if ((entry & X86_PG_V) == 0)
		return (0);
	if ((entry & PG_PS) != 0) {
		/*
		 * va resolves through a 1 GiB PDPTE.  There is no PD/PT
		 * below a superpage, so the leaf frame IS this entry's
		 * frame (offset by va's own low bits) -- self-copy that
		 * exact 4 KiB page here (if copy_leaf), matching
		 * hibernate_md_tree_walk()'s own superpage handling, then
		 * stop: the walk has nothing further to traverse.
		 */
		if (copy_leaf) {
			table_pa = ((entry & PG_PS_PDP_FRAME) |
				       (va & PDPMASK)) &
			    PG_FRAME;
			if ((error = hibernate_md_selfcopy_page(ha, vector,
				 vector_count, table_pa, &did)) != 0)
				return (error);
		}
		if (did)
			(*countp)++;
		return (0);
	}
	table_pa = entry & PG_FRAME;
	if ((error = hibernate_md_selfcopy_page(ha, vector, vector_count,
		 table_pa, &did)) != 0)
		return (error);
	pd = (pd_entry_t *)PHYS_TO_DMAP(table_pa);
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = pd[index];
	if ((entry & X86_PG_V) == 0)
		return (0);
	if ((entry & PG_PS) != 0) {
		/*
		 * va resolves through a 2 MiB PDE.  Same reasoning as the
		 * 1 GiB case above: self-copy the exact 4 KiB page va
		 * falls in (if copy_leaf), then stop.
		 */
		if (copy_leaf) {
			table_pa = ((entry & PG_PS_FRAME) | (va & PDRMASK)) &
			    PG_FRAME;
			if ((error = hibernate_md_selfcopy_page(ha, vector,
				 vector_count, table_pa, &did)) != 0)
				return (error);
		}
		if (did)
			(*countp)++;
		return (0);
	}
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

int
hibernate_md_selfcopy_range(const struct hibernate_attempt *ha,
    vm_paddr_t *wvec, uint64_t p, vm_offset_t va, size_t len, u_int *countp)
{
	vm_offset_t va_start, va_end;
	int error;

	va_start = trunc_page(va);
	va_end = round_page(va + len);
	error = 0;
	for (; va_start < va_end && error == 0; va_start += PAGE_SIZE)
		error = hibernate_md_selfcopy_walk(ha, wvec, p,
		    kernel_pmap->pm_cr3, va_start, true, countp);
	return (error);
}

/*
 * Independently prove every mapping the private-domain trampoline may touch.
 * All arithmetic used to enumerate runs and arena/vector pages is checked.
 */
static int
hibernate_md_private_tree_validate(const struct hibernate_attempt *ha,
    const struct hibernate_md_run *runs, uint64_t run_count,
    const vm_paddr_t *vector, uint64_t vector_count, vm_paddr_t window_va,
    const vm_paddr_t *storage_pa, uint64_t vector_pages, vm_paddr_t xsave_pa,
    vm_paddr_t private_cr3)
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
	/*
	 * independently re-walk each window-mapped backing page,
	 * proving VA window_va+j*PAGE_SIZE resolves to the EXACT scattered
	 * frame storage_pa[j] the builder was given -- the same
	 * independent-walk discipline every other object in this function
	 * already receives, just keyed by window VA instead of identity PA.
	 */
	for (j = 0; j < vector_pages; j++) {
		if (__builtin_mul_overflow(j, (uint64_t)HIB_PAGE_SIZE,
			&bytes) ||
		    __builtin_add_overflow(window_va, bytes, &pa))
			return (EOVERFLOW);
		if (!hibernate_md_walk_matches(private_cr3, pa,
			storage_pa[j], X86_PG_V | X86_PG_RW))
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

static int
hib_selfcopy_pt(const struct hibernate_attempt *ha, vm_paddr_t *wvec,
    uint64_t p, vm_offset_t va, u_int *count)
{

	return (hibernate_md_selfcopy_walk(ha, wvec, p,
	    kernel_pmap->pm_cr3, va, false, count));
}

static bool
hib_staged_leaf(const struct hibernate_attempt *ha,
    const vm_paddr_t *wvec, uint64_t p, vm_offset_t va,
    struct hibernate_md_walk *walk)
{

	return (hibernate_md_staged_leaf_for_live_slot(ha, wvec, p, va,
	    walk));
}

/*
 * hib_saved_domain_leaf_valid() -- quiet (non-printf) variant of
 * the saved-domain leaf capture, used by the per-thread kstack self-copy
 * loop's own fail-closed decision below. Walks the SAVED domain's own
 * page tables (rooted at hi_pcb.hp_cr3), reading each intermediate
 * table page via the destination-set+wvec mechanism when that page is
 * itself part of the K-10 destination set, or directly via
 * PHYS_TO_DMAP() otherwise (a page outside the destination set is never
 * touched by the destructive copy, so its current live content is
 * already byte-identical to what the saved image held -- the same
 * reasoning this function's own saved-domain walk already documents).
 * Returns true only if every level down to a terminal 4 KiB PTE is
 * present/valid; never returns a superpage leaf as "valid" here (this
 * caller only needs a yes/no answer for a specific 4 KiB VA, matching
 * the page-at-a-time granularity the kstack loop already uses).
 */
static u_int hibernate_resume_kstack_skip_count;

static u_int k24t00_pte_verify_threads;
static u_int k24t00_pte_verify_mismatch_threads;
static pid_t k24t00_pte_verify_first_pid = -1;
static vm_offset_t k24t00_pte_verify_first_va;
static vm_paddr_t k24t00_pte_verify_first_expected_pa;
static uint64_t k24t00_pte_verify_first_actual_pte;

static bool
k24t00_live_pte_read(vm_offset_t va, uint64_t *pte_out)
{
	vm_paddr_t table_pa;
	uint64_t entry;
	u_int index;

	table_pa = kernel_pmap->pm_cr3 & PG_FRAME;
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	entry = ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0)
		return (false);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	entry = ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (false);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	entry = ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (false);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	entry = ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	*pte_out = entry;
	return (true);
}

static bool
hib_saved_domain_leaf_valid(const struct hibernate_attempt *ha,
    const vm_paddr_t *wvec, uint64_t p, vm_offset_t va)
{
	vm_paddr_t table_pa;
	uint64_t entry, idx;
	u_int index;
	int err;

	table_pa = ha->ha_image.hi_pcb.hp_cr3 & PG_FRAME;
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0)
		return (false);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (false);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0 || (entry & PG_PS) != 0)
		return (false);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	return ((entry & X86_PG_V) != 0);
}

/*
 * K24-T00 round 11: the load-bearing fix. hibernate_md_staged_read()'s
 * PRIMARY resolution path (hib_md_safe_resolve() against
 * kernel_pmap->pm_cr3, i.e. THIS resume boot's own LIVE page tables)
 * answers "what is VA mapped to in the CURRENTLY RUNNING kernel", not
 * "what was VA mapped to in the SAVED image". For boot-invariant
 * regions (kernel text/.data/.bss, whose page tables are rebuilt
 * identically by every boot of the same kernel binary) the two
 * questions happen to have the same answer, which is exactly why
 * every check on those regions came back clean across ten prior
 * rounds. For anything from a UMA zone (struct proc, struct thread,
 * and every other dynamically-allocated kernel object) the two boots
 * assign DIFFERENT physical pages to the SAME virtual address -- the
 * live walk then either fails to resolve, or worse, resolves to a
 * live PA that happens to ALSO be a current destination-set member
 * (coincidental, not causal), silently returning whatever unrelated
 * content that live page holds instead of the image's own page for
 * that VA. Round 10 proved devd's struct proc is written to a STORED
 * interval with real content at save time; this is the mechanism that
 * then serves zeros for it at resume time regardless.
 *
 * hibernate_md_staged_resolve_via_saved_tables() performs the SAME
 * walk hib_saved_domain_leaf_valid() (immediately above) already
 * proved correct and in production use for the kstack self-copy
 * fail-closed path -- rooted at hi_pcb.hp_cr3, the SAVED kernel's own
 * CR3 captured into the image's PCB at save time -- but returns the
 * resolved PHYSICAL ADDRESS instead of a bare validity bool, which is
 * what a read primitive needs. Each intermediate table page is read
 * through the destination-set+wvec mechanism when that page is ITSELF
 * a destination-set member (meaning the destructive copy has already
 * overwritten its live content with image content, so only wvec[]
 * holds the true saved bytes), or directly via PHYS_TO_DMAP() when it
 * is not (a page outside the destination set was never touched by the
 * copy, so its live content is still byte-identical to what the image
 * held -- the identical reasoning hib_saved_domain_leaf_valid()'s own
 * comment already documents for exactly this situation). This covers
 * EVERY VA the kernel's own saved address space maps, both
 * boot-invariant and dynamic, because hi_pcb.hp_cr3 is the root of the
 * ENTIRE saved kernel map, not a partial or region-limited view.
 */
static int
hibernate_md_staged_resolve_via_saved_tables(const struct hibernate_attempt *ha,
    const vm_paddr_t *wvec, uint64_t p, vm_offset_t va, vm_paddr_t *pa_out)
{
	vm_paddr_t table_pa;
	uint64_t entry, idx;
	u_int index;
	int err;

	table_pa = ha->ha_image.hi_pcb.hp_cr3 & PG_FRAME;
	index = (u_int)((va >> PML4SHIFT) & (NPML4EPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0)
		return (ENOENT);

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PDPSHIFT) & (NPDPEPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0)
		return (ENOENT);
	if ((entry & PG_PS) != 0) {
		*pa_out = ((entry & PG_PS_PDP_FRAME) | (va & PDPMASK)) &
		    PG_FRAME;
		return (0);
	}

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PDRSHIFT) & (NPDEPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0)
		return (ENOENT);
	if ((entry & PG_PS) != 0) {
		*pa_out = ((entry & PG_PS_FRAME) | (va & PDRMASK)) & PG_FRAME;
		return (0);
	}

	table_pa = entry & PG_FRAME;
	index = (u_int)((va >> PAGE_SHIFT) & (NPTEPG - 1));
	err = hibernate_md_dst_page_index(ha, table_pa, &idx);
	entry = (err == 0 && idx < p) ?
	    ((const uint64_t *)PHYS_TO_DMAP(wvec[idx]))[index] :
	    ((const uint64_t *)PHYS_TO_DMAP(table_pa))[index];
	if ((entry & X86_PG_V) == 0)
		return (ENOENT);
	*pa_out = (entry & PG_FRAME) | (va & PAGE_MASK);
	return (0);
}

static int
hibernate_md_staged_read(const struct hibernate_attempt *ha,
    const vm_paddr_t *wvec, uint64_t p, vm_offset_t va, void *buf, size_t len)
{
	uint8_t *dst;
	vm_offset_t cur, page_va;
	size_t remaining, page_off, chunk;
	vm_paddr_t staged_pa;
	uint64_t dst_idx;
	int err;

	dst = buf;
	cur = va;
	remaining = len;
	while (remaining > 0) {
		page_va = trunc_page(cur);
		page_off = (size_t)(cur - page_va);
		chunk = MIN(PAGE_SIZE - page_off, remaining);

		/*
		 * K24-T00 round 11: the load-bearing fix (see the
		 * extensive comment on hib_saved_domain_leaf_valid()/
		 * hibernate_md_staged_resolve_via_saved_tables() above).
		 * The two PRIOR resolution paths here both rooted their
		 * walk at kernel_pmap->pm_cr3 -- THIS resume boot's own
		 * LIVE page tables -- which only agrees with the SAVED
		 * image's own mapping for boot-invariant VAs (kernel
		 * text/.data/.bss). For any VA from a UMA zone (struct
		 * proc, struct thread, and everything else dynamically
		 * allocated), the two boots assign different physical
		 * pages to the same VA; the live walk then either fails
		 * (false ENOENT, masking a page that IS present in the
		 * image) or -- the worse case, confirmed directly this
		 * round for devd's own struct proc -- resolves to a live
		 * PA that is ALSO a destination-set member by pure
		 * coincidence, silently returning that unrelated page's
		 * content (zeros, or someone else's data) instead of the
		 * image's own page for this VA.
		 *
		 * hibernate_md_staged_resolve_via_saved_tables() walks
		 * from hi_pcb.hp_cr3 -- the SAVED kernel's own CR3,
		 * captured into the image's PCB at save time -- which is
		 * the root of the saved kernel's ENTIRE address space, so
		 * this single path correctly covers both boot-invariant
		 * and dynamically-allocated VAs; no separate live-walk
		 * fallback is needed or kept, because the live walk is
		 * not "sometimes correct, sometimes wrong" -- it answers
		 * a different question (this boot's mapping) than the one
		 * this function exists to answer (the saved image's own
		 * mapping), and no VA class is exempt from that
		 * distinction merely by chance occasionally agreeing.
		 */
		err = hibernate_md_staged_resolve_via_saved_tables(ha, wvec,
		    p, page_va, &staged_pa);
		if (err != 0)
			return (err);
		if (hibernate_md_dst_page_index(ha, trunc_page(staged_pa),
			&dst_idx) == 0 && dst_idx < p) {
			memcpy(dst,
			    (const uint8_t *)PHYS_TO_DMAP(wvec[dst_idx]) +
				page_off,
			    chunk);
		} else {
			/*
			 * staged_pa is NOT a destination-set member: this
			 * page was never a target of the destructive copy,
			 * so its CURRENT live content at that physical
			 * address is still byte-identical to what the
			 * image held at save time -- the identical
			 * reasoning hib_saved_domain_leaf_valid()'s own
			 * comment already documents for its own
			 * intermediate table pages.
			 */
			memcpy(dst,
			    (const uint8_t *)PHYS_TO_DMAP(staged_pa) +
				page_off,
			    chunk);
		}

		dst += chunk;
		cur += chunk;
		remaining -= chunk;
	}
	return (0);
}

/*
 * K24-T00 site=50 fix: resolve the resuming thread's own kstack leaf
 * PTEs EARLY -- immediately after wvec becomes valid, before this
 * function's own caller (hibernate_machdep_prepare()) runs its later
 * self-copy sweep (trampoline/GDT/KPML4/live-kstack-protect) -- and
 * cache the results for hibernate_md_staged_leaf_for_live_slot()
 * itself to consult first (see the cache check at its own top).
 *
 * Root cause this directly targets: hibernate_md_staged_leaf_for_
 * live_slot()'s own round-2 fallback (the "vector[sidx] == pt_page_pa"
 * branch) re-derives sidx via hibernate_md_dst_page_index() on the
 * SAME pt_page_pa that triggered the aliasing check in the first
 * place -- a pure function of physical address, so it always yields
 * the SAME destination-set index back into the SAME already-
 * overwritten vector[] slot.  It is not an independent read in that
 * exact case, only a differently-shaped read of the identical wrong
 * bytes -- which is exactly why fail_reason=9 persists no matter how
 * the fallback's own per-level table reads are routed.  Resolving
 * here, before the sweep that introduces the aliasing has run at all,
 * means vector[sidx] for the shared PT page still holds its genuine
 * staged content, so the function's own ORDINARY (non-fallback) path
 * already succeeds -- no parallel lookup implementation is added;
 * this calls the exact same hibernate_md_staged_leaf_for_live_slot(),
 * only early enough that its aliasing detection never triggers.
 *
 * Purely additive and fails open: any resolution failure here just
 * leaves the cache empty (k24t00_early_kstack_count == 0 entries
 * marked valid), so the original, unchanged call site later in
 * hibernate_machdep_prepare() runs exactly as before, with identical
 * diagnostics, for any page this early capture did not get.
 */
static void
k24t00_early_kstack_capture(const struct hibernate_attempt *ha,
    const vm_paddr_t *wvec, uint64_t p)
{
	uint64_t saved_susppcbs_ptr, saved_susppcb0_ptr;
	register_t staged_pcb_rsp;
	vm_offset_t susppcbs_global_va, susppcb_pcb_va;
	vm_offset_t kstack_va, kstack_base, kstack_end, kstack_slot;
	vm_size_t kstack_stride;
	u_int pg;

	bzero(k24t00_early_kstack_valid, sizeof(k24t00_early_kstack_valid));
	k24t00_early_kstack_count = 0;
	if (susppcbs == NULL || susppcbs[0] == NULL)
		return;

	susppcbs_global_va = (vm_offset_t)&susppcbs;
	if (hibernate_md_staged_read(ha, wvec, p, susppcbs_global_va,
		&saved_susppcbs_ptr, sizeof(saved_susppcbs_ptr)) != 0 ||
	    saved_susppcbs_ptr == 0)
		return;
	if (hibernate_md_staged_read(ha, wvec, p,
		(vm_offset_t)saved_susppcbs_ptr, &saved_susppcb0_ptr,
		sizeof(saved_susppcb0_ptr)) != 0 ||
	    saved_susppcb0_ptr == 0)
		return;
	susppcb_pcb_va = (vm_offset_t)saved_susppcb0_ptr +
	    offsetof(struct susppcb, sp_pcb);
	if (hibernate_md_staged_read(ha, wvec, p,
		susppcb_pcb_va + offsetof(struct pcb, pcb_rsp),
		&staged_pcb_rsp, sizeof(staged_pcb_rsp)) != 0)
		return;

	kstack_va = staged_pcb_rsp;
	kstack_va &= ~(register_t)PAGE_MASK;
	if ((vm_offset_t)kstack_va < VM_MIN_KERNEL_ADDRESS ||
	    (vm_offset_t)kstack_va >= VM_MAX_KERNEL_ADDRESS)
		return;

	kstack_stride = ptoa(KSTACK_PAGES + KSTACK_GUARD_PAGES);
	kstack_slot = VM_MIN_KERNEL_ADDRESS +
	    (((vm_offset_t)staged_pcb_rsp - VM_MIN_KERNEL_ADDRESS) /
		kstack_stride) * kstack_stride;
	kstack_base = kstack_slot + ptoa(KSTACK_GUARD_PAGES);
	kstack_end = kstack_base + ptoa(KSTACK_PAGES);
	if (kstack_base < kstack_slot || kstack_end < kstack_base ||
	    (vm_offset_t)staged_pcb_rsp < kstack_base ||
	    (vm_offset_t)staged_pcb_rsp >= kstack_end)
		return;

	for (pg = 0; pg < KSTACK_PAGES &&
	    pg < K24T00_EARLY_KSTACK_CACHE_MAX; pg++) {
		vm_offset_t stack_va;
		struct hibernate_md_walk walk;

		stack_va = kstack_base + (vm_offset_t)pg * PAGE_SIZE;
		if (hibernate_md_staged_leaf_for_live_slot(ha, wvec, p,
			stack_va, &walk) &&
		    (walk.hmw_flags & (X86_PG_V | X86_PG_RW)) ==
			(X86_PG_V | X86_PG_RW)) {
			k24t00_early_kstack_va[pg] = stack_va;
			k24t00_early_kstack_walk[pg] = walk;
			k24t00_early_kstack_valid[pg] = true;
		}
	}
	k24t00_early_kstack_count = MIN(KSTACK_PAGES,
	    K24T00_EARLY_KSTACK_CACHE_MAX);
}

#define HIB_STAGED_MAX_THREADS 256
_Static_assert(HIB_STAGED_MAX_THREADS == 256,
    "K24T00_KSTACK_STASH_MAX's own literal 256 (near this file's top, "
    "forward-reference-by-literal) must track HIB_STAGED_MAX_THREADS");
#define HIB_STAGED_ITER_GUARD  4096

struct hib_staged_thread {
	vm_offset_t kstack_va;
	u_int kstack_pages;
	pid_t pid;	/* K24-T00: for targeted syslogd/devd marker counts */
	/*
	 * K24-T00 round 3: this thread's own staged td_tid, captured
	 * alongside pid for the independent pid/tid staged-set
	 * cross-check (see k24t00_staged_tid_g[]/hibernate_k24t00_
	 * tid_is_staged(), above).
	 */
	lwpid_t tid;
	/*
	 * K24-T00: staged pcb_rsp sanity check. Captured read-only,
	 * pre-copy, from this thread's own staged td_pcb->pcb_rsp, so
	 * the resume continuation's own pre-copy validation can confirm
	 * each thread's saved stack pointer actually lands inside that
	 * SAME thread's own kstack range (already proven fully covered
	 * and path-protected above) rather than trusting the two are
	 * consistent by construction.
	 */
	register_t pcb_rsp;
	bool pcb_rsp_valid;
	char comm[MAXCOMLEN + 1];
	/*
	 * K24-T00: this thread's own staged td_pcb pointer value (a
	 * kernel virtual address, boot-invariant layout) -- captured
	 * unconditionally alongside pcb_rsp above so the resume
	 * continuation's switch-time provenance check (see
	 * k24t00_staged_pcb_page_g[]/hibernate_k24t00_pcb_is_staged(),
	 * below) has every staged thread's PCB page available, not just
	 * the ones whose deeper pcb_rsp read also succeeded.
	 */
	vm_offset_t pcb_va;
	/*
	 * K24-T00 round 27: this thread's own staged struct thread *
	 * pointer value (thread_cursor at capture time), so the
	 * populate-pass offender report below can name the exact
	 * thread object a stash-resolution failure traces back to,
	 * not just its pid/comm/tid.
	 */
	vm_offset_t td_va;
	/*
	 * K24-T00 round 31: this thread's own staged pcb->pcb_save
	 * pointer (the FPU/XSAVE save area fpu_activate_sw()'s
	 * restore_fpu_curthread() writes into on first use post-
	 * resume). Captured from staged_thread_pcb (already read below
	 * for pcb_rsp) rather than a fresh staged read. 0 if the pcb
	 * read failed or pcb_save was NULL for this thread.
	 */
	vm_offset_t fpu_save_va;
};

static int
hibernate_md_enumerate_staged_threads(const struct hibernate_attempt *ha,
    const vm_paddr_t *wvec, uint64_t p, struct hib_staged_thread *out,
    u_int max_out, u_int *n_out)
{
	struct pidhashhead *table;
	struct proc **heads;
	struct proc *proc_cursor;
	u_long hash, i;
	u_int chains_entered, n, swept_nonnull;
	int error;
	/*
	 * K24-T00 round 2: chain-walk failure counting. Every staged
	 * read in the main enumeration loop below can fail (an
	 * unresolvable page in the staged image), and until now each
	 * failure was handled with a silent "break" that abandons the
	 * REST of the current chain (proc-link failure) or the rest of
	 * the current process's threads (thread-link failure) -- the
	 * loop then simply moves on to the next bucket/process as if
	 * nothing were lost. A real image thread sitting past a broken
	 * link is therefore never staged, never installed, yet still
	 * schedulable once APs are released. Count both failure
	 * kinds and their first error code here, unconditionally, so a
	 * single printf below can report the totals every run.
	 */
	u_int k24t00_chain_fail_count, k24t00_thread_fail_count;
	int k24t00_chain_fail_err, k24t00_thread_fail_err;
	/*
	 * K24-T00 round 5: proc_ok/thread-validity gate rejection
	 * counting. Both gates silently `continue` past a proc/thread
	 * that read successfully but failed a CONTENT condition -- no
	 * counter, no print, unlike the round-2 chain-link read
	 * failures. Count each distinct reason separately so a
	 * dominant single cause (vs. scattered noise) is visible, and
	 * capture the first few rejections' identifying detail (pid,
	 * p_state, raw p_comm bytes for proc-level; pid, kva, pages for
	 * thread-level) without printing per-rejection spam.
	 */
	u_int k24t00_rej_prs_new, k24t00_rej_state_lo, k24t00_rej_state_hi;
	u_int k24t00_rej_pid_range, k24t00_rej_no_nul;
	u_int k24t00_rej_kva_range, k24t00_rej_kva_align;
	u_int k24t00_rej_pages_range;
#define K24T00_REJ_FIRST_MAX 8
	struct {
		pid_t pid;
		int p_state;
		char comm[MAXCOMLEN + 1];
	} k24t00_rej_proc_first[K24T00_REJ_FIRST_MAX];
	u_int k24t00_rej_proc_first_n;
	struct {
		pid_t pid;
		vm_offset_t kva;
		u_int pages;
	} k24t00_rej_thread_first[K24T00_REJ_FIRST_MAX];
	u_int k24t00_rej_thread_first_n;
	/*
	 * K24-T00 round 7: user-process exclusion hunt. procs_visited
	 * counts every proc_cursor read that SUCCEEDED (error == 0),
	 * i.e. every proc the p_hash walk actually reached, regardless
	 * of whether the content gate then accepted or rejected it --
	 * this is the number that answers "does the walk visit user
	 * procs at all", independent of acceptance. procs_accepted is
	 * the existing `n` counter's own proc-level analogue (n counts
	 * ACCEPTED THREADS, not accepted procs, so a separate count is
	 * needed). sslp_* track SSLEEP/SRUN (ordinary user-process
	 * states) specifically, split by accept/reject, because those
	 * are exactly the states a normal user process is almost always
	 * found in -- a kernel proc is essentially never SSLEEP/SRUN in
	 * the sense of having userland to sleep/run in, though SRUN/
	 * SSLEEP cover kernel threads' procs too (e.g. "kernel" proc0's
	 * own threads can be SRUN) so this is suggestive, not proof, by
	 * itself -- the first-15-accepted pid/comm/threadcount list
	 * below is the authoritative evidence.
	 */
	u_int k24t00_procs_visited, k24t00_procs_accepted;
	u_int k24t00_sslp_accepted, k24t00_sslp_rejected;
/*
	 * K24-T00 round 7b: raised from 15 to 40 -- the first clean
	 * run showed procs_accepted=16 with only the first 15
	 * (all low, sequential, kernel-internal pids 0-14) visible,
	 * hiding whether the 16th accepted proc was devd/syslogd.
	 * Bounded by HIB_STAGED_MAX_THREADS (256) in principle, but
	 * 40 is ample: no run so far has accepted more than ~16.
	 */
#define K24T00_ACCEPTED_FIRST_MAX 40
	struct {
		pid_t pid;
		char comm[MAXCOMLEN + 1];
		u_int nthreads;
	} k24t00_accepted_first[K24T00_ACCEPTED_FIRST_MAX];
	u_int k24t00_accepted_first_n;
	/*
	 * K24-T00 round 8: one-shot deep-resolution diagnostic. Fires
	 * exactly once for the FIRST rejected proc (zero content,
	 * read succeeded) and once for the FIRST accepted proc, so the
	 * two resolution paths are visible side by side for comparison.
	 */
	bool k24t00_deep_rej_done, k24t00_deep_acc_done;
	int error;

	table = pidhashtbl;
	hash = pidhash;
	if (table == NULL)
		return (EINVAL);

	heads = malloc((size_t)(hash + 1) * sizeof(*heads), M_TEMP,
	    M_NOWAIT | M_ZERO);
	if (heads == NULL)
		return (ENOMEM);

	swept_nonnull = 0;
	for (i = 0; i <= hash; i++) {
		error = hibernate_md_staged_read(ha, wvec, p,
		    (vm_offset_t)&table[i], &heads[i], sizeof(heads[i]));
		if (error != 0)
			continue;
		if (heads[i] != NULL)
			swept_nonnull++;
	}

	n = 0;
	chains_entered = 0;
	k24t00_chain_fail_count = 0;
	k24t00_thread_fail_count = 0;
	k24t00_chain_fail_err = 0;
	k24t00_thread_fail_err = 0;
	k24t00_kstack_stash_n = 0;
	k24t00_exclude_n = 0;
	k24t31_recorded_n = 0;
	for (i = 0; i <= hash; i++) {
		struct proc staged_proc;
		u_int iter_guard;

		proc_cursor = heads[i];
		if (proc_cursor != NULL)
			chains_entered++;
		iter_guard = 0;

		while (proc_cursor != NULL) {
			struct thread *thread_cursor;
			bool has_nul, proc_ok;
			u_int k, thread_guard;

			if (++iter_guard > HIB_STAGED_ITER_GUARD) {
				error = ELOOP;
				goto out;
			}
			error = hibernate_md_staged_read(ha, wvec, p,
			    (vm_offset_t)proc_cursor, &staged_proc,
			    sizeof(staged_proc));
			if (error != 0) {
				/*
				 * K24-T00 round 2: this read is what
				 * would have yielded LIST_NEXT(&staged_
				 * proc, p_hash) -- its failure means the
				 * REST of this bucket's chain (unknown
				 * length) is abandoned, unvisited, by the
				 * break below.
				 */
				k24t00_chain_fail_count++;
				if (k24t00_chain_fail_count == 1)
					k24t00_chain_fail_err = error;
				break;
			}

			proc_ok = staged_proc.p_state != PRS_NEW &&
			    staged_proc.p_state >= SIDL &&
			    staged_proc.p_state <= SLOCK &&
			    staged_proc.p_pid >= 0 &&
			    staged_proc.p_pid <= PID_MAX;
			has_nul = false;
			for (k = 0; k < sizeof(staged_proc.p_comm); k++) {
				if (staged_proc.p_comm[k] == '\0') {
					has_nul = true;
					break;
				}
			}
			proc_ok = proc_ok && has_nul;
			if (!proc_ok) {
				proc_cursor = LIST_NEXT(&staged_proc, p_hash);
				continue;
			}

			thread_cursor = TAILQ_FIRST(&staged_proc.p_threads);
			thread_guard = 0;
			while (thread_cursor != NULL) {
				struct thread staged_thread;
				vm_offset_t kva;

				if (++thread_guard > HIB_STAGED_ITER_GUARD) {
					error = ELOOP;
					goto out;
				}
				error = hibernate_md_staged_read(ha, wvec, p,
				    (vm_offset_t)thread_cursor,
				    &staged_thread, sizeof(staged_thread));
				if (error != 0) {
					/*
					 * K24-T00 round 2: this read is
					 * what would have yielded TAILQ_
					 * NEXT(&staged_thread, td_plist)
					 * -- its failure means the REST
					 * of this process's own thread
					 * list (unknown length) is
					 * abandoned, unvisited, by the
					 * break below; the chain walk
					 * itself continues to the next
					 * process.
					 */
					k24t00_thread_fail_count++;
					if (k24t00_thread_fail_count == 1)
						k24t00_thread_fail_err = error;
					break;
				}

				kva = trunc_page(
				    (vm_offset_t)staged_thread.td_kstack);
				if (kva >= VM_MIN_KERNEL_ADDRESS &&
				    kva < VM_MAX_KERNEL_ADDRESS &&
				    ((vm_offset_t)staged_thread.td_kstack &
				    PAGE_MASK) == 0 &&
				    staged_thread.td_kstack_pages > 0 &&
				    staged_thread.td_kstack_pages <=
				    KSTACK_PAGES && n < max_out) {
					out[n].kstack_va = kva;
					out[n].kstack_pages =
					    staged_thread.td_kstack_pages;
					out[n].pid = staged_proc.p_pid;
					out[n].tid = staged_thread.td_tid;
					out[n].pcb_va = (vm_offset_t)
					    staged_thread.td_pcb;
					out[n].td_va =
					    (vm_offset_t)thread_cursor;
					memcpy(out[n].comm,
					    staged_proc.p_comm,
					    sizeof(out[n].comm));
					/*
					 * K24-T00: capture this thread's own
					 * staged pcb_rsp, read-only, for the
					 * PCB sanity check below. td_pcb is
					 * itself staged-image content (a
					 * pointer value restored verbatim by
					 * the eventual K-10 copy), so it must
					 * be read via the SAME staged
					 * accessor already used for every
					 * other staged-image field in this
					 * walk, not dereferenced directly.
					 * A read failure here is recorded as
					 * invalid, not fatal to the whole
					 * enumeration -- the kstack entry
					 * above is still valid and useful on
					 * its own.
					 */
					if (staged_thread.td_pcb != NULL &&
					    hibernate_md_staged_read(ha, wvec,
						p,
						(vm_offset_t)
						    staged_thread.td_pcb,
						&staged_thread_pcb,
						sizeof(staged_thread_pcb)) ==
					    0) {
						out[n].pcb_rsp =
						    staged_thread_pcb.pcb_rsp;
						out[n].pcb_rsp_valid = true;
						out[n].fpu_save_va =
						    (vm_offset_t)
							staged_thread_pcb
							    .pcb_save;
						/*
						 * K24-T00: pcb_cr3
						 * asymmetry check. Print
						 * one line per thread of
						 * interest (syslogd, devd,
						 * and one kernel-only
						 * control) comparing this
						 * thread's own staged
						 * pcb_cr3 against the live
						 * kernel_pmap->pm_cr3,
						 * safe here (pre-copy,
						 * same safety window as
						 * the existing kstack
						 * coverage printf several
						 * lines below).
						 */
						if (staged_proc.p_pid ==
						    871 ||
						    staged_proc.p_pid ==
							601 ||
						    staged_proc.p_pid == 0) {
							printf(
							    "hibernate: k24t00: pcb_cr3 check: pid=%d comm=%s pcb_cr3=%#jx kernel_pmap_cr3=%#jx %s\n",
							    (int)staged_proc
								.p_pid,
							    staged_proc
								.p_comm,
							    (uintmax_t)
								staged_thread_pcb
								    .pcb_cr3,
							    (uintmax_t)
								kernel_pmap
								    ->pm_cr3,
							    (vm_paddr_t)
									staged_thread_pcb
									    .pcb_cr3 ==
								kernel_pmap
								    ->pm_cr3 ?
								"EQUAL" :
								"NOT-EQUAL");
						}
					} else {
						out[n].pcb_rsp = 0;
						out[n].pcb_rsp_valid = false;
						out[n].fpu_save_va = 0;
					}
					if (staged_proc.p_pid == 871 ||
					    staged_proc.p_pid == 601) {
						hibernate_k24t04_raw_marker(
						    'W');
						hibernate_k24t04_raw_uint(1);
					}
					n++;
				}
				thread_cursor = TAILQ_NEXT(&staged_thread,
				    td_plist);
			}
			proc_cursor = LIST_NEXT(&staged_proc, p_hash);
		}
	}

	printf("hibernate: k24t00: chain-walk failures: "
	    "chain_link_fail=%u chain_link_err=%d "
	    "thread_link_fail=%u thread_link_err=%d\n",
	    k24t00_chain_fail_count, k24t00_chain_fail_err,
	    k24t00_thread_fail_count, k24t00_thread_fail_err);

	/*
	 * K24-T00 round 2: fail-closed. A chain-link or thread-link
	 * read failure means the enumeration silently stopped short of
	 * the staged image's true thread set -- some real thread may
	 * never have been staged or installed, yet remains schedulable
	 * once APs are released. Refuse rather than proceed with a
	 * known-partial enumeration; the caller
	 * (hibernate_machdep_prepare()) already treats any nonzero
	 * return here as refuse-and-cold-boot (see
	 * sys/kern/kern_hibernate.c's "if (error != 0) goto cleanup;"
	 * immediately after its own call to
	 * hibernate_machdep_prepare()), so this is a plain extension of
	 * behaviour that already exists for every other error path in
	 * this same function, not new machinery.
	 */
	if (k24t00_chain_fail_count > 0 || k24t00_thread_fail_count > 0) {
		error = EIO;
		goto out;
	}

	if (swept_nonnull != chains_entered) {
		error = EDOOFUS;
		goto out;
	}
	*n_out = n;
	error = 0;
out:
	free(heads, M_TEMP);
	return (error);
}

int
hibernate_machdep_prepare(struct hibernate_attempt *ha)
{
	struct hibernate_md_arena_layout layout;
	struct hibernate_arena_header hah;
	struct hibernate_handoff_record hhr;
	struct hibernate_md_run *runs;
	vm_paddr_t window_va, xsave_pa, private_cr3, arena_end;
	vm_paddr_t trampoline_stub_pa;
	const vm_paddr_t *vector_va;
	const vm_paddr_t *storage_pa;
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
	/*
	 * kstack_va, computed inside the resumectx-stack install block
	 * below, is needed again later in this same function (the FPU
	 * save-area install) but that block's own "register_t
	 * kstack_va;" is scoped to its own braces. Mirrored here at
	 * function scope, assigned inside that block, read at the later
	 * site.
	 */
	register_t k24t00_kstack_va __unused = 0;
	/*
	 * staged_pcb->pcb_save is read inside the kstack_va block below,
	 * whose own braces close before this value is needed again (the
	 * FPU save-area page-table-path protection, below) -- mirrored
	 * at function scope exactly like k24t00_kstack_va immediately
	 * above, for the identical reason.
	 */
	struct savefpu *k24t00_staged_fpu_save __unused = NULL;
	/*
	 * __stack_chk_guard's own genuine
	 * staged source-vector content, captured ONCE immediately after
	 * wvec becomes valid and BEFORE any later hibernate_md_selfcopy_walk()
	 * sweep in this same function can overwrite that shared destination
	 * index's entry to the LIVE page (self-referential "preserve as-is"
	 * protection; confirmed this round, via direct diagnostic, that at
	 * least one later sweep's own VA range resolves to the SAME physical
	 * page as __stack_chk_guard, silently clobbering wvec[idx] before
	 * any later read reaches it -- hibernate_md_staged_read()'s prior
	 * use at the original, later insertion point was reading an
	 * already-overwritten entry, not a primitive defect).  0 is a valid
	 * sentinel-adjacent possibility in principle but vanishingly
	 * unlikely for a 64-bit arc4rand() value; hib_guard_captured
	 * distinguishes "never captured" from "captured, value happens to be
	 * zero" unambiguously.
	 *
	 * Promoted to file-scope globals (hib_guard_image_value_g /
	 * hib_guard_captured_g, declared below, outside this function) so
	 * hibernate_resume_attempt() (sys/kern/kern_hibernate.c) can install
	 * the value AFTER this function has already returned -- installing
	 * it HERE, inside this function's own body, was tried and reverted:
	 * it broke this function's OWN currently-executing frame (its
	 * prologue stored the OLD guard; changing the global before this
	 * function's own epilogue runs made ITS OWN return panic,
	 * reproduced 3/3).  The local copies below remain for this
	 * function's own diagnostic print.
	 */
	uint64_t hib_guard_image_value = 0;
	bool hib_guard_captured = false;

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
	error = hibernate_staging_source_pages(ha, &storage_pa, &vector_pages,
	    &vector_va, &xsave_pa);
	if (error != 0)
		return (error);
	p = ha->ha_image.hi_destination_pages;
	/*
	 * window_va is a fixed, VA-only private-domain window base
	 * (HIBERNATE_MD_VECTOR_SLOT * NBPML4, no PA offset -- unlike
	 * HIBERNATE_MD_SAVED_SLOT's use, this window never aliases a real
	 * identity PA, it is purely a destination for the per-page
	 * hibernate_md_private_window_map() calls below), so it can be
	 * computed here with no allocation or page-table side effects.
	 */
	window_va = (vm_paddr_t)HIBERNATE_MD_VECTOR_SLOT * (vm_paddr_t)NBPML4;

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
	if ((uint64_t)arena_end > phys_limit || (uint64_t)xsave_pa >= phys_limit) {
		return (EINVAL);
	}
	/*
	 * storage_pa[] is a scattered per-page array, not a
	 * contiguous range -- prove each backing frame individually
	 * representable, rather than checking a single base+extent that no
	 * longer corresponds to how the pages are laid out.
	 */
	for (di = 0; di < (uint64_t)vector_pages; di++) {
		if ((uint64_t)storage_pa[di] >= phys_limit)
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
	/*
	 * each scattered backing frame (storage_pa[j]), not a
	 * single contiguous range, must be disjoint from the arena.
	 */
	for (di = 0; di < (uint64_t)vector_pages; di++) {
		if (storage_pa[di] >= ha->ha_arena_start &&
		    storage_pa[di] < arena_end)
			return (EINVAL);
	}
	if (xsave_pa >= ha->ha_arena_start && xsave_pa < arena_end)
		return (EINVAL);

	/* 5. Build the private CR3 tree. */
	error = hibernate_md_private_tree_build(ha, &layout, runs, run_count,
	    vector_va, p, window_va, storage_pa, (uint64_t)vector_pages,
	    xsave_pa, &private_cr3, &private_leaf_pages);
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
	    vector_va, p, window_va, storage_pa, (uint64_t)vector_pages,
	    xsave_pa, private_cr3);
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

		/*
		 * capture __stack_chk_guard's
		 * own genuine wvec[] entry HERE, before the very first
		 * hibernate_md_selfcopy_walk() call in this function has any
		 * chance to overwrite a shared destination index.  See the
		 * function-scope hib_guard_image_value comment above for
		 * the full root-cause account of why the ORIGINAL, later
		 * read point returned a tautological (already-live)  value.
		 */
		{
			extern long __stack_chk_guard[8];
			vm_paddr_t hib_guard_live_pa;
			uint64_t hib_guard_dst_idx;

			if (hib_md_safe_resolve(kernel_pmap->pm_cr3,
			    trunc_page((vm_offset_t)__stack_chk_guard),
			    &hib_guard_live_pa) &&
			    hibernate_md_dst_page_index(ha,
			    trunc_page(hib_guard_live_pa),
			    &hib_guard_dst_idx) == 0 &&
			    hib_guard_dst_idx < p) {
				size_t hib_guard_pgoff;

				hib_guard_pgoff = (size_t)
				    ((vm_offset_t)__stack_chk_guard &
				    PAGE_MASK);
				memcpy(&hib_guard_image_value,
				    (const uint8_t *)PHYS_TO_DMAP(
				    wvec[hib_guard_dst_idx]) +
				    hib_guard_pgoff,
				    sizeof(hib_guard_image_value));
				hib_guard_captured = true;
			}
		}

		k24t00_early_kstack_capture(ha, wvec, p);

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
		if (error == 0) {
			/*
			 * The BSP's own live GDT (pc_gdt) is read by
			 * hibernate_restore_kernel() via the saved PCB's
			 * pcb_gdt (lgdt(PCB_GDT(%r12))) immediately after
			 * landing in the saved domain.  Captured and
			 * confirmed this session: the GDT's own
			 * governing page-table (PT) entry is present and
			 * valid at hibernate_machdep_enter() but reads
			 * zero (not present) by the time
			 * hibernate_restore_kernel() executes "lgdt", with
			 * the very next instruction ("mov %eax,%ds",
			 * support.S's lgdt()) resetting the machine --
			 * the GDT page-table path, not its data, falls
			 * inside the K-10 destination set and collapses
			 * exactly like the saved_pcb_va bug this same loop
			 * already fixes.  Unlike saved_pcb_va, the GDT's
			 * *data* must come from the resume kernel's own,
			 * already-correct boot (not the saved image): the
			 * saved PCB's pcb_gdt base/limit simply name this
			 * CPU's one fixed GDT, which the ordinary boot
			 * already built correctly, so this leaf's *data*
			 * must be the resume kernel's own current bytes,
			 * not the saved image's -- copy_leaf is therefore
			 * true here, exactly mirroring the KPML4phys case
			 * below (also "must keep the resume boot's own
			 * value", also copy_leaf=true), not saved_pcb_va's
			 * case above (whose content must come FROM the
			 * saved image, hence copy_leaf=false there).  A
			 * prior version of this call passed copy_leaf=false,
			 * which contradicted this exact comment's own stated
			 * intent and, because pc_gdt shares its one-page
			 * struct pcpu with pc_curthread/pc_idlethread, let
			 * the K-10 destructive copy overwrite the BSP's
			 * entire live pcpu leaf (not just the GDT) with the
			 * saved image's snapshot of it -- confirmed by a
			 * live GDB capture at vm_phys_hibernate_release()'s
			 * entry showing curthread resolved to an unrelated,
			 * stale thread (a WITNESS "spinlock or critical
			 * section held" panic followed, since that stale
			 * thread's td_critnest was never the one
			 * acpi_s4_resume_discard_snapshot() had just
			 * zeroed).  Making this leaf self-copied (a no-op
			 * under the destructive copy) keeps the whole BSP
			 * pcpu page -- GDT included -- as this boot's own,
			 * already-correct, already-running state.
			 */
			struct pcpu *bsp_pc, *ap_pc;
			u_int ap_cpu;

			bsp_pc = pcpu_find(0);
			if (bsp_pc == NULL)
				return (EINVAL);
			error = hibernate_md_selfcopy_walk(ha, wvec, p,
			    kernel_pmap->pm_cr3, (vm_offset_t)bsp_pc->pc_gdt,
			    true, &selfcopied);
			/*
			 * hibernate_resume_ap_entry() loads the AP's own
			 * pc_gdt via lgdt() on the release path.  Each CPU's
			 * pc_gdt lives in that CPU's own per-CPU page, so the
			 * BSP's walk above does not cover it: protect its
			 * leaf under the same corrected rule (copy_leaf=true;
			 * see the comment above) -- the AP's own pcpu page,
			 * including its pc_curthread/pc_idlethread, must
			 * likewise survive the destructive copy as this
			 * boot's own state, not the saved image's.  The
			 * mp_ncpus == 2 refusal above leaves exactly one
			 * such CPU.
			 */
			if (error == 0) {
				for (ap_cpu = 0; ap_cpu < (u_int)mp_ncpus;
				    ap_cpu++) {
					if (ap_cpu != PCPU_GET(cpuid))
						break;
				}
				if (ap_cpu >= (u_int)mp_ncpus)
					return (EINVAL);
				ap_pc = pcpu_find(ap_cpu);
				if (ap_pc == NULL)
					return (EINVAL);
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3,
				    (vm_offset_t)ap_pc->pc_gdt, true,
				    &selfcopied);
			}
		}
		if (error == 0) {
			/*
			 * resumectx() (sys/amd64/amd64/cpu_switch.S)
			 * unconditionally reloads %cr3 from the global
			 * KPML4phys (not from any value this file hands it)
			 * as its very first act.  Captured and confirmed
			 * this session: KPML4phys's own data word changes
			 * from the correct, live resume-boot value
			 * (matching kernel_pmap->pm_cr3 exactly) at
			 * hibernate_machdep_enter() to a foreign value at
			 * resumectx() entry, after the K-10 copy has run --
			 * i.e. unlike the GDT fix above, here it is the
			 * LEAF (KPML4phys's own stored physical address),
			 * not merely its page-table path, that the
			 * destructive copy overwrites with the saved
			 * image's own (differently-placed) KPML4 address.
			 * That bogus %cr3 reload is consistent with the
			 * guest resetting moments into resumectx() with no
			 * trap.  KPML4phys must keep the resume boot's own
			 * value (this boot's one and only correct kernel
			 * PML4 physical address), so copy_leaf is true here,
			 * the opposite of saved_pcb_va/pc_gdt above.
			 * KPML5phys is not similarly protected:
			 * hibernate_amd64_cpu_validate() already refuses any
			 * la57 != 0 host, so resumectx()'s KPML5phys load is
			 * never the value actually moved into %cr3 on any
			 * restore this code can reach.
			 */
			error = hibernate_md_selfcopy_walk(ha, wvec, p,
			    kernel_pmap->pm_cr3, (vm_offset_t)&KPML4phys, true,
			    &selfcopied);
		}
		if (error == 0) {
			/*
			 * resumectx() (sys/amd64/amd64/cpu_switch.S)'s final
			 * act is "movq PCB_RSP(%rdi),%rsp; ... ; movq
			 * PCB_RIP(%rdi),%rax; movq %rax,(%rsp)" -- it switches
			 * onto the SUSPENDED thread's own saved kernel stack
			 * (pcb_rsp) and writes the saved return address onto
			 * it, immediately before the final jmp/ret back into
			 * .Lhibernate_resumed.  Its content must come from the
			 * saved image, so copy_leaf is false here, exactly like
			 * saved_pcb_va/pc_gdt above.
			 *
			 * reading susppcbs[0]->sp_pcb.pcb_rsp directly
			 * on THIS (resume) boot reads this boot's own
			 * never-written PCB allocation (acpi_wakeup.c's
			 * acpi_install_wakeup_handler(), M_WAITOK, not M_ZERO):
			 * savectx() only ever runs on the SAVE boot
			 * (dumpsys_hibernate_savectx()) or an ordinary ACPI S3
			 * suspend, never here. Live capture confirmed this read
			 * is boot-dependent garbage (a non-canonical address)
			 * the self-copy walk silently no-ops on, protecting
			 * nothing, while the real suspended stack's own
			 * page-table path is left unprotected and can collide
			 * with the K-10 destination set on a boot-dependent
			 * basis -- the double fault this fix chases.
			 *
			 * The real value must come from the SAVED image.
			 * susppcbs[0]->sp_pcb's own physical page is itself one
			 * of the image's PT_LOAD destination pages (the same
			 * page saved_pcb_va's copy_leaf=false walk above already
			 * relies on being restored from the image), so its
			 * SAVED content is already staged in the K-9 source
			 * vector (wvec[]), addressable via
			 * hibernate_md_dst_page_index() + PHYS_TO_DMAP() before
			 * the K-10 destructive copy ever runs.  Read pcb_rsp from
			 * there instead.
			 *
			 * Further, round 63/64's own direct per-level capture
			 * proved the live kernel_pmap genuinely has no
			 * page-table entry at all for this class of VA at this
			 * point: there is nothing for an ordinary self-copy
			 * walk to protect. The mapping is instead derived from
			 * the SAVED kernel's own page tables (via
			 * hibernate_md_staged_leaf_for_live_slot(), which walks
			 * the LIVE tree down to the PT-page level -- proven
			 * present -- and reads the STAGED content for that
			 * page's own terminal slot) and installed into the live
			 * tree before resumectx() runs (via
			 * hibernate_md_kva_install()), not a self-copy walk and
			 * not vtoslab().
			 *
			 * Installing only the single page containing pcb_rsp is
			 * insufficient: a correlated capture proved the double
			 * fault's own faulting rsp is bit-identical to this
			 * cycle's own kstack_va -- a page-aligned boundary --
			 * meaning execution pushes the stack pointer down, past
			 * the first page, into the immediately lower,
			 * never-installed page of the same KSTACK_PAGES-page
			 * kernel stack, the instant any callee inside
			 * resumectx()'s return path needs more than one page of
			 * stack. Install every remaining lower page of the
			 * stack's KSTACK_PAGES range (kernel stacks grow down;
			 * KSTACK_GUARD_PAGES below kstack_va is deliberately
			 * left unmapped, matching the saved kernel's own
			 * intent), best-effort: reaching a VA the live
			 * tree/staged image cannot resolve is the expected,
			 * benign end of the stack's mapped range and stops the
			 * extension quietly, without invalidating the base
			 * page's already-proven-good install. Only a genuine
			 * install error on a page that DID resolve is treated
			 * as fatal.
			 */
			register_t kstack_va;
			register_t staged_pcb_rsp;
			vm_offset_t susppcb_pcb_va;
			vm_offset_t kstack_base, kstack_end, kstack_slot;
			vm_size_t kstack_stride;

			if (susppcbs == NULL || susppcbs[0] == NULL)
				return (EINVAL);
			/*
			 * K24-T00 (round 3): resolve &susppcbs[0]->sp_pcb
			 * through the SAVED kernel's own page tables
			 * (hibernate_md_staged_read(), rooted at
			 * ha->ha_image.hi_pcb.hp_cr3 -- see that function's
			 * own extensive comment above), not the resume
			 * boot's live vtophys()/kernel_pmap.
			 *
			 * The two previously-tried sources were both
			 * disproven by direct evidence: susppcbs[0]->sp_pcb
			 * itself is uninitialized on the save side (the BSP
			 * removes itself from suspend_cpus()'s set, so
			 * nothing ever wrote it -- fixed separately, this
			 * same file/round, by populating it from curthread->
			 * td_pcb at the acpi.c save-side call site); and
			 * ha->ha_image.hi_pcb.hp_rsp is a different field
			 * entirely (the savectx() scratch-stack pointer, not
			 * any thread's kstack).  Even with the save-side
			 * population fix applied and proven correct (direct
			 * capture: pre_copy_rsp=0 -> post_copy pcb_rsp
			 * matching curthread->td_pcb->pcb_rsp exactly, a
			 * genuine kernel-half address), site 42 still fired
			 * in 5/12 verification runs: vtophys(&susppcbs[0]->
			 * sp_pcb) on THIS (resume) boot's own live tables
			 * returns THIS boot's cold-boot allocation address
			 * for that VA, which only coincidentally matches the
			 * SAVE boot's own (already-running, non-deterministic
			 * heap state) allocation address for the identical
			 * VA -- confirmed directly: the same VA resolved to
			 * PA 0x168fd80 on the save side in one capture and
			 * the resume side's own guess landed on the
			 * DIFFERENT PA 0x1690d80 in the very same run.
			 *
			 * hibernate_md_staged_read() eliminates this guess
			 * entirely: it walks hi_pcb.hp_cr3 -- the SAVED
			 * kernel's own captured CR3 -- so the VA ->
			 * PA resolution is authoritative by construction,
			 * identical in kind to every other dynamically-
			 * allocated object this file already resolves this
			 * way (struct proc, struct thread, etc., per round
			 * 11's fix, same function).
			 *
			 * K24-T00 (round 4/5, REVERTED): rounds 4-5 tried
			 * routing this read through saved_pcb_va (the PA
			 * hibernate_md_patch_saved_domain() computes for the
			 * identity map) instead of this hi_pcb.hp_cr3 walk,
			 * reasoning that resumectx() already dereferences
			 * that exact address without faulting on most runs.
			 * Live N=12 evidence disproved this: saved_pcb_va's
			 * own PA comes from that SAME function's live
			 * vtophys(&susppcbs[0]->sp_pcb) call -- the identical
			 * per-boot-random-allocation problem this round-3
			 * comment already documents -- so it is not an
			 * independent, reliable source; it only happens to
			 * be identity-MAPPED (hibernate_md_identity_ensure()
			 * guarantees the mapping exists and is present), which
			 * is why resumectx() never faults dereferencing it,
			 * even when the CONTENT at that address is wrong.
			 * Routing through it made site 42 fire in 8/12 runs
			 * (worse than this round's own 4/12 baseline), so it
			 * was reverted back to this hi_pcb.hp_cr3 walk, the
			 * last version with a strictly better (not worse)
			 * fire rate.
			 *
			 * K24-T00 (round 6): the bug round 3 never actually
			 * fixed. hibernate_md_staged_read() above correctly
			 * walks the SAVED kernel's page tables (hi_pcb.hp_cr3)
			 * for the VA-to-PA resolution step -- but the VA it
			 * was given, "&susppcbs[0]->sp_pcb", is computed by
			 * first dereferencing susppcbs (a plain global
			 * pointer, sys/x86/x86/mp_x86.c) on THIS (resume)
			 * boot, in C, before any staged walk ever runs.
			 * susppcbs is allocated fresh by
			 * acpi_alloc_wakeup_handler() (sys/amd64/acpica/
			 * acpi_wakeup.c) on EVERY boot via plain malloc(), so
			 * its VALUE is exactly as boot-specific as the heap
			 * allocation round 3 already proved unreliable for
			 * susppcbs[0] itself -- staging the VA->PA walk for
			 * *(susppcbs[0]) never helped, because the pointer
			 * being dereferenced to REACH that VA was always the
			 * live, resume-boot pointer, not the saved one.
			 * susppcbs is NOT in any self-copy-protection set:
			 * searching every hibernate_md_selfcopy_walk() call
			 * site in this file (31 call sites checked) finds
			 * none passing &susppcbs or any VA resolving to its
			 * containing .bss page; only &susppcbs[0]->sp_pcb
			 * (the pointee) was ever protected or referenced.
			 * The two-step fix: first stage-read the GLOBAL's own
			 * VA (&susppcbs, a compile-time-constant kernel symbol
			 * address, identical on both boots) through the saved
			 * tables to recover the SAVE boot's susppcbs value;
			 * then stage-read sp_pcb.pcb_rsp from THAT (save-boot)
			 * pointer's [0] slot, also through the saved tables.
			 * Both steps are staged reads rooted in image content;
			 * no live pointer is dereferenced in C at any point.
			 */
			{
				vm_offset_t susppcbs_global_va;
				uint64_t saved_susppcbs_ptr;
				uint64_t saved_susppcb0_ptr;

				susppcbs_global_va = (vm_offset_t)&susppcbs;
				error = hibernate_md_staged_read(ha, wvec, p,
				    susppcbs_global_va, &saved_susppcbs_ptr,
				    sizeof(saved_susppcbs_ptr));
				if (error != 0)
					return (error);
				/*
				 * K24-T00 (round 6, guard fix): susppcbs is
				 * malloc(M_DEVBUF)'d (sys/amd64/acpica/
				 * acpi_wakeup.c), so its VA lives in the
				 * general kernel map, NOT the kstack arena
				 * VM_MIN_KERNEL_ADDRESS..VM_MAX_KERNEL_ADDRESS
				 * range this same function uses for kstack_va
				 * below -- that range rejected the real,
				 * independently-confirmed value
				 * (0xfffff8000109a180, identical across every
				 * boot observed this session) as invalid.
				 * Only rule out a NULL/corrupt staged read
				 * here; the subsequent staged read of
				 * sp_pcb.pcb_rsp through this pointer (site
				 * 39 below) is the real content check, and a
				 * canonical-range guard on the FINAL kstack_va
				 * result still applies at site 42.
				 */
				if (saved_susppcbs_ptr == 0)
					return (EINVAL);
				/*
				 * K24-T00 (round 6, 2nd bug): saved_susppcbs_
				 * ptr is the ARRAY base (struct susppcb **),
				 * not susppcbs[0] (struct susppcb *) -- the
				 * previous version of this block skipped
				 * dereferencing slot 0 entirely and fed the
				 * array base straight into offsetof(sp_pcb),
				 * which is why site 42 still fired with
				 * susppcb_pcb_va printing the exact array-
				 * base address (0xfffff8000109a180) instead
				 * of a struct pcb address. A THIRD staged
				 * read -- of the 8-byte pointer AT
				 * saved_susppcbs_ptr (i.e. susppcbs[0] on the
				 * SAVE boot) -- is required before this
				 * offset can be added, mirroring exactly how
				 * live code reads susppcbs[0] before
				 * susppcbs[0]->sp_pcb.
				 */
				error = hibernate_md_staged_read(ha, wvec, p,
				    (vm_offset_t)saved_susppcbs_ptr,
				    &saved_susppcb0_ptr,
				    sizeof(saved_susppcb0_ptr));
				if (error != 0)
					return (error);
				if (saved_susppcb0_ptr == 0)
					return (EINVAL);
				susppcb_pcb_va = (vm_offset_t)saved_susppcb0_ptr +
				    offsetof(struct susppcb, sp_pcb);
			}
			error = hibernate_md_staged_read(ha, wvec, p,
			    susppcb_pcb_va + offsetof(struct pcb, pcb_rsp),
			    &staged_pcb_rsp, sizeof(staged_pcb_rsp));
			if (error != 0)
				/*
				 * Fail closed with a DISTINCT message:
				 * per this round's instruction, an
				 * unresolved saved-table walk here
				 * means slot 0's own struct pcb page
				 * was never captured in the image at
				 * all -- a different and equally
				 * important finding from a bad VALUE,
				 * pointing at the writer/enumeration
				 * side rather than this reader.
				 */
				return (error);
			kstack_va = staged_pcb_rsp;
			kstack_va &= ~(register_t)PAGE_MASK;

			/*
			 * A kstack VA must lie in the kernel half of the
			 * address space; fail closed (EINVAL; a pre-RESTORE
			 * refusal, so the stage machine cold-boots) rather
			 * than guess.
			 */
			if ((vm_offset_t)kstack_va < VM_MIN_KERNEL_ADDRESS ||
			    (vm_offset_t)kstack_va >= VM_MAX_KERNEL_ADDRESS)
				return (EINVAL);

			/*
			 * Derive the exact bounds from the standard kstack
			 * arena's allocator geometry.
			 * vm_thread_alloc_kstack_kva() aligns each standard
			 * allocation to KSTACK_PAGES + KSTACK_GUARD_PAGES pages
			 * relative to VM_MIN_KERNEL_ADDRESS.
			 * vm_thread_stack_create() then leaves the first page
			 * unmapped as the guard and publishes td_kstack at the
			 * following page.  pcb_rsp is an interior stack
			 * address, so its containing aligned slot uniquely
			 * determines:
			 *
			 *   slot  = guard page
			 *   base  = slot + KSTACK_GUARD_PAGES
			 *   end   = base + KSTACK_PAGES
			 *
			 * The prior staged-process enumeration was not
			 * authoritative here: HIB_STAGED_MAX_THREADS caps it at
			 * 256 entries, and this probe consumed the image before
			 * emitting I/U because the hibernating thread was
			 * omitted.  Allocation geometry has no process-list or
			 * enumeration dependency and matches vm_glue.c's
			 * enforced KASSERT.
			 */
			kstack_stride = ptoa(KSTACK_PAGES + KSTACK_GUARD_PAGES);
			kstack_slot = VM_MIN_KERNEL_ADDRESS +
			    (((vm_offset_t)staged_pcb_rsp -
				 VM_MIN_KERNEL_ADDRESS) /
				kstack_stride) *
				kstack_stride;
			kstack_base = kstack_slot + ptoa(KSTACK_GUARD_PAGES);
			kstack_end = kstack_base + ptoa(KSTACK_PAGES);
			if (kstack_base < kstack_slot ||
			    kstack_end < kstack_base ||
			    (vm_offset_t)staged_pcb_rsp < kstack_base ||
			    (vm_offset_t)staged_pcb_rsp >= kstack_end)
				return (EINVAL);

			k24t00_kstack_va = kstack_va;
			/*
			 * do NOT source hib_staged_
			 * fpu_save from staged_pcb->pcb_save. staged_pcb here
			 * is susppcbs[0]->sp_pcb (see hibernate_md_patch_
			 * saved_domain() above) -- a per-CPU scratch struct
			 * pcb populated SOLELY by savectx() (sys/amd64/amd64/
			 * cpu_switch.S), which writes exactly: pcb_rip, pcb_
			 * rbx/rsp/rbp/r12-r15, pcb_cr0-cr4, pcb_dr0-dr7, pcb_
			 * fsbase/gsbase/kgsbase, the MSR block (EFER/STAR/
			 * LSTAR/CSTAR/SFMASK/FRED_*), and pcb_idt/gdt/ldt/tr.
			 * pcb_save is never among them (confirmed by reading
			 * savectx()'s own complete body) -- it is thread-
			 * identity bookkeeping (struct thread's own td_pcb-
			 * relative field, populated at thread creation by
			 * cpu_fork()/cpu_thread_alloc() -> get_pcb_user_save_
			 * pcb(), sys/amd64/amd64/vm_machdep.c), meaningless
			 * for a standalone struct pcb that was never part of
			 * a struct thread. susppcbs[i]->sp_pcb is malloc()'d
			 * with M_WAITOK only, not M_ZERO (sys/amd64/acpica/
			 * acpi_wakeup.c's acpi_alloc_wakeup_handler()), so its
			 * own pcb_save field retains whatever the backing heap
			 * slab last held -- confirmed directly this round: the
			 * observed poison value 0xdeadc0dedeadc0de is UMA's own
			 * documented free-memory junk-fill constant (sys/vm/
			 * uma_dbg.c's own "uma_junk"), meaning this specific
			 * slab had previously been freed and junked before this
			 * allocation reused it. This is not a wrong offset (the
			 * field read is byte-correct for struct pcb) and not a
			 * legitimate "thread never touched the FPU" case (that
			 * case is pcb_flags & PCB_FPUINITDONE == 0 on a GENUINE
			 * thread pcb, which this scratch struct can never carry
			 * meaningfully either way) -- it is reading a field from
			 * a struct that was never a valid carrier of that
			 * field's semantics at all.
			 *
			 * The correct, narrow fix is to leave k24t00_staged_
			 * fpu_save at its NULL initializer (declared above) so
			 * the FPU page-table-path protection block below is
			 * skipped entirely -- it is a pure, additive protection
			 * for a live mapping, not a content requirement (unlike
			 * saved_pcb_va's copy_leaf=false case); skipping it
			 * changes nothing about WHICH bytes resumectx() or a
			 * later context switch read, only whether this file
			 * proactively pre-maps one VA. The safe fallback already
			 * exists and needs no new code: restore_fpu_curthread()
			 * (sys/amd64/amd64/fpu.c) dereferences the REAL resumed
			 * thread's own td->td_pcb->pcb_save (never susppcbs[0]'s),
			 * and its own cold-init branch -- "if ((pcb->pcb_flags &
			 * PCB_FPUINITDONE) == 0) { bcopy(fpu_initialstate,
			 * pcb->pcb_save, ...); fpurestore(pcb->pcb_save); ...
			 * set_pcb_flags(..., PCB_FPUINITDONE | ...); }" -- runs
			 * unconditionally whenever that flag is clear, which is
			 * exactly the state every thread's own copied/restored
			 * pcb_flags field already carries unless the saved image
			 * itself set PCB_FPUINITDONE (an ordinary image-content
			 * question, already covered by the K-10 destination-set
			 * copy with no dependency on this block). No separate
			 * guarantee is needed: this is the SAME fallback every
			 * ordinary first-fpu-use thread already takes on an
			 * ordinary cold boot, not a new or weakened path.
			 *
			 * This does NOT relax the fpu_va canonical-range guard
			 * below -- that guard stays exactly as the prior round
			 * wrote it, unreachable now because its own precondition
			 * (k24t00_staged_fpu_save != NULL) is never met from this
			 * invalid source.  If a future round finds a genuine
			 * staged source for the ACTUAL resumed thread's own
			 * pcb_save (e.g. by resolving saved_td via the allproc
			 * walk hibernate_md_enumerate_procs() already proves
			 * works, then reading ITS td_pcb->pcb_save from the K-9
			 * staged vector), the guard is what will correctly catch
			 * a genuinely bad value from that real source.
			 */

			{
				struct hibernate_md_walk saved_walk;
				bool walk_ok;
				int install_err;
				vm_offset_t kstack_page_va;
				u_int kstack_npages;

				walk_ok = hibernate_md_staged_leaf_for_live_slot(ha,
				    wvec, p, (vm_offset_t)kstack_va, &saved_walk);
				install_err = 0;
				bzero(stack_resolved, sizeof(stack_resolved));

				/*
				 * Resolve every stack leaf before installing
				 * any of them. hibernate_md_kva_install()
				 * mutates the live terminal chain used by
				 * hibernate_md_staged_leaf_for_live_slot() to
				 * locate staged PT pages, so resolving and
				 * installing one page at a time makes later
				 * pages in the same allocation appear absent.
				 * Snapshotting all leaves first keeps discovery
				 * in the original live/staged topology and
				 * installation in a separate phase.
				 */
				for (pg = 0; pg < KSTACK_PAGES; pg++) {
					stack_va = kstack_base +
					    (vm_offset_t)pg * PAGE_SIZE;
					if (!hibernate_md_staged_leaf_for_live_slot(
						ha, wvec, p, stack_va,
						&stack_walks[pg]) ||
					    (stack_walks[pg].hmw_flags &
						(X86_PG_V | X86_PG_RW)) !=
						(X86_PG_V | X86_PG_RW)) {
						unresolved++;
						continue;
					}
					stack_resolved[pg] = true;
				}

				for (pg = 0; pg < KSTACK_PAGES; pg++) {
					if (!stack_resolved[pg])
						continue;
					stack_va = kstack_base +
					    (vm_offset_t)pg * PAGE_SIZE;
					/*
					 * K24-T00 stack disposition fix:
					 * force_overwrite=true -- this VA is
					 * the RESUMING thread's own kstack,
					 * necessarily already live-mapped by
					 * the ordinary resume-boot thread0
					 * allocation; the image's leaf must
					 * replace it, not be refused against
					 * it (see hibernate_md_kva_install()'s
					 * own comment).
					 */
					install_err = hibernate_md_kva_install(
					    ha, stack_va,
					    stack_walks[pg].hmw_pa,
					    stack_walks[pg].hmw_flags, true);
					if (install_err == 0)
						install_err =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							stack_va, false,
							&selfcopied);
					if (install_err != 0)
						break;
					installed++;
					if (stack_va == (vm_offset_t)kstack_va) {
						rsp_page_ready = true;
						/*
						 * K24-T00: probe slot 0, the
						 * BSP's own control. Record
						 * the exact VA/expected PA
						 * this install just wrote,
						 * for the post-copy decode.
						 */
						k24t00_probe_va_g[0] =
						    stack_va;
						k24t00_probe_expected_pa_g[0] =
						    stack_walks[pg].hmw_pa;
						k24t00_probe_set_g[0] = true;
					}
				}

				/*
				 * The page containing pcb_rsp is mandatory.
				 * Other absent pages are permitted as untouched
				 * sparse stack pages.
				 */
				if (install_err == 0 && !rsp_page_ready)
					install_err = EINVAL;

				hibernate_k24t04_raw_marker('I');
				hibernate_k24t04_raw_uint(installed);
				hibernate_k24t04_raw_marker('U');
				hibernate_k24t04_raw_uint(unresolved);
				if (install_err != 0) {
					hibernate_k24t04_raw_marker('J');
					hibernate_k24t04_raw_uint(install_err);
					hibernate_k24t04_raw_marker('Y');
					hibernate_k24t04_raw_uint(
					    hib_kva_install_reason);
					hibernate_k24t04_raw_marker('V');
					hibernate_k24t04_raw_uint(
					    hib_kva_install_va);
					hibernate_k24t04_raw_marker('L');
					hibernate_k24t04_raw_uint(
					    hib_kva_install_leaf_pa);
					hibernate_k24t04_raw_marker('P');
					hibernate_k24t04_raw_uint(
					    hib_kva_install_entry);
					hibernate_k24t04_raw_marker('F');
					hibernate_k24t04_raw_uint(
					    hib_kva_install_leaf_flags);
					hibernate_k24t04_raw_marker('A');
					hibernate_k24t04_raw_uint(
					    hib_kva_install_table_pa);
				}
				error = install_err;
			}
		}
		if (error == 0) {
			struct hib_staged_thread *threads;
			u_int i, nthreads, selfcopied;

			threads = malloc(sizeof(*threads) *
				HIB_STAGED_MAX_THREADS,
			    M_TEMP, M_NOWAIT);
			if (threads == NULL)
				return (ENOMEM);

			error = hibernate_md_enumerate_staged_threads(ha, wvec,
			    p, threads, HIB_STAGED_MAX_THREADS, &nthreads);
			if (error != 0) {
				free(threads, M_TEMP);
				return (error);
			}

			/*
			 * K24-T31: record this exact same staged-thread set
			 * into the protected, persistent array every post-
			 * copy allproc-walking pass now iterates instead of
			 * the kernel's own (documented-corrupt-at-that-
			 * point) allproc/p_list. See k24t31_recorded_
			 * threads[]'s own declaration comment for the full
			 * account. One entry per thread (nthreads is
			 * already <= HIB_STAGED_MAX_THREADS, the array this
			 * global is sized to match).
			 */
			for (i = 0; i < nthreads &&
			    k24t31_recorded_n < HIB_STAGED_MAX_THREADS;
			    i++) {
				struct k24t31_recorded_thread *rt;

				rt = &k24t31_recorded_threads[
				    k24t31_recorded_n];
				rt->td = (struct thread *)threads[i].td_va;
				rt->pid = threads[i].pid;
				rt->tid = threads[i].tid;
				memcpy(rt->comm, threads[i].comm,
				    sizeof(rt->comm) - 1);
				rt->comm[sizeof(rt->comm) - 1] = '\0';
				rt->fpu_save_va = threads[i].fpu_save_va;
				k24t31_recorded_n++;
			}

			/*
			 * K24-T00 round 24: fail closed, pre-copy, if this
			 * boot's own real requirement ever exceeds the
			 * stash's capacity -- refusing here is cheap (no
			 * destructive copy has run yet); discovering a
			 * silent truncation post-copy, as a kstack_verify
			 * miss or a done_load_dr fault, is not. One stash
			 * entry per kstack PAGE (matching the populate
			 * loop's own granularity, below), summed across
			 * every enumerated thread.
			 */
			{
				u_int cap_i;
				uint64_t required_pages;

				required_pages = 0;
				for (cap_i = 0; cap_i < nthreads; cap_i++) {
					required_pages +=
					    threads[cap_i].kstack_pages;
				}
				printf("hibernate: k24t00: kstack stash "
				    "capacity: capacity=%u nthreads=%u "
				    "required_pages=%ju\n",
				    (u_int)K24T00_KSTACK_STASH_MAX, nthreads,
				    (uintmax_t)required_pages);
				if (required_pages >
				    (uint64_t)K24T00_KSTACK_STASH_MAX) {
					printf("hibernate: k24t00: kstack "
					    "stash capacity exceeded: "
					    "required_pages=%ju > "
					    "capacity=%u -- refusing resume\n",
					    (uintmax_t)required_pages,
					    (u_int)K24T00_KSTACK_STASH_MAX);
					free(threads, M_TEMP);
					return (ENOSPC);
				}
			}

			/*
			 * K24-T00 thread provenance: build the staged-PCB-
			 * page set from this SAME enumeration pass, deduped,
			 * bounded by HIB_STAGED_PCB_PAGE_MAX. Printed as one
			 * auditable summary line (count + first few page
			 * numbers) -- safe here, pre-copy, same window as
			 * every other printf in this function.
			 */
			{
				u_int sp_i, sp_j, sp_n, sp_dropped;
				u_long sp_key;
				bool sp_dup;

				sp_n = 0;
				sp_dropped = 0;
				for (sp_i = 0; sp_i < nthreads; sp_i++) {
					if (threads[sp_i].pcb_va == 0)
						continue;
					sp_key = (u_long)(threads[sp_i].pcb_va
					    >> PAGE_SHIFT);
					sp_dup = false;
					for (sp_j = 0; sp_j < sp_n; sp_j++) {
						if (k24t00_staged_pcb_page_g[
							sp_j] == sp_key) {
							sp_dup = true;
							break;
						}
					}
					if (sp_dup)
						continue;
					if (sp_n >= HIB_STAGED_PCB_PAGE_MAX) {
						sp_dropped++;
						continue;
					}
					k24t00_staged_pcb_page_g[sp_n++] =
					    sp_key;
				}
				k24t00_staged_pcb_page_n_g = sp_n;

				printf("hibernate: k24t00: staged pcb pages: "
				    "count=%u first=%#lx,%#lx,%#lx,%#lx\n",
				    sp_n,
				    sp_n > 0 ? k24t00_staged_pcb_page_g[0] : 0,
				    sp_n > 1 ? k24t00_staged_pcb_page_g[1] : 0,
				    sp_n > 2 ? k24t00_staged_pcb_page_g[2] : 0,
				    sp_n > 3 ? k24t00_staged_pcb_page_g[3] : 0);

				/*
				 * K24-T00 round 3: independent pid/tid
				 * staged sets, built from this SAME
				 * enumeration pass (threads[0..nthreads)),
				 * but via plain, direct assignment (no
				 * page-shift, no dedup-by-page-number) --
				 * a structurally simpler, independently-
				 * computed answer to "is this thread part
				 * of the staged set" than the PCB-page
				 * path above. nthreads is already bounded
				 * by HIB_STAGED_MAX_THREADS (the array
				 * size), so no separate capacity check is
				 * needed here (unlike the PCB-page set,
				 * which dedupes and can therefore legitimately
				 * hold fewer entries than nthreads).
				 */
				k24t00_staged_pid_n_g = nthreads;
				k24t00_staged_tid_n_g = nthreads;
				k24t00_staged_tid_max_g = 0;
				for (sp_i = 0; sp_i < nthreads; sp_i++) {
					k24t00_staged_pid_g[sp_i] =
					    threads[sp_i].pid;
					k24t00_staged_tid_g[sp_i] =
					    threads[sp_i].tid;
					if (threads[sp_i].tid >
					    k24t00_staged_tid_max_g)
						k24t00_staged_tid_max_g =
						    threads[sp_i].tid;
				}
				printf("hibernate: k24t00: staged pid/tid "
				    "sets: count=%u tid_max=%u\n",
				    nthreads, (u_int)k24t00_staged_tid_max_g);
				/*
				 * K24-T00 Q1 (array truncation): capacity is
				 * HIB_STAGED_PCB_PAGE_MAX (256), bounded by
				 * nthreads (itself bounded by
				 * HIB_STAGED_MAX_THREADS, also 256) -- unique
				 * pages can never exceed nthreads, so
				 * dropped is structurally 0 unless the two
				 * bounds are ever de-synced. Printed every
				 * run as direct evidence, not an assumption.
				 */
				printf("hibernate: k24t00: staged pcb page "
				    "capacity: capacity=%u nthreads=%u "
				    "unique=%u dropped=%u\n",
				    (u_int)HIB_STAGED_PCB_PAGE_MAX, nthreads,
				    sp_n, sp_dropped);

				/*
				 * Self-copy-protect immediately after the
				 * final write above, exactly like
				 * hib_keg_topo_head_g: this array's correct
				 * content is THIS boot's own just-captured
				 * enumeration, never the saved image's stale
				 * content for these same global addresses.
				 */
				if (error == 0) {
					vm_offset_t sp_pg, sp_end;
					u_int sp_selfcopied = 0;

					sp_pg = trunc_page((vm_offset_t)
					    &k24t00_staged_pcb_page_g);
					sp_end = round_page((vm_offset_t)
					    &k24t00_staged_pcb_page_g +
					    sizeof(k24t00_staged_pcb_page_g));
					for (; sp_pg < sp_end;
					    sp_pg += PAGE_SIZE) {
						error =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							sp_pg, true,
							&sp_selfcopied);
						if (error != 0)
							break;
					}
				}
				/*
				 * K24-T00 round 3: self-copy-protect the
				 * new pid/tid staged sets the identical way
				 * -- written pre-copy here, read post-copy
				 * from the fault path (trap.c), exactly
				 * the same lifetime as k24t00_staged_pcb_
				 * page_g immediately above.
				 */
				if (error == 0) {
					vm_offset_t sp_pg, sp_end;
					u_int sp_selfcopied = 0;

					sp_pg = trunc_page((vm_offset_t)
					    &k24t00_staged_pid_g);
					sp_end = round_page((vm_offset_t)
					    &k24t00_staged_pid_g +
					    sizeof(k24t00_staged_pid_g));
					for (; sp_pg < sp_end;
					    sp_pg += PAGE_SIZE) {
						error =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							sp_pg, true,
							&sp_selfcopied);
						if (error != 0)
							break;
					}
				}
				if (error == 0) {
					vm_offset_t sp_pg, sp_end;
					u_int sp_selfcopied = 0;

					sp_pg = trunc_page((vm_offset_t)
					    &k24t00_staged_tid_g);
					sp_end = round_page((vm_offset_t)
					    &k24t00_staged_tid_g +
					    sizeof(k24t00_staged_tid_g));
					for (; sp_pg < sp_end;
					    sp_pg += PAGE_SIZE) {
						error =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							sp_pg, true,
							&sp_selfcopied);
						if (error != 0)
							break;
					}
				}
			}

			if (error != 0) {
				free(threads, M_TEMP);
				return (error);
			}

			/*
			 * K24-T00 non-image threads: compare THIS boot's own
			 * live thread set (allproc/td_hash, walked exactly
			 * like the existing live FPU walk a few hundred
			 * lines below: allproc_lock then PROC_LOCK) against
			 * the staged-PCB-page set just captured above. Any
			 * live thread whose own PCB page is NOT in that set
			 * is a thread the image's own enumeration never saw
			 * -- after the destructive copy, the image's page
			 * tables do not map that thread's kernel stack, which
			 * is exactly the not-present fault already captured
			 * (K24T00: first kernel pfault, sys/amd64/amd64/
			 * trap.c) for pid 601 "devd". Read-only, pre-copy,
			 * same safety window as every other printf in this
			 * function (not yet past hibernate_machdep_enter()).
			 *
			 * curthread is excluded unconditionally: it is this
			 * resume continuation's own thread, running this
			 * exact function, by construction never a member of
			 * the staged (saved-image) set and not a candidate
			 * for exclusion -- it must survive to complete the
			 * restore.
			 */
			{
				struct proc *ni_pp;
				struct thread *ni_td;
				struct thread *ni_self;
				u_int ni_total, ni_staged, ni_nonimage;
				u_int ni_runnable, ni_reported;
				u_long ni_pcb_page;

				ni_self = curthread;
				ni_total = 0;
				ni_staged = 0;
				ni_nonimage = 0;
				ni_runnable = 0;
				ni_reported = 0;

				sx_slock(&allproc_lock);
				FOREACH_PROC_IN_SYSTEM(ni_pp) {
					PROC_LOCK(ni_pp);
					FOREACH_THREAD_IN_PROC(ni_pp, ni_td) {
						bool ni_is_staged;
						bool ni_is_runnable;

						if (ni_td == ni_self)
							continue;
						ni_total++;
						if (ni_td->td_pcb == NULL)
							continue;
						ni_pcb_page = (u_long)
						    ni_td->td_pcb >>
						    PAGE_SHIFT;
						ni_is_staged =
						    hibernate_k24t00_pcb_is_staged(
							ni_pcb_page) != 0;
						if (ni_is_staged) {
							ni_staged++;
							continue;
						}
						ni_nonimage++;
						/*
						 * Runnable-or-will-become-
						 * runnable-without-an-image-
						 * event: TDS_RUNQ/TDS_CAN_RUN/
						 * TDS_RUNNING are runnable now;
						 * TDI_SLEEPING/TDI_LOCK/TDI_IWAIT
						 * all resolve via an event this
						 * boot's own live kernel
						 * delivers (a timeout, a lock
						 * release, an interrupt) and
						 * are NOT gated on anything
						 * from the image's own world --
						 * so only genuine
						 * TDI_SUSPENDED (this boot's
						 * own suspend machinery, e.g.
						 * single-threading) is excluded
						 * from "will become runnable".
						 */
						ni_is_runnable =
						    TD_ON_RUNQ(ni_td) ||
						    TD_CAN_RUN(ni_td) ||
						    TD_IS_RUNNING(ni_td) ||
						    TD_IS_SLEEPING(ni_td) ||
						    TD_ON_LOCK(ni_td) ||
						    TD_AWAITING_INTR(ni_td);
						if (ni_is_runnable) {
							ni_runnable++;
							if (ni_reported < 8) {
								printf(
								    "hibernate: k24t00: non-image runnable: "
								    "pid=%d comm=%s tid=%d state=%s pcb_page=%#lx\n",
								    (int)
									ni_pp->p_pid,
								    ni_pp->p_comm,
								    (int)
									ni_td->td_tid,
								    TD_IS_SLEEPING(
									ni_td) ?
									"sleep" :
									TD_ON_LOCK(
									    ni_td) ?
									"lock" :
									TD_AWAITING_INTR(
									    ni_td) ?
									"iwait" :
									"runnable",
								    ni_pcb_page);
								ni_reported++;
							}
						}
					}
					PROC_UNLOCK(ni_pp);
				}
				sx_sunlock(&allproc_lock);

				printf("hibernate: k24t00: non-image census: "
				    "live=%u staged=%u nonimage=%u "
				    "nonimage_runnable=%u\n",
				    ni_total, ni_staged, ni_nonimage,
				    ni_runnable);
			}

			selfcopied = 0;
			u_int k24t31_fpu_attempted = 0;
			u_int k24t31_fpu_unresolved = 0;
			u_int k24t31_fpu_stashed = 0;
			/*
			 * K24-T00 (rip=0x2 fix, round 2): this worker
			 * thread's own kstack is self-copy-protected
			 * (copy_leaf=true, see hibernate_machdep_prepare()'s
			 * block_seq=4 live-kstack block, above) so it
			 * survives the K-10 destructive copy as THIS boot's
			 * own live, still-executing C frames at its own
			 * VIRTUAL ADDRESS -- never the image's content for
			 * that VA. Round 1 of this fix compared PHYSICAL
			 * frames (worker_kstack_pa_lo/_hi) and proved
			 * insufficient: a repeat capture (K24T00-WORKERCOLL-
			 * SKIP, this round) showed the skip correctly firing
			 * for "sh" (pid 1084)'s 4 kstack pages, yet the
			 * SAME rip=0x2 panic recurred on that exact pid/tid.
			 * The real collision is not physical-frame aliasing
			 * at all: kstack VAs are assigned from a small,
			 * deterministic kva-arena stride
			 * (VM_MIN_KERNEL_ADDRESS + slot*stride, see
			 * hibernate_machdep_prepare()'s own kstack_slot
			 * derivation elsewhere in this file), so an
			 * unrelated SAVED thread from the image's own boot
			 * and this LIVE worker thread from the resume boot
			 * can be assigned the IDENTICAL kernel virtual
			 * address for their respective kstacks -- confirmed
			 * directly: "sh"'s own stashed va
			 * (0xfffffe0068f75000-0xfffffe0068f78000) is
			 * BIT-IDENTICAL to this worker's own
			 * worker_kstack_va (K24T00-PARKSTACK's own print,
			 * same run). The post-copy stash install
			 * (hibernate_md_kva_install_pub(), acpi.c) then
			 * rewrites the PTE at that exact live VA to point at
			 * "sh"'s own foreign leaf_pa -- unmapping the
			 * physical backing store this worker is CURRENTLY
			 * executing its own C frames on, out from under it,
			 * which is the actual write that produces the
			 * rip=0x2/corrupt-rbp signature (not a frame-content
			 * read of stale bytes, a VA whose mapping itself
			 * was just yanked).
			 *
			 * Fix: compute this worker's own live kstack VIRTUAL
			 * ADDRESS range once, here, before the per-thread
			 * stash loop runs, and skip stashing any leaf whose
			 * DESTINATION VA (not physical frame) falls inside
			 * this worker's own live kstack VA range. That VA's
			 * live mapping is left exactly as the ordinary resume
			 * boot already set it up -- this worker's own, still
			 * in use -- never retargeted by the post-copy
			 * install, regardless of which physical frame either
			 * side happens to use.
			 */
			vm_offset_t k24t00_worker_kstack_va_lo,
			    k24t00_worker_kstack_va_hi;

			k24t00_worker_kstack_va_lo =
			    (vm_offset_t)curthread->td_kstack;
			k24t00_worker_kstack_va_hi =
			    k24t00_worker_kstack_va_lo +
			    ptoa(curthread->td_kstack_pages);

			for (i = 0; i < nthreads; i++) {
				struct hibernate_md_walk walk;
				vm_offset_t va;
				bool resolved;
				u_int pg;

				for (pg = 0; pg < threads[i].kstack_pages;
				    pg++) {
					vm_paddr_t live_pa;

					va = threads[i].kstack_va +
					    (vm_offset_t)pg * PAGE_SIZE;
					resolved = hib_staged_leaf(ha, wvec, p,
					    va, &walk);
					if (!resolved) {
						if (hib_md_safe_resolve(
						    kernel_pmap->pm_cr3, va,
						    &live_pa)) {
							continue;
						}
						/*
						 * neither the staged
						 * leaf resolver NOR the live-
						 * superpage fallback can
						 * resolve this VA. Before
						 * refusing, check whether the
						 * SAVED domain's own page
						 * tables (hi_pcb.hp_cr3, the
						 * CR3 that will be in force
						 * immediately after this
						 * resume continuation) have a
						 * valid terminal PTE here.
						 * Confirmed by direct
						 * capture: this
						 * case DOES occur (a kstack
						 * page genuinely unmapped in
						 * the LIVE resume-kernel tree
						 * at this early point, but
						 * also unmapped in the saved
						 * domain's own tree -- the
						 * saved image's own terminal
						 * PTE read back as 0/invalid,
						 * not merely unreachable). A
						 * page absent from BOTH
						 * domains is not a resolution
						 * gap to paper over: it means
						 * this exact 4 KiB kstack
						 * page was never written by
						 * either kernel and will
						 * never be read before being
						 * written again (ordinary
						 * kernel stacks are sized for
						 * worst-case depth, not
						 * guaranteed fully touched) --
						 * skip it, counted and named,
						 * exactly as the sibling
						 * thread0-superpage case
						 * above already skips a
						 * disjoint-but-resolvable
						 * page for an analogous
						 * reason. If the saved domain
						 * DID show a valid leaf here,
						 * that would be a different,
						 * install-worthy case this
						 * branch does not take --
						 * fail closed instead.
						 */
						if (!hib_saved_domain_leaf_valid(
						    ha, wvec, p, va)) {
							hibernate_resume_kstack_skip_count++;
							continue;
						}
						error = EINVAL;
						break;
					}
					if ((walk.hmw_flags &
					    (X86_PG_V | X86_PG_RW)) !=
					    (X86_PG_V | X86_PG_RW)) {
						error = EINVAL;
						break;
					}
					/*
					 * K24-T00 round 19: stash this
					 * thread's resolved staged leaf
					 * (va, walk.hmw_pa, walk.hmw_flags)
					 * into the arena's copy-excluded
					 * stash region BEFORE the destructive
					 * copy runs, so a POST-copy pass can
					 * install it into whatever page
					 * tables are actually in force at
					 * that point (round 17/18's own
					 * finding: pre-copy, kernel_pmap's
					 * own root is not itself an image
					 * destination-set member, so
					 * installing into the LIVE tree here
					 * writes into a tree the restored
					 * kernel does not adopt). One entry
					 * per PAGE, not per thread, since
					 * each page's own leaf PA/flags are
					 * independent and the post-copy pass
					 * needs exactly this granularity to
					 * install correctly.
					 */
					/*
					 * K24-T00 (rip=0x2 fix, round 2):
					 * never stash a leaf whose
					 * DESTINATION VA (not physical
					 * frame -- see this loop's own
					 * header comment, immediately
					 * above its opening brace, for why
					 * round 1's PA-based check was
					 * insufficient) aliases this
					 * worker's own live kstack VA
					 * range. Skipping the stash means
					 * the post-copy install pass never
					 * rewrites the PTE at this VA away
					 * from the resume boot's own,
					 * already-correct live mapping;
					 * the page is left exactly as this
					 * file's own pre-existing "sparse,
					 * never-touched" sentinel case.
					 */
					if (va >=
					    k24t00_worker_kstack_va_lo &&
					    va <
					    k24t00_worker_kstack_va_hi) {
						printf(
						    "K24T00-WORKERCOLL-SKIP: "
						    "pid=%d comm=%s "
						    "page_index=%u va=%#jx "
						    "leaf_pa=%#jx "
						    "worker_va=[%#jx-%#jx)\n",
						    (int)threads[i].pid,
						    threads[i].comm, pg,
						    (uintmax_t)va,
						    (uintmax_t)walk.hmw_pa,
						    (uintmax_t)
						    k24t00_worker_kstack_va_lo,
						    (uintmax_t)
						    k24t00_worker_kstack_va_hi);
						/*
						 * K24-T00 (rip=0x2 fix,
						 * round 3): skipping the
						 * stash/install is not
						 * sufficient on its own --
						 * THIS thread's own
						 * td_kstack field (copied
						 * verbatim from the image)
						 * still equals the worker's
						 * own live VA range, so if
						 * this thread is later
						 * scheduled and runs on that
						 * VA, it executes on
						 * physical memory the
						 * worker's own live context
						 * may still be using (or
						 * vice versa) -- the second,
						 * distinct half of the same
						 * collision. Route through
						 * the SAME already-proven
						 * exclusion list the
						 * "genuine zero terminal
						 * PTE" case immediately
						 * below already uses: mark
						 * thread_has_uncovered so
						 * this thread is recorded
						 * in k24t00_exclude_list and
						 * not released post-copy,
						 * exactly like any other
						 * thread whose kstack cannot
						 * be safely installed.
						 */
						if (!thread_has_uncovered) {
							thread_has_uncovered =
							    true;
							if (!have_first_offender) {
								have_first_offender =
								    true;
								first_offending_pid =
								    threads[i].pid;
								first_offending_va =
								    va;
							}
						}
						total_uncovered_pages++;
						thread_missing_pages++;
					} else if (k24t00_kstack_stash_n <
					    K24T00_KSTACK_STASH_MAX) {
						struct k24t00_kstack_stash_entry
						    *se;

						se = (struct
						    k24t00_kstack_stash_entry *)
						    PHYS_TO_DMAP(
							layout.stash_pa) +
						    k24t00_kstack_stash_n;
						se->va = va;
						se->leaf_pa = walk.hmw_pa;
						se->flags = walk.hmw_flags;
						se->is_fpu = false;
						/*
						 * K24-T00 round 26: the
						 * post-copy install pass
						 * (acpi.c) reports 13
						 * deterministic failures
						 * every run, all at the
						 * identical va
						 * 0x6f69d50c0311000 with
						 * reason=1 (misaligned
						 * va/leaf_pa in
						 * hibernate_md_kva_install()).
						 * That va cannot be a real
						 * kstack VA produced by
						 * this loop (va is always
						 * page-aligned here by
						 * construction). Print, at
						 * the trusted pre-copy
						 * population site, the
						 * pid/comm/tid of whichever
						 * thread's iteration writes
						 * this exact va into the
						 * stash, so the install-
						 * time failure can be
						 * correlated back to its
						 * true originating thread.
						 */
						k24t00_kstack_stash_n++;
					 * K24-T00 round 15 RESULT: the test
					 * above (disabling this install for
					 * staged threads) was REVERTED.
					 * Round 15's N=12 campaign showed
					 * kstack_verify firing MORE often
					 * (6/12) with the install disabled
					 * than with it active (4/12) -- the
					 * install is doing useful work for
					 * some threads even though it does
					 * not fix syslogd's/logger's own
					 * gap. The gap itself was proven
					 * save-side (round 16): the image's
					 * own post-copy tables lack the
					 * mapping regardless of this
					 * install, so this install is
					 * restored to its original
					 * unconditional form rather than
					 * kept disabled as a non-fix that
					 * measurably worsened the failure
					 * rate.
					 *
					 * K24-T00 round 19: this pre-copy
					 * install into the LIVE tree is now
					 * SUPERSEDED by the post-copy
					 * install from the stash above --
					 * round 17/18 proved this live tree
					 * is not the one the restored kernel
					 * actually adopts. error is forced
					 * to 0 so the existing per-page
					 * accounting below (which still has
					 * real value: req_pages/inst_pages
					 * diagnostics, the kstack-coverage
					 * printf) is unaffected; the actual
					 * mapping work now happens once,
					 * post-copy, from the stash just
					 * populated above.
					 */
					error = 0;
					if (error == 0) {
						/*
						break;
					error = hib_selfcopy_pt(ha, wvec, p, va,
					    &selfcopied);
					if (error != 0) {
						if (is_target) {
							err_pages++;
							last_err = error;
						}
						break;
					}
					if (is_target)
						inst_pages++;

					/*
				 * K24-T00 round 31: stash this thread's own
				 * pcb->pcb_save (FPU/XSAVE save area) pages
				 * the same way the kstack loop above stashes
				 * td_kstack pages -- resolved from the
				 * image's own saved tables via the identical
				 * hib_staged_leaf(), stored as (va, leaf_pa,
				 * flags) in the same stash array/mechanism
				 * the post-copy install pass (acpi.c) already
				 * consumes. is_fpu=true marks these entries
				 * so the install pass can force PG_RW on
				 * them (see acpi.c's own comment for why) and
				 * so the verifier can report them separately
				 * from kstack pages.
				 *
				 * Round 30's live DDB capture proved the
				 * concrete failure mode: fpu_activate_sw()'s
				 * memmove() into pcb_save faulted with
				 * "supervisor write data, protection
				 * violation" at a mapped-but-read-only page
				 * -- not missing. Resolution failures here
				 * are counted (k24t31_fpu_unresolved) but do
				 * not block the thread's kstack stash above;
				 * this is strictly additive.
				 */
				if (threads[i].fpu_save_va != 0) {
					vm_offset_t fpu_lo, fpu_hi, fva;

					fpu_lo = trunc_page(
					    threads[i].fpu_save_va);
					fpu_hi = trunc_page(
					    threads[i].fpu_save_va +
					    cpu_max_ext_state_size - 1);
					for (fva = fpu_lo; fva <= fpu_hi;
					    fva += PAGE_SIZE) {
						struct hibernate_md_walk
						    fpu_walk;

						k24t31_fpu_attempted++;
						if (!hib_staged_leaf(ha, wvec,
						    p, fva, &fpu_walk)) {
							k24t31_fpu_unresolved++;
							continue;
						}
						if (k24t00_kstack_stash_n <
						    K24T00_KSTACK_STASH_MAX) {
							struct
							    k24t00_kstack_stash_entry
								*fse;

							fse = (struct
							    k24t00_kstack_stash_entry
								*)
							    PHYS_TO_DMAP(
								layout
								    .stash_pa) +
							    k24t00_kstack_stash_n;
							fse->va = fva;
							fse->leaf_pa =
							    fpu_walk.hmw_pa;
							/*
							 * Force PG_RW (and
							 * PG_V) regardless
							 * of the image's
							 * own saved flags.
							 * fpu_activate_sw()'s
							 * restore path
							 * WRITES into this
							 * page every time
							 * it runs (the
							 * round 30 fault is
							 * exactly that
							 * write failing);
							 * unlike a kstack
							 * leaf (whose
							 * image-saved
							 * flags are
							 * trusted as-is), a
							 * pcb_save page is
							 * never correct
							 * read-only, so
							 * forcing
							 * writability here
							 * is specific to
							 * this one content
							 * class, not a
							 * generic
							 * override. NX/U
							 * are still
							 * preserved from
							 * the image: this
							 * page's
							 * executability/
							 * user-
							 * accessibility
							 * semantics are
							 * unrelated to the
							 * bug and must not
							 * be touched. Do
							 * NOT apply this
							 * force-writable
							 * treatment to any
							 * other content
							 * class (e.g.
							 * kstack text/
							 * data, kernel
							 * .rodata) whose
							 * read-only
							 * disposition in
							 * the image is
							 * intentional and
							 * must be
							 * preserved as-is.
							 */
							fse->flags =
							    (fpu_walk
								    .hmw_flags |
								X86_PG_V |
								X86_PG_RW);
							fse->is_fpu = true;
							k24t00_kstack_stash_n++;
							k24t31_fpu_stashed++;
						}
					}
				}
				/*
				if (thread_has_uncovered) {
					threads_with_uncovered++;
					/*
					 * K24-T00 round 29: record this
					 * thread in the arena-backed
					 * exclusion list -- round 28
					 * confirmed its missing page(s) are
					 * a genuine zero terminal PTE in
					 * the saved image's own tables, not
					 * a resolvable gap. No install can
					 * ever place these pages; this
					 * thread must not be released
					 * post-copy.
					 */
					if (k24t00_exclude_n <
					    K24T00_EXCLUDE_MAX) {
						struct k24t00_exclude_entry
						    *xe;

						xe = &k24t00_exclude_list[
						    k24t00_exclude_n];
						xe->td = (struct thread *)
						    threads[i].td_va;
						xe->pid = threads[i].pid;
						memcpy(xe->comm,
						    threads[i].comm,
						    sizeof(xe->comm) - 1);
						xe->comm[
						    sizeof(xe->comm) - 1] =
						    '\0';
						xe->missing_pages =
						    thread_missing_pages;
						k24t00_exclude_n++;
					}
				}
			 * K24-T00 round 24: self-copy-protect
			 * k24t00_kstack_stash_n immediately after the last
			 * write to it, exactly like k24t00_staged_pcb_
			 * page_g above -- this count's correct content is
			 * THIS boot's own just-populated value, never the
			 * saved image's stale content for this same
			 * address (see this global's own declaration
			 * comment for the full account).
			 */
			if (error == 0) {
				vm_offset_t ksn_pg, ksn_end;
				u_int ksn_selfcopied = 0;

				ksn_pg = trunc_page(
				    (vm_offset_t)&k24t00_kstack_stash_n);
				ksn_end = round_page(
				    (vm_offset_t)&k24t00_kstack_stash_n +
				    sizeof(k24t00_kstack_stash_n));
				for (; ksn_pg < ksn_end;
				    ksn_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    ksn_pg, true, &ksn_selfcopied);
					if (error != 0)
						break;
				}
			}
			/*
			 * K24-T00 round 29: self-copy-protect
			 * k24t00_exclude_n the same way, immediately
			 * after the last write to it -- same reasoning as
			 * k24t00_kstack_stash_n above: this count's correct
			 * content is this boot's own just-populated value.
			 */
			if (error == 0) {
				vm_offset_t xn_pg, xn_end;
				u_int xn_selfcopied = 0;

				xn_pg = trunc_page(
				    (vm_offset_t)&k24t00_exclude_n);
				xn_end = round_page(
				    (vm_offset_t)&k24t00_exclude_n +
				    sizeof(k24t00_exclude_n));
				for (; xn_pg < xn_end; xn_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    xn_pg, true, &xn_selfcopied);
					if (error != 0)
						break;
				}
			}
			/*
			 * K24-T00 round 29: self-copy-protect the exclusion
			 * list array itself, same reasoning as
			 * k24t00_exclude_n immediately above -- this boot's
			 * own just-populated entries, not the saved image's
			 * stale content for this same address range.
			 */
			if (error == 0) {
				vm_offset_t xl_pg, xl_end;
				u_int xl_selfcopied = 0;

				xl_pg = trunc_page(
				    (vm_offset_t)&k24t00_exclude_list);
				xl_end = round_page(
				    (vm_offset_t)&k24t00_exclude_list +
				    sizeof(k24t00_exclude_list));
				for (; xl_pg < xl_end; xl_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    xl_pg, true, &xl_selfcopied);
					if (error != 0)
						break;
				}
			}
			/*
			 * K24-T31: self-copy-protect k24t31_recorded_n and
			 * k24t31_recorded_threads[] the same way, immediately
			 * after the last write to each -- same reasoning as
			 * k24t00_exclude_n/k24t00_exclude_list immediately
			 * above: this boot's own just-populated staged-
			 * thread list, never the saved image's stale content
			 * for this same address range. See k24t31_recorded_
			 * threads[]'s own declaration comment for why this
			 * list exists and what it replaces.
			 */
			if (error == 0) {
				vm_offset_t rn_pg, rn_end;
				u_int rn_selfcopied = 0;

				rn_pg = trunc_page(
				    (vm_offset_t)&k24t31_recorded_n);
				rn_end = round_page(
				    (vm_offset_t)&k24t31_recorded_n +
				    sizeof(k24t31_recorded_n));
				for (; rn_pg < rn_end; rn_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    rn_pg, true, &rn_selfcopied);
					if (error != 0)
						break;
				}
			}
			if (error == 0) {
				vm_offset_t rt_pg, rt_end;
				u_int rt_selfcopied = 0;

				rt_pg = trunc_page(
				    (vm_offset_t)&k24t31_recorded_threads);
				rt_end = round_page(
				    (vm_offset_t)&k24t31_recorded_threads +
				    sizeof(k24t31_recorded_threads));
				for (; rt_pg < rt_end; rt_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    rt_pg, true, &rt_selfcopied);
					if (error != 0)
						break;
				}
			}
			free(threads, M_TEMP);
		}
		if (error == 0) {
			/*
			 * per-thread user-FPU save area --
			 * requested after direct testing isolated the AP-
			 * side fpurestore_xrstor3264() GPF/double-fault
			 * cascade (T13's own outcome table, runs 5/9; T12's
			 * own runs 6-7) to shape (1) of the two candidates:
			 * PCB_FPUINITDONE already set (a genuine, working
			 * thread per the restore_fpu capture
			 * taken immediately before the K-10 copy) on a
			 * thread whose pcb_save area reads a MALFORMED
			 * XSAVE header post-copy (live capture,
			 * restore-20261109-112805.log: xstate_bv=
			 * 0xfffffe00004d1f48, xcomp_bv=0x1 -- not a valid
			 * state-component bitmap, closer in magnitude to a
			 * raw pointer value than to any of this round's
			 * own genuinely-valid captures, which read small,
			 * sparse values like 0x1/0x2 throughout). This
			 * rules out shape (2) (pcb_save itself invalid/
			 * misaligned): every capture's own pcb_save pointer
			 * resolved to a valid physical page via vtophys()
			 * (added this round specifically to test this),
			 * align6=0 (64-byte aligned, satisfying XSAVE's own
			 * requirement) on every single capture, pre- and
			 * post-copy alike.
			 *
			 * Root cause: get_pcb_user_save_td()/
			 * get_pcb_user_save_pcb() (sys/amd64/amd64/
			 * vm_machdep.c) resolve pcb_save to
			 * td->td_md.md_usr_fpu_save -- a SEPARATE
			 * allocation from both the struct proc page and the
			 * thread's own kstack (fpu_save_area_alloc(),
			 * cpu_thread_alloc(), sys/amd64/amd64/
			 * vm_machdep.c:375), outside the destination-set
			 * bitmap hibernate_md_enumerate_procs() (this same
			 * file) computes: that function's own k28
			 * enumeration walks exactly two physical regions
			 * per thread -- the struct proc page
			 * (trunc_page((vm_offset_t)pp)) and
			 * td->td_kstack -- and never resolves or registers
			 * td_md.md_usr_fpu_save at all. The pointer value
			 * itself survives the K-10 copy correctly (it lives
			 * on the kstack, which IS covered), but the
			 * separate physical page it points at is never
			 * accounted for by the destination-set membership
			 * test, so its post-copy CONTENT is whatever the
			 * saved image's own snapshot happened to leave at
			 * that physical address -- the identical "never-
			 * accounted-for, live-but-clobbered" shape this
			 * epic has already found and fixed seven times
			 * (pc_gdt, KPML4phys, ths[], vm_page_array, idle
			 * kstacks, vm_dom[], and DPCPU, several lines above
			 * this same block).
			 *
			 * Disposition: copy_leaf=true, mirroring the DPCPU
			 * block immediately above and for the identical
			 * reason -- this is live, in-use allocator content
			 * this boot's own cpu_fork()/fpu_save_area_alloc()
			 * already built correctly (a freshly allocated save
			 * area, or this boot's own prior fpurestore() output
			 * for a thread that had already used the FPU before
			 * suspend); there is no saved-image content here
			 * worth restoring FROM -- the resumed thread's own
			 * logical FPU state is reconstructed by the ordinary
			 * cold-init branch in restore_fpu_curthread() when
			 * PCB_FPUINITDONE is clear, and left as this boot's
			 * own valid data when it is already set, exactly
			 * paralleling why saved_pcb_va alone (not this
			 * region) needs copy_leaf=false.
			 *
			 * Walked for every process/thread in the system
			 * (mirroring hibernate_md_enumerate_procs()'s own
			 * traversal shape exactly, same locks, same order:
			 * allproc_lock then PROC_LOCK), not merely the BSP/
			 * AP idle threads the pre-existing kstack self-copy
			 * blocks above already cover -- the T14 capture's
			 * own faulting thread (tid 100089, "acpiconf") is
			 * an ordinary user thread reached via the interrupt-
			 * resume path, not an idle thread.
			 *
			 * a zone-wide variant of this fix
			 * (protecting fpu_save_area_zone's own backing pages
			 * as a unit) was tried and REVERTED: an 8-run
			 * campaign showed it recurred on 3/3 runs that
			 * reached the fault's own call path (worse than this
			 * per-thread walk's own 1/5), falsifying the
			 * "immune by construction" reasoning it was built
			 * on. Its own failure mode was never re-diagnosed.
			 *
			 * CONTENT PROTECTION REPLACED WITH A
			 * GATE. Both T14 (per-thread self-copy-protect) and
			 * T15 (zone-wide self-copy-protect) tried to make
			 * td_md.md_usr_fpu_save's own CONTENT survive the
			 * K-10 copy intact -- but any thread created between
			 * this walk and the destructive copy (via fork() or
			 * pthread_create(), both funnelled through
			 * sys/amd64/amd64/vm_machdep.c's own copy_thread())
			 * is handed a BRAND-NEW fpu_save_area_alloc()
			 * physical page that did not exist at this walk's
			 * own time and so could never have been protected by
			 * either mechanism -- the structural reason both
			 * attempts left a window (T14: 1/5 recurrence) or
			 * failed outright (T15: 3/3).
			 *
			 * The content-preservation goal is abandoned here in
			 * favour of a GATE that is robust to this timing by
			 * CONSTRUCTION, not merely by coverage: instead of
			 * self-copy-protecting each thread's own save-area
			 * page, clear_pcb_flags(..., PCB_FPUINITDONE |
			 * PCB_USERFPUINITDONE) is called on every thread this
			 * walk reaches, forcing restore_fpu_curthread()'s own
			 * cold-init branch ("if ((pcb->pcb_flags &
			 * PCB_FPUINITDONE) == 0) { bcopy(fpu_initialstate,
			 * pcb->pcb_save, ...); ... }", sys/amd64/amd64/
			 * fpu.c) on this thread's own first post-resume FPU
			 * use, UNCONDITIONALLY overwriting whatever content
			 * (genuine or clobbered) its own save area holds --
			 * the save area's own CONTENT becomes irrelevant, so
			 * no self-copy-protect call against it is needed at
			 * all.
			 *
			 * Why this closes the race rather than narrowing it:
			 * copy_thread() (sys/amd64/amd64/vm_machdep.c)
			 * ALWAYS begins with "bcopy(td1->td_pcb, pcb2,
			 * sizeof(*pcb2))" -- an unconditional, byte-for-byte
			 * copy of the creating thread's ENTIRE pcb, including
			 * pcb_flags, into the new thread's own pcb, BEFORE
			 * that new thread is handed its own fresh
			 * fpu_save_area_alloc() page. Any thread created
			 * during the race window is therefore, by ordinary
			 * causality within this single boot's own execution
			 * timeline, forked from (or pthread_create()'d
			 * alongside) a thread that was ALREADY walked and
			 * gated by this exact loop -- so its own inherited
			 * pcb_flags already has PCB_FPUINITDONE clear at the
			 * moment of the bcopy, regardless of how much later
			 * the creation happens relative to this walk. The new
			 * thread's own cold-init branch fires on its own
			 * first FPU use, exactly as if it were an ordinary
			 * first-time FPU user -- no gap, no timing dependency
			 * on when between this walk and the no-return jump
			 * the creation occurs.
			 *
			 * TRADE-OFF, stated explicitly per this round's own
			 * requested disposition: every walked thread LOSES
			 * its own genuine pre-suspend FPU register state --
			 * its first post-resume FPU touch reloads
			 * fpu_initialstate (ordinary reset values, the exact
			 * same state an ordinary cold-boot first-FPU-use
			 * thread already gets) rather than its own real,
			 * pre-hibernate register contents. This is accepted,
			 * for every thread class including the resuming/
			 * dump-invoking userland process itself, with no
			 * special-casing, because: (1) the alternative,
			 * confirmed this epic's own own T14/T15 campaigns, is
			 * an outright kernel panic (GPF in
			 * fpurestore_xrstor3264()) on recurrence -- a
			 * silently-reinitialised FPU register file is
			 * strictly preferable to a crash; (2) no FreeBSD ABI
			 * or POSIX contract promises FPU register CONTENT
			 * persistence across hibernate/resume -- unlike
			 * general-purpose registers, memory, or file-
			 * descriptor state, x87/SSE/AVX register VALUES are
			 * not part of any documented cross-suspend guarantee,
			 * and ordinary ACPI S3/S4 resume on real hardware
			 * already involves CPU state re-establishment of this
			 * kind; (3) the lost state is register CONTENT only,
			 * never correctness-bearing kernel bookkeeping (pcb
			 * identity, thread scheduling state, memory contents,
			 * and process semantics are all untouched by this
			 * change) -- a program that depends on specific FPU
			 * register VALUES surviving an actual hibernate cycle
			 * unchanged is relying on behaviour no POSIX/FreeBSD
			 * interface guarantees in the first place. No thread
			 * class was found needing different handling.
			 */
			struct proc *fpu_pp;
			struct thread *fpu_td;

			sx_xlock(&allproc_lock);
			FOREACH_PROC_IN_SYSTEM(fpu_pp) {
				PROC_LOCK(fpu_pp);
				FOREACH_THREAD_IN_PROC(fpu_pp, fpu_td) {
					if (fpu_td->td_md.md_usr_fpu_save ==
					    NULL)
						continue;
					clear_pcb_flags(fpu_td->td_pcb,
					    PCB_FPUINITDONE |
					    PCB_USERFPUINITDONE);
				}
				PROC_UNLOCK(fpu_pp);
			}
			sx_xunlock(&allproc_lock);
		}
		if (error == 0) {
			/*
			 * ths[]'s (timehands ring buffer,
			 * sys/kern/kern_tc.c) own page-table path can fall
			 * inside the K-10 destination set and collapse,
			 * exactly like pc_gdt/vm_page_array/kstack above.
			 * Every time-reading primitive built on
			 * GETTHBINTIME() (binuptime()/sbinuptime()/etc.)
			 * loops until it observes th_generation nonzero and
			 * stable across two consecutive loads; if that
			 * generation field is left unreadable/unstable by a
			 * collapsed mapping, the loop spins forever with no
			 * escape -- confirmed this session: execution hangs
			 * silently, with no further output at all,
			 * immediately after the first unbracketed
			 * sbinuptime() call on the resume path
			 * (hibernate_resume_park_release(),
			 * sys/kern/kern_hibernate.c), before clock resume
			 * (resumeclock()/resume_TSC()) has even run -- exactly
			 * where this analysis predicts, since nothing upstream
			 * of this fix ever protected this structure.  The
			 * array's *content* must be the RESUME kernel's own,
			 * correctly cold-booted clock state (ths[0]'s own
			 * static initializer sets th_generation = 1), not the
			 * saved image's cross-boot snapshot of a different
			 * boot's clock hardware/calibration -- so copy_leaf is
			 * true here, the same rule as pc_gdt/KPML4phys, not
			 * vm_page_array/kstack's copy_leaf=false.
			 */
			uintptr_t ths_va;
			size_t ths_len;
			vm_offset_t ths_pg, ths_end;

			tc_hibernate_selfcopy_range(&ths_va, &ths_len);
			ths_pg = trunc_page((vm_offset_t)ths_va);
			ths_end = round_page((vm_offset_t)ths_va + ths_len);
			for (; ths_pg < ths_end; ths_pg += PAGE_SIZE) {
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, ths_pg, true,
				    &selfcopied);
				if (error != 0)
					break;
			}
		}
		if (error == 0) {
			/*
			 * K24-T02: struct pvclock_vcpu_time_info
			 * timeinfos[] (sys/dev/kvm_clock/kvm_clock.c) --
			 * the per-vCPU TSC-scale/shift/timestamp array
			 * pvclock_read_time_info() spins on (an ABA loop
			 * on its own `version` field, the IDENTICAL shape
			 * ths[] above was already fixed for), reached by
			 * every sbinuptime()/binuptime() call on this
			 * KVM-clock-backed harness via
			 * pvclock_tc_get_timecount().  A corrupted version
			 * field here spins hibernate_park_dispatch()'s own
			 * deadline poll forever, silently, with no panic
			 * and no further output -- captured live this
			 * round via QMP (CPU#1 frozen at an identical RIP
			 * across samples minutes apart; CPU#0 parked at
			 * the literal power-on reset vector).  Never
			 * previously protected: zero prior references
			 * confirmed by exhaustive grep.  copy_leaf=true,
			 * same rule as ths[] -- this boot's own
			 * kvm_clock_attach()-initialized calibration, not
			 * the saved image's snapshot of a different boot's
			 * clock hardware.
			 */
			extern void kvm_clock_hibernate_selfcopy_range(
			    uintptr_t *va_out, size_t *len_out);
			uintptr_t ti_va;
			size_t ti_len;
			vm_offset_t ti_pg, ti_end;

			kvm_clock_hibernate_selfcopy_range(&ti_va, &ti_len);
			if (ti_va != 0 && ti_len != 0) {
				ti_pg = trunc_page((vm_offset_t)ti_va);
				ti_end = round_page((vm_offset_t)ti_va +
				    ti_len);
		if (error == 0) {
			/*
			 * acpi_timer_eh (sys/dev/acpica/acpi_timer.c) -- a
			 * plain static eventhandler_tag global, not reached
			 * by the eventhandler_hibernate_selfcopy_nodes() walk
			 * above (that walk only protects struct
			 * eventhandler_list nodes and the struct
			 * eventhandler_entry nodes hanging off their own
			 * el_entries TAILQ, not every driver-local cache of
			 * one of those nodes' addresses).  Confirmed by live
			 * capture: two independent 12-run verification
			 * campaigns (k24t00-ssp-n12, runs 3 and 10) both
			 * panicked with an identical RIP inside
			 * _eventhandler_deregister()+0xac, called from
			 * acpi_timer_resume() via EVENTHANDLER_DEREGISTER
			 * (power_resume, acpi_timer_eh), itself reached from
			 * acpi_EnterSleepState() via an ordinary acpiconf(8)
			 * ioctl run after restore completes.  Whenever
			 * hibernate entry runs acpi_timer_suspend_handler(),
			 * this boot's own acpi_timer_eh is set non-NULL
			 * before the image is saved; the K-10 destructive
			 * copy then overwrites this (resume) boot's own
			 * fresh BSS-zero value with that stale pointer,
			 * which acpi_timer_resume() unconditionally
			 * dereferences.  copy_leaf=true: this boot's own
			 * fresh NULL is the correct content to preserve,
			 * the same rule already applied to every sibling
			 * driver-local eventhandler_tag/cache global in this
			 * tree.
			 */
			extern void acpi_timer_hibernate_selfcopy_eh_va(
			    uintptr_t *va_out, size_t *len_out);
			uintptr_t ateh_va;
			size_t ateh_len;
			vm_offset_t ateh_pg, ateh_end;

			acpi_timer_hibernate_selfcopy_eh_va(&ateh_va,
			    &ateh_len);
			if (ateh_va != 0 && ateh_len != 0) {
				ateh_pg = trunc_page((vm_offset_t)ateh_va);
				ateh_end = round_page(
				    (vm_offset_t)ateh_va + ateh_len);
				for (; ateh_pg < ateh_end;
				    ateh_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    ateh_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * CAM peripheral driver structs (ata_da.c's own
			 * "adadriver", scsi_da.c's "dadriver", etc.) -- the
			 * NINTH instance of the same destination-set-
			 * accounting-gap class as pc_gdt/KPML4phys/ths[]/
			 * vm_page_array/idle kstacks/vm_dom[]/DPCPU/FPU save
			 * area above.  Confirmed by direct disassembly of a
			 * live crash this round: adaresume()'s own
			 * CAM_PERIPH_FOREACH(periph, &adadriver) loads
			 * adadriver.units.tqh_first directly ("mov
			 * 0x10(%rbx),%rbx" at adaresume+0x19, rbx=
			 * 0xdeadc0dedeadc0de observed at the fault), then
			 * faults dereferencing periph->flags at adaresume+
			 * 0x30 -- i.e. the driver struct's own TAILQ_HEAD
			 * sentinel, populated once by THIS boot's own
			 * periphdriver_register() (sys/cam/cam_periph.c) at
			 * module-load time, was overwritten by the SAVED
			 * image's cross-boot content.  Content must be the
			 * RESUME kernel's own cold-boot value (copy_leaf=
			 * true, the same rule as pc_gdt/ths[]/vm_dom[]/
			 * DPCPU), since each driver's own periph TAILQ was
			 * built by this boot's own device probes, not the
			 * saved image's.  cam_periph_hibernate_ndrivers()/
			 * cam_periph_hibernate_selfcopy_range()
			 * (sys/cam/cam_periph.c, declared sys/cam/
			 * cam_periph.h) reuse the existing periph_drivers[]
			 * registry so every registered CAM peripheral driver
			 * (ada, da, cd, sa, nda, pass, ...) is protected
			 * uniformly, not just the one (adadriver) this
			 * round's own crash happened to surface.
			 */
			extern u_int cam_periph_hibernate_ndrivers(void);
			extern void cam_periph_hibernate_selfcopy_range(
			    u_int idx, uintptr_t *va_out, size_t *len_out);
			u_int cam_ndrivers, cam_idx;

			cam_ndrivers = cam_periph_hibernate_ndrivers();
			for (cam_idx = 0; cam_idx < cam_ndrivers && error == 0;
			    cam_idx++) {
				uintptr_t cam_va;
				size_t cam_len;
				vm_offset_t cam_pg, cam_end;

				cam_periph_hibernate_selfcopy_range(cam_idx,
				    &cam_va, &cam_len);
				if (cam_va == 0 || cam_len == 0)
					continue;
				cam_pg = trunc_page((vm_offset_t)cam_va);
				cam_end = round_page((vm_offset_t)cam_va +
				    cam_len);
				for (; cam_pg < cam_end;
				    cam_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    cam_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * Each live CPU's own DPCPU (dynamic per-CPU) region.
			 * Confirmed by direct testing: once the AP idle-thread
			 * reseed above lets the continuation run further, a NEW
			 * panic appears inside resumeclock()'s own configtimer()
			 * call ("spin lock held too long", ET_HW_LOCK).  This is
			 * the same bug class as pc_gdt/KPML4phys/ths[] above: a
			 * resume-kernel-owned structure whose backing physical
			 * pages can fall inside the K-10 destination set.  Each
			 * live CPU's own DPCPU area is a separate
			 * kmem_malloc_domainset() allocation, disjoint from the
			 * shared template and from every other CPU's own area, so
			 * each is walked independently via DPCPU_START/DPCPU_SIZE
			 * from the CPU's own pc_dynamic base.  copy_leaf is true:
			 * this is live resume-kernel state (et_hw_mtx, the
			 * scheduler's own tdq_lock/run queue, timer bookkeeping)
			 * every live CPU keeps using for the remainder of this
			 * boot, not saved-image content worth restoring.
			 */
			vm_offset_t dpcpu_va, dpcpu_end;
			u_int dp_cpu;

			CPU_FOREACH(dp_cpu) {
				struct pcpu *dp_pc = pcpu_find(dp_cpu);
				if (dp_pc == NULL)
					return (EINVAL);
				dpcpu_va = trunc_page((vm_offset_t)
				    (dp_pc->pc_dynamic + DPCPU_START));
				dpcpu_end = dpcpu_va + DPCPU_SIZE;
				for (; dpcpu_va < dpcpu_end;
				    dpcpu_va += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    dpcpu_va, true, &selfcopied);
					if (error != 0)
						break;
				}
				if (error != 0)
					break;
			}
		}
		if (error == 0) {
			/*
			 * this comment
			 * previously argued for copy_leaf=false ("Corrected
			 * disposition, matching vm_page_array's own precedent
			 * exactly"), but the CODE below has always passed
			 * copy_leaf=true -- round 43's own verdict reverted to
			 * true after its own direct testing found BOTH values
			 * reproduce failures (true: the original "Bad link
			 * elm"/"not owned" variants; false: the SAME eventual
			 * failures PLUS a new cross-CPU hang in configtimer()),
			 * and explicitly restored true "as the safest known-
			 * good configuration ... with no evidence it is worse
			 * than any alternative tried." That revert was never
			 * reflected back into this comment, leaving code and
			 * comment contradicting each other; this corrects that
			 * omission.
			 *
			 * copy_leaf=true is correct, for a reason round 43 did
			 * not yet have: round 44's own
			 * sleepq_hibernate_reinit_chains()/
			 * turnstile_hibernate_reinit_chains()/
			 * callout_cpu_hibernate_reinit_chains() (sys/kern/
			 * subr_sleepqueue.c, subr_turnstile.c, kern_timeout.c;
			 * called from sys/dev/acpica/acpi.c, strictly before
			 * any sleep/lock-contention/callout operation this
			 * continuation performs) now unconditionally
			 * REINITIALIZES every CPU's own cc_callwheel bucket
			 * LIST_HEADs and cc_lock before anything can observe
			 * them, superseding this array's own copy_leaf debate
			 * entirely: whichever content the self-copy walk below
			 * admits for this leaf is overwritten before any code
			 * reads it, so copy_leaf's value cannot affect final
			 * correctness either way. Of the two, true remains the
			 * better choice even for the narrow window before that
			 * reinit runs: a fresh-boot, all-empty bucket (true)
			 * can never reference a now-dead saved-image thread's
			 * identity, whereas a saved-image bucket (false) could
			 * -- the exact defect class round 44 root-caused.
			 * Round 42's own cc_lock/cc_cpu DPCPU fix (the loop
			 * immediately above) remains correct and unchanged:
			 * that per-CPU hardware/lock state IS boot-instance-
			 * specific and must stay copy_leaf=true; only this
			 * array's own CONTENT disposition was ever in question,
			 * and it is now moot in practice thanks to round 44's
			 * reinit, with true remaining the defensible choice
			 * regardless.
			 */
			u_int cw_cpu;

			CPU_FOREACH(cw_cpu) {
				uintptr_t cw_va;
				size_t cw_len;
				vm_offset_t cw_pg, cw_end;

				callout_cpu_hibernate_selfcopy_range(cw_cpu,
				    &cw_va, &cw_len);
				if (cw_va == 0)
					continue;
				cw_pg = trunc_page((vm_offset_t)cw_va);
				cw_end = round_page((vm_offset_t)cw_va +
				    cw_len);
				for (; cw_pg < cw_end && error == 0;
				    cw_pg += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    cw_pg, true, &selfcopied);
				if (error != 0)
					break;
			}
		}
		if (error == 0) {
			/*
			 * dpcpu_off[]/cpuid_to_pcpu[]: the two BSS-global lookup
			 * tables the per-CPU DPCPU protection above does not
			 * cover, found by live register capture of a genuine,
			 * reproducible hang: CPU0 stuck spinning forever inside
			 * configtimer()'s own restart: loop, which resolves every
			 * other live CPU's own DPCPU_ID_PTR() -- expanding to
			 * dpcpu_off[cpu] as its base -- while CPU1 (the AP) was
			 * simultaneously observed genuinely idle, having already
			 * cleared its own action flag.  If the K-10 copy
			 * overwrites dpcpu_off[]/cpuid_to_pcpu[] with the saved
			 * image's own (different-boot) offsets, CPU0 computes the
			 * wrong physical address for CPU1's action/handle flags,
			 * spinning on memory that is never CPU1's own live
			 * pcpu_state.  copy_leaf is true for both: these are this
			 * boot's own, already-correct lookup tables, populated
			 * once at cold SMP bring-up and read continuously by
			 * every CPU_FOREACH/IPI caller thereafter.
			 */
			vm_offset_t tbl_va, tbl_end;

			tbl_va = trunc_page((vm_offset_t)dpcpu_off);
			tbl_end = round_page((vm_offset_t)dpcpu_off +
			    sizeof(dpcpu_off[0]) * MAXCPU);
			for (; tbl_va < tbl_end && error == 0;
			    tbl_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, tbl_va, true,
				    &selfcopied);
			if (error == 0) {
				tbl_va = trunc_page(
				    (vm_offset_t)cpuid_to_pcpu);
				tbl_end = round_page(
				    (vm_offset_t)cpuid_to_pcpu +
				    sizeof(cpuid_to_pcpu[0]) * MAXCPU);
				for (; tbl_va < tbl_end && error == 0;
				    tbl_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    tbl_va, true, &selfcopied);
			}
		}
		if (error == 0) {
			/*
			 * vm_dom[] (sys/vm/vm_page.c), the per-NUMA-domain array
			 * whose vmd_pagequeues[] embed each struct vm_pagequeue's
			 * own pq_pl (TAILQ_HEAD).  Found after the DPCPU fix above
			 * resolved the configtimer() panic on three consecutive
			 * fresh runs, exposing a new, perfectly deterministic
			 * panic further downstream: vm_pageout_init_scan()'s own
			 * TAILQ_INSERT into pq->pq_pl trips "Bad link elm ...
			 * next->prev != elm" -- the exact signature of a TAILQ
			 * whose prev/next pointers were overwritten by the K-10
			 * destructive copy with the saved image's own vm_dom[]
			 * snapshot, not built by this boot's own
			 * vm_page_startup().  copy_leaf is true: vm_dom's own
			 * pq_pl/pq_cnt/pq_mutex are live, in-use allocator/pageout
			 * state this boot's own vm_page_startup() already built
			 * correctly, not saved-image content worth restoring.
			 * Walked over vm_ndomains (the actual populated domain
			 * count for this boot), not the MAXMEMDOM upper bound.
			 */
			vm_offset_t vmd_va, vmd_end;
			int dom;

			for (dom = 0; dom < vm_ndomains && error == 0; dom++) {
				vmd_va = trunc_page(
				    (vm_offset_t)&vm_dom[dom]);
				vmd_end = round_page(
				    (vm_offset_t)&vm_dom[dom] +
				    sizeof(vm_dom[dom]));
				for (; vmd_va < vmd_end && error == 0;
				    vmd_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    vmd_va, true, &selfcopied);
			}
		}
		if (error == 0) {
			/*
			 * vm_phys_free_queues
			 * (sys/vm/vm_phys.c), the per-domain/per-freelist/
			 * per-pool array of struct vm_freelist, each embedding
			 * a TAILQ_HEAD of free vm_page_t's at every buddy
			 * order. Direct testing this round confirmed the
			 * sibling "page ... has object" panic
			 * (vm_page_alloc_check(), reached via
			 * vm_page_alloc_noobj_domain() allocating a page it
			 * believes free) recurs even after vm_page_array
			 * (round 59) and hs_src/hs_aux's own vr_pages arrays
			 * (this round, above) are both already correctly
			 * protected -- this is the remaining, genuinely
			 * authoritative source vm_phys_alloc_freelist_pages()/
			 * vm_page_alloc_noobj_domain() actually consult to find
			 * a "free" page in the first place: if THIS boot's own
			 * free-page accounting (built correctly at this boot's
			 * own vm_page_startup()) is overwritten by the K-10
			 * copy with the SAVED kernel's own, unrelated free-list
			 * snapshot, the allocator can be handed a vm_page_t
			 * that this boot never actually freed (and whose own,
			 * correctly-reinitialized vm_page_t.object/ref_count/
			 * a.queue fields -- round 59's own fix -- therefore
			 * still reflect genuine, in-use content), tripping
			 * exactly the observed assertion. Same bug class as
			 * vm_dom[]/tdq/sleepq_chains[] above: ordinary BSS
			 * global, live allocator state this boot's own startup
			 * already built correctly, never previously added to
			 * this file's protected-VA set. copy_leaf is true:
			 * there is no saved-image free-list content worth
			 * restoring, since a resume-kernel's own free-page
			 * population bears no relationship to the save-kernel's
			 * own (identical reasoning to vm_dom[]). The array is
			 * file-static in sys/vm/vm_phys.c, so its VA/size come
			 * from a narrow accessor there
			 * (hibernate_md_vm_phys_free_queues_va()), matching this
			 * file's own existing convention for such cross-file
			 * hibernate accessors.
			 */
			extern void hibernate_md_vm_phys_free_queues_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t vpfq_raw, vpfq_va, vpfq_end;
			size_t vpfq_len;

			hibernate_md_vm_phys_free_queues_va(&vpfq_raw, &vpfq_len);
			vpfq_va = trunc_page(vpfq_raw);
			vpfq_end = round_page(vpfq_raw + vpfq_len);
			for (; vpfq_va < vpfq_end && error == 0;
			    vpfq_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, vpfq_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * vm_reserv_array
			 * (sys/vm/vm_reserv.c), the per-superpage reservation
			 * array -- functionally parallel to vm_page_array
			 * (round 59) and allocated the same way (a single,
			 * large, file-static mapping established once at
			 * boot by vm_reserv_startup(), never reallocated).
			 * Confirmed by direct inspection this round to be the
			 * ONE sibling structure in this class (vm_page_array,
			 * vm_dom[], vm_phys_free_queues, all already protected
			 * above) that had NO self-copy protection of its own
			 * anywhere in this file -- every other structure
			 * vm_phys_alloc_pages()'s own call chain can reach was
			 * already covered; this one was not.
			 *
			 * Each struct vm_reserv embeds its own "object"
			 * (vm_object_t) and "popcnt" fields identifying which
			 * object currently owns that reservation's pages, read
			 * by vm_reserv_to_superpage()/vm_reserv_from_page() and
			 * the reservation-level allocation/reclaim paths. If
			 * the K-10 copy overwrites this array with the SAVED
			 * kernel's own, unrelated reservation snapshot, these
			 * per-reservation object/popcnt fields can disagree
			 * with vm_page_array's own (round 59, already correct)
			 * per-page object/ref_count/queue fields -- the same
			 * disagreement-between-siblings shape as every other
			 * defect in this class, just not yet proven to fire
			 * through this exact field (the observed "page ...
			 * has object" panic's own call chain,
			 * vm_page_alloc_noobj_domain() via
			 * pmap_alloc_pt_page()/pmap_growkernel(), does not
			 * itself branch through vm_reserv in the ordinary,
			 * non-VM_NRESERVLEVEL-reclaim case -- this fix closes
			 * the one remaining unprotected sibling structure in
			 * this class regardless, since an allocator-consulted,
			 * file-static, cross-boot-stale array is exactly the
			 * established defect shape this epic has repeatedly
			 * found and fixed, and leaving the sole unprotected
			 * instance in place is not a sound resting point).
			 *
			 * copy_leaf is true: this boot's own cold
			 * vm_reserv_startup() already built every reservation
			 * correctly (every "object" field NULL, every "popcnt"
			 * zero, matching this boot's own, genuinely-empty
			 * reservation state at this early point in the resume
			 * continuation); there is no saved-image reservation
			 * content worth restoring, since a resume-kernel's own
			 * reservation population bears no relationship to the
			 * save-kernel's own -- identical reasoning to
			 * vm_dom[]/vm_phys_free_queues above. The array is
			 * file-static in sys/vm/vm_reserv.c, so its VA/size
			 * come from a narrow accessor there
			 * (hibernate_md_vm_reserv_array_va()), matching this
			 * file's own existing convention for every other such
			 * cross-file hibernate accessor.
			 */
			extern void hibernate_md_vm_reserv_array_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t vra_raw, vra_va, vra_end;
			size_t vra_len;

			hibernate_md_vm_reserv_array_va(&vra_raw, &vra_len);
			vra_va = trunc_page(vra_raw);
			vra_end = round_page(vra_raw + vra_len);
			for (; vra_va < vra_end && error == 0;
			    vra_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, vra_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * vm_phys_segs[] (sys/vm/vm_phys.c), the
			 * per-segment physical-memory descriptor array --
			 * functionally parallel to vm_phys_free_queues and
			 * vm_reserv_array (both already protected above) and
			 * read by the identical allocator call chain
			 * (vm_phys_alloc_freelist_pages() via
			 * vm_phys_paddr_to_seg()/PHYS_TO_VM_PAGE()) that the
			 * "page ... has object"/"uma-wrong-zone"/"refcount
			 * ... wraparound" family of panics all trace to
			 * (acpi_pwr_register_consumer() -> malloc() ->
			 * zone_import() -> keg_alloc_slab() ->
			 * uma_small_alloc() -> vm_page_alloc_noobj_domain()).
			 * Confirmed by direct grep this round: unlike its two
			 * siblings, vm_phys_segs[] had NO self-copy
			 * protection anywhere in this file before this fix --
			 * each struct vm_phys_seg's own first_page/
			 * free_queues/domain fields are exactly the kind of
			 * allocator-consulted, cold-boot-correct,
			 * cross-boot-stale content this epic's established
			 * rule already covers for every sibling structure.
			 * copy_leaf is true: this boot's own vm_phys_init()/
			 * vm_phys_add_seg() already built every segment
			 * descriptor correctly; there is no saved-image
			 * content worth restoring, identical reasoning to
			 * vm_phys_free_queues/vm_reserv_array. The array is
			 * file-static in sys/vm/vm_phys.c, so its VA/size come
			 * from a narrow accessor there
			 * (hibernate_md_vm_phys_segs_va()), matching this
			 * file's own existing convention for every other such
			 * cross-file hibernate accessor.
			 */
			extern void hibernate_md_vm_phys_segs_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t vps_raw, vps_va, vps_end;
			size_t vps_len;

			hibernate_md_vm_phys_segs_va(&vps_raw, &vps_len);
			vps_va = trunc_page(vps_raw);
			vps_end = round_page(vps_raw + vps_len);
			for (; vps_va < vps_end && error == 0;
			    vps_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, vps_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * vm_rvd[] (sys/vm/
			 * vm_reserv.c), the per-domain reservation-queue
			 * lock/partpop-list/scan-marker array -- sibling to
			 * vm_reserv_array above, same disposition and
			 * reasoning. See sys/vm/vm_reserv.c for the full
			 * comment.
			 */
			extern void hibernate_md_vm_rvd_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t rvd_raw, rvd_va, rvd_end;
			size_t rvd_len;

			hibernate_md_vm_rvd_va(&rvd_raw, &rvd_len);
			rvd_va = trunc_page(rvd_raw);
			rvd_end = round_page(rvd_raw + rvd_len);
			for (; rvd_va < rvd_end && error == 0;
			    rvd_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, rvd_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * vm_reserv_object_mtx[]
			 * (sys/vm/vm_reserv.c), the hashed per-object lock
			 * array -- sibling to vm_rvd[] above, same
			 * disposition. See sys/vm/vm_reserv.c for the full
			 * comment.
			 */
			extern void hibernate_md_vm_reserv_object_mtx_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t vrom_raw, vrom_va, vrom_end;
			size_t vrom_len;

			hibernate_md_vm_reserv_object_mtx_va(&vrom_raw,
			    &vrom_len);
			vrom_va = trunc_page(vrom_raw);
			vrom_end = round_page(vrom_raw + vrom_len);
			for (; vrom_va < vrom_end && error == 0;
			    vrom_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, vrom_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * vm_domainset_lock plus
			 * the domain-state fields it protects (sys/vm/
			 * vm_page.c). See sys/vm/vm_page.c for the full
			 * comment.
			 */
			extern void hibernate_md_vm_domainset_lock_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t vdl_raw, vdl_va, vdl_end;
			size_t vdl_len;

			hibernate_md_vm_domainset_lock_va(&vdl_raw, &vdl_len);
			vdl_va = trunc_page(vdl_raw);
			vdl_end = round_page(vdl_raw + vdl_len);
			for (; vdl_va < vdl_end && error == 0;
			    vdl_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, vdl_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * sleepq_chains[SC_TABLESIZE] (sys/kern/subr_sleepqueue.c)
			 * is live, continuously-read-and-written kernel lock/queue
			 * state this boot's own init_sleepqueues() already built
			 * correctly at startup, never previously added to this
			 * file's protected-VA set.  copy_leaf is true: this boot's
			 * own sc_lock must be unlocked (or correctly held by this
			 * boot's own thread) exactly as this boot's own SYSINIT
			 * left it; there is no saved-image sleepq_chains content
			 * worth restoring, since a resume kernel's own sleeping-
			 * thread population is necessarily different from the
			 * save kernel's own.  This self-copy protects the page-
			 * table path; the content itself is independently
			 * reinitialised at resume time
			 * (sleepq_hibernate_reinit_chains(), sys/dev/acpica/acpi.c).
			 */
			uintptr_t sq_va;
			size_t sq_len;
			vm_offset_t sq_pg, sq_end;

			sleepq_hibernate_selfcopy_range(&sq_va, &sq_len);
			sq_pg = trunc_page((vm_offset_t)sq_va);
			sq_end = round_page((vm_offset_t)sq_va + sq_len);
			for (; sq_pg < sq_end && error == 0;
			    sq_pg += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, sq_pg, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * turnstile_chains[TC_TABLESIZE]
			 * (sys/kern/subr_turnstile.c) is the identical bug shape
			 * as sleepq_chains[] above: priority-propagating lock
			 * contention is reached from numerous points in this
			 * continuation, including inside DEVICE_RESUME(root_bus)'s
			 * own driver resume callbacks.  copy_leaf is true, same
			 * rule as sleepq_chains[] above; content is independently
			 * reinitialised at resume time
			 * (turnstile_hibernate_reinit_chains(), sys/dev/acpica/
			 * acpi.c).
			 */
			uintptr_t ts_va;
			size_t ts_len;
			vm_offset_t ts_pg, ts_end;

			turnstile_hibernate_selfcopy_range(&ts_va, &ts_len);
			ts_pg = trunc_page((vm_offset_t)ts_va);
			ts_end = round_page((vm_offset_t)ts_va + ts_len);
			for (; ts_pg < ts_end && error == 0;
			    ts_pg += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, ts_pg, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * w_mtx (sys/kern/subr_witness.c) is the single spin mutex
			 * protecting WITNESS's own lock-order graph, acquired by
			 * witness_checkorder()/witness_lock() on every mtx/sx lock
			 * acquire anywhere in the kernel -- active for literally
			 * every lock operation this entire continuation performs,
			 * from acpi_s4_resume_bsp_cpu() through
			 * DEVICE_RESUME(root_bus) and beyond.  Same exposure class
			 * as sleepq_chains/turnstile_chains above: an ordinary
			 * struct mtx whose raw mtx_lock owner-pointer field, if
			 * overwritten by the K-10 copy with the saved image's own
			 * byte content, would corrupt every subsequent lock/unlock
			 * this boot performs through witness's own checking path.
			 * copy_leaf is true: this boot's own w_mtx must be unlocked
			 * (or correctly held) exactly as this boot's own
			 * witness_initialize() left it; the saved image's own
			 * witness lock state belongs to a different boot's own
			 * lock-order graph and is meaningless here.
			 */
			uintptr_t wm_va;
			size_t wm_len;
			vm_offset_t wm_pg, wm_end;

			witness_hibernate_selfcopy_range(&wm_va, &wm_len);
			wm_pg = trunc_page((vm_offset_t)wm_va);
			wm_end = round_page((vm_offset_t)wm_va + wm_len);
			for (; wm_pg < wm_end && error == 0;
			    wm_pg += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, wm_pg, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 *
			 * eventhandler_lists/eventhandler_mutex/
			 * eventhandler_lists_initted (sys/kern/
			 * subr_eventhandler.c) -- confirmed by direct, live
			 * backtrace capture to be the exact, sole remaining
			 * blocker to DEVICE_RESUME(root_bus): the
			 * acpi_pre_dev_resume EVENTHANDLER_INVOKE()
			 * immediately preceding it faults in
			 * eventhandler_find_list(). See
			 * sys/kern/subr_eventhandler.c for the full comment.
			 */
			extern void hibernate_md_eventhandler_lists_va(
			    vm_offset_t *va, size_t *len);
			extern void hibernate_md_eventhandler_mutex_va(
			    vm_offset_t *va, size_t *len);
			extern void hibernate_md_eventhandler_lists_initted_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t eh_raw, eh_va, eh_end;
			size_t eh_len;

			hibernate_md_eventhandler_lists_va(&eh_raw, &eh_len);
			eh_va = trunc_page(eh_raw);
			eh_end = round_page(eh_raw + eh_len);
			for (; eh_va < eh_end && error == 0;
			    eh_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, eh_va, true,
				    &selfcopied);
			if (error == 0) {
				hibernate_md_eventhandler_mutex_va(&eh_raw,
				    &eh_len);
				eh_va = trunc_page(eh_raw);
				eh_end = round_page(eh_raw + eh_len);
				for (; eh_va < eh_end && error == 0;
				    eh_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha, wvec,
					    p, kernel_pmap->pm_cr3, eh_va, true,
					    &selfcopied);
			}
			if (error == 0) {
				hibernate_md_eventhandler_lists_initted_va(
				    &eh_raw, &eh_len);
				eh_va = trunc_page(eh_raw);
				eh_end = round_page(eh_raw + eh_len);
				for (; eh_va < eh_end && error == 0;
				    eh_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha, wvec,
					    p, kernel_pmap->pm_cr3, eh_va, true,
					    &selfcopied);
			}
			/*
			 *
			 * per this round's own explicit instruction, every
			 * structure this subsystem's resume-path consumers
			 * touch was enumerated once, not rediscovered by
			 * panic. The STATIC head (above) is a BSS global this
			 * boot's own eventhandler_init() SYSINIT already
			 * builds correctly -- the "adopt this boot's fresh
			 * content" rule applies, matching every sibling. But
			 * EVERY struct eventhandler_list node AND every struct
			 * eventhandler_entry node hanging off it is a SEPARATE
			 * malloc(M_EVENTHANDLER) allocation this boot's own
			 * EVENTHANDLER_REGISTER()/_LIST_DEFINE() calls make
			 * during ordinary SYSINIT device-attach processing,
			 * BEFORE the hibernate ioctl ever runs -- this is LIVE
			 * RESUME-KERNEL STATE by this epic's own established
			 * rule (continuously read-and-written, this boot's
			 * own, never the saved image's), not saved-image
			 * content, exactly like sleepq_chains[]'s own
			 * per-bucket LIST_HEAD entries. Unlike a fixed-size
			 * static array, these nodes' OWN addresses are chosen
			 * fresh each boot by the allocator and cannot be named
			 * by one fixed VA/len pair; they must be discovered by
			 * walking the (already-protected) list head and its
			 * own entries, protecting each node found. This is
			 * what was missing: the head was protected, but the
			 * nodes reachable from it were not, so the K-10 copy
			 * could still overwrite an eventhandler_list/
			 * eventhandler_entry node's own backing page with the
			 * SAVE kernel's own unrelated content -- a direct
			 * explanation for eventhandler_find_list()'s own
			 * strcmp() GPF (a node's el_name pointer, or the bytes
			 * it points to, reading as foreign/poisoned content).
			 */
			if (error == 0) {
				extern int
				eventhandler_hibernate_selfcopy_nodes(
				    const struct hibernate_attempt *ha,
				    vm_paddr_t *wvec, uint64_t p,
				    u_int *countp);
				error = eventhandler_hibernate_selfcopy_nodes(
				    ha, wvec, p, &selfcopied);
			}
		}
		if (error == 0) {
			/*
			 *
			 * event_list/event_lock (sys/kern/kern_intr.c) --
			 * the static registry every struct intr_event is
			 * linked onto -- and every intr_event/intr_handler
			 * node reachable from it. Confirmed by live capture
			 * (round 15/16, five independent runs) to be the
			 * exact, previously-misclassified gap: round 16's
			 * own sweep wrongly concluded "no unprotected static
			 * global reachable" because it looked only at the
			 * immediate call chain into intr_event_resume_
			 * handler(), not at the registry these nodes are
			 * THEMSELVES linked onto at creation time. See
			 * sys/kern/kern_intr.c for the full corrected
			 * classification argument.
			 */
			extern void hibernate_md_intr_event_list_va(
			    vm_offset_t *va, size_t *len);
			extern void hibernate_md_intr_event_lock_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t ie_raw, ie_va, ie_end;
			size_t ie_len;

			hibernate_md_intr_event_list_va(&ie_raw, &ie_len);
			ie_va = trunc_page(ie_raw);
			ie_end = round_page(ie_raw + ie_len);
			for (; ie_va < ie_end && error == 0;
			    ie_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, ie_va, true,
				    &selfcopied);
			if (error == 0) {
				hibernate_md_intr_event_lock_va(&ie_raw,
				    &ie_len);
				ie_va = trunc_page(ie_raw);
				ie_end = round_page(ie_raw + ie_len);
				for (; ie_va < ie_end && error == 0;
				    ie_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    ie_va, true, &selfcopied);
			}
			if (error == 0) {
				extern int
				intr_event_hibernate_selfcopy_nodes(
				    const struct hibernate_attempt *ha,
				    vm_paddr_t *wvec, uint64_t p,
				    u_int *countp);
				error = intr_event_hibernate_selfcopy_nodes(
				    ha, wvec, p, &selfcopied);
			}
		}
		if (error == 0) {
			/*
			 *
			 * rman_head/rman_mtx (sys/kern/subr_rman.c) -- the
			 * static registry every struct rman (irq_rman et al)
			 * is linked onto -- and every struct resource_i node
			 * (including shared-allocation siblings reachable
			 * only via r_sharehead) reachable from it. This is
			 * the upstream source of the r_irq_cookie value
			 * nexus_resume_intr() passes into the (already
			 * protected, above) intr_event graph: live capture
			 * (hardware breakpoint on intr_event_resume_
			 * handler(), this round) proved the intr_event
			 * protection alone was insufficient because THIS
			 * node -- not the intr_event graph -- was the one
			 * left holding the SAVE kernel's own stale content.
			 * See sys/kern/subr_rman.c for the full argument.
			 */
			extern void hibernate_md_rman_head_va(
			    vm_offset_t *va, size_t *len);
			extern void hibernate_md_rman_mtx_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t rm_raw, rm_va, rm_end;
			size_t rm_len;

			hibernate_md_rman_head_va(&rm_raw, &rm_len);
			rm_va = trunc_page(rm_raw);
			rm_end = round_page(rm_raw + rm_len);
			for (; rm_va < rm_end && error == 0;
			    rm_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, rm_va, true,
				    &selfcopied);
			if (error == 0) {
				hibernate_md_rman_mtx_va(&rm_raw, &rm_len);
				rm_va = trunc_page(rm_raw);
				rm_end = round_page(rm_raw + rm_len);
				for (; rm_va < rm_end && error == 0;
				    rm_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    rm_va, true, &selfcopied);
			}
			if (error == 0) {
				extern int
				rman_hibernate_selfcopy_nodes(
				    const struct hibernate_attempt *ha,
				    vm_paddr_t *wvec, uint64_t p,
				    u_int *countp);
				error = rman_hibernate_selfcopy_nodes(
				    ha, wvec, p, &selfcopied);
			}
		}
		if (error == 0) {
			/*
			 * pci_powerstate_
			 * sxlock (sys/dev/acpica/acpi_pci.c) is
			 * ACPI_SERIAL_BEGIN()'d as the FIRST statement of
			 * acpi_pci_set_powerstate_method() -- the exact
			 * function one stack frame above
			 * acpi_pwr_switch_consumer() in every captured
			 * GPF/tailq-corruption backtrace this epic has ever
			 * recorded for this defect, reached BEFORE
			 * powerres_sxlock (below) is ever touched. Never
			 * previously protected. See
			 * sys/dev/acpica/acpi_pci.c for the full comment.
			 */
			extern void hibernate_md_pci_powerstate_sxlock_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t pps_raw, pps_va, pps_end;
			size_t pps_len;

			hibernate_md_pci_powerstate_sxlock_va(&pps_raw,
			    &pps_len);
			pps_va = trunc_page(pps_raw);
			pps_end = round_page(pps_raw + pps_len);
			for (; pps_va < pps_end && error == 0;
			    pps_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, pps_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * powerres_sxlock (the
			 * ACPI_SERIAL_DECL()-expanded sx this file's own
			 * acpi_pwr_switch_consumer() locks as its FIRST
			 * statement) was never added to this file's own
			 * protected set, confirmed by live capture to be the
			 * exact site: GPF at acpi_pwr_switch_consumer+0x80 on
			 * function entry, even after both TAILQ heads and
			 * every node reachable from them (below) were already
			 * protected. See sys/dev/acpica/acpi_powerres.c for
			 * the full comment.
			 */
			extern void hibernate_md_acpi_powerres_sxlock_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t sx_raw, sx_va, sx_end;
			size_t sx_len;

			hibernate_md_acpi_powerres_sxlock_va(&sx_raw, &sx_len);
			sx_va = trunc_page(sx_raw);
			sx_end = round_page(sx_raw + sx_len);
			for (; sx_va < sx_end && error == 0;
			    sx_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, sx_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 *
			 * acpi_powerresources/acpi_powerconsumers
			 * (sys/dev/acpica/acpi_powerres.c) -- confirmed by
			 * direct, live backtrace capture to be reached and
			 * corrupted during the FIRST confirmed
			 * DEVICE_RESUME(root_bus) execution reached in this
			 * epic's entire history (acpi_pwr_switch_consumer()'s
			 * own %%rbx == 0xdeadc0dedeadc0de). See
			 * sys/dev/acpica/acpi_powerres.c for the full comment.
			 */
			extern void hibernate_md_acpi_powerresources_va(
			    vm_offset_t *va, size_t *len);
			extern void hibernate_md_acpi_powerconsumers_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t pr_raw, pr_va, pr_end;
			size_t pr_len;

			hibernate_md_acpi_powerresources_va(&pr_raw, &pr_len);
			pr_va = trunc_page(pr_raw);
			pr_end = round_page(pr_raw + pr_len);
			for (; pr_va < pr_end && error == 0;
			    pr_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, pr_va, true,
				    &selfcopied);
			if (error == 0) {
				hibernate_md_acpi_powerconsumers_va(&pr_raw,
				    &pr_len);
				pr_va = trunc_page(pr_raw);
				pr_end = round_page(pr_raw + pr_len);
				for (; pr_va < pr_end && error == 0;
				    pr_va += PAGE_SIZE)
					error = hibernate_md_selfcopy_walk(ha, wvec,
					    p, kernel_pmap->pm_cr3, pr_va, true,
					    &selfcopied);
			}
			/*
			 * per this round's own instruction ("check
			 * whether the ENTRIES need the do-not-free/protect
			 * disposition rather than the heads"), the two static
			 * TAILQ HEADS above are correctly protected (live BSS
			 * globals, ordinary rule), but every struct
			 * acpi_powerresource/acpi_powerconsumer/
			 * acpi_powerreference node reachable from them is a
			 * SEPARATE malloc(M_ACPIPWR) allocation this boot's
			 * own ACPI namespace walk (acpi_pwr_register_resource/
			 * _consumer(), acpi_pwr_reference_resource(), this
			 * file) performs during ordinary device-attach
			 * processing, before any hibernate ioctl -- LIVE
			 * RESUME-KERNEL STATE by the same rule as the
			 * eventhandler nodes above, never the saved image's.
			 * Confirmed by direct source reading: every
			 * acpi_powerreference is reachable from its OWN
			 * consumer's ac_references TAILQ (ar_clink), so
			 * walking consumers alone reaches every reference
			 * node transitively; walking resources separately
			 * would revisit the same reference nodes a second
			 * time, not reach any node the consumer walk misses.
			 */
			if (error == 0) {
				extern int
				acpi_powerres_hibernate_selfcopy_nodes(
				    const struct hibernate_attempt *ha,
				    vm_paddr_t *wvec, uint64_t p,
				    u_int *countp);
				error = acpi_powerres_hibernate_selfcopy_nodes(
				    ha, wvec, p, &selfcopied);
			}

			/*
			 * struct
			 * acpi_pci_devinfo's own ap_handle field (sys/dev/
			 * acpica/acpi_pci.c) is a SEPARATE malloc(M_DEVBUF)
			 * allocation this boot's own cold PCI bus scan
			 * performs during ordinary device-attach processing
			 * (acpi_pci_alloc_devinfo()/acpi_pci_save_handle())
			 * -- LIVE RESUME-KERNEL STATE by the same rule just
			 * applied to the ACPI power-resource nodes above, but
			 * never swept here because it lives in a different
			 * file and is reached via a different call path
			 * (acpi_get_handle(child) inside
			 * acpi_pci_set_powerstate_method(), not the TAILQ-
			 * based power-resource lists). Confirmed by direct
			 * live capture this round: acpi_get_handle(child)
			 * returned a handle AcpiGetType() rejected immediately
			 * (AE_BAD_PARAMETER) on its very first post-resume use,
			 * for device hostb0, whose own acpi_pci_devinfo the
			 * K-10 copy's destination set evidently still
			 * overlapped. copy_leaf is true: this boot's own cold
			 * PCI scan already populated ap_handle correctly from
			 * its own, live ACPI namespace; there is no
			 * saved-image content worth restoring.
			 */
			if (error == 0) {
				extern int
				acpi_pci_hibernate_selfcopy_devinfo(
				    const struct hibernate_attempt *ha,
				    vm_paddr_t *wvec, uint64_t p,
				    u_int *countp);
				error = acpi_pci_hibernate_selfcopy_devinfo(
				    ha, wvec, p, &selfcopied);
			}
			/*
			 * install the
			 * SAVE-SIDE __stack_chk_guard[0] into the live global,
			 * the opposite disposition from every self-copy
			 * protect call above.  Root-caused this round with
			 * side-by-side evidence, not inference: at
			 * __stack_chk_fail() in sched_ule_switch()'s own
			 * frame, the canary slot sched_ule_switch()'s own
			 * prologue stored at function entry
			 * (-0x30(%rbp), confirmed by direct objdump of this
			 * build's own kernel.full) equals the IMAGE's own
			 * __stack_chk_guard[0] (read directly from the
			 * on-disk ABI 1 image's own PT_LOAD payload at the
			 * physical address the LIVE resume kernel's own page
			 * tables resolve for __stack_chk_guard's VA -- not
			 * inferred, cross-checked byte-for-byte across
			 * multiple independent captures), while the LIVE
			 * global __stack_chk_guard[0] is a DIFFERENT value
			 * every capture (each boot's own fresh SI_SUB_RANDOM
			 * arc4rand() reseed, confirmed by
			 * __stack_chk_init()'s own SYSINIT ordering, which
			 * runs again on this resume kernel's OWN cold boot,
			 * before any hibernate resume logic executes).  The
			 * faulting thread in every capture is this CPU's own
			 * BSP idle thread (pid 11 tid 100003, confirmed by
			 * the KDB "[ thread pid ... ]" banner in every
			 * capture) -- its kstack is a genuine K-10
			 * destination-set page (the dormant frame Residual 1
			 * already named as unreseedable), so its existing
			 * stack frame's canary was computed with the SAVE
			 * kernel's own guard value and is restored verbatim
			 * by the destructive copy, but the comparison it is
			 * later checked against uses whichever
			 * __stack_chk_guard this resume kernel's own cold
			 * boot happened to generate -- a genuine two-kernel
			 * value conflict, not a self-inflicted "compare value
			 * X against itself" no-op (the prior, already-
			 * reverted "generalized guard-reconcile" attempt
			 * read/wrote the SAME resume-kernel global on both
			 * sides of its own comparison, which is why it
			 * measured no effect).
			 *
			 * copy_leaf is explicitly false here: unlike ap_handle
			 * or the power-resource nodes (this boot's own cold-
			 * attach state, correctly preserved), the correct
			 * value for a dormant, image-restored thread frame to
			 * compare against is the image's OWN frozen guard,
			 * since that frame's own canary was computed under
			 * that value and will never be re-stored before this
			 * thread's own cpu_switch() epilogue checks it.  This
			 * mirrors saved_pcb_va/the suspended kstack's own
			 * "content must be the save-time captured bytes" rule
			 * immediately below, not the copy_leaf=true rule.
			 *
			 * Read via hibernate_md_staged_read() (the existing,
			 * already-proven staged-byte accessor used by the
			 * K-10 copy loop itself), at MD_PREPARE time, strictly
			 * before the destructive copy runs, so the read
			 * itself takes no lock and calls nothing that could
			 * (same safety class as every other MD_PREPARE sweep
			 * on this path).  A read failure (ENOENT: the guard's
			 * own page is not resolvable in the staged image,
			 * e.g. an all-RAM hibernate where the page genuinely
			 * is not part of any destination run) is treated as a
			 * silent no-op, not a hard error -- the live value is
			 * then left exactly as this resume kernel's own cold
			 * boot set it, the pre-existing, already-characterized
			 * baseline behavior.
			 */
			if (error == 0) {
				/*
				 * REVERTED --
				 * installing hib_guard_image_value into
				 * the live __stack_chk_guard[0] HERE panicked
				 * hibernate_machdep_prepare() ITSELF, 3/3
				 * reproductions, deterministic
				 * (__stack_chk_fail() <- hibernate_machdep_
				 * prepare() <- hibernate_resume_attempt() <-
				 * g_hibernate_worker(), confirmed by direct
				 * backtrace capture): this function's own
				 * currently-executing C frame was compiled
				 * against the OLD live guard value at its own
				 * entry, and its own epilogue compares against
				 * whatever __stack_chk_guard holds at RETURN
				 * time -- changing the global mid-function
				 * breaks every live C frame still relying on
				 * continuity (this function's own, plus every
				 * caller up the still-executing chain:
				 * hibernate_resume_attempt(),
				 * g_hibernate_worker(), fork_exit()), not just
				 * the dormant image-restored idle thread this
				 * fix targeted.  The capture itself is proven
				 * correct (the staged value was confirmed
				 * distinct from the live global in every
				 * run) -- only the INSTALL POINT here was
				 * wrong.  This function therefore only
				 * captures and publishes the value; the
				 * install itself is done by
				 * hibernate_resume_attempt() (kern_
				 * hibernate.c), immediately before the
				 * no-return hibernate_machdep_enter()
				 * call, after every resume-kernel C frame
				 * expected to survive has already returned.
				 */
				extern long __stack_chk_guard[8];

				/*
				 * Publish to the file-scope globals for
				 * hibernate_resume_attempt() to install
				 * AFTER this function has returned (see the
				 * function-scope declaration's own comment
				 * above for why installing HERE panicked
				 * this function's own frame, reproduced
				 * 3/3).  No write to __stack_chk_guard in
				 * this function.
				 */
				hib_guard_image_value_g =
				    hib_guard_image_value;
				hib_guard_captured_g = hib_guard_captured;
			}		}
		if (error == 0) {
			/*
			 * The save-side hcb allocation (sys/kern/kern_dump.c) is a
			 * large, dynamically-sized kmem_malloc()-backed allocation
			 * whose own page-table path was never added to this
			 * protected-VA set.  Confirmed by direct QMP register
			 * capture: a page fault at a kmem-range VA (outside DMAP)
			 * inside dumpsys_hibernate_free_hcb() on the resume path.
			 * Content must be the save-time captured bytes (the
			 * reserved spare-page physical addresses
			 * dumpsys_hibernate_free_hcb() reads back on resume to
			 * release them), so copy_leaf is false here -- the same
			 * rule as saved_pcb_va/the suspended kstack above, not
			 * pc_gdt/ths[]'s copy_leaf=true.  A zero VA (no hcb was
			 * ever created this boot) is a silent no-op.
			 */
			uintptr_t hcb_va;
			size_t hcb_len;
			vm_offset_t hcb_pg, hcb_end;

			dumpsys_hibernate_selfcopy_range(&hcb_va, &hcb_len);
			if (hcb_va != 0) {
				hcb_pg = trunc_page((vm_offset_t)hcb_va);
				hcb_end = round_page((vm_offset_t)hcb_va +
				    hcb_len);
				for (; hcb_pg < hcb_end;
				    hcb_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    hcb_pg, false, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		/*
		 * pidhashtbl's own
		 * backing array (sys/kern/kern_proc.c, one hashinit() ->
		 * hashalloc() malloc() block) is staged here with
		 * copy_leaf=FALSE, correcting the previous round's
		 * copy_leaf=true attempt (reverted after a confirmed
		 * regression, see git history/evidence record). With
		 * copy_leaf=false, hibernate_md_selfcopy_walk() still
		 * self-copy-protects every PAGE-TABLE page along the walk
		 * (PML4/PDPT/PD/PT), keeping the VA range mapped and
		 * readable, but does NOT self-copy the terminal LEAF data
		 * page itself -- that page is left to participate normally
		 * in the K-10 destination-set copy, so its content becomes
		 * the IMAGE's own saved bucket-pointer bytes. This is the
		 * saved_pcb_va rule, not the sleepq_chains rule: the table
		 * the walk reads is now internally consistent BECAUSE both
		 * the pointers (now image content) and the struct proc
		 * objects they reference (already image content, via the
		 * ordinary destination-set copy) come from the SAME saved
		 * boot, rather than the live/image mismatch copy_leaf=true
		 * produced.
		 */
		if (error == 0) {
			extern struct pidhashhead *pidhashtbl;
			extern u_long pidhash;
			vm_offset_t ph_va, ph_end;

			ph_va = trunc_page((vm_offset_t)pidhashtbl);
			ph_end = round_page((vm_offset_t)pidhashtbl +
			    (pidhash + 1) * sizeof(*pidhashtbl));
			for (; ph_va < ph_end && error == 0;
			    ph_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha,
				    wvec, p, kernel_pmap->pm_cr3,
				    ph_va, false, &selfcopied);
		}
		if (error == 0) {
			/*
			 * bucket_zones[]
			 * (sys/vm/uma_core.c), the per-size cache-bucket
			 * zone descriptor table, each entry's own ubz_zone
			 * an identity pointer into this boot's own,
			 * bucket_init()-created zone. See sys/vm/uma_core.c
			 * for the full comment.
			 */
			extern void hibernate_md_bucket_zones_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t bz_raw, bz_va, bz_end;
			size_t bz_len;

			hibernate_md_bucket_zones_va(&bz_raw, &bz_len);
			bz_va = trunc_page(bz_raw);
			bz_end = round_page(bz_raw + bz_len);
			for (; bz_va < bz_end && error == 0;
			    bz_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, bz_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * kmemzones[]
			 * (sys/kern/kern_malloc.c) -- the table EVERY malloc(9)
			 * call anywhere resolves through to find its backing
			 * UMA zone. Confirmed by direct source reading to be
			 * the real, single root cause of the four previously-
			 * separate-looking symptom variants at
			 * acpi_pwr_register_consumer()'s own malloc() call.
			 * See sys/kern/kern_malloc.c for the full comment.
			 */
			extern void hibernate_md_kmemzones_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t kz_raw, kz_va, kz_end;
			size_t kz_len;

			hibernate_md_kmemzones_va(&kz_raw, &kz_len);
			kz_va = trunc_page(kz_raw);
			kz_end = round_page(kz_raw + kz_len);
			for (; kz_va < kz_end && error == 0;
			    kz_va += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, kz_va, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * kernel_object (sys/vm/vm_object.c's
			 * own kernel_object_store, extern'd as
			 * &kernel_object_store via sys/vm/vm_object.h's
			 * kernel_object macro) -- the single, statically-
			 * allocated vm_object_t every kmem-backed kernel
			 * allocation in this boot (UMA multi-page/
			 * kmem_malloc-class slabs via keg_alloc_slab() ->
			 * kmem_malloc(), and any other kmem_back()-style
			 * caller) is inserted into. Confirmed this round by
			 * a direct, instrumented capture (
			 * vm_page_alloc_check()'s own "page ... has object"
			 * panic, sys/vm/vm_page.c): obj=0xffffffff81eb31d8
			 * resolves via this binary's own symbol table to
			 * kernel_object_store exactly, with
			 * page_ref=0x80000001 (VPRC_OBJREF | one wiring),
			 * busy_lock=0x3650002 (genuinely exclusive-busy, not
			 * VPB_UNBUSIED/VPB_FREED), dirty=0, queue=PQ_NONE --
			 * every field consistent with a REAL, currently
			 * in-use, resume-kernel-own allocation, not
			 * stale/garbage content.
			 *
			 * Root cause: this is the same "ordinary BSS global,
			 * live allocator state this boot's own startup
			 * already built correctly" class already fixed for
			 * vm_dom[]/vm_phys_free_queues/vm_reserv_array/
			 * bucket_zones[] above in this same file -- but
			 * kernel_object_store itself (the struct vm_object
			 * header: its own rtree root/size/ref_count/
			 * generation fields, distinct from the PAGES that
			 * point AT it, which vm_page_array's own self-copy,
			 * round 59, already protects) was never added to
			 * this file's protected-VA set, confirmed by an
			 * exhaustive grep this round finding zero prior
			 * references. Left unprotected, the K-10 destructive
			 * copy overwrites kernel_object_store's own memory
			 * with the SAVED kernel's unrelated snapshot of that
			 * same object (a different, earlier point in that
			 * OTHER boot's own kmem history) while every
			 * vm_page_t that already points AT
			 * &kernel_object_store (a fixed address, unaffected
			 * pointer-wise) keeps its own resume-kernel-correct
			 * per-page state -- an object/page bookkeeping
			 * disagreement of exactly the same "disagreement
			 * between siblings" shape this epic already names
			 * for every other defect in this class.
			 *
			 * Disposition: REINITIALIZE (copy_leaf=true, preserve
			 * THIS boot's own already-correct content), the
			 * identical rule as vm_dom[]/vm_phys_free_queues/
			 * vm_reserv_array/bucket_zones[] above -- not "do not
			 * free" (that rule is for single SAVE-time
			 * allocations whose own identity is
			 * unreconstructable; kernel_object_store is shared,
			 * system-wide bookkeeping every future kmem
			 * allocation this boot performs legitimately depends
			 * on being correct, exactly the reasoning already
			 * established for every sibling in this class).
			 * Scope is bounded to sizeof(struct vm_object) (a
			 * small, fixed-size header, not the object's own
			 * unbounded rtree node allocations, which this round
			 * deliberately does NOT attempt to walk -- avoiding
			 * the round-30 blanket-sweep trap this epic's own
			 * established rules warn against). The object is
			 * file-static in scope here (sys/vm/vm_object.h only
			 * exposes it via the kernel_object macro, which this
			 * file does not currently pull in), so its VA/size
			 * come from a narrow accessor in sys/vm/vm_object.c
			 * (hibernate_md_kernel_object_va()), matching this
			 * file's own existing convention for such cross-file
			 * hibernate accessors
			 * (hibernate_md_vm_phys_free_queues_va(),
			 * hibernate_md_vm_reserv_array_va(), etc., above).
			 */
			extern void hibernate_md_kernel_object_va(
			    vm_offset_t *va, size_t *len);
			vm_offset_t ko_raw, ko_pg, ko_end;
			size_t ko_len;

			hibernate_md_kernel_object_va(&ko_raw, &ko_len);
			ko_pg = trunc_page(ko_raw);
			ko_end = round_page(ko_raw + ko_len);
			for (; ko_pg < ko_end && error == 0;
			    ko_pg += PAGE_SIZE)
				error = hibernate_md_selfcopy_walk(ha, wvec, p,
				    kernel_pmap->pm_cr3, ko_pg, true,
				    &selfcopied);
		}
		if (error == 0) {
			/*
			 * Device driver method-dispatch tables (struct
			 * kobj_ops).  sys/bus.h is already included above,
			 * so device_hibernate_nclasses()/
			 * device_hibernate_class_selfcopy_range()
			 * (sys/kern/subr_bus.c) are globally declared; no
			 * local extern needed.  Each attached driver
			 * class's own compiled dispatch cache is this
			 * boot's own devclass_add_driver()/
			 * kobj_class_compile() output, never the saved
			 * image's -- copy_leaf=true.
			 */
			u_int dc_n, dc_idx;

			dc_n = device_hibernate_nclasses();
			for (dc_idx = 0; dc_idx < dc_n &&
			    error == 0; dc_idx++) {
				uintptr_t dc_va;
				size_t dc_len;
				vm_offset_t dc_pg, dc_end;

				device_hibernate_class_selfcopy_range(dc_idx,
				    &dc_va, &dc_len);
				if (dc_va == 0 || dc_len == 0)
					continue;
				dc_pg = trunc_page((vm_offset_t)dc_va);
				dc_end = round_page((vm_offset_t)dc_va +
				    dc_len);
				for (; dc_pg < dc_end;
				    dc_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    dc_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * K24-T00: struct uart_class's own compiled kobj_ops
			 * dispatch cache (sys/dev/uart/uart.h,
			 * uart_hibernate_nclasses()/
			 * uart_hibernate_class_selfcopy_range()).  A
			 * separate object from the per-device_t ops caches
			 * walked just above: uart_class_set is a DATA_SET,
			 * not a devclass, and the console/debug-port
			 * uart_softc (struct uart_devinfo's own "sc", e.g.
			 * uart_dbgport in uart_dbg.c) is never attached via
			 * newbus, so it is outside bus_data_devices too.
			 * This boot's own kobj_class_compile() output,
			 * never the saved image's -- copy_leaf=true, same
			 * rule as every sibling in this class.
			 */
			extern u_int uart_hibernate_nclasses(void);
			extern void uart_hibernate_class_selfcopy_range(
			    u_int, uintptr_t *, size_t *);
			u_int uc_n, uc_idx;

			uc_n = uart_hibernate_nclasses();
			for (uc_idx = 0; uc_idx < uc_n && error == 0;
			    uc_idx++) {
				uintptr_t uc_va;
				size_t uc_len;
				vm_offset_t uc_pg, uc_end;

				uart_hibernate_class_selfcopy_range(uc_idx,
				    &uc_va, &uc_len);
				if (uc_va == 0 || uc_len == 0)
					continue;
				uc_pg = trunc_page((vm_offset_t)uc_va);
				uc_end = round_page(
				    (vm_offset_t)uc_va + uc_len);
				for (; uc_pg < uc_end; uc_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3, uc_pg,
					    true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * DSA00 "keg topology" round: capture every keg's
			 * own three per-domain slab-list HEAD pointers from
			 * the STAGED (saved) image, via hibernate_md_staged_
			 * read(), before the destructive copy below runs.
			 * This removes uma_hibernate_reinit_plinks()'s own
			 * dependency on live uk_domain[] content being the
			 * saved image's topology -- the root cause of the
			 * item #11 contradiction (confirmed prior round: that
			 * function needs the SAVED list topology to walk
			 * slabs, while keg protection forces uk_domain[] to
			 * hold the RESUME kernel's own pre-jump topology
			 * instead). Keg protection (immediately below, inside
			 * this same "if (error == 0)" chain) is UNCHANGED and
			 * STAYS: with the reinit no longer reading uk_domain[]
			 * live, there is no remaining reason to remove it, and
			 * every other keg field (uk_hash, uk_zones, uk_align,
			 * etc.) still needs this boot's own live content.
			 */
			{
				extern u_int uma_hibernate_nkegs_raw(void);
				extern void uma_hibernate_keg_domain_headvas(
				    u_int keg_idx, u_int dom,
				    vm_offset_t * part_va,
				    vm_offset_t * free_va,
				    vm_offset_t * full_va, int *is_vtoslab_keg);
				u_int topo_nkegs, topo_ki;
				int topo_dom;

				topo_nkegs = uma_hibernate_nkegs_raw();
				if (topo_nkegs > HIB_KEG_TOPO_MAX_KEGS)
					topo_nkegs = HIB_KEG_TOPO_MAX_KEGS;
				for (topo_ki = 0; topo_ki < topo_nkegs;
				    topo_ki++) {
					for (topo_dom = 0;
					    topo_dom < vm_ndomains &&
					    topo_dom < MAXMEMDOM;
					    topo_dom++) {
						vm_offset_t pva, fva, uva;
						int is_vtoslab;
						uintptr_t hv;
						int terr;

						uma_hibernate_keg_domain_headvas(
						    topo_ki, (u_int)topo_dom,
						    &pva, &fva, &uva,
						    &is_vtoslab);
						if (!is_vtoslab)
							continue;

						terr = hibernate_md_staged_read(
						    ha, wvec, p, pva, &hv,
						    sizeof(hv));
						hib_keg_topo_head_g
						    [topo_ki][topo_dom][0] =
							(terr == 0) ? hv : 0;

						terr = hibernate_md_staged_read(
						    ha, wvec, p, fva, &hv,
						    sizeof(hv));
						hib_keg_topo_head_g
						    [topo_ki][topo_dom][1] =
							(terr == 0) ? hv : 0;

						terr = hibernate_md_staged_read(
						    ha, wvec, p, uva, &hv,
						    sizeof(hv));
						hib_keg_topo_head_g
						    [topo_ki][topo_dom][2] =
							(terr == 0) ? hv : 0;
					}
				}
				hib_keg_topo_captured_n_g = topo_nkegs;
				hib_keg_topo_captured_g = true;

				/*
				 * DSA00 "keg topology" round, correction:
				 * hib_keg_topo_head_g[]/hib_keg_topo_captured_
				 * n_g/hib_keg_topo_captured_g are ordinary
				 * file-scope globals -- their OWN backing
				 * pages are exactly as subject to the K-10
				 * destructive copy (executed later, by
				 * hibernate_tramp.S's copy loop, not by this
				 * function) as any other live structure in
				 * this class. Captured directly this round:
				 * N=1 verification showed topo_fallback=139,
				 * topo_oob=0 -- EVERY consumer call fell back
				 * to the live uk_domain[] read, proving these
				 * globals' own correct, just-written content
				 * was being silently overwritten by the
				 * saved image's stale content before the
				 * resume continuation ever read them. This is
				 * the same destination-set-accounting-gap
				 * class as every other site in this file --
				 * the fix is the same: copy_leaf=true
				 * protection, since the correct content is
				 * THIS boot's own just-captured values, never
				 * the saved image's. Protected here,
				 * immediately after the final write above, so
				 * the self-copy walk sees the fully-populated
				 * array.
				 */
				if (error == 0) {
					vm_offset_t topo_pg, topo_end;

					topo_pg = trunc_page(
					    (vm_offset_t)&hib_keg_topo_head_g);
					topo_end = round_page(
					    (vm_offset_t)&hib_keg_topo_head_g +
					    sizeof(hib_keg_topo_head_g));
					for (; topo_pg < topo_end;
					    topo_pg += PAGE_SIZE) {
						error =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							topo_pg, true,
							&selfcopied);
						if (error != 0)
							break;
					}
				}
				if (error == 0) {
					vm_offset_t topo_pg, topo_end;

					topo_pg = trunc_page((
					    vm_offset_t)&hib_keg_topo_captured_n_g);
					topo_end = round_page(
					    (vm_offset_t)&hib_keg_topo_captured_n_g +
					    sizeof(hib_keg_topo_captured_n_g));
					for (; topo_pg < topo_end;
					    topo_pg += PAGE_SIZE) {
						error =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							topo_pg, true,
							&selfcopied);
						if (error != 0)
							break;
					}
				}
				if (error == 0) {
					vm_offset_t topo_pg, topo_end;

					topo_pg = trunc_page((
					    vm_offset_t)&hib_keg_topo_captured_g);
					topo_end = round_page(
					    (vm_offset_t)&hib_keg_topo_captured_g +
					    sizeof(hib_keg_topo_captured_g));
					for (; topo_pg < topo_end;
					    topo_pg += PAGE_SIZE) {
						error =
						    hibernate_md_selfcopy_walk(
							ha, wvec, p,
							kernel_pmap->pm_cr3,
							topo_pg, true,
							&selfcopied);
						if (error != 0)
							break;
					}
				}
			}
		}
		if (error == 0) {
			/*
			 * DSA00 round 3: item #11 conversion ATTEMPTED and
			 * REVERTED. Removing keg protection (to resolve the
			 * documented contradiction with uma_hibernate_reinit_
			 * plinks()'s own precondition) was tested directly:
			 * N=3 with protection removed reproduced the
			 * previously-closed "32 Bucket" trash-detect panic at
			 * 3/3 (the IDENTICAL address,
			 * 0xfffff8000142af00, every time) -- a reproducible
			 * regression, and a WORSE rate than the 2/9 plinks
			 * GPF rate this conversion was meant to fix. Per the
			 * standing rule (a change that raises another class
			 * is a regression), this conversion is rolled back:
			 * keg protection is RESTORED exactly as before this
			 * round. The contradiction with
			 * uma_hibernate_reinit_plinks()'s own documented
			 * precondition is real and UNRESOLVED -- neither
			 * disposition (protect, or let the saved image
			 * through) is fully correct for this single object;
			 * the keg almost certainly needs a finer-grained
			 * split (list-head reinit distinct from the keg's
			 * other, structural fields) that this round's budget
			 * does not extend to designing and verifying. Flagged
			 * for the next round, not force-fixed here.
			 *
			 * Every struct uma_keg (sys/vm/uma_core.c),
			 * enumerated via the existing uma_kegs list.  Each
			 * keg's own uk_domain[] slab lists are this boot's
			 * own live allocator state -- copy_leaf=true.
			 */
			extern u_int uma_hibernate_nkegs(void);
			extern void uma_hibernate_keg_selfcopy_range(u_int idx,
			    uintptr_t *va_out, size_t *len_out);
			u_int keg_n, keg_idx;

			keg_n = uma_hibernate_nkegs();
			for (keg_idx = 0; keg_idx < keg_n &&
			    error == 0; keg_idx++) {
				uintptr_t keg_va;
				size_t keg_len;
				vm_offset_t keg_pg, keg_end;

				uma_hibernate_keg_selfcopy_range(keg_idx,
				    &keg_va, &keg_len);
				if (keg_va == 0 || keg_len == 0)
					continue;
				keg_pg = trunc_page((vm_offset_t)keg_va);
				keg_end = round_page((vm_offset_t)keg_va +
				    keg_len);
				for (; keg_pg < keg_end;
				    keg_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    keg_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * Every struct uma_zone reachable from each keg's
			 * own uk_zones, plus the standalone uma_cachezones
			 * list (sys/vm/uma_core.c).  copy_leaf=true: this
			 * boot's own live zone bookkeeping.
			 */
			extern u_int uma_hibernate_nzones(void);
			extern void uma_hibernate_zone_selfcopy_range(u_int idx,
			    uintptr_t *va_out, size_t *len_out);
			u_int zone_n, zone_idx;

			zone_n = uma_hibernate_nzones();
			for (zone_idx = 0; zone_idx < zone_n &&
			    error == 0; zone_idx++) {
				uintptr_t zone_va;
				size_t zone_len;
				vm_offset_t zone_pg, zone_end;

				uma_hibernate_zone_selfcopy_range(zone_idx,
				    &zone_va, &zone_len);
				if (zone_va == 0 || zone_len == 0)
					continue;
				zone_pg = trunc_page((vm_offset_t)zone_va);
				zone_end = round_page((vm_offset_t)zone_va +
				    zone_len);
				for (; zone_pg < zone_end;
				    zone_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    zone_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * Individual struct uma_bucket objects (per-CPU
			 * alloc/free/cross buckets and each zone-domain's
			 * uzd_buckets, sys/vm/uma_core.c).  copy_leaf=true:
			 * this boot's own live bucket cache state.
			 */
			extern u_int uma_hibernate_nbuckets(void);
			extern void uma_hibernate_bucket_selfcopy_range(
			    u_int idx, uintptr_t *va_out, size_t *len_out);
			u_int bkt_n, bkt_idx;

			bkt_n = uma_hibernate_nbuckets();
			for (bkt_idx = 0; bkt_idx < bkt_n &&
			    error == 0; bkt_idx++) {
				uintptr_t bkt_va;
				size_t bkt_len;
				vm_offset_t bkt_pg, bkt_end;

				uma_hibernate_bucket_selfcopy_range(bkt_idx,
				    &bkt_va, &bkt_len);
				if (bkt_va == 0 || bkt_len == 0)
					continue;
				bkt_pg = trunc_page((vm_offset_t)bkt_va);
				bkt_end = round_page((vm_offset_t)bkt_va +
				    bkt_len);
				for (; bkt_pg < bkt_end;
				    bkt_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    bkt_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * Individual struct cam_periph nodes reachable
			 * from every registered CAM driver's own units
			 * TAILQ (sys/cam/cam_periph.c) -- the sibling fix
			 * to the already-wired driver-registry
			 * (periph_drivers[]) above.  copy_leaf=true: this
			 * boot's own live CAM topology.
			 */
			extern u_int cam_periph_hibernate_nperiphs(void);
			extern void
			cam_periph_hibernate_periph_selfcopy_range(
			    u_int idx, uintptr_t *va_out, size_t *len_out);
			u_int cph_n, cph_idx;

			cph_n = cam_periph_hibernate_nperiphs();
			for (cph_idx = 0; cph_idx < cph_n &&
			    error == 0; cph_idx++) {
				uintptr_t cph_va;
				size_t cph_len;
				vm_offset_t cph_pg, cph_end;

				cam_periph_hibernate_periph_selfcopy_range(
				    cph_idx, &cph_va, &cph_len);
				if (cph_va == 0 || cph_len == 0)
					continue;
				cph_pg = trunc_page((vm_offset_t)cph_va);
				cph_end = round_page((vm_offset_t)cph_va +
				    cph_len);
				for (; cph_pg < cph_end;
				    cph_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    cph_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * Individual struct cam_ed ("existing device") nodes
			 * reachable from xsoftc.xpt_busses -> et_entries ->
			 * ed_entries (sys/cam/cam_xpt.c) -- the sibling fix
			 * one level deeper than periph_drivers[]/cam_periph
			 * above.  copy_leaf=true: this boot's own live CAM
			 * device topology, including each device's own
			 * device_mtx (the lock cam_periph_release()'s own
			 * cam_periph_mtx()/xpt_path_mtx() chain resolves to).
			 */
			extern u_int cam_xpt_hibernate_ndevices(void);
			extern void
			cam_xpt_hibernate_device_selfcopy_range(
			    u_int idx, uintptr_t *va_out, size_t *len_out);
			u_int ced_n, ced_idx;

			ced_n = cam_xpt_hibernate_ndevices();
			for (ced_idx = 0; ced_idx < ced_n &&
			    error == 0; ced_idx++) {
				uintptr_t ced_va;
				size_t ced_len;
				vm_offset_t ced_pg, ced_end;

				cam_xpt_hibernate_device_selfcopy_range(
				    ced_idx, &ced_va, &ced_len);
				if (ced_va == 0 || ced_len == 0)
					continue;
				ced_pg = trunc_page((vm_offset_t)ced_va);
				ced_end = round_page((vm_offset_t)ced_va +
				    ced_len);
				for (; ced_pg < ced_end;
				    ced_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    ced_pg, true, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
		if (error == 0) {
			/*
			 * Every struct dumperinfo on the dumper_configs
			 * TAILQ (sys/kern/kern_shutdown.c).  copy_leaf=false:
			 * hib_dumper is acquired via dumper_hold() BEFORE
			 * suspend specifically so its content must be the
			 * SAVED image's own, not this boot's -- the
			 * saved_pcb_va rule, not the live-state rule every
			 * other accessor in this set follows (evidence
			 * record: copy_leaf=true was tried and reverted,
			 * confirmed NOT to close the refcount-wraparound
			 * panic).
			 */
			extern u_int dumper_hibernate_nconfigs(void);
			extern void dumper_hibernate_config_selfcopy_range(
			    u_int idx, uintptr_t *va_out, size_t *len_out);
			u_int dmp_n, dmp_idx;

			dmp_n = dumper_hibernate_nconfigs();
			for (dmp_idx = 0; dmp_idx < dmp_n &&
			    error == 0; dmp_idx++) {
				uintptr_t dmp_va;
				size_t dmp_len;
				vm_offset_t dmp_pg, dmp_end;

				dumper_hibernate_config_selfcopy_range(dmp_idx,
				    &dmp_va, &dmp_len);
				if (dmp_va == 0 || dmp_len == 0)
					continue;
				dmp_pg = trunc_page((vm_offset_t)dmp_va);
				dmp_end = round_page((vm_offset_t)dmp_va +
				    dmp_len);
				for (; dmp_pg < dmp_end;
				    dmp_pg += PAGE_SIZE) {
					error = hibernate_md_selfcopy_walk(ha,
					    wvec, p, kernel_pmap->pm_cr3,
					    dmp_pg, false, &selfcopied);
					if (error != 0)
						break;
				}
			}
		}
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
	/*
	 * hah_source_vector_pa now names the PRIVATE-DOMAIN window
	 * VA (window_va), not a physical base address -- hibernate_tramp.S
	 * only ever dereferences this field after the private CR3 is
	 * already loaded (step 2 of its own sequence, before the copy loop
	 * in step 3 reads it), so a valid private-domain VA is exactly as
	 * usable there as a real PA was.  No on-disk/wire-format change:
	 * this field is produced and consumed entirely within this same
	 * resume boot, never encoded by the save-side writer or decoded
	 * across a reboot.
	 */
	hah.hah_source_vector_pa = window_va;
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
