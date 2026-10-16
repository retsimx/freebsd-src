/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org> at Kumacom
 * SARL under sponsorship from the FreeBSD Foundation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/hibernate.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/errno.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/hibernate.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/pmap.h>
#include <machine/psl.h>
#include <machine/segments.h>
#include <machine/specialreg.h>
#include <x86/x86_var.h>

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
 */
static void
hibernate_setup_identity_map(void)
{
	static vm_page_t m_pdp, m_pd[4], m_pml4;
	static bool map_initialized = false;
	pml4_entry_t *v_pml4;
	pdp_entry_t *v_pdp;
	pd_entry_t *v_pd;
	int i, j;

	if (map_initialized)
		return;

	if (la57) {
		m_pml4 = pmap_page_alloc_below_4g(true);
		v_pml4 = (pml4_entry_t *)VM_PAGE_TO_DMAP(m_pml4);
	} else {
		v_pml4 = &kernel_pmap->pm_pmltop[0];
	}
	m_pdp = pmap_page_alloc_below_4g(true);
	v_pdp = (pdp_entry_t *)VM_PAGE_TO_DMAP(m_pdp);

	for (i = 0; i < 4; i++) {
		m_pd[i] = pmap_page_alloc_below_4g(false);
		v_pd = (pd_entry_t *)VM_PAGE_TO_DMAP(m_pd[i]);
		for (j = 0; j < NPDEPG; j++) {
			v_pd[j] = ((vm_paddr_t)i * NBPDP + ((vm_paddr_t)j << PDRSHIFT)) |
			    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M | PG_PS;
		}
		v_pdp[i] = VM_PAGE_TO_PHYS(m_pd[i]) |
		    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
	}

	if (la57) {
		kernel_pmap->pm_pmltop[0] = VM_PAGE_TO_PHYS(m_pml4) |
		    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
	}
	v_pml4[0] = VM_PAGE_TO_PHYS(m_pdp) |
	    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;

	if ((read_rflags() & PSL_I) != 0)
		pmap_invalidate_all(kernel_pmap);
	else
		invltlb_glob();

	map_initialized = true;
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
	if (low_page == NULL) {
		low_page = contigmalloc(PAGE_SIZE, M_DEVBUF, M_WAITOK, 0,
		    0xfffffffful, PAGE_SIZE, 0ul);
		if (low_page == NULL)
			return (ENOMEM);
	}
	hibernate_setup_identity_map();
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
 * The EFER mask contains every bit currently defined by specialreg.h.  Each
 * PAT entry has three architecturally defined memory-type bits.
 */
#define	HIBERNATE_CR0_MASK	(CR0_PE | CR0_MP | CR0_EM | \
	    CR0_NE | CR0_WP | CR0_AM | CR0_NW | CR0_CD | CR0_PG)
#define	HIBERNATE_CR4_MASK	(CR4_VME | CR4_PVI | CR4_TSD | CR4_DE | \
	    CR4_PSE | CR4_PAE | CR4_MCE | CR4_PGE | CR4_PCE | CR4_FXSR | \
	    CR4_XMM | CR4_UMIP | CR4_LA57 | CR4_VMXE | CR4_FSGSBASE | \
	    CR4_PCIDE | CR4_XSAVE | CR4_SMEP | CR4_SMAP | CR4_PKE | \
	    CR4_CET | CR4_PKS | CR4_UINTR | CR4_LASS | CR4_LAM_SUP | \
	    CR4_FRED)
#define	HIBERNATE_EFER_MASK	(EFER_SCE | EFER_LME | EFER_LMA | \
	    EFER_NXE | EFER_SVM | EFER_LMSLE | EFER_FFXSR | EFER_TCE | \
	    EFER_MCOMMIT | EFER_INTWB | EFER_UAIE | EFER_AIBRSE)
#define	HIBERNATE_PAT_MASK	UINT64_C(0x0707070707070707)

int
hibernate_amd64_cpu_validate(const struct hibernate_pcb *pcb,
    bool *refuse_la57, bool *refuse_mtrr)
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
