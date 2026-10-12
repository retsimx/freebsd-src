/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

#ifndef _SYS_HIBERNATE_H_
#define _SYS_HIBERNATE_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/_stdint.h>

struct dumperinfo;

#define HCB_VERSION		      1
#define HIBERNATE_META_BUF_MAX	      65536
#define HIBERNATE_METADATA_SIZE	      UINT64_C(65536)
#define HIBERNATE_MAX_PHDRS	      900

#define HIBERNATE_MARKER_ENCODED_SIZE 40
#define HIBERNATE_CB_ENCODED_SIZE     256
#define HIBERNATE_CB_ALIGNMENT	      16
#define HIBERNATE_PCB_ENCODED_SIZE    1024
#define HIBERNATE_PCB_ALIGNMENT	      64
#define HIBERNATE_PCB_XSAVE_SIZE      768

/* Marker encoding. */
#define HIBERNATE_MARKER_OFF_MAGIC	    0x000
#define HIBERNATE_MARKER_WIDTH_MAGIC	    8
#define HIBERNATE_MARKER_OFF_VERSION	    0x008
#define HIBERNATE_MARKER_WIDTH_VERSION	    4
#define HIBERNATE_MARKER_OFF_STATE	    0x00c
#define HIBERNATE_MARKER_WIDTH_STATE	    4
#define HIBERNATE_MARKER_OFF_IMAGE_OFFSET   0x010
#define HIBERNATE_MARKER_WIDTH_IMAGE_OFFSET 8
#define HIBERNATE_MARKER_OFF_IMAGE_LENGTH   0x018
#define HIBERNATE_MARKER_WIDTH_IMAGE_LENGTH 8
#define HIBERNATE_MARKER_OFF_CRC32C	    0x020
#define HIBERNATE_MARKER_WIDTH_CRC32C	    4
#define HIBERNATE_MARKER_OFF_RESERVED_024   0x024
#define HIBERNATE_MARKER_WIDTH_RESERVED_024 4

/*
 * ABI 1 marker values.  Zero magic means clear/absent; the magic value is
 * opaque to K-3 and owned by K-4 classification.
 */
#define HIBERNATE_MARKER_MAGIC		 UINT64_C(0x48494245524e4154)
#define HIBERNATE_MARKER_VERSION	 1
#define HIBERNATE_MARKER_STATE_PENDING	 1
#define HIBERNATE_MARKER_STATE_CONSUMING 2
#define HIBERNATE_MARKER_STATE_CONSUMED	 3

/* Control-block encoding. */
#define HIBERNATE_CB_OFF_MAGIC			   0x000
#define HIBERNATE_CB_WIDTH_MAGIC		   8
#define HIBERNATE_CB_OFF_VERSION		   0x008
#define HIBERNATE_CB_WIDTH_VERSION		   4
#define HIBERNATE_CB_OFF_ENCODED_SIZE		   0x00c
#define HIBERNATE_CB_WIDTH_ENCODED_SIZE		   4
#define HIBERNATE_CB_OFF_PAGE_SIZE		   0x010
#define HIBERNATE_CB_WIDTH_PAGE_SIZE		   8
#define HIBERNATE_CB_OFF_PHYSMEM_BYTES		   0x018
#define HIBERNATE_CB_WIDTH_PHYSMEM_BYTES	   8
#define HIBERNATE_CB_OFF_IMAGE_LENGTH		   0x020
#define HIBERNATE_CB_WIDTH_IMAGE_LENGTH		   8
#define HIBERNATE_CB_OFF_PAYLOAD_START		   0x028
#define HIBERNATE_CB_WIDTH_PAYLOAD_START	   8
#define HIBERNATE_CB_OFF_DESTINATION_PAGES	   0x030
#define HIBERNATE_CB_WIDTH_DESTINATION_PAGES	   8
#define HIBERNATE_CB_OFF_SOURCE_VECTOR_BYTES	   0x038
#define HIBERNATE_CB_WIDTH_SOURCE_VECTOR_BYTES	   8
#define HIBERNATE_CB_OFF_ARENA_START		   0x040
#define HIBERNATE_CB_WIDTH_ARENA_START		   8
#define HIBERNATE_CB_OFF_ARENA_SIZE		   0x048
#define HIBERNATE_CB_WIDTH_ARENA_SIZE		   8
#define HIBERNATE_CB_OFF_FACS_HARDWARE_SIGNATURE   0x050
#define HIBERNATE_CB_WIDTH_FACS_HARDWARE_SIGNATURE 8
#define HIBERNATE_CB_OFF_SAVED_PCB_OFFSET	   0x058
#define HIBERNATE_CB_WIDTH_SAVED_PCB_OFFSET	   8
#define HIBERNATE_CB_OFF_SAVED_PCB_SIZE		   0x060
#define HIBERNATE_CB_WIDTH_SAVED_PCB_SIZE	   8
#define HIBERNATE_CB_OFF_ELF_PHNUM		   0x068
#define HIBERNATE_CB_WIDTH_ELF_PHNUM		   8
#define HIBERNATE_CB_OFF_METADATA_LENGTH	   0x070
#define HIBERNATE_CB_WIDTH_METADATA_LENGTH	   8
#define HIBERNATE_CB_OFF_CRC32C			   0x078
#define HIBERNATE_CB_WIDTH_CRC32C		   8
#define HIBERNATE_CB_OFF_RESTORE_FOOTPRINT_PAGES   0x080
#define HIBERNATE_CB_WIDTH_RESTORE_FOOTPRINT_PAGES 8
#define HIBERNATE_CB_OFF_MACHINE_FLAGS		   0x088
#define HIBERNATE_CB_WIDTH_MACHINE_FLAGS	   8
#define HIBERNATE_CB_OFF_DESTINATION_BYTES	   0x090
#define HIBERNATE_CB_WIDTH_DESTINATION_BYTES	   8
#define HIBERNATE_CB_OFF_COPY_LIST_BOUND	   0x098
#define HIBERNATE_CB_WIDTH_COPY_LIST_BOUND	   8
#define HIBERNATE_CB_OFF_RESERVED_0A0		   0x0a0
#define HIBERNATE_CB_WIDTH_RESERVED_0A0		   32
#define HIBERNATE_CB_OFF_RESERVED_0C0		   0x0c0
#define HIBERNATE_CB_WIDTH_RESERVED_0C0		   64

/* Process-control-block encoding. */
#define HIBERNATE_PCB_OFF_VERSION	  0x000
#define HIBERNATE_PCB_WIDTH_VERSION	  4
#define HIBERNATE_PCB_OFF_ENCODED_SIZE	  0x004
#define HIBERNATE_PCB_WIDTH_ENCODED_SIZE  4
#define HIBERNATE_PCB_OFF_CR0		  0x008
#define HIBERNATE_PCB_WIDTH_CR0		  8
#define HIBERNATE_PCB_OFF_CR3		  0x010
#define HIBERNATE_PCB_WIDTH_CR3		  8
#define HIBERNATE_PCB_OFF_CR4		  0x018
#define HIBERNATE_PCB_WIDTH_CR4		  8
#define HIBERNATE_PCB_OFF_EFER		  0x020
#define HIBERNATE_PCB_WIDTH_EFER	  8
#define HIBERNATE_PCB_OFF_PAT		  0x028
#define HIBERNATE_PCB_WIDTH_PAT		  8
#define HIBERNATE_PCB_OFF_XCR0		  0x030
#define HIBERNATE_PCB_WIDTH_XCR0	  8
#define HIBERNATE_PCB_OFF_RFLAGS	  0x038
#define HIBERNATE_PCB_WIDTH_RFLAGS	  8
#define HIBERNATE_PCB_OFF_RSP		  0x040
#define HIBERNATE_PCB_WIDTH_RSP		  8
#define HIBERNATE_PCB_OFF_RIP		  0x048
#define HIBERNATE_PCB_WIDTH_RIP		  8
#define HIBERNATE_PCB_OFF_R12_PCB_PA	  0x050
#define HIBERNATE_PCB_WIDTH_R12_PCB_PA	  8
#define HIBERNATE_PCB_OFF_GDTR_LIMIT	  0x058
#define HIBERNATE_PCB_WIDTH_GDTR_LIMIT	  2
#define HIBERNATE_PCB_OFF_RESERVED_05A	  0x05a
#define HIBERNATE_PCB_WIDTH_RESERVED_05A  6
#define HIBERNATE_PCB_OFF_GDTR_BASE	  0x060
#define HIBERNATE_PCB_WIDTH_GDTR_BASE	  8
#define HIBERNATE_PCB_OFF_IDTR_LIMIT	  0x068
#define HIBERNATE_PCB_WIDTH_IDTR_LIMIT	  2
#define HIBERNATE_PCB_OFF_RESERVED_06A	  0x06a
#define HIBERNATE_PCB_WIDTH_RESERVED_06A  6
#define HIBERNATE_PCB_OFF_IDTR_BASE	  0x070
#define HIBERNATE_PCB_WIDTH_IDTR_BASE	  8
#define HIBERNATE_PCB_OFF_FSBASE	  0x078
#define HIBERNATE_PCB_WIDTH_FSBASE	  8
#define HIBERNATE_PCB_OFF_GSBASE	  0x080
#define HIBERNATE_PCB_WIDTH_GSBASE	  8
#define HIBERNATE_PCB_OFF_KGSBASE	  0x088
#define HIBERNATE_PCB_WIDTH_KGSBASE	  8
#define HIBERNATE_PCB_OFF_STAR		  0x090
#define HIBERNATE_PCB_WIDTH_STAR	  8
#define HIBERNATE_PCB_OFF_LSTAR		  0x098
#define HIBERNATE_PCB_WIDTH_LSTAR	  8
#define HIBERNATE_PCB_OFF_CSTAR		  0x0a0
#define HIBERNATE_PCB_WIDTH_CSTAR	  8
#define HIBERNATE_PCB_OFF_SFMASK	  0x0a8
#define HIBERNATE_PCB_WIDTH_SFMASK	  8
#define HIBERNATE_PCB_OFF_KERNEL_GSBASE	  0x0b0
#define HIBERNATE_PCB_WIDTH_KERNEL_GSBASE 8
#define HIBERNATE_PCB_OFF_XSAVE_LENGTH	  0x0b8
#define HIBERNATE_PCB_WIDTH_XSAVE_LENGTH  4
#define HIBERNATE_PCB_OFF_XSAVE_FORMAT	  0x0bc
#define HIBERNATE_PCB_WIDTH_XSAVE_FORMAT  4
#define HIBERNATE_PCB_OFF_XSAVE		  0x0c0
#define HIBERNATE_PCB_WIDTH_XSAVE	  768
#define HIBERNATE_PCB_OFF_RESERVED_3C0	  0x3c0
#define HIBERNATE_PCB_WIDTH_RESERVED_3C0  64

/*
 * ABI 1 accepts no machine flags.  Its canonical XSAVE image supports the
 * mandatory x87 and SSE components only.  AVX (XCR0 bit 2) is deferred
 * until a future ABI version increases the XSAVE region beyond 768 bytes:
 * AVX requires at least 832 bytes (576-byte x87+SSE region + 256-byte YMM
 * high halves), which exceeds HIBERNATE_PCB_XSAVE_SIZE.
 *
 * Canonical XSAVE length for x87+SSE (ABI 1): 576 bytes
 *   512-byte legacy region (x87 + SSE) + 64-byte XSAVE header = 576.
 * Encoded region: HIBERNATE_PCB_WIDTH_XSAVE = 768 bytes.
 * Valid range: [HIBERNATE_PCB_XSAVE_MIN, HIBERNATE_PCB_XSAVE_SIZE].
 * Tail bytes [xsave_length, 768) must be zero.
 */
#define HIBERNATE_MACHINE_FLAGS_MASK UINT64_C(0)
#define HIBERNATE_XSAVE_FORMAT	     1
#define HIBERNATE_XSAVE_FORMAT_MASK  (1U << HIBERNATE_XSAVE_FORMAT)
#define HIBERNATE_XCR0_X87	     UINT64_C(0x1)
#define HIBERNATE_XCR0_SSE	     UINT64_C(0x2)
#define HIBERNATE_XCR0_REQUIRED_MASK (HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE)
/*
 * ABI 1: x87 + SSE only.  AVX excluded; see comment above.
 */
#define HIBERNATE_XCR0_MASK HIBERNATE_XCR0_REQUIRED_MASK
/*
 * Canonical XSAVE length for ABI 1 (x87+SSE): 512-byte legacy region +
 * 64-byte XSAVE header = 576 bytes.
 */
#define HIBERNATE_PCB_XSAVE_MIN 576U

/*
 * These are decoded host-order value objects.  They are never persistent
 * representations; codecs must use the explicit offsets and little-endian
 * byte operations above.
 */
struct hibernate_marker {
	uint64_t hm_magic;
	uint32_t hm_version;
	uint32_t hm_state;
	uint64_t hm_image_offset;
	uint64_t hm_image_length;
	uint32_t hm_crc32c;
};

struct hibernate_cb {
	uint64_t hc_magic;
	uint32_t hc_version;
	uint32_t hc_encoded_size;
	uint64_t hc_page_size;
	uint64_t hc_physmem_bytes;
	uint64_t hc_image_length;
	uint64_t hc_payload_start;
	uint64_t hc_destination_pages;
	uint64_t hc_source_vector_bytes;
	uint64_t hc_arena_start;
	uint64_t hc_arena_size;
	uint64_t hc_facs_hardware_signature;
	uint64_t hc_saved_pcb_offset;
	uint64_t hc_saved_pcb_size;
	uint64_t hc_elf_phnum;
	uint64_t hc_metadata_length;
	uint32_t hc_crc32c;
	uint64_t hc_restore_footprint_pages;
	uint64_t hc_machine_flags;
	uint64_t hc_destination_bytes;
	uint64_t hc_copy_list_bound;
};

struct hibernate_pcb {
	uint32_t hp_version;
	uint32_t hp_encoded_size;
	uint64_t hp_cr0;
	uint64_t hp_cr3;
	uint64_t hp_cr4;
	uint64_t hp_efer;
	uint64_t hp_pat;
	uint64_t hp_xcr0;
	uint64_t hp_rflags;
	uint64_t hp_rsp;
	uint64_t hp_rip;
	uint64_t hp_r12_pcb_pa;
	uint16_t hp_gdtr_limit;
	uint64_t hp_gdtr_base;
	uint16_t hp_idtr_limit;
	uint64_t hp_idtr_base;
	uint64_t hp_fsbase;
	uint64_t hp_gsbase;
	uint64_t hp_kgsbase;
	uint64_t hp_star;
	uint64_t hp_lstar;
	uint64_t hp_cstar;
	uint64_t hp_sfmask;
	uint64_t hp_kernel_gsbase;
	uint32_t hp_xsave_length;
	uint32_t hp_xsave_format;
	uint8_t hp_xsave[HIBERNATE_PCB_XSAVE_SIZE];
};

enum hibernate_image_interval_class { HIIC_STORED, HIIC_ZERO_GAP };

struct hibernate_image_interval {
	uint64_t hii_offset;
	uint64_t hii_length;
	enum hibernate_image_interval_class hii_class;
};

/*
 * A decoded image borrows hi_prefix.  The image and every iterator derived
 * from it remain valid only while that buffer is alive, immutable, and at the
 * same address.
 */
struct hibernate_image {
	const uint8_t *hi_prefix;
	size_t hi_prefix_length;
	struct hibernate_cb hi_cb;
	struct hibernate_pcb hi_pcb;
	uint32_t hi_phnum;
	uint32_t hi_load_count;
	uint32_t hi_cb_count;
	uint32_t hi_pcb_count;
	uint64_t hi_cb_offset;
	uint64_t hi_pcb_offset;
	uint64_t hi_payload_start;
	uint64_t hi_image_length;
	uint64_t hi_destination_pages;
	uint64_t hi_destination_bytes;
	uint64_t hi_source_vector_bytes;
	uint64_t hi_crc_zero_offset;
	uint64_t hi_crc_zero_length;
	uint32_t hi_first_load_index;
	uint32_t hi_last_load_index;
};

enum hibernate_image_iterator_phase { HIIP_METADATA, HIIP_PAYLOAD, HIIP_DONE };

/*
 * hibernate_image_iterator initialization contract:
 *
 * Before the first call to hibernate_image_interval_next(), the caller
 * must populate all five fields:
 *   hii_image      -- pointer to the decoded hibernate_image (must be non-NULL)
 *   hii_next_index -- set to 0 (or img->hi_first_load_index for payload-only)
 *   hii_cursor     -- set to 0 (image-relative byte offset)
 *   hii_phase      -- set to HIIP_METADATA
 *   hii_error      -- set to 0
 *
 * Zero-initialising the struct (e.g. memset to 0) then assigning hii_image
 * and hii_phase = HIIP_METADATA satisfies the contract because the numeric
 * zero values for hii_next_index, hii_cursor, and hii_error are correct.
 */
struct hibernate_image_iterator {
	const struct hibernate_image *hii_image;
	uint32_t hii_next_index;
	uint64_t hii_cursor;
	enum hibernate_image_iterator_phase hii_phase;
	int hii_error;
};

struct hibernate_provider_id {
	char name[SPECNAMELEN];
	uint64_t media_size;
};

enum hibernate_marker_class {
	HMC_ABSENT,
	HMC_PENDING,
	HMC_STALE_CONSUMING,
	HMC_CONSUMED,
	HMC_MALFORMED,
	HMC_IO_ERROR
};

struct hibernate_marker_result {
	enum hibernate_marker_class class;
	struct hibernate_marker marker;
	int error;
};

struct cam_sim;		/* Forward declaration; full type in cam/cam_sim.h. */

struct hibernate_attempt {
	struct hibernate_marker_result ha_marker_result;
	struct dumperinfo *ha_dumper; /* Borrowed; NULL means unbound. */
	off_t ha_marker_offset;	      /* Backend marker I/O offset. */
	uint64_t ha_provider_offset;  /* Provider-relative marker offset P. */
	uint64_t ha_provider_size;    /* Full logical provider size. */

	/*
	 * K-5: validated destination-interval view and arena tuple.
	 *
	 * ha_dst_intervals points to a caller-owned array of
	 * ha_dst_count validated, sorted, strictly increasing
	 * [start, end) physical-address intervals that form the
	 * union of all PT_LOAD destinations.  The view is
	 * source-only attempt state; it does not alter any wire
	 * layout.  ha_dst_valid is set only after the full
	 * validated set has been published; readers must check it
	 * before consulting the intervals or arena fields.
	 *
	 * ha_arena_start and ha_arena_size describe the transition
	 * arena in bytes.  Both are zero when no arena has been
	 * established.
	 */
	vm_paddr_t *ha_dst_intervals;	/* Validated [start,end) pairs. */
	uint64_t ha_dst_count;		/* Number of intervals (pairs/2). */
	vm_paddr_t ha_arena_start;	/* Transition arena base address. */
	uint64_t ha_arena_size;		/* Transition arena size in bytes. */
	bool ha_dst_valid;		/* Destination view is published. */

	/*
	 * K-5: CAM sim used for the hibernate dump path.
	 *
	 * Set by the ACPI save coordinator before calling
	 * hibernate_barrier_prepare().  The barrier uses it to apply
	 * xpt_freeze_simq() admission freeze and bounded xpt_sim_poll()
	 * drain (step 6), then xpt_release_simq() on unwind.  NULL when
	 * no pollable CAM sim is associated with the dump path.
	 */
	struct cam_sim *ha_cam_sim;	/* Dump-path CAM sim; NULL if none. */
};

#define	HIBERNATE_ATTEMPT_INIT							\
	{                                                       \
		.ha_marker_result = { .class = HMC_ABSENT,      \
		    .error = 0 },                               \
		.ha_dst_intervals = NULL,                       \
		.ha_dst_count = 0,                              \
		.ha_arena_start = 0,                            \
		.ha_arena_size = 0,                             \
		.ha_dst_valid = false,                          \
		.ha_cam_sim = NULL,                             \
	}

/*
 * K-5: capacity budget and result types.
 *
 * hibernate_capacity_check() accepts pairwise-disjoint cardinalities
 * and computes the eligible source page count via sequential checked
 * subtraction.  All cardinalities are in pages.
 *
 * Return codes:
 *   0        Sufficient capacity, including exact equality.
 *   EINVAL   Null pointer, zero required cardinality, or impossible
 *            set sizes.
 *   EOVERFLOW Checked arithmetic failure.
 *   ENOMEM   Valid cardinalities but insufficient eligible sources.
 */
struct hibernate_capacity_budget {
	uint64_t physmem_pages;
	uint64_t arena_pages;
	uint64_t destination_union_pages;
	uint64_t restore_kernel_footprint_budget;
};

struct hibernate_capacity_result {
	uint64_t eligible_source_pages;
	uint64_t required_source_pages;
	uint64_t shortfall_pages;
};

int hibernate_capacity_check(const struct hibernate_capacity_budget *b,
    struct hibernate_capacity_result *r);

/*
 * K-5: destination membership predicate.
 *
 * Returns true when the physical address of page m falls within the
 * validated destination-interval view stored in the current hibernate
 * attempt.  Reads only attempt-owned, pre-validated state; does not
 * reparse ELF headers or inspect page queues.
 */
bool hibernate_page_is_destination(vm_page_t m);

/*
 * K-5: eight-stage SAVE stability barrier.
 *
 * Each bit records one successfully acquired barrier stage.  The
 * coordinator sets each bit only after the corresponding step succeeds;
 * the reverse-unwind helper releases only bits that are set.
 *
 * Stage ordering (must be acquired in ascending bit order, released in
 * descending bit order):
 *   HIB_STAGE_COORDINATOR    — coordinator lock held, new work blocked
 *   HIB_STAGE_RESOURCES      — all writer resources preallocated
 *   HIB_STAGE_APS_STOPPED    — APs suspended and acknowledged
 *   HIB_STAGE_BSP_PREEMPT    — BSP preemption disabled
 *   HIB_STAGE_BSP_INTRS      — BSP maskable interrupts disabled
 *   HIB_STAGE_CALLOUTS       — callout freeze active
 *   HIB_STAGE_CAM            — CAM admission frozen and drained
 *   HIB_STAGE_RESERVED       — vm_phys FREE pages reserved
 */
#define	HIB_STAGE_COORDINATOR	(1u << 0)
#define	HIB_STAGE_RESOURCES	(1u << 1)
#define	HIB_STAGE_APS_STOPPED	(1u << 2)
#define	HIB_STAGE_BSP_PREEMPT	(1u << 3)
#define	HIB_STAGE_BSP_INTRS	(1u << 4)
#define	HIB_STAGE_CALLOUTS	(1u << 5)
#define	HIB_STAGE_CAM		(1u << 6)
#define	HIB_STAGE_RESERVED	(1u << 7)

/* Forward declaration; full type in vm/vm_phys.h. */
struct vm_phys_reservation;

#ifdef _KERNEL
/*
 * hibernate_barrier_prepare: acquire stages 1–7 of the K-5 stability
 * barrier around the SAVE attempt.  On failure, releases all acquired
 * stages in strict reverse order and returns a non-zero errno.
 *
 * On success, *stages_out contains the full stage mask and the caller
 * proceeds to step 8 (image write) using only preallocated resources.
 *
 * ha must be the active attempt; res must be a zeroed reservation
 * record with vr_pages pointing to the preallocated array.
 *
 * No allocation is permitted after this function returns 0.
 */
int hibernate_barrier_prepare(struct hibernate_attempt *ha,
    struct vm_phys_reservation *res, unsigned int *stages,
    register_t *intr_statep);

/*
 * hibernate_barrier_unwind: release stages 7-2 recorded in *stages in
 * strict reverse order.  Idempotent for bits that are not set.
 * Always succeeds; clears *stages on return (except HIB_STAGE_COORDINATOR
 * bit is cleared but the lock is NOT released here).
 *
 * After this function returns the caller MUST complete all physical
 * cleanup (resume APs, restore interrupts, free reservation array) and
 * then call hibernate_coordinator_release() as the absolute last step
 * to enforce strict reverse order of the full eight-stage barrier.
 *
 * ha must be the same attempt passed to hibernate_barrier_prepare.
 * res must be the same reservation record.
 */
void hibernate_barrier_unwind(struct hibernate_attempt *ha,
    struct vm_phys_reservation *res, unsigned int *stages);

/*
 * hibernate_barrier_publish_attempt: make ha visible to
 * hibernate_page_is_destination() during the frozen window.
 * Called immediately before hibernate_barrier_prepare() enters
 * stage HIB_STAGE_RESERVED.
 */
void hibernate_barrier_publish_attempt(struct hibernate_attempt *ha);

/*
 * hibernate_barrier_retract_attempt: withdraw the attempt pointer
 * published by hibernate_barrier_publish_attempt().  Called during
 * unwind before resources are freed.
 */
void hibernate_barrier_retract_attempt(void);

/*
 * K-5 footprint arithmetic constants.  Defined here (not in kern_hibernate.c)
 * so they are available in both kernel and _HIBERNATE_USERLAND_BUILD modes
 * for hibernate_restore_footprint_compute() and host-runnable tests (N7).
 *
 * HIB_FOOTPRINT_DEFAULT: default restore footprint floor (262144 pages = 1 GiB).
 * HIB_FOOTPRINT_MAX:     maximum restore footprint (16777216 pages = 64 GiB).
 * HIB_METADATA_MAX_BYTES: maximum metadata-prefix storage (<=64029 B).
 * HIB_FRAG_PCT:          fragmentation margin numerator (25%).
 * HIB_FRAG_DIV:          fragmentation margin denominator.
 * HIB_MAXPHYS_BYTES:     maximum BIO transfer size (MAXPHYS equivalent, 128 KiB).
 * HIB_SCRATCH_STACK_BYTES: arena-external MD workspace size.
 * HIB_RESERVATION_RECORD_BYTES: per-page reservation record size (16 bytes on amd64).
 * HIB_PAGE_SIZE:         page size for footprint arithmetic (4096 bytes).
 */
#define	HIB_FOOTPRINT_DEFAULT		262144UL
#define	HIB_FOOTPRINT_MAX		16777216UL
#define	HIB_METADATA_MAX_BYTES		64029UL
#define	HIB_FRAG_PCT			25UL
#define	HIB_FRAG_DIV			100UL
#define	HIB_MAXPHYS_BYTES		131072UL	/* 128 KiB */
#define	HIB_SCRATCH_STACK_BYTES		65536UL		/* 64 KiB */
#define	HIB_RESERVATION_RECORD_BYTES	16UL		/* amd64 LP64 */
#define	HIB_PAGE_SIZE			4096UL

/*
 * hibernate_restore_footprint_compute: pure arithmetic core of footprint
 * derivation, parameterized by wired_pages so it is testable in userland
 * without vm_wire_count() (N7).  Compiled in both kernel and userland modes.
 */
int hibernate_restore_footprint_compute(uint64_t destination_union_pages,
    uint64_t wired_pages, uint64_t *derived_pages_out);

/*
 * hibernate_restore_footprint_derive: compute the minimum restore-kernel
 * footprint in pages from destination_union_pages using checked arithmetic.
 * Non-static so host-runnable tests can call production derivation directly
 * (N7: exercise production footprint derivation rather than duplicating
 * the formula).
 * Returns 0 on success with *derived_pages_out set; EOVERFLOW on overflow;
 * ENOMEM if the result exceeds HIB_FOOTPRINT_MAX.
 */
int hibernate_restore_footprint_derive(uint64_t destination_union_pages,
    uint64_t *derived_pages_out);

/*
 * hibernate_footprint_check: return the footprint derivation/configuration
 * status recorded at boot.  Returns 0 when valid, EINVAL/EOVERFLOW/ENOMEM
 * on error.  Must be called before the freeze to enforce refusal.
 */
int hibernate_footprint_check(void);

/*
 * hibernate_footprint_effective: return the effective restore-kernel
 * footprint budget in pages.  Valid only when hibernate_footprint_check()
 * returns 0.
 */
u_long hibernate_footprint_effective(void);

/*
 * hibernate_coordinator_acquire: acquire the coordinator lock, serialising
 * concurrent save attempts.  Must be called before HIB_STAGE_COORDINATOR
 * is set.  Returns 0 on success.
 */
int hibernate_coordinator_acquire(void);

/*
 * hibernate_coordinator_release: release the coordinator lock.  Must be
 * called by the save-path caller as the LAST step of unwind, after
 * hibernate_barrier_unwind() has returned and all physical cleanup
 * (AP resume, interrupt restore, reservation array free) is complete.
 * hibernate_barrier_unwind() clears HIB_STAGE_COORDINATOR but does NOT
 * release the lock; this function performs the actual release.
 */
void hibernate_coordinator_release(void);
#endif /* _KERNEL */

int hibernate_probe(struct hibernate_attempt *ha);
bool hibernate_provider_conflicts(const struct hibernate_provider_id *id);
int hibernate_extent_hold(const struct hibernate_provider_id *id,
    uint64_t offset, uint64_t length);
void hibernate_extent_release(const struct hibernate_provider_id *id);
void hibernate_marker_decode_complete(const uint8_t *buf,
    struct hibernate_marker *marker, uint32_t *reserved);
enum hibernate_marker_class hibernate_marker_classify(uint64_t marker_offset,
    uint64_t media_size, const struct hibernate_marker *marker,
    uint32_t reserved);
int hibernate_marker_result_from_transfer(int error, size_t transferred,
    const uint8_t *sector, uint64_t provider_offset, uint64_t provider_size,
    struct hibernate_marker_result *out);

/*
 * Internal K-4 interfaces shared with the single-purpose GEOM owner.
 * These are kernel-only lifecycle operations, not persistent ABI.
 */
#ifdef _KERNEL
struct hibernate_config {
	char hc_name[SPECNAMELEN];
	unsigned int hc_wait_ms;
	bool hc_enabled;
};

int hibernate_config_get(struct hibernate_config *config);
int hibernate_dumper_lookup(const struct hibernate_provider_id *id,
    struct dumperinfo **dip);
int hibernate_owner_publish(const struct hibernate_provider_id *id);
void hibernate_owner_deactivate(const struct hibernate_provider_id *id);
void hibernate_probe_begin(void);
void hibernate_probe_complete(void);
bool hibernate_probe_active(void);
#endif

int hibernate_image_decode(const void *, size_t, struct hibernate_image *);
int hibernate_image_interval_next(struct hibernate_image_iterator *,
    struct hibernate_image_interval *);

/*
 * Marker operations use one attempt-bound, ordered dumper.  The caller must
 * keep the dumper admission regime closed against competing image and marker
 * writers for the complete read-modify-write sequence through its flush.
 * Dump execution owns the operation through dumping; hibernation additionally
 * marks hibernate_writing.  K-3 adds no lock (design sections 3.3 and 11.7).
 */
int hibernate_marker_read(struct hibernate_attempt *ha,
    struct hibernate_marker *out);
int hibernate_marker_write(struct hibernate_attempt *ha,
    const struct hibernate_marker *m);
int hibernate_marker_clear(struct hibernate_attempt *ha);
int hibernate_marker_flush(struct hibernate_attempt *ha);

/*
 * CRC32C primitive: reflected Castagnoli polynomial 0x82f63b78.
 *
 * Convention:
 *   - caller passes initial crc = 0xffffffff on the first call
 *   - caller applies final XOR 0xffffffff to the value returned
 *     by the last call to obtain the canonical CRC32C digest
 *   - intermediate calls chain: crc = hibernate_crc32c_update(crc, ...)
 *
 * The whole-image CRC covers [I, I + image_length) in encoded order.
 * Consumers virtually supply only the eight encoded hc_crc32c bytes at
 * CB+0x078 as zero.  They do not mutate the encoded image.  K-6 and K-8
 * stream metadata, encoded zero gaps, and payload through this primitive.
 *
 * Vectors (initial 0xffffffff, final XOR 0xffffffff applied):
 *   empty input   -> 0x00000000
 *   "123456789"   -> 0xe3069283
 */
uint32_t hibernate_crc32c_update(uint32_t crc, const void *buf, size_t len);

#ifndef _LOCORE
/*
 * Private byte-only declarations prove the wire tables.  They are layout
 * witnesses, not codec or persistent scalar structures.
 */
struct __hibernate_marker_layout {
	uint8_t magic[HIBERNATE_MARKER_WIDTH_MAGIC];
	uint8_t version[HIBERNATE_MARKER_WIDTH_VERSION];
	uint8_t state[HIBERNATE_MARKER_WIDTH_STATE];
	uint8_t image_offset[HIBERNATE_MARKER_WIDTH_IMAGE_OFFSET];
	uint8_t image_length[HIBERNATE_MARKER_WIDTH_IMAGE_LENGTH];
	uint8_t crc32c[HIBERNATE_MARKER_WIDTH_CRC32C];
	uint8_t reserved_024[HIBERNATE_MARKER_WIDTH_RESERVED_024];
};

struct __hibernate_cb_layout {
	uint8_t magic[HIBERNATE_CB_WIDTH_MAGIC];
	uint8_t version[HIBERNATE_CB_WIDTH_VERSION];
	uint8_t encoded_size[HIBERNATE_CB_WIDTH_ENCODED_SIZE];
	uint8_t page_size[HIBERNATE_CB_WIDTH_PAGE_SIZE];
	uint8_t physmem_bytes[HIBERNATE_CB_WIDTH_PHYSMEM_BYTES];
	uint8_t image_length[HIBERNATE_CB_WIDTH_IMAGE_LENGTH];
	uint8_t payload_start[HIBERNATE_CB_WIDTH_PAYLOAD_START];
	uint8_t destination_pages[HIBERNATE_CB_WIDTH_DESTINATION_PAGES];
	uint8_t source_vector_bytes[HIBERNATE_CB_WIDTH_SOURCE_VECTOR_BYTES];
	uint8_t arena_start[HIBERNATE_CB_WIDTH_ARENA_START];
	uint8_t arena_size[HIBERNATE_CB_WIDTH_ARENA_SIZE];
	uint8_t
	    facs_hardware_signature[HIBERNATE_CB_WIDTH_FACS_HARDWARE_SIGNATURE];
	uint8_t saved_pcb_offset[HIBERNATE_CB_WIDTH_SAVED_PCB_OFFSET];
	uint8_t saved_pcb_size[HIBERNATE_CB_WIDTH_SAVED_PCB_SIZE];
	uint8_t elf_phnum[HIBERNATE_CB_WIDTH_ELF_PHNUM];
	uint8_t metadata_length[HIBERNATE_CB_WIDTH_METADATA_LENGTH];
	uint8_t crc32c[HIBERNATE_CB_WIDTH_CRC32C];
	uint8_t
	    restore_footprint_pages[HIBERNATE_CB_WIDTH_RESTORE_FOOTPRINT_PAGES];
	uint8_t machine_flags[HIBERNATE_CB_WIDTH_MACHINE_FLAGS];
	uint8_t destination_bytes[HIBERNATE_CB_WIDTH_DESTINATION_BYTES];
	uint8_t copy_list_bound[HIBERNATE_CB_WIDTH_COPY_LIST_BOUND];
	uint8_t reserved_0a0[HIBERNATE_CB_WIDTH_RESERVED_0A0];
	uint8_t reserved_0c0[HIBERNATE_CB_WIDTH_RESERVED_0C0];
} __aligned(HIBERNATE_CB_ALIGNMENT);

struct __hibernate_pcb_layout {
	uint8_t version[HIBERNATE_PCB_WIDTH_VERSION];
	uint8_t encoded_size[HIBERNATE_PCB_WIDTH_ENCODED_SIZE];
	uint8_t cr0[HIBERNATE_PCB_WIDTH_CR0];
	uint8_t cr3[HIBERNATE_PCB_WIDTH_CR3];
	uint8_t cr4[HIBERNATE_PCB_WIDTH_CR4];
	uint8_t efer[HIBERNATE_PCB_WIDTH_EFER];
	uint8_t pat[HIBERNATE_PCB_WIDTH_PAT];
	uint8_t xcr0[HIBERNATE_PCB_WIDTH_XCR0];
	uint8_t rflags[HIBERNATE_PCB_WIDTH_RFLAGS];
	uint8_t rsp[HIBERNATE_PCB_WIDTH_RSP];
	uint8_t rip[HIBERNATE_PCB_WIDTH_RIP];
	uint8_t r12_pcb_pa[HIBERNATE_PCB_WIDTH_R12_PCB_PA];
	uint8_t gdtr_limit[HIBERNATE_PCB_WIDTH_GDTR_LIMIT];
	uint8_t reserved_05a[HIBERNATE_PCB_WIDTH_RESERVED_05A];
	uint8_t gdtr_base[HIBERNATE_PCB_WIDTH_GDTR_BASE];
	uint8_t idtr_limit[HIBERNATE_PCB_WIDTH_IDTR_LIMIT];
	uint8_t reserved_06a[HIBERNATE_PCB_WIDTH_RESERVED_06A];
	uint8_t idtr_base[HIBERNATE_PCB_WIDTH_IDTR_BASE];
	uint8_t fsbase[HIBERNATE_PCB_WIDTH_FSBASE];
	uint8_t gsbase[HIBERNATE_PCB_WIDTH_GSBASE];
	uint8_t kgsbase[HIBERNATE_PCB_WIDTH_KGSBASE];
	uint8_t star[HIBERNATE_PCB_WIDTH_STAR];
	uint8_t lstar[HIBERNATE_PCB_WIDTH_LSTAR];
	uint8_t cstar[HIBERNATE_PCB_WIDTH_CSTAR];
	uint8_t sfmask[HIBERNATE_PCB_WIDTH_SFMASK];
	uint8_t kernel_gsbase[HIBERNATE_PCB_WIDTH_KERNEL_GSBASE];
	uint8_t xsave_length[HIBERNATE_PCB_WIDTH_XSAVE_LENGTH];
	uint8_t xsave_format[HIBERNATE_PCB_WIDTH_XSAVE_FORMAT];
	uint8_t xsave[HIBERNATE_PCB_WIDTH_XSAVE];
	uint8_t reserved_3c0[HIBERNATE_PCB_WIDTH_RESERVED_3C0];
} __aligned(HIBERNATE_PCB_ALIGNMENT);

#define HIBERNATE_LAYOUT_ASSERT(type, member, prefix, field) \
	_Static_assert(__offsetof(struct type, member) ==    \
		prefix##_OFF_##field,                        \
	    #type "." #member " offset");                    \
	_Static_assert(sizeof(((struct type *)0)->member) == \
		prefix##_WIDTH_##field,                      \
	    #type "." #member " width")

HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, magic, HIBERNATE_MARKER,
    MAGIC);
HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, version, HIBERNATE_MARKER,
    VERSION);
HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, state, HIBERNATE_MARKER,
    STATE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, image_offset,
    HIBERNATE_MARKER, IMAGE_OFFSET);
HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, image_length,
    HIBERNATE_MARKER, IMAGE_LENGTH);
HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, crc32c, HIBERNATE_MARKER,
    CRC32C);
HIBERNATE_LAYOUT_ASSERT(__hibernate_marker_layout, reserved_024,
    HIBERNATE_MARKER, RESERVED_024);

HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, magic, HIBERNATE_CB, MAGIC);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, version, HIBERNATE_CB, VERSION);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, encoded_size, HIBERNATE_CB,
    ENCODED_SIZE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, page_size, HIBERNATE_CB,
    PAGE_SIZE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, physmem_bytes, HIBERNATE_CB,
    PHYSMEM_BYTES);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, image_length, HIBERNATE_CB,
    IMAGE_LENGTH);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, payload_start, HIBERNATE_CB,
    PAYLOAD_START);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, destination_pages, HIBERNATE_CB,
    DESTINATION_PAGES);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, source_vector_bytes,
    HIBERNATE_CB, SOURCE_VECTOR_BYTES);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, arena_start, HIBERNATE_CB,
    ARENA_START);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, arena_size, HIBERNATE_CB,
    ARENA_SIZE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, facs_hardware_signature,
    HIBERNATE_CB, FACS_HARDWARE_SIGNATURE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, saved_pcb_offset, HIBERNATE_CB,
    SAVED_PCB_OFFSET);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, saved_pcb_size, HIBERNATE_CB,
    SAVED_PCB_SIZE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, elf_phnum, HIBERNATE_CB,
    ELF_PHNUM);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, metadata_length, HIBERNATE_CB,
    METADATA_LENGTH);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, crc32c, HIBERNATE_CB, CRC32C);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, restore_footprint_pages,
    HIBERNATE_CB, RESTORE_FOOTPRINT_PAGES);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, machine_flags, HIBERNATE_CB,
    MACHINE_FLAGS);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, destination_bytes, HIBERNATE_CB,
    DESTINATION_BYTES);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, copy_list_bound, HIBERNATE_CB,
    COPY_LIST_BOUND);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, reserved_0a0, HIBERNATE_CB,
    RESERVED_0A0);
HIBERNATE_LAYOUT_ASSERT(__hibernate_cb_layout, reserved_0c0, HIBERNATE_CB,
    RESERVED_0C0);

HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, version, HIBERNATE_PCB,
    VERSION);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, encoded_size, HIBERNATE_PCB,
    ENCODED_SIZE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, cr0, HIBERNATE_PCB, CR0);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, cr3, HIBERNATE_PCB, CR3);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, cr4, HIBERNATE_PCB, CR4);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, efer, HIBERNATE_PCB, EFER);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, pat, HIBERNATE_PCB, PAT);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, xcr0, HIBERNATE_PCB, XCR0);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, rflags, HIBERNATE_PCB, RFLAGS);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, rsp, HIBERNATE_PCB, RSP);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, rip, HIBERNATE_PCB, RIP);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, r12_pcb_pa, HIBERNATE_PCB,
    R12_PCB_PA);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, gdtr_limit, HIBERNATE_PCB,
    GDTR_LIMIT);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, reserved_05a, HIBERNATE_PCB,
    RESERVED_05A);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, gdtr_base, HIBERNATE_PCB,
    GDTR_BASE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, idtr_limit, HIBERNATE_PCB,
    IDTR_LIMIT);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, reserved_06a, HIBERNATE_PCB,
    RESERVED_06A);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, idtr_base, HIBERNATE_PCB,
    IDTR_BASE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, fsbase, HIBERNATE_PCB, FSBASE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, gsbase, HIBERNATE_PCB, GSBASE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, kgsbase, HIBERNATE_PCB,
    KGSBASE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, star, HIBERNATE_PCB, STAR);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, lstar, HIBERNATE_PCB, LSTAR);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, cstar, HIBERNATE_PCB, CSTAR);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, sfmask, HIBERNATE_PCB, SFMASK);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, kernel_gsbase, HIBERNATE_PCB,
    KERNEL_GSBASE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, xsave_length, HIBERNATE_PCB,
    XSAVE_LENGTH);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, xsave_format, HIBERNATE_PCB,
    XSAVE_FORMAT);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, xsave, HIBERNATE_PCB, XSAVE);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, reserved_3c0, HIBERNATE_PCB,
    RESERVED_3C0);

_Static_assert(sizeof(struct __hibernate_marker_layout) ==
	HIBERNATE_MARKER_ENCODED_SIZE,
    "marker complete coverage");
_Static_assert(sizeof(struct __hibernate_cb_layout) ==
	HIBERNATE_CB_ENCODED_SIZE,
    "CB complete coverage");
_Static_assert(sizeof(struct __hibernate_pcb_layout) ==
	HIBERNATE_PCB_ENCODED_SIZE,
    "PCB complete coverage");
_Static_assert(_Alignof(struct __hibernate_cb_layout) == HIBERNATE_CB_ALIGNMENT,
    "CB alignment");
_Static_assert(_Alignof(struct __hibernate_pcb_layout) ==
	HIBERNATE_PCB_ALIGNMENT,
    "PCB alignment");
_Static_assert(HIBERNATE_CB_OFF_RESERVED_0C0 +
	    HIBERNATE_CB_WIDTH_RESERVED_0C0 ==
	HIBERNATE_CB_ENCODED_SIZE,
    "CB collision-free complete coverage");
_Static_assert(HIBERNATE_PCB_OFF_RESERVED_3C0 +
	    HIBERNATE_PCB_WIDTH_RESERVED_3C0 ==
	HIBERNATE_PCB_ENCODED_SIZE,
    "PCB collision-free complete coverage");
_Static_assert(HIBERNATE_MARKER_OFF_RESERVED_024 +
	    HIBERNATE_MARKER_WIDTH_RESERVED_024 ==
	HIBERNATE_MARKER_ENCODED_SIZE,
    "marker collision-free complete coverage");

#undef HIBERNATE_LAYOUT_ASSERT
#endif /* !_LOCORE */

#endif /* !_SYS_HIBERNATE_H_ */
