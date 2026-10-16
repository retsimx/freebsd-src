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
#include <sys/_cpuset.h>

struct dumperinfo;
struct hibernate_xsave_terminal;

enum hibernate_arena_interval_class {
	HAIC_ELIGIBLE,
	HAIC_INELIGIBLE_FIRMWARE,
	HAIC_INELIGIBLE_LIVE
};

struct hibernate_arena_interval {
	vm_paddr_t hai_start;
	vm_paddr_t hai_end;
	enum hibernate_arena_interval_class hai_class;
};

struct hibernate_early_arena {
	vm_paddr_t hea_start;
	vm_size_t hea_size;
	uint32_t hea_rule_version;
	bool hea_valid;
	bool hea_claimed;
};

struct hibernate_arena_sizing {
	uint64_t has_private_page_tables;
	uint64_t has_copy_run_storage;
	uint64_t has_aux_descriptor_storage;
	uint64_t has_descriptor_storage;
	uint64_t has_alignment_allowance;
	uint64_t has_raw_required;
	uint64_t has_required;
};


#define HCB_VERSION		      1
#define HIBERNATE_META_BUF_MAX	      65536
#define HIBERNATE_METADATA_SIZE	      UINT64_C(65536)
#define HIBERNATE_MAX_PHDRS	      900

#define HIBERNATE_ARENA_RULE_VERSION	     1U
#define HIBERNATE_ARENA_ALIGNMENT	     UINT64_C(4096)
#define HIBERNATE_ARENA_HEADER_BYTES	     UINT64_C(256)
#define HIBERNATE_ARENA_TRAMPOLINE_BYTES     UINT64_C(4096)
#define HIBERNATE_ARENA_STACK_BYTES	     UINT64_C(65536)
#define HIBERNATE_ARENA_HANDOFF_BYTES	     UINT64_C(4096)
#define HIBERNATE_ARENA_COPY_RUN_MAX	     UINT64_C(900)
#define HIBERNATE_ARENA_COPY_RUN_BYTES	     UINT64_C(32)
#define HIBERNATE_ARENA_AUX_DESCRIPTOR_MAX   UINT64_C(64)
#define HIBERNATE_ARENA_AUX_DESCRIPTOR_BYTES UINT64_C(16)
#define HIBERNATE_ARENA_PT_PML4_PAGES	     UINT64_C(1)
#define HIBERNATE_ARENA_PT_PDPT_PAGES	     UINT64_C(4)
#define HIBERNATE_ARENA_PT_PD_PAGES	     UINT64_C(8)
#define HIBERNATE_ARENA_PT_LEAF_PAGES	     UINT64_C(16)
#define HIBERNATE_ARENA_OBJECT_ALIGNMENTS    UINT64_C(7)
#define HIBERNATE_ARENA_BOUNDED_SLACK_BYTES  UINT64_C(65536)
#define HIBERNATE_ARENA_POLICY_DEFAULT_BYTES (UINT64_C(4) * 1024 * 1024)
#define HIBERNATE_ARENA_PHYS_LIMIT	     UINT64_C(0x100000000)
#define HIBERNATE_ARENA_INTERVAL_MAX	     128

#define HIBERNATE_ARENA_PRIVATE_PT_PAGES                                 \
	(HIBERNATE_ARENA_PT_PML4_PAGES + HIBERNATE_ARENA_PT_PDPT_PAGES + \
	    HIBERNATE_ARENA_PT_PD_PAGES + HIBERNATE_ARENA_PT_LEAF_PAGES)
#define HIBERNATE_ARENA_ALIGNMENT_ALLOWANCE_BYTES \
	(HIBERNATE_ARENA_OBJECT_ALIGNMENTS *      \
	    (HIBERNATE_ARENA_ALIGNMENT - UINT64_C(1)))


#define HIBERNATE_MARKER_ENCODED_SIZE 40
#define HIBERNATE_CB_ENCODED_SIZE     256
#define HIBERNATE_CB_ALIGNMENT	      16
#define HIBERNATE_PCB_ENCODED_SIZE    1024
#define HIBERNATE_PCB_ALIGNMENT	      64

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
#define HIBERNATE_PCB_OFF_XSAVE_LENGTH		0x0b8
#define HIBERNATE_PCB_WIDTH_XSAVE_LENGTH	4
#define HIBERNATE_PCB_OFF_XSAVE_FORMAT		0x0bc
#define HIBERNATE_PCB_WIDTH_XSAVE_FORMAT	4
#define HIBERNATE_PCB_OFF_XSAVE_OFFSET		0x0c0
#define HIBERNATE_PCB_WIDTH_XSAVE_OFFSET	8
#define HIBERNATE_PCB_OFF_XSAVE_ENABLED_MASK	0x0c8
#define HIBERNATE_PCB_WIDTH_XSAVE_ENABLED_MASK	8
#define HIBERNATE_PCB_OFF_RESERVED_0D0		0x0d0
#define HIBERNATE_PCB_WIDTH_RESERVED_0D0	816

/*
 * ABI 1 accepts no machine flags.  XSAVE state is stored in one standard,
 * non-compacted payload object.  These values mirror XFEATURE_ENABLED_*
 * without requiring a kernel-only architecture header in userland builds.
 */
#define HIBERNATE_MACHINE_FLAGS_MASK		UINT64_C(0)
#define HIBERNATE_XSAVE_FORMAT			1
#define HIBERNATE_XSAVE_FORMAT_MASK		(1U << HIBERNATE_XSAVE_FORMAT)
#define HIBERNATE_XCR0_X87			UINT64_C(0x000001)
#define HIBERNATE_XCR0_SSE			UINT64_C(0x000002)
#define HIBERNATE_XCR0_YMM_HI128		UINT64_C(0x000004)
#define HIBERNATE_XCR0_AVX			HIBERNATE_XCR0_YMM_HI128
#define HIBERNATE_XCR0_BNDREGS			UINT64_C(0x000008)
#define HIBERNATE_XCR0_BNDCSR			UINT64_C(0x000010)
#define HIBERNATE_XCR0_OPMASK			UINT64_C(0x000020)
#define HIBERNATE_XCR0_ZMM_HI256		UINT64_C(0x000040)
#define HIBERNATE_XCR0_HI16_ZMM			UINT64_C(0x000080)
#define HIBERNATE_XCR0_PT			UINT64_C(0x000100)
#define HIBERNATE_XCR0_PKRU			UINT64_C(0x000200)
#define HIBERNATE_XCR0_TILECONFIG		UINT64_C(0x020000)
#define HIBERNATE_XCR0_TILEDATA			UINT64_C(0x040000)
#define HIBERNATE_XCR0_REQUIRED_MASK		\
	(HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE)
#define HIBERNATE_XCR0_SUPPORTED_MASK		UINT64_C(0x0603ff)
#define HIBERNATE_XCR0_MASK			HIBERNATE_XCR0_SUPPORTED_MASK
#define HIBERNATE_PCB_XSAVE_MIN			576U

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

/*
 * Synthetic CPUID leaf 0xD component fact used by the allocation-free
 * standard-format XSAVE extent derivation core.  Components 0 and 1 occupy
 * the architectural legacy region; callers provide facts only for enabled
 * components numbered 2 and above.
 */
struct hibernate_xsave_component_fact {
	uint32_t hxcf_component;
	uint32_t hxcf_size;
	uint32_t hxcf_offset;
};

/*
 * One immutable PT_LOAD input to the portable ABI 1 writer-plan assembler.
 * hwr_file_offset is image-relative.  hwr_source identifies the backing
 * source object; overlapping source intervals are aliases and are refused.
 */
struct hibernate_writer_run {
	uint64_t hwr_destination;
	uint64_t hwr_file_offset;
	uint64_t hwr_length;
	uint64_t hwr_source;
	uint64_t hwr_source_offset;
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
	uint64_t hp_xsave_offset;
	uint64_t hp_xsave_enabled_mask;
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
	uint32_t hi_xsave_index;
	uint64_t hi_xsave_offset;
	uint64_t hi_xsave_length;
	uint64_t hi_xsave_enabled_mask;
	uint32_t hi_xsave_format;
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

/*
 * Allocation-free input and output for canonical ABI 1 prefix assembly.
 * hwp_prefix is caller-owned bounded storage and remains immutable while
 * hwp_image or hwp_iterator is used.
 */
struct hibernate_writer_plan {
	uint8_t *hwp_prefix;
	size_t hwp_prefix_capacity;
	size_t hwp_prefix_length;
	const struct hibernate_writer_run *hwp_runs;
	size_t hwp_run_count;
	struct hibernate_image hwp_image;
	struct hibernate_image_iterator hwp_iterator;
};

#ifdef _KERNEL
/*
 * Preallocated K-6 save-side workspace.
 *
 * ACPI owns every pointed-to allocation and creates it before entering the
 * K-5 no-allocation window.  The dump worker fills the immutable plan after
 * reserve_all() has stabilised the FREE omission set.  Provider code borrows
 * the completed workspace only for the ordered image transaction.
 */
struct hibernate_writer_workspace {
	struct hibernate_writer_plan hww_plan;
	struct hibernate_cb hww_cb;
	struct hibernate_pcb hww_pcb;
	struct hibernate_xsave_terminal *hww_xsave_terminal;
	uint8_t *hww_prefix;
	size_t hww_prefix_capacity;
	void *hww_xsave;
	size_t hww_xsave_capacity;
	struct hibernate_writer_run *hww_runs;
	size_t hww_runs_capacity;
	vm_paddr_t *hww_free_scratch;
	size_t hww_free_scratch_capacity;
	vm_paddr_t *hww_destination_intervals;
	size_t hww_destination_capacity;
	uint8_t *hww_io_buffer;
	size_t hww_io_capacity;
	uint32_t hww_crc32c;
	bool hww_image_committed;
};
#endif

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

enum hibernate_marker_owned {
	HM_OWNED_NONE,
	HM_OWNED_PENDING,
	HM_OWNED_CONSUMING
};

enum hibernate_owner_rollback_outcome {
	HIBERNATE_OWNER_ROLLBACK_VERIFIED = 0,
	HIBERNATE_OWNER_ROLLBACK_UNSAFE,
	HIBERNATE_OWNER_ROLLBACK_UNKNOWN
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

	/*
	 * K-7: marker ownership, RESTORE-attempt resource ownership, and the
	 * exact acknowledged-AP set.  Each flag changes only at its one stated
	 * acquisition point and one stated release point.  ha_marker_owned is
	 * the sole marker-ownership representation.
	 */
	enum hibernate_marker_owned ha_marker_owned;
	bool ha_has_root_hold;		/* K-4 probe gate root_mount_hold(). */
	bool ha_has_provider;		/* K-4 GEOM consumer access + dumper. */
	bool ha_has_extent;		/* K-4 hibernate_extent_hold(). */
	bool ha_has_metadata;		/* K-8 metadata/image ownership. */
	bool ha_has_safe_pages;		/* K-8 source-page reservation. */
	bool ha_has_arena;		/* K-9 hibernate_arena_claim(). */
	bool ha_has_admission_closed;	/* K-12 coordinator admission closed. */
	bool ha_has_quiesce;		/* K-12 hibernate_quiesce() success. */
	bool ha_has_stopped_cpus;	/* K-12 stop_cpus() success. */
	cpuset_t ha_acknowledged_cpus;	/* Exact acknowledged AP subset. */
	struct hibernate_image ha_image;
					/* K-7 decoded image (transient). */
};

#define	HIBERNATE_ATTEMPT_INIT                                  \
	{                                                       \
		.ha_marker_result = { .class = HMC_ABSENT,      \
		    .error = 0 },                               \
		.ha_dst_intervals = NULL,                       \
		.ha_dst_count = 0,                              \
		.ha_arena_start = 0,                            \
		.ha_arena_size = 0,                             \
		.ha_dst_valid = false,                          \
		.ha_cam_sim = NULL,                             \
		.ha_marker_owned = HM_OWNED_NONE,               \
		.ha_has_root_hold = false,                      \
		.ha_has_provider = false,                       \
		.ha_has_extent = false,                         \
		.ha_has_metadata = false,                       \
		.ha_has_safe_pages = false,                     \
		.ha_has_arena = false,                          \
		.ha_has_admission_closed = false,               \
		.ha_has_quiesce = false,                        \
		.ha_has_stopped_cpus = false,                   \
		.ha_acknowledged_cpus = { { 0 } },              \
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
 * K-9 early arena derivation and ownership contract.  The interval helpers
 * are allocation-free and are shared by early amd64 discovery and userland
 * fixtures.  hibernate_image_validate(), when supplied by K-7, is the sole
 * site that may compare decoded CB arena fields with the immutable tuple.
 */
int hibernate_arena_required(struct hibernate_arena_sizing *sizing);
int hibernate_arena_normalize(const struct hibernate_arena_interval *input,
    size_t input_count, struct hibernate_arena_interval *output,
    size_t output_capacity, size_t *output_count);
int hibernate_arena_exclude_live(struct hibernate_arena_interval *intervals,
    size_t *count, size_t capacity, vm_paddr_t start, vm_paddr_t end);
int hibernate_arena_select(const struct hibernate_arena_interval *intervals,
    size_t count, uint64_t policy_bound, vm_paddr_t *pa, vm_size_t *size);
int hibernate_arena_split_pairs(const vm_paddr_t *input, size_t input_count,
    vm_paddr_t arena_start, vm_paddr_t arena_end, vm_paddr_t *output,
    size_t output_capacity, size_t *output_count);
void hibernate_arena_reset(void);
int hibernate_arena_reserve(vm_paddr_t pa, vm_size_t size);
int hibernate_arena_claim(struct hibernate_attempt *ha);
void hibernate_arena_release(struct hibernate_attempt *ha);


/*
 * K-5: destination membership predicate.
 *
 * Returns true when the physical address of page m falls within the
 * validated destination-interval view stored in the current hibernate
 * attempt.  Reads only attempt-owned, pre-validated state; does not
 * reparse ELF headers or inspect page queues.
 */
#ifdef _KERNEL
bool hibernate_page_is_destination(vm_page_t m);
#endif

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

#ifdef _KERNEL
/*
 * hibernate_barrier_prepare: acquire stages 1–7 of the K-5 stability
 * barrier around the SAVE attempt.  On failure, releases all acquired
 * stages in strict reverse order and returns a non-zero errno.
 *
 * On success, *stages_out contains the stage mask for the stages this
 * function acquires.  The caller then releases the bound dump SIM
 * immediately before the step-8 image write (clearing HIB_STAGE_CAM),
 * because a frozen SIM cannot dispatch its own write CCB.  The callout
 * freeze, the BSP preemption/interrupt state, and the physical-page
 * reservation remain held through the write; those, plus stages 1-3, are
 * released by hibernate_barrier_unwind() on the reverse path.
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

/*
 * hibernate_dst_interval_contains / hibernate_dst_page_agrees: H-1 fix --
 * dual-build (kernel + _HIBERNATE_USERLAND_BUILD) predicate core shared by
 * hibernate_page_is_destination() and the production publish-then-verify
 * gate hibernate_writer_runs_verify().  Declared here, outside any
 * #ifdef _KERNEL block, so host-runnable tests can exercise the identical
 * logic the kernel predicate and the K-6 construction-verification path
 * both depend on.  See kern/kern_hibernate.c for full documentation.
 */
bool hibernate_dst_interval_contains(const struct hibernate_attempt *ha,
    vm_paddr_t pa);
bool hibernate_dst_page_agrees(const struct hibernate_attempt *ha,
    const vm_paddr_t *sorted_free, size_t free_count, size_t *free_idx,
    vm_paddr_t arena_start, vm_paddr_t arena_end, vm_paddr_t pa);

int hibernate_probe(struct hibernate_attempt *ha);
bool hibernate_provider_conflicts(const struct hibernate_provider_id *id);
int hibernate_extent_hold(const struct hibernate_provider_id *id,
    uint64_t offset, uint64_t length);
void hibernate_extent_release(const struct hibernate_provider_id *id);

int hibernate_resume_attempt(struct hibernate_attempt *ha);
int hibernate_image_validate(struct hibernate_attempt *ha);
void hibernate_attempt_cleanup(struct hibernate_attempt *ha);

int hibernate_quiesce(struct hibernate_attempt *ha);
int hibernate_quiesce_rollback(struct hibernate_attempt *ha);
int hibernate_stop_cpus(cpuset_t target, cpuset_t *acknowledged);
int hibernate_restart_cpus(cpuset_t acknowledged);

/* K-8-owned stage functions; K-7 provides temporary ENOTSUP bodies. */
int hibernate_meta_read(struct hibernate_attempt *ha);
int hibernate_safe_pages_alloc(struct hibernate_attempt *ha);
int hibernate_payload_read(struct hibernate_attempt *ha);
int hibernate_payload_verify(struct hibernate_attempt *ha);
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

/* Live FACS HardwareSignature; defined in sys/dev/acpica/acpi.c. */
uint64_t acpi_hibernate_facs_signature(void);
void hibernate_provider_release(struct hibernate_attempt *ha);
void hibernate_probe_begin(void);
void hibernate_probe_complete(void);
bool hibernate_probe_active(void);
#endif

typedef int hibernate_image_write_t(void *);

int hibernate_cb_encode(uint8_t *, size_t, const struct hibernate_cb *);
int hibernate_pcb_encode(uint8_t *, size_t, const struct hibernate_pcb *);
int hibernate_xsave_extent(uint64_t,
    const struct hibernate_xsave_component_fact *, size_t, uint32_t *);
int hibernate_writer_plan_assemble(struct hibernate_writer_plan *,
    const struct hibernate_cb *, const struct hibernate_pcb *);
int hibernate_writer_plan_interval_next(struct hibernate_writer_plan *,
    struct hibernate_image_interval *);

/*
 * K-6 task-4: forward-stream callback contracts.
 *
 * hibernate_writer_write_t and hibernate_writer_zero_t are invoked exactly
 * once per iterator interval, in the strictly increasing file-offset order
 * produced by hibernate_writer_plan_interval_next().  Each callback must
 * either (a) complete the full requested logical length and fold exactly
 * those bytes into *crc via hibernate_crc32c_update(), returning 0; or
 * (b) return a nonzero errno without any partial CRC credit.  A transport
 * retry inside the callback is invisible to the caller: no byte is fed to
 * *crc and no cursor advances until the callback itself reports complete
 * logical success.
 *
 * hibernate_writer_rewrite_t is invoked exactly once, after complete
 * iterator coverage of [0, hi_image_length), to perform the sole bounded
 * four-byte provider rewrite of the low half of the encoded hc_crc32c
 * field at image-relative offset cb_crc_offset.  final_crc is the fully
 * finalized value (caller has already applied the closing XOR 0xffffffff).
 * The high four bytes of the encoded field remain zero; no other image
 * byte may change.
 */
typedef int hibernate_writer_write_t(void *arg, uint64_t file_offset,
    uint64_t length, uint32_t *crc);
typedef int hibernate_writer_zero_t(void *arg, uint64_t file_offset,
    uint64_t length, uint32_t *crc);
typedef int hibernate_writer_rewrite_t(void *arg, uint64_t cb_crc_offset,
    uint32_t final_crc);

/*
 * hibernate_writer_plan_stream: drive the sole forward interval iterator
 * over an already-assembled, already-self-decoded plan, dispatching each
 * interval to write_stored or write_zero and folding the running CRC32C
 * strictly in iterator order.  After complete coverage of
 * [0, hi_image_length) (iterator ENOENT) with the iterator cursor exactly
 * equal to hi_image_length, finalizes the CRC with XOR 0xffffffff and
 * calls rewrite() exactly once with the image-relative offset of the low
 * half of hc_crc32c.  Returns 0 only when the full forward stream and the
 * bounded rewrite both succeed; any other return leaves the rewrite
 * uncalled and the image incomplete.  Must be called at most once per
 * plan (the plan's embedded iterator is forward-only).
 */
int hibernate_writer_plan_stream(struct hibernate_writer_plan *plan,
    hibernate_writer_write_t *write_stored, hibernate_writer_zero_t *write_zero,
    hibernate_writer_rewrite_t *rewrite, void *arg);

/*
 * hibernate_writer_payload_start: compute the exact page-aligned
 * payload_start (and, incidentally, the cb/pcb offsets) that
 * hibernate_writer_plan_assemble() will derive for a plan with exactly
 * run_count PT_LOAD runs.  Pure arithmetic, no I/O, no allocation; callers
 * (task-4/5 integration) use this to know where PT_LOAD payload begins
 * before constructing the live run array, without duplicating or
 * second-guessing the assembler's own geometry.  Returns 0 with
 * *payload_start_out set, EINVAL for an out-of-range run_count, or
 * EOVERFLOW/E2BIG propagated from the same checked arithmetic
 * hibernate_writer_plan_assemble() performs.
 */
int hibernate_writer_payload_start(size_t run_count,
    uint64_t *payload_start_out);

#ifdef _KERNEL
/*
 * hibernate_writer_runs_build: construct the maximal SAVEABLE PT_LOAD run
 * set directly from live kernel memory state (task-4 prerequisite).
 *
 * Universe: every page in every vm_phys_segs[] segment ("ingested RAM",
 * the same universe the K-5 capacity check treats as physmem).  A page is
 * omitted from the destination set when it is a member of the locked
 * SAVE-side FREE reservation *res (the exact set captured by
 * vm_phys_hibernate_reserve_all()), or when it falls inside
 * [ha_arena_start, ha_arena_start + ha_arena_size).  Every other page is a
 * destination.  Adjacent destination pages coalesce into maximal runs.
 *
 * free_scratch is caller-owned, preallocated storage of at least
 * res->vr_count entries; this function sorts a copy of the reservation's
 * physical addresses into it to merge-classify against vm_phys_segs in one
 * forward pass.  No allocation occurs.
 *
 * payload_cursor is the image-relative offset immediately after the last
 * fixed object before PT_LOAD payload (i.e. payload_start + xsave_length);
 * it need not be page-aligned on entry.  File offsets are assigned
 * sequentially starting at align_up(payload_cursor, HIB_PAGE_SIZE).  Each
 * run's hwr_source is 0 and hwr_source_offset equals its own destination
 * physical address: because destinations are constructed non-overlapping,
 * this makes source ranges non-overlapping too, satisfying
 * hibernate_writer_plan_assemble()'s alias check without a separate
 * source-object registry.
 *
 * Returns 0 with *run_count_out set on success; EINVAL on a null/malformed
 * argument; EOVERFLOW on checked-arithmetic failure; E2BIG if runs_capacity
 * is insufficient for the live run count.
 */
int hibernate_writer_runs_build(struct hibernate_attempt *ha,
    const struct vm_phys_reservation *res, vm_paddr_t *free_scratch,
    size_t free_scratch_capacity, uint64_t payload_cursor,
    struct hibernate_writer_run *runs, size_t runs_capacity,
    size_t *run_count_out);

/*
 * hibernate_writer_runs_verify: H-1 fix -- publish-then-verify gate.
 *
 * Caller contract: publish ha_dst_intervals/ha_dst_count/ha_dst_valid
 * (from the just-built run set) BEFORE calling this function.  This
 * function then walks every ingested physical page and confirms
 * hibernate_page_is_destination()'s predicate logic
 * (hibernate_dst_interval_contains(), via hibernate_dst_page_agrees())
 * agrees with the independently recomputed FREE/arena classification for
 * every single page.  res and free_scratch must be the same reservation
 * and scratch buffer passed to the preceding hibernate_writer_runs_build()
 * call.
 *
 * Returns 0 when the predicate agrees with construction for every page.
 * On any disagreement or argument error, forces ha_dst_valid = false and
 * returns EINVAL; the caller must refuse the image.
 */
int hibernate_writer_runs_verify(struct hibernate_attempt *ha,
    const struct vm_phys_reservation *res, vm_paddr_t *free_scratch,
    size_t free_scratch_capacity);
#endif /* _KERNEL */

int hibernate_commit_pending(struct hibernate_attempt *,
    hibernate_image_write_t *, void *, const struct hibernate_marker *, bool *);
bool hibernate_s4_commit_gate(bool);
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
	uint8_t xsave_offset[HIBERNATE_PCB_WIDTH_XSAVE_OFFSET];
	uint8_t xsave_enabled_mask[HIBERNATE_PCB_WIDTH_XSAVE_ENABLED_MASK];
	uint8_t reserved_0d0[HIBERNATE_PCB_WIDTH_RESERVED_0D0];
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
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, xsave_offset, HIBERNATE_PCB,
    XSAVE_OFFSET);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, xsave_enabled_mask,
    HIBERNATE_PCB, XSAVE_ENABLED_MASK);
HIBERNATE_LAYOUT_ASSERT(__hibernate_pcb_layout, reserved_0d0, HIBERNATE_PCB,
    RESERVED_0D0);

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
_Static_assert(HIBERNATE_PCB_OFF_RESERVED_0D0 +
	    HIBERNATE_PCB_WIDTH_RESERVED_0D0 ==
	HIBERNATE_PCB_ENCODED_SIZE,
    "PCB collision-free complete coverage");
_Static_assert(HIBERNATE_PCB_ENCODED_SIZE == 1024,
    "PCB encoded size must remain 1024 bytes");
_Static_assert(HIBERNATE_MARKER_OFF_RESERVED_024 +
	    HIBERNATE_MARKER_WIDTH_RESERVED_024 ==
	HIBERNATE_MARKER_ENCODED_SIZE,
    "marker collision-free complete coverage");

#undef HIBERNATE_LAYOUT_ASSERT
#endif /* !_LOCORE */

#endif /* !_SYS_HIBERNATE_H_ */
