/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Production-source host tests for K-8 READ_METADATA: the bounded
 * two-step metadata read (hibernate_meta_read()), its exported pure
 * bound predicates, and the destination-view builder
 * (hibernate_dst_view_build(), exercised indirectly through the K-7
 * resume coordinator because it is file-local).
 *
 * The image fixture builder (build_image_ex() and its small encoding
 * helpers) is a local copy of the one in hibernate_format_test.c,
 * intentionally not shared (design 035 SS6.1 / grug 4).
 */

#include <sys/param.h>
#include <sys/elf_common.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Constants matching the ABI 1 wire format (local copy)                */
/* ------------------------------------------------------------------ */

#define HIB_PAGE_SIZE 4096U
#define EHDR_SIZE     64U
#define PHDR_SIZE     56U

#define PHDR_OFF_P_TYPE	  0
#define PHDR_OFF_P_OFFSET 8
#define PHDR_OFF_P_PADDR  24
#define PHDR_OFF_P_FILESZ 32
#define PHDR_OFF_P_MEMSZ  40

#define EHDR_OFF_EI_MAG0     0
#define EHDR_OFF_EI_CLASS    4
#define EHDR_OFF_EI_DATA     5
#define EHDR_OFF_EI_VERSION  6
#define EHDR_OFF_E_TYPE	     16
#define EHDR_OFF_E_MACHINE   18
#define EHDR_OFF_E_VERSION   20
#define EHDR_OFF_E_PHOFF     32
#define EHDR_OFF_E_EHSIZE    52
#define EHDR_OFF_E_PHENTSIZE 54
#define EHDR_OFF_E_PHNUM     56

/* ------------------------------------------------------------------ */
/* Local fixture builder (copy of hibernate_format_test.c's; SS6.1)      */
/* ------------------------------------------------------------------ */

static uint64_t
align_up(uint64_t v, uint64_t align)
{
	return ((v + align - 1) & ~(align - 1));
}

static void
le16enc_p(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
}

static void
le32enc_p(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void
le64enc_p(uint8_t *p, uint64_t v)
{
	le32enc_p(p, (uint32_t)(v));
	le32enc_p(p + 4, (uint32_t)(v >> 32));
}

static void
write_phdr(uint8_t *buf, uint64_t off, uint32_t p_type, uint64_t p_offset,
    uint64_t p_filesz, uint64_t p_memsz, uint64_t p_paddr)
{
	uint8_t *ph = buf + off;
	memset(ph, 0, PHDR_SIZE);
	le32enc_p(ph + PHDR_OFF_P_TYPE, p_type);
	le64enc_p(ph + PHDR_OFF_P_OFFSET, p_offset);
	le64enc_p(ph + PHDR_OFF_P_FILESZ, p_filesz);
	le64enc_p(ph + PHDR_OFF_P_MEMSZ, p_memsz);
	le64enc_p(ph + PHDR_OFF_P_PADDR, p_paddr);
}

static void
write_ehdr(uint8_t *buf, uint16_t phnum, uint64_t phoff)
{
	memset(buf, 0, EHDR_SIZE);
	buf[EHDR_OFF_EI_MAG0 + 0] = 0x7f;
	buf[EHDR_OFF_EI_MAG0 + 1] = 'E';
	buf[EHDR_OFF_EI_MAG0 + 2] = 'L';
	buf[EHDR_OFF_EI_MAG0 + 3] = 'F';
	buf[EHDR_OFF_EI_CLASS] = ELFCLASS64;
	buf[EHDR_OFF_EI_DATA] = ELFDATA2LSB;
	buf[EHDR_OFF_EI_VERSION] = EV_CURRENT;
	le16enc_p(buf + EHDR_OFF_E_TYPE, (uint16_t)ET_FREEBSD_HIBERNATE_IMAGE);
	le16enc_p(buf + EHDR_OFF_E_MACHINE, EM_X86_64);
	le32enc_p(buf + EHDR_OFF_E_VERSION, EV_CURRENT);
	le64enc_p(buf + EHDR_OFF_E_PHOFF, phoff);
	le16enc_p(buf + EHDR_OFF_E_EHSIZE, (uint16_t)EHDR_SIZE);
	le16enc_p(buf + EHDR_OFF_E_PHENTSIZE, (uint16_t)PHDR_SIZE);
	le16enc_p(buf + EHDR_OFF_E_PHNUM, phnum);
}

static void
write_cb(uint8_t *buf, uint64_t cb_offset, uint64_t image_length,
    uint64_t payload_start, uint16_t phnum, uint64_t dest_pages,
    uint64_t pcb_offset)
{
	uint8_t *p = buf + cb_offset;
	memset(p, 0, HIBERNATE_CB_ENCODED_SIZE);

	le64enc_p(p + HIBERNATE_CB_OFF_MAGIC, UINT64_C(0xdeadbeefcafe0001));
	le32enc_p(p + HIBERNATE_CB_OFF_VERSION, HCB_VERSION);
	le32enc_p(p + HIBERNATE_CB_OFF_ENCODED_SIZE, HIBERNATE_CB_ENCODED_SIZE);
	le64enc_p(p + HIBERNATE_CB_OFF_PAGE_SIZE, HIB_PAGE_SIZE);
	le64enc_p(p + HIBERNATE_CB_OFF_PHYSMEM_BYTES, UINT64_C(0x100000000));
	le64enc_p(p + HIBERNATE_CB_OFF_IMAGE_LENGTH, image_length);
	le64enc_p(p + HIBERNATE_CB_OFF_PAYLOAD_START, payload_start);
	le64enc_p(p + HIBERNATE_CB_OFF_DESTINATION_PAGES, dest_pages);
	le64enc_p(p + HIBERNATE_CB_OFF_SOURCE_VECTOR_BYTES,
	    (dest_pages + 7) / 8);
	le64enc_p(p + HIBERNATE_CB_OFF_ARENA_START, UINT64_C(0x200000));
	le64enc_p(p + HIBERNATE_CB_OFF_ARENA_SIZE, UINT64_C(0x400000));
	le64enc_p(p + HIBERNATE_CB_OFF_FACS_HARDWARE_SIGNATURE, 0);
	le64enc_p(p + HIBERNATE_CB_OFF_SAVED_PCB_OFFSET, pcb_offset);
	le64enc_p(p + HIBERNATE_CB_OFF_SAVED_PCB_SIZE,
	    HIBERNATE_PCB_ENCODED_SIZE);
	le64enc_p(p + HIBERNATE_CB_OFF_ELF_PHNUM, phnum);
	le64enc_p(p + HIBERNATE_CB_OFF_METADATA_LENGTH, payload_start);
	le64enc_p(p + HIBERNATE_CB_OFF_CRC32C, 0);
	le64enc_p(p + HIBERNATE_CB_OFF_RESTORE_FOOTPRINT_PAGES, 4);
	le64enc_p(p + HIBERNATE_CB_OFF_MACHINE_FLAGS, 0);
	le64enc_p(p + HIBERNATE_CB_OFF_DESTINATION_BYTES,
	    dest_pages * HIB_PAGE_SIZE);
	le64enc_p(p + HIBERNATE_CB_OFF_COPY_LIST_BOUND, 0x42);
}

static void
write_pcb(uint8_t *buf, uint64_t pcb_offset, uint64_t xsave_offset)
{
	uint8_t *p = buf + pcb_offset;
	memset(p, 0, HIBERNATE_PCB_ENCODED_SIZE);

	le32enc_p(p + HIBERNATE_PCB_OFF_VERSION, 1);
	le32enc_p(p + HIBERNATE_PCB_OFF_ENCODED_SIZE,
	    HIBERNATE_PCB_ENCODED_SIZE);
	le64enc_p(p + HIBERNATE_PCB_OFF_CR0, UINT64_C(0x80050033));
	le64enc_p(p + HIBERNATE_PCB_OFF_CR3, UINT64_C(0x1000));
	le64enc_p(p + HIBERNATE_PCB_OFF_CR4, UINT64_C(0x6f0));
	le64enc_p(p + HIBERNATE_PCB_OFF_EFER, UINT64_C(0xd01));
	le64enc_p(p + HIBERNATE_PCB_OFF_PAT, UINT64_C(0x0007040600070406));
	le64enc_p(p + HIBERNATE_PCB_OFF_XCR0,
	    HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE);
	le64enc_p(p + HIBERNATE_PCB_OFF_RFLAGS, UINT64_C(0x202));
	le64enc_p(p + HIBERNATE_PCB_OFF_RSP, UINT64_C(0xffff800000100000));
	le64enc_p(p + HIBERNATE_PCB_OFF_RIP, UINT64_C(0xffffffff80100000));
	le64enc_p(p + HIBERNATE_PCB_OFF_R12_PCB_PA, UINT64_C(0x5000));
	le16enc_p(p + HIBERNATE_PCB_OFF_GDTR_LIMIT, 0x3f);
	le64enc_p(p + HIBERNATE_PCB_OFF_GDTR_BASE,
	    UINT64_C(0xffffffff81000000));
	le16enc_p(p + HIBERNATE_PCB_OFF_IDTR_LIMIT, 0xfff);
	le64enc_p(p + HIBERNATE_PCB_OFF_IDTR_BASE,
	    UINT64_C(0xffffffff81100000));
	le64enc_p(p + HIBERNATE_PCB_OFF_FSBASE, 0);
	le64enc_p(p + HIBERNATE_PCB_OFF_GSBASE, UINT64_C(0xffffffff81200000));
	le64enc_p(p + HIBERNATE_PCB_OFF_KGSBASE, 0);
	le64enc_p(p + HIBERNATE_PCB_OFF_STAR, UINT64_C(0x0030002800000000));
	le64enc_p(p + HIBERNATE_PCB_OFF_LSTAR, UINT64_C(0xffffffff81300000));
	le64enc_p(p + HIBERNATE_PCB_OFF_CSTAR, 0);
	le64enc_p(p + HIBERNATE_PCB_OFF_SFMASK, UINT64_C(0x4700));
	le64enc_p(p + HIBERNATE_PCB_OFF_KERNEL_GSBASE,
	    UINT64_C(0xffffffff81200000));
	le32enc_p(p + HIBERNATE_PCB_OFF_XSAVE_LENGTH, 576);
	le32enc_p(p + HIBERNATE_PCB_OFF_XSAVE_FORMAT, HIBERNATE_XSAVE_FORMAT);
	le64enc_p(p + HIBERNATE_PCB_OFF_XSAVE_OFFSET, xsave_offset);
	le64enc_p(p + HIBERNATE_PCB_OFF_XSAVE_ENABLED_MASK,
	    HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE);
}

/*
 * build_image_ex: build a valid ABI 1 metadata prefix.  Returns
 * payload_start.  PT_LOAD entries are placed back-to-back starting at
 * physical address 0 (paddr[i] = i * HIB_PAGE_SIZE), so for n_loads > 1
 * every pair of consecutive entries is touching (p_paddr ==
 * previous end) -- deliberately, so one fixture can exercise both the
 * READ_METADATA bound tests and the VALIDATE-stage coalescing test
 * (hibernate_dst_view_build() must merge them, or
 * hibernate_image_validate() step 4 would refuse the raw adjacent
 * pairs).
 */
static uint64_t
build_image_ex(uint8_t *buf, size_t bufsize, uint16_t n_loads,
    uint64_t image_length, int include_xsave)
{
	uint64_t phdr_table_end, cb_offset, pcb_offset, payload_start;
	uint64_t xsave_offset, xsave_len, load_base, file_off;
	uint16_t phnum, idx;
	uint64_t dest_pages = n_loads;
	uint16_t i;

	phnum = 2 + n_loads;
	if (include_xsave)
		phnum += 1;

	memset(buf, 0, bufsize);

	phdr_table_end = EHDR_SIZE + (uint64_t)phnum * PHDR_SIZE;
	cb_offset = align_up(phdr_table_end, HIB_PAGE_SIZE);
	pcb_offset = align_up(cb_offset + HIBERNATE_CB_ENCODED_SIZE,
	    HIB_PAGE_SIZE);
	payload_start = align_up(pcb_offset + HIBERNATE_PCB_ENCODED_SIZE,
	    HIB_PAGE_SIZE);

	xsave_len = 576;
	xsave_offset = payload_start;
	file_off = payload_start;
	if (include_xsave)
		file_off += xsave_len;
	load_base = align_up(file_off, HIB_PAGE_SIZE);

	ATF_REQUIRE(payload_start <= bufsize);
	ATF_REQUIRE(image_length >=
	    load_base + (uint64_t)n_loads * HIB_PAGE_SIZE);

	write_ehdr(buf, phnum, EHDR_SIZE);

	write_phdr(buf, EHDR_SIZE + 0 * PHDR_SIZE, PT_FREEBSD_HIBERNATE_CB,
	    cb_offset, HIBERNATE_CB_ENCODED_SIZE, HIBERNATE_CB_ENCODED_SIZE, 0);
	write_phdr(buf, EHDR_SIZE + 1 * PHDR_SIZE, PT_FREEBSD_HIBERNATE_PCB,
	    pcb_offset, HIBERNATE_PCB_ENCODED_SIZE, HIBERNATE_PCB_ENCODED_SIZE,
	    0);
	idx = 2;
	if (include_xsave) {
		write_phdr(buf, EHDR_SIZE + (uint64_t)idx * PHDR_SIZE,
		    PT_FREEBSD_HIBERNATE_XSAVE, xsave_offset, xsave_len,
		    xsave_len, 0);
		idx++;
	}
	for (i = 0; i < n_loads; i++) {
		uint64_t off = load_base + (uint64_t)i * HIB_PAGE_SIZE;
		uint64_t paddr = (uint64_t)i * HIB_PAGE_SIZE;
		write_phdr(buf, EHDR_SIZE + (uint64_t)idx * PHDR_SIZE,
		    PT_LOAD, off, HIB_PAGE_SIZE, HIB_PAGE_SIZE, paddr);
		idx++;
	}

	write_cb(buf, cb_offset, image_length, payload_start, phnum, dest_pages,
	    pcb_offset);
	write_pcb(buf, pcb_offset, xsave_offset);

	return (payload_start);
}

/* ------------------------------------------------------------------ */
/* Read-seam infrastructure                                              */
/* ------------------------------------------------------------------ */

#define SEAM_MAX_CALLS 8

struct seam_call {
	uint64_t rel;
	uint64_t prov_off;
	size_t length;
};

struct seam_state {
	const uint8_t *image;	/* image-relative backing bytes */
	size_t image_bufsize;
	uint64_t base;		/* I - mediaoffset */
	uint64_t max_rel;	/* payload_start bound; 0 == no bound check */
	struct seam_call calls[SEAM_MAX_CALLS];
	unsigned int call_count;
	unsigned int fail_at;	/* 1-based call index to fail; 0 = never */
	int fail_errno;
};

static struct seam_state g_seam;

static void
seam_reset(void)
{
	memset(&g_seam, 0, sizeof(g_seam));
}

static int
test_read_seam(struct hibernate_attempt *ha, uint64_t prov_off, void *buf,
    size_t length)
{
	uint64_t rel;

	(void)ha;
	ATF_REQUIRE(g_seam.call_count < SEAM_MAX_CALLS);
	ATF_REQUIRE(prov_off >= g_seam.base);
	rel = prov_off - g_seam.base;

	g_seam.calls[g_seam.call_count].rel = rel;
	g_seam.calls[g_seam.call_count].prov_off = prov_off;
	g_seam.calls[g_seam.call_count].length = length;
	g_seam.call_count++;

	/*
	 * Acceptance invariant: READ_METADATA never requests a byte at or
	 * beyond payload_start.
	 */
	if (g_seam.max_rel != 0)
		ATF_REQUIRE(rel + length <= g_seam.max_rel);

	if (g_seam.fail_at != 0 && g_seam.call_count == g_seam.fail_at)
		return (g_seam.fail_errno != 0 ? g_seam.fail_errno : EIO);

	ATF_REQUIRE(rel + length <= g_seam.image_bufsize);
	memcpy(buf, g_seam.image + rel, length);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Fixture: hibernate_attempt + dumperinfo wired to the read seam        */
/* ------------------------------------------------------------------ */

#define FIXTURE_IMAGE_BUFSIZE 70000

struct restore_fixture {
	uint8_t image[FIXTURE_IMAGE_BUFSIZE];
	struct dumperinfo di;
	struct hibernate_attempt ha;
};

/*
 * fixture_init: wire ha/di for hibernate_meta_read()/hibernate_stage_
 * read(), with image-relative offset I = mediaoffset + i_rel and
 * hm_image_length = image_length.  Installs the read seam and bounds
 * it to max_rel (normally the fixture's own payload_start once known).
 */
static void
fixture_init(struct restore_fixture *f, uint64_t mediaoffset,
    uint64_t i_rel, uint64_t image_length)
{

	memset(f, 0, sizeof(*f));
	f->di.mediaoffset = (off_t)mediaoffset;
	f->di.mediasize = (off_t)(mediaoffset + image_length + 0x100000);
	f->ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	f->ha.ha_dumper = &f->di;
	f->ha.ha_has_provider = true;
	f->ha.ha_provider_size = mediaoffset + i_rel + image_length + 0x100000;
	f->ha.ha_marker_result.class = HMC_PENDING;
	f->ha.ha_marker_result.marker.hm_image_offset = mediaoffset + i_rel;
	f->ha.ha_marker_result.marker.hm_image_length = image_length;

	seam_reset();
	g_seam.image = f->image;
	g_seam.image_bufsize = FIXTURE_IMAGE_BUFSIZE;
	g_seam.base = i_rel;
	hibernate_test_provider_read_fn = test_read_seam;
}

static void
fixture_fini(void)
{

	hibernate_test_provider_read_fn = NULL;
	seam_reset();
}

/* ------------------------------------------------------------------ */
/* READ_METADATA step-boundary tests (design 035 SS6.2)                 */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(read_metadata_minimal);
ATF_TC_BODY(read_metadata_minimal, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps;

	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	ATF_CHECK_EQ(12288, ps);
	g_seam.max_rel = ps;

	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(0, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(12288, meta_len);

	/* Exactly two logical reads: (0,64) and (64, payload_start-64). */
	ATF_CHECK_EQ(2, g_seam.call_count);
	ATF_CHECK_EQ(0, g_seam.calls[0].rel);
	ATF_CHECK_EQ(64, g_seam.calls[0].length);
	ATF_CHECK_EQ(64, g_seam.calls[1].rel);
	ATF_CHECK_EQ(12224, g_seam.calls[1].length);

	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(read_metadata_900_phdr);
ATF_TC_BODY(read_metadata_900_phdr, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps;

	/*
	 * 897 PT_LOAD pages need the full image_length to cover their
	 * (unread) payload bytes too, even though metadata reading only
	 * ever touches [0, payload_start) of the backing buffer.
	 */
	fixture_init(&f, 0, 0, UINT64_C(0x400000));
	/* CB + PCB + 897 PT_LOAD + 1 XSAVE == 900 program headers. */
	ps = build_image_ex(f.image, sizeof(f.image), 897,
	    UINT64_C(0x400000), 1);
	ATF_CHECK_EQ(61440, ps);
	ATF_CHECK(ps <= 64029);
	g_seam.max_rel = ps;

	meta_len = 0;
	ATF_CHECK_EQ(0, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(61440, meta_len);
	ATF_CHECK(meta_len <= 64029);
	ATF_CHECK_EQ(2, g_seam.call_count);
	ATF_CHECK_EQ(64, g_seam.calls[1].rel);
	ATF_CHECK_EQ(ps - 64, g_seam.calls[1].length);

	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(read_metadata_phnum_out_of_range);
ATF_TC_BODY(read_metadata_phnum_out_of_range, tc)
{
	struct restore_fixture f;
	size_t meta_len;

	/* e_phnum == 901: patch the 16-bit field after a valid build. */
	fixture_init(&f, 0, 0, 0x100000);
	(void)build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	le16enc_p(f.image + EHDR_OFF_E_PHNUM, 901);
	g_seam.max_rel = 0; /* step 1 only; bound not yet known */
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	ATF_CHECK_EQ(1, g_seam.call_count);
	fixture_fini();

	/* e_phnum == 0. */
	fixture_init(&f, 0, 0, 0x100000);
	(void)build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	le16enc_p(f.image + EHDR_OFF_E_PHNUM, 0);
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	ATF_CHECK_EQ(1, g_seam.call_count);
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(meta_check_phdr_end_predicate);
ATF_TC_BODY(meta_check_phdr_end_predicate, tc)
{

	/* The 900-phdr fixture's own ELF+phdr-table length. */
	ATF_CHECK_EQ(0, hibernate_meta_check_phdr_end(50464));
	ATF_CHECK_EQ(E2BIG, hibernate_meta_check_phdr_end(50465));
}

ATF_TC_WITHOUT_HEAD(meta_check_total_predicate);
ATF_TC_BODY(meta_check_total_predicate, tc)
{

	ATF_CHECK_EQ(0, hibernate_meta_check_total(64029, 65536, 1000000));
	ATF_CHECK_EQ(EINVAL, hibernate_meta_check_total(65536, 65536,
	    1000000));
	ATF_CHECK_EQ(EINVAL, hibernate_meta_check_total(65537, 65536,
	    1000000));
	ATF_CHECK_EQ(EINVAL, hibernate_meta_check_total(0, 65536, 1000000));
	/* buf_max smaller than total: E2BIG. */
	ATF_CHECK_EQ(E2BIG, hibernate_meta_check_total(12288, 12000,
	    1000000));
	/* total above the image length: EINVAL. */
	ATF_CHECK_EQ(EINVAL, hibernate_meta_check_total(12288, 65536, 100));
}

ATF_TC_WITHOUT_HEAD(read_metadata_buf_max_and_length_bounds);
ATF_TC_BODY(read_metadata_buf_max_and_length_bounds, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps;

	/* buf_max < payload_start: E2BIG, exactly one read. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	ATF_CHECK_EQ(12288, ps);
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(E2BIG, hibernate_meta_read(&f.ha, f.image, ps - 1,
	    &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	ATF_CHECK_EQ(1, g_seam.call_count);
	fixture_fini();

	/* payload_start > image length (hm_image_length): EINVAL, 1 read. */
	fixture_init(&f, 0, 0, ps + 1);
	/*
	 * Rebuild against a short marker length directly (bypass
	 * build_image_ex's own internal consistency requirement by
	 * reusing the already-built image bytes and only shrinking the
	 * marker's hm_image_length below payload_start).
	 */
	(void)build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	f.ha.ha_marker_result.marker.hm_image_length = ps - 1;
	g_seam.max_rel = 0;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	ATF_CHECK_EQ(1, g_seam.call_count);
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(read_metadata_disagreement);
ATF_TC_BODY(read_metadata_disagreement, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps;

	/* hc_metadata_length off by +4096 from the derived payload_start. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	{
		uint64_t cb_off = align_up(
		    EHDR_SIZE + (uint64_t)(2 + 1 + 1) * PHDR_SIZE,
		    HIB_PAGE_SIZE);
		le64enc_p(f.image + cb_off + HIBERNATE_CB_OFF_METADATA_LENGTH,
		    ps + 4096);
	}
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();

	/* hc_elf_phnum disagrees with the real e_phnum. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	{
		uint64_t cb_off = align_up(
		    EHDR_SIZE + (uint64_t)(2 + 1 + 1) * PHDR_SIZE,
		    HIB_PAGE_SIZE);
		le64enc_p(f.image + cb_off + HIBERNATE_CB_OFF_ELF_PHNUM, 5);
	}
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();

	/* CB hc_image_length disagrees with the marker's hm_image_length. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	f.ha.ha_marker_result.marker.hm_image_length = 0x100000 - 4096;
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(read_metadata_nonzero_padding);
ATF_TC_BODY(read_metadata_nonzero_padding, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps, phdr_end, cb_off, cb_end, pcb_off, pcb_end;

	/* n_loads=1 (phnum=4) leaves all three padding runs non-empty. */
	phdr_end = EHDR_SIZE + (uint64_t)4 * PHDR_SIZE;
	cb_off = align_up(phdr_end, HIB_PAGE_SIZE);
	cb_end = cb_off + HIBERNATE_CB_ENCODED_SIZE;
	pcb_off = align_up(cb_end, HIB_PAGE_SIZE);
	pcb_end = pcb_off + HIBERNATE_PCB_ENCODED_SIZE;

	/* Run 1: phdr_table_end .. cb_offset. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	ATF_REQUIRE(phdr_end < cb_off);
	f.image[phdr_end] = 1;
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();

	/* Run 2: cb_end .. pcb_offset. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	ATF_REQUIRE(cb_end < pcb_off);
	f.image[cb_end] = 1;
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();

	/* Run 3: pcb_end .. payload_start (final post-PCB padding). */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	ATF_REQUIRE(pcb_end < ps);
	f.image[pcb_end] = 1;
	g_seam.max_rel = ps;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EINVAL, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(read_metadata_read_faults);
ATF_TC_BODY(read_metadata_read_faults, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps;

	/* Fault on the first (step-1) read: no second read is attempted. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	g_seam.max_rel = ps;
	g_seam.fail_at = 1;
	g_seam.fail_errno = EIO;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EIO, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	ATF_CHECK_EQ(1, g_seam.call_count);
	fixture_fini();

	/* Fault on the second (step-2) read. */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	g_seam.max_rel = ps;
	g_seam.fail_at = 2;
	g_seam.fail_errno = EIO;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EIO, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	ATF_CHECK_EQ(2, g_seam.call_count);
	fixture_fini();

	/*
	 * Short read: the provider-read contract reports any incomplete
	 * transfer as an error after draining, so a short read is
	 * represented here (at the host level) the same way a backend
	 * error is: the seam returns a nonzero errno for that call rather
	 * than filling buf.  (The physical partial-sector drain logic
	 * lives in hibernate_provider_read(), geom_hibernate.c, which is
	 * kernel-only and is covered by the GENERIC build, not this seam.)
	 */
	fixture_init(&f, 0, 0, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	g_seam.max_rel = ps;
	g_seam.fail_at = 2;
	g_seam.fail_errno = EIO;
	meta_len = 0xdeadbeef;
	ATF_CHECK_EQ(EIO, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(0, meta_len);
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(read_metadata_nonzero_mediaoffset);
ATF_TC_BODY(read_metadata_nonzero_mediaoffset, tc)
{
	struct restore_fixture f;
	size_t meta_len;
	uint64_t ps, mediaoffset, i_rel;

	/*
	 * H2 (design 035 SS3.2): I is in dumper address space; prov_off
	 * must equal (I - mediaoffset) + rel.  Use a non-zero, non-trivial
	 * mediaoffset and image offset.
	 */
	mediaoffset = 0x8000;
	i_rel = 0x4000;
	fixture_init(&f, mediaoffset, i_rel, 0x100000);
	ps = build_image_ex(f.image, sizeof(f.image), 1, 0x100000, 1);
	g_seam.max_rel = ps;

	meta_len = 0;
	ATF_CHECK_EQ(0, hibernate_meta_read(&f.ha, f.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	ATF_CHECK_EQ(ps, meta_len);
	ATF_CHECK_EQ(2, g_seam.call_count);

	/* prov_off == (I - mediaoffset) + rel == i_rel + rel. */
	ATF_CHECK_EQ(i_rel + 0, g_seam.calls[0].prov_off);
	ATF_CHECK_EQ(i_rel + 64, g_seam.calls[1].prov_off);
	ATF_CHECK_EQ(0, g_seam.calls[0].rel);
	ATF_CHECK_EQ(64, g_seam.calls[1].rel);

	fixture_fini();
}

/* ------------------------------------------------------------------ */
/* hibernate_dst_view_build(), exercised via the K-7 coordinator        */
/* (it is file-local; it cannot be called directly from this TU).       */
/* ------------------------------------------------------------------ */

#define COORD_VALID_ARENA_START	UINT64_C(0x200000)
#define COORD_VALID_ARENA_SIZE	UINT64_C(0x400000)

static int
coord_cpu_validate(const struct hibernate_pcb *pcb, bool *refuse_la57,
    bool *refuse_mtrr)
{

	(void)pcb;
	*refuse_la57 = false;
	*refuse_mtrr = false;
	return (0);
}

static int
coord_probe_pending(struct hibernate_attempt *ha)
{

	ha->ha_marker_result.class = HMC_PENDING;
	ha->ha_marker_result.error = 0;
	ha->ha_marker_result.marker.hm_magic = HIBERNATE_MARKER_MAGIC;
	ha->ha_marker_result.marker.hm_version = HIBERNATE_MARKER_VERSION;
	ha->ha_marker_result.marker.hm_state = HIBERNATE_MARKER_STATE_PENDING;
	return (0);
}

static void
coord_reset_seams(void)
{

	hibernate_test_probe_fn = NULL;
	hibernate_test_provider_release_fn = NULL;
	hibernate_test_quiesce_rollback_fn = NULL;
	hibernate_test_restart_cpus_fn = NULL;
	hibernate_test_owner_rollback_fn = NULL;
	hibernate_test_amd64_cpu_validate = NULL;
	hibernate_test_provider_read_fn = NULL;
}

/*
 * coordinator_destination_coalescing: with n_loads adjacent PT_LOAD
 * entries (paddr[i] == i * HIB_PAGE_SIZE, so each p_paddr equals the
 * previous entry's end), hibernate_image_validate() step 4 refuses any
 * pair of *separate* published intervals with start <= prev_end.  The
 * coordinator only reaches ALLOCATE (still ENOTSUP) if
 * hibernate_dst_view_build() coalesced the touching raw intervals into
 * one before VALIDATE ran, so success in reaching ALLOCATE is a direct,
 * production-path proof of the coalescing requirement (design 035 H4).
 */
ATF_TC_WITHOUT_HEAD(coordinator_destination_coalescing);
ATF_TC_BODY(coordinator_destination_coalescing, tc)
{
	struct restore_fixture f;
	int error;

	fixture_init(&f, 0, 0, 0x100000);
	(void)build_image_ex(f.image, sizeof(f.image), 3, 0x100000, 1);
	g_seam.max_rel = 0; /* coordinator drives its own reads */

	f.ha.ha_dumper = &f.di;
	hibernate_test_probe_fn = coord_probe_pending;
	hibernate_test_amd64_cpu_validate = coord_cpu_validate;
	hibernate_test_facs_signature = 0;
	hibernate_test_physmem_bytes = UINT64_C(0x100000000);

	hibernate_arena_reset();
	ATF_REQUIRE_EQ(0, hibernate_arena_reserve(COORD_VALID_ARENA_START,
	    COORD_VALID_ARENA_SIZE));

	error = hibernate_resume_attempt(&f.ha);

	/*
	 * ALLOCATE is still an ENOTSUP stub (task-3); reaching it proves
	 * READ_METADATA, VALIDATE (decode + dst_view_build + arena claim +
	 * image_validate) all succeeded first.
	 */
	ATF_CHECK_EQ(ENOTSUP, error);
	ATF_CHECK_EQ(HIB_RESUME_ALLOCATE,
	    hibernate_resume_stage_log[hibernate_resume_stage_log_length - 1]);

	coord_reset_seams();
	fixture_fini();
}

/* ------------------------------------------------------------------ */
/* K-8 ALLOCATE (H7) tests: a recording page-backend seam.             */
/*                                                                      */
/* hib_pages_reserve()/hib_pages_map()/hib_pages_release() are         */
/* entirely delegated to these seams in the userland build (H1), so    */
/* the literal vm_phys_hibernate_reserve_count() success predicate      */
/* (0 && vr_count == P) is proven by code inspection plus the K-5      */
/* vm_phys_hib_fixture_test.c fixture and the GENERIC kernel build,     */
/* not by this file.  What IS host-testable, and is tested here, is    */
/* every portable H7 step built on top of that seam: the X > 1 E2BIG   */
/* refusal, the direct verification of S (count/alignment/dst/arena/   */
/* uniqueness/aux-intersect-src), the source-PA vector placement        */
/* (independently readable through the same backing pool the map seam  */
/* hands out), and H11 release/idempotence/accounting balance.          */
/* ------------------------------------------------------------------ */

#define PGSEAM_POOL_MAX	 128
#define PGSEAM_POOL_BASE ((vm_paddr_t)0x20000000)

static uint8_t pgseam_pool[PGSEAM_POOL_MAX][HIB_PAGE_SIZE];

struct pgseam_state {
	unsigned int reserve_calls;
	unsigned int reserve_fail_at;	/* 1-based; 0 = never */
	int reserve_fail_errno;
	int next_slot;
	bool dup_within_call;		/* hp_pa[1] = hp_pa[0] on dup_call */
	unsigned int dup_call;
	bool override_active;		/* hp_pa[override_idx] = value */
	unsigned int override_call;
	size_t override_idx;
	vm_paddr_t override_value;
	unsigned int release_calls;
	u_long last_release_count;
	u_long last_release_wired;
	unsigned int map_calls;
};

static struct pgseam_state g_pg;

static void
pgseam_reset(void)
{

	memset(&g_pg, 0, sizeof(g_pg));
	memset(pgseam_pool, 0, sizeof(pgseam_pool));
}

static int
pgseam_reserve(struct hibernate_attempt *ha, size_t count,
    struct hib_page_set *set)
{
	size_t i;

	(void)ha;
	g_pg.reserve_calls++;
	if (g_pg.reserve_fail_at != 0 &&
	    g_pg.reserve_calls == g_pg.reserve_fail_at)
		return (g_pg.reserve_fail_errno != 0 ?
		    g_pg.reserve_fail_errno : ENOMEM);
	if ((size_t)g_pg.next_slot + count > PGSEAM_POOL_MAX)
		return (ENOMEM);

	set->hp_pa = calloc(count, sizeof(vm_paddr_t));
	if (set->hp_pa == NULL)
		return (ENOMEM);
	for (i = 0; i < count; i++)
		set->hp_pa[i] = PGSEAM_POOL_BASE +
		    (uint64_t)(g_pg.next_slot++) * HIB_PAGE_SIZE;

	if (g_pg.dup_within_call && g_pg.dup_call == g_pg.reserve_calls &&
	    count >= 2)
		set->hp_pa[1] = set->hp_pa[0];
	if (g_pg.override_active && g_pg.override_call == g_pg.reserve_calls &&
	    g_pg.override_idx < count)
		set->hp_pa[g_pg.override_idx] = g_pg.override_value;

	set->hp_count = count;
	set->hp_wired = count;
	return (0);
}

static void *
pgseam_map(vm_paddr_t pa)
{
	uint64_t slot;

	if (pa < PGSEAM_POOL_BASE)
		return (NULL);
	slot = (pa - PGSEAM_POOL_BASE) / HIB_PAGE_SIZE;
	if (slot >= PGSEAM_POOL_MAX)
		return (NULL);
	g_pg.map_calls++;
	return (pgseam_pool[slot]);
}

static void
pgseam_release(struct hib_page_set *set)
{
	u_long i;

	g_pg.release_calls++;
	g_pg.last_release_count = set->hp_count;
	g_pg.last_release_wired = set->hp_wired;
	/* Simulate the kernel's wipe-on-release (pagezero). */
	for (i = 0; i < set->hp_count; i++) {
		void *va = pgseam_map(set->hp_pa[i]);

		if (va != NULL)
			memset(va, 0, HIB_PAGE_SIZE);
	}
	set->hp_count = 0;
	set->hp_wired = 0;
	/*
	 * set->hp_pa itself is hib_free()d later by
	 * hibernate_safe_pages_free().
	 */
}

struct alloc_fixture {
	struct hibernate_attempt ha;
	vm_paddr_t dst_intervals[2];
	uint8_t prefix_byte;
};

#define ALLOC_FIXTURE_DST_START ((vm_paddr_t)0x1000)
#define ALLOC_FIXTURE_DST_END	((vm_paddr_t)0x2000)
#define ALLOC_FIXTURE_ARENA_START ((vm_paddr_t)0x3000)
#define ALLOC_FIXTURE_ARENA_SIZE  ((uint64_t)0x1000)

static void
alloc_fixture_init(struct alloc_fixture *f, uint64_t p_pages,
    uint64_t xsave_length)
{

	memset(f, 0, sizeof(*f));
	f->ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	f->ha.ha_has_metadata = true;
	f->ha.ha_image.hi_prefix = &f->prefix_byte;
	f->ha.ha_image.hi_destination_pages = p_pages;
	f->ha.ha_image.hi_xsave_length = xsave_length;

	f->dst_intervals[0] = ALLOC_FIXTURE_DST_START;
	f->dst_intervals[1] = ALLOC_FIXTURE_DST_END;
	f->ha.ha_dst_intervals = f->dst_intervals;
	f->ha.ha_dst_count = 1;
	f->ha.ha_dst_valid = true;

	f->ha.ha_arena_start = ALLOC_FIXTURE_ARENA_START;
	f->ha.ha_arena_size = ALLOC_FIXTURE_ARENA_SIZE;

	hibernate_test_pages_reserve_fn = pgseam_reserve;
	hibernate_test_pages_map_fn = pgseam_map;
	hibernate_test_pages_release_fn = pgseam_release;
	pgseam_reset();
}

static void
alloc_fixture_fini(void)
{

	hibernate_test_pages_reserve_fn = NULL;
	hibernate_test_pages_map_fn = NULL;
	hibernate_test_pages_release_fn = NULL;
	hibernate_test_alloc_fail_after = 0;
	pgseam_reset();
}

/*
 * V (vector pages) for P destination pages, matching
 * hibernate_safe_pages_alloc()'s own derivation (design 035 SS4.2 step 2).
 */
static uint64_t
expected_vector_pages(uint64_t p_pages)
{
	uint64_t bytes = p_pages * 8;

	return ((bytes + HIB_PAGE_SIZE - 1) / HIB_PAGE_SIZE);
}

ATF_TC_WITHOUT_HEAD(allocate_success_basic);
ATF_TC_BODY(allocate_success_basic, tc)
{
	struct alloc_fixture f;
	uint64_t p_pages, v_pages, per_page;
	size_t i;

	p_pages = 3;
	alloc_fixture_init(&f, p_pages, 600); /* X == 1 */

	ATF_CHECK_EQ(0, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(f.ha.ha_has_safe_pages);
	ATF_CHECK(f.ha.ha_staging != NULL);

	v_pages = expected_vector_pages(p_pages);

	ATF_CHECK_EQ(2, g_pg.reserve_calls);

	/*
	 * Independently recompute every source-PA vector entry from the
	 * SAME backing pool the production hib_pages_map() seam hands
	 * out: src call (call 1) occupies pool slots [0, P); aux call
	 * (call 2) occupies [P, P + A).
	 */
	per_page = HIB_PAGE_SIZE / sizeof(vm_paddr_t);
	for (i = 0; i < (size_t)p_pages; i++) {
		uint64_t page_idx = i / per_page;
		uint64_t off = i % per_page;
		uint64_t aux_slot = p_pages + page_idx;
		vm_paddr_t *vec = (vm_paddr_t *)pgseam_pool[aux_slot];
		vm_paddr_t expect_src_pa = PGSEAM_POOL_BASE +
		    (uint64_t)i * HIB_PAGE_SIZE;

		ATF_CHECK_EQ(expect_src_pa, vec[off]);
	}
	(void)v_pages;

	ATF_CHECK_EQ(0, g_pg.release_calls);
	hibernate_safe_pages_free(&f.ha);
	ATF_CHECK_EQ(2, g_pg.release_calls); /* aux then src */
	ATF_CHECK(!f.ha.ha_has_safe_pages);
	ATF_CHECK(f.ha.ha_staging == NULL);

	/* Idempotent: a second and third call are no-ops. */
	hibernate_safe_pages_free(&f.ha);
	hibernate_safe_pages_free(&f.ha);
	ATF_CHECK_EQ(2, g_pg.release_calls);

	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_src_shortage_passthrough);
ATF_TC_BODY(allocate_src_shortage_passthrough, tc)
{
	struct alloc_fixture f;

	alloc_fixture_init(&f, 5, 600);
	g_pg.reserve_fail_at = 1;
	g_pg.reserve_fail_errno = ENOMEM;

	ATF_CHECK_EQ(ENOMEM, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(f.ha.ha_has_safe_pages); /* struct published at step 3 */
	ATF_CHECK_EQ(1, g_pg.reserve_calls); /* aux never attempted */

	hibernate_safe_pages_free(&f.ha);
	/* Both release calls occur, each on an empty (never-reserved) set. */
	ATF_CHECK_EQ(2, g_pg.release_calls);
	ATF_CHECK_EQ(0, g_pg.last_release_count);
	ATF_CHECK(!f.ha.ha_has_safe_pages);

	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_aux_shortage_after_src_success);
ATF_TC_BODY(allocate_aux_shortage_after_src_success, tc)
{
	struct alloc_fixture f;
	uint64_t p_pages = 4;

	alloc_fixture_init(&f, p_pages, 600);
	g_pg.reserve_fail_at = 2;
	g_pg.reserve_fail_errno = ENOMEM;

	ATF_CHECK_EQ(ENOMEM, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(f.ha.ha_has_safe_pages);
	ATF_CHECK_EQ(2, g_pg.reserve_calls);

	hibernate_safe_pages_free(&f.ha);
	ATF_CHECK_EQ(2, g_pg.release_calls);
	/*
	 * Release order is aux then src (reverse acquisition order), so
	 * the LAST recorded call is src's, which succeeded with p_pages
	 * pages; aux (the first call, never successfully reserved) is
	 * released as an empty set.
	 */
	ATF_CHECK_EQ(p_pages, g_pg.last_release_count);

	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_duplicate_pa_within_src);
ATF_TC_BODY(allocate_duplicate_pa_within_src, tc)
{
	struct alloc_fixture f;

	alloc_fixture_init(&f, 3, 600);
	g_pg.dup_within_call = true;
	g_pg.dup_call = 1;

	ATF_CHECK_EQ(EINVAL, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(f.ha.ha_has_safe_pages);
	hibernate_safe_pages_free(&f.ha);
	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_pa_in_destination);
ATF_TC_BODY(allocate_pa_in_destination, tc)
{
	struct alloc_fixture f;

	alloc_fixture_init(&f, 3, 600);
	g_pg.override_active = true;
	g_pg.override_call = 1;
	g_pg.override_idx = 0;
	g_pg.override_value = ALLOC_FIXTURE_DST_START;

	ATF_CHECK_EQ(EINVAL, hibernate_safe_pages_alloc(&f.ha));
	hibernate_safe_pages_free(&f.ha);
	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_pa_in_arena);
ATF_TC_BODY(allocate_pa_in_arena, tc)
{
	struct alloc_fixture f;

	alloc_fixture_init(&f, 3, 600);
	g_pg.override_active = true;
	g_pg.override_call = 1;
	g_pg.override_idx = 0;
	g_pg.override_value = ALLOC_FIXTURE_ARENA_START;

	ATF_CHECK_EQ(EINVAL, hibernate_safe_pages_alloc(&f.ha));
	hibernate_safe_pages_free(&f.ha);
	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_aux_intersects_src);
ATF_TC_BODY(allocate_aux_intersects_src, tc)
{
	struct alloc_fixture f;

	alloc_fixture_init(&f, 3, 600);
	/* Call 1 (src) always starts at pool slot 0: PA == POOL_BASE. */
	g_pg.override_active = true;
	g_pg.override_call = 2;
	g_pg.override_idx = 0;
	g_pg.override_value = PGSEAM_POOL_BASE;

	ATF_CHECK_EQ(EINVAL, hibernate_safe_pages_alloc(&f.ha));
	hibernate_safe_pages_free(&f.ha);
	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_hib_malloc_struct_failure);
ATF_TC_BODY(allocate_hib_malloc_struct_failure, tc)
{
	struct alloc_fixture f;

	alloc_fixture_init(&f, 3, 600);
	hibernate_test_alloc_fail_after = 1;

	ATF_CHECK_EQ(ENOMEM, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(!f.ha.ha_has_safe_pages);
	ATF_CHECK(f.ha.ha_staging == NULL);
	ATF_CHECK_EQ(0, g_pg.reserve_calls);

	/*
	 * hibernate_safe_pages_free() must also tolerate the no-staging
	 * case (ha_has_safe_pages already false; nothing to release).
	 */
	hibernate_safe_pages_free(&f.ha);
	ATF_CHECK_EQ(0, g_pg.release_calls);

	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_xsave_bound_e2big);
ATF_TC_BODY(allocate_xsave_bound_e2big, tc)
{
	struct alloc_fixture f;

	/* 4097 bytes: X == 2 (> 1) refuses before any reservation. */
	alloc_fixture_init(&f, 3, 4097);
	ATF_CHECK_EQ(E2BIG, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(!f.ha.ha_has_safe_pages);
	ATF_CHECK_EQ(0, g_pg.reserve_calls);
	alloc_fixture_fini();

	/* 8192 bytes: X == 2, same refusal. */
	alloc_fixture_init(&f, 3, 8192);
	ATF_CHECK_EQ(E2BIG, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK(!f.ha.ha_has_safe_pages);
	ATF_CHECK_EQ(0, g_pg.reserve_calls);
	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_xsave_bound_exactly_4096);
ATF_TC_BODY(allocate_xsave_bound_exactly_4096, tc)
{
	struct alloc_fixture f;
	uint64_t p_pages = 2;
	uint64_t v_pages = expected_vector_pages(p_pages);

	/* 4096 bytes: X == 1 (ceil(4096/4096)); succeeds, A == V + 2. */
	alloc_fixture_init(&f, p_pages, 4096);
	ATF_CHECK_EQ(0, hibernate_safe_pages_alloc(&f.ha));
	ATF_CHECK_EQ(2, g_pg.reserve_calls);
	/* The seam saw the aux call's requested count directly. */
	ATF_CHECK_EQ(v_pages + 2, (uint64_t)g_pg.next_slot - p_pages);

	hibernate_safe_pages_free(&f.ha);
	alloc_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(allocate_release_idempotent_partial_states);
ATF_TC_BODY(allocate_release_idempotent_partial_states, tc)
{
	struct alloc_fixture f;
	int scenario;

	for (scenario = 0; scenario < 3; scenario++) {
		alloc_fixture_init(&f, 3, 600);

		switch (scenario) {
		case 0:
			/* struct-only: src reservation itself fails. */
			g_pg.reserve_fail_at = 1;
			g_pg.reserve_fail_errno = ENOMEM;
			ATF_CHECK_EQ(ENOMEM,
			    hibernate_safe_pages_alloc(&f.ha));
			break;
		case 1:
			/* struct+src: aux reservation fails. */
			g_pg.reserve_fail_at = 2;
			g_pg.reserve_fail_errno = ENOMEM;
			ATF_CHECK_EQ(ENOMEM,
			    hibernate_safe_pages_alloc(&f.ha));
			break;
		case 2:
			/* struct+src+aux: full success. */
			ATF_CHECK_EQ(0, hibernate_safe_pages_alloc(&f.ha));
			break;
		}
		ATF_CHECK(f.ha.ha_has_safe_pages);

		hibernate_safe_pages_free(&f.ha);
		ATF_CHECK(!f.ha.ha_has_safe_pages);
		ATF_CHECK(f.ha.ha_staging == NULL);
		ATF_CHECK_EQ(2, g_pg.release_calls);

		/* Idempotent: repeat calls change nothing further. */
		hibernate_safe_pages_free(&f.ha);
		hibernate_safe_pages_free(&f.ha);
		ATF_CHECK_EQ(2, g_pg.release_calls);

		alloc_fixture_fini();
	}
}

ATF_TC_WITHOUT_HEAD(allocate_zero_side_effects);
ATF_TC_BODY(allocate_zero_side_effects, tc)
{
	struct alloc_fixture f;
	int unused_slot;

	alloc_fixture_init(&f, 3, 600);
	ATF_CHECK_EQ(0, hibernate_safe_pages_alloc(&f.ha));

	/* Pool slots beyond everything handed out remain untouched. */
	for (unused_slot = g_pg.next_slot; unused_slot < PGSEAM_POOL_MAX;
	    unused_slot++) {
		uint8_t zero[HIB_PAGE_SIZE];

		memset(zero, 0, sizeof(zero));
		ATF_CHECK(memcmp(pgseam_pool[unused_slot], zero,
		    HIB_PAGE_SIZE) == 0);
	}
	/* No destination-interval byte is ever touched by ALLOCATE. */
	ATF_CHECK_EQ(ALLOC_FIXTURE_DST_START, f.dst_intervals[0]);
	ATF_CHECK_EQ(ALLOC_FIXTURE_DST_END, f.dst_intervals[1]);

	hibernate_safe_pages_free(&f.ha);
	alloc_fixture_fini();
}


/* ------------------------------------------------------------------ */
/* K-8 READ_PAYLOAD + VERIFY (H8/H9/H10) tests (design 035 SS6.4).      */
/*                                                                      */
/* Reuses build_image_ex() (layout), the provider read seam             */
/* (test_read_seam / fixture_init / fixture_fini via struct             */
/* restore_fixture) for payload bytes, and the page-backend seam        */
/* (pgseam_reserve/map/release) for staged source/XSAVE/vector/bounce   */
/* pages -- the same seams ALLOCATE's own tests already use.  A         */
/* payload fixture drives the real hibernate_meta_read() +              */
/* hibernate_image_decode() + hibernate_safe_pages_alloc() so           */
/* hibernate_payload_read()/hibernate_image_crc32c_verify() exercise    */
/* genuine production ha_image/ha_staging state, not a mock.            */
/* ------------------------------------------------------------------ */

/*
 * golden_crc32c: an independent, test-local bitwise CRC32C (reflected
 * Castagnoli, init 0xffffffff, final XOR 0xffffffff), deliberately NOT
 * hibernate_crc32c_update()/hib_crc_feed(), with only the 8-byte
 * encoded hc_crc32c field replaced by zeros (design 035 SS6.4's
 * "test-local independent bitwise recompute" golden).
 */
#define GOLDEN_CRC32C_POLY 0x82f63b78U

static uint32_t
golden_crc32c_update(uint32_t crc, const uint8_t *buf, size_t len)
{
	size_t i;
	int bit;

	for (i = 0; i < len; i++) {
		crc ^= buf[i];
		for (bit = 0; bit < 8; bit++) {
			if (crc & 1)
				crc = (crc >> 1) ^ GOLDEN_CRC32C_POLY;
			else
				crc >>= 1;
		}
	}
	return (crc);
}

static uint32_t
golden_image_crc32c(const uint8_t *image, uint64_t image_length,
    uint64_t cb_offset)
{
	uint8_t *copy;
	uint32_t crc;

	copy = malloc((size_t)image_length);
	ATF_REQUIRE(copy != NULL);
	memcpy(copy, image, (size_t)image_length);
	memset(copy + cb_offset + HIBERNATE_CB_OFF_CRC32C, 0,
	    HIBERNATE_CB_WIDTH_CRC32C);

	crc = 0xffffffffU;
	crc = golden_crc32c_update(crc, copy, (size_t)image_length);
	crc ^= 0xffffffffU;

	free(copy);
	return (crc);
}

/*
 * patch_image_crc: write the golden whole-image CRC32C (computed with
 * only the 8-byte hc_crc32c field zeroed) into the image's encoded CB
 * hc_crc32c field (low 4 bytes; the high 4 bytes are already encoded
 * zero from write_cb()).  write_cb() always encodes hc_crc32c == 0,
 * so every payload fixture must call this after the pattern fill and
 * before hibernate_meta_read()/hibernate_image_decode() for the
 * decoded hc_crc32c to agree with the real recomputation.
 */
static uint32_t
patch_image_crc(uint8_t *image, uint64_t image_length, uint64_t cb_offset)
{
	uint32_t crc;

	crc = golden_image_crc32c(image, image_length, cb_offset);
	le32enc_p(image + cb_offset + HIBERNATE_CB_OFF_CRC32C, crc);
	return (crc);
}

/*
 * payload_layout: mirrors build_image_ex()'s own internal derivation
 * (xsave_len is always 576, matching write_pcb()'s fixed encoding) so
 * tests can compute cb_offset/payload_start/load_base/image_length
 * without reaching into production internals.
 */
struct payload_layout {
	uint16_t phnum;
	uint64_t cb_offset;
	uint64_t pcb_offset;
	uint64_t payload_start;
	uint64_t xsave_len;
	uint64_t load_base;
	uint64_t image_length; /* load_base + n_loads*PAGE; no trailing gap */
};

static void
payload_layout_compute(struct payload_layout *pl, uint16_t n_loads)
{
	uint64_t phdr_table_end, file_off;

	pl->phnum = 2 + n_loads + 1; /* CB, PCB, XSAVE, n_loads PT_LOAD */
	pl->xsave_len = 576;

	phdr_table_end = EHDR_SIZE + (uint64_t)pl->phnum * PHDR_SIZE;
	pl->cb_offset = align_up(phdr_table_end, HIB_PAGE_SIZE);
	pl->pcb_offset = align_up(pl->cb_offset + HIBERNATE_CB_ENCODED_SIZE,
	    HIB_PAGE_SIZE);
	pl->payload_start = align_up(
	    pl->pcb_offset + HIBERNATE_PCB_ENCODED_SIZE, HIB_PAGE_SIZE);

	file_off = pl->payload_start + pl->xsave_len;
	pl->load_base = align_up(file_off, HIB_PAGE_SIZE);
	pl->image_length = pl->load_base + (uint64_t)n_loads * HIB_PAGE_SIZE;
}

/*
 * payload fixture: wires both the provider-read seam (metadata AND
 * payload bytes come from rf.image) and the page-backend seam (staged
 * pages are the separate pgseam_pool backing), then drives the real
 * READ_METADATA read, decode, and ALLOCATE, exactly as the coordinator
 * would, so hibernate_payload_read()/hibernate_image_crc32c_verify()
 * see genuine production state.  Zero-trailing-gap images keep
 * provider-read call counts small and deterministic: calls 1-2 are the
 * two metadata reads; call 3 is the XSAVE read; call 4 is the
 * xsave-to-load-base gap; calls 5..5+n_loads-1 are the PT_LOAD pages,
 * one call each (no trailing gap).
 */
struct payload_fixture {
	struct restore_fixture rf;
	struct payload_layout pl;
	vm_paddr_t dst_intervals[2];
	uint16_t n_loads;
};

static void
payload_fixture_init(struct payload_fixture *pf, uint16_t n_loads)
{
	size_t meta_len;
	uint64_t off;

	memset(pf, 0, sizeof(*pf));
	pf->n_loads = n_loads;
	payload_layout_compute(&pf->pl, n_loads);

	fixture_init(&pf->rf, 0, 0, pf->pl.image_length);
	ATF_REQUIRE(pf->pl.image_length <= FIXTURE_IMAGE_BUFSIZE);
	(void)build_image_ex(pf->rf.image, sizeof(pf->rf.image), n_loads,
	    pf->pl.image_length, 1);
	g_seam.max_rel = 0; /* the walker drives its own bounded reads */

	/*
	 * Fill only the XSAVE object and PT_LOAD page bytes with a
	 * distinctive non-zero pattern, leaving the zero-gap between
	 * them (payload_start+xsave_len, load_base) encoded zero, as
	 * the ABI requires.
	 */
	for (off = pf->pl.payload_start;
	    off < pf->pl.payload_start + pf->pl.xsave_len; off++)
		pf->rf.image[off] = (uint8_t)(0x55 + (off & 0x1f));
	for (off = pf->pl.load_base; off < pf->pl.image_length; off++)
		pf->rf.image[off] = (uint8_t)(0x55 + (off & 0x1f));
	(void)patch_image_crc(pf->rf.image, pf->pl.image_length,
	    pf->pl.cb_offset);

	pf->dst_intervals[0] = 0;
	pf->dst_intervals[1] = (vm_paddr_t)n_loads * HIB_PAGE_SIZE;
	pf->rf.ha.ha_dst_intervals = pf->dst_intervals;
	pf->rf.ha.ha_dst_count = 1;
	pf->rf.ha.ha_dst_valid = true;
	pf->rf.ha.ha_arena_start = (vm_paddr_t)0x900000;
	pf->rf.ha.ha_arena_size = 0x100000;

	hibernate_test_pages_reserve_fn = pgseam_reserve;
	hibernate_test_pages_map_fn = pgseam_map;
	hibernate_test_pages_release_fn = pgseam_release;
	pgseam_reset();

	meta_len = 0;
	ATF_REQUIRE_EQ(0, hibernate_meta_read(&pf->rf.ha, pf->rf.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	pf->rf.ha.ha_meta_buf = pf->rf.image;
	pf->rf.ha.ha_meta_len = meta_len;
	pf->rf.ha.ha_has_metadata = true;
	ATF_REQUIRE_EQ(0, hibernate_image_decode(pf->rf.image, meta_len,
	    &pf->rf.ha.ha_image));

	ATF_REQUIRE_EQ(0, hibernate_safe_pages_alloc(&pf->rf.ha));
}

static void
payload_fixture_fini(struct payload_fixture *pf)
{

	hibernate_safe_pages_free(&pf->rf.ha);
	hibernate_test_pages_reserve_fn = NULL;
	hibernate_test_pages_map_fn = NULL;
	hibernate_test_pages_release_fn = NULL;
	hibernate_test_alloc_fail_after = 0;
	hibernate_test_interval_next_fn = NULL;
	pgseam_reset();
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(payload_streaming_and_verify_success);
ATF_TC_BODY(payload_streaming_and_verify_success, tc)
{
	struct payload_fixture pf;
	uint32_t crc, golden;
	uint64_t v_pages, i;

	payload_fixture_init(&pf, 3);
	v_pages = expected_vector_pages(pf.n_loads);

	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));

	/* Every source page (pool slots [0,P)) holds its payload bytes. */
	for (i = 0; i < pf.n_loads; i++) {
		uint64_t file_off = pf.pl.load_base + i * HIB_PAGE_SIZE;

		ATF_CHECK(memcmp(pgseam_pool[i], pf.rf.image + file_off,
		    HIB_PAGE_SIZE) == 0);
	}
	/* The XSAVE page (pool slot P+V) holds the XSAVE bytes. */
	ATF_CHECK(memcmp(pgseam_pool[pf.n_loads + v_pages],
	    pf.rf.image + pf.pl.payload_start, (size_t)pf.pl.xsave_len) == 0);

	golden = golden_image_crc32c(pf.rf.image, pf.pl.image_length,
	    pf.pl.cb_offset);
	ATF_CHECK_EQ(golden, crc);

	ATF_CHECK_EQ(0, hibernate_image_crc32c_verify(&pf.rf.ha, crc));

	payload_fixture_fini(&pf);
}

ATF_TC_WITHOUT_HEAD(payload_read_faults_first_middle_last);
ATF_TC_BODY(payload_read_faults_first_middle_last, tc)
{
	struct payload_fixture pf;
	uint32_t crc;
	unsigned int base_calls, k;

	/*
	 * Deterministic call layout (zero trailing gap, one chunk per
	 * xsave/gap interval): 1-2 metadata, 3 xsave, 4 xsave-to-load
	 * gap, 5..5+n_loads-1 one call per PT_LOAD page.
	 */
	for (k = 0; k < 3; k++) {
		payload_fixture_init(&pf, 3);
		base_calls = g_seam.call_count; /* == 2, after metadata */
		/* first/middle/last load */
		g_seam.fail_at = base_calls + 3 + k;
		g_seam.fail_errno = EIO;

		ATF_CHECK_EQ(EIO, hibernate_payload_read(&pf.rf.ha, &crc));
		ATF_CHECK_EQ(0, crc);
		ATF_CHECK_EQ(g_seam.fail_at, g_seam.call_count);

		payload_fixture_fini(&pf);
	}
}

ATF_TC_WITHOUT_HEAD(payload_nonzero_mediaoffset);
ATF_TC_BODY(payload_nonzero_mediaoffset, tc)
{
	struct payload_fixture pf;
	uint32_t crc;
	uint64_t mediaoffset, i_rel;
	size_t meta_len;

	memset(&pf, 0, sizeof(pf));
	pf.n_loads = 2;
	payload_layout_compute(&pf.pl, pf.n_loads);

	mediaoffset = 0x8000;
	i_rel = 0x4000;
	fixture_init(&pf.rf, mediaoffset, i_rel, pf.pl.image_length);
	ATF_REQUIRE(pf.pl.image_length <= FIXTURE_IMAGE_BUFSIZE);
	(void)build_image_ex(pf.rf.image, sizeof(pf.rf.image), pf.n_loads,
	    pf.pl.image_length, 1);
	g_seam.max_rel = 0;
	{
		uint64_t off;

		for (off = pf.pl.payload_start;
		    off < pf.pl.payload_start + pf.pl.xsave_len; off++)
			pf.rf.image[off] = (uint8_t)(0x77 + (off & 0xf));
		for (off = pf.pl.load_base; off < pf.pl.image_length; off++)
			pf.rf.image[off] = (uint8_t)(0x77 + (off & 0xf));
	}
	(void)patch_image_crc(pf.rf.image, pf.pl.image_length,
	    pf.pl.cb_offset);

	pf.dst_intervals[0] = 0;
	pf.dst_intervals[1] = (vm_paddr_t)pf.n_loads * HIB_PAGE_SIZE;
	pf.rf.ha.ha_dst_intervals = pf.dst_intervals;
	pf.rf.ha.ha_dst_count = 1;
	pf.rf.ha.ha_dst_valid = true;
	pf.rf.ha.ha_arena_start = (vm_paddr_t)0x900000;
	pf.rf.ha.ha_arena_size = 0x100000;

	hibernate_test_pages_reserve_fn = pgseam_reserve;
	hibernate_test_pages_map_fn = pgseam_map;
	hibernate_test_pages_release_fn = pgseam_release;
	pgseam_reset();

	meta_len = 0;
	ATF_REQUIRE_EQ(0, hibernate_meta_read(&pf.rf.ha, pf.rf.image,
	    HIBERNATE_META_BUF_MAX, &meta_len));
	pf.rf.ha.ha_meta_buf = pf.rf.image;
	pf.rf.ha.ha_meta_len = meta_len;
	pf.rf.ha.ha_has_metadata = true;
	ATF_REQUIRE_EQ(0, hibernate_image_decode(pf.rf.image, meta_len,
	    &pf.rf.ha.ha_image));
	ATF_REQUIRE_EQ(0, hibernate_safe_pages_alloc(&pf.rf.ha));

	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));

	/*
	 * Every recorded provider offset equals (I - mediaoffset) + rel,
	 * i.e. i_rel + rel, for every payload-phase call beyond the two
	 * metadata reads (H2, design 035 SS3.2, risk R1).
	 */
	{
		unsigned int idx;

		for (idx = 2; idx < g_seam.call_count; idx++)
			ATF_CHECK_EQ(i_rel + g_seam.calls[idx].rel,
			    g_seam.calls[idx].prov_off);
	}

	ATF_CHECK_EQ(0, hibernate_image_crc32c_verify(&pf.rf.ha, crc));

	payload_fixture_fini(&pf);
}

ATF_TC_WITHOUT_HEAD(payload_xsave_bound_direct_e2big);
ATF_TC_BODY(payload_xsave_bound_direct_e2big, tc)
{
	struct hibernate_attempt ha;
	uint32_t crc;

	/*
	 * A direct hibernate_payload_read() call against an over-bound
	 * XSAVE image refuses E2BIG before any provider read and before
	 * the ha_has_safe_pages/ha_staging precondition check -- no
	 * ALLOCATE is needed to observe this (design 035 SS6.4 "XSAVE
	 * bound" row).
	 */
	ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	ha.ha_image.hi_xsave_length = 4097;
	seam_reset();
	hibernate_test_provider_read_fn = test_read_seam;

	crc = 0xdeadbeef;
	ATF_CHECK_EQ(E2BIG, hibernate_payload_read(&ha, &crc));
	ATF_CHECK_EQ(0, crc);
	ATF_CHECK_EQ(0, g_seam.call_count);

	hibernate_test_provider_read_fn = NULL;
	seam_reset();
}

ATF_TC_WITHOUT_HEAD(crc_invariance_and_other_byte_mismatch);
ATF_TC_BODY(crc_invariance_and_other_byte_mismatch, tc)
{
	struct payload_fixture pf;
	uint32_t crc;

	/*
	 * Stored-field invariance: mutating the decoded hc_crc32c copy
	 * does not change the recomputation, but VERIFY still refuses
	 * because the decoded/stored comparison now disagrees.
	 */
	payload_fixture_init(&pf, 2);
	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));
	pf.rf.ha.ha_image.hi_cb.hc_crc32c++; /* only the decoded copy */
	ATF_CHECK_EQ(EINVAL, hibernate_image_crc32c_verify(&pf.rf.ha, crc));
	payload_fixture_fini(&pf);

	/* Flip one byte in a PT_LOAD page -> CRC mismatch. */
	payload_fixture_init(&pf, 2);
	pf.rf.image[pf.pl.load_base] ^= 0xff;
	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));
	ATF_CHECK_EQ(EINVAL, hibernate_image_crc32c_verify(&pf.rf.ha, crc));
	payload_fixture_fini(&pf);

	/* Flip one byte in the XSAVE object -> CRC mismatch. */
	payload_fixture_init(&pf, 2);
	pf.rf.image[pf.pl.payload_start] ^= 0xff;
	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));
	ATF_CHECK_EQ(EINVAL, hibernate_image_crc32c_verify(&pf.rf.ha, crc));
	payload_fixture_fini(&pf);

	/* Flip hc_copy_list_bound (CB 0x098): covered normally -> mismatch. */
	payload_fixture_init(&pf, 2);
	pf.rf.image[pf.pl.cb_offset + HIBERNATE_CB_OFF_COPY_LIST_BOUND] ^=
	    0xff;
	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));
	ATF_CHECK_EQ(EINVAL, hibernate_image_crc32c_verify(&pf.rf.ha, crc));
	payload_fixture_fini(&pf);

	/*
	 * One byte in a payload ZERO_GAP (between the XSAVE object and
	 * load_base, always non-empty here because payload_start+xsave_len
	 * is never page-aligned): hibernate_payload_read() itself refuses
	 * EINVAL from the walker's all-zero check, before CRC mismatch is
	 * ever reached; *crc_out stays 0.
	 */
	payload_fixture_init(&pf, 2);
	ATF_REQUIRE(pf.pl.payload_start + pf.pl.xsave_len < pf.pl.load_base);
	pf.rf.image[pf.pl.payload_start + pf.pl.xsave_len] ^= 0xff;
	ATF_CHECK_EQ(EINVAL, hibernate_payload_read(&pf.rf.ha, &crc));
	ATF_CHECK_EQ(0, crc);
	payload_fixture_fini(&pf);
}

ATF_TC_WITHOUT_HEAD(verify_staged_memory_corruption);
ATF_TC_BODY(verify_staged_memory_corruption, tc)
{
	struct payload_fixture pf;
	uint32_t crc;

	payload_fixture_init(&pf, 2);
	ATF_CHECK_EQ(0, hibernate_payload_read(&pf.rf.ha, &crc));
	ATF_CHECK_EQ(0, hibernate_image_crc32c_verify(&pf.rf.ha, crc));

	/* Corrupt the staged source page AFTER a successful read/verify. */
	pgseam_pool[0][0] ^= 0xff;
	ATF_CHECK_EQ(EINVAL, hibernate_image_crc32c_verify(&pf.rf.ha, crc));

	payload_fixture_fini(&pf);
}

/* ------------------------------------------------------------------ */
/* Coverage refusal via a TEST-ONLY hibernate_test_interval_next_fn     */
/* seam.  Every scenario fails on the walker's own offset==cursor /    */
/* end<=image_length / zero-length checks, strictly before any         */
/* payload byte is read (the provider read-seam call count is          */
/* therefore unchanged across every scenario below).                   */
/* ------------------------------------------------------------------ */

#define MALFORMED_SEAM_MAX 4

struct malformed_entry {
	uint64_t offset;
	uint64_t length;
	enum hibernate_image_interval_class cls;
};

struct malformed_seam_state {
	struct malformed_entry entries[MALFORMED_SEAM_MAX];
	unsigned int n;
	unsigned int idx;
};

static struct malformed_seam_state g_malformed;

static int
malformed_interval_next(struct hibernate_image_iterator *it,
    struct hibernate_image_interval *out)
{

	(void)it;
	if (g_malformed.idx >= g_malformed.n)
		return (ENOENT);
	out->hii_offset = g_malformed.entries[g_malformed.idx].offset;
	out->hii_length = g_malformed.entries[g_malformed.idx].length;
	out->hii_class = g_malformed.entries[g_malformed.idx].cls;
	g_malformed.idx++;
	return (0);
}

static void
malformed_push(uint64_t offset, uint64_t length,
    enum hibernate_image_interval_class cls)
{

	ATF_REQUIRE(g_malformed.n < MALFORMED_SEAM_MAX);
	g_malformed.entries[g_malformed.n].offset = offset;
	g_malformed.entries[g_malformed.n].length = length;
	g_malformed.entries[g_malformed.n].cls = cls;
	g_malformed.n++;
}

ATF_TC_WITHOUT_HEAD(coverage_refusal_malformed_intervals);
ATF_TC_BODY(coverage_refusal_malformed_intervals, tc)
{
	struct payload_fixture pf;
	unsigned int scenario, reads_before;
	uint32_t crc;

	for (scenario = 0; scenario < 8; scenario++) {
		payload_fixture_init(&pf, 2);
		memset(&g_malformed, 0, sizeof(g_malformed));

		switch (scenario) {
		case 0: /* zero-length */
			malformed_push(0, 0, HIIC_STORED);
			break;
		case 1: /* overshoot: end > image_length */
			malformed_push(0, pf.pl.image_length + 1, HIIC_STORED);
			break;
		case 2: /* short-of-end: immediate ENOENT, cursor stays 0 */
			break;
		case 3: /* gapped: skips bytes [10,20) */
			malformed_push(0, 10, HIIC_STORED);
			malformed_push(20, 10, HIIC_STORED);
			break;
		case 4: /* overlapping */
			malformed_push(0, 10, HIIC_STORED);
			malformed_push(5, 10, HIIC_STORED);
			break;
		case 5: /* backward */
			malformed_push(0, 10, HIIC_STORED);
			malformed_push(3, 10, HIIC_STORED);
			break;
		case 6: /* repeated */
			malformed_push(0, 10, HIIC_STORED);
			malformed_push(0, 10, HIIC_STORED);
			break;
		case 7: /* interleaved */
			malformed_push(0, 10, HIIC_STORED);
			malformed_push(10, 10, HIIC_ZERO_GAP);
			malformed_push(15, 5, HIIC_STORED);
			break;
		}

		hibernate_test_interval_next_fn = malformed_interval_next;
		reads_before = g_seam.call_count;
		ATF_CHECK_EQ(EINVAL, hibernate_payload_read(&pf.rf.ha, &crc));
		ATF_CHECK_EQ(0, crc);
		ATF_CHECK_EQ(reads_before, g_seam.call_count);
		hibernate_test_interval_next_fn = NULL;

		payload_fixture_fini(&pf);
	}
}

/* ------------------------------------------------------------------ */
/* Coordinator full-chain tests: real K-8 stages (READ_METADATA        */
/* through VERIFY) wired through the coordinator, landing on the K-12  */
/* ENOTSUP seam (QUIESCE) on full success, and proving cleanup runs    */
/* exactly once on a READ_PAYLOAD or VERIFY failure.                   */
/* ------------------------------------------------------------------ */

struct full_chain_fixture {
	struct restore_fixture rf;
	struct payload_layout pl;
	vm_paddr_t dst_intervals[2];
	uint8_t marker_sector[DEV_BSIZE];
};

/*
 * full_chain_read / full_chain_write / full_chain_flush: minimal
 * marker-sector backend so the coordinator's CONSUMING-stage
 * hibernate_marker_write() + hibernate_marker_flush() (K-7, unchanged
 * by K-8) succeed and the chain reaches the K-12 QUIESCE ENOTSUP seam
 * instead of failing earlier for a reason K-8 does not own.
 * full_chain_fixture_init() pre-encodes marker_sector as the PENDING
 * marker hibernate_marker_write()'s read-modify-write expects.
 */
static int
full_chain_read(void *arg, void *buf, off_t offset, size_t length)
{
	struct full_chain_fixture *ff;

	ff = arg;
	if (offset != 0 || length != DEV_BSIZE)
		return (EINVAL);
	memcpy(buf, ff->marker_sector, DEV_BSIZE);
	return (0);
}

static int
full_chain_write(void *arg, void *buf, off_t offset, size_t length)
{
	struct full_chain_fixture *ff;

	ff = arg;
	if (offset != 0 || length != DEV_BSIZE)
		return (EINVAL);
	memcpy(ff->marker_sector, buf, DEV_BSIZE);
	return (0);
}

static int
full_chain_flush(struct dumperinfo *di)
{

	(void)di;
	return (0);
}

static void
full_chain_fixture_init(struct full_chain_fixture *ff, uint16_t n_loads)
{
	uint64_t off;

	memset(ff, 0, sizeof(*ff));
	payload_layout_compute(&ff->pl, n_loads);

	fixture_init(&ff->rf, 0, 0, ff->pl.image_length);
	ff->rf.ha.ha_marker_offset = 0;
	ff->rf.di.dumper = full_chain_write;
	ff->rf.di.dumper_read = full_chain_read;
	ff->rf.di.dumper_flush = full_chain_flush;
	ff->rf.di.priv = ff;
	ff->rf.di.blocksize = DEV_BSIZE;
	le64enc(ff->marker_sector + HIBERNATE_MARKER_OFF_MAGIC,
	    HIBERNATE_MARKER_MAGIC);
	le32enc(ff->marker_sector + HIBERNATE_MARKER_OFF_VERSION,
	    HIBERNATE_MARKER_VERSION);
	le32enc(ff->marker_sector + HIBERNATE_MARKER_OFF_STATE,
	    HIBERNATE_MARKER_STATE_PENDING);
	le64enc(ff->marker_sector + HIBERNATE_MARKER_OFF_IMAGE_OFFSET, 0);
	le64enc(ff->marker_sector + HIBERNATE_MARKER_OFF_IMAGE_LENGTH,
	    ff->pl.image_length);
	le32enc(ff->marker_sector + HIBERNATE_MARKER_OFF_CRC32C, 0);
	le32enc(ff->marker_sector + HIBERNATE_MARKER_OFF_RESERVED_024, 0);
	ATF_REQUIRE(ff->pl.image_length <= FIXTURE_IMAGE_BUFSIZE);
	(void)build_image_ex(ff->rf.image, sizeof(ff->rf.image), n_loads,
	    ff->pl.image_length, 1);
	g_seam.max_rel = 0;
	for (off = ff->pl.payload_start;
	    off < ff->pl.payload_start + ff->pl.xsave_len; off++)
		ff->rf.image[off] = (uint8_t)(0x55 + (off & 0x1f));
	for (off = ff->pl.load_base; off < ff->pl.image_length; off++)
		ff->rf.image[off] = (uint8_t)(0x55 + (off & 0x1f));
	(void)patch_image_crc(ff->rf.image, ff->pl.image_length,
	    ff->pl.cb_offset);

	ff->rf.ha.ha_dumper = &ff->rf.di;
	hibernate_test_probe_fn = coord_probe_pending;
	hibernate_test_amd64_cpu_validate = coord_cpu_validate;
	hibernate_test_facs_signature = 0;
	hibernate_test_physmem_bytes = UINT64_C(0x100000000);
	hibernate_test_pages_reserve_fn = pgseam_reserve;
	hibernate_test_pages_map_fn = pgseam_map;
	hibernate_test_pages_release_fn = pgseam_release;
	pgseam_reset();

	hibernate_arena_reset();
	ATF_REQUIRE_EQ(0, hibernate_arena_reserve(COORD_VALID_ARENA_START,
	    COORD_VALID_ARENA_SIZE));
}

static void
full_chain_fixture_fini(void)
{

	coord_reset_seams();
	hibernate_test_pages_reserve_fn = NULL;
	hibernate_test_pages_map_fn = NULL;
	hibernate_test_pages_release_fn = NULL;
	hibernate_test_quiesce_rollback_fn = NULL;
	pgseam_reset();
	fixture_fini();
}

ATF_TC_WITHOUT_HEAD(coordinator_full_chain_to_k12_enotsup);
ATF_TC_BODY(coordinator_full_chain_to_k12_enotsup, tc)
{
	struct full_chain_fixture ff;
	int error;

	full_chain_fixture_init(&ff, 2);

	error = hibernate_resume_attempt(&ff.rf.ha);

	ATF_CHECK_EQ(ENOTSUP, error);
	ATF_CHECK_EQ(HIB_RESUME_QUIESCE,
	    hibernate_resume_stage_log[hibernate_resume_stage_log_length - 1]);
	ATF_CHECK(ff.rf.ha.ha_has_safe_pages == false); /* cleanup ran */
	ATF_CHECK(ff.rf.ha.ha_has_metadata == false);

	full_chain_fixture_fini();
}

ATF_TC_WITHOUT_HEAD(coordinator_payload_and_verify_failure_cleanup_once);
ATF_TC_BODY(coordinator_payload_and_verify_failure_cleanup_once, tc)
{
	struct full_chain_fixture ff;
	int error;

	/* READ_PAYLOAD failure: fail the first payload-phase provider read. */
	full_chain_fixture_init(&ff, 2);
	/* calls 1-2 are metadata; 3 is the first payload read */
	g_seam.fail_at = 3;
	g_seam.fail_errno = EIO;

	error = hibernate_resume_attempt(&ff.rf.ha);

	ATF_CHECK_EQ(EIO, error);
	ATF_CHECK_EQ(HIB_RESUME_READ_PAYLOAD,
	    hibernate_resume_stage_log[hibernate_resume_stage_log_length - 1]);
	ATF_CHECK(!ff.rf.ha.ha_has_safe_pages);
	ATF_CHECK(!ff.rf.ha.ha_has_metadata);
	ATF_CHECK_EQ(2, g_pg.release_calls);

	full_chain_fixture_fini();

	/*
	 * VERIFY failure: corrupt one payload byte so the whole-image
	 * recompute disagrees with the stored hc_crc32c; the coordinator
	 * still runs cleanup exactly once.
	 */
	full_chain_fixture_init(&ff, 2);
	ff.rf.image[ff.pl.load_base] ^= 0xff;

	error = hibernate_resume_attempt(&ff.rf.ha);

	ATF_CHECK_EQ(EINVAL, error);
	ATF_CHECK_EQ(HIB_RESUME_VERIFY,
	    hibernate_resume_stage_log[hibernate_resume_stage_log_length - 1]);
	ATF_CHECK(!ff.rf.ha.ha_has_safe_pages);
	ATF_CHECK(!ff.rf.ha.ha_has_metadata);
	ATF_CHECK_EQ(2, g_pg.release_calls);

	full_chain_fixture_fini();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, read_metadata_minimal);
	ATF_TP_ADD_TC(tp, read_metadata_900_phdr);
	ATF_TP_ADD_TC(tp, read_metadata_phnum_out_of_range);
	ATF_TP_ADD_TC(tp, meta_check_phdr_end_predicate);
	ATF_TP_ADD_TC(tp, meta_check_total_predicate);
	ATF_TP_ADD_TC(tp, read_metadata_buf_max_and_length_bounds);
	ATF_TP_ADD_TC(tp, read_metadata_disagreement);
	ATF_TP_ADD_TC(tp, read_metadata_nonzero_padding);
	ATF_TP_ADD_TC(tp, read_metadata_read_faults);
	ATF_TP_ADD_TC(tp, read_metadata_nonzero_mediaoffset);
	ATF_TP_ADD_TC(tp, coordinator_destination_coalescing);
	ATF_TP_ADD_TC(tp, allocate_success_basic);
	ATF_TP_ADD_TC(tp, allocate_src_shortage_passthrough);
	ATF_TP_ADD_TC(tp, allocate_aux_shortage_after_src_success);
	ATF_TP_ADD_TC(tp, allocate_duplicate_pa_within_src);
	ATF_TP_ADD_TC(tp, allocate_pa_in_destination);
	ATF_TP_ADD_TC(tp, allocate_pa_in_arena);
	ATF_TP_ADD_TC(tp, allocate_aux_intersects_src);
	ATF_TP_ADD_TC(tp, allocate_hib_malloc_struct_failure);
	ATF_TP_ADD_TC(tp, allocate_xsave_bound_e2big);
	ATF_TP_ADD_TC(tp, allocate_xsave_bound_exactly_4096);
	ATF_TP_ADD_TC(tp, allocate_release_idempotent_partial_states);
	ATF_TP_ADD_TC(tp, allocate_zero_side_effects);
	ATF_TP_ADD_TC(tp, payload_streaming_and_verify_success);
	ATF_TP_ADD_TC(tp, payload_read_faults_first_middle_last);
	ATF_TP_ADD_TC(tp, payload_nonzero_mediaoffset);
	ATF_TP_ADD_TC(tp, payload_xsave_bound_direct_e2big);
	ATF_TP_ADD_TC(tp, crc_invariance_and_other_byte_mismatch);
	ATF_TP_ADD_TC(tp, verify_staged_memory_corruption);
	ATF_TP_ADD_TC(tp, coverage_refusal_malformed_intervals);
	ATF_TP_ADD_TC(tp, coordinator_full_chain_to_k12_enotsup);
	ATF_TP_ADD_TC(tp, coordinator_payload_and_verify_failure_cleanup_once);
	return (atf_no_error());
}
