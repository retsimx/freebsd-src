/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * Initial RED fixtures for the K-6 canonical ABI 1 writer.
 *
 * This test is deliberately registered before the production encoder and
 * commit-gate seams exist.  It establishes the fixed wire-size, explicit
 * little-endian, reserved-zero and fail-closed gate requirements.  Later K-6
 * tasks extend this production-source test with ordered fake-dumper,
 * iterator, retry, CRC-rewrite and transaction failure fixtures.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define TX_MEDIA_SIZE	(HIBERNATE_METADATA_SIZE + DEV_BSIZE)
#define TX_IMAGE_OFFSET HIBERNATE_METADATA_SIZE
#define TX_IMAGE_LENGTH DEV_BSIZE
#define TX_MAX_EVENTS	32

struct transaction_mock {
	uint8_t sector[DEV_BSIZE];
	char events[TX_MAX_EVENTS + 1];
	unsigned int event_count;
	unsigned int read_count;
	unsigned int write_count;
	unsigned int flush_count;
	unsigned int image_count;
	unsigned int flush_attempt;
	unsigned int fail_flush_attempt;
	int read_error;
	int write_error;
	int image_error;
};

struct transaction_fixture {
	struct transaction_mock mock;
	struct dumperinfo di;
	struct hibernate_attempt ha;
	struct hibernate_marker pending;
	bool committed;
};

static void
tx_event(struct transaction_mock *mock, char event)
{
	ATF_REQUIRE(mock->event_count < TX_MAX_EVENTS);
	mock->events[mock->event_count++] = event;
	mock->events[mock->event_count] = '\0';
}

static int
tx_read(void *priv, void *virtual, off_t offset, size_t length)
{
	struct transaction_mock *mock;

	mock = priv;
	tx_event(mock, 'R');
	mock->read_count++;
	if (offset != 0 || length != DEV_BSIZE)
		return (EINVAL);
	if (mock->read_error != 0)
		return (mock->read_error);
	memcpy(virtual, mock->sector, sizeof(mock->sector));
	return (0);
}

static int
tx_write(void *priv, void *virtual, off_t offset, size_t length)
{
	struct transaction_mock *mock;

	mock = priv;
	tx_event(mock, 'W');
	mock->write_count++;
	if (offset != 0 || length != DEV_BSIZE)
		return (EINVAL);
	if (mock->write_error != 0)
		return (mock->write_error);
	memcpy(mock->sector, virtual, sizeof(mock->sector));
	return (0);
}

static int
tx_flush(struct dumperinfo *di)
{
	struct transaction_mock *mock;

	mock = di->priv;
	tx_event(mock, 'F');
	mock->flush_count++;
	mock->flush_attempt++;
	if (mock->fail_flush_attempt == mock->flush_attempt)
		return (EIO);
	return (0);
}

static int
tx_image(void *arg)
{
	struct transaction_mock *mock;

	mock = arg;
	tx_event(mock, 'I');
	mock->image_count++;
	return (mock->image_error);
}

static struct hibernate_marker
tx_pending_marker(void)
{
	struct hibernate_marker marker;

	memset(&marker, 0, sizeof(marker));
	marker.hm_magic = HIBERNATE_MARKER_MAGIC;
	marker.hm_version = HIBERNATE_MARKER_VERSION;
	marker.hm_state = HIBERNATE_MARKER_STATE_PENDING;
	marker.hm_image_offset = TX_IMAGE_OFFSET;
	marker.hm_image_length = TX_IMAGE_LENGTH;
	marker.hm_crc32c = UINT32_C(0x1234abcd);
	return (marker);
}

static void
tx_fixture_init(struct transaction_fixture *f)
{
	size_t i;

	memset(f, 0, sizeof(*f));
	for (i = HIBERNATE_MARKER_ENCODED_SIZE; i < DEV_BSIZE; i++)
		f->mock.sector[i] = (uint8_t)((i * 29U + (i >> 1) + 7U) & 0xff);

	f->di.dumper = tx_write;
	f->di.dumper_read = tx_read;
	f->di.dumper_flush = tx_flush;
	f->di.priv = &f->mock;
	f->di.blocksize = DEV_BSIZE;
	f->di.mediaoffset = 0;
	f->di.mediasize = TX_MEDIA_SIZE;

	f->ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	f->ha.ha_dumper = &f->di;
	f->ha.ha_marker_offset = 0;
	f->ha.ha_provider_offset = 0;
	f->ha.ha_provider_size = TX_MEDIA_SIZE;

	f->pending = tx_pending_marker();
	f->committed = true;
}

static void
tx_check_marker(const struct transaction_fixture *f)
{
	ATF_CHECK_EQ(HIBERNATE_MARKER_MAGIC,
	    le64dec(f->mock.sector + HIBERNATE_MARKER_OFF_MAGIC));
	ATF_CHECK_EQ(HIBERNATE_MARKER_VERSION,
	    le32dec(f->mock.sector + HIBERNATE_MARKER_OFF_VERSION));
	ATF_CHECK_EQ(HIBERNATE_MARKER_STATE_PENDING,
	    le32dec(f->mock.sector + HIBERNATE_MARKER_OFF_STATE));
	ATF_CHECK_EQ(TX_IMAGE_OFFSET,
	    le64dec(f->mock.sector + HIBERNATE_MARKER_OFF_IMAGE_OFFSET));
	ATF_CHECK_EQ(TX_IMAGE_LENGTH,
	    le64dec(f->mock.sector + HIBERNATE_MARKER_OFF_IMAGE_LENGTH));
	ATF_CHECK_EQ(UINT32_C(0x1234abcd),
	    le32dec(f->mock.sector + HIBERNATE_MARKER_OFF_CRC32C));
}

static struct hibernate_cb
valid_cb(void)
{
	struct hibernate_cb cb;

	memset(&cb, 0, sizeof(cb));
	cb.hc_magic = UINT64_C(0x48494245524e4154);
	cb.hc_version = HCB_VERSION;
	cb.hc_encoded_size = HIBERNATE_CB_ENCODED_SIZE;
	cb.hc_page_size = HIB_PAGE_SIZE;
	cb.hc_physmem_bytes = UINT64_C(0x40000000);
	cb.hc_image_length = UINT64_C(0x12000);
	cb.hc_payload_start = UINT64_C(0x3000);
	cb.hc_destination_pages = 8;
	cb.hc_source_vector_bytes = 64;
	cb.hc_arena_start = UINT64_C(0x100000);
	cb.hc_arena_size = UINT64_C(0x400000);
	cb.hc_facs_hardware_signature = UINT64_C(0x89abcdef);
	cb.hc_saved_pcb_offset = UINT64_C(0x2000);
	cb.hc_saved_pcb_size = HIBERNATE_PCB_ENCODED_SIZE;
	cb.hc_elf_phnum = 5;
	cb.hc_metadata_length = UINT64_C(0x3000);
	cb.hc_crc32c = 0;
	cb.hc_restore_footprint_pages = 4096;
	cb.hc_machine_flags = 0;
	cb.hc_destination_bytes = 8 * HIB_PAGE_SIZE;
	cb.hc_copy_list_bound = 8;
	return (cb);
}

static struct hibernate_pcb
valid_pcb(void)
{
	struct hibernate_pcb pcb;

	memset(&pcb, 0, sizeof(pcb));
	pcb.hp_version = 1;
	pcb.hp_encoded_size = HIBERNATE_PCB_ENCODED_SIZE;
	pcb.hp_cr0 = UINT64_C(0x80050033);
	pcb.hp_cr3 = UINT64_C(0x12345000);
	pcb.hp_cr4 = UINT64_C(0x000006f0);
	pcb.hp_efer = UINT64_C(0x00000d01);
	pcb.hp_pat = UINT64_C(0x0007040600070406);
	pcb.hp_xcr0 = HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE;
	pcb.hp_rflags = UINT64_C(0x202);
	pcb.hp_rsp = UINT64_C(0xffffffff81fff000);
	pcb.hp_rip = UINT64_C(0xffffffff80200000);
	pcb.hp_r12_pcb_pa = UINT64_C(0x23456000);
	pcb.hp_gdtr_limit = 0x57;
	pcb.hp_gdtr_base = UINT64_C(0xffffffff81a00000);
	pcb.hp_idtr_limit = 0xfff;
	pcb.hp_idtr_base = UINT64_C(0xffffffff81b00000);
	pcb.hp_fsbase = UINT64_C(0x1111222233334444);
	pcb.hp_gsbase = UINT64_C(0x5555666677778888);
	pcb.hp_kgsbase = UINT64_C(0x9999aaaabbbbcccc);
	pcb.hp_star = UINT64_C(0x0013000800000000);
	pcb.hp_lstar = UINT64_C(0xffffffff80201000);
	pcb.hp_cstar = UINT64_C(0xffffffff80202000);
	pcb.hp_sfmask = UINT64_C(0x4700);
	pcb.hp_kernel_gsbase = UINT64_C(0xffffffff81c00000);
	pcb.hp_xsave_length = HIBERNATE_PCB_XSAVE_MIN;
	pcb.hp_xsave_format = HIBERNATE_XSAVE_FORMAT;
	pcb.hp_xsave_offset = UINT64_C(0x3000);
	pcb.hp_xsave_enabled_mask = HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE;
	return (pcb);
}

ATF_TC_WITHOUT_HEAD(fixed_wire_sizes);
ATF_TC_BODY(fixed_wire_sizes, tc)
{
	ATF_CHECK_EQ(256U, (unsigned)HIBERNATE_CB_ENCODED_SIZE);
	ATF_CHECK_EQ(1024U, (unsigned)HIBERNATE_PCB_ENCODED_SIZE);
	ATF_CHECK_EQ(1, HCB_VERSION);
}

ATF_TC_WITHOUT_HEAD(cb_encoding);
ATF_TC_BODY(cb_encoding, tc)
{
	struct hibernate_cb cb;
	uint8_t wire[HIBERNATE_CB_ENCODED_SIZE];
	size_t i;

	cb = valid_cb();
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(0, hibernate_cb_encode(wire, sizeof(wire), &cb));

	ATF_CHECK_EQ(cb.hc_magic, le64dec(wire + HIBERNATE_CB_OFF_MAGIC));
	ATF_CHECK_EQ(HCB_VERSION, le32dec(wire + HIBERNATE_CB_OFF_VERSION));
	ATF_CHECK_EQ(HIBERNATE_CB_ENCODED_SIZE,
	    le32dec(wire + HIBERNATE_CB_OFF_ENCODED_SIZE));
	ATF_CHECK_EQ(cb.hc_arena_start,
	    le64dec(wire + HIBERNATE_CB_OFF_ARENA_START));
	ATF_CHECK_EQ(cb.hc_arena_size,
	    le64dec(wire + HIBERNATE_CB_OFF_ARENA_SIZE));
	ATF_CHECK_EQ(cb.hc_copy_list_bound,
	    le64dec(wire + HIBERNATE_CB_OFF_COPY_LIST_BOUND));

	for (i = 0; i < HIBERNATE_CB_WIDTH_CRC32C; i++)
		ATF_CHECK_EQ_MSG(0, wire[HIBERNATE_CB_OFF_CRC32C + i],
		    "initial CRC byte %zu was not zero", i);
	for (i = 0; i < HIBERNATE_CB_WIDTH_RESERVED_0A0; i++)
		ATF_CHECK_EQ(0, wire[HIBERNATE_CB_OFF_RESERVED_0A0 + i]);
	for (i = 0; i < HIBERNATE_CB_WIDTH_RESERVED_0C0; i++)
		ATF_CHECK_EQ(0, wire[HIBERNATE_CB_OFF_RESERVED_0C0 + i]);
}

ATF_TC_WITHOUT_HEAD(cb_bad_length_refuses);
ATF_TC_BODY(cb_bad_length_refuses, tc)
{
	struct hibernate_cb cb;
	uint8_t wire[HIBERNATE_CB_ENCODED_SIZE];

	cb = valid_cb();
	ATF_CHECK_EQ(EINVAL, hibernate_cb_encode(wire, sizeof(wire) - 1, &cb));
	ATF_CHECK_EQ(EINVAL, hibernate_cb_encode(NULL, sizeof(wire), &cb));
	ATF_CHECK_EQ(EINVAL, hibernate_cb_encode(wire, sizeof(wire), NULL));
}

ATF_TC_WITHOUT_HEAD(pcb_encoding);
ATF_TC_BODY(pcb_encoding, tc)
{
	struct hibernate_pcb pcb;
	uint8_t wire[HIBERNATE_PCB_ENCODED_SIZE];
	size_t i;

	pcb = valid_pcb();
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(0, hibernate_pcb_encode(wire, sizeof(wire), &pcb));

	ATF_CHECK_EQ(1U, le32dec(wire + HIBERNATE_PCB_OFF_VERSION));
	ATF_CHECK_EQ(HIBERNATE_PCB_ENCODED_SIZE,
	    le32dec(wire + HIBERNATE_PCB_OFF_ENCODED_SIZE));
	ATF_CHECK_EQ(pcb.hp_xsave_length,
	    le32dec(wire + HIBERNATE_PCB_OFF_XSAVE_LENGTH));
	ATF_CHECK_EQ(pcb.hp_xsave_format,
	    le32dec(wire + HIBERNATE_PCB_OFF_XSAVE_FORMAT));
	ATF_CHECK_EQ(pcb.hp_xsave_offset,
	    le64dec(wire + HIBERNATE_PCB_OFF_XSAVE_OFFSET));
	ATF_CHECK_EQ(pcb.hp_xsave_enabled_mask,
	    le64dec(wire + HIBERNATE_PCB_OFF_XSAVE_ENABLED_MASK));

	for (i = 0; i < HIBERNATE_PCB_WIDTH_RESERVED_05A; i++)
		ATF_CHECK_EQ(0, wire[HIBERNATE_PCB_OFF_RESERVED_05A + i]);
	for (i = 0; i < HIBERNATE_PCB_WIDTH_RESERVED_06A; i++)
		ATF_CHECK_EQ(0, wire[HIBERNATE_PCB_OFF_RESERVED_06A + i]);
	for (i = 0; i < HIBERNATE_PCB_WIDTH_RESERVED_0D0; i++)
		ATF_CHECK_EQ(0, wire[HIBERNATE_PCB_OFF_RESERVED_0D0 + i]);
}

ATF_TC_WITHOUT_HEAD(pcb_bad_descriptor_refuses);
ATF_TC_BODY(pcb_bad_descriptor_refuses, tc)
{
	struct hibernate_pcb pcb;
	uint8_t wire[HIBERNATE_PCB_ENCODED_SIZE];

	pcb = valid_pcb();
	pcb.hp_xcr0 |= UINT64_C(1) << 63;
	ATF_CHECK_EQ(EINVAL, hibernate_pcb_encode(wire, sizeof(wire), &pcb));

	pcb = valid_pcb();
	pcb.hp_xsave_enabled_mask ^= HIBERNATE_XCR0_SSE;
	ATF_CHECK_EQ(EINVAL, hibernate_pcb_encode(wire, sizeof(wire), &pcb));

	pcb = valid_pcb();
	pcb.hp_xsave_offset++;
	ATF_CHECK_EQ(EINVAL, hibernate_pcb_encode(wire, sizeof(wire), &pcb));

	pcb = valid_pcb();
	ATF_CHECK_EQ(EINVAL,
	    hibernate_pcb_encode(wire, sizeof(wire) - 1, &pcb));
}

ATF_TC_WITHOUT_HEAD(commit_gate_fail_closed);
ATF_TC_BODY(commit_gate_fail_closed, tc)
{
	ATF_CHECK(!hibernate_s4_commit_gate(false));
	ATF_CHECK(hibernate_s4_commit_gate(true));
}

ATF_TC_WITHOUT_HEAD(transaction_success);
ATF_TC_BODY(transaction_success, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	ATF_REQUIRE_EQ(0,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		&f.committed));

	ATF_CHECK(f.committed);
	ATF_CHECK_STREQ("RWFIFRWF", f.mock.events);
	ATF_CHECK_EQ(2U, f.mock.read_count);
	ATF_CHECK_EQ(2U, f.mock.write_count);
	ATF_CHECK_EQ(3U, f.mock.flush_count);
	ATF_CHECK_EQ(1U, f.mock.image_count);
	tx_check_marker(&f);
}

ATF_TC_WITHOUT_HEAD(transaction_clear_write_failure);
ATF_TC_BODY(transaction_clear_write_failure, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	f.mock.write_error = EIO;
	ATF_CHECK_EQ(EIO,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		&f.committed));

	ATF_CHECK(!f.committed);
	ATF_CHECK_STREQ("RW", f.mock.events);
	ATF_CHECK_EQ(0U, f.mock.flush_count);
	ATF_CHECK_EQ(0U, f.mock.image_count);
}

ATF_TC_WITHOUT_HEAD(transaction_clear_flush_failure);
ATF_TC_BODY(transaction_clear_flush_failure, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	f.mock.fail_flush_attempt = 1;
	ATF_CHECK_EQ(EIO,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		&f.committed));

	ATF_CHECK(!f.committed);
	ATF_CHECK_STREQ("RWF", f.mock.events);
	ATF_CHECK_EQ(1U, f.mock.write_count);
	ATF_CHECK_EQ(0U, f.mock.image_count);
}

ATF_TC_WITHOUT_HEAD(transaction_image_failure);
ATF_TC_BODY(transaction_image_failure, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	f.mock.image_error = ENOSPC;
	ATF_CHECK_EQ(ENOSPC,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		&f.committed));

	ATF_CHECK(!f.committed);
	ATF_CHECK_STREQ("RWFI", f.mock.events);
	ATF_CHECK_EQ(1U, f.mock.flush_count);
	ATF_CHECK_EQ(1U, f.mock.image_count);
}

ATF_TC_WITHOUT_HEAD(transaction_image_flush_failure);
ATF_TC_BODY(transaction_image_flush_failure, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	f.mock.fail_flush_attempt = 2;
	ATF_CHECK_EQ(EIO,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		&f.committed));

	ATF_CHECK(!f.committed);
	ATF_CHECK_STREQ("RWFIF", f.mock.events);
	ATF_CHECK_EQ(1U, f.mock.write_count);
	ATF_CHECK_EQ(2U, f.mock.flush_count);
}

ATF_TC_WITHOUT_HEAD(transaction_pending_write_failure);
ATF_TC_BODY(transaction_pending_write_failure, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	/*
	 * The clear write is the first write.  The callback changes the
	 * injected result immediately before the PENDING update.
	 */
	f.mock.write_error = 0;
	f.mock.image_error = 0;
	f.mock.fail_flush_attempt = 0;
	ATF_REQUIRE_EQ(0, hibernate_marker_clear(&f.ha));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	ATF_REQUIRE_EQ(0, tx_image(&f.mock));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	f.mock.write_error = EIO;
	ATF_CHECK_EQ(EIO, hibernate_marker_write(&f.ha, &f.pending));
	ATF_CHECK(!hibernate_s4_commit_gate(false));
	ATF_CHECK_STREQ("RWFIFRW", f.mock.events);
}

ATF_TC_WITHOUT_HEAD(transaction_pending_flush_failure);
ATF_TC_BODY(transaction_pending_flush_failure, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	f.mock.fail_flush_attempt = 3;
	ATF_CHECK_EQ(EIO,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		&f.committed));

	ATF_CHECK(!f.committed);
	ATF_CHECK_STREQ("RWFIFRWF", f.mock.events);
	ATF_CHECK_EQ(2U, f.mock.write_count);
	ATF_CHECK_EQ(3U, f.mock.flush_count);
	tx_check_marker(&f);
}

ATF_TC_WITHOUT_HEAD(transaction_bad_arguments);
ATF_TC_BODY(transaction_bad_arguments, tc)
{
	struct transaction_fixture f;

	tx_fixture_init(&f);
	ATF_CHECK_EQ(EINVAL,
	    hibernate_commit_pending(NULL, tx_image, &f.mock, &f.pending,
		&f.committed));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_commit_pending(&f.ha, NULL, &f.mock, &f.pending,
		&f.committed));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, NULL,
		&f.committed));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_commit_pending(&f.ha, tx_image, &f.mock, &f.pending,
		NULL));
	ATF_CHECK_STREQ("", f.mock.events);
}

ATF_TC_WITHOUT_HEAD(xsave_extent_x87_sse);
ATF_TC_BODY(xsave_extent_x87_sse, tc)
{
	uint32_t extent;

	extent = 0;
	ATF_CHECK_EQ(0,
	    hibernate_xsave_extent(HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE,
		NULL, 0, &extent));
	ATF_CHECK_EQ(HIBERNATE_PCB_XSAVE_MIN, extent);
}

ATF_TC_WITHOUT_HEAD(xsave_extent_avx);
ATF_TC_BODY(xsave_extent_avx, tc)
{
	const struct hibernate_xsave_component_fact facts[] = {
		{ .hxcf_component = 2, .hxcf_size = 256, .hxcf_offset = 576 },
	};
	uint32_t extent;

	extent = 0;
	ATF_CHECK_EQ(0,
	    hibernate_xsave_extent(HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE |
		    HIBERNATE_XCR0_AVX,
		facts, nitems(facts), &extent));
	ATF_CHECK_EQ(832U, extent);
}

ATF_TC_WITHOUT_HEAD(xsave_extent_sparse);
ATF_TC_BODY(xsave_extent_sparse, tc)
{
	const struct hibernate_xsave_component_fact facts[] = {
		{ .hxcf_component = 2, .hxcf_size = 256, .hxcf_offset = 576 },
		{ .hxcf_component = 9, .hxcf_size = 8, .hxcf_offset = 2688 },
	};
	uint32_t extent;

	extent = 0;
	ATF_CHECK_EQ(0,
	    hibernate_xsave_extent(HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE |
		    HIBERNATE_XCR0_AVX | HIBERNATE_XCR0_PKRU,
		facts, nitems(facts), &extent));
	ATF_CHECK_EQ(2696U, extent);
}

ATF_TC_WITHOUT_HEAD(xsave_extent_avx512);
ATF_TC_BODY(xsave_extent_avx512, tc)
{
	const struct hibernate_xsave_component_fact facts[] = {
		{ .hxcf_component = 2, .hxcf_size = 256, .hxcf_offset = 576 },
		{ .hxcf_component = 5, .hxcf_size = 64, .hxcf_offset = 1088 },
		{ .hxcf_component = 6, .hxcf_size = 512, .hxcf_offset = 1152 },
		{ .hxcf_component = 7, .hxcf_size = 1024, .hxcf_offset = 1664 },
	};
	uint32_t extent;
	uint64_t mask;

	mask = HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE | HIBERNATE_XCR0_AVX |
	    HIBERNATE_XCR0_OPMASK | HIBERNATE_XCR0_ZMM_HI256 |
	    HIBERNATE_XCR0_HI16_ZMM;
	extent = 0;
	ATF_CHECK_EQ(0,
	    hibernate_xsave_extent(mask, facts, nitems(facts), &extent));
	ATF_CHECK_EQ(2688U, extent);
}

ATF_TC_WITHOUT_HEAD(xsave_extent_refusals);
ATF_TC_BODY(xsave_extent_refusals, tc)
{
	const struct hibernate_xsave_component_fact avx[] = {
		{ .hxcf_component = 2, .hxcf_size = 256, .hxcf_offset = 576 },
	};
	const struct hibernate_xsave_component_fact duplicate[] = {
		{ .hxcf_component = 2, .hxcf_size = 256, .hxcf_offset = 576 },
		{ .hxcf_component = 2, .hxcf_size = 256, .hxcf_offset = 576 },
	};
	const struct hibernate_xsave_component_fact overflow[] = {
		{
		    .hxcf_component = 2,
		    .hxcf_size = 512,
		    .hxcf_offset = UINT32_MAX - 255,
		},
	};
	uint32_t extent;
	uint64_t required;

	required = HIBERNATE_XCR0_X87 | HIBERNATE_XCR0_SSE;
	extent = UINT32_MAX;

	ATF_CHECK_EQ(EINVAL,
	    hibernate_xsave_extent(HIBERNATE_XCR0_X87, NULL, 0, &extent));
	ATF_CHECK_EQ(0U, extent);

	extent = UINT32_MAX;
	ATF_CHECK_EQ(EINVAL,
	    hibernate_xsave_extent(required | (UINT64_C(1) << 63), NULL, 0,
		&extent));
	ATF_CHECK_EQ(0U, extent);

	extent = UINT32_MAX;
	ATF_CHECK_EQ(EINVAL,
	    hibernate_xsave_extent(required | HIBERNATE_XCR0_AVX, NULL, 0,
		&extent));
	ATF_CHECK_EQ(0U, extent);

	extent = UINT32_MAX;
	ATF_CHECK_EQ(EINVAL,
	    hibernate_xsave_extent(required | HIBERNATE_XCR0_AVX, duplicate,
		nitems(duplicate), &extent));
	ATF_CHECK_EQ(0U, extent);

	extent = UINT32_MAX;
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_xsave_extent(required | HIBERNATE_XCR0_AVX, overflow,
		nitems(overflow), &extent));
	ATF_CHECK_EQ(0U, extent);

	extent = UINT32_MAX;
	ATF_CHECK_EQ(EINVAL,
	    hibernate_xsave_extent(required | HIBERNATE_XCR0_AVX, avx,
		nitems(avx), NULL));
	ATF_CHECK_EQ(UINT32_MAX, extent);
}

#define WRITER_PREFIX_SIZE HIBERNATE_META_BUF_MAX

static void
writer_fixture(struct hibernate_writer_plan *plan, struct hibernate_cb *cb,
    struct hibernate_pcb *pcb, struct hibernate_writer_run *runs,
    uint8_t *prefix)
{
	*cb = valid_cb();
	*pcb = valid_pcb();
	memset(plan, 0, sizeof(*plan));
	memset(runs, 0, 2 * sizeof(*runs));
	memset(prefix, 0xa5, WRITER_PREFIX_SIZE);

	pcb->hp_xsave_offset = UINT64_C(0x3000);
	runs[0].hwr_destination = UINT64_C(0x800000);
	runs[0].hwr_file_offset = UINT64_C(0x4000);
	runs[0].hwr_length = HIB_PAGE_SIZE;
	runs[0].hwr_source = 1;
	runs[0].hwr_source_offset = 0;
	runs[1].hwr_destination = UINT64_C(0x802000);
	runs[1].hwr_file_offset = UINT64_C(0x5000);
	runs[1].hwr_length = HIB_PAGE_SIZE;
	runs[1].hwr_source = 1;
	runs[1].hwr_source_offset = HIB_PAGE_SIZE;

	cb->hc_image_length = UINT64_C(0x6000);
	cb->hc_arena_start = UINT64_C(0x100000);
	cb->hc_arena_size = UINT64_C(0x400000);
	cb->hc_physmem_bytes = UINT64_C(0x1000000);
	cb->hc_source_vector_bytes = 2;
	cb->hc_restore_footprint_pages = 16;
	cb->hc_copy_list_bound = 2;

	plan->hwp_prefix = prefix;
	plan->hwp_prefix_capacity = WRITER_PREFIX_SIZE;
	plan->hwp_runs = runs;
	plan->hwp_run_count = 2;
}

ATF_TC_WITHOUT_HEAD(writer_plan_canonical);
ATF_TC_BODY(writer_plan_canonical, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_image_interval interval;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;
	uint64_t cursor;
	unsigned int stored, gaps;
	int error;

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	ATF_REQUIRE_EQ(0, hibernate_writer_plan_assemble(&plan, &cb, &pcb));
	ATF_CHECK_EQ(UINT64_C(0x3000), plan.hwp_prefix_length);
	ATF_CHECK_EQ(5U, plan.hwp_image.hi_phnum);
	ATF_CHECK_EQ(2U, plan.hwp_image.hi_load_count);
	ATF_CHECK_EQ(UINT64_C(0x2000), plan.hwp_image.hi_destination_bytes);
	ATF_CHECK_EQ(0U,
	    le64dec(prefix + plan.hwp_image.hi_cb_offset +
		HIBERNATE_CB_OFF_CRC32C));

	cursor = 0;
	stored = 0;
	gaps = 0;
	while ((error = hibernate_writer_plan_interval_next(&plan,
		    &interval)) == 0) {
		ATF_CHECK_EQ(cursor, interval.hii_offset);
		ATF_CHECK(interval.hii_length != 0);
		cursor += interval.hii_length;
		if (interval.hii_class == HIIC_STORED)
			stored++;
		else
			gaps++;
	}
	ATF_CHECK_EQ(ENOENT, error);
	ATF_CHECK_EQ(cb.hc_image_length, cursor);
	ATF_CHECK_EQ(6U, stored);
	ATF_CHECK(gaps >= 3);
}

ATF_TC_WITHOUT_HEAD(writer_plan_offset_refusals);
ATF_TC_BODY(writer_plan_offset_refusals, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_file_offset = UINT64_C(0x4000);
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_file_offset = UINT64_C(0x6000);
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[0].hwr_file_offset++;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));
}

ATF_TC_WITHOUT_HEAD(writer_plan_destination_refusals);
ATF_TC_BODY(writer_plan_destination_refusals, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_destination = runs[0].hwr_destination;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_destination = runs[0].hwr_destination - HIB_PAGE_SIZE;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[0].hwr_destination = cb.hc_arena_start + HIB_PAGE_SIZE;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));
}

ATF_TC_WITHOUT_HEAD(writer_plan_alias_refusals);
ATF_TC_BODY(writer_plan_alias_refusals, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_source_offset = 0;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_source_offset = HIB_PAGE_SIZE / 2;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_source = 2;
	runs[1].hwr_source_offset = 0;
	ATF_CHECK_EQ(0, hibernate_writer_plan_assemble(&plan, &cb, &pcb));
}

ATF_TC_WITHOUT_HEAD(writer_plan_bounds_refusals);
ATF_TC_BODY(writer_plan_bounds_refusals, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	cb.hc_image_length = UINT64_C(0x5fff);
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	cb.hc_arena_start = UINT64_MAX - HIB_PAGE_SIZE;
	cb.hc_arena_size = 2 * HIB_PAGE_SIZE;
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	plan.hwp_prefix_capacity = HIB_PAGE_SIZE;
	ATF_CHECK_EQ(E2BIG, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[1].hwr_length = UINT64_MAX & ~(HIB_PAGE_SIZE - 1);
	ATF_CHECK_EQ(EOVERFLOW,
	    hibernate_writer_plan_assemble(&plan, &cb, &pcb));
}


struct stream_test_ctx {
	struct hibernate_writer_plan *plan;
	uint64_t cursor;
	uint64_t stored_bytes;
	uint64_t zero_bytes;
	uint64_t offsets[32];
	uint64_t lengths[32];
	unsigned int calls;
	unsigned int stored_calls;
	unsigned int zero_calls;
	unsigned int rewrite_calls;
	unsigned int fail_call;
	unsigned int retry_call;
	unsigned int transport_attempts;
	uint64_t rewrite_offset;
	uint32_t rewrite_crc;
	bool bad_offset;
};

static int
stream_record(struct stream_test_ctx *ctx, uint64_t offset, uint64_t length,
    uint32_t *crc, bool zero)
{
	static const uint8_t zeros[256];
	const uint8_t *bytes;
	uint64_t left;
	size_t chunk;

	if (ctx == NULL || crc == NULL || length == 0)
		return (EINVAL);
	ctx->calls++;
	ctx->transport_attempts++;
	if (ctx->fail_call != 0 && ctx->calls == ctx->fail_call)
		return (EIO);
	if (ctx->retry_call != 0 && ctx->calls == ctx->retry_call) {
		/*
		 * Model one failed low-level submission followed by an internal
		 * successful retry.  The failed attempt receives no CRC credit and
		 * does not advance the logical cursor.
		 */
		ctx->transport_attempts++;
	}
	if (offset != ctx->cursor) {
		ctx->bad_offset = true;
		return (EINVAL);
	}
	if (ctx->calls <= nitems(ctx->offsets)) {
		ctx->offsets[ctx->calls - 1] = offset;
		ctx->lengths[ctx->calls - 1] = length;
	}

	if (zero) {
		ctx->zero_calls++;
		ctx->zero_bytes += length;
		left = length;
		while (left != 0) {
			chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
			*crc = hibernate_crc32c_update(*crc, zeros, chunk);
			left -= chunk;
		}
	} else {
		ctx->stored_calls++;
		ctx->stored_bytes += length;
		if (offset < ctx->plan->hwp_prefix_length) {
			if (length > ctx->plan->hwp_prefix_length - offset)
				return (EINVAL);
			bytes = ctx->plan->hwp_prefix + offset;
			*crc = hibernate_crc32c_update(*crc, bytes, (size_t)length);
		} else {
			/*
			 * Host fixtures do not materialise XSAVE/PT_LOAD payloads.
			 * Use deterministic nonzero bytes while preserving exact
			 * slice length and logical-completion CRC accounting.
			 */
			static const uint8_t payload[256] = { 0x5a };
			left = length;
			while (left != 0) {
				chunk = left > sizeof(payload) ?
				    sizeof(payload) : (size_t)left;
				*crc = hibernate_crc32c_update(*crc, payload, chunk);
				left -= chunk;
			}
		}
	}
	ctx->cursor += length;
	return (0);
}

static int
stream_write_stored(void *arg, uint64_t offset, uint64_t length, uint32_t *crc)
{
	return (stream_record(arg, offset, length, crc, false));
}

static int
stream_write_zero(void *arg, uint64_t offset, uint64_t length, uint32_t *crc)
{
	return (stream_record(arg, offset, length, crc, true));
}

static int
stream_rewrite(void *arg, uint64_t offset, uint32_t crc)
{
	struct stream_test_ctx *ctx;

	ctx = arg;
	if (ctx == NULL || offset !=
	    ctx->plan->hwp_image.hi_cb_offset + HIBERNATE_CB_OFF_CRC32C)
		return (EINVAL);
	ctx->rewrite_calls++;
	ctx->rewrite_offset = offset;
	ctx->rewrite_crc = crc;
	return (0);
}

static void
stream_fixture(struct hibernate_writer_plan *plan, struct hibernate_cb *cb,
    struct hibernate_pcb *pcb, struct hibernate_writer_run *runs,
    uint8_t *prefix, struct stream_test_ctx *ctx)
{
	writer_fixture(plan, cb, pcb, runs, prefix);
	ATF_REQUIRE_EQ(0, hibernate_writer_plan_assemble(plan, cb, pcb));
	memset(ctx, 0, sizeof(*ctx));
	ctx->plan = plan;
}

ATF_TC_WITHOUT_HEAD(writer_stream_slices_and_zero_gaps);
ATF_TC_BODY(writer_stream_slices_and_zero_gaps, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;
	struct stream_test_ctx ctx;

	stream_fixture(&plan, &cb, &pcb, runs, prefix, &ctx);
	ATF_REQUIRE_EQ(0, hibernate_writer_plan_stream(&plan,
	    stream_write_stored, stream_write_zero, stream_rewrite, &ctx));
	ATF_CHECK(!ctx.bad_offset);
	ATF_CHECK_EQ(cb.hc_image_length, ctx.cursor);
	ATF_CHECK(ctx.stored_calls != 0);
	ATF_CHECK(ctx.zero_calls != 0);
	ATF_CHECK(ctx.zero_bytes != 0);
	ATF_CHECK_EQ(1U, ctx.rewrite_calls);
}

ATF_TC_WITHOUT_HEAD(writer_stream_retry_no_double_count);
ATF_TC_BODY(writer_stream_retry_no_double_count, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;
	struct stream_test_ctx retried, baseline;

	/*
	 * The transport retry is below the logical-completion boundary.  The
	 * callback records two low-level attempts for one logical call, but folds
	 * the bytes into CRC and advances the cursor only once.
	 */
	stream_fixture(&plan, &cb, &pcb, runs, prefix, &retried);
	retried.retry_call = 3;
	ATF_REQUIRE_EQ(0, hibernate_writer_plan_stream(&plan,
	    stream_write_stored, stream_write_zero, stream_rewrite, &retried));
	ATF_CHECK_EQ(retried.calls + 1, retried.transport_attempts);

	stream_fixture(&plan, &cb, &pcb, runs, prefix, &baseline);
	ATF_REQUIRE_EQ(0, hibernate_writer_plan_stream(&plan,
	    stream_write_stored, stream_write_zero, stream_rewrite, &baseline));
	ATF_CHECK_EQ(baseline.calls, baseline.transport_attempts);
	ATF_CHECK_EQ(baseline.rewrite_crc, retried.rewrite_crc);
	ATF_CHECK_EQ(baseline.cursor, retried.cursor);
	ATF_CHECK_EQ(1U, retried.rewrite_calls);
}

ATF_TC_WITHOUT_HEAD(writer_stream_malformed_completion);
ATF_TC_BODY(writer_stream_malformed_completion, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;
	struct stream_test_ctx ctx;

	stream_fixture(&plan, &cb, &pcb, runs, prefix, &ctx);
	/*
	 * Model premature iterator completion with residual image coverage.
	 * ENOENT is accepted only when the iterator cursor equals image_length.
	 */
	plan.hwp_iterator.hii_phase = HIIP_DONE;
	plan.hwp_iterator.hii_cursor = plan.hwp_image.hi_image_length - 1;
	ctx.cursor = plan.hwp_iterator.hii_cursor;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_stream(&plan,
	    stream_write_stored, stream_write_zero, stream_rewrite, &ctx));
	ATF_CHECK_EQ(0U, ctx.rewrite_calls);
}

ATF_TC_WITHOUT_HEAD(writer_stream_one_four_byte_rewrite);
ATF_TC_BODY(writer_stream_one_four_byte_rewrite, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;
	struct stream_test_ctx ctx;
	uint8_t before[HIBERNATE_CB_ENCODED_SIZE];
	uint8_t after[HIBERNATE_CB_ENCODED_SIZE];
	uint64_t crc_offset;
	size_t i;

	stream_fixture(&plan, &cb, &pcb, runs, prefix, &ctx);
	memcpy(before, prefix + plan.hwp_image.hi_cb_offset, sizeof(before));
	ATF_REQUIRE_EQ(0, hibernate_writer_plan_stream(&plan,
	    stream_write_stored, stream_write_zero, stream_rewrite, &ctx));
	memcpy(after, before, sizeof(after));
	crc_offset = ctx.rewrite_offset - plan.hwp_image.hi_cb_offset;
	ATF_REQUIRE(crc_offset + sizeof(uint32_t) <= sizeof(after));
	le32enc(after + crc_offset, ctx.rewrite_crc);

	ATF_CHECK_EQ(1U, ctx.rewrite_calls);
	ATF_CHECK_EQ(0U, le32dec(after + crc_offset + sizeof(uint32_t)));
	for (i = 0; i < sizeof(after); i++) {
		if (i >= crc_offset && i < crc_offset + sizeof(uint32_t))
			continue;
		ATF_CHECK_EQ_MSG(before[i], after[i],
		    "byte %zu changed outside four-byte rewrite", i);
	}
}

ATF_TC_WITHOUT_HEAD(writer_plan_arena_collision_edges);
ATF_TC_BODY(writer_plan_arena_collision_edges, tc)
{
	static uint8_t prefix[WRITER_PREFIX_SIZE];
	struct hibernate_writer_run runs[2];
	struct hibernate_writer_plan plan;
	struct hibernate_pcb pcb;
	struct hibernate_cb cb;

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[0].hwr_destination = cb.hc_arena_start - HIB_PAGE_SIZE;
	ATF_CHECK_EQ(0, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[0].hwr_destination = cb.hc_arena_start;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));

	writer_fixture(&plan, &cb, &pcb, runs, prefix);
	runs[0].hwr_destination =
	    cb.hc_arena_start + cb.hc_arena_size - HIB_PAGE_SIZE;
	ATF_CHECK_EQ(EINVAL, hibernate_writer_plan_assemble(&plan, &cb, &pcb));
}

ATF_TC_WITHOUT_HEAD(writer_dst_verify_agreement);
ATF_TC_BODY(writer_dst_verify_agreement, tc)
{
	struct hibernate_attempt ha;
	vm_paddr_t dst_intervals[4];
	vm_paddr_t sorted_free[2];
	vm_paddr_t arena_start, arena_end, pa;
	size_t free_idx;

	ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	sorted_free[0] = UINT64_C(0x2000);
	sorted_free[1] = UINT64_C(0x3000);
	arena_start = UINT64_C(0x5000);
	arena_end = UINT64_C(0x6000);

	dst_intervals[0] = UINT64_C(0x0000);
	dst_intervals[1] = UINT64_C(0x2000);
	dst_intervals[2] = UINT64_C(0x4000);
	dst_intervals[3] = UINT64_C(0x5000);
	ha.ha_dst_intervals = dst_intervals;
	ha.ha_dst_count = 2;
	ha.ha_dst_valid = true;

	free_idx = 0;
	for (pa = 0; pa < UINT64_C(0x6000); pa += HIB_PAGE_SIZE) {
		ATF_CHECK(hibernate_dst_page_agrees(&ha, sorted_free,
		    nitems(sorted_free), &free_idx, arena_start, arena_end,
		    pa));
	}

	ATF_CHECK(hibernate_dst_interval_contains(&ha, UINT64_C(0x0000)));
	ATF_CHECK(hibernate_dst_interval_contains(&ha, UINT64_C(0x1000)));
	ATF_CHECK(!hibernate_dst_interval_contains(&ha, UINT64_C(0x2000)));
	ATF_CHECK(!hibernate_dst_interval_contains(&ha, UINT64_C(0x3000)));
	ATF_CHECK(hibernate_dst_interval_contains(&ha, UINT64_C(0x4000)));
	ATF_CHECK(!hibernate_dst_interval_contains(&ha, UINT64_C(0x5000)));
}

ATF_TC_WITHOUT_HEAD(writer_dst_verify_refuses);
ATF_TC_BODY(writer_dst_verify_refuses, tc)
{
	struct hibernate_attempt ha;
	vm_paddr_t dst_intervals[2];
	vm_paddr_t sorted_free[2];
	size_t free_idx;

	ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	sorted_free[0] = UINT64_C(0x2000);
	sorted_free[1] = UINT64_C(0x3000);

	dst_intervals[0] = UINT64_C(0x0000);
	dst_intervals[1] = UINT64_C(0x3000);
	ha.ha_dst_intervals = dst_intervals;
	ha.ha_dst_count = 1;
	ha.ha_dst_valid = true;

	free_idx = 0;
	ATF_CHECK(hibernate_dst_page_agrees(&ha, sorted_free,
	    nitems(sorted_free), &free_idx, 0, 0, UINT64_C(0x0000)));
	ATF_CHECK(hibernate_dst_page_agrees(&ha, sorted_free,
	    nitems(sorted_free), &free_idx, 0, 0, UINT64_C(0x1000)));
	ATF_CHECK(!hibernate_dst_page_agrees(&ha, sorted_free,
	    nitems(sorted_free), &free_idx, 0, 0, UINT64_C(0x2000)));
	ATF_CHECK(hibernate_dst_interval_contains(&ha, UINT64_C(0x2000)));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fixed_wire_sizes);
	ATF_TP_ADD_TC(tp, cb_encoding);
	ATF_TP_ADD_TC(tp, cb_bad_length_refuses);
	ATF_TP_ADD_TC(tp, pcb_encoding);
	ATF_TP_ADD_TC(tp, pcb_bad_descriptor_refuses);
	ATF_TP_ADD_TC(tp, commit_gate_fail_closed);
	ATF_TP_ADD_TC(tp, transaction_success);
	ATF_TP_ADD_TC(tp, transaction_clear_write_failure);
	ATF_TP_ADD_TC(tp, transaction_clear_flush_failure);
	ATF_TP_ADD_TC(tp, transaction_image_failure);
	ATF_TP_ADD_TC(tp, transaction_image_flush_failure);
	ATF_TP_ADD_TC(tp, transaction_pending_write_failure);
	ATF_TP_ADD_TC(tp, transaction_pending_flush_failure);
	ATF_TP_ADD_TC(tp, transaction_bad_arguments);
	ATF_TP_ADD_TC(tp, xsave_extent_x87_sse);
	ATF_TP_ADD_TC(tp, xsave_extent_avx);
	ATF_TP_ADD_TC(tp, xsave_extent_sparse);
	ATF_TP_ADD_TC(tp, xsave_extent_avx512);
	ATF_TP_ADD_TC(tp, xsave_extent_refusals);
	ATF_TP_ADD_TC(tp, writer_plan_canonical);
	ATF_TP_ADD_TC(tp, writer_plan_offset_refusals);
	ATF_TP_ADD_TC(tp, writer_plan_destination_refusals);
	ATF_TP_ADD_TC(tp, writer_plan_alias_refusals);
	ATF_TP_ADD_TC(tp, writer_plan_bounds_refusals);
	ATF_TP_ADD_TC(tp, writer_stream_slices_and_zero_gaps);
	ATF_TP_ADD_TC(tp, writer_stream_retry_no_double_count);
	ATF_TP_ADD_TC(tp, writer_stream_malformed_completion);
	ATF_TP_ADD_TC(tp, writer_stream_one_four_byte_rewrite);
	ATF_TP_ADD_TC(tp, writer_plan_arena_collision_edges);
	ATF_TP_ADD_TC(tp, writer_dst_verify_agreement);
	ATF_TP_ADD_TC(tp, writer_dst_verify_refuses);
	return (atf_no_error());
}
