/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

#include <sys/param.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ASSERT_FIELD(member, name)                                             \
	_Static_assert(offsetof(struct hibernate_arena_header, member) ==      \
		HIBERNATE_ARENA_HEADER_OFF_##name,                             \
	    "offset: " #member);                                               \
	_Static_assert(sizeof(((struct hibernate_arena_header *)0)->member) == \
		HIBERNATE_ARENA_HEADER_WIDTH_##name,                           \
	    "width: " #member)

ASSERT_FIELD(hah_magic, MAGIC);
ASSERT_FIELD(hah_version, VERSION);
ASSERT_FIELD(hah_header_size, HEADER_SIZE);
ASSERT_FIELD(hah_arena_pa, ARENA_PA);
ASSERT_FIELD(hah_arena_size, ARENA_SIZE);
ASSERT_FIELD(hah_private_cr3_pa, PRIVATE_CR3_PA);
ASSERT_FIELD(hah_saved_cr3_pa, SAVED_CR3_PA);
ASSERT_FIELD(hah_trampoline_pa, TRAMPOLINE_PA);
ASSERT_FIELD(hah_trampoline_identity_va, TRAMPOLINE_IDENTITY_VA);
ASSERT_FIELD(hah_trampoline_saved_va, TRAMPOLINE_SAVED_VA);
ASSERT_FIELD(hah_arena_stack_pa, ARENA_STACK_PA);
ASSERT_FIELD(hah_arena_stack_size, ARENA_STACK_SIZE);
ASSERT_FIELD(hah_source_vector_pa, SOURCE_VECTOR_PA);
ASSERT_FIELD(hah_first_destination_pa, FIRST_DESTINATION_PA);
ASSERT_FIELD(hah_destination_page_count, DESTINATION_PAGE_COUNT);
ASSERT_FIELD(hah_iterator_pa, ITERATOR_PA);
ASSERT_FIELD(hah_handoff_record_pa, HANDOFF_RECORD_PA);
ASSERT_FIELD(hah_saved_handoff_va, SAVED_HANDOFF_VA);
ASSERT_FIELD(hah_saved_pcb_va, SAVED_PCB_VA);
ASSERT_FIELD(hah_restore_kernel_va, RESTORE_KERNEL_VA);
ASSERT_FIELD(hah_saved_cr0, SAVED_CR0);
ASSERT_FIELD(hah_saved_cr4, SAVED_CR4);
ASSERT_FIELD(hah_saved_efer, SAVED_EFER);
ASSERT_FIELD(hah_saved_pat, SAVED_PAT);
ASSERT_FIELD(hah_saved_xcr0, SAVED_XCR0);
ASSERT_FIELD(hah_gdtr, GDTR);
ASSERT_FIELD(hah_idtr, IDTR);
ASSERT_FIELD(hah_handoff_length, HANDOFF_LENGTH);
ASSERT_FIELD(hah_instruction_page_pa, INSTRUCTION_PAGE_PA);
ASSERT_FIELD(hah_terminal_flags, TERMINAL_FLAGS);
ASSERT_FIELD(hah_saved_entry_rsp, SAVED_ENTRY_RSP);
ASSERT_FIELD(hah_reserved_0f0, RESERVED_0F0);

_Static_assert(sizeof(struct hibernate_arena_header) == 256,
    "arena header must be 256 bytes");
_Static_assert(HIBERNATE_ARENA_TRAMPOLINE_BYTES ==
    HIBERNATE_ARENA_TRAMPOLINE_PAGES * HIBERNATE_ARENA_ALIGNMENT,
    "reserved trampoline span must be a whole number of arena pages");
_Static_assert(HIBERNATE_ARENA_TRAMPOLINE_PAGES >= 3,
    "the copied trampoline object spans at least the entry, both-domain and "
    "saved-domain stub pages");
_Static_assert(_Alignof(struct hibernate_arena_header) == 64,
    "arena header must be 64-byte aligned");
_Static_assert(sizeof(struct hibernate_arena_packed_dtr) == 10,
    "packed GDTR/IDTR must be 10 bytes");
_Static_assert(offsetof(struct hibernate_arena_packed_dtr, hap_limit) == 0,
    "DTR limit offset");
_Static_assert(offsetof(struct hibernate_arena_packed_dtr, hap_base) == 2,
    "DTR base offset");
_Static_assert(sizeof(((struct hibernate_arena_packed_dtr *)0)->hap_limit) == 2,
    "DTR limit width");
_Static_assert(sizeof(((struct hibernate_arena_packed_dtr *)0)->hap_base) == 8,
    "DTR base width");

static struct hibernate_arena_header
golden_header(void)
{
	struct hibernate_arena_header hah;
	uint64_t *value;
	size_t i;

	memset(&hah, 0, sizeof(hah));
	hah.hah_magic = HIBERNATE_ARENA_HEADER_MAGIC;
	hah.hah_version = HIBERNATE_ARENA_HEADER_VERSION;
	hah.hah_header_size = HIBERNATE_ARENA_HEADER_ENCODED_SIZE;

	/*
	 * Give every eight-byte scalar after the fixed prefix a distinct value.
	 * Explicit assignments below cover the packed and four-byte fields.
	 */
	value = &hah.hah_arena_pa;
	for (i = 0; i < 22; i++)
		value[i] = UINT64_C(0x1000000000000000) + i;
	hah.hah_gdtr.hap_limit = 0x1234;
	hah.hah_gdtr.hap_base = UINT64_C(0x1122334455667788);
	hah.hah_idtr.hap_limit = 0xabcd;
	hah.hah_idtr.hap_base = UINT64_C(0x8877665544332211);
	hah.hah_handoff_length = HIBERNATE_HANDOFF_ENCODED_SIZE;
	hah.hah_instruction_page_pa = UINT64_C(0x200000);
	hah.hah_terminal_flags = HIBERNATE_ARENA_HEADER_TERMINAL_FLAGS_DEFINED;
	hah.hah_saved_entry_rsp = UINT64_C(0xfffffe0000010000);
	return (hah);
}

ATF_TC_WITHOUT_HEAD(layout_visible);
ATF_TC_BODY(layout_visible, tc)
{
	ATF_CHECK_EQ(256, sizeof(struct hibernate_arena_header));
	ATF_CHECK_EQ(64, _Alignof(struct hibernate_arena_header));
	ATF_CHECK_EQ(10, sizeof(struct hibernate_arena_packed_dtr));
	ATF_CHECK_EQ(0xc0, offsetof(struct hibernate_arena_header, hah_gdtr));
	ATF_CHECK_EQ(0xca, offsetof(struct hibernate_arena_header, hah_idtr));
	ATF_CHECK_EQ(0xf0,
	    offsetof(struct hibernate_arena_header, hah_reserved_0f0));
	ATF_CHECK_EQ(256,
	    HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0 +
		HIBERNATE_ARENA_HEADER_WIDTH_RESERVED_0F0);
}

ATF_TC_WITHOUT_HEAD(round_trip_and_zeroing);
ATF_TC_BODY(round_trip_and_zeroing, tc)
{
	struct hibernate_arena_header in, out;
	uint8_t buf[HIBERNATE_ARENA_HEADER_ENCODED_SIZE];
	size_t i;

	in = golden_header();
	memset(buf, 0xa5, sizeof(buf));
	ATF_REQUIRE_EQ(0, hibernate_arena_header_encode(buf, sizeof(buf), &in));
	for (i = HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0; i < sizeof(buf); i++)
		ATF_CHECK_EQ_MSG(0, buf[i], "reserved byte %zu", i);
	ATF_REQUIRE_EQ(0,
	    hibernate_arena_header_decode(buf, sizeof(buf), &out));
	ATF_CHECK_EQ(0, memcmp(&in, &out, sizeof(in)));
}

ATF_TC_WITHOUT_HEAD(reject_reserved_and_short);
ATF_TC_BODY(reject_reserved_and_short, tc)
{
	struct hibernate_arena_header in, out;
	uint8_t buf[HIBERNATE_ARENA_HEADER_ENCODED_SIZE];
	size_t i;

	in = golden_header();
	ATF_REQUIRE_EQ(0, hibernate_arena_header_encode(buf, sizeof(buf), &in));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_header_encode(buf, sizeof(buf) - 1, &in));
	ATF_CHECK_EQ(EINVAL,
	    hibernate_arena_header_decode(buf, sizeof(buf) - 1, &out));

	for (i = 0; i < HIBERNATE_ARENA_HEADER_WIDTH_RESERVED_0F0; i++) {
		buf[HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0 + i] = 1;
		ATF_CHECK_EQ_MSG(EINVAL,
		    hibernate_arena_header_decode(buf, sizeof(buf), &out),
		    "reserved byte %zu accepted", i);
		buf[HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0 + i] = 0;
	}
}

ATF_TC_WITHOUT_HEAD(reject_undefined_terminal_flags);
ATF_TC_BODY(reject_undefined_terminal_flags, tc)
{
	struct hibernate_arena_header in, out;
	uint8_t buf[HIBERNATE_ARENA_HEADER_ENCODED_SIZE];

	in = golden_header();
	in.hah_terminal_flags = 1;
	ATF_CHECK_EQ_MSG(EINVAL,
	    hibernate_arena_header_encode(buf, sizeof(buf), &in),
	    "encoder accepted an undefined terminal-flag bit");

	in = golden_header();
	ATF_REQUIRE_EQ(0, hibernate_arena_header_encode(buf, sizeof(buf), &in));
	buf[HIBERNATE_ARENA_HEADER_OFF_TERMINAL_FLAGS] = 1;
	ATF_CHECK_EQ_MSG(EINVAL,
	    hibernate_arena_header_decode(buf, sizeof(buf), &out),
	    "decoder accepted an undefined terminal-flag bit");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, layout_visible);
	ATF_TP_ADD_TC(tp, round_trip_and_zeroing);
	ATF_TP_ADD_TC(tp, reject_reserved_and_short);
	ATF_TP_ADD_TC(tp, reject_undefined_terminal_flags);
	return (atf_no_error());
}
