/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * Production-source host tests for saved-kernel handoff validation.
 */

#include <sys/param.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

static jmp_buf failure_env;
static const char *failure_field;
static uintmax_t failure_value;

static void
failure_trap(const char *field, uintmax_t value)
{
	failure_field = field;
	failure_value = value;
	longjmp(failure_env, 1);
}

static void
valid_record(void)
{
	memset(&hibernate_saved_handoff, 0, sizeof(hibernate_saved_handoff));
	hibernate_saved_handoff.hhr_magic = HIBERNATE_HANDOFF_MAGIC;
	hibernate_saved_handoff.hhr_version = HIBERNATE_HANDOFF_VERSION;
	hibernate_saved_handoff.hhr_encoded_size =
	    HIBERNATE_HANDOFF_ENCODED_SIZE;
}

static void
check_failure(const char *field, uintmax_t value)
{
	hibernate_test_handoff_failure_fn = failure_trap;
	failure_field = NULL;
	failure_value = 0;
	if (setjmp(failure_env) == 0) {
		hibernate_handoff_consume();
		ATF_REQUIRE(false);
	}
	hibernate_test_handoff_failure_fn = NULL;
	ATF_CHECK_STREQ(field, failure_field);
	ATF_CHECK_EQ(value, failure_value);
}

ATF_TC_WITHOUT_HEAD(valid);
ATF_TC_BODY(valid, tc)
{
	valid_record();
	hibernate_test_handoff_failure_fn = NULL;
	hibernate_handoff_consume();
}

ATF_TC_WITHOUT_HEAD(terminal_copy_round_trip);
ATF_TC_BODY(terminal_copy_round_trip, tc)
{
	struct hibernate_handoff_record src = {
		.hhr_magic = HIBERNATE_HANDOFF_MAGIC,
		.hhr_version = HIBERNATE_HANDOFF_VERSION,
		.hhr_encoded_size = HIBERNATE_HANDOFF_ENCODED_SIZE,
		.hhr_provider_name = "gpt/k11-round-trip",
		.hhr_provider_media_size = UINT64_C(0x1122334455667788),
		.hhr_provider_writable = 0xa5,
		.hhr_marker_offset = UINT64_C(0x2132435465768798),
		.hhr_image_offset = UINT64_C(0x31425364758697a8),
		.hhr_image_length = UINT64_C(0x415263748596a7b8),
		.hhr_marker_sequence = UINT32_C(0x52637485),
		.hhr_marker_state = UINT32_C(0x63748596),
		.hhr_completion_provider_acquired = 0xb6,
		.hhr_completion_consumer_attached = 0xc7,
		.hhr_reserved = { 0 },
	};
	uint8_t buf[HIBERNATE_HANDOFF_ENCODED_SIZE];
	size_t i;

	ATF_REQUIRE_EQ(0,
	    hibernate_handoff_record_encode(buf, HIBERNATE_HANDOFF_ENCODED_SIZE,
		&src));
	memcpy(&hibernate_saved_handoff, buf, HIBERNATE_HANDOFF_ENCODED_SIZE);

	ATF_CHECK_EQ(sizeof(struct hibernate_handoff_record),
	    HIBERNATE_HANDOFF_ENCODED_SIZE);
	ATF_CHECK_EQ(src.hhr_magic, hibernate_saved_handoff.hhr_magic);
	ATF_CHECK_EQ(src.hhr_version, hibernate_saved_handoff.hhr_version);
	ATF_CHECK_EQ(src.hhr_encoded_size,
	    hibernate_saved_handoff.hhr_encoded_size);
	for (i = 0; i < SPECNAMELEN; i++) {
		ATF_CHECK_EQ(src.hhr_provider_name[i],
		    hibernate_saved_handoff.hhr_provider_name[i]);
	}
	ATF_CHECK_EQ(src.hhr_provider_media_size,
	    hibernate_saved_handoff.hhr_provider_media_size);
	ATF_CHECK_EQ(src.hhr_provider_writable,
	    hibernate_saved_handoff.hhr_provider_writable);
	ATF_CHECK_EQ(src.hhr_marker_offset,
	    hibernate_saved_handoff.hhr_marker_offset);
	ATF_CHECK_EQ(src.hhr_image_offset,
	    hibernate_saved_handoff.hhr_image_offset);
	ATF_CHECK_EQ(src.hhr_image_length,
	    hibernate_saved_handoff.hhr_image_length);
	ATF_CHECK_EQ(src.hhr_marker_sequence,
	    hibernate_saved_handoff.hhr_marker_sequence);
	ATF_CHECK_EQ(src.hhr_marker_state,
	    hibernate_saved_handoff.hhr_marker_state);
	ATF_CHECK_EQ(src.hhr_completion_provider_acquired,
	    hibernate_saved_handoff.hhr_completion_provider_acquired);
	ATF_CHECK_EQ(src.hhr_completion_consumer_attached,
	    hibernate_saved_handoff.hhr_completion_consumer_attached);
	for (i = 0; i < sizeof(src.hhr_reserved); i++) {
		ATF_CHECK_EQ(src.hhr_reserved[i],
		    hibernate_saved_handoff.hhr_reserved[i]);
	}
}

ATF_TC_WITHOUT_HEAD(bad_magic);
ATF_TC_BODY(bad_magic, tc)
{
	valid_record();
	hibernate_saved_handoff.hhr_magic++;
	check_failure("magic", hibernate_saved_handoff.hhr_magic);
}

ATF_TC_WITHOUT_HEAD(bad_version);
ATF_TC_BODY(bad_version, tc)
{
	valid_record();
	hibernate_saved_handoff.hhr_version++;
	check_failure("version", hibernate_saved_handoff.hhr_version);
}

ATF_TC_WITHOUT_HEAD(bad_encoded_size);
ATF_TC_BODY(bad_encoded_size, tc)
{
	valid_record();
	hibernate_saved_handoff.hhr_encoded_size++;
	check_failure("encoded_size", hibernate_saved_handoff.hhr_encoded_size);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid);
	ATF_TP_ADD_TC(tp, terminal_copy_round_trip);
	ATF_TP_ADD_TC(tp, bad_magic);
	ATF_TP_ADD_TC(tp, bad_version);
	ATF_TP_ADD_TC(tp, bad_encoded_size);
	return (atf_no_error());
}
