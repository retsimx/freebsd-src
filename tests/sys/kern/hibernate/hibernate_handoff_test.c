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
	ATF_TP_ADD_TC(tp, bad_magic);
	ATF_TP_ADD_TC(tp, bad_version);
	ATF_TP_ADD_TC(tp, bad_encoded_size);
	return (atf_no_error());
}
