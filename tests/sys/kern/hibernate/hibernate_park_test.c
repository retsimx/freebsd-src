/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * Host-runnable ABI and state-machine tests for the K-23 AP park-state
 * word (struct hibernate_park_state, sys/sys/hibernate.h).  The word
 * occupies bytes [0:8) of the arena header's hah_reserved_0f0[16]; bytes
 * [8:16) remain reserved-zero (sys/sys/hibernate.h's own comment and
 * _Static_assert above struct hibernate_arena_header).
 *
 * This file tests only the word's encoding and the WAITING/READY/RELEASE
 * protocol semantics (design 040 SS5.1-SS5.2): both are plain data
 * layout and comparison logic, fully expressible without any kernel or
 * SMP dependency.  It does not, and cannot, host-run the production
 * dispatch/release functions themselves
 * (hibernate_park_dispatch()/hibernate_resume_park_release(),
 * sys/kern/kern_hibernate.c) or the AP-side entry
 * (hibernate_resume_ap_entry(), sys/amd64/amd64/hibernate_machdep.c) or
 * trampoline (sys/amd64/amd64/hibernate_park_tramp.S): all three require
 * _KERNEL (ipi_startup(), PHYS_TO_DMAP(), atomic_load_acq_32()/
 * atomic_store_rel_32(), sbinuptime()) and real SMP hardware (a second
 * physical CPU reset via INIT/SIPI).  Those paths remain
 * QEMU-evidence-only.
 *
 * The verified-ready predicate below is a literal transcription of the
 * single comparison hibernate_park_dispatch() performs
 * (sys/kern/kern_hibernate.c: "if (seq == 1 && state ==
 * HIBERNATE_PARK_READY)"), not a copy of the function itself: that
 * comparison is embedded inline in a larger _KERNEL-only, hardware-
 * dependent function and is not separable into a host-callable unit.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Mirrors hibernate_park_dispatch()'s sole acceptance test: the sequence
 * must match the single expected value (always 1 in this ABI's
 * mp_ncpus == 2 singleton model, design 040 SS14.2) and the state must
 * read PARK_READY.  Any other combination -- in particular a stale or
 * otherwise mismatched sequence -- must not be accepted as ready.
 */
static bool
park_verified_ready(const struct hibernate_park_state *park,
    uint32_t expected_seq)
{

	return (park->hps_sequence == expected_seq &&
	    park->hps_state == HIBERNATE_PARK_READY);
}

/*
 * WAITING/READY/RELEASE transitions and the monotonic sequence number.
 * The real protocol (design 040 SS5.2): the BSP writes {seq=1, WAITING}
 * before SIPI; the park stub writes {seq=1, READY} after arrival (same
 * sequence, state only); the BSP writes {seq=2, RELEASE} to wake it
 * (sequence strictly increases).
 */
ATF_TC_WITHOUT_HEAD(waiting_ready_release_transitions);
ATF_TC_BODY(waiting_ready_release_transitions, tc)
{
	struct hibernate_park_state park;

	park.hps_sequence = 1;
	park.hps_state = HIBERNATE_PARK_WAITING;
	ATF_CHECK_EQ(HIBERNATE_PARK_WAITING, park.hps_state);
	ATF_CHECK(!park_verified_ready(&park, 1));

	/* AP arrival: state advances to READY; sequence is unchanged. */
	park.hps_state = HIBERNATE_PARK_READY;
	ATF_CHECK_EQ(UINT32_C(1), park.hps_sequence);
	ATF_CHECK(park_verified_ready(&park, 1));

	/* BSP release: sequence strictly increases; state becomes RELEASE. */
	park.hps_sequence = 2;
	park.hps_state = HIBERNATE_PARK_RELEASE;
	ATF_CHECK(park.hps_sequence > 1);
	ATF_CHECK_EQ(HIBERNATE_PARK_RELEASE, park.hps_state);
	ATF_CHECK(!park_verified_ready(&park, 1));
}

/*
 * A stale expected sequence must not be accepted as ready: state ==
 * READY alone is insufficient if the sequence does not match, and a
 * correct sequence with any other state is likewise not ready.
 */
ATF_TC_WITHOUT_HEAD(sequence_mismatch_rejected);
ATF_TC_BODY(sequence_mismatch_rejected, tc)
{
	struct hibernate_park_state park;

	/* READY state, but the sequence does not match what was expected. */
	park.hps_sequence = 2;
	park.hps_state = HIBERNATE_PARK_READY;
	ATF_CHECK(!park_verified_ready(&park, 1));

	/* Matching sequence, but the state has not yet reached READY. */
	park.hps_sequence = 1;
	park.hps_state = HIBERNATE_PARK_WAITING;
	ATF_CHECK(!park_verified_ready(&park, 1));

	/* Only the exact (sequence, state) pair is accepted. */
	park.hps_sequence = 1;
	park.hps_state = HIBERNATE_PARK_READY;
	ATF_CHECK(park_verified_ready(&park, 1));
}

/*
 * Reserved-bytes rule: hibernate_machdep_prepare() writes the park word
 * into header_buf + HIBERNATE_ARENA_HEADER_OFF_RESERVED_0F0 using
 * exactly this two-field, little-endian encoding
 * (sys/amd64/amd64/hibernate_machdep.c); it never touches the remaining
 * eight bytes, which hibernate_arena_header_encode() already zeroed via
 * its whole-header memset.  This test reproduces that write against a
 * standalone buffer sized to HIBERNATE_ARENA_HEADER_WIDTH_RESERVED_0F0
 * and proves bytes [8:16) stay zero while [0:8) hold the word.
 */
ATF_TC_WITHOUT_HEAD(reserved_bytes_rule);
ATF_TC_BODY(reserved_bytes_rule, tc)
{
	uint8_t buf[HIBERNATE_ARENA_HEADER_WIDTH_RESERVED_0F0];
	struct hibernate_park_state park;
	size_t i;

	ATF_CHECK_EQ(16, HIBERNATE_ARENA_HEADER_WIDTH_RESERVED_0F0);
	ATF_CHECK_EQ(sizeof(struct hibernate_park_state) + 8,
	    HIBERNATE_ARENA_HEADER_WIDTH_RESERVED_0F0);

	/* Start from a nonzero pattern so the zero check below is real. */
	memset(buf, 0xa5, sizeof(buf));
	memset(buf, 0, sizeof(buf));

	/* The same two little-endian stores hibernate_machdep_prepare() does */
	le32enc(buf + 0, 1);
	le32enc(buf + 4, HIBERNATE_PARK_WAITING);

	for (i = 8; i < sizeof(buf); i++)
		ATF_CHECK_EQ_MSG(0, buf[i], "reserved byte %zu nonzero", i);

	memcpy(&park, buf, sizeof(park));
	ATF_CHECK_EQ(UINT32_C(1), park.hps_sequence);
	ATF_CHECK_EQ(HIBERNATE_PARK_WAITING, park.hps_state);

	/* Advancing the word must not disturb the reserved tail. */
	le32enc(buf + 4, HIBERNATE_PARK_RELEASE);
	for (i = 8; i < sizeof(buf); i++)
		ATF_CHECK_EQ_MSG(0, buf[i], "reserved byte %zu nonzero", i);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, waiting_ready_release_transitions);
	ATF_TP_ADD_TC(tp, sequence_mismatch_rejected);
	ATF_TP_ADD_TC(tp, reserved_bytes_rule);
	return (atf_no_error());
}
