/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * Ordered-dumper tests for the ABI 1 hibernate marker primitives.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define MOCK_MEDIA_SIZE	  (HIBERNATE_METADATA_SIZE + DEV_BSIZE)
#define MOCK_IMAGE_OFFSET HIBERNATE_METADATA_SIZE
#define MOCK_IMAGE_LENGTH DEV_BSIZE
#define MOCK_MAGIC	  UINT64_C(0x48494245524e4154)
#define MOCK_CRC32C	  UINT32_C(0x1234abcd)
#define MOCK_MAX_EVENTS	  16

struct marker_mock {
	uint8_t sector[DEV_BSIZE];
	char events[MOCK_MAX_EVENTS + 1];
	unsigned int event_count;
	unsigned int mock_read_count;
	unsigned int mock_write_count;
	unsigned int mock_flush_count;
	unsigned int overlap_count;
	bool callback_active;
	bool wrong_instance;
	bool wrong_offset;
	bool wrong_length;
	bool short_read;
	bool short_write;
	int read_error;
	int write_error;
	int flush_error;
	void *expected_priv;
	off_t expected_offset;
};

struct marker_fixture {
	struct marker_mock mock;
	struct dumperinfo di;
	struct hibernate_attempt ha;
};

static void
mock_event(struct marker_mock *mock, char event)
{
	ATF_REQUIRE(mock->event_count < MOCK_MAX_EVENTS);
	mock->events[mock->event_count++] = event;
	mock->events[mock->event_count] = '\0';
}

static void
mock_enter(struct marker_mock *mock)
{
	if (mock->callback_active)
		mock->overlap_count++;
	mock->callback_active = true;
}

static void
mock_leave(struct marker_mock *mock)
{
	mock->callback_active = false;
}

static int
mock_read(void *priv, void *virtual, off_t offset, size_t length)
{
	struct marker_mock *mock;

	mock = priv;
	mock_enter(mock);
	mock_event(mock, 'R');
	mock->mock_read_count++;
	if (priv != mock->expected_priv)
		mock->wrong_instance = true;
	if (offset != mock->expected_offset)
		mock->wrong_offset = true;
	if (length != DEV_BSIZE)
		mock->wrong_length = true;
	if (mock->read_error != 0) {
		mock_leave(mock);
		return (mock->read_error);
	}
	if (mock->short_read) {
		mock_leave(mock);
		return (EIO);
	}
	memcpy(virtual, mock->sector, DEV_BSIZE);
	mock_leave(mock);
	return (0);
}

static int
mock_write(void *priv, void *virtual, off_t offset, size_t length)
{
	struct marker_mock *mock;

	mock = priv;
	mock_enter(mock);
	mock_event(mock, 'W');
	mock->mock_write_count++;
	if (priv != mock->expected_priv)
		mock->wrong_instance = true;
	if (offset != mock->expected_offset)
		mock->wrong_offset = true;
	if (length != DEV_BSIZE)
		mock->wrong_length = true;
	if (mock->write_error != 0) {
		mock_leave(mock);
		return (mock->write_error);
	}
	if (mock->short_write) {
		mock_leave(mock);
		return (EIO);
	}
	memcpy(mock->sector, virtual, DEV_BSIZE);
	mock_leave(mock);
	return (0);
}

static int
mock_flush(struct dumperinfo *di)
{
	struct marker_mock *mock;

	mock = di->priv;
	mock_enter(mock);
	mock_event(mock, 'F');
	mock->mock_flush_count++;
	if (di->priv != mock->expected_priv)
		mock->wrong_instance = true;
	if (mock->flush_error != 0) {
		mock_leave(mock);
		return (mock->flush_error);
	}
	mock_leave(mock);
	return (0);
}

static void
fixture_init(struct marker_fixture *f)
{
	memset(f, 0, sizeof(*f));
	f->di.dumper = mock_write;
	f->di.dumper_read = mock_read;
	f->di.dumper_flush = mock_flush;
	f->di.priv = &f->mock;
	f->di.blocksize = DEV_BSIZE;
	f->di.mediaoffset = 0;
	f->di.mediasize = MOCK_MEDIA_SIZE;
	f->ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	f->ha.ha_dumper = &f->di;
	f->ha.ha_marker_offset = 0;
	f->mock.expected_priv = &f->mock;
	f->mock.expected_offset = 0;
}

static struct hibernate_marker
pending_marker(void)
{
	struct hibernate_marker marker;

	memset(&marker, 0, sizeof(marker));
	marker.hm_magic = MOCK_MAGIC;
	marker.hm_version = HIBERNATE_MARKER_VERSION;
	marker.hm_state = HIBERNATE_MARKER_STATE_PENDING;
	marker.hm_image_offset = MOCK_IMAGE_OFFSET;
	marker.hm_image_length = MOCK_IMAGE_LENGTH;
	marker.hm_crc32c = MOCK_CRC32C;
	return (marker);
}

static void
seed_trailer(struct marker_mock *mock)
{
	size_t i;

	for (i = HIBERNATE_MARKER_ENCODED_SIZE; i < DEV_BSIZE; i++)
		mock->sector[i] = (uint8_t)((i * 73U + (i >> 2) + 19U) & 0xff);
}

static void
encode_marker_literal(uint8_t *sector, const struct hibernate_marker *marker)
{
	le64enc(sector + HIBERNATE_MARKER_OFF_MAGIC, marker->hm_magic);
	le32enc(sector + HIBERNATE_MARKER_OFF_VERSION, marker->hm_version);
	le32enc(sector + HIBERNATE_MARKER_OFF_STATE, marker->hm_state);
	le64enc(sector + HIBERNATE_MARKER_OFF_IMAGE_OFFSET,
	    marker->hm_image_offset);
	le64enc(sector + HIBERNATE_MARKER_OFF_IMAGE_LENGTH,
	    marker->hm_image_length);
	le32enc(sector + HIBERNATE_MARKER_OFF_CRC32C, marker->hm_crc32c);
	le32enc(sector + HIBERNATE_MARKER_OFF_RESERVED_024, 0);
}

static void
save_trailer(const struct marker_mock *mock, uint8_t *trailer)
{
	memcpy(trailer, mock->sector + HIBERNATE_MARKER_ENCODED_SIZE,
	    DEV_BSIZE - HIBERNATE_MARKER_ENCODED_SIZE);
}

static void
check_trailer(const struct marker_mock *mock, const uint8_t *trailer)
{
	ATF_CHECK_EQ_MSG(0,
	    memcmp(trailer, mock->sector + HIBERNATE_MARKER_ENCODED_SIZE,
		DEV_BSIZE - HIBERNATE_MARKER_ENCODED_SIZE),
	    "sector trailer was modified");
}

static void
check_mock(const struct marker_mock *mock, const char *events,
    unsigned int reads, unsigned int writes, unsigned int flushes)
{
	ATF_CHECK_STREQ(events, mock->events);
	ATF_CHECK_EQ(reads, mock->mock_read_count);
	ATF_CHECK_EQ(writes, mock->mock_write_count);
	ATF_CHECK_EQ(flushes, mock->mock_flush_count);
	ATF_CHECK_EQ(0U, mock->overlap_count);
	ATF_CHECK(!mock->callback_active);
	ATF_CHECK(!mock->wrong_instance);
	ATF_CHECK(!mock->wrong_offset);
	ATF_CHECK(!mock->wrong_length);
}

static void
check_error_without_flush(struct marker_fixture *f, int expected, int actual,
    const char *events, unsigned int reads)
{
	ATF_CHECK_EQ(expected, actual);
	check_mock(&f->mock, events, reads, 0, 0);
}

static void
reset_observations(struct marker_mock *mock)
{
	mock->events[0] = '\0';
	mock->event_count = 0;
	mock->mock_read_count = 0;
	mock->mock_write_count = 0;
	mock->mock_flush_count = 0;
	mock->overlap_count = 0;
	mock->callback_active = false;
	mock->wrong_instance = false;
	mock->wrong_offset = false;
	mock->wrong_length = false;
}

static void
require_marker_equal(const struct hibernate_marker *a,
    const struct hibernate_marker *b)
{
	ATF_CHECK_EQ(a->hm_magic, b->hm_magic);
	ATF_CHECK_EQ(a->hm_version, b->hm_version);
	ATF_CHECK_EQ(a->hm_state, b->hm_state);
	ATF_CHECK_EQ(a->hm_image_offset, b->hm_image_offset);
	ATF_CHECK_EQ(a->hm_image_length, b->hm_image_length);
	ATF_CHECK_EQ(a->hm_crc32c, b->hm_crc32c);
}

ATF_TC_WITHOUT_HEAD(marker_read_order);
ATF_TC_BODY(marker_read_order, tc)
{
	struct marker_fixture f;
	struct hibernate_marker out;

	fixture_init(&f);
	ATF_REQUIRE_EQ(0, hibernate_marker_read(&f.ha, &out));
	check_mock(&f.mock, "R", 1, 0, 0);
	ATF_CHECK_EQ(0U, out.hm_magic);
}

ATF_TC_WITHOUT_HEAD(pending_write_order_and_durability);
ATF_TC_BODY(pending_write_order_and_durability, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker;

	fixture_init(&f);
	marker = pending_marker();
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	check_mock(&f.mock, "RW", 1, 1, 0);

	fixture_init(&f);
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "RWF", 1, 1, 1);
}

ATF_TC_WITHOUT_HEAD(state_transitions);
ATF_TC_BODY(state_transitions, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker;
	uint8_t before[HIBERNATE_MARKER_ENCODED_SIZE];
	size_t i;

	fixture_init(&f);
	marker = pending_marker();
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));

	reset_observations(&f.mock);
	memcpy(before, f.mock.sector, sizeof(before));
	marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMING;
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "RWF", 1, 1, 1);
	for (i = 0; i < sizeof(before); i++) {
		if (i >= HIBERNATE_MARKER_OFF_STATE &&
		    i < HIBERNATE_MARKER_OFF_STATE +
			    HIBERNATE_MARKER_WIDTH_STATE)
			continue;
		ATF_CHECK_EQ_MSG(before[i], f.mock.sector[i],
		    "CONSUMING changed marker byte %zu", i);
	}

	reset_observations(&f.mock);
	memcpy(before, f.mock.sector, sizeof(before));
	marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMED;
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "RWF", 1, 1, 1);
	for (i = 0; i < sizeof(before); i++) {
		if (i >= HIBERNATE_MARKER_OFF_STATE &&
		    i < HIBERNATE_MARKER_OFF_STATE +
			    HIBERNATE_MARKER_WIDTH_STATE)
			continue;
		ATF_CHECK_EQ_MSG(before[i], f.mock.sector[i],
		    "CONSUMED changed marker byte %zu", i);
	}
}

ATF_TC_WITHOUT_HEAD(clear_order_and_zero);
ATF_TC_BODY(clear_order_and_zero, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker;
	size_t i;

	fixture_init(&f);
	marker = pending_marker();
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	reset_observations(&f.mock);
	ATF_REQUIRE_EQ(0, hibernate_marker_clear(&f.ha));
	check_mock(&f.mock, "RW", 1, 1, 0);
	for (i = 0; i < HIBERNATE_MARKER_ENCODED_SIZE; i++)
		ATF_CHECK_EQ_MSG(0, f.mock.sector[i],
		    "clear retained marker byte %zu", i);

	fixture_init(&f);
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	reset_observations(&f.mock);
	ATF_REQUIRE_EQ(0, hibernate_marker_clear(&f.ha));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "RWF", 1, 1, 1);
}

ATF_TC_WITHOUT_HEAD(trailer_preservation);
ATF_TC_BODY(trailer_preservation, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker;
	uint8_t trailer[DEV_BSIZE - HIBERNATE_MARKER_ENCODED_SIZE];
	size_t i;

	fixture_init(&f);
	marker = pending_marker();

	seed_trailer(&f.mock);
	save_trailer(&f.mock, trailer);
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	check_trailer(&f.mock, trailer);

	seed_trailer(&f.mock);
	save_trailer(&f.mock, trailer);
	marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMING;
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	check_trailer(&f.mock, trailer);

	seed_trailer(&f.mock);
	save_trailer(&f.mock, trailer);
	marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMED;
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	check_trailer(&f.mock, trailer);

	seed_trailer(&f.mock);
	save_trailer(&f.mock, trailer);
	ATF_REQUIRE_EQ(0, hibernate_marker_clear(&f.ha));
	check_trailer(&f.mock, trailer);
	for (i = 0; i < HIBERNATE_MARKER_ENCODED_SIZE; i++)
		ATF_CHECK_EQ(0, f.mock.sector[i]);
}

ATF_TC_WITHOUT_HEAD(golden_pending_encoding);
ATF_TC_BODY(golden_pending_encoding, tc)
{
	static const uint8_t expected[HIBERNATE_MARKER_ENCODED_SIZE] = { 0x54,
		0x41, 0x4e, 0x52, 0x45, 0x42, 0x49, 0x48, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xcd, 0xab, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 };
	struct marker_fixture f;
	struct hibernate_marker marker, out;

	fixture_init(&f);
	marker = pending_marker();
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	ATF_CHECK_EQ_MSG(0, memcmp(expected, f.mock.sector, sizeof(expected)),
	    "PENDING marker differs from independent little-endian golden array");

	reset_observations(&f.mock);
	memset(&out, 0xa5, sizeof(out));
	ATF_REQUIRE_EQ(0, hibernate_marker_read(&f.ha, &out));
	require_marker_equal(&marker, &out);
	check_mock(&f.mock, "R", 1, 0, 0);
}

ATF_TC_WITHOUT_HEAD(validation_failures);
ATF_TC_BODY(validation_failures, tc)
{
	struct marker_fixture f;
	struct hibernate_attempt unbound;
	struct hibernate_marker marker, out;

	fixture_init(&f);
	marker = pending_marker();
	unbound = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;

	ATF_CHECK_EQ(EINVAL, hibernate_marker_read(NULL, &out));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_read(&f.ha, NULL));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_write(NULL, &marker));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_write(&f.ha, NULL));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_clear(NULL));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_flush(NULL));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_read(&unbound, &out));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_write(&unbound, &marker));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_clear(&unbound));
	ATF_CHECK_EQ(EINVAL, hibernate_marker_flush(&unbound));

	f.di.dumper_read = NULL;
	ATF_CHECK_EQ(EOPNOTSUPP, hibernate_marker_read(&f.ha, &out));
	ATF_CHECK_EQ(EOPNOTSUPP, hibernate_marker_write(&f.ha, &marker));
	ATF_CHECK_EQ(EOPNOTSUPP, hibernate_marker_clear(&f.ha));
	check_mock(&f.mock, "", 0, 0, 0);

	fixture_init(&f);
	f.di.dumper = NULL;
	ATF_CHECK_EQ(EOPNOTSUPP, hibernate_marker_write(&f.ha, &marker));
	ATF_CHECK_EQ(EOPNOTSUPP, hibernate_marker_clear(&f.ha));
	check_mock(&f.mock, "", 0, 0, 0);

	fixture_init(&f);
	f.di.blocksize = DEV_BSIZE * 2;
	ATF_CHECK_EQ(EINVAL, hibernate_marker_write(&f.ha, &marker));
	check_mock(&f.mock, "", 0, 0, 0);

	fixture_init(&f);
	f.ha.ha_marker_offset = 1;
	ATF_CHECK_EQ(EINVAL, hibernate_marker_write(&f.ha, &marker));
	check_mock(&f.mock, "", 0, 0, 0);

	fixture_init(&f);
	f.di.mediaoffset = DEV_BSIZE;
	f.di.mediasize = MOCK_MEDIA_SIZE;
	f.ha.ha_marker_offset = 0;
	ATF_CHECK_EQ(EINVAL, hibernate_marker_read(&f.ha, &out));
	check_mock(&f.mock, "", 0, 0, 0);

	fixture_init(&f);
	f.di.mediasize = DEV_BSIZE - 1;
	ATF_CHECK_EQ(EINVAL, hibernate_marker_read(&f.ha, &out));
	check_mock(&f.mock, "", 0, 0, 0);
}

ATF_TC_WITHOUT_HEAD(validation_boundaries_and_marker_content);
ATF_TC_BODY(validation_boundaries_and_marker_content, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker, requested, out;

	marker = pending_marker();

	/* P + DEV_BSIZE overflows after the media extent itself validates. */
	fixture_init(&f);
	f.di.mediasize = OFF_MAX;
	f.ha.ha_marker_offset = OFF_MAX - (DEV_BSIZE - 1);
	f.mock.expected_offset = f.ha.ha_marker_offset;
	check_error_without_flush(&f, EOVERFLOW,
	    hibernate_marker_read(&f.ha, &out), "", 0);

	/* mediaoffset + HIBERNATE_METADATA_SIZE overflows for PENDING. */
	fixture_init(&f);
	f.di.mediaoffset = OFF_MAX - (HIBERNATE_METADATA_SIZE - 1);
	f.di.mediasize = DEV_BSIZE;
	f.ha.ha_marker_offset = f.di.mediaoffset;
	f.mock.expected_offset = f.ha.ha_marker_offset;
	check_error_without_flush(&f, EOVERFLOW,
	    hibernate_marker_write(&f.ha, &marker), "", 0);

	fixture_init(&f);
	marker.hm_image_length = 0;
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_write(&f.ha, &marker), "", 0);

	fixture_init(&f);
	marker = pending_marker();
	marker.hm_image_length = UINT64_MAX;
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_write(&f.ha, &marker), "", 0);

	fixture_init(&f);
	marker = pending_marker();
	marker.hm_image_length = DEV_BSIZE * 2;
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_write(&f.ha, &marker), "", 0);

	/*
	 * The remaining malformed encodings fail after exactly one read.
	 * No validation failure may write or flush.
	 */
	fixture_init(&f);
	marker = pending_marker();
	encode_marker_literal(f.mock.sector, &marker);
	le64enc(f.mock.sector + HIBERNATE_MARKER_OFF_MAGIC, 0);
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_read(&f.ha, &out), "R", 1);

	fixture_init(&f);
	encode_marker_literal(f.mock.sector, &marker);
	le32enc(f.mock.sector + HIBERNATE_MARKER_OFF_VERSION,
	    HIBERNATE_MARKER_VERSION + 1);
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_read(&f.ha, &out), "R", 1);

	fixture_init(&f);
	encode_marker_literal(f.mock.sector, &marker);
	le32enc(f.mock.sector + HIBERNATE_MARKER_OFF_STATE, UINT32_MAX);
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_read(&f.ha, &out), "R", 1);

	fixture_init(&f);
	encode_marker_literal(f.mock.sector, &marker);
	le32enc(f.mock.sector + HIBERNATE_MARKER_OFF_RESERVED_024, 1);
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_read(&f.ha, &out), "R", 1);

	fixture_init(&f);
	encode_marker_literal(f.mock.sector, &marker);
	requested = marker;
	requested.hm_state = HIBERNATE_MARKER_STATE_CONSUMED;
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_write(&f.ha, &requested), "R", 1);

	fixture_init(&f);
	encode_marker_literal(f.mock.sector, &marker);
	requested = marker;
	requested.hm_state = HIBERNATE_MARKER_STATE_CONSUMING;
	requested.hm_crc32c++;
	check_error_without_flush(&f, EINVAL,
	    hibernate_marker_write(&f.ha, &requested), "R", 1);
}

ATF_TC_WITHOUT_HEAD(io_failures_and_flush_suppression);
ATF_TC_BODY(io_failures_and_flush_suppression, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker, out;
	unsigned int flushes;

	fixture_init(&f);
	marker = pending_marker();
	f.mock.short_read = true;
	ATF_CHECK_EQ(EIO, hibernate_marker_read(&f.ha, &out));
	check_mock(&f.mock, "R", 1, 0, 0);

	fixture_init(&f);
	f.mock.read_error = ENXIO;
	ATF_CHECK_EQ(ENXIO, hibernate_marker_write(&f.ha, &marker));
	check_mock(&f.mock, "R", 1, 0, 0);

	fixture_init(&f);
	f.mock.write_error = EIO;
	flushes = f.mock.mock_flush_count;
	ATF_CHECK_EQ(EIO, hibernate_marker_write(&f.ha, &marker));
	ATF_CHECK_EQ(flushes, f.mock.mock_flush_count);
	check_mock(&f.mock, "RW", 1, 1, 0);

	fixture_init(&f);
	f.mock.short_write = true;
	flushes = f.mock.mock_flush_count;
	ATF_CHECK_EQ(EIO, hibernate_marker_write(&f.ha, &marker));
	ATF_CHECK_EQ(flushes, f.mock.mock_flush_count);
	check_mock(&f.mock, "RW", 1, 1, 0);

	fixture_init(&f);
	f.di.dumper_flush = NULL;
	ATF_CHECK_EQ(EOPNOTSUPP, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "", 0, 0, 0);

	fixture_init(&f);
	f.mock.flush_error = EBUSY;
	ATF_CHECK_EQ(EBUSY, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "F", 0, 0, 1);
}

ATF_TC_WITHOUT_HEAD(instance_offset_and_sentinel_self_test);
ATF_TC_BODY(instance_offset_and_sentinel_self_test, tc)
{
	struct marker_fixture f;
	struct hibernate_marker marker;

	fixture_init(&f);
	marker = pending_marker();
	ATF_REQUIRE_EQ(0, hibernate_marker_write(&f.ha, &marker));
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	check_mock(&f.mock, "RWF", 1, 1, 1);

	/*
	 * Sentinel self-test only: forcing callback_active proves that the fake
	 * detects re-entry.  It is not race evidence.  Real concurrency
	 * exclusion is the caller's documented ownership precondition (design
	 * section 3.3).
	 */
	reset_observations(&f.mock);
	f.mock.callback_active = true;
	ATF_REQUIRE_EQ(0, hibernate_marker_flush(&f.ha));
	ATF_CHECK_EQ(1U, f.mock.overlap_count);
	ATF_CHECK_STREQ("F", f.mock.events);
	ATF_CHECK(!f.mock.wrong_instance);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, marker_read_order);
	ATF_TP_ADD_TC(tp, pending_write_order_and_durability);
	ATF_TP_ADD_TC(tp, state_transitions);
	ATF_TP_ADD_TC(tp, clear_order_and_zero);
	ATF_TP_ADD_TC(tp, trailer_preservation);
	ATF_TP_ADD_TC(tp, golden_pending_encoding);
	ATF_TP_ADD_TC(tp, validation_failures);
	ATF_TP_ADD_TC(tp, validation_boundaries_and_marker_content);
	ATF_TP_ADD_TC(tp, io_failures_and_flush_suppression);
	ATF_TP_ADD_TC(tp, instance_offset_and_sentinel_self_test);
	return (atf_no_error());
}
