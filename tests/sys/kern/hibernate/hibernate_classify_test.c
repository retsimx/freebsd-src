/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#define TEST_MARKER_OFFSET UINT64_C(4096)
#define TEST_MEDIA_SIZE	   (HIBERNATE_METADATA_SIZE + UINT64_C(8192))
#define TEST_IMAGE_OFFSET  (TEST_MARKER_OFFSET + HIBERNATE_METADATA_SIZE)
#define TEST_IMAGE_LENGTH  UINT64_C(4096)

static void
marker_init(struct hibernate_marker *marker, uint32_t state)
{
	memset(marker, 0, sizeof(*marker));
	marker->hm_magic = HIBERNATE_MARKER_MAGIC;
	marker->hm_version = HIBERNATE_MARKER_VERSION;
	marker->hm_state = state;
	marker->hm_image_offset = TEST_IMAGE_OFFSET;
	marker->hm_image_length = TEST_IMAGE_LENGTH;
	marker->hm_crc32c = UINT32_C(0x1234abcd);
}

static void
encode_marker(uint8_t *sector, const struct hibernate_marker *marker,
    uint32_t reserved)
{
	memset(sector, 0, DEV_BSIZE);
	le64enc(sector + HIBERNATE_MARKER_OFF_MAGIC, marker->hm_magic);
	le32enc(sector + HIBERNATE_MARKER_OFF_VERSION, marker->hm_version);
	le32enc(sector + HIBERNATE_MARKER_OFF_STATE, marker->hm_state);
	le64enc(sector + HIBERNATE_MARKER_OFF_IMAGE_OFFSET,
	    marker->hm_image_offset);
	le64enc(sector + HIBERNATE_MARKER_OFF_IMAGE_LENGTH,
	    marker->hm_image_length);
	le32enc(sector + HIBERNATE_MARKER_OFF_CRC32C, marker->hm_crc32c);
	le32enc(sector + HIBERNATE_MARKER_OFF_RESERVED_024, reserved);
}

static enum hibernate_marker_class
classify_sector(const uint8_t *sector, struct hibernate_marker_result *result)
{
	uint32_t reserved;

	memset(result, 0xa5, sizeof(*result));
	hibernate_marker_decode_complete(sector, &result->marker, &reserved);
	result->class = hibernate_marker_classify(TEST_MARKER_OFFSET,
	    TEST_MEDIA_SIZE, &result->marker, reserved);
	result->error = 0;
	return (result->class);
}

static void
check_class(uint8_t *sector, enum hibernate_marker_class expected)
{
	struct hibernate_marker_result result;

	ATF_CHECK_EQ(expected, classify_sector(sector, &result));
	ATF_CHECK_EQ(expected, result.class);
	ATF_CHECK_EQ(0, result.error);
}

ATF_TC_WITHOUT_HEAD(six_classes);
ATF_TC_BODY(six_classes, tc)
{
	struct hibernate_marker marker;
	uint8_t sector[DEV_BSIZE];

	memset(sector, 0, sizeof(sector));
	check_class(sector, HMC_ABSENT);

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_PENDING);

	marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMING;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_STALE_CONSUMING);

	marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMED;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_CONSUMED);

	marker.hm_state = UINT32_MAX;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	{
		struct hibernate_marker_result result;
		struct hibernate_marker zero_marker;
		const int transfer_error = EBUSY;

		memset(&zero_marker, 0, sizeof(zero_marker));
		memset(&result, 0xa5, sizeof(result));
		ATF_CHECK_EQ(transfer_error,
		    hibernate_marker_result_from_transfer(transfer_error,
			DEV_BSIZE, sector, TEST_MARKER_OFFSET, TEST_MEDIA_SIZE,
			&result));
		ATF_CHECK_EQ(HMC_IO_ERROR, result.class);
		ATF_CHECK_EQ(transfer_error, result.error);
		ATF_CHECK_EQ(0,
		    memcmp(&zero_marker, &result.marker, sizeof(zero_marker)));

		memset(&result, 0xa5, sizeof(result));
		ATF_CHECK_EQ(EIO,
		    hibernate_marker_result_from_transfer(0, DEV_BSIZE - 1,
			sector, TEST_MARKER_OFFSET, TEST_MEDIA_SIZE, &result));
		ATF_CHECK_EQ(HMC_IO_ERROR, result.class);
		ATF_CHECK_EQ(EIO, result.error);
		ATF_CHECK_EQ(0,
		    memcmp(&zero_marker, &result.marker, sizeof(zero_marker)));
	}
}

ATF_TC_WITHOUT_HEAD(malformed_fixtures);
ATF_TC_BODY(malformed_fixtures, tc)
{
	struct hibernate_marker marker;
	uint8_t sector[DEV_BSIZE];

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);

	marker.hm_magic ^= UINT64_C(1);
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	marker.hm_version++;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	marker_init(&marker, UINT32_C(99));
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	encode_marker(sector, &marker, 1);
	check_class(sector, HMC_MALFORMED);

	marker.hm_image_length = 0;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	marker.hm_image_offset++;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	marker.hm_image_length = UINT64_MAX;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	marker.hm_image_length = TEST_MEDIA_SIZE;
	encode_marker(sector, &marker, 0);
	check_class(sector, HMC_MALFORMED);
}

ATF_TC_WITHOUT_HEAD(decode_complete);
ATF_TC_BODY(decode_complete, tc)
{
	struct hibernate_marker marker, decoded;
	uint8_t sector[DEV_BSIZE];
	uint32_t reserved;

	marker_init(&marker, HIBERNATE_MARKER_STATE_PENDING);
	encode_marker(sector, &marker, UINT32_C(0x55aa));
	memset(&decoded, 0xa5, sizeof(decoded));
	reserved = UINT32_MAX;
	hibernate_marker_decode_complete(sector, &decoded, &reserved);
	ATF_CHECK_EQ(marker.hm_magic, decoded.hm_magic);
	ATF_CHECK_EQ(marker.hm_version, decoded.hm_version);
	ATF_CHECK_EQ(marker.hm_state, decoded.hm_state);
	ATF_CHECK_EQ(marker.hm_image_offset, decoded.hm_image_offset);
	ATF_CHECK_EQ(marker.hm_image_length, decoded.hm_image_length);
	ATF_CHECK_EQ(marker.hm_crc32c, decoded.hm_crc32c);
	ATF_CHECK_EQ(UINT32_C(0x55aa), reserved);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, six_classes);
	ATF_TP_ADD_TC(tp, malformed_fixtures);
	ATF_TP_ADD_TC(tp, decode_complete);
	return (atf_no_error());
}
