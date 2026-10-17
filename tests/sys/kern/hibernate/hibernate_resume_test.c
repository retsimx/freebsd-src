/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

/*
 * Production-source host tests for the K-7 resume coordinator, ownership
 * unwind, temporary stage bodies, and portable live-image validation.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/hibernate.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define	RESUME_MEDIA_SIZE	(HIBERNATE_METADATA_SIZE + DEV_BSIZE)
#define	RESUME_MAX_EVENTS	16
#define	VALID_FACS		UINT64_C(0x12345678)
#define	VALID_PHYSMEM		UINT64_C(0x40000000)
#define	VALID_ARENA_START	UINT64_C(0x100000)
#define	VALID_ARENA_SIZE	UINT64_C(0x200000)

/*
 * TEST-ONLY seams are declared by hibernate_compat.h, which is force-included
 * for both this translation unit and production kern_hibernate.c.
 */

struct resume_mock {
	uint8_t sector[DEV_BSIZE];
	char events[RESUME_MAX_EVENTS + 1];
	unsigned int event_count;
	unsigned int reads;
	unsigned int writes;
	unsigned int flushes;
	unsigned int provider_releases;
	unsigned int quiesce_rollbacks;
	unsigned int restarts;
	unsigned int owner_rollbacks;
	enum hibernate_marker_owned ownership_at_write;
};

struct resume_fixture {
	struct resume_mock mock;
	struct dumperinfo di;
	struct hibernate_attempt ha;
};

static struct resume_fixture *active_fixture;

static void
record_event(struct resume_mock *mock, char event)
{

	ATF_REQUIRE(mock->event_count < RESUME_MAX_EVENTS);
	mock->events[mock->event_count++] = event;
	mock->events[mock->event_count] = '\0';
}

static int
mock_read(void *arg, void *buf, off_t offset, size_t length)
{
	struct resume_mock *mock;

	mock = arg;
	record_event(mock, 'R');
	mock->reads++;
	if (offset != 0 || length != DEV_BSIZE)
		return (EINVAL);
	memcpy(buf, mock->sector, DEV_BSIZE);
	return (0);
}

static int
mock_write(void *arg, void *buf, off_t offset, size_t length)
{
	struct resume_mock *mock;

	mock = arg;
	record_event(mock, 'W');
	mock->writes++;
	mock->ownership_at_write = active_fixture->ha.ha_marker_owned;
	if (offset != 0 || length != DEV_BSIZE)
		return (EINVAL);
	memcpy(mock->sector, buf, DEV_BSIZE);
	return (0);
}

static int
mock_flush(struct dumperinfo *di)
{
	struct resume_mock *mock;

	mock = di->priv;
	record_event(mock, 'F');
	mock->flushes++;
	return (0);
}

static void
fixture_init(struct resume_fixture *f)
{

	memset(f, 0, sizeof(*f));
	f->di.dumper = mock_write;
	f->di.dumper_read = mock_read;
	f->di.dumper_flush = mock_flush;
	f->di.priv = &f->mock;
	f->di.blocksize = DEV_BSIZE;
	f->di.mediasize = RESUME_MEDIA_SIZE;
	f->ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	f->ha.ha_dumper = &f->di;
	f->ha.ha_provider_size = RESUME_MEDIA_SIZE;
	active_fixture = f;
}

static int
probe_pending(struct hibernate_attempt *ha)
{

	ha->ha_marker_result.class = HMC_PENDING;
	ha->ha_marker_result.error = 0;
	ha->ha_marker_result.marker.hm_magic = HIBERNATE_MARKER_MAGIC;
	ha->ha_marker_result.marker.hm_version = HIBERNATE_MARKER_VERSION;
	ha->ha_marker_result.marker.hm_state = HIBERNATE_MARKER_STATE_PENDING;
	ha->ha_marker_result.marker.hm_image_offset = HIBERNATE_METADATA_SIZE;
	ha->ha_marker_result.marker.hm_image_length = DEV_BSIZE;
	return (0);
}

static int
probe_absent(struct hibernate_attempt *ha)
{

	ha->ha_marker_result.class = HMC_ABSENT;
	ha->ha_marker_result.error = 0;
	return (0);
}

static int
probe_io_error(struct hibernate_attempt *ha)
{

	ha->ha_marker_result.class = HMC_IO_ERROR;
	ha->ha_marker_result.error = EIO;
	return (EIO);
}

static int
probe_class(struct hibernate_attempt *ha, enum hibernate_marker_class cls)
{

	ha->ha_marker_result.class = cls;
	ha->ha_marker_result.error = 0;
	ha->ha_marker_result.marker.hm_magic = HIBERNATE_MARKER_MAGIC;
	ha->ha_marker_result.marker.hm_version = HIBERNATE_MARKER_VERSION;
	ha->ha_marker_result.marker.hm_state = HIBERNATE_MARKER_STATE_CONSUMING;
	ha->ha_marker_result.marker.hm_image_offset = HIBERNATE_METADATA_SIZE;
	ha->ha_marker_result.marker.hm_image_length = DEV_BSIZE;
	return (0);
}

static int
probe_stale(struct hibernate_attempt *ha)
{

	return (probe_class(ha, HMC_STALE_CONSUMING));
}

static int
probe_consumed(struct hibernate_attempt *ha)
{

	return (probe_class(ha, HMC_CONSUMED));
}

static int
probe_malformed(struct hibernate_attempt *ha)
{

	return (probe_class(ha, HMC_MALFORMED));
}

static void
provider_release(struct hibernate_attempt *ha)
{

	active_fixture->mock.provider_releases++;
	ha->ha_has_provider = false;
	ha->ha_has_extent = false;
	ha->ha_has_root_hold = false;
}

static int
quiesce_rollback(struct hibernate_attempt *ha)
{

	active_fixture->mock.quiesce_rollbacks++;
	(void)ha;
	return (0);
}

static int
restart_cpus(cpuset_t acknowledged)
{

	active_fixture->mock.restarts++;
	(void)acknowledged;
	return (0);
}

static int
owner_rollback(struct hibernate_attempt *ha,
    enum hibernate_owner_rollback_outcome *outcome)
{

	active_fixture->mock.owner_rollbacks++;
	(void)ha;
	*outcome = HIBERNATE_OWNER_ROLLBACK_VERIFIED;
	return (0);
}

static int
cpu_validate(const struct hibernate_pcb *pcb, bool *refuse_la57,
    bool *refuse_mtrr)
{

	(void)pcb;
	*refuse_la57 = false;
	*refuse_mtrr = false;
	return (0);
}

static void
install_cleanup_seams(void)
{

	hibernate_test_provider_release_fn = provider_release;
	hibernate_test_quiesce_rollback_fn = quiesce_rollback;
	hibernate_test_restart_cpus_fn = restart_cpus;
	hibernate_test_owner_rollback_fn = owner_rollback;
}

static void
reset_seams(void)
{

	hibernate_test_probe_fn = NULL;
	hibernate_test_provider_release_fn = NULL;
	hibernate_test_quiesce_rollback_fn = NULL;
	hibernate_test_restart_cpus_fn = NULL;
	hibernate_test_owner_rollback_fn = NULL;
}

ATF_TC_WITHOUT_HEAD(coordinator_order_and_marker_ownership);
ATF_TC_BODY(coordinator_order_and_marker_ownership, tc)
{
	struct resume_fixture f;

	fixture_init(&f);
	install_cleanup_seams();
	hibernate_test_probe_fn = probe_pending;
	/*
	 * K-8's hibernate_meta_read() requires ha_has_provider before
	 * issuing any read; with no hibernate_test_provider_read_fn
	 * installed, hibernate_stage_read() still reaches exactly
	 * ENOTSUP (design 035 SS1.5's default-seam expectation), so this
	 * coordinator test's READ_METADATA-stop expectation is unchanged.
	 */
	f.ha.ha_has_provider = true;

	ATF_CHECK_EQ(ENOTSUP, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(2U, hibernate_resume_stage_log_length);
	ATF_CHECK_EQ(HIB_RESUME_PROBE, hibernate_resume_stage_log[0]);
	ATF_CHECK_EQ(HIB_RESUME_READ_METADATA,
	    hibernate_resume_stage_log[1]);
	ATF_CHECK_EQ(HM_OWNED_PENDING, f.mock.ownership_at_write);
	ATF_CHECK_EQ(HM_OWNED_NONE, f.ha.ha_marker_owned);
	ATF_CHECK_STREQ("RWF", f.mock.events);
	ATF_CHECK_EQ(1U, f.mock.writes);
	ATF_CHECK_EQ(1U, f.mock.flushes);
	ATF_CHECK_EQ(1U, f.mock.owner_rollbacks);

	fixture_init(&f);
	install_cleanup_seams();
	hibernate_test_probe_fn = probe_absent;
	ATF_CHECK_EQ(ENOENT, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(HM_OWNED_NONE, f.ha.ha_marker_owned);
	ATF_CHECK_EQ(0U, f.mock.writes);
	ATF_CHECK_EQ(0U, f.mock.flushes);

	fixture_init(&f);
	install_cleanup_seams();
	hibernate_test_probe_fn = probe_io_error;
	ATF_CHECK_EQ(EIO, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(HM_OWNED_NONE, f.ha.ha_marker_owned);
	ATF_CHECK_EQ(0U, f.mock.writes);
	ATF_CHECK_EQ(0U, f.mock.flushes);

	/*
	 * Non-PENDING, non-ABSENT classes are the coordinator's sole
	 * responsibility: with the exact provider held it must clear and
	 * flush the marker exactly once, even without an image extent
	 * (a malformed marker has no known extent).
	 */
	fixture_init(&f);
	install_cleanup_seams();
	f.ha.ha_has_provider = true;
	hibernate_test_probe_fn = probe_stale;
	ATF_CHECK_EQ(ENOENT, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(1U, f.mock.writes);
	ATF_CHECK_EQ(1U, f.mock.flushes);

	fixture_init(&f);
	install_cleanup_seams();
	f.ha.ha_has_provider = true;
	hibernate_test_probe_fn = probe_consumed;
	ATF_CHECK_EQ(ENOENT, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(1U, f.mock.writes);
	ATF_CHECK_EQ(1U, f.mock.flushes);

	fixture_init(&f);
	install_cleanup_seams();
	f.ha.ha_has_provider = true;
	hibernate_test_probe_fn = probe_malformed;
	ATF_CHECK_EQ(ENOENT, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(1U, f.mock.writes);
	ATF_CHECK_EQ(1U, f.mock.flushes);

	/* Without a held provider there is no safe clear. */
	fixture_init(&f);
	install_cleanup_seams();
	hibernate_test_probe_fn = probe_stale;
	ATF_CHECK_EQ(ENOENT, hibernate_resume_attempt(&f.ha));
	ATF_CHECK_EQ(0U, f.mock.writes);
	ATF_CHECK_EQ(0U, f.mock.flushes);
	reset_seams();
}

static void
set_cleanup_prefix(struct hibernate_attempt *ha, unsigned int prefix)
{

	ha->ha_has_root_hold = prefix >= 1;
	ha->ha_has_provider = prefix >= 2;
	ha->ha_has_extent = prefix >= 3;
	ha->ha_has_metadata = prefix >= 4;
	ha->ha_has_safe_pages = prefix >= 5;
	ha->ha_has_arena = prefix >= 6;
	ha->ha_has_admission_closed = prefix >= 7;
	ha->ha_has_quiesce = prefix >= 8;
	ha->ha_has_stopped_cpus = prefix >= 9;
}

static void
check_flags_clear(const struct hibernate_attempt *ha)
{

	ATF_CHECK(!ha->ha_has_root_hold);
	ATF_CHECK(!ha->ha_has_provider);
	ATF_CHECK(!ha->ha_has_extent);
	ATF_CHECK(!ha->ha_has_metadata);
	ATF_CHECK(!ha->ha_has_safe_pages);
	ATF_CHECK(!ha->ha_has_arena);
	ATF_CHECK(!ha->ha_has_admission_closed);
	ATF_CHECK(!ha->ha_has_quiesce);
	ATF_CHECK(!ha->ha_has_stopped_cpus);
}

ATF_TC_WITHOUT_HEAD(cleanup_idempotence);
ATF_TC_BODY(cleanup_idempotence, tc)
{
	struct resume_fixture f;
	unsigned int prefix;

	for (prefix = 0; prefix <= 9; prefix++) {
		fixture_init(&f);
		install_cleanup_seams();
		set_cleanup_prefix(&f.ha, prefix);
		hibernate_attempt_cleanup(&f.ha);
		hibernate_attempt_cleanup(&f.ha);
		check_flags_clear(&f.ha);
		ATF_CHECK(f.mock.provider_releases <= 1);
		ATF_CHECK(f.mock.quiesce_rollbacks <= 1);
		ATF_CHECK(f.mock.restarts <= 1);
		/*
		 * Selected-owner rollback is deliberately unconditional, once
		 * per cleanup invocation, and is therefore the sole exception
		 * to flag-gated release counting.
		 */
		ATF_CHECK_EQ(2U, f.mock.owner_rollbacks);
	}
	reset_seams();
}

typedef int (*stage_fn_t)(struct hibernate_attempt *);

static void
check_stub(stage_fn_t fn)
{
	struct hibernate_attempt before, ha;

	ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	ha.ha_has_root_hold = true;
	ha.ha_has_metadata = true;
	ha.ha_has_arena = true;
	before = ha;
	ATF_CHECK_EQ(ENOTSUP, fn(&ha));
	ATF_CHECK_EQ(0, memcmp(&before, &ha, sizeof(ha)));
}

/*
 * temporary_stubs: K-12 stubs.  hibernate_meta_read(),
 * hibernate_safe_pages_alloc(), hibernate_payload_read() and
 * hibernate_image_crc32c_verify() (formerly hibernate_payload_verify())
 * are landed K-8 bodies (design 035 SS1.5) and no longer compile
 * against check_stub()'s unconditional-ENOTSUP contract; only the
 * still-unimplemented K-12 quiesce/CPU-restart seams remain here.
 */
ATF_TC_WITHOUT_HEAD(temporary_stubs);
ATF_TC_BODY(temporary_stubs, tc)
{
	struct hibernate_attempt before, ha;
	cpuset_t target, acknowledged;

	reset_seams();
	check_stub(hibernate_quiesce);
	check_stub(hibernate_quiesce_rollback);

	ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	ha.ha_has_extent = true;
	before = ha;
	memset(&target, 0, sizeof(target));
	memset(&acknowledged, 0xa5, sizeof(acknowledged));
	ATF_CHECK_EQ(ENOTSUP, hibernate_stop_cpus(target, &acknowledged));
	ATF_CHECK_EQ(0, memcmp(&before, &ha, sizeof(ha)));
	ATF_CHECK_EQ(ENOTSUP, hibernate_restart_cpus(acknowledged));
	ATF_CHECK_EQ(0, memcmp(&before, &ha, sizeof(ha)));
}

static void
validation_fixture(struct hibernate_attempt *ha, vm_paddr_t *intervals)
{

	*ha = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;
	intervals[0] = UINT64_C(0x400000);
	intervals[1] = UINT64_C(0x402000);
	ha->ha_dst_intervals = intervals;
	ha->ha_dst_count = 1;
	ha->ha_dst_valid = true;
	/*
	 * Claim the transition arena through the production K-9 path rather
	 * than writing ha_arena_start/size directly, so the arena-agreement
	 * check is exercised against a genuinely claimed tuple.
	 */
	hibernate_arena_reset();
	ATF_REQUIRE_EQ(0, hibernate_arena_reserve(VALID_ARENA_START,
	    VALID_ARENA_SIZE));
	ATF_REQUIRE_EQ(0, hibernate_arena_claim(ha));
	ha->ha_image.hi_cb.hc_facs_hardware_signature = VALID_FACS;
	ha->ha_image.hi_cb.hc_physmem_bytes = VALID_PHYSMEM;
	ha->ha_image.hi_cb.hc_arena_start = ha->ha_arena_start;
	ha->ha_image.hi_cb.hc_arena_size = ha->ha_arena_size;
	hibernate_test_facs_signature = VALID_FACS;
	hibernate_test_physmem_bytes = VALID_PHYSMEM;
	hibernate_test_amd64_cpu_validate = cpu_validate;
}

ATF_TC_WITHOUT_HEAD(image_validation);
ATF_TC_BODY(image_validation, tc)
{
	struct hibernate_attempt ha;
	vm_paddr_t intervals[2];

	validation_fixture(&ha, intervals);
	ATF_CHECK_EQ(0, hibernate_image_validate(&ha));

	validation_fixture(&ha, intervals);
	ha.ha_image.hi_cb.hc_facs_hardware_signature++;
	ATF_CHECK_EQ(EINVAL, hibernate_image_validate(&ha));

	validation_fixture(&ha, intervals);
	ha.ha_image.hi_cb.hc_physmem_bytes++;
	ATF_CHECK_EQ(EINVAL, hibernate_image_validate(&ha));

	validation_fixture(&ha, intervals);
	ha.ha_image.hi_cb.hc_arena_start++;
	ATF_CHECK_EQ(EINVAL, hibernate_image_validate(&ha));

	validation_fixture(&ha, intervals);
	intervals[0] = VALID_ARENA_START + HIB_PAGE_SIZE;
	intervals[1] = intervals[0] + HIB_PAGE_SIZE;
	ATF_CHECK_EQ(EINVAL, hibernate_image_validate(&ha));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, coordinator_order_and_marker_ownership);
	ATF_TP_ADD_TC(tp, cleanup_idempotence);
	ATF_TP_ADD_TC(tp, temporary_stubs);
	ATF_TP_ADD_TC(tp, image_validation);
	return (atf_no_error());
}
