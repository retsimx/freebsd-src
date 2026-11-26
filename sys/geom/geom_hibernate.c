/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/callout.h>
#include <sys/conf.h>
#include <sys/hibernate.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>

#include <geom/geom.h>
#include <geom/geom_int.h>

struct g_hibernate_softc {
	struct mtx lock;
	struct g_geom *geom;
	struct g_consumer *consumer;
	struct dumperinfo *dumper;
	struct proc *worker;
	struct hibernate_provider_id id;
	struct hibernate_attempt attempt;
	struct callout deadline;
	u_int io_inflight;
	bool admission_open;
	bool extent_held;
	bool teardown_requested;
	bool teardown_done;
	bool worker_done;
};

static struct hibernate_config g_hibernate_config;
static struct hibernate_marker_result g_hibernate_result = {
	.class = HMC_ABSENT,
	.error = 0,
};
static struct callout g_hibernate_deadline_callout;
static struct root_hold_token *g_hibernate_root_hold;
static struct g_hibernate_softc *g_hibernate_owner;
static volatile u_int g_hibernate_complete;
/*
 * K24-T00: g_hibernate_claimed state values.
 *   0 -- unclaimed: no taste has ever attempted discovery for the
 *        configured provider (or a prior attempt fully completed and
 *        reset nothing -- in practice state only ever returns to 0
 *        implicitly via process exit, never explicitly after this fix).
 *   1 -- an attempt owns discovery: either a live g_hibernate_softc
 *        exists (admission in flight, protected by its own per-attempt
 *        sc->deadline) or a taste call is briefly executing.
 *   2 -- transient target value only: written by g_hibernate_deadline()
 *        (the global, arg == NULL boot-time deadline) at the instant it
 *        wins the race and panics; never read back as a stable state.
 *   3 -- retry pending: a taste hit ENXIO on hibernate_dumper_lookup()
 *        (the documented GEOM_HIBERNATE-races-ahead-of-GEOM_DEV ordering,
 *        see g_hibernate_taste()'s "retryable" comment below) and is
 *        waiting for hibernate_dumper_registered()'s retry
 *        (g_hibernate_retry_event()) to re-taste once the dumper exists.
 *        The root-mount hold stays open throughout (g_hibernate_complete_
 *        probe() is not called on this path). Holding state at 3 instead
 *        of releasing it to 0 is what prevents the global deadline from
 *        treating a pending retry as "never tasted at all".
 */
static volatile u_int g_hibernate_claimed;

static void g_hibernate_teardown_event(void *, int);
static void g_hibernate_teardown_topology(struct g_hibernate_softc *);
static void g_hibernate_retry_event(void *, int);

/*
 * K13-T00 fix: g_hibernate_retry_event() (defined before the class's own
 * definition further down) re-enters g_hibernate_taste() directly, so the
 * class object needs a forward declaration here.
 */
static struct g_class g_hibernate_class;

static struct hibernate_marker_result
g_hibernate_error_result(int error)
{
	struct hibernate_marker_result result;

	memset(&result, 0, sizeof(result));
	result.class = HMC_IO_ERROR;
	result.error = error != 0 ? error : EIO;
	return (result);
}

static void
g_hibernate_complete_probe(const struct hibernate_marker_result *result)
{
	struct root_hold_token *hold;

	if (!atomic_cmpset_int(&g_hibernate_complete, 0, 1))
		return;
	if (result != NULL)
		g_hibernate_result = *result;
	hibernate_probe_complete();
	hold = g_hibernate_root_hold;
	g_hibernate_root_hold = NULL;
	if (hold != NULL)
		root_mount_rel(hold);
}

static bool
g_hibernate_publish_error(struct g_hibernate_softc *sc, int error)
{
	struct hibernate_marker_result result;
	bool published;

	result = g_hibernate_error_result(error);
	mtx_lock(&sc->lock);
	published = sc->admission_open;
	if (published) {
		sc->attempt.ha_marker_result = result;
		sc->admission_open = false;
		sc->teardown_requested = true;
	}
	mtx_unlock(&sc->lock);
	if (published)
		g_hibernate_complete_probe(&result);
	return (published);
}

static bool
g_hibernate_release_owner(struct g_hibernate_softc *sc)
{
	struct dumperinfo *dumper;
	bool extent_held;

	mtx_lock(&sc->lock);
	if (sc->teardown_done || !sc->worker_done || sc->io_inflight != 0) {
		mtx_unlock(&sc->lock);
		return (false);
	}
	sc->teardown_done = true;
	extent_held = sc->extent_held;
	sc->extent_held = false;
	dumper = sc->dumper;
	sc->dumper = NULL;
	mtx_unlock(&sc->lock);

	if (extent_held)
		hibernate_extent_release(&sc->id);
	if (dumper != NULL)
		dumper_drop(dumper);
	hibernate_owner_deactivate(&sc->id);
	return (true);
}

void
hibernate_provider_release(struct hibernate_attempt *ha)
{
	struct g_hibernate_softc *sc;
	bool extent_held;

	if (ha == NULL)
		return;

	/*
	 * Reuse the existing teardown primitives; clear each flag only
	 * after its action completes.  Idempotent.
	 */
	sc = g_hibernate_owner;
	if (ha->ha_has_extent && sc != NULL) {
		mtx_lock(&sc->lock);
		extent_held = sc->extent_held;
		sc->extent_held = false;
		mtx_unlock(&sc->lock);
		if (extent_held)
			hibernate_extent_release(&sc->id);
		ha->ha_has_extent = false;
	}
	if (ha->ha_has_provider && sc != NULL &&
	    g_hibernate_release_owner(sc)) {
		(void)g_waitfor_event(g_hibernate_teardown_event, sc, M_WAITOK,
		    NULL);
		ha->ha_has_provider = false;
	}
	if (ha->ha_has_root_hold) {
		if (g_hibernate_root_hold != NULL) {
			root_mount_rel(g_hibernate_root_hold);
			g_hibernate_root_hold = NULL;
		}
		ha->ha_has_root_hold = false;
	}
}

/*
 * hibernate_provider_read() streams bytes through the K-4 access-held
 * consumer with the topology lock absent.  It performs no write, no
 * marker operation, and no extent/topology change; it adds no access
 * count beyond the one g_hibernate_taste() already holds.
 *
 * Every BIO is waited on (biowait()) before the next is submitted, so
 * no I/O is outstanding when this function returns, on either the
 * success or the failure path.
 */
int
hibernate_provider_read(struct hibernate_attempt *ha, uint64_t offset,
    void *buf, size_t length)
{
	uint8_t bounce[DEV_BSIZE];
	struct g_hibernate_softc *sc;
	struct g_consumer *cp;
	struct bio *bp;
	uint8_t *dst;
	uint64_t end, sector_off;
	size_t n, copy_off, copy_len;
	int error;

	g_topology_assert_not();

	sc = g_hibernate_owner;
	if (ha == NULL || buf == NULL || length == 0 || sc == NULL ||
	    !ha->ha_has_provider)
		return (EINVAL);

	if (__builtin_add_overflow(offset, length, &end))
		return (EOVERFLOW);
	if (end > sc->id.media_size)
		return (EINVAL);

	mtx_lock(&sc->lock);
	cp = sc->consumer;
	if (cp == NULL || cp->provider == NULL || sc->teardown_done) {
		mtx_unlock(&sc->lock);
		return (ENXIO);
	}
	sc->io_inflight++;
	mtx_unlock(&sc->lock);

	dst = buf;
	error = 0;
	while (length > 0) {
		if ((offset % DEV_BSIZE) != 0 || length < DEV_BSIZE) {
			sector_off = rounddown(offset, DEV_BSIZE);
			copy_off = (size_t)(offset - sector_off);
			copy_len = MIN(length, DEV_BSIZE - copy_off);

			bp = g_alloc_bio();
			bp->bio_cmd = BIO_READ;
			bp->bio_offset = sector_off;
			bp->bio_data = bounce;
			bp->bio_length = DEV_BSIZE;
			bp->bio_done = NULL;
			g_io_request(bp, cp);
			error = biowait(bp, "hibrd");
			if (error == 0 && bp->bio_completed != bp->bio_length)
				error = EIO;
			g_destroy_bio(bp);
			if (error != 0)
				break;

			memcpy(dst, bounce + copy_off, copy_len);
			n = copy_len;
		} else {
			n = rounddown(MIN(length, maxphys), DEV_BSIZE);

			bp = g_alloc_bio();
			bp->bio_cmd = BIO_READ;
			bp->bio_offset = offset;
			bp->bio_data = dst;
			bp->bio_length = n;
			bp->bio_done = NULL;
			g_io_request(bp, cp);
			error = biowait(bp, "hibrd");
			if (error == 0 && bp->bio_completed != bp->bio_length)
				error = EIO;
			g_destroy_bio(bp);
			if (error != 0)
				break;
		}

		dst += n;
		offset += n;
		length -= n;
	}

	mtx_lock(&sc->lock);
	sc->io_inflight--;
	mtx_unlock(&sc->lock);

	return (error);
}

static void
g_hibernate_worker(void *arg)
{
	struct g_hibernate_softc *sc;
	struct hibernate_attempt attempt;
	struct hibernate_marker_result result;
	uint64_t extent_end, extent_length;
	bool admitted, extent_held, teardown;
	int error;

	sc = arg;
	g_topology_assert_not();
	attempt = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;

	mtx_lock(&sc->lock);
	admitted = sc->admission_open;
	if (admitted) {
		sc->io_inflight++;
		attempt.ha_dumper = sc->dumper;
		attempt.ha_marker_offset = sc->dumper->mediaoffset;
		/*
		 * K13-T00 fix: hibernate_marker_classify() (called via
		 * hibernate_probe() -> hibernate_marker_result_from_
		 * transfer()) requires its "marker_offset" argument to equal
		 * the exact base that was added when the on-disk marker's
		 * hm_image_offset was encoded -- the dumper's absolute
		 * mediaoffset, matching ha_marker_offset above -- not 0.
		 * This dumper's provider *is* the GPT partition (its
		 * mediaoffset already encodes the partition's absolute disk
		 * offset), so "provider-relative" here means relative to the
		 * whole backing disk, the same frame hm_image_offset was
		 * written in.  With 0, every genuine PENDING/CONSUMED/
		 * STALE_CONSUMING marker misclassifies as HMC_MALFORMED and
		 * the K-7 resume path is never entered.  This path was never
		 * exercised with a real marker before K13-T00 (the taste-
		 * order and CAM-periph-lock fixes, applied earlier in this
		 * task) let the probe run to completion for the first time.
		 */
		attempt.ha_provider_offset = sc->dumper->mediaoffset;
		attempt.ha_provider_size = sc->id.media_size;
	}
	mtx_unlock(&sc->lock);

	error = admitted ? hibernate_probe(&attempt) : ECANCELED;
	result = attempt.ha_marker_result;
	if (admitted && error == 0 && result.class != HMC_ABSENT &&
	    result.class != HMC_MALFORMED) {
		if (__builtin_add_overflow(result.marker.hm_image_offset,
			result.marker.hm_image_length, &extent_end) ||
		    extent_end < attempt.ha_provider_offset)
			error = EOVERFLOW;
		else {
			extent_length = extent_end - attempt.ha_provider_offset;
			error = hibernate_extent_hold(&sc->id,
			    attempt.ha_provider_offset, extent_length);
			if (error == 0) {
				mtx_lock(&sc->lock);
				sc->extent_held = true;
				mtx_unlock(&sc->lock);
			}
		}
		if (error != 0)
			result = g_hibernate_error_result(error);
	}

	/*
	 * Stop and drain the deadline before final publication.  If timeout won
	 * the race, admission is already closed and its result remains final.
	 */
	callout_drain(&sc->deadline);

	mtx_lock(&sc->lock);
	if (admitted)
		sc->io_inflight--;
	if (sc->admission_open) {
		sc->attempt.ha_marker_result = result;
		sc->admission_open = false;
		teardown = error != 0;
		if (teardown)
			sc->teardown_requested = true;
		admitted = true;
	} else {
		teardown = sc->teardown_requested;
		admitted = false;
	}
	extent_held = sc->extent_held;
	mtx_unlock(&sc->lock);

	/*
	 * Hand the classified attempt to the K-7 coordinator in the same kproc
	 * before signalling worker completion.  The coordinator owns every
	 * RESTORE-attempt marker clear/flush, including the narrow
	 * classification clear for a stale, consumed, or malformed marker.
	 */
	if (admitted && error == 0 &&
	    (result.class == HMC_PENDING ||
	    result.class == HMC_STALE_CONSUMING ||
	    result.class == HMC_CONSUMED ||
	    result.class == HMC_MALFORMED)) {
		attempt.ha_has_root_hold = true;
		attempt.ha_has_provider = true;
		attempt.ha_has_extent = extent_held;
		hibernate_resume_attempt(&attempt);
		result = attempt.ha_marker_result;
	}
	if (admitted)
		g_hibernate_complete_probe(&result);

	mtx_lock(&sc->lock);
	sc->worker_done = true;
	wakeup(sc);
	mtx_unlock(&sc->lock);

	if (teardown && g_hibernate_release_owner(sc))
		(void)g_waitfor_event(g_hibernate_teardown_event, sc, M_WAITOK,
		    NULL);
	kproc_exit(0);
}

static void
g_hibernate_deadline(void *arg)
{
	struct g_hibernate_softc *sc;
	struct hibernate_marker_result result;
	u_int cur;

	sc = arg;
	result = g_hibernate_error_result(ETIMEDOUT);
	if (sc != NULL) {
		/*
		 * K24-T00 (round 2): this is the PER-ATTEMPT deadline,
		 * started only after g_hibernate_taste() has already
		 * found the matching provider, located its registered
		 * dumper, and opened admission (sc->admission_open = true
		 * in g_hibernate_taste(), just above the
		 * callout_reset(&sc->deadline, ...) that arms this
		 * callout).  Firing here therefore means a genuine image
		 * was found and admitted, but g_hibernate_worker() (the
		 * kproc that calls hibernate_probe() to read the marker
		 * and, if PENDING, hibernate_resume_attempt()) did not
		 * finish within hc_wait_ms -- a second, previously
		 * unguarded silent-cold-boot path distinct from the
		 * global/state-3 one fixed above: g_hibernate_publish_
		 * error() below closes admission and calls
		 * g_hibernate_complete_probe() exactly like a genuine
		 * "no image present" result, releasing the root-mount
		 * hold with no panic and -- because admission_open was
		 * true, not merely claimed -- WITHOUT ever going through
		 * the state-3 "retry pending" path this round's earlier
		 * fix covers.  Confirmed directly this round: K24
		 * production-kernel N=12 after the first admission fix
		 * still produced 7/12 cold boots with zero "hibernate:
		 * k24t00"/"hibernate: k12" diagnostic prints and zero
		 * admission-timeout panics -- this per-attempt path was
		 * the remaining gap.
		 *
		 * Fail closed here too, for the identical reason: a
		 * silent cold boot over a confirmed-present, confirmed-
		 * admitted image is strictly worse than a loud failure.
		 * g_hibernate_publish_error() returns true only when it
		 * actually found admission_open still true and closed it
		 * (false means the worker already finished first and this
		 * callout lost the race harmlessly) -- panic only in the
		 * true case.
		 */
		if (g_hibernate_publish_error(sc, ETIMEDOUT)) {
			panic("GEOM_HIBERNATE: provider \"%s\" has an "
			    "admitted hibernate image but the probe/resume "
			    "worker did not complete within hc_wait_ms=%u "
			    "ms; refusing to silently cold boot over an "
			    "unconsumed image", sc->id.name,
			    g_hibernate_config.hc_wait_ms);
		}
		return;
	}
	/*
	 * Compete atomically with taste for the unresolved discovery attempt.
	 * State 1 belongs to taste; state 2 belongs to this deadline.
	 */
	if (atomic_cmpset_acq_int(&g_hibernate_claimed, 0, 2)) {
		g_hibernate_complete_probe(&result);
		return;
	}
	/*
	 * K24-T00: the cmpset above only succeeds from state 0 ("no taste
	 * ever matched the configured provider").  State 3 ("retry
	 * pending" -- g_hibernate_taste() found the provider but
	 * hibernate_dumper_lookup() raced ahead of GEOM_DEV's own
	 * registration, see that function's "retryable" comment) is a
	 * DIFFERENT, much more dangerous case to let through silently: it
	 * means a hibernate image is confirmed present on the configured
	 * provider -- that's the only way discovery could have progressed
	 * past the name/sectorsize/mediasize checks to reach
	 * hibernate_dumper_lookup() at all -- and the retry driven by
	 * hibernate_dumper_registered() has still not completed admission
	 * after the full hc_wait_ms deadline.
	 *
	 * Before this fix, the prior round's cmpset(0, 2) here used to
	 * succeed in exactly this situation, because a retryable ENXIO
	 * reset the claim all the way back to 0 instead of parking it at
	 * 3 -- silently calling g_hibernate_complete_probe() and
	 * releasing the root-mount hold with no admission ever attempted
	 * and no diagnostic printed anywhere: an operator-invisible cold
	 * boot with a valid, CRC-verified PENDING image still on disk.
	 * Confirmed directly this round on the K24 production
	 * (non-debug) kernel: 9/12 restores cold-booted exactly this way,
	 * indistinguishable in every log from an ordinary successful boot
	 * except for the absent "hibernate: k24t00"/"hibernate: k12"
	 * diagnostic trail.
	 *
	 * A silent cold boot is strictly worse than a loud failure: fail
	 * closed instead.  This is a boot-time-only path (the global
	 * deadline fires once per boot, long before any user process
	 * exists), so panic() is the correct terminal action -- there is
	 * no running system yet to degrade gracefully into, and silently
	 * continuing a normal boot is exactly the bug being fixed.
	 */
	cur = atomic_load_acq_int(&g_hibernate_claimed);
	if (cur == 3) {
		panic("GEOM_HIBERNATE: provider \"%s\" has a pending "
		    "hibernate image but admission did not complete "
		    "within hc_wait_ms=%u ms; refusing to silently cold "
		    "boot over an unconsumed image",
		    g_hibernate_config.hc_name, g_hibernate_config.hc_wait_ms);
	}
}

static void
g_hibernate_teardown_topology(struct g_hibernate_softc *sc)
{
	struct g_consumer *cp;
	struct g_geom *gp;

	g_topology_assert();
	cp = sc->consumer;
	gp = sc->geom;
	if (cp != NULL) {
		g_access(cp, -1, -1, 0);
		if (cp->provider != NULL)
			g_detach(cp);
		g_destroy_consumer(cp);
		sc->consumer = NULL;
	}
	if (gp != NULL) {
		g_wither_geom(gp, ENXIO);
		sc->geom = NULL;
	}
	if (g_hibernate_owner == sc)
		g_hibernate_owner = NULL;
}

static void
g_hibernate_teardown_event(void *arg, int flag)
{
	(void)flag;
	g_hibernate_teardown_topology(arg);
}

static void
g_hibernate_orphan(struct g_consumer *cp)
{
	struct g_hibernate_softc *sc;
	bool drained;

	g_topology_assert();
	sc = cp->geom->softc;
	if (sc == NULL)
		return;

	(void)g_hibernate_publish_error(sc, ENXIO);
	mtx_lock(&sc->lock);
	sc->teardown_requested = true;
	drained = sc->worker_done && sc->io_inflight == 0;
	mtx_unlock(&sc->lock);

	/*
	 * A running worker observes teardown_requested after finishing I/O.
	 * A completed worker has no coordinator left, so orphan owns teardown.
	 */
	if (drained && g_hibernate_release_owner(sc))
		g_hibernate_teardown_topology(sc);
}

static struct g_geom *
g_hibernate_taste(struct g_class *mp, struct g_provider *pp, int flags)
{
	struct g_hibernate_softc *sc;
	struct hibernate_marker_result result;
	struct g_consumer *cp;
	struct g_geom *gp;
	size_t length;
	int error;
	bool retryable;

	(void)flags;
	retryable = false;
	g_topology_assert();
	if (!g_hibernate_config.hc_enabled ||
	    atomic_load_acq_int(&g_hibernate_complete) != 0 ||
	    strcmp(pp->name, g_hibernate_config.hc_name) != 0 ||
	    pp->sectorsize != DEV_BSIZE || pp->mediasize <= 0)
		return (NULL);
	/*
	 * K24-T00: claim from EITHER state 0 (never tasted) or state 3
	 * (a prior taste hit the GEOM_DEV-not-yet-registered race below,
	 * parked the claim at 3, and is waiting for exactly this retried
	 * call).  A plain cmpset(0, 1) here -- the original form -- can
	 * only ever succeed on the very first taste; every retry taste
	 * driven by hibernate_dumper_registered() would then find the
	 * claim already non-zero and bail out as EEXIST, so the retry
	 * this whole mechanism exists for could never actually run.
	 */
	for (;;) {
		u_int cur = atomic_load_acq_int(&g_hibernate_claimed);

		if (cur != 0 && cur != 3) {
			if (g_hibernate_owner != NULL)
				(void)g_hibernate_publish_error(
				    g_hibernate_owner, EEXIST);
			return (NULL);
		}
		if (atomic_cmpset_acq_int(&g_hibernate_claimed, cur, 1))
			break;
	}
	sc = malloc(sizeof(*sc), M_GEOM, M_WAITOK | M_ZERO);
	mtx_init(&sc->lock, "geom hibernate", NULL, MTX_DEF);
	callout_init(&sc->deadline, 1);
	length = strlcpy(sc->id.name, pp->name, sizeof(sc->id.name));
	if (length >= sizeof(sc->id.name)) {
		error = ENAMETOOLONG;
		goto fail;
	}
	sc->id.media_size = (uint64_t)pp->mediasize;
	sc->attempt = (struct hibernate_attempt)HIBERNATE_ATTEMPT_INIT;

	gp = g_new_geomf(mp, "hibernate.%s", pp->name);
	gp->softc = sc;
	gp->orphan = g_hibernate_orphan;
	sc->geom = gp;
	cp = g_new_consumer(gp);
	sc->consumer = cp;
	error = g_attach(cp, pp);
	if (error != 0)
		goto fail_geom;
	error = g_access(cp, 1, 1, 0);
	if (error != 0)
		goto fail_attached;
	if (strcmp(pp->name, sc->id.name) != 0 ||
	    (uint64_t)pp->mediasize != sc->id.media_size ||
	    pp->sectorsize != DEV_BSIZE) {
		error = ENXIO;
		goto fail_access;
	}
	error = hibernate_dumper_lookup(&sc->id, &sc->dumper);
	if (error != 0) {
		/*
		 * K13-T00 fix: GEOM_HIBERNATE's taste always races ahead of
		 * GEOM_DEV's for this same new-provider arrival (confirmed
		 * empirically: g_hibernate_class precedes g_dev_class in
		 * g_classes), so ENXIO here usually means "no dumper yet",
		 * not a real refusal.  Defer instead of latching the
		 * one-shot probe closed; hibernate_dumper_registered() below
		 * retries once dumper_insert() actually registers a match.
		 */
		retryable = (error == ENXIO);
		goto fail_access;
	}
	error = hibernate_owner_publish(&sc->id);
	if (error != 0)
		goto fail_dumper;

	sc->admission_open = true;
	g_hibernate_owner = sc;
	error = kproc_create(g_hibernate_worker, sc, &sc->worker, 0, 0,
	    "g_hibernate");
	if (error != 0)
		goto fail_owner;
	callout_reset(&sc->deadline,
	    MAX(1, (g_hibernate_config.hc_wait_ms * hz) / 1000),
	    g_hibernate_deadline, sc);
	/*
	 * Topology context cannot drain.  The atomic discovery claim
	 * prevents a running callback from completing this attempt.
	 */
	callout_stop(&g_hibernate_deadline_callout);
	return (gp);

fail_owner:
	g_hibernate_owner = NULL;
	sc->admission_open = false;
	hibernate_owner_deactivate(&sc->id);
fail_dumper:
	dumper_drop(sc->dumper);
	sc->dumper = NULL;
fail_access:
	g_access(cp, -1, -1, 0);
fail_attached:
	g_detach(cp);
fail_geom:
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
fail:
	if (retryable) {
		mtx_destroy(&sc->lock);
		free(sc, M_GEOM);
		/*
		 * K24-T00: park the claim at state 3 ("retry pending"), not
		 * 0.  Resetting fully to 0 here used to let the global
		 * boot-time deadline (g_hibernate_deadline_callout, arg ==
		 * NULL, below) race the pending hibernate_dumper_
		 * registered() retry and sometimes win it -- especially on
		 * a fast, non-debug kernel -- silently calling
		 * g_hibernate_complete_probe() and releasing the
		 * root-mount hold with no admission ever attempted and no
		 * diagnostic printed: an undetectable cold boot with a
		 * valid, CRC-verified PENDING image still on disk
		 * (confirmed directly this round: K24 production-kernel
		 * verification, 9/12 restores cold-booted this way).  This
		 * was not a genuine refusal -- a later
		 * hibernate_dumper_registered() retry must still be able
		 * to re-attempt discovery (g_hibernate_taste()'s own entry
		 * cmpset above accepts state 3 as well as state 0) -- but
		 * the global deadline below must now be able to tell this
		 * state apart from "nothing ever matched" and refuse to
		 * silently complete while it persists.
		 */
		atomic_store_rel_int(&g_hibernate_claimed, 3);
		return (NULL);
	}
	result = g_hibernate_error_result(error);
	sc->attempt.ha_marker_result = result;
	/*
	 * Retain the taste-owned claim through completion.  Reopening state
	 * zero would let a running discovery callback publish ETIMEDOUT.
	 */
	mtx_destroy(&sc->lock);
	free(sc, M_GEOM);
	g_hibernate_complete_probe(&result);
	return (NULL);
}

static void
g_hibernate_retry_event(void *arg, int flag)
{
	struct g_provider *pp;

	(void)arg;
	if (flag == EV_CANCEL)
		return;
	g_topology_assert();
	/*
	 * K24-T00: state 3 ("retry pending", set by g_hibernate_taste()'s
	 * own retryable-ENXIO path) is exactly the state this retry exists
	 * to resolve -- do not treat it as "already claimed by someone
	 * else" and bail.  Only a genuinely different claim (any value
	 * other than 0 or 3) means another attempt owns discovery.
	 */
	if (atomic_load_acq_int(&g_hibernate_complete) != 0)
		return;
	{
		u_int cur = atomic_load_acq_int(&g_hibernate_claimed);
		if (cur != 0 && cur != 3)
			return;
	}
	pp = g_provider_by_name(g_hibernate_config.hc_name);
	if (pp != NULL)
		(void)g_hibernate_taste(&g_hibernate_class, pp, 0);
}

/*
 * K13-T00 fix (design-039 debug addendum, option b): called by
 * dumper_insert() (sys/kern/kern_shutdown.c) after every successful
 * dumper registration.  This removes GEOM_HIBERNATE's dependency on
 * tasting after GEOM_DEV for the same provider: a deferred discovery
 * attempt (see the "retryable" ENXIO path in g_hibernate_taste() above)
 * only needed to know a matching dumper now exists, not which GEOM
 * class order produced it.
 *
 * g_post_event() is safe to call from any context (topology held or
 * not, any lock held) and runs the callback later from the GEOM event
 * thread with topology held, matching g_hibernate_taste()'s own
 * precondition.
 */
void
hibernate_dumper_registered(const char *devname)
{
	u_int cur;

	if (devname == NULL ||
	    atomic_load_acq_int(&g_hibernate_complete) != 0 ||
	    !g_hibernate_config.hc_enabled ||
	    strcmp(devname, g_hibernate_config.hc_name) != 0)
		return;
	/*
	 * K24-T00: state 3 ("retry pending") is the normal, expected state
	 * here -- it is what g_hibernate_taste()'s retryable-ENXIO path
	 * sets precisely so that THIS callback's retry can still proceed.
	 * Treating any nonzero claim as "someone else owns discovery" (the
	 * original check) silently dropped every retry: once the first
	 * taste parked at 3, this function would see claimed != 0 and
	 * return without ever posting g_hibernate_retry_event(), and the
	 * attempt could only complete via the global deadline timing out
	 * (see g_hibernate_deadline()) -- or, before this fix, by that
	 * deadline silently succeeding instead.
	 */
	cur = atomic_load_acq_int(&g_hibernate_claimed);
	if (cur != 0 && cur != 3)
		return;
	(void)g_post_event(g_hibernate_retry_event, NULL, M_NOWAIT, NULL);
}

static void
g_hibernate_init(struct g_class *mp)
{
	struct hibernate_marker_result result;
	int error;

	(void)mp;
	callout_init(&g_hibernate_deadline_callout, 1);
	error = hibernate_config_get(&g_hibernate_config);
	if (error != 0) {
		hibernate_probe_begin();
		g_hibernate_root_hold = root_mount_hold("hibernate");
		result = g_hibernate_error_result(error);
		printf("GEOM_HIBERNATE: invalid configuration: %d\n", error);
		g_hibernate_complete_probe(&result);
		return;
	}
	if (!g_hibernate_config.hc_enabled)
		return;
	hibernate_probe_begin();
	g_hibernate_root_hold = root_mount_hold("hibernate");
	callout_reset(&g_hibernate_deadline_callout,
	    MAX(1, (g_hibernate_config.hc_wait_ms * hz) / 1000),
	    g_hibernate_deadline, NULL);
}

static struct g_class g_hibernate_class = {
	.name = "HIBERNATE",
	.version = G_VERSION,
	.init = g_hibernate_init,
	.taste = g_hibernate_taste,
};

DECLARE_GEOM_CLASS(g_hibernate_class, g_hibernate);
