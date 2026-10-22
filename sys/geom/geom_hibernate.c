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

	sc = arg;
	result = g_hibernate_error_result(ETIMEDOUT);
	if (sc != NULL) {
		(void)g_hibernate_publish_error(sc, ETIMEDOUT);
		return;
	}
	/*
	 * Compete atomically with taste for the unresolved discovery attempt.
	 * State 1 belongs to taste; state 2 belongs to this deadline.
	 */
	if (atomic_cmpset_acq_int(&g_hibernate_claimed, 0, 2))
		g_hibernate_complete_probe(&result);
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
	if (!atomic_cmpset_acq_int(&g_hibernate_claimed, 0, 1)) {
		if (g_hibernate_owner != NULL)
			(void)g_hibernate_publish_error(g_hibernate_owner,
			    EEXIST);
		return (NULL);
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
		 * Release the one-shot claim (but not g_hibernate_complete):
		 * this was not a genuine refusal, so a later
		 * hibernate_dumper_registered() retry must be able to
		 * re-attempt discovery from the top of this function.
		 */
		atomic_store_rel_int(&g_hibernate_claimed, 0);
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
	if (atomic_load_acq_int(&g_hibernate_complete) != 0 ||
	    atomic_load_acq_int(&g_hibernate_claimed) != 0)
		return;
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
	if (devname == NULL ||
	    atomic_load_acq_int(&g_hibernate_complete) != 0 ||
	    atomic_load_acq_int(&g_hibernate_claimed) != 0 ||
	    !g_hibernate_config.hc_enabled ||
	    strcmp(devname, g_hibernate_config.hc_name) != 0)
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
