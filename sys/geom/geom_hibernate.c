/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 */

#include <sys/param.h>
#include <sys/systm.h>
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

static void
g_hibernate_worker(void *arg)
{
	struct g_hibernate_softc *sc;
	struct hibernate_attempt attempt;
	struct hibernate_marker_result result;
	uint64_t extent_end, extent_length;
	bool admitted, teardown;
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
		attempt.ha_provider_offset = 0;
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
	sc->worker_done = true;
	wakeup(sc);
	mtx_unlock(&sc->lock);

	if (admitted)
		g_hibernate_complete_probe(&result);

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

	(void)flags;
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
	if (error != 0)
		goto fail_access;
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
g_hibernate_init(void *arg)
{
	struct hibernate_marker_result result;
	int error;

	(void)arg;
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
	.taste = g_hibernate_taste,
};

DECLARE_GEOM_CLASS(g_hibernate_class, g_hibernate);
SYSINIT(g_hibernate_config, SI_SUB_KENV, SI_ORDER_ANY, g_hibernate_init, NULL);
