/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Direct boundary and sentinel regression coverage of the authoritative
 * production dumpsys_hibernate_start() calculation in sys/kern/kern_dump.c.
 *
 * This file compiles the real production function by defining
 * _HIBERNATE_DUMP_EXTENT_TEST and including kern_dump.c directly.
 * No copy of the arithmetic lives here; the test exercises the identical
 * code path used by the kernel.
 */

/*
 * All required types, constants, and the production function must be
 * established before the ATF test-case bodies reference them.
 *
 * Order:
 *   1. Minimal standard headers (stdint, errno, string)
 *   2. Stub type definitions matching exactly the fields that
 *      dumpsys_hibernate_start() reads and writes
 *   3. _HIBERNATE_DUMP_EXTENT_TEST guard + #include "kern_dump.c"
 *      (compiles only the production function body)
 *   4. ATF headers and test cases
 */

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

/*
 * SIZEOF_METADATA: matches sys/sys/kerneldump.h (64 KiB).
 */
#define	SIZEOF_METADATA	((uint64_t)(64 * 1024))

/*
 * Byte-order macros: identity functions for little-endian amd64.
 * This seam is amd64/little-endian-specific; the test is not portable
 * to big-endian targets without replacing these with real conversions.
 */
#ifndef htod64
#define	htod64(x)	(x)
#endif
#ifndef dtoh64
#define	dtoh64(x)	(x)
#endif

/*
 * Minimal stub types for dumpsys_hibernate_start().
 *
 * kerneldumpcomp: only its NULL/non-NULL value is tested (compression flag).
 * kerneldumpheader: only dumpextent is accessed.
 * dumperinfo: only mediaoffset, mediasize, dumpoff, and kdcomp are accessed.
 */
struct kerneldumpcomp {
	int _placeholder;
};

struct kerneldumpheader {
	uint64_t	dumpextent;
	char		_pad[504]; /* unused in test */
};

struct dumperinfo {
	off_t	mediaoffset;
	off_t	mediasize;
	off_t	dumpoff;
	struct kerneldumpcomp *kdcomp;
};

/* Typedef stubs required by the static forward declarations in kern_dump.c. */
typedef int dumper_t(void *, void *, off_t, size_t);
typedef int dumper_read_t(void *, void *, off_t, size_t);
typedef int dumper_flush_t(struct dumperinfo *);
typedef int dumper_start_t(struct dumperinfo *, struct kerneldumpheader *,
    void *, uint32_t);
typedef int dumper_hdr_t(struct dumperinfo *, struct kerneldumpheader *);

/*
 * Compile the authoritative production function body.
 * _HIBERNATE_DUMP_EXTENT_TEST causes kern_dump.c to skip all kernel-only
 * code and compile only dumpsys_hibernate_start().
 */
#define _HIBERNATE_DUMP_EXTENT_TEST
#include "kern_dump.c"

/*
 * ATF test framework.  Included after the production function so that
 * the function definition is visible to all test-case bodies below.
 */
#include <atf-c.h>

/* ------------------------------------------------------------------ */
/* Test helpers                                                         */
/* ------------------------------------------------------------------ */

#define	M	SIZEOF_METADATA

/*
 * Sentinel for di->dumpoff: a non-zero bit pattern that no success path
 * would write (success writes mediaoffset + M, never this value for the
 * mediaoffset values used in tests).
 */
#define	SENTINEL_DUMPOFF	((off_t)0x5A5A5A5A5A5A5A5ALL)

static struct dumperinfo
make_di(int compressed, uint64_t mediasize, off_t mediaoffset)
{
	static struct kerneldumpcomp fake_kdcomp;
	struct dumperinfo di;
	memset(&di, 0, sizeof(di));
	di.mediaoffset = mediaoffset;
	di.mediasize   = (off_t)mediasize;
	di.dumpoff     = SENTINEL_DUMPOFF;
	di.kdcomp      = compressed ? &fake_kdcomp : NULL;
	return (di);
}

static struct kerneldumpheader
make_kdh(uint64_t dumpextent)
{
	struct kerneldumpheader kdh;
	memset(&kdh, 0, sizeof(kdh));
	kdh.dumpextent = htod64(dumpextent);
	return (kdh);
}

/* ------------------------------------------------------------------ */
/* T5 test cases                                                        */
/* ------------------------------------------------------------------ */

/*
 * Compressed P = M - 1 (P < M < S): E2BIG, both sentinels unchanged.
 */
ATF_TC(compressed_p_less_than_m);
ATF_TC_HEAD(compressed_p_less_than_m, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Compressed provider P=M-1: E2BIG, sentinels unchanged");
}
ATF_TC_BODY(compressed_p_less_than_m, tc)
{
	const uint64_t D = 4096;
	const uint64_t P = M - 1;
	struct dumperinfo di = make_di(1, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);
	uint64_t orig_extent = kdh.dumpextent;

	ATF_CHECK_EQ(E2BIG, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(orig_extent, kdh.dumpextent);
	ATF_CHECK_EQ(SENTINEL_DUMPOFF, di.dumpoff);
}

/*
 * Compressed P = M, D > 0 (M <= P < S): success, published extent 0.
 */
ATF_TC(compressed_p_equals_m);
ATF_TC_HEAD(compressed_p_equals_m, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Compressed provider P=M: success, extent 0");
}
ATF_TC_BODY(compressed_p_equals_m, tc)
{
	const uint64_t D = 4096;
	const uint64_t P = M;
	const off_t off = 512;
	struct dumperinfo di = make_di(1, P, off);
	struct kerneldumpheader kdh = make_kdh(D);

	ATF_CHECK_EQ(0, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(htod64(0), kdh.dumpextent);
	ATF_CHECK_EQ(off + (off_t)M, di.dumpoff);
}

/*
 * Compressed P = M + 1, D > 1 (M <= P < S): success, published extent 1.
 */
ATF_TC(compressed_p_equals_m_plus_1);
ATF_TC_HEAD(compressed_p_equals_m_plus_1, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Compressed provider P=M+1: success, extent 1");
}
ATF_TC_BODY(compressed_p_equals_m_plus_1, tc)
{
	const uint64_t D = 4096;
	const uint64_t P = M + 1;
	struct dumperinfo di = make_di(1, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);

	ATF_CHECK_EQ(0, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(htod64(1), kdh.dumpextent);
	ATF_CHECK_EQ((off_t)M, di.dumpoff);
}

/*
 * Compressed P = S - 1 (M <= P < S): success, published extent D - 1.
 */
ATF_TC(compressed_p_equals_s_minus_1);
ATF_TC_HEAD(compressed_p_equals_s_minus_1, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Compressed provider P=S-1: success, extent D-1");
}
ATF_TC_BODY(compressed_p_equals_s_minus_1, tc)
{
	const uint64_t D = 8192;
	const uint64_t P = M + D - 1;
	struct dumperinfo di = make_di(1, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);

	ATF_CHECK_EQ(0, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(htod64(D - 1), kdh.dumpextent);
	ATF_CHECK_EQ((off_t)M, di.dumpoff);
}

/*
 * P = S, compressed: success, original D retained.
 */
ATF_TC(p_equals_s_compressed);
ATF_TC_HEAD(p_equals_s_compressed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Compressed provider P=S: success, original D retained");
}
ATF_TC_BODY(p_equals_s_compressed, tc)
{
	const uint64_t D = 8192;
	const uint64_t P = M + D;
	struct dumperinfo di = make_di(1, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);
	uint64_t orig_extent = kdh.dumpextent;

	ATF_CHECK_EQ(0, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(orig_extent, kdh.dumpextent);
	ATF_CHECK_EQ((off_t)M, di.dumpoff);
}

/*
 * P = S, uncompressed: success, original D retained.
 */
ATF_TC(p_equals_s_uncompressed);
ATF_TC_HEAD(p_equals_s_uncompressed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Uncompressed provider P=S: success, original D retained");
}
ATF_TC_BODY(p_equals_s_uncompressed, tc)
{
	const uint64_t D = 8192;
	const uint64_t P = M + D;
	struct dumperinfo di = make_di(0, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);
	uint64_t orig_extent = kdh.dumpextent;

	ATF_CHECK_EQ(0, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(orig_extent, kdh.dumpextent);
	ATF_CHECK_EQ((off_t)M, di.dumpoff);
}

/*
 * D = UINT64_MAX - M + 1: M + D overflows, E2BIG, sentinels unchanged.
 */
ATF_TC(span_overflow);
ATF_TC_HEAD(span_overflow, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "D=UINT64_MAX-M+1: M+D overflows, E2BIG, sentinels unchanged");
}
ATF_TC_BODY(span_overflow, tc)
{
	const uint64_t D = UINT64_MAX - M + 1;
	const uint64_t P = UINT64_MAX;
	struct dumperinfo di = make_di(1, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);
	uint64_t orig_extent = kdh.dumpextent;

	ATF_CHECK_EQ(E2BIG, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(orig_extent, kdh.dumpextent);
	ATF_CHECK_EQ(SENTINEL_DUMPOFF, di.dumpoff);
}

/*
 * Uncompressed P < S: E2BIG, sentinels unchanged.
 */
ATF_TC(uncompressed_undersized);
ATF_TC_HEAD(uncompressed_undersized, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Uncompressed provider P<S: E2BIG, sentinels unchanged");
}
ATF_TC_BODY(uncompressed_undersized, tc)
{
	const uint64_t D = 4096;
	const uint64_t P = M + D - 1;
	struct dumperinfo di = make_di(0, P, 0);
	struct kerneldumpheader kdh = make_kdh(D);
	uint64_t orig_extent = kdh.dumpextent;

	ATF_CHECK_EQ(E2BIG, dumpsys_hibernate_start(&di, &kdh, NULL, 0));
	ATF_CHECK_EQ(orig_extent, kdh.dumpextent);
	ATF_CHECK_EQ(SENTINEL_DUMPOFF, di.dumpoff);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, compressed_p_less_than_m);
	ATF_TP_ADD_TC(tp, compressed_p_equals_m);
	ATF_TP_ADD_TC(tp, compressed_p_equals_m_plus_1);
	ATF_TP_ADD_TC(tp, compressed_p_equals_s_minus_1);
	ATF_TP_ADD_TC(tp, p_equals_s_compressed);
	ATF_TP_ADD_TC(tp, p_equals_s_uncompressed);
	ATF_TP_ADD_TC(tp, span_overflow);
	ATF_TP_ADD_TC(tp, uncompressed_undersized);
	return (atf_no_error());
}
