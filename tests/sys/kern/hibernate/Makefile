# SPDX-License-Identifier: BSD-2-Clause
#
# ATF tests for the ABI 1 hibernate image codec and K-5 capacity
# arithmetic.
#
# Compiles kern/kern_hibernate.c directly from the source tree so that
# the tests exercise the identical authoritative code used by the kernel
# and the offline tool.  A narrow portability seam
# (hibernate_compat.h, included via CFLAGS -include) substitutes
# <sys/systm.h> with userland equivalents when
# _HIBERNATE_USERLAND_BUILD is defined; no layout or validation policy
# lives in the seam.

.include <src.opts.mk>

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/kern/hibernate

ATF_TESTS_C+=	hibernate_arena_test
ATF_TESTS_C+=	hibernate_capacity_test
ATF_TESTS_C+=	hibernate_classify_test
ATF_TESTS_C+=	hibernate_dump_extent_test
ATF_TESTS_C+=	hibernate_format_test
ATF_TESTS_C+=	hibernate_marker_test

SRCS.hibernate_arena_test+=	hibernate_arena_test.c
SRCS.hibernate_arena_test+=	kern_hibernate.c

SRCS.hibernate_capacity_test+=	hibernate_capacity_test.c
SRCS.hibernate_capacity_test+=	kern_hibernate.c

SRCS.hibernate_dump_extent_test+=	hibernate_dump_extent_test.c

SRCS.hibernate_classify_test+=	hibernate_classify_test.c
SRCS.hibernate_classify_test+=	kern_hibernate.c

SRCS.hibernate_format_test+=	hibernate_format_test.c
SRCS.hibernate_format_test+=	kern_hibernate.c

SRCS.hibernate_marker_test+=	hibernate_marker_test.c
SRCS.hibernate_marker_test+=	kern_hibernate.c

# Pull in kern_hibernate.c and kern_dump.c from the kernel source tree.
.PATH:	${SRCTOP}/sys/kern

# Dual-build portability seam: define _HIBERNATE_USERLAND_BUILD so
# kern_hibernate.c omits <sys/systm.h> and uses userland headers
# instead.  The compat header is force-included before any other
# header so that bool/size_t/errno are available.
CFLAGS.kern_hibernate.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.kern_hibernate.c+=	-include ${.CURDIR}/hibernate_compat.h

# The codec uses __builtin_* which are always available in GCC/Clang.
# Suppress missing-prototypes for kern_hibernate.c (same pattern as
# subr_unit_test in the parent Makefile).
CFLAGS.kern_hibernate.c+=	-Wno-missing-prototypes

# sys/sys/hibernate.h uses _Static_assert and HIBERNATE_LAYOUT_ASSERT;
# those are compile-time-only and are safe in userland with C11.
CFLAGS.hibernate_arena_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_capacity_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_classify_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_format_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_marker_test.c+=	-D_HIBERNATE_USERLAND_BUILD

# The extent test defines _HIBERNATE_DUMP_EXTENT_TEST itself before including
# kern_dump.c, compiling only dumpsys_hibernate_start() and its minimal
# dependencies.  sys/sys/ headers are available in the userland include path.
CFLAGS.hibernate_dump_extent_test.c+=	-I${SRCTOP}/sys
CFLAGS.hibernate_dump_extent_test.c+=	-Wno-missing-prototypes

WARNS?=	3

.include <bsd.test.mk>
