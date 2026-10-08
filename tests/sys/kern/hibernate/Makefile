# SPDX-License-Identifier: BSD-2-Clause
#
# ATF test for the ABI 1 hibernate image codec.
#
# Compiles kern/kern_hibernate.c directly from the source tree so that
# the test exercises the identical authoritative decoder used by the
# kernel and the offline tool.  A narrow portability seam
# (hibernate_compat.h, included via CFLAGS -include) substitutes
# <sys/systm.h> with userland equivalents when
# _HIBERNATE_USERLAND_BUILD is defined; no layout or validation policy
# lives in the seam.

.include <src.opts.mk>

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/kern/hibernate

ATF_TESTS_C+=	hibernate_format_test
ATF_TESTS_C+=	hibernate_marker_test

SRCS.hibernate_format_test+=	hibernate_format_test.c
SRCS.hibernate_format_test+=	kern_hibernate.c

SRCS.hibernate_marker_test+=	hibernate_marker_test.c
SRCS.hibernate_marker_test+=	kern_hibernate.c

# Pull in kern_hibernate.c from the kernel source tree.
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
CFLAGS.hibernate_format_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_marker_test.c+=	-D_HIBERNATE_USERLAND_BUILD

WARNS?=	3

.include <bsd.test.mk>
