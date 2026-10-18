# SPDX-License-Identifier: BSD-2-Clause
#
# ATF tests for the amd64 hibernate transition-arena ABI.
#
# These tests compile the MI codec directly, using the unchanged compatibility
# seam from tests/sys/kern/hibernate.  hibernate_machdep.c is deliberately not
# linked: its CR3, MSR, direct-map, pmap, and assembly behaviour is kernel-only.

.include <src.opts.mk>

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/amd64/hibernate

ATF_TESTS_C+=	hibernate_arena_header_test
ATF_TESTS_C+=	hibernate_machdep_test

SRCS.hibernate_arena_header_test+=	hibernate_arena_header_test.c
SRCS.hibernate_arena_header_test+=	kern_hibernate.c

SRCS.hibernate_machdep_test+=	hibernate_machdep_test.c
SRCS.hibernate_machdep_test+=	kern_hibernate.c

.PATH:	${SRCTOP}/sys/kern

CFLAGS.kern_hibernate.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.kern_hibernate.c+=	-include ${SRCTOP}/tests/sys/kern/hibernate/hibernate_compat.h
CFLAGS.kern_hibernate.c+=	-Wno-missing-prototypes

CFLAGS.hibernate_arena_header_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_arena_header_test.c+=	-include ${SRCTOP}/tests/sys/kern/hibernate/hibernate_compat.h
CFLAGS.hibernate_machdep_test.c+=	-D_HIBERNATE_USERLAND_BUILD
CFLAGS.hibernate_machdep_test.c+=	-include ${SRCTOP}/tests/sys/kern/hibernate/hibernate_compat.h

WARNS?=	3

.include <bsd.test.mk>
