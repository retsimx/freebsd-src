# SPDX-License-Identifier: BSD-2-Clause
#
# Offline shared-decoder frontend for ABI 1 hibernate images.
#
# Codec source: ${SRCTOP}/sys/kern/kern_hibernate.c is compiled directly
# so that the offline tool exercises the identical parser and iterator
# as the kernel.  No second ELF/CB/PCB parser exists in this directory.
#
# Userland compatibility seam:
#   kern_hibernate.c includes <sys/systm.h>, which is a kernel-only header.
#   This is resolved via -D_HIBERNATE_USERLAND_BUILD (same mechanism as the
#   ATF test) plus -include of tests/sys/kern/hibernate/hibernate_compat.h,
#   which provides the required userland headers.  Both the tool and the ATF
#   test share the same single seam; hibernate_userland.h is no longer used.
#
# Usage:
#   make            # build hibernate_decode
#   make clean
#
# Runtime:
#   ./hibernate_decode <prefix-file>
#   Exit 0 = valid ABI 1 prefix; nonzero = malformed (message on stderr).

PROG=	hibernate_decode
SRCS=	hibernate_decode.c \
	kern_hibernate.c
MAN=

# Pull in the codec source from the kernel tree.
.PATH:	${SRCTOP}/sys/kern

# Portability seam: use the same mechanism as the ATF test.
# -D_HIBERNATE_USERLAND_BUILD causes kern_hibernate.c to omit <sys/systm.h>
# and use userland headers instead.  -include of hibernate_compat.h (from
# the ATF test directory) provides the standard userland headers.
CFLAGS+=	-I${SRCTOP}/sys \
		-D_HIBERNATE_USERLAND_BUILD \
		-include ${SRCTOP}/tests/sys/kern/hibernate/hibernate_compat.h

# Suppress _Static_assert layout witnesses that use __aligned(), which
# the kernel header guards with #ifndef _LOCORE but which may warn in
# userland with strict -Wpedantic.  We compile as C11.
CFLAGS+=	-std=c11

.include <bsd.prog.mk>
