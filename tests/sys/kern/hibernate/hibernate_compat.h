/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Narrow portability seam for compiling kern/kern_hibernate.c outside
 * the kernel (ATF tests, offline tools).  No layout or validation
 * policy lives here; only the minimum stub definitions needed to satisfy
 * the compiler.
 *
 * Include this file BEFORE any sys/ headers when building in userland.
 */

#ifndef _HIBERNATE_COMPAT_H_
#define _HIBERNATE_COMPAT_H_

/*
 * Prevent kernel-only headers from being included.
 * kern_hibernate.c includes <sys/systm.h> which is kernel-only.
 * We define _KERNEL_UT (userland translation) guard and provide
 * the minimal stubs sys/systm.h would otherwise supply.
 *
 * Strategy: define _KERNEL before any sys/ include so that
 * sys/param.h and sys/types.h do the right thing for the codec
 * primitives (le64dec, le32dec, le16dec, __builtin_*, bool), then
 * intercept <sys/systm.h> with a no-op via a -include or by
 * replacing it here before kern_hibernate.c is compiled.
 *
 * We use a simpler approach: the Makefile passes
 *   -D_HIBERNATE_USERLAND_BUILD
 * and kern_hibernate.c has a conditional include block that
 * substitutes userland headers when that macro is defined.
 *
 * This file is included by the Makefile via CFLAGS+= -include.
 * It must be idempotent and self-contained.
 */

#ifndef _HIBERNATE_USERLAND_BUILD
#define _HIBERNATE_USERLAND_BUILD
#endif

/*
 * Pull in the standard userland headers that cover everything
 * kern_hibernate.c needs outside the kernel:
 *   - stdint.h    : uint8_t, uint16_t, uint32_t, uint64_t, UINT32_C
 *   - stdbool.h   : bool, true, false
 *   - stddef.h    : size_t, NULL
 *   - string.h    : memcpy/memset (for __builtin_memcpy/__builtin_memset)
 *   - sys/endian.h: le64dec, le32dec, le16dec (available in userland)
 *   - errno.h     : EINVAL, EOVERFLOW, ENOENT, E2BIG, ENOTSUP
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/endian.h>

/*
 * sys/param.h is safe in userland (it guards _KERNEL-only sections).
 * sys/types.h is also safe.  Include them so that the codec source's
 * own #include <sys/param.h> is a no-op (include guard).
 */
#include <sys/types.h>
#include <sys/param.h>

/*
 * Provide the ELF constants that kern_hibernate.c references from
 * <sys/elf64.h> and <sys/elf_common.h>.  In userland those headers
 * are available as <sys/elf64.h> and <sys/elf_common.h> but some
 * constants are gated on _KERNEL.  Define only what kern_hibernate.c
 * actually uses.
 */
#include <sys/elf64.h>
#include <sys/elf_common.h>

#ifndef DEV_BSIZE
#define DEV_BSIZE 512
#endif

#ifndef EOPNOTSUPP
#define EOPNOTSUPP ENOTSUP
#endif

struct dumperinfo;

typedef int dumper_t(void *_priv, void *_virtual, off_t _offset,
    size_t _length);
typedef int dumper_read_t(void *_priv, void *_virtual, off_t _offset,
    size_t _length);
typedef int dumper_flush_t(struct dumperinfo *di);

struct dumperinfo {
	dumper_t *dumper;
	dumper_read_t *dumper_read;
	dumper_flush_t *dumper_flush;
	void *priv;
	u_int blocksize;
	off_t mediaoffset;
	off_t mediasize;
};

/* ELFCLASS64 / ELFDATA2LSB / EV_CURRENT are always exposed. */
/* ET_FREEBSD_HIBERNATE_IMAGE and PT_FREEBSD_HIBERNATE_* are in elf_common.h. */

/*
 * __builtin_add_overflow, __builtin_mul_overflow, __builtin_memcpy,
 * __builtin_memset are GCC/Clang builtins available unconditionally.
 * No stub needed.
 */

#endif /* _HIBERNATE_COMPAT_H_ */
