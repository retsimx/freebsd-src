#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

set -eu

srcdir=${SRCTOP:-$(CDPATH= cd -- "$(dirname -- "$0")/../../../../.." && pwd)}
header="$srcdir/sys/sys/hibernate.h"
kern="$srcdir/sys/kern/kern_hibernate.c"
geom="$srcdir/sys/geom/geom_hibernate.c"
shutdown="$srcdir/sys/kern/kern_shutdown.c"
swap="$srcdir/sys/vm/swap_pager.c"
mountroot="$srcdir/sys/kern/vfs_mountroot.c"

enum=$(sed -n '/enum hibernate_marker_class {/,/};/p' "$header")
count=$(printf '%s\n' "$enum" |
    grep -Ec '^[[:space:]]*HMC_[A-Z_]+,?$')
[ "$count" -eq 6 ]
printf '%s\n' "$enum" | grep -q 'HMC_STALE_CONSUMING'
printf '%s\n' "$enum" | grep -q 'HMC_MALFORMED'
! grep -REn '\b(HMC_CONSUMING|HMC_INVALID|hmr_class|hmr_marker|hmr_error)\b' \
    "$srcdir/sys" "$srcdir/tests/sys/kern/hibernate"
grep -q '#define HCB_VERSION[[:space:]]*1' "$header"
grep -q '#define HIBERNATE_MARKER_ENCODED_SIZE[[:space:]]*40' "$header"
grep -q '#define HIBERNATE_MARKER_STATE_PENDING[[:space:]]*1' "$header"
grep -q '#define HIBERNATE_MARKER_STATE_CONSUMING[[:space:]]*2' "$header"
grep -q '#define HIBERNATE_MARKER_STATE_CONSUMED[[:space:]]*3' "$header"
grep -q '\.class = HMC_ABSENT, \.error = 0' "$header"

grep -q 'hibernate_marker_result_from_transfer(' "$kern"
grep -q 'hibernate_marker_result_from_transfer(raw.error,' "$kern"
grep -q '&ha->ha_marker_result' "$kern"
grep -q 'hibernate_marker_result_from_transfer(int error' "$header"
grep -q 'hibernate_provider_conflicts(&id)' "$shutdown"
grep -q 'hibernate_provider_conflicts(&id)' "$swap"
grep -q 'hibernate_probe_active()' "$mountroot"
grep -q 'hibernate_extent_hold(&sc->id' "$geom"
grep -q 'hibernate_extent_release' "$kern"
grep -q 'root_mount_hold("hibernate")' "$geom"
grep -q 'root_mount_rel(hold)' "$geom"
grep -q 'atomic_cmpset_int(&g_hibernate_complete, 0, 1)' "$geom"

printf '%s\n' "PASS: K-4 source contracts"
printf '%s\n' "six classes; old names absent; ABI constants unchanged"
printf '%s\n' "probe transfer seam, root hold, swap/dumper guards, extent paths"
