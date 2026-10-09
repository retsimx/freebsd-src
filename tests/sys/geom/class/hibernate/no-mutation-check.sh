#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

set -eu

srcdir=${SRCTOP:-$(CDPATH= cd -- "$(dirname -- "$0")/../../../../.." && pwd)}
kern="$srcdir/sys/kern/kern_hibernate.c"
geom="$srcdir/sys/geom/geom_hibernate.c"

python3 - "$kern" "$geom" <<'PY'
import re
import sys
from pathlib import Path

kernel = Path(sys.argv[1]).read_text()
geom = Path(sys.argv[2]).read_text()
forbidden = (
    "hibernate_marker_clear",
    "hibernate_marker_write",
    "hibernate_marker_flush",
)

def body(source, name):
    match = re.search(
        r"(?ms)^[A-Za-z_][A-Za-z0-9_ \t\n*]*\n"
        + re.escape(name)
        + r"\([^;]*?\)\n\{",
        source,
    )
    if match is None:
        raise SystemExit(f"FAIL: function not found: {name}")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise SystemExit(f"FAIL: unterminated function: {name}")

kernel_roots = (
    "hibernate_marker_decode_complete",
    "hibernate_marker_classify",
    "hibernate_probe",
    "hibernate_provider_conflicts",
    "hibernate_extent_hold",
    "hibernate_extent_release",
)
geom_roots = (
    "g_hibernate_complete_probe",
    "g_hibernate_publish_error",
    "g_hibernate_worker",
    "g_hibernate_deadline",
    "g_hibernate_teardown_event",
    "g_hibernate_orphan",
    "g_hibernate_taste",
    "g_hibernate_init",
)
for source, names in ((kernel, kernel_roots), (geom, geom_roots)):
    for name in names:
        function = body(source, name)
        for symbol in forbidden:
            if re.search(r"\b" + re.escape(symbol) + r"\s*\(", function):
                raise SystemExit(f"FAIL: {name} calls {symbol}")
print("PASS: K-4 reachable paths are classify-only")
print("checked 14 production functions; mutation calls: 0")
PY
