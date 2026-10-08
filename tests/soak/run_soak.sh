#!/usr/bin/env bash
# Multi-hour soak of the sensor under mixed load, Manager faults and signed dry-run commands (see soak.py).
#
# usage: sudo tests/soak/run_soak.sh [hours] [work-dir]
# Environment: SENSORD, CTL, SIGNER (default build-rel/...), SCALE (workload multiplier, default 1),
#              PANOPTICON_SOURCE_HEAD (the commit that was built, recorded in run.json when the tree has no .git).
# Results: <work-dir>/report.txt and report.json; the raw samples, store and logs stay beside them.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HOURS=${1:-6}
W=${2:-/var/tmp/soak}
SENSORD=${SENSORD:-$ROOT/build-rel/panopticon-sensord}
CTL=${CTL:-$ROOT/build-rel/panopticon-ctl}
SIGNER=${SIGNER:-$ROOT/build-rel/panopticon-command-signer}
for binary in "$SENSORD" "$CTL" "$SIGNER"; do [ -x "$binary" ] || { echo "missing $binary" >&2; exit 2; }; done
[ "$(id -u)" = 0 ] || { echo "run as root (eBPF, fanotify, audit)" >&2; exit 2; }
# By process name: `pkill -f` would also match a wrapper whose command line names the daemon (SENSORD=... as an argument).
pkill -INT -x panopticon-sens 2>/dev/null; sleep 1; pkill -9 -x panopticon-sens 2>/dev/null
pkill -9 -f fake_command_manager.py 2>/dev/null
rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
exec python3 "$ROOT/tests/soak/soak.py" run --hours "$HOURS" --work "$W" --sensord "$SENSORD" --ctl "$CTL" --signer "$SIGNER" \
  --scale "${SCALE:-1}"
