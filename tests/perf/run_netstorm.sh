#!/usr/bin/env bash
# Where the sensor runs out of capacity under a loopback connection storm, and whether every event that is lost is
# reported. For each rate it starts a real sensor, drives the load, waits for the pipeline to drain, and prints:
#
#   conns/s     connections per second the generator actually reached (errors in brackets)
#   prov_ev     events the network provider handed to the sensor (a connection is four: connect, accept, two closes)
#   delivered   events that reached the write-ahead log
#   loss        every loss the sensor reported, by stage (kernel = ring buffer overflow, queue = the in-memory queue)
#   gap         prov_ev - delivered - reported queue loss. Nothing should be unaccounted, so this is ~0 (a few hundred
#               other events the sensor emits itself, such as state and health, show up as a small negative number)
#   cpu         CPU of the pipeline thread over the storm, and rss_MiB the peak resident set of the process
#
# Nothing here is a pass/fail test: it measures the boundary so the loss reporting can be read against it.
#
# usage: sudo tests/perf/run_netstorm.sh [seconds per step] [rate rate ...]      (defaults: 15 s; 2000 5000 8000 0)
# A rate of 0 means as fast as the load generator can go. Environment: SENSORD / CTL paths, PERF_DIR (work directory),
# PERF_LOAD_CPUS (taskset list for the generator, e.g. 0-3, so it does not compete with the sensor), PERF_PROCS (generator
# processes, default 3), PERF_PORT_PAUSE (seconds between steps, default 65: each connection leaves a TIME_WAIT socket for
# 60 s and the ephemeral range is about 28000 ports, so without a pause the next step measures port exhaustion).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/tests/perf
SENSORD=${SENSORD:-$ROOT/build/panopticon-sensord}
CTL=${CTL:-$ROOT/build/panopticon-ctl}
W=${PERF_DIR:-/var/tmp/perf-netstorm}
SECONDS_PER_STEP=${1:-15}
shift 2>/dev/null
RATES=("$@"); [ ${#RATES[@]} -gt 0 ] || RATES=(2000 5000 8000 0)

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$SENSORD" ] || { echo "build first: $SENSORD" >&2; exit 2; }
pkill -INT -f panopticon-sensord 2>/dev/null; sleep 1
clock_ticks=$(getconf CLK_TCK)
LOADPIN=(); [ -n "${PERF_LOAD_CPUS:-}" ] && LOADPIN=(taskset -c "$PERF_LOAD_CPUS")
# The pipeline thread is the process's first thread: it is the one that serialises and writes, so it is the one whose
# saturation sets the ceiling.
cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/task/$1/stat"; }
# "<records> <events> <events handed over by all providers>" from the control socket.
snapshot() { "$CTL" --socket "$W/ctl.sock" status 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); d=d.get("result",d)
print(d["totals"]["records"], d["totals"]["events"], sum(p.get("events", 0) for p in d.get("providers", [])))'; }

printf '%-7s %-17s %-9s %-9s %-8s %-6s %-7s %-6s %s\n' target conns/s prov_ev delivered gap cpu rss_MiB "" "loss reported (stage=events)"
for rate in "${RATES[@]}"; do
  rm -rf "$W"; mkdir -p "$W"
  printf 'sensor_id=perf-sensor\nhost_id=%s\nwal_path=%s/wal\nwal_quota_bytes=1073741824\n' "$(tr -d '\n-' </etc/machine-id)" "$W" >"$W/sensor.conf"
  "$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >"$W/sensord.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do [ -S "$W/ctl.sock" ] && break; sleep 0.1; done
  sleep 3
  read -r _ e0 p0 < <(snapshot)
  t0=$(cpu_ticks "$pid"); s0=$SECONDS
  load=$("${LOADPIN[@]}" python3 "$HERE/netstorm.py" --rate "$rate" --seconds "$SECONDS_PER_STEP" --procs "${PERF_PROCS:-3}")
  t1=$(cpu_ticks "$pid"); s1=$SECONDS
  # Wait for the pipeline to drain what the queue still holds: the delivered count stops moving.
  last=-1
  for _ in $(seq 1 60); do
    read -r _ e1 p1 < <(snapshot)
    [ "$e1" = "$last" ] && break
    last=$e1; sleep 2
  done
  rss=$(awk '/^VmHWM:/ {printf "%d", $2 / 1024}' "/proc/$pid/status")
  kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  cps=$(echo "$load" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("%s (%d err)" % (d["conns_per_s"], d["errors"]))')
  # Every loss the sensor reported, by stage: the loss records sit in the WAL as plain JSON.
  losses=$(python3 - "$W" <<'PY'
import glob, re, sys
totals = {}
for path in sorted(glob.glob(sys.argv[1] + "/wal/wal-*.log")):
    for match in re.finditer(rb'"stage":"([a-z_]+)","count":(\d+)', open(path, "rb").read()):
        totals[match.group(1).decode()] = totals.get(match.group(1).decode(), 0) + int(match.group(2))
print(",".join("%s=%d" % item for item in sorted(totals.items())) or "none")
PY
)
  queue=$(echo "$losses" | grep -o 'queue=[0-9]*' | cut -d= -f2)
  printf '%-7s %-17s %-9s %-9s %-8s %-6s %-7s %-6s %s\n' "$rate" "$cps" "$((p1 - p0))" "$((e1 - e0))" "$(( (p1 - p0) - (e1 - e0) - ${queue:-0} ))" \
    "$(python3 -c "print(round(($t1 - $t0) / $clock_ticks / max($s1 - $s0, 1) * 100))")%" "$rss" "" "$losses"
  sleep "${PERF_PORT_PAUSE:-65}"
done
