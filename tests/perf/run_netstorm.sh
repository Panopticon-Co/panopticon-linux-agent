#!/usr/bin/env bash
# Where the network provider runs out of capacity: a loopback connection storm at rising rates against a real
# sensor, and for each rate how many records the sensor wrote, what the kernel ring buffer dropped (reported by the
# sensor as a `kernel` loss with an exact count), and how much CPU and memory it used. Nothing here is a pass/fail
# test: it measures the boundary so the loss reporting can be read against it.
#
# usage: sudo tests/perf/run_netstorm.sh [seconds per step] [rate rate ...]      (defaults: 15 s; 2000 5000 8000 0)
# A rate of 0 means as fast as the load generator can go. SENSORD / CTL override the paths.
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
# PERF_LOAD_CPUS=0,1 keeps the load generator off the other CPUs, so the sensor is not competing with it for them;
# PERF_PROCS sets the number of generator processes (default 3).
LOADPIN=(); [ -n "${PERF_LOAD_CPUS:-}" ] && LOADPIN=(taskset -c "$PERF_LOAD_CPUS")
cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }
field() { python3 -c 'import json,sys
d=json.load(sys.stdin); d=d.get("result",d)
for p in sys.argv[1].split("."): d=d.get(p) if isinstance(d,dict) else None
print("" if d is None else d)' "$1"; }

printf '%-8s %-10s %-10s %-10s %-12s %-9s %-8s %s\n' target conns/s records rec/s kernel_loss sensor_cpu rss_MiB "loss detail"
for rate in "${RATES[@]}"; do
  rm -rf "$W"; mkdir -p "$W"
  printf 'sensor_id=perf-sensor\nhost_id=%s\nwal_path=%s/wal\nwal_quota_bytes=1073741824\n' "$(tr -d '\n-' </etc/machine-id)" "$W" >"$W/sensor.conf"
  "$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >"$W/sensord.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do [ -S "$W/ctl.sock" ] && break; sleep 0.1; done
  sleep 3
  r0=$("$CTL" --socket "$W/ctl.sock" status 2>/dev/null | field totals.records)
  t0=$(cpu_ticks "$pid"); s0=$SECONDS
  load=$("${LOADPIN[@]}" python3 "$HERE/netstorm.py" --rate "$rate" --seconds "$SECONDS_PER_STEP" --procs "${PERF_PROCS:-3}")
  t1=$(cpu_ticks "$pid"); s1=$SECONDS
  sleep 5                                    # let the pipeline drain what the ring still holds
  r1=$("$CTL" --socket "$W/ctl.sock" status 2>/dev/null | field totals.records)
  rss=$(awk '/^VmHWM:/ {printf "%d", $2 / 1024}' "/proc/$pid/status")
  kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  cps=$(echo "$load" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conns_per_s"], "errors=%d" % d["errors"], sep="/")')
  # Every loss the sensor reported, by stage: the loss records sit in the WAL as plain JSON.
  losses=$(python3 - "$W" <<'PY'
import glob, re, sys
totals = {}
for path in sorted(glob.glob(sys.argv[1] + "/wal/wal-*.log")):
    for match in re.finditer(rb'"loss":\{"stage":"([a-z_]+)","count":(\d+)', open(path, "rb").read()):
        totals[match.group(1).decode()] = totals.get(match.group(1).decode(), 0) + int(match.group(2))
print(",".join("%s=%d" % item for item in sorted(totals.items())) or "none")
PY
)
  kernel=$(echo "$losses" | grep -o 'kernel=[0-9]*' | cut -d= -f2)
  printf '%-8s %-10s %-10s %-10s %-12s %-9s %-8s %s\n' "$rate" "$cps" "$((r1 - r0))" "$(( (r1 - r0) / SECONDS_PER_STEP ))" "${kernel:-0}" \
    "$(python3 -c "print(round(($t1 - $t0) / $clock_ticks / max($s1 - $s0, 1) * 100, 1))")%" "$rss" "losses: $losses"
  # Each connection leaves a TIME_WAIT socket for 60 s and the ephemeral range is about 28000 ports: without a pause the
  # next step runs out of ports and measures the load generator, not the sensor.
  sleep "${PERF_PORT_PAUSE:-65}"
done
