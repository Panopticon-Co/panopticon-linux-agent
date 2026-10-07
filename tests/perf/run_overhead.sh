#!/usr/bin/env bash
# Sensor overhead on the paths it hooks (docs/endpoint/LINUX_ENDPOINT_PERFORMANCE.md budgets):
# the same workload (tests/perf/overhead_load.py) with no sensor and with the sensor running its
# default providers against a WAL (no Manager, so the records are spooled), interleaved so slow drift
# of the VM does not look like overhead.
#
# usage: sudo tests/perf/run_overhead.sh [pairs]        (default 3 baseline/sensor pairs)
# Needs root and a built build/panopticon-sensord (SENSORD / CTL override the paths).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/tests/perf
SENSORD=${SENSORD:-$ROOT/build/panopticon-sensord}
CTL=${CTL:-$ROOT/build/panopticon-ctl}
W=${PERF_DIR:-/var/tmp/perf-overhead}
PAIRS=${1:-3}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$SENSORD" ] || { echo "build first: $SENSORD" >&2; exit 2; }
pkill -INT -f panopticon-sensord 2>/dev/null; sleep 1
rm -rf "$W"; mkdir -p "$W"
printf 'sensor_id=perf-sensor\nhost_id=%s\nwal_path=%s/wal\n' "$(tr -d '\n-' </etc/machine-id)" "$W" >"$W/sensor.conf"

clock_ticks=$(getconf CLK_TCK)
cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }   # utime + stime
field() { python3 -c 'import json,sys
d=json.load(sys.stdin); d=d.get("result",d)
for p in sys.argv[1].split("."): d=d.get(p) if isinstance(d,dict) else None
print("" if d is None else d)' "$1"; }

# Pinned to one CPU: unpinned, the client and server threads of the TCP loop land on different vCPUs from run to
# run and a loopback connection varies by 2x with no sensor at all. The sensor is not pinned.
PIN=(); command -v taskset >/dev/null && [ "${PERF_PIN-1}" != "" ] && PIN=(taskset -c "${PERF_PIN-1}")   # PERF_PIN= (empty) disables
run_load() { "${PIN[@]}" python3 "$HERE/overhead_load.py" --dir "$W" "$@"; }

echo "# sensor off / on, $PAIRS pairs; microseconds per operation (median of 5 rounds)"
off_rows=(); on_rows=()
for i in $(seq 1 "$PAIRS"); do
  off=$(run_load); off_rows+=("$off"); echo "off $i: $off"
  rm -rf "$W/wal" "$W/ctl.sock"
  "$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >"$W/sensord.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do [ -S "$W/ctl.sock" ] && break; sleep 0.1; done
  sleep 3                                   # past the startup scan
  t0=$(cpu_ticks "$pid"); s0=$SECONDS
  on=$(run_load); on_rows+=("$on")
  t1=$(cpu_ticks "$pid"); s1=$SECONDS
  records=$("$CTL" --socket "$W/ctl.sock" status 2>/dev/null | field totals.records)
  losses=$("$CTL" --socket "$W/ctl.sock" status 2>/dev/null | field totals.loss_records)
  rss=$(awk '/^VmHWM:/ {printf "%d", $2 / 1024}' "/proc/$pid/status")
  echo "on  $i: $on  sensor_cpu=$(python3 -c "print(round(($t1 - $t0) / $clock_ticks / max($s1 - $s0, 1) * 100, 1))")% of one core over the workload, records=$records loss_records=$losses peak_rss=${rss}MiB"
  kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  # What was lost, if anything: the loss records sit in the WAL as plain JSON.
  grep -a -o '"loss":{[^}]*}[^}]*}' "$W"/wal/wal-*.log 2>/dev/null | sed 's/^/    loss: /'
done

python3 - "${off_rows[@]}" -- "${on_rows[@]}" <<'EOF'
import json, statistics, sys
split = sys.argv.index("--")
off = [json.loads(r) for r in sys.argv[1:split]]
on = [json.loads(r) for r in sys.argv[split + 1:]]
print("# median over the pairs")
for key, label in (("exec_us", "exec (spawn+wait)"), ("tcp_us", "tcp loopback connection"), ("file_us", "open+close")):
    a = statistics.median(r[key] for r in off)
    b = statistics.median(r[key] for r in on)
    print("%-26s off %9.2f us   on %9.2f us   overhead %+6.1f %%" % (label, a, b, (b - a) / a * 100))
EOF
