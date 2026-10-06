#!/usr/bin/env bash
# Per-thread CPU time and wake-ups of an idle sensor (all providers on, product defaults).
#
# usage: sudo [MANAGER=1] [HEALTH=seconds] [SENSORD=build-rel/panopticon-sensord] tests/perf/idle_wakeups.sh [settle_s] [measure_s]
#
# Prints, per thread, the voluntary and involuntary context switches per second and the user and system CPU
# per second over the measurement window, then a syscall summary of the same sensor (perf trace -s).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SENSORD=${SENSORD:-$ROOT/build-rel/panopticon-sensord}
W=${PROFILE_DIR:-/var/tmp/idle-wakeups}
SETTLE=${1:-30}
MEASURE=${2:-60}
HZ=$(getconf CLK_TCK)
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
pkill -INT -f panopticon-sensord 2>/dev/null; sleep 1; pkill -9 -f panopticon-sensord 2>/dev/null
rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
cat >"$W/sensor.conf" <<CONF
sensor_id=idle-sensor
host_id=$(cat /etc/machine-id)
wal_path=$W/wal
health_interval_seconds=${HEALTH:-60}
CONF
MGR=
if [ -n "${MANAGER:-}" ]; then
  # deliver to the chaos fake Manager over TLS, the way the size profile does
  TOKEN=chaos-token-0123456789abcdef
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1     -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1 || exit 2
  printf 'idle-agent
%s
%s
' "$(cat /etc/machine-id)" "$TOKEN" >"$W/identity.json"; chmod 600 "$W/identity.json"
  printf 'manager_url=https://127.0.0.1:18555
identity_path=%s/identity.json
ca_bundle=%s/cert.pem
' "$W" "$W" >>"$W/sensor.conf"
  echo ok >"$W/mode"
  python3 "$ROOT/tests/chaos/fake_manager.py" --port 18555 --cert "$W/cert.pem" --key "$W/key.pem" --store "$W/store.ndjson"     --mode-file "$W/mode" --token "$TOKEN" >"$W/manager.log" 2>&1 &
  MGR=$!
  sleep 1
fi
"$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >"$W/sensord.log" 2>&1 &
PID=$!
sleep "$SETTLE"
snap() {
  for t in /proc/$PID/task/*; do
    tid=${t##*/}
    read -r _ _ _ _ _ _ _ _ _ _ _ _ _ ut st _ <"$t/stat" 2>/dev/null || continue
    vol=$(awk '/^voluntary_ctxt_switches/ {print $2}' "$t/status")
    inv=$(awk '/^nonvoluntary_ctxt_switches/ {print $2}' "$t/status")
    echo "$tid $(tr ' ' _ <"$t/comm") $ut $st $vol $inv"
  done
}
snap >"$W/a.txt"; T0=$(date +%s.%N)
sleep "$MEASURE"
snap >"$W/b.txt"; T1=$(date +%s.%N)
python3 - "$W/a.txt" "$W/b.txt" "$T0" "$T1" "$HZ" <<'PY'
import sys
a, b, t0, t1, hz = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
def load(p):
    d = {}
    for line in open(p):
        tid, comm, ut, st, vol, inv = line.split()
        d[tid] = (comm, int(ut), int(st), int(vol), int(inv))
    return d
A, B = load(a), load(b)
dt = t1 - t0
rows = []
for tid, (comm, ut, st, vol, inv) in B.items():
    c0 = A.get(tid, (comm, 0, 0, 0, 0))
    rows.append((tid, comm, (ut - c0[1]) / hz / dt * 100, (st - c0[2]) / hz / dt * 100, (vol - c0[3]) / dt, (inv - c0[4]) / dt))
rows.sort(key=lambda r: -(r[4] + r[5]))
print("window %.1f s" % dt)
print("%-8s %-18s %7s %7s %9s %9s" % ("tid", "comm", "user%", "sys%", "vol/s", "invol/s"))
for r in rows:
    print("%-8s %-18s %7.2f %7.2f %9.1f %9.1f" % r)
print("%-27s %7.2f %7.2f %9.1f %9.1f" % (("TOTAL",) + tuple(sum(r[i] for r in rows) for i in range(2, 6))))
PY
if command -v perf >/dev/null; then
  echo "--- syscalls over 20 s (perf trace -s)"
  timeout 25 perf trace -s -p "$PID" -o "$W/trace.txt" -- sleep 20 >/dev/null 2>&1
  [ -s "$W/trace.txt" ] && head -70 "$W/trace.txt"
fi
kill -INT $PID 2>/dev/null; wait $PID 2>/dev/null
[ -n "$MGR" ] && kill -9 $MGR 2>/dev/null
