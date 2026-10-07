#!/usr/bin/env bash
# Records what the sensor emits under a realistic mixed workload, with every provider on (the product
# defaults), and reports record sizes, rates and compression (tests/perf/size_profile.py).
#
# usage: sudo [PERF=1] [SENSORD=build-rel/panopticon-sensord] tests/perf/run_size_profile.sh [idle_seconds] [work_seconds]
#
# Phases: startup (state snapshots), idle, then a mixed workload run as an unprivileged user: compile and
# script churn, file changes in watched places, loopback HTTP, DNS lookups, sudo and su (success and failure),
# a kernel module load. Use a Release build for CPU numbers; sizes do not depend on the build type.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CHAOS=$ROOT/tests/chaos
SENSORD=${SENSORD:-$ROOT/build-rel/panopticon-sensord}
CTL=${CTL:-$ROOT/build-rel/panopticon-ctl}
W=${PROFILE_DIR:-/var/tmp/size-profile}
PORT=18554
TOKEN=chaos-token-0123456789abcdef
IDLE=${1:-60}
WORK=${2:-120}
USER_NAME=${WORK_USER:-vagrant}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$SENSORD" ] || { echo "build first: $SENSORD" >&2; exit 2; }

pkill -INT -f panopticon-sensord 2>/dev/null; sleep 1; pkill -9 -f panopticon-sensord 2>/dev/null
pkill -9 -f fake_manager.py 2>/dev/null
rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
  -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1 || exit 2
HOSTID=$(cat /etc/machine-id)
printf 'size-agent\n%s\n%s\n' "$HOSTID" "$TOKEN" >"$W/identity.json"; chmod 600 "$W/identity.json"
cat >"$W/sensor.conf" <<CONF
sensor_id=size-sensor
host_id=$HOSTID
wal_path=$W/wal
manager_url=https://127.0.0.1:$PORT
identity_path=$W/identity.json
ca_bundle=$W/cert.pem
health_interval_seconds=10
CONF
echo ok >"$W/mode"
python3 "$CHAOS/fake_manager.py" --port $PORT --cert "$W/cert.pem" --key "$W/key.pem" --store "$W/store.ndjson" \
  --mode-file "$W/mode" --token "$TOKEN" --wire-log "$W/wire.ndjson" >"$W/manager.log" 2>&1 &
MGR=$!
sleep 1

# workload files
mkdir -p "$W/work"; chown "$USER_NAME" "$W/work"
cat >"$W/work/hello.c" <<'C'
#include <stdio.h>
int main(void) { puts("hello"); return 0; }
C
cat >"$W/work/workload.sh" <<'SH'
#!/bin/bash
# one pass of mixed activity; every command is a real process the sensor sees
cd "$1"
gcc -O0 -o hello hello.c && ./hello >/dev/null
python3 -c "import json, os; print(len(json.dumps(dict(os.environ))))" >/dev/null
ls -la /usr/bin | wc -l >/dev/null
find /usr/share/doc -maxdepth 2 -name copyright 2>/dev/null | head -20 | xargs -r ls -l >/dev/null
grep -r "root" /etc/passwd /etc/group >/dev/null
tar -cf data.tar hello.c hello && gzip -f data.tar && rm -f data.tar.gz
echo data >f1.txt; cp f1.txt f2.txt; mv f2.txt f3.txt; chmod 600 f3.txt; rm -f f1.txt f3.txt
curl -s -o /dev/null http://127.0.0.1:18099/ || true
getent hosts localhost >/dev/null; getent hosts example.com >/dev/null 2>&1 || true
nc -z -w1 127.0.0.1 18554 || true
sudo -n true
echo wrong | su -c true nobody 2>/dev/null || true
cat /etc/hostname >/dev/null
SH
chmod +x "$W/work/workload.sh"
(cd "$W/work" && runuser -u "$USER_NAME" -- python3 -m http.server 18099 --bind 127.0.0.1 >/dev/null 2>&1 &) 
sleep 1

"$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >"$W/sensord.log" 2>&1 &
SENSOR=$!
for _ in $(seq 1 100); do [ -S "$W/ctl.sock" ] && break; sleep 0.1; done
if [ -n "${PERF:-}" ]; then perf record -F 499 -p $SENSOR -o "$W/perf.data" >"$W/perf.log" 2>&1 & PERFPID=$!; fi
T0=$(date +%s.%N)
echo "[profile] startup settle 20 s"; sleep 20
T_IDLE=$(date +%s.%N)
echo "[profile] idle $IDLE s"; sleep "$IDLE"
T_WORK=$(date +%s.%N)
echo "[profile] workload $WORK s"
(
  end=$((SECONDS + WORK))
  while [ $SECONDS -lt $end ]; do runuser -u "$USER_NAME" -- "$W/work/workload.sh" "$W/work" >/dev/null 2>&1; done
) &
LOADER=$!
sleep $((WORK / 2))
# one kernel module load/unload and a file change in a watched path, mid-run
modprobe dummy 2>/dev/null; sleep 1; rmmod dummy 2>/dev/null
echo "# size profile" >>/etc/hosts.size-profile; rm -f /etc/hosts.size-profile
wait $LOADER
T_END=$(date +%s.%N)
[ -n "${PERFPID:-}" ] && { kill -INT $PERFPID; wait $PERFPID 2>/dev/null; }
sleep 8
"$CTL" --socket "$W/ctl.sock" status >"$W/status.json" 2>/dev/null
kill -INT $SENSOR 2>/dev/null; for _ in $(seq 1 100); do kill -0 $SENSOR 2>/dev/null || break; sleep 0.1; done; kill -9 $SENSOR 2>/dev/null
pkill -f "http.server 18099" 2>/dev/null
kill -9 $MGR 2>/dev/null
echo "$T0 $T_IDLE $T_WORK $T_END" >"$W/times"
echo "[profile] wal dir: $(du -sb "$W/wal" | cut -f1) bytes, $(ls "$W/wal" | wc -l) files"
python3 - "$W/status.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1])).get("result", {})
    print("[profile] sensor:", json.dumps({k: d.get(k) for k in ("resources", "totals", "wal")}))
except Exception as error:
    print("[profile] no status:", error)
PY
echo "[profile] store: $W/store.ndjson wire: $W/wire.ndjson times: $(cat "$W/times")"
