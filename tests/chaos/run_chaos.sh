#!/usr/bin/env bash
# Real-kernel chaos scenarios for the sensor's WAL, uplink and recovery paths (test plan section 5).
#
# usage: sudo tests/chaos/run_chaos.sh [scenario ...]        (default: every scenario)
#   scenarios: baseline kill9 outage ackloss badack http503 rejected slowack diskfull clock walcorrupt ringoverflow memcap nofile walseg waldir
#   power loss needs a reboot, so it is two runs (see scenario_powerloss_crash)
#
# Needs root (eBPF process provider), python3, openssl and a built build/panopticon-sensord.
# Everything lives under $CHAOS_DIR (default /tmp/chaos). A fake Manager (tests/chaos/fake_manager.py)
# stands in for the real one so that faults can be injected; analyze.py checks what it stored.
# Providers other than the process provider are off so the only load is the load we generate.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/tests/chaos
SENSORD=${SENSORD:-$ROOT/build/panopticon-sensord}
CTL=${CTL:-$ROOT/build/panopticon-ctl}
W=${CHAOS_DIR:-/tmp/chaos}
PORT=${CHAOS_PORT:-18553}
TOKEN=chaos-token-0123456789abcdef
FAILED=0
RESULTS=()

say() { printf '[chaos] %s\n' "$*"; }
verdict() { # name status detail
  RESULTS+=("$2  $1  $3")
  [ "$2" = FAIL ] && FAILED=1
  say "$2 $1 $3"
}

setup() {
  # By process name, not command line: a wrapper such as `sudo env SENSORD=.../panopticon-sensord bash run_chaos.sh`
  # contains the daemon's name and `pkill -f` would kill the runner itself (comm is cut to 15 characters).
  pkill -INT -x panopticon-sens 2>/dev/null; sleep 1; pkill -9 -x panopticon-sens 2>/dev/null
  pkill -9 -f fake_manager.py 2>/dev/null
  umount "$W/small" 2>/dev/null
  rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
    -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1 || { say "openssl failed"; exit 2; }
  HOSTID=$(tr -d '\n-' </etc/machine-id)
  printf 'chaos-agent\n%s\n%s\n' "$HOSTID" "$TOKEN" >"$W/identity.json"; chmod 600 "$W/identity.json"
}

write_conf() { # extra lines on stdin
  {
    echo "sensor_id=chaos-sensor"
    echo "host_id=$HOSTID"
    echo "wal_path=${WAL:-$W/wal}"
    echo "manager_url=https://127.0.0.1:$PORT"
    echo "identity_path=$W/identity.json"
    echo "ca_bundle=$W/cert.pem"
    echo "health_interval_seconds=${HEALTH:-5}"
    echo "state_interval_seconds=3600"
    echo "enable_file_events=false"
    echo "enable_network_events=false"
    echo "enable_auth_events=false"
    echo "enable_kernel_events=false"
    echo "enable_security_events=false"
    echo "enable_sensitive_file_events=false"
    echo "enable_fim=false"
    echo "enable_hashing=false"
    cat
  } >"$W/sensor.conf"
}

reset_run() { # fresh store, WAL and mode
  stop_sensor; stop_manager
  rm -rf "$W/wal" "$W/wal.instance" "$W/store.ndjson" "$W/mode" "$W/sensord.log"
  echo ok >"$W/mode"
}

start_manager() {
  python3 "$HERE/fake_manager.py" --port "$PORT" --cert "$W/cert.pem" --key "$W/key.pem" --store "$W/store.ndjson" \
    --mode-file "$W/mode" --token "$TOKEN" >>"$W/manager.log" 2>&1 &
  MGR=$!
  for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && return 0; sleep 0.1; done
  say "manager did not start"; return 1
}
stop_manager() {
  if [ -n "${MGR:-}" ]; then kill -9 "$MGR" 2>/dev/null; wait "$MGR" 2>/dev/null; fi
  MGR=
}

start_sensor() {
  "$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >>"$W/sensord.log" 2>&1 &
  SENSOR=$!
  for _ in $(seq 1 100); do [ -S "$W/ctl.sock" ] && return 0; sleep 0.1; done
  say "sensor did not come up"; tail -5 "$W/sensord.log"; return 1
}
stop_sensor() { # graceful (never signal pid 0: that is the whole process group)
  if [ -n "${SENSOR:-}" ]; then
    kill -INT "$SENSOR" 2>/dev/null
    for _ in $(seq 1 100); do kill -0 "$SENSOR" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$SENSOR" 2>/dev/null; wait "$SENSOR" 2>/dev/null
  fi
  SENSOR=; rm -f "$W/ctl.sock"
}
kill_sensor() {
  if [ -n "${SENSOR:-}" ]; then kill -9 "$SENSOR" 2>/dev/null; wait "$SENSOR" 2>/dev/null; fi
  SENSOR=; rm -f "$W/ctl.sock"
}
alive() { [ -n "${SENSOR:-}" ] && kill -0 "$SENSOR" 2>/dev/null; }
# Peak and current resident memory of the sensor in MiB (VmHWM / VmRSS), "?" when it is gone.
rss_peak_mb() { awk '/^VmHWM:/ {printf "%d", $2 / 1024; f=1} END {if (!f) printf "?"}' "/proc/${SENSOR:-0}/status" 2>/dev/null; }

status() { "$CTL" --socket "$W/ctl.sock" status 2>/dev/null; }
# field of the status reply, e.g. status_field wal.durable_seq
status_field() {
  status | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
d = d.get("result", d) if isinstance(d, dict) else d
for part in sys.argv[1].split("."):
    d = d.get(part) if isinstance(d, dict) else None
print("" if d is None else d)' "$1"
}

# Waits until everything durable has been acknowledged (health records keep arriving, so allow a few).
wait_drained() { # timeout seconds
  local limit=${1:-60} d a
  for _ in $(seq 1 "$limit"); do
    d=$(status_field wal.durable_seq); a=$(status_field wal.acknowledged_seq)
    if [ -n "$d" ] && [ -n "$a" ] && [ $((d - a)) -le 8 ]; then return 0; fi
    sleep 1
  done
  say "not drained: durable=${d:-?} acknowledged=${a:-?}"; return 1
}

# Spawns short-lived processes for N seconds (each is a fork, exec and exit for the process provider).
load() {
  local seconds=$1 pause=${2:-0}
  (
    end=$((SECONDS + seconds))
    while [ $SECONDS -lt $end ]; do /bin/true; /bin/true; /bin/true; [ "$pause" != 0 ] && sleep "$pause"; done
  ) &
  LOADPID=$!
}
wait_load() { [ -n "${LOADPID:-}" ] && wait "$LOADPID" 2>/dev/null; }

# Waits until the store holds `count` exec events of the process called `name` (the pipeline can trail the WAL
# acknowledgements by seconds after a burst, so "drained" alone does not mean everything was processed).
wait_exec_seen() { # name count timeout
  local seen=0 i
  for i in $(seq 1 "${3:-60}"); do
    seen=$(analyze --count-exec "$1" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_named"]["'"$1"'"])' 2>/dev/null)
    [ "${seen:-0}" -ge "$2" ] && return 0
    sleep 1
  done
  return 1
}

analyze() { python3 "$HERE/analyze.py" "$W/store.ndjson" --json "$@"; }
jfield() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[sys.argv[1]])' "$1"; }

# ---------------------------------------------------------------- scenarios

scenario_baseline() {
  reset_run; write_conf </dev/null; start_manager && start_sensor || return
  load 15 0.01; wait_load; wait_drained 30
  local out; out=$(analyze); local rc=$?
  stop_sensor
  verdict baseline "$([ $rc = 0 ] && [ "$(echo "$out" | jfield stored)" -gt 100 ] && echo PASS || echo FAIL)" \
    "stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing)"
}

scenario_kill9() {
  reset_run; write_conf </dev/null; start_manager && start_sensor || return
  load 70 0.005
  local kills=0
  for _ in $(seq 1 14); do
    sleep $((2 + RANDOM % 4)); kill_sensor; kills=$((kills + 1)); sleep 0.3; start_sensor || break
  done
  wait_load; wait_drained 60
  local out; out=$(analyze); local rc=$?
  # Every kill -9 must be reported by the next start as exactly one sensor_gap; a clean stop and restart adds none.
  local gaps; gaps=$(echo "$out" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["other_loss_reported"].get("sensor_gap", 0))')
  stop_sensor; start_sensor || return; sleep 3; wait_drained 30
  local after; after=$(analyze | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["other_loss_reported"].get("sensor_gap", 0))')
  stop_sensor
  say "kill9 detail: $(echo "$out" | jfield loss_records)"
  verdict kill9 "$([ $rc = 0 ] && [ "$gaps" = "$kills" ] && [ "$after" = "$kills" ] && echo PASS || echo FAIL)" \
    "kills=$kills sensor_gap=$gaps after_clean_restart=$after stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) wal_loss_reported=$(echo "$out" | jfield wal_loss_reported) conflicts=$(echo "$out" | jfield conflicts)"
}

scenario_outage() {
  # Short outage under the quota: nothing may be lost. Long outage over a small quota: the gap
  # must equal what the loss records report.
  reset_run; write_conf <<EOF
wal_quota_bytes=16777216
wal_segment_bytes=262144
EOF
  start_manager && start_sensor || return
  load 10 0.02; wait_load; wait_drained 30
  local before; before=$(analyze | jfield stored)
  stop_manager
  load 6 0.05; wait_load; sleep 2
  start_manager; wait_drained 60
  local out; out=$(analyze); local rc=$?
  verdict outage-short "$([ $rc = 0 ] && [ "$(echo "$out" | jfield missing)" = 0 ] && [ "$(echo "$out" | jfield stored)" -gt "$before" ] && echo PASS || echo FAIL)" \
    "before=$before stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing)"
  stop_manager
  sed -i 's/^wal_quota_bytes=.*/wal_quota_bytes=2097152/' "$W/sensor.conf"
  stop_sensor; start_sensor || return           # a smaller quota takes a restart
  load 25 0; wait_load; sleep 2
  start_manager; wait_drained 90
  out=$(analyze); rc=$?
  say "outage-long losses: $(echo "$out" | jfield loss_records) ranges=$(echo "$out" | jfield missing_ranges)"
  stop_sensor
  verdict outage-long "$([ $rc = 0 ] && [ "$(echo "$out" | jfield wal_loss_reported)" -gt 0 ] && echo PASS || echo FAIL)" \
    "stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) wal_loss_reported=$(echo "$out" | jfield wal_loss_reported)"
}

ackloss_case() { # name mode [gap_ok]: a gap is acceptable only when it is accounted (the analyzer fails a silent one)
  reset_run; write_conf </dev/null; start_manager && start_sensor || return
  load 6 0.02; wait_load; wait_drained 30
  echo "$2" >"$W/mode"
  load 10 0.02; wait_load; sleep 12
  echo ok >"$W/mode"
  wait_drained 60
  local out; out=$(analyze); local rc=$?
  local retries; retries=$(status_field delivery.retries); local refusals; refusals=$(status_field delivery.refusals)
  local quarantined; quarantined=$(status_field delivery.records_quarantined)
  stop_sensor
  local gap_ok=${3:-no} verdict_now=FAIL
  if [ $rc = 0 ] && { [ "$gap_ok" = yes ] || [ "$(echo "$out" | jfield missing)" = 0 ]; }; then verdict_now=PASS; fi
  verdict "$1" "$verdict_now" \
    "stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) accounted=$(echo "$out" | jfield accounted) conflicts=$(echo "$out" | jfield conflicts) retries=$retries refusals=$refusals quarantined=$quarantined"
}
scenario_ackloss() { ackloss_case ackloss "drop_ack 6"; }
scenario_badack() { ackloss_case badack "bad_ack"; }
scenario_http503() { ackloss_case http503 "http503"; }
scenario_rejected() { ackloss_case rejected "reject 3" yes; }
scenario_slowack() { ackloss_case slowack "slow 3"; }

scenario_diskfull() {
  reset_run
  mkdir -p "$W/small"; mount -t tmpfs -o size=2m tmpfs "$W/small"
  WAL=$W/small/wal write_conf <<EOF
wal_quota_bytes=67108864
wal_segment_bytes=262144
EOF
  start_manager && start_sensor || { umount "$W/small"; return; }
  echo http503 >"$W/mode"            # nothing is acknowledged, so nothing is freed
  load 20 0; wait_load; sleep 3
  local alive=no; alive && alive=yes
  local errors; errors=$(status_field totals.sink_errors); local health; health=$(status_field status)
  say "diskfull while full: alive=$alive sink_errors=$errors status=$health free=$(df -k "$W/small" | tail -1 | awk '{print $4}')k"
  mount -o remount,size=64m "$W/small"; echo ok >"$W/mode"
  load 6 0.02; wait_load; wait_drained 60
  local out; out=$(analyze); local rc=$?
  local errors_after; errors_after=$(status_field totals.sink_errors)
  local accounted; accounted=$(echo "$out" | jfield other_loss_reported)
  stop_sensor; umount "$W/small"
  local ok=FAIL
  [ "$alive" = yes ] && [ "${errors:-0}" -gt 0 ] && [ $rc = 0 ] && [ "$(echo "$out" | jfield write_failed_reported)" -gt 0 ] && ok=PASS
  verdict diskfull "$ok" "alive=$alive sink_errors=$errors->$errors_after stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) write_failed_reported=$(echo "$out" | jfield write_failed_reported)"
}

scenario_clock() {
  reset_run; write_conf </dev/null; start_manager && start_sensor || return
  command -v timedatectl >/dev/null && timedatectl set-ntp false 2>/dev/null
  local base; base=$(date +%s)
  load 30 0.02
  sleep 5; date -s "@$((base + 172800))" >/dev/null     # two days forward
  sleep 8; date -s "@$((base - 86400 + 14))" >/dev/null  # then a day behind the start
  sleep 8; date -s "@$((base + 28))" >/dev/null          # then back to the right time
  wait_load; wait_drained 60
  local alive=no; alive && alive=yes
  command -v timedatectl >/dev/null && timedatectl set-ntp true 2>/dev/null
  local out; out=$(analyze); local rc=$?
  stop_sensor
  # Events already queued when the clock steps are converted with the new offset: 25 to 80 per run at this load (the count varies with what is in flight at each step),
  # so the limit is 50 per logged step. Event time far from observed time beyond that means the sensor did not re-base its clock (579 before step detection existed).
  local steps; steps=$(grep -c "wall clock stepped" "$W/sensord.log"); [ "$steps" -ge 1 ] || steps=1
  verdict clock "$([ $alive = yes ] && [ $rc = 0 ] && [ "$(echo "$out" | jfield skewed_events)" -le $((50 * steps)) ] && echo PASS || echo FAIL)" \
    "alive=$alive stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) skewed_events=$(echo "$out" | jfield skewed_events) (limit $((50 * steps))) clock_steps_logged=$steps"
}

scenario_walcorrupt() {
  reset_run; write_conf </dev/null; start_manager && start_sensor || return
  echo http503 >"$W/mode"
  load 12 0.01; wait_load; sleep 1
  kill_sensor
  local file; file=$(ls -S "$W"/wal/wal-*.log | head -1)
  local size; size=$(stat -c %s "$file")
  say "walcorrupt: overwriting 64 bytes in the middle of $(basename "$file") ($size bytes)"
  dd if=/dev/urandom of="$file" bs=1 count=64 seek=$((size / 2)) conv=notrunc 2>/dev/null
  echo ok >"$W/mode"
  start_sensor || return
  wait_drained 60
  local alive=no; alive && alive=yes
  local out; out=$(analyze); local rc=$?
  stop_sensor
  say "walcorrupt losses: $(echo "$out" | jfield loss_records)"
  verdict walcorrupt "$([ $alive = yes ] && [ $rc = 0 ] && echo PASS || echo FAIL)" \
    "stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) wal_loss_reported=$(echo "$out" | jfield wal_loss_reported) conflicts=$(echo "$out" | jfield conflicts)"
}

# The kernel ring buffer overflows: the sensor is stopped (SIGSTOP) while 6000 processes run, so the
# 4 MiB buffer fills and the BPF program drops. The sensor must survive, report the overflow as a
# `kernel` loss, deliver at least part of the storm plus everything that happens after SIGCONT, and
# the events it saw plus the losses it reported must cover what was generated.
scenario_ringoverflow() {
  reset_run; write_conf </dev/null; start_manager && start_sensor || return
  cp /bin/true "$W/chaosstorm"; cp /bin/true "$W/chaospost"
  load 3 0.02; wait_load; wait_drained 30
  kill -STOP "$SENSOR"
  local storm=6000 i
  for i in $(seq 1 $storm); do "$W/chaosstorm"; done
  kill -CONT "$SENSOR"
  sleep 8
  for i in $(seq 1 50); do "$W/chaospost"; done
  # The sensor may still be working through the backlog the storm left in the ring: the post-storm execs are queued
  # behind it, late but not lost, and the uplink looks drained until they arrive. Judge them after they could.
  local waited_from=$SECONDS
  wait_exec_seen chaospost 50 90
  say "ringoverflow: post-storm execs waited for $((SECONDS - waited_from)) s after they were run"
  wait_drained 90
  local alive=no; alive && alive=yes
  local out; out=$(analyze --count-exec chaosstorm,chaospost); local rc=$?
  local rss; rss=$(rss_peak_mb)
  stop_sensor
  local seen post lost
  seen=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_named"]["chaosstorm"])')
  post=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_named"]["chaospost"])')
  lost=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["other_loss_reported"].get("kernel", 0))')
  say "ringoverflow losses: $(echo "$out" | jfield loss_records)"
  local ok=FAIL
  [ "$alive" = yes ] && [ $rc = 0 ] && [ "$lost" -gt 0 ] && [ "$seen" -gt 0 ] && [ "$seen" -lt "$storm" ] \
    && [ $((seen + lost)) -ge "$storm" ] && [ "$post" = 50 ] && ok=PASS
  verdict ringoverflow "$ok" "generated=$storm seen=$seen kernel_loss_reported=$lost post_storm_seen=$post/50 peak_rss=${rss}MiB stored=$(echo "$out" | jfield stored)"
}

# Memory pressure: the sensor lives in a cgroup whose limit is only a little above its working set
# while it takes an exec storm and the Manager is down (so the WAL grows). It must not be OOM-killed,
# its memory must stay bounded, and nothing may go missing without a loss record.
scenario_memcap() {
  local cg=/sys/fs/cgroup/chaos-mem limit=$((48 * 1024 * 1024))
  [ -f /sys/fs/cgroup/cgroup.controllers ] || { verdict memcap SKIP "no cgroup v2"; return; }
  rmdir "$cg" 2>/dev/null
  mkdir "$cg" 2>/dev/null || { verdict memcap SKIP "cannot create $cg"; return; }
  echo "+memory" >/sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
  reset_run; write_conf </dev/null; start_manager && start_sensor || { rmdir "$cg"; return; }
  echo "$limit" >"$cg/memory.max"; echo 0 >"$cg/memory.swap.max" 2>/dev/null
  echo "$SENSOR" >"$cg/cgroup.procs"
  cp /bin/true "$W/chaosstorm"
  echo http503 >"$W/mode"                       # nothing is acknowledged: the backlog builds up
  load 20 0
  local i; for i in $(seq 1 3000); do "$W/chaosstorm"; done
  wait_load
  echo ok >"$W/mode"
  wait_drained 120
  local alive=no; alive && alive=yes
  local oom; oom=$(awk '/^oom_kill / {print $2}' "$cg/memory.events")
  local current; current=$(( $(cat "$cg/memory.current") / 1048576 ))
  local rss; rss=$(rss_peak_mb)
  local out; out=$(analyze --count-exec chaosstorm); local rc=$?
  stop_sensor; rmdir "$cg" 2>/dev/null
  verdict memcap "$([ "$alive" = yes ] && [ "${oom:-1}" = 0 ] && [ $rc = 0 ] && echo PASS || echo FAIL)" \
    "limit=48MiB alive=$alive oom_kill=${oom:-?} peak_rss=${rss}MiB cgroup_current=${current}MiB stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) accounted=$(echo "$out" | jfield accounted)"
}

# Descriptor exhaustion: the soft and hard RLIMIT_NOFILE of a running sensor are cut to a few above
# what it holds at rest, with file events and hashing on so each event wants more descriptors. It must
# stay up, keep delivering, and pick up again when the limit is raised.
scenario_nofile() {
  reset_run; write_conf </dev/null
  sed -i 's/^enable_file_events=.*/enable_file_events=true/; s/^enable_hashing=.*/enable_hashing=true/' "$W/sensor.conf"   # duplicate keys are refused
  start_manager && start_sensor || return
  sleep 3
  local held; held=$(ls "/proc/$SENSOR/fd" | wc -l)
  local limit=$held                               # nothing new can be opened: no socket, no /proc file, no hashed file
  prlimit --pid "$SENSOR" --nofile="$limit:$limit" || { verdict nofile SKIP "prlimit unavailable"; return; }
  cp /bin/true "$W/chaosstorm"; cp /bin/true "$W/chaospost"
  load 15 0
  local i; for i in $(seq 1 1500); do "$W/chaosstorm"; echo x >"$W/scratch-$((i % 50))"; done
  wait_load
  local alive=no; alive && alive=yes
  say "nofile: held=$held limit=$limit alive=$alive status=$(status_field status) sink_errors=$(status_field totals.sink_errors)"
  prlimit --pid "$SENSOR" --nofile=65536:65536
  sleep 6
  for i in $(seq 1 30); do "$W/chaospost"; done
  wait_exec_seen chaospost 30 90
  wait_drained 90
  local out; out=$(analyze --count-exec chaosstorm,chaospost); local rc=$?
  local post; post=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_named"]["chaospost"])')
  alive=no; alive && alive=yes
  stop_sensor
  verdict nofile "$([ "$alive" = yes ] && [ $rc = 0 ] && [ "$post" = 30 ] && echo PASS || echo FAIL)" \
    "held=$held limit=$limit alive=$alive recovered_post_seen=$post/30 stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) accounted=$(echo "$out" | jfield accounted)"
}

# Someone removes the sensor's spool while it runs. `walseg`: the oldest sealed segments of an
# undelivered backlog are deleted. `waldir`: the whole directory, active segment included, is removed
# while records keep arriving. The sensor must stay up, report what the removal cost as a `wal` loss,
# keep the records written after it, and deliver everything that still exists (no wedged uplink).
walremove_case() { # name what
  reset_run; write_conf <<EOF2
wal_quota_bytes=134217728
wal_segment_bytes=262144
EOF2
  start_manager && start_sensor || return
  echo http503 >"$W/mode"                       # nothing is acknowledged: segments pile up
  load 12 0; wait_load; sleep 2
  local segs; segs=$(ls "$W"/wal/wal-*.log | wc -l)
  # The quota is far above what the run writes, so nothing is dropped by it and every missing record is the removal's.
  case "$2" in
    seg) ls "$W"/wal/wal-*.log | sed -n 5,6p | xargs rm -f ;;      # two sealed segments in the middle of the backlog
    dir) rm -rf "$W/wal" ;;
  esac
  say "$1: removed $2 ($segs segments before)"
  cp /bin/true "$W/chaospost"
  load 6 0.01; wait_load
  echo ok >"$W/mode"
  sleep 3
  for i in $(seq 1 40); do "$W/chaospost"; done
  wait_exec_seen chaospost 40 90
  wait_drained 90
  local alive=no; alive && alive=yes
  local out; out=$(analyze --count-exec chaospost); local rc=$?
  local post; post=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_named"]["chaospost"])')
  stop_sensor
  say "$1 losses: $(echo "$out" | jfield loss_records)"
  local removed=no; echo "$out" | grep -q "removed:" && removed=yes     # a loss that says the removal, not the quota, cost them
  local quota=no; echo "$out" | grep -q "quota:" && quota=yes
  verdict "$1" "$([ "$alive" = yes ] && [ $rc = 0 ] && [ "$post" = 40 ] && [ "$removed" = yes ] && [ "$quota" = no ] && echo PASS || echo FAIL)" \
    "alive=$alive post_removal_seen=$post/40 removal_reported=$removed quota_dropped=$quota stored=$(echo "$out" | jfield stored) missing=$(echo "$out" | jfield missing) wal_loss_reported=$(echo "$out" | jfield wal_loss_reported) problems=$(echo "$out" | jfield problems)"
}
scenario_walseg() { walremove_case walseg seg; }
scenario_waldir() { walremove_case waldir dir; }

# Power loss, phase 1. Crashes the machine with sysrq-b (no sync, no unmount: the page cache is lost) while the
# sensor is writing under load and the Manager is refusing, so nothing is acknowledged. The lines "DURABLE n" go
# to stdout (read them from outside the machine: files here would be subject to the same loss); n is a seq the
# sensor had already reported durable, so it must survive the reboot.
#   sudo CHAOS_DIR=/var/tmp/chaos-pl tests/chaos/run_chaos.sh powerloss_crash
scenario_powerloss_crash() {
  reset_run; write_conf </dev/null
  sync  # the harness own files (cert, identity, config) must survive; only the sensor WAL is under test
  start_manager && start_sensor || return
  echo http503 >"$W/mode"
  echo 1 >/proc/sys/kernel/sysrq
  local run=${CRASH_AFTER:-12}
  load $((run + 10)) 0
  local end=$((SECONDS + run))
  while [ $SECONDS -lt $end ]; do echo "DURABLE $(status_field wal.durable_seq)"; sleep 0.2; done
  echo "DIRTY_KB $(awk '/^Dirty:/ {print $2}' /proc/meminfo)"
  echo "CRASHING"
  echo b >/proc/sysrq-trigger
  sleep 60
}

# Power loss, phase 2, after the reboot: the sensor restarts on the surviving WAL, the Manager accepts, and
# everything up to REQUIRE_SEQ (the last DURABLE value seen from outside) must arrive.
#   sudo CHAOS_DIR=/var/tmp/chaos-pl REQUIRE_SEQ=n tests/chaos/run_chaos.sh powerloss_verify
scenario_powerloss_verify() {
  [ -n "${REQUIRE_SEQ:-}" ] || { say "REQUIRE_SEQ not set"; return; }
  HOSTID=$(cat /etc/machine-id)
  rm -f "$W/ctl.sock" "$W/store.ndjson"; echo ok >"$W/mode"
  say "wal after the crash: $(ls "$W"/wal | tr '\n' ' ')"
  write_conf </dev/null; start_manager && start_sensor || return
  wait_drained 90
  local alive=no; alive && alive=yes
  local out; out=$(analyze --require-through "$REQUIRE_SEQ"); local rc=$?
  stop_sensor
  say "powerloss losses: $(echo "$out" | jfield loss_records)"
  verdict powerloss "$([ $alive = yes ] && [ $rc = 0 ] && echo PASS || echo FAIL)" \
    "required_through=$REQUIRE_SEQ required_absent=$(echo "$out" | jfield required_absent) stored=$(echo "$out" | jfield stored) last_seq=$(echo "$out" | jfield last_seq) missing=$(echo "$out" | jfield missing) wal_loss_reported=$(echo "$out" | jfield wal_loss_reported) conflicts=$(echo "$out" | jfield conflicts)"
}

# ---------------------------------------------------------------- main

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$SENSORD" ] || { echo "build first: $SENSORD" >&2; exit 2; }
SCENARIOS=("$@")
case " ${SCENARIOS[*]:-} " in *" powerloss_verify "*) ;; *) setup ;; esac
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(baseline kill9 outage ackloss badack http503 rejected slowack diskfull clock walcorrupt ringoverflow memcap nofile walseg waldir)
for name in "${SCENARIOS[@]}"; do
  say "=== $name"
  "scenario_$name"
done
stop_sensor; stop_manager
echo; echo "chaos summary"; printf '  %s\n' "${RESULTS[@]}"
exit $FAILED
