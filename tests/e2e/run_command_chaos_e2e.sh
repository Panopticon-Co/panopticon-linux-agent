#!/usr/bin/env bash
# Real-kernel chaos test of the command channel (ADR 024/025) against a fake Manager, as root.
#
# usage: sudo [SENSORD=build-rel/panopticon-sensord] [SIGNER=build-rel/panopticon-command-signer] tests/e2e/run_command_chaos_e2e.sh
#
# Scenarios: a burst of commands (one result each, none lost, none duplicated, more than one poll's worth); the
# changing-action rate limit; the same command id twice in one batch; hostile but parseable command content (a
# 2 MB field, 20000-deep nesting, absurd numbers, non-object entries, over-long and control-character ids, more
# than a poll's maximum) with a signed canary after each; a Manager outage while a command is waiting; the replay
# ledger on a filesystem that fills up while the sensor runs, then recovers; a corrupt ledger tail; a deleted
# ledger; the sensor killed with SIGKILL in the middle of a burst.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SENSORD=${SENSORD:-$ROOT/build-rel/panopticon-sensord}
SIGNER=${SIGNER:-$ROOT/build-rel/panopticon-command-signer}
W=${CHAOS_DIR:-/var/tmp/cmdchaos}
PORT=${CHAOS_PORT:-18558}
TOKEN=chaos-token-0123456789abcdef
AGENT=chaos-agent
RATE=60
LEDGER=
FAILED=0
PASSED=0
SENSOR=
MGR=

say() { printf '[cmdchaos] %s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then PASSED=$((PASSED + 1)); say "PASS $1 ($3)"; else FAILED=$((FAILED + 1)); say "FAIL $1: expected '$2', got '$3'"; fi
}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$SENSORD" ] && [ -x "$SIGNER" ] || { echo "build panopticon-sensord and panopticon-command-signer first" >&2; exit 2; }

cleanup() {
  [ -n "$SENSOR" ] && kill -INT "$SENSOR" 2>/dev/null
  [ -n "$MGR" ] && kill -9 "$MGR" 2>/dev/null
  [ -f "$W/victim.pids" ] && xargs -r kill -9 <"$W/victim.pids" 2>/dev/null
  return 0
}
trap cleanup EXIT

pkill -INT -f panopticon-sensord 2>/dev/null; sleep 1; pkill -9 -f panopticon-sensord 2>/dev/null
pkill -9 -f fake_command_manager.py 2>/dev/null
rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
HOSTID=$(tr -d '\n-' </etc/machine-id)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
  -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1 || { say "openssl failed"; exit 2; }
printf '%s\n%s\n%s\n' "$AGENT" "$HOSTID" "$TOKEN" >"$W/identity.json"; chmod 600 "$W/identity.json"
KEYLINE=$("$SIGNER" keygen "$W/signing.key") || exit 2
"$SIGNER" keygen "$W/foreign.key" >/dev/null || exit 2
SPARELINE=$("$SIGNER" keygen "$W/spare.key") || exit 2
KEY=${KEYLINE% *}
SPARE=${SPARELINE% *}
echo "$KEY e2e-signing-key" >"$W/keyring"
echo ok >"$W/mode"; : >"$W/commands.ndjson"; : >"$W/events.ndjson"; echo no >"$W/redeliver"

write_conf() { # keys | unsigned [enforce | dry_run]
  {
    echo "sensor_id=chaos-sensor"
    echo "host_id=$HOSTID"
    echo "wal_path=$W/wal"
    echo "manager_url=https://127.0.0.1:$PORT"
    echo "identity_path=$W/identity.json"
    echo "ca_bundle=$W/cert.pem"
    echo "health_interval_seconds=30"
    echo "enable_file_events=false"
    echo "enable_network_events=false"
    echo "enable_auth_events=false"
    echo "enable_kernel_events=false"
    echo "enable_security_events=false"
    echo "enable_sensitive_file_events=false"
    echo "enable_fim=false"
    echo "enable_hashing=false"
    echo "response_mode=${2:-enforce}"
    echo "response_actions=KILL_PROCESS,COLLECT_PROCESS_INFO"
    echo "response_poll_seconds=1"
    echo "response_max_changes_per_minute=$RATE"
    [ -n "$LEDGER" ] && echo "response_ledger_path=$LEDGER"
    if [ "$1" = keys ]; then echo "response_signing_keys=$W/keyring"; else echo "response_allow_unsigned=true"; fi
  } >"$W/sensor.conf"
}

start_manager() {
  python3 "$ROOT/tests/e2e/fake_command_manager.py" --port "$PORT" --cert "$W/cert.pem" --key "$W/key.pem" --store "$W/store.ndjson" \
    --mode-file "$W/mode" --token "$TOKEN" --commands "$W/commands.ndjson" --events "$W/events.ndjson" --redeliver-file "$W/redeliver" \
    >>"$W/manager.log" 2>&1 &
  MGR=$!
  for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && return 0; sleep 0.1; done
  say "manager did not start"; exit 2
}
start_sensor() {
  "$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >>"$W/sensord.log" 2>&1 &
  SENSOR=$!
  sleep 4
}
stop_sensor() { kill -INT "$SENSOR" 2>/dev/null; wait "$SENSOR" 2>/dev/null; SENSOR=; }

victim() { # starts a sleeping process, prints "pid ticks"
  sleep 3000 >/dev/null 2>&1 &
  local pid=$!
  echo "$pid" >>"$W/victim.pids"  # a file, because this runs in a subshell
  echo "$pid $(awk '{ sub(/^.*\) /, ""); print $20 }' "/proc/$pid/stat")"
}
alive() { kill -0 "$1" 2>/dev/null && echo alive || echo gone; }

# mk <id> <action> <target-json> [created-offset-s] [expires-offset-s] [agent]  -> an unsigned command object
mk() {
  AGENT=$AGENT HOSTID=$HOSTID python3 - "$@" <<'PY'
import datetime, json, os, sys
a = sys.argv[1:] + [None] * 6
ident, action, target = a[0], a[1], a[2]
created = int(a[3] or 0)
expires = int(a[4] or 300)
agent = a[5] or os.environ["AGENT"]
def z(offset):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({"command_id": ident, "schema_version": "1", "agent_id": agent, "action": action, "expires_at": z(expires),
                  "target": json.loads(target), "correlation_id": "corr-" + ident, "host_id": os.environ["HOSTID"],
                  "created_at": z(created)}, separators=(",", ":")))
PY
}
sign() { "$SIGNER" sign "$1"; }  # sign <keyfile> < command
enqueue() { cat >>"$W/commands.ndjson"; }
tamper() { # <json> <python statements editing d> -> edited JSON: the values change, the signature does not
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); exec(sys.argv[2]); print(json.dumps(d,separators=(",",":")))' "$1" "$2"
}

events() { # <kind> <id> -> how many events of that kind name the command, or the outcome:reason of the result
  python3 - "$W/events.ndjson" "$1" "$2" <<'PY'
import json, sys
path, kind, ident = sys.argv[1:4]
count, last = 0, ""
for row in open(path):
    try:
        event = json.loads(row)
    except ValueError:
        continue
    if kind == "accept" and event.get("accept") == ident:
        count += 1
    result = event.get("result")
    if kind == "result" and result and result.get("command_id") == ident:
        count += 1
        last = (result["outcome"] + ":" + result["detail"].split(":")[0]).lower()
print(last if kind == "verdict" else count)
PY
}
result_of() { # <id> -> "outcome:reason" once the Manager received the result (up to 25 s), else no-result
  local id=$1 line
  for _ in $(seq 1 50); do
    line=$(python3 - "$W/events.ndjson" "$id" <<'PY'
import json, sys
for row in open(sys.argv[1]):
    try:
        result = json.loads(row).get("result")
    except ValueError:
        continue
    if result and result.get("command_id") == sys.argv[2]:
        print((result["outcome"] + ":" + result["detail"].split(":")[0]).lower())
        break
PY
)
    [ -n "$line" ] && { echo "$line"; return; }
    sleep 0.5
  done
  echo "no-result"
}
detail_of() { # <id> -> the detail the Manager received for a command
  python3 - "$W/events.ndjson" "$1" <<'PY'
import json, sys
for row in open(sys.argv[1]):
    try:
        result = json.loads(row).get("result")
    except ValueError:
        continue
    if result and result.get("command_id") == sys.argv[2]:
        print(result["detail"])
PY
}
audited() { grep -c "$1" "$W/store.ndjson" 2>/dev/null; true; }

# ---- helpers for this suite -------------------------------------------------------------------------------------
cmd_signed() { mk "$@" | sign "$W/signing.key"; }  # cmd_signed <id> <action> <target-json> [created] [expires]
rows_for() { # <id-prefix> -> "rows distinct succeeded rate_limited indeterminate" of the results the Manager received
  python3 - "$W/events.ndjson" "$1" <<'PY'
import json, sys
rows, ids, count = 0, set(), {}
for row in open(sys.argv[1]):
    try:
        result = json.loads(row).get("result")
    except ValueError:
        continue
    if result and result.get("command_id", "").startswith(sys.argv[2]):
        rows += 1
        ids.add(result["command_id"])
        word = (result["outcome"] + ":" + result["detail"].split(":")[0]).lower()
        count[word] = count.get(word, 0) + 1
print(rows, len(ids), count.get("succeeded:ok", 0), count.get("rejected:rate_limited", 0),
      sum(v for k, v in count.items() if k.startswith("indeterminate")))
PY
}
wait_distinct() { # <id-prefix> <n> <timeout-s> -> waits until n distinct results arrived
  local deadline=$((SECONDS + $3)) got
  while [ $SECONDS -lt $deadline ]; do
    got=$(rows_for "$1"); got=${got#* }; got=${got%% *}
    [ "$got" -ge "$2" ] && return 0
    sleep 1
  done
  return 1
}
sensor_alive() { kill -0 "$SENSOR" 2>/dev/null && echo alive || echo dead; }
rss_mb() { awk '/VmRSS/ { printf "%d", $2 / 1024 }' "/proc/$SENSOR/status" 2>/dev/null; }
fresh_manager_events() { : >"$W/events.ndjson"; }
canary() { # <id> <pid> <ticks> -> the outcome of a signed read-only command
  cmd_signed "$1" COLLECT_PROCESS_INFO "{\"pid\":$2,\"start_time_ticks\":$3}" | enqueue
  result_of "$1"
}
cleanup_all() { cleanup; mountpoint -q /run/cmdledger 2>/dev/null && umount /run/cmdledger 2>/dev/null; return 0; }
trap cleanup_all EXIT

write_conf keys
start_manager
start_sensor
say "sensor up (pid $SENSOR), rss $(rss_mb) MB"
read -r PC TC < <(victim)   # the canary target

# 1. A burst larger than one poll's maximum (32): one result each, none lost, none duplicated.
START=$SECONDS
for i in $(seq 1 100); do cmd_signed "burst-$i" COLLECT_PROCESS_INFO "{\"pid\":$PC,\"start_time_ticks\":$TC}" | enqueue; done
wait_distinct burst- 100 120; say "burst of 100 answered in $((SECONDS - START)) s"
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for burst-)"
check "burst: 100 distinct results" 100 "$DISTINCT"
check "burst: no duplicate results" 100 "$ROWS"
check "burst: every command succeeded" 100 "$OK"
check "burst: the sensor is alive" alive "$(sensor_alive)"
say "rss after the burst: $(rss_mb) MB"

# 2. The changing-action rate limit: only RATE kills run per minute, the rest are refused and their victims live.
stop_sensor; RATE=5; write_conf keys; start_sensor
VICTIMS=()
for i in $(seq 1 12); do read -r P T < <(victim); VICTIMS+=("$P:$T"); done
i=0; for v in "${VICTIMS[@]}"; do i=$((i + 1)); cmd_signed "rate-$i" KILL_PROCESS "{\"pid\":${v%:*},\"start_time_ticks\":${v#*:}}" | enqueue; done
wait_distinct rate- 12 60; sleep 1
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for rate-)"
check "rate limit: five kills ran" 5 "$OK"
check "rate limit: seven refused as rate_limited" 7 "$RATED"
GONE=0; for v in "${VICTIMS[@]}"; do [ "$(alive "${v%:*}")" = gone ] && GONE=$((GONE + 1)); done
check "rate limit: exactly the five that ran are dead" 5 "$GONE"
stop_sensor; RATE=60; write_conf keys; start_sensor

# 3. The same command id twice in one batch, with different signed content: the first runs, the second is a replay.
read -r PA TA < <(victim); read -r PB TB < <(victim)
{ cmd_signed dup-1 KILL_PROCESS "{\"pid\":$PA,\"start_time_ticks\":$TA}"; cmd_signed dup-1 KILL_PROCESS "{\"pid\":$PB,\"start_time_ticks\":$TB}"; } | enqueue
wait_distinct dup- 1 30; sleep 3
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for dup-)"
check "duplicate id in one batch: one result" 1 "$ROWS"
check "duplicate id in one batch: only one victim died" 1 "$(( $( [ "$(alive "$PA")" = gone ] && echo 1 || echo 0 ) + $( [ "$(alive "$PB")" = gone ] && echo 1 || echo 0 ) ))"

# 4. Hostile but parseable content, one case per poll, each followed by a signed canary that must still run.
SPID=$SENSOR
for CASE in $(python3 "$ROOT/tests/e2e/hostile_commands.py" list); do
  python3 "$ROOT/tests/e2e/hostile_commands.py" "$CASE" "$AGENT" "$HOSTID" | enqueue
  sleep 3
  : >"$W/commands.ndjson"  # the Manager drops what it cannot deliver; one unreadable-size entry would otherwise sit in every reply
  C=$(canary "canary-$CASE" "$PC" "$TC")
  check "hostile $CASE: the next signed command still runs" succeeded "${C%%:*}"
done
check "hostile: the same sensor process survived them all" "$SPID" "$SENSOR"
check "hostile: the sensor is alive" alive "$(sensor_alive)"
RSS=$(rss_mb); say "rss after the hostile cases: $RSS MB"
check "hostile: the sensor stayed under 250 MB" yes "$([ "${RSS:-9999}" -lt 250 ] && echo yes || echo no)"
check "hostile: the victim of every refused kill (pid 1) still exists" alive "$(alive 1)"

# 5. The Manager disappears while a command is waiting; the command waits, then runs once.
read -r PO TO < <(victim)
: >"$W/commands.ndjson"  # the restarted Manager forgets what it delivered; do not hand the sensor the whole history again
kill -9 "$MGR"; wait "$MGR" 2>/dev/null; MGR=
cmd_signed outage-1 KILL_PROCESS "{\"pid\":$PO,\"start_time_ticks\":$TO}" | enqueue
sleep 6
check "outage: nothing ran while the Manager was unreachable" alive "$(alive "$PO")"
check "outage: the sensor is alive" alive "$(sensor_alive)"
start_manager
R=$(result_of outage-1); check "outage: the command runs once the Manager is back" succeeded "${R%%:*}"
sleep 3
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for outage-)"
check "outage: one result, not retried into duplicates" 1 "$ROWS"
check "outage: the victim is gone" gone "$(alive "$PO")"

# 6. The replay ledger on a filesystem that fills up while the sensor runs, then recovers.
stop_sensor
mkdir -p /run/cmdledger; umount /run/cmdledger 2>/dev/null
mount -t tmpfs -o size=64k tmpfs /run/cmdledger || { say "cannot mount tmpfs"; exit 2; }
LEDGER=/run/cmdledger/ledger; write_conf keys; start_sensor
C=$(canary ledger-before "$PC" "$TC"); check "ledger: a command runs while the filesystem has room" succeeded "${C%%:*}"
dd if=/dev/zero of=/run/cmdledger/fill bs=1k 2>/dev/null; sync
check "ledger: the filesystem is full" 0 "$(df --output=avail -k /run/cmdledger | tail -1 | tr -d ' ')"
# The ledger file's last page may still have room, so feed read-only commands until one cannot be recorded.
FULL_AT=
for round in $(seq 1 6); do
  for i in $(seq 1 20); do cmd_signed "ledger-fill-$round-$i" COLLECT_PROCESS_INFO "{\"pid\":$PC,\"start_time_ticks\":$TC}" | enqueue; done
  sleep 6
  if grep -q 'ledger_unavailable' "$W/events.ndjson"; then FULL_AT=$round; break; fi
done
check "ledger: once the ledger cannot grow, commands are answered rejected:ledger_unavailable" yes "$([ -n "$FULL_AT" ] && echo yes || echo no)"
read -r PL TL < <(victim)
LONGID=ledger-full-$(printf 'x%.0s' $(seq 1 100))  # longer than any record that fit in the page's last gap
cmd_signed "$LONGID" KILL_PROCESS "{\"pid\":$PL,\"start_time_ticks\":$TL}" | enqueue
R=$(result_of "$LONGID")
check "ledger: with no room to record it the kill is refused (fail closed)" "rejected:ledger_unavailable" "$R"
check "ledger: and the victim lives" alive "$(alive "$PL")"
check "ledger: the sensor is alive" alive "$(sensor_alive)"
rm -f /run/cmdledger/fill
# The refused kill was never accepted by the Manager, so it is still pending and still valid: it runs once it can be recorded.
for _ in $(seq 1 20); do [ "$(alive "$PL")" = gone ] && break; sleep 1; done
check "ledger: once room is freed the still-valid refused kill runs (and is recorded first)" gone "$(alive "$PL")"
read -r PL2 TL2 < <(victim)
cmd_signed ledger-room KILL_PROCESS "{\"pid\":$PL2,\"start_time_ticks\":$TL2}" | enqueue
R=$(result_of ledger-room); check "ledger: after room is freed new commands run" succeeded "${R%%:*}"
stop_sensor; umount /run/cmdledger; LEDGER=; write_conf keys

# 7. A corrupt ledger tail and a deleted ledger.
: >"$W/commands.ndjson"
start_sensor
C=$(canary ledger-a "$PC" "$TC"); check "ledger fault: a first command runs" succeeded "${C%%:*}"
stop_sensor
printf 'garbage that is not a ledger line\0\377\n' >>"$W/wal.commands"
say "ledger tail after corruption: $(tail -c 160 "$W/wal.commands" | tr '\000\n' '.|')"
echo yes >"$W/redeliver"
start_sensor
sleep 6
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for ledger-a)"
check "corrupt ledger tail: the old command is not run again (it may be refused as ledger_reset)" 1 "$OK"
C=$(canary ledger-b "$PC" "$TC"); check "corrupt ledger tail: new commands run" succeeded "${C%%:*}"
stop_sensor
rm -f "$W/wal.commands"
start_sensor
sleep 8
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for ledger-a)"
check "deleted ledger: a redelivered command that may already have run is not run again" 1 "$OK"
check "deleted ledger: it is refused as ledger_reset instead" yes "$(grep -q ledger_reset "$W/events.ndjson" && echo yes || echo no)"
echo no >"$W/redeliver"
stop_sensor; start_sensor

# 8. SIGKILL in the middle of a burst: every command still ends with an answer, and none runs twice.
fresh_manager_events; : >"$W/commands.ndjson"
for i in $(seq 1 64); do cmd_signed "kb-$i" COLLECT_PROCESS_INFO "{\"pid\":$PC,\"start_time_ticks\":$TC}" | enqueue; done
sleep 2
kill -9 "$SENSOR"; wait "$SENSOR" 2>/dev/null; SENSOR=
start_sensor
wait_distinct kb- 64 120
read -r ROWS DISTINCT OK RATED IND <<<"$(rows_for kb-)"
check "sigkill mid-burst: all 64 commands were answered" 64 "$DISTINCT"
check "sigkill mid-burst: every answer is a success or an honest indeterminate (a repeated result carries the same result_id)" "$ROWS" "$((OK + IND))"
say "sigkill mid-burst: $OK succeeded, $IND indeterminate, $ROWS result rows"

say "passed $PASSED, failed $FAILED"
[ "$FAILED" = 0 ]
