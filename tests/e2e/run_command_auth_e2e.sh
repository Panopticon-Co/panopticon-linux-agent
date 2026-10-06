#!/usr/bin/env bash
# Real-kernel end-to-end test of per-command authorization (ADR 025) against a fake Manager that delivers
# commands over TLS, with real victim processes, as root.
#
# usage: sudo [SENSORD=build-rel/panopticon-sensord] [SIGNER=build-rel/panopticon-command-signer] tests/e2e/run_command_auth_e2e.sh
#
# Scenarios: signed commands run; unsigned, foreign-key, tampered (target, action, validity window) and
# wrong-endpoint commands are refused and the victim survives; a replayed command is closed from the ledger and
# not run again; a key is revoked by editing the keyring while the sensor runs; an invalid keyring edit keeps the
# previous keys; a restart does not re-run anything; an unsigned-allowed sensor still runs unsigned commands; a
# sensor whose keyring is unusable at start processes no command.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SENSORD=${SENSORD:-$ROOT/build-rel/panopticon-sensord}
SIGNER=${SIGNER:-$ROOT/build-rel/panopticon-command-signer}
W=${AUTH_DIR:-/var/tmp/cmdauth}
PORT=${AUTH_PORT:-18556}
TOKEN=auth-token-0123456789abcdef
AGENT=auth-agent
FAILED=0
PASSED=0
SENSOR=
MGR=

say() { printf '[cmdauth] %s\n' "$*"; }
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
    echo "sensor_id=auth-sensor"
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
    echo "response_actions=KILL_PROCESS,COLLECT_PROCESS_INFO,COLLECT_FILE,QUARANTINE_FILE"
    echo "response_file_roots=$W,/run/cmdvictims"
    echo "response_poll_seconds=1"
    echo "response_max_changes_per_minute=60"
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

write_conf keys
start_manager
start_sensor
say "sensor up; pinned key id ${KEYLINE##* }"

read -r P1 T1 < <(victim); read -r P2 T2 < <(victim); read -r P3 T3 < <(victim); read -r P4 T4 < <(victim); read -r P5 T5 < <(victim)

# 1. A correctly signed read-only command runs, and so does a signed kill.
mk ok-collect COLLECT_PROCESS_INFO "{\"pid\":$P1,\"start_time_ticks\":$T1}" | sign "$W/signing.key" | enqueue
R=$(result_of ok-collect); check "signed collect runs" "succeeded" "${R%%:*}"
mk ok-kill KILL_PROCESS "{\"pid\":$P1,\"start_time_ticks\":$T1}" | sign "$W/signing.key" | enqueue
R=$(result_of ok-kill); check "signed kill is executed" "succeeded" "${R%%:*}"; sleep 1
check "signed kill: victim gone" gone "$(alive "$P1")"

# 2. Refusals: the victim must survive every one of these.
mk unsigned-kill KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":$T2}" | enqueue
check "unsigned kill refused" "rejected:signature_required" "$(result_of unsigned-kill)"

mk foreign-kill KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":$T2}" | sign "$W/foreign.key" | enqueue
check "kill signed by an unpinned key refused" "rejected:unknown_signing_key" "$(result_of foreign-kill)"

BENIGN=$(mk tamper-action COLLECT_PROCESS_INFO "{\"pid\":$P2,\"start_time_ticks\":$T2}" | sign "$W/signing.key")
tamper "$BENIGN" 'd["action"]="KILL_PROCESS"' | enqueue
check "signed collect turned into a kill refused" "rejected:signature_invalid" "$(result_of tamper-action)"

SIGNED=$(mk tamper-target KILL_PROCESS "{\"pid\":$P3,\"start_time_ticks\":$T3}" | sign "$W/signing.key")
tamper "$SIGNED" "d['target']['pid']=$P2; d['target']['start_time_ticks']=$T2" | enqueue
check "kill retargeted to another process refused" "rejected:signature_invalid" "$(result_of tamper-target)"

SIGNED=$(mk tamper-window KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":$T2}" -3000 -2700 | sign "$W/signing.key")
tamper "$SIGNED" 'd["expires_at"]="2099-01-01T00:00:00Z"; d["created_at"]="2098-12-31T23:00:00Z"' | enqueue
check "expired signed command given a new window refused" "rejected:signature_invalid" "$(result_of tamper-window)"

mk wrong-agent KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":$T2}" 0 300 other-agent | sign "$W/signing.key" | enqueue
check "validly signed command for another agent refused" "rejected:wrong_endpoint" "$(result_of wrong-agent)"

mk stale-signed KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":$T2}" -3000 -2000 | sign "$W/signing.key" | enqueue
check "validly signed but expired command refused" "rejected:expired" "$(result_of stale-signed)"

mk long-lived KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":$T2}" -10 3000 | sign "$W/signing.key" | enqueue
check "validly signed but over-long command refused" "rejected:lifetime_exceeded" "$(result_of long-lived)"

mk pid-reuse KILL_PROCESS "{\"pid\":$P2,\"start_time_ticks\":1}" | sign "$W/signing.key" | enqueue
R=$(result_of pid-reuse); check "validly signed kill of a pid with the wrong start time refused" "rejected" "${R%%:*}"
check "every refused command left its victim alive" "alive alive alive" "$(alive "$P2") $(alive "$P3") $(alive "$P4")"
check "refusals are audited as response.action records" "yes" "$([ "$(audited signature_required)" -ge 1 ] && [ "$(audited signature_invalid)" -ge 1 ] && echo yes || echo no)"

# 3. Replay: the Manager delivers an already closed, validly signed command again. The ledger closes it; the
#    action is not performed again and no second result is produced.
BEFORE=$(events result ok-kill); ACC_BEFORE=$(events accept ok-kill)
echo yes >"$W/redeliver"; sleep 6; echo no >"$W/redeliver"
check "replayed command produced no second result" "$BEFORE" "$(events result ok-kill)"
check "replayed command was only re-closed (accept is idempotent)" "yes" "$([ "$(events accept ok-kill)" -gt "$ACC_BEFORE" ] && echo yes || echo no)"

# 4. Revocation by editing the keyring while the sensor runs; an unusable edit keeps the previous keys.
echo "$SPARE spare-key" >"$W/keyring"; sleep 3
mk after-revoke KILL_PROCESS "{\"pid\":$P4,\"start_time_ticks\":$T4}" | sign "$W/signing.key" | enqueue
check "kill signed by a revoked key refused" "rejected:unknown_signing_key" "$(result_of after-revoke)"
check "revoked-key victim alive" alive "$(alive "$P4")"
echo "not a key at all" >"$W/keyring"; sleep 3
mk bad-keyring COLLECT_PROCESS_INFO "{\"pid\":$P4,\"start_time_ticks\":$T4}" | sign "$W/spare.key" | enqueue
R=$(result_of bad-keyring); check "an unusable keyring edit keeps the previous (spare-only) keys: spare key works" "succeeded" "${R%%:*}"
printf '%s e2e-signing-key\n%s spare-key\n' "$KEY" "$SPARE" >"$W/keyring"; sleep 3
mk restored KILL_PROCESS "{\"pid\":$P4,\"start_time_ticks\":$T4}" | sign "$W/signing.key" | enqueue
R=$(result_of restored); check "key restored: signed kill runs again" "succeeded" "${R%%:*}"; sleep 1
check "restored-key victim gone" gone "$(alive "$P4")"

# 5. Restart with redelivery: nothing is run twice and no answer changes.
BEFORE=$(events result ok-kill)
stop_sensor
echo yes >"$W/redeliver"
start_sensor; sleep 6
echo no >"$W/redeliver"
check "restart: no extra result for ok-kill" "$BEFORE" "$(events result ok-kill)"
check "restart: the survivor of the refused commands is alive" alive "$(alive "$P5")"

# 6. File actions (ADR 026): COLLECT_FILE and QUARANTINE_FILE on real files, signed, through the real channel.
VICT=$W/victims; XD=/run/cmdvictims
rm -rf "$XD"; mkdir -p "$VICT" "$XD"
HELLO=5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
printf 'hello\n' >"$VICT/sample"; chmod 640 "$VICT/sample"
fcmd() { mk "$1" "$2" "{\"path\":\"$3\"}" "${@:4}"; }
fcmd f-collect COLLECT_FILE "$VICT/sample" | sign "$W/signing.key" | enqueue
R=$(result_of f-collect); check "signed COLLECT_FILE succeeds" "succeeded:ok" "$R"
check "COLLECT_FILE reports the SHA-256 and mode" yes "$(d=$(detail_of f-collect); case $d in *sha256=$HELLO*mode=0640*|*mode=0640*sha256=$HELLO*) echo yes;; *) echo no;; esac)"
fcmd f-unsigned QUARANTINE_FILE "$VICT/sample" | enqueue
check "unsigned QUARANTINE_FILE refused" "rejected:signature_required" "$(result_of f-unsigned)"
BENIGN=$(fcmd f-tamper COLLECT_FILE "$VICT/sample" | sign "$W/signing.key")
tamper "$BENIGN" 'd["action"]="QUARANTINE_FILE"' | enqueue
check "signed COLLECT_FILE turned into QUARANTINE_FILE refused" "rejected:signature_invalid" "$(result_of f-tamper)"
SIGNED=$(fcmd f-retarget QUARANTINE_FILE "$VICT/sample" | sign "$W/signing.key")
tamper "$SIGNED" "d['target']['path']='/etc/hostname'" | enqueue
check "signed quarantine retargeted to another path refused" "rejected:signature_invalid" "$(result_of f-retarget)"
fcmd f-outside QUARANTINE_FILE /etc/hostname | sign "$W/signing.key" | enqueue
check "quarantine outside the permitted directories refused" "rejected:outside_roots" "$(result_of f-outside)"
fcmd f-keyring QUARANTINE_FILE "$W/keyring" | sign "$W/signing.key" | enqueue
check "the sensor's own keyring is protected" "rejected:target_protected" "$(result_of f-keyring)"
fcmd f-identity QUARANTINE_FILE "$W/identity.json" | sign "$W/signing.key" | enqueue
check "the sensor's own identity is protected" "rejected:target_protected" "$(result_of f-identity)"
ln -s "$VICT/sample" "$VICT/link"; ln -s "$VICT" "$VICT/dirlink"
fcmd f-link QUARANTINE_FILE "$VICT/link" | sign "$W/signing.key" | enqueue
check "a symlink is not quarantined" "rejected:not_a_file" "$(result_of f-link)"
fcmd f-dirlink QUARANTINE_FILE "$VICT/dirlink/sample" | sign "$W/signing.key" | enqueue
check "a path through a symlinked directory is refused" "rejected:path_symlink" "$(result_of f-dirlink)"
fcmd f-dotdot QUARANTINE_FILE "$VICT/../victims/sample" | sign "$W/signing.key" | enqueue
check "a path with .. is refused before anything is opened" "rejected:invalid_target" "$(result_of f-dotdot)"
check "every refusal left the file in place with its content" "hello" "$(cat "$VICT/sample")"

fcmd f-quarantine QUARANTINE_FILE "$VICT/sample" | sign "$W/signing.key" | enqueue
check "signed QUARANTINE_FILE succeeds" "succeeded:ok" "$(result_of f-quarantine)"
check "the original is gone" gone "$([ -e "$VICT/sample" ] && echo present || echo gone)"
check "the stored copy is the file" "hello" "$(cat "$W/wal.quarantine/f-quarantine.blob" 2>/dev/null)"
check "the stored copy is read-only and private" "400 700" "$(stat -c %a "$W/wal.quarantine/f-quarantine.blob") $(stat -c %a "$W/wal.quarantine")"
check "the record names the original path and hash" yes "$(grep -q "$VICT/sample" "$W/wal.quarantine/f-quarantine.json" && grep -q "$HELLO" "$W/wal.quarantine/f-quarantine.json" && echo yes || echo no)"
# Exactly once: a new file at the same path survives a redelivery of the same signed command, and a restart.
printf 'second\n' >"$VICT/sample"
BEFORE=$(events result f-quarantine)
echo yes >"$W/redeliver"; sleep 6
stop_sensor; start_sensor; sleep 6
echo no >"$W/redeliver"
check "redelivery and restart do not quarantine the new file at the same path" "second" "$(cat "$VICT/sample" 2>/dev/null)"
check "and produce no second result" "$BEFORE" "$(events result f-quarantine)"
printf 'across\n' >"$XD/x"
fcmd f-xdev QUARANTINE_FILE "$XD/x" | sign "$W/signing.key" | enqueue
check "quarantine across filesystems succeeds" "succeeded:ok" "$(result_of f-xdev)"
check "it was a copy, then the original was removed" "copied gone across" "$(d=$(detail_of f-xdev); case $d in *copied*) printf copied;; *) printf other;; esac) $([ -e "$XD/x" ] && echo present || echo gone) $(cat "$W/wal.quarantine/f-xdev.blob")"
check "file actions are audited as response.action records" yes "$([ "$(audited COLLECT_FILE)" -ge 1 ] && [ "$(audited QUARANTINE_FILE)" -ge 1 ] && echo yes || echo no)"
# A dry-run sensor still collects, and verifies a quarantine without moving anything.
stop_sensor; write_conf keys dry_run; start_sensor
fcmd f-dry-collect COLLECT_FILE "$VICT/sample" | sign "$W/signing.key" | enqueue
check "dry_run still runs COLLECT_FILE" "succeeded:ok" "$(result_of f-dry-collect)"
fcmd f-dry-q QUARANTINE_FILE "$VICT/sample" | sign "$W/signing.key" | enqueue
check "dry_run verifies QUARANTINE_FILE and moves nothing" "rejected:dry_run" "$(result_of f-dry-q)"
check "the file is still there after the dry run" "second" "$(cat "$VICT/sample")"
stop_sensor; write_conf keys enforce; start_sensor

# 7. An unsigned-allowed sensor (explicit opt-in) runs unsigned commands, and warns at start.
stop_sensor
write_conf unsigned
: >"$W/sensord.log"
start_sensor
check "unsigned mode warns at start" yes "$(grep -q WARNING "$W/sensord.log" && echo yes || echo no)"
mk unsigned-ok COLLECT_PROCESS_INFO "{\"pid\":$P5,\"start_time_ticks\":$T5}" | enqueue
R=$(result_of unsigned-ok); check "opted-in unsigned sensor runs an unsigned command" "succeeded" "${R%%:*}"
stop_sensor

# 8. Fail closed: signing keys configured but the file is unusable at start, so the channel does not run.
write_conf keys
echo "garbage" >"$W/keyring"
: >"$W/sensord.log"
start_sensor
mk closed COLLECT_PROCESS_INFO "{\"pid\":$P5,\"start_time_ticks\":$T5}" | sign "$W/signing.key" | enqueue
sleep 6
check "unusable keyring at start: no command is processed" 0 "$(events result closed)"
say "sensord said: $(grep -i -m2 'command\|signing' "$W/sensord.log" | tr '\n' ' ')"
stop_sensor

say "passed $PASSED, failed $FAILED"
[ "$FAILED" = 0 ]
