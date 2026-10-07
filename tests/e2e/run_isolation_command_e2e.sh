#!/usr/bin/env bash
# Real-kernel end-to-end test of ISOLATE_HOST / RELEASE_HOST_ISOLATION through the command channel (ADR 027):
# signed command -> sensord -> privileged helper -> nftables, with packets sent before, during and after.
#
# usage: sudo [SENSORD=..] [HELPER=..] [SIGNER=..] tests/e2e/run_isolation_command_e2e.sh
#
# Topology (three throwaway network namespaces, two veth pairs; the host's own network is never touched):
#
#   ici-manager (10.251.0.2, TLS fake Manager) --- ici-agent (10.251.0.1 / 10.251.1.1: sensord + helper) --- ici-peer (10.251.1.2, TCP)
#
# The helper pins the Manager's address and port. While isolated, the agent must still reach the Manager (results
# and further commands keep flowing) and must reach nothing else; release restores everything.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SENSORD=${SENSORD:-$ROOT/build-rel/panopticon-sensord}
HELPER=${HELPER:-$ROOT/build-rel/panopticon-isolation-helper}
SIGNER=${SIGNER:-$ROOT/build-rel/panopticon-command-signer}
W=${ISO_DIR:-/var/tmp/isocmd}
PORT=18557
PEER_PORT=9001
TOKEN=iso-token-0123456789abcdef
AGENT=iso-agent
MANAGER_IP=10.251.0.2
AGENT_MGR_IP=10.251.0.1
AGENT_PEER_IP=10.251.1.1
PEER_IP=10.251.1.2
FAILED=0
PASSED=0
SENSOR=
MGR=
HELPERPID=
export PYTHONDONTWRITEBYTECODE=1

say() { printf '[isocmd] %s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then PASSED=$((PASSED + 1)); say "PASS $1 ($3)"; else FAILED=$((FAILED + 1)); say "FAIL $1: expected '$2', got '$3'"; fi
}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$SENSORD" ] && [ -x "$HELPER" ] && [ -x "$SIGNER" ] || { echo "build panopticon-sensord, panopticon-isolation-helper and panopticon-command-signer first" >&2; exit 2; }

cleanup() {
  [ -n "$SENSOR" ] && kill -INT "$SENSOR" 2>/dev/null
  [ -n "$MGR" ] && kill -9 "$MGR" 2>/dev/null
  [ -n "$HELPERPID" ] && kill -9 "$HELPERPID" 2>/dev/null
  for ns in ici-manager ici-peer ici-agent; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; done
  for ns in ici-agent ici-manager ici-peer; do ip netns delete "$ns" 2>/dev/null; done
  return 0
}
trap cleanup EXIT

pkill -9 -f panopticon-isolation-helper 2>/dev/null
pkill -INT -f panopticon-sensord 2>/dev/null; sleep 1; pkill -9 -f panopticon-sensord 2>/dev/null
pkill -9 -f fake_command_manager.py 2>/dev/null
for ns in ici-agent ici-manager ici-peer; do ip netns delete "$ns" 2>/dev/null; ip netns add "$ns" && ip netns exec "$ns" ip link set lo up; done
rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"

ip link add ici-a-m netns ici-agent type veth peer name ici-m-a netns ici-manager || { say "veth setup failed"; exit 2; }
ip link add ici-a-p netns ici-agent type veth peer name ici-p-a netns ici-peer || { say "veth setup failed"; exit 2; }
ip netns exec ici-agent ip addr add $AGENT_MGR_IP/30 dev ici-a-m; ip netns exec ici-agent ip link set ici-a-m up
ip netns exec ici-manager ip addr add $MANAGER_IP/30 dev ici-m-a; ip netns exec ici-manager ip link set ici-m-a up
ip netns exec ici-agent ip addr add $AGENT_PEER_IP/30 dev ici-a-p; ip netns exec ici-agent ip link set ici-a-p up
ip netns exec ici-peer ip addr add $PEER_IP/30 dev ici-p-a; ip netns exec ici-peer ip link set ici-p-a up
ip netns exec ici-peer nc -lk "$PEER_PORT" >/dev/null 2>&1 &

HOSTID=$(tr -d '\n-' </etc/machine-id)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=$MANAGER_IP -addext subjectAltName=IP:$MANAGER_IP \
  -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1 || { say "openssl failed"; exit 2; }
printf '%s\n%s\n%s\n' "$AGENT" "$HOSTID" "$TOKEN" >"$W/identity.json"; chmod 600 "$W/identity.json"
KEYLINE=$("$SIGNER" keygen "$W/signing.key") || exit 2
echo "${KEYLINE% *} e2e-signing-key" >"$W/keyring"
echo ok >"$W/mode"; : >"$W/commands.ndjson"; : >"$W/events.ndjson"; echo no >"$W/redeliver"

write_conf() { # enforce | dry_run
  {
    echo "sensor_id=iso-sensor"
    echo "host_id=$HOSTID"
    echo "wal_path=$W/wal"
    echo "manager_url=https://$MANAGER_IP:$PORT"
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
    echo "response_mode=$1"
    echo "response_actions=COLLECT_NETWORK_CONNECTIONS,ISOLATE_HOST,RELEASE_HOST_ISOLATION"
    echo "response_isolation_socket=$W/isolation.sock"
    echo "response_poll_seconds=1"
    echo "response_max_changes_per_minute=60"
    echo "response_signing_keys=$W/keyring"
  } >"$W/sensor.conf"
}

in_agent() { ip netns exec ici-agent "$@"; }
start_manager() {
  ip netns exec ici-manager python3 "$ROOT/tests/e2e/fake_command_manager.py" --bind $MANAGER_IP --port "$PORT" --cert "$W/cert.pem" \
    --key "$W/key.pem" --store "$W/store.ndjson" --mode-file "$W/mode" --token "$TOKEN" --commands "$W/commands.ndjson" \
    --events "$W/events.ndjson" --redeliver-file "$W/redeliver" >>"$W/manager.log" 2>&1 &
  MGR=$!
  for _ in $(seq 1 50); do in_agent bash -c "exec 3<>/dev/tcp/$MANAGER_IP/$PORT" 2>/dev/null && return 0; sleep 0.1; done
  say "manager did not start"; exit 2
}
start_helper() {
  rm -f "$W/isolation.sock"
  ip netns exec ici-agent "$HELPER" "$W/isolation.sock" "$W/isolation.state" "$MANAGER_IP" "$PORT" root >>"$W/helper.log" 2>&1 &  # not through a function: $! must be the helper itself
  HELPERPID=$!
  for _ in $(seq 1 50); do [ -S "$W/isolation.sock" ] && return 0; sleep 0.1; done
  say "helper did not start"; exit 2
}
stop_helper() { kill -9 "$HELPERPID" 2>/dev/null; wait "$HELPERPID" 2>/dev/null; HELPERPID=; }
start_sensor() {
  ip netns exec ici-agent "$SENSORD" --config "$W/sensor.conf" --control-socket "$W/ctl.sock" >>"$W/sensord.log" 2>&1 &
  SENSOR=$!
  sleep 4
}
stop_sensor() { kill -INT "$SENSOR" 2>/dev/null; wait "$SENSOR" 2>/dev/null; SENSOR=; }

reachable() { in_agent bash -c "timeout 2 bash -c '</dev/tcp/$1/$2'" >/dev/null 2>&1 && echo yes || echo no; }
isolated_state() { grep -qx isolated "$W/isolation.state" 2>/dev/null && echo yes || echo no; }

mk() { # <id> <action> [created-offset-s] [expires-offset-s]
  AGENT=$AGENT HOSTID=$HOSTID python3 - "$@" <<'PY'
import datetime, json, os, sys
a = sys.argv[1:] + [None] * 4
ident, action = a[0], a[1]
created, expires = int(a[2] or 0), int(a[3] or 300)
def z(offset):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({"command_id": ident, "schema_version": "1", "agent_id": os.environ["AGENT"], "action": action, "expires_at": z(expires),
                  "target": {}, "correlation_id": "corr-" + ident, "host_id": os.environ["HOSTID"], "created_at": z(created)},
                 separators=(",", ":")))
PY
}
sign() { "$SIGNER" sign "$1"; }
enqueue() { cat >>"$W/commands.ndjson"; }

results() { # <id> -> how many results the Manager received for the command
  python3 - "$W/events.ndjson" "$1" <<'PY'
import json, sys
count = 0
for row in open(sys.argv[1]):
    try:
        result = json.loads(row).get("result")
    except ValueError:
        continue
    if result and result.get("command_id") == sys.argv[2]:
        count += 1
print(count)
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
audited() { grep -c "$1" "$W/store.ndjson" 2>/dev/null; true; }

start_manager
start_helper
check "baseline: the Manager is reachable" yes "$(reachable $MANAGER_IP $PORT)"
check "baseline: the peer is reachable" yes "$(reachable $PEER_IP $PEER_PORT)"

# 1. A dry-run sensor checks the helper and sends nothing.
write_conf dry_run
start_sensor
mk dry-isolate ISOLATE_HOST | sign "$W/signing.key" | enqueue
check "dry run: isolate is verified, not applied" "rejected:dry_run" "$(result_of dry-isolate)"
check "dry run: the peer is still reachable" yes "$(reachable $PEER_IP $PEER_PORT)"
check "dry run: the helper recorded nothing" no "$(isolated_state)"
stop_sensor

# 2. Enforcing sensor: an unsigned command is refused before the helper is asked.
write_conf enforce
start_sensor
mk unsigned-isolate ISOLATE_HOST | enqueue
check "unsigned isolate refused" "rejected:signature_required" "$(result_of unsigned-isolate)"
check "unsigned isolate: the peer is still reachable" yes "$(reachable $PEER_IP $PEER_PORT)"

# 3. A signed isolate applies the ruleset; the result still reaches the Manager through it.
mk iso-1 ISOLATE_HOST | sign "$W/signing.key" | enqueue
check "signed isolate succeeds (the result crossed the pinned Manager path)" "succeeded:ok" "$(result_of iso-1)"
check "isolated: the peer is no longer reachable" no "$(reachable $PEER_IP $PEER_PORT)"
check "isolated: the Manager is still reachable" yes "$(reachable $MANAGER_IP $PORT)"
check "isolated: the helper recorded it" yes "$(isolated_state)"

# 4. The command channel keeps working while the host is isolated.
mk while-isolated COLLECT_NETWORK_CONNECTIONS | sign "$W/signing.key" | enqueue
check "a command delivered while isolated runs" "succeeded:ok" "$(result_of while-isolated)"

# 5. Redelivery and a restart of the sensor while isolated change nothing and re-run nothing.
BEFORE=$(results iso-1)
stop_sensor
echo yes >"$W/redeliver"
start_sensor; sleep 5
echo no >"$W/redeliver"
check "restart while isolated: no second result for iso-1" "$BEFORE" "$(results iso-1)"
check "restart while isolated: still contained" no "$(reachable $PEER_IP $PEER_PORT)"

# 6. A helper crash does not release the host, and its restart re-applies the recorded state.
stop_helper
check "helper down: the kernel ruleset keeps the host contained" no "$(reachable $PEER_IP $PEER_PORT)"
start_helper
check "helper restarted: still contained" no "$(reachable $PEER_IP $PEER_PORT)"

# 7. Release restores connectivity; a second release is a no-op success.
mk rel-1 RELEASE_HOST_ISOLATION | sign "$W/signing.key" | enqueue
check "signed release succeeds" "succeeded:ok" "$(result_of rel-1)"
check "released: the peer is reachable again" yes "$(reachable $PEER_IP $PEER_PORT)"
check "released: the helper recorded it" no "$(isolated_state)"
mk rel-2 RELEASE_HOST_ISOLATION | sign "$W/signing.key" | enqueue
check "release when not isolated is an idempotent success" "succeeded:ok" "$(result_of rel-2)"

# 8. Helper unavailable: the answer says failed and nothing was applied.
stop_helper
rm -f "$W/isolation.sock"
mk iso-nohelper ISOLATE_HOST | sign "$W/signing.key" | enqueue
check "no helper: isolate fails safely" "failed:helper_unreachable" "$(result_of iso-nohelper)"
check "no helper: the peer is still reachable" yes "$(reachable $PEER_IP $PEER_PORT)"
start_helper

# 9. Isolation is audited, and a second isolate after the helper is back works.
mk iso-2 ISOLATE_HOST | sign "$W/signing.key" | enqueue
check "isolate after the helper returns" "succeeded:ok" "$(result_of iso-2)"
mk rel-3 RELEASE_HOST_ISOLATION | sign "$W/signing.key" | enqueue
check "and release again" "succeeded:ok" "$(result_of rel-3)"
check "isolation outcomes are audited as response.action records" "yes" \
  "$([ "$(audited helper_unreachable)" -ge 1 ] && [ "$(audited ISOLATE_HOST)" -ge 1 ] && echo yes || echo no)"
check "the host ends released" yes "$(reachable $PEER_IP $PEER_PORT)"

say "passed $PASSED, failed $FAILED"
[ "$FAILED" = 0 ]
