#!/usr/bin/env bash
# Real-kernel end-to-end test of the start-of-policy sweep (ADR 035) with the release sensord, as root, no Manager.
#
# usage: sudo [BUILD=/path/to/build-dir] tests/e2e/run_policy_sweep_e2e.sh
#
# A real process is already running before any policy exists. Scenarios: a signed policy that matches its command
# line is accepted while the sensor runs, and the running process is reported (policy.match, subject
# process.running, the right pid and entity); an unrelated running process is not; the same version is not swept
# again; a newer version sweeps again; a restarted sensor with a policy already in place reports the process that
# is still running; a policy that does not match anything writes nothing. Nothing is killed: a match is a recommendation.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
B=${BUILD:-$ROOT/build-rel}
SENSORD=$B/panopticon-sensord
SIGNER=$B/panopticon-command-signer
W=${SWEEP_DIR:-/var/tmp/policy-sweep-e2e}
FAILED=0
PASSED=0

say() { printf '[sweep] %s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then PASSED=$((PASSED + 1)); say "PASS $1 ($3)"; else FAILED=$((FAILED + 1)); say "FAIL $1: expected '$2', got '$3'"; fi
}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for f in "$SENSORD" "$SIGNER"; do [ -x "$f" ] || { echo "missing $f" >&2; exit 2; }; done

rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
LINE=$("$SIGNER" keygen "$W/policy.key") || exit 2
echo "$LINE" >"$W/policy.keys"; chmod 600 "$W/policy.keys"

cat >"$W/sensor.conf" <<CONF
sensor_id=sweep-e2e
host_id=$(tr -d '\n-' </etc/machine-id)
wal_path=$W/wal
health_interval_seconds=10
policy_path=$W/policy
policy_signing_keys=$W/policy.keys
policy_check_seconds=5
enable_network_events=false
enable_auth_events=false
enable_kernel_events=false
enable_security_events=false
enable_sensitive_file_events=false
enable_fim=false
CONF
chmod 644 "$W/sensor.conf"

# Only this script's own sensor and victims are ever signalled (by pid).
start() { rm -f "$W/sensor.pid"; setsid -f bash -c "echo \$\$ >$W/sensor.pid; exec $SENSORD --config $W/sensor.conf >>$W/sensord.log 2>&1" </dev/null >/dev/null 2>&1; sleep 1; }
stop() {
  local pid; pid=$(cat "$W/sensor.pid" 2>/dev/null) || return 0
  [ -n "$pid" ] || return 0
  kill -INT "$pid" 2>/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -9 "$pid" 2>/dev/null
}
VICTIMS=
cleanup() { stop; [ -n "$VICTIMS" ] && kill -9 $VICTIMS 2>/dev/null; return 0; }
trap cleanup EXIT

publish() { # <version> <rule line>
  local now; now=$(date +%s)
  printf '%s\n' "$2" | "$SIGNER" sign-policy "$W/policy.key" sweep-policy "$1" $((now - 30)) $((now + 3600)) all >"$W/policy.new" || return 1
  chmod 600 "$W/policy.new"; mv "$W/policy.new" "$W/policy"
}

WAL=$W/wal
# shellcheck source=tests/e2e/wal_helpers.sh
. "$ROOT/tests/e2e/wal_helpers.sh"

matches_for() { # <pid> <version>
  count "sum(1 for r in rows if r['kind']=='match' and r['subject']['type']=='process.running' and r['process'] and r['process']['pid']==$1 and r['version']==$2)"
}

say "0. two processes are running before the sensor and before any policy"
sleep 7771 & TARGET=$!
sleep 7772 & BYSTANDER=$!
VICTIMS="$TARGET $BYSTANDER"
start
sleep 8
check "no policy: no match" 0 "$(count "sum(1 for r in rows if r['kind']=='match')")"

say "1. a signed policy naming the first process's command line is accepted while the sensor runs"
publish 1 "rule sleep-7771 process.exec cmdline contains recommend_terminate high sleep 7771" || { say "cannot sign"; exit 2; }
wait_for 40 "any(r['kind']=='match' for r in rows)"
check "the running process is reported" 1 "$(matches_for "$TARGET" 1)"
check "the match names the rule and the action" "sleep-7771 recommend_terminate high" \
  "$(count "[r['rule_id']+' '+r['action']+' '+r['severity'] for r in rows if r['kind']=='match'][0]")"
check "the match is labelled as a sweep of a running process" process.running "$(count "[r['subject']['type'] for r in rows if r['kind']=='match'][0]")"
check "the match's subject seq is a real record" 1 "$(count "1 if [r for r in rows if r['kind']=='match'][0]['subject']['seq'] >= 1 else 0")"
check "the unrelated process is not reported" 0 "$(count "sum(1 for r in rows if r['kind']=='match' and r['process'] and r['process']['pid']==$BYSTANDER)")"
check "nothing was killed" yes "$(kill -0 "$TARGET" 2>/dev/null && echo yes || echo no)"

say "2. the same version is not swept again"
sleep 16
check "one match for version 1" 1 "$(matches_for "$TARGET" 1)"

say "3. a newer version sweeps again"
publish 2 "rule sleep-7771 process.exec cmdline contains recommend_terminate high sleep 7771"
wait_for 40 "any(r['kind']=='match' and r['version']==2 for r in rows)"
check "version 2 reports the still-running process" 1 "$(matches_for "$TARGET" 2)"
check "version 1 was not repeated" 1 "$(matches_for "$TARGET" 1)"

say "4. a restarted sensor with the policy already in place reports what is still running"
stop
start
wait_for 40 "sum(1 for r in rows if r['kind']=='match' and r['version']==2) >= 2"
check "after the restart version 2 reports it again" 2 "$(matches_for "$TARGET" 2)"
check "the policy provider is active without a sweep warning" active \
  "$(count "[r['policy']['state'] for r in rows if r['kind']=='health' and r['policy']][-1]")"
check "no sweep limit was reached" 0 "$(count "sum(1 for r in rows if r['kind']=='health' and r['policy'] and 'sweep stopped' in (r['policy'].get('reason') or ''))")"

say "5. a policy that matches nothing writes nothing"
BEFORE=$(count "sum(1 for r in rows if r['kind']=='match')")
publish 3 "rule nothing process.exec cmdline contains alert low no-such-command-line-7773"
sleep 16
check "no new match" "$BEFORE" "$(count "sum(1 for r in rows if r['kind']=='match')")"

say "6. an indicator on the digest of the running image is matched once the sweep has hashed it"
SLEEP_SHA=$(sha256sum "$(readlink -f "$(command -v sleep)")" | cut -d' ' -f1)
publish 4 "$(printf 'ioc sha256 %s\nrule known-bad process.exec sha256 ioc recommend_quarantine critical' "$SLEEP_SHA")"
wait_for 60 "any(r['kind']=='match' and r['version']==4 and r['field']=='sha256' for r in rows)"
check "the digest indicator matches the running target" 1 \
  "$(count "sum(1 for r in rows if r['kind']=='match' and r['version']==4 and r['field']=='sha256' and r['rule_id']=='known-bad' and r['matched']=='$SLEEP_SHA' and r['process'] and r['process']['pid']==$TARGET)")"
check "and the bystander, which runs the same image" 1 \
  "$(count "sum(1 for r in rows if r['kind']=='match' and r['version']==4 and r['field']=='sha256' and r['process'] and r['process']['pid']==$BYSTANDER)")"

stop
say "passed $PASSED, failed $FAILED"
[ "$FAILED" = 0 ]
