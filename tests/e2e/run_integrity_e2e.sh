#!/usr/bin/env bash
# Real-kernel end-to-end test of self-integrity (ADR 033) with the release sensord, as root, no Manager.
#
# usage: sudo [BUILD=/path/to/build-dir] tests/e2e/run_integrity_e2e.sh
#
# The sensor runs from an "install" directory whose two files (the sensor and panopticon-ctl) are listed in a signed
# build manifest. Scenarios: a clean start is quiet; a listed file is edited (reported after two looks, with the
# process that wrote it, then restored); the running binary is replaced by another copy of the same build
# (binary_replaced, with the process that renamed it); the manifest is edited (manifest_invalid); a listed file is
# deleted (binary_missing); a restart from the replaced binary verifies clean; a restart with a manifest signed by a
# key this endpoint does not pin reports manifest_invalid at once and degrades health.
# The tamper.integrity records are written to $W/tamper.ndjson for the contract validator.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
B=${BUILD:-$ROOT/build-rel}
SENSORD_SRC=$B/panopticon-sensord
CTL_SRC=$B/panopticon-ctl
SIGNER=$B/panopticon-command-signer
W=${INTEGRITY_DIR:-/var/tmp/integrity-e2e}
FAILED=0
PASSED=0

say() { printf '[integrity] %s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then PASSED=$((PASSED + 1)); say "PASS $1 ($3)"; else FAILED=$((FAILED + 1)); say "FAIL $1: expected '$2', got '$3'"; fi
}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for f in "$SENSORD_SRC" "$CTL_SRC" "$SIGNER"; do [ -x "$f" ] || { echo "missing $f" >&2; exit 2; }; done

# Only this script's own sensor is ever signalled (by pid), so it can share a host with another sensord.
rm -rf "$W"; mkdir -p "$W/bin"; chmod 755 "$W" "$W/bin"
install -m 0755 "$SENSORD_SRC" "$W/bin/panopticon-sensord"
install -m 0755 "$CTL_SRC" "$W/bin/panopticon-ctl"
SENSOR_BIN=$W/bin/panopticon-sensord
CTL_BIN=$W/bin/panopticon-ctl

LINE=$("$SIGNER" keygen "$W/release.key") || exit 2
"$SIGNER" keygen "$W/stranger.key" >/dev/null || exit 2
echo "$LINE" >"$W/integrity.keys"; chmod 644 "$W/integrity.keys"

sign_manifest() { # <key> <out>
  printf '%s\n%s\n' "$SENSOR_BIN" "$CTL_BIN" | "$SIGNER" sign-manifest "$1" panopticon-sensord 0.0.1-e2e "$(date +%s)" >"$2.new" || return 1
  chmod 644 "$2.new"; mv "$2.new" "$2"
}
sign_manifest "$W/release.key" "$W/build-manifest" || { say "cannot sign the manifest"; exit 2; }

cat >"$W/sensor.conf" <<CONF
sensor_id=integrity-e2e
host_id=$(tr -d '\n-' </etc/machine-id)
wal_path=$W/wal
health_interval_seconds=10
integrity_manifest=$W/build-manifest
integrity_keys=$W/integrity.keys
integrity_check_seconds=5
enable_network_events=false
enable_auth_events=false
enable_kernel_events=false
enable_security_events=false
enable_sensitive_file_events=false
enable_fim=false
CONF
chmod 644 "$W/sensor.conf"

start() { rm -f "$W/sensor.pid"; setsid -f bash -c "echo \$\$ >$W/sensor.pid; exec $SENSOR_BIN --config $W/sensor.conf >>$W/sensord.log 2>&1" </dev/null >/dev/null 2>&1; sleep 1; }
stop() {
  local pid; pid=$(cat "$W/sensor.pid" 2>/dev/null) || return 0
  [ -n "$pid" ] || return 0
  kill -INT "$pid" 2>/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -9 "$pid" 2>/dev/null
}
cleanup() { stop; return 0; }
trap cleanup EXIT

WAL=$W/wal
# shellcheck source=tests/e2e/wal_helpers.sh
. "$ROOT/tests/e2e/wal_helpers.sh"

say "1. clean start from the installed binary"
start
sleep 14
check "clean start: no tamper record" 0 "$(count "sum(1 for r in rows if r['kind']=='tamper')")"
check "clean start: integrity provider active" active "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"
check "clean start: health status healthy" healthy "$(count "[r['status'] for r in rows if r['kind']=='health'][-1]")"

say "2. a listed file is edited by a process we know"
cp "$CTL_BIN" "$W/ctl.orig"
bash -c "echo \$\$ >$W/tamperer.pid; echo tampered >>$CTL_BIN"
TAMPERER=$(cat "$W/tamperer.pid")
wait_for 60 "any(r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_modified' and r['target']=='$CTL_BIN' for r in rows)"
check "edit: reported as binary_modified" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_modified' and r['target']=='$CTL_BIN')")"
check "edit: hashes differ" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['technique']=='binary_modified' and r['target']=='$CTL_BIN' and r['expected_sha256']!=r['observed_sha256'])")"
check "edit: attributed to the writer's pid" "$TAMPERER" "$(count "[r['process']['pid'] for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['target']=='$CTL_BIN'][0]")"
check "edit: last_change is a modify" modify "$(count "[r['last_change']['operation'] for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['target']=='$CTL_BIN'][0]")"
check "edit: health degraded" degraded "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"
cat "$W/ctl.orig" >"$CTL_BIN"
wait_for 40 "any(r['kind']=='tamper' and r['status']=='restored' and r['target']=='$CTL_BIN' for r in rows)"
check "edit undone: restored" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='restored' and r['target']=='$CTL_BIN')")"

say "3. the running binary is replaced by another copy of the same build"
cp "$SENSOR_BIN" "$W/bin/.new"
bash -c "echo \$\$ >$W/replacer.pid; exec mv $W/bin/.new $SENSOR_BIN"
REPLACER=$(cat "$W/replacer.pid")
wait_for 60 "any(r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_replaced' for r in rows)"
check "replace: reported as binary_replaced" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_replaced' and r['target']=='$SENSOR_BIN')")"
check "replace: attributed to the renaming process" "$REPLACER" "$(count "[r['process']['pid'] for r in rows if r['kind']=='tamper' and r['technique']=='binary_replaced' and r['status']=='violated'][0]")"
check "replace: last_change is a rename" rename "$(count "[r['last_change']['operation'] for r in rows if r['kind']=='tamper' and r['technique']=='binary_replaced' and r['status']=='violated'][0]")"

say "4. the manifest is edited"
cp "$W/build-manifest" "$W/manifest.orig"
bash -c "echo '$(printf 'a%.0s' $(seq 64)) 1 /opt/extra' >>$W/build-manifest"
wait_for 60 "any(r['kind']=='tamper' and r['status']=='violated' and r['technique']=='manifest_invalid' for r in rows)"
check "manifest edit: manifest_invalid" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='manifest_invalid')")"
check "manifest edit: the reason is named" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['technique']=='manifest_invalid' and ('bad_signature' in r['detail'] or 'malformed' in r['detail']))")"
cp "$W/manifest.orig" "$W/build-manifest"
wait_for 40 "any(r['kind']=='tamper' and r['status']=='restored' and r['technique']=='manifest_invalid' for r in rows)"
check "manifest put back: restored" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='restored' and r['technique']=='manifest_invalid')")"

say "5. a listed file is deleted"
rm -f "$CTL_BIN"
wait_for 60 "any(r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_missing' for r in rows)"
check "delete: binary_missing" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_missing' and r['target']=='$CTL_BIN')")"
install -m 0755 "$W/ctl.orig" "$CTL_BIN"

say "6. restart from the replaced binary: the install verifies"
stop
BEFORE=$(count "max([r['seq'] for r in rows] or [0])")
start
sleep 16
check "restart: no new violated tamper record" 0 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['seq']>$BEFORE)")"
check "restart: integrity provider active" active "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"

say "7. restart with a manifest signed by a key this endpoint does not pin"
stop
sign_manifest "$W/stranger.key" "$W/build-manifest"
BEFORE=$(count "max([r['seq'] for r in rows] or [0])")
start
sleep 16
check "stranger manifest: reported at once, as unknown_key" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='manifest_invalid' and 'unknown_key' in r['detail'] and r['seq']>$BEFORE)")"
check "stranger manifest: health degraded" degraded "$(count "[r['status'] for r in rows if r['kind']=='health'][-1]")"
stop

dump | python3 -c "import sys, json
for line in sys.stdin:
    row = json.loads(line)
    if row['kind'] == 'tamper': print(json.dumps(row['record']))" >"$W/tamper.ndjson"
say "tamper records written to $W/tamper.ndjson: $(wc -l <"$W/tamper.ndjson")"
say "passed $PASSED, failed $FAILED"
[ "$FAILED" = 0 ]
