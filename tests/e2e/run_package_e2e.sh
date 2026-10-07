#!/usr/bin/env bash
# Real-VM end-to-end test of the signed package path: signed apt repository, install, upgrade, a corrupted package,
# a repository signed by the wrong key, an unsigned repository, downgrade and rollback, and tampering with an
# installed file (ADR 033, docs/endpoint/LINUX_ENDPOINT_SECURITY_MODEL.md T12, T14).
#
# usage: sudo [BUILD=/path/to/build-dir] tests/e2e/run_package_e2e.sh
#
# DISPOSABLE VM ONLY. It installs and purges the panopticon-sensord package, starts its systemd service, and adds
# (then removes) an apt source and a keyring. It refuses to run if the package is installed or a sensor is running.
# Needs: dpkg-deb, cpack, apt-ftparchive, gpg, systemd, and a build tree with panopticon-sensord, panopticon-ctl and
# panopticon-command-signer. The apt lists and cache it uses are private (under $W), not the system's.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
B=${BUILD:-$ROOT/build-rel}
SIGNER=$B/panopticon-command-signer
W=${PACKAGE_DIR:-/var/tmp/package-e2e}
WAL=/var/lib/panopticon/wal
V1=0.9.1
V2=0.9.2
V3=0.9.3
KEYRING=/usr/share/keyrings/panopticon-e2e.gpg
FAILED=0
PASSED=0

say() { printf '[package] %s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then PASSED=$((PASSED + 1)); say "PASS $1 ($3)"; else FAILED=$((FAILED + 1)); say "FAIL $1: expected '$2', got '$3'"; fi
}
check_match() { # name regex text
  if printf '%s' "$3" | grep -Eiq "$2"; then PASSED=$((PASSED + 1)); say "PASS $1"; else FAILED=$((FAILED + 1)); say "FAIL $1: no match for /$2/ in: $(printf '%s' "$3" | tail -n 5 | tr '\n' '|')"; fi
}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for tool in dpkg-deb cpack apt-ftparchive gpg systemctl apt-get; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done
[ -x "$SIGNER" ] || { echo "missing $SIGNER" >&2; exit 2; }
if dpkg -s panopticon-sensord >/dev/null 2>&1; then echo "panopticon-sensord is already installed; this test is for a disposable VM" >&2; exit 2; fi
if pgrep -x panopticon-sens >/dev/null; then echo "a panopticon sensor is running; this test would disturb it" >&2; exit 2; fi
. "$ROOT/tests/e2e/wal_helpers.sh"

rm -rf "$W"; mkdir -p "$W/debs" "$W/lists/partial" "$W/cache/archives/partial" "$W/gnupg" "$W/gnupg-rogue"
chmod 755 "$W"; chmod 700 "$W/gnupg" "$W/gnupg-rogue"
echo "deb [signed-by=$KEYRING] file:$W/repo stable main" >"$W/sources.list"
chmod 644 "$W/sources.list"

apt() { # apt-get restricted to this test's repository and private state
  apt-get -y -o Dir::Etc::sourcelist="$W/sources.list" -o Dir::Etc::sourceparts=/dev/null -o Dir::State::lists="$W/lists" \
    -o Dir::Cache::archives="$W/cache/archives" -o APT::Get::List-Cleanup=0 "$@" 2>&1
}
cleanup() {
  apt-get -y purge panopticon-sensord >/dev/null 2>&1
  rm -f "$KEYRING"
  return 0
}
trap cleanup EXIT

say "setup: keys, packages $V1 $V2 $V3, signed repository"
"$SIGNER" keygen "$W/release.key" >/dev/null || exit 2
gen_gpg() { GNUPGHOME=$1 gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "$2 <$3@panopticon.invalid>" rsa3072 sign never >/dev/null 2>&1; }
gen_gpg "$W/gnupg" "Panopticon E2E Release" release || { echo "gpg key generation failed" >&2; exit 2; }
gen_gpg "$W/gnupg-rogue" "Rogue" rogue || { echo "gpg key generation failed" >&2; exit 2; }
KEYID=$(GNUPGHOME=$W/gnupg gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
ROGUEID=$(GNUPGHOME=$W/gnupg-rogue gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
GNUPGHOME=$W/gnupg gpg --export >"$KEYRING"; chmod 644 "$KEYRING"
for v in $V1 $V2 $V3; do
  DEB_VERSION=$v SOURCE_DATE_EPOCH=$(date +%s) bash "$ROOT/packaging/build_signed_deb.sh" "$B" "$W/release.key" "$W/debs" >/dev/null || { echo "cannot build $v" >&2; exit 2; }
done
ls "$W"/debs/*.deb | sed 's/^/[package]   /'
repo() { # <gnupg home> <key id> <deb>...
  local home=$1 key=$2; shift 2
  rm -rf "$W/repo"
  bash "$ROOT/packaging/build_apt_repo.sh" "$W/repo" "$home" "$key" "$@" >/dev/null || return 1
  chmod -R a+rX "$W/repo"
}
deb_of() { ls "$W"/debs/panopticon-sensord_"$1"_*.deb; }
installed() { dpkg-query -W -f='${Version}' panopticon-sensord 2>/dev/null; }
wait_active() { for _ in $(seq 1 30); do systemctl is-active --quiet panopticon-sensord && return 0; sleep 1; done; return 1; }

say "1. install $V1 from the signed repository"
repo "$W/gnupg" "$KEYID" "$(deb_of $V1)" || exit 2
OUT=$(apt update); check_match "update: the signed repository is accepted" "Get:|Hit:|Reading package lists" "$OUT"
OUT=$(apt install panopticon-sensord="$V1")
check "install: version" "$V1" "$(installed)"
check_match "install: the config enables integrity" "^integrity_manifest=/usr/share/panopticon/build-manifest" "$(cat /etc/panopticon/sensord.conf)"
check "install: the manifest ships" 1 "$(test -s /usr/share/panopticon/build-manifest && echo 1 || echo 0)"
echo "integrity_check_seconds=5" >>/etc/panopticon/sensord.conf
systemctl restart panopticon-sensord
wait_active; check "install: the service is active" active "$(systemctl is-active panopticon-sensord)"
wait_for 90 "any(r['kind']=='health' and r['integrity'] and r['integrity']['state']=='active' for r in rows)"
check "install: the integrity provider is active" active "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"
check "install: no tamper record" 0 "$(count "sum(1 for r in rows if r['kind']=='tamper')")"

say "2. upgrade to $V2: the replaced files must not look like tampering"
repo "$W/gnupg" "$KEYID" "$(deb_of $V1)" "$(deb_of $V2)" || exit 2
apt update >/dev/null
BEFORE=$(count "max([r['seq'] for r in rows] or [0])")
OUT=$(apt install --only-upgrade panopticon-sensord)
check "upgrade: version" "$V2" "$(installed)"
wait_active; sleep 20
check "upgrade: the service is active" active "$(systemctl is-active panopticon-sensord)"
check "upgrade: no violated record after the upgrade" 0 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['seq']>$BEFORE)")"
check "upgrade: the integrity provider is active" active "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"

say "3. a package changed in the repository after it was signed"
repo "$W/gnupg" "$KEYID" "$(deb_of $V1)" "$(deb_of $V2)" "$(deb_of $V3)" || exit 2
apt update >/dev/null
printf 'x' >>"$W/repo/pool/$(basename "$(deb_of $V3)")"
OUT=$(apt install panopticon-sensord="$V3"); RC=$?
check "corrupt: the install is refused" 1 "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
check_match "corrupt: apt names the mismatch" "unexpected size|Hash Sum mismatch|mismatch" "$OUT"
check "corrupt: the installed version is unchanged" "$V2" "$(installed)"

say "4. a repository signed by a key apt was not told to trust, and one that is not signed at all"
repo "$W/gnupg-rogue" "$ROGUEID" "$(deb_of $V1)" "$(deb_of $V2)" "$(deb_of $V3)" || exit 2
OUT=$(apt update); RC=$?
check_match "rogue key: update rejects the repository" "NO_PUBKEY|not signed|invalid|EXPKEYSIG|BADSIG|Release.*signed" "$OUT"
rm -f "$W/repo/dists/stable/InRelease" "$W/repo/dists/stable/Release.gpg"
OUT=$(apt update)
check_match "unsigned: update rejects the repository" "not signed|no longer signed|Release" "$OUT"
OUT=$(apt install panopticon-sensord="$V3"); RC=$?
check "rogue/unsigned: nothing is installed from it" "$V2" "$(installed)"

say "5. downgrade is refused, a deliberate rollback to $V1 works"
repo "$W/gnupg" "$KEYID" "$(deb_of $V1)" "$(deb_of $V2)" "$(deb_of $V3)" || exit 2
apt update >/dev/null
OUT=$(apt install panopticon-sensord="$V1"); RC=$?
check "downgrade: refused without the explicit flag" 1 "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
check "downgrade: still $V2" "$V2" "$(installed)"
BEFORE=$(count "max([r['seq'] for r in rows] or [0])")
OUT=$(apt install --allow-downgrades panopticon-sensord="$V1")
check "rollback: version" "$V1" "$(installed)"
wait_active; sleep 20
check "rollback: the service is active" active "$(systemctl is-active panopticon-sensord)"
wait_for 60 "any(r['kind']=='tamper' and r['status']=='violated' and r['technique']=='manifest_rollback' and r['seq']>$BEFORE for r in rows)"
check "rollback: reported as manifest_rollback (ADR 036)" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='manifest_rollback' and r['seq']>$BEFORE)")"
check "rollback: nothing else is reported as violated" 0 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']!='manifest_rollback' and r['seq']>$BEFORE)")"
check "rollback: the integrity provider says so" degraded "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"
# An intended downgrade is acknowledged by deleting the state file and restarting (the mark is read at start).
rm -f "$WAL.integrity"
systemctl restart panopticon-sensord
wait_active; sleep 20
check "rollback acknowledged: the service is active" active "$(systemctl is-active panopticon-sensord)"
check "rollback acknowledged: the integrity provider is active" active "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"

say "6. an installed file is edited on the running system"
cp /usr/bin/panopticon-ctl "$W/ctl.orig"
bash -c "echo \$\$ >$W/tamperer.pid; echo tampered >>/usr/bin/panopticon-ctl"
TAMPERER=$(cat "$W/tamperer.pid")
wait_for 60 "any(r['kind']=='tamper' and r['status']=='violated' and r['target']=='/usr/bin/panopticon-ctl' for r in rows)"
check "tamper: binary_modified on panopticon-ctl" 1 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['technique']=='binary_modified' and r['target']=='/usr/bin/panopticon-ctl')")"
check "tamper: attributed to the writer" "$TAMPERER" "$(count "[r['process']['pid'] for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['target']=='/usr/bin/panopticon-ctl'][0]")"
check "tamper: dpkg --verify agrees" 1 "$(dpkg --verify panopticon-sensord 2>&1 | grep -q panopticon-ctl && echo 1 || echo 0)"
BEFORE=$(count "max([r['seq'] for r in rows] or [0])")
OUT=$(apt install --reinstall panopticon-sensord="$V1")
wait_active; sleep 20
check "repair: reinstall restores the file" "$(sha256sum <"$W/ctl.orig" | cut -d' ' -f1)" "$(sha256sum </usr/bin/panopticon-ctl | cut -d' ' -f1)"
check "repair: no violated record after the reinstall" 0 "$(count "sum(1 for r in rows if r['kind']=='tamper' and r['status']=='violated' and r['seq']>$BEFORE)")"
check "repair: the integrity provider is active" active "$(count "[r['integrity']['state'] for r in rows if r['kind']=='health' and r['integrity']][-1]")"

dump | python3 -c "import sys, json
for line in sys.stdin:
    row = json.loads(line)
    if row['kind'] == 'tamper': print(json.dumps(row['record']))" >"$W/tamper.ndjson"
say "tamper records written to $W/tamper.ndjson: $(wc -l <"$W/tamper.ndjson")"
say "passed $PASSED, failed $FAILED"
[ "$FAILED" = 0 ]
