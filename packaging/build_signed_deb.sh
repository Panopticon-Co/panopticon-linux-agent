#!/usr/bin/env bash
# Builds the panopticon-sensord .deb and adds the signed build manifest of ADR 033 to it.
#
# usage: packaging/build_signed_deb.sh <build-dir> <release-key-file> <out-dir>
#
#   <build-dir>         a configured and built CMake tree that has panopticon-sensord, panopticon-ctl and
#                       panopticon-command-signer
#   <release-key-file>  the P-256 manifest signing key (panopticon-command-signer keygen); stays on the build host
#   <out-dir>           receives panopticon-sensord_<version>_<arch>.deb
#
# The package then carries
#   /usr/share/panopticon/build-manifest   SHA-256, size and install path of the sensor, panopticon-ctl and the unit file
#   /usr/share/panopticon/integrity.keys   the public key that verifies it
# and the postinst turns integrity checking on at first install. Set SOURCE_DATE_EPOCH for a repeatable built_at and
# DEB_VERSION to build a version other than the project's.
#
# What this protects: replacement of the installed files after install, by anything that does not also replace the
# key file. It does not protect against a malicious package; that is the job of the repository signature
# (packaging/build_apt_repo.sh). See docs/adr/033-signed-build-manifest-and-self-integrity.md.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2
  exit 2
fi
BUILD=$(cd "$1" && pwd)
KEY=$(readlink -f "$2")
OUT=$(mkdir -p "$3" && cd "$3" && pwd)
SIGNER=$BUILD/panopticon-command-signer
for f in "$SIGNER" "$BUILD/panopticon-sensord" "$BUILD/panopticon-ctl" "$KEY"; do
  [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done
# ADR 034: a package never carries the lab unsigned-command mode. The refusal message exists in the binary only when
# the option was compiled out.
grep -aq 'built without lab unsigned-command support' "$BUILD/panopticon-sensord" ||
  { echo "refusing to package $BUILD/panopticon-sensord: it was built with PANOPTICON_LAB_UNSIGNED_COMMANDS=ON (ADR 034)" >&2; exit 2; }
for tool in cpack dpkg-deb; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CPACK_ARGS=(-G DEB -B "$WORK/cpack")
# DEB_VERSION overrides the project version; the upgrade, tamper and rollback tests build several versions of one tree.
[ -z "${DEB_VERSION:-}" ] || CPACK_ARGS+=(-D "CPACK_PACKAGE_VERSION=$DEB_VERSION")
(cd "$BUILD" && cpack "${CPACK_ARGS[@]}" >"$WORK/cpack.log" 2>&1) || { cat "$WORK/cpack.log" >&2; exit 1; }
DEB=$(ls "$WORK"/cpack/panopticon-sensord_*.deb | head -n 1)
[ -f "$DEB" ] || { echo "cpack produced no panopticon-sensord .deb" >&2; exit 1; }

TREE=$WORK/tree
dpkg-deb -R "$DEB" "$TREE"
VERSION=$(sed -n 's/^Version: //p' "$TREE/DEBIAN/control")
BUILT_AT=${SOURCE_DATE_EPOCH:-$(date +%s)}

# Every file whose content decides what the sensor does. Order does not matter to the manifest; the paths are the
# paths the files have once installed.
FILES=(usr/bin/panopticon-sensord usr/bin/panopticon-ctl usr/lib/systemd/system/panopticon-sensord.service)
LIST=
for rel in "${FILES[@]}"; do
  [ -f "$TREE/$rel" ] || { echo "the package has no /$rel" >&2; exit 1; }
  LIST+="$TREE/$rel"$'\t'"/$rel"$'\n'
done

mkdir -p "$TREE/usr/share/panopticon"
printf '%s' "$LIST" | "$SIGNER" sign-manifest "$KEY" panopticon-sensord "$VERSION" "$BUILT_AT" >"$TREE/usr/share/panopticon/build-manifest"
"$SIGNER" pubkey "$KEY" >"$TREE/usr/share/panopticon/integrity.keys"
chmod 0644 "$TREE/usr/share/panopticon/build-manifest" "$TREE/usr/share/panopticon/integrity.keys"

# dpkg verifies installed files against md5sums; the two new files must be listed.
(cd "$TREE" && md5sum usr/share/panopticon/build-manifest usr/share/panopticon/integrity.keys >>DEBIAN/md5sums)

NAME=$(basename "$DEB")
dpkg-deb --root-owner-group -b "$TREE" "$OUT/$NAME" >/dev/null
echo "$OUT/$NAME"
echo "manifest: $(grep -c '^[0-9a-f]\{64\} ' "$TREE/usr/share/panopticon/build-manifest") files, key $("$SIGNER" keyid "$KEY"), version $VERSION" >&2
