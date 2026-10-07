#!/usr/bin/env bash
# Builds a signed apt repository from one or more panopticon-sensord .deb files.
#
# usage: packaging/build_apt_repo.sh <repo-dir> <gnupg-home> <gpg-key-id> <deb>...
#
# Layout (suite "stable", component "main", architecture amd64):
#   <repo-dir>/pool/*.deb
#   <repo-dir>/dists/stable/Release, Release.gpg, InRelease
#   <repo-dir>/dists/stable/main/binary-amd64/Packages(.gz)
#
# dpkg does not check a .deb's own signature. The signature that protects an install is the one over the
# repository's Release file, which carries the hash of Packages, which carries the hash of every .deb. apt refuses a
# repository whose Release is not signed by a key it is told to trust, and refuses a .deb whose hash differs.
# Pointing a host at it:
#   deb [signed-by=/usr/share/keyrings/panopticon.gpg] https://<repository> stable main
# Older versions stay in the pool, so a rollback is `apt-get install panopticon-sensord=<version> --allow-downgrades`.
# apt never downgrades without that flag.
set -euo pipefail

if [ "$#" -lt 4 ]; then
  sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2
  exit 2
fi
REPO=$(mkdir -p "$1" && cd "$1" && pwd)
export GNUPGHOME=$2
KEYID=$3
shift 3
for tool in apt-ftparchive gpg gzip; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done

mkdir -p "$REPO/pool" "$REPO/dists/stable/main/binary-amd64"
for deb in "$@"; do
  [ -f "$deb" ] || { echo "no such file: $deb" >&2; exit 2; }
  cp -- "$deb" "$REPO/pool/"
done

cd "$REPO"
apt-ftparchive packages pool >dists/stable/main/binary-amd64/Packages
gzip -9nkf dists/stable/main/binary-amd64/Packages
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=Panopticon \
  -o APT::FTPArchive::Release::Label=Panopticon \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures=amd64 \
  -o APT::FTPArchive::Release::Components=main \
  release dists/stable >dists/stable/Release
rm -f dists/stable/Release.gpg dists/stable/InRelease
gpg --batch --yes --local-user "$KEYID" -abs -o dists/stable/Release.gpg dists/stable/Release
gpg --batch --yes --local-user "$KEYID" --clearsign -o dists/stable/InRelease dists/stable/Release
echo "$REPO"
