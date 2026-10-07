#!/usr/bin/env bash
# Runs the ADR 004 netlink spike inside a throwaway network namespace, so it
# never touches the real host firewall.
#
# Prefers an unprivileged user+network namespace (no real root needed at
# all). Some hardened distributions (including GitHub-hosted ubuntu-24.04
# runners, via Ubuntu's AppArmor unprivileged-userns restriction) refuse
# CLONE_NEWUSER for a non-root caller -- in that case this falls back to
# `sudo unshare --net`, which still creates an isolated, empty network
# namespace (distinct from the real host's), just using ambient sudo
# instead of a user-namespace remap.
set -euo pipefail

SPIKE_BINARY="${1:?usage: run_isolation_namespace_spike.sh <path-to-isolation-namespace-spike>}"

if [ ! -x "${SPIKE_BINARY}" ]; then
    echo "spike binary not found or not executable: ${SPIKE_BINARY}" >&2
    exit 1
fi

if unshare --user --map-root-user --net -- true 2>/dev/null; then
    exec unshare --user --map-root-user --net -- "${SPIKE_BINARY}"
fi

echo "unprivileged user namespaces are restricted here; falling back to sudo unshare --net" >&2
exec sudo unshare --net -- "${SPIKE_BINARY}"
