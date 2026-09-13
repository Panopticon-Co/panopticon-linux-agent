#!/usr/bin/env bash
# Runs the ADR 004 netlink spike inside an unprivileged, throwaway network
# namespace, so it never touches the real host firewall and needs no real
# root/sudo -- only unprivileged user namespaces, which CI (and any modern
# Linux) already supports.
set -euo pipefail

SPIKE_BINARY="${1:?usage: run_isolation_namespace_spike.sh <path-to-isolation-namespace-spike>}"

if [ ! -x "${SPIKE_BINARY}" ]; then
    echo "spike binary not found or not executable: ${SPIKE_BINARY}" >&2
    exit 1
fi

exec unshare --user --map-root-user --net -- "${SPIKE_BINARY}"
