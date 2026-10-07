#!/usr/bin/env bash
# Real end-to-end isolate -> verify -> release cycle against the actual
# helper binary and its real IPC client, inside a throwaway network
# namespace (see run_isolation_namespace_spike.sh for the privilege
# fallback rationale).
#
# What this proves: the helper daemon starts, resolves and pins the
# manager host once, applies the real ruleset on ISOLATE, stays reachable
# on loopback throughout (the agent's own IPC socket is a loopback-local
# AF_UNIX connection, so a helper bug that dropped loopback would make
# this whole script fail to talk to it at all), is idempotent, and
# RELEASE tears the ruleset back down. Full production-topology packet
# verification (a real Manager reachable over a real non-loopback
# interface, isolated hosts truly unable to reach anything else) is
# deferred to VMware validation -- see docs/VM_VALIDATION_GAPS.md.
set -euo pipefail

HELPER_BINARY="${1:?usage: run_isolation_e2e.sh <helper-binary> <client-tool-binary>}"
CLIENT_BINARY="${2:?usage: run_isolation_e2e.sh <helper-binary> <client-tool-binary>}"

WORKDIR="$(mktemp -d)"
SOCKET_PATH="${WORKDIR}/isolation.sock"
STATE_PATH="${WORKDIR}/isolation.state"
trap 'rm -rf "${WORKDIR}"' EXIT

run_inside_namespace() {
    if unshare --user --map-root-user --net -- true 2>/dev/null; then
        unshare --user --map-root-user --net -- "$@"
    else
        sudo unshare --net -- "$@"
    fi
}

run_inside_namespace bash -c "
    set -euo pipefail
    # Redirected to a file, not inherited from this step's own stdout/stderr:
    # a backgrounded process that keeps those pipes open (even after this
    # script and its EXIT trap have run) hangs the whole CI step waiting for
    # EOF on them, regardless of whether the kill below actually lands.
    '${HELPER_BINARY}' '${SOCKET_PATH}' '${STATE_PATH}' 127.0.0.1 443 \"\$(id -un)\" > '${WORKDIR}/helper.log' 2>&1 &
    HELPER_PID=\$!
    trap 'kill \${HELPER_PID} 2>/dev/null || true; cat \"${WORKDIR}/helper.log\" >&2 || true' EXIT
    for _ in \$(seq 1 50); do
        [ -S '${SOCKET_PATH}' ] && break
        sleep 0.1
    done
    [ -S '${SOCKET_PATH}' ] || { echo 'helper socket never appeared'; exit 1; }

    # Bounded independently of the isolation helper's own netlink receive
    # timeout: a client call must fail fast (seconds), never hang the whole
    # CI job for its full runner timeout, regardless of which side of the
    # IPC round-trip a future regression breaks.
    echo '--- isolate ---'
    timeout 10s '${CLIENT_BINARY}' '${SOCKET_PATH}' isolate cmd-e2e-1
    grep -qx isolated '${STATE_PATH}' || { echo 'state file does not record isolation'; exit 1; }

    echo '--- idempotent re-isolate ---'
    timeout 10s '${CLIENT_BINARY}' '${SOCKET_PATH}' isolate cmd-e2e-2

    echo '--- release ---'
    timeout 10s '${CLIENT_BINARY}' '${SOCKET_PATH}' release cmd-e2e-3
    if grep -qx isolated '${STATE_PATH}' 2>/dev/null; then
        echo 'state file still claims isolation after release'
        exit 1
    fi

    echo '--- idempotent re-release ---'
    timeout 10s '${CLIENT_BINARY}' '${SOCKET_PATH}' release cmd-e2e-4

    echo 'isolation e2e cycle succeeded'
"
