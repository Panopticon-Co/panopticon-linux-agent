#!/usr/bin/env bash
# Robustness/security coverage for the isolation helper's IPC boundary and
# restart behavior that run_isolation_e2e.sh's happy-path cycle does not
# exercise: malformed IPC, oversized IPC, an unauthorized peer UID, and
# durable-state recovery across a helper restart (including releasing after
# that restart). See docs/adr/004-host-isolation-privilege-boundary.md.
#
# Real kernel network/nftables behavior against a non-loopback interface is
# still deferred to VMware validation -- this script only proves the IPC
# frame handling and local state-file recovery, which do not require it.
set -euo pipefail

HELPER_BINARY="${1:?usage: run_isolation_robustness_e2e.sh <helper-binary> <client-tool-binary> <raw-frame-tool-binary>}"
CLIENT_BINARY="${2:?usage: run_isolation_robustness_e2e.sh <helper-binary> <client-tool-binary> <raw-frame-tool-binary>}"
RAW_FRAME_BINARY="${3:?usage: run_isolation_robustness_e2e.sh <helper-binary> <client-tool-binary> <raw-frame-tool-binary>}"

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
    AGENT_USER=\"\$(id -un)\"

    start_helper() {
        '${HELPER_BINARY}' '${SOCKET_PATH}' '${STATE_PATH}' 127.0.0.1 443 \"\${AGENT_USER}\" >> '${WORKDIR}/helper.log' 2>&1 &
        echo \$!
    }
    wait_for_socket() {
        for _ in \$(seq 1 50); do
            [ -S '${SOCKET_PATH}' ] && return 0
            sleep 0.1
        done
        echo 'helper socket never appeared'; cat '${WORKDIR}/helper.log' >&2 || true; exit 1
    }

    HELPER_PID=\$(start_helper)
    trap 'kill \${HELPER_PID} 2>/dev/null || true; cat \"${WORKDIR}/helper.log\" >&2 || true' EXIT
    wait_for_socket

    echo '--- malformed IPC: wrong-size frame is rejected, not crashed ---'
    OUT=\$(timeout 10s '${RAW_FRAME_BINARY}' '${SOCKET_PATH}' 5 01)
    [ \"\${OUT}\" = 'rejected' ] || [ \"\${OUT}\" = 'no-response' ] || { echo \"expected rejection for a too-short frame, got: \${OUT}\"; exit 1; }
    kill -0 \${HELPER_PID} || { echo 'helper died handling a malformed frame'; exit 1; }

    echo '--- malformed IPC: invalid opcode at the exact frame size is rejected ---'
    OUT=\$(timeout 10s '${RAW_FRAME_BINARY}' '${SOCKET_PATH}' 129 ff)
    [ \"\${OUT}\" = 'rejected' ] || { echo \"expected rejection for an invalid opcode, got: \${OUT}\"; exit 1; }
    kill -0 \${HELPER_PID} || { echo 'helper died handling an invalid opcode'; exit 1; }

    echo '--- oversized IPC: an over-length frame is rejected, not truncated-and-accepted ---'
    OUT=\$(timeout 10s '${RAW_FRAME_BINARY}' '${SOCKET_PATH}' 4096 01)
    [ \"\${OUT}\" = 'rejected' ] || [ \"\${OUT}\" = 'no-response' ] || { echo \"expected rejection for an oversized frame, got: \${OUT}\"; exit 1; }
    kill -0 \${HELPER_PID} || { echo 'helper died handling an oversized frame'; exit 1; }
    if grep -qx isolated '${STATE_PATH}' 2>/dev/null; then
        echo 'an oversized/malformed frame must never cause a state change'
        exit 1
    fi

    echo '--- unauthorized peer: a different UID is rejected without a response ---'
    if id -u nobody >/dev/null 2>&1; then
        chmod o+rwx '${SOCKET_PATH}' 2>/dev/null || true
        OUT=\$(timeout 10s runuser -u nobody -- '${RAW_FRAME_BINARY}' '${SOCKET_PATH}' 129 01 2>/dev/null || echo 'no-response')
        [ \"\${OUT}\" = 'no-response' ] || { echo \"expected the unauthorized peer's connection to be silently closed, got: \${OUT}\"; exit 1; }
    else
        echo 'no unprivileged nobody user available in this environment -- skipping unauthorized-peer check'
    fi

    echo '--- isolate, then crash the helper (kill -9) ---'
    timeout 10s '${CLIENT_BINARY}' '${SOCKET_PATH}' isolate cmd-robustness-1
    grep -qx isolated '${STATE_PATH}' || { echo 'state file does not record isolation before crash'; exit 1; }
    kill -9 \${HELPER_PID}
    # HELPER_PID is not a direct child of this shell (it was backgrounded
    # inside start_helper()'s command-substitution subshell, so it was
    # reparented away as soon as that subshell exited) -- 'wait' cannot
    # block on it. Poll /proc instead of assuming SIGKILL has already been
    # fully reaped before the next line runs.
    for _ in \$(seq 1 50); do
        kill -0 \${HELPER_PID} 2>/dev/null || break
        sleep 0.1
    done
    # SIGKILL gives the helper no chance to unlink its own socket special
    # file, so it is still sitting on disk pointing at a dead listener.
    # wait_for_socket() below only checks '[ -S \$SOCKET_PATH ]', which that
    # stale file satisfies immediately -- racing ahead of the restarted
    # helper's own listening_socket() call, which (correctly, fail-closed)
    # only runs *after* it finishes re-applying isolation on startup. Without
    # removing the stale file first, a client can connect to the dead
    # listener and fail before the new helper is actually up; this was the
    # real, deterministic cause of this script's intermittent CI failures
    # ('isolation-client-tool: request failed' right after restart), not two
    # overlapping helper lifecycles as an earlier read of the doubled log
    # output (printed once by this failure branch's own 'cat' and again by
    # the EXIT trap's 'cat' of the same single log file) suggested.
    rm -f '${SOCKET_PATH}'

    echo '--- restart while isolation state exists: helper re-applies fail-closed ---'
    HELPER_PID=\$(start_helper)
    trap 'kill \${HELPER_PID} 2>/dev/null || true; cat \"${WORKDIR}/helper.log\" >&2 || true' EXIT
    wait_for_socket
    REAPPLIED=0
    for _ in \$(seq 1 20); do
        grep -q 're-applying isolation recorded before restart' '${WORKDIR}/helper.log' && { REAPPLIED=1; break; }
        sleep 0.1
    done
    [ \"\${REAPPLIED}\" = 1 ] || { echo 'restart did not log fail-closed re-apply'; cat '${WORKDIR}/helper.log' >&2; exit 1; }

    echo '--- release after restart: still tears the ruleset down and clears state ---'
    timeout 10s '${CLIENT_BINARY}' '${SOCKET_PATH}' release cmd-robustness-2 || { cat '${WORKDIR}/helper.log' >&2; exit 1; }
    if grep -qx isolated '${STATE_PATH}' 2>/dev/null; then
        echo 'state file still claims isolation after post-restart release'
        exit 1
    fi

    echo 'isolation robustness e2e suite succeeded'
"
