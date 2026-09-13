#!/usr/bin/env bash
# Priority 5 (post-integration adversarial directive): real, non-loopback
# PACKET-LEVEL verification that ISOLATE_HOST actually blocks traffic and
# RELEASE_HOST_ISOLATION actually restores it -- the existing
# run_isolation_e2e.sh only proves the IPC/state-file round-trip, never
# whether a single packet was actually accepted or dropped, on loopback or
# otherwise.
#
# Topology (three real Linux network namespaces connected by two veth
# pairs, each side with its own non-loopback IPv4 address -- this is a
# genuine network boundary, not shared loopback):
#
#   pan-manager (10.250.0.2) --veth--- pan-agent (10.250.0.1 / 10.250.1.1) ---veth--- pan-peer (10.250.1.2)
#
# pan-manager and pan-peer each run a plain TCP listener. pan-agent runs the
# real panopticon-isolation-helper pinned to pan-manager's address/port.
# Verifies: pre-isolation both listeners are reachable; after ISOLATE_HOST
# only the pinned Manager listener remains reachable and the peer listener
# is not; after RELEASE_HOST_ISOLATION the peer listener is reachable again.
# Also verifies idempotent isolate/release do not disturb this.
#
# Requires real root (creating/naming multiple network namespaces and
# moving veth ends between them is not achievable with the unprivileged
# user-namespace trick the loopback-only scripts use). Run inside a
# disposable container or CI runner, never on a host whose real network
# state matters.
#
# What this still cannot prove without a real second physical/VM host: a
# genuine production topology where the isolated host's only path to
# anything is a real NIC shared with other real traffic, SSH break-glass
# expectations under a real operator's login, and multi-NIC/routing-table
# edge cases. See docs/VM_VALIDATION_GAPS.md for that remaining, genuinely
# environment-blocked scope.
set -euo pipefail

HELPER_BINARY="${1:?usage: run_isolation_packet_verification_e2e.sh <helper-binary> <client-tool-binary>}"
CLIENT_BINARY="${2:?usage: run_isolation_packet_verification_e2e.sh <helper-binary> <client-tool-binary>}"

if [ "$(id -u)" -ne 0 ]; then
    echo "this script needs real root (multi-namespace veth wiring); re-run as root or via sudo" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
SOCKET_PATH="${WORKDIR}/isolation.sock"
STATE_PATH="${WORKDIR}/isolation.state"

MANAGER_IP=10.250.0.2
AGENT_MGR_IP=10.250.0.1
AGENT_PEER_IP=10.250.1.1
PEER_IP=10.250.1.2
MANAGER_PORT=8443
PEER_PORT=9000

cleanup() {
    local status=$?
    if [ "${status}" -ne 0 ]; then
        echo "--- diagnostic: actual nftables ruleset in pan-agent at failure time ---" >&2
        ip netns exec pan-agent nft list ruleset >&2 2>&1 || true
        if [ -f "${WORKDIR}/helper.log" ]; then
            echo "--- diagnostic: helper log ---" >&2
            cat "${WORKDIR}/helper.log" >&2 || true
        fi
    fi
    kill "${HELPER_PID:-0}" 2>/dev/null || true
    ip netns pids pan-manager 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids pan-peer 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete pan-agent 2>/dev/null || true
    ip netns delete pan-manager 2>/dev/null || true
    ip netns delete pan-peer 2>/dev/null || true
    rm -rf "${WORKDIR}"
    exit "${status}"
}
trap cleanup EXIT

for ns in pan-agent pan-manager pan-peer; do
    ip netns delete "${ns}" 2>/dev/null || true
    ip netns add "${ns}"
    ip netns exec "${ns}" ip link set lo up
done

ip link add veth-agent-mgr netns pan-agent type veth peer name veth-mgr-agent netns pan-manager
ip link add veth-agent-peer netns pan-agent type veth peer name veth-peer-agent netns pan-peer

ip netns exec pan-agent ip addr add ${AGENT_MGR_IP}/30 dev veth-agent-mgr
ip netns exec pan-agent ip link set veth-agent-mgr up
ip netns exec pan-manager ip addr add ${MANAGER_IP}/30 dev veth-mgr-agent
ip netns exec pan-manager ip link set veth-mgr-agent up

ip netns exec pan-agent ip addr add ${AGENT_PEER_IP}/30 dev veth-agent-peer
ip netns exec pan-agent ip link set veth-agent-peer up
ip netns exec pan-peer ip addr add ${PEER_IP}/30 dev veth-peer-agent
ip netns exec pan-peer ip link set veth-peer-agent up

# Plain TCP listeners standing in for "the real Manager" and "an unrelated
# non-Manager peer host" -- netcat-openbsd's -k keeps accepting repeated
# probe connections for the whole script's lifetime.
ip netns exec pan-manager nc -lk "${MANAGER_PORT}" >/dev/null 2>&1 &
ip netns exec pan-peer nc -lk "${PEER_PORT}" >/dev/null 2>&1 &
sleep 0.3

reachable() {
    # $1=ns $2=ip $3=port
    ip netns exec "$1" bash -c "timeout 2 bash -c '</dev/tcp/$2/$3'" >/dev/null 2>&1
}

echo "--- pre-isolation: both the manager and the peer must be reachable ---"
reachable pan-agent "${MANAGER_IP}" "${MANAGER_PORT}" || { echo "FAIL: manager unreachable before isolation"; exit 1; }
reachable pan-agent "${PEER_IP}" "${PEER_PORT}" || { echo "FAIL: peer unreachable before isolation (test setup is broken)"; exit 1; }

ip netns exec pan-agent "${HELPER_BINARY}" "${SOCKET_PATH}" "${STATE_PATH}" "${MANAGER_IP}" "${MANAGER_PORT}" "$(id -un)" \
    > "${WORKDIR}/helper.log" 2>&1 &
HELPER_PID=$!
for _ in $(seq 1 50); do
    [ -S "${SOCKET_PATH}" ] && break
    sleep 0.1
done
[ -S "${SOCKET_PATH}" ] || { echo "FAIL: helper socket never appeared"; exit 1; }

echo "--- isolate ---"
ip netns exec pan-agent timeout 10s "${CLIENT_BINARY}" "${SOCKET_PATH}" isolate cmd-pv-1

echo "--- post-isolation: manager must remain reachable ---"
reachable pan-agent "${MANAGER_IP}" "${MANAGER_PORT}" || { echo "FAIL: manager became unreachable during isolation -- pinned exception is broken"; exit 1; }

echo "--- post-isolation: the non-Manager peer must NOT be reachable ---"
if reachable pan-agent "${PEER_IP}" "${PEER_PORT}"; then
    echo "FAIL: non-Manager peer is still reachable during isolation -- containment is not real"
    exit 1
fi

echo "--- idempotent re-isolate must not change the above ---"
ip netns exec pan-agent timeout 10s "${CLIENT_BINARY}" "${SOCKET_PATH}" isolate cmd-pv-2
reachable pan-agent "${MANAGER_IP}" "${MANAGER_PORT}" || { echo "FAIL: manager unreachable after idempotent re-isolate"; exit 1; }
if reachable pan-agent "${PEER_IP}" "${PEER_PORT}"; then
    echo "FAIL: peer became reachable after idempotent re-isolate"
    exit 1
fi

echo "--- release ---"
ip netns exec pan-agent timeout 10s "${CLIENT_BINARY}" "${SOCKET_PATH}" release cmd-pv-3

echo "--- post-release: connectivity to the peer must be restored ---"
reachable pan-agent "${PEER_IP}" "${PEER_PORT}" || { echo "FAIL: peer still unreachable after release"; exit 1; }
reachable pan-agent "${MANAGER_IP}" "${MANAGER_PORT}" || { echo "FAIL: manager unreachable after release"; exit 1; }

echo "--- idempotent re-release must not change the above ---"
ip netns exec pan-agent timeout 10s "${CLIENT_BINARY}" "${SOCKET_PATH}" release cmd-pv-4
reachable pan-agent "${PEER_IP}" "${PEER_PORT}" || { echo "FAIL: peer unreachable after idempotent re-release"; exit 1; }

echo "real non-loopback packet-level isolation/release verification succeeded"
