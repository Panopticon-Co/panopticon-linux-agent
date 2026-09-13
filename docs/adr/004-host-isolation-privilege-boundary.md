# ADR 004: Host isolation via a separate privileged helper process

**Status:** Accepted
**Date:** 2026-09-13

## Context

`ISOLATE_HOST` and `RELEASE_HOST_ISOLATION` are the last two of the closed
7-action response set with no implementation. Isolating a real host requires
reprogramming the kernel firewall, which requires `CAP_NET_ADMIN` somewhere.
The main agent process runs unprivileged today (dedicated `panopticon` system
user, `systemd` sandboxing -- see `systemd/panopticon-linux-agent.service`),
and every other response action (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`) only ever
needs privileges the agent's own user already has.

## Decision

A second, minimal privileged process (`panopticon-isolation-helper`) holds
`CAP_NET_ADMIN` and nothing else. The main agent process never gains this
capability. The two processes communicate over a fixed, closed 2-opcode local
IPC; the helper applies/removes a single fixed nftables ruleset via direct
netlink calls (`libmnl` + `libnftnl`) and never shells out to `nft` or any
other executable.

This mirrors the closed-typed-action idiom already used throughout this
codebase (the 7-action command enum, the protected-PID set, the replay
ledger): the isolation opcode set is closed and fixed, never a free-form
command.

### Why a helper process, not `CAP_NET_ADMIN` on the main agent

Granting `CAP_NET_ADMIN` to the single agent process would put the capability
to reprogram the host firewall in the same process as JSON command parsing,
file-path handling, and every future action handler. A memory-safety or
logic bug anywhere in that process would then be one step from firewall
control. A separate helper confines that capability to a few hundred lines
of auditable code with an IPC surface of exactly two verbs and no untrusted
input reaching it beyond a `command_id` string.

### Mechanism: netlink via libmnl/libnftnl, never the `nft` CLI

The whole-repository prohibition on `system()`/`popen()`/`exec*`/shell
execution applies to the helper too. `libnftnl` (built on `libmnl`) is the
same library the `nft` binary itself uses to construct and apply
`NFT_MSG_*` netlink messages -- using it directly gives the same
capability with a typed, in-process API and no subprocess, no shell, and no
externally-injectable command string.

New build-time dependency: `libmnl-dev`, `libnftnl-dev` (apt), added to
both `.github/workflows/ci.yml` jobs. This is the repository's first
non-libcurl external dependency.

### IPC: `AF_UNIX SOCK_SEQPACKET`, 2 fixed opcodes

- Socket path `/run/panopticon-agent/isolation.sock`, permissions `0660`,
  shared group between the two `systemd` units.
- Exactly two fixed-width request frames: `ISOLATE(command_id)` and
  `RELEASE(command_id)`. No free-form string, IP address, or rule content
  ever crosses the wire -- there is nothing in the protocol an attacker
  could inject a rule through.
- The helper authenticates the peer with `SO_PEERCRED` against the
  configured agent UID, in addition to socket-file permissions (defense in
  depth, not the sole control).
- Response is a single fixed-width status byte (`ok` / `rejected`); the
  helper never returns rule content, error strings from netlink, or
  anything else an attacker-controlled agent process could use to probe
  the ruleset it cannot otherwise see.

### Ruleset: fixed, never dynamically constructed from command content

Both `ISOLATE_HOST` and `RELEASE_HOST_ISOLATION` already carry an empty
target in the Manager's schema (`manager/routers/commands.py`) -- there is
no per-command data to feed into a ruleset even if we wanted to. The
helper's ruleset is entirely compiled in:

- One table/chain, default-drop policy when isolated.
- Static exceptions: loopback, and the Manager's `host:port` (both
  directions), resolved once and pinned at helper startup (never
  re-resolved during isolation, so a DNS outage cannot bypass isolation by
  re-resolving to an attacker address, nor can it extend an isolation
  window by failing closed on release). **Deliberately no
  `ESTABLISHED`/`RELATED` conntrack exception**: exempting all established
  connections would also keep an attacker's already-established connection
  flowing straight through "isolation," which directly contradicts the
  locked no-SSH-break-glass decision. Every connection except the pinned
  Manager channel and loopback is dropped, established or not.
- **No SSH break-glass exception.** Recovery is `RELEASE_HOST_ISOLATION`
  from the Manager, or local/console access to the host -- not a standing
  network hole in the isolation itself. (Locked decision.)
- **No automatic release / TTL.** Isolation does not silently expire.
  (Locked decision.)

### State: durable, idempotent, fail-closed

A local state file (`/var/lib/panopticon-agent/isolation.state`, `0600`)
records `{isolated, applied_at, command_id, revision}`, written before and
after every operation. On helper start (including after a crash), the
helper re-applies whatever state it last recorded -- a crash never silently
un-isolates a host. Both `ISOLATE` and `RELEASE` are idempotent: issuing
either while already in the target state is a no-op success, so a retried
command from the agent (e.g. after a lost result-submission) cannot double
-apply or race the ruleset.

### Deployment

A new `systemd/panopticon-isolation-helper.service` unit, separate from the
main agent's: `CapabilityBoundingSet=CAP_NET_ADMIN`,
`AmbientCapabilities=CAP_NET_ADMIN`, `NoNewPrivileges=true`,
`ProtectSystem=strict`, no filesystem write access beyond the one state
file and its directory.

## Alternatives considered

- **`CAP_NET_ADMIN` on the main agent process.** Rejected: raises the blast
  radius of every other, unrelated command handler to include firewall
  control (see above).
- **Shelling out to `nft`/`iptables`.** Rejected outright by the
  whole-repository no-shell-execution invariant; also reintroduces exactly
  the "command string reaches an external program" pattern the closed
  action set exists to prevent.
- **`iptables` via `libiptc`.** `libiptc` is unstable/unofficial API and
  `iptables`-legacy is being phased out in favor of `nftables` on the
  distributions this agent targets; `libnftnl`/`libmnl` is the maintained,
  documented path.
- **A generic "run this privileged operation" IPC.** Rejected: this is
  exactly the arbitrary-command-execution shape the entire response-action
  design is built to avoid. The IPC is two fixed opcodes, full stop.

## Consequences

- The helper is a new, small, independently auditable binary and `systemd`
  unit, not a library linked into the main agent.
- `libmnl`/`libnftnl` become required build dependencies for any target
  that builds the helper; the main agent binary and its tests remain
  unaffected and continue to build without them if the helper target is
  excluded from a given build.
- Host isolation cannot be un-stuck by an SSH session into the isolated
  host by design; recovery is `RELEASE_HOST_ISOLATION` via the Manager or
  local/console access. This is a deliberate containment-over-convenience
  trade-off per the locked decision.
- A de-risking spike (namespace-based netlink test, see
  `tests/e2e/isolation_namespace_spike.sh`) validates the netlink
  ruleset-apply/tear-down mechanics in CI using `unshare -rn` before the
  helper is wired into the live command-dispatch path, so the one part of
  this design unlike anything already in the codebase is proven
  independently first.

## Revisit triggers

If a future phase needs per-connection or per-IP blocking (e.g. mapping
`BLOCK_FIREWALL_IP` to something finer-grained than whole-host isolation),
that is a new action requiring its own ADR, security review, and expansion
of the closed action set -- not a silent extension of this ruleset's fixed
shape.
