# Panopticon Linux Agent

Linux endpoint telemetry collector and constrained response executor for the
[Panopticon](https://github.com/Panopticon-Co) EDR/XDR capstone platform.

This is a capstone/research security project, not a commercial product. It is a separate C++20
component: it shares versioned wire contracts with, but never imports source from, the Windows
"Officer" agent ([panopticon-agent](https://github.com/Panopticon-Co/panopticon-agent)).

## Status

Actively developed capstone project. The agent has a working C++20 core -- not scaffolding -- but
several areas are explicitly unvalidated; see [Limitations](#limitations) below and
[docs/VM_VALIDATION_GAPS.md](docs/VM_VALIDATION_GAPS.md) for exactly what is CI-proven versus
what still requires a VM.

## Where this sits in the pipeline

```text
Linux adapters -> internal normalized event -> bounded queue -> durable spool -> transport
Response Engine -> authenticated typed command -> gate -> closed action handler -> receipt/audit
```

This agent is an endpoint executor, not a detection or authorization engine. It reports telemetry
upstream and executes only commands the Manager's Response Engine has already authorized. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full data-flow description.

It integrates with:

- [panopticon-manager](https://github.com/Panopticon-Co/panopticon-manager) -- enrollment, typed
  command dispatch, result/audit APIs (the agent's only upstream service).
- [panopticon-detection-engine](https://github.com/Panopticon-Co/panopticon-detection-engine) --
  consumes the shared Panopticon event contract; no direct integration with this agent.
- [panopticon-contracts](https://github.com/Panopticon-Co/panopticon-contracts) -- canonical
  JSON-schema wire contracts (schema versions, command/result envelopes) shared across repos.
- [panopticon-agent](https://github.com/Panopticon-Co/panopticon-agent) -- the Windows sibling
  agent ("Officer"); shares the response-action contract, has no shared source.

## Key capabilities

- Bounded, priority-ordered internal event queue with an atomic, quota-bounded durable spool
  (corruption recovery on restart).
- Strict configuration parsing (unknown/duplicate keys are errors).
- PID/start-time process identity (`host_id`, `pid`, `start_time_ticks`) to defeat PID-reuse
  targeting.
- procfs-based process, TCP/UDP (IPv4/IPv6), and host-context collectors.
- Canonical schema-0.4 process event serialization and HTTPS delivery to the Manager
  (`transport.hpp`), with peer/hostname verification, bearer auth, timeouts, and bounded
  responses.
- Durable enrolled identity and command replay-protection state that survives restart.
- Bounded audit and health records.
- Safe file collection (root-jailed, symlink-rejecting, size-bounded, hash-only) and quarantine
  (root-jailed atomic move).
- All 7 actions in Panopticon's closed response-command set are dispatched to a real, bounded
  implementation: `KILL_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`,
  `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`. See
  [RESPONSE.md](RESPONSE.md).
- `KILL_PROCESS` re-observes the exact PID/start-time tuple via procfs immediately before
  signaling, so a recycled PID from a different process is never targeted.
- `ISOLATE_HOST` / `RELEASE_HOST_ISOLATION` run across a privilege boundary: the main agent never
  holds `CAP_NET_ADMIN`. It sends a fixed 2-opcode request over an `AF_UNIX SOCK_SEQPACKET`
  socket to a separate, minimal privileged helper (`panopticon-isolation-helper`) that applies a
  fixed nftables ruleset via direct netlink (`libmnl`/`libnftnl`) -- never a shell or the `nft`
  CLI. See [ADR 004](docs/adr/004-host-isolation-privilege-boundary.md).

Not yet implemented: an eBPF telemetry adapter, a file-integrity watcher, and VM-based runtime
validation. `COLLECT_PROCESS_INFO` and `COLLECT_NETWORK_CONNECTIONS` are supported response
commands; whether every detection rule automatically triggers them in production is a
detection-engine-side concern this repo cannot verify.

## Repository structure

```text
include/panopticon/   Public headers for the core library
src/                   Core library sources + agent/isolation-helper entry points
tests/                 CTest unit suite + shell-driven e2e suites (tests/e2e/)
systemd/               Unit files for the agent and the isolation helper
docs/                  ADRs, cross-repo impact notes, VM validation gap notes
docs/adr/              Architecture decision records
```

Top-level docs: [ARCHITECTURE.md](ARCHITECTURE.md), [BUILD.md](BUILD.md),
[CONFIGURATION.md](CONFIGURATION.md), [TELEMETRY.md](TELEMETRY.md), [RESPONSE.md](RESPONSE.md),
[TESTING.md](TESTING.md), [SECURITY.md](SECURITY.md).

## Supported platforms

Linux only. Non-Linux platform adapters explicitly report "unsupported" rather than pretending to
have host visibility. Development and CI target Ubuntu 24.04; there is no distro-compatibility
matrix beyond that.

## Dependencies

- CMake 3.20+, Ninja, a C++20 compiler (CI uses GCC on Ubuntu 24.04; Clang is used for the
  sanitizer build).
- `libcurl` (optional at configure time; enables HTTPS transport to the Manager -- without it the
  agent still builds but cannot deliver telemetry or poll commands).
- `libmnl` and `libnftnl` (required to build `panopticon-isolation-helper` and the isolation
  test/spike executables; the main agent and core library do not depend on them).

## Build and test

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Sanitizer build (Clang, Linux only):

```bash
cmake -S . -B build-sanitized -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DPANOPTICON_ENABLE_ASAN=ON -DPANOPTICON_ENABLE_UBSAN=ON
cmake --build build-sanitized --parallel
ctest --test-dir build-sanitized --output-on-failure
```

A portable (e.g. non-Linux) build is not a validation of procfs, systemd, permissions, or network
behavior -- see [BUILD.md](BUILD.md) and [TESTING.md](TESTING.md) for full detail, and
[docs/VM_VALIDATION_GAPS.md](docs/VM_VALIDATION_GAPS.md) for what CI does and does not prove for
the isolation feature.

## Configuration

The agent reads a strict, line-based configuration file (unknown/duplicate keys are rejected).
Required keys: `manager_url` (`https://`), `agent_id`, `host_id`, `queue_capacity`,
`spool_quota_bytes`, `maximum_event_bytes`, `maximum_batch_bytes`, `response_enabled`. Optional
keys enable enrollment/transport, durable spooling, file collection/quarantine root jails, and
host isolation (`isolation_socket_path`). See [CONFIGURATION.md](CONFIGURATION.md) for the full
list and defaults-when-unset behavior.

## Privilege and capability requirements

- The main agent (`panopticon-linux-agent`) runs unprivileged and holds no special capabilities;
  see `systemd/panopticon-linux-agent.service`.
- Host isolation requires the separate `panopticon-isolation-helper` process, which runs as
  `root` with `CapabilityBoundingSet=CAP_NET_ADMIN` only (no other capability, no shell, no `nft`
  CLI) -- see `systemd/panopticon-isolation-helper.service` and
  [ADR 004](docs/adr/004-host-isolation-privilege-boundary.md). Leaving `isolation_socket_path`
  unset in the agent's configuration makes both isolation actions fail closed
  (`execution_failed`) instead of silently no-opping.

## Security considerations

- No shell execution API, command string, `system`, `popen`, or arbitrary executable dispatcher
  exists anywhere in the codebase. Commands use a closed `action_type` enum and are rejected
  unless schema, agent/host binding, expiry, and replay state all pass a local gate. PID 1 is
  always protected from `KILL_PROCESS`.
- `KILL_PROCESS` and `COLLECT_PROCESS_INFO` re-verify the PID/start-time identity tuple against a
  fresh procfs read immediately before acting, closing the PID-reuse race.
- The durable spool uses atomic publish and a non-cryptographic checksum to detect *accidental*
  corruption; it does not claim tamper evidence. Production-grade integrity/authentication awaits
  an approved credential and protocol design.
- Sanitizer builds (ASan/UBSan) are required test tooling, not a production control.
- See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Limitations

- No eBPF telemetry adapter and no file-integrity watcher yet.
- No VM-based runtime validation is currently claimed; see
  [docs/VM_VALIDATION_GAPS.md](docs/VM_VALIDATION_GAPS.md) for what CI's network-namespace-based
  isolation tests do and do not prove versus a real VM/NIC.
- One isolation robustness e2e scenario ("restart while isolation state exists") has an
  undiagnosed, intermittent CI flake unrelated to isolation-ruleset correctness -- see
  [TESTING.md](TESTING.md).
- No standing schema-0.4 event type for network connections yet; `COLLECT_NETWORK_CONNECTIONS`
  data is only produced on demand as a response action, not as ambient telemetry.
- Cross-repository dependencies (Manager enrollment/typed-command APIs, contract fixtures) are
  tracked in [docs/CROSS_REPO_IMPACT.md](docs/CROSS_REPO_IMPACT.md); this repo does not duplicate
  that status here.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build/test/branch/PR expectations.

## Security reporting

See [SECURITY.md](SECURITY.md). Please do not open public issues for suspected vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).

## Project

Part of [Panopticon-Co](https://github.com/Panopticon-Co), an EDR/XDR capstone project.
