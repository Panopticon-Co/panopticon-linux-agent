# ADR 002: Use Rust for the Linux agent

**Status:** Superseded by ADR 003
**Date:** 2026-09-12

## Context

Panopticon's existing Windows Officer is a C++20 application. That is an
important operational precedent, but it is not a portable endpoint framework:
its collection and delivery layers directly use ETW, Sysmon event-log APIs,
Windows CNG, and WinHTTP. The repositories share JSON/NDJSON contracts with
the Manager, not a C++ ABI, common library, or build system.

The Linux agent must collect process, file, and network telemetry through
Linux-native mechanisms; run reliably as a `systemd` service; deliver records
over HTTPS; and eventually receive authenticated, typed response commands.
The command path is particularly sensitive: it accepts remote data, validates
replay/target/expiry information, then may act on processes, files, or network
state across a privilege boundary. It must never become a shell-command
transport.

Initial collection does not require eBPF. Procfs, netlink, inotify/journald
or audit integrations, and eBPF are implementation choices behind collector
interfaces. eBPF will be introduced only after its event, kernel-version, and
operational advantages are demonstrated for a specific collector.

## Decision

Build the Linux agent in stable Rust (edition 2024), with Cargo as its primary
build and dependency-management contract. Keep Linux system interaction and
any unsafe/FFI code in small, independently testable adapters. Keep eBPF
optional: a future collector may use a Rust eBPF library or a narrow binding to
libbpf, without changing the telemetry pipeline or response contract.

This is a language decision for the new Linux agent only. It neither rewrites
the Windows Officer nor changes the Manager's wire contracts.

## Alternatives considered

| Requirement | Modern C++ | Rust | Decision basis |
| --- | --- | --- | --- |
| Linux APIs and `systemd` | Excellent access to libc, netlink, inotify, audit, and systemd libraries. | Equivalent access through safe wrappers plus explicit FFI where needed. | Neither language blocks native Linux integration. |
| eBPF | libbpf's C API is the reference ecosystem and is mature. | Viable Rust ecosystems exist, but some features may lag libbpf. | Do not make eBPF a foundation dependency; permit a narrow libbpf binding if it proves necessary. |
| Process, network, and file telemetry | High performance and direct kernel API access. | High performance for this I/O-bound workload with ownership-safe buffers and handles. | Collection design and kernel API choice matter more than language. |
| Privileged response execution | RAII and modern library types help, but parsing, paths, file descriptors, and lifetime errors remain discipline-dependent. | Ownership, bounds checks, and typed deserialization reduce memory-corruption exposure at the untrusted-command boundary. | Rust has a material security advantage for newly written privileged code. |
| HTTPS and signed messages | Mature libraries, but careful ownership and parser hardening are required. | Mature TLS/HTTP and serialization ecosystem; `Result`-based error handling fits fail-closed validation. | Rust reduces implementation risk without inventing a new protocol. |
| Performance and resource use | Maximum control and excellent predictable performance. | Comparable performance for the planned bounded queues, NDJSON, procfs/netlink I/O, and HTTP delivery. | No demonstrated hot path requires C++. Benchmark before optimizing or adding eBPF. |
| Maintainability and team familiarity | Matches the Windows Officer's language and existing CMake/vcpkg knowledge. | Adds a language to the team, but isolates Linux concerns and makes ownership/error paths explicit. | C++ familiarity is real, but there is no shared source to preserve; clear Rust conventions and review gates offset onboarding cost. |
| Build and deployment | CMake/vcpkg can work, but Linux dependency and cross-build matrices must be maintained. | Cargo produces a reproducible dependency lockfile and straightforward x86_64/aarch64 build matrix. | Rust is simpler for a self-contained new service; native eBPF artifacts remain a separate deployment concern in either language. |
| Testing | Sanitizers, fuzzers, static analysis, and unit tests are capable but require consistent use. | Unit/property tests, clippy, formatting, and memory safety are available by default; FFI still needs sanitizer/integration coverage. | Rust improves the secure default, not a substitute for tests. |
| Panopticon interoperability | Would not reuse Officer source because its APIs are Windows-specific. | Uses the same versioned JSON/NDJSON contract with no ABI coupling. | Both interoperate equally; contract tests, not language, protect compatibility. |

## Consequences

- The agent keeps its own repository and has no source-level dependency on the
  Windows Officer. Cross-agent compatibility is enforced with canonical schema
  fixtures and Manager ingest tests.
- Rust does not authorize a new Manager protocol. Until Manager exposes
  enrollment, authentication, command signing, acknowledgements, and result
  endpoints, those operations remain explicit interfaces and local test
  doubles rather than claimed live features.
- All direct syscall, capability, eBPF, and C-library bindings must be narrow
  and documented. Unsafe Rust is prohibited outside those adapters and must
  receive targeted tests/review.
- Linux CI is required for platform adapters. Portable logic can be tested on
  developer machines, but a Windows build is not evidence that Linux telemetry
  or privilege behavior works. x86_64 is the first supported target; aarch64
  is added through CI and VM validation before support is claimed.
- C++ remains a permitted exception for a small, isolated helper when a
  validated libbpf/kernel integration cannot be delivered safely in Rust. Any
  such exception requires a follow-up ADR with the API boundary, ownership
  rules, packaging impact, and fallback behavior.

## Revisit triggers

This ADR was superseded after the team clarified that it has strong C/C++
experience and essentially no Rust experience. See ADR 003 for the current
decision and its required C++ security controls.
