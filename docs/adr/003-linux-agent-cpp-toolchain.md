# ADR 003: Use modern C++ for the Linux agent

**Status:** Accepted
**Date:** 2026-09-12
**Supersedes:** ADR 002

## Context

Panopticon's team has strong C/C++ expertise and essentially no Rust production
experience. The Windows Officer is C++20, uses CMake/CTest and a vcpkg manifest,
and has separable core, collector, and delivery targets. Its Windows-specific
source is not reusable on Linux, but shared language knowledge, debugging habits,
review standards, CI conventions, and the ability to move engineers between
endpoint agents are material long-term ownership benefits.

The Linux agent needs procfs/netlink/inotify and `systemd` integration, HTTPS,
durable telemetry delivery, constrained privileged responses, and potentially
eBPF. libbpf is a C library with a documented BPF object lifecycle and CO-RE
support; using it directly avoids making a less familiar Rust abstraction a
critical dependency. Rust's memory-safety model is valuable, especially for the
remote-command boundary, but it does not remove the need to learn a new build,
debugging, dependency, and operational ecosystem.

## Decision

Implement the Linux agent in portable modern C++20, using CMake, CTest, and a
locked dependency manifest aligned with the Windows Officer's engineering
model. Use direct Linux APIs and libbpf when eBPF is justified by a specific
collector. Keep the shared boundary at versioned JSON/NDJSON contracts, not a
shared binary or platform abstraction.

The existing Rust foundation is a discontinued prototype, not a supported
implementation. No further Rust feature work may proceed; the repository is
rebaselined to C++ before collector, delivery, or response features are added.

## Alternatives considered

### Rust

- **Pros:** Memory-safe defaults, strong typed serialization, and Cargo's
  cohesive build experience reduce several classes of endpoint implementation
  defects.
- **Cons:** No current team expertise means slower incident debugging, weaker
  code review, added hiring/onboarding cost, and a second endpoint toolchain.
  eBPF would either introduce a less familiar Rust ecosystem or return to a
  libbpf FFI boundary anyway.
- **Why not:** For this team and an agent expected to be maintained alongside a
  C++ Windows Officer, the ownership and integration risk is greater than the
  incremental safety benefit of a wholesale language change.

### Modern C++20 with explicit hardening

- **Pros:** Matches team capability and the Officer's language/toolchain;
  provides direct access to Linux and libbpf C APIs; enables common code-review,
  CMake, CTest, packaging, symbolization, and incident-response practices.
  It has no meaningful performance disadvantage for I/O-bound telemetry and
  offers predictable native deployment.
- **Cons:** Does not prevent memory-safety errors by construction. CMake and
  native dependency packaging require discipline; eBPF still requires clang,
  BTF/CO-RE compatibility testing, and kernel capability handling.
- **Why chosen:** It is the strongest current delivery and ownership choice
  when paired with mandatory security engineering controls below.

## Required controls and consequences

- Compile as C++20 with warnings treated as errors and a narrowly approved
  dependency set. Prefer RAII, value types, `std::span`, `std::string_view`,
  `std::expected`-style error handling (or a project equivalent), and explicit
  ownership. Ban raw owning pointers, unchecked C string manipulation, shell
  execution, and ad-hoc command parsing.
- Parse every remote command into a versioned typed model; authenticate before
  dispatch; validate signature, replay, host/agent target, expiry, and action
  parameters; dispatch only an allowlist. Response handlers must use Linux APIs,
  never a shell or arbitrary executable path.
- Put process/file/network privilege operations behind small interfaces. The
  supervisor and any privileged helper must have a documented privilege and
  capability boundary; `systemd` hardening and least privilege are release
  requirements.
- Use Clang AddressSanitizer, UndefinedBehaviorSanitizer, and libFuzzer in
  Linux CI for parser, NDJSON, spool, and command-handler inputs. Run static
  analysis and dependency/license checks; sanitizer builds are test artifacts,
  not production packaging.
- Treat libbpf as an optional collector adapter, not the telemetry architecture.
  Build BPF objects with clang, use CO-RE where applicable, and provide
  documented fallback/disable behavior for unsupported kernels, permissions, or
  BTF availability.
- CMake/CTest remain the common cross-agent build vocabulary. Linux packaging
  must pin native dependency versions and ship or declare the BPF object and
  libbpf requirements explicitly. A successful Windows Officer build is not
  Linux validation; Linux x86_64 VM/CI validation is mandatory before support
  is claimed.
- The common event schema still requires an additive Linux source extension
  before live Manager ingest. Language consistency does not replace contract
  tests.

## Revisit triggers

Revisit if measured C++ implementation risk persists despite the controls,
if the team deliberately invests in Rust training and operating experience, or
if a future shared endpoint SDK changes the source-sharing economics.
