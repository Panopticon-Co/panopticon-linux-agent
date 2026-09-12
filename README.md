# Panopticon Linux Agent

Linux endpoint telemetry and constrained response executor for Panopticon. This is a
separate C++20 component: it shares versioned contracts with, but never imports, the
Windows Officer source tree.

## Current status

The agent has a C++20 core with a bounded, thread-safe priority queue; atomic quota-bounded
spool segments with accidental-corruption detection/recovery; a typed command gate; and a
Linux procfs process-snapshot adapter. The procfs adapter reports unsupported rather than
pretending to have host visibility on non-Linux systems.

The previous Rust core is discontinued by [ADR 003](docs/adr/003-linux-agent-cpp-toolchain.md).
The current core is not enrolled and must not be deployed as a production endpoint.

There is no approved Linux telemetry schema, Manager enrollment/authentication protocol,
command endpoint, TLS client, eBPF program, file watcher, isolation implementation, or
privileged helper. Those capabilities are intentionally disabled rather than simulated.

## Development

See [BUILD.md](BUILD.md) and [TESTING.md](TESTING.md). Use a Linux systemd host for runtime
validation; no VM validation is currently claimed.
