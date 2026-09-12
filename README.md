# Panopticon Linux Agent

Linux endpoint telemetry and constrained response executor for Panopticon. This is a
separate C++20 component: it shares versioned contracts with, but never imports, the
Windows Officer source tree.

## Current status

The previous Rust core is a discontinued prototype following the language re-evaluation in
[ADR 003](docs/adr/003-linux-agent-cpp-toolchain.md). It is not an implemented Linux agent
and must not be packaged, deployed, or extended. The C++20 rebaseline has not started.

No Linux collectors, spool/delivery path, Manager enrollment/command protocol, response
handler, eBPF program, or systemd deployment is currently implemented or claimed.

## Development

The C++ build and test instructions will be added with the rebaseline. Use a Linux systemd
host for runtime validation; no VM validation is currently claimed.
