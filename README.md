# Panopticon Linux Agent

Linux endpoint telemetry and constrained response executor for Panopticon. This is a
separate C++20 component: it shares versioned contracts with, but never imports, the
Windows Officer source tree.

## Current status

The agent has a C++20 core with a bounded priority queue; atomic quota-bounded spool segments
with corruption recovery; strict configuration; PID/start-time process identity; procfs process,
TCP/UDP IPv4/IPv6, and host-context collectors; canonical schema-0.4 process serialization;
durable enrolled identity and command replay state; bounded audit/health records; safe file
collection/quarantine; and a closed response foundation. Linux-only adapters report unsupported
rather than pretending to have host visibility on other platforms.

The previous Rust core is discontinued by [ADR 003](docs/adr/003-linux-agent-cpp-toolchain.md).
The Manager has additive enrollment, schema-0.4 Linux ingestion, typed command queue, and typed
result APIs. The agent provides a libcurl HTTPS client when libcurl is available, enforcing peer
and hostname verification, bearer authentication, timeouts, bounded responses, and spool ACK
semantics. A strict-configured executable can emit bounded canonical procfs snapshots.

Enrollment, transport, and the command poll/dispatch/result runtime loop are fully wired. All
7 actions in the closed response set are dispatched to a real bounded implementation
(`KILL_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`,
`QUARANTINE_FILE`, `ISOLATE_HOST`, `RELEASE_HOST_ISOLATION` -- see [RESPONSE.md](RESPONSE.md)).
`ISOLATE_HOST`/`RELEASE_HOST_ISOLATION` are implemented via a separate, minimal privileged
helper process (`panopticon-isolation-helper`) that holds `CAP_NET_ADMIN` so the main agent
never does; see [ADR 004](docs/adr/004-host-isolation-privilege-boundary.md). CI proves real,
non-loopback packet-level containment across network namespaces (not just IPC/state-file
mechanics) -- see [docs/VM_VALIDATION_GAPS.md](docs/VM_VALIDATION_GAPS.md) for exactly what is
CI-verified versus what still genuinely requires a VM. There is no eBPF adapter or file watcher
yet. These are not claimed as complete.

## Development

See [BUILD.md](BUILD.md) and [TESTING.md](TESTING.md). Use a Linux systemd host for runtime
validation; no VM validation is currently claimed.
