# Panopticon Linux Agent

Linux endpoint telemetry and constrained response executor for Panopticon. This is a
separate Rust component: it emits the existing Panopticon Schema 0.3 event contract and
never imports the Windows Officer source tree.

## Current implementation

- Deterministic PID-reuse-safe process entity IDs (`host_id + pid + start time`).
- Schema-shaped process telemetry types and collector interfaces.
- Bounded priority queue: security telemetry evicts lower-priority work; acquisition never
  waits on delivery.
- Atomic, quota-bounded NDJSON segment spool with acknowledged deletion only.
- Closed response registry with no shell, script, binary, or arbitrary-command action.
- Command target/schema/host/agent/expiry validation, in-memory idempotency, and safe
  process-kill validation through a platform `ProcessControl` interface.

The real Linux procfs/inotify/journald collectors, mTLS enrollment, Manager command
endpoint, persistent command replay store, quarantine, and firewall isolation are not yet
implemented. They are intentionally not represented as live capabilities.

## Development

```bash
cargo fmt --check
cargo test
```

Use a Linux systemd host for runtime validation. See `docs/VM_VALIDATION_GAPS.md`; no VM
validation is claimed by this repository.
