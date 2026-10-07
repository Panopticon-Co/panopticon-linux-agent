# Architecture

This repository builds two generations of Linux endpoint software. **`panopticon-sensord` is the current Linux
endpoint implementation**; the original foundation agent below it is still built, tested and used (its response
library and isolation helper are reused by `sensord`).

## Current implementation: `panopticon-sensord`

```text
kernel hooks and procfs -> providers -> bounded queue -> pipeline thread (entity graph, policy, serializer)
  -> WAL (CRC frames, fsync policy, quota) -> uplink (batches, ack cursor) -> Manager
Manager -> signed command (ES256) -> verify -> durable ledger -> executor -> durable result -> response.action record
```

The diagrams, the component table and the invariants (single pipeline thread, contiguous `seq`, no silent loss,
privilege separation, fail-safe policy/command handling) are in [README.md](README.md#2-architecture). The design
document is [docs/endpoint/LINUX_ENDPOINT_ARCHITECTURE.md](docs/endpoint/LINUX_ENDPOINT_ARCHITECTURE.md); it
describes the intended end state, so read it together with
[docs/endpoint/IMPLEMENTATION_STATUS.md](docs/endpoint/IMPLEMENTATION_STATUS.md), which records what exists and how
far each piece is verified. Decisions are in [docs/adr/](docs/adr/) (36 records).

Source map of the sensor (`src/sensor/`, headers in `include/panopticon/linux_agent/sensor/`):

| Area | Files | Role |
| --- | --- | --- |
| Providers | `ebpf_process.cpp`, `fanotify_file.cpp`, `sensitive_file.cpp`, `audit_netlink.cpp`, `kernel_change.cpp`, `netlink_proc.cpp`, `sockdiag_network.cpp`, `auth_log.cpp`, `host_state.cpp`, `persistence.cpp`, `fim.cpp` | Telemetry sources with primary and fallback tiers, health and re-attachment |
| Identity | `entity_graph.cpp`, `container_tracker.cpp`, `container_identity.cpp`, `process_info.cpp` | Boot-scoped process identity, PID-reuse handling, exec generations, container ids |
| Pipeline | `pipeline.cpp`, `serializer.cpp`, `state_diff.cpp`, `hash_service.cpp` | The single thread that enriches, applies policy, serializes, writes; the hash worker |
| Durability and delivery | `wal.cpp`, `uplink.cpp`, `uplink_https.cpp` | WAL, at-least-once delivery with an ack cursor |
| Policy | `policy.cpp`, `policy_bundle.cpp` (sweep of running processes is in `pipeline.cpp`) | Signed local policy; `policy.match` only, never actions |
| Command plane | `command_auth.cpp`, `command_channel.cpp`, `command_https.cpp`, `file_actions.cpp`; `src/response.cpp`, `src/isolation*.cpp`, `src/replay_ledger.cpp` | Signed command authentication, ledger, execution, audit; reused foundation response library |
| Integrity | `integrity.cpp` | Signed build manifest, running-image hash, rollback high-water mark |
| Operations | `control.cpp`, `systemd_notify.cpp`, `sensord_main.cpp`, `ctl_main.cpp` | Control socket, watchdog, entry points (`panopticon-sensord`, read-only `panopticon-ctl`) |

Cross-repository boundary: the record format is defined only in
[panopticon-contracts](https://github.com/Panopticon-Co/panopticon-contracts) (`schema/linux-endpoint/1.0.schema.json`)
and enforced on the Manager side by its vendored copy; nothing here imports another repository's code. See
[docs/CROSS_REPO_IMPACT.md](docs/CROSS_REPO_IMPACT.md).

## Foundation agent: `panopticon-linux-agent`

The Linux Agent is an endpoint executor, not a detection or authorization engine.

```text
Linux adapters -> internal normalized event -> bounded queue -> durable spool -> transport
Response Engine -> authenticated typed command -> gate -> closed action handler -> receipt/audit
```

The queue, spool, typed command gate, procfs/network collectors, enrollment, TLS transport, and
all 7 closed response actions (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`,
`RELEASE_HOST_ISOLATION`) exist today (see RESPONSE.md). `ISOLATE_HOST`/`RELEASE_HOST_ISOLATION`
are the only actions implemented across a privilege boundary: the main agent process sends a
fixed 2-opcode request over `AF_UNIX SOCK_SEQPACKET` to a separate, minimal privileged helper
(`panopticon-isolation-helper`) that alone holds `CAP_NET_ADMIN` and applies/removes a fixed
nftables ruleset via direct netlink (`libmnl`/`libnftnl`), never a shell or the `nft` CLI (see
ADR 004). This privileged-helper split exists only on Linux; it has no Windows-agent
counterpart. Collection is separated from normalization and transport: no collector knows a
Manager HTTP protocol. The Manager's ingest contract now accepts an additive schema-0.4 Linux
source kind alongside Windows's 0.1-0.3 (see `docs/LINUX_TELEMETRY_SCHEMA_0_4.md` in
panopticon-manager). See `docs/CROSS_REPO_IMPACT.md`.
