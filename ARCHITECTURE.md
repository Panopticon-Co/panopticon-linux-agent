# Architecture

The Linux Agent is an endpoint executor, not a detection or authorization engine.

```text
Linux adapters -> internal normalized event -> bounded queue -> durable spool -> transport
Response Engine -> authenticated typed command -> gate -> closed action handler -> receipt/audit
```

The queue, spool, typed command gate, procfs/network collectors, enrollment, TLS transport, and
5 of the 7 closed response actions (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
`COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`) exist today; `ISOLATE_HOST` and
`RELEASE_HOST_ISOLATION` do not (see RESPONSE.md). Collection is separated from normalization and
transport: no collector knows a Manager HTTP protocol. The Manager's ingest contract now accepts
an additive schema-0.4 Linux source kind alongside Windows's 0.1-0.3 (see
`docs/LINUX_TELEMETRY_SCHEMA_0_4.md` in panopticon-manager). See `docs/CROSS_REPO_IMPACT.md`.
