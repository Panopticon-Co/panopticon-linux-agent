# Architecture

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
