# Architecture

The Linux Agent is an endpoint executor, not a detection or authorization engine.

```text
Linux adapters -> internal normalized event -> bounded queue -> durable spool -> transport
Response Engine -> authenticated typed command -> gate -> closed action handler -> receipt/audit
```

Only the queue, spool, typed command gate, and procfs snapshot adapter exist today. Collection
is separated from normalization and transport: no collector knows a Manager HTTP protocol.
The Manager's current ingest contract accepts Windows-only source kinds, so Linux records remain
internal until an additive contract change is approved. See `docs/CROSS_REPO_IMPACT.md`.
