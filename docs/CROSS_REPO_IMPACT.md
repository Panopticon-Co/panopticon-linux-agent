# Cross-repository impact

| Repository | Required change | Status |
| --- | --- | --- |
| panopticon-agent | Canonical Schema 0.3 remains the source of truth | No change |
| panopticon-manager | Enrollment, authenticated Linux identity, durable retry semantics, and typed command/result endpoints | Dependency; not invented here |
| panopticon-detection-engine | Consume existing event contract | No change |
| panopticon-diagrams | Add Linux diagrams only as implementations land | Pending |

Linux does not duplicate the canonical schema. Contract CI will validate emitted fixtures
against a checked-out `panopticon-agent/schema/event.schema.json`.
