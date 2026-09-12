# Cross-repository impact

| Repository | Required change | Status |
| --- | --- | --- |
| panopticon-agent | Schema 0.4 adds the additive `linux_procfs` source kind while preserving Windows kinds | Implemented; Linux agent canonical serialization still required |
| panopticon-manager | Enrollment, authenticated Linux identity, durable retry semantics, and typed command/result endpoints | Dependency; not invented here |
| panopticon-detection-engine | Consume existing event contract | No change |
| panopticon-diagrams | Add Linux diagrams only as implementations land | Pending |

Linux does not duplicate the canonical schema. The current 0.3 schema permits only Windows
source kinds (`etw`, `sysmon`, and `windows_event_log`), so it cannot validate Linux telemetry
unchanged. The agent retains internal normalized events until a shared additive extension and
cross-repository contract fixtures are reviewed.
