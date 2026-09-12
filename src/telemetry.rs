use serde::{Deserialize, Serialize};

/// Minimal, schema-0.3-compatible process event shape. The canonical JSON schema remains
/// owned by panopticon-agent/schema/event.schema.json; contract CI validates this output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PanopticonEvent {
    pub schema_version: String,
    pub event: EventMeta,
    pub source: Source,
    pub agent: Agent,
    pub host: Host,
    pub process: Process,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventMeta {
    pub id: String,
    pub category: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Source {
    pub kind: String,
    pub provider: String,
    pub channel: String,
    pub record_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Agent {
    pub id: String,
    pub version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub id: String,
    pub hostname: String,
    pub os: Os,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Os {
    pub name: String,
    pub build: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Process {
    pub entity_id: String,
    pub pid: u32,
    pub name: String,
    pub executable: String,
    pub command_line: String,
}

pub trait ProcessCollector: Send {
    fn poll(&mut self) -> Result<Vec<PanopticonEvent>, String>;
}
pub trait NetworkCollector: Send {
    fn poll(&mut self) -> Result<Vec<PanopticonEvent>, String>;
}
pub trait FileCollector: Send {
    fn poll(&mut self) -> Result<Vec<PanopticonEvent>, String>;
}
