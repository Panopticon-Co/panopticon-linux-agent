use serde::{Deserialize, Serialize};

/// Internal normalized telemetry draft.
///
/// This is deliberately not advertised as schema-0.3-compatible. The current canonical
/// schema is owned by the Windows Officer and permits only Windows source kinds. The Linux
/// extension must be approved and added to the shared contract before this type is serialized
/// onto the Manager ingest path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LinuxTelemetryEvent {
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
    fn poll(&mut self) -> Result<Vec<LinuxTelemetryEvent>, String>;
}
pub trait NetworkCollector: Send {
    fn poll(&mut self) -> Result<Vec<LinuxTelemetryEvent>, String>;
}
pub trait FileCollector: Send {
    fn poll(&mut self) -> Result<Vec<LinuxTelemetryEvent>, String>;
}
