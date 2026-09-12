use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    KillProcess,
    CollectProcessInfo,
    CollectNetworkConnections,
    CollectFile,
    QuarantineFile,
    IsolateHost,
    ReleaseHostIsolation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub command_id: String,
    pub request_id: String,
    pub host_id: String,
    pub agent_id: String,
    pub schema_version: String,
    pub action: Action,
    pub target: serde_json::Value,
    pub expires_at_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Code {
    Succeeded,
    InvalidCommand,
    UnsupportedAction,
    Expired,
    ReplayDetected,
    TargetNotFound,
    TargetMismatch,
    TargetProtected,
    PolicyDenied,
    PermissionDenied,
    ResourceLimit,
    ExecutionFailed,
    AlreadyCompleted,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultReceipt {
    pub command_id: String,
    pub request_id: String,
    pub action: Action,
    pub code: Code,
    pub summary: String,
    pub evidence: serde_json::Value,
}

pub trait ActionHandler: Send {
    fn execute(&mut self, command: &Command) -> ResultReceipt;
}
pub struct Registry {
    handlers: HashMap<String, Box<dyn ActionHandler>>,
    completed: HashMap<String, ResultReceipt>,
    seen: HashSet<String>,
    pub host_id: String,
    pub agent_id: String,
}
impl Registry {
    pub fn new(host_id: String, agent_id: String) -> Self {
        Self {
            handlers: HashMap::new(),
            completed: HashMap::new(),
            seen: HashSet::new(),
            host_id,
            agent_id,
        }
    }
    pub fn register(&mut self, action: Action, handler: Box<dyn ActionHandler>) {
        self.handlers.insert(key(&action), handler);
    }
    pub fn dispatch(&mut self, command: Command) -> ResultReceipt {
        if let Some(previous) = self.completed.get(&command.command_id) {
            return previous.clone();
        }
        if command.schema_version != "1"
            || command.host_id != self.host_id
            || command.agent_id != self.agent_id
            || command.command_id.is_empty()
        {
            return receipt(
                &command,
                Code::InvalidCommand,
                "command target or schema is invalid",
            );
        }
        if now() > command.expires_at_unix {
            return receipt(&command, Code::Expired, "command expired");
        }
        if !self.seen.insert(command.command_id.clone()) {
            return receipt(
                &command,
                Code::ReplayDetected,
                "duplicate command in progress",
            );
        }
        let result = match self.handlers.get_mut(&key(&command.action)) {
            Some(handler) => handler.execute(&command),
            None => receipt(&command, Code::UnsupportedAction, "action is not enabled"),
        };
        self.completed
            .insert(command.command_id.clone(), result.clone());
        result
    }
}
fn key(a: &Action) -> String {
    format!("{a:?}")
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn receipt(c: &Command, code: Code, summary: &str) -> ResultReceipt {
    ResultReceipt {
        command_id: c.command_id.clone(),
        request_id: c.request_id.clone(),
        action: c.action.clone(),
        code,
        summary: summary.into(),
        evidence: serde_json::json!({}),
    }
}

/// A safe kill handler must be wired to a Linux inspector that verifies entity-id + start
/// time immediately before signalling. It never receives a shell string.
pub trait ProcessControl {
    fn matches(&self, pid: u32, entity_id: &str) -> bool;
    fn protected(&self, pid: u32) -> bool;
    fn terminate(&mut self, pid: u32) -> Result<(), String>;
}
pub struct KillProcessHandler<C: ProcessControl>(pub C);
impl<C: ProcessControl + Send> ActionHandler for KillProcessHandler<C> {
    fn execute(&mut self, c: &Command) -> ResultReceipt {
        let pid = c
            .target
            .get("pid")
            .and_then(|v| v.as_u64())
            .filter(|p| *p <= u32::MAX as u64)
            .map(|p| p as u32);
        let entity = c.target.get("entity_id").and_then(|v| v.as_str());
        match (pid, entity) {
            (Some(pid), Some(_entity)) if self.0.protected(pid) => {
                receipt(c, Code::TargetProtected, "protected process")
            }
            (Some(pid), Some(entity)) if !self.0.matches(pid, entity) => {
                receipt(c, Code::TargetMismatch, "PID no longer matches entity")
            }
            (Some(pid), Some(_)) => match self.0.terminate(pid) {
                Ok(()) => receipt(c, Code::Succeeded, "process terminated"),
                Err(_) => receipt(c, Code::ExecutionFailed, "termination failed"),
            },
            _ => receipt(c, Code::InvalidCommand, "pid and entity_id are required"),
        }
    }
}
