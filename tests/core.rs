use panopticon_linux_agent::{
    identity::process_entity_id,
    queue::{BoundedPriorityQueue, Priority},
    response::*,
};
use serde_json::json;
struct Fake {
    matched: bool,
    killed: usize,
}
impl ProcessControl for Fake {
    fn matches(&self, _: u32, _: &str) -> bool {
        self.matched
    }
    fn protected(&self, p: u32) -> bool {
        p == 1
    }
    fn terminate(&mut self, _: u32) -> Result<(), String> {
        self.killed += 1;
        Ok(())
    }
}
fn command() -> Command {
    Command {
        command_id: "c1".into(),
        request_id: "r1".into(),
        host_id: "h".into(),
        agent_id: "a".into(),
        schema_version: "1".into(),
        action: Action::KillProcess,
        target: json!({"pid":42,"entity_id":"proc-x"}),
        expires_at_unix: u64::MAX,
    }
}
#[test]
fn identity_is_pid_reuse_safe() {
    assert_ne!(process_entity_id("h", 1, 1), process_entity_id("h", 1, 2));
}
#[test]
fn security_priority_evicts_low() {
    let mut q = BoundedPriorityQueue::new(1).unwrap();
    assert!(q.push(Priority::Low, 1));
    assert!(q.push(Priority::Security, 2));
    assert_eq!(q.pop(), Some(2));
    assert_eq!(q.dropped, 1);
}
#[test]
fn command_is_idempotent() {
    let mut r = Registry::new("h".into(), "a".into());
    r.register(
        Action::KillProcess,
        Box::new(KillProcessHandler(Fake {
            matched: true,
            killed: 0,
        })),
    );
    assert_eq!(r.dispatch(command()).code, Code::Succeeded);
    assert_eq!(r.dispatch(command()).code, Code::Succeeded);
}
#[test]
fn pid_one_is_never_killed() {
    let mut r = Registry::new("h".into(), "a".into());
    r.register(
        Action::KillProcess,
        Box::new(KillProcessHandler(Fake {
            matched: true,
            killed: 0,
        })),
    );
    let mut c = command();
    c.target = json!({"pid":1,"entity_id":"proc-init"});
    assert_eq!(r.dispatch(c).code, Code::TargetProtected);
}
#[test]
fn wrong_host_is_rejected() {
    let mut r = Registry::new("h".into(), "a".into());
    let mut c = command();
    c.host_id = "other".into();
    assert_eq!(r.dispatch(c).code, Code::InvalidCommand);
}
