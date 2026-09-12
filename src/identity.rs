use sha2::{Digest, Sha256};

/// Stable only for one boot/process instance: host + PID + observed start time.
pub fn process_entity_id(host_id: &str, pid: u32, start_time_ticks: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(host_id.as_bytes());
    hash.update(b"\0");
    hash.update(pid.to_le_bytes());
    hash.update(start_time_ticks.to_le_bytes());
    format!("proc_{:x}", hash.finalize())
}

pub fn event_id(canonical_json: &[u8]) -> String {
    format!("evt_{:x}", Sha256::digest(canonical_json))
}
