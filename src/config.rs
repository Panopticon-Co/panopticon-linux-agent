use serde::Deserialize;
#[derive(Debug, Deserialize)]
pub struct Config {
    pub manager_url: String,
    pub queue_capacity: usize,
    pub spool_quota_bytes: u64,
    #[serde(default)]
    pub enable_response: bool,
}
impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.manager_url.starts_with("https://") {
            return Err("manager_url must use https");
        }
        if self.queue_capacity == 0 || self.spool_quota_bytes == 0 {
            return Err("queue and spool quota must be positive");
        }
        Ok(())
    }
}
