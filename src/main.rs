use panopticon_linux_agent::{config::Config, spool::SegmentSpool};
fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/panopticon-agent/config.toml".into());
    let config: Config = match std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
    {
        Some(c) => c,
        None => {
            eprintln!("configuration unavailable or invalid: {config_path}");
            return;
        }
    };
    if let Err(e) = config.validate() {
        eprintln!("configuration rejected: {e}");
        return;
    }
    let _spool = SegmentSpool::open("/var/lib/panopticon-agent/spool", config.spool_quota_bytes)
        .expect("spool directory unavailable");
    eprintln!(
        "panopticon-linux-agent core initialized; collectors and transport run under the Linux service"
    );
}
