# Linux Endpoint Performance

Numbers here are **measured by us** on named hardware with named workloads. Vendor figures are
not copied. Each result records commit, environment and tool.

## 1. Budgets (targets)

| Metric | Target |
| --- | --- |
| Idle CPU | < 1 % of one core |
| CPU under normal workload | < 5 % of one core |
| RSS | < 150 MiB steady state |
| exec latency overhead | < 5 % on an exec-heavy micro-benchmark |
| File operation overhead | < 5 % on an open/close storm (no prevention) |
| Event latency kernel → WAL, p99 | < 250 ms |
| Host → Manager, p95 | < 5 s |
| Loss under normal workload | 0 |
| Startup to full coverage | < 5 s |

## 2. Workloads

| Workload | Tool | Purpose |
| --- | --- | --- |
| Idle | none, 10 min | baseline |
| Normal | parallel build of a medium project | realistic |
| Process churn | `stress-ng --exec`, `--fork` | lifecycle path |
| Fork flood (inside a cgroup with `pids.max`) | contained loop | flood behaviour |
| File storm | `stress-ng --dentry`, `--rename`, `--hdd` | file path |
| Network storm | `stress-ng --sock`, short TCP connections | network path |
| Container storm | short-lived containers | container enrichment |
| Disk pressure | WAL directory at quota | WAL policy |
| Memory pressure | `stress-ng --vm` | governor |
| Manager outage | Manager stopped N minutes | WAL growth and catch-up |

## 3. Results

| Date | Commit | Environment | Workload | Result |
| --- | --- | --- | --- | --- |
| – | – | – | – | No measurements yet; first run after the resident sensor lands. |
