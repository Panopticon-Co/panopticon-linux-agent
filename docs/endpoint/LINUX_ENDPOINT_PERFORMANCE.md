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
| 2026-10-06 | S1 (uncommitted tree, release build) | Ubuntu 22.04 VM, 5.15.0-91, 2 vCPU, ext4 | Idle 20 s, `--stdout` to file | 85 ms CPU total (≈0.4 % of one core, mostly the startup procfs scan); 5 MB RSS |
| 2026-10-06 | S1, first version | same | `stress-ng --fork 4`, 4 s, CNPROC + procfs | 0 losses, all fork/exec/exit captured, seq contiguous; ≈480 µs CPU per event; 22 MB RSS |
| 2026-10-06 | S1, after queue batching + JSON fast path | same | same | 0 losses; ≈168 µs CPU per event |
| 2026-10-06 | S1, after netlink drain pause (5 ms) | same | same | 0 losses; 107–125 µs CPU per event (includes startup and ≈2.5 KB of JSON per event written to ext4); 17.8 MB RSS |

S1 notes: CPU per event is measured from the sensor's own `health` record (`getrusage`)
divided by emitted records; `/usr/bin/time` was not installed in the VM. The remaining
hotspots are the output write, `poll`, JSON string escaping and the `open` of
`/proc/<pid>/stat` on every fork. Exec latency overhead and kernel→WAL p99 latency are not
measured yet; they need the eBPF provider (S2) and are scheduled for S11. Record size can
shrink (an exit does not need the full parent object).
