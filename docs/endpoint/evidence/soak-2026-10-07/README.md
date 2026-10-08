# 6-hour soak, 2026-10-07 — evidence and reading

**Result in one line:** the run completed all 6.00 hours with the sensor alive and exiting cleanly, no sequence gap
and no unexplained loss; eight of nine automated verdicts are clean and the ninth (health timer) reports `DRIFT`,
which coincides with other work done on the same VM and is absent in the final two unperturbed hours. It is **not**
a clean-room pass, and **it soaked an older build than the current source** (see below).

## What was soaked

| Item | Value |
| --- | --- |
| Command | `sudo tests/soak/run_soak.sh 6 /var/tmp/soak` on VM `panopticon-endpoint-dev` (Ubuntu 22.04, kernel 5.15.0-91, 8 vCPU, 6 GB) |
| Window | 2026-10-07 20:12:05 UTC to 2026-10-08 02:12:07 UTC; drained; sensor exit code 0; store integrity checked at 02:17:51 |
| Sensor binary | `build-rel/panopticon-sensord`, Release, built 2026-10-07 18:12 UTC, sha256 starts `b8c098c06f71ce25` |
| **Source era of that binary** | **Before ADR 033.** It contains signed local policy (ADR 032) but none of: the self-integrity monitor and `tamper.integrity` (ADR 033), the compile-out of the unsigned-command option (ADR 034), the start-of-policy sweep (ADR 035), rollback detection (ADR 036). Checked with `strings` against the binary built later from the final source. `918b154` was the newest commit when it was built |
| Harness | `tests/soak/soak.py` as committed in `d90068c` (signed-policy workload with every fifth publish an older, refused version). It did not yet record the binary's identity; that was added afterwards, so for this run the identity above was established by inspection |
| Workload | Mixed process, file, network, DNS and long-lived-connection load (about 173 events/s on average), 180 signed dry-run commands, a Manager outage of 90 s every 30 min, slow and dropped acknowledgements |

**Consequence.** This run is evidence for the stability, loss accounting, delivery, command and signed-policy paths
as they were before the integrity work. The integrity monitor, the policy sweep and the rollback state file have
**not** been soaked. A soak of the current build is a separate, pending item
(`docs/HANDOFF.md#6-hour-soak-status`).

## Files

| File | What it is |
| --- | --- |
| `report.txt`, `report.json` | The analyzer output (`tests/soak/soak.py analyze`): trends, counts, loss, delivery, commands, policy, verdicts |
| `run.json` | Run facts: start/end, faults injected (with times), commands sent, drain and exit code |
| `integrity.json` | `tests/chaos/analyze.py` over the full store: 3,742,620 records, `first_seq` 1, `last_seq` 3,742,620, 0 missing, no conflicts |
| `samples.csv` | One row per 30 s sample (721): RSS, threads, descriptors, CPU ticks, WAL size, health state (the raw `samples.ndjson` is 3.8 MB and not kept) |
| `soak-fault-log.txt` | The harness's own log of faults |
| `gaps.txt` | `tests/soak/gaps.py` output: every health interval over 11 s and every loss record, with times |

The 1.3 GB record store itself was not kept; it stays on the VM (`/var/tmp/soak/store.ndjson`) until the VM is rebuilt.

## Verdicts

| Verdict | Result | Notes |
| --- | --- | --- |
| RSS | stable | 53.4 MiB after warm-up, peak 65.2 MiB; rose over about the first 1.5 h and has been flat since (second-half slope 0.000 MiB/h) |
| File descriptors | stable | 84 to 92 |
| Threads | stable | 12 throughout |
| Providers | active outside injected faults | `policy` degraded in 140 of 721 samples (each refused rollback publish) and `command_channel` in 48 (Manager outages): both induced |
| Commands | all answered, victim alive | 180 sent, 180 accepted, 180 results, 0 duplicates; 90 `COLLECT_PROCESS_INFO` succeeded, 90 `KILL_PROCESS` rejected `dry_run`; result latency p50 2.9 s, max 139.3 s (during outages) |
| Policy | every publish accounted for, matches ordered | 145 good publishes loaded, 35 refused as rollback; 146,866 matches, 0 before their subject |
| Store | consistent | no gap in `seq`; delivery retries 101, refusals 0, quarantined 0, sink errors 0; WAL quota drops 0; 6 records unacknowledged at the end |
| Sensor | ran to the end | exit 0 after drain |
| **Health timer** | **DRIFT** | p99 of the health interval 12.5 s against a nominal 10 s (threshold 11 s); max 39.2 s |

## Reading the health-timer DRIFT and the loss

This is analysis, not a proven cause.

* 36 health intervals exceeded 11 s (`gaps.txt`). Every one ended during, or within a few minutes after, a window in
  which other work ran on the same VM (builds, test suites, sanitizer runs): about 20:27–21:30, 21:37–21:55,
  22:00–22:12, 22:30–22:35 and 23:55–00:05 UTC. The exceptions are two intervals ending at 22:21 (18.2 s, 22.9 s),
  nine minutes from the nearest recorded window; **their cause is not established.**
* The last two hours (00:12 to 02:12 UTC) had no builds or test runs on the VM (only brief read-only status checks) and no interval above 10.9 s.
* The only loss reported was 54,904 events at the `governor` stage in 32 records, in three clusters that begin at
  22:00:42, 23:41:58 and 00:03:34 UTC. Each cluster lies inside one of those windows (file-event bursts from builds
  and test runs exceeding the file provider's rate governor, ADR 009). The soak's own workload caused none. The loss
  was **reported**, not silent: the store check found 0 missing sequence numbers and the loss records account for the rest.
* Process-event latency (event time to the sensor's observation time, ADR 007 timestamps) in the two unperturbed
  hours: p50 19.4 to 19.7 ms, p99 189 and 207 ms, max 0.8 and 1.2 s (about 220,000 events per hour). In the perturbed
  hours the p99 was 0.5 to 4.0 s and the maximum 12 to 36 s. This is not kernel-to-WAL or host-to-Manager latency.
* CPU was 12.15 % of one core over the run (13.3 % in hour 0 falling to 10.3 % in hour 5) at about 173 events/s, a
  deliberately heavy mixed workload; it must not be compared with the 0.4 % idle figure.

What would remove the caveat: a soak of the current build with nothing else running on the VM for its whole length (and `PANOPTICON_SOURCE_HEAD` set, so the report names what was soaked).
