# 6-hour soak 2, 2026-10-08: the current build

**Result: COMPLETED, DEGRADED BY THE ENVIRONMENT, no sensor defect found.** The run lasted the full 6.00 hours, the
sensor ran to the end and exited 0, the store has no sequence gap and the sensor reported no loss. The automated report
is not fully clean for one reason: the VM itself stalled twice (98 s and 231 s, logged by the guest kernel), which
shows up as two long health intervals, one unexpectedly degraded `command_channel` sample, four unexpectedly degraded
`policy` samples and one expired command. It is **not** a clean-room pass, and **it did not exercise the self-integrity
monitor** (see "Not covered").

Soak 1 ([../soak-2026-10-07/](../soak-2026-10-07/)) soaked an **older, pre-integrity-monitor build** and is not validation
of the current build. This directory is the soak evidence for the current build.

## What was soaked

| Item | Value |
| --- | --- |
| Command | `sudo PANOPTICON_SOURCE_HEAD=b31d009 tests/soak/run_soak.sh 6 /var/tmp/soak2` on VM `panopticon-endpoint-dev` (Ubuntu 22.04, kernel 5.15.0-91, 8 vCPU, 6 GB, VirtualBox), started from a fresh boot (`uptime -s` 08:26:45 UTC) with nothing else running |
| Window | 2026-10-08 08:30:02 UTC to 14:30:10 UTC (6.00 h, 721 samples at 30 s); drained; sensor exit code 0; store check at 14:34:56 |
| Binary | `build-rel/panopticon-sensord`, Release, built 2026-10-08 02:37:54 UTC, sha256 `ad05314b48c4cb4302ccec37083cf6e9ddcdf064b5c16a4f5fc1752a1442ec8e`, 3,046,216 bytes. Packaged configuration (the unsigned-command option is compiled out, ADR 034) |
| Source | The harness stamp says `b31d009`, passed in by `PANOPTICON_SOURCE_HEAD` (the VM has no `.git`, so it could not check). The last commit that touches `src`, `include`, `bpf` or `CMakeLists.txt` is `0e18ee6` (ADR 036), which is older than the build, and nothing under those paths changed after it; so the binary matches the sources of `b31d009` and of main |
| Harness | `tests/soak/soak.py` and `run_soak.sh` as on main at the time |
| Workload | Mixed process, file, network, DNS and long-lived-connection load (about 150 events/s), 180 signed dry-run commands, a Manager outage of 90 s every 30 min, slow acknowledgements (120 s) and dropped acknowledgements, a signed policy published every 5 min with every fifth an older version that must be refused |

## Measurements (MEASURED, one run)

| Measure | Result |
| --- | --- |
| Events and records | 3,246,765 events (150.3/s); 3,249,683 records stored, `seq` 1 to 3,249,683, **0 missing, no conflicts** |
| Loss | **0 loss records, 0 events lost at any stage**, 0 sink errors, 0 WAL quota drops, 0 provider drops |
| Delivery | 38,024 batches, 101 retries (the run injected outages and ack faults throughout; retries were not attributed one by one), 0 refusals, 0 quarantined, longest failure run 8, most unacknowledged 21,122 records, 0 unacknowledged at the end; WAL on disk 63.3 MiB at its largest (an outage), 5.5 MiB at the end |
| RSS | 52.2 MiB at the start of the trend, 52.7 MiB at the end, peak (VmHWM) 52.7 MiB; slope +0.07 MiB/h overall, +0.14 MiB/h in the second half (about 0.4 MiB over three hours) |
| File descriptors, threads | 84 to 91 descriptors; 12 threads throughout |
| CPU | 12.87 % of one core overall (per hour 12.1, 12.9, 13.3, 12.2, 13.9, 12.8) at about 150 events/s, a deliberately heavy mixed load; not comparable with the 0.4 % idle figure |
| Health cadence | nominal 10 s; median 10.03 s, p99 10.40 s, **max 249.9 s**; four intervals above 11 s (below) |
| Event observation latency | process event time to the sensor's observation time: p50 20.4 to 21.1 ms and p99 249 to 288 ms in every full hour; maxima 0.76 to 1.31 s, and 7.95 s in the hour that contains the first stall. This is **not** kernel-to-WAL or host-to-Manager latency, which were not measured |
| Commands | 180 sent, 180 accepted, 180 results, 0 duplicates, victim alive; 90 `COLLECT_PROCESS_INFO` succeeded, 89 `KILL_PROCESS` rejected `dry_run`, 1 `KILL_PROCESS` rejected `expired`; result latency p50 3.0 s, max 364.4 s |
| Policy | 145 good publishes and 35 older ones sent; 143 loaded as updates plus the first load; 34 refused as rollback; 146,974 matches, 0 before their subject; one publish and one refusal short of the sent count (the harness tolerates 1; the last publish fell at the time of the second stall) |
| Verdicts | RSS stable, descriptors stable, threads stable, timer "on time" (by p99), commands all answered and victim alive, policy every publish accounted for, store consistent, sensor ran to the end; **providers "NOT ALWAYS ACTIVE"** |

## The two VM stalls, and the degradation they explain

`gaps.txt` lists four health intervals above 11 s: 109.4 s ending 09:23:32 UTC, 15.2 s ending 09:23:48, 11.4 s ending
11:33:13, and 249.9 s ending 11:51:07. The report also flags `policy` degraded in four samples at minute 53.5 to 53.6 and
`command_channel` degraded in one sample at minute 201.1 ("command poll failed: transport: Couldn't connect to server"),
both outside any injected fault; those minutes are 09:23 and 11:51 UTC.

Evidence that these were stalls of the **whole VM**, not of the sensor (`vm-stalls.txt`):

* The guest kernel logged `rcu: INFO: rcu_sched self-detected stall` and `watchdog: BUG: soft lockup - CPU#2 stuck for
  98s! [swapper/2:0]` at 09:23:32, and `soft lockup - CPU#2 stuck for 231s! [swapper/2:0]` at 11:51:06. A CPU in the idle
  task "stuck" for minutes means the host stopped running the vCPU.
* The harness's own sampler, a separate process, shows gaps of 120.7 s (ending 09:23:32) and 244.5 s (ending 11:51:06)
  in a 30 s cadence.
* The load generator's `sshd` log lines stop for the same intervals (09:21:36 to 09:23:32, 11:47:01 to 11:51:07).
* The expired command was received at 11:51:07; its lifetime ran out while the VM was frozen. The 249.9 s health gap and
  the 364.4 s maximum command latency fall in the same window.

What caused the host to stop the VM is **not established**. At 14:53:37 IST (09:23:37 UTC), five seconds after the first
stall, the Windows host logged creation of a Hyper-V virtual switch ("WSL (Hyper-V firewall)"); nothing was logged at the
second. There is no host sleep or hibernate event in the window. The 11.4 s interval at 11:33:13 is marginal and its
cause is not established.

Interpretation: the sensor's own timer and pipeline were not the cause, because the loss accounting stayed exact
(0 missing, 0 loss, 0 drops) and every other measure stayed flat. This is an environment limitation of a
VirtualBox VM on a laptop-class host, and a soak on a dedicated machine would not have it. It also means the harness
verdict "timer: on time" (which reads p99) hides a 250 s maximum; the maximum is recorded here and in `gaps.txt`.

The checker also counted 57 events as clock-skewed (`skewed_events` in `integrity.json`); this was not investigated and
is plausibly the stalls.

## Not covered by this soak

* **The self-integrity monitor and rollback high-water mark (ADR 033, ADR 036) were not enabled.** The soak's
  `sensor.conf` has no `integrity_manifest`, there is no integrity provider in the provider list and none of the 721
  samples carries an integrity block. "store integrity" in the report is the sequence-number check, not self-integrity.
  Those paths are covered by the integrity e2e (26/26, `../e2e-2026-10-08/`) and by unit tests, but have **not** been
  soaked. A soak with a signed manifest configured is open work; the harness has no option for it yet.
* Kernel-to-WAL and host-to-Manager latency, a file-event storm, more than one host, a real Manager (the harness uses its
  fake Manager), other kernels and distributions.

## Files

| File | What it is |
| --- | --- |
| `report.txt`, `report.json` | The analyzer output (`tests/soak/soak.py analyze`) |
| `run.json` | Run facts: start/end, faults injected with times, commands sent, drain, exit code, build stamp |
| `integrity.json` | `tests/chaos/analyze.py` over the full store (record type counts, `missing` 0, `loss_records` empty) |
| `samples.csv` | One row per 30 s sample (721): RSS, threads, descriptors, CPU ticks, WAL size, health status |
| `soak-fault-log.txt` | The harness's log of the faults it injected |
| `sensord-stderr.txt` | The sensor's stderr (start-up lines and the final delivery summary) |
| `gaps.txt` | `tests/soak/gaps.py` output: health intervals above 11 s and loss records (none) |
| `vm-stalls.txt` | The guest kernel's soft-lockup lines and the sampler/load-generator gaps |

The record store (about 1.1 GB with the other work files) stays on the VM (`/var/tmp/soak2/store.ndjson`) until it is rebuilt.
