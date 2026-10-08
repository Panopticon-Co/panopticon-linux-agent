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

| 2026-10-06 | S2, debug build | same | 2000 × `/bin/true` (6071 events), eBPF process provider (netlink on standby) + procfs | 0 losses; ≈640 µs CPU per event over the storm window |
| 2026-10-06 | S2 | same | same workload, `--no-ebpf` (netlink_proc + procfs) | 0 losses; ≈520 µs CPU per event |
| 2026-10-06 | S2 | same | 4 × 4000 `/bin/true` (48 024 events, 16 003 execs), eBPF | 0 losses; 16 003 execs for 16 000 spawns (+3 from the harness shell); fork, exec and exit counts equal |

S2 notes: the eBPF provider does **not** lower user-space CPU per event. The entity graph's
procfs enrichment (`read_process` per exec, reconcile) dominates, so the provider's gain is
correctness: argv captured at exec, in-kernel start time, no PID-reuse race, exact last-thread
exit semantics, and drop accounting from the ring buffer. These per-event numbers come from a
shared 2-vCPU VM with the workload generator competing for CPU and are not comparable with the
S1 rows (different workload and event mix); S11 re-measures both providers on a quiet host and
profiles `read_process`. Exec latency overhead and provider start-up cost are still unmeasured.

S1 notes: CPU per event is measured from the sensor's own `health` record (`getrusage`)
divided by emitted records; `/usr/bin/time` was not installed in the VM. The remaining
hotspots are the output write, `poll`, JSON string escaping and the `open` of
`/proc/<pid>/stat` on every fork. Exec latency overhead and kernel→WAL p99 latency are not
measured yet; they need the eBPF provider (S2) and are scheduled for S11. Record size is
analysed in section 4. The CPU figures above come from a Debug (unoptimised) build; section 4 is the first
Release (-O3) measurement.

## 4. Record size and transport economy (S11.3)

Measured with `tests/perf/run_size_profile.sh` (all providers on, product defaults except a 10 s health
interval; 20 s startup, 60 s idle, 150 s mixed workload run as an unprivileged user: gcc, python, find, tar,
file create/modify/delete, loopback HTTP, DNS, sudo and failed su, a module load) and
`tests/perf/size_profile.py`. Ubuntu 22.04 VM, 5.15.0-91, 4 vCPU, Release build, fake Manager on the same
host over TLS. Events the test Manager itself causes on loopback are excluded. Sizes are bytes of the record
line, which is also the WAL payload and the wire body.

**Sizes.** One run, 6,955 records, 24.8 MB:

| Class or type | n | mean | p50 | p95 | p99 | max | share of bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| all records | 6,955 | 3,562 | 4,054 | 4,345 | 4,613 | 4,968 | 100 % |
| `process.fork` / `exit` / `exec` / `cred_change` | 5,138 | 4,056 to 4,174 | 4,050 to 4,111 | up to 4,613 | up to 4,617 | 4,968 | 85 % |
| `file.*` | 1,168 | 1,938 to 2,123 | 1,927 to 2,052 | up to 2,360 | up to 2,360 | 2,360 | 6 % |
| `network.*`, `dns.query`, `auth.privilege` | 456 | 1,922 to 2,159 | 1,894 to 2,159 | up to 2,137 | up to 2,137 | 2,159 | 2 % |
| `hash.computed` | 30 | 871 | 867 | 892 | 895 | 895 | 0.1 % |
| `health` | 22 | 4,262 | 4,264 | 4,273 | 4,273 | 4,273 | 0.4 % |
| `state.*` parts (startup, hourly after) | 26 | 17,036 | 11,336 | 38,486 | 88,277 | 88,277 | startup only |

The 4.2 KB figure came from the chaos run, which was almost all process events plus the startup snapshot. A
process lifecycle event costs about 4.1 KB; a file, network, DNS or auth event about 2 KB.

**Envelope against payload.** The envelope (everything except the event body) is 14.5 % of the bytes: `host`
133 B per record, `provenance` 87, `sensor` 71, `observed_time` 48, `id` 39, `time` 39, `unavailable` 24,
`type` 22, `schema_version` 22, `record_type` 21, `seq` 10. The event body is 85.5 %: `process` 55 % and `parent`
28 % of all bytes. Inside event bodies the largest members are `process.ancestry` (about 4.2 MB of 26 MB in the
first run), `env`, `caps` (five 16-digit masks), `executable`, `creds`, `ns`, `args`, `confidence` and `cgroup`,
and the same set again under `parent`. The WAL adds a 20-byte frame per record (0.5 %).

**Redundancy, measured.** `parent` is byte-identical to an earlier record `parent` in 94.8 % of records
(271 distinct parents in 5,148 records); `process` is an exact repeat in 17.6 % and would be 32 % of its size if
only the keys that changed since the previous record of the same entity were written.

**Rates.**

| Phase | records/s | WAL bytes/s | wire bytes/s | CPU of one core | RSS |
| --- | --- | --- | --- | --- | --- |
| startup (first 13 s, state snapshots) | 6.2 | 48,624 | 48,807 | 5.4 % | 44 MB |
| idle (health every 10 s) | 0.27 | 1,006 | 1,042 | 1.85 % | 44 MB |
| mixed workload | 46.6 | 167,833 | 168,542 | 4.83 % (about 1 ms per record, all-in) | 46 MB |

At the default 60 s health interval idle traffic is about 70 B/s of health plus the events themselves. The
WAL quota (256 MiB default) covers about 27 minutes of this workload offline, and about 71 hours of the idle
profile at a 10 s health interval.

**Serialization and compression cost.** `perf record` of the sensor over the workload: the record serializer
and JSON writer are 2.8 % of the sensor samples (about 0.14 % of one core) and the WAL frame and CRC 3.2 %;
77 % of the samples are in the kernel (scheduler and lock time: `finish_task_switch`, spinlocks) and 17 % in
other user code. Record size does not drive CPU. Compression at the measured rates, on batches as the uplink
sends them (mean 175 KB under load): zlib level 1 gives 15.1x for 6.6 ms CPU per MB, level 6 gives 25.8x for
12.5 ms per MB, and zstd on the whole stream gives 40x at level 1 and 52x at level 3 (3.6 and 8.8 ms per MB
wall, CLI); that is 0.1 % of one core at 168 KB/s. A single record compressed alone gets only 2.8x (zstd -3)
to 2.9x (zlib 6); one dictionary experiment was worse than none, probably a poor training set, so it is
inconclusive. The uplink sends no compression today and the Manager ingest route
(`manager/routers/linux_endpoint.py`) reads the body as is, so using compression needs a Manager change
(decompression with a size bound).

**Defect found: one TLS connection per batch.** The uplink created and destroyed a libcurl handle for every
POST: 728 connections for 728 batches in 4 minutes, a TCP and TLS handshake for one to a few records while the
host is quiet, and 12.8 % of the sensor CPU in libcrypto. Fixed: the poster keeps one handle, so libcurl keeps
the connection alive (TCP keepalive on; the handle is dropped after a transport error so the next attempt
starts clean). Same workload after the fix: 1 connection for 159 requests, libcrypto 2.4 %, and the sensor
used 11.1 s of CPU against 16.8 s (both under `perf`, 7,200 to 8,100 records).

**Decision.**

* 4 KB per process event is acceptable as the stored and in-memory form. It is self-contained on purpose
  (full process, parent and ancestry in every record, so a record is forensically useful alone and the
  stream survives a lost neighbour), and it costs 0.14 % of a core to serialize. No field is removed.
* It is not acceptable uncompressed on the wire for a sustained busy host (about 14 GB a day at the measured
  workload of 168 KB/s). Compressing batches removes 15x to 50x of that with no loss of information. This is
  the next step and needs a Manager change (`Content-Encoding` with a decompressed-size bound), which is a
  cross-component decision; the sensor would send it only to a Manager that accepts it.
* The one large avoidable redundancy is `parent` (28 % of bytes, 95 % exact repeats). Referencing the parent
  by `entity_id` once its full record was sent in the same boot would remove most of it, but it makes records
  depend on each other and changes the 1.0 contract (consumers would have to join), so it is a schema 1.1
  proposal for the team, not a change made here. Compression already collapses these repeats on the wire.
* Health records (4.2 KB each, most of it static provider capability lists) are small in total at the default
  interval and are left alone.
* Idle CPU was 1.85 % of a core against a budget of 1 % when this section was first measured. It is
  explained and fixed in section 5.

## 5. Idle CPU and wake-ups (S11.4)

`tests/perf/idle_wakeups.sh` starts the Release sensor with every provider on, waits 30 s, and reads per-thread
user and system time and context switches from `/proc/<pid>/task/*` over 60 s, then `perf trace -s` for the
syscalls. Same VM as section 4. `MANAGER=1` delivers to the chaos fake Manager over TLS.

| Configuration | CPU of one core (user + sys) | wake-ups/s |
| --- | --- | --- |
| before: defaults, no Manager | 0.76 % (0.41 + 0.35) | 42 |
| before: Manager, health every 10 s | 0.94 % (0.23 + 0.71) | 46 |
| after: defaults, no Manager | 0.40 % (0.22 + 0.18) | 17.5 |
| after: Manager, health every 10 s | 0.35 % (0.10 + 0.25) | 20.5 |

What the wake-ups were: the three eBPF providers (process, network, security) each ran
`ring_buffer__poll(ring, 100)`, 30 wake-ups a second for nothing, because the kernel wakes the poll as soon as a
record is submitted (the programs submit with flags 0) and the timeout only bounds how long a stop request waits.
It is now 1000 ms, with a two-phase stop (`provider::request_stop()` on every provider, then `stop()`) so the
providers finish together; shutdown of an idle sensor takes 1.4 s. The remaining wake-ups are the pipeline loop
(200 ms), the uplink idle poll (500 ms), the 1 s polls of the file and auth providers, and the once-a-second status
refresh (reads `/proc` and the BPF maps, about 11 `bpf()` calls a second); together they cost about 0.1 %.

The earlier 1.85 % was a run with the Manager attached, before the fix to the TLS connection per batch
(section 4) and with `perf record` attached, which adds its own overhead; the two changes are not separated
by an A/B run, so the split between them is not known. Both configurations are now under the 1 % budget
by a factor of 2 or more, with the kernel share 40 to 70 %. Not measured: 6.x kernels, other hardware, a
host with many mounts (the 30 s mount rescan and the 15 s sensitive-file re-mark scale with mount and
pattern counts).

## 6. Sensor overhead on the hooked paths and the ring-buffer wake-up policy (S13.7)

`tests/perf/run_overhead.sh` runs the same workload (`tests/perf/overhead_load.py`: `posix_spawn` of `/bin/true`,
a loopback TCP connection with a 100-byte exchange, open+close of a file) alternately with no sensor and with
`panopticon-sensord` running its default providers against a WAL (no Manager, records spooled). The load is pinned to
one CPU (`taskset -c 1`); unpinned, a loopback connection varied 2x from run to run with no sensor at all. Median of 5
rounds per sample, median over 4 off/on pairs, microseconds per operation. Ubuntu 22.04, kernel 5.15, x86_64,
4 vCPU VirtualBox VM.

| Build | exec (spawn+wait) | tcp loopback connection | open+close | sensor CPU during the load | peak RSS |
| --- | --- | --- | --- | --- | --- |
| Before: ring buffer woken on every record | 5422 us off, 6660 us on: **+22.8 %** | 199 us off, 669 us on: **+235 %** | +5.3 % | 16 to 22 % of one core | 52 MiB |
| After: adaptive wake (ADR 029) | 5318 us off, 5447 us on: **+2.4 %** | 190 us off, 219 us on: +15 % | +8 % | 14 to 28 % of one core | 56 to 63 MiB |

What the numbers do and do not say:

- The cause was found with `bpftool prog show` (`kernel.bpf_stats_enabled=1`): `on_fork`, `on_exec` and `on_exit` took
  500 to 850 us each in the kernel, because `bpf_ringbuf_output` with flags 0 wakes the reader (irq_work and a
  scheduler wake) whenever it has caught up, which on a quiet reader is every record. With `BPF_RB_NO_WAKEUP` the same
  programs take 3 to 5 us. The exec path crosses three of these hooks.
- Exec overhead now meets the 5 % budget. The TCP figure is a ~29 us difference on a ~190 us operation whose own
  baseline moved between 175 and 275 us across samples; the single clean sample before the fix was 2 %, so the
  +15 % is within what this VM cannot resolve, and it is not claimed as a measurement of the sensor's cost.
  The open+close difference is 0.4 us on 5 us and also inside the noise (the file-event provider is off in the
  default configuration this ran with, so this path only pays for the in-kernel hooks).
- The first "after" attempt (two of three pairs) was discarded: it overlapped a repository sync and the baseline
  exec time swung between 5.3 and 14.9 ms. The numbers above are from the later back-to-back run of both binaries,
  4 pairs each, the VM otherwise idle.
- Records spooled to the WAL without a Manager reach the WAL quota in this test (the quota drops the oldest
  segments and says so: `quota: seq a-b`); `loss_records` in `status` counted none from the kernel or the pipeline.
- Not measured: more than one heavy workload at once, other kernels or hardware, p99 added latency per call.

## 7. Network storm: where the sensor saturates and whether the loss is reported (S13.9)

`tests/perf/run_netstorm.sh` drives a rate-controlled loopback TCP storm (`tests/perf/netstorm.py`: connect, 100 bytes
each way, close; every connection is four network events: connect, accept and the two closes) against a real
`panopticon-sensord` with default providers and a WAL (no Manager), waits for the pipeline to drain, and reconciles
**events the network provider handed over** with **events that reached the WAL** and the **loss the sensor reported**.
Ubuntu 22.04, kernel 5.15, x86_64, VirtualBox VM with 8 vCPUs, 4 GiB, ext4 on a virtual disk that sustains 57 to
65 MB/s sequential writes (`dd ... conv=fdatasync`). The generator is pinned to CPUs 0 to 3 (4 processes) so it does
not compete with the sensor's reader thread; 12 s per step.

| Offered (connections/s) | Provider events | Delivered to the WAL | Reported loss | Unaccounted | Pipeline thread CPU |
| --- | --- | --- | --- | --- | --- |
| 1481 | 73567 | 73570 | none | 0 | 38 % |
| 2949 | 144802 | 144812 | none | 0 | 60 % |
| 4471 | 216841 | 172138 | `queue` 44709 | 0 | 51 % |
| 6567 (generator unlimited) | 319432 | 154392 | `queue` 165037 | 0 | 48 % |

("Unaccounted" is provider events minus delivered minus reported loss; the few events the sensor emits itself make it a
number between -10 and +11, never a gap.) **No kernel ring buffer loss occurred in any of these runs**: the 4 MiB ring
holds about 12000 network records and the reader keeps up. The sensor is therefore loss-free to roughly **12000 events
per second** (3000 connections/s) on this VM and sheds beyond roughly **14000 to 19000 events per second**, and what it
sheds is counted and reported. The amount shed at a given offered rate varies a lot from run to run (three runs of the
same 5000 connections/s step lost 86131 unreported before the fix, then 36799 and 73817 reported), so the table is a
picture of the boundary, not a repeatable benchmark figure.

What this found, in the order it was found:

1. **A silent loss, now fixed.** The first runs showed the provider counting 238472 events and the WAL holding 152341
   records with `loss_records` 0: 86131 events (36 %) vanished with no loss record. `record_queue` counted what it refused
   when full and nothing ever read the count (`take_dropped()` was called only by a unit test), although the capability
   matrix claimed queue loss was reported. `collect_losses` now turns it into a `loss` record (`stage: queue`, exact count)
   and a reconcile of the entity graph. `pipeline_reports_records_the_queue_refused` fails with the reporting disabled
   (checked). This also corrects the earlier wording "no silent gap in 12 scenarios": the chaos suite never overflowed the
   in-memory queue, so it could not see this. The `ringoverflow` scenario overflows the kernel ring buffer.
2. **The ceiling is the single pipeline thread, and it is not CPU alone.** Profiling the pipeline thread under the storm
   (`perf record`): 13.5 % `encode_wal_frame` (a byte-at-a-time CRC-32C over about 2.2 KB per record), 7 % JSON string
   escaping, about 8 % kernel page zeroing for the page cache, and the rest spread over serialisation, allocation and
   `write`. Moving the CRC to the SSE4.2 instruction (the same CRC-32C value; the table version remains for other CPUs and
   is checked against it) cut the thread's CPU per record from **63 to 76 us down to 50 to 54 us** (three alternating
   before/after pairs on the same storm). The thread is still only about 50 to 60 % busy when it saturates: it also
   blocks in `fdatasync` (ADR 008: every 256 KiB or 200 ms; at 33 MB/s that is about 130 synchronous syncs a second on a
   disk that takes milliseconds for each). A throwaway build with the byte trigger raised to 4 MiB delivered 182018
   instead of 172138 events at 4500 connections/s: +6 %, smaller than this scenario's run-to-run spread, so it shows no
   effect worth weakening the ADR 008 durability window for, and it was **not adopted**. Overlapping serialisation with
   the sync on a second thread would raise the ceiling toward the CPU bound (about 20000 records/s at 50 us), at the cost
   of WAL concurrency that has to be proven under TSAN; it is future work, not done.
3. **Where loss does come from the kernel, it is contention, not capacity.** In earlier 4-vCPU runs with the generator
   unpinned, the kernel ring overflowed (11368 events at 8000 connections/s offered, 217864 in one unconstrained run at
   a sensor CPU of only 55 %) because the generator's busy processes starved the reader thread of CPU. With the generator
   confined to its own CPUs no ring loss appeared in any run here. Those losses were also reported exactly (the BPF `drops`
   map counts every `bpf_ringbuf_output` failure). The pipeline used to attach "number of lost events is unknown" to
   every `kernel` loss, which was wrong for eBPF, where the count is exact; it is right for netlink, audit and fanotify,
   where a count is overflow notices. A provider now says which it is (`losses_are_event_counts`), and the eBPF
   providers' loss record says "the count is exact".
4. **Not claimed:** "zero loss under load". The honest statement is: no loss up to about 12000 network events a second
   on this VM, exact accounting of everything beyond it. A bigger queue absorbs bursts (`queue_capacity`, default 65536
   records, a few seconds at the observed drain rate) but not a sustained overload; the choice between a larger queue and
   shedding earlier is a memory-for-latency trade that the operator can make.

A caution about the 8-vCPU configuration of this VM: the kernel's per-program run time is wall time, and on 8 vCPUs the
same binary averaged 3 to 6 us per hook call in some windows of 300 spawns and 40 to 58 us in others, where with CPUs
4 to 7 offlined in the guest every window was 2.5 to 6 us. Section 6's figures were taken on 4 vCPUs and are not
re-measured here. `live_wake_policy` now judges the hook cost on the best of five windows of 100 spawns (a build that
wakes the reader on every record costs 535 us in its best window and still fails; checked).

**Re-measured after the attachment self-check (S13.14), same script, same binary.** With 4 vCPUs online (CPUs 4 to 7 offlined in the guest): exec -0.4 %, tcp loopback connection +5.1 %, open+close +1.3 %; the sensor used about 10 % of one core and 55 MiB and recorded no loss. With all 8 vCPUs online the same binary measured exec +11.9 % and tcp +38 % and the sensor 14 to 27 % of a core. The 4-vCPU numbers are the ones comparable with the table above; the 8-vCPU figures are the scheduling effect described in section 7, so overhead budgets are judged on the pinned 4-CPU configuration and the 8-vCPU result is reported, not hidden.

## 8. Throughput ladder and overload recovery (2026-10-08)

`tests/perf/ladder.py` on the Ubuntu 22.04 VM (kernel 5.15.0-91, 8 vCPU, 6 GiB), Release `build-rel`, nothing else
running, a real `panopticon-sensord` with default providers and a WAL (no Manager), loopback connection storm
(`netstorm.py`, 3 generator processes, **not pinned** to separate CPUs), 20 s per step, 65 s pause between steps.
Raw output: [evidence/perf-ladder-2026-10-08/](evidence/perf-ladder-2026-10-08/). **MEASURED, one run each.**

| Target conn/s | Offered ev/s | Written ev/s | Peak backlog (events) | Drain (s) | WAL MB/s | Pipeline CPU | Peak RSS (MiB) | Reported loss |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 37 | 153 | 153 | 2 | 2 | 0.4 | 3 % | 40 | none |
| 100 | 388 | 388 | 4 | 2 | 0.9 | 4 % | 40 | none |
| 250 | 948 | 948 | 11 | 2 | 2.2 | 7 % | 40 | none |
| 750 | 2904 | 2853 | 1052 | 2 | 6.6 | 33 % | 41 | none |
| 1500 | 4033 | 3266 | 15625 | 3 | 7.6 | 44 % | 48 | none |
| 3000 | 4045 | 2977 | 23805 | 5 | 6.9 | 36 % | 53 | none |

`--recover` (one sensor: baseline, unlimited overload, baseline again):

| Phase | Offered ev/s | Written ev/s | Peak backlog | Drain (s) | Peak RSS (MiB) | Reported loss |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | 147 | 147 | 3 | 2 | 40 | none |
| overload | 5271 | 3741 | 35641 | 6 | 61 | kernel 8703 |
| baseline again | 149 | 149 | 8 | 2 | 61 | no new loss (the 8703 is the cumulative counter) |

Reading it:

* Up to about 950 events/s offered the pipeline keeps up with a backlog of at most a dozen events. From about 2900
  events/s the backlog is in the thousands and is drained within 2 to 6 s of the load stopping; no loss was reported on
  any ladder step (largest backlog 23805 events, 53 MiB RSS).
* Under unlimited overload (5271 events/s offered) the sensor wrote 3741/s, held a backlog of 35641 events, reported the
  shortfall as `kernel` loss (8703 events) and returned to the idle rate with no new loss once the load stopped. The
  loss is reported, not silent; the `gap` column of the raw output (handed over minus written minus reported) stayed
  between -2 and 8 events, which is the sensor's own records.
* **These numbers are not comparable with section 7.** The ladder's generator is weaker (3 unpinned processes) and
  competes with the sensor for CPU; here the pipeline wrote 3.0 to 3.7k events/s while loaded, where section 7 (generator
  pinned to 4 CPUs) delivered loss-free to roughly 12000 events/s. The kernel loss in the overload phase fits section 7's
  finding that ring overflow is CPU contention with the generator, not capacity. Neither figure is a capacity
  guarantee, and no figure here may be quoted as a sustained rate for real hosts.
* Not measured: kernel-to-WAL latency p99, host-to-Manager latency p95, a file-event storm.
