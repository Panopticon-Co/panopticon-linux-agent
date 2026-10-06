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
