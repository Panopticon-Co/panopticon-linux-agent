# Linux Endpoint Implementation Status

Single source of truth for progress. Updated in the same commit as the code it describes.

## 1. Starting point (2026-10-06)

| Repository | Branch | Commit |
| --- | --- | --- |
| panopticon-linux-agent | main | 335dae0 |
| panopticon-contracts | master | 00f2181 |
| panopticon-manager | main | 75ebac6 |
| panopticon-detection-engine | main | f089331 |
| panopticon-response-engine | main | cc61fcc |
| panopticon-console | main | 296e1ad |
| panopticon-agent (Windows) | main | fb54c4a |
| panopticon-diagrams | main | d4fd92c |

All repositories were equal to `origin` after `git fetch --all`. Active teammate branches not
touched by this program: `panopticon-agent` `feat/ml-telemetry-foundation`;
`panopticon-manager` `feat/ml-telemetry-ingest`, `phase-0/prune-under-load`;
`panopticon-detection-engine` `phase-0/make-claims-true`,
`phase-1/causal-incidents-and-stateful-detection`, `phase-2/behavioral-rarity-baseline`.

Repository dependency map:

```text
panopticon-contracts  (event 0.x, endpoint 1.0, commands, enrollment)
   ^          ^              ^                                   ^
linux-agent  windows agent  manager (vendors detection-engine     console
   |                          + response-engine)                   ^
   +----- HTTPS ingest / commands ---> manager ---- REST API -------+
```

## 2. Roadmap (vertical slices)

Each slice ends with something that runs end-to-end and with a capability-matrix audit.

| Slice | Content | Depends on | Status |
| --- | --- | --- | --- |
| S1 | Resident sensor core: daemon, entity graph, procfs reconcile + netlink proc providers, canonical 1.0 serializer, WAL v2 (CRC, fsync, contiguous seq), health/coverage/loss records, file sink | – | done |
| S2 | eBPF provider framework (vendored libbpf, embedded CO-RE objects), capability prober, process family on eBPF, ground-truth suite | S1 | done |
| S3 | Contracts schema 1.0, uplink with seq ack, Manager ingest + storage, Detection Engine adapter | S1 | planned |
| S4 | Host-state engine, `QUERY_STATE`, `panopticon-ctl` | S1 | done (local control only) |
| S5 | File telemetry (fanotify first, eBPF later), FIM, persistence catalog, hashing | S2 | in progress: S5.1 file events and S5.2 persistence catalog + FIM done; S5.3 executable hashing done (see log) |
| S6 | Network telemetry (eBPF + sock_diag), DNS, rtnetlink, nftables monitor | S2 | planned |
| S7 | Auth and accounts (audit multicast + journal), kernel modules, BPF loads, mounts, credentials, injection, memory | S2 | planned |
| S8 | Policy engine, prevention (BPF-LSM + fanotify permission), indicators, local detections | S5, S7 | planned |
| S9 | Responder (pidfd kill, tree kill, quarantine/restore, evidence), self-protection | S4, S8 | planned |
| S10 | Packaging (deb/rpm), systemd hardening, update/rollback, SBOM | S9 | planned |
| S11 | Performance, chaos, fuzz, distro/kernel matrix, Console views | all | planned |

## 3. Progress log

| Date | Slice | Commit(s) | Verified | Notes |
| --- | --- | --- | --- | --- |
| 2026-10-06 | docs | – | – | Assessment, architecture, capability matrix, catalog, security model, competitor analysis, test plan written before production code. |
| 2026-10-06 | S1 | see git log `sensor:` | Ubuntu 22.04 VM, 5.15.0-91 | `panopticon-sensord`: netlink proc provider, procfs reader and reconciler, entity graph (entity ids, exec generations, PID-reuse detection, inferred exits), endpoint/1.0 serializer, WAL with CRC-32C frames, group commit, cursor and recovery, health/loss/state records, strict config. 21 sensor tests pass as root; ASAN+UBSAN and TSAN clean; fork storm with 0 losses at 107–125 µs CPU per event. Matrix audit run 1: 1 IMPL, 38 PARTIAL, 75 MISSING. Not yet: eBPF (S2), uplink to Manager (S3). Known: core_tests config test fails under umask 0002 (environmental). |
| 2026-10-06 | S2 | see git log `ebpf:` / `sensor:` | Ubuntu 22.04 VM, 5.15.0-91 | Vendored libbpf v1.6.3 built statically; CO-RE programs for fork, exec (argv + path), exit (last thread only), rename, commit_creds and ptrace access; embedded object; provider families so `netlink_proc` is standby while eBPF serves (health `healthy`, fallback reports `degraded`); `--no-ebpf`. 12 eBPF tests (decoder, wiring, live ground truth) and 22 sensor tests pass; ASAN+UBSAN and TSAN clean; fork storm of 16 000 spawns, 0 losses, exec/exit counts exact. Bugs found and fixed by the live runs: netlink never declared its family (both providers ran, duplicating events); an exec of a short-lived child kept the pre-exec parent image. Matrix audit run 2: no status change (see matrix §5). Not yet: second kernel, aarch64 `vmlinux.h`, uplink (S3). |
| 2026-10-06 | S4 | see git log `sensor:` | Ubuntu 22.04 VM, 5.15.0-91 | Inventory collectors (host, posture, users, groups, interfaces, mounts, modules) as pure functions of a filesystem root, emitted as `state.<object>` at start and every state interval; read-only 0600 control socket with `SO_PEERCRED` check and `panopticon-ctl status/coverage/state`; status served from a cache so the control thread never touches pipeline state. 8 state tests, 9 control tests, 23 sensor tests, 12 eBPF tests pass; ASAN+UBSAN and TSAN clean; live `sensord` + `ctl` smoke: non-root client refused, socket removed on shutdown. Matrix audit run 3: 5 rows MISSING → PARTIAL (A3, C1, AP1, AT1, AZ1); totals 1 IMPL, 43 PARTIAL, 70 MISSING. Not yet: Manager-initiated `QUERY_STATE` (needs S3/S9), packages/services/sessions/listeners state objects (S5-S7), RTNL address dump. |
| 2026-10-06 | S5.1 | see git log `sensor:` | Ubuntu 22.04 VM, 5.15.0-91 | `fanotify_file` provider (ADR 009): FID/DFID_NAME decoder that treats the kernel buffer as hostile, filesystem marks re-evaluated every 30 s, handle-resolved and cached paths, rename pairing that survives kernel event merging and read boundaries (found by the live smoke and fixed: a 100-rename burst now pairs 100/100 across 15 consecutive runs), token-bucket governor reported as exact `governor` losses, own-pid and exclusion filtering, actor and post-event `lstat` enrichment in the pipeline, `file.*` records, config keys `enable_file_events`, `file_include`, `file_exclude`. 7 file tests (6 decoder/filter + live root ground truth), 24 sensor tests; ASAN+UBSAN and TSAN clean; live `sensord --stdout` shows `file.create`/`file.rename` with the shell and `mv` as actors. Matrix audit run 4: P1-P3 MISSING to PARTIAL. Not yet: eBPF fentry primaries, `file.link`, P4 sensitive reads, FIM baseline/diff, persistence catalog, hashing. |
| 2026-10-06 | S5.2 | see git log `sensor:` | Ubuntu 22.04 VM, 5.15.0-91 | Persistence catalog and file-integrity monitoring (ADR 010): 16 categories of system and per-user persistence locations, hostile-input handling (FIFO not read, symlink not followed, size and entry caps, walk-once), no secret material emitted; `state.persistence`; `fim_monitor` with a strict persisted baseline (0600, fsync+rename, visible reset on corruption or symlink), offline-change report at start, periodic rescan, event-driven re-description with debounce and actor attribution, truncated scans never report removals. Config keys `enable_fim`, `fim_path`, `fim_interval_seconds`. 9 fim tests (incl. every-truncation rejection of the baseline format) and 25 sensor tests; ASAN+UBSAN and TSAN clean; live `sensord --stdout` reports a cron file add/remove and a `.bashrc` edit with the writing process. Known: attribution uses the pid's current image, so a process that exec-ed since the write is shown as its new program. Matrix audit run 5: 8 rows MISSING to PARTIAL. |
| 2026-10-06 | S5.3 | see git log `sensor:` | Ubuntu 22.04 VM, 5.15.0-91 | Executable hashing worker: SHA-256/SHA-1/MD5 on one low-priority thread (nice 10), paced by a token bucket (default 64 MiB/s), files above 256 MiB reported `too_large`, bounded queue of 1024 and cache of 8192 keyed by (dev, inode, size, mtime_ns), in-flight sharing between processes that exec the same image. The image is opened through `/proc/<pid>/exe` at exec time and its dev/inode verified. A cache hit is inline in the exec record; a miss is `hash.status=pending` followed by a `hash.computed` record joined on entity_id + exec_gen. An image never identified because the process exited first is `unreadable`, never guessed. | 6 hash tests; sensor test `pipeline_hashes_executed_images`; ASAN+UBSAN and TSAN clean; live: `sleep` and `md5sum` digests equal an independent SHA-256/MD5 of the file, `sha1sum` (exited before identification) is `unreadable` | Hashes are of the executed image only; created executables and IOC matching (AX1) are not done. Verified on kernel 5.15 only. |