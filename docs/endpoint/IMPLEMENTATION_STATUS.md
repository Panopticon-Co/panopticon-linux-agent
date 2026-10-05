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
| S2 | eBPF provider framework (vendored libbpf, embedded CO-RE objects), capability prober, process family on eBPF, ground-truth suite | S1 | in progress |
| S3 | Contracts schema 1.0, uplink with seq ack, Manager ingest + storage, Detection Engine adapter | S1 | planned |
| S4 | Host-state engine, `QUERY_STATE`, `panopticon-ctl` | S1 | planned |
| S5 | File telemetry (eBPF + fanotify fallback), FIM, persistence catalog, hashing | S2 | planned |
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
