# Linux Endpoint Architecture

Status: target architecture, adopted 2026-10-06. Sections marked **[built]** describe code
that exists and is tested on this branch; everything else is **[designed]** and is tracked in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). This document is updated in the same
commit as the code that changes it.

## 1. Design goals

1. **Complete, honest visibility.** Every security-relevant Linux behaviour is either observed,
   observed with a documented reduction, or explicitly reported as not observed. The sensor
   never presents a degraded view as a complete one.
2. **Correct identity.** A PID is never an identity. Processes, executable images, files,
   sockets, users and containers are addressed by stable entity identifiers that survive PID
   reuse, `exec`, namespaces and reboots.
3. **Host safety first.** The sensor must never destabilise the host it protects. All kernel
   code is verifier-checked eBPF (no kernel module); every queue is bounded; every resource has
   a governor; prevention fails open unless policy explicitly says otherwise.
4. **Capability-level fallback.** Fallback is chosen per capability (process, file, network,
   auth, ...), not per kernel. Each provider reports its own health and coverage.
5. **Durable and accountable.** Telemetry is written to a crash-safe write-ahead log before it
   is acknowledged as collected. Every loss is counted, attributed and transmitted.
6. **Least privilege where Linux allows it.** Destructive actions run in separate executables
   with narrower privileges than the sensor; every destructive action verifies the target's
   identity through a pidfd or an `openat2`-resolved file handle.
7. **The endpoint defines the contract.** The canonical data model is designed from what the
   endpoint must express; Manager, Detection Engine and Console are adapted to it.

## 2. Process topology

```text
                  +---------------------------------------------------------------+
                  |                    panopticon-sensord (root, hardened unit)    |
 kernel  --eBPF-->|  providers -> ingest queue -> entity graph -> enrich -> rules ->|--> WAL --> uplink --> Manager
 netlink -------->|                                   |                 (local)    |      ^          |
 fanotify ------->|                     host-state engine <-- query/inventory      |      |          v
 audit/journal -->|                                   |                            |   health   command channel
 procfs/sysfs --->|                       coverage + resource governor             |                 |
                  +--------------------------------|-------------------------------+                 |
                                                   | AF_UNIX SEQPACKET, SO_PEERCRED-checked,         |
                                                   | signed command envelope re-verified by helper   |
                         +-------------------------+--------------------+                           |
                         v                         v                    v                           |
           panopticon-responder         panopticon-isolation-helper   panopticon-ctl (local CLI,    |
           (kill/quarantine/evidence)   (nftables only, CAP_NET_ADMIN) read-only status/query)       |
```

| Executable | Privilege | Responsibility |
| --- | --- | --- |
| `panopticon-sensord` | root with a bounded capability set (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_AUDIT_READ`, `CAP_SYS_RESOURCE`, `CAP_NET_ADMIN` for netlink multicast only) | All telemetry, state, local rules, prevention policy load, WAL, uplink, command verification |
| `panopticon-responder` | root, `CAP_KILL`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`; no network | Process termination, quarantine/restore, evidence capture |
| `panopticon-isolation-helper` | `CAP_NET_ADMIN` only | Applies or removes the fixed isolation ruleset (ADR 004) **[built]** |
| `panopticon-ctl` | caller's privileges; talks to a read-only control socket | Status, coverage, host-state queries, diagnostics bundle |

On kernels older than 5.8, `CAP_BPF`/`CAP_PERFMON` do not exist and `CAP_SYS_ADMIN` is used
instead; this is reported in health as `privilege_model=legacy_sys_admin`.

## 3. Subsystems

### 3.1 Kernel telemetry providers

All kernel instrumentation is eBPF compiled once with CO-RE (clang `-target bpf`, BTF
relocations via libbpf). Objects are embedded in the sensor binary; no compiler, headers or
`bpftool` are required on the host.

| Program family | Hooks (preferred → fallback) | Kernel floor |
| --- | --- | --- |
| process | `tp_btf/sched_process_fork`, `tp_btf/sched_process_exec`, `tp_btf/sched_process_exit` → classic tracepoints | 5.5 / 4.7 |
| credentials | `fentry/commit_creds` → `kprobe/commit_creds` | 5.5 / 4.x |
| file | `fentry/security_file_open`, `security_inode_unlink`, `security_inode_rename`, `security_path_chmod/chown`, `security_inode_setxattr` → kprobes on the same | 5.5 / 4.x |
| mmap / mprotect | `fentry/security_mmap_file`, `security_file_mprotect` → kprobes | 5.5 / 4.x |
| network | `fentry/tcp_connect`, `fexit/inet_csk_accept`, `security_socket_bind/listen`, first `udp_sendmsg` per flow → kprobes | 5.5 / 4.x |
| kernel integrity | `fentry/do_init_module`, `security_kernel_read_file`, `security_bpf`, `security_ptrace_access_check`, `process_vm_writev` → kprobes | 5.5 / 4.x |
| namespaces / mounts | `fentry/security_sb_mount`, `security_move_mount`, `switch_task_namespaces` → kprobes | 5.5 / 4.x |
| prevention | `lsm/bprm_check_security`, `lsm/file_open`, `lsm/socket_connect`, `lsm/kernel_read_file`, `lsm/bpf`, `lsm/task_kill` | 5.7 + `lsm=…,bpf` |

Transport to user space uses `BPF_MAP_TYPE_RINGBUF` (5.8). Where it is unavailable (older
kernels, some RHEL 8 builds) the same programs are loaded against a per-CPU perf buffer. In-kernel
filtering (self-exclusion, noise suppression, per-process rate limits) happens before
reservation; drops are counted per program in a per-CPU array and surfaced as loss records.

### 3.2 User-space telemetry providers

| Provider | Mechanism | Role |
| --- | --- | --- |
| `netlink.proc` | `NETLINK_CONNECTOR` / `CN_IDX_PROC` | Process fork/exec/exit/uid/gid/sid/ptrace/comm/coredump when eBPF is unavailable |
| `fanotify` | `fanotify_init(FAN_CLASS_NOTIF\|FAN_REPORT_DFID_NAME)` on filesystems | File create/modify/delete/move/attrib fallback; `FAN_OPEN_EXEC_PERM` for exec prevention fallback |
| `audit` | `NETLINK_AUDIT` multicast read (`AUDIT_NLGRP_READLOG`), never taking the audit daemon role | Login/auth/user-management records emitted by PAM and shadow-utils |
| `journal` | `sd_journal` cursor-based reader | sshd, sudo, su, systemd unit state changes, kernel messages |
| `utmp` | `/var/run/utmp`, `/var/log/wtmp` | Sessions and logins when journald is absent |
| `sock_diag` | `NETLINK_SOCK_DIAG` (`inet_diag`, `unix_diag`) | Socket inventory and ownership by inode |
| `rtnetlink` | `NETLINK_ROUTE` multicast | Interface, address and route changes |
| `nfnetlink` | `NFNL_SUBSYS_NFTABLES` multicast | Firewall ruleset changes |
| `inventory.*` | procfs, sysfs, package databases, systemd unit files, crontabs, container runtime state | Host-state snapshots and differential change events |

### 3.3 Process / entity graph

The entity graph is the sensor's in-memory model of the host. Every telemetry record is
attached to entities before it leaves the pipeline.

* **Process entity id** = first 128 bits of `SHA-256(host_id ‖ boot_id ‖ tgid ‖ start_time_ns)`,
  hex. `start_time_ns` is `task->start_time` (monotonic since boot); the procfs equivalent is
  `starttime` ticks × (1e9 / `CLK_TCK`). Both providers normalise to clock-tick resolution so
  eBPF- and procfs-derived records produce the same id.
* **Image generation**: each successful `exec` increments `exec_gen` for the same process
  entity. `(process_entity_id, exec_gen)` identifies the running image; the event carries both.
* **Threads** are members of a thread-group entity; thread creation is not a process start.
* **Ancestry** is maintained as parent entity links; the event carries a bounded ancestry
  vector (default depth 8) so consumers do not need the full graph.
* **Exited processes** stay resolvable for a grace period (default 30 s) so late events and
  enrichment can still attach to them.
* **Reboot**: `boot_id` comes from `/proc/sys/kernel/random/boot_id`; entity ids from a
  previous boot can never collide with the current one.
* **PID namespaces**: the graph is keyed by host-namespace tgid; namespace-local pids are
  recorded as attributes (`pid_ns`, `vpid`).
* **Reconciliation**: on start, after a provider failover, and every reconciliation interval,
  procfs is scanned and compared with the graph. Processes found in procfs but not in the graph
  are emitted as `process.discovered` (confidence `reconstructed`), never as `process.exec`.

### 3.4 Event normalisation

Providers emit typed records. Normalisation converts them into the canonical model
(`panopticon.endpoint/1.0`, defined in `panopticon-contracts`) with explicit provenance:
which provider, which mechanism, which hook, and confidence. Fields that a provider cannot
supply are listed in `unavailable` with a reason code instead of being silently omitted or
zero-filled.

### 3.5 Enrichment

Enrichment is synchronous and bounded: user and group names (parsed from `/etc/passwd` and
`/etc/group` with change detection, no NSS calls on the hot path), container id and runtime
from the cgroup path, Kubernetes pod identity from runtime state, image hash from the hash
cache, package ownership from the package index, and systemd unit from the cgroup path. An
enrichment that cannot complete within its budget is marked unavailable; it never blocks the
pipeline.

### 3.6 Hashing and file identity

File identity is `(st_dev, st_ino, mtime_ns, ctime_ns, size)`; the hash cache is keyed by it.
Hashes are SHA-256 (plus SHA-1 and MD5 for threat-intelligence compatibility), computed on a
dedicated low-priority thread with a per-file size cap and a global byte budget. Executed images
are hashed with priority, through `/proc/<pid>/exe` so deleted and memfd images are covered.

### 3.7 Container and runtime enrichment

The cgroup path identifies containerd, CRI-O, Docker and Podman containers. Runtime metadata
(image name, pod labels) is read from the runtime's on-disk state without linking a runtime
client library.

### 3.8 Local policy engine

Policy is a signed, versioned document from Manager with a local fallback. It controls provider
enablement, exclusions, noise filters, hash/path/destination block lists, prevention mode per
control (`off`, `audit`, `protect`), response permissions and resource budgets. Policy changes
apply atomically; the active policy version is stamped on every record.

### 3.9 Detection / prevention pipeline

Local detection evaluates a small set of high-confidence, latency-sensitive rules (known-bad
hash execution, execution from a world-writable directory by a privileged process, sensor
tampering, kernel module load, BPF program load by an unexpected process). Rich behavioural
correlation stays in the Detection Engine. Local detections are `detection` records with full
provenance and are separate from response, which needs an authorised command or an explicit
prevention policy.

Prevention uses BPF-LSM hooks (deny with `-EPERM`) where available and fanotify permission
events as the fallback for exec. Each control has a fail-open timeout, a protected allowlist
(init, the sensor, systemd, the package manager when configured), an expiry, and a local kill
switch.

### 3.10 Evidence collection

Evidence is collected on demand (command) or on a detection with an evidence policy. Evidence
items are content-addressed, size-bounded, and recorded as `evidence` records: process
snapshot, memory maps, open fds, environment (with secret redaction), sockets, executable copy,
persistence snapshot, log excerpts, package verification, container context.

### 3.11 Durable local storage (WAL)

Segmented append-only log under `/var/lib/panopticon/wal/`. Each record:
`magic | length | crc32c | seq | kind | payload`. Writes are group-committed with `fdatasync`
(default 200 ms or 256 KiB). The uplink acknowledges sequence ranges; acknowledged segments are
deleted. At quota the oldest segments are dropped and a `loss` record with the dropped sequence
range and per-type counts is written. Recovery validates every record's CRC and truncates a
torn tail.

### 3.12 Transport

HTTPS with mutual TLS where Manager issues client certificates, and the existing signed bearer
identity otherwise. Batches are gzip-compressed NDJSON carrying a contiguous `seq` range;
Manager returns the highest durably stored `seq`, and only then does the sensor advance its
cursor. Retries use jittered exponential backoff; a Manager outage only grows the WAL.

### 3.13 Command channel

Commands are signed by Manager, bound to `(agent_id, host_id)`, carry an expiry and a nonce, and
are recorded in a replay ledger **[built]**. The sensor verifies, journals, dispatches to the
responder or isolation helper, and reports a typed result.

### 3.14 Response executor

`panopticon-responder` accepts only typed requests from the sensor over a peer-credential
checked socket. Process actions open a pidfd and re-verify `start_time` before
`pidfd_send_signal`; tree kill freezes the target's descendants first (SIGSTOP via pidfd) and
then kills them. File actions resolve the path with `openat2(RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS)` and verify `(dev, ino)` before acting.

### 3.15 Self-protection

See [LINUX_ENDPOINT_SECURITY_MODEL.md](LINUX_ENDPOINT_SECURITY_MODEL.md). In summary: root-owned
installation, systemd `Restart=always` and watchdog, BPF-LSM guards on signals to the sensor,
writes to its files and foreign `bpf()` operations where BPF-LSM is active; otherwise tamper
*detection* through eBPF and integrity checks. Root can defeat any user-space agent; this is
documented, not hidden.

### 3.16 Health and diagnostics

Per provider: `state` (active, degraded, failed, disabled, unsupported), `reason`, `coverage`
(capabilities supplied), `loss` counters, and resource use. A `health` record is emitted every
60 s and on every state change. `panopticon-ctl status` and `panopticon-ctl coverage` show the
same data locally.

### 3.17 Configuration

A strict local configuration file (root-owned, mode 0600/0640, allow-listed keys, unknown keys
rejected) holds bootstrap settings only **[built]**. Everything that changes at run time is policy.

### 3.18 Update and rollback

deb and rpm packages. The package keeps the previous sensor binary as
`/usr/lib/panopticon/rollback/`; the post-install health check restores it and restarts if the
new version does not report healthy within the grace period.

### 3.19 Compatibility / fallback manager

At start-up the capability prober inspects kernel version, BTF availability, BPF program and map
type support (libbpf probes), active LSMs, fanotify features, audit, journald, cgroup version and
container runtimes. Per capability it selects the highest-fidelity provider that loaded and
records the decision and the reason for every rejected provider.

### 3.20 Performance / resource governor

Hard limits: memory (systemd `MemoryMax` plus internal caps), CPU (`CPUQuota`), WAL quota, hash
bytes per second, event rate per process. Under pressure it sheds in a fixed order — low-value
events (file reads, repeated connects) first, never process lifecycle or security-control
events — and reports each step as a loss record.

### 3.21 Testing and validation infrastructure

Unit tests, deterministic process-model ground-truth tests, provider integration tests in a VM,
the attack-simulation suite, fuzzers for every parser, chaos tests and the
distribution/kernel matrix. See [LINUX_ENDPOINT_TEST_PLAN.md](LINUX_ENDPOINT_TEST_PLAN.md).

## 4. Data flow and threading

```text
[ringbuf poll thread]--+
[netlink thread]-------+--> bounded MPSC ingest queue (priority-aware shedding + loss count)
[fanotify thread]------+                   |
[journal/audit thread]-+                   v
[inventory scheduler]--+        pipeline thread: entity graph → enrich → local rules → serialise
                                           |
                                           v
                            WAL writer (group commit) ──> uplink thread (batch, ack, retry)
                                                          command thread (poll, verify, dispatch)
                                                          health thread
                                                          hash worker (nice 10)
```

The pipeline is single-threaded by design: the entity graph is mutated in one place, so its
invariants are easy to test and no locks are needed on the hot path.

## 5. Repository layout

```text
bpf/                     eBPF C sources, shared headers, vendored vmlinux.h per arch
third_party/libbpf/      pinned libbpf (git submodule)
include/panopticon/linux_agent/   headers (existing + new subsystems)
src/                     existing core plus sensor/, providers/, state/, response/
packaging/               deb/rpm (CPack), systemd units, maintainer scripts
tests/                   unit, ground_truth, e2e, attack, fuzz, perf, chaos
docs/endpoint/           this documentation set
```

## 6. Relationship to the rest of Panopticon

The canonical model lives in `panopticon-contracts` (`schema/linux-endpoint/1.0.schema.json`). Manager accepts it
on a new ingest route, stores it, and serves it to Detection Engine and Console; the 0.4 route
stays for the Windows agent and older Linux agents until they migrate. See
[CROSS_REPO_IMPACT.md](../CROSS_REPO_IMPACT.md).
