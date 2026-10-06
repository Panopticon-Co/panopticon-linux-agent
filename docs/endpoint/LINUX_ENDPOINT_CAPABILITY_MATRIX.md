# Linux Endpoint Capability Matrix

This is the completion yardstick for the Linux endpoint. It is re-run after every
implementation slice ([IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) records each run).
A capability is only **IMPL** when code exists on this branch *and* the named test passes on
real kernels; anything less is **PARTIAL** or **MISSING**. **UNSUPPORTED** requires a written
justification in §4.

* Field-level detail for every event type: [LINUX_ENDPOINT_TELEMETRY_CATALOG.md](LINUX_ENDPOINT_TELEMETRY_CATALOG.md)
* Kernel/distribution results: [LINUX_ENDPOINT_COMPATIBILITY_MATRIX.md](LINUX_ENDPOINT_COMPATIBILITY_MATRIX.md)
* Threats, privacy and self-protection: [LINUX_ENDPOINT_SECURITY_MODEL.md](LINUX_ENDPOINT_SECURITY_MODEL.md)

Status legend: **IMPL** implemented and verified · **PARTIAL** implemented with a documented gap ·
**MISSING** not yet implemented · **UNSUPPORTED** deliberately not provided (see §4).
"Req" is **M** (mandatory for flagship), **S** (should; expected by the industry baseline) or
**O** (optional/differentiator).

The *Baseline* column is the state at `335dae0` (start of this program). The *Current* column is
the state on this branch at the last audit (§5).

## 1. Mechanism properties

Every row in §2 names one or more of these mechanisms. Kernel floor, privilege, performance and
security properties are stated once here instead of being repeated per row.

| Key | Mechanism | Kernel floor | Privilege | Perf notes | Security / accuracy notes |
| --- | --- | --- | --- | --- | --- |
| EBPF-TP | eBPF on BTF tracepoints (`tp_btf`) or classic tracepoints | 5.5 (tp_btf), 4.7 (classic) | CAP_BPF+CAP_PERFMON (5.8+) or CAP_SYS_ADMIN | ~100–300 ns per hit | Stable hook ABI; kernel structs read via CO-RE; cannot be bypassed from user space |
| EBPF-FENTRY | eBPF fentry/fexit on kernel functions | 5.5 x86_64, 6.0 arm64 | as above | lower than kprobe | Function may be inlined/renamed across versions → probed at load |
| EBPF-KPROBE | eBPF kprobes/kretprobes | 4.1+ | as above | ~1 µs per hit | Same instability; fallback for fentry |
| EBPF-LSM | BPF-LSM programs | 5.7 + `CONFIG_BPF_LSM` + `bpf` in active `lsm=` | CAP_BPF+CAP_SYS_ADMIN | per hook | Only mechanism here that can deny an operation in-kernel without a module |
| RINGBUF | `BPF_MAP_TYPE_RINGBUF` | 5.8 | – | shared, ordered | Fallback: per-CPU perf buffer (4.4+), cross-CPU order restored by timestamp |
| CNPROC | netlink proc connector | 2.6.15 | CAP_NET_ADMIN | very low | Lifecycle only; argv/exe must be read from procfs (racy for short-lived) |
| FANOTIFY | fanotify notification / permission | 2.6.37; FID 5.1; DFID_NAME 5.9 | CAP_SYS_ADMIN | moderate under write storms | Permission events can stall I/O if the reader hangs → strict timeouts, fail-open |
| AUDIT | kernel audit multicast | 3.16 (READLOG group) | CAP_AUDIT_READ | rule-dependent | Coexists with auditd via multicast; no syscall rules installed by default |
| JOURNAL | systemd-journald via `sd_journal` | userland | journal read | low | User-space–generated content (spoofable by root); provenance says so |
| PROCFS | `/proc` reads | all | CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH for other users' exe/fd | O(processes) per scan | Snapshot; misses short-lived processes |
| SOCKDIAG | `NETLINK_SOCK_DIAG` | 2.6.x; unix_diag 3.3 | none for dump | low | Snapshot; socket→pid via `/proc/*/fd` inode map |
| RTNL | `NETLINK_ROUTE` multicast | all | none | low | Interface/route/address changes in real time |
| NFNL | nftables netlink monitor | 3.13 | CAP_NET_ADMIN | low | iptables-legacy changes are not visible this way |
| PKGDB | dpkg status / rpm database | userland | read | periodic | rpm via `rpm -qa --qf` in a sandboxed child (no librpm link) |
| FSSCAN | filesystem walk / stat / hash | all | CAP_DAC_READ_SEARCH | budgeted | Point-in-time baseline |
| SYSFS | `/sys` reads | all | none/root | low | Modules, LSM, lockdown, Secure Boot efivars |
| RUNTIME | container runtime on-disk state | userland | root read | low | Read-only; no runtime socket calls |
| UEVENT | `NETLINK_KOBJECT_UEVENT` | all | none | low | Device add/remove |
| PIDFD | `pidfd_open` / `pidfd_send_signal` | 5.3 / 5.1 | CAP_KILL | – | Race-free signalling; fallback is kill() after start-time re-check (documented race window) |
| OPENAT2 | `openat2` RESOLVE_* | 5.6 | – | – | Symlink-safe resolution; fallback is an `O_NOFOLLOW` component walk |
| NFT | nftables via libnftnl (isolation helper) | 3.13 | CAP_NET_ADMIN | – | Built (ADR 004) |

## 2. Capability domains

Columns: **Req** · **Threats** (MITRE ATT&CK where applicable) · **Events/state** (canonical
type names; fields in the catalog) · **Primary** mechanism · **Fallback chain** · **Accuracy
limits** · **Perf** impact · **Privacy** implications · **Test** method · **Baseline** · **Current**.

### A–C. Host identity, OS and posture

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | Host identity (host id, machine-id, hostname, boot id) | M | Spoofed/duplicated sensors | `state.host` | PROCFS + `/etc/machine-id` | DMI product uuid | cloned golden images share machine-id → duplicate detection on (machine-id, enrollment key) | – | low | unit + VM | PARTIAL | PARTIAL |
| A2 | Hardware inventory (CPU, memory, DMI vendor/model/serial, virtualisation) | S | Asset context | `state.host.hardware` | SYSFS dmi + `/proc/cpuinfo`, `/proc/meminfo` | partial if DMI unreadable | serial root-only | – | serial is PII-adjacent | VM | MISSING | MISSING |
| A3 | Network identity (interfaces, MACs, addresses) | M | Correlation, lateral movement | `state.interfaces` | RTNL dump | `/sys/class/net` | – | – | MACs | VM | MISSING | PARTIAL |
| B1 | OS / distribution / version | M | Vulnerability context | `state.host.os` | `/etc/os-release` | `/usr/lib/os-release` | – | – | none | unit | MISSING | MISSING |
| B2 | Kernel version, cmdline, taint | M | Tainted kernel / rootkit | `state.kernel` | PROCFS version, cmdline, `kernel/tainted` | – | – | – | cmdline redaction | unit | PARTIAL | PARTIAL |
| C1 | Security posture: Secure Boot, lockdown, active LSMs, SELinux/AppArmor mode, `kptr_restrict`, `ptrace_scope`, `unprivileged_bpf_disabled`, `modules_disabled`, ASLR, `core_pattern` | M | Weakened defences (TA0005) | `state.posture`, `posture.changed` | SYSFS + PROCFS | each item independently `unknown` | some need root | – | none | unit + VM | MISSING | PARTIAL |
| C2 | Sensor capability report (BTF, BPF features, LSMs, fanotify, audit) | M | Silent coverage loss | `health.coverage` | capability prober | – | – | startup | none | VM matrix | MISSING | PARTIAL |

### D–N. Process, identity and isolation context

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D1 | Fork/clone/vfork | M | Execution (TA0002) | `process.fork` | EBPF-TP `sched_process_fork` | CNPROC → PROCFS reconcile | procfs misses short-lived | low | none | ground truth | MISSING | PARTIAL |
| D2 | Exec | M | T1059, T1204 | `process.exec` | EBPF-TP `sched_process_exec` | CNPROC + procfs read (racy) → reconcile | procfs-sourced argv lost if the process exits first | low | argv redaction | ground truth | PARTIAL | PARTIAL |
| D3 | Exit with code/signal | M | Timeline | `process.exit` | EBPF-TP `sched_process_exit` | CNPROC → reconcile (code unknown) | inferred exits carry no code | low | none | ground truth | MISSING | PARTIAL |
| D4 | Threads (not process starts) | S | Thread injection context | `process.thread_count` | EBPF fork with CLONE_THREAD | CNPROC | – | low | none | ground truth | MISSING | PARTIAL |
| E1 | Process entity identity (boot-scoped, PID-reuse safe) | M | Mis-attribution; PID reuse vs response | every record | entity graph | same algorithm in every provider | – | – | none | PID-reuse ground truth | PARTIAL | PARTIAL |
| E2 | Exec generation | M | Image swap after exec | `process.exec_gen` | entity graph | CNPROC exec | – | – | none | ground truth | MISSING | PARTIAL |
| F1 | Parent / ancestry vector | M | Parent anomalies | `process.ancestry[]` | entity graph | PROCFS ppid | subreaper re-parenting flagged | low | none | ground truth | PARTIAL | PARTIAL |
| F2 | pgid / sid / controlling TTY | S | Interactive attribution | `process.pgid/sid/tty` | EBPF `task->signal` | PROCFS stat | – | low | none | unit | MISSING | PARTIAL |
| G1 | Full argv (bounded, truncation flagged) | M | T1059 | `process.args[]` | EBPF `mm->arg_start..arg_end` | PROCFS cmdline | default cap 4 KiB / 64 args | low | redaction policy | ground truth | PARTIAL | PARTIAL |
| G2 | Executable path, dev/inode, deleted/memfd flags | M | T1036, T1620 | `process.executable` | EBPF `mm->exe_file` dentry walk | PROCFS `exe` readlink + stat | walk capped at 32 components | low | none | ground truth | PARTIAL | PARTIAL |
| G3 | Interpreter/script detection | M | T1059.004/006 | `process.interpreter` | EBPF `bprm->interp` vs `bprm->filename` | argv heuristics | – | low | none | attack sim | MISSING | MISSING |
| G4 | comm, cwd, selected env (LD_PRELOAD, LD_LIBRARY_PATH, PATH) | M | T1574.006 | `process.env` | EBPF env read (allowlisted keys) | PROCFS environ | allowlisted keys only | low | values may be secrets → allowlist | attack sim | MISSING | PARTIAL |
| G5 | stdio types (pipe, socket, tty) | S | Reverse shells | `process.stdio` | PROCFS fd readlink at exec | – | racy for short-lived | low | none | attack sim | MISSING | MISSING |
| H1 | Credentials (r/e/s/fs uid+gid, groups, securebits, no_new_privs) | M | T1548 | `process.creds` | EBPF `task->cred` | PROCFS status | – | low | none | ground truth | PARTIAL | PARTIAL |
| H2 | Credential change with before/after | M | T1548; kernel exploit | `process.cred_change` | EBPF-FENTRY `commit_creds` | CNPROC uid/gid | no capability deltas in fallback | low | none | attack sim | MISSING | PARTIAL |
| I1 | User/group names, login uid, audit session | M | T1078 | `user.*` | passwd/group cache + `loginuid` | – | NSS/LDAP users show uid only | – | usernames | unit | MISSING | PARTIAL |
| J1 | Capability sets | M | T1548; breakout | `process.caps` | EBPF `cred->cap_*` | PROCFS status | – | low | none | ground truth | MISSING | PARTIAL |
| K1 | Namespace inode numbers | M | T1611 | `process.ns` | EBPF `nsproxy` | PROCFS `ns/*` | – | low | none | ground truth | PARTIAL (six inode numbers on the process record from procfs; `ns_change` keeps them current after a move; no time or user namespace) | PARTIALLY VERIFIED: procfs equality verified live; a record's namespaces after setns verified via ns_change test only |
| K2 | Namespace changes (setns/unshare) | M | T1611 | `process.ns_change` | EBPF-FENTRY on namespace switch | reconcile diff | – | low | none | attack sim | PARTIAL (setns/unshare via `switch_task_namespaces`: six namespaces, process or thread scope, one record per setns; user namespaces unavailable; no rate limit) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root (live unshare equals procfs; runc container start; nsenter into container); 6.x, aarch64 NOT YET VERIFIED |
| L1 | cgroup path and systemd unit | M | Attribution | `process.cgroup`, `process.unit` | EBPF cgroup id + PROCFS path | PROCFS cgroup | v1 multi-hierarchy → name=systemd | low | none | VM | PARTIAL | PARTIAL |
| M1 | Container id, runtime, image | M | T1610/T1611 | `container.*` | cgroup parse + RUNTIME | id only | rootless paths vary | low | image names | VM docker+podman | PARTIAL (id and runtime from the cgroup path; no image, name or labels) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root with real docker (cgroup v2, systemd driver); podman, containerd, CRI-O, cgroupfs driver, cgroup v1 covered by unit tests only; aarch64 NOT YET VERIFIED |
| M2 | Container lifecycle | S | T1610 | `container.started/stopped` | derived from first/last process in new container cgroup | RUNTIME poll | derived, not runtime events | low | none | VM | MISSING | MISSING |
| N1 | Kubernetes pod uid/name/namespace | S | Workload context | `container.k8s.*` | RUNTIME CRI annotations | cgroup pod uid | no API server calls | low | labels | VM (optional kind) | PARTIAL (pod uid parsed from kubepods slices; no name or namespace) | PARTIALLY VERIFIED: unit tests on systemd and cgroupfs kubepods layouts; no real cluster |

### O–Y. Image, file, memory, IPC and syscalls

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| O1 | Executable image metadata (ELF class/type/machine, interpreter, setuid bit, owner, mode, mtime, package owner) | M | T1036, T1554 | `process.executable.*` | ELF header via `/proc/pid/exe` | path stat | – | low (cached) | none | unit | MISSING | MISSING |
| P1 | File create / open-for-write | M | T1105, T1486 | `file.create`, `file.modify` | EBPF-FENTRY `security_file_open` (write) + `security_inode_create` | FANOTIFY → FIM diff | modify is per open-for-write, not per write() | med; in-kernel rate limit | paths | attack sim + file storm | MISSING | PARTIAL |
| P2 | Delete / rename / link | M | T1070.004, T1036 | `file.delete`, `file.rename`, `file.link` | EBPF-FENTRY `security_inode_unlink/rename/link` | FANOTIFY DFID_NAME | – | low | paths | attack sim | MISSING | PARTIAL |
| P3 | chmod / chown / setxattr | M | T1222.002 | `file.chmod`, `file.chown`, `file.setxattr` | EBPF-FENTRY `security_path_chmod/chown`, `security_inode_setxattr` | FANOTIFY attrib | fallback lacks old/new values | low | none | attack sim | MISSING | PARTIAL |
| P4 | Sensitive-file reads (shadow, SSH keys, kube/cloud creds) | M | T1003.008, T1552 | `file.open_sensitive` | EBPF-FENTRY `security_file_open` + in-kernel prefix filter | FANOTIFY on watched files | built-in credential list | low | sensitive | attack sim | PARTIAL (open only; fixed list) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root; other platforms NOT YET VERIFIED |
| Q1 | File integrity monitoring (baseline + diff for critical paths) | M | T1543, T1546, T1574 | `fim.changed` | FSSCAN baseline + real-time P1–P3 | FSSCAN periodic | – | budgeted | none | VM | PARTIAL | PARTIAL |
| R1 | Hashing (SHA-256, SHA-1, MD5) of executed images/created executables | M | IOC matching | `*.hash.*` | hash worker | – | large files `hash_pending` | budgeted | none | unit + perf | PARTIAL | PARTIAL |
| S1 | Anonymous executable mappings, mprotect→X, W+X | M | T1055, T1620 | `memory.exec_mapping`, `memory.mprotect` | EBPF-FENTRY `security_mmap_file`, `security_file_mprotect` | PROCFS maps scan | JIT noise → per-image suppression | med | none | attack sim | PARTIAL (anonymous/memfd exec mmap and mprotect-to-exec, one record per process per 5 s; no mmap address, no procfs fallback) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root (live RWX, mprotect, memfd, file-backed not reported); JIT-heavy workloads, 6.x kernels, aarch64 NOT YET VERIFIED |
| T1 | Injection: ptrace attach, `process_vm_writev`, `/proc/pid/mem` write | M | T1055.008/009 | `process.inject` | EBPF-FENTRY `security_ptrace_access_check` + kprobe on `process_vm_rw` | CNPROC ptrace | fallback: attach only | low | none | attack sim | MISSING | PARTIAL |
| U1 | Shared library loads | S | T1574.006 | `library.load` | EBPF-FENTRY `security_mmap_file` (PROT_EXEC, file-backed) | PROCFS maps diff | dedup per (process, inode) | med | none | attack sim | MISSING | MISSING |
| U2 | LD_PRELOAD / `/etc/ld.so.preload` | M | T1574.006 | `process.env`, `fim.changed` | G4 + Q1 | – | – | low | none | attack sim | PARTIAL | PARTIAL |
| V1 | Fileless exec (memfd + execveat, deleted exe, `/dev/shm`) | M | T1620 | `process.exec` (`executable.kind`) | EBPF exec + flags | PROCFS `(deleted)`/`memfd:` | – | low | none | attack sim | PARTIAL (executable.kind from the exe link; an executable memfd mapping is now reported by S1) | PARTIALLY VERIFIED: memfd exec mapping verified live; execveat(memfd) end to end NOT YET VERIFIED |
| W1 | IPC objects (UNIX sockets) | O | Lateral comms | `state.unix_sockets` | SOCKDIAG unix_diag | – | event-level IPC not traced (noise) | – | none | VM | MISSING | MISSING |
| X1 | Fatal signals to non-children / protected processes | S | T1562.001 | `process.signal` | EBPF-TP `signal_generate` filtered | – | – | low | none | attack sim | MISSING | MISSING |
| Y1 | Security syscalls: `init_module`, `bpf`, `perf_event_open`, `keyctl`, `userfaultfd`, `io_uring_setup`, `kexec_load`, `ptrace` | M | T1547.006, T1014, evasion | specific types | EBPF-FENTRY on security hooks | AUDIT if rules exist | io_uring ops bypass syscall hooks (LSM hooks still fire) | low | none | attack sim | PARTIAL (bpf only; perf_event_open, userfaultfd, io_uring_setup, kexec_load, keyctl, module load with actor missing) | PARTIALLY VERIFIED: bpf verified live; others not implemented |

### Z–AD. Network

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Z1 | Outbound TCP connect with process attribution | M | T1071 | `network.connect` | EBPF-FENTRY `tcp_connect` | SOCKDIAG diff + fd scan | fallback misses short connections | low | remote IPs | attack sim | PARTIAL (eBPF hooks plus sockdiag fallback; no inode) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root; 6.x kernels, aarch64 NOT YET VERIFIED |
| Z2 | Inbound accept | M | T1021, backdoors | `network.accept` | EBPF fexit `inet_csk_accept` | SOCKDIAG diff | – | low | remote IPs | attack sim | PARTIAL (eBPF hooks plus sockdiag fallback; no inode) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root; 6.x kernels, aarch64 NOT YET VERIFIED |
| Z3 | UDP flows (first datagram per 5-tuple per process) | S | DNS tunnelling, UDP C2 | `network.udp_flow` | EBPF `udp_sendmsg`/`udpv6_sendmsg` + LRU dedup | SOCKDIAG | 60 s dedup window | med | remote IPs | attack sim | PARTIAL (first datagram per process and destination per 60 s; no DNS names) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root; 6.x kernels, aarch64 NOT YET VERIFIED |
| Z4 | Close with byte counts | S | T1041 | `network.close` | EBPF `tcp_close` (`bytes_acked/received`) | – | – | low | none | VM | MISSING | MISSING |
| Z5 | Raw / packet sockets | S | T1040 | `network.raw_socket` | EBPF `security_socket_create` | – | – | low | none | attack sim | MISSING | MISSING |
| AA1 | Listening sockets (state + listen events) | M | T1205, backdoors | `state.listeners`, `network.listen` | SOCKDIAG + EBPF `security_socket_listen` | PROCFS `/proc/net/*` | – | low | none | VM | PARTIAL | PARTIAL |
| AB1 | Interface/address/route changes | S | T1599 | `network.config_changed` | RTNL multicast | periodic diff | – | low | none | VM | MISSING | MISSING |
| AC1 | Firewall state and changes | M | T1562.004 | `state.firewall`, `firewall.changed` | NFNL monitor | iptables-legacy table hash diff | legacy not decoded | low | none | VM | MISSING | MISSING |
| AD1 | DNS queries/answers with process attribution | M | T1071.004, DGA | `dns.query` | EBPF payload capture on UDP/TCP :53 + user-space parse | – | DoH/DoT invisible (§4) | med | queried names | attack sim | MISSING | MISSING |

### AE–AM. Authentication, accounts and persistence

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AE1 | Authentication success/failure (PAM) | M | T1110, T1078 | `auth.login`, `auth.failure` | AUDIT `USER_AUTH`/`USER_LOGIN`/`USER_START` | JOURNAL → `auth.log`/`secure` tail | text formats vary per distro → per-distro parser tests | low | usernames, IPs | attack sim | MISSING | PARTIAL |
| AF1 | SSH sessions (source, user, method, key fingerprint) | M | T1021.004 | `auth.ssh` | JOURNAL sshd + AUDIT | auth log | – | low | IPs | attack sim | MISSING | PARTIAL |
| AF2 | `authorized_keys` changes | M | T1098.004 | `fim.changed` (class `ssh_keys`) | Q1 | FSSCAN | network-FS homes only by scan | low | none | attack sim | PARTIAL | PARTIAL |
| AG1 | sudo / su / pkexec | M | T1548.003 | `auth.privilege` | AUDIT `USER_CMD` + exec correlation | JOURNAL sudo | – | low | commands | attack sim | MISSING | PARTIAL |
| AH1 | PAM configuration / module changes | M | T1556.003 | `fim.changed` (class `pam`) | Q1 | FSSCAN | – | low | none | attack sim | PARTIAL | PARTIAL |
| AI1 | Account/group create/delete/modify | M | T1136.001, T1098 | `account.*` | AUDIT `ADD_USER`/`DEL_USER`/`USER_MGMT` + passwd/group diff | passwd/group FIM diff (writer from P1) | – | low | usernames | attack sim | MISSING | PARTIAL |
| AJ1 | Credential/secret access | M | T1552, T1555 | `file.open_sensitive` | P4 | – | – | low | sensitive | attack sim | PARTIAL (fanotify inode marks on a fixed credential list; open only, content read not seen) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root; other distros, kernels, aarch64 NOT YET VERIFIED |
| AK1 | systemd units (state + new/changed/enabled) | M | T1543.002 | `state.services`, `persistence.systemd` | Q1 on unit dirs + unit-file parse | JOURNAL | transient D-Bus units seen via cgroup only | low | none | attack sim | PARTIAL | PARTIAL |
| AL1 | cron / at / timers | M | T1053.003/002/006 | `persistence.scheduled` | Q1 on cron/at/timer paths | FSSCAN | – | low | none | attack sim | PARTIAL | PARTIAL |
| AM1 | Other persistence (shell rc, rc.local, init.d, udev, XDG autostart, motd, ld.so.preload, modules-load.d, package-manager hooks) | M | T1546.004, T1037, T1547 | `persistence.*` | Q1 over persistence catalog | FSSCAN | catalog is explicit; unknown locations are a gap | low | none | attack sim | PARTIAL | PARTIAL |

### AN–AW. Software, kernel and platform

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AN1 | Package install/remove events | M | T1072, supply chain | `package.changed` | PKGDB change detection + diff | periodic diff | – | low | none | VM | MISSING | MISSING |
| AO1 | Software inventory (deb, rpm; snap/flatpak optional) | M | Vulnerability management | `state.packages` | PKGDB | – | – | periodic | none | VM | MISSING | MISSING |
| AO2 | Package file verification | S | T1554 | `evidence.package_verify` | dpkg md5sums / `rpm -V` | – | on demand | med | none | VM | MISSING | MISSING |
| AP1 | Kernel module load/unload + inventory + taint | M | T1547.006, T1014 | `kernel.module_load`, `state.modules` | EBPF-FENTRY `do_init_module` + SYSFS | `/proc/modules` diff | – | low | none | attack sim | MISSING | PARTIAL |
| AP2 | Hidden-module cross-view | S | T1014 | `detection` | `/sys/module` vs `/proc/modules` vs kallsyms | – | heuristic | low | none | unit | MISSING | MISSING |
| AQ1 | BPF program/map load + inventory | M | eBPF rootkits | `kernel.bpf_load`, `state.bpf` | EBPF-FENTRY `security_bpf` + `BPF_PROG_GET_NEXT_ID` | periodic enumeration | – | low | none | attack sim | PARTIAL (prog_load, prog_attach, link_create, raw_tracepoint_open events; no state.bpf inventory, no map events) | VERIFIED on Ubuntu 22.04 / 5.15 / x86_64 root (real BPF_PROG_LOAD, type and name); attach commands by unit test only; 6.x, aarch64 NOT YET VERIFIED |
| AR1 | LSM / SELinux / AppArmor state and denials | M | T1562.001 | `posture.changed`, `lsm.denial` | SYSFS + AUDIT AVC/APPARMOR | JOURNAL kernel | – | low | none | VM | MISSING | MISSING |
| AS1 | seccomp mode per process | S | Sandbox context | `process.seccomp` | PROCFS status | – | – | low | none | VM | MISSING | PARTIAL |
| AT1 | Mounts (state + mount/umount events) | M | T1611, T1564 | `state.mounts`, `mount.changed` | EBPF-FENTRY `security_sb_mount` + mountinfo | mountinfo poll (POLLPRI) | – | low | none | attack sim | MISSING | PARTIAL |
| AU1 | USB / removable media | S | T1091, T1052 | `device.attached` | UEVENT | `/sys/bus/usb` diff | – | low | device serials | VM | MISSING | MISSING |
| AV1 | Log tampering (truncate/delete logs, `auditctl -D`) | M | T1070.002 | `file.*` + `audit.config_changed` | P1–P2 on log paths + AUDIT `CONFIG_CHANGE` | FSSCAN | – | low | none | attack sim | MISSING | MISSING |
| AV2 | Selected log forwarding | O | context | `log.record` | JOURNAL | file tail | policy volume cap | med | log content | VM | MISSING | MISSING |
| AW1 | Cloud instance identity (AWS/Azure/GCP) | S | Asset context | `state.cloud` | IMDS (IMDSv2) at start, opt-in | DMI hints | – | – | account ids | mocked IMDS | MISSING | MISSING |
| AW2 | IMDS access by processes | S | T1552.005 | `network.connect` tagged `imds` | Z1 | – | – | low | none | attack sim | MISSING | MISSING |

### AX–BB. Intelligence, forensics, state, prevention and response

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AX1 | Indicator matching (hash, IP, domain, path) from policy | M | IOC hits | `detection` (`ioc.*`) | pipeline matcher | – | bounded set size | low | none | unit | MISSING | MISSING |
| AY1 | Forensic evidence (process, maps, fds, env, sockets, exe copy, persistence, logs, packages, container) | M | Investigation | `evidence.*` | responder + state engine | – | memory capture bounded | on demand | high → audit trail | e2e | PARTIAL | PARTIAL |
| AZ1 | Live host-state query for every §9 object | M | Hunting | `state.*` on demand | state engine + `QUERY_STATE` + `panopticon-ctl query` | – | – | on demand | per object | e2e | MISSING | PARTIAL |
| BA1 | Exec prevention by hash/path | M | T1204 | `prevention.blocked` | EBPF-LSM `bprm_check_security` | FANOTIFY `FAN_OPEN_EXEC_PERM` | fanotify adds exec latency | low | none | attack sim | MISSING | MISSING |
| BA2 | Network destination blocking | S | C2 | `prevention.blocked` | EBPF-LSM `socket_connect` | nft set via helper | – | low | none | attack sim | MISSING | MISSING |
| BA3 | Kernel module / BPF load prevention | S | T1547.006 | `prevention.blocked` | EBPF-LSM `kernel_read_file`, `bpf` | – (detect only) | – | low | none | attack sim | MISSING | MISSING |
| BA4 | Modes off/audit/protect, expiry, kill switch, protected allowlist | M | Safety | `policy.applied` | policy engine | – | – | – | none | unit + VM | PARTIAL | PARTIAL |
| BB1 | Terminate process (pidfd, identity-verified) | M | Containment | `response.result` | PIDFD | kill() after start-time check | fallback race window | – | none | e2e | PARTIAL | PARTIAL |
| BB2 | Terminate process tree | M | Containment | `response.result` | PIDFD stop-then-kill | `cgroup.kill` (5.14) for container scope | – | – | none | e2e | PARTIAL | PARTIAL |
| BB3 | Quarantine / restore | M | Containment | `response.result` | OPENAT2 + quarantine store | `O_NOFOLLOW` walk | – | – | content retained | e2e | PARTIAL | PARTIAL |
| BB4 | Block hash / path | M | Containment | `policy.applied` | BA1 | – | – | – | none | e2e | MISSING | MISSING |
| BB5 | Block network destination | S | Containment | `policy.applied` | BA2 | – | – | – | none | e2e | MISSING | MISSING |
| BB6 | Host isolation / release | M | Containment | `response.result` | NFT helper | – | – | – | none | e2e | IMPL | IMPL |

### BC–BO. Product, reliability and operations

| ID | Capability | Req | Threats | Events/state | Primary | Fallback chain | Accuracy limits | Perf | Privacy | Test | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BC1 | Tamper detection (kill attempts, unit disable, binary/config replacement, BPF detach, WAL deletion) | M | T1562.001 | `tamper.*` | EBPF signal + file hooks on sensor paths; watchdog; self-integrity | FIM of sensor paths | root can stop any agent; detection emitted before death where possible | low | none | attack sim | MISSING | MISSING |
| BC2 | Tamper prevention (protect mode) | S | T1562.001 | `prevention.blocked` | EBPF-LSM `task_kill`, `file_open`, `bpf` | detection only | needs BPF-LSM | low | none | attack sim | MISSING | MISSING |
| BD1 | Per-provider health, coverage, reasons | M | Silent blind spots | `health` | coverage manager | – | – | low | none | VM matrix | PARTIAL | PARTIAL |
| BD2 | Diagnostics bundle | S | Supportability | file | `panopticon-ctl diagnose` | – | redacted | on demand | redaction | e2e | MISSING | MISSING |
| BE1 | Loss accounting (kernel, queue, WAL, shedding) | M | Silent loss | `loss` | counters at every stage | – | – | – | none | perf/chaos | MISSING | PARTIAL |
| BF1 | Durable offline operation (crash-safe WAL, quota, accounted drop) | M | Evidence loss | – | WAL | – | – | budgeted | 0700 state dir | chaos | PARTIAL | PARTIAL |
| BG1 | Secure resilient transport (TLS 1.2+, CA pinning, identity, seq ack, backoff, compression) | M | MITM, loss | – | libcurl | – | – | – | in transit | e2e + chaos | PARTIAL | PARTIAL |
| BG2 | Low latency (p95 host→Manager < 5 s normal load) | S | Timeliness | – | uplink | – | – | – | – | perf | MISSING | MISSING |
| BH1 | Strict config + signed versioned policy | M | Tampering | `policy.applied` | config loader + policy engine | – | – | – | none | unit | PARTIAL | PARTIAL |
| BI1 | Update / rollback | M | Bricked fleet | `sensor.updated` | package + rollback check | – | – | – | none | VM | MISSING | MISSING |
| BJ1 | deb/rpm, systemd units, SBOM, signing | M | Supply chain | – | CPack + scripts | – | signing key is a release secret | – | none | VM install | MISSING | MISSING |
| BK1 | Kernel/distro compatibility with per-capability fallback | M | Silent failure | `health.coverage` | prober | – | – | – | none | matrix | MISSING | MISSING |
| BL1 | Performance budgets and governor | M | Host destabilisation | `health.resources`, `loss` | governor | – | – | – | none | perf | MISSING | MISSING |
| BM1 | Recovery (crash restart, WAL replay, re-attach, resync) | M | Gaps after crash | `sensor.started` | systemd + WAL + reconcile | – | – | – | none | chaos | PARTIAL | PARTIAL |
| BN1 | Test infrastructure (unit, ground truth, attack, fuzz, chaos, matrix) | M | Regressions | – | – | – | – | – | – | CI + VM | PARTIAL | PARTIAL |
| BO1 | Hardening (systemd sandboxing, capability bounding, FORTIFY, PIE/RELRO/NX, stack protector, no shell-outs) | M | Sensor as attack surface | – | build + units | – | – | – | – | checksec + review | PARTIAL | PARTIAL |

### Additional categories found during research

| ID | Capability | Req | Why added | Primary | Baseline | Current |
| --- | --- | --- | --- | --- | --- | --- |
| EX1 | io_uring visibility | S | io_uring operations bypass syscall-level hooks — a publicly demonstrated EDR blind spot in 2025; LSM/security hooks still fire for file and network operations issued through it | security_* fentry/LSM hooks rather than syscall hooks; `io_uring_setup` recorded | MISSING | MISSING |
| EX2 | Clock tampering | O | Timeline integrity | EBPF `security_settime64` | MISSING | MISSING |
| EX3 | Core dumps and `core_pattern` changes | S | Credential dumping via cores; `core_pattern` persistence | C1 re-poll + CNPROC coredump | MISSING | MISSING |
| EX4 | Sysctl changes | S | Posture weakening | C1 re-poll + file hooks on `/proc/sys` | MISSING | MISSING |
| EX5 | Reverse-shell composite | M | Very common intrusion step | G5 + Z1 → local rule | MISSING | MISSING |
| EX6 | comm/argv rewrite masquerade (`prctl(PR_SET_NAME)`) | S | T1036.004 | `task_rename` tracepoint | MISSING | PARTIAL |
| EX7 | Clock domain alignment (boot-time ns → wall clock) | M | Timeline correctness across providers | periodic `CLOCK_BOOTTIME`↔`CLOCK_REALTIME` sampling | MISSING | PARTIAL |

## 3. Per-capability completion rule

A row moves to **IMPL** only when all of the following are true and recorded in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md):

1. The primary mechanism is implemented and its test passes on at least two kernels (one ≤ 5.15,
   one ≥ 6.1).
2. Every listed fallback is implemented, or the row stays PARTIAL with the missing fallback named.
3. The provider reports health, coverage and loss for it.
4. The telemetry catalog documents every emitted field.
5. Manager stores it and the Detection Engine consumes it (cross-repo fixture test).

## 4. Unsupported capabilities and justifications

| Capability | Decision | Justification |
| --- | --- | --- |
| Kernel-module collection | Not provided | eBPF reaches the same hooks with verifier-enforced safety; kernel modules are the main host-crash risk in this product class (competitor analysis §3). |
| Full packet capture / payload inspection | Not provided | Network-sensor territory; DNS is the only payload parsed. |
| DoH / DoT query contents | Not observable | Encrypted in user space; only the connection to the resolver is seen. uprobes on TLS libraries rejected for stability and privacy. |
| File-modification rollback (VSS-like) | Not provided | No portable Linux snapshot primitive; SentinelOne documents rollback as Windows-only for the same reason. |
| Full memory dumps | Restricted | Bounded region capture on explicit command only. |
| Signature AV engine | Not provided in-agent | Hash/IOC matching is provided; a scanning engine is out of scope. |

## 5. Audit log

| Date | Commit | Run | Summary |
| --- | --- | --- | --- |
| 2026-10-06 | 335dae0 (baseline) | 0 | 1 IMPL (host isolation), 18 PARTIAL, the rest MISSING. Weakest subsystem: everything continuous — there is no resident sensor. |
| 2026-10-06 | S1 (resident sensor core) | 1 | Resident `panopticon-sensord` with CNPROC lifecycle + procfs enrichment/reconcile, entity graph, endpoint/1.0 serializer, CRC-checked WAL, provider health and loss records. 17 rows moved MISSING → PARTIAL (C2, D1, D3, D4, E2, F2, G4, H2, I1, J1, K1, T1, V1, AS1, BE1, EX6, EX7) and 11 baseline-PARTIAL rows (D2, E1, F1, G1, G2, H1, L1, BD1, BF1, BM1, BN1) now have resident, real-kernel evidence — fallback mechanisms only; every primary eBPF mechanism is S2. Totals: 1 IMPL, 38 PARTIAL, 75 MISSING. (Correction to run 0: the Baseline column holds 21 PARTIAL, not 18.) Still 1 IMPL: no row satisfies rule §3.1 (primary mechanism on two kernels) or §3.5 (Manager + Detection Engine consumption). Weakest subsystem now: kernel-level visibility (no eBPF) and everything beyond process lifecycle. |
| 2026-10-06 | S2 (eBPF process provider) | 2 | Primary eBPF mechanisms for D1, D2, D3, E2, G1, H2, EX6 and T1 (ptrace access check only; `process_vm_*` and `/proc/<pid>/mem` hooks are S7) now exist and pass real-kernel ground truth on 5.15 (`panopticon-ebpf-tests` 12/12; ASAN, UBSAN, TSAN clean; fork storm 0 losses). **No status changes**: every one of those rows was already PARTIAL and rule §3.1 needs the primary mechanism on two kernels plus Manager/Detection Engine acceptance, and only 5.15 has been run. Gaps named: aarch64 has no `vmlinux.h`, so eBPF is x86_64 only; optional-hook loss leaves capability uncovered; start-ticks conversion ignores time-namespace offsets; short-lived exec paths are the raw `execve` string. Totals unchanged: 1 IMPL, 38 PARTIAL, 75 MISSING. Next-weakest: everything uplink-related (S3) and all non-process telemetry (S5–S7). |
| 2026-10-06 | S4 (host-state engine, control socket) | 3 | Inventory collectors for host, posture, users, groups, interfaces, mounts and modules emit `state.<object>` records at start and every state interval, and are served on demand through the 0600 control socket (`panopticon-ctl state <object>`). 5 rows moved MISSING → PARTIAL (A3, C1, AP1, AT1, AZ1); A1 gains real state evidence. Every one is fallback-grade (procfs/sysfs/etc reads, `getifaddrs`): no RTNL dump, no change events (`posture.changed`, `kernel.module_load`, `mount.changed` are S7), and `QUERY_STATE` is local only until the Manager command channel (S3/S9) exists. 8 state tests, 9 control tests and a pipeline emission test pass; ASAN, UBSAN and TSAN clean on 5.15 only. Totals: 1 IMPL, 43 PARTIAL, 70 MISSING. Next-weakest: uplink (S3) and all non-process event telemetry (S5-S7). |
| 2026-10-06 | S5.1 (fanotify file telemetry) | 4 | `fanotify_file` provider (FID + DFID_NAME, filesystem marks, handle-resolved paths, rename pairing, governor, hostile-buffer decoder) emits `file.create/modify/delete/rename/attrib` with actor and post-event stat. P1, P2 and P3 MISSING to PARTIAL via the fallback mechanism only (ADR 009); the eBPF fentry primaries, `file.link`, distinct chmod/chown/setxattr and sensitive-read events (P4) remain. Live ground truth on 5.15 (create, close-write, rename pairing incl. a 100-rename burst, chmod, mkdir, unlink, rmdir, exclusion, own-pid filtering); decoder fuzzed with 40000 mutations; ASAN+UBSAN and TSAN clean. Totals: 1 IMPL, 46 PARTIAL, 67 MISSING. |
| 2026-10-06 | S5.2 (persistence catalog, FIM) | 5 | `persistence_catalog` (16 categories, system and per-user paths, hostile-input handling, secrets never emitted) emits `state.persistence`; `fim_monitor` keeps a persisted baseline, reports offline changes at start, rescans periodically and re-describes event-named paths after a debounce with the actor attached (ADR 010). Q1, U2, AF2, AH1, AK1, AL1, AM1 MISSING to PARTIAL (FSSCAN mechanism); AI1 fallback only (passwd/group diff; the audit primary is missing). Not yet: eBPF write hooks give no writer identity at the instant of the write, no `state.services`, `state.scheduled` (timers, at), package-manager integrity, process environment for U2 (G4). Live on 5.15: cron file added and removed, `.bashrc` modified, each attributed to the writing process. Totals: 1 IMPL, 54 PARTIAL, 59 MISSING. |
| 2026-10-06 | S6.1 (network telemetry, sock_diag fallback) | 6 | `sockdiag_network` provider (family `network`): IPv4/IPv6 TCP and UDP tables over NETLINK_SOCK_DIAG, hostile-reply decoder, a bounded snapshot-diff tracker, inode-to-pid attribution within a time budget, `network.connect/accept/listen` (ADR 011). Z1 and Z2 MISSING to PARTIAL via the fallback only; AA1 stays PARTIAL (`network.listen` exists, `state.listeners` does not). Short-lived connections are missed and ownerless sockets are reported unattributed, so no row can be IMPL before the eBPF primaries. Totals: 1 IMPL, 56 PARTIAL, 57 MISSING. |
| 2026-10-06 | S7.1 (authentication telemetry, log fallback) | 7 | `auth_log` provider (family `auth`): rotation-safe tailer, hostile-line parser for sshd, sudo, su, pkexec and console login, `auth.login/failure/privilege` (ADR 012). AE1, AF1 and AG1 MISSING to PARTIAL via the fallback only. Reported by a program, delayed by syslog, actor usually gone, so none can be IMPL before the audit multicast primary. Totals: 1 IMPL, 59 PARTIAL, 54 MISSING. |
| 2026-10-06 | S7.2 (authentication telemetry, audit primary) | 8 | `audit_netlink` provider joins the kernel audit read-log group (read-only, no rules), kernel-only sender check, bounded datagram decoder, quote- and hex-aware tokenizer where the kernel header wins over sender text; `USER_LOGIN`, `USER_AUTH` failure, `USER_CMD`, `su` session (ADR 013). The pipeline prefers it and keeps `auth_log` on standby, so nothing is reported twice. AE1, AF1 and AG1 have both mechanisms and stay PARTIAL: one kernel (5.15) and one distro format, no `auth.logout` or session ids, and AG1 has no exec correlation yet. Totals unchanged: 1 IMPL, 59 PARTIAL, 54 MISSING. |
| 2026-10-06 | S7.3 (kernel module and mount events, snapshot diff) | 9 | `kernel_change` provider: pure snapshot tracker over `/proc/modules` and mountinfo, first snapshot is state, bounded snapshots (a list at the limit is not diffed), governor on bursts, hostile mount paths stay escaped (ADR 014). AP1 and AT1 already PARTIAL via state inventories; they gain `kernel.module_load/unload` and `mount.changed` through the fallback, but have no actor and miss changes shorter than the 1 s poll, so neither can be IMPL before the eBPF hooks. Totals unchanged: 1 IMPL, 59 PARTIAL, 54 MISSING. |
| 2026-10-06 | S9.1 (pidfd responder) | 10 | `response` module (ADR 015): pidfd taken before identity verification, signals only through `pidfd_send_signal`, verified `kill()` fallback reported in the outcome, protected set (init, kernel threads, the agent and its ancestors), dry run by default, SIGTERM with optional SIGKILL escalation, tree kill that stops then kills and refuses on any protected member. BB1 stays PARTIAL (no second kernel, `cgroup.kill` and nothing calls it automatically yet); BB2 moves MISSING to PARTIAL. Totals: 1 IMPL, 60 PARTIAL, 53 MISSING. |
| 2026-10-06 | S8.1 (policy engine core) | 11 | `policy_engine` (ADR 016): strict policy file, indicator sets for hash, address, domain and path, regex-free rules, allow list, bounded decisions, recommendations only. BA4 moves MISSING to PARTIAL (allow list and decisions exist; modes, expiry and kill switch do not). Not wired into the pipeline until the schema decision (S3). Totals: 1 IMPL, 61 PARTIAL, 52 MISSING. |
| 2026-10-06 | S3.1 (wire schema) | 12 | Strict Linux endpoint record 1.0 schema, fixtures and validator in `panopticon-contracts` (ADR 017), validated on 508 real records / 28 types. No capability row changes status: the schema describes what is emitted; no consumer reads it yet. Six record types have no real sample. Totals: 1 IMPL, 61 PARTIAL, 52 MISSING. |
| 2026-10-06 | S3.2 (uplink, Manager ingest) | 13 | `uplink` delivers durable WAL records to the Manager route over HTTPS with the cursor moving only on a batch-matching acknowledgement, exponential backoff with jitter, 413 batch shrinking, and quarantine of records the Manager rejects (ADR 018); the Manager stores Linux records per stream with contiguous-prefix and missing-range accounting (Manager ADR 007). BF1 and BG1 gain real evidence (a real run from the VM against the real Manager, including an outage and recovery) but **stay PARTIAL**: no compression, no pinning beyond a private CA, no Manager-initiated command channel, no Detection Engine or Console consumption, one kernel. BG2 (latency) is unmeasured and stays MISSING. The first real run found a producer/contract bug (`"process":{}` on records with an unknown owner), fixed in the serializer and covered by a regression assertion; one record from the earlier run was quarantined and shows as the single stream gap. Totals: 1 IMPL, 61 PARTIAL, 52 MISSING. |