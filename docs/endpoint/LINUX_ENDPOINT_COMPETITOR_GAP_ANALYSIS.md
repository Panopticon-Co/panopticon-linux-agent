# Linux Endpoint Competitor Analysis and Gap Analysis

Research date: 2026-10-06. Every claim cites a public source. Vendors document their Linux
internals unevenly; where a vendor does not publish something, the cell says **not public**
rather than guessing. The final section compares Panopticon against this baseline and is re-run
at every audit.

## 1. Industry baseline in one paragraph

Serious Linux EDRs have converged on the same shape: **user-space agent + eBPF sensor**, a
**fallback** for kernels where eBPF is missing (kernel module, netlink, audit, tracefs or a
"reduced functionality" mode), **process / file / network** telemetry with process attribution,
**authentication and persistence** visibility from logs and file monitoring, **host isolation**,
**process kill**, **file quarantine/collection**, **live response**, **health reporting with
explicit degraded states**, and **vendor-managed kernel compatibility**. Differentiators are
coverage of in-memory/fileless techniques, container context, in-kernel filtering and
enforcement, and how honestly degraded coverage is reported.

## 2. Product-by-product findings

### 2.1 Microsoft Defender for Endpoint (Linux)

| Question | Finding |
| --- | --- |
| Collects | Process, file and socket events for EDR; real-time AV ([MDE Linux](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux)) |
| From | eBPF "supplementary event provider", default since 101.23082.0006; no kernel module ([eBPF sensor](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf)) |
| When eBPF is unavailable | Falls back to **Netlink**: process events (exec, exit, fork, gid, tid) continue; **file (rename, unlink) and socket events are lost**. AuditD provider removed in 101.2408.0000 |
| Detects / prevents | Behaviour monitoring, cloud ML, real-time AV, file indicators |
| Responds | Live Response (scripts, kill, delete, evidence), device isolation, investigation package, remote scan |
| Kernel compatibility | Published minimums, e.g. RHEL/CentOS 7.6 (3.10.0-957), Ubuntu 16.04 (4.15), Debian 9 (4.19), AL2 (5.4.261), Rocky/Alma 9.2 (5.14.0-284). Documented eBPF kernel panics on RHEL 8.1 + SAP and on specific Oracle UEK 5.15 builds |
| High event rates | `mdatp diagnostic ebpf-statistics` reports top syscalls/paths/initiators; exclusions applied backend-side |
| Updates | Monthly releases; each expires after nine months |
| Self-reporting | `mdatp health` exposes `supplementary_events_subsystem` (ebpf/netlink) |

### 2.2 CrowdStrike Falcon (Linux)

| Question | Finding |
| --- | --- |
| From | **Kernel mode** (kernel module with per-kernel support) or **user mode** (eBPF) |
| When unavailable | **Reduced Functionality Mode**: if the kernel is neither supported in kernel mode nor meets user-mode requirements, the sensor stops processing events and detections but keeps sending heartbeats ([Duke OIT](https://oit.duke.edu/help/articles/kb0038677/), [Prelude](https://www.preludesecurity.com/blog/crowdstrike-reduced-functionality-mode-rfm)) |
| Known incident | 2024: the eBPF user-mode sensor triggered a kernel BPF bug that crashed RHEL 9.4 hosts (kernel-side bug fixed by Red Hat) — eBPF reduces but does not remove host-crash risk |
| Internals | **Not public** (customer portal only) |

### 2.3 SentinelOne (Linux)

| Question | Finding |
| --- | --- |
| From | User-space agent with eBPF probes; no kernel module ([SentinelOne Linux datasheet](https://go.sentinelone.com/rs/327-MNM-087/images/Linux.pdf)) |
| Responds | Remote shell, firewall control, network isolation, file fetch ([Help Net Security](https://www.helpnetsecurity.com/?p=107397)) |
| Limits | Rollback (VSS-based) is Windows-only |

### 2.4 Elastic Defend (Linux)

| Question | Finding |
| --- | --- |
| From | eBPF on kprobes/tracepoints/ftrace hooks with a BPF ring buffer on newer kernels; **tracefs** on older kernels ([elastic/ebpf events doc](https://github.com/elastic/ebpf/blob/main/docs/events.md)) |
| Process model | Open-source **quark**: EBPF backend falling back to KPROBE; process cache seeded by scraping `/proc`; keeps exited processes briefly so late lookups succeed; per-field availability flags; lost-event counters; ordered delivery ([elastic/quark](https://github.com/elastic/quark)) |
| Isolation | eBPF is also used for host isolation |
| Lesson | Same pattern adopted here: procfs-seeded cache, exit grace window, per-field availability, loss counters |

### 2.5 Sophos (Protection for Linux / Linux Sensor)

| Question | Finding |
| --- | --- |
| Detects | Runtime detection without a kernel module: container escapes, kernel exploits, privilege escalation ([Sophos RTD](https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/ServerProtection/ServerConfigureLinuxRTD/index.html)) |
| Internals | **Not public** |

### 2.6 Trellix (Endpoint Security for Linux / HX)

| Question | Finding |
| --- | --- |
| Capabilities | NGAV, EDR, host firewall, device control; EDR forensics modules Logon Tracker, Process Tracker and Host Remediation span Linux ([Trellix EDRF](https://docs-dr.trellix.com/docs/edrf-50-1-0)) |
| Internals | **Not public** |

### 2.7 Broadcom / Symantec Endpoint Security (Linux)

| Question | Finding |
| --- | --- |
| From | Kernel modules `sisevt` and `sisap` for real-time file scanning; `sisidsagent` for EDR ([Broadcom KB 279969](https://knowledge.broadcom.com/external/article/279969/what-modules-and-services-does-endpoint.html)) |
| Lesson | Kernel-module dependence implies per-kernel support lag |

### 2.8 Carbon Black Cloud (Linux)

| Question | Finding |
| --- | --- |
| From | Kernel module below 4.8; **BPF** from 4.8; BTF from sensor 2.15, otherwise kernel headers required ([CBC install guide](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/cbc-sensor-installation-guide/GUID-4343A65E-94B7-4A66-A68E-0EB1F0061663.html)) |
| Requirements | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_BPF_EVENTS` |
| SELinux | BPF collection needed an SELinux policy allowance ([Broadcom KB 292463](https://knowledge.broadcom.com/external/article/292463/carbon-black-cloud-how-to-allow-bpf-even.html)) — we must test RHEL with SELinux enforcing |

### 2.9 Trend Micro Vision One / Deep Security (Linux)

| Question | Finding |
| --- | --- |
| From | Per-kernel **kernel support packages**; unsupported kernel → Activity Monitoring **basic** mode ([Trend docs](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-activity-monitoring-basic)) |
| Basic mode | Keeps process create/terminate and network in/out; **loses file create/open and DNS query** |
| Other | Integrity monitoring of files, services, processes, installed software, ports |
| Lesson | The vendor publishes exactly which event types are lost when degraded — we do the same per capability |

### 2.10 Palo Alto Cortex XDR (Linux)

| Question | Finding |
| --- | --- |
| From | **Kernel mode** (module) or **user mode** (eBPF, kernel ≥ 5.0) with configurable fallback; equivalent protection claimed ([Cortex XDR for Linux](https://cortex-docs.paloaltonetworks.com/cortex-xdr-agent/9.0/cortex-xdr-agent-for-linux)) |
| Prevents | Exploit protection, malware protection |
| Responds | Live Terminal (files, processes, OS/Python commands; download ≤ 200 MB, upload ≤ 40 MB; agent 7.0+), isolation (7.7+) |

### 2.11 Rapid7 Insight Agent (Linux)

| Question | Finding |
| --- | --- |
| From | **auditd**: process-start events require auditd in a compatibility mode with an af_unix plugin ([Rapid7 auditd compatibility](https://docs.rapid7.com/insight-agent/auditd-compatibility-mode-for-linux-assets/)) |
| Lesson | Audit-only collection limits coverage and interferes with existing audit configuration — Panopticon never takes ownership of auditd |

### 2.12 Open-source and research systems

| Project | Collects / does | Degradation | Lessons |
| --- | --- | --- | --- |
| **Falco** | Syscall stream evaluated by rules; modern eBPF (kernel ≥ 5.8, ring buffer + BTF) or kernel module ([Falco kernel sources](https://falco.org/docs/concepts/event-sources/kernel/)) | Driver choice; drop actions | Modern probe runs with `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_PTRACE` |
| **Tetragon** | Process lifecycle, syscalls, file/network I/O, credentials, namespaces, capabilities; Kubernetes-aware ([overview](https://tetragon.io/docs/overview/)) | – | **In-kernel filtering and enforcement** (SIGKILL, return override, BPF-LSM); warns that low-level policies risk TOCTOU ([TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/)) |
| **Tracee** | Syscalls, network (DNS/HTTP/TCP/UDP/ICMP), LSM hooks, container lifecycle; behavioural events: fileless exec, dropped executables, LD_PRELOAD, hooked syscall table, hidden modules, ptrace/process_vm_write injection ([events](https://aquasecurity.github.io/tracee/latest/docs/events/)) | – | Its behavioural set is our attack-simulation checklist |
| **osquery** | SQL over host state: processes, users, listening ports, kernel modules, packages, crontab, systemd units, authorized_keys, mounts, containers; audit/eBPF event tables | – | "What exists now" is a first-class query surface → our `QUERY_STATE` |
| **Wazuh** | FIM (inotify real-time; audit "whodata" for attribution), Syscollector inventory, rootcheck, SCA, active response, log collection ([capabilities](https://documentation.wazuh.com/current/user-manual/capabilities/index.html)) | – | FIM attribution needs a kernel source; we attribute through eBPF |
| **Linux Audit** | Syscall records and user-space records (PAM, shadow-utils) | – | PAM and account-management records come from user space through audit; read via multicast, never own auditd |

## 3. Industry capability matrix

Legend: ● documented · ◐ partial or degraded · ○ not provided · ? not public.

| Capability | MDE | CrowdStrike | S1 | Elastic | Cortex | Trend | CB | Rapid7 | Falco | Tetragon | Tracee | osquery | Wazuh |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Collection without kernel module | ● | ● (user mode) | ● | ● | ● (user mode) | ? | ● (≥4.8) | ● (audit) | ● | ● | ● | ● | ● |
| Explicit degraded-mode reporting | ● | ● (RFM) | ? | ? | ● | ● | ? | ? | ◐ | ○ | ○ | ○ | ○ |
| Process lifecycle | ● | ● | ● | ● | ● | ● | ● | ◐ | ● | ● | ● | ● | ◐ |
| File events with attribution | ● | ● | ● | ● | ● | ● | ● | ○ | ● | ● | ● | ◐ | ● |
| Network with attribution | ● | ● | ● | ● | ● | ● | ● | ? | ● | ● | ● | ◐ | ○ |
| DNS | ? | ? | ? | ● | ? | ● (full mode) | ? | ? | ◐ | ◐ | ● | ○ | ○ |
| Authentication / logins | ● | ? | ? | ● | ? | ? | ? | ● | ◐ | ○ | ○ | ● | ● |
| Persistence visibility | ? | ? | ? | ● | ? | ● (integrity) | ? | ? | ◐ | ◐ | ◐ | ● | ● |
| Container context | ? | ? | ● | ● | ? | ? | ? | ? | ● | ● | ● | ● | ◐ |
| In-memory / injection | ● (claim) | ? | ? | ● | ● (exploit prot.) | ? | ? | ○ | ◐ | ● | ● | ○ | ○ |
| Exec prevention / blocking | ● (indicators) | ? | ? | ● | ● | ? | ? | ○ | ○ | ● | ○ | ○ | ◐ |
| Kill process | ● | ? | ? | ● | ● | ? | ? | ? | ○ | ● | ○ | ○ | ● |
| File collection / quarantine | ● | ? | ● | ● | ● | ? | ? | ? | ○ | ○ | ○ | ◐ | ◐ |
| Host isolation | ● | ? | ● | ● | ● | ? | ? | ? | ○ | ○ | ○ | ○ | ◐ |
| Live response | ● | ? | ● (shell) | ● | ● (terminal) | ? | ? | ? | ○ | ○ | ○ | ● (query) | ○ |
| Host-state query / inventory | ● (TVM) | ? | ? | ◐ | ? | ● | ? | ? | ○ | ○ | ○ | ● | ● |

"?" means the vendor's public documentation reviewed here does not state it for Linux, not that
the product lacks it.

## 4. Requirements derived for Panopticon

1. **Name and publish degraded modes per capability** (Trend basic mode, MDE netlink fallback,
   CrowdStrike RFM) → capability matrix + `health.coverage`.
2. **Netlink proc connector** fallback for process lifecycle (MDE) and a **procfs-seeded process
   cache with an exit grace window** (quark).
3. **fanotify** file fallback so file visibility does not vanish without eBPF (MDE loses it).
4. **SELinux-enforcing** compatibility tests (Carbon Black needed a policy change).
5. **eBPF can still crash kernels** (CrowdStrike/RHEL 9.4; MDE known issues) → per-family kill
   switch, known-bad-kernel deny list, staged rollout.
6. **Never take over auditd** (Rapid7) → audit multicast only.
7. **In-kernel filtering** on high-rate hooks (Tetragon/Falco).
8. **Live response** is table stakes; Panopticon provides typed, audited actions and state
   queries instead of an arbitrary root shell (§5).

## 5. Panopticon comparison (re-run every audit)

| Area | Status | vs. baseline |
| --- | --- | --- |
| Collection | one-shot procfs snapshot | **weaker** |
| Degraded-mode reporting | none | **weaker** |
| Process model | pid + start ticks, no boot id | **weaker** |
| Isolation | nftables helper, privilege-separated | **equal** |
| Arbitrary remote shell | deliberately not provided | **weaker by design** — a remote root shell is the highest-value target in an EDR |
| Rollback | not provided | equal to the Linux baseline |

| Date | Commit | Summary |
| --- | --- | --- |
| 2026-10-06 | 335dae0 | Weaker in every telemetry domain; equal only in host isolation. |
