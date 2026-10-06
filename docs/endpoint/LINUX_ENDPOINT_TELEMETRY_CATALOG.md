# Linux Endpoint Telemetry Catalog — `panopticon.endpoint/1.0`

The canonical record model produced by the Linux endpoint. The machine-readable definition is
`panopticon-contracts/schema/linux-endpoint/1.0.schema.json` (JSON Schema 2020-12); this document explains it.
Implementation state per type is tracked in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## 1. Principles

1. **Record kinds are separate.** Raw provider data never leaves the sensor. What leaves is one
   of `event` (something happened), `state` (what exists now), `health`, `loss`, `detection`,
   `evidence`, `response` and `policy`. Detections never masquerade as telemetry and telemetry
   never masquerades as state.
2. **Provenance is mandatory.** Every record names its provider and mechanism and a confidence:
   `observed` (kernel hook), `reconstructed` (rebuilt from a snapshot, e.g. a process found by a
   procfs scan), `inferred` (deduced, e.g. an exit inferred from absence) or
   `user_space_reported` (from logs written by user space).
3. **Absence is explicit.** A field the provider could not supply is listed in `unavailable`
   with a reason code; it is never zero-filled or guessed.
4. **Identity is entity-based.** Processes, files and containers carry entity ids; PIDs are
   attributes.
5. **Sequence is contiguous.** `seq` is per sensor, starts at 1, increases by exactly one per
   record and survives restarts (persisted by the WAL). A gap at Manager is either a reported
   `loss` record or tampering.

## 2. Envelope

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | `"1.0"` | Model version |
| `record_type` | enum | `event`, `state`, `health`, `loss`, `detection`, `evidence`, `response`, `policy` |
| `id` | 32 hex | `SHA-256(sensor_id ‖ boot_id ‖ seq)` truncated; deterministic |
| `seq` | uint64 ≥ 1 | Per-sensor contiguous sequence |
| `type` | string | Dotted type, e.g. `process.exec` (§4) |
| `time` | RFC 3339 UTC, ns | When it happened (kernel boot-time clock converted to wall clock) |
| `observed_time` | RFC 3339 UTC, ns | When the sensor processed it |
| `host` | object | `id`, `boot_id`, `hostname` |
| `sensor` | object | `id`, `version`, `policy_version` |
| `provenance` | object | `provider` (`ebpf`, `netlink_proc`, `procfs`, `fanotify`, `audit`, `journal`, `inventory`, `sensor`), `mechanism` (hook or source), `confidence` |
| `unavailable` | array | `{field, reason}`; reasons: `not_supported_by_provider`, `process_exited`, `permission_denied`, `truncated`, `budget_exceeded`, `not_applicable`, `kernel_feature_missing`, `object_gone` (a file or directory no longer existed when it was resolved) |
| family objects | object | `process`, `parent`, `target`, `file`, `network`, `dns`, `auth`, `account`, `persistence`, `package`, `kernel`, `mount`, `device`, `container`, `state`, `health`, `loss`, `detection`, `evidence`, `response`, `policy`, `tamper` |

## 3. Shared objects

### 3.1 `process`

| Field | Type | Source (primary / fallback) | Notes |
| --- | --- | --- | --- |
| `entity_id` | 32 hex | entity graph | `SHA-256(host_id ‖ boot_id ‖ tgid ‖ start_ticks)` truncated |
| `exec_gen` | uint | entity graph | 0 before the first observed exec |
| `pid` | uint | kernel tgid / procfs | host pid namespace |
| `vpid` | uint | innermost-namespace pid / `NSpid` | |
| `ppid` | uint | `real_parent` tgid / stat | |
| `start_time` | RFC 3339 | `task->start_time` / stat starttime | |
| `start_ticks` | uint | normalised to `CLK_TCK` | identity input |
| `name` | string ≤ 15 | `task->comm` / `/proc/pid/comm` | never derived from the exe path |
| `state` | string | stat state letter | `R`, `S`, `D`, `Z`, … at observation time |
| `kernel_thread` | bool | `PF_KTHREAD` in stat flags | kernel threads have no executable or args |
| `threads` | uint | stat `num_threads` | at observation time |
| `confidence` | object | `identity`, `attributes` | identity can be `observed` while attributes copied from the parent at fork are `inferred` until exec or reconcile |
| `executable` | object | §3.2 | |
| `args` | string[] | `mm->arg_start..arg_end` / cmdline | bounded (64 args, 4 KiB) |
| `args_truncated` | bool | | |
| `cwd` | string | `/proc/pid/cwd` | |
| `interpreter` | string | `bprm->interp` when it differs from `bprm->filename` | scripts, `ld.so` invocations |
| `creds` | object | `uid euid suid fsuid gid egid sgid fsgid groups[] loginuid sessionid` | |
| `caps` | object | `effective permitted inheritable bounding ambient` as 16-hex masks | |
| `ns` | object | `mnt pid net user uts ipc cgroup` inode numbers | |
| `cgroup` | string | `/proc/pid/cgroup` (v2 path or v1 `name=systemd`) | |
| `unit` | string | parsed from cgroup | systemd unit |
| `tty` | string | stat `tty_nr` | |
| `pgid`, `sid` | uint | stat | |
| `env` | object | allowlisted keys only | |
| `user` | object | `name`, `group` | resolved from uid/gid |
| `container` | object | §3.4 | |
| `ancestry` | array | up to 8 `{entity_id, pid, name, executable}` | nearest first |
| `exit_code`, `exit_signal`, `core_dumped` | int / bool | exit events only | decoded from the kernel wait status |

Event-level fields alongside `process`: `previous_executable` (exec: the image the entity ran
before this exec), `previous_name` (`process.rename`), `creds_before` (`process.cred_change`),
`technique` (`process.inject`).

### 3.2 `executable` / `file`

| Field | Type | Notes |
| --- | --- | --- |
| `path` | string | as resolved; `kind` qualifies it |
| `kind` | enum | `file`, `deleted`, `memfd`, `anonymous`, `unknown` |
| `dev`, `inode` | uint | identity |
| `size`, `mode`, `uid`, `gid` | | `fstat` on the opened handle |
| `mtime`, `ctime` | RFC 3339 | |
| `setuid`, `setgid` | bool | |
| `hash` | object | `sha256`, `sha1`, `md5`, `status` (`computed`, `pending`, `too_large`, `unreadable`, `skipped`) |
| `elf` | object | `class`, `machine`, `type`, `interp` |
| `package` | object | owning package `name`, `version` |

### 3.3 `network`

`transport` (`tcp`, `udp`), `family` (`ipv4`, `ipv6`), `direction` (`outbound`, `inbound`,
`listen`), `local {ip, port}`, `remote {ip, port}`, `bytes_sent`, `bytes_received`,
`socket_inode`, `tags[]` (e.g. `imds`, `loopback`).

### 3.4 `container`

`id`, `runtime` (`docker`, `containerd`, `cri-o`, `podman`, `unknown`), `image`, `image_id`,
`k8s {pod_uid, pod_name, namespace}`.

## 4. Event types

| Type | Family objects | Primary provider | Fallback |
| --- | --- | --- | --- |
| `process.fork` | process, parent | ebpf `sched_process_fork` | netlink_proc |
| `process.exec` | process, parent | ebpf `sched_process_exec` | netlink_proc + procfs |
| `process.exit` | process (`exit_code`, `exit_signal`) | ebpf `sched_process_exit` | netlink_proc; reconcile (`inferred`) |
| `process.discovered` | process | procfs reconcile (`reconstructed`) | – |
| `process.rename` | process, `previous_name` | ebpf `task_rename` | netlink_proc comm |
| `process.cred_change` | process, `creds_before`, `caps_before` | ebpf `commit_creds` | netlink_proc uid/gid |
| `process.ns_change` | process, `ns_before` | ebpf | reconcile |
| `process.inject` | process (actor), `target`, `technique` (`ptrace_attach` from netlink_proc; `ptrace_access` from eBPF, which also covers `process_vm_*` and `/proc/<pid>/mem` access checks; `vm_writev`, `proc_mem_write` later) | ebpf | netlink_proc ptrace |
| `process.signal` | process (sender), `target`, `signal` | ebpf `signal_generate` | – |
| `memory.exec_mapping` | process, `prot`, `flags`, file, `technique` (`anon_exec`, `mprotect_exec`, `wx`) | ebpf | procfs maps |
| `library.load` | process, file | ebpf `security_mmap_file` | procfs maps diff |
| `file.create`, `file.modify`, `file.delete`, `file.rename` (`file`, `target`), `file.link`, `file.chmod`, `file.chown`, `file.setxattr`, `file.open_sensitive` | process, file | ebpf `security_*` hooks | fanotify |
| `network.connect`, `network.accept`, `network.listen`, `network.close`, `network.udp_flow`, `network.raw_socket` | process, network | ebpf | sock_diag diff |
| `network.config_changed` | `change` (`link`, `addr`, `route`) | rtnetlink | poll diff |
| `firewall.changed` | `firewall {table, chain, operation}` | nfnetlink | poll |
| `dns.query` | process, `dns {qname, qtype, rcode, answers[], server}` | ebpf payload capture | – |
| `auth.login`, `auth.failure`, `auth.logout` | `auth {service, method, user, source_ip, result, session_id}` | audit | journal → auth log |
| `auth.privilege` | `auth {service, user, target_user, command, result}` | audit `USER_CMD` | journal |
| `account.created`, `account.deleted`, `account.modified`, `group.*` | `account {name, uid, gid, shell, home, changes[]}`, writer process if known | audit + passwd diff | passwd diff |
| `persistence.created`, `persistence.modified`, `persistence.deleted` | `persistence {class, path, content_hash, summary}`, writer process if known | file events on the persistence catalog | scan diff |
| `fim.changed` | file, `before`, `after`, `class` | file events | scan diff |
| `package.installed`, `package.removed`, `package.upgraded` | `package {manager, name, version, arch}` | package DB diff | – |
| `kernel.module_load`, `kernel.module_unload` | process, `module {name, path}` | ebpf | `/proc/modules` diff |
| `kernel.bpf_load` | process, `bpf {prog_id, prog_type, name}` | ebpf | enumeration diff |
| `mount.changed` | process, `mount {source, target, fstype, operation}` | ebpf | mountinfo diff |
| `device.attached`, `device.removed` | `device {subsystem, vendor_id, product_id, devpath}` | uevent | sysfs diff |
| `posture.changed` | `posture {item, before, after}` | sysfs/procfs poll | – |
| `container.started`, `container.stopped` | container | cgroup-derived | runtime poll |
| `tamper.*` | process (actor), `tamper {target, technique}` | ebpf | file events |

Process images: when procfs can no longer be read at exec time (short-lived processes), `process.executable.path` is the string given to `execve` (it may be relative, or a symlink such as `/bin/true`), `kind` is `file`, and the file metadata (`dev`, `inode`, `size`) is absent; `process.name` is its basename. The pre-exec image is never carried over.

### 4.1 `file.*` events as emitted today (fanotify provider)

| Type | Meaning | Notes |
| --- | --- | --- |
| `file.create` | entry created (file, directory, symlink) | `file.directory` marks directories |
| `file.modify` | writable descriptor closed | close-after-write, not each `write()` |
| `file.delete` | entry removed | no `stat` |
| `file.rename` | entry moved | `file.old_path` set when both halves were seen; otherwise `unavailable` names the missing side (`file.old_path` or `file.path`) |
| `file.attrib` | attribute change | chmod, chown, utimes and xattr changes are indistinguishable here; the eBPF provider will split them |

Event body: `process` (actor, resolved through the entity graph; `{pid}` plus `unavailable: process` when it already exited), `file {path, name, directory, old_path?, stat?}` with `stat {mode, uid, gid, size, inode, device, mtime}` from an `lstat` taken after the event (`unavailable: file.stat / object_gone` when the path is gone). Provenance `{fanotify_file, FANOTIFY, observed}`. Events skipped by the rate governor are not individually reported; they appear as one `loss` record with `stage: governor` and an exact `count`.

### 4.2 `fim.*` events as emitted today (S5.2, ADR 010)

| Type | Meaning | Body |
| --- | --- | --- |
| `fim.baseline` | the monitor started | `fim {state created/loaded/reset, reason?, items, changes}` where `changes` counts what differed while the sensor was down (each is also reported as `fim.changed`) |
| `fim.changed` | a persistence item was added, removed or modified | `fim {path, category, change added/removed/modified, fields[] (kind, content, mode, uid, gid, target), before?, after?}` with `process` when a file event named the path |
| `hash.computed` | an executed image whose exec record carried `hash.status=pending` finished hashing | `process {entity_id, exec_gen, pid}`, `executable {path, dev, inode, size, hash {status, sha256, sha1, md5}}`; join to the exec record on `entity_id` + `exec_gen`. `hash.status` on the exec record: `computed` (cache hit, inline), `pending`, `too_large` (above `hash_max_file_bytes`), `unreadable` (image not identified before the process exited, or not a regular file), `skipped` (queue or waiter limit reached) |

`before` and `after` are `state.persistence` items (below). Provenance `{fim, FSSCAN, observed}`, or `FSSCAN+FANOTIFY` when a file event attributed the change. Without an actor, `unavailable` lists `process / not_supported_by_provider`; an actor that already exited is `process / process_exited`.

**`state.persistence` item:** `category` (systemd_unit, cron, shell_profile, ssh, ld_preload, init_script, privilege, pam, account, system_config, udev_rule, autostart, kernel_module, login_hook, package_hook), `path`, `kind` (file, symlink, other), `uid`, `gid`, `mode` (07777), `size`, `mtime`, `hash_status` (computed, too_large, unreadable, not_applicable), and when known `sha256`, `target`, `exec` (systemd: program of the first `ExecStart`), `entries` (cron, `ld.so.preload`: active lines), `key_count`, `forced_commands`, `key_digests[]` (`authorized_keys`), `nopasswd` (sudoers lines granting NOPASSWD). File content, key material and key comments are never emitted.

### 4.3 `network.*` events as emitted today (S6.1, ADR 011)

| Type | Meaning | Body |
| --- | --- | --- |
| `network.connect` | a new outbound TCP or connected UDP socket | `process` (owner, or `unavailable: process`), `network` (section 3.3: `transport`, `family` ipv4/ipv6, `direction`, `local {ip, port}`, `remote {ip, port}`, `tags[]`, `state`, `socket_inode`, `uid`, `holders` when more than one process holds the socket) |
| `network.accept` | a new connection to a local listening port (TCP) | as above, `direction` inbound |
| `network.listen` | a socket started listening, or a UDP socket was bound | as above without `remote`, `direction` listen |

Provenance `{sockdiag_network, SOCKDIAG, reconstructed}`: sockets are found by polling the kernel tables every 500 ms and the owner by matching the inode to `/proc/<pid>/fd`, so a connection that closed between polls is not seen and one whose process exited has no owner. Event time is the observation time. `network.close`, `network.udp_flow`, `network.raw_socket` and byte counters are not provided.

### 4.4 `auth.*` events as emitted today (S7.1, ADR 012)

| Type | Meaning | Body |
| --- | --- | --- |
| `auth.login` | a successful login: sshd (`publickey`, `password`, ...) or a console login | `process` (`pid` as logged, `unavailable: process_exited`), `auth` (`service`, `method`, `outcome` success, `user`, `source {ip, port}`, `key {type, fingerprint}` for public keys, `tty`) |
| `auth.failure` | a failed login | as above, `outcome` failure, `invalid_user` when the account does not exist |
| `auth.privilege` | `sudo`, `su` or `pkexec`, success or failure | `auth` (`service`, `outcome`, `user`, `target_user`, `tty`, `working_directory`, `command`) |

SSH has no separate type: it is `auth.login` or `auth.failure` with `service` `sshd`. Fields that were made printable or cut carry `sanitized` and `truncated`. Two mechanisms serve the family, in preference order (ADR 013, ADR 012). Primary `{audit_netlink, AUDIT, observed}`: kernel audit records (`USER_LOGIN`, `USER_AUTH` failure, `USER_CMD`, `su` `USER_START`); `process` is the live sender with its ancestry, the actor is the audit uid, and `method` is the program for sudo and su. Fallback `{auth_log, AUTHLOG, user_space_reported}`: what a program chose to log, read from `/var/log/auth.log` or `/var/log/secure` with syslog delay; it is on standby while the audit provider runs. sudo logs no pid, so its `process` is empty with `unavailable: not_supported_by_provider`. `auth.logout`, session ids and audit-sourced events are not provided.

### 4.5 `kernel.*` and `mount.*` events as emitted today (S7.3, ADR 014)

| Type | Meaning | Body |
| --- | --- | --- |
| `kernel.module_load` | a module appeared in `/proc/modules` (or was replaced under the same name) | `module {name, size, state}` |
| `kernel.module_unload` | a module left `/proc/modules` | as above |
| `mount.changed` | a mount appeared, disappeared or changed options | `mount {operation mounted/unmounted/remounted, source, target, fstype, mount_id, device, options[], super_options[]}` |

There is no acting process: `process` is omitted and `unavailable` carries `{process, not_supported_by_provider}`. Provenance `{kernel_change, PROCFS, reconstructed}`: found by comparing snapshots taken every second, so a change that came and went between two polls is not seen, and the event time is the observation time. The first snapshot is the starting state. `kernel.bpf_load`, `device.*` and hidden-module cross-view are not provided.

### 4.6 `memory.exec_mapping` and `kernel.bpf_load` events as emitted today (ADR 020)

Provenance `{ebpf, security_mmap_file | security_file_mprotect | security_bpf, observed}`. Each
carries the requesting `process` (full entity, or a `{pid}` stub with `process` unavailable when it
had exited) and one body.

- `memory`: `operation` (`mmap` | `mprotect`), `backing` (`anonymous` | `memfd` | `file`),
  `write_exec`, and for `mprotect` the `address` and `length` of the mapping touched. For `mmap` the
  address is not known at the hook and `memory.range` is listed as unavailable.
- `bpf`: `command` (`prog_load` | `prog_attach` | `raw_tracepoint_open` | `link_create`),
  `program_type` (`prog_load`), `attach_type` (attach, link), `name`.

These are requests seen before the kernel acts, deduplicated per process, operation and backing
over five seconds. File-backed mappings, read-only mprotects of file mappings and eBPF map creation
are not reported. JIT runtimes (browsers, JVM, Node, .NET) legitimately produce `memory.*` records,
so a rule needs the process identity and an allowlist, not the event alone.

### 4.7 `process.ns_change` events as emitted today (ADR 021)

Provenance `{ebpf, switch_task_namespaces, observed}`. The acting `process` (full entity) and an
`ns_change` body: `scope` (`process` | `thread`), `thread_id`, and `changes[]` of `{ns, from, to}`
for each of `mnt`, `pid_for_children`, `net`, `uts`, `ipc`, `cgroup` that actually changed.
`unavailable` always lists `ns_change.user`.

A call that changes nothing is not reported. `nsenter` with several flags is one record per
namespace type. Container runtimes and daemons that bind a thread to a container network namespace
produce these records routinely; a rule needs the process identity, not the event alone.

### 4.8 `dns.query` events as emitted today (ADR 022)

Provenance `{ebpf, udp_sendmsg, observed}`. The asking `process` (full entity, or a `{pid}` stub with
`process` unavailable when it had exited) and a `dns` body: `name` (as sent, case preserved, escaped),
`type`, `class`, `transaction_id`, `recursion_desired`, `transport` (always `udp`), `family`, and the
`server` and `local` endpoints.

This is the question as it left the process: no answer, no response code. A stub resolver produces a
record from the application to the stub and further records from the stub to its upstream, each
attributed to its own process; a validating stub adds `DNSKEY` and `DS` lookups. One record per
process and question per five seconds (the transaction id is ignored). Not reported: a question
split across `sendmsg` buffers, DNS over TCP, DoH and DoT, mDNS, responses.

### 4.9 `lsm.denial`, `lsm.policy` and `netfilter.config_change` events as emitted today (ADR 023)

Provenance `{audit_netlink, AUDIT, observed}`. The acting `process` is attached when the audit pid is a
process the sensor knows, a `{pid}` stub with `process` unavailable when it is gone, and absent for
the SELinux status records.

`lsm.denial` carries `lsm`: `module`, `operation`, `outcome` (`denied` or `would_deny`), and the
`object`, `requested`, `denied`, `profile`, `target_context`, `object_class` and `comm` the kernel
gave. `lsm.policy` carries `module`, `operation` (`profile_load`, `profile_replace`, `profile_remove`,
`policy_load`, `enforcing`, `permissive`, `enabled`, `disabled`) and, for AppArmor, the profile name
as `object`; it has no `outcome`. `netfilter.config_change` carries `netfilter`: `subsystem`,
`operation`, `table`, `family`, `entries`, `generation` (nftables) and `comm`; it says a table
changed and who changed it, not what the rule is.

Only what the kernel audits is visible: no records on a host with auditing disabled, none for
AppArmor `AUDIT` rules, none for SELinux decisions that were granted. All strings are bounded and
printable. Not reported: the ruleset itself, nftables changes made on a host where the audit
records are suppressed by an audit rule.

## 5. State records

`state.host`, `state.posture`, `state.processes`, `state.users`, `state.groups`,
`state.sessions`, `state.services`, `state.scheduled`, `state.packages`, `state.listeners`,
`state.connections`, `state.interfaces`, `state.routes`, `state.mounts`, `state.modules`,
`state.bpf`, `state.firewall`, `state.persistence`, `state.containers`. Each carries
`state {object, snapshot_id, part, parts, items[]}` so large snapshots split cleanly. Emitted at
start, on a schedule, and on `QUERY_STATE` commands.

**Implemented (S4):** `state.processes` (procfs reconciler) and the inventory objects `state.host`,
`state.posture`, `state.users`, `state.groups`, `state.interfaces`, `state.mounts` and
`state.modules` and `state.persistence`, emitted at start and every `state_interval_seconds` (default 3600, 100 items per
part). Inventory records carry provenance `{provider "inventory", mechanism, confidence observed}`
and list every field that could not be collected in `unavailable[]` (`{field, reason}`, on part 1
of a snapshot); an unreadable value is `null` or absent, never guessed. Collectors read a
filesystem root, bound every file (4 MiB) and every list (8192 items, excess flagged with a
`<object>.items` `truncated` entry), skip malformed lines and never follow a FIFO or device.

| Object | Item fields |
| --- | --- |
| `host` (1 item) | `hostname`; `os {id, id_like, name, pretty_name, version_id, version_codename}`; `kernel {release, version, cmdline, tainted {value, flags[]}}`; `boot {boot_id, boot_time_unix, uptime_seconds}`; `hardware {cpu_count, cpu_model, memory_total_kb, virtualization {hypervisor, sys_vendor, product_name}}`; `machine_id_sha256` |
| `posture` (1 item) | `lockdown`, `secure_boot` (`enabled`, `disabled`, `not_efi`, or null), `lsm[]`, `selinux`, `apparmor`, `sysctl {kernel/kptr_restrict, ..., net/ipv4/ip_forward}` (15 keys; integer, text or null) |
| `users` | `name, uid, gid, home, shell, login_shell, system_account, uid0_non_root, password_state` (`set`, `locked`, `empty` or null) |
| `groups` | `name, gid, members[]` |
| `interfaces` | `name, mac, operstate, mtu, arphrd_type, addresses[{family, address, prefix}]` (addresses only from the live host) |
| `mounts` | `mount_id, parent_id, device, root, mount_point, fs_type, source, options[], super_options[], nosuid, noexec, nodev, read_only` |
| `modules` | `name, size, refcount, state, used_by[]` |

Privacy: the machine-id leaves the host only as a salted SHA-256 prefix; password hashes are
reduced to `password_state`; DMI serial numbers and the product uuid are not collected; kernel
command-line parameters whose name contains `pass`, `secret`, `token` or `key` are redacted.

**Control socket.** `panopticon-sensord --control-socket PATH` serves one request line per
connection (at most 256 bytes, 2 s deadline) and replies with one JSON line,
`{"ok":true,"result":...}` or `{"ok":false,"error":"..."}`. Commands: `status` (health body),
`coverage` (capability to provider), `state list` and `state <object>` (collected on demand:
`{object, provider, mechanism, truncated, items[], unavailable[]}`). `panopticon-ctl [--socket
PATH] <command>` is the client (default `/run/panopticon/sensord.sock`).

## 6. Health, loss and policy

* `health`: `health {status, providers[{name, state, reason, capabilities[], events, drops}],
  coverage {capability: provider|null}, resources {rss_bytes, cpu_milliseconds, wal_bytes,
  wal_records}, kernel {release, btf, bpf_lsm, ringbuf}}`.
* `loss`: `loss {stage (kernel, queue, wal, governor, transport), count, by_type{}, detail}`.
  WAL losses carry the reason in `detail`: `torn_tail`, `corrupt_segment`, `gap`, `quota`.
* The `procfs` provider always appears in `providers[]`: it is the reconciler that backs every
  process capability when no kernel provider is active.
* `policy`: `policy {version, applied, errors[]}`.

## 7. Detection, evidence, response

* `detection`: `detection {rule_id, rule_version, severity, confidence, mitre[], summary}` plus
  the triggering family objects and `related_records[]` (record ids).
* `evidence`: `evidence {command_id, kind, items[], truncated}`.
* `response`: `response {command_id, action, result, summary, target}`.
