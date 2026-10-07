# Linux endpoint configuration reference

Source of truth: `parse_sensor_config` in `src/sensor/pipeline.cpp` and the defaults in `struct sensor_config`
(`include/panopticon/linux_agent/sensor/pipeline.hpp`). This page is derived from them; if they disagree, the code
is right. The file is `key=value` lines. **Unknown keys, duplicate keys and out-of-range values are errors**, and
the loader (`load_sensor_config`) also refuses a file that is not a regular file, is owned by anyone but root or the sensor's own user, is group- or world-writable, or sits under a directory others can write into (sticky directories such as `/tmp` are fine). The same rule applies to the `ca_bundle` and to the `response_signing_keys` file (ADR 031).
`panopticon-sensord --config <file>` does not start on any error.

Paths named "absolute" must start with `/` and must not contain `..`. Booleans are `true` or `false`.

## Identity and storage

| Key | Default | Rule |
| --- | --- | --- |
| `sensor_id` | empty | Free identifier for this sensor instance. |
| `host_id` | empty | Host identifier; commands are accepted only for this host (ADR 024). |
| `wal_path` | `/var/lib/panopticon/wal` | Write-ahead log base path. Also the base of the default ledger (`.commands`) and quarantine store (`.quarantine`). |
| `wal_quota_bytes` | 268435456 | 1 MiB to 1 TiB. |
| `wal_segment_bytes` | 8388608 | 64 KiB to 1 GiB. |
| `queue_capacity` | 65536 | 1024 to 16777216 records between providers and the serializer. |
| `proc_root` | `/proc` | Tests point it at a fake tree. |

## Delivery

| Key | Default | Rule |
| --- | --- | --- |
| `manager_url` | empty (collection only, records stay in the WAL) | `https://` only. Needs `identity_path`; the two are both set or both empty. |
| `identity_path` | empty | Enrolled identity file (agent id, host id, bearer token), absolute. |
| `ca_bundle` | empty | Optional private CA for the Manager certificate. |

## Collection

| Key | Default | Rule |
| --- | --- | --- |
| `reconcile_interval_seconds` | 30 | 1 to 86400. |
| `health_interval_seconds` | 60 | 1 to 86400. |
| `state_interval_seconds` | 3600 | 60 to 604800 (state snapshots). |
| `collect_environment` | `true` | Environment variables allow-list in process records. |
| `maximum_args`, `maximum_args_bytes`, `maximum_entities` | 64, 4096, 65536 | 1 to 1024; 256 to 1 MiB; 1024 to 4194304. |
| `enable_ebpf` | `true` | `false`: netlink and procfs only. |
| `enable_file_events` | `true` | fanotify file telemetry. |
| `enable_sensitive_file_events` | `true` | Credential files being opened. |
| `enable_network_events` | `true` | sock_diag telemetry. |
| `enable_auth_events` | `true` | Audit group and auth log. |
| `enable_kernel_events` | `true` | Module and mount changes. |
| `enable_security_events` | `true` | Executable-memory and eBPF-load telemetry. |
| `file_include`, `file_exclude` | built-in sets | Comma-separated absolute prefixes, at most 256 each. |
| `enable_fim` | `true` (when read from a file) | File-integrity monitoring of the persistence catalog. |
| `fim_path` | `<dir of wal_path>/fim.baseline` | Baseline file, absolute. |
| `fim_interval_seconds` | 300 | 60 to 86400. |
| `enable_hashing` | `true` (when read from a file) | Hash executed images. |
| `hash_max_file_bytes` | 268435456 | 1 MiB to 4 GiB. |
| `hash_bytes_per_second` | 67108864 | 1 MiB/s to 1 GiB/s. |

## Command channel and response (ADR 024 to 027)

The channel is **off** unless `response_mode` says otherwise, and it needs `manager_url`.

| Key | Default | Rule |
| --- | --- | --- |
| `response_mode` | `off` | `off`, `dry_run` (verify, change nothing) or `enforce`. |
| `response_actions` | `KILL_PROCESS,COLLECT_PROCESS_INFO,COLLECT_NETWORK_CONNECTIONS` | Comma-separated, no duplicates, only actions this sensor implements: `KILL_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`, `RELEASE_HOST_ISOLATION`. Anything not listed answers `action_not_permitted`. |
| `response_poll_seconds` | 5 | 1 to 300. |
| `response_max_lifetime_seconds` | 900 | 30 to 86400; a command valid for longer is `lifetime_exceeded`. |
| `response_max_changes_per_minute` | 6 | 1 to 600; shared by every changing action (kill, quarantine, isolate, release). |
| `response_ledger_path` | `<wal_path>.commands` | Durable command ledger, absolute. |
| `response_require_boot_binding` | `false` | Refuse process commands that are not bound to a boot (schema 1). |
| `response_signing_keys` | empty | Absolute path of the pinned keyring (ADR 025). |
| `response_allow_unsigned` | `false` | Explicit opt-in to acting without signatures (labs). |
| `response_file_roots` | empty | Comma-separated absolute directories, never `/`, no duplicates. Quarantine acts only under these (ADR 026). |
| `response_quarantine_dir` | `<wal_path>.quarantine` | Quarantine store, absolute; used only with roots. |
| `response_isolation_socket` | empty | Absolute AF_UNIX path of the privileged isolation helper, shorter than 108 bytes (ADR 027). |

Cross-key rules, all enforced at start:

* `response_mode` other than `off` needs `manager_url`.
* `response_mode` other than `off` needs exactly one of `response_signing_keys` and `response_allow_unsigned=true`;
  both together is a contradiction.
* `QUARANTINE_FILE` is listed if and only if `response_file_roots` is set.
* `ISOLATE_HOST` and `RELEASE_HOST_ISOLATION` are listed together, and if and only if `response_isolation_socket`
  is set.

## Installing and running as a service

`cpack -G DEB` (in the build directory) produces `panopticon-sensord_<version>_amd64.deb` with `/usr/bin/panopticon-sensord`,
`/usr/bin/panopticon-ctl`, `/usr/lib/systemd/system/panopticon-sensord.service` and
`/usr/share/panopticon/sensord.conf.example`. The post-install script creates `/etc/panopticon/sensord.conf` (root-owned,
0644, `sensor_id` and `host_id` derived from `/etc/machine-id`, collection only) if there is none, enables the service
and restarts it, so an upgrade runs the new binary and never overwrites an edited configuration. `dpkg -r` stops and
disables the service and keeps the configuration and the log; `dpkg -P` removes both (the log holds records the Manager
may not have acknowledged, so purge is the only way it is deleted). The unit is described in ADR 031: `Type=notify`,
`WatchdogSec=30`, `Restart=always`, `StateDirectory=panopticon` (`/var/lib/panopticon`), control socket
`/run/panopticon/control.sock` (`panopticon-ctl --socket /run/panopticon/control.sock status`). File actions that move
files out of `response_file_roots` need those roots in `ReadWritePaths=` (a drop-in, because the unit makes the file
system read-only for the sensor).
