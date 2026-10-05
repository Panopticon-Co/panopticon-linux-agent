# Linux Endpoint Compatibility Matrix

"Supported" means: telemetry verified, fallbacks verified, response verified, package installs
and upgrades, tests pass, limitations documented. A distribution where the binary merely
compiles is **not** supported. Results are only entered from real runs, with date and commit.

## 1. Kernel feature floors used by the sensor

| Feature | Kernel | Used for | If missing |
| --- | --- | --- | --- |
| BPF ring buffer | 5.8 | event transport | perf buffer |
| BTF (`/sys/kernel/btf/vmlinux`) | 5.4 (distro-enabled) | CO-RE | eBPF providers disabled → netlink/fanotify/procfs fallbacks |
| `tp_btf` / fentry / fexit | 5.5 (x86_64), 6.0 (arm64 fentry) | low-overhead hooks | classic tracepoints / kprobes |
| BPF-LSM | 5.7 + `CONFIG_BPF_LSM` + `bpf` in `lsm=` | prevention, tamper protection | fanotify permission (exec) / detection only |
| pidfd_open | 5.3 | race-free response | start-time re-check + kill() |
| openat2 | 5.6 | symlink-safe file actions | `O_NOFOLLOW` walk |
| fanotify `FAN_REPORT_DFID_NAME` | 5.9 | file fallback with names | `FAN_REPORT_FID` / per-directory marks |
| proc connector | all | process fallback | procfs polling |

## 2. Distribution / kernel targets

| Distribution | Default kernel | Arch | BTF | BPF-LSM active by default | Status | Verified run |
| --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 20.04 | 5.4 (HWE 5.15) | x86_64, aarch64 | yes | no | not yet tested | – |
| Ubuntu 22.04 | 5.15 | x86_64, aarch64 | yes | no (compiled in) | development platform | §3 |
| Ubuntu 24.04 | 6.8 | x86_64, aarch64 | yes | no (compiled in) | not yet tested | – |
| Debian 12 | 6.1 | x86_64, aarch64 | yes | no | not yet tested | – |
| Debian 13 | 6.12 | x86_64, aarch64 | yes | no | not yet tested | – |
| RHEL / Rocky / Alma 8 | 4.18 + backports | x86_64, aarch64 | yes (8.2+) | no | not yet tested | – |
| RHEL / Rocky / Alma 9 | 5.14 + backports | x86_64, aarch64 | yes | no | not yet tested | – |
| RHEL 10 | 6.12 | x86_64, aarch64 | yes | no | not yet tested | – |
| Amazon Linux 2 | 4.14 / 5.10 | x86_64, aarch64 | 5.10 only | no | not yet tested | – |
| Amazon Linux 2023 | 6.1+ | x86_64, aarch64 | yes | no | not yet tested | – |
| SUSE SLES 15 | 5.14 | x86_64, aarch64 | yes | no | not yet tested | – |

The Status column only changes after a real run recorded in §3.

## 3. Verified runs

| Date | Commit | Distro / kernel / arch | Result |
| --- | --- | --- | --- |
| 2026-10-05 | 335dae0 | Ubuntu 22.04 / 5.15.0-91 / x86_64 | Build + unit tests pass (umask 022); isolation e2e pass; BTF, ring buffer, fentry available; BPF-LSM compiled in but inactive |

## 4. Test environment

Kernel/distro runs use Vagrant + VirtualBox on an x86_64 workstation. aarch64 is listed as
**build-only** until an aarch64 VM run is recorded.
