# Linux Endpoint Test Plan

## 1. Levels

| Level | Where | Runs | Gate |
| --- | --- | --- | --- |
| Unit | any Linux (CI) | every commit | must pass |
| Contract | CI | every commit | sensor fixtures validate against contracts schema 1.0; Manager and Detection Engine consume the same fixtures |
| Ground truth (process model) | VM, root | every slice | must pass |
| Provider integration | VM, root | every slice | must pass on the dev kernel |
| Attack simulation | VM, root | every slice | expected records produced |
| Fuzz | CI (time-boxed) + longer local runs | every slice | no crashes or sanitizer findings |
| Chaos | VM | reliability slices | recovery within budget, losses accounted |
| Performance | VM | slices touching hot paths | within LINUX_ENDPOINT_PERFORMANCE.md budgets |
| Distro/kernel matrix | Vagrant VMs | each milestone | per LINUX_ENDPOINT_COMPATIBILITY_MATRIX.md |
| Package | VM | packaging changes | install, upgrade, rollback, uninstall |

## 2. Process-model ground truth

Deterministic programs with known behaviour run while the sensor records; the test compares
records with the known truth:

1. fork → exec → exit with known argv and exit code.
2. PID reuse inside a small PID namespace: distinct entity ids, no cross-attribution.
3. Several execs in one process: `exec_gen` increments, entity id stable.
4. Threads do not produce process starts.
5. vfork + exec.
6. Very short-lived processes still produce exec and exit with argv.
7. Re-parenting to a subreaper.
8. PID namespace: host pid vs vpid.
9. Exec of a deleted binary and of a memfd.
10. Script with shebang: interpreter recorded.
11. Sensor restart: running processes reconciled as `process.discovered`, not re-emitted as exec.
12. Reboot: new boot id, no id collisions.

## 3. Attack simulations

Benign, self-contained simulations of ATT&CK techniques, each with an expected record type.
They touch only dedicated test artefacts (test users, test files, test units) and are reverted
afterwards. Coverage list: execution from `/tmp` and `/dev/shm`; memfd execution; LD_PRELOAD;
`/etc/ld.so.preload` change; cron, systemd and shell-rc persistence; local account creation;
authorized_keys change; sudo usage; sensitive-file reads; ptrace attach to a test process;
kernel module load of an in-tree module; BPF program load by a non-sensor process; namespace
mount; firewall rule change; DNS query for a test domain; IMDS address access; log truncation;
stdio-to-socket shell pattern against a local listener; attempts to stop the sensor.

## 4. Fuzzing

libFuzzer targets: command envelope, config, procfs stat/status, cgroup/container path, ELF
header, WAL record decoder, kernel event decoder, netlink decoder, journal/auth-log parsers,
DNS packet parser, policy parser.

## 5. Chaos

`kill -9` mid-write (torn WAL tail), disk full, Manager outage and recovery, memory pressure,
ring-buffer overflow, forced provider failure (eBPF unavailable → fallback active and reported).

## 6. Security tests

One per threat in [LINUX_ENDPOINT_SECURITY_MODEL.md](LINUX_ENDPOINT_SECURITY_MODEL.md) §3:
forged/replayed/expired commands; unprivileged client on helper sockets; symlink swap during
quarantine; PID reuse between command and execution; malformed and oversized parser inputs;
event flood; WAL truncation/corruption; config with wrong ownership; stop/disable attempts;
foreign BPF detach attempts; binary replacement; downgrade attempt.

## 7. Implemented suites

| Binary | Level | Contents |
| --- | --- | --- |
| `panopticon-sensor-tests` | unit + ground truth + provider integration | JSON escaping and UTF-8 replacement; clock round trip; `stat` parsing with a hostile `comm`; `status` parsing; cmdline bounds; exe-link classification; fake-procfs read; ground truth on the real kernel: exec with argv and env allowlist (secret keys excluded), exec of a deleted binary, memfd `fexecve`; entity-graph lifecycle (fork, exec, rename, cred change, ptrace inject, exit, duplicate exit, PID reuse); reconcile infers a missed exit; exit-status decoding; CNPROC message decoding; live CNPROC fork/exec/exit (root, skipped otherwise); CRC-32C check value; WAL append/read/ack/recover across segments, torn tail, quota and corruption; pipeline end to end with a scripted provider; strict config; record-queue FIFO and drop counting |
| `panopticon-ebpf-tests` | unit + live ground truth | decoder for every event kind (fork, exec with argv containing spaces and empty arguments, exit, rename, credential change of uid/gid, ptrace access), argv truncation by limit and by kernel flag, rejection of malformed samples (null, short, oversized, unknown kind, `args_len` beyond the buffer or the received bytes); `ebpf_process` and `netlink_proc` declare one provider family; live on the real kernel through a self re-exec child: exact exit code and argv, in-kernel start time equals `/proc/<pid>/stat`, death by `SIGKILL`, exactly one rename (the kernel's own exec rename is not reported), uid and gid change with no event for a plain exec, ptrace access with the correct tracer, one process exit for a multi-threaded process whose leader exits first (reported when the last thread ends). Live tests need root and a BTF kernel and print SKIP otherwise |
| `panopticon-linux-agent-core-tests` | unit | pre-existing command/config/isolation tests. Known environmental failure: "regular configuration file must load" fails when the umask is 0002 (the test file is group-writable and correctly rejected); passes with umask 022 |

Ground-truth items from §2 covered so far: 1, 3 (in the entity graph), 9, 11, and with the eBPF
provider the short-lived process, exit status, rename, credential and thread-group cases. The
rest need a PID namespace / container harness.

## 8. Commands

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure      # unit + contract
sudo build/panopticon-sensor-tests              # includes live netlink proc
sudo build/panopticon-ebpf-tests                # live eBPF ground truth (skips without BPF)
sudo tests/ground_truth/run.sh build            # process model (root, VM)
```
