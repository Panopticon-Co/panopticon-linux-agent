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

## 7. Commands

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure      # unit + contract
sudo tests/ground_truth/run.sh build            # process model (root, VM)
```
