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
| `panopticon-state-tests` | unit + fake root + real kernel | hostile-input parsers (os-release quoting and escapes, passwd/group with malformed, non-numeric, overflowing and empty-name lines and an entry cap, mountinfo optional fields and octal escapes, `/proc/modules`, taint decoding, kernel cmdline redaction); every collector against a fake root (taint, redaction, machine-id never raw, password hash never emitted, uid-0 impostor flagged, mount flags); an empty root reports `unavailable[]` instead of inventing values; item cap with truncation entry, a FIFO planted in place of a file, an oversized file; every object on the real kernel produces valid JSON |
| `panopticon-control-tests` | unit + live socket + TSAN | round trip and error replies; socket mode 0600; unauthorized peer refused before its request is read; oversized, control-character and unterminated requests; a stalled client delays others by less than the deadline; a regular file at the socket path is never replaced and a stale socket is; over-long path; `state` arguments including `../../etc/passwd`; the `panopticon-ctl` binary (exit statuses 0, 1, 2); status and coverage from a pipeline that keeps stepping on another thread |
| `panopticon-sensor-tests` (S4 addition) | integration | `pipeline_emits_host_state_parts`: every inventory object is emitted at start with contiguous `seq`, 300 accounts split into three parts, `unavailable[]` on part 1 |
| `panopticon-file-tests` | unit + fuzz + live (root) | well-formed events; every truncation of a valid buffer is reported malformed and yields no events; oversized/zero `event_len`, unknown version, handle larger than its record, unterminated name, info length below its header; queue overflow is a loss; 40000 mutated buffers never crash and keep bounded output; filter prefixes respect directory boundaries; live: create, close-after-write, rename paired with its source, chmod, mkdir, unlink, rmdir, a 100-rename burst all paired, an excluded directory stays silent, own writes are never reported |
| `panopticon-sensor-tests` (S5 addition) | integration | `pipeline_enriches_file_events`: actor from the entity graph, path/name/stat, rename `old_path`, unknown actor reported as `process_exited` with no stat on delete, vanished path reported as `object_gone`, governed events become an exact `governor` loss, `seq` stays contiguous; file config keys strict |
| `panopticon-fim-tests` | unit + fixture tree | every persistence category found in a fake root; ExecStart prefix characters, cron/preload active lines, NOPASSWD count; authorized_keys counts, forced commands, 16-hex digests and no key text or comment in the JSON; classification incl. depth, traversal and nologin homes; a planted FIFO (no hang), a symlink (not followed), a too-large file, item cap flagged; extractors on garbage; diff semantics (touch is not a change, mode-only, owner, too-large by mtime); baseline text round trip, every truncation rejected, limits, unknown status, noise; monitor lifecycle (created, 0600, loaded with offline add/modify/remove, corrupt reset, symlinked baseline reset); dirty-path debounce, coalescing, latest actor, identical rewrite silent, removed directory takes children, rename queues both halves; a truncated scan reports no removals |
| `panopticon-hash-tests` | unit + real files | known SHA-256/SHA-1/MD5 vectors, empty and multi-chunk files, size limit, pacing abort, directory/pipe/bad-fd refusals (a pipe never hangs the worker), cache keyed on size/mtime, in-flight sharing and waiter limit, full-queue refusal, prompt shutdown with a paced read running |
| `panopticon-network-tests` | unit + hostile input + real kernel | sock_diag decoder (v4/v6 addresses, ports, owner inode, error replies, cut at every byte, oversized and undersized lengths, unknown family, random buffers), tracker (seed is state, connect/accept/listen classification, reused four-tuple, unowned and finished sockets skipped, table bound and overflow count), owner scan over a fake /proc with hostile links (overflowing, malformed, non-socket, non-pid), real loopback listen/connect/accept attributed to the test process |
| `panopticon-auth-tests` | unit + hostile input + file behaviour | auth log parser (sshd accepted/failed, key fingerprints, IPv6, sudo/su/pkexec/login, user-name injection and forged success, endpoint and fingerprint validation, both time formats and year inference, cut at every byte, random lines), tailer (starts at the end, partial lines, rotation, truncation, oversize lines, missing file, symlink refused), provider (new lines only, governor count) |
| `panopticon-audit-tests` | unit + hostile input + real kernel | audit record mapping (login, failed authentication, sudo and su, hex and quoted commands), records that are not events (successful authentication, failed login, other PAM operations, other types), first-key-wins and kernel header over sender text, quote injection, invalid and odd hex, control bytes, bad addresses, datagram decoder (cut at every byte, lying and tiny lengths, oversize, random buffers), uid resolution, and as root a user message sent to the kernel read back through the multicast group |
| `panopticon-kernel-tests` | unit + hostile input + file behaviour | module and mount tracker (starting state, load, unload, reload under a changed size, new, removed, remounted, re-mounted under a new id, mount over an existing path, super-block options), provider over a fake /proc (probe, one file enough, escaped mount paths, long paths, garbage lines, event budget count, snapshot at the limit is degraded and not diffed) |
| `panopticon-response-tests` | ground truth (real processes) | pidfd response: dry run, identity mismatch, exited target, SIGTERM and SIGKILL escalation, protected set, PID fallback, tree stop-then-kill with bound, command wrapper error codes |
| `panopticon-sensor-tests` (S5.2 addition) | integration | `pipeline_reports_integrity_changes`: `fim.baseline` then `fim.changed` with path, field, before/after, actor from the entity graph and `FSSCAN+FANOTIFY`, baseline persisted, `seq` contiguous; FIM config keys strict |
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
build/panopticon-state-tests                    # host-state collectors (no root needed)
build/panopticon-control-tests                  # control socket and panopticon-ctl
sudo build/panopticon-file-tests                 # fanotify decoder, filter and live file ground truth
build/panopticon-fim-tests                      # persistence catalog and FIM
build/panopticon-hash-tests                     # hash worker
build/panopticon-network-tests                  # sock_diag network telemetry
build/panopticon-auth-tests                     # auth log telemetry
build/panopticon-audit-tests                    # audit multicast telemetry (run as root for the live test)
build/panopticon-kernel-tests                   # kernel module and mount change telemetry
build/panopticon-response-tests                 # pidfd process and tree response
sudo tests/ground_truth/run.sh build            # process model (root, VM)
```
