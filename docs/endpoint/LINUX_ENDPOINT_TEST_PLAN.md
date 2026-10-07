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

`tests/chaos/run_chaos.sh` runs the real sensor on a real kernel (root) against
`tests/chaos/fake_manager.py`, an HTTPS stand-in for the Linux ingest route of the Manager that
stores what it accepts and injects faults, and `tests/chaos/analyze.py`, which fails on a
conflicting payload under one seq or on a gap that the sensor did not report as lost. Only the
process provider runs, so the load is the load the script generates (fork, exec, exit of
`/bin/true`, about 4 KB a record). Scenarios:

| Scenario | Fault | Pass condition |
| --- | --- | --- |
| `baseline` | none | stream contiguous |
| `kill9` | `kill -9` of the sensor 14 times in 70 s under load | contiguous, no conflicting payloads |
| `outage` | Manager killed, short (under the WAL quota) then long (over a 2 MiB quota) | short: nothing lost; long: the gap is reported (loss records plus the cumulative `wal.dropped_records` of the newest health record) |
| `ackloss` | Manager stores a batch then drops the connection, 6 times | duplicates absorbed, contiguous |
| `badack` / `http503` / `slowack` | acknowledgement that does not add up / 503 / 3 s delay | cursor does not move on a bad answer, delivery resumes, contiguous |
| `rejected` | Manager rejects one line of a batch, 3 times | records quarantined, gap equals the `manager_rejected` loss |
| `diskfull` | WAL on a 2 MiB tmpfs that fills, then is grown | sensor alive and degraded, no crash, refused records reported as one `wal` loss with reason `write_failed` |
| `clock` | wall clock stepped +2 days, then -1 day, then back, NTP off | sensor alive, contiguous, event `time` re-based (few records far from `observed_time`) |
| `powerloss_crash` + `powerloss_verify` | `sysrq-b` (no sync, page cache lost) under load with the Manager refusing; then restart on the surviving WAL | every seq that the sensor had reported durable, read from outside the machine before the crash, arrives; nothing conflicts |
| `ringoverflow` | sensor SIGSTOPped while 6000 processes run, so the 4 MiB kernel ring buffer fills; then SIGCONT and 50 more processes | sensor alive, overflow reported as a `kernel` loss, part of the storm delivered, events seen plus losses reported cover the 6000 generated, all 50 later processes seen once the backlog has been worked through (the scenario waits for them; judged earlier they looked lost when they were only late), resident memory bounded (37 MiB peak) |
| `memcap` | sensor in a 48 MiB cgroup v2 limit during a 3000-process storm with the Manager refusing, then accepting | no OOM kill, peak resident memory 38 MiB, contiguous |
| `nofile` | `RLIMIT_NOFILE` of the running sensor cut to exactly the descriptors it holds (file events and hashing on) during a storm and file writes, then raised | sensor alive, records it could not write are reported as `write_failed` loss (4 in the run), no silent gap, all 30 processes after the limit was raised are delivered |
| `walcorrupt` | 64 random bytes written into the middle of an unacknowledged WAL segment | recovery reports the lost range, no sequence number reused, no conflict |
| `walseg` | two sealed segments in the middle of an undelivered backlog deleted while the sensor runs (quota far above the run, so the quota drops nothing) | sensor alive, a `wal` loss `removed: seq a-b` whose count equals the records that went missing (140 in the run), all 40 later processes delivered. Before ADR 030 the uplink wedged for good: 27 records stored, 0 of 40 later processes, no loss reported |
| `waldir` | the whole WAL directory removed while records keep arriving | sensor alive, the removal reported as a `removed` loss (6559 reported for 6527 missing: delivered but unacknowledged records are counted too), directory re-created private, all 40 later processes delivered. Before ADR 030: 0 records stored after the removal and no loss reported |

Power loss is a guest crash of a VirtualBox VM: it loses the guest page cache and tests the sensor fsync discipline, but it does not reorder or tear writes at the disk, and the host cache survives. Run it with `tests/chaos/run_chaos.sh powerloss_crash` (output read from outside the VM), reboot, then `REQUIRE_SEQ=n tests/chaos/run_chaos.sh powerloss_verify`.

Forced provider failure was probed by hand rather than scripted: with `kernel.ftrace_enabled=0` set before the sensor starts, the kernel refuses every fentry attach with `-EBUSY`, so `ebpf_network` and `ebpf_security` report `unavailable` with the libbpf reason, `sockdiag_network` takes over, and the process role (tracepoints) keeps working. With the sensor running the kernel refuses to set the sysctl at all (`EBUSY`). So that evasion is not silent on kernel 5.15.

Not covered yet: disk-level torn writes and a real host power cut, a long real outage with the real
Manager, a full disk under the state directory for the FIM baseline (the command ledger's append
failure is unit tested and covered by `run_command_chaos_e2e.sh`), a scripted provider-failure
scenario, failures of the response executor under resource pressure.

## 6. Security tests

One per threat in [LINUX_ENDPOINT_SECURITY_MODEL.md](LINUX_ENDPOINT_SECURITY_MODEL.md) §3:
forged/replayed/expired commands; unprivileged client on helper sockets; symlink swap during
quarantine; PID reuse between command and execution; malformed and oversized parser inputs;
event flood; WAL truncation/corruption; config with wrong ownership; stop/disable attempts;
foreign BPF detach attempts; binary replacement; downgrade attempt.

## 7. Implemented suites

| Binary | Level | Contents |
| --- | --- | --- |
| `panopticon-sensor-tests` | unit + ground truth + provider integration | JSON escaping and UTF-8 replacement; clock round trip; `stat` parsing with a hostile `comm`; `status` parsing; cmdline bounds; exe-link classification; fake-procfs read; ground truth on the real kernel: exec with argv and env allowlist (secret keys excluded), exec of a deleted binary, memfd `fexecve`; entity-graph lifecycle (fork, exec, rename, cred change, ptrace inject, exit, duplicate exit, PID reuse); reconcile infers a missed exit; exit-status decoding; CNPROC message decoding; live CNPROC fork/exec/exit (root, skipped otherwise); CRC-32C check value; WAL append/read/ack/recover across segments, torn tail, quota and corruption; pipeline end to end with a scripted provider; strict config; record-queue FIFO and drop counting; container tracker (a first process starts a container and a host process does not, joins and an exec of a member are silent, the last exit stops it with lifetime and peak, a duplicate exit and a reappearing id, seeded and reconciled processes mark the start as not observed, a move between containers, the container and process bounds), and the pipeline writing `container.started` and `container.stopped` for a runtime-style fork then exec |
| `panopticon-ebpf-tests` | unit + live ground truth | decoder for every event kind (fork, exec with argv containing spaces and empty arguments, exit, rename, credential change of uid/gid, ptrace access), argv truncation by limit and by kernel flag, rejection of malformed samples (null, short, oversized, unknown kind, `args_len` beyond the buffer or the received bytes); `ebpf_process` and `netlink_proc` declare one provider family; live on the real kernel through a self re-exec child: exact exit code and argv, in-kernel start time equals `/proc/<pid>/stat`, death by `SIGKILL`, exactly one rename (the kernel's own exec rename is not reported), exec of a binary and of a `#!` script (interpreter and script path), TCP close (exact payload byte counts for the client and the accepting side of a loopback conversation with the peer closing first, state `close_wait` on the late closer, direction and duration; an unconnected socket and a listener not reported), raw and packet sockets (a packet socket and a raw ICMP socket reported with their protocols, a repeated one reported once, TCP, UDP and Unix sockets not reported), signals between processes (`kill(2)` and `tgkill` seen with sender, target, number and result; a signal outside the set and a process ending itself not seen; a signal to the test process, standing in for the sensor, marked `target_is_sensor` and recorded as ignored), stdio kinds for a socket, pipe, regular file, `/dev/null` and a closed descriptor read from the real kernel, uid and gid change with no event for a plain exec, ptrace access with the correct tracer, one process exit for a multi-threaded process whose leader exits first (reported when the last thread ends). Live tests need root and a BTF kernel and print SKIP otherwise |
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
| `panopticon-policy-tests` | unit + hostile input + fuzz | policy parser (strict, whole-file rejection, limits), rule operators, indicator sets, allow list, decision and match bounds, 10 MB input, 3000 random policies |
| `panopticon-sensor-tests` (S5.2 addition) | integration | `pipeline_reports_integrity_changes`: `fim.baseline` then `fim.changed` with path, field, before/after, actor from the entity graph and `FSSCAN+FANOTIFY`, baseline persisted, `seq` contiguous; FIM config keys strict |
| `panopticon-isolation-tests` (ADR 027) | unit + fake helper on a real SEQPACKET socket | exchange outcomes (accepted, refused, unreachable, no answer within the bound, hang-up), invalid command id and socket path, reachability probe sends no frame, executor isolate/release/dry-run/failure outcomes. Config pairing rules are in `panopticon-command-tests`, whose envelope fuzz (60000 mutations, every action and the authorization member, per-action survivor invariants) also runs under ASAN/UBSAN and TSAN |
| `tests/e2e/run_isolation_command_e2e.sh` | real VM, three network namespaces, real helper and nftables, TLS fake Manager | 26 checks: dry run, unsigned refusal, signed isolate with packet-level proof that the peer is blocked and the Manager path stays open, commands while isolated, restart and redelivery, helper crash, release, idempotent release, helper down |
| `tests/e2e/run_command_chaos_e2e.sh` (ADR 028) | real VM chaos, fake Manager, signed commands | 56 checks: burst, rate limit, duplicate id, 23 hostile content shapes (`tests/e2e/hostile_commands.py`) each followed by a signed canary, Manager outage, full ledger filesystem and recovery, corrupt ledger tail, deleted ledger (`ledger_reset`), SIGKILL mid-burst |
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
build/panopticon-policy-tests                   # local policy engine
sudo tests/ground_truth/run.sh build            # process model (root, VM)
```
