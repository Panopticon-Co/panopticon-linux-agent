# Linux Endpoint Security Model

The sensor runs with high privilege on every protected host, so it is itself a high-value
target. This document states what the sensor defends, what it can and cannot guarantee, and
how each protection is tested.

## 1. Trust boundaries

| Boundary | Trusted side | Untrusted side | Control |
| --- | --- | --- | --- |
| Manager ↔ sensor | Manager signing key, pinned CA | Network | TLS 1.2+ with CA pinning; enrolled ECDSA P-256 identity; signed commands with expiry, nonce and replay ledger **[built]** |
| Sensor ↔ helpers | `panopticon-sensord` | Any other local process | AF_UNIX SEQPACKET in a root-only directory; `SO_PEERCRED` check; helpers re-validate every request; fixed opcode sets |
| Sensor ↔ local operator | `panopticon-sensord` | Any other local process | Read-only control socket, mode 0600, `SO_PEERCRED` check before the request is read (root or the daemon's own uid), 256-byte request line, 2 s deadline, no command changes state **[built]** |
| Sensor ↔ kernel | eBPF objects embedded in the packaged binary | Other BPF users | Sensor programs/maps are not pinned by default |
| Sensor ↔ host data | Kernel-sourced records | User-space–generated logs | Provenance marks journald/syslog-derived data as `user_space_reported` |
| Policy | Manager-signed policy | Local edits | Signature + monotonically increasing version; downgrade rejected |

## 2. Assets

Sensor and helper binaries; configuration; enrolled identity and private key; Manager CA
bundle; WAL and quarantine store; replay ledger; active policy; loaded BPF programs, links and
maps; systemd units; the rollback copy.

## 3. Threats and controls

| # | Threat | Control | Residual risk |
| --- | --- | --- | --- |
| T1 | Forged or replayed commands | Agent/host binding, boot binding for process targets (schema 2), expiry, skew, single-use durable ledger with an epoch, so a lost or corrupt ledger refuses older commands instead of re-running them **[built and live-verified, ADR 024 / 028 / platform ADR 0008]**; per-command ES256 signature with pinned, revocable keys **[built endpoint-side and live-verified, ADR 025; the Manager does not sign yet, platform ADR 0013]** | Manager signing-key compromise; Manager clock far ahead of the endpoint clock weakens the ledger-epoch check (ADR 028) |
| T2 | Manager impersonation | CA pinning; no verification bypass in release builds | CA compromise |
| T3 | Unprivileged local process reaches helper sockets | Root-only socket directory + `SO_PEERCRED` + fixed opcodes | – |
| T4 | Path manipulation in file actions (symlink swap, `..`, magic links, FIFO/device opens) | Absolute normal paths only; every directory walked with `openat(O_PATH\|O_DIRECTORY\|O_NOFOLLOW)`, symlinks refused; leaf opened `O_PATH\|O_NOFOLLOW`, content read through `/proc/self/fd/<n>` of that descriptor after a `(dev, ino)` check; special files never opened; quarantine by `renameat2(RENAME_NOREPLACE)` with an inode check and restore **[built and live-verified, ADR 026]** | Cross-filesystem copy path has a microsecond name-swap window before `unlinkat` (ADR 026); `openat2` not used, so no kernel-side `RESOLVE_*` enforcement |
| T5 | PID reuse during response | pidfd opened, start time re-verified, signal sent through the pidfd | Pre-5.3 kernels: documented small race window |
| T6 | Parser bugs (commands, procfs, netlink, ELF, journal, package DB) | Bounded parsers, size limits, fuzzing of every parser, ASan/UBSan runs | Unknown bugs |
| T7 | Event flooding to blind the sensor | In-kernel rate limits; priority-aware shedding that drops low-value events first; every drop counted and reported | Low-priority visibility reduced under sustained floods (reported) |
| T8 | WAL tampering or deletion | 0700 root directory; CRC per record; contiguous `seq` lets Manager see gaps | Root can delete; detected via the gap |
| T9 | Configuration tampering | Strict loader rejects non-root or group/world-writable files **[built]**; config path monitored | Root can edit; detected |
| T10 | Stopping the sensor | `Restart=always`; systemd watchdog; `process.signal` records every KILL, TERM, STOP, QUIT, ABRT or SEGV another process sends, with `target_is_sensor` set for the sensor (REAL-VM VERIFIED with SIGSTOP); unit-file changes are not yet recorded; BPF-LSM denial in protect mode | Root with `CAP_SYS_ADMIN` can always stop a user-space agent |
| T11 | Detaching sensor BPF programs | Links owned by the sensor process; periodic attachment self-check; foreign `bpf()` activity recorded; BPF-LSM denial in protect mode | Root can still unload; detected by self-check and Manager heartbeat |
| T12 | Binary replacement | Package-owned files; self-integrity check against the build manifest; file events on install paths | Root can replace; detected |
| T13 | Identity key theft | 0600 root key file; never logged | Root can read |
| T14 | Update abuse / downgrade | Signed packages; monotonic versions; rollback only to the copy kept by the package | Signing-key compromise |
| T15 | Response executor misuse, including host isolation | No network; typed requests from the sensor only; refuses protected targets (pid 1, kernel threads, sensor, helpers). Isolation: the sensor holds no `CAP_NET_ADMIN` and sends one of two fixed opcodes (command id only) to the ADR 004 helper, which applies a fixed ruleset; both isolation actions must be allow-listed together with the helper socket, are off by default, share the changing-action rate limit, and report `indeterminate` when the answer is lost **[built and live-verified in network namespaces, ADR 027]** | Helper pins the Manager address itself and the sensor cannot check it matches `manager_url`; no TTL or break-glass (ADR 004, locked) |
| T17 | Local abuse of the control socket (unprivileged client, stalled or oversized request, symlink or file at the socket path) | 0600 socket created under a restrictive umask; peer credentials checked first; bounded line and deadline; a non-socket at the path is never replaced; status is served from a cache so the control thread never touches live pipeline state **[built]** | A slow client can delay other control clients by up to the 2 s deadline (collection is unaffected) |
| T16 | Information exposure via telemetry | Command-line redaction; environment allowlist; file content only on explicit evidence commands | Unknown secret formats in command lines |

## 4. What root can defeat

A process with full root on the same kernel can disable any user-space security agent,
including this one. The position, consistent with the industry:

1. **Make it noisy:** observable tamper paths produce a `tamper.*` record, written to the WAL and
   sent as early as possible.
2. **Make it visible remotely:** Manager alerts when heartbeat, sequence continuity or a
   program-family heartbeat stops.
3. **Make it harder with BPF-LSM** where the host enables it (protect mode).
4. **Never claim prevention** where only detection exists.

## 5. Privacy

| Data | Default | Control |
| --- | --- | --- |
| Command lines | collected, pattern-redacted (`--password=`, `token=`, credentials in URLs) | policy redaction list |
| Environment | allowlisted keys only (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, `SSH_CONNECTION`, `SUDO_USER`) | policy |
| Host inventory secrets | machine-id as a salted digest; password hashes reduced to a state; DMI serial and uuid not collected; secret-looking kernel cmdline values redacted **[built]** | – |
| File contents | never, except explicit evidence commands | audit trail |
| DNS names, remote IPs | collected | policy can disable DNS |
| Memory | never by default; bounded capture only on explicit command | audit trail |

## 6. Hardening baseline

* Compiler: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE, full RELRO, non-executable
  stack, `-fstack-clash-protection`, `-fcf-protection` on x86_64.
* No shell execution in the sensor or helpers; any child process is spawned with a fixed argv.
* systemd sandboxing per unit (`ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`,
  `RestrictSUIDSGID`, `LockPersonality`, `RestrictRealtime`, `SystemCallArchitectures=native`,
  explicit `CapabilityBoundingSet`, `ReadWritePaths` limited to state directories).
* The responder additionally runs with `PrivateNetwork=yes`.

## 7. Verification

Each threat maps to a test in [LINUX_ENDPOINT_TEST_PLAN.md](LINUX_ENDPOINT_TEST_PLAN.md) §6. A
threat is only recorded as controlled when that test passes.
