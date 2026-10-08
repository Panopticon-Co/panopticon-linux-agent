# Linux Endpoint Handoff

For engineers taking over the Panopticon Linux endpoint who may not know the history. Read this first, then
[README.md](../README.md). It states facts as of the handoff pass and separates what is **verified** from what is
**implemented but not yet validated**.

**One-sentence summary.** `panopticon-sensord` is a resident C++20 Linux sensor with eBPF/fanotify/audit
telemetry, a durable write-ahead log, at-least-once delivery to the Manager, signed commands and signed local
policy, and self-integrity checks; it is validated on one platform (Ubuntu 22.04, kernel 5.15, x86_64, in a VM),
is not claimed to be production-ready, and four validations are still pending (6-hour soak, package end-to-end,
command-auth re-run after ADR 034, performance ladder).

## Contents

1. [Where things are](#where-things-are) · 2. [Repository relationships](#repository-relationships) ·
3. [Build, test, VM setup](#build-test-and-vm-setup) · 4. [What is complete](#what-is-complete) ·
5. [6-hour soak status](#6-hour-soak-status) · 6. [Validation evidence and what is pending](#validation-evidence-and-what-is-pending) ·
7. [Final gap analysis](#final-gap-analysis) · 8. [Known limitations and security gaps](#known-limitations-and-security-gaps) ·
9. [Integration boundaries](#integration-boundaries) · 10. [Do not break](#things-not-to-break) ·
11. [Recommended next priorities](#recommended-next-priorities) · 12. [Important commits](#important-commits)

## Where things are

| Item | Value |
| --- | --- |
| Repository | `Panopticon-Co/panopticon-linux-agent` |
| Development branch | `feat/flagship-endpoint` (the name is historical; it holds the whole current Linux endpoint, about 120 commits ahead of the old `main`) |
| Default branch on GitHub | **not** `main`: `origin/HEAD` points at `feat/linux-agent-foundation`. Nobody changed it; the owner of the organization should decide |
| Scope | Ubuntu 22.04, kernel 5.15, x86_64 only |
| Status log (authoritative, dated) | [endpoint/IMPLEMENTATION_STATUS.md](endpoint/IMPLEMENTATION_STATUS.md) |
| Capability matrix (115 rows, gaps against a mature EDR) | [endpoint/LINUX_ENDPOINT_CAPABILITY_MATRIX.md](endpoint/LINUX_ENDPOINT_CAPABILITY_MATRIX.md). Some rows lag the code; the status log wins |
| Decisions | [adr/](adr/), 36 records. ADR 004 (isolation privilege boundary) is locked |
| Security model and key custody | [endpoint/LINUX_ENDPOINT_SECURITY_MODEL.md](endpoint/LINUX_ENDPOINT_SECURITY_MODEL.md), [endpoint/LINUX_ENDPOINT_KEY_CUSTODY.md](endpoint/LINUX_ENDPOINT_KEY_CUSTODY.md) |

## Repository relationships

| Repo | Role for the Linux endpoint | Branch to use |
| --- | --- | --- |
| `panopticon-linux-agent` (this) | The sensor, response library, helper, tests, packaging | `main` after the handoff merge; `feat/flagship-endpoint` carries the same history |
| `panopticon-contracts` | **Owns the record format**: `schema/linux-endpoint/1.0.schema.json`, spec, fixtures, validator | `feat/linux-endpoint-record` (HEAD `2a8e847`); default branch is `master`; not merged |
| `panopticon-manager` | Ingest, ack cursor, command signing, vendored schema copy | `feat/linux-command-signing` (HEAD `9effe68`, contains the ingest branch); not merged |
| `panopticon-detection-engine` | Out of scope for now | – |
| `panopticon-agent` (Windows) | Independent; no shared code | – |

**Contracts dependency.** The sensor's serializer (`src/sensor/serializer.cpp`) must produce records valid against
the contracts schema. `scripts/validate_linux_endpoint.py --ndjson FILE` in contracts validates real output. Both the
contracts and Manager checkouts may contain **someone else's uncommitted Windows endpoint work**: do not
`git add -A`, reset, stash or switch branches in them; use a separate worktree (`git worktree add`). Details:
[CROSS_REPO_IMPACT.md](CROSS_REPO_IMPACT.md).

## Build, test and VM setup

```bash
git clone --recurse-submodules https://github.com/Panopticon-Co/panopticon-linux-agent.git
cd panopticon-linux-agent
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build-rel --parallel
sudo ctest --test-dir build-rel --output-on-failure -j1        # 21 targets
```

Dependencies, sanitizer/fuzz/lab options: [../BUILD.md](../BUILD.md). Test layers and every script:
[../TESTING.md](../TESTING.md).

### VM setup

`tests/vm/Vagrantfile` reproduces the validation VM (Ubuntu 22.04, kernel 5.15.0-91, 8 vCPU, 6 GB, VirtualBox);
[tests/vm/README.md](../tests/vm/README.md) gives the commands and the rules (one timing-sensitive job at a time, never
kill sensors by name while a soak runs, the package e2e is for disposable VMs only). The VM we used was
`panopticon-endpoint-dev`; it is not part of the repository.

## What is complete

Labels as defined in the README. Evidence lives in IMPLEMENTATION_STATUS (section numbers in brackets).

| Capability | State |
| --- | --- |
| eBPF process, memory, kernel, network, DNS, security telemetry; fanotify files; FIM; auth; host state | IMPLEMENTED + REAL-VM VERIFIED [S1–S13] |
| Entity graph, container identity, PID reuse | IMPLEMENTED + REAL-VM VERIFIED |
| WAL with CRC, quota, runtime self-check, recovery | IMPLEMENTED + REAL-VM VERIFIED + chaos [S11, S13.9–S13.10] |
| At-least-once uplink, ack cursor, Manager rejection to loss | IMPLEMENTED + REAL-VM VERIFIED [S7] |
| Loss accounting for all stages | IMPLEMENTED + chaos 16/16 (Release, ASan/UBSan) |
| Signed commands (ES256), ledger, 7 actions, dry-run default | IMPLEMENTED + REAL-VM VERIFIED (auth 51, chaos 56, isolation 26 checks) |
| Signed local policy and sweep of running processes | IMPLEMENTED + REAL-VM VERIFIED (sweep e2e 16 checks) |
| Self-integrity, signed build manifest, rollback detection | IMPLEMENTED + REAL-VM VERIFIED (integrity e2e 26 checks) |
| Trusted configuration checks, hardened systemd unit with watchdog | IMPLEMENTED; unit tested; install REAL-VM VERIFIED [S13.13] |
| TSan (ctest 20/20 + 30 min live), 16 fuzz harnesses × 900 s | SUSTAINED-LOAD VERIFIED (before the latest additions; see pending) |
| Signed `.deb` and apt repository tooling | IMPLEMENTED — **VALIDATION PENDING** |
| Throughput ladder harness | IMPLEMENTED — **VALIDATION PENDING** |

## 6-hour soak status

**Not complete at the time this section was written. Do not read "the soak passed" from this repository until the
result below says so.**

| Item | Value |
| --- | --- |
| Command | `sudo tests/soak/run_soak.sh 6 /var/tmp/soak` (Release build `build-rel`; environment `SENSORD`, `CTL`, `SIGNER`, `SCALE`) |
| Started | 2026-10-07 20:12:05 UTC (VM clock), sensor pid 248602 |
| Planned duration / expected end | 6.00 h, ending about 02:12 UTC on 2026-10-08, plus a drain and analysis |
| Progress when last read | 471 samples at 3.92 h (about 00:08 UTC 2026-10-08); sensor alive in every sample; threads constant at 12; fds 84–92; RSS 43 MB at start, rising to 66.8 MB by about 1.5 h and flat at 66.8 MB since (hours 2 and 3). **Preliminary only; no verdict until the full 6 h is analyzed** |
| Induced degraded periods (expected) | Manager outage of 90 s every 30 min, slow acknowledgements, dropped acknowledgements, and signed-policy rollback attempts every fifth publish (which turn health `degraded`, by design) |
| Unexpected degraded periods | None so far: of 471 samples, 124 were `degraded` and all 124 are induced (92 policy-rollback refusals, 32 command polls failing during Manager outages); 347 `healthy`. To be rechecked against the complete log |
| Perturbation windows | Builds and test runs on the same VM while the soak ran: about 20:27–21:30, 21:37–21:55, 22:00–22:12, 22:30–22:35 UTC, and a niced Release build plus full ctest 23:55–00:05 UTC (the ctest itself 00:03–00:05). A verdict that depends on those minutes must say so |
| Result | **PENDING.** `/var/tmp/soak/report.txt` and `report.json` are written when it finishes |

The RSS verdict in `tests/soak/soak.py` deliberately prints "NOT ENOUGH DATA" for runs under 2 h. A pass requires:
no unexplained loss or gap, `seq` contiguous, WAL and policy accounting consistent, RSS/fd/thread trends bounded
after warm-up, and a clean shutdown. Do not call stability proven from a short run.

To reproduce or resume: build `build-rel` Release, then run the command above on a quiet VM. It cannot be paused;
a restart is a new run.

## Validation evidence and what is pending

| Validation | State |
| --- | --- |
| Release unit tests (21 targets) | **21/21 passed** on the VM, Release build of `5491442` (documentation-only change on top of the last code commit `d90068c`), 2026-10-08 00:03–00:05 UTC, niced, as root, 131 s; 0 compiler warnings in the 143-target build |
| ASan/UBSan | Full ctest and chaos 16/16 passed once; long repeat pending |
| TSan | ctest 20/20, 30 min live, 0 reports, before policy sweep and rollback code; re-run pending |
| Chaos | 16/16 Release and ASan/UBSan; 14 kill -9; two power-loss runs |
| Command authorization e2e | 51 checks passed before ADR 034; the lab-versus-packaged scenario 7 needs a re-run |
| Integrity / rollback e2e | 26/26 |
| Policy sweep e2e | 16/16 |
| Package e2e | **Never run** (`tests/e2e/run_package_e2e.sh`, disposable VM) |
| Performance ladder, latency | Harness only; **not measured** |
| Fuzz | 16 harnesses × 900 s once |

## Final gap analysis

Classification of every gap named in the plan, with the decision. "Today" means during the handoff pass.

| Area | Classification | Decision |
| --- | --- | --- |
| Provider runtime recovery / re-attachment | IMPLEMENTED + REAL-VM VERIFIED (lost hooks detected and re-attached, S13.14/16) | Done. Detach by an attacker is not reported as tamper (future) |
| Prevention / enforcement | NOT IMPLEMENTED | Future: BPF-LSM or fanotify-permission design needed; out of the current scope |
| Self-protection | PARTIAL (service hardening, integrity detection; no anti-kill, no protected process) | Future; document, do not claim |
| Binary self-integrity | IMPLEMENTED + REAL-VM VERIFIED | Done; same-host trust anchor is a documented limit |
| Signed package / update path | IMPLEMENTED — VALIDATION PENDING | Validate today after the soak (`run_package_e2e.sh`); fix what it finds |
| Missing telemetry categories (package events, library loads, injection, interface/route, USB, log tampering, OS/hardware inventory, cloud identity) | NOT IMPLEMENTED | Future, ranked in the capability matrix; no stubs |
| File telemetry performance | PARTIALLY VERIFIED (mixed workload and FIM; no dedicated file-event storm ladder) | Future: add a file storm to `tests/perf` |
| Latency measurements (kernel→WAL p99, host→Manager p95) | NOT YET MEASURED | Future: needs a timestamp harness; do not quote numbers |
| Fuzzing | IMPLEMENTED + SUSTAINED-LOAD VERIFIED for one 900 s campaign | Future: longer campaigns, structure-aware corpora |
| Long soak | VALIDATION PENDING (running) | See above |
| Long sanitized runs | PARTIALLY VERIFIED | Validate after the soak: ASan/UBSan chaos with `MEMCAP_MB=512`, TSan on the latest code |
| Pipeline scalability / concurrency | PARTIAL (single pipeline thread, ≈12,000 events/s loss-free; excess shed and reported) | Do not redesign without ladder evidence; sequence, ordering, loss accounting and WAL semantics must survive any change |
| Manager-side command signing | IMPLEMENTED + REAL-VM VERIFIED against a real Manager process over HTTPS (S13.17: sign, verify, ledger, action, result; a command rewritten after signing was refused) | Remaining: the Manager branch is not merged; the signing key is a file held online by the Manager process (whoever controls it can sign); distributing the public key at enrollment is not built (see key custody) |
| Forensic / evidence collection | PARTIAL (process info, file collect with hash, quarantine; no memory capture, no evidence signing or chain of custody) | Future |
| Secure update / rollback | Rollback **detection** IMPLEMENTED + REAL-VM VERIFIED; automatic update and automatic rollback NOT IMPLEMENTED | Future: out of the current scope |
| Cross-kernel / distro / architecture | FUTURE — OUT OF SCOPE | 6.x needs BPF verifier fixes (`on_tcp_accept` is rejected); ARM64 needs its own `vmlinux.h`; SELinux unverified |

## Known limitations and security gaps

Repeated here so a maintainer does not have to hunt: single validated platform; no prevention; trust anchors on the
same host (a root attacker who replaces the binary can replace the keys and manifest); no secure-boot/IMA/TPM anchor;
killing the sensor, detaching its BPF programs or ptracing it is not reported as `tamper.*` (the next start reports
the blind interval as `sensor_gap`); no certificate pinning; no independent security review; the package path is not
verified; telemetry gaps listed above; queue depth is not exposed in health; transport compression is not used (the
Manager route does not accept it). `LINUX_ENDPOINT_SECURITY_MODEL.md` has the threat-by-threat list.

## Integration boundaries

* **Record contract:** sensor ↔ Manager only through Linux endpoint record 1.0 (contracts repo). Never edit the
  Manager's vendored copy without the contracts change.
* **Command contract:** the Manager signs, the endpoint verifies. The signed envelope, key ids and the signer tool
  (`panopticon-command-signer`, used by the tests) are described in ADR 025; signing vectors are in
  `tests/e2e/command_signing_vectors.py`.
* **Detection Engine:** deliberately not integrated. The Linux endpoint should remain **independently mature**
  (validation complete, gaps closed or documented) before any deep Detection Engine integration. Do not add
  Detection Engine code to this repository or detection logic that executes responses.
* **Response:** remediation stays dry-run except in sacrificial test targets; detection/policy code never calls the
  executor.

## Things not to break

1. **No silent loss.** Every disappearing event arrives or is represented by a correctly attributed `loss`/`gap`
   record. `tests/chaos/analyze.py` is the arbiter; do not loosen its thresholds.
2. **`seq` contiguity** and ordering per sensor stream, and the single pipeline thread that guarantees them.
3. **WAL durability and at-least-once replay**: the ack cursor moves only on a matching acknowledgement.
4. **Bounded memory** everywhere; do not weaken the Release memory budget to make a sanitizer pass (use `MEMCAP_MB`).
5. **The command chain**: signature → epoch/boot/target/lifetime → durable ledger → execute → durable result →
   `response.action`. A packaged build must not be able to trust unsigned commands (ADR 034).
6. **Fail-safe policy/integrity updates**: a bad update leaves the previous state in force.
7. **Privilege separation** of the isolation helper (two fixed opcodes, ADR 004).
8. **Schema strictness** (`additionalProperties: false`) and contracts/Manager parity.
9. Do not put "production-ready" language into docs; use the validation labels.

## Recommended next priorities

1. Read the soak report (section above) and record the verdict; run the pending validations in this order on a
   quiet VM: full Release ctest, `run_package_e2e.sh`, `run_command_auth_e2e.sh`, `tests/perf/ladder.py` (default and
   `--recover`), long ASan/UBSan chaos, TSan on the latest code. Fix and re-run, and record results in
   IMPLEMENTATION_STATUS.
2. Get the contracts and Manager branches reviewed and merged by their owners; decide the agent repository's default
   branch.
3. Add what a real deployment needs next: tamper reporting for sensor kill/BPF detach, an externally anchored trust
   root (TPM/IMA or a signed key-distribution message), certificate pinning.
4. Close the highest-value telemetry gaps (package events, library loads, injection) using the capability matrix.
5. Measure latency and file-event performance; only then consider changing the pipeline threading.
6. Decide, with Sokhi, when the endpoint is mature enough to connect to the Detection Engine through the Manager.

## Important commits

Agent repository, `feat/flagship-endpoint` (see `git log --oneline origin/main..HEAD` for all of them):

| SHA | Subject |
| --- | --- |
| `d90068c` | soak signed-policy workload, honest RSS verdict, scripts executable, ignore `__pycache__` |
| `f3388a5` | throughput ladder and overload-recovery harness |
| `ab77bb9` | key custody document |
| `0e18ee6` | rollback detection (ADR 036) |
| `351a839` | policy sweep of running processes (ADR 035) |
| `d973dba` | no unsigned commands in packaged builds (ADR 034) |
| `6ac1a19` | signed `.deb`, apt repository, package e2e |
| `d236fa2` | signed build manifest and self-integrity (ADR 033) |
| `112cbdc` | per-command ES256 authorization (ADR 025) |
| `940d1ed` | chaos suite |
| `e896b16` | at-least-once HTTPS delivery |

Contracts `2a8e847`, `3bbb993`, `b04b1a0`; Manager `9effe68`, `68be0e8`, `9cf27b1`, `bceea18`.
