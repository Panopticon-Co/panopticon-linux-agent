# Testing

How the current Linux endpoint (`panopticon-sensord`) is tested. The plan and its rationale are in
[docs/endpoint/LINUX_ENDPOINT_TEST_PLAN.md](docs/endpoint/LINUX_ENDPOINT_TEST_PLAN.md); dated results are in
[docs/endpoint/IMPLEMENTATION_STATUS.md](docs/endpoint/IMPLEMENTATION_STATUS.md). A passing run of a layer says
nothing about layers above it, and nothing about platforms other than Ubuntu 22.04 / kernel 5.15 / x86_64.

## Layers

| Layer | What | How to run | Needs |
| --- | --- | --- | --- |
| Unit and component | 21 CTest executables: WAL, uplink, serializer, entity graph, policy, integrity, command auth, parsers, file actions, isolation IPC | `ctest --test-dir build --output-on-failure -j1` | Linux; a few need root |
| Live ground truth | `panopticon-ebpf-tests` and the other provider tests run the real hooks and compare with procfs / `/proc` ground truth | `sudo build/panopticon-ebpf-tests` | root, kernel 5.15 |
| End to end | One script per feature, each starting a real sensor and, where relevant, a fake Manager over TLS | `sudo tests/e2e/run_*_e2e.sh` (header of each script has usage) | root; disposable VM |
| Chaos | 16 scenarios: baseline, kill9, outage, ackloss, badack, http503, rejected, slowack, diskfull, clock, walcorrupt, ringoverflow, memcap, nofile, walseg, waldir (+ power loss, which needs a reboot) | `sudo tests/chaos/run_chaos.sh [scenario ...]` | root; `MEMCAP_MB=512` for sanitizer builds |
| Sanitizers | ASan+UBSan and TSan builds of the full ctest and of the chaos suite | See [BUILD.md](BUILD.md) | clang build dir |
| Fuzz | 16 libFuzzer harnesses over every parser that sees untrusted bytes | `tests/fuzz/run_fuzz.sh [seconds] [target ...]` | clang, `build-fuzz` |
| Performance | Idle cost, hook overhead, record sizes, network storm, throughput ladder | `tests/perf/run_*.sh`, `tests/perf/ladder.py` | root; quiet VM; Release build |
| Soak | Multi-hour run with mixed load, Manager faults, signed commands and signed policy | `sudo tests/soak/run_soak.sh [hours] [work-dir]` | root; dedicated VM |

The chaos invariant is the contract for every change to the pipeline: *every event that disappears must either arrive
at the Manager or be represented by an explicit, correctly attributed loss or gap record.* `tests/chaos/analyze.py`
checks it for chaos and soak runs. Do not loosen its thresholds to make a run pass.

## End-to-end scripts

| Script | Proves |
| --- | --- |
| `run_command_auth_e2e.sh` | Signed commands run; unsigned, foreign-key, tampered, wrong-endpoint, replayed commands are refused (ADR 025, 034) |
| `run_command_chaos_e2e.sh` | Bursts, rate limit, duplicates, hostile content, restart mid-command (ADR 024, 028) |
| `run_isolation_command_e2e.sh` | `ISOLATE_HOST` / `RELEASE_HOST_ISOLATION` through the command channel with real packets between namespaces (ADR 027) |
| `run_integrity_e2e.sh` | Binary edit/replace/delete, manifest invalid/missing, rollback, restoration (ADR 033, 036) |
| `run_policy_sweep_e2e.sh` | A signed policy applied to already-running processes (ADR 035) |
| `run_package_e2e.sh` | Signed apt repository: install, upgrade, corrupted/wrong-key/unsigned repository, downgrade, tamper. **34/34 on the VM, 2026-10-08** ([log](docs/endpoint/evidence/package-e2e-2026-10-08/package-e2e.txt)) |
| `run_isolation_*_e2e.sh`, `isolation_namespace_spike` | Foundation helper mechanics; also run in GitHub CI (see below) |

## Current results and what is pending

See the table in [README.md](README.md#15-current-validation-status) and the handoff status in
[docs/HANDOFF.md](docs/HANDOFF.md). In short: the unit/live/e2e/chaos/sanitizer/fuzz layers have passed on the
validation VM; the 6-hour soak of the current build (an older build completed one, see the evidence directory), a re-run of the command-auth e2e after ADR 034, and the
performance ladder are pending.

## GitHub CI

`.github/workflows/ci.yml` builds and runs the portable tests and the namespace-based isolation scripts on Ubuntu
24.04. Its eBPF step is non-blocking because the 6.x verifier rejects one network program. It is a regression
guard, not validation of the endpoint.

## Foundation agent tests (original text)

`panopticon-linux-core-tests` is a deterministic CTest executable. It verifies PID-reuse-safe
identity tuples, priority overflow behavior, spool acknowledgement and corrupt-record recovery,
command expiry/replay/protected-PID handling, bounded IPv4/IPv6 TCP and UDP procfs parsing,
and the explicit non-Linux collector boundary.

Linux CI runs a normal C++ build plus an ASan/UBSan build. Integration tests use an isolated
procfs fixture, a disposable VM, or (for host isolation) disposable Linux network namespaces; no
test may kill a user process, alter the CI runner's real/default-namespace firewall, or
quarantine user data.

`tests/e2e/` holds shell-driven end-to-end suites, each wired into `.github/workflows/ci.yml`:

- `run_isolation_namespace_spike.sh` -- de-risking spike proving the netlink
  ruleset-apply/tear-down mechanics work under `unshare -rn` before the privileged helper was
  wired into the live command-dispatch path (see ADR 004).
- `run_isolation_e2e.sh` -- IPC/state-file mechanics between the agent and
  `panopticon-isolation-helper`.
- `run_isolation_packet_verification_e2e.sh` -- CI-verified, real non-loopback packet-level
  containment: three network namespaces joined by two veth pairs (genuine non-loopback IPv4),
  proving the Manager stays reachable during isolation, an unrelated peer becomes unreachable,
  connectivity is restored after release, and isolate/release are idempotent. Confirmed green on
  real GitHub Actions CI (see `docs/VM_VALIDATION_GAPS.md` for the run reference and for what
  this still cannot prove without a real VM/NIC).
- `run_isolation_robustness_e2e.sh` -- restart/crash-recovery scenarios. Its "restart while
  isolation state exists" case has an **undiagnosed, intermittent CI flake** (not caused by, and
  not fixed by, the isolation-ruleset correctness fix above) -- see `docs/VM_VALIDATION_GAPS.md`.
  Do not treat an isolated failure of this script alone as a regression; do not weaken or remove
  it to make it pass.
