# Testing

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
