# VM validation gaps

Automated tests cover pure core behavior on the development host. A real Ubuntu/Debian
systemd VM is still required for procfs process collection, inotify/journald sources,
capability-limited service operation, HTTPS Manager delivery, and any firewall isolation.
The former Rust validation commands and service are discontinued by ADR 003. Do not install
or validate that prototype. After the C++20 rebaseline, run its CTest/sanitizer suite, install
the service, generate benign process/file activity, and verify only the documented Manager
endpoint before marking each item validated.

## Host isolation (ADR 004)

**Updated**: CI now proves real, non-loopback packet-level containment, not just IPC/
state-file mechanics. `tests/e2e/run_isolation_packet_verification_e2e.sh` wires three
real network namespaces together with two veth pairs (genuine non-loopback IPv4
addresses) and real TCP listeners standing in for "the Manager" and "an unrelated peer
host," then verifies actual reachability before/during/after isolate and release. Adding
this surfaced and led to fixing a real, critical bug (confirmed on real GitHub Actions
CI, not this development environment): `apply_isolation_ruleset()` could report success
while the nftables table/chains/rules were never actually created, because its leading
idempotent `DELTABLE` (against a table that does not exist on first run) silently doomed
the whole atomic batch transaction's commit, and a separate bug in ack-draining
(`mnl_cb_run()` stopping after the first successful ack) meant this was never detected.
Both are fixed; see `src/isolation_ruleset.cpp`'s doc comments and the commit that fixed
this for full detail. `apply_isolation_ruleset()` now also verifies the table actually
exists via a real `NFT_MSG_GETTABLE` query before ever reporting success, as defense in
depth against any future discrepancy of this kind.

What CI still cannot prove, and genuinely requires a VM (not achievable via network
namespaces): a real physical/virtual NIC shared with other real host traffic (as opposed
to a namespace's own isolated interfaces), SSH break-glass expectations under a real
operator's interactive login, and multi-NIC/routing-table edge cases. On the VM: install
both units, confirm `panopticon-isolation-helper` starts and creates its socket, issue
`ISOLATE_HOST` from the Manager, verify from a second real host that all non-Manager
traffic is dropped while the agent's Manager connection keeps working, then issue
`RELEASE_HOST_ISOLATION` and verify normal connectivity returns.

**Known, separate, pre-existing CI flake (not caused by the above, not yet root-caused)**:
`tests/e2e/run_isolation_robustness_e2e.sh`'s "restart while isolation state exists"
scenario intermittently fails with `isolation-client-tool: request failed`, and its log
shows what looks like two overlapping helper-process lifecycles. Reproduces on real CI
only intermittently (not every run); needs its own dedicated investigation rather than a
guessed fix. Track before relying on this specific script's CI-green status as proof of
restart-recovery correctness.
