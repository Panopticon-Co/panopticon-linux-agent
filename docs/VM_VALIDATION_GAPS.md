# VM validation gaps

Automated tests cover pure core behavior on the development host. A real Ubuntu/Debian
systemd VM is still required for procfs process collection, inotify/journald sources,
capability-limited service operation, HTTPS Manager delivery, and any firewall isolation.
The former Rust validation commands and service are discontinued by ADR 003. Do not install
or validate that prototype. After the C++20 rebaseline, run its CTest/sanitizer suite, install
the service, generate benign process/file activity, and verify only the documented Manager
endpoint before marking each item validated.

## Host isolation (ADR 004)

CI proves the netlink mechanics (tests/e2e/isolation_namespace_spike.cpp) and the real
helper's IPC/idempotency/state-file behavior (tests/e2e/run_isolation_e2e.sh) inside a
throwaway network namespace with only loopback. What CI cannot prove: that isolating a real
host on a real network actually blocks a non-Manager peer while keeping the pinned Manager
channel open on a real non-loopback interface. On the VM: install both units, confirm
`panopticon-isolation-helper` starts and creates its socket, issue `ISOLATE_HOST` from the
Manager, verify from a second host that all non-Manager traffic is dropped while the agent's
Manager connection keeps working, then issue `RELEASE_HOST_ISOLATION` and verify normal
connectivity returns.
