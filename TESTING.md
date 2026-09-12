# Testing

`panopticon-linux-core-tests` is a deterministic CTest executable. It verifies PID-reuse-safe
identity tuples, priority overflow behavior, spool acknowledgement and corrupt-record recovery,
command expiry/replay/protected-PID handling, and the explicit non-Linux collector boundary.

Linux CI runs a normal C++ build plus an ASan/UBSan build. Planned Linux integration tests must
use an isolated procfs fixture or disposable VM; no test may kill a user process, alter the host
firewall, or quarantine user data.
