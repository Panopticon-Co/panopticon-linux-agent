# Package end-to-end run, 2026-10-08

`package-e2e.txt` is the unedited output of `sudo BUILD=build-rel tests/e2e/run_package_e2e.sh` on the Ubuntu 22.04 VM
(kernel 5.15.0-91, x86_64, Release build): **34 PASS, 0 FAIL, exit 0**.

What it exercised: install from a signed local `file:` apt repository, a benign upgrade (must not look like tampering),
a `.deb` altered after signing (refused), a repository signed by an untrusted key and an unsigned one (rejected), apt
downgrade refused without `--allow-downgrades`, a deliberate rollback (reported as `manifest_rollback`, ADR 036), and an
installed file edited on a running system (attributed, repaired by `--reinstall`).

An earlier run the same day gave 30 PASS, 2 FAIL. The cause was in the test: a rejected `apt update` leaves apt's earlier
trusted lists in place, so installing 0.9.3 from them was correct. The test now offers 0.9.4 only in the rejected
repositories and checks it is neither visible nor installable.

Not covered: a remote repository, key custody (the release and repository keys are generated on the same host), a fleet.
