# ADR 015: Process response through pidfd with verified identity

**Status:** Accepted
**Date:** 2026-10-06

## Context

The existing `terminate_process` read procfs, compared the (pid, start time) identity, and then
called `kill(pid, SIGTERM)`. Between the comparison and the signal the process can exit and the PID
can be handed to an unrelated process, so the signal lands on the wrong target. For an agent that
runs as root and is driven by remote commands this is the one response bug that must not exist.
There was also no tree termination (matrix BB2) and no way to see what a response would do.

## Decision

1. A response module (`response.hpp`, `response.cpp`) owns process signalling. The Manager command
   envelope and the `terminate_process` signature are unchanged; `terminate_process` now calls it.
2. Order of operations: protection check, `pidfd_open(pid)`, then read the start time from
   `/proc/<pid>/stat` and compare it with the identity the caller named, then signal through
   `pidfd_send_signal`. The pidfd refers to one process for its whole life, so if that process has
   exited the signal fails with ESRCH and nothing else is hit. A PID that was reused before
   `pidfd_open` shows a different start time and is refused as a mismatch.
3. Where pidfd is unavailable (ENOSYS, EPERM, EACCES), the responder falls back to `kill(2)` after
   the same verification, re-reading the identity immediately before the signal. The remaining
   window is the time between that read and the syscall. The mode (`pidfd` or `pid_fallback`) is
   part of every outcome, and `allow_pid_fallback = false` turns the fallback off.
4. Never signalled: pid 0 and 1, pid 2, the agent itself, every ancestor of the agent, and kernel
   threads (parent pid 2). A tree is refused as a whole if any member is protected.
5. `response_options::dry_run` defaults to true. A dry run does all verification, reports the
   identities it would act on, and sends nothing. The command path sets it to false because that
   behaviour already existed.
6. SIGTERM is the default. Optionally the responder waits a grace period for the pidfd to become
   readable (exit), then escalates to SIGKILL.
7. Tree termination: verify and bound the tree (default 256 processes), check every member against
   the protection rules, then stop the root with SIGSTOP so it cannot keep forking, rescan and stop
   new descendants until a rescan finds nothing new (at most 8 rounds), and only then SIGKILL every
   held pidfd. If the tree keeps growing, exceeds the bound, or gains a protected member, every
   stopped process is continued and the operation is refused.

## Consequences

* A PID reused between verification and signal cannot be signalled on kernels with pidfd (5.3 and
  later). On older kernels the fallback has a small race, which is stated in the outcome and can be
  disabled.
* A descendant that was reparented to init before the first scan (its parent died earlier) is not
  part of the tree. `cgroup.kill` (5.14) is the planned complement for services and containers.
* The tree is held stopped for the duration of collection; a tree that refuses is released
  with SIGCONT, not killed.
* This is the response engine only. Which actions run automatically is a policy decision (S8);
  nothing in the sensor daemon calls it yet.
