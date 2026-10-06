# ADR 012: Authentication telemetry from the system log

**Status:** Accepted
**Date:** 2026-10-06

## Context

Matrix rows AE1 (login success and failure), AF1 (SSH sessions) and AG1 (sudo, su, pkexec) need
to say who authenticated, from where, how, and what they ran with elevated rights. The primary
mechanism is the kernel audit multicast socket (`USER_AUTH`, `USER_LOGIN`, `USER_CMD`), which
needs `CAP_AUDIT_READ` and its own provider. That is a later part of this slice. Until then the
sensor must not be blind to authentication, and it must not claim more than a log line can prove.

## Decision

1. An `auth_log_provider` in family `auth` follows `/var/log/auth.log` and `/var/log/secure`
   the way `tail -F` does: it starts at the end (history is not replayed), drains the old file
   and follows the new one after a rotation, restarts at the top after a truncation, and
   refuses to follow a symlink. Complete lines only; an oversize line is skipped and counted.
2. The line is hostile input. A user name, a sudo command and a TTY are chosen by whoever is
   logging in. The parser therefore:
   * anchors the program tag at the start and accepts only `sshd`, `sudo`, `su`, `pkexec` and
     `login`;
   * matches the fixed words of a message from the left and the address and port from the
     right, so the name `x from 1.2.3.4 port 22 ssh2` cannot change who or where the event is
     for, and a name that spells out `Accepted password for root` stays a failure;
   * validates addresses, ports and `SHA256:` fingerprints, and drops the line otherwise;
   * takes the whole rest of a sudo line as the command, so it cannot rewrite the fields before it;
   * replaces control and non-ASCII bytes, bounds every field, and says so with `sanitized`
     and `truncated`.
3. Duplicates are not reported twice: sshd's `Invalid user` line is skipped because the
   `Failed ...` line that follows carries the same attempt with the address; `pam_unix`
   authentication-failure lines are skipped for the same reason.
4. Both rsyslog time formats are read. The traditional `Oct  6 01:40:47` has no year and no
   zone, so the year is taken from the observation time (a December line seen just after New
   Year belongs to last year) and the time is read as local time.
5. Records: `auth.login` (success), `auth.failure` (login failure), `auth.privilege` (sudo, su,
   pkexec, either outcome). SSH is carried by `auth.login` and `auth.failure` with `service`
   `sshd`, `source` and `key`; there is no separate `auth.ssh`.
6. Provenance is `{auth_log, AUTHLOG, user_space_reported}`: the record is what a program chose
   to write, delayed by syslog. The acting process has usually exited, so `process` carries the
   logged pid with `unavailable: process_exited`, or `not_supported_by_provider` when the line
   has no pid (sudo does not log one).
7. A per-poll event budget (2000) bounds a log flood. What exceeds it is counted and reported
   as a governor loss, never dropped silently.

## Consequences

* A forged log line (anyone who can write to syslog, or a program that logs a chosen string)
  produces an event. The `user_space_reported` confidence says so, and detection must weigh it.
  The audit mechanism, which is kernel-reported, stays the primary for these rows.
* Delivery is delayed by syslog and by the 500 ms poll.
* Distro formats differ. Only the formats covered by tests are parsed; an unknown line is
  ignored rather than guessed.
* Hosts that log only to the journal produce nothing until a journal provider exists; the
  provider says so through `probe()` when neither file is readable.
