# ADR 013: Authentication telemetry from the kernel audit group

**Status:** Accepted
**Date:** 2026-10-06

## Context

ADR 012 reads authentication events from the system log, which is a fallback: the line is
written by a program, delayed by syslog, and names a pid that has usually exited. The matrix
mechanism for AE1, AF1 and AG1 is the kernel audit subsystem, whose records carry the sending
process's pid, uid and audit uid filled in by the kernel.

## Decision

1. An `audit_netlink` provider in family `auth`, listed before `auth_log`, joins the audit
   read-log multicast group (`NETLINK_AUDIT`, group 1). It is read-only: it installs no audit
   rules, does not register as the audit daemon, and cannot change what auditd does. It needs
   `CAP_AUDIT_READ`; `probe()` says so when the bind fails, and the pipeline then starts
   `auth_log` instead. When the audit provider runs, `auth_log` stays on standby
   ("superseded by audit_netlink") so an event is never reported twice.
2. Only datagrams from the kernel (netlink portid 0) are decoded. The decoder checks every length
   against the datagram, caps a message at 9000 bytes and never reads out of bounds; the tests
   cut a valid datagram at every byte and feed random buffers under ASAN and UBSAN.
3. Records read: `USER_LOGIN` success (`auth.login`), `USER_AUTH` failure (`auth.failure`, or
   `auth.privilege` failure for sudo, su and pkexec), `USER_CMD` (`auth.privilege`, with the
   command, working directory, target user and result) and `USER_START` for `su`. A successful
   `USER_AUTH` and a failed `USER_LOGIN` are not reported: the following login or command, and
   the authentication failure, are the events. Without this rule every login would appear twice.
4. The kernel fills `pid`, `uid`, `auid` and `ses` in the header before the text the sender
   supplied. The tokenizer reads the first occurrence of each key, so the sender's text cannot
   override the kernel's fields; values are quote-aware (a quote inside a quoted value does not
   end it), `acct`, `exe`, `cmd` and `cwd` are decoded from quotes or hex, and every value is
   made printable and bounded. The actor is the audit uid (the real user, not root after sudo),
   or the uid when the audit uid is unset, resolved through `getpwuid_r` with a bounded cache.
5. Provenance is `{audit_netlink, AUDIT, observed}`: the pid and user come from the kernel. The
   sender's text is trusted as far as a process holding `CAP_AUDIT_WRITE` can be trusted.
6. A per-second budget (500) bounds a flood; the excess is counted and reported as a governor
   loss. `ENOBUFS` on the socket is counted as a loss so the pipeline reconciles.

## Consequences

* The record's `process` is the live sender (sudo, sshd), so the entity graph attributes the
  event to a real process and its ancestry, which the log fallback cannot do.
* Auditing must be enabled in the kernel. On a host with `audit=0` the group is silent;
  health says "no audit records seen yet" instead of claiming coverage, and the log fallback is
  not started because the audit socket did open. A later health check that switches to the
  fallback when no record arrives is a possible refinement.
* Auth failures from programs that do not use PAM through libaudit (some containers, custom
  daemons) are only visible in the log.
* Reading the group alongside auditd is safe: multicast delivery does not remove records from
  the daemon's unicast stream.
* Only auth and privilege records are decoded. Syscall, module-load, mount and credential
  records need audit rules, which this sensor does not install; those families use eBPF.
