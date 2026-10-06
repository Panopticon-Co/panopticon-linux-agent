# ADR 010: File-integrity monitoring over a persistence catalog

**Status:** Accepted
**Date:** 2026-10-06

## Context

Matrix row Q1 and the persistence rows (U2, AF2, AH1, AI1, AK1, AL1, AM1) need to answer two
questions: what is configured to run or grant access on this host, and what changed in it. The
file telemetry of ADR 009 reports writes, but it cannot say whether a write changed anything that
matters, cannot see changes made while the sensor was down, and drops events under a write storm.

## Decision

1. A **persistence catalog** (`persistence_catalog`) lists the locations an intruder uses: systemd
   units, cron, shell profiles, SSH keys and configuration, `ld.so.preload`, init scripts, sudo, PAM,
   account files, udev rules, autostart entries, module-load configuration and package hooks, each
   as a system path and, for every account in `/etc/passwd` with a real home directory, as a
   per-user path. It is a pure function of a filesystem root and is emitted as `state.persistence`.
2. Everything read is hostile. Files are opened with `O_NOFOLLOW|O_NONBLOCK` after an `lstat`, so a
   planted FIFO or device is listed and never read and a symlink is recorded with its target and
   never followed; content is read up to 1 MiB (larger files are listed with `hash_status
   too_large`); directories are listed at most 2048 entries deep to a fixed depth and a directory
   reachable twice is listed once; the whole scan is capped at 8192 items and says so.
3. **Secrets are never emitted.** An item carries the SHA-256 of the content and counted facts. For
   `authorized_keys` that is the number of keys, the number with a forced `command=`, and a
   16-hex digest of `sha256(type + " " + blob)` per key; no key, no comment, no option text.
4. A **baseline** (`fim_monitor`) is the last known state of every item. A change is a difference in
   kind, content (SHA-256 or hash status; size and mtime only for files too large to hash, so a
   bare `touch` is not a change), mode, owner, group or link target.
5. The baseline is **persisted** (default next to the WAL) as a strict text format written to a
   temporary file with mode 0600, `fsync`ed and renamed. A missing file is `created`; an unusable,
   truncated, damaged or symlinked file is a visible `reset` with a reason. A valid file is
   `loaded` and diffed against a fresh scan, so changes made while the sensor was down are reported.
6. Two inputs feed the diff. A **periodic rescan** (default 300 s) finds everything, including what
   events missed. **File events** that classify as persistence paths queue the path; after a
   500 ms debounce the path is described again and compared with the baseline, which coalesces an
   editor save into one change, ignores a rewrite with identical content, and attaches the acting
   process. A removed or moved directory also re-describes the baseline items below it.
7. A scan that was truncated or could not enter a directory says nothing about the items it did
   not reach: those keep their baseline entry and are not reported as removed.

## Consequences

* `fim.changed` carries the actor only when a file event named the path; a change found by
  comparing states has no actor and says so in `unavailable`.
* The actor is the process the entity graph knows under that pid when the record is built. If the
  process executed a different program in the meantime (a `bash -c` whose last command is
  exec-ed) the record shows the current image. The eBPF primary (matrix P1) will carry the identity
  at the moment of the write.
* Per-user locations are found from the account database; a home on a network filesystem is
  only seen by the periodic rescan.
* A change to a persistence file that is reverted before the next rescan and not seen as an event
  is invisible; this is inherent to state comparison and is why the file events exist.
