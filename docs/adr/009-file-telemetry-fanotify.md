# ADR 009: File telemetry through fanotify with FID reporting

**Status:** Accepted
**Date:** 2026-10-06

## Context

The capability matrix lists eBPF fentry hooks on `security_file_open`, `security_inode_create`,
`security_inode_unlink/rename/link` and `security_path_chmod/chown` as the primary mechanism for
file telemetry (P1-P3), with fanotify as the fallback. Reaching those hooks needs per-kernel
attach points and in-kernel path resolution (`bpf_d_path` is restricted to an allowlist of
hooks), and the first production slice must work on every supported kernel. fanotify with
`FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (Linux 5.9) delivers create, delete, move, attribute and
close-after-write events for a whole filesystem with the acting pid and a directory handle plus
entry name, with no per-hook kernel code.

## Decision

1. `fanotify_file_provider` (family `file`, mechanism `FANOTIFY`) is the first file provider.
   Event masks: `CREATE`, `DELETE`, `MOVED_FROM`, `MOVED_TO`, `CLOSE_WRITE`, `ATTRIB`, `ONDIR`,
   marked per filesystem (`FAN_MARK_FILESYSTEM`) for ext2/3/4, xfs, btrfs, f2fs, tmpfs and
   overlay, re-evaluated every 30 s so late mounts are covered.
2. Paths are resolved from the directory handle with `open_by_handle_at(O_PATH)` and
   `readlink(/proc/self/fd/N)`, then joined with the reported name. Resolutions are cached
   (4096 entries, 60 s) and the cache is dropped whenever a directory is moved or removed.
   Failure to resolve is reported in `unavailable[]` (`object_gone`, `permission_denied`,
   `not_supported_by_provider`), never guessed.
3. The kernel buffer is decoded as hostile input: every length is checked against the bytes that
   remain, names must be terminated and are bounded to 4096 bytes, handles to 128 bytes, and
   any inconsistency stops decoding and is counted, never partially trusted.
4. Events are filtered after resolution against an include/exclude prefix list (persistence,
   credential, binary and staging directories by default; `/proc`, `/sys` and the WAL and
   control-socket directories of the daemon itself excluded). Events from the daemon pid are
   dropped at the source.
5. A token-bucket governor (5000 events/s sustained, 10000 burst) bounds work during write
   storms. Skipped events are counted exactly and reported as a `loss` record with
   `stage: governor`; a kernel queue overflow is a `kernel` loss.
6. **The kernel merges queued events** that share pid, directory and name, OR-ing their masks
   and placing the combined event at the earlier position. Consequences handled explicitly:
   * one event may carry several operations; they are emitted in the order create, moved-to,
     moved-from, attrib, close-write, delete;
   * in a rename chain (`a` to `b`, then `b` to `c`) one event carries `MOVED_TO|MOVED_FROM` for
     `b`; the arrival came first, so the `MOVED_TO` half is handled first;
   * other events of the same process can appear between the two halves of a rename, so a
     pending `MOVED_FROM` is closed only by its `MOVED_TO`, a newer `MOVED_FROM`, or a 25 ms
     deadline; unpaired halves are emitted with an `unavailable` entry instead of being paired
     across a gap, and a half skipped by the governor cancels the pending pair.
7. The pipeline resolves the acting process through the entity graph (`process_exited` when it
   is already gone) and takes an `lstat` of the path after the event (`object_gone` when it no
   longer exists). The stat is the state after the event, not at the moment of the operation.

## Consequences

* P1-P3 are covered on 5.9+ kernels today; they remain PARTIAL until the eBPF fentry primary
  exists (it gives `file.chmod/chown/setxattr` distinctly, open-for-write semantics and old/new
  values), and until a second kernel validates the decoder.
* The fallback cannot tell `chmod` from `chown` or `setxattr`: all are `file.attrib`.
* `file.modify` means close-after-write, not each `write()`.
* Hard links are not reported by this provider (`file.link` is eBPF-only).
* `CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH` are required; without them the provider is
  `unavailable` with the reason in health and the rest of the sensor runs.
