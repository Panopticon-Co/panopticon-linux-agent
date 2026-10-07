# ADR 030: WAL integrity while the sensor runs

**Status:** Accepted (implemented; unit tested; real-VM verified by the `walseg` and `waldir` chaos scenarios)
**Date:** 2026-10-07

## Context

The write-ahead log checks its segments when it is opened (torn tail, bad checksum, gap, all reported as `wal`
losses). While it runs it trusted them. Two chaos scenarios written against the real sensor showed what that costs
(`tests/chaos/run_chaos.sh walseg`, `waldir`, on the build before this change, Ubuntu 22.04, kernel 5.15):

| Scenario | What happened | Result |
| --- | --- | --- |
| `walseg`: two sealed segments in the middle of an undelivered backlog are deleted | `read()` failed with "cannot read write-ahead log segment" on every call, for ever. The uplink never got past the hole | Manager received 27 records, then nothing; 0 of 40 later execs arrived; no loss reported; sensor alive and healthy-looking |
| `waldir`: the whole WAL directory is removed | the active segment's descriptor pointed at an unlinked file: appends succeeded and went nowhere | Manager received 0 records; 0 of 40 later execs arrived; no loss reported |

A checksum failure found by `read()` while running returned `corrupt_data` the same way, with the same permanent
effect. Both are conditions an administrator, a disk fault, a full-disk cleaner or an attacker can produce, and in all
of them the endpoint went quiet without saying so.

## Decision

Missing or damaged storage becomes an explicit loss, delivery continues past it, and sequence numbers are never
reused.

1. **Missing segments** (`write_ahead_log::verify_storage`, called by the pipeline about once a second, and by
   `read()` when an `open` fails with `ENOENT`). A segment whose path no longer exists, or, for the active segment,
   whose descriptor no longer names the file at that path (deleted and recreated, or unlinked), is removed from the log's
   index. The log keeps the first and last seq of every segment in memory, so the range is exact: the records of that
   segment above the acknowledged seq are reported as a `wal` loss with reason `removed` and the detail
   `removed: seq a-b, N bytes`. Records already acknowledged are not reported (the Manager has them).
   A removed active segment closes its descriptor and the next append opens a new segment at the next seq. A
   removed directory is created again (mode 0700).
2. **Damaged frames at runtime** (`read()`). The seq a frame must carry is tracked from the segment's first seq, so
   the damage is located without trusting the damaged header. A bad magic, a wrong seq, a short read, or a failed checksum
   isolates the rest of that segment: the valid prefix stays deliverable, the remainder is reported as `corrupt_segment`
   with its exact range, the segment is sealed if it was the active one, and the read continues with the next
   segment. If the first frame is bad the file is removed.
3. **A read that meets a missing file continues in the same call** with the first segment that still holds records
   at or after the point reached, so an empty batch is never the result of a hole.
4. **Seqs are never reused.** `next_seq` is untouched; the lost range stays a hole in the stream, and the loss
   record that explains it takes its own, new seq. The Manager sees `wal` loss `count` and the range in `detail`, in
   the same form as the quota and recovery losses it already receives.
5. **At-least-once delivery is preserved.** Nothing is acknowledged by this code. A record that was delivered but not
   yet acknowledged when its segment disappears is counted as lost: an over-report, never an under-report.
6. Not done on purpose: restoring a deleted segment, or trying to resynchronise inside a damaged segment after
   the damaged frame (the length field cannot be trusted, so the rest of the segment is not guessed at).

## Evidence

- Unit tests (`tests/sensor_tests.cpp`): `wal_removed_sealed_segment_is_reported_and_skipped` (range exact, only
  unacknowledged records counted, reader finishes the stream, restart opens), `wal_removed_active_segment_and_directory`
  (loss range, new segment readable, directory re-created private, acknowledged records not reported),
  `wal_runtime_corruption_is_isolated` (one loss, exact range, seqs strictly increase, nothing from the lost range is
  delivered, a second pass yields the same stream, the loss is reported once, no seq reuse).
- Real VM, same scenarios on the fixed build:
  `PASS walseg post_removal_seen=40/40 removal_reported=yes quota_dropped=no stored=6524 missing=140 wal_loss_reported=140`
  (the report equals the two segments' 140 records exactly),
  `PASS waldir post_removal_seen=40/40 removal_reported=yes quota_dropped=no stored=1937 missing=6527 wal_loss_reported=6559`
  (32 more than missing: delivered but unacknowledged records of the removed directory, the safe direction).
  The scenario fails if the quota dropped anything, so the loss it sees is the removal's.

## Limits

- Detection takes up to one second (the `verify_storage` period) or the next `read()`, whichever comes first.
  Records appended into an unlinked active segment in that window are in the reported range (the log's own seq
  accounting counts them) but were never on disk.
- An attacker with root can delete the segments and the sensor's own binary. This makes the damage visible, it does
  not prevent it; tamper records for the sensor's files are a separate gap (matrix BC1).
- The corruption path is exercised by unit tests only; the chaos scenarios remove files, they do not flip bytes in
  a running sensor's segment.
