# ADR 008: Write-ahead log and sequence-acknowledged delivery

**Status:** Accepted
**Date:** 2026-10-06
**Supersedes:** the durability properties of `durable_spool` (`src/spool.cpp`)

## Context

The existing spool never calls `fsync`, names segments from `steady_clock` (not unique across
reboots), uses an FNV-1a checksum, and the transport discards data on a batch-level HTTP 200
even though Manager may reject individual lines. A full spool causes a restart loop.

## Decision

1. Records are appended to segment files `wal-<first_seq:020>.log` in a 0700 directory.
   Framing: `u32 magic | u32 length | u32 crc32c(seq ‖ payload) | u64 seq | payload`.
2. Writes are group-committed: `fdatasync` at most every 200 ms or 256 KiB, and always before a
   delivery cursor advance. The acknowledged `seq` is persisted in `cursor` (temp file +
   `rename` + directory `fsync`).
3. On start every segment is scanned; a torn or CRC-failing tail is truncated and reported as a
   `loss` record (`stage: wal`).
4. `seq` continues from the highest durable record, so it is contiguous across restarts.
5. Manager acknowledges the highest contiguous `seq` it has durably stored; the uplink deletes
   whole segments whose last `seq` ≤ acknowledged.
6. At quota, the oldest unacknowledged segment is deleted and a `loss` record names the dropped
   `seq` range and record count. The sensor never exits because the WAL is full.

## Consequences

* A Manager outage only grows the WAL up to its quota; nothing is lost silently.
* Manager ingest must be idempotent on `(sensor_id, seq)` (slice S3).
