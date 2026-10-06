# ADR 018: Uplink delivery and WAL cursor semantics

**Status:** Accepted
**Date:** 2026-10-06

## Context

Until now `panopticon-sensord` wrote records to a local WAL and nothing left the host. The Manager
gained a Linux endpoint ingest route (`POST /api/v2/linux-endpoint/records`, Manager ADR 007) that
validates each line against the 1.0 schema, derives and checks the record id, binds records to the
enrolled host, deduplicates by digest and answers with per-stream sequence accounting.

The sensor needs a delivery path that never loses a record it has not been told is stored, never
blocks collection, and cannot be wedged by one bad record or one bad response.

## Decision

1. **At-least-once delivery from the WAL.** `uplink` reads durable (synced) records after the WAL's
   acknowledged cursor, posts them as one NDJSON batch with the id `wal-<first>-<last>`, and only
   then calls `acknowledge`. Records are never deleted from the WAL before that. A retry sends the
   identical batch; the Manager's digest deduplication makes the repeat harmless.
2. **The cursor moves only on an answer that matches the batch.** The response must be HTTP 200,
   strict JSON (duplicate keys refused, depth, size and value count bounded), echo the batch id, and
   account for every record sent exactly once:
   `received == sent` and `accepted + duplicates + rejected == sent`, with each `rejected` entry
   naming a distinct line inside the batch. Anything else (empty body, other batch, short counts,
   wrong types, unnamed or repeated lines) is a refusal: the cursor stays and the batch is retried.
3. **A record the Manager rejects is quarantined, not retried forever.** When the answer above is
   consistent but names rejected lines, the rejection is the Manager saying that exact record can
   never be valid. The sensor appends it (seq, reason, the record) to `<wal_path>.rejected.ndjson`
   (bounded to 4 MiB), counts it in `records_quarantined` and `quarantine_failures`, keeps the
   reason in the metrics and in the shutdown report, and advances past it. The Manager's stream
   therefore shows a visible hole at that sequence number; the loss is accounted, not hidden.
   This was found by the first real run: a `network.connect` whose owner was never known was
   serialized with `"process":{}`, the schema rejected it, and delivery stalled behind it.
4. **Failure handling.** Network errors, 429 and 5xx back off exponentially from 1 s to 60 s with
   50-100 % jitter. 401 and 403 wait the maximum backoff (an identity problem is not hammered).
   413 halves the batch and it grows back after successes. Other refusals back off and are counted.
5. **Transport.** libcurl over HTTPS only. Certificate and host verification are always on and
   cannot be disabled; a private CA is supplied with `ca_bundle`. Bearer token and agent id come
   from the enrolled identity file (`identity_path`). The sensor refuses to deliver if the enrolled
   host id differs from the configured `host_id`.
6. **Collection never depends on delivery.** The uplink runs on its own thread. A missing identity,
   a build without libcurl, or an unreachable Manager only leaves records in the WAL; the reason is
   printed at start and kept in `uplink_metrics`. The WAL is internally synchronized so the producer
   and the uplink thread can use it concurrently (checked under TSAN).
7. **The serializer omits what it does not know.** A file, network or auth record with no known
   process and no pid omits `process` and lists it in `unavailable` (`not_supported_by_provider`,
   or `process_exited` when a pid is known). The schema only requires `process` on `process.*`.

## Consequences

- Delivery is exactly as durable as the WAL: records lost to WAL quota are reported as `wal_loss`
  and appear as a gap at the Manager, which is the correct outcome.
- A quarantined record is a real, visible data-loss event. It means the producer and the contract
  disagree, which is a bug to fix, so it is surfaced rather than retried silently.
- Verified: unit tests with a scripted Manager (10 plus 1 quarantine), TSAN with concurrent append
  and delivery, and a real run against the real Manager over HTTPS from the Ubuntu 22.04 VM,
  including a Manager outage and recovery (retries counted, all records delivered, stream gap only
  at the quarantined sequence).
- Not done: payload compression, certificate pinning beyond a private CA, Manager-initiated
  commands over this channel, a freshness nonce on the route, retention of Linux records at the
  Manager.

## Addendum: delivery states and rejection (S3.3)

A record is OBSERVED, ACCEPTED BY SENSOR, DURABLY COMMITTED (WAL sync), SENT, then ACCEPTED BY
MANAGER (an acknowledgement that matches the batch). Rejection is a separate path: REJECTED by the
Manager with a reason and line, QUARANTINED on the sensor under its sequence number, reported as a
`manager_rejected` loss record in the stream and as `delivery.records_quarantined` and
`recent_quarantined_seqs` in health (which marks the sensor degraded). A rejection is therefore
distinguishable from loss in the WAL (`wal_loss`) or the queue. HTTP 200 alone never advances the
cursor. The Manager exposes the latest health at `GET /api/v2/linux-endpoint/hosts/{host_id}/health`.
Open: retention of the quarantine file and of Manager-side Linux records.
