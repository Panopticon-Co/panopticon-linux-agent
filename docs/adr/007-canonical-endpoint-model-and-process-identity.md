# ADR 007: Canonical endpoint model 1.0 and process identity

**Status:** Accepted
**Date:** 2026-10-06

## Context

Schema 0.4 is a single flat process-start event shaped around the Windows agent (`user.sid`,
`user.domain`), with no provenance, no distinction between events and state, and a process
entity id over `(host_id, pid, start_time_ticks)` without the boot id. Linux needs dozens of
event families, host state, health, loss and evidence records, and must say which mechanism
produced each record and which fields are unavailable.

## Decision

1. A new model, `panopticon.endpoint/1.0`, is defined in `panopticon-contracts`
   (`schemas/endpoint/1.0/`) and documented in
   [LINUX_ENDPOINT_TELEMETRY_CATALOG.md](../endpoint/LINUX_ENDPOINT_TELEMETRY_CATALOG.md).
2. The envelope separates `record_type` (event, state, health, loss, detection, evidence,
   response, policy) from `type`, carries mandatory `provenance` and explicit `unavailable`
   fields, and a contiguous per-sensor `seq`.
3. **Process entity id** = first 32 hex characters of
   `SHA-256(host_id | boot_id | tgid | start_ticks)`, where `start_ticks` is the process start
   time in `CLK_TCK` units since boot. eBPF reads `task->start_time` (ns) and divides by
   `NSEC_PER_SEC / CLK_TCK`; procfs reads field 22 of `stat`. Both yield the same value, so a
   process discovered by procfs and later seen by eBPF has one identity.
4. `exec_gen` counts observed execs of the same process entity.
5. Schema 0.4 stays accepted by Manager for the Windows agent and older Linux agents; the Linux
   sensor emits only 1.0.

## Consequences

* Manager, Detection Engine and Console add 1.0 consumers (slice S3).
* `CLK_TCK` resolution (normally 10 ms) is sufficient because the tuple also includes pid and
  boot id: a collision needs the same pid reused within one tick of the same boot.
