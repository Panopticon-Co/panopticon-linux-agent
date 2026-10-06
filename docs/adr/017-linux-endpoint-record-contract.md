# ADR 017: The Linux endpoint record is its own contract

**Status:** Accepted
**Date:** 2026-10-06

## Context

`panopticon-sensord` has always written "endpoint/1.0" NDJSON, but the format existed only in
`serializer.cpp`. No schema, no fixtures, no consumer could check it. The contracts repository
holds a generic `endpoint-record` schema used for Windows records and is being changed by other
developers. The Linux endpoint is the primary product requirement, so its data model must not be
bent to fit whatever a consumer happens to accept today.

## Decision

1. The Linux wire format gets its own strict JSON Schema, `schema/linux-endpoint/1.0.schema.json`
   in `panopticon-contracts`, with valid fixtures taken from real sensord output and invalid
   fixtures that each break one rule, plus `scripts/validate_linux_endpoint.py`.
2. The schema was derived from the serializer and validated against real output, not written from
   intent. 508 records across 28 record types validated with zero failures. Types the VM did not
   produce (`auth.login`, `auth.failure`, `fim.changed`, `loss`, `process.inject`,
   `process.discovered`) share the same definitions but have no real sample yet.
3. The envelope separates the nine kinds of information (observations, events, state, derived
   events, detections, evidence, commands, results, health and coverage). Detections and
   evidence are defined but not yet emitted; the schema does not claim them.
4. It is a separate contract from the Windows one. Consumers route on `schema_version` plus the
   presence of `record_type`; an adapter between the two is a consumer concern.
5. The work lives on branch `feat/linux-endpoint-record` in an isolated worktree, so other
   developers' uncommitted endpoint work in the contracts working tree was not touched.

## Consequences

* ADR 007 and the architecture document name `schemas/endpoint/1.0/`; the real path is
  `schema/linux-endpoint/1.0.schema.json`.
* The envelope is closed, so any new field needs a schema release and a consumer update.
* Manager, Detection Engine and Console still do not consume it. Those changes follow, each on
  its own branch.
