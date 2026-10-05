# ADR 005: Resident sensor with capability-level provider fallback

**Status:** Accepted
**Date:** 2026-10-06
**Supersedes:** the one-shot execution model in `src/main.cpp` (procfs snapshot, drain, exit)

## Context

The agent at `335dae0` runs once: it snapshots `/proc`, serialises up to `queue_capacity`
processes, drains the spool and exits. A one-shot snapshot cannot observe anything that starts
and ends between runs, re-emits every live process as a new "start" event on each run (two
runs on Ubuntu 22.04 shared 0 of 127 event ids), and has no notion of coverage or loss. The
industry Linux EDRs reviewed all run a resident sensor fed by kernel events, with a fallback
when the preferred mechanism is unavailable (see the competitor analysis).

## Decision

1. `panopticon-sensord` is a long-running daemon. Its pipeline is
   providers → bounded ingest queue → single pipeline thread (entity graph, enrichment, rules,
   serialisation) → WAL → uplink.
2. A **provider** owns one telemetry mechanism and implements `probe()` (can it run here; if
   not, why), `start()`, `stop()` and `health()` (state, reason, event and drop counters), and
   declares the **capabilities** it supplies (`process.lifecycle`, `file.events`, …).
3. A **coverage manager** selects, per capability, the highest-fidelity provider whose `probe()`
   and `start()` succeeded, and re-selects when a provider fails at run time. Decisions and
   rejection reasons are emitted as `health` records.
4. The procfs **reconciler** is always active. It seeds the entity graph at start and after any
   provider failover, and is the last-resort provider for process state.
5. The sensor runs as the dedicated `panopticon` user (continuing ADR 004's least-privilege
   stance) with systemd `AmbientCapabilities` limited to what its providers need:
   `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN
   CAP_AUDIT_READ CAP_SYS_RESOURCE`. It does **not** hold `CAP_DAC_OVERRIDE`, `CAP_FOWNER` or
   `CAP_KILL`; those belong to the responder. On kernels without `CAP_BPF` (< 5.8),
   `CAP_SYS_ADMIN` covers BPF and this is reported in health.
6. The existing one-shot binary stays buildable as `panopticon-linux-agent` until Manager and
   packaging have moved to the sensor; it is then removed.

## Consequences

* Short-lived processes and every other event family become observable.
* `CAP_SYS_ADMIN` is broad; it is required for fanotify and for BPF on older kernels. The unit's
  remaining sandboxing (no DAC override, `ProtectSystem=strict`, `NoNewPrivileges`) still
  prevents the sensor from rewriting root-owned files.
* Every capability has a named fallback chain and a published degraded state.
