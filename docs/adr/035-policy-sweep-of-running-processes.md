# ADR 035: A policy is applied to the processes that are already running

Status: accepted, 2026-10-08.
Closes a known gap of ADR 032. The record schema does not change: `policy.match` already carries a free-form
`subject.type`.

## Context

ADR 032 decides about events as they happen: an exec, a file event, a connection. A process that was already
running when the sensor started, or when a newer policy arrived, is never decided about, because its exec record was
written before the policy existed (or before this sensor did) and the start-up reconciliation seeds the process graph
without emitting per-process records. The case that matters most is the ordinary one for incident response: an
indicator is published *after* the malware started.

## Decision

1. When a policy comes into force that the sensor has not swept before (identified by `policy_id/version`), the
   sensor decides about every live process in its entity graph once. That is at start when a policy is already in
   place, and each time a newer version replaces the one in force. A policy that leaves force (expired, revoked,
   never accepted) forgets the mark, so the same version coming back is swept again.
2. The input is the process's executable path and its joined command line, evaluated as kind `process.exec`: a
   running process was started by an exec, so the rules written about executions apply. Rules scoped to
   `process.discovered` are not applied by the sweep (they apply to the discovery events that already exist).
3. A match is a normal `policy.match` record with `subject.type = "process.running"` and the process as actor. It
   does not name a record of the process's own, because there is none; `subject.seq` is the seq of the last record
   written when the sweep ran, as it already is for `hash.computed`.
4. If a rule can use a digest (`sha256` or an indicator on it) and hashing is on, the sweep asks the hash service
   for each image (a cached digest is decided at once, others when `hash.computed` arrives, as for an exec). At
   most 2,048 images are requested per sweep.
5. A sweep writes at most 1,024 `policy.match` records. Past that it stops, and the policy provider's health reason
   says `start-of-policy sweep stopped at its limit (...)` until the next sweep. A rule that matches everything
   would otherwise write tens of thousands of records at once. The processes that were not reached are still
   decided about when they exec.
6. The sweep only decides. It reaches no response action, as for every policy decision.

## Consequences

* An indicator published after the process started now produces a recommendation, within one policy check
  interval of the policy being accepted.
* Every new policy version re-reports every still-running process that matches. A deployment that publishes a new
  version every few minutes (the soak does, every two minutes) repeats the match for a long-lived matching process
  each time; consumers de-duplicate on the process entity and rule. The 1,024 limit bounds the burst.
* A process that started and exited between two policies is not covered, only what is alive when the sweep runs.
* The sweep runs on the pipeline thread and costs one evaluation per live process (the engine has no
  backtracking), plus the hash requests; the process graph is bounded at 65,536 entities.
* Not tested: a sweep on a host with tens of thousands of processes under load; the unit tests use ~1,100 fake
  processes.
