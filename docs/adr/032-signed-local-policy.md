# ADR 032: Signed, versioned local policy that only decides

**Status:** Accepted
**Date:** 2026-10-07

## Context

ADR 016 built the local policy engine: indicators and simple rules that turn one event into a recommendation,
with no side effects. Nothing wired it in. Two questions were left open: where a policy comes from, and what a
decision becomes.

A policy is an input that changes what the endpoint reports. An attacker who can replace it can blind the
endpoint (an `allow exe /` line suppresses every decision). An attacker who can replay an older policy can bring
back an allow list that was withdrawn. A policy that half loads stops protecting without saying so. And a
decision must not become an action: a rule typo, a bad indicator feed or a crafted command line must never be
able to kill a process. Response stays where ADR 024 and ADR 025 put it: a Manager-authorized, signed command.

## Decision

1. **Decisions only.** A match becomes a `policy.match` record in the WAL, next to the event that caused it.
   The record names the policy, the version, the rule, the recommended action and the matched fact. The policy
   module has no path to the responder, the command processor or the isolation helper. Acting on a
   recommendation means a Manager-side decision, which becomes a signed command (Manager ADR 008). The endpoint
   then verifies that command like any other.
2. **Signed bundle.** The policy file is a header, a `---` line, and the ADR 016 policy text:

   ```text
   panopticon-policy 1
   policy_id <identifier>
   version <1 .. 2^63-1>
   issued_at <unix seconds>
   expires_at <unix seconds>
   scope all | host:<host_id>
   key_id <16 hex>
   signature <base64 of the 64-byte r||s>
   ---
   <ADR 016 policy text>
   ```

   The ES256 signature covers `panopticon-policy/1\n` and then `name:<bytelen>:<value>\n` for policy_id,
   version, issued_at, expires_at, scope and the SHA-256 (lowercase hex) of the exact body bytes. That is the
   same length-prefixed construction as command signatures (ADR 025), with its own domain line, so a command
   signature can never be a valid policy signature. Policy keys are pinned in their own file
   (`policy_signing_keys`), separate from command keys. The authority to change detection is not the authority
   to kill processes. There is no unsigned mode.
3. **Monotonic.** The sensor durably records the policy it accepted (`<wal_path>.policy`: id, version, body
   hash). A new file must carry a higher version. The same version with the same hash is a no-op after a
   restart. A lower version, or the same version with different content, is refused as `rollback`. If the state
   file is missing or unreadable, the next valid policy is accepted, and its `policy.change` record says that no
   previous state was found, so a reset is visible.
4. **Fail-safe on a bad update, fail-closed on expiry.** A replacement that is malformed, unsigned, signed by an
   unpinned key, out of scope, issued in the future (beyond 30 s of clock skew), already expired or a rollback
   is refused as a whole. The previous policy stays in force, because a bad update must not be a way to switch
   detection off. The refusal is recorded and health is `degraded` until a good policy is in place. When the
   policy in force passes its `expires_at`, it stops producing decisions. That is the point of an expiry: an
   indicator or allow-list entry withdrawn upstream must not live on. The expiry is recorded and health is
   `degraded`. A policy file that is removed leaves the policy in force (fail-safe) and is reported.
5. **Auditable.** Every load, refusal, expiry and removal is a `policy.change` record: outcome, reason, policy
   id and version, previous version, key id, rule and indicator counts, expiry. Health names the policy in
   force.
6. **Where it is evaluated.** On `process.exec` and `process.discovered` (executable, command line, and the
   SHA-256 when it is already known), on `hash.computed` (only the SHA-256 rules, under the kind of the event
   that asked for the hash, because hashing is asynchronous), on file events (path), on network connect, accept
   and UDP flows (the remote address) and on DNS queries (the name without its trailing dot). The acting
   process's executable is set everywhere, so an `allow exe` line applies to every kind. A match record is
   written only after its subject record and names it by type and `seq`. It runs on the pipeline thread,
   before the next record. ADR 016 bounds the cost: matching is linear, there are no regular expressions,
   decisions are capped at 16 per event and matched text at 256 bytes. Every record carries
   `sensor.policy_version` (`<policy_id>/<version>`, or `none`).
7. **Delivery is a file.** The sensor checks the file every 30 s (`policy_check_seconds`, 5 to 3600) and at
   start, and at once when the policy in force expires. A change is detected by size, mtime, ctime and inode. A
   file modified within the last two seconds is read again on the next check, and the content digest
   suppresses duplicate records, so a same-size rewrite within one timestamp tick is not missed. Placing the
   file is the job of the package, configuration management or, later, the Manager. Delivery by the Manager
   does not change any of the above. `policy_path` and `policy_signing_keys` are set together or not at all.
   The file and its directories must pass the ADR 031 trusted-path check (owned by root or the sensor's user,
   not writable by group or others), or it is refused as `untrusted_file`.

## Consequences

* `policy.match` and `policy.change` are new event types in the linux-endpoint record contract, and the Manager
  must accept them before a sensor with a policy can deliver.
* Until a Manager-side consumer exists, a recommendation is evidence for an analyst and for the detection
  engine, not an action.
* An indicator on a SHA-256 matches when the hash completes. That is after the exec record, by the hashing
  queue's delay.
* The policy key is a second trust anchor, managed like the command keys: pinned in a root-owned file, revoked
  by removal. Removing the key of the policy in force takes that policy out of force (`policy.change` `removed`,
  reason `key_revoked`; an unreadable key list revokes nothing); a newer policy signed by a pinned key, or pinning
  the key again, brings one back.
* Known gaps: processes already running when the sensor starts are not evaluated, because the start-up
  reconciliation emits no per-process records (closed by ADR 035, which sweeps them when a policy comes into force). When a refused or removed file is followed by the file of the
  policy already in force, no new record is written; health shows the recovery.
