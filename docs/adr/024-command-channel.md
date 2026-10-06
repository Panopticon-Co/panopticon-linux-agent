# ADR 024: The command channel

**Status:** Accepted
**Date:** 2026-10-06

## Context

Detection, policy recommendation and response execution are separate duties. The Manager decides
that a response is wanted; the endpoint decides whether it will carry it out, carries it out once,
and says exactly what happened. A command that is replayed, late, aimed at the wrong host or at a
process that has since changed identity must do nothing, and a sensor that dies mid-action must
never repeat the action.

## Decision

1. **Path.** Manager enqueue (`POST /api/v1/commands`, command token) → the sensor polls
   `GET /api/v1/agents/{agent}/commands?delivery_mode=durable` over the enrolled TLS identity →
   strict parse → authorization → durable ledger → exact target verification → execution →
   durable result → `POST .../commands/{id}/accept` and `POST .../command-results` (schema 2) →
   a `response.action` audit record in the WAL.
2. **Strict parse.** Closed key set, schema "1" or "2", bounded sizes, aware timestamps. Anything
   else is `invalid_command` and is answered, never executed. A 20,000-round mutation fuzz runs in
   the tests.
3. **Decision order, first failure wins.** `wrong_endpoint`, then for boot-bound commands
   `boot_unavailable` / `boot_mismatch` (or `boot_binding_required` for an unbound process target
   when `response_require_boot_binding=true`), then `expired`, `not_yet_valid`
   (30 s skew), `lifetime_exceeded`, `response_disabled`, `unsupported_action`,
   `action_not_permitted`, `rate_limited` (6 changing actions a minute). Only then does the ledger
   record the intent.
4. **Mode.** `response_mode` is `off` (the channel is not built), `dry_run` (everything is
   verified, nothing is sent; reason `dry_run`) or `enforce`. `response_actions` is an allow-list.
   Skew, lifetime and rate are local policy, not Manager input.
5. **Ledger.** Append-only, fsync per line, intent (`R`) before the action, result (`D`) after,
   `S` when the result was delivered. A truncated tail is tolerated; a corrupt line fails closed.
   A command found `R` with no `D` after a restart is answered `indeterminate / interrupted` and
   is never run again. The ledger is bounded and compacts without losing a stored result. If it
   is full or unreadable, commands are refused (`ledger_unavailable`), not run.
6. **Exact targets.** A process target is `{pid, start_time_ticks}`. The pidfd is taken first, the
   start time is read, and the signal goes through `pidfd_send_signal`. PID 0 and 1, kernel threads
   and the sensor itself are protected. There is no PID-only fallback: a mismatch is
   `target_mismatch`. A kernel without pidfd uses a verified `kill()` and says so (`mode:
   pid_fallback`).
   **Schema 2** (platform ADR 0008) adds the boot scope: the target is exactly
   `{pid, start_time_ticks, boot_id}`, with ticks a canonical positive uint64 decimal string and
   `boot_id` = `"boot_" + sha256_hex(kernel boot_id text)` (the 36-character lowercase UUID from
   `/proc/sys/kernel/random/boot_id`, no newline). The sensor computes its own scope at start; a
   sensor that cannot read a UUID refuses every boot-bound command (`boot_unavailable`). Schema 2
   carries process actions only; file and targetless actions are `invalid_target`.
7. **Actions today.** `KILL_PROCESS` and `COLLECT_PROCESS_INFO` (bounded name, exe, ppid, uid,
   threads). `COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST` and
   `RELEASE_HOST_ISOLATION` answer `unsupported_action`. The set of seven is closed; there is no
   shell action.
8. **Results are repeatable.** The result id is `res-<command_id>` and the detail is stored in the
   ledger, so a retry after a lost acknowledgement sends the same bytes and the Manager's digest
   idempotency applies. A Manager reply that is not strict JSON is not an acknowledgement.
9. **Audit record.** `response.action` (contract 1.0) carries the command, outcome, reason,
   `dry_run`, `executed`, the verified target and the mode. `executed` means the executor was
   invoked; the host changed only if `executed && !dry_run && outcome == succeeded`.

## Consequences

* Verified on Ubuntu 22.04 / 5.15 / x86_64 against the real Manager: dry-run and enforced kill,
  process info, start-time mismatch, protected pid, lifetime and unsupported refusals, restart
  without re-execution, Manager lifecycle `SUCCEEDED` / `REJECTED`, and every `response.action`
  record accepted.
* Schema 2 verified live the same day against a Manager that preserves the command version (a
  trial merge of the Linux and Windows Manager branches): a scope from another boot was
  `REJECTED / boot_mismatch`, a bound collect and a bound kill `SUCCEEDED` (process gone), and an
  unbound schema-1 kill with binding required was `REJECTED / boot_binding_required`; all four
  `response.action` records were accepted. The Linux Manager branch alone rewrites every command
  to schema "1" and must be fixed before schema 2 is used with it.
* A strict clock check is a real operational dependency: a VM clock 27 s behind the Manager
  host produced `not_yet_valid` for every command in the first live run. The gate is kept.
* **Known gaps.** Commands are authenticated by TLS plus the enrolled identity; there is no
  per-command signature, so a compromised Manager channel can still request any permitted action.
  Schema "1" has no `boot_id`; schema 2 closes that for process actions, but binding is required
  only when `response_require_boot_binding=true` (off by default until Manager issues schema 2 to
  Linux everywhere). There is no
  nonce beyond the command id and the ledger. Five actions are not implemented. Behaviour under a
  long Manager outage and ledger loss (disk replaced) are untested.
