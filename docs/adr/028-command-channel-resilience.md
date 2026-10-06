# ADR 028: Command-channel resilience: backlogs, interrupted commands, ledger epoch and recovery

**Status:** Accepted (implemented; unit tested; real-VM verified by `tests/e2e/run_command_chaos_e2e.sh`)
**Date:** 2026-10-07

## Context

ADR 024 to 027 built the command channel, its authorization, file actions and isolation. A chaos run against the
real sensor (`tests/e2e/run_command_chaos_e2e.sh`: bursts, rate limit, duplicate ids, hostile content, a Manager
outage, a full ledger filesystem, a corrupt and a deleted ledger, SIGKILL in the middle of a burst) found four
defects that the unit tests and the earlier e2e runs did not reach. Each one is a way for the channel to stop
working, or to stop being exact about what ran, without anything being wrong with a command.

## Defects found and the decisions that fix them

1. **A backlog above the poll bound stalled the channel.** A reply with more than 32 commands was rejected as a
   whole ("longer than the bound"). The Manager does not drop commands it has not had accepted, so once more
   than 32 were pending the sensor rejected every reply for as long as the backlog stayed above 32: the first run
   answered 39 of 100 commands in 128 s and then nothing.
   *Decision:* a reply is read up to the bound and the rest is left for the next poll (the Manager sends again
   what it has not had accepted). `command_poll.omitted` says how many were left. While a backlog drains and the
   poll made progress the next poll comes after at most 200 ms; a reply in which nothing could be closed (for
   example entries without a usable id, which are never accepted) waits the normal interval, so a Manager that
   keeps resending them cannot make the sensor spin. A reply that is not a command list at all, or exceeds the
   256 KB / 4096-value JSON limits, is still rejected whole (see limits).

2. **A command interrupted by a restart was never answered.** The sensor tells the Manager a command is accepted
   when its intent is durable and before the action begins. If the process then died, the Manager never sends
   the command again, and ADR 024's "answered `indeterminate` after the restart" only happened when the command
   was redelivered. The kill-9 run lost one of 64 answers (`kb-40`: ledger state `R`, accepted, no result).
   *Decision:* at the start of every step, ledger entries still marked as begun are answered
   `indeterminate / interrupted` (and audited as a `response.action` record). Commands run inside a step, so none
   is in flight when a step starts; a begun entry can only come from a previous process. Nothing is run again.

3. **A corrupt ledger disabled the channel for good, and a lost one allowed a second run.** A malformed ledger
   line made `command_ledger::open` fail, so the command channel never started until an operator intervened;
   deleting the ledger instead let a still-valid signed command run once more (the residual recorded in
   ADR 025).
   *Decision:* a ledger has an **epoch**: its first line, `E<TAB><unix seconds>`, written when a ledger begins
   (first start, or a replacement). `open_or_recover` moves a corrupt ledger to `<path>.corrupt` (replacing an
   older one; the evidence is kept, a flood of corrupt ledgers cannot fill the disk) and starts a new one, so the
   channel keeps working and `last_error` says what happened. The processor refuses a command whose signed
   `created_at` is earlier than the epoch with `rejected / ledger_reset`: whatever ran under the lost ledger was
   issued before the loss, and the record that would say so is gone, so the Manager has to issue it again.
   A ledger written before epochs has none (0) and is not refused for it, so an upgrade locks nothing out. An
   unreadable or unwritable ledger path is still an error: the endpoint does not guess.
   Residual: the comparison uses the endpoint's clock for the epoch and the Manager's for `created_at`; a
   Manager clock ahead of the endpoint's by more than the gap lets a command created just before the loss pass.
   An unsigned command with no `created_at` (only possible with the explicit unsigned opt-in) cannot be placed in
   time and is not covered.

4. **A failed ledger append could leave half a record.** A write that fails part way (no space, a file size
   limit) left a partial line, and the next append glued onto it, so the file no longer loaded.
   *Decision:* the append remembers where the record began and cuts back to it on failure; if it cannot cut back,
   the ledger closes and refuses everything after (fail closed). Verified with `RLIMIT_FSIZE` (a record written
   in part, refused, and the file is exactly as before) and on a real full filesystem.

## Behaviour confirmed, not changed

* With no room to record a command the sensor answers `rejected / ledger_unavailable` and does nothing; the
  command is not accepted, so it stays pending and, if still valid, runs after room returns (verified: the
  refused kill ran, once, after the space was freed).
* A result is sent again until acknowledged with the same `result_id`, so a SIGKILL between the send and the
  ledger note produces one more row at the Manager, never a different answer.
* Fifty-six chaos checks include 100 commands in a burst answered in 16 s with no duplicate or lost result and
  28 MB RSS after, five kills per minute under a limit of five with the other seven refused and their victims
  alive, and 23 hostile command shapes (2 MB field, 20000-deep nesting, absurd numbers, non-object entries, over-
  long and control-character ids) each followed by a signed command that still ran.

## Residual risks and limits

* A single command larger than the 256 KB reply limit (or with more than 4096 JSON values) makes the whole reply
  unreadable, so it blocks the commands behind it until the Manager stops sending it. Parsing cannot skip one
  entry without parsing the rest. The Manager owns what it queues; it can always withhold commands, so this is
  not a new capability for an attacker, but a Manager must not enqueue such an entry.
* The epoch protects against loss of the ledger, not against an attacker who can write the ledger; root on the
  endpoint is outside this boundary (SECURITY_MODEL).
* Not tested: ledger on a failing disk with partial sector writes, power loss with page-cache drop.
