# ADR 025: Per-command authorization

**Status:** Accepted (endpoint side implemented and verified; the Manager signs on `feat/linux-command-signing`, Manager ADR 008, verified end to end; the contract change is still a proposal, see "For the Manager and contracts owners")
**Date:** 2026-10-07

## Context

ADR 024 authenticates the command channel: TLS to the Manager and the enrolled bearer token. That says the
*channel* is the Manager's. It does not say that a given command was issued by the Manager's command authority.
A stolen agent token, a compromised ingest tier, a TLS-terminating proxy or a Manager bug can all put a command
on the channel; without more, the endpoint would run any action its policy permits. "Detection recommends, the
control plane authorizes, the endpoint validates and executes": authorization has to be something the endpoint
can check for itself, per command.

## Decision

1. **A command may carry `authorization`**: `{"algorithm": "ES256", "key_id": "<16 hex>", "signature":
   "<base64 of the 64-byte r||s>"}`. ECDSA P-256 over SHA-256, raw IEEE P1363 signature, the same conventions
   as enrollment (contract section 6). `key_id` is the first 16 hex digits of the SHA-256 of the 65-byte
   uncompressed public point. The parser's key set is closed, so `authorization` is one more known key; any
   other member is still `invalid_command`.
2. **What is signed is what is executed.** The signature covers a string built by the endpoint from the
   *parsed* command, not the JSON text, so there is no canonicalisation to get wrong and key order and spacing
   are the Manager's business:

   ```
   panopticon-command-auth/1\n
   schema_version:<len>:<"1" or "2">\n   command_id:   correlation_id:   agent_id:   host_id:
   action:   created_at:<unix s>   expires_at:<unix s>   pid:   start_time_ticks:   boot_id:   path:
   ```
   Each field is `name:<byte length>:<value>\n`, so no value can run into the next. Fields that do not apply to
   the action are present and empty (`0` for numbers); the domain line separates this use of the key from any
   other. A command with no `created_at` cannot be signed (`signature_invalid`): the validity window must be
   inside the signature or a signed command could be given a new lifetime.
3. **Pinned, revocable keys.** `response_signing_keys=/abs/path` names a file with one base64 point per line
   (optional label after a space, `#` comments). A line that is not a valid P-256 point invalidates the file.
   The file is re-read at every poll when its size or mtime changes: **removing a line revokes that key within
   one poll interval**, an emptied file revokes everything, an unusable edit (or a missing file) keeps the
   previous keys and reports the reason in the channel's `last_error`, so a transient failure cannot lock an
   endpoint out. At start an unusable file **disables the channel** (fail closed), with a message.
4. **Configuration cannot leave authorization implicit.** `response_mode` other than `off` needs either
   `response_signing_keys` or `response_allow_unsigned=true`; both together is invalid. Unsigned operation is an
   explicit opt-in and prints a warning at start. With keys pinned **every** command must be signed, including
   the read-only collections: an unsigned command is `signature_required`.
5. **Order.** `wrong_endpoint` first (cheap, and not an authorization question), then the signature
   (`signature_required`, `unknown_signing_key`, `signature_invalid`), then boot scope, `expired`,
   `not_yet_valid`, `lifetime_exceeded`, mode, allow-list and rate. A forged command therefore learns nothing
   about local policy, and a refused command never reaches the ledger intent or an executor. Refusals are
   answered (`rejected`), audited as `response.action`, and counted (`authorization_refused`).
6. **Replay.** Four things bound it. The signed `command_id` is the ledger key: a re-delivered command that was
   already closed is only re-accepted (idempotent), no second result, no second action; a command found
   started but not finished after a crash is `indeterminate / interrupted` and never run again. The signed
   `expires_at` and `created_at` bound the lifetime to 900 s (`lifetime_exceeded`) and cannot be moved without
   breaking the signature. The signed `agent_id` / `host_id` stop a command for one endpoint working on
   another. Schema 2 binds the boot and the exact process start time, so a signed kill cannot hit a reused pid
   or another boot.
7. **Rejected alternatives.** mTLS client certificates (authenticates the channel again, not the command);
   signing the raw JSON (needs canonicalisation on two languages); a shared HMAC secret (every endpoint could
   forge commands for every other); one embedded key (no rotation or revocation).

## Verified

Unit: verify and base64, signing-input ambiguity (field shifting changes the input), authorization parsing
(bad algorithm, key id, base64 and length), processor decisions (missing, unknown key, tampered, unsigned
window), policy modes, keyring file and revocation, and "values, not text" (key order irrelevant, edited
target fails). Real VM (Ubuntu 22.04, kernel 5.15, root, TLS fake Manager, real victim processes,
`tests/e2e/run_command_auth_e2e.sh`, 26 checks): signed collect and kill run and the victim dies; unsigned,
foreign-key, action-tampered, target-tampered and window-tampered commands are refused and the victims
survive; a validly signed command for another agent, an expired one, an over-long one and one with a wrong
start time are refused; a replayed signed command produces no second result; a key revoked by editing the
keyring stops working while the sensor runs, an unusable edit keeps the previous keys, a restored key works;
restart with redelivery re-runs nothing; the explicit unsigned opt-in warns and runs; an unusable keyring at
start processes no command.

## Residual risks and limits

* **Loss of the ledger inside the validity window** (disk replaced, state deleted, corruption) used to let a
  still-valid signed command run once more. Since ADR 028 a new ledger has an epoch and a command whose signed
  `created_at` is earlier is refused as `ledger_reset`; the remaining gap is a Manager clock ahead of the
  endpoint clock by more than the time between issue and loss.
* **Whoever holds a pinned private key is the command authority.** Keys are not bound to an action class: one
  key may sign every permitted action. Per-key action scopes are a possible refinement.
* **Root on the endpoint** can edit the keyring or the config; that is outside this boundary (SECURITY_MODEL).
* The endpoint trusts its clock for `expires_at` (30 s skew); a Manager clock far from the endpoint's is an
  operational failure that is refused, not a bypass.
* ES256 only; algorithm agility is deliberately absent.

## For the Manager and contracts owners

* **Done in the Manager** (`panopticon-manager` `feat/linux-command-signing`, ADR 008, not yet merged):
  `authorize_and_enqueue` signs every command it stores with a file-held P-256 key
  (`PANOPTICON_COMMAND_SIGNING_KEY`), using a port of the string in decision 2. Its tests check it byte for byte
  against vectors from `tests/e2e/command_signing_vectors.py`, which runs the reference signer, and verify the
  reference signer's signatures. The signature is stored with the command, so a rewrite of the Manager's table
  is refused at the endpoint. The sensor asks for it with `command_auth=ES256` on its poll; the Manager leaves
  `authorization` out for a poll without it, because the Windows agent refuses unknown members. When signing is
  configured and the key is unusable, command creation fails rather than queueing unsigned.
  `python -m manager.command_signing keyring-line <key>` prints the line for this endpoint's key file.
  REAL-VM VERIFIED against the real Manager over HTTPS: a signed `COLLECT_PROCESS_INFO` and a dry-run
  `KILL_PROCESS` were carried out as configured; an enforced `KILL_PROCESS` stopped a sacrificial process; a
  command was refused (`unknown_signing_key`) by a sensor pinning another key; and a command whose target was
  rewritten in the `commands` table after signing was refused (`signature_invalid`), touching neither process.
  Every command closed at the Manager with its result and a `created … signed ES256 key_id=…` audit event.
* Still a proposal: command envelope 1.1 in `panopticon-contracts`, with an optional `authorization` object as
  in decision 1 and `created_at` required when signing.
* Later: a signer that holds the private key outside the Manager process (today anyone controlling that process
  can sign), and delivery of the public half at enrollment (today the key file is placed by hand or by the
  package).
* `tests/e2e/command_signer.cpp` is the reference implementation of the signing input and
  `tests/e2e/fake_command_manager.py` shows the delivery routes.
