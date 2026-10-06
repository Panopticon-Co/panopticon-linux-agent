# ADR 025: Per-command authorization

**Status:** Accepted (endpoint side implemented and verified; the Manager signer and the contract change are proposals, see "For the Manager and contracts owners")
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

* **Loss of the ledger inside the validity window** (disk replaced, state deleted) lets a still-valid signed
  command run once more. The window is at most 900 s and a kill still needs the exact start time and boot, so
  the practical exposure is a repeated collection or a repeated action on the same live process. A per-key
  monotonic serial or a per-boot counter kept outside the ledger would close it; deferred.
* **Whoever holds a pinned private key is the command authority.** Keys are not bound to an action class: one
  key may sign every permitted action. Per-key action scopes are a possible refinement.
* **Root on the endpoint** can edit the keyring or the config; that is outside this boundary (SECURITY_MODEL).
* The endpoint trusts its clock for `expires_at` (30 s skew); a Manager clock far from the endpoint's is an
  operational failure that is refused, not a bypass.
* ES256 only; algorithm agility is deliberately absent.

## For the Manager and contracts owners (proposal; not implemented in their repositories)

* Command envelope 1.1: an optional `authorization` object as in decision 1, and `created_at` required when
  signing. Note that the Manager rewrites a command to a schema-1 envelope on enqueue (`authorize_and_enqueue`);
  it must carry `authorization` through unchanged.
* A signer holding the private key outside the ingest tier, signing the string in decision 2, and a way to
  distribute the public half to endpoints (the keyring file today; enrollment-time delivery later).
* `tests/e2e/command_signer.cpp` is the reference implementation of the signing input and
  `tests/e2e/fake_command_manager.py` shows the delivery routes.
