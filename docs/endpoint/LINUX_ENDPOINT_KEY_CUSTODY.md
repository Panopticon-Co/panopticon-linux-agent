# Linux endpoint: keys, who holds them, and what is not designed

Status: 2026-10-08. This describes what the code does today. It is not a key-management design; the gaps are in the
last section and are real.

The endpoint verifies three kinds of signature itself, and relies on apt for a fourth. Each has its own key, so that
the authority to act, to change detection, to say what a build is, and to publish a package are not one authority
(ADR 025, 032, 033).

| Anchor | Signs | Private key held by | Public key pinned on the endpoint | Verified by |
|---|---|---|---|---|
| Command key | response commands (ADR 025) | the Manager (or whoever signs commands) | `response_signing_keys` file, one base64 P-256 point per line | the command processor, ES256, before any epoch / boot / target / lifetime check and before the durable ledger |
| Policy key | local detection policy bundles (ADR 032) | the policy author | `policy_signing_keys` file, same line format, a different file | the policy loader, ES256 over every header field and the body hash |
| Release (manifest) key | the build manifest of installed files (ADR 033) | the build / release machine | `integrity_keys` file, same line format | the integrity monitor, ES256 |
| Repository key | the apt `Release` file | the build / release machine | apt's own keyring (`signed-by`) | apt, not the sensor |

The endpoint's TLS client identity (enrolment to the Manager) is not a signing anchor for the artifacts above; a TLS
identity alone does not authorize a command on a packaged build (ADR 034).

## What the endpoint does with its pinned files

* The key files must be absolute, owned by root or the sensor's user, not group- or world-writable, and in a
  directory others cannot write into. A file that fails the check is refused, not read.
* The files are re-read when their size or mtime changes. **Removing a line revokes that key** at the next poll
  or check. An emptied file revokes everything. A file that cannot be read keeps the previously loaded keys and
  says so in health: an attacker who can make a file unreadable does not thereby revoke, and a mistake does not
  silently disarm the sensor.
* Revoking a policy key also takes out of force the policy that key signed (`policy.change` `removed` /
  `key_revoked`). Revoking a command key does not undo a command already executed; its audit record stays.
* A key is named in records by `key_id`: the first 8 bytes (16 hex characters) of the SHA-256 of the public
  point. An investigation can name which key authorized what.

## Rotation, as the code allows it

1. Add the new public line to the pinned file next to the old one. Both verify.
2. Start signing with the new key.
3. Remove the old line once nothing signed by it should still be accepted. Anything signed only by it is then
   refused (commands) or out of force (policies).

For the release key the same applies, with one addition: the manifest in an installed package is signed by the key
that was current at build time, and the package post-install pins its key on first install only, so a later build
signed by a new release key needs that key added to `integrity_keys` before the package is installed.

## What is not designed or built

* **Where the private keys live.** There is no HSM, no TPM, no offline root, no split between a root and a
  signing sub-key, no key expiry, no dual control. The signing tool (`panopticon-command-signer`) reads a private
  key from a file. Whoever has that file can sign.
* **Distribution of public keys to an existing fleet.** Pinned files are provisioned at install or by
  configuration management. There is no signed key-update message; adding or revoking a key on an endpoint is a
  root file edit (the pinned files sit on the same host as the sensor: see ADR 033, honest limits).
* **Compromise of one anchor.** Command key compromise lets the holder issue commands the endpoint allows (still
  bounded by the response mode, the dry-run default, epoch / boot / target / lifetime checks, and the audit).
  Policy key compromise lets the holder change detection. Release key compromise lets the holder produce a
  manifest the endpoint accepts. The recovery for each is the revocation above on every endpoint, and nothing
  automates it.
* **The Manager's signing path.** How the Manager protects its command key is that repository's concern; this
  document says nothing about it.
