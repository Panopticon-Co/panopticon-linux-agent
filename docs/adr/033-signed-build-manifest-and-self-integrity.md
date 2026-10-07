# ADR 033: Signed build manifest and runtime self-integrity

**Status:** Accepted
**Date:** 2026-10-08

## Context

The security model claimed (T12) that the sensor checks itself "against the build manifest" and that file events
on install paths make replacement visible. Neither was built. There was no manifest, no check, and no record an
analyst could read. An attacker who replaces `panopticon-sensord`, `panopticon-ctl` or a helper under
`/usr/lib/panopticon` therefore left no trace until the sensor stopped reporting, and even then nothing said who
did it or what the file had been.

The check has to survive an attacker who can write to the install directory, so the manifest cannot be a plain
checksum list stored next to the files. It must be signed, and the key that verifies it must live somewhere the
install-directory attacker does not own. It also must not raise false alarms on a benign package upgrade, which
replaces the same files.

## Decision

1. **Signed manifest.** A build produces one text file listing the installed files of the package:

   ```text
   panopticon-build-manifest 1
   package <name>
   version <version>
   built_at <unix seconds>
   key_id <16 hex>
   signature <base64 of the 64-byte r||s>
   ---
   <sha256 lowercase hex> <size in bytes> <absolute normalized install path>
   ...
   ```

   At most 128 entries and 64 KiB. The parser is strict: a fixed header order, printable header values, a
   lowercase 64-digit digest, a decimal size, an absolute path that is already normal (no `..`, `.`, `//`, no
   trailing `/`), a path listed twice, an empty body, a missing final newline and a 65th entry are each
   rejected. The ES256 signature covers `panopticon-build-manifest/1\n` and then `name:<bytelen>:<value>\n` for
   package, version, built_at and the SHA-256 of the exact body bytes. That is the construction of commands
   (ADR 025) and policies (ADR 032) with its own domain line, so a command or policy signature is never a valid
   manifest signature.
2. **Pinned verification key.** The manifest is verified with a key file the operator pins (`integrity_keys`,
   the same format as `command_signing_keys`, loaded as "integrity key file"). The manifest and the key file must
   pass the ADR 031 trusted-path check. `integrity_manifest` and `integrity_keys` are set together or not at
   all, both absolute and without `..`. Without them the check is off, and neither health nor the coverage map
   claims `tamper.integrity`.
3. **What is checked.** Once at start, then every `integrity_check_seconds` (default 60, 5 to 3600), the sensor:
   * re-reads the manifest when its identity changed and verifies it. A manifest that does not verify is refused
     as a whole and the last verified manifest stays in force, so a forged or truncated manifest cannot switch
     the check off;
   * hashes each listed file (opened `O_NOFOLLOW`, so a symlink is a finding; at most 512 MiB), with a cache
     keyed by device, inode, size, mtime and ctime so an unchanged file is not read again, and a same-size edit
     with restored timestamps is still caught through ctime;
   * hashes the **running image**, held open since start (`/proc/self/exe`), and compares it with the manifest
     entry for its path (re-hashed at least every 15 minutes). The running process is the thing that matters:
     an attacker can replace the file on disk while the old image keeps executing.
4. **Findings.** One technique each, in `tamper.technique`:
   * `binary_modified`: the content differs from the manifest, the file cannot be read or verified, the running
     image is not the manifest's build, or the running binary is not listed in the manifest at all;
   * `binary_missing`: a listed file is gone;
   * `binary_replaced`: the path now names a different inode than the running image, but the content is the
     manifest's. This is what an attacker's swap with a copy of the same build, or a package upgrade in
     progress, looks like. The detail says a restart is pending;
   * `manifest_missing`, `manifest_invalid` with a named reason (`untrusted_file`, `too_large`, `unreadable`,
     `malformed`, `no_keys`, `unknown_key`, `bad_signature`);
   * `manifest_rollback`: a manifest that verifies but is older than the newest build this endpoint has run
     (added by ADR 036).
5. **Debounce, then report once.** A finding is reported after two consecutive looks, except at the first look
   after start, which is immediate (a sensor that starts from a bad install should say so at once). It is
   reported as `violated`, once, and as `restored` when the condition clears. A package upgrade replaces the
   files and then restarts the sensor, and the debounce plus the restart mean the transient mismatch is not
   reported (`transient_change_is_never_reported`). A restart from a verified install starts clean.
6. **Attribution.** The pipeline notes the last writer of every watched path from fanotify file events
   (`create`, `modify`, `delete`, `rename`, `attrib`, and the old path of a rename). A finding carries that
   process, built as for any other record, and `last_change {operation, time}`. If no writer was seen (file
   events are off, the event was lost, the change predates the sensor) the record says so through
   `unavailable.process`, never a guess: `process_exited` when only a pid remains, `not_supported_by_provider`
   otherwise.
7. **Record and health.** `tamper.integrity` events carry `tamper {status, technique, target, expected_sha256?,
   observed_sha256?, manifest_version?, key_id?, files_checked, files_in_violation, last_change?, detail}`.
   Health has a provider `integrity` (capability `tamper.integrity`), `degraded` while any finding is violated.
8. **Packaging.** The package step generates the manifest from the installed files with
   `panopticon-command-signer sign-manifest` and signs it with the release key, and installs the public key line
   as the integrity key file. The signing key never touches the target host.

## Consequences

* **What this does not stop.** The trust anchor is a key file under `/etc`. A root attacker who replaces the
  binary can also replace the key file and the manifest, and the sensor then verifies the attacker's manifest.
  This catches casual replacement, a swap done without also replacing the pinned key, partial tampering, and a
  replaced file under a still-running verified binary. It makes tampering by anything short of careful root
  control noisy and attributable. It is not a defense against a careful root attacker. Moving the anchor out of
  reach (a remotely held key, secure boot with IMA appraisal, a TPM) is future work and is not built.
* The check reads files: one hash per listed file, then nothing until it changes. The 128-entry cap bounds it.
* `tamper.integrity` is a new event type in the linux-endpoint record contract
  (`schema/linux-endpoint/1.0.schema.json`, `$defs.Tamper`). The Manager must accept it before a sensor with
  integrity enabled can deliver.
* Not covered here: the signed package and update path (rollback protection), `tamper.*` for kernel module and
  BPF tampering, and the unsigned lab bypass of the command channel.
