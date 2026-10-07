# ADR 036: Rollback detection by a signed build-time high-water mark

Status: accepted, 2026-10-08.
Extends ADR 033 (signed build manifest and self-integrity). Closes the "Not decided here" rollback item of ADR 034.
Adds one `tamper.integrity` technique, `manifest_rollback`; the contract change is additive (panopticon-contracts
2a8e847).

## Context

A signed manifest proves a build is one the release key signed. It does not prove the build is the newest. An
attacker who can write files can put back an older, correctly signed build (with a known weakness) together with
its older, correctly signed manifest, and ADR 033 sees a consistent install.

## Decision

1. The sensor keeps the newest manifest `built_at` (signed, in the manifest header) it has run, with that
   manifest's version, in `<wal_path>.integrity`:

   ```
   panopticon-integrity-state 1
   built_at <unix seconds>
   version <version>
   ```

   The file is written 0600 through a temporary file, `fsync` and `rename`. It is read with the same bounded,
   untrusted-path checks as the manifest.
2. The first verified manifest with no state file is trusted on first use and recorded.
3. A manifest that verifies and has `built_at` newer than the mark moves the mark. One that is older is a
   finding, `manifest_rollback` (target: the manifest path; the detail names both versions and times and says
   that deleting the state file accepts the older build). Equal is fine.
4. The finding goes through the same two-look debounce as the others (immediately at start), degrades the
   `integrity` health provider, and is reported `restored` when a manifest at least as new as the mark is in
   force again.
5. A manifest that does not verify is `manifest_invalid`, never a rollback: an unsigned `built_at` means
   nothing. An unreadable, malformed or untrusted state file is a fresh start (the next verified manifest
   becomes the mark), not an error.
6. Detection only. The sensor does not refuse to run an older build; a legitimate downgrade must stay possible
   and visible rather than stuck.

## Consequences

* A downgrade by package (`dpkg -i` of an older .deb, or apt with `--allow-downgrades`) produces a
  `manifest_rollback` record with the versions and times. An intended downgrade is acknowledged by deleting the
  state file; that act is not itself reported as a tamper record.
* apt's refusal to downgrade and a signed repository remain the first protection; this is the endpoint's own
  evidence.
* No Manager or Console change: it is one more value of an existing field.

## Honest limits

* A root attacker can delete or rewrite `<wal_path>.integrity` (the same host-trust limit as ADR 033), then the
  older build is a fresh start. The record that the downgrade happened is lost with the mark, unless the sensor
  was running and saw the change.
* It relies on a trustworthy `built_at`: builds must be signed with monotonically increasing times (the release
  script uses the build clock).
* Not tested: clock steps on the build host, state kept across a re-image of the data directory.
