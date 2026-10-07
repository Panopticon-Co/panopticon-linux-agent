# ADR 034: Packaged builds have no unsigned-command mode

Status: accepted, 2026-10-08.
Extends ADR 025 (command authorization). Does not change the command envelope or the Manager.

## Context

ADR 025 made a response mode other than `off` require either pinned command-signing keys
(`response_signing_keys`) or the explicit opt-in `response_allow_unsigned=true`. The opt-in was
described as "labs only", but it was one line in a config file. Anyone who could edit
`/etc/panopticon/sensord.conf` could switch a signing endpoint to trusting the TLS identity alone,
and the shipped binary contained the code path whether or not anyone wanted it.

A flagship endpoint should not have an unsigned production path that the configuration can reach.

## Decision

1. The opt-in is compiled in only with `-DPANOPTICON_LAB_UNSIGNED_COMMANDS=ON`. The default is OFF.
2. Without it, `parse_sensor_config` returns an error for `response_allow_unsigned=true`:
   `response_allow_unsigned=true is not available: this sensor was built without lab unsigned-command
   support`. The sensor does not start; it does not ignore the key. `response_allow_unsigned=false` is
   accepted and means nothing.
3. A lab build prints `WARNING LAB BUILD: command signing is off ...` at start. CMake also warns at
   configure time.
4. `packaging/build_signed_deb.sh` never enables the option. The tests build with it off; only the
   scenario that exercises the unsigned path (`run_command_auth_e2e.sh`, scenario 7) needs a lab build, and
   in a non-lab build that scenario checks the refusal instead.
5. The command processor itself is unchanged. Its `require_signature` and "no keyring" behaviour stay
   because the processor is a library with its own unit tests; it is the configuration that can no longer
   reach them in a packaged build.

## Consequences

* A packaged sensor cannot be told to skip command signatures by editing its configuration. An attacker who can
  replace the binary can still do anything; ADR 033 detects that after the fact, it does not prevent it.
* Test and e2e rigs that relied on unsigned commands use pinned keys (the e2e scripts already did, except
  scenario 7).
* A lab build is a different artifact from a packaged build. Nothing prevents someone building with the option
  ON and installing it; the sensor says so loudly at start, and its manifest would not match a signed one.

## Not decided here

* Rollback: the sensor does not refuse an older signed manifest version. A signed apt repository plus apt's
  refusal to downgrade is the current protection (ADR 033). A high-water-mark check would need a design for
  where the mark lives and what a legitimate downgrade looks like.
