# ADR 016: Local policy engine decides, it does not act

**Status:** Accepted
**Date:** 2026-10-06

## Context

The endpoint needs a local, offline answer to "does this event match something we already know is
bad": a known hash, a known address, an executable running out of `/tmp`. It also needs a clean
line between deciding and doing. The responder (ADR 015) can kill processes; a policy bug must not
be able to turn a typo into a kill.

## Decision

1. `policy_engine` evaluates one `policy_input` (event kind, executable, command line, SHA-256,
   file path, destination address and domain) against a loaded policy and returns decisions:
   rule id, recommended action (`alert`, `recommend_terminate`, `recommend_quarantine`,
   `recommend_block`), severity, and the field and value that matched. It has no side effects.
2. Matching is equals, prefix, suffix, contains, or membership in an indicator set. There are no
   regular expressions, so cost is linear in the input and an attacker who chooses a command line
   or file name cannot cause backtracking. Path prefixes match on a component boundary
   (`/tmp` matches `/tmp/x`, not `/tmpfoo`). A domain indicator matches its subdomains and nothing
   else. Hashes compare case-insensitively.
3. The policy text format is strict and line based (`rule`, `ioc`, `allow`). Unknown directives,
   duplicate ids, bad enumerations, control characters, oversize lines and counts over the limits
   (1024 rules, 100000 indicators) reject the whole file. So do indicators on a field that no
   `rule ... <field> ioc ...` consults: they would load and never match. A policy that half loads
   would silently stop protecting, so it never half loads.
4. An `allow exe <prefix>` entry suppresses every decision for that executable. Decisions per
   event are capped at 16 and matched text at 256 bytes.
5. The engine produces recommendations only. Carrying one out is the responder's job, behind its
   dry-run default and protected set.

## Consequences

* This slice is the decision core. It is not yet wired into the pipeline: that needs a record type
  for a local detection, which belongs to the endpoint schema decision (S3), so nothing is
  emitted until that is settled.
* Modes (off, audit, protect), rule expiry and a kill switch (matrix BA4) and the in-kernel
  prevention hooks (BA1 to BA3) are later slices. The engine currently has no notion of mode.
* Indicator updates arrive by replacing the policy file; signed delivery is part of the update
  work (S10).
