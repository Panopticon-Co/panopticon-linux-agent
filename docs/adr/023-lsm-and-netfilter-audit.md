# ADR 023: AppArmor and SELinux decisions, and firewall changes, from the audit stream

**Status:** Accepted
**Date:** 2026-10-06

## Context

Two of the cheapest ways to blind or weaken a host are to switch off its mandatory access control and
to open its firewall. Both leave a record in the kernel audit stream the sensor already reads for
authentication (ADR 013): AppArmor and SELinux write what they refused and when their policy
changed, and the netfilter core writes a record for every change to a table, naming the process
that made it. Neither needed a new hook.

## Decision

1. **Extend `audit_netlink`, do not add a provider.** The provider already holds the audit multicast
   socket, the kernel sender check, the datagram decoder and the quote- and hex-aware tokenizer.
   `parse_audit_security_record` runs on records the authentication parser does not take.
2. **`lsm.denial`.** AVC records (type 1400, and 1501 to 1506 on kernels that use them). AppArmor
   `DENIED` is `outcome: denied`; `ALLOWED` (complain mode) is `would_deny`, because the access
   happened. An SELinux `avc: denied` with `permissive=1` is `would_deny`. `AUDIT` records (an
   explicit audit rule) and `granted` decisions are not denials and are not reported.
3. **`lsm.policy`.** AppArmor `STATUS` records for `profile_load`, `profile_replace` and
   `profile_remove`, with the loading process. SELinux `MAC_POLICY_LOAD`, and `MAC_STATUS` only when
   `enforcing` or `enabled` actually changed. The SELinux records name no process.
4. **`netfilter.config_change`** from `NETFILTER_CFG` (type 1325): subsystem (`nft` or `xtables`),
   operation, table, family, entry count, the nftables generation and the acting process. The name
   differs from `firewall.changed` on purpose: that type is already the contract name for the
   difference between two firewall inventories and has a different body; the schema rule that
   requires a `change` body for every `firewall.*` type caught the collision during the first live
   run (seven records quarantined by the Manager), which is why the event was renamed.
5. **The rule text is not reported.** The audit record says a table changed and who changed it. It
   does not carry the rule. A snapshot of the ruleset (AC1 state) remains to be built.
6. **Hostile text.** The path, command name and profile name come from the process that was denied.
   Strings are decoded from audit hex or quotes, cut at their limit and reduced to printable
   ASCII, with `sanitized` set when that changed anything. The operation of a decision and a
   netfilter operation must be lower-case identifiers; anything else drops the record. The first
   occurrence of a key wins, so a path that contains `name=` cannot overwrite the real one.
7. **Process attribution.** The audit `pid` is looked up in the entity graph. AppArmor reports the
   thread group id: checked with a denial raised by a non-leader thread of a Python process (thread
   id 10196, process 10195), the record carried 10195. A process that has gone resolves to a
   `{pid}` stub (`process_exited`).
8. **Same family, same switch.** These records come from the `auth` family primary (the audit
   provider) and stop when `enable_auth_events` is false. The log fallback cannot produce them, so a
   host that falls back to the log loses them and health says so.

## Consequences

- Verified on Ubuntu 22.04 / 5.15.0-91 / x86_64 as root, against the real Manager: a temporary
  AppArmor profile loaded, replaced and removed (each reported with `apparmor_parser` as the
  process), two reads and a file creation denied (process `cat` and `sh` resolved), `iptables`
  creating and deleting a chain and a rule, and `nft` creating a table and a chain and deleting the
  table; 452 records acknowledged, none quarantined. Unit tests cover the captured AppArmor and
  netfilter records, the SELinux message formats, hostile values and 20 000 mutated records.
- Not verified: SELinux on a real host (the formats come from the kernel and policy documentation,
  not from a capture), the dedicated AppArmor record types 1501 to 1506, kernels other than 5.15,
  aarch64, hosts where auditd owns the audit socket exclusively.
- Volume: container runtimes change the firewall on every container start, and a busy AppArmor
  profile in complain mode can produce a record per access. The provider governor (500 events per
  second) bounds both and counts what it drops; no per-profile or per-table limit exists yet.
- Not done: the firewall ruleset snapshot, a nftables netlink monitor (which would give the rule
  itself), the journal fallback for kernel messages, and posture changes of the LSM beyond what the
  audit stream reports (the AppArmor kernel parameters and SELinux enforce file are in
  `state.posture`, polled).
