# ADR 027: Wiring ISOLATE_HOST and RELEASE_HOST_ISOLATION into the command channel

**Status:** Accepted (implemented; unit tested; real-VM verification recorded under "Verified")
**Date:** 2026-10-07

## Context

ADR 004 built the privileged helper (the only holder of `CAP_NET_ADMIN`, a fixed 2-opcode IPC, a fixed nftables
ruleset, no TTL, no SSH break-glass) and its tests. ADR 024 left both isolation actions answering
`unsupported_action` because nothing connected the command channel to the helper. This ADR is that connection
and what the sensor must guarantee around it. It does not change ADR 004's decisions.

## Decision

1. **The sensor only asks.** `local_executor` calls `exchange_isolation_request` (pure socket syscalls: connect,
   send one fixed 129-byte frame, receive one status byte). The sensor gains no capability and runs no program.
   Only the validated command id crosses the socket; there is no address, rule or free text in the protocol.
2. **Configuration.** `response_isolation_socket=/abs/path` names the helper's AF_UNIX SEQPACKET socket (shorter
   than `sun_path`, no `..`). `ISOLATE_HOST` and `RELEASE_HOST_ISOLATION` are listed **together and only with the
   socket**; either action alone, or the socket without them, is a configuration error. An endpoint that can cut
   itself off must be able to be released, and an action without a helper to ask would be a promise the sensor
   cannot keep. Both are off the default allow-list: a sensor isolates only if its operator listed the actions.
3. **Bounded waiting.** The helper is a single-threaded daemon. Connect, send and receive are bounded by
   `isolation_timeout` (20 s) with `SO_SNDTIMEO`/`SO_RCVTIMEO` (a full backlog also blocks `connect`, and
   `SO_SNDTIMEO` covers it). A sensor thread never waits on the helper forever. The bound has to outlast the
   helper's own netlink waits: the first real-VM run found a 5 s client timeout racing a helper whose release
   path always waited out its own 5 s receive timeout (the kernel does not acknowledge a delete batch), so an
   idempotent release answered `helper_no_answer`. The release path now waits 0.5 s, because a reply, when there
   is one, is queued while `sendto` is still running, and the sensor allows 20 s.
4. **Outcomes say what is known.**

   | Situation | outcome / reason |
   | --- | --- |
   | helper answered ok | `succeeded` / `ok` |
   | helper answered, declined | `failed` / `helper_refused` |
   | nothing listening (nothing sent) | `failed` / `helper_unreachable` |
   | request sent, no complete answer in time | `indeterminate` / `helper_no_answer` |
   | command id cannot be encoded | `failed` / `invalid_request` |
   | no socket configured | `rejected` / `isolation_unavailable` |
   | dry run, helper reachable | `rejected` / `dry_run` |
   | dry run, helper not listening | `rejected` / `helper_unreachable` |

   `indeterminate` is the one that matters: the helper may have applied the ruleset and the answer was lost. The
   result says so instead of guessing. ISOLATE and RELEASE are idempotent in the helper (ADR 004), so the
   Manager can safely issue a new command to learn or fix the state.
5. **Dry run proves the path, changes nothing.** The probe connects and closes without sending a frame
   (`isolation_helper_reachable`); the helper sees an empty connection and does nothing.
6. **Lifecycle is the common one.** Authorization (ADR 025), policy mode, allow-list and the shared per-minute
   limit for changing actions run first; the ledger records intent before the executor runs; a redelivered or
   restarted command is closed from the ledger and never asks the helper twice; every outcome is a
   `response.action` audit record. `ISOLATE_HOST` is a changing action, so it counts against
   `response_max_changes_per_minute`.
7. **Capabilities are what policy permits.** The provider advertises `response.<action>` for each action the
   local policy allows, not a fixed list, so the Manager plans from what the endpoint will actually do.

## Not decided here (kept from ADR 004)

* **No automatic release / TTL and no SSH break-glass.** These were locked by ADR 004 and are unchanged. A
  dead-man's switch would be a reasonable operational feature, but it contradicts a locked decision and belongs to
  that decision's owners.
* **The helper pins the Manager address itself**, resolved once at its start. The sensor cannot verify that the
  address the helper pinned is the one `manager_url` uses. If they differ, an isolated host loses its Manager and
  can be released only from the console (or by the helper restarting with the right address). This is an
  operational requirement, recorded in the residual risks.

## Rejected alternatives

* **`CAP_NET_ADMIN` on the sensor, or `nft` through `exec`.** Rejected by ADR 004.
* **Treating `no_answer` as failure.** It would let a Manager believe a host was reachable when it may be cut off.
* **Letting a dry run send a harmless opcode.** There is none: both opcodes change the firewall.
* **Listing isolate without release.** An operator could strand a host; the configuration refuses it.

## Residual risks and limits

* Helper and `manager_url` must name the same Manager (see above); the sensor cannot check it.
* `helper_no_answer` leaves the true state unknown until the Manager asks again.
* The helper authenticates the peer by uid (`SO_PEERCRED`); the sensor and helper must agree on that user.
* Isolation is whole-host and fixed-shape (ADR 004 revisit triggers apply to anything finer).
* Packet-level behaviour is validated in namespaces on one VM, not on a multi-NIC production topology.

## Verified

Unit (`panopticon-isolation-tests`, 6 tests): an in-process fake helper on a real AF_UNIX SEQPACKET socket
exercises accepted, refused, unreachable, no answer (bounded wait), hang-up, invalid command id and socket path,
the reachability probe sending nothing, and the executor's isolate, release, dry-run and failure outcomes. Config
rules (pairing, socket required, relative, `..`, over-long) in `command_tests`.

Real VM (Ubuntu 22.04, kernel 5.15, root, three network namespaces with veth pairs, TLS fake Manager on a veth
address, real helper, real nftables, `tests/e2e/run_isolation_command_e2e.sh`, 26 checks): a dry-run sensor
proves the helper and applies nothing; an unsigned isolate is refused with the peer still reachable; a signed
isolate returns `succeeded` **through** the pinned Manager path, the peer becomes unreachable, the Manager stays
reachable and the helper records it; a command delivered while isolated still runs; redelivery and a sensor
restart while isolated re-run nothing and keep containment; a helper crash keeps the host contained (the kernel
ruleset persists) and its restart re-applies the recorded state; a signed release restores the peer; a second
release is an idempotent success; with no helper, isolate fails with `helper_unreachable` and nothing is applied;
outcomes are audited. The existing helper scripts (`run_isolation_e2e.sh`, packet verification, robustness) pass
against the changed helper.

Defect found by this run and fixed: an idempotent release answered `helper_no_answer`, because the helper's
release path waited out its whole 5 s netlink receive timeout and the client's 5 s bound raced it (see decision
3).
