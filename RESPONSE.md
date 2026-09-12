# Response boundary

The Manager's Response Engine authorizes commands; this agent only authenticates, validates,
target-checks, replay-checks, dispatches a closed action set, executes, receipts, and audits.

## Current status

The agent authenticates to the Manager via its enrolled bearer identity, polls
`GET /api/v1/agents/{agent_id}/commands`, decodes only the closed schema-1 envelope
(`parse_command_json`), and gates every command through `command_gate::validate_and_mark`
before dispatch: agent/host binding, expiry, in-memory and durable (`replay_ledger`,
survives restart) replay protection, and protected-PID rejection for `KILL_PROCESS`.

Of the 7 actions in the closed set, 5 are dispatched to a real, bounded implementation:

- `KILL_PROCESS` -- SIGTERM only after a fresh procfs re-observation proves the exact
  PID/start-time tuple (defeats PID reuse).
- `COLLECT_PROCESS_INFO` -- same re-observation, returns the process observation.
- `COLLECT_NETWORK_CONNECTIONS` -- bounded `/proc/net/{tcp,tcp6,udp,udp6}` collection.
- `COLLECT_FILE` -- root-jailed, symlink-rejecting, size-bounded read; only a SHA-256 hash
  and metadata are ever returned, never raw content.
- `QUARANTINE_FILE` -- root-jailed atomic move into a configured quarantine directory.

`ISOLATE_HOST` and `RELEASE_HOST_ISOLATION` are rejected at parse time as
`unsupported_action` -- no implementation of any kind exists yet. See `docs/adr/` for the
planned privileged-helper design once it lands.

Every command result is a typed, bounded receipt (`serialize_command_result`) submitted to
`POST /api/v1/agents/{agent_id}/command-results`. No command ever reaches an unbounded
filesystem read, a shell, or an arbitrary executable -- see `SECURITY.md`.
