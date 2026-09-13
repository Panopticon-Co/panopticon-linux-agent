# Response boundary

The Manager's Response Engine authorizes commands; this agent only authenticates, validates,
target-checks, replay-checks, dispatches a closed action set, executes, receipts, and audits.

## Current status

The agent authenticates to the Manager via its enrolled bearer identity, polls
`GET /api/v1/agents/{agent_id}/commands`, decodes only the closed schema-1 envelope
(`parse_command_json`), and gates every command through `command_gate::validate_and_mark`
before dispatch: agent/host binding, expiry, in-memory and durable (`replay_ledger`,
survives restart) replay protection, and protected-PID rejection for `KILL_PROCESS`.

Immediately after a command passes the gate and before this agent executes it, the agent
sends a best-effort `POST /api/v1/agents/{agent_id}/commands/{command_id}/accept`
(`curl_https_client::accept_command`), moving Manager's lifecycle state from `DISPATCHED`
to `ACCEPTED`. This is an optional acknowledgement, not a second protocol: its outcome is
never checked and never blocks execution, because Manager still accepts a result submitted
straight from `DISPATCHED` for an agent that skipped or failed the call.

All 7 actions in the closed set are dispatched to a real, bounded implementation:

- `KILL_PROCESS` -- SIGTERM only after a fresh procfs re-observation proves the exact
  PID/start-time tuple (defeats PID reuse).
- `COLLECT_PROCESS_INFO` -- same re-observation, returns the process observation.
- `COLLECT_NETWORK_CONNECTIONS` -- bounded `/proc/net/{tcp,tcp6,udp,udp6}` collection.
- `COLLECT_FILE` -- root-jailed, symlink-rejecting, size-bounded read; only a SHA-256 hash
  and metadata are ever returned, never raw content.
- `QUARANTINE_FILE` -- root-jailed atomic move into a configured quarantine directory.
- `ISOLATE_HOST` / `RELEASE_HOST_ISOLATION` -- typed, bounded IPC (`request_isolation`) to
  the privileged `panopticon-isolation-helper` over `AF_UNIX SOCK_SEQPACKET`; this agent
  process never holds `CAP_NET_ADMIN` itself. If `isolation_socket_path` is not configured,
  both actions fail closed as `execution_failed` rather than silently no-opping. See
  `docs/adr/004-host-isolation-privilege-boundary.md`.

Every command result is a typed, bounded receipt (`serialize_command_result`) submitted to
`POST /api/v1/agents/{agent_id}/command-results`. No command ever reaches an unbounded
filesystem read, a shell, or an arbitrary executable -- see `SECURITY.md`.
