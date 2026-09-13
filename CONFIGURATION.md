# Configuration

The internal line-based configuration parser is strict: unknown and duplicate keys are errors.
It currently requires `manager_url` (an `https://` URL), `agent_id`, `host_id`,
`queue_capacity`, `spool_quota_bytes`, `maximum_event_bytes`, `maximum_batch_bytes`, and
`response_enabled`. All limits must be positive and a batch cannot be smaller than an event.

Optional keys enable additional subsystems once populated: `identity_path` and
`enrollment_token_path` (durable enrolled identity plus schema-0.4 HTTPS delivery via
`transport.hpp` -- see TELEMETRY.md), `spool_path` (durable spool segments),
`file_collection_root` / `quarantine_root` (root jail for `COLLECT_FILE`/`QUARANTINE_FILE`),
and `isolation_socket_path` (the `AF_UNIX SOCK_SEQPACKET` path to the privileged
`panopticon-isolation-helper` for `ISOLATE_HOST`/`RELEASE_HOST_ISOLATION` -- see RESPONSE.md
and ADR 004). Leaving `isolation_socket_path` unset makes both isolation actions fail closed as
`execution_failed` rather than silently no-opping.

The parser validates configuration text only; it does not itself manage file permissions,
reload, or certificate provisioning -- those remain operational/deployment concerns (see
`systemd/` unit hardening).
