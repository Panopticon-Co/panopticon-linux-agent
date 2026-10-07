# Configuration

**`panopticon-sensord`** reads one strict `key=value` file (`--config PATH`). Unknown or duplicate keys stop it from
starting. The complete key reference, defaults and validation rules are in
[docs/endpoint/LINUX_ENDPOINT_CONFIGURATION.md](docs/endpoint/LINUX_ENDPOINT_CONFIGURATION.md); a commented example
is [packaging/sensord.conf.example](packaging/sensord.conf.example). Feature groups, each all-or-nothing:

| Feature | Keys that must be set together |
| --- | --- |
| Delivery to a Manager | `manager_url`, `identity_path`, `ca_bundle` |
| Command channel | the delivery keys plus `response_signing_keys` (pinned ES256 keys). `response_allow_unsigned=true` is accepted **only** by a `-DPANOPTICON_LAB_UNSIGNED_COMMANDS=ON` build |
| Signed local policy | `policy_path`, `policy_signing_keys` |
| Self-integrity | `integrity_manifest`, `integrity_keys` (state is kept in `<wal_path>.integrity`) |
| Durability | `wal_path`, `wal_quota_bytes` |

Configuration, key files and the CA bundle must be regular files owned by root or the sensor user and not
group/world-writable, in directories that are not writable by others (ADR 031). Key custody and rotation:
[docs/endpoint/LINUX_ENDPOINT_KEY_CUSTODY.md](docs/endpoint/LINUX_ENDPOINT_KEY_CUSTODY.md).

## Foundation agent (`panopticon-linux-agent`)

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
