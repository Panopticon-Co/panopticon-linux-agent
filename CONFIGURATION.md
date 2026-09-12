# Configuration

The internal line-based configuration parser is strict: unknown and duplicate keys are errors.
It currently requires `manager_url` (an `https://` URL), `agent_id`, `host_id`,
`queue_capacity`, `spool_quota_bytes`, `maximum_event_bytes`, `maximum_batch_bytes`, and
`response_enabled`. All limits must be positive and a batch cannot be smaller than an event.

The parser validates configuration text only. Secure configuration-file ownership, certificate
material, enrollment credentials, reload, and a live transport are not implemented yet.
