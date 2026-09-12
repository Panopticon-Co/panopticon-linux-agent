# Response-agent contract v1

Commands are typed JSON objects containing `command_id`, `request_id`, `host_id`,
`agent_id`, `schema_version`, `action`, `target`, and expiry. Supported action names are a
closed enum: `KILL_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`,
`COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`, and `RELEASE_HOST_ISOLATION`.

There is deliberately no execute-command, shell, script, executable, or firewall-rule
action. The agent validates target host/agent/schema/expiry before dispatch and returns a
structured receipt. Repeated completed command IDs return the prior receipt; a persistent
replay ledger and authenticated command envelope await the Manager/Response API contract.
