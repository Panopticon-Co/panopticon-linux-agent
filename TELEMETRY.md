# Telemetry

The only implemented live-source adapter is a bounded Linux procfs process snapshot. For each
readable process it obtains PID, PPID, UID/GID, state, executable symlink, command line, cgroup
text, and kernel start ticks. The internal process identity is `(host_id, pid, start_time_ticks)`
to prevent PID-only targeting.

Normalization produces a size-bounded `linux-internal-1` NDJSON record. It JSON-escapes string
fields, includes agent/host context and the process identity tuple, and rejects oversized output.
It is an internal spool format, not a Panopticon 0.3 event.

For Manager delivery, the process adapter can additionally emit a size-bounded canonical schema
0.4 NDJSON process event. It uses `source.kind = linux_procfs`, deterministic SHA-256 event and
process entity identifiers, and nulls for fields procfs cannot safely provide. The adapter has no
transport dependency; Manager delivery remains disabled until enrollment and TLS transport exist.

The agent also reads bounded `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and
`/proc/net/udp6` tables, normalizing IPv4 and procfs-word-ordered IPv6 endpoints, protocol, and
a small set of connection states. It deliberately reports no process owner: these tables alone
cannot safely map a socket to a PID. Socket timestamps, safe process attribution, file, and
authentication collection are not implemented.

The current Panopticon 0.3 contract cannot represent Linux source kinds, so this data is never
sent to the Manager.
