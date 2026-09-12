# Telemetry

The only implemented live-source adapter is a bounded Linux procfs process snapshot. For each
readable process it obtains PID, PPID, UID/GID, state, executable symlink, command line, cgroup
text, and kernel start ticks. The internal process identity is `(host_id, pid, start_time_ticks)`
to prevent PID-only targeting.

Normalization produces a size-bounded `linux-internal-1` NDJSON record. It JSON-escapes string
fields, includes agent/host context and the process identity tuple, and rejects oversized output.
It is an internal spool format, not a Panopticon 0.3 event.

The snapshot is not reliable process-creation telemetry. Network, file, and authentication
collection are not implemented. The current Panopticon 0.3 contract cannot represent Linux
source kinds, so this data is never sent to the Manager.
