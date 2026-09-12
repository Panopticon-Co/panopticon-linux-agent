# Telemetry

The only implemented live-source adapter is a bounded Linux procfs process snapshot. For each
readable process it obtains PID, PPID, UID/GID, state, executable symlink, command line, cgroup
text, and kernel start ticks. The internal process identity is `(host_id, pid, start_time_ticks)`
to prevent PID-only targeting.

It is a snapshot, not reliable process-creation telemetry. Network, file, and authentication
collection are not implemented. The current Panopticon 0.3 contract cannot represent Linux
source kinds, so this data is never sent to the Manager.
