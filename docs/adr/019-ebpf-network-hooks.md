# ADR 019: eBPF network hooks and the network provider family

**Status:** Accepted
**Date:** 2026-10-06

## Context

Network telemetry came only from `sockdiag_network`, which polls the kernel socket tables every
500 ms and finds the owning process by matching the socket inode to `/proc/<pid>/fd` afterwards.
That misses a connection that opens and closes between two polls, attributes by reconstruction
rather than observation, and cannot see UDP traffic to a destination at all.

## Decision

1. **Hooks that run in the calling process.** `fentry/tcp_connect` (active open, SYN about to be
   sent), `fexit/inet_csk_accept` (the accepted socket, only when one was returned),
   `fexit/inet_listen` (only when `listen()` succeeded, so the port is bound), and
   `fentry/udp_sendmsg` / `fentry/udpv6_sendmsg`. The actor is `current`, so the pid, start time and
   uid are exact and confidence is `observed`.
2. **UDP is one record per (process, destination, port) per 60 s**, kept in an LRU map in the
   kernel so a scanner cannot exhaust it. The destination comes from the `msg_name` of an
   unconnected send, or from the socket for a connected one. Event type `network.udp_flow`,
   direction `outbound`.
3. **One BPF object, two providers.** `ebpf_process_provider` takes a role. The `process` role
   loads the process hooks (preferred over `netlink_proc`); the `network` role loads the network
   hooks and is registered in the `network` family ahead of `sockdiag_network`, so the existing
   family mechanism makes sockdiag a standby when the hooks load and the active provider when they
   do not (older kernel, no BTF, no root). Each provider disables autoload for the other role's
   programs, so no hook is attached twice. `connect` is required for the provider to start; the
   others are dropped and reported in health when the kernel cannot host them.
4. **The sensor does not report its own network events.** The uplink to the Manager would
   otherwise generate a record per delivered batch, which is then delivered in the next batch.
   This is a provider option (`skip_own_network_events`, default on); tests turn it off.
5. **Honest gaps.** `socket_inode` is `unavailable` (the hook sees the socket before a file
   descriptor exists). An unconnected UDP socket shows `0.0.0.0` as its local address because the
   kernel has not chosen a source yet. With the hooks active, UDP binds (the sockdiag `listen` for
   UDP) and sockets that existed before the sensor started are no longer reported as events; the
   host `state` snapshots are the place for those.

## Consequences

- Verified on Ubuntu 22.04 / 5.15.0-91 / x86_64 as root: decoder unit tests (all four kinds, IPv4
  and IPv6, malformed family and protocol), a live test that listens, connects, accepts and sends
  two datagrams in one process and checks exact ports, actor and the single UDP record, and a real
  `panopticon-sensord` run with a Python client and server. The verifier accepted the programs on
  5.15 with no changes.
- Not verified: other kernels (6.x), aarch64, IPv6 end to end on a live host, performance under a
  connection storm, and the kernels that inline or rename `tcp_connect` / `inet_listen`.
- Not done: `network.close` with byte counts, raw/packet sockets, DNS query names, TLS SNI,
  per-connection byte counters, and cgroup/namespace context on the record.
