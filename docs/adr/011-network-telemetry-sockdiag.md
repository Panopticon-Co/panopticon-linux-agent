# ADR 011: Network telemetry through sock_diag polling

**Status:** Accepted
**Date:** 2026-10-06

## Context

Matrix rows Z1 (outbound connect), Z2 (inbound accept) and AA1 (listeners) need to say which
process opened, accepted or listens on a socket. The primary mechanisms are eBPF socket hooks
(`tcp_connect`, `inet_csk_accept`, `security_socket_listen`), which are exact, in-kernel and
carry the acting process. They are a separate slice because they need new CO-RE programs and a
new ring-buffer event layout. Until then the sensor must not be blind to the network, and it must
not claim more than it can see.

## Decision

1. A `sockdiag_network` provider in family `network` polls the kernel's TCP and UDP socket tables
   (IPv4 and IPv6) over `NETLINK_SOCK_DIAG` every 500 ms. It needs no capability for the dump.
2. The decoder treats the netlink reply as hostile input: every length is checked against what
   remains, an unknown address family or short body stops decoding with `malformed`, an error
   reply is reported with its errno, and the tests cut a valid reply at every byte and feed
   random buffers under ASAN/UBSAN.
3. A pure `socket_tracker` diffs successive snapshots. The first snapshot is state, not events.
   A socket is reported once, when it first appears:
   * TCP `LISTEN` or a bound, unconnected UDP socket: `network.listen`;
   * a socket with a remote end whose local port is a listener in the same snapshot:
     `network.accept` (TCP only); any other: `network.connect`.

   The table is bounded (65 536 sockets); what does not fit is counted and reported as a loss.
   Sockets that appear already finished (TIME_WAIT, CLOSE, no owner inode) are not reported,
   because their process cannot be known.
4. The owner is found by matching the socket inode to `/proc/<pid>/fd` after the fact, within a
   250 ms budget, only when there are new sockets. When several processes hold the socket (a
   forked server) the lowest pid is reported with `holders`. A socket with no holder left is
   reported with `unavailable: process` (`process_exited`, or `budget_exceeded` when the scan
   ran out of time); the owner is never guessed.
5. Provenance is `{sockdiag_network, SOCKDIAG, reconstructed}`: the record says it was derived
   after the fact.

## Consequences

* A connection that opens and closes between two polls is invisible, and one that is seen after
  its process exited has no owner. A DNS lookup by a short-lived client shows exactly this. This
  is the reason the eBPF mechanism stays the primary for Z1 and Z2 and why the rows are only
  PARTIAL (fallback).
* Direction is inferred from the local port being a listener; a client that connects to a port
  this host also listens on (loopback tests) yields both a connect and an accept, which is
  correct.
* Event time is the observation time, not the time of the connect.
* Volume is bounded by socket churn, not packet rate; there is no byte accounting.
* `network.close`, `network.udp_flow` and `network.raw_socket` are not provided.
