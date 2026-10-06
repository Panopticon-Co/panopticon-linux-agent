# ADR 022: DNS queries with process attribution (`dns.query`)

**Status:** Accepted
**Date:** 2026-10-06

## Context

A network record says a process talked to an address. It does not say what it asked for. The names
a process resolves are the earliest and often the only visible trace of DGA malware, DNS tunnelling
and staged downloads, and a resolver daemon hides which application asked: the datagram on the wire
comes from `systemd-resolved`, not from the program.

## Decision

1. **Read the datagram where it leaves the process.** The existing `udp_sendmsg`/`udpv6_sendmsg`
   fentry hooks of the `network` provider role, when the destination port is 53, copy up to 320
   bytes of the sender's buffer (`bpf_probe_read_user`) into a `PAN_EVENT_DNS_QUERY` record. The
   sender is `current`, so the asker is exact for the application's own query to a stub resolver
   and, separately, for the stub's upstream query. No new hook and no packet capture.
2. **Parse in user space, bounded and strict.** `parse_dns_query` accepts a message with the response
   bit clear and exactly one question, rejects compression pointers and extended label types (not
   valid in a question), labels over 63 bytes and names over 255, and renders the name in
   presentation form with `.`, `\` and non-printable bytes escaped. Port-53 traffic that is not a DNS
   question yields no `dns.query` (the UDP flow record still names it) and is not an error.
3. **Read the buffer across kernel layouts.** `struct iov_iter` changed shape in 6.0 (`ubuf`) and 6.4
   (`__iov`). A CO-RE flavour of the struct, field-existence guards and the `ITER_IOVEC` enumerator
   value select the right read at load time. Only the first buffer of a message is read, so a
   question split across several `sendmsg` iovecs is not reported (documented, tested).
4. **Deduplicate in the kernel.** One record per (process, question) per five seconds, keyed on a
   hash of the message after its transaction id, so an A/AAAA pair is two records and a retry is
   one. An LRU map bounds the memory.
5. **Questions only.** No answers, no response codes, no resolved addresses. That needs the ingress
   path and a correlation to the asker, and is a separate decision.
6. **The sensor does not report its own queries.** `skip_own_network_events` covers them.

## Consequences

- Verified on Ubuntu 22.04 / 5.15.0-91 / x86_64 as root: parser unit tests (valid forms, escapes, the
  root name, every rejection above, and 20 000 pseudo-random messages that must stay bounded); decoder
  tests; a live test (explicit destination, retry deduplicated, other type reported, write on a
  connected socket, `sendmsg` with one iovec, text that is not DNS ignored, a split question not
  reported); a real sensord run with `getent`, glibc `getaddrinfo` and a direct TXT query: each
  attributed to its own process, `systemd-resolved` attributed separately for its upstream and
  DNSSEC (`DNSKEY`, `DS`) queries; the Manager accepted every record, none quarantined.
- Finding: a validating stub resolver multiplies the volume (five or six upstream records per new
  name). They are accurate; a rule that wants the application should look at the stub-side record.
- Finding: while building this the BPF verifier rejected the first version: a length whose address
  was taken lived in a stack slot and lost its bound. The length is now passed by value and clamped
  immediately before use.
- Not verified: 6.x kernels (the `ubuf` and `__iov` paths are unexercised), aarch64, IPv6 servers
  (shared code, no live test), a glibc resolver using `sendmmsg` against a non-stub server.
- Not done: DNS over TCP (including truncated-response retries), answers, mDNS/LLMNR, DoH and DoT
  (invisible by design, they are ordinary connections), a per-name rate limit.
