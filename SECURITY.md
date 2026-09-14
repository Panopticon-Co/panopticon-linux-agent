# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Panopticon-Co/panopticon-linux-agent/security/advisories/new)
for this repository. **Do not open a public issue for a vulnerability report.**

There is no dedicated security email address for this project. This is a capstone/research
security project maintained by a small team; response and remediation times are best-effort, not
SLA-backed.

## Security architecture notes

The codebase contains no shell execution API, command string, `system`, `popen`, or arbitrary
executable dispatcher. Commands use a closed `action_type` enum and are rejected unless their
schema, agent, host, expiry, and replay state pass the local gate. PID 1 is always protected.

The spool uses atomic publish and a non-cryptographic checksum to detect accidental corruption;
it does not claim tamper evidence. Production integrity/authentication awaits an approved
credential and protocol design. Sanitizers are required test tooling, not production controls.

Host isolation (`ISOLATE_HOST` / `RELEASE_HOST_ISOLATION`) runs across a privilege boundary: only
the separate `panopticon-isolation-helper` process holds `CAP_NET_ADMIN`, and it never invokes a
shell or the `nft` CLI -- see [ADR 004](docs/adr/004-host-isolation-privilege-boundary.md).
