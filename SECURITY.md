# Security

The codebase contains no shell execution API, command string, `system`, `popen`, or arbitrary
executable dispatcher. Commands use a closed `action_type` enum and are rejected unless their
schema, agent, host, expiry, and replay state pass the local gate. PID 1 is always protected.

The spool uses atomic publish and a non-cryptographic checksum to detect accidental corruption;
it does not claim tamper evidence. Production integrity/authentication awaits an approved
credential and protocol design. Sanitizers are required test tooling, not production controls.
