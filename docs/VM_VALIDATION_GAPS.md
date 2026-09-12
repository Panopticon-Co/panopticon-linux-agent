# VM validation gaps

Automated tests cover pure core behavior on the development host. A real Ubuntu/Debian
systemd VM is still required for procfs process collection, inotify/journald sources,
capability-limited service operation, HTTPS Manager delivery, and any firewall isolation.
Run `cargo test`, install the service, generate benign process/file activity, and verify
only the documented Manager endpoint before marking each item validated.
