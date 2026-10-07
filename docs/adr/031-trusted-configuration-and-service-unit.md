# ADR 031: Trusted configuration paths, and the sensord service unit with a real watchdog

**Status:** Accepted (implemented; unit tested; real-VM verified on Ubuntu 22.04, kernel 5.15, systemd 249)
**Date:** 2026-10-07

## Context

Two things the security model already claimed were not true of the sensor that ships.

1. **"Strict loader rejects non-root or group/world-writable files [built]"** (threat T9). The sensord loader checked
   only the group and world write bits of the configuration file itself. It did not check who owned it, and it did
   not look at the directory it lives in. The command signing key list (ADR 025), which is the trust anchor for every
   enforcement command, and the CA bundle (which decides who may speak as the Manager) were read with no check at
   all. A user who could write the key list could authorise their own `KILL_PROCESS`, `QUARANTINE_FILE` or
   `ISOLATE_HOST`; one who could write the CA bundle could stand in for the Manager. Root can always do these things
   directly, so the boundary that matters is everyone else.
2. **"`Restart=always`; systemd watchdog"** (threat T10). There was no service unit for `panopticon-sensord` at all
   (the two units in `systemd/` belong to the older agent and its isolation helper), and the sensor could not
   have fed a watchdog: it never spoke the notify protocol. A sensor stuck behind a hung disk looked alive.

## Decision

### Trusted paths (`include/panopticon/linux_agent/trusted_path.hpp`)

`untrusted_path_reason(path)` returns why a path must not be trusted, or an empty string. A trusted path is a regular
file that is owned by root or by the effective user and not writable by group or others, under directories (checked
both as written and after resolving symlinks) that are owned by root or the effective user and not writable by group
or others. A directory that others can write into is accepted only if it is sticky (`/tmp`, `/var/tmp`), because there
nobody can rename or delete another user's file.

It is applied to:

* the sensor configuration (`load_sensor_config`): the sensor does not start;
* the `ca_bundle` it names, at the same time: the sensor does not start;
* the command signing key list (`command_keyring::read_file`): at start the command channel stays off (the existing
  fail-closed path for an unusable key list), and at a reload the previous keys stay in force with the reason in
  `last_error`. A change of mode alone is not noticed until the next content change, because the reload is keyed on
  size and modification time.

The check does not try to stop root. Group-write is refused even where the group is private, because the sensor
cannot know that; the tests set `umask(022)` because Ubuntu's login umask of 002 would make every file they create
group-writable.

### Service unit (`systemd/panopticon-sensord.service`)

* `Type=notify`, `NotifyAccess=main`, `WatchdogSec=30`, `Restart=always`, `StartLimitIntervalSec=0`,
  `OOMScoreAdjust=-900`.
* `sensor/systemd_notify.{hpp,cpp}` implements the three messages the unit needs (`READY=1`, `WATCHDOG=1`,
  `STOPPING=1`, plus `STATUS=`) with one datagram each to `NOTIFY_SOCKET`, without libsystemd. `WATCHDOG_USEC` and
  `WATCHDOG_PID` are honoured; a sensor started by hand has no socket and every call does nothing.
* The watchdog is fed from **inside `sensor_pipeline::run`** through `set_heartbeat`, at half the period, once per
  loop iteration. A loop stuck behind a hung disk or a deadlock stops feeding it and systemd restarts the sensor.
  Feeding it from a timer thread would have measured nothing.
* A restart after the watchdog (or any kill) is reported by the next start as a `sensor_gap` loss (S13.11), so the
  Manager sees the blind interval.
* Capabilities are bounded to what the providers use: `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE
  CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER CAP_NET_ADMIN CAP_AUDIT_READ CAP_AUDIT_CONTROL
  CAP_KILL`. `NoNewPrivileges`, `ProtectSystem=strict` (state under `StateDirectory=panopticon`),
  `ProtectHome=read-only`, `ProtectKernelModules/Logs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
  `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`,
  `SystemCallArchitectures=native`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `UMask=0077`.
* **No `PrivateTmp=` on purpose.** The sensor must see the real `/tmp` and `/dev/shm`, where payloads are staged; a
  private mount namespace for them would blind exactly that telemetry.
* No `SystemCallFilter=`: a filter that is slightly wrong kills the sensor with SIGSYS on a code path that is rarely
  exercised, which is a worse failure than the exposure it removes. `systemd-analyze security` scores the unit 5.3
  (MEDIUM), the cost of the capabilities an EDR needs.

## Verification (Ubuntu 22.04 VM, real systemd)

* Under the unit with the sandbox above every provider starts (`ebpf_process`, `fanotify_file`, `sensitive_file`,
  `ebpf_network`, `ebpf_security`, `kernel_change`, `audit_netlink`, `procfs`), and real activity produced the
  expected records: execs, a script staged in `/tmp` and a binary dropped in `/dev/shm` (both seen with their real
  paths), `/etc/shadow` opens, loopback connections.
* A sensor stopped with `SIGSTOP` was restarted by the watchdog (`WatchdogSec=4` in a test drop-in), reported one
  `sensor_gap`, and ran again; `kill -9` was restarted by `Restart=always` with one more gap; a clean
  `systemctl restart` added none.
* Unit tests: the notifier protocol (`systemd_notifier_protocol`), the configuration and CA checks
  (`config_and_ca_must_be_trustworthy`), the key list (`keyring_refuses_an_untrusted_file`, including a directory
  that others can write and, as root, a file owned by another user). The command authorization end-to-end suite still
  passes (51 checks, 0 failed).

## Limits

* The path check is a check at load and, for the key list, at reload. A file that is swapped between the check and the
  read by someone who can write its directory is exactly what the directory rule exists to prevent; where the
  directory is sticky, the owner rule covers it.
* The unit is not packaged: there is no `.deb`/`.rpm` and no installer that creates `/etc/panopticon/sensord.conf`
  with the right owner. Response file actions need the roots they move files out of in `ReadWritePaths=` (a drop-in).
* Not tested: other distributions' systemd versions, SELinux or AppArmor profiles for the unit.
