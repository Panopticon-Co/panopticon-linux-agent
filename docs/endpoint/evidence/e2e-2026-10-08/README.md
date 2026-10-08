# End-to-end runs on the current Release build, 2026-10-08

Ubuntu 22.04 VM (kernel 5.15.0-91, x86_64), Release `build-rel` built from the tree at the commit that follows `448a6d3`.
Logs are unedited script output.

| Script | Result | Notes |
| --- | --- | --- |
| `run_command_auth_e2e.sh` | 51 passed, 0 failed | Packaged build (the unsigned option is compiled out, ADR 034); the lab-build variant of scenario 7 was not re-run. The script's own `pkill -f panopticon-sensord` killed my wrapper shell, whose command line contained that name; the script had already printed its summary |
| `run_integrity_e2e.sh` | 26 passed, 0 failed | The first run gave 25/1: the check `edit: health degraded` read the last health record, which can predate the violation (health is every ~10 s). The test now waits for a degraded health record; the product behaved correctly. The log here is the re-run |
| `run_policy_sweep_e2e.sh` | 16 passed, 0 failed | |

The package e2e is in `../package-e2e-2026-10-08/`.
