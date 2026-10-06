# ADR 014: Kernel module and mount changes by snapshot diff

**Status:** Accepted
**Date:** 2026-10-06

## Context

Matrix rows AP1 (kernel module load and unload) and AT1 (mount and unmount events) have state
inventories since S4 (`state.modules`, `state.mounts`) but no events. The primary mechanisms
are eBPF fentry hooks (`do_init_module`, `security_sb_mount`), which name the acting process and
catch short-lived changes. They are a later slice. The `/proc/modules` and mountinfo diff is the
documented fallback, and a module load or a new mount over `/etc` is exactly what a defender
needs to hear about even without the actor.

## Decision

1. A `kernel_change` provider polls `/proc/modules` and `/proc/self/mountinfo` every second and
   diffs against the previous snapshot with a pure `kernel_change_tracker`. The first snapshot of
   each file is the starting state and produces no events.
2. Modules are keyed by name. A module that appears is `kernel.module_load`, one that vanishes is
   `kernel.module_unload`, and a module whose size changed under the same name is reported as an
   unload followed by a load (it was replaced between two polls).
3. Mounts are keyed by mount id, device, root, mount point and file system type. A new key is
   `mount.changed` with `operation: mounted`, a missing key is `unmounted`, and the same key with
   different mount or super-block options is `remounted` (for example `ro` to `rw`). A mount
   over an existing directory such as `/etc` is a new mount id, so it is reported.
4. Snapshots are bounded. A file over 4 MiB, or a parsed list at the entry limit (4096), is not
   diffed: a truncated list would turn every missing entry into a false unload. The provider
   reports `degraded` with the reason instead.
5. At most 500 events per poll are sent; the excess is counted and reported as a governor loss.
6. There is no acting process. The record omits `process` and carries
   `unavailable: process, not_supported_by_provider`. Provenance is
   `{kernel_change, PROCFS, reconstructed}`: the change was found by comparing, not observed.
7. Mount paths are chosen by whoever mounts. They are decoded from mountinfo's octal escapes and
   written through the JSON encoder, so a path with quotes or newlines stays data.

## Consequences

* A module loaded and removed between two polls is not seen, and a mount that exists for less
  than a second is not seen. This is the reason the eBPF hooks stay the primary and the rows
  remain PARTIAL.
* Event time is the observation time, up to one second after the change.
* Mounts are read from the sensor's own mount namespace. Mounts inside containers' private
  namespaces are not visible until a per-namespace reader exists.
* Hosts with `modules_disabled` or a monolithic kernel have no `/proc/modules`; the provider
  runs on mounts alone and says so through its probe when neither file is readable.
