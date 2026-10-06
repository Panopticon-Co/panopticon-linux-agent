# ADR 021: Namespace changes (`process.ns_change`)

**Status:** Accepted
**Date:** 2026-10-06

## Context

Escaping a container, joining one, and hiding from a view all pass through `setns(2)` or
`unshare(2)`. The namespace inode numbers on a process record (ADR 019/`process.ns`) say where a
process is; they do not say that it moved, who moved it, or from where.

## Decision

1. **Hook `switch_task_namespaces`** with `fentry` in the `security` provider role. Both syscalls end
   there, in the calling task, so the actor is exact (`observed`).
2. **Report only a real change.** The hook compares the inode numbers of the task's current
   namespace proxy with the one replacing it and emits nothing when none differ. Task exit (a call
   with no new proxy) is ignored. So `nsenter` into the host's own namespaces is silent.
3. **Six namespaces:** mnt, pid_for_children, net, uts, ipc, cgroup. The pid entry is the namespace
   the task's *children* are born in, which is what `unshare(CLONE_NEWPID)` changes. time namespaces
   are not read (not present on every supported kernel). User namespaces live in the credentials and
   are reported as unavailable (`ns_change.user`); the credential hooks already cover uid changes.
4. **Scope.** `process` when the thread group leader moved: the entity's recorded namespaces are
   updated so later records carry the new ones. `thread` when another thread moved: the process
   entity is left alone, because the process did not move. The record names the thread.
5. **One record per `setns`.** `nsenter -m -u -i -n -p -C` performs six calls and yields six records.
   That is faithful and is documented, not merged.

## Consequences

- Verified on Ubuntu 22.04 / 5.15.0-91 / x86_64 as root: decoder unit test; a live test in which a
  thread unshares UTS and IPC (inode numbers equal procfs exactly, other namespaces unchanged, one
  record); a real sensord run: `unshare --uts --ipc`, a docker container start (`runc` enters all
  six, equal to the container's `/proc/<pid>/ns`) and `nsenter` into that container; the Manager
  accepted every record, none quarantined.
- Finding: `dockerd` locks OS threads to a container network namespace and back, so a host with
  containers produces thread-scope `net` pairs steadily (ten in a few seconds of one container
  start). They are accurate and legitimate; rules must key on the process identity. No rate
  limit exists yet.
- Not verified: 6.x kernels, aarch64, `CLONE_NEWUSER` flows (not reported by design), a kernel that
  lacks `switch_task_namespaces` as an fentry target (the hook would be dropped and reported in
  health; the family still runs).
- Not done: user-namespace transitions, time namespaces, correlation of a `process.ns_change` to a
  container entity (the cgroup-derived identity is on the process record already).
