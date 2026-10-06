# ADR 020: Executable memory and eBPF load hooks (the `security` provider family)

**Status:** Accepted
**Date:** 2026-10-06

## Context

Fileless and in-memory execution (anonymous RWX staging, `mprotect` to executable, `memfd` code) and
kernel-resident eBPF implants leave no file for the file or process providers to see. The only
place to observe them is the kernel call that asks for the memory or the program.

## Decision

1. **LSM call sites, not syscall tracepoints.** `fentry/security_mmap_file`,
   `fentry/security_file_mprotect` and `fentry/security_bpf`. They run in the requesting process
   (the actor is `current`, confidence `observed`) and are the same hooks an LSM would use, so
   `io_uring` paths that bypass syscall entry points still reach them.
2. **What is reported.**
   - `mmap` requested with `PROT_EXEC` whose backing is anonymous memory or a memfd. File-backed
     mappings (every shared library) are not reported.
   - `mprotect` that adds `PROT_EXEC` to a mapping that was not executable. File mappings are
     reported only when the new protection is also writable. The record carries the address and
     length of the mapping the call touched.
   - `bpf(2)` commands `PROG_LOAD`, `PROG_ATTACH`, `RAW_TRACEPOINT_OPEN` and `LINK_CREATE`, with the
     program type and name (load), the attach type (attach, link) or the tracepoint (raw tp).
     Creating maps is routine and is not reported.
3. **Deduplicate in the kernel.** One memory event per (process, operation, backing, writable) per
   five seconds, kept in an LRU map, so a JIT is one fact. This bounds the ring buffer without a
   user-space governor; it also means a second distinct mapping in the window is not a record.
4. **A request, not an outcome.** The hooks run before the kernel acts. The records say what the
   process asked for; a later security module may refuse it. The catalog and contract say so.
5. **Same BPF object, a third role.** `ebpf_role::security`, family `security`, with no
   fallback provider: if the kernel cannot host the hooks the family reports unavailable with the
   reason instead of a weaker substitute. `security_mmap_file` is required; the other two are
   dropped and reported in health when absent. Config key `enable_security_events` (default true).
6. **The sensor does not report its own eBPF loads.**

## Consequences

- Verified on Ubuntu 22.04 / 5.15.0-91 / x86_64 as root: decoder unit tests (all kinds, unknown
  backing, unknown command, unknown program type, unterminated name), a live test that makes an
  RWX mapping twice (one report), an mprotect (exact address and length), a memfd exec mapping, a
  file-backed exec mapping (not reported) and a real `bpf(PROG_LOAD)`; a real `panopticon-sensord`
  run delivering all four records to the Manager with none quarantined; the same run against a Manager
  that still had the old schema produced a real `manager_rejected` loss record.
- Not verified: 6.x kernels (`vm_flags` is a union there, CO-RE should cope), aarch64, a JIT-heavy
  workload (browser, JVM, Node) for volume, and an LSM that refuses the request.
- Not done: the address of an `mmap` (unknown at the hook), `perf_event_open`, `userfaultfd`,
  `io_uring_setup`, `kexec_load`, module load with an actor, `state.bpf` inventory and
  hidden-program cross-view, a procfs `maps` scan fallback.
