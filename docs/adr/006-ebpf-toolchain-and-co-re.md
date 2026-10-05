# ADR 006: eBPF via libbpf CO-RE with embedded objects

**Status:** Accepted
**Date:** 2026-10-06

## Context

Kernel instrumentation without a kernel module requires eBPF. Options: BCC (compiles on the
host, needs kernel headers and LLVM at run time), bpftrace (not embeddable as a sensor),
libbpf with CO-RE (compile once, relocate against the running kernel's BTF), or Go/Rust
loaders which do not fit the C++20 codebase (ADR 003).

## Decision

1. eBPF programs are C under `bpf/`, compiled with clang (`-target bpf -g -O2`) against a
   vendored `vmlinux.h` per architecture (generated from a BTF-enabled kernel and committed, as
   libbpf-bootstrap does).
2. libbpf is vendored as a pinned git submodule (`third_party/libbpf`) and linked statically, so
   the sensor does not depend on the distribution's libbpf (Ubuntu 22.04 ships 0.5).
3. Compiled BPF objects are embedded into the sensor binary at build time and opened with
   `bpf_object__open_mem`. No skeleton generator, kernel headers or `bpftool` are needed at run
   time.
4. Every program is optional at load time: programs whose hook does not exist on the running
   kernel are disabled with `bpf_program__set_autoload(false)`, and fentry programs fall back to
   kprobe variants.
5. Event transport uses the ring buffer when supported, otherwise a perf event array.
6. Kernels without BTF use external BTF only if the operator supplies it; otherwise eBPF
   providers report `kernel_feature_missing` and the netlink/fanotify/procfs fallbacks take over.

## Consequences

* One binary per architecture covers all supported kernels with BTF.
* Build hosts need clang ≥ 12 and libelf/zlib (for libbpf). libbpf itself is vendored and
  linked statically, but libelf (and zlib) are still dynamic **runtime** dependencies of the
  sensor binary; packaging (S10) must declare them or link them statically.
* A committed `vmlinux.h` exists for x86_64 only. aarch64 builds disable the eBPF provider with
  an explanatory CMake message until one is generated on an aarch64 kernel; the sensor then runs
  on netlink_proc + procfs.
* Optional programs that a kernel cannot host leave their capability uncovered even though the
  fallback provider is on standby; the fallback only takes over when the whole provider fails.
* Verifier limits are a design constraint (bounded loops, 512-byte stack, per-CPU scratch maps
  for large records).
