# ADR 029: Ring-buffer wake-up policy

**Status:** Accepted (implemented; unit tested; real-VM verified with `tests/perf/run_overhead.sh` and `bpftool` program statistics)
**Date:** 2026-10-07

## Context

The first overhead measurement on the real VM (`tests/perf/run_overhead.sh`, Ubuntu 22.04, kernel 5.15, 4 vCPU)
showed the sensor adding **22.8 % to a spawn+wait loop and 235 % to a loopback TCP connection**, far over the 5 %
budget in `LINUX_ENDPOINT_PERFORMANCE.md`. `bpftool prog show` with `kernel.bpf_stats_enabled=1` located it: the
fork, exec and exit programs ran for 500 to 850 us per call, the other hooks for 0.2 to 1.4 us.

The programs submit with `bpf_ringbuf_output(..., 0)`. With flags 0 the kernel wakes the consumer whenever it has
caught up with the producer (an irq_work plus a scheduler wake), which for a consumer that keeps up is every
record. That wake is paid inside the hooked syscall, on the monitored process's time. With `BPF_RB_NO_WAKEUP` the same
programs take 3 to 5 us.

## Decision

The kernel side decides per record whether to wake; the user-space reader polls fast while records are flowing so
that not waking costs no latency.

1. **Wake only after a quiet gap.** A one-entry array map `wake_last` holds a timestamp. `wake_flags(now)` returns 0
   (wake) if `now - wake_last >= 20 ms` and stores `now`; otherwise it returns `BPF_RB_NO_WAKEUP`, and stores `now`
   only if at least 1 ms has passed since the stored value (one map write per millisecond, not per record). The first
   record after a pause therefore wakes the reader at once; the records of a burst after it do not. The map is
   updated without atomics, and that is safe in the direction that matters: a lost or late update can only leave
   `wake_last` older, which makes the gap look longer, which makes the kernel wake more often, never less.
2. **Poll fast after activity.** `ebpf_process::run` polls with a 1000 ms timeout while idle. After any record it
   polls with 5 ms until it has seen 6 consecutive empty polls (30 ms of silence, longer than the 20 ms gap), then
   returns to 1000 ms. After each `ring_buffer__poll` it calls `ring_buffer__consume` explicitly: `ring_buffer__poll`
   consumes nothing when it times out, and records that arrived without a wake-up would otherwise wait for the next
   wake.
3. **Delivery latency bound.** A record is delivered either by a wake (the first after a quiet gap) or by the 5 ms poll
   that follows it: at most about 5 ms plus the wake latency while active. The 30 ms hold-over is deliberately above
   the 20 ms gap so the reader is always in 5 ms mode when the kernel stops waking it.

The same policy applies to every role that uses the shared program (process, network, security) and to the DNS emit
path.

## Evidence

| | exec | tcp loopback | in-kernel `on_exec` |
| --- | --- | --- | --- |
| wake on every record | +22.8 % | +235 % | 510 us |
| this policy | +2.4 % | +15 % (inside this VM's noise, see the performance doc) | 3 to 5 us |

Test: `live_wake_policy` in `tests/ebpf_tests.cpp` spawns 200 children and requires every exit to be delivered, then
spawns one child after pauses of 5, 15, 22, 28, 35, 45, 60, 120, 300 and 1200 ms (around the 20 ms gap and the 30 ms
hold-over, and out to the idle poll) and requires each to arrive in under 400 ms, then requires zero kernel loss.
It then spawns 300 `/bin/true` processes back to back with the kernel's BPF run-time statistics enabled
(`BPF_ENABLE_STATS`) and requires `on_fork`, `on_exec` and `on_exit` to average under 100 us per call over them (the two
policies are 3 to 5 us and 320 to 850 us apart). The cost is measured on a dense workload only: when events are further
apart than the gap every one is meant to wake the reader, and the sanitizer builds of the test start their own children
so slowly (tens of ms) that the earlier part of the test is such a workload (a first version of the check averaged over
the whole test and failed under ASAN with 642 us on `on_exit`, which was the policy working, not a regression).
The test was checked against both ways of getting the policy wrong, on the dev VM:

| Build | Result |
| --- | --- |
| this policy, release and ASAN/UBSAN builds | PASS |
| the kernel never wakes the reader (gap test replaced by `if (0)`) | FAIL: "a record after a pause of 45 ms arrived in 988 ms" (the 5 to 35 ms pauses still pass, because the reader is in its 5 ms mode then, as designed) |
| the kernel wakes on every record (`PAN_WAKE_GAP_NS` 0) | FAIL: "on_fork costs 522 us per call in the kernel over 300 back-to-back processes (bound 100 us)" |

Delivery alone cannot catch the second kind of mistake, which is why the statistics check is there. The 100 us bound is
a ratio of 20 to 100 against what the policy costs on this VM; a much slower machine could need it raised.

## Consequences

- The kernel cost of a hook no longer depends on whether the reader is idle. CPU of the sensor during the heavy
  loop is 14 to 28 % of one core in the measurements (before: 16 to 22 %), so the cost moved from the monitored
  process to the sensor, where it is bounded and governed.
- Latency is bounded by the poll interval rather than the wake: up to ~5 ms more while records flow. The kernel to WAL
  p99 budget (250 ms) is unaffected.
- The 5 ms poll while active costs wake-ups of the reader thread (200/s) only while events flow; the reader is idle
  at 1 wake-up per second otherwise (section 5 of the performance doc).
- Not covered: loss behaviour under a producer faster than the reader is unchanged (the `drops` map still counts what
  `bpf_ringbuf_output` could not submit, and the provider reports it as a `kernel` loss).
