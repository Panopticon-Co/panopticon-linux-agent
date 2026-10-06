#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace panopticon::linux_agent::sensor {

// Kernel event sources report different clocks: eBPF `bpf_ktime_get_boot_ns()` and procfs
// start times are CLOCK_BOOTTIME based, the proc connector reports CLOCK_MONOTONIC. The sensor
// converts both to wall-clock nanoseconds with offsets re-sampled periodically, so that
// records from different providers order correctly on one timeline.
class clock_domain {
public:
    clock_domain();
    void resample();
    // How far the wall clock has moved against CLOCK_BOOTTIME since the offsets were sampled: near
    // zero normally (slew is a few milliseconds a minute), large after the clock was stepped (NTP
    // correcting a wrong boot time, `date -s`, a VM resumed).
    [[nodiscard]] std::int64_t boot_offset_drift_ns() const noexcept;
    // For tests: pretend the offsets were sampled when the wall clock read `shift_ns` less.
    void shift_offsets_for_test(std::int64_t shift_ns) noexcept;

    [[nodiscard]] std::uint64_t boottime_to_unix_ns(std::uint64_t boottime_ns) const noexcept;
    [[nodiscard]] std::uint64_t monotonic_to_unix_ns(std::uint64_t monotonic_ns) const noexcept;
    [[nodiscard]] std::uint64_t ticks_to_unix_ns(std::uint64_t ticks_since_boot) const noexcept;
    // Inverse of ticks_to_unix_ns; used only to infer an identity when procfs is already gone.
    [[nodiscard]] std::uint64_t unix_ns_to_ticks(std::uint64_t unix_ns) const noexcept;
    [[nodiscard]] std::uint64_t ticks_per_second() const noexcept { return ticks_per_second_; }

    [[nodiscard]] static std::uint64_t now_unix_ns() noexcept;
    [[nodiscard]] static std::uint64_t now_boottime_ns() noexcept;
    [[nodiscard]] static std::uint64_t now_monotonic_ns() noexcept;

private:
    // Read by provider threads while the pipeline resamples; relaxed atomics suffice because the
    // two offsets are independent and a stale value is off only by the clock slew.
    std::atomic<std::int64_t> boot_offset_ns_{0};       // unix - boottime
    std::atomic<std::int64_t> monotonic_offset_ns_{0};  // unix - monotonic
    std::uint64_t ticks_per_second_{100};
};

// RFC 3339 UTC with nanosecond precision, e.g. 2026-10-06T12:00:00.000000001Z.
[[nodiscard]] std::string format_rfc3339_ns(std::uint64_t unix_ns);

}  // namespace panopticon::linux_agent::sensor
