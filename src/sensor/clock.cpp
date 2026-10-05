#include "panopticon/linux_agent/sensor/clock.hpp"

#include <array>
#include <cstdio>
#include <ctime>
#ifdef __linux__
#include <unistd.h>
#endif

namespace panopticon::linux_agent::sensor {
namespace {

std::uint64_t read_clock(const clockid_t id) noexcept {
    timespec value{};
    if (clock_gettime(id, &value) != 0) return 0U;
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL + static_cast<std::uint64_t>(value.tv_nsec);
}

std::uint64_t apply(const std::uint64_t value, const std::int64_t offset) noexcept {
    const auto adjusted = static_cast<std::int64_t>(value) + offset;
    return adjusted < 0 ? 0U : static_cast<std::uint64_t>(adjusted);
}

}  // namespace

clock_domain::clock_domain() {
#ifdef __linux__
    const auto ticks = sysconf(_SC_CLK_TCK);
    if (ticks > 0) ticks_per_second_ = static_cast<std::uint64_t>(ticks);
#endif
    resample();
}

void clock_domain::resample() {
    // Bracket the realtime read between two reads of the other clock to bound the error.
    const auto boot_before = now_boottime_ns();
    const auto unix_now = now_unix_ns();
    const auto boot_after = now_boottime_ns();
    boot_offset_ns_.store(static_cast<std::int64_t>(unix_now) - static_cast<std::int64_t>(boot_before + (boot_after - boot_before) / 2U),
                          std::memory_order_relaxed);
    const auto mono_before = now_monotonic_ns();
    const auto unix_again = now_unix_ns();
    const auto mono_after = now_monotonic_ns();
    monotonic_offset_ns_.store(static_cast<std::int64_t>(unix_again) - static_cast<std::int64_t>(mono_before + (mono_after - mono_before) / 2U),
                               std::memory_order_relaxed);
}

std::uint64_t clock_domain::boottime_to_unix_ns(const std::uint64_t boottime_ns) const noexcept {
    return apply(boottime_ns, boot_offset_ns_.load(std::memory_order_relaxed));
}

std::uint64_t clock_domain::monotonic_to_unix_ns(const std::uint64_t monotonic_ns) const noexcept {
    return apply(monotonic_ns, monotonic_offset_ns_.load(std::memory_order_relaxed));
}

std::uint64_t clock_domain::ticks_to_unix_ns(const std::uint64_t ticks_since_boot) const noexcept {
    return boottime_to_unix_ns(ticks_since_boot * (1'000'000'000ULL / ticks_per_second_));
}

std::uint64_t clock_domain::unix_ns_to_ticks(const std::uint64_t unix_ns) const noexcept {
    return apply(unix_ns, -boot_offset_ns_.load(std::memory_order_relaxed)) / (1'000'000'000ULL / ticks_per_second_);
}

std::uint64_t clock_domain::now_unix_ns() noexcept { return read_clock(CLOCK_REALTIME); }
std::uint64_t clock_domain::now_boottime_ns() noexcept {
#ifdef CLOCK_BOOTTIME
    return read_clock(CLOCK_BOOTTIME);
#else
    return read_clock(CLOCK_MONOTONIC);
#endif
}
std::uint64_t clock_domain::now_monotonic_ns() noexcept { return read_clock(CLOCK_MONOTONIC); }

std::string format_rfc3339_ns(const std::uint64_t unix_ns) {
    const auto seconds = static_cast<std::time_t>(unix_ns / 1'000'000'000ULL);
    const auto nanoseconds = static_cast<unsigned long>(unix_ns % 1'000'000'000ULL);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &seconds);
#else
    gmtime_r(&seconds, &utc);
#endif
    std::array<char, 40> buffer{};
    const auto written = std::snprintf(buffer.data(), buffer.size(), "%04d-%02d-%02dT%02d:%02d:%02d.%09luZ",
        utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour, utc.tm_min, utc.tm_sec, nanoseconds);
    return written > 0 ? std::string{buffer.data(), static_cast<std::size_t>(written)} : std::string{};
}

}  // namespace panopticon::linux_agent::sensor
