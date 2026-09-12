#pragma once
#include <algorithm>
#include <chrono>
#include <cstdint>
namespace panopticon::linux_agent {
struct retry_policy { std::chrono::milliseconds initial{1000}; std::chrono::milliseconds maximum{300000}; std::uint32_t maximum_attempts{8}; };
[[nodiscard]] inline std::chrono::milliseconds retry_delay(const retry_policy& policy, const std::uint32_t attempt) {
    if (attempt >= policy.maximum_attempts || policy.initial.count() <= 0 || policy.maximum < policy.initial) return std::chrono::milliseconds{0};
    auto delay = policy.initial;
    for (std::uint32_t index = 0U; index < attempt && delay < policy.maximum / 2; ++index) delay *= 2;
    return std::min(delay, policy.maximum);
}
}  // namespace panopticon::linux_agent
