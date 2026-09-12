#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <cstdint>
#include <string>
namespace panopticon::linux_agent {
struct host_observation { std::string hostname; std::string kernel_release; std::string machine; std::string boot_id; std::uint64_t uptime_seconds{}; };
[[nodiscard]] result<host_observation> collect_host_observation();
}  // namespace panopticon::linux_agent
