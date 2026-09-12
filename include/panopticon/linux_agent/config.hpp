#pragma once

#include "panopticon/linux_agent/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace panopticon::linux_agent {

struct agent_config {
    std::string manager_url;
    std::string agent_id;
    std::string host_id;
    std::size_t queue_capacity{};
    std::uint64_t spool_quota_bytes{};
    std::size_t maximum_event_bytes{};
    std::size_t maximum_batch_bytes{};
    bool response_enabled{};
};

[[nodiscard]] result<agent_config> parse_config(std::string_view contents);
[[nodiscard]] result<agent_config> load_config_file(const std::filesystem::path& path);

}  // namespace panopticon::linux_agent
