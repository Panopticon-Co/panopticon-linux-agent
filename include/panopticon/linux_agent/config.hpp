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
    // Transport state is opt-in to retain the one-shot collector mode used by
    // diagnostics. When identity_path is set, spool_path is mandatory.
    std::string identity_path;
    std::string enrollment_token_path;
    std::string spool_path;
};

[[nodiscard]] result<agent_config> parse_config(std::string_view contents);
[[nodiscard]] result<agent_config> load_config_file(const std::filesystem::path& path);

}  // namespace panopticon::linux_agent
