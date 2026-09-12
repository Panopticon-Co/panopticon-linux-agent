#pragma once

#include <cstdint>
#include <filesystem>
#include "panopticon/linux_agent/error.hpp"
#include <string>
#include <string_view>

namespace panopticon::linux_agent {

struct process_identity {
    std::string host_id;
    std::uint32_t pid{};
    std::uint64_t start_time_ticks{};

    [[nodiscard]] bool operator==(const process_identity&) const = default;
};

struct enrolled_identity {
    std::string agent_id;
    std::string host_id;
    std::string bearer_token;
};

// This is an internal durable identity tuple. Canonical `proc_<sha256>` serialization
// waits for the approved shared contract and a production cryptography dependency.
[[nodiscard]] std::string process_identity_key(const process_identity& identity);
[[nodiscard]] bool is_valid_identifier(std::string_view value) noexcept;
[[nodiscard]] result<enrolled_identity> load_enrolled_identity(const std::filesystem::path& path);
[[nodiscard]] result<bool> store_enrolled_identity(const std::filesystem::path& path, const enrolled_identity& identity);

}  // namespace panopticon::linux_agent
