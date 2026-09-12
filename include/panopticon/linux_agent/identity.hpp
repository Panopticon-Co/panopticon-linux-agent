#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace panopticon::linux_agent {

struct process_identity {
    std::string host_id;
    std::uint32_t pid{};
    std::uint64_t start_time_ticks{};

    [[nodiscard]] bool operator==(const process_identity&) const = default;
};

// This is an internal durable identity tuple. Canonical `proc_<sha256>` serialization
// waits for the approved shared contract and a production cryptography dependency.
[[nodiscard]] std::string process_identity_key(const process_identity& identity);
[[nodiscard]] bool is_valid_identifier(std::string_view value) noexcept;

}  // namespace panopticon::linux_agent
