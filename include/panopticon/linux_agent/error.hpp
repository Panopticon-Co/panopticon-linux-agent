#pragma once

#include <string>
#include <variant>

namespace panopticon::linux_agent {

enum class error_code {
    invalid_input,
    resource_limit,
    replay_detected,
    target_mismatch,
    unsupported_action,
    expired,
    io_failure,
    corrupt_data,
};

struct error {
    error_code code;
    std::string message;
};

template <typename value_type>
using result = std::variant<value_type, error>;

template <typename value_type>
[[nodiscard]] bool succeeded(const result<value_type>& value) noexcept {
    return std::holds_alternative<value_type>(value);
}

}  // namespace panopticon::linux_agent
