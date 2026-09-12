#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <cstddef>
#include <filesystem>
#include <string_view>
namespace panopticon::linux_agent {
[[nodiscard]] result<bool> append_audit_record(const std::filesystem::path& path, std::string_view action,
                                                std::string_view correlation_id, std::string_view outcome,
                                                std::size_t maximum_record_bytes);
}  // namespace panopticon::linux_agent
