#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <cstddef>
#include <filesystem>
#include <string>
namespace panopticon::linux_agent {
struct collected_file { std::filesystem::path path; std::string contents; };
[[nodiscard]] result<collected_file> collect_regular_file(const std::filesystem::path& allowed_root,
                                                           const std::filesystem::path& requested_path,
                                                           std::size_t maximum_bytes);
}  // namespace panopticon::linux_agent
