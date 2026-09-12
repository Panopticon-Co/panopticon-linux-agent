#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <filesystem>
#include <string>
namespace panopticon::linux_agent {
struct quarantine_entry { std::filesystem::path stored_path; std::filesystem::path metadata_path; };
[[nodiscard]] result<quarantine_entry> quarantine_regular_file(const std::filesystem::path& allowed_root,
                                                                const std::filesystem::path& source,
                                                                const std::filesystem::path& quarantine_root);
}  // namespace panopticon::linux_agent
