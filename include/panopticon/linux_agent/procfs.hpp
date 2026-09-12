#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/identity.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace panopticon::linux_agent {

struct process_observation {
    process_identity identity;
    std::uint32_t parent_pid{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    char state{};
    std::string executable;
    std::string command_line;
    std::string cgroup;
};

// Reads a bounded snapshot from an injected procfs root. On a non-Linux platform this
// deliberately returns an unsupported error rather than pretending to have host visibility.
[[nodiscard]] result<std::vector<process_observation>> collect_processes(
    const std::filesystem::path& proc_root, std::string host_id, std::size_t maximum_processes);

}  // namespace panopticon::linux_agent
