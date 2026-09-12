#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/procfs.hpp"

#include <chrono>
#include <cstddef>
#include <string>

namespace panopticon::linux_agent {

struct agent_context {
    std::string agent_id;
    std::string host_id;
    std::string hostname;
    std::string os_name;
    std::string kernel_release;
    std::string agent_version{"0.1.0"};
};

struct internal_process_event {
    std::string schema_version{"linux-internal-1"};
    std::string event_id;
    std::chrono::sys_seconds observed_at;
    agent_context context;
    process_observation process;
};

[[nodiscard]] result<internal_process_event> normalize_process(
    process_observation observation, agent_context context, std::chrono::sys_seconds observed_at);
[[nodiscard]] result<std::string> serialize_ndjson(const internal_process_event& event, std::size_t maximum_bytes);
// Converts an internal process snapshot to the shared schema 0.4 contract.
// The caller remains responsible for transport; this adapter has no Manager dependency.
[[nodiscard]] result<std::string> serialize_canonical_process_ndjson(
    const internal_process_event& event, std::size_t maximum_bytes);

}  // namespace panopticon::linux_agent
