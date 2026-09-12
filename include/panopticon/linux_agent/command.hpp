#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/replay_ledger.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent {

enum class action_type : std::uint8_t {
    kill_process,
    collect_process_info,
    collect_network_connections,
    collect_file,
    quarantine_file,
    isolate_host,
    release_host_isolation,
};

struct command {
    std::string command_id;
    std::string agent_id;
    std::string host_id;
    std::string schema_version;
    std::string correlation_id;
    action_type action;
    std::chrono::sys_seconds expires_at;
    process_identity process_target;
};

enum class receipt_code : std::uint8_t {
    succeeded,
    invalid_command,
    expired,
    replay_detected,
    target_mismatch,
    target_protected,
    unsupported_action,
    execution_failed,
};

struct command_receipt {
    std::string command_id;
    std::string correlation_id;
    receipt_code code;
    std::string summary;
};

// Decodes only the Manager's schema-1 closed command envelope. It intentionally
// rejects escapes, unknown action names, local times, and unconstrained targets.
[[nodiscard]] result<command> parse_command_json(std::string_view payload);
[[nodiscard]] result<std::vector<command>> parse_command_poll_response(std::string_view payload,
                                                                         std::size_t maximum_commands);
[[nodiscard]] result<std::string> serialize_command_result(const command_receipt& receipt, std::size_t maximum_bytes);

class command_gate {
public:
    command_gate(std::string agent_id, std::string host_id, std::function<std::chrono::sys_seconds()> clock,
                 replay_ledger* durable_ledger = nullptr);

    [[nodiscard]] command_receipt validate_and_mark(const command& command);

private:
    std::string agent_id_;
    std::string host_id_;
    std::function<std::chrono::sys_seconds()> clock_;
    replay_ledger* durable_ledger_;
    std::mutex mutex_;
    std::set<std::string> seen_;
};

[[nodiscard]] bool is_protected_process(std::uint32_t pid) noexcept;
// Sends SIGTERM only after a fresh procfs observation proves the PID/start-time tuple.
[[nodiscard]] result<bool> terminate_process(const std::filesystem::path& proc_root, const process_identity& target);

}  // namespace panopticon::linux_agent
