#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/file_collection.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/network.hpp"
#include "panopticon/linux_agent/procfs.hpp"
#include "panopticon/linux_agent/quarantine.hpp"
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
    // Populated only for collect_file / quarantine_file; empty otherwise.
    std::string file_target_path;
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
// Re-observes exactly the requested PID/start-time tuple to prevent PID reuse
// from turning a collection command into collection of a different process.
[[nodiscard]] result<process_observation> collect_process_info(const std::filesystem::path& proc_root,
                                                                const process_identity& target);
// Collects bounded TCP/UDP (v4 and v6) connection tables and serializes them
// as a single bounded JSON line. Socket-to-PID attribution is never fabricated
// (see network.hpp); owner_pid is omitted when the kernel doesn't supply it.
[[nodiscard]] result<std::string> collect_network_evidence(const std::filesystem::path& proc_root,
                                                            std::size_t maximum_connections_per_table,
                                                            std::size_t maximum_bytes);
// Reads a bounded regular file under allowed_root and serializes its path,
// size, and SHA-256 as evidence -- never the raw content, which stays
// entirely local to this call and is discarded once hashed.
[[nodiscard]] result<std::string> collect_file_evidence(const std::filesystem::path& allowed_root,
                                                         const std::filesystem::path& requested_path,
                                                         std::size_t maximum_bytes);
// Atomically moves a regular file under allowed_root into quarantine_root and
// serializes the resulting stored/metadata paths as a bounded JSON line.
[[nodiscard]] result<std::string> quarantine_file_and_serialize(const std::filesystem::path& allowed_root,
                                                                 const std::filesystem::path& requested_path,
                                                                 const std::filesystem::path& quarantine_root,
                                                                 std::size_t maximum_bytes);

}  // namespace panopticon::linux_agent
