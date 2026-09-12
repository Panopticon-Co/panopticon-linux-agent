#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/procfs.hpp"

#include <utility>
#ifdef __linux__
#include <signal.h>
#endif

namespace panopticon::linux_agent {

command_gate::command_gate(std::string agent_id, std::string host_id, std::function<std::chrono::sys_seconds()> clock)
    : agent_id_{std::move(agent_id)}, host_id_{std::move(host_id)}, clock_{std::move(clock)} {}

command_receipt command_gate::validate_and_mark(const command& received) {
    std::lock_guard lock{mutex_};
    if (!is_valid_identifier(received.command_id) || received.schema_version != "1" || received.agent_id != agent_id_ ||
        received.host_id != host_id_ || received.process_target.host_id != host_id_) {
        return {received.command_id, receipt_code::invalid_command, "command identity, target, or schema is invalid"};
    }
    if (received.expires_at <= clock_()) {
        return {received.command_id, receipt_code::expired, "command has expired"};
    }
    if (!seen_.insert(received.command_id).second) {
        return {received.command_id, receipt_code::replay_detected, "command was already accepted"};
    }
    if (received.action != action_type::kill_process && received.action != action_type::collect_process_info &&
        received.action != action_type::collect_network_connections) {
        return {received.command_id, receipt_code::unsupported_action, "action is not implemented"};
    }
    if (received.action == action_type::kill_process && is_protected_process(received.process_target.pid)) {
        return {received.command_id, receipt_code::target_protected, "target is a protected process"};
    }
    return {received.command_id, receipt_code::succeeded, "command accepted for a closed action handler"};
}

bool is_protected_process(const std::uint32_t pid) noexcept {
    return pid <= 1U;
}

result<bool> terminate_process(const std::filesystem::path& proc_root, const process_identity& target) {
    if (is_protected_process(target.pid) || target.start_time_ticks == 0U || !is_valid_identifier(target.host_id))
        return error{error_code::invalid_input, "process target is protected or invalid"};
#ifndef __linux__
    (void)proc_root;
    return error{error_code::unsupported_action, "process termination is available only on Linux"};
#else
    // Keep verification bounded even when procfs contains adversarially many entries.
    constexpr std::size_t maximum_verification_observations{131072U};
    const auto processes = collect_processes(proc_root, target.host_id, maximum_verification_observations);
    if (!succeeded(processes)) return std::get<error>(processes);
    const auto& observations = std::get<std::vector<process_observation>>(processes);
    const auto found = std::find_if(observations.begin(), observations.end(), [&](const process_observation& observation) {
        return observation.identity == target;
    });
    if (found == observations.end()) return error{error_code::target_mismatch, "process identity no longer matches"};
    if (kill(static_cast<pid_t>(target.pid), SIGTERM) != 0) return error{error_code::io_failure, "SIGTERM was refused"};
    return true;
#endif
}

}  // namespace panopticon::linux_agent
