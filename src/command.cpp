#include "panopticon/linux_agent/command.hpp"

#include <utility>

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

}  // namespace panopticon::linux_agent
