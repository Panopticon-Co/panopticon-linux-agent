#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/procfs.hpp"

#include <utility>
#include <sstream>
#include <charconv>
#include <chrono>
#include <limits>
#include <optional>
#ifdef __linux__
#include <signal.h>
#include <unistd.h>
#endif

namespace panopticon::linux_agent {
namespace {
std::string escape_evidence_json(const std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const unsigned char character : value) {
        switch (character) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (character < 0x20U) {
                    constexpr char hexadecimal[] = "0123456789abcdef";
                    output += "\\u00";
                    output += hexadecimal[(character >> 4U) & 0x0FU];
                    output += hexadecimal[character & 0x0FU];
                } else {
                    output += static_cast<char>(character);
                }
        }
    }
    return output;
}

std::string string_field(const std::string_view payload, const std::string_view key) {
    const auto marker = "\"" + std::string{key} + "\":\"";
    const auto begin = payload.find(marker);
    if (begin == std::string_view::npos) return {};
    const auto value_begin = begin + marker.size();
    const auto end = payload.find('"', value_begin);
    if (end == std::string_view::npos || payload.find('\\', value_begin) < end) return {};
    return std::string{payload.substr(value_begin, end - value_begin)};
}

std::optional<std::uint64_t> unsigned_field(const std::string_view payload, const std::string_view key) {
    const auto marker = "\"" + std::string{key} + "\":";
    const auto begin = payload.find(marker);
    if (begin == std::string_view::npos) return std::nullopt;
    std::uint64_t value{};
    const auto start = payload.data() + begin + marker.size();
    const auto end = payload.data() + payload.size();
    const auto [parsed, issue] = std::from_chars(start, end, value);
    if (issue != std::errc{} || parsed == start || value == 0U) return std::nullopt;
    return value;
}

std::optional<std::chrono::sys_seconds> utc_timestamp(const std::string_view value) {
    if (value.size() < 20U || (value.back() != 'Z' && value.substr(value.size() - 6U) != "+00:00")) return std::nullopt;
    const auto digits = [&](const std::size_t offset, const std::size_t count) -> std::optional<int> {
        int number{};
        for (std::size_t index{}; index < count; ++index) {
            const auto character = value[offset + index];
            if (character < '0' || character > '9') return std::nullopt;
            number = number * 10 + (character - '0');
        }
        return number;
    };
    if (value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':') return std::nullopt;
    const auto year = digits(0U, 4U); const auto month = digits(5U, 2U); const auto day = digits(8U, 2U);
    const auto hour = digits(11U, 2U); const auto minute = digits(14U, 2U); const auto second = digits(17U, 2U);
    if (!year || !month || !day || !hour || !minute || !second || *month < 1 || *month > 12 || *day < 1 || *day > 31 || *hour > 23 || *minute > 59 || *second > 59) return std::nullopt;
    const std::chrono::year_month_day date{std::chrono::year{*year}, std::chrono::month{static_cast<unsigned>(*month)}, std::chrono::day{static_cast<unsigned>(*day)}};
    if (!date.ok()) return std::nullopt;
    return std::chrono::sys_days{date} + std::chrono::hours{*hour} + std::chrono::minutes{*minute} + std::chrono::seconds{*second};
}
}

result<command> parse_command_json(const std::string_view payload) {
    if (payload.size() < 2U || payload.size() > 8192U || payload.front() != '{' || payload.back() != '}' ||
        payload.find('\\') != std::string_view::npos) return error{error_code::invalid_input, "command JSON is invalid"};
    const auto command_id = string_field(payload, "command_id");
    const auto agent_id = string_field(payload, "agent_id");
    const auto host_id = string_field(payload, "host_id");
    const auto schema_version = string_field(payload, "schema_version");
    const auto action = string_field(payload, "action");
    const auto correlation_id = string_field(payload, "correlation_id");
    const auto created_at = utc_timestamp(string_field(payload, "created_at"));
    const auto expiry = utc_timestamp(string_field(payload, "expires_at"));
    if (!is_valid_identifier(command_id) || !is_valid_identifier(agent_id) || !is_valid_identifier(host_id) ||
        !is_valid_identifier(correlation_id) || schema_version != "1" || !created_at || !expiry || *created_at >= *expiry) {
        return error{error_code::invalid_input, "command envelope is invalid"};
    }
    action_type action_type_value{};
    if (action == "KILL_PROCESS") action_type_value = action_type::kill_process;
    else if (action == "COLLECT_PROCESS_INFO") action_type_value = action_type::collect_process_info;
    else if (action == "COLLECT_NETWORK_CONNECTIONS") action_type_value = action_type::collect_network_connections;
    else if (action == "COLLECT_FILE") action_type_value = action_type::collect_file;
    else if (action == "QUARANTINE_FILE") action_type_value = action_type::quarantine_file;
    else return error{error_code::unsupported_action, "command action is not supported by this agent build"};
    const bool is_process_action = action_type_value == action_type::kill_process || action_type_value == action_type::collect_process_info;
    const bool is_file_action = action_type_value == action_type::collect_file || action_type_value == action_type::quarantine_file;
    process_identity target{host_id, 0U, 0U};
    std::string file_path;
    if (is_process_action) {
        const auto pid = unsigned_field(payload, "pid"); const auto start = unsigned_field(payload, "start_time_ticks");
        if (!pid || !start || *pid > std::numeric_limits<std::uint32_t>::max()) return error{error_code::invalid_input, "process command target is invalid"};
        target.pid = static_cast<std::uint32_t>(*pid); target.start_time_ticks = *start;
    } else if (is_file_action) {
        file_path = string_field(payload, "path");
        if (file_path.empty() || file_path.size() > 4096U) return error{error_code::invalid_input, "file command target is invalid"};
    }
    return command{command_id, agent_id, host_id, schema_version, correlation_id, action_type_value, *expiry, target, file_path};
}

result<std::vector<command>> parse_command_poll_response(const std::string_view payload,
                                                          const std::size_t maximum_commands) {
    constexpr std::string_view prefix{"{\"commands\":["};
    if (maximum_commands == 0U || payload.size() < prefix.size() + 2U || payload.rfind(prefix, 0U) != 0U ||
        payload.back() != '}' || payload.find('\\') != std::string_view::npos) {
        return error{error_code::invalid_input, "command poll response is invalid"};
    }
    std::vector<command> commands;
    std::size_t cursor = prefix.size();
    if (payload[cursor] == ']') return commands;
    while (cursor < payload.size() && payload[cursor] != ']') {
        if (commands.size() == maximum_commands || payload[cursor] != '{') {
            return error{error_code::resource_limit, "command poll response exceeds bounds"};
        }
        std::size_t depth{};
        const auto object_begin = cursor;
        do {
            if (payload[cursor] == '{') ++depth;
            else if (payload[cursor] == '}') --depth;
            ++cursor;
        } while (cursor < payload.size() && depth != 0U);
        if (depth != 0U) return error{error_code::invalid_input, "command poll response has unbalanced object"};
        const auto parsed = parse_command_json(payload.substr(object_begin, cursor - object_begin));
        if (!succeeded(parsed)) return std::get<error>(parsed);
        commands.push_back(std::get<command>(parsed));
        if (payload[cursor] == ',') ++cursor;
        else if (payload[cursor] != ']') return error{error_code::invalid_input, "command poll response separator is invalid"};
    }
    if (cursor + 2U != payload.size() || payload[cursor] != ']' || payload[cursor + 1U] != '}') {
        return error{error_code::invalid_input, "command poll response trailing data is invalid"};
    }
    return commands;
}

command_gate::command_gate(std::string agent_id, std::string host_id, std::function<std::chrono::sys_seconds()> clock,
                           replay_ledger* durable_ledger)
    : agent_id_{std::move(agent_id)}, host_id_{std::move(host_id)}, clock_{std::move(clock)}, durable_ledger_{durable_ledger} {}

command_receipt command_gate::validate_and_mark(const command& received) {
    std::lock_guard lock{mutex_};
    if (!is_valid_identifier(received.command_id) || !is_valid_identifier(received.correlation_id) || received.schema_version != "1" || received.agent_id != agent_id_ ||
        received.host_id != host_id_ || received.process_target.host_id != host_id_) {
        return {received.command_id, received.correlation_id, receipt_code::invalid_command, "command identity, target, or schema is invalid"};
    }
    if (received.expires_at <= clock_()) {
        return {received.command_id, received.correlation_id, receipt_code::expired, "command has expired"};
    }
    if (seen_.contains(received.command_id)) {
        return {received.command_id, received.correlation_id, receipt_code::replay_detected, "command was already accepted"};
    }
    if (received.action != action_type::kill_process && received.action != action_type::collect_process_info &&
        received.action != action_type::collect_network_connections && received.action != action_type::collect_file &&
        received.action != action_type::quarantine_file) {
        return {received.command_id, received.correlation_id, receipt_code::unsupported_action, "action is not implemented"};
    }
    if (received.action == action_type::kill_process && is_protected_process(received.process_target.pid)) {
        return {received.command_id, received.correlation_id, receipt_code::target_protected, "target is a protected process"};
    }
    if (durable_ledger_ != nullptr) {
        const auto recorded = durable_ledger_->mark_if_new(received.command_id);
        if (!succeeded(recorded)) return {received.command_id, received.correlation_id, receipt_code::execution_failed, "cannot persist command replay state"};
        if (!std::get<bool>(recorded)) return {received.command_id, received.correlation_id, receipt_code::replay_detected, "command was accepted before restart"};
    }
    seen_.insert(received.command_id);
    return {received.command_id, received.correlation_id, receipt_code::succeeded, "command accepted for a closed action handler"};
}

bool is_protected_process(const std::uint32_t pid) noexcept {
    if (pid <= 1U) return true;
#ifdef __linux__
    return pid == static_cast<std::uint32_t>(getpid());
#else
    return false;
#endif
}

result<std::string> serialize_command_result(const command_receipt& receipt, const std::size_t maximum_bytes) {
    if (!is_valid_identifier(receipt.command_id) || !is_valid_identifier(receipt.correlation_id) || maximum_bytes == 0U) return error{error_code::invalid_input, "receipt is invalid"};
    const auto outcome = receipt.code == receipt_code::succeeded ? "succeeded" :
                         receipt.code == receipt_code::execution_failed ? "failed" : "rejected";
    std::ostringstream output;
    output << "{\"result_id\":\"result-" << receipt.command_id << "\",\"command_id\":\"" << receipt.command_id
           << "\",\"outcome\":\"" << outcome << "\",\"detail\":\"" << static_cast<unsigned int>(receipt.code)
           << "\",\"correlation_id\":\"" << receipt.correlation_id << "\"}";
    auto serialized = output.str();
    if (serialized.size() > maximum_bytes) return error{error_code::resource_limit, "command result exceeds limit"};
    return serialized;
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

result<process_observation> collect_process_info(const std::filesystem::path& proc_root, const process_identity& target) {
    if (target.pid == 0U || target.start_time_ticks == 0U || !is_valid_identifier(target.host_id)) {
        return error{error_code::invalid_input, "process target is invalid"};
    }
    constexpr std::size_t maximum_verification_observations{131072U};
    const auto processes = collect_processes(proc_root, target.host_id, maximum_verification_observations);
    if (!succeeded(processes)) return std::get<error>(processes);
    const auto& observations = std::get<std::vector<process_observation>>(processes);
    const auto found = std::find_if(observations.begin(), observations.end(), [&](const process_observation& observation) {
        return observation.identity == target;
    });
    if (found == observations.end()) return error{error_code::target_mismatch, "process identity no longer matches"};
    return *found;
}

result<std::string> collect_network_evidence(const std::filesystem::path& proc_root, const std::size_t maximum_connections_per_table,
                                              const std::size_t maximum_bytes) {
    if (maximum_connections_per_table == 0U || maximum_bytes == 0U) return error{error_code::invalid_input, "network evidence limits are invalid"};
#ifndef __linux__
    (void)proc_root;
    return error{error_code::unsupported_action, "network collection is available only on Linux"};
#else
    std::vector<network_connection> connections;
    for (const auto& collect : {&collect_tcp_connections, &collect_tcp6_connections, &collect_udp_connections, &collect_udp6_connections}) {
        const auto collected = (*collect)(proc_root, maximum_connections_per_table);
        if (!succeeded(collected)) return std::get<error>(collected);
        const auto& batch = std::get<std::vector<network_connection>>(collected);
        connections.insert(connections.end(), batch.begin(), batch.end());
    }
    std::ostringstream output;
    output << "{\"connections\":[";
    bool first = true;
    for (const auto& connection : connections) {
        if (!first) output << ",";
        first = false;
        output << "{\"protocol\":\"" << escape_evidence_json(connection.protocol) << "\",\"local_address\":\""
               << escape_evidence_json(connection.local_address) << "\",\"local_port\":" << connection.local_port
               << ",\"remote_address\":\"" << escape_evidence_json(connection.remote_address)
               << "\",\"remote_port\":" << connection.remote_port << ",\"state\":\"" << escape_evidence_json(connection.state)
               << "\",\"owner_pid\":" << (connection.owner_pid ? std::to_string(*connection.owner_pid) : "null") << "}";
    }
    output << "]}";
    auto serialized = output.str();
    if (serialized.size() > maximum_bytes) return error{error_code::resource_limit, "network evidence exceeds limit"};
    return serialized;
#endif
}

result<std::string> collect_file_evidence(const std::filesystem::path& allowed_root, const std::filesystem::path& requested_path,
                                          const std::size_t maximum_bytes) {
    if (allowed_root.empty()) return error{error_code::unsupported_action, "file collection root is not configured"};
    // The full file is read (bounded) only long enough to hash it; the raw
    // content is never included in the evidence this function returns.
    constexpr std::size_t maximum_hashed_bytes{16U * 1024U * 1024U};
    const auto collected = collect_regular_file(allowed_root, requested_path, maximum_hashed_bytes);
    if (!succeeded(collected)) return std::get<error>(collected);
    const auto& file = std::get<collected_file>(collected);
    const auto hash = sha256_hex(file.contents);
    std::ostringstream output;
    output << "{\"path\":\"" << escape_evidence_json(file.path.string()) << "\",\"size\":" << file.contents.size()
           << ",\"sha256\":\"" << hash << "\"}";
    auto serialized = output.str();
    if (serialized.size() > maximum_bytes) return error{error_code::resource_limit, "file evidence exceeds limit"};
    return serialized;
}

result<std::string> quarantine_file_and_serialize(const std::filesystem::path& allowed_root, const std::filesystem::path& requested_path,
                                                  const std::filesystem::path& quarantine_root, const std::size_t maximum_bytes) {
    if (allowed_root.empty() || quarantine_root.empty()) return error{error_code::unsupported_action, "quarantine roots are not configured"};
    const auto quarantined = quarantine_regular_file(allowed_root, requested_path, quarantine_root);
    if (!succeeded(quarantined)) return std::get<error>(quarantined);
    const auto& entry = std::get<quarantine_entry>(quarantined);
    std::ostringstream output;
    output << "{\"stored_path\":\"" << escape_evidence_json(entry.stored_path.string()) << "\",\"metadata_path\":\""
           << escape_evidence_json(entry.metadata_path.string()) << "\"}";
    auto serialized = output.str();
    if (serialized.size() > maximum_bytes) return error{error_code::resource_limit, "quarantine result exceeds limit"};
    return serialized;
}

}  // namespace panopticon::linux_agent
