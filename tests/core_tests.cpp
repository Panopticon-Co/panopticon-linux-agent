#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/queue.hpp"
#include "panopticon/linux_agent/procfs.hpp"
#include "panopticon/linux_agent/spool.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using namespace panopticon::linux_agent;

void require(const bool condition, const std::string_view message) {
    if (!condition) {
        throw std::runtime_error{std::string{message}};
    }
}

std::filesystem::path temporary_directory() {
    const auto directory = std::filesystem::temp_directory_path() / "panopticon-linux-agent-core-tests";
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    std::filesystem::create_directories(directory, error);
    if (error) {
        throw std::runtime_error{"cannot create test directory"};
    }
    return directory;
}

command valid_command() {
    return {
        "cmd-1",
        "agent-1",
        "host-1",
        "1",
        action_type::kill_process,
        std::chrono::sys_seconds{std::chrono::seconds{200}},
        {"host-1", 42U, 99U},
    };
}

void test_process_identity_accounts_for_pid_reuse() {
    const process_identity original{"host", 42U, 100U};
    const process_identity replacement{"host", 42U, 101U};
    require(process_identity_key(original) != process_identity_key(replacement), "process identities must include start time");
}

void test_security_event_evicts_low_priority_work() {
    bounded_priority_queue<int> queue{1U};
    require(queue.try_push(event_priority::low, 1), "low priority item should fit");
    require(queue.try_push(event_priority::security, 2), "security event should replace low priority work");
    require(queue.try_pop() == 2, "security event must be dequeued");
    require(queue.metrics().dropped == 1U, "eviction must be counted");
}

void test_spool_recovers_and_acknowledges_only_its_entries() {
    const auto directory = temporary_directory();
    durable_spool spool{directory, 4096U};
    const auto appended = spool.append("{\"event\":\"safe\"}\n");
    require(succeeded(appended), "spool append should succeed");
    const auto entry = std::get<std::filesystem::path>(appended);
    require(succeeded(spool.read(entry)), "spool entry should verify");
    require(std::get<std::string>(spool.read(entry)) == "{\"event\":\"safe\"}\n", "spool preserves payload");
    require(succeeded(spool.acknowledge(entry)), "acknowledgement should delete an owned entry");
    require(std::get<bool>(spool.acknowledge(entry)) == false, "acknowledging an absent entry is idempotent");
    std::error_code error;
    std::filesystem::remove_all(directory, error);
}

void test_spool_quarantines_corrupt_segments() {
    const auto directory = temporary_directory();
    durable_spool spool{directory, 4096U};
    const auto appended = spool.append("payload");
    require(succeeded(appended), "spool append should succeed");
    const auto entry = std::get<std::filesystem::path>(appended);
    {
        std::ofstream corrupt{entry, std::ios::binary | std::ios::trunc};
        corrupt << "not a spool record";
    }
    const auto recovered = spool.recover();
    require(succeeded(recovered), "recovery should complete");
    require(std::get<std::uint64_t>(recovered) == 1U, "corrupt segment must be quarantined");
    require(std::filesystem::exists(directory / "corrupt" / entry.filename()), "corrupt segment must be retained for forensics");
    std::error_code error;
    std::filesystem::remove_all(directory, error);
}

void test_procfs_is_explicitly_unsupported_off_linux() {
#ifndef __linux__
    const auto collected = collect_processes("/proc", "host-1", 10U);
    require(!succeeded(collected), "non-Linux collection must not claim host visibility");
    require(std::get<error>(collected).code == error_code::unsupported_action, "unsupported platform should be explicit");
#endif
}

void test_command_gate_rejects_expiry_replay_and_pid_one() {
    command_gate gate{"agent-1", "host-1", [] { return std::chrono::sys_seconds{std::chrono::seconds{100}}; }};
    const auto first = gate.validate_and_mark(valid_command());
    require(first.code == receipt_code::succeeded, "valid command should be accepted");
    require(gate.validate_and_mark(valid_command()).code == receipt_code::replay_detected, "duplicates must be rejected");

    auto expired = valid_command();
    expired.command_id = "cmd-2";
    expired.expires_at = std::chrono::sys_seconds{std::chrono::seconds{100}};
    require(gate.validate_and_mark(expired).code == receipt_code::expired, "expired commands must be rejected");

    auto protected_target = valid_command();
    protected_target.command_id = "cmd-3";
    protected_target.process_target.pid = 1U;
    require(gate.validate_and_mark(protected_target).code == receipt_code::target_protected, "pid one must be protected");
}

}  // namespace

int main() {
    try {
        test_process_identity_accounts_for_pid_reuse();
        test_security_event_evicts_low_priority_work();
        test_spool_recovers_and_acknowledges_only_its_entries();
        test_spool_quarantines_corrupt_segments();
        test_procfs_is_explicitly_unsupported_off_linux();
        test_command_gate_rejects_expiry_replay_and_pid_one();
    } catch (const std::exception& error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
    std::cout << "all core tests passed\n";
    return 0;
}
