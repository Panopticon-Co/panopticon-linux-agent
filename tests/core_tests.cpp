#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/audit.hpp"
#include "panopticon/linux_agent/config.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/health.hpp"
#include "panopticon/linux_agent/network.hpp"
#include "panopticon/linux_agent/queue.hpp"
#include "panopticon/linux_agent/procfs.hpp"
#include "panopticon/linux_agent/quarantine.hpp"
#include "panopticon/linux_agent/spool.hpp"
#include "panopticon/linux_agent/transport.hpp"

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

void test_enrolled_identity_is_persisted_atomically() {
    const auto path = temporary_directory() / "identity" / "agent.token";
    const enrolled_identity expected{"agent-1", "host-1", "opaque-test-token"};
    require(succeeded(store_enrolled_identity(path, expected)), "identity should persist");
    const auto loaded = load_enrolled_identity(path);
    require(succeeded(loaded), "identity should reload");
    require(std::get<enrolled_identity>(loaded).bearer_token == expected.bearer_token, "identity token must round-trip");
}

void test_audit_and_health_are_bounded_and_secret_free() {
    const auto audit_path = temporary_directory() / "audit" / "events.ndjson";
    require(succeeded(append_audit_record(audit_path, "command_received", "cmd-1", "accepted", 256U)), "audit should persist");
    require(!succeeded(append_audit_record(audit_path, "bad space", "cmd-1", "accepted", 256U)), "audit must reject malformed identifiers");
    const auto health = serialize_health_ndjson({true, 42U, 3U, "online", "secret-token"}, 256U);
    require(health.find("secret-token") == std::string::npos, "health output must not disclose errors containing secrets");
    require(serialize_health_ndjson({true, 42U, 3U, "online", ""}, 8U).empty(), "health must observe output limit");
}

void test_quarantine_moves_regular_file_and_rejects_symlink() {
    const auto directory = temporary_directory();
    const auto source = directory / "allowed" / "sample.txt";
    std::filesystem::create_directories(source.parent_path());
    { std::ofstream output{source}; output << "evidence"; }
    const auto quarantined = quarantine_regular_file(directory / "allowed", source, directory / "quarantine");
    require(succeeded(quarantined), "regular allowed file should quarantine");
    require(!std::filesystem::exists(source), "source must be moved");
    require(std::filesystem::exists(std::get<quarantine_entry>(quarantined).metadata_path), "metadata must exist");
    const auto link = directory / "allowed" / "link";
    std::error_code error;
    std::filesystem::create_symlink(std::get<quarantine_entry>(quarantined).stored_path, link, error);
    if (!error) require(!succeeded(quarantine_regular_file(directory / "allowed", link, directory / "quarantine")), "symlink must be rejected");
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

class fake_https_client final : public https_client {
public:
    transport_outcome outcome{transport_outcome::acknowledged};
    transport_outcome post_ndjson(const std::string&, const enrolled_identity&, const std::string&) override { return outcome; }
};

void test_transport_drains_only_acknowledged_spool_entries() {
    const auto directory = temporary_directory(); durable_spool spool{directory, 4096U};
    require(succeeded(spool.append("event")), "spool append should succeed");
    fake_https_client client; const enrolled_identity identity{"agent-1", "host-1", "token"};
    require(std::get<std::size_t>(drain_spool(spool, client, "https://manager", identity, 1U)) == 1U, "ack must drain");
    require(succeeded(spool.append("event")), "spool append should succeed"); client.outcome = transport_outcome::retryable;
    require(std::get<std::size_t>(drain_spool(spool, client, "https://manager", identity, 1U)) == 0U, "retry must retain");
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

void test_internal_normalization_escapes_and_bounds_ndjson() {
    process_observation observation{{"host-1", 42U, 99U}, 1U, 1000U, 1000U, 'R', "/bin/test", "test\nargument", ""};
    const agent_context context{"agent-1", "host-1", "test-host", "Linux", "6.8"};
    const auto normalized = normalize_process(std::move(observation), context, std::chrono::sys_seconds{std::chrono::seconds{100}});
    require(succeeded(normalized), "valid observation should normalize");
    const auto serialized = serialize_ndjson(std::get<internal_process_event>(normalized), 4096U);
    require(succeeded(serialized), "normalized event should serialize within limit");
    require(std::get<std::string>(serialized).find("test\\nargument") != std::string::npos, "control characters must be JSON escaped");
    require(!succeeded(serialize_ndjson(std::get<internal_process_event>(normalized), 8U)), "oversized events must be rejected");
    const auto canonical = serialize_canonical_process_ndjson(std::get<internal_process_event>(normalized), 4096U);
    require(succeeded(canonical), "canonical process event should serialize");
    const auto& canonical_text = std::get<std::string>(canonical);
    require(canonical_text.find("\"schema_version\":\"0.4\"") != std::string::npos, "canonical schema version must be emitted");
    require(canonical_text.find("\"kind\":\"linux_procfs\"") != std::string::npos, "canonical Linux source kind must be emitted");
}

void test_proc_net_tcp_parser_is_bounded_and_decodes_endpoints() {
    constexpr std::string_view table{
        "  sl  local_address rem_address   st\n"
        "   0: 0100007F:1F90 020000C0:01BB 01\n"
        "   1: 00000000:0016 00000000:0000 0A\n"};
    const auto parsed = parse_proc_net_tcp(table, 1U);
    require(succeeded(parsed), "TCP table should parse");
    const auto& connection = std::get<std::vector<network_connection>>(parsed).front();
    require(connection.local_address == "127.0.0.1" && connection.local_port == 8080U, "local endpoint must decode");
    require(connection.remote_address == "192.0.0.2" && connection.remote_port == 443U, "remote endpoint must decode");
    require(connection.state == "established", "TCP state must normalize");
}

void test_proc_net_udp_and_ipv6_parsers_are_bounded_and_typed() {
    constexpr std::string_view udp_table{
        "  sl  local_address rem_address   st\n"
        "   0: 00000000:0035 00000000:0000 07\n"};
    const auto udp = parse_proc_net_udp(udp_table, 1U);
    require(succeeded(udp), "UDP table should parse");
    require(std::get<std::vector<network_connection>>(udp).front().protocol == "udp", "UDP protocol must be typed");
    constexpr std::string_view tcp6_table{
        "  sl  local_address                         remote_address                        st\n"
        "   0: 0000000000000000FFFF00000100007F:01BB 00000000000000000000000000000000:0000 0A\n"};
    const auto tcp6 = parse_proc_net_tcp6(tcp6_table, 1U);
    require(succeeded(tcp6), "TCP6 table should parse");
    const auto& connection = std::get<std::vector<network_connection>>(tcp6).front();
    require(connection.protocol == "tcp6" && connection.local_address == "0:0:0:0:0:ffff:7f00:1",
            "TCP6 endpoint must decode procfs word order");
    require(connection.state == "listen", "TCP6 state must normalize");
    require(!succeeded(parse_proc_net_udp6(udp_table, 0U)), "all network tables must reject zero limits");
}

void test_configuration_rejects_unknown_and_insecure_values() {
    constexpr std::string_view valid{
        "manager_url=https://manager.example\nagent_id=agent-1\nhost_id=host-1\nqueue_capacity=10\nspool_quota_bytes=4096\nmaximum_event_bytes=256\nmaximum_batch_bytes=512\nresponse_enabled=false\n"};
    require(succeeded(parse_config(valid)), "complete HTTPS configuration must parse");
    require(!succeeded(parse_config("manager_url=http://bad\n")), "incomplete insecure configuration must fail");
    const std::string unknown_key = std::string{valid} + "unknown=true\n";
    require(!succeeded(parse_config(unknown_key)), "unknown key must fail");
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
        test_enrolled_identity_is_persisted_atomically();
        test_audit_and_health_are_bounded_and_secret_free();
        test_quarantine_moves_regular_file_and_rejects_symlink();
        test_security_event_evicts_low_priority_work();
        test_spool_recovers_and_acknowledges_only_its_entries();
        test_transport_drains_only_acknowledged_spool_entries();
        test_spool_quarantines_corrupt_segments();
        test_procfs_is_explicitly_unsupported_off_linux();
        test_internal_normalization_escapes_and_bounds_ndjson();
        test_proc_net_tcp_parser_is_bounded_and_decodes_endpoints();
        test_proc_net_udp_and_ipv6_parsers_are_bounded_and_typed();
        test_configuration_rejects_unknown_and_insecure_values();
        test_command_gate_rejects_expiry_replay_and_pid_one();
    } catch (const std::exception& error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
    std::cout << "all core tests passed\n";
    return 0;
}
