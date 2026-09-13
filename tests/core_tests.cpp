#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/audit.hpp"
#include "panopticon/linux_agent/config.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/health.hpp"
#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/network.hpp"
#include "panopticon/linux_agent/queue.hpp"
#include "panopticon/linux_agent/procfs.hpp"
#include "panopticon/linux_agent/quarantine.hpp"
#include "panopticon/linux_agent/retry.hpp"
#include "panopticon/linux_agent/replay_ledger.hpp"
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
        "correlation-1",
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
    require(!succeeded(append_audit_record(audit_path, "command_received", "cmd-2", "accepted", 256U, 1U)), "audit file quota must be enforced");
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

void test_collect_regular_file_enforces_bounds_and_root_jail() {
    const auto directory = temporary_directory();
    const auto allowed = directory / "allowed";
    std::filesystem::create_directories(allowed);
    const auto file = allowed / "evidence.txt";
    { std::ofstream output{file}; output << "abc"; }
#ifdef __linux__
    const auto collected = collect_regular_file(allowed, file, 4096U);
    require(succeeded(collected), "regular file within bounds and root should collect");
    require(std::get<collected_file>(collected).contents == "abc", "collected content must be exact");
    require(!succeeded(collect_regular_file(allowed, file, 2U)), "oversized file must be rejected, never truncated");
    const auto outside = directory / "outside.txt";
    { std::ofstream output{outside}; output << "abc"; }
    require(!succeeded(collect_regular_file(allowed, outside, 4096U)), "path outside the allowed root must be rejected");
    const auto link = allowed / "link.txt";
    std::error_code error;
    std::filesystem::create_symlink(file, link, error);
    if (!error) require(!succeeded(collect_regular_file(allowed, link, 4096U)), "symlink must be rejected");
    require(!succeeded(collect_regular_file(allowed, allowed, 4096U)), "a directory must be rejected");
#else
    require(!succeeded(collect_regular_file(allowed, file, 4096U)), "file collection is unsupported off Linux");
#endif
}

void test_collect_file_evidence_hashes_without_leaking_content() {
    const auto directory = temporary_directory();
    const auto allowed = directory / "allowed";
    std::filesystem::create_directories(allowed);
    const auto file = allowed / "sample.txt";
    { std::ofstream output{file}; output << "abc"; }
#ifdef __linux__
    const auto evidence = collect_file_evidence(allowed, file, 4096U);
    require(succeeded(evidence), "bounded evidence collection should succeed");
    const auto& serialized = std::get<std::string>(evidence);
    require(serialized.find("\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"") != std::string::npos,
            "evidence must carry the correct content hash");
    require(serialized.find("\"size\":3") != std::string::npos, "evidence must carry the exact size");
    require(serialized.find("abc") == std::string::npos, "raw file content must never appear in evidence");
#endif
    require(!succeeded(collect_file_evidence({}, file, 4096U)), "an unconfigured collection root must fail closed");
}

void test_quarantine_file_and_serialize_moves_file() {
    const auto directory = temporary_directory();
    const auto allowed = directory / "allowed";
    std::filesystem::create_directories(allowed);
    const auto file = allowed / "sample.txt";
    { std::ofstream output{file}; output << "evidence"; }
    require(!succeeded(quarantine_file_and_serialize({}, file, directory / "quarantine", 4096U)), "unconfigured roots must fail closed");
#ifdef __linux__
    const auto result = quarantine_file_and_serialize(allowed, file, directory / "quarantine", 4096U);
    require(succeeded(result), "quarantine should succeed for an allowed regular file");
    require(!std::filesystem::exists(file), "source file must be moved");
    require(std::get<std::string>(result).find("\"stored_path\":\"") != std::string::npos, "result must report stored path");
    require(std::get<std::string>(result).find("\"metadata_path\":\"") != std::string::npos, "result must report metadata path");
#endif
}

void test_collect_network_evidence_is_bounded() {
    require(!succeeded(collect_network_evidence("/proc", 0U, 4096U)), "zero connection limit must be rejected");
    require(!succeeded(collect_network_evidence("/proc", 16U, 0U)), "zero byte limit must be rejected");
#ifndef __linux__
    require(!succeeded(collect_network_evidence("/proc", 16U, 4096U)), "network collection is unsupported off Linux");
#endif
}

void test_retry_backoff_is_bounded() {
    const retry_policy policy{std::chrono::milliseconds{100}, std::chrono::milliseconds{1000}, 4U};
    require(retry_delay(policy, 0U) == std::chrono::milliseconds{100}, "initial retry delay must be used");
    require(retry_delay(policy, 3U) == std::chrono::milliseconds{800}, "retry delay must grow exponentially");
    require(retry_delay(policy, 4U) == std::chrono::milliseconds{0}, "retry attempts must be bounded");
}

void test_replay_ledger_survives_restart() {
    const auto path = temporary_directory() / "state" / "replay";
    replay_ledger first{path, 2U}; require(succeeded(first.load()), "new replay ledger should load");
    require(std::get<bool>(first.mark_if_new("cmd-1")), "first command must be recorded");
    replay_ledger restarted{path, 2U}; require(succeeded(restarted.load()), "replay ledger should reload");
    require(!std::get<bool>(restarted.mark_if_new("cmd-1")), "persisted command must be rejected as replay");
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
    std::string last_payload;
    std::size_t calls{};
    transport_outcome post_ndjson(const std::string&, const enrolled_identity&, const std::string& payload) override {
        last_payload = payload; ++calls; return outcome;
    }
};

void test_transport_drains_only_acknowledged_spool_entries() {
    const auto directory = temporary_directory(); durable_spool spool{directory, 4096U};
    require(succeeded(spool.append("event")), "spool append should succeed");
    fake_https_client client; const enrolled_identity identity{"agent-1", "host-1", "token"};
    require(std::get<std::size_t>(drain_spool(spool, client, "https://manager", identity, 1U, 1024U)) == 1U, "ack must drain");
    require(succeeded(spool.append("event-one")), "spool append should succeed");
    require(succeeded(spool.append("event-two")), "spool append should succeed");
    require(std::get<std::size_t>(drain_spool(spool, client, "https://manager", identity, 2U, 1024U)) == 2U, "batch ack must drain all records");
    require(client.last_payload == "event-one\nevent-two\n", "batch payload must be bounded NDJSON");
    require(succeeded(spool.append("event")), "spool append should succeed"); client.outcome = transport_outcome::retryable;
    require(std::get<std::size_t>(drain_spool(spool, client, "https://manager", identity, 1U, 1024U)) == 0U, "retry must retain");
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
    const std::string incomplete_transport = std::string{valid} + "identity_path=/var/lib/panopticon/identity\n";
    require(!succeeded(parse_config(incomplete_transport)), "identity transport mode must require a spool path");
    const std::string complete_transport = std::string{valid} + "identity_path=/var/lib/panopticon/identity\n"
        "enrollment_token_path=/run/panopticon/enrollment-token\nspool_path=/var/lib/panopticon/spool\n";
    require(succeeded(parse_config(complete_transport)), "complete persistent transport configuration must parse");
    const auto path = temporary_directory() / "agent.conf";
    { std::ofstream output{path}; output << valid; }
    require(succeeded(load_config_file(path)), "regular configuration file must load");
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

    auto uncorrelated = valid_command();
    uncorrelated.command_id = "cmd-4";
    uncorrelated.correlation_id.clear();
    require(gate.validate_and_mark(uncorrelated).code == receipt_code::invalid_command, "commands without a correlation ID must reject");
}

void test_command_parser_accepts_only_closed_manager_envelopes() {
    constexpr std::string_view command_json{
        "{\"command_id\":\"cmd-1\",\"agent_id\":\"agent-1\",\"action\":\"KILL_PROCESS\","
        "\"expires_at\":\"2030-01-02T03:04:05+00:00\",\"target\":{\"pid\":42,\"start_time_ticks\":99},"
        "\"correlation_id\":\"correlation-1\",\"created_at\":\"2030-01-01T03:04:05+00:00\","
        "\"schema_version\":\"1\",\"host_id\":\"host-1\"}"};
    const auto parsed = parse_command_json(command_json);
    require(succeeded(parsed), "canonical Manager command must parse");
    require(std::get<command>(parsed).process_target.pid == 42U, "parser must preserve typed PID");
    const auto poll = parse_command_poll_response("{\"commands\":[" + std::string{command_json} + "]}", 1U);
    require(succeeded(poll) && std::get<std::vector<command>>(poll).size() == 1U, "bounded command poll must decode canonical commands");
    require(!succeeded(parse_command_json("{\"action\":\"EXECUTE_COMMAND\"}")), "arbitrary execution must never parse");
    require(!succeeded(parse_command_json(std::string{command_json}.replace(0U, 1U, "["))), "non-object command must reject");
}

void test_command_parser_accepts_file_and_isolation_actions() {
    constexpr std::string_view collect_file_json{
        "{\"command_id\":\"cmd-2\",\"agent_id\":\"agent-1\",\"action\":\"COLLECT_FILE\","
        "\"expires_at\":\"2030-01-02T03:04:05+00:00\",\"target\":{\"path\":\"/tmp/evidence.txt\"},"
        "\"correlation_id\":\"correlation-2\",\"created_at\":\"2030-01-01T03:04:05+00:00\","
        "\"schema_version\":\"1\",\"host_id\":\"host-1\"}"};
    const auto parsed_collect = parse_command_json(collect_file_json);
    require(succeeded(parsed_collect), "COLLECT_FILE must parse under the closed action set");
    require(std::get<command>(parsed_collect).file_target_path == "/tmp/evidence.txt", "parser must preserve the requested path");
    require(std::get<command>(parsed_collect).action == action_type::collect_file, "parser must classify the action correctly");

    constexpr std::string_view quarantine_json{
        "{\"command_id\":\"cmd-3\",\"agent_id\":\"agent-1\",\"action\":\"QUARANTINE_FILE\","
        "\"expires_at\":\"2030-01-02T03:04:05+00:00\",\"target\":{\"path\":\"/tmp/evidence.txt\"},"
        "\"correlation_id\":\"correlation-3\",\"created_at\":\"2030-01-01T03:04:05+00:00\","
        "\"schema_version\":\"1\",\"host_id\":\"host-1\"}"};
    require(succeeded(parse_command_json(quarantine_json)), "QUARANTINE_FILE must parse under the closed action set");

    constexpr std::string_view empty_path_json{
        "{\"command_id\":\"cmd-4\",\"agent_id\":\"agent-1\",\"action\":\"COLLECT_FILE\","
        "\"expires_at\":\"2030-01-02T03:04:05+00:00\",\"target\":{\"path\":\"\"},"
        "\"correlation_id\":\"correlation-4\",\"created_at\":\"2030-01-01T03:04:05+00:00\","
        "\"schema_version\":\"1\",\"host_id\":\"host-1\"}"};
    require(!succeeded(parse_command_json(empty_path_json)), "an empty file target path must be rejected");

    constexpr std::string_view isolate_json{
        "{\"command_id\":\"cmd-5\",\"agent_id\":\"agent-1\",\"action\":\"ISOLATE_HOST\","
        "\"expires_at\":\"2030-01-02T03:04:05+00:00\",\"target\":{},"
        "\"correlation_id\":\"correlation-5\",\"created_at\":\"2030-01-01T03:04:05+00:00\","
        "\"schema_version\":\"1\",\"host_id\":\"host-1\"}"};
    const auto parsed_isolate = parse_command_json(isolate_json);
    require(succeeded(parsed_isolate), "ISOLATE_HOST must parse under the closed action set");
    require(std::get<command>(parsed_isolate).action == action_type::isolate_host, "parser must classify the action correctly");

    constexpr std::string_view release_json{
        "{\"command_id\":\"cmd-6\",\"agent_id\":\"agent-1\",\"action\":\"RELEASE_HOST_ISOLATION\","
        "\"expires_at\":\"2030-01-02T03:04:05+00:00\",\"target\":{},"
        "\"correlation_id\":\"correlation-6\",\"created_at\":\"2030-01-01T03:04:05+00:00\","
        "\"schema_version\":\"1\",\"host_id\":\"host-1\"}"};
    require(succeeded(parse_command_json(release_json)), "RELEASE_HOST_ISOLATION must parse under the closed action set");

    require(!succeeded(parse_command_json("{\"action\":\"BLOCK_FIREWALL_IP\"}")),
            "no action beyond the closed 7-tuple may ever parse");

    command_gate gate{"agent-1", "host-1", [] { return std::chrono::sys_seconds{std::chrono::seconds{100}}; }};
    auto collect_command = std::get<command>(parsed_collect);
    require(gate.validate_and_mark(collect_command).code == receipt_code::succeeded, "the gate must accept COLLECT_FILE");
    command_gate isolation_gate{"agent-1", "host-1", [] { return std::chrono::sys_seconds{std::chrono::seconds{100}}; }};
    auto isolate_command = std::get<command>(parsed_isolate);
    require(isolation_gate.validate_and_mark(isolate_command).code == receipt_code::succeeded, "the gate must accept ISOLATE_HOST");
}

void test_isolation_ipc_frame_is_closed_and_bounded() {
    const auto encoded = encode_isolation_request(isolation_opcode::isolate, "cmd-1");
    require(succeeded(encoded), "a valid isolate request must encode");
    require(std::get<std::string>(encoded).size() == kIsolationRequestFrameSize, "the frame must always be the fixed size");
    const auto decoded = decode_isolation_request(std::get<std::string>(encoded));
    require(succeeded(decoded), "an encoded frame must decode");
    require(std::get<std::pair<isolation_opcode, std::string>>(decoded).first == isolation_opcode::isolate, "opcode must round-trip");
    require(std::get<std::pair<isolation_opcode, std::string>>(decoded).second == "cmd-1", "command_id must round-trip");

    require(!succeeded(encode_isolation_request(isolation_opcode::isolate, "bad id with spaces")),
            "an invalid identifier must not encode");
    require(!succeeded(decode_isolation_request("too short")), "a frame of the wrong size must not decode");
    const std::string oversized(kIsolationRequestFrameSize + 64U, 'A');
    require(!succeeded(decode_isolation_request(oversized)), "an oversized frame must not decode");

    std::string tampered_padding(kIsolationRequestFrameSize, '\0');
    tampered_padding[0] = static_cast<char>(static_cast<std::uint8_t>(isolation_opcode::release));
    tampered_padding[5] = 'x';
    tampered_padding[kIsolationRequestFrameSize - 1U] = 'Z';  // non-zero byte after the id's own terminator
    require(!succeeded(decode_isolation_request(tampered_padding)), "non-zero trailing padding must be rejected");

    std::string unknown_opcode(kIsolationRequestFrameSize, '\0');
    unknown_opcode[0] = static_cast<char>(99);
    require(!succeeded(decode_isolation_request(unknown_opcode)), "an opcode outside the closed pair must be rejected");
}

void test_command_gate_uses_durable_replay_ledger() {
    const auto path = temporary_directory() / "state" / "commands";
    replay_ledger first_ledger{path, 8U}; require(succeeded(first_ledger.load()), "ledger must load");
    command_gate first{"agent-1", "host-1", [] { return std::chrono::sys_seconds{std::chrono::seconds{100}}; }, &first_ledger};
    require(first.validate_and_mark(valid_command()).code == receipt_code::succeeded, "first command must be accepted");
    replay_ledger restarted_ledger{path, 8U}; require(succeeded(restarted_ledger.load()), "ledger must reload");
    command_gate restarted{"agent-1", "host-1", [] { return std::chrono::sys_seconds{std::chrono::seconds{100}}; }, &restarted_ledger};
    require(restarted.validate_and_mark(valid_command()).code == receipt_code::replay_detected, "restart replay must be rejected");
}

void test_command_result_is_typed_and_bounded() {
    const auto result = serialize_command_result({"cmd-1", "correlation-1", receipt_code::expired, "ignored"}, 256U);
    require(succeeded(result), "receipt should serialize");
    require(std::get<std::string>(result).find("\"outcome\":\"rejected\"") != std::string::npos, "expired command must be rejected");
    require(std::get<std::string>(result).find("\"correlation_id\":\"correlation-1\"") != std::string::npos, "receipt must preserve correlation");
    require(!succeeded(serialize_command_result({"cmd-1", "correlation-1", receipt_code::succeeded, ""}, 4U)), "receipt must be bounded");
}

void test_collect_process_info_rejects_pid_reuse() {
#ifdef __linux__
    const auto directory = temporary_directory();
    const auto process = directory / "42";
    std::filesystem::create_directories(process);
    { std::ofstream output{process / "stat"}; output << "42 (fixture) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0"; }
    { std::ofstream output{process / "status"}; output << "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"; }
    { std::ofstream output{process / "cmdline", std::ios::binary}; output << "fixture"; }
    std::error_code error;
    std::filesystem::create_symlink("/bin/true", process / "exe", error);
    const auto found = collect_process_info(directory, {"host-1", 42U, 100U});
    require(succeeded(found), "matching process identity should collect");
    require(std::get<process_observation>(found).identity.pid == 42U, "collected process must preserve PID");
    require(!succeeded(collect_process_info(directory, {"host-1", 42U, 101U})), "reused PID must not collect a different process");
#else
    require(!succeeded(collect_process_info("/proc", {"host-1", 42U, 100U})), "collection is unsupported off Linux");
#endif
}

}  // namespace

int main() {
    try {
        test_process_identity_accounts_for_pid_reuse();
        test_enrolled_identity_is_persisted_atomically();
        test_audit_and_health_are_bounded_and_secret_free();
        test_quarantine_moves_regular_file_and_rejects_symlink();
        test_collect_regular_file_enforces_bounds_and_root_jail();
        test_collect_file_evidence_hashes_without_leaking_content();
        test_quarantine_file_and_serialize_moves_file();
        test_collect_network_evidence_is_bounded();
        test_retry_backoff_is_bounded();
        test_replay_ledger_survives_restart();
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
        test_command_parser_accepts_only_closed_manager_envelopes();
        test_command_parser_accepts_file_and_isolation_actions();
        test_isolation_ipc_frame_is_closed_and_bounded();
        test_command_gate_uses_durable_replay_ledger();
        test_command_result_is_typed_and_bounded();
        test_collect_process_info_rejects_pid_reuse();
    } catch (const std::exception& error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
    std::cout << "all core tests passed\n";
    return 0;
}
