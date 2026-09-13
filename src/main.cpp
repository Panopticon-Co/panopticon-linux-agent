#include "panopticon/linux_agent/config.hpp"
#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/host.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/procfs.hpp"
#include "panopticon/linux_agent/replay_ledger.hpp"
#include "panopticon/linux_agent/spool.hpp"
#include "panopticon/linux_agent/transport.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#ifdef __linux__
#include <sys/stat.h>
#endif

namespace {
panopticon::linux_agent::result<std::string> load_bootstrap_token(const std::filesystem::path& path) {
#ifdef __linux__
    struct stat details {};
    if (stat(path.c_str(), &details) != 0 || !S_ISREG(details.st_mode) || (details.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return panopticon::linux_agent::error{panopticon::linux_agent::error_code::invalid_input,
                                               "enrollment token must be a private regular file"};
    }
#endif
    std::ifstream input{path};
    std::string token;
    std::string unexpected;
    if (!input || !std::getline(input, token) || std::getline(input, unexpected) || token.empty() || token.size() > 512U) {
        return panopticon::linux_agent::error{panopticon::linux_agent::error_code::invalid_input,
                                               "enrollment token is absent or invalid"};
    }
    return token;
}
}

int main(int argc, char** argv) {
    if (argc != 2) { std::cerr << "usage: panopticon-linux-agent <strict-config-path>\n"; return 2; }
    const auto config = panopticon::linux_agent::load_config_file(argv[1]);
    if (!panopticon::linux_agent::succeeded(config)) { std::cerr << "invalid agent configuration\n"; return 2; }
    const auto host = panopticon::linux_agent::collect_host_observation();
    if (!panopticon::linux_agent::succeeded(host)) { std::cerr << "host collection unavailable\n"; return 1; }
    const auto& settings = std::get<panopticon::linux_agent::agent_config>(config);
    const auto& host_info = std::get<panopticon::linux_agent::host_observation>(host);
    const auto processes = panopticon::linux_agent::collect_processes("/proc", settings.host_id, settings.queue_capacity);
    if (!panopticon::linux_agent::succeeded(processes)) { std::cerr << "process collection unavailable\n"; return 1; }
    const panopticon::linux_agent::agent_context context{settings.agent_id, settings.host_id, host_info.hostname, "Linux", host_info.kernel_release};
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    if (settings.identity_path.empty()) {
        for (auto observation : std::get<std::vector<panopticon::linux_agent::process_observation>>(processes)) {
            const auto normalized = panopticon::linux_agent::normalize_process(std::move(observation), context, now);
            if (!panopticon::linux_agent::succeeded(normalized)) continue;
            const auto serialized = panopticon::linux_agent::serialize_canonical_process_ndjson(
                std::get<panopticon::linux_agent::internal_process_event>(normalized), settings.maximum_event_bytes);
            if (panopticon::linux_agent::succeeded(serialized)) std::cout << std::get<std::string>(serialized);
        }
        return 0;
    }
    auto identity = panopticon::linux_agent::load_enrolled_identity(settings.identity_path);
    panopticon::linux_agent::curl_https_client client;
    if (!panopticon::linux_agent::succeeded(identity)) {
        if (settings.enrollment_token_path.empty()) { std::cerr << "enrolled identity unavailable\n"; return 1; }
        const auto token = load_bootstrap_token(settings.enrollment_token_path);
        if (!panopticon::linux_agent::succeeded(token)) { std::cerr << "enrollment credential unavailable\n"; return 1; }
        identity = client.enroll(settings.manager_url, settings.agent_id, settings.host_id, std::get<std::string>(token));
        if (!panopticon::linux_agent::succeeded(identity) ||
            !panopticon::linux_agent::succeeded(panopticon::linux_agent::store_enrolled_identity(settings.identity_path, std::get<panopticon::linux_agent::enrolled_identity>(identity)))) {
            std::cerr << "agent enrollment failed\n"; return 1;
        }
    }
    panopticon::linux_agent::durable_spool spool{settings.spool_path, settings.spool_quota_bytes};
    if (!panopticon::linux_agent::succeeded(spool.recover())) { std::cerr << "spool recovery failed\n"; return 1; }
    for (auto observation : std::get<std::vector<panopticon::linux_agent::process_observation>>(processes)) {
        const auto normalized = panopticon::linux_agent::normalize_process(std::move(observation), context, now);
        if (!panopticon::linux_agent::succeeded(normalized)) continue;
        const auto serialized = panopticon::linux_agent::serialize_canonical_process_ndjson(
            std::get<panopticon::linux_agent::internal_process_event>(normalized), settings.maximum_event_bytes);
        if (panopticon::linux_agent::succeeded(serialized) && !panopticon::linux_agent::succeeded(spool.append(std::get<std::string>(serialized)))) {
            std::cerr << "spool quota exhausted\n"; return 1;
        }
    }
    const auto delivered = panopticon::linux_agent::drain_spool(spool, client, settings.manager_url + "/api/v1/ingest",
        std::get<panopticon::linux_agent::enrolled_identity>(identity), settings.queue_capacity, settings.maximum_batch_bytes);
    if (!panopticon::linux_agent::succeeded(delivered)) { std::cerr << "telemetry transport failed\n"; return 1; }
    if (settings.response_enabled) {
        panopticon::linux_agent::replay_ledger ledger{std::filesystem::path{settings.spool_path} / "commands", settings.queue_capacity};
        const auto poll = client.poll_commands(settings.manager_url, std::get<panopticon::linux_agent::enrolled_identity>(identity));
        if (panopticon::linux_agent::succeeded(poll) && panopticon::linux_agent::succeeded(ledger.load())) {
            const auto commands = panopticon::linux_agent::parse_command_poll_response(std::get<std::string>(poll), settings.queue_capacity);
            if (panopticon::linux_agent::succeeded(commands)) for (const auto& received : std::get<std::vector<panopticon::linux_agent::command>>(commands)) {
                panopticon::linux_agent::command_gate gate{settings.agent_id, settings.host_id, [] { return std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()); }, &ledger};
                auto receipt = gate.validate_and_mark(received);
                if (receipt.code == panopticon::linux_agent::receipt_code::succeeded && received.action == panopticon::linux_agent::action_type::kill_process) {
                    if (!panopticon::linux_agent::succeeded(panopticon::linux_agent::terminate_process("/proc", received.process_target))) receipt.code = panopticon::linux_agent::receipt_code::execution_failed;
                } else if (receipt.code == panopticon::linux_agent::receipt_code::succeeded && received.action == panopticon::linux_agent::action_type::collect_process_info) {
                    const auto observed = panopticon::linux_agent::collect_process_info("/proc", received.process_target);
                    if (!panopticon::linux_agent::succeeded(observed)) {
                        receipt.code = panopticon::linux_agent::receipt_code::target_mismatch;
                        receipt.summary = "process identity could not be re-observed";
                    } else {
                        const auto normalized = panopticon::linux_agent::normalize_process(std::get<panopticon::linux_agent::process_observation>(observed), context,
                            std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
                        const auto serialized = panopticon::linux_agent::succeeded(normalized)
                            ? panopticon::linux_agent::serialize_canonical_process_ndjson(std::get<panopticon::linux_agent::internal_process_event>(normalized), settings.maximum_event_bytes)
                            : panopticon::linux_agent::result<std::string>{std::get<panopticon::linux_agent::error>(normalized)};
                        if (!panopticon::linux_agent::succeeded(serialized) || !panopticon::linux_agent::succeeded(spool.append(std::get<std::string>(serialized)))) {
                            receipt.code = panopticon::linux_agent::receipt_code::execution_failed;
                            receipt.summary = "process observation could not be durably queued";
                        }
                    }
                } else if (receipt.code == panopticon::linux_agent::receipt_code::succeeded && received.action == panopticon::linux_agent::action_type::collect_network_connections) {
                    const auto evidence = panopticon::linux_agent::collect_network_evidence("/proc", settings.queue_capacity, settings.maximum_event_bytes);
                    if (!panopticon::linux_agent::succeeded(evidence) || !panopticon::linux_agent::succeeded(spool.append(std::get<std::string>(evidence)))) {
                        receipt.code = panopticon::linux_agent::receipt_code::execution_failed;
                        receipt.summary = "network evidence could not be durably queued";
                    }
                } else if (receipt.code == panopticon::linux_agent::receipt_code::succeeded && received.action == panopticon::linux_agent::action_type::collect_file) {
                    const auto evidence = panopticon::linux_agent::collect_file_evidence(settings.file_collection_root, received.file_target_path, settings.maximum_event_bytes);
                    if (!panopticon::linux_agent::succeeded(evidence)) {
                        receipt.code = panopticon::linux_agent::receipt_code::target_mismatch;
                        receipt.summary = "requested file could not be safely collected";
                    } else if (!panopticon::linux_agent::succeeded(spool.append(std::get<std::string>(evidence)))) {
                        receipt.code = panopticon::linux_agent::receipt_code::execution_failed;
                        receipt.summary = "file evidence could not be durably queued";
                    }
                } else if (receipt.code == panopticon::linux_agent::receipt_code::succeeded && received.action == panopticon::linux_agent::action_type::quarantine_file) {
                    const auto quarantined = panopticon::linux_agent::quarantine_file_and_serialize(settings.file_collection_root, received.file_target_path,
                        settings.quarantine_root, settings.maximum_event_bytes);
                    if (!panopticon::linux_agent::succeeded(quarantined)) {
                        receipt.code = panopticon::linux_agent::receipt_code::target_mismatch;
                        receipt.summary = "requested file could not be safely quarantined";
                    } else if (!panopticon::linux_agent::succeeded(spool.append(std::get<std::string>(quarantined)))) {
                        receipt.code = panopticon::linux_agent::receipt_code::execution_failed;
                        receipt.summary = "quarantine result could not be durably queued";
                    }
                } else if (receipt.code == panopticon::linux_agent::receipt_code::succeeded &&
                           (received.action == panopticon::linux_agent::action_type::isolate_host ||
                            received.action == panopticon::linux_agent::action_type::release_host_isolation)) {
                    const auto opcode = received.action == panopticon::linux_agent::action_type::isolate_host
                        ? panopticon::linux_agent::isolation_opcode::isolate
                        : panopticon::linux_agent::isolation_opcode::release;
                    const auto isolated = settings.isolation_socket_path.empty()
                        ? panopticon::linux_agent::result<bool>{panopticon::linux_agent::error{panopticon::linux_agent::error_code::unsupported_action, "isolation helper is not configured"}}
                        : panopticon::linux_agent::request_isolation(settings.isolation_socket_path, opcode, received.command_id);
                    if (!panopticon::linux_agent::succeeded(isolated) || !std::get<bool>(isolated)) {
                        receipt.code = panopticon::linux_agent::receipt_code::execution_failed;
                        receipt.summary = "isolation helper rejected or was unreachable for this request";
                    }
                } else if (receipt.code == panopticon::linux_agent::receipt_code::succeeded) {
                    receipt.code = panopticon::linux_agent::receipt_code::unsupported_action;
                    receipt.summary = "action handler is not available in this agent build";
                }
                const auto result = panopticon::linux_agent::serialize_command_result(receipt, settings.maximum_event_bytes);
                if (panopticon::linux_agent::succeeded(result)) (void)client.submit_command_result(settings.manager_url, std::get<panopticon::linux_agent::enrolled_identity>(identity), std::get<std::string>(result));
            }
        }
    }
    return 0;
}
