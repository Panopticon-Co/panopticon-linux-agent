#include "panopticon/linux_agent/config.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/host.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/procfs.hpp"
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
        std::get<panopticon::linux_agent::enrolled_identity>(identity), settings.queue_capacity);
    if (!panopticon::linux_agent::succeeded(delivered)) { std::cerr << "telemetry transport failed\n"; return 1; }
    return 0;
}
