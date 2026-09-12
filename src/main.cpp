#include "panopticon/linux_agent/config.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/host.hpp"
#include "panopticon/linux_agent/procfs.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

int main(int argc, char** argv) {
    if (argc != 2) { std::cerr << "usage: panopticon-linux-agent <strict-config-path>\n"; return 2; }
    std::ifstream input{argv[1]}; std::ostringstream contents; contents << input.rdbuf();
    const auto config = panopticon::linux_agent::parse_config(contents.str());
    if (!panopticon::linux_agent::succeeded(config)) { std::cerr << "invalid agent configuration\n"; return 2; }
    const auto host = panopticon::linux_agent::collect_host_observation();
    if (!panopticon::linux_agent::succeeded(host)) { std::cerr << "host collection unavailable\n"; return 1; }
    const auto& settings = std::get<panopticon::linux_agent::agent_config>(config);
    const auto& host_info = std::get<panopticon::linux_agent::host_observation>(host);
    const auto processes = panopticon::linux_agent::collect_processes("/proc", settings.host_id, settings.queue_capacity);
    if (!panopticon::linux_agent::succeeded(processes)) { std::cerr << "process collection unavailable\n"; return 1; }
    const panopticon::linux_agent::agent_context context{settings.agent_id, settings.host_id, host_info.hostname, "Linux", host_info.kernel_release};
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    for (auto observation : std::get<std::vector<panopticon::linux_agent::process_observation>>(processes)) {
        const auto normalized = panopticon::linux_agent::normalize_process(std::move(observation), context, now);
        if (!panopticon::linux_agent::succeeded(normalized)) continue;
        const auto serialized = panopticon::linux_agent::serialize_canonical_process_ndjson(
            std::get<panopticon::linux_agent::internal_process_event>(normalized), settings.maximum_event_bytes);
        if (panopticon::linux_agent::succeeded(serialized)) std::cout << std::get<std::string>(serialized);
    }
    return 0;
}
