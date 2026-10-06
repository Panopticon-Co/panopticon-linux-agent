// panopticon-sensord: the resident Linux endpoint sensor (ADR 005).
//
//   panopticon-sensord --config /etc/panopticon/sensord.conf
//   panopticon-sensord --stdout [--duration SECONDS]     development: NDJSON on stdout, no WAL
//   panopticon-sensord --probe                           print provider availability and exit
//   panopticon-sensord ... --no-ebpf                     skip the eBPF provider (fallback testing)
//   panopticon-sensord ... --control-socket PATH         serve status/coverage/state on a 0600 unix socket

#include "panopticon/linux_agent/host.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/sensor/audit_netlink.hpp"
#include "panopticon/linux_agent/sensor/auth_log.hpp"
#include "panopticon/linux_agent/sensor/kernel_change.hpp"
#include "panopticon/linux_agent/sensor/control.hpp"
#include "panopticon/linux_agent/sensor/ebpf_process.hpp"
#include "panopticon/linux_agent/sensor/fanotify_file.hpp"
#include "panopticon/linux_agent/sensor/netlink_proc.hpp"
#include "panopticon/linux_agent/sensor/pipeline.hpp"
#include "panopticon/linux_agent/sensor/sockdiag_network.hpp"
#include "panopticon/linux_agent/sensor/uplink.hpp"

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace sensor = panopticon::linux_agent::sensor;
using panopticon::linux_agent::error;
using panopticon::linux_agent::succeeded;

namespace {

std::atomic<bool> stop_requested{false};
static_assert(std::atomic<bool>::is_always_lock_free, "the signal handler requires a lock-free flag");

extern "C" void request_stop(int) { stop_requested.store(true); }

void install_signal_handlers() {
    struct sigaction action {};
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGPIPE, &ignore, nullptr);
}

int usage() {
    std::fprintf(stderr,
                 "usage: panopticon-sensord (--config PATH | --stdout) [--duration SECONDS] [--proc-root PATH] [--wal PATH] [--no-ebpf] [--control-socket PATH]\n"
                 "       panopticon-sensord --probe\n");
    return 2;
}

std::string machine_id() {
    std::ifstream input{"/etc/machine-id"};
    std::string value;
    std::getline(input, value);
    return value;
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path;
    std::string proc_root;
    std::string wal_path;
    std::string control_socket;
    bool to_stdout = false;
    bool probe_only = false;
    bool no_ebpf = false;
    std::uint64_t duration_seconds = 0U;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        const auto next = [&]() -> const char* { return index + 1 < argc ? argv[++index] : nullptr; };
        if (argument == "--config") {
            const auto* value = next();
            if (value == nullptr) return usage();
            config_path = value;
        } else if (argument == "--stdout") {
            to_stdout = true;
        } else if (argument == "--probe") {
            probe_only = true;
        } else if (argument == "--no-ebpf") {
            no_ebpf = true;
        } else if (argument == "--duration") {
            const auto* value = next();
            if (value == nullptr) return usage();
            duration_seconds = std::strtoull(value, nullptr, 10);
        } else if (argument == "--proc-root") {
            const auto* value = next();
            if (value == nullptr) return usage();
            proc_root = value;
        } else if (argument == "--control-socket") {
            const auto* value = next();
            if (value == nullptr) return usage();
            control_socket = value;
        } else if (argument == "--wal") {
            const auto* value = next();
            if (value == nullptr) return usage();
            wal_path = value;
        } else {
            return usage();
        }
    }

    sensor::clock_domain clock;
    if (probe_only) {
        sensor::ebpf_process_provider ebpf{clock};
        const auto ebpf_reason = ebpf.probe();
        std::printf("{\"provider\":\"ebpf_process\",\"built\":%s,\"available\":%s,\"reason\":\"%s\"}\n",
                    sensor::ebpf_process_built() ? "true" : "false", ebpf_reason.empty() ? "true" : "false", ebpf_reason.c_str());
        sensor::netlink_proc_provider netlink{clock};
        const auto reason = netlink.probe();
        std::printf("{\"provider\":\"netlink_proc\",\"available\":%s,\"reason\":\"%s\"}\n", reason.empty() ? "true" : "false",
                    reason.c_str());
        return 0;
    }
    if (config_path.empty() && !to_stdout) return usage();

    const auto host = panopticon::linux_agent::collect_host_observation();
    if (!succeeded(host)) {
        std::fprintf(stderr, "panopticon-sensord: %s\n", std::get<error>(host).message.c_str());
        return 1;
    }
    const auto& observation = std::get<panopticon::linux_agent::host_observation>(host);

    sensor::sensor_config config;
    if (!config_path.empty()) {
        auto loaded = sensor::load_sensor_config(config_path);
        if (!succeeded(loaded)) {
            std::fprintf(stderr, "panopticon-sensord: %s\n", std::get<error>(loaded).message.c_str());
            return 1;
        }
        config = std::move(std::get<sensor::sensor_config>(loaded));
    } else {
        config.host_id = machine_id();
        if (config.host_id.empty()) config.host_id = "unknown-host";
        config.sensor_id = "sensor-" + config.host_id.substr(0U, 12U);
        config.enable_fim = true;  // development mode: baseline in memory, nothing is stored
        config.enable_hashing = true;
    }
    if (!proc_root.empty()) config.proc_root = proc_root;
    if (!wal_path.empty()) config.wal_path = wal_path;

    sensor::sensor_identity identity{config.host_id, observation.boot_id, observation.hostname, config.sensor_id,
                                     PANOPTICON_SENSOR_VERSION, "none"};

    std::unique_ptr<sensor::record_sink> sink;
    if (to_stdout) {
        sink = std::make_unique<sensor::stream_sink>(stdout);
    } else {
        sensor::wal_options options;
        options.directory = config.wal_path;
        options.quota_bytes = config.wal_quota_bytes;
        options.segment_bytes = config.wal_segment_bytes;
        options.maximum_record_bytes = static_cast<std::uint32_t>(std::min<std::uint64_t>(1024U * 1024U, config.wal_segment_bytes - 64U));
        auto log = sensor::write_ahead_log::open(options);
        if (!succeeded(log)) {
            std::fprintf(stderr, "panopticon-sensord: write-ahead log: %s\n", std::get<error>(log).message.c_str());
            return 1;
        }
        sink = std::make_unique<sensor::wal_sink>(std::move(std::get<std::unique_ptr<sensor::write_ahead_log>>(log)));
    }

    // Delivery to the Manager. Collection never depends on it: a missing identity or an unreachable
    // Manager leaves records in the WAL, and the reason is printed and visible in uplink metrics.
    std::unique_ptr<sensor::record_poster> poster;
    std::unique_ptr<sensor::uplink> delivery;
    std::unique_ptr<sensor::uplink_runner> delivery_runner;
    if (!to_stdout && !config.manager_url.empty()) {
        auto enrolled = panopticon::linux_agent::load_enrolled_identity(config.identity_path);
        if (!succeeded(enrolled)) {
            std::fprintf(stderr, "panopticon-sensord: delivery disabled: %s\n", std::get<error>(enrolled).message.c_str());
        } else if (std::get<panopticon::linux_agent::enrolled_identity>(enrolled).host_id != config.host_id) {
            std::fprintf(stderr, "panopticon-sensord: delivery disabled: the enrolled host id differs from host_id\n");
        } else if (!sensor::https_poster_built()) {
            std::fprintf(stderr, "panopticon-sensord: delivery disabled: this build has no libcurl\n");
        } else {
            sensor::https_poster_options poster_options;
            poster_options.manager_url = config.manager_url;
            poster_options.identity = std::get<panopticon::linux_agent::enrolled_identity>(enrolled);
            poster_options.ca_bundle = config.ca_bundle;
            poster = sensor::make_https_poster(std::move(poster_options));
            sensor::uplink_options uplink_options;
            uplink_options.quarantine_path = config.wal_path.string() + ".rejected.ndjson";
            delivery = std::make_unique<sensor::uplink>(static_cast<sensor::wal_sink&>(*sink).log(), *poster, uplink_options);
            delivery_runner = std::make_unique<sensor::uplink_runner>(*delivery);
            delivery_runner->start();
            std::fprintf(stderr, "panopticon-sensord: delivering to %s\n", config.manager_url.c_str());
        }
    }

    install_signal_handlers();
    std::vector<std::unique_ptr<sensor::provider>> providers;
    // Preference order within the `process` family: eBPF first (in-kernel exec path, argv and exit
    // status), the proc connector as the fallback.
    if (config.enable_ebpf && !no_ebpf) {
        sensor::ebpf_process_options ebpf_options;
        ebpf_options.limits = sensor::procfs_limits{config.maximum_args, config.maximum_args_bytes, 4096U, config.collect_environment};
        providers.push_back(std::make_unique<sensor::ebpf_process_provider>(clock, ebpf_options));
    }
    providers.push_back(std::make_unique<sensor::netlink_proc_provider>(clock));
    if (config.enable_file_events) {
        sensor::fanotify_options file_options;
        if (!config.file_include.empty()) file_options.filter.include = config.file_include;
        file_options.filter.exclude.insert(file_options.filter.exclude.end(), config.file_exclude.begin(), config.file_exclude.end());
        // The daemon's own state is never telemetry: its WAL and control socket would feed back.
        file_options.filter.exclude.push_back(config.wal_path.string());
        if (!control_socket.empty()) file_options.filter.exclude.push_back(std::filesystem::path{control_socket}.parent_path().string());
        providers.push_back(std::make_unique<sensor::fanotify_file_provider>(std::move(file_options)));
    }
    if (config.enable_network_events) providers.push_back(std::make_unique<sensor::sockdiag_network_provider>());
    if (config.enable_kernel_events) providers.push_back(std::make_unique<sensor::kernel_change_provider>());
    if (config.enable_auth_events) {
        // One family, two mechanisms: the kernel audit group is preferred, the log is the fallback.
        providers.push_back(std::make_unique<sensor::audit_netlink_provider>());
        providers.push_back(std::make_unique<sensor::auth_log_provider>());
    }
    sensor::sensor_pipeline pipeline{config, identity, clock, *sink, std::move(providers)};
    if (delivery) {
        auto* uplink_state_source = delivery.get();
        pipeline.set_delivery_probe([uplink_state_source] {
            const auto metrics = uplink_state_source->metrics();
            sensor::delivery_health health;
            health.configured = true;
            health.state = sensor::to_string(metrics.state);
            health.acknowledged_seq = metrics.acknowledged_seq;
            health.batches_sent = metrics.batches_sent;
            health.records_acknowledged = metrics.records_acknowledged;
            health.retries = metrics.retries;
            health.refusals = metrics.refusals;
            health.consecutive_failures = metrics.consecutive_failures;
            health.records_quarantined = metrics.records_quarantined;
            health.quarantine_failures = metrics.quarantine_failures;
            health.recent_quarantined_seqs = metrics.recent_quarantined_seqs;
            health.last_error = metrics.last_error;
            return health;
        });
    }
    if (auto started = pipeline.start(); !succeeded(started)) {
        std::fprintf(stderr, "panopticon-sensord: start: %s\n", std::get<error>(started).message.c_str());
        return 1;
    }
    for (const auto& provider : pipeline.health_now().providers) {
        std::fprintf(stderr, "panopticon-sensord: provider %s %s%s%s\n", provider.name.c_str(), provider.state.c_str(),
                     provider.reason.empty() ? "" : ": ", provider.reason.c_str());
    }
    std::unique_ptr<sensor::control_server> control;
    if (!control_socket.empty()) {
        sensor::control_sources sources;
        sources.status = [&pipeline] { return pipeline.status_json(); };
        sources.coverage = [&pipeline] { return pipeline.coverage_json(); };
        sources.state_options.root = config.host_root;
        control = std::make_unique<sensor::control_server>(control_socket, sensor::make_control_handler(std::move(sources)));
        if (auto bound = control->start(); !succeeded(bound)) {
            // Control is a convenience: collection continues without it.
            std::fprintf(stderr, "panopticon-sensord: control socket disabled: %s\n", std::get<error>(bound).message.c_str());
            control.reset();
        }
    }
    const auto deadline = duration_seconds == 0U ? 0U : sensor::clock_domain::now_monotonic_ns() + duration_seconds * 1'000'000'000ULL;
    const auto finished = pipeline.run(stop_requested, deadline);
    if (control) control->stop();
    pipeline.shutdown();
    if (delivery_runner) {
        delivery_runner->stop();
        const auto uplink_metrics = delivery->metrics();
        std::fprintf(stderr, "panopticon-sensord: uplink %s; batches=%llu acknowledged=%llu through seq %llu retries=%llu refusals=%llu quarantined=%llu%s%s\n",
                     sensor::to_string(uplink_metrics.state), static_cast<unsigned long long>(uplink_metrics.batches_sent),
                     static_cast<unsigned long long>(uplink_metrics.records_acknowledged),
                     static_cast<unsigned long long>(uplink_metrics.acknowledged_seq), static_cast<unsigned long long>(uplink_metrics.retries),
                     static_cast<unsigned long long>(uplink_metrics.refusals),
                     static_cast<unsigned long long>(uplink_metrics.records_quarantined), uplink_metrics.last_error.empty() ? "" : "; last error: ",
                     uplink_metrics.last_error.c_str());
    }
    const auto& metrics = pipeline.metrics();
    std::fprintf(stderr, "panopticon-sensord: stopped; records=%llu events=%llu losses=%llu sink_errors=%llu\n",
                 static_cast<unsigned long long>(metrics.records), static_cast<unsigned long long>(metrics.events),
                 static_cast<unsigned long long>(metrics.loss_records), static_cast<unsigned long long>(metrics.sink_errors));
    return succeeded(finished) ? 0 : 1;
}
