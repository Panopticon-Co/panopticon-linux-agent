#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/sensor/entity_graph.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"
#include "panopticon/linux_agent/sensor/serializer.hpp"
#include "panopticon/linux_agent/sensor/wal.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

struct sensor_config {
    std::string sensor_id;
    std::string host_id;
    std::filesystem::path wal_path{"/var/lib/panopticon/wal"};
    std::uint64_t wal_quota_bytes{256ULL * 1024U * 1024U};
    std::uint64_t wal_segment_bytes{8ULL * 1024U * 1024U};
    std::size_t queue_capacity{65536U};
    std::uint64_t reconcile_interval_seconds{30U};
    std::uint64_t health_interval_seconds{60U};
    std::uint64_t state_interval_seconds{3600U};
    bool collect_environment{true};
    bool enable_ebpf{true};  // false: skip the eBPF provider; netlink_proc and procfs only
    bool enable_file_events{true};  // false: no fanotify file telemetry
    std::vector<std::string> file_include;  // empty: the built-in persistence/credential/binary/staging set
    std::vector<std::string> file_exclude;  // added to the built-in exclusions
    std::size_t maximum_args{64U};
    std::size_t maximum_args_bytes{4096U};
    std::size_t maximum_entities{65536U};
    std::filesystem::path proc_root{"/proc"};
    std::filesystem::path host_root{"/"};  // prefix for host-state inventory; tests point it at a fake tree
};

// Strict key=value parser: unknown keys, duplicates and out-of-range values are errors.
[[nodiscard]] result<sensor_config> parse_sensor_config(std::string_view contents);
// Rejects files that are group/world writable or not regular files.
[[nodiscard]] result<sensor_config> load_sensor_config(const std::filesystem::path& path);

// Destination for serialised records. Every record carries its seq, so the sink hands out the
// next seq and must receive records in that order.
class record_sink {
public:
    virtual ~record_sink() = default;
    [[nodiscard]] virtual std::uint64_t next_seq() const = 0;
    [[nodiscard]] virtual result<bool> append(std::uint64_t seq, std::string_view record) = 0;
    [[nodiscard]] virtual result<bool> flush(std::uint64_t now_ns, bool force) = 0;
    [[nodiscard]] virtual std::vector<wal_loss> take_losses() { return {}; }
    [[nodiscard]] virtual wal_metrics metrics() const { return {}; }
};

class wal_sink final : public record_sink {
public:
    explicit wal_sink(std::unique_ptr<write_ahead_log> log) : log_{std::move(log)} {}
    [[nodiscard]] std::uint64_t next_seq() const override { return log_->next_seq(); }
    [[nodiscard]] result<bool> append(std::uint64_t seq, std::string_view record) override;
    [[nodiscard]] result<bool> flush(std::uint64_t now_ns, bool force) override { return log_->sync(now_ns, force); }
    [[nodiscard]] std::vector<wal_loss> take_losses() override { return log_->take_losses(); }
    [[nodiscard]] wal_metrics metrics() const override { return log_->metrics(); }
    [[nodiscard]] write_ahead_log& log() noexcept { return *log_; }

private:
    std::unique_ptr<write_ahead_log> log_;
};

// Development and test sink: NDJSON lines on a stream, seq kept in memory.
class stream_sink final : public record_sink {
public:
    explicit stream_sink(std::FILE* stream) : stream_{stream} {}
    [[nodiscard]] std::uint64_t next_seq() const override { return next_; }
    [[nodiscard]] result<bool> append(std::uint64_t seq, std::string_view record) override;
    [[nodiscard]] result<bool> flush(std::uint64_t now_ns, bool force) override;

private:
    std::FILE* stream_;
    std::uint64_t next_{1};
};

struct pipeline_metrics {
    std::uint64_t records{};
    std::uint64_t events{};
    std::uint64_t loss_records{};
    std::uint64_t reconciles{};
    std::uint64_t sink_errors{};
    std::uint64_t oversize_dropped{};
};

class sensor_pipeline {
public:
    sensor_pipeline(const sensor_config& config, sensor_identity identity, clock_domain& clock, record_sink& sink,
                    std::vector<std::unique_ptr<provider>> providers);
    ~sensor_pipeline();

    // Starts providers (an unavailable provider degrades coverage, it is not fatal; of several
    // providers in one family only the first that starts runs), seeds the
    // entity graph and emits the initial health and state.processes records.
    [[nodiscard]] result<bool> start();
    // Processes queued records and periodic work until `stop` becomes true or `deadline_ns`
    // (0 = none) passes. Flushes the sink before returning.
    [[nodiscard]] result<bool> run(const std::atomic<bool>& stop, std::uint64_t deadline_ns = 0U);
    void shutdown();

    // One iteration; exposed for tests.
    [[nodiscard]] result<bool> step(std::uint64_t now_ns, std::chrono::milliseconds wait);

    [[nodiscard]] const pipeline_metrics& metrics() const noexcept { return metrics_; }
    [[nodiscard]] const entity_graph& graph() const noexcept { return graph_; }
    [[nodiscard]] health_snapshot health_now() const;
    // Health as JSON, cached by the pipeline thread (refreshed at most once a second), so other
    // threads such as the control socket never touch live pipeline state.
    [[nodiscard]] std::string status_json() const;
    [[nodiscard]] std::string coverage_json() const;

private:
    void refresh_status(std::uint64_t now_ns);

    result<bool> emit(const std::function<std::string(std::uint64_t)>& serialise);
    result<bool> emit_events(const std::vector<process_event>& events, std::uint64_t observed_ns);
    // Routes one dequeued record: file events are enriched and written, everything else feeds the
    // entity graph.
    void process_record(const raw_record& record, std::uint64_t observed_ns);
    result<bool> emit_file_event(const raw_record& record, const raw_file_event& file, std::uint64_t observed_ns);
    result<bool> emit_loss(loss_report report);
    result<bool> emit_health(std::uint64_t now_ns);
    result<bool> emit_process_state(std::uint64_t now_ns);
    result<bool> emit_host_state(std::uint64_t now_ns);
    result<bool> collect_losses(std::uint64_t now_ns);

    sensor_config config_;
    clock_domain& clock_;
    record_sink& sink_;
    record_serializer serializer_;
    entity_graph graph_;
    record_queue queue_;
    std::vector<std::unique_ptr<provider>> providers_;
    std::vector<std::string> standby_;  // per provider: name of the family member that superseded it, else empty
    pipeline_metrics metrics_;
    std::vector<raw_record> batch_;
    std::uint64_t last_reconcile_ns_{};
    std::uint64_t last_health_ns_{};
    std::uint64_t last_state_ns_{};
    std::uint64_t last_resample_ns_{};
    std::uint64_t snapshots_{};
    mutable std::mutex status_mutex_;
    std::string status_cache_{"{}"};
    std::string coverage_cache_{"{}"};
    std::uint64_t last_status_ns_{};
    bool started_{false};
};

}  // namespace panopticon::linux_agent::sensor
