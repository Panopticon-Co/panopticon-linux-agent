#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/sensor/container_tracker.hpp"
#include "panopticon/linux_agent/sensor/entity_graph.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"
#include "panopticon/linux_agent/sensor/serializer.hpp"
#include "panopticon/linux_agent/sensor/state_diff.hpp"
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
    // Delivery to the Manager. Empty manager_url: records stay in the WAL (collection only).
    std::string manager_url;                // https:// only
    std::filesystem::path identity_path;    // enrolled identity file (agent id, host id, bearer token)
    std::filesystem::path ca_bundle;        // optional private CA for the Manager certificate
    // Marker of whether the previous sensor process ended cleanly (empty: not kept). A sensor that is killed or
    // loses power cannot say so itself, and its sequence numbers continue unbroken afterwards, so the next
    // start reports the blind interval as a loss from this file.
    std::filesystem::path instance_state_path;
    std::uint64_t instance_heartbeat_seconds{10U};
    std::uint64_t wal_quota_bytes{256ULL * 1024U * 1024U};
    std::uint64_t wal_segment_bytes{8ULL * 1024U * 1024U};
    std::size_t queue_capacity{65536U};
    std::uint64_t reconcile_interval_seconds{30U};
    std::uint64_t health_interval_seconds{60U};
    std::uint64_t state_interval_seconds{3600U};
    bool collect_environment{true};
    bool enable_ebpf{true};  // false: skip the eBPF provider; netlink_proc and procfs only
    bool enable_file_events{true};  // false: no fanotify file telemetry
    bool enable_sensitive_file_events{true};  // false: no reports of credential files being opened
    bool enable_network_events{true};  // false: no socket telemetry (sock_diag)
    bool enable_auth_events{true};     // false: no authentication telemetry (audit group, auth log)
    bool enable_kernel_events{true};   // false: no kernel module and mount change events
    bool enable_security_events{true}; // false: no executable-memory and eBPF-load telemetry
    std::vector<std::string> file_include;  // empty: the built-in persistence/credential/binary/staging set
    std::vector<std::string> file_exclude;  // added to the built-in exclusions
    // File-integrity monitoring of the persistence catalog. Off in the struct so embedders and
    // tests opt in; parse_sensor_config() turns it on unless the file says otherwise.
    bool enable_fim{false};
    std::filesystem::path fim_path;          // empty: baseline kept in memory only
    std::uint64_t fim_interval_seconds{300U};  // full rescan period
    // Content hashing of executed images (off in the struct like FIM; the parser turns it on).
    bool enable_hashing{false};
    std::uint64_t hash_max_file_bytes{256ULL * 1024U * 1024U};
    std::uint64_t hash_bytes_per_second{64ULL * 1024U * 1024U};
    // Manager commands (ADR 024). Off unless the file says otherwise: a sensor that only reports
    // never opens the command channel.
    std::string response_mode{"off"};  // off, dry_run, enforce
    std::vector<std::string> response_actions{"KILL_PROCESS", "COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS"};
    std::uint64_t response_poll_seconds{5U};
    std::uint64_t response_max_lifetime_seconds{900U};
    std::uint64_t response_max_changes_per_minute{6U};
    std::filesystem::path response_ledger_path;  // empty: <wal_path>.commands
    bool response_require_boot_binding{false};   // refuse schema-1 (unbound) process targets
    // Command authorization (ADR 025): the pinned command-signing keys, one base64 P-256 point per line. With keys,
    // every command must carry a valid signature. Without keys, response_mode other than off needs
    // response_allow_unsigned=true; the two together are a contradiction and refused.
    std::filesystem::path response_signing_keys;
    bool response_allow_unsigned{false};
    // File actions (ADR 026). COLLECT_FILE needs nothing more. QUARANTINE_FILE moves files only from under one of
    // these directories (absolute, never "/") into response_quarantine_dir (empty: <wal_path>.quarantine).
    std::vector<std::filesystem::path> response_file_roots;
    std::filesystem::path response_quarantine_dir;
    // The privileged isolation helper's AF_UNIX socket (ADR 004, ADR 027). Required to list ISOLATE_HOST and
    // RELEASE_HOST_ISOLATION, which must be listed together.
    std::filesystem::path response_isolation_socket;
    // Signed local policy (ADR 032): the bundle and the pinned policy-signing keys, both or neither. Its decisions
    // become policy.match records only; the accepted version is kept durably in <wal_path>.policy.
    std::filesystem::path policy_path;
    std::filesystem::path policy_signing_keys;
    std::uint64_t policy_check_seconds{30U};
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
    // Checks that the storage behind the sink still exists (see write_ahead_log::verify_storage).
    virtual void verify_storage() {}
};

class wal_sink final : public record_sink {
public:
    explicit wal_sink(std::unique_ptr<write_ahead_log> log) : log_{std::move(log)} {}
    [[nodiscard]] std::uint64_t next_seq() const override { return log_->next_seq(); }
    [[nodiscard]] result<bool> append(std::uint64_t seq, std::string_view record) override;
    [[nodiscard]] result<bool> flush(std::uint64_t now_ns, bool force) override { return log_->sync(now_ns, force); }
    [[nodiscard]] std::vector<wal_loss> take_losses() override { return log_->take_losses(); }
    [[nodiscard]] wal_metrics metrics() const override { return log_->metrics(); }
    void verify_storage() override { (void)log_->verify_storage(); }
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
    std::uint64_t clock_steps{};        // wall-clock steps detected; offsets were re-sampled at once
    std::uint64_t records_unwritten{};  // records the sink refused (full or failing disk); reported as a wal loss
    std::uint64_t policy_matches{};     // policy.match records written
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

    // Reports delivery state in health records and turns Manager rejections into loss records.
    // Called only from the pipeline thread; the probe must be safe to call there.
    using delivery_probe = std::function<delivery_health()>;
    void set_delivery_probe(delivery_probe probe) { delivery_probe_ = std::move(probe); }
    // Called once per loop iteration of run(), on the pipeline thread. A service watchdog is fed from here, so a loop that
    // is stuck stops feeding it.
    void set_heartbeat(std::function<void()> heartbeat) { heartbeat_ = std::move(heartbeat); }

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
    result<bool> emit_network_event(const raw_record& record, const raw_network_event& network, std::uint64_t observed_ns);
    result<bool> emit_auth_event(const raw_record& record, const raw_auth_event& auth, std::uint64_t observed_ns);
    result<bool> emit_kernel_event(const raw_record& record, const raw_kernel_event& kernel, std::uint64_t observed_ns);
    result<bool> emit_security_event(const raw_record& record, const raw_security_event& security, std::uint64_t observed_ns);
    result<bool> emit_dns_event(const raw_record& record, const raw_dns_query& dns, std::uint64_t observed_ns);
    result<bool> emit_lsm_event(const raw_record& record, const raw_lsm_event& lsm, std::uint64_t observed_ns);
    result<bool> emit_firewall_event(const raw_record& record, const raw_firewall_change& firewall, std::uint64_t observed_ns);
    result<bool> emit_response_event(const raw_record& record, const raw_response_action& response, std::uint64_t observed_ns);
    result<bool> emit_loss(loss_report report);
    result<bool> emit_health(std::uint64_t now_ns);
    result<bool> emit_process_state(std::uint64_t now_ns);
    result<bool> emit_host_state(std::uint64_t now_ns);
    result<bool> emit_state_changes(const state_snapshot& snapshot, std::uint64_t now_ns);
    // Adds the executable hash (cached, pending or refused) to exec and discovery events.
    [[nodiscard]] process_event with_executable_hash(const process_event& event);
    result<bool> emit_hash_results(std::uint64_t observed_ns);
    result<bool> emit_fim_changes(const std::vector<fim_change>& changes, std::uint64_t observed_ns);
    result<bool> collect_losses(std::uint64_t now_ns);
    // Compares the previous instance's marker with now, reports an unclean end, and writes this instance's marker.
    void begin_instance(std::uint64_t unix_now);
    void write_instance_marker(std::uint64_t unix_now, bool clean);
    // Signed local policy (ADR 032): re-reads the policy and key files, records what changed, and names the policy
    // in force in every later record.
    void refresh_policy(std::uint64_t unix_now_ns);
    // Writes a policy.match for each decision about the record just written (seq last_emitted_seq_). Decides only:
    // nothing here can reach the command processor or any response action.
    void evaluate_policy(const policy_input& input, const entity_ptr& actor, std::uint32_t pid, std::uint64_t time_unix_ns,
                         std::string_view subject_type, std::uint64_t observed_ns, std::optional<policy_field> only = std::nullopt);

    sensor_config config_;
    clock_domain& clock_;
    record_sink& sink_;
    record_serializer serializer_;
    entity_graph graph_;
    container_tracker containers_;
    record_queue queue_;
    std::vector<std::unique_ptr<provider>> providers_;
    std::vector<std::string> standby_;  // per provider: name of the family member that superseded it, else empty
    pipeline_metrics metrics_;
    std::vector<raw_record> batch_;
    std::uint64_t last_reconcile_ns_{};
    std::uint64_t last_health_ns_{};
    std::uint64_t last_state_ns_{};
    std::uint64_t last_resample_ns_{};
    std::uint64_t last_fim_ns_{};
    std::unique_ptr<fim_monitor> fim_;
    std::unique_ptr<hash_service> hashes_;
    std::uint64_t snapshots_{};
    state_differ differ_;
    std::string package_signature_;
    std::uint64_t last_package_inventory_ns_{};
    mutable std::mutex status_mutex_;
    std::string status_cache_{"{}"};
    std::string coverage_cache_{"{}"};
    std::uint64_t last_status_ns_{};
    delivery_probe delivery_probe_;
    std::function<void()> heartbeat_;
    std::uint64_t quarantine_reported_{};
    // A loss record is a record: if the sink refuses it, the loss it describes must not vanish with it.
    std::vector<loss_report> pending_losses_;
    // Loss records are written into the log they report on, so a quota drop can remove the records that explain an
    // earlier drop. Every loss record written and not yet acknowledged is remembered by seq; when the log drops a range
    // that holds some, carry_dropped_loss_reports() writes what they said again, so the loss records that survive
    // always explain the whole gap. Process local: a loss record written before a restart is not carried. Bounded: past
    // the limit the oldest entry is merged into the next of its stage, which can only over-report.
    struct written_loss {
        std::uint64_t seq{};
        loss_report report;
    };
    std::vector<written_loss> written_losses_;
    void carry_dropped_loss_reports(const std::vector<wal_loss>& dropped);
    std::uint64_t unwritten_reported_{};
    std::uint64_t last_loss_retry_ns_{};
    std::uint64_t last_storage_check_ns_{};
    std::uint64_t last_instance_marker_ns_{};
    std::uint64_t instance_started_unix_ns_{};
    std::string boot_id_;
    std::string last_write_error_;
    bool write_failed_{false};
    std::uint64_t started_ns_{};
    bool started_{false};
    std::unique_ptr<policy_store> policy_;
    std::uint64_t last_policy_ns_{};
    std::int64_t policy_expires_unix_{};  // of the policy in force; 0 when none
    std::uint64_t last_emitted_seq_{};    // seq of the last record the sink accepted
};

}  // namespace panopticon::linux_agent::sensor
