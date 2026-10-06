#include "panopticon/linux_agent/sensor/pipeline.hpp"

#include "panopticon/linux_agent/identity.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::uint64_t ns_per_second = 1'000'000'000ULL;
constexpr std::size_t state_items_per_part = 100U;
// Upper bound on the extra latency batching adds to an event (see record_queue::pop_batch).
constexpr std::chrono::milliseconds batch_linger{20};

std::string trim(const std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r");
    const auto last = value.find_last_not_of(" \t\r");
    return first == std::string_view::npos ? std::string{} : std::string{value.substr(first, last - first + 1U)};
}

template <typename integer_type>
std::optional<integer_type> integer(const std::string_view value) {
    integer_type parsed{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    return error == std::errc{} && end == value.data() + value.size() ? std::optional{parsed} : std::nullopt;
}

std::string read_small_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

bool kernel_at_least(const std::string& release, const int major, const int minor) {
    int found_major = 0;
    int found_minor = 0;
    if (std::sscanf(release.c_str(), "%d.%d", &found_major, &found_minor) != 2) return false;
    return found_major > major || (found_major == major && found_minor >= minor);
}

}  // namespace

result<sensor_config> parse_sensor_config(const std::string_view contents) {
    std::map<std::string, std::string> values;
    std::istringstream lines{std::string{contents}};
    for (std::string line; std::getline(lines, line);) {
        line = trim(line);
        if (line.empty() || line.front() == '#') continue;
        const auto separator = line.find('=');
        if (separator == std::string::npos) return error{error_code::invalid_input, "configuration line lacks '='"};
        const auto key = trim(std::string_view{line}.substr(0U, separator));
        const auto value = trim(std::string_view{line}.substr(separator + 1U));
        if (key.empty() || value.empty() || !values.emplace(key, value).second) {
            return error{error_code::invalid_input, "configuration contains an empty or duplicate key"};
        }
    }
    constexpr std::array<std::string_view, 18U> allowed{
        "sensor_id", "host_id", "wal_path", "wal_quota_bytes", "wal_segment_bytes", "queue_capacity",
        "reconcile_interval_seconds", "health_interval_seconds", "state_interval_seconds", "collect_environment",
        "maximum_args", "maximum_args_bytes", "maximum_entities", "proc_root", "enable_ebpf", "enable_file_events",
        "file_include", "file_exclude"};
    for (const auto& [key, value] : values) {
        (void)value;
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            return error{error_code::invalid_input, "unknown configuration key: " + key};
        }
    }
    sensor_config config;
    const auto text = [&values](const char* key) -> std::optional<std::string> {
        const auto found = values.find(key);
        return found == values.end() ? std::nullopt : std::optional{found->second};
    };
    bool valid = true;
    const auto number = [&](const char* key, auto& target, const std::uint64_t minimum, const std::uint64_t maximum) {
        if (const auto value = text(key); value.has_value()) {
            const auto parsed = integer<std::uint64_t>(*value);
            if (!parsed || *parsed < minimum || *parsed > maximum) valid = false;
            else target = static_cast<std::decay_t<decltype(target)>>(*parsed);
        }
    };
    config.sensor_id = text("sensor_id").value_or("");
    config.host_id = text("host_id").value_or("");
    if (const auto value = text("wal_path"); value.has_value()) config.wal_path = *value;
    if (const auto value = text("proc_root"); value.has_value()) config.proc_root = *value;
    number("wal_quota_bytes", config.wal_quota_bytes, 1ULL << 20U, 1ULL << 40U);
    number("wal_segment_bytes", config.wal_segment_bytes, 1ULL << 16U, 1ULL << 30U);
    number("queue_capacity", config.queue_capacity, 1024U, 1U << 24U);
    number("reconcile_interval_seconds", config.reconcile_interval_seconds, 1U, 86400U);
    number("health_interval_seconds", config.health_interval_seconds, 1U, 86400U);
    number("state_interval_seconds", config.state_interval_seconds, 60U, 7U * 86400U);
    number("maximum_args", config.maximum_args, 1U, 1024U);
    number("maximum_args_bytes", config.maximum_args_bytes, 256U, 1U << 20U);
    number("maximum_entities", config.maximum_entities, 1024U, 1U << 22U);
    if (const auto value = text("collect_environment"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.collect_environment = *value == "true";
    }
    if (const auto value = text("enable_ebpf"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_ebpf = *value == "true";
    }
    if (const auto value = text("enable_file_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_file_events = *value == "true";
    }
    // Comma-separated absolute directory prefixes.
    const auto prefixes = [&](const char* key, std::vector<std::string>& target) {
        const auto value = text(key);
        if (!value.has_value()) return;
        std::istringstream stream{*value};
        std::string item;
        while (std::getline(stream, item, ',')) {
            item = std::string{trim(item)};
            if (item.empty() || item.front() != '/' || item.find("..") != std::string::npos || target.size() >= 256U) valid = false;
            else target.push_back(item);
        }
    };
    prefixes("file_include", config.file_include);
    prefixes("file_exclude", config.file_exclude);
    if (!valid) return error{error_code::invalid_input, "configuration value is out of range"};
    if (!is_valid_identifier(config.sensor_id) || !is_valid_identifier(config.host_id)) {
        return error{error_code::invalid_input, "sensor_id and host_id are required identifiers"};
    }
    if (config.wal_quota_bytes < 2U * config.wal_segment_bytes || !config.wal_path.is_absolute() || !config.proc_root.is_absolute()) {
        return error{error_code::invalid_input, "write-ahead log limits or paths are invalid"};
    }
    return config;
}

result<sensor_config> load_sensor_config(const std::filesystem::path& path) {
    std::error_code filesystem_error;
    const auto status = std::filesystem::status(path, filesystem_error);
    if (filesystem_error || !std::filesystem::is_regular_file(status)) {
        return error{error_code::io_failure, "configuration path is not a regular file"};
    }
    const auto unsafe = std::filesystem::perms::group_write | std::filesystem::perms::others_write;
    if ((status.permissions() & unsafe) != std::filesystem::perms::none) {
        return error{error_code::invalid_input, "configuration must not be group or world writable"};
    }
    return parse_sensor_config(read_small_file(path));
}

result<bool> wal_sink::append(const std::uint64_t seq, const std::string_view record) {
    auto appended = log_->append(seq, record);
    if (!succeeded(appended)) return std::get<error>(appended);
    return true;
}

result<bool> stream_sink::append(const std::uint64_t seq, const std::string_view record) {
    if (seq != next_) return error{error_code::invalid_input, "stream seq is not contiguous"};
    if (std::fwrite(record.data(), 1U, record.size(), stream_) != record.size() || std::fputc('\n', stream_) == EOF) {
        return error{error_code::io_failure, "cannot write record"};
    }
    ++next_;
    return true;
}

result<bool> stream_sink::flush(const std::uint64_t, const bool) {
    if (std::fflush(stream_) != 0) return error{error_code::io_failure, "cannot flush records"};
    return true;
}

sensor_pipeline::sensor_pipeline(const sensor_config& config, sensor_identity identity, clock_domain& clock, record_sink& sink,
                                 std::vector<std::unique_ptr<provider>> providers)
    : config_{config},
      clock_{clock},
      sink_{sink},
      serializer_{identity, clock},
      graph_{entity_graph_options{identity.host_id, identity.boot_id, config.proc_root,
                                  procfs_limits{config.maximum_args, config.maximum_args_bytes, 4096U, config.collect_environment},
                                  30U * ns_per_second, config.maximum_entities, 8U},
             clock},
      queue_{config.queue_capacity},
      providers_{std::move(providers)},
      standby_(providers_.size()) {}

sensor_pipeline::~sensor_pipeline() { shutdown(); }

result<bool> sensor_pipeline::emit(const std::function<std::string(std::uint64_t)>& serialise) {
    const auto seq = sink_.next_seq();
    const auto record = serialise(seq);
    auto appended = sink_.append(seq, record);
    if (!succeeded(appended)) {
        ++metrics_.sink_errors;
        if (std::get<error>(appended).code == error_code::resource_limit) ++metrics_.oversize_dropped;
        return appended;
    }
    ++metrics_.records;
    return true;
}

result<bool> sensor_pipeline::emit_events(const std::vector<process_event>& events, const std::uint64_t observed_ns) {
    result<bool> outcome = true;
    for (const auto& event : events) {
        auto emitted = emit([&](const std::uint64_t seq) { return serializer_.event(event, seq, observed_ns); });
        if (succeeded(emitted)) ++metrics_.events;
        else outcome = emitted;
    }
    return outcome;
}

void sensor_pipeline::process_record(const raw_record& record, const std::uint64_t observed_ns) {
    if (const auto* file = std::get_if<raw_file_event>(&record.payload)) {
        (void)emit_file_event(record, *file, observed_ns);
        return;
    }
    (void)emit_events(graph_.apply(record), observed_ns);
}

result<bool> sensor_pipeline::emit_file_event(const raw_record& record, const raw_file_event& file, const std::uint64_t observed_ns) {
    file_record out;
    out.type = std::string{"file."} + to_string(file.operation);
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = graph_.find(file.pid);
    out.pid = file.pid;
    out.path = file.path;
    out.old_path = file.old_path;
    out.directory = file.directory;
    out.unavailable = file.unavailable;
    // The state after the event; a deleted or moved-away path legitimately has none.
    if (file.operation != file_operation::remove && !file.path.empty()) {
        struct stat info {};
        if (::lstat(file.path.c_str(), &info) == 0) {
            out.stat = file_stat{info.st_mode, info.st_uid, info.st_gid, static_cast<std::uint64_t>(info.st_size),
                                 info.st_ino, info.st_dev,
                                 static_cast<std::uint64_t>(info.st_mtim.tv_sec) * 1000000000ULL +
                                     static_cast<std::uint64_t>(info.st_mtim.tv_nsec)};
        } else {
            out.unavailable.push_back({"file.stat", unavailable_reason::object_gone});
        }
    }
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.file_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_loss(loss_report report) {
    const auto now = clock_domain::now_unix_ns();
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.loss(report, seq, now); });
    if (succeeded(emitted)) ++metrics_.loss_records;
    return emitted;
}

health_snapshot sensor_pipeline::health_now() const {
    health_snapshot snapshot;
    std::size_t active = 0U;
    std::size_t expected = 0U;
    std::vector<provider_health> reported;
    for (std::size_t index = 0U; index < providers_.size(); ++index) {
        const auto& source = providers_[index];
        if (!standby_[index].empty()) {
            // Not started on purpose: another provider of its family does the same job.
            reported.push_back({std::string{source->name()}, "standby", "superseded by " + standby_[index], source->capabilities(), 0U, 0U});
            continue;
        }
        ++expected;
        auto health = source->health();
        if (health.state == "active") ++active;
        reported.push_back(std::move(health));
    }
    // A capability is covered by the first active provider that offers it; capabilities nobody
    // active offers are listed as uncovered rather than omitted.
    for (const auto& health : reported) {
        if (health.state != "active") continue;
        for (const auto& capability : health.capabilities) snapshot.coverage.emplace(capability, health.name);
    }
    for (const auto& health : reported) {
        for (const auto& capability : health.capabilities) snapshot.coverage.emplace(capability, "");
    }
    for (auto& health : reported) snapshot.providers.push_back(std::move(health));
    // The procfs reconciler is always active: it discovers processes and infers missed exits.
    snapshot.coverage["process.discovered"] = "procfs";
    if (snapshot.coverage["process.exit"].empty()) snapshot.coverage["process.exit"] = "procfs";
    snapshot.providers.push_back({"procfs", "active", "", {"process.discovered", "process.exit", "state.processes"},
                                  graph_.metrics().discovered + graph_.metrics().reconciled_exits, 0U});
    snapshot.status = metrics_.sink_errors > 0U ? "degraded" : (active == expected ? "healthy" : "degraded");

    const auto statm = read_small_file("/proc/self/statm");
    unsigned long long size_pages = 0U;
    unsigned long long resident_pages = 0U;
    if (std::sscanf(statm.c_str(), "%llu %llu", &size_pages, &resident_pages) == 2) {
        snapshot.rss_bytes = resident_pages * static_cast<unsigned long long>(::sysconf(_SC_PAGESIZE));
    }
    rusage usage{};
    if (::getrusage(RUSAGE_SELF, &usage) == 0) {
        snapshot.cpu_milliseconds = static_cast<std::uint64_t>(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000U +
                                    static_cast<std::uint64_t>(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000U;
    }
    const auto wal = sink_.metrics();
    snapshot.wal_bytes = wal.bytes;
    snapshot.wal_records = wal.next_seq > wal.acknowledged_seq + 1U ? wal.next_seq - 1U - wal.acknowledged_seq : 0U;
    utsname names{};
    if (::uname(&names) == 0) snapshot.kernel_release = names.release;
    std::error_code ignored;
    snapshot.btf = std::filesystem::exists("/sys/kernel/btf/vmlinux", ignored);
    snapshot.bpf_lsm = read_small_file("/sys/kernel/security/lsm").find("bpf") != std::string::npos;
    snapshot.ringbuf = kernel_at_least(snapshot.kernel_release, 5, 8);
    return snapshot;
}

std::string sensor_pipeline::status_json() const {
    const std::lock_guard lock{status_mutex_};
    return status_cache_;
}

std::string sensor_pipeline::coverage_json() const {
    const std::lock_guard lock{status_mutex_};
    return coverage_cache_;
}

void sensor_pipeline::refresh_status(const std::uint64_t now_ns) {
    const auto snapshot = health_now();
    auto json = record_serializer::status_json(snapshot);
    auto coverage = record_serializer::coverage_json(snapshot);
    const std::lock_guard lock{status_mutex_};
    status_cache_ = std::move(json);
    coverage_cache_ = std::move(coverage);
    last_status_ns_ = now_ns;
}

result<bool> sensor_pipeline::emit_health(const std::uint64_t now_ns) {
    const auto snapshot = health_now();
    return emit([&](const std::uint64_t seq) { return serializer_.health(snapshot, seq, now_ns); });
}

result<bool> sensor_pipeline::emit_process_state(const std::uint64_t now_ns) {
    const auto live = graph_.live_entities();
    const auto parts = static_cast<std::uint32_t>(std::max<std::size_t>(1U, (live.size() + state_items_per_part - 1U) / state_items_per_part));
    const auto snapshot_id = serializer_.identity().sensor_id + "-processes-" + std::to_string(++snapshots_);
    result<bool> outcome = true;
    for (std::uint32_t part = 0U; part < parts; ++part) {
        const auto begin = live.begin() + static_cast<std::ptrdiff_t>(std::min(live.size(), part * state_items_per_part));
        const auto end = live.begin() + static_cast<std::ptrdiff_t>(std::min(live.size(), (part + 1U) * state_items_per_part));
        const std::vector<entity_ptr> items(begin, end);
        auto emitted = emit([&](const std::uint64_t seq) {
            return serializer_.process_state(items, snapshot_id, part + 1U, parts, seq, now_ns);
        });
        if (!succeeded(emitted)) outcome = emitted;
    }
    return outcome;
}

result<bool> sensor_pipeline::emit_host_state(const std::uint64_t now_ns) {
    host_state_options options;
    options.root = config_.host_root;
    result<bool> outcome = true;
    for (const auto object : state_objects()) {
        const auto collected = collect_state(object, options);
        if (!collected.has_value()) continue;
        const auto& items = collected->items;
        const auto parts = static_cast<std::uint32_t>(std::max<std::size_t>(1U, (items.size() + state_items_per_part - 1U) / state_items_per_part));
        const auto snapshot_id = serializer_.identity().sensor_id + "-" + std::string{object} + "-" + std::to_string(++snapshots_);
        for (std::uint32_t part = 0U; part < parts; ++part) {
            const auto first = std::min(items.size(), part * state_items_per_part);
            const auto last = std::min(items.size(), (part + 1U) * state_items_per_part);
            const std::span<const std::string> slice{items.data() + first, last - first};
            auto emitted = emit([&](const std::uint64_t seq) {
                return serializer_.host_state(*collected, slice, snapshot_id, part + 1U, parts, seq, now_ns);
            });
            if (!succeeded(emitted)) outcome = emitted;
        }
    }
    return outcome;
}

result<bool> sensor_pipeline::collect_losses(const std::uint64_t now_ns) {
    bool reconcile_now = false;
    if (const auto dropped = queue_.take_dropped(); dropped > 0U) {
        (void)emit_loss({"queue", dropped, {}, "record queue full; process state will be reconciled"});
        reconcile_now = true;
    }
    for (const auto& source : providers_) {
        if (const auto governed = source->take_governed(); governed > 0U) {
            (void)emit_loss({"governor", governed, {},
                             std::string{source->name()} + " exceeded its event budget; " + std::to_string(governed) + " event(s) skipped"});
        }
        if (const auto lost = source->take_losses(); lost > 0U) {
            (void)emit_loss({"kernel", lost, {},
                             std::string{source->name()} + " receive buffer overflowed " + std::to_string(lost) +
                                 " time(s); the number of lost events is unknown"});
            reconcile_now = true;
        }
    }
    for (const auto& loss : sink_.take_losses()) {
        loss_report report{"wal", loss.records, {{loss.reason, loss.records}}, {}};
        report.detail = loss.reason + ": seq " + std::to_string(loss.first_seq) +
                        (loss.last_seq != 0U ? "-" + std::to_string(loss.last_seq) : std::string{"+"}) + ", " +
                        std::to_string(loss.bytes) + " bytes";
        (void)emit_loss(std::move(report));
    }
    if (reconcile_now) {
        const auto unix_now = clock_domain::now_unix_ns();
        (void)emit_events(graph_.reconcile(unix_now), unix_now);
        ++metrics_.reconciles;
        last_reconcile_ns_ = now_ns;
    }
    return true;
}

result<bool> sensor_pipeline::start() {
    if (started_) return true;
    // Providers of one family are alternatives in preference order (e.g. eBPF before the proc
    // connector). The first that starts runs; later ones stay on standby so events are not
    // reported twice.
    std::map<std::string, std::string> running;  // family -> provider that serves it
    for (std::size_t index = 0U; index < providers_.size(); ++index) {
        auto& source = providers_[index];
        const std::string family{source->family()};
        if (!family.empty()) {
            if (const auto serving = running.find(family); serving != running.end()) {
                standby_[index] = serving->second;
                continue;
            }
        }
        if (const auto reason = source->probe(); !reason.empty()) continue;  // reported as unavailable in health
        if (succeeded(source->start(queue_)) && !family.empty()) running.emplace(family, std::string{source->name()});
    }
    const auto now = clock_domain::now_monotonic_ns();
    const auto unix_now = clock_domain::now_unix_ns();
    (void)graph_.reconcile(unix_now, false);
    ++metrics_.reconciles;
    (void)collect_losses(now);  // recovery losses from the WAL
    (void)emit_health(unix_now);
    (void)emit_process_state(unix_now);
    (void)emit_host_state(unix_now);
    last_reconcile_ns_ = last_health_ns_ = last_state_ns_ = last_resample_ns_ = now;
    refresh_status(now);
    started_ = true;
    return sink_.flush(now, true);
}

result<bool> sensor_pipeline::step(const std::uint64_t now_ns, const std::chrono::milliseconds wait) {
    if (now_ns - last_resample_ns_ >= 60U * ns_per_second) {
        clock_.resample();
        last_resample_ns_ = now_ns;
    }
    batch_.clear();
    queue_.pop_batch(batch_, 1024U, wait, wait.count() > 0 ? batch_linger : std::chrono::milliseconds{0});
    const auto observed = clock_domain::now_unix_ns();
    for (const auto& record : batch_) process_record(record, observed);
    (void)collect_losses(now_ns);

    if (now_ns - last_reconcile_ns_ >= config_.reconcile_interval_seconds * ns_per_second) {
        const auto unix_now = clock_domain::now_unix_ns();
        (void)emit_events(graph_.reconcile(unix_now), unix_now);
        graph_.purge(unix_now);
        ++metrics_.reconciles;
        last_reconcile_ns_ = now_ns;
    }
    if (now_ns - last_health_ns_ >= config_.health_interval_seconds * ns_per_second) {
        (void)emit_health(clock_domain::now_unix_ns());
        last_health_ns_ = now_ns;
    }
    if (now_ns - last_state_ns_ >= config_.state_interval_seconds * ns_per_second) {
        const auto unix_now = clock_domain::now_unix_ns();
        (void)emit_process_state(unix_now);
        (void)emit_host_state(unix_now);
        last_state_ns_ = now_ns;
    }
    if (now_ns - last_status_ns_ >= ns_per_second) refresh_status(now_ns);
    return sink_.flush(now_ns, false);
}

result<bool> sensor_pipeline::run(const std::atomic<bool>& stop, const std::uint64_t deadline_ns) {
    while (!stop.load(std::memory_order_relaxed)) {
        const auto now = clock_domain::now_monotonic_ns();
        if (deadline_ns != 0U && now >= deadline_ns) break;
        if (auto stepped = step(now, std::chrono::milliseconds{200}); !succeeded(stepped)) {
            ++metrics_.sink_errors;  // keep running: a full or failing disk must not stop collection
        }
    }
    return sink_.flush(clock_domain::now_monotonic_ns(), true);
}

void sensor_pipeline::shutdown() {
    if (!started_) return;
    started_ = false;
    for (auto& source : providers_) source->stop();
    // Drain what the providers queued before stopping.
    while (queue_.depth() > 0U) {
        batch_.clear();
        queue_.pop_batch(batch_, 1024U, std::chrono::milliseconds{0});
        const auto observed = clock_domain::now_unix_ns();
        for (const auto& record : batch_) process_record(record, observed);
    }
    (void)emit_health(clock_domain::now_unix_ns());
    (void)sink_.flush(clock_domain::now_monotonic_ns(), true);
}

}  // namespace panopticon::linux_agent::sensor
