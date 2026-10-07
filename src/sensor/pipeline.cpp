#include "panopticon/linux_agent/sensor/pipeline.hpp"

#include "panopticon/linux_agent/durable_file.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"
#include "panopticon/linux_agent/trusted_path.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>
#include <sys/resource.h>
#include <fcntl.h>
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
    constexpr std::array<std::string_view, 50U> allowed{
        "policy_path", "policy_signing_keys", "policy_check_seconds",
        "integrity_manifest", "integrity_keys", "integrity_check_seconds",
        "sensor_id", "host_id", "wal_path", "wal_quota_bytes", "wal_segment_bytes", "queue_capacity",
        "reconcile_interval_seconds", "health_interval_seconds", "state_interval_seconds", "collect_environment",
        "maximum_args", "maximum_args_bytes", "maximum_entities", "proc_root", "enable_ebpf", "enable_file_events",
        "file_include", "file_exclude", "enable_fim", "fim_path", "fim_interval_seconds", "enable_hashing", "hash_max_file_bytes",
        "hash_bytes_per_second", "enable_network_events", "enable_auth_events", "enable_kernel_events", "enable_security_events", "enable_sensitive_file_events", "manager_url", "identity_path", "ca_bundle",
        "response_mode", "response_actions", "response_poll_seconds", "response_max_lifetime_seconds",
        "response_max_changes_per_minute", "response_ledger_path", "response_require_boot_binding", "response_signing_keys",
        "response_allow_unsigned", "response_file_roots", "response_quarantine_dir",
        "response_isolation_socket"};
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
    config.manager_url = text("manager_url").value_or("");
    if (const auto value = text("identity_path"); value.has_value()) config.identity_path = *value;
    if (const auto value = text("ca_bundle"); value.has_value()) config.ca_bundle = *value;
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
    if (const auto value = text("response_require_boot_binding"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.response_require_boot_binding = *value == "true";
    }
    if (const auto value = text("response_allow_unsigned"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.response_allow_unsigned = *value == "true";
#ifndef PANOPTICON_LAB_UNSIGNED_COMMANDS
        // Not a configuration mistake to be tolerated: this binary has no unsigned mode at all (ADR 034).
        if (config.response_allow_unsigned) {
            return error{error_code::invalid_input, "response_allow_unsigned=true is not available: this sensor was built without lab unsigned-command support"};
        }
#endif
    }
    if (const auto value = text("response_file_roots"); value.has_value()) {
        std::istringstream stream{*value};
        std::string item;
        while (std::getline(stream, item, ',')) {
            item = std::string{trim(item)};
            const std::filesystem::path root{item};
            const bool bad = item.empty() || !root.is_absolute() || item.find("..") != std::string::npos || root.lexically_normal() == "/" ||
                             std::find(config.response_file_roots.begin(), config.response_file_roots.end(), root) != config.response_file_roots.end();
            if (bad) valid = false;
            else config.response_file_roots.push_back(root);
        }
        if (config.response_file_roots.empty()) valid = false;
    }
    if (const auto value = text("response_quarantine_dir"); value.has_value()) {
        config.response_quarantine_dir = *value;
        if (!config.response_quarantine_dir.is_absolute() || value->find("..") != std::string::npos) valid = false;
    }
    if (const auto value = text("response_isolation_socket"); value.has_value()) {
        config.response_isolation_socket = *value;
        // sockaddr_un::sun_path holds 108 bytes including the terminator.
        if (!config.response_isolation_socket.is_absolute() || value->find("..") != std::string::npos || value->size() >= 108U) valid = false;
    }
    if (const auto value = text("response_signing_keys"); value.has_value()) {
        config.response_signing_keys = *value;
        if (!config.response_signing_keys.is_absolute() || value->find("..") != std::string::npos) valid = false;
    }
    // A policy without pinned keys could never be accepted, and keys without a policy are a mistake: both or neither.
    for (const auto& [key, target] : {std::pair{"policy_path", &config.policy_path}, std::pair{"policy_signing_keys", &config.policy_signing_keys}}) {
        if (const auto value = text(key); value.has_value()) {
            *target = *value;
            if (!target->is_absolute() || value->find("..") != std::string::npos) valid = false;
        }
    }
    if (config.policy_path.empty() != config.policy_signing_keys.empty()) valid = false;
    number("policy_check_seconds", config.policy_check_seconds, 5U, 3600U);
    // A manifest without a pinned key could never verify, and a key without a manifest is a mistake: both or neither.
    for (const auto& [key, target] : {std::pair{"integrity_manifest", &config.integrity_manifest}, std::pair{"integrity_keys", &config.integrity_keys}}) {
        if (const auto value = text(key); value.has_value()) {
            *target = *value;
            if (!target->is_absolute() || value->find("..") != std::string::npos) valid = false;
        }
    }
    if (config.integrity_manifest.empty() != config.integrity_keys.empty()) valid = false;
    number("integrity_check_seconds", config.integrity_check_seconds, 5U, 3600U);
    if (const auto value = text("enable_ebpf"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_ebpf = *value == "true";
    }
    if (const auto value = text("enable_file_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_file_events = *value == "true";
    }
    if (const auto value = text("enable_sensitive_file_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_sensitive_file_events = *value == "true";
    }
    if (const auto value = text("enable_network_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_network_events = *value == "true";
    }
    if (const auto value = text("enable_auth_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_auth_events = *value == "true";
    }
    if (const auto value = text("enable_security_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_security_events = *value == "true";
    }
    if (const auto value = text("enable_kernel_events"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_kernel_events = *value == "true";
    }
    config.enable_fim = true;
    config.fim_path = config.wal_path.parent_path() / "fim.baseline";
    number("fim_interval_seconds", config.fim_interval_seconds, 60U, 86400U);
    config.enable_hashing = true;
    number("hash_max_file_bytes", config.hash_max_file_bytes, 1ULL << 20U, 1ULL << 32U);
    number("hash_bytes_per_second", config.hash_bytes_per_second, 1ULL << 20U, 1ULL << 30U);
    if (const auto value = text("enable_hashing"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_hashing = *value == "true";
    }
    if (const auto value = text("enable_fim"); value.has_value()) {
        if (*value != "true" && *value != "false") valid = false;
        config.enable_fim = *value == "true";
    }
    if (const auto value = text("fim_path"); value.has_value()) {
        config.fim_path = *value;
        if (!config.fim_path.is_absolute() || value->find("..") != std::string::npos) valid = false;
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
    // Manager commands: off unless asked for, and only with delivery configured (the same enrolled
    // identity and https URL authenticate both directions).
    number("response_poll_seconds", config.response_poll_seconds, 1U, 300U);
    number("response_max_lifetime_seconds", config.response_max_lifetime_seconds, 30U, 86400U);
    number("response_max_changes_per_minute", config.response_max_changes_per_minute, 1U, 600U);
    if (const auto value = text("response_mode"); value.has_value()) {
        if (*value != "off" && *value != "dry_run" && *value != "enforce") valid = false;
        config.response_mode = *value;
    }
    if (const auto value = text("response_actions"); value.has_value()) {
        // Only actions this sensor implements may be listed; the Manager's other names are not valid here.
        config.response_actions.clear();
        std::istringstream stream{*value};
        std::string item;
        while (std::getline(stream, item, ',')) {
            item = std::string{trim(item)};
            const auto action = parse_command_action(item);
            if (!action || !command_action_implemented(*action) ||
                std::find(config.response_actions.begin(), config.response_actions.end(), item) != config.response_actions.end()) {
                valid = false;
            } else {
                config.response_actions.push_back(item);
            }
        }
        if (config.response_actions.empty()) valid = false;
    }
    if (const auto value = text("response_ledger_path"); value.has_value()) {
        config.response_ledger_path = *value;
        if (!config.response_ledger_path.is_absolute() || value->find("..") != std::string::npos) valid = false;
    }
    if (config.response_mode != "off" && config.manager_url.empty()) valid = false;
    // Quarantine is the one action that moves a file; it acts only where the operator said it may.
    const bool quarantine_listed = std::find(config.response_actions.begin(), config.response_actions.end(), "QUARANTINE_FILE") != config.response_actions.end();
    if (quarantine_listed != !config.response_file_roots.empty()) valid = false;
    // Isolation is both directions or neither: an endpoint that can cut itself off must be able to be released,
    // and either action without a helper to ask would be a promise it cannot keep.
    const auto listed = [&](const char* name) {
        return std::find(config.response_actions.begin(), config.response_actions.end(), name) != config.response_actions.end();
    };
    const bool isolate_listed = listed("ISOLATE_HOST");
    if (isolate_listed != listed("RELEASE_HOST_ISOLATION") || isolate_listed != !config.response_isolation_socket.empty()) valid = false;
    // Commands are acted on only when signed by a pinned key, or when the operator said in so many words that
    // unsigned commands are acceptable (a lab). There is no silent default to trusting the channel alone.
    if (config.response_mode != "off" && config.response_signing_keys.empty() && !config.response_allow_unsigned) valid = false;
    if (!config.response_signing_keys.empty() && config.response_allow_unsigned) valid = false;
    // Delivery needs an https URL and an identity file together; a private CA must be absolute.
    if (config.manager_url.empty() != config.identity_path.empty()) valid = false;
    if (!config.manager_url.empty() && config.manager_url.rfind("https://", 0U) != 0U) valid = false;
    if (!config.identity_path.empty() && !config.identity_path.is_absolute()) valid = false;
    if (!config.ca_bundle.empty() && !config.ca_bundle.is_absolute()) valid = false;
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
    // The configuration decides what the sensor trusts and does (command mode, signing keys, CA), so anyone who can
    // edit it or replace it by writing to its directory controls the sensor.
    if (const auto reason = untrusted_path_reason(path); !reason.empty()) {
        return error{error_code::invalid_input, "configuration is not trustworthy: " + reason};
    }
    auto parsed = parse_sensor_config(read_small_file(path));
    // The CA bundle decides which server may speak as the Manager (records go there, commands come from there).
    if (succeeded(parsed) && !std::get<sensor_config>(parsed).ca_bundle.empty()) {
        if (const auto reason = untrusted_path_reason(std::get<sensor_config>(parsed).ca_bundle); !reason.empty()) {
            return error{error_code::invalid_input, "ca_bundle is not trustworthy: " + reason};
        }
    }
    return parsed;
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
      standby_(providers_.size()),
      boot_id_{identity.boot_id} {}

sensor_pipeline::~sensor_pipeline() { shutdown(); }

result<bool> sensor_pipeline::emit(const std::function<std::string(std::uint64_t)>& serialise) {
    const auto seq = sink_.next_seq();
    const auto record = serialise(seq);
    auto appended = sink_.append(seq, record);
    if (!succeeded(appended)) {
        ++metrics_.sink_errors;
        ++metrics_.records_unwritten;
        write_failed_ = true;
        last_write_error_ = std::get<error>(appended).message;
        if (std::get<error>(appended).code == error_code::resource_limit) ++metrics_.oversize_dropped;
        return appended;
    }
    write_failed_ = false;
    ++metrics_.records;
    last_emitted_seq_ = seq;
    return true;
}

void sensor_pipeline::refresh_policy(const std::uint64_t unix_now_ns) {
    if (!policy_) return;
    const auto now = static_cast<std::int64_t>(unix_now_ns / ns_per_second);
    for (const auto& change : policy_->refresh(now)) {
        (void)emit([&](const std::uint64_t seq) { return serializer_.policy_change_event(change, seq, unix_now_ns); });
    }
    const auto* active = policy_->active(now);
    policy_expires_unix_ = active != nullptr ? active->header.expires_unix : 0;
    // Every record names the policy that decided about it, or "none" (none accepted, or the one accepted expired).
    serializer_.set_policy_version(active != nullptr ? active->header.policy_id + "/" + std::to_string(active->header.version) : "none");
}

void sensor_pipeline::note_integrity_writer(const std::string& path, const std::string_view operation, const entity_ptr& actor, const std::uint32_t pid,
                                            const std::uint64_t time_unix_ns) {
    if (integrity_watched_.count(path) == 0U) return;
    // One entry per watched path (the manifest lists at most maximum_manifest_entries), so this cannot grow.
    integrity_writers_[path] = integrity_writer{actor, pid, std::string{operation}, time_unix_ns};
}

void sensor_pipeline::refresh_integrity(const std::uint64_t unix_now_ns) {
    if (!integrity_) return;
    for (const auto& change : integrity_->refresh(static_cast<std::int64_t>(unix_now_ns / ns_per_second))) {
        tamper_record record;
        record.change = change;
        // Who last touched the file, if a file event saw it. A restored finding is not attributed.
        if (change.status == "violated") {
            if (const auto writer = integrity_writers_.find(change.finding.target); writer != integrity_writers_.end()) {
                record.actor = writer->second.actor;
                record.actor_pid = writer->second.pid;
                record.last_operation = writer->second.operation;
                record.last_change_unix_ns = writer->second.time_unix_ns;
            }
        }
        if (succeeded(emit([&](const std::uint64_t seq) { return serializer_.tamper_integrity_event(record, seq, unix_now_ns); }))) ++metrics_.tamper_records;
    }
    integrity_watched_ = integrity_->watched_paths();
}

void sensor_pipeline::evaluate_policy(const policy_input& input, const entity_ptr& actor, const std::uint32_t pid, const std::uint64_t time_unix_ns,
                                      const std::string_view subject_type, const std::uint64_t observed_ns, const std::optional<policy_field> only) {
    if (!policy_) return;
    const auto* active = policy_->active(static_cast<std::int64_t>(observed_ns / ns_per_second));
    if (active == nullptr) return;
    const auto subject_seq = last_emitted_seq_;
    for (auto& decision : active->engine.evaluate(input, only)) {
        policy_match_record record;
        record.time_unix_ns = time_unix_ns;
        record.actor = actor;
        record.pid = pid;
        record.policy_id = active->header.policy_id;
        record.policy_version = active->header.version;
        record.decision = std::move(decision);
        record.subject_type = std::string{subject_type};
        record.subject_seq = subject_seq;
        if (succeeded(emit([&](const std::uint64_t seq) { return serializer_.policy_match(record, seq, observed_ns); }))) {
            ++metrics_.events;
            ++metrics_.policy_matches;
        }
    }
}

process_event sensor_pipeline::with_executable_hash(const process_event& event) {
    process_event copy = event;
    const auto& info = event.process->info;
    const auto& image = info.executable;
    if (image.kind != executable_kind::file && image.kind != executable_kind::deleted && image.kind != executable_kind::memfd) {
        return copy;
    }
    // Open the image through the process now: the descriptor names the file that was executed
    // even if the path is replaced or removed before the worker gets to it. An image that was
    // never identified (the process exited first) is not opened by path: there is no identity to
    // verify, so the hash is reported as unreadable rather than guessed.
    int fd = image.known ? ::open((config_.proc_root / std::to_string(info.pid) / "exe").c_str(), O_RDONLY | O_CLOEXEC) : -1;
    if (fd >= 0) {
        struct stat opened {};
        if (::fstat(fd, &opened) != 0 || static_cast<std::uint64_t>(opened.st_dev) != image.dev ||
            static_cast<std::uint64_t>(opened.st_ino) != image.inode) {
            ::close(fd);  // the process executed something else in the meantime
            fd = -1;
        }
    }
    hash_subject subject;
    subject.entity_id = event.process->entity_id;
    subject.pid = info.pid;
    subject.exec_gen = event.process->exec_gen;
    subject.path = image.path;
    subject.key = {image.dev, image.inode, image.size, image.mtime_ns};
    subject.event_type = event.type;
    copy.executable_hash = hashes_->submit(std::move(subject), fd);
    return copy;
}

result<bool> sensor_pipeline::emit_hash_results(const std::uint64_t observed_ns) {
    result<bool> outcome = true;
    if (!hashes_) return outcome;
    for (const auto& finished : hashes_->drain()) {
        auto emitted = emit([&](const std::uint64_t seq) { return serializer_.hash_computed(finished, seq, observed_ns); });
        if (!succeeded(emitted)) {
            outcome = emitted;
            continue;
        }
        ++metrics_.events;
        if (policy_ && finished.hash.status == "computed" && !finished.hash.sha256.empty()) {
            // Decided as part of the event that asked for the hash (so `allow exe` applies), but only on the hash:
            // its executable and command line were decided when that event was written.
            policy_input input;
            input.kind = finished.subject.event_type.empty() ? std::string{"process.exec"} : finished.subject.event_type;
            input.exe = finished.subject.path;
            input.sha256 = finished.hash.sha256;
            entity_ptr actor = graph_.find(finished.subject.pid);
            if (actor && (actor->entity_id != finished.subject.entity_id || actor->exec_gen != finished.subject.exec_gen)) actor = nullptr;
            evaluate_policy(input, actor, finished.subject.pid, observed_ns, "hash.computed", observed_ns, policy_field::sha256);
        }
    }
    return outcome;
}

result<bool> sensor_pipeline::emit_events(const std::vector<process_event>& events, const std::uint64_t observed_ns) {
    result<bool> outcome = true;
    for (const auto& original : events) {
        const bool hashable = hashes_ && original.process && (original.type == "process.exec" || original.type == "process.discovered");
        const process_event hashed = hashable ? with_executable_hash(original) : process_event{};
        const auto& event = hashable ? hashed : original;
        auto emitted = emit([&](const std::uint64_t seq) { return serializer_.event(event, seq, observed_ns); });
        if (!succeeded(emitted)) {
            outcome = emitted;
            continue;
        }
        ++metrics_.events;
        if (policy_ && event.process && (event.type == "process.exec" || event.type == "process.discovered")) {
            const auto& info = event.process->info;
            policy_input input;
            input.kind = event.type;
            input.exe = info.executable.path;
            for (const auto& arg : info.args) {
                if (!input.cmdline.empty()) input.cmdline += ' ';
                input.cmdline += arg;
            }
            // A hash already known (cache) is decided now; one still being computed when hash.computed arrives.
            if (event.executable_hash && event.executable_hash->status == "computed") input.sha256 = event.executable_hash->sha256;
            evaluate_policy(input, event.process, info.pid, event.time_unix_ns, event.type, observed_ns);
        }
    }
    for (const auto& lifecycle : containers_.observe(events)) {
        auto emitted = emit([&](const std::uint64_t seq) { return serializer_.container_event(lifecycle, seq, observed_ns); });
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
    if (const auto* network = std::get_if<raw_network_event>(&record.payload)) {
        (void)emit_network_event(record, *network, observed_ns);
        return;
    }
    if (const auto* auth = std::get_if<raw_auth_event>(&record.payload)) {
        (void)emit_auth_event(record, *auth, observed_ns);
        return;
    }
    if (const auto* kernel = std::get_if<raw_kernel_event>(&record.payload)) {
        (void)emit_kernel_event(record, *kernel, observed_ns);
        return;
    }
    if (const auto* security = std::get_if<raw_security_event>(&record.payload)) {
        (void)emit_security_event(record, *security, observed_ns);
        return;
    }
    if (const auto* dns = std::get_if<raw_dns_query>(&record.payload)) {
        (void)emit_dns_event(record, *dns, observed_ns);
        return;
    }
    if (const auto* lsm = std::get_if<raw_lsm_event>(&record.payload)) {
        (void)emit_lsm_event(record, *lsm, observed_ns);
        return;
    }
    if (const auto* firewall = std::get_if<raw_firewall_change>(&record.payload)) {
        (void)emit_firewall_event(record, *firewall, observed_ns);
        return;
    }
    if (const auto* response = std::get_if<raw_response_action>(&record.payload)) {
        (void)emit_response_event(record, *response, observed_ns);
        return;
    }
    (void)emit_events(graph_.apply(record), observed_ns);
}

result<bool> sensor_pipeline::emit_auth_event(const raw_record& record, const raw_auth_event& auth, const std::uint64_t observed_ns) {
    auth_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = auth.pid != 0U ? graph_.find(auth.pid) : nullptr;
    out.auth = auth;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.auth_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_kernel_event(const raw_record& record, const raw_kernel_event& kernel, const std::uint64_t observed_ns) {
    kernel_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.kernel = kernel;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.kernel_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_security_event(const raw_record& record, const raw_security_event& security, const std::uint64_t observed_ns) {
    security_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = security.pid != 0U ? graph_.find(security.pid) : nullptr;
    out.security = security;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.security_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_dns_event(const raw_record& record, const raw_dns_query& dns, const std::uint64_t observed_ns) {
    dns_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = dns.pid != 0U ? graph_.find(dns.pid) : nullptr;
    out.dns = dns;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.dns_event(out, seq, observed_ns); });
    if (!succeeded(emitted)) return emitted;
    ++metrics_.events;
    if (policy_ && !dns.name.empty()) {
        policy_input input;
        input.kind = "dns.query";
        if (out.actor) input.exe = out.actor->info.executable.path;
        input.dest_domain = dns.name.back() == '.' ? dns.name.substr(0U, dns.name.size() - 1U) : dns.name;
        evaluate_policy(input, out.actor, dns.pid, record.time_unix_ns, "dns.query", observed_ns);
    }
    return emitted;
}

result<bool> sensor_pipeline::emit_lsm_event(const raw_record& record, const raw_lsm_event& lsm, const std::uint64_t observed_ns) {
    lsm_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = lsm.pid != 0U ? graph_.find(lsm.pid) : nullptr;
    out.lsm = lsm;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.lsm_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_firewall_event(const raw_record& record, const raw_firewall_change& firewall, const std::uint64_t observed_ns) {
    firewall_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = firewall.pid != 0U ? graph_.find(firewall.pid) : nullptr;
    out.firewall = firewall;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.firewall_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_response_event(const raw_record& record, const raw_response_action& response, const std::uint64_t observed_ns) {
    if (response.evidence) {
        // What a collection command gathered, as a state snapshot. It precedes the audit record that
        // names it, so a reader that has the record has already been sent the evidence.
        state_snapshot snapshot;
        snapshot.object = response.evidence->object;
        snapshot.provider = record.source.provider;
        snapshot.mechanism = response.evidence->mechanism;
        snapshot.unavailable = response.evidence->unavailable;
        snapshot.truncated = std::any_of(snapshot.unavailable.begin(), snapshot.unavailable.end(), [](const unavailable_field& f) { return f.reason == unavailable_reason::truncated; });
        const auto& items = response.evidence->items;
        const auto parts = static_cast<std::uint32_t>(std::max<std::size_t>(1U, (items.size() + state_items_per_part - 1U) / state_items_per_part));
        for (std::uint32_t part = 0U; part < parts; ++part) {
            const auto first = std::min<std::size_t>(items.size(), static_cast<std::size_t>(part) * state_items_per_part);
            const auto last = std::min<std::size_t>(items.size(), static_cast<std::size_t>(part + 1U) * state_items_per_part);
            const std::span<const std::string> slice{items.data() + first, last - first};
            auto emitted = emit([&](const std::uint64_t seq) {
                return serializer_.host_state(snapshot, slice, response.evidence->snapshot_id, part + 1U, parts, seq, observed_ns);
            });
            if (!succeeded(emitted)) return emitted;
        }
    }
    response_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    if (response.pid != 0U) {
        // The entity for this pid, only when it is the instance the command named. After a reuse the
        // graph holds a different process under the same pid and it is not the command's target.
        const auto known = graph_.find(response.pid);
        if (known && known->info.start_ticks == response.start_ticks) out.target = known;
    }
    out.response = response;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.response_event(out, seq, observed_ns); });
    if (succeeded(emitted)) ++metrics_.events;
    return emitted;
}

result<bool> sensor_pipeline::emit_network_event(const raw_record& record, const raw_network_event& network, const std::uint64_t observed_ns) {
    network_record out;
    out.time_unix_ns = record.time_unix_ns;
    out.source = record.source;
    out.actor = network.pid != 0U ? graph_.find(network.pid) : nullptr;
    out.network = network;
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.network_event(out, seq, observed_ns); });
    if (!succeeded(emitted)) return emitted;
    ++metrics_.events;
    // The far end of a connection in either direction; a listener has none, and a close repeats its open.
    const bool has_peer = network.operation == network_operation::connect || network.operation == network_operation::accept ||
                          network.operation == network_operation::udp_flow;
    if (policy_ && has_peer && !network.remote_address.empty()) {
        policy_input input;
        input.kind = std::string{"network."} + to_string(network.operation);
        if (out.actor) input.exe = out.actor->info.executable.path;
        input.dest_ip = network.remote_address;
        evaluate_policy(input, out.actor, network.pid, record.time_unix_ns, input.kind, observed_ns);
    }
    return emitted;
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
    if (succeeded(emitted)) {
        ++metrics_.events;
        if (policy_ && !file.path.empty()) {
            policy_input input;
            input.kind = out.type;
            if (out.actor) input.exe = out.actor->info.executable.path;
            input.file_path = file.path;
            evaluate_policy(input, out.actor, file.pid, record.time_unix_ns, out.type, observed_ns);
        }
    }
    if (integrity_ && succeeded(emitted) && file.operation != file_operation::open_sensitive) {
        note_integrity_writer(file.path, to_string(file.operation), out.actor, file.pid, record.time_unix_ns);
        if (file.old_path.has_value()) note_integrity_writer(*file.old_path, to_string(file.operation), out.actor, file.pid, record.time_unix_ns);
    }
    if (fim_ && file.pid != 0U && file.operation != file_operation::open_sensitive) (void)fim_->note(file.path, file.old_path, file.pid, record.time_unix_ns, clock_domain::now_monotonic_ns());
    return emitted;
}

result<bool> sensor_pipeline::emit_loss(loss_report report) {
    const auto now = clock_domain::now_unix_ns();
    auto emitted = emit([&](const std::uint64_t seq) { return serializer_.loss(report, seq, now); });
    if (succeeded(emitted)) {
        ++metrics_.loss_records;
        written_losses_.push_back({last_emitted_seq_, report});
        constexpr std::size_t maximum_tracked = 8192U;
        if (written_losses_.size() > maximum_tracked) {
            // Fold the oldest entry into the next of its stage (it keeps the older seq, so it is carried as soon as that
            // one is dropped, possibly while the newer record still exists: an over-report, never an under-report).
            const auto next = std::find_if(written_losses_.begin() + 1, written_losses_.end(),
                                           [&](const written_loss& other) { return other.report.stage == written_losses_.front().report.stage; });
            if (next != written_losses_.end()) {
                written_losses_.front().report.count += next->report.count;
                for (const auto& [name, count] : next->report.by_type) written_losses_.front().report.by_type[name] += count;
                written_losses_.erase(next);
            } else {
                written_losses_.erase(written_losses_.begin());
            }
        }
        return emitted;
    }
    // Keep the report and write it once the sink accepts records again. It is not an unwritten
    // data record, so it does not count towards records_unwritten while it waits.
    --metrics_.records_unwritten;
    constexpr std::size_t maximum_pending = 64U;
    if (pending_losses_.size() < maximum_pending) pending_losses_.push_back(std::move(report));
    else pending_losses_.back().count += report.count;
    return emitted;
}

// A range the log dropped may hold loss records this process wrote: what they reported would vanish with them. Write it
// again, one record per stage with the summed count, so the newest loss records always explain the whole gap. For the
// "wal" stage the count is a number of sequence numbers; the dropped loss record's own seq is inside the range being
// reported now, so every missing seq is still counted exactly once.
void sensor_pipeline::carry_dropped_loss_reports(const std::vector<wal_loss>& dropped) {
    std::map<std::string, loss_report> carried;
    std::map<std::string, std::uint64_t> reports;
    for (const auto& loss : dropped) {
        if (loss.last_seq == 0U) continue;  // open ended (a torn tail at recovery): nothing this process wrote
        for (auto entry = written_losses_.begin(); entry != written_losses_.end();) {
            if (entry->seq < loss.first_seq || entry->seq > loss.last_seq) {
                ++entry;
                continue;
            }
            auto& into = carried[entry->report.stage];
            if (into.stage.empty()) {
                into.stage = entry->report.stage;
                into.detail = entry->report.detail;
            }
            into.count += entry->report.count;
            for (const auto& [name, count] : entry->report.by_type) into.by_type[name] += count;
            ++reports[entry->report.stage];
            entry = written_losses_.erase(entry);
        }
    }
    for (auto& [stage, report] : carried) {
        constexpr std::size_t maximum_detail = 160U;
        report.detail = "carried forward: " + std::to_string(reports[stage]) + " earlier " + stage +
                        " loss record(s) were removed from the write-ahead log before delivery; the first said: " + report.detail.substr(0U, maximum_detail);
        (void)emit_loss(std::move(report));
    }
}

void sensor_pipeline::write_instance_marker(const std::uint64_t unix_now, const bool clean) {
    if (config_.instance_state_path.empty()) return;
    const std::string content = "panopticon-instance 1\nboot_id=" + boot_id_ + "\nstarted_unix_ns=" + std::to_string(instance_started_unix_ns_) +
                                "\nalive_unix_ns=" + std::to_string(unix_now) + "\nclean=" + (clean ? "1" : "0") + "\n";
    // Durable on purpose: a marker that still says "clean" after a power loss would hide the very gap it exists
    // to report. The cost is one small fsync every heartbeat interval.
    (void)write_file_durably(config_.instance_state_path, content, 0600U);
}

void sensor_pipeline::begin_instance(const std::uint64_t unix_now) {
    if (config_.instance_state_path.empty()) return;
    instance_started_unix_ns_ = unix_now;
    std::error_code ignored;
    if (std::filesystem::exists(config_.instance_state_path, ignored)) {
        const auto text = read_small_file(config_.instance_state_path);
        std::map<std::string, std::string> fields;
        std::istringstream lines{text};
        std::string line;
        std::getline(lines, line);
        const bool recognised = line == "panopticon-instance 1";
        while (std::getline(lines, line)) {
            if (const auto equals = line.find('='); equals != std::string::npos) fields[line.substr(0U, equals)] = line.substr(equals + 1U);
        }
        const auto clean = fields.find("clean");
        if (!recognised || clean == fields.end() || clean->second != "1") {
            // Not "clean=1": the previous process was killed, crashed, lost power, or its marker is unreadable.
            // All of those are unobserved intervals the sequence numbers do not show.
            std::uint64_t last_alive_ns = 0U;
            bool alive_known = false;
            if (recognised) {
                if (const auto parsed = integer<std::uint64_t>(fields["alive_unix_ns"])) {
                    last_alive_ns = *parsed;
                    alive_known = true;
                }
            }
            std::string detail = "the previous sensor process did not shut down cleanly (killed, crashed, or lost power)";
            if (alive_known) {
                detail += "; it was last known to be running at unix time " + std::to_string(last_alive_ns / ns_per_second) + " s and this instance started at " +
                          std::to_string(unix_now / ns_per_second) + " s";
                if (unix_now >= last_alive_ns) detail += ", so up to " + std::to_string((unix_now - last_alive_ns) / ns_per_second) + " s of activity were not observed";
            } else {
                detail += "; its state marker could not be read, so the length of the gap is unknown";
            }
            if (recognised && fields["boot_id"] != boot_id_) detail += "; the host rebooted in between";
            detail += ". The count is 1 interval, not a number of events";
            (void)emit_loss({"sensor_gap", 1U, {}, detail});
        }
    }
    write_instance_marker(unix_now, false);
    last_instance_marker_ns_ = clock_domain::now_monotonic_ns();
}

health_snapshot sensor_pipeline::health_now() const {
    health_snapshot snapshot;
    std::size_t active = 0U;
    std::size_t expected = 0U;
    std::vector<provider_health> reported;
    std::map<std::string, int> family_seen;
    for (std::size_t index = 0U; index < providers_.size(); ++index) {
        const auto& source = providers_[index];
        const std::string family{source->family()};
        // Providers of a family are listed in preference order: the first is the primary mechanism.
        const auto* tier = family.empty() || family_seen[family]++ == 0 ? "primary" : "fallback";
        if (!standby_[index].empty()) {
            // Not started on purpose: another provider of its family does the same job.
            reported.push_back({std::string{source->name()}, "standby", "superseded by " + standby_[index], source->capabilities(), 0U, 0U, family, tier});
            continue;
        }
        ++expected;
        auto health = source->health();
        health.family = family;
        health.tier = tier;
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
    if (policy_) {
        // A configured policy that is not in force (refused, expired, missing keys) is lost protection, not a detail.
        const auto policy = policy_->health(static_cast<std::int64_t>(clock_domain::now_unix_ns() / ns_per_second));
        snapshot.providers.push_back({"policy", policy.state, policy.reason, {"policy.match"}, metrics_.policy_matches, 0U});
        snapshot.coverage["policy.match"] = policy.state == "active" ? "policy" : "";
        if (policy.state != "active") snapshot.status = "degraded";
    }
    if (integrity_) {
        // Installed files that differ from the signed manifest are lost trust in the sensor itself, not a detail.
        const auto integrity = integrity_->health();
        snapshot.providers.push_back({"integrity", integrity.state, integrity.reason, {"tamper.integrity"}, metrics_.tamper_records, 0U});
        snapshot.coverage["tamper.integrity"] = integrity.state == "active" ? "integrity" : "";
        if (integrity.state != "active") snapshot.status = "degraded";
    }

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
    snapshot.wal_next_seq = wal.next_seq;
    snapshot.wal_durable_seq = wal.durable_seq;
    snapshot.wal_acknowledged_seq = wal.acknowledged_seq;
    snapshot.wal_dropped_records = wal.dropped_records;
    snapshot.records_total = metrics_.records;
    snapshot.events_total = metrics_.events;
    snapshot.loss_records_total = metrics_.loss_records;
    snapshot.sink_errors = metrics_.sink_errors;
    snapshot.uptime_ms = started_ns_ == 0U ? 0U : (clock_domain::now_monotonic_ns() - started_ns_) / 1'000'000U;
    if (delivery_probe_) {
        snapshot.delivery = delivery_probe_();
        snapshot.delivery.configured = true;
        // A transport that cannot deliver, or that threw records away, is a degraded sensor.
        if (snapshot.delivery.state != "idle" && snapshot.delivery.state != "delivering" && snapshot.status == "healthy") snapshot.status = "degraded";
        if (snapshot.delivery.records_quarantined > 0U && snapshot.status == "healthy") snapshot.status = "degraded";
    }
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
    constexpr std::uint64_t package_inventory_interval_ns = 24ULL * 3600ULL * 1'000'000'000ULL;
    for (const auto object : state_objects()) {
        bool inventory = true;
        if (object == "packages") {
            // The package list is large. Re-read it only when the database changed, and send the whole
            // inventory once a day; changes are reported as they happen either way.
            const auto signature = package_database_signature(options);
            const bool due = last_package_inventory_ns_ == 0U || now_ns - last_package_inventory_ns_ >= package_inventory_interval_ns;
            if (!due && signature == package_signature_) continue;
            package_signature_ = signature;
            inventory = due;
            if (due) last_package_inventory_ns_ = now_ns;
        }
        const auto collected = collect_state(object, options);
        if (!collected.has_value()) continue;
        if (auto emitted = emit_state_changes(*collected, now_ns); !succeeded(emitted)) outcome = emitted;
        if (!inventory) continue;
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

result<bool> sensor_pipeline::emit_state_changes(const state_snapshot& snapshot, const std::uint64_t now_ns) {
    constexpr std::size_t entries_per_record = 32U;
    const auto change = differ_.observe(snapshot);
    if (!change.has_value()) return true;
    result<bool> outcome = true;
    const auto parts = static_cast<std::uint32_t>((change->entries.size() + entries_per_record - 1U) / entries_per_record);
    for (std::uint32_t part = 0U; part < parts; ++part) {
        const auto first = part * entries_per_record;
        const auto count = std::min(entries_per_record, change->entries.size() - first);
        const std::span<const state_change_entry> slice{change->entries.data() + first, count};
        auto emitted = emit([&](const std::uint64_t seq) { return serializer_.state_changed(*change, slice, part + 1U, parts, seq, now_ns); });
        if (succeeded(emitted)) ++metrics_.events;
        else outcome = emitted;
    }
    return outcome;
}

result<bool> sensor_pipeline::emit_fim_changes(const std::vector<fim_change>& changes, const std::uint64_t observed_ns) {
    result<bool> outcome = true;
    for (const auto& change : changes) {
        const entity_ptr actor = change.actor_pid != 0U ? graph_.find(change.actor_pid) : nullptr;
        auto emitted = emit([&](const std::uint64_t seq) { return serializer_.fim_changed(change, actor, seq, observed_ns); });
        if (succeeded(emitted)) ++metrics_.events;
        else outcome = emitted;
    }
    return outcome;
}

result<bool> sensor_pipeline::collect_losses(const std::uint64_t now_ns) {
    bool reconcile_now = false;
    // While the sink refuses records a retry is attempted once a second (each failed attempt is
    // counted); after a successful write it is attempted at once.
    if (!write_failed_ || now_ns - last_loss_retry_ns_ >= ns_per_second) {
        last_loss_retry_ns_ = now_ns;
        if (!pending_losses_.empty()) {
            auto deferred = std::move(pending_losses_);
            pending_losses_.clear();
            for (auto& report : deferred) (void)emit_loss(std::move(report));
        }
        if (metrics_.records_unwritten > unwritten_reported_) {
            const auto total = metrics_.records_unwritten;
            const auto lost = total - unwritten_reported_;
            unwritten_reported_ = total;  // a refused loss record is kept in pending_losses_, so its count is not lost
            (void)emit_loss({"wal", lost, {{"write_failed", lost}},
                             "write_failed: " + std::to_string(lost) + " record(s) could not be written to the write-ahead log (" +
                                 last_write_error_ + "); their sequence numbers were not used, so the stream has no gap"});
        }
    }
    // Records the providers could not queue because the pipeline was behind: counted by the queue, never
    // by a provider, so nothing else would ever say they existed. A dropped fork, exec or exit also
    // leaves the entity graph wrong, hence the reconcile.
    if (const auto dropped = queue_.take_dropped(); dropped > 0U) {
        (void)emit_loss({"queue", dropped, {},
                         "the in-memory record queue (capacity " + std::to_string(config_.queue_capacity) + ") was full: " + std::to_string(dropped) +
                             " event(s) were dropped before the pipeline could process them"});
        reconcile_now = true;
    }
    for (const auto& source : providers_) {
        if (const auto governed = source->take_governed(); governed > 0U) {
            (void)emit_loss({"governor", governed, {},
                             std::string{source->name()} + " exceeded its event budget; " + std::to_string(governed) + " event(s) skipped"});
        }
        if (const auto refused = source->take_refused(); refused > 0U) {
            (void)emit_loss({"refused", refused, {},
                             std::string{source->name()} + " refused " + std::to_string(refused) +
                                 " input(s) it could not turn into events (for example a log line over the size limit); nothing was recorded about them"});
        }
        if (const auto lost = source->take_losses(); lost > 0U) {
            (void)emit_loss({"kernel", lost, {},
                             source->losses_are_event_counts()
                                 ? std::string{source->name()} + " could not reserve space in its kernel ring buffer for " + std::to_string(lost) +
                                       " event(s); the count is exact"
                                 : std::string{source->name()} + " receive buffer overflowed " + std::to_string(lost) +
                                       " time(s); the number of lost events is unknown"});
            reconcile_now = true;
        }
        // A hook removed from outside the sensor and attached again: whatever it would have seen in between is missing,
        // and the entity graph may have missed forks, execs or exits, hence the reconcile.
        for (const auto& gap : source->take_gaps()) {
            const auto ms = [](const std::uint64_t ns) { return std::to_string(ns / 1000000U); };
            const auto blind = gap.restored_unix_ns >= gap.last_verified_unix_ns ? gap.restored_unix_ns - gap.last_verified_unix_ns : 0U;
            (void)emit_loss({"provider_gap", 1U, {},
                             std::string{source->name()} + " " + gap.what + " was removed from outside the sensor: last verified attached at unix " +
                                 ms(gap.last_verified_unix_ns) + " ms, found missing at " + ms(gap.detected_unix_ns) + " ms, attached again and verified at " +
                                 ms(gap.restored_unix_ns) + " ms after " + std::to_string(gap.attempts) + " attempt(s); events it would have reported in those " +
                                 ms(blind) + " ms may be missing. The count is 1 interval, not a number of events"});
            reconcile_now = true;
        }
    }
    if (now_ns - last_storage_check_ns_ >= ns_per_second) {
        last_storage_check_ns_ = now_ns;
        sink_.verify_storage();
    }
    if (!written_losses_.empty()) {
        // Acknowledged loss records have been delivered; only unacknowledged ones can still be dropped.
        const auto acknowledged = sink_.metrics().acknowledged_seq;
        written_losses_.erase(std::remove_if(written_losses_.begin(), written_losses_.end(),
                                             [&](const written_loss& entry) { return entry.seq <= acknowledged; }),
                              written_losses_.end());
    }
    const auto dropped = sink_.take_losses();
    for (const auto& loss : dropped) {
        loss_report report{"wal", loss.records, {{loss.reason, loss.records}}, {}};
        report.detail = loss.reason + ": seq " + std::to_string(loss.first_seq) +
                        (loss.last_seq != 0U ? "-" + std::to_string(loss.last_seq) : std::string{"+"}) + ", " +
                        std::to_string(loss.bytes) + " bytes";
        (void)emit_loss(std::move(report));
    }
    carry_dropped_loss_reports(dropped);
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
    if (config_.enable_hashing) {
        hash_options options;
        options.maximum_file_bytes = config_.hash_max_file_bytes;
        options.bytes_per_second = config_.hash_bytes_per_second;
        hashes_ = std::make_unique<hash_service>(options);
    }
    (void)graph_.reconcile(unix_now, false);
    ++metrics_.reconciles;
    containers_.seed(graph_.live_entities());  // already running: followed, not reported as started
    (void)collect_losses(now);  // recovery losses from the WAL
    begin_instance(unix_now);
    if (!config_.policy_path.empty()) {
        policy_store_options options;
        options.policy_path = config_.policy_path;
        options.keys_path = config_.policy_signing_keys;
        options.state_path = config_.wal_path.string() + ".policy";
        options.host_id = serializer_.identity().host_id;
        policy_ = std::make_unique<policy_store>(std::move(options));
        refresh_policy(unix_now);
    }
    if (!config_.integrity_manifest.empty()) {
        integrity_options options;
        options.manifest_path = config_.integrity_manifest;
        options.keys_path = config_.integrity_keys;
        integrity_ = std::make_unique<integrity_monitor>(std::move(options));
        refresh_integrity(unix_now);
    }
    (void)emit_health(unix_now);
    (void)emit_process_state(unix_now);
    (void)emit_host_state(unix_now);
    if (config_.enable_fim) {
        fim_options options;
        options.persistence.root = config_.host_root;
        options.baseline_path = config_.fim_path;
        fim_ = std::make_unique<fim_monitor>(std::move(options));
        const auto begun = fim_->start();
        (void)emit([&](const std::uint64_t seq) { return serializer_.fim_baseline_record(begun, seq, unix_now); });
        (void)emit_fim_changes(begun.changes, unix_now);
    }
    last_reconcile_ns_ = last_health_ns_ = last_state_ns_ = last_resample_ns_ = last_fim_ns_ = last_policy_ns_ = last_integrity_ns_ = now;
    refresh_status(now);
    started_ns_ = clock_domain::now_monotonic_ns();
    started_ = true;
    return sink_.flush(now, true);
}

result<bool> sensor_pipeline::step(const std::uint64_t now_ns, const std::chrono::milliseconds wait) {
    // A stepped wall clock would leave event times wrong until the next periodic resample, so look
    // for one every step (two clock reads) and resample at once.
    constexpr std::int64_t step_threshold_ns = 250'000'000;
    const auto drift = clock_.boot_offset_drift_ns();
    const bool stepped = drift > step_threshold_ns || drift < -step_threshold_ns;
    if (stepped) {
        ++metrics_.clock_steps;
        std::fprintf(stderr, "panopticon-sensord: wall clock stepped by %lld ms; event times re-based\n", static_cast<long long>(drift / 1'000'000));
    }
    if (stepped || now_ns - last_resample_ns_ >= 60U * ns_per_second) {
        clock_.resample();
        last_resample_ns_ = now_ns;
    }
    batch_.clear();
    queue_.pop_batch(batch_, 1024U, wait, wait.count() > 0 ? batch_linger : std::chrono::milliseconds{0});
    const auto observed = clock_domain::now_unix_ns();
    for (const auto& record : batch_) process_record(record, observed);
    (void)collect_losses(now_ns);
    if (policy_) {
        // On schedule, and at once when the policy in force reaches its expiry (decisions already stopped then:
        // policy_store::active() checks the time; this records the expiry and stops naming the policy).
        const auto unix_now = clock_domain::now_unix_ns();
        const bool expired = policy_expires_unix_ != 0 && static_cast<std::int64_t>(unix_now / ns_per_second) >= policy_expires_unix_;
        if (expired || now_ns - last_policy_ns_ >= config_.policy_check_seconds * ns_per_second) {
            refresh_policy(unix_now);
            last_policy_ns_ = now_ns;
        }
    }
    if (integrity_ && now_ns - last_integrity_ns_ >= config_.integrity_check_seconds * ns_per_second) {
        refresh_integrity(clock_domain::now_unix_ns());
        last_integrity_ns_ = now_ns;
    }
    if (delivery_probe_) {
        // The Manager said these records can never be valid. Say so in the stream, with the
        // sequence numbers, so the gap at the Manager is explained rather than anonymous.
        const auto delivery = delivery_probe_();
        if (delivery.records_quarantined > quarantine_reported_) {
            std::string detail = "sequence numbers";
            for (const auto seq : delivery.recent_quarantined_seqs) detail += " " + std::to_string(seq);
            detail += "; " + delivery.last_error;
            (void)emit_loss({"manager_rejected", delivery.records_quarantined - quarantine_reported_, {}, detail});
            quarantine_reported_ = delivery.records_quarantined;
        }
    }

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
    (void)emit_hash_results(clock_domain::now_unix_ns());
    if (fim_) {
        if (now_ns - last_fim_ns_ >= config_.fim_interval_seconds * ns_per_second) {
            (void)emit_fim_changes(fim_->rescan(), clock_domain::now_unix_ns());
            last_fim_ns_ = now_ns;
        }
        if (fim_->pending() > 0U) (void)emit_fim_changes(fim_->take_due(now_ns), clock_domain::now_unix_ns());
    }
    if (now_ns - last_status_ns_ >= ns_per_second) refresh_status(now_ns);
    if (!config_.instance_state_path.empty() && now_ns - last_instance_marker_ns_ >= config_.instance_heartbeat_seconds * ns_per_second) {
        write_instance_marker(clock_domain::now_unix_ns(), false);
        last_instance_marker_ns_ = now_ns;
    }
    return sink_.flush(now_ns, false);
}

result<bool> sensor_pipeline::run(const std::atomic<bool>& stop, const std::uint64_t deadline_ns) {
    while (!stop.load(std::memory_order_relaxed)) {
        const auto now = clock_domain::now_monotonic_ns();
        if (deadline_ns != 0U && now >= deadline_ns) break;
        if (heartbeat_) heartbeat_();
        if (auto stepped = step(now, std::chrono::milliseconds{200}); !succeeded(stepped)) {
            ++metrics_.sink_errors;  // keep running: a full or failing disk must not stop collection
        }
    }
    return sink_.flush(clock_domain::now_monotonic_ns(), true);
}

void sensor_pipeline::shutdown() {
    if (!started_) return;
    started_ = false;
    for (auto& source : providers_) source->request_stop();
    for (auto& source : providers_) source->stop();
    // Drain what the providers queued before stopping.
    while (queue_.depth() > 0U) {
        batch_.clear();
        queue_.pop_batch(batch_, 1024U, std::chrono::milliseconds{0});
        const auto observed = clock_domain::now_unix_ns();
        for (const auto& record : batch_) process_record(record, observed);
    }
    (void)emit_health(clock_domain::now_unix_ns());
    // Only a shutdown whose records reached the sink may say "clean"; otherwise the next start reports the gap.
    if (succeeded(sink_.flush(clock_domain::now_monotonic_ns(), true))) write_instance_marker(clock_domain::now_unix_ns(), true);
}

}  // namespace panopticon::linux_agent::sensor
