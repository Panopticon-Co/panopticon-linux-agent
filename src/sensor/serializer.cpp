#include "panopticon/linux_agent/sensor/serializer.hpp"

#include "panopticon/linux_agent/event.hpp"

#include <array>
#include <cstdio>

namespace panopticon::linux_agent::sensor {
namespace {

std::string hex_mask(const std::uint64_t value) {
    std::array<char, 17> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%016llx", static_cast<unsigned long long>(value));
    return std::string{buffer.data(), 16U};
}

std::string tty_name(const std::uint32_t tty_nr) {
    if (tty_nr == 0U) return {};
    const auto major = (tty_nr >> 8U) & 0xFFFU;
    const auto minor = (tty_nr & 0xFFU) | ((tty_nr >> 12U) & 0xFFF00U);
    if (major >= 136U && major <= 143U) return "pts/" + std::to_string((major - 136U) * 256U + minor);
    if (major == 4U) return minor < 64U ? "tty" + std::to_string(minor) : "ttyS" + std::to_string(minor - 64U);
    return std::to_string(major) + ":" + std::to_string(minor);
}

// Last cgroup path component naming a systemd unit (".service" or ".scope").
std::string systemd_unit(const std::string_view cgroup) {
    std::string_view unit;
    std::size_t start = 0U;
    while (start <= cgroup.size()) {
        auto end = cgroup.find('/', start);
        if (end == std::string_view::npos) end = cgroup.size();
        const auto part = cgroup.substr(start, end - start);
        const auto ends_with = [part](const std::string_view suffix) {
            return part.size() > suffix.size() && part.substr(part.size() - suffix.size()) == suffix;
        };
        if (ends_with(".service") || ends_with(".scope")) unit = part;
        start = end + 1U;
    }
    return std::string{unit};
}

}  // namespace

std::string compute_record_id(const std::string_view sensor_id, const std::string_view boot_id, const std::uint64_t seq) {
    std::string input;
    input.append(sensor_id).append("|").append(boot_id).append("|").append(std::to_string(seq));
    return sha256_hex(input).substr(0U, 32U);
}

record_serializer::record_serializer(sensor_identity identity, const clock_domain& clock)
    : identity_{std::move(identity)}, clock_{clock} {}

void record_serializer::begin(json_writer& out, const std::string_view record_type, const std::string_view type,
                              const std::uint64_t seq, const std::uint64_t time_unix_ns,
                              const std::uint64_t observed_unix_ns, const provenance& source) const {
    out.begin_object();
    out.field("schema_version", endpoint_schema_version);
    out.field("record_type", record_type);
    out.field("id", compute_record_id(identity_.sensor_id, identity_.boot_id, seq));
    out.field("seq", seq);
    out.field("type", type);
    out.field("time", format_rfc3339_ns(time_unix_ns));
    out.field("observed_time", format_rfc3339_ns(observed_unix_ns));
    out.key("host").begin_object();
    out.field("id", identity_.host_id);
    out.field("boot_id", identity_.boot_id);
    out.field("hostname", identity_.hostname);
    out.end_object();
    out.key("sensor").begin_object();
    out.field("id", identity_.sensor_id);
    out.field("version", identity_.version);
    out.field("policy_version", identity_.policy_version);
    out.end_object();
    out.key("provenance").begin_object();
    out.field("provider", source.provider);
    out.field("mechanism", source.mechanism);
    out.field("confidence", to_string(source.level));
    out.end_object();
}

void record_serializer::write_process(json_writer& out, const process_entity& entity) const {
    const auto& info = entity.info;
    out.begin_object();
    if (!entity.entity_id.empty()) out.field("entity_id", entity.entity_id);
    out.field("exec_gen", entity.exec_gen);
    out.field("pid", info.pid);
    if (info.vpid != 0U) out.field("vpid", info.vpid);
    out.field("ppid", info.ppid);
    if (info.start_ticks != 0U || !entity.entity_id.empty()) {
        out.field("start_time", format_rfc3339_ns(clock_.ticks_to_unix_ns(info.start_ticks)));
        out.field("start_ticks", info.start_ticks);
    }
    out.field("name", info.comm);
    out.field("state", std::string_view{&info.state, 1U});
    out.field("kernel_thread", info.kernel_thread);
    out.field("threads", info.threads);
    out.key("confidence").begin_object();
    out.field("identity", to_string(entity.identity));
    out.field("attributes", to_string(entity.attributes));
    out.end_object();

    out.key("executable").begin_object();
    out.field("path", info.executable.path);
    out.field("kind", to_string(info.executable.kind));
    if (info.executable.known) {
        out.field("dev", info.executable.dev);
        out.field("inode", info.executable.inode);
        out.field("size", info.executable.size);
        out.field("mode", info.executable.mode & 07777U);
        out.field("uid", info.executable.uid);
        out.field("gid", info.executable.gid);
        out.field("setuid", (info.executable.mode & 04000U) != 0U);
        out.field("setgid", (info.executable.mode & 02000U) != 0U);
    }
    out.end_object();

    out.key("args").begin_array();
    for (const auto& arg : info.args) out.value(arg);
    out.end_array();
    out.field("args_truncated", info.args_truncated);
    if (!info.cwd.empty()) out.field("cwd", info.cwd);

    const auto& creds = info.creds;
    out.key("creds").begin_object();
    out.field("uid", creds.uids[0]).field("euid", creds.uids[1]).field("suid", creds.uids[2]).field("fsuid", creds.uids[3]);
    out.field("gid", creds.gids[0]).field("egid", creds.gids[1]).field("sgid", creds.gids[2]).field("fsgid", creds.gids[3]);
    out.key("groups").begin_array();
    for (const auto group : creds.groups) out.value(group);
    out.end_array();
    if (creds.loginuid.has_value()) out.field("loginuid", *creds.loginuid);
    else out.field_null("loginuid");
    if (creds.sessionid.has_value()) out.field("sessionid", *creds.sessionid);
    else out.field_null("sessionid");
    out.end_object();

    out.key("caps").begin_object();
    out.field("effective", hex_mask(info.caps.effective));
    out.field("permitted", hex_mask(info.caps.permitted));
    out.field("inheritable", hex_mask(info.caps.inheritable));
    out.field("bounding", hex_mask(info.caps.bounding));
    out.field("ambient", hex_mask(info.caps.ambient));
    out.end_object();
    if (info.seccomp_mode.has_value()) out.field("seccomp", static_cast<std::int64_t>(*info.seccomp_mode));
    if (info.no_new_privs.has_value()) out.field("no_new_privs", *info.no_new_privs);

    out.key("ns").begin_object();
    for (std::size_t index = 0U; index < namespace_names.size(); ++index) {
        if (info.namespaces[index] != 0U) out.field(namespace_names[index], info.namespaces[index]);
    }
    out.end_object();
    if (!info.cgroup.empty()) {
        out.field("cgroup", info.cgroup);
        if (const auto unit = systemd_unit(info.cgroup); !unit.empty()) out.field("unit", unit);
    }
    if (const auto tty = tty_name(info.tty_nr); !tty.empty()) out.field("tty", tty);
    out.field("pgid", info.pgid);
    out.field("sid", info.sid);
    if (!info.env.empty()) {
        out.key("env").begin_object();
        for (const auto& [name, value] : info.env) out.field(name, value);
        out.end_object();
    }
}

std::string record_serializer::event(const process_event& event, const std::uint64_t seq,
                                     const std::uint64_t observed_unix_ns) const {
    json_writer out;
    begin(out, "event", event.type, seq, event.time_unix_ns, observed_unix_ns, event.source);
    std::vector<unavailable_field> unavailable = event.unavailable;
    if (event.process) {
        out.key("process");
        write_process(out, *event.process);
        if (event.exit.has_value()) {
            if (event.exit->code.has_value()) out.field("exit_code", static_cast<std::int64_t>(*event.exit->code));
            if (event.exit->signal.has_value()) out.field("exit_signal", static_cast<std::int64_t>(*event.exit->signal));
            out.field("core_dumped", event.exit->core_dumped);
        }
        out.key("ancestry").begin_array();
        for (const auto& ancestor : event.ancestry) {
            out.begin_object();
            out.field("entity_id", ancestor.entity_id);
            out.field("pid", ancestor.pid);
            out.field("name", ancestor.name);
            out.field("executable", ancestor.executable);
            out.end_object();
        }
        out.end_array();
        out.end_object();
        unavailable.insert(unavailable.end(), event.process->info.unavailable.begin(), event.process->info.unavailable.end());
    }
    if (event.parent) {
        out.key("parent");
        write_process(out, *event.parent);
        out.end_object();
    }
    if (event.target) {
        out.key("target");
        write_process(out, *event.target);
        out.end_object();
    }
    if (event.previous_executable.has_value()) out.field("previous_executable", *event.previous_executable);
    if (event.previous_name.has_value()) out.field("previous_name", *event.previous_name);
    if (event.technique.has_value()) out.field("technique", *event.technique);
    if (event.creds_before.has_value()) {
        const auto& creds = *event.creds_before;
        out.key("creds_before").begin_object();
        out.field("uid", creds.uids[0]).field("euid", creds.uids[1]).field("gid", creds.gids[0]).field("egid", creds.gids[1]);
        out.end_object();
    }
    out.key("unavailable").begin_array();
    for (const auto& field : unavailable) {
        out.begin_object();
        out.field("field", field.field);
        out.field("reason", to_string(field.reason));
        out.end_object();
    }
    out.end_array();
    out.end_object();
    return out.take();
}

namespace {

void write_coverage(json_writer& out, const health_snapshot& snapshot) {
    out.begin_object();
    for (const auto& [capability, provider] : snapshot.coverage) {
        if (provider.empty()) out.field_null(capability);
        else out.field(capability, provider);
    }
    out.end_object();
}

void write_health_body(json_writer& out, const health_snapshot& snapshot) {
    out.begin_object();
    out.field("status", snapshot.status);
    out.key("providers").begin_array();
    for (const auto& provider : snapshot.providers) {
        out.begin_object();
        out.field("name", provider.name);
        out.field("state", provider.state);
        out.field("reason", provider.reason);
        out.key("capabilities").begin_array();
        for (const auto& capability : provider.capabilities) out.value(capability);
        out.end_array();
        out.field("events", provider.events);
        out.field("drops", provider.drops);
        out.end_object();
    }
    out.end_array();
    out.key("coverage");
    write_coverage(out, snapshot);
    out.key("resources").begin_object();
    out.field("rss_bytes", snapshot.rss_bytes);
    out.field("cpu_milliseconds", snapshot.cpu_milliseconds);
    out.field("wal_bytes", snapshot.wal_bytes);
    out.field("wal_records", snapshot.wal_records);
    out.end_object();
    out.key("kernel").begin_object();
    out.field("release", snapshot.kernel_release);
    out.field("btf", snapshot.btf);
    out.field("bpf_lsm", snapshot.bpf_lsm);
    out.field("ringbuf", snapshot.ringbuf);
    out.end_object();
    out.end_object();
}

}  // namespace

std::string record_serializer::health(const health_snapshot& snapshot, const std::uint64_t seq,
                                      const std::uint64_t now_unix_ns) const {
    json_writer out;
    begin(out, "health", "health", seq, now_unix_ns, now_unix_ns, {"sensor", "self", confidence::observed});
    out.key("health");
    write_health_body(out, snapshot);
    out.key("unavailable").begin_array().end_array();
    out.end_object();
    return out.take();
}

std::string record_serializer::coverage_json(const health_snapshot& snapshot) {
    json_writer out;
    write_coverage(out, snapshot);
    return out.take();
}

std::string record_serializer::status_json(const health_snapshot& snapshot) {
    json_writer out;
    write_health_body(out, snapshot);
    return out.take();
}

std::string record_serializer::loss(const loss_report& report, const std::uint64_t seq, const std::uint64_t now_unix_ns) const {
    json_writer out;
    begin(out, "loss", "loss", seq, now_unix_ns, now_unix_ns, {"sensor", "self", confidence::observed});
    out.key("loss").begin_object();
    out.field("stage", report.stage);
    out.field("count", report.count);
    out.key("by_type").begin_object();
    for (const auto& [type, count] : report.by_type) out.field(type, count);
    out.end_object();
    if (!report.detail.empty()) out.field("detail", report.detail);
    out.end_object();
    out.key("unavailable").begin_array().end_array();
    out.end_object();
    return out.take();
}

std::string record_serializer::file_event(const file_record& record, const std::uint64_t seq,
                                          const std::uint64_t observed_unix_ns) const {
    json_writer out;
    begin(out, "event", record.type, seq, record.time_unix_ns, observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable = record.unavailable;
    if (record.actor) {
        out.key("process");
        write_process(out, *record.actor);
        out.end_object();
    } else {
        out.key("process").begin_object();
        out.field("pid", record.pid);
        out.end_object();
        unavailable.push_back({"process", unavailable_reason::process_exited});
    }
    out.key("file").begin_object();
    out.field("path", record.path);
    const auto slash = record.path.find_last_of('/');
    if (!record.path.empty() && slash != std::string::npos && slash + 1U < record.path.size()) {
        out.field("name", std::string_view{record.path}.substr(slash + 1U));
    }
    out.field("directory", record.directory);
    if (record.old_path.has_value()) out.field("old_path", *record.old_path);
    if (record.stat.has_value()) {
        const auto& stat = *record.stat;
        out.key("stat").begin_object();
        out.field("mode", stat.mode).field("uid", stat.uid).field("gid", stat.gid).field("size", stat.size);
        out.field("inode", stat.inode).field("device", stat.device);
        out.field("mtime", format_rfc3339_ns(stat.mtime_unix_ns));
        out.end_object();
    }
    out.end_object();
    out.key("unavailable").begin_array();
    for (const auto& field : unavailable) {
        out.begin_object();
        out.field("field", field.field);
        out.field("reason", to_string(field.reason));
        out.end_object();
    }
    out.end_array();
    out.end_object();
    return out.take();
}

std::string record_serializer::process_state(const std::vector<entity_ptr>& items, const std::string_view snapshot_id,
                                             const std::uint32_t part, const std::uint32_t parts, const std::uint64_t seq,
                                             const std::uint64_t now_unix_ns) const {
    json_writer out;
    begin(out, "state", "state.processes", seq, now_unix_ns, now_unix_ns, {"procfs", "PROCFS", confidence::reconstructed});
    out.key("state").begin_object();
    out.field("object", "processes");
    out.field("snapshot_id", snapshot_id);
    out.field("part", part);
    out.field("parts", parts);
    out.key("items").begin_array();
    for (const auto& item : items) {
        write_process(out, *item);
        out.end_object();
    }
    out.end_array();
    out.end_object();
    out.key("unavailable").begin_array().end_array();
    out.end_object();
    return out.take();
}

std::string record_serializer::host_state(const state_snapshot& snapshot, const std::span<const std::string> items,
                                          const std::string_view snapshot_id, const std::uint32_t part,
                                          const std::uint32_t parts, const std::uint64_t seq,
                                          const std::uint64_t now_unix_ns) const {
    json_writer out;
    begin(out, "state", "state." + snapshot.object, seq, now_unix_ns, now_unix_ns,
          {snapshot.provider, snapshot.mechanism, confidence::observed});
    out.key("state").begin_object();
    out.field("object", snapshot.object);
    out.field("snapshot_id", snapshot_id);
    out.field("part", part);
    out.field("parts", parts);
    out.key("items").begin_array();
    for (const auto& item : items) out.raw(item);
    out.end_array();
    out.end_object();
    out.key("unavailable").begin_array();
    if (part == 1U) {
        for (const auto& field : snapshot.unavailable) {
            out.begin_object();
            out.field("field", field.field);
            out.field("reason", to_string(field.reason));
            out.end_object();
        }
    }
    out.end_array();
    out.end_object();
    return out.take();
}

}  // namespace panopticon::linux_agent::sensor
