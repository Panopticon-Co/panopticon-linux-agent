#include "panopticon/linux_agent/sensor/serializer.hpp"

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/sensor/container_identity.hpp"

#include <algorithm>
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

std::string signal_name(const std::uint32_t number) {
    static constexpr const char* names[] = {"",        "SIGHUP",  "SIGINT",   "SIGQUIT", "SIGILL",    "SIGTRAP", "SIGABRT", "SIGBUS",
                                            "SIGFPE",  "SIGKILL", "SIGUSR1",  "SIGSEGV", "SIGUSR2",   "SIGPIPE", "SIGALRM", "SIGTERM",
                                            "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP",   "SIGTTIN", "SIGTTOU", "SIGURG",
                                            "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO",   "SIGPWR",  "SIGSYS"};
    if (number >= 1U && number < std::size(names)) return names[number];
    return "SIG" + std::to_string(number);
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

// The `hash` object of catalog §3.2: the status always, the digests only once known.
static void write_hash(json_writer& out, const file_hash& hash) {
    out.key("hash").begin_object();
    out.field("status", hash.status);
    if (!hash.sha256.empty()) out.field("sha256", hash.sha256);
    if (!hash.sha1.empty()) out.field("sha1", hash.sha1);
    if (!hash.md5.empty()) out.field("md5", hash.md5);
    out.end_object();
}

void record_serializer::write_process(json_writer& out, const process_entity& entity, const file_hash* hash) const {
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
    if (hash != nullptr) write_hash(out, *hash);
    out.end_object();

    out.key("args").begin_array();
    for (const auto& arg : info.args) out.value(arg);
    out.end_array();
    out.field("args_truncated", info.args_truncated);
    if (info.stdio.has_value()) {
        out.key("stdio").begin_object();
        out.field("stdin", to_string((*info.stdio)[0]));
        out.field("stdout", to_string((*info.stdio)[1]));
        out.field("stderr", to_string((*info.stdio)[2]));
        out.end_object();
    }
    if (!info.interpreter.empty()) {
        out.field("interpreter", info.interpreter);
        out.field("script", info.script);
    }
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
        if (const auto container = parse_container_cgroup(info.cgroup)) {
            out.key("container").begin_object();
            out.field("id", container->id);
            out.field("runtime", container->runtime);
            if (!container->pod_uid.empty()) out.field("pod_uid", container->pod_uid);
            out.end_object();
        }
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
        write_process(out, *event.process, event.executable_hash ? &*event.executable_hash : nullptr);
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
    if (event.signal.has_value()) {
        const auto& signal = *event.signal;
        out.key("signal").begin_object();
        out.field("number", signal.number);
        out.field("name", signal_name(signal.number));
        out.field("via", signal.code == 0 ? "kill" : signal.code == -6 ? "tgkill" : signal.code == -1 ? "sigqueue" : "other");
        out.field("result", signal.result);
        out.field("target_is_sensor", signal.target_is_sensor);
        out.end_object();
    }
    if (event.ns_change.has_value()) {
        const auto& change = *event.ns_change;
        out.key("ns_change").begin_object();
        out.field("scope", change.whole_process ? "process" : "thread");
        out.field("thread_id", change.thread_id);
        out.key("changes").begin_array();
        for (const auto& move : change.moves) {
            out.begin_object();
            out.field("ns", move.name);
            out.field("from", move.from);
            out.field("to", move.to);
            out.end_object();
        }
        out.end_array();
        out.end_object();
    }
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
        if (!provider.family.empty()) out.field("family", provider.family);
        if (!provider.tier.empty()) out.field("tier", provider.tier);
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
    out.key("wal").begin_object();
    out.field("next_seq", snapshot.wal_next_seq);
    out.field("durable_seq", snapshot.wal_durable_seq);
    out.field("acknowledged_seq", snapshot.wal_acknowledged_seq);
    out.field("dropped_records", snapshot.wal_dropped_records);
    out.end_object();
    out.key("totals").begin_object();
    out.field("records", snapshot.records_total);
    out.field("events", snapshot.events_total);
    out.field("loss_records", snapshot.loss_records_total);
    out.field("sink_errors", snapshot.sink_errors);
    out.field("uptime_ms", snapshot.uptime_ms);
    out.end_object();
    if (snapshot.delivery.configured) {
        const auto& delivery = snapshot.delivery;
        out.key("delivery").begin_object();
        out.field("state", delivery.state);
        out.field("acknowledged_seq", delivery.acknowledged_seq);
        out.field("batches_sent", delivery.batches_sent);
        out.field("records_acknowledged", delivery.records_acknowledged);
        out.field("retries", delivery.retries);
        out.field("refusals", delivery.refusals);
        out.field("consecutive_failures", delivery.consecutive_failures);
        out.field("records_quarantined", delivery.records_quarantined);
        out.field("quarantine_failures", delivery.quarantine_failures);
        out.key("recent_quarantined_seqs").begin_array();
        for (const auto seq : delivery.recent_quarantined_seqs) out.value(seq);
        out.end_array();
        if (!delivery.last_error.empty()) out.field("last_error", delivery.last_error);
        out.end_object();
    }
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
        // A process stub needs a pid; without one the member is omitted and reported as unavailable.
        if (record.pid != 0U) {
            out.key("process").begin_object();
            out.field("pid", record.pid);
            out.end_object();
            unavailable.push_back({"process", unavailable_reason::process_exited});
        } else if (std::none_of(unavailable.begin(), unavailable.end(), [](const unavailable_field& item) { return item.field == "process"; })) {
            unavailable.push_back({"process", unavailable_reason::not_supported_by_provider});
        }
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

std::string record_serializer::network_event(const network_record& record, const std::uint64_t seq,
                                             const std::uint64_t observed_unix_ns) const {
    const auto& net = record.network;
    json_writer out;
    begin(out, "event", std::string{"network."} + to_string(net.operation), seq, record.time_unix_ns, observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable = net.unavailable;
    if (record.actor) {
        out.key("process");
        write_process(out, *record.actor);
        out.end_object();
    } else {
        if (net.pid != 0U) {
            out.key("process").begin_object();
            out.field("pid", net.pid);
            out.end_object();
            unavailable.push_back({"process", unavailable_reason::process_exited});
        } else if (std::none_of(unavailable.begin(), unavailable.end(), [](const unavailable_field& item) { return item.field == "process"; })) {
            unavailable.push_back({"process", unavailable_reason::not_supported_by_provider});
        }
    }
    out.key("network").begin_object();
    out.field("transport", net.protocol);
    out.field("family", net.family == "inet" ? "ipv4" : "ipv6");
    const auto direction = [&]() -> std::string {
        switch (net.operation) {
        case network_operation::connect:
        case network_operation::udp_flow: return "outbound";
        case network_operation::accept: return "inbound";
        case network_operation::close: return net.direction.empty() ? "unknown" : net.direction;
        default: return "listen";
        }
    }();
    out.field("direction", direction);
    out.key("local").begin_object();
    out.field("ip", net.local_address);
    out.field("port", static_cast<std::uint32_t>(net.local_port));
    out.end_object();
    if (net.operation != network_operation::listen) {
        out.key("remote").begin_object();
        out.field("ip", net.remote_address);
        out.field("port", static_cast<std::uint32_t>(net.remote_port));
        out.end_object();
    }
    const auto& far_end = net.operation == network_operation::listen ? net.local_address : net.remote_address;
    const bool loopback = far_end.rfind("127.", 0U) == 0U || far_end == "::1";
    out.key("tags").begin_array();
    if (loopback) out.value("loopback");
    out.end_array();
    out.field("state", net.state);
    out.field("socket_inode", net.inode);
    out.field("uid", net.uid);
    if (net.holders > 1U) out.field("holders", net.holders);
    if (net.operation == network_operation::close) {
        out.field("bytes_sent", net.bytes_sent);
        out.field("bytes_received", net.bytes_received);
        if (net.duration_ns != 0U) out.field("duration_ns", net.duration_ns);
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

std::string record_serializer::dns_event(const dns_record& record, const std::uint64_t seq, const std::uint64_t observed_unix_ns) const {
    const auto& dns = record.dns;
    json_writer out;
    begin(out, "event", "dns.query", seq, record.time_unix_ns, observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable;
    if (record.actor) {
        out.key("process");
        write_process(out, *record.actor);
        out.end_object();
    } else {
        if (dns.pid != 0U) {
            out.key("process").begin_object();
            out.field("pid", dns.pid);
            out.end_object();
            unavailable.push_back({"process", unavailable_reason::process_exited});
        } else {
            unavailable.push_back({"process", unavailable_reason::not_supported_by_provider});
        }
    }
    out.key("dns").begin_object();
    out.field("name", dns.name);
    out.field("type", dns.type);
    out.field("class", dns.klass);
    out.field("transaction_id", static_cast<std::uint32_t>(dns.transaction_id));
    out.field("recursion_desired", dns.recursion_desired);
    out.field("transport", "udp");
    out.field("family", dns.family == "inet" ? "ipv4" : "ipv6");
    out.key("server").begin_object();
    out.field("ip", dns.server_address);
    out.field("port", static_cast<std::uint32_t>(dns.server_port));
    out.end_object();
    out.key("local").begin_object();
    out.field("ip", dns.local_address);
    out.field("port", static_cast<std::uint32_t>(dns.local_port));
    out.end_object();
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

namespace {

// The acting process of an audit-derived event: the full entity, a pid-only stub when it has
// exited, or nothing when the record names none.
template <typename WriteProcess>
void write_audit_actor(json_writer& out, const entity_ptr& actor, const std::uint32_t pid, std::vector<unavailable_field>& unavailable,
                       WriteProcess&& write_process) {
    if (actor) {
        out.key("process");
        write_process(*actor);
        out.end_object();
    } else if (pid != 0U) {
        out.key("process").begin_object();
        out.field("pid", pid);
        out.end_object();
        unavailable.push_back({"process", unavailable_reason::process_exited});
    } else {
        unavailable.push_back({"process", unavailable_reason::not_supported_by_provider});
    }
}

void write_unavailable(json_writer& out, const std::vector<unavailable_field>& unavailable) {
    out.key("unavailable").begin_array();
    for (const auto& field : unavailable) {
        out.begin_object();
        out.field("field", field.field);
        out.field("reason", to_string(field.reason));
        out.end_object();
    }
    out.end_array();
}

}  // namespace

std::string record_serializer::lsm_event(const lsm_record& record, const std::uint64_t seq, const std::uint64_t observed_unix_ns) const {
    const auto& lsm = record.lsm;
    json_writer out;
    begin(out, "event", lsm.policy_change ? "lsm.policy" : "lsm.denial", seq, record.time_unix_ns, observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable;
    write_audit_actor(out, record.actor, lsm.pid, unavailable, [&](const process_entity& entity) { write_process(out, entity); });
    out.key("lsm").begin_object();
    out.field("module", lsm.module);
    out.field("operation", lsm.operation);
    if (!lsm.policy_change) out.field("outcome", lsm.outcome);
    if (!lsm.object.empty()) out.field("object", lsm.object);
    if (!lsm.requested.empty()) out.field("requested", lsm.requested);
    if (!lsm.denied.empty()) out.field("denied", lsm.denied);
    if (!lsm.profile.empty()) out.field("profile", lsm.profile);
    if (!lsm.target_context.empty()) out.field("target_context", lsm.target_context);
    if (!lsm.object_class.empty()) out.field("object_class", lsm.object_class);
    if (!lsm.comm.empty()) out.field("comm", lsm.comm);
    if (lsm.sanitized) out.field("sanitized", true);
    out.end_object();
    write_unavailable(out, unavailable);
    out.end_object();
    return out.take();
}

std::string record_serializer::firewall_event(const firewall_record& record, const std::uint64_t seq,
                                              const std::uint64_t observed_unix_ns) const {
    const auto& firewall = record.firewall;
    json_writer out;
    begin(out, "event", "netfilter.config_change", seq, record.time_unix_ns, observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable;
    write_audit_actor(out, record.actor, firewall.pid, unavailable, [&](const process_entity& entity) { write_process(out, entity); });
    out.key("netfilter").begin_object();
    out.field("subsystem", firewall.subsystem);
    out.field("operation", firewall.operation);
    out.field("table", firewall.table);
    out.field("family", firewall.family);
    out.field("entries", firewall.entries);
    if (firewall.generation) out.field("generation", *firewall.generation);
    if (!firewall.comm.empty()) out.field("comm", firewall.comm);
    out.end_object();
    write_unavailable(out, unavailable);
    out.end_object();
    return out.take();
}

std::string record_serializer::response_event(const response_record& record, const std::uint64_t seq,
                                              const std::uint64_t observed_unix_ns) const {
    const auto& response = record.response;
    json_writer out;
    begin(out, "event", "response.action", seq, record.time_unix_ns, observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable;
    // The process is the one the command named, and only when the sensor knows that exact identity.
    // A pid that now belongs to a different process is not attributed to the command's target.
    write_audit_actor(out, record.target, response.pid, unavailable, [&](const process_entity& entity) { write_process(out, entity); });
    out.key("response").begin_object();
    out.field("command_id", response.command_id);
    out.field("correlation_id", response.correlation_id);
    out.field("action", response.action);
    out.field("outcome", response.outcome);
    out.field("reason", response.reason);
    out.field("dry_run", response.dry_run);
    out.field("executed", response.executed);
    if (!response.mode.empty()) out.field("mode", response.mode);
    if (response.pid != 0U) {
        out.key("target").begin_object();
        out.field("pid", response.pid);
        out.field("start_time_ticks", response.start_ticks);
        out.end_object();
    }
    if (!response.path.empty()) out.field("path", response.path);
    if (response.affected != 0U) out.field("affected", response.affected);
    if (!response.detail.empty()) out.field("detail", response.detail);
    out.end_object();
    write_unavailable(out, unavailable);
    out.end_object();
    return out.take();
}

std::string record_serializer::auth_event(const auth_record& record, const std::uint64_t seq,
                                          const std::uint64_t observed_unix_ns) const {
    const auto& auth = record.auth;
    const bool login = auth.kind == auth_kind::login_success || auth.kind == auth_kind::login_failure;
    const bool success = auth.kind == auth_kind::login_success || auth.kind == auth_kind::privilege_success;
    json_writer out;
    begin(out, "event", login ? (success ? "auth.login" : "auth.failure") : "auth.privilege", seq, record.time_unix_ns, observed_unix_ns,
          record.source);
    std::vector<unavailable_field> unavailable;
    if (record.actor) {
        out.key("process");
        write_process(out, *record.actor);
        out.end_object();
    } else {
        if (auth.pid != 0U) {
            out.key("process").begin_object();
            out.field("pid", auth.pid);
            out.end_object();
            unavailable.push_back({"process", unavailable_reason::process_exited});
        } else if (std::none_of(unavailable.begin(), unavailable.end(), [](const unavailable_field& item) { return item.field == "process"; })) {
            unavailable.push_back({"process", unavailable_reason::not_supported_by_provider});
        }
    }
    out.key("auth").begin_object();
    out.field("service", auth.service);
    if (!auth.method.empty()) out.field("method", auth.method);
    out.field("outcome", success ? "success" : "failure");
    out.field("user", auth.user);
    if (!auth.target_user.empty()) out.field("target_user", auth.target_user);
    if (auth.invalid_user) out.field("invalid_user", true);
    if (!auth.source_address.empty()) {
        out.key("source").begin_object();
        out.field("ip", auth.source_address);
        out.field("port", static_cast<std::uint32_t>(auth.source_port));
        out.end_object();
    }
    if (!auth.key_fingerprint.empty()) {
        out.key("key").begin_object();
        out.field("type", auth.key_type);
        out.field("fingerprint", auth.key_fingerprint);
        out.end_object();
    }
    if (!auth.tty.empty()) out.field("tty", auth.tty);
    if (!auth.working_directory.empty()) out.field("working_directory", auth.working_directory);
    if (!auth.command.empty()) out.field("command", auth.command);
    if (auth.sanitized) out.field("sanitized", true);
    if (auth.truncated) out.field("truncated", true);
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

std::string record_serializer::security_event(const security_record& record, const std::uint64_t seq,
                                              const std::uint64_t observed_unix_ns) const {
    const auto& item = record.security;
    const bool memory = item.kind == security_kind::memory_exec_mapping;
    const bool raw_socket = item.kind == security_kind::raw_socket;
    json_writer out;
    begin(out, "event", memory ? "memory.exec_mapping" : raw_socket ? "network.raw_socket" : "kernel.bpf_load", seq, record.time_unix_ns,
          observed_unix_ns, record.source);
    std::vector<unavailable_field> unavailable;
    if (record.actor) {
        out.key("process");
        write_process(out, *record.actor);
        out.end_object();
    } else {
        out.key("process").begin_object();
        out.field("pid", item.pid);
        out.end_object();
        unavailable.push_back({"process", unavailable_reason::process_exited});
    }
    if (memory) {
        out.key("memory").begin_object();
        out.field("operation", item.operation);
        out.field("backing", item.backing);
        out.field("write_exec", item.write_exec);
        if (item.length != 0U) {
            out.field("address", item.address);
            out.field("length", item.length);
        } else {
            unavailable.push_back({"memory.range", unavailable_reason::not_supported_by_provider});
        }
        out.end_object();
    } else if (raw_socket) {
        out.key("socket").begin_object();
        out.field("family", item.socket_family);
        out.field("type", item.socket_type);
        out.field("protocol", item.socket_protocol);
        if (!item.protocol_name.empty()) out.field("protocol_name", item.protocol_name);
        out.end_object();
    } else {
        out.key("bpf").begin_object();
        out.field("command", item.command);
        if (!item.program_type.empty()) out.field("program_type", item.program_type);
        if (item.attach_type.has_value()) out.field("attach_type", *item.attach_type);
        if (!item.name.empty()) out.field("name", item.name);
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

std::string record_serializer::kernel_event(const kernel_record& record, const std::uint64_t seq,
                                            const std::uint64_t observed_unix_ns) const {
    const auto& item = record.kernel;
    const bool is_module = item.kind == kernel_event_kind::module_load || item.kind == kernel_event_kind::module_unload;
    const char* type = item.kind == kernel_event_kind::module_load     ? "kernel.module_load"
                       : item.kind == kernel_event_kind::module_unload ? "kernel.module_unload"
                                                                      : "mount.changed";
    json_writer out;
    begin(out, "event", type, seq, record.time_unix_ns, observed_unix_ns, record.source);
    if (is_module) {
        out.key("module").begin_object();
        out.field("name", item.module_name);
        out.field("size", item.module_size);
        if (!item.module_state.empty()) out.field("state", item.module_state);
        out.end_object();
    } else {
        out.key("mount").begin_object();
        out.field("operation", item.kind == kernel_event_kind::mount_added     ? "mounted"
                               : item.kind == kernel_event_kind::mount_removed ? "unmounted"
                                                                              : "remounted");
        out.field("source", item.source);
        out.field("target", item.target);
        out.field("fstype", item.fs_type);
        out.field("mount_id", item.mount_id);
        out.field("device", item.device);
        out.key("options").begin_array();
        for (const auto& option : item.options) out.value(option);
        out.end_array();
        out.key("super_options").begin_array();
        for (const auto& option : item.super_options) out.value(option);
        out.end_array();
        out.end_object();
    }
    out.key("unavailable").begin_array();
    out.begin_object();
    out.field("field", "process");
    out.field("reason", "not_supported_by_provider");
    out.end_object();
    out.end_array();
    out.end_object();
    return out.take();
}

std::string record_serializer::container_event(const container_lifecycle& lifecycle, const std::uint64_t seq,
                                               const std::uint64_t observed_unix_ns) const {
    json_writer out;
    // Derived from process events, not reported by a runtime: the record says so.
    begin(out, "event", lifecycle.started ? "container.started" : "container.stopped", seq, lifecycle.time_unix_ns, observed_unix_ns,
          provenance{"sensor", "container_tracker", confidence::inferred});
    if (lifecycle.process) {
        out.key("process");
        write_process(out, *lifecycle.process);
        out.end_object();
    }
    out.key("container").begin_object();
    out.field("id", lifecycle.identity.id);
    out.field("runtime", lifecycle.identity.runtime);
    if (!lifecycle.identity.pod_uid.empty()) out.field("pod_uid", lifecycle.identity.pod_uid);
    out.field("cgroup", lifecycle.cgroup);
    if (!lifecycle.started) {
        out.field("start_observed", lifecycle.start_observed);
        if (lifecycle.start_observed) out.field("lifetime_ns", lifecycle.lifetime_ns);
        out.field("peak_processes", lifecycle.peak_processes);
    }
    out.end_object();
    write_unavailable(out, {});
    out.end_object();
    return out.take();
}

std::string record_serializer::hash_computed(const hash_result& result, const std::uint64_t seq, const std::uint64_t now_unix_ns) const {
    json_writer out;
    begin(out, "event", "hash.computed", seq, now_unix_ns, now_unix_ns, {"hash", "FSSCAN", confidence::observed});
    out.key("process").begin_object();
    if (!result.subject.entity_id.empty()) out.field("entity_id", result.subject.entity_id);
    out.field("exec_gen", result.subject.exec_gen);
    out.field("pid", result.subject.pid);
    out.end_object();
    out.key("executable").begin_object();
    out.field("path", result.subject.path);
    out.field("dev", result.subject.key.dev);
    out.field("inode", result.subject.key.inode);
    out.field("size", result.subject.key.size);
    write_hash(out, result.hash);
    out.end_object();
    out.key("unavailable").begin_array();
    out.end_array();
    out.end_object();
    return out.take();
}

std::string record_serializer::fim_changed(const fim_change& change, const entity_ptr& actor, const std::uint64_t seq,
                                           const std::uint64_t observed_unix_ns) const {
    json_writer out;
    const bool attributed = change.actor_pid != 0U;
    const provenance source{"fim", attributed ? "FSSCAN+FANOTIFY" : "FSSCAN", confidence::observed};
    begin(out, "event", "fim.changed", seq, attributed ? change.actor_time_unix_ns : observed_unix_ns, observed_unix_ns, source);
    std::vector<unavailable_field> unavailable;
    if (actor) {
        out.key("process");
        write_process(out, *actor);
        out.end_object();
    } else if (attributed) {
        out.key("process").begin_object();
        out.field("pid", change.actor_pid);
        out.end_object();
        unavailable.push_back({"process", unavailable_reason::process_exited});
    } else {
        // Found by comparing states, not by watching the write: nobody was seen doing it.
        unavailable.push_back({"process", unavailable_reason::not_supported_by_provider});
    }
    out.key("fim").begin_object();
    out.field("path", change.path);
    out.field("category", change.category);
    out.field("change", change.change);
    out.key("fields").begin_array();
    for (const auto& field : change.fields) out.value(field);
    out.end_array();
    if (change.before) out.key("before").raw(persistence_item_json(*change.before));
    if (change.after) out.key("after").raw(persistence_item_json(*change.after));
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

std::string record_serializer::fim_baseline_record(const fim_start_result& start, const std::uint64_t seq,
                                                   const std::uint64_t now_unix_ns) const {
    json_writer out;
    begin(out, "event", "fim.baseline", seq, now_unix_ns, now_unix_ns, {"fim", "FSSCAN", confidence::observed});
    out.key("fim").begin_object();
    out.field("state", start.state);
    if (!start.reset_reason.empty()) out.field("reason", start.reset_reason);
    out.field("items", static_cast<std::uint64_t>(start.items));
    out.field("changes", static_cast<std::uint64_t>(start.changes.size()));
    out.end_object();
    out.key("unavailable").begin_array();
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

std::string record_serializer::state_changed(const state_change& change, const std::span<const state_change_entry> entries,
                                             const std::uint32_t part, const std::uint32_t parts, const std::uint64_t seq,
                                             const std::uint64_t now_unix_ns) const {
    json_writer out;
    // Found by comparing two inventories, so nobody is attributed and the process is not known.
    begin(out, "event", change.type, seq, now_unix_ns, now_unix_ns, {"inventory", "SNAPSHOT_DIFF", confidence::observed});
    out.key("change").begin_object();
    out.field("object", change.object);
    out.field("total", static_cast<std::uint64_t>(change.total));
    out.field("part", part);
    out.field("parts", parts);
    out.field("truncated", change.truncated);
    out.key("entries").begin_array();
    for (const auto& entry : entries) {
        out.begin_object();
        out.field("key", entry.key);
        out.field("kind", entry.kind);
        if (entry.before) out.key("before").raw(*entry.before);
        if (entry.after) out.key("after").raw(*entry.after);
        out.end_object();
    }
    out.end_array();
    out.end_object();
    out.key("unavailable").begin_array();
    out.begin_object();
    out.field("field", "process");
    out.field("reason", "not_supported_by_provider");
    out.end_object();
    out.end_array();
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
