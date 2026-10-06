#include "panopticon/linux_agent/sensor/ebpf_process.hpp"

#include "panopticon/linux_agent/sensor/dns_message.hpp"
#include "panopticon_events.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string_view>
#include <vector>

#if defined(PANOPTICON_HAVE_EBPF)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

// Generated at build time from the compiled BPF object (cmake/embed_binary.cmake).
extern const unsigned char panopticon_bpf_object[];
extern const std::size_t panopticon_bpf_object_size;
#endif

namespace panopticon::linux_agent::sensor {
namespace {

namespace wire = ::panopticon::linux_agent::sensor::bpf;

// A hook this provider installs. `core` hooks are required for the provider to be useful at
// all; optional hooks are dropped (and reported) when the kernel cannot host them.
struct hook {
    const char* program;     // function name in panopticon.bpf.c
    const char* capability;  // catalog capability it provides
    bool core;
};
constexpr std::array<hook, 6U> process_hooks{{
    {"on_fork", "process.fork", true},
    {"on_exec", "process.exec", true},
    {"on_exit", "process.exit", true},
    {"on_rename", "process.rename", false},
    {"on_commit_creds", "process.cred_change", false},
    {"on_ptrace", "process.inject", false},
}};
// Network hooks run in the calling process, so the actor is exact. Connect is the one that makes
// the provider worth having; the rest are dropped (and reported) when the kernel cannot host them.
constexpr std::array<hook, 5U> network_hooks{{
    {"on_tcp_connect", "network.connect", true},
    {"on_tcp_accept", "network.accept", false},
    {"on_tcp_listen", "network.listen", false},
    {"on_udp_send", "network.udp_flow", false},
    {"on_udp6_send", "network.udp_flow", false},
}};

// Hooks on the kernel's LSM call sites. The mmap hook is the one that makes the provider worth
// having; the others are dropped (and reported) when the kernel cannot host them.
constexpr std::array<hook, 4U> security_hooks{{
    {"on_mmap_exec", "memory.exec_mapping", true},
    {"on_mprotect_exec", "memory.exec_mapping", false},
    {"on_bpf_syscall", "kernel.bpf_load", false},
    {"on_ns_switch", "process.ns_change", false},
}};

std::vector<hook> hooks_for(const ebpf_role role) {
    if (role == ebpf_role::network) return {network_hooks.begin(), network_hooks.end()};
    if (role == ebpf_role::security) return {security_hooks.begin(), security_hooks.end()};
    return {process_hooks.begin(), process_hooks.end()};
}

std::string address_text(const std::uint8_t family, const std::uint8_t* bytes) {
    char text[INET6_ADDRSTRLEN]{};
    if (::inet_ntop(family == 2U ? AF_INET : AF_INET6, bytes, text, sizeof(text)) == nullptr) return {};
    return text;
}

// Text of a NUL-terminated string stored in a fixed field of `capacity` bytes, of which only the
// first `available` are valid.
std::string_view bounded_string(const char* data, const std::size_t capacity, const std::size_t available) {
    const auto limit = std::min(capacity, available);
    const auto* end = static_cast<const char*>(std::memchr(data, '\0', limit));
    return {data, end != nullptr ? static_cast<std::size_t>(end - data) : limit};
}

std::optional<std::uint64_t> ticks_from_boot_ns(const std::uint64_t boot_ns, const clock_domain& clock) {
    if (boot_ns == 0U) return std::nullopt;
    // The kernel reports /proc/<pid>/stat starttime as nsec_to_clock_t(start_boottime).
    return boot_ns / (1'000'000'000ULL / clock.ticks_per_second());
}

provenance observed(const char* hook_name) { return {"ebpf", hook_name, confidence::observed}; }

// enum bpf_prog_type, as of Linux 6.x. A value this table does not know is reported as its number.
constexpr std::array<const char*, 33U> bpf_program_types{
    "unspec", "socket_filter", "kprobe", "sched_cls", "sched_act", "tracepoint", "xdp", "perf_event", "cgroup_skb",
    "cgroup_sock", "lwt_in", "lwt_out", "lwt_xmit", "sock_ops", "sk_skb", "cgroup_device", "sk_msg", "raw_tracepoint",
    "cgroup_sock_addr", "lwt_seg6local", "lirc_mode2", "sk_reuseport", "flow_dissector", "cgroup_sysctl",
    "raw_tracepoint_writable", "cgroup_sockopt", "tracing", "struct_ops", "ext", "lsm", "sk_lookup", "syscall", "netfilter"};

}  // namespace

std::vector<raw_record> decode_ebpf_process_sample(const void* data, const std::size_t size, const clock_domain& clock,
                                                   const procfs_limits& limits, bool* malformed) {
    if (malformed != nullptr) *malformed = false;
    constexpr auto header_bytes = __builtin_offsetof(wire::pan_event, filename);
    if (data == nullptr || size < header_bytes || size > sizeof(wire::pan_event)) {
        if (malformed != nullptr) *malformed = true;
        return {};
    }
    // Copy into an aligned, trivially-copyable local so no field is read through a pointer into
    // the shared buffer, and so nothing beyond `size` is ever interpreted.
    static thread_local wire::pan_event event;
    std::memcpy(&event, data, size);

    const auto time = clock.boottime_to_unix_ns(event.time_boot_ns);
    const auto start_ticks = ticks_from_boot_ns(event.start_boot_ns, clock);
    const auto comm = bounded_string(event.comm, wire::PAN_COMM_LEN, wire::PAN_COMM_LEN);
    std::vector<raw_record> records;

    switch (event.kind) {
    case wire::PAN_EVENT_FORK:
        records.push_back({time, observed("sched_process_fork"), raw_fork{event.pid, event.tid, event.child_pid, event.child_tid, start_ticks}});
        break;
    case wire::PAN_EVENT_EXEC: {
        constexpr auto args_offset = __builtin_offsetof(wire::pan_event, args);
        if (size < args_offset || event.args_len >= wire::PAN_ARGS_LEN || size < args_offset + event.args_len) {
            if (malformed != nullptr) *malformed = true;
            return {};
        }
        raw_exec exec;
        exec.tgid = event.pid;
        exec.pid = event.tid;
        exec.start_ticks = start_ticks;
        if (const auto filename = bounded_string(event.filename, wire::PAN_FILENAME_LEN, size - header_bytes); !filename.empty()) {
            exec.filename = std::string{filename};
        }
        bool truncated = (event.flags & wire::PAN_FLAG_ARGS_TRUNC) != 0U;
        exec.args = split_cmdline(std::string_view{event.args, event.args_len}, limits.maximum_args, limits.maximum_args_bytes, truncated);
        exec.args_truncated = truncated;
        records.push_back({time, observed("sched_process_exec"), std::move(exec)});
        break;
    }
    case wire::PAN_EVENT_EXIT:
        records.push_back({time, observed("sched_process_exit"), raw_exit{event.pid, event.pid, event.exit_code, 0U}});
        break;
    case wire::PAN_EVENT_RENAME:
        records.push_back({time, observed("task_rename"), raw_comm_change{event.pid, event.tid, std::string{comm}}});
        break;
    case wire::PAN_EVENT_CRED:
        if ((event.flags & wire::PAN_FLAG_CRED_UID) != 0U) {
            records.push_back({time, observed("commit_creds"), raw_credential_change{event.pid, event.tid, true, event.uid, event.euid}});
        }
        if ((event.flags & wire::PAN_FLAG_CRED_GID) != 0U) {
            records.push_back({time, observed("commit_creds"), raw_credential_change{event.pid, event.tid, false, event.gid, event.egid}});
        }
        break;
    case wire::PAN_EVENT_PTRACE:
        records.push_back({time, observed("security_ptrace_access_check"),
                           raw_ptrace{event.pid, event.tid, event.tracer_pid, event.tracer_pid, "ptrace_access"}});
        break;
    case wire::PAN_EVENT_NET_CONNECT:
    case wire::PAN_EVENT_NET_ACCEPT:
    case wire::PAN_EVENT_NET_LISTEN:
    case wire::PAN_EVENT_NET_UDP: {
        const bool known_family = event.net_family == 2U || event.net_family == 10U;
        const bool known_proto = event.net_proto == 6U || event.net_proto == 17U;
        if (!known_family || !known_proto) {
            if (malformed != nullptr) *malformed = true;
            return {};
        }
        raw_network_event net;
        const char* hook_name = "tcp_connect";
        switch (event.kind) {
        case wire::PAN_EVENT_NET_ACCEPT:
            net.operation = network_operation::accept;
            net.state = "established";
            hook_name = "inet_csk_accept";
            break;
        case wire::PAN_EVENT_NET_LISTEN:
            net.operation = network_operation::listen;
            net.state = "listen";
            hook_name = "inet_listen";
            break;
        case wire::PAN_EVENT_NET_UDP:
            net.operation = network_operation::udp_flow;
            hook_name = "udp_sendmsg";
            break;
        default:
            net.operation = network_operation::connect;
            net.state = "syn_sent";
            break;
        }
        net.protocol = event.net_proto == 6U ? "tcp" : "udp";
        net.family = event.net_family == 2U ? "inet" : "inet6";
        net.local_address = address_text(event.net_family, event.net_saddr);
        net.local_port = static_cast<std::uint16_t>(event.net_sport);
        if (event.kind != wire::PAN_EVENT_NET_LISTEN) {
            net.remote_address = address_text(event.net_family, event.net_daddr);
            net.remote_port = static_cast<std::uint16_t>(event.net_dport);
        }
        net.uid = event.uid;
        net.pid = event.pid;
        net.holders = 1U;
        // The hook sees the socket before any file descriptor is attached to it.
        net.unavailable.push_back({"network.socket_inode", unavailable_reason::not_supported_by_provider});
        records.push_back({time, observed(hook_name), std::move(net)});
        break;
    }
    case wire::PAN_EVENT_MEM_MAP:
    case wire::PAN_EVENT_MEM_PROTECT: {
        if (event.mem_backing != wire::PAN_MEM_ANON && event.mem_backing != wire::PAN_MEM_MEMFD && event.mem_backing != wire::PAN_MEM_FILE) {
            if (malformed != nullptr) *malformed = true;
            return {};
        }
        raw_security_event memory;
        memory.kind = security_kind::memory_exec_mapping;
        memory.pid = event.pid;
        const bool mapping = event.kind == wire::PAN_EVENT_MEM_MAP;
        memory.operation = mapping ? "mmap" : "mprotect";
        memory.backing = event.mem_backing == wire::PAN_MEM_ANON ? "anonymous" : event.mem_backing == wire::PAN_MEM_MEMFD ? "memfd" : "file";
        memory.write_exec = event.mem_write != 0U;
        memory.address = event.mem_addr;
        memory.length = event.mem_length;
        records.push_back({time, observed(mapping ? "security_mmap_file" : "security_file_mprotect"), std::move(memory)});
        break;
    }
    case wire::PAN_EVENT_BPF: {
        const char* command = event.bpf_cmd == 5U ? "prog_load" : event.bpf_cmd == 8U ? "prog_attach"
                              : event.bpf_cmd == 17U ? "raw_tracepoint_open" : event.bpf_cmd == 28U ? "link_create" : nullptr;
        if (command == nullptr) {
            if (malformed != nullptr) *malformed = true;
            return {};
        }
        raw_security_event load;
        load.kind = security_kind::bpf_load;
        load.pid = event.pid;
        load.command = command;
        if (event.bpf_cmd == 5U) {
            load.program_type = event.bpf_type < bpf_program_types.size() ? bpf_program_types[event.bpf_type] : "type_" + std::to_string(event.bpf_type);
        } else if (event.bpf_cmd == 8U || event.bpf_cmd == 28U) {
            load.attach_type = event.bpf_type;
        }
        load.name = std::string{bounded_string(event.obj_name, wire::PAN_COMM_LEN, wire::PAN_COMM_LEN)};
        records.push_back({time, observed("security_bpf"), std::move(load)});
        break;
    }
    case wire::PAN_EVENT_DNS_QUERY: {
        const bool known_family = event.net_family == 2U || event.net_family == 10U;
        if (!known_family || event.net_proto != 17U || event.dns_len < 17U || event.dns_len > wire::PAN_DNS_CAPTURE ||
            size < header_bytes + event.dns_len) {
            if (malformed != nullptr) *malformed = true;
            return {};
        }
        const auto question = parse_dns_query(std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(event.filename), event.dns_len});
        // Traffic to port 53 that is not a DNS question is not an error: the udp flow record still names it.
        if (!question.has_value()) return {};
        raw_dns_query dns;
        dns.pid = event.pid;
        dns.family = event.net_family == 2U ? "inet" : "inet6";
        dns.local_address = address_text(event.net_family, event.net_saddr);
        dns.local_port = static_cast<std::uint16_t>(event.net_sport);
        dns.server_address = address_text(event.net_family, event.net_daddr);
        dns.server_port = static_cast<std::uint16_t>(event.net_dport);
        dns.transaction_id = question->transaction_id;
        dns.recursion_desired = question->recursion_desired;
        dns.name = question->name;
        dns.type = dns_type_name(question->type);
        dns.klass = dns_class_name(question->klass);
        records.push_back({time, observed("udp_sendmsg"), std::move(dns)});
        break;
    }
    case wire::PAN_EVENT_NS_CHANGE: {
        raw_namespace_change change;
        change.tgid = event.pid;
        change.tid = event.tid;
        for (std::size_t index = 0U; index < change.before.size(); ++index) {
            change.before[index] = event.ns_old[index];
            change.after[index] = event.ns_new[index];
        }
        records.push_back({time, observed("switch_task_namespaces"), change});
        break;
    }
    default:
        if (malformed != nullptr) *malformed = true;
        break;
    }
    return records;
}

#if defined(PANOPTICON_HAVE_EBPF)

namespace {

// libbpf reports load and verifier failures through a global print callback; capture them while
// a provider is starting so the failure reason reaches health instead of stderr.
std::string* capture_target = nullptr;

int capture_libbpf(const enum libbpf_print_level level, const char* format, va_list arguments) {
    if (level == LIBBPF_DEBUG || capture_target == nullptr) return 0;
    char line[512];
    std::vsnprintf(line, sizeof(line), format, arguments);
    capture_target->append(line);
    if (capture_target->size() > 8192U) capture_target->erase(0U, capture_target->size() - 4096U);
    return 0;
}

// Last lines of a captured libbpf log, flattened for a health reason.
std::string summarise(const std::string& log) {
    std::string tail = log.size() > 600U ? log.substr(log.size() - 600U) : log;
    for (auto& character : tail) {
        if (character == '\n' || character == '\r') character = ' ';
    }
    return tail;
}

struct log_capture {
    std::string text;
    log_capture() : previous_{libbpf_set_print(capture_libbpf)} { capture_target = &text; }
    ~log_capture() {
        capture_target = nullptr;
        libbpf_set_print(previous_);
    }
    log_capture(const log_capture&) = delete;
    log_capture& operator=(const log_capture&) = delete;

private:
    libbpf_print_fn_t previous_;
};

}  // namespace

bool ebpf_process_built() noexcept { return true; }

ebpf_process_provider::ebpf_process_provider(const clock_domain& clock, ebpf_process_options options, const ebpf_role role)
    : clock_{clock}, options_{std::move(options)}, role_{role}, own_pid_{static_cast<std::uint32_t>(::getpid())} {}

ebpf_process_provider::~ebpf_process_provider() { stop(); }

std::vector<std::string> ebpf_process_provider::capabilities() const {
    if (state_ == "active") return capabilities_;
    std::vector<std::string> all;
    for (const auto& entry : hooks_for(role_)) {
        if (std::find(all.begin(), all.end(), entry.capability) == all.end()) all.emplace_back(entry.capability);
    }
    return all;
}

std::string ebpf_process_provider::probe() {
    std::error_code ignored;
    if (!std::filesystem::exists("/sys/kernel/btf/vmlinux", ignored)) {
        return reason_ = "kernel_feature_missing: no kernel BTF (/sys/kernel/btf/vmlinux); CO-RE programs cannot be relocated";
    }
    log_capture capture;
    const auto ring = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, nullptr);
    if (ring == 0) return reason_ = "kernel_feature_missing: BPF ring buffer maps need Linux 5.8 or newer";
    if (ring < 0) {
        return reason_ = -ring == EPERM || -ring == EACCES ? "permission_denied: loading eBPF programs needs root or CAP_BPF and CAP_PERFMON"
                                                            : std::string{"probe failed: "} + std::strerror(-ring);
    }
    return {};
}

result<bool> ebpf_process_provider::start(record_queue& queue) {
    if (object_ != nullptr) return true;
    queue_ = &queue;
    stop_ = false;
    poll_failed_ = false;
    capabilities_.clear();
    missing_programs_.clear();
    drops_seen_ = 0U;

    const auto fail = [this](std::string reason, const error_code code = error_code::unsupported_action) -> result<bool> {
        release();
        state_ = "unavailable";
        reason_ = std::move(reason);
        return error{code, reason_};
    };

    // Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK instead of the memory cgroup.
    const rlimit unlimited{RLIM_INFINITY, RLIM_INFINITY};
    (void)::setrlimit(RLIMIT_MEMLOCK, &unlimited);

    log_capture capture;
    object_ = bpf_object__open_mem(panopticon_bpf_object, panopticon_bpf_object_size, nullptr);
    if (object_ == nullptr) return fail("cannot open the embedded eBPF object: " + summarise(capture.text), error_code::corrupt_data);

    if (auto* events_map = bpf_object__find_map_by_name(object_, "events"); events_map != nullptr) {
        (void)bpf_map__set_max_entries(events_map, options_.ringbuf_bytes);
    }

    // The object holds the programs of every role; this provider loads only its own. The others
    // would attach a second copy of hooks another provider already serves.
    const auto active_hooks = hooks_for(role_);
    {
        ::bpf_program* program = nullptr;
        bpf_object__for_each_program(program, object_) {
            const std::string_view program_name = bpf_program__name(program);
            const bool ours = std::any_of(active_hooks.begin(), active_hooks.end(), [&](const hook& entry) { return program_name == entry.program; });
            if (!ours) (void)bpf_program__set_autoload(program, false);
        }
    }

    // Programs whose hook is absent from this kernel are not loaded: the verifier would reject
    // the whole object otherwise.
    for (const auto& entry : active_hooks) {
        auto* program = bpf_object__find_program_by_name(object_, entry.program);
        if (program == nullptr) return fail(std::string{"embedded eBPF object lacks program "} + entry.program, error_code::corrupt_data);
        const std::string section = bpf_program__section_name(program);
        const auto slash = section.find('/');
        const auto target = section.substr(slash == std::string::npos ? 0U : slash + 1U);
        const auto attach_type = section.rfind("fentry/", 0U) == 0U   ? BPF_TRACE_FENTRY
                                 : section.rfind("fexit/", 0U) == 0U ? BPF_TRACE_FEXIT
                                                                     : BPF_TRACE_RAW_TP;
        if (libbpf_find_vmlinux_btf_id(target.c_str(), attach_type) > 0) continue;
        if (entry.core) {
            return fail("kernel_feature_missing: kernel BTF has no hook " + target + " (required for " + entry.capability + ")");
        }
        (void)bpf_program__set_autoload(program, false);
        missing_programs_.push_back(entry.capability);
    }

    if (const auto loaded = bpf_object__load(object_); loaded != 0) {
        const auto code = -loaded == EPERM || -loaded == EACCES ? "permission_denied: " : "load failed: ";
        return fail(std::string{code} + std::strerror(-loaded) + " " + summarise(capture.text));
    }

    for (const auto& entry : active_hooks) {
        auto* program = bpf_object__find_program_by_name(object_, entry.program);
        if (!bpf_program__autoload(program)) continue;
        auto* link = bpf_program__attach(program);
        if (link == nullptr) {
            const auto attach_error = errno;
            if (entry.core) {
                return fail(std::string{"cannot attach "} + entry.program + ": " + std::strerror(attach_error) + " " + summarise(capture.text));
            }
            missing_programs_.push_back(entry.capability);
            continue;
        }
        links_.push_back(link);
        if (std::find(capabilities_.begin(), capabilities_.end(), entry.capability) == capabilities_.end()) capabilities_.emplace_back(entry.capability);
    }

    if (auto* drops_map = bpf_object__find_map_by_name(object_, "drops"); drops_map != nullptr) drops_map_fd_ = bpf_map__fd(drops_map);
    auto* events_map = bpf_object__find_map_by_name(object_, "events");
    if (events_map == nullptr) return fail("embedded eBPF object lacks the events ring buffer", error_code::corrupt_data);
    const auto callback = [](void* context, void* data, const std::size_t size) -> int {
        return static_cast<ebpf_process_provider*>(context)->on_sample(data, size);
    };
    ring_ = ring_buffer__new(bpf_map__fd(events_map), callback, this, nullptr);
    if (ring_ == nullptr) return fail(std::string{"cannot create ring buffer reader: "} + std::strerror(errno));

    state_ = "active";
    reason_.clear();
    if (!missing_programs_.empty()) {
        reason_ = "kernel cannot host:";
        for (const auto& capability : missing_programs_) reason_ += " " + capability;
    }
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void ebpf_process_provider::run() {
    // The kernel wakes this poll as soon as a record is submitted (the programs submit with flags 0), so the
    // timeout only bounds how long a stop request waits; a short one is 10 idle wake-ups a second per ring.
    while (!stop_.load(std::memory_order_relaxed)) {
        const auto polled = ring_buffer__poll(ring_, 1000);
        if (polled < 0 && polled != -EINTR) {
            poll_failed_ = true;
            return;
        }
    }
    (void)ring_buffer__consume(ring_);  // whatever the kernel queued before shutdown
}

int ebpf_process_provider::on_sample(const void* data, const std::size_t size) {
    bool malformed = false;
    auto records = decode_ebpf_process_sample(data, size, clock_, options_.limits, &malformed);
    if (malformed) ++malformed_;
    for (auto& record : records) {
        // The sensor's own connections (the uplink to the Manager) are not telemetry: reporting
        // them would make every delivered batch produce the next record.
        if (const auto* net = std::get_if<raw_network_event>(&record.payload); net != nullptr && options_.skip_own_network_events && net->pid == own_pid_) continue;
        // The sensor loads its own BPF programs; reporting that would be noise about itself.
        if (const auto* load = std::get_if<raw_security_event>(&record.payload); load != nullptr && options_.skip_own_network_events && load->pid == own_pid_) continue;
        if (const auto* query = std::get_if<raw_dns_query>(&record.payload); query != nullptr && options_.skip_own_network_events && query->pid == own_pid_) continue;
        (void)queue_->push(std::move(record));
        ++events_;
    }
    return 0;
}

void ebpf_process_provider::stop() {
    stop_ = true;
    if (thread_.joinable()) thread_.join();
    release();
    if (state_ == "active") state_ = "stopped";
}

void ebpf_process_provider::release() {
    if (ring_ != nullptr) {
        ring_buffer__free(ring_);
        ring_ = nullptr;
    }
    for (auto* link : links_) bpf_link__destroy(link);
    links_.clear();
    if (object_ != nullptr) {
        bpf_object__close(object_);
        object_ = nullptr;
    }
    drops_map_fd_ = -1;
}

provider_health ebpf_process_provider::health() const {
    auto reason = reason_;
    auto state = state_;
    if (state == "active" && poll_failed_.load()) {
        state = "degraded";
        reason = "ring buffer polling failed";
    }
    if (malformed_.load() > 0U) reason += (reason.empty() ? "" : "; ") + std::to_string(malformed_.load()) + " malformed samples";
    return {std::string{name()}, state, reason, capabilities(), events_.load(), drops_seen_};
}

std::uint64_t ebpf_process_provider::take_losses() {
    if (drops_map_fd_ < 0) return 0U;
    const std::uint32_t key = 0U;
    std::uint64_t total = 0U;
    if (bpf_map_lookup_elem(drops_map_fd_, &key, &total) != 0 || total <= drops_seen_) return 0U;
    const auto delta = total - drops_seen_;
    drops_seen_ = total;
    return delta;
}

#else  // built without eBPF support

bool ebpf_process_built() noexcept { return false; }

ebpf_process_provider::ebpf_process_provider(const clock_domain& clock, ebpf_process_options options, const ebpf_role role)
    : clock_{clock}, options_{std::move(options)}, role_{role}, own_pid_{static_cast<std::uint32_t>(::getpid())} {}
ebpf_process_provider::~ebpf_process_provider() = default;

std::vector<std::string> ebpf_process_provider::capabilities() const {
    std::vector<std::string> all;
    for (const auto& entry : hooks_for(role_)) {
        if (std::find(all.begin(), all.end(), entry.capability) == all.end()) all.emplace_back(entry.capability);
    }
    return all;
}

std::string ebpf_process_provider::probe() {
    return "kernel_feature_missing: this build has no eBPF support (clang, libelf, zlib or vmlinux.h was missing at build time)";
}

result<bool> ebpf_process_provider::start(record_queue&) { return error{error_code::unsupported_action, probe()}; }
void ebpf_process_provider::stop() {}
void ebpf_process_provider::run() {}
int ebpf_process_provider::on_sample(const void*, std::size_t) { return 0; }
void ebpf_process_provider::release() {}
provider_health ebpf_process_provider::health() const { return {std::string{name()}, "unavailable", probe(), capabilities(), 0U, 0U}; }
std::uint64_t ebpf_process_provider::take_losses() { return 0U; }

#endif

}  // namespace panopticon::linux_agent::sensor
