#include "panopticon/linux_agent/sensor/ebpf_process.hpp"

#include "panopticon_events.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string_view>

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
constexpr std::array<hook, 6U> hooks{{
    {"on_fork", "process.fork", true},
    {"on_exec", "process.exec", true},
    {"on_exit", "process.exit", true},
    {"on_rename", "process.rename", false},
    {"on_commit_creds", "process.cred_change", false},
    {"on_ptrace", "process.inject", false},
}};

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

ebpf_process_provider::ebpf_process_provider(const clock_domain& clock, ebpf_process_options options)
    : clock_{clock}, options_{std::move(options)} {}

ebpf_process_provider::~ebpf_process_provider() { stop(); }

std::vector<std::string> ebpf_process_provider::capabilities() const {
    if (state_ == "active") return capabilities_;
    std::vector<std::string> all;
    for (const auto& entry : hooks) all.emplace_back(entry.capability);
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

    // Programs whose hook is absent from this kernel are not loaded: the verifier would reject
    // the whole object otherwise.
    for (const auto& entry : hooks) {
        auto* program = bpf_object__find_program_by_name(object_, entry.program);
        if (program == nullptr) return fail(std::string{"embedded eBPF object lacks program "} + entry.program, error_code::corrupt_data);
        const std::string section = bpf_program__section_name(program);
        const auto slash = section.find('/');
        const auto target = section.substr(slash == std::string::npos ? 0U : slash + 1U);
        const auto attach_type = section.rfind("fentry/", 0U) == 0U ? BPF_TRACE_FENTRY : BPF_TRACE_RAW_TP;
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

    for (const auto& entry : hooks) {
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
        capabilities_.emplace_back(entry.capability);
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
    while (!stop_.load(std::memory_order_relaxed)) {
        const auto polled = ring_buffer__poll(ring_, 100);
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
    return {"ebpf_process", state, reason, capabilities(), events_.load(), drops_seen_};
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

ebpf_process_provider::ebpf_process_provider(const clock_domain& clock, ebpf_process_options options)
    : clock_{clock}, options_{std::move(options)} {}
ebpf_process_provider::~ebpf_process_provider() = default;

std::vector<std::string> ebpf_process_provider::capabilities() const {
    std::vector<std::string> all;
    for (const auto& entry : hooks) all.emplace_back(entry.capability);
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
provider_health ebpf_process_provider::health() const { return {"ebpf_process", "unavailable", probe(), capabilities(), 0U, 0U}; }
std::uint64_t ebpf_process_provider::take_losses() { return 0U; }

#endif

}  // namespace panopticon::linux_agent::sensor
