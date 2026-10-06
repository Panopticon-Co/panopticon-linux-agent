#include "panopticon/linux_agent/sensor/kernel_change.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <optional>
#include <variant>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::size_t maximum_file_bytes = 4U << 20U;

// Reads a procfs file (their size is reported as 0, so read until the end or the cap). Returns
// nothing when it cannot be opened or is larger than the cap, so a huge file is never half-parsed.
std::optional<std::string> read_proc_file(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return std::nullopt;
    std::string out;
    char buffer[8192];
    for (;;) {
        const auto got = ::read(fd, buffer, sizeof(buffer));
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return std::nullopt;
        }
        if (got == 0) break;
        out.append(buffer, static_cast<std::size_t>(got));
        if (out.size() > maximum_file_bytes) {
            ::close(fd);
            return std::nullopt;
        }
    }
    ::close(fd);
    return out;
}

std::string mount_key(const mount_entry& mount) {
    return std::to_string(mount.mount_id) + '|' + mount.device + '|' + mount.root + '|' + mount.mount_point + '|' + mount.fs_type;
}

raw_kernel_event module_event(const kernel_event_kind kind, const module_entry& module) {
    raw_kernel_event event;
    event.kind = kind;
    event.module_name = module.name;
    event.module_size = module.size;
    event.module_state = module.state;
    return event;
}

raw_kernel_event mount_event(const kernel_event_kind kind, const mount_entry& mount) {
    raw_kernel_event event;
    event.kind = kind;
    event.mount_id = mount.mount_id;
    event.device = mount.device;
    event.source = mount.source;
    event.target = mount.mount_point;
    event.fs_type = mount.fs_type;
    event.options = mount.options;
    event.super_options = mount.super_options;
    return event;
}

}  // namespace

std::vector<raw_kernel_event> kernel_change_tracker::update_modules(const std::vector<module_entry>& now) {
    std::map<std::string, module_entry> next;
    for (const auto& module : now) next.emplace(module.name, module);
    std::vector<raw_kernel_event> events;
    if (modules_seeded_) {
        for (const auto& [name, old] : modules_) {
            const auto found = next.find(name);
            if (found == next.end() || found->second.size != old.size) events.push_back(module_event(kernel_event_kind::module_unload, old));
        }
        for (const auto& [name, current] : next) {
            const auto found = modules_.find(name);
            if (found == modules_.end() || found->second.size != current.size) events.push_back(module_event(kernel_event_kind::module_load, current));
        }
    }
    modules_ = std::move(next);
    modules_seeded_ = true;
    return events;
}

std::vector<raw_kernel_event> kernel_change_tracker::update_mounts(const std::vector<mount_entry>& now) {
    std::map<std::string, mount_entry> next;
    for (const auto& mount : now) next.emplace(mount_key(mount), mount);
    std::vector<raw_kernel_event> events;
    if (mounts_seeded_) {
        for (const auto& [key, old] : mounts_) {
            if (next.find(key) == next.end()) events.push_back(mount_event(kernel_event_kind::mount_removed, old));
        }
        for (const auto& [key, current] : next) {
            const auto found = mounts_.find(key);
            if (found == mounts_.end()) {
                events.push_back(mount_event(kernel_event_kind::mount_added, current));
            } else if (found->second.options != current.options || found->second.super_options != current.super_options) {
                events.push_back(mount_event(kernel_event_kind::mount_remounted, current));
            }
        }
    }
    mounts_ = std::move(next);
    mounts_seeded_ = true;
    return events;
}

kernel_change_provider::kernel_change_provider(kernel_change_options options) : options_{std::move(options)} {}

kernel_change_provider::~kernel_change_provider() { stop(); }

std::vector<std::string> kernel_change_provider::capabilities() const { return {"kernel.module_load", "kernel.module_unload", "mount.changed"}; }

std::string kernel_change_provider::probe() {
    const bool modules = read_proc_file(options_.proc_root / "modules").has_value();
    const bool mounts = read_proc_file(options_.proc_root / "self" / "mountinfo").has_value();
    if (modules || mounts) return {};
    return "neither " + (options_.proc_root / "modules").string() + " nor " + (options_.proc_root / "self" / "mountinfo").string() + " is readable";
}

result<bool> kernel_change_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    if (const auto reason = probe(); !reason.empty()) return error{error_code::io_failure, reason};
    queue_ = &queue;
    poll_once();  // the starting state; produces no events
    running_.store(true);
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void kernel_change_provider::poll_once() {
    std::string failure;
    std::vector<raw_kernel_event> events;
    if (const auto text = read_proc_file(options_.proc_root / "modules")) {
        const auto modules = parse_proc_modules(*text, options_.maximum_entries);
        if (modules.size() >= options_.maximum_entries) failure += "module list exceeds the limit; ";
        else for (auto& event : tracker_.update_modules(modules)) events.push_back(std::move(event));
    }
    if (const auto text = read_proc_file(options_.proc_root / "self" / "mountinfo")) {
        const auto mounts = parse_mountinfo(*text, options_.maximum_entries);
        if (mounts.size() >= options_.maximum_entries) failure += "mount list exceeds the limit; ";
        else for (auto& event : tracker_.update_mounts(mounts)) events.push_back(std::move(event));
    } else {
        failure += "cannot read mountinfo; ";
    }
    const auto now = clock_domain::now_unix_ns();
    std::size_t sent = 0U;
    for (auto& event : events) {
        if (sent >= options_.maximum_events_per_poll) {
            ++governed_;
            continue;
        }
        raw_record record;
        record.time_unix_ns = now;
        record.source = {"kernel_change", "PROCFS", confidence::reconstructed};
        record.payload = std::move(event);
        if (queue_ != nullptr && queue_->push(std::move(record))) ++events_;
        ++sent;
    }
    const std::lock_guard lock{failure_mutex_};
    failure_ = std::move(failure);
}

void kernel_change_provider::run() {
    while (running_.load()) {
        std::unique_lock lock{wake_mutex_};
        wake_.wait_for(lock, options_.interval, [this] { return !running_.load(); });
        lock.unlock();
        if (!running_.load()) break;
        poll_once();
    }
}

void kernel_change_provider::stop() {
    if (!running_.exchange(false)) return;
    {
        const std::lock_guard lock{wake_mutex_};
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}

provider_health kernel_change_provider::health() const {
    std::string reason;
    {
        const std::lock_guard lock{failure_mutex_};
        reason = failure_;
    }
    const bool active = running_.load();
    const std::string state = !active ? "stopped" : reason.empty() ? "active" : "degraded";
    return {std::string{name()}, state, reason, capabilities(), events_.load(), governed_.load()};
}

}  // namespace panopticon::linux_agent::sensor
