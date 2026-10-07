#include "panopticon/linux_agent/sensor/fanotify_file.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::chrono::milliseconds pending_window{25};
constexpr std::chrono::milliseconds pending_hard_limit{1000};
constexpr std::size_t maximum_name_bytes = 4096U;
constexpr std::uint32_t maximum_handle_bytes = 128U;  // MAX_HANDLE_SZ
constexpr std::uint64_t watched_mask =
    FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CLOSE_WRITE | FAN_ATTRIB | FAN_ONDIR;
constexpr unsigned init_flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DFID_NAME;

bool prefix_matches(const std::string_view path, std::string_view prefix) {
    while (prefix.size() > 1U && prefix.back() == '/') prefix.remove_suffix(1U);
    if (prefix == "/") return !path.empty() && path.front() == '/';
    if (path.size() < prefix.size() || path.compare(0U, prefix.size(), prefix) != 0) return false;
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

bool any_prefix(const std::vector<std::string>& prefixes, const std::string_view path) {
    return std::any_of(prefixes.begin(), prefixes.end(), [path](const std::string& prefix) { return prefix_matches(path, prefix); });
}

std::string errno_text(const int error) { return std::strerror(error); }

}  // namespace

bool file_filter::selects(const std::string_view path) const {
    if (any_prefix(exclude, path)) return false;
    return include.empty() || any_prefix(include, path);
}

file_filter file_filter::defaults() {
    file_filter filter;
    filter.include = {"/etc", "/usr/bin", "/usr/sbin", "/usr/local", "/bin", "/sbin", "/lib", "/lib64", "/usr/lib", "/boot",
                      "/root", "/home", "/var/spool", "/var/www", "/opt", "/srv", "/tmp", "/var/tmp", "/dev/shm"};
    filter.exclude = {"/proc", "/sys", "/run/user", "/var/log/journal", "/tmp/.X11-unix"};
    return filter;
}

fanotify_decode_result decode_fanotify_events(const unsigned char* data, const std::size_t length) {
    fanotify_decode_result result;
    std::size_t offset = 0U;
    while (length - offset >= sizeof(fanotify_event_metadata)) {
        fanotify_event_metadata metadata{};
        std::memcpy(&metadata, data + offset, sizeof(metadata));
        if (metadata.vers != FANOTIFY_METADATA_VERSION || metadata.metadata_len < sizeof(metadata) ||
            metadata.event_len < metadata.metadata_len || metadata.event_len > length - offset) {
            result.malformed = true;
            return result;
        }
        const auto end = offset + metadata.event_len;
        if ((metadata.mask & FAN_Q_OVERFLOW) != 0U) {
            result.queue_overflow = true;
            offset = end;
            continue;
        }
        fanotify_decoded event;
        event.mask = metadata.mask;
        event.pid = static_cast<std::uint32_t>(metadata.pid);
        auto position = offset + metadata.metadata_len;
        while (end - position >= sizeof(fanotify_event_info_header)) {
            fanotify_event_info_header header{};
            std::memcpy(&header, data + position, sizeof(header));
            if (header.len < sizeof(header) || header.len > end - position) {
                result.malformed = true;
                return result;
            }
            if (header.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME || header.info_type == FAN_EVENT_INFO_TYPE_DFID) {
                constexpr std::size_t fixed = sizeof(fanotify_event_info_header) + sizeof(__kernel_fsid_t);
                constexpr std::size_t handle_header = 8U;  // handle_bytes (u32) + handle_type (int)
                if (header.len < fixed + handle_header) {
                    result.malformed = true;
                    return result;
                }
                std::uint32_t handle_bytes = 0U;
                std::memcpy(&handle_bytes, data + position + fixed, sizeof(handle_bytes));
                if (handle_bytes > maximum_handle_bytes || header.len < fixed + handle_header + handle_bytes) {
                    result.malformed = true;
                    return result;
                }
                std::memcpy(event.fsid.data(), data + position + sizeof(header), sizeof(event.fsid));
                event.handle.assign(data + position + fixed, data + position + fixed + handle_header + handle_bytes);
                event.has_location = true;
                if (header.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                    const auto name_start = position + fixed + handle_header + handle_bytes;
                    const auto name_limit = position + header.len;
                    const auto* terminator = static_cast<const unsigned char*>(std::memchr(data + name_start, '\0', name_limit - name_start));
                    if (terminator == nullptr || static_cast<std::size_t>(terminator - (data + name_start)) > maximum_name_bytes) {
                        result.malformed = true;
                        return result;
                    }
                    event.name.assign(reinterpret_cast<const char*>(data + name_start), static_cast<std::size_t>(terminator - (data + name_start)));
                    if (event.name.empty()) event.name = ".";
                } else {
                    event.name = ".";
                }
            }
            position += header.len;
        }
        result.events.push_back(std::move(event));
        offset = end;
    }
    if (offset != length) result.malformed = true;  // a partial record can only mean corruption
    return result;
}

fanotify_file_provider::fanotify_file_provider(fanotify_options options) : options_{std::move(options)} {}

fanotify_file_provider::~fanotify_file_provider() { stop(); }

std::vector<std::string> fanotify_file_provider::capabilities() const {
    return {"file.create", "file.modify", "file.delete", "file.rename", "file.attrib"};
}

std::string fanotify_file_provider::probe() {
    const int fd = ::fanotify_init(init_flags, O_RDONLY | O_LARGEFILE);
    if (fd >= 0) {
        ::close(fd);
        return {};
    }
    switch (errno) {
    case EPERM: return "fanotify requires CAP_SYS_ADMIN";
    case ENOSYS: return "fanotify is not available in this kernel";
    case EINVAL: return "kernel lacks FAN_REPORT_DFID_NAME (needs Linux 5.9)";
    default: return std::string{"fanotify_init: "} + errno_text(errno);
    }
}

result<bool> fanotify_file_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    queue_ = &queue;
    fan_fd_ = ::fanotify_init(init_flags, O_RDONLY | O_LARGEFILE);
    if (fan_fd_ < 0) return error{error_code::io_failure, std::string{"fanotify_init: "} + errno_text(errno)};
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        ::close(fan_fd_);
        fan_fd_ = -1;
        return error{error_code::io_failure, std::string{"eventfd: "} + errno_text(errno)};
    }
    mark_filesystems();
    if (marked_.load() == 0U) {
        std::string reason;
        {
            const std::lock_guard lock{failure_mutex_};
            reason = mark_failures_;
        }
        ::close(wake_fd_);
        ::close(fan_fd_);
        wake_fd_ = fan_fd_ = -1;
        return error{error_code::io_failure, "no filesystem could be marked" + (reason.empty() ? std::string{} : ": " + reason)};
    }
    tokens_ = static_cast<double>(options_.burst);
    last_refill_ = std::chrono::steady_clock::now();
    running_ = true;
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void fanotify_file_provider::stop() {
    if (!running_.exchange(false)) return;
    const std::uint64_t one = 1U;
    (void)!::write(wake_fd_, &one, sizeof(one));
    if (thread_.joinable()) thread_.join();
    for (const auto& [fsid, descriptor] : mounts_) ::close(descriptor);
    mounts_.clear();
    ::close(wake_fd_);
    ::close(fan_fd_);
    wake_fd_ = fan_fd_ = -1;
}

provider_health fanotify_file_provider::health() const {
    std::string reason;
    {
        const std::lock_guard lock{failure_mutex_};
        reason = mark_failures_;
    }
    const bool active = running_.load();
    if (active && !reason.empty()) reason = "some filesystems could not be marked: " + reason;
    return {std::string{name()}, active ? "active" : "stopped", reason, capabilities(), events_.load(), governed_.load() + overflows_.load()};
}

void fanotify_file_provider::mark_filesystems() {
    // Filesystems worth watching; pseudo filesystems (proc, sysfs, cgroup, devpts ...) are never marked.
    static const std::set<std::string, std::less<>> watched{"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "tmpfs", "overlay"};
    std::ifstream input{options_.mountinfo};
    std::ostringstream contents;
    contents << input.rdbuf();
    std::string failures;
    for (const auto& mount : parse_mountinfo(contents.str(), 4096U)) {
        if (watched.find(mount.fs_type) == watched.end()) continue;
        const int directory = ::open(mount.mount_point.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) continue;
        struct statfs info {};
        if (::fstatfs(directory, &info) != 0) {
            ::close(directory);
            continue;
        }
        const std::array<std::int32_t, 2> fsid{info.f_fsid.__val[0], info.f_fsid.__val[1]};
        const bool known = std::any_of(mounts_.begin(), mounts_.end(), [&](const auto& entry) { return entry.first == fsid; });
        if (known) {
            ::close(directory);
            continue;
        }
        if (::fanotify_mark(fan_fd_, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, watched_mask, AT_FDCWD, mount.mount_point.c_str()) != 0) {
            if (!failures.empty()) failures += "; ";
            failures += mount.fs_type + " " + mount.mount_point + ": " + errno_text(errno);
            ::close(directory);
            continue;
        }
        mounts_.emplace_back(fsid, directory);
        marked_.fetch_add(1U);
    }
    const std::lock_guard lock{failure_mutex_};
    mark_failures_ = failures;
}

void fanotify_file_provider::run() {
    std::vector<unsigned char> buffer(256U * 1024U);
    auto last_remark = std::chrono::steady_clock::now();
    while (running_.load()) {
        pollfd descriptors[2] = {{fan_fd_, POLLIN, 0}, {wake_fd_, POLLIN, 0}};
        // A half-seen rename is held only briefly: the kernel queues its two halves microseconds
        // apart, so they can straddle a read().
        if (::poll(descriptors, 2, pending_.valid ? static_cast<int>(pending_window.count()) : 1000) < 0 && errno != EINTR) break;
        if ((descriptors[1].revents & POLLIN) != 0) break;
        const auto drain = [&] {
            bool any = false;
            while (true) {
                const auto got = ::read(fan_fd_, buffer.data(), buffer.size());
                if (got > 0) {
                    any = true;
                    handle_buffer(buffer.data(), static_cast<std::size_t>(got));
                } else if (got < 0 && errno == EINTR) {
                    continue;
                } else {
                    return any;  // EAGAIN: drained
                }
            }
        };
        if ((descriptors[0].revents & POLLIN) != 0) (void)drain();
        const auto now = std::chrono::steady_clock::now();
        // A pending half is given up only when the descriptor is empty. The reader can be descheduled for far longer than
        // the window between the kernel queueing the two halves and this read, so a clock alone must not split a rename
        // whose other half is already waiting: read once more, and only an empty read lets the window decide.
        if (pending_.valid && now >= pending_.deadline && !drain()) flush_pending_move();
        if (now - last_remark >= options_.remark_interval) {
            mark_filesystems();
            last_remark = now;
        }
    }
}

void fanotify_file_provider::handle_buffer(const unsigned char* data, const std::size_t length) {
    const auto decoded = decode_fanotify_events(data, length);
    if (decoded.queue_overflow) overflows_.fetch_add(1U);
    for (const auto& event : decoded.events) handle_event(event);
}

bool fanotify_file_provider::take_token() {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
    last_refill_ = now;
    tokens_ = std::min(static_cast<double>(options_.burst), tokens_ + elapsed * static_cast<double>(options_.events_per_second));
    if (tokens_ < 1.0) return false;
    tokens_ -= 1.0;
    return true;
}

std::string fanotify_file_provider::resolve_directory(const fanotify_decoded& event, std::vector<unavailable_field>& unavailable) {
    if (!event.has_location) {
        unavailable.push_back({"file.path", unavailable_reason::not_supported_by_provider});
        return {};
    }
    std::string key{reinterpret_cast<const char*>(event.handle.data()), event.handle.size()};
    key.append(reinterpret_cast<const char*>(event.fsid.data()), sizeof(event.fsid));
    const auto now = std::chrono::steady_clock::now();
    if (const auto cached = path_cache_.find(key); cached != path_cache_.end() && cached->second.expires > now) return cached->second.path;

    const auto mount = std::find_if(mounts_.begin(), mounts_.end(), [&](const auto& entry) { return entry.first == event.fsid; });
    if (mount == mounts_.end()) {
        unavailable.push_back({"file.path", unavailable_reason::not_supported_by_provider});
        return {};
    }
    std::vector<unsigned char> handle{event.handle};
    const int descriptor = ::open_by_handle_at(mount->second, reinterpret_cast<file_handle*>(handle.data()), O_PATH | O_CLOEXEC);
    if (descriptor < 0) {
        const auto reason = (errno == ESTALE || errno == ENOENT) ? unavailable_reason::object_gone
                            : (errno == EPERM || errno == EACCES) ? unavailable_reason::permission_denied
                                                                  : unavailable_reason::not_supported_by_provider;
        unavailable.push_back({"file.path", reason});
        return {};
    }
    char buffer[4096];
    const auto link = ::readlink(("/proc/self/fd/" + std::to_string(descriptor)).c_str(), buffer, sizeof(buffer) - 1U);
    ::close(descriptor);
    if (link <= 0) {
        unavailable.push_back({"file.path", unavailable_reason::not_supported_by_provider});
        return {};
    }
    std::string path{buffer, static_cast<std::size_t>(link)};
    constexpr std::string_view deleted_suffix{" (deleted)"};
    if (path.size() > deleted_suffix.size() && path.compare(path.size() - deleted_suffix.size(), deleted_suffix.size(), deleted_suffix) == 0) {
        path.resize(path.size() - deleted_suffix.size());
    }
    if (path_cache_.size() >= options_.path_cache_entries) path_cache_.clear();
    path_cache_[key] = {path, now + options_.path_cache_ttl};
    return path;
}

void fanotify_file_provider::emit(raw_file_event event) {
    // Filter on the resolved path(s); an unresolved path cannot be filtered and is kept so the
    // gap is visible.
    const bool resolved = !event.path.empty() || (event.old_path.has_value() && !event.old_path->empty());
    if (resolved) {
        const bool selected = (!event.path.empty() && options_.filter.selects(event.path)) ||
                              (event.old_path.has_value() && !event.old_path->empty() && options_.filter.selects(*event.old_path));
        if (!selected) return;
    }
    events_.fetch_add(1U);
    raw_record record;
    record.time_unix_ns = clock_domain::now_unix_ns();
    record.source = {"fanotify_file", "FANOTIFY", confidence::observed};
    record.payload = std::move(event);
    (void)queue_->push(std::move(record));
}

void fanotify_file_provider::flush_pending_move() {
    if (!pending_.valid) return;
    raw_file_event event;
    event.pid = pending_.pid;
    event.operation = file_operation::rename;
    event.old_path = pending_.path;
    event.directory = pending_.directory;
    event.unavailable.push_back({"file.path", unavailable_reason::not_supported_by_provider});  // moved out of the watched filesystems
    pending_.valid = false;
    emit(std::move(event));
}

void fanotify_file_provider::flush_stale_move(const std::chrono::steady_clock::time_point now) {
    if (pending_.valid && now >= pending_.hard_deadline) flush_pending_move();
}

void fanotify_file_provider::handle_event(const fanotify_decoded& event) {
    if (event.pid == static_cast<std::uint32_t>(::getpid())) return;  // never report our own WAL and state writes
    // Merged events can arrive in a different order than they happened, so other events of the same
    // process may sit between the two halves of a rename: a pending half is closed only by its
    // MOVED_TO, a newer MOVED_FROM, an empty descriptor after its soft deadline (run), or its hard deadline. The soft
    // deadline is not checked here: this event may be the very half it is waiting for, already queued when the reader
    // was descheduled. The hard deadline bounds how stale a half can be and still pair with an unrelated later move.
    flush_stale_move(std::chrono::steady_clock::now());
    if (!take_token()) {
        governed_.fetch_add(1U);
        // A skipped event may have been the missing half; never pair across a gap.
        if (pending_.valid && (event.mask & FAN_MOVED_TO) != 0U) {
            pending_.valid = false;
            governed_.fetch_add(1U);
        }
        return;
    }
    std::vector<unavailable_field> unavailable;
    const auto directory_path = resolve_directory(event, unavailable);
    std::string path;
    if (!directory_path.empty()) {
        path = event.name == "." ? directory_path : (directory_path == "/" ? "/" + event.name : directory_path + "/" + event.name);
    }
    const bool is_directory = (event.mask & FAN_ONDIR) != 0U;
    // A moved or removed directory invalidates every cached path below it.
    if (is_directory && (event.mask & (FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO)) != 0U) path_cache_.clear();

    const auto make = [&](const file_operation operation) {
        raw_file_event out;
        out.pid = event.pid;
        out.operation = operation;
        out.path = path;
        out.directory = is_directory;
        out.unavailable = unavailable;
        return out;
    };
    if ((event.mask & FAN_CREATE) != 0U) emit(make(file_operation::create));
    // The kernel merges queued events with the same pid, directory and name, so in a rename chain
    // (a->b then b->c) one event can carry MOVED_TO and MOVED_FROM for "b". The arrival came first,
    // so the TO half is handled before the FROM half; separate FROM/TO events are unaffected.
    if ((event.mask & FAN_MOVED_TO) != 0U) {
        auto moved = make(file_operation::rename);
        if (pending_.valid && pending_.pid == event.pid) {
            moved.old_path = pending_.path;
            pending_.valid = false;
        } else {
            flush_pending_move();
            moved.unavailable.push_back({"file.old_path", unavailable_reason::not_supported_by_provider});  // moved in from outside
        }
        emit(std::move(moved));
    }
    if ((event.mask & FAN_MOVED_FROM) != 0U) {
        flush_pending_move();
        const auto started = std::chrono::steady_clock::now();
        pending_ = {true, event.pid, path, is_directory, started + pending_window, started + pending_hard_limit};
    }
    if ((event.mask & FAN_ATTRIB) != 0U) emit(make(file_operation::attrib));
    if ((event.mask & FAN_CLOSE_WRITE) != 0U) emit(make(file_operation::modify));
    if ((event.mask & FAN_DELETE) != 0U) emit(make(file_operation::remove));
}

}  // namespace panopticon::linux_agent::sensor
