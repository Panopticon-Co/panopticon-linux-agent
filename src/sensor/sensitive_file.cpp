#include "panopticon/linux_agent/sensor/sensitive_file.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"

#include <fcntl.h>
#include <fnmatch.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <system_error>

namespace panopticon::linux_agent::sensor {

namespace fs = std::filesystem;

namespace {

constexpr unsigned init_flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK;
constexpr std::uint64_t watched_mask = FAN_OPEN;
constexpr std::size_t maximum_homes = 256U;
constexpr std::size_t maximum_watched = 512U;

bool has_wildcard(const std::string_view text) { return text.find_first_of("*?[") != std::string_view::npos; }

}  // namespace

std::vector<std::string> sensitive_file_defaults() {
    return {
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/security/opasswd",
        "/etc/krb5.keytab",
        "/etc/ssh/ssh_host_*_key",
        "/etc/ssl/private/*",
        "~/.ssh/id_*",
        "~/.aws/credentials",
        "~/.azure/accessTokens.json",
        "~/.config/gcloud/credentials.db",
        "~/.config/gcloud/application_default_credentials.json",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.git-credentials",
        "~/.netrc",
        "~/.pgpass",
    };
}

std::vector<std::string> expand_sensitive_patterns(const std::vector<std::string>& patterns, const std::vector<std::string>& home_directories,
                                                   const fs::path& root, const std::size_t maximum) {
    std::set<std::string> found;
    const auto add_matches = [&](const std::string& pattern) {
        if (pattern.empty() || pattern.front() != '/') return;
        const auto slash = pattern.find_last_of('/');
        const auto directory = pattern.substr(0U, slash == 0U ? 1U : slash);
        const auto leaf = pattern.substr(slash + 1U);
        if (leaf.empty() || has_wildcard(directory)) return;  // a wildcard is only supported in the last component
        const fs::path real_directory = root / fs::path{directory}.relative_path();
        if (!has_wildcard(leaf)) {
            std::error_code ec;
            if (fs::exists(real_directory / leaf, ec)) found.insert(pattern);
            return;
        }
        std::error_code ec;
        for (fs::directory_iterator it{real_directory, ec}, end; !ec && it != end && found.size() < maximum; it.increment(ec)) {
            const auto name = it->path().filename().string();
            std::error_code type_error;
            if (::fnmatch(leaf.c_str(), name.c_str(), FNM_PERIOD) == 0 && !it->is_directory(type_error)) {
                found.insert((directory == "/" ? std::string{} : directory) + "/" + name);
            }
        }
    };
    for (const auto& pattern : patterns) {
        if (found.size() >= maximum) break;
        if (pattern.rfind("~/", 0U) == 0U) {
            for (const auto& home : home_directories) add_matches(home + pattern.substr(1U));
        } else {
            add_matches(pattern);
        }
    }
    return {found.begin(), found.end()};
}

sensitive_file_provider::sensitive_file_provider(sensitive_file_options options) : options_{std::move(options)} {
    if (options_.patterns.empty()) options_.patterns = sensitive_file_defaults();
}

sensitive_file_provider::~sensitive_file_provider() { stop(); }

std::string sensitive_file_provider::probe() {
    const int fd = ::fanotify_init(init_flags, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd >= 0) {
        ::close(fd);
        return {};
    }
    if (errno == EPERM) return "fanotify requires CAP_SYS_ADMIN";
    if (errno == ENOSYS) return "fanotify is not available in this kernel";
    return std::string{"fanotify_init: "} + std::strerror(errno);
}

result<bool> sensitive_file_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    queue_ = &queue;
    fan_fd_ = ::fanotify_init(init_flags, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fan_fd_ < 0) return error{error_code::io_failure, std::string{"fanotify_init: "} + std::strerror(errno)};
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        ::close(fan_fd_);
        fan_fd_ = -1;
        return error{error_code::io_failure, std::string{"eventfd: "} + std::strerror(errno)};
    }
    remark();
    tokens_ = static_cast<double>(options_.burst);
    last_refill_ = std::chrono::steady_clock::now();
    running_ = true;
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void sensitive_file_provider::stop() {
    if (!running_.exchange(false)) return;
    const std::uint64_t one = 1U;
    (void)!::write(wake_fd_, &one, sizeof(one));
    if (thread_.joinable()) thread_.join();
    ::close(wake_fd_);
    ::close(fan_fd_);
    wake_fd_ = fan_fd_ = -1;
}

provider_health sensitive_file_provider::health() const {
    const bool active = running_.load();
    std::string reason;
    if (active && watched_.load() == 0U) reason = "no credential file exists to watch yet";
    return {std::string{name()}, active ? "active" : "stopped", reason, capabilities(), events_.load(), governed_.load() + overflows_.load()};
}

void sensitive_file_provider::remark() {
    std::ifstream input{options_.root / fs::path{options_.passwd}.relative_path()};
    if (!input.is_open()) input.open(options_.passwd);
    std::ostringstream contents;
    contents << input.rdbuf();
    std::vector<std::string> homes{"/root"};
    for (const auto& entry : parse_passwd(contents.str(), maximum_homes)) {
        if (entry.home.empty() || entry.home.front() != '/' || entry.home == "/" || entry.home == "/nonexistent") continue;
        if (std::find(homes.begin(), homes.end(), entry.home) == homes.end()) homes.push_back(entry.home);
    }
    std::uint64_t marked = 0U;
    for (const auto& path : expand_sensitive_patterns(options_.patterns, homes, options_.root, maximum_watched)) {
        const auto real = (options_.root / fs::path{path}.relative_path()).string();
        // Marking again is harmless and re-establishes the mark on a file that was replaced.
        if (::fanotify_mark(fan_fd_, FAN_MARK_ADD, watched_mask, AT_FDCWD, real.c_str()) == 0) ++marked;
    }
    watched_.store(marked);
}

void sensitive_file_provider::run() {
    std::vector<unsigned char> buffer(64U * 1024U);
    auto last_remark = std::chrono::steady_clock::now();
    while (running_.load()) {
        pollfd descriptors[2] = {{fan_fd_, POLLIN, 0}, {wake_fd_, POLLIN, 0}};
        if (::poll(descriptors, 2, 1000) < 0 && errno != EINTR) break;
        if ((descriptors[1].revents & POLLIN) != 0) break;
        if ((descriptors[0].revents & POLLIN) != 0) {
            while (true) {
                const auto got = ::read(fan_fd_, buffer.data(), buffer.size());
                if (got > 0) handle_buffer(buffer.data(), static_cast<std::size_t>(got));
                else if (got < 0 && errno == EINTR) continue;
                else break;
            }
        }
        const auto now = std::chrono::steady_clock::now();
        if (now - last_remark >= options_.remark_interval) {
            remark();
            last_remark = now;
            for (auto it = recent_.begin(); it != recent_.end();) it = now - it->second > options_.repeat_window ? recent_.erase(it) : std::next(it);
        }
    }
}

void sensitive_file_provider::handle_buffer(const unsigned char* data, const std::size_t length) {
    std::size_t offset = 0U;
    while (length - offset >= FAN_EVENT_METADATA_LEN) {
        fanotify_event_metadata event;
        std::memcpy(&event, data + offset, sizeof(event));
        if (event.vers != FANOTIFY_METADATA_VERSION || event.event_len < FAN_EVENT_METADATA_LEN || event.event_len > length - offset) return;
        offset += event.event_len;
        const int descriptor = event.fd;
        if ((event.mask & FAN_Q_OVERFLOW) != 0U) overflows_.fetch_add(1U);
        if (descriptor < 0) continue;
        std::string path;
        char link[4096];
        const auto got = ::readlink(("/proc/self/fd/" + std::to_string(descriptor)).c_str(), link, sizeof(link) - 1U);
        ::close(descriptor);
        if (got > 0) path.assign(link, static_cast<std::size_t>(got));
        if (event.pid == static_cast<std::int32_t>(::getpid())) continue;  // the sensor hashing its own inventory is not telemetry
        if ((event.mask & FAN_OPEN) == 0U) continue;

        const auto now = std::chrono::steady_clock::now();
        const auto key = std::to_string(event.pid) + " " + path;
        if (const auto seen = recent_.find(key); seen != recent_.end() && now - seen->second < options_.repeat_window) continue;
        const auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
        last_refill_ = now;
        tokens_ = std::min(static_cast<double>(options_.burst), tokens_ + elapsed * static_cast<double>(options_.events_per_second));
        if (tokens_ < 1.0) {
            governed_.fetch_add(1U);
            continue;
        }
        tokens_ -= 1.0;
        if (recent_.size() >= 4096U) recent_.clear();
        recent_[key] = now;

        raw_file_event file;
        file.pid = static_cast<std::uint32_t>(event.pid);
        file.operation = file_operation::open_sensitive;
        file.path = std::move(path);
        if (file.path.empty()) file.unavailable.push_back({"file.path", unavailable_reason::not_supported_by_provider});
        events_.fetch_add(1U);
        raw_record record;
        record.time_unix_ns = clock_domain::now_unix_ns();
        record.source = {"sensitive_file", "FANOTIFY", confidence::observed};
        record.payload = std::move(file);
        (void)queue_->push(std::move(record));
    }
}

}  // namespace panopticon::linux_agent::sensor
