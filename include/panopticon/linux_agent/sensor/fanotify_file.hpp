#pragma once

#include "panopticon/linux_agent/sensor/provider.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Which paths produce file telemetry. Prefixes match on a directory boundary ("/etc" matches
// "/etc" and "/etc/passwd", not "/etcetera"); exclusion wins over inclusion.
struct file_filter {
    std::vector<std::string> include;
    std::vector<std::string> exclude;

    [[nodiscard]] bool selects(std::string_view path) const;
    // Persistence, credential, binary and staging locations; excludes /proc, /sys, /dev and
    // /run/user. The daemon adds its own state directories before use.
    [[nodiscard]] static file_filter defaults();
};

struct fanotify_options {
    file_filter filter{file_filter::defaults()};
    std::uint32_t events_per_second{5000U};  // governor: sustained rate
    std::uint32_t burst{10000U};             // governor: bucket size
    std::size_t path_cache_entries{4096U};
    std::chrono::seconds path_cache_ttl{60};
    std::chrono::seconds remark_interval{30};  // look for newly mounted filesystems
    std::filesystem::path mountinfo{"/proc/self/mountinfo"};
};

// One kernel event after bounds-checked decoding (no kernel access needed to produce it).
struct fanotify_decoded {
    std::uint64_t mask{};
    std::uint32_t pid{};
    std::array<std::int32_t, 2> fsid{};
    std::vector<unsigned char> handle;  // a complete `struct file_handle` of the containing directory
    std::string name;                   // "." when the event concerns the directory itself
    bool has_location{false};
};

struct fanotify_decode_result {
    std::vector<fanotify_decoded> events;
    bool queue_overflow{false};  // FAN_Q_OVERFLOW seen: the kernel dropped events
    bool malformed{false};       // decoding stopped at an inconsistent record
};

// Decodes a buffer read from a fanotify descriptor opened with FAN_REPORT_DFID_NAME. Treats the
// buffer as hostile: every length is checked against what remains, names must be terminated and
// are bounded.
[[nodiscard]] fanotify_decode_result decode_fanotify_events(const unsigned char* data, std::size_t length);

// File telemetry through fanotify with filesystem marks and FID reporting (capability-matrix
// FANOTIFY mechanism): create, close-after-write, delete, rename and attribute changes, each with
// the acting pid and a resolved path. Needs CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH and kernel 5.9+.
class fanotify_file_provider final : public provider {
public:
    explicit fanotify_file_provider(fanotify_options options = {});
    ~fanotify_file_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "fanotify_file"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "file"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return overflows_.exchange(0U); }
    [[nodiscard]] std::uint64_t take_governed() override { return governed_.exchange(0U); }

private:
    friend struct fanotify_file_provider_test_access;

    struct pending_move {
        bool valid{false};
        std::uint32_t pid{};
        std::string path;
        bool directory{false};
        std::chrono::steady_clock::time_point deadline;       // soft: flushed once the descriptor has nothing more to read
        std::chrono::steady_clock::time_point hard_deadline;  // hard: never paired with a later rename after this
    };
    struct cached_path {
        std::string path;
        std::chrono::steady_clock::time_point expires;
    };

    void run();
    void mark_filesystems();
    void handle_buffer(const unsigned char* data, std::size_t length);
    void handle_event(const fanotify_decoded& event);
    void emit(raw_file_event event);
    void flush_pending_move();
    void flush_stale_move(std::chrono::steady_clock::time_point now);
    bool take_token();
    std::string resolve_directory(const fanotify_decoded& event, std::vector<unavailable_field>& unavailable);

    fanotify_options options_;
    record_queue* queue_{nullptr};
    int fan_fd_{-1};
    int wake_fd_{-1};
    std::thread thread_;
    std::vector<std::pair<std::array<std::int32_t, 2>, int>> mounts_;  // fsid -> descriptor for open_by_handle_at
    pending_move pending_;
    std::unordered_map<std::string, cached_path> path_cache_;
    double tokens_{0.0};
    std::chrono::steady_clock::time_point last_refill_;
    std::atomic<std::uint64_t> events_{0U};
    std::atomic<std::uint64_t> overflows_{0U};
    std::atomic<std::uint64_t> governed_{0U};
    std::atomic<std::uint64_t> marked_{0U};
    mutable std::mutex failure_mutex_;
    std::string mark_failures_;
    std::atomic<bool> running_{false};
};

}  // namespace panopticon::linux_agent::sensor
