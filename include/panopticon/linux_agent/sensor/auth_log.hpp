#pragma once

#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace panopticon::linux_agent::sensor {

inline constexpr std::size_t maximum_auth_line_bytes = 4096U;

// Printable ASCII only and at most `maximum` bytes; anything else becomes '?'. Sets `sanitized`
// and `truncated` on the event when it changed the text. Shared by every auth source.
[[nodiscard]] std::string sanitize_auth_field(std::string_view text, std::size_t maximum, raw_auth_event& event);
// True for a well-formed IPv4 or IPv6 address.
[[nodiscard]] bool is_ip_address(std::string_view text);

struct parsed_auth_line {
    std::uint64_t time_unix_ns{};
    raw_auth_event event;
};

// Parses one syslog line from auth.log / secure. Returns nothing for any line that is not an
// authentication event this sensor reports, and for every line it cannot read with confidence.
//
// The line is hostile: user names and sudo commands are chosen by whoever is logging in. The
// program tag is anchored at the start, the fixed words of a message are matched from the
// left and the address and port from the right, so a user name such as
// "x from 1.2.3.4 port 22 ssh2" cannot change who or where the event is reported for. Fields are
// bounded and made printable; `sanitized` and `truncated` say when that happened.
//
// Both rsyslog formats are read: ISO 8601 ("2026-10-06T01:40:47.580173+00:00") and the
// traditional "Oct  6 01:40:47", which has no year and no zone; the year is taken from
// `reference_unix_ns` and the time is read as local time.
[[nodiscard]] std::optional<parsed_auth_line> parse_auth_line(std::string_view line, std::uint64_t reference_unix_ns);

// Reads new complete lines from a log file the way `tail -F` does: starts at the end (history is
// not replayed), follows a rotation to the new file after draining the old one, and restarts at
// the top after a truncation. Lines longer than the limit are skipped and counted.
class log_tailer {
public:
    explicit log_tailer(std::filesystem::path path, std::size_t maximum_bytes_per_poll = 1U << 20U)
        : path_{std::move(path)}, maximum_bytes_{maximum_bytes_per_poll} {}
    ~log_tailer();
    log_tailer(const log_tailer&) = delete;
    log_tailer& operator=(const log_tailer&) = delete;

    // Opens the file and seeks to the end. False when it cannot be opened.
    [[nodiscard]] bool open(std::string* reason = nullptr);
    // Appends the complete new lines to `lines`; returns false when the file cannot be read.
    [[nodiscard]] bool poll(std::vector<std::string>& lines);
    [[nodiscard]] std::uint64_t oversize_lines() const noexcept { return oversize_; }
    [[nodiscard]] std::uint64_t rotations() const noexcept { return rotations_; }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    bool drain(std::vector<std::string>& lines);
    void split(std::string_view data, std::vector<std::string>& lines);

    std::filesystem::path path_;
    std::size_t maximum_bytes_;
    int fd_{-1};
    std::uint64_t device_{};
    std::uint64_t inode_{};
    std::uint64_t offset_{};
    std::string carry_;
    bool skipping_{false};  // inside an oversize line
    std::uint64_t oversize_{};
    std::uint64_t rotations_{};
};

struct auth_log_options {
    std::vector<std::filesystem::path> paths{"/var/log/auth.log", "/var/log/secure"};
    std::chrono::milliseconds interval{500};
    std::size_t maximum_events_per_poll{2000U};
};

// Authentication telemetry from the system log (capability-matrix AUTHLOG mechanism, the
// fallback for AUDIT). Honest about what that is: the event is what a program chose to log,
// delayed by syslog, and the acting process has usually exited by the time it is read.
class auth_log_provider final : public provider {
public:
    explicit auth_log_provider(auth_log_options options = {});
    ~auth_log_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "auth_log"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "auth"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return 0U; }
    [[nodiscard]] std::uint64_t take_governed() override { return governed_.exchange(0U); }
    // Log lines over `maximum_auth_line_bytes`, skipped because they cannot be parsed safely. A failed
    // login padded past the limit would otherwise disappear without a trace.
    [[nodiscard]] std::uint64_t take_refused() override { return refused_.exchange(0U); }

    // One pass over every followed file. Public for tests.
    void poll_once();

private:
    void run();

    auth_log_options options_;
    record_queue* queue_{nullptr};
    std::vector<std::unique_ptr<log_tailer>> tailers_;
    std::thread thread_;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> events_{0U};
    std::atomic<std::uint64_t> governed_{0U};
    std::atomic<std::uint64_t> refused_{0U};
    std::atomic<std::uint64_t> lines_{0U};
    mutable std::mutex failure_mutex_;
    std::string failure_;
};

}  // namespace panopticon::linux_agent::sensor
