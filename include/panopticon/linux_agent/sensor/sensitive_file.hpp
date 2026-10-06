#pragma once

#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Which files are credentials or secrets worth knowing about when something opens them. A pattern
// is an absolute path; a "*" matches within one path component, and "/home/*" and "/root" are
// expanded from the account database so every user's own files are covered.
struct sensitive_file_options {
    std::vector<std::string> patterns;       // empty: sensitive_file_defaults()
    std::filesystem::path passwd{"/etc/passwd"};
    std::filesystem::path root{"/"};          // prefix for tests
    std::chrono::seconds remark_interval{15};  // pick up files that appeared or were replaced
    std::chrono::seconds repeat_window{5};     // one report per (process, file) in this window
    std::uint32_t events_per_second{200U};
    std::uint32_t burst{400U};
};

[[nodiscard]] std::vector<std::string> sensitive_file_defaults();

// Expands patterns to existing paths. `home_directories` replaces "~" in a pattern. Pure so a
// fake tree can test it.
[[nodiscard]] std::vector<std::string> expand_sensitive_patterns(const std::vector<std::string>& patterns,
                                                                 const std::vector<std::string>& home_directories,
                                                                 const std::filesystem::path& root, std::size_t maximum);

// Reports opens of credential files (capability-matrix P4/AJ1) with the opening pid and the path.
// Uses inode marks on the listed files only, so cost is proportional to how often secrets are
// opened, not to file activity. Needs CAP_SYS_ADMIN. A replaced file (passwd(1) renames a new
// /etc/shadow into place) loses its mark, so the set is re-marked periodically.
class sensitive_file_provider final : public provider {
public:
    explicit sensitive_file_provider(sensitive_file_options options = {});
    ~sensitive_file_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "sensitive_file"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "sensitive_file"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override { return {"file.open_sensitive"}; }
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return overflows_.exchange(0U); }
    [[nodiscard]] std::uint64_t take_governed() override { return governed_.exchange(0U); }

private:
    void run();
    void remark();
    void handle_buffer(const unsigned char* data, std::size_t length);

    sensitive_file_options options_;
    record_queue* queue_{nullptr};
    int fan_fd_{-1};
    int wake_fd_{-1};
    std::thread thread_;
    std::map<std::string, std::chrono::steady_clock::time_point> recent_;  // "pid path" -> last report
    double tokens_{0.0};
    std::chrono::steady_clock::time_point last_refill_;
    std::atomic<std::uint64_t> events_{0U};
    std::atomic<std::uint64_t> overflows_{0U};
    std::atomic<std::uint64_t> governed_{0U};
    std::atomic<std::uint64_t> watched_{0U};
    std::atomic<bool> running_{false};
};

}  // namespace panopticon::linux_agent::sensor
