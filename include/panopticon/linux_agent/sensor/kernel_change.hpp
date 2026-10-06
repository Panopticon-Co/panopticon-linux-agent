#pragma once

#include "panopticon/linux_agent/sensor/host_state.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Turns successive snapshots of /proc/modules and mountinfo into events. The first snapshot of
// each is the starting state and produces nothing. Pure: no files, no clock.
class kernel_change_tracker {
public:
    // A module whose size changed under the same name was unloaded and loaded again.
    [[nodiscard]] std::vector<raw_kernel_event> update_modules(const std::vector<module_entry>& now);
    // A mount is identified by id, device, root, mount point and file system type. The same mount
    // with different options was remounted (for example read-only to read-write).
    [[nodiscard]] std::vector<raw_kernel_event> update_mounts(const std::vector<mount_entry>& now);

private:
    bool modules_seeded_{false};
    bool mounts_seeded_{false};
    std::map<std::string, module_entry> modules_;
    std::map<std::string, mount_entry> mounts_;
};

struct kernel_change_options {
    std::filesystem::path proc_root{"/proc"};
    std::chrono::milliseconds interval{1000};
    std::size_t maximum_entries{4096U};         // per snapshot; more is treated as unreadable
    std::size_t maximum_events_per_poll{500U};  // the excess is counted, not sent
};

// Kernel module and mount change telemetry by comparing snapshots (matrix mechanism PROCFS; the
// fallback for the eBPF module-load and mount hooks). It sees what is loaded or mounted when it
// looks, so a module loaded and removed between two polls is missed, and it cannot name the
// process that did it.
class kernel_change_provider final : public provider {
public:
    explicit kernel_change_provider(kernel_change_options options = {});
    ~kernel_change_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "kernel_change"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return 0U; }
    [[nodiscard]] std::uint64_t take_governed() override { return governed_.exchange(0U); }

    // One pass: read both files, diff, queue the events. Public for tests.
    void poll_once();

private:
    void run();

    kernel_change_options options_;
    kernel_change_tracker tracker_;
    record_queue* queue_{nullptr};
    std::thread thread_;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> events_{0U};
    std::atomic<std::uint64_t> governed_{0U};
    mutable std::mutex failure_mutex_;
    std::string failure_;
};

}  // namespace panopticon::linux_agent::sensor
