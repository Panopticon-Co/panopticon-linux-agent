#pragma once

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <cstddef>
#include <optional>
#include <thread>

namespace panopticon::linux_agent::sensor {

// Process lifecycle via the kernel proc connector (CN_IDX_PROC). Available on every supported
// kernel; needs CAP_NET_ADMIN to subscribe. Reports pids only, so exec details are enriched from
// procfs by the entity graph (a short-lived process can exit before that read).
class netlink_proc_provider final : public provider {
public:
    explicit netlink_proc_provider(const clock_domain& clock, std::size_t receive_buffer_bytes = 8U * 1024U * 1024U);
    ~netlink_proc_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "netlink_proc"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "process"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override;

private:
    void run(record_queue& queue);
    result<int> open_socket();

    const clock_domain& clock_;
    std::size_t receive_buffer_bytes_;
    int socket_{-1};
    int wake_fd_{-1};
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> events_{0};
    std::atomic<std::uint64_t> drops_{0};
    std::atomic<std::uint64_t> losses_{0};        // since the last take_losses()
    std::atomic<std::uint64_t> total_losses_{0};
    std::string reason_;
};

// Decodes one proc connector event (the `struct proc_event` payload of a cn_msg). Returns nullopt
// for event kinds the sensor does not use. Exposed for unit tests and fuzzing.
[[nodiscard]] std::optional<raw_record> decode_proc_event(const void* data, std::size_t size, const clock_domain& clock);

}  // namespace panopticon::linux_agent::sensor
