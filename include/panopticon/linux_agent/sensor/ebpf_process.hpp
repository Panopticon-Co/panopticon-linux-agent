#pragma once

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// libbpf types stay opaque so no consumer of this header needs libbpf's headers.
struct bpf_object;
struct bpf_link;
struct ring_buffer;

namespace panopticon::linux_agent::sensor {

struct ebpf_process_options {
    std::uint32_t ringbuf_bytes{4U * 1024U * 1024U};  // power of two, multiple of the page size
    bool skip_own_network_events{true};  // the sensor own uplink must not produce telemetry about itself
    procfs_limits limits;                              // bounds applied to argv captured in-kernel
};

// True when this binary was built with the eBPF provider (clang, libelf, zlib and a vmlinux.h
// for the target architecture were available at build time).
[[nodiscard]] bool ebpf_process_built() noexcept;

// Decodes one ring-buffer sample produced by panopticon.bpf.c into canonical raw records: zero
// for an uninteresting sample, one for most, two for a credential change of both uid and gid.
// A malformed or unknown sample yields no records and sets `*malformed`; the sample comes from
// a buffer shared with the kernel's side of the hook, so it is bounds-checked completely.
[[nodiscard]] std::vector<raw_record> decode_ebpf_process_sample(const void* data, std::size_t size, const clock_domain& clock,
                                                                  const procfs_limits& limits, bool* malformed = nullptr);

// Process-family provider backed by eBPF (ADR 005, ADR 006): BTF-typed tracepoints and fentry
// hooks with CO-RE. It supersedes netlink_proc (same `family`) when it loads; otherwise the
// pipeline falls back to netlink_proc and reports why in health.
// One BPF object serves two providers so that each family has its own fallback chain: the
// `process` role is preferred over netlink_proc, the `network` role over sockdiag.
enum class ebpf_role : std::uint8_t { process, network, security };

class ebpf_process_provider final : public provider {
public:
    ebpf_process_provider(const clock_domain& clock, ebpf_process_options options = {}, ebpf_role role = ebpf_role::process);
    ~ebpf_process_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return role_ == ebpf_role::network ? "ebpf_network" : role_ == ebpf_role::security ? "ebpf_security" : "ebpf_process";
    }
    [[nodiscard]] std::string_view family() const noexcept override {
        return role_ == ebpf_role::network ? "network" : role_ == ebpf_role::security ? "security" : "process";
    }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void request_stop() noexcept override { stop_ = true; }
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override;
    // The probes count each event they fail to reserve in the ring buffer.
    [[nodiscard]] bool losses_are_event_counts() const noexcept override { return true; }

    [[nodiscard]] std::vector<provider_gap> take_gaps() override;

    // Asks the kernel about every link this provider attached and returns how many are gone or no longer the
    // link that was attached (closed or replaced from outside the sensor). Runs on the provider thread every
    // few seconds; a non-zero result makes health() report "degraded". Public so a test can provoke it.
    std::uint32_t check_attachments();
    // Restores every hook check_attachments() found lost and returns how many are still lost. A link the kernel
    // still holds (another process kept a reference) is taken back: the hook never stopped, so there is no gap.
    // Otherwise the program is attached again, the new link is verified, and the interval since the hook was last
    // verified is queued for take_gaps(). Runs right after check_attachments(); public for the same reason.
    std::uint32_t recover_attachments();

private:
    // One attached hook, with the identity the kernel gave it so a closed and reused descriptor is noticed. The
    // descriptor is owned here rather than by a libbpf link, so that a descriptor number someone else closed (and the
    // process may have reused) is never closed again by the sensor.
    struct attached_link {
        int fd{-1};  // -1 while lost
        std::uint32_t id{0U};
        std::uint32_t type{0U};
        std::uint32_t program_id{0U};
        std::string program;
        std::string capability;
        std::uint64_t last_verified_unix_ns{0U};
        std::uint64_t detected_unix_ns{0U};  // non-zero while lost
        std::uint32_t attempts{0U};
        std::string last_error;
    };

    void run();
    int on_sample(const void* data, std::size_t size);
    void release();
    bool attach(attached_link& attached);
    bool intact(const attached_link& attached) const;

    const clock_domain& clock_;
    ebpf_process_options options_;
    ebpf_role role_;
    std::uint32_t own_pid_;
    record_queue* queue_{nullptr};

    ::bpf_object* object_{nullptr};
    ::ring_buffer* ring_{nullptr};
    std::mutex links_mutex_;  // the provider thread checks the links while a test may also check them
    std::vector<attached_link> links_;
    std::atomic<std::uint32_t> links_lost_{0U};
    mutable std::mutex lost_mutex_;
    std::string lost_programs_;           // guarded by lost_mutex_
    std::vector<provider_gap> gaps_;      // guarded by lost_mutex_; bounded, see recover_attachments()
    std::uint64_t reattached_{0U};        // guarded by lost_mutex_
    std::uint64_t adopted_{0U};           // guarded by lost_mutex_
    int drops_map_fd_{-1};
    std::uint64_t drops_seen_{0};

    std::vector<std::string> capabilities_;      // programs actually attached
    std::vector<std::string> missing_programs_;  // optional programs the kernel cannot host
    std::string state_{"unavailable"};
    std::string reason_{"not started"};

    std::atomic<bool> stop_{false};
    std::atomic<bool> poll_failed_{false};
    std::atomic<std::uint64_t> events_{0};
    std::atomic<std::uint64_t> malformed_{0};
    std::thread thread_;
};

}  // namespace panopticon::linux_agent::sensor
