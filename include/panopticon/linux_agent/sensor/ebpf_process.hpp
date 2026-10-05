#pragma once

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
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
class ebpf_process_provider final : public provider {
public:
    ebpf_process_provider(const clock_domain& clock, ebpf_process_options options = {});
    ~ebpf_process_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "ebpf_process"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "process"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override;

private:
    void run();
    int on_sample(const void* data, std::size_t size);
    void release();

    const clock_domain& clock_;
    ebpf_process_options options_;
    record_queue* queue_{nullptr};

    ::bpf_object* object_{nullptr};
    ::ring_buffer* ring_{nullptr};
    std::vector<::bpf_link*> links_;
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
