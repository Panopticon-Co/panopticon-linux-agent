#pragma once

#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace panopticon::linux_agent::sensor {

// One socket as the kernel's sock_diag interface reports it.
struct socket_entry {
    std::uint8_t protocol{};  // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    std::uint8_t family{};    // AF_INET (2) or AF_INET6 (10)
    std::uint8_t state{};     // TCP_* state number
    std::string local_address;
    std::string remote_address;
    std::uint16_t local_port{};
    std::uint16_t remote_port{};
    std::uint64_t inode{};  // 0 for sockets with no owner (TIME_WAIT)
    std::uint32_t uid{};

    [[nodiscard]] bool operator==(const socket_entry&) const = default;
};

[[nodiscard]] const char* tcp_state_name(std::uint8_t state) noexcept;

struct sockdiag_decode_result {
    std::vector<socket_entry> entries;
    bool malformed{false};  // decoding stopped at an inconsistent message
    bool done{false};       // NLMSG_DONE seen
    int error{0};           // errno from an NLMSG_ERROR reply
};

// Decodes one recv() buffer of sock_diag replies for `protocol`. The buffer is hostile input:
// every length is checked against what remains, unknown families and short messages stop the
// decode with `malformed`, never an out-of-range read.
[[nodiscard]] sockdiag_decode_result decode_sock_diag(const unsigned char* data, std::size_t length, std::uint8_t protocol);

// What a new socket means, decided from the current snapshot alone.
struct socket_change {
    network_operation operation;
    socket_entry socket;
};

struct socket_tracker_options {
    std::size_t maximum_sockets{65536U};
    bool report_existing{false};  // the first snapshot is state, not events, unless set
};

// Diffs successive socket snapshots. A socket is reported once, when it first appears:
//   TCP LISTEN                         -> listen
//   UDP bound, not connected           -> listen
//   TCP/UDP with a remote end          -> accept when its local port is a listener in the same
//                                         snapshot, otherwise connect
// Sockets that appear already finished (TIME_WAIT, CLOSE, no owner) are not reported: their
// process cannot be known. Pure and deterministic, so it is tested without a kernel.
class socket_tracker {
public:
    explicit socket_tracker(socket_tracker_options options = {}) : options_{options} {}

    [[nodiscard]] std::vector<socket_change> update(const std::vector<socket_entry>& snapshot);
    [[nodiscard]] std::size_t tracked() const noexcept { return known_.size(); }
    // Sockets that were not tracked because the table was full; reported as a loss by the provider.
    [[nodiscard]] std::uint64_t take_overflow() noexcept { return std::exchange(overflow_, 0U); }

private:
    using key_type = std::tuple<std::uint8_t, std::uint8_t, std::string, std::uint16_t, std::string, std::uint16_t, std::uint64_t>;
    static key_type key_of(const socket_entry& entry);

    socket_tracker_options options_;
    std::set<key_type> known_;
    bool seeded_{false};
    std::uint64_t overflow_{};
};

struct holder_info {
    std::uint32_t pid{};
    std::uint32_t holders{};
};
// inode -> lowest process id holding it, from /proc/<pid>/fd. Bounded by `budget`; sockets it did
// not reach are simply absent from the result, and `exhausted` says the budget ran out.
using socket_owner_map = std::unordered_map<std::uint64_t, holder_info>;
// The kernel's TCP and UDP socket tables, IPv4 and IPv6, over NETLINK_SOCK_DIAG; at most
// `maximum_entries` sockets are kept.
[[nodiscard]] result<std::vector<socket_entry>> read_socket_tables(std::size_t maximum_entries);

// One `state.connections` item per socket: protocol, family, state, local and remote end, uid,
// inode and, when the owner scan found it, the lowest holding pid and the holder count (`pid` is
// null otherwise). Sorted, so equal tables give equal items; at most `maximum_items`.
[[nodiscard]] std::vector<std::string> connection_state_items(const std::vector<socket_entry>& sockets, const socket_owner_map& owners,
                                                              std::size_t maximum_items, bool& truncated);
// "tcp_listen=N tcp_established=N tcp_other=N udp=N attributed=A/T": the bounded result line.
[[nodiscard]] std::string connection_summary(const std::vector<socket_entry>& sockets, const socket_owner_map& owners);

[[nodiscard]] socket_owner_map scan_socket_owners(const std::filesystem::path& proc_root, const std::set<std::uint64_t>& wanted,
                                                  std::chrono::milliseconds budget, bool* exhausted = nullptr);

struct sockdiag_options {
    std::chrono::milliseconds interval{500};
    std::chrono::milliseconds owner_scan_budget{250};
    std::size_t maximum_sockets{65536U};
    std::filesystem::path proc_root{"/proc"};
};

// Network telemetry by polling the kernel's socket tables over NETLINK_SOCK_DIAG (capability-
// matrix SOCKDIAG mechanism). Honest about what that is: a connection that opens and closes
// between two polls is not seen, and the owning process is found by matching the socket inode to
// /proc/<pid>/fd after the fact (confidence `reconstructed`). eBPF socket hooks later supersede
// this with exact, in-kernel observation.
class sockdiag_network_provider final : public provider {
public:
    explicit sockdiag_network_provider(sockdiag_options options = {});
    ~sockdiag_network_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "sockdiag_network"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "network"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return losses_.exchange(0U); }

    // One poll: reads the tables, diffs, attributes and queues the new sockets. Public for tests;
    // the first call only seeds the baseline.
    [[nodiscard]] result<bool> poll_once();

private:
    [[nodiscard]] result<std::vector<socket_entry>> read_tables();
    void run();

    sockdiag_options options_;
    record_queue* queue_{nullptr};
    socket_tracker tracker_;
    std::thread thread_;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> events_{0U};
    std::atomic<std::uint64_t> losses_{0U};
    std::atomic<std::uint64_t> unattributed_{0U};
    mutable std::mutex failure_mutex_;
    std::string last_failure_;
};

}  // namespace panopticon::linux_agent::sensor
