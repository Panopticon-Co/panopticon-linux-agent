#include "panopticon/linux_agent/sensor/netlink_proc.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::size_t receive_chunk_bytes = 65536U;
constexpr int drain_pause_ms = 5;

bool send_mcast_op(const int fd, const proc_cn_mcast_op op) {
    // nlmsghdr | cn_msg | proc_cn_mcast_op, laid out by hand: cn_msg ends in a flexible array.
    alignas(nlmsghdr) std::array<unsigned char, NLMSG_SPACE(sizeof(cn_msg) + sizeof(proc_cn_mcast_op))> buffer{};
    auto* header = reinterpret_cast<nlmsghdr*>(buffer.data());
    header->nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(proc_cn_mcast_op));
    header->nlmsg_type = NLMSG_DONE;
    header->nlmsg_pid = 0U;
    auto* connector = static_cast<cn_msg*>(NLMSG_DATA(header));
    connector->id.idx = CN_IDX_PROC;
    connector->id.val = CN_VAL_PROC;
    connector->len = sizeof(proc_cn_mcast_op);
    std::memcpy(connector->data, &op, sizeof(op));
    return ::send(fd, buffer.data(), header->nlmsg_len, 0) == static_cast<ssize_t>(header->nlmsg_len);
}

// The kernel ABI values of enum proc_cn_event. Linux 6.x headers moved the enumerators out of struct proc_event,
// so naming them through the struct stops compiling there; the values themselves never change.
constexpr std::uint32_t proc_event_fork = 0x00000001U;
constexpr std::uint32_t proc_event_exec = 0x00000002U;
constexpr std::uint32_t proc_event_uid = 0x00000004U;
constexpr std::uint32_t proc_event_gid = 0x00000040U;
constexpr std::uint32_t proc_event_sid = 0x00000080U;
constexpr std::uint32_t proc_event_ptrace = 0x00000100U;
constexpr std::uint32_t proc_event_comm = 0x00000200U;
constexpr std::uint32_t proc_event_exit = 0x80000000U;

}  // namespace

std::optional<raw_record> decode_proc_event(const void* data, const std::size_t size, const clock_domain& clock) {
    constexpr std::size_t header_bytes = offsetof(proc_event, event_data);
    if (size < header_bytes) return std::nullopt;
    proc_event event{};
    std::memcpy(&event, data, std::min(size, sizeof(event)));
    const auto have = [size](const std::size_t member_bytes) { return size >= header_bytes + member_bytes; };

    raw_record record;
    record.time_unix_ns = clock.monotonic_to_unix_ns(event.timestamp_ns);
    record.source = {"netlink_proc", "CNPROC", confidence::observed};
    switch (static_cast<std::uint32_t>(event.what)) {
    case proc_event_fork: {
        if (!have(sizeof(event.event_data.fork))) return std::nullopt;
        const auto& fork = event.event_data.fork;
        record.payload = raw_fork{static_cast<std::uint32_t>(fork.parent_tgid), static_cast<std::uint32_t>(fork.parent_pid),
                                  static_cast<std::uint32_t>(fork.child_tgid), static_cast<std::uint32_t>(fork.child_pid), std::nullopt};
        return record;
    }
    case proc_event_exec: {
        if (!have(sizeof(event.event_data.exec))) return std::nullopt;
        const auto& exec = event.event_data.exec;
        raw_exec payload;
        payload.tgid = static_cast<std::uint32_t>(exec.process_tgid);
        payload.pid = static_cast<std::uint32_t>(exec.process_pid);
        record.payload = std::move(payload);
        return record;
    }
    case proc_event_uid:
    case proc_event_gid: {
        if (!have(sizeof(event.event_data.id))) return std::nullopt;
        const auto& id = event.event_data.id;
        const bool user = static_cast<std::uint32_t>(event.what) == proc_event_uid;
        record.payload = raw_credential_change{static_cast<std::uint32_t>(id.process_tgid), static_cast<std::uint32_t>(id.process_pid),
                                               user, user ? id.r.ruid : id.r.rgid, user ? id.e.euid : id.e.egid};
        return record;
    }
    case proc_event_sid: {
        if (!have(sizeof(event.event_data.sid))) return std::nullopt;
        const auto& sid = event.event_data.sid;
        record.payload = raw_session_change{static_cast<std::uint32_t>(sid.process_tgid), static_cast<std::uint32_t>(sid.process_pid)};
        return record;
    }
    case proc_event_ptrace: {
        if (!have(sizeof(event.event_data.ptrace))) return std::nullopt;
        const auto& trace = event.event_data.ptrace;
        record.payload = raw_ptrace{static_cast<std::uint32_t>(trace.process_tgid), static_cast<std::uint32_t>(trace.process_pid),
                                    static_cast<std::uint32_t>(trace.tracer_tgid), static_cast<std::uint32_t>(trace.tracer_pid)};
        return record;
    }
    case proc_event_comm: {
        if (!have(sizeof(event.event_data.comm))) return std::nullopt;
        const auto& comm = event.event_data.comm;
        const auto length = ::strnlen(comm.comm, sizeof(comm.comm));
        record.payload = raw_comm_change{static_cast<std::uint32_t>(comm.process_tgid), static_cast<std::uint32_t>(comm.process_pid),
                                         std::string{comm.comm, length}};
        return record;
    }
    case proc_event_exit: {
        // Older kernels lack parent_pid/parent_tgid at the end of the struct; they are unused.
        const auto& exit = event.event_data.exit;
        const auto minimum = static_cast<std::size_t>(reinterpret_cast<const char*>(&exit.exit_signal) -
                                                      reinterpret_cast<const char*>(&exit)) + sizeof(exit.exit_signal);
        if (!have(minimum)) return std::nullopt;
        record.payload = raw_exit{static_cast<std::uint32_t>(exit.process_tgid), static_cast<std::uint32_t>(exit.process_pid),
                                  exit.exit_code, exit.exit_signal};
        return record;
    }
    default:
        return std::nullopt;
    }
}

netlink_proc_provider::netlink_proc_provider(const clock_domain& clock, const std::size_t receive_buffer_bytes)
    : clock_{clock}, receive_buffer_bytes_{receive_buffer_bytes} {}

netlink_proc_provider::~netlink_proc_provider() { stop(); }

std::vector<std::string> netlink_proc_provider::capabilities() const {
    return {"process.fork", "process.exec", "process.exit", "process.cred_change", "process.inject", "process.rename"};
}

result<int> netlink_proc_provider::open_socket() {
    const int fd = ::socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_CONNECTOR);
    if (fd < 0) return error{error_code::unsupported_action, std::string{"netlink connector socket: "} + std::strerror(errno)};
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = CN_IDX_PROC;
    address.nl_pid = 0U;  // kernel assigns a unique port id
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        const auto message = std::string{"netlink connector bind: "} + std::strerror(errno);
        ::close(fd);
        return error{error_code::unsupported_action, message};
    }
    const int requested = static_cast<int>(receive_buffer_bytes_);
    // SO_RCVBUFFORCE needs CAP_NET_ADMIN, which subscribing requires anyway; fall back if denied.
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &requested, sizeof(requested)) != 0) {
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested));
    }
    if (!send_mcast_op(fd, PROC_CN_MCAST_LISTEN)) {
        const auto message = std::string{"proc connector subscribe: "} + std::strerror(errno);
        ::close(fd);
        return error{error_code::unsupported_action, message};
    }
    return fd;
}

std::string netlink_proc_provider::probe() {
    auto fd = open_socket();
    if (!succeeded(fd)) return std::get<error>(fd).message;
    (void)send_mcast_op(std::get<int>(fd), PROC_CN_MCAST_IGNORE);
    ::close(std::get<int>(fd));
    return {};
}

result<bool> netlink_proc_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    auto fd = open_socket();
    if (!succeeded(fd)) {
        reason_ = std::get<error>(fd).message;
        return std::get<error>(fd);
    }
    socket_ = std::get<int>(fd);
    wake_fd_ = ::eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        ::close(socket_);
        socket_ = -1;
        return error{error_code::io_failure, "cannot create eventfd"};
    }
    reason_.clear();
    running_.store(true);
    thread_ = std::thread{[this, &queue] { run(queue); }};
    return true;
}

void netlink_proc_provider::stop() {
    if (!running_.exchange(false)) return;
    const std::uint64_t one = 1U;
    (void)!::write(wake_fd_, &one, sizeof(one));
    if (thread_.joinable()) thread_.join();
    (void)send_mcast_op(socket_, PROC_CN_MCAST_IGNORE);
    ::close(socket_);
    ::close(wake_fd_);
    socket_ = -1;
    wake_fd_ = -1;
}

void netlink_proc_provider::run(record_queue& queue) {
    std::vector<char> buffer(receive_chunk_bytes);
    std::array<pollfd, 2> descriptors{{{socket_, POLLIN, 0}, {wake_fd_, POLLIN, 0}}};
    while (running_.load(std::memory_order_relaxed)) {
        if (::poll(descriptors.data(), descriptors.size(), 1000) < 0 && errno != EINTR) break;
        if ((descriptors[1].revents & POLLIN) != 0) break;
        if ((descriptors[0].revents & POLLIN) == 0) continue;
        while (true) {
            sockaddr_nl sender{};
            socklen_t sender_length = sizeof(sender);
            const auto received = ::recvfrom(socket_, buffer.data(), buffer.size(), 0,
                                             reinterpret_cast<sockaddr*>(&sender), &sender_length);
            if (received < 0) {
                if (errno == EINTR) continue;
                if (errno == ENOBUFS) {
                    // The kernel dropped events because the socket buffer overflowed.
                    losses_.fetch_add(1U);
                    total_losses_.fetch_add(1U);
                    continue;
                }
                break;  // EAGAIN: drained
            }
            if (sender.nl_pid != 0U) continue;  // only the kernel may speak on this group
            auto length = static_cast<unsigned int>(received);
            for (auto* header = reinterpret_cast<nlmsghdr*>(buffer.data()); NLMSG_OK(header, length);
                 header = NLMSG_NEXT(header, length)) {
                if (header->nlmsg_type == NLMSG_ERROR || header->nlmsg_type == NLMSG_NOOP) continue;
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(cn_msg))) continue;
                const auto* message = static_cast<const cn_msg*>(NLMSG_DATA(header));
                if (message->id.idx != CN_IDX_PROC || message->id.val != CN_VAL_PROC) continue;
                if (NLMSG_LENGTH(sizeof(cn_msg) + message->len) > header->nlmsg_len) continue;
                auto record = decode_proc_event(message->data, message->len, clock_);
                if (!record.has_value()) continue;
                events_.fetch_add(1U, std::memory_order_relaxed);
                if (!queue.push(std::move(*record))) drops_.fetch_add(1U, std::memory_order_relaxed);
            }
        }
        // The kernel sends one datagram per event. Pausing after a drain lets events accumulate
        // in the socket buffer (sized for ~10k events) instead of waking this thread per event;
        // the wake fd keeps stop() responsive.
        pollfd wake{wake_fd_, POLLIN, 0};
        if (::poll(&wake, 1U, drain_pause_ms) > 0) break;
    }
}

provider_health netlink_proc_provider::health() const {
    provider_health health;
    health.name = std::string{name()};
    health.state = running_.load() ? "active" : (reason_.empty() ? "stopped" : "unavailable");
    health.reason = reason_;
    health.capabilities = capabilities();
    health.events = events_.load();
    health.drops = drops_.load() + total_losses_.load();
    return health;
}

std::uint64_t netlink_proc_provider::take_losses() { return losses_.exchange(0U); }

}  // namespace panopticon::linux_agent::sensor
