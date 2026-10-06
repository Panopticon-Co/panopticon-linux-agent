#include "panopticon/linux_agent/sensor/sockdiag_network.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"

#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string_view>
#include <utility>
#include <variant>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::uint8_t tcp_time_wait = 6U;
constexpr std::uint8_t tcp_close = 7U;
constexpr std::uint8_t tcp_listen = 10U;

std::size_t aligned(const std::size_t length) { return (length + 3U) & ~static_cast<std::size_t>(3U); }

std::string format_address(const std::uint8_t family, const std::uint32_t (&words)[4]) {
    char text[INET6_ADDRSTRLEN]{};
    if (family == AF_INET) {
        if (::inet_ntop(AF_INET, &words[0], text, sizeof(text)) == nullptr) return {};
    } else if (::inet_ntop(AF_INET6, words, text, sizeof(text)) == nullptr) {
        return {};
    }
    return text;
}

std::uint16_t host_port(const std::uint16_t network) { return static_cast<std::uint16_t>((network >> 8U) | (network << 8U)); }

bool owned_and_open(const socket_entry& entry) {
    if (entry.inode == 0U) return false;
    if (entry.protocol == IPPROTO_TCP && (entry.state == tcp_time_wait || entry.state == tcp_close)) return false;
    return true;
}

bool is_listener(const socket_entry& entry) {
    if (entry.protocol == IPPROTO_TCP) return entry.state == tcp_listen;
    return entry.remote_port == 0U && entry.local_port != 0U;
}

}  // namespace

const char* tcp_state_name(const std::uint8_t state) noexcept {
    switch (state) {
    case 1U: return "established";
    case 2U: return "syn_sent";
    case 3U: return "syn_recv";
    case 4U: return "fin_wait1";
    case 5U: return "fin_wait2";
    case 6U: return "time_wait";
    case 7U: return "close";
    case 8U: return "close_wait";
    case 9U: return "last_ack";
    case 10U: return "listen";
    case 11U: return "closing";
    default: return "unknown";
    }
}

sockdiag_decode_result decode_sock_diag(const unsigned char* data, const std::size_t length, const std::uint8_t protocol) {
    sockdiag_decode_result result;
    std::size_t offset = 0U;
    while (length - offset >= sizeof(nlmsghdr)) {
        nlmsghdr header{};
        std::memcpy(&header, data + offset, sizeof(header));
        if (header.nlmsg_len < sizeof(nlmsghdr) || header.nlmsg_len > length - offset) {
            result.malformed = true;
            return result;
        }
        const unsigned char* payload = data + offset + sizeof(nlmsghdr);
        const std::size_t payload_length = header.nlmsg_len - sizeof(nlmsghdr);
        if (header.nlmsg_type == NLMSG_DONE) {
            result.done = true;
            return result;
        }
        if (header.nlmsg_type == NLMSG_ERROR) {
            if (payload_length < sizeof(nlmsgerr)) {
                result.malformed = true;
            } else {
                nlmsgerr failure{};
                std::memcpy(&failure, payload, sizeof(failure));
                result.error = failure.error < 0 ? -failure.error : failure.error;
                result.done = true;
            }
            return result;
        }
        if (header.nlmsg_type == SOCK_DIAG_BY_FAMILY) {
            if (payload_length < sizeof(inet_diag_msg)) {
                result.malformed = true;
                return result;
            }
            inet_diag_msg message{};
            std::memcpy(&message, payload, sizeof(message));
            if (message.idiag_family != AF_INET && message.idiag_family != AF_INET6) {
                result.malformed = true;
                return result;
            }
            socket_entry entry;
            entry.protocol = protocol;
            entry.family = message.idiag_family;
            entry.state = message.idiag_state;
            std::uint32_t source[4];
            std::uint32_t destination[4];
            std::memcpy(source, message.id.idiag_src, sizeof(source));
            std::memcpy(destination, message.id.idiag_dst, sizeof(destination));
            entry.local_address = format_address(message.idiag_family, source);
            entry.remote_address = format_address(message.idiag_family, destination);
            entry.local_port = host_port(message.id.idiag_sport);
            entry.remote_port = host_port(message.id.idiag_dport);
            entry.inode = message.idiag_inode;
            entry.uid = message.idiag_uid;
            result.entries.push_back(std::move(entry));
        }
        const auto step = aligned(header.nlmsg_len);
        if (step > length - offset) break;  // the last message may be unpadded
        offset += step;
    }
    return result;
}

socket_tracker::key_type socket_tracker::key_of(const socket_entry& entry) {
    return {entry.protocol, entry.family, entry.local_address, entry.local_port, entry.remote_address, entry.remote_port, entry.inode};
}

std::vector<socket_change> socket_tracker::update(const std::vector<socket_entry>& snapshot) {
    std::vector<socket_change> changes;
    std::set<key_type> next;
    const bool report = seeded_ || options_.report_existing;
    std::set<std::pair<std::uint8_t, std::uint16_t>> listeners;
    for (const auto& entry : snapshot) {
        if (is_listener(entry)) listeners.insert({entry.protocol, entry.local_port});
    }
    for (const auto& entry : snapshot) {
        auto key = key_of(entry);
        const bool already = known_.count(key) != 0U;
        if (!already && next.size() >= options_.maximum_sockets) {
            ++overflow_;
            continue;
        }
        next.insert(std::move(key));
        if (already || !report || !owned_and_open(entry)) continue;
        if (is_listener(entry)) {
            changes.push_back({network_operation::listen, entry});
        } else if (entry.remote_port != 0U) {
            const bool inbound = entry.protocol == IPPROTO_TCP && listeners.count({entry.protocol, entry.local_port}) != 0U;
            changes.push_back({inbound ? network_operation::accept : network_operation::connect, entry});
        }
    }
    known_ = std::move(next);
    seeded_ = true;
    return changes;
}

socket_owner_map scan_socket_owners(const std::filesystem::path& proc_root, const std::set<std::uint64_t>& wanted,
                                    const std::chrono::milliseconds budget, bool* exhausted) {
    socket_owner_map owners;
    if (exhausted != nullptr) *exhausted = false;
    if (wanted.empty()) return owners;
    const auto deadline = std::chrono::steady_clock::now() + budget;
    std::error_code error;
    for (std::filesystem::directory_iterator process{proc_root, std::filesystem::directory_options::skip_permission_denied, error};
         !error && process != std::filesystem::directory_iterator{}; process.increment(error)) {
        const auto name = process->path().filename().string();
        if (name.empty() || name.size() > 10U || !std::all_of(name.begin(), name.end(), [](const char c) { return c >= '0' && c <= '9'; })) {
            continue;
        }
        if (std::chrono::steady_clock::now() > deadline) {
            if (exhausted != nullptr) *exhausted = true;
            break;
        }
        const auto pid = static_cast<std::uint32_t>(std::stoull(name));
        std::error_code fd_error;
        for (std::filesystem::directory_iterator fd{process->path() / "fd", std::filesystem::directory_options::skip_permission_denied, fd_error};
             !fd_error && fd != std::filesystem::directory_iterator{}; fd.increment(fd_error)) {
            char target[64]{};
            const auto size = ::readlink(fd->path().c_str(), target, sizeof(target) - 1U);
            if (size < 10) continue;
            const std::string_view text{target, static_cast<std::size_t>(size)};
            if (text.substr(0U, 8U) != "socket:[" || text.back() != ']') continue;
            std::uint64_t inode = 0U;
            bool valid = text.size() > 9U;
            for (const char c : text.substr(8U, text.size() - 9U)) {
                if (c < '0' || c > '9' || inode > (UINT64_MAX - 9U) / 10U) {
                    valid = false;
                    break;
                }
                inode = inode * 10U + static_cast<std::uint64_t>(c - '0');
            }
            if (!valid || wanted.count(inode) == 0U) continue;
            auto& holder = owners[inode];
            ++holder.holders;
            if (holder.pid == 0U || pid < holder.pid) holder.pid = pid;
        }
    }
    return owners;
}

sockdiag_network_provider::sockdiag_network_provider(sockdiag_options options)
    : options_{std::move(options)}, tracker_{socket_tracker_options{options_.maximum_sockets, false}} {}

sockdiag_network_provider::~sockdiag_network_provider() { stop(); }

std::vector<std::string> sockdiag_network_provider::capabilities() const {
    return {"network.connect", "network.accept", "network.listen"};
}

std::string sockdiag_network_provider::probe() {
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return std::string{"NETLINK_SOCK_DIAG: "} + std::strerror(errno);
    ::close(fd);
    return {};
}

result<std::vector<socket_entry>> sockdiag_network_provider::read_tables() {
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return error{error_code::io_failure, std::string{"NETLINK_SOCK_DIAG: "} + std::strerror(errno)};
    const timeval timeout{2, 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    std::vector<socket_entry> all;
    std::vector<unsigned char> buffer(65536U);
    struct request {
        nlmsghdr header;
        inet_diag_req_v2 body;
    };
    for (const std::uint8_t protocol : {static_cast<std::uint8_t>(IPPROTO_TCP), static_cast<std::uint8_t>(IPPROTO_UDP)}) {
        for (const std::uint8_t family : {static_cast<std::uint8_t>(AF_INET), static_cast<std::uint8_t>(AF_INET6)}) {
            request message{};
            message.header.nlmsg_len = sizeof(request);
            message.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
            message.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            message.body.sdiag_family = family;
            message.body.sdiag_protocol = protocol;
            message.body.idiag_states = 0xFFFFFFFFU;
            sockaddr_nl kernel{};
            kernel.nl_family = AF_NETLINK;
            if (::sendto(fd, &message, sizeof(message), 0, reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) < 0) {
                const auto reason = std::string{"sock_diag request: "} + std::strerror(errno);
                ::close(fd);
                return error{error_code::io_failure, reason};
            }
            bool finished = false;
            while (!finished) {
                const auto received = ::recv(fd, buffer.data(), buffer.size(), 0);
                if (received < 0) {
                    if (errno == EINTR) continue;
                    const auto reason = std::string{"sock_diag read: "} + std::strerror(errno);
                    ::close(fd);
                    return error{error_code::io_failure, reason};
                }
                auto decoded = decode_sock_diag(buffer.data(), static_cast<std::size_t>(received), protocol);
                if (decoded.error != 0) {
                    // IPv6 may be compiled out or disabled: that family is simply absent.
                    if (decoded.error == EAFNOSUPPORT || decoded.error == ENOENT) break;
                    ::close(fd);
                    return error{error_code::io_failure, std::string{"sock_diag: "} + std::strerror(decoded.error)};
                }
                if (decoded.malformed) {
                    ::close(fd);
                    return error{error_code::corrupt_data, "sock_diag reply was malformed"};
                }
                for (auto& entry : decoded.entries) {
                    if (all.size() < options_.maximum_sockets * 2U) all.push_back(std::move(entry));
                }
                finished = decoded.done;
            }
        }
    }
    ::close(fd);
    return all;
}

result<bool> sockdiag_network_provider::poll_once() {
    auto tables = read_tables();
    if (!std::holds_alternative<std::vector<socket_entry>>(tables)) {
        auto failure = std::get<error>(tables);
        {
            const std::lock_guard lock{failure_mutex_};
            last_failure_ = failure.message;
        }
        return failure;
    }
    {
        const std::lock_guard lock{failure_mutex_};
        last_failure_.clear();
    }
    const auto changes = tracker_.update(std::get<std::vector<socket_entry>>(tables));
    if (const auto overflow = tracker_.take_overflow(); overflow != 0U) losses_ += overflow;
    if (changes.empty() || queue_ == nullptr) return true;
    std::set<std::uint64_t> wanted;
    for (const auto& change : changes) wanted.insert(change.socket.inode);
    bool exhausted = false;
    const auto owners = scan_socket_owners(options_.proc_root, wanted, options_.owner_scan_budget, &exhausted);
    for (const auto& change : changes) {
        raw_network_event event;
        event.operation = change.operation;
        event.protocol = change.socket.protocol == IPPROTO_TCP ? "tcp" : "udp";
        event.family = change.socket.family == AF_INET ? "inet" : "inet6";
        event.local_address = change.socket.local_address;
        event.local_port = change.socket.local_port;
        if (change.operation != network_operation::listen) {
            event.remote_address = change.socket.remote_address;
            event.remote_port = change.socket.remote_port;
        }
        event.state = change.socket.protocol == IPPROTO_TCP ? tcp_state_name(change.socket.state)
                      : change.socket.remote_port != 0U     ? "connected"
                                                            : "bound";
        event.inode = change.socket.inode;
        event.uid = change.socket.uid;
        if (const auto found = owners.find(change.socket.inode); found != owners.end()) {
            event.pid = found->second.pid;
            event.holders = found->second.holders;
        } else {
            // The socket is gone, or its holder exited, or the scan ran out of budget.
            ++unattributed_;
            event.unavailable.push_back({"process", exhausted ? unavailable_reason::budget_exceeded : unavailable_reason::process_exited});
        }
        raw_record record;
        record.time_unix_ns = clock_domain::now_unix_ns();
        record.source = {"sockdiag_network", "SOCKDIAG", confidence::reconstructed};
        record.payload = std::move(event);
        if (queue_->push(std::move(record))) ++events_;
    }
    return true;
}

result<bool> sockdiag_network_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    queue_ = &queue;
    // The first poll seeds the baseline: sockets that already exist are state, not events.
    if (auto first = poll_once(); !std::holds_alternative<bool>(first)) return std::get<error>(first);
    running_.store(true);
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void sockdiag_network_provider::run() {
    while (running_.load()) {
        {
            std::unique_lock lock{wake_mutex_};
            wake_.wait_for(lock, options_.interval, [this] { return !running_.load(); });
        }
        if (!running_.load()) break;
        (void)poll_once();
    }
}

void sockdiag_network_provider::stop() {
    if (!running_.exchange(false)) return;
    {
        const std::lock_guard lock{wake_mutex_};
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}

provider_health sockdiag_network_provider::health() const {
    std::string reason;
    {
        const std::lock_guard lock{failure_mutex_};
        reason = last_failure_;
    }
    const bool active = running_.load();
    const std::string state = !active ? "stopped" : reason.empty() ? "active" : "degraded";
    return {std::string{name()}, state, reason, capabilities(), events_.load(), losses_.load()};
}

}  // namespace panopticon::linux_agent::sensor
