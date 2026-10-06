#include "panopticon/linux_agent/sensor/sockdiag_network.hpp"

#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

void append(std::vector<unsigned char>& out, const void* data, const std::size_t size) {
    // resize + memcpy: vector::insert from a raw range trips GCC 11's -Wstringop-overflow at -O3 (false positive)
    const auto offset = out.size();
    out.resize(offset + size);
    if (size != 0U) std::memcpy(out.data() + offset, data, size);
}

// One sock_diag reply message, as the kernel lays it out.
std::vector<unsigned char> diag_message(const std::uint8_t family, const std::uint8_t state, const char* local, const std::uint16_t local_port,
                                        const char* remote, const std::uint16_t remote_port, const std::uint32_t inode) {
    inet_diag_msg body{};
    body.idiag_family = family;
    body.idiag_state = state;
    body.id.idiag_sport = htons(local_port);
    body.id.idiag_dport = htons(remote_port);
    if (family == AF_INET) {
        ::inet_pton(AF_INET, local, body.id.idiag_src);
        ::inet_pton(AF_INET, remote, body.id.idiag_dst);
    } else {
        ::inet_pton(AF_INET6, local, body.id.idiag_src);
        ::inet_pton(AF_INET6, remote, body.id.idiag_dst);
    }
    body.idiag_uid = 1000U;
    body.idiag_inode = inode;
    nlmsghdr header{};
    header.nlmsg_len = static_cast<std::uint32_t>(sizeof(header) + sizeof(body));
    header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    std::vector<unsigned char> out;
    append(out, &header, sizeof(header));
    append(out, &body, sizeof(body));
    return out;
}

std::vector<unsigned char> control_message(const std::uint16_t type, const int error_number) {
    nlmsghdr header{};
    std::vector<unsigned char> payload;
    if (type == NLMSG_ERROR) {
        nlmsgerr failure{};
        failure.error = -error_number;
        append(payload, &failure, sizeof(failure));
    } else {
        const int zero = 0;
        append(payload, &zero, sizeof(zero));
    }
    header.nlmsg_len = static_cast<std::uint32_t>(sizeof(header) + payload.size());
    header.nlmsg_type = type;
    std::vector<unsigned char> out;
    append(out, &header, sizeof(header));
    append(out, payload.data(), payload.size());
    return out;
}

void test_decoder_reads_addresses_ports_and_owner() {
    auto buffer = diag_message(AF_INET, 10U, "0.0.0.0", 8080U, "0.0.0.0", 0U, 4242U);
    const auto second = diag_message(AF_INET6, 1U, "::1", 40000U, "::1", 443U, 77U);
    buffer.insert(buffer.end(), second.begin(), second.end());
    const auto done = control_message(NLMSG_DONE, 0);
    buffer.insert(buffer.end(), done.begin(), done.end());
    const auto decoded = decode_sock_diag(buffer.data(), buffer.size(), IPPROTO_TCP);
    require(!decoded.malformed && decoded.done && decoded.entries.size() == 2U, "two entries and a terminator");
    const auto& listener = decoded.entries[0];
    require(listener.protocol == IPPROTO_TCP && listener.family == AF_INET && listener.state == 10U && listener.local_address == "0.0.0.0" &&
                listener.local_port == 8080U && listener.remote_port == 0U && listener.inode == 4242U && listener.uid == 1000U,
            "ipv4 listener");
    const auto& connection = decoded.entries[1];
    require(connection.family == AF_INET6 && connection.local_address == "::1" && connection.remote_address == "::1" &&
                connection.local_port == 40000U && connection.remote_port == 443U && connection.state == 1U,
            "ipv6 connection");
}

void test_decoder_survives_every_truncation_and_corruption() {
    auto buffer = diag_message(AF_INET, 1U, "10.0.0.5", 51000U, "93.184.216.34", 443U, 9001U);
    const auto more = diag_message(AF_INET, 10U, "127.0.0.1", 22U, "0.0.0.0", 0U, 9002U);
    buffer.insert(buffer.end(), more.begin(), more.end());
    for (std::size_t length = 0U; length <= buffer.size(); ++length) {
        const auto decoded = decode_sock_diag(buffer.data(), length, IPPROTO_TCP);
        require(decoded.entries.size() <= 2U, "never more entries than were sent");
        if (length < buffer.size() / 2U) require(decoded.entries.size() <= 1U, "a prefix gives at most the first entry");
    }
    // A header that claims more bytes than exist, one that claims fewer than a header, and a
    // payload too short for the diag body are all rejected without reading past the buffer.
    auto huge = buffer;
    const std::uint32_t big = 0xFFFFFFF0U;
    std::memcpy(huge.data(), &big, sizeof(big));
    require(decode_sock_diag(huge.data(), huge.size(), IPPROTO_TCP).malformed, "oversized length");
    auto tiny = buffer;
    const std::uint32_t small = 4U;
    std::memcpy(tiny.data(), &small, sizeof(small));
    require(decode_sock_diag(tiny.data(), tiny.size(), IPPROTO_TCP).malformed, "undersized length");
    auto bad_family = diag_message(AF_INET, 1U, "1.2.3.4", 1U, "1.2.3.5", 2U, 3U);
    bad_family[sizeof(nlmsghdr)] = 99U;  // idiag_family
    require(decode_sock_diag(bad_family.data(), bad_family.size(), IPPROTO_TCP).malformed, "unknown family");
    auto short_body = diag_message(AF_INET, 1U, "1.2.3.4", 1U, "1.2.3.5", 2U, 3U);
    const std::uint32_t partial = sizeof(nlmsghdr) + 8U;
    std::memcpy(short_body.data(), &partial, sizeof(partial));
    require(decode_sock_diag(short_body.data(), partial, IPPROTO_TCP).malformed, "payload shorter than the diag body");
    // Randomised garbage must never crash or over-read (the sanitizer builds make that visible).
    std::srand(7);
    for (int round = 0; round < 2000; ++round) {
        std::vector<unsigned char> junk(static_cast<std::size_t>(std::rand() % 200));
        for (auto& byte : junk) byte = static_cast<unsigned char>(std::rand());
        (void)decode_sock_diag(junk.data(), junk.size(), IPPROTO_UDP);
    }
}

void test_decoder_reports_kernel_errors() {
    const auto message = control_message(NLMSG_ERROR, EPERM);
    const auto decoded = decode_sock_diag(message.data(), message.size(), IPPROTO_TCP);
    require(decoded.error == EPERM && decoded.done && decoded.entries.empty(), "error reply carries the errno");
    auto short_error = message;
    const std::uint32_t shorter = sizeof(nlmsghdr) + 2U;
    std::memcpy(short_error.data(), &shorter, sizeof(shorter));
    require(decode_sock_diag(short_error.data(), shorter, IPPROTO_TCP).malformed, "truncated error body");
}

socket_entry tcp(const std::uint8_t state, const char* local, const std::uint16_t local_port, const char* remote, const std::uint16_t remote_port,
                 const std::uint64_t inode) {
    socket_entry entry;
    entry.protocol = IPPROTO_TCP;
    entry.family = AF_INET;
    entry.state = state;
    entry.local_address = local;
    entry.local_port = local_port;
    entry.remote_address = remote;
    entry.remote_port = remote_port;
    entry.inode = inode;
    return entry;
}

socket_entry udp(const char* local, const std::uint16_t local_port, const char* remote, const std::uint16_t remote_port, const std::uint64_t inode) {
    auto entry = tcp(remote_port == 0U ? 7U : 1U, local, local_port, remote, remote_port, inode);
    entry.protocol = IPPROTO_UDP;
    return entry;
}

bool has(const std::vector<socket_change>& changes, const network_operation operation, const std::uint64_t inode) {
    for (const auto& change : changes) {
        if (change.operation == operation && change.socket.inode == inode) return true;
    }
    return false;
}

void test_tracker_seeds_then_reports_new_sockets_once() {
    socket_tracker tracker;
    const auto existing = tcp(10U, "0.0.0.0", 22U, "0.0.0.0", 0U, 1U);
    require(tracker.update({existing}).empty(), "the first snapshot is state, not events");
    const auto connect = tcp(1U, "10.0.0.5", 51000U, "93.184.216.34", 443U, 2U);
    const auto accept = tcp(1U, "10.0.0.5", 22U, "10.0.0.9", 60000U, 3U);
    const auto listen = tcp(10U, "127.0.0.1", 9000U, "0.0.0.0", 0U, 4U);
    const auto bound = udp("0.0.0.0", 5353U, "0.0.0.0", 0U, 5U);
    const auto connected = udp("10.0.0.5", 42000U, "1.1.1.1", 53U, 6U);
    auto changes = tracker.update({existing, connect, accept, listen, bound, connected});
    require(changes.size() == 5U, "five new sockets");
    require(has(changes, network_operation::connect, 2U), "outbound tcp is a connect");
    require(has(changes, network_operation::accept, 3U), "a connection to a local listening port is an accept");
    require(has(changes, network_operation::listen, 4U), "tcp LISTEN");
    require(has(changes, network_operation::listen, 5U), "a bound, unconnected udp socket listens");
    require(has(changes, network_operation::connect, 6U), "a connected udp socket is a connect");
    require(tracker.update({existing, connect, accept, listen, bound, connected}).empty(), "nothing is reported twice");
    // The connection closes and the same four-tuple is used again by a new socket: new inode, new event.
    require(tracker.update({existing, accept, listen, bound, connected}).empty(), "closing is silent");
    const auto again = tcp(1U, "10.0.0.5", 51000U, "93.184.216.34", 443U, 7U);
    changes = tracker.update({existing, accept, listen, bound, connected, again});
    require(changes.size() == 1U && has(changes, network_operation::connect, 7U), "reused four-tuple is a new connection");
}

void test_tracker_skips_what_it_cannot_attribute() {
    socket_tracker tracker;
    require(tracker.update({}).empty(), "seed");
    const auto waiting = tcp(6U, "10.0.0.5", 51000U, "93.184.216.34", 443U, 0U);  // TIME_WAIT: no owner
    const auto closed = tcp(7U, "10.0.0.5", 51001U, "93.184.216.34", 443U, 8U);
    const auto unbound = udp("0.0.0.0", 0U, "0.0.0.0", 0U, 9U);
    require(tracker.update({waiting, closed, unbound}).empty(), "finished or unowned sockets are not events");
    const auto late = tcp(8U, "10.0.0.5", 51002U, "93.184.216.34", 443U, 10U);  // CLOSE_WAIT with an owner
    require(has(tracker.update({late}), network_operation::connect, 10U), "an open connection first seen late is still reported");
}

void test_tracker_is_bounded_and_counts_overflow() {
    socket_tracker tracker{socket_tracker_options{3U, false}};
    require(tracker.update({}).empty(), "seed");
    std::vector<socket_entry> many;
    for (std::uint64_t index = 1U; index <= 10U; ++index) {
        many.push_back(tcp(10U, "0.0.0.0", static_cast<std::uint16_t>(1000U + index), "0.0.0.0", 0U, index));
    }
    const auto changes = tracker.update(many);
    require(changes.size() == 3U && tracker.tracked() == 3U, "the table never exceeds its bound");
    require(tracker.take_overflow() == 7U && tracker.take_overflow() == 0U, "the sockets that did not fit are counted");
}

struct scratch {
    fs::path path;
    scratch() {
        std::string pattern = (fs::temp_directory_path() / "panopticon-net-XXXXXX").string();
        require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp");
        path = pattern;
    }
    ~scratch() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    void link(const std::string& pid, const std::string& fd, const std::string& target) const {
        fs::create_directories(path / pid / "fd");
        fs::create_symlink(target, path / pid / "fd" / fd);
    }
};

void test_owner_scan_picks_lowest_pid_and_ignores_noise() {
    scratch proc;
    proc.link("300", "3", "socket:[555]");
    proc.link("200", "7", "socket:[555]");
    proc.link("200", "8", "socket:[556]");
    proc.link("400", "1", "pipe:[555]");
    proc.link("400", "2", "socket:[99999999999999999999999]");  // overflows 64 bits
    proc.link("400", "3", "socket:[12ab]");
    proc.link("400", "4", "socket:[]");
    proc.link("400", "5", "/tmp/not-a-socket");
    proc.link("self", "3", "socket:[555]");  // not a pid
    const auto owners = scan_socket_owners(proc.path, {555U, 556U, 12U}, std::chrono::milliseconds{1000});
    require(owners.size() == 2U, "only the wanted, well-formed sockets");
    require(owners.at(555U).pid == 200U && owners.at(555U).holders == 2U, "two holders, lowest pid reported");
    require(owners.at(556U).pid == 200U && owners.at(556U).holders == 1U, "single holder");
    bool exhausted = false;
    (void)scan_socket_owners(proc.path, {555U}, std::chrono::milliseconds{-1}, &exhausted);
    require(exhausted, "an exhausted budget is reported");
}

bool wait_for_events(record_queue& queue, std::vector<raw_network_event>& seen, const std::size_t count) {
    for (int attempt = 0; attempt < 100 && seen.size() < count; ++attempt) {
        std::vector<raw_record> batch;
        queue.pop_batch(batch, 64U, std::chrono::milliseconds{50});
        for (const auto& record : batch) {
            if (const auto* event = std::get_if<raw_network_event>(&record.payload)) seen.push_back(*event);
        }
    }
    return seen.size() >= count;
}

void test_real_kernel_sees_loopback_listener_connect_and_accept() {
    sockdiag_options options;
    options.interval = std::chrono::milliseconds{50};
    sockdiag_network_provider provider{options};
    if (const auto reason = provider.probe(); !reason.empty()) {
        std::printf("SKIP real_kernel (%s)\n", reason.c_str());
        return;
    }
    record_queue queue{1024U};
    require(std::holds_alternative<bool>(provider.start(queue)), "provider starts and seeds");

    const int server = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(server >= 0, "socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "bind");
    require(::listen(server, 4) == 0, "listen");
    socklen_t length = sizeof(address);
    require(::getsockname(server, reinterpret_cast<sockaddr*>(&address), &length) == 0, "getsockname");
    const std::uint16_t port = ntohs(address.sin_port);
    const int client = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "connect");
    const int accepted = ::accept(server, nullptr, nullptr);
    require(accepted >= 0, "accept");

    std::vector<raw_network_event> seen;
    require(wait_for_events(queue, seen, 3U), "three events within five seconds");
    provider.stop();
    ::close(accepted);
    ::close(client);
    ::close(server);

    const auto self = static_cast<std::uint32_t>(::getpid());
    bool listen_seen = false;
    bool connect_seen = false;
    bool accept_seen = false;
    for (const auto& event : seen) {
        if (event.protocol != "tcp" || (event.local_port != port && event.remote_port != port)) continue;
        if (event.operation == network_operation::listen && event.local_port == port && event.pid == self) listen_seen = true;
        if (event.operation == network_operation::connect && event.remote_port == port && event.remote_address == "127.0.0.1" && event.pid == self) {
            connect_seen = true;
        }
        if (event.operation == network_operation::accept && event.local_port == port && event.pid == self) accept_seen = true;
    }
    require(listen_seen, "listen attributed to this process");
    require(connect_seen, "connect attributed to this process");
    require(accept_seen, "accept attributed to this process");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"decoder_reads_addresses_ports_and_owner", test_decoder_reads_addresses_ports_and_owner},
        {"decoder_survives_every_truncation_and_corruption", test_decoder_survives_every_truncation_and_corruption},
        {"decoder_reports_kernel_errors", test_decoder_reports_kernel_errors},
        {"tracker_seeds_then_reports_new_sockets_once", test_tracker_seeds_then_reports_new_sockets_once},
        {"tracker_skips_what_it_cannot_attribute", test_tracker_skips_what_it_cannot_attribute},
        {"tracker_is_bounded_and_counts_overflow", test_tracker_is_bounded_and_counts_overflow},
        {"owner_scan_picks_lowest_pid_and_ignores_noise", test_owner_scan_picks_lowest_pid_and_ignores_noise},
        {"real_kernel_sees_loopback_listener_connect_and_accept", test_real_kernel_sees_loopback_listener_connect_and_accept},
    };
    int failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::printf("PASS %s\n", test.name);
        } catch (const std::exception& error) {
            std::printf("FAIL %s: %s\n", test.name, error.what());
            ++failures;
        }
    }
    std::printf(failures == 0 ? "ALL PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
