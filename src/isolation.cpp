#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/identity.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#ifdef __linux__
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace panopticon::linux_agent {

result<std::string> encode_isolation_request(const isolation_opcode opcode, const std::string_view command_id) {
    if (!is_valid_identifier(command_id) || command_id.size() > kIsolationCommandIdCapacity) {
        return error{error_code::invalid_input, "isolation request command_id is invalid"};
    }
    if (opcode != isolation_opcode::isolate && opcode != isolation_opcode::release) {
        return error{error_code::invalid_input, "isolation opcode is not one of the two closed values"};
    }
    std::string frame(kIsolationRequestFrameSize, '\0');
    frame[0] = static_cast<char>(static_cast<std::uint8_t>(opcode));
    std::copy(command_id.begin(), command_id.end(), frame.begin() + 1);
    return frame;
}

result<std::pair<isolation_opcode, std::string>> decode_isolation_request(const std::string_view frame) {
    if (frame.size() != kIsolationRequestFrameSize) {
        return error{error_code::invalid_input, "isolation request frame has the wrong size"};
    }
    const auto raw_opcode = static_cast<std::uint8_t>(frame[0]);
    if (raw_opcode != static_cast<std::uint8_t>(isolation_opcode::isolate) &&
        raw_opcode != static_cast<std::uint8_t>(isolation_opcode::release)) {
        return error{error_code::unsupported_action, "isolation opcode is not one of the two closed values"};
    }
    const auto field = frame.substr(1U);
    const auto terminator = field.find('\0');
    const auto command_id = std::string{field.substr(0U, terminator == std::string_view::npos ? field.size() : terminator)};
    // Every byte after the terminator must be padding, not trailing content
    // an attacker appended past a shorter command_id.
    if (terminator != std::string_view::npos &&
        field.substr(terminator).find_first_not_of('\0') != std::string_view::npos) {
        return error{error_code::invalid_input, "isolation request has non-zero padding"};
    }
    if (!is_valid_identifier(command_id)) return error{error_code::invalid_input, "isolation request command_id is invalid"};
    return std::pair{static_cast<isolation_opcode>(raw_opcode), command_id};
}

namespace {

#ifdef __linux__
// Opens and connects a SOCK_SEQPACKET client; -1 with errno-free semantics for "unreachable"/"unusable path".
struct connection_attempt {
    int descriptor{-1};
    isolation_exchange failure{isolation_exchange::unreachable};
};

void bound_socket_waits(const int descriptor, const std::chrono::milliseconds timeout) {
    const auto whole = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    timeval limit{};
    limit.tv_sec = static_cast<time_t>(whole.count());
    limit.tv_usec = static_cast<suseconds_t>(std::chrono::duration_cast<std::chrono::microseconds>(timeout - whole).count());
    (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
}
connection_attempt connect_to_helper(const std::filesystem::path& socket_path, const std::chrono::milliseconds timeout) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto path_text = socket_path.string();
    if (path_text.empty() || path_text.size() >= sizeof(address.sun_path)) return {-1, isolation_exchange::invalid};
    const int descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor < 0) return {-1, isolation_exchange::unreachable};
    std::copy(path_text.begin(), path_text.end(), address.sun_path);
    bound_socket_waits(descriptor, timeout);  // connect() waits too when the helper's backlog is full
    if (connect(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        close(descriptor);
        return {-1, isolation_exchange::unreachable};
    }
    return {descriptor, isolation_exchange::accepted};
}

#endif

}  // namespace

isolation_exchange exchange_isolation_request(const std::filesystem::path& socket_path, const isolation_opcode opcode,
                                              const std::string_view command_id,
                                              const std::chrono::milliseconds timeout) {
    const auto encoded = encode_isolation_request(opcode, command_id);
    if (!succeeded(encoded)) return isolation_exchange::invalid;
#ifndef __linux__
    (void)socket_path;
    (void)timeout;
    return isolation_exchange::unreachable;
#else
    const auto attempt = connect_to_helper(socket_path, timeout);
    if (attempt.descriptor < 0) return attempt.failure;
    const auto& frame = std::get<std::string>(encoded);
    if (send(attempt.descriptor, frame.data(), frame.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(frame.size())) {
        // Nothing, or an unknown amount, reached the helper; a refused send on a connected socket means the
        // helper went away before reading, which is the same as not having asked.
        close(attempt.descriptor);
        return isolation_exchange::unreachable;
    }
    std::uint8_t status{kIsolationStatusRejected};
    const auto received = recv(attempt.descriptor, &status, sizeof(status), 0);
    close(attempt.descriptor);
    if (received != static_cast<ssize_t>(sizeof(status))) return isolation_exchange::no_answer;
    return status == kIsolationStatusOk ? isolation_exchange::accepted : isolation_exchange::refused;
#endif
}

bool isolation_helper_reachable(const std::filesystem::path& socket_path) {
#ifndef __linux__
    (void)socket_path;
    return false;
#else
    const auto attempt = connect_to_helper(socket_path, std::chrono::seconds{2});
    if (attempt.descriptor < 0) return false;
    close(attempt.descriptor);
    return true;
#endif
}

result<bool> request_isolation(const std::filesystem::path& socket_path, const isolation_opcode opcode,
                                const std::string_view command_id) {
    const auto encoded = encode_isolation_request(opcode, command_id);
    if (!succeeded(encoded)) return std::get<error>(encoded);
#ifndef __linux__
    (void)socket_path;
    return error{error_code::unsupported_action, "the isolation helper IPC is available only on Linux"};
#else
    switch (exchange_isolation_request(socket_path, opcode, command_id, std::chrono::seconds{10})) {
        case isolation_exchange::accepted: return true;
        case isolation_exchange::refused: return false;
        case isolation_exchange::unreachable: return error{error_code::io_failure, "cannot connect to isolation helper"};
        case isolation_exchange::no_answer: return error{error_code::io_failure, "isolation helper response was malformed"};
        case isolation_exchange::invalid: return error{error_code::invalid_input, "isolation helper socket path is invalid"};
    }
    return error{error_code::io_failure, "isolation request failed"};
#endif
}

}  // namespace panopticon::linux_agent
