#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/identity.hpp"

#include <algorithm>
#include <cstring>
#ifdef __linux__
#include <sys/socket.h>
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

result<bool> request_isolation(const std::filesystem::path& socket_path, const isolation_opcode opcode,
                                const std::string_view command_id) {
    const auto encoded = encode_isolation_request(opcode, command_id);
    if (!succeeded(encoded)) return std::get<error>(encoded);
#ifndef __linux__
    (void)socket_path;
    return error{error_code::unsupported_action, "the isolation helper IPC is available only on Linux"};
#else
    const int socket_descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (socket_descriptor < 0) return error{error_code::io_failure, "cannot create isolation helper socket"};
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto path_text = socket_path.string();
    if (path_text.size() >= sizeof(address.sun_path)) {
        close(socket_descriptor);
        return error{error_code::invalid_input, "isolation helper socket path is too long"};
    }
    std::copy(path_text.begin(), path_text.end(), address.sun_path);
    if (connect(socket_descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        close(socket_descriptor);
        return error{error_code::io_failure, "cannot connect to isolation helper"};
    }
    const auto& frame = std::get<std::string>(encoded);
    if (send(socket_descriptor, frame.data(), frame.size(), 0) != static_cast<ssize_t>(frame.size())) {
        close(socket_descriptor);
        return error{error_code::io_failure, "isolation request could not be sent"};
    }
    std::uint8_t status{kIsolationStatusRejected};
    const auto received = recv(socket_descriptor, &status, sizeof(status), 0);
    close(socket_descriptor);
    if (received != static_cast<ssize_t>(sizeof(status))) {
        return error{error_code::io_failure, "isolation helper response was malformed"};
    }
    return status == kIsolationStatusOk;
#endif
}

}  // namespace panopticon::linux_agent
