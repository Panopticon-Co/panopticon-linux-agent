#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

namespace panopticon::linux_agent {

// The isolation helper's entire wire protocol: exactly two opcodes, no
// free-form content. See docs/adr/004-host-isolation-privilege-boundary.md.
enum class isolation_opcode : std::uint8_t {
    isolate = 1U,
    release = 2U,
};

inline constexpr std::size_t kIsolationCommandIdCapacity{128U};
// 1 opcode byte + a fixed, null-padded command_id field. Never variable
// length -- there is nothing in this frame an attacker could use to smuggle
// additional content.
inline constexpr std::size_t kIsolationRequestFrameSize{1U + kIsolationCommandIdCapacity};
inline constexpr std::uint8_t kIsolationStatusOk{0U};
inline constexpr std::uint8_t kIsolationStatusRejected{1U};

// Encodes a request frame. Fails closed (returns an error) if command_id is
// not a valid identifier or doesn't fit the fixed field.
[[nodiscard]] result<std::string> encode_isolation_request(isolation_opcode opcode, std::string_view command_id);
// Decodes a request frame built by encode_isolation_request. Used by the
// helper daemon; rejects anything that isn't exactly the fixed frame shape.
[[nodiscard]] result<std::pair<isolation_opcode, std::string>> decode_isolation_request(std::string_view frame);

// Client-side: connects to the helper's AF_UNIX SOCK_SEQPACKET socket,
// sends one request, and returns whether the helper reported success.
// Pure socket syscalls -- no shell, no subprocess -- so this stays inside
// the main agent's unprivileged, no-exec boundary while still being able
// to ask the privileged helper to act.
[[nodiscard]] result<bool> request_isolation(const std::filesystem::path& socket_path, isolation_opcode opcode,
                                              std::string_view command_id);

}  // namespace panopticon::linux_agent
