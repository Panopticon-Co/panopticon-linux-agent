#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace panopticon::linux_agent::sensor {

// The question of a DNS query as a process sent it on the wire (RFC 1035 section 4). Everything here
// is bytes a program chose, so the parser is bounded and a malformed message yields nothing rather
// than a guess.
struct dns_question {
    std::uint16_t transaction_id{};
    bool recursion_desired{};
    std::uint8_t opcode{};
    std::string name;  // presentation form, as sent (case preserved), no trailing dot; "." for the root
    std::uint16_t type{};
    std::uint16_t klass{};
};

// Parses the first question of a query message (QR bit clear, exactly one question). Compression
// pointers and extended label types are not valid in a question and are rejected, as is a name over
// 255 bytes or a label over 63. Labels are rendered with `.` and `\` escaped and every byte outside
// printable ASCII written as `\DDD`, so a name can never contain a separator the reader would
// misinterpret.
[[nodiscard]] std::optional<dns_question> parse_dns_query(std::span<const std::uint8_t> message);

[[nodiscard]] std::string dns_type_name(std::uint16_t type);   // A, AAAA, TXT, ... or TYPE<n>
[[nodiscard]] std::string dns_class_name(std::uint16_t klass);  // IN, CH, HS, ANY or CLASS<n>

}  // namespace panopticon::linux_agent::sensor
