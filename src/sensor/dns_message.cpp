#include "panopticon/linux_agent/sensor/dns_message.hpp"

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::size_t header_size = 12U;
constexpr std::size_t max_name_wire = 255U;
constexpr std::size_t max_label = 63U;

std::uint16_t be16(const std::uint8_t* bytes) { return static_cast<std::uint16_t>((bytes[0] << 8U) | bytes[1]); }

void append_label_byte(std::string& out, const std::uint8_t byte) {
    if (byte == '.' || byte == '\\') {
        out.push_back('\\');
        out.push_back(static_cast<char>(byte));
    } else if (byte >= 0x21U && byte <= 0x7eU) {
        out.push_back(static_cast<char>(byte));
    } else {
        out.push_back('\\');
        out.push_back(static_cast<char>('0' + byte / 100U));
        out.push_back(static_cast<char>('0' + (byte / 10U) % 10U));
        out.push_back(static_cast<char>('0' + byte % 10U));
    }
}

}  // namespace

std::optional<dns_question> parse_dns_query(const std::span<const std::uint8_t> message) {
    if (message.size() < header_size + 1U + 4U) return std::nullopt;
    const std::uint16_t flags = be16(&message[2]);
    if ((flags & 0x8000U) != 0U) return std::nullopt;  // a response, not a query
    if (be16(&message[4]) != 1U) return std::nullopt;   // exactly one question

    dns_question question;
    question.transaction_id = be16(&message[0]);
    question.recursion_desired = (flags & 0x0100U) != 0U;
    question.opcode = static_cast<std::uint8_t>((flags >> 11U) & 0x0fU);

    std::size_t position = header_size;
    std::size_t wire_length = 1U;  // the terminating root label
    bool first_label = true;
    while (true) {
        if (position >= message.size()) return std::nullopt;
        const std::uint8_t length = message[position++];
        if (length == 0U) break;
        if ((length & 0xc0U) != 0U) return std::nullopt;  // compression pointer or extended label type
        if (length > max_label || position + length > message.size()) return std::nullopt;
        wire_length += 1U + length;
        if (wire_length > max_name_wire) return std::nullopt;
        if (!first_label) question.name.push_back('.');
        first_label = false;
        for (std::size_t index = 0U; index < length; ++index) append_label_byte(question.name, message[position + index]);
        position += length;
    }
    if (question.name.empty()) question.name = ".";
    if (position + 4U > message.size()) return std::nullopt;
    question.type = be16(&message[position]);
    question.klass = be16(&message[position + 2U]);
    return question;
}

std::string dns_type_name(const std::uint16_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 35: return "NAPTR";
    case 41: return "OPT";
    case 43: return "DS";
    case 44: return "SSHFP";
    case 46: return "RRSIG";
    case 48: return "DNSKEY";
    case 52: return "TLSA";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 99: return "SPF";
    case 251: return "IXFR";
    case 252: return "AXFR";
    case 255: return "ANY";
    case 257: return "CAA";
    default: return "TYPE" + std::to_string(type);
    }
}

std::string dns_class_name(const std::uint16_t klass) {
    switch (klass) {
    case 1: return "IN";
    case 3: return "CH";
    case 4: return "HS";
    case 255: return "ANY";
    default: return "CLASS" + std::to_string(klass);
    }
}

}  // namespace panopticon::linux_agent::sensor
