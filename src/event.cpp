#include "panopticon/linux_agent/event.hpp"

#include "panopticon/linux_agent/identity.hpp"

#include <sstream>
#include <array>
#include <ctime>
#include <iomanip>

namespace panopticon::linux_agent {
namespace {

std::string escape_json(const std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const unsigned char character : value) {
        switch (character) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (character < 0x20U) {
                    constexpr char hexadecimal[] = "0123456789abcdef";
                    output += "\\u00";
                    output += hexadecimal[(character >> 4U) & 0x0FU];
                    output += hexadecimal[character & 0x0FU];
                } else {
                    output += static_cast<char>(character);
                }
        }
    }
    return output;
}

bool valid_context(const agent_context& context) {
    return is_valid_identifier(context.agent_id) && is_valid_identifier(context.host_id) && !context.hostname.empty() &&
        !context.os_name.empty() && !context.kernel_release.empty();
}

constexpr std::array<std::uint32_t, 64U> sha256_constants{
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};

std::uint32_t rotate_right(const std::uint32_t value, const std::uint32_t bits) { return (value >> bits) | (value << (32U - bits)); }

std::string sha256_hex(std::string input) {
    const auto original_bits = static_cast<std::uint64_t>(input.size()) * 8U;
    input.push_back(static_cast<char>(0x80U));
    while ((input.size() % 64U) != 56U) input.push_back('\0');
    for (int shift = 56; shift >= 0; shift -= 8) input.push_back(static_cast<char>((original_bits >> shift) & 0xFFU));
    std::array<std::uint32_t, 8U> hash{0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    for (std::size_t offset = 0U; offset < input.size(); offset += 64U) {
        std::array<std::uint32_t, 64U> words{};
        for (std::size_t i = 0U; i < 16U; ++i) {
            words[i] = (static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + i * 4U])) << 24U) |
                       (static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + i * 4U + 1U])) << 16U) |
                       (static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + i * 4U + 2U])) << 8U) |
                       static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + i * 4U + 3U]));
        }
        for (std::size_t i = 16U; i < words.size(); ++i) {
            const auto s0 = rotate_right(words[i - 15U], 7U) ^ rotate_right(words[i - 15U], 18U) ^ (words[i - 15U] >> 3U);
            const auto s1 = rotate_right(words[i - 2U], 17U) ^ rotate_right(words[i - 2U], 19U) ^ (words[i - 2U] >> 10U);
            words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
        }
        auto [a,b,c,d,e,f,g,h] = hash;
        for (std::size_t i = 0U; i < words.size(); ++i) {
            const auto s1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
            const auto choice = (e & f) ^ (~e & g);
            const auto temp1 = h + s1 + choice + sha256_constants[i] + words[i];
            const auto s0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + majority;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        hash[0]+=a; hash[1]+=b; hash[2]+=c; hash[3]+=d; hash[4]+=e; hash[5]+=f; hash[6]+=g; hash[7]+=h;
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto value : hash) output << std::setw(8) << value;
    return output.str();
}

std::string canonical_timestamp(const std::chrono::sys_seconds timestamp) {
    const auto seconds = timestamp.time_since_epoch().count();
    const auto raw_time = static_cast<std::time_t>(seconds);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &raw_time);
#else
    gmtime_r(&raw_time, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S.000Z");
    return output.str();
}

std::string nullable_json(const std::string& value) { return value.empty() ? "null" : "\"" + escape_json(value) + "\""; }

}  // namespace

result<internal_process_event> normalize_process(
    process_observation observation, agent_context context, const std::chrono::sys_seconds observed_at) {
    if (!valid_context(context) || observation.identity.host_id != context.host_id || observation.identity.start_time_ticks == 0U) {
        return error{error_code::invalid_input, "process observation or agent context is invalid"};
    }
    const auto identity = process_identity_key(observation.identity);
    return internal_process_event{
        "linux-internal-1",
        "process-snapshot-" + identity,
        observed_at,
        std::move(context),
        std::move(observation),
    };
}

result<std::string> serialize_ndjson(const internal_process_event& event, const std::size_t maximum_bytes) {
    if (event.schema_version != "linux-internal-1" || maximum_bytes == 0U) {
        return error{error_code::invalid_input, "event schema or output limit is invalid"};
    }
    std::ostringstream output;
    output << "{\"schema_version\":\"linux-internal-1\",\"event_id\":\"" << escape_json(event.event_id)
           << "\",\"observed_at_unix\":" << event.observed_at.time_since_epoch().count() << ",\"agent\":{\"id\":\""
           << escape_json(event.context.agent_id) << "\"},\"host\":{\"id\":\"" << escape_json(event.context.host_id)
           << "\",\"hostname\":\"" << escape_json(event.context.hostname) << "\",\"os\":\""
           << escape_json(event.context.os_name) << "\",\"kernel\":\"" << escape_json(event.context.kernel_release)
           << "\"},\"process\":{\"identity\":\"" << escape_json(process_identity_key(event.process.identity))
           << "\",\"pid\":" << event.process.identity.pid << ",\"ppid\":" << event.process.parent_pid << ",\"uid\":"
           << event.process.uid << ",\"gid\":" << event.process.gid << ",\"state\":\"" << event.process.state
           << "\",\"executable\":\"" << escape_json(event.process.executable) << "\",\"command_line\":\""
           << escape_json(event.process.command_line) << "\",\"cgroup\":\"" << escape_json(event.process.cgroup) << "\"}}\n";
    auto serialized = output.str();
    if (serialized.size() > maximum_bytes) {
        return error{error_code::resource_limit, "normalized event exceeds configured size"};
    }
    return serialized;
}

result<std::string> serialize_canonical_process_ndjson(const internal_process_event& event, const std::size_t maximum_bytes) {
    if (event.schema_version != "linux-internal-1" || maximum_bytes == 0U || !valid_context(event.context)) {
        return error{error_code::invalid_input, "event schema, context, or output limit is invalid"};
    }
    const auto identity = process_identity_key(event.process.identity);
    const auto entity_id = "proc_" + sha256_hex(identity);
    const auto event_id = "evt_" + sha256_hex("linux_procfs|" + identity + "|" + std::to_string(event.observed_at.time_since_epoch().count()));
    const auto name = std::filesystem::path{event.process.executable}.filename().string();
    std::ostringstream output;
    output << "{\"schema_version\":\"0.4\",\"event\":{\"id\":\"" << event_id
           << "\",\"category\":\"process\",\"type\":\"start\",\"timestamp\":\"" << canonical_timestamp(event.observed_at)
           << "\"},\"source\":{\"kind\":\"linux_procfs\",\"provider\":\"procfs\",\"channel\":null,\"record_id\":null},\"agent\":{\"id\":\""
           << escape_json(event.context.agent_id) << "\",\"version\":\"" << escape_json(event.context.agent_version)
           << "\"},\"host\":{\"id\":\"" << escape_json(event.context.host_id) << "\",\"hostname\":\"" << escape_json(event.context.hostname)
           << "\",\"os\":{\"name\":\"" << escape_json(event.context.os_name) << "\",\"build\":\"" << escape_json(event.context.kernel_release)
           << "\"}},\"user\":{\"name\":null,\"domain\":null,\"sid\":null},\"process\":{\"entity_id\":\"" << entity_id
           << "\",\"pid\":" << event.process.identity.pid << ",\"name\":" << nullable_json(name) << ",\"executable\":" << nullable_json(event.process.executable)
           << ",\"command_line\":" << nullable_json(event.process.command_line) << ",\"parent\":{\"entity_id\":null,\"pid\":" << event.process.parent_pid
           << ",\"name\":null},\"hash\":{\"sha256\":null}}}\n";
    auto serialized = output.str();
    if (serialized.size() > maximum_bytes) return error{error_code::resource_limit, "canonical event exceeds configured size"};
    return serialized;
}

}  // namespace panopticon::linux_agent
