#include "panopticon/linux_agent/event.hpp"

#include "panopticon/linux_agent/identity.hpp"

#include <sstream>

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

}  // namespace panopticon::linux_agent
