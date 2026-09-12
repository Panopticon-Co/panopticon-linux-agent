#include "panopticon/linux_agent/transport.hpp"

namespace panopticon::linux_agent {
result<std::size_t> drain_spool(durable_spool& spool, https_client& client, const std::string& https_url,
                                const enrolled_identity& identity, const std::size_t maximum_records) {
    if (https_url.rfind("https://", 0U) != 0U || maximum_records == 0U || !is_valid_identifier(identity.agent_id))
        return error{error_code::invalid_input, "transport requires HTTPS, an enrolled identity, and a positive limit"};
    const auto entries = spool.pending();
    if (!succeeded(entries)) return std::get<error>(entries);
    std::size_t drained{};
    for (const auto& entry : std::get<std::vector<std::filesystem::path>>(entries)) {
        if (drained == maximum_records) break;
        const auto payload = spool.read(entry);
        if (!succeeded(payload)) return std::get<error>(payload);
        const auto outcome = client.post_ndjson(https_url, identity, std::get<std::string>(payload));
        if (outcome != transport_outcome::acknowledged) break;
        const auto acknowledged = spool.acknowledge(entry);
        if (!succeeded(acknowledged)) return std::get<error>(acknowledged);
        ++drained;
    }
    return drained;
}
}  // namespace panopticon::linux_agent
