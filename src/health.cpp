#include "panopticon/linux_agent/health.hpp"
#include <sstream>
namespace panopticon::linux_agent {
std::string serialize_health_ndjson(const health_status& status, const std::size_t maximum_bytes) {
    std::ostringstream output;
    output << "{\"enrolled\":" << (status.enrolled ? "true" : "false") << ",\"spool_bytes\":" << status.spool_bytes
           << ",\"dropped_events\":" << status.dropped_events << ",\"transport_state\":\"" << status.transport_state << "\"}";
    auto result = output.str(); return result.size() <= maximum_bytes ? result : std::string{};
}
}  // namespace panopticon::linux_agent
