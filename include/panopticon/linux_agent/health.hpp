#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
namespace panopticon::linux_agent {
struct health_status {
    bool enrolled{};
    std::uint64_t spool_bytes{};
    std::uint64_t dropped_events{};
    std::string transport_state;
    std::string last_error;
};
[[nodiscard]] std::string serialize_health_ndjson(const health_status& status, std::size_t maximum_bytes);
}  // namespace panopticon::linux_agent
