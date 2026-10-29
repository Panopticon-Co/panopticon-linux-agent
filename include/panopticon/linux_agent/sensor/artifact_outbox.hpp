#pragma once

#include "panopticon/linux_agent/sensor/wal.hpp"
#include <functional>
#include <mutex>
#include <string>

namespace panopticon::linux_agent::sensor {

[[nodiscard]] std::string make_artifact_payload(const std::string& command_id,
    const std::string& correlation_id, const std::string& host_id,
    const std::string& kind, const std::string& content);
[[nodiscard]] bool valid_artifact_ack(std::string_view payload, std::string_view receipt);

// Private, identity-scoped WAL; admission prevents quota eviction of originals.
class artifact_outbox {
public:
    [[nodiscard]] static result<std::unique_ptr<artifact_outbox>> open(
        const std::filesystem::path& directory, std::string agent, std::string host,
        std::uint64_t quota = 64ULL * 1024U * 1024U);
    artifact_outbox(std::unique_ptr<write_ahead_log> log, std::string agent, std::string host,
                    std::uint64_t quota);
    [[nodiscard]] result<bool> save(const std::string& payload);
    [[nodiscard]] result<std::size_t> flush(
        const std::function<std::string(const std::string&)>& sender, std::size_t limit = 8U);
    [[nodiscard]] std::uint64_t pending() const;
private:
    std::unique_ptr<write_ahead_log> log_;
    std::string agent_, host_;
    std::uint64_t quota_;
    std::mutex producer_;
};

}  // namespace panopticon::linux_agent::sensor
