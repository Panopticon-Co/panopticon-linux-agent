#include "panopticon/linux_agent/sensor/artifact_outbox.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"
#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include <stdexcept>
#include <algorithm>
#include <utility>

namespace panopticon::linux_agent::sensor {
namespace {
const json_value* member(const json_value& value, const char* key) { return value.find(key); }
std::string text(const json_value& value, const char* key) {
    const auto* field = member(value, key);
    return field && field->as_string() ? std::string(*field->as_string()) : std::string{};
}
}
std::string make_artifact_payload(const std::string& command_id, const std::string& correlation_id,
    const std::string& host_id, const std::string& kind, const std::string& content) {
    if (content.empty() || content.size() > 1024U * 1024U)
        throw std::invalid_argument("structured artifact exceeds content bound");
    const auto body = parse_json(content, json_limits{1024U * 1024U, 32U, 200000U}, nullptr);
    if (!body || (!body->is_object() && !body->is_array()))
        throw std::invalid_argument("structured artifact must be bounded JSON object/array");
    const auto digest = sha256_hex(content);
    std::string material = "response-artifact-v1\n";
    for (const auto& field : {command_id, correlation_id, kind, digest})
        material += std::to_string(field.size()) + ":" + field;
    json_writer out;
    out.begin_object().field("schema_version", "1").field("artifact_id", "art_" + sha256_hex(material));
    out.field("command_id", command_id).field("correlation_id", correlation_id).field("host_id", host_id);
    out.field("kind", kind).field("media_type", "application/json");
    out.field("content_bytes", static_cast<std::uint64_t>(content.size())).field("sha256", digest);
    out.field("content_base64", response_profile_header(content)).end_object();
    return out.take();
}

bool valid_artifact_ack(const std::string_view payload, const std::string_view receipt) {
    const auto sent = parse_json(payload, json_limits{1500U * 1024U, 4U, 64U}, nullptr);
    const auto ack = parse_json(receipt, json_limits{4096U, 4U, 16U}, nullptr);
    if (!sent || !ack || !ack->is_object() || ack->keys().size() != 3U) return false;
    const auto* retained = ack->find("retained");
    return retained && retained->as_boolean() == true && !text(*sent, "artifact_id").empty()
        && text(*ack, "artifact_id") == text(*sent, "artifact_id")
        && !text(*sent, "sha256").empty() && text(*ack, "sha256") == text(*sent, "sha256");
}

artifact_outbox::artifact_outbox(std::unique_ptr<write_ahead_log> log, std::string agent,
    std::string host, const std::uint64_t quota)
    : log_{std::move(log)}, agent_{std::move(agent)}, host_{std::move(host)}, quota_{quota} {}

result<std::unique_ptr<artifact_outbox>> artifact_outbox::open(const std::filesystem::path& directory,
    std::string agent, std::string host, const std::uint64_t quota) {
    wal_options options;
    options.directory = directory;
    options.quota_bytes = quota;
    options.segment_bytes = std::min<std::uint64_t>(8ULL * 1024U * 1024U, quota / 2U);
    options.maximum_record_bytes = static_cast<std::uint32_t>(std::min<std::uint64_t>(
        1500U * 1024U, options.segment_bytes > wal_header_bytes ? options.segment_bytes - wal_header_bytes : 0U));
    auto opened = write_ahead_log::open(options);
    if (!succeeded(opened)) return std::get<error>(opened);
    if (!std::get<std::unique_ptr<write_ahead_log>>(opened)->take_losses().empty())
        return error{error_code::corrupt_data, "artifact recovery reported loss; store requires investigation"};
    return std::make_unique<artifact_outbox>(std::move(std::get<std::unique_ptr<write_ahead_log>>(opened)),
        std::move(agent), std::move(host), quota);
}

result<bool> artifact_outbox::save(const std::string& payload) {
    const auto value = parse_json(payload, json_limits{1500U * 1024U, 4U, 64U}, nullptr);
    if (!value || text(*value, "schema_version") != "1" || text(*value, "host_id") != host_
        || !is_valid_identifier(text(*value, "command_id"))
        || text(*value, "artifact_id").size() != 68U || text(*value, "sha256").size() != 64U)
        return error{error_code::invalid_input, "artifact scope/schema disagreement"};
    json_writer wrapper;
    wrapper.begin_object().field("agent_id", agent_).field("host_id", host_).field("artifact", payload).end_object();
    const auto bytes = wrapper.take();
    std::lock_guard lock{producer_};
    if (bytes.size() > 1500U * 1024U || log_->metrics().bytes + bytes.size() + wal_header_bytes > quota_)
        return error{error_code::resource_limit, "artifact quota reached; originals preserved"};
    auto appended = log_->append(log_->next_seq(), bytes);
    if (!succeeded(appended)) return std::get<error>(appended);
    return log_->sync(clock_domain::now_monotonic_ns(), true);
}

result<std::size_t> artifact_outbox::flush(const std::function<std::string(const std::string&)>& sender,
                                         const std::size_t limit) {
    std::size_t retired = 0U;
    for (std::size_t i = 0; i < limit; ++i) {
        const auto metrics = log_->metrics();
        auto read = log_->read(metrics.acknowledged_seq + 1U, 1U, 2U * 1024U * 1024U);
        if (!succeeded(read)) return std::get<error>(read);
        const auto& records = std::get<std::vector<wal_record>>(read);
        if (records.empty()) return retired;
        const auto wrapper = parse_json(records.front().payload, json_limits{1500U * 1024U, 4U, 64U}, nullptr);
        if (!wrapper || text(*wrapper, "agent_id") != agent_ || text(*wrapper, "host_id") != host_)
            return error{error_code::invalid_input, "artifact outbox scope mismatch; original retained"};
        const auto payload = text(*wrapper, "artifact");
        if (!valid_artifact_ack(payload, sender(payload))) return retired;
        auto acked = log_->acknowledge(records.front().seq);
        if (!succeeded(acked)) return std::get<error>(acked);
        ++retired;
    }
    return retired;
}

std::uint64_t artifact_outbox::pending() const {
    const auto metrics = log_->metrics();
    return metrics.next_seq > metrics.acknowledged_seq ? metrics.next_seq - metrics.acknowledged_seq - 1U : 0U;
}
}  // namespace panopticon::linux_agent::sensor
