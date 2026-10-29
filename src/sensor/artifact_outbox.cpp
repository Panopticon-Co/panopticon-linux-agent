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

result<std::string> artifact_manifest_signing_input(const std::string_view manifest) {
    const auto document = parse_json(manifest, json_limits{1500U * 1024U, 4U, 64U}, nullptr);
    const auto* value = document ? document->find("manifest") : nullptr;
    if (!value && document) value = &*document;
    const auto* auth = value ? value->find("authorization") : nullptr;
    if (!value || value->keys().size() != 12U || text(*value, "schema_version") != "2" ||
        !auth || auth->keys().size() != 3U || text(*auth, "algorithm") != "ES256")
        return error{error_code::invalid_input, "invalid closed artifact manifest"};
    std::string result = "panopticon-response-artifact-auth/2\n";
    for (const auto* name : {"schema_version", "artifact_id", "agent_id", "host_id", "command_id",
        "correlation_id", "kind", "media_type", "content_bytes", "sha256", "produced_at_unix", "algorithm", "key_id"}) {
        const bool authorization = std::string_view{name} == "algorithm" || std::string_view{name} == "key_id";
        const auto* field = (authorization ? auth : &*value)->find(name);
        if (!field) return error{error_code::invalid_input, "missing artifact signing field"};
        const bool numeric = std::string_view{name} == "content_bytes" || std::string_view{name} == "produced_at_unix";
        if (numeric ? !field->as_unsigned().has_value() : !field->as_string().has_value())
            return error{error_code::invalid_input, "invalid artifact signing field type"};
        const auto data = numeric ? std::to_string(*field->as_unsigned()) : std::string(*field->as_string());
        result += std::string{name} + ":" + std::to_string(data.size()) + ":" + data + "\n";
    }
    return result;
}

result<std::string> sign_artifact_payload(const std::string& payload, const std::string& agent,
    const ec_keypair& keypair, const std::uint64_t produced_at_unix) {
    const auto value = parse_json(payload, json_limits{1500U * 1024U, 4U, 64U}, nullptr);
    if (!value || text(*value, "schema_version") != "1" || !is_valid_identifier(agent))
        return error{error_code::invalid_input, "invalid unsigned collection envelope"};
    const auto* count = value->find("content_bytes");
    if (!count || !count->as_unsigned() || *count->as_unsigned() > 1024U * 1024U)
        return error{error_code::invalid_input, "invalid artifact content bound"};
    const auto key_id = sha256_hex(std::string{reinterpret_cast<const char*>(keypair.public_point.data()),
                                             keypair.public_point.size()}).substr(0U, 16U);
    const auto manifest = [&](const std::string& signature) {
        json_writer out;
        out.begin_object().field("schema_version", "2").field("agent_id", agent);
        for (const auto* name : {"artifact_id", "host_id", "command_id", "correlation_id", "kind", "media_type", "sha256"})
            out.field(name, text(*value, name));
        out.field("content_bytes", *count->as_unsigned()).field("produced_at_unix", produced_at_unix);
        out.key("authorization").begin_object().field("algorithm", "ES256").field("key_id", key_id);
        out.field("signature", signature).end_object().end_object();
        return out.take();
    };
    const auto input = artifact_manifest_signing_input(manifest(response_profile_header(std::string(64U, '\0'))));
    if (!succeeded(input)) return std::get<error>(input);
    const auto& data = std::get<std::string>(input);
    const auto signed_bytes = sign_raw(keypair, std::vector<std::uint8_t>(data.begin(), data.end()));
    if (!succeeded(signed_bytes)) return std::get<error>(signed_bytes);
    const auto& raw = std::get<ec_raw_signature>(signed_bytes);
    json_writer out;
    out.begin_object().key("manifest").raw(manifest(response_profile_header(
        std::string_view{reinterpret_cast<const char*>(raw.data()), raw.size()})));
    out.field("content_base64", text(*value, "content_base64")).end_object();
    return out.take();
}

bool valid_artifact_ack(const std::string_view payload, const std::string_view receipt) {
    const auto sent = parse_json(payload, json_limits{1500U * 1024U, 4U, 64U}, nullptr);
    const auto ack = parse_json(receipt, json_limits{4096U, 4U, 16U}, nullptr);
    if (!sent || !ack || !ack->is_object() || ack->keys().size() != 3U) return false;
    const auto* manifest = sent->find("manifest");
    if (!manifest) manifest = &*sent;
    const auto* retained = ack->find("retained");
    return retained && retained->as_boolean() == true && !text(*manifest, "artifact_id").empty()
        && text(*ack, "artifact_id") == text(*manifest, "artifact_id")
        && !text(*manifest, "sha256").empty() && text(*ack, "sha256") == text(*manifest, "sha256");
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
    const auto* manifest = value ? value->find("manifest") : nullptr;
    if (!manifest && value) manifest = &*value;
    if (!manifest || (text(*manifest, "schema_version") != "1" && text(*manifest, "schema_version") != "2") ||
        text(*manifest, "host_id") != host_ ||
        (value->find("manifest") && text(*manifest, "agent_id") != agent_) ||
        !is_valid_identifier(text(*manifest, "command_id")) ||
        text(*manifest, "artifact_id").size() != 68U || text(*manifest, "sha256").size() != 64U)
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
