#include "panopticon/linux_agent/transport.hpp"
#include <random>
#include <iomanip>
#include <sstream>
#include <mutex>

#ifdef PANOPTICON_HAVE_CURL
#include <curl/curl.h>
#endif

namespace panopticon::linux_agent {
#ifdef PANOPTICON_HAVE_CURL
namespace {
std::once_flag curl_initialization;
bool curl_ready{};
bool initialize_curl() {
    std::call_once(curl_initialization, [] { curl_ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
    return curl_ready;
}
std::string batch_id() {
    std::random_device source; std::mt19937_64 generator{source()};
    std::ostringstream output; output << std::hex << std::setfill('0');
    for (int index = 0; index < 2; ++index) output << std::setw(16) << generator();
    return output.str();
}
}
#endif
curl_https_client::curl_https_client(const long timeout_seconds, const std::size_t maximum_response_bytes)
    : timeout_seconds_{timeout_seconds}, maximum_response_bytes_{maximum_response_bytes} {}

#ifdef PANOPTICON_HAVE_CURL
namespace {
struct response_sink { std::size_t limit; std::string contents; };
size_t capture_bounded_response(char* data, const size_t size, const size_t count, void* context) {
    auto* sink = static_cast<response_sink*>(context); const auto bytes = size * count;
    if (bytes > sink->limit - sink->contents.size()) return 0U;
    sink->contents.append(data, bytes); return bytes;
}
}
#endif

#ifdef PANOPTICON_HAVE_CURL
namespace {
std::string without_trailing_slash(std::string url) {
    while (url.size() > 8U && url.back() == '/') url.pop_back();
    return url;
}

std::string json_string_value(const std::string& body, const std::string& key) {
    const auto needle = "\"" + key + "\":\"";
    const auto begin = body.find(needle);
    if (begin == std::string::npos) return {};
    const auto value_begin = begin + needle.size();
    const auto end = body.find('"', value_begin);
    if (end == std::string::npos || body.find('\\', value_begin) < end) return {};
    return body.substr(value_begin, end - value_begin);
}
}
#endif

transport_outcome curl_https_client::post_ndjson(const std::string& https_url, const enrolled_identity& identity,
                                                  const std::string& payload) {
    if (https_url.rfind("https://", 0U) != 0U || identity.bearer_token.empty() || payload.empty() || timeout_seconds_ <= 0L)
        return transport_outcome::rejected;
#ifndef PANOPTICON_HAVE_CURL
    return transport_outcome::retryable;
#else
    if (!initialize_curl()) return transport_outcome::retryable;
    CURL* handle = curl_easy_init(); if (handle == nullptr) return transport_outcome::retryable;
    response_sink sink{maximum_response_bytes_, {}};
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
    headers = curl_slist_append(headers, "X-Panopticon-Protocol: 1");
    const auto agent_header = "X-Panopticon-Agent-Id: " + identity.agent_id;
    const auto request_batch_id = batch_id();
    const auto batch_header = "X-Panopticon-Batch-Id: " + request_batch_id;
    const auto auth_header = "Authorization: Bearer " + identity.bearer_token;
    headers = curl_slist_append(headers, agent_header.c_str()); headers = curl_slist_append(headers, batch_header.c_str()); headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(handle, CURLOPT_URL, https_url.c_str()); curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload.data()); curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(payload.size()));
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, timeout_seconds_); curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout_seconds_);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, capture_bounded_response); curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink);
    const auto code = curl_easy_perform(handle); long status{}; curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers); curl_easy_cleanup(handle);
    if (code != CURLE_OK) return transport_outcome::retryable;
    if (status == 200L && sink.contents.find("\"batch_id\":\"" + request_batch_id + "\"") != std::string::npos)
        return transport_outcome::acknowledged;
    if (status == 401L || status == 403L) return transport_outcome::authentication_failed;
    return status == 429L || status >= 500L ? transport_outcome::retryable : transport_outcome::rejected;
#endif
}

result<enrolled_identity> curl_https_client::enroll(const std::string& manager_url, const std::string& agent_id,
                                                     const std::string& host_id, const std::string& bootstrap_token) const {
    if (manager_url.rfind("https://", 0U) != 0U || !is_valid_identifier(agent_id) || !is_valid_identifier(host_id) ||
        bootstrap_token.empty() || bootstrap_token.size() > 512U || timeout_seconds_ <= 0L) {
        return error{error_code::invalid_input, "enrollment input is invalid"};
    }
#ifndef PANOPTICON_HAVE_CURL
    return error{error_code::unsupported_action, "HTTPS enrollment requires libcurl"};
#else
    if (!initialize_curl()) return error{error_code::io_failure, "cannot initialize HTTPS client"};
    CURL* handle = curl_easy_init();
    if (handle == nullptr) return error{error_code::io_failure, "cannot allocate HTTPS client"};
    response_sink sink{maximum_response_bytes_, {}};
    const auto body = "{\"agent_id\":\"" + agent_id + "\",\"host_id\":\"" + host_id + "\"}";
    const auto endpoint = without_trailing_slash(manager_url) + "/api/v1/agents/enroll";
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const auto enrollment_header = "X-Panopticon-Enrollment-Token: " + bootstrap_token;
    headers = curl_slist_append(headers, enrollment_header.c_str());
    curl_easy_setopt(handle, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, timeout_seconds_); curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout_seconds_);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, capture_bounded_response); curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink);
    const auto code = curl_easy_perform(handle); long status{}; curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers); curl_easy_cleanup(handle);
    if (code != CURLE_OK) return error{error_code::io_failure, "enrollment transport failure"};
    if (status == 401L || status == 403L) return error{error_code::target_mismatch, "enrollment credential rejected"};
    if (status != 200L) return error{error_code::io_failure, "enrollment service rejected request"};
    const auto returned_agent = json_string_value(sink.contents, "agent_id");
    const auto access_token = json_string_value(sink.contents, "access_token");
    if (returned_agent != agent_id || access_token.empty() || access_token.size() > 512U) {
        return error{error_code::corrupt_data, "enrollment response is malformed"};
    }
    return enrolled_identity{agent_id, host_id, access_token};
#endif
}

result<std::string> curl_https_client::poll_commands(const std::string& manager_url,
                                                      const enrolled_identity& identity) const {
    if (manager_url.rfind("https://", 0U) != 0U || !is_valid_identifier(identity.agent_id) ||
        identity.bearer_token.empty() || identity.bearer_token.size() > 512U || timeout_seconds_ <= 0L) {
        return error{error_code::invalid_input, "command polling input is invalid"};
    }
#ifndef PANOPTICON_HAVE_CURL
    return error{error_code::unsupported_action, "HTTPS command polling requires libcurl"};
#else
    if (!initialize_curl()) return error{error_code::io_failure, "cannot initialize HTTPS client"};
    CURL* handle = curl_easy_init();
    if (handle == nullptr) return error{error_code::io_failure, "cannot allocate HTTPS client"};
    response_sink sink{maximum_response_bytes_, {}};
    const auto endpoint = without_trailing_slash(manager_url) + "/api/v1/agents/" + identity.agent_id + "/commands";
    curl_slist* headers = nullptr;
    const auto auth_header = "Authorization: Bearer " + identity.bearer_token;
    headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(handle, CURLOPT_URL, endpoint.c_str()); curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L); curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, timeout_seconds_); curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout_seconds_);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, capture_bounded_response); curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink);
    const auto code = curl_easy_perform(handle); long status{}; curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers); curl_easy_cleanup(handle);
    if (code != CURLE_OK) return error{error_code::io_failure, "command poll transport failure"};
    if (status == 401L || status == 403L) return error{error_code::target_mismatch, "command poll authentication rejected"};
    if (status != 200L || sink.contents.size() > maximum_response_bytes_) return error{error_code::io_failure, "command poll service rejected request"};
    return sink.contents;
#endif
}

transport_outcome curl_https_client::submit_command_result(const std::string& manager_url,
                                                            const enrolled_identity& identity,
                                                            const std::string& payload) const {
    if (manager_url.rfind("https://", 0U) != 0U || !is_valid_identifier(identity.agent_id) ||
        identity.bearer_token.empty() || payload.empty() || payload.size() > maximum_response_bytes_ || timeout_seconds_ <= 0L) {
        return transport_outcome::rejected;
    }
#ifndef PANOPTICON_HAVE_CURL
    return transport_outcome::retryable;
#else
    if (!initialize_curl()) return transport_outcome::retryable;
    CURL* handle = curl_easy_init(); if (handle == nullptr) return transport_outcome::retryable;
    response_sink sink{maximum_response_bytes_, {}};
    const auto endpoint = without_trailing_slash(manager_url) + "/api/v1/agents/" + identity.agent_id + "/command-results";
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const auto auth_header = "Authorization: Bearer " + identity.bearer_token;
    headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(handle, CURLOPT_URL, endpoint.c_str()); curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload.data()); curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(payload.size()));
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, timeout_seconds_); curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout_seconds_);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, capture_bounded_response); curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink);
    const auto code = curl_easy_perform(handle); long status{}; curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers); curl_easy_cleanup(handle);
    if (code != CURLE_OK) return transport_outcome::retryable;
    if (status == 200L && sink.contents.find("\"accepted\":true") != std::string::npos) return transport_outcome::acknowledged;
    if (status == 401L || status == 403L) return transport_outcome::authentication_failed;
    return status == 429L || status >= 500L ? transport_outcome::retryable : transport_outcome::rejected;
#endif
}

result<std::size_t> drain_spool(durable_spool& spool, https_client& client, const std::string& https_url,
                                const enrolled_identity& identity, const std::size_t maximum_records,
                                const std::size_t maximum_batch_bytes) {
    if (https_url.rfind("https://", 0U) != 0U || maximum_records == 0U || maximum_batch_bytes == 0U || !is_valid_identifier(identity.agent_id))
        return error{error_code::invalid_input, "transport requires HTTPS, an enrolled identity, and a positive limit"};
    const auto entries = spool.pending();
    if (!succeeded(entries)) return std::get<error>(entries);
    std::size_t drained{};
    const auto& pending = std::get<std::vector<std::filesystem::path>>(entries);
    std::size_t next{};
    while (next < pending.size() && drained < maximum_records) {
        std::vector<std::filesystem::path> batch_entries;
        std::string batch_payload;
        while (next < pending.size() && batch_entries.size() < maximum_records - drained) {
            const auto& entry = pending[next];
            const auto payload = spool.read(entry);
            if (!succeeded(payload)) return std::get<error>(payload);
            auto record = std::get<std::string>(payload);
            if (record.empty() || record.size() > maximum_batch_bytes ||
                batch_payload.size() > maximum_batch_bytes - record.size() - (record.back() == '\n' ? 0U : 1U)) {
                if (batch_entries.empty()) return error{error_code::resource_limit, "spool record exceeds transport batch limit"};
                break;
            }
            batch_payload += record;
            if (batch_payload.back() != '\n') batch_payload.push_back('\n');
            batch_entries.push_back(entry);
            ++next;
        }
        const auto outcome = client.post_ndjson(https_url, identity, batch_payload);
        if (outcome != transport_outcome::acknowledged) break;
        for (const auto& entry : batch_entries) {
            const auto acknowledged = spool.acknowledge(entry);
            if (!succeeded(acknowledged)) return std::get<error>(acknowledged);
            ++drained;
        }
    }
    return drained;
}
}  // namespace panopticon::linux_agent
