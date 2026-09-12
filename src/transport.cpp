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
