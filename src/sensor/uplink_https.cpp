#include "panopticon/linux_agent/sensor/uplink.hpp"

#include <mutex>

#ifdef PANOPTICON_HAVE_CURL
#include <curl/curl.h>
#endif

namespace panopticon::linux_agent::sensor {
namespace {

#ifdef PANOPTICON_HAVE_CURL

std::once_flag curl_once;
bool curl_ready{};

struct response_buffer {
    std::size_t limit{};
    std::string contents;
};

std::size_t capture(char* data, const std::size_t size, const std::size_t count, void* context) {
    auto* buffer = static_cast<response_buffer*>(context);
    const auto bytes = size * count;
    if (bytes > buffer->limit - buffer->contents.size()) return 0U;  // aborts the transfer
    buffer->contents.append(data, bytes);
    return bytes;
}

class https_poster final : public record_poster {
public:
    explicit https_poster(https_poster_options options) : options_{std::move(options)} {
        while (options_.manager_url.size() > 8U && options_.manager_url.back() == '/') options_.manager_url.pop_back();
        endpoint_ = options_.manager_url + "/api/v2/linux-endpoint/records";
    }
    ~https_poster() override {
        if (handle_ != nullptr) curl_easy_cleanup(handle_);
    }
    https_poster(const https_poster&) = delete;
    https_poster& operator=(const https_poster&) = delete;

    post_response post(const std::string& batch_id, const std::string_view ndjson) override {
        post_response result;
        if (options_.manager_url.rfind("https://", 0U) != 0U || options_.identity.bearer_token.empty() || ndjson.empty()) {
            result.status = post_status::refused;
            result.detail = "manager_url must be https:// and an enrolled identity is required";
            return result;
        }
        std::call_once(curl_once, [] { curl_ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
        if (!curl_ready) {
            result.detail = "cannot initialise libcurl";
            return result;
        }
        // One handle for the life of the poster, so that libcurl keeps the TLS connection alive between
        // batches. A handle per request cost a TCP and TLS handshake for every batch, one to a few records
        // each while the machine is quiet (measured: 728 connections in 4 minutes, libcrypto 13% of the
        // sensor CPU). Options are set on every request; the connection cache survives that.
        const std::lock_guard<std::mutex> lock{mutex_};
        if (handle_ == nullptr) handle_ = curl_easy_init();
        CURL* handle = handle_;
        if (handle == nullptr) {
            result.detail = "cannot allocate an HTTPS handle";
            return result;
        }
        response_buffer buffer{options_.maximum_response_bytes, {}};
        curl_slist* headers = nullptr;
        const auto agent_header = "X-Panopticon-Agent-Id: " + options_.identity.agent_id;
        const auto batch_header = "X-Panopticon-Batch-Id: " + batch_id;
        const auto auth_header = "Authorization: Bearer " + options_.identity.bearer_token;
        headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
        headers = curl_slist_append(headers, "X-Panopticon-Protocol: linux-endpoint/1.0");
        headers = curl_slist_append(headers, agent_header.c_str());
        headers = curl_slist_append(headers, batch_header.c_str());
        headers = curl_slist_append(headers, auth_header.c_str());
        curl_easy_setopt(handle, CURLOPT_URL, endpoint_.c_str());
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ndjson.data());
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(ndjson.size()));
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
        if (!options_.ca_bundle.empty()) curl_easy_setopt(handle, CURLOPT_CAINFO, options_.ca_bundle.c_str());
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, options_.timeout_seconds);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, options_.timeout_seconds);
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPINTVL, 15L);
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, capture);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &buffer);
        const auto code = curl_easy_perform(handle);
        long status = 0;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
        curl_slist_free_all(headers);

        result.http_status = status;
        if (code != CURLE_OK) {
            // Start the next attempt from a clean handle and a new connection.
            curl_easy_cleanup(handle_);
            handle_ = nullptr;
            result.status = post_status::retry;
            result.detail = std::string{"transport: "} + curl_easy_strerror(code);
            return result;
        }
        result.body = std::move(buffer.contents);
        if (status == 200L) result.status = post_status::answered;
        else if (status == 401L || status == 403L) result.status = post_status::unauthorized;
        else if (status == 429L || status >= 500L) {
            result.status = post_status::retry;
            result.detail = "Manager answered HTTP " + std::to_string(status);
        } else {
            result.status = post_status::refused;
            result.detail = "Manager answered HTTP " + std::to_string(status);
        }
        return result;
    }

private:
    https_poster_options options_;
    std::string endpoint_;
    std::mutex mutex_;
    CURL* handle_{nullptr};
};

#else

class unavailable_poster final : public record_poster {
public:
    post_response post(const std::string&, std::string_view) override {
        post_response result;
        result.status = post_status::refused;
        result.detail = "this build has no libcurl; HTTPS delivery is unavailable";
        return result;
    }
};

#endif

}  // namespace

std::unique_ptr<record_poster> make_https_poster([[maybe_unused]] https_poster_options options) {
#ifdef PANOPTICON_HAVE_CURL
    return std::make_unique<https_poster>(std::move(options));
#else
    return std::make_unique<unavailable_poster>();
#endif
}

bool https_poster_built() noexcept {
#ifdef PANOPTICON_HAVE_CURL
    return true;
#else
    return false;
#endif
}

}  // namespace panopticon::linux_agent::sensor
