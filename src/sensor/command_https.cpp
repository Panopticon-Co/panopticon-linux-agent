#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"

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

class https_command_transport final : public command_transport {
public:
    explicit https_command_transport(https_poster_options options) : options_{std::move(options)} {
        while (options_.manager_url.size() > 8U && options_.manager_url.back() == '/') options_.manager_url.pop_back();
        base_ = options_.manager_url + "/api/v1/agents/" + options_.identity.agent_id;
    }
    ~https_command_transport() override {
        if (handle_ != nullptr) curl_easy_cleanup(handle_);
    }
    https_command_transport(const https_command_transport&) = delete;
    https_command_transport& operator=(const https_command_transport&) = delete;

    post_response poll() override { return exchange(false, base_ + "/commands?delivery_mode=durable", {}); }

    post_response accept(const std::string& command_id) override {
        if (!is_valid_identifier(command_id)) return refused("the command id is not a valid identifier");
        return exchange(true, base_ + "/commands/" + command_id + "/accept", {});
    }

    post_response submit(const std::string& result_json) override {
        if (result_json.empty()) return refused("there is no result to send");
        return exchange(true, base_ + "/command-results", result_json);
    }

private:
    static post_response refused(std::string why) {
        post_response result;
        result.status = post_status::refused;
        result.detail = std::move(why);
        return result;
    }

    post_response exchange(const bool post, const std::string& url, const std::string& body) {
        if (options_.manager_url.rfind("https://", 0U) != 0U || options_.identity.bearer_token.empty() ||
            !is_valid_identifier(options_.identity.agent_id)) {
            return refused("manager_url must be https:// and an enrolled identity is required");
        }
        post_response result;
        std::call_once(curl_once, [] { curl_ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
        if (!curl_ready) {
            result.detail = "cannot initialise libcurl";
            return result;
        }
        // One handle for the life of the transport: the poll runs every few seconds and each answer adds an accept
        // and a result, so a handle per request meant a TLS handshake each time. Options are set on every request.
        const std::lock_guard<std::mutex> lock{mutex_};
        if (handle_ == nullptr) handle_ = curl_easy_init();
        CURL* handle = handle_;
        if (handle == nullptr) {
            result.detail = "cannot allocate an HTTPS handle";
            return result;
        }
        response_buffer buffer{options_.maximum_response_bytes, {}};
        curl_slist* headers = nullptr;
        const auto auth_header = "Authorization: Bearer " + options_.identity.bearer_token;
        headers = curl_slist_append(headers, auth_header.c_str());
        headers = curl_slist_append(headers, "Accept: application/json");
        if (post) headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
        if (post) {
            curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.data());
            curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
        } else {
            curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
        }
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
        if (code != CURLE_OK) {
            // A failed transfer may leave the connection in an unknown state: start the next request clean.
            curl_easy_cleanup(handle_);
            handle_ = nullptr;
        }

        result.http_status = status;
        if (code != CURLE_OK) {
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

    https_poster_options options_;
    std::string base_;
    std::mutex mutex_;
    CURL* handle_{nullptr};
};

#else

class unavailable_transport final : public command_transport {
public:
    post_response poll() override { return reply(); }
    post_response accept(const std::string&) override { return reply(); }
    post_response submit(const std::string&) override { return reply(); }

private:
    static post_response reply() {
        post_response result;
        result.status = post_status::refused;
        result.detail = "this build has no libcurl; the command channel is unavailable";
        return result;
    }
};

#endif

}  // namespace

std::unique_ptr<command_transport> make_https_command_transport([[maybe_unused]] https_poster_options options) {
#ifdef PANOPTICON_HAVE_CURL
    return std::make_unique<https_command_transport>(std::move(options));
#else
    return std::make_unique<unavailable_transport>();
#endif
}

}  // namespace panopticon::linux_agent::sensor
