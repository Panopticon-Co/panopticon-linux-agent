#pragma once

#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/sensor/wal.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Outcome of one HTTP exchange, as the transport saw it.
enum class post_status {
    answered,       // HTTP 200 with a body to interpret
    retry,          // network failure, 429 or 5xx: nothing is known about the batch
    unauthorized,   // 401 or 403: the Manager refused this identity
    refused,        // any other non-200: the Manager will not take this batch as sent
};

struct post_response {
    post_status status{post_status::retry};
    long http_status{};
    std::string body;
    std::string detail;
};

// The seam between delivery logic and the network, so the logic is tested without a socket.
class record_poster {
public:
    virtual ~record_poster() = default;
    [[nodiscard]] virtual post_response post(const std::string& batch_id, std::string_view ndjson) = 0;
};

struct uplink_options {
    std::size_t maximum_records{500U};
    std::size_t maximum_bytes{2U * 1024U * 1024U};
    std::uint64_t idle_poll_ns{500'000'000ULL};
    std::uint64_t initial_backoff_ns{1'000'000'000ULL};
    std::uint64_t maximum_backoff_ns{60'000'000'000ULL};
    // Records the Manager rejects one by one (it answers that this exact record can never be valid)
    // are written here, counted, and skipped so that one bad record cannot stop delivery of
    // everything behind it. Empty: they are counted and skipped without a copy.
    std::filesystem::path quarantine_path;
    std::uint64_t quarantine_limit_bytes{4ULL * 1024U * 1024U};
};

enum class uplink_state { idle, delivering, backing_off, unauthorized, rejected };
[[nodiscard]] const char* to_string(uplink_state state) noexcept;

struct uplink_metrics {
    uplink_state state{uplink_state::idle};
    std::uint64_t batches_sent{};
    std::uint64_t records_acknowledged{};
    std::uint64_t retries{};
    std::uint64_t refusals{};
    std::uint64_t records_quarantined{};
    std::uint64_t quarantine_failures{};  // quarantined records that could not be copied to disk
    std::uint64_t consecutive_failures{};
    std::uint64_t acknowledged_seq{};
    std::string last_error;
};

// Delivers durable WAL records to the Manager and advances the WAL's acknowledged cursor only
// when the Manager has said, in a response that matches the batch, that every record in it is
// stored. Everything else (timeouts, refusals, a response that disagrees with what was sent)
// leaves the cursor where it was, so the records are sent again.
class uplink {
public:
    uplink(write_ahead_log& log, record_poster& poster, uplink_options options);

    // One delivery attempt. Returns how long the caller should wait before the next call
    // (0 means there may be more to send right now).
    [[nodiscard]] std::uint64_t step(std::uint64_t now_ns);
    [[nodiscard]] uplink_metrics metrics() const;

private:
    [[nodiscard]] std::uint64_t fail(std::uint64_t now_ns, uplink_state state, std::string error);
    struct verdict {
        bool accepted{false};
        std::vector<std::size_t> rejected_lines;  // 1-based positions inside the batch
        std::vector<std::string> rejected_reasons;
        std::string why;
    };
    [[nodiscard]] verdict check_response(const post_response& response, const std::string& batch_id, std::size_t sent) const;
    void quarantine(const std::vector<wal_record>& records, const verdict& outcome);

    write_ahead_log& log_;
    record_poster& poster_;
    uplink_options options_;
    mutable std::mutex mutex_;
    uplink_metrics metrics_;
    std::uint64_t next_attempt_ns_{};
    std::uint64_t backoff_ns_{};
    std::size_t record_budget_;
    std::uint64_t jitter_state_{0x9E3779B97F4A7C15ULL};
};

// Runs uplink::step on its own thread until stopped.
class uplink_runner {
public:
    explicit uplink_runner(uplink& target) : target_{target} {}
    ~uplink_runner();
    uplink_runner(const uplink_runner&) = delete;
    uplink_runner& operator=(const uplink_runner&) = delete;
    void start();
    void stop();

private:
    void run();
    uplink& target_;
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_{false};
};

// HTTPS poster for POST /api/v2/linux-endpoint/records. TLS verification is always on; a private
// CA is supplied with `ca_bundle` and nothing can turn verification off.
struct https_poster_options {
    std::string manager_url;
    enrolled_identity identity;
    std::filesystem::path ca_bundle;  // empty: the system trust store
    long timeout_seconds{20L};
    std::size_t maximum_response_bytes{256U * 1024U};
};
[[nodiscard]] std::unique_ptr<record_poster> make_https_poster(https_poster_options options);
[[nodiscard]] bool https_poster_built() noexcept;

}  // namespace panopticon::linux_agent::sensor
