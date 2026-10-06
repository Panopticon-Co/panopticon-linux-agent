#include "panopticon/linux_agent/sensor/uplink.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <algorithm>
#include <chrono>

namespace panopticon::linux_agent::sensor {

const char* to_string(const uplink_state state) noexcept {
    switch (state) {
        case uplink_state::idle: return "idle";
        case uplink_state::delivering: return "delivering";
        case uplink_state::backing_off: return "backing_off";
        case uplink_state::unauthorized: return "unauthorized";
        case uplink_state::rejected: return "rejected";
    }
    return "unknown";
}

uplink::uplink(write_ahead_log& log, record_poster& poster, uplink_options options)
    : log_{log}, poster_{poster}, options_{options}, record_budget_{std::max<std::size_t>(1U, options.maximum_records)} {
    metrics_.acknowledged_seq = log_.metrics().acknowledged_seq;
}

uplink_metrics uplink::metrics() const {
    const std::lock_guard<std::mutex> lock{mutex_};
    return metrics_;
}

std::uint64_t uplink::fail(const std::uint64_t now_ns, const uplink_state state, std::string error) {
    backoff_ns_ = backoff_ns_ == 0U ? options_.initial_backoff_ns : std::min(options_.maximum_backoff_ns, backoff_ns_ * 2U);
    if (state == uplink_state::unauthorized) backoff_ns_ = options_.maximum_backoff_ns;
    // Jitter in [50%, 100%] of the backoff so a fleet that lost the Manager together does not come
    // back together.
    jitter_state_ ^= jitter_state_ << 13U;
    jitter_state_ ^= jitter_state_ >> 7U;
    jitter_state_ ^= jitter_state_ << 17U;
    const auto delay = backoff_ns_ / 2U + jitter_state_ % (backoff_ns_ / 2U + 1U);
    next_attempt_ns_ = now_ns + delay;
    const std::lock_guard<std::mutex> lock{mutex_};
    metrics_.state = state;
    ++metrics_.consecutive_failures;
    metrics_.last_error = std::move(error);
    return delay;
}

bool uplink::response_matches(const post_response& response, const std::string& batch_id, const std::size_t sent,
                              std::string& why) const {
    json_limits limits;
    limits.maximum_bytes = 256U * 1024U;
    limits.maximum_depth = 8U;
    limits.maximum_values = 20'000U;
    std::string parse_error;
    const auto document = parse_json(response.body, limits, &parse_error);
    if (!document || !document->is_object()) {
        why = "acknowledgement is not a JSON object: " + parse_error;
        return false;
    }
    const auto* echoed = document->find("batch_id");
    if (echoed == nullptr || echoed->as_string() != std::optional<std::string_view>{batch_id}) {
        why = "acknowledgement is for a different batch";
        return false;
    }
    const auto received = document->find("received");
    const auto accepted = document->find("accepted");
    const auto duplicates = document->find("duplicates");
    const auto rejected = document->find("rejected");
    if (received == nullptr || accepted == nullptr || duplicates == nullptr || rejected == nullptr ||
        !received->as_unsigned() || !accepted->as_unsigned() || !duplicates->as_unsigned() || !rejected->is_array()) {
        why = "acknowledgement lacks received, accepted, duplicates or rejected";
        return false;
    }
    if (!rejected->items().empty()) {
        why = "the Manager rejected " + std::to_string(rejected->items().size()) + " record(s)";
        const auto* reason = rejected->items().front().find("reason");
        const auto* detail = rejected->items().front().find("detail");
        if (reason != nullptr && reason->as_string()) why += ": " + std::string{*reason->as_string()};
        if (detail != nullptr && detail->as_string()) why += " (" + std::string{detail->as_string()->substr(0U, 200U)} + ")";
        return false;
    }
    if (*received->as_unsigned() != sent || *accepted->as_unsigned() + *duplicates->as_unsigned() != sent) {
        why = "acknowledgement does not account for every record sent";
        return false;
    }
    return true;
}

std::uint64_t uplink::step(const std::uint64_t now_ns) {
    if (now_ns < next_attempt_ns_) return next_attempt_ns_ - now_ns;

    const auto from = log_.metrics().acknowledged_seq + 1U;
    auto read = log_.read(from, record_budget_, options_.maximum_bytes);
    if (!succeeded(read)) return fail(now_ns, uplink_state::backing_off, "cannot read the write-ahead log");
    const auto& records = std::get<std::vector<wal_record>>(read);
    if (records.empty()) {
        const std::lock_guard<std::mutex> lock{mutex_};
        metrics_.state = uplink_state::idle;
        return options_.idle_poll_ns;
    }

    std::string payload;
    for (const auto& record : records) {
        payload += record.payload;
        payload += '\n';
    }
    const auto first = records.front().seq;
    const auto last = records.back().seq;
    const auto batch_id = "wal-" + std::to_string(first) + "-" + std::to_string(last);
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        metrics_.state = uplink_state::delivering;
        ++metrics_.batches_sent;
    }

    const auto response = poster_.post(batch_id, payload);
    switch (response.status) {
        case post_status::retry:
            {
                const std::lock_guard<std::mutex> lock{mutex_};
                ++metrics_.retries;
            }
            return fail(now_ns, uplink_state::backing_off, response.detail.empty() ? "delivery failed" : response.detail);
        case post_status::unauthorized:
            return fail(now_ns, uplink_state::unauthorized, "the Manager refused this agent's credentials");
        case post_status::refused:
            {
                const std::lock_guard<std::mutex> lock{mutex_};
                ++metrics_.refusals;
            }
            // A batch the Manager calls too large is retried smaller; anything else waits.
            if (response.http_status == 413 && record_budget_ > 1U) record_budget_ = std::max<std::size_t>(1U, record_budget_ / 2U);
            return fail(now_ns, uplink_state::rejected, "the Manager refused the batch (HTTP " + std::to_string(response.http_status) + ")");
        case post_status::answered:
            break;
    }

    std::string why;
    if (!response_matches(response, batch_id, records.size(), why)) {
        {
            const std::lock_guard<std::mutex> lock{mutex_};
            ++metrics_.refusals;
        }
        return fail(now_ns, uplink_state::rejected, std::move(why));
    }
    if (auto acknowledged = log_.acknowledge(last); !succeeded(acknowledged)) {
        return fail(now_ns, uplink_state::backing_off, "cannot record the acknowledgement in the write-ahead log");
    }
    backoff_ns_ = 0U;
    next_attempt_ns_ = 0U;
    record_budget_ = std::min(options_.maximum_records, record_budget_ * 2U);
    const std::lock_guard<std::mutex> lock{mutex_};
    metrics_.state = uplink_state::idle;
    metrics_.consecutive_failures = 0U;
    metrics_.records_acknowledged += records.size();
    metrics_.acknowledged_seq = last;
    metrics_.last_error.clear();
    return 0U;
}

uplink_runner::~uplink_runner() { stop(); }

void uplink_runner::start() {
    const std::lock_guard<std::mutex> lock{mutex_};
    if (thread_.joinable()) return;
    stopping_ = false;
    thread_ = std::thread{[this] { run(); }};
}

void uplink_runner::stop() {
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        stopping_ = true;
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void uplink_runner::run() {
    for (;;) {
        const auto delay = target_.step(clock_domain::now_monotonic_ns());
        std::unique_lock<std::mutex> lock{mutex_};
        if (stopping_) return;
        if (delay == 0U) continue;
        wake_.wait_for(lock, std::chrono::nanoseconds{delay}, [this] { return stopping_; });
        if (stopping_) return;
    }
}

}  // namespace panopticon::linux_agent::sensor
