#include "panopticon/linux_agent/sensor/uplink.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>

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

uplink::verdict uplink::check_response(const post_response& response, const std::string& batch_id, const std::size_t sent) const {
    verdict outcome;
    json_limits limits;
    limits.maximum_bytes = 256U * 1024U;
    limits.maximum_depth = 8U;
    limits.maximum_values = 20'000U;
    std::string parse_error;
    const auto document = parse_json(response.body, limits, &parse_error);
    if (!document || !document->is_object()) {
        outcome.why = "acknowledgement is not a JSON object: " + parse_error;
        return outcome;
    }
    const auto* echoed = document->find("batch_id");
    if (echoed == nullptr || echoed->as_string() != std::optional<std::string_view>{batch_id}) {
        outcome.why = "acknowledgement is for a different batch";
        return outcome;
    }
    const auto received = document->find("received");
    const auto accepted = document->find("accepted");
    const auto duplicates = document->find("duplicates");
    const auto rejected = document->find("rejected");
    if (received == nullptr || accepted == nullptr || duplicates == nullptr || rejected == nullptr ||
        !received->as_unsigned() || !accepted->as_unsigned() || !duplicates->as_unsigned() || !rejected->is_array()) {
        outcome.why = "acknowledgement lacks received, accepted, duplicates or rejected";
        return outcome;
    }
    // Every record sent must be accounted for exactly once: stored, already stored, or rejected
    // at a named position. Anything else is not an acknowledgement.
    std::vector<bool> seen(sent + 1U, false);
    for (const auto& entry : rejected->items()) {
        const auto* line = entry.find("line");
        const auto* reason = entry.find("reason");
        const auto* detail = entry.find("detail");
        const auto position = line == nullptr ? std::nullopt : line->as_unsigned();
        if (!position || *position < 1U || *position > sent || seen[*position]) {
            outcome.why = "the Manager rejected a record without naming a valid line";
            outcome.rejected_lines.clear();
            outcome.rejected_reasons.clear();
            return outcome;
        }
        seen[*position] = true;
        outcome.rejected_lines.push_back(static_cast<std::size_t>(*position));
        std::string text = reason != nullptr && reason->as_string() ? std::string{*reason->as_string()} : std::string{"rejected"};
        if (detail != nullptr && detail->as_string()) text += " (" + std::string{detail->as_string()->substr(0U, 200U)} + ")";
        outcome.rejected_reasons.push_back(std::move(text));
    }
    if (*received->as_unsigned() != sent || *accepted->as_unsigned() + *duplicates->as_unsigned() + outcome.rejected_lines.size() != sent) {
        outcome.why = "acknowledgement does not account for every record sent";
        if (!outcome.rejected_reasons.empty()) outcome.why += "; the Manager reported: " + outcome.rejected_reasons.front();
        outcome.rejected_lines.clear();
        outcome.rejected_reasons.clear();
        return outcome;
    }
    outcome.accepted = true;
    return outcome;
}

namespace {

std::string json_escaped(const std::string_view text) {
    std::string out;
    for (const unsigned char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20U) {
            char buffer[8];
            std::snprintf(buffer, sizeof buffer, "\\u%04x", c);
            out += buffer;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

}  // namespace

void uplink::quarantine(const std::vector<wal_record>& records, const verdict& outcome) {
    std::uint64_t failures = 0U;
    for (std::size_t index = 0U; index < outcome.rejected_lines.size(); ++index) {
        const auto& record = records[outcome.rejected_lines[index] - 1U];
        bool written = false;
        if (!options_.quarantine_path.empty()) {
            std::error_code ignored;
            const auto size = std::filesystem::exists(options_.quarantine_path, ignored) ? std::filesystem::file_size(options_.quarantine_path, ignored) : 0U;
            if (size + record.payload.size() + 512U <= options_.quarantine_limit_bytes) {
                if (std::FILE* file = std::fopen(options_.quarantine_path.c_str(), "ae"); file != nullptr) {
                    const auto line = "{\"seq\":" + std::to_string(record.seq) + ",\"reason\":\"" + json_escaped(outcome.rejected_reasons[index]) +
                                      "\",\"record\":\"" + json_escaped(record.payload) + "\"}\n";
                    written = std::fwrite(line.data(), 1U, line.size(), file) == line.size();
                    written = std::fclose(file) == 0 && written;
                }
            }
        }
        if (!written && !options_.quarantine_path.empty()) ++failures;
    }
    const std::lock_guard<std::mutex> lock{mutex_};
    metrics_.records_quarantined += outcome.rejected_lines.size();
    for (const auto line : outcome.rejected_lines) {
        metrics_.recent_quarantined_seqs.push_back(records[line - 1U].seq);
        if (metrics_.recent_quarantined_seqs.size() > 16U) metrics_.recent_quarantined_seqs.erase(metrics_.recent_quarantined_seqs.begin());
    }
    metrics_.quarantine_failures += failures;
    if (!outcome.rejected_reasons.empty()) metrics_.last_error = "quarantined: " + outcome.rejected_reasons.front();
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

    auto verdict = check_response(response, batch_id, records.size());
    if (!verdict.accepted) {
        {
            const std::lock_guard<std::mutex> lock{mutex_};
            ++metrics_.refusals;
        }
        return fail(now_ns, uplink_state::rejected, std::move(verdict.why));
    }
    if (!verdict.rejected_lines.empty()) quarantine(records, verdict);
    if (auto acknowledged = log_.acknowledge(last); !succeeded(acknowledged)) {
        return fail(now_ns, uplink_state::backing_off, "cannot record the acknowledgement in the write-ahead log");
    }
    backoff_ns_ = 0U;
    next_attempt_ns_ = 0U;
    record_budget_ = std::min(options_.maximum_records, record_budget_ * 2U);
    const std::lock_guard<std::mutex> lock{mutex_};
    metrics_.state = uplink_state::idle;
    metrics_.consecutive_failures = 0U;
    metrics_.records_acknowledged += records.size() - verdict.rejected_lines.size();
    metrics_.acknowledged_seq = last;
    if (verdict.rejected_lines.empty()) metrics_.last_error.clear();
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
