#include "panopticon/linux_agent/sensor/uplink.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <deque>
#include <exception>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

template <typename value_type>
value_type value_of(result<value_type> outcome, const char* what) {
    if (!succeeded(outcome)) throw std::runtime_error{std::string{what} + ": " + std::get<error>(outcome).message};
    return std::get<value_type>(std::move(outcome));
}

fs::path fresh_directory(const char* name) {
    const auto path = fs::temp_directory_path() / ("panopticon-uplink-" + std::string{name} + "-" + std::to_string(::getpid()));
    fs::remove_all(path);
    return path;
}

std::unique_ptr<write_ahead_log> open_log(const fs::path& directory) {
    wal_options options;
    options.directory = directory;
    options.segment_bytes = 1U << 20U;
    options.quota_bytes = 8U << 20U;
    options.maximum_record_bytes = 4096U;
    return value_of(write_ahead_log::open(options), "open wal");
}

void fill(write_ahead_log& log, const std::uint64_t first, const std::uint64_t last) {
    for (auto seq = first; seq <= last; ++seq) value_of(log.append(seq, "{\"seq\":" + std::to_string(seq) + "}"), "append");
    value_of(log.sync(0U, true), "sync");
}

std::size_t line_count(const std::string_view text) {
    std::size_t count = 0U;
    for (const char c : text) count += c == '\n' ? 1U : 0U;
    return count;
}

std::string ack_body(const std::string& batch_id, const std::size_t received, const std::size_t accepted, const std::size_t duplicates,
                     const std::string& rejected = "[]") {
    return "{\"batch_id\":\"" + batch_id + "\",\"received\":" + std::to_string(received) + ",\"accepted\":" + std::to_string(accepted) +
           ",\"duplicates\":" + std::to_string(duplicates) + ",\"rejected\":" + rejected + ",\"streams\":[]}";
}

// A Manager that follows a script, then stores everything it is sent.
class scripted_poster final : public record_poster {
public:
    std::deque<post_response> script;  // consumed first, one entry per post
    std::vector<std::string> payloads;
    std::vector<std::string> batch_ids;
    std::set<std::string> stored;  // lines the "Manager" holds

    post_response post(const std::string& batch_id, const std::string_view ndjson) override {
        payloads.emplace_back(ndjson);
        batch_ids.push_back(batch_id);
        if (!script.empty()) {
            auto response = script.front();
            script.pop_front();
            return response;
        }
        std::size_t accepted = 0U, duplicates = 0U;
        std::size_t begin = 0U;
        while (begin < ndjson.size()) {
            const auto end = ndjson.find('\n', begin);
            const std::string line{ndjson.substr(begin, end - begin)};
            if (stored.insert(line).second) ++accepted;
            else ++duplicates;
            begin = end + 1U;
        }
        post_response response;
        response.status = post_status::answered;
        response.http_status = 200;
        response.body = ack_body(batch_id, accepted + duplicates, accepted, duplicates);
        return response;
    }
};

post_response network_failure() {
    post_response response;
    response.status = post_status::retry;
    response.detail = "transport: could not connect";
    return response;
}

post_response answer(const std::string& body) {
    post_response response;
    response.status = post_status::answered;
    response.http_status = 200;
    response.body = body;
    return response;
}

constexpr std::uint64_t second = 1'000'000'000ULL;

void test_delivers_and_acknowledges_only_after_a_matching_answer() {
    const auto directory = fresh_directory("deliver");
    auto log = open_log(directory);
    fill(*log, 1U, 5U);
    scripted_poster poster;
    uplink delivery{*log, poster, uplink_options{}};
    require(delivery.step(1U) == 0U, "a delivered batch asks to continue at once");
    require(poster.payloads.size() == 1U && line_count(poster.payloads[0]) == 5U, "five lines in one batch");
    require(poster.batch_ids[0] == "wal-1-5", "batch id names the sequence range");
    require(log->metrics().acknowledged_seq == 5U, "cursor advanced");
    require(delivery.step(2U) > 0U && poster.payloads.size() == 1U, "nothing left: idle without posting");
    const auto metrics = delivery.metrics();
    require(metrics.state == uplink_state::idle && metrics.records_acknowledged == 5U && metrics.acknowledged_seq == 5U, "metrics");
    fs::remove_all(directory);
}

void test_unsynced_records_are_not_sent() {
    const auto directory = fresh_directory("unsynced");
    auto log = open_log(directory);
    value_of(log->append(1U, "{\"seq\":1}"), "append");
    scripted_poster poster;
    uplink delivery{*log, poster, uplink_options{}};
    (void)delivery.step(1U);
    require(poster.payloads.empty(), "a record that is not durable yet is never offered");
    fs::remove_all(directory);
}

void test_failures_keep_the_cursor_and_back_off() {
    const auto directory = fresh_directory("retry");
    auto log = open_log(directory);
    fill(*log, 1U, 3U);
    scripted_poster poster;
    poster.script = {network_failure(), network_failure(), network_failure()};
    uplink_options options;
    options.initial_backoff_ns = 1U * second;
    options.maximum_backoff_ns = 4U * second;
    uplink delivery{*log, poster, options};

    std::uint64_t now = 100U * second;
    auto delay = delivery.step(now);
    require(delay >= second / 2U && delay <= second, "first backoff is 0.5 to 1 s");
    require(log->metrics().acknowledged_seq == 0U, "cursor unchanged after a failure");
    require(delivery.step(now + 1U) == now + delay - (now + 1U), "no attempt before the backoff elapses");
    require(poster.payloads.size() == 1U, "and nothing was sent in the meantime");
    now += delay;
    delay = delivery.step(now);
    require(delay >= second && delay <= 2U * second, "second backoff doubles");
    now += delay;
    delay = delivery.step(now);
    require(delay >= 2U * second && delay <= 4U * second, "third backoff is capped by the maximum");
    require(delivery.metrics().state == uplink_state::backing_off && delivery.metrics().retries == 3U, "metrics report the outage");
    require(delivery.metrics().last_error.find("could not connect") != std::string::npos, "the reason is kept");
    now += delay;
    require(delivery.step(now) == 0U && log->metrics().acknowledged_seq == 3U, "recovers and delivers everything once the Manager answers");
    require(delivery.metrics().consecutive_failures == 0U && delivery.metrics().last_error.empty(), "failure state clears");
    fs::remove_all(directory);
}

void test_an_answer_that_does_not_match_is_never_an_acknowledgement() {
    const auto directory = fresh_directory("mismatch");
    auto log = open_log(directory);
    fill(*log, 1U, 4U);
    const std::string rejected_record = R"([{"line":2,"record_id":"abc","reason":"schema_invalid","detail":"/process: bad"}])";
    const std::vector<std::string> bad_answers{
        "",                                                                       // empty body
        "not json",                                                               // malformed
        "[]",                                                                     // not an object
        ack_body("wal-9-9", 4U, 4U, 0U),                                          // another batch
        ack_body("wal-1-4", 3U, 3U, 0U),                                          // fewer received than sent
        ack_body("wal-1-4", 4U, 3U, 0U),                                          // accepted + duplicates short of sent
        ack_body("wal-1-4", 4U, 2U, 0U, rejected_record),                         // the Manager rejected one
        R"({"batch_id":"wal-1-4","received":4,"accepted":4})",                    // missing fields
        R"({"batch_id":"wal-1-4","received":"4","accepted":4,"duplicates":0,"rejected":[]})",  // wrong type
        R"({"batch_id":"wal-1-4","received":4,"received":4,"accepted":4,"duplicates":0,"rejected":[]})",  // duplicate key
    };
    scripted_poster poster;
    uplink_options options;
    options.initial_backoff_ns = 1U;
    options.maximum_backoff_ns = 2U;
    uplink delivery{*log, poster, options};
    std::uint64_t now = second;
    for (const auto& body : bad_answers) {
        poster.script.push_back(answer(body));
        (void)delivery.step(now);
        require(log->metrics().acknowledged_seq == 0U, "cursor must not move on a bad answer");
        require(delivery.metrics().state == uplink_state::rejected, "the state says the Manager did not take the batch");
        now += second;
    }
    require(delivery.metrics().refusals == bad_answers.size(), "every bad answer counted");
    poster.script.push_back(answer(ack_body("wal-1-4", 4U, 2U, 0U, rejected_record)));
    (void)delivery.step(now);
    require(delivery.metrics().last_error.find("schema_invalid") != std::string::npos, "rejection reason is surfaced");
    now += second;
    require(delivery.step(now) == 0U && log->metrics().acknowledged_seq == 4U, "and a correct answer still works afterwards");
    fs::remove_all(directory);
}

void test_authentication_failure_waits_long_and_does_not_acknowledge() {
    const auto directory = fresh_directory("auth");
    auto log = open_log(directory);
    fill(*log, 1U, 2U);
    scripted_poster poster;
    post_response refused;
    refused.status = post_status::unauthorized;
    refused.http_status = 401;
    poster.script = {refused};
    uplink_options options;
    options.maximum_backoff_ns = 60U * second;
    uplink delivery{*log, poster, options};
    const auto delay = delivery.step(second);
    require(delay >= 30U * second, "an identity problem is not hammered");
    require(delivery.metrics().state == uplink_state::unauthorized && log->metrics().acknowledged_seq == 0U, "state and cursor");
    fs::remove_all(directory);
}

void test_too_large_batches_shrink_and_recover() {
    const auto directory = fresh_directory("large");
    auto log = open_log(directory);
    fill(*log, 1U, 64U);
    scripted_poster poster;
    post_response too_large;
    too_large.status = post_status::refused;
    too_large.http_status = 413;
    poster.script = {too_large, too_large};
    uplink_options options;
    options.maximum_records = 64U;
    options.initial_backoff_ns = 1U;
    options.maximum_backoff_ns = 2U;
    uplink delivery{*log, poster, options};
    std::uint64_t now = second;
    (void)delivery.step(now);
    now += second;
    (void)delivery.step(now);
    now += second;
    require(line_count(poster.payloads[0]) == 64U && line_count(poster.payloads[1]) == 32U, "the batch halves after a 413");
    (void)delivery.step(now);
    require(line_count(poster.payloads[2]) == 16U && log->metrics().acknowledged_seq == 16U, "and a smaller batch gets through");
    for (int round = 0; round < 10 && log->metrics().acknowledged_seq < 64U; ++round) (void)delivery.step(now += second);
    require(log->metrics().acknowledged_seq == 64U, "the rest follows, batches growing back");
    fs::remove_all(directory);
}

void test_a_lost_answer_means_the_batch_is_sent_again_and_deduplicated() {
    const auto directory = fresh_directory("lost");
    auto log = open_log(directory);
    fill(*log, 1U, 3U);
    scripted_poster poster;
    // The Manager stores the batch but the answer never arrives: the sender cannot know.
    post_response timed_out;
    timed_out.status = post_status::retry;
    timed_out.detail = "transport: timeout";
    poster.stored.insert("{\"seq\":1}");
    poster.stored.insert("{\"seq\":2}");
    poster.stored.insert("{\"seq\":3}");
    poster.script = {timed_out};
    uplink_options options;
    options.initial_backoff_ns = 1U;
    options.maximum_backoff_ns = 2U;
    uplink delivery{*log, poster, options};
    (void)delivery.step(second);
    require(log->metrics().acknowledged_seq == 0U, "no answer, no acknowledgement");
    (void)delivery.step(2U * second);
    require(poster.payloads.size() == 2U && poster.payloads[0] == poster.payloads[1], "the identical batch is resent");
    require(log->metrics().acknowledged_seq == 3U, "the duplicate answer acknowledges it");
    fs::remove_all(directory);
}

void test_delivery_resumes_after_a_restart() {
    const auto directory = fresh_directory("restart");
    scripted_poster poster;
    {
        auto log = open_log(directory);
        fill(*log, 1U, 8U);
        uplink_options options;
        options.maximum_records = 3U;
        uplink delivery{*log, poster, options};
        (void)delivery.step(second);  // seq 1-3 only
        require(log->metrics().acknowledged_seq == 3U, "three acknowledged");
    }
    auto log = open_log(directory);
    require(log->metrics().acknowledged_seq == 3U, "the cursor survived the restart");
    uplink delivery{*log, poster, uplink_options{}};
    require(delivery.metrics().acknowledged_seq == 3U, "and the uplink starts from it");
    (void)delivery.step(second);
    require(poster.payloads.size() == 2U && poster.payloads[1].rfind("{\"seq\":4}", 0U) == 0U, "resumes at record 4");
    require(log->metrics().acknowledged_seq == 8U && poster.stored.size() == 8U, "everything was delivered exactly once");
    fs::remove_all(directory);
}

void test_the_runner_delivers_while_the_log_is_being_written() {
    const auto directory = fresh_directory("runner");
    auto log = open_log(directory);
    scripted_poster poster;
    uplink_options options;
    options.idle_poll_ns = 1'000'000ULL;
    uplink delivery{*log, poster, options};
    uplink_runner runner{delivery};
    runner.start();
    constexpr std::uint64_t total = 3000U;
    for (std::uint64_t seq = 1U; seq <= total; ++seq) {
        value_of(log->append(log->next_seq(), "{\"seq\":" + std::to_string(seq) + "}"), "append");
        if (seq % 50U == 0U) value_of(log->sync(0U, true), "sync");
    }
    value_of(log->sync(0U, true), "final sync");
    for (int wait = 0; wait < 400 && log->metrics().acknowledged_seq < total; ++wait) std::this_thread::sleep_for(std::chrono::milliseconds{10});
    runner.stop();
    require(log->metrics().acknowledged_seq == total, "everything delivered and acknowledged");
    require(poster.stored.size() == total, "the Manager holds each record once");
    fs::remove_all(directory);
}

void test_a_stopped_runner_can_be_destroyed_without_start() {
    const auto directory = fresh_directory("norun");
    auto log = open_log(directory);
    scripted_poster poster;
    uplink delivery{*log, poster, uplink_options{}};
    { uplink_runner never_started{delivery}; }
    uplink_runner runner{delivery};
    runner.start();
    runner.start();
    runner.stop();
    runner.stop();
    fs::remove_all(directory);
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"delivers_and_acknowledges_only_after_a_matching_answer", test_delivers_and_acknowledges_only_after_a_matching_answer},
        {"unsynced_records_are_not_sent", test_unsynced_records_are_not_sent},
        {"failures_keep_the_cursor_and_back_off", test_failures_keep_the_cursor_and_back_off},
        {"an_answer_that_does_not_match_is_never_an_acknowledgement", test_an_answer_that_does_not_match_is_never_an_acknowledgement},
        {"authentication_failure_waits_long_and_does_not_acknowledge", test_authentication_failure_waits_long_and_does_not_acknowledge},
        {"too_large_batches_shrink_and_recover", test_too_large_batches_shrink_and_recover},
        {"a_lost_answer_means_the_batch_is_sent_again_and_deduplicated", test_a_lost_answer_means_the_batch_is_sent_again_and_deduplicated},
        {"delivery_resumes_after_a_restart", test_delivery_resumes_after_a_restart},
        {"the_runner_delivers_while_the_log_is_being_written", test_the_runner_delivers_while_the_log_is_being_written},
        {"a_stopped_runner_can_be_destroyed_without_start", test_a_stopped_runner_can_be_destroyed_without_start},
    };
    int failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::printf("PASS %s\n", test.name);
        } catch (const std::exception& error) {
            std::printf("FAIL %s: %s\n", test.name, error.what());
            ++failures;
        }
    }
    std::printf(failures == 0 ? "ALL PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
