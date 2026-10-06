#pragma once

#include "panopticon/linux_agent/sensor/auth_log.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Audit record types this sensor reads (linux/audit.h).
inline constexpr std::uint16_t audit_user_auth = 1100;
inline constexpr std::uint16_t audit_user_start = 1105;
inline constexpr std::uint16_t audit_user_login = 1112;
inline constexpr std::uint16_t audit_user_cmd = 1123;

struct audit_message {
    std::uint16_t type{};
    std::string text;  // without the trailing NUL
};

// Splits one netlink datagram from the audit multicast group into messages. Every length is
// checked against what remains; a message that is short, longer than the datagram or longer than
// `maximum_audit_text_bytes` ends decoding. Never reads out of bounds, whatever the input.
inline constexpr std::size_t maximum_audit_text_bytes = 9000U;
[[nodiscard]] std::vector<audit_message> decode_audit_datagram(const std::uint8_t* data, std::size_t size);

using uid_lookup = std::function<std::string(std::uint32_t)>;

struct parsed_audit_event {
    std::uint64_t time_unix_ns{};
    raw_auth_event event;
};

// Maps one audit record to an authentication event, or nothing when the record is not one this
// sensor reports or cannot be read with confidence:
//   USER_LOGIN (success)        -> login_success
//   USER_AUTH  (failure)        -> login_failure, or privilege_failure for sudo/su/pkexec
//   USER_CMD                    -> privilege_success / privilege_failure with the command
//   USER_START by su            -> privilege_success
// A successful USER_AUTH is not reported: the USER_LOGIN or USER_CMD that follows is the event.
//
// `pid`, `uid` and `auid` in the header are filled in by the kernel from the sending process;
// the text inside msg='...' is chosen by the sender. Untrusted strings arrive quoted or
// hex-encoded, the tokenizer honours quotes so a quote-free injection cannot end a value early,
// the first occurrence of a key wins, and every value is made printable and bounded.
[[nodiscard]] std::optional<parsed_audit_event> parse_audit_record(std::uint16_t type, std::string_view text, const uid_lookup& lookup);

// Resolves a uid to a user name through the system databases, with a bounded cache. Unknown uids
// become "uid:N".
[[nodiscard]] std::string resolve_user_name(std::uint32_t uid);

struct audit_netlink_options {
    std::size_t receive_buffer_bytes{1U << 20U};
    std::size_t maximum_events_per_second{500U};
    std::chrono::milliseconds poll_interval{200};
    uid_lookup lookup;  // empty: resolve_user_name
};

// Authentication telemetry from the kernel audit subsystem's multicast group (matrix mechanism
// AUDIT; the primary for AE1/AF1/AG1, ahead of the auth log). Read-only: it adds no audit rules
// and does not become the audit daemon. It reports what the kernel is already sending, so it
// sees nothing on a host where auditing is disabled, and says so through health.
class audit_netlink_provider final : public provider {
public:
    explicit audit_netlink_provider(audit_netlink_options options = {});
    ~audit_netlink_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "audit_netlink"; }
    [[nodiscard]] std::string_view family() const noexcept override { return "auth"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return losses_.exchange(0U); }
    [[nodiscard]] std::uint64_t take_governed() override { return governed_.exchange(0U); }

private:
    void run();
    void handle(const std::uint8_t* data, std::size_t size);

    audit_netlink_options options_;
    record_queue* queue_{nullptr};
    int fd_{-1};
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> events_{0U};
    std::atomic<std::uint64_t> governed_{0U};
    std::atomic<std::uint64_t> losses_{0U};
    std::atomic<std::uint64_t> seen_{0U};
    std::uint64_t window_second_{0U};
    std::size_t window_count_{0U};
};

}  // namespace panopticon::linux_agent::sensor
