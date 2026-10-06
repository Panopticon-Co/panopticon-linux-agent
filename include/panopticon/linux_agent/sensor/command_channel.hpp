#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/sensor/file_actions.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"
#include "panopticon/linux_agent/sensor/records.hpp"
#include "panopticon/linux_agent/sensor/uplink.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

namespace panopticon::linux_agent::sensor {

// The endpoint side of the Manager command channel (ADR 024).
//
// The Manager owns the command vocabulary: a closed set of seven typed actions with a closed target
// per action and no field that carries a command line, a script or a path to run. The sensor pulls
// commands (it never listens), checks each one against what it knows locally, and reports one
// structured result. Nothing here executes text, and nothing is accepted because it arrived: the
// transport (TLS and the enrolled bearer token) says who sent it, the checks below say whether
// this endpoint will act on it.

enum class response_mode : std::uint8_t {
    off,      // no polling at all; the channel does not exist
    dry_run,  // commands are polled, checked and answered; changing actions are verified, never performed
    enforce,  // permitted actions are performed
};
[[nodiscard]] const char* to_string(response_mode mode) noexcept;
[[nodiscard]] std::optional<response_mode> parse_response_mode(std::string_view text) noexcept;

enum class command_action : std::uint8_t {
    kill_process,
    collect_process_info,
    collect_network_connections,
    collect_file,
    quarantine_file,
    isolate_host,
    release_host_isolation,
};
[[nodiscard]] const char* to_string(command_action action) noexcept;
[[nodiscard]] std::optional<command_action> parse_command_action(std::string_view text) noexcept;
// The actions this sensor can carry out today. The rest are part of the Manager's vocabulary and are
// answered `rejected` with reason `unsupported_action`; they cannot be listed in the policy.
[[nodiscard]] bool command_action_implemented(command_action action) noexcept;
// An action that changes the host. Collection is read-only and runs in every mode that polls.
[[nodiscard]] bool command_action_changes_host(command_action action) noexcept;

// One command as the Manager stored it, after strict parsing.
struct endpoint_command {
    std::string command_id;
    std::string agent_id;
    std::string host_id;
    std::string correlation_id;
    command_action action{command_action::kill_process};
    std::int64_t created_unix{};  // 0 when the envelope carries no created_at
    std::int64_t expires_unix{};
    std::uint32_t pid{};          // process actions
    std::uint64_t start_ticks{};  // process actions: /proc/<pid>/stat field 22, the identity beside the pid
    std::string path;             // file actions
    // Schema 2 only: the boot the target was observed in, "boot_" + 64 hex (see linux_boot_digest).
    // Empty for schema 1, whose process target is bound to a boot only by its start ticks.
    std::string boot_id;
    // The signature the Manager's command authority made over this command, when it carried one.
    std::optional<command_authorization> authorization;
};

// The boot scope a schema-2 command names for this host: "boot_" followed by the lowercase hex SHA-256
// of the kernel's boot id exactly as /proc/sys/kernel/random/boot_id prints it (36 characters, no
// newline). The Manager derives the same value from `host.boot_id` in this host's records; it is
// never reconstructed from wall time or uptime. Empty when the kernel boot id is not a UUID.
[[nodiscard]] std::string linux_boot_digest(std::string_view kernel_boot_id);

// A command that could not be read. `command_id` is set when the id itself was readable, so the
// Manager can be told this one command was refused instead of retrying it forever.
struct command_unreadable {
    std::string command_id;
    std::string correlation_id;
    std::string reason;
};

using parsed_command = std::variant<endpoint_command, command_unreadable>;

struct command_poll {
    std::vector<parsed_command> commands;
    bool malformed{false};  // the reply as a whole was not a command list
    std::string why;
};

// Strict: a closed set of envelope keys, exact types, a closed target per action, a timestamp with a
// zone. Unknown or duplicated keys, a target with an extra field and a pid that does not fit 32 bits
// are all refusals.
[[nodiscard]] parsed_command parse_endpoint_command(const json_value& value);
[[nodiscard]] command_poll parse_command_poll(std::string_view body, std::size_t maximum_commands = 32U);

// Seconds since the epoch for an ISO 8601 UTC-offset timestamp ("...Z", "...+00:00", "...-05:30"),
// with optional fractional seconds. A timestamp without a zone is refused: the Manager would
// compare it with its own local clock and this endpoint cannot know which one that was.
[[nodiscard]] std::optional<std::int64_t> parse_utc_offset_timestamp(std::string_view text) noexcept;

struct command_policy {
    response_mode mode{response_mode::off};
    std::set<command_action> allowed{command_action::kill_process, command_action::collect_process_info,
                                     command_action::collect_network_connections};
    // A command whose expiry is further away than this was not issued for an incident response;
    // refusing it bounds how long a captured command stays usable.
    std::int64_t maximum_lifetime_seconds{900};
    std::int64_t clock_skew_seconds{30};
    // Refuse process actions that are not boot-bound (schema 1). Off until the Manager issues schema 2
    // to Linux endpoints; then a target from a previous boot cannot be acted on by start ticks alone.
    bool require_boot_binding{false};
    // Refuse every command: set when signatures are required and no key is pinned (a misconfiguration that
    // must not fall back to acting on unsigned commands).
    bool require_signature{false};
    // Changing actions performed in any rolling minute; the next one is refused. A runaway
    // automation cannot take the host apart faster than a person can notice.
    std::size_t maximum_changes_per_minute{6U};
};

// Durable record of every command id this endpoint has acted on. The id is recorded before the
// action starts, so a crash cannot make a command run twice: after a restart the same command is
// answered `indeterminate` instead of being executed again.
class command_ledger {
public:
    enum class phase : std::uint8_t { received, done, reported };
    struct entry {
        phase state{phase::received};
        std::int64_t expires_unix{};
        std::string correlation_id;
        std::string outcome;  // succeeded, failed, rejected, indeterminate (done and reported)
        std::string reason;
        std::string detail;  // what the result said; kept so a repeat is the same result
    };

    // Entries older than a day past their expiry that were reported are dropped on open. A
    // malformed line (other than a final unterminated one, which a crash can leave) is an error: a
    // ledger that half-loads would let a command run twice.
    [[nodiscard]] static result<std::unique_ptr<command_ledger>> open(const std::filesystem::path& path, std::size_t maximum_entries,
                                                                      std::int64_t now_unix);

    [[nodiscard]] std::optional<entry> find(const std::string& command_id) const;
    // false (and no change) when the id is already present.
    [[nodiscard]] result<bool> mark_received(const std::string& command_id, const std::string& correlation_id, std::int64_t expires_unix);
    [[nodiscard]] result<bool> mark_done(const std::string& command_id, std::string_view outcome, std::string_view reason,
                                         std::string_view detail = {});
    [[nodiscard]] result<bool> mark_reported(const std::string& command_id);
    // Commands whose outcome is recorded but was never acknowledged by the Manager, oldest first.
    [[nodiscard]] std::vector<std::pair<std::string, entry>> unreported() const;
    [[nodiscard]] std::size_t size() const;
    ~command_ledger();
    command_ledger(const command_ledger&) = delete;
    command_ledger& operator=(const command_ledger&) = delete;

private:
    command_ledger() = default;
    [[nodiscard]] result<bool> append(std::string_view line);

    mutable std::mutex mutex_;
    std::filesystem::path path_;
    std::size_t maximum_entries_{};
    int fd_{-1};
    std::map<std::string, entry> entries_;
};

// What carrying out one command did, in the Manager's own result vocabulary plus a machine reason.
struct execution_result {
    std::string outcome;  // succeeded, failed, rejected, indeterminate
    std::string reason;   // [a-z_]+
    std::string detail;   // bounded, printable
    std::string mode;     // "pidfd" or "pid_fallback" when a signal path was chosen
    std::uint32_t affected{};
    std::shared_ptr<const response_evidence> evidence;  // what a collection gathered, emitted as state
};

// The one place an action touches the host. A test supplies its own; the sensor supplies the local one.
class command_executor {
public:
    virtual ~command_executor() = default;
    [[nodiscard]] virtual execution_result execute(const endpoint_command& command, bool dry_run) = 0;
};

struct local_executor_options {
    std::filesystem::path proc_root{"/proc"};
    std::string host_id;
    // SIGTERM first, SIGKILL after this long without an exit (at least 1 ms).
    std::uint32_t kill_grace_ms{3000U};
    // kill(2) after verification when pidfd is unavailable. Off: the command fails instead, because that
    // path leaves a window in which the pid could be reused (ADR 015).
    bool allow_pid_fallback{false};
    // COLLECT_NETWORK_CONNECTIONS: sockets reported, and how long the /proc/<pid>/fd owner scan may take.
    std::size_t maximum_connections{4096U};
    std::chrono::milliseconds owner_scan_budget{500};
    // COLLECT_FILE and QUARANTINE_FILE (ADR 026).
    file_action_options files;
    // ISOLATE_HOST and RELEASE_HOST_ISOLATION (ADR 027): the privileged helper's socket. Empty: not configured.
    // The sensor holds no firewall capability; it can only ask the helper for one of two fixed opcodes.
    std::filesystem::path isolation_socket;
    // How long one request may take, connect included. It must outlast the helper's own netlink waits (its
    // receive timeouts are 5 s each); a helper that does not answer in time leaves the outcome `indeterminate`,
    // never a guess.
    std::chrono::milliseconds isolation_timeout{20000};
};
[[nodiscard]] std::unique_ptr<command_executor> make_local_executor(local_executor_options options);

// Everything decided about one command: what to tell the Manager and what to record.
struct command_outcome {
    std::string command_id;
    std::string correlation_id;
    std::string outcome;
    std::string reason;
    std::string detail;
    std::string mode;
    std::string action;
    bool dry_run{false};
    bool executed{false};  // the executor ran (so the host may have changed)
    std::uint32_t pid{};
    std::uint64_t start_ticks{};
    std::string path;
    std::uint32_t affected{};
    std::shared_ptr<const response_evidence> evidence;
};

struct command_processor_options {
    std::string agent_id;
    std::string host_id;
    std::string boot_digest;  // linux_boot_digest of the running kernel; empty: schema-2 commands are refused
    // The pinned command-signing keys. When set, a command is acted on only with a valid signature from one of
    // them; unsigned commands are refused. Empty: see command_policy::require_signature.
    std::shared_ptr<command_keyring> keyring;
    command_policy policy;
    std::function<std::int64_t()> now_unix;  // empty: the system clock
    // Called once a command has passed every check and its intent is durably recorded, just before it
    // is carried out (the Manager's DISPATCHED to ACCEPTED step). Failures here never block execution.
    std::function<void(const endpoint_command&)> on_accepted;
};

// The decision procedure, free of any network: envelope identity, expiry and lifetime bound, replay,
// policy (mode, allowed actions, rate), durable intent record, execution, durable outcome.
class command_processor {
public:
    command_processor(command_processor_options options, command_ledger& ledger, command_executor& executor);

    // Handles a command the ledger has not seen. Commands the ledger knows are never executed:
    // see `resume`.
    [[nodiscard]] command_outcome handle(const endpoint_command& command);
    // The answer for an id the ledger already holds: the stored result for a command that finished,
    // `indeterminate` for one whose execution was interrupted before it recorded an outcome.
    // `command` (when the Manager sent it again) supplies the action and target for the record.
    [[nodiscard]] std::optional<command_outcome> resume(const std::string& command_id, const std::string& correlation_id,
                                                        const endpoint_command* command);
    // A refusal for something that was not even a command.
    [[nodiscard]] command_outcome unreadable(const command_unreadable& failure);

    [[nodiscard]] const command_policy& policy() const noexcept { return options_.policy; }

private:
    [[nodiscard]] command_outcome refuse(const endpoint_command& command, std::string reason, std::string detail, bool record);
    [[nodiscard]] std::int64_t now() const;

    command_processor_options options_;
    command_ledger& ledger_;
    command_executor& executor_;
    std::mutex mutex_;
    std::deque<std::int64_t> change_times_;
};

// The result body for POST /api/v1/agents/{id}/command-results (result schema 2: the correlation id
// is required, `indeterminate` is a legal outcome, no native execution evidence is claimed).
[[nodiscard]] std::string command_result_json(const command_outcome& outcome);
// The audit payload for the record stream; the pipeline attaches the target process it knows.
[[nodiscard]] raw_response_action response_audit(const command_outcome& outcome);

// The seam between the channel and the network, so the channel is tested without a socket.
class command_transport {
public:
    virtual ~command_transport() = default;
    [[nodiscard]] virtual post_response poll() = 0;                                  // GET .../commands?delivery_mode=durable
    [[nodiscard]] virtual post_response accept(const std::string& command_id) = 0;   // POST .../commands/{id}/accept
    [[nodiscard]] virtual post_response submit(const std::string& result_json) = 0;  // POST .../command-results
};
[[nodiscard]] std::unique_ptr<command_transport> make_https_command_transport(https_poster_options options);

struct command_channel_options {
    command_processor_options processor;
    std::filesystem::path ledger_path;
    std::size_t maximum_ledger_entries{4096U};
    std::uint64_t poll_interval_ms{5000U};
    std::uint64_t maximum_backoff_ms{60'000U};
};

struct command_channel_metrics {
    std::uint64_t polls{};
    std::uint64_t commands_seen{};
    std::uint64_t executed{};
    std::uint64_t rejected{};
    std::uint64_t results_reported{};
    std::uint64_t result_failures{};
    std::uint64_t unreadable{};
    std::uint64_t authorization_refused{};  // refused for a missing, unknown or invalid signature
    std::string last_error;
};

// The provider that runs the channel (family-less: no other source can answer a command). Its
// records, one `response.action` per command it answered, go through the queue like any other
// telemetry, so the entity graph attaches the process the command named.
class command_channel_provider final : public provider {
public:
    command_channel_provider(command_channel_options options, std::unique_ptr<command_transport> transport,
                             std::unique_ptr<command_executor> executor);
    ~command_channel_provider() override;

    [[nodiscard]] std::string_view name() const noexcept override { return "command_channel"; }
    [[nodiscard]] std::vector<std::string> capabilities() const override;
    [[nodiscard]] std::string probe() override;
    [[nodiscard]] result<bool> start(record_queue& queue) override;
    void stop() override;
    [[nodiscard]] provider_health health() const override;
    [[nodiscard]] std::uint64_t take_losses() override { return 0U; }

    // Opens the ledger and builds the processor; start() does this and then runs the polling thread.
    // Public so tests drive `step` without a thread.
    [[nodiscard]] result<bool> prepare(record_queue& queue);
    // One poll and everything it brings; returns how long to wait before the next one.
    [[nodiscard]] std::uint64_t step(record_queue& queue);
    [[nodiscard]] command_channel_metrics metrics() const;

private:
    void run();
    void report(const command_outcome& outcome, record_queue& queue, bool audit);

    command_channel_options options_;
    std::unique_ptr<command_transport> transport_;
    std::unique_ptr<command_executor> executor_;
    std::unique_ptr<command_ledger> ledger_;
    std::unique_ptr<command_processor> processor_;
    record_queue* queue_{nullptr};
    mutable std::mutex mutex_;
    command_channel_metrics metrics_;
    std::uint64_t backoff_ms_{};
    std::thread thread_;
    std::mutex wait_mutex_;
    std::condition_variable wake_;
    std::atomic<bool> running_{false};
    std::string state_{"stopped"};
};

}  // namespace panopticon::linux_agent::sensor
