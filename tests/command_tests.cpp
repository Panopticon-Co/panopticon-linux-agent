// Tests for the sensor command channel (ADR 024): strict parsing, the durable ledger, the decision
// procedure, the local executor against real processes, and the poll/accept/result exchange through
// a fake Manager.

#include "panopticon/linux_agent/keypair.hpp"
#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"
#include "panopticon/linux_agent/sensor/pipeline.hpp"
#include "panopticon/linux_agent/sensor/serializer.hpp"
#include "panopticon/linux_agent/sensor/sockdiag_network.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

constexpr std::int64_t now_fixed = 1'800'000'000;  // 2027-01-15T08:00:00Z

fs::path scratch(const std::string& name) {
    const auto path = fs::temp_directory_path() / ("panopticon-command-tests-" + std::to_string(::getpid()) + "-" + name);
    fs::remove_all(path);
    fs::create_directories(path);
    return path;
}

std::string envelope(const std::string& id, const std::string& action, const std::string& target, const std::string& expires,
                     const std::string& created = "", const std::string& agent = "agent-1", const std::string& host = "host-1") {
    std::string text = "{\"command_id\":\"" + id + "\",\"schema_version\":\"1\",\"agent_id\":\"" + agent + "\",\"action\":\"" + action +
                       "\",\"expires_at\":\"" + expires + "\",\"target\":" + target + ",\"correlation_id\":\"corr-" + id +
                       "\",\"host_id\":\"" + host + "\"";
    if (!created.empty()) text += ",\"created_at\":\"" + created + "\"";
    return text + "}";
}

const std::string kill_target = "{\"pid\":4242,\"start_time_ticks\":99}";
// The kernel boot id of the test host, and the schema-2 scope that names it.
const std::string test_kernel_boot = "a4d9d0e1-c8d8-4a67-a703-bdf6f6f01263";
const std::string other_kernel_boot = "b4d9d0e1-c8d8-4a67-a703-bdf6f6f01263";
std::string bound_target(const std::string& boot, const std::string& ticks = "\"99\"") {
    return "{\"pid\":4242,\"start_time_ticks\":" + ticks + ",\"boot_id\":\"" + boot + "\"}";
}
std::string schema2(std::string text) {
    const std::string from = "\"schema_version\":\"1\"";
    text.replace(text.find(from), from.size(), "\"schema_version\":\"2\"");
    return text;
}

parsed_command parse_one(const std::string& text) {
    std::string why;
    const auto document = parse_json(text, json_limits{}, &why);
    require(document.has_value(), "the test envelope is valid JSON");
    return parse_endpoint_command(*document);
}

const endpoint_command& as_command(const parsed_command& parsed) {
    const auto* command = std::get_if<endpoint_command>(&parsed);
    require(command != nullptr, "the envelope was accepted");
    return *command;
}

const command_unreadable& as_unreadable(const parsed_command& parsed) {
    const auto* failure = std::get_if<command_unreadable>(&parsed);
    require(failure != nullptr, "the envelope was refused");
    return *failure;
}

// ---- parsing --------------------------------------------------------------------------------

void test_timestamps() {
    require(parse_utc_offset_timestamp("2027-01-15T08:00:00Z") == now_fixed, "Z");
    require(parse_utc_offset_timestamp("2027-01-15T08:00:00+00:00") == now_fixed, "+00:00");
    require(parse_utc_offset_timestamp("2027-01-15T08:00:00.123456+00:00") == now_fixed, "microseconds, as the Manager writes them");
    require(parse_utc_offset_timestamp("2027-01-15T03:00:00-05:00") == now_fixed, "an offset is applied");
    require(parse_utc_offset_timestamp("2027-01-15T13:30:00+05:30") == now_fixed, "a half-hour offset is applied");
    require(parse_utc_offset_timestamp("1970-01-01T00:00:00Z") == 0, "the epoch");
    require(parse_utc_offset_timestamp("2028-02-29T00:00:00Z").has_value(), "a leap day is valid");
    require(!parse_utc_offset_timestamp("2027-02-29T00:00:00Z"), "2027 has no 29 February");
    require(!parse_utc_offset_timestamp("2027-01-15T08:00:00"), "no zone is refused");
    require(!parse_utc_offset_timestamp("2027-01-15 08:00:00Z"), "a space is not a T");
    require(!parse_utc_offset_timestamp("2027-13-15T08:00:00Z"), "month 13");
    require(!parse_utc_offset_timestamp("2027-01-15T24:00:00Z"), "hour 24");
    require(!parse_utc_offset_timestamp("2027-01-15T08:00:00+0000"), "offset without a colon");
    require(!parse_utc_offset_timestamp("2027-01-15T08:00:00Zjunk"), "trailing text");
    require(!parse_utc_offset_timestamp("2027-01-15T08:00:00.Z"), "an empty fraction");
    require(!parse_utc_offset_timestamp(""), "empty");
}

void test_parse_valid_commands() {
    const auto kill = as_command(parse_one(envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00+00:00", "2027-01-15T08:00:00+00:00")));
    require(kill.action == command_action::kill_process && kill.pid == 4242U && kill.start_ticks == 99U, "kill target");
    require(kill.expires_unix == now_fixed + 300 && kill.created_unix == now_fixed, "times");
    require(kill.agent_id == "agent-1" && kill.host_id == "host-1" && kill.correlation_id == "corr-c1", "identity");
    const auto info = as_command(parse_one(envelope("c2", "COLLECT_PROCESS_INFO", kill_target, "2027-01-15T08:05:00Z")));
    require(info.action == command_action::collect_process_info && info.created_unix == 0, "no created_at is allowed");
    const auto file = as_command(parse_one(envelope("c3", "COLLECT_FILE", "{\"path\":\"/tmp/x\"}", "2027-01-15T08:05:00Z")));
    require(file.path == "/tmp/x", "file target");
    const auto isolate = as_command(parse_one(envelope("c4", "ISOLATE_HOST", "{}", "2027-01-15T08:05:00Z")));
    require(isolate.action == command_action::isolate_host, "an action without a target takes an empty target");
}

void test_parse_refusals() {
    const auto reason = [](const std::string& text) { return as_unreadable(parse_one(text)).reason; };
    require(reason(envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00")) == "invalid_expiry", "no zone");
    require(reason(envelope("c1", "RUN_SHELL", "{}", "2027-01-15T08:05:00Z")) == "unknown_action", "no such action");
    require(as_unreadable(parse_one(envelope("c1", "RUN_SHELL", "{}", "2027-01-15T08:05:00Z"))).command_id == "c1",
            "an unknown action still names its command, so it can be closed");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":4242}", "2027-01-15T08:05:00Z")) == "invalid_target", "missing start time");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":4242,\"start_time_ticks\":99,\"signal\":9}", "2027-01-15T08:05:00Z")) == "invalid_target",
            "an extra target field");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":0,\"start_time_ticks\":99}", "2027-01-15T08:05:00Z")) == "invalid_target", "pid 0");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":4294967296,\"start_time_ticks\":99}", "2027-01-15T08:05:00Z")) == "invalid_target",
            "pid beyond 32 bits");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":-5,\"start_time_ticks\":99}", "2027-01-15T08:05:00Z")) == "invalid_target", "negative pid");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":\"4242\",\"start_time_ticks\":99}", "2027-01-15T08:05:00Z")) == "invalid_target",
            "a pid in a string");
    require(reason(envelope("c1", "KILL_PROCESS", "{\"pid\":1.5,\"start_time_ticks\":99}", "2027-01-15T08:05:00Z")) == "invalid_target", "a fractional pid");
    require(reason(envelope("c1", "COLLECT_FILE", "{\"path\":\"\"}", "2027-01-15T08:05:00Z")) == "invalid_target", "an empty path");
    require(reason(envelope("c1", "COLLECT_FILE", "{\"path\":\"/a\\u0000b\"}", "2027-01-15T08:05:00Z")) == "invalid_target", "a NUL in a path");
    require(reason(envelope("c1", "ISOLATE_HOST", "{\"pid\":1}", "2027-01-15T08:05:00Z")) == "invalid_target", "a target on a targetless action");
    require(reason(envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z", "garbage")) == "invalid_created_at", "bad created_at");
    require(reason("{\"command_id\":\"c1\",\"command\":\"rm -rf /\"}") == "unknown_field", "a field outside the envelope");
    auto with_script = envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z");
    with_script.insert(with_script.size() - 1U, ",\"script\":\"id\"");
    require(reason(with_script) == "unknown_field", "a script field is refused");
    auto wrong_version = envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z");
    wrong_version.replace(wrong_version.find("\"1\""), 3U, "\"2\"");
    require(reason(wrong_version) == "invalid_target", "schema 2 does not take a schema-1 target");
    auto unknown_version = envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z");
    unknown_version.replace(unknown_version.find("\"1\""), 3U, "\"3\"");
    require(reason(unknown_version) == "unsupported_schema_version", "schema 3 does not exist");
    require(reason(envelope("c/1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z")) == "invalid_envelope", "an id with a slash");
    require(as_unreadable(parse_one(envelope("c/1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z"))).command_id.empty(),
            "an unusable id names no command");
    require(reason(envelope(std::string(121U, 'a'), "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z")) == "invalid_envelope", "an id too long to answer");
}

void test_parse_poll() {
    auto list = parse_command_poll("{\"commands\":[]}");
    require(!list.malformed && list.commands.empty(), "an empty list");
    list = parse_command_poll("{\"commands\":[" + envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z") + "," +
                              envelope("c2", "RUN_SHELL", "{}", "2027-01-15T08:05:00Z") + "]}");
    require(!list.malformed && list.commands.size() == 2U, "two commands, one unreadable");
    require(std::holds_alternative<endpoint_command>(list.commands[0]) && std::holds_alternative<command_unreadable>(list.commands[1]),
            "each is judged alone");
    require(parse_command_poll("").malformed, "empty body");
    require(parse_command_poll("not json").malformed, "not JSON");
    require(parse_command_poll("[]").malformed, "an array");
    require(parse_command_poll("{\"commands\":[],\"extra\":1}").malformed, "an extra top-level field");
    require(parse_command_poll("{\"commands\":{}}").malformed, "commands is not a list");
    require(parse_command_poll("{\"commands\":[],\"commands\":[]}").malformed, "duplicate keys");
    require(parse_command_poll("{\"commands\":[1,2]}").commands.size() == 2U, "non-objects are unreadable, not fatal");
    std::string many = "{\"commands\":[";
    for (int index = 0; index < 40; ++index) many += std::string{index == 0 ? "" : ","} + envelope("c" + std::to_string(index), "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z");
    many += "]}";
    require(parse_command_poll(many, 32U).malformed, "more commands than the bound");
}

void test_parse_survives_garbage() {
    std::mt19937_64 random{0xC0FFEE};
    // One valid envelope per action (and a signed one, so the authorization member is mutated too), so a mutation
    // can land anywhere in any action's grammar.
    const std::string expires = "2027-01-15T08:05:00Z";
    const std::string created = "2027-01-15T08:00:00Z";
    std::vector<std::string> bases{
        envelope("c1", "KILL_PROCESS", kill_target, expires, created),
        envelope("c2", "COLLECT_PROCESS_INFO", kill_target, expires, created),
        envelope("c3", "COLLECT_NETWORK_CONNECTIONS", "{}", expires, created),
        envelope("c4", "COLLECT_FILE", "{\"path\":\"/srv/data/file\"}", expires, created),
        envelope("c5", "QUARANTINE_FILE", "{\"path\":\"/srv/data/file\"}", expires, created),
        envelope("c6", "ISOLATE_HOST", "{}", expires, created),
        envelope("c7", "RELEASE_HOST_ISOLATION", "{}", expires, created),
        schema2(envelope("c8", "KILL_PROCESS", bound_target(test_kernel_boot), expires, created)),
    };
    {
        auto signed_one = bases[0];
        signed_one.pop_back();
        signed_one += ",\"authorization\":{\"algorithm\":\"ES256\",\"key_id\":\"0123456789abcdef\",\"signature\":\"" +
                      std::string(86U, 'A') + "==\"}}";
        bases.push_back(signed_one);
    }
    std::size_t survivors = 0;
    for (int round = 0; round < 60000; ++round) {
        auto text = bases[static_cast<std::size_t>(random() % bases.size())];
        const auto edits = 1U + random() % 4U;
        for (unsigned edit = 0; edit < edits; ++edit) {
            switch (random() % 5U) {
                case 0: text[random() % text.size()] = static_cast<char>(random() % 256U); break;
                case 1: text.erase(random() % text.size(), 1U + random() % 6U); break;
                case 2: text.insert(random() % text.size(), 1U, static_cast<char>(random() % 256U)); break;
                case 3: {  // duplicate a slice: repeated keys, doubled values
                    const auto from = static_cast<std::size_t>(random() % text.size());
                    const auto length = static_cast<std::size_t>(1U + random() % 24U);
                    text.insert(random() % text.size(), text.substr(from, length));
                    break;
                }
                default: {  // swap two bytes: reordered members
                    const auto one = static_cast<std::size_t>(random() % text.size());
                    const auto two = static_cast<std::size_t>(random() % text.size());
                    std::swap(text[one], text[two]);
                    break;
                }
            }
            if (text.empty()) text = "{";
        }
        const auto list = parse_command_poll("{\"commands\":[" + text + "]}");
        for (const auto& item : list.commands) {
            const auto* command = std::get_if<endpoint_command>(&item);
            if (command == nullptr) continue;
            ++survivors;
            // Whatever survives is a fully valid command of a known action, with an id the ledger can key on.
            require(!command->command_id.empty() && command->command_id.size() <= 128U, "a survivor has a usable id");
            require(command->expires_unix > 0, "a survivor expires");
            require(parse_command_action(to_string(command->action)).has_value(), "a survivor's action is in the vocabulary");
            switch (command->action) {
                case command_action::kill_process:
                case command_action::collect_process_info:
                    require(command->pid != 0U && command->start_ticks != 0U, "a process survivor names a process");
                    require(command->path.empty(), "a process survivor has no path");
                    break;
                case command_action::collect_file:
                case command_action::quarantine_file:
                    require(!command->path.empty() && command->path.size() <= 4096U && command->path.find('\0') == std::string::npos,
                            "a file survivor names a path without NUL");
                    require(command->pid == 0U, "a file survivor has no pid");
                    break;
                default:
                    require(command->pid == 0U && command->path.empty(), "a targetless survivor carries no target");
                    break;
            }
        }
    }
    require(survivors > 0U, "some mutations leave a valid command, so the invariants were exercised");
}

// ---- ledger ---------------------------------------------------------------------------------

std::unique_ptr<command_ledger> open_ledger(const fs::path& path, const std::size_t bound = 64U, const std::int64_t now = now_fixed) {
    auto opened = command_ledger::open(path, bound, now);
    require(succeeded(opened), "ledger opens");
    return std::move(std::get<std::unique_ptr<command_ledger>>(opened));
}

void test_ledger_persists_and_refuses_replay() {
    const auto dir = scratch("ledger");
    const auto path = dir / "commands";
    {
        auto ledger = open_ledger(path);
        require(std::get<bool>(ledger->mark_received("c1", "corr-1", now_fixed + 300)), "first sight");
        require(!std::get<bool>(ledger->mark_received("c1", "corr-1", now_fixed + 300)), "second sight is a replay");
        require(std::get<bool>(ledger->mark_done("c1", "succeeded", "ok", "name=sleep\texe=/bin/sleep\nx")), "done, with what it said");
        require(!std::get<bool>(ledger->mark_done("c1", "failed", "signal_failed")), "an outcome is written once");
        require(std::get<bool>(ledger->mark_received("c2", "corr-2", now_fixed + 300)), "c2 received, never finished");
        require(std::get<bool>(ledger->mark_received("c3", "corr-3", now_fixed + 300)), "c3");
        require(std::get<bool>(ledger->mark_done("c3", "rejected", "dry_run")), "c3 done");
        require(std::get<bool>(ledger->mark_reported("c3")), "c3 reported");
        require(!std::get<bool>(ledger->mark_reported("c2")), "an unfinished command cannot be reported");
    }
    auto reopened = open_ledger(path);
    require(reopened->size() == 3U, "every command survived the restart");
    require(reopened->find("c1")->state == command_ledger::phase::done && reopened->find("c1")->outcome == "succeeded", "c1 outcome kept");
    require(reopened->find("c1")->detail == "name=sleep?exe=/bin/sleep?x", "the detail survives, with control characters made inert");
    require(reopened->find("c3")->detail.empty(), "no detail stays empty");
    require(reopened->find("c2")->state == command_ledger::phase::received, "c2 is still unfinished");
    require(reopened->find("c3")->state == command_ledger::phase::reported && reopened->find("c3")->correlation_id == "corr-3", "c3 reported");
    require(!std::get<bool>(reopened->mark_received("c1", "corr-1", now_fixed + 300)), "a restart does not forget a command");
    const auto pending = reopened->unreported();
    require(pending.size() == 1U && pending[0].first == "c1", "only c1 awaits acknowledgement");
    fs::remove_all(dir);
}

void test_ledger_corruption_and_tail() {
    const auto dir = scratch("corrupt");
    const auto path = dir / "commands";
    {
        std::ofstream out{path};
        out << "R\tc1\tcorr-1\t1800000300\nD\tc1\tsucceeded\tok\nR\tc2\tcorr-2\t18000";  // crash mid-line
    }
    {
        auto ledger = open_ledger(path);
        require(ledger->size() == 1U && ledger->find("c1").has_value() && !ledger->find("c2"), "the unfinished last line is dropped");
        require(std::get<bool>(ledger->mark_received("c2", "corr-2", now_fixed + 300)), "and can be written again");
    }
    require(open_ledger(path)->size() == 2U, "the rewritten ledger loads");
    const auto bad = [&](const std::string& contents, const char* what) {
        {
            std::ofstream out{path, std::ios::trunc};
            out << contents;
        }
        require(!succeeded(command_ledger::open(path, 64U, now_fixed)), what);
    };
    bad("R\tc1\tcorr-1\t1800000300\nthis is not a record\n", "garbage line");
    bad("D\tc9\tsucceeded\tok\n", "an outcome for a command never received");
    bad("R\tc1\tcorr-1\t1800000300\nD\tc1\tsucceeded\tOK; rm\n", "a reason that is not a code");
    bad("R\tc1\tcorr-1\t1800000300\nD\tc1\tdone\tok\n", "an outcome outside the vocabulary");
    bad("R\tc1\tcorr-1\t1800000300\nS\tc1\n", "reported before done");
    bad("R\tc1\tcorr-1\tabc\n", "a non-numeric expiry");
    bad("X\tc1\n", "an unknown record kind");
    fs::remove_all(dir);
}

void test_ledger_bounds_and_compaction() {
    const auto dir = scratch("bounds");
    const auto path = dir / "commands";
    {
        auto ledger = open_ledger(path, 3U);
        for (int index = 0; index < 3; ++index) require(std::get<bool>(ledger->mark_received("c" + std::to_string(index), "corr", now_fixed + 300)), "within the bound");
        const auto full = ledger->mark_received("c9", "corr", now_fixed + 300);
        require(!succeeded(full), "a full ledger refuses instead of forgetting");
        for (int index = 0; index < 3; ++index) {
            require(std::get<bool>(ledger->mark_done("c" + std::to_string(index), "rejected", "expired")), "done");
            require(std::get<bool>(ledger->mark_reported("c" + std::to_string(index))), "reported");
        }
    }
    require(open_ledger(path, 3U, now_fixed)->size() == 3U, "recent entries are kept");
    require(open_ledger(path, 3U, now_fixed + 300 + 86400 + 1)->size() == 0U, "reported entries a day past expiry are dropped");
    {
        auto ledger = open_ledger(path, 3U, now_fixed);
        require(std::get<bool>(ledger->mark_received("keep", "corr", 1000)), "an old unfinished command");
    }
    require(open_ledger(path, 3U, now_fixed + 10'000'000)->find("keep").has_value(), "an unfinished command is never compacted away");
    fs::remove_all(dir);
}

// ---- processor ------------------------------------------------------------------------------

struct fake_executor final : command_executor {
    std::vector<std::string> calls;
    std::vector<bool> dry_runs;
    execution_result next{"succeeded", "ok", "done", "pidfd", 1U, {}};
    std::function<void()> on_execute;
    execution_result execute(const endpoint_command& command, const bool dry_run) override {
        calls.push_back(command.command_id);
        dry_runs.push_back(dry_run);
        if (on_execute) on_execute();
        return next;
    }
};

std::string zulu(const std::int64_t unix_time) {
    std::time_t seconds = static_cast<std::time_t>(unix_time);
    std::tm parts{};
    gmtime_r(&seconds, &parts);
    char text[32];
    std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &parts);
    return std::string{text};
}

struct world {
    fs::path dir;
    std::unique_ptr<command_ledger> ledger;
    fake_executor executor;
    std::int64_t clock{now_fixed};
    std::vector<std::string> accepted;
    std::unique_ptr<command_processor> processor;

    explicit world(const std::string& name, const response_mode mode = response_mode::enforce, const std::size_t ledger_bound = 64U) : dir{scratch(name)} {
        ledger = open_ledger(dir / "commands", ledger_bound);
        command_processor_options options;
        options.agent_id = "agent-1";
        options.host_id = "host-1";
        options.boot_digest = linux_boot_digest(test_kernel_boot);
        options.policy.mode = mode;
        options.now_unix = [this] { return clock; };
        options.on_accepted = [this](const endpoint_command& command) { accepted.push_back(command.command_id); };
        processor = std::make_unique<command_processor>(std::move(options), *ledger, executor);
    }
    ~world() { fs::remove_all(dir); }

    // Built through the real parser so the tests exercise exactly what the channel sees.
    endpoint_command make(const std::string& id, const std::string& action = "KILL_PROCESS", const std::string& target = kill_target,
                          const std::int64_t expires_in = 300, const std::string& agent = "agent-1", const std::string& host = "host-1") const {
        return as_command(parse_one(envelope(id, action, target, zulu(clock + expires_in), zulu(clock), agent, host)));
    }
};

void test_processor_executes_once() {
    world w{"once"};
    const auto command = w.make("c1");
    const auto first = w.processor->handle(command);
    require(first.outcome == "succeeded" && first.reason == "ok" && first.executed && !first.dry_run && first.mode == "pidfd", "executed");
    require(w.executor.calls.size() == 1U && w.executor.dry_runs[0] == false, "the executor ran once, for real");
    require(w.accepted == std::vector<std::string>{"c1"}, "accept ran before the action, once");
    const auto again = w.processor->handle(command);
    require(again.outcome == "rejected" && again.reason == "replay" && !again.executed, "the same id is a replay");
    require(w.executor.calls.size() == 1U, "a replay never reaches the executor");
    require(w.ledger->find("c1")->state == command_ledger::phase::done, "the outcome is durable");
}

void test_processor_checks() {
    world w{"checks"};
    const auto refused = [&](const endpoint_command& command, const char* reason) {
        const auto outcome = w.processor->handle(command);
        require(outcome.outcome == "rejected" && outcome.reason == reason && !outcome.executed, reason);
        require(w.executor.calls.empty(), "a refused command never reaches the executor");
        require(w.ledger->find(command.command_id)->state == command_ledger::phase::done, "and the refusal is remembered");
    };
    refused(w.make("wa", "KILL_PROCESS", kill_target, 300, "other-agent"), "wrong_endpoint");
    refused(w.make("wh", "KILL_PROCESS", kill_target, 300, "agent-1", "other-host"), "wrong_endpoint");
    refused(w.make("ex", "KILL_PROCESS", kill_target, -1), "expired");
    refused(w.make("ex0", "KILL_PROCESS", kill_target, 0), "expired");
    refused(w.make("long", "KILL_PROCESS", kill_target, 7 * 86400), "lifetime_exceeded");
    refused(w.make("iso", "ISOLATE_HOST", "{}"), "action_not_permitted");  // implemented, but not on the default allow-list
    refused(w.make("qf", "QUARANTINE_FILE", "{\"path\":\"/tmp/x\"}"), "action_not_permitted");  // implemented, but not on the default allow-list

    auto future = w.make("fut");
    future.created_unix = w.clock + 3600;
    refused(future, "not_yet_valid");

    world off{"checks-off", response_mode::off};
    const auto disabled = off.processor->handle(off.make("c1"));
    require(disabled.reason == "response_disabled" && off.executor.calls.empty(), "off means off");

    // The skew allowance: a lifetime a little over the bound is tolerated, well over is not.
    world skew{"checks-skew"};
    require(skew.processor->handle(skew.make("edge", "KILL_PROCESS", kill_target, 900 + 30)).executed, "at the bound plus skew");
    require(skew.processor->handle(skew.make("over", "KILL_PROCESS", kill_target, 900 + 31)).reason == "lifetime_exceeded", "one second past it");
}

void test_processor_policy() {
    world w{"policy"};
    const auto policy = w.processor->policy();
    require(policy.allowed.contains(command_action::kill_process) && policy.allowed.contains(command_action::collect_process_info) &&
                policy.allowed.contains(command_action::collect_network_connections),
            "default allow-list");
    command_processor_options options;
    options.agent_id = "agent-1";
    options.host_id = "host-1";
    options.policy.mode = response_mode::enforce;
    options.policy.allowed = {command_action::collect_process_info};
    options.now_unix = [&w] { return w.clock; };
    command_processor collect_only{options, *w.ledger, w.executor};
    require(collect_only.handle(w.make("k1")).reason == "action_not_permitted", "kill is not on the list");
    require(collect_only.handle(w.make("i1", "COLLECT_PROCESS_INFO")).executed, "collect is");

    // dry_run: a changing action is verified (the executor is told), collection still runs.
    world dry{"policy-dry", response_mode::dry_run};
    dry.executor.next = {"rejected", "dry_run", "verified", "pidfd", 1U, {}};
    const auto killed = dry.processor->handle(dry.make("d1"));
    require(killed.dry_run && killed.executed && killed.outcome == "rejected" && killed.reason == "dry_run", "kill in dry_run mode");
    require(dry.executor.dry_runs[0], "the executor was told not to change anything");
    dry.executor.next = {"succeeded", "ok", "name=x", "", 1U, {}};
    const auto info = dry.processor->handle(dry.make("d2", "COLLECT_PROCESS_INFO"));
    require(!info.dry_run && info.outcome == "succeeded" && !dry.executor.dry_runs[1], "collection is read-only and is not suppressed");
    auto evidence = std::make_shared<response_evidence>();
    evidence->snapshot_id = "response-d3";
    dry.executor.next = {"succeeded", "ok", "tcp_listen=1", "", 1U, evidence};
    const auto connections = dry.processor->handle(dry.make("d3", "COLLECT_NETWORK_CONNECTIONS", "{}"));
    require(!connections.dry_run && connections.outcome == "succeeded" && !dry.executor.dry_runs[2], "the socket inventory runs in dry_run too");
    require(connections.evidence == evidence && response_audit(connections).evidence == evidence, "and its evidence reaches the audit record");
}

void test_processor_rate_limit() {
    world w{"rate"};
    for (int index = 0; index < 6; ++index) require(w.processor->handle(w.make("c" + std::to_string(index))).executed, "within the allowance");
    const auto seventh = w.processor->handle(w.make("c6"));
    require(seventh.reason == "rate_limited" && !seventh.executed && w.executor.calls.size() == 6U, "the seventh change in a minute is refused");
    // Collection is not a change and is not counted.
    require(w.processor->handle(w.make("i1", "COLLECT_PROCESS_INFO")).executed, "reads are not limited");
    w.clock += 61;
    require(w.processor->handle(w.make("c7")).executed, "the window slides");
}

void test_processor_crash_recovery() {
    world w{"crash"};
    // The process died after recording intent and before recording an outcome.
    require(std::get<bool>(w.ledger->mark_received("c1", "corr-c1", w.clock + 300)), "intent recorded");
    const auto command = w.make("c1");
    const auto resumed = w.processor->resume("c1", "corr-c1", &command);
    require(resumed.has_value() && resumed->outcome == "indeterminate" && resumed->reason == "interrupted", "an interrupted command is indeterminate");
    require(w.executor.calls.empty(), "and is never run again");
    require(w.ledger->find("c1")->state == command_ledger::phase::done, "the answer is now durable");
    const auto repeated = w.processor->resume("c1", "corr-c1", &command);
    require(repeated->outcome == "indeterminate" && repeated->reason == "interrupted", "asking again gives the same answer");
    require(!w.processor->resume("never-seen", "corr", nullptr).has_value(), "an unknown id has nothing to resume");
}

void test_processor_ledger_failure_is_fail_closed() {
    world w{"full", response_mode::enforce, 1U};
    require(w.processor->handle(w.make("c1")).executed, "the first command fits");
    const auto second = w.processor->handle(w.make("c2"));
    require(second.reason == "ledger_unavailable" && !second.executed, "no room to record it: not executed");
    require(w.executor.calls.size() == 1U, "the executor was not called");
}

void test_processor_unreadable() {
    world w{"unreadable"};
    command_unreadable failure;
    failure.command_id = "bad1";
    failure.correlation_id = "corr-bad1";
    failure.reason = "unknown_action";
    const auto outcome = w.processor->unreadable(failure);
    require(outcome.outcome == "rejected" && outcome.reason == "invalid_command" && outcome.command_id == "bad1", "closed with a rejection");
    require(w.ledger->find("bad1")->state == command_ledger::phase::done, "and remembered");
    command_unreadable anonymous;
    anonymous.reason = "invalid_envelope";
    require(w.processor->unreadable(anonymous).command_id.empty(), "nothing to address");
}

// ---- result and record ----------------------------------------------------------------------

void test_result_json() {
    command_outcome outcome;
    outcome.command_id = "c1";
    outcome.correlation_id = "corr-c1";
    outcome.outcome = "indeterminate";
    outcome.reason = "interrupted";
    outcome.detail = "it \"stopped\"\nhere";
    const auto text = command_result_json(outcome);
    const auto document = parse_json(text, json_limits{}, nullptr);
    require(document && document->is_object(), "the result is JSON");
    require(*document->find("schema_version")->as_string() == "2", "schema 2: indeterminate is legal");
    require(*document->find("result_id")->as_string() == "res-c1", "the result id is fixed by the command");
    require(*document->find("correlation_id")->as_string() == "corr-c1", "schema 2 requires the correlation id");
    require(document->find("execution") == nullptr, "no native execution evidence is claimed");
    require(document->keys().size() == 6U, "exactly the contract fields");
    require(command_result_json(outcome) == text, "a retry sends byte-identical content");
    require(document->find("detail")->as_string()->size() <= 512U, "the detail is within the contract bound");
}

void test_response_record_shape() {
    clock_domain clock;
    sensor_identity identity{"host-1", "boot-1", "name", "sensor-1", "0.0.0", "none"};
    record_serializer serializer{identity, clock};
    response_record record;
    record.time_unix_ns = 1'800'000'000'000'000'000ULL;
    record.source = provenance{"command_channel", "MGR-CMD", confidence::observed};
    command_outcome outcome;
    outcome.command_id = "c1";
    outcome.correlation_id = "corr-c1";
    outcome.action = "KILL_PROCESS";
    outcome.outcome = "rejected";
    outcome.reason = "dry_run";
    outcome.detail = "verified";
    outcome.mode = "pidfd";
    outcome.dry_run = true;
    outcome.executed = true;
    outcome.pid = 4242U;
    outcome.start_ticks = 99U;
    outcome.affected = 1U;
    record.response = response_audit(outcome);
    const auto text = serializer.response_event(record, 7U, record.time_unix_ns);
    const auto document = parse_json(text, json_limits{}, nullptr);
    require(document.has_value(), "valid JSON");
    require(*document->find("type")->as_string() == "response.action", "type");
    const auto* body = document->find("response");
    require(body != nullptr && *body->find("command_id")->as_string() == "c1" && *body->find("outcome")->as_string() == "rejected", "body");
    require(body->find("dry_run")->as_boolean() == true && body->find("executed")->as_boolean() == true, "flags");
    require(body->find("target")->find("pid")->as_unsigned() == 4242U && body->find("target")->find("start_time_ticks")->as_unsigned() == 99U, "target identity");
    const auto* process = document->find("process");
    require(process != nullptr && process->find("pid")->as_unsigned() == 4242U && process->find("entity_id") == nullptr,
            "an unknown target is a pid stub, not an invented entity");
    require(document->find("unavailable") != nullptr && !document->find("unavailable")->items().empty(), "and the gap is stated");
}

// ---- local executor against real processes --------------------------------------------------

std::uint64_t start_of(const pid_t pid) {
    std::ifstream input{"/proc/" + std::to_string(pid) + "/stat"};
    std::string text;
    std::getline(input, text);
    const auto close = text.rfind(')');
    require(close != std::string::npos, "stat readable");
    std::size_t cursor = close + 2U;
    for (int field = 0; field < 19; ++field) {
        cursor = text.find(' ', cursor);
        require(cursor != std::string::npos, "stat has the start time");
        ++cursor;
    }
    return std::stoull(text.substr(cursor));
}

pid_t spawn_sleeper() {
    const pid_t pid = ::fork();
    require(pid >= 0, "fork");
    if (pid == 0) {
        for (;;) ::pause();
    }
    return pid;
}

bool alive(const pid_t pid) {
    int status = 0;
    return ::waitpid(pid, &status, WNOHANG) == 0;
}

endpoint_command real_command(const std::string& id, const command_action action, const pid_t pid, const std::uint64_t ticks) {
    endpoint_command command;
    command.command_id = id;
    command.agent_id = "agent-1";
    command.host_id = "host-1";
    command.correlation_id = "corr-" + id;
    command.action = action;
    command.expires_unix = now_fixed + 300;
    command.pid = static_cast<std::uint32_t>(pid);
    command.start_ticks = ticks;
    return command;
}

void test_local_executor_real_processes() {
    local_executor_options options;
    options.host_id = "host-1";
    options.kill_grace_ms = 500U;
    const auto executor = make_local_executor(options);

    const pid_t victim = spawn_sleeper();
    const auto ticks = start_of(victim);
    const auto dry = executor->execute(real_command("k1", command_action::kill_process, victim, ticks), true);
    require(dry.outcome == "rejected" && dry.reason == "dry_run" && dry.mode == "pidfd", "dry run verifies through a pidfd");
    require(alive(victim), "and sends nothing");

    const auto reused = executor->execute(real_command("k2", command_action::kill_process, victim, ticks + 1U), false);
    require(reused.outcome == "rejected" && reused.reason == "target_mismatch", "a pid with another start time is a different process");
    require(alive(victim), "and is left alone");

    const auto info = executor->execute(real_command("i1", command_action::collect_process_info, victim, ticks), false);
    require(info.outcome == "succeeded" && info.detail.find("ppid=" + std::to_string(::getpid())) != std::string::npos, "collection reads the process");
    const auto stale_info = executor->execute(real_command("i2", command_action::collect_process_info, victim, ticks + 5U), false);
    require(stale_info.reason == "target_mismatch", "collection checks the identity too");

    const auto self = executor->execute(real_command("k3", command_action::kill_process, ::getpid(), start_of(::getpid())), false);
    require(self.outcome == "rejected" && self.reason == "target_protected", "the sensor never kills itself");
    const auto init = executor->execute(real_command("k4", command_action::kill_process, 1, 1), false);
    require(init.reason == "target_protected", "init is protected");

    const auto killed = executor->execute(real_command("k5", command_action::kill_process, victim, ticks), false);
    require(killed.outcome == "succeeded" && killed.reason == "ok" && killed.mode == "pidfd" && killed.affected == 1U, "the verified target is killed");
    int status = 0;
    require(::waitpid(victim, &status, 0) == victim && WIFSIGNALED(status), "it really died of a signal");

    const auto gone = executor->execute(real_command("k6", command_action::kill_process, victim, ticks), false);
    require(gone.outcome == "rejected" && (gone.reason == "target_gone" || gone.reason == "target_mismatch"), "a dead target is not signalled");

    const auto none = executor->execute(real_command("f1", command_action::isolate_host, 0, 0), false);
    require(none.outcome == "rejected" && none.reason == "isolation_unavailable", "isolation without a configured helper is refused by the executor");
}

// ---- network connection inventory ------------------------------------------------------------

bool has(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }

void test_connection_items() {
    const socket_entry listener{6U, 2U, 10U, "127.0.0.1", "0.0.0.0", 8080U, 0U, 77U, 1000U};
    const socket_entry client{6U, 2U, 1U, "10.0.0.5", "203.0.113.9", 40000U, 443U, 78U, 1000U};
    const socket_entry closing{6U, 10U, 6U, "::1", "::1", 5000U, 6000U, 0U, 0U};  // TIME_WAIT: no owner
    const socket_entry dns{17U, 2U, 7U, "0.0.0.0", "0.0.0.0", 53U, 0U, 79U, 101U};
    const socket_owner_map owners{{77U, {321U, 2U}}, {79U, {55U, 1U}}};
    const std::vector<socket_entry> sockets{client, dns, closing, listener};
    bool truncated = true;
    const auto items = connection_state_items(sockets, owners, 16U, truncated);
    require(!truncated && items.size() == 4U, "one item per socket");
    require(items[0] == "{\"protocol\":\"tcp\",\"family\":\"inet\",\"state\":\"listen\",\"local_address\":\"127.0.0.1\",\"local_port\":8080,"
                        "\"remote_address\":\"0.0.0.0\",\"remote_port\":0,\"uid\":1000,\"inode\":77,\"pid\":321,\"holders\":2}",
            "a listener with its owner");
    require(has(items[1], "\"state\":\"established\"") && has(items[1], "\"remote_port\":443") && has(items[1], "\"pid\":null"),
            "a socket the owner scan did not reach has no pid, not a guessed one");
    require(has(items[2], "\"family\":\"inet6\"") && has(items[2], "\"state\":\"time_wait\"") && has(items[2], "\"pid\":null"), "TIME_WAIT");
    require(has(items[3], "\"protocol\":\"udp\"") && has(items[3], "\"state\":\"bound\"") && has(items[3], "\"pid\":55"), "a bound UDP socket");
    for (const auto& item : items) require(parse_json(item, json_limits{}, nullptr).has_value(), "each item is a JSON object");
    require(connection_state_items({listener, closing, dns, client}, owners, 16U, truncated) == items, "the table's order does not matter");
    const auto bounded = connection_state_items(sockets, owners, 2U, truncated);
    require(truncated && bounded.size() == 2U && bounded[0] == items[0], "bounded, and the bound is stated");
    require(connection_summary(sockets, owners) == "tcp_listen=1 tcp_established=1 tcp_other=1 udp=1 attributed=2/4", "the result line");
    require(connection_summary({}, {}) == "tcp_listen=0 tcp_established=0 tcp_other=0 udp=0 attributed=0/0", "an empty table");
}

void test_local_executor_collects_connections() {
    const int listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(listener >= 0, "socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof address;
    require(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0 && ::listen(listener, 1) == 0, "listen on loopback");
    require(::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0, "the port");
    const auto port = std::to_string(ntohs(address.sin_port));

    local_executor_options options;
    options.host_id = "host-1";
    options.owner_scan_budget = std::chrono::milliseconds{5000};
    const auto executor = make_local_executor(options);
    // A read: dry_run does not suppress it, and nothing about the host changes.
    const auto collected = executor->execute(real_command("n1", command_action::collect_network_connections, 0, 0), true);
    require(collected.outcome == "succeeded" && collected.reason == "ok" && collected.evidence != nullptr, "collected");
    const auto& evidence = *collected.evidence;
    require(evidence.object == "connections" && evidence.snapshot_id == "response-n1" && evidence.mechanism == "SOCKDIAG+PROCFS", "the snapshot names");
    require(collected.affected == evidence.items.size() && !evidence.items.empty(), "affected counts the sockets reported");
    require(has(collected.detail, "tcp_listen=") && has(collected.detail, " snapshot=response-n1") && collected.detail.size() <= 400U, "a bounded result line");
    const auto ours = std::find_if(evidence.items.begin(), evidence.items.end(), [&](const std::string& item) {
        return has(item, "\"local_address\":\"127.0.0.1\",\"local_port\":" + port + ",") && has(item, "\"state\":\"listen\"");
    });
    require(ours != evidence.items.end(), "our listener is in the table");
    require(has(*ours, "\"pid\":" + std::to_string(::getpid()) + ","), "and is attributed to this process");

    options.maximum_connections = 1U;
    const auto bounded = make_local_executor(options)->execute(real_command("n2", command_action::collect_network_connections, 0, 0), false);
    require(bounded.outcome == "succeeded" && bounded.evidence->items.size() == 1U && bounded.affected == 1U, "bounded");
    require(!bounded.evidence->unavailable.empty() && bounded.evidence->unavailable.front().field == "connections" &&
                bounded.evidence->unavailable.front().reason == unavailable_reason::truncated && has(bounded.detail, " truncated"),
            "and the bound is stated, never silent");
    ::close(listener);
}

void test_executor_survives_pid_reuse_race() {
    // A target that exits and whose pid is reused while commands arrive must never be hit: the
    // identity includes the start time, so every attempt after the exit is a mismatch or a gone.
    local_executor_options options;
    options.host_id = "host-1";
    options.kill_grace_ms = 200U;
    const auto executor = make_local_executor(options);
    for (int round = 0; round < 20; ++round) {
        const pid_t first = spawn_sleeper();
        const auto ticks = start_of(first);
        ::kill(first, SIGKILL);
        int status = 0;
        ::waitpid(first, &status, 0);
        const pid_t bystander = spawn_sleeper();
        const auto result = executor->execute(real_command("r" + std::to_string(round), command_action::kill_process, first, ticks), false);
        require(alive(bystander), "a process that is not the target survives");
        require(result.outcome == "rejected", "the stale identity is refused");
        ::kill(bystander, SIGKILL);
        ::waitpid(bystander, &status, 0);
    }
}

// ---- the exchange with a fake Manager -------------------------------------------------------

struct fake_manager final : command_transport {
    std::vector<post_response> poll_replies;
    std::vector<std::string> log;
    std::vector<std::string> results;
    post_status submit_status{post_status::answered};
    post_response poll() override {
        log.push_back("poll");
        if (poll_replies.empty()) {
            post_response reply;
            reply.status = post_status::answered;
            reply.body = "{\"commands\":[]}";
            return reply;
        }
        auto reply = poll_replies.front();
        poll_replies.erase(poll_replies.begin());
        return reply;
    }
    post_response accept(const std::string& id) override {
        log.push_back("accept:" + id);
        post_response reply;
        reply.status = post_status::answered;
        return reply;
    }
    post_response submit(const std::string& result) override {
        log.push_back("submit");
        results.push_back(result);
        post_response reply;
        reply.status = submit_status;
        reply.detail = "fake";
        return reply;
    }
};

post_response answered(const std::string& body) {
    post_response reply;
    reply.status = post_status::answered;
    reply.http_status = 200;
    reply.body = body;
    return reply;
}

struct channel_world {
    fs::path dir;
    fake_manager* manager{};
    fake_executor* executor{};
    std::unique_ptr<command_channel_provider> channel;
    record_queue queue{64U};

    explicit channel_world(const std::string& name) : dir{scratch(name)} {
        command_channel_options options;
        options.processor.agent_id = "agent-1";
        options.processor.host_id = "host-1";
        options.processor.policy.mode = response_mode::enforce;
        options.processor.now_unix = [] { return now_fixed; };
        options.ledger_path = dir / "commands";
        options.poll_interval_ms = 1000U;
        auto transport = std::make_unique<fake_manager>();
        auto execute = std::make_unique<fake_executor>();
        manager = transport.get();
        executor = execute.get();
        channel = std::make_unique<command_channel_provider>(std::move(options), std::move(transport), std::move(execute));
        require(succeeded(channel->prepare(queue)), "the channel prepares");
    }
    ~channel_world() { fs::remove_all(dir); }

    std::vector<raw_response_action> drain() {
        std::vector<raw_record> records;
        queue.pop_batch(records, 64U, std::chrono::milliseconds{1});
        std::vector<raw_response_action> out;
        for (const auto& record : records) out.push_back(std::get<raw_response_action>(record.payload));
        return out;
    }
};

std::string listing(const std::vector<std::string>& commands) {
    std::string text = "{\"commands\":[";
    for (std::size_t index = 0; index < commands.size(); ++index) text += (index == 0U ? "" : ",") + commands[index];
    return text + "]}";
}

const std::string valid_command = envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00+00:00", "2027-01-15T08:00:00+00:00");

void test_channel_round_trip() {
    channel_world w{"round-trip"};
    w.manager->poll_replies.push_back(answered(listing({valid_command})));
    const auto wait = w.channel->step(w.queue);
    require(wait == 1000U, "the next poll is one interval away");
    require(w.manager->log == (std::vector<std::string>{"poll", "accept:c1", "submit"}), "poll, then accept, then the result");
    require(w.executor->calls == std::vector<std::string>{"c1"}, "executed once");
    const auto document = parse_json(w.manager->results.at(0), json_limits{}, nullptr);
    require(*document->find("outcome")->as_string() == "succeeded" && *document->find("command_id")->as_string() == "c1", "the result names the command");
    const auto audit = w.drain();
    require(audit.size() == 1U && audit[0].command_id == "c1" && audit[0].pid == 4242U && audit[0].start_ticks == 99U && audit[0].executed,
            "one audit record, carrying the target identity");
    require(w.channel->metrics().results_reported == 1U && w.channel->metrics().executed == 1U, "metrics");

    // The Manager sends it again (accept was lost): nothing runs, accept is repeated, no new audit.
    w.manager->poll_replies.push_back(answered(listing({valid_command})));
    w.manager->log.clear();
    (void)w.channel->step(w.queue);
    require(w.executor->calls.size() == 1U, "a redelivered command does not run again");
    require(w.manager->log == (std::vector<std::string>{"poll", "accept:c1"}), "it is accepted again, and nothing is re-sent");
    require(w.drain().empty(), "and is not audited twice");
}

void test_channel_retries_the_result() {
    channel_world w{"retry"};
    w.manager->submit_status = post_status::retry;
    w.manager->poll_replies.push_back(answered(listing({valid_command})));
    (void)w.channel->step(w.queue);
    require(w.manager->results.size() == 1U && w.channel->metrics().result_failures == 1U, "the first delivery failed");
    require(w.channel->metrics().results_reported == 0U, "so it is not reported");
    // The Manager does not redeliver an accepted command; the channel itself repeats the answer.
    w.manager->submit_status = post_status::answered;
    (void)w.channel->step(w.queue);
    require(w.manager->results.size() == 2U && w.manager->results[0] == w.manager->results[1], "the same result is sent again, byte for byte");
    require(w.executor->calls.size() == 1U, "and the command did not run again");
    require(w.channel->metrics().results_reported == 1U, "now reported");
    (void)w.channel->step(w.queue);
    require(w.manager->results.size() == 2U, "and never again after that");
}

void test_channel_refused_result_is_not_retried_forever() {
    channel_world w{"refused"};
    w.manager->submit_status = post_status::refused;
    w.manager->poll_replies.push_back(answered(listing({valid_command})));
    (void)w.channel->step(w.queue);
    require(w.channel->metrics().result_failures == 1U && w.channel->metrics().last_error.find("refused") != std::string::npos,
            "the refusal is counted and its reason is visible");
    (void)w.channel->step(w.queue);
    (void)w.channel->step(w.queue);
    require(w.manager->results.size() == 1U, "a result the Manager will never take is sent once");
}

void test_channel_restart_does_not_rerun() {
    const auto dir = scratch("restart");
    {
        channel_world first{"restart-a"};
        first.manager->submit_status = post_status::retry;  // the answer never reached the Manager
        first.manager->poll_replies.push_back(answered(listing({valid_command})));
        (void)first.channel->step(first.queue);
        require(first.executor->calls.size() == 1U, "ran once");
        fs::copy_file(first.dir / "commands", dir / "commands");
    }
    // A new process, the old ledger.
    command_channel_options options;
    options.processor.agent_id = "agent-1";
    options.processor.host_id = "host-1";
    options.processor.policy.mode = response_mode::enforce;
    options.processor.now_unix = [] { return now_fixed; };
    options.ledger_path = dir / "commands";
    auto transport = std::make_unique<fake_manager>();
    auto execute = std::make_unique<fake_executor>();
    auto* manager = transport.get();
    auto* executor = execute.get();
    command_channel_provider restarted{std::move(options), std::move(transport), std::move(execute)};
    record_queue queue{16U};
    require(succeeded(restarted.prepare(queue)), "prepares");
    manager->poll_replies.push_back(answered(listing({valid_command})));
    (void)restarted.step(queue);
    require(executor->calls.empty(), "a restart does not run a command that already ran");
    require(manager->results.size() == 1U, "the stored result is sent (it was never acknowledged)");
    fs::remove_all(dir);
}

void test_channel_failures_and_hostile_replies() {
    channel_world w{"hostile"};
    post_response unauthorized;
    unauthorized.status = post_status::unauthorized;
    w.manager->poll_replies.push_back(unauthorized);
    require(w.channel->step(w.queue) >= 2000U, "a refused credential backs off");
    require(w.channel->health().state == "degraded", "and is visible in health");
    post_response down;
    down.status = post_status::retry;
    down.detail = "transport: timeout";
    w.manager->poll_replies.push_back(down);
    const auto second_wait = w.channel->step(w.queue);
    require(second_wait > 2000U, "the backoff grows");
    w.manager->poll_replies.push_back(answered(listing({valid_command})));
    require(w.channel->step(w.queue) == 1000U && w.channel->health().state == "active", "and resets when the Manager answers");
    w.executor->calls.clear();

    for (const char* body : {"not json", "[]", "{\"commands\":5}", "{\"commands\":[],\"x\":1}", "{\"commands\":[{}]}", ""}) {
        w.manager->poll_replies.push_back(answered(body));
        (void)w.channel->step(w.queue);
    }
    require(w.executor->calls.empty(), "no hostile reply reaches the executor");

    // An unreadable command whose id is readable is closed with a rejection.
    const auto unknown_action = envelope("weird1", "RUN_SHELL", "{\"cmd\":\"id\"}", "2027-01-15T08:05:00Z");
    w.manager->results.clear();
    w.manager->poll_replies.push_back(answered(listing({unknown_action})));
    (void)w.channel->step(w.queue);
    require(w.manager->results.size() == 1U && w.executor->calls.empty(), "refused, not run");
    const auto document = parse_json(w.manager->results[0], json_limits{}, nullptr);
    require(*document->find("outcome")->as_string() == "rejected" && *document->find("command_id")->as_string() == "weird1", "with a rejection for that command");
    // One with no usable id cannot be answered at all.
    w.manager->results.clear();
    w.manager->poll_replies.push_back(answered(listing({"{\"command_id\":\"a/b\"}"})));
    (void)w.channel->step(w.queue);
    require(w.manager->results.empty(), "nothing to address, nothing sent");
}

void test_channel_mixed_batch() {
    channel_world w{"mixed"};
    const auto other_host = envelope("c2", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00+00:00", "2027-01-15T08:00:00+00:00", "agent-1", "someone-else");
    const auto expired = envelope("c3", "KILL_PROCESS", kill_target, "2027-01-15T07:00:00+00:00", "2027-01-15T06:59:00+00:00");
    w.manager->poll_replies.push_back(answered(listing({valid_command, other_host, expired})));
    (void)w.channel->step(w.queue);
    require(w.executor->calls == std::vector<std::string>{"c1"}, "only the valid command ran");
    require(w.manager->results.size() == 3U, "each command got its own answer");
    const auto audit = w.drain();
    require(audit.size() == 3U && audit[1].reason == "wrong_endpoint" && audit[2].reason == "expired", "and its own audit record");
}

// ---- boot-bound targets (schema 2) ----------------------------------------------------------

void test_boot_bound_commands() {
    const auto digest = linux_boot_digest(test_kernel_boot);
    require(digest.size() == 69U && digest.rfind("boot_", 0) == 0U, "boot_ + 64 hex");
    require(digest == linux_boot_digest(test_kernel_boot), "deterministic");
    require(digest != linux_boot_digest(other_kernel_boot), "another boot, another scope");
    require(linux_boot_digest("").empty() && linux_boot_digest(test_kernel_boot + "\n").empty() &&
                linux_boot_digest("A4D9D0E1-C8D8-4A67-A703-BDF6F6F01263").empty() && linux_boot_digest("not-a-uuid").empty(),
            "only the kernel's exact text form is digested; nothing is normalised into a match");

    const std::string expires = "2027-01-15T08:05:00Z";
    const auto parsed = as_command(parse_one(schema2(envelope("b1", "KILL_PROCESS", bound_target(digest), expires))));
    require(parsed.pid == 4242U && parsed.start_ticks == 99U && parsed.boot_id == digest, "a schema-2 kill");
    const auto max = as_command(parse_one(schema2(envelope("b2", "COLLECT_PROCESS_INFO", bound_target(digest, "\"18446744073709551615\""), expires))));
    require(max.start_ticks == 18446744073709551615ULL, "the uint64 maximum");
    const auto legacy = as_command(parse_one(envelope("b3", "KILL_PROCESS", kill_target, expires)));
    require(legacy.boot_id.empty(), "schema 1 carries no boot scope");

    const auto reason = [&](const std::string& action, const std::string& target) {
        return as_unreadable(parse_one(schema2(envelope("b9", action, target, expires)))).reason;
    };
    for (const char* ticks : {"99", "\"0\"", "\"099\"", "\"+99\"", "\"9e2\"", "\" 99\"", "\"\"", "\"18446744073709551616\"", "\"99999999999999999999\""}) {
        require(reason("KILL_PROCESS", bound_target(digest, ticks)) == "invalid_target", "ticks must be a canonical positive uint64 string");
    }
    require(reason("KILL_PROCESS", bound_target("boot_" + std::string(63U, 'a'))) == "invalid_target", "a short boot scope");
    require(reason("KILL_PROCESS", bound_target("boot_" + std::string(64U, 'A'))) == "invalid_target", "an upper-case boot scope");
    require(reason("KILL_PROCESS", bound_target(test_kernel_boot)) == "invalid_target", "a raw kernel boot id is not a scope");
    require(reason("KILL_PROCESS", kill_target) == "invalid_target", "schema 2 without a boot");
    require(reason("KILL_PROCESS", "{\"pid\":4242,\"start_time_ticks\":\"99\",\"boot_id\":\"" + digest + "\",\"x\":1}") == "invalid_target",
            "an extra field");
    require(reason("COLLECT_FILE", "{\"path\":\"/tmp/x\"}") == "invalid_target", "schema 2 is a process-target contract");
    require(reason("ISOLATE_HOST", "{}") == "invalid_target", "and has no targetless form");

    world w{"boot"};
    const auto bound = [&](const std::string& id, const std::string& boot) {
        return as_command(parse_one(schema2(envelope(id, "KILL_PROCESS", bound_target(boot), zulu(w.clock + 300), zulu(w.clock)))));
    };
    const auto ran = w.processor->handle(bound("same", digest));
    require(ran.outcome == "succeeded" && w.executor.calls.size() == 1U, "the current boot is acted on");
    const auto other = w.processor->handle(bound("prev", linux_boot_digest(other_kernel_boot)));
    require(other.reason == "boot_mismatch" && !other.executed && w.executor.calls.size() == 1U, "a target from another boot is refused");
    require(w.ledger->find("prev")->reason == "boot_mismatch", "and the refusal is remembered");
    // Boot scope is checked before expiry: a stale-boot command is reported as that, whatever else is wrong.
    auto stale = bound("prev-exp", linux_boot_digest(other_kernel_boot));
    stale.expires_unix = w.clock - 1;
    require(w.processor->handle(stale).reason == "boot_mismatch", "boot scope first");

    // A sensor that could not read its boot id refuses every boot-bound command.
    const fs::path dir = scratch("boot-unknown");
    auto ledger = open_ledger(dir / "commands", 16U);
    fake_executor executor;
    command_processor_options options;
    options.agent_id = "agent-1";
    options.host_id = "host-1";
    options.policy.mode = response_mode::enforce;
    options.now_unix = [&] { return w.clock; };
    command_processor blind{options, *ledger, executor};
    require(blind.handle(bound("u1", digest)).reason == "boot_unavailable" && executor.calls.empty(), "no boot identity, no boot-bound action");

    // With binding required, schema-1 process targets are refused; non-process actions are unaffected.
    options.boot_digest = digest;
    options.policy.require_boot_binding = true;
    auto ledger2 = open_ledger(dir / "commands2", 16U);
    command_processor strict{options, *ledger2, executor};
    require(strict.handle(w.make("s1")).reason == "boot_binding_required", "an unbound kill");
    require(strict.handle(w.make("s2", "COLLECT_PROCESS_INFO")).reason == "boot_binding_required", "an unbound collect");
    require(strict.handle(w.make("s3", "ISOLATE_HOST", "{}")).reason == "action_not_permitted", "non-process actions are unaffected");
    require(strict.handle(bound("s4", digest)).outcome == "succeeded", "a bound target runs");
    fs::remove_all(dir);
}

// ---- command authorization (ADR 025) ---------------------------------------------------------

std::string base64_encode_for_test(const std::uint8_t* data, const std::size_t size) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t index = 0; index < size; index += 3U) {
        const unsigned a = data[index];
        const unsigned b = index + 1U < size ? data[index + 1U] : 0U;
        const unsigned c = index + 2U < size ? data[index + 2U] : 0U;
        const unsigned group = (a << 16U) | (b << 8U) | c;
        out.push_back(alphabet[(group >> 18U) & 63U]);
        out.push_back(alphabet[(group >> 12U) & 63U]);
        out.push_back(index + 1U < size ? alphabet[(group >> 6U) & 63U] : '=');
        out.push_back(index + 2U < size ? alphabet[group & 63U] : '=');
    }
    return out;
}

ec_keypair make_key() {
    auto generated = generate_ec_p256_keypair();
    require(succeeded(generated), "a test key");
    return std::get<ec_keypair>(generated);
}

endpoint_command sign_command(endpoint_command command, const ec_keypair& key) {
    const auto input = command_signing_input(command);
    const auto signature = sign_raw(key, std::vector<std::uint8_t>(input.begin(), input.end()));
    require(succeeded(signature), "signing works");
    command_authorization authorization;
    authorization.algorithm = "ES256";
    authorization.key_id = signing_key_id(key.public_point);
    authorization.signature = std::get<ec_raw_signature>(signature);
    command.authorization = authorization;
    return command;
}

std::string authorization_json(const endpoint_command& command) {
    const auto& a = *command.authorization;
    return "{\"algorithm\":\"" + a.algorithm + "\",\"key_id\":\"" + a.key_id + "\",\"signature\":\"" +
           base64_encode_for_test(a.signature.data(), a.signature.size()) + "\"}";
}

void test_ecdsa_verify_and_base64() {
    const auto key = make_key();
    const auto other = make_key();
    const std::vector<std::uint8_t> data{'p', 'a', 'n'};
    const auto signature = sign_raw(key, data);
    require(succeeded(signature), "sign");
    const auto& raw = std::get<ec_raw_signature>(signature);
    const auto ok = verify_raw(key.public_point, data, raw);
    require(succeeded(ok) && std::get<bool>(ok), "a signature verifies under its own key");
    auto tampered = data;
    tampered[0] ^= 1U;
    const auto wrong_data = verify_raw(key.public_point, tampered, raw);
    require(succeeded(wrong_data) && !std::get<bool>(wrong_data), "other data does not");
    require(!std::get<bool>(verify_raw(other.public_point, data, raw)), "another key does not");
    auto flipped = raw;
    flipped[10] ^= 0x80U;
    require(!std::get<bool>(verify_raw(key.public_point, data, flipped)), "a damaged signature does not");
    require(!std::get<bool>(verify_raw(key.public_point, data, ec_raw_signature{})), "an all-zero signature does not (and does not crash)");
    ec_public_key_point off_curve = key.public_point;
    off_curve[40] ^= 1U;
    require(!succeeded(verify_raw(off_curve, data, raw)), "a point off the curve is an error, not a key that verifies nothing");
    ec_public_key_point compressed = key.public_point;
    compressed[0] = 0x02;
    require(!succeeded(verify_raw(compressed, data, raw)), "only the uncompressed form");

    const auto bytes = [](const char* text) { return decode_base64(text); };
    require(bytes("QQ==") && *bytes("QQ==") == std::vector<std::uint8_t>{'A'}, "padding");
    require(bytes("TWFu") && *bytes("TWFu") == std::vector<std::uint8_t>{'M', 'a', 'n'}, "no padding");
    for (const char* bad : {"", "QQ=", "Q===", "QR==", "QQ==QQ==", "QQ =", "QQ\n=", "QU-_", "QUJD=", "====", "Q Q=", "QQ=A"}) {
        require(!bytes(bad), bad);
    }
}

void test_signing_input_is_unambiguous() {
    const auto base = as_command(parse_one(envelope("c1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z", "2027-01-15T08:00:00Z")));
    const auto input = command_signing_input(base);
    require(input.rfind("panopticon-command-auth/1\n", 0) == 0U, "domain separation");
    const auto differs = [&](auto change, const char* what) {
        auto copy = base;
        change(copy);
        require(command_signing_input(copy) != input, what);
    };
    differs([](endpoint_command& c) { c.command_id = "c2"; }, "command id");
    differs([](endpoint_command& c) { c.correlation_id = "x"; }, "correlation id");
    differs([](endpoint_command& c) { c.agent_id = "agent-2"; }, "agent");
    differs([](endpoint_command& c) { c.host_id = "host-2"; }, "host");
    differs([](endpoint_command& c) { c.action = command_action::collect_process_info; }, "action");
    differs([](endpoint_command& c) { c.created_unix += 1; }, "created_at");
    differs([](endpoint_command& c) { c.expires_unix += 1; }, "expires_at");
    differs([](endpoint_command& c) { c.pid += 1U; }, "pid");
    differs([](endpoint_command& c) { c.start_ticks += 1U; }, "start ticks");
    differs([](endpoint_command& c) { c.boot_id = "boot_" + std::string(64U, 'a'); }, "boot scope (and schema version)");
    differs([](endpoint_command& c) { c.path = "/etc/shadow"; }, "path");
    // A value can not run into its neighbour: shifting characters between fields changes the input.
    auto left = base;
    auto right = base;
    left.command_id = "ab";
    left.correlation_id = "c";
    right.command_id = "a";
    right.correlation_id = "bc";
    require(command_signing_input(left) != command_signing_input(right), "length-prefixed fields do not collide");
    auto newline_a = base;
    auto newline_b = base;
    newline_a.path = "/a\npath:1:/b";
    newline_b.path = "/a";
    require(command_signing_input(newline_a) != command_signing_input(newline_b), "a path cannot forge a field");
}

void test_parse_authorization() {
    const auto key = make_key();
    const std::string expires = "2027-01-15T08:05:00Z";
    const std::string created = "2027-01-15T08:00:00Z";
    const auto plain = as_command(parse_one(envelope("a1", "KILL_PROCESS", kill_target, expires, created)));
    const auto signed_one = sign_command(plain, key);
    const auto with = [&](const std::string& authorization) {
        std::string text = envelope("a1", "KILL_PROCESS", kill_target, expires, created);
        text.insert(text.size() - 1U, ",\"authorization\":" + authorization);
        return parse_one(text);
    };
    const auto parsed = as_command(with(authorization_json(signed_one)));
    require(parsed.authorization && parsed.authorization->key_id == signed_one.authorization->key_id &&
                parsed.authorization->signature == signed_one.authorization->signature && parsed.authorization->algorithm == "ES256",
            "a well-formed authorization parses");
    require(!as_command(parse_one(envelope("a2", "KILL_PROCESS", kill_target, expires, created))).authorization, "none is none");

    const auto a = authorization_json(signed_one);
    const auto replace = [&](const std::string& from, const std::string& to) {
        auto text = a;
        text.replace(text.find(from), from.size(), to);
        return text;
    };
    const std::string good_key = signed_one.authorization->key_id;
    const std::string sig64 = base64_encode_for_test(signed_one.authorization->signature.data(), 64U);
    auto upper = good_key;
    upper[0] = 'A';
    const std::vector<std::pair<std::string, std::string>> bad{
        {"not an object", "\"abc\""},
        {"empty object", "{}"},
        {"extra member", a.substr(0U, a.size() - 1U) + ",\"x\":1}"},
        {"missing member", "{\"algorithm\":\"ES256\",\"key_id\":\"" + good_key + "\"}"},
        {"other algorithm", replace("ES256", "ES384")},
        {"none algorithm", replace("ES256", "none")},
        {"short key id", replace(good_key, good_key.substr(0U, 15U))},
        {"upper-case key id", replace(good_key, upper)},
        {"non-hex key id", replace(good_key, std::string(16U, 'z'))},
        {"signature too short", replace(sig64, base64_encode_for_test(signed_one.authorization->signature.data(), 63U))},
        {"signature not base64", replace(sig64, std::string(sig64.size(), '*'))},
        {"signature number", "{\"algorithm\":\"ES256\",\"key_id\":\"" + good_key + "\",\"signature\":5}"},
    };
    for (const auto& [why, text] : bad) {
        const auto outcome = with(text);
        require(std::holds_alternative<command_unreadable>(outcome) && std::get<command_unreadable>(outcome).reason == "invalid_authorization", why.c_str());
        require(std::get<command_unreadable>(outcome).command_id == "a1", "and the command stays addressable so the Manager can close it");
    }
}

// A processor with a pinned key, the way the sensor builds one.
struct signed_world {
    fs::path dir;
    fake_executor executor;
    std::unique_ptr<command_ledger> ledger;
    std::unique_ptr<command_processor> processor;
    std::int64_t clock{now_fixed};
    ec_keypair key{make_key()};
    std::shared_ptr<command_keyring> keyring;

    explicit signed_world(const std::string& name, std::vector<ec_public_key_point> trusted = {}, const bool require = false,
                          const bool pin_own_key = true)
        : dir{scratch(name)} {
        ledger = open_ledger(dir / "commands", 64U);
        if (pin_own_key) trusted.push_back(key.public_point);
        if (!trusted.empty()) keyring = std::shared_ptr<command_keyring>{command_keyring::from_points(trusted).release()};
        command_processor_options options;
        options.agent_id = "agent-1";
        options.host_id = "host-1";
        options.boot_digest = linux_boot_digest(test_kernel_boot);
        options.policy.mode = response_mode::enforce;
        options.policy.require_signature = require;
        options.keyring = keyring;
        options.now_unix = [this] { return clock; };
        processor = std::make_unique<command_processor>(std::move(options), *ledger, executor);
    }
    ~signed_world() { fs::remove_all(dir); }

    endpoint_command make(const std::string& id, const std::string& action = "KILL_PROCESS", const std::string& target = kill_target) const {
        return as_command(parse_one(envelope(id, action, target, zulu(clock + 300), zulu(clock))));
    }
};

void test_processor_requires_valid_signature() {
    signed_world w{"signed"};
    const auto refused = [&](const endpoint_command& command, const char* reason) {
        const auto outcome = w.processor->handle(command);
        require(outcome.outcome == "rejected" && outcome.reason == reason && !outcome.executed, reason);
        require(w.executor.calls.empty(), "a refused command never reaches the executor");
        require(w.ledger->find(command.command_id)->state == command_ledger::phase::done, "and the refusal is remembered");
    };
    refused(w.make("unsigned"), "signature_required");

    const auto foreign = make_key();
    refused(sign_command(w.make("foreign"), foreign), "unknown_signing_key");

    // Every field the endpoint acts on is covered: change one after signing and the signature no longer fits.
    const auto tamper = [&](const std::string& id, auto change, const char* what) {
        auto command = sign_command(w.make(id), w.key);
        change(command);
        const auto outcome = w.processor->handle(command);
        require(outcome.reason == "signature_invalid" && !outcome.executed, what);
    };
    tamper("t-pid", [](endpoint_command& c) { c.pid = 1234U; }, "a different pid");
    tamper("t-ticks", [](endpoint_command& c) { c.start_ticks = 100U; }, "different start ticks");
    tamper("t-exp", [](endpoint_command& c) { c.expires_unix += 600; }, "a longer life");
    tamper("t-act", [](endpoint_command& c) { c.action = command_action::collect_process_info; }, "another action");
    tamper("t-corr", [](endpoint_command& c) { c.correlation_id = "other"; }, "another correlation id");
    tamper("t-algo", [](endpoint_command& c) { c.authorization->algorithm = "ES384"; }, "another algorithm");
    auto damaged = sign_command(w.make("t-sig"), w.key);
    damaged.authorization->signature[3] ^= 1U;
    require(w.processor->handle(damaged).reason == "signature_invalid", "a damaged signature");

    // A signature cannot give a command a window it was not signed with.
    auto no_window = w.make("t-window");
    no_window.created_unix = 0;
    require(w.processor->handle(sign_command(no_window, w.key)).reason == "signature_invalid", "created_at is part of the signed window");

    require(w.executor.calls.empty(), "nothing above ran");
    const auto good = sign_command(w.make("good"), w.key);
    const auto ran = w.processor->handle(good);
    require(ran.outcome == "succeeded" && ran.executed && w.executor.calls.size() == 1U, "a signed command runs");
    const auto replay = w.processor->handle(good);
    require(replay.reason == "replay" && w.executor.calls.size() == 1U, "the same signed command is a replay");

    // The ledger holds a refused id, so a later correctly signed command with that id is a replay too: ids
    // are single-use whatever happened to them.
    require(w.processor->handle(sign_command(w.make("unsigned"), w.key)).reason == "replay", "a refused id is spent");
    // Wrong endpoint is still decided first.
    auto wrong_host = w.make("wh");
    wrong_host.host_id = "other-host";
    require(w.processor->handle(wrong_host).reason == "wrong_endpoint", "wrong endpoint is decided before the signature");
}

void test_processor_signature_policy() {
    // No key and signatures required: nothing runs, whatever the command carries.
    signed_world strict{"signed-strict", {}, true, false};
    require(strict.processor->handle(strict.make("s1")).reason == "signature_required", "required with no key pinned");
    require(strict.processor->handle(sign_command(strict.make("s2"), strict.key)).reason == "signature_required", "a signature nobody can check");
    require(strict.executor.calls.empty(), "nothing ran");
    // No key and not required (the explicit lab opt-out): unsigned commands are acted on, as before this change.
    signed_world lab{"signed-lab", {}, false, false};
    require(lab.processor->handle(lab.make("l1")).executed, "response_allow_unsigned keeps the TLS-only behaviour");
    // Several keys: rotation. A command signed by either runs.
    const auto old_key = make_key();
    const auto fresh = make_key();
    signed_world both{"signed-both", {old_key.public_point, fresh.public_point}, false, false};
    require(both.processor->handle(sign_command(both.make("r1"), old_key)).executed, "the old key");
    require(both.processor->handle(sign_command(both.make("r2"), fresh)).executed, "the new key");
    require(both.keyring->size() == 2U, "two keys pinned");
    require(both.processor->handle(sign_command(both.make("r3"), both.key)).reason == "unknown_signing_key", "a third key is not trusted");
}

void test_keyring_file_and_revocation() {
    const fs::path dir = scratch("keyring");
    const auto k1 = make_key();
    const auto k2 = make_key();
    const auto line = [](const ec_keypair& key, const char* label) {
        return base64_encode_for_test(key.public_point.data(), key.public_point.size()) + (label[0] != '\0' ? std::string{" "} + label : std::string{});
    };
    const auto write = [&](const std::string& text) {
        std::ofstream out{dir / "keys", std::ios::trunc};
        out << text;
    };
    write("# the command authority\n\n" + line(k1, "primary") + "\n  " + line(k2, "") + "  \n");
    auto loaded = command_keyring::load(dir / "keys");
    require(succeeded(loaded), "a file with comments, labels and blanks loads");
    auto ring = std::move(std::get<std::unique_ptr<command_keyring>>(loaded));
    require(ring->size() == 2U, "two keys");
    const auto ids = ring->key_ids();
    require(std::find(ids.begin(), ids.end(), signing_key_id(k1.public_point)) != ids.end(), "the id names the key");

    const auto command = as_command(parse_one(envelope("k1", "KILL_PROCESS", kill_target, "2027-01-15T08:05:00Z", "2027-01-15T08:00:00Z")));
    require(ring->check(sign_command(command, k1)) == authorization_verdict::valid, "key one");
    require(ring->check(sign_command(command, k2)) == authorization_verdict::valid, "key two");
    require(ring->check(command) == authorization_verdict::missing, "none");

    // Revocation by removal takes effect at the next refresh, with no restart.
    write("# rotated\n" + line(k2, "") + "\n");
    ring->refresh();
    require(ring->size() == 1U && ring->check(sign_command(command, k1)) == authorization_verdict::unknown_key, "a removed key is revoked");
    require(ring->check(sign_command(command, k2)) == authorization_verdict::valid && ring->last_error().empty(), "the other still works");

    // A damaged file keeps the keys in force and says so; it never widens trust.
    write("this is not a key\n" + line(k1, "") + "\n");
    ring->refresh();
    require(ring->size() == 1U && !ring->last_error().empty(), "an invalid file is reported and the previous keys stay");
    require(ring->check(sign_command(command, k1)) == authorization_verdict::unknown_key, "the key in the bad file was not adopted");
    write(line(k1, "") + "xx\n");
    ring->refresh();
    require(ring->size() == 1U && !ring->last_error().empty(), "a key with trailing junk is invalid");

    // An emptied file revokes everything.
    write("# no keys\n");
    ring->refresh();
    require(ring->size() == 0U && ring->check(sign_command(command, k2)) == authorization_verdict::unknown_key, "an empty file revokes all");

    require(!succeeded(command_keyring::load(dir / "missing")), "a missing file does not load");
    write("AAAA\n");
    require(!succeeded(command_keyring::load(dir / "keys")), "a short key does not load");
    ec_public_key_point off = k1.public_point;
    off[50] ^= 1U;
    write(base64_encode_for_test(off.data(), off.size()) + "\n");
    require(!succeeded(command_keyring::load(dir / "keys")), "a point off the curve does not load");
    fs::remove_all(dir);
}

void test_signature_covers_values_not_json_text() {
    // The signature travels as JSON and verifies against the parsed command.
    const auto key = make_key();
    const std::string expires = zulu(now_fixed + 300);
    const std::string created = zulu(now_fixed);
    const auto plain = as_command(parse_one(envelope("w1", "COLLECT_PROCESS_INFO", kill_target, expires, created)));
    const auto signed_one = sign_command(plain, key);
    std::string text = envelope("w1", "COLLECT_PROCESS_INFO", kill_target, expires, created);
    text.insert(text.size() - 1U, ",\"authorization\":" + authorization_json(signed_one));
    const auto parsed = as_command(parse_one(text));
    const auto ring = std::shared_ptr<command_keyring>{command_keyring::from_points({key.public_point}).release()};
    require(ring->check(parsed) == authorization_verdict::valid, "what arrives as JSON verifies");
    // The same JSON with the target edited does not.
    std::string edited = text;
    edited.replace(edited.find("4242"), 4U, "4243");
    require(ring->check(as_command(parse_one(edited))) == authorization_verdict::bad_signature, "an edited target fails");
    // Key order and spacing are the Manager's business and are not part of the signature.
    const std::string base = envelope("w1", "COLLECT_PROCESS_INFO", kill_target, expires, created);
    const std::string reordered = "{\"authorization\":" + authorization_json(signed_one) + "," + base.substr(1U);
    require(ring->check(as_command(parse_one(reordered))) == authorization_verdict::valid, "key order is not part of the signature");
}

// ---- configuration --------------------------------------------------------------------------

void test_configuration() {
    const std::string base = "sensor_id=s1\nhost_id=h1\nmanager_url=https://manager.example:8553\nidentity_path=/etc/panopticon/identity.json\n";
    auto config = parse_sensor_config(base);
    require(succeeded(config) && std::get<sensor_config>(config).response_mode == "off", "the channel is off by default");
    config = parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=dry_run\nresponse_actions=COLLECT_PROCESS_INFO\nresponse_poll_seconds=2\nresponse_max_changes_per_minute=3\n");
    require(succeeded(config), "dry_run parses");
    const auto& parsed = std::get<sensor_config>(config);
    require(parsed.response_mode == "dry_run" && parsed.response_actions == std::vector<std::string>{"COLLECT_PROCESS_INFO"} && parsed.response_poll_seconds == 2U,
            "values");
    require(!succeeded(parse_sensor_config(base + "response_mode=yes\n")), "a mode outside the vocabulary");
    require(!succeeded(parse_sensor_config(base + "response_actions=NO_SUCH_ACTION\n")), "an action outside the vocabulary cannot be listed");
    const std::string signed_base = base + "response_allow_unsigned=true\nresponse_mode=dry_run\n";
    const std::string both = "response_actions=ISOLATE_HOST,RELEASE_HOST_ISOLATION\n";
    require(succeeded(parse_sensor_config(signed_base + both + "response_isolation_socket=/run/panopticon/isolation.sock\n")),
            "isolation with a helper socket, both directions");
    require(!succeeded(parse_sensor_config(signed_base + both)), "isolation actions need a helper socket");
    require(!succeeded(parse_sensor_config(signed_base + "response_actions=ISOLATE_HOST\nresponse_isolation_socket=/run/x.sock\n")),
            "isolation cannot be listed without its release");
    require(!succeeded(parse_sensor_config(signed_base + "response_actions=RELEASE_HOST_ISOLATION\nresponse_isolation_socket=/run/x.sock\n")),
            "release alone is not a configuration either");
    require(!succeeded(parse_sensor_config(signed_base + "response_actions=COLLECT_PROCESS_INFO\nresponse_isolation_socket=/run/x.sock\n")),
            "a helper socket without the actions that use it");
    require(!succeeded(parse_sensor_config(signed_base + both + "response_isolation_socket=run/x.sock\n")), "a relative socket path");
    require(!succeeded(parse_sensor_config(signed_base + both + "response_isolation_socket=/run/../x.sock\n")), "a socket path with ..");
    require(!succeeded(parse_sensor_config(signed_base + both + "response_isolation_socket=/" + std::string(120U, 'a') + "\n")),
            "a socket path longer than sun_path");
    require(succeeded(parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=dry_run\nresponse_actions=COLLECT_NETWORK_CONNECTIONS,COLLECT_FILE\n")),
            "the implemented collections can be listed by name");
    require(!succeeded(parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=dry_run\nresponse_actions=QUARANTINE_FILE\n")),
            "QUARANTINE_FILE needs the directories it may act in");
    require(!succeeded(parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=dry_run\nresponse_actions=COLLECT_FILE\nresponse_file_roots=/tmp\n")),
            "directories without the action are a contradiction");
    auto file_config = parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=enforce\nresponse_actions=QUARANTINE_FILE,COLLECT_FILE\nresponse_file_roots=/tmp, /var/tmp\nresponse_quarantine_dir=/var/lib/panopticon/q\n");
    require(succeeded(file_config) && std::get<sensor_config>(file_config).response_file_roots.size() == 2U &&
                std::get<sensor_config>(file_config).response_quarantine_dir == "/var/lib/panopticon/q",
            "quarantine with its roots and store parses");
    for (const char* bad : {"/", "relative", "/a/../b", "/tmp,/tmp", ""}) {
        require(!succeeded(parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=enforce\nresponse_actions=QUARANTINE_FILE\nresponse_file_roots=" + bad + "\n")),
                "an unsafe root list is refused");
    }
    require(!succeeded(parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=enforce\nresponse_actions=QUARANTINE_FILE\nresponse_file_roots=/tmp\nresponse_quarantine_dir=store\n")),
            "a relative store path is refused");
    require(!succeeded(parse_sensor_config(base + "response_actions=KILL_PROCESS,KILL_PROCESS\n")), "a duplicate");
    require(!succeeded(parse_sensor_config(base + "response_actions=rm\n")), "an arbitrary name");
    require(!succeeded(parse_sensor_config(base + "response_poll_seconds=0\n")), "a zero interval");
    require(!succeeded(parse_sensor_config(base + "response_ledger_path=relative/path\n")), "a relative ledger path");
    require(!succeeded(parse_sensor_config(base + "response_ledger_path=/var/../etc/ledger\n")), "a traversing ledger path");
    require(!succeeded(parse_sensor_config("sensor_id=s1\nhost_id=h1\nresponse_mode=enforce\n")), "commands need a Manager to come from");
    require(succeeded(parse_sensor_config("sensor_id=s1\nhost_id=h1\n")), "a collection-only sensor is unchanged");
    config = parse_sensor_config(base + "response_allow_unsigned=true\nresponse_mode=enforce\nresponse_require_boot_binding=true\n");
    require(succeeded(config) && std::get<sensor_config>(config).response_require_boot_binding, "boot binding can be required");
    require(!succeeded(parse_sensor_config(base + "response_require_boot_binding=yes\n")), "a boolean is true or false");
    // Command authorization: a response mode needs pinned keys or an explicit unsigned opt-in, never neither.
    require(!succeeded(parse_sensor_config(base + "response_mode=dry_run\n")), "no keys and no opt-in: refused at configuration time");
    require(!succeeded(parse_sensor_config(base + "response_mode=enforce\n")), "enforce too");
    require(succeeded(parse_sensor_config(base + "response_mode=enforce\nresponse_signing_keys=/etc/panopticon/command-keys\n")), "pinned keys");
    require(!succeeded(parse_sensor_config(base + "response_mode=enforce\nresponse_signing_keys=/etc/panopticon/command-keys\nresponse_allow_unsigned=true\n")),
            "keys and the unsigned opt-in contradict each other");
    require(!succeeded(parse_sensor_config(base + "response_mode=enforce\nresponse_signing_keys=keys\n")), "a relative key path");
    require(!succeeded(parse_sensor_config(base + "response_mode=enforce\nresponse_signing_keys=/etc/../tmp/keys\n")), "a traversing key path");
    require(!succeeded(parse_sensor_config(base + "response_allow_unsigned=maybe\n")), "a boolean is true or false");
    require(succeeded(parse_sensor_config(base)), "off needs neither");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"timestamps", test_timestamps},
        {"parse_valid_commands", test_parse_valid_commands},
        {"parse_refusals", test_parse_refusals},
        {"parse_poll", test_parse_poll},
        {"parse_survives_garbage", test_parse_survives_garbage},
        {"ledger_persists_and_refuses_replay", test_ledger_persists_and_refuses_replay},
        {"ledger_corruption_and_tail", test_ledger_corruption_and_tail},
        {"ledger_bounds_and_compaction", test_ledger_bounds_and_compaction},
        {"processor_executes_once", test_processor_executes_once},
        {"processor_checks", test_processor_checks},
        {"processor_policy", test_processor_policy},
        {"processor_rate_limit", test_processor_rate_limit},
        {"processor_crash_recovery", test_processor_crash_recovery},
        {"processor_ledger_failure_is_fail_closed", test_processor_ledger_failure_is_fail_closed},
        {"processor_unreadable", test_processor_unreadable},
        {"result_json", test_result_json},
        {"response_record_shape", test_response_record_shape},
        {"local_executor_real_processes", test_local_executor_real_processes},
        {"connection_items", test_connection_items},
        {"local_executor_collects_connections", test_local_executor_collects_connections},
        {"executor_survives_pid_reuse_race", test_executor_survives_pid_reuse_race},
        {"channel_round_trip", test_channel_round_trip},
        {"channel_retries_the_result", test_channel_retries_the_result},
        {"channel_refused_result_is_not_retried_forever", test_channel_refused_result_is_not_retried_forever},
        {"channel_restart_does_not_rerun", test_channel_restart_does_not_rerun},
        {"channel_failures_and_hostile_replies", test_channel_failures_and_hostile_replies},
        {"channel_mixed_batch", test_channel_mixed_batch},
        {"boot_bound_commands", test_boot_bound_commands},
        {"ecdsa_verify_and_base64", test_ecdsa_verify_and_base64},
        {"signing_input_is_unambiguous", test_signing_input_is_unambiguous},
        {"parse_authorization", test_parse_authorization},
        {"processor_requires_valid_signature", test_processor_requires_valid_signature},
        {"processor_signature_policy", test_processor_signature_policy},
        {"keyring_file_and_revocation", test_keyring_file_and_revocation},
        {"signature_covers_values_not_json_text", test_signature_covers_values_not_json_text},
        {"configuration", test_configuration},
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
