#include "panopticon/linux_agent/sensor/command_channel.hpp"

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/response.hpp"
#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"
#include "panopticon/linux_agent/sensor/sockdiag_network.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::size_t maximum_command_id_bytes = 120U;  // "res-" + id must stay a valid 128-byte identifier
constexpr std::size_t maximum_path_bytes = 4096U;
constexpr std::size_t maximum_detail_bytes = 400U;

std::int64_t system_now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

bool command_id_ok(const std::string_view id) noexcept { return id.size() <= maximum_command_id_bytes && is_valid_identifier(id); }

// Printable ASCII only, bounded: details travel to the Manager and into records.
std::string clean(const std::string_view text, const std::size_t maximum = maximum_detail_bytes) {
    std::string out;
    out.reserve(std::min(text.size(), maximum));
    for (const unsigned char c : text) {
        if (out.size() >= maximum) break;
        out.push_back(c >= 0x20U && c < 0x7FU ? static_cast<char>(c) : '?');
    }
    return out;
}

bool reason_code_ok(const std::string_view reason) noexcept {
    return !reason.empty() && reason.size() <= 48U &&
           std::all_of(reason.begin(), reason.end(), [](const char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
}

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
std::int64_t days_from_civil(std::int64_t year, const unsigned month, const unsigned day) noexcept {
    year -= month <= 2U ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto year_of_era = static_cast<unsigned>(year - era * 400);
    const unsigned day_of_year = (153U * (month + (month > 2U ? -3 : 9)) + 2U) / 5U + day - 1U;
    const unsigned day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
    return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

}  // namespace

const char* to_string(const response_mode mode) noexcept {
    switch (mode) {
        case response_mode::off: return "off";
        case response_mode::dry_run: return "dry_run";
        case response_mode::enforce: return "enforce";
    }
    return "off";
}

std::optional<response_mode> parse_response_mode(const std::string_view text) noexcept {
    if (text == "off") return response_mode::off;
    if (text == "dry_run") return response_mode::dry_run;
    if (text == "enforce") return response_mode::enforce;
    return std::nullopt;
}

const char* to_string(const command_action action) noexcept {
    switch (action) {
        case command_action::kill_process: return "KILL_PROCESS";
        case command_action::collect_process_info: return "COLLECT_PROCESS_INFO";
        case command_action::collect_network_connections: return "COLLECT_NETWORK_CONNECTIONS";
        case command_action::collect_file: return "COLLECT_FILE";
        case command_action::quarantine_file: return "QUARANTINE_FILE";
        case command_action::isolate_host: return "ISOLATE_HOST";
        case command_action::release_host_isolation: return "RELEASE_HOST_ISOLATION";
    }
    return "KILL_PROCESS";
}

std::optional<command_action> parse_command_action(const std::string_view text) noexcept {
    for (const auto action : {command_action::kill_process, command_action::collect_process_info,
                              command_action::collect_network_connections, command_action::collect_file,
                              command_action::quarantine_file, command_action::isolate_host,
                              command_action::release_host_isolation}) {
        if (text == to_string(action)) return action;
    }
    return std::nullopt;
}

bool command_action_implemented(const command_action action) noexcept {
    return action == command_action::kill_process || action == command_action::collect_process_info ||
           action == command_action::collect_network_connections || action == command_action::collect_file ||
           action == command_action::quarantine_file || action == command_action::isolate_host ||
           action == command_action::release_host_isolation;
}

bool command_action_changes_host(const command_action action) noexcept {
    return action == command_action::kill_process || action == command_action::quarantine_file ||
           action == command_action::isolate_host || action == command_action::release_host_isolation;
}

std::optional<std::int64_t> parse_utc_offset_timestamp(const std::string_view text) noexcept {
    // YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)
    if (text.size() < 20U || text.size() > 40U) return std::nullopt;
    const auto digits = [&](const std::size_t offset, const std::size_t count) -> std::optional<int> {
        int number = 0;
        for (std::size_t index = 0; index < count; ++index) {
            const char c = text[offset + index];
            if (c < '0' || c > '9') return std::nullopt;
            number = number * 10 + (c - '0');
        }
        return number;
    };
    if (text[4] != '-' || text[7] != '-' || (text[10] != 'T' && text[10] != 't') || text[13] != ':' || text[16] != ':') return std::nullopt;
    const auto year = digits(0U, 4U);
    const auto month = digits(5U, 2U);
    const auto day = digits(8U, 2U);
    const auto hour = digits(11U, 2U);
    const auto minute = digits(14U, 2U);
    const auto second = digits(17U, 2U);
    if (!year || !month || !day || !hour || !minute || !second) return std::nullopt;
    if (*year < 1970 || *month < 1 || *month > 12 || *day < 1 || *hour > 23 || *minute > 59 || *second > 59) return std::nullopt;
    static constexpr std::array<int, 12> month_days{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (*year % 4 == 0 && *year % 100 != 0) || *year % 400 == 0;
    if (*day > month_days[static_cast<std::size_t>(*month - 1)] + (*month == 2 && leap ? 1 : 0)) return std::nullopt;
    std::size_t cursor = 19U;
    if (text[cursor] == '.') {
        ++cursor;
        const auto begin = cursor;
        while (cursor < text.size() && text[cursor] >= '0' && text[cursor] <= '9') ++cursor;
        if (cursor == begin) return std::nullopt;
    }
    std::int64_t offset_seconds = 0;
    if (cursor < text.size() && (text[cursor] == 'Z' || text[cursor] == 'z')) {
        ++cursor;
    } else if (cursor + 6U == text.size() && (text[cursor] == '+' || text[cursor] == '-') && text[cursor + 3U] == ':') {
        const auto offset_hour = digits(cursor + 1U, 2U);
        const auto offset_minute = digits(cursor + 4U, 2U);
        if (!offset_hour || !offset_minute || *offset_hour > 23 || *offset_minute > 59) return std::nullopt;
        offset_seconds = (*offset_hour * 3600 + *offset_minute * 60) * (text[cursor] == '-' ? -1 : 1);
        cursor += 6U;
    } else {
        return std::nullopt;  // no zone
    }
    if (cursor != text.size()) return std::nullopt;
    const auto days = days_from_civil(*year, static_cast<unsigned>(*month), static_cast<unsigned>(*day));
    return days * 86400 + *hour * 3600 + *minute * 60 + *second - offset_seconds;
}

namespace {

std::optional<std::string> string_member(const json_value& object, const char* key) {
    const auto* member = object.find(key);
    if (member == nullptr) return std::nullopt;
    const auto text = member->as_string();
    if (!text) return std::nullopt;
    return std::string{*text};
}

// "1".."18446744073709551615": no sign, no leading zero, no exponent, no spaces.
std::optional<std::uint64_t> parse_canonical_uint64(const std::string_view text) noexcept {
    if (text.empty() || text.size() > 20U || text.front() == '0') return std::nullopt;
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        const auto digit = static_cast<std::uint64_t>(c - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) return std::nullopt;
        value = value * 10U + digit;
    }
    return value;
}

bool boot_digest_ok(const std::string_view text) noexcept {
    if (text.size() != 69U || text.substr(0U, 5U) != "boot_") return false;
    return std::all_of(text.begin() + 5, text.end(), [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

}  // namespace

parsed_command parse_endpoint_command(const json_value& value) {
    command_unreadable failure;
    if (!value.is_object()) {
        failure.reason = "not_an_object";
        return failure;
    }
    // Whatever else is wrong, say which command it was when its id is readable, so the Manager can
    // close that one command instead of redelivering it.
    if (const auto id = string_member(value, "command_id"); id && command_id_ok(*id)) failure.command_id = *id;
    if (const auto correlation = string_member(value, "correlation_id"); correlation && command_id_ok(*correlation)) {
        failure.correlation_id = *correlation;
    }
    static constexpr std::array<std::string_view, 10U> allowed{"command_id", "agent_id", "host_id", "schema_version", "action",
                                                               "expires_at", "created_at", "correlation_id", "target", "authorization"};
    for (const auto& key : value.keys()) {
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            failure.reason = "unknown_field";
            return failure;
        }
    }
    const auto fail = [&](const char* reason) -> parsed_command {
        failure.reason = reason;
        return failure;
    };
    endpoint_command command;
    const auto id = string_member(value, "command_id");
    const auto agent = string_member(value, "agent_id");
    const auto host = string_member(value, "host_id");
    const auto correlation = string_member(value, "correlation_id");
    const auto version = string_member(value, "schema_version");
    const auto action_text = string_member(value, "action");
    const auto expires = string_member(value, "expires_at");
    if (!id || !command_id_ok(*id) || !agent || !is_valid_identifier(*agent) || !host || !is_valid_identifier(*host) || !correlation ||
        !command_id_ok(*correlation)) {
        return fail("invalid_envelope");
    }
    if (!version || (*version != "1" && *version != "2")) return fail("unsupported_schema_version");
    const bool boot_bound = *version == "2";
    if (!action_text) return fail("invalid_envelope");
    const auto action = parse_command_action(*action_text);
    if (!action) return fail("unknown_action");
    if (!expires) return fail("invalid_envelope");
    const auto expires_unix = parse_utc_offset_timestamp(*expires);
    if (!expires_unix) return fail("invalid_expiry");
    command.command_id = *id;
    command.agent_id = *agent;
    command.host_id = *host;
    command.correlation_id = *correlation;
    command.action = *action;
    command.expires_unix = *expires_unix;
    if (const auto* created = value.find("created_at"); created != nullptr) {
        const auto text = created->as_string();
        const auto parsed = text ? parse_utc_offset_timestamp(*text) : std::nullopt;
        if (!parsed) return fail("invalid_created_at");
        command.created_unix = *parsed;
    }
    if (const auto* authorization = value.find("authorization"); authorization != nullptr) {
        // A closed object: an extra member is a refusal, as everywhere else in the envelope.
        const auto& members = authorization->keys();
        if (!authorization->is_object() || members.size() != 3U) return fail("invalid_authorization");
        const auto algorithm = string_member(*authorization, "algorithm");
        const auto key_id = string_member(*authorization, "key_id");
        const auto signature = string_member(*authorization, "signature");
        if (!algorithm || !key_id || !signature) return fail("invalid_authorization");
        if (*algorithm != "ES256" || key_id->size() != 16U) return fail("invalid_authorization");
        if (!std::all_of(key_id->begin(), key_id->end(), [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) {
            return fail("invalid_authorization");
        }
        const auto raw = decode_base64(*signature);
        if (!raw || raw->size() != 64U) return fail("invalid_authorization");
        command_authorization parsed;
        parsed.algorithm = std::string{*algorithm};
        parsed.key_id = std::string{*key_id};
        std::copy(raw->begin(), raw->end(), parsed.signature.begin());
        command.authorization = std::move(parsed);
    }
    const auto* target = value.find("target");
    if (target == nullptr || !target->is_object()) return fail("invalid_target");
    const auto& names = target->keys();
    const auto only = [&](std::initializer_list<std::string_view> expected) {
        if (names.size() != expected.size()) return false;
        return std::all_of(names.begin(), names.end(), [&](const std::string& name) {
            return std::find(expected.begin(), expected.end(), name) != expected.end();
        });
    };
    switch (*action) {
        case command_action::kill_process:
        case command_action::collect_process_info: {
            if (boot_bound) {
                // Schema 2: ticks are a canonical decimal string (the Windows uint64 creation-time form),
                // and the boot scope is exact. Nothing is coerced.
                if (!only({"pid", "start_time_ticks", "boot_id"})) return fail("invalid_target");
                const auto pid = target->find("pid")->as_unsigned();
                const auto ticks_text = target->find("start_time_ticks")->as_string();
                const auto boot = target->find("boot_id")->as_string();
                const auto ticks = ticks_text ? parse_canonical_uint64(*ticks_text) : std::nullopt;
                if (!pid || *pid == 0U || *pid > std::numeric_limits<std::uint32_t>::max() || !ticks || *ticks == 0U || !boot ||
                    !boot_digest_ok(*boot)) {
                    return fail("invalid_target");
                }
                command.pid = static_cast<std::uint32_t>(*pid);
                command.start_ticks = *ticks;
                command.boot_id = std::string{*boot};
                break;
            }
            if (!only({"pid", "start_time_ticks"})) return fail("invalid_target");
            const auto pid = target->find("pid")->as_unsigned();
            const auto ticks = target->find("start_time_ticks")->as_unsigned();
            if (!pid || !ticks || *pid == 0U || *pid > std::numeric_limits<std::uint32_t>::max() || *ticks == 0U) {
                return fail("invalid_target");
            }
            command.pid = static_cast<std::uint32_t>(*pid);
            command.start_ticks = *ticks;
            break;
        }
        case command_action::collect_file:
        case command_action::quarantine_file: {
            if (boot_bound) return fail("invalid_target");  // schema 2 is a process-target contract
            if (!only({"path"})) return fail("invalid_target");
            const auto path = target->find("path")->as_string();
            if (!path || path->empty() || path->size() > maximum_path_bytes || path->find('\0') != std::string_view::npos) {
                return fail("invalid_target");
            }
            command.path = std::string{*path};
            break;
        }
        default:
            if (boot_bound || !names.empty()) return fail("invalid_target");
            break;
    }
    return command;
}

std::string linux_boot_digest(const std::string_view kernel_boot_id) {
    if (kernel_boot_id.size() != 36U) return {};
    for (std::size_t index = 0; index < kernel_boot_id.size(); ++index) {
        const char c = kernel_boot_id[index];
        const bool dash = index == 8U || index == 13U || index == 18U || index == 23U;
        if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return {};
    }
    return "boot_" + sha256_hex(kernel_boot_id);
}

command_poll parse_command_poll(const std::string_view body, const std::size_t maximum_commands) {
    command_poll poll;
    std::string why;
    json_limits limits;
    limits.maximum_bytes = 256U * 1024U;
    limits.maximum_depth = 8U;
    limits.maximum_values = 4096U;
    const auto document = parse_json(body, limits, &why);
    if (!document || !document->is_object() || document->keys().size() != 1U || document->keys().front() != "commands") {
        poll.malformed = true;
        poll.why = document ? "the reply is not a command list" : "the reply is not valid JSON: " + clean(why, 120U);
        return poll;
    }
    const auto* list = document->find("commands");
    if (list == nullptr || !list->is_array() || list->items().size() > maximum_commands) {
        poll.malformed = true;
        poll.why = "the command list is missing or longer than the bound";
        return poll;
    }
    for (const auto& item : list->items()) poll.commands.push_back(parse_endpoint_command(item));
    return poll;
}

// ---- ledger ---------------------------------------------------------------------------------

namespace {

std::vector<std::string> split_tabs(const std::string_view line) {
    std::vector<std::string> parts;
    std::size_t begin = 0U;
    while (true) {
        const auto tab = line.find('\t', begin);
        if (tab == std::string_view::npos) {
            parts.emplace_back(line.substr(begin));
            break;
        }
        parts.emplace_back(line.substr(begin, tab - begin));
        begin = tab + 1U;
    }
    return parts;
}

std::optional<std::int64_t> parse_signed(const std::string& text) {
    if (text.empty() || text.size() > 19U) return std::nullopt;
    std::int64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + (c - '0');
    }
    return value;
}

}  // namespace

result<std::unique_ptr<command_ledger>> command_ledger::open(const std::filesystem::path& path, const std::size_t maximum_entries,
                                                             const std::int64_t now_unix) {
    if (maximum_entries == 0U || path.empty()) return error{error_code::invalid_input, "command ledger path or bound is invalid"};
    std::unique_ptr<command_ledger> ledger{new command_ledger()};
    ledger->path_ = path;
    ledger->maximum_entries_ = maximum_entries;
    std::error_code code;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), code);
    if (code) return error{error_code::io_failure, "cannot create the command ledger directory"};

    std::string contents;
    {
        std::ifstream input{path, std::ios::binary};
        if (input) {
            std::ostringstream buffer;
            buffer << input.rdbuf();
            contents = buffer.str();
        } else if (std::filesystem::exists(path, code)) {
            return error{error_code::io_failure, "cannot read the command ledger"};
        }
    }
    // A crash can leave one unterminated final line; it was never acknowledged, so it is dropped.
    // Anything else malformed is corruption, and a half-loaded ledger would let a command run twice.
    bool dropped_tail = false;
    if (!contents.empty() && contents.back() != '\n') {
        const auto last = contents.find_last_of('\n');
        contents.resize(last == std::string::npos ? 0U : last + 1U);
        dropped_tail = true;
    }
    std::istringstream lines{contents};
    for (std::string line; std::getline(lines, line);) {
        const auto parts = split_tabs(line);
        if (parts.size() < 2U || parts[0].size() != 1U || !command_id_ok(parts[1])) {
            return error{error_code::corrupt_data, "the command ledger has a malformed line"};
        }
        const auto& id = parts[1];
        switch (parts[0][0]) {
            case 'R': {
                if (parts.size() != 4U) return error{error_code::corrupt_data, "the command ledger has a malformed line"};
                const auto expires = parse_signed(parts[3]);
                if (!expires || !command_id_ok(parts[2])) return error{error_code::corrupt_data, "the command ledger has a malformed line"};
                entry made;
                made.expires_unix = *expires;
                made.correlation_id = parts[2];
                ledger->entries_[id] = made;
                break;
            }
            case 'D': {
                const auto found = ledger->entries_.find(id);
                if ((parts.size() != 4U && parts.size() != 5U) || found == ledger->entries_.end() || !reason_code_ok(parts[3]) ||
                    (parts[2] != "succeeded" && parts[2] != "failed" && parts[2] != "rejected" && parts[2] != "indeterminate")) {
                    return error{error_code::corrupt_data, "the command ledger has a malformed line"};
                }
                found->second.state = phase::done;
                found->second.outcome = parts[2];
                found->second.reason = parts[3];
                if (parts.size() == 5U) found->second.detail = parts[4];
                break;
            }
            case 'S': {
                const auto found = ledger->entries_.find(id);
                if (parts.size() != 2U || found == ledger->entries_.end() || found->second.state != phase::done) {
                    return error{error_code::corrupt_data, "the command ledger has a malformed line"};
                }
                found->second.state = phase::reported;
                break;
            }
            default: return error{error_code::corrupt_data, "the command ledger has a malformed line"};
        }
    }
    constexpr std::int64_t keep_after_expiry = 86400;
    const std::size_t before = ledger->entries_.size();
    for (auto it = ledger->entries_.begin(); it != ledger->entries_.end();) {
        if (it->second.state == phase::reported && it->second.expires_unix + keep_after_expiry < now_unix) it = ledger->entries_.erase(it);
        else ++it;
    }
    if (ledger->entries_.size() > maximum_entries) return error{error_code::resource_limit, "the command ledger holds more commands than its bound"};
    if (ledger->entries_.size() != before || dropped_tail) {
        // Rewrite compactly through a temporary file, so a crash keeps either the old or the new ledger.
        const auto temporary = path.string() + ".tmp";
        const int out = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (out < 0) return error{error_code::io_failure, "cannot rewrite the command ledger"};
        std::string text;
        for (const auto& [id, item] : ledger->entries_) {
            text += "R\t" + id + "\t" + item.correlation_id + "\t" + std::to_string(item.expires_unix) + "\n";
            if (item.state != phase::received) {
                text += "D\t" + id + "\t" + item.outcome + "\t" + item.reason + (item.detail.empty() ? "" : "\t" + item.detail) + "\n";
            }
            if (item.state == phase::reported) text += "S\t" + id + "\n";
        }
        const bool wrote = ::write(out, text.data(), text.size()) == static_cast<ssize_t>(text.size()) && ::fdatasync(out) == 0;
        ::close(out);
        if (!wrote || std::rename(temporary.c_str(), path.c_str()) != 0) return error{error_code::io_failure, "cannot rewrite the command ledger"};
    }
    ledger->fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (ledger->fd_ < 0) return error{error_code::io_failure, "cannot open the command ledger for writing"};
    return ledger;
}

command_ledger::~command_ledger() {
    if (fd_ >= 0) ::close(fd_);
}

result<bool> command_ledger::append(const std::string_view line) {
    const auto* data = line.data();
    std::size_t left = line.size();
    while (left > 0U) {
        const auto written = ::write(fd_, data, left);
        if (written < 0) return error{error_code::io_failure, "cannot append to the command ledger"};
        data += written;
        left -= static_cast<std::size_t>(written);
    }
    // The ledger is the guard against running a command twice, so a record is on disk before the
    // action it protects begins.
    if (::fdatasync(fd_) != 0) return error{error_code::io_failure, "cannot sync the command ledger"};
    return true;
}

std::optional<command_ledger::entry> command_ledger::find(const std::string& command_id) const {
    std::lock_guard lock{mutex_};
    const auto found = entries_.find(command_id);
    if (found == entries_.end()) return std::nullopt;
    return found->second;
}

result<bool> command_ledger::mark_received(const std::string& command_id, const std::string& correlation_id, const std::int64_t expires_unix) {
    if (!command_id_ok(command_id) || !command_id_ok(correlation_id) || expires_unix <= 0) {
        return error{error_code::invalid_input, "command identity is invalid"};
    }
    std::lock_guard lock{mutex_};
    if (entries_.contains(command_id)) return false;
    if (entries_.size() >= maximum_entries_) return error{error_code::resource_limit, "the command ledger is full"};
    auto appended = append("R\t" + command_id + "\t" + correlation_id + "\t" + std::to_string(expires_unix) + "\n");
    if (!succeeded(appended)) return appended;
    entry made;
    made.expires_unix = expires_unix;
    made.correlation_id = correlation_id;
    entries_[command_id] = made;
    return true;
}

result<bool> command_ledger::mark_done(const std::string& command_id, const std::string_view outcome, const std::string_view reason,
                                       const std::string_view detail) {
    if (!reason_code_ok(reason) || (outcome != "succeeded" && outcome != "failed" && outcome != "rejected" && outcome != "indeterminate")) {
        return error{error_code::invalid_input, "command outcome is invalid"};
    }
    std::lock_guard lock{mutex_};
    const auto found = entries_.find(command_id);
    if (found == entries_.end()) return error{error_code::invalid_input, "the command is not in the ledger"};
    if (found->second.state != phase::received) return false;
    // Printable ASCII, no tab or newline: the stored detail is exactly what a repeat will send.
    const auto kept = clean(std::string{detail});
    auto appended = append("D\t" + command_id + "\t" + std::string{outcome} + "\t" + std::string{reason} + (kept.empty() ? "" : "\t" + kept) + "\n");
    if (!succeeded(appended)) return appended;
    found->second.state = phase::done;
    found->second.outcome = std::string{outcome};
    found->second.reason = std::string{reason};
    found->second.detail = kept;
    return true;
}

result<bool> command_ledger::mark_reported(const std::string& command_id) {
    std::lock_guard lock{mutex_};
    const auto found = entries_.find(command_id);
    if (found == entries_.end() || found->second.state != phase::done) return false;
    auto appended = append("S\t" + command_id + "\n");
    if (!succeeded(appended)) return appended;
    found->second.state = phase::reported;
    return true;
}

std::vector<std::pair<std::string, command_ledger::entry>> command_ledger::unreported() const {
    std::lock_guard lock{mutex_};
    std::vector<std::pair<std::string, entry>> out;
    for (const auto& [id, item] : entries_) {
        if (item.state == phase::done) out.emplace_back(id, item);
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.second.expires_unix < b.second.expires_unix; });
    return out;
}

std::size_t command_ledger::size() const {
    std::lock_guard lock{mutex_};
    return entries_.size();
}

// ---- local executor -------------------------------------------------------------------------

namespace {

class local_executor final : public command_executor {
public:
    explicit local_executor(local_executor_options options) : options_{std::move(options)} {}

    execution_result execute(const endpoint_command& command, const bool dry_run) override {
        switch (command.action) {
            case command_action::kill_process: return kill(command, dry_run);
            case command_action::collect_process_info: return collect(command);
            case command_action::collect_network_connections: return collect_connections(command);
            case command_action::collect_file: return from_file_result(collect_file(command.path, options_.files));
            case command_action::quarantine_file:
                return from_file_result(quarantine_file(command.path, command.command_id, dry_run, options_.files));
            case command_action::isolate_host: return isolation(command, dry_run, isolation_opcode::isolate);
            case command_action::release_host_isolation: return isolation(command, dry_run, isolation_opcode::release);
            default: return {"rejected", "unsupported_action", "this sensor does not carry out that action", {}, 0U, {}};
        }
    }

private:
    static execution_result from_file_result(const file_action_result& result) {
        execution_result out;
        out.outcome = result.outcome;
        out.reason = result.reason;
        out.detail = clean(result.detail);
        out.affected = result.affected;
        return out;
    }

    // The sensor never touches the firewall: it asks the privileged helper for one of two fixed opcodes and
    // reports what came back. Only the command id crosses the socket (ADR 004). A dry run proves the helper is
    // listening and sends nothing.
    execution_result isolation(const endpoint_command& command, const bool dry_run, const isolation_opcode opcode) const {
        const bool isolating = opcode == isolation_opcode::isolate;
        if (options_.isolation_socket.empty()) {
            return {"rejected", "isolation_unavailable", "no isolation helper is configured", {}, 0U, {}};
        }
        if (dry_run) {
            if (!isolation_helper_reachable(options_.isolation_socket)) {
                return {"rejected", "helper_unreachable", "the isolation helper is not listening; nothing sent", {}, 0U, {}};
            }
            return {"rejected", "dry_run", "helper reachable, nothing sent", {}, 0U, {}};
        }
        switch (exchange_isolation_request(options_.isolation_socket, opcode, command.command_id, options_.isolation_timeout)) {
            case isolation_exchange::accepted:
                return {"succeeded", "ok", isolating ? "the helper applied host isolation" : "the helper released host isolation", {}, 1U, {}};
            case isolation_exchange::refused:
                return {"failed", "helper_refused", "the isolation helper declined the request", {}, 0U, {}};
            case isolation_exchange::unreachable:
                return {"failed", "helper_unreachable", "the isolation helper is not listening", {}, 0U, {}};
            case isolation_exchange::no_answer:
                return {"indeterminate", "helper_no_answer",
                        "the request was sent and no answer came; whether the host is isolated is not known", {}, 0U, {}};
            case isolation_exchange::invalid: break;
        }
        return {"failed", "invalid_request", "the request could not be encoded for the isolation helper", {}, 0U, {}};
    }

    execution_result kill(const endpoint_command& command, const bool dry_run) const {
        // The identity is the pid together with the start time. respond_terminate_process takes a
        // pidfd, compares the start time it reads through procfs with the one the Manager named, and
        // signals through the pidfd only, so a pid that was handed to another process is never hit.
        process_identity target;
        target.host_id = options_.host_id;
        target.pid = command.pid;
        target.start_time_ticks = command.start_ticks;
        response_options options;
        options.proc_root = options_.proc_root;
        options.dry_run = dry_run;
        options.allow_pid_fallback = options_.allow_pid_fallback;
        options.escalate_to_kill = true;
        options.grace = std::chrono::milliseconds{std::max<std::uint32_t>(1U, options_.kill_grace_ms)};
        const auto outcome = respond_terminate_process(target, options);
        execution_result result;
        result.mode = outcome.mode;
        result.affected = static_cast<std::uint32_t>(outcome.affected.size());
        result.detail = clean(outcome.detail);
        switch (outcome.status) {
            case response_status::dry_run:
                result.outcome = "rejected";
                result.reason = "dry_run";
                result.detail = "verified, nothing sent (" + (outcome.mode.empty() ? std::string{"no signal path"} : outcome.mode) + ")";
                break;
            case response_status::terminated: result.outcome = "succeeded"; result.reason = "ok"; break;
            case response_status::signalled:
                result.outcome = "indeterminate";
                result.reason = "exit_not_observed";
                break;
            case response_status::already_gone: result.outcome = "rejected"; result.reason = "target_gone"; break;
            case response_status::refused_invalid: result.outcome = "rejected"; result.reason = "invalid_target"; break;
            case response_status::refused_protected: result.outcome = "rejected"; result.reason = "target_protected"; break;
            case response_status::refused_mismatch: result.outcome = "rejected"; result.reason = "target_mismatch"; break;
            case response_status::refused_limit: result.outcome = "rejected"; result.reason = "limit"; break;
            case response_status::failed:
                result.outcome = "failed";
                result.reason = outcome.mode.empty() ? "no_signal_path" : "signal_failed";
                break;
        }
        return result;
    }

    execution_result collect(const endpoint_command& command) const {
        const auto ticks = read_start_ticks(options_.proc_root, command.pid);
        if (!ticks) return {"rejected", "target_gone", "no process has that pid now", {}, 0U, {}};
        if (*ticks != command.start_ticks) return {"rejected", "target_mismatch", "the pid now belongs to a different process", {}, 0U, {}};
        procfs_limits limits;
        limits.collect_environment = false;
        const auto info = read_process(options_.proc_root, command.pid, limits);
        if (!succeeded(info)) return {"rejected", "target_gone", "the process exited while it was read", {}, 0U, {}};
        const auto& process = std::get<process_info>(info);
        // The identity was read twice: a process that was replaced in between is not the target.
        if (process.start_ticks != command.start_ticks) return {"rejected", "target_mismatch", "the pid was reused while it was read", {}, 0U, {}};
        std::string detail = "name=" + clean(process.comm, 32U) + " exe=" + clean(process.executable.path, 160U) +
                             " ppid=" + std::to_string(process.ppid) + " uid=" + std::to_string(process.creds.uids[1]) +
                             " threads=" + std::to_string(process.threads);
        // The full record (command line, ancestry, hashes) is the `response.action` event itself.
        return {"succeeded", "ok", clean(detail), {}, 1U, {}};
    }

    // Read-only: the socket tables now, each socket attributed to the process holding it where the
    // owner scan reaches it in its budget. The result line is a count; the table itself goes out as a
    // `state.connections` snapshot the response.action record names.
    execution_result collect_connections(const endpoint_command& command) const {
        auto tables = read_socket_tables(options_.maximum_connections + 1U);
        if (!succeeded(tables)) return {"failed", "collection_failed", clean(std::get<error>(tables).message), {}, 0U, {}};
        const auto& sockets = std::get<std::vector<socket_entry>>(tables);
        std::set<std::uint64_t> wanted;
        for (const auto& socket : sockets) {
            if (socket.inode != 0U) wanted.insert(socket.inode);
        }
        bool exhausted = false;
        const auto owners = scan_socket_owners(options_.proc_root, wanted, options_.owner_scan_budget, &exhausted);
        auto evidence = std::make_shared<response_evidence>();
        evidence->object = "connections";
        evidence->snapshot_id = "response-" + command.command_id;
        evidence->mechanism = "SOCKDIAG+PROCFS";
        bool truncated = false;
        evidence->items = connection_state_items(sockets, owners, options_.maximum_connections, truncated);
        if (truncated) evidence->unavailable.push_back({"connections", unavailable_reason::truncated});
        if (exhausted) evidence->unavailable.push_back({"connections.pid", unavailable_reason::budget_exceeded});
        std::string detail = connection_summary(sockets, owners) + " snapshot=" + evidence->snapshot_id;
        if (truncated) detail += " truncated";
        execution_result result{"succeeded", "ok", clean(detail), {}, static_cast<std::uint32_t>(evidence->items.size()), {}};
        result.evidence = std::move(evidence);
        return result;
    }

    local_executor_options options_;
};

}  // namespace

std::unique_ptr<command_executor> make_local_executor(local_executor_options options) {
    return std::make_unique<local_executor>(std::move(options));
}

// ---- processor ------------------------------------------------------------------------------

command_processor::command_processor(command_processor_options options, command_ledger& ledger, command_executor& executor)
    : options_{std::move(options)}, ledger_{ledger}, executor_{executor} {}

std::int64_t command_processor::now() const { return options_.now_unix ? options_.now_unix() : system_now_unix(); }

namespace {

command_outcome describe(const endpoint_command& command, std::string outcome, std::string reason, std::string detail) {
    command_outcome result;
    result.command_id = command.command_id;
    result.correlation_id = command.correlation_id;
    result.action = to_string(command.action);
    result.outcome = std::move(outcome);
    result.reason = std::move(reason);
    result.detail = clean(detail);
    result.pid = command.pid;
    result.start_ticks = command.start_ticks;
    result.path = command.path;
    return result;
}

}  // namespace

command_outcome command_processor::refuse(const endpoint_command& command, std::string reason, std::string detail, const bool record) {
    if (record) {
        // Remember the refusal so a redelivery of the same command is answered, not reconsidered.
        const auto made = ledger_.mark_received(command.command_id, command.correlation_id, std::max<std::int64_t>(command.expires_unix, 1));
        if (succeeded(made) && std::get<bool>(made)) (void)ledger_.mark_done(command.command_id, "rejected", reason, detail);
    }
    return describe(command, "rejected", std::move(reason), std::move(detail));
}

command_outcome command_processor::handle(const endpoint_command& command) {
    std::lock_guard lock{mutex_};
    const auto& policy = options_.policy;
    const auto current = now();

    if (command.agent_id != options_.agent_id || command.host_id != options_.host_id) {
        return refuse(command, "wrong_endpoint", "the command names a different agent or host", true);
    }
    // Who issued it comes before anything about what it asks for. A pinned key means every command must be
    // signed by one of them; with none pinned the endpoint was configured to accept unsigned commands, or
    // refuses everything.
    if (options_.keyring) {
        switch (options_.keyring->check(command)) {
            case authorization_verdict::valid: break;
            case authorization_verdict::missing:
                return refuse(command, "signature_required", "this endpoint acts only on commands signed by the Manager's command authority", true);
            case authorization_verdict::unknown_key:
                return refuse(command, "unknown_signing_key", "the command is signed with a key this endpoint does not trust", true);
            case authorization_verdict::unsigned_window:
                return refuse(command, "signature_invalid", "a signed command must carry created_at inside the signature", true);
            case authorization_verdict::bad_signature:
                return refuse(command, "signature_invalid", "the signature does not match the command", true);
        }
    } else if (policy.require_signature) {
        return refuse(command, "signature_required", "signed commands are required and no signing key is configured", true);
    }
    if (!command.boot_id.empty()) {
        if (options_.boot_digest.empty()) return refuse(command, "boot_unavailable", "this endpoint cannot establish its boot identity", true);
        if (command.boot_id != options_.boot_digest) {
            return refuse(command, "boot_mismatch", "the target was observed in a different boot of this host", true);
        }
    } else if (policy.require_boot_binding &&
               (command.action == command_action::kill_process || command.action == command_action::collect_process_info)) {
        return refuse(command, "boot_binding_required", "this endpoint acts only on boot-bound process targets", true);
    }
    if (command.expires_unix <= current) return refuse(command, "expired", "the command had expired before it was handled", true);
    if (command.created_unix > current + policy.clock_skew_seconds) {
        return refuse(command, "not_yet_valid", "the command claims to be issued in the future", true);
    }
    const auto issued_lifetime = command.created_unix > 0 ? command.expires_unix - command.created_unix : 0;
    if (command.expires_unix - current > policy.maximum_lifetime_seconds + policy.clock_skew_seconds ||
        issued_lifetime > policy.maximum_lifetime_seconds + policy.clock_skew_seconds) {
        return refuse(command, "lifetime_exceeded", "the command is valid for longer than this endpoint allows", true);
    }
    if (policy.mode == response_mode::off) return refuse(command, "response_disabled", "this endpoint does not act on commands", true);
    if (!command_action_implemented(command.action)) {
        return refuse(command, "unsupported_action", "this sensor does not carry out that action", true);
    }
    if (!policy.allowed.contains(command.action)) {
        return refuse(command, "action_not_permitted", "local policy does not permit that action", true);
    }
    const bool changes = command_action_changes_host(command.action);
    const bool dry_run = changes && policy.mode != response_mode::enforce;
    if (changes && !dry_run) {
        while (!change_times_.empty() && change_times_.front() <= current - 60) change_times_.pop_front();
        if (change_times_.size() >= policy.maximum_changes_per_minute) {
            return refuse(command, "rate_limited", "too many changing actions in the last minute", true);
        }
    }

    // The intent is on disk before the action begins. If this process dies mid-action the command is
    // answered `indeterminate` after the restart and never run a second time.
    const auto made = ledger_.mark_received(command.command_id, command.correlation_id, command.expires_unix);
    if (!succeeded(made)) return describe(command, "rejected", "ledger_unavailable", "the replay ledger cannot record the command");
    if (!std::get<bool>(made)) return describe(command, "rejected", "replay", "the command id was handled before");

    if (options_.on_accepted) options_.on_accepted(command);
    if (changes && !dry_run) change_times_.push_back(current);

    const auto done = executor_.execute(command, dry_run);
    auto result = describe(command, done.outcome, done.reason, done.detail);
    result.mode = done.mode;
    result.affected = done.affected;
    result.dry_run = dry_run;
    result.executed = true;
    result.evidence = done.evidence;
    (void)ledger_.mark_done(command.command_id, result.outcome, result.reason, result.detail);
    return result;
}

std::optional<command_outcome> command_processor::resume(const std::string& command_id, const std::string& correlation_id,
                                                          const endpoint_command* command) {
    std::lock_guard lock{mutex_};
    const auto entry = ledger_.find(command_id);
    if (!entry) return std::nullopt;
    command_outcome result;
    if (command != nullptr) result = describe(*command, "", "", "");
    result.command_id = command_id;
    result.correlation_id = entry->correlation_id.empty() ? correlation_id : entry->correlation_id;
    if (entry->state == command_ledger::phase::received) {
        result.outcome = "indeterminate";
        result.reason = "interrupted";
        result.detail = "the sensor stopped while this command was being carried out; whether it took effect is not known";
        (void)ledger_.mark_done(command_id, result.outcome, result.reason, result.detail);
    } else {
        result.outcome = entry->outcome;
        result.reason = entry->reason;
        result.detail = entry->detail;
    }
    return result;
}

command_outcome command_processor::unreadable(const command_unreadable& failure) {
    std::lock_guard lock{mutex_};
    command_outcome result;
    result.command_id = failure.command_id;
    result.correlation_id = failure.correlation_id;
    result.action = "UNKNOWN";
    result.outcome = "rejected";
    result.reason = "invalid_command";
    result.detail = clean("the command could not be read: " + failure.reason);
    if (!failure.command_id.empty() && !failure.correlation_id.empty()) {
        const auto made = ledger_.mark_received(failure.command_id, failure.correlation_id, now() + 86400);
        if (succeeded(made) && std::get<bool>(made)) (void)ledger_.mark_done(failure.command_id, "rejected", "invalid_command", result.detail);
    }
    return result;
}

std::string command_result_json(const command_outcome& outcome) {
    json_writer out;
    out.begin_object();
    out.field("schema_version", "2");
    out.field("result_id", "res-" + outcome.command_id);  // fixed per command: a retry is the same result
    out.field("command_id", outcome.command_id);
    out.field("outcome", outcome.outcome);
    out.field("detail", clean(outcome.reason + ": " + outcome.detail, 500U));
    out.field("correlation_id", outcome.correlation_id);
    out.end_object();
    return out.take();
}

raw_response_action response_audit(const command_outcome& outcome) {
    raw_response_action audit;
    audit.command_id = outcome.command_id;
    audit.correlation_id = outcome.correlation_id;
    audit.action = outcome.action;
    audit.outcome = outcome.outcome;
    audit.reason = outcome.reason;
    audit.detail = outcome.detail;
    audit.mode = outcome.mode;
    audit.dry_run = outcome.dry_run;
    audit.executed = outcome.executed;
    audit.pid = outcome.pid;
    audit.start_ticks = outcome.start_ticks;
    audit.path = outcome.path;
    audit.affected = outcome.affected;
    audit.evidence = outcome.evidence;
    return audit;
}

// ---- provider -------------------------------------------------------------------------------

command_channel_provider::command_channel_provider(command_channel_options options, std::unique_ptr<command_transport> transport,
                                                   std::unique_ptr<command_executor> executor)
    : options_{std::move(options)}, transport_{std::move(transport)}, executor_{std::move(executor)} {}

command_channel_provider::~command_channel_provider() { stop(); }

std::vector<std::string> command_channel_provider::capabilities() const {
    // What this endpoint can do under its policy, not what the code could do: the Manager plans from this.
    std::vector<std::string> names{"response.command"};
    for (const auto action : {command_action::kill_process, command_action::collect_process_info,
                              command_action::collect_network_connections, command_action::collect_file,
                              command_action::quarantine_file, command_action::isolate_host,
                              command_action::release_host_isolation}) {
        if (!options_.processor.policy.allowed.contains(action)) continue;
        std::string name{to_string(action)};
        for (auto& c : name) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        names.push_back("response." + name);
    }
    return names;
}

std::string command_channel_provider::probe() {
    if (options_.processor.policy.mode == response_mode::off) return "response is off in the configuration";
    if (!transport_ || !executor_) return "no transport";
    return {};
}

result<bool> command_channel_provider::prepare(record_queue& queue) {
    if (auto reason = probe(); !reason.empty()) return error{error_code::unsupported_action, reason};
    auto opened = command_ledger::open(options_.ledger_path, options_.maximum_ledger_entries,
                                       options_.processor.now_unix ? options_.processor.now_unix() : system_now_unix());
    if (!succeeded(opened)) return std::get<error>(opened);
    ledger_ = std::move(std::get<std::unique_ptr<command_ledger>>(opened));
    auto processor_options = options_.processor;
    auto* transport = transport_.get();
    // Tell the Manager the command is accepted once it is durably recorded and about to run. A failed
    // call changes nothing: the Manager takes a result straight from DISPATCHED.
    processor_options.on_accepted = [transport](const endpoint_command& command) { (void)transport->accept(command.command_id); };
    processor_ = std::make_unique<command_processor>(std::move(processor_options), *ledger_, *executor_);
    queue_ = &queue;
    return true;
}

result<bool> command_channel_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    if (auto prepared = prepare(queue); !succeeded(prepared)) return prepared;
    running_.store(true);
    {
        std::lock_guard lock{mutex_};
        state_ = "active";
    }
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void command_channel_provider::stop() {
    if (!running_.exchange(false)) return;
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    std::lock_guard lock{mutex_};
    state_ = "stopped";
}

provider_health command_channel_provider::health() const {
    std::lock_guard lock{mutex_};
    provider_health health;
    health.name = "command_channel";
    health.state = state_;
    health.reason = metrics_.last_error;
    health.capabilities = capabilities();
    health.events = metrics_.commands_seen;
    return health;
}

command_channel_metrics command_channel_provider::metrics() const {
    std::lock_guard lock{mutex_};
    return metrics_;
}

void command_channel_provider::report(const command_outcome& outcome, record_queue& queue, const bool audit) {
    if (audit) {
        raw_record record;
        record.time_unix_ns = clock_domain::now_unix_ns();
        record.source = provenance{"command_channel", "MGR-CMD", confidence::observed};
        record.payload = response_audit(outcome);
        (void)queue.push(std::move(record));
    }
    {
        std::lock_guard lock{mutex_};
        if (outcome.outcome == "rejected") {
            ++metrics_.rejected;
            if (outcome.reason == "signature_required" || outcome.reason == "unknown_signing_key" || outcome.reason == "signature_invalid") {
                ++metrics_.authorization_refused;
            }
        }
        else if (outcome.executed) ++metrics_.executed;
    }
    if (outcome.command_id.empty()) return;
    const auto reply = transport_->submit(command_result_json(outcome));
    std::lock_guard lock{mutex_};
    if (reply.status == post_status::answered) {
        ++metrics_.results_reported;
        (void)ledger_->mark_reported(outcome.command_id);
    } else if (reply.status == post_status::refused) {
        // The Manager will never take this result (for example 422: the command is not ours). Keep
        // retrying and the channel would repeat the request forever.
        ++metrics_.result_failures;
        metrics_.last_error = "the Manager refused a command result: " + clean(reply.detail, 120U);
        (void)ledger_->mark_reported(outcome.command_id);
    } else {
        ++metrics_.result_failures;
        metrics_.last_error = "command result not delivered: " + clean(reply.detail, 120U);
    }
}

std::uint64_t command_channel_provider::step(record_queue& queue) {
    {
        std::lock_guard lock{mutex_};
        ++metrics_.polls;
    }
    if (options_.processor.keyring) options_.processor.keyring->refresh();  // a revoked key stops working at the next poll
    // Results the Manager never acknowledged go first: once a command is accepted the Manager does
    // not send it again, so nothing else would repeat the answer.
    for (const auto& [id, entry] : ledger_->unreported()) {
        command_outcome again;
        again.command_id = id;
        again.correlation_id = entry.correlation_id;
        again.outcome = entry.outcome;
        again.reason = entry.reason;
        again.detail = entry.detail;
        report(again, queue, false);
    }
    const auto reply = transport_->poll();
    if (reply.status != post_status::answered) {
        std::lock_guard lock{mutex_};
        state_ = "degraded";
        metrics_.last_error = reply.status == post_status::unauthorized ? "the Manager refused the agent credentials"
                                                                        : "command poll failed: " + clean(reply.detail, 120U);
        backoff_ms_ = backoff_ms_ == 0U ? options_.poll_interval_ms * 2U : std::min(backoff_ms_ * 2U, options_.maximum_backoff_ms);
        return backoff_ms_;
    }
    {
        std::lock_guard lock{mutex_};
        state_ = "active";
        metrics_.last_error.clear();
        if (options_.processor.keyring) metrics_.last_error = options_.processor.keyring->last_error();
        backoff_ms_ = 0U;
    }
    const auto poll = parse_command_poll(reply.body);
    if (poll.malformed) {
        std::lock_guard lock{mutex_};
        ++metrics_.unreadable;
        metrics_.last_error = "command poll reply rejected: " + poll.why;
        return options_.poll_interval_ms;
    }
    for (const auto& item : poll.commands) {
        {
            std::lock_guard lock{mutex_};
            ++metrics_.commands_seen;
        }
        if (const auto* unreadable = std::get_if<command_unreadable>(&item)) {
            if (unreadable->command_id.empty() || unreadable->correlation_id.empty()) {
                std::lock_guard lock{mutex_};
                ++metrics_.unreadable;
                continue;  // not addressable: there is no command to close
            }
            if (ledger_->find(unreadable->command_id)) continue;  // already closed; the Manager has the answer or will
            report(processor_->unreadable(*unreadable), queue, true);
            continue;
        }
        const auto& command = std::get<endpoint_command>(item);
        const auto known = ledger_->find(command.command_id);
        if (!known) {
            report(processor_->handle(command), queue, true);
        } else if (known->state == command_ledger::phase::received) {
            if (auto resumed = processor_->resume(command.command_id, command.correlation_id, &command)) report(*resumed, queue, true);
        } else if (known->state == command_ledger::phase::reported) {
            (void)transport_->accept(command.command_id);  // the Manager sent it again; closing it is idempotent
        }
        // phase::done and not reported: handled by the retry loop above on this and the next step.
    }
    return options_.poll_interval_ms;
}

void command_channel_provider::run() {
    std::uint64_t wait_ms = 0U;
    while (running_.load()) {
        if (wait_ms > 0U) {
            std::unique_lock lock{wait_mutex_};
            wake_.wait_for(lock, std::chrono::milliseconds{wait_ms}, [this] { return !running_.load(); });
            if (!running_.load()) break;
        }
        wait_ms = step(*queue_);
    }
}

}  // namespace panopticon::linux_agent::sensor
