#include "panopticon/linux_agent/sensor/auth_log.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <variant>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::size_t maximum_user_bytes = 256U;
constexpr std::size_t maximum_path_bytes = 512U;
constexpr std::size_t maximum_command_bytes = 1024U;
constexpr std::uint64_t ns_per_second = 1'000'000'000ULL;

bool starts_with(const std::string_view text, const std::string_view prefix) { return text.substr(0U, prefix.size()) == prefix; }

bool ends_with(const std::string_view text, const std::string_view suffix) {
    return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

// Printable ASCII only, bounded. Anything else becomes '?' so a crafted name cannot smuggle
// control characters or invalid UTF-8 into a record.
std::string clean(const std::string_view text, const std::size_t maximum, raw_auth_event& event) {
    std::string out;
    out.reserve(std::min(text.size(), maximum));
    for (const char c : text) {
        if (out.size() >= maximum) {
            event.truncated = true;
            break;
        }
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20U || byte >= 0x7FU) {
            out.push_back('?');
            event.sanitized = true;
        } else {
            out.push_back(c);
        }
    }
    return out;
}

bool digits_only(const std::string_view text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](const char c) { return c >= '0' && c <= '9'; });
}

bool valid_address(const std::string_view text) {
    if (text.empty() || text.size() > 45U) return false;
    const std::string copy{text};
    unsigned char buffer[16];
    return ::inet_pton(AF_INET, copy.c_str(), buffer) == 1 || ::inet_pton(AF_INET6, copy.c_str(), buffer) == 1;
}

std::optional<std::uint64_t> parse_number(const std::string_view text, const std::uint64_t maximum) {
    if (!digits_only(text) || text.size() > 10U) return std::nullopt;
    std::uint64_t value = 0U;
    for (const char c : text) value = value * 10U + static_cast<std::uint64_t>(c - '0');
    if (value > maximum) return std::nullopt;
    return value;
}

// ---- timestamps ------------------------------------------------------------------------------

struct stamp {
    std::uint64_t unix_ns{};
    std::size_t consumed{};
};

std::optional<stamp> parse_iso(const std::string_view line) {
    // 2026-10-06T01:40:47[.ffffff](Z|+HH:MM)
    if (line.size() < 20U || line[4] != '-' || line[7] != '-' || line[10] != 'T' || line[13] != ':' || line[16] != ':') return std::nullopt;
    const auto number = [&](const std::size_t at, const std::size_t length) { return parse_number(line.substr(at, length), 99999U); };
    const auto year = number(0U, 4U);
    const auto month = number(5U, 2U);
    const auto day = number(8U, 2U);
    const auto hour = number(11U, 2U);
    const auto minute = number(14U, 2U);
    const auto second = number(17U, 2U);
    if (!year || !month || !day || !hour || !minute || !second) return std::nullopt;
    if (*month < 1U || *month > 12U || *day < 1U || *day > 31U || *hour > 23U || *minute > 59U || *second > 60U) return std::nullopt;
    std::size_t at = 19U;
    std::uint64_t fraction_ns = 0U;
    if (at < line.size() && line[at] == '.') {
        ++at;
        std::uint64_t scale = 100'000'000ULL;
        const std::size_t begin = at;
        while (at < line.size() && line[at] >= '0' && line[at] <= '9') {
            if (scale != 0U) fraction_ns += static_cast<std::uint64_t>(line[at] - '0') * scale;
            scale /= 10U;
            ++at;
        }
        if (at == begin) return std::nullopt;
    }
    std::int64_t offset_seconds = 0;
    if (at < line.size() && line[at] == 'Z') {
        ++at;
    } else if (at + 6U <= line.size() && (line[at] == '+' || line[at] == '-') && line[at + 3U] == ':') {
        const auto offset_hours = parse_number(line.substr(at + 1U, 2U), 23U);
        const auto offset_minutes = parse_number(line.substr(at + 4U, 2U), 59U);
        if (!offset_hours || !offset_minutes) return std::nullopt;
        offset_seconds = static_cast<std::int64_t>(*offset_hours * 3600U + *offset_minutes * 60U);
        if (line[at] == '-') offset_seconds = -offset_seconds;
        at += 6U;
    } else {
        return std::nullopt;
    }
    if (at >= line.size() || line[at] != ' ') return std::nullopt;
    std::tm parts{};
    parts.tm_year = static_cast<int>(*year) - 1900;
    parts.tm_mon = static_cast<int>(*month) - 1;
    parts.tm_mday = static_cast<int>(*day);
    parts.tm_hour = static_cast<int>(*hour);
    parts.tm_min = static_cast<int>(*minute);
    parts.tm_sec = static_cast<int>(*second);
    const auto seconds = static_cast<std::int64_t>(::timegm(&parts)) - offset_seconds;
    if (seconds < 0) return std::nullopt;
    return stamp{static_cast<std::uint64_t>(seconds) * ns_per_second + fraction_ns, at + 1U};
}

std::optional<stamp> parse_traditional(const std::string_view line, const std::uint64_t reference_unix_ns) {
    // "Oct  6 01:40:47 "
    static constexpr std::string_view months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (line.size() < 16U || line[3] != ' ' || line[6] != ' ' || line[9] != ':' || line[12] != ':' || line[15] != ' ') return std::nullopt;
    int month = -1;
    for (int index = 0; index < 12; ++index) {
        if (line.substr(0U, 3U) == months[index]) month = index;
    }
    if (month < 0) return std::nullopt;
    const auto day = parse_number(line[4] == ' ' ? line.substr(5U, 1U) : line.substr(4U, 2U), 31U);
    const auto hour = parse_number(line.substr(7U, 2U), 23U);
    const auto minute = parse_number(line.substr(10U, 2U), 59U);
    const auto second = parse_number(line.substr(13U, 2U), 60U);
    if (!day || *day < 1U || !hour || !minute || !second) return std::nullopt;
    const auto reference = static_cast<std::time_t>(reference_unix_ns / ns_per_second);
    std::tm now{};
    ::localtime_r(&reference, &now);
    const auto build = [&](const int year) {
        std::tm parts{};
        parts.tm_year = year;
        parts.tm_mon = month;
        parts.tm_mday = static_cast<int>(*day);
        parts.tm_hour = static_cast<int>(*hour);
        parts.tm_min = static_cast<int>(*minute);
        parts.tm_sec = static_cast<int>(*second);
        parts.tm_isdst = -1;
        return static_cast<std::int64_t>(::mktime(&parts));
    };
    auto seconds = build(now.tm_year);
    // No year in the line: a date more than a day ahead of now belongs to the previous year.
    if (seconds > static_cast<std::int64_t>(reference) + 86400) seconds = build(now.tm_year - 1);
    if (seconds < 0) return std::nullopt;
    return stamp{static_cast<std::uint64_t>(seconds) * ns_per_second, 16U};
}

// ---- message parsers -------------------------------------------------------------------------

// Removes " from <ip> port <n>" (and a trailing " ssh2") from the end of `text`, leaving what
// came before it. Read from the right so a name that itself looks like an endpoint is harmless.
bool take_endpoint(std::string_view& text, std::string& address, std::uint16_t& port) {
    if (ends_with(text, " ssh2")) text.remove_suffix(5U);
    else if (ends_with(text, " ssh")) text.remove_suffix(4U);
    auto split = text.rfind(' ');
    if (split == std::string_view::npos) return false;
    const auto number = parse_number(text.substr(split + 1U), 65535U);
    if (!number) return false;
    text.remove_suffix(text.size() - split);
    if (!ends_with(text, " port")) return false;
    text.remove_suffix(5U);
    split = text.rfind(' ');
    if (split == std::string_view::npos) return false;
    const auto candidate = text.substr(split + 1U);
    if (!valid_address(candidate)) return false;
    address = std::string{candidate};
    text.remove_suffix(text.size() - split);
    if (!ends_with(text, " from")) return false;
    text.remove_suffix(5U);
    port = static_cast<std::uint16_t>(*number);
    return true;
}

std::optional<raw_auth_event> parse_sshd(std::string_view message) {
    raw_auth_event event;
    event.service = "sshd";
    if (starts_with(message, "Accepted ")) {
        event.kind = auth_kind::login_success;
        message.remove_prefix(9U);
        // A public-key login ends with ": <type> SHA256:<fingerprint>".
        if (const auto key = message.rfind(" ssh2: "); key != std::string_view::npos) {
            const auto suffix = message.substr(key + 7U);
            const auto space = suffix.find(' ');
            if (space == std::string_view::npos || !starts_with(suffix.substr(space + 1U), "SHA256:")) return std::nullopt;
            const auto fingerprint = suffix.substr(space + 1U);
            if (fingerprint.size() > 7U + 64U ||
                !std::all_of(fingerprint.begin() + 7, fingerprint.end(), [](const char c) {
                    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                })) {
                return std::nullopt;
            }
            event.key_type = clean(suffix.substr(0U, space), 32U, event);
            event.key_fingerprint = std::string{fingerprint};
            message = message.substr(0U, key + 5U);
        }
    } else if (starts_with(message, "Failed ")) {
        event.kind = auth_kind::login_failure;
        message.remove_prefix(7U);
    } else {
        return std::nullopt;
    }
    const auto space = message.find(' ');
    if (space == std::string_view::npos || space == 0U) return std::nullopt;
    event.method = clean(message.substr(0U, space), 64U, event);
    message.remove_prefix(space + 1U);
    if (!starts_with(message, "for ")) return std::nullopt;
    message.remove_prefix(4U);
    if (!take_endpoint(message, event.source_address, event.source_port)) return std::nullopt;
    if (event.kind == auth_kind::login_failure && starts_with(message, "invalid user ")) {
        event.invalid_user = true;
        message.remove_prefix(13U);
    }
    if (message.empty()) return std::nullopt;
    event.user = clean(message, maximum_user_bytes, event);
    return event;
}

// "USER : TTY=pts/0 ; PWD=/home/u ; USER=root ; COMMAND=/bin/ls -l"
std::optional<raw_auth_event> parse_sudo(std::string_view message) {
    // sudo writes two spaces after the tag when the user name is padded.
    while (!message.empty() && message.front() == ' ') message.remove_prefix(1U);
    const auto colon = message.find(" : ");
    if (colon == std::string_view::npos || colon == 0U) return std::nullopt;
    raw_auth_event event;
    event.service = "sudo";
    event.user = clean(message.substr(0U, colon), maximum_user_bytes, event);
    std::string_view rest = message.substr(colon + 3U);
    bool failure = false;
    bool have_command = false;
    bool first = true;
    while (!rest.empty()) {
        const auto next = rest.find(" ; ");
        const auto segment = next == std::string_view::npos ? rest : rest.substr(0U, next);
        if (starts_with(segment, "COMMAND=")) {
            // The command is last and may itself contain " ; ": it takes everything that remains.
            event.command = clean(rest.substr(8U), maximum_command_bytes, event);
            have_command = true;
            break;
        }
        if (starts_with(segment, "TTY=")) event.tty = clean(segment.substr(4U), 64U, event);
        else if (starts_with(segment, "PWD=")) event.working_directory = clean(segment.substr(4U), maximum_path_bytes, event);
        else if (starts_with(segment, "USER=")) event.target_user = clean(segment.substr(5U), maximum_user_bytes, event);
        else if (first && (segment.find("incorrect password attempt") != std::string_view::npos ||
                           segment.find("NOT in sudoers") != std::string_view::npos ||
                           segment.find("command not allowed") != std::string_view::npos)) {
            failure = true;
        }
        first = false;
        if (next == std::string_view::npos) break;
        rest.remove_prefix(next + 3U);
    }
    if (!failure && !have_command) return std::nullopt;
    event.kind = failure ? auth_kind::privilege_failure : auth_kind::privilege_success;
    event.method = "sudo";
    return event;
}

std::optional<raw_auth_event> parse_su(std::string_view message) {
    raw_auth_event event;
    event.service = "su";
    event.method = "su";
    event.kind = auth_kind::privilege_success;
    if (starts_with(message, "FAILED SU ")) {
        event.kind = auth_kind::privilege_failure;
        message.remove_prefix(10U);
    }
    if (starts_with(message, "(to ")) {
        // "(to root) user on pts/0"
        message.remove_prefix(4U);
        const auto close = message.find(") ");
        if (close == std::string_view::npos || close == 0U) return std::nullopt;
        event.target_user = clean(message.substr(0U, close), maximum_user_bytes, event);
        message.remove_prefix(close + 2U);
        const auto on = message.rfind(" on ");
        if (on == std::string_view::npos || on == 0U) return std::nullopt;
        event.user = clean(message.substr(0U, on), maximum_user_bytes, event);
        event.tty = clean(message.substr(on + 4U), 64U, event);
        return event;
    }
    // Older form: "Successful su for root by user" / "FAILED su for root by user"
    const bool success = starts_with(message, "Successful su for ");
    const bool failed = starts_with(message, "FAILED su for ");
    if (!success && !failed) return std::nullopt;
    event.kind = success ? auth_kind::privilege_success : auth_kind::privilege_failure;
    message.remove_prefix(success ? 18U : 14U);
    const auto by = message.rfind(" by ");
    if (by == std::string_view::npos || by == 0U || by + 4U >= message.size()) return std::nullopt;
    event.target_user = clean(message.substr(0U, by), maximum_user_bytes, event);
    event.user = clean(message.substr(by + 4U), maximum_user_bytes, event);
    return event;
}

std::optional<raw_auth_event> parse_login(std::string_view message) {
    raw_auth_event event;
    event.service = "login";
    event.method = "console";
    static constexpr std::string_view opened = "pam_unix(login:session): session opened for user ";
    if (starts_with(message, opened)) {
        message.remove_prefix(opened.size());
        const auto paren = message.find('(');
        if (paren == std::string_view::npos || paren == 0U) return std::nullopt;
        event.kind = auth_kind::login_success;
        event.user = clean(message.substr(0U, paren), maximum_user_bytes, event);
        return event;
    }
    if (starts_with(message, "FAILED LOGIN ")) {
        // FAILED LOGIN (1) on '/dev/tty1' FOR 'name', Authentication failure
        const auto tty_begin = message.find(" on '");
        const auto user_begin = message.rfind(" FOR '");
        if (user_begin == std::string_view::npos) return std::nullopt;
        const auto name = message.substr(user_begin + 6U);
        const auto quote = name.find('\'');
        if (quote == std::string_view::npos || quote == 0U) return std::nullopt;
        event.kind = auth_kind::login_failure;
        event.user = clean(name.substr(0U, quote), maximum_user_bytes, event);
        if (tty_begin != std::string_view::npos && tty_begin + 5U < user_begin) {
            const auto tty = message.substr(tty_begin + 5U, user_begin - tty_begin - 5U);
            if (!tty.empty() && tty.back() == '\'') event.tty = clean(tty.substr(0U, tty.size() - 1U), 64U, event);
        }
        return event;
    }
    return std::nullopt;
}

// "user: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/home/user] [COMMAND=/usr/bin/id]"
std::optional<raw_auth_event> parse_pkexec(const std::string_view message) {
    const auto marker = message.find(": Executing command ");
    if (marker == std::string_view::npos || marker == 0U) return std::nullopt;
    raw_auth_event event;
    event.service = "pkexec";
    event.method = "polkit";
    event.kind = auth_kind::privilege_success;
    event.user = clean(message.substr(0U, marker), maximum_user_bytes, event);
    const auto fields = message.substr(marker + 20U);
    const auto field = [&](const std::string_view key) -> std::optional<std::string_view> {
        const std::string needle = "[" + std::string{key} + "=";
        const auto at = fields.find(needle);
        if (at == std::string_view::npos) return std::nullopt;
        return fields.substr(at + needle.size());
    };
    const auto bracketed = [](const std::string_view value) { return value.substr(0U, value.find(']')); };
    if (const auto value = field("USER")) event.target_user = clean(bracketed(*value), maximum_user_bytes, event);
    if (const auto value = field("TTY")) event.tty = clean(bracketed(*value), 64U, event);
    if (const auto value = field("CWD")) event.working_directory = clean(bracketed(*value), maximum_path_bytes, event);
    // The command is last and may contain ']' itself: drop only the closing bracket.
    if (const auto value = field("COMMAND")) {
        auto command = *value;
        if (!command.empty() && command.back() == ']') command.remove_suffix(1U);
        event.command = clean(command, maximum_command_bytes, event);
    }
    return event;
}

bool tag_is_well_formed(const std::string_view tag, std::string_view& name, std::uint32_t& pid) {
    pid = 0U;
    auto text = tag;
    if (!text.empty() && text.back() == ']') {
        const auto open = text.rfind('[');
        if (open == std::string_view::npos) return false;
        const auto number = parse_number(text.substr(open + 1U, text.size() - open - 2U), 4294967295ULL);
        if (!number) return false;
        pid = static_cast<std::uint32_t>(*number);
        text = text.substr(0U, open);
    }
    if (text.empty() || text.size() > 64U) return false;
    for (const char c : text) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '/';
        if (!ok) return false;
    }
    const auto slash = text.rfind('/');
    name = slash == std::string_view::npos ? text : text.substr(slash + 1U);
    return !name.empty();
}

}  // namespace

std::optional<parsed_auth_line> parse_auth_line(std::string_view line, const std::uint64_t reference_unix_ns) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1U);
    if (line.empty() || line.size() > maximum_auth_line_bytes) return std::nullopt;
    auto when = parse_iso(line);
    if (!when) when = parse_traditional(line, reference_unix_ns);
    if (!when) return std::nullopt;
    auto rest = line.substr(when->consumed);
    // host
    const auto host_end = rest.find(' ');
    if (host_end == std::string_view::npos || host_end == 0U) return std::nullopt;
    rest.remove_prefix(host_end + 1U);
    // tag: up to the first ": "
    const auto tag_end = rest.find(": ");
    if (tag_end == std::string_view::npos) return std::nullopt;
    std::string_view name;
    std::uint32_t pid = 0U;
    if (!tag_is_well_formed(rest.substr(0U, tag_end), name, pid)) return std::nullopt;
    const auto message = rest.substr(tag_end + 2U);

    std::optional<raw_auth_event> event;
    if (name == "sshd" || name == "sshd-session") event = parse_sshd(message);
    else if (name == "sudo") event = parse_sudo(message);
    else if (name == "su") event = parse_su(message);
    else if (name == "login") event = parse_login(message);
    else if (name == "pkexec") event = parse_pkexec(message);
    if (!event) return std::nullopt;
    if (event->user.empty()) return std::nullopt;
    event->pid = pid;
    return parsed_auth_line{when->unix_ns, std::move(*event)};
}

// ---- tailing ---------------------------------------------------------------------------------

log_tailer::~log_tailer() {
    if (fd_ >= 0) ::close(fd_);
}

bool log_tailer::open(std::string* reason) {
    const int fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (reason != nullptr) *reason = path_.string() + ": " + std::strerror(errno);
        return false;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        if (reason != nullptr) *reason = path_.string() + ": not a regular file";
        ::close(fd);
        return false;
    }
    if (fd_ >= 0) ::close(fd_);
    fd_ = fd;
    device_ = static_cast<std::uint64_t>(info.st_dev);
    inode_ = static_cast<std::uint64_t>(info.st_ino);
    offset_ = static_cast<std::uint64_t>(info.st_size);  // history is not replayed
    carry_.clear();
    skipping_ = false;
    return true;
}

void log_tailer::split(const std::string_view data, std::vector<std::string>& lines) {
    for (const char c : data) {
        if (c == '\n') {
            if (skipping_) {
                skipping_ = false;
            } else {
                lines.push_back(std::move(carry_));
            }
            carry_.clear();
            continue;
        }
        if (skipping_) continue;
        carry_.push_back(c);
        if (carry_.size() > maximum_auth_line_bytes) {
            carry_.clear();
            skipping_ = true;
            ++oversize_;
        }
    }
}

bool log_tailer::drain(std::vector<std::string>& lines) {
    char buffer[65536];
    std::size_t total = 0U;
    while (total < maximum_bytes_) {
        const auto got = ::pread(fd_, buffer, sizeof(buffer), static_cast<off_t>(offset_));
        if (got < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (got == 0) break;
        offset_ += static_cast<std::uint64_t>(got);
        total += static_cast<std::size_t>(got);
        split(std::string_view{buffer, static_cast<std::size_t>(got)}, lines);
    }
    return true;
}

bool log_tailer::poll(std::vector<std::string>& lines) {
    if (fd_ < 0) {
        // The file did not exist when we started or was removed: a file that appears is new, read it all.
        if (!open()) return true;
        offset_ = 0U;
    }
    struct stat held {};
    if (::fstat(fd_, &held) != 0) return false;
    if (static_cast<std::uint64_t>(held.st_size) < offset_) {  // truncated in place
        offset_ = 0U;
        carry_.clear();
        skipping_ = false;
    }
    if (!drain(lines)) return false;
    struct stat current {};
    if (::stat(path_.c_str(), &current) == 0 &&
        (static_cast<std::uint64_t>(current.st_ino) != inode_ || static_cast<std::uint64_t>(current.st_dev) != device_)) {
        // Rotated: the old file was drained above, continue with the new one from its start.
        if (open()) {
            offset_ = 0U;
            ++rotations_;
            if (!drain(lines)) return false;
        }
    }
    return true;
}

// ---- provider --------------------------------------------------------------------------------

auth_log_provider::auth_log_provider(auth_log_options options) : options_{std::move(options)} {}

auth_log_provider::~auth_log_provider() { stop(); }

std::vector<std::string> auth_log_provider::capabilities() const { return {"auth.login", "auth.failure", "auth.privilege"}; }

std::string auth_log_provider::probe() {
    std::string reasons;
    for (const auto& path : options_.paths) {
        log_tailer tailer{path};
        std::string reason;
        if (tailer.open(&reason)) return {};
        if (!reasons.empty()) reasons += "; ";
        reasons += reason;
    }
    return reasons.empty() ? "no authentication log configured" : "no readable authentication log: " + reasons;
}

result<bool> auth_log_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    queue_ = &queue;
    std::string reasons;
    for (const auto& path : options_.paths) {
        auto tailer = std::make_unique<log_tailer>(path);
        std::string reason;
        if (tailer->open(&reason)) {
            tailers_.push_back(std::move(tailer));
        } else {
            if (!reasons.empty()) reasons += "; ";
            reasons += reason;
        }
    }
    if (tailers_.empty()) return error{error_code::io_failure, "no readable authentication log: " + reasons};
    {
        const std::lock_guard lock{failure_mutex_};
        failure_.clear();
    }
    running_.store(true);
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void auth_log_provider::poll_once() {
    std::size_t emitted = 0U;
    std::string failure;
    for (auto& tailer : tailers_) {
        std::vector<std::string> lines;
        if (!tailer->poll(lines)) failure = "cannot read " + tailer->path().string();
        const auto now = clock_domain::now_unix_ns();
        for (const auto& line : lines) {
            ++lines_;
            auto parsed = parse_auth_line(line, now);
            if (!parsed) continue;
            if (emitted >= options_.maximum_events_per_poll) {
                ++governed_;
                continue;
            }
            raw_record record;
            record.time_unix_ns = parsed->time_unix_ns;
            record.source = {"auth_log", "AUTHLOG", confidence::user_space_reported};
            record.payload = std::move(parsed->event);
            if (queue_ != nullptr && queue_->push(std::move(record))) ++events_;
            ++emitted;
        }
    }
    const std::lock_guard lock{failure_mutex_};
    failure_ = std::move(failure);
}

void auth_log_provider::run() {
    while (running_.load()) {
        poll_once();
        std::unique_lock lock{wake_mutex_};
        wake_.wait_for(lock, options_.interval, [this] { return !running_.load(); });
    }
}

void auth_log_provider::stop() {
    if (!running_.exchange(false)) return;
    {
        const std::lock_guard lock{wake_mutex_};
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    tailers_.clear();
}

provider_health auth_log_provider::health() const {
    std::string reason;
    {
        const std::lock_guard lock{failure_mutex_};
        reason = failure_;
    }
    const bool active = running_.load();
    const std::string state = !active ? "stopped" : reason.empty() ? "active" : "degraded";
    return {std::string{name()}, state, reason, capabilities(), events_.load(), governed_.load()};
}

}  // namespace panopticon::linux_agent::sensor
