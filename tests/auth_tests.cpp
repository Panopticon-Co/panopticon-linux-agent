#include "panopticon/linux_agent/sensor/auth_log.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
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

std::uint64_t utc_ns(const int year, const int month, const int day, const int hour, const int minute, const int second,
                     const std::uint64_t extra_ns = 0U) {
    std::tm parts{};
    parts.tm_year = year - 1900;
    parts.tm_mon = month - 1;
    parts.tm_mday = day;
    parts.tm_hour = hour;
    parts.tm_min = minute;
    parts.tm_sec = second;
    return static_cast<std::uint64_t>(::timegm(&parts)) * 1'000'000'000ULL + extra_ns;
}

const std::uint64_t reference = utc_ns(2026, 10, 6, 12, 0, 0);

parsed_auth_line must_parse(const std::string& line) {
    auto parsed = parse_auth_line(line, reference);
    if (!parsed) throw std::runtime_error{"expected an event: " + line};
    return *parsed;
}

bool ignored(const std::string& line) { return !parse_auth_line(line, reference).has_value(); }

const std::string iso = "2026-10-06T01:40:47.580173+00:00 host ";

void test_sshd_logins() {
    const auto key = must_parse(iso + "sshd[4242]: Accepted publickey for vagrant from 10.0.2.2 port 28449 ssh2: ED25519 SHA256:AbCdEf+/0123456789abcdefghijklmnopqrstuvwxyz1");
    require(key.event.kind == auth_kind::login_success && key.event.service == "sshd" && key.event.method == "publickey" &&
                key.event.user == "vagrant" && key.event.source_address == "10.0.2.2" && key.event.source_port == 28449U &&
                key.event.key_type == "ED25519" && key.event.key_fingerprint.rfind("SHA256:AbCdEf", 0U) == 0U && key.event.pid == 4242U,
            "public key login with fingerprint");
    require(key.time_unix_ns == utc_ns(2026, 10, 6, 1, 40, 47, 580173000U), "iso time with microseconds");
    const auto password = must_parse(iso + "sshd[1]: Accepted password for root from 2001:db8::1 port 22022 ssh2");
    require(password.event.method == "password" && password.event.source_address == "2001:db8::1" && password.event.key_fingerprint.empty(),
            "password login over ipv6");
    const auto invalid = must_parse(iso + "sshd[2]: Failed password for invalid user admin from 203.0.113.9 port 40000 ssh2");
    require(invalid.event.kind == auth_kind::login_failure && invalid.event.invalid_user && invalid.event.user == "admin" &&
                invalid.event.source_address == "203.0.113.9",
            "failure for an account that does not exist");
    const auto valid = must_parse(iso + "sshd[3]: Failed keyboard-interactive/pam for root from 203.0.113.9 port 40001 ssh2");
    require(valid.event.kind == auth_kind::login_failure && !valid.event.invalid_user && valid.event.method == "keyboard-interactive/pam",
            "failure for a real account");
    require(ignored(iso + "sshd[4]: Invalid user admin from 203.0.113.9 port 40000"), "the duplicate Invalid user line is not a second failure");
    require(ignored(iso + "sshd[5]: Connection closed by authenticating user root 203.0.113.9 port 40002 [preauth]"), "noise is ignored");
    const auto offset = must_parse("2026-10-06T03:40:47+02:00 host sshd[6]: Accepted password for u from 1.2.3.4 port 5 ssh2");
    require(offset.time_unix_ns == utc_ns(2026, 10, 6, 1, 40, 47), "a zone offset is applied");
    const auto zulu = must_parse("2026-10-06T01:40:47Z host sshd-session[7]: Accepted password for u from 1.2.3.4 port 5 ssh2");
    require(zulu.event.service == "sshd" && zulu.event.pid == 7U, "newer OpenSSH program name and Z suffix");
}

void test_sshd_log_injection_cannot_change_who_or_where() {
    // The attacker chooses the user name; the real endpoint is the last one on the line.
    const auto forged = must_parse(iso + "sshd[9]: Failed password for invalid user x from 1.2.3.4 port 22 ssh2 from 9.9.9.9 port 51000 ssh2");
    require(forged.event.source_address == "9.9.9.9" && forged.event.source_port == 51000U, "endpoint is read from the right");
    require(forged.event.user == "x from 1.2.3.4 port 22 ssh2" && forged.event.invalid_user, "the whole name stays the name");
    // A name that spells out a success must stay a failure.
    const auto fake = must_parse(iso + "sshd[10]: Failed password for invalid user Accepted password for root from 1.1.1.1 port 1 ssh2 from 8.8.8.8 port 2 ssh2");
    require(fake.event.kind == auth_kind::login_failure && fake.event.source_address == "8.8.8.8", "a failure cannot be turned into a success");
    // A different program cannot speak for sshd.
    require(ignored(iso + "evil[11]: Accepted password for root from 1.1.1.1 port 1 ssh2"), "only sshd lines are sshd events");
    require(ignored(iso + "sshd [11]: Accepted password for root from 1.1.1.1 port 1 ssh2"), "a tag with a space is not a tag");
    require(ignored(iso + "cron: sshd[11]: Accepted password for root from 1.1.1.1 port 1 ssh2"), "a program name cannot be spelled into the message");
    // Control and non-ASCII bytes in a name are replaced, not passed on.
    const auto odd = must_parse(iso + "sshd[12]: Failed password for invalid user a\x01\x1b[31mb\xc3\xa9 from 5.6.7.8 port 9 ssh2");
    require(odd.event.sanitized && odd.event.user.find('\x1b') == std::string::npos && odd.event.user.find('\x01') == std::string::npos &&
                odd.event.user.find('\xc3') == std::string::npos,
            "control characters and non-ASCII bytes are replaced");
    const auto longname = must_parse(iso + "sshd[13]: Failed password for invalid user " + std::string(1000U, 'a') + " from 5.6.7.8 port 9 ssh2");
    require(longname.event.truncated && longname.event.user.size() == 256U, "a long name is cut and says so");
}

void test_endpoints_are_validated() {
    require(ignored(iso + "sshd[1]: Accepted password for u from 999.1.1.1 port 22 ssh2"), "impossible address");
    require(ignored(iso + "sshd[1]: Accepted password for u from 1.2.3.4 port 70000 ssh2"), "impossible port");
    require(ignored(iso + "sshd[1]: Accepted password for u from not-an-ip port 22 ssh2"), "not an address");
    require(ignored(iso + "sshd[1]: Accepted password for  from 1.2.3.4 port 22 ssh2"), "empty user");
    require(ignored(iso + "sshd[1]: Accepted publickey for u from 1.2.3.4 port 22 ssh2: RSA MD5:aa:bb"), "only SHA256 fingerprints are accepted");
    require(ignored(iso + "sshd[1]: Accepted publickey for u from 1.2.3.4 port 22 ssh2: RSA SHA256:bad fingerprint!"), "malformed fingerprint");
}

void test_privilege_events() {
    const auto sudo = must_parse(iso + "sudo[100]:  vagrant : TTY=pts/0 ; PWD=/home/vagrant ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow");
    require(sudo.event.kind == auth_kind::privilege_success && sudo.event.service == "sudo" && sudo.event.user == "vagrant" &&
                sudo.event.target_user == "root" && sudo.event.tty == "pts/0" && sudo.event.working_directory == "/home/vagrant" &&
                sudo.event.command == "/usr/bin/cat /etc/shadow",
            "sudo command");
    const auto chained = must_parse(iso + "sudo[101]: u : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c echo a ; USER=nobody ; COMMAND=x");
    require(chained.event.target_user == "root" && chained.event.command == "/bin/sh -c echo a ; USER=nobody ; COMMAND=x",
            "the command takes everything after COMMAND=, so it cannot rewrite the fields before it");
    const auto attempts = must_parse(iso + "sudo[102]: u : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id");
    require(attempts.event.kind == auth_kind::privilege_failure, "incorrect password attempts");
    const auto sudoers = must_parse(iso + "sudo[103]: u : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id");
    require(sudoers.event.kind == auth_kind::privilege_failure, "not in sudoers");
    require(ignored(iso + "sudo[104]: pam_unix(sudo:session): session opened for user root(uid=0) by u(uid=1000)"), "pam chatter is ignored");
    const auto su = must_parse(iso + "su[200]: (to root) vagrant on pts/1");
    require(su.event.kind == auth_kind::privilege_success && su.event.user == "vagrant" && su.event.target_user == "root" && su.event.tty == "pts/1",
            "su");
    const auto failed_su = must_parse(iso + "su[201]: FAILED SU (to root) vagrant on pts/1");
    require(failed_su.event.kind == auth_kind::privilege_failure, "failed su");
    const auto old_su = must_parse(iso + "su[202]: Successful su for root by vagrant");
    require(old_su.event.user == "vagrant" && old_su.event.target_user == "root", "older su wording");
    const auto pkexec = must_parse(iso + "pkexec[300]: vagrant: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/home/vagrant] [COMMAND=/usr/bin/id]");
    require(pkexec.event.service == "pkexec" && pkexec.event.target_user == "root" && pkexec.event.command == "/usr/bin/id" &&
                pkexec.event.working_directory == "/home/vagrant",
            "pkexec");
    const auto login = must_parse(iso + "login[400]: pam_unix(login:session): session opened for user vagrant(uid=1000) by LOGIN(uid=0)");
    require(login.event.kind == auth_kind::login_success && login.event.user == "vagrant" && login.event.method == "console", "console login");
    const auto bad_login = must_parse(iso + "login[401]: FAILED LOGIN (1) on '/dev/tty1' FOR 'root', Authentication failure");
    require(bad_login.event.kind == auth_kind::login_failure && bad_login.event.user == "root" && bad_login.event.tty == "/dev/tty1", "failed console login");
}

void test_traditional_timestamps_and_year_inference() {
    ::setenv("TZ", "UTC", 1);
    ::tzset();
    const auto now = parse_auth_line("Oct  6 01:40:47 host sshd[1]: Accepted password for u from 1.2.3.4 port 5 ssh2", reference);
    require(now && now->time_unix_ns == utc_ns(2026, 10, 6, 1, 40, 47), "the year comes from the reference time");
    const auto earlier = parse_auth_line("Dec 31 23:59:59 host sshd[1]: Accepted password for u from 1.2.3.4 port 5 ssh2", utc_ns(2027, 1, 1, 0, 0, 5));
    require(earlier && earlier->time_unix_ns == utc_ns(2026, 12, 31, 23, 59, 59), "a line from last December just after New Year");
    require(ignored("Foo  6 01:40:47 host sshd[1]: Accepted password for u from 1.2.3.4 port 5 ssh2"), "unknown month");
    require(ignored("2026-13-06T01:40:47Z host sshd[1]: Accepted password for u from 1.2.3.4 port 5 ssh2"), "month 13");
    require(ignored("2026-10-06T25:40:47Z host sshd[1]: Accepted password for u from 1.2.3.4 port 5 ssh2"), "hour 25");
}

void test_parser_survives_garbage() {
    const std::string valid = iso + "sshd[4242]: Accepted publickey for vagrant from 10.0.2.2 port 28449 ssh2: ED25519 SHA256:AbCdEf0123";
    for (std::size_t length = 0U; length <= valid.size(); ++length) (void)parse_auth_line(valid.substr(0U, length), reference);
    require(ignored(""), "empty");
    require(ignored(std::string(maximum_auth_line_bytes + 1U, 'a')), "oversize line");
    require(ignored(iso + "CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"), "cron is not authentication");
    std::srand(11);
    for (int round = 0; round < 5000; ++round) {
        std::string junk = iso + (round % 2 == 0 ? "sshd[1]: " : "sudo: ");
        const auto size = static_cast<std::size_t>(std::rand() % 120);
        for (std::size_t index = 0U; index < size; ++index) junk.push_back(static_cast<char>(std::rand()));
        (void)parse_auth_line(junk, reference);
    }
}

struct scratch {
    fs::path path;
    scratch() {
        std::string pattern = (fs::temp_directory_path() / "panopticon-auth-XXXXXX").string();
        require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp");
        path = pattern;
    }
    ~scratch() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    void append(const std::string& name, const std::string& text) const {
        std::ofstream out{path / name, std::ios::binary | std::ios::app};
        out << text;
    }
    void write(const std::string& name, const std::string& text) const {
        std::ofstream out{path / name, std::ios::binary | std::ios::trunc};
        out << text;
    }
};

void test_tailer_follows_appends_rotation_and_truncation() {
    scratch dir;
    dir.write("log", "old line that is history\n");
    log_tailer tailer{dir.path / "log"};
    require(tailer.open(), "open");
    std::vector<std::string> lines;
    require(tailer.poll(lines) && lines.empty(), "history is not replayed");
    dir.append("log", "first\nsecond\npart");
    require(tailer.poll(lines) && lines == std::vector<std::string>{"first", "second"}, "complete lines only");
    lines.clear();
    dir.append("log", "ial\nthird\n");
    require(tailer.poll(lines) && lines == std::vector<std::string>{"partial", "third"}, "a partial line is completed later");
    // Rotation: the old file keeps receiving a last line, then a new file takes its place.
    lines.clear();
    dir.append("log", "last-of-old\n");
    fs::rename(dir.path / "log", dir.path / "log.1");
    dir.write("log", "first-of-new\n");
    require(tailer.poll(lines) && lines == std::vector<std::string>{"last-of-old", "first-of-new"}, "old file drained, new file followed");
    require(tailer.rotations() == 1U, "rotation counted");
    // Truncation in place.
    lines.clear();
    dir.append("log", "x\ny\n");
    require(tailer.poll(lines) && lines == std::vector<std::string>{"x", "y"}, "append after rotation");
    lines.clear();
    dir.write("log", "fresh\n");
    require(tailer.poll(lines) && lines == std::vector<std::string>{"fresh"}, "restart after truncation");
}

void test_tailer_skips_oversize_lines_and_waits_for_missing_files() {
    scratch dir;
    dir.write("log", "");
    log_tailer tailer{dir.path / "log"};
    require(tailer.open(), "open");
    std::vector<std::string> lines;
    dir.append("log", std::string(maximum_auth_line_bytes * 3U, 'z'));
    require(tailer.poll(lines) && lines.empty(), "an unterminated oversize line yields nothing");
    dir.append("log", "\nafter\n");
    require(tailer.poll(lines) && lines == std::vector<std::string>{"after"}, "the line after an oversize one is intact");
    require(tailer.oversize_lines() == 1U, "oversize line counted");
    log_tailer missing{dir.path / "later"};
    std::string reason;
    require(!missing.open(&reason) && !reason.empty(), "a missing file reports why");
    lines.clear();
    require(missing.poll(lines) && lines.empty(), "polling a file that does not exist yet is not an error");
    dir.write("later", "hello\n");
    require(missing.poll(lines) && lines == std::vector<std::string>{"hello"}, "a file that appears later is read from its start");
    fs::create_symlink(dir.path / "log", dir.path / "link");
    log_tailer linked{dir.path / "link"};
    require(!linked.open(), "a symlink is not followed");
}

bool wait_for_auth(record_queue& queue, std::vector<raw_auth_event>& seen, const std::size_t count) {
    for (int attempt = 0; attempt < 100 && seen.size() < count; ++attempt) {
        std::vector<raw_record> batch;
        queue.pop_batch(batch, 64U, std::chrono::milliseconds{50});
        for (const auto& record : batch) {
            if (const auto* event = std::get_if<raw_auth_event>(&record.payload)) seen.push_back(*event);
        }
    }
    return seen.size() >= count;
}

void test_provider_reports_new_lines_only() {
    scratch dir;
    dir.write("auth.log", iso + "sshd[1]: Accepted password for before from 1.1.1.1 port 1 ssh2\n");
    auth_log_options options;
    options.paths = {dir.path / "auth.log", dir.path / "secure"};
    options.interval = std::chrono::milliseconds{20};
    auth_log_provider provider{options};
    require(provider.probe().empty(), "one readable log is enough");
    record_queue queue{256U};
    require(std::holds_alternative<bool>(provider.start(queue)), "start");
    dir.append("auth.log", iso + "sshd[2]: Failed password for root from 2.2.2.2 port 2 ssh2\n" + iso + "CRON[3]: noise\n" +
                               iso + "sudo[4]: u : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n");
    std::vector<raw_auth_event> seen;
    require(wait_for_auth(queue, seen, 2U), "two events");
    provider.stop();
    require(seen.size() == 2U && seen[0].user == "root" && seen[0].kind == auth_kind::login_failure && seen[1].service == "sudo",
            "only lines written after the start, only authentication lines");
    require(provider.health().state == "stopped", "health after stop");
}

void test_provider_without_logs_is_unavailable_and_governor_counts() {
    scratch dir;
    auth_log_options none;
    none.paths = {dir.path / "missing"};
    auth_log_provider absent{none};
    require(!absent.probe().empty(), "no log, no provider");
    record_queue queue{64U};
    require(!std::holds_alternative<bool>(absent.start(queue)), "start fails with a reason");

    dir.write("auth.log", "");
    auth_log_options limited;
    limited.paths = {dir.path / "auth.log"};
    limited.maximum_events_per_poll = 2U;
    auth_log_provider provider{limited};
    require(std::holds_alternative<bool>(provider.start(queue)), "start");
    std::string burst;
    for (int index = 0; index < 5; ++index) burst += iso + "sshd[1]: Failed password for root from 2.2.2.2 port 2 ssh2\n";
    dir.append("auth.log", burst);
    std::vector<raw_auth_event> seen;
    require(wait_for_auth(queue, seen, 2U), "events");
    provider.stop();
    require(seen.size() == 2U && provider.take_governed() == 3U && provider.take_governed() == 0U, "events over the budget are counted, exactly");
}

// A log line over the limit is skipped, and that used to be silent: the tailer counted it and nothing read the count, so a
// failed login padded past the limit disappeared without a trace.
void test_provider_reports_refused_oversize_lines() {
    scratch dir;
    dir.write("auth.log", "");
    auth_log_options options;
    options.paths = {dir.path / "auth.log"};
    options.interval = std::chrono::milliseconds{20};
    auth_log_provider provider{options};
    record_queue queue{64U};
    require(std::holds_alternative<bool>(provider.start(queue)), "start");
    dir.append("auth.log", iso + "sshd[1]: Failed password for invalid user " + std::string(maximum_auth_line_bytes + 100U, 'A') +
                               " from 3.3.3.3 port 3 ssh2\n" + iso + "sshd[2]: Failed password for root from 2.2.2.2 port 2 ssh2\n");
    std::vector<raw_auth_event> seen;
    require(wait_for_auth(queue, seen, 1U), "the ordinary line after the oversize one is delivered");
    provider.stop();
    require(seen.size() == 1U && seen[0].user == "root", "only the ordinary line became an event");
    require(provider.take_refused() == 1U && provider.take_refused() == 0U, "the oversize line is counted, exactly once");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"sshd_logins", test_sshd_logins},
        {"sshd_log_injection_cannot_change_who_or_where", test_sshd_log_injection_cannot_change_who_or_where},
        {"endpoints_are_validated", test_endpoints_are_validated},
        {"privilege_events", test_privilege_events},
        {"traditional_timestamps_and_year_inference", test_traditional_timestamps_and_year_inference},
        {"parser_survives_garbage", test_parser_survives_garbage},
        {"tailer_follows_appends_rotation_and_truncation", test_tailer_follows_appends_rotation_and_truncation},
        {"tailer_skips_oversize_lines_and_waits_for_missing_files", test_tailer_skips_oversize_lines_and_waits_for_missing_files},
        {"provider_reports_new_lines_only", test_provider_reports_new_lines_only},
        {"provider_without_logs_is_unavailable_and_governor_counts", test_provider_without_logs_is_unavailable_and_governor_counts},
        {"provider_reports_refused_oversize_lines", test_provider_reports_refused_oversize_lines},
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
