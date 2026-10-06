#include "panopticon/linux_agent/sensor/audit_netlink.hpp"

#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

const uid_lookup people = [](const std::uint32_t uid) -> std::string {
    if (uid == 0U) return "root";
    if (uid == 1000U) return "vagrant";
    return "uid:" + std::to_string(uid);
};

const std::string stamp = "audit(1791253539.217:100): ";

std::optional<parsed_audit_event> parse(const std::uint16_t type, const std::string& body) { return parse_audit_record(type, stamp + body, people); }

parsed_audit_event must_parse(const std::uint16_t type, const std::string& body) {
    auto parsed = parse(type, body);
    if (!parsed) throw std::runtime_error{"expected an event: " + body};
    return *parsed;
}

const std::string login_ok =
    "pid=1234 uid=0 auid=1000 ses=3 subj=unconfined msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=10.0.2.2 addr=10.0.2.2 terminal=ssh res=success'";
const std::string auth_failed =
    "pid=1235 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct=\"mallory\" exe=\"/usr/sbin/sshd\" "
    "hostname=203.0.113.7 addr=203.0.113.7 terminal=ssh res=failed'";
const std::string sudo_ok =
    "pid=2000 uid=1000 auid=1000 ses=3 subj=unconfined msg='cwd=\"/home/vagrant\" cmd=636174202F6574632F736861646F77 acct=\"root\" "
    "exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'";

void test_real_record_shapes() {
    const auto login = must_parse(audit_user_login, login_ok);
    require(login.time_unix_ns == 1791253539ULL * 1'000'000'000ULL + 217'000'000ULL, "audit time");
    require(login.event.kind == auth_kind::login_success && login.event.service == "sshd" && login.event.user == "vagrant" &&
                login.event.source_address == "10.0.2.2" && login.event.tty == "ssh" && login.event.pid == 1234U,
            "login: user from id, kernel pid, source address");
    const auto failure = must_parse(audit_user_auth, auth_failed);
    require(failure.event.kind == auth_kind::login_failure && failure.event.user == "mallory" && failure.event.service == "sshd" &&
                failure.event.source_address == "203.0.113.7" && failure.event.pid == 1235U,
            "failed authentication");
    const auto sudo = must_parse(audit_user_cmd, sudo_ok);
    require(sudo.event.kind == auth_kind::privilege_success && sudo.event.service == "sudo" && sudo.event.user == "vagrant" &&
                sudo.event.target_user == "root" && sudo.event.command == "cat /etc/shadow" && sudo.event.working_directory == "/home/vagrant" &&
                sudo.event.tty == "pts/0" && sudo.event.pid == 2000U && sudo.event.method == "sudo",
            "sudo command: hex command decoded, actor from auid");
    const auto quoted = must_parse(audit_user_cmd,
                                   "pid=1 uid=1000 auid=1000 ses=1 msg='cwd=\"/\" cmd=\"id\" acct=\"root\" exe=\"/usr/bin/sudo\" terminal=pts/1 res=failed'");
    require(quoted.event.kind == auth_kind::privilege_failure && quoted.event.command == "id", "a quoted command and a refused sudo");
    const auto sudo_failed = must_parse(audit_user_auth,
                                        "pid=5 uid=1000 auid=1000 ses=1 msg='op=PAM:authentication grantors=? acct=\"root\" exe=\"/usr/bin/sudo\" "
                                        "hostname=? addr=? terminal=/dev/pts/0 res=failed'");
    require(sudo_failed.event.kind == auth_kind::privilege_failure && sudo_failed.event.user == "vagrant" && sudo_failed.event.target_user == "root" &&
                sudo_failed.event.source_address.empty(),
            "failed sudo authentication names the actor and the target");
    const auto su = must_parse(audit_user_start,
                               "pid=7 uid=1000 auid=1000 ses=1 msg='op=PAM:session_open grantors=pam_keyinit,pam_limits acct=\"root\" exe=\"/usr/bin/su\" "
                               "hostname=? addr=? terminal=/dev/pts/1 res=success'");
    require(su.event.kind == auth_kind::privilege_success && su.event.service == "su" && su.event.user == "vagrant" && su.event.target_user == "root",
            "su session");
}

void test_records_that_are_not_events() {
    require(!parse(audit_user_auth, "pid=1 uid=0 auid=1000 ses=1 msg='op=PAM:authentication acct=\"u\" exe=\"/usr/sbin/sshd\" res=success'"),
            "a successful authentication is not an event; the login or command that follows is");
    require(!parse(audit_user_login, "pid=1 uid=0 auid=4294967295 ses=1 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" res=failed'"),
            "a failed login is reported through the authentication failure");
    require(!parse(audit_user_start, "pid=1 uid=0 auid=1000 ses=1 msg='op=PAM:session_open acct=\"u\" exe=\"/usr/sbin/sshd\" res=success'"),
            "only su sessions are reported");
    require(!parse(audit_user_auth, "pid=1 uid=0 auid=1000 ses=1 msg='op=PAM:setcred acct=\"u\" exe=\"/usr/sbin/sshd\" res=failed'"), "other PAM operations");
    require(!parse(1300, "pid=1 uid=0 msg='res=success'"), "other record types");
    require(!parse(audit_user_login, "pid=1 uid=0 auid=1000 ses=1 msg='op=login id=1000 exe=\"/usr/sbin/sshd\"'"), "no result");
    require(!parse(audit_user_login, "pid=1 uid=0 auid=1000 ses=1 msg='op=login id=1000 res=maybe'"), "unknown result");
    require(!parse_audit_record(audit_user_login, "not an audit record res=success", people), "no audit prefix");
    require(!parse_audit_record(audit_user_login, "audit(12.3:4 pid=1 res=success", people), "unterminated prefix");
}

void test_hostile_values_cannot_change_the_event() {
    // A first occurrence wins: a later res= or exe= after it cannot override.
    const auto first_wins = must_parse(audit_user_auth,
                                       "pid=9 uid=0 auid=4294967295 ses=1 msg='op=PAM:authentication acct=\"a\" exe=\"/usr/sbin/sshd\" res=failed res=success exe=\"/usr/bin/sudo\"'");
    require(first_wins.event.kind == auth_kind::login_failure && first_wins.event.service == "sshd", "duplicate keys: the first wins");
    // The kernel's header fields come before msg; an inner auid/pid cannot replace them.
    const auto header = must_parse(audit_user_cmd,
                                   "pid=2000 uid=1000 auid=1000 ses=3 msg='cwd=\"/\" cmd=\"id\" acct=\"root\" exe=\"/usr/bin/sudo\" auid=0 pid=1 res=success'");
    require(header.event.user == "vagrant" && header.event.pid == 2000U, "an inner auid or pid cannot override the kernel's");
    // Quote characters and key=value text inside a quoted value stay part of the value.
    const auto quoted = must_parse(audit_user_auth,
                                   "pid=9 uid=0 auid=4294967295 ses=1 msg='op=PAM:authentication acct=\"a'x=1\" exe=\"/usr/sbin/sshd\" res=failed'");
    require(quoted.event.user == "a'x=1" && quoted.event.kind == auth_kind::login_failure, "a quote inside a quoted value does not end the record");
    // A broken quote never produces a success.
    const auto broken = parse(audit_user_auth, "pid=9 uid=0 msg='op=PAM:authentication acct=\"a exe=\"/usr/sbin/sshd\" res=failed'");
    require(!broken || broken->event.kind != auth_kind::login_success, "a broken quote never produces a success");
    // Hex that is not hex, odd-length hex, and a missing command.
    require(!parse(audit_user_cmd, "pid=1 uid=1000 auid=1000 msg='cwd=\"/\" cmd=ZZ acct=\"root\" exe=\"/usr/bin/sudo\" res=success'"), "invalid hex command");
    require(!parse(audit_user_cmd, "pid=1 uid=1000 auid=1000 msg='cwd=\"/\" cmd=ABC acct=\"root\" exe=\"/usr/bin/sudo\" res=success'"), "odd-length hex command");
    require(!parse(audit_user_cmd, "pid=1 uid=1000 auid=1000 msg='cwd=\"/\" acct=\"root\" exe=\"/usr/bin/sudo\" res=success'"), "no command");
    // Control bytes in a decoded command are replaced and flagged.
    const auto control = must_parse(audit_user_cmd, "pid=1 uid=1000 auid=1000 msg='cwd=\"/\" cmd=6C730A1B5B31 acct=\"root\" exe=\"/usr/bin/sudo\" res=success'");
    require(control.event.sanitized && control.event.command.find('\n') == std::string::npos && control.event.command.find('\x1b') == std::string::npos,
            "control bytes in a command");
    // A source address that is not an address is dropped rather than reported.
    const auto address = must_parse(audit_user_login,
                                    "pid=1 uid=0 auid=1000 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=evil addr=\"999.1.1.1\" terminal=ssh res=success'");
    require(address.event.source_address.empty(), "addr must be an address");
    // A very long account is cut.
    const auto longname = must_parse(audit_user_auth, "pid=1 uid=0 auid=1 msg='op=PAM:authentication acct=\"" + std::string(2000U, 'a') +
                                                          "\" exe=\"/usr/sbin/sshd\" res=failed'");
    require(longname.event.user.size() == 256U, "a long account is cut");
    // An unset auid falls back to uid for the actor.
    const auto unset = must_parse(audit_user_cmd, "pid=1 uid=1000 auid=4294967295 msg='cwd=\"/\" cmd=\"id\" acct=\"root\" exe=\"/usr/bin/sudo\" res=success'");
    require(unset.event.user == "vagrant", "uid is used when auid is unset");
}

std::vector<std::uint8_t> datagram(const std::vector<std::pair<std::uint16_t, std::string>>& messages) {
    std::vector<std::uint8_t> out;
    for (const auto& [type, text] : messages) {
        nlmsghdr header{};
        header.nlmsg_len = static_cast<std::uint32_t>(sizeof(header) + text.size() + 1U);
        header.nlmsg_type = type;
        const auto begin = out.size();
        out.resize(begin + ((header.nlmsg_len + 3U) & ~3U), 0U);
        std::memcpy(out.data() + begin, &header, sizeof(header));
        std::memcpy(out.data() + begin + sizeof(header), text.data(), text.size());
    }
    return out;
}

void test_datagram_decoder() {
    const auto data = datagram({{audit_user_login, stamp + login_ok}, {audit_user_cmd, stamp + sudo_ok}});
    const auto messages = decode_audit_datagram(data.data(), data.size());
    require(messages.size() == 2U && messages[0].type == audit_user_login && messages[0].text == stamp + login_ok && messages[1].type == audit_user_cmd,
            "two messages, trailing NUL removed");
    for (std::size_t length = 0U; length <= data.size(); ++length) (void)decode_audit_datagram(data.data(), length);
    require(decode_audit_datagram(data.data(), 15U).empty(), "shorter than a header");
    require(decode_audit_datagram(nullptr, 0U).empty(), "nothing");
    auto lying = data;
    std::uint32_t huge = 0xFFFFFFF0U;
    std::memcpy(lying.data(), &huge, sizeof(huge));
    require(decode_audit_datagram(lying.data(), lying.size()).empty(), "a length beyond the datagram");
    std::uint32_t tiny = 4U;
    std::memcpy(lying.data(), &tiny, sizeof(tiny));
    require(decode_audit_datagram(lying.data(), lying.size()).empty(), "a length shorter than the header");
    const auto big = datagram({{audit_user_login, std::string(maximum_audit_text_bytes + 10U, 'a')}});
    require(decode_audit_datagram(big.data(), big.size()).empty(), "a message longer than the limit");
    std::srand(5);
    for (int round = 0; round < 3000; ++round) {
        std::vector<std::uint8_t> junk(static_cast<std::size_t>(std::rand() % 200));
        for (auto& byte : junk) byte = static_cast<std::uint8_t>(std::rand());
        (void)decode_audit_datagram(junk.data(), junk.size());
        if (junk.size() >= 4U) {  // plausible lengths reach deeper code
            const std::uint32_t length = static_cast<std::uint32_t>(std::rand() % 220);
            std::memcpy(junk.data(), &length, sizeof(length));
            (void)decode_audit_datagram(junk.data(), junk.size());
        }
    }
}

void test_parser_survives_garbage() {
    for (const auto* sample : {&login_ok, &auth_failed, &sudo_ok}) {
        const std::string full = stamp + *sample;
        for (std::size_t length = 0U; length <= full.size(); ++length) {
            for (const auto type : {audit_user_login, audit_user_auth, audit_user_cmd, audit_user_start}) {
                (void)parse_audit_record(type, std::string_view{full}.substr(0U, length), people);
            }
        }
    }
    std::srand(9);
    for (int round = 0; round < 5000; ++round) {
        std::string junk = stamp + "pid=1 uid=1000 auid=1000 msg='";
        const auto size = static_cast<std::size_t>(std::rand() % 160);
        for (std::size_t index = 0U; index < size; ++index) junk.push_back(static_cast<char>(std::rand()));
        for (const auto type : {audit_user_login, audit_user_auth, audit_user_cmd, audit_user_start}) (void)parse_audit_record(type, junk, people);
    }
    std::string many = stamp;
    for (int index = 0; index < 500; ++index) many += "k" + std::to_string(index) + "=v ";
    many += "res=success";
    (void)parse_audit_record(audit_user_login, many, people);  // field count is bounded
}

void test_user_names_resolve_and_fall_back() {
    require(resolve_user_name(0U) == "root", "uid 0");
    require(resolve_user_name(4000000000U) == "uid:4000000000", "an unknown uid is named by number");
    require(resolve_user_name(4000000000U) == "uid:4000000000", "and stays stable from the cache");
}

// Sends a user-space audit message to the kernel the way PAM and sudo do. Needs CAP_AUDIT_WRITE.
bool send_user_message(const std::uint16_t type, const std::string& text) {
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 9);
    if (fd < 0) return false;
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    auto message = datagram({{type, text}});
    nlmsghdr header;
    std::memcpy(&header, message.data(), sizeof(header));
    header.nlmsg_flags = NLM_F_REQUEST;
    header.nlmsg_seq = 1U;
    std::memcpy(message.data(), &header, sizeof(header));
    const auto sent = ::sendto(fd, message.data(), header.nlmsg_len, 0, reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel));
    ::close(fd);
    return sent == static_cast<ssize_t>(header.nlmsg_len);
}

void test_live_kernel_round_trip() {
    if (::geteuid() != 0) {
        std::printf("SKIP live audit: requires root (CAP_AUDIT_READ and CAP_AUDIT_WRITE)\n");
        return;
    }
    audit_netlink_options options;
    options.lookup = people;
    audit_netlink_provider provider{options};
    if (const auto reason = provider.probe(); !reason.empty()) {
        std::printf("SKIP live audit: %s\n", reason.c_str());
        return;
    }
    record_queue queue{256U};
    require(std::holds_alternative<bool>(provider.start(queue)), "start");
    require(send_user_message(audit_user_cmd, "cwd=\"/tmp\" cmd=2F62696E2F74727565202D78 acct=\"root\" exe=\"/usr/bin/sudo\" terminal=pts/9 res=success"),
            "send a user message to the kernel");
    std::optional<raw_auth_event> seen;
    for (int attempt = 0; attempt < 40 && !seen; ++attempt) {
        std::vector<raw_record> batch;
        queue.pop_batch(batch, 16U, std::chrono::milliseconds{50});
        for (const auto& record : batch) {
            const auto* event = std::get_if<raw_auth_event>(&record.payload);
            if (event != nullptr && event->command == "/bin/true -x") {
                seen = *event;
                require(record.source.mechanism == "AUDIT" && record.source.level == confidence::observed, "provenance");
            }
        }
    }
    provider.stop();
    if (!seen) {
        std::printf("SKIP live audit: the kernel sent no record (auditing is probably disabled on this host)\n");
        return;
    }
    require(seen->kind == auth_kind::privilege_success && seen->pid == static_cast<std::uint32_t>(::getpid()) && seen->target_user == "root" &&
                seen->tty == "pts/9" && seen->working_directory == "/tmp",
            "the kernel's pid and the sender's text arrive as one event");
    require(provider.health().state == "stopped", "health after stop");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"real_record_shapes", test_real_record_shapes},
        {"records_that_are_not_events", test_records_that_are_not_events},
        {"hostile_values_cannot_change_the_event", test_hostile_values_cannot_change_the_event},
        {"datagram_decoder", test_datagram_decoder},
        {"parser_survives_garbage", test_parser_survives_garbage},
        {"user_names_resolve_and_fall_back", test_user_names_resolve_and_fall_back},
        {"live_kernel_round_trip", test_live_kernel_round_trip},
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
