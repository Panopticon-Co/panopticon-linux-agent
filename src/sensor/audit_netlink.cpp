#include "panopticon/linux_agent/sensor/audit_netlink.hpp"

#include "panopticon/linux_agent/sensor/clock.hpp"

#include <linux/netlink.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <variant>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr int netlink_audit_protocol = 9;       // NETLINK_AUDIT
constexpr unsigned int audit_readlog_group = 1;  // AUDIT_NLGRP_READLOG
constexpr std::uint32_t unset_id = 4294967295U;  // (uid_t)-1
constexpr std::size_t maximum_fields = 64U;
constexpr std::size_t maximum_name_bytes = 256U;
constexpr std::size_t maximum_path_bytes = 512U;
constexpr std::size_t maximum_command_bytes = 1024U;
constexpr std::uint64_t ns_per_second = 1'000'000'000ULL;

struct field {
    std::string_view key;
    std::string_view value;
    bool quoted{false};
};

using fields = std::vector<field>;

// Reads "key=value" tokens. A value is either "double quoted" or runs to the next space; inside
// msg='...' it also stops at the closing quote. Returns the offset where reading stopped. Audit
// encodes any untrusted string that holds a space, a quote or a non-printable byte as hex, so a
// well-formed quoted value never contains '"' and an unquoted one never contains ' '.
std::size_t tokenize(const std::string_view text, const bool inside_msg, fields& out) {
    std::size_t at = 0U;
    while (at < text.size() && out.size() < maximum_fields) {
        while (at < text.size() && text[at] == ' ') ++at;
        if (at >= text.size()) break;
        if (inside_msg && text[at] == '\'') return at;
        const auto begin = at;
        while (at < text.size() && text[at] != '=' && text[at] != ' ' && !(inside_msg && text[at] == '\'')) ++at;
        if (at >= text.size() || text[at] != '=') continue;  // a token without a value
        const auto key = text.substr(begin, at - begin);
        ++at;  // '='
        if (!inside_msg && key == "msg" && at < text.size() && text[at] == '\'') {
            fields inner;
            const auto consumed = tokenize(text.substr(at + 1U), true, inner);
            for (const auto& item : inner) {
                if (out.size() < maximum_fields) out.push_back({item.key, item.value, item.quoted});
            }
            at += 1U + consumed;
            if (at < text.size() && text[at] == '\'') ++at;
            continue;
        }
        if (at < text.size() && text[at] == '"') {
            const auto close = text.find('"', at + 1U);
            if (close == std::string_view::npos) return text.size();  // unterminated: stop reading
            out.push_back({key, text.substr(at + 1U, close - at - 1U), true});
            at = close + 1U;
        } else {
            const auto start = at;
            while (at < text.size() && text[at] != ' ' && !(inside_msg && text[at] == '\'')) ++at;
            out.push_back({key, text.substr(start, at - start), false});
        }
    }
    return at;
}

const field* find(const fields& all, const std::string_view key) {
    for (const auto& item : all) {
        if (item.key == key) return &item;  // the first occurrence wins
    }
    return nullptr;
}

int hex_value(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// A string field: quoted text, "(null)", or hex.
std::optional<std::string> decode_string(const field& item, const std::size_t maximum_raw) {
    if (item.quoted) return std::string{item.value.substr(0U, maximum_raw)};
    if (item.value == "(null)") return std::string{};
    if (item.value.empty() || item.value.size() % 2U != 0U || item.value.size() > maximum_raw * 2U) return std::nullopt;
    std::string out;
    out.reserve(item.value.size() / 2U);
    for (std::size_t index = 0U; index < item.value.size(); index += 2U) {
        const auto high = hex_value(item.value[index]);
        const auto low = hex_value(item.value[index + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        out.push_back(static_cast<char>(high * 16 + low));
    }
    return out;
}

std::optional<std::uint32_t> decode_number(const field* item) {
    if (item == nullptr || item->quoted || item->value.empty() || item->value.size() > 10U) return std::nullopt;
    std::uint64_t value = 0U;
    for (const char c : item->value) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10U + static_cast<std::uint64_t>(c - '0');
    }
    if (value > unset_id) return std::nullopt;
    return static_cast<std::uint32_t>(value);
}

std::string base_name(const std::string_view path) {
    const auto slash = path.rfind('/');
    return std::string{slash == std::string_view::npos ? path : path.substr(slash + 1U)};
}

// "audit(1791253539.217:5854): " -> unix nanoseconds, and the offset after the prefix.
std::optional<std::pair<std::uint64_t, std::size_t>> parse_stamp(const std::string_view text) {
    constexpr std::string_view prefix = "audit(";
    if (text.substr(0U, prefix.size()) != prefix) return std::nullopt;
    std::size_t at = prefix.size();
    std::uint64_t seconds = 0U;
    std::size_t digits = 0U;
    while (at < text.size() && text[at] >= '0' && text[at] <= '9' && digits < 11U) {
        seconds = seconds * 10U + static_cast<std::uint64_t>(text[at] - '0');
        ++at;
        ++digits;
    }
    if (digits == 0U || at >= text.size() || text[at] != '.') return std::nullopt;
    ++at;
    std::uint64_t nanoseconds = 0U;
    std::uint64_t scale = 100'000'000ULL;
    digits = 0U;
    while (at < text.size() && text[at] >= '0' && text[at] <= '9') {
        if (scale != 0U) nanoseconds += static_cast<std::uint64_t>(text[at] - '0') * scale;
        scale /= 10U;
        ++at;
        ++digits;
    }
    if (digits == 0U || at >= text.size() || text[at] != ':') return std::nullopt;
    while (at < text.size() && text[at] != ')') ++at;
    if (at + 1U >= text.size() || text[at + 1U] != ':') return std::nullopt;
    at += 2U;
    while (at < text.size() && text[at] == ' ') ++at;
    return std::pair{seconds * ns_per_second + nanoseconds, at};
}

bool is_login_program(const std::string_view program) { return program == "sshd" || program == "login"; }
bool is_privilege_program(const std::string_view program) { return program == "sudo" || program == "su" || program == "pkexec"; }

}  // namespace

std::vector<audit_message> decode_audit_datagram(const std::uint8_t* const data, const std::size_t size) {
    std::vector<audit_message> out;
    std::size_t at = 0U;
    while (data != nullptr && at <= size && size - at >= sizeof(nlmsghdr)) {
        nlmsghdr header;
        std::memcpy(&header, data + at, sizeof(header));
        if (header.nlmsg_len < sizeof(nlmsghdr) || header.nlmsg_len > size - at) break;
        const std::size_t payload = header.nlmsg_len - sizeof(nlmsghdr);
        if (payload > maximum_audit_text_bytes) break;
        std::string text{reinterpret_cast<const char*>(data + at + sizeof(nlmsghdr)), payload};
        while (!text.empty() && text.back() == '\0') text.pop_back();
        out.push_back({header.nlmsg_type, std::move(text)});
        const std::size_t step = (static_cast<std::size_t>(header.nlmsg_len) + 3U) & ~static_cast<std::size_t>(3U);
        if (step > size - at) break;
        at += step;
    }
    return out;
}

std::optional<parsed_audit_event> parse_audit_record(const std::uint16_t type, const std::string_view text, const uid_lookup& lookup) {
    if (type != audit_user_auth && type != audit_user_start && type != audit_user_login && type != audit_user_cmd) return std::nullopt;
    const auto stamp = parse_stamp(text);
    if (!stamp) return std::nullopt;
    fields all;
    (void)tokenize(text.substr(stamp->second), false, all);
    if (all.empty()) return std::nullopt;

    raw_auth_event event;
    // Only acct, exe, cmd and cwd (the untrusted strings) are quoted or hex-encoded by audit; op,
    // terminal, addr and hostname are plain tokens.
    const auto text_of = [&](const std::string_view key, const std::size_t maximum_raw) -> std::optional<std::string> {
        const auto* item = find(all, key);
        if (item == nullptr) return std::nullopt;
        const bool encoded = key == "acct" || key == "exe" || key == "cmd" || key == "cwd";
        if (!encoded) return std::string{item->value.substr(0U, maximum_raw)};
        return decode_string(*item, maximum_raw);
    };
    const auto name_of = [&](const std::uint32_t uid) {
        if (uid == unset_id) return std::string{};
        return lookup ? lookup(uid) : resolve_user_name(uid);
    };
    const auto result_field = find(all, "res");
    if (result_field == nullptr) return std::nullopt;
    const bool success = result_field->value == "success";
    if (!success && result_field->value != "failed") return std::nullopt;
    if (const auto pid = decode_number(find(all, "pid")); pid && *pid != unset_id) event.pid = *pid;
    const auto uid = decode_number(find(all, "uid"));
    const auto auid = decode_number(find(all, "auid"));
    const auto actor_uid = auid && *auid != unset_id ? auid : uid;

    const auto exe = text_of("exe", maximum_path_bytes);
    const std::string program = exe ? base_name(*exe) : std::string{};
    event.service = sanitize_auth_field(program.empty() ? "unknown" : program, 64U, event);
    if (const auto terminal = text_of("terminal", 64U); terminal && *terminal != "?" && !terminal->empty()) {
        event.tty = sanitize_auth_field(*terminal, 64U, event);
    }
    const auto source_address = text_of("addr", 64U);
    if (source_address && is_ip_address(*source_address)) event.source_address = *source_address;
    const auto account = text_of("acct", maximum_name_bytes);

    switch (type) {
    case audit_user_login: {
        if (!success) return std::nullopt;  // the USER_AUTH failure is the event
        std::string user = account ? *account : std::string{};
        if (user.empty()) {
            if (const auto id = decode_number(find(all, "id"))) user = name_of(*id);
        }
        if (user.empty()) return std::nullopt;
        event.kind = auth_kind::login_success;
        event.user = sanitize_auth_field(user, maximum_name_bytes, event);
        break;
    }
    case audit_user_auth: {
        if (success) return std::nullopt;  // the USER_LOGIN or USER_CMD that follows is the event
        const auto operation = text_of("op", 64U);
        if (!operation || operation->rfind("PAM:authentication", 0U) != 0U) return std::nullopt;
        event.kind = is_privilege_program(program) ? auth_kind::privilege_failure : auth_kind::login_failure;
        event.user = sanitize_auth_field(account && !account->empty() ? *account : std::string{"(unknown)"}, maximum_name_bytes, event);
        if (event.kind == auth_kind::privilege_failure && actor_uid) {
            event.target_user = event.user;
            const auto actor = name_of(*actor_uid);
            if (!actor.empty()) event.user = sanitize_auth_field(actor, maximum_name_bytes, event);
        }
        break;
    }
    case audit_user_cmd: {
        const auto command = text_of("cmd", maximum_command_bytes);
        if (!command || !actor_uid) return std::nullopt;
        event.kind = success ? auth_kind::privilege_success : auth_kind::privilege_failure;
        event.service = program.empty() ? "sudo" : event.service;
        event.user = sanitize_auth_field(name_of(*actor_uid), maximum_name_bytes, event);
        if (event.user.empty()) return std::nullopt;
        if (account) event.target_user = sanitize_auth_field(*account, maximum_name_bytes, event);
        if (const auto cwd = text_of("cwd", maximum_path_bytes)) event.working_directory = sanitize_auth_field(*cwd, maximum_path_bytes, event);
        event.command = sanitize_auth_field(*command, maximum_command_bytes, event);
        break;
    }
    case audit_user_start: {
        if (is_login_program(program) && success) {
            // Real sshd on Ubuntu 22.04 reports a successful login only as this PAM session, with no
            // USER_LOGIN; a USER_LOGIN failure is reported through the USER_AUTH failure instead.
            const auto operation = text_of("op", 64U);
            if (!operation || *operation != "PAM:session_open" || !account || account->empty()) return std::nullopt;
            event.kind = auth_kind::login_success;
            event.user = sanitize_auth_field(*account, maximum_name_bytes, event);
            break;
        }
        if (program != "su" || !success || !actor_uid) return std::nullopt;
        const auto operation = text_of("op", 64U);
        if (!operation || *operation != "PAM:session_open") return std::nullopt;
        event.kind = auth_kind::privilege_success;
        event.user = sanitize_auth_field(name_of(*actor_uid), maximum_name_bytes, event);
        if (event.user.empty()) return std::nullopt;
        if (account) event.target_user = sanitize_auth_field(*account, maximum_name_bytes, event);
        break;
    }
    default:
        return std::nullopt;
    }
    event.method = type == audit_user_cmd || (type == audit_user_start && event.kind != auth_kind::login_success) ? event.service : std::string{};
    return parsed_audit_event{stamp->first, std::move(event)};
}

// ---- security records: mandatory access control and firewall ------------------------------------

namespace {

constexpr std::size_t maximum_object_bytes = 512U;
constexpr std::size_t maximum_label_bytes = 256U;
constexpr std::size_t maximum_permission_bytes = 128U;

std::string clean_text(const std::string_view text, const std::size_t maximum, bool& changed) {
    std::string out;
    out.reserve(std::min(text.size(), maximum));
    for (const char c : text) {
        if (out.size() >= maximum) {
            changed = true;
            break;
        }
        const auto byte = static_cast<unsigned char>(c);
        if (byte >= 0x20U && byte <= 0x7eU) {
            out.push_back(c);
        } else {
            out.push_back('?');
            changed = true;
        }
    }
    return out;
}

bool is_identifier(const std::string_view text, const std::size_t maximum) {
    if (text.empty() || text.size() > maximum) return false;
    for (const char c : text) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return true;
}

std::string family_name(const std::uint32_t family) {
    switch (family) {
    case 1U: return "inet";
    case 2U: return "ipv4";
    case 3U: return "arp";
    case 5U: return "netdev";
    case 7U: return "bridge";
    case 10U: return "ipv6";
    default: return "family-" + std::to_string(family);
    }
}

// The "{ read write }" of an SELinux AVC message.
std::string selinux_permissions(const std::string_view text) {
    const auto open = text.find('{');
    if (open == std::string_view::npos) return {};
    const auto close = text.find('}', open);
    if (close == std::string_view::npos) return {};
    std::string out;
    std::size_t at = open + 1U;
    while (at < close) {
        while (at < close && text[at] == ' ') ++at;
        const auto begin = at;
        while (at < close && text[at] != ' ') ++at;
        if (at > begin) {
            if (!out.empty()) out.push_back(' ');
            out.append(text.substr(begin, at - begin));
        }
    }
    return out.substr(0U, maximum_permission_bytes);
}

std::optional<parsed_audit_security> parse_apparmor(const std::uint64_t time, const fields& all) {
    const auto* verdict = find(all, "apparmor");
    if (verdict == nullptr) return std::nullopt;
    raw_lsm_event event;
    event.module = "apparmor";
    bool changed = false;
    const auto string_of = [&](const std::string_view key, const std::size_t maximum) {
        const auto* item = find(all, key);
        if (item == nullptr) return std::string{};
        // One byte more than the limit, so that clean_text sees the overflow and flags it.
        const auto decoded = decode_string(*item, maximum + 1U);
        return decoded ? clean_text(*decoded, maximum, changed) : std::string{};
    };
    event.operation = string_of("operation", 64U);
    if (!is_identifier(event.operation, 48U)) {
        // AppArmor operation names are lower-case words with underscores (open, file_mmap, profile_load).
        return std::nullopt;
    }
    if (const auto pid = decode_number(find(all, "pid")); pid && *pid != unset_id) event.pid = *pid;
    event.comm = string_of("comm", 64U);
    event.profile = string_of("profile", maximum_label_bytes);
    if (verdict->value == "STATUS") {
        if (event.operation != "profile_load" && event.operation != "profile_replace" && event.operation != "profile_remove") return std::nullopt;
        event.policy_change = true;
        event.object = string_of("name", maximum_object_bytes);
    } else if (verdict->value == "DENIED" || verdict->value == "ALLOWED") {
        event.outcome = verdict->value == "DENIED" ? "denied" : "would_deny";
        event.object = string_of("name", maximum_object_bytes);
        if (event.object.empty()) event.object = string_of("capname", maximum_object_bytes);
        if (event.object.empty()) event.object = string_of("peer", maximum_object_bytes);
        event.requested = string_of("requested_mask", 32U);
        event.denied = string_of("denied_mask", 32U);
    } else {
        return std::nullopt;  // AUDIT (an explicit audit rule), HINT, ERROR
    }
    event.sanitized = changed;
    return parsed_audit_security{time, std::move(event)};
}

std::optional<parsed_audit_security> parse_selinux_avc(const std::uint64_t time, const std::string_view text, const fields& all) {
    // "avc:  denied  { read } for  pid=..."; a granted decision is audited only when a rule asks for it.
    std::size_t at = 4U;  // after "avc:"
    while (at < text.size() && text[at] == ' ') ++at;
    const auto begin = at;
    while (at < text.size() && text[at] != ' ') ++at;
    if (text.substr(begin, at - begin) != "denied") return std::nullopt;
    raw_lsm_event event;
    event.module = "selinux";
    bool changed = false;
    const auto string_of = [&](const std::string_view key, const std::size_t maximum) {
        const auto* item = find(all, key);
        if (item == nullptr) return std::string{};
        // One byte more than the limit, so that clean_text sees the overflow and flags it.
        const auto decoded = decode_string(*item, maximum + 1U);
        return decoded ? clean_text(*decoded, maximum, changed) : std::string{};
    };
    event.denied = selinux_permissions(text);
    if (event.denied.empty()) return std::nullopt;
    event.operation = event.denied.substr(0U, event.denied.find(' '));
    if (const auto pid = decode_number(find(all, "pid")); pid && *pid != unset_id) event.pid = *pid;
    event.comm = string_of("comm", 64U);
    event.object = string_of("name", maximum_object_bytes);
    if (event.object.empty()) event.object = string_of("path", maximum_object_bytes);
    // Contexts and the class are plain tokens (never quoted or hex-encoded) made of word characters.
    const auto plain_of = [&](const std::string_view key, const std::size_t maximum) {
        const auto* item = find(all, key);
        return item == nullptr ? std::string{} : clean_text(item->value, maximum, changed);
    };
    event.profile = plain_of("scontext", maximum_label_bytes);
    event.target_context = plain_of("tcontext", maximum_label_bytes);
    event.object_class = plain_of("tclass", 64U);
    const auto* permissive = find(all, "permissive");
    event.outcome = permissive != nullptr && permissive->value == "1" ? "would_deny" : "denied";
    event.sanitized = changed;
    return parsed_audit_security{time, std::move(event)};
}

std::optional<parsed_audit_security> parse_mac_status(const std::uint64_t time, const std::uint16_t type, const fields& all) {
    const auto* module = find(all, "lsm");
    if (module == nullptr || module->value != "selinux") return std::nullopt;
    const auto* result = find(all, "res");
    if (result == nullptr || result->value != "1") return std::nullopt;
    raw_lsm_event event;
    event.policy_change = true;
    event.module = "selinux";
    if (type == audit_mac_policy_load) {
        event.operation = "policy_load";
    } else {
        const auto number = [&](const std::string_view key) -> std::optional<std::uint32_t> { return decode_number(find(all, key)); };
        const auto enforcing = number("enforcing");
        const auto old_enforcing = number("old_enforcing");
        const auto enabled = number("enabled");
        const auto old_enabled = number("old-enabled");
        if (enabled && old_enabled && *enabled != *old_enabled) {
            event.operation = *enabled != 0U ? "enabled" : "disabled";
        } else if (enforcing && old_enforcing && *enforcing != *old_enforcing) {
            event.operation = *enforcing != 0U ? "enforcing" : "permissive";
        } else {
            return std::nullopt;  // a status record that changed nothing
        }
    }
    return parsed_audit_security{time, std::move(event)};
}

std::optional<parsed_audit_security> parse_netfilter(const std::uint64_t time, const fields& all) {
    raw_firewall_change event;
    const auto* table = find(all, "table");
    const auto* operation = find(all, "op");
    if (table == nullptr || operation == nullptr) return std::nullopt;
    if (!is_identifier(operation->value, 48U)) return std::nullopt;
    event.operation = std::string{operation->value};
    event.subsystem = operation->value.rfind("nft_", 0U) == 0U ? "nft" : operation->value.rfind("xt_", 0U) == 0U ? "xtables" : "other";
    // nftables appends the ruleset generation: "raw:48".
    std::string_view name = table->value;
    if (const auto colon = name.rfind(':'); colon != std::string_view::npos && colon + 1U < name.size()) {
        const auto digits = name.substr(colon + 1U);
        std::uint64_t generation = 0U;
        bool numeric = digits.size() <= 18U;
        for (const char c : digits) {
            if (c < '0' || c > '9') numeric = false;
            else generation = generation * 10U + static_cast<std::uint64_t>(c - '0');
        }
        if (numeric) {
            event.generation = generation;
            name = name.substr(0U, colon);
        }
    }
    bool changed = false;
    event.table = clean_text(name, 64U, changed);
    if (event.table.empty()) return std::nullopt;
    if (const auto family = decode_number(find(all, "family"))) event.family = family_name(*family);
    else event.family = "family-0";
    if (const auto entries = decode_number(find(all, "entries"))) event.entries = *entries;
    if (const auto pid = decode_number(find(all, "pid")); pid && *pid != unset_id) event.pid = *pid;
    if (const auto* comm = find(all, "comm")) {
        if (const auto decoded = decode_string(*comm, 65U)) event.comm = clean_text(*decoded, 64U, changed);
    }
    return parsed_audit_security{time, std::move(event)};
}

}  // namespace

std::optional<parsed_audit_security> parse_audit_security_record(const std::uint16_t type, const std::string_view text) {
    const bool apparmor_type = type >= audit_apparmor_audit && type <= audit_apparmor_error;
    if (type != audit_avc && type != audit_mac_policy_load && type != audit_mac_status && type != audit_netfilter_cfg && !apparmor_type) {
        return std::nullopt;
    }
    const auto stamp = parse_stamp(text);
    if (!stamp) return std::nullopt;
    const auto body = text.substr(stamp->second);
    fields all;
    (void)tokenize(body, false, all);
    if (all.empty() && body.rfind("avc:", 0U) != 0U) return std::nullopt;
    if (type == audit_netfilter_cfg) return parse_netfilter(stamp->first, all);
    if (type == audit_mac_policy_load || type == audit_mac_status) return parse_mac_status(stamp->first, type, all);
    if (body.rfind("avc:", 0U) == 0U) return parse_selinux_avc(stamp->first, body, all);
    return parse_apparmor(stamp->first, all);
}

std::string resolve_user_name(const std::uint32_t uid) {
    static std::mutex mutex;
    static std::unordered_map<std::uint32_t, std::string> cache;
    {
        const std::lock_guard lock{mutex};
        if (const auto found = cache.find(uid); found != cache.end()) return found->second;
    }
    std::string name = "uid:" + std::to_string(uid);
    std::vector<char> buffer(4096U);
    passwd entry{};
    passwd* found = nullptr;
    if (::getpwuid_r(uid, &entry, buffer.data(), buffer.size(), &found) == 0 && found != nullptr && found->pw_name != nullptr) name = found->pw_name;
    const std::lock_guard lock{mutex};
    if (cache.size() >= 1024U) cache.clear();
    cache.emplace(uid, name);
    return name;
}

// ---- provider --------------------------------------------------------------------------------

audit_netlink_provider::audit_netlink_provider(audit_netlink_options options) : options_{std::move(options)} {}

audit_netlink_provider::~audit_netlink_provider() { stop(); }

std::vector<std::string> audit_netlink_provider::capabilities() const { return {"auth.login", "auth.failure", "auth.privilege", "lsm.denial", "lsm.policy", "netfilter.config_change"}; }

namespace {

// Opens the audit socket and joins the read-log multicast group. Returns -1 with `reason` set.
int open_audit_socket(const std::size_t receive_buffer, std::string& reason) {
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, netlink_audit_protocol);
    if (fd < 0) {
        reason = std::string{"cannot open an audit socket: "} + std::strerror(errno);
        return -1;
    }
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = audit_readlog_group;
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        reason = std::string{"cannot join the audit multicast group (needs CAP_AUDIT_READ): "} + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    const int size = static_cast<int>(std::min<std::size_t>(receive_buffer, 1U << 24U));
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    return fd;
}

}  // namespace

std::string audit_netlink_provider::probe() {
    std::string reason;
    const int fd = open_audit_socket(options_.receive_buffer_bytes, reason);
    if (fd < 0) return reason;
    ::close(fd);
    return {};
}

result<bool> audit_netlink_provider::start(record_queue& queue) {
    if (running_.load()) return true;
    std::string reason;
    const int fd = open_audit_socket(options_.receive_buffer_bytes, reason);
    if (fd < 0) return error{error_code::io_failure, reason};
    fd_ = fd;
    queue_ = &queue;
    running_.store(true);
    thread_ = std::thread{[this] { run(); }};
    return true;
}

void audit_netlink_provider::handle(const std::uint8_t* const data, const std::size_t size) {
    for (const auto& message : decode_audit_datagram(data, size)) {
        ++seen_;
        raw_record record;
        record.source = {"audit_netlink", "AUDIT", confidence::observed};
        if (auto parsed = parse_audit_record(message.type, message.text, options_.lookup)) {
            record.time_unix_ns = parsed->time_unix_ns;
            record.payload = std::move(parsed->event);
        } else if (auto security = parse_audit_security_record(message.type, message.text)) {
            record.time_unix_ns = security->time_unix_ns;
            std::visit([&](auto&& event) { record.payload = std::forward<decltype(event)>(event); }, std::move(security->event));
        } else {
            continue;
        }
        const auto second = clock_domain::now_unix_ns() / ns_per_second;
        if (second != window_second_) {
            window_second_ = second;
            window_count_ = 0U;
        }
        if (window_count_ >= options_.maximum_events_per_second) {
            ++governed_;
            continue;
        }
        ++window_count_;
        if (queue_ != nullptr && queue_->push(std::move(record))) ++events_;
    }
}

void audit_netlink_provider::run() {
    std::vector<std::uint8_t> buffer(65536U);
    while (running_.load()) {
        pollfd waiting{fd_, POLLIN, 0};
        const int ready = ::poll(&waiting, 1, static_cast<int>(options_.poll_interval.count()));
        if (ready <= 0) continue;
        for (;;) {
            sockaddr_nl from{};
            socklen_t from_size = sizeof(from);
            const auto received = ::recvfrom(fd_, buffer.data(), buffer.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&from), &from_size);
            if (received < 0) {
                if (errno == ENOBUFS) ++losses_;  // the kernel dropped audit records we did not read in time
                if (errno == EINTR || errno == ENOBUFS) continue;
                break;
            }
            // Only the kernel (portid 0) speaks on this group; anything else is ignored.
            if (from_size >= sizeof(sockaddr_nl) && from.nl_pid == 0U) handle(buffer.data(), static_cast<std::size_t>(received));
        }
    }
}

void audit_netlink_provider::stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

provider_health audit_netlink_provider::health() const {
    const bool active = running_.load();
    std::string reason;
    if (active && seen_.load() == 0U) reason = "no audit records seen yet; auditing may be disabled on this host";
    return {std::string{name()}, active ? "active" : "stopped", reason, capabilities(), events_.load(), governed_.load()};
}

}  // namespace panopticon::linux_agent::sensor
