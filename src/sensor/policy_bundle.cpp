#include "panopticon/linux_agent/sensor/policy_bundle.hpp"

#include "panopticon/linux_agent/durable_file.hpp"
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/trusted_path.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>

#include <sys/stat.h>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::string_view magic_line = "panopticon-policy 1";
constexpr std::string_view separator_line = "---";
constexpr std::string_view state_magic = "panopticon-policy-state 1";
constexpr std::array<std::string_view, 7U> header_names{"policy_id", "version", "issued_at", "expires_at", "scope", "key_id", "signature"};
constexpr std::size_t maximum_header_value_bytes = 256U;

void append_field(std::string& out, const std::string_view name, const std::string_view value) {
    out += name;
    out += ':';
    out += std::to_string(value.size());
    out += ':';
    out += value;
    out += '\n';
}

// Plain decimal: digits only, no sign, no leading zero (except "0" itself), within the type.
template <typename integer_type>
std::optional<integer_type> decimal(const std::string_view text) {
    if (text.empty() || text.size() > 19U || (text.size() > 1U && text.front() == '0')) return std::nullopt;
    if (!std::all_of(text.begin(), text.end(), [](const char c) { return c >= '0' && c <= '9'; })) return std::nullopt;
    integer_type value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

bool lower_hex(const std::string_view text, const std::size_t length) {
    return text.size() == length && std::all_of(text.begin(), text.end(), [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

std::string read_bounded(const std::filesystem::path& path, const std::uint64_t maximum, bool& too_large, bool& unreadable) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        unreadable = true;
        return {};
    }
    std::string text;
    std::array<char, 65536U> chunk{};
    while (input) {
        input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const auto got = static_cast<std::size_t>(input.gcount());
        if (text.size() + got > maximum) {
            too_large = true;
            return {};
        }
        text.append(chunk.data(), got);
    }
    if (input.bad()) unreadable = true;
    return text;
}

std::string describe(const policy_bundle& bundle) {
    return "policy " + bundle.header.policy_id + " version " + std::to_string(bundle.header.version);
}

}  // namespace

std::string policy_signing_input(const policy_header& header, const std::string_view body_sha256_hex) {
    std::string out{"panopticon-policy/1\n"};
    append_field(out, "policy_id", header.policy_id);
    append_field(out, "version", std::to_string(header.version));
    append_field(out, "issued_at", std::to_string(header.issued_unix));
    append_field(out, "expires_at", std::to_string(header.expires_unix));
    append_field(out, "scope", header.scope);
    append_field(out, "body_sha256", body_sha256_hex);
    return out;
}

result<policy_bundle> parse_policy_bundle(const std::string_view text, const policy_limits& limits) {
    const auto fail = [](const std::string& why) -> result<policy_bundle> { return error{error_code::invalid_input, "policy header: " + why}; };
    std::size_t cursor = 0U;
    // Every header line, and the separator, ends with a newline; a carriage return is not tolerated in the header.
    const auto next_line = [&](std::string_view& line) {
        if (cursor >= text.size()) return false;
        const auto newline = text.find('\n', cursor);
        if (newline == std::string_view::npos) return false;
        line = text.substr(cursor, newline - cursor);
        cursor = newline + 1U;
        return true;
    };
    std::string_view line;
    if (!next_line(line) || line != magic_line) return fail("the first line must be \"panopticon-policy 1\"");
    std::array<std::string_view, header_names.size()> values{};
    for (std::size_t index = 0U; index < header_names.size(); ++index) {
        const std::string name{header_names[index]};
        if (!next_line(line)) return fail("missing " + name);
        const auto space = line.find(' ');
        if (space == std::string_view::npos || line.substr(0U, space) != header_names[index]) {
            return fail("line " + std::to_string(index + 2U) + " must be " + name);
        }
        values[index] = line.substr(space + 1U);
        const bool printable = std::all_of(values[index].begin(), values[index].end(), [](const unsigned char c) { return c > 0x20U && c < 0x7fU; });
        if (values[index].empty() || values[index].size() > maximum_header_value_bytes || !printable) return fail("bad value for " + name);
    }
    if (!next_line(line) || line != separator_line) return fail("the header must be followed by a line \"---\"");
    const auto body = text.substr(cursor);

    policy_header header;
    header.policy_id = std::string{values[0]};
    if (!is_valid_identifier(header.policy_id)) return fail("policy_id must be an identifier (letters, digits, '.', '_', '-')");
    const auto version = decimal<std::uint64_t>(values[1]);
    if (!version || *version == 0U || *version > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return fail("version must be a decimal from 1 to 2^63-1");
    }
    header.version = *version;
    const auto issued = decimal<std::int64_t>(values[2]);
    const auto expires = decimal<std::int64_t>(values[3]);
    // At most 10 digits (year 2286): the time is reported in nanoseconds, which must fit in 64 bits.
    constexpr std::int64_t latest_unix = 9'999'999'999LL;
    if (!issued || !expires || *issued > latest_unix || *expires > latest_unix) {
        return fail("issued_at and expires_at must be decimal unix seconds up to 9999999999");
    }
    if (*expires <= *issued) return fail("expires_at must be after issued_at");
    header.issued_unix = *issued;
    header.expires_unix = *expires;
    header.scope = std::string{values[4]};
    if (header.scope != "all" && !(header.scope.rfind("host:", 0U) == 0U && is_valid_identifier(std::string_view{header.scope}.substr(5U)))) {
        return fail("scope must be \"all\" or \"host:<host_id>\"");
    }
    header.key_id = std::string{values[5]};
    if (!lower_hex(header.key_id, 16U)) return fail("key_id must be 16 lowercase hex digits");
    const auto signature = decode_base64(values[6]);
    if (!signature || signature->size() != header.signature.size()) return fail("signature must be the base64 of 64 bytes");
    std::copy(signature->begin(), signature->end(), header.signature.begin());

    auto engine = policy_engine::parse(body, limits);
    if (!succeeded(engine)) return std::get<error>(engine);
    return policy_bundle{std::move(header), sha256_hex(body), std::move(std::get<policy_engine>(engine))};
}

policy_store::policy_store(policy_store_options options) : options_{std::move(options)} { load_saved_state(); }

policy_store::~policy_store() = default;

void policy_store::load_saved_state() {
    std::error_code ignored;
    if (!std::filesystem::exists(options_.state_path, ignored)) return;
    bool too_large = false;
    bool unreadable = false;
    const auto text = read_bounded(options_.state_path, 4096U, too_large, unreadable);
    std::istringstream lines{text};
    std::string line;
    saved_state state;
    bool ok = !too_large && !unreadable && std::getline(lines, line) && line == state_magic;
    std::size_t seen = 0U;
    while (ok && std::getline(lines, line)) {
        const auto equals = line.find('=');
        if (equals == std::string::npos) {
            ok = false;
            break;
        }
        const auto key = line.substr(0U, equals);
        const auto value = line.substr(equals + 1U);
        if (key == "policy_id") {
            state.policy_id = value;
        } else if (key == "version") {
            const auto parsed = decimal<std::uint64_t>(value);
            if (!parsed) ok = false;
            else state.version = *parsed;
        } else if (key == "body_sha256") {
            state.body_sha256 = value;
        } else {
            ok = false;
        }
        ++seen;
    }
    if (ok && seen == 3U && is_valid_identifier(state.policy_id) && state.version > 0U && lower_hex(state.body_sha256, 64U)) {
        saved_ = std::move(state);
    } else {
        // Present but not readable as a state: monotonicity cannot be checked against it. The next valid policy is
        // accepted, and its record says the state was unreadable.
        saved_unreadable_ = true;
    }
}

policy_change policy_store::rejected(std::string reason, std::string detail, const policy_bundle* candidate) const {
    policy_change change;
    change.outcome = "rejected";
    change.reason = std::move(reason);
    if (candidate != nullptr) {
        change.policy_id = candidate->header.policy_id;
        change.version = candidate->header.version;
        change.key_id = candidate->header.key_id;
        change.rules = candidate->engine.rule_count();
        change.indicators = candidate->engine.ioc_count();
        change.expires_unix = candidate->header.expires_unix;
    }
    if (active_) {
        change.previous_version = active_->header.version;
        detail += "; " + describe(*active_) + " stays in force";
    } else {
        detail += "; no policy is in force";
    }
    change.detail = std::move(detail);
    return change;
}

policy_change policy_store::about_active(std::string outcome, std::string reason, std::string detail) const {
    policy_change change;
    change.outcome = std::move(outcome);
    change.reason = std::move(reason);
    change.policy_id = active_->header.policy_id;
    change.version = active_->header.version;
    change.key_id = active_->header.key_id;
    change.rules = active_->engine.rule_count();
    change.indicators = active_->engine.ioc_count();
    change.expires_unix = active_->header.expires_unix;
    change.detail = std::move(detail);
    return change;
}

std::vector<policy_change> policy_store::refresh(const std::int64_t now_unix) {
    std::vector<policy_change> changes;
    if (!keys_) {
        auto loaded = command_keyring::load(options_.keys_path, "policy signing key file");
        if (succeeded(loaded)) {
            keys_ = std::move(std::get<std::unique_ptr<command_keyring>>(loaded));
            keys_error_.clear();
        } else {
            keys_error_ = std::get<error>(loaded).message;
        }
    } else {
        keys_->refresh();
        keys_error_ = keys_->last_error();
    }
    std::string fingerprint;
    if (keys_) {
        for (const auto& id : keys_->key_ids()) fingerprint += id + ",";
    }
    const bool keys_changed = fingerprint != keys_fingerprint_;
    keys_fingerprint_ = std::move(fingerprint);

    const auto path = options_.policy_path.string();
    struct stat info {};
    if (::stat(options_.policy_path.c_str(), &info) != 0) {
        if (!file_missing_) {
            file_missing_ = true;
            file_size_ = -1;
            file_mtime_ns_ = -1;
            file_ctime_ns_ = -1;
            file_inode_ = 0U;
            last_file_digest_.clear();
            if (active_) {
                changes.push_back(about_active("removed", "file_missing", "the policy file " + path + " is missing; " + describe(*active_) + " stays in force"));
            } else {
                refused_reason_ = "file_missing: the policy file " + path + " is missing";
                changes.push_back(rejected("file_missing", "the policy file " + path + " is missing", nullptr));
            }
        }
    } else {
        file_missing_ = false;
        const auto size = static_cast<std::int64_t>(info.st_size);
        const auto mtime = static_cast<std::int64_t>(info.st_mtim.tv_sec) * 1'000'000'000LL + info.st_mtim.tv_nsec;
        const auto ctime = static_cast<std::int64_t>(info.st_ctim.tv_sec) * 1'000'000'000LL + info.st_ctim.tv_nsec;
        const auto inode = static_cast<std::uint64_t>(info.st_ino);
        // Written within the last two seconds: a further write in the same timestamp tick would leave the identity
        // unchanged, so the content is checked again (the digest makes that free of new records).
        const bool racy = static_cast<std::int64_t>(info.st_mtim.tv_sec) >= now_unix - 1 || static_cast<std::int64_t>(info.st_ctim.tv_sec) >= now_unix - 1;
        // A changed key set can make a refused file valid (its key was pinned), so it is a reason to decide again. The
        // policy in force stays even if its key is removed: a key file that changed is no reason to stop detecting.
        if (size != file_size_ || mtime != file_mtime_ns_ || ctime != file_ctime_ns_ || inode != file_inode_ || racy || keys_changed) {
            file_size_ = size;
            file_mtime_ns_ = mtime;
            file_ctime_ns_ = ctime;
            file_inode_ = inode;
            if (auto change = consider(now_unix, keys_changed)) changes.push_back(std::move(*change));
        }
    }
    if (active_ && now_unix >= active_->header.expires_unix && !expired_reported_) {
        expired_reported_ = true;
        changes.push_back(about_active("expired", "expired",
                                       describe(*active_) + " expired at unix " + std::to_string(active_->header.expires_unix) +
                                           " s; it makes no decisions until a newer valid policy is in place"));
    }
    return changes;
}

std::optional<policy_change> policy_store::consider(const std::int64_t now_unix, const bool force) {
    const auto refuse = [&](std::string reason, std::string detail, const policy_bundle* candidate) {
        refused_reason_ = reason + ": " + detail;
        return std::optional<policy_change>{rejected(std::move(reason), std::move(detail), candidate)};
    };
    // Refusals that are not about the content forget the digest, so the same content is decided on once readable.
    const auto refuse_file = [&](std::string reason, std::string detail) {
        if (last_file_digest_ == reason) return std::optional<policy_change>{};
        last_file_digest_ = reason;  // the same refusal is not repeated while the file stays as it is
        return refuse(std::move(reason), std::move(detail), nullptr);
    };
    if (const auto reason = untrusted_path_reason(options_.policy_path); !reason.empty()) {
        return refuse_file("untrusted_file", "the policy file is not trustworthy: " + reason);
    }
    bool too_large = false;
    bool unreadable = false;
    const auto text = read_bounded(options_.policy_path, options_.maximum_file_bytes, too_large, unreadable);
    if (too_large) return refuse_file("too_large", "the policy file is larger than " + std::to_string(options_.maximum_file_bytes) + " bytes");
    if (unreadable) return refuse_file("unreadable", "the policy file could not be read");
    const auto digest = sha256_hex(text);
    if (digest == last_file_digest_ && !force) return std::nullopt;
    last_file_digest_ = digest;
    auto parsed = parse_policy_bundle(text, options_.limits);
    if (!succeeded(parsed)) return refuse("malformed", std::get<error>(parsed).message, nullptr);
    auto candidate = std::make_unique<policy_bundle>(std::move(std::get<policy_bundle>(parsed)));
    const auto& header = candidate->header;

    if (!keys_) return refuse("no_keys", keys_error_.empty() ? "no policy signing key is pinned" : keys_error_, candidate.get());
    const auto verdict = keys_->verify(header.key_id, policy_signing_input(header, candidate->body_sha256), header.signature);
    if (verdict == authorization_verdict::unknown_key) {
        return refuse("unknown_key", "the policy is signed with key " + header.key_id + ", which this endpoint does not pin", candidate.get());
    }
    if (verdict != authorization_verdict::valid) return refuse("bad_signature", "the signature does not match the policy", candidate.get());
    if (header.scope != "all" && header.scope != "host:" + options_.host_id) {
        return refuse("out_of_scope", "the policy is for " + header.scope + ", not this host", candidate.get());
    }
    if (header.issued_unix > now_unix + options_.clock_skew_seconds) {
        return refuse("not_yet_valid",
                      "the policy is issued at unix " + std::to_string(header.issued_unix) + " s, later than now (" + std::to_string(now_unix) +
                          " s) plus the allowed clock skew",
                      candidate.get());
    }
    if (header.expires_unix <= now_unix) {
        return refuse("already_expired", "the policy expired at unix " + std::to_string(header.expires_unix) + " s", candidate.get());
    }
    // The file was touched, or put back to the policy already in force: nothing changes.
    if (active_ && active_->header.version == header.version && active_->body_sha256 == candidate->body_sha256 &&
        active_->header.policy_id == header.policy_id) {
        refused_reason_.clear();
        return std::nullopt;
    }
    std::string reason;
    if (saved_) {
        if (header.version < saved_->version) {
            return refuse("rollback",
                          "version " + std::to_string(header.version) + " is older than version " + std::to_string(saved_->version) +
                              " already accepted here",
                          candidate.get());
        }
        if (header.version == saved_->version && (candidate->body_sha256 != saved_->body_sha256 || header.policy_id != saved_->policy_id)) {
            return refuse("rollback", "version " + std::to_string(header.version) + " was already accepted here with different content", candidate.get());
        }
        reason = header.version == saved_->version ? "resumed" : "updated";
    } else {
        reason = saved_unreadable_ ? "state_unreadable" : "no_previous_state";
    }

    policy_change change;
    change.outcome = "loaded";
    change.reason = reason;
    change.policy_id = header.policy_id;
    change.version = header.version;
    change.key_id = header.key_id;
    change.rules = candidate->engine.rule_count();
    change.indicators = candidate->engine.ioc_count();
    change.expires_unix = header.expires_unix;
    if (saved_) change.previous_version = saved_->version;
    if (reason == "resumed") {
        change.detail = "the accepted policy is in force again after a restart";
    } else if (reason == "updated") {
        change.detail = "replaces version " + std::to_string(saved_->version);
    } else if (reason == "state_unreadable") {
        change.detail = "the record of the previously accepted version could not be read, so rollback could not be checked";
    } else {
        change.detail = "no previously accepted version is recorded on this endpoint (first policy, or the record was removed)";
    }

    if (reason != "resumed") {
        const std::string state = std::string{state_magic} + "\npolicy_id=" + header.policy_id + "\nversion=" + std::to_string(header.version) +
                                  "\nbody_sha256=" + candidate->body_sha256 + "\n";
        // Durable before the policy takes effect: after a power loss the endpoint must still refuse older versions.
        if (auto written = write_file_durably(options_.state_path, state, 0600U); !succeeded(written)) {
            state_write_error_ = std::get<error>(written).message;
            change.detail += "; the accepted version could not be recorded (" + state_write_error_ + "), so a later rollback would not be detected";
        } else {
            state_write_error_.clear();
        }
    }
    saved_ = saved_state{header.policy_id, header.version, candidate->body_sha256};
    saved_unreadable_ = false;
    active_ = std::move(candidate);
    expired_reported_ = false;
    refused_reason_.clear();
    return change;
}

const policy_bundle* policy_store::active(const std::int64_t now_unix) const {
    return active_ && now_unix < active_->header.expires_unix ? active_.get() : nullptr;
}

policy_store::status policy_store::health(const std::int64_t now_unix) const {
    if (!active_) return {"degraded", "no policy is in force: " + (refused_reason_.empty() ? std::string{"none has been loaded"} : refused_reason_)};
    if (now_unix >= active_->header.expires_unix) {
        return {"degraded", describe(*active_) + " expired at unix " + std::to_string(active_->header.expires_unix) + " s and makes no decisions"};
    }
    const auto base = describe(*active_) + " in force (" + std::to_string(active_->engine.rule_count()) + " rules, " +
                      std::to_string(active_->engine.ioc_count()) + " indicators, expires at unix " +
                      std::to_string(active_->header.expires_unix) + " s)";
    std::string problems;
    if (file_missing_) problems += "; the policy file is missing";
    if (!refused_reason_.empty()) problems += "; its replacement was refused: " + refused_reason_;
    if (!keys_error_.empty()) problems += "; " + keys_error_;
    if (!state_write_error_.empty()) problems += "; the accepted version could not be recorded: " + state_write_error_;
    return {problems.empty() ? "active" : "degraded", base + problems};
}

}  // namespace panopticon::linux_agent::sensor
