#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/keypair.hpp"
#include "panopticon/linux_agent/sensor/policy.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

class command_keyring;

// Signed, versioned local policy (ADR 032). The file is a header, a `---` line and the ADR 016 policy text:
//
//   panopticon-policy 1
//   policy_id <identifier>
//   version <1 .. 2^63-1>
//   issued_at <unix seconds>
//   expires_at <unix seconds>
//   scope all | host:<host_id>
//   key_id <16 hex>
//   signature <base64 of the 64-byte r||s>
//   ---
//   <policy text>
//
// Every header line is required, once, in this order. The signature covers policy_signing_input().
struct policy_header {
    std::string policy_id;
    std::uint64_t version{};
    std::int64_t issued_unix{};
    std::int64_t expires_unix{};
    std::string scope;  // "all" or "host:<host_id>"
    std::string key_id;
    ec_raw_signature signature{};
};

// `panopticon-policy/1\n`, then `name:<bytelen>:<value>\n` for policy_id, version, issued_at, expires_at, scope
// and body_sha256 (the same construction as command signatures, under its own domain line).
[[nodiscard]] std::string policy_signing_input(const policy_header& header, std::string_view body_sha256_hex);

struct policy_bundle {
    policy_header header;
    std::string body_sha256;  // lowercase hex of the exact body bytes
    policy_engine engine;
};

// Parses the header and the policy text. Checks nothing about the signature, the scope or the times.
[[nodiscard]] result<policy_bundle> parse_policy_bundle(std::string_view text, const policy_limits& limits = {});

// One `policy.change` record.
struct policy_change {
    std::string outcome;  // loaded | rejected | expired | removed
    std::string reason;   // [a-z_]{1,48}
    std::string policy_id;
    std::uint64_t version{};
    std::optional<std::uint64_t> previous_version;
    std::string key_id;
    std::size_t rules{};
    std::size_t indicators{};
    std::int64_t expires_unix{};
    std::string detail;
};

struct policy_store_options {
    std::filesystem::path policy_path;
    std::filesystem::path keys_path;
    std::filesystem::path state_path;  // durable record of the accepted policy (id, version, body hash)
    std::string host_id;
    std::int64_t clock_skew_seconds{30};
    std::uint64_t maximum_file_bytes{32ULL << 20U};
    policy_limits limits{};
};

// Owns the policy in force. Single-threaded: the pipeline thread refreshes it and evaluates with it.
class policy_store {
public:
    explicit policy_store(policy_store_options options);
    ~policy_store();
    policy_store(const policy_store&) = delete;
    policy_store& operator=(const policy_store&) = delete;

    // Re-reads the key file and the policy file when they changed, decides, and returns what changed (for the
    // record stream). The first call after construction reports the policy that is in force.
    [[nodiscard]] std::vector<policy_change> refresh(std::int64_t now_unix);

    // The policy that decides now: nullptr when none was accepted or the one in force has expired.
    [[nodiscard]] const policy_bundle* active(std::int64_t now_unix) const;

    struct status {
        std::string state;  // "active" or "degraded"
        std::string reason;
    };
    [[nodiscard]] status health(std::int64_t now_unix) const;

private:
    struct saved_state {
        std::string policy_id;
        std::uint64_t version{};
        std::string body_sha256;
    };
    void load_saved_state();
    // Reads, verifies and decides on the policy file; nullopt when nothing changes (the policy already in force, or
    // content already decided on, unless `force`).
    [[nodiscard]] std::optional<policy_change> consider(std::int64_t now_unix, bool force);
    [[nodiscard]] policy_change rejected(std::string reason, std::string detail, const policy_bundle* candidate) const;
    [[nodiscard]] policy_change about_active(std::string outcome, std::string reason, std::string detail) const;

    policy_store_options options_;
    std::unique_ptr<command_keyring> keys_;
    std::string keys_error_;
    std::string keys_fingerprint_;  // the pinned key ids at the last refresh; a change re-checks the policy file
    std::optional<saved_state> saved_;
    bool saved_unreadable_{false};
    std::unique_ptr<policy_bundle> active_;
    // File identity of the last policy file read, so an unchanged file is not parsed again. Timestamps are coarse (a
    // kernel tick), so a file changed in the last two seconds is read again anyway, and the SHA-256 of the content
    // last decided on keeps such a re-read from producing a second record.
    std::int64_t file_size_{-1};
    std::int64_t file_mtime_ns_{-1};
    std::int64_t file_ctime_ns_{-1};  // a chmod or chown changes only this
    std::uint64_t file_inode_{};
    std::string last_file_digest_;
    bool file_missing_{false};
    bool expired_reported_{false};
    std::string refused_reason_;  // the last replacement that was refused, until a good one is in place
    std::string state_write_error_;
};

}  // namespace panopticon::linux_agent::sensor
