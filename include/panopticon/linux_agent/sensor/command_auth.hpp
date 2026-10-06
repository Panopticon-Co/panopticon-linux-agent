#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/keypair.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

struct endpoint_command;

// Per-command authorization (ADR 025).
//
// TLS and the enrolled bearer token say that the Manager's channel is the one talking. They do not say that
// this particular command was issued by the Manager's command authority: anything that can reach the channel
// (a stolen token, a compromised ingest tier, a proxy that terminates TLS) could otherwise ask for any
// permitted action. A command can therefore carry an `authorization` member: an ECDSA P-256 / SHA-256
// signature, made with a key whose public half is pinned on this endpoint, over the fields this endpoint
// acts on. The signature is checked against the values the strict parser produced, not against transport
// bytes, so there is no canonicalisation of JSON to get wrong: what is signed is what is executed.
struct command_authorization {
    std::string algorithm;  // "ES256" is the only value
    std::string key_id;     // signing_key_id of the key that signed
    ec_raw_signature signature{};
};

// The bytes that are signed: a domain-separation line and then every field as `name:<length>:<value>\n`
// (length in bytes, so no value can run into the next). Times are decimal seconds since the epoch, the
// schema version is "2" for a boot-bound command and "1" otherwise, and fields that do not apply to the action
// are present and empty ("0" for numbers), so no two actions share a signing input.
[[nodiscard]] std::string command_signing_input(const endpoint_command& command);

// First 16 hex digits of the SHA-256 of the 65-byte uncompressed point; names a key without revealing more.
[[nodiscard]] std::string signing_key_id(const ec_public_key_point& point);

// Strict base64 (RFC 4648 alphabet, padding required, no whitespace) to bytes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> decode_base64(std::string_view text);

enum class authorization_verdict : std::uint8_t {
    valid,
    missing,          // the command carries no authorization
    unknown_key,      // the key id is not pinned here (never pinned, or revoked by removal)
    bad_signature,    // the signature does not match the command
    unsigned_window,  // signed, but without created_at: the validity window would not be part of the signature
};
[[nodiscard]] const char* to_string(authorization_verdict verdict) noexcept;

// The pinned command-signing keys. File format: one key per line, the base64 of the 65-byte uncompressed
// P-256 point (the same encoding enrollment uses for `public_key`), optionally followed by a space and a label;
// blank lines and lines starting with `#` are ignored. A line that is not a valid P-256 point makes the whole
// file invalid. Removing a line revokes that key.
class command_keyring {
public:
    // Fails when the file cannot be read or any line is not a valid key. A file with no keys loads (every
    // command is then refused: that is how all keys are revoked).
    [[nodiscard]] static result<std::unique_ptr<command_keyring>> load(const std::filesystem::path& path);
    [[nodiscard]] static std::unique_ptr<command_keyring> from_points(const std::vector<ec_public_key_point>& points);

    [[nodiscard]] authorization_verdict check(const endpoint_command& command) const;

    // Re-reads the file when it changed since the last load (size or modification time). A changed file that is
    // invalid keeps the previous keys and reports why through last_error(); a missing file does the same, so
    // that a transient failure cannot lock an endpoint out, while an emptied file revokes everything.
    void refresh();
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::string last_error() const;
    [[nodiscard]] std::vector<std::string> key_ids() const;

private:
    command_keyring() = default;
    static result<std::map<std::string, ec_public_key_point>> read_file(const std::filesystem::path& path);

    mutable std::mutex mutex_;
    std::filesystem::path path_;
    std::map<std::string, ec_public_key_point> keys_;
    std::int64_t file_size_{-1};
    std::int64_t file_mtime_ns_{-1};
    std::string last_error_;
};

}  // namespace panopticon::linux_agent::sensor
