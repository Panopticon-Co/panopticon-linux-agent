#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/keypair.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

class command_keyring;

// Signed build manifest and the self-integrity monitor (ADR 033). The manifest is a header, a `---` line and one line
// per installed file:
//
//   panopticon-build-manifest 1
//   package <identifier>
//   version <printable, up to 64 bytes>
//   built_at <unix seconds>
//   key_id <16 hex>
//   signature <base64 of the 64-byte r||s>
//   ---
//   <sha256 hex> <size in bytes> <absolute path>
//
// Every header line is required, once, in this order; the signature covers manifest_signing_input().
struct manifest_entry {
    std::string sha256;
    std::uint64_t size{};
    std::string path;
};

struct build_manifest {
    std::string package;
    std::string version;
    std::int64_t built_unix{};
    std::string key_id;
    ec_raw_signature signature{};
    std::string body_sha256;  // lowercase hex of the exact body bytes
    std::vector<manifest_entry> entries;
};

// `panopticon-build-manifest/1\n`, then `name:<bytelen>:<value>\n` for package, version, built_at and body_sha256
// (the construction of command and policy signatures, under its own domain line).
[[nodiscard]] std::string manifest_signing_input(const build_manifest& manifest, std::string_view body_sha256_hex);

// The body of a manifest for these entries (what the signature covers through its hash), and the whole file.
[[nodiscard]] std::string render_manifest_body(const std::vector<manifest_entry>& entries);
[[nodiscard]] std::string render_build_manifest(const build_manifest& header, std::string_view body);

constexpr std::size_t maximum_manifest_entries = 128U;
constexpr std::size_t maximum_manifest_bytes = 64U * 1024U;

// Parses header and body. Checks nothing about the signature or the files.
[[nodiscard]] result<build_manifest> parse_build_manifest(std::string_view text);

// One thing wrong with the install (or one thing put right again).
struct integrity_finding {
    // binary_modified (content differs from the manifest, or the running image is not a listed build),
    // binary_missing, binary_replaced (the file at the running binary's path is no longer the running image),
    // manifest_invalid (does not verify), manifest_missing.
    std::string technique;
    std::string target;
    std::string expected_sha256;
    std::string observed_sha256;
    std::string detail;
};

struct integrity_change {
    std::string status;  // violated | restored
    integrity_finding finding;
    std::string manifest_version;
    std::string key_id;
    std::size_t files_checked{};
    std::size_t files_in_violation{};
};

struct integrity_options {
    std::filesystem::path manifest_path;
    std::filesystem::path keys_path;
    // The image that is running: "/proc/self/exe" (the default when empty) or, for tests, a file standing in for it.
    std::filesystem::path running_image;
    // A file whose content is not read again unless it changed (size, mtime, ctime, inode) is still re-hashed at this
    // interval, because an attacker can restore the timestamps.
    std::uint64_t full_check_seconds{900U};
    std::uint64_t maximum_file_bytes{512ULL << 20U};
};

// Owns the verdict about the installed files. Single-threaded: the pipeline thread refreshes it.
//
// A finding is reported once it has been seen by two consecutive refreshes (a package upgrade replaces files and the
// manifest within seconds and then restarts the sensor, which must not look like tampering), except at the first
// refresh after start, which follows such a restart. A finding that stops is reported as restored at once.
class integrity_monitor {
public:
    explicit integrity_monitor(integrity_options options);
    ~integrity_monitor();
    integrity_monitor(const integrity_monitor&) = delete;
    integrity_monitor& operator=(const integrity_monitor&) = delete;

    [[nodiscard]] std::vector<integrity_change> refresh(std::int64_t now_unix);

    struct status {
        std::string state;  // "active" or "degraded"
        std::string reason;
    };
    [[nodiscard]] status health() const;

    // Paths the manifest lists (and the manifest itself): the pipeline notes who last changed them.
    [[nodiscard]] std::set<std::string> watched_paths() const;
    [[nodiscard]] std::string running_path() const { return running_path_; }

private:
    struct fingerprint {
        std::uint64_t dev{}, inode{}, size{}, mtime_ns{}, ctime_ns{};
        bool operator==(const fingerprint&) const = default;
    };
    struct cached_hash {
        fingerprint identity;
        std::int64_t hashed_unix{};
        std::string sha256;
        bool unreadable{false};
        bool missing{false};
        std::string why;
    };

    void load_keys();
    // Reads and verifies the manifest if it changed; fills `findings` for a manifest that cannot be trusted.
    void refresh_manifest(std::int64_t now_unix, std::map<std::string, integrity_finding>& findings);
    [[nodiscard]] cached_hash hash_of(const std::string& path, std::int64_t now_unix);
    void check_files(std::int64_t now_unix, std::map<std::string, integrity_finding>& findings);

    integrity_options options_;
    std::string running_path_;
    int running_fd_{-1};  // the image that is running, held open: it names that image even if the file is replaced
    std::uint64_t running_dev_{};
    std::uint64_t running_inode_{};
    std::unique_ptr<command_keyring> keys_;
    std::string keys_error_;
    std::string keys_fingerprint_;
    std::optional<fingerprint> manifest_identity_;
    std::unique_ptr<build_manifest> manifest_;  // the last one that verified
    std::optional<integrity_finding> manifest_problem_;
    std::map<std::string, cached_hash> hashes_;
    std::map<std::string, integrity_finding> pending_;   // seen once, not yet reported
    std::map<std::string, integrity_finding> reported_;  // in violation and reported
    std::string running_sha256_;
    std::int64_t running_hashed_unix_{};
    std::size_t files_checked_{};
    bool first_refresh_{true};
};

}  // namespace panopticon::linux_agent::sensor
