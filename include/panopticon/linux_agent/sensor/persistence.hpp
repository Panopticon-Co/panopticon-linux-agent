#pragma once

#include "panopticon/linux_agent/sensor/process_info.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Persistence catalog (slice S5.2, catalog §5 `state.persistence`). Lists the places where an
// intruder keeps code running or keeps access: systemd units, cron, shell profiles, SSH keys and
// configuration, the dynamic-linker preload, init scripts, sudo and PAM policy, account files,
// udev rules, autostart entries, module-load configuration and package hooks, including the
// per-user variants of each. It is a pure function of a filesystem root, so tests run it against
// a fake tree. Everything read is treated as hostile: files are opened without following
// symlinks and without blocking, reads are bounded, directory listings are capped.
//
// Secrets are never emitted: content is represented by its SHA-256 and a few counted facts
// (for example how many authorized keys exist and a short digest of each key), never by text.

struct persistence_options {
    std::filesystem::path root{"/"};
    std::size_t maximum_items{8192U};
    std::size_t maximum_directory_entries{2048U};
    std::size_t maximum_file_bytes{1U * 1024U * 1024U};  // larger files are listed but not hashed
    std::size_t maximum_homes{1024U};
};

// One persistence-relevant object on disk; also the unit the FIM baseline compares.
struct persistence_item {
    std::string category;      // systemd_unit, cron, shell_profile, ssh, ld_preload, init_script, ...
    std::string path;          // absolute as the host sees it (the options root is not part of it)
    std::string kind;          // file, symlink, other
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::uint32_t mode{};      // permission bits including setuid/setgid/sticky (07777)
    std::uint64_t size{};
    std::uint64_t mtime_ns{};
    std::string sha256;        // hex; set only when hash_status is "computed"
    std::string hash_status;   // computed, too_large, unreadable, not_applicable
    std::string target;        // symlink target as stored
    // Facts extracted from the content. Counts and digests only.
    std::string exec;                                  // systemd: program of the first ExecStart
    std::optional<std::uint32_t> entries;              // cron and ld.so.preload: active lines
    std::optional<std::uint32_t> key_count;            // authorized_keys
    std::optional<std::uint32_t> forced_commands;      // authorized_keys lines with command=
    std::vector<std::string> key_digests;              // authorized_keys: 16 hex of sha256(type + blob)
    std::optional<std::uint32_t> nopasswd;             // sudoers lines granting NOPASSWD
};

struct persistence_scan {
    std::vector<persistence_item> items;
    std::vector<unavailable_field> unavailable;
    bool truncated{false};
};

class persistence_catalog {
public:
    explicit persistence_catalog(persistence_options options);

    // Re-reads the account database to learn the per-user locations.
    void refresh_homes();
    // Walks every location. Calls refresh_homes() first.
    [[nodiscard]] persistence_scan scan();
    // Category of an absolute host path, or empty when it is not a persistence location.
    [[nodiscard]] std::string classify(std::string_view path) const;
    // Describes one path now. nullopt when the path is not a persistence location or no longer
    // exists (a removed entry is not an error).
    [[nodiscard]] std::optional<persistence_item> describe(std::string_view path) const;
    [[nodiscard]] const persistence_options& options() const noexcept { return options_; }

private:
    persistence_options options_;
    std::vector<std::string> homes_;
};

// Serialised JSON object for one item (used by state.persistence and fim.changed).
[[nodiscard]] std::string persistence_item_json(const persistence_item& item);

// Extractors, exposed for tests and fuzzing.
[[nodiscard]] std::string systemd_exec_program(std::string_view unit_text);
[[nodiscard]] std::uint32_t count_active_lines(std::string_view text);
struct authorized_keys_facts {
    std::uint32_t key_count{};
    std::uint32_t forced_commands{};
    std::vector<std::string> digests;
};
[[nodiscard]] authorized_keys_facts parse_authorized_keys(std::string_view text, std::size_t maximum_keys);
[[nodiscard]] std::uint32_t count_nopasswd(std::string_view sudoers_text);

}  // namespace panopticon::linux_agent::sensor
