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

// Host-state inventory (slice S4, catalog §5). Collectors are pure functions of a filesystem
// root, so they run against a fake tree in tests and against "/" in production. Everything read
// from the filesystem is treated as hostile: every file and every list is bounded, malformed
// lines are skipped, and a field that cannot be read is reported in `unavailable` with a reason
// instead of being guessed.

struct host_state_options {
    std::filesystem::path root{"/"};            // prefix of /proc, /sys and /etc
    std::size_t maximum_items{8192U};           // per object; excess is dropped and flagged
    std::size_t maximum_file_bytes{4U * 1024U * 1024U};
};

struct state_snapshot {
    std::string object;                          // "host", "posture", "users", ...
    std::string provider{"inventory"};           // provenance
    std::string mechanism;                       // e.g. "PROCFS+SYSFS"
    std::vector<std::string> items;              // each one serialised JSON object
    std::vector<unavailable_field> unavailable;  // what could not be collected, with the reason
    bool truncated{false};
};

// Object names accepted by collect_state(), in emission order.
[[nodiscard]] const std::vector<std::string_view>& state_objects();

// Collects one object; nullopt for an unknown name.
[[nodiscard]] std::optional<state_snapshot> collect_state(std::string_view object, const host_state_options& options);

// ---- parsers (exposed for unit tests and fuzzing) ---------------------------------------------

struct os_release_info {
    std::string id, id_like, name, pretty_name, version_id, version_codename;
};
[[nodiscard]] os_release_info parse_os_release(std::string_view contents);

struct passwd_entry {
    std::string name;
    std::string password_field;  // "x", "*", "" ... never a usable secret on modern systems
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::string home;
    std::string shell;
};
[[nodiscard]] std::vector<passwd_entry> parse_passwd(std::string_view contents, std::size_t maximum_entries);

struct group_entry {
    std::string name;
    std::uint32_t gid{};
    std::vector<std::string> members;
};
[[nodiscard]] std::vector<group_entry> parse_group(std::string_view contents, std::size_t maximum_entries);

struct mount_entry {
    std::uint32_t mount_id{};
    std::uint32_t parent_id{};
    std::string device;  // major:minor
    std::string root;
    std::string mount_point;
    std::vector<std::string> options;
    std::string fs_type;
    std::string source;
    std::vector<std::string> super_options;
};
[[nodiscard]] std::vector<mount_entry> parse_mountinfo(std::string_view contents, std::size_t maximum_entries);

struct module_entry {
    std::string name;
    std::uint64_t size{};
    std::int64_t refcount{};
    std::vector<std::string> used_by;
    std::string state;
};
[[nodiscard]] std::vector<module_entry> parse_proc_modules(std::string_view contents, std::size_t maximum_entries);

struct package_entry {
    std::string name;
    std::string version;
    std::string architecture;
    std::string source;  // source package when it differs from the binary name
};
// Installed packages from a dpkg `status` file (stanzas of `Field: value` separated by blank lines).
[[nodiscard]] std::vector<package_entry> parse_dpkg_status(std::string_view contents, std::size_t maximum_entries);

// Changes whenever the package database is modified; empty when there is no readable database.
// Cheap (one stat), so the pipeline can skip the full parse while nothing was installed or removed.
[[nodiscard]] std::string package_database_signature(const host_state_options& options);

// Names of the set bits of /proc/sys/kernel/tainted (kernel's TAINT_* flags).
[[nodiscard]] std::vector<std::string> decode_taint(std::uint64_t value);

// Replaces the value of secret-looking `key=value` kernel command-line parameters.
[[nodiscard]] std::string redact_kernel_cmdline(std::string_view cmdline);

// Decodes the `\040`-style octal escapes used by /proc/self/mountinfo.
[[nodiscard]] std::string decode_mount_escapes(std::string_view text);

}  // namespace panopticon::linux_agent::sensor
