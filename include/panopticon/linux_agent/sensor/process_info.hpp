#pragma once

#include "panopticon/linux_agent/error.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace panopticon::linux_agent::sensor {

enum class executable_kind : std::uint8_t { file, deleted, memfd, anonymous, unknown };
[[nodiscard]] const char* to_string(executable_kind kind) noexcept;

// Reason codes for the canonical `unavailable` array (telemetry catalog §2).
enum class unavailable_reason : std::uint8_t {
    not_supported_by_provider,
    process_exited,
    permission_denied,
    truncated,
    budget_exceeded,
    not_applicable,
    kernel_feature_missing,
    object_gone,  // a file or directory no longer existed when it was resolved
};
[[nodiscard]] const char* to_string(unavailable_reason reason) noexcept;

struct unavailable_field {
    std::string field;
    unavailable_reason reason;
};

struct process_credentials {
    std::array<std::uint32_t, 4> uids{};  // real, effective, saved, filesystem
    std::array<std::uint32_t, 4> gids{};
    std::vector<std::uint32_t> groups;
    std::optional<std::uint32_t> loginuid;   // nullopt: unset (4294967295) or unreadable
    std::optional<std::uint32_t> sessionid;
};

struct process_capabilities {
    std::uint64_t effective{}, permitted{}, inheritable{}, bounding{}, ambient{};
};

struct executable_info {
    std::string path;
    executable_kind kind{executable_kind::unknown};
    std::uint64_t dev{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint64_t mtime_ns{};  // internal: part of the hash cache key, not serialised
    std::uint32_t mode{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    bool known{false};  // dev/inode/size/mode valid
};

// Namespace inode numbers in catalog order: mnt, pid, net, user, uts, ipc, cgroup.
inline constexpr std::array<const char*, 7> namespace_names{"mnt", "pid", "net", "user", "uts", "ipc", "cgroup"};

struct process_info {
    std::uint32_t pid{};
    std::uint32_t ppid{};
    std::uint32_t pgid{};
    std::uint32_t sid{};
    std::uint32_t tty_nr{};
    std::uint32_t vpid{};          // innermost-namespace pid (NSpid last value)
    std::uint32_t threads{};
    std::uint64_t start_ticks{};   // stat field 22, CLK_TCK units since boot
    char state{'?'};
    bool kernel_thread{false};
    std::string comm;
    process_credentials creds;
    process_capabilities caps;
    std::optional<int> seccomp_mode;
    std::optional<bool> no_new_privs;
    executable_info executable;
    std::vector<std::string> args;
    bool args_truncated{false};
    std::string cwd;
    std::array<std::uint64_t, 7> namespaces{};  // 0 = unknown
    std::string cgroup;
    std::map<std::string, std::string> env;      // allowlisted keys only
    std::vector<unavailable_field> unavailable;

    void mark_unavailable(std::string field, unavailable_reason reason) {
        unavailable.push_back({std::move(field), reason});
    }
};

struct procfs_limits {
    std::size_t maximum_args{64};
    std::size_t maximum_args_bytes{4096};
    std::size_t maximum_path_bytes{4096};
    bool collect_environment{true};
};

// Environment keys collected from processes. /proc/<pid>/environ is read into a bounded buffer
// and discarded; values for any other key are never retained or emitted (security model §5).
[[nodiscard]] const std::vector<std::string>& environment_allowlist();

// Reads one process from an injectable procfs root. Returns error::target_mismatch when the
// process is gone (or was replaced) before the core fields could be read; secondary fields that
// fail are recorded in `unavailable` instead of failing the read.
[[nodiscard]] result<process_info> read_process(const std::filesystem::path& proc_root, std::uint32_t pid,
                                                const procfs_limits& limits);

// Reads only the (pid, start_ticks) identity; used to re-verify a process cheaply.
[[nodiscard]] std::optional<std::uint64_t> read_start_ticks(const std::filesystem::path& proc_root, std::uint32_t pid);

// Lists numeric entries of the procfs root (thread-group leaders only).
[[nodiscard]] std::vector<std::uint32_t> list_pids(const std::filesystem::path& proc_root);

// Parsers exposed for unit tests and fuzzing.
struct stat_fields {
    std::string comm;
    char state{'?'};
    std::uint32_t ppid{}, pgid{}, sid{}, tty_nr{};
    std::uint64_t flags{};
    std::uint32_t threads{};
    std::uint64_t start_ticks{};
};
[[nodiscard]] std::optional<stat_fields> parse_stat(std::string_view contents);
// Fills creds/caps/vpid/seccomp/no_new_privs from /proc/<pid>/status text.
void parse_status(std::string_view contents, process_info& info);
[[nodiscard]] std::vector<std::string> split_cmdline(std::string_view contents, std::size_t maximum_args,
                                                     std::size_t maximum_bytes, bool& truncated);
// Classifies a /proc/<pid>/exe link target.
[[nodiscard]] std::pair<std::string, executable_kind> classify_exe_link(std::string_view target);

}  // namespace panopticon::linux_agent::sensor
