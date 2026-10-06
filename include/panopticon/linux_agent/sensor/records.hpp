#pragma once

#include "panopticon/linux_agent/sensor/process_info.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace panopticon::linux_agent::sensor {

// How a field or record was obtained (telemetry catalog §2, ADR 007).
enum class confidence : std::uint8_t {
    observed,             // reported by the kernel at the time of the event
    reconstructed,        // derived after the fact from state (e.g. procfs reconcile)
    inferred,             // estimated (e.g. identity computed from an event timestamp)
    user_space_reported,  // reported by a user-space component that could lie
};
[[nodiscard]] const char* to_string(confidence value) noexcept;

struct provenance {
    std::string provider;   // e.g. "netlink_proc", "ebpf_process", "procfs"
    std::string mechanism;  // capability-matrix mechanism id, e.g. "CNPROC", "EBPF-TP", "PROCFS"
    confidence level{confidence::observed};
};

// Raw observations produced by providers. Times are unix nanoseconds (already converted
// through the clock_domain by the provider). `tgid` is the user-visible process id.
struct raw_fork {
    std::uint32_t parent_tgid{};
    std::uint32_t parent_pid{};
    std::uint32_t child_tgid{};
    std::uint32_t child_pid{};
    std::optional<std::uint64_t> child_start_ticks;  // known to eBPF providers
};

struct raw_exec {
    std::uint32_t tgid{};
    std::uint32_t pid{};
    // Fields eBPF providers capture in-kernel; netlink-only providers leave them empty and the
    // graph enriches from procfs.
    std::optional<std::string> filename;
    std::optional<std::vector<std::string>> args;
    std::optional<std::uint64_t> start_ticks;
    bool args_truncated{false};  // `args` was cut at a limit
};

struct raw_exit {
    std::uint32_t tgid{};
    std::uint32_t pid{};
    std::uint32_t exit_status{};  // kernel wait-status encoding
    std::uint32_t exit_signal{};
};

struct raw_credential_change {
    std::uint32_t tgid{};
    std::uint32_t pid{};
    bool user{true};  // false: group change
    std::uint32_t real{};
    std::uint32_t effective{};
};

struct raw_ptrace {
    std::uint32_t tgid{};
    std::uint32_t pid{};
    std::uint32_t tracer_tgid{};  // 0 on detach
    std::uint32_t tracer_pid{};
    // CNPROC reports PTRACE_ATTACH itself; the eBPF access check also covers process_vm_* and
    // /proc/<pid>/mem, so it reports the broader "ptrace_access".
    std::string technique{"ptrace_attach"};
};

struct raw_comm_change {
    std::uint32_t tgid{};
    std::uint32_t pid{};
    std::string comm;
};

struct raw_session_change {
    std::uint32_t tgid{};
    std::uint32_t pid{};
};

enum class file_operation : std::uint8_t {
    create,
    modify,  // closed after being opened for writing (fanotify cannot see individual write() calls)
    remove,
    rename,
    attrib,  // metadata change; the fanotify fallback cannot tell chmod from chown from setxattr
};
[[nodiscard]] const char* to_string(file_operation value) noexcept;

// A filesystem change observed by a file provider. The actor is only a pid here; the pipeline
// resolves it against the entity graph, which only it may touch.
struct raw_file_event {
    std::uint32_t pid{};
    file_operation operation{file_operation::modify};
    std::string path;                    // empty when it could not be resolved
    std::optional<std::string> old_path; // rename only
    bool directory{false};
    std::vector<unavailable_field> unavailable;
};

using raw_payload = std::variant<raw_fork, raw_exec, raw_exit, raw_credential_change, raw_ptrace, raw_comm_change,
                                 raw_session_change, raw_file_event>;

struct raw_record {
    std::uint64_t time_unix_ns{};
    provenance source;
    raw_payload payload;
};

// Decoded wait-status of an exiting process.
struct exit_details {
    std::optional<int> code;    // set when the process exited normally
    std::optional<int> signal;  // set when it was killed by a signal
    bool core_dumped{false};
};
[[nodiscard]] exit_details decode_exit_status(std::uint32_t status) noexcept;

}  // namespace panopticon::linux_agent::sensor
