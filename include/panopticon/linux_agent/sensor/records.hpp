#pragma once

#include "panopticon/linux_agent/sensor/process_info.hpp"

#include <array>
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
    open_sensitive,  // a credential file was opened; the content read is not observed
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

enum class network_operation : std::uint8_t {
    connect,  // an outbound connection was seen (TCP connect, connected UDP socket)
    accept,   // an inbound connection was seen on a local listening port
    listen,   // a socket started listening (TCP) or was bound (UDP)
    udp_flow, // first datagram of a UDP flow from a process to a destination, once per window
};
[[nodiscard]] const char* to_string(network_operation value) noexcept;

// A socket observed by a network provider. The owner is only a pid here; the pipeline resolves
// it against the entity graph. `pid` is 0 when no process held the socket when it was looked up.
struct raw_network_event {
    network_operation operation{network_operation::connect};
    std::string protocol;  // tcp, udp
    std::string family;    // inet, inet6
    std::string local_address;
    std::uint16_t local_port{};
    std::string remote_address;  // empty for listeners
    std::uint16_t remote_port{};
    std::string state;  // kernel TCP state name, e.g. established
    std::uint64_t inode{};
    std::uint32_t uid{};
    std::uint32_t pid{};
    std::uint32_t holders{};  // processes holding the socket (a forked server shares it)
    std::vector<unavailable_field> unavailable;
};

enum class auth_kind : std::uint8_t {
    login_success,
    login_failure,
    privilege_success,  // sudo, su, pkexec
    privilege_failure,
};
[[nodiscard]] const char* to_string(auth_kind value) noexcept;

// An authentication event taken from a log line. Everything here is text a user-space program
// wrote, and parts of it (user names, commands) are chosen by whoever is being authenticated, so
// it is bounded and cleaned before it gets here and reported as user_space_reported.
struct raw_auth_event {
    auth_kind kind{auth_kind::login_success};
    std::string service;  // sshd, sudo, su, login, pkexec
    std::string method;   // publickey, password, keyboard-interactive, console, ...
    std::string user;     // who authenticated, or who tried to
    std::string target_user;  // sudo/su/pkexec: the account taken on
    std::string source_address;  // empty for local authentication
    std::uint16_t source_port{};
    std::string key_type;         // publickey logins: RSA, ED25519, ...
    std::string key_fingerprint;  // SHA256:...
    std::string tty;
    std::string working_directory;
    std::string command;
    std::uint32_t pid{};      // the logging process (sshd child, sudo)
    bool invalid_user{false};  // sshd: the account does not exist
    bool sanitized{false};     // a field contained control or non-ASCII bytes that were replaced
    bool truncated{false};     // a field was cut at its limit
};

enum class kernel_event_kind : std::uint8_t {
    module_load,
    module_unload,
    mount_added,
    mount_removed,
    mount_remounted,  // same mount, different options
};
[[nodiscard]] const char* to_string(kernel_event_kind value) noexcept;

// A change in kernel state seen by comparing two snapshots of /proc/modules or mountinfo. There
// is no acting process: the diff cannot say who loaded the module or ran mount.
struct raw_kernel_event {
    kernel_event_kind kind{kernel_event_kind::module_load};
    // modules
    std::string module_name;
    std::uint64_t module_size{};
    std::string module_state;
    // mounts
    std::uint32_t mount_id{};
    std::string device;  // major:minor
    std::string source;
    std::string target;
    std::string fs_type;
    std::vector<std::string> options;
    std::vector<std::string> super_options;
};

// Order of the namespace slots in raw_namespace_change. The pid slot is the namespace the task's
// children will be born in: unshare(CLONE_NEWPID) changes it, not the task's own pid namespace.
inline constexpr std::array<const char*, 6> nsproxy_names{"mnt", "pid_for_children", "net", "uts", "ipc", "cgroup"};

// A task moved into other namespaces with setns(2) or unshare(2). `tid` is the task that did it;
// it is the process leader only when the whole process was moved.
struct raw_namespace_change {
    std::uint32_t tgid{};
    std::uint32_t tid{};
    std::array<std::uint32_t, 6> before{};
    std::array<std::uint32_t, 6> after{};
};

enum class security_kind : std::uint8_t {
    memory_exec_mapping,  // memory that no file on disk backs was made executable
    bpf_load,             // a process loaded or attached an eBPF program
};

// A request a process made to the kernel that matters for code execution. The kernel reports it
// before acting, so it says what was asked, not that it succeeded.
struct raw_security_event {
    security_kind kind{security_kind::memory_exec_mapping};
    std::uint32_t pid{};
    // memory_exec_mapping
    std::string operation;  // mmap, mprotect
    std::string backing;    // anonymous, memfd
    bool write_exec{false}; // the mapping is writable as well as executable
    std::uint64_t address{};  // mprotect: start of the mapping the call touched; 0 for mmap
    std::uint64_t length{};
    // bpf_load
    std::string command;       // prog_load, prog_attach, raw_tracepoint_open, link_create
    std::string program_type;  // prog_load: kprobe, tracing, lsm, xdp, ...
    std::optional<std::uint32_t> attach_type;
    std::string name;          // program name (prog_load) or tracepoint name (raw_tracepoint_open)
};

using raw_payload = std::variant<raw_fork, raw_exec, raw_exit, raw_credential_change, raw_ptrace, raw_comm_change,
                                 raw_session_change, raw_file_event, raw_network_event, raw_auth_event, raw_kernel_event,
                                 raw_security_event, raw_namespace_change>;

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
