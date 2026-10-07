// Tests for the eBPF process provider (slice S2): decoder unit tests, malformed-input rejection,
// and live ground truth. The live tests re-execute this binary as a controlled child
// (`--child <mode>`) that does something whose outcome the test knows exactly (exit code, signal,
// argv, rename, credential change, thread-group exit), then compare what the kernel hooks
// reported with that truth. They need root and a BTF kernel and are skipped otherwise.

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/ebpf_process.hpp"
#include "panopticon/linux_agent/sensor/netlink_proc.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"

#include "panopticon_events.h"

#include <fcntl.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <limits>
#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern char** environ;

namespace {

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;
namespace wire = panopticon::linux_agent::sensor::bpf;

int failures = 0;
int skipped = 0;

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

// ---- decoder unit tests -----------------------------------------------------------------------

constexpr std::size_t header_size = offsetof(wire::pan_event, filename);
constexpr std::size_t args_offset = offsetof(wire::pan_event, args);

wire::pan_event base_event(const std::uint32_t kind) {
    wire::pan_event event{};
    event.kind = kind;
    event.time_boot_ns = clock_domain::now_boottime_ns();
    event.start_boot_ns = 123'450'000'000ULL;  // 12345 ticks at CLK_TCK=100
    event.pid = 4242U;
    event.tid = 4242U;
    event.ppid = 100U;
    std::strncpy(event.comm, "worker", sizeof(event.comm) - 1U);
    return event;
}

void test_decode_fork_exit_rename() {
    clock_domain clock;
    auto fork = base_event(wire::PAN_EVENT_FORK);
    fork.child_pid = 4300U;
    fork.child_tid = 4301U;
    auto records = decode_ebpf_process_sample(&fork, header_size, clock, {});
    require(records.size() == 1U, "fork decodes to one record");
    const auto& forked = std::get<raw_fork>(records[0].payload);
    require(forked.parent_tgid == 4242U && forked.child_tgid == 4300U && forked.child_pid == 4301U, "fork ids");
    require(forked.child_start_ticks == 12345U, "boot nanoseconds become clock ticks exactly as procfs reports them");
    require(records[0].source.provider == "ebpf" && records[0].source.mechanism == "sched_process_fork" &&
                records[0].source.level == confidence::observed,
            "provenance names the hook");
    const auto now = clock_domain::now_unix_ns();
    require(records[0].time_unix_ns + 5'000'000'000ULL > now && records[0].time_unix_ns < now + 5'000'000'000ULL, "kernel time becomes wall-clock time");

    auto exit = base_event(wire::PAN_EVENT_EXIT);
    exit.exit_code = 7U << 8U;
    records = decode_ebpf_process_sample(&exit, header_size, clock, {});
    require(records.size() == 1U, "exit decodes to one record");
    const auto& ended = std::get<raw_exit>(records[0].payload);
    require(ended.tgid == 4242U && decode_exit_status(ended.exit_status).code == 7, "exit status passes through");

    auto rename = base_event(wire::PAN_EVENT_RENAME);
    std::strncpy(rename.comm, "newname", sizeof(rename.comm) - 1U);
    records = decode_ebpf_process_sample(&rename, header_size, clock, {});
    require(records.size() == 1U && std::get<raw_comm_change>(records[0].payload).comm == "newname", "rename carries the new name");

    // An unterminated comm must not be read past its field.
    auto full = base_event(wire::PAN_EVENT_RENAME);
    std::memset(full.comm, 'x', sizeof(full.comm));
    records = decode_ebpf_process_sample(&full, header_size, clock, {});
    require(records.size() == 1U && std::get<raw_comm_change>(records[0].payload).comm.size() == wire::PAN_COMM_LEN, "comm is bounded by its field");
}

void test_decode_exec_arguments() {
    clock_domain clock;
    auto exec = base_event(wire::PAN_EVENT_EXEC);
    const std::string filename = "/usr/bin/curl";
    std::memcpy(exec.filename, filename.c_str(), filename.size() + 1U);
    static constexpr char raw_args[] = "curl\0-s\0http://198.51.100.7/x y\0\0tail\0";
    const std::string args{raw_args, sizeof(raw_args) - 1U};
    std::memcpy(exec.args, args.data(), args.size());
    exec.args_len = static_cast<std::uint32_t>(args.size());
    const auto size = args_offset + exec.args_len;
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&exec, size, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "exec decodes");
    const auto& decoded = std::get<raw_exec>(records[0].payload);
    require(decoded.filename == filename, "filename");
    require(decoded.args.has_value() && *decoded.args == std::vector<std::string>({"curl", "-s", "http://198.51.100.7/x y", "", "tail"}),
            "argv is split on NUL, keeping spaces and empty arguments");
    require(!decoded.args_truncated && decoded.start_ticks == 12345U, "not truncated; identity from the kernel start time");

    // The configured limits apply to what the kernel captured.
    procfs_limits tight;
    tight.maximum_args = 2U;
    records = decode_ebpf_process_sample(&exec, size, clock, tight);
    const auto& limited = std::get<raw_exec>(records[0].payload);
    require(limited.args->size() == 2U && limited.args_truncated, "argument count limit sets the truncation flag");

    // The kernel-side flag survives even when the user-space limits are generous.
    exec.flags |= wire::PAN_FLAG_ARGS_TRUNC;
    records = decode_ebpf_process_sample(&exec, size, clock, {});
    require(std::get<raw_exec>(records[0].payload).args_truncated, "kernel truncation flag is kept");
}

void put_address(std::uint8_t (&field)[16], const char* text, const int family) {
    std::memset(field, 0, sizeof(field));
    if (::inet_pton(family, text, field) != 1) throw std::runtime_error{"bad test address"};
}

void test_decode_exec_stdio_and_interpreter() {
    clock_domain clock;
    auto exec = base_event(wire::PAN_EVENT_EXEC);
    const std::string script = "./deploy.sh";
    std::memcpy(exec.filename, script.c_str(), script.size() + 1U);
    const std::string interp = "/bin/bash";
    std::memcpy(exec.interp, interp.c_str(), interp.size() + 1U);
    exec.stdio[0] = wire::PAN_FD_SOCKET;
    exec.stdio[1] = wire::PAN_FD_PIPE;
    exec.stdio[2] = wire::PAN_FD_TTY;
    exec.args_len = 0U;
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&exec, args_offset, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "exec decodes");
    const auto& decoded = std::get<raw_exec>(records[0].payload);
    require(decoded.interpreter == interp && decoded.filename == script, "a script reports its interpreter next to the script path");
    require(decoded.stdio.has_value() && (*decoded.stdio)[0] == stdio_kind::socket && (*decoded.stdio)[1] == stdio_kind::pipe &&
                (*decoded.stdio)[2] == stdio_kind::tty,
            "stdio kinds pass through");

    // A binary: the kernel repeats the filename as the interpreter; that is not a script.
    std::memset(exec.interp, 0, sizeof(exec.interp));
    std::memcpy(exec.interp, script.c_str(), script.size() + 1U);
    exec.stdio[0] = wire::PAN_FD_NULL;
    exec.stdio[1] = wire::PAN_FD_FILE;
    exec.stdio[2] = wire::PAN_FD_OTHER;
    records = decode_ebpf_process_sample(&exec, args_offset, clock, {}, &malformed);
    const auto& binary = std::get<raw_exec>(records[0].payload);
    require(!binary.interpreter.has_value(), "an interpreter equal to the filename is not a script");
    require((*binary.stdio)[0] == stdio_kind::null && (*binary.stdio)[1] == stdio_kind::file && (*binary.stdio)[2] == stdio_kind::other,
            "null, file and other");

    exec.interp[0] = '\0';
    exec.stdio[0] = 0U;
    exec.stdio[1] = 200U;  // a code this build does not know is reported closed, not guessed
    records = decode_ebpf_process_sample(&exec, args_offset, clock, {}, &malformed);
    const auto& unknown = std::get<raw_exec>(records[0].payload);
    require(!unknown.interpreter.has_value() && (*unknown.stdio)[0] == stdio_kind::closed && (*unknown.stdio)[1] == stdio_kind::closed,
            "an empty interpreter and unknown codes");

    // An interpreter field that is not NUL-terminated is read only as far as its own buffer.
    std::memset(exec.interp, 'i', sizeof(exec.interp));
    records = decode_ebpf_process_sample(&exec, args_offset, clock, {}, &malformed);
    require(std::get<raw_exec>(records[0].payload).interpreter->size() == wire::PAN_INTERP_LEN, "the interpreter is bounded by its field");
}

void test_decode_signal() {
    clock_domain clock;
    auto event = base_event(wire::PAN_EVENT_SIGNAL);
    event.pid = 700U;
    event.tid = 701U;
    event.sig_sender = 650U;
    event.sig_number = 9U;
    event.sig_code = static_cast<std::uint32_t>(-6);
    event.sig_result = 0U;
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "a signal decodes");
    const auto& signal = std::get<raw_signal>(records[0].payload);
    require(signal.sender_tgid == 650U && signal.target_tgid == 700U && signal.target_pid == 701U && signal.number == 9U && signal.code == -6 &&
                signal.result == "delivered",
            "sender, target thread, number, tgkill code and result");
    require(!signal.target_is_sensor, "only the provider knows its own pid, the decoder never claims the target is the sensor");
    require(records[0].source.mechanism == "signal_generate", "provenance");

    event.sig_result = 1U;
    records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    require(std::get<raw_signal>(records[0].payload).result == "ignored", "an ignored signal says so");

    for (const std::uint32_t bad_number : {0U, 65U, 4000000000U}) {
        event.sig_number = bad_number;
        malformed = false;
        require(decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed).empty() && malformed, "a signal number outside 1..64 is malformed");
    }
    event.sig_number = 9U;
    event.sig_result = 5U;
    malformed = false;
    require(decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed).empty() && malformed, "an unknown result code is malformed");
}

void test_decode_raw_socket() {
    clock_domain clock;
    auto event = base_event(wire::PAN_EVENT_RAW_SOCKET);
    event.pid = 801U;
    event.sock_family = 17U;  // AF_PACKET, ETH_P_ALL as the process gave it: network byte order
    event.sock_type = 3U;
    event.sock_protocol = htons(0x0003U);
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "a raw socket decodes");
    const auto& packet = std::get<raw_security_event>(records[0].payload);
    require(packet.kind == security_kind::raw_socket && packet.pid == 801U && packet.socket_family == "packet" && packet.socket_type == "raw" &&
                packet.socket_protocol == 3U && packet.protocol_name == "all",
            "AF_PACKET with ETH_P_ALL is read in host order");
    require(records[0].source.mechanism == "security_socket_create", "provenance");

    event.sock_family = 2U;
    event.sock_type = 3U;
    event.sock_protocol = 1U;
    records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    const auto& icmp = std::get<raw_security_event>(records[0].payload);
    require(icmp.socket_family == "inet" && icmp.socket_type == "raw" && icmp.socket_protocol == 1U && icmp.protocol_name == "icmp", "a raw ICMP socket");

    event.sock_family = 10U;
    event.sock_protocol = 200U;  // not a name this build knows: the number is still reported
    records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    const auto& other = std::get<raw_security_event>(records[0].payload);
    require(other.socket_family == "inet6" && other.socket_protocol == 200U && other.protocol_name.empty(), "an unnamed protocol keeps its number");

    event.sock_family = 17U;
    event.sock_type = 2U;
    records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    require(std::get<raw_security_event>(records[0].payload).socket_type == "dgram", "a cooked packet socket");

    const auto reject = [&](const std::uint8_t family, const std::uint8_t type, const char* why) {
        event.sock_family = family;
        event.sock_type = type;
        malformed = false;
        require(decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed).empty() && malformed, why);
    };
    reject(1U, 3U, "AF_UNIX is not a raw socket");
    reject(2U, 0U, "type 0 is malformed");
    reject(2U, 9U, "an unnamed socket type is malformed");
    reject(2U, 200U, "a type past the table is malformed");
}

void test_decode_tcp_close() {
    clock_domain clock;
    auto event = base_event(wire::PAN_EVENT_NET_CLOSE);
    event.net_family = 2U;
    event.net_proto = 6U;
    event.net_sport = 41000U;
    event.net_dport = 443U;
    event.net_state = 1U;
    event.net_dir = 1U;
    event.net_bytes_sent = 5120U;
    event.net_bytes_received = 1048576U;
    event.net_duration_ns = 2500000000ULL;
    put_address(event.net_saddr, "10.0.2.15", AF_INET);
    put_address(event.net_daddr, "198.51.100.7", AF_INET);
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "a close decodes");
    const auto& closed = std::get<raw_network_event>(records[0].payload);
    require(closed.operation == network_operation::close && closed.state == "established" && closed.direction == "outbound" &&
                closed.bytes_sent == 5120U && closed.bytes_received == 1048576U && closed.duration_ns == 2500000000ULL &&
                closed.remote_address == "198.51.100.7" && closed.remote_port == 443U && closed.local_port == 41000U,
            "close carries state, direction, counters, duration and endpoints");
    require(records[0].source.mechanism == "tcp_close", "provenance names the hook");

    event.net_dir = 0U;
    event.net_duration_ns = 0U;
    event.net_state = 8U;
    records = decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed);
    const auto& unseen = std::get<raw_network_event>(records[0].payload);
    require(unseen.direction.empty() && unseen.duration_ns == 0U && unseen.state == "close_wait", "a socket opened before the sensor has no direction or duration");

    const auto reject = [&](const std::uint8_t state, const std::uint8_t direction, const std::uint8_t proto, const char* why) {
        event.net_state = state;
        event.net_dir = direction;
        event.net_proto = proto;
        malformed = false;
        require(decode_ebpf_process_sample(&event, header_size, clock, {}, &malformed).empty() && malformed, why);
    };
    reject(0U, 1U, 6U, "state 0 is malformed");
    reject(12U, 1U, 6U, "a state past the table is malformed");
    reject(1U, 3U, 6U, "an unknown direction is malformed");
    reject(1U, 1U, 17U, "only TCP closes are reported");
}

void test_decode_network() {
    clock_domain clock;
    auto connect = base_event(wire::PAN_EVENT_NET_CONNECT);
    connect.net_family = 2U;
    connect.net_proto = 6U;
    connect.net_sport = 41000U;
    connect.net_dport = 443U;
    connect.uid = 1000U;
    put_address(connect.net_saddr, "10.0.2.15", AF_INET);
    put_address(connect.net_daddr, "198.51.100.7", AF_INET);
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&connect, header_size, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "connect decodes");
    const auto& out = std::get<raw_network_event>(records[0].payload);
    require(out.operation == network_operation::connect && out.protocol == "tcp" && out.family == "inet", "connect shape");
    require(out.local_address == "10.0.2.15" && out.local_port == 41000U && out.remote_address == "198.51.100.7" && out.remote_port == 443U,
            "addresses and ports in host order");
    require(out.pid == 4242U && out.uid == 1000U && out.state == "syn_sent", "the calling process and its uid");
    require(records[0].source.provider == "ebpf" && records[0].source.mechanism == "tcp_connect" && records[0].source.level == confidence::observed,
            "provenance names the hook");

    auto listen = base_event(wire::PAN_EVENT_NET_LISTEN);
    listen.net_family = 10U;
    listen.net_proto = 6U;
    listen.net_sport = 8080U;
    listen.net_dport = 9999U;  // a listener has no remote end, whatever the kernel left in the field
    put_address(listen.net_saddr, "::", AF_INET6);
    records = decode_ebpf_process_sample(&listen, header_size, clock, {});
    require(records.size() == 1U, "listen decodes");
    const auto& listening = std::get<raw_network_event>(records[0].payload);
    require(listening.operation == network_operation::listen && listening.family == "inet6" && listening.local_address == "::" &&
                listening.remote_address.empty() && listening.remote_port == 0U,
            "a listener reports only its local end");

    auto accept = base_event(wire::PAN_EVENT_NET_ACCEPT);
    accept.net_family = 2U;
    accept.net_proto = 6U;
    accept.net_sport = 22U;
    accept.net_dport = 50000U;
    put_address(accept.net_saddr, "10.0.2.15", AF_INET);
    put_address(accept.net_daddr, "10.0.2.2", AF_INET);
    records = decode_ebpf_process_sample(&accept, header_size, clock, {});
    const auto& accepted = std::get<raw_network_event>(records[0].payload);
    require(accepted.operation == network_operation::accept && accepted.remote_address == "10.0.2.2" && accepted.local_port == 22U, "accept");

    auto udp = base_event(wire::PAN_EVENT_NET_UDP);
    udp.net_family = 10U;
    udp.net_proto = 17U;
    udp.net_dport = 53U;
    put_address(udp.net_daddr, "2001:db8::53", AF_INET6);
    records = decode_ebpf_process_sample(&udp, header_size, clock, {});
    const auto& flow = std::get<raw_network_event>(records[0].payload);
    require(flow.operation == network_operation::udp_flow && flow.protocol == "udp" && flow.remote_address == "2001:db8::53" && flow.remote_port == 53U,
            "udp flow to a resolver");

    // A family or protocol the program never produces is a malformed sample, not a guess.
    auto bad_family = connect;
    bad_family.net_family = 3U;
    malformed = false;
    require(decode_ebpf_process_sample(&bad_family, header_size, clock, {}, &malformed).empty() && malformed, "unknown address family rejected");
    auto bad_proto = connect;
    bad_proto.net_proto = 1U;
    malformed = false;
    require(decode_ebpf_process_sample(&bad_proto, header_size, clock, {}, &malformed).empty() && malformed, "unknown protocol rejected");
}

void test_decode_security() {
    clock_domain clock;
    auto map = base_event(wire::PAN_EVENT_MEM_MAP);
    map.mem_backing = wire::PAN_MEM_ANON;
    map.mem_write = 1U;
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&map, header_size, clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "anonymous exec mapping decodes");
    const auto& anonymous = std::get<raw_security_event>(records[0].payload);
    require(anonymous.kind == security_kind::memory_exec_mapping && anonymous.operation == "mmap" && anonymous.backing == "anonymous" &&
                anonymous.write_exec && anonymous.pid == 4242U && anonymous.length == 0U,
            "mmap shape: no address at the hook, writable and executable");
    require(records[0].source.provider == "ebpf" && records[0].source.mechanism == "security_mmap_file" && records[0].source.level == confidence::observed,
            "provenance names the hook");

    auto protect = base_event(wire::PAN_EVENT_MEM_PROTECT);
    protect.mem_backing = wire::PAN_MEM_MEMFD;
    protect.mem_addr = 0x7f0000001000ULL;
    protect.mem_length = 8192U;
    records = decode_ebpf_process_sample(&protect, header_size, clock, {}, &malformed);
    const auto& protected_memory = std::get<raw_security_event>(records[0].payload);
    require(protected_memory.operation == "mprotect" && protected_memory.backing == "memfd" && !protected_memory.write_exec &&
                protected_memory.address == 0x7f0000001000ULL && protected_memory.length == 8192U,
            "mprotect carries the mapping it touched");

    auto bad_backing = map;
    bad_backing.mem_backing = 9U;
    malformed = false;
    require(decode_ebpf_process_sample(&bad_backing, header_size, clock, {}, &malformed).empty() && malformed, "unknown backing rejected");

    auto load = base_event(wire::PAN_EVENT_BPF);
    load.bpf_cmd = 5U;
    load.bpf_type = 2U;
    std::strncpy(load.obj_name, "rootkit_hook", sizeof(load.obj_name) - 1U);
    records = decode_ebpf_process_sample(&load, header_size, clock, {}, &malformed);
    const auto& program = std::get<raw_security_event>(records[0].payload);
    require(program.kind == security_kind::bpf_load && program.command == "prog_load" && program.program_type == "kprobe" &&
                program.name == "rootkit_hook" && !program.attach_type.has_value(),
            "prog_load names the program type and name");

    auto unknown_type = load;
    unknown_type.bpf_type = 99U;
    records = decode_ebpf_process_sample(&unknown_type, header_size, clock, {}, &malformed);
    require(std::get<raw_security_event>(records[0].payload).program_type == "type_99", "a program type this build does not know keeps its number");

    auto attach = base_event(wire::PAN_EVENT_BPF);
    attach.bpf_cmd = 28U;
    attach.bpf_type = 24U;
    records = decode_ebpf_process_sample(&attach, header_size, clock, {}, &malformed);
    const auto& link = std::get<raw_security_event>(records[0].payload);
    require(link.command == "link_create" && link.attach_type == 24U && link.program_type.empty(), "link_create reports the attach type only");

    auto tracepoint = base_event(wire::PAN_EVENT_BPF);
    tracepoint.bpf_cmd = 17U;
    std::memset(tracepoint.obj_name, 'x', sizeof(tracepoint.obj_name));  // unterminated: bounded by its field
    records = decode_ebpf_process_sample(&tracepoint, header_size, clock, {}, &malformed);
    require(records.size() == 1U && std::get<raw_security_event>(records[0].payload).name.size() == wire::PAN_COMM_LEN, "tracepoint name is bounded by its field");

    auto bad_command = base_event(wire::PAN_EVENT_BPF);
    bad_command.bpf_cmd = 0U;
    malformed = false;
    require(decode_ebpf_process_sample(&bad_command, header_size, clock, {}, &malformed).empty() && malformed, "a command the program never reports is rejected");
}

void test_decode_credentials_and_ptrace() {
    clock_domain clock;
    auto cred = base_event(wire::PAN_EVENT_CRED);
    cred.flags = wire::PAN_FLAG_CRED_UID | wire::PAN_FLAG_CRED_GID;
    cred.uid = 0U;
    cred.euid = 0U;
    cred.gid = 5U;
    cred.egid = 6U;
    auto records = decode_ebpf_process_sample(&cred, header_size, clock, {});
    require(records.size() == 2U, "uid and gid changes are separate records");
    const auto& user = std::get<raw_credential_change>(records[0].payload);
    const auto& group = std::get<raw_credential_change>(records[1].payload);
    require(user.user && user.real == 0U && user.effective == 0U && !group.user && group.real == 5U && group.effective == 6U, "credential values");
    cred.flags = wire::PAN_FLAG_CRED_GID;
    require(decode_ebpf_process_sample(&cred, header_size, clock, {}).size() == 1U, "only the changed kind is reported");
    cred.flags = 0U;
    require(decode_ebpf_process_sample(&cred, header_size, clock, {}).empty(), "a credential sample that changed nothing yields nothing");

    auto trace = base_event(wire::PAN_EVENT_PTRACE);
    trace.tracer_pid = 999U;
    records = decode_ebpf_process_sample(&trace, header_size, clock, {});
    require(records.size() == 1U, "ptrace decodes");
    const auto& access = std::get<raw_ptrace>(records[0].payload);
    require(access.tgid == 4242U && access.tracer_tgid == 999U && access.technique == "ptrace_access",
            "the access check is reported as ptrace_access, not as a PTRACE_ATTACH it cannot distinguish");
}

void test_decode_rejects_malformed_samples() {
    clock_domain clock;
    bool malformed = false;
    auto fork = base_event(wire::PAN_EVENT_FORK);

    require(decode_ebpf_process_sample(nullptr, header_size, clock, {}, &malformed).empty() && malformed, "null sample");
    require(decode_ebpf_process_sample(&fork, header_size - 1U, clock, {}, &malformed).empty() && malformed, "sample shorter than the header");
    require(decode_ebpf_process_sample(&fork, sizeof(wire::pan_event) + 1U, clock, {}, &malformed).empty() && malformed, "sample longer than the wire struct");

    auto unknown = base_event(99U);
    require(decode_ebpf_process_sample(&unknown, header_size, clock, {}, &malformed).empty() && malformed, "unknown kind");

    auto exec = base_event(wire::PAN_EVENT_EXEC);
    exec.args_len = wire::PAN_ARGS_LEN;  // would index past the args buffer
    require(decode_ebpf_process_sample(&exec, sizeof(wire::pan_event), clock, {}, &malformed).empty() && malformed, "args_len beyond the buffer");
    exec.args_len = 100U;  // claims more argv than the sample carries
    require(decode_ebpf_process_sample(&exec, args_offset + 50U, clock, {}, &malformed).empty() && malformed, "args_len larger than the received bytes");
    exec.args_len = 0U;
    require(decode_ebpf_process_sample(&exec, header_size, clock, {}, &malformed).empty() && malformed, "exec sample without the filename area");

    malformed = true;
    require(decode_ebpf_process_sample(&fork, header_size, clock, {}, &malformed).size() == 1U && !malformed, "the flag is cleared for a good sample");
}

void test_process_providers_share_a_family() {
    // The pipeline only treats netlink_proc as a fallback for eBPF when both declare one family;
    // a missing declaration makes both run and every process event arrive twice.
    clock_domain clock;
    ebpf_process_provider ebpf{clock};
    netlink_proc_provider netlink{clock};
    require(!ebpf.family().empty() && ebpf.family() == netlink.family(), "ebpf_process and netlink_proc are alternatives of one family");
}

// ---- live ground truth -----------------------------------------------------------------------

void* sleeper(void*) {
    ::usleep(250'000);
    ::_exit(0);  // ends the whole thread group once the leader is long gone
}

// Child behaviours, run when the test binary is re-executed as `--child <mode>`.
int child_main(const std::string& mode) {
    if (mode == "exit7") ::_exit(7);
    if (mode == "plain") ::_exit(0);
    if (mode == "sigkill") {
        ::raise(SIGKILL);
        ::_exit(99);
    }
    if (mode == "rename") {
        ::prctl(PR_SET_NAME, "pan-renamed", 0, 0, 0);
        ::usleep(20'000);
        ::_exit(0);
    }
    if (mode == "setid") {
        if (::setresgid(1234, 1234, 1234) != 0 || ::setresuid(1234, 1234, 1234) != 0) ::_exit(98);
        ::_exit(0);
    }
    if (mode == "threads") {
        // The leader exits first; the process lives until the other thread returns.
        pthread_t thread;
        if (::pthread_create(&thread, nullptr, sleeper, nullptr) != 0) ::_exit(97);
        // Raw thread exit: pthread_exit on the main thread would hang sanitizer runtimes at shutdown.
        ::syscall(SYS_exit, 0);
        ::_exit(95);
    }
    if (mode == "signal_parent") {
        ::kill(::getppid(), SIGTERM);
        ::_exit(0);
    }
    if (mode == "sleep") {
        ::usleep(1'500'000);
        ::_exit(0);
    }
    return 96;
}

std::string self_path() { return fs::read_symlink("/proc/self/exe").string(); }

pid_t spawn_child(const std::string& mode, const std::vector<std::string>& extra = {}) {
    const auto self = self_path();
    std::vector<std::string> arguments{"pan-child", "--child", mode};
    arguments.insert(arguments.end(), extra.begin(), extra.end());
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    pid_t pid = 0;
    if (::posix_spawn(&pid, self.c_str(), nullptr, nullptr, argv.data(), environ) != 0) throw std::runtime_error{"posix_spawn failed"};
    return pid;
}

int reap(const pid_t pid) {
    int status = 0;
    ::waitpid(pid, &status, 0);
    return status;
}

using records_t = std::vector<raw_record>;

// Drains `queue` into `all` until `done(all)` or the timeout.
bool collect(record_queue& queue, records_t& all, const std::function<bool(const records_t&)>& done,
             const std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (done(all)) return true;
        (void)queue.pop_batch(all, 4096U, std::chrono::milliseconds{50});
    }
    return done(all);
}

template <typename payload_type>
std::vector<const raw_record*> select(const records_t& records, const std::function<bool(const payload_type&)>& match) {
    std::vector<const raw_record*> found;
    for (const auto& record : records) {
        if (const auto* payload = std::get_if<payload_type>(&record.payload); payload != nullptr && match(*payload)) found.push_back(&record);
    }
    return found;
}

std::vector<const raw_record*> exits_of(const records_t& records, const pid_t pid) {
    return select<raw_exit>(records, [pid](const raw_exit& e) { return e.tgid == static_cast<std::uint32_t>(pid); });
}
std::vector<const raw_record*> execs_of(const records_t& records, const pid_t pid) {
    return select<raw_exec>(records, [pid](const raw_exec& e) { return e.tgid == static_cast<std::uint32_t>(pid); });
}
std::vector<const raw_record*> forks_of(const records_t& records, const pid_t pid) {
    return select<raw_fork>(records, [pid](const raw_fork& e) { return e.child_tgid == static_cast<std::uint32_t>(pid); });
}

// Owns a started provider for one live test; counts a skip and returns false when the
// environment cannot run eBPF at all.
class live_provider {
public:
    static ebpf_process_options make_options() {
        ebpf_process_options options;
        options.skip_own_network_events = false;  // the test process is the actor under test
        return options;
    }
    explicit live_provider(const ebpf_role role = ebpf_role::process) : provider_{clock_, make_options(), role}, queue_{65536U} {}
    live_provider(const live_provider&) = delete;
    live_provider& operator=(const live_provider&) = delete;
    ~live_provider() { provider_.stop(); }

    bool begin(const char* what) {
        if (!ebpf_process_built()) return skip(what, "this build has no eBPF support");
        if (const auto reason = provider_.probe(); !reason.empty()) return skip(what, reason);
        const auto started = provider_.start(queue_);
        if (!succeeded(started)) throw std::runtime_error{std::string{"probe passed but start failed: "} + std::get<error>(started).message};
        return true;
    }
    ebpf_process_provider& provider() { return provider_; }
    record_queue& queue() { return queue_; }

private:
    static bool skip(const char* what, const std::string& reason) {
        std::cout << "SKIP " << what << ": " << reason << '\n';
        ++skipped;
        return false;
    }
    clock_domain clock_;
    ebpf_process_provider provider_;
    record_queue queue_;
};

// A loopback server and client in one process: the kernel hooks must report the listen, the
// connect, the accept and the first UDP datagram with this process as the actor and the exact
// ports. A connection that is closed immediately is the case the socket-table poll misses.
void test_live_network_connect_accept_listen_udp() {
    live_provider live{ebpf_role::network};
    if (!live.begin("live_network_connect_accept_listen_udp")) return;

    const int server = ::socket(AF_INET, SOCK_STREAM, 0);
    require(server >= 0, "socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    require(::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(server, 1) == 0, "bind and listen");
    socklen_t length = sizeof(address);
    require(::getsockname(server, reinterpret_cast<sockaddr*>(&address), &length) == 0, "getsockname");
    const auto port = ntohs(address.sin_port);

    const int client = ::socket(AF_INET, SOCK_STREAM, 0);
    require(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "connect");
    const int peer = ::accept(server, nullptr, nullptr);
    require(peer >= 0, "accept");
    ::close(peer);
    ::close(client);

    const int datagram = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(static_cast<std::uint16_t>(port + 1U));
    require(::sendto(datagram, "a", 1U, 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 1, "first datagram");
    require(::sendto(datagram, "b", 1U, 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 1, "second datagram");
    ::close(datagram);
    ::close(server);

    const auto self = static_cast<std::uint32_t>(::getpid());
    const auto count = [&](const records_t& seen, const network_operation operation, const std::uint16_t wanted) {
        return select<raw_network_event>(seen, [&](const raw_network_event& e) {
                   const auto relevant = operation == network_operation::listen || operation == network_operation::accept ? e.local_port : e.remote_port;
                   return e.pid == self && e.operation == operation && relevant == wanted;
               }).size();
    };
    records_t all;
    const auto next = static_cast<std::uint16_t>(port + 1U);
    require(collect(live.queue(), all,
                    [&](const records_t& seen) {
                        return count(seen, network_operation::listen, port) >= 1U && count(seen, network_operation::connect, port) >= 1U &&
                               count(seen, network_operation::accept, port) >= 1U && count(seen, network_operation::udp_flow, next) >= 1U;
                    }),
            "listen, connect, accept and udp flow were reported for this process and port");
    require(count(all, network_operation::udp_flow, next) == 1U, "the second datagram of the same flow is not reported again");
    const auto connects = select<raw_network_event>(all, [&](const raw_network_event& e) {
        return e.pid == self && e.operation == network_operation::connect && e.remote_port == port;
    });
    require(connects[0]->source.mechanism == "tcp_connect" && std::get<raw_network_event>(connects[0]->payload).remote_address == "127.0.0.1",
            "connect provenance and destination");
}

// A real loopback conversation with known sizes: the client sends 1000 bytes, the server answers
// with 300, both ends close. Each end's close names itself, the direction it saw, the byte counts
// the kernel kept and a duration, and a socket that never connected and a listener are not reported.
void test_live_tcp_close_bytes() {
    live_provider live{ebpf_role::network};
    if (!live.begin("live_tcp_close_bytes")) return;

    const int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(server, 1) == 0, "bind and listen");
    socklen_t length = sizeof(address);
    require(::getsockname(server, reinterpret_cast<sockaddr*>(&address), &length) == 0, "getsockname");
    const auto port = ntohs(address.sin_port);

    const int idle = ::socket(AF_INET, SOCK_STREAM, 0);  // never connected
    const int client = ::socket(AF_INET, SOCK_STREAM, 0);
    require(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "connect");
    const int peer = ::accept(server, nullptr, nullptr);
    require(peer >= 0, "accept");

    std::vector<char> out(1000U, 'x');
    std::vector<char> back(300U, 'y');
    std::vector<char> sink(2048U);
    const auto drain = [&](const int fd, const std::size_t wanted) {
        std::size_t got = 0U;
        while (got < wanted) {
            const auto n = ::recv(fd, sink.data(), sink.size(), 0);
            if (n <= 0) break;
            got += static_cast<std::size_t>(n);
        }
        return got;
    };
    require(::send(client, out.data(), out.size(), 0) == 1000, "client send");
    require(drain(peer, 1000U) == 1000U, "peer received everything");
    require(::send(peer, back.data(), back.size(), 0) == 300, "peer send");
    require(drain(client, 300U) == 300U, "client received everything");
    ::close(peer);
    ::close(client);
    ::close(idle);
    ::close(server);

    const auto self = static_cast<std::uint32_t>(::getpid());
    const auto closes = [&](const records_t& seen) {
        return select<raw_network_event>(seen, [&](const raw_network_event& e) {
            return e.pid == self && e.operation == network_operation::close && (e.remote_port == port || e.local_port == port);
        });
    };
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& seen) { return closes(seen).size() >= 2U; }), "both ends of the connection reported a close");
    (void)collect(live.queue(), all, [&](const records_t& seen) { return closes(seen).size() > 2U; }, std::chrono::milliseconds{500});
    const auto found = closes(all);
    require(found.size() == 2U, "two closes: the unconnected socket and the listener are not reported");
    bool saw_client = false;
    bool saw_peer = false;
    for (const auto* record : found) {
        const auto& event = std::get<raw_network_event>(record->payload);
        const auto detail = "direction=" + event.direction + " state=" + event.state + " sent=" + std::to_string(event.bytes_sent) +
                            " received=" + std::to_string(event.bytes_received) + " duration=" + std::to_string(event.duration_ns);
        // Exact payload bytes: the kernel's SYN and FIN sequence numbers are taken out in the program.
        // The peer closed first, so the client's socket was in CLOSE_WAIT when it closed.
        if (event.direction == "outbound" && event.remote_port == port) {
            saw_client = event.bytes_sent == 1000U && event.bytes_received == 300U && event.duration_ns > 0U && event.state == "close_wait";
            require(saw_client, "client close counters: " + detail);
        } else if (event.direction == "inbound" && event.local_port == port) {
            saw_peer = event.bytes_sent == 300U && event.bytes_received == 1000U && event.duration_ns > 0U && event.state == "established";
            require(saw_peer, "peer close counters: " + detail);
        } else {
            require(false, "an unexpected close: " + detail);
        }
    }
    require(saw_client && saw_peer, "one outbound and one inbound close");
    require(live.provider().take_losses() == 0U, "no ring buffer losses");
}

// The test process asks the kernel for each thing the security hooks report and nothing else, so
// the records are exactly what it did: an anonymous RWX mapping, a mapping made executable later,
// an executable memfd mapping and a real bpf(PROG_LOAD). A file-backed executable mapping (every
// shared library) must not be reported.
void test_live_executable_memory_and_bpf() {
    live_provider live{ebpf_role::security};
    if (!live.begin("live_executable_memory_and_bpf")) return;

    void* rwx = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(rwx != MAP_FAILED, "anonymous rwx mapping");
    void* again = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(again != MAP_FAILED, "second anonymous rwx mapping");

    void* staged = ::mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(staged != MAP_FAILED && ::mprotect(staged, 8192, PROT_READ | PROT_EXEC) == 0, "mapping made executable");

    const int memory_file = static_cast<int>(::syscall(SYS_memfd_create, "panopticon-test", 0U));
    require(memory_file >= 0 && ::ftruncate(memory_file, 4096) == 0, "memfd");
    void* from_memfd = ::mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, memory_file, 0);
    require(from_memfd != MAP_FAILED, "executable memfd mapping");

    const int self_file = ::open("/proc/self/exe", O_RDONLY);
    void* image = ::mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, self_file, 0);
    require(image != MAP_FAILED, "file-backed executable mapping");

    struct instruction {
        std::uint8_t code;
        std::uint8_t registers;
        std::int16_t offset;
        std::int32_t immediate;
    };
    const instruction program[2] = {{0xB7, 0, 0, 0}, {0x95, 0, 0, 0}};  // r0 = 0; exit
    static const char license[] = "GPL";
    struct {
        std::uint32_t prog_type, insn_cnt;
        std::uint64_t insns, license;
        std::uint32_t log_level, log_size;
        std::uint64_t log_buf;
        std::uint32_t kern_version, prog_flags;
        char prog_name[16];
    } attribute;
    std::memset(&attribute, 0, sizeof(attribute));
    attribute.prog_type = 1U;  // socket filter
    attribute.insn_cnt = 2U;
    attribute.insns = reinterpret_cast<std::uint64_t>(program);
    attribute.license = reinterpret_cast<std::uint64_t>(license);
    std::strncpy(attribute.prog_name, "pan_test", sizeof(attribute.prog_name) - 1U);
    const int loaded = static_cast<int>(::syscall(SYS_bpf, 5, &attribute, sizeof(attribute)));
    require(loaded >= 0, "bpf(PROG_LOAD) succeeds as root");
    ::close(loaded);

    const auto self = static_cast<std::uint32_t>(::getpid());
    const auto mine = [&](const records_t& seen, const std::string& operation, const std::string& backing) {
        return select<raw_security_event>(seen, [&](const raw_security_event& e) {
            return e.pid == self && e.kind == security_kind::memory_exec_mapping && e.operation == operation && e.backing == backing;
        });
    };
    const auto loads = [&](const records_t& seen) {
        return select<raw_security_event>(seen, [&](const raw_security_event& e) {
            return e.pid == self && e.kind == security_kind::bpf_load && e.command == "prog_load" && e.name == "pan_test";
        });
    };
    records_t all;
    require(collect(live.queue(), all,
                    [&](const records_t& seen) {
                        return !mine(seen, "mmap", "anonymous").empty() && !mine(seen, "mprotect", "anonymous").empty() &&
                               !mine(seen, "mmap", "memfd").empty() && !loads(seen).empty();
                    }),
            "anonymous mmap, mprotect, memfd mmap and bpf load were reported for this process");

    const auto anonymous = mine(all, "mmap", "anonymous");
    require(anonymous.size() == 1U, "two identical mappings in the window are one report");
    require(std::get<raw_security_event>(anonymous[0]->payload).write_exec, "an rwx mapping is flagged writable and executable");
    const auto protects = mine(all, "mprotect", "anonymous");
    const auto& protection = std::get<raw_security_event>(protects[0]->payload);
    // The hook sees the whole VMA that holds the range, so when the kernel has merged the test's pages with a
    // neighbouring anonymous mapping (the sanitizer builds do this some of the time) it is larger than 8192 bytes.
    const auto staged_address = reinterpret_cast<std::uint64_t>(staged);
    require(protection.address <= staged_address && staged_address + 8192U <= protection.address + protection.length && !protection.write_exec,
            "mprotect reports a mapping that covers the range that became executable: expected " + std::to_string(reinterpret_cast<std::uint64_t>(staged)) +
                "+8192, got " + std::to_string(protection.address) + "+" + std::to_string(protection.length) + " write_exec=" +
                std::to_string(protection.write_exec) + " among " + std::to_string(protects.size()) + " anonymous mprotect reports");
    require(mine(all, "mmap", "file").empty(), "a file-backed executable mapping is never reported");
    const auto program_load = std::get<raw_security_event>(loads(all)[0]->payload);
    require(program_load.program_type == "socket_filter", "the program type is named");

    ::munmap(rwx, 4096);
    ::munmap(again, 4096);
    ::munmap(staged, 8192);
    ::munmap(from_memfd, 4096);
    ::munmap(image, 4096);
    ::close(memory_file);
    ::close(self_file);
}

std::vector<std::uint8_t> dns_packet(const std::string& name, const std::uint16_t type, const std::uint16_t id, const std::uint16_t flags = 0x0100U) {
    std::vector<std::uint8_t> out{static_cast<std::uint8_t>(id >> 8U), static_cast<std::uint8_t>(id & 0xffU), static_cast<std::uint8_t>(flags >> 8U),
                                  static_cast<std::uint8_t>(flags & 0xffU), 0, 1, 0, 0, 0, 0, 0, 0};
    std::size_t start = 0U;
    while (start < name.size()) {
        auto end = name.find('.', start);
        if (end == std::string::npos) end = name.size();
        out.push_back(static_cast<std::uint8_t>(end - start));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start), name.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1U;
    }
    out.push_back(0);
    out.push_back(static_cast<std::uint8_t>(type >> 8U));
    out.push_back(static_cast<std::uint8_t>(type & 0xffU));
    out.push_back(0);
    out.push_back(1);
    return out;
}

void test_decode_dns() {
    clock_domain clock;
    auto event = base_event(wire::PAN_EVENT_DNS_QUERY);
    event.net_family = 2U;
    event.net_proto = 17U;
    event.net_sport = 40000U;
    event.net_dport = 53U;
    event.net_saddr[0] = 10U;
    event.net_saddr[3] = 5U;
    event.net_daddr[0] = 10U;
    event.net_daddr[2] = 2U;
    event.net_daddr[3] = 3U;
    const auto packet = dns_packet("Evil.Example.COM", 16U, 0x1234U);
    std::memcpy(event.filename, packet.data(), packet.size());
    event.dns_len = static_cast<std::uint16_t>(packet.size());
    bool malformed = true;
    auto records = decode_ebpf_process_sample(&event, header_size + packet.size(), clock, {}, &malformed);
    require(!malformed && records.size() == 1U, "dns query decodes");
    const auto& query = std::get<raw_dns_query>(records[0].payload);
    require(query.pid == 4242U && query.name == "Evil.Example.COM" && query.type == "TXT" && query.klass == "IN" && query.transaction_id == 0x1234U &&
                query.recursion_desired && query.server_address == "10.0.2.3" && query.server_port == 53U && query.local_address == "10.0.0.5" &&
                query.local_port == 40000U && query.family == "inet",
            "question, endpoints and case are kept as sent");
    require(records[0].source.mechanism == "udp_sendmsg" && records[0].source.level == confidence::observed, "provenance names the hook");

    auto response = event;
    const auto answer = dns_packet("example.com", 1U, 7U, 0x8180U);
    std::memcpy(response.filename, answer.data(), answer.size());
    response.dns_len = static_cast<std::uint16_t>(answer.size());
    malformed = false;
    require(decode_ebpf_process_sample(&response, header_size + answer.size(), clock, {}, &malformed).empty() && !malformed,
            "a response is not a query and is not an error");

    auto text = event;
    const char note[] = "this is plain text sent to port fifty-three";
    std::memcpy(text.filename, note, sizeof(note));
    text.dns_len = sizeof(note);
    malformed = false;
    require(decode_ebpf_process_sample(&text, header_size + sizeof(note), clock, {}, &malformed).empty() && !malformed,
            "port 53 traffic that is not DNS yields no dns record and is not an error");

    auto oversize = event;
    oversize.dns_len = wire::PAN_DNS_CAPTURE + 1U;
    malformed = false;
    require(decode_ebpf_process_sample(&oversize, sizeof(wire::pan_event), clock, {}, &malformed).empty() && malformed, "a length past the capture bound is malformed");
    malformed = false;
    require(decode_ebpf_process_sample(&event, header_size + packet.size() - 1U, clock, {}, &malformed).empty() && malformed, "a sample shorter than its length is malformed");
    auto no_family = event;
    no_family.net_family = 0U;
    malformed = false;
    require(decode_ebpf_process_sample(&no_family, header_size + packet.size(), clock, {}, &malformed).empty() && malformed, "an unknown family is malformed");
}

// The test process sends the datagrams itself, so the records are exactly what it did: a question
// to an explicit destination, the same question again with a new transaction id (a retry, one
// report), another type of the same name, a write on a connected socket, a sendmsg with one iovec,
// text that is not DNS, and a datagram whose first iovec is too short to hold the question.
void test_live_dns_query() {
    live_provider live{ebpf_role::network};
    if (!live.begin("live_dns_query")) return;

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    ::inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    require(fd >= 0, "udp socket");
    const auto send_to = [&](const std::vector<std::uint8_t>& data) {
        return ::sendto(fd, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&server), sizeof(server)) == static_cast<ssize_t>(data.size());
    };
    require(send_to(dns_packet("panopticon-probe.example.test", 16U, 0x1111U)), "first question sent");
    require(send_to(dns_packet("panopticon-probe.example.test", 16U, 0x2222U)), "retry sent");
    require(send_to(dns_packet("panopticon-probe.example.test", 28U, 0x3333U)), "second type sent");

    const int connected = ::socket(AF_INET, SOCK_DGRAM, 0);
    require(connected >= 0 && ::connect(connected, reinterpret_cast<const sockaddr*>(&server), sizeof(server)) == 0, "connected udp socket");
    const auto on_connected = dns_packet("connected.example.test", 1U, 0x4444U);
    require(::send(connected, on_connected.data(), on_connected.size(), 0) == static_cast<ssize_t>(on_connected.size()), "send on a connected socket");

    const auto by_message = dns_packet("sendmsg.example.test", 1U, 0x5555U);
    iovec vector{const_cast<std::uint8_t*>(by_message.data()), by_message.size()};
    msghdr message{};
    message.msg_name = &server;
    message.msg_namelen = sizeof(server);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    require(::sendmsg(fd, &message, 0) == static_cast<ssize_t>(by_message.size()), "sendmsg with one iovec");

    require(send_to(std::vector<std::uint8_t>(40U, 'x')), "text that is not DNS");

    const auto split = dns_packet("split.example.test", 1U, 0x6666U);
    iovec halves[2] = {{const_cast<std::uint8_t*>(split.data()), 20U}, {const_cast<std::uint8_t*>(split.data()) + 20U, split.size() - 20U}};
    msghdr divided{};
    divided.msg_name = &server;
    divided.msg_namelen = sizeof(server);
    divided.msg_iov = halves;
    divided.msg_iovlen = 2;
    require(::sendmsg(fd, &divided, 0) == static_cast<ssize_t>(split.size()), "sendmsg with two iovecs");
    require(send_to(dns_packet("marker.example.test", 1U, 0x7777U)), "marker question sent last");

    sockaddr_in bound{};
    socklen_t bound_length = sizeof(bound);
    require(::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0, "local port");

    const auto self = static_cast<std::uint32_t>(::getpid());
    const auto asked = [&](const records_t& seen, const std::string& name) {
        return select<raw_dns_query>(seen, [&](const raw_dns_query& e) { return e.pid == self && e.name == name; });
    };
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& seen) { return !asked(seen, "marker.example.test").empty(); }), "the questions were reported for this process");

    const auto probes = asked(all, "panopticon-probe.example.test");
    require(probes.size() == 2U, "the retry is a duplicate; the other type is a new question");
    const auto& first = std::get<raw_dns_query>(probes[0]->payload);
    const auto& second = std::get<raw_dns_query>(probes[1]->payload);
    require(first.type == "TXT" && first.transaction_id == 0x1111U && second.type == "AAAA" && second.transaction_id == 0x3333U, "types and ids of the two reports");
    require(first.server_address == "127.0.0.1" && first.server_port == 53U && first.local_port == ntohs(bound.sin_port) && first.family == "inet", "endpoints");
    require(asked(all, "connected.example.test").size() == 1U, "a send on a connected socket is attributed too");
    require(asked(all, "sendmsg.example.test").size() == 1U, "sendmsg with an iovec is read");
    require(asked(all, "split.example.test").empty(), "a question split across iovecs is not reported (only the first iovec is read)");
    ::close(fd);
    ::close(connected);
}

std::uint64_t namespace_inode(const char* path) {
    struct stat status {};
    if (::stat(path, &status) != 0) throw std::runtime_error{std::string{"stat failed: "} + path};
    return status.st_ino;
}

// A thread leaves its UTS and IPC namespaces; the process and every other thread stay. The hook must
// report the thread that did it, the exact inode numbers before and after (read from procfs by the
// test as ground truth), and no change in the namespaces nothing touched.
void test_live_namespace_change() {
    live_provider live{ebpf_role::security};
    if (!live.begin("live_namespace_change")) return;

    std::uint32_t thread_id = 0U;
    std::uint64_t uts_before = 0U, uts_after = 0U, ipc_before = 0U, ipc_after = 0U, net_before = 0U;
    bool unshared = false;
    std::thread worker{[&] {
        thread_id = static_cast<std::uint32_t>(::syscall(SYS_gettid));
        uts_before = namespace_inode("/proc/thread-self/ns/uts");
        ipc_before = namespace_inode("/proc/thread-self/ns/ipc");
        net_before = namespace_inode("/proc/thread-self/ns/net");
        unshared = ::unshare(CLONE_NEWUTS | CLONE_NEWIPC) == 0;
        uts_after = namespace_inode("/proc/thread-self/ns/uts");
        ipc_after = namespace_inode("/proc/thread-self/ns/ipc");
    }};
    worker.join();
    require(unshared, "unshare(CLONE_NEWUTS|CLONE_NEWIPC) as root");
    require(uts_after != uts_before && ipc_after != ipc_before, "procfs shows the new namespaces");

    const auto self = static_cast<std::uint32_t>(::getpid());
    records_t all;
    require(collect(live.queue(), all,
                    [&](const records_t& seen) {
                        return !select<raw_namespace_change>(seen, [&](const raw_namespace_change& e) { return e.tgid == self && e.tid == thread_id; }).empty();
                    }),
            "the namespace change was reported for the thread that made it");
    const auto changes = select<raw_namespace_change>(all, [&](const raw_namespace_change& e) { return e.tgid == self && e.tid == thread_id; });
    require(changes.size() == 1U, "one change for one unshare");
    const auto& change = std::get<raw_namespace_change>(changes[0]->payload);
    require(change.before[3] == uts_before && change.after[3] == uts_after, "uts inode numbers match procfs exactly");
    require(change.before[4] == ipc_before && change.after[4] == ipc_after, "ipc inode numbers match procfs exactly");
    require(change.before[2] == net_before && change.after[2] == net_before, "the network namespace did not move");
    require(change.before[0] == change.after[0] && change.before[5] == change.after[5], "mount and cgroup namespaces did not move");
    require(changes[0]->source.mechanism == "switch_task_namespaces", "provenance names the hook");
}

void test_decode_namespace_change() {
    clock_domain clock;
    auto event = base_event(wire::PAN_EVENT_NS_CHANGE);
    for (std::uint32_t index = 0U; index < 6U; ++index) {
        event.ns_old[index] = 4026531800U + index;
        event.ns_new[index] = 4026531800U + index;
    }
    event.ns_new[0] = 4026532500U;
    event.ns_new[2] = 4026532600U;
    auto records = decode_ebpf_process_sample(&event, header_size, clock, {});
    require(records.size() == 1U, "namespace change decodes");
    const auto& change = std::get<raw_namespace_change>(records[0].payload);
    require(change.tgid == 4242U && change.before[0] == 4026531800U && change.after[0] == 4026532500U && change.after[2] == 4026532600U &&
                change.before[1] == change.after[1],
            "before and after slots are kept in order");
}

void test_live_lifecycle_and_arguments() {
    live_provider live;
    if (!live.begin("live lifecycle")) return;
    const std::vector<std::string> extra{"arg with space", "", "x"};
    const auto pid = spawn_child("exit7", extra);
    const auto status = reap(pid);
    require(WIFEXITED(status) && WEXITSTATUS(status) == 7, "child exits with 7");

    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !exits_of(r, pid).empty(); }), "the exit of a short-lived process is observed");
    const auto forks = forks_of(all, pid);
    const auto execs = execs_of(all, pid);
    const auto exits = exits_of(all, pid);
    require(forks.size() == 1U && execs.size() == 1U && exits.size() == 1U, "exactly one fork, exec and exit");
    const auto& fork = std::get<raw_fork>(forks[0]->payload);
    require(fork.parent_tgid == static_cast<std::uint32_t>(::getpid()), "fork names the real parent");

    const auto& exec = std::get<raw_exec>(execs[0]->payload);
    require(exec.filename == self_path(), "the kernel reports the path execve was given");
    std::vector<std::string> expected{"pan-child", "--child", "exit7"};
    expected.insert(expected.end(), extra.begin(), extra.end());
    require(exec.args.has_value() && *exec.args == expected, "argv captured at exec, including spaces and an empty argument");
    require(exec.start_ticks.has_value() && exec.start_ticks == fork.child_start_ticks, "fork and exec agree on the process start time");

    const auto& exit = std::get<raw_exit>(exits[0]->payload);
    require(decode_exit_status(exit.exit_status).code == 7, "exact exit code");
    require(forks[0]->time_unix_ns <= execs[0]->time_unix_ns && execs[0]->time_unix_ns <= exits[0]->time_unix_ns, "records are ordered in time");
    require(execs[0]->source.provider == "ebpf" && execs[0]->source.mechanism == "sched_process_exec", "provenance");
    require(live.provider().take_losses() == 0U, "no ring buffer losses");
}

// The programs wake the reader only for the first record after an idle gap and the reader polls on a
// timer while records flow. A burst must be delivered whole, and a record that follows a pause of any
// length (shorter and longer than the 20 ms gap, and the 30 ms the reader stays fast) must arrive long
// before the 1 s idle timeout: a missed wake-up would show as a delay near a second.
//
// Delivery alone cannot tell "wake on every record" from the policy, so the test also reads what the kernel
// measured for the hooks themselves: waking costs 500 to 850 us inside fork, exec and exit on the dev VM, the
// policy 3 to 5 us. The bound is 100 us, well clear of both.
class bpf_run_time_stats {
public:
    bpf_run_time_stats() {
        union bpf_attr attr {};
        attr.enable_stats.type = BPF_STATS_RUN_TIME;
        fd_ = static_cast<int>(::syscall(SYS_bpf, BPF_ENABLE_STATS, &attr, sizeof(attr)));
    }
    ~bpf_run_time_stats() {
        if (fd_ >= 0) ::close(fd_);
    }
    bpf_run_time_stats(const bpf_run_time_stats&) = delete;
    bpf_run_time_stats& operator=(const bpf_run_time_stats&) = delete;
    bool enabled() const { return fd_ >= 0; }

    // Runs and nanoseconds of every loaded program with this name, summed.
    static std::pair<std::uint64_t, std::uint64_t> of(const std::string& name) {
        std::uint64_t runs = 0U;
        std::uint64_t nanoseconds = 0U;
        std::uint32_t id = 0U;
        for (;;) {
            union bpf_attr next {};
            next.start_id = id;
            if (::syscall(SYS_bpf, BPF_PROG_GET_NEXT_ID, &next, sizeof(next)) != 0) break;
            id = next.next_id;
            union bpf_attr open {};
            open.prog_id = id;
            const int fd = static_cast<int>(::syscall(SYS_bpf, BPF_PROG_GET_FD_BY_ID, &open, sizeof(open)));
            if (fd < 0) continue;
            struct bpf_prog_info info {};
            union bpf_attr query {};
            query.info.bpf_fd = static_cast<std::uint32_t>(fd);
            query.info.info_len = sizeof(info);
            query.info.info = reinterpret_cast<std::uint64_t>(&info);
            if (::syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &query, sizeof(query)) == 0 && name == info.name) {
                runs += info.run_cnt;
                nanoseconds += info.run_time_ns;
            }
            ::close(fd);
        }
        return {runs, nanoseconds};
    }

private:
    int fd_{-1};
};

void test_live_wake_policy_delivers_after_bursts_and_pauses() {
    live_provider live;
    if (!live.begin("live wake policy")) return;
    bpf_run_time_stats stats;
    records_t all;

    std::vector<pid_t> burst;
    for (int i = 0; i < 200; ++i) {
        const auto pid = spawn_child("exit7");
        reap(pid);
        burst.push_back(pid);
    }
    require(collect(live.queue(), all,
                    [&](const records_t& r) {
                        return std::all_of(burst.begin(), burst.end(), [&](const pid_t pid) { return !exits_of(r, pid).empty(); });
                    },
                    std::chrono::milliseconds{10000}),
            "every process of a burst is delivered");

    for (const int pause_ms : {5, 15, 22, 28, 35, 45, 60, 120, 300, 1200}) {
        std::this_thread::sleep_for(std::chrono::milliseconds{pause_ms});
        const auto started = std::chrono::steady_clock::now();
        const auto pid = spawn_child("exit7");
        reap(pid);
        require(collect(live.queue(), all, [&](const records_t& r) { return !exits_of(r, pid).empty(); }, std::chrono::milliseconds{3000}),
                "a record after a pause of " + std::to_string(pause_ms) + " ms is delivered");
        const auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
        require(delay < 400, "a record after a pause of " + std::to_string(pause_ms) + " ms arrived in " + std::to_string(delay) + " ms");
    }
    require(live.provider().take_losses() == 0U, "no ring buffer losses");

    if (!stats.enabled()) {
        std::cout << "SKIP live_wake_policy hook cost: kernel run-time statistics unavailable\n";
        return;
    }
    // Cost is measured over a dense workload only. When events are further apart than the gap every one of them
    // is supposed to wake the reader (the sanitizer builds of this binary start children so slowly that their own
    // processes are such a workload), so the earlier part of the test says nothing about it.
    //
    // The kernel's figure is wall time, so an interrupt or a descheduled virtual CPU inside a hook is counted as
    // the hook's cost. On the dev VM with 8 vCPUs the same binary averaged 3 to 6 us in some windows of 300
    // spawns and 40 to 58 us in others (with 4 CPUs online every window was 2.5 to 6 us), and a single window
    // failed this bound in 2 of 3 runs under ctest. The policy is judged on the best of five windows of 100
    // spawns: a build that wakes the reader on every record pays 500 us or more in every window, so it still
    // fails, while one disturbed window no longer does.
    const std::array<const char*, 3U> hooks{"on_fork", "on_exec", "on_exit"};
    constexpr int windows = 5;
    constexpr int spawns_per_window = 100;
    std::array<std::uint64_t, 3U> best_us{};
    best_us.fill(std::numeric_limits<std::uint64_t>::max());
    char* const argv[] = {const_cast<char*>("true"), nullptr};
    for (int window = 0; window < windows; ++window) {
        std::array<std::pair<std::uint64_t, std::uint64_t>, 3U> before;
        for (std::size_t index = 0U; index < hooks.size(); ++index) before[index] = bpf_run_time_stats::of(hooks[index]);
        for (int i = 0; i < spawns_per_window; ++i) {
            pid_t pid = 0;
            require(::posix_spawn(&pid, "/bin/true", nullptr, nullptr, argv, environ) == 0, "spawn /bin/true");
            reap(pid);
        }
        for (std::size_t index = 0U; index < hooks.size(); ++index) {
            const auto after = bpf_run_time_stats::of(hooks[index]);
            const auto runs = after.first - before[index].first;
            require(runs >= static_cast<std::uint64_t>(spawns_per_window), std::string{hooks[index]} + " ran often enough to measure");
            best_us[index] = std::min(best_us[index], (after.second - before[index].second) / runs / 1000U);
        }
    }
    for (std::size_t index = 0U; index < hooks.size(); ++index) {
        require(best_us[index] < 100U, std::string{hooks[index]} + " costs " + std::to_string(best_us[index]) +
                                           " us per call in the kernel in its best window of " + std::to_string(spawns_per_window) +
                                           " back-to-back processes (bound 100 us)");
    }
}

// Spawns the test binary as a child with `actions` applied before exec, so its standard descriptors
// are exactly what the test wants the kernel to classify.
pid_t spawn_with_actions(const std::string& mode, posix_spawn_file_actions_t* actions) {
    const auto self = self_path();
    std::vector<std::string> arguments{"pan-child", "--child", mode};
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    pid_t pid = 0;
    if (::posix_spawn(&pid, self.c_str(), actions, nullptr, argv.data(), environ) != 0) throw std::runtime_error{"posix_spawn failed"};
    return pid;
}

void test_live_exec_stdio_and_interpreter() {
    live_provider live;
    if (!live.begin("live exec stdio")) return;

    // 0 = a socket, 1 = a pipe, 2 = a regular file.
    int pair[2];
    int pipe_fds[2];
    require(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0 && ::pipe2(pipe_fds, O_CLOEXEC) == 0, "descriptors for the test");
    const auto file_path = (fs::temp_directory_path() / ("pan-stdio-" + std::to_string(::getpid()))).string();
    const int file_fd = ::open(file_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    require(file_fd >= 0, "a regular file to point stderr at");
    posix_spawn_file_actions_t actions;
    ::posix_spawn_file_actions_init(&actions);
    ::posix_spawn_file_actions_adddup2(&actions, pair[0], 0);
    ::posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], 1);
    ::posix_spawn_file_actions_adddup2(&actions, file_fd, 2);
    const auto first = spawn_with_actions("plain", &actions);
    ::posix_spawn_file_actions_destroy(&actions);

    // 0 and 1 = /dev/null, 2 closed.
    ::posix_spawn_file_actions_init(&actions);
    ::posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDWR, 0);
    ::posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_RDWR, 0);
    ::posix_spawn_file_actions_addclose(&actions, 2);
    const auto second = spawn_with_actions("plain", &actions);
    ::posix_spawn_file_actions_destroy(&actions);

    // A #! script run directly.
    const auto script_path = (fs::temp_directory_path() / ("pan-script-" + std::to_string(::getpid()) + ".sh")).string();
    {
        const int script_fd = ::open(script_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0700);
        require(script_fd >= 0, "a script to run");
        static constexpr char body[] = "#!/bin/sh\nexit 0\n";
        require(::write(script_fd, body, sizeof(body) - 1U) == static_cast<ssize_t>(sizeof(body) - 1U), "script written");
        ::close(script_fd);
    }
    pid_t third = 0;
    {
        char* argv[] = {const_cast<char*>("pan-script"), nullptr};
        require(::posix_spawn(&third, script_path.c_str(), nullptr, nullptr, argv, environ) == 0, "the script starts");
    }
    reap(first);
    reap(second);
    reap(third);
    ::close(pair[0]);
    ::close(pair[1]);
    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);
    ::close(file_fd);
    fs::remove(file_path);

    records_t all;
    require(collect(live.queue(), all,
                    [&](const records_t& r) {
                        return !execs_of(r, first).empty() && !execs_of(r, second).empty() && !execs_of(r, third).empty();
                    }),
            "all three execs are observed");
    const auto& one = std::get<raw_exec>(execs_of(all, first)[0]->payload);
    require(one.stdio.has_value() && (*one.stdio)[0] == stdio_kind::socket && (*one.stdio)[1] == stdio_kind::pipe &&
                (*one.stdio)[2] == stdio_kind::file,
            "socket, pipe and file on stdin, stdout and stderr");
    require(!one.interpreter.has_value(), "a binary has no interpreter");
    const auto& two = std::get<raw_exec>(execs_of(all, second)[0]->payload);
    require(two.stdio.has_value() && (*two.stdio)[0] == stdio_kind::null && (*two.stdio)[1] == stdio_kind::null &&
                (*two.stdio)[2] == stdio_kind::closed,
            "/dev/null twice and a closed descriptor");
    const auto& three = std::get<raw_exec>(execs_of(all, third)[0]->payload);
    require(three.interpreter == "/bin/sh" && three.filename == script_path, "a script reports its interpreter and the script path");
    fs::remove(script_path);
    require(live.provider().take_losses() == 0U, "no ring buffer losses");
}

std::vector<const raw_record*> signals_to(const records_t& records, const pid_t target) {
    return select<raw_signal>(records, [target](const raw_signal& s) { return s.target_tgid == static_cast<std::uint32_t>(target); });
}

void test_live_signals_between_processes() {
    live_provider live;
    if (!live.begin("live signals")) return;
    records_t all;
    const auto started = [&](const pid_t pid) {
        return collect(live.queue(), all, [&](const records_t& r) { return !execs_of(r, pid).empty(); });
    };

    const auto killed = spawn_child("sleep");
    require(started(killed), "first child started");
    require(::kill(killed, SIGTERM) == 0, "kill(2) of a running child");
    reap(killed);

    const auto tkilled = spawn_child("sleep");
    require(started(tkilled), "second child started");
    require(::syscall(SYS_tgkill, tkilled, tkilled, SIGKILL) == 0, "tgkill of a running child");
    reap(tkilled);

    // Not in the reported set, and a process ending itself: neither is a process acting on another.
    const auto usr = spawn_child("sleep");
    require(started(usr), "third child started");
    ::kill(usr, SIGUSR1);
    reap(usr);
    const auto self_kill = spawn_child("sigkill");
    reap(self_kill);

    // A child signals this process, which ignores SIGTERM for the moment: this process stands in for the sensor.
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    struct sigaction previous {};
    require(::sigaction(SIGTERM, &ignore, &previous) == 0, "SIGTERM ignored for the test");
    const auto nudger = spawn_child("signal_parent");
    reap(nudger);
    ::sigaction(SIGTERM, &previous, nullptr);

    require(collect(live.queue(), all,
                    [&](const records_t& r) {
                        return !exits_of(r, nudger).empty() && !exits_of(r, self_kill).empty() && !exits_of(r, usr).empty() &&
                               !exits_of(r, killed).empty() && !exits_of(r, tkilled).empty();
                    }),
            "every child exit is observed, so absence below means no event");

    const auto to_killed = signals_to(all, killed);
    require(to_killed.size() == 1U, "exactly one signal to the first child");
    const auto& one = std::get<raw_signal>(to_killed[0]->payload);
    require(one.sender_tgid == static_cast<std::uint32_t>(::getpid()) && one.number == 15U && one.code == 0 && one.result == "delivered" &&
                !one.target_is_sensor,
            "SIGTERM by kill(2), sent by this process, delivered, not aimed at the sensor");
    const auto to_tkilled = signals_to(all, tkilled);
    require(to_tkilled.size() == 1U, "exactly one signal to the second child");
    const auto& two = std::get<raw_signal>(to_tkilled[0]->payload);
    require(two.number == 9U && two.code == -6 && two.target_pid == static_cast<std::uint32_t>(tkilled), "SIGKILL by tgkill names the thread");
    require(signals_to(all, usr).empty(), "SIGUSR1 is outside the reported set");
    require(signals_to(all, self_kill).empty(), "a process killing itself is not reported");

    const auto from_nudger = select<raw_signal>(all, [nudger](const raw_signal& s) { return s.sender_tgid == static_cast<std::uint32_t>(nudger); });
    require(from_nudger.size() == 1U, "exactly one signal from the child that signalled its parent");
    const auto& three = std::get<raw_signal>(from_nudger[0]->payload);
    require(three.target_tgid == static_cast<std::uint32_t>(::getpid()) && three.target_is_sensor && three.number == 15U && three.result == "ignored",
            "a signal aimed at the sensor process is marked, and records that the sensor ignored it");
    require(live.provider().take_losses() == 0U, "no ring buffer losses");
}

void test_live_raw_sockets() {
    live_provider live{ebpf_role::security};
    if (!live.begin("live raw sockets")) return;

    const int packet = ::socket(AF_PACKET, SOCK_RAW, htons(0x0003U));
    require(packet >= 0, "a packet socket can be created as root");
    const int packet_again = ::socket(AF_PACKET, SOCK_RAW, htons(0x0003U));
    const int icmp = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    require(icmp >= 0, "a raw ICMP socket can be created as root");
    // Ordinary sockets are not reported.
    const int tcp = ::socket(AF_INET, SOCK_STREAM, 0);
    const int udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    const int unix_socket = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    for (const int fd : {packet, packet_again, icmp, tcp, udp, unix_socket}) {
        if (fd >= 0) ::close(fd);
    }

    const auto self = static_cast<std::uint32_t>(::getpid());
    const auto mine = [&](const records_t& seen) {
        return select<raw_security_event>(seen, [&](const raw_security_event& e) { return e.pid == self && e.kind == security_kind::raw_socket; });
    };
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& seen) { return mine(seen).size() >= 2U; }), "both raw sockets were reported for this process");
    // Give a possible third report (a duplicate, or an ordinary socket) time to arrive before counting.
    (void)collect(live.queue(), all, [&](const records_t& seen) { return mine(seen).size() > 2U; }, std::chrono::milliseconds{500});
    const auto found = mine(all);
    require(found.size() == 2U, "two reports: the repeated packet socket is one, ordinary sockets are none");
    bool saw_packet = false;
    bool saw_icmp = false;
    for (const auto* record : found) {
        const auto& event = std::get<raw_security_event>(record->payload);
        if (event.socket_family == "packet" && event.socket_type == "raw" && event.socket_protocol == 3U && event.protocol_name == "all") saw_packet = true;
        if (event.socket_family == "inet" && event.socket_type == "raw" && event.socket_protocol == 1U && event.protocol_name == "icmp") saw_icmp = true;
    }
    require(saw_packet && saw_icmp, "a packet socket for all EtherTypes and a raw ICMP socket, with their protocols");
    require(live.provider().take_losses() == 0U, "no ring buffer losses");
}

void test_live_start_ticks_match_procfs() {
    live_provider live;
    if (!live.begin("live start ticks")) return;
    const auto pid = spawn_child("sleep");
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !execs_of(r, pid).empty(); }), "exec observed");
    const auto from_kernel = std::get<raw_exec>(execs_of(all, pid)[0]->payload).start_ticks;
    const auto from_procfs = read_start_ticks("/proc", static_cast<std::uint32_t>(pid));
    ::kill(pid, SIGKILL);
    reap(pid);
    require(from_kernel.has_value() && from_procfs.has_value(), "both identities available");
    require(*from_kernel == *from_procfs, "the in-kernel start time equals /proc/<pid>/stat starttime, so entity ids agree across providers");
}

void test_live_signal_exit() {
    live_provider live;
    if (!live.begin("live signal exit")) return;
    const auto pid = spawn_child("sigkill");
    reap(pid);
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !exits_of(r, pid).empty(); }), "exit observed");
    const auto details = decode_exit_status(std::get<raw_exit>(exits_of(all, pid)[0]->payload).exit_status);
    require(details.signal == SIGKILL && !details.code.has_value(), "a process killed by a signal is reported with that signal");
}

void test_live_rename_ignores_exec_rename() {
    live_provider live;
    if (!live.begin("live rename")) return;
    const auto pid = spawn_child("rename");
    reap(pid);
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !exits_of(r, pid).empty(); }), "exit observed");
    const auto renames = select<raw_comm_change>(all, [pid](const raw_comm_change& c) { return c.tgid == static_cast<std::uint32_t>(pid); });
    require(renames.size() == 1U, "exactly one rename: the kernel's own rename during exec must not be reported (got " + std::to_string(renames.size()) + ")");
    require(std::get<raw_comm_change>(renames[0]->payload).comm == "pan-renamed", "the new name");
}

void test_live_credential_changes() {
    live_provider live;
    if (!live.begin("live credentials")) return;
    const auto changing = spawn_child("setid");
    const auto plain = spawn_child("plain");
    reap(changing);
    reap(plain);
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !exits_of(r, changing).empty() && !exits_of(r, plain).empty(); }), "exits observed");
    const auto changes = select<raw_credential_change>(all, [changing](const raw_credential_change& c) { return c.tgid == static_cast<std::uint32_t>(changing); });
    const auto uid = std::find_if(changes.begin(), changes.end(), [](const raw_record* r) { return std::get<raw_credential_change>(r->payload).user; });
    const auto gid = std::find_if(changes.begin(), changes.end(), [](const raw_record* r) { return !std::get<raw_credential_change>(r->payload).user; });
    require(uid != changes.end() && std::get<raw_credential_change>((*uid)->payload).real == 1234U && std::get<raw_credential_change>((*uid)->payload).effective == 1234U,
            "uid change to 1234");
    require(gid != changes.end() && std::get<raw_credential_change>((*gid)->payload).real == 1234U, "gid change to 1234");
    const auto spurious = select<raw_credential_change>(all, [plain](const raw_credential_change& c) { return c.tgid == static_cast<std::uint32_t>(plain); });
    require(spurious.empty(), "an exec that keeps the same credentials is not a credential change");
}

void test_live_ptrace_access() {
    live_provider live;
    if (!live.begin("live ptrace")) return;
    const auto target = spawn_child("sleep");
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !execs_of(r, target).empty(); }), "target exec observed");
    require(::ptrace(PTRACE_ATTACH, target, nullptr, nullptr) == 0, "attach to the target");
    int status = 0;
    ::waitpid(target, &status, 0);
    ::ptrace(PTRACE_DETACH, target, nullptr, nullptr);
    ::kill(target, SIGKILL);
    reap(target);
    const auto is_target = [target](const raw_ptrace& p) { return p.tgid == static_cast<std::uint32_t>(target); };
    require(collect(live.queue(), all, [&](const records_t& r) { return !select<raw_ptrace>(r, is_target).empty(); }), "the attach is observed");
    const auto traces = select<raw_ptrace>(all, is_target);
    require(std::get<raw_ptrace>(traces[0]->payload).tracer_tgid == static_cast<std::uint32_t>(::getpid()), "the tracer is the test process, not the target");
}

void test_live_thread_group_exit_is_one_process_exit() {
    live_provider live;
    if (!live.begin("live thread group")) return;
    const auto pid = spawn_child("threads");
    reap(pid);
    records_t all;
    require(collect(live.queue(), all, [&](const records_t& r) { return !exits_of(r, pid).empty(); }), "exit observed");
    // Give a hypothetical second report time to arrive.
    (void)collect(live.queue(), all, [](const records_t&) { return false; }, std::chrono::milliseconds{300});
    const auto exits = exits_of(all, pid);
    const auto execs = execs_of(all, pid);
    require(exits.size() == 1U, "one process exit for a multi-threaded process (got " + std::to_string(exits.size()) + ")");
    require(!execs.empty() && exits[0]->time_unix_ns - execs[0]->time_unix_ns >= 200'000'000ULL,
            "the exit is reported when the last thread ends, not when the leader does");
    require(decode_exit_status(std::get<raw_exit>(exits[0]->payload).exit_status).code == 0, "exit status of the group");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 3 && std::strcmp(argv[1], "--child") == 0) return child_main(argv[2]);
    std::cout << std::unitbuf;
    const auto run = [](const char* name, void (*test)()) {
        try {
            test();
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& failure) {
            ++failures;
            std::cout << "FAIL " << name << ": " << failure.what() << '\n';
        }
    };
    run("decode_fork_exit_rename", test_decode_fork_exit_rename);
    run("decode_exec_arguments", test_decode_exec_arguments);
    run("decode_exec_stdio_and_interpreter", test_decode_exec_stdio_and_interpreter);
    run("decode_signal", test_decode_signal);
    run("decode_raw_socket", test_decode_raw_socket);
    run("decode_tcp_close", test_decode_tcp_close);
    run("decode_network", test_decode_network);
    run("decode_security", test_decode_security);
    run("decode_namespace_change", test_decode_namespace_change);
    run("decode_dns", test_decode_dns);
    run("decode_credentials_and_ptrace", test_decode_credentials_and_ptrace);
    run("decode_rejects_malformed_samples", test_decode_rejects_malformed_samples);
    run("process_providers_share_a_family", test_process_providers_share_a_family);
    run("live_lifecycle_and_arguments", test_live_lifecycle_and_arguments);
    run("live_wake_policy", test_live_wake_policy_delivers_after_bursts_and_pauses);
    run("live_exec_stdio_and_interpreter", test_live_exec_stdio_and_interpreter);
    run("live_signals_between_processes", test_live_signals_between_processes);
    run("live_raw_sockets", test_live_raw_sockets);
    run("live_start_ticks_match_procfs", test_live_start_ticks_match_procfs);
    run("live_signal_exit", test_live_signal_exit);
    run("live_rename_ignores_exec_rename", test_live_rename_ignores_exec_rename);
    run("live_credential_changes", test_live_credential_changes);
    run("live_ptrace_access", test_live_ptrace_access);
    run("live_thread_group_exit_is_one_process_exit", test_live_thread_group_exit_is_one_process_exit);
    run("live_network_connect_accept_listen_udp", test_live_network_connect_accept_listen_udp);
    run("live_tcp_close_bytes", test_live_tcp_close_bytes);
    run("live_executable_memory_and_bpf", test_live_executable_memory_and_bpf);
    run("live_namespace_change", test_live_namespace_change);
    run("live_dns_query", test_live_dns_query);
    std::cout << (failures == 0 ? std::string{"ALL PASSED"} : "FAILURES: " + std::to_string(failures)) << " (skipped " << skipped << ")\n";
    return failures == 0 ? 0 : 1;
}
