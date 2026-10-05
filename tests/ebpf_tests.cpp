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

#include <pthread.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
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
    live_provider() : provider_{clock_}, queue_{65536U} {}
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
    run("decode_credentials_and_ptrace", test_decode_credentials_and_ptrace);
    run("decode_rejects_malformed_samples", test_decode_rejects_malformed_samples);
    run("process_providers_share_a_family", test_process_providers_share_a_family);
    run("live_lifecycle_and_arguments", test_live_lifecycle_and_arguments);
    run("live_start_ticks_match_procfs", test_live_start_ticks_match_procfs);
    run("live_signal_exit", test_live_signal_exit);
    run("live_rename_ignores_exec_rename", test_live_rename_ignores_exec_rename);
    run("live_credential_changes", test_live_credential_changes);
    run("live_ptrace_access", test_live_ptrace_access);
    run("live_thread_group_exit_is_one_process_exit", test_live_thread_group_exit_is_one_process_exit);
    std::cout << (failures == 0 ? std::string{"ALL PASSED"} : "FAILURES: " + std::to_string(failures)) << " (skipped " << skipped << ")\n";
    return failures == 0 ? 0 : 1;
}
