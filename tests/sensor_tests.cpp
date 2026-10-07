// Unit and ground-truth tests for the resident sensor (slice S1). Ground-truth cases start real
// processes and compare what the sensor reads with what the test knows it created.

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/container_identity.hpp"
#include "panopticon/linux_agent/sensor/container_tracker.hpp"
#include "panopticon/linux_agent/sensor/dns_message.hpp"
#include "panopticon/linux_agent/sensor/entity_graph.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"
#include "panopticon/linux_agent/sensor/netlink_proc.hpp"
#include "panopticon/linux_agent/sensor/pipeline.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"
#include "panopticon/linux_agent/sensor/serializer.hpp"
#include "panopticon/linux_agent/sensor/systemd_notify.hpp"
#include "panopticon/linux_agent/sensor/wal.hpp"

#include <linux/cn_proc.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

int failures = 0;
int skipped = 0;

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

template <typename value_type>
value_type value_of(result<value_type> outcome, const std::string& what) {
    if (!succeeded(outcome)) throw std::runtime_error{what + ": " + std::get<error>(outcome).message};
    return std::move(std::get<value_type>(outcome));
}

bool contains(const std::string_view haystack, const std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

fs::path fresh_directory(const std::string& name) {
    const auto directory = fs::temp_directory_path() / ("panopticon-sensor-tests-" + std::to_string(::getpid())) / name;
    fs::remove_all(directory);
    fs::create_directories(directory);
    return directory;
}

void write_file(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << contents;
}

std::string read_file(const fs::path& path) {
    std::ifstream input{path, std::ios::binary};
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

std::string stat_line(const std::uint32_t pid, const std::string& comm, const std::uint32_t ppid,
                      const std::uint64_t start_ticks, const std::uint64_t flags = 0x400100U, const std::uint32_t threads = 1U) {
    std::ostringstream line;
    line << pid << " (" << comm << ") S " << ppid << ' ' << pid << ' ' << pid << " 34816 -1 " << flags
         << " 0 0 0 0 0 0 0 0 20 0 " << threads << " 0 " << start_ticks << " 1000 100 18446744073709551615\n";
    return line.str();
}

// Builds /proc/<pid> in a fake procfs root.
struct fake_process {
    std::uint32_t pid{};
    std::uint32_t ppid{};
    std::string comm;
    std::uint64_t start_ticks{};
    std::string exe;
    std::vector<std::string> args;
    std::uint32_t uid{1000};
    std::string cgroup{"/system.slice/ssh.service"};

    void write(const fs::path& root) const {
        const auto base = root / std::to_string(pid);
        fs::remove_all(base);
        fs::create_directories(base / "ns");
        write_file(base / "stat", stat_line(pid, comm, ppid, start_ticks));
        std::ostringstream status;
        status << "Name:\t" << comm << "\nUid:\t" << uid << '\t' << uid << '\t' << uid << '\t' << uid << "\nGid:\t100\t100\t100\t100\n"
               << "Groups:\t4 27 100\nNSpid:\t" << pid << "\nThreads:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
               << "CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n";
        write_file(base / "status", status.str());
        std::string cmdline;
        for (const auto& arg : args) cmdline.append(arg).push_back('\0');
        write_file(base / "cmdline", cmdline);
        write_file(base / "environ", std::string{"PATH=/usr/bin\0SECRET=hunter2\0", 29U});
        write_file(base / "cgroup", "0::" + cgroup + "\n");
        write_file(base / "loginuid", "1000");
        write_file(base / "sessionid", "4294967295");
        fs::create_symlink(exe, base / "exe");
        fs::create_symlink("/home/user", base / "cwd");
        fs::create_symlink("mnt:[4026531840]", base / "ns" / "mnt");
        fs::create_symlink("pid:[4026531836]", base / "ns" / "pid");
    }
};

// ---- json -------------------------------------------------------------------------------

void test_json_escapes_and_replaces_invalid_utf8() {
    json_writer out;
    out.begin_object().field("text", std::string_view{"a\"b\\c\n\x01\x7f", 8U}).field("bad", std::string_view{"x\xff\xc0\xafy", 5U});
    out.field("utf8", "caf\xc3\xa9").field("n", std::uint64_t{18446744073709551615ULL}).field("neg", std::int64_t{-5});
    out.key("list").begin_array().value(true).null().end_array().end_object();
    require(out.str() == "{\"text\":\"a\\\"b\\\\c\\n\\u0001\\u007f\",\"bad\":\"x\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBDy\","
                         "\"utf8\":\"caf\xc3\xa9\",\"n\":18446744073709551615,\"neg\":-5,\"list\":[true,null]}",
            "json output: " + out.str());
    require(out.replaced_invalid_utf8(), "invalid utf-8 must be reported");
    std::string surrogate;
    require(append_json_string_body(surrogate, "\xed\xa0\x80"), "surrogates are invalid utf-8");
}

// ---- clock ------------------------------------------------------------------------------

void test_clock_formats_rfc3339_and_converts_ticks() {
    require(format_rfc3339_ns(0U) == "1970-01-01T00:00:00.000000000Z", "epoch formatting");
    require(format_rfc3339_ns(1700000000123456789ULL) == "2023-11-14T22:13:20.123456789Z", "nanosecond formatting");
    clock_domain clock;
    const auto now = clock_domain::now_unix_ns();
    const auto ticks = clock.unix_ns_to_ticks(now);
    const auto back = clock.ticks_to_unix_ns(ticks);
    const auto tick_ns = 1'000'000'000ULL / clock.ticks_per_second();
    require(back <= now && now - back < 2U * tick_ns, "ticks round trip within one tick");
    // Our own start time from procfs converts to a moment in the recent past.
    const auto self = read_start_ticks("/proc", static_cast<std::uint32_t>(::getpid()));
    require(self.has_value(), "own start ticks");
    const auto started = clock.ticks_to_unix_ns(*self);
    require(started <= now + tick_ns && now - started < 600ULL * 1'000'000'000ULL, "own start time is recent");
}

// ---- procfs parsing -----------------------------------------------------------------------

void test_parse_stat_handles_hostile_comm() {
    const auto fields = parse_stat(stat_line(123U, "a) S 9 (b", 77U, 4242U, 0x00200040U, 3U));
    require(fields.has_value(), "stat with parentheses in comm parses");
    require(fields->comm == "a) S 9 (b", "comm is bounded by the first '(' and the last ')'");
    require(fields->ppid == 77U && fields->start_ticks == 4242U && fields->threads == 3U, "numeric stat fields");
    require((fields->flags & 0x00200000U) != 0U, "kernel thread flag");
    require(!parse_stat("123 (x) S 1 2").has_value(), "short stat is rejected");
    require(!parse_stat("garbage").has_value(), "garbage stat is rejected");
}

void test_parse_status_reads_credentials_and_capabilities() {
    process_info info;
    parse_status("Uid:\t0\t1000\t2\t3\nGid:\t4\t5\t6\t7\nGroups:\t10 20\nNSpid:\t900\t1\nCapEff:\t000001ffffffffff\n"
                 "CapAmb:\t0000000000003000\nSeccomp:\t2\nNoNewPrivs:\t1\nThreads:\t7\n",
                 info);
    require(info.creds.uids == std::array<std::uint32_t, 4>{0U, 1000U, 2U, 3U}, "uids");
    require(info.creds.gids == std::array<std::uint32_t, 4>{4U, 5U, 6U, 7U}, "gids");
    require(info.creds.groups == std::vector<std::uint32_t>{10U, 20U}, "groups");
    require(info.vpid == 1U, "innermost NSpid");
    require(info.caps.effective == 0x1ffffffffffULL && info.caps.ambient == 0x3000ULL, "capability masks");
    require(info.seccomp_mode == 2 && info.no_new_privs == true && info.threads == 7U, "seccomp, nnp, threads");
}

void test_split_cmdline_bounds() {
    bool truncated = false;
    auto args = split_cmdline(std::string_view{"a\0bb\0ccc\0", 9U}, 64U, 4096U, truncated);
    require(args == std::vector<std::string>{"a", "bb", "ccc"} && !truncated, "plain cmdline");
    args = split_cmdline(std::string_view{"a\0bb\0ccc\0", 9U}, 2U, 4096U, truncated);
    require(args.size() == 2U && truncated, "argument count bound");
    truncated = false;
    args = split_cmdline(std::string_view{"abcdef\0gh\0", 10U}, 64U, 4U, truncated);
    require(args == std::vector<std::string>{"abcd"} && truncated, "byte bound");
}

void test_classify_exe_link() {
    require(classify_exe_link("/usr/bin/ls") == std::pair<std::string, executable_kind>{"/usr/bin/ls", executable_kind::file}, "file");
    require(classify_exe_link("/tmp/x (deleted)") == std::pair<std::string, executable_kind>{"/tmp/x", executable_kind::deleted}, "deleted");
    require(classify_exe_link("/memfd:payload (deleted)").second == executable_kind::memfd, "memfd");
    require(classify_exe_link("anon_inode:[x]").second == executable_kind::anonymous, "anonymous");
}

void test_read_process_from_fake_procfs() {
    const auto root = fresh_directory("fakeproc");
    fake_process{4242U, 1U, "sshd", 777U, "/usr/sbin/sshd (deleted)", {"/usr/sbin/sshd", "-D"}}.write(root);
    const auto& info = value_of(read_process(root, 4242U, procfs_limits{}), "read fake process");
    require(info.comm == "sshd" && info.ppid == 1U && info.start_ticks == 777U, "core fields");
    require(info.executable.path == "/usr/sbin/sshd" && info.executable.kind == executable_kind::deleted, "deleted executable");
    require(info.args == std::vector<std::string>{"/usr/sbin/sshd", "-D"}, "args");
    require(info.cwd == "/home/user", "cwd");
    require(info.cgroup == "/system.slice/ssh.service", "cgroup v2 path");
    require(info.creds.loginuid == 1000U && !info.creds.sessionid.has_value(), "loginuid set, sessionid unset");
    require(info.namespaces[0] == 4026531840ULL && info.namespaces[1] == 4026531836ULL, "namespace inodes");
    require(info.env.count("PATH") == 1U && info.env.count("SECRET") == 0U, "environment allowlist");
    require(!succeeded(read_process(root, 999U, procfs_limits{})), "missing process is an error");
    require(list_pids(root) == std::vector<std::uint32_t>{4242U}, "pid listing");
}

// ---- ground truth on the real procfs ---------------------------------------------------------

pid_t spawn(const std::function<void()>& child) {
    const pid_t pid = ::fork();
    if (pid == 0) {
        child();
        ::_exit(127);
    }
    return pid;
}

void reap(const pid_t pid) {
    ::kill(pid, SIGKILL);
    int status = 0;
    ::waitpid(pid, &status, 0);
}

// Waits until the child has exec'd (its comm differs from ours).
process_info wait_for_exec(const pid_t pid, const std::string& expected_comm) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        auto info = read_process("/proc", static_cast<std::uint32_t>(pid), procfs_limits{});
        if (succeeded(info) && std::get<process_info>(info).comm == expected_comm) return std::get<process_info>(info);
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    throw std::runtime_error{"child did not exec " + expected_comm};
}

std::string sleep_binary() {
    for (const char* candidate : {"/usr/bin/sleep", "/bin/sleep"}) {
        if (fs::exists(candidate)) return fs::canonical(candidate).string();
    }
    throw std::runtime_error{"no sleep binary"};
}

void test_ground_truth_exec_args_environment() {
    const auto binary = sleep_binary();
    const pid_t pid = spawn([&] {
        const char* argv[] = {"sleep", "30", nullptr};
        const char* envp[] = {"PATH=/usr/bin", "SUDO_USER=tester", "API_TOKEN=do-not-collect", nullptr};
        ::execve(binary.c_str(), const_cast<char* const*>(argv), const_cast<char* const*>(envp));
    });
    const auto info = wait_for_exec(pid, "sleep");
    reap(pid);
    require(info.pid == static_cast<std::uint32_t>(pid) && info.ppid == static_cast<std::uint32_t>(::getpid()), "pid and ppid");
    require(info.executable.path == binary && info.executable.kind == executable_kind::file && info.executable.known, "executable");
    require(info.args == std::vector<std::string>{"sleep", "30"}, "argv as executed");
    require(info.env.count("SUDO_USER") == 1U && info.env.at("SUDO_USER") == "tester", "allowlisted environment");
    require(info.env.count("API_TOKEN") == 0U, "non-allowlisted environment is never collected");
    require(info.creds.uids[0] == ::getuid() && info.namespaces[0] != 0U, "credentials and namespaces");
}

void test_ground_truth_deleted_executable() {
    const auto directory = fresh_directory("deleted");
    const auto copy = directory / "dropper";
    fs::copy_file(sleep_binary(), copy);
    fs::permissions(copy, fs::perms::owner_all);
    const pid_t pid = spawn([&] {
        const char* argv[] = {"dropper", "30", nullptr};
        ::execv(copy.c_str(), const_cast<char* const*>(argv));
    });
    (void)wait_for_exec(pid, "dropper");
    fs::remove(copy);
    const auto info = value_of(read_process("/proc", static_cast<std::uint32_t>(pid), procfs_limits{}), "read deleted");
    reap(pid);
    require(info.executable.kind == executable_kind::deleted, "deleted executable kind");
    require(info.executable.path == copy.string(), "deleted executable keeps its original path");
    require(info.executable.known && info.executable.inode != 0U, "deleted executable inode is still readable");
}

void test_ground_truth_memfd_execution() {
    const auto image = read_file(sleep_binary());
    const pid_t pid = spawn([&] {
        const int fd = ::memfd_create("panopticon-test", MFD_CLOEXEC);
        if (fd < 0 || ::write(fd, image.data(), image.size()) != static_cast<ssize_t>(image.size())) ::_exit(126);
        const char* argv[] = {"memexec", "30", nullptr};
        const char* envp[] = {nullptr};
        ::fexecve(fd, const_cast<char* const*>(argv), const_cast<char* const*>(envp));
    });
    // comm after fexecve is the fd number name the kernel used (e.g. "3"), so wait on the exe link.
    process_info info;
    for (int attempt = 0; attempt < 200; ++attempt) {
        auto read = read_process("/proc", static_cast<std::uint32_t>(pid), procfs_limits{});
        if (succeeded(read) && std::get<process_info>(read).executable.kind == executable_kind::memfd) {
            info = std::get<process_info>(read);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    reap(pid);
    require(info.executable.kind == executable_kind::memfd, "memfd execution is classified as memfd");
    require(contains(info.executable.path, "panopticon-test"), "memfd name is preserved: " + info.executable.path);
}

// ---- entity graph -------------------------------------------------------------------------

raw_record record_of(raw_payload payload, const std::uint64_t time = 1'700'000'000'000'000'000ULL) {
    return raw_record{time, {"netlink_proc", "CNPROC", confidence::observed}, std::move(payload)};
}

void test_entity_graph_lifecycle() {
    const auto root = fresh_directory("graphproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    clock_domain clock;
    entity_graph graph{{"host-1", "boot-1", root, {}, 30'000'000'000ULL, 1024U, 8U}, clock};
    require(graph.reconcile(1U, false).empty(), "silent seed");
    require(graph.find(100U) && graph.find(1U), "seeded entities");
    const auto bash_id = graph.find(100U)->entity_id;
    require(bash_id == compute_entity_id("host-1", "boot-1", 100U, 500U), "entity id is SHA-256(host|boot|tgid|ticks)");
    require(graph.find(100U)->parent_entity_id == graph.find(1U)->entity_id, "parent link from seed");

    // Thread creation is not a process.
    require(graph.apply(record_of(raw_fork{100U, 100U, 100U, 101U, std::nullopt})).empty(), "thread fork ignored");

    fake_process{200U, 100U, "bash", 900U, "/usr/bin/bash", {"-bash"}}.write(root);
    auto events = graph.apply(record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}));
    require(events.size() == 1U && events[0].type == "process.fork", "fork event");
    const auto child_id = events[0].process->entity_id;
    require(child_id == compute_entity_id("host-1", "boot-1", 200U, 900U), "child identity from procfs start ticks");
    require(events[0].parent && events[0].parent->entity_id == bash_id, "fork parent");
    require(events[0].process->exec_gen == 0U && events[0].process->info.comm == "bash", "fork child inherits image");

    fake_process{200U, 100U, "curl", 900U, "/usr/bin/curl", {"curl", "http://example.invalid"}}.write(root);
    events = graph.apply(record_of(raw_exec{200U, 200U, std::nullopt, std::nullopt, std::nullopt}));
    require(events.size() == 1U && events[0].type == "process.exec", "exec event");
    require(events[0].process->entity_id == child_id, "exec keeps the entity id");
    require(events[0].process->exec_gen == 1U, "exec_gen increments");
    require(events[0].previous_executable == "/usr/bin/bash", "previous executable");
    require(events[0].process->info.args.size() == 2U && events[0].process->info.comm == "curl", "exec enrichment");
    require(events[0].ancestry.size() == 2U && events[0].ancestry[0].entity_id == bash_id && events[0].ancestry[1].pid == 1U,
            "ancestry nearest first");

    events = graph.apply(record_of(raw_comm_change{200U, 200U, "kworker/0:1"}));
    require(events.size() == 1U && events[0].type == "process.rename" && events[0].previous_name == "curl", "rename");

    events = graph.apply(record_of(raw_credential_change{200U, 200U, true, 0U, 0U}));
    require(events.size() == 1U && events[0].type == "process.cred_change" && events[0].creds_before->uids[1] == 1000U &&
                events[0].process->info.creds.uids[1] == 0U,
            "credential change");

    events = graph.apply(record_of(raw_ptrace{200U, 200U, 100U, 100U}));
    require(events.size() == 1U && events[0].type == "process.inject" && events[0].target->entity_id == child_id &&
                events[0].process->entity_id == bash_id && events[0].technique == "ptrace_attach",
            "ptrace attach");

    events = graph.apply(record_of(raw_exit{200U, 200U, 0x8BU, 17U}));
    require(events.size() == 1U && events[0].type == "process.exit" && events[0].exit->signal == 11 && events[0].exit->core_dumped,
            "exit decoded");
    require(graph.apply(record_of(raw_exit{200U, 200U, 0U, 17U})).empty(), "duplicate exit suppressed");

    // PID reuse: a new process with the same pid and a different start time is a new entity.
    fake_process{200U, 100U, "nc", 1500U, "/usr/bin/nc", {"nc", "-l"}}.write(root);
    events = graph.apply(record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}));
    require(events.size() == 1U && events[0].process->entity_id != child_id, "reused pid gets a new entity id");
}

void test_entity_graph_prefers_kernel_arguments_and_paths() {
    const auto root = fresh_directory("graphkernel");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    // procfs shows arguments the process rewrote after exec; the kernel saw the original ones.
    fake_process{200U, 100U, "curl", 900U, "/usr/bin/curl", {"curl", "-s", "https://rewritten.invalid"}}.write(root);
    clock_domain clock;
    entity_graph graph{{"host-1", "boot-1", root, {}, 30'000'000'000ULL, 1024U, 8U}, clock};
    (void)graph.reconcile(1U, false);

    raw_exec observed;
    observed.tgid = 200U;
    observed.pid = 200U;
    observed.filename = "./curl";
    observed.args = std::vector<std::string>{"curl", "-s", "http://original.invalid"};
    observed.start_ticks = 900U;
    auto events = graph.apply(record_of(observed));
    require(events.size() == 1U && events[0].type == "process.exec", "exec event");
    const auto& info = events[0].process->info;
    require(info.args == std::vector<std::string>({"curl", "-s", "http://original.invalid"}), "kernel-captured argv wins over procfs");
    require(events[0].process->attributes == confidence::observed, "attributes are observed when argv came from the kernel");
    require(info.executable.path == "/usr/bin/curl" && info.executable.kind == executable_kind::file,
            "a resolved procfs executable wins over the raw execve string");

    // The process is already gone from procfs: the kernel-captured path and argv are all there is.
    raw_exec gone;
    gone.tgid = 300U;
    gone.pid = 300U;
    gone.filename = "./tool";
    gone.args = std::vector<std::string>{"tool", "--x"};
    gone.start_ticks = 777U;
    gone.args_truncated = true;
    events = graph.apply(record_of(gone));
    require(events.size() == 1U, "exec of a process that has already exited");
    const auto& vanished = *events[0].process;
    require(vanished.entity_id == compute_entity_id("host-1", "boot-1", 300U, 777U), "identity from the kernel start time");
    require(vanished.identity == confidence::observed && vanished.attributes == confidence::observed, "observed provenance");
    require(vanished.info.executable.path == "./tool" && vanished.info.args.size() == 2U && vanished.info.args_truncated,
            "kernel path, argv and truncation flag survive");
    for (const auto& field : vanished.info.unavailable) {
        require(field.field != "process.executable" && field.field != "process.args", "no stale unavailable marker for " + field.field);
    }

    // A short-lived child: seen as a copy of its parent at fork, gone from procfs by the time its
    // exec is processed. The exec must describe the new program, not the pre-exec parent image.
    fake_process{400U, 100U, "bash", 1200U, "/usr/bin/bash", {"-bash"}}.write(root);
    (void)graph.apply(record_of(raw_fork{100U, 100U, 400U, 400U, std::nullopt}));
    fs::remove_all(root / "400");
    raw_exec shortlived;
    shortlived.tgid = 400U;
    shortlived.pid = 400U;
    shortlived.filename = "/usr/bin/true";
    shortlived.args = std::vector<std::string>{"/bin/true"};
    shortlived.start_ticks = 1200U;
    events = graph.apply(record_of(shortlived));
    require(events.size() == 1U && events[0].type == "process.exec", "exec of a short-lived child");
    const auto& child = *events[0].process;
    require(child.info.executable.path == "/usr/bin/true", "executable is the exec'd program, not the inherited parent image");
    require(child.info.comm == "true", "name follows the exec'd program");
    require(events[0].previous_executable == "/usr/bin/bash", "the previous image is still reported as such");
}

void test_entity_graph_reconcile_infers_missed_exit() {
    const auto root = fresh_directory("reconcileproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    clock_domain clock;
    entity_graph graph{{"host-1", "boot-1", root, {}, 30'000'000'000ULL, 1024U, 8U}, clock};
    (void)graph.reconcile(1U, false);
    fake_process{300U, 1U, "cron", 50U, "/usr/sbin/cron", {"cron"}}.write(root);
    auto events = graph.reconcile(2U);
    require(events.size() == 1U && events[0].type == "process.discovered" && events[0].source.level == confidence::reconstructed,
            "discovered");
    fs::remove_all(root / "300");
    require(graph.reconcile(3U).empty(), "one missed scan is not yet an exit");
    events = graph.reconcile(4U);
    require(events.size() == 1U && events[0].type == "process.exit" && events[0].source.level == confidence::inferred, "inferred exit");
    graph.purge(4U + 31'000'000'000ULL);
    require(!graph.find(300U), "exited entity purged after grace");
}

void test_exit_status_decoding() {
    require(decode_exit_status(0x0100U).code == 1, "exit code");
    require(decode_exit_status(0x0009U).signal == 9 && !decode_exit_status(0x0009U).core_dumped, "signal");
    require(decode_exit_status(0x008BU).signal == 11 && decode_exit_status(0x008BU).core_dumped, "core dump");
}

// ---- netlink decoding ---------------------------------------------------------------------

void test_decode_proc_events() {
    clock_domain clock;
    proc_event event{};
    event.what = static_cast<decltype(event.what)>(0x00000001U);  // PROC_EVENT_FORK (named differently across header versions)
    event.timestamp_ns = 5U;
    event.event_data.fork.parent_pid = 10;
    event.event_data.fork.parent_tgid = 10;
    event.event_data.fork.child_pid = 11;
    event.event_data.fork.child_tgid = 11;
    auto decoded = decode_proc_event(&event, sizeof(event), clock);
    require(decoded && std::holds_alternative<raw_fork>(decoded->payload) && std::get<raw_fork>(decoded->payload).child_tgid == 11U, "fork");

    event = {};
    event.what = static_cast<decltype(event.what)>(0x00000200U);  // PROC_EVENT_COMM
    event.event_data.comm.process_pid = 12;
    event.event_data.comm.process_tgid = 12;
    std::memcpy(event.event_data.comm.comm, "0123456789abcdef", 16U);  // no terminator
    decoded = decode_proc_event(&event, sizeof(event), clock);
    require(decoded && std::get<raw_comm_change>(decoded->payload).comm == "0123456789abcdef", "unterminated comm bounded");

    event = {};
    event.what = static_cast<decltype(event.what)>(0x80000000U);  // PROC_EVENT_EXIT
    event.event_data.exit.process_pid = 12;
    event.event_data.exit.process_tgid = 12;
    event.event_data.exit.exit_code = 0x0200U;
    decoded = decode_proc_event(&event, sizeof(event), clock);
    require(decoded && std::get<raw_exit>(decoded->payload).exit_status == 0x0200U, "exit");

    require(!decode_proc_event(&event, 8U, clock).has_value(), "truncated event rejected");
    event.what = static_cast<decltype(event.what)>(0U);  // PROC_EVENT_NONE
    require(!decode_proc_event(&event, sizeof(event), clock).has_value(), "unused kinds ignored");
}

void test_live_netlink_observes_real_process() {
    if (::geteuid() != 0) {
        std::cout << "SKIP live netlink: requires CAP_NET_ADMIN (run as root)\n";
        ++skipped;
        return;
    }
    clock_domain clock;
    netlink_proc_provider provider{clock};
    require(provider.probe().empty(), "netlink probe as root");
    record_queue queue{65536U};
    value_of(provider.start(queue), "start netlink");
    const auto binary = sleep_binary();
    const pid_t pid = spawn([&] {
        const char* argv[] = {"sleep", "0", nullptr};
        ::execv(binary.c_str(), const_cast<char* const*>(argv));
    });
    int status = 0;
    ::waitpid(pid, &status, 0);
    bool fork_seen = false, exec_seen = false, exit_seen = false;
    std::vector<raw_record> batch;
    for (int attempt = 0; attempt < 40 && !(fork_seen && exec_seen && exit_seen); ++attempt) {
        batch.clear();
        queue.pop_batch(batch, 4096U, std::chrono::milliseconds{50});
        for (const auto& record : batch) {
            if (const auto* fork = std::get_if<raw_fork>(&record.payload); fork && fork->child_tgid == static_cast<std::uint32_t>(pid)) fork_seen = true;
            if (const auto* exec = std::get_if<raw_exec>(&record.payload); exec && exec->tgid == static_cast<std::uint32_t>(pid)) exec_seen = true;
            if (const auto* exit = std::get_if<raw_exit>(&record.payload); exit && exit->tgid == static_cast<std::uint32_t>(pid) && exit->pid == exit->tgid) {
                exit_seen = decode_exit_status(exit->exit_status).code == 0;
            }
        }
    }
    provider.stop();
    require(fork_seen && exec_seen && exit_seen, "netlink saw fork, exec and exit of a real process");
    require(provider.health().events > 0U, "provider counts events");
}

// ---- WAL --------------------------------------------------------------------------------

wal_options small_wal(const fs::path& directory) {
    wal_options options;
    options.directory = directory;
    options.segment_bytes = 4096U;
    options.quota_bytes = 16384U;
    options.maximum_record_bytes = 1024U;
    return options;
}

void test_crc32c_known_vector() {
    require(crc32c(0U, "123456789", 9U) == 0xE3069283U, "crc32c check value");
    require(crc32c_portable(0U, "123456789", 9U) == 0xE3069283U, "table implementation check value");
    // The hardware path takes eight bytes at a time and then single bytes, so sizes and start offsets around the word
    // boundary are where it could differ from the table version; frames already on disk depend on them agreeing.
    std::vector<unsigned char> bytes(1024U);
    std::uint32_t state = 0x9E3779B9U;
    for (auto& byte : bytes) {
        state = state * 1664525U + 1013904223U;
        byte = static_cast<unsigned char>(state >> 24U);
    }
    for (std::size_t offset = 0U; offset < 9U; ++offset) {
        for (std::size_t size = 0U; size <= 300U; ++size) {
            require(crc32c(0U, bytes.data() + offset, size) == crc32c_portable(0U, bytes.data() + offset, size),
                    "hardware and table crc32c agree at offset " + std::to_string(offset) + " size " + std::to_string(size));
        }
    }
    const auto chained = crc32c(crc32c(0U, bytes.data(), 13U), bytes.data() + 13U, 600U);
    require(chained == crc32c_portable(crc32c_portable(0U, bytes.data(), 13U), bytes.data() + 13U, 600U), "running values agree");
    require(chained == crc32c(0U, bytes.data(), 613U), "a running value equals one pass over the same bytes");
}

void test_wal_append_read_ack_and_recover() {
    const auto directory = fresh_directory("wal");
    {
        auto log = std::move(std::get<std::unique_ptr<write_ahead_log>>(write_ahead_log::open(small_wal(directory))));
        require(log->next_seq() == 1U, "fresh log starts at 1");
        // ~220-byte frames: 18 per 4 KiB segment, so 40 records span three segments.
        for (std::uint64_t seq = 1U; seq <= 40U; ++seq) value_of(log->append(seq, "record-" + std::to_string(seq) + std::string(200U, 'p')), "append");
        require(!succeeded(log->append(99U, "gap")), "non-contiguous seq rejected");
        // Rotation syncs the finished segment; records in the active one stay unreadable until synced.
        const auto durable = log->metrics().durable_seq;
        require(durable > 0U && durable < 40U, "rotation made earlier segments durable");
        require(value_of(log->read(durable + 1U, 100U, 1U << 20U), "read before sync").empty(), "unsynced records are not readable");
        value_of(log->sync(0U, true), "sync");
        const auto first = value_of(log->read(1U, 10U, 1U << 20U), "read 1");
        require(first.size() == 10U && first.front().seq == 1U && first.back().payload.rfind("record-10p", 0U) == 0U, "bounded read");
        const auto second = value_of(log->read(11U, 100U, 1U << 20U), "read 2");
        require(second.size() == 30U && second.front().seq == 11U && second.back().seq == 40U, "read across segments");
        value_of(log->acknowledge(20U), "ack");
        require(log->metrics().acknowledged_seq == 20U, "ack recorded");
    }
    {
        auto log = std::move(std::get<std::unique_ptr<write_ahead_log>>(write_ahead_log::open(small_wal(directory))));
        require(log->next_seq() == 41U, "seq continues after restart");
        require(log->take_losses().empty(), "clean restart has no losses");
        require(log->metrics().segments >= 2U, "records span several segments");
        const auto records = value_of(log->read(21U, 100U, 1U << 20U), "read after restart");
        require(!records.empty() && records.front().seq == 21U && records.back().seq == 40U, "unacknowledged records survive");
    }
    // Tear the tail of the newest segment.
    std::vector<fs::path> segments;
    for (const auto& entry : fs::directory_iterator{directory}) {
        if (entry.path().filename().string().rfind("wal-", 0U) == 0U) segments.push_back(entry.path());
    }
    std::sort(segments.begin(), segments.end());
    const auto newest = segments.back();
    fs::resize_file(newest, fs::file_size(newest) - 3U);
    {
        auto log = std::move(std::get<std::unique_ptr<write_ahead_log>>(write_ahead_log::open(small_wal(directory))));
        const auto losses = log->take_losses();
        require(losses.size() == 1U && losses[0].reason == "torn_tail" && losses[0].bytes > 0U, "torn tail reported");
        require(log->next_seq() == 40U, "torn record is gone and its seq is reused");
        value_of(log->append(40U, "replacement"), "append after recovery");
    }
}

void test_wal_detects_corruption_and_enforces_quota() {
    const auto directory = fresh_directory("walquota");
    auto log = std::move(std::get<std::unique_ptr<write_ahead_log>>(write_ahead_log::open(small_wal(directory))));
    const std::string payload(500U, 'x');
    for (std::uint64_t seq = 1U; seq <= 60U; ++seq) value_of(log->append(seq, payload), "append for quota");
    const auto losses = log->take_losses();
    require(!losses.empty() && losses.front().reason == "quota" && losses.front().first_seq == 1U, "quota drops oldest");
    require(log->metrics().bytes <= 16384U, "quota bound respected");
    value_of(log->sync(0U, true), "sync");
    const auto records = value_of(log->read(1U, 1000U, 1U << 20U), "read after drop");
    require(!records.empty() && records.front().seq > 1U && records.back().seq == 60U, "reader skips dropped range");

    // Flip a payload byte in the oldest remaining segment: recovery cuts it and everything after.
    log.reset();
    std::vector<fs::path> segments;
    for (const auto& entry : fs::directory_iterator{directory}) {
        if (entry.path().filename().string().rfind("wal-", 0U) == 0U) segments.push_back(entry.path());
    }
    std::sort(segments.begin(), segments.end());
    {
        std::fstream file{segments.front(), std::ios::in | std::ios::out | std::ios::binary};
        file.seekp(static_cast<std::streamoff>(wal_header_bytes + 10U));
        file.put('y');
    }
    auto reopened = std::move(std::get<std::unique_ptr<write_ahead_log>>(write_ahead_log::open(small_wal(directory))));
    const auto recovery = reopened->take_losses();
    require(!recovery.empty() && recovery.front().reason == "corrupt_segment", "corruption reported");
}

std::unique_ptr<write_ahead_log> open_wal(const fs::path& directory) {
    return std::move(std::get<std::unique_ptr<write_ahead_log>>(write_ahead_log::open(small_wal(directory))));
}

std::vector<fs::path> wal_segments(const fs::path& directory) {
    std::vector<fs::path> segments;
    for (const auto& entry : fs::directory_iterator{directory}) {
        if (entry.path().filename().string().rfind("wal-", 0U) == 0U) segments.push_back(entry.path());
    }
    std::sort(segments.begin(), segments.end());
    return segments;
}

// Everything the log will hand out from `from`, the way the uplink asks for it: read, then read after the last seq.
std::vector<std::uint64_t> drain_wal(write_ahead_log& log, std::uint64_t from) {
    std::vector<std::uint64_t> seqs;
    for (int guard = 0; guard < 64; ++guard) {
        const auto records = value_of(log.read(from, 100U, 1U << 20U), "drain read");
        if (records.empty()) break;
        for (const auto& record : records) seqs.push_back(record.seq);
        from = records.back().seq + 1U;
    }
    return seqs;
}

// A segment deleted behind a running log is reported with its exact range, and delivery carries on with what is left.
void test_wal_removed_sealed_segment_is_reported_and_skipped() {
    const auto directory = fresh_directory("walremoved");
    auto log = open_wal(directory);
    const std::string payload(200U, 'p');
    for (std::uint64_t seq = 1U; seq <= 40U; ++seq) value_of(log->append(seq, payload), "append");
    value_of(log->sync(0U, true), "sync");
    value_of(log->acknowledge(5U), "ack");
    const auto segments = wal_segments(directory);
    require(segments.size() >= 3U, "records span at least three segments");
    fs::remove(segments.front());
    require(log->verify_storage() == 1U, "one segment found missing");
    const auto losses = log->take_losses();
    require(losses.size() == 1U && losses[0].reason == "removed", "removal reported as a loss");
    require(losses[0].first_seq == 6U && losses[0].records == losses[0].last_seq - 5U, "only unacknowledged records of the segment are lost");
    require(log->metrics().dropped_records == losses[0].records, "dropped_records counts the removal");
    const auto seqs = drain_wal(*log, 6U);
    require(!seqs.empty() && seqs.front() == losses[0].last_seq + 1U && seqs.back() == 40U, "delivery resumes after the removed range");
    require(log->next_seq() == 41U, "no seq is reused");

    // A reader that finds the file missing before verify_storage does is not wedged either.
    const auto directory_two = fresh_directory("walremoved2");
    auto second = open_wal(directory_two);
    for (std::uint64_t seq = 1U; seq <= 40U; ++seq) value_of(second->append(seq, payload), "append");
    value_of(second->sync(0U, true), "sync");
    fs::remove(wal_segments(directory_two).front());
    const auto delivered = drain_wal(*second, 1U);
    require(!delivered.empty() && delivered.back() == 40U, "read survives a missing segment and reaches the end");
    const auto reported = second->take_losses();
    require(reported.size() == 1U && reported[0].reason == "removed" && reported[0].first_seq == 1U, "missing segment reported by the reader");
    log.reset();
    second.reset();

    // A restart after the removal opens, and carries on from the remaining records.
    auto reopened = open_wal(directory);
    require(reopened->next_seq() == 41U, "seq continues after restart");
}

// The segment being written is deleted: appends were going to an unlinked file. Nothing may be silently lost.
void test_wal_removed_active_segment_and_directory() {
    const auto directory = fresh_directory("walactive");
    auto log = open_wal(directory);
    for (std::uint64_t seq = 1U; seq <= 5U; ++seq) value_of(log->append(seq, "before"), "append");
    value_of(log->sync(0U, true), "sync");
    fs::remove(wal_segments(directory).front());
    require(log->verify_storage() == 1U, "deleted active segment found");
    auto losses = log->take_losses();
    require(losses.size() == 1U && losses[0].reason == "removed" && losses[0].first_seq == 1U && losses[0].last_seq == 5U && losses[0].records == 5U,
            "the five unacknowledged records are reported with their range");
    require(log->verify_storage() == 0U, "second check is quiet");
    value_of(log->append(6U, "after"), "append after removal");
    value_of(log->sync(0U, true), "sync after removal");
    require(drain_wal(*log, 1U) == std::vector<std::uint64_t>{6U}, "new records land in a new segment and are readable");

    // The whole directory.
    fs::remove_all(directory);
    require(log->verify_storage() == 1U, "removed directory found");
    losses = log->take_losses();
    require(losses.size() == 1U && losses[0].first_seq == 6U && losses[0].last_seq == 6U, "record 6 reported");
    require(fs::is_directory(directory), "directory is created again");
    const auto mode = fs::status(directory).permissions();
    require((mode & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none, "directory is private again");
    value_of(log->append(7U, "again"), "append into the new directory");
    value_of(log->sync(0U, true), "sync into the new directory");
    require(drain_wal(*log, 7U) == std::vector<std::uint64_t>{7U}, "readable");
    require(log->next_seq() == 8U, "no seq is reused");

    // Acknowledged records are not reported as lost when their segment goes: they were delivered.
    value_of(log->acknowledge(7U), "ack");
    fs::remove(wal_segments(directory).front());
    require(log->verify_storage() == 1U, "found");
    require(log->take_losses().empty(), "nothing unacknowledged was lost");
}

// A frame that fails its checksum while the log runs costs the rest of that segment, not the stream.
void test_wal_runtime_corruption_is_isolated() {
    const auto directory = fresh_directory("walruntime");
    auto log = open_wal(directory);
    const std::string payload(200U, 'p');
    for (std::uint64_t seq = 1U; seq <= 40U; ++seq) value_of(log->append(seq, payload), "append");
    value_of(log->sync(0U, true), "sync");
    const auto segments = wal_segments(directory);
    require(segments.size() >= 3U, "records span at least three segments");
    {
        std::fstream file{segments[1], std::ios::in | std::ios::out | std::ios::binary};
        file.seekp(static_cast<std::streamoff>(wal_header_bytes + payload.size() + wal_header_bytes + 10U));  // second frame's payload
        file.put('y');
    }
    const auto seqs = drain_wal(*log, 1U);
    const auto losses = log->take_losses();
    require(losses.size() == 1U && losses[0].reason == "corrupt_segment", "corruption reported once");
    const auto lost_first = losses[0].first_seq;
    const auto lost_last = losses[0].last_seq;
    require(lost_first > 1U && lost_last >= lost_first && lost_last < 40U && losses[0].records == lost_last - lost_first + 1U, "range is exact");
    require(!seqs.empty() && seqs.front() == 1U && seqs.back() == 40U, "delivery reaches the newest record");
    for (std::size_t index = 1U; index < seqs.size(); ++index) require(seqs[index] > seqs[index - 1U], "seqs only increase");
    for (const auto seq : seqs) require(seq < lost_first || seq > lost_last, "nothing inside the lost range is delivered");
    require(seqs.size() == 40U - losses[0].records, "everything outside the lost range is delivered");
    require(log->next_seq() == 41U, "no seq is reused");
    require(drain_wal(*log, 1U) == seqs, "a second pass sees the same stream");
    require(log->take_losses().empty(), "the loss is reported once");
}

// ---- serializer and pipeline ----------------------------------------------------------------

class scripted_provider final : public provider {
public:
    explicit scripted_provider(std::vector<raw_record> records, const std::uint64_t governed = 0U)
        : records_{std::move(records)}, governed_{governed} {}
    std::string_view name() const noexcept override { return "scripted"; }
    std::vector<std::string> capabilities() const override { return {"process.fork", "process.exec", "process.exit"}; }
    std::string probe() override { return {}; }
    result<bool> start(record_queue& queue) override {
        queue_ = &queue;
        for (auto& record : records_) (void)queue.push(record);
        active_ = true;
        return true;
    }
    // Queues more records after start, as a live provider would.
    void push(std::vector<raw_record> more) {
        for (auto& record : more) (void)queue_->push(std::move(record));
    }
    void stop() override { active_ = false; }
    provider_health health() const override { return {"scripted", active_ ? "active" : "stopped", "", capabilities(), records_.size(), 0U}; }
    std::uint64_t take_losses() override { return 0U; }
    std::uint64_t take_governed() override { return std::exchange(governed_, 0U); }
    std::uint64_t take_refused() override { return std::exchange(refused_, 0U); }
    void refuse(const std::uint64_t count) { refused_ = count; }

private:
    std::vector<raw_record> records_;
    std::uint64_t governed_{0U};
    std::uint64_t refused_{0U};
    bool active_{false};
    record_queue* queue_{nullptr};
};

std::vector<std::string> lines_of(std::FILE* stream) {
    std::rewind(stream);
    std::vector<std::string> lines;
    std::string current;
    for (int c = std::fgetc(stream); c != EOF; c = std::fgetc(stream)) {
        if (c == '\n') lines.push_back(std::move(current)), current.clear();
        else current.push_back(static_cast<char>(c));
    }
    return lines;
}

void test_pipeline_end_to_end_with_scripted_provider() {
    const auto root = fresh_directory("pipelineproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    fake_process{200U, 100U, "curl", 900U, "/usr/bin/curl", {"curl", "-s", "http://198.51.100.7/x"}}.write(root);
    std::vector<raw_record> script{record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}),
                                   record_of(raw_exec{200U, 200U, std::nullopt, std::nullopt, std::nullopt}),
                                   record_of(raw_exit{200U, 200U, 0U, 17U})};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
        require(pipeline.metrics().events == 3U, "three process events");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    require(lines.size() >= 6U, "health, state, fork, exec, exit, final health");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq is contiguous from 1");
        require(contains(lines[index], "\"schema_version\":\"1.0\""), "schema version");
        require(lines[index].front() == '{' && lines[index].back() == '}', "one JSON object per line");
    }
    require(contains(lines[0], "\"record_type\":\"health\"") && contains(lines[0], "\"coverage\""), "first record is health");
    require(contains(lines[1], "\"type\":\"state.processes\"") && contains(lines[1], "\"parts\":1"), "initial state snapshot");
    const auto exec = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"type\":\"process.exec\""); });
    require(exec != lines.end(), "exec record present");
    require(contains(*exec, "\"exec_gen\":1") && contains(*exec, "\"path\":\"/usr/bin/curl\"") &&
                contains(*exec, "\"args\":[\"curl\",\"-s\",\"http://198.51.100.7/x\"]") &&
                contains(*exec, "\"unit\":\"ssh.service\"") && contains(*exec, "\"parent\":{\"entity_id\":\"" +
                                                                                     compute_entity_id("host-test", "boot-test", 100U, 500U)),
            "exec record content: " + *exec);
    require(contains(*exec, "\"id\":\"" + compute_record_id("sensor-test", "boot-test", static_cast<std::uint64_t>(exec - lines.begin()) + 1U) + "\""),
            "record id derived from seq");
    require(!contains(*exec, "hunter2"), "secret environment never serialised");
    // This provider did not capture stdio at exec; the record says so rather than staying silent.
    require(!contains(*exec, "\"stdio\":") && contains(*exec, "{\"field\":\"process.stdio\",\"reason\":\"not_supported_by_provider\"}"),
            "an exec without kernel-captured stdio says it is unavailable: " + *exec);
}

void test_pipeline_exec_stdio_and_interpreter() {
    const auto root = fresh_directory("stdioproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    fake_process{200U, 100U, "sh", 900U, "/usr/bin/dash", {"/bin/sh", "./run.sh"}}.write(root);
    raw_exec script_exec;
    script_exec.tgid = 200U;
    script_exec.pid = 200U;
    script_exec.filename = "./run.sh";
    script_exec.interpreter = "/bin/sh";
    script_exec.stdio = std::array<stdio_kind, 3>{stdio_kind::socket, stdio_kind::socket, stdio_kind::pipe};
    std::vector<raw_record> script{record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}), record_of(script_exec)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto exec = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"type\":\"process.exec\""); });
    require(exec != lines.end(), "exec record present");
    require(contains(*exec, "\"stdio\":{\"stdin\":\"socket\",\"stdout\":\"socket\",\"stderr\":\"pipe\"}"),
            "stdio is serialised with the process: " + *exec);
    require(contains(*exec, "\"interpreter\":\"/bin/sh\",\"script\":\"./run.sh\""), "a script is reported with its interpreter: " + *exec);
    require(!contains(*exec, "{\"field\":\"process.stdio\""), "and nothing is marked unavailable for it");
}

void test_pipeline_signal_event() {
    const auto root = fresh_directory("signalproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    fake_process{200U, 1U, "panopticon-sens", 900U, "/usr/sbin/panopticon-sensord", {"panopticon-sensord"}}.write(root);
    raw_signal to_sensor;
    to_sensor.sender_tgid = 100U;
    to_sensor.target_tgid = 200U;
    to_sensor.target_pid = 200U;
    to_sensor.number = 9U;
    to_sensor.code = 0;
    to_sensor.result = "delivered";
    to_sensor.target_is_sensor = true;
    raw_signal gone;  // the sender is not in the process table and not in procfs
    gone.sender_tgid = 4040U;
    gone.target_tgid = 100U;
    gone.target_pid = 100U;
    gone.number = 19U;
    gone.code = -6;
    gone.result = "ignored";
    std::vector<raw_record> script{record_of(to_sensor), record_of(gone)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::string> signals;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"process.signal\"")) signals.push_back(line);
    }
    require(signals.size() == 2U, "two process.signal records");
    require(contains(signals[0], "\"signal\":{\"number\":9,\"name\":\"SIGKILL\",\"via\":\"kill\",\"result\":\"delivered\",\"target_is_sensor\":true}") &&
                contains(signals[0], "\"process\":{") && contains(signals[0], "\"target\":{"),
            "sender, target and the signal, aimed at the sensor: " + signals[0]);
    require(contains(signals[0], "\"name\":\"bash\"") && contains(signals[0], "\"name\":\"panopticon-sens\""), "both processes are described");
    require(contains(signals[1], "\"name\":\"SIGSTOP\",\"via\":\"tgkill\",\"result\":\"ignored\",\"target_is_sensor\":false}") &&
                contains(signals[1], "{\"field\":\"process\",\"reason\":\"process_exited\"}"),
            "a sender that is gone is reported as unavailable, not invented: " + signals[1]);
}

void test_pipeline_raw_socket_event() {
    const auto root = fresh_directory("rawsockproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "sniff", 500U, "/tmp/sniff", {"sniff"}}.write(root);
    raw_security_event packet;
    packet.kind = security_kind::raw_socket;
    packet.pid = 100U;
    packet.socket_family = "packet";
    packet.socket_type = "raw";
    packet.socket_protocol = 3U;
    packet.protocol_name = "all";
    raw_security_event unnamed;
    unnamed.kind = security_kind::raw_socket;
    unnamed.pid = 4040U;  // gone
    unnamed.socket_family = "inet";
    unnamed.socket_type = "raw";
    unnamed.socket_protocol = 200U;
    std::vector<raw_record> script{record_of(packet), record_of(unnamed)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::string> found;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"network.raw_socket\"")) found.push_back(line);
    }
    require(found.size() == 2U, "two network.raw_socket records");
    require(contains(found[0], "\"socket\":{\"family\":\"packet\",\"type\":\"raw\",\"protocol\":3,\"protocol_name\":\"all\"}") &&
                contains(found[0], "\"name\":\"sniff\""),
            "the socket and the process that made it: " + found[0]);
    require(contains(found[1], "\"socket\":{\"family\":\"inet\",\"type\":\"raw\",\"protocol\":200}") && !contains(found[1], "protocol_name") &&
                contains(found[1], "{\"field\":\"process\",\"reason\":\"process_exited\"}"),
            "an unnamed protocol keeps its number and a vanished process is unavailable: " + found[1]);
}

void test_pipeline_enriches_file_events() {
    const auto root = fresh_directory("fileproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    const auto scratch = fresh_directory("filedata");
    write_file(scratch / "dropped.sh", "#!/bin/sh\n");
    const auto existing = (scratch / "dropped.sh").string();
    const auto make = [](const std::uint32_t pid, const file_operation operation, std::string path) {
        raw_file_event event;
        event.pid = pid;
        event.operation = operation;
        event.path = std::move(path);
        return record_of(event);
    };
    auto moved = make(100U, file_operation::rename, existing);
    std::get<raw_file_event>(moved.payload).old_path = "/tmp/old.sh";
    std::vector<raw_record> script{make(100U, file_operation::create, existing), std::move(moved),
                                   make(4242U, file_operation::remove, "/tmp/gone.sh"),
                                   make(100U, file_operation::modify, "/tmp/vanished.sh")};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 7U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto find = [&](const std::string_view type) {
        const auto found = std::find_if(lines.begin(), lines.end(), [&](const std::string& line) {
            return contains(line, std::string{"\"type\":\""} + std::string{type} + "\"");
        });
        require(found != lines.end(), std::string{"record present: "} + std::string{type});
        return *found;
    };
    const auto create = find("file.create");
    require(contains(create, "\"file\":{\"path\":\"" + existing + "\",\"name\":\"dropped.sh\",\"directory\":false,\"stat\":{\"mode\":"), "file path, name and stat");
    require(contains(create, "\"name\":\"bash\"") && contains(create, "\"pid\":100") && contains(create, "\"entity_id\":\""), "actor resolved from the entity graph");
    require(contains(find("file.rename"), "\"old_path\":\"/tmp/old.sh\""), "rename carries the old path");
    const auto removed = find("file.delete");
    require(contains(removed, "{\"field\":\"process\",\"reason\":\"process_exited\"}") && !contains(removed, "\"stat\":"), "unknown actor is reported, deleted file has no stat");
    require(contains(find("file.modify"), "{\"field\":\"file.stat\",\"reason\":\"object_gone\"}"), "a vanished path is reported, not invented");
    const auto loss = find("loss");
    require(contains(loss, "\"stage\":\"governor\"") && contains(loss, "\"count\":7"), "governed events become an exact loss record");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with file records");
    }
}

void test_pipeline_tcp_close_event() {
    const auto root = fresh_directory("closeproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "curl", 500U, "/usr/bin/curl", {"curl", "https://example.com"}}.write(root);
    raw_network_event seen_open;
    seen_open.operation = network_operation::close;
    seen_open.protocol = "tcp";
    seen_open.family = "inet";
    seen_open.local_address = "10.0.0.5";
    seen_open.local_port = 51000U;
    seen_open.remote_address = "93.184.216.34";
    seen_open.remote_port = 443U;
    seen_open.state = "established";
    seen_open.pid = 100U;
    seen_open.direction = "outbound";
    seen_open.bytes_sent = 5120U;
    seen_open.bytes_received = 1048576U;
    seen_open.duration_ns = 2500000000ULL;
    raw_network_event predates = seen_open;
    predates.pid = 4040U;  // gone
    predates.direction.clear();
    predates.duration_ns = 0U;
    predates.state = "close_wait";
    std::vector<raw_record> script{record_of(seen_open), record_of(predates)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::string> closes;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"network.close\"")) closes.push_back(line);
    }
    require(closes.size() == 2U, "two network.close records");
    require(contains(closes[0], "\"direction\":\"outbound\"") && contains(closes[0], "\"bytes_sent\":5120,\"bytes_received\":1048576,\"duration_ns\":2500000000") &&
                contains(closes[0], "\"name\":\"curl\""),
            "counters, duration and the closing process: " + closes[0]);
    require(contains(closes[1], "\"direction\":\"unknown\"") && contains(closes[1], "\"state\":\"close_wait\"") && !contains(closes[1], "duration_ns") &&
                contains(closes[1], "{\"field\":\"process\",\"reason\":\"process_exited\"}"),
            "a socket opened before the sensor has unknown direction and no duration: " + closes[1]);
}

void test_pipeline_enriches_network_events() {
    const auto root = fresh_directory("netproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "curl", 500U, "/usr/bin/curl", {"curl", "https://example.com"}}.write(root);
    const auto make = [](const network_operation operation, const std::uint32_t pid) {
        raw_network_event event;
        event.operation = operation;
        event.protocol = "tcp";
        event.family = "inet";
        event.local_address = "10.0.0.5";
        event.local_port = operation == network_operation::connect ? 51000U : 8080U;
        if (operation != network_operation::listen) {
            event.remote_address = "93.184.216.34";
            event.remote_port = 443U;
        }
        event.state = operation == network_operation::listen ? "listen" : "established";
        event.inode = 12345U;
        event.uid = 1000U;
        event.pid = pid;
        event.holders = pid == 100U ? 2U : 0U;
        if (pid == 0U) event.unavailable.push_back({"process", unavailable_reason::process_exited});
        return record_of(event);
    };
    std::vector<raw_record> script{make(network_operation::connect, 100U), make(network_operation::listen, 0U),
                                   make(network_operation::accept, 4242U)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto find = [&](const std::string_view type) {
        const auto found = std::find_if(lines.begin(), lines.end(), [&](const std::string& line) {
            return contains(line, std::string{"\"type\":\""} + std::string{type} + "\"");
        });
        require(found != lines.end(), std::string{"record present: "} + std::string{type});
        return *found;
    };
    const auto connect = find("network.connect");
    require(contains(connect, "\"name\":\"curl\"") && contains(connect, "\"entity_id\":\""), "owner resolved from the entity graph");
    require(contains(connect, "\"transport\":\"tcp\"") && contains(connect, "\"family\":\"ipv4\"") &&
                contains(connect, "\"direction\":\"outbound\"") && contains(connect, "\"local\":{\"ip\":\"10.0.0.5\",\"port\":51000}") &&
                contains(connect, "\"remote\":{\"ip\":\"93.184.216.34\",\"port\":443}") && contains(connect, "\"tags\":[]") && contains(connect, "\"socket_inode\":12345") &&
                contains(connect, "\"holders\":2"),
            "endpoints, direction, socket and shared holders");
    require(contains(connect, "\"mechanism\":\"CNPROC\""), "the record carries the provider provenance it was given");
    const auto listen = find("network.listen");
    require(contains(listen, "\"direction\":\"listen\"") && !contains(listen, "\"remote\":") &&
                contains(listen, "{\"field\":\"process\",\"reason\":\"process_exited\"}"),
            "a listener has no remote end and an unattributed owner is reported");
    require(!contains(listen, "\"process\":{}") && !contains(listen, "\"process\":{\"pid\""),
            "an owner that was never known leaves the process member out instead of emitting an empty object");
    const auto accept = find("network.accept");
    require(contains(accept, "\"direction\":\"inbound\"") && contains(accept, "{\"field\":\"process\",\"reason\":\"process_exited\"}") &&
                contains(accept, "\"pid\":4242"),
            "an owner that left the graph is named by pid and flagged");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with network records");
    }
}

void test_pipeline_serializes_auth_events() {
    const auto root = fresh_directory("authproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    const auto make = [](const auth_kind kind, const std::string& service, const std::uint32_t pid) {
        raw_auth_event event;
        event.kind = kind;
        event.service = service;
        event.method = service == "sshd" ? "publickey" : "sudo";
        event.user = "vagrant";
        event.pid = pid;
        if (service == "sshd") {
            event.source_address = "203.0.113.9";
            event.source_port = 40000U;
            event.key_type = "ED25519";
            event.key_fingerprint = "SHA256:abc";
            event.invalid_user = kind == auth_kind::login_failure;
        } else {
            event.target_user = "root";
            event.command = "/bin/id";
            event.sanitized = true;
        }
        return record_of(event);
    };
    std::vector<raw_record> script{make(auth_kind::login_success, "sshd", 4242U), make(auth_kind::login_failure, "sshd", 0U),
                                   make(auth_kind::privilege_success, "sudo", 1U)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto find = [&](const std::string_view type) {
        const auto found = std::find_if(lines.begin(), lines.end(), [&](const std::string& line) {
            return contains(line, std::string{"\"type\":\""} + std::string{type} + "\"");
        });
        require(found != lines.end(), std::string{"record present: "} + std::string{type});
        return *found;
    };
    const auto login = find("auth.login");
    require(contains(login, "\"outcome\":\"success\"") && contains(login, "\"service\":\"sshd\"") && contains(login, "\"user\":\"vagrant\"") &&
                contains(login, "\"source\":{\"ip\":\"203.0.113.9\",\"port\":40000}") &&
                contains(login, "\"key\":{\"type\":\"ED25519\",\"fingerprint\":\"SHA256:abc\"}") && contains(login, "\"pid\":4242") &&
                contains(login, "{\"field\":\"process\",\"reason\":\"process_exited\"}"),
            "a login names the user, the source and the key, and says the process is gone");
    const auto failure = find("auth.failure");
    require(contains(failure, "\"outcome\":\"failure\"") && contains(failure, "\"invalid_user\":true") &&
                contains(failure, "{\"field\":\"process\",\"reason\":\"not_supported_by_provider\"}"),
            "a failure without a pid says the provider cannot name the process");
    const auto privilege = find("auth.privilege");
    require(contains(privilege, "\"target_user\":\"root\"") && contains(privilege, "\"command\":\"/bin/id\"") && contains(privilege, "\"sanitized\":true") &&
                contains(privilege, "\"name\":\"systemd\""),
            "a privilege event carries the target user and command, and the actor when it is known");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with auth records");
    }
}

void test_pipeline_serializes_kernel_events() {
    const auto root = fresh_directory("kernproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    raw_kernel_event load;
    load.kind = kernel_event_kind::module_load;
    load.module_name = "evil_mod";
    load.module_size = 16384U;
    load.module_state = "Live";
    raw_kernel_event unload = load;
    unload.kind = kernel_event_kind::module_unload;
    raw_kernel_event mounted;
    mounted.kind = kernel_event_kind::mount_added;
    mounted.mount_id = 40U;
    mounted.device = "8:1";
    mounted.source = "/dev/sdb1";
    mounted.target = "/mnt/\"usb\"\n";
    mounted.fs_type = "vfat";
    mounted.options = {"rw", "nosuid"};
    raw_kernel_event remounted = mounted;
    remounted.kind = kernel_event_kind::mount_remounted;
    raw_kernel_event gone = mounted;
    gone.kind = kernel_event_kind::mount_removed;
    std::vector<raw_record> script{record_of(load), record_of(unload), record_of(mounted), record_of(remounted), record_of(gone)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto find = [&](const std::string_view type) {
        const auto found = std::find_if(lines.begin(), lines.end(), [&](const std::string& line) {
            return contains(line, std::string{"\"type\":\""} + std::string{type} + "\"");
        });
        require(found != lines.end(), std::string{"record present: "} + std::string{type});
        return *found;
    };
    const auto module_load = find("kernel.module_load");
    require(contains(module_load, "\"module\":{\"name\":\"evil_mod\",\"size\":16384,\"state\":\"Live\"}") &&
                contains(module_load, "{\"field\":\"process\",\"reason\":\"not_supported_by_provider\"}") && !contains(module_load, "\"process\":{"),
            "a module load names the module and says there is no process");
    require(contains(find("kernel.module_unload"), "\"name\":\"evil_mod\""), "unload");
    std::size_t changes = 0U;
    for (const auto& line : lines) {
        if (!contains(line, "\"type\":\"mount.changed\"")) continue;
        ++changes;
        require(contains(line, "\\\"usb\\\"\\n") && !contains(line, "\n\""), "a hostile mount path stays escaped inside the record");
    }
    require(changes == 3U, "three mount records");
    const auto mount_line = find("mount.changed");
    require(contains(mount_line, "\"operation\":\"mounted\"") && contains(mount_line, "\"source\":\"/dev/sdb1\"") && contains(mount_line, "\"fstype\":\"vfat\"") &&
                contains(mount_line, "\"options\":[\"rw\",\"nosuid\"]") && contains(mount_line, "\"mount_id\":40"),
            "mount fields");
    require(std::any_of(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"operation\":\"unmounted\""); }), "unmount");
    require(std::any_of(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"operation\":\"remounted\""); }), "remount");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with kernel records");
    }
}

void test_pipeline_reports_integrity_changes() {
    const auto proc = fresh_directory("fimproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(proc);
    fake_process{100U, 1U, "vim", 500U, "/usr/bin/vim", {"vim", "/etc/cron.d/job"}}.write(proc);
    const auto host = fresh_directory("fimhost");
    write_file(host / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    write_file(host / "etc/cron.d/job", "* * * * * root /bin/true\n");
    const auto stored = fresh_directory("fimstate") / "fim.baseline";
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = proc;
    config.host_root = host;
    config.enable_fim = true;
    config.fim_path = stored;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    raw_file_event event;
    event.pid = 100U;
    event.operation = file_operation::modify;
    event.path = "/etc/cron.d/job";
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(std::vector<raw_record>{record_of(event)}, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        write_file(host / "etc/cron.d/job", "* * * * * root /tmp/payload\n");  // the change the file event reports
        value_of(pipeline.step(clock_domain::now_monotonic_ns() + 3000000000ULL, std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto find = [&](const std::string_view type) {
        const auto found = std::find_if(lines.begin(), lines.end(), [&](const std::string& line) {
            return contains(line, std::string{"\"type\":\""} + std::string{type} + "\"");
        });
        require(found != lines.end(), std::string{"record present: "} + std::string{type});
        return *found;
    };
    const auto baseline = find("fim.baseline");
    require(contains(baseline, "\"state\":\"created\"") && contains(baseline, "\"changes\":0"), "first start creates the baseline");
    const auto changed = find("fim.changed");
    require(contains(changed, "\"path\":\"/etc/cron.d/job\"") && contains(changed, "\"change\":\"modified\"") &&
                contains(changed, "\"fields\":[\"content\"]") && contains(changed, "\"before\":{") && contains(changed, "\"after\":{"),
            "change names the path, the field and both states");
    require(contains(changed, "\"name\":\"vim\"") && contains(changed, "\"mechanism\":\"FSSCAN+FANOTIFY\""), "actor attached from the file event");
    require(std::filesystem::exists(stored), "baseline persisted");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with fim records");
    }
}

void test_pipeline_hashes_executed_images() {
    const auto proc = fresh_directory("hashproc");
    const auto data = fresh_directory("hashdata");
    write_file(data / "tool", "abc");
    const auto exe = (data / "tool").string();
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(proc);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(proc);
    fake_process{200U, 100U, "tool", 900U, exe, {"tool"}}.write(proc);
    fake_process{300U, 100U, "tool", 950U, exe, {"tool"}}.write(proc);
    // Two executions of the same image: the second one is answered from the cache once the first has finished.
    std::vector<raw_record> first{record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}),
                                  record_of(raw_exec{200U, 200U, std::nullopt, std::nullopt, std::nullopt})};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = proc;
    config.enable_hashing = true;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    auto script = std::make_unique<scripted_provider>(first);
    auto* feeder = script.get();
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::move(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        const auto deadline = clock_domain::now_monotonic_ns() + 5000000000ULL;
        std::size_t seen = 0U;
        while (clock_domain::now_monotonic_ns() < deadline && seen == 0U) {
            value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{20}), "step");
            std::fflush(stream);
            for (const auto& line : lines_of(stream)) {
                if (contains(line, "\"type\":\"hash.computed\"")) ++seen;
            }
            std::fseek(stream, 0, SEEK_END);
        }
        require(seen == 1U, "the pending hash is reported");
        feeder->push({record_of(raw_fork{100U, 100U, 300U, 300U, std::nullopt}), record_of(raw_exec{300U, 300U, std::nullopt, std::nullopt, std::nullopt})});
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{50}), "second exec");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::string> execs;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"process.exec\"")) execs.push_back(line);
    }
    require(execs.size() == 2U, "two exec records");
    require(contains(execs[0], "\"hash\":{\"status\":\"pending\"}"), "first exec: hash pending");
    const auto computed = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"type\":\"hash.computed\""); });
    require(computed != lines.end() && contains(*computed, "\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"") &&
                contains(*computed, "\"sha1\":\"a9993e364706816aba3e25717850c26c9cd0d89d\"") &&
                contains(*computed, "\"md5\":\"900150983cd24fb0d6963f7d28e17f72\"") &&
                contains(*computed, "\"entity_id\":\"" + compute_entity_id("host-test", "boot-test", 200U, 900U) + "\"") &&
                contains(*computed, "\"exec_gen\":1"),
            "hash.computed joins to the exec by entity and exec_gen");
    require(contains(execs[1], "\"hash\":{\"status\":\"computed\",\"sha256\":\"ba7816bf") , "second exec: cache hit is inline");
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with hash records");
    }
}

void test_pipeline_reports_delivery_and_turns_rejections_into_loss() {
    const auto proc = fresh_directory("deliveryproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(proc);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = proc;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(std::vector<raw_record>{}, 0U));
    std::uint64_t quarantined = 0U;
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        pipeline.set_delivery_probe([&quarantined] {
            delivery_health health;
            health.state = quarantined == 0U ? "idle" : "rejected";
            health.acknowledged_seq = 40U;
            health.retries = 2U;
            health.records_quarantined = quarantined;
            if (quarantined > 0U) {
                health.recent_quarantined_seqs = {68U};
                health.last_error = "quarantined: schema_invalid";
            }
            return health;
        });
        value_of(pipeline.start(), "pipeline start");
        quarantined = 1U;
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "second step does not repeat the loss");
        require(pipeline.health_now().status == "degraded", "a rejected record makes the sensor degraded");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    const auto health = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, R"("type":"health")"); });
    require(health != lines.end(), "health record emitted");
    require(contains(*health, R"("delivery":{"state":"idle","acknowledged_seq":40,)") && contains(*health, R"("wal":{"next_seq":)") &&
                contains(*health, R"("totals":{"records":)") && contains(*health, R"("tier":"primary")"),
            "health carries delivery, WAL and totals and provider tier: " + *health);
    const auto losses = std::count_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, R"("stage":"manager_rejected")"); });
    require(losses == 1, "the rejection is reported once as a loss record");
    const auto loss = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, R"("stage":"manager_rejected")"); });
    require(contains(*loss, R"("count":1)") && contains(*loss, "sequence numbers 68") && contains(*loss, "schema_invalid"), "loss names the sequence and the reason");
}

// A sink that refuses records while `refuse` is set, as a full disk does.
class refusing_sink final : public record_sink {
public:
    explicit refusing_sink(std::FILE* stream) : inner_{stream} {}
    [[nodiscard]] std::uint64_t next_seq() const override { return inner_.next_seq(); }
    [[nodiscard]] result<bool> append(const std::uint64_t seq, const std::string_view record) override {
        if (refuse) return error{error_code::io_failure, "no space left on device"};
        return inner_.append(seq, record);
    }
    [[nodiscard]] result<bool> flush(const std::uint64_t now_ns, const bool force) override { return inner_.flush(now_ns, force); }
    bool refuse{false};

private:
    stream_sink inner_;
};

void test_pipeline_reports_records_the_sink_refused() {
    const auto root = fresh_directory("refuseproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "bash", 500U, "/usr/bin/bash", {"-bash"}}.write(root);
    fake_process{200U, 100U, "curl", 900U, "/usr/bin/curl", {"curl"}}.write(root);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    refusing_sink sink{stream};
    auto script = std::make_unique<scripted_provider>(std::vector<raw_record>{}, 7U);
    auto* handle = script.get();
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::move(script));
    std::uint64_t unwritten = 0U;
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        const auto before = pipeline.metrics().records;
        sink.refuse = true;
        handle->push({record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}), record_of(raw_exec{200U, 200U, std::nullopt, std::nullopt, std::nullopt}),
                      record_of(raw_exit{200U, 200U, 0U, 17U})});
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        unwritten = pipeline.metrics().records_unwritten;
        require(unwritten >= 3U, "every refused data record is counted");
        require(pipeline.metrics().records == before, "nothing was written while the sink refused");
        sink.refuse = false;
        // The retry is rate limited to one a second while the sink is failing; let a second pass.
        const auto later = clock_domain::now_monotonic_ns() + 2'000'000'000ULL;
        for (int i = 0; i < 3; ++i) (void)pipeline.step(later, std::chrono::milliseconds{0});
        require(pipeline.metrics().records_unwritten == unwritten, "reporting the loss does not count as another loss");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "refused records do not use up sequence numbers");
    }
    const auto governor = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, R"("stage":"governor")"); });
    require(governor != lines.end() && contains(*governor, R"("count":7)"), "a loss whose own record was refused is written once the sink recovers");
    // The refused records may be reported in more than one loss record (one more can be refused
    // after the first report is attempted); what matters is that every one is counted exactly once.
    std::uint64_t reported = 0U;
    bool cause_named = false;
    for (const auto& line : lines) {
        const auto at = line.find(R"("by_type":{"write_failed":)");
        if (at == std::string::npos) continue;
        require(contains(line, R"("stage":"wal")"), "refused records are reported as a wal loss");
        reported += std::stoull(line.substr(at + std::string{R"("by_type":{"write_failed":)"}.size()));
        cause_named = cause_named || contains(line, "no space left on device");
    }
    require(reported == unwritten, "the refused records are reported exactly once in total: " + std::to_string(reported) + " of " + std::to_string(unwritten));
    require(cause_named, "the cause is named");
}

// A burst that fills the in-memory queue used to vanish without a trace: the queue counted what it refused and nothing
// ever read the count (found by comparing a network provider's event count with the records in the WAL under a
// loopback connection storm). The loss must be written, with the exact count, and the stream must stay gap free.
void test_pipeline_reports_records_the_queue_refused() {
    const auto root = fresh_directory("queueloss");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    config.queue_capacity = 8U;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    auto script = std::make_unique<scripted_provider>(std::vector<raw_record>{});
    auto* handle = script.get();
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::move(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        std::vector<raw_record> burst;
        for (std::uint32_t pid = 100U; pid < 120U; ++pid) burst.push_back(record_of(raw_fork{1U, 1U, pid, pid, std::nullopt}));
        handle->push(std::move(burst));
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        const auto reconciles = pipeline.metrics().reconciles;
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        require(pipeline.metrics().reconciles == reconciles, "the loss is reported once, not on every step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "a queue loss does not leave a gap in the sequence numbers");
    }
    std::size_t loss_records = 0U;
    for (const auto& line : lines) {
        if (!contains(line, R"("stage":"queue")")) continue;
        ++loss_records;
        require(contains(line, R"("count":12)"), "the loss carries the exact number of refused records (20 pushed, 8 fit)");
    }
    require(loss_records == 1U, "exactly one queue loss record is written: " + std::to_string(loss_records));
}

// Inputs a provider read and refused (an oversize log line) are reported as a `refused` loss with the exact count, once.
void test_pipeline_reports_inputs_a_provider_refused() {
    const auto root = fresh_directory("refusedloss");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    auto script = std::make_unique<scripted_provider>(std::vector<raw_record>{});
    auto* handle = script.get();
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::move(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        handle->refuse(3U);
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::size_t reports = 0U;
    for (const auto& line : lines) {
        if (!contains(line, R"("stage":"refused")")) continue;
        ++reports;
        require(contains(line, R"("count":3)") && contains(line, "scripted"), "the loss names the provider and carries the exact count");
    }
    require(reports == 1U, "exactly one refused loss record is written: " + std::to_string(reports));
}

// An unclean end of the sensor (kill, crash, power loss) is reported by the next start as a `sensor_gap` loss; a clean
// stop and a first start report nothing.
void test_pipeline_reports_an_unclean_previous_instance() {
    const auto root = fresh_directory("instancegap");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    const auto marker = fresh_directory("instancegap-state") / "instance";
    auto run_instance = [&](const std::string& boot_id, const std::function<void()>& while_running) {
        sensor_config config;
        config.sensor_id = "sensor-test";
        config.host_id = "host-test";
        config.proc_root = root;
        config.instance_state_path = marker;
        clock_domain clock;
        std::FILE* stream = std::tmpfile();
        stream_sink sink{stream};
        std::vector<std::unique_ptr<provider>> providers;
        providers.push_back(std::make_unique<scripted_provider>(std::vector<raw_record>{}, 0U));
        {
            sensor_pipeline pipeline{config, {"host-test", boot_id, "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
            value_of(pipeline.start(), "pipeline start");
            while_running();
        }
        const auto lines = lines_of(stream);
        std::fclose(stream);
        std::vector<std::string> gaps;
        for (const auto& line : lines) {
            if (contains(line, R"("stage":"sensor_gap")")) gaps.push_back(line);
        }
        return gaps;
    };
    auto marker_text = [&] { std::ifstream in{marker}; return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}}; };

    require(run_instance("boot-a", [&] { require(contains(marker_text(), "clean=0"), "a running sensor's marker says it is not finished"); }).empty(),
            "a first start has no previous instance to report");
    require(contains(marker_text(), "clean=1"), "a clean shutdown marks the marker clean");
    require(run_instance("boot-a", [] {}).empty(), "a clean stop is not reported as a gap");

    // The previous process died: its marker still says it was running, last seen 30 s ago, on another boot.
    const auto last_alive = clock_domain::now_unix_ns() - 30ULL * 1'000'000'000ULL;
    { std::ofstream out{marker, std::ios::trunc};
      out << "panopticon-instance 1\nboot_id=boot-before\nstarted_unix_ns=1\nalive_unix_ns=" << last_alive << "\nclean=0\n"; }
    const auto killed = run_instance("boot-a", [] {});
    require(killed.size() == 1U, "exactly one gap is reported after an unclean end: " + std::to_string(killed.size()));
    require(contains(killed[0], R"("count":1)") && contains(killed[0], "did not shut down cleanly") && contains(killed[0], "rebooted"),
            "the gap says what happened and that the host rebooted: " + killed[0]);
    require(contains(killed[0], "up to 3"), "the gap says how long the blind interval was (about 30 s): " + killed[0]);
    require(run_instance("boot-a", [] {}).empty(), "the gap is reported once, not on every later start");

    { std::ofstream out{marker, std::ios::trunc}; out << "garbage"; }
    const auto unreadable = run_instance("boot-a", [] {});
    require(unreadable.size() == 1U && contains(unreadable[0], "length of the gap is unknown"), "an unreadable marker is a gap of unknown length, not silence");
}

// The configuration decides what the sensor trusts, and the CA bundle decides who may speak as the Manager: a copy that
// another user can write, or can replace by writing to its directory, is refused at load.
void test_config_and_ca_must_be_trustworthy() {
    const auto dir = fresh_directory("trustedconfig");
    const auto config_path = dir / "sensor.conf";
    const auto ca_path = dir / "ca.pem";
    const auto set_mode = [](const fs::path& path, const fs::perms perms) { fs::permissions(path, perms, fs::perm_options::replace); };
    const auto owner_only = fs::perms::owner_read | fs::perms::owner_write;
    write_file(config_path, "sensor_id=s-1\nhost_id=h-1\n");
    set_mode(config_path, owner_only | fs::perms::group_read | fs::perms::others_read);
    require(succeeded(load_sensor_config(config_path)), "a config only its owner can write loads");

    set_mode(config_path, owner_only | fs::perms::group_write);
    const auto group_writable = load_sensor_config(config_path);
    require(!succeeded(group_writable) && contains(std::get<error>(group_writable).message, "writable by group or others"), "a group-writable config is refused");
    set_mode(config_path, owner_only | fs::perms::others_write);
    require(!succeeded(load_sensor_config(config_path)), "a world-writable config is refused");
    set_mode(config_path, owner_only);

    set_mode(dir, fs::perms::all);
    const auto open_directory = load_sensor_config(config_path);
    require(!succeeded(open_directory) && contains(std::get<error>(open_directory).message, "directory"), "a config in a directory others can write into is refused");
    set_mode(dir, fs::perms::owner_all);
    require(succeeded(load_sensor_config(config_path)), "the same config loads once the directory is closed");

    write_file(config_path, "sensor_id=s-1\nhost_id=h-1\nca_bundle=" + ca_path.string() + "\n");
    set_mode(config_path, owner_only);
    const auto missing_ca = load_sensor_config(config_path);
    require(!succeeded(missing_ca) && contains(std::get<error>(missing_ca).message, "ca_bundle"), "a CA bundle that cannot be read is refused");
    write_file(ca_path, "not a real certificate\n");
    set_mode(ca_path, owner_only | fs::perms::others_read);
    require(succeeded(load_sensor_config(config_path)), "a CA bundle only its owner can write is accepted");
    set_mode(ca_path, owner_only | fs::perms::group_write);
    const auto writable_ca = load_sensor_config(config_path);
    require(!succeeded(writable_ca) && contains(std::get<error>(writable_ca).message, "ca_bundle is not trustworthy"), "a CA bundle another user can write is refused");

    if (::geteuid() == 0) {
        set_mode(ca_path, owner_only);
        require(::chown(ca_path.c_str(), 12345, static_cast<gid_t>(-1)) == 0, "chown to another user");
        require(!succeeded(load_sensor_config(config_path)), "a CA bundle owned by another user is refused");
    }
    set_mode(dir, fs::perms::all);
}

// A Type=notify unit: READY and STOPPING are sent, the watchdog is fed at half its period and only by whoever calls
// pet_if_due (the pipeline loop), and a sensor started by hand sends nothing.
void test_systemd_notifier_protocol() {
    const auto dir = fresh_directory("notify");
    const auto socket_path = (dir / "notify.sock").string();
    const int server = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(server >= 0, "create the notify socket");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socket_path.c_str(), socket_path.size());
    require(::bind(server, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "bind the notify socket");
    const auto received = [&] {
        std::vector<std::string> messages;
        char buffer[256];
        for (;;) {
            const auto count = ::recv(server, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (count <= 0) break;
            messages.emplace_back(buffer, static_cast<std::size_t>(count));
        }
        return messages;
    };

    systemd_notifier notifier{socket_path, 2'000'000U};  // WatchdogSec=2: a pet at least every second
    require(notifier.active() && notifier.watchdog_interval_ns() == 1'000'000'000ULL, "the watchdog interval is half the period");
    require(notifier.ready() && notifier.status("collecting"), "ready and status are sent");
    const auto first = received();
    require(first.size() == 2U && first[0] == "READY=1" && first[1] == "STATUS=collecting", "the messages arrive as written");

    constexpr std::uint64_t second = 1'000'000'000ULL;
    require(notifier.pet_if_due(10U * second), "the first pet is sent at once");
    require(!notifier.pet_if_due(10U * second + second / 2U), "no second pet inside the interval");
    require(notifier.pet_if_due(11U * second), "a pet is sent when the interval has passed");
    const auto pets = received();
    require(pets.size() == 2U && pets[0] == "WATCHDOG=1" && pets[1] == "WATCHDOG=1", "exactly the two pets were sent");
    require(notifier.stopping(), "stopping is sent");
    require(received() == std::vector<std::string>{"STOPPING=1"}, "the stop notice arrives");

    systemd_notifier no_watchdog{socket_path, 0U};
    require(no_watchdog.ready() && !no_watchdog.pet_if_due(99U * second), "without a watchdog period nothing is petted");
    require(received() == std::vector<std::string>{"READY=1"}, "only READY went out");

    systemd_notifier by_hand{"", 2'000'000U};
    require(!by_hand.active() && !by_hand.ready() && !by_hand.pet_if_due(5U * second) && !by_hand.stopping(), "a sensor started by hand sends nothing");
    systemd_notifier gone{(dir / "nobody-listens.sock").string(), 2'000'000U};
    require(!gone.ready() && !gone.pet_if_due(5U * second), "a missing notify socket fails quietly");
    ::close(server);
}

void test_pipeline_rebases_event_times_after_a_clock_step() {
    const auto root = fresh_directory("clockstepproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    require(std::llabs(clock.boot_offset_drift_ns()) < 50'000'000LL, "no drift right after sampling");
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(std::vector<raw_record>{}, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        require(pipeline.metrics().clock_steps == 0U, "a steady clock is not a step");
        clock.shift_offsets_for_test(3'000'000'000LL);  // as if the wall clock had been stepped forward 3 s since sampling
        require(clock.boot_offset_drift_ns() > 2'500'000'000LL, "the step is visible as drift");
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        require(pipeline.metrics().clock_steps == 1U, "the step is detected");
        require(std::llabs(clock.boot_offset_drift_ns()) < 50'000'000LL, "offsets were re-sampled at once");
        (void)pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0});
        require(pipeline.metrics().clock_steps == 1U, "one step is counted once");
    }
    std::fclose(stream);
}

void test_pipeline_emits_host_state_parts() {
    const auto proc = fresh_directory("hostproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(proc);
    const auto host = fresh_directory("hostroot");
    write_file(host / "proc/sys/kernel/hostname", "fakehost\n");
    std::string passwd;
    for (int i = 0; i < 300; ++i) passwd += "user" + std::to_string(i) + ":x:" + std::to_string(2000 + i) + ":100::/home/u:/bin/sh\n";
    write_file(host / "etc/passwd", passwd);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = proc;
    config.host_root = host;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, {}};
        value_of(pipeline.start(), "pipeline start");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        require(contains(lines[index], "\"seq\":" + std::to_string(index + 1U) + ","), "seq stays contiguous with state records");
    }
    const auto count = [&](const std::string_view needle) {
        return std::count_if(lines.begin(), lines.end(), [&](const std::string& line) { return contains(line, needle); });
    };
    for (const char* object : {"host", "posture", "users", "groups", "interfaces", "mounts", "modules"}) {
        require(count(std::string{"\"type\":\"state."} + object + "\"") >= 1, std::string{"state."} + object + " emitted");
    }
    // 300 accounts at 100 items per part is three parts; unavailable[] rides on part 1 only.
    require(count("\"type\":\"state.users\"") == 3, "users snapshot split into three parts");
    const auto first = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"type\":\"state.users\""); });
    require(first != lines.end() && contains(*first, "\"part\":1,\"parts\":3") && contains(*first, "\"provider\":\"inventory\"") &&
                contains(*first, "\"object\":\"users\"") && contains(*first, "\"name\":\"user0\""),
            "first users part: " + *first);
    const auto host_line = std::find_if(lines.begin(), lines.end(), [](const std::string& line) { return contains(line, "\"type\":\"state.host\""); });
    require(host_line != lines.end() && contains(*host_line, "\"hostname\":\"fakehost\""), "host state reads the fake root");
    require(contains(*host_line, "\"unavailable\":[{\"field\":"), "unreadable fields are listed with reasons");
}

// A provider that belongs to a family and can be told to fail, for the fallback chain.
class family_provider final : public provider {
public:
    family_provider(std::string name, std::string probe_failure)
        : name_{std::move(name)}, probe_failure_{std::move(probe_failure)} {}
    std::string_view name() const noexcept override { return name_; }
    std::string_view family() const noexcept override { return "process"; }
    std::vector<std::string> capabilities() const override { return {"process.fork", "process.exec", "process.exit"}; }
    std::string probe() override { return probe_failure_; }
    result<bool> start(record_queue&) override {
        active_ = true;
        started = true;
        return true;
    }
    void stop() override { active_ = false; }
    provider_health health() const override {
        return {name_, active_ ? "active" : "unavailable", active_ ? "" : probe_failure_, capabilities(), 0U, 0U};
    }
    std::uint64_t take_losses() override { return 0U; }
    bool started{false};

private:
    std::string name_;
    std::string probe_failure_;
    bool active_{false};
};

health_snapshot health_of_family(const std::string& first_failure, bool& first_started, bool& second_started) {
    const auto root = fresh_directory("familyproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    auto first = std::make_unique<family_provider>("preferred", first_failure);
    auto second = std::make_unique<family_provider>("fallback", "");
    const auto* first_ptr = first.get();
    const auto* second_ptr = second.get();
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::move(first));
    providers.push_back(std::move(second));
    sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
    value_of(pipeline.start(), "pipeline start");
    first_started = first_ptr->started;
    second_started = second_ptr->started;
    auto snapshot = pipeline.health_now();
    pipeline.shutdown();
    std::fclose(stream);
    return snapshot;
}

void test_provider_family_prefers_first_and_falls_back() {
    bool first_started = false;
    bool second_started = false;
    auto healthy = health_of_family("", first_started, second_started);
    require(first_started && !second_started, "only the preferred provider of a family starts");
    const auto standby = std::find_if(healthy.providers.begin(), healthy.providers.end(), [](const provider_health& h) { return h.name == "fallback"; });
    require(standby != healthy.providers.end() && standby->state == "standby" && contains(standby->reason, "preferred"),
            "the other provider is reported as standby, naming who superseded it");
    require(healthy.status == "healthy", "standby is not degradation");
    require(healthy.coverage["process.exec"] == "preferred", "coverage names the serving provider");

    auto degraded = health_of_family("kernel_feature_missing: test", first_started, second_started);
    require(!first_started && second_started, "an unavailable preferred provider hands over to the fallback");
    const auto failed = std::find_if(degraded.providers.begin(), degraded.providers.end(), [](const provider_health& h) { return h.name == "preferred"; });
    require(failed != degraded.providers.end() && failed->state == "unavailable" && contains(failed->reason, "kernel_feature_missing"),
            "the failure reason reaches health");
    require(degraded.status == "degraded", "running on the fallback is degraded, not healthy");
    require(degraded.coverage["process.exec"] == "fallback", "coverage follows the fallback");
}

void test_sensor_config_is_strict() {
    const auto& config = value_of(parse_sensor_config("sensor_id = s-1\nhost_id=h-1\n# comment\nqueue_capacity=4096\n"), "valid config");
    require(config.queue_capacity == 4096U && config.wal_path == "/var/lib/panopticon/wal", "values and defaults");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nbogus=1\n")), "unknown key rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nqueue_capacity=1\n")), "out of range rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nsensor_id=t\nhost_id=h\n")), "duplicate rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nwal_path=relative\n")), "relative path rejected");
    require(!value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_ebpf=false\n"), "ebpf off").enable_ebpf, "enable_ebpf=false");
    require(value_of(parse_sensor_config("sensor_id=s\nhost_id=h\n"), "defaults").enable_ebpf, "eBPF is on by default");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_ebpf=maybe\n")), "non-boolean enable_ebpf rejected");
    const auto& files = value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_file_events=false\nfile_include=/etc, /opt/app\nfile_exclude=/etc/ssl\n"), "file keys");
    require(!files.enable_file_events && files.file_include == std::vector<std::string>{"/etc", "/opt/app"} && files.file_exclude == std::vector<std::string>{"/etc/ssl"}, "file telemetry keys parse");
    require(value_of(parse_sensor_config("sensor_id=s\nhost_id=h\n"), "defaults").enable_file_events, "file telemetry is on by default");
    require(value_of(parse_sensor_config("sensor_id=s\nhost_id=h\n"), "defaults").enable_network_events, "network telemetry is on by default");
    require(!value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_network_events=false\n"), "network off").enable_network_events,
            "network telemetry can be disabled");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_network_events=maybe\n")), "non-boolean enable_network_events rejected");
    require(value_of(parse_sensor_config("sensor_id=s\nhost_id=h\n"), "defaults").enable_auth_events, "authentication telemetry is on by default");
    require(!value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_auth_events=false\n"), "auth off").enable_auth_events,
            "authentication telemetry can be disabled");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_auth_events=maybe\n")), "non-boolean enable_auth_events rejected");
    require(value_of(parse_sensor_config("sensor_id=s\nhost_id=h\n"), "defaults").enable_kernel_events, "kernel change telemetry is on by default");
    require(!value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_kernel_events=false\n"), "kernel off").enable_kernel_events,
            "kernel change telemetry can be disabled");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_kernel_events=maybe\n")), "non-boolean enable_kernel_events rejected");
    const auto& integrity = value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nwal_path=/data/wal\n"), "fim defaults");
    require(integrity.enable_fim && integrity.fim_path == "/data/fim.baseline" && integrity.fim_interval_seconds == 300U, "FIM is on by default, next to the WAL");
    const auto& tuned = value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_fim=false\nfim_path=/x/b\nfim_interval_seconds=60\n"), "fim keys");
    require(!tuned.enable_fim && tuned.fim_path == "/x/b" && tuned.fim_interval_seconds == 60U, "FIM keys parse");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nfim_interval_seconds=59\n")), "FIM interval lower bound");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nfim_path=relative\n")), "relative FIM path rejected");
    const auto& hashing = value_of(parse_sensor_config("sensor_id=s\nhost_id=h\n"), "hash defaults");
    require(hashing.enable_hashing && hashing.hash_max_file_bytes == 256ULL * 1024U * 1024U && hashing.hash_bytes_per_second == 64ULL * 1024U * 1024U,
            "hashing is on by default with a size and rate budget");
    const auto& hash_tuned = value_of(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_hashing=false\nhash_max_file_bytes=1048576\nhash_bytes_per_second=2097152\n"), "hash keys");
    require(!hash_tuned.enable_hashing && hash_tuned.hash_max_file_bytes == 1048576U && hash_tuned.hash_bytes_per_second == 2097152U, "hash keys parse");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nhash_max_file_bytes=1\n")), "hash size lower bound");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_hashing=2\n")), "non-boolean enable_hashing rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nenable_fim=maybe\n")), "non-boolean enable_fim rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nfile_include=relative\n")), "relative file prefix rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nfile_exclude=/etc/../root\n")), "parent traversal in a file prefix rejected");
}

void test_record_queue_counts_drops_and_keeps_order() {
    record_queue queue{2U};
    require(queue.push(record_of(raw_exit{1U, 1U, 0U, 0U})) && queue.push(record_of(raw_exit{2U, 2U, 0U, 0U})), "fill");
    require(!queue.push(record_of(raw_exit{3U, 3U, 0U, 0U})), "full queue drops");
    std::vector<raw_record> out;
    require(queue.pop_batch(out, 10U, std::chrono::milliseconds{0}) == 2U, "pop all");
    require(std::get<raw_exit>(out[0].payload).tgid == 1U && std::get<raw_exit>(out[1].payload).tgid == 2U, "FIFO order");
    require(queue.take_dropped() == 1U && queue.take_dropped() == 0U, "drop counter");
}

void run(const char* name, void (*test)()) {
    try {
        test();
        std::cout << "PASS " << name << '\n';
    } catch (const std::exception& failure) {
        ++failures;
        std::cout << "FAIL " << name << ": " << failure.what() << '\n';
    }
}

}  // namespace

std::vector<std::uint8_t> dns_bytes(const std::vector<std::string>& labels, const std::uint16_t type = 1U, const std::uint16_t flags = 0x0100U,
                                    const std::uint16_t questions = 1U) {
    std::vector<std::uint8_t> out{0x12, 0x34, static_cast<std::uint8_t>(flags >> 8U), static_cast<std::uint8_t>(flags & 0xffU),
                                  static_cast<std::uint8_t>(questions >> 8U), static_cast<std::uint8_t>(questions & 0xffU), 0, 0, 0, 0, 0, 0};
    for (const auto& label : labels) {
        out.push_back(static_cast<std::uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
    out.push_back(static_cast<std::uint8_t>(type >> 8U));
    out.push_back(static_cast<std::uint8_t>(type & 0xffU));
    out.push_back(0);
    out.push_back(1);
    return out;
}

void test_parse_dns_query() {
    auto found = parse_dns_query(dns_bytes({"www", "Example", "com"}, 28U));
    require(found.has_value() && found->name == "www.Example.com" && found->type == 28U && found->klass == 1U && found->transaction_id == 0x1234U &&
                found->recursion_desired && found->opcode == 0U,
            "an ordinary query, case preserved");
    require(dns_type_name(28U) == "AAAA" && dns_type_name(16U) == "TXT" && dns_type_name(65U) == "HTTPS" && dns_type_name(9999U) == "TYPE9999" &&
                dns_class_name(1U) == "IN" && dns_class_name(3U) == "CH" && dns_class_name(77U) == "CLASS77",
            "type and class names");
    found = parse_dns_query(dns_bytes({}, 2U));
    require(found.has_value() && found->name == ".", "the root name");
    found = parse_dns_query(dns_bytes({std::string{"a.b"}, "c"}));
    require(found.has_value() && found->name == "a\\.b.c", "a dot inside a label is escaped, so it cannot look like a separator");
    found = parse_dns_query(dns_bytes({std::string{"x\0y", 3U}, "\x80z"}));
    require(found.has_value() && found->name == "x\\000y.\\128z", "bytes outside printable ASCII are written as \\DDD");
    found = parse_dns_query(dns_bytes({"a\\b"}));
    require(found.has_value() && found->name == "a\\\\b", "a backslash is escaped");
    found = parse_dns_query(dns_bytes({std::string(63U, 'a')}));
    require(found.has_value() && found->name.size() == 63U, "a 63-byte label is the longest allowed");
    found = parse_dns_query(dns_bytes({"example", "com"}, 1U, 0x2800U));
    require(found.has_value() && found->opcode == 5U && !found->recursion_desired, "opcode and recursion-desired are read from the flags");

    require(!parse_dns_query(dns_bytes({"example", "com"}, 1U, 0x8180U)), "a response is not a query");
    require(!parse_dns_query(dns_bytes({"example", "com"}, 1U, 0x0100U, 2U)), "two questions are not accepted");
    require(!parse_dns_query(dns_bytes({"example", "com"}, 1U, 0x0100U, 0U)), "no question is not accepted");
    require(!parse_dns_query(dns_bytes({std::string(64U, 'a')})), "a label over 63 bytes");
    auto long_name = std::vector<std::string>(5U, std::string(60U, 'b'));
    require(!parse_dns_query(dns_bytes(long_name)), "a name over 255 bytes");
    auto pointer = dns_bytes({"example", "com"});
    pointer[12] = 0xc0U;
    require(!parse_dns_query(pointer), "a compression pointer is not valid in a question");
    auto extended = dns_bytes({"example", "com"});
    extended[12] = 0x40U;
    require(!parse_dns_query(extended), "an extended label type");
    auto truncated = dns_bytes({"example", "com"});
    truncated.resize(truncated.size() - 1U);
    require(!parse_dns_query(truncated), "a message that ends inside the type and class");
    truncated.resize(15U);
    require(!parse_dns_query(truncated), "a message that ends inside a label");
    require(!parse_dns_query({}), "an empty message");

    std::uint32_t state = 0x9e3779b9U;
    const auto next = [&state]() {
        state = state * 1664525U + 1013904223U;
        return state;
    };
    for (int round = 0; round < 20000; ++round) {
        std::vector<std::uint8_t> noise(next() % 400U);
        for (auto& byte : noise) byte = static_cast<std::uint8_t>(next() >> 24U);
        if (noise.size() > 6U) {
            noise[2] &= 0x7fU;
            noise[4] = 0;
            noise[5] = 1;
        }
        if (const auto parsed = parse_dns_query(noise); parsed.has_value()) require(parsed->name.size() <= 4U * 255U, "a parsed name stays bounded");
    }
}

void test_pipeline_emits_dns_queries() {
    const auto root = fresh_directory("dnsproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "curl", 500U, "/usr/bin/curl", {"curl", "https://example.com"}}.write(root);
    const auto make = [](const std::uint32_t pid) {
        raw_dns_query query;
        query.pid = pid;
        query.family = "inet";
        query.local_address = "10.0.0.5";
        query.local_port = 40000U;
        query.server_address = "10.0.2.3";
        query.server_port = 53U;
        query.transaction_id = 4660U;
        query.recursion_desired = true;
        query.name = "evil.example";
        query.type = "TXT";
        query.klass = "IN";
        return record_of(query);
    };
    std::vector<raw_record> script{make(100U), make(4242U)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::string> queries;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"dns.query\"")) queries.push_back(line);
    }
    require(queries.size() == 2U, "both queries were emitted");
    require(contains(queries[0], "\"name\":\"curl\"") && contains(queries[0], "\"entity_id\":\""), "asker resolved from the entity graph");
    require(contains(queries[0], "\"dns\":{\"name\":\"evil.example\",\"type\":\"TXT\",\"class\":\"IN\",\"transaction_id\":4660,\"recursion_desired\":true,"
                                 "\"transport\":\"udp\",\"family\":\"ipv4\",\"server\":{\"ip\":\"10.0.2.3\",\"port\":53},\"local\":{\"ip\":\"10.0.0.5\",\"port\":40000}}"),
            "the dns body");
    require(contains(queries[1], "{\"field\":\"process\",\"reason\":\"process_exited\"}") && contains(queries[1], "\"pid\":4242"), "an unknown asker is reported, not invented");
}

void test_pipeline_emits_response_evidence_first() {
    const auto root = fresh_directory("respproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    auto evidence = std::make_shared<response_evidence>();
    evidence->object = "connections";
    evidence->snapshot_id = "response-n1";
    evidence->mechanism = "SOCKDIAG+PROCFS";
    for (int index = 0; index < 150; ++index) evidence->items.push_back("{\"local_port\":" + std::to_string(index) + "}");
    evidence->unavailable.push_back({"connections.pid", unavailable_reason::budget_exceeded});
    raw_response_action response;
    response.command_id = "n1";
    response.correlation_id = "corr-n1";
    response.action = "COLLECT_NETWORK_CONNECTIONS";
    response.outcome = "succeeded";
    response.reason = "ok";
    response.detail = "tcp_listen=150 snapshot=response-n1";
    response.executed = true;
    response.affected = 150U;
    response.evidence = evidence;
    std::vector<raw_record> script{raw_record{1'700'000'000'000'000'000ULL, {"command_channel", "MGR-CMD", confidence::observed}, response}};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::size_t> parts;
    std::size_t action = lines.size();
    for (std::size_t index = 0U; index < lines.size(); ++index) {
        if (contains(lines[index], "\"type\":\"state.connections\"")) parts.push_back(index);
        if (contains(lines[index], "\"type\":\"response.action\"")) action = index;
    }
    require(parts.size() == 2U && action < lines.size(), "two state parts and the audit record");
    require(parts[1] < action, "the evidence is sent before the record that names it");
    require(contains(lines[parts[0]], "\"snapshot_id\":\"response-n1\"") && contains(lines[parts[0]], "\"part\":1") &&
                contains(lines[parts[0]], "\"parts\":2") && contains(lines[parts[1]], "\"part\":2"),
            "one snapshot in two parts");
    require(contains(lines[parts[0]], "\"provider\":\"command_channel\"") && contains(lines[parts[0]], "\"mechanism\":\"SOCKDIAG+PROCFS\"") &&
                contains(lines[parts[0]], "{\"field\":\"connections.pid\",\"reason\":\"budget_exceeded\"}"),
            "provenance and the stated gap: " + lines[parts[0]]);
    require(contains(lines[action], "\"command_id\":\"n1\"") && contains(lines[action], "snapshot=response-n1"), "the record names it");
}

void test_pipeline_emits_lsm_and_firewall_events() {
    const auto root = fresh_directory("lsmproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "cat", 500U, "/usr/bin/cat", {"cat", "/etc/hostname"}}.write(root);
    raw_lsm_event denial;
    denial.module = "apparmor";
    denial.operation = "open";
    denial.outcome = "denied";
    denial.object = "/etc/hostname";
    denial.requested = "r";
    denial.denied = "r";
    denial.profile = "panopticon-aa-test";
    denial.comm = "cat";
    denial.pid = 100U;
    raw_lsm_event policy;
    policy.policy_change = true;
    policy.module = "selinux";
    policy.operation = "enforcing";
    raw_firewall_change firewall;
    firewall.subsystem = "nft";
    firewall.operation = "nft_register_rule";
    firewall.table = "raw";
    firewall.family = "ipv4";
    firewall.entries = 1U;
    firewall.generation = 48U;
    firewall.comm = "iptables";
    firewall.pid = 4242U;
    std::vector<raw_record> script{record_of(denial), record_of(policy), record_of(firewall)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script, 0U));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink, std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::string denial_line;
    std::string policy_line;
    std::string firewall_line;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"lsm.denial\"")) denial_line = line;
        if (contains(line, "\"type\":\"lsm.policy\"")) policy_line = line;
        if (contains(line, "\"type\":\"netfilter.config_change\"")) firewall_line = line;
    }
    require(contains(denial_line, "\"name\":\"cat\"") && contains(denial_line, "\"entity_id\":\""), "the denied process is resolved from the entity graph");
    require(contains(denial_line, "\"lsm\":{\"module\":\"apparmor\",\"operation\":\"open\",\"outcome\":\"denied\",\"object\":\"/etc/hostname\",\"requested\":\"r\","
                                  "\"denied\":\"r\",\"profile\":\"panopticon-aa-test\",\"comm\":\"cat\"}"),
            "the lsm body");
    require(contains(policy_line, "\"lsm\":{\"module\":\"selinux\",\"operation\":\"enforcing\"}") && !contains(policy_line, "\"outcome\"") &&
                contains(policy_line, "{\"field\":\"process\",\"reason\":\"not_supported_by_provider\"}"),
            "a policy change has no outcome and no process");
    require(contains(firewall_line, "\"netfilter\":{\"subsystem\":\"nft\",\"operation\":\"nft_register_rule\",\"table\":\"raw\",\"family\":\"ipv4\",\"entries\":1,"
                                    "\"generation\":48,\"comm\":\"iptables\"}") &&
                contains(firewall_line, "\"pid\":4242") && contains(firewall_line, "{\"field\":\"process\",\"reason\":\"process_exited\"}"),
            "an exited iptables is reported as exited, not invented");
}

const std::string container_a = std::string(64, 'a');
const std::string container_b = std::string(64, 'b');
const std::string container_c = std::string(64, 'c');

entity_ptr tracked_process(const std::string& entity_id, const std::uint32_t pid, const std::string& cgroup) {
    auto entity = std::make_shared<process_entity>();
    entity->entity_id = entity_id;
    entity->info.pid = pid;
    entity->info.cgroup = cgroup;
    entity->first_seen_unix_ns = 1000U;
    return entity;
}

process_event tracked_event(const std::string& type, const entity_ptr& process, const std::uint64_t time) {
    process_event event;
    event.type = type;
    event.process = process;
    event.time_unix_ns = time;
    return event;
}

std::string docker_cgroup(const std::string& id) { return "/system.slice/docker-" + id + ".scope"; }

void test_container_tracker_lifecycle() {
    container_tracker tracker;
    const auto init = tracked_process("p-init", 10U, docker_cgroup(container_a));
    const auto worker = tracked_process("p-worker", 11U, docker_cgroup(container_a));
    const auto host = tracked_process("p-host", 12U, "/system.slice/ssh.service");

    auto changes = tracker.observe({tracked_event("process.fork", host, 100U), tracked_event("process.fork", init, 200U)});
    require(changes.size() == 1U && changes[0].started && changes[0].identity.id == container_a && changes[0].identity.runtime == "docker" &&
                changes[0].process == init && changes[0].time_unix_ns == 200U,
            "the first process in a new container cgroup is the start; a host process is not");
    require(tracker.containers() == 1U && tracker.processes() == 1U, "one container, one process followed");

    changes = tracker.observe({tracked_event("process.exec", init, 210U), tracked_event("process.fork", worker, 300U)});
    require(changes.empty() && tracker.processes() == 2U, "an exec of a known process and a second process join silently");

    changes = tracker.observe({tracked_event("process.exit", worker, 400U), tracked_event("process.exit", host, 410U)});
    require(changes.empty() && tracker.processes() == 1U, "a process leaving while another remains is not a stop, nor is a host process");

    changes = tracker.observe({tracked_event("process.exit", init, 700U)});
    require(changes.size() == 1U && !changes[0].started && changes[0].identity.id == container_a && changes[0].start_observed &&
                changes[0].lifetime_ns == 500U && changes[0].peak_processes == 2U && changes[0].process == init,
            "the last exit is the stop, with lifetime from the observed start and the peak process count");
    require(tracker.containers() == 0U && tracker.processes() == 0U, "nothing is kept for a stopped container");

    changes = tracker.observe({tracked_event("process.exit", init, 800U)});
    require(changes.empty(), "a duplicate exit reports nothing");

    changes = tracker.observe({tracked_event("process.fork", tracked_process("p-again", 20U, docker_cgroup(container_a)), 900U)});
    require(changes.size() == 1U && changes[0].started, "the same id appearing again is a new start");
}

void test_container_tracker_preexisting_and_discovered() {
    container_tracker tracker;
    const auto seeded = tracked_process("p-seeded", 30U, docker_cgroup(container_b));
    tracker.seed({seeded, tracked_process("p-host", 31U, "/")});
    require(tracker.containers() == 1U && tracker.processes() == 1U, "seeding follows container processes only");
    auto changes = tracker.observe({tracked_event("process.fork", tracked_process("p-more", 32U, docker_cgroup(container_b)), 100U)});
    require(changes.empty(), "a process joining a container that predates the sensor is not a start");
    changes = tracker.observe({tracked_event("process.exit", seeded, 200U),
                               tracked_event("process.exit", tracked_process("p-more", 32U, docker_cgroup(container_b)), 300U)});
    require(changes.size() == 1U && !changes[0].started && !changes[0].start_observed && changes[0].lifetime_ns == 0U &&
                changes[0].peak_processes == 2U,
            "its stop says the start was not observed instead of inventing a lifetime");

    const auto late = tracked_process("p-late", 40U, docker_cgroup(container_c));
    changes = tracker.observe({tracked_event("process.discovered", late, 400U)});
    require(changes.empty(), "a process found by reconcile says nothing about when its container started");
    changes = tracker.observe({tracked_event("process.exit", late, 500U)});
    require(changes.size() == 1U && !changes[0].start_observed, "and its container's stop is marked the same way");
}

void test_container_tracker_moves_and_limits() {
    container_tracker tracker;
    const auto mover = tracked_process("p-mover", 50U, docker_cgroup(container_a));
    (void)tracker.observe({tracked_event("process.fork", mover, 100U)});
    const auto moved = tracked_process("p-mover", 50U, docker_cgroup(container_b));
    auto changes = tracker.observe({tracked_event("process.exec", moved, 200U)});
    require(changes.size() == 2U && !changes[0].started && changes[0].identity.id == container_a && changes[1].started &&
                changes[1].identity.id == container_b,
            "a process that moves to another container stops the old one if it was the last and starts the new one");

    container_tracker small{2U, 3U};
    changes = small.observe({tracked_event("process.fork", tracked_process("a1", 1U, docker_cgroup(container_a)), 1U),
                             tracked_event("process.fork", tracked_process("b1", 2U, docker_cgroup(container_b)), 2U),
                             tracked_event("process.fork", tracked_process("c1", 3U, docker_cgroup(container_c)), 3U)});
    require(changes.size() == 2U && small.containers() == 2U && small.untracked() == 1U, "containers past the limit are counted, not followed");
    changes = small.observe({tracked_event("process.fork", tracked_process("a2", 4U, docker_cgroup(container_a)), 4U),
                             tracked_event("process.fork", tracked_process("a3", 5U, docker_cgroup(container_a)), 5U)});
    require(small.processes() == 3U && small.untracked() == 2U, "processes past the limit are counted, not followed");
    changes = small.observe({tracked_event("process.exit", tracked_process("c1", 3U, docker_cgroup(container_c)), 6U)});
    require(changes.empty(), "an untracked container never reports a stop");
}

void test_pipeline_container_events() {
    const auto root = fresh_directory("containerproc");
    fake_process{1U, 0U, "systemd", 1U, "/usr/lib/systemd/systemd", {"/sbin/init"}, 0U}.write(root);
    fake_process{100U, 1U, "containerd-shim", 500U, "/usr/bin/containerd-shim-runc-v2", {"containerd-shim"}}.write(root);
    const auto cgroup = docker_cgroup(container_a);
    constexpr std::uint64_t base = 1'700'000'000'000'000'000ULL;
    // What a container runtime does: the shim forks a process that is still in the host cgroup, the
    // process is moved into the container's cgroup and executes the entrypoint, which forks a worker.
    // The fork copies the shim's cgroup; the exec is where the container is first visible.
    raw_exec entrypoint;
    entrypoint.tgid = 200U;
    entrypoint.pid = 200U;
    std::vector<raw_record> script{record_of(raw_fork{100U, 100U, 200U, 200U, std::nullopt}, base),
                                   record_of(entrypoint, base + 1'000'000ULL),
                                   record_of(raw_fork{200U, 200U, 201U, 201U, std::nullopt}, base + 2'000'000ULL),
                                   record_of(raw_exit{201U, 201U, 0U, 0U}, base + 3'000'000ULL),
                                   record_of(raw_exit{200U, 200U, 0U, 0U}, base + 6'000'000ULL)};
    sensor_config config;
    config.sensor_id = "sensor-test";
    config.host_id = "host-test";
    config.proc_root = root;
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    std::vector<std::unique_ptr<provider>> providers;
    providers.push_back(std::make_unique<scripted_provider>(script));
    {
        sensor_pipeline pipeline{config, {"host-test", "boot-test", "testhost", "sensor-test", "0.1.0", "none"}, clock, sink,
                                 std::move(providers)};
        value_of(pipeline.start(), "pipeline start");
        // The container appears after the sensor began: processes already running at start are followed silently.
        fake_process{200U, 100U, "app", 900U, "/usr/bin/app", {"app"}, 0U, cgroup}.write(root);
        fake_process{201U, 200U, "worker", 910U, "/usr/bin/worker", {"worker"}, 0U, cgroup}.write(root);
        value_of(pipeline.step(clock_domain::now_monotonic_ns(), std::chrono::milliseconds{0}), "pipeline step");
    }
    const auto lines = lines_of(stream);
    std::fclose(stream);
    std::vector<std::string> started;
    std::vector<std::string> stopped;
    for (const auto& line : lines) {
        if (contains(line, "\"type\":\"container.started\"")) started.push_back(line);
        if (contains(line, "\"type\":\"container.stopped\"")) stopped.push_back(line);
    }
    std::string types;
    for (const auto& line : lines) {
        const auto at = line.find("\"type\":\"");
        if (at != std::string::npos) types += line.substr(at + 8U, line.find('"', at + 8U) - at - 8U) + " ";
    }
    require(started.size() == 1U && stopped.size() == 1U, "one container.started and one container.stopped; records: " + types);
    require(contains(started[0], "\"container\":{\"id\":\"" + container_a + "\",\"runtime\":\"docker\",\"cgroup\":\"" + cgroup + "\"}") &&
                contains(started[0], "\"provenance\":{\"provider\":\"sensor\",\"mechanism\":\"container_tracker\",\"confidence\":\"inferred\"}") &&
                contains(started[0], "\"name\":\"app\""),
            "the start names the container, says it is inferred, and carries the first process: " + started[0]);
    require(contains(stopped[0], "\"start_observed\":true,\"lifetime_ns\":5000000,\"peak_processes\":2}") && contains(stopped[0], "\"name\":\"app\""),
            "the stop carries the lifetime, the peak process count and the last process: " + stopped[0]);
}

void test_parse_container_cgroup() {
    const std::string id = "a350fac50ee37dc176158ed8c5be13204c6fb12b56a3cf6d20b9fcb51cce40e2";
    const std::string pod_dashes = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";
    const std::string pod_underscores = "0a1b2c3d_4e5f_6071_8293_a4b5c6d7e8f9";

    auto found = parse_container_cgroup("/system.slice/docker-" + id + ".scope");
    require(found && found->id == id && found->runtime == "docker" && found->pod_uid.empty(), "docker with the systemd driver");
    found = parse_container_cgroup("/docker/" + id);
    require(found && found->id == id && found->runtime == "docker", "docker with the cgroupfs driver");
    found = parse_container_cgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + pod_underscores + ".slice/cri-containerd-" + id + ".scope");
    require(found && found->id == id && found->runtime == "containerd" && found->pod_uid == pod_dashes, "containerd in a burstable pod, uid restored with dashes");
    found = parse_container_cgroup("/kubepods/besteffort/pod" + pod_dashes + "/" + id);
    require(found && found->id == id && found->runtime == "kubernetes" && found->pod_uid == pod_dashes, "cgroupfs pod names the pod but not the runtime");
    found = parse_container_cgroup("/kubepods.slice/kubepods-pod" + pod_underscores + ".slice/crio-" + id + ".scope");
    require(found && found->runtime == "crio" && found->pod_uid == pod_dashes, "cri-o in a guaranteed pod");
    found = parse_container_cgroup("/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id + ".scope/container");
    require(found && found->id == id && found->runtime == "podman", "rootless podman below a user slice");

    // Helper processes are not the container, and ordinary host paths are not containers.
    require(!parse_container_cgroup("/machine.slice/crio-conmon-" + id + ".scope"), "conmon is not the container");
    require(!parse_container_cgroup("/machine.slice/libpod-conmon-" + id + ".scope"), "podman conmon is not the container");
    require(!parse_container_cgroup("/user.slice/user-1000.slice/session-145.scope"), "a login session");
    require(!parse_container_cgroup("/system.slice/ssh.service"), "a host service");
    require(!parse_container_cgroup("/"), "the root cgroup");
    require(!parse_container_cgroup(""), "no cgroup");
    require(!parse_container_cgroup("/docker/" + std::string(65, 'a')), "an id longer than a container id");
    require(!parse_container_cgroup("/docker/" + std::string(11, 'a')), "an id shorter than a container id");
    require(!parse_container_cgroup("/docker/" + std::string(64, 'G')), "not hexadecimal");
    require(!parse_container_cgroup("/kubepods/pod" + std::string(36, 'z') + "/" + id.substr(0U, 10U)), "malformed pod uid and short id");

    // Hostile input is bounded.
    std::string deep;
    for (int level = 0; level < 5000; ++level) deep += "/a";
    require(!parse_container_cgroup(deep), "an absurdly deep path");
    require(!parse_container_cgroup(std::string(100000, 'x')), "an absurdly long path");
}

int main() {
    ::umask(0022);  // the sensor refuses configuration another user can write; see test_config_and_ca_must_be_trustworthy
    std::cout << std::unitbuf;
    run("parse_container_cgroup", test_parse_container_cgroup);
    run("container_tracker_lifecycle", test_container_tracker_lifecycle);
    run("container_tracker_preexisting_and_discovered", test_container_tracker_preexisting_and_discovered);
    run("container_tracker_moves_and_limits", test_container_tracker_moves_and_limits);
    run("pipeline_container_events", test_pipeline_container_events);
    run("parse_dns_query", test_parse_dns_query);
    run("pipeline_emits_dns_queries", test_pipeline_emits_dns_queries);
    run("pipeline_emits_lsm_and_firewall_events", test_pipeline_emits_lsm_and_firewall_events);
    run("pipeline_emits_response_evidence_first", test_pipeline_emits_response_evidence_first);
    run("json_escapes_and_replaces_invalid_utf8", test_json_escapes_and_replaces_invalid_utf8);
    run("clock_formats_rfc3339_and_converts_ticks", test_clock_formats_rfc3339_and_converts_ticks);
    run("parse_stat_handles_hostile_comm", test_parse_stat_handles_hostile_comm);
    run("parse_status_reads_credentials_and_capabilities", test_parse_status_reads_credentials_and_capabilities);
    run("split_cmdline_bounds", test_split_cmdline_bounds);
    run("classify_exe_link", test_classify_exe_link);
    run("read_process_from_fake_procfs", test_read_process_from_fake_procfs);
    run("ground_truth_exec_args_environment", test_ground_truth_exec_args_environment);
    run("ground_truth_deleted_executable", test_ground_truth_deleted_executable);
    run("ground_truth_memfd_execution", test_ground_truth_memfd_execution);
    run("entity_graph_lifecycle", test_entity_graph_lifecycle);
    run("entity_graph_prefers_kernel_arguments_and_paths", test_entity_graph_prefers_kernel_arguments_and_paths);
    run("entity_graph_reconcile_infers_missed_exit", test_entity_graph_reconcile_infers_missed_exit);
    run("exit_status_decoding", test_exit_status_decoding);
    run("decode_proc_events", test_decode_proc_events);
    run("live_netlink_observes_real_process", test_live_netlink_observes_real_process);
    run("crc32c_known_vector", test_crc32c_known_vector);
    run("wal_append_read_ack_and_recover", test_wal_append_read_ack_and_recover);
    run("wal_detects_corruption_and_enforces_quota", test_wal_detects_corruption_and_enforces_quota);
    run("wal_removed_sealed_segment_is_reported_and_skipped", test_wal_removed_sealed_segment_is_reported_and_skipped);
    run("wal_removed_active_segment_and_directory", test_wal_removed_active_segment_and_directory);
    run("wal_runtime_corruption_is_isolated", test_wal_runtime_corruption_is_isolated);
    run("pipeline_end_to_end_with_scripted_provider", test_pipeline_end_to_end_with_scripted_provider);
    run("pipeline_exec_stdio_and_interpreter", test_pipeline_exec_stdio_and_interpreter);
    run("pipeline_signal_event", test_pipeline_signal_event);
    run("pipeline_raw_socket_event", test_pipeline_raw_socket_event);
    run("pipeline_tcp_close_event", test_pipeline_tcp_close_event);
    run("pipeline_emits_host_state_parts", test_pipeline_emits_host_state_parts);
    run("pipeline_reports_records_the_sink_refused", test_pipeline_reports_records_the_sink_refused);
    run("pipeline_reports_records_the_queue_refused", test_pipeline_reports_records_the_queue_refused);
    run("pipeline_reports_inputs_a_provider_refused", test_pipeline_reports_inputs_a_provider_refused);
    run("pipeline_reports_an_unclean_previous_instance", test_pipeline_reports_an_unclean_previous_instance);
    run("config_and_ca_must_be_trustworthy", test_config_and_ca_must_be_trustworthy);
    run("systemd_notifier_protocol", test_systemd_notifier_protocol);
    run("pipeline_rebases_event_times_after_a_clock_step", test_pipeline_rebases_event_times_after_a_clock_step);
    run("pipeline_reports_delivery_and_turns_rejections_into_loss", test_pipeline_reports_delivery_and_turns_rejections_into_loss);
    run("pipeline_enriches_file_events", test_pipeline_enriches_file_events);
    run("pipeline_enriches_network_events", test_pipeline_enriches_network_events);
    run("pipeline_serializes_auth_events", test_pipeline_serializes_auth_events);
    run("pipeline_serializes_kernel_events", test_pipeline_serializes_kernel_events);
    run("pipeline_reports_integrity_changes", test_pipeline_reports_integrity_changes);
    run("pipeline_hashes_executed_images", test_pipeline_hashes_executed_images);
    run("provider_family_prefers_first_and_falls_back", test_provider_family_prefers_first_and_falls_back);
    run("sensor_config_is_strict", test_sensor_config_is_strict);
    run("record_queue_counts_drops_and_keeps_order", test_record_queue_counts_drops_and_keeps_order);
    std::error_code ignored;
    fs::remove_all(fs::temp_directory_path() / ("panopticon-sensor-tests-" + std::to_string(::getpid())), ignored);
    std::cout << (failures == 0 ? "ALL PASSED" : "FAILURES: " + std::to_string(failures)) << " (skipped " << skipped << ")\n";
    return failures == 0 ? 0 : 1;
}
