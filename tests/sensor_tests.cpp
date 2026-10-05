// Unit and ground-truth tests for the resident sensor (slice S1). Ground-truth cases start real
// processes and compare what the sensor reads with what the test knows it created.

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/entity_graph.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"
#include "panopticon/linux_agent/sensor/netlink_proc.hpp"
#include "panopticon/linux_agent/sensor/pipeline.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"
#include "panopticon/linux_agent/sensor/serializer.hpp"
#include "panopticon/linux_agent/sensor/wal.hpp"

#include <linux/cn_proc.h>

#include <algorithm>
#include <chrono>
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
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
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
        write_file(base / "cgroup", "0::/system.slice/ssh.service\n");
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
    event.what = proc_event::PROC_EVENT_FORK;
    event.timestamp_ns = 5U;
    event.event_data.fork.parent_pid = 10;
    event.event_data.fork.parent_tgid = 10;
    event.event_data.fork.child_pid = 11;
    event.event_data.fork.child_tgid = 11;
    auto decoded = decode_proc_event(&event, sizeof(event), clock);
    require(decoded && std::holds_alternative<raw_fork>(decoded->payload) && std::get<raw_fork>(decoded->payload).child_tgid == 11U, "fork");

    event = {};
    event.what = proc_event::PROC_EVENT_COMM;
    event.event_data.comm.process_pid = 12;
    event.event_data.comm.process_tgid = 12;
    std::memcpy(event.event_data.comm.comm, "0123456789abcdef", 16U);  // no terminator
    decoded = decode_proc_event(&event, sizeof(event), clock);
    require(decoded && std::get<raw_comm_change>(decoded->payload).comm == "0123456789abcdef", "unterminated comm bounded");

    event = {};
    event.what = proc_event::PROC_EVENT_EXIT;
    event.event_data.exit.process_pid = 12;
    event.event_data.exit.process_tgid = 12;
    event.event_data.exit.exit_code = 0x0200U;
    decoded = decode_proc_event(&event, sizeof(event), clock);
    require(decoded && std::get<raw_exit>(decoded->payload).exit_status == 0x0200U, "exit");

    require(!decode_proc_event(&event, 8U, clock).has_value(), "truncated event rejected");
    event.what = proc_event::PROC_EVENT_NONE;
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

// ---- serializer and pipeline ----------------------------------------------------------------

class scripted_provider final : public provider {
public:
    explicit scripted_provider(std::vector<raw_record> records) : records_{std::move(records)} {}
    std::string_view name() const noexcept override { return "scripted"; }
    std::vector<std::string> capabilities() const override { return {"process.fork", "process.exec", "process.exit"}; }
    std::string probe() override { return {}; }
    result<bool> start(record_queue& queue) override {
        for (auto& record : records_) (void)queue.push(record);
        active_ = true;
        return true;
    }
    void stop() override { active_ = false; }
    provider_health health() const override { return {"scripted", active_ ? "active" : "stopped", "", capabilities(), records_.size(), 0U}; }
    std::uint64_t take_losses() override { return 0U; }

private:
    std::vector<raw_record> records_;
    bool active_{false};
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
}

void test_sensor_config_is_strict() {
    const auto& config = value_of(parse_sensor_config("sensor_id = s-1\nhost_id=h-1\n# comment\nqueue_capacity=4096\n"), "valid config");
    require(config.queue_capacity == 4096U && config.wal_path == "/var/lib/panopticon/wal", "values and defaults");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nbogus=1\n")), "unknown key rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nqueue_capacity=1\n")), "out of range rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nsensor_id=t\nhost_id=h\n")), "duplicate rejected");
    require(!succeeded(parse_sensor_config("sensor_id=s\nhost_id=h\nwal_path=relative\n")), "relative path rejected");
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

int main() {
    std::cout << std::unitbuf;
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
    run("entity_graph_reconcile_infers_missed_exit", test_entity_graph_reconcile_infers_missed_exit);
    run("exit_status_decoding", test_exit_status_decoding);
    run("decode_proc_events", test_decode_proc_events);
    run("live_netlink_observes_real_process", test_live_netlink_observes_real_process);
    run("crc32c_known_vector", test_crc32c_known_vector);
    run("wal_append_read_ack_and_recover", test_wal_append_read_ack_and_recover);
    run("wal_detects_corruption_and_enforces_quota", test_wal_detects_corruption_and_enforces_quota);
    run("pipeline_end_to_end_with_scripted_provider", test_pipeline_end_to_end_with_scripted_provider);
    run("sensor_config_is_strict", test_sensor_config_is_strict);
    run("record_queue_counts_drops_and_keeps_order", test_record_queue_counts_drops_and_keeps_order);
    std::error_code ignored;
    fs::remove_all(fs::temp_directory_path() / ("panopticon-sensor-tests-" + std::to_string(::getpid())), ignored);
    std::cout << (failures == 0 ? "ALL PASSED" : "FAILURES: " + std::to_string(failures)) << " (skipped " << skipped << ")\n";
    return failures == 0 ? 0 : 1;
}
