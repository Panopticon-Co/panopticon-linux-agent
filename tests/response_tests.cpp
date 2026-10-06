#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/response.hpp"

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <exception>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace panopticon::linux_agent;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

// Start time of a live process, read independently of the code under test.
std::uint64_t start_of(const pid_t pid) {
    std::ifstream input{"/proc/" + std::to_string(pid) + "/stat"};
    std::string text;
    std::getline(input, text);
    const auto close = text.rfind(')');
    require(close != std::string::npos, "stat readable");
    std::size_t cursor = close + 2U;
    for (int field = 0; field < 19; ++field) {
        cursor = text.find(' ', cursor);
        require(cursor != std::string::npos, "stat has the start time field");
        ++cursor;
    }
    return std::stoull(text.substr(cursor));
}

process_identity identity_of(const pid_t pid) { return {"host-test", static_cast<std::uint32_t>(pid), start_of(pid)}; }

// A child that sleeps until signalled. `ignore_term` makes it survive SIGTERM.
pid_t spawn_sleeper(const bool ignore_term) {
    const pid_t pid = ::fork();
    require(pid >= 0, "fork");
    if (pid == 0) {
        if (ignore_term) ::signal(SIGTERM, SIG_IGN);
        for (;;) ::pause();
    }
    return pid;
}

bool alive(const pid_t pid) {
    std::ifstream input{"/proc/" + std::to_string(pid) + "/stat"};
    std::string text;
    if (!std::getline(input, text)) return false;
    const auto close = text.rfind(')');
    return close != std::string::npos && close + 2U < text.size() && text[close + 2U] != 'Z' && text[close + 2U] != 'X';
}

bool wait_until_gone(const pid_t pid) {
    for (int attempt = 0; attempt < 400; ++attempt) {
        if (!alive(pid)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
}

int reap(const pid_t pid) {
    int status = 0;
    require(::waitpid(pid, &status, 0) == pid, "waitpid");
    return status;
}

void cleanup(const pid_t pid) {
    ::kill(pid, SIGKILL);
    int status = 0;
    ::waitpid(pid, &status, 0);
}

response_options live_options() {
    response_options options;
    options.dry_run = false;
    options.grace = std::chrono::milliseconds{3000};
    return options;
}

void test_dry_run_changes_nothing() {
    const pid_t child = spawn_sleeper(false);
    const auto outcome = respond_terminate_process(identity_of(child), response_options{});
    require(outcome.status == response_status::dry_run, "default options are a dry run");
    require(outcome.mode == (pidfd_supported() ? "pidfd" : "pid_fallback"), "the signal path is reported");
    require(outcome.affected.size() == 1U && outcome.affected[0].pid == static_cast<std::uint32_t>(child), "the verified identity is named");
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    require(alive(child), "a dry run leaves the process alone");
    cleanup(child);
}

void test_identity_mismatch_is_refused() {
    const pid_t child = spawn_sleeper(false);
    auto wrong = identity_of(child);
    wrong.start_time_ticks += 1U;
    const auto outcome = respond_terminate_process(wrong, live_options());
    require(outcome.status == response_status::refused_mismatch, "a different start time is a different process");
    require(alive(child), "the process the PID really belongs to is untouched");
    cleanup(child);
}

void test_reused_or_missing_pid_is_not_signalled() {
    const pid_t child = spawn_sleeper(false);
    const auto identity = identity_of(child);
    cleanup(child);
    const auto outcome = respond_terminate_process(identity, live_options());
    require(outcome.status == response_status::refused_mismatch, "a process that is gone is not re-targeted");
}

void test_terminate_with_sigterm() {
    const pid_t child = spawn_sleeper(false);
    const auto outcome = respond_terminate_process(identity_of(child), live_options());
    require(outcome.status == response_status::terminated, "the exit is observed through the pidfd");
    const int status = reap(child);
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "the signal was SIGTERM");
}

void test_escalation_to_sigkill() {
    const pid_t child = spawn_sleeper(true);
    // Let the child install its handler before the first signal.
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    auto options = live_options();
    options.grace = std::chrono::milliseconds{200};
    const auto without = respond_terminate_process(identity_of(child), options);
    require(without.status == response_status::signalled, "SIGTERM ignored, no escalation: reported as signalled");
    require(alive(child), "still running");
    options.escalate_to_kill = true;
    const auto with = respond_terminate_process(identity_of(child), options);
    require(with.status == response_status::terminated, "escalation ends the process");
    const int status = reap(child);
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "the final signal was SIGKILL");
}

void test_protected_processes_are_refused() {
    const auto options = live_options();
    require(respond_terminate_process({"h", 1U, 1U}, options).status == response_status::refused_protected, "init");
    require(respond_terminate_process({"h", static_cast<std::uint32_t>(::getpid()), start_of(::getpid())}, options).status ==
                response_status::refused_protected,
            "the agent itself");
    require(respond_terminate_process({"h", static_cast<std::uint32_t>(::getppid()), start_of(::getppid())}, options).status ==
                response_status::refused_protected,
            "the agent's parent");
    require(respond_terminate_process({"h", 2U, 1U}, options).status == response_status::refused_protected, "kthreadd");
    require(respond_terminate_tree({"h", static_cast<std::uint32_t>(::getpid()), start_of(::getpid())}, options).status ==
                response_status::refused_protected,
            "a tree rooted at the agent");
    require(respond_terminate_process({"h", 0U, 0U}, options).status == response_status::refused_invalid, "no identity at all");
    require(!protected_reason(static_cast<std::uint32_t>(::getppid()), "/proc").empty(), "ancestor reason is explained");
}

void test_pid_fallback_path() {
    const pid_t child = spawn_sleeper(false);
    auto options = live_options();
    options.force_pid_fallback = true;
    auto wrong = identity_of(child);
    wrong.start_time_ticks += 1U;
    require(respond_terminate_process(wrong, options).status == response_status::refused_mismatch, "the fallback verifies identity too");
    const auto outcome = respond_terminate_process(identity_of(child), options);
    require(outcome.status == response_status::terminated && outcome.mode == "pid_fallback", "the fallback works and says so");
    reap(child);

    const pid_t second = spawn_sleeper(false);
    options.allow_pid_fallback = false;
    require(respond_terminate_process(identity_of(second), options).status == response_status::failed, "fallback can be disabled");
    require(alive(second), "and then nothing is signalled");
    cleanup(second);
}

struct family {
    pid_t root{};
    std::vector<pid_t> descendants;
};

// root forks two children, one of which forks a grandchild; their pids come back through a pipe.
family spawn_family() {
    int fds[2];
    require(::pipe(fds) == 0, "pipe");
    const pid_t root = ::fork();
    require(root >= 0, "fork");
    if (root == 0) {
        ::close(fds[0]);
        for (int index = 0; index < 2; ++index) {
            const pid_t kid = ::fork();
            if (kid == 0) {
                if (index == 0) {
                    const pid_t grand = ::fork();
                    if (grand == 0) {
                        for (;;) ::pause();
                    }
                    if (::write(fds[1], &grand, sizeof(grand)) < 0) _exit(1);
                }
                for (;;) ::pause();
            }
            if (::write(fds[1], &kid, sizeof(kid)) < 0) _exit(1);
        }
        ::close(fds[1]);
        for (;;) ::pause();
    }
    ::close(fds[1]);
    family result;
    result.root = root;
    pid_t value = 0;
    while (result.descendants.size() < 3U && ::read(fds[0], &value, sizeof(value)) == static_cast<ssize_t>(sizeof(value))) {
        result.descendants.push_back(value);
    }
    ::close(fds[0]);
    require(result.descendants.size() == 3U, "three descendants reported");
    return result;
}

void test_tree_termination() {
    const auto tree = spawn_family();

    const auto preview = respond_terminate_tree(identity_of(tree.root), response_options{});
    require(preview.status == response_status::dry_run && preview.affected.size() == 4U, "the dry run lists the root and all descendants");
    require(alive(tree.root), "nothing was signalled");
    for (const auto pid : tree.descendants) require(alive(pid), "descendants alive after dry run");

    auto bounded = live_options();
    bounded.maximum_tree_size = 2U;
    const auto limited = respond_terminate_tree(identity_of(tree.root), bounded);
    require(limited.status == response_status::refused_limit, "a tree over the bound is refused");
    for (const auto pid : tree.descendants) require(alive(pid), "the refusal came before anything was stopped");

    const auto outcome = respond_terminate_tree(identity_of(tree.root), live_options());
    require(outcome.status == response_status::terminated && outcome.affected.size() == 4U, "the whole tree is terminated");
    const int status = reap(tree.root);
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "the root died of SIGKILL");
    for (const auto pid : tree.descendants) require(wait_until_gone(pid), "every descendant is gone");
}

void test_command_wrapper_keeps_its_contract() {
    const pid_t child = spawn_sleeper(false);
    auto wrong = identity_of(child);
    wrong.start_time_ticks += 1U;
    const auto mismatch = terminate_process("/proc", wrong);
    require(!succeeded(mismatch) && std::get<error>(mismatch).code == error_code::target_mismatch, "mismatch keeps its error code");
    require(alive(child), "still running");
    const auto ok = terminate_process("/proc", identity_of(child));
    require(succeeded(ok), "the verified target is signalled");
    const int status = reap(child);
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "SIGTERM, as before");
    const auto protected_target = terminate_process("/proc", {"host-test", static_cast<std::uint32_t>(::getpid()), start_of(::getpid())});
    require(!succeeded(protected_target) && std::get<error>(protected_target).code == error_code::invalid_input, "self stays protected");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"dry_run_changes_nothing", test_dry_run_changes_nothing},
        {"identity_mismatch_is_refused", test_identity_mismatch_is_refused},
        {"reused_or_missing_pid_is_not_signalled", test_reused_or_missing_pid_is_not_signalled},
        {"terminate_with_sigterm", test_terminate_with_sigterm},
        {"escalation_to_sigkill", test_escalation_to_sigkill},
        {"protected_processes_are_refused", test_protected_processes_are_refused},
        {"pid_fallback_path", test_pid_fallback_path},
        {"tree_termination", test_tree_termination},
        {"command_wrapper_keeps_its_contract", test_command_wrapper_keeps_its_contract},
    };
    int failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::printf("PASS %s\n", test.name);
        } catch (const std::exception& error) {
            std::printf("FAIL %s: %s\n", test.name, error.what());
            ++failures;
        }
    }
    std::printf(failures == 0 ? "ALL PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
