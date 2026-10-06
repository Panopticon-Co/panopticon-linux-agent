#include "panopticon/linux_agent/response.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <thread>
#include <utility>

#ifdef __linux__
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace panopticon::linux_agent {

const char* to_string(const response_status status) noexcept {
    switch (status) {
        case response_status::dry_run: return "dry_run";
        case response_status::terminated: return "terminated";
        case response_status::signalled: return "signalled";
        case response_status::already_gone: return "already_gone";
        case response_status::refused_invalid: return "refused_invalid";
        case response_status::refused_protected: return "refused_protected";
        case response_status::refused_mismatch: return "refused_mismatch";
        case response_status::refused_limit: return "refused_limit";
        case response_status::failed: return "failed";
    }
    return "failed";
}

#ifndef __linux__

bool pidfd_supported() noexcept { return false; }
std::string protected_reason(std::uint32_t, const std::filesystem::path&) { return "not supported on this platform"; }
response_outcome respond_terminate_process(const process_identity&, const response_options&) {
    return {response_status::failed, {}, {}, "process response is available only on Linux"};
}
response_outcome respond_terminate_tree(const process_identity&, const response_options&) {
    return {response_status::failed, {}, {}, "process response is available only on Linux"};
}

#else

namespace {

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

namespace fs = std::filesystem;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

constexpr std::size_t maximum_scan_entries{131072U};
constexpr std::size_t maximum_ancestor_depth{64U};

struct stat_view {
    char state{};
    std::uint32_t parent{};
    std::uint64_t start{};
};

// /proc/<pid>/stat: "pid (comm) state ppid ... starttime ...". comm may contain spaces and
// parentheses, so fields are counted from the last ')'.
std::optional<stat_view> parse_stat(const std::string_view text) {
    const auto close = text.rfind(')');
    if (close == std::string_view::npos || close + 2U >= text.size()) return std::nullopt;
    std::string_view rest = text.substr(close + 2U);
    std::vector<std::string_view> fields;
    while (!rest.empty() && fields.size() < 20U) {
        const auto space = rest.find(' ');
        fields.push_back(rest.substr(0U, space));
        if (space == std::string_view::npos) break;
        rest.remove_prefix(space + 1U);
    }
    if (fields.size() < 20U || fields[0].size() != 1U) return std::nullopt;
    stat_view view;
    view.state = fields[0][0];
    const auto number = [](const std::string_view field, auto& out) {
        const auto [end, issue] = std::from_chars(field.data(), field.data() + field.size(), out);
        return issue == std::errc{} && end == field.data() + field.size();
    };
    if (!number(fields[1], view.parent) || !number(fields[19], view.start)) return std::nullopt;
    return view;
}

std::optional<stat_view> read_stat(const fs::path& root, const std::uint32_t pid) {
    std::ifstream input{root / std::to_string(pid) / "stat", std::ios::binary};
    if (!input) return std::nullopt;
    std::string text(8192U, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    text.resize(static_cast<std::size_t>(input.gcount()));
    return parse_stat(text);
}

// One process the responder holds a stable reference to.
class process_handle {
public:
    process_handle() = default;
    process_handle(const process_handle&) = delete;
    process_handle& operator=(const process_handle&) = delete;
    process_handle(process_handle&& other) noexcept
        : descriptor_{std::exchange(other.descriptor_, -1)}, pid_{other.pid_}, start_{other.start_}, root_{std::move(other.root_)} {}
    process_handle& operator=(process_handle&& other) noexcept {
        if (this != &other) {
            close_descriptor();
            descriptor_ = std::exchange(other.descriptor_, -1);
            pid_ = other.pid_;
            start_ = other.start_;
            root_ = std::move(other.root_);
        }
        return *this;
    }
    ~process_handle() { close_descriptor(); }

    // Takes the reference first, then verifies the start time, so a reused PID is a mismatch.
    static std::optional<process_handle> open(const std::uint32_t pid, const std::uint64_t expected_start, const response_options& options,
                                              bool& mismatch, std::string& problem) {
        mismatch = false;
        process_handle handle;
        handle.pid_ = pid;
        handle.start_ = expected_start;
        handle.root_ = options.proc_root;
        if (!options.force_pid_fallback) {
            const long fd = ::syscall(SYS_pidfd_open, static_cast<pid_t>(pid), 0U);
            if (fd >= 0) {
                handle.descriptor_ = static_cast<int>(fd);
            } else if (errno == ESRCH) {
                mismatch = true;
                problem = "the process no longer exists";
                return std::nullopt;
            } else if (errno != ENOSYS && errno != EPERM && errno != EACCES) {
                problem = "pidfd_open failed: errno " + std::to_string(errno);
                return std::nullopt;
            }
        }
        if (handle.descriptor_ < 0 && !options.allow_pid_fallback) {
            problem = "pidfd is unavailable and PID fallback is disabled";
            return std::nullopt;
        }
        const auto stat = read_stat(options.proc_root, pid);
        if (!stat || stat->start != expected_start) {
            mismatch = true;
            problem = "the PID no longer belongs to the process that was named";
            return std::nullopt;
        }
        return handle;
    }

    [[nodiscard]] bool uses_pidfd() const noexcept { return descriptor_ >= 0; }
    [[nodiscard]] const char* mode() const noexcept { return uses_pidfd() ? "pidfd" : "pid_fallback"; }

    // 0 on success, an errno otherwise (ESRCH: the process is gone).
    [[nodiscard]] int send(const int signal_number) const noexcept {
        if (uses_pidfd()) {
            return ::syscall(SYS_pidfd_send_signal, descriptor_, signal_number, nullptr, 0U) == 0 ? 0 : errno;
        }
        // The fallback re-checks the identity immediately before the signal; the remaining window is
        // the time between that read and kill(2).
        const auto stat = read_stat(root_, pid_);
        if (!stat || stat->start != start_ || stat->state == 'Z' || stat->state == 'X') return ESRCH;
        return ::kill(static_cast<pid_t>(pid_), signal_number) == 0 ? 0 : errno;
    }

    [[nodiscard]] bool exited() const {
        if (uses_pidfd()) {
            pollfd item{descriptor_, POLLIN, 0};
            return ::poll(&item, 1, 0) > 0 && (item.revents & POLLIN) != 0;
        }
        const auto stat = read_stat(root_, pid_);
        return !stat || stat->start != start_ || stat->state == 'Z' || stat->state == 'X';
    }

    [[nodiscard]] bool wait_exit(const milliseconds limit) const {
        const auto deadline = steady_clock::now() + limit;
        while (true) {
            if (exited()) return true;
            if (steady_clock::now() >= deadline) return false;
            std::this_thread::sleep_for(milliseconds{5});
        }
    }

private:
    void close_descriptor() noexcept {
        if (descriptor_ >= 0) ::close(descriptor_);
        descriptor_ = -1;
    }
    int descriptor_{-1};
    std::uint32_t pid_{};
    std::uint64_t start_{};
    fs::path root_;
};

struct scanned_process {
    std::uint32_t parent{};
    std::uint64_t start{};
};

// pid -> parent and start time for every process, bounded.
bool scan_processes(const fs::path& root, std::map<std::uint32_t, scanned_process>& out) {
    out.clear();
    std::error_code error;
    std::size_t visited{};
    for (fs::directory_iterator it{root, error}, end; !error && it != end; it.increment(error)) {
        const auto name = it->path().filename().string();
        std::uint32_t pid{};
        const auto [stop, issue] = std::from_chars(name.data(), name.data() + name.size(), pid);
        if (issue != std::errc{} || stop != name.data() + name.size() || pid == 0U) continue;
        if (++visited > maximum_scan_entries) return false;
        const auto stat = read_stat(root, pid);
        if (stat) out[pid] = {stat->parent, stat->start};
    }
    return !error;
}

std::vector<std::uint32_t> descendants_of(const std::map<std::uint32_t, scanned_process>& table, const std::uint32_t root_pid) {
    std::map<std::uint32_t, std::vector<std::uint32_t>> children;
    for (const auto& [pid, info] : table) children[info.parent].push_back(pid);
    std::vector<std::uint32_t> order;
    std::vector<std::uint32_t> queue{root_pid};
    std::set<std::uint32_t> seen{root_pid};
    for (std::size_t index = 0; index < queue.size(); ++index) {
        const auto found = children.find(queue[index]);
        if (found == children.end()) continue;
        for (const auto child : found->second) {
            if (!seen.insert(child).second) continue;
            queue.push_back(child);
            order.push_back(child);
        }
    }
    return order;
}

response_outcome refusal(const response_status status, std::string detail) {
    response_outcome outcome;
    outcome.status = status;
    outcome.detail = std::move(detail);
    return outcome;
}

bool valid_target(const process_identity& target) { return target.pid != 0U && target.start_time_ticks != 0U; }

}  // namespace

bool pidfd_supported() noexcept {
    const long fd = ::syscall(SYS_pidfd_open, ::getpid(), 0U);
    if (fd < 0) return false;
    ::close(static_cast<int>(fd));
    return true;
}

std::string protected_reason(const std::uint32_t pid, const fs::path& proc_root) {
    if (pid <= 1U) return "pid 0 and 1 are never signalled";
    if (pid == 2U) return "kernel thread daemon";
    const auto self = static_cast<std::uint32_t>(::getpid());
    if (pid == self) return "the agent itself";
    // Ancestors: killing a supervisor of the agent would take the agent down with it.
    std::uint32_t cursor = self;
    for (std::size_t depth = 0; depth < maximum_ancestor_depth && cursor > 1U; ++depth) {
        const auto stat = read_stat(proc_root, cursor);
        if (!stat) break;
        cursor = stat->parent;
        if (cursor == pid) return "an ancestor of the agent";
    }
    const auto stat = read_stat(proc_root, pid);
    if (stat && stat->parent == 2U) return "kernel thread";
    return {};
}

response_outcome respond_terminate_process(const process_identity& target, const response_options& options) {
    if (!valid_target(target)) return refusal(response_status::refused_invalid, "the identity needs a pid and a start time");
    if (const auto reason = protected_reason(target.pid, options.proc_root); !reason.empty()) {
        return refusal(response_status::refused_protected, reason);
    }
    bool mismatch{};
    std::string problem;
    const auto handle = process_handle::open(target.pid, target.start_time_ticks, options, mismatch, problem);
    if (!handle) return refusal(mismatch ? response_status::refused_mismatch : response_status::failed, problem);

    response_outcome outcome;
    outcome.mode = handle->mode();
    outcome.affected.push_back(target);
    if (options.dry_run) {
        outcome.status = response_status::dry_run;
        outcome.detail = "verified; no signal sent";
        return outcome;
    }
    if (const int code = handle->send(SIGTERM); code != 0) {
        outcome.status = code == ESRCH ? response_status::already_gone : response_status::failed;
        outcome.detail = code == ESRCH ? "the process exited before the signal" : "SIGTERM refused: errno " + std::to_string(code);
        return outcome;
    }
    outcome.status = response_status::signalled;
    outcome.detail = "SIGTERM sent";
    if (options.grace.count() > 0 && handle->wait_exit(options.grace)) {
        outcome.status = response_status::terminated;
        return outcome;
    }
    if (options.escalate_to_kill && !handle->exited()) {
        if (const int code = handle->send(SIGKILL); code != 0 && code != ESRCH) {
            outcome.status = response_status::failed;
            outcome.detail = "SIGKILL refused: errno " + std::to_string(code);
            return outcome;
        }
        outcome.detail = "SIGTERM ignored for the grace period; SIGKILL sent";
        if (handle->wait_exit(milliseconds{2000})) outcome.status = response_status::terminated;
    }
    return outcome;
}

response_outcome respond_terminate_tree(const process_identity& target, const response_options& options) {
    if (!valid_target(target)) return refusal(response_status::refused_invalid, "the identity needs a pid and a start time");
    if (options.maximum_tree_size == 0U) return refusal(response_status::refused_invalid, "the tree bound is zero");
    if (const auto reason = protected_reason(target.pid, options.proc_root); !reason.empty()) {
        return refusal(response_status::refused_protected, reason);
    }
    bool mismatch{};
    std::string problem;
    auto root_handle = process_handle::open(target.pid, target.start_time_ticks, options, mismatch, problem);
    if (!root_handle) return refusal(mismatch ? response_status::refused_mismatch : response_status::failed, problem);

    response_outcome outcome;
    outcome.mode = root_handle->mode();
    outcome.affected.push_back(target);
    const std::string host = target.host_id;

    std::map<std::uint32_t, scanned_process> table;
    if (!scan_processes(options.proc_root, table)) return refusal(response_status::refused_limit, "the process table is too large to scan");
    const auto first = descendants_of(table, target.pid);
    if (first.size() + 1U > options.maximum_tree_size) return refusal(response_status::refused_limit, "the tree is larger than the configured bound");
    // Every member is checked before anything is stopped: one protected process refuses the lot.
    for (const auto pid : first) {
        if (const auto reason = protected_reason(pid, options.proc_root); !reason.empty()) {
            return refusal(response_status::refused_protected, "pid " + std::to_string(pid) + " in the tree is protected: " + reason);
        }
    }
    if (options.dry_run) {
        for (const auto pid : first) outcome.affected.push_back({host, pid, table[pid].start});
        outcome.status = response_status::dry_run;
        outcome.detail = "verified " + std::to_string(first.size() + 1U) + " process(es); no signal sent";
        return outcome;
    }

    // Stop the root first so it cannot keep forking, then collect descendants until a rescan finds
    // nothing new. A stopped process still dies to SIGKILL.
    std::vector<process_handle> held;
    const auto resume_all = [&] {
        (void)root_handle->send(SIGCONT);
        for (const auto& handle : held) (void)handle.send(SIGCONT);
    };
    if (const int code = root_handle->send(SIGSTOP); code != 0) {
        outcome.status = code == ESRCH ? response_status::already_gone : response_status::failed;
        outcome.detail = code == ESRCH ? "the root exited before it could be stopped" : "SIGSTOP refused: errno " + std::to_string(code);
        return outcome;
    }
    std::set<std::uint32_t> known{target.pid};
    constexpr int maximum_rounds{8};
    bool stable{false};
    for (int round = 0; round < maximum_rounds && !stable; ++round) {
        if (!scan_processes(options.proc_root, table)) {
            resume_all();
            return refusal(response_status::refused_limit, "the process table is too large to scan");
        }
        stable = true;
        for (const auto pid : descendants_of(table, target.pid)) {
            if (!known.insert(pid).second) continue;
            stable = false;
            if (known.size() > options.maximum_tree_size) {
                resume_all();
                return refusal(response_status::refused_limit, "the tree grew beyond the configured bound");
            }
            if (const auto reason = protected_reason(pid, options.proc_root); !reason.empty()) {
                resume_all();
                return refusal(response_status::refused_protected, "pid " + std::to_string(pid) + " joined the tree and is protected: " + reason);
            }
            bool skipped{};
            std::string ignored;
            auto handle = process_handle::open(pid, table[pid].start, options, skipped, ignored);
            if (!handle) continue;  // exited or reused since the scan: not ours to signal
            (void)handle->send(SIGSTOP);
            outcome.affected.push_back({host, pid, table[pid].start});
            held.push_back(std::move(*handle));
        }
    }
    if (!stable) {
        resume_all();
        return refusal(response_status::refused_limit, "the tree kept growing; it was released unharmed");
    }

    int refused{0};
    for (const auto& handle : held) {
        const int code = handle.send(SIGKILL);
        if (code != 0 && code != ESRCH) ++refused;
    }
    const int root_code = root_handle->send(SIGKILL);
    if (root_code != 0 && root_code != ESRCH) ++refused;
    bool all_exited = refused == 0;
    for (const auto& handle : held) all_exited = handle.wait_exit(milliseconds{2000}) && all_exited;
    all_exited = root_handle->wait_exit(milliseconds{2000}) && all_exited;
    outcome.status = refused != 0 ? response_status::failed : all_exited ? response_status::terminated : response_status::signalled;
    outcome.detail = "SIGKILL sent to " + std::to_string(held.size() + 1U) + " process(es)" +
                     (refused != 0 ? "; " + std::to_string(refused) + " refused" : std::string{});
    return outcome;
}

#endif

}  // namespace panopticon::linux_agent
