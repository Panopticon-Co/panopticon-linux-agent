#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

void require_result(const execution_result& result, const char* outcome, const char* reason, const char* what) {
    if (result.outcome != outcome || result.reason != reason) {
        throw std::runtime_error{std::string{what} + ": got " + result.outcome + "/" + result.reason + " (" + result.detail + ")"};
    }
}

// A stand-in for panopticon-isolation-helper: same socket type and framing, no firewall. It records every
// frame it is sent and answers as told, so the client's handling of each outcome can be tested without
// CAP_NET_ADMIN.
class fake_helper {
public:
    enum class behaviour { accept, refuse, silent, hang_up };

    explicit fake_helper(const behaviour how) : how_{how} {
        char pattern[] = "/tmp/panopticon-isolation-XXXXXX";
        const char* made = ::mkdtemp(pattern);
        require(made != nullptr, "temporary directory");
        directory_ = made;
        socket_path_ = directory_ / "isolation.sock";
        server_ = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        require(server_ >= 0, "socket");
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, socket_path_.c_str(), sizeof(address.sun_path) - 1U);
        require(::bind(server_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "bind");
        require(::listen(server_, 8) == 0, "listen");
        thread_ = std::thread{[this] { serve(); }};
    }
    ~fake_helper() {
        stop_.store(true);
        // Wake accept() by connecting once.
        const int wake = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (wake >= 0) {
            sockaddr_un address{};
            address.sun_family = AF_UNIX;
            std::strncpy(address.sun_path, socket_path_.c_str(), sizeof(address.sun_path) - 1U);
            (void)::connect(wake, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
            ::close(wake);
        }
        thread_.join();
        ::close(server_);
        std::error_code ec;
        fs::remove_all(directory_, ec);
    }
    fake_helper(const fake_helper&) = delete;
    fake_helper& operator=(const fake_helper&) = delete;

    [[nodiscard]] const fs::path& path() const { return socket_path_; }
    [[nodiscard]] std::vector<std::string> frames() const {
        std::lock_guard lock{mutex_};
        return frames_;
    }
    // Connections that arrived and sent nothing (the reachability probe).
    [[nodiscard]] int empty_connections() const { return empty_.load(); }

private:
    void serve() {
        while (!stop_.load()) {
            const int connection = ::accept4(server_, nullptr, nullptr, SOCK_CLOEXEC);
            if (connection < 0) continue;
            if (stop_.load()) {
                ::close(connection);
                break;
            }
            char buffer[kIsolationRequestFrameSize + 1U];
            const auto received = ::recv(connection, buffer, sizeof(buffer), 0);
            if (received <= 0) {
                empty_.fetch_add(1);
                ::close(connection);
                continue;
            }
            {
                std::lock_guard lock{mutex_};
                frames_.emplace_back(buffer, static_cast<std::size_t>(received));
            }
            std::uint8_t status = how_ == behaviour::accept ? kIsolationStatusOk : kIsolationStatusRejected;
            if (how_ == behaviour::silent) {
                // Never answers: hold the connection until the client gives up.
                char scratch[1];
                (void)::recv(connection, scratch, sizeof(scratch), 0);
            } else if (how_ != behaviour::hang_up) {
                (void)::send(connection, &status, sizeof(status), 0);
            }
            ::close(connection);
        }
    }

    behaviour how_;
    fs::path directory_;
    fs::path socket_path_;
    int server_{-1};
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<int> empty_{0};
    mutable std::mutex mutex_;
    std::vector<std::string> frames_;
};

constexpr std::chrono::milliseconds quick{300};

endpoint_command isolate_command(const command_action action = command_action::isolate_host) {
    endpoint_command command;
    command.command_id = "cmd-isolate-1";
    command.action = action;
    return command;
}

execution_result run(const endpoint_command& command, const bool dry_run, const fs::path& socket) {
    local_executor_options options;
    options.isolation_socket = socket;
    options.isolation_timeout = quick;
    return make_local_executor(options)->execute(command, dry_run);
}

void exchange_outcomes() {
    {
        fake_helper helper{fake_helper::behaviour::accept};
        require(exchange_isolation_request(helper.path(), isolation_opcode::isolate, "cmd-1", quick) ==
                    isolation_exchange::accepted,
                "an answering helper is accepted");
        const auto frames = helper.frames();
        require(frames.size() == 1U, "exactly one frame was sent");
        const auto expected = encode_isolation_request(isolation_opcode::isolate, "cmd-1");
        require(succeeded(expected) && frames[0] == std::get<std::string>(expected), "the frame is the fixed encoding");
    }
    {
        fake_helper helper{fake_helper::behaviour::refuse};
        require(exchange_isolation_request(helper.path(), isolation_opcode::release, "cmd-2", quick) ==
                    isolation_exchange::refused,
                "a declining helper is refused");
    }
    require(exchange_isolation_request("/tmp/panopticon-no-such-helper.sock", isolation_opcode::isolate, "cmd-3", quick) ==
                isolation_exchange::unreachable,
            "no listener is unreachable");
    {
        fake_helper helper{fake_helper::behaviour::silent};
        const auto started = std::chrono::steady_clock::now();
        require(exchange_isolation_request(helper.path(), isolation_opcode::isolate, "cmd-4", quick) ==
                    isolation_exchange::no_answer,
                "a helper that never answers is no_answer");
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds{5}, "the wait is bounded by the timeout");
        require(helper.frames().size() == 1U, "the request did reach the silent helper");
    }
    {
        fake_helper helper{fake_helper::behaviour::hang_up};
        require(exchange_isolation_request(helper.path(), isolation_opcode::isolate, "cmd-5", quick) ==
                    isolation_exchange::no_answer,
                "a helper that hangs up is no_answer");
    }
}

void exchange_invalid_requests() {
    fake_helper helper{fake_helper::behaviour::accept};
    require(exchange_isolation_request(helper.path(), isolation_opcode::isolate, "bad id!", quick) == isolation_exchange::invalid,
            "an unusable command id is invalid");
    require(exchange_isolation_request(helper.path(), isolation_opcode::isolate, "", quick) == isolation_exchange::invalid,
            "an empty command id is invalid");
    require(exchange_isolation_request(fs::path{std::string(300U, 'x')}, isolation_opcode::isolate, "cmd-6", quick) ==
                isolation_exchange::invalid,
            "a socket path longer than sun_path is invalid");
    require(exchange_isolation_request("", isolation_opcode::isolate, "cmd-7", quick) == isolation_exchange::invalid,
            "an empty socket path is invalid");
    require(helper.frames().empty(), "nothing invalid reached the helper");
}

void reachability_probe_sends_nothing() {
    fake_helper helper{fake_helper::behaviour::accept};
    require(isolation_helper_reachable(helper.path()), "a listening helper is reachable");
    require(!isolation_helper_reachable("/tmp/panopticon-no-such-helper.sock"), "a missing socket is not");
    // The helper learns of the probe only as a connection with no data.
    for (int waited = 0; waited < 100 && helper.empty_connections() == 0; ++waited) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    require(helper.empty_connections() == 1, "the probe is an empty connection");
    require(helper.frames().empty(), "the probe sent no frame");
}

void executor_isolate_and_release() {
    fake_helper helper{fake_helper::behaviour::accept};
    const auto isolated = run(isolate_command(), false, helper.path());
    require_result(isolated, "succeeded", "ok", "isolate");
    require(isolated.affected == 1U, "one host affected");
    const auto released = run(isolate_command(command_action::release_host_isolation), false, helper.path());
    require_result(released, "succeeded", "ok", "release");
    const auto frames = helper.frames();
    require(frames.size() == 2U, "two requests reached the helper");
    require(static_cast<std::uint8_t>(frames[0][0]) == static_cast<std::uint8_t>(isolation_opcode::isolate), "first is isolate");
    require(static_cast<std::uint8_t>(frames[1][0]) == static_cast<std::uint8_t>(isolation_opcode::release), "second is release");
}

void executor_dry_run_sends_nothing() {
    fake_helper helper{fake_helper::behaviour::accept};
    const auto result = run(isolate_command(), true, helper.path());
    require_result(result, "rejected", "dry_run", "dry-run isolate");
    require(helper.frames().empty(), "a dry run never sends a request");
    require_result(run(isolate_command(command_action::release_host_isolation), true, helper.path()), "rejected", "dry_run",
                   "dry-run release");
    require(helper.frames().empty(), "a dry run never sends a release either");
    require_result(run(isolate_command(), true, "/tmp/panopticon-no-such-helper.sock"), "rejected", "helper_unreachable",
                   "dry-run proves the helper is reachable");
}

void executor_failures() {
    require_result(run(isolate_command(), false, ""), "rejected", "isolation_unavailable", "no helper configured");
    require_result(run(isolate_command(), false, "/tmp/panopticon-no-such-helper.sock"), "failed", "helper_unreachable",
                   "helper not running");
    {
        fake_helper helper{fake_helper::behaviour::refuse};
        require_result(run(isolate_command(), false, helper.path()), "failed", "helper_refused", "helper declines");
    }
    {
        // Sent but not acknowledged: the host may or may not be isolated, so the answer must say so.
        fake_helper helper{fake_helper::behaviour::silent};
        require_result(run(isolate_command(), false, helper.path()), "indeterminate", "helper_no_answer", "helper silent");
    }
    {
        fake_helper helper{fake_helper::behaviour::accept};
        auto command = isolate_command();
        command.command_id = "not a valid id";
        require_result(run(command, false, helper.path()), "failed", "invalid_request", "bad command id");
        require(helper.frames().empty(), "a bad id never reaches the helper");
    }
}

template <typename Fn>
bool run_test(const char* name, Fn&& fn) {
    try {
        fn();
        std::printf("PASS %s\n", name);
        return true;
    } catch (const std::exception& error) {
        std::printf("FAIL %s: %s\n", name, error.what());
        return false;
    }
}

}  // namespace

int main() {
    bool ok = true;
    ok &= run_test("exchange_outcomes", exchange_outcomes);
    ok &= run_test("exchange_invalid_requests", exchange_invalid_requests);
    ok &= run_test("reachability_probe_sends_nothing", reachability_probe_sends_nothing);
    ok &= run_test("executor_isolate_and_release", executor_isolate_and_release);
    ok &= run_test("executor_dry_run_sends_nothing", executor_dry_run_sends_nothing);
    ok &= run_test("executor_failures", executor_failures);
    return ok ? 0 : 1;
}
