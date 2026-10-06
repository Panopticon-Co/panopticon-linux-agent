#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <thread>

namespace panopticon::linux_agent::sensor {

// Local control channel (catalog: QUERY_STATE / status). A unix stream socket with one
// request line in and one JSON line out:
//
//   request : <command>[ <argument>]\n          at most 256 bytes, read within a 2 s deadline
//   reply   : {"ok":true,"result":<json>}\n  or  {"ok":false,"error":"<text>"}\n
//
// The channel is read-only: it reports status, coverage and inventory state and changes nothing.
// The socket is created 0600 and every peer is checked with SO_PEERCRED before its request is read.

struct control_peer {
    uid_t uid{};
    gid_t gid{};
    pid_t pid{};
};

struct control_reply {
    bool ok{true};
    std::string body;  // ok: a JSON value; otherwise a plain error message
};

class control_server {
public:
    using handler = std::function<control_reply(std::string_view command, std::string_view argument)>;
    using authorizer = std::function<bool(const control_peer&)>;

    // Default authorizer: root, or the user the daemon itself runs as.
    [[nodiscard]] static bool default_authorizer(const control_peer& peer);

    control_server(std::filesystem::path socket_path, handler on_request, authorizer allow = default_authorizer);
    ~control_server();
    control_server(const control_server&) = delete;
    control_server& operator=(const control_server&) = delete;

    // Binds the socket (replacing a stale socket, refusing to replace anything else) and starts
    // the serving thread.
    [[nodiscard]] result<bool> start();
    void stop();

    [[nodiscard]] std::uint64_t served() const noexcept { return served_.load(); }
    [[nodiscard]] std::uint64_t rejected() const noexcept { return rejected_.load(); }

private:
    void serve();
    void handle(int connection);

    std::filesystem::path path_;
    handler on_request_;
    authorizer allow_;
    int listen_fd_{-1};
    int wake_fd_{-1};
    std::thread thread_;
    std::atomic<std::uint64_t> served_{0U};
    std::atomic<std::uint64_t> rejected_{0U};
};

struct control_sources {
    std::function<std::string()> status;    // JSON object (health body)
    std::function<std::string()> coverage;  // JSON object (capability -> provider)
    host_state_options state_options;
};

// Dispatches `status`, `coverage` and `state <object|list>`; anything else is an error reply.
[[nodiscard]] control_server::handler make_control_handler(control_sources sources);

// Client side: sends one request line and returns the raw reply line (without the newline).
[[nodiscard]] result<std::string> control_request(const std::filesystem::path& socket_path, std::string_view line,
                                                  std::chrono::milliseconds timeout);

}  // namespace panopticon::linux_agent::sensor
