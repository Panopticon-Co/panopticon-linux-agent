#include "panopticon/linux_agent/sensor/control.hpp"

#include "panopticon/linux_agent/sensor/json.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <system_error>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::size_t maximum_request_bytes = 256U;
constexpr std::size_t maximum_reply_bytes = 32U * 1024U * 1024U;
constexpr std::chrono::milliseconds connection_deadline{2000};

error io_error(const std::string& what) {
    return {error_code::io_failure, what + ": " + std::strerror(errno)};
}

std::chrono::steady_clock::time_point now() { return std::chrono::steady_clock::now(); }

int remaining_ms(const std::chrono::steady_clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now()).count();
    return left <= 0 ? 0 : static_cast<int>(std::min<long long>(left, 1'000'000));
}

// Waits for `events` on `fd` until the deadline. False on timeout or error.
bool wait_for(const int fd, const short events, const std::chrono::steady_clock::time_point deadline) {
    while (true) {
        pollfd descriptor{fd, events, 0};
        const auto ready = ::poll(&descriptor, 1, remaining_ms(deadline));
        if (ready > 0) return (descriptor.revents & (events | POLLHUP)) != 0;
        if (ready == 0) return false;
        if (errno != EINTR) return false;
    }
}

bool send_all(const int fd, const std::string_view data, const std::chrono::steady_clock::time_point deadline) {
    std::size_t sent = 0U;
    while (sent < data.size()) {
        const auto wrote = ::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (wrote > 0) {
            sent += static_cast<std::size_t>(wrote);
        } else if (wrote < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!wait_for(fd, POLLOUT, deadline)) return false;
        } else if (wrote < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

std::string error_reply(const std::string_view message) {
    json_writer out;
    out.begin_object().field("ok", false).field("error", message).end_object();
    return out.take() + "\n";
}

std::string ok_reply(const std::string_view body) {
    std::string reply{"{\"ok\":true,\"result\":"};
    reply.append(body).append("}\n");
    return reply;
}

}  // namespace

bool control_server::default_authorizer(const control_peer& peer) { return peer.uid == 0U || peer.uid == ::geteuid(); }

control_server::control_server(std::filesystem::path socket_path, handler on_request, authorizer allow)
    : path_{std::move(socket_path)}, on_request_{std::move(on_request)}, allow_{std::move(allow)} {}

control_server::~control_server() { stop(); }

result<bool> control_server::start() {
    if (listen_fd_ >= 0) return true;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto text = path_.string();
    if (text.empty() || text.size() >= sizeof(address.sun_path)) return error{error_code::invalid_input, "control socket path is empty or too long"};
    std::memcpy(address.sun_path, text.c_str(), text.size() + 1U);

    // A stale socket from a previous run is replaced; any other file type is never touched.
    struct stat existing {};
    if (::lstat(text.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode)) return error{error_code::invalid_input, "refusing to replace a non-socket at " + text};
        ::unlink(text.c_str());
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return io_error("control socket");
    // The mode of a unix socket file comes from the umask at bind time: restrict it first so there
    // is no window in which other users could connect. The umask is process-wide, but only for
    // the duration of bind(), and a concurrent file creation in that window gets stricter modes.
    const auto previous_umask = ::umask(0177);
    const int bound = ::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    const int bind_errno = errno;
    ::umask(previous_umask);
    if (bound != 0) {
        ::close(fd);
        errno = bind_errno;
        return io_error("bind " + text);
    }
    ::chmod(text.c_str(), 0600);
    if (::listen(fd, 8) != 0) {
        const auto failure = io_error("listen " + text);
        ::close(fd);
        ::unlink(text.c_str());
        return failure;
    }
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        const auto failure = io_error("eventfd");
        ::close(fd);
        ::unlink(text.c_str());
        return failure;
    }
    listen_fd_ = fd;
    thread_ = std::thread{[this] { serve(); }};
    return true;
}

void control_server::stop() {
    if (listen_fd_ < 0) return;
    const std::uint64_t one = 1U;
    (void)!::write(wake_fd_, &one, sizeof(one));
    if (thread_.joinable()) thread_.join();
    ::close(listen_fd_);
    ::close(wake_fd_);
    listen_fd_ = wake_fd_ = -1;
    // Only a socket is removed: if something else has since taken the path, leave it.
    struct stat existing {};
    if (::lstat(path_.c_str(), &existing) == 0 && S_ISSOCK(existing.st_mode)) ::unlink(path_.c_str());
}

void control_server::serve() {
    while (true) {
        pollfd descriptors[2] = {{listen_fd_, POLLIN, 0}, {wake_fd_, POLLIN, 0}};
        if (::poll(descriptors, 2, -1) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if ((descriptors[1].revents & POLLIN) != 0) return;
        if ((descriptors[0].revents & POLLIN) == 0) continue;
        const int connection = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (connection < 0) continue;
        handle(connection);
        ::close(connection);
    }
}

void control_server::handle(const int connection) {
    const auto deadline = now() + connection_deadline;

    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 || !allow_({credentials.uid, credentials.gid, credentials.pid})) {
        rejected_.fetch_add(1U);
        (void)send_all(connection, error_reply("unauthorized"), deadline);
        return;
    }

    std::string line;
    bool complete = false;
    while (!complete) {
        char buffer[maximum_request_bytes + 1U];
        const auto got = ::recv(connection, buffer, sizeof(buffer), 0);
        if (got > 0) {
            line.append(buffer, static_cast<std::size_t>(got));
            if (const auto newline = line.find('\n'); newline != std::string::npos) {
                line.resize(newline);
                complete = true;
            } else if (line.size() > maximum_request_bytes) {
                rejected_.fetch_add(1U);
                (void)send_all(connection, error_reply("request too long"), deadline);
                return;
            }
        } else if (got == 0) {
            break;  // peer closed before sending a full line
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!wait_for(connection, POLLIN, deadline)) {
                rejected_.fetch_add(1U);
                (void)send_all(connection, error_reply("request timed out"), deadline);
                return;
            }
        } else if (errno != EINTR) {
            return;
        }
    }
    if (!complete || line.size() > maximum_request_bytes) {
        rejected_.fetch_add(1U);
        (void)send_all(connection, error_reply("incomplete request"), deadline);
        return;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    for (const char ch : line) {
        if (static_cast<unsigned char>(ch) < 0x20U || static_cast<unsigned char>(ch) == 0x7FU) {
            rejected_.fetch_add(1U);
            (void)send_all(connection, error_reply("invalid characters in request"), deadline);
            return;
        }
    }

    const std::string_view request{line};
    const auto space = request.find(' ');
    const auto command = request.substr(0U, space);
    const auto argument = space == std::string_view::npos ? std::string_view{} : request.substr(space + 1U);
    control_reply reply;
    try {
        reply = on_request_(command, argument);
    } catch (const std::exception& failure) {
        reply = {false, std::string{"internal error: "} + failure.what()};
    }
    served_.fetch_add(1U);
    (void)send_all(connection, reply.ok ? ok_reply(reply.body) : error_reply(reply.body), deadline);
}

control_server::handler make_control_handler(control_sources sources) {
    return [sources = std::move(sources)](const std::string_view command, const std::string_view argument) -> control_reply {
        if (command == "status") return {true, sources.status ? sources.status() : "{}"};
        if (command == "coverage") return {true, sources.coverage ? sources.coverage() : "{}"};
        if (command == "state") {
            if (argument.empty()) return {false, "usage: state <object|list>"};
            if (argument == "list") {
                json_writer out;
                out.begin_array();
                for (const auto object : state_objects()) out.value(object);
                out.end_array();
                return {true, out.take()};
            }
            const auto collected = collect_state(argument, sources.state_options);
            if (!collected.has_value()) return {false, "unknown state object"};
            json_writer out;
            out.begin_object();
            out.field("object", collected->object).field("provider", collected->provider).field("mechanism", collected->mechanism);
            out.field("truncated", collected->truncated);
            out.key("items").begin_array();
            for (const auto& item : collected->items) out.raw(item);
            out.end_array();
            out.key("unavailable").begin_array();
            for (const auto& field : collected->unavailable) {
                out.begin_object().field("field", field.field).field("reason", to_string(field.reason)).end_object();
            }
            out.end_array();
            out.end_object();
            return {true, out.take()};
        }
        return {false, "unknown command"};
    };
}

result<std::string> control_request(const std::filesystem::path& socket_path, const std::string_view line,
                                    const std::chrono::milliseconds timeout) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto text = socket_path.string();
    if (text.empty() || text.size() >= sizeof(address.sun_path)) return error{error_code::invalid_input, "control socket path is empty or too long"};
    std::memcpy(address.sun_path, text.c_str(), text.size() + 1U);

    const auto deadline = now() + timeout;
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return io_error("socket");
    struct closer {
        int fd;
        ~closer() { ::close(fd); }
    } guard{fd};

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) return io_error("connect " + text);
        if (!wait_for(fd, POLLOUT, deadline)) return error{error_code::io_failure, "connect " + text + ": timed out"};
        int status = 0;
        socklen_t size = sizeof(status);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &size);
        if (status != 0) {
            errno = status;
            return io_error("connect " + text);
        }
    }
    std::string request{line};
    request.push_back('\n');
    if (!send_all(fd, request, deadline)) return error{error_code::io_failure, "send to " + text + " failed"};

    std::string reply;
    while (true) {
        char buffer[8192];
        const auto got = ::recv(fd, buffer, sizeof(buffer), 0);
        if (got > 0) {
            reply.append(buffer, static_cast<std::size_t>(got));
            if (reply.size() > maximum_reply_bytes) return error{error_code::resource_limit, "control reply too large"};
            if (const auto newline = reply.find('\n'); newline != std::string::npos) {
                reply.resize(newline);
                return reply;
            }
        } else if (got == 0) {
            break;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!wait_for(fd, POLLIN, deadline)) return error{error_code::io_failure, "control reply timed out"};
        } else if (errno != EINTR) {
            return io_error("recv");
        }
    }
    if (reply.empty()) return error{error_code::io_failure, "control socket closed without a reply"};
    return reply;
}

}  // namespace panopticon::linux_agent::sensor
