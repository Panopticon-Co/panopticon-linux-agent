#include "panopticon/linux_agent/sensor/control.hpp"
#include "panopticon/linux_agent/sensor/pipeline.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifndef PANOPTICON_CTL_PATH
#error "PANOPTICON_CTL_PATH must name the panopticon-ctl binary"
#endif

namespace {

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;
using std::chrono::milliseconds;

int failures = 0;
int skipped = 0;

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

bool contains(const std::string_view haystack, const std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

std::string text_of(result<std::string> outcome, const std::string& what) {
    if (!succeeded(outcome)) throw std::runtime_error{what + ": " + std::get<error>(outcome).message};
    return std::move(std::get<std::string>(outcome));
}

// Short paths: sun_path is only ~107 bytes.
fs::path fresh_directory(const std::string& name) {
    const auto directory = fs::temp_directory_path() / ("pcc-" + std::to_string(::getpid())) / name;
    fs::remove_all(directory);
    fs::create_directories(directory);
    return directory;
}

void write_file(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << contents;
}

// Raw client: connects, optionally sends bytes, reads one line (or until close / timeout).
std::string raw_exchange(const fs::path& path, const std::string& bytes, const milliseconds wait = milliseconds{3000}) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "socket");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1U);
    require(::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "connect");
    if (!bytes.empty()) (void)!::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    std::string reply;
    const auto deadline = std::chrono::steady_clock::now() + wait;
    while (reply.find('\n') == std::string::npos) {
        const auto left = std::chrono::duration_cast<milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) break;
        pollfd descriptor{fd, POLLIN, 0};
        if (::poll(&descriptor, 1, static_cast<int>(left)) <= 0) break;
        char buffer[4096];
        const auto got = ::recv(fd, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        reply.append(buffer, static_cast<std::size_t>(got));
    }
    ::close(fd);
    return reply;
}

control_server::handler echo_handler() {
    return [](const std::string_view command, const std::string_view argument) -> control_reply {
        if (command == "status") return {true, "{\"status\":\"healthy\"}"};
        if (command == "echo") return {true, "\"" + std::string{argument} + "\""};
        return {false, "unknown command"};
    };
}

void test_round_trip_and_errors() {
    const auto dir = fresh_directory("rt");
    control_server server{dir / "c.sock", echo_handler()};
    const auto started = server.start();
    require(succeeded(started), "start");
    const auto ok = text_of(control_request(dir / "c.sock", "status", milliseconds{3000}), "status");
    require(ok == "{\"ok\":true,\"result\":{\"status\":\"healthy\"}}", "ok reply: " + ok);
    require(text_of(control_request(dir / "c.sock", "echo hi there", milliseconds{3000}), "echo") == "{\"ok\":true,\"result\":\"hi there\"}", "argument passed through");
    const auto bad = text_of(control_request(dir / "c.sock", "format-disk", milliseconds{3000}), "unknown");
    require(bad == "{\"ok\":false,\"error\":\"unknown command\"}", "error reply: " + bad);
    require(server.served() == 3U, "served counter");
    server.stop();
    require(!fs::exists(dir / "c.sock"), "socket removed on stop");
    require(!succeeded(control_request(dir / "c.sock", "status", milliseconds{500})), "no server, no reply");
}

void test_socket_is_private() {
    const auto dir = fresh_directory("mode");
    control_server server{dir / "c.sock", echo_handler()};
    require(succeeded(server.start()), "start");
    struct stat info {};
    require(::lstat((dir / "c.sock").c_str(), &info) == 0 && S_ISSOCK(info.st_mode), "is a socket");
    require((info.st_mode & 0777) == 0600, "mode is 0600, not " + std::to_string(info.st_mode & 0777));
}

void test_unauthorized_peer_is_refused_without_reading() {
    const auto dir = fresh_directory("auth");
    std::atomic<int> invoked{0};
    control_server server{dir / "c.sock", [&](std::string_view, std::string_view) -> control_reply { ++invoked; return {true, "1"}; },
                          [](const control_peer& peer) { return peer.uid == 0xFFFFFFF0U; }};
    require(succeeded(server.start()), "start");
    const auto reply = text_of(control_request(dir / "c.sock", "status", milliseconds{3000}), "unauthorized");
    require(reply == "{\"ok\":false,\"error\":\"unauthorized\"}", "unauthorized reply: " + reply);
    require(invoked.load() == 0 && server.rejected() == 1U, "handler never ran");
}

void test_malformed_requests() {
    const auto dir = fresh_directory("bad");
    control_server server{dir / "c.sock", echo_handler()};
    require(succeeded(server.start()), "start");
    const auto too_long = raw_exchange(dir / "c.sock", std::string(600U, 'A'));
    require(contains(too_long, "request too long"), "oversized request refused: " + too_long);
    const auto control_chars = raw_exchange(dir / "c.sock", std::string{"status\x01\x1b[2J\n"});
    require(contains(control_chars, "invalid characters"), "control characters refused: " + control_chars);
    // Never terminated: the server's 2 s deadline answers. The client waits well past it (5 s more) because a
    // stalled VM has failed this test with an empty reply when the margin was 1 s.
    const auto half = raw_exchange(dir / "c.sock", "status", milliseconds{7000});
    require(contains(half, "request timed out") || contains(half, "incomplete request"), "unterminated request refused: " + half);
    // The server survived all of that.
    require(contains(text_of(control_request(dir / "c.sock", "status", milliseconds{3000}), "after abuse"), "\"ok\":true"), "still serving");
}

void test_stalled_client_does_not_block_others() {
    const auto dir = fresh_directory("stall");
    control_server server{dir / "c.sock", echo_handler()};
    require(succeeded(server.start()), "start");
    // A client that connects and says nothing holds the single-threaded server for at most the
    // 2 s connection deadline, after which a normal client is served.
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, (dir / "c.sock").c_str(), sizeof(address.sun_path) - 1U);
    require(::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "connect");
    const auto started = std::chrono::steady_clock::now();
    const auto reply = text_of(control_request(dir / "c.sock", "status", milliseconds{6000}), "behind stalled client");
    const auto waited = std::chrono::duration_cast<milliseconds>(std::chrono::steady_clock::now() - started).count();
    ::close(fd);
    require(contains(reply, "\"ok\":true"), "served after the stalled client timed out");
    require(waited < 4500, "stalled client held the server for " + std::to_string(waited) + " ms");
}

void test_socket_path_safety() {
    const auto dir = fresh_directory("safe");
    write_file(dir / "precious", "do not delete");
    control_server refuses{dir / "precious", echo_handler()};
    const auto refused = refuses.start();
    require(!succeeded(refused), "start over a regular file must fail");
    std::ifstream check{dir / "precious"};
    std::string contents;
    std::getline(check, contents);
    require(contents == "do not delete", "regular file untouched");

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, (dir / "stale.sock").c_str(), sizeof(address.sun_path) - 1U);
    require(::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "make a stale socket");
    ::close(fd);
    control_server replaces{dir / "stale.sock", echo_handler()};
    require(succeeded(replaces.start()), "stale socket replaced");
    require(contains(text_of(control_request(dir / "stale.sock", "status", milliseconds{3000}), "after replace"), "\"ok\":true"), "serves on replaced path");

    control_server too_long{fs::path{"/tmp/" + std::string(200U, 'x')}, echo_handler()};
    require(!succeeded(too_long.start()), "over-long path rejected");
}

fs::path fake_host_root() {
    const auto root = fresh_directory("host");
    write_file(root / "proc/sys/kernel/hostname", "ctlhost\n");
    write_file(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    return root;
}

void test_state_commands_through_handler() {
    control_sources sources;
    sources.state_options.root = fake_host_root();
    sources.status = [] { return std::string{"{\"status\":\"healthy\"}"}; };
    sources.coverage = [] { return std::string{"{\"process.exec\":\"ebpf_process\"}"}; };
    const auto handler = make_control_handler(sources);
    const auto list = handler("state", "list");
    require(list.ok && contains(list.body, "\"host\"") && contains(list.body, "\"modules\""), "state list: " + list.body);
    const auto host = handler("state", "host");
    require(host.ok && contains(host.body, "\"hostname\":\"ctlhost\"") && contains(host.body, "\"unavailable\":["), "state host: " + host.body);
    const auto users = handler("state", "users");
    require(users.ok && contains(users.body, "\"name\":\"root\""), "state users: " + users.body);
    require(!handler("state", "").ok && !handler("state", "nonsense").ok && !handler("state", "../../etc/passwd").ok, "bad state arguments rejected");
    require(handler("coverage", "").body == "{\"process.exec\":\"ebpf_process\"}", "coverage passthrough");
    require(!handler("shell", "id").ok && !handler("", "").ok, "unknown commands rejected");
}

int run_ctl(const fs::path& socket, const std::vector<std::string>& arguments, std::string& output) {
    int pipe_fds[2];
    require(::pipe(pipe_fds) == 0, "pipe");
    const auto child = ::fork();
    require(child >= 0, "fork");
    if (child == 0) {
        ::dup2(pipe_fds[1], STDOUT_FILENO);
        ::dup2(pipe_fds[1], STDERR_FILENO);
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        std::vector<std::string> storage{PANOPTICON_CTL_PATH, "--socket", socket.string()};
        for (const auto& argument : arguments) storage.push_back(argument);
        std::vector<char*> argv;
        for (auto& item : storage) argv.push_back(item.data());
        argv.push_back(nullptr);
        ::execv(argv[0], argv.data());
        ::_exit(127);
    }
    ::close(pipe_fds[1]);
    output.clear();
    char buffer[4096];
    for (ssize_t got = ::read(pipe_fds[0], buffer, sizeof(buffer)); got > 0; got = ::read(pipe_fds[0], buffer, sizeof(buffer))) {
        output.append(buffer, static_cast<std::size_t>(got));
    }
    ::close(pipe_fds[0]);
    int status = 0;
    ::waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void test_ctl_binary() {
    const auto dir = fresh_directory("ctl");
    control_sources sources;
    sources.state_options.root = fake_host_root();
    sources.status = [] { return std::string{"{\"status\":\"healthy\"}"}; };
    control_server server{dir / "c.sock", make_control_handler(sources)};
    require(succeeded(server.start()), "start");
    std::string output;
    require(run_ctl(dir / "c.sock", {"status"}, output) == 0 && contains(output, "\"healthy\""), "ctl status: " + output);
    require(run_ctl(dir / "c.sock", {"state", "list"}, output) == 0 && contains(output, "\"interfaces\""), "ctl state list: " + output);
    require(run_ctl(dir / "c.sock", {"state", "host"}, output) == 0 && contains(output, "ctlhost"), "ctl state host: " + output);
    require(run_ctl(dir / "c.sock", {"state", "bogus"}, output) == 1 && contains(output, "unknown state object"), "ctl error exit status: " + output);
    require(run_ctl(dir / "c.sock", {}, output) == 2, "ctl usage exit status");
    server.stop();
    require(run_ctl(dir / "c.sock", {"status"}, output) == 1 && contains(output, "panopticon-ctl:"), "ctl without a daemon: " + output);
}

// The pipeline thread keeps stepping while a client queries status over the real socket; run
// under TSAN this proves the cached status is the only shared state.
void test_status_from_a_running_pipeline() {
    const auto dir = fresh_directory("pipe");
    fs::create_directories(dir / "proc");
    sensor_config config;
    config.sensor_id = "sensor-ctl";
    config.host_id = "host-ctl";
    config.proc_root = dir / "proc";
    config.host_root = fake_host_root();
    clock_domain clock;
    std::FILE* stream = std::tmpfile();
    stream_sink sink{stream};
    sensor_pipeline pipeline{config, {"host-ctl", "boot-ctl", "ctlhost", "sensor-ctl", "0.1.0", "none"}, clock, sink, {}};
    require(succeeded(pipeline.start()), "pipeline start");

    control_sources sources;
    sources.status = [&pipeline] { return pipeline.status_json(); };
    sources.coverage = [&pipeline] { return pipeline.coverage_json(); };
    sources.state_options.root = config.host_root;
    control_server server{dir / "c.sock", make_control_handler(sources)};
    require(succeeded(server.start()), "control start");

    std::atomic<bool> stop{false};
    std::thread stepper{[&] {
        while (!stop.load()) (void)pipeline.step(clock_domain::now_monotonic_ns() + 2'000'000'000ULL, milliseconds{1});
    }};
    std::string last;
    for (int index = 0; index < 20; ++index) {
        last = text_of(control_request(dir / "c.sock", index % 2 == 0 ? "status" : "coverage", milliseconds{3000}), "query");
        require(contains(last, "\"ok\":true"), "query ok: " + last);
    }
    stop = true;
    stepper.join();
    const auto status = text_of(control_request(dir / "c.sock", "status", milliseconds{3000}), "status");
    require(contains(status, "\"status\":") && contains(status, "\"providers\":[") && contains(status, "\"procfs\""), "status carries provider health: " + status);
    const auto coverage = text_of(control_request(dir / "c.sock", "coverage", milliseconds{3000}), "coverage");
    require(contains(coverage, "\"process.discovered\":\"procfs\""), "coverage names its provider: " + coverage);
    server.stop();
    pipeline.shutdown();
    std::fclose(stream);
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
    run("round_trip_and_errors", test_round_trip_and_errors);
    run("socket_is_private", test_socket_is_private);
    run("unauthorized_peer_is_refused_without_reading", test_unauthorized_peer_is_refused_without_reading);
    run("malformed_requests", test_malformed_requests);
    run("stalled_client_does_not_block_others", test_stalled_client_does_not_block_others);
    run("socket_path_safety", test_socket_path_safety);
    run("state_commands_through_handler", test_state_commands_through_handler);
    run("ctl_binary", test_ctl_binary);
    run("status_from_a_running_pipeline", test_status_from_a_running_pipeline);
    std::error_code ignored;
    fs::remove_all(fs::temp_directory_path() / ("pcc-" + std::to_string(::getpid())), ignored);
    std::cout << (failures == 0 ? "ALL PASSED" : "FAILURES: " + std::to_string(failures)) << " (skipped " << skipped << ")\n";
    return failures == 0 ? 0 : 1;
}
