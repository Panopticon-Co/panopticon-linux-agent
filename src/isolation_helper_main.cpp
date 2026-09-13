// panopticon-isolation-helper: the ONLY process in this system that holds
// CAP_NET_ADMIN. See docs/adr/004-host-isolation-privilege-boundary.md.
//
// Speaks exactly the 2-opcode protocol in isolation.hpp over a local
// AF_UNIX SOCK_SEQPACKET socket. Never executes a shell, `nft`, or any
// other subprocess -- isolation is applied/released purely via netlink
// (isolation_ruleset.cpp).
#include "panopticon/linux_agent/isolation.hpp"
#include "panopticon/linux_agent/isolation_ruleset.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

namespace {

using panopticon::linux_agent::decode_isolation_request;
using panopticon::linux_agent::isolation_opcode;
using panopticon::linux_agent::kIsolationRequestFrameSize;
using panopticon::linux_agent::kIsolationStatusOk;
using panopticon::linux_agent::kIsolationStatusRejected;
using panopticon::linux_agent::apply_isolation_ruleset;
using panopticon::linux_agent::release_isolation_ruleset;
using panopticon::linux_agent::succeeded;

// Durable local record of the last applied state, so a crash or restart
// re-applies the same state rather than silently un-isolating (fail-closed
// per ADR 004). Deliberately a tiny two-line format, not JSON -- this file
// is written by this process only and read by no other tool.
struct isolation_state {
    bool isolated{false};
    std::string command_id;
};

isolation_state load_state(const std::string& state_path) {
    std::ifstream input{state_path};
    isolation_state state{};
    std::string line;
    if (std::getline(input, line) && line == "isolated") {
        state.isolated = true;
        std::getline(input, state.command_id);
    }
    return state;
}

bool save_state(const std::string& state_path, const isolation_state& state) {
    std::ofstream output{state_path, std::ios::trunc};
    if (!output) return false;
    if (state.isolated) output << "isolated\n" << state.command_id << '\n';
    output.flush();
    return static_cast<bool>(output);
}

std::uint32_t resolve_manager_ipv4(const std::string& host) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
        std::fprintf(stderr, "isolation-helper: cannot resolve manager host '%s'\n", host.c_str());
        std::exit(1);
    }
    const auto address = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(result);
    return address;
}

int listening_socket(const std::string& socket_path) {
    unlink(socket_path.c_str());
    const int descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor < 0) { std::perror("socket"); std::exit(1); }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(address.sun_path)) {
        std::fprintf(stderr, "isolation-helper: socket path too long\n");
        std::exit(1);
    }
    std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1U);
    if (bind(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        std::perror("bind");
        std::exit(1);
    }
    chmod(socket_path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (listen(descriptor, 8) != 0) { std::perror("listen"); std::exit(1); }
    return descriptor;
}

// Defense in depth beyond socket-file permissions: reject a peer that
// isn't the expected agent UID, even though only that UID's group should
// ever be able to open the socket in the first place.
bool peer_is_expected_agent(const int connection, const uid_t expected_uid) {
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0) return false;
    return credentials.uid == expected_uid;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 6) {
        std::fprintf(stderr, "usage: panopticon-isolation-helper <socket-path> <state-path> <manager-host> <manager-port> <expected-agent-username>\n");
        return 2;
    }
    const std::string socket_path{argv[1]};
    const std::string state_path{argv[2]};
    const std::string manager_host{argv[3]};
    const auto manager_port = static_cast<std::uint16_t>(std::strtoul(argv[4], nullptr, 10));
    if (manager_port == 0U) {
        std::fprintf(stderr, "isolation-helper: manager port must be nonzero\n");
        return 2;
    }
    const passwd* agent_user = getpwnam(argv[5]);
    if (agent_user == nullptr) {
        std::fprintf(stderr, "isolation-helper: unknown expected agent username '%s'\n", argv[5]);
        return 2;
    }
    const uid_t expected_uid = agent_user->pw_uid;

    // Resolved once, at startup, per ADR 004 -- never re-resolved while
    // running, so a DNS outage during isolation can neither be exploited
    // to bypass it nor silently prolong it.
    const auto manager_ipv4 = resolve_manager_ipv4(manager_host);

    auto state = load_state(state_path);
    if (state.isolated) {
        std::fprintf(stderr, "isolation-helper: re-applying isolation recorded before restart (command_id=%s)\n", state.command_id.c_str());
        if (!succeeded(apply_isolation_ruleset(manager_ipv4, manager_port))) {
            std::fprintf(stderr, "isolation-helper: fail-closed re-apply failed; exiting rather than serving with unknown firewall state\n");
            return 1;
        }
    }

    const int server = listening_socket(socket_path);
    std::fprintf(stderr, "isolation-helper: listening on %s\n", socket_path.c_str());

    for (;;) {
        const int connection = accept4(server, nullptr, nullptr, SOCK_CLOEXEC);
        if (connection < 0) continue;
        if (!peer_is_expected_agent(connection, expected_uid)) { close(connection); continue; }

        // Sized one byte larger than the only legal frame: a SOCK_SEQPACKET
        // recv() into a buffer exactly the frame's size cannot distinguish a
        // valid frame from an oversized packet silently truncated to fit --
        // the kernel just discards the excess and reports the buffer-capped
        // length. Making the buffer one byte bigger means any oversized
        // packet reports a received length that is provably not the exact
        // frame size, so it is rejected here rather than having its
        // (attacker-controlled) truncated prefix parsed as if it were valid.
        char buffer[kIsolationRequestFrameSize + 1U];
        const auto received = recv(connection, buffer, sizeof(buffer), 0);
        std::uint8_t status = kIsolationStatusRejected;
        if (received == static_cast<ssize_t>(kIsolationRequestFrameSize)) {
            const auto decoded = decode_isolation_request(std::string_view{buffer, kIsolationRequestFrameSize});
            if (succeeded(decoded)) {
                const auto& [opcode, command_id] = std::get<std::pair<isolation_opcode, std::string>>(decoded);
                if (opcode == isolation_opcode::isolate) {
                    // Idempotent: re-applying while already isolated is a
                    // no-op success, not an error, so a retried command
                    // cannot fail or double-apply.
                    const auto applied = apply_isolation_ruleset(manager_ipv4, manager_port);
                    if (!succeeded(applied)) {
                        std::fprintf(stderr, "isolation-helper: apply failed: %s\n", std::get<panopticon::linux_agent::error>(applied).message.c_str());
                    } else if (!save_state(state_path, {true, command_id})) {
                        std::fprintf(stderr, "isolation-helper: could not persist isolation state\n");
                    } else {
                        status = kIsolationStatusOk;
                    }
                } else if (opcode == isolation_opcode::release) {
                    const auto released = release_isolation_ruleset();
                    if (!succeeded(released)) {
                        std::fprintf(stderr, "isolation-helper: release failed: %s\n", std::get<panopticon::linux_agent::error>(released).message.c_str());
                    } else if (!save_state(state_path, {false, ""})) {
                        std::fprintf(stderr, "isolation-helper: could not persist release state\n");
                    } else {
                        status = kIsolationStatusOk;
                    }
                }
            }
        }
        (void)send(connection, &status, sizeof(status), 0);
        close(connection);
    }
}
