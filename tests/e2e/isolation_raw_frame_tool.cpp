// Sends an arbitrary raw byte string to the isolation helper's socket,
// bypassing encode_isolation_request() entirely. Test-only: the real agent
// can never construct anything but a well-formed frame, so this tool exists
// purely to let the e2e script prove the helper rejects malformed/oversized
// input from a hostile peer instead of crashing or misparsing it.
//
// Usage: isolation-raw-frame-tool <socket-path> <byte-count> <fill-byte-hex>
// Sends <byte-count> bytes, each equal to <fill-byte-hex> (e.g. "01").
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: isolation-raw-frame-tool <socket-path> <byte-count> <fill-byte-hex>\n");
        return 2;
    }
    const std::string socket_path{argv[1]};
    const auto byte_count = static_cast<std::size_t>(std::strtoul(argv[2], nullptr, 10));
    const auto fill_byte = static_cast<char>(std::strtoul(argv[3], nullptr, 16));

    const int socket_descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (socket_descriptor < 0) { std::perror("socket"); return 1; }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(address.sun_path)) {
        std::fprintf(stderr, "socket path too long\n");
        return 2;
    }
    std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1U);
    if (connect(socket_descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        std::perror("connect");
        close(socket_descriptor);
        return 1;
    }
    std::string frame(byte_count, fill_byte);
    if (const auto sent = send(socket_descriptor, frame.data(), frame.size(), 0);
        sent != static_cast<ssize_t>(frame.size())) {
        std::perror("send");
        close(socket_descriptor);
        return 1;
    }
    std::uint8_t status{0xFFU};
    const auto received = recv(socket_descriptor, &status, sizeof(status), 0);
    close(socket_descriptor);
    if (received != static_cast<ssize_t>(sizeof(status))) {
        // No response at all is a valid outcome for some malformed inputs
        // (e.g. the connection is simply closed) -- report it distinctly
        // from an explicit reject/ok status rather than treating it as a
        // tool failure the e2e script can't interpret.
        std::printf("no-response\n");
        return 0;
    }
    std::printf(status == 0U ? "ok\n" : "rejected\n");
    return 0;
}
