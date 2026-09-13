// Minimal CLI wrapper around request_isolation() -- lets the e2e shell
// script exercise the real IPC client without needing a full agent
// configuration. Not part of the agent or the helper; test-only.
#include "panopticon/linux_agent/isolation.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: isolation-client-tool <socket-path> <isolate|release> <command-id>\n");
        return 2;
    }
    const std::string socket_path{argv[1]};
    const std::string verb{argv[2]};
    const std::string command_id{argv[3]};
    const auto opcode = verb == "isolate" ? panopticon::linux_agent::isolation_opcode::isolate
                                           : panopticon::linux_agent::isolation_opcode::release;
    if (verb != "isolate" && verb != "release") {
        std::fprintf(stderr, "verb must be exactly 'isolate' or 'release'\n");
        return 2;
    }
    const auto result = panopticon::linux_agent::request_isolation(socket_path, opcode, command_id);
    if (!panopticon::linux_agent::succeeded(result)) {
        std::fprintf(stderr, "isolation-client-tool: request failed\n");
        return 1;
    }
    if (!std::get<bool>(result)) {
        std::fprintf(stderr, "isolation-client-tool: helper rejected the request\n");
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
