// panopticon-ctl: read-only client for the sensord control socket.
//
//   panopticon-ctl [--socket PATH] status
//   panopticon-ctl [--socket PATH] coverage
//   panopticon-ctl [--socket PATH] state list
//   panopticon-ctl [--socket PATH] state <object>
//
// Prints the daemon's one-line JSON reply; exit status 0 only when the reply is {"ok":true,...}.

#include "panopticon/linux_agent/sensor/control.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>

namespace sensor = panopticon::linux_agent::sensor;

namespace {

int usage() {
    std::fprintf(stderr,
                 "usage: panopticon-ctl [--socket PATH] status\n"
                 "       panopticon-ctl [--socket PATH] coverage\n"
                 "       panopticon-ctl [--socket PATH] state (list | <object>)\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string socket_path = "/run/panopticon/sensord.sock";
    std::string request;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--socket") {
            if (index + 1 >= argc) return usage();
            socket_path = argv[++index];
        } else if (argument.substr(0U, 2U) == "--") {
            return usage();
        } else {
            if (!request.empty()) request.push_back(' ');
            request.append(argument);
        }
    }
    if (request.empty()) return usage();

    const auto reply = sensor::control_request(socket_path, request, std::chrono::seconds{5});
    if (!panopticon::linux_agent::succeeded(reply)) {
        std::fprintf(stderr, "panopticon-ctl: %s\n", std::get<panopticon::linux_agent::error>(reply).message.c_str());
        return 1;
    }
    const auto& text = std::get<std::string>(reply);
    std::printf("%s\n", text.c_str());
    return text.rfind("{\"ok\":true", 0U) == 0U ? 0 : 1;
}
