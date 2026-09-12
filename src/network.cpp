#include "panopticon/linux_agent/network.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace panopticon::linux_agent {
namespace {

std::optional<std::pair<std::string, std::uint16_t>> parse_endpoint(const std::string_view endpoint) {
    const auto delimiter = endpoint.find(':');
    if (delimiter == std::string_view::npos || endpoint.size() != 13U) {
        return std::nullopt;
    }
    try {
        const auto address = static_cast<std::uint32_t>(std::stoul(std::string{endpoint.substr(0U, delimiter)}, nullptr, 16));
        const auto port = static_cast<std::uint16_t>(std::stoul(std::string{endpoint.substr(delimiter + 1U)}, nullptr, 16));
        std::ostringstream formatted;
        formatted << (address & 0xFFU) << '.' << ((address >> 8U) & 0xFFU) << '.' << ((address >> 16U) & 0xFFU) << '.'
                  << ((address >> 24U) & 0xFFU);
        return std::pair{formatted.str(), port};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string tcp_state(const std::string_view value) {
    if (value == "01") return "established";
    if (value == "0A") return "listen";
    if (value == "06") return "time_wait";
    return "other";
}

}  // namespace

result<std::vector<network_connection>> parse_proc_net_tcp(const std::string_view contents, const std::size_t maximum_connections) {
    if (maximum_connections == 0U) {
        return error{error_code::invalid_input, "network connection limit must be positive"};
    }
    std::istringstream lines{std::string{contents}};
    std::string line;
    std::getline(lines, line);
    std::vector<network_connection> connections;
    while (std::getline(lines, line) && connections.size() < maximum_connections) {
        std::istringstream fields{line};
        std::string slot;
        std::string local;
        std::string remote;
        std::string state;
        if (!(fields >> slot >> local >> remote >> state)) {
            continue;
        }
        const auto local_endpoint = parse_endpoint(local);
        const auto remote_endpoint = parse_endpoint(remote);
        if (!local_endpoint.has_value() || !remote_endpoint.has_value()) {
            continue;
        }
        connections.push_back({"tcp", local_endpoint->first, local_endpoint->second, remote_endpoint->first,
                               remote_endpoint->second, tcp_state(state), std::nullopt});
    }
    return connections;
}

result<std::vector<network_connection>> collect_tcp_connections(
    const std::filesystem::path& proc_root, const std::size_t maximum_connections) {
#ifndef __linux__
    (void)proc_root;
    (void)maximum_connections;
    return error{error_code::unsupported_action, "network collection is available only on Linux"};
#else
    std::ifstream input{proc_root / "net" / "tcp"};
    if (!input) {
        return error{error_code::io_failure, "cannot read procfs TCP table"};
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    return parse_proc_net_tcp(contents.str(), maximum_connections);
#endif
}

}  // namespace panopticon::linux_agent
