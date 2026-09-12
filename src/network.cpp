#include "panopticon/linux_agent/network.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

namespace panopticon::linux_agent {
namespace {

std::optional<std::pair<std::string, std::uint16_t>> parse_ipv4_endpoint(const std::string_view endpoint) {
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

std::optional<std::pair<std::string, std::uint16_t>> parse_ipv6_endpoint(const std::string_view endpoint) {
    const auto delimiter = endpoint.find(':');
    if (delimiter != 32U || endpoint.size() != 37U) return std::nullopt;
    std::array<std::uint16_t, 8U> groups{};
    try {
        for (std::size_t word = 0U; word < 4U; ++word) {
            const auto raw_value = static_cast<std::uint32_t>(std::stoul(std::string{endpoint.substr(word * 8U, 8U)}, nullptr, 16));
            const auto value = ((raw_value & 0x000000FFU) << 24U) | ((raw_value & 0x0000FF00U) << 8U) |
                               ((raw_value & 0x00FF0000U) >> 8U) | ((raw_value & 0xFF000000U) >> 24U);
            groups[word * 2U] = static_cast<std::uint16_t>(value >> 16U);
            groups[word * 2U + 1U] = static_cast<std::uint16_t>(value & 0xFFFFU);
        }
        const auto port = std::stoul(std::string{endpoint.substr(delimiter + 1U)}, nullptr, 16);
        if (port > std::numeric_limits<std::uint16_t>::max()) return std::nullopt;
        std::ostringstream formatted;
        formatted << std::hex;
        for (std::size_t index = 0U; index < groups.size(); ++index) {
            if (index != 0U) formatted << ':';
            formatted << groups[index];
        }
        return std::pair{formatted.str(), static_cast<std::uint16_t>(port)};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string connection_state(const std::string_view value) {
    if (value == "01") return "established";
    if (value == "0A") return "listen";
    if (value == "06") return "time_wait";
    return "other";
}

result<std::vector<network_connection>> parse_proc_net_table(
    const std::string_view contents, const std::size_t maximum_connections, const std::string_view protocol, const bool ipv6) {
    if (maximum_connections == 0U) return error{error_code::invalid_input, "network connection limit must be positive"};
    std::istringstream lines{std::string{contents}};
    std::string line;
    std::getline(lines, line);
    std::vector<network_connection> connections;
    while (std::getline(lines, line) && connections.size() < maximum_connections) {
        std::istringstream fields{line};
        std::string slot, local, remote, state;
        if (!(fields >> slot >> local >> remote >> state)) continue;
        const auto local_endpoint = ipv6 ? parse_ipv6_endpoint(local) : parse_ipv4_endpoint(local);
        const auto remote_endpoint = ipv6 ? parse_ipv6_endpoint(remote) : parse_ipv4_endpoint(remote);
        if (!local_endpoint.has_value() || !remote_endpoint.has_value()) continue;
        connections.push_back({std::string{protocol}, local_endpoint->first, local_endpoint->second, remote_endpoint->first,
                               remote_endpoint->second, connection_state(state), std::nullopt});
    }
    return connections;
}

result<std::vector<network_connection>> collect_table(
    const std::filesystem::path& proc_root, const std::string_view filename, const std::size_t maximum_connections,
    const std::string_view protocol, const bool ipv6) {
#ifndef __linux__
    (void)proc_root; (void)filename; (void)maximum_connections; (void)protocol; (void)ipv6;
    return error{error_code::unsupported_action, "network collection is available only on Linux"};
#else
    std::ifstream input{proc_root / "net" / filename};
    if (!input) return error{error_code::io_failure, "cannot read procfs network table"};
    std::ostringstream contents;
    contents << input.rdbuf();
    return parse_proc_net_table(contents.str(), maximum_connections, protocol, ipv6);
#endif
}

}  // namespace

result<std::vector<network_connection>> parse_proc_net_tcp(const std::string_view contents, const std::size_t maximum_connections) {
    return parse_proc_net_table(contents, maximum_connections, "tcp", false);
}

result<std::vector<network_connection>> parse_proc_net_tcp6(const std::string_view contents, const std::size_t maximum_connections) {
    return parse_proc_net_table(contents, maximum_connections, "tcp6", true);
}

result<std::vector<network_connection>> parse_proc_net_udp(const std::string_view contents, const std::size_t maximum_connections) {
    return parse_proc_net_table(contents, maximum_connections, "udp", false);
}

result<std::vector<network_connection>> parse_proc_net_udp6(const std::string_view contents, const std::size_t maximum_connections) {
    return parse_proc_net_table(contents, maximum_connections, "udp6", true);
}

result<std::vector<network_connection>> collect_tcp_connections(
    const std::filesystem::path& proc_root, const std::size_t maximum_connections) {
    return collect_table(proc_root, "tcp", maximum_connections, "tcp", false);
}

result<std::vector<network_connection>> collect_tcp6_connections(
    const std::filesystem::path& proc_root, const std::size_t maximum_connections) {
    return collect_table(proc_root, "tcp6", maximum_connections, "tcp6", true);
}

result<std::vector<network_connection>> collect_udp_connections(
    const std::filesystem::path& proc_root, const std::size_t maximum_connections) {
    return collect_table(proc_root, "udp", maximum_connections, "udp", false);
}

result<std::vector<network_connection>> collect_udp6_connections(
    const std::filesystem::path& proc_root, const std::size_t maximum_connections) {
    return collect_table(proc_root, "udp6", maximum_connections, "udp6", true);
}

}  // namespace panopticon::linux_agent
