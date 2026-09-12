#pragma once

#include "panopticon/linux_agent/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent {

struct network_connection {
    std::string protocol;
    std::string local_address;
    std::uint16_t local_port{};
    std::string remote_address;
    std::uint16_t remote_port{};
    std::string state;
    std::optional<std::uint32_t> owner_pid;
};

[[nodiscard]] result<std::vector<network_connection>> parse_proc_net_tcp(std::string_view contents, std::size_t maximum_connections);
[[nodiscard]] result<std::vector<network_connection>> collect_tcp_connections(
    const std::filesystem::path& proc_root, std::size_t maximum_connections);

}  // namespace panopticon::linux_agent
