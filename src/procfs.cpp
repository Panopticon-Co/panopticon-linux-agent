#include "panopticon/linux_agent/procfs.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <string_view>

namespace panopticon::linux_agent {
#ifdef __linux__
namespace {

struct stat_fields {
    std::uint32_t parent_pid{};
    std::uint64_t start_time_ticks{};
    char state{};
};

std::optional<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        return std::nullopt;
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

std::optional<stat_fields> parse_stat(const std::string_view stat) {
    const auto closing = stat.rfind(')');
    if (closing == std::string_view::npos || closing + 2U >= stat.size()) {
        return std::nullopt;
    }
    std::istringstream fields{std::string{stat.substr(closing + 2U)}};
    std::vector<std::string> values;
    for (std::string value; fields >> value;) {
        values.push_back(std::move(value));
    }
    constexpr std::size_t state_index{0U};
    constexpr std::size_t parent_index{1U};
    constexpr std::size_t start_time_index{19U};
    if (values.size() <= start_time_index || values[state_index].size() != 1U) {
        return std::nullopt;
    }
    try {
        return stat_fields{
            static_cast<std::uint32_t>(std::stoul(values[parent_index])),
            std::stoull(values[start_time_index]),
            values[state_index].front(),
        };
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::pair<std::uint32_t, std::uint32_t> parse_identity(const std::string_view status) {
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::istringstream lines{std::string{status}};
    for (std::string line; std::getline(lines, line);) {
        std::istringstream fields{line};
        std::string label;
        std::uint32_t value{};
        if ((fields >> label >> value) && label == "Uid:") {
            uid = value;
        }
        if ((fields.clear(), fields.str(line), fields >> label >> value) && label == "Gid:") {
            gid = value;
        }
    }
    return {uid, gid};
}

std::string command_line(std::string value) {
    std::replace(value.begin(), value.end(), '\0', ' ');
    while (!value.empty() && value.back() == ' ') {
        value.pop_back();
    }
    return value;
}

bool numeric_directory(const std::filesystem::path& path) {
    const auto name = path.filename().string();
    return !name.empty() && std::all_of(name.begin(), name.end(), [](const unsigned char character) {
        return std::isdigit(character) != 0;
    });
}

}  // namespace
#endif

result<std::vector<process_observation>> collect_processes(
    const std::filesystem::path& proc_root, std::string host_id, const std::size_t maximum_processes) {
#ifndef __linux__
    (void)proc_root;
    (void)host_id;
    (void)maximum_processes;
    return error{error_code::unsupported_action, "procfs collection is available only on Linux"};
#else
    if (!is_valid_identifier(host_id) || maximum_processes == 0U) {
        return error{error_code::invalid_input, "host id and process limit are required"};
    }
    std::error_code filesystem_error;
    std::vector<process_observation> observations;
    for (const auto& entry : std::filesystem::directory_iterator{proc_root, filesystem_error}) {
        if (filesystem_error) {
            return error{error_code::io_failure, "cannot enumerate procfs"};
        }
        if (!entry.is_directory() || !numeric_directory(entry.path())) {
            continue;
        }
        const auto pid_value = std::stoul(entry.path().filename().string());
        if (pid_value > UINT32_MAX) {
            continue;
        }
        const auto stat = read_file(entry.path() / "stat");
        const auto status = read_file(entry.path() / "status");
        if (!stat.has_value() || !status.has_value()) {
            continue;  // Process exited or access was denied while collecting.
        }
        const auto parsed_stat = parse_stat(*stat);
        if (!parsed_stat.has_value()) {
            continue;
        }
        const auto [uid, gid] = parse_identity(*status);
        std::error_code link_error;
        const auto executable = std::filesystem::read_symlink(entry.path() / "exe", link_error).string();
        observations.push_back({
            {host_id, static_cast<std::uint32_t>(pid_value), parsed_stat->start_time_ticks},
            parsed_stat->parent_pid,
            uid,
            gid,
            parsed_stat->state,
            link_error ? std::string{} : executable,
            command_line(read_file(entry.path() / "cmdline").value_or("")),
            read_file(entry.path() / "cgroup").value_or(""),
        });
        if (observations.size() == maximum_processes) {
            break;
        }
    }
    return observations;
#endif
}

}  // namespace panopticon::linux_agent
