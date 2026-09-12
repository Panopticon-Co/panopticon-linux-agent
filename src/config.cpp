#include "panopticon/linux_agent/config.hpp"

#include "panopticon/linux_agent/identity.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <map>
#include <fstream>
#include <optional>
#include <sstream>

namespace panopticon::linux_agent {
namespace {

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r");
    const auto last = value.find_last_not_of(" \t\r");
    return first == std::string::npos ? std::string{} : value.substr(first, last - first + 1U);
}

template <typename integer_type>
std::optional<integer_type> integer(const std::string_view value) {
    integer_type parsed{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    return error == std::errc{} && end == value.data() + value.size() ? std::optional{parsed} : std::nullopt;
}

}  // namespace

result<agent_config> parse_config(const std::string_view contents) {
    std::map<std::string, std::string> values;
    std::istringstream lines{std::string{contents}};
    for (std::string line; std::getline(lines, line);) {
        line = trim(std::move(line));
        if (line.empty() || line.front() == '#') {
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string::npos) return error{error_code::invalid_input, "configuration line lacks '='"};
        const auto key = trim(line.substr(0U, separator));
        const auto value = trim(line.substr(separator + 1U));
        if (key.empty() || value.empty() || !values.emplace(key, value).second) {
            return error{error_code::invalid_input, "configuration contains empty or duplicate key"};
        }
    }
    constexpr std::array<std::string_view, 11U> allowed{"manager_url", "agent_id", "host_id", "queue_capacity", "spool_quota_bytes", "maximum_event_bytes", "maximum_batch_bytes", "response_enabled", "identity_path", "enrollment_token_path", "spool_path"};
    for (const auto& [key, value] : values) {
        (void)value;
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) return error{error_code::invalid_input, "unknown configuration key"};
    }
    const auto required = [&](const std::string_view key) -> std::optional<std::string> {
        const auto it = values.find(std::string{key});
        return it == values.end() ? std::nullopt : std::optional{it->second};
    };
    const auto url = required("manager_url");
    const auto agent = required("agent_id");
    const auto host = required("host_id");
    const auto queue = required("queue_capacity");
    const auto spool = required("spool_quota_bytes");
    const auto event = required("maximum_event_bytes");
    const auto batch = required("maximum_batch_bytes");
    const auto response = required("response_enabled");
    if (!url || !agent || !host || !queue || !spool || !event || !batch || !response || url->rfind("https://", 0U) != 0U ||
        !is_valid_identifier(*agent) || !is_valid_identifier(*host)) return error{error_code::invalid_input, "required configuration is invalid"};
    const auto queue_value = integer<std::size_t>(*queue); const auto spool_value = integer<std::uint64_t>(*spool);
    const auto event_value = integer<std::size_t>(*event); const auto batch_value = integer<std::size_t>(*batch);
    if (!queue_value || !spool_value || !event_value || !batch_value || *queue_value == 0U || *spool_value == 0U || *event_value == 0U ||
        *batch_value < *event_value || (*response != "true" && *response != "false")) return error{error_code::invalid_input, "configuration resource limit is invalid"};
    const auto identity_path = required("identity_path").value_or("");
    const auto enrollment_token_path = required("enrollment_token_path").value_or("");
    const auto spool_path = required("spool_path").value_or("");
    if ((!identity_path.empty() && spool_path.empty()) || (identity_path.empty() && (!spool_path.empty() || !enrollment_token_path.empty()))) {
        return error{error_code::invalid_input, "transport state paths must include identity and spool paths"};
    }
    return agent_config{*url, *agent, *host, *queue_value, *spool_value, *event_value, *batch_value, *response == "true",
                        identity_path, enrollment_token_path, spool_path};
}

result<agent_config> load_config_file(const std::filesystem::path& path) {
    std::error_code filesystem_error;
    const auto status = std::filesystem::status(path, filesystem_error);
    if (filesystem_error || !std::filesystem::is_regular_file(status)) return error{error_code::io_failure, "configuration path is not a regular file"};
#ifdef __linux__
    const auto unsafe = std::filesystem::perms::group_write | std::filesystem::perms::others_write;
    if ((status.permissions() & unsafe) != std::filesystem::perms::none) return error{error_code::invalid_input, "configuration must not be group or world writable"};
#endif
    std::ifstream input{path, std::ios::binary};
    std::ostringstream contents; contents << input.rdbuf();
    if (!input.good() && !input.eof()) return error{error_code::io_failure, "cannot read configuration"};
    return parse_config(contents.str());
}

}  // namespace panopticon::linux_agent
