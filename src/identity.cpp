#include "panopticon/linux_agent/identity.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <fstream>
#ifdef __linux__
#include <sys/stat.h>
#endif

namespace panopticon::linux_agent {

std::string process_identity_key(const process_identity& identity) {
    std::ostringstream stream;
    stream << identity.host_id << ':' << identity.pid << ':' << identity.start_time_ticks;
    return stream.str();
}

bool is_valid_identifier(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::isalnum(character) != 0 || character == '-' || character == '_' || character == '.';
    });
}

result<enrolled_identity> load_enrolled_identity(const std::filesystem::path& path) {
    std::ifstream input{path};
    std::string agent_id, host_id, token;
    if (!input || !std::getline(input, agent_id) || !std::getline(input, host_id) || !std::getline(input, token) ||
        !is_valid_identifier(agent_id) || !is_valid_identifier(host_id) || token.empty() || token.size() > 512U) {
        return error{error_code::invalid_input, "enrolled identity is absent or invalid"};
    }
    return enrolled_identity{std::move(agent_id), std::move(host_id), std::move(token)};
}

result<bool> store_enrolled_identity(const std::filesystem::path& path, const enrolled_identity& identity) {
    if (!is_valid_identifier(identity.agent_id) || !is_valid_identifier(identity.host_id) || identity.bearer_token.empty() ||
        identity.bearer_token.size() > 512U) return error{error_code::invalid_input, "enrolled identity is invalid"};
    std::error_code filesystem_error;
    std::filesystem::create_directories(path.parent_path(), filesystem_error);
    if (filesystem_error) return error{error_code::io_failure, "cannot create identity directory"};
    const auto temporary = path.string() + ".tmp";
    { std::ofstream output{temporary, std::ios::trunc};
      if (!output) return error{error_code::io_failure, "cannot write enrolled identity"};
      output << identity.agent_id << '\n' << identity.host_id << '\n' << identity.bearer_token << '\n';
      output.flush(); if (!output) return error{error_code::io_failure, "cannot persist enrolled identity"}; }
#ifdef __linux__
    if (chmod(temporary.c_str(), S_IRUSR | S_IWUSR) != 0) return error{error_code::io_failure, "cannot protect enrolled identity"};
#endif
    std::filesystem::rename(temporary, path, filesystem_error);
    if (filesystem_error) { std::filesystem::remove(temporary, filesystem_error); return error{error_code::io_failure, "cannot publish enrolled identity"}; }
    return true;
}

}  // namespace panopticon::linux_agent
