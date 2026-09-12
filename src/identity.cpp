#include "panopticon/linux_agent/identity.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

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

}  // namespace panopticon::linux_agent
