#include "panopticon/linux_agent/audit.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include <fstream>
namespace panopticon::linux_agent {
result<bool> append_audit_record(const std::filesystem::path& path, const std::string_view action,
                                 const std::string_view correlation_id, const std::string_view outcome,
                                 const std::size_t maximum_record_bytes) {
    if (!is_valid_identifier(action) || !is_valid_identifier(correlation_id) || !is_valid_identifier(outcome) || maximum_record_bytes == 0U)
        return error{error_code::invalid_input, "audit fields are invalid"};
    const std::string line{"{\"action\":\"" + std::string{action} + "\",\"correlation_id\":\"" + std::string{correlation_id} + "\",\"outcome\":\"" + std::string{outcome} + "\"}\n"};
    if (line.size() > maximum_record_bytes) return error{error_code::resource_limit, "audit record exceeds limit"};
    std::error_code ec; std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return error{error_code::io_failure, "cannot create audit directory"};
    std::ofstream output{path, std::ios::app | std::ios::binary};
    if (!output) return error{error_code::io_failure, "cannot write audit record"};
    output << line; output.flush();
    return output ? result<bool>{true} : result<bool>{error{error_code::io_failure, "cannot persist audit record"}};
}
}  // namespace panopticon::linux_agent
