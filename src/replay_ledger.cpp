#include "panopticon/linux_agent/replay_ledger.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include <fstream>
namespace panopticon::linux_agent {
replay_ledger::replay_ledger(std::filesystem::path path, const std::size_t maximum_entries) : path_{std::move(path)}, maximum_entries_{maximum_entries} {}
result<bool> replay_ledger::load() {
    std::ifstream input{path_}; if (!input) return std::filesystem::exists(path_) ? result<bool>{error{error_code::io_failure, "cannot read replay ledger"}} : result<bool>{true};
    for (std::string id; std::getline(input, id);) { if (!is_valid_identifier(id) || entries_.size() == maximum_entries_) return error{error_code::corrupt_data, "replay ledger is malformed or exceeds limit"}; entries_.insert(std::move(id)); }
    return true;
}
result<bool> replay_ledger::mark_if_new(const std::string& command_id) {
    if (!is_valid_identifier(command_id) || maximum_entries_ == 0U) return error{error_code::invalid_input, "command id or replay ledger limit is invalid"};
    if (entries_.contains(command_id)) return false;
    if (entries_.size() == maximum_entries_) return error{error_code::resource_limit, "replay ledger capacity exhausted"};
    std::error_code filesystem_error; std::filesystem::create_directories(path_.parent_path(), filesystem_error); if (filesystem_error) return error{error_code::io_failure, "cannot create replay ledger directory"};
    std::ofstream output{path_, std::ios::app}; if (!output) return error{error_code::io_failure, "cannot persist replay entry"};
    output << command_id << '\n'; output.flush(); if (!output) return error{error_code::io_failure, "cannot flush replay entry"}; entries_.insert(command_id); return true;
}
}  // namespace panopticon::linux_agent
