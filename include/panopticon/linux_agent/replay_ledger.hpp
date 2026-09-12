#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <cstddef>
#include <filesystem>
#include <set>
#include <string>
namespace panopticon::linux_agent {
class replay_ledger {
public:
    replay_ledger(std::filesystem::path path, std::size_t maximum_entries);
    [[nodiscard]] result<bool> load();
    [[nodiscard]] result<bool> mark_if_new(const std::string& command_id);
private:
    std::filesystem::path path_; std::size_t maximum_entries_; std::set<std::string> entries_;
};
}  // namespace panopticon::linux_agent
