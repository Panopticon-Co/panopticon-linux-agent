#pragma once

#include "panopticon/linux_agent/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace panopticon::linux_agent {

class durable_spool {
public:
    durable_spool(std::filesystem::path directory, std::uint64_t quota_bytes);

    [[nodiscard]] result<std::filesystem::path> append(std::string payload);
    [[nodiscard]] result<std::vector<std::filesystem::path>> pending() const;
    [[nodiscard]] result<std::string> read(const std::filesystem::path& entry) const;
    [[nodiscard]] result<bool> acknowledge(const std::filesystem::path& entry) const;
    [[nodiscard]] result<std::uint64_t> recover();
    [[nodiscard]] std::uint64_t size_bytes() const;

private:
    std::filesystem::path directory_;
    std::uint64_t quota_bytes_;
};

}  // namespace panopticon::linux_agent
