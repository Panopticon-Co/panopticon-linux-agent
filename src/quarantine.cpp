#include "panopticon/linux_agent/quarantine.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
namespace panopticon::linux_agent {
namespace {
bool child_of(const std::filesystem::path& root, const std::filesystem::path& path) {
    const auto mismatch = std::mismatch(root.begin(), root.end(), path.begin(), path.end());
    return mismatch.first == root.end();
}
}
result<quarantine_entry> quarantine_regular_file(const std::filesystem::path& allowed_root, const std::filesystem::path& source,
                                                 const std::filesystem::path& quarantine_root) {
    std::error_code ec; const auto root = std::filesystem::weakly_canonical(allowed_root, ec);
    const auto source_path = std::filesystem::absolute(source, ec).lexically_normal();
    if (ec || !child_of(root, source_path)) return error{error_code::invalid_input, "quarantine source is outside allowed root"};
    const auto status = std::filesystem::symlink_status(source_path, ec);
    if (ec || !std::filesystem::is_regular_file(status)) return error{error_code::invalid_input, "quarantine source is not a regular file"};
    std::filesystem::create_directories(quarantine_root, ec); if (ec) return error{error_code::io_failure, "cannot create quarantine directory"};
    const auto sequence = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto destination = quarantine_root / (source_path.filename().string() + "." + std::to_string(sequence));
    std::filesystem::rename(source_path, destination, ec);
    if (ec) return error{error_code::io_failure, "cannot atomically move source into quarantine"};
    const auto metadata = destination.string() + ".meta";
    std::ofstream output{metadata, std::ios::trunc};
    if (!output) return error{error_code::io_failure, "quarantine metadata could not be written"};
    output << "original_path=" << source_path.string() << '\n'; output.flush();
    if (!output) return error{error_code::io_failure, "quarantine metadata could not be persisted"};
    return quarantine_entry{destination, metadata};
}
}  // namespace panopticon::linux_agent
