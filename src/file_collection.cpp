#include "panopticon/linux_agent/file_collection.hpp"
#include <algorithm>
#include <fstream>
#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace panopticon::linux_agent {
result<collected_file> collect_regular_file(const std::filesystem::path& allowed_root, const std::filesystem::path& requested_path,
                                            const std::size_t maximum_bytes) {
    if (maximum_bytes == 0U || requested_path.empty()) return error{error_code::invalid_input, "file request is invalid"};
    std::error_code ec; const auto root = std::filesystem::weakly_canonical(allowed_root, ec);
    const auto path = std::filesystem::weakly_canonical(requested_path, ec);
    const auto mismatch = std::mismatch(root.begin(), root.end(), path.begin(), path.end());
    if (ec || root.empty() || path.empty() || mismatch.first != root.end()) return error{error_code::invalid_input, "file is outside allowed root"};
#ifndef __linux__
    return error{error_code::unsupported_action, "safe file collection is available only on Linux"};
#else
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return error{error_code::io_failure, "cannot open requested file"};
    struct stat metadata{}; if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0 || static_cast<std::uint64_t>(metadata.st_size) > maximum_bytes) { close(fd); return error{error_code::resource_limit, "file is not a permitted bounded regular file"}; }
    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0'); std::size_t offset{};
    while (offset < contents.size()) { const auto count = read(fd, contents.data() + offset, contents.size() - offset); if (count <= 0) { close(fd); return error{error_code::io_failure, "file changed while being read"}; } offset += static_cast<std::size_t>(count); }
    close(fd); return collected_file{path, std::move(contents)};
#endif
}
}  // namespace panopticon::linux_agent
