#pragma once

#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

#include "panopticon/linux_agent/error.hpp"

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace panopticon::linux_agent {

// Replaces `path` with `data` so that after a crash or power loss it holds either the old content or all of the
// new content, never an empty or partial file: the data is written to a fresh sibling created with `mode` (so a
// secret is never readable between creation and chmod), fsynced, renamed over `path`, and the directory is
// fsynced so the rename itself is durable. flush() alone leaves the data in the page cache; a rename that
// reaches the disk before the data leaves a zero-length file (seen after a sysrq-b crash of a file written
// with flush() only). Header-only because identity.cpp is linked into targets that do not link the core library.
[[nodiscard]] inline result<bool> write_file_durably(const std::filesystem::path& path, const std::string_view data,
                                                     const unsigned int mode = 0600U) {
    const auto temporary = path.string() + ".tmp";
#ifdef __linux__
    (void)::unlink(temporary.c_str());
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(mode));
    if (fd < 0) return error{error_code::io_failure, "cannot create " + temporary};
    bool ok = true;
    for (std::size_t written = 0; ok && written < data.size();) {
        const auto count = ::write(fd, data.data() + written, data.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        written += static_cast<std::size_t>(count);
    }
    ok = ok && ::fsync(fd) == 0;
    ok = (::close(fd) == 0) && ok;
    if (!ok || ::rename(temporary.c_str(), path.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        return error{error_code::io_failure, "cannot write " + path.string() + " durably"};
    }
    const auto directory = path.has_parent_path() ? path.parent_path() : std::filesystem::path{"."};
    const int directory_fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) return error{error_code::io_failure, "cannot open the directory of " + path.string()};
    const bool synced = ::fsync(directory_fd) == 0;
    (void)::close(directory_fd);
    if (!synced) return error{error_code::io_failure, "cannot sync the directory of " + path.string()};
    return true;
#else
    { std::ofstream output{temporary, std::ios::trunc | std::ios::binary};
      if (!output) return error{error_code::io_failure, "cannot create " + temporary};
      output.write(data.data(), static_cast<std::streamsize>(data.size())); output.flush();
      if (!output) return error{error_code::io_failure, "cannot write " + temporary}; }
    std::error_code rename_error;
    std::filesystem::rename(temporary, path, rename_error);
    if (rename_error) { std::filesystem::remove(temporary, rename_error); return error{error_code::io_failure, "cannot publish " + path.string()}; }
    (void)mode;
    return true;
#endif
}

}  // namespace panopticon::linux_agent
