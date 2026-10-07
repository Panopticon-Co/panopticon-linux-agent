#pragma once

#include <filesystem>
#include <set>
#include <string>
#include <system_error>

#ifdef __linux__
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace panopticon::linux_agent {

// Says why `path` must not be trusted as configuration or as a trust anchor (command signing keys, the Manager CA),
// or returns an empty string when it can be. A file that someone other than root (or the sensor's own user) can
// write or replace is an instruction channel: whoever can edit the signing key list can authorise their own
// commands, whoever can edit the CA bundle can stand in for the Manager. So the file must be a regular file owned by
// root or the effective user and not writable by group or others, and so must be every directory above it
// (resolved and as written), except that a sticky directory such as /tmp may be world-writable because there nobody
// can rename or delete another user's file. The check does not stop root; it stops everyone else.
[[nodiscard]] inline std::string untrusted_path_reason(const std::filesystem::path& path) {
#ifdef __linux__
    namespace fs = std::filesystem;
    std::error_code code;
    const auto lexical = fs::absolute(path, code).lexically_normal();
    if (code) return "cannot resolve " + path.string();
    const auto real = fs::canonical(lexical, code);
    if (code) return "cannot resolve " + path.string();
    const auto trusted_owner = [](const uid_t owner) { return owner == 0 || owner == ::geteuid(); };

    struct stat info {};
    if (::stat(real.c_str(), &info) != 0) return "cannot read " + real.string();
    if (!S_ISREG(info.st_mode)) return real.string() + " is not a regular file";
    if (!trusted_owner(info.st_uid)) return real.string() + " is owned by uid " + std::to_string(info.st_uid) + ", not root or the sensor's own user";
    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) return real.string() + " is writable by group or others";

    std::set<fs::path> directories;
    for (const auto& start : {lexical, real}) {
        for (auto directory = start.parent_path(); !directory.empty(); directory = directory.parent_path()) {
            directories.insert(directory);
            if (directory == directory.root_path()) break;
        }
    }
    for (const auto& directory : directories) {
        struct stat dir {};
        if (::stat(directory.c_str(), &dir) != 0) return "cannot read " + directory.string();
        if (!trusted_owner(dir.st_uid)) return "the directory " + directory.string() + " is owned by uid " + std::to_string(dir.st_uid) + ", not root or the sensor's own user";
        if ((dir.st_mode & (S_IWGRP | S_IWOTH)) != 0 && (dir.st_mode & S_ISVTX) == 0) return "the directory " + directory.string() + " is writable by group or others";
    }
    return {};
#else
    (void)path;
    return {};
#endif
}

}  // namespace panopticon::linux_agent
