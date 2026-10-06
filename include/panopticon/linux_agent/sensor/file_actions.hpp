#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace panopticon::linux_agent::sensor {

// COLLECT_FILE and QUARANTINE_FILE (ADR 026): the two file actions of the command channel.
//
// A path arrives as text from the Manager, and between "the Manager saw this file" and "the sensor acts on
// it" an unprivileged local user can swap names. Every step therefore works on descriptors, not on names:
// the path must be absolute and already normal (no `.`, `..`, empty or trailing components), every directory
// on the way is opened with O_NOFOLLOW and refused if it is a symlink, the last component is opened with
// O_PATH|O_NOFOLLOW, and the file is read through /proc/self/fd/<n> of that same descriptor, never by name.
// Device nodes, FIFOs and sockets are never opened. The Manager is the authority on *which* file; the sensor
// is the authority on whether it is safe to touch.

struct file_action_options {
    // Quarantine acts only on files under one of these (lexical prefix on whole components). Empty: no
    // quarantine. Collection is not limited by it.
    std::vector<std::filesystem::path> roots;
    // Where quarantined files are kept (mode 0700, owned by the sensor's user). Empty: no quarantine.
    std::filesystem::path quarantine_dir;
    // Never quarantined, whatever the roots say: the sensor's own configuration, keys, ledger, WAL, identity
    // and quarantine store, and anything under /proc, /sys, /dev and /boot (built in).
    std::vector<std::filesystem::path> protected_paths;
    std::uint64_t maximum_bytes{256ULL * 1024U * 1024U};
    std::chrono::milliseconds budget{10000};  // for hashing and copying one file
    std::uint64_t store_maximum_bytes{2ULL * 1024U * 1024U * 1024U};
    std::size_t store_maximum_entries{4096U};
    std::uint64_t reserve_free_bytes{64ULL * 1024U * 1024U};  // a copy across filesystems must leave this free
};

struct file_action_result {
    std::string outcome;  // succeeded, failed, rejected, indeterminate
    std::string reason;   // [a-z_]+
    std::string detail;   // printable, bounded by the caller
    std::uint32_t affected{};
};

// Read-only: type, size, mode, owner, times and SHA-256 of one regular file (a symlink is reported as a
// symlink with its target text; directories and special files are refused unopened). File contents never
// leave this function.
[[nodiscard]] file_action_result collect_file(const std::string& path, const file_action_options& options);

// Moves one regular file into the quarantine store, byte for byte, after recording what it was. `dry_run`
// does every check and the hash and then stops. The original is removed only after the stored copy has
// been verified, and only if the name still refers to the inode that was examined.
[[nodiscard]] file_action_result quarantine_file(const std::string& path, const std::string& command_id, bool dry_run,
                                                 const file_action_options& options);

// Quarantine files whose copy was interrupted (`*.part`) are removed. Called before each quarantine.
void remove_partial_quarantine_files(const std::filesystem::path& quarantine_dir);

}  // namespace panopticon::linux_agent::sensor
