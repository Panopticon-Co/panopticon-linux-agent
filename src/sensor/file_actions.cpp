#include "panopticon/linux_agent/sensor/file_actions.hpp"

#include "panopticon/linux_agent/sensor/hash_service.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <optional>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0U)
#endif

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::size_t maximum_path_bytes = 4096U;

// Best-effort calls whose failure changes nothing that was promised.
inline void ignore(const int) noexcept {}

class unique_fd {
public:
    unique_fd() = default;
    explicit unique_fd(const int fd) : fd_{fd} {}
    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;
    unique_fd(unique_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}
    unique_fd& operator=(unique_fd&& other) noexcept {
        if (this != &other) reset(std::exchange(other.fd_, -1));
        return *this;
    }
    ~unique_fd() { reset(); }
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    void reset(const int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_{-1};
};

file_action_result make(std::string outcome, std::string reason, std::string detail, const std::uint32_t affected = 0U) {
    return {std::move(outcome), std::move(reason), std::move(detail), affected};
}

std::string errno_text(const int code) { return std::strerror(code); }

std::string printable(const std::string_view text, const std::size_t maximum = 200U) {
    std::string out;
    for (const unsigned char c : text) {
        if (out.size() >= maximum) break;
        out.push_back(c >= 0x20U && c < 0x7FU ? static_cast<char>(c) : '?');
    }
    return out;
}

std::string hex_of(const std::string_view bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const unsigned char c : bytes) {
        out.push_back(digits[c >> 4U]);
        out.push_back(digits[c & 15U]);
    }
    return out;
}

std::optional<std::vector<std::string>> components_of(const std::string& path) {
    if (path.size() < 2U || path.size() > maximum_path_bytes || path.front() != '/' || path.find('\0') != std::string::npos) {
        return std::nullopt;
    }
    std::vector<std::string> parts;
    std::size_t begin = 1U;
    while (begin <= path.size()) {
        auto end = path.find('/', begin);
        if (end == std::string::npos) end = path.size();
        auto part = path.substr(begin, end - begin);
        if (part.empty() || part == "." || part == ".." || part.size() > 255U) return std::nullopt;
        parts.push_back(std::move(part));
        begin = end + 1U;
    }
    return parts;
}

std::vector<std::string> components_of_directory(const std::filesystem::path& path) {
    std::vector<std::string> parts;
    for (const auto& part : path.lexically_normal()) {
        const auto text = part.string();
        if (text.empty() || text == "/" || text == ".") continue;
        parts.push_back(text);
    }
    return parts;
}

bool is_under(const std::vector<std::string>& prefix, const std::vector<std::string>& parts) {
    if (prefix.size() > parts.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), parts.begin());
}

const char* kind_of(const mode_t mode) noexcept {
    if (S_ISREG(mode)) return "regular";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISCHR(mode)) return "chardev";
    if (S_ISBLK(mode)) return "blockdev";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISSOCK(mode)) return "socket";
    return "other";
}

std::int64_t mtime_ns(const struct stat& info) noexcept {
    return static_cast<std::int64_t>(info.st_mtim.tv_sec) * 1'000'000'000LL + info.st_mtim.tv_nsec;
}
std::int64_t ctime_ns(const struct stat& info) noexcept {
    return static_cast<std::int64_t>(info.st_ctim.tv_sec) * 1'000'000'000LL + info.st_ctim.tv_nsec;
}

bool same_inode(const struct stat& left, const struct stat& right) noexcept {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}

std::string facts_of(const struct stat& info) {
    char buffer[400];
    std::snprintf(buffer, sizeof(buffer), "type=%s size=%llu mode=%04o uid=%u gid=%u mtime=%lld nlink=%llu dev=%llu ino=%llu", kind_of(info.st_mode),
                  static_cast<unsigned long long>(info.st_size), static_cast<unsigned>(info.st_mode & 07777U), static_cast<unsigned>(info.st_uid),
                  static_cast<unsigned>(info.st_gid), static_cast<long long>(info.st_mtim.tv_sec), static_cast<unsigned long long>(info.st_nlink),
                  static_cast<unsigned long long>(info.st_dev), static_cast<unsigned long long>(info.st_ino));
    return buffer;
}

// The file named by `parts`, found without following a symlink anywhere on the way.
struct resolution {
    bool ok{false};
    file_action_result failure;
    unique_fd parent;
    std::string leaf;
    unique_fd entry;  // O_PATH, no follow
    struct stat info {};
};

resolution resolve(const std::vector<std::string>& parts) {
    resolution out;
    unique_fd current{::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC)};
    if (!current.valid()) {
        out.failure = make("failed", "path_unavailable", "cannot open the root directory");
        return out;
    }
    for (std::size_t index = 0U; index + 1U < parts.size(); ++index) {
        const int next = ::openat(current.get(), parts[index].c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            const int code = errno;
            struct stat link {};
            if (code != ENOENT && ::fstatat(current.get(), parts[index].c_str(), &link, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(link.st_mode)) {
                out.failure = make("rejected", "path_symlink", "a directory on the path is a symlink: " + printable(parts[index], 80U));
            } else if (code == ENOENT || code == ENOTDIR) {
                out.failure = make("rejected", "not_found", "no such directory on the path: " + printable(parts[index], 80U));
            } else {
                out.failure = make("failed", "path_unavailable", errno_text(code));
            }
            return out;
        }
        current.reset(next);
    }
    out.leaf = parts.back();
    unique_fd entry{::openat(current.get(), out.leaf.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC)};
    if (!entry.valid()) {
        const int code = errno;
        out.failure = code == ENOENT ? make("rejected", "not_found", "there is no such file") : make("failed", "path_unavailable", errno_text(code));
        return out;
    }
    if (::fstat(entry.get(), &out.info) != 0) {
        out.failure = make("failed", "path_unavailable", errno_text(errno));
        return out;
    }
    out.parent = std::move(current);
    out.entry = std::move(entry);
    out.ok = true;
    return out;
}

// Reads the very inode `path_fd` refers to, whatever the name has become since.
unique_fd open_for_reading(const int path_fd) {
    const auto link = "/proc/self/fd/" + std::to_string(path_fd);
    return unique_fd{::open(link.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)};
}

struct hashed {
    file_hash value;
    bool timed_out{false};
};

hashed hash_within(const int fd, const std::uint64_t limit, const std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    hashed out;
    out.value = hash_stream(fd, limit, [&](std::size_t) {
        if (std::chrono::steady_clock::now() > deadline) {
            out.timed_out = true;
            return false;
        }
        return true;
    });
    return out;
}

// Why a regular file cannot be hashed, as a result; empty when it can.
std::optional<file_action_result> hash_refusal(const hashed& h, const std::uint64_t size) {
    if (h.timed_out) return make("failed", "budget_exceeded", "hashing did not finish in the time allowed");
    if (h.value.status == "too_large") return make("rejected", "file_too_large", "size=" + std::to_string(size));
    if (h.value.status != "computed") return make("failed", "unreadable", "the file could not be read");
    return std::nullopt;
}

bool is_protected(const std::vector<std::string>& parts, const file_action_options& options) {
    for (const char* name : {"proc", "sys", "dev", "boot"}) {
        if (!parts.empty() && parts.front() == name) return true;
    }
    for (const auto& path : options.protected_paths) {
        const auto prefix = components_of_directory(path);
        if (!prefix.empty() && is_under(prefix, parts)) return true;
    }
    if (!options.quarantine_dir.empty()) {
        const auto prefix = components_of_directory(options.quarantine_dir);
        if (!prefix.empty() && is_under(prefix, parts)) return true;
    }
    return false;
}

// The inode of an executable that must never be moved: this sensor's and init's.
bool is_critical_executable(const struct stat& info) {
    for (const char* link : {"/proc/self/exe", "/proc/1/exe"}) {
        struct stat other {};
        if (::stat(link, &other) == 0 && same_inode(info, other)) return true;
    }
    return false;
}

}  // namespace

file_action_result collect_file(const std::string& path, const file_action_options& options) {
    const auto parts = components_of(path);
    if (!parts) return make("rejected", "invalid_target", "the path must be absolute and normal");
    auto found = resolve(*parts);
    if (!found.ok) return found.failure;
    if (S_ISLNK(found.info.st_mode)) {
        char target[maximum_path_bytes + 1U];
        const auto length = ::readlinkat(found.entry.get(), "", target, maximum_path_bytes);
        const std::string text = length > 0 ? printable(std::string_view{target, static_cast<std::size_t>(length)}, 160U) : std::string{};
        return make("succeeded", "ok", facts_of(found.info) + " target=" + text, 1U);
    }
    if (!S_ISREG(found.info.st_mode)) return make("rejected", "not_a_file", facts_of(found.info));
    if (static_cast<std::uint64_t>(found.info.st_size) > options.maximum_bytes) {
        return make("rejected", "file_too_large", facts_of(found.info));
    }
    auto reader = open_for_reading(found.entry.get());
    if (!reader.valid()) return make("failed", "unreadable", errno_text(errno));
    struct stat opened {};
    if (::fstat(reader.get(), &opened) != 0 || !same_inode(opened, found.info) || !S_ISREG(opened.st_mode)) {
        return make("rejected", "target_changed", "the file was replaced while it was opened");
    }
    const auto digest = hash_within(reader.get(), options.maximum_bytes, options.budget);
    if (const auto refusal = hash_refusal(digest, static_cast<std::uint64_t>(opened.st_size))) return *refusal;
    struct stat after {};
    if (::fstat(reader.get(), &after) != 0 || after.st_size != opened.st_size || mtime_ns(after) != mtime_ns(opened) || ctime_ns(after) != ctime_ns(opened)) {
        return make("failed", "file_changed", "the file changed while it was read");
    }
    return make("succeeded", "ok", facts_of(opened) + " sha256=" + digest.value.sha256, 1U);
}

void remove_partial_quarantine_files(const std::filesystem::path& quarantine_dir) {
    std::error_code ec;
    for (const auto& item : std::filesystem::directory_iterator{quarantine_dir, ec}) {
        if (item.path().extension() == ".part") std::filesystem::remove(item.path(), ec);
    }
}

namespace {

struct store_use {
    std::uint64_t bytes{};
    std::size_t entries{};
};

store_use measure_store(const std::filesystem::path& directory) {
    store_use use;
    std::error_code ec;
    std::size_t visited = 0U;
    for (const auto& item : std::filesystem::directory_iterator{directory, ec}) {
        if (++visited > 100000U) break;
        if (item.path().extension() != ".blob") continue;
        ++use.entries;
        const auto size = item.file_size(ec);
        if (!ec) use.bytes += size;
    }
    return use;
}

// fsync needs a real descriptor; an O_PATH one (as `resolve` returns for directories) is refused by the kernel.
void sync_directory(const int path_fd) {
    const auto link = "/proc/self/fd/" + std::to_string(path_fd);
    unique_fd real{::open(link.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (real.valid()) ignore(::fsync(real.get()));
}

bool write_all(const int fd, const char* data, std::size_t size) {
    while (size > 0U) {
        const auto count = ::write(fd, data, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        data += count;
        size -= static_cast<std::size_t>(count);
    }
    return true;
}

int rename_no_replace(const int from_dir, const char* from, const int to_dir, const char* to) {
    return static_cast<int>(::syscall(SYS_renameat2, from_dir, from, to_dir, to, RENAME_NOREPLACE));
}

std::string metadata_json(const std::string& command_id, const std::string& path, const struct stat& info, const std::string& sha256) {
    json_writer out;
    out.begin_object();
    out.field("schema", "panopticon-quarantine/1");
    out.field("command_id", command_id);
    out.field("original_path", path);
    out.field("original_path_hex", hex_of(path));
    out.field("size", static_cast<std::uint64_t>(info.st_size));
    out.field("sha256", sha256);
    out.field("mode", static_cast<std::uint64_t>(info.st_mode & 07777U));
    out.field("uid", static_cast<std::uint64_t>(info.st_uid));
    out.field("gid", static_cast<std::uint64_t>(info.st_gid));
    out.field("mtime_ns", mtime_ns(info));
    out.field("device", static_cast<std::uint64_t>(info.st_dev));
    out.field("inode", static_cast<std::uint64_t>(info.st_ino));
    out.field("nlink", static_cast<std::uint64_t>(info.st_nlink));
    out.field("quarantined_unix", static_cast<std::int64_t>(std::time(nullptr)));
    out.end_object();
    return out.take();
}

// Copies the inode behind `source` into `<dir>/<name>.part` and renames it to `<name>`; used when the
// original lives on another filesystem than the store.
std::optional<file_action_result> copy_into_store(const int source, const int dir_fd, const std::string& name, const std::string& expected_sha256,
                                                  const std::uint64_t size, const file_action_options& options) {
    struct statvfs space {};
    if (::fstatvfs(dir_fd, &space) == 0) {
        const auto free_bytes = static_cast<std::uint64_t>(space.f_bavail) * space.f_frsize;
        if (free_bytes < size + options.reserve_free_bytes) return make("failed", "no_space", "the quarantine store has too little free space");
    }
    const auto part = name + ".part";
    unique_fd out{::openat(dir_fd, part.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
    if (!out.valid()) return make("failed", "store_unavailable", errno_text(errno));
    std::vector<char> buffer(1U << 20U);
    std::uint64_t offset = 0U;
    const auto deadline = std::chrono::steady_clock::now() + options.budget;
    for (;;) {
        const auto count = ::pread(source, buffer.data(), buffer.size(), static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            ignore(::unlinkat(dir_fd, part.c_str(), 0));
            return make("failed", "unreadable", "the file could not be read while it was copied");
        }
        if (count == 0) break;
        offset += static_cast<std::uint64_t>(count);
        if (offset > options.maximum_bytes || std::chrono::steady_clock::now() > deadline) {
            ignore(::unlinkat(dir_fd, part.c_str(), 0));
            return make("failed", "budget_exceeded", "the copy did not finish within its bounds");
        }
        if (!write_all(out.get(), buffer.data(), static_cast<std::size_t>(count))) {
            const int code = errno;
            ignore(::unlinkat(dir_fd, part.c_str(), 0));
            return make("failed", "store_write_failed", errno_text(code));
        }
    }
    if (::fsync(out.get()) != 0) {
        ignore(::unlinkat(dir_fd, part.c_str(), 0));
        return make("failed", "store_write_failed", "fsync of the stored copy failed");
    }
    // The copy is verified from what is on disk, through a descriptor that can read.
    out.reset();
    unique_fd verify{::openat(dir_fd, part.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    const auto stored = verify.valid() ? hash_within(verify.get(), options.maximum_bytes, options.budget) : hashed{};
    verify.reset();
    if (stored.value.status != "computed" || stored.value.sha256 != expected_sha256) {
        ignore(::unlinkat(dir_fd, part.c_str(), 0));
        return make("failed", "copy_mismatch", "the stored copy does not match the examined file");
    }
    if (rename_no_replace(dir_fd, part.c_str(), dir_fd, name.c_str()) != 0) {
        const int code = errno;
        ignore(::unlinkat(dir_fd, part.c_str(), 0));
        return make("failed", "store_conflict", errno_text(code));
    }
    return std::nullopt;
}

}  // namespace

file_action_result quarantine_file(const std::string& path, const std::string& command_id, const bool dry_run, const file_action_options& options) {
    if (options.quarantine_dir.empty() || options.roots.empty()) {
        return make("rejected", "quarantine_unavailable", "no quarantine store or no permitted directory is configured");
    }
    const auto parts = components_of(path);
    if (!parts) return make("rejected", "invalid_target", "the path must be absolute and normal");
    bool inside = false;
    for (const auto& root : options.roots) {
        const auto prefix = components_of_directory(root);
        if (!prefix.empty() && is_under(prefix, *parts)) inside = true;
    }
    if (!inside) return make("rejected", "outside_roots", "the file is not under a directory this endpoint may quarantine from");
    if (is_protected(*parts, options)) return make("rejected", "target_protected", "the sensor's own files and system pseudo-filesystems are never quarantined");

    auto found = resolve(*parts);
    if (!found.ok) return found.failure;
    if (!S_ISREG(found.info.st_mode)) return make("rejected", "not_a_file", facts_of(found.info));
    if (is_critical_executable(found.info)) return make("rejected", "target_protected", "this is the sensor's own or init's executable");
    if (static_cast<std::uint64_t>(found.info.st_size) > options.maximum_bytes) return make("rejected", "file_too_large", facts_of(found.info));

    auto reader = open_for_reading(found.entry.get());
    if (!reader.valid()) return make("failed", "unreadable", errno_text(errno));
    struct stat opened {};
    if (::fstat(reader.get(), &opened) != 0 || !same_inode(opened, found.info) || !S_ISREG(opened.st_mode)) {
        return make("rejected", "target_changed", "the file was replaced while it was opened");
    }
    const auto digest = hash_within(reader.get(), options.maximum_bytes, options.budget);
    if (const auto refusal = hash_refusal(digest, static_cast<std::uint64_t>(opened.st_size))) return *refusal;
    const std::string identity = facts_of(opened) + " sha256=" + digest.value.sha256;
    if (dry_run) return make("rejected", "dry_run", "verified, nothing moved: " + identity);

    // The store: a directory only this user can enter.
    std::error_code ec;
    const bool created = std::filesystem::create_directory(options.quarantine_dir, ec);
    if (ec) return make("failed", "store_unavailable", "cannot create the quarantine store");
    if (created) ignore(::chmod(options.quarantine_dir.c_str(), 0700));
    unique_fd store{::open(options.quarantine_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (!store.valid()) return make("failed", "store_unavailable", errno_text(errno));
    struct stat store_info {};
    if (::fstat(store.get(), &store_info) != 0 || !S_ISDIR(store_info.st_mode) || store_info.st_uid != ::geteuid() || (store_info.st_mode & 077U) != 0U) {
        return make("failed", "store_insecure", "the quarantine store is not a private directory of this user");
    }
    remove_partial_quarantine_files(options.quarantine_dir);
    const auto use = measure_store(options.quarantine_dir);
    if (use.entries >= options.store_maximum_entries || use.bytes + static_cast<std::uint64_t>(opened.st_size) > options.store_maximum_bytes) {
        return make("rejected", "quarantine_full", "the quarantine store is at its limit");
    }

    const auto blob = command_id + ".blob";
    const auto meta = command_id + ".json";
    {
        unique_fd record{::openat(store.get(), meta.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
        if (!record.valid()) return make("failed", errno == EEXIST ? "store_conflict" : "store_unavailable", errno_text(errno));
        const auto text = metadata_json(command_id, path, opened, digest.value.sha256) + "\n";
        if (!write_all(record.get(), text.data(), text.size()) || ::fsync(record.get()) != 0) {
            record.reset();
            ignore(::unlinkat(store.get(), meta.c_str(), 0));
            return make("failed", "store_write_failed", "the quarantine record could not be written");
        }
    }
    const auto abandon = [&](file_action_result result) {
        ignore(::unlinkat(store.get(), meta.c_str(), 0));
        return result;
    };

    bool moved_by_rename = true;
    if (rename_no_replace(found.parent.get(), found.leaf.c_str(), store.get(), blob.c_str()) != 0) {
        const int code = errno;
        if (code != EXDEV) return abandon(make("failed", code == EEXIST ? "store_conflict" : "move_failed", errno_text(code)));
        moved_by_rename = false;
        if (const auto failure = copy_into_store(reader.get(), store.get(), blob, digest.value.sha256, static_cast<std::uint64_t>(opened.st_size), options)) {
            return abandon(*failure);
        }
        // Only the inode that was examined may be removed.
        struct stat now {};
        if (::fstatat(found.parent.get(), found.leaf.c_str(), &now, AT_SYMLINK_NOFOLLOW) != 0 || !same_inode(now, opened)) {
            ignore(::unlinkat(store.get(), blob.c_str(), 0));
            return abandon(make("rejected", "target_changed", "the name no longer refers to the file that was examined"));
        }
        if (::unlinkat(found.parent.get(), found.leaf.c_str(), 0) != 0) {
            const int unlink_error = errno;
            ignore(::unlinkat(store.get(), blob.c_str(), 0));
            return abandon(make("failed", "remove_failed", errno_text(unlink_error)));
        }
    } else {
        // A rename moves whatever the name pointed at the instant it ran; make sure it was the examined inode.
        struct stat stored {};
        if (::fstatat(store.get(), blob.c_str(), &stored, AT_SYMLINK_NOFOLLOW) != 0 || !same_inode(stored, opened)) {
            if (rename_no_replace(store.get(), blob.c_str(), found.parent.get(), found.leaf.c_str()) != 0) {
                return abandon(make("indeterminate", "target_changed", "another file was moved and could not be put back; see the quarantine store"));
            }
            return abandon(make("rejected", "target_changed", "the name was swapped while it was moved; it was put back"));
        }
    }
    // Neutralise what was stored: no execute, no setuid, owner only. Best effort; the store is already private.
    ignore(::fchmodat(store.get(), blob.c_str(), 0400, 0));
    ignore(::fchownat(store.get(), blob.c_str(), ::geteuid(), ::getegid(), AT_SYMLINK_NOFOLLOW));
    ignore(::fsync(store.get()));
    sync_directory(found.parent.get());
    const std::string other_links =
        opened.st_nlink > 1U ? " other_links=" + std::to_string(static_cast<unsigned long long>(opened.st_nlink) - 1ULL) : std::string{};
    return make("succeeded", "ok", "id=" + command_id + " " + (moved_by_rename ? "moved " : "copied ") + identity + other_links, 1U);
}

}  // namespace panopticon::linux_agent::sensor
