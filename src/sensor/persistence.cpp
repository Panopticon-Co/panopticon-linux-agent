#include "panopticon/linux_agent/sensor/persistence.hpp"

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <set>

namespace panopticon::linux_agent::sensor {

namespace fs = std::filesystem;

namespace {

// A location is either one file (depth 0) or a directory whose entries, down to `depth` levels,
// belong to the category.
struct location {
    const char* category;
    const char* path;
    unsigned depth;
};

constexpr std::array system_locations{
    location{"systemd_unit", "/etc/systemd/system", 3U},
    location{"systemd_unit", "/etc/systemd/user", 2U},
    location{"systemd_unit", "/usr/lib/systemd/system", 1U},
    location{"systemd_unit", "/lib/systemd/system", 1U},
    location{"systemd_unit", "/usr/lib/systemd/user", 1U},
    location{"systemd_unit", "/run/systemd/system", 2U},
    location{"cron", "/etc/crontab", 0U},
    location{"cron", "/etc/anacrontab", 0U},
    location{"cron", "/etc/cron.allow", 0U},
    location{"cron", "/etc/cron.deny", 0U},
    location{"cron", "/etc/cron.d", 1U},
    location{"cron", "/etc/cron.hourly", 1U},
    location{"cron", "/etc/cron.daily", 1U},
    location{"cron", "/etc/cron.weekly", 1U},
    location{"cron", "/etc/cron.monthly", 1U},
    location{"cron", "/var/spool/cron", 2U},
    location{"shell_profile", "/etc/profile", 0U},
    location{"shell_profile", "/etc/bash.bashrc", 0U},
    location{"shell_profile", "/etc/bashrc", 0U},
    location{"shell_profile", "/etc/environment", 0U},
    location{"shell_profile", "/etc/profile.d", 1U},
    location{"shell_profile", "/etc/zsh", 1U},
    location{"ssh", "/etc/ssh/sshd_config", 0U},
    location{"ssh", "/etc/ssh/sshrc", 0U},
    location{"ssh", "/etc/ssh/sshd_config.d", 1U},
    location{"ld_preload", "/etc/ld.so.preload", 0U},
    location{"ld_preload", "/etc/ld.so.conf", 0U},
    location{"ld_preload", "/etc/ld.so.conf.d", 1U},
    location{"init_script", "/etc/rc.local", 0U},
    location{"init_script", "/etc/rc.d/rc.local", 0U},
    location{"init_script", "/etc/init.d", 1U},
    location{"privilege", "/etc/sudoers", 0U},
    location{"privilege", "/etc/doas.conf", 0U},
    location{"privilege", "/etc/sudoers.d", 1U},
    location{"pam", "/etc/pam.d", 1U},
    location{"account", "/etc/passwd", 0U},
    location{"account", "/etc/group", 0U},
    location{"account", "/etc/shadow", 0U},
    location{"account", "/etc/gshadow", 0U},
    location{"system_config", "/etc/hosts", 0U},
    location{"system_config", "/etc/fstab", 0U},
    location{"system_config", "/etc/nsswitch.conf", 0U},
    location{"udev_rule", "/etc/udev/rules.d", 1U},
    location{"autostart", "/etc/xdg/autostart", 1U},
    location{"kernel_module", "/etc/modules", 0U},
    location{"kernel_module", "/etc/modules-load.d", 1U},
    location{"kernel_module", "/usr/lib/modules-load.d", 1U},
    location{"kernel_module", "/etc/modprobe.d", 1U},
    location{"login_hook", "/etc/update-motd.d", 1U},
    location{"package_hook", "/etc/apt/apt.conf.d", 1U},
};

// Relative to each account home directory.
constexpr std::array home_locations{
    location{"shell_profile", ".bashrc", 0U},
    location{"shell_profile", ".bash_profile", 0U},
    location{"shell_profile", ".bash_login", 0U},
    location{"shell_profile", ".bash_logout", 0U},
    location{"shell_profile", ".profile", 0U},
    location{"shell_profile", ".zshrc", 0U},
    location{"shell_profile", ".zprofile", 0U},
    location{"shell_profile", ".zshenv", 0U},
    location{"shell_profile", ".zlogin", 0U},
    location{"shell_profile", ".config/fish/config.fish", 0U},
    location{"ssh", ".ssh/authorized_keys", 0U},
    location{"ssh", ".ssh/authorized_keys2", 0U},
    location{"ssh", ".ssh/rc", 0U},
    location{"ssh", ".ssh/config", 0U},
    location{"autostart", ".config/autostart", 1U},
    location{"systemd_unit", ".config/systemd/user", 2U},
};

bool has_prefix(const std::string_view text, const std::string_view prefix) {
    return text.size() >= prefix.size() && text.compare(0U, prefix.size(), prefix) == 0;
}

bool has_suffix(const std::string_view text, const std::string_view suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// True when `path` is `base` itself (depth 0) or lies at most `depth` levels below `base`.
bool within(const std::string_view path, const std::string_view base, const unsigned depth) {
    if (depth == 0U) return path == base;
    if (path.size() <= base.size() + 1U || !has_prefix(path, base) || path[base.size()] != '/') return false;
    const auto rest = path.substr(base.size() + 1U);
    if (rest.empty() || rest.front() == '/' || rest.back() == '/') return false;
    unsigned levels = 1U;
    for (std::size_t index = 0U; index < rest.size(); ++index) {
        if (rest[index] != '/') continue;
        if (rest[index + 1U] == '/') return false;
        ++levels;
    }
    return levels <= depth;
}

bool path_is_clean(const std::string_view path) {
    if (path.empty() || path.front() != '/' || path.size() > 4096U) return false;
    // No traversal components; a classified path is later joined onto the scan root.
    return path.find("/../") == std::string_view::npos && !has_suffix(path, "/..") && path.find('\0') == std::string_view::npos;
}

fs::path join_root(const fs::path& root, const std::string_view host_path) {
    return root / std::string{host_path.substr(1U)};
}

struct file_content {
    bool present{false};
    bool symlink{false};
    bool regular{false};
    struct stat info {};
    std::string target;
    std::string text;
    std::string hash_status{"not_applicable"};
};

// Reads one path without following a final symlink and without blocking on a planted FIFO.
file_content read_object(const fs::path& path, const std::size_t maximum) {
    file_content out;
    struct stat link_info {};
    if (::lstat(path.c_str(), &link_info) != 0) return out;
    out.present = true;
    out.info = link_info;
    if (S_ISLNK(link_info.st_mode)) {
        out.symlink = true;
        char buffer[4096];
        const auto length = ::readlink(path.c_str(), buffer, sizeof(buffer));
        if (length > 0) out.target.assign(buffer, static_cast<std::size_t>(length));
        return out;
    }
    if (!S_ISREG(link_info.st_mode)) return out;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        out.regular = true;
        out.hash_status = "unreadable";
        return out;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        ::close(fd);
        out.hash_status = "unreadable";
        return out;
    }
    out.regular = true;
    out.info = info;  // attributes of the object that was actually read
    if (static_cast<std::uint64_t>(info.st_size) > maximum) {
        ::close(fd);
        out.hash_status = "too_large";
        return out;
    }
    char buffer[8192];
    while (out.text.size() <= maximum) {
        const auto got = ::read(fd, buffer, std::min(sizeof(buffer), maximum + 1U - out.text.size()));
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            out.text.clear();
            out.hash_status = "unreadable";
            return out;
        }
        if (got == 0) break;
        out.text.append(buffer, static_cast<std::size_t>(got));
    }
    ::close(fd);
    if (out.text.size() > maximum) {  // grew while being read
        out.text.clear();
        out.hash_status = "too_large";
        return out;
    }
    out.hash_status = "computed";
    return out;
}

std::string_view trim_view(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) text.remove_prefix(1U);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n')) text.remove_suffix(1U);
    return text;
}

template <typename callback_type>
void for_each_line(const std::string_view text, callback_type&& callback) {
    std::size_t start = 0U;
    std::size_t lines = 0U;
    while (start <= text.size() && lines < 100000U) {
        auto end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        callback(text.substr(start, end - start));
        start = end + 1U;
        ++lines;
    }
}

}  // namespace

std::string systemd_exec_program(const std::string_view unit_text) {
    std::string program;
    for_each_line(unit_text, [&program](const std::string_view raw) {
        if (!program.empty()) return;
        const auto line = trim_view(raw);
        constexpr std::string_view key{"ExecStart="};
        if (!has_prefix(line, key)) return;
        auto value = trim_view(line.substr(key.size()));
        // systemd allows prefix characters that change how the command runs.
        while (!value.empty() && (value.front() == '@' || value.front() == '-' || value.front() == ':' || value.front() == '+' ||
                                  value.front() == '!')) {
            value.remove_prefix(1U);
        }
        const auto space = value.find_first_of(" \t");
        program = std::string{value.substr(0U, space)};
        if (program.size() > 512U) program.resize(512U);
    });
    return program;
}

std::uint32_t count_active_lines(const std::string_view text) {
    std::uint32_t count = 0U;
    for_each_line(text, [&count](const std::string_view raw) {
        const auto line = trim_view(raw);
        if (!line.empty() && line.front() != '#') ++count;
    });
    return count;
}

std::uint32_t count_nopasswd(const std::string_view sudoers_text) {
    std::uint32_t count = 0U;
    for_each_line(sudoers_text, [&count](const std::string_view raw) {
        const auto line = trim_view(raw);
        if (!line.empty() && line.front() != '#' && line.find("NOPASSWD") != std::string_view::npos) ++count;
    });
    return count;
}

authorized_keys_facts parse_authorized_keys(const std::string_view text, const std::size_t maximum_keys) {
    static constexpr std::array<std::string_view, 7> key_types{"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-",
                                                              "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-", "ssh-ed448"};
    authorized_keys_facts facts;
    for_each_line(text, [&](const std::string_view raw) {
        const auto line = trim_view(raw);
        if (line.empty() || line.front() == '#') return;
        // The key type starts a token: at the beginning of the line or after a space. Options may
        // precede it and may contain quoted spaces, so the line is searched, not split.
        std::size_t best = std::string_view::npos;
        for (const auto type : key_types) {
            for (auto at = line.find(type); at != std::string_view::npos; at = line.find(type, at + 1U)) {
                if (at == 0U || line[at - 1U] == ' ' || line[at - 1U] == '\t') {
                    best = std::min(best, at);
                    break;
                }
            }
        }
        if (best == std::string_view::npos) return;
        ++facts.key_count;
        if (line.substr(0U, best).find("command=") != std::string_view::npos) ++facts.forced_commands;
        if (facts.digests.size() >= maximum_keys) return;
        const auto rest = line.substr(best);
        const auto first_space = rest.find_first_of(" \t");
        if (first_space == std::string_view::npos) return;
        const auto blob_start = rest.find_first_not_of(" \t", first_space);
        if (blob_start == std::string_view::npos) return;
        const auto blob = rest.substr(blob_start, rest.find_first_of(" \t", blob_start) - blob_start);
        // A short digest identifies the key without reproducing it.
        facts.digests.push_back(sha256_hex(std::string{rest.substr(0U, first_space)} + " " + std::string{blob}).substr(0U, 16U));
    });
    return facts;
}

persistence_catalog::persistence_catalog(persistence_options options) : options_{std::move(options)} {}

void persistence_catalog::refresh_homes() {
    homes_.clear();
    const auto passwd = read_object(options_.root / "etc/passwd", 4U * 1024U * 1024U);
    if (!passwd.regular || passwd.hash_status != "computed") return;
    std::set<std::string> seen;
    for (const auto& entry : parse_passwd(passwd.text, 65536U)) {
        if (homes_.size() >= options_.maximum_homes) break;
        const auto& home = entry.home;
        if (!path_is_clean(home) || home == "/" || home == "/nonexistent" || home.back() == '/') continue;
        if (!seen.insert(home).second) continue;
        struct stat info {};
        if (::lstat(join_root(options_.root, home).c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) continue;
        homes_.push_back(home);
    }
}

std::string persistence_catalog::classify(const std::string_view path) const {
    if (!path_is_clean(path)) return {};
    for (const auto& entry : system_locations) {
        if (within(path, entry.path, entry.depth)) return entry.category;
    }
    for (const auto& home : homes_) {
        if (!has_prefix(path, home) || path.size() <= home.size() + 1U || path[home.size()] != '/') continue;
        const auto relative = path.substr(home.size() + 1U);
        for (const auto& entry : home_locations) {
            if (entry.depth == 0U ? relative == entry.path : within(std::string{"/"} + std::string{relative}, std::string{"/"} + entry.path, entry.depth)) {
                return entry.category;
            }
        }
    }
    return {};
}

namespace {

persistence_item build_item(const std::string_view host_path, const std::string_view category, const file_content& content) {
    persistence_item item;
    item.category = category;
    item.path = host_path;
    item.uid = content.info.st_uid;
    item.gid = content.info.st_gid;
    item.mode = content.info.st_mode & 07777U;
    item.size = static_cast<std::uint64_t>(content.info.st_size);
    item.mtime_ns = static_cast<std::uint64_t>(content.info.st_mtim.tv_sec) * 1000000000ULL + static_cast<std::uint64_t>(content.info.st_mtim.tv_nsec);
    item.hash_status = content.hash_status;
    if (content.symlink) {
        item.kind = "symlink";
        item.target = content.target;
        return item;
    }
    item.kind = content.regular ? "file" : "other";
    if (content.hash_status != "computed") return item;
    item.sha256 = sha256_hex(content.text);
    const auto name = host_path.substr(host_path.find_last_of('/') + 1U);
    if (category == "systemd_unit") {
        for (const char* suffix : {".service", ".timer", ".socket", ".path", ".conf"}) {
            if (has_suffix(name, suffix)) {
                item.exec = systemd_exec_program(content.text);
                break;
            }
        }
    } else if (category == "cron" || host_path == "/etc/ld.so.preload") {
        item.entries = count_active_lines(content.text);
    } else if (category == "ssh" && (name == "authorized_keys" || name == "authorized_keys2")) {
        auto facts = parse_authorized_keys(content.text, 256U);
        item.key_count = facts.key_count;
        item.forced_commands = facts.forced_commands;
        item.key_digests = std::move(facts.digests);
    } else if (category == "privilege" && has_prefix(host_path, "/etc/sudoers")) {
        item.nopasswd = count_nopasswd(content.text);
    }
    return item;
}

struct scan_state {
    const persistence_options& options;
    persistence_scan result;
    std::set<std::string> visited_directories;

    bool full() {
        if (result.items.size() < options.maximum_items) return false;
        result.truncated = true;
        return true;
    }
};

void walk(scan_state& state, const std::string& host_directory, const unsigned depth, const char* category) {
    if (depth == 0U || state.full()) return;
    const auto directory = join_root(state.options.root, host_directory);
    std::error_code error;
    // The same directory can be reachable twice (/lib -> /usr/lib); each is listed once.
    const auto canonical = fs::canonical(directory, error);
    if (!error && !state.visited_directories.insert(canonical.string()).second) return;
    fs::directory_iterator iterator{directory, fs::directory_options::none, error};
    if (error) {
        if (error != std::errc::no_such_file_or_directory && error != std::errc::not_a_directory) {
            state.result.unavailable.push_back({host_directory, error == std::errc::permission_denied ? unavailable_reason::permission_denied
                                                                                                   : unavailable_reason::not_supported_by_provider});
        }
        return;
    }
    std::vector<std::string> names;
    for (; iterator != fs::directory_iterator{}; iterator.increment(error)) {
        if (error) break;
        if (names.size() >= state.options.maximum_directory_entries) {
            state.result.truncated = true;
            state.result.unavailable.push_back({host_directory, unavailable_reason::truncated});
            break;
        }
        names.push_back(iterator->path().filename().string());
    }
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
        if (state.full()) return;
        const auto host_path = (host_directory == "/" ? std::string{"/"} : host_directory + "/") + name;
        struct stat info {};
        const auto absolute = join_root(state.options.root, host_path);
        if (::lstat(absolute.c_str(), &info) != 0) continue;
        if (S_ISDIR(info.st_mode)) {
            walk(state, host_path, depth - 1U, category);
            continue;
        }
        const auto content = read_object(absolute, state.options.maximum_file_bytes);
        if (content.present) state.result.items.push_back(build_item(host_path, category, content));
    }
}

void visit(scan_state& state, const std::string& host_path, const location& entry) {
    if (state.full()) return;
    if (entry.depth > 0U) {
        walk(state, host_path, entry.depth, entry.category);
        return;
    }
    const auto content = read_object(join_root(state.options.root, host_path), state.options.maximum_file_bytes);
    if (content.present) state.result.items.push_back(build_item(host_path, entry.category, content));
}

}  // namespace

persistence_scan persistence_catalog::scan() {
    refresh_homes();
    scan_state state{options_, {}, {}};
    for (const auto& entry : system_locations) visit(state, entry.path, entry);
    for (const auto& home : homes_) {
        for (const auto& entry : home_locations) visit(state, home + "/" + entry.path, entry);
    }
    return std::move(state.result);
}

std::optional<persistence_item> persistence_catalog::describe(const std::string_view path) const {
    const auto category = classify(path);
    if (category.empty()) return std::nullopt;
    const auto content = read_object(join_root(options_.root, path), options_.maximum_file_bytes);
    if (!content.present || S_ISDIR(content.info.st_mode)) return std::nullopt;  // a directory is not itself an item
    return build_item(path, category, content);
}

std::string persistence_item_json(const persistence_item& item) {
    json_writer out;
    out.begin_object();
    out.field("category", item.category);
    out.field("path", item.path);
    out.field("kind", item.kind);
    out.field("uid", item.uid).field("gid", item.gid).field("mode", item.mode).field("size", item.size);
    out.field("mtime", format_rfc3339_ns(item.mtime_ns));
    out.field("hash_status", item.hash_status);
    if (!item.sha256.empty()) out.field("sha256", item.sha256);
    if (!item.target.empty()) out.field("target", item.target);
    if (!item.exec.empty()) out.field("exec", item.exec);
    if (item.entries.has_value()) out.field("entries", *item.entries);
    if (item.key_count.has_value()) out.field("key_count", *item.key_count);
    if (item.forced_commands.has_value()) out.field("forced_commands", *item.forced_commands);
    if (!item.key_digests.empty()) {
        out.key("key_digests").begin_array();
        for (const auto& digest : item.key_digests) out.value(digest);
        out.end_array();
    }
    if (item.nopasswd.has_value()) out.field("nopasswd", *item.nopasswd);
    out.end_object();
    return out.take();
}

}  // namespace panopticon::linux_agent::sensor
