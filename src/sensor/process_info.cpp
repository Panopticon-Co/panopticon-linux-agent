#include "panopticon/linux_agent/sensor/process_info.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fstream>
#include <string_view>
#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::uint64_t pf_kthread = 0x00200000U;
constexpr std::size_t maximum_stat_bytes = 4096U;
constexpr std::size_t maximum_status_bytes = 16384U;
constexpr std::size_t maximum_environ_bytes = 65536U;
constexpr std::size_t maximum_cgroup_bytes = 8192U;
constexpr std::uint32_t unset_id = 4294967295U;

struct read_outcome {
    std::optional<std::string> contents;
    bool truncated{false};
    unavailable_reason reason{unavailable_reason::process_exited};
};

unavailable_reason reason_from_errno(const int error_number) {
    switch (error_number) {
    case EACCES:
    case EPERM: return unavailable_reason::permission_denied;
    default: return unavailable_reason::process_exited;  // ENOENT, ESRCH, EIO after exit
    }
}

// procfs files report size 0, so they are read until EOF with a hard upper bound.
read_outcome read_bounded(const std::filesystem::path& path, const std::size_t limit) {
    read_outcome outcome;
#ifdef __linux__
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        outcome.reason = reason_from_errno(errno);
        return outcome;
    }
    std::string contents;
    contents.resize(std::min<std::size_t>(limit, 4096U));
    std::size_t used = 0U;
    while (true) {
        if (used == contents.size()) {
            if (contents.size() >= limit) {
                char probe{};
                outcome.truncated = ::read(descriptor, &probe, 1U) > 0;
                break;
            }
            contents.resize(std::min(limit, contents.size() * 2U));
        }
        const auto count = ::read(descriptor, contents.data() + used, contents.size() - used);
        if (count < 0) {
            if (errno == EINTR) continue;
            outcome.reason = reason_from_errno(errno);
            ::close(descriptor);
            return outcome;
        }
        if (count == 0) break;
        used += static_cast<std::size_t>(count);
    }
    ::close(descriptor);
    contents.resize(used);
    outcome.contents = std::move(contents);
#else
    std::ifstream input{path, std::ios::binary};
    if (!input) return outcome;
    std::string contents(limit, '\0');
    input.read(contents.data(), static_cast<std::streamsize>(limit));
    contents.resize(static_cast<std::size_t>(input.gcount()));
    outcome.truncated = contents.size() == limit && input.peek() != std::char_traits<char>::eof();
    outcome.contents = std::move(contents);
#endif
    return outcome;
}

std::optional<std::string> read_link(const std::filesystem::path& path, unavailable_reason& reason) {
    std::error_code error;
    auto target = std::filesystem::read_symlink(path, error);
    if (error) {
        reason = error == std::errc::permission_denied || error == std::errc::operation_not_permitted
                     ? unavailable_reason::permission_denied
                     : unavailable_reason::process_exited;
        return std::nullopt;
    }
    return target.string();
}

template <typename number_type>
bool parse_number(std::string_view text, number_type& out, const int base = 10) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1U);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\n')) text.remove_suffix(1U);
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), out, base);
    return error == std::errc{} && end == text.data() + text.size();
}

std::vector<std::string_view> split_whitespace(std::string_view text) {
    std::vector<std::string_view> parts;
    std::size_t index = 0U;
    while (index < text.size()) {
        while (index < text.size() && (text[index] == ' ' || text[index] == '\t' || text[index] == '\n')) ++index;
        const auto start = index;
        while (index < text.size() && text[index] != ' ' && text[index] != '\t' && text[index] != '\n') ++index;
        if (index > start) parts.push_back(text.substr(start, index - start));
    }
    return parts;
}

std::uint64_t parse_namespace_link(const std::string_view target) {
    // Format: "<type>:[<inode>]"
    const auto open = target.find(":[");
    const auto close = target.rfind(']');
    if (open == std::string_view::npos || close == std::string_view::npos || close <= open + 2U) return 0U;
    std::uint64_t inode = 0U;
    return parse_number(target.substr(open + 2U, close - open - 2U), inode) ? inode : 0U;
}

std::string select_cgroup(const std::string_view contents) {
    // Prefer the unified (v2) hierarchy "0::<path>"; otherwise keep the v1 lines joined.
    std::string joined;
    std::size_t start = 0U;
    while (start < contents.size()) {
        auto end = contents.find('\n', start);
        if (end == std::string_view::npos) end = contents.size();
        const auto line = contents.substr(start, end - start);
        if (line.rfind("0::", 0U) == 0U) return std::string{line.substr(3U)};
        if (!line.empty()) {
            if (!joined.empty()) joined += ';';
            joined.append(line);
        }
        start = end + 1U;
    }
    return joined;
}

std::optional<std::uint32_t> parse_optional_id(const std::optional<std::string>& contents) {
    std::uint32_t value = 0U;
    if (!contents.has_value() || !parse_number(std::string_view{*contents}, value) || value == unset_id) return std::nullopt;
    return value;
}

}  // namespace

const char* to_string(const executable_kind kind) noexcept {
    switch (kind) {
    case executable_kind::file: return "file";
    case executable_kind::deleted: return "deleted";
    case executable_kind::memfd: return "memfd";
    case executable_kind::anonymous: return "anonymous";
    case executable_kind::unknown: break;
    }
    return "unknown";
}

const char* to_string(const unavailable_reason reason) noexcept {
    switch (reason) {
    case unavailable_reason::not_supported_by_provider: return "not_supported_by_provider";
    case unavailable_reason::process_exited: return "process_exited";
    case unavailable_reason::permission_denied: return "permission_denied";
    case unavailable_reason::truncated: return "truncated";
    case unavailable_reason::budget_exceeded: return "budget_exceeded";
    case unavailable_reason::not_applicable: return "not_applicable";
    case unavailable_reason::kernel_feature_missing: return "kernel_feature_missing";
    case unavailable_reason::object_gone: return "object_gone";
    }
    return "unknown";
}

const std::vector<std::string>& environment_allowlist() {
    static const std::vector<std::string> keys{
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "SSH_CONNECTION", "SSH_CLIENT", "SUDO_USER",
        "SUDO_UID", "SUDO_COMMAND", "container",
    };
    return keys;
}

std::optional<stat_fields> parse_stat(const std::string_view contents) {
    // comm may itself contain ')' and spaces, so it is bounded by the first '(' and the last ')'.
    const auto open = contents.find('(');
    const auto close = contents.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open || close + 2U > contents.size()) {
        return std::nullopt;
    }
    const auto values = split_whitespace(contents.substr(close + 1U));
    // values[0] is field 3 (state); field N is values[N - 3].
    constexpr std::size_t state = 0U, ppid = 1U, pgrp = 2U, session = 3U, tty = 4U, flags = 6U, threads = 17U, start = 19U;
    if (values.size() <= start || values[state].size() != 1U) return std::nullopt;
    stat_fields fields;
    fields.comm = std::string{contents.substr(open + 1U, close - open - 1U)};
    fields.state = values[state].front();
    std::int64_t tty_value = 0;
    if (!parse_number(values[ppid], fields.ppid) || !parse_number(values[pgrp], fields.pgid) ||
        !parse_number(values[session], fields.sid) || !parse_number(values[tty], tty_value) ||
        !parse_number(values[flags], fields.flags) || !parse_number(values[threads], fields.threads) ||
        !parse_number(values[start], fields.start_ticks)) {
        return std::nullopt;
    }
    fields.tty_nr = static_cast<std::uint32_t>(tty_value);
    return fields;
}

void parse_status(const std::string_view contents, process_info& info) {
    std::size_t start = 0U;
    while (start < contents.size()) {
        auto end = contents.find('\n', start);
        if (end == std::string_view::npos) end = contents.size();
        const auto line = contents.substr(start, end - start);
        start = end + 1U;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        const auto label = line.substr(0U, colon);
        const auto rest = line.substr(colon + 1U);
        const auto values = split_whitespace(rest);
        const auto fill_ids = [&values](std::array<std::uint32_t, 4>& ids) {
            for (std::size_t index = 0U; index < ids.size() && index < values.size(); ++index) {
                (void)parse_number(values[index], ids[index]);
            }
        };
        const auto hex = [&rest](std::uint64_t& out) { (void)parse_number(rest, out, 16); };
        if (label == "Uid") fill_ids(info.creds.uids);
        else if (label == "Gid") fill_ids(info.creds.gids);
        else if (label == "Groups") {
            info.creds.groups.clear();
            for (const auto value : values) {
                std::uint32_t group = 0U;
                if (parse_number(value, group)) info.creds.groups.push_back(group);
            }
        } else if (label == "NSpid") {
            if (!values.empty()) (void)parse_number(values.back(), info.vpid);
        } else if (label == "Threads") {
            if (!values.empty()) (void)parse_number(values.front(), info.threads);
        } else if (label == "CapInh") hex(info.caps.inheritable);
        else if (label == "CapPrm") hex(info.caps.permitted);
        else if (label == "CapEff") hex(info.caps.effective);
        else if (label == "CapBnd") hex(info.caps.bounding);
        else if (label == "CapAmb") hex(info.caps.ambient);
        else if (label == "Seccomp") {
            int mode = 0;
            if (!values.empty() && parse_number(values.front(), mode)) info.seccomp_mode = mode;
        } else if (label == "NoNewPrivs") {
            int flag = 0;
            if (!values.empty() && parse_number(values.front(), flag)) info.no_new_privs = flag != 0;
        }
    }
}

std::vector<std::string> split_cmdline(const std::string_view contents, const std::size_t maximum_args,
                                       const std::size_t maximum_bytes, bool& truncated) {
    std::vector<std::string> args;
    std::size_t used = 0U;
    std::size_t start = 0U;
    while (start < contents.size()) {
        auto end = contents.find('\0', start);
        if (end == std::string_view::npos) end = contents.size();
        const auto arg = contents.substr(start, end - start);
        start = end + 1U;
        if (args.size() == maximum_args) {
            truncated = true;
            break;
        }
        if (used + arg.size() > maximum_bytes) {
            args.emplace_back(arg.substr(0U, maximum_bytes - used));
            truncated = true;
            break;
        }
        used += arg.size();
        args.emplace_back(arg);
    }
    return args;
}

std::pair<std::string, executable_kind> classify_exe_link(std::string_view target) {
    constexpr std::string_view deleted_suffix{" (deleted)"};
    const bool deleted = target.size() > deleted_suffix.size() &&
                         target.substr(target.size() - deleted_suffix.size()) == deleted_suffix;
    if (target.rfind("/memfd:", 0U) == 0U) return {std::string{target}, executable_kind::memfd};
    if (deleted) target.remove_suffix(deleted_suffix.size());
    if (target.empty() || target.front() != '/') return {std::string{target}, executable_kind::anonymous};
    return {std::string{target}, deleted ? executable_kind::deleted : executable_kind::file};
}

std::optional<std::uint64_t> read_start_ticks(const std::filesystem::path& proc_root, const std::uint32_t pid) {
    const auto stat_file = read_bounded(proc_root / std::to_string(pid) / "stat", maximum_stat_bytes);
    if (!stat_file.contents.has_value()) return std::nullopt;
    const auto fields = parse_stat(*stat_file.contents);
    if (!fields.has_value()) return std::nullopt;
    return fields->start_ticks;
}

std::vector<std::uint32_t> list_pids(const std::filesystem::path& proc_root) {
    std::vector<std::uint32_t> pids;
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator{proc_root, error}) {
        std::uint32_t pid = 0U;
        const auto name = entry.path().filename().string();
        if (parse_number(std::string_view{name}, pid) && pid != 0U) pids.push_back(pid);
    }
    std::sort(pids.begin(), pids.end());
    return pids;
}

result<process_info> read_process(const std::filesystem::path& proc_root, const std::uint32_t pid,
                                  const procfs_limits& limits) {
    const auto base = proc_root / std::to_string(pid);
    const auto stat_file = read_bounded(base / "stat", maximum_stat_bytes);
    if (!stat_file.contents.has_value()) return error{error_code::target_mismatch, "process is not present"};
    const auto fields = parse_stat(*stat_file.contents);
    if (!fields.has_value()) return error{error_code::corrupt_data, "unparseable stat"};

    process_info info;
    info.pid = pid;
    info.vpid = pid;
    info.ppid = fields->ppid;
    info.pgid = fields->pgid;
    info.sid = fields->sid;
    info.tty_nr = fields->tty_nr;
    info.threads = fields->threads;
    info.start_ticks = fields->start_ticks;
    info.state = fields->state;
    info.comm = fields->comm;
    info.kernel_thread = (fields->flags & pf_kthread) != 0U;

    if (const auto status = read_bounded(base / "status", maximum_status_bytes); status.contents.has_value()) {
        parse_status(*status.contents, info);
    } else {
        info.mark_unavailable("process.user", status.reason);
        info.mark_unavailable("process.capabilities", status.reason);
    }

    if (info.kernel_thread) {
        info.executable.kind = executable_kind::anonymous;
        info.mark_unavailable("process.executable", unavailable_reason::not_applicable);
    } else {
        auto reason = unavailable_reason::process_exited;
        if (const auto target = read_link(base / "exe", reason); target.has_value()) {
            auto [path, kind] = classify_exe_link(*target);
            info.executable.path = std::move(path);
            info.executable.kind = kind;
#ifdef __linux__
            struct stat file_status {};
            // The magic link resolves to the mapped inode even after the file was unlinked.
            if (::stat((base / "exe").c_str(), &file_status) == 0) {
                info.executable.dev = static_cast<std::uint64_t>(file_status.st_dev);
                info.executable.inode = static_cast<std::uint64_t>(file_status.st_ino);
                info.executable.size = static_cast<std::uint64_t>(file_status.st_size);
                info.executable.mtime_ns = static_cast<std::uint64_t>(file_status.st_mtim.tv_sec) * 1000000000ULL +
                                           static_cast<std::uint64_t>(file_status.st_mtim.tv_nsec);
                info.executable.mode = static_cast<std::uint32_t>(file_status.st_mode);
                info.executable.uid = static_cast<std::uint32_t>(file_status.st_uid);
                info.executable.gid = static_cast<std::uint32_t>(file_status.st_gid);
                info.executable.known = true;
            }
#endif
        } else {
            info.mark_unavailable("process.executable", reason);
        }

        const auto cmdline = read_bounded(base / "cmdline", limits.maximum_args_bytes + 1U);
        if (cmdline.contents.has_value()) {
            info.args = split_cmdline(*cmdline.contents, limits.maximum_args, limits.maximum_args_bytes, info.args_truncated);
            info.args_truncated = info.args_truncated || cmdline.truncated;
            if (info.args_truncated) info.mark_unavailable("process.args", unavailable_reason::truncated);
        } else {
            info.mark_unavailable("process.args", cmdline.reason);
        }

        reason = unavailable_reason::process_exited;
        if (const auto cwd = read_link(base / "cwd", reason); cwd.has_value()) {
            info.cwd = cwd->substr(0U, limits.maximum_path_bytes);
        } else {
            info.mark_unavailable("process.cwd", reason);
        }

        if (limits.collect_environment) {
            const auto environ = read_bounded(base / "environ", maximum_environ_bytes);
            if (environ.contents.has_value()) {
                const std::string_view text{*environ.contents};
                std::size_t start = 0U;
                while (start < text.size()) {
                    auto end = text.find('\0', start);
                    if (end == std::string_view::npos) end = text.size();
                    const auto entry = text.substr(start, end - start);
                    start = end + 1U;
                    const auto equals = entry.find('=');
                    if (equals == std::string_view::npos) continue;
                    const auto name = entry.substr(0U, equals);
                    const auto& allow = environment_allowlist();
                    if (std::find(allow.begin(), allow.end(), name) != allow.end()) {
                        info.env.emplace(std::string{name}, std::string{entry.substr(equals + 1U, limits.maximum_path_bytes)});
                    }
                }
                if (environ.truncated) info.mark_unavailable("process.env", unavailable_reason::truncated);
            } else {
                info.mark_unavailable("process.env", environ.reason);
            }
        }
    }

    bool namespaces_missing = false;
    for (std::size_t index = 0U; index < namespace_names.size(); ++index) {
        auto reason = unavailable_reason::process_exited;
        if (const auto target = read_link(base / "ns" / namespace_names[index], reason); target.has_value()) {
            info.namespaces[index] = parse_namespace_link(*target);
        } else {
            namespaces_missing = true;
        }
    }
    if (namespaces_missing) info.mark_unavailable("process.namespaces", unavailable_reason::permission_denied);

    if (const auto cgroup = read_bounded(base / "cgroup", maximum_cgroup_bytes); cgroup.contents.has_value()) {
        info.cgroup = select_cgroup(*cgroup.contents);
    } else {
        info.mark_unavailable("process.cgroup", cgroup.reason);
    }
    info.creds.loginuid = parse_optional_id(read_bounded(base / "loginuid", 32U).contents);
    info.creds.sessionid = parse_optional_id(read_bounded(base / "sessionid", 32U).contents);

    // A PID reused while the files above were read would mix two processes into one record.
    if (const auto again = read_start_ticks(proc_root, pid); again.has_value() && *again != info.start_ticks) {
        return error{error_code::target_mismatch, "pid was reused during the read"};
    }
    return info;
}

}  // namespace panopticon::linux_agent::sensor
