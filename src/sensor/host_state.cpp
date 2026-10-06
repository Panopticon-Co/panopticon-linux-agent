#include "panopticon/linux_agent/sensor/host_state.hpp"

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"
#include "panopticon/linux_agent/sensor/persistence.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <map>
#include <system_error>

namespace panopticon::linux_agent::sensor {

namespace fs = std::filesystem;

namespace {

constexpr std::size_t maximum_line_bytes = 64U * 1024U;

unavailable_reason reason_for_errno(const int error) noexcept {
    if (error == EACCES || error == EPERM) return unavailable_reason::permission_denied;
    if (error == ENOENT || error == ENOTDIR) return unavailable_reason::kernel_feature_missing;
    return unavailable_reason::not_supported_by_provider;
}

// Reads at most `maximum` bytes of a regular file. O_NONBLOCK so a FIFO planted at a well-known
// path cannot hang the collector; directories and devices are refused.
std::optional<std::string> read_bounded(const fs::path& path, const std::size_t maximum, unavailable_reason& reason) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        reason = reason_for_errno(errno);
        return std::nullopt;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        ::close(fd);
        reason = unavailable_reason::not_supported_by_provider;
        return std::nullopt;
    }
    std::string contents;
    char buffer[8192];
    while (contents.size() < maximum) {
        const auto want = std::min(sizeof(buffer), maximum - contents.size());
        const auto got = ::read(fd, buffer, want);
        if (got < 0) {
            if (errno == EINTR) continue;
            const auto saved = errno;
            ::close(fd);
            reason = reason_for_errno(saved);
            return std::nullopt;
        }
        if (got == 0) break;
        contents.append(buffer, static_cast<std::size_t>(got));
    }
    ::close(fd);
    return contents;
}

std::string trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\n' || text.front() == '\r')) text.remove_prefix(1U);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\n' || text.back() == '\r')) text.remove_suffix(1U);
    return std::string{text};
}

std::vector<std::string_view> split(std::string_view text, const char separator, const std::size_t maximum_parts = 0U) {
    std::vector<std::string_view> parts;
    while (true) {
        if (maximum_parts != 0U && parts.size() + 1U == maximum_parts) {
            parts.push_back(text);
            break;
        }
        const auto at = text.find(separator);
        if (at == std::string_view::npos) {
            parts.push_back(text);
            break;
        }
        parts.push_back(text.substr(0U, at));
        text.remove_prefix(at + 1U);
    }
    return parts;
}

// Lines are bounded: an over-long line is skipped rather than parsed.
std::vector<std::string_view> lines_of(std::string_view contents) {
    std::vector<std::string_view> lines;
    while (!contents.empty()) {
        const auto at = contents.find('\n');
        auto line = contents.substr(0U, at);
        contents.remove_prefix(at == std::string_view::npos ? contents.size() : at + 1U);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1U);
        if (line.size() <= maximum_line_bytes) lines.push_back(line);
    }
    return lines;
}

template <typename integer>
std::optional<integer> parse_integer(std::string_view text, const int base = 10) {
    integer value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

std::vector<std::string> split_strings(std::string_view text, const char separator) {
    std::vector<std::string> out;
    for (const auto part : split(text, separator)) {
        if (!part.empty()) out.emplace_back(part);
    }
    return out;
}

void write_string_array(json_writer& out, const std::vector<std::string>& values) {
    out.begin_array();
    for (const auto& value : values) out.value(value);
    out.end_array();
}

bool has_option(const std::vector<std::string>& options, std::string_view wanted) {
    return std::find(options.begin(), options.end(), wanted) != options.end();
}

// Collects `unavailable` entries while reading files for one object.
class collector {
public:
    collector(std::string object, std::string mechanism, const host_state_options& options) : options_{options}, root_{options.root} {
        snapshot_.object = std::move(object);
        snapshot_.mechanism = std::move(mechanism);
    }

    std::optional<std::string> read(const std::string& relative, const std::string& field) {
        unavailable_reason reason{};
        auto contents = read_bounded(root_ / relative, options_.maximum_file_bytes, reason);
        if (!contents.has_value()) snapshot_.unavailable.push_back({field, reason});
        return contents;
    }
    // Same, but a missing file is an absent feature and not worth reporting.
    std::optional<std::string> read_optional(const std::string& relative, const std::string& field) {
        unavailable_reason reason{};
        auto contents = read_bounded(root_ / relative, options_.maximum_file_bytes, reason);
        if (!contents.has_value() && reason != unavailable_reason::kernel_feature_missing) snapshot_.unavailable.push_back({field, reason});
        return contents;
    }
    void add(json_writer&& item) {
        if (snapshot_.items.size() >= options_.maximum_items) {
            if (!snapshot_.truncated) snapshot_.unavailable.push_back({snapshot_.object + ".items", unavailable_reason::truncated});
            snapshot_.truncated = true;
            return;
        }
        snapshot_.items.push_back(item.take());
    }
    state_snapshot& snapshot() { return snapshot_; }

private:
    const host_state_options& options_;
    fs::path root_;
    state_snapshot snapshot_;
};

// ---- host ---------------------------------------------------------------------------------

std::string first_line(const std::optional<std::string>& contents) {
    if (!contents.has_value()) return {};
    return trim(std::string_view{*contents}.substr(0U, contents->find('\n')));
}

std::optional<std::uint64_t> meminfo_kb(std::string_view meminfo, std::string_view key) {
    for (const auto line : lines_of(meminfo)) {
        if (line.substr(0U, key.size()) != key || line.size() <= key.size() || line[key.size()] != ':') continue;
        const auto fields = split_strings(trim(line.substr(key.size() + 1U)), ' ');
        if (!fields.empty()) return parse_integer<std::uint64_t>(fields[0]);
    }
    return std::nullopt;
}

state_snapshot collect_host(const host_state_options& options) {
    collector c{"host", "PROCFS+SYSFS+ETC", options};
    json_writer out;
    out.begin_object();

    out.field("hostname", first_line(c.read("proc/sys/kernel/hostname", "host.hostname")));

    os_release_info os;
    auto release = c.read_optional("etc/os-release", "host.os");
    if (!release.has_value()) release = c.read("usr/lib/os-release", "host.os");
    if (release.has_value()) os = parse_os_release(*release);
    out.key("os").begin_object();
    out.field("id", os.id).field("id_like", os.id_like).field("name", os.name).field("pretty_name", os.pretty_name);
    out.field("version_id", os.version_id).field("version_codename", os.version_codename);
    out.end_object();

    out.key("kernel").begin_object();
    out.field("release", first_line(c.read("proc/sys/kernel/osrelease", "host.kernel.release")));
    out.field("version", first_line(c.read("proc/sys/kernel/version", "host.kernel.version")));
    const auto cmdline = c.read("proc/cmdline", "host.kernel.cmdline");
    out.field("cmdline", cmdline.has_value() ? redact_kernel_cmdline(trim(*cmdline)) : std::string{});
    const auto tainted = c.read("proc/sys/kernel/tainted", "host.kernel.tainted");
    const auto taint_value = tainted.has_value() ? parse_integer<std::uint64_t>(trim(*tainted)) : std::nullopt;
    out.key("tainted").begin_object();
    if (taint_value.has_value()) {
        out.field("value", *taint_value);
        out.key("flags");
        write_string_array(out, decode_taint(*taint_value));
    } else {
        out.field_null("value");
        out.key("flags").begin_array().end_array();
    }
    out.end_object();
    out.end_object();

    out.key("boot").begin_object();
    out.field("boot_id", first_line(c.read("proc/sys/kernel/random/boot_id", "host.boot.boot_id")));
    if (const auto stat = c.read("proc/stat", "host.boot.time")) {
        std::optional<std::uint64_t> btime;
        for (const auto line : lines_of(*stat)) {
            if (line.substr(0U, 6U) == "btime ") btime = parse_integer<std::uint64_t>(trim(line.substr(6U)));
        }
        if (btime.has_value()) out.field("boot_time_unix", *btime);
        else out.field_null("boot_time_unix");
    } else {
        out.field_null("boot_time_unix");
    }
    if (const auto uptime = c.read("proc/uptime", "host.boot.uptime")) {
        const auto seconds = split_strings(*uptime, ' ');
        const auto whole = seconds.empty() ? std::string{} : seconds[0].substr(0U, seconds[0].find('.'));
        if (const auto value = parse_integer<std::uint64_t>(whole)) out.field("uptime_seconds", *value);
        else out.field_null("uptime_seconds");
    } else {
        out.field_null("uptime_seconds");
    }
    out.end_object();

    out.key("hardware").begin_object();
    std::uint64_t cpus = 0U;
    std::string cpu_model;
    bool hypervisor = false;
    if (const auto cpuinfo = c.read("proc/cpuinfo", "host.hardware.cpu")) {
        for (const auto line : lines_of(*cpuinfo)) {
            const auto colon = line.find(':');
            if (colon == std::string_view::npos) continue;
            const auto key = trim(line.substr(0U, colon));
            const auto value = trim(line.substr(colon + 1U));
            if (key == "processor") ++cpus;
            if (key == "model name" && cpu_model.empty()) cpu_model = value;
            if (key == "flags" && !hypervisor) hypervisor = (" " + value + " ").find(" hypervisor ") != std::string::npos;
        }
    }
    out.field("cpu_count", cpus).field("cpu_model", cpu_model);
    if (const auto meminfo = c.read("proc/meminfo", "host.hardware.memory")) {
        if (const auto total = meminfo_kb(*meminfo, "MemTotal")) out.field("memory_total_kb", *total);
        else out.field_null("memory_total_kb");
    } else {
        out.field_null("memory_total_kb");
    }
    out.key("virtualization").begin_object();
    out.field("hypervisor", hypervisor);
    // DMI vendor/product are world-readable; serial numbers and the product uuid are root-only
    // and deliberately not collected (privacy; see the security model).
    out.field("sys_vendor", first_line(c.read_optional("sys/class/dmi/id/sys_vendor", "host.hardware.dmi")));
    out.field("product_name", first_line(c.read_optional("sys/class/dmi/id/product_name", "host.hardware.dmi")));
    out.end_object();
    out.end_object();

    // machine-id is treated as confidential by systemd; only a salted digest leaves the host.
    if (const auto machine_id = c.read("etc/machine-id", "host.machine_id")) {
        out.field("machine_id_sha256", sha256_hex("panopticon-machine-id|" + trim(*machine_id)).substr(0U, 32U));
    } else {
        out.field_null("machine_id_sha256");
    }

    out.end_object();
    c.add(std::move(out));
    return std::move(c.snapshot());
}

// ---- posture ------------------------------------------------------------------------------

state_snapshot collect_posture(const host_state_options& options) {
    collector c{"posture", "SYSFS+PROCFS", options};
    json_writer out;
    out.begin_object();

    // Lockdown: "none [integrity] confidentiality" with the active mode in brackets.
    if (const auto lockdown = c.read_optional("sys/kernel/security/lockdown", "posture.lockdown")) {
        std::string active = "unknown";
        const auto text = trim(*lockdown);
        const auto open = text.find('[');
        const auto close = text.find(']');
        if (open != std::string::npos && close != std::string::npos && close > open) active = text.substr(open + 1U, close - open - 1U);
        out.field("lockdown", active);
    } else {
        out.field_null("lockdown");
    }

    // Secure Boot: EFI variable = 4 attribute bytes + 1 value byte; no efi directory = BIOS boot.
    unavailable_reason reason{};
    const fs::path efi = options.root / "sys/firmware/efi";
    std::error_code ec;
    if (!fs::exists(efi, ec)) {
        out.field("secure_boot", "not_efi");
    } else if (const auto var = read_bounded(efi / "efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", 16U, reason); var && var->size() == 5U) {
        out.field("secure_boot", (*var)[4] != '\0' ? "enabled" : "disabled");
    } else {
        c.snapshot().unavailable.push_back({"posture.secure_boot", var ? unavailable_reason::not_supported_by_provider : reason});
        out.field_null("secure_boot");
    }

    out.key("lsm");
    if (const auto lsm = c.read_optional("sys/kernel/security/lsm", "posture.lsm")) write_string_array(out, split_strings(trim(*lsm), ','));
    else out.begin_array().end_array();

    if (const auto selinux = c.read_optional("sys/fs/selinux/enforce", "posture.selinux")) out.field("selinux", trim(*selinux) == "1" ? "enforcing" : "permissive");
    else out.field("selinux", "absent");
    if (const auto apparmor = c.read_optional("sys/module/apparmor/parameters/enabled", "posture.apparmor")) out.field("apparmor", trim(*apparmor) == "Y" ? "enabled" : "disabled");
    else out.field("apparmor", "absent");

    // Each sysctl is an integer when it parses as one, otherwise text; null when unreadable.
    static const char* const sysctls[] = {
        "kernel/kptr_restrict", "kernel/dmesg_restrict", "kernel/perf_event_paranoid", "kernel/unprivileged_bpf_disabled",
        "kernel/modules_disabled", "kernel/randomize_va_space", "kernel/yama/ptrace_scope", "kernel/sysrq",
        "kernel/core_pattern", "fs/suid_dumpable", "fs/protected_symlinks", "fs/protected_hardlinks",
        "user/max_user_namespaces", "kernel/unprivileged_userns_clone", "net/ipv4/ip_forward",
    };
    out.key("sysctl").begin_object();
    for (const auto* name : sysctls) {
        const auto value = c.read_optional(std::string{"proc/sys/"} + name, std::string{"posture.sysctl."} + name);
        out.key(name);
        if (!value.has_value()) {
            out.null();
        } else if (const auto number = parse_integer<std::int64_t>(trim(*value))) {
            out.value(*number);
        } else {
            out.value(first_line(value));
        }
    }
    out.end_object();

    out.end_object();
    c.add(std::move(out));
    return std::move(c.snapshot());
}

// ---- users and groups ---------------------------------------------------------------------

state_snapshot collect_users(const host_state_options& options) {
    collector c{"users", "ETC", options};
    const auto passwd = c.read("etc/passwd", "users.passwd");
    // /etc/shadow is root-only; only a coarse state is ever reported, never the hash.
    std::map<std::string, std::string> password_state;
    if (const auto shadow = c.read("etc/shadow", "users.password_state")) {
        for (const auto line : lines_of(*shadow)) {
            const auto fields = split(line, ':', 3U);
            if (fields.size() < 2U || fields[0].empty()) continue;
            const auto hash = fields[1];
            password_state[std::string{fields[0]}] = hash.empty() ? "empty" : (hash.front() == '!' || hash.front() == '*') ? "locked" : "set";
        }
    }
    if (passwd.has_value()) {
        for (const auto& entry : parse_passwd(*passwd, options.maximum_items + 1U)) {
            json_writer out;
            out.begin_object();
            out.field("name", entry.name).field("uid", entry.uid).field("gid", entry.gid);
            out.field("home", entry.home).field("shell", entry.shell);
            const bool login_shell = !entry.shell.empty() && entry.shell.find("nologin") == std::string::npos && entry.shell != "/bin/false" && entry.shell != "/usr/bin/false";
            out.field("login_shell", login_shell);
            out.field("system_account", entry.uid != 0U && entry.uid < 1000U);
            out.field("uid0_non_root", entry.uid == 0U && entry.name != "root");
            if (const auto state = password_state.find(entry.name); state != password_state.end()) out.field("password_state", state->second);
            else out.field_null("password_state");
            out.end_object();
            c.add(std::move(out));
        }
    }
    return std::move(c.snapshot());
}

state_snapshot collect_groups(const host_state_options& options) {
    collector c{"groups", "ETC", options};
    if (const auto contents = c.read("etc/group", "groups.group")) {
        for (const auto& entry : parse_group(*contents, options.maximum_items + 1U)) {
            json_writer out;
            out.begin_object();
            out.field("name", entry.name).field("gid", entry.gid);
            out.key("members");
            write_string_array(out, entry.members);
            out.end_object();
            c.add(std::move(out));
        }
    }
    return std::move(c.snapshot());
}

// ---- interfaces ---------------------------------------------------------------------------

struct interface_address {
    std::string family;
    std::string address;
    int prefix{};
};

int prefix_length(const sockaddr* mask) {
    if (mask == nullptr) return 0;
    const unsigned char* bytes = nullptr;
    std::size_t length = 0U;
    if (mask->sa_family == AF_INET) {
        bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in*>(mask)->sin_addr);
        length = 4U;
    } else if (mask->sa_family == AF_INET6) {
        bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(mask)->sin6_addr);
        length = 16U;
    } else {
        return 0;
    }
    int bits = 0;
    for (std::size_t i = 0U; i < length; ++i) bits += __builtin_popcount(bytes[i]);
    return bits;
}

std::map<std::string, std::vector<interface_address>> live_addresses(bool& failed) {
    std::map<std::string, std::vector<interface_address>> result;
    ifaddrs* head = nullptr;
    if (::getifaddrs(&head) != 0) {
        failed = true;
        return result;
    }
    for (const ifaddrs* entry = head; entry != nullptr; entry = entry->ifa_next) {
        if (entry->ifa_addr == nullptr || entry->ifa_name == nullptr) continue;
        char text[INET6_ADDRSTRLEN] = {};
        interface_address address;
        if (entry->ifa_addr->sa_family == AF_INET) {
            ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(entry->ifa_addr)->sin_addr, text, sizeof(text));
            address.family = "inet";
        } else if (entry->ifa_addr->sa_family == AF_INET6) {
            ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(entry->ifa_addr)->sin6_addr, text, sizeof(text));
            address.family = "inet6";
        } else {
            continue;
        }
        address.address = text;
        address.prefix = prefix_length(entry->ifa_netmask);
        result[entry->ifa_name].push_back(std::move(address));
    }
    ::freeifaddrs(head);
    return result;
}

state_snapshot collect_interfaces(const host_state_options& options) {
    collector c{"interfaces", "SYSFS+GETIFADDRS", options};
    std::map<std::string, std::vector<interface_address>> addresses;
    if (options.root == fs::path{"/"}) {
        bool failed = false;
        addresses = live_addresses(failed);
        if (failed) c.snapshot().unavailable.push_back({"interfaces.addresses", unavailable_reason::not_supported_by_provider});
    } else {
        c.snapshot().unavailable.push_back({"interfaces.addresses", unavailable_reason::not_applicable});
    }
    std::error_code ec;
    std::vector<std::string> names;
    for (fs::directory_iterator it{options.root / "sys/class/net", ec}, end; !ec && it != end; it.increment(ec)) names.push_back(it->path().filename().string());
    if (ec) c.snapshot().unavailable.push_back({"interfaces.list", reason_for_errno(ec.value())});
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
        const auto base = "sys/class/net/" + name + "/";
        json_writer out;
        out.begin_object();
        out.field("name", name);
        out.field("mac", first_line(c.read_optional(base + "address", "interfaces.mac")));
        out.field("operstate", first_line(c.read_optional(base + "operstate", "interfaces.operstate")));
        const auto mtu = parse_integer<std::uint64_t>(first_line(c.read_optional(base + "mtu", "interfaces.mtu")));
        if (mtu.has_value()) out.field("mtu", *mtu);
        else out.field_null("mtu");
        const auto type = parse_integer<std::uint64_t>(first_line(c.read_optional(base + "type", "interfaces.type")));
        if (type.has_value()) out.field("arphrd_type", *type);
        else out.field_null("arphrd_type");
        out.key("addresses").begin_array();
        if (const auto found = addresses.find(name); found != addresses.end()) {
            for (const auto& address : found->second) {
                out.begin_object().field("family", address.family).field("address", address.address);
                out.field("prefix", static_cast<std::int64_t>(address.prefix)).end_object();
            }
        }
        out.end_array();
        out.end_object();
        c.add(std::move(out));
    }
    return std::move(c.snapshot());
}

// ---- mounts and modules ---------------------------------------------------------------------

state_snapshot collect_mounts(const host_state_options& options) {
    collector c{"mounts", "PROCFS", options};
    if (const auto contents = c.read("proc/self/mountinfo", "mounts.mountinfo")) {
        for (const auto& entry : parse_mountinfo(*contents, options.maximum_items + 1U)) {
            json_writer out;
            out.begin_object();
            out.field("mount_id", entry.mount_id).field("parent_id", entry.parent_id).field("device", entry.device);
            out.field("root", entry.root).field("mount_point", entry.mount_point).field("fs_type", entry.fs_type).field("source", entry.source);
            out.key("options");
            write_string_array(out, entry.options);
            out.key("super_options");
            write_string_array(out, entry.super_options);
            out.field("nosuid", has_option(entry.options, "nosuid"));
            out.field("noexec", has_option(entry.options, "noexec"));
            out.field("nodev", has_option(entry.options, "nodev"));
            out.field("read_only", has_option(entry.options, "ro"));
            out.end_object();
            c.add(std::move(out));
        }
    }
    return std::move(c.snapshot());
}

state_snapshot collect_modules(const host_state_options& options) {
    collector c{"modules", "PROCFS", options};
    if (const auto contents = c.read("proc/modules", "modules.list")) {
        for (const auto& entry : parse_proc_modules(*contents, options.maximum_items + 1U)) {
            json_writer out;
            out.begin_object();
            out.field("name", entry.name).field("size", entry.size).field("refcount", entry.refcount).field("state", entry.state);
            out.key("used_by");
            write_string_array(out, entry.used_by);
            out.end_object();
            c.add(std::move(out));
        }
    }
    return std::move(c.snapshot());
}

// ---- packages and devices ---------------------------------------------------------------------

constexpr std::size_t maximum_package_database_bytes = 48U * 1024U * 1024U;

state_snapshot collect_packages(const host_state_options& options) {
    collector c{"packages", "PKGDB", options};
    unavailable_reason reason{};
    const auto contents = read_bounded(options.root / "var/lib/dpkg/status", maximum_package_database_bytes, reason);
    if (!contents.has_value()) {
        std::error_code ignored;
        const bool rpm = fs::exists(options.root / "var/lib/rpm", ignored) || fs::exists(options.root / "usr/lib/sysimage/rpm", ignored);
        // rpm needs librpm or a child process; that is not implemented, and saying so beats an empty list.
        c.snapshot().unavailable.push_back({rpm ? "packages.rpm" : "packages.dpkg", rpm ? unavailable_reason::not_supported_by_provider : reason});
        return std::move(c.snapshot());
    }
    for (const auto& entry : parse_dpkg_status(*contents, options.maximum_items + 1U)) {
        json_writer out;
        out.begin_object();
        out.field("name", entry.name).field("version", entry.version).field("architecture", entry.architecture);
        if (!entry.source.empty()) out.field("source", entry.source);
        out.field("manager", "dpkg");
        out.end_object();
        c.add(std::move(out));
    }
    return std::move(c.snapshot());
}

state_snapshot collect_devices(const host_state_options& options) {
    collector c{"devices", "SYSFS", options};
    std::error_code ec;
    std::vector<std::string> names;
    for (fs::directory_iterator it{options.root / "sys/bus/usb/devices", ec}, end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().filename().string();
        if (name.find(':') == std::string::npos) names.push_back(name);  // interfaces are "1-1:1.0"
    }
    if (ec && ec != std::errc::no_such_file_or_directory) c.snapshot().unavailable.push_back({"devices.usb", reason_for_errno(ec.value())});
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
        const auto base = "sys/bus/usb/devices/" + name + "/";
        json_writer out;
        out.begin_object();
        out.field("bus", "usb").field("path", name);
        out.field("vendor_id", first_line(c.read_optional(base + "idVendor", "devices.vendor_id")));
        out.field("product_id", first_line(c.read_optional(base + "idProduct", "devices.product_id")));
        out.field("class", first_line(c.read_optional(base + "bDeviceClass", "devices.class")));
        out.field("manufacturer", first_line(c.read_optional(base + "manufacturer", "devices.manufacturer")));
        out.field("product", first_line(c.read_optional(base + "product", "devices.product")));
        out.field("serial", first_line(c.read_optional(base + "serial", "devices.serial")));
        out.end_object();
        c.add(std::move(out));
    }
    return std::move(c.snapshot());
}

}  // namespace

// ---- public parsers -------------------------------------------------------------------------

os_release_info parse_os_release(const std::string_view contents) {
    os_release_info info;
    for (const auto line : lines_of(contents)) {
        const auto text = trim(line);
        if (text.empty() || text.front() == '#') continue;
        const auto equals = text.find('=');
        if (equals == std::string::npos) continue;
        const auto key = text.substr(0U, equals);
        auto value = trim(std::string_view{text}.substr(equals + 1U));
        if (value.size() >= 2U && (value.front() == '"' || value.front() == '\'') && value.back() == value.front()) {
            const auto inner = value.substr(1U, value.size() - 2U);
            value.clear();
            for (std::size_t i = 0U; i < inner.size(); ++i) {
                if (inner[i] == '\\' && i + 1U < inner.size() && std::strchr("\"\\$`", inner[i + 1U]) != nullptr) ++i;
                value.push_back(inner[i]);
            }
        }
        if (key == "ID") info.id = value;
        else if (key == "ID_LIKE") info.id_like = value;
        else if (key == "NAME") info.name = value;
        else if (key == "PRETTY_NAME") info.pretty_name = value;
        else if (key == "VERSION_ID") info.version_id = value;
        else if (key == "VERSION_CODENAME") info.version_codename = value;
    }
    return info;
}

std::vector<passwd_entry> parse_passwd(const std::string_view contents, const std::size_t maximum_entries) {
    std::vector<passwd_entry> entries;
    for (const auto line : lines_of(contents)) {
        if (entries.size() >= maximum_entries) break;
        if (line.empty() || line.front() == '#') continue;
        const auto fields = split(line, ':');
        if (fields.size() < 7U || fields[0].empty()) continue;
        const auto uid = parse_integer<std::uint32_t>(fields[2]);
        const auto gid = parse_integer<std::uint32_t>(fields[3]);
        if (!uid.has_value() || !gid.has_value()) continue;
        entries.push_back({std::string{fields[0]}, std::string{fields[1]}, *uid, *gid, std::string{fields[5]}, std::string{fields[6]}});
    }
    return entries;
}

std::vector<group_entry> parse_group(const std::string_view contents, const std::size_t maximum_entries) {
    std::vector<group_entry> entries;
    for (const auto line : lines_of(contents)) {
        if (entries.size() >= maximum_entries) break;
        if (line.empty() || line.front() == '#') continue;
        const auto fields = split(line, ':');
        if (fields.size() < 4U || fields[0].empty()) continue;
        const auto gid = parse_integer<std::uint32_t>(fields[2]);
        if (!gid.has_value()) continue;
        entries.push_back({std::string{fields[0]}, *gid, split_strings(fields[3], ',')});
    }
    return entries;
}

std::string decode_mount_escapes(const std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0U; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 3U < text.size() && text[i + 1U] >= '0' && text[i + 1U] <= '3' && text[i + 2U] >= '0' && text[i + 2U] <= '7' &&
            text[i + 3U] >= '0' && text[i + 3U] <= '7') {
            out.push_back(static_cast<char>(((text[i + 1U] - '0') << 6) | ((text[i + 2U] - '0') << 3) | (text[i + 3U] - '0')));
            i += 3U;
        } else {
            out.push_back(text[i]);
        }
    }
    return out;
}

std::vector<mount_entry> parse_mountinfo(const std::string_view contents, const std::size_t maximum_entries) {
    std::vector<mount_entry> entries;
    for (const auto line : lines_of(contents)) {
        if (entries.size() >= maximum_entries) break;
        const auto fields = split_strings(line, ' ');
        // id parent major:minor root mountpoint options [optional...] - fstype source superoptions
        const auto separator = std::find(fields.begin(), fields.end(), "-");
        if (fields.size() < 10U || separator == fields.end() || static_cast<std::size_t>(separator - fields.begin()) < 6U ||
            static_cast<std::size_t>(fields.end() - separator) < 4U) {
            continue;
        }
        const auto id = parse_integer<std::uint32_t>(fields[0]);
        const auto parent = parse_integer<std::uint32_t>(fields[1]);
        if (!id.has_value() || !parent.has_value()) continue;
        mount_entry entry;
        entry.mount_id = *id;
        entry.parent_id = *parent;
        entry.device = fields[2];
        entry.root = decode_mount_escapes(fields[3]);
        entry.mount_point = decode_mount_escapes(fields[4]);
        entry.options = split_strings(fields[5], ',');
        entry.fs_type = *(separator + 1);
        entry.source = decode_mount_escapes(*(separator + 2));
        entry.super_options = split_strings(*(separator + 3), ',');
        entries.push_back(std::move(entry));
    }
    return entries;
}

std::vector<module_entry> parse_proc_modules(const std::string_view contents, const std::size_t maximum_entries) {
    std::vector<module_entry> entries;
    for (const auto line : lines_of(contents)) {
        if (entries.size() >= maximum_entries) break;
        const auto fields = split_strings(line, ' ');
        if (fields.size() < 5U) continue;
        const auto size = parse_integer<std::uint64_t>(fields[1]);
        const auto refcount = parse_integer<std::int64_t>(fields[2]);
        if (!size.has_value() || !refcount.has_value()) continue;
        module_entry entry;
        entry.name = fields[0];
        entry.size = *size;
        entry.refcount = *refcount;
        if (fields[3] != "-") entry.used_by = split_strings(fields[3], ',');
        entry.state = fields[4];
        entries.push_back(std::move(entry));
    }
    return entries;
}

std::vector<package_entry> parse_dpkg_status(const std::string_view contents, const std::size_t maximum_entries) {
    std::vector<package_entry> entries;
    package_entry current;
    bool installed = false;
    const auto finish = [&] {
        if (installed && !current.name.empty() && entries.size() < maximum_entries) entries.push_back(std::move(current));
        current = {};
        installed = false;
    };
    for (const auto line : lines_of(contents)) {
        if (line.empty()) {
            finish();
            continue;
        }
        if (line.front() == ' ' || line.front() == '\t') continue;  // continuation of a long field
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        const auto field = line.substr(0U, colon);
        const auto value = trim(line.substr(colon + 1U));
        if (field == "Package") current.name = value.substr(0U, 256U);
        else if (field == "Version") current.version = value.substr(0U, 128U);
        else if (field == "Architecture") current.architecture = value.substr(0U, 32U);
        else if (field == "Source") current.source = value.substr(0U, 256U);
        else if (field == "Status") installed = value.size() >= 9U && value.substr(value.size() - 9U) == "installed" && value.find("not-installed") == std::string::npos;
    }
    finish();
    return entries;
}

std::string package_database_signature(const host_state_options& options) {
    struct stat info {};
    const auto path = (options.root / "var/lib/dpkg/status").string();
    if (::stat(path.c_str(), &info) != 0) return {};
    return std::to_string(static_cast<long long>(info.st_mtim.tv_sec)) + "." + std::to_string(static_cast<long long>(info.st_mtim.tv_nsec)) + ":" +
           std::to_string(static_cast<long long>(info.st_size));
}

std::vector<std::string> decode_taint(const std::uint64_t value) {
    static const char* const names[] = {
        "proprietary_module", "forced_module", "smp_unsafe", "forced_rmmod", "machine_check", "bad_page", "user_request",
        "kernel_die", "acpi_override", "kernel_warning", "staging_driver", "firmware_workaround", "out_of_tree_module",
        "unsigned_module", "soft_lockup", "live_patch", "auxiliary", "struct_randomization", "in_kernel_test",
    };
    std::vector<std::string> flags;
    for (std::size_t bit = 0U; bit < sizeof(names) / sizeof(names[0]); ++bit) {
        if ((value >> bit) & 1U) flags.emplace_back(names[bit]);
    }
    return flags;
}

std::string redact_kernel_cmdline(const std::string_view cmdline) {
    std::string out;
    for (const auto token : split(cmdline, ' ')) {
        if (token.empty()) continue;
        if (!out.empty()) out.push_back(' ');
        const auto equals = token.find('=');
        if (equals != std::string_view::npos) {
            std::string key{token.substr(0U, equals)};
            std::transform(key.begin(), key.end(), key.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            if (key.find("pass") != std::string::npos || key.find("secret") != std::string::npos || key.find("token") != std::string::npos ||
                key.find("key") != std::string::npos) {
                out.append(token.substr(0U, equals + 1U)).append("[redacted]");
                continue;
            }
        }
        out.append(token);
    }
    return out;
}

const std::vector<std::string_view>& state_objects() {
    static const std::vector<std::string_view> objects{"host", "posture", "users", "groups", "interfaces", "mounts", "modules", "persistence", "packages", "devices"};
    return objects;
}

namespace {

state_snapshot collect_persistence(const host_state_options& options) {
    persistence_options scan_options;
    scan_options.root = options.root;
    scan_options.maximum_items = options.maximum_items;
    persistence_catalog catalog{scan_options};
    auto scan = catalog.scan();
    state_snapshot snapshot;
    snapshot.object = "persistence";
    snapshot.mechanism = "FSSCAN";
    snapshot.truncated = scan.truncated;
    snapshot.unavailable = std::move(scan.unavailable);
    snapshot.items.reserve(scan.items.size());
    for (const auto& item : scan.items) snapshot.items.push_back(persistence_item_json(item));
    return snapshot;
}

}  // namespace

std::optional<state_snapshot> collect_state(const std::string_view object, const host_state_options& options) {
    if (object == "host") return collect_host(options);
    if (object == "posture") return collect_posture(options);
    if (object == "users") return collect_users(options);
    if (object == "groups") return collect_groups(options);
    if (object == "interfaces") return collect_interfaces(options);
    if (object == "mounts") return collect_mounts(options);
    if (object == "modules") return collect_modules(options);
    if (object == "persistence") return collect_persistence(options);
    if (object == "packages") return collect_packages(options);
    if (object == "devices") return collect_devices(options);
    return std::nullopt;
}

}  // namespace panopticon::linux_agent::sensor
