#include "panopticon/linux_agent/sensor/host_state.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

int failures = 0;

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

bool contains(const std::string_view haystack, const std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

fs::path fresh_directory(const std::string& name) {
    const auto directory = fs::temp_directory_path() / ("panopticon-state-tests-" + std::to_string(::getpid())) / name;
    fs::remove_all(directory);
    fs::create_directories(directory);
    return directory;
}

void write_file(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << contents;
}

// Minimal structural JSON check: balanced braces/brackets outside strings, no raw control bytes.
bool looks_like_json_object(const std::string& text) {
    if (text.size() < 2U || text.front() != '{' || text.back() != '}') return false;
    int depth = 0;
    bool in_string = false;
    for (std::size_t i = 0U; i < text.size(); ++i) {
        const char ch = text[i];
        if (in_string) {
            if (static_cast<unsigned char>(ch) < 0x20U) return false;
            if (ch == '\\') ++i;
            else if (ch == '"') in_string = false;
            continue;
        }
        if (ch == '"') in_string = true;
        else if (ch == '{' || ch == '[') ++depth;
        else if (ch == '}' || ch == ']') {
            if (--depth < 0) return false;
        }
    }
    return depth == 0 && !in_string;
}

void test_os_release_quoting() {
    const auto info = parse_os_release(
        "# comment\nNAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE='debian'\nVERSION_ID=\"22.04\"\n"
        "PRETTY_NAME=\"Ubuntu \\\"Jammy\\\" 22.04\"\nVERSION_CODENAME=jammy\nGARBAGE\n=novalue\n");
    require(info.id == "ubuntu" && info.id_like == "debian" && info.name == "Ubuntu", "basic keys");
    require(info.pretty_name == "Ubuntu \"Jammy\" 22.04", "escaped quotes decoded: " + info.pretty_name);
    require(info.version_id == "22.04" && info.version_codename == "jammy", "version keys");
    require(parse_os_release("").id.empty(), "empty input");
}

void test_passwd_and_group_hostile_lines() {
    const auto entries = parse_passwd(
        "root:x:0:0:root:/root:/bin/bash\n"
        "short:line\n"
        "bad:x:notanumber:1:::/bin/sh\n"
        ":x:5:5:::\n"
        "# comment\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "big:x:99999999999:1:::/bin/sh\n",
        100U);
    require(entries.size() == 2U, "only well-formed entries survive: " + std::to_string(entries.size()));
    require(entries[0].name == "root" && entries[0].uid == 0U && entries[1].shell == "/usr/sbin/nologin", "fields");
    require(parse_passwd("a:x:1:1:::/bin/sh\nb:x:2:2:::/bin/sh\nc:x:3:3:::/bin/sh\n", 2U).size() == 2U, "entry cap");

    const auto groups = parse_group("sudo:x:27:alice,bob\nempty:x:50:\nbad:x:zz:\nshort:x\n", 100U);
    require(groups.size() == 2U, "group parsing");
    require(groups[0].members.size() == 2U && groups[0].members[1] == "bob" && groups[1].members.empty(), "members");
}

void test_mountinfo_escapes_and_optional_fields() {
    const auto mounts = parse_mountinfo(
        "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 shared:2 - ext3 /dev/root rw,errors=continue\n"
        "40 36 0:30 / /with\\040space\\134back nosuid,nodev,noexec - tmpfs tmpfs rw\n"
        "garbage line\n"
        "41 36 0:31 / /x rw - \n",
        100U);
    require(mounts.size() == 2U, "malformed lines skipped: " + std::to_string(mounts.size()));
    require(mounts[0].mount_point == "/mnt2" && mounts[0].fs_type == "ext3" && mounts[0].source == "/dev/root", "optional fields tolerated");
    require(mounts[0].super_options.size() == 2U, "super options");
    require(mounts[1].mount_point == "/with space\\back", "octal escapes decoded: " + mounts[1].mount_point);
    require(decode_mount_escapes("\\04") == "\\04" && decode_mount_escapes("\\777") == "\\777", "invalid escapes preserved");
}

void test_modules_taint_and_cmdline() {
    const auto modules = parse_proc_modules(
        "nf_tables 266240 123 nft_chain_nat,nft_ct, Live 0x0000000000000000\n"
        "lonely 16384 0 - Live 0x0000000000000000\n"
        "broken 1\n"
        "neg x 0 - Live 0x0\n",
        100U);
    require(modules.size() == 2U, "module parsing");
    require(modules[0].used_by.size() == 2U && modules[0].refcount == 123 && modules[1].used_by.empty(), "used_by");

    require(decode_taint(0U).empty(), "untainted");
    const auto flags = decode_taint((1U << 0U) | (1U << 12U) | (1U << 13U));
    require(flags.size() == 3U && flags[0] == "proprietary_module" && flags[1] == "out_of_tree_module" && flags[2] == "unsigned_module", "taint flags");
    require(decode_taint(~std::uint64_t{0U}).size() >= 19U, "all bits do not crash");

    const auto redacted = redact_kernel_cmdline("BOOT_IMAGE=/vmlinuz root=/dev/sda1 cryptkey=abc123 ro rd.luks.key=s3cret quiet");
    require(!contains(redacted, "abc123") && !contains(redacted, "s3cret"), "secrets redacted: " + redacted);
    require(contains(redacted, "root=/dev/sda1") && contains(redacted, "quiet"), "ordinary parameters kept");
}

fs::path build_fake_root(const std::string& name) {
    const auto root = fresh_directory(name);
    write_file(root / "proc/sys/kernel/hostname", "testhost\n");
    write_file(root / "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nNAME=\"Debian GNU/Linux\"\n");
    write_file(root / "proc/sys/kernel/osrelease", "6.1.0-test\n");
    write_file(root / "proc/sys/kernel/version", "#1 SMP\n");
    write_file(root / "proc/cmdline", "root=/dev/vda1 ro password=hunter2\n");
    write_file(root / "proc/sys/kernel/tainted", "4096\n");
    write_file(root / "proc/sys/kernel/random/boot_id", "11111111-2222-3333-4444-555555555555\n");
    write_file(root / "proc/stat", "cpu  1 2 3\nbtime 1700000000\n");
    write_file(root / "proc/uptime", "1234.56 4321.00\n");
    write_file(root / "proc/cpuinfo", "processor\t: 0\nmodel name\t: Fake CPU\nflags\t\t: fpu hypervisor\n\nprocessor\t: 1\nmodel name\t: Fake CPU\n");
    write_file(root / "proc/meminfo", "MemTotal:       2048000 kB\nMemFree: 1 kB\n");
    write_file(root / "etc/machine-id", "0123456789abcdef0123456789abcdef\n");
    write_file(root / "sys/kernel/security/lockdown", "none [integrity] confidentiality\n");
    write_file(root / "sys/kernel/security/lsm", "lockdown,capability,apparmor,bpf\n");
    write_file(root / "sys/module/apparmor/parameters/enabled", "Y\n");
    write_file(root / "proc/sys/kernel/kptr_restrict", "2\n");
    write_file(root / "proc/sys/kernel/core_pattern", "|/usr/lib/systemd/systemd-coredump %P\n");
    write_file(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/nonexistent:/usr/sbin/nologin\nmallory:x:0:0::/:/bin/sh\n");
    write_file(root / "etc/shadow", "root:$6$salt$hash:19000:0:99999:7:::\nsvc:!:19000::::::\nmallory::19000::::::\n");
    write_file(root / "etc/group", "root:x:0:\nsudo:x:27:alice\n");
    write_file(root / "sys/class/net/eth0/address", "52:54:00:12:34:56\n");
    write_file(root / "sys/class/net/eth0/operstate", "up\n");
    write_file(root / "sys/class/net/eth0/mtu", "1500\n");
    write_file(root / "sys/class/net/eth0/type", "1\n");
    write_file(root / "proc/self/mountinfo", "22 1 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n23 22 0:5 / /tmp nosuid,nodev - tmpfs tmpfs rw\n");
    write_file(root / "proc/modules", "dummy 4096 0 - Live 0x0\n");
    return root;
}

void test_fake_root_collection() {
    host_state_options options;
    options.root = build_fake_root("fake-root");

    const auto host = collect_state("host", options);
    require(host.has_value() && host->items.size() == 1U, "host snapshot");
    const auto& h = host->items[0];
    require(looks_like_json_object(h), "host JSON valid: " + h);
    require(contains(h, "\"hostname\":\"testhost\"") && contains(h, "\"id\":\"debian\"") && contains(h, "\"release\":\"6.1.0-test\""), "host basics: " + h);
    require(contains(h, "\"value\":4096") && contains(h, "\"out_of_tree_module\""), "taint 4096 (bit 12) decoded: " + h);
    require(!contains(h, "hunter2") && contains(h, "password=[redacted]"), "kernel cmdline secret redacted: " + h);
    require(contains(h, "\"cpu_count\":2") && contains(h, "\"memory_total_kb\":2048000") && contains(h, "\"hypervisor\":true"), "hardware: " + h);
    require(contains(h, "\"boot_time_unix\":1700000000") && contains(h, "\"uptime_seconds\":1234"), "boot: " + h);
    require(!contains(h, "0123456789abcdef0123456789abcdef") && contains(h, "machine_id_sha256"), "machine-id never emitted raw: " + h);

    const auto posture = collect_state("posture", options);
    require(posture.has_value() && looks_like_json_object(posture->items[0]), "posture JSON valid");
    const auto& p = posture->items[0];
    require(contains(p, "\"lockdown\":\"integrity\"") && contains(p, "\"secure_boot\":\"not_efi\"") && contains(p, "\"apparmor\":\"enabled\"") && contains(p, "\"kernel/kptr_restrict\":2"), "posture: " + p);
    require(contains(p, "\"selinux\":\"absent\""), "absent features are absent: " + p);

    const auto users = collect_state("users", options);
    require(users.has_value() && users->items.size() == 3U, "three users");
    require(contains(users->items[0], "\"password_state\":\"set\"") && !contains(users->items[0], "salt"), "hash never emitted: " + users->items[0]);
    require(contains(users->items[1], "\"password_state\":\"locked\"") && contains(users->items[1], "\"system_account\":true") && contains(users->items[1], "\"login_shell\":false"), "service account: " + users->items[1]);
    require(contains(users->items[2], "\"uid0_non_root\":true") && contains(users->items[2], "\"password_state\":\"empty\""), "uid-0 impostor flagged: " + users->items[2]);

    const auto groups = collect_state("groups", options);
    require(groups.has_value() && groups->items.size() == 2U && contains(groups->items[1], "\"alice\""), "groups");

    const auto interfaces = collect_state("interfaces", options);
    require(interfaces.has_value() && interfaces->items.size() == 1U && contains(interfaces->items[0], "52:54:00:12:34:56") && contains(interfaces->items[0], "\"mtu\":1500"), "interfaces");
    bool addresses_not_applicable = false;
    for (const auto& entry : interfaces->unavailable) {
        if (entry.field == "interfaces.addresses" && entry.reason == unavailable_reason::not_applicable) addresses_not_applicable = true;
    }
    require(addresses_not_applicable, "live addresses are reported unavailable for a fake root");

    const auto mounts = collect_state("mounts", options);
    require(mounts.has_value() && mounts->items.size() == 2U && contains(mounts->items[1], "\"nosuid\":true") && contains(mounts->items[1], "\"noexec\":false"), "mount flags");
    const auto modules = collect_state("modules", options);
    require(modules.has_value() && modules->items.size() == 1U, "modules");

    require(!collect_state("nonsense", options).has_value(), "unknown object rejected");
}

void test_missing_files_are_reported_not_guessed() {
    host_state_options options;
    options.root = fresh_directory("empty-root");
    for (const auto object : state_objects()) {
        const auto snapshot = collect_state(object, options);
        require(snapshot.has_value(), std::string{"snapshot for "} + std::string{object});
        for (const auto& item : snapshot->items) require(looks_like_json_object(item), "valid JSON on empty root: " + item);
    }
    const auto users = collect_state("users", options);
    require(users->items.empty() && !users->unavailable.empty(), "missing passwd is reported unavailable");
    const auto host = collect_state("host", options);
    require(!host->unavailable.empty(), "missing host files are reported unavailable");
    require(contains(host->items[0], "\"machine_id_sha256\":null"), "absent machine-id is null, not invented: " + host->items[0]);
}

void test_limits_and_hostile_files() {
    host_state_options options;
    options.root = fresh_directory("limits");
    std::string passwd;
    for (int i = 0; i < 50; ++i) passwd += "u" + std::to_string(i) + ":x:" + std::to_string(1000 + i) + ":100::/home/u:/bin/sh\n";
    write_file(options.root / "etc/passwd", passwd);
    options.maximum_items = 10U;
    const auto users = collect_state("users", options);
    require(users->items.size() == 10U && users->truncated, "item cap enforced and flagged");
    bool truncated_reported = false;
    for (const auto& entry : users->unavailable) {
        if (entry.field == "users.items" && entry.reason == unavailable_reason::truncated) truncated_reported = true;
    }
    require(truncated_reported, "truncation recorded in unavailable[]");

    // A FIFO planted where a file is expected must not hang the collector.
    host_state_options fifo_options;
    fifo_options.root = fresh_directory("fifo");
    fs::create_directories(fifo_options.root / "proc/sys/kernel");
    require(::mkfifo((fifo_options.root / "proc/sys/kernel/hostname").c_str(), 0600) == 0, "mkfifo");
    const auto host = collect_state("host", fifo_options);
    require(host.has_value() && contains(host->items[0], "\"hostname\":\"\""), "FIFO ignored");

    // Oversized files are truncated at the byte bound rather than slurped.
    host_state_options big_options;
    big_options.root = fresh_directory("big");
    big_options.maximum_file_bytes = 1024U;
    write_file(big_options.root / "proc/modules", std::string(1U << 20U, 'A') + "\n");
    require(collect_state("modules", big_options)->items.empty(), "oversized garbage yields no modules");
}

void test_real_kernel_smoke() {
    host_state_options options;
    for (const auto object : state_objects()) {
        const auto snapshot = collect_state(object, options);
        require(snapshot.has_value(), "real snapshot " + std::string{object});
        for (const auto& item : snapshot->items) require(looks_like_json_object(item), "valid JSON for " + std::string{object} + ": " + item);
    }
    const auto host = collect_state("host", options);
    require(host->items.size() == 1U && contains(host->items[0], "\"boot_id\":\"") && !contains(host->items[0], "\"release\":\"\""), "real host has a kernel release: " + host->items[0]);
    require(collect_state("mounts", options)->items.size() > 1U, "real mounts");
    const auto users = collect_state("users", options);
    bool saw_root = false;
    for (const auto& item : users->items) saw_root = saw_root || contains(item, "\"name\":\"root\"");
    require(saw_root, "root account present");
}

void run(const char* name, void (*test)()) {
    try {
        test();
        std::cout << "PASS " << name << '\n';
    } catch (const std::exception& failure) {
        ++failures;
        std::cout << "FAIL " << name << ": " << failure.what() << '\n';
    }
}

}  // namespace

int main() {
    std::cout << std::unitbuf;
    run("os_release_quoting", test_os_release_quoting);
    run("passwd_and_group_hostile_lines", test_passwd_and_group_hostile_lines);
    run("mountinfo_escapes_and_optional_fields", test_mountinfo_escapes_and_optional_fields);
    run("modules_taint_and_cmdline", test_modules_taint_and_cmdline);
    run("fake_root_collection", test_fake_root_collection);
    run("missing_files_are_reported_not_guessed", test_missing_files_are_reported_not_guessed);
    run("limits_and_hostile_files", test_limits_and_hostile_files);
    run("real_kernel_smoke", test_real_kernel_smoke);
    std::error_code ignored;
    fs::remove_all(fs::temp_directory_path() / ("panopticon-state-tests-" + std::to_string(::getpid())), ignored);
    std::cout << (failures == 0 ? "ALL PASSED" : "FAILURES: " + std::to_string(failures)) << '\n';
    return failures == 0 ? 0 : 1;
}
