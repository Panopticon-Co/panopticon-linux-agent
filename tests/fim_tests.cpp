#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"
#include "panopticon/linux_agent/sensor/persistence.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

struct fake_root {
    fs::path path;
    fake_root() {
        std::string pattern = (fs::temp_directory_path() / "panopticon-fim-XXXXXX").string();
        require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp");
        path = pattern;
    }
    ~fake_root() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    void put(const std::string& host_path, const std::string& text) const {
        const auto target = path / host_path.substr(1U);
        fs::create_directories(target.parent_path());
        std::ofstream{target, std::ios::binary} << text;
    }
};

const persistence_item* find(const persistence_scan& scan, const std::string& path) {
    for (const auto& item : scan.items) {
        if (item.path == path) return &item;
    }
    return nullptr;
}

void test_categories_and_extractors() {
    fake_root root;
    root.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n");
    root.put("/etc/systemd/system/evil.service", "[Service]\nExecStart=-/tmp/.x/payload --quiet\n");
    root.put("/etc/crontab", "# comment\n\n* * * * * root /tmp/x\n");
    root.put("/etc/ld.so.preload", "/lib/evil.so\n");
    root.put("/etc/sudoers.d/ops", "# x\nalice ALL=(ALL) NOPASSWD: ALL\nbob ALL=(ALL) ALL\n");
    root.put("/etc/ssh/sshd_config", "PermitRootLogin yes\n");
    root.put("/home/alice/.bashrc", "alias ls=ls\n");
    const std::string blob = "AAAAC3NzaC1lZDI1NTE5AAAAIsecretsecretsecret";
    root.put("/home/alice/.ssh/authorized_keys",
             "# keys\nssh-ed25519 " + blob + " alice@laptop\ncommand=\"/bin/true\",no-pty ssh-rsa AAAAB3NzaC1yc2E other\n");
    fs::create_directories(root.path / "root");

    persistence_options options;
    options.root = root.path;
    persistence_catalog catalog{options};
    const auto scan = catalog.scan();

    const auto* unit = find(scan, "/etc/systemd/system/evil.service");
    require(unit != nullptr && unit->category == "systemd_unit", "systemd unit found");
    require(unit->exec == "/tmp/.x/payload", "ExecStart prefix characters are stripped");
    require(unit->hash_status == "computed" && unit->sha256.size() == 64U, "unit hashed");

    const auto* cron = find(scan, "/etc/crontab");
    require(cron != nullptr && cron->entries && *cron->entries == 1U, "cron counts active lines only");
    const auto* preload = find(scan, "/etc/ld.so.preload");
    require(preload != nullptr && preload->category == "ld_preload" && preload->entries && *preload->entries == 1U, "ld.so.preload");
    const auto* sudo = find(scan, "/etc/sudoers.d/ops");
    require(sudo != nullptr && sudo->nopasswd && *sudo->nopasswd == 1U, "NOPASSWD counted");
    require(find(scan, "/etc/ssh/sshd_config") != nullptr, "sshd_config");
    require(find(scan, "/home/alice/.bashrc") != nullptr, "per-user shell profile");

    const auto* keys = find(scan, "/home/alice/.ssh/authorized_keys");
    require(keys != nullptr && keys->key_count && *keys->key_count == 2U, "two keys");
    require(keys->forced_commands && *keys->forced_commands == 1U, "one forced command");
    require(keys->key_digests.size() == 2U && keys->key_digests[0].size() == 16U, "key digests");
    const auto json = persistence_item_json(*keys);
    require(json.find(blob) == std::string::npos && json.find("alice@laptop") == std::string::npos, "no key material or comment is emitted");

    require(catalog.classify("/home/alice/.ssh/authorized_keys") == "ssh", "classify per-user path");
    require(catalog.classify("/etc/cron.d/job") == "cron", "classify system path");
    require(catalog.classify("/etc/cron.d/a/b") != "cron", "depth is respected");
    require(catalog.classify("/etc/cron.d/../shadow2").empty(), "traversal is not classified");
    require(catalog.classify("/home/alice/notes.txt").empty(), "ordinary file is not a persistence location");
    require(catalog.classify("/nonexistent/.bashrc").empty(), "nologin home excluded");
    const auto described = catalog.describe("/etc/crontab");
    require(described && described->sha256 == cron->sha256, "describe matches scan");
    require(!catalog.describe("/etc/cron.d/missing"), "missing path is not an error");
}

void test_hostile_objects() {
    fake_root root;
    root.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    fs::create_directories(root.path / "etc/cron.d");
    require(::mkfifo((root.path / "etc/cron.d/fifo").c_str(), 0600) == 0, "mkfifo");  // a read would block forever
    fs::create_symlink("/etc/shadow", root.path / "etc/cron.d/link");
    root.put("/etc/cron.d/big", std::string(2048U, 'a'));
    fs::create_directories(root.path / "etc/profile.d");
    for (int index = 0; index < 50; ++index) root.put("/etc/profile.d/f" + std::to_string(index) + ".sh", "x\n");

    persistence_options options;
    options.root = root.path;
    options.maximum_file_bytes = 1024U;
    options.maximum_directory_entries = 40U;
    options.maximum_items = 30U;
    persistence_catalog catalog{options};
    const auto scan = catalog.scan();  // returning at all proves the FIFO did not block

    const auto* link = find(scan, "/etc/cron.d/link");
    require(link != nullptr && link->kind == "symlink" && link->target == "/etc/shadow" && link->sha256.empty(), "symlink recorded, not followed");
    const auto* big = find(scan, "/etc/cron.d/big");
    require(big != nullptr && big->hash_status == "too_large" && big->sha256.empty(), "oversized file listed but not hashed");
    const auto* fifo = find(scan, "/etc/cron.d/fifo");
    require(fifo != nullptr && fifo->kind == "other" && fifo->sha256.empty(), "FIFO listed, never read");
    require(scan.items.size() <= 30U && scan.truncated, "item cap flagged");
}

void test_extractors_survive_garbage() {
    std::string garbage;
    for (int index = 0; index < 4096; ++index) garbage.push_back(static_cast<char>(index * 31 + 7));
    (void)systemd_exec_program(garbage);
    (void)count_active_lines(garbage);
    (void)count_nopasswd(garbage);
    (void)parse_authorized_keys(garbage, 8U);
    const auto limited = parse_authorized_keys("ssh-rsa AAAA a\nssh-rsa BBBB b\nssh-rsa CCCC c\n", 2U);
    require(limited.key_count == 3U && limited.digests.size() == 2U, "digest list bounded, count exact");
    require(systemd_exec_program("ExecStart=\n[Service]\nExecStart=/bin/true x\n") == "/bin/true", "first non-empty ExecStart");
}

void test_state_object() {
    fake_root root;
    root.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    root.put("/etc/crontab", "* * * * * root x\n");
    host_state_options options;
    options.root = root.path;
    const auto snapshot = collect_state("persistence", options);
    require(snapshot && snapshot->object == "persistence" && snapshot->mechanism == "FSSCAN", "state object");
    require(!snapshot->items.empty() && snapshot->items.front().front() == '{', "items are JSON objects");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"categories_and_extractors", test_categories_and_extractors},
        {"hostile_objects", test_hostile_objects},
        {"extractors_survive_garbage", test_extractors_survive_garbage},
        {"state_object", test_state_object},
    };
    int failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::printf("PASS %s\n", test.name);
        } catch (const std::exception& error) {
            std::printf("FAIL %s: %s\n", test.name, error.what());
            ++failures;
        }
    }
    std::printf(failures == 0 ? "ALL PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
