#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/sensor/fim.hpp"
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

fim_options fim_for(const fake_root& root, const fs::path& baseline) {
    fim_options options;
    options.persistence.root = root.path;
    options.baseline_path = baseline;
    options.debounce_ns = 0U;
    return options;
}

void test_diff_semantics() {
    persistence_item a;
    a.category = "cron";
    a.path = "/etc/crontab";
    a.kind = "file";
    a.mode = 0644U;
    a.hash_status = "computed";
    a.sha256 = std::string(64U, 'a');
    auto b = a;
    b.mtime_ns = 99U;  // a bare touch is not a change
    require(!fim_compare(a.path, a, b), "mtime alone is not a change for a hashed file");
    b.sha256 = std::string(64U, 'b');
    auto change = fim_compare(a.path, a, b);
    require(change && change->change == "modified" && change->fields == std::vector<std::string>{"content"}, "content change");
    b = a;
    b.mode = 04755U;
    change = fim_compare(a.path, a, b);
    require(change && change->fields == std::vector<std::string>{"mode"}, "mode-only change");
    b = a;
    b.uid = 1000U;
    require(fim_compare(a.path, a, b)->fields == std::vector<std::string>{"uid"}, "owner change");
    auto big = a;
    big.hash_status = "too_large";
    big.sha256.clear();
    auto big2 = big;
    big2.mtime_ns = 5U;
    require(fim_compare(a.path, big, big2) && fim_compare(a.path, big, big2)->fields == std::vector<std::string>{"content"}, "too-large file compared by mtime");
    require(fim_compare(a.path, std::nullopt, a)->change == "added" && fim_compare(a.path, a, std::nullopt)->change == "removed", "add and remove");
    require(!fim_compare(a.path, std::nullopt, std::nullopt), "nothing to nothing");
    fim_baseline one{{a.path, a}};
    fim_baseline two{{a.path, b}, {"/etc/z", a}};
    require(fim_diff(one, two).size() == 2U && fim_diff(one, one).empty(), "baseline diff");
}

void test_baseline_text_round_trip_and_rejection() {
    persistence_item item;
    item.category = "ssh";
    item.path = "/home/a b/.ssh/authorized_keys";  // a space in the path must survive
    item.kind = "symlink";
    item.target = "../x y";
    item.hash_status = "not_applicable";
    item.uid = 1000U;
    item.mode = 0777U;
    persistence_item file;
    file.category = "cron";
    file.path = "/etc/crontab";
    file.kind = "file";
    file.hash_status = "computed";
    file.sha256 = std::string(64U, 'c');
    const fim_baseline baseline{{item.path, item}, {file.path, file}};
    const auto text = fim_serialise(baseline);
    const auto parsed = fim_parse(text, 100U);
    require(parsed && parsed->size() == 2U, "round trip");
    require(parsed->at(item.path).target == item.target && parsed->at(file.path).sha256 == file.sha256, "fields survive");
    require(fim_diff(baseline, *parsed).empty(), "round trip is lossless for compared fields");
    for (std::size_t cut = 0U; cut < text.size(); ++cut) {
        require(!fim_parse(std::string_view{text}.substr(0U, cut), 100U), "every truncation is rejected");
    }
    require(!fim_parse(text, 1U), "item limit");
    auto bad = text;
    bad.replace(bad.find(" computed "), 10U, " bogus ");
    require(!fim_parse(bad, 100U), "unknown hash status");
    require(!fim_parse("PANOPTICON-FIM 2 0\n", 100U) && !fim_parse("", 100U), "other version and empty");
    std::string noise;
    for (int index = 0; index < 2000; ++index) noise.push_back(static_cast<char>(index * 17 + 3));
    require(!fim_parse(noise, 100U), "noise");
}

void test_monitor_lifecycle() {
    fake_root root;
    fake_root state;
    root.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    root.put("/etc/crontab", "* * * * * root a\n");
    root.put("/etc/cron.d/job", "x\n");
    const auto baseline_path = state.path / "var/fim.baseline";

    std::size_t items = 0U;
    {
        fim_monitor monitor{fim_for(root, baseline_path)};
        const auto begun = monitor.start();
        require(begun.state == "created" && begun.changes.empty() && begun.items >= 3U, "first start creates a baseline");
        items = begun.items;
        struct stat info {};
        require(::stat(baseline_path.c_str(), &info) == 0 && (info.st_mode & 0777U) == 0600U, "baseline stored with mode 0600");
        require(monitor.rescan().empty(), "no change, no records");
    }
    // Changes made while the sensor is not running.
    root.put("/etc/crontab", "* * * * * root b\n");
    fs::remove(root.path / "etc/cron.d/job");
    root.put("/etc/cron.d/new", "y\n");
    {
        fim_monitor monitor{fim_for(root, baseline_path)};
        const auto begun = monitor.start();
        require(begun.state == "loaded" && begun.items == items, "second start loads the baseline");
        bool modified = false;
        bool removed = false;
        bool added = false;
        for (const auto& change : begun.changes) {
            if (change.path == "/etc/crontab" && change.change == "modified") modified = true;
            if (change.path == "/etc/cron.d/job" && change.change == "removed") removed = true;
            if (change.path == "/etc/cron.d/new" && change.change == "added") added = true;
            require(change.actor_pid == 0U, "an offline change has no actor");
        }
        require(modified && removed && added && begun.changes.size() == 3U, "offline changes are reported");
    }
    {
        fim_monitor monitor{fim_for(root, baseline_path)};
        require(monitor.start().changes.empty(), "the adopted state is stored");
    }
    // A damaged baseline is replaced visibly, never trusted.
    std::ofstream{baseline_path, std::ios::binary | std::ios::trunc} << "PANOPTICON-FIM 1 5\nzz\n";
    {
        fim_monitor monitor{fim_for(root, baseline_path)};
        const auto begun = monitor.start();
        require(begun.state == "reset" && begun.reset_reason == "corrupt" && begun.changes.empty(), "corrupt baseline resets");
        require(monitor.storage_healthy(), "reset baseline stored");
    }
    // A symlink planted at the baseline path is not followed.
    fs::remove(baseline_path);
    fs::create_symlink("/etc/hostname", baseline_path);
    {
        fim_monitor monitor{fim_for(root, baseline_path)};
        const auto begun = monitor.start();
        require(begun.state == "reset", "a symlinked baseline is rejected");
    }
}

void test_dirty_paths_and_actor() {
    fake_root root;
    root.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    root.put("/etc/cron.d/job", "x\n");
    fim_options options;
    options.persistence.root = root.path;
    options.debounce_ns = 1000U;
    fim_monitor monitor{options};
    (void)monitor.start();
    require(!monitor.note("/var/log/syslog", std::nullopt, 7U, 1U, 0U) && monitor.pending() == 0U, "other paths are ignored");
    root.put("/etc/cron.d/job", "changed\n");
    require(monitor.note("/etc/cron.d/job", std::nullopt, 4242U, 777U, 100U), "persistence path queued");
    require(monitor.note("/etc/cron.d/job", std::nullopt, 4243U, 778U, 200U) && monitor.pending() == 1U, "same path coalesces");
    require(monitor.take_due(500U).empty(), "debounce holds the change back");
    const auto changes = monitor.take_due(2000U);
    require(changes.size() == 1U && changes[0].change == "modified" && changes[0].actor_pid == 4243U && changes[0].actor_time_unix_ns == 778U,
            "change attributed to the latest actor");
    require(monitor.pending() == 0U && monitor.take_due(9999U).empty(), "queue drained");
    // The same content written again is not a change.
    root.put("/etc/cron.d/job", "changed\n");
    (void)monitor.note("/etc/cron.d/job", std::nullopt, 1U, 1U, 0U);
    require(monitor.take_due(5000U).empty(), "identical rewrite is silent");
    // A directory that disappears takes its children along.
    root.put("/etc/systemd/system/sub/inner.service", "[Service]\nExecStart=/bin/x\n");
    root.put("/etc/systemd/system/sub/deeper/other.service", "[Service]\nExecStart=/bin/y\n");
    require(monitor.rescan().size() == 2U, "nested items found");
    fs::remove_all(root.path / "etc/systemd/system/sub");
    (void)monitor.note("/etc/systemd/system/sub", std::nullopt, 9U, 1U, 0U);  // only the directory is named
    const auto gone = monitor.take_due(9000U);
    require(gone.size() == 2U && gone[0].change == "removed" && gone[1].change == "removed", "children of a removed directory are removed");
    require(gone[0].actor_pid == 9U, "removal attributed to the directory's actor");
    // A rename names both paths.
    root.put("/etc/cron.d/a", "1\n");
    (void)monitor.rescan();
    fs::rename(root.path / "etc/cron.d/a", root.path / "etc/cron.d/b");
    require(monitor.note("/etc/cron.d/b", std::string{"/etc/cron.d/a"}, 3U, 1U, 0U) && monitor.pending() == 2U, "rename queues both halves");
    require(monitor.take_due(9000U).size() == 2U, "rename is a removal and an addition");
}

void test_scan_gaps_do_not_report_removals() {
    fake_root root;
    fake_root state;
    root.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    for (int index = 0; index < 20; ++index) root.put("/etc/cron.d/j" + std::to_string(index), "x\n");
    const auto baseline_path = state.path / "fim.baseline";
    {
        fim_monitor monitor{fim_for(root, baseline_path)};
        require(monitor.start().state == "created", "full baseline");
    }
    // The next run can only see part of the directory: that is a gap in the scan, not 15 removals.
    auto limited = fim_for(root, baseline_path);
    limited.persistence.maximum_directory_entries = 5U;
    fim_monitor squeezed{limited};
    const auto begun = squeezed.start();
    require(begun.state == "loaded" && begun.changes.empty(), "a truncated scan reports no removals");
    require(squeezed.item_count() >= 20U, "unobserved items stay in the baseline");
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
        {"diff_semantics", test_diff_semantics},
        {"baseline_text_round_trip_and_rejection", test_baseline_text_round_trip_and_rejection},
        {"monitor_lifecycle", test_monitor_lifecycle},
        {"dirty_paths_and_actor", test_dirty_paths_and_actor},
        {"scan_gaps_do_not_report_removals", test_scan_gaps_do_not_report_removals},
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
