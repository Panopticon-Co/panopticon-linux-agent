#include "panopticon/linux_agent/sensor/kernel_change.hpp"

#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

module_entry module(const std::string& name, const std::uint64_t size) {
    module_entry entry;
    entry.name = name;
    entry.size = size;
    entry.state = "Live";
    return entry;
}

mount_entry mount(const std::uint32_t id, const std::string& target, const std::string& type, const std::vector<std::string>& options = {"rw"}) {
    mount_entry entry;
    entry.mount_id = id;
    entry.parent_id = 1U;
    entry.device = "8:1";
    entry.root = "/";
    entry.mount_point = target;
    entry.fs_type = type;
    entry.source = "/dev/sda1";
    entry.options = options;
    return entry;
}

void test_modules_seed_then_report_changes() {
    kernel_change_tracker tracker;
    require(tracker.update_modules({module("a", 10U), module("b", 20U)}).empty(), "the first snapshot is the starting state");
    require(tracker.update_modules({module("a", 10U), module("b", 20U)}).empty(), "no change, no event");
    auto events = tracker.update_modules({module("a", 10U), module("b", 20U), module("rootkit", 4096U)});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::module_load && events[0].module_name == "rootkit" &&
                events[0].module_size == 4096U && events[0].module_state == "Live",
            "a new module is a load");
    events = tracker.update_modules({module("a", 10U), module("rootkit", 4096U)});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::module_unload && events[0].module_name == "b", "a missing module is an unload");
    events = tracker.update_modules({module("a", 99U), module("rootkit", 4096U)});
    require(events.size() == 2U && events[0].kind == kernel_event_kind::module_unload && events[0].module_size == 10U &&
                events[1].kind == kernel_event_kind::module_load && events[1].module_size == 99U,
            "a module that changed size was reloaded: unload first, then load");
    require(tracker.update_modules({}).size() == 2U, "everything unloaded");
}

void test_mounts_seed_then_report_changes() {
    kernel_change_tracker tracker;
    require(tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc")}).empty(), "starting state");
    auto events = tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc"), mount(3U, "/mnt/usb", "vfat", {"rw", "nosuid"})});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::mount_added && events[0].target == "/mnt/usb" && events[0].fs_type == "vfat" &&
                events[0].options == std::vector<std::string>{"rw", "nosuid"} && events[0].source == "/dev/sda1" && events[0].mount_id == 3U,
            "a new mount");
    events = tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc"), mount(3U, "/mnt/usb", "vfat", {"ro", "nosuid"})});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::mount_remounted && events[0].options.front() == "ro", "same mount, new options");
    events = tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc")});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::mount_removed && events[0].target == "/mnt/usb", "a mount that went away");
    // The same path mounted again gets a new id, so it is a removal and an addition, not a no-op.
    events = tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc"), mount(9U, "/mnt/usb", "vfat")});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::mount_added && events[0].mount_id == 9U, "a re-mount under a new id");
    auto covered = mount(4U, "/etc", "ext4");  // a bind mount over an existing path
    events = tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc"), mount(9U, "/mnt/usb", "vfat"), covered});
    require(events.size() == 1U && events[0].target == "/etc", "a mount over an existing directory is reported");
    auto super = mount(4U, "/etc", "ext4");
    super.super_options = {"rw", "errors=remount-ro"};
    events = tracker.update_mounts({mount(1U, "/", "ext4"), mount(2U, "/proc", "proc"), mount(9U, "/mnt/usb", "vfat"), super});
    require(events.size() == 1U && events[0].kind == kernel_event_kind::mount_remounted, "a change in super-block options counts as a remount");
}

struct fake_proc {
    fs::path root;
    fake_proc() {
        std::string pattern = (fs::temp_directory_path() / "panopticon-kernel-XXXXXX").string();
        require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp");
        root = pattern;
        fs::create_directories(root / "self");
    }
    ~fake_proc() {
        std::error_code error;
        fs::remove_all(root, error);
    }
    void write(const std::string& relative, const std::string& text) const {
        std::ofstream out{root / relative, std::ios::binary | std::ios::trunc};
        out << text;
    }
};

const std::string modules_one = "nf_tables 245760 100 - Live 0x0000000000000000\nlp 20480 0 - Live 0x0000000000000000\n";
const std::string modules_two = modules_one + "evil_mod 16384 0 - Live 0x0000000000000000\n";
const std::string mounts_one = "36 35 98:0 / / rw,relatime - ext4 /dev/root rw\n";
const std::string mounts_two = mounts_one + "40 36 8:1 / /mnt/usb rw,nosuid - vfat /dev/sdb1 rw\n";

std::vector<raw_kernel_event> drain(record_queue& queue) {
    std::vector<raw_record> batch;
    queue.pop_batch(batch, 1000U, std::chrono::milliseconds{0});
    std::vector<raw_kernel_event> out;
    for (const auto& record : batch) {
        const auto* event = std::get_if<raw_kernel_event>(&record.payload);
        require(event != nullptr, "only kernel events");
        require(record.source.provider == "kernel_change" && record.source.mechanism == "PROCFS" && record.source.level == confidence::reconstructed,
                "provenance");
        out.push_back(*event);
    }
    return out;
}

void test_provider_reads_proc_files() {
    fake_proc proc;
    proc.write("modules", modules_one);
    proc.write("self/mountinfo", mounts_one);
    kernel_change_options options;
    options.proc_root = proc.root;
    options.interval = std::chrono::milliseconds{3600000};
    kernel_change_provider provider{options};
    require(provider.probe().empty(), "readable");
    record_queue queue{256U};
    require(std::holds_alternative<bool>(provider.start(queue)), "start");
    require(drain(queue).empty(), "starting state is not reported");
    proc.write("modules", modules_two);
    proc.write("self/mountinfo", mounts_two);
    provider.poll_once();
    const auto events = drain(queue);
    require(events.size() == 2U, "one module and one mount");
    require(events[0].kind == kernel_event_kind::module_load && events[0].module_name == "evil_mod" && events[0].module_size == 16384U, "module load");
    require(events[1].kind == kernel_event_kind::mount_added && events[1].target == "/mnt/usb" && events[1].fs_type == "vfat" && events[1].source == "/dev/sdb1",
            "mount");
    provider.stop();
    require(provider.health().state == "stopped", "health after stop");
}

void test_provider_survives_hostile_and_missing_files() {
    fake_proc proc;
    kernel_change_options options;
    options.proc_root = proc.root;
    options.interval = std::chrono::milliseconds{3600000};
    kernel_change_provider none{options};
    require(!none.probe().empty(), "no files, no provider");
    record_queue queue{64U};
    require(!std::holds_alternative<bool>(none.start(queue)), "start fails with a reason");

    proc.write("self/mountinfo", mounts_one);  // no /proc/modules: a kernel without module support
    kernel_change_provider mounts_only{options};
    require(mounts_only.probe().empty(), "one file is enough");
    require(std::holds_alternative<bool>(mounts_only.start(queue)), "start");
    // Mount paths are chosen by whoever mounts: escapes decode, control bytes and long paths stay data.
    proc.write("self/mountinfo", mounts_one + "41 36 8:2 / /mnt/with\\040space\\012newline rw - tmpfs tmpfs rw\n" + "42 36 8:3 / /" + std::string(3000U, 'x') +
                                     " rw - tmpfs tmpfs rw\ngarbage line\n\n");
    mounts_only.poll_once();
    const auto events = drain(queue);
    require(events.size() >= 1U, "new mounts are reported");
    bool found = false;
    for (const auto& event : events) found = found || (event.kind == kernel_event_kind::mount_added && event.target == "/mnt/with space\nnewline");
    require(found, "escapes are decoded");
    mounts_only.stop();
}

void test_provider_limits_events_and_snapshots() {
    fake_proc proc;
    proc.write("modules", "");
    proc.write("self/mountinfo", mounts_one);
    kernel_change_options options;
    options.proc_root = proc.root;
    options.interval = std::chrono::milliseconds{3600000};
    options.maximum_events_per_poll = 3U;
    options.maximum_entries = 50U;
    kernel_change_provider provider{options};
    record_queue queue{256U};
    require(std::holds_alternative<bool>(provider.start(queue)), "start");
    std::string flood;
    for (int index = 0; index < 10; ++index) flood += "m" + std::to_string(index) + " 4096 0 - Live 0x0\n";
    proc.write("modules", flood);
    provider.poll_once();
    require(drain(queue).size() == 3U && provider.take_governed() == 7U && provider.take_governed() == 0U, "events over the budget are counted exactly");

    std::string huge;
    for (int index = 0; index < 60; ++index) huge += "h" + std::to_string(index) + " 4096 0 - Live 0x0\n";
    proc.write("modules", huge);
    provider.poll_once();
    require(drain(queue).empty() && provider.health().state == "degraded", "a snapshot at the limit is not trusted and not diffed");
    provider.stop();
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"modules_seed_then_report_changes", test_modules_seed_then_report_changes},
        {"mounts_seed_then_report_changes", test_mounts_seed_then_report_changes},
        {"provider_reads_proc_files", test_provider_reads_proc_files},
        {"provider_survives_hostile_and_missing_files", test_provider_survives_hostile_and_missing_files},
        {"provider_limits_events_and_snapshots", test_provider_limits_events_and_snapshots},
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
