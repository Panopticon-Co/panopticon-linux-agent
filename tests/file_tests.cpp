#include "panopticon/linux_agent/sensor/fanotify_file.hpp"
#include "panopticon/linux_agent/sensor/sensitive_file.hpp"

#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

namespace panopticon::linux_agent::sensor {
// Lets a test hand the provider decoded events without a kernel descriptor.
struct fanotify_file_provider_test_access {
    static void attach(fanotify_file_provider& provider, record_queue& queue) {
        provider.queue_ = &queue;
        provider.tokens_ = 1000.0;
        provider.last_refill_ = std::chrono::steady_clock::now();
    }
    static void event(fanotify_file_provider& provider, const fanotify_decoded& decoded) { provider.handle_event(decoded); }
};
}  // namespace panopticon::linux_agent::sensor

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

// Builds one kernel-shaped event with a DFID_NAME record.
std::vector<unsigned char> make_event(const std::uint64_t mask, const std::int32_t pid, const std::string& name,
                                      const std::uint32_t handle_bytes = 8U) {
    std::vector<unsigned char> info;
    fanotify_event_info_header header{};
    header.info_type = FAN_EVENT_INFO_TYPE_DFID_NAME;
    const std::size_t body = sizeof(header) + 8U + 8U + handle_bytes + name.size() + 1U;
    header.len = static_cast<std::uint16_t>(body);
    info.resize(body, 0U);
    std::memcpy(info.data(), &header, sizeof(header));
    const std::int32_t fsid[2]{7, 9};
    std::memcpy(info.data() + sizeof(header), fsid, sizeof(fsid));
    std::memcpy(info.data() + sizeof(header) + 8U, &handle_bytes, sizeof(handle_bytes));
    std::memcpy(info.data() + sizeof(header) + 16U + handle_bytes, name.c_str(), name.size() + 1U);

    fanotify_event_metadata metadata{};
    metadata.event_len = static_cast<std::uint32_t>(sizeof(metadata) + info.size());
    metadata.vers = FANOTIFY_METADATA_VERSION;
    metadata.metadata_len = sizeof(metadata);
    metadata.mask = mask;
    metadata.fd = FAN_NOFD;
    metadata.pid = pid;
    std::vector<unsigned char> out(metadata.event_len);
    std::memcpy(out.data(), &metadata, sizeof(metadata));
    std::memcpy(out.data() + sizeof(metadata), info.data(), info.size());
    return out;
}

void test_decoder_reads_a_well_formed_event() {
    auto buffer = make_event(FAN_CREATE | FAN_ONDIR, 4321, "newdir");
    const auto second = make_event(FAN_CLOSE_WRITE, 99, "a.txt");
    buffer.insert(buffer.end(), second.begin(), second.end());
    const auto result = decode_fanotify_events(buffer.data(), buffer.size());
    require(!result.malformed && !result.queue_overflow && result.events.size() == 2U, "two events decoded");
    require(result.events[0].pid == 4321U && result.events[0].name == "newdir" && result.events[0].has_location, "first event fields");
    require((result.events[0].mask & FAN_ONDIR) != 0U && result.events[0].fsid[0] == 7 && result.events[0].fsid[1] == 9, "mask and fsid");
    require(result.events[0].handle.size() == 16U, "handle keeps the file_handle header and bytes");
    require(result.events[1].name == "a.txt" && result.events[1].pid == 99U, "second event fields");
}

void test_decoder_survives_every_truncation() {
    const auto buffer = make_event(FAN_MOVED_TO, 5, "renamed");
    for (std::size_t length = 1U; length < buffer.size(); ++length) {
        const auto result = decode_fanotify_events(buffer.data(), length);
        require(result.malformed && result.events.empty(), "a truncated buffer is reported malformed, never partially trusted");
    }
    require(!decode_fanotify_events(buffer.data(), 0U).malformed, "an empty read is not an error");
}

void test_decoder_rejects_hostile_records() {
    const auto buffer = make_event(FAN_CREATE, 1, "x");
    auto copy = buffer;
    const std::uint32_t huge = 0x7fffffffU;
    std::memcpy(copy.data(), &huge, sizeof(huge));
    require(decode_fanotify_events(copy.data(), copy.size()).malformed, "oversized event_len");
    copy = buffer;
    const std::uint32_t zero = 0U;
    std::memcpy(copy.data(), &zero, sizeof(zero));
    require(decode_fanotify_events(copy.data(), copy.size()).malformed, "zero event_len");
    copy = buffer;
    copy[offsetof(fanotify_event_metadata, vers)] = 1U;
    require(decode_fanotify_events(copy.data(), copy.size()).malformed, "unknown version");
    copy = make_event(FAN_CREATE, 1, "x", 8U);
    const std::uint32_t big_handle = 4000U;
    std::memcpy(copy.data() + sizeof(fanotify_event_metadata) + sizeof(fanotify_event_info_header) + 8U, &big_handle, sizeof(big_handle));
    require(decode_fanotify_events(copy.data(), copy.size()).malformed, "handle_bytes beyond the record");
    copy = make_event(FAN_CREATE, 1, "abc");
    copy.back() = 'z';
    require(decode_fanotify_events(copy.data(), copy.size()).malformed, "unterminated name");
    copy = make_event(FAN_CREATE, 1, "x");
    const std::uint16_t tiny = 2U;
    std::memcpy(copy.data() + sizeof(fanotify_event_metadata) + 2U, &tiny, sizeof(tiny));
    require(decode_fanotify_events(copy.data(), copy.size()).malformed, "info length below header size");
}

void test_decoder_flags_queue_overflow() {
    fanotify_event_metadata metadata{};
    metadata.event_len = sizeof(metadata);
    metadata.vers = FANOTIFY_METADATA_VERSION;
    metadata.metadata_len = sizeof(metadata);
    metadata.mask = FAN_Q_OVERFLOW;
    metadata.fd = FAN_NOFD;
    const auto result = decode_fanotify_events(reinterpret_cast<const unsigned char*>(&metadata), sizeof(metadata));
    require(result.queue_overflow && result.events.empty() && !result.malformed, "overflow is a loss, not an event");
}

void test_decoder_fuzz_never_crashes() {
    auto seed = 0x9e3779b97f4a7c15ULL;
    const auto next = [&seed] {
        seed ^= seed << 13U;
        seed ^= seed >> 7U;
        seed ^= seed << 17U;
        return seed;
    };
    const auto valid = make_event(FAN_CREATE | FAN_CLOSE_WRITE, 3, "fuzz-target-name");
    for (int round = 0; round < 40000; ++round) {
        auto buffer = valid;
        const auto mutations = 1U + next() % 6U;
        for (std::uint64_t index = 0U; index < mutations; ++index) buffer[next() % buffer.size()] = static_cast<unsigned char>(next());
        if (next() % 4U == 0U) buffer.resize(next() % (buffer.size() + 1U));
        const auto result = decode_fanotify_events(buffer.data(), buffer.size());
        for (const auto& event : result.events) require(event.name.size() <= 4096U && event.handle.size() <= 136U, "bounded output");
    }
}

void test_filter_prefixes_respect_directory_boundaries() {
    file_filter filter;
    filter.include = {"/etc", "/home/"};
    filter.exclude = {"/etc/ssl/private"};
    require(filter.selects("/etc") && filter.selects("/etc/passwd") && filter.selects("/home/a/.bashrc"), "included");
    require(!filter.selects("/etcetera/x") && !filter.selects("/var/log/x"), "boundary and non-included");
    require(!filter.selects("/etc/ssl/private/key") && filter.selects("/etc/ssl/certs/a"), "exclusion wins only below its prefix");
    const auto defaults = file_filter::defaults();
    require(defaults.selects("/etc/cron.d/x") && defaults.selects("/tmp/dropper") && defaults.selects("/dev/shm/x"), "default includes");
    require(!defaults.selects("/proc/1/mem") && !defaults.selects("/sys/kernel/x") && !defaults.selects("/var/lib/x"), "default excludes");
    require(file_filter{}.selects("/anything"), "an empty filter selects everything");
}

pid_t run_child_operations(const std::string& directory, const std::string& excluded) {
    const auto child = ::fork();
    require(child >= 0, "fork");
    if (child == 0) {
        const auto file = directory + "/a.txt";
        const auto moved = directory + "/b.txt";
        const auto folder = directory + "/sub";
        const int fd = ::open(file.c_str(), O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) {
            (void)!::write(fd, "payload", 7U);
            ::close(fd);
        }
        (void)::rename(file.c_str(), moved.c_str());
        (void)::chmod(moved.c_str(), 0640);
        (void)::mkdir(folder.c_str(), 0700);
        (void)::unlink(moved.c_str());
        // A burst of renames: their halves straddle read() boundaries and must still pair up.
        const int seed = ::open((directory + "/r0").c_str(), O_CREAT | O_WRONLY, 0600);
        if (seed >= 0) ::close(seed);
        for (int step = 0; step < 100; ++step) {
            (void)::rename((directory + "/r" + std::to_string(step)).c_str(), (directory + "/r" + std::to_string(step + 1)).c_str());
        }
        (void)::unlink((directory + "/r100").c_str());
        (void)::rmdir(folder.c_str());
        const int hidden = ::open((excluded + "/hidden").c_str(), O_CREAT | O_WRONLY, 0600);
        if (hidden >= 0) ::close(hidden);
        // The last event of the child. The kernel merges queued events with the same pid and name, so the rmdir of "sub"
        // is folded into the earlier mkdir event, which a reader can collect before the renames; only a name used once
        // is certain to come after everything above.
        const int last = ::open((directory + "/zz-end").c_str(), O_CREAT | O_WRONLY, 0600);
        if (last >= 0) ::close(last);
        ::_exit(0);
    }
    int status = 0;
    require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child finished");
    return child;
}

bool has(const std::vector<raw_file_event>& events, const file_operation operation, const std::string& path, const std::uint32_t pid,
         const bool directory = false) {
    return std::any_of(events.begin(), events.end(), [&](const raw_file_event& event) {
        return event.operation == operation && event.path == path && event.pid == pid && event.directory == directory;
    });
}

// Ground truth on a real kernel: the child's operations must appear with its pid, the parent's
// own writes must not, and an excluded directory must stay silent.
void test_live_file_events_match_ground_truth() {
    // A filesystem-wide fanotify mark needs CAP_SYS_ADMIN, but newer kernels let an unprivileged process pass the
    // probe (fanotify_init itself is allowed), so the probe alone would let this test fail instead of skip.
    if (::geteuid() != 0) {
        std::printf("SKIP live fanotify test: needs root for a filesystem mark\n");
        return;
    }
    {
        fanotify_file_provider probe_only;
        if (const auto reason = probe_only.probe(); !reason.empty()) {
            std::printf("SKIP live fanotify test: %s\n", reason.c_str());
            return;
        }
    }
    char pattern[] = "/tmp/panopticon-file-XXXXXX";
    require(::mkdtemp(pattern) != nullptr, "mkdtemp");
    const std::string root = pattern;
    const std::string watched = root + "/watched";
    const std::string silent = root + "/silent";
    require(::mkdir(watched.c_str(), 0700) == 0 && ::mkdir(silent.c_str(), 0700) == 0, "scratch directories");

    fanotify_options options;
    options.filter.include = {root};
    options.filter.exclude = {silent};
    fanotify_file_provider live{options};
    record_queue queue{4096U};
    require(succeeded(live.start(queue)), "provider starts as root");

    const int own = ::open((watched + "/own.txt").c_str(), O_CREAT | O_WRONLY, 0600);
    require(own >= 0, "own write");
    ::close(own);
    const auto child = static_cast<std::uint32_t>(run_child_operations(watched, silent));

    std::vector<raw_file_event> events;
    for (int attempt = 0; attempt < 40 && !has(events, file_operation::create, watched + "/zz-end", child); ++attempt) {
        std::vector<raw_record> batch;
        queue.pop_batch(batch, 256U, std::chrono::milliseconds{100});
        for (const auto& record : batch) {
            require(record.source.provider == "fanotify_file" && record.source.mechanism == "FANOTIFY", "provenance");
            if (const auto* event = std::get_if<raw_file_event>(&record.payload)) events.push_back(*event);
        }
    }
    live.stop();

    for (const auto& event : events) {
        if (event.operation != file_operation::rename || (!event.path.empty() && event.old_path.has_value())) continue;
        std::printf("  unpaired rename: path='%s' old='%s' pid=%u unavailable=%zu\n", event.path.c_str(),
                    event.old_path.value_or("<none>").c_str(), event.pid, event.unavailable.size());
    }
    require(has(events, file_operation::create, watched + "/a.txt", child), "create");
    require(has(events, file_operation::modify, watched + "/a.txt", child), "close-after-write is a modify");
    const auto rename = std::find_if(events.begin(), events.end(), [&](const raw_file_event& event) {
        return event.operation == file_operation::rename && event.path == watched + "/b.txt" && event.pid == child;
    });
    require(rename != events.end() && rename->old_path.has_value() && *rename->old_path == watched + "/a.txt", "rename paired with its source");
    require(has(events, file_operation::attrib, watched + "/b.txt", child), "chmod is an attribute change");
    require(has(events, file_operation::create, watched + "/sub", child, true), "mkdir is a directory create");
    require(has(events, file_operation::remove, watched + "/b.txt", child), "unlink");
    require(has(events, file_operation::remove, watched + "/sub", child, true), "rmdir");
    std::size_t paired = 0U;
    for (const auto& event : events) {
        if (event.operation != file_operation::rename) continue;
        require(!event.path.empty() && event.old_path.has_value() && !event.old_path->empty(), "every rename is paired, even across read boundaries");
        if (event.path.find("/r") != std::string::npos) ++paired;
    }
    require(paired == 100U, "all 100 burst renames were reported once");
    for (const auto& event : events) {
        require(event.path.find("/silent") == std::string::npos, "excluded directory stays silent");
        require(event.pid != static_cast<std::uint32_t>(::getpid()), "the daemon never reports its own writes");
    }

    (void)::unlink((silent + "/hidden").c_str());
    (void)::unlink((watched + "/own.txt").c_str());
    (void)::rmdir(watched.c_str());
    (void)::rmdir(silent.c_str());
    (void)::rmdir(root.c_str());
}

// A rename is two kernel events and the reader can be descheduled between handling them. Found on the VM: under CPU
// contention the live test saw halves of one rename reported separately, because a clock check threw away the pending
// half although its partner was already queued. Driven without a kernel so the delay is exact.
std::vector<raw_file_event> feed_rename(const std::chrono::milliseconds delay) {
    fanotify_file_provider provider;
    record_queue queue{64U};
    fanotify_file_provider_test_access::attach(provider, queue);
    fanotify_decoded from;
    from.mask = FAN_MOVED_FROM;
    from.pid = 4242U;
    from.name = "a";
    fanotify_decoded to = from;
    to.mask = FAN_MOVED_TO;
    to.name = "b";
    fanotify_file_provider_test_access::event(provider, from);
    std::this_thread::sleep_for(delay);
    fanotify_file_provider_test_access::event(provider, to);
    std::vector<raw_record> batch;
    queue.pop_batch(batch, 64U, std::chrono::milliseconds{1});
    std::vector<raw_file_event> events;
    for (const auto& record : batch) {
        if (const auto* event = std::get_if<raw_file_event>(&record.payload)) events.push_back(*event);
    }
    return events;
}

bool lacks_old_path(const raw_file_event& event) {
    return std::any_of(event.unavailable.begin(), event.unavailable.end(), [](const unavailable_field& field) { return field.field == "file.old_path"; });
}

void test_a_delayed_reader_still_pairs_the_halves_of_a_rename() {
    // Far past the 25 ms soft window, well inside the hard bound.
    const auto delayed = feed_rename(std::chrono::milliseconds{120});
    require(delayed.size() == 1U, "one rename, not two halves");
    require(delayed.front().operation == file_operation::rename && delayed.front().old_path.has_value() && !lacks_old_path(delayed.front()),
            "the rename keeps its source");
    const auto prompt = feed_rename(std::chrono::milliseconds{0});
    require(prompt.size() == 1U && prompt.front().old_path.has_value(), "an undelayed rename pairs as before");
    // A half older than the hard bound is never paired with a later move: it is reported alone, and so is the later one.
    const auto stale = feed_rename(std::chrono::milliseconds{1100});
    require(stale.size() == 2U, "a half older than the hard bound is flushed, not paired");
    require(std::count_if(stale.begin(), stale.end(), lacks_old_path) == 1, "the later move is reported as arriving from outside");
}

void test_sensitive_patterns_expand_against_a_root() {
    namespace fs = std::filesystem;
    const auto root = fs::temp_directory_path() / ("panopticon-sensitive-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "etc/ssh");
    fs::create_directories(root / "home/alice/.ssh");
    for (const auto* file : {"etc/shadow", "etc/ssh/ssh_host_ed25519_key", "etc/ssh/ssh_host_ed25519_key.pub", "home/alice/.ssh/id_rsa", "home/alice/.ssh/known_hosts"}) {
        std::ofstream{root / file} << "x";
    }
    const auto found = expand_sensitive_patterns(sensitive_file_defaults(), {"/home/alice", "/home/bob"}, root, 100U);
    const auto has = [&](const std::string& path) { return std::find(found.begin(), found.end(), path) != found.end(); };
    require(has("/etc/shadow") && has("/etc/ssh/ssh_host_ed25519_key") && has("/home/alice/.ssh/id_rsa"), "existing credential files are found");
    require(!has("/etc/ssh/ssh_host_ed25519_key.pub") && !has("/home/alice/.ssh/known_hosts"), "a wildcard does not over-match");
    require(!has("/home/bob/.ssh/id_rsa") && !has("/etc/gshadow"), "files that do not exist are not reported");
    require(expand_sensitive_patterns(sensitive_file_defaults(), {"/home/alice"}, root, 2U).size() <= 2U, "the watch count is bounded");
    require(expand_sensitive_patterns({"relative/path", "/etc/*/shadow"}, {}, root, 10U).empty(), "relative paths and directory wildcards are refused");
    fs::remove_all(root);
}

void run(const char* name, void (*test)()) {
    try {
        test();
        std::printf("ok   %s\n", name);
    } catch (const std::exception& error) {
        std::printf("FAIL %s: %s\n", name, error.what());
        std::exit(1);
    }
}

}  // namespace

int main() {
    run("decoder reads a well-formed event", test_decoder_reads_a_well_formed_event);
    run("decoder survives every truncation", test_decoder_survives_every_truncation);
    run("decoder rejects hostile records", test_decoder_rejects_hostile_records);
    run("decoder flags queue overflow", test_decoder_flags_queue_overflow);
    run("decoder fuzz never crashes", test_decoder_fuzz_never_crashes);
    run("filter prefixes respect directory boundaries", test_filter_prefixes_respect_directory_boundaries);
    run("sensitive patterns expand against a root", test_sensitive_patterns_expand_against_a_root);
    run("a delayed reader still pairs the halves of a rename", test_a_delayed_reader_still_pairs_the_halves_of_a_rename);
    run("live file events match ground truth", test_live_file_events_match_ground_truth);
    return 0;
}
