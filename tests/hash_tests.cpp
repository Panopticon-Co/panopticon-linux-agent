#include "panopticon/linux_agent/sensor/hash_service.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

struct scratch {
    fs::path path;
    scratch() {
        std::string pattern = (fs::temp_directory_path() / "panopticon-hash-XXXXXX").string();
        require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp");
        path = pattern;
    }
    ~scratch() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    fs::path put(const std::string& name, const std::string& text) const {
        const auto target = path / name;
        std::ofstream{target, std::ios::binary} << text;
        return target;
    }
};

int open_read(const fs::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    require(fd >= 0, "open");
    return fd;
}

hash_key key_of(const fs::path& path) {
    struct stat info {};
    require(::stat(path.c_str(), &info) == 0, "stat");
    return {static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino), static_cast<std::uint64_t>(info.st_size),
            static_cast<std::uint64_t>(info.st_mtim.tv_sec) * 1000000000ULL + static_cast<std::uint64_t>(info.st_mtim.tv_nsec)};
}

hash_subject subject_of(const std::string& entity, const fs::path& path) {
    hash_subject subject;
    subject.entity_id = entity;
    subject.pid = 1U;
    subject.exec_gen = 1U;
    subject.path = path.string();
    subject.key = key_of(path);
    return subject;
}

std::vector<hash_result> wait_for(hash_service& service, const std::size_t count) {
    std::vector<hash_result> all;
    for (int attempt = 0; attempt < 1000 && all.size() < count; ++attempt) {
        for (auto& result : service.drain()) all.push_back(std::move(result));
        if (all.size() < count) std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return all;
}

constexpr const char* abc_sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
constexpr const char* abc_sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
constexpr const char* abc_md5 = "900150983cd24fb0d6963f7d28e17f72";

void test_known_vectors() {
    scratch dir;
    const auto abc = dir.put("abc", "abc");
    const int fd = open_read(abc);
    const auto hash = hash_stream(fd, 0U, nullptr);
    ::close(fd);
    require(hash.status == "computed" && hash.sha256 == abc_sha256 && hash.sha1 == abc_sha1 && hash.md5 == abc_md5, "abc");
    const auto empty = dir.put("empty", "");
    const int empty_fd = open_read(empty);
    const auto none = hash_stream(empty_fd, 0U, nullptr);
    ::close(empty_fd);
    require(none.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" &&
                none.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709" && none.md5 == "d41d8cd98f00b204e9800998ecf8427e",
            "empty file");
    // A file longer than one chunk covers the streaming loop; the same content hashed in one go
    // by the shell tools is compared in the live check, here the digest sizes and determinism.
    const auto big = dir.put("big", std::string(200000U, 'a'));
    const int big_fd = open_read(big);
    const auto first = hash_stream(big_fd, 0U, nullptr);
    const auto second = hash_stream(big_fd, 0U, nullptr);
    ::close(big_fd);
    require(first.status == "computed" && first.sha256.size() == 64U && first.sha1.size() == 40U && first.md5.size() == 32U, "digest sizes");
    require(first.sha256 == second.sha256 && first.sha256 != abc_sha256, "streaming is deterministic and reads from offset zero each time");
}

void test_refusals() {
    scratch dir;
    const auto file = dir.put("f", std::string(4096U, 'x'));
    int fd = open_read(file);
    require(hash_stream(fd, 1024U, nullptr).status == "too_large", "size above the limit is not read");
    std::size_t chunks = 0U;
    require(hash_stream(fd, 0U, [&](const std::size_t) { ++chunks; return true; }).status == "computed" && chunks == 1U, "pace called per chunk");
    require(hash_stream(fd, 0U, [](const std::size_t) { return false; }).status == "unreadable", "pace can abandon the read");
    ::close(fd);
    fd = ::open(dir.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(hash_stream(fd, 0U, nullptr).status == "unreadable", "a directory is unreadable");
    ::close(fd);
    int pipes[2];
    require(::pipe(pipes) == 0, "pipe");
    require(hash_stream(pipes[0], 0U, nullptr).status == "unreadable", "a pipe is never read (no hang)");
    ::close(pipes[0]);
    ::close(pipes[1]);
    require(hash_stream(-1, 0U, nullptr).status == "unreadable", "bad descriptor");
}

void test_service_computes_caches_and_fans_out() {
    scratch dir;
    const auto abc = dir.put("abc", "abc");
    hash_service service{hash_options{}};
    auto first = service.submit(subject_of("e1", abc), open_read(abc));
    require(first.status == "pending", "a new image is pending");
    const auto done = wait_for(service, 1U);
    require(done.size() == 1U && done[0].subject.entity_id == "e1" && done[0].hash.status == "computed" && done[0].hash.sha256 == abc_sha256 &&
                done[0].hash.sha1 == abc_sha1 && done[0].hash.md5 == abc_md5,
            "result carries the subject and the digests");
    const auto cached = service.submit(subject_of("e2", abc), open_read(abc));
    require(cached.status == "computed" && cached.sha256 == abc_sha256 && service.drain().empty(), "second exec of the same image is a cache hit");
    // A changed file (new size) is hashed again.
    dir.put("abc", "abcd");
    const auto changed = service.submit(subject_of("e3", abc), open_read(abc));
    require(changed.status == "pending", "a modified image is not served from the cache");
    const auto after = wait_for(service, 1U);
    require(after.size() == 1U && after[0].hash.sha256 != abc_sha256, "new content, new digest");
    const auto metrics = service.metrics();
    require(metrics.submitted == 3U && metrics.cache_hits == 1U && metrics.computed == 2U, "metrics");
}

void test_in_flight_subjects_share_one_hash() {
    scratch dir;
    const auto file = dir.put("slow", std::string(256U * 1024U, 'q'));
    hash_options options;
    options.bytes_per_second = 128U * 1024U;  // paced: the file takes about a second
    options.maximum_waiters = 3U;
    hash_service service{options};
    require(service.submit(subject_of("a", file), open_read(file)).status == "pending", "first");
    require(service.submit(subject_of("b", file), open_read(file)).status == "pending", "second joins the running hash");
    require(service.submit(subject_of("c", file), open_read(file)).status == "pending", "third joins");
    require(service.submit(subject_of("d", file), open_read(file)).status == "skipped", "waiter limit is enforced and reported");
    require(service.pending() == 1U, "one hash for three subjects");
    const auto done = wait_for(service, 3U);
    require(done.size() == 3U, "every waiter gets a result");
    require(done[0].hash.sha256 == done[1].hash.sha256 && done[1].hash.sha256 == done[2].hash.sha256, "same digests");
}

void test_queue_limits_and_shutdown() {
    scratch dir;
    const auto slow = dir.put("slow", std::string(512U * 1024U, 'z'));
    const auto other = dir.put("other", "other");
    const auto third = dir.put("third", "third");
    hash_options options;
    options.bytes_per_second = 64U * 1024U;
    options.queue_capacity = 1U;
    {
        hash_service service{options};
        require(service.submit(subject_of("a", slow), open_read(slow)).status == "pending", "slow file starts");
        // Give the worker time to take the first request off the queue.
        std::this_thread::sleep_for(std::chrono::milliseconds{200});
        require(service.submit(subject_of("b", other), open_read(other)).status == "pending", "one request may wait");
        require(service.submit(subject_of("c", third), open_read(third)).status == "skipped", "a full queue refuses and says so");
        require(service.metrics().skipped == 1U, "refusal is counted");
    }
    // Destroying the service with the slow file still being read must not wait for it.
    const auto started = std::chrono::steady_clock::now();
    {
        hash_service temporary{options};
        (void)temporary.submit(subject_of("t", slow), open_read(slow));
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    require(std::chrono::steady_clock::now() - started < std::chrono::seconds{3}, "shutdown abandons pending work promptly");
}

void test_too_large_and_unreadable_through_the_service() {
    scratch dir;
    const auto file = dir.put("f", std::string(8192U, 'k'));
    hash_options options;
    options.maximum_file_bytes = 4096U;
    hash_service service{options};
    require(service.submit(subject_of("big", file), open_read(file)).status == "pending", "queued");
    const auto done = wait_for(service, 1U);
    require(done.size() == 1U && done[0].hash.status == "too_large" && done[0].hash.sha256.empty(), "too large reported without digests");
    hash_subject vanished;
    vanished.entity_id = "gone";
    vanished.key = {9U, 9U, 9U, 9U};
    require(service.submit(vanished, -1).status == "unreadable", "a process that vanished before its image could be opened");
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"known_vectors", test_known_vectors},
        {"refusals", test_refusals},
        {"service_computes_caches_and_fans_out", test_service_computes_caches_and_fans_out},
        {"in_flight_subjects_share_one_hash", test_in_flight_subjects_share_one_hash},
        {"queue_limits_and_shutdown", test_queue_limits_and_shutdown},
        {"too_large_and_unreadable_through_the_service", test_too_large_and_unreadable_through_the_service},
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
