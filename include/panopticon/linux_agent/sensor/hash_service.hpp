#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Content hashing of executed images (slice S5.3, matrix R1). Hashing a large binary takes
// longer than the process takes to start, so it never runs on the pipeline thread: the pipeline
// hands over an already-open descriptor (opened from /proc/<pid>/exe at exec time, so it names the
// image that was executed even if the file is replaced or deleted afterwards), gets an immediate
// answer on a cache hit, and receives the rest later through drain().
//
// Bounds: files above `maximum_file_bytes` are not read; reading is paced to `bytes_per_second`;
// the request queue is bounded and refusals are counted, never silent; the worker runs at low CPU
// priority.

struct file_hash {
    // computed, pending, too_large, unreadable, skipped (request queue full)
    std::string status{"pending"};
    std::string sha256;
    std::string sha1;
    std::string md5;
};

// Identity of one file content as far as the filesystem tells: used as the cache key, so an
// in-place change (new size or mtime) or a replaced file (new inode) is hashed again.
struct hash_key {
    std::uint64_t dev{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint64_t mtime_ns{};
    friend bool operator<(const hash_key& left, const hash_key& right) {
        return std::tie(left.dev, left.inode, left.size, left.mtime_ns) < std::tie(right.dev, right.inode, right.size, right.mtime_ns);
    }
};

struct hash_subject {
    std::string entity_id;
    std::uint32_t pid{};
    std::uint32_t exec_gen{};
    std::string path;
    hash_key key;
};

struct hash_result {
    hash_subject subject;
    file_hash hash;
};

struct hash_options {
    std::uint64_t maximum_file_bytes{256ULL * 1024U * 1024U};
    std::uint64_t bytes_per_second{64ULL * 1024U * 1024U};
    std::size_t queue_capacity{1024U};
    std::size_t cache_entries{8192U};
    std::size_t maximum_waiters{64U};  // subjects served by one in-flight hash
};

struct hash_metrics {
    std::uint64_t submitted{};
    std::uint64_t cache_hits{};
    std::uint64_t computed{};
    std::uint64_t too_large{};
    std::uint64_t unreadable{};
    std::uint64_t skipped{};  // queue full or waiter limit reached
    std::uint64_t bytes_hashed{};
};

// Streams `fd` from offset 0 through SHA-256, SHA-1 and MD5. `limit_bytes` caps what is read;
// `pace` (may be empty) is called after every chunk with the chunk size, may block, and returns
// false to abandon the read (status unreadable). Never
// reads more than the cap even if the file grows; a file that is not a regular file is
// unreadable. Does not close `fd`.
[[nodiscard]] file_hash hash_stream(int fd, std::uint64_t limit_bytes, const std::function<bool(std::size_t)>& pace);

class hash_service {
public:
    explicit hash_service(hash_options options);
    ~hash_service();
    hash_service(const hash_service&) = delete;
    hash_service& operator=(const hash_service&) = delete;

    // Takes ownership of `fd` (it is closed on every path). Returns the final hash on a cache
    // hit or an immediate refusal; otherwise status "pending" and the result arrives via drain().
    [[nodiscard]] file_hash submit(hash_subject subject, int fd);
    // Finished hashes since the last call, one per submitted subject that returned pending.
    [[nodiscard]] std::vector<hash_result> drain();

    [[nodiscard]] std::size_t pending() const;
    [[nodiscard]] hash_metrics metrics() const;

private:
    struct request {
        hash_subject subject;
        int fd{-1};
    };
    struct in_flight {
        std::vector<hash_subject> waiters;
    };

    void run();
    void remember(const hash_key& key, const file_hash& hash);

    hash_options options_;
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<request> queue_;
    std::map<hash_key, in_flight> in_flight_;
    std::map<hash_key, file_hash> cache_;
    std::deque<hash_key> cache_order_;
    std::vector<hash_result> finished_;
    hash_metrics metrics_;
    bool stopping_{false};
    std::thread worker_;
};

}  // namespace panopticon::linux_agent::sensor
