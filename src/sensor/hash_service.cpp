#include "panopticon/linux_agent/sensor/hash_service.hpp"

#include <openssl/evp.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <memory>
#include <utility>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::size_t chunk_bytes = 64U * 1024U;

std::string to_hex(const unsigned char* bytes, const unsigned int length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2U);
    for (unsigned int index = 0U; index < length; ++index) {
        out.push_back(digits[bytes[index] >> 4U]);
        out.push_back(digits[bytes[index] & 15U]);
    }
    return out;
}

struct digest_context {
    EVP_MD_CTX* context{EVP_MD_CTX_new()};
    ~digest_context() { EVP_MD_CTX_free(context); }
    digest_context() = default;
    digest_context(const digest_context&) = delete;
    digest_context& operator=(const digest_context&) = delete;

    bool start(const EVP_MD* method) { return context != nullptr && method != nullptr && EVP_DigestInit_ex(context, method, nullptr) == 1; }
    bool update(const unsigned char* data, const std::size_t length) { return EVP_DigestUpdate(context, data, length) == 1; }
    bool finish(std::string& hex) {
        std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
        unsigned int length = 0U;
        if (EVP_DigestFinal_ex(context, bytes.data(), &length) != 1) return false;
        hex = to_hex(bytes.data(), length);
        return true;
    }
};

file_hash unreadable() {
    file_hash out;
    out.status = "unreadable";
    return out;
}

}  // namespace

file_hash hash_stream(const int fd, const std::uint64_t limit_bytes, const std::function<bool(std::size_t)>& pace) {
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) return unreadable();
    if (limit_bytes != 0U && static_cast<std::uint64_t>(info.st_size) > limit_bytes) {
        file_hash out;
        out.status = "too_large";
        return out;
    }
    digest_context sha256;
    digest_context sha1;
    digest_context md5;
    if (!sha256.start(EVP_sha256()) || !sha1.start(EVP_sha1()) || !md5.start(EVP_md5())) return unreadable();
    std::array<unsigned char, chunk_bytes> buffer{};
    std::uint64_t offset = 0U;
    for (;;) {
        const auto count = ::pread(fd, buffer.data(), buffer.size(), static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return unreadable();
        if (count == 0) break;
        offset += static_cast<std::uint64_t>(count);
        if (limit_bytes != 0U && offset > limit_bytes) {  // grew while being read
            file_hash out;
            out.status = "too_large";
            return out;
        }
        if (!sha256.update(buffer.data(), static_cast<std::size_t>(count)) || !sha1.update(buffer.data(), static_cast<std::size_t>(count)) ||
            !md5.update(buffer.data(), static_cast<std::size_t>(count))) {
            return unreadable();
        }
        if (pace && !pace(static_cast<std::size_t>(count))) return unreadable();
    }
    file_hash out;
    if (!sha256.finish(out.sha256) || !sha1.finish(out.sha1) || !md5.finish(out.md5)) return unreadable();
    out.status = "computed";
    return out;
}

hash_service::hash_service(hash_options options) : options_{std::move(options)} {
    worker_ = std::thread{[this] { run(); }};
}

hash_service::~hash_service() {
    {
        const std::lock_guard lock{mutex_};
        stopping_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
    for (auto& waiting : queue_) {
        if (waiting.fd >= 0) ::close(waiting.fd);
    }
}

file_hash hash_service::submit(hash_subject subject, const int fd) {
    const auto refuse = [&](const char* status) {
        if (fd >= 0) ::close(fd);
        ++metrics_.skipped;
        file_hash out;
        out.status = status;
        return out;
    };
    const std::lock_guard lock{mutex_};
    ++metrics_.submitted;
    if (stopping_) return refuse("skipped");
    const auto key = subject.key;
    if (const auto cached = cache_.find(key); cached != cache_.end()) {
        ++metrics_.cache_hits;
        if (fd >= 0) ::close(fd);
        return cached->second;
    }
    if (const auto running = in_flight_.find(key); running != in_flight_.end()) {
        if (running->second.waiters.size() >= options_.maximum_waiters) return refuse("skipped");
        running->second.waiters.push_back(std::move(subject));
        if (fd >= 0) ::close(fd);  // the request already queued covers this content
        return file_hash{};
    }
    if (fd < 0) {
        ++metrics_.unreadable;
        return unreadable();
    }
    if (queue_.size() >= options_.queue_capacity) return refuse("skipped");
    in_flight_[key].waiters.push_back(subject);
    queue_.push_back({std::move(subject), fd});
    wake_.notify_one();
    return file_hash{};
}

std::vector<hash_result> hash_service::drain() {
    const std::lock_guard lock{mutex_};
    return std::exchange(finished_, {});
}

std::size_t hash_service::pending() const {
    const std::lock_guard lock{mutex_};
    return in_flight_.size();
}

hash_metrics hash_service::metrics() const {
    const std::lock_guard lock{mutex_};
    return metrics_;
}

void hash_service::remember(const hash_key& key, const file_hash& hash) {
    if (cache_.emplace(key, hash).second) cache_order_.push_back(key);
    while (cache_order_.size() > options_.cache_entries) {
        cache_.erase(cache_order_.front());
        cache_order_.pop_front();
    }
}

void hash_service::run() {
    // Hashing is background work: it must never compete with the monitored workload.
    (void)::setpriority(PRIO_PROCESS, static_cast<id_t>(::syscall(SYS_gettid)), 10);
    using clock = std::chrono::steady_clock;
    auto last = clock::now();
    double allowance = static_cast<double>(options_.bytes_per_second);
    const std::function<bool(std::size_t)> pace = [&](const std::size_t bytes) {
        const auto now = clock::now();
        const double rate = static_cast<double>(std::max<std::uint64_t>(1U, options_.bytes_per_second));
        allowance = std::min(rate, allowance + std::chrono::duration<double>(now - last).count() * rate);
        last = now;
        allowance -= static_cast<double>(bytes);
        std::unique_lock lock{mutex_};
        if (allowance < 0.0) {
            const auto delay = std::chrono::duration<double>(-allowance / rate);
            wake_.wait_for(lock, delay, [this] { return stopping_; });
            last = clock::now();
            allowance = 0.0;
        }
        return !stopping_;
    };
    for (;;) {
        request current;
        {
            std::unique_lock lock{mutex_};
            wake_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_) return;
            current = std::move(queue_.front());
            queue_.pop_front();
        }
        const auto hash = hash_stream(current.fd, options_.maximum_file_bytes, pace);
        ::close(current.fd);
        const std::lock_guard lock{mutex_};
        if (hash.status == "computed") {
            ++metrics_.computed;
            metrics_.bytes_hashed += current.subject.key.size;
        } else if (hash.status == "too_large") {
            ++metrics_.too_large;
        } else {
            ++metrics_.unreadable;
        }
        if (hash.status == "computed" || hash.status == "too_large") remember(current.subject.key, hash);
        if (const auto running = in_flight_.find(current.subject.key); running != in_flight_.end()) {
            for (auto& waiter : running->second.waiters) finished_.push_back({std::move(waiter), hash});
            in_flight_.erase(running);
        }
    }
}

}  // namespace panopticon::linux_agent::sensor
