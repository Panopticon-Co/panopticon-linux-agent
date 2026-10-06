#pragma once

#include "panopticon/linux_agent/error.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

// CRC-32C (Castagnoli), software implementation. `crc` is the running value (0 to start).
[[nodiscard]] std::uint32_t crc32c(std::uint32_t crc, const void* data, std::size_t size) noexcept;

inline constexpr std::uint32_t wal_magic = 0x314C5750U;  // "PWL1" little-endian
inline constexpr std::size_t wal_header_bytes = 20U;     // magic, length, crc, seq

struct wal_options {
    std::filesystem::path directory;
    std::uint64_t quota_bytes{256ULL * 1024U * 1024U};
    std::uint64_t segment_bytes{8ULL * 1024U * 1024U};
    std::uint64_t sync_interval_ns{200'000'000ULL};
    std::uint64_t sync_bytes{256U * 1024U};
    std::uint32_t maximum_record_bytes{1024U * 1024U};
};

// Range of records that no longer exist: torn tail at recovery, or dropped at quota.
struct wal_loss {
    std::string reason;  // "torn_tail", "corrupt_segment", "gap", "quota"
    std::uint64_t first_seq{};
    std::uint64_t last_seq{};
    std::uint64_t records{};
    std::uint64_t bytes{};
};

struct wal_record {
    std::uint64_t seq{};
    std::string payload;
};

struct wal_metrics {
    std::uint64_t bytes{};
    std::uint64_t segments{};
    std::uint64_t next_seq{};
    std::uint64_t durable_seq{};
    std::uint64_t acknowledged_seq{};
    std::uint64_t syncs{};
    std::uint64_t dropped_records{};
};

class write_ahead_log {
public:
    // Creates the directory (0700) if needed, recovers existing segments and positions `seq`
    // after the highest valid record. Recovery losses are available from take_losses().
    [[nodiscard]] static result<std::unique_ptr<write_ahead_log>> open(wal_options options);
    ~write_ahead_log();
    write_ahead_log(const write_ahead_log&) = delete;
    write_ahead_log& operator=(const write_ahead_log&) = delete;

    // The seq the next append must carry. Records embed their seq, so callers serialise with
    // next_seq() and then append.
    // Safe to call from any thread. Every other method takes the log's mutex, so the uplink thread
    // may read() and acknowledge() while the pipeline thread appends.
    [[nodiscard]] std::uint64_t next_seq() const noexcept { return next_seq_.load(); }

    // Appends one record; `seq` must equal next_seq(). Enforces the quota by dropping the oldest
    // segment (reported via take_losses()); never fails because the log is full.
    [[nodiscard]] result<std::uint64_t> append(std::uint64_t seq, std::string_view payload);

    // Group commit: syncs when the byte or time threshold is reached, or always when `force`.
    [[nodiscard]] result<bool> sync(std::uint64_t now_ns, bool force = false);

    // Durable records with seq >= from_seq, bounded by count and bytes.
    [[nodiscard]] result<std::vector<wal_record>> read(std::uint64_t from_seq, std::size_t maximum_records,
                                                       std::size_t maximum_bytes);

    // Persists the delivery cursor and deletes segments that are fully acknowledged.
    [[nodiscard]] result<bool> acknowledge(std::uint64_t seq);

    [[nodiscard]] std::vector<wal_loss> take_losses();
    [[nodiscard]] wal_metrics metrics() const;

private:
    struct segment {
        std::filesystem::path path;
        std::uint64_t first_seq{};
        std::uint64_t last_seq{};  // 0 when empty
        std::uint64_t bytes{};
    };

    explicit write_ahead_log(wal_options options);
    result<bool> recover();
    result<bool> open_active(std::uint64_t first_seq);
    result<bool> persist_cursor(std::uint64_t seq);
    void enforce_quota();
    void delete_segment(std::size_t index);

    wal_options options_;
    mutable std::mutex mutex_;
    std::vector<segment> segments_;
    int active_fd_{-1};
    std::atomic<std::uint64_t> next_seq_{1};
    std::uint64_t durable_seq_{0};
    std::uint64_t acknowledged_seq_{0};
    std::uint64_t pending_bytes_{0};
    std::uint64_t last_sync_ns_{0};
    std::uint64_t syncs_{0};
    std::uint64_t dropped_records_{0};
    std::vector<wal_loss> losses_;
    // Reader position cache so sequential reads do not rescan segments.
    std::optional<std::uint64_t> reader_seq_;
    std::filesystem::path reader_path_;
    std::uint64_t reader_offset_{0};
};

// Parses a frame header and validates it against `payload`; exposed for fuzzing.
struct wal_frame_header {
    std::uint32_t magic{};
    std::uint32_t length{};
    std::uint32_t crc{};
    std::uint64_t seq{};
};
[[nodiscard]] wal_frame_header decode_wal_header(const unsigned char* bytes) noexcept;
[[nodiscard]] std::string encode_wal_frame(std::uint64_t seq, std::string_view payload);
[[nodiscard]] std::uint32_t wal_frame_crc(std::uint64_t seq, std::string_view payload) noexcept;

}  // namespace panopticon::linux_agent::sensor
