#include "panopticon/linux_agent/sensor/wal.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::array<std::uint32_t, 256> make_crc32c_table() {
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t index = 0U; index < 256U; ++index) {
        std::uint32_t value = index;
        for (int bit = 0; bit < 8; ++bit) value = (value & 1U) != 0U ? (value >> 1U) ^ 0x82F63B78U : value >> 1U;
        table[index] = value;
    }
    return table;
}
constexpr auto crc32c_table = make_crc32c_table();

void put_u32(unsigned char* out, const std::uint32_t value) {
    for (int index = 0; index < 4; ++index) out[index] = static_cast<unsigned char>(value >> (8 * index));
}
void put_u64(unsigned char* out, const std::uint64_t value) {
    for (int index = 0; index < 8; ++index) out[index] = static_cast<unsigned char>(value >> (8 * index));
}
std::uint32_t get_u32(const unsigned char* in) {
    std::uint32_t value = 0U;
    for (int index = 3; index >= 0; --index) value = (value << 8U) | in[index];
    return value;
}
std::uint64_t get_u64(const unsigned char* in) {
    std::uint64_t value = 0U;
    for (int index = 7; index >= 0; --index) value = (value << 8U) | in[index];
    return value;
}

std::string segment_name(const std::uint64_t first_seq) {
    std::array<char, 40> buffer{};
    const auto written = std::snprintf(buffer.data(), buffer.size(), "wal-%020llu.log", static_cast<unsigned long long>(first_seq));
    return std::string{buffer.data(), static_cast<std::size_t>(written)};
}

std::optional<std::uint64_t> parse_segment_name(const std::string& name) {
    if (name.size() != 28U || name.rfind("wal-", 0U) != 0U || name.substr(24U) != ".log") return std::nullopt;
    std::uint64_t value = 0U;
    const auto digits = std::string_view{name}.substr(4U, 20U);
    const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (error != std::errc{} || end != digits.data() + digits.size() || value == 0U) return std::nullopt;
    return value;
}

bool write_all(const int fd, const char* data, std::size_t size) {
    while (size > 0U) {
        const auto written = ::write(fd, data, size);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

bool read_exact(const int fd, void* out, const std::size_t size, const std::uint64_t offset) {
    auto* cursor = static_cast<char*>(out);
    std::size_t done = 0U;
    while (done < size) {
        const auto count = ::pread(fd, cursor + done, size - done, static_cast<off_t>(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += static_cast<std::size_t>(count);
    }
    return true;
}

bool sync_directory(const std::filesystem::path& directory) {
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

}  // namespace

std::uint32_t crc32c(std::uint32_t crc, const void* data, const std::size_t size) noexcept {
    const auto* bytes = static_cast<const unsigned char*>(data);
    crc = ~crc;
    for (std::size_t index = 0U; index < size; ++index) crc = crc32c_table[(crc ^ bytes[index]) & 0xFFU] ^ (crc >> 8U);
    return ~crc;
}

std::uint32_t wal_frame_crc(const std::uint64_t seq, const std::string_view payload) noexcept {
    unsigned char seq_bytes[8];
    put_u64(seq_bytes, seq);
    return crc32c(crc32c(0U, seq_bytes, sizeof(seq_bytes)), payload.data(), payload.size());
}

wal_frame_header decode_wal_header(const unsigned char* bytes) noexcept {
    return {get_u32(bytes), get_u32(bytes + 4), get_u32(bytes + 8), get_u64(bytes + 12)};
}

std::string encode_wal_frame(const std::uint64_t seq, const std::string_view payload) {
    std::string frame(wal_header_bytes + payload.size(), '\0');
    auto* out = reinterpret_cast<unsigned char*>(frame.data());
    put_u32(out, wal_magic);
    put_u32(out + 4, static_cast<std::uint32_t>(payload.size()));
    put_u32(out + 8, wal_frame_crc(seq, payload));
    put_u64(out + 12, seq);
    std::memcpy(frame.data() + wal_header_bytes, payload.data(), payload.size());
    return frame;
}

write_ahead_log::write_ahead_log(wal_options options) : options_{std::move(options)} {}

write_ahead_log::~write_ahead_log() {
    if (active_fd_ >= 0) {
        (void)::fdatasync(active_fd_);
        ::close(active_fd_);
    }
}

result<std::unique_ptr<write_ahead_log>> write_ahead_log::open(wal_options options) {
    if (options.directory.empty() || options.segment_bytes < 4096U || options.quota_bytes < 2U * options.segment_bytes ||
        options.maximum_record_bytes == 0U || options.maximum_record_bytes + wal_header_bytes > options.segment_bytes) {
        return error{error_code::invalid_input, "invalid write-ahead log limits"};
    }
    std::unique_ptr<write_ahead_log> log{new write_ahead_log{std::move(options)}};
    if (auto recovered = log->recover(); !succeeded(recovered)) return std::get<error>(recovered);
    return log;
}

result<bool> write_ahead_log::recover() {
    std::error_code fs_error;
    std::filesystem::create_directories(options_.directory, fs_error);
    if (fs_error) return error{error_code::io_failure, "cannot create write-ahead log directory"};
    if (::chmod(options_.directory.c_str(), 0700) != 0) return error{error_code::io_failure, "cannot restrict write-ahead log directory"};

    if (FILE* cursor = std::fopen((options_.directory / "cursor").c_str(), "re"); cursor != nullptr) {
        unsigned long long value = 0U;
        if (std::fscanf(cursor, "acknowledged %llu", &value) == 1) acknowledged_seq_ = value;
        std::fclose(cursor);
    }

    for (const auto& entry : std::filesystem::directory_iterator{options_.directory, fs_error}) {
        if (const auto first = parse_segment_name(entry.path().filename().string()); first.has_value()) {
            segments_.push_back({entry.path(), *first, 0U, 0U});
        }
    }
    if (fs_error) return error{error_code::io_failure, "cannot list write-ahead log directory"};
    std::sort(segments_.begin(), segments_.end(), [](const segment& a, const segment& b) { return a.first_seq < b.first_seq; });

    // Frames inside a segment must be contiguous; a torn or corrupt frame ends that segment (its
    // valid prefix is kept). Between segments a missing range is reported as a gap rather than
    // discarding later intact segments.
    std::optional<std::uint64_t> expected;
    bool last_has_garbage = false;
    for (std::size_t index = 0U; index < segments_.size();) {
        auto& current = segments_[index];
        if (expected.has_value() && current.first_seq < *expected) {
            std::error_code ignored;
            const auto bytes = std::filesystem::file_size(current.path, ignored);
            losses_.push_back({"corrupt_segment", current.first_seq, 0U, 0U, ignored ? 0U : bytes});
            delete_segment(index);
            continue;
        }
        if (expected.has_value() && current.first_seq > *expected) {
            losses_.push_back({"gap", *expected, current.first_seq - 1U, current.first_seq - *expected, 0U});
        }
        expected = current.first_seq;
        const int fd = ::open(current.path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return error{error_code::io_failure, "cannot open write-ahead log segment"};
        struct stat file_status {};
        if (::fstat(fd, &file_status) != 0) {
            ::close(fd);
            return error{error_code::io_failure, "cannot stat write-ahead log segment"};
        }
        const auto size = static_cast<std::uint64_t>(file_status.st_size);
        std::uint64_t offset = 0U;
        std::string payload;
        while (offset < size) {
            unsigned char header[wal_header_bytes];
            if (size - offset < wal_header_bytes || !read_exact(fd, header, sizeof(header), offset)) break;
            const auto frame = decode_wal_header(header);
            if (frame.magic != wal_magic || frame.length > options_.maximum_record_bytes ||
                size - offset - wal_header_bytes < frame.length || frame.seq != *expected) {
                break;
            }
            payload.resize(frame.length);
            if (!read_exact(fd, payload.data(), frame.length, offset + wal_header_bytes) ||
                wal_frame_crc(frame.seq, payload) != frame.crc) {
                break;
            }
            offset += wal_header_bytes + frame.length;
            current.last_seq = frame.seq;
            expected = frame.seq + 1U;
        }
        const bool last_segment = index + 1U == segments_.size();
        if (offset < size) {
            losses_.push_back({last_segment ? "torn_tail" : "corrupt_segment", *expected, 0U, 0U, size - offset});
            // If the cut fails the bytes stay beyond `current.bytes`, which readers never pass;
            // the segment is then not reused for appends.
            if (::ftruncate(fd, static_cast<off_t>(offset)) != 0 && last_segment) last_has_garbage = true;
        }
        (void)::fdatasync(fd);
        ::close(fd);
        current.bytes = offset;
        if (current.last_seq == 0U) {
            delete_segment(index);
            continue;
        }
        ++index;
    }

    const std::uint64_t last = segments_.empty() ? 0U : segments_.back().last_seq;
    next_seq_ = std::max(last, acknowledged_seq_) + 1U;
    durable_seq_ = next_seq_ - 1U;
    while (!segments_.empty() && segments_.front().last_seq <= acknowledged_seq_) delete_segment(0U);
    if (!segments_.empty() && !last_has_garbage && segments_.back().bytes < options_.segment_bytes) {
        active_fd_ = ::open(segments_.back().path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
        if (active_fd_ < 0) return error{error_code::io_failure, "cannot reopen active segment"};
    }
    (void)sync_directory(options_.directory);
    return true;
}

result<bool> write_ahead_log::open_active(const std::uint64_t first_seq) {
    if (active_fd_ >= 0) {
        if (::fdatasync(active_fd_) != 0) return error{error_code::io_failure, "cannot sync write-ahead log segment"};
        ++syncs_;
        durable_seq_ = next_seq_ - 1U;
        pending_bytes_ = 0U;
        ::close(active_fd_);
        active_fd_ = -1;
    }
    const auto path = options_.directory / segment_name(first_seq);
    active_fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (active_fd_ < 0) return error{error_code::io_failure, "cannot create write-ahead log segment"};
    segments_.push_back({path, first_seq, 0U, 0U});
    if (!sync_directory(options_.directory)) return error{error_code::io_failure, "cannot sync write-ahead log directory"};
    return true;
}

result<std::uint64_t> write_ahead_log::append(const std::uint64_t seq, const std::string_view payload) {
    if (seq != next_seq_) return error{error_code::invalid_input, "write-ahead log seq is not contiguous"};
    if (payload.size() > options_.maximum_record_bytes) return error{error_code::resource_limit, "record exceeds maximum size"};
    const auto frame = encode_wal_frame(seq, payload);
    if (active_fd_ < 0 || segments_.back().bytes + frame.size() > options_.segment_bytes) {
        if (auto opened = open_active(seq); !succeeded(opened)) return std::get<error>(opened);
    }
    auto& current = segments_.back();
    if (!write_all(active_fd_, frame.data(), frame.size())) {
        // Never leave a partial frame in front of later appends: cut it, or if that fails seal
        // the segment so the next append starts a new one (recovery then trims the tail).
        if (::ftruncate(active_fd_, static_cast<off_t>(current.bytes)) != 0) {
            if (::fdatasync(active_fd_) == 0) durable_seq_ = next_seq_ - 1U;
            ::close(active_fd_);
            active_fd_ = -1;
            if (current.last_seq == 0U) delete_segment(segments_.size() - 1U);
        }
        return error{error_code::io_failure, "cannot append to write-ahead log"};
    }
    current.bytes += frame.size();
    current.last_seq = seq;
    ++next_seq_;
    pending_bytes_ += frame.size();
    enforce_quota();
    return seq;
}

result<bool> write_ahead_log::sync(const std::uint64_t now_ns, const bool force) {
    if (pending_bytes_ == 0U || active_fd_ < 0) {
        last_sync_ns_ = now_ns;
        return false;
    }
    if (!force && pending_bytes_ < options_.sync_bytes && now_ns - last_sync_ns_ < options_.sync_interval_ns) return false;
    if (::fdatasync(active_fd_) != 0) return error{error_code::io_failure, "cannot sync write-ahead log"};
    ++syncs_;
    durable_seq_ = next_seq_ - 1U;
    pending_bytes_ = 0U;
    last_sync_ns_ = now_ns;
    return true;
}

void write_ahead_log::enforce_quota() {
    std::uint64_t total = 0U;
    for (const auto& current : segments_) total += current.bytes;
    while (total > options_.quota_bytes && segments_.size() > 1U) {
        const auto oldest = segments_.front();
        if (oldest.last_seq > acknowledged_seq_) {
            const auto first = std::max(oldest.first_seq, acknowledged_seq_ + 1U);
            losses_.push_back({"quota", first, oldest.last_seq, oldest.last_seq - first + 1U, oldest.bytes});
            dropped_records_ += oldest.last_seq - first + 1U;
        }
        total -= oldest.bytes;
        delete_segment(0U);
    }
}

void write_ahead_log::delete_segment(const std::size_t index) {
    std::error_code ignored;
    std::filesystem::remove(segments_[index].path, ignored);
    if (reader_path_ == segments_[index].path) reader_seq_.reset();
    segments_.erase(segments_.begin() + static_cast<std::ptrdiff_t>(index));
}

result<std::vector<wal_record>> write_ahead_log::read(const std::uint64_t from_seq, const std::size_t maximum_records,
                                                      const std::size_t maximum_bytes) {
    std::vector<wal_record> records;
    if (from_seq > durable_seq_ || maximum_records == 0U || segments_.empty()) return records;

    std::size_t index = 0U;
    std::uint64_t offset = 0U;
    for (std::size_t position = 0U; position < segments_.size(); ++position) {
        if (segments_[position].first_seq <= from_seq) index = position;
    }
    if (reader_seq_ == from_seq) {
        const auto found = std::find_if(segments_.begin(), segments_.end(), [this](const segment& s) { return s.path == reader_path_; });
        if (found != segments_.end()) {
            index = static_cast<std::size_t>(found - segments_.begin());
            offset = reader_offset_;
        }
    }

    std::size_t bytes = 0U;
    std::string payload;
    for (; index < segments_.size(); ++index, offset = 0U) {
        const auto& current = segments_[index];
        const int fd = ::open(current.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return error{error_code::io_failure, "cannot read write-ahead log segment"};
        while (offset + wal_header_bytes <= current.bytes) {
            unsigned char header[wal_header_bytes];
            if (!read_exact(fd, header, sizeof(header), offset)) break;
            const auto frame = decode_wal_header(header);
            if (frame.magic != wal_magic || frame.seq > durable_seq_) break;
            const auto next_offset = offset + wal_header_bytes + frame.length;
            if (frame.seq >= from_seq) {
                if (!records.empty() && (records.size() == maximum_records || bytes + frame.length > maximum_bytes)) {
                    ::close(fd);
                    reader_seq_ = frame.seq;
                    reader_path_ = current.path;
                    reader_offset_ = offset;
                    return records;
                }
                payload.resize(frame.length);
                if (!read_exact(fd, payload.data(), frame.length, offset + wal_header_bytes) ||
                    wal_frame_crc(frame.seq, payload) != frame.crc) {
                    ::close(fd);
                    return error{error_code::corrupt_data, "write-ahead log record failed its checksum"};
                }
                bytes += frame.length;
                records.push_back({frame.seq, payload});
            }
            offset = next_offset;
        }
        ::close(fd);
        reader_seq_ = records.empty() ? std::optional<std::uint64_t>{} : std::optional<std::uint64_t>{records.back().seq + 1U};
        reader_path_ = current.path;
        reader_offset_ = offset;
        if (!records.empty() && records.back().seq >= durable_seq_) break;
    }
    return records;
}

result<bool> write_ahead_log::persist_cursor(const std::uint64_t seq) {
    const auto temporary = options_.directory / "cursor.tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return error{error_code::io_failure, "cannot write delivery cursor"};
    const auto text = "acknowledged " + std::to_string(seq) + "\n";
    const bool written = write_all(fd, text.data(), text.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (!written || ::rename(temporary.c_str(), (options_.directory / "cursor").c_str()) != 0 ||
        !sync_directory(options_.directory)) {
        return error{error_code::io_failure, "cannot persist delivery cursor"};
    }
    return true;
}

result<bool> write_ahead_log::acknowledge(std::uint64_t seq) {
    if (seq <= acknowledged_seq_) return false;
    if (seq > durable_seq_) return error{error_code::invalid_input, "acknowledgement beyond durable records"};
    if (auto persisted = persist_cursor(seq); !succeeded(persisted)) return persisted;
    acknowledged_seq_ = seq;
    while (segments_.size() > 1U && segments_.front().last_seq <= seq) delete_segment(0U);
    return true;
}

std::vector<wal_loss> write_ahead_log::take_losses() {
    auto taken = std::move(losses_);
    losses_.clear();
    return taken;
}

wal_metrics write_ahead_log::metrics() const {
    wal_metrics values;
    for (const auto& current : segments_) values.bytes += current.bytes;
    values.segments = segments_.size();
    values.next_seq = next_seq_;
    values.durable_seq = durable_seq_;
    values.acknowledged_seq = acknowledged_seq_;
    values.syncs = syncs_;
    values.dropped_records = dropped_records_;
    return values;
}

}  // namespace panopticon::linux_agent::sensor
