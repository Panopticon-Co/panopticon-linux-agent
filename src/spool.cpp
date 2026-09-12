#include "panopticon/linux_agent/spool.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace panopticon::linux_agent {
namespace {

constexpr std::string_view format_marker{"PANO-SPOOL-1"};

std::uint64_t checksum(const std::string_view value) noexcept {
    // Detects accidental truncation/corruption only. It is not a cryptographic integrity check.
    std::uint64_t state{14695981039346656037ULL};
    for (const auto byte : value) {
        state ^= static_cast<unsigned char>(byte);
        state *= 1099511628211ULL;
    }
    return state;
}

error io_error(const std::string_view operation) {
    return {error_code::io_failure, std::string{operation}};
}

bool is_child_of(const std::filesystem::path& directory, const std::filesystem::path& file) {
    const auto canonical_directory = std::filesystem::weakly_canonical(directory);
    const auto canonical_file = std::filesystem::weakly_canonical(file);
    const auto mismatch = std::mismatch(canonical_directory.begin(), canonical_directory.end(), canonical_file.begin());
    return mismatch.first == canonical_directory.end();
}

}  // namespace

durable_spool::durable_spool(std::filesystem::path directory, const std::uint64_t quota_bytes)
    : directory_{std::move(directory)}, quota_bytes_{quota_bytes} {
    std::error_code error;
    std::filesystem::create_directories(directory_, error);
}

result<std::filesystem::path> durable_spool::append(std::string payload) {
    if (payload.empty() || payload.size() > quota_bytes_) {
        return error{error_code::resource_limit, "spool payload is empty or exceeds quota"};
    }
    if (size_bytes() > quota_bytes_ - payload.size()) {
        return error{error_code::resource_limit, "spool quota exceeded"};
    }

    const auto sequence = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto final_path = directory_ / ("segment-" + std::to_string(sequence) + ".record");
    const auto temporary_path = final_path.string() + ".tmp";
    std::ofstream output{temporary_path, std::ios::binary | std::ios::trunc};
    if (!output) {
        return io_error("cannot create spool segment");
    }
    output << format_marker << '\n' << payload.size() << '\n' << std::hex << checksum(payload) << '\n' << payload;
    output.flush();
    if (!output) {
        return io_error("cannot write spool segment");
    }
    output.close();
    std::error_code error;
    std::filesystem::rename(temporary_path, final_path, error);
    if (error) {
        std::filesystem::remove(temporary_path, error);
        return io_error("cannot atomically publish spool segment");
    }
    return final_path;
}

result<std::vector<std::filesystem::path>> durable_spool::pending() const {
    std::error_code error;
    std::vector<std::filesystem::path> entries;
    for (const auto& entry : std::filesystem::directory_iterator{directory_, error}) {
        if (error) {
            return io_error("cannot enumerate spool directory");
        }
        if (entry.is_regular_file() && entry.path().extension() == ".record") {
            entries.push_back(entry.path());
        }
    }
    std::sort(entries.begin(), entries.end());
    return entries;
}

result<std::string> durable_spool::read(const std::filesystem::path& entry) const {
    if (!is_child_of(directory_, entry) || entry.extension() != ".record") {
        return error{error_code::invalid_input, "entry is outside the spool"};
    }
    std::ifstream input{entry, std::ios::binary};
    if (!input) {
        return io_error("cannot open spool segment");
    }
    std::string marker;
    std::string length_line;
    std::string checksum_line;
    if (!std::getline(input, marker) || !std::getline(input, length_line) || !std::getline(input, checksum_line) || marker != format_marker) {
        return error{error_code::corrupt_data, "spool header is invalid"};
    }
    std::size_t expected_length{};
    std::uint64_t expected_checksum{};
    std::istringstream length_parser{length_line};
    std::istringstream checksum_parser{checksum_line};
    checksum_parser >> std::hex >> expected_checksum;
    if (!(length_parser >> expected_length) || !checksum_parser) {
        return error{error_code::corrupt_data, "spool header cannot be parsed"};
    }
    std::string payload(expected_length, '\0');
    input.read(payload.data(), static_cast<std::streamsize>(payload.size()));
    if (static_cast<std::size_t>(input.gcount()) != payload.size() || checksum(payload) != expected_checksum) {
        return error{error_code::corrupt_data, "spool payload is corrupt"};
    }
    return payload;
}

result<bool> durable_spool::acknowledge(const std::filesystem::path& entry) const {
    if (!is_child_of(directory_, entry) || entry.extension() != ".record") {
        return error{error_code::invalid_input, "entry is outside the spool"};
    }
    std::error_code error;
    const bool removed = std::filesystem::remove(entry, error);
    if (error) {
        return io_error("cannot acknowledge spool segment");
    }
    return removed;
}

result<std::uint64_t> durable_spool::recover() {
    const auto entries = pending();
    if (!succeeded(entries)) {
        return std::get<error>(entries);
    }
    std::uint64_t quarantined{};
    const auto corrupt_directory = directory_ / "corrupt";
    std::error_code error;
    std::filesystem::create_directories(corrupt_directory, error);
    if (error) {
        return io_error("cannot create corrupt spool directory");
    }
    for (const auto& entry : std::get<std::vector<std::filesystem::path>>(entries)) {
        if (succeeded(read(entry))) {
            continue;
        }
        std::filesystem::rename(entry, corrupt_directory / entry.filename(), error);
        if (error) {
            return io_error("cannot quarantine corrupt spool segment");
        }
        ++quarantined;
    }
    return quarantined;
}

std::uint64_t durable_spool::size_bytes() const {
    std::error_code error;
    std::uint64_t size{};
    for (const auto& entry : std::filesystem::directory_iterator{directory_, error}) {
        if (error) {
            return quota_bytes_;
        }
        if (entry.is_regular_file()) {
            size += entry.file_size(error);
            if (error) {
                return quota_bytes_;
            }
        }
    }
    return size;
}

}  // namespace panopticon::linux_agent
