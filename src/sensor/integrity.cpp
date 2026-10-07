#include "panopticon/linux_agent/sensor/integrity.hpp"

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/trusted_path.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <limits>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::string_view magic_line = "panopticon-build-manifest 1";
constexpr std::string_view separator_line = "---";
constexpr std::array<std::string_view, 5U> header_names{"package", "version", "built_at", "key_id", "signature"};
constexpr std::size_t maximum_header_value_bytes = 256U;
constexpr std::size_t maximum_version_bytes = 64U;
constexpr std::size_t maximum_path_bytes = 4096U;
// A violation names at most this many bytes of why, in the record and in the health reason.
constexpr std::size_t maximum_detail_bytes = 480U;

void append_field(std::string& out, const std::string_view name, const std::string_view value) {
    out += name;
    out += ':';
    out += std::to_string(value.size());
    out += ':';
    out += value;
    out += '\n';
}

template <typename integer_type>
std::optional<integer_type> decimal(const std::string_view text) {
    if (text.empty() || text.size() > 19U || (text.size() > 1U && text.front() == '0')) return std::nullopt;
    if (!std::all_of(text.begin(), text.end(), [](const char c) { return c >= '0' && c <= '9'; })) return std::nullopt;
    integer_type value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

bool lower_hex(const std::string_view text, const std::size_t length) {
    return text.size() == length && std::all_of(text.begin(), text.end(), [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

std::string hex(const unsigned char* bytes, const std::size_t count) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(count * 2U);
    for (std::size_t index = 0U; index < count; ++index) {
        out.push_back(digits[bytes[index] >> 4U]);
        out.push_back(digits[bytes[index] & 15U]);
    }
    return out;
}

// SHA-256 of an open file, read with pread so the descriptor's offset (and any other reader of it) is not disturbed.
// Empty and `why` set when it cannot be read or is larger than `maximum`.
std::string hash_descriptor(const int fd, const std::uint64_t maximum, std::string& why) {
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        why = "not a regular file";
        return {};
    }
    if (static_cast<std::uint64_t>(info.st_size) > maximum) {
        why = "larger than " + std::to_string(maximum) + " bytes";
        return {};
    }
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        why = "hashing is unavailable";
        return {};
    }
    std::array<unsigned char, 65536U> buffer{};
    off_t offset = 0;
    std::string digest;
    while (true) {
        const auto count = ::pread(fd, buffer.data(), buffer.size(), offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            why = std::string{"read failed: "} + std::strerror(errno);
            EVP_MD_CTX_free(context);
            return {};
        }
        if (count == 0) break;
        EVP_DigestUpdate(context, buffer.data(), static_cast<std::size_t>(count));
        offset += count;
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
    unsigned int length = 0U;
    if (EVP_DigestFinal_ex(context, bytes.data(), &length) == 1) digest = hex(bytes.data(), length);
    else why = "hashing failed";
    EVP_MD_CTX_free(context);
    return digest;
}

std::string read_bounded(const std::filesystem::path& path, const std::uint64_t maximum, bool& too_large, bool& unreadable) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        unreadable = true;
        return {};
    }
    std::string text;
    std::array<char, 8192U> chunk{};
    while (input) {
        input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const auto got = static_cast<std::size_t>(input.gcount());
        if (text.size() + got > maximum) {
            too_large = true;
            return {};
        }
        text.append(chunk.data(), got);
    }
    if (input.bad()) unreadable = true;
    return text;
}

std::uint64_t nanoseconds(const timespec& time) {
    return static_cast<std::uint64_t>(time.tv_sec) * 1'000'000'000ULL + static_cast<std::uint64_t>(time.tv_nsec);
}

std::string clip(std::string text) {
    if (text.size() > maximum_detail_bytes) text.resize(maximum_detail_bytes);
    return text;
}

}  // namespace

std::string manifest_signing_input(const build_manifest& manifest, const std::string_view body_sha256_hex) {
    std::string out{"panopticon-build-manifest/1\n"};
    append_field(out, "package", manifest.package);
    append_field(out, "version", manifest.version);
    append_field(out, "built_at", std::to_string(manifest.built_unix));
    append_field(out, "body_sha256", body_sha256_hex);
    return out;
}

std::string render_manifest_body(const std::vector<manifest_entry>& entries) {
    std::string body;
    for (const auto& entry : entries) body += entry.sha256 + " " + std::to_string(entry.size) + " " + entry.path + "\n";
    return body;
}

std::string render_build_manifest(const build_manifest& header, const std::string_view body) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string signature;
    for (std::size_t index = 0U; index < header.signature.size(); index += 3U) {
        const unsigned a = header.signature[index];
        const unsigned b = index + 1U < header.signature.size() ? header.signature[index + 1U] : 0U;
        const unsigned c = index + 2U < header.signature.size() ? header.signature[index + 2U] : 0U;
        const unsigned group = (a << 16U) | (b << 8U) | c;
        signature.push_back(alphabet[(group >> 18U) & 63U]);
        signature.push_back(alphabet[(group >> 12U) & 63U]);
        signature.push_back(index + 1U < header.signature.size() ? alphabet[(group >> 6U) & 63U] : '=');
        signature.push_back(index + 2U < header.signature.size() ? alphabet[group & 63U] : '=');
    }
    return std::string{magic_line} + "\npackage " + header.package + "\nversion " + header.version + "\nbuilt_at " + std::to_string(header.built_unix) +
           "\nkey_id " + header.key_id + "\nsignature " + signature + "\n---\n" + std::string{body};
}

result<build_manifest> parse_build_manifest(const std::string_view text) {
    const auto fail = [](const std::string& why) -> result<build_manifest> { return error{error_code::invalid_input, "build manifest: " + why}; };
    if (text.size() > maximum_manifest_bytes) return fail("larger than " + std::to_string(maximum_manifest_bytes) + " bytes");
    std::size_t cursor = 0U;
    const auto next_line = [&](std::string_view& line) {
        if (cursor >= text.size()) return false;
        const auto newline = text.find('\n', cursor);
        if (newline == std::string_view::npos) return false;
        line = text.substr(cursor, newline - cursor);
        cursor = newline + 1U;
        return true;
    };
    std::string_view line;
    if (!next_line(line) || line != magic_line) return fail("the first line must be \"panopticon-build-manifest 1\"");
    std::array<std::string_view, header_names.size()> values{};
    for (std::size_t index = 0U; index < header_names.size(); ++index) {
        const std::string name{header_names[index]};
        if (!next_line(line)) return fail("missing " + name);
        const auto space = line.find(' ');
        if (space == std::string_view::npos || line.substr(0U, space) != header_names[index]) return fail("line " + std::to_string(index + 2U) + " must be " + name);
        values[index] = line.substr(space + 1U);
        const bool printable = std::all_of(values[index].begin(), values[index].end(), [](const unsigned char c) { return c >= 0x20U && c < 0x7fU; });
        if (values[index].empty() || values[index].size() > maximum_header_value_bytes || !printable) return fail("bad value for " + name);
    }
    if (!next_line(line) || line != separator_line) return fail("the header must be followed by a line \"---\"");
    const auto body = text.substr(cursor);

    build_manifest manifest;
    manifest.package = std::string{values[0]};
    if (!is_valid_identifier(manifest.package)) return fail("package must be an identifier (letters, digits, '.', '_', '-')");
    manifest.version = std::string{values[1]};
    if (manifest.version.size() > maximum_version_bytes) return fail("version is longer than " + std::to_string(maximum_version_bytes) + " bytes");
    const auto built = decimal<std::int64_t>(values[2]);
    if (!built || *built > 9'999'999'999LL) return fail("built_at must be decimal unix seconds up to 9999999999");
    manifest.built_unix = *built;
    manifest.key_id = std::string{values[3]};
    if (!lower_hex(manifest.key_id, 16U)) return fail("key_id must be 16 lowercase hex digits");
    const auto signature = decode_base64(values[4]);
    if (!signature || signature->size() != manifest.signature.size()) return fail("signature must be the base64 of 64 bytes");
    std::copy(signature->begin(), signature->end(), manifest.signature.begin());

    if (body.empty() || body.back() != '\n') return fail("the body must be one or more lines, each ending with a newline");
    std::size_t position = 0U;
    std::set<std::string> seen;
    while (position < body.size()) {
        const auto end = body.find('\n', position);
        const auto row = body.substr(position, end - position);
        position = end + 1U;
        if (manifest.entries.size() >= maximum_manifest_entries) return fail("more than " + std::to_string(maximum_manifest_entries) + " files");
        // "<64 hex> <size> <path>"
        const auto first = row.find(' ');
        const auto second = first == std::string_view::npos ? std::string_view::npos : row.find(' ', first + 1U);
        if (first == std::string_view::npos || second == std::string_view::npos) return fail("line \"" + std::string{row.substr(0U, 40U)} + "\" is not \"<sha256> <size> <path>\"");
        manifest_entry entry;
        entry.sha256 = std::string{row.substr(0U, first)};
        const auto size = decimal<std::uint64_t>(row.substr(first + 1U, second - first - 1U));
        entry.path = std::string{row.substr(second + 1U)};
        if (!lower_hex(entry.sha256, 64U) || !size) return fail("a file line needs a lowercase hex SHA-256 and a decimal size");
        entry.size = *size;
        const bool printable = std::all_of(entry.path.begin(), entry.path.end(), [](const unsigned char c) { return c >= 0x20U && c < 0x7fU; });
        if (entry.path.empty() || entry.path.size() > maximum_path_bytes || entry.path.front() != '/' || !printable ||
            std::filesystem::path{entry.path}.lexically_normal().string() != entry.path || entry.path.back() == '/') {
            return fail("a path must be absolute, normal (no '..', '.', '//') and not end in '/': " + entry.path.substr(0U, 80U));
        }
        if (!seen.insert(entry.path).second) return fail("a path is listed twice: " + entry.path.substr(0U, 80U));
        manifest.entries.push_back(std::move(entry));
    }
    manifest.body_sha256 = sha256_hex(body);
    return manifest;
}

integrity_monitor::integrity_monitor(integrity_options options) : options_{std::move(options)} {
    const bool real = options_.running_image.empty();
    const std::filesystem::path image = real ? std::filesystem::path{"/proc/self/exe"} : options_.running_image;
    running_fd_ = ::open(image.c_str(), O_RDONLY | O_CLOEXEC);
    if (running_fd_ >= 0) {
        struct stat info {};
        if (::fstat(running_fd_, &info) == 0) {
            running_dev_ = static_cast<std::uint64_t>(info.st_dev);
            running_inode_ = static_cast<std::uint64_t>(info.st_ino);
        }
    }
    if (real) {
        std::array<char, 4096U> link{};
        const auto count = ::readlink("/proc/self/exe", link.data(), link.size() - 1U);
        running_path_ = count > 0 ? std::string{link.data(), static_cast<std::size_t>(count)} : std::string{};
        constexpr std::string_view deleted = " (deleted)";
        if (running_path_.size() > deleted.size() && running_path_.compare(running_path_.size() - deleted.size(), deleted.size(), deleted) == 0) {
            running_path_.resize(running_path_.size() - deleted.size());
        }
    } else {
        running_path_ = image.string();
    }
}

integrity_monitor::~integrity_monitor() {
    if (running_fd_ >= 0) ::close(running_fd_);
}

void integrity_monitor::load_keys() {
    if (!keys_) {
        auto loaded = command_keyring::load(options_.keys_path, "integrity key file");
        if (succeeded(loaded)) {
            keys_ = std::move(std::get<std::unique_ptr<command_keyring>>(loaded));
            keys_error_.clear();
        } else {
            keys_error_ = std::get<error>(loaded).message;
        }
    } else {
        keys_->refresh();
        keys_error_ = keys_->last_error();
    }
}

void integrity_monitor::refresh_manifest(const std::int64_t now_unix, std::map<std::string, integrity_finding>& findings) {
    load_keys();
    std::string keys_now;
    if (keys_) {
        for (const auto& id : keys_->key_ids()) keys_now += id + ",";
    }
    const bool keys_changed = keys_now != keys_fingerprint_;
    keys_fingerprint_ = std::move(keys_now);

    const auto path = options_.manifest_path.string();
    struct stat info {};
    if (::stat(options_.manifest_path.c_str(), &info) != 0) {
        manifest_identity_.reset();
        manifest_problem_ = integrity_finding{"manifest_missing", path, {}, {}, "the build manifest " + path + " is missing"};
    } else {
        const fingerprint identity{static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino), static_cast<std::uint64_t>(info.st_size),
                                   nanoseconds(info.st_mtim), nanoseconds(info.st_ctim)};
        const bool racy = static_cast<std::int64_t>(info.st_mtim.tv_sec) >= now_unix - 1 || static_cast<std::int64_t>(info.st_ctim.tv_sec) >= now_unix - 1;
        if (!manifest_identity_ || !(*manifest_identity_ == identity) || racy || keys_changed || manifest_problem_) {
            manifest_identity_ = identity;
            const auto refuse = [&](const std::string& reason, const std::string& why) {
                manifest_problem_ = integrity_finding{"manifest_invalid", path, {}, {}, clip(reason + ": " + why)};
            };
            bool too_large = false;
            bool unreadable = false;
            const auto text = read_bounded(options_.manifest_path, maximum_manifest_bytes, too_large, unreadable);
            if (const auto untrusted = untrusted_path_reason(options_.manifest_path); !untrusted.empty()) {
                refuse("untrusted_file", "the build manifest is not trustworthy: " + untrusted);
            } else if (too_large) {
                refuse("too_large", "the build manifest is larger than " + std::to_string(maximum_manifest_bytes) + " bytes");
            } else if (unreadable) {
                refuse("unreadable", "the build manifest could not be read");
            } else if (auto parsed = parse_build_manifest(text); !succeeded(parsed)) {
                refuse("malformed", std::get<error>(parsed).message);
            } else if (!keys_) {
                refuse("no_keys", keys_error_.empty() ? "no integrity key is pinned" : keys_error_);
            } else {
                auto& candidate = std::get<build_manifest>(parsed);
                const auto verdict = keys_->verify(candidate.key_id, manifest_signing_input(candidate, candidate.body_sha256), candidate.signature);
                if (verdict == authorization_verdict::unknown_key) {
                    refuse("unknown_key", "the manifest is signed with key " + candidate.key_id + ", which this endpoint does not pin");
                } else if (verdict != authorization_verdict::valid) {
                    refuse("bad_signature", "the signature does not match the manifest");
                } else {
                    manifest_ = std::make_unique<build_manifest>(std::move(candidate));
                    manifest_problem_.reset();
                }
            }
        }
    }
    if (manifest_problem_) findings[manifest_problem_->technique + "|" + manifest_problem_->target] = *manifest_problem_;
}

integrity_monitor::cached_hash integrity_monitor::hash_of(const std::string& path, const std::int64_t now_unix) {
    cached_hash fresh;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        fresh.unreadable = true;
        fresh.missing = errno == ENOENT || errno == ENOTDIR;
        fresh.why = errno == ELOOP ? std::string{"is a symbolic link, not the installed file"} : std::string{std::strerror(errno)};
        return fresh;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        ::close(fd);
        fresh.unreadable = true;
        fresh.why = std::strerror(errno);
        return fresh;
    }
    fresh.identity = {static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino), static_cast<std::uint64_t>(info.st_size),
                      nanoseconds(info.st_mtim), nanoseconds(info.st_ctim)};
    // A cached hash is trusted only if the file had been quiet for two seconds when it was hashed. A change in the very
    // timestamp tick of the last one (a write racing the hash) would otherwise leave size, mtime and ctime as they were
    // and the old digest in place; a recently written file is simply hashed again until it has settled.
    if (const auto known = hashes_.find(path); known != hashes_.end() && known->second.identity == fresh.identity && !known->second.unreadable &&
                                              now_unix - known->second.hashed_unix < static_cast<std::int64_t>(options_.full_check_seconds) &&
                                              known->second.hashed_unix - static_cast<std::int64_t>(known->second.identity.ctime_ns / 1'000'000'000ULL) >= 2) {
        ::close(fd);
        return known->second;
    }
    fresh.hashed_unix = now_unix;
    fresh.sha256 = hash_descriptor(fd, options_.maximum_file_bytes, fresh.why);
    fresh.unreadable = fresh.sha256.empty();
    ::close(fd);
    return fresh;
}

void integrity_monitor::check_files(const std::int64_t now_unix, std::map<std::string, integrity_finding>& findings) {
    files_checked_ = 0U;
    if (!manifest_) return;
    const manifest_entry* running_entry = nullptr;
    for (const auto& entry : manifest_->entries) {
        ++files_checked_;
        if (entry.path == running_path_) running_entry = &entry;
        auto observed = hash_of(entry.path, now_unix);
        hashes_[entry.path] = observed;
        if (observed.missing) {
            findings["binary_missing|" + entry.path] = {"binary_missing", entry.path, entry.sha256, {}, clip(entry.path + " is listed in the build manifest and is missing")};
        } else if (observed.unreadable) {
            findings["binary_modified|" + entry.path] = {"binary_modified", entry.path, entry.sha256, {}, clip(entry.path + " cannot be verified: " + observed.why)};
        } else if (observed.sha256 != entry.sha256) {
            findings["binary_modified|" + entry.path] = {"binary_modified", entry.path, entry.sha256, observed.sha256,
                                                          clip(entry.path + " differs from the build manifest (size " + std::to_string(observed.identity.size) + ", expected " +
                                                               std::to_string(entry.size) + ")")};
        }
    }
    if (running_path_.empty() || running_fd_ < 0) return;
    // What is running, not what is on disk now: an attacker who replaces the file leaves the old image executing.
    if (running_sha256_.empty() || now_unix - running_hashed_unix_ >= static_cast<std::int64_t>(options_.full_check_seconds)) {
        std::string why;
        running_sha256_ = hash_descriptor(running_fd_, options_.maximum_file_bytes, why);
        running_hashed_unix_ = now_unix;
        if (running_sha256_.empty()) {
            findings["binary_modified|" + running_path_ + "|running"] = {"binary_modified", running_path_, {}, {}, clip("the running image cannot be verified: " + why)};
            return;
        }
    }
    if (running_entry == nullptr) {
        findings["binary_modified|" + running_path_ + "|running"] = {"binary_modified", running_path_, {}, running_sha256_,
                                                                       clip("the running binary " + running_path_ + " is not listed in the build manifest")};
        return;
    }
    if (running_sha256_ != running_entry->sha256) {
        findings["binary_modified|" + running_path_ + "|running"] = {"binary_modified", running_path_, running_entry->sha256, running_sha256_,
                                                                       clip("the running image of " + running_path_ + " is not the build in the manifest")};
        return;
    }
    // The image is right. Is the file at its path still that image?
    struct stat on_disk {};
    if (::stat(running_path_.c_str(), &on_disk) == 0 &&
        (static_cast<std::uint64_t>(on_disk.st_dev) != running_dev_ || static_cast<std::uint64_t>(on_disk.st_ino) != running_inode_) &&
        findings.count("binary_modified|" + running_path_) == 0U && findings.count("binary_missing|" + running_path_) == 0U) {
        findings["binary_replaced|" + running_path_] = {"binary_replaced", running_path_, running_entry->sha256, running_entry->sha256,
                                                          clip(running_path_ + " was replaced by another copy of a listed build while the sensor kept running; a restart is pending")};
    }
}

std::vector<integrity_change> integrity_monitor::refresh(const std::int64_t now_unix) {
    std::map<std::string, integrity_finding> findings;
    refresh_manifest(now_unix, findings);
    check_files(now_unix, findings);

    std::vector<integrity_change> changes;
    const auto describe = [&](const std::string& status, const integrity_finding& finding) {
        integrity_change change;
        change.status = status;
        change.finding = finding;
        change.manifest_version = manifest_ ? manifest_->version : std::string{};
        change.key_id = manifest_ ? manifest_->key_id : std::string{};
        change.files_checked = files_checked_;
        return change;
    };
    const bool settle = !first_refresh_;
    std::map<std::string, integrity_finding> next_pending;
    for (const auto& [key, finding] : findings) {
        if (reported_.count(key) != 0U) {
            reported_[key] = finding;
        } else if (!settle || pending_.count(key) != 0U) {
            reported_[key] = finding;
            changes.push_back(describe("violated", finding));
        } else {
            next_pending[key] = finding;
        }
    }
    std::vector<integrity_change> restored;
    for (auto entry = reported_.begin(); entry != reported_.end();) {
        if (findings.count(entry->first) == 0U) {
            // The record says what is true now, not what was wrong: the violating digest and text are in the earlier record.
            integrity_finding settled = entry->second;
            if (settled.technique == "manifest_missing" || settled.technique == "manifest_invalid") {
                settled.detail = "the build manifest " + settled.target + " is present and verifies again";
            } else if (settled.technique == "binary_replaced") {
                settled.detail = clip(settled.target + " is the file the sensor is running from again");
            } else {
                settled.observed_sha256 = settled.expected_sha256;
                settled.detail = clip(settled.target + " is as the build manifest lists it again");
            }
            restored.push_back(describe("restored", settled));
            entry = reported_.erase(entry);
        } else {
            ++entry;
        }
    }
    changes.insert(changes.end(), restored.begin(), restored.end());
    for (auto& change : changes) change.files_in_violation = reported_.size();
    pending_ = std::move(next_pending);
    first_refresh_ = false;
    return changes;
}

integrity_monitor::status integrity_monitor::health() const {
    if (!reported_.empty()) {
        const auto& first = reported_.begin()->second;
        return {"degraded", std::to_string(reported_.size()) + " integrity finding(s); first: " + first.technique + ": " + first.detail};
    }
    if (!manifest_) return {"active", "no build manifest has been verified yet"};
    return {"active", std::to_string(files_checked_) + " file(s) match build manifest version " + manifest_->version + " signed with key " + manifest_->key_id};
}

std::set<std::string> integrity_monitor::watched_paths() const {
    std::set<std::string> paths;
    paths.insert(options_.manifest_path.string());
    if (manifest_) {
        for (const auto& entry : manifest_->entries) paths.insert(entry.path);
    }
    return paths;
}

}  // namespace panopticon::linux_agent::sensor
