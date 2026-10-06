#include "panopticon/linux_agent/sensor/command_auth.hpp"

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <sstream>

#include <sys/stat.h>

namespace panopticon::linux_agent::sensor {
namespace {

void field(std::string& out, const std::string_view name, const std::string_view value) {
    out.append(name);
    out.push_back(':');
    out.append(std::to_string(value.size()));
    out.push_back(':');
    out.append(value);
    out.push_back('\n');
}

std::string trimmed(const std::string_view text) {
    std::size_t begin = 0U;
    std::size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r')) ++begin;
    while (end > begin && (text[end - 1U] == ' ' || text[end - 1U] == '\t' || text[end - 1U] == '\r')) --end;
    return std::string{text.substr(begin, end - begin)};
}

// A key is pinned only if it is a point on the P-256 curve; verify_raw reports an error for anything else.
bool usable_point(const ec_public_key_point& point) {
    const ec_raw_signature zero{};
    return succeeded(verify_raw(point, {}, zero));
}

}  // namespace

std::string command_signing_input(const endpoint_command& command) {
    std::string out = "panopticon-command-auth/1\n";
    field(out, "schema_version", command.boot_id.empty() ? "1" : "2");
    field(out, "command_id", command.command_id);
    field(out, "correlation_id", command.correlation_id);
    field(out, "agent_id", command.agent_id);
    field(out, "host_id", command.host_id);
    field(out, "action", to_string(command.action));
    field(out, "created_at", std::to_string(command.created_unix));
    field(out, "expires_at", std::to_string(command.expires_unix));
    field(out, "pid", std::to_string(command.pid));
    field(out, "start_time_ticks", std::to_string(command.start_ticks));
    field(out, "boot_id", command.boot_id);
    field(out, "path", command.path);
    return out;
}

std::string signing_key_id(const ec_public_key_point& point) {
    return sha256_hex(std::string_view{reinterpret_cast<const char*>(point.data()), point.size()}).substr(0U, 16U);
}

std::optional<std::vector<std::uint8_t>> decode_base64(const std::string_view text) {
    if (text.empty() || text.size() % 4U != 0U) return std::nullopt;
    const auto value = [](const char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(text.size() / 4U * 3U);
    for (std::size_t index = 0U; index < text.size(); index += 4U) {
        const bool last = index + 4U == text.size();
        int quad[4];
        int padding = 0;
        for (std::size_t offset = 0U; offset < 4U; ++offset) {
            const char c = text[index + offset];
            if (c == '=') {
                // Padding only in the last quad, only at its end, and the bits it stands for must be zero.
                if (!last || offset < 2U) return std::nullopt;
                ++padding;
                quad[offset] = 0;
                continue;
            }
            if (padding != 0) return std::nullopt;
            quad[offset] = value(c);
            if (quad[offset] < 0) return std::nullopt;
        }
        if (padding == 1 && (quad[2] & 0x03) != 0) return std::nullopt;
        if (padding == 2 && (quad[1] & 0x0F) != 0) return std::nullopt;
        const unsigned group = (static_cast<unsigned>(quad[0]) << 18U) | (static_cast<unsigned>(quad[1]) << 12U) |
                               (static_cast<unsigned>(quad[2]) << 6U) | static_cast<unsigned>(quad[3]);
        out.push_back(static_cast<std::uint8_t>(group >> 16U));
        if (padding < 2) out.push_back(static_cast<std::uint8_t>(group >> 8U));
        if (padding < 1) out.push_back(static_cast<std::uint8_t>(group));
    }
    return out;
}

const char* to_string(const authorization_verdict verdict) noexcept {
    switch (verdict) {
        case authorization_verdict::valid: return "valid";
        case authorization_verdict::missing: return "missing";
        case authorization_verdict::unknown_key: return "unknown_key";
        case authorization_verdict::bad_signature: return "bad_signature";
        case authorization_verdict::unsigned_window: return "unsigned_window";
    }
    return "missing";
}

result<std::map<std::string, ec_public_key_point>> command_keyring::read_file(const std::filesystem::path& path) {
    std::ifstream input{path};
    if (!input) return error{error_code::io_failure, "cannot read the command signing key file " + path.string()};
    std::map<std::string, ec_public_key_point> keys;
    std::string line;
    std::size_t number = 0U;
    while (std::getline(input, line)) {
        ++number;
        const auto text = trimmed(line);
        if (text.empty() || text.front() == '#') continue;
        const auto split = text.find_first_of(" \t");
        const auto decoded = decode_base64(split == std::string::npos ? std::string_view{text} : std::string_view{text}.substr(0U, split));
        const auto where = path.string() + " line " + std::to_string(number);
        if (!decoded || decoded->size() != 65U) return error{error_code::invalid_input, where + ": not a base64 65-byte P-256 point"};
        ec_public_key_point point{};
        std::memcpy(point.data(), decoded->data(), point.size());
        if (!usable_point(point)) return error{error_code::invalid_input, where + ": not a valid P-256 public key"};
        keys.emplace(signing_key_id(point), point);
    }
    return keys;
}

result<std::unique_ptr<command_keyring>> command_keyring::load(const std::filesystem::path& path) {
    auto keys = read_file(path);
    if (!succeeded(keys)) return std::get<error>(keys);
    std::unique_ptr<command_keyring> ring{new command_keyring{}};
    ring->path_ = path;
    ring->keys_ = std::move(std::get<std::map<std::string, ec_public_key_point>>(keys));
    struct stat info {};
    if (::stat(path.c_str(), &info) == 0) {
        ring->file_size_ = static_cast<std::int64_t>(info.st_size);
        ring->file_mtime_ns_ = static_cast<std::int64_t>(info.st_mtim.tv_sec) * 1'000'000'000LL + info.st_mtim.tv_nsec;
    }
    return ring;
}

std::unique_ptr<command_keyring> command_keyring::from_points(const std::vector<ec_public_key_point>& points) {
    std::unique_ptr<command_keyring> ring{new command_keyring{}};
    for (const auto& point : points) {
        if (usable_point(point)) ring->keys_.emplace(signing_key_id(point), point);
    }
    return ring;
}

authorization_verdict command_keyring::check(const endpoint_command& command) const {
    if (!command.authorization) return authorization_verdict::missing;
    const auto& authorization = *command.authorization;
    if (authorization.algorithm != "ES256") return authorization_verdict::bad_signature;
    ec_public_key_point point{};
    {
        const std::lock_guard lock{mutex_};
        const auto found = keys_.find(authorization.key_id);
        if (found == keys_.end()) return authorization_verdict::unknown_key;
        point = found->second;
    }
    // The validity window must be inside the signature, or a signed command could be given a new lifetime.
    if (command.created_unix <= 0) return authorization_verdict::unsigned_window;
    const auto input = command_signing_input(command);
    const auto verified = verify_raw(point, std::vector<std::uint8_t>(input.begin(), input.end()), authorization.signature);
    return succeeded(verified) && std::get<bool>(verified) ? authorization_verdict::valid : authorization_verdict::bad_signature;
}

void command_keyring::refresh() {
    if (path_.empty()) return;
    struct stat info {};
    if (::stat(path_.c_str(), &info) != 0) {
        const std::lock_guard lock{mutex_};
        last_error_ = "the command signing key file is not readable; the previous keys stay in force";
        return;
    }
    const auto size = static_cast<std::int64_t>(info.st_size);
    const auto mtime = static_cast<std::int64_t>(info.st_mtim.tv_sec) * 1'000'000'000LL + info.st_mtim.tv_nsec;
    {
        const std::lock_guard lock{mutex_};
        if (size == file_size_ && mtime == file_mtime_ns_) return;
    }
    auto keys = read_file(path_);
    const std::lock_guard lock{mutex_};
    file_size_ = size;
    file_mtime_ns_ = mtime;
    if (!succeeded(keys)) {
        last_error_ = std::get<error>(keys).message + "; the previous keys stay in force";
        return;
    }
    keys_ = std::move(std::get<std::map<std::string, ec_public_key_point>>(keys));
    last_error_.clear();
}

std::size_t command_keyring::size() const {
    const std::lock_guard lock{mutex_};
    return keys_.size();
}

std::string command_keyring::last_error() const {
    const std::lock_guard lock{mutex_};
    return last_error_;
}

std::vector<std::string> command_keyring::key_ids() const {
    const std::lock_guard lock{mutex_};
    std::vector<std::string> ids;
    for (const auto& [id, point] : keys_) ids.push_back(id);
    return ids;
}

}  // namespace panopticon::linux_agent::sensor
