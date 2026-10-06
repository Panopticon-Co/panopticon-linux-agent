#include "panopticon/linux_agent/sensor/fim.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <set>

namespace panopticon::linux_agent::sensor {

namespace fs = std::filesystem;

namespace {

constexpr std::string_view baseline_header{"PANOPTICON-FIM 1 "};

std::string hex_encode(const std::string_view text) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() * 2U);
    for (const unsigned char byte : text) {
        out.push_back(digits[byte >> 4U]);
        out.push_back(digits[byte & 15U]);
    }
    return out;
}

std::optional<std::string> hex_decode(const std::string_view text) {
    if (text.size() % 2U != 0U) return std::nullopt;
    const auto nibble = [](const char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::string out;
    out.reserve(text.size() / 2U);
    for (std::size_t index = 0U; index < text.size(); index += 2U) {
        const auto high = nibble(text[index]);
        const auto low = nibble(text[index + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        out.push_back(static_cast<char>((high << 4) | low));
    }
    return out;
}

template <typename number_type>
bool parse_number(const std::string_view text, number_type& out) {
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), out);
    return error == std::errc{} && end == text.data() + text.size();
}

bool valid_category(const std::string_view text) {
    return !text.empty() && text.size() <= 32U &&
           std::all_of(text.begin(), text.end(), [](const char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
}

bool valid_hash_status(const std::string_view text) {
    return text == "computed" || text == "too_large" || text == "unreadable" || text == "not_applicable";
}

bool has_prefix_dir(const std::string_view path, const std::string_view directory) {
    return path.size() > directory.size() + 1U && path.compare(0U, directory.size(), directory) == 0 && path[directory.size()] == '/';
}

}  // namespace

std::vector<std::string> fim_changed_fields(const persistence_item& before, const persistence_item& after) {
    std::vector<std::string> fields;
    if (before.kind != after.kind) fields.emplace_back("kind");
    bool content = before.hash_status != after.hash_status || before.sha256 != after.sha256;
    if (!content && before.hash_status == "too_large") content = before.size != after.size || before.mtime_ns != after.mtime_ns;
    if (content) fields.emplace_back("content");
    if (before.mode != after.mode) fields.emplace_back("mode");
    if (before.uid != after.uid) fields.emplace_back("uid");
    if (before.gid != after.gid) fields.emplace_back("gid");
    if (before.target != after.target) fields.emplace_back("target");
    return fields;
}

std::optional<fim_change> fim_compare(const std::string& path, const std::optional<persistence_item>& before,
                                      const std::optional<persistence_item>& after) {
    if (!before && !after) return std::nullopt;
    fim_change change;
    change.path = path;
    change.before = before;
    change.after = after;
    if (!before) {
        change.change = "added";
        change.category = after->category;
    } else if (!after) {
        change.change = "removed";
        change.category = before->category;
    } else {
        change.fields = fim_changed_fields(*before, *after);
        if (change.fields.empty()) return std::nullopt;
        change.change = "modified";
        change.category = after->category;
    }
    return change;
}

std::vector<fim_change> fim_diff(const fim_baseline& before, const fim_baseline& after) {
    std::vector<fim_change> changes;
    auto left = before.begin();
    auto right = after.begin();
    while (left != before.end() || right != after.end()) {
        std::optional<fim_change> change;
        if (right == after.end() || (left != before.end() && left->first < right->first)) {
            change = fim_compare(left->first, left->second, std::nullopt);
            ++left;
        } else if (left == before.end() || right->first < left->first) {
            change = fim_compare(right->first, std::nullopt, right->second);
            ++right;
        } else {
            change = fim_compare(left->first, left->second, right->second);
            ++left;
            ++right;
        }
        if (change) changes.push_back(std::move(*change));
    }
    return changes;
}

std::string fim_serialise(const fim_baseline& baseline) {
    std::string out{baseline_header};
    out += std::to_string(baseline.size());
    out += '\n';
    for (const auto& [path, item] : baseline) {
        out += hex_encode(path);
        out += ' ' + item.category + ' ' + item.kind + ' ' + std::to_string(item.uid) + ' ' + std::to_string(item.gid) + ' ' +
               std::to_string(item.mode) + ' ' + std::to_string(item.size) + ' ' + std::to_string(item.mtime_ns) + ' ' + item.hash_status +
               ' ' + (item.sha256.empty() ? std::string{"-"} : item.sha256) + ' ' +
               (item.target.empty() ? std::string{"-"} : hex_encode(item.target)) + '\n';
    }
    return out;
}

std::optional<fim_baseline> fim_parse(const std::string_view text, const std::size_t maximum_items) {
    if (text.compare(0U, baseline_header.size(), baseline_header) != 0) return std::nullopt;
    auto cursor = baseline_header.size();
    const auto header_end = text.find('\n', cursor);
    if (header_end == std::string_view::npos) return std::nullopt;
    std::size_t declared = 0U;
    if (!parse_number(text.substr(cursor, header_end - cursor), declared) || declared > maximum_items) return std::nullopt;
    cursor = header_end + 1U;
    fim_baseline baseline;
    while (cursor < text.size()) {
        const auto line_end = text.find('\n', cursor);
        if (line_end == std::string_view::npos) return std::nullopt;  // a truncated final line
        const auto line = text.substr(cursor, line_end - cursor);
        cursor = line_end + 1U;
        std::vector<std::string_view> fields;
        for (std::size_t start = 0U;;) {
            const auto space = line.find(' ', start);
            if (space == std::string_view::npos) {
                fields.push_back(line.substr(start));
                break;
            }
            fields.push_back(line.substr(start, space - start));
            start = space + 1U;
        }
        if (fields.size() != 11U) return std::nullopt;
        persistence_item item;
        const auto path = hex_decode(fields[0]);
        if (!path || path->empty() || path->front() != '/' || !valid_category(fields[1]) || !valid_hash_status(fields[8])) return std::nullopt;
        if (!parse_number(fields[3], item.uid) || !parse_number(fields[4], item.gid) || !parse_number(fields[5], item.mode) ||
            !parse_number(fields[6], item.size) || !parse_number(fields[7], item.mtime_ns)) {
            return std::nullopt;
        }
        if (fields[2] != "file" && fields[2] != "symlink" && fields[2] != "other") return std::nullopt;
        if (fields[9] != "-") {
            if (fields[9].size() != 64U || !hex_decode(fields[9])) return std::nullopt;
            item.sha256 = std::string{fields[9]};
        }
        if (fields[10] != "-") {
            const auto target = hex_decode(fields[10]);
            if (!target) return std::nullopt;
            item.target = *target;
        }
        item.path = *path;
        item.category = std::string{fields[1]};
        item.kind = std::string{fields[2]};
        item.hash_status = std::string{fields[8]};
        if (!baseline.emplace(*path, std::move(item)).second) return std::nullopt;  // duplicate path
        if (baseline.size() > declared) return std::nullopt;
    }
    if (baseline.size() != declared) return std::nullopt;
    return baseline;
}

fim_monitor::fim_monitor(fim_options options) : options_{std::move(options)}, catalog_{options_.persistence} {}

void fim_monitor::store() {
    if (options_.baseline_path.empty()) return;
    const auto data = fim_serialise(baseline_);
    const auto temporary = fs::path{options_.baseline_path.string() + ".tmp"};
    std::error_code error;
    fs::create_directories(options_.baseline_path.parent_path(), error);
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        storage_healthy_ = false;
        return;
    }
    bool written = true;
    for (std::size_t offset = 0U; offset < data.size() && written;) {
        const auto count = ::write(fd, data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) written = false;
        else offset += static_cast<std::size_t>(count);
    }
    written = written && ::fsync(fd) == 0;
    ::close(fd);
    if (!written || ::rename(temporary.c_str(), options_.baseline_path.c_str()) != 0) {
        ::unlink(temporary.c_str());
        storage_healthy_ = false;
        return;
    }
    if (const int directory = ::open(options_.baseline_path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); directory >= 0) {
        (void)::fsync(directory);
        ::close(directory);
    }
    storage_healthy_ = true;
}

namespace {

// Reads the stored baseline. nullopt with `reason` empty means "none yet"; a non-empty reason
// means a file is present but unusable.
std::optional<fim_baseline> load_baseline(const fs::path& path, const std::size_t maximum_bytes, const std::size_t maximum_items,
                                          std::string& reason) {
    reason.clear();
    if (path.empty()) return std::nullopt;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT) reason = "unreadable";
        return std::nullopt;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || static_cast<std::uint64_t>(info.st_size) > maximum_bytes) {
        ::close(fd);
        reason = "unusable_file";
        return std::nullopt;
    }
    std::string text;
    char buffer[65536];
    for (;;) {
        const auto count = ::read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        text.append(buffer, static_cast<std::size_t>(count));
        if (text.size() > maximum_bytes) break;
    }
    ::close(fd);
    auto parsed = fim_parse(text, maximum_items);
    if (!parsed) reason = "corrupt";
    return parsed;
}

}  // namespace

fim_start_result fim_monitor::start() {
    fim_start_result result;
    std::string reason;
    auto stored = load_baseline(options_.baseline_path, options_.maximum_baseline_bytes, options_.persistence.maximum_items, reason);
    if (stored) {
        baseline_ = std::move(*stored);
        result.state = "loaded";
        result.changes = rescan();
    } else {
        result.state = reason.empty() ? "created" : "reset";
        result.reset_reason = reason;
        auto scan = catalog_.scan();
        baseline_.clear();
        for (auto& item : scan.items) baseline_.emplace(item.path, std::move(item));
        store();
    }
    result.items = baseline_.size();
    return result;
}

std::vector<fim_change> fim_monitor::rescan() {
    auto scan = catalog_.scan();
    fim_baseline current;
    for (auto& item : scan.items) current.emplace(item.path, std::move(item));
    // A scan that stopped early, or could not enter a directory, says nothing about the items it
    // did not reach; they keep their baseline entry instead of being reported as removed.
    for (const auto& [path, item] : baseline_) {
        if (current.count(path) != 0U) continue;
        bool unobserved = scan.truncated;
        for (const auto& hole : scan.unavailable) {
            if (!hole.field.empty() && hole.field.front() == '/' && has_prefix_dir(path, hole.field)) unobserved = true;
        }
        if (unobserved) current.emplace(path, item);
    }
    auto changes = fim_diff(baseline_, current);
    if (!changes.empty()) {
        baseline_ = std::move(current);
        store();
    }
    return changes;
}

bool fim_monitor::note(const std::string_view path, const std::optional<std::string>& old_path, const std::uint32_t pid,
                       const std::uint64_t time_unix_ns, const std::uint64_t now_ns) {
    bool queued = false;
    const auto queue = [&](const std::string_view candidate) {
        if (catalog_.classify(candidate).empty()) return;
        const std::string key{candidate};
        auto found = dirty_.find(key);
        if (found == dirty_.end()) {
            if (dirty_.size() >= options_.maximum_dirty) {
                ++dropped_dirty_;  // the periodic rescan still finds it
                return;
            }
            found = dirty_.emplace(key, dirty_path{now_ns + options_.debounce_ns, pid, time_unix_ns}).first;
        } else {
            found->second.pid = pid;  // the most recent actor wins; the deadline is not extended
            found->second.time_unix_ns = time_unix_ns;
        }
        queued = true;
    };
    queue(path);
    if (old_path) queue(*old_path);
    return queued;
}

std::vector<fim_change> fim_monitor::take_due(const std::uint64_t now_ns) {
    std::vector<fim_change> changes;
    std::vector<std::pair<std::string, dirty_path>> due;
    for (auto it = dirty_.begin(); it != dirty_.end();) {
        if (it->second.due_ns <= now_ns) {
            due.emplace_back(it->first, it->second);
            it = dirty_.erase(it);
        } else {
            ++it;
        }
    }
    const auto apply = [&](const std::string& path, const dirty_path& source) {
        std::optional<persistence_item> before;
        if (const auto found = baseline_.find(path); found != baseline_.end()) before = found->second;
        const auto after = catalog_.describe(path);
        auto change = fim_compare(path, before, after);
        if (!change) return;
        change->actor_pid = source.pid;
        change->actor_time_unix_ns = source.time_unix_ns;
        if (after) baseline_[path] = *after;
        else baseline_.erase(path);
        changes.push_back(std::move(*change));
    };
    for (const auto& [path, source] : due) {
        apply(path, source);
        // A directory that moved or vanished takes everything below it along; the events for the
        // children are not delivered separately.
        if (!catalog_.describe(path)) {
            std::vector<std::string> below;
            const auto prefix = path + "/";
            for (auto it = baseline_.lower_bound(prefix); it != baseline_.end() && it->first.compare(0U, prefix.size(), prefix) == 0; ++it) {
                below.push_back(it->first);
            }
            for (const auto& child : below) apply(child, source);
        }
    }
    if (!changes.empty()) store();
    return changes;
}

}  // namespace panopticon::linux_agent::sensor
