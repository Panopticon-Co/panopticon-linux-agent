#pragma once

#include "panopticon/linux_agent/sensor/persistence.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

// File-integrity monitoring over the persistence catalog (slice S5.2, catalog §4.2 `fim.*`).
//
// A baseline is the last known state of every persistence item. A change is the difference
// between the baseline and a fresh description of the same path. The baseline survives restarts
// (a change made while the sensor was down is still reported at the next start) and is replaced
// by a visible reset when the stored file is missing, damaged or from another format version.
// Two things feed it: a periodic full rescan, and file events that name a persistence path (the
// path is re-described after a short debounce so one editor save yields one change, and the
// acting process of the file event is attached).

using fim_baseline = std::map<std::string, persistence_item>;

struct fim_change {
    std::string path;
    std::string category;
    std::string change;                 // added, removed, modified
    std::vector<std::string> fields;    // modified only: kind, content, mode, uid, gid, target
    std::optional<persistence_item> before;
    std::optional<persistence_item> after;
    std::uint32_t actor_pid{};          // 0: unknown (found by a scan, not by an event)
    std::uint64_t actor_time_unix_ns{}; // time of the file event that named the path
};

// Names of the compared fields that differ. Files too large to hash are compared by size and
// mtime; a hashed file is compared by content only, so a bare `touch` is not a change.
[[nodiscard]] std::vector<std::string> fim_changed_fields(const persistence_item& before, const persistence_item& after);

// The change between two descriptions of one path, or nullopt when they are equivalent.
[[nodiscard]] std::optional<fim_change> fim_compare(const std::string& path, const std::optional<persistence_item>& before,
                                                    const std::optional<persistence_item>& after);

// Full diff of two baselines, ordered by path.
[[nodiscard]] std::vector<fim_change> fim_diff(const fim_baseline& before, const fim_baseline& after);

// Persisted form. The parser rejects anything that is not exactly what serialise wrote (header,
// field counts, hex fields, the declared item count) rather than accepting a partial baseline.
[[nodiscard]] std::string fim_serialise(const fim_baseline& baseline);
[[nodiscard]] std::optional<fim_baseline> fim_parse(std::string_view text, std::size_t maximum_items);

struct fim_options {
    persistence_options persistence;
    std::filesystem::path baseline_path;  // empty: the baseline is kept in memory only
    std::uint64_t debounce_ns{500ULL * 1000000ULL};
    std::size_t maximum_dirty{4096U};
    std::size_t maximum_baseline_bytes{64U * 1024U * 1024U};
};

struct fim_start_result {
    std::string state;                // created, loaded, reset
    std::string reset_reason;         // set when state == reset
    std::size_t items{};
    std::vector<fim_change> changes;  // loaded: what changed while the sensor was not running
};

class fim_monitor {
public:
    explicit fim_monitor(fim_options options);

    // Loads the stored baseline (if any), scans, diffs and stores the result.
    [[nodiscard]] fim_start_result start();
    // Full rescan; returns what differs from the baseline and adopts the new state.
    [[nodiscard]] std::vector<fim_change> rescan();
    // Records that a file event named `path` (and `old_path` for a rename). Paths that are not
    // persistence locations are ignored. Returns true when something was queued.
    bool note(std::string_view path, const std::optional<std::string>& old_path, std::uint32_t pid, std::uint64_t time_unix_ns,
              std::uint64_t now_ns);
    // Re-describes the queued paths whose debounce has passed.
    [[nodiscard]] std::vector<fim_change> take_due(std::uint64_t now_ns);

    [[nodiscard]] std::size_t item_count() const noexcept { return baseline_.size(); }
    [[nodiscard]] std::size_t pending() const noexcept { return dirty_.size(); }
    [[nodiscard]] const fim_baseline& baseline() const noexcept { return baseline_; }
    // False after a failed store; the monitor keeps running from memory.
    [[nodiscard]] bool storage_healthy() const noexcept { return storage_healthy_; }
    [[nodiscard]] std::uint64_t dropped_dirty() const noexcept { return dropped_dirty_; }

private:
    struct dirty_path {
        std::uint64_t due_ns{};
        std::uint32_t pid{};
        std::uint64_t time_unix_ns{};
    };

    void store();

    fim_options options_;
    persistence_catalog catalog_;
    fim_baseline baseline_;
    std::map<std::string, dirty_path> dirty_;
    bool storage_healthy_{true};
    std::uint64_t dropped_dirty_{};
};

}  // namespace panopticon::linux_agent::sensor
