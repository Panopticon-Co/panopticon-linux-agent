#pragma once

#include "panopticon/linux_agent/sensor/host_state.hpp"

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Turns two consecutive snapshots of one host-state object into a bounded list of changes, so an
// operator learns that a sysctl moved, an account appeared or a package was installed without
// diffing inventories. The first snapshot of an object is only remembered: a baseline is not a
// change. Items are identified by object-specific key fields; the posture object is flattened to
// one entry per setting.

struct state_change_entry {
    std::string key;                    // item identity, or the setting path for posture
    std::string kind;                   // added, removed, modified
    std::optional<std::string> before;  // serialised JSON
    std::optional<std::string> after;
};

struct state_change {
    std::string object;                 // the snapshot object that changed
    std::string type;                   // record type, e.g. "posture.changed"
    std::size_t total{};                // all differences found, entries may be fewer
    std::vector<state_change_entry> entries;
    bool truncated{false};
};

// Record type emitted for an object's changes; empty when the object is not diffed.
[[nodiscard]] std::string_view change_type_for(std::string_view object);

class state_differ {
public:
    explicit state_differ(std::size_t maximum_entries = 256U) : maximum_entries_{maximum_entries} {}

    // Returns the changes since the previous call for this object, or nullopt when there are none
    // (including the first call). A snapshot that could not be collected completely (`truncated`,
    // or anything unavailable) never produces removals: a missing item is not a removed item.
    [[nodiscard]] std::optional<state_change> observe(const state_snapshot& snapshot);

private:
    std::size_t maximum_entries_;
    std::map<std::string, std::map<std::string, std::string>, std::less<>> previous_;
};

}  // namespace panopticon::linux_agent::sensor
