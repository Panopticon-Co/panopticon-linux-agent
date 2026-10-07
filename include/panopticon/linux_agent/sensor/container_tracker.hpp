#pragma once

#include "panopticon/linux_agent/sensor/container_identity.hpp"
#include "panopticon/linux_agent/sensor/entity_graph.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace panopticon::linux_agent::sensor {

// A container the sensor saw start or stop, derived from the processes in its cgroup. There is no
// runtime event behind it: the first process seen in a new container cgroup is the start and the
// exit of the last one is the stop (matrix M2).
struct container_lifecycle {
    bool started{true};  // false: the container stopped
    container_identity identity;
    std::string cgroup;  // the cgroup of the process that revealed the container, as the kernel reported it
    std::uint64_t time_unix_ns{};
    // stopped only: false when the container was already running when the sensor first saw it, so
    // the lifetime is unknown rather than short.
    bool start_observed{true};
    std::uint64_t lifetime_ns{};      // stopped and start_observed only
    std::uint32_t peak_processes{};   // stopped only: most processes seen in the container at once
    entity_ptr process;               // started: the first process seen; stopped: the last one to exit
};

// Follows which container each live process belongs to. It never reads the system: it is fed the
// same process events the pipeline writes, so what it reports is consistent with them. Bounded:
// containers or processes past the limits are counted in `untracked()` and not followed.
class container_tracker {
public:
    explicit container_tracker(std::size_t maximum_containers = 4096U, std::size_t maximum_processes = 262144U);

    // Processes that existed before the sensor began: followed, but starting is not reported.
    void seed(const std::vector<entity_ptr>& live);
    // Process events in order; returns the lifecycle changes they cause.
    [[nodiscard]] std::vector<container_lifecycle> observe(const std::vector<process_event>& events);

    [[nodiscard]] std::size_t containers() const noexcept { return containers_.size(); }
    [[nodiscard]] std::size_t processes() const noexcept { return member_of_.size(); }
    [[nodiscard]] std::uint64_t untracked() const noexcept { return untracked_; }

private:
    struct tracked {
        container_identity identity;
        std::string cgroup;
        std::uint64_t first_seen_unix_ns{};
        bool start_observed{true};
        std::unordered_set<std::string> members;  // entity ids of live processes
        std::uint32_t peak{};
    };

    void join(const entity_ptr& process, const container_identity& identity, bool start_observed, std::uint64_t time_unix_ns,
              std::vector<container_lifecycle>& changes);
    void leave(const entity_ptr& process, std::uint64_t time_unix_ns, std::vector<container_lifecycle>& changes);

    std::size_t maximum_containers_;
    std::size_t maximum_processes_;
    std::unordered_map<std::string, tracked> containers_;      // by container id
    std::unordered_map<std::string, std::string> member_of_;   // process entity id -> container id
    std::uint64_t untracked_{};
};

}  // namespace panopticon::linux_agent::sensor
