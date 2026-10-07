#include "panopticon/linux_agent/sensor/container_tracker.hpp"

#include <optional>
#include <utility>

namespace panopticon::linux_agent::sensor {

namespace {

// The container a process belongs to, when its cgroup names one with a full id (a Kubernetes pod
// slice alone is not a container).
std::optional<container_identity> identify(const entity_ptr& process) {
    if (!process || process->entity_id.empty() || process->info.cgroup.empty()) return std::nullopt;
    auto identity = parse_container_cgroup(process->info.cgroup);
    if (!identity || identity->id.empty()) return std::nullopt;
    return identity;
}

}  // namespace

container_tracker::container_tracker(const std::size_t maximum_containers, const std::size_t maximum_processes)
    : maximum_containers_(maximum_containers), maximum_processes_(maximum_processes) {}

void container_tracker::join(const entity_ptr& process, const container_identity& identity, const bool start_observed,
                             const std::uint64_t time_unix_ns, std::vector<container_lifecycle>& changes) {
    if (member_of_.size() >= maximum_processes_) {
        ++untracked_;
        return;
    }
    auto found = containers_.find(identity.id);
    if (found == containers_.end()) {
        if (containers_.size() >= maximum_containers_) {
            ++untracked_;
            return;
        }
        tracked fresh;
        fresh.identity = identity;
        fresh.cgroup = process->info.cgroup;
        fresh.first_seen_unix_ns = time_unix_ns;
        fresh.start_observed = start_observed;
        found = containers_.emplace(identity.id, std::move(fresh)).first;
        if (start_observed) {
            container_lifecycle started;
            started.started = true;
            started.identity = identity;
            started.cgroup = process->info.cgroup;
            started.time_unix_ns = time_unix_ns;
            started.process = process;
            changes.push_back(std::move(started));
        }
    }
    found->second.members.insert(process->entity_id);
    if (found->second.members.size() > found->second.peak) found->second.peak = static_cast<std::uint32_t>(found->second.members.size());
    member_of_[process->entity_id] = identity.id;
}

void container_tracker::leave(const entity_ptr& process, const std::uint64_t time_unix_ns, std::vector<container_lifecycle>& changes) {
    const auto member = member_of_.find(process->entity_id);
    if (member == member_of_.end()) return;
    const std::string id = member->second;
    member_of_.erase(member);
    const auto found = containers_.find(id);
    if (found == containers_.end()) return;
    found->second.members.erase(process->entity_id);
    if (!found->second.members.empty()) return;
    container_lifecycle stopped;
    stopped.started = false;
    stopped.identity = found->second.identity;
    stopped.cgroup = found->second.cgroup;
    stopped.time_unix_ns = time_unix_ns;
    stopped.start_observed = found->second.start_observed;
    if (found->second.start_observed && time_unix_ns > found->second.first_seen_unix_ns) {
        stopped.lifetime_ns = time_unix_ns - found->second.first_seen_unix_ns;
    }
    stopped.peak_processes = found->second.peak;
    stopped.process = process;
    containers_.erase(found);
    changes.push_back(std::move(stopped));
}

void container_tracker::seed(const std::vector<entity_ptr>& live) {
    std::vector<container_lifecycle> ignored;
    for (const auto& process : live) {
        if (const auto identity = identify(process)) join(process, *identity, false, process->first_seen_unix_ns, ignored);
    }
}

std::vector<container_lifecycle> container_tracker::observe(const std::vector<process_event>& events) {
    std::vector<container_lifecycle> changes;
    for (const auto& event : events) {
        const auto& process = event.process;
        if (!process || process->entity_id.empty()) continue;
        if (event.type == "process.exit") {
            leave(process, event.time_unix_ns, changes);
            continue;
        }
        if (event.type != "process.fork" && event.type != "process.exec" && event.type != "process.discovered") continue;
        const auto identity = identify(process);
        if (!identity) continue;
        if (const auto known = member_of_.find(process->entity_id); known != member_of_.end()) {
            if (known->second == identity->id) continue;
            leave(process, event.time_unix_ns, changes);  // moved to another container's cgroup
        }
        // A process the sensor only found later (a missed fork) says nothing about when its
        // container started.
        join(process, *identity, event.type != "process.discovered", event.time_unix_ns, changes);
    }
    return changes;
}

}  // namespace panopticon::linux_agent::sensor
