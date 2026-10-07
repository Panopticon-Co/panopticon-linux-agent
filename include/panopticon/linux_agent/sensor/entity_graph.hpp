#pragma once

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/hash_service.hpp"
#include "panopticon/linux_agent/sensor/process_info.hpp"
#include "panopticon/linux_agent/sensor/records.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace panopticon::linux_agent::sensor {

// One process instance (ADR 007). Snapshots are immutable once published in an event; the
// graph replaces the shared pointer instead of mutating, so events never observe later changes.
struct process_entity {
    std::string entity_id;         // empty only when the identity could not be determined
    std::string parent_entity_id;  // empty when the parent is unknown
    std::uint32_t exec_gen{0};
    confidence identity{confidence::observed};
    confidence attributes{confidence::reconstructed};  // how `info` was obtained
    process_info info;
    std::uint64_t first_seen_unix_ns{};
    std::optional<std::uint64_t> exited_unix_ns;
};
using entity_ptr = std::shared_ptr<const process_entity>;

struct ancestor_ref {
    std::string entity_id;
    std::uint32_t pid{};
    std::string name;
    std::string executable;
};

// One namespace a task moved out of (process.ns_change).
struct namespace_move {
    std::string name;
    std::uint64_t from{};
    std::uint64_t to{};
};

struct namespace_change_body {
    bool whole_process{true};  // false: only one thread moved; the process entity keeps its namespaces
    std::uint32_t thread_id{};
    std::vector<namespace_move> moves;
};

struct signal_details {
    std::uint32_t number{};
    std::int32_t code{};
    std::string result;
    bool target_is_sensor{false};
};

struct process_event {
    std::string type;  // catalog §4: process.fork/exec/exit/discovered/cred_change/inject/rename
    std::uint64_t time_unix_ns{};
    provenance source;
    entity_ptr process;  // subject (for process.inject: the actor)
    entity_ptr parent;
    entity_ptr target;   // process.inject: the traced process
    std::vector<ancestor_ref> ancestry;  // nearest first, excludes `process` itself
    std::optional<exit_details> exit;
    std::optional<std::string> previous_executable;  // process.exec
    std::optional<std::string> previous_name;        // process.rename
    std::optional<process_credentials> creds_before; // process.cred_change
    std::optional<std::string> technique;            // process.inject
    std::optional<signal_details> signal;            // process.signal (process = sender, target = receiver)
    std::optional<namespace_change_body> ns_change;  // process.ns_change
    std::vector<unavailable_field> unavailable;      // event-level, in addition to process ones
    // Filled in by the pipeline (not the graph) for exec and discovery events: the hash of the
    // executed image when it was already known, or status "pending" when it is being computed.
    std::optional<file_hash> executable_hash;
};

struct entity_graph_options {
    std::string host_id;
    std::string boot_id;
    std::filesystem::path proc_root{"/proc"};
    procfs_limits limits;
    std::uint64_t exit_grace_ns{30'000'000'000ULL};
    std::size_t maximum_entities{65536};
    std::size_t maximum_ancestry{8};
};

struct entity_graph_metrics {
    std::uint64_t entities{};
    std::uint64_t forks{};
    std::uint64_t execs{};
    std::uint64_t exits{};
    std::uint64_t threads_ignored{};
    std::uint64_t discovered{};
    std::uint64_t reconciled_exits{};
    std::uint64_t pid_reuse{};
    std::uint64_t inferred_identities{};
    std::uint64_t evicted{};
};

[[nodiscard]] std::string compute_entity_id(std::string_view host_id, std::string_view boot_id, std::uint32_t tgid,
                                            std::uint64_t start_ticks);

class entity_graph {
public:
    entity_graph(entity_graph_options options, const clock_domain& clock);

    // Applies one provider record; returns the canonical events it produces (possibly none,
    // e.g. thread creation).
    [[nodiscard]] std::vector<process_event> apply(const raw_record& record);

    // Scans procfs: unknown live processes produce process.discovered (reconstructed); tracked
    // processes that vanished without an exit produce process.exit (inferred). The first call
    // builds the initial graph; pass `emit_discovered=false` to seed silently.
    [[nodiscard]] std::vector<process_event> reconcile(std::uint64_t now_unix_ns, bool emit_discovered = true);

    // Drops exited entities older than the grace window and enforces the entity bound.
    void purge(std::uint64_t now_unix_ns);

    [[nodiscard]] entity_ptr find(std::uint32_t tgid) const;
    [[nodiscard]] std::vector<entity_ptr> live_entities() const;
    [[nodiscard]] const entity_graph_metrics& metrics() const noexcept { return metrics_; }

private:
    entity_ptr load(std::uint32_t tgid, std::uint64_t now_unix_ns, confidence attributes);
    entity_ptr lookup_or_load(std::uint32_t tgid, std::uint64_t now_unix_ns);
    void store(const entity_ptr& entity);
    process_event make_event(std::string type, const raw_record& record, entity_ptr subject) const;
    std::vector<ancestor_ref> ancestry_of(const process_entity& entity) const;

    std::vector<process_event> on_fork(const raw_record& record, const raw_fork& fork);
    std::vector<process_event> on_exec(const raw_record& record, const raw_exec& exec);
    std::vector<process_event> on_exit(const raw_record& record, const raw_exit& exit);
    std::vector<process_event> on_credentials(const raw_record& record, const raw_credential_change& change);
    std::vector<process_event> on_ptrace(const raw_record& record, const raw_ptrace& trace);
    std::vector<process_event> on_signal(const raw_record& record, const raw_signal& signal);
    std::vector<process_event> on_comm(const raw_record& record, const raw_comm_change& change);
    std::vector<process_event> on_namespaces(const raw_record& record, const raw_namespace_change& change);
    std::vector<process_event> on_session(const raw_record& record, const raw_session_change& change);

    entity_graph_options options_;
    const clock_domain& clock_;
    std::unordered_map<std::uint32_t, entity_ptr> by_tgid_;
    std::unordered_map<std::string, entity_ptr> by_entity_id_;  // includes exited, for ancestry
    std::unordered_map<std::uint32_t, std::uint64_t> missing_;  // tgid -> first scan that missed it
    entity_graph_metrics metrics_;
};

}  // namespace panopticon::linux_agent::sensor
