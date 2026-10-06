#include "panopticon/linux_agent/sensor/entity_graph.hpp"

#include "panopticon/linux_agent/event.hpp"

#include <algorithm>
#include <unordered_set>

namespace panopticon::linux_agent::sensor {

const char* to_string(const confidence value) noexcept {
    switch (value) {
    case confidence::observed: return "observed";
    case confidence::reconstructed: return "reconstructed";
    case confidence::inferred: return "inferred";
    case confidence::user_space_reported: return "user_space_reported";
    }
    return "inferred";
}

const char* to_string(const file_operation value) noexcept {
    switch (value) {
    case file_operation::create: return "create";
    case file_operation::modify: return "modify";
    case file_operation::remove: return "delete";
    case file_operation::rename: return "rename";
    case file_operation::attrib: return "attrib";
    case file_operation::open_sensitive: return "open_sensitive";
    }
    return "modify";
}

const char* to_string(const network_operation value) noexcept {
    switch (value) {
    case network_operation::connect: return "connect";
    case network_operation::accept: return "accept";
    case network_operation::listen: return "listen";
    case network_operation::udp_flow: return "udp_flow";
    }
    return "connect";
}

const char* to_string(const auth_kind value) noexcept {
    switch (value) {
    case auth_kind::login_success: return "login_success";
    case auth_kind::login_failure: return "login_failure";
    case auth_kind::privilege_success: return "privilege_success";
    case auth_kind::privilege_failure: return "privilege_failure";
    }
    return "login_failure";
}

const char* to_string(const kernel_event_kind value) noexcept {
    switch (value) {
    case kernel_event_kind::module_load: return "module_load";
    case kernel_event_kind::module_unload: return "module_unload";
    case kernel_event_kind::mount_added: return "mount_added";
    case kernel_event_kind::mount_removed: return "mount_removed";
    case kernel_event_kind::mount_remounted: return "mount_remounted";
    }
    return "module_load";
}

exit_details decode_exit_status(const std::uint32_t status) noexcept {
    exit_details details;
    const auto low = status & 0x7FU;
    if (low == 0U) {
        details.code = static_cast<int>((status >> 8U) & 0xFFU);
    } else if (low != 0x7FU) {  // 0x7F marks a stopped (not exited) task
        details.signal = static_cast<int>(low);
        details.core_dumped = (status & 0x80U) != 0U;
    }
    return details;
}

std::string compute_entity_id(const std::string_view host_id, const std::string_view boot_id, const std::uint32_t tgid,
                              const std::uint64_t start_ticks) {
    std::string input;
    input.reserve(host_id.size() + boot_id.size() + 32U);
    input.append(host_id).append("|").append(boot_id).append("|").append(std::to_string(tgid)).append("|").append(
        std::to_string(start_ticks));
    return sha256_hex(input).substr(0U, 32U);
}

entity_graph::entity_graph(entity_graph_options options, const clock_domain& clock)
    : options_{std::move(options)}, clock_{clock} {}

entity_ptr entity_graph::find(const std::uint32_t tgid) const {
    const auto found = by_tgid_.find(tgid);
    return found == by_tgid_.end() ? nullptr : found->second;
}

std::vector<entity_ptr> entity_graph::live_entities() const {
    std::vector<entity_ptr> live;
    live.reserve(by_tgid_.size());
    for (const auto& [tgid, entity] : by_tgid_) {
        if (!entity->exited_unix_ns.has_value()) live.push_back(entity);
    }
    std::sort(live.begin(), live.end(), [](const entity_ptr& a, const entity_ptr& b) { return a->info.pid < b->info.pid; });
    return live;
}

void entity_graph::store(const entity_ptr& entity) {
    auto& slot = by_tgid_[entity->info.pid];
    if (slot && slot->entity_id != entity->entity_id && !slot->exited_unix_ns.has_value()) {
        // The previous instance never reported an exit: its PID was reused.
        ++metrics_.pid_reuse;
        auto ended = std::make_shared<process_entity>(*slot);
        ended->exited_unix_ns = entity->first_seen_unix_ns;
        if (!ended->entity_id.empty()) by_entity_id_[ended->entity_id] = ended;
    }
    slot = entity;
    if (!entity->entity_id.empty()) by_entity_id_[entity->entity_id] = entity;
    metrics_.entities = by_tgid_.size();
}

entity_ptr entity_graph::load(const std::uint32_t tgid, const std::uint64_t now_unix_ns, const confidence attributes) {
    auto info = read_process(options_.proc_root, tgid, options_.limits);
    if (!succeeded(info)) return nullptr;
    auto entity = std::make_shared<process_entity>();
    entity->info = std::move(std::get<process_info>(info));
    entity->entity_id = compute_entity_id(options_.host_id, options_.boot_id, tgid, entity->info.start_ticks);
    entity->identity = confidence::observed;
    entity->attributes = attributes;
    entity->first_seen_unix_ns = now_unix_ns;
    if (const auto parent = find(entity->info.ppid);
        parent && !parent->exited_unix_ns.has_value() && parent->info.start_ticks <= entity->info.start_ticks) {
        entity->parent_entity_id = parent->entity_id;
    }
    return entity;
}

entity_ptr entity_graph::lookup_or_load(const std::uint32_t tgid, const std::uint64_t now_unix_ns) {
    if (tgid == 0U) return nullptr;
    if (auto existing = find(tgid); existing && !existing->exited_unix_ns.has_value()) return existing;
    auto loaded = load(tgid, now_unix_ns, confidence::reconstructed);
    if (loaded) store(loaded);
    return loaded;
}

std::vector<ancestor_ref> entity_graph::ancestry_of(const process_entity& entity) const {
    std::vector<ancestor_ref> chain;
    auto next = entity.parent_entity_id;
    while (!next.empty() && chain.size() < options_.maximum_ancestry) {
        const auto found = by_entity_id_.find(next);
        if (found == by_entity_id_.end()) break;
        const auto& ancestor = *found->second;
        chain.push_back({ancestor.entity_id, ancestor.info.pid, ancestor.info.comm, ancestor.info.executable.path});
        if (ancestor.parent_entity_id == next) break;
        next = ancestor.parent_entity_id;
    }
    return chain;
}

process_event entity_graph::make_event(std::string type, const raw_record& record, entity_ptr subject) const {
    process_event event;
    event.type = std::move(type);
    event.time_unix_ns = record.time_unix_ns;
    event.source = record.source;
    if (subject) {
        if (!subject->parent_entity_id.empty()) {
            if (const auto parent = by_entity_id_.find(subject->parent_entity_id); parent != by_entity_id_.end()) {
                event.parent = parent->second;
            }
        }
        event.ancestry = ancestry_of(*subject);
    }
    event.process = std::move(subject);
    return event;
}

std::vector<process_event> entity_graph::apply(const raw_record& record) {
    return std::visit(
        [this, &record](const auto& payload) -> std::vector<process_event> {
            using payload_type = std::decay_t<decltype(payload)>;
            if constexpr (std::is_same_v<payload_type, raw_fork>) return on_fork(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_exec>) return on_exec(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_exit>) return on_exit(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_credential_change>) return on_credentials(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_ptrace>) return on_ptrace(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_comm_change>) return on_comm(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_namespace_change>) return on_namespaces(record, payload);
            else if constexpr (std::is_same_v<payload_type, raw_file_event> || std::is_same_v<payload_type, raw_network_event> ||
                               std::is_same_v<payload_type, raw_auth_event> || std::is_same_v<payload_type, raw_kernel_event> ||
                               std::is_same_v<payload_type, raw_security_event> || std::is_same_v<payload_type, raw_dns_query> ||
                               std::is_same_v<payload_type, raw_lsm_event> || std::is_same_v<payload_type, raw_firewall_change>) {
                return {};  // not a process change
            } else return on_session(record, payload);
        },
        record.payload);
}

std::vector<process_event> entity_graph::on_fork(const raw_record& record, const raw_fork& fork) {
    if (fork.child_pid != fork.child_tgid) {
        ++metrics_.threads_ignored;
        return {};
    }
    ++metrics_.forks;
    const auto parent = lookup_or_load(fork.parent_tgid, record.time_unix_ns);
    auto child = std::make_shared<process_entity>();
    child->first_seen_unix_ns = record.time_unix_ns;

    std::optional<std::uint64_t> start_ticks = fork.child_start_ticks;
    if (!start_ticks.has_value()) start_ticks = read_start_ticks(options_.proc_root, fork.child_tgid);
    if (start_ticks.has_value()) {
        child->identity = fork.child_start_ticks.has_value() ? confidence::observed : confidence::reconstructed;
    } else {
        start_ticks = clock_.unix_ns_to_ticks(record.time_unix_ns);
        child->identity = confidence::inferred;
        ++metrics_.inferred_identities;
    }

    if (parent) {
        // fork(2) copies the parent: image, arguments, credentials, namespaces and cwd.
        child->info = parent->info;
        child->info.unavailable.clear();
        child->attributes = parent->attributes;
        child->parent_entity_id = parent->entity_id;
        child->info.vpid = parent->info.vpid == parent->info.pid ? fork.child_tgid : 0U;
        if (child->info.vpid == 0U) child->info.mark_unavailable("process.vpid", unavailable_reason::not_supported_by_provider);
    } else {
        child->attributes = confidence::inferred;
        child->info.vpid = fork.child_tgid;
        child->info.mark_unavailable("process.executable", unavailable_reason::process_exited);
        child->info.mark_unavailable("process.args", unavailable_reason::process_exited);
        child->info.mark_unavailable("process.user", unavailable_reason::process_exited);
    }
    child->info.pid = fork.child_tgid;
    child->info.ppid = fork.parent_tgid;
    child->info.start_ticks = *start_ticks;
    child->info.threads = 1U;
    child->entity_id = compute_entity_id(options_.host_id, options_.boot_id, fork.child_tgid, *start_ticks);
    store(child);

    auto event = make_event("process.fork", record, child);
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_exec(const raw_record& record, const raw_exec& exec) {
    ++metrics_.execs;
    auto prior = find(exec.tgid);
    if (prior && prior->exited_unix_ns.has_value()) prior = nullptr;

    auto entity = std::make_shared<process_entity>();
    entity->first_seen_unix_ns = prior ? prior->first_seen_unix_ns : record.time_unix_ns;
    auto info = read_process(options_.proc_root, exec.tgid, options_.limits);
    if (succeeded(info)) {
        entity->info = std::move(std::get<process_info>(info));
        entity->attributes = confidence::reconstructed;
        entity->identity = confidence::observed;
        if (prior && prior->info.start_ticks != entity->info.start_ticks) prior = nullptr;  // stale entry
    } else if (prior) {
        entity->info = prior->info;
        entity->info.unavailable.clear();
        // exec replaced the image: the pre-exec executable and name describe a program that no
        // longer runs, so they must not survive when procfs can no longer tell us the new one.
        entity->info.executable = {};
        if (exec.filename.has_value()) {
            const auto slash = exec.filename->find_last_of('/');
            entity->info.comm = exec.filename->substr(slash == std::string::npos ? 0U : slash + 1U, 15U);
        }
        entity->attributes = confidence::inferred;
        entity->identity = prior->identity;
        entity->info.mark_unavailable("process.executable", unavailable_reason::process_exited);
        entity->info.mark_unavailable("process.args", unavailable_reason::process_exited);
    } else {
        entity->info.pid = exec.tgid;
        entity->info.vpid = exec.tgid;
        entity->attributes = confidence::inferred;
        entity->info.mark_unavailable("process.executable", unavailable_reason::process_exited);
        entity->info.mark_unavailable("process.args", unavailable_reason::process_exited);
        entity->info.mark_unavailable("process.user", unavailable_reason::process_exited);
        if (exec.start_ticks.has_value()) {
            entity->info.start_ticks = *exec.start_ticks;
            entity->identity = confidence::observed;
        } else {
            entity->info.start_ticks = clock_.unix_ns_to_ticks(record.time_unix_ns);
            entity->identity = confidence::inferred;
            ++metrics_.inferred_identities;
        }
    }
    if (exec.start_ticks.has_value()) entity->info.start_ticks = *exec.start_ticks;
    // The kernel-captured path is what execve() was given (possibly relative, or /dev/fd/N for
    // fexecve), so it is only used when procfs could not resolve the executable; a resolved
    // /proc/<pid>/exe is more informative (absolute, and it exposes memfd and deleted images).
    if (exec.filename.has_value() && entity->info.executable.kind == executable_kind::unknown) {
        auto [path, kind] = classify_exe_link(*exec.filename);
        entity->info.executable.path = std::move(path);
        entity->info.executable.kind = kind;
        std::erase_if(entity->info.unavailable, [](const unavailable_field& field) { return field.field == "process.executable"; });
    }
    // Arguments captured in-kernel at exec time are authoritative over a later procfs read: the
    // process may already have rewritten its argv, or be gone.
    if (exec.args.has_value()) {
        entity->info.args = *exec.args;
        entity->info.args_truncated = exec.args_truncated;
        entity->attributes = confidence::observed;
        std::erase_if(entity->info.unavailable, [](const unavailable_field& field) { return field.field == "process.args"; });
    }

    entity->exec_gen = prior ? prior->exec_gen + 1U : 1U;
    entity->entity_id = compute_entity_id(options_.host_id, options_.boot_id, exec.tgid, entity->info.start_ticks);
    if (prior && prior->entity_id == entity->entity_id) {
        entity->parent_entity_id = prior->parent_entity_id;
    } else if (const auto parent = lookup_or_load(entity->info.ppid, record.time_unix_ns); parent) {
        entity->parent_entity_id = parent->entity_id;
    }
    store(entity);

    auto event = make_event("process.exec", record, entity);
    if (prior) event.previous_executable = prior->info.executable.path;
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_exit(const raw_record& record, const raw_exit& exit) {
    if (exit.pid != exit.tgid) {
        ++metrics_.threads_ignored;
        return {};
    }
    auto prior = find(exit.tgid);
    if (prior && prior->exited_unix_ns.has_value()) return {};  // already ended (e.g. by reconcile)
    ++metrics_.exits;
    std::shared_ptr<process_entity> ended;
    if (prior) {
        ended = std::make_shared<process_entity>(*prior);
    } else {
        ended = std::make_shared<process_entity>();
        ended->info.pid = exit.tgid;
        ended->identity = confidence::inferred;
        ended->attributes = confidence::inferred;
        ended->info.mark_unavailable("process.entity_id", unavailable_reason::process_exited);
        ended->info.mark_unavailable("process.executable", unavailable_reason::process_exited);
    }
    ended->exited_unix_ns = record.time_unix_ns;
    if (prior) store(ended);
    auto event = make_event("process.exit", record, ended);
    event.exit = decode_exit_status(exit.exit_status);
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_credentials(const raw_record& record, const raw_credential_change& change) {
    if (change.pid != change.tgid) return {};  // per-thread setuid is folded into the leader's next change
    const auto prior = lookup_or_load(change.tgid, record.time_unix_ns);
    if (!prior) return {};
    auto updated = std::make_shared<process_entity>(*prior);
    auto& ids = change.user ? updated->info.creds.uids : updated->info.creds.gids;
    if (ids[0] == change.real && ids[1] == change.effective) return {};
    ids[0] = change.real;
    ids[1] = change.effective;
    store(updated);
    auto event = make_event("process.cred_change", record, updated);
    event.creds_before = prior->info.creds;
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_ptrace(const raw_record& record, const raw_ptrace& trace) {
    if (trace.tracer_tgid == 0U) return {};  // detach
    const auto tracer = lookup_or_load(trace.tracer_tgid, record.time_unix_ns);
    const auto target = lookup_or_load(trace.tgid, record.time_unix_ns);
    auto event = make_event("process.inject", record, tracer);
    event.target = target;
    event.technique = trace.technique;
    if (!tracer) event.unavailable.push_back({"process", unavailable_reason::process_exited});
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_comm(const raw_record& record, const raw_comm_change& change) {
    if (change.pid != change.tgid) return {};  // thread names are not process names
    const auto prior = lookup_or_load(change.tgid, record.time_unix_ns);
    if (!prior || prior->info.comm == change.comm) return {};
    auto updated = std::make_shared<process_entity>(*prior);
    updated->info.comm = change.comm;
    store(updated);
    auto event = make_event("process.rename", record, updated);
    event.previous_name = prior->info.comm;
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_namespaces(const raw_record& record, const raw_namespace_change& change) {
    const auto prior = lookup_or_load(change.tgid, record.time_unix_ns);
    if (!prior) return {};
    const bool whole_process = change.tid == change.tgid;
    entity_ptr subject = prior;
    if (whole_process) {
        // Slots of process_info::namespaces for mnt, (pid_for_children: not a slot), net, uts, ipc, cgroup.
        constexpr std::array<int, 6> slot{0, -1, 2, 4, 5, 6};
        auto updated = std::make_shared<process_entity>(*prior);
        for (std::size_t index = 0U; index < slot.size(); ++index) {
            if (slot[index] >= 0 && change.after[index] != 0U) updated->info.namespaces[static_cast<std::size_t>(slot[index])] = change.after[index];
        }
        store(updated);
        subject = updated;
    }
    namespace_change_body body;
    body.whole_process = whole_process;
    body.thread_id = change.tid;
    for (std::size_t index = 0U; index < change.before.size(); ++index) {
        if (change.before[index] != change.after[index]) body.moves.push_back({nsproxy_names[index], change.before[index], change.after[index]});
    }
    if (body.moves.empty()) return {};
    auto event = make_event("process.ns_change", record, subject);
    event.ns_change = std::move(body);
    // A user namespace is part of the credentials, not the namespace proxy this hook compares.
    event.unavailable.push_back({"ns_change.user", unavailable_reason::not_supported_by_provider});
    return {std::move(event)};
}

std::vector<process_event> entity_graph::on_session(const raw_record& record, const raw_session_change& change) {
    if (const auto prior = lookup_or_load(change.tgid, record.time_unix_ns); prior) {
        auto updated = std::make_shared<process_entity>(*prior);
        updated->info.sid = change.tgid;
        updated->info.pgid = change.tgid;
        store(updated);
    }
    return {};
}

std::vector<process_event> entity_graph::reconcile(const std::uint64_t now_unix_ns, const bool emit_discovered) {
    std::vector<process_event> events;
    const auto pids = list_pids(options_.proc_root);
    std::unordered_set<std::uint32_t> present(pids.begin(), pids.end());
    const raw_record discovered_record{now_unix_ns, {"procfs", "PROCFS", confidence::reconstructed}, raw_session_change{}};

    for (const auto pid : pids) {
        const auto existing = find(pid);
        if (existing && !existing->exited_unix_ns.has_value()) {
            const auto ticks = read_start_ticks(options_.proc_root, pid);
            if (!ticks.has_value() || *ticks == existing->info.start_ticks) continue;
        }
        auto loaded = load(pid, now_unix_ns, confidence::reconstructed);
        if (!loaded) continue;  // exited between listing and reading
        if (existing && existing->entity_id == loaded->entity_id && !existing->exited_unix_ns.has_value()) continue;
        store(loaded);
        ++metrics_.discovered;
        if (emit_discovered) events.push_back(make_event("process.discovered", discovered_record, loaded));
    }
    // Parent links for processes loaded before their parents.
    for (auto& [pid, entity] : by_tgid_) {
        if (!entity->parent_entity_id.empty() || entity->exited_unix_ns.has_value()) continue;
        if (const auto parent = find(entity->info.ppid);
            parent && !parent->exited_unix_ns.has_value() && parent->info.start_ticks <= entity->info.start_ticks) {
            auto linked = std::make_shared<process_entity>(*entity);
            linked->parent_entity_id = parent->entity_id;
            entity = linked;
            by_entity_id_[linked->entity_id] = linked;
        }
    }

    // A tracked process missing from two consecutive scans has exited without a reported exit
    // (lost kernel event or a gap in the provider). One scan is not enough: its exit record may
    // still be queued behind the scan.
    const raw_record exit_record{now_unix_ns, {"procfs", "PROCFS", confidence::inferred}, raw_session_change{}};
    std::unordered_map<std::uint32_t, std::uint64_t> still_missing;
    for (const auto& [pid, entity] : by_tgid_) {
        if (entity->exited_unix_ns.has_value() || present.count(pid) != 0U) continue;
        if (const auto first = missing_.find(pid); first != missing_.end()) {
            auto ended = std::make_shared<process_entity>(*entity);
            ended->exited_unix_ns = now_unix_ns;
            ++metrics_.reconciled_exits;
            auto event = make_event("process.exit", exit_record, ended);
            event.unavailable.push_back({"process.exit_code", unavailable_reason::not_supported_by_provider});
            events.push_back(std::move(event));
        } else {
            still_missing.emplace(pid, now_unix_ns);
        }
    }
    for (auto& event : events) {
        if (event.type == "process.exit") store(event.process);
    }
    missing_ = std::move(still_missing);
    return events;
}

void entity_graph::purge(const std::uint64_t now_unix_ns) {
    const auto expired = [&](const entity_ptr& entity) {
        return entity->exited_unix_ns.has_value() && *entity->exited_unix_ns + options_.exit_grace_ns <= now_unix_ns;
    };
    for (auto it = by_tgid_.begin(); it != by_tgid_.end();) {
        it = expired(it->second) ? by_tgid_.erase(it) : std::next(it);
    }
    for (auto it = by_entity_id_.begin(); it != by_entity_id_.end();) {
        it = expired(it->second) ? by_entity_id_.erase(it) : std::next(it);
    }
    if (by_entity_id_.size() > options_.maximum_entities) {
        // Bound memory under fork storms: drop the oldest exited entities first.
        std::vector<std::pair<std::uint64_t, std::string>> exited;
        for (const auto& [id, entity] : by_entity_id_) {
            if (entity->exited_unix_ns.has_value()) exited.emplace_back(*entity->exited_unix_ns, id);
        }
        std::sort(exited.begin(), exited.end());
        const auto excess = by_entity_id_.size() - options_.maximum_entities;
        for (std::size_t index = 0U; index < excess && index < exited.size(); ++index) {
            const auto found = by_entity_id_.find(exited[index].second);
            const auto pid = found->second->info.pid;
            if (const auto slot = by_tgid_.find(pid); slot != by_tgid_.end() && slot->second == found->second) by_tgid_.erase(slot);
            by_entity_id_.erase(found);
            ++metrics_.evicted;
        }
    }
    metrics_.entities = by_tgid_.size();
}

}  // namespace panopticon::linux_agent::sensor
