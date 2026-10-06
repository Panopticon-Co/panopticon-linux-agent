#pragma once

#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/entity_graph.hpp"
#include "panopticon/linux_agent/sensor/fim.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"
#include "panopticon/linux_agent/sensor/json.hpp"
#include "panopticon/linux_agent/sensor/provider.hpp"

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

inline constexpr std::string_view endpoint_schema_version{"1.0"};

struct sensor_identity {
    std::string host_id;
    std::string boot_id;
    std::string hostname;
    std::string sensor_id;
    std::string version;
    std::string policy_version{"none"};
};

// `SHA-256(sensor_id | boot_id | seq)` truncated to 32 hex (catalog §2).
[[nodiscard]] std::string compute_record_id(std::string_view sensor_id, std::string_view boot_id, std::uint64_t seq);

struct health_snapshot {
    std::string status;  // healthy, degraded, failed
    std::vector<provider_health> providers;
    std::map<std::string, std::string> coverage;  // capability -> provider ("" = uncovered)
    std::uint64_t rss_bytes{};
    std::uint64_t cpu_milliseconds{};
    std::uint64_t wal_bytes{};
    std::uint64_t wal_records{};
    std::string kernel_release;
    bool btf{false};
    bool bpf_lsm{false};
    bool ringbuf{false};
};

struct loss_report {
    std::string stage;  // kernel, queue, wal, governor, transport
    std::uint64_t count{};
    std::map<std::string, std::uint64_t> by_type;
    std::string detail;
};

// A file.* event after the pipeline attached the acting process (if it still exists) and an
// optional lstat of the path.
struct file_stat {
    std::uint32_t mode{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::uint64_t size{};
    std::uint64_t inode{};
    std::uint64_t device{};
    std::uint64_t mtime_unix_ns{};
};

struct file_record {
    std::string type;  // file.create / file.modify / file.delete / file.rename / file.attrib
    std::uint64_t time_unix_ns{};
    provenance source;
    entity_ptr actor;  // null when the process was gone before it could be identified
    std::uint32_t pid{};
    std::string path;
    std::optional<std::string> old_path;
    bool directory{false};
    std::optional<file_stat> stat;
    std::vector<unavailable_field> unavailable;
};

// A network.* event after the pipeline attached the owning process (if it still exists).
struct network_record {
    std::uint64_t time_unix_ns{};
    provenance source;
    entity_ptr actor;  // null when no process held the socket when it was looked up
    raw_network_event network;
};

// An auth.* event after the pipeline attached the logging process (if it still exists).
struct auth_record {
    std::uint64_t time_unix_ns{};
    provenance source;
    entity_ptr actor;
    raw_auth_event auth;
};

// A kernel.* or mount.* event. There is no acting process.
struct kernel_record {
    std::uint64_t time_unix_ns{};
    provenance source;
    raw_kernel_event kernel;
};

class record_serializer {
public:
    record_serializer(sensor_identity identity, const clock_domain& clock);

    [[nodiscard]] std::string event(const process_event& event, std::uint64_t seq, std::uint64_t observed_unix_ns) const;
    [[nodiscard]] std::string health(const health_snapshot& snapshot, std::uint64_t seq, std::uint64_t now_unix_ns) const;
    // The health object without a record envelope: the body of the control-socket `status` reply.
    [[nodiscard]] static std::string status_json(const health_snapshot& snapshot);
    // Just the capability -> provider map (null = uncovered).
    [[nodiscard]] static std::string coverage_json(const health_snapshot& snapshot);
    [[nodiscard]] std::string loss(const loss_report& report, std::uint64_t seq, std::uint64_t now_unix_ns) const;
    // state.processes snapshot part (catalog §5).
    [[nodiscard]] std::string process_state(const std::vector<entity_ptr>& items, std::string_view snapshot_id,
                                            std::uint32_t part, std::uint32_t parts, std::uint64_t seq,
                                            std::uint64_t now_unix_ns) const;

    [[nodiscard]] std::string file_event(const file_record& record, std::uint64_t seq, std::uint64_t observed_unix_ns) const;

    // network.connect / network.accept / network.listen (catalog §4.3).
    [[nodiscard]] std::string network_event(const network_record& record, std::uint64_t seq, std::uint64_t observed_unix_ns) const;

    // auth.login / auth.failure / auth.privilege (catalog 4.4).
    [[nodiscard]] std::string auth_event(const auth_record& record, std::uint64_t seq, std::uint64_t observed_unix_ns) const;

    // kernel.module_load / kernel.module_unload / mount.changed (catalog 4.5).
    [[nodiscard]] std::string kernel_event(const kernel_record& record, std::uint64_t seq, std::uint64_t observed_unix_ns) const;

    // fim.changed (catalog §4.2). `actor` is the acting process when a file event named the path
    // and the process was still known; otherwise the process is reported as unavailable.
    [[nodiscard]] std::string fim_changed(const fim_change& change, const entity_ptr& actor, std::uint64_t seq,
                                          std::uint64_t observed_unix_ns) const;
    // hash.computed: the content hash of an executed image that was still pending when the
    // exec record was written. Joined to that record by process.entity_id + exec_gen.
    [[nodiscard]] std::string hash_computed(const hash_result& result, std::uint64_t seq, std::uint64_t now_unix_ns) const;
    // fim.baseline: what the monitor started from and how many offline changes it found.
    [[nodiscard]] std::string fim_baseline_record(const fim_start_result& start, std::uint64_t seq, std::uint64_t now_unix_ns) const;

    // state.<object> snapshot part for host-state inventory objects (catalog §5). `items` are
    // already-serialised JSON objects; `unavailable` is carried on part 1 only.
    [[nodiscard]] std::string host_state(const state_snapshot& snapshot, std::span<const std::string> items,
                                         std::string_view snapshot_id, std::uint32_t part, std::uint32_t parts,
                                         std::uint64_t seq, std::uint64_t now_unix_ns) const;

    void set_policy_version(std::string version) { identity_.policy_version = std::move(version); }
    [[nodiscard]] const sensor_identity& identity() const noexcept { return identity_; }

private:
    void begin(json_writer& out, std::string_view record_type, std::string_view type, std::uint64_t seq,
               std::uint64_t time_unix_ns, std::uint64_t observed_unix_ns, const provenance& source) const;
    // Writes the catalog §3.1 process object but leaves it open, so event-specific fields
    // (exit status, ancestry) can be appended; the caller closes it.
    void write_process(json_writer& out, const process_entity& entity, const file_hash* hash = nullptr) const;

    sensor_identity identity_;
    const clock_domain& clock_;
};

}  // namespace panopticon::linux_agent::sensor
