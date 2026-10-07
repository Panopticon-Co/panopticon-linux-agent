// libFuzzer harnesses for every parser that reads bytes an attacker can influence while the sensor runs as root.
// One binary per target: this file is compiled once per FUZZ_<NAME> definition (see CMakeLists.txt,
// PANOPTICON_ENABLE_FUZZ). Run with tests/fuzz/run_fuzz.sh. A harness must never crash, hang, leak or read out of
// bounds whatever the input is; the parsers' own tests cover what they should return.

#include "panopticon/linux_agent/command.hpp"
#include "panopticon/linux_agent/sensor/audit_netlink.hpp"
#include "panopticon/linux_agent/sensor/auth_log.hpp"
#include "panopticon/linux_agent/sensor/clock.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"
#include "panopticon/linux_agent/sensor/container_identity.hpp"
#include "panopticon/linux_agent/sensor/dns_message.hpp"
#include "panopticon/linux_agent/sensor/ebpf_process.hpp"
#include "panopticon/linux_agent/sensor/fanotify_file.hpp"
#include "panopticon/linux_agent/sensor/fim.hpp"
#include "panopticon/linux_agent/sensor/host_state.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"
#include "panopticon/linux_agent/sensor/netlink_proc.hpp"
#include "panopticon/linux_agent/sensor/persistence.hpp"
#include "panopticon/linux_agent/sensor/pipeline.hpp"
#include "panopticon/linux_agent/sensor/policy.hpp"
#include "panopticon/linux_agent/sensor/policy_bundle.hpp"
#include "panopticon/linux_agent/sensor/sockdiag_network.hpp"
#include "panopticon/linux_agent/sensor/wal.hpp"

#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

std::string_view as_text(const std::uint8_t* data, const std::size_t size) {
    return {reinterpret_cast<const char*>(data), size};
}

}  // namespace

#if defined(FUZZ_JSON)
// The strict JSON reader every Manager reply and command goes through.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    json_limits limits;
    limits.maximum_bytes = 64U * 1024U;
    std::string error;
    (void)parse_json(as_text(data, size), limits, &error);
}

#elif defined(FUZZ_COMMANDS)
// A poll reply from the Manager: the strict reader, then the command schema, then the legacy parser.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    const auto text = as_text(data, size);
    (void)parse_command_poll(text, 32U);
    (void)parse_command_json(text);
    (void)parse_command_poll_response(text, 32U);
    json_limits limits;
    limits.maximum_bytes = 64U * 1024U;
    if (const auto value = parse_json(text, limits)) {
        const auto parsed = parse_endpoint_command(*value);
        (void)parsed;
    }
    (void)parse_utc_offset_timestamp(text);
    (void)decode_base64(text);
}

#elif defined(FUZZ_CONFIG)
// The sensor configuration file.
static void fuzz(const std::uint8_t* data, const std::size_t size) { (void)parse_sensor_config(as_text(data, size)); }

#elif defined(FUZZ_POLICY)
// A policy body (ADR 016) and a signed bundle (ADR 032). A body that loads is also evaluated, with the input
// itself as every attacker-chosen fact, so matching runs on hostile text as well.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    const auto text = as_text(data, size);
    auto engine = policy_engine::parse(text);
    if (succeeded(engine)) {
        policy_input input;
        input.kind = "process.exec";
        input.exe = "/tmp/" + std::string{text.substr(0U, 256U)};
        input.cmdline = std::string{text};
        input.file_path = input.exe;
        input.dest_domain = std::string{text.substr(0U, 253U)};
        (void)std::get<policy_engine>(engine).evaluate(input);
        (void)std::get<policy_engine>(engine).evaluate(input, policy_field::sha256);
    }
    (void)parse_policy_bundle(text);
}

#elif defined(FUZZ_AUTH_LINE)
// A line of auth.log or the journal: written by users (a user name is attacker text).
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    (void)parse_auth_line(as_text(data, size), 1'700'000'000'000'000'000ULL);
}

#elif defined(FUZZ_AUDIT)
// One audit netlink datagram, then every record in it through both record parsers.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    const uid_lookup lookup = [](const std::uint32_t) { return std::string{"user"}; };
    for (const auto& message : decode_audit_datagram(data, size)) {
        (void)parse_audit_record(message.type, message.text, lookup);
        (void)parse_audit_security_record(message.type, message.text);
    }
}

#elif defined(FUZZ_DNS)
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    (void)parse_dns_query(std::span<const std::uint8_t>{data, size});
}

#elif defined(FUZZ_FANOTIFY)
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    (void)decode_fanotify_events(reinterpret_cast<const unsigned char*>(data), size);
}

#elif defined(FUZZ_SOCKDIAG)
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    if (size == 0U) return;
    const std::uint8_t protocol = (data[0] & 1U) != 0U ? 6U : 17U;
    (void)decode_sock_diag(reinterpret_cast<const unsigned char*>(data + 1), size - 1U, protocol);
}

#elif defined(FUZZ_PROC_EVENT)
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    static const clock_domain clock;
    (void)decode_proc_event(data, size, clock);
}

#elif defined(FUZZ_EBPF_SAMPLE)
// A ring-buffer sample: written by the sensor's own programs, but read from memory shared with the kernel.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    static const clock_domain clock;
    bool malformed = false;
    (void)decode_ebpf_process_sample(data, size, clock, procfs_limits{}, &malformed);
}

#elif defined(FUZZ_PROCFS)
// /proc/<pid> as a hostile process can shape it (comm, cmdline, environ and its links are the process's own choice).
// The input is split at 0xFF into stat, status, cmdline, environ, cgroup, loginuid, sessionid, exe target and cwd
// target; the parsers run directly and then read_process runs over a fake procfs root built from the parts.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    namespace fs = std::filesystem;
    std::vector<std::string> parts(9);
    std::size_t part = 0U;
    for (std::size_t index = 0U; index < size; ++index) {
        if (data[index] == 0xFFU && part + 1U < parts.size()) {
            ++part;
            continue;
        }
        parts[part].push_back(static_cast<char>(data[index]));
    }
    (void)parse_stat(parts[0]);
    process_info direct;
    parse_status(parts[1], direct);
    bool truncated = false;
    (void)split_cmdline(parts[2], 64U, 4096U, truncated);
    (void)classify_exe_link(parts[7]);

    static const fs::path root = fs::path{"/dev/shm"} / ("panopticon-fuzz-proc-" + std::to_string(::getpid()));
    const fs::path base = root / "4242";
    std::error_code ignored;
    fs::remove_all(root, ignored);
    fs::create_directories(base, ignored);
    const char* names[] = {"stat", "status", "cmdline", "environ", "cgroup", "loginuid", "sessionid"};
    for (std::size_t index = 0U; index < 7U; ++index) {
        std::ofstream file{base / names[index], std::ios::binary};
        file.write(parts[index].data(), static_cast<std::streamsize>(parts[index].size()));
    }
    // A link target is a C string: it ends at the first NUL, and an empty one is not a link.
    for (const auto& [name, target] : {std::pair{"exe", parts[7]}, std::pair{"cwd", parts[8]}}) {
        const std::string text{target.c_str()};
        if (!text.empty()) fs::create_symlink(text, base / name, ignored);
    }
    (void)read_process(root, 4242U, procfs_limits{});
    (void)read_start_ticks(root, 4242U);
    (void)list_pids(root);
    fs::remove_all(root, ignored);
}

#elif defined(FUZZ_CGROUP)
static void fuzz(const std::uint8_t* data, const std::size_t size) { (void)parse_container_cgroup(as_text(data, size)); }

#elif defined(FUZZ_HOSTFILES)
// The files the inventory reads: the first byte picks the parser, the rest is the file.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    if (size == 0U) return;
    const auto text = as_text(data + 1, size - 1U);
    switch (data[0] % 8U) {
    case 0: (void)parse_os_release(text); break;
    case 1: (void)parse_passwd(text, 256U); break;
    case 2: (void)parse_group(text, 256U); break;
    case 3: (void)parse_mountinfo(text, 256U); break;
    case 4: (void)parse_proc_modules(text, 256U); break;
    case 5: (void)parse_dpkg_status(text, 512U); break;
    case 6: (void)decode_mount_escapes(text); break;
    default: (void)parse_authorized_keys(text, 64U); break;
    }
}

#elif defined(FUZZ_FIM)
// The persisted file-integrity baseline.
static void fuzz(const std::uint8_t* data, const std::size_t size) { (void)fim_parse(as_text(data, size), 1000U); }

#elif defined(FUZZ_WAL)
// A write-ahead-log segment as left by a crash or an attacker: recover it, read it, append to it, read again.
static void fuzz(const std::uint8_t* data, const std::size_t size) {
    namespace fs = std::filesystem;
    static const fs::path directory = fs::path{"/dev/shm"} / ("panopticon-fuzz-wal-" + std::to_string(::getpid()));
    std::error_code ignored;
    fs::remove_all(directory, ignored);
    fs::create_directories(directory, ignored);
    {
        std::ofstream segment{directory / "wal-00000000000000000001.log", std::ios::binary};
        segment.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
    wal_options options;
    options.directory = directory;
    // A record plus its header must fit a segment, or open() refuses the limits before recovery reads anything.
    options.segment_bytes = 128U * 1024U;
    options.quota_bytes = 1024U * 1024U;
    options.maximum_record_bytes = 32U * 1024U;
    auto opened = write_ahead_log::open(options);
    if (!std::holds_alternative<std::unique_ptr<write_ahead_log>>(opened)) {
        // Only the input may make open() fail; a refusal of the harness's own limits would make this target blind.
        if (std::get<error>(opened).code == error_code::invalid_input) __builtin_trap();
    }
    if (auto* log = std::get_if<std::unique_ptr<write_ahead_log>>(&opened); log != nullptr && *log != nullptr) {
        auto& wal = **log;
        (void)wal.read(1U, 1000U, 1U << 20);
        (void)wal.append(wal.next_seq(), "fuzz");
        (void)wal.sync(1U, true);
        (void)wal.read(1U, 1000U, 1U << 20);
        (void)wal.verify_storage();
        (void)wal.take_losses();
    }
    fs::remove_all(directory, ignored);
}

#else
#error "define one FUZZ_<NAME> target"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, const std::size_t size) {
    fuzz(data, size);
    return 0;
}
