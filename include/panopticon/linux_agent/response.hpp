#pragma once

#include "panopticon/linux_agent/identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace panopticon::linux_agent {

// Process termination bound to a verified identity (ADR 015).
//
// A PID is a number the kernel reuses, so a PID alone never names a process. The identity here is
// (pid, start time). The responder takes a pidfd for the PID, then reads the start time from procfs
// and refuses when it differs from the identity the caller was shown. From then on every signal goes
// through the pidfd, which refers to one process for its whole life: if that process exits, the
// signal fails with ESRCH instead of reaching whatever process the PID is handed to next.
//
// Where pidfd is not available (kernel before 5.3, or seccomp filtering) the responder can fall
// back to kill(2) after the same verification. That leaves a window between check and signal in
// which the PID could be reused. It is reported in `mode` and can be turned off.

enum class response_status : std::uint8_t {
    dry_run,            // everything verified, nothing signalled
    terminated,         // signalled and the process(es) exited
    signalled,          // signalled; exit not (yet) observed within the grace period
    already_gone,       // the target had exited before the signal
    refused_invalid,    // identity or options are unusable
    refused_protected,  // the target, or a member of its tree, must never be killed by the agent
    refused_mismatch,   // the PID no longer belongs to the process the caller named
    refused_limit,      // the tree is larger than the configured bound
    failed,             // the kernel refused the signal or the responder could not run
};

[[nodiscard]] const char* to_string(response_status status) noexcept;

struct response_options {
    std::filesystem::path proc_root{"/proc"};
    // Verify everything, change nothing. The default is the safe one; a caller that means to act
    // says so explicitly.
    bool dry_run{true};
    // Use kill(2) after verification when pidfd is unavailable. Off: the response fails instead.
    bool allow_pid_fallback{true};
    // Skip pidfd even when available (exercises the fallback path in tests).
    bool force_pid_fallback{false};
    // After `grace` without exit, send SIGKILL. SIGTERM first gives the process a chance to clean up.
    bool escalate_to_kill{false};
    std::chrono::milliseconds grace{0};
    // Upper bound on processes handled by a tree response.
    std::size_t maximum_tree_size{256U};
};

struct response_outcome {
    response_status status{response_status::failed};
    std::string mode;                      // "pidfd" or "pid_fallback"; empty when no signal path was chosen
    std::vector<process_identity> affected;  // verified identities, root first
    std::string detail;
};

// Whether this kernel allows pidfd_open at all (a live probe, not a version guess).
[[nodiscard]] bool pidfd_supported() noexcept;

// Why the agent refuses to signal `pid`, or an empty string when it may. Covers init, the agent itself,
// its ancestors (a supervisor killed from below stops the agent), and kernel threads.
[[nodiscard]] std::string protected_reason(std::uint32_t pid, const std::filesystem::path& proc_root);

// SIGTERM (optionally escalating to SIGKILL) to exactly the process named by `target`.
[[nodiscard]] response_outcome respond_terminate_process(const process_identity& target, const response_options& options);

// SIGKILL to the named process and every descendant, stopped first so that nothing forks while the
// tree is being collected. Refuses the whole operation when any member is protected.
[[nodiscard]] response_outcome respond_terminate_tree(const process_identity& target, const response_options& options);

}  // namespace panopticon::linux_agent
