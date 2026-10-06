#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace panopticon::linux_agent::sensor {

// Who a process belongs to when it runs inside a container, derived from its cgroup path alone.
// The path is what the container runtime created before the first process started, so it is
// available at exec time without asking the runtime anything (no socket calls, no race with the
// runtime's own state). It is a claim by whoever set the cgroup up, not proof of isolation: a
// process can place itself in a cgroup it owns, which is why the record keeps `cgroup` too.
struct container_identity {
    std::string id;       // lowercase hex container id as the runtime names it (usually 64 characters)
    std::string runtime;  // docker, containerd, crio, podman, or kubernetes when only the pod is known
    std::string pod_uid;  // Kubernetes pod uid with dashes, empty outside Kubernetes
};

// Understands the systemd and cgroupfs layouts of Docker, containerd (CRI), CRI-O and Podman, and
// Kubernetes pod slices (guaranteed, burstable, best-effort). Runtime helper processes such as
// conmon are not the container and yield nothing. Pure and bounded; hostile input yields nothing.
[[nodiscard]] std::optional<container_identity> parse_container_cgroup(std::string_view cgroup);

}  // namespace panopticon::linux_agent::sensor
