#include "panopticon/linux_agent/sensor/container_identity.hpp"

#include <algorithm>
#include <vector>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr std::size_t maximum_path_bytes = 8192U;
constexpr std::size_t maximum_components = 64U;
constexpr std::size_t minimum_id = 12U;
constexpr std::size_t maximum_id = 64U;

bool is_lower_hex(const std::string_view text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

bool is_container_id(const std::string_view text) { return text.size() >= minimum_id && text.size() <= maximum_id && is_lower_hex(text); }

bool starts_with(const std::string_view text, const std::string_view prefix) { return text.substr(0U, prefix.size()) == prefix; }

bool ends_with(const std::string_view text, const std::string_view suffix) {
    return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

// "<prefix><id>.scope" -> id, when the id is a container id.
std::optional<std::string_view> scope_id(const std::string_view component, const std::string_view prefix) {
    if (!starts_with(component, prefix) || !ends_with(component, ".scope")) return std::nullopt;
    const auto id = component.substr(prefix.size(), component.size() - prefix.size() - 6U);
    if (!is_container_id(id)) return std::nullopt;
    return id;
}

// A Kubernetes pod uid is 36 characters of lowercase hex with dashes; the systemd driver writes the
// dashes as underscores because a slice name uses dashes for hierarchy.
std::optional<std::string> pod_uid_from(std::string_view text) {
    if (text.size() != 36U) return std::nullopt;
    std::string uid{text};
    std::replace(uid.begin(), uid.end(), '_', '-');
    for (std::size_t index = 0U; index < uid.size(); ++index) {
        const bool dash = index == 8U || index == 13U || index == 18U || index == 23U;
        const char c = uid[index];
        if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return std::nullopt;
    }
    return uid;
}

// "pod<uid>" (cgroupfs) or "...-pod<uid>.slice" (systemd).
std::optional<std::string> pod_uid_of_component(const std::string_view component) {
    if (starts_with(component, "pod")) return pod_uid_from(component.substr(3U));
    if (ends_with(component, ".slice")) {
        const auto marker = component.rfind("-pod");
        if (marker != std::string_view::npos) return pod_uid_from(component.substr(marker + 4U, component.size() - marker - 4U - 6U));
    }
    return std::nullopt;
}

struct scope_rule {
    std::string_view prefix;
    const char* runtime;
};
constexpr scope_rule rules[] = {{"docker-", "docker"}, {"cri-containerd-", "containerd"}, {"crio-", "crio"}, {"libpod-", "podman"}};

}  // namespace

std::optional<container_identity> parse_container_cgroup(const std::string_view cgroup) {
    if (cgroup.empty() || cgroup.size() > maximum_path_bytes) return std::nullopt;
    std::vector<std::string_view> parts;
    for (std::size_t start = 0U; start <= cgroup.size() && parts.size() <= maximum_components;) {
        auto end = cgroup.find('/', start);
        if (end == std::string_view::npos) end = cgroup.size();
        if (end > start) parts.push_back(cgroup.substr(start, end - start));
        start = end + 1U;
    }
    if (parts.empty() || parts.size() > maximum_components) return std::nullopt;

    container_identity found;
    bool in_kubernetes = false;
    for (std::size_t index = 0U; index < parts.size(); ++index) {
        const auto part = parts[index];
        if (starts_with(part, "kubepods")) in_kubernetes = true;
        if (const auto uid = pod_uid_of_component(part)) {
            found.pod_uid = *uid;
            in_kubernetes = true;
        }
        // systemd driver: one scope per container.
        for (const auto& rule : rules) {
            if (const auto id = scope_id(part, rule.prefix)) {
                found.id = std::string{*id};
                found.runtime = rule.runtime;
            }
        }
        // cgroupfs driver: the container id is a bare directory name below the runtime's parent.
        if (is_container_id(part) && found.id.empty()) {
            const auto parent = index > 0U ? parts[index - 1U] : std::string_view{};
            if (parent == "docker") {
                found.id = std::string{part};
                found.runtime = "docker";
            } else if (in_kubernetes && part.size() == maximum_id) {
                found.id = std::string{part};
                found.runtime = "kubernetes";  // the runtime behind the pod is not named by this layout
            } else if (parent == "libpod_parent" || parent == "libpod") {
                found.id = std::string{part};
                found.runtime = "podman";
            }
        }
    }
    if (found.id.empty()) return std::nullopt;
    return found;
}

}  // namespace panopticon::linux_agent::sensor
