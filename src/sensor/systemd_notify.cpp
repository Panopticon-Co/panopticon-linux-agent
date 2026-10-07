#include "panopticon/linux_agent/sensor/systemd_notify.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace panopticon::linux_agent::sensor {

systemd_notifier::systemd_notifier(std::string socket_path, const std::uint64_t watchdog_usec)
    : socket_path_{std::move(socket_path)}, interval_ns_{socket_path_.empty() ? 0U : watchdog_usec * 1000U / 2U} {}

systemd_notifier systemd_notifier::from_environment() {
    const char* socket = std::getenv("NOTIFY_SOCKET");
    std::uint64_t watchdog_usec = 0U;
    if (const char* value = std::getenv("WATCHDOG_USEC"); value != nullptr) {
        char* end = nullptr;
        errno = 0;
        const auto parsed = std::strtoull(value, &end, 10);
        if (errno == 0 && end != value && *end == '\0') watchdog_usec = parsed;
    }
    if (const char* pid = std::getenv("WATCHDOG_PID"); pid != nullptr) {
        char* end = nullptr;
        const auto owner = std::strtoull(pid, &end, 10);
        if (end == pid || *end != '\0' || owner != static_cast<unsigned long long>(::getpid())) watchdog_usec = 0U;  // not meant for this process
    }
    return systemd_notifier{socket == nullptr ? std::string{} : std::string{socket}, watchdog_usec};
}

bool systemd_notifier::send(const std::string_view message) const {
    if (socket_path_.empty()) return false;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(address.sun_path)) return false;
    std::memcpy(address.sun_path, socket_path_.data(), socket_path_.size());
    if (address.sun_path[0] == '@') address.sun_path[0] = '\0';  // abstract namespace
    const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + socket_path_.size());
    const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    const auto sent = ::sendto(fd, message.data(), message.size(), MSG_NOSIGNAL, reinterpret_cast<const sockaddr*>(&address), length);
    ::close(fd);
    return sent == static_cast<ssize_t>(message.size());
}

bool systemd_notifier::ready() { return send("READY=1"); }

bool systemd_notifier::stopping() { return send("STOPPING=1"); }

bool systemd_notifier::status(const std::string_view text) { return send("STATUS=" + std::string{text}); }

bool systemd_notifier::pet_if_due(const std::uint64_t now_ns) {
    if (interval_ns_ == 0U) return false;
    if (petted_ && now_ns - last_pet_ns_ < interval_ns_) return false;
    const bool sent = send("WATCHDOG=1");
    if (sent) {
        petted_ = true;
        last_pet_ns_ = now_ns;
    }
    return sent;
}

}  // namespace panopticon::linux_agent::sensor
