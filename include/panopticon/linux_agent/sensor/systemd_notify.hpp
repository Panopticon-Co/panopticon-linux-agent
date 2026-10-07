#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace panopticon::linux_agent::sensor {

// The service-manager side of a Type=notify unit with a watchdog, without libsystemd: one datagram per message to
// the socket in NOTIFY_SOCKET. A sensor that is started by hand has no such socket and every call does nothing.
//
// The watchdog is only worth having if it measures the work that matters: pet_if_due() is called by the pipeline
// loop itself, so a loop stuck behind a hung disk or a deadlock stops the pets and systemd restarts the sensor.
class systemd_notifier {
public:
    // `socket_path` empty: inactive. A leading '@' names an abstract socket, as systemd writes it.
    // `watchdog_usec` 0: no watchdog (READY and STOPPING are still sent).
    systemd_notifier(std::string socket_path, std::uint64_t watchdog_usec);
    // NOTIFY_SOCKET, WATCHDOG_USEC and WATCHDOG_PID (ignored when it names another process) from the environment.
    [[nodiscard]] static systemd_notifier from_environment();

    [[nodiscard]] bool active() const noexcept { return !socket_path_.empty(); }
    [[nodiscard]] std::uint64_t watchdog_interval_ns() const noexcept { return interval_ns_; }

    bool ready();
    bool stopping();
    bool status(std::string_view text);
    // Sends WATCHDOG=1 when half the watchdog period has passed since the last one (the period systemd recommends).
    bool pet_if_due(std::uint64_t now_ns);

private:
    bool send(std::string_view message) const;

    std::string socket_path_;
    std::uint64_t interval_ns_{};
    std::uint64_t last_pet_ns_{};
    bool petted_{false};
};

}  // namespace panopticon::linux_agent::sensor
