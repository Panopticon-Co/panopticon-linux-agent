#include "panopticon/linux_agent/host.hpp"
#include <fstream>
#include <sstream>
#ifdef __linux__
#include <sys/utsname.h>
#include <unistd.h>
#endif
namespace panopticon::linux_agent {
result<host_observation> collect_host_observation() {
#ifndef __linux__
    return error{error_code::unsupported_action, "host collection is available only on Linux"};
#else
    struct utsname details{}; char hostname[256]{};
    if (uname(&details) != 0 || gethostname(hostname, sizeof(hostname) - 1U) != 0)
        return error{error_code::io_failure, "cannot collect host identity"};
    std::ifstream boot_input{"/proc/sys/kernel/random/boot_id"}; std::string boot_id; std::getline(boot_input, boot_id);
    std::ifstream uptime_input{"/proc/uptime"}; double uptime{}; uptime_input >> uptime;
    if (!boot_input || !uptime_input || uptime < 0.0) return error{error_code::io_failure, "cannot collect host runtime"};
    return host_observation{hostname, details.release, details.machine, std::move(boot_id), static_cast<std::uint64_t>(uptime)};
#endif
}
}  // namespace panopticon::linux_agent
