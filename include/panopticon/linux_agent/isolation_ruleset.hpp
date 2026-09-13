#pragma once
#include "panopticon/linux_agent/error.hpp"
#include <cstdint>
#include <string>

namespace panopticon::linux_agent {

// Compiled-in nftables table/chain names. Never derived from command
// content -- ISOLATE_HOST/RELEASE_HOST_ISOLATION carry no target (see
// docs/adr/004-host-isolation-privilege-boundary.md).
inline constexpr std::string_view kIsolationTableName{"panopticon_isolation"};
inline constexpr std::string_view kIsolationInputChainName{"panopticon_isolation_input"};
inline constexpr std::string_view kIsolationOutputChainName{"panopticon_isolation_output"};

// Applies the fixed isolation ruleset via netlink (libmnl/libnftnl), never
// a shell or `nft`/`iptables` subprocess: one table with input/output base
// chains at hook priority 0, default policy drop, with exactly two
// exceptions -- loopback, and the given pinned Manager IPv4 address/port in
// both directions. No ESTABLISHED/RELATED exception is granted (see ADR
// 004): every other connection, including one already established, is
// dropped. Idempotent -- applying while already isolated tears down and
// re-creates the same fixed ruleset rather than erroring or duplicating it.
[[nodiscard]] result<bool> apply_isolation_ruleset(std::uint32_t manager_ipv4_network_order, std::uint16_t manager_port);

// Removes exactly the panopticon_isolation table this helper owns. Never
// touches any other table/chain a human operator or another tool created.
// Idempotent -- releasing when not isolated is a no-op success.
[[nodiscard]] result<bool> release_isolation_ruleset();

}  // namespace panopticon::linux_agent
