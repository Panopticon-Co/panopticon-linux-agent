// ADR 004 de-risking spike -- NOT part of the agent or the isolation helper.
//
// Proves that this toolchain can drive nftables purely via netlink
// (libmnl + libnftnl), with no `nft`/`iptables` subprocess and no shell,
// before any of that code is wired into the real command-dispatch path.
// Run inside an unprivileged network namespace (see
// tests/e2e/run_isolation_namespace_spike.sh) so it never touches the
// real host firewall.
//
// Sequence: create a table -> create a chain inside it -> delete the table
// (which removes the chain with it) -> confirm each step is acknowledged
// by the kernel over netlink.

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace {

constexpr const char* kTableName = "panopticon_spike";
constexpr const char* kChainName = "spike_chain";

bool send_and_await_ack(mnl_socket* nl, const nlmsghdr* nlh, const std::uint32_t seq,
                         const std::uint32_t portid) {
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        std::perror("mnl_socket_sendto");
        return false;
    }
    char reply[MNL_SOCKET_BUFFER_SIZE];
    auto received = mnl_socket_recvfrom(nl, reply, sizeof(reply));
    while (received > 0) {
        const auto result = mnl_cb_run(reply, static_cast<std::size_t>(received), seq, portid, nullptr, nullptr);
        if (result <= 0) return result == 0;
        received = mnl_socket_recvfrom(nl, reply, sizeof(reply));
    }
    if (received < 0) std::perror("mnl_socket_recvfrom");
    return received == 0;
}

}  // namespace

int main() {
    mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == nullptr) {
        std::perror("mnl_socket_open");
        return 1;
    }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        std::perror("mnl_socket_bind");
        mnl_socket_close(nl);
        return 1;
    }
    const auto portid = mnl_socket_get_portid(nl);
    std::uint32_t seq = static_cast<std::uint32_t>(std::time(nullptr));
    char buffer[MNL_SOCKET_BUFFER_SIZE];

    // Create table.
    nftnl_table* table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, kTableName);
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    ++seq;
    nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(buffer, NFT_MSG_NEWTABLE, NFPROTO_INET,
                                                 NLM_F_CREATE | NLM_F_ACK, seq);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    if (!send_and_await_ack(nl, nlh, seq, portid)) {
        std::fprintf(stderr, "spike: NEWTABLE was not acknowledged\n");
        mnl_socket_close(nl);
        return 1;
    }
    std::printf("spike: table created\n");

    // Create chain inside that table.
    nftnl_chain* chain = nftnl_chain_alloc();
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, kTableName);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, kChainName);
    ++seq;
    nlh = nftnl_chain_nlmsg_build_hdr(buffer, NFT_MSG_NEWCHAIN, NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, seq);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    nftnl_chain_free(chain);
    if (!send_and_await_ack(nl, nlh, seq, portid)) {
        std::fprintf(stderr, "spike: NEWCHAIN was not acknowledged\n");
        mnl_socket_close(nl);
        return 1;
    }
    std::printf("spike: chain created\n");

    // Delete the table (removes the chain with it) -- proves teardown works,
    // matching the isolation helper's RELEASE_HOST_ISOLATION requirement.
    nftnl_table* doomed = nftnl_table_alloc();
    nftnl_table_set_str(doomed, NFTNL_TABLE_NAME, kTableName);
    nftnl_table_set_u32(doomed, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    ++seq;
    nlh = nftnl_table_nlmsg_build_hdr(buffer, NFT_MSG_DELTABLE, NFPROTO_INET, NLM_F_ACK, seq);
    nftnl_table_nlmsg_build_payload(nlh, doomed);
    nftnl_table_free(doomed);
    if (!send_and_await_ack(nl, nlh, seq, portid)) {
        std::fprintf(stderr, "spike: DELTABLE was not acknowledged\n");
        mnl_socket_close(nl);
        return 1;
    }
    std::printf("spike: table (and chain) removed\n");

    mnl_socket_close(nl);
    std::printf("spike: netlink apply/teardown cycle succeeded with no subprocess, no shell\n");
    return 0;
}
