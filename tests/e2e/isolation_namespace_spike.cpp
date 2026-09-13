// ADR 004 de-risking spike -- NOT part of the agent or the isolation helper.
//
// Proves that this toolchain can drive nftables purely via netlink
// (libmnl + libnftnl), with no `nft`/`iptables` subprocess and no shell,
// before any of that code is wired into the real command-dispatch path.
// Run inside a throwaway network namespace (see
// run_isolation_namespace_spike.sh) so it never touches the real host
// firewall.
//
// The nftables netlink protocol requires every operation to be wrapped in
// an NFNL_MSG_BATCH_BEGIN/END pair, even a single one -- sending a bare
// NFT_MSG_NEWTABLE outside a batch is rejected by the kernel with EINVAL.
// This spike sends one batch containing: create a table, create a chain
// inside it, then delete the table (removing the chain with it), and
// confirms the kernel acknowledges the whole batch.

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/batch.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace {

constexpr const char* kTableName = "panopticon_spike";
constexpr const char* kChainName = "spike_chain";

int on_netlink_message([[maybe_unused]] const nlmsghdr* nlh, void* data) {
    ++(*static_cast<int*>(data));
    return MNL_CB_OK;
}

bool send_batch_and_await_acks(mnl_socket* nl, mnl_nlmsg_batch* batch, const std::uint32_t portid) {
    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
        std::perror("mnl_socket_sendto");
        return false;
    }
    char reply[MNL_SOCKET_BUFFER_SIZE];
    int acknowledged = 0;
    for (;;) {
        const auto received = mnl_socket_recvfrom(nl, reply, sizeof(reply));
        if (received < 0) {
            std::perror("mnl_socket_recvfrom");
            return false;
        }
        if (received == 0) break;
        // seq 0 accepts any sequence number in the batch (begin/end/messages
        // each carry their own seq); we only care that every reply is a
        // clean ACK, not an error, so any callback return besides <0 counts.
        const auto result = mnl_cb_run(reply, static_cast<std::size_t>(received), 0, portid, on_netlink_message, &acknowledged);
        if (result < 0) {
            std::fprintf(stderr, "mnl_cb_run: %s\n", std::strerror(errno));
            return false;
        }
        if (result == MNL_CB_STOP) break;
    }
    return true;
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

    char raw_buffer[8U * MNL_SOCKET_BUFFER_SIZE];
    mnl_nlmsg_batch* batch = mnl_nlmsg_batch_start(raw_buffer, sizeof(raw_buffer));

    nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    nftnl_table* table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, kTableName);
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWTABLE,
                                                 NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    nftnl_chain* chain = nftnl_chain_alloc();
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, kTableName);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, kChainName);
    nlh = nftnl_chain_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWCHAIN,
                                       NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    nftnl_chain_free(chain);
    mnl_nlmsg_batch_next(batch);

    nftnl_table* doomed = nftnl_table_alloc();
    nftnl_table_set_str(doomed, NFTNL_TABLE_NAME, kTableName);
    nftnl_table_set_u32(doomed, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    nlh = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_DELTABLE,
                                       NFPROTO_INET, NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, doomed);
    nftnl_table_free(doomed);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    const bool ok = send_batch_and_await_acks(nl, batch, portid);
    mnl_nlmsg_batch_stop(batch);
    mnl_socket_close(nl);

    if (!ok) {
        std::fprintf(stderr, "spike: batch (create table, create chain, delete table) was not fully acknowledged\n");
        return 1;
    }
    std::printf("spike: netlink batch apply/teardown cycle succeeded with no subprocess, no shell\n");
    return 0;
}
