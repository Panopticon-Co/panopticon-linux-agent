#include "panopticon/linux_agent/isolation_ruleset.hpp"

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/batch.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/in.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace panopticon::linux_agent {
namespace {

// MNL_SOCKET_BUFFER_SIZE is a runtime expression (page-size based) in
// libmnl, not a compile-time constant, so it cannot size a stack array
// under -Werror=vla. 8192 bytes matches libmnl's own upper bound.
constexpr std::size_t kNetlinkBufferBytes{8192U};

int on_ack([[maybe_unused]] const nlmsghdr* nlh, void* count) {
    ++(*static_cast<int*>(count));
    return MNL_CB_OK;
}

// Sends everything staged in `batch` and waits for the kernel to
// acknowledge the whole thing. Returns false (never throws, never leaves
// a half-applied ruleset silently claimed as success) on any netlink-level
// failure.
bool commit_batch(mnl_nlmsg_batch* batch) {
    mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == nullptr) { std::perror("isolation-ruleset: mnl_socket_open"); return false; }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        std::perror("isolation-ruleset: mnl_socket_bind");
        mnl_socket_close(nl);
        return false;
    }
    // Defense in depth against a batch with no NLM_F_ACK-flagged message
    // ever getting a kernel reply at all (see the release-path fix below,
    // NLM_F_ACK is now always requested) -- a privileged daemon must never
    // block indefinitely on a netlink call regardless of how the batch was
    // built, so a bounded receive timeout is enforced independently.
    timeval receive_timeout{.tv_sec = 5, .tv_usec = 0};
    if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        std::perror("isolation-ruleset: setsockopt(SO_RCVTIMEO)");
        mnl_socket_close(nl);
        return false;
    }
    const auto portid = mnl_socket_get_portid(nl);
    const auto batch_size = mnl_nlmsg_batch_size(batch);
    const auto sent = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), batch_size);
    if (sent < 0) {
        std::perror("isolation-ruleset: mnl_socket_sendto");
        mnl_socket_close(nl);
        return false;
    }
    std::fprintf(stderr, "isolation-ruleset: sent %zd of %zu batch bytes, portid=%u, awaiting reply\n",
                 sent, batch_size, portid);
    char reply[kNetlinkBufferBytes];
    int acknowledged = 0;
    for (;;) {
        const auto received = mnl_socket_recvfrom(nl, reply, sizeof(reply));
        if (received < 0) {
            std::perror("isolation-ruleset: mnl_socket_recvfrom");
            std::fprintf(stderr, "isolation-ruleset: %d ack(s) processed before this failure\n", acknowledged);
            mnl_socket_close(nl);
            return false;
        }
        if (received == 0) break;
        const auto result = mnl_cb_run(reply, static_cast<std::size_t>(received), 0, portid, on_ack, &acknowledged);
        if (result < 0) {
            // ENOENT here means "delete a table that doesn't exist yet" --
            // the expected first-run/idempotent-release case, not a real
            // failure. Any other error still fails the whole batch.
            if (errno == ENOENT) continue;
            std::fprintf(stderr, "isolation-ruleset: mnl_cb_run: %s\n", std::strerror(errno));
            mnl_socket_close(nl);
            return false;
        }
        if (result == MNL_CB_STOP) break;
    }
    mnl_socket_close(nl);
    return true;
}

// Appends "match register 1 == value (len bytes), else fall through" and
// then an unconditional accept verdict -- the shared tail of every
// exception rule this ruleset defines.
void append_accept_after_match(nftnl_rule* rule) {
    nftnl_expr* verdict = nftnl_expr_alloc("immediate");
    nftnl_expr_set_u32(verdict, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(verdict, NFTNL_EXPR_IMM_VERDICT, NF_ACCEPT);
    nftnl_rule_add_expr(rule, verdict);
}

void append_cmp_eq(nftnl_rule* rule, const void* data, const std::uint32_t length) {
    nftnl_expr* cmp = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(cmp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(cmp, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set(cmp, NFTNL_EXPR_CMP_DATA, data, length);
    nftnl_rule_add_expr(rule, cmp);
}

void append_meta_load(nftnl_rule* rule, const std::uint32_t key) {
    nftnl_expr* meta = nftnl_expr_alloc("meta");
    nftnl_expr_set_u32(meta, NFTNL_EXPR_META_KEY, key);
    nftnl_expr_set_u32(meta, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, meta);
}

void append_payload_load(nftnl_rule* rule, const std::uint32_t base, const std::uint32_t offset, const std::uint32_t length) {
    nftnl_expr* payload = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_LEN, length);
    nftnl_rule_add_expr(rule, payload);
}

// Builds "match loopback ingress/egress, accept" for the given chain,
// selecting the interface-index meta key by direction.
nftnl_rule* loopback_accept_rule(const std::string_view chain, const std::uint32_t meta_key) {
    nftnl_rule* rule = nftnl_rule_alloc();
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, std::string{kIsolationTableName}.c_str());
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, std::string{chain}.c_str());
    append_meta_load(rule, meta_key);
    constexpr std::uint32_t loopback_ifindex{1U};
    append_cmp_eq(rule, &loopback_ifindex, sizeof(loopback_ifindex));
    append_accept_after_match(rule);
    return rule;
}

// Builds "match TCP + <address payload offset> == manager_ip + <port
// payload offset> == manager_port, accept" -- the one pinned exception
// besides loopback. `address_offset`/`port_offset` select source vs.
// destination fields, so the same builder serves both directions.
nftnl_rule* manager_pinned_accept_rule(const std::string_view chain, const std::uint32_t address_offset,
                                       const std::uint32_t port_offset, const std::uint32_t manager_ipv4_network_order,
                                       const std::uint16_t manager_port) {
    nftnl_rule* rule = nftnl_rule_alloc();
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, std::string{kIsolationTableName}.c_str());
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, std::string{chain}.c_str());

    append_meta_load(rule, NFT_META_L4PROTO);
    const std::uint8_t tcp_protocol{IPPROTO_TCP};
    append_cmp_eq(rule, &tcp_protocol, sizeof(tcp_protocol));

    append_payload_load(rule, NFT_PAYLOAD_NETWORK_HEADER, address_offset, sizeof(std::uint32_t));
    append_cmp_eq(rule, &manager_ipv4_network_order, sizeof(manager_ipv4_network_order));

    append_payload_load(rule, NFT_PAYLOAD_TRANSPORT_HEADER, port_offset, sizeof(std::uint16_t));
    const auto port_network_order = static_cast<std::uint16_t>((manager_port << 8U) | (manager_port >> 8U));
    append_cmp_eq(rule, &port_network_order, sizeof(port_network_order));

    append_accept_after_match(rule);
    return rule;
}

nftnl_chain* base_chain(const std::string_view name, const std::uint32_t hook) {
    nftnl_chain* chain = nftnl_chain_alloc();
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, std::string{kIsolationTableName}.c_str());
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, std::string{name}.c_str());
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "filter");
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, hook);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 0U);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_POLICY, NF_DROP);
    return chain;
}

}  // namespace

result<bool> apply_isolation_ruleset(const std::uint32_t manager_ipv4_network_order, const std::uint16_t manager_port) {
    // Idempotent: release whatever isolation state (if any) exists first,
    // then re-create the fixed ruleset from scratch in the same batch.
    // Offsets: IPv4 header saddr/daddr are always at bytes 12/16; TCP
    // header sport/dport are always at bytes 0/2 -- fixed by protocol, not
    // configuration, so no bounds/validation branch is needed here.
    char raw_buffer[16U * kNetlinkBufferBytes];
    mnl_nlmsg_batch* batch = mnl_nlmsg_batch_start(raw_buffer, sizeof(raw_buffer));
    std::uint32_t seq = static_cast<std::uint32_t>(std::time(nullptr));

    nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    // Tear down any prior instance of our table (ignored by the kernel if
    // absent -- NLM_F_ACK without NLM_F_EXCL/NLM_F_CREATE on a delete of a
    // nonexistent table is simply not part of this batch's failure path
    // because we do not check this specific message's individual ack).
    nftnl_table* doomed = nftnl_table_alloc();
    nftnl_table_set_str(doomed, NFTNL_TABLE_NAME, std::string{kIsolationTableName}.c_str());
    nftnl_table_set_u32(doomed, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_DELTABLE,
                                                 NFPROTO_INET, 0U, seq++);
    nftnl_table_nlmsg_build_payload(nlh, doomed);
    nftnl_table_free(doomed);
    mnl_nlmsg_batch_next(batch);

    nftnl_table* table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, std::string{kIsolationTableName}.c_str());
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    nlh = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWTABLE, NFPROTO_INET,
                                       NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    for (const auto& [name, hook] : {std::pair{kIsolationInputChainName, static_cast<std::uint32_t>(NF_INET_LOCAL_IN)},
                                      std::pair{kIsolationOutputChainName, static_cast<std::uint32_t>(NF_INET_LOCAL_OUT)}}) {
        nftnl_chain* chain = base_chain(name, hook);
        nlh = nftnl_chain_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWCHAIN,
                                           NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, seq++);
        nftnl_chain_nlmsg_build_payload(nlh, chain);
        nftnl_chain_free(chain);
        mnl_nlmsg_batch_next(batch);
    }

    const auto add_rule = [&](nftnl_rule* rule) {
        nlmsghdr* rule_header = nftnl_rule_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWRULE,
                                                            NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, seq++);
        nftnl_rule_nlmsg_build_payload(rule_header, rule);
        nftnl_rule_free(rule);
        mnl_nlmsg_batch_next(batch);
    };

    add_rule(loopback_accept_rule(kIsolationInputChainName, NFT_META_IIF));
    add_rule(manager_pinned_accept_rule(kIsolationInputChainName, 12U /* IPv4 saddr */, 0U /* TCP sport */,
                                        manager_ipv4_network_order, manager_port));
    add_rule(loopback_accept_rule(kIsolationOutputChainName, NFT_META_OIF));
    add_rule(manager_pinned_accept_rule(kIsolationOutputChainName, 16U /* IPv4 daddr */, 2U /* TCP dport */,
                                        manager_ipv4_network_order, manager_port));

    nftnl_batch_end(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    const bool ok = commit_batch(batch);
    mnl_nlmsg_batch_stop(batch);
    if (!ok) return error{error_code::io_failure, "isolation ruleset could not be applied via netlink"};
    return true;
}

result<bool> release_isolation_ruleset() {
    char raw_buffer[8U * kNetlinkBufferBytes];
    mnl_nlmsg_batch* batch = mnl_nlmsg_batch_start(raw_buffer, sizeof(raw_buffer));
    std::uint32_t seq = static_cast<std::uint32_t>(std::time(nullptr));

    nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    // Real nft(8) client behavior when deleting a table (see nftables'
    // src/rule.c do_command_delete): every base chain is torn down with its
    // own NFT_MSG_DELCHAIN first, because deleting a *hooked* base chain
    // means unregistering its netfilter hook -- collapsing that into a bare
    // NFT_MSG_DELTABLE on a table with active hooked chains produced no
    // netlink reply at all (confirmed on real CI: zero bytes received
    // within a 5s timeout, not even an error ack), which is exactly what
    // caused the original indefinite hang this whole ADR 004 e2e test was
    // added to catch. NLM_F_ACK on every message here is required, not
    // optional, precisely because of that -- a batch must never be built
    // with no reply expected from any of its messages.
    for (const auto& chain_name : {kIsolationInputChainName, kIsolationOutputChainName}) {
        nftnl_chain* chain = nftnl_chain_alloc();
        nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, std::string{kIsolationTableName}.c_str());
        nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, std::string{chain_name}.c_str());
        nlmsghdr* chain_header = nftnl_chain_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)),
                                                              NFT_MSG_DELCHAIN, NFPROTO_INET, NLM_F_ACK, seq++);
        nftnl_chain_nlmsg_build_payload(chain_header, chain);
        nftnl_chain_free(chain);
        mnl_nlmsg_batch_next(batch);
    }

    nftnl_table* table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, std::string{kIsolationTableName}.c_str());
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_DELTABLE,
                                                 NFPROTO_INET, NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    const bool ok = commit_batch(batch);
    mnl_nlmsg_batch_stop(batch);
    if (!ok) return error{error_code::io_failure, "isolation ruleset could not be released via netlink"};
    return true;
}

}  // namespace panopticon::linux_agent
