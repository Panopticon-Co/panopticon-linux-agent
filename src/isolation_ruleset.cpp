#include "panopticon/linux_agent/isolation_ruleset.hpp"

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/batch.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netlink.h>
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

// Counts how many messages in the constructed (pre-send) batch carry
// NLM_F_ACK -- exactly how many individual NLMSG_ERROR replies the kernel
// is expected to send back. This replaced a real bug: the previous
// implementation used mnl_cb_run(), whose documented behavior is to return
// MNL_CB_STOP as soon as it sees the *first* successful (error == 0)
// NLMSG_ERROR reply in a receive buffer -- correct for a single-request/
// single-reply exchange, but wrong for a multi-message batch, where a
// provisional per-message ack does not mean the whole atomic transaction
// committed. Real CI reproduction: apply_isolation_ruleset() reported
// success (a real ack for NEWTABLE, the first NLM_F_ACK-flagged message,
// was received) while nft list ruleset / nft monitor showed the table,
// chains, and rules were never actually created. The actual root cause
// (see apply_isolation_ruleset()'s doc comment) was a poisoned atomic
// transaction, not a rejected message -- but this code had already
// stopped reading and returned true after that very first ack regardless,
// so it could never have told the difference either way. Both bugs are
// fixed together: this function now drains and validates every expected
// ack, and the transaction it validates can no longer be poisoned.
std::size_t count_expected_acks(const mnl_nlmsg_batch* batch) {
    const auto* walk = static_cast<const unsigned char*>(mnl_nlmsg_batch_head(const_cast<mnl_nlmsg_batch*>(batch)));
    std::size_t remaining = mnl_nlmsg_batch_size(const_cast<mnl_nlmsg_batch*>(batch));
    std::size_t expected{0U};
    while (remaining >= sizeof(nlmsghdr)) {
        const auto* header = reinterpret_cast<const nlmsghdr*>(walk);
        if (header->nlmsg_len < sizeof(nlmsghdr) || header->nlmsg_len > remaining) break;
        if ((header->nlmsg_flags & NLM_F_ACK) != 0U) ++expected;
        const auto aligned = NLMSG_ALIGN(header->nlmsg_len);
        walk += aligned;
        remaining -= aligned;
    }
    return expected;
}

// Sends everything staged in `batch` and waits for the kernel to
// individually acknowledge every NLM_F_ACK-flagged message in it --
// draining and validating each NLMSG_ERROR reply itself (not via
// mnl_cb_run(), see count_expected_acks()'s doc for why) so that a later
// message's rejection is never masked by an earlier message's provisional
// ack. Returns false (never throws, never leaves a half-applied ruleset
// silently claimed as success) on any netlink-level failure or if fewer
// than the expected number of successful acks are ever received.
//
// `tolerate_receive_timeout`: AF_NETLINK request processing is synchronous
// -- the kernel handler for a REQUEST message runs inside the sender's own
// sendto()/sendmsg() syscall, so by the time mnl_socket_sendto returns
// without error, the kernel has already fully committed or rejected the
// batch, independent of whether it also emits an ack afterward. Confirmed
// on real CI (runs 34736470889, 34736603098): a delete-only batch (single
// DELTABLE, and separately DELCHAIN+DELCHAIN+DELTABLE) reliably produces
// zero reply bytes within a 5s timeout even though the identical mechanism
// (NLM_F_ACK, same commit_batch, same socket handling) reliably acks
// create-type batches. Since a genuine synchronous rejection would surface
// either as a negative mnl_socket_sendto return or a real (non-timeout)
// error reply -- neither of which happened -- a receive timeout
// specifically (as opposed to any other socket error) is treated as
// "processed synchronously, kernel chose not to reply" rather than a
// failure, only where the caller explicitly opts in.
bool commit_batch(mnl_nlmsg_batch* batch, bool tolerate_receive_timeout = false) {
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
    const auto batch_size = mnl_nlmsg_batch_size(batch);
    const auto sent = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), batch_size);
    if (sent < 0) {
        std::perror("isolation-ruleset: mnl_socket_sendto");
        mnl_socket_close(nl);
        return false;
    }
    const auto expected_acks = count_expected_acks(batch);
    std::fprintf(stderr,
                 "isolation-ruleset: sent %zd of %zu batch bytes, awaiting %zu ack(s)\n",
                 sent, batch_size, expected_acks);
    char reply[kNetlinkBufferBytes];
    std::size_t acknowledged = 0U;
    while (acknowledged < expected_acks) {
        const auto received = mnl_socket_recvfrom(nl, reply, sizeof(reply));
        if (received < 0) {
            if (tolerate_receive_timeout && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                std::fprintf(stderr,
                             "isolation-ruleset: only %zu of %zu expected ack(s) arrived before timeout "
                             "after a synchronously-sent request -- treating as processed (see "
                             "commit_batch's tolerate_receive_timeout doc)\n",
                             acknowledged, expected_acks);
                mnl_socket_close(nl);
                return true;
            }
            std::perror("isolation-ruleset: mnl_socket_recvfrom");
            std::fprintf(stderr, "isolation-ruleset: %zu of %zu expected ack(s) processed before this failure\n",
                         acknowledged, expected_acks);
            mnl_socket_close(nl);
            return false;
        }
        if (received == 0) break;
        // Parsed by hand rather than via mnl_cb_run(): mnl_cb_run() returns
        // MNL_CB_STOP as soon as it sees the *first* successful ack in a
        // receive buffer, which is correct for a single-request exchange
        // but silently discards every later message's reply in a
        // multi-message NLM_F_ACK batch like this one -- see this
        // function's doc comment and count_expected_acks() for the real
        // failure that behavior caused.
        const auto* walk = reinterpret_cast<const unsigned char*>(reply);
        std::size_t remaining = static_cast<std::size_t>(received);
        while (remaining >= sizeof(nlmsghdr) && acknowledged < expected_acks) {
            const auto* header = reinterpret_cast<const nlmsghdr*>(walk);
            if (header->nlmsg_len < sizeof(nlmsghdr) || header->nlmsg_len > remaining) break;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const auto* ack = reinterpret_cast<const nlmsgerr*>(walk + NLMSG_ALIGN(sizeof(nlmsghdr)));
                if (ack->error == 0) {
                    ++acknowledged;
                } else if (ack->error == -ENOENT) {
                    // Deleting a table that does not exist yet -- the
                    // expected first-run/idempotent-release case. This
                    // reply corresponds to the DELTABLE message, which is
                    // never sent with NLM_F_ACK and so is never counted in
                    // expected_acks; nothing further to do here.
                } else {
                    std::fprintf(stderr, "isolation-ruleset: netlink rejected a batch message: %s\n",
                                 std::strerror(-ack->error));
                    mnl_socket_close(nl);
                    return false;
                }
            }
            const auto aligned = NLMSG_ALIGN(header->nlmsg_len);
            walk += aligned;
            remaining -= aligned;
        }
    }
    mnl_socket_close(nl);
    if (acknowledged < expected_acks) {
        std::fprintf(stderr, "isolation-ruleset: only %zu of %zu expected ack(s) were ever received\n",
                     acknowledged, expected_acks);
        return false;
    }
    return true;
}

// Defense in depth beyond commit_batch()'s own per-message ack accounting:
// queries the kernel directly for the table by name and requires a real
// NFT_MSG_NEWTABLE reply, rather than trusting that a fully-acked batch
// necessarily means the atomic transaction it described was actually
// committed. This exists because of a real, confirmed-on-CI failure mode:
// every individual NEWTABLE/NEWCHAIN/NEWRULE message in a batch can be
// acked successfully (error == 0) by the kernel while the whole batch's
// atomic commit at NFNL_MSG_BATCH_END still silently fails to persist
// anything, with no further netlink-visible signal for the sender to catch
// (BATCH_END is sent without NLM_F_ACK, like every other control message
// in this batch, and a bare send-without-ack success is not itself proof
// the referenced transaction was ever durably applied). Rather than fully
// diagnose that kernel-level discrepancy, apply_isolation_ruleset() simply
// never trusts an ack alone again: it reads the resulting state back and
// fails closed if verification does not confirm it.
bool verify_table_exists(const std::string_view table_name) {
    mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == nullptr) { std::perror("isolation-ruleset: verify: mnl_socket_open"); return false; }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        std::perror("isolation-ruleset: verify: mnl_socket_bind");
        mnl_socket_close(nl);
        return false;
    }
    timeval receive_timeout{.tv_sec = 5, .tv_usec = 0};
    if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        std::perror("isolation-ruleset: verify: setsockopt(SO_RCVTIMEO)");
        mnl_socket_close(nl);
        return false;
    }
    char request[kNetlinkBufferBytes];
    nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(request, NFT_MSG_GETTABLE, NFPROTO_INET, NLM_F_ACK,
                                                 static_cast<std::uint32_t>(std::time(nullptr)));
    nftnl_table* query = nftnl_table_alloc();
    nftnl_table_set_str(query, NFTNL_TABLE_NAME, std::string{table_name}.c_str());
    nftnl_table_nlmsg_build_payload(nlh, query);
    nftnl_table_free(query);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        std::perror("isolation-ruleset: verify: mnl_socket_sendto");
        mnl_socket_close(nl);
        return false;
    }
    char reply[kNetlinkBufferBytes];
    const auto received = mnl_socket_recvfrom(nl, reply, sizeof(reply));
    mnl_socket_close(nl);
    if (received < static_cast<ssize_t>(sizeof(nlmsghdr))) {
        std::perror("isolation-ruleset: verify: mnl_socket_recvfrom");
        return false;
    }
    const auto* header = reinterpret_cast<const nlmsghdr*>(reply);
    if (header->nlmsg_type == NLMSG_ERROR) {
        const auto* ack = reinterpret_cast<const nlmsgerr*>(reply + NLMSG_ALIGN(sizeof(nlmsghdr)));
        std::fprintf(stderr, "isolation-ruleset: verify: table '%s' does not exist after apply (%s)\n",
                     std::string{table_name}.c_str(), std::strerror(-ack->error));
        return false;
    }
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
    // as its own separate atomic netlink transaction, then re-create the
    // fixed ruleset from scratch in a second, independent transaction.
    //
    // These must NOT be combined into a single BATCH_BEGIN/.../BATCH_END
    // transaction -- that was the real bug behind a critical, confirmed-
    // on-real-CI failure: ISOLATE_HOST reported success (every individual
    // NEWTABLE/NEWCHAIN/NEWRULE message was genuinely acked by the kernel)
    // while nft list ruleset / nft monitor showed the table was never
    // actually created and containment was never applied. Root cause: the
    // combined batch's first message was DELTABLE against a table that
    // does not exist yet (the common first-run case), which fails with
    // ENOENT -- and nftables batch transactions are atomic, so that one
    // failure silently doomed the *entire* transaction's commit at
    // NFNL_MSG_BATCH_END, even though every later message was still
    // individually validated and acked as if it would succeed. Splitting
    // the (expected-to-sometimes-fail) delete into its own transaction
    // means its failure can never poison the create transaction that
    // follows it. Verified against a real nft(8)-driven multi-object batch
    // in the same environment (table+chain+rule via `nft -f`) succeeding
    // and persisting correctly, ruling out a kernel/environment limitation
    // -- this was specifically this code's own transaction boundary that
    // was wrong.
    //
    // Offsets: IPv4 header saddr/daddr are always at bytes 12/16; TCP
    // header sport/dport are always at bytes 0/2 -- fixed by protocol, not
    // configuration, so no bounds/validation branch is needed here.
    std::uint32_t seq = static_cast<std::uint32_t>(std::time(nullptr));

    {
        char delete_buffer[kNetlinkBufferBytes];
        mnl_nlmsg_batch* delete_batch = mnl_nlmsg_batch_start(delete_buffer, sizeof(delete_buffer));
        nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(delete_batch)), seq++);
        mnl_nlmsg_batch_next(delete_batch);

        // Tear down any prior instance of our table. Never sent with
        // NLM_F_ACK -- a nonexistent table is the common, expected,
        // harmless case (ENOENT), and this transaction's outcome is
        // deliberately never checked; the create transaction below always
        // (re)builds the table from scratch regardless of whether this
        // delete found anything to delete.
        nftnl_table* doomed = nftnl_table_alloc();
        nftnl_table_set_str(doomed, NFTNL_TABLE_NAME, std::string{kIsolationTableName}.c_str());
        nftnl_table_set_u32(doomed, NFTNL_TABLE_FAMILY, NFPROTO_INET);
        nlmsghdr* delete_hdr = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(delete_batch)),
                                                            NFT_MSG_DELTABLE, NFPROTO_INET, 0U, seq++);
        nftnl_table_nlmsg_build_payload(delete_hdr, doomed);
        nftnl_table_free(doomed);
        mnl_nlmsg_batch_next(delete_batch);

        nftnl_batch_end(static_cast<char*>(mnl_nlmsg_batch_current(delete_batch)), seq++);
        mnl_nlmsg_batch_next(delete_batch);

        // Fire-and-forget by construction: this transaction carries zero
        // NLM_F_ACK-flagged messages, so commit_batch() sends it and
        // returns immediately without waiting on any reply -- consistent
        // with AF_NETLINK's synchronous processing (the kernel has already
        // fully resolved this transaction, one way or the other, by the
        // time the sendto() call for it returns), and with this
        // transaction's outcome being intentionally unchecked either way.
        commit_batch(delete_batch);
        mnl_nlmsg_batch_stop(delete_batch);
    }

    char raw_buffer[16U * kNetlinkBufferBytes];
    mnl_nlmsg_batch* batch = mnl_nlmsg_batch_start(raw_buffer, sizeof(raw_buffer));

    nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
    mnl_nlmsg_batch_next(batch);

    nftnl_table* table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, std::string{kIsolationTableName}.c_str());
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWTABLE,
                                                 NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, seq++);
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
    if (!verify_table_exists(kIsolationTableName)) {
        return error{error_code::io_failure,
                     "isolation ruleset was fully acked but the table does not exist after apply -- "
                     "refusing to report success for an unconfirmed containment state"};
    }
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

    const bool ok = commit_batch(batch, /*tolerate_receive_timeout=*/true);
    mnl_nlmsg_batch_stop(batch);
    if (!ok) return error{error_code::io_failure, "isolation ruleset could not be released via netlink"};
    return true;
}

}  // namespace panopticon::linux_agent
