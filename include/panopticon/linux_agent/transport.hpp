#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/identity.hpp"
#include "panopticon/linux_agent/keypair.hpp"
#include "panopticon/linux_agent/spool.hpp"

#include <cstddef>
#include <string>

namespace panopticon::linux_agent {

enum class transport_outcome { acknowledged, retryable, authentication_failed, rejected };

class https_client {
public:
    virtual ~https_client() = default;
    virtual transport_outcome post_ndjson(const std::string& https_url, const enrolled_identity& identity,
                                          const std::string& payload) = 0;
};

class curl_https_client final : public https_client {
public:
    explicit curl_https_client(long timeout_seconds = 15L, std::size_t maximum_response_bytes = 65536U);
    transport_outcome post_ndjson(const std::string& https_url, const enrolled_identity& identity,
                                  const std::string& payload) override;
    // Phase 13: requests a one-time, short-TTL nonce for enrollment proof
    // of possession. No authentication required or possible to misuse --
    // a nonce alone proves and authorizes nothing without a subsequent
    // valid bootstrap token and a real signature over it.
    [[nodiscard]] result<std::string> request_enrollment_challenge(const std::string& manager_url) const;

    // Bootstrap is deliberately a separate operation: the bootstrap secret is
    // never persisted as an enrolled credential and is sent only over verified TLS.
    // Phase 13: also proves possession of `keypair`'s private key by signing
    // `nonce_b64` (as returned by request_enrollment_challenge, verbatim) --
    // see panopticon-manager/docs/adr/004-agent-enrollment-identity.md.
    [[nodiscard]] result<enrolled_identity> enroll(const std::string& manager_url, const std::string& agent_id,
                                                    const std::string& host_id, const std::string& bootstrap_token,
                                                    const ec_keypair& keypair, const std::string& nonce_b64) const;
    [[nodiscard]] result<std::string> poll_commands(const std::string& manager_url,
                                                     const enrolled_identity& identity) const;
    // Optional DISPATCHED -> ACCEPTED acknowledgement (POST .../commands/{id}/accept),
    // sent after this agent has validated a polled command and before it starts
    // executing it. Best-effort: Manager treats a result submitted straight from
    // DISPATCHED as legal too, so a failure here never blocks execution -- callers
    // should ignore the outcome and proceed to execute regardless.
    [[nodiscard]] transport_outcome accept_command(const std::string& manager_url, const enrolled_identity& identity,
                                                    const std::string& command_id) const;
    [[nodiscard]] transport_outcome submit_command_result(const std::string& manager_url,
                                                           const enrolled_identity& identity,
                                                           const std::string& payload) const;
private:
    long timeout_seconds_;
    std::size_t maximum_response_bytes_;
};

// Drains only acknowledged records. Retryable, auth, and rejection outcomes retain
// evidence durably for operator action/retry; no transport implementation may disable TLS.
[[nodiscard]] result<std::size_t> drain_spool(durable_spool& spool, https_client& client,
                                               const std::string& https_url, const enrolled_identity& identity,
                                               std::size_t maximum_records, std::size_t maximum_batch_bytes);
}  // namespace panopticon::linux_agent
