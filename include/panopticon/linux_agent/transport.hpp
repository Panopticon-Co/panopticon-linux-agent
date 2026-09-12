#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/identity.hpp"
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
private:
    long timeout_seconds_;
    std::size_t maximum_response_bytes_;
};

// Drains only acknowledged records. Retryable, auth, and rejection outcomes retain
// evidence durably for operator action/retry; no transport implementation may disable TLS.
[[nodiscard]] result<std::size_t> drain_spool(durable_spool& spool, https_client& client,
                                               const std::string& https_url, const enrolled_identity& identity,
                                               std::size_t maximum_records);
}  // namespace panopticon::linux_agent
