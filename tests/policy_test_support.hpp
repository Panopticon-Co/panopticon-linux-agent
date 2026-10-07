#pragma once

// Signing of ADR 032 policy bundles for tests: the endpoint only verifies, so the tests sign.

#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/keypair.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/sensor/policy_bundle.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace policy_test_support {

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

inline std::string base64(const std::uint8_t* data, const std::size_t size) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t index = 0U; index < size; index += 3U) {
        std::uint32_t group = static_cast<std::uint32_t>(data[index]) << 16U;
        if (index + 1U < size) group |= static_cast<std::uint32_t>(data[index + 1U]) << 8U;
        if (index + 2U < size) group |= data[index + 2U];
        out.push_back(alphabet[(group >> 18U) & 63U]);
        out.push_back(alphabet[(group >> 12U) & 63U]);
        out.push_back(index + 1U < size ? alphabet[(group >> 6U) & 63U] : '=');
        out.push_back(index + 2U < size ? alphabet[group & 63U] : '=');
    }
    return out;
}

inline ec_keypair make_key() {
    auto generated = generate_ec_p256_keypair();
    if (!succeeded(generated)) throw std::runtime_error{"cannot generate a test key"};
    return std::get<ec_keypair>(generated);
}

// One line of a policy_signing_keys file.
inline std::string key_line(const ec_keypair& key) { return base64(key.public_point.data(), key.public_point.size()) + " test\n"; }

struct bundle_fields {
    std::string policy_id{"test-policy"};
    std::uint64_t version{1U};
    std::int64_t issued_unix{};
    std::int64_t expires_unix{};
    std::string scope{"all"};
};

// The complete file: header with key_id and signature, `---`, body.
inline std::string signed_bundle(const ec_keypair& key, const bundle_fields& fields, const std::string& body) {
    policy_header header;
    header.policy_id = fields.policy_id;
    header.version = fields.version;
    header.issued_unix = fields.issued_unix;
    header.expires_unix = fields.expires_unix;
    header.scope = fields.scope;
    const auto input = policy_signing_input(header, sha256_hex(body));
    const auto signature = sign_raw(key, std::vector<std::uint8_t>(input.begin(), input.end()));
    if (!succeeded(signature)) throw std::runtime_error{"cannot sign a test policy"};
    const auto& raw = std::get<ec_raw_signature>(signature);
    return "panopticon-policy 1\npolicy_id " + fields.policy_id + "\nversion " + std::to_string(fields.version) + "\nissued_at " +
           std::to_string(fields.issued_unix) + "\nexpires_at " + std::to_string(fields.expires_unix) + "\nscope " + fields.scope + "\nkey_id " +
           signing_key_id(key.public_point) + "\nsignature " + base64(raw.data(), raw.size()) + "\n---\n" + body;
}

}  // namespace policy_test_support
