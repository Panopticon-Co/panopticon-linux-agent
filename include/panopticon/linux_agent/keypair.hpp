#pragma once

// Phase 13: the endpoint-held half of enrollment cryptographic identity
// (panopticon-manager/docs/adr/004-agent-enrollment-identity.md). Built on
// OpenSSL (libssl-dev), added as a new but extremely standard dependency --
// this repository had no asymmetric-crypto library before this. ECDSA
// P-256, matching the Windows agent's Windows-CNG-based implementation and
// panopticon-manager's verification.

#include "panopticon/linux_agent/error.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace panopticon::linux_agent {

// Raw uncompressed NIST P-256 point: 0x04 || X (32 bytes) || Y (32 bytes) --
// the exact wire format panopticon-contracts/schema/enrollment_request.schema.json
// expects for public_key.
using ec_public_key_point = std::array<std::uint8_t, 65>;

// Raw r||s ECDSA signature (32 + 32 bytes) -- IEEE P1363 format, matching
// the corrected (non-DER) wire contract and the Windows agent's CNG output.
using ec_raw_signature = std::array<std::uint8_t, 64>;

// An ECDSA P-256 keypair. private_der is OpenSSL's own DER (SEC1
// ECPrivateKey) serialization -- opaque to everything except
// load_ec_keypair/sign_raw below, never hand-parsed or reconstructed.
struct ec_keypair {
    std::vector<std::uint8_t> private_der;
    ec_public_key_point public_point{};
};

// Generates a brand-new P-256 keypair. The private key exists only in
// memory until store_ec_keypair persists it.
[[nodiscard]] result<ec_keypair> generate_ec_p256_keypair();

// Signs `data` with SHA-256 then ECDSA and returns the raw 64-byte r||s
// signature (converted from OpenSSL's native DER signature output).
[[nodiscard]] result<ec_raw_signature> sign_raw(const ec_keypair& keypair, const std::vector<std::uint8_t>& data);

// Persists a keypair's private key to `path` (0600, write-temp-then-rename)
// so a crash mid-write never leaves a partial, ambiguous key file behind.
[[nodiscard]] result<bool> store_ec_keypair(const std::filesystem::path& path, const ec_keypair& keypair);

// Loads a previously stored keypair. Fails closed on a missing, truncated,
// or otherwise unimportable file -- never silently regenerated, since that
// would discard an already-enrolled identity binding without saying so.
[[nodiscard]] result<ec_keypair> load_ec_keypair(const std::filesystem::path& path);

}  // namespace panopticon::linux_agent
