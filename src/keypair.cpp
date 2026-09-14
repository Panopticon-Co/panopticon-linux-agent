#include "panopticon/linux_agent/keypair.hpp"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#ifdef __linux__
#include <sys/stat.h>
#endif

namespace panopticon::linux_agent {

namespace {

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

EvpPkeyPtr make_pkey(EVP_PKEY* raw) { return EvpPkeyPtr{raw, EVP_PKEY_free}; }

// Imports an OpenSSL DER-serialized (SEC1 ECPrivateKey / traditional
// format, as produced by i2d_PrivateKey below) private key back into an
// EVP_PKEY. Returns nullptr on any malformed input -- never partially
// trusted.
EvpPkeyPtr import_private_der(const std::vector<std::uint8_t>& der) {
    const std::uint8_t* cursor = der.data();
    EVP_PKEY* raw = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &cursor, static_cast<long>(der.size()));
    return make_pkey(raw);
}

result<ec_public_key_point> export_public_point(EVP_PKEY* pkey) {
    std::uint8_t* buffer = nullptr;
    const int length = EVP_PKEY_get1_encoded_public_key(pkey, &buffer);
    if (length != 65 || buffer == nullptr) {
        if (buffer != nullptr) OPENSSL_free(buffer);
        return error{error_code::io_failure, "unexpected EC public key encoding"};
    }
    ec_public_key_point point{};
    std::memcpy(point.data(), buffer, point.size());
    OPENSSL_free(buffer);
    if (point[0] != 0x04) {
        return error{error_code::io_failure, "EC public key is not an uncompressed point"};
    }
    return point;
}

}  // namespace

result<ec_keypair> generate_ec_p256_keypair() {
    EvpCtxPtr paramgen_ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free};
    if (!paramgen_ctx || EVP_PKEY_keygen_init(paramgen_ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramgen_ctx.get(), NID_X9_62_prime256v1) <= 0) {
        return error{error_code::io_failure, "cannot initialize ECDSA P-256 key generation"};
    }
    EVP_PKEY* generated = nullptr;
    if (EVP_PKEY_keygen(paramgen_ctx.get(), &generated) <= 0 || generated == nullptr) {
        return error{error_code::io_failure, "cannot generate ECDSA P-256 key pair"};
    }
    auto pkey = make_pkey(generated);

    auto public_point = export_public_point(pkey.get());
    if (!succeeded(public_point)) return std::get<error>(public_point);

    std::uint8_t* der_buffer = nullptr;
    const int der_length = i2d_PrivateKey(pkey.get(), &der_buffer);
    if (der_length <= 0 || der_buffer == nullptr) {
        if (der_buffer != nullptr) OPENSSL_free(der_buffer);
        return error{error_code::io_failure, "cannot serialize ECDSA private key"};
    }
    ec_keypair result_pair;
    result_pair.private_der.assign(der_buffer, der_buffer + der_length);
    OPENSSL_free(der_buffer);
    result_pair.public_point = std::get<ec_public_key_point>(public_point);
    return result_pair;
}

result<ec_raw_signature> sign_raw(const ec_keypair& keypair, const std::vector<std::uint8_t>& data) {
    auto pkey = import_private_der(keypair.private_der);
    if (!pkey) {
        return error{error_code::corrupt_data, "cannot import ECDSA private key for signing"};
    }

    EvpMdCtxPtr md_ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!md_ctx || EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
        return error{error_code::io_failure, "cannot initialize ECDSA signing"};
    }
    std::size_t signature_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &signature_len, data.data(), data.size()) <= 0) {
        return error{error_code::io_failure, "cannot size ECDSA signature"};
    }
    std::vector<std::uint8_t> der_signature(signature_len);
    if (EVP_DigestSign(md_ctx.get(), der_signature.data(), &signature_len, data.data(), data.size()) <= 0) {
        return error{error_code::io_failure, "cannot produce ECDSA signature"};
    }
    der_signature.resize(signature_len);

    const std::uint8_t* cursor = der_signature.data();
    EcdsaSigPtr sig{d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der_signature.size())), ECDSA_SIG_free};
    if (!sig) {
        return error{error_code::io_failure, "cannot decode ECDSA signature"};
    }
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    ec_raw_signature raw{};
    if (BN_bn2binpad(r, raw.data(), 32) != 32 || BN_bn2binpad(s, raw.data() + 32, 32) != 32) {
        return error{error_code::io_failure, "cannot encode ECDSA signature as raw r||s"};
    }
    return raw;
}

result<bool> store_ec_keypair(const std::filesystem::path& path, const ec_keypair& keypair) {
    std::error_code filesystem_error;
    std::filesystem::create_directories(path.parent_path(), filesystem_error);
    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output{temporary, std::ios::trunc | std::ios::binary};
        if (!output) return error{error_code::io_failure, "cannot write key file"};
        const auto size = static_cast<std::uint32_t>(keypair.private_der.size());
        output.write(reinterpret_cast<const char*>(&size), sizeof(size));
        output.write(reinterpret_cast<const char*>(keypair.private_der.data()), keypair.private_der.size());
        output.flush();
        if (!output) return error{error_code::io_failure, "cannot persist key file"};
    }
#ifdef __linux__
    if (chmod(temporary.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::filesystem::remove(temporary, filesystem_error);
        return error{error_code::io_failure, "cannot protect key file"};
    }
#endif
    std::filesystem::rename(temporary, path, filesystem_error);
    if (filesystem_error) {
        std::filesystem::remove(temporary, filesystem_error);
        return error{error_code::io_failure, "cannot publish key file"};
    }
    return true;
}

result<ec_keypair> load_ec_keypair(const std::filesystem::path& path) {
#ifdef __linux__
    struct stat details {};
    if (stat(path.c_str(), &details) == 0 && S_ISREG(details.st_mode) &&
        (details.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return error{error_code::invalid_input, "key file must be private (not group/world accessible)"};
    }
#endif
    std::ifstream input{path, std::ios::binary};
    if (!input) return error{error_code::io_failure, "key file is absent"};
    std::uint32_t size = 0;
    input.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!input || size == 0 || size > 4096) {
        return error{error_code::corrupt_data, "key file is truncated or has an implausible size"};
    }
    std::vector<std::uint8_t> private_der(size);
    input.read(reinterpret_cast<char*>(private_der.data()), size);
    if (!input || static_cast<std::uint32_t>(input.gcount()) != size) {
        return error{error_code::corrupt_data, "key file is truncated"};
    }

    auto pkey = import_private_der(private_der);
    if (!pkey) {
        return error{error_code::corrupt_data, "key file does not contain a valid ECDSA P-256 private key"};
    }
    auto public_point = export_public_point(pkey.get());
    if (!succeeded(public_point)) return std::get<error>(public_point);

    ec_keypair result_pair;
    result_pair.private_der = std::move(private_der);
    result_pair.public_point = std::get<ec_public_key_point>(public_point);
    return result_pair;
}

}  // namespace panopticon::linux_agent
