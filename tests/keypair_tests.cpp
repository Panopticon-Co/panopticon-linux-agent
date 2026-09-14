#include "panopticon/linux_agent/keypair.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using namespace panopticon::linux_agent;

void require(const bool condition, const std::string_view message) {
    if (!condition) {
        throw std::runtime_error{std::string{message}};
    }
}

std::filesystem::path scratch_path(const char* label) {
    const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           (std::string("panopticon-linux-keypair-test-") + label + "-" + std::to_string(seed));
}

void test_generate_produces_a_valid_uncompressed_point() {
    auto keypair = generate_ec_p256_keypair();
    require(succeeded(keypair), "key generation succeeds");
    const auto& value = std::get<ec_keypair>(keypair);
    require(value.public_point[0] == 0x04, "public point starts with the uncompressed-point marker 0x04");
    require(!value.private_der.empty(), "private key DER is non-empty");
}

void test_two_keypairs_produce_different_public_points() {
    auto first = generate_ec_p256_keypair();
    auto second = generate_ec_p256_keypair();
    require(succeeded(first) && succeeded(second), "both key generations succeed");
    require(std::get<ec_keypair>(first).public_point != std::get<ec_keypair>(second).public_point,
            "freshly generated keys are not identical");
}

void test_sign_produces_different_signatures_for_different_data() {
    auto keypair = generate_ec_p256_keypair();
    require(succeeded(keypair), "key generation succeeds");
    const auto& value = std::get<ec_keypair>(keypair);

    const std::vector<std::uint8_t> data_a{1, 2, 3, 4};
    const std::vector<std::uint8_t> data_b{5, 6, 7, 8};
    auto sig_a = sign_raw(value, data_a);
    auto sig_b = sign_raw(value, data_b);
    require(succeeded(sig_a) && succeeded(sig_b), "signing succeeds for both inputs");
    require(std::get<ec_raw_signature>(sig_a) != std::get<ec_raw_signature>(sig_b),
            "signatures over different data are different");
}

void test_store_then_load_round_trips_the_same_key() {
    auto original = generate_ec_p256_keypair();
    require(succeeded(original), "key generation succeeds");
    const auto& original_value = std::get<ec_keypair>(original);

    const auto path = scratch_path("roundtrip") / "identity.key";
    require(succeeded(store_ec_keypair(path, original_value)), "storing the key succeeds");

    auto loaded = load_ec_keypair(path);
    require(succeeded(loaded), "loading the stored key succeeds");
    require(std::get<ec_keypair>(loaded).public_point == original_value.public_point,
            "the loaded key's public point matches the original exactly");

    std::error_code ec;
    std::filesystem::remove_all(path.parent_path(), ec);
}

void test_loading_a_missing_key_file_fails_closed() {
    auto loaded = load_ec_keypair(scratch_path("missing") / "nope.key");
    require(!succeeded(loaded), "loading a nonexistent key file returns an error, not a fabricated key");
}

void test_loading_a_truncated_key_file_fails_closed_without_crashing() {
    const auto dir = scratch_path("truncated");
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const auto path = dir / "identity.key";
    {
        std::ofstream out(path, std::ios::binary);
        std::uint32_t claimed_size = 9999;
        out.write(reinterpret_cast<const char*>(&claimed_size), sizeof(claimed_size));
        out.write("short", 5);
    }
    auto loaded = load_ec_keypair(path);
    require(!succeeded(loaded), "a truncated key file is rejected, not partially trusted");
    std::filesystem::remove_all(dir, ec);
}

}  // namespace

int main() {
    try {
        test_generate_produces_a_valid_uncompressed_point();
        test_two_keypairs_produce_different_public_points();
        test_sign_produces_different_signatures_for_different_data();
        test_store_then_load_round_trips_the_same_key();
        test_loading_a_missing_key_file_fails_closed();
        test_loading_a_truncated_key_file_fails_closed_without_crashing();
    } catch (const std::exception& ex) {
        std::cerr << "FAIL: " << ex.what() << '\n';
        return 1;
    }
    std::cout << "All Linux agent keypair tests passed.\n";
    return 0;
}
