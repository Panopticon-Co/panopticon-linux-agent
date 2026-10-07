// Reference signer for the sensor command channel (ADR 025), used by the end-to-end tests.
//
//   command_signer keygen <private-key-file>     writes the key (0600), prints the public key line for the keyring
//   command_signer keyid  <private-key-file>     prints the key id a command names
//   command_signer sign   <private-key-file>     reads one command object on stdin, prints it with `authorization`
//   command_signer input  -                      reads one command object on stdin, prints the exact signing input
//   command_signer verify <keyring-file>         reads one signed command on stdin, prints the sensor's verdict
//
// `input` and `verify` let another implementation of the signing input (the Manager's) be checked byte for byte
// against the sensor's, and its signatures against the sensor's own verifier.
//
// It signs what the sensor's own strict parser produced from the command, using the sensor's own
// command_signing_input, so a command this tool signs is exactly a command the sensor will verify. A Manager
// implements the same input (docs/adr/025-command-authorization.md) in its own language.
#include "panopticon/linux_agent/keypair.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/sensor/command_channel.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <cstdio>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

namespace {

std::string base64(const std::uint8_t* data, const std::size_t size) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t index = 0U; index < size; index += 3U) {
        const unsigned a = data[index];
        const unsigned b = index + 1U < size ? data[index + 1U] : 0U;
        const unsigned c = index + 2U < size ? data[index + 2U] : 0U;
        const unsigned group = (a << 16U) | (b << 8U) | c;
        out.push_back(alphabet[(group >> 18U) & 63U]);
        out.push_back(alphabet[(group >> 12U) & 63U]);
        out.push_back(index + 1U < size ? alphabet[(group >> 6U) & 63U] : '=');
        out.push_back(index + 2U < size ? alphabet[group & 63U] : '=');
    }
    return out;
}

int usage() {
    std::fprintf(stderr, "usage: command_signer keygen|keyid|sign <private-key-file> | input - | verify <keyring-file>\n");
    return 2;
}

std::string read_stdin() {
    std::string text{std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>()};
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) text.pop_back();
    return text;
}

// The command as the sensor's strict parser sees it, or nullopt (with the reason on stderr).
std::optional<endpoint_command> parse_command(const std::string& text) {
    std::string why;
    const auto document = parse_json(text, json_limits{}, &why);
    if (!document) {
        std::fprintf(stderr, "not JSON: %s\n", why.c_str());
        return std::nullopt;
    }
    auto parsed = parse_endpoint_command(*document);
    if (auto* command = std::get_if<endpoint_command>(&parsed); command != nullptr) return std::move(*command);
    std::fprintf(stderr, "the sensor would not accept this command\n");
    return std::nullopt;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) return usage();
    const std::string verb = argv[1];
    const std::filesystem::path key_path = argv[2];
    if (verb == "input") {
        const auto command = parse_command(read_stdin());
        if (!command) return 1;
        std::fputs(command_signing_input(*command).c_str(), stdout);
        return 0;
    }
    if (verb == "verify") {
        auto ring = command_keyring::load(key_path);
        if (!succeeded(ring)) return std::fprintf(stderr, "%s\n", std::get<error>(ring).message.c_str()), 1;
        const auto command = parse_command(read_stdin());
        if (!command) return 1;
        const auto verdict = std::get<std::unique_ptr<command_keyring>>(ring)->check(*command);
        std::printf("%s\n", to_string(verdict));
        return verdict == authorization_verdict::valid ? 0 : 3;
    }
    if (verb == "keygen") {
        auto pair = generate_ec_p256_keypair();
        if (!succeeded(pair)) return std::fprintf(stderr, "keygen failed\n"), 1;
        const auto& key = std::get<ec_keypair>(pair);
        if (!succeeded(store_ec_keypair(key_path, key))) return std::fprintf(stderr, "cannot store the key\n"), 1;
        std::printf("%s %s\n", base64(key.public_point.data(), key.public_point.size()).c_str(), signing_key_id(key.public_point).c_str());
        return 0;
    }
    auto loaded = load_ec_keypair(key_path);
    if (!succeeded(loaded)) return std::fprintf(stderr, "cannot load the key\n"), 1;
    const auto& key = std::get<ec_keypair>(loaded);
    if (verb == "keyid") {
        std::printf("%s\n", signing_key_id(key.public_point).c_str());
        return 0;
    }
    if (verb != "sign") return usage();

    std::string text = read_stdin();
    const auto command = parse_command(text);
    if (!command) return 1;
    if (command->created_unix <= 0) return std::fprintf(stderr, "a signed command needs created_at\n"), 1;
    const auto input = command_signing_input(*command);
    const auto signature = sign_raw(key, std::vector<std::uint8_t>(input.begin(), input.end()));
    if (!succeeded(signature)) return std::fprintf(stderr, "signing failed\n"), 1;
    const auto& raw = std::get<ec_raw_signature>(signature);
    if (text.empty() || text.back() != '}') return std::fprintf(stderr, "not an object\n"), 1;
    text.pop_back();
    std::printf("%s,\"authorization\":{\"algorithm\":\"ES256\",\"key_id\":\"%s\",\"signature\":\"%s\"}}\n", text.c_str(),
                signing_key_id(key.public_point).c_str(), base64(raw.data(), raw.size()).c_str());
    return 0;
}
