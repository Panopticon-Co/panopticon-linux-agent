#include "panopticon/linux_agent/sensor/policy.hpp"

#include <cstdio>
#include <exception>
#include <random>
#include <stdexcept>
#include <string>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

const std::string hash_a(64U, 'a');
const std::string hash_b = std::string(63U, 'b') + "c";

policy_engine load(const std::string& text) {
    auto parsed = policy_engine::parse(text);
    require(succeeded(parsed), "policy must load");
    return std::get<policy_engine>(std::move(parsed));
}

bool rejects(const std::string& text) { return !succeeded(policy_engine::parse(text)); }

void test_rules_match_each_operator() {
    const auto engine = load(
        "# comment\n"
        "rule tmp-exec process.exec exe prefix recommend_terminate high /tmp\n"
        "rule curl-pipe process.exec cmdline contains alert medium | sh\n"
        "rule ssh-key file.created file_path suffix alert low authorized_keys\n"
        "rule exact process.exec exe equals alert low /usr/bin/nc\n"
        "rule anywhere * dest_ip equals recommend_block critical 203.0.113.9\n");
    require(engine.rule_count() == 5U, "five rules");
    policy_input input;
    input.kind = "process.exec";
    input.exe = "/tmp/payload";
    input.cmdline = "bash -c curl x | sh";
    const auto decisions = engine.evaluate(input);
    require(decisions.size() == 2U && decisions[0].rule_id == "tmp-exec" && decisions[0].action == policy_action::recommend_terminate &&
                decisions[0].severity == policy_severity::high && decisions[0].field == "exe" && decisions[1].rule_id == "curl-pipe",
            "prefix and contains, in rule order");
    input.exe = "/tmpfoo/payload";
    input.cmdline = "ls";
    require(engine.evaluate(input).empty(), "a path prefix stops at a component boundary");
    input.exe = "/usr/bin/nc";
    require(engine.evaluate(input).size() == 1U, "equals");
    policy_input file;
    file.kind = "file.created";
    file.file_path = "/root/.ssh/authorized_keys";
    require(engine.evaluate(file).size() == 1U, "suffix on a file event");
    file.kind = "process.exec";
    require(engine.evaluate(file).empty(), "the rule applies to its own event kind only");
    policy_input net;
    net.kind = "network.connect";
    net.dest_ip = "203.0.113.9";
    require(engine.evaluate(net).size() == 1U, "a wildcard kind matches any event");
}

void test_indicators() {
    const auto engine = load("ioc sha256 " + hash_a + "\nioc dest_domain Evil.Example\nioc dest_ip 198.51.100.7\nioc file_path /etc/cron.d/x\n"
                             "rule bad-hash * sha256 ioc recommend_quarantine critical\n"
                             "rule bad-domain * dest_domain ioc recommend_block high\n"
                             "rule bad-ip * dest_ip ioc recommend_block high\n"
                             "rule bad-file * file_path ioc alert medium\n");
    require(engine.ioc_count() == 4U, "four indicators");
    policy_input input;
    input.kind = "process.exec";
    input.sha256 = std::string(64U, 'A');
    require(engine.evaluate(input).size() == 1U, "hashes compare case-insensitively");
    input.sha256 = hash_b;
    require(engine.evaluate(input).empty(), "a different hash does not match");
    policy_input net;
    net.kind = "network.connect";
    net.dest_domain = "c2.cdn.EVIL.example";
    require(engine.evaluate(net).size() == 1U, "a subdomain of an indicator domain matches");
    net.dest_domain = "notevil.example";
    require(engine.evaluate(net).empty(), "a different registered name does not");
    net.dest_domain = "evil.example.org";
    require(engine.evaluate(net).empty(), "a suffix extension does not");
    net.dest_ip = "198.51.100.7";
    require(engine.evaluate(net).size() == 1U, "address indicator");
}

void test_allow_list_suppresses() {
    const auto engine = load("allow exe /opt/trusted\nrule tmp * exe prefix alert low /opt\n");
    policy_input input;
    input.kind = "process.exec";
    input.exe = "/opt/trusted/bin/tool";
    require(engine.evaluate(input).empty(), "an allow-listed executable raises nothing");
    input.exe = "/opt/trustedevil/tool";
    require(engine.evaluate(input).size() == 1U, "allow-listing is on a component boundary");
}

void test_bad_policies_are_rejected_whole() {
    require(rejects("frobnicate x\n"), "unknown directive");
    require(rejects("rule a * exe equals alert low\n"), "no value");
    require(rejects("rule a * exe ioc alert low extra\n"), "ioc rule with a value");
    require(rejects("rule a * exe nothing alert low x\n"), "bad operator");
    require(rejects("rule a * bogus equals alert low x\n"), "bad field");
    require(rejects("rule a * exe equals explode low x\n"), "bad action");
    require(rejects("rule a * exe equals alert dire x\n"), "bad severity");
    require(rejects("rule a * exe equals alert low x\nrule a * exe equals alert low y\n"), "duplicate id");
    require(rejects("ioc sha256 abc\n"), "short hash");
    require(rejects("ioc cmdline foo\n"), "no cmdline indicators");
    require(rejects("allow exe relative/path\n"), "allow needs an absolute path");
    require(rejects(std::string("rule a * exe equals alert low x\x01y\n")), "control character");
    require(rejects("rule " + std::string(5000U, 'a') + " * exe equals alert low x\n"), "oversize line");
    policy_limits small;
    small.maximum_rules = 1U;
    require(!succeeded(policy_engine::parse("rule a * exe equals alert low x\nrule b * exe equals alert low y\n", small)), "rule limit");
    small = {};
    small.maximum_iocs = 1U;
    require(!succeeded(policy_engine::parse("ioc dest_ip 1.1.1.1\nioc dest_ip 2.2.2.2\n", small)), "indicator limit");
    const auto empty = policy_engine::parse("");
    require(succeeded(empty) && std::get<policy_engine>(empty).rule_count() == 0U, "an empty policy is valid and matches nothing");
}

void test_evaluation_is_bounded() {
    std::string text;
    for (int index = 0; index < 40; ++index) text += "rule r" + std::to_string(index) + " * exe prefix alert low /\n";
    const auto engine = load(text);
    policy_input input;
    input.kind = "process.exec";
    input.exe = "/bin/x";
    require(engine.evaluate(input).size() == 16U, "decisions are capped");
    // A hostile 10 MB command line against a contains rule completes (linear, no backtracking).
    const auto hostile = load("rule h * cmdline contains alert low needle-that-is-absent\n");
    input.cmdline = std::string(10U * 1024U * 1024U, 'a');
    require(hostile.evaluate(input).empty(), "large input is handled");
    const auto matched = load("rule m * cmdline contains alert low aaa\n");
    input.cmdline = std::string(10000U, 'a');
    const auto decisions = matched.evaluate(input);
    require(decisions.size() == 1U && decisions[0].matched.size() == 256U, "the matched text is truncated");
}

void test_random_input_never_crashes() {
    std::mt19937 random{12345U};
    const std::string alphabet = "rule ioc allow exe sha256 dest_ip */#\n\t abcdef0123456789\\\"'";
    for (int round = 0; round < 3000; ++round) {
        std::string text;
        const auto length = random() % 300U;
        for (unsigned index = 0; index < length; ++index) text += alphabet[random() % alphabet.size()];
        auto parsed = policy_engine::parse(text);
        if (succeeded(parsed)) {
            policy_input input;
            input.kind = "process.exec";
            input.exe = "/x";
            input.cmdline = text;
            (void)std::get<policy_engine>(parsed).evaluate(input);
        }
    }
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"rules_match_each_operator", test_rules_match_each_operator},
        {"indicators", test_indicators},
        {"allow_list_suppresses", test_allow_list_suppresses},
        {"bad_policies_are_rejected_whole", test_bad_policies_are_rejected_whole},
        {"evaluation_is_bounded", test_evaluation_is_bounded},
        {"random_input_never_crashes", test_random_input_never_crashes},
    };
    int failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::printf("PASS %s\n", test.name);
        } catch (const std::exception& error) {
            std::printf("FAIL %s: %s\n", test.name, error.what());
            ++failures;
        }
    }
    std::printf(failures == 0 ? "ALL PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
