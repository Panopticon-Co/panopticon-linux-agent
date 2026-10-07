#include "panopticon/linux_agent/sensor/policy.hpp"
#include "panopticon/linux_agent/sensor/policy_bundle.hpp"
#include "policy_test_support.hpp"

#include <cstdio>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;

namespace {

void require(const bool condition, const std::string& message) {
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
    require(!succeeded(policy_engine::parse("rule ip * dest_ip ioc alert low\nioc dest_ip 1.1.1.1\nioc dest_ip 2.2.2.2\n", small)), "indicator limit");
    require(succeeded(policy_engine::parse("rule ip * dest_ip ioc alert low\nioc dest_ip 1.1.1.1\n", small)), "within the indicator limit");
    // Indicators that no ioc rule consults would never match: the policy is refused rather than half in force.
    require(rejects("ioc dest_ip 1.1.1.1\n"), "indicators without a rule");
    require(rejects("rule h * sha256 ioc alert low\nioc sha256 " + std::string(64U, 'a') + "\nioc dest_domain evil.example\n"),
            "indicators on a field no ioc rule names");
    require(rejects("rule d * dest_domain equals alert low evil.example\nioc dest_domain evil.example\n"), "a non-ioc rule on the field does not count");
    require(succeeded(policy_engine::parse("rule h * sha256 ioc alert low\n")), "an ioc rule with an empty indicator set is valid");
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

void test_only_filter() {
    const auto engine = load(
        "rule by-exe process.exec exe prefix alert low /tmp\n"
        "rule by-hash process.exec sha256 ioc recommend_terminate critical\n"
        "ioc sha256 " + hash_a + "\n");
    policy_input input;
    input.kind = "process.exec";
    input.exe = "/tmp/x";
    input.sha256 = hash_a;
    require(engine.evaluate(input).size() == 2U, "both facts match");
    const auto late = engine.evaluate(input, policy_field::sha256);
    require(late.size() == 1U && late[0].rule_id == "by-hash", "only the late fact is decided again");
    const auto allowed = load("allow exe /tmp\nrule by-hash process.exec sha256 ioc alert low\nioc sha256 " + hash_a + "\n");
    require(allowed.evaluate(input, policy_field::sha256).empty(), "the allow list still applies to the late fact");
}

// ---- signed bundles (ADR 032) ----------------------------------------------------------------

namespace fs = std::filesystem;
using policy_test_support::bundle_fields;
using policy_test_support::key_line;
using policy_test_support::make_key;
using policy_test_support::signed_bundle;

const std::string body_v = "rule tmp-exec process.exec exe prefix recommend_terminate high /tmp\nrule bad-ip * dest_ip ioc recommend_block high\nioc dest_ip 203.0.113.9\n";

fs::path fresh(const std::string& name) {
    const auto path = fs::temp_directory_path() / ("panopticon-policy-tests-" + std::to_string(::getpid()) + "-" + name);
    fs::remove_all(path);
    fs::create_directories(path);
    fs::permissions(path, fs::perms::owner_all, fs::perm_options::replace);
    return path;
}

void put(const fs::path& path, const std::string& text, const mode_t mode = 0600) {
    {
        std::ofstream out{path, std::ios::binary | std::ios::trunc};
        out << text;
    }
    ::chmod(path.c_str(), mode);
}

std::int64_t now_s() { return static_cast<std::int64_t>(std::time(nullptr)); }

bundle_fields fields(const std::uint64_t version, const std::int64_t now) {
    bundle_fields f;
    f.version = version;
    f.issued_unix = now - 10;
    f.expires_unix = now + 3600;
    return f;
}

void test_bundle_parses_and_is_strict() {
    const auto key = make_key();
    const auto now = now_s();
    const auto text = signed_bundle(key, fields(7U, now), body_v);
    auto parsed = parse_policy_bundle(text);
    require(succeeded(parsed), "a signed bundle parses");
    const auto& bundle = std::get<policy_bundle>(parsed);
    require(bundle.header.policy_id == "test-policy" && bundle.header.version == 7U && bundle.header.scope == "all", "header fields");
    require(bundle.body_sha256 == sha256_hex(body_v) && bundle.engine.rule_count() == 2U && bundle.engine.ioc_count() == 1U, "body");
    // The signing input names every field with its length: a field cannot run into the next.
    const auto input = policy_signing_input(bundle.header, bundle.body_sha256);
    require(input.rfind("panopticon-policy/1\npolicy_id:11:test-policy\nversion:1:7\n", 0U) == 0U, "length-prefixed signing input: " + input);

    const auto bad = [&](std::string variant, const char* what) {
        require(!succeeded(parse_policy_bundle(variant)), what);
    };
    const auto replace = [&](const std::string& from, const std::string& to) {
        auto copy = text;
        const auto at = copy.find(from);
        require(at != std::string::npos, "test setup: text to replace");
        return copy.replace(at, from.size(), to);
    };
    bad(text.substr(1U), "the magic line is required");
    bad(replace("panopticon-policy 1", "panopticon-policy 2"), "an unknown format version");
    bad(replace("\nversion 7\n", "\nversion 07\n"), "a leading zero");
    bad(replace("\nversion 7\n", "\nversion 0\n"), "version 0");
    bad(replace("\nversion 7\n", "\nversion -7\n"), "a negative version");
    bad(replace("\nversion 7\n", "\nversion 9223372036854775808\n"), "a version over 2^63-1");
    bad(replace("\nversion 7\n", "\nversion  7\n"), "a doubled space");
    bad(replace("\nversion 7\n", "\nversion 7\r\n"), "a carriage return in the header");
    bad(replace("scope all", "scope everyone"), "an unknown scope");
    bad(replace("scope all", "scope host:"), "an empty host scope");
    bad(replace("\n---\n", "\n--\n"), "the separator is exact");
    bad(replace("expires_at " + std::to_string(now + 3600), "expires_at " + std::to_string(now - 10)), "expiry not after issue");
    bad(replace("expires_at " + std::to_string(now + 3600), "expires_at 99999999999"), "an expiry past year 2286");
    bad(replace("key_id ", "key_id A"), "a key id that is not 16 lowercase hex digits");
    bad(replace("signature ", "signature !"), "a signature that is not base64");
    bad(text + "bogus directive\n", "a body that does not parse");
    // The header lines must be in order and complete.
    const auto policy_line = text.find("policy_id ");
    const auto version_line = text.find("version ");
    auto swapped = text;
    swapped.replace(policy_line, version_line - policy_line, "");
    bad(swapped, "a missing header line");
}

// A store over files in a fresh directory, with one pinned key.
struct store_fixture {
    fs::path dir;
    ec_keypair key = make_key();
    policy_store_options options;

    explicit store_fixture(const std::string& name) : dir{fresh(name)} {
        options.policy_path = dir / "policy";
        options.keys_path = dir / "keys";
        options.state_path = dir / "wal.policy";
        options.host_id = "host-a";
        put(options.keys_path, key_line(key));
    }
    void write(const bundle_fields& f, const std::string& body = body_v) const { put(options.policy_path, signed_bundle(key, f, body)); }
};

// By value: callers pass `store.refresh(now)`, a temporary vector, and keep the result. A reference into it would dangle
// after the statement (ThreadSanitizer reported it as a heap-use-after-free); a returned copy has its lifetime extended.
policy_change only_change(const std::vector<policy_change>& changes, const std::string& outcome, const std::string& reason) {
    require(changes.size() == 1U, ("one change expected, got " + std::to_string(changes.size())).c_str());
    if (changes[0].outcome != outcome || changes[0].reason != reason) {
        throw std::runtime_error{"expected " + outcome + "/" + reason + ", got " + changes[0].outcome + "/" + changes[0].reason + ": " + changes[0].detail};
    }
    return changes[0];
}

void test_store_accepts_updates_and_refuses_rollback() {
    store_fixture fx{"lifecycle"};
    const auto now = now_s();
    policy_store store{fx.options};
    only_change(store.refresh(now), "rejected", "file_missing");
    require(store.active(now) == nullptr && store.health(now).state == "degraded", "no file: no policy and degraded");

    fx.write(fields(1U, now));
    const auto& first = only_change(store.refresh(now), "loaded", "no_previous_state");
    require(first.version == 1U && !first.previous_version && first.rules == 2U && first.indicators == 1U, "first load");
    require(store.active(now) != nullptr && store.health(now).state == "active", "in force and healthy");
    require(fs::exists(fx.options.state_path), "the accepted version is recorded");

    fx.write(fields(1U, now));
    require(store.refresh(now).empty(), "the same content again is no change");

    fx.write(fields(2U, now));
    const auto& second = only_change(store.refresh(now), "loaded", "updated");
    require(second.version == 2U && second.previous_version == 1U, "update names the previous version");

    fx.write(fields(1U, now));
    const auto& rollback = only_change(store.refresh(now), "rejected", "rollback");
    require(rollback.version == 1U && rollback.previous_version == 2U, "rollback names both versions");
    require(store.active(now)->header.version == 2U, "the newer policy stays in force (fail-safe)");
    require(store.health(now).state == "degraded" && store.health(now).reason.find("rollback") != std::string::npos, "a refused update degrades health");

    fx.write(fields(2U, now), body_v + "ioc dest_ip 198.51.100.1\n");
    only_change(store.refresh(now), "rejected", "rollback");  // same version, different content

    fx.write(fields(3U, now));
    only_change(store.refresh(now), "loaded", "updated");
    require(store.health(now).state == "active", "a good update clears the refusal");

    // A restart: the record of version 3 survives, an older file is still refused, the same one resumes.
    policy_store restarted{fx.options};
    only_change(restarted.refresh(now), "loaded", "resumed");
    fx.write(fields(2U, now));
    only_change(restarted.refresh(now), "rejected", "rollback");
    policy_store again{fx.options};
    only_change(again.refresh(now), "rejected", "rollback");
    require(again.active(now) == nullptr, "after a restart a rollback is not accepted even with nothing in force");
}

void test_store_refuses_bad_signatures_and_scope() {
    store_fixture fx{"signatures"};
    const auto now = now_s();
    policy_store store{fx.options};
    fx.write(fields(5U, now));
    only_change(store.refresh(now), "loaded", "no_previous_state");

    // Tampered body: the header still names the old body's signature.
    auto text = signed_bundle(fx.key, fields(6U, now), body_v);
    text += "allow exe /\n";
    put(fx.options.policy_path, text);
    only_change(store.refresh(now), "rejected", "bad_signature");
    // Tampered header: a later expiry is not covered by the signature.
    text = signed_bundle(fx.key, fields(6U, now), body_v);
    const auto expiry = std::to_string(now + 3600);
    text.replace(text.find("expires_at " + expiry), 11U + expiry.size(), "expires_at " + std::to_string(now + 7200));
    put(fx.options.policy_path, text);
    only_change(store.refresh(now), "rejected", "bad_signature");

    const auto stranger = make_key();
    put(fx.options.policy_path, signed_bundle(stranger, fields(6U, now), body_v));
    only_change(store.refresh(now), "rejected", "unknown_key");
    // Pinning the key afterwards makes the same file acceptable without touching it.
    put(fx.options.keys_path, key_line(fx.key) + key_line(stranger));
    only_change(store.refresh(now), "loaded", "updated");

    auto scoped = fields(7U, now);
    scoped.scope = "host:host-b";
    fx.write(scoped);
    only_change(store.refresh(now), "rejected", "out_of_scope");
    scoped.scope = "host:host-a";
    fx.write(scoped);
    only_change(store.refresh(now), "loaded", "updated");

    auto future = fields(8U, now);
    future.issued_unix = now + 600;
    future.expires_unix = now + 3600;
    fx.write(future);
    only_change(store.refresh(now), "rejected", "not_yet_valid");
    auto skewed = fields(8U, now);
    skewed.issued_unix = now + 20;  // inside the 30 s allowance
    fx.write(skewed);
    only_change(store.refresh(now), "loaded", "updated");

    auto stale = fields(9U, now);
    stale.issued_unix = now - 7200;
    stale.expires_unix = now - 3600;
    fx.write(stale);
    only_change(store.refresh(now), "rejected", "already_expired");

    put(fx.options.policy_path, "not a policy\n");
    only_change(store.refresh(now), "rejected", "malformed");
    require(store.active(now)->header.version == 8U, "every refusal keeps the policy in force");

    // A policy file others can write is refused, and accepted once it is fixed.
    fx.write(fields(10U, now));
    ::chmod(fx.options.policy_path.c_str(), 0666);
    only_change(store.refresh(now), "rejected", "untrusted_file");
    require(store.refresh(now).empty(), "the same refusal is not repeated");
    ::chmod(fx.options.policy_path.c_str(), 0600);
    only_change(store.refresh(now), "loaded", "updated");
}

void test_store_expiry_removal_and_lost_state() {
    store_fixture fx{"expiry"};
    const auto now = now_s();
    policy_store store{fx.options};
    auto short_lived = fields(1U, now);
    short_lived.expires_unix = now + 100;
    fx.write(short_lived);
    only_change(store.refresh(now), "loaded", "no_previous_state");
    require(store.active(now + 99) != nullptr, "in force until its expiry");
    require(store.active(now + 100) == nullptr, "no decisions from the moment it expires (fail-closed)");
    only_change(store.refresh(now + 100), "expired", "expired");
    require(store.refresh(now + 101).empty(), "the expiry is recorded once");
    require(store.health(now + 100).state == "degraded", "an expired policy degrades health");

    // Refreshed at the real time from here: a file written in the last two seconds is always read again, even
    // when the write fell in the same timestamp tick as the previous one.
    fx.write(fields(2U, now));
    only_change(store.refresh(now), "loaded", "updated");
    require(store.health(now).state == "active", "a newer policy ends the expiry");
    fs::remove(fx.options.policy_path);
    const auto& removed = only_change(store.refresh(now), "removed", "file_missing");
    require(removed.version == 2U, "removal names the policy that stays");
    require(store.active(now) != nullptr, "a removed file leaves the policy in force (fail-safe)");
    require(store.health(now).state == "degraded", "and is reported");

    // A state record that cannot be read: the next valid policy is accepted, and says rollback was not checked.
    put(fx.options.state_path, "garbage\n");
    policy_store fresh_store{fx.options};
    fx.write(fields(1U, now));
    only_change(fresh_store.refresh(now), "loaded", "state_unreadable");
    // Missing state: accepted, recorded as having no previous state.
    fs::remove(fx.options.state_path);
    policy_store reset{fx.options};
    only_change(reset.refresh(now), "loaded", "no_previous_state");
}

void test_store_without_usable_keys() {
    store_fixture fx{"nokeys"};
    const auto now = now_s();
    fx.write(fields(1U, now));
    put(fx.options.keys_path, "not a key\n");
    policy_store store{fx.options};
    only_change(store.refresh(now), "rejected", "no_keys");
    require(store.active(now) == nullptr && store.health(now).state == "degraded", "no keys, no policy");
    put(fx.options.keys_path, key_line(fx.key));
    only_change(store.refresh(now), "loaded", "no_previous_state");
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
        {"only_filter", test_only_filter},
        {"bundle_parses_and_is_strict", test_bundle_parses_and_is_strict},
        {"store_accepts_updates_and_refuses_rollback", test_store_accepts_updates_and_refuses_rollback},
        {"store_refuses_bad_signatures_and_scope", test_store_refuses_bad_signatures_and_scope},
        {"store_expiry_removal_and_lost_state", test_store_expiry_removal_and_lost_state},
        {"store_without_usable_keys", test_store_without_usable_keys},
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
