#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <cstdio>
#include <exception>
#include <random>
#include <stdexcept>
#include <string>

using namespace panopticon::linux_agent::sensor;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

std::optional<json_value> parse(const std::string& text) { return parse_json(text, json_limits{}); }
bool rejects(const std::string& text) { return !parse(text).has_value(); }

void test_accepts_a_manager_acknowledgement() {
    const auto document = parse(
        R"({"batch_id":"wal-1-3","received":3,"accepted":2,"duplicates":1,"rejected":[],)"
        R"("streams":[{"sensor_id":"s","boot_id":"b","acked_through_seq":3,"highest_seq":3,"missing_ranges":[[4,5]]}],)"
        R"("server_time":"2026-10-06T00:00:00.000Z"})");
    require(document && document->is_object(), "object");
    require(document->find("batch_id")->as_string() == std::optional<std::string_view>{"wal-1-3"}, "string");
    require(document->find("received")->as_unsigned() == std::optional<std::uint64_t>{3U}, "unsigned");
    require(document->find("rejected")->is_array() && document->find("rejected")->items().empty(), "empty array");
    const auto& stream = document->find("streams")->items().front();
    require(stream.find("missing_ranges")->items().front().items().size() == 2U, "nested arrays");
    require(document->find("absent") == nullptr, "missing member is nullptr");
}

void test_integers_are_exact_and_types_are_not_coerced() {
    const auto big = parse("18446744073709551615");
    require(big && big->as_unsigned() == std::optional<std::uint64_t>{18446744073709551615ULL}, "uint64 max survives");
    require(!big->as_integer().has_value(), "does not fit a signed value");
    const auto negative = parse("-9223372036854775808");
    require(negative && negative->as_integer() == std::optional<std::int64_t>{INT64_MIN}, "int64 min");
    require(!negative->as_unsigned().has_value(), "negative is not unsigned");
    require(parse("-0")->as_unsigned() == std::optional<std::uint64_t>{0U}, "negative zero is zero");
    const auto real = parse("1.5e3");
    require(real && !real->as_integer() && !real->as_unsigned() && !real->as_string(), "a real is not an integer");
    require(!parse("\"7\"")->as_unsigned().has_value(), "a string is not a number");
    require(parse("true")->as_boolean() == std::optional<bool>{true} && !parse("1")->as_boolean().has_value(), "booleans");
    require(rejects("18446744073709551616"), "uint64 overflow");
}

void test_strings_and_utf8() {
    const auto escaped = parse(R"("a\n\t\"\\\/\u00e9\u20ac\ud83d\ude00")");
    require(escaped && escaped->as_string() == std::optional<std::string_view>{"a\n\t\"\\/\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80"}, "escapes and surrogate pair");
    require(parse("\"\xC3\xA9\"").has_value(), "valid UTF-8 passes through");
    require(rejects("\"\xC3\x28\""), "bad continuation");
    require(rejects("\"\xC0\xAF\""), "overlong");
    require(rejects("\"\xED\xA0\x80\""), "encoded surrogate");
    require(rejects("\"\xF4\x90\x80\x80\""), "above U+10FFFF");
    require(rejects("\"\\ud800\""), "lone high surrogate");
    require(rejects("\"\\udc00\""), "lone low surrogate");
    require(rejects("\"\\ud800\\u0041\""), "high surrogate without a low one");
    require(rejects(std::string{"\"a\x01"} + "b\""), "raw control character");
    require(rejects("\"\\x41\""), "unknown escape");
    require(rejects("\"abc"), "unterminated");
}

void test_structure_is_strict() {
    for (const char* bad : {"", " ", "{", "[", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "[1,]", "[1 2]", "{1:2}", "{'a':1}", "nul", "tru",
                            "01", "1.", ".5", "1e", "+1", "NaN", "Infinity", "-", "[] []", "{} x", "\"a\" \"b\"", "/*c*/1", "[1]//x"}) {
        require(rejects(bad), bad);
    }
    require(rejects(R"({"a":1,"a":2})"), "duplicate keys are refused");
    require(rejects(R"({"a":{"b":1,"b":1}})"), "nested duplicate keys are refused");
    require(parse(" \t\r\n{ \"a\" : [ 1 , 2 ] } \n").has_value(), "insignificant whitespace");
    require(rejects("1e999"), "non-finite number");
}

void test_limits_hold() {
    std::string deep(40U, '[');
    deep += std::string(40U, ']');
    require(rejects(deep), "depth beyond the limit");
    json_limits tight;
    tight.maximum_depth = 3U;
    require(parse_json("[[1]]", tight).has_value() && !parse_json("[[[1]]]", tight).has_value(), "configurable depth");
    std::string huge = "[";
    for (int index = 0; index < 1000; ++index) huge += "1,";
    huge += "1]";
    json_limits few;
    few.maximum_values = 100U;
    require(!parse_json(huge, few).has_value(), "value count");
    json_limits small;
    small.maximum_bytes = 16U;
    require(!parse_json(R"({"aaaaaaaaaaaaaaaa":1})", small).has_value(), "byte limit");
    require(rejects(std::string(1'000'000U, '[')), "a million brackets is refused without recursion");
}

void test_random_input_never_crashes() {
    std::mt19937 generator{20261006U};
    const std::string alphabet = "{}[]\",:0123456789.eE+-truefalsn \\u\n\t\xC3\xA9\x01";
    for (int round = 0; round < 20000; ++round) {
        std::string text;
        const auto length = generator() % 64U;
        for (unsigned index = 0U; index < length; ++index) text.push_back(alphabet[generator() % alphabet.size()]);
        (void)parse_json(text, json_limits{});
    }
    const std::string valid = R"({"batch_id":"x","received":1,"rejected":[{"line":1,"reason":"y"}],"n":-1.5e2,"t":true,"z":null})";
    for (int round = 0; round < 20000; ++round) {
        auto text = valid;
        const auto edits = 1U + generator() % 3U;
        for (unsigned edit = 0U; edit < edits; ++edit) {
            const auto at = generator() % text.size();
            switch (generator() % 3U) {
                case 0U: text[at] = static_cast<char>(generator() % 256U); break;
                case 1U: text.erase(at, 1U); break;
                default: text.insert(at, 1U, alphabet[generator() % alphabet.size()]); break;
            }
            if (text.empty()) text = "x";
        }
        (void)parse_json(text, json_limits{});
    }
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"accepts_a_manager_acknowledgement", test_accepts_a_manager_acknowledgement},
        {"integers_are_exact_and_types_are_not_coerced", test_integers_are_exact_and_types_are_not_coerced},
        {"strings_and_utf8", test_strings_and_utf8},
        {"structure_is_strict", test_structure_is_strict},
        {"limits_hold", test_limits_hold},
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
