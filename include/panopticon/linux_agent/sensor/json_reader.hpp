#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace panopticon::linux_agent::sensor {

// A parsed JSON document. Numbers are kept exactly when they are integers (a sequence number must
// not pass through a double); anything with a fraction or exponent is a double.
class json_value {
public:
    enum class kind { null, boolean, integer, real, string, array, object };

    [[nodiscard]] kind type() const noexcept { return kind_; }
    [[nodiscard]] bool is_object() const noexcept { return kind_ == kind::object; }
    [[nodiscard]] bool is_array() const noexcept { return kind_ == kind::array; }

    // Typed accessors return nullopt on a type mismatch instead of throwing or defaulting, so a
    // response with the wrong shape is distinguishable from a response with a zero.
    [[nodiscard]] std::optional<std::int64_t> as_integer() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> as_unsigned() const noexcept;
    [[nodiscard]] std::optional<std::string_view> as_string() const noexcept;
    [[nodiscard]] std::optional<bool> as_boolean() const noexcept;
    [[nodiscard]] const std::vector<json_value>& items() const noexcept { return items_; }
    // Object member lookup; nullptr when absent or when this is not an object.
    [[nodiscard]] const json_value* find(std::string_view key) const noexcept;
    // Object member names, parallel to items(); empty for anything but an object.
    [[nodiscard]] const std::vector<std::string>& keys() const noexcept { return keys_; }
    [[nodiscard]] double as_double_or(double fallback) const noexcept { return kind_ == kind::real ? real_ : fallback; }

private:
    friend class json_parser;
    kind kind_{kind::null};
    bool boolean_{};
    bool negative_{};
    std::uint64_t magnitude_{};
    double real_{};
    std::string text_;
    std::vector<json_value> items_;
    std::vector<std::string> keys_;  // parallel to items_ for objects
};

struct json_limits {
    std::size_t maximum_bytes{4U * 1024U * 1024U};
    std::size_t maximum_depth{32U};
    std::size_t maximum_values{200'000U};
};

// Strict RFC 8259 parser: no comments, no trailing commas, no duplicate object keys, no
// non-finite numbers, valid UTF-8 only, nothing after the document. Returns nullopt and a reason
// in `error` on any violation; it never throws and its recursion is bounded by `maximum_depth`.
[[nodiscard]] std::optional<json_value> parse_json(std::string_view text, const json_limits& limits,
                                                    std::string* error = nullptr);

}  // namespace panopticon::linux_agent::sensor
