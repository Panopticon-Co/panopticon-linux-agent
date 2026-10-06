#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>

namespace panopticon::linux_agent::sensor {

std::optional<std::int64_t> json_value::as_integer() const noexcept {
    if (kind_ != kind::integer) return std::nullopt;
    if (negative_) {
        if (magnitude_ > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1U) return std::nullopt;
        return static_cast<std::int64_t>(0U - magnitude_);
    }
    if (magnitude_ > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return std::nullopt;
    return static_cast<std::int64_t>(magnitude_);
}

std::optional<std::uint64_t> json_value::as_unsigned() const noexcept {
    if (kind_ != kind::integer || (negative_ && magnitude_ != 0U)) return std::nullopt;
    return magnitude_;
}

std::optional<std::string_view> json_value::as_string() const noexcept {
    if (kind_ != kind::string) return std::nullopt;
    return std::string_view{text_};
}

std::optional<bool> json_value::as_boolean() const noexcept {
    if (kind_ != kind::boolean) return std::nullopt;
    return boolean_;
}

const json_value* json_value::find(const std::string_view key) const noexcept {
    if (kind_ != kind::object) return nullptr;
    for (std::size_t index = 0U; index < keys_.size(); ++index) {
        if (keys_[index] == key) return &items_[index];
    }
    return nullptr;
}

class json_parser {
public:
    json_parser(const std::string_view text, const json_limits& limits) : text_{text}, limits_{limits} {}

    std::optional<json_value> run(std::string* error) {
        if (text_.size() > limits_.maximum_bytes) return fail("document is too large", error);
        skip_space();
        json_value root;
        if (!value(root, 1U)) return fail(reason_, error);
        skip_space();
        if (position_ != text_.size()) return fail("data after the document", error);
        return root;
    }

private:
    std::optional<json_value> fail(const std::string& reason, std::string* error) {
        if (error != nullptr) *error = reason + " at byte " + std::to_string(position_);
        return std::nullopt;
    }

    bool bad(const char* reason) {
        if (reason_.empty()) reason_ = reason;
        return false;
    }

    void skip_space() {
        while (position_ < text_.size() &&
               (text_[position_] == ' ' || text_[position_] == '\t' || text_[position_] == '\n' || text_[position_] == '\r')) {
            ++position_;
        }
    }

    bool literal(const std::string_view word) {
        if (text_.compare(position_, word.size(), word) != 0) return bad("invalid literal");
        position_ += word.size();
        return true;
    }

    bool value(json_value& out, const std::size_t depth) {
        if (depth > limits_.maximum_depth) return bad("nesting is too deep");
        if (++values_ > limits_.maximum_values) return bad("too many values");
        if (position_ >= text_.size()) return bad("unexpected end of input");
        const char first = text_[position_];
        switch (first) {
            case '{': return object(out, depth);
            case '[': return array(out, depth);
            case '"': out.kind_ = json_value::kind::string; return string(out.text_);
            case 't': out.kind_ = json_value::kind::boolean; out.boolean_ = true; return literal("true");
            case 'f': out.kind_ = json_value::kind::boolean; out.boolean_ = false; return literal("false");
            case 'n': out.kind_ = json_value::kind::null; return literal("null");
            default: return number(out);
        }
    }

    bool object(json_value& out, const std::size_t depth) {
        out.kind_ = json_value::kind::object;
        ++position_;
        skip_space();
        if (position_ < text_.size() && text_[position_] == '}') {
            ++position_;
            return true;
        }
        for (;;) {
            skip_space();
            if (position_ >= text_.size() || text_[position_] != '"') return bad("object key expected");
            std::string key;
            if (!string(key)) return false;
            if (std::find(out.keys_.begin(), out.keys_.end(), key) != out.keys_.end()) return bad("duplicate object key");
            skip_space();
            if (position_ >= text_.size() || text_[position_] != ':') return bad("':' expected");
            ++position_;
            skip_space();
            json_value member;
            if (!value(member, depth + 1U)) return false;
            out.keys_.push_back(std::move(key));
            out.items_.push_back(std::move(member));
            skip_space();
            if (position_ >= text_.size()) return bad("unterminated object");
            if (text_[position_] == ',') {
                ++position_;
                continue;
            }
            if (text_[position_] == '}') {
                ++position_;
                return true;
            }
            return bad("',' or '}' expected");
        }
    }

    bool array(json_value& out, const std::size_t depth) {
        out.kind_ = json_value::kind::array;
        ++position_;
        skip_space();
        if (position_ < text_.size() && text_[position_] == ']') {
            ++position_;
            return true;
        }
        for (;;) {
            skip_space();
            json_value element;
            if (!value(element, depth + 1U)) return false;
            out.items_.push_back(std::move(element));
            skip_space();
            if (position_ >= text_.size()) return bad("unterminated array");
            if (text_[position_] == ',') {
                ++position_;
                continue;
            }
            if (text_[position_] == ']') {
                ++position_;
                return true;
            }
            return bad("',' or ']' expected");
        }
    }

    static bool hex4(const std::string_view text, std::uint32_t& out) {
        if (text.size() < 4U) return false;
        out = 0U;
        for (std::size_t index = 0U; index < 4U; ++index) {
            const char c = text[index];
            std::uint32_t digit = 0U;
            if (c >= '0' && c <= '9') digit = static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') digit = static_cast<std::uint32_t>(c - 'A' + 10);
            else return false;
            out = out * 16U + digit;
        }
        return true;
    }

    static void append_utf8(std::string& out, const std::uint32_t code) {
        if (code < 0x80U) {
            out.push_back(static_cast<char>(code));
        } else if (code < 0x800U) {
            out.push_back(static_cast<char>(0xC0U | (code >> 6U)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
        } else if (code < 0x10000U) {
            out.push_back(static_cast<char>(0xE0U | (code >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
        } else {
            out.push_back(static_cast<char>(0xF0U | (code >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((code >> 12U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
        }
    }

    // Length of the well-formed UTF-8 sequence at `at` (overlongs, surrogates and values above
    // U+10FFFF are malformed), or 0.
    std::size_t utf8_length(const std::size_t at) const {
        const auto byte = [&](const std::size_t offset) { return static_cast<unsigned char>(text_[at + offset]); };
        const auto remaining = text_.size() - at;
        const auto lead = byte(0U);
        const auto continuation = [&](const std::size_t offset) { return (byte(offset) & 0xC0U) == 0x80U; };
        if (lead < 0x80U) return 1U;
        if (lead >= 0xC2U && lead <= 0xDFU) return remaining >= 2U && continuation(1U) ? 2U : 0U;
        if (lead >= 0xE0U && lead <= 0xEFU) {
            if (remaining < 3U || !continuation(1U) || !continuation(2U)) return 0U;
            if (lead == 0xE0U && byte(1U) < 0xA0U) return 0U;
            if (lead == 0xEDU && byte(1U) > 0x9FU) return 0U;
            return 3U;
        }
        if (lead >= 0xF0U && lead <= 0xF4U) {
            if (remaining < 4U || !continuation(1U) || !continuation(2U) || !continuation(3U)) return 0U;
            if (lead == 0xF0U && byte(1U) < 0x90U) return 0U;
            if (lead == 0xF4U && byte(1U) > 0x8FU) return 0U;
            return 4U;
        }
        return 0U;
    }

    bool string(std::string& out) {
        ++position_;  // opening quote
        while (position_ < text_.size()) {
            const auto c = static_cast<unsigned char>(text_[position_]);
            if (c == '"') {
                ++position_;
                return true;
            }
            if (c < 0x20U) return bad("control character in string");
            if (c != '\\') {
                const auto length = utf8_length(position_);
                if (length == 0U) return bad("invalid UTF-8");
                out.append(text_, position_, length);
                position_ += length;
                continue;
            }
            if (++position_ >= text_.size()) return bad("unterminated escape");
            const char escape = text_[position_++];
            switch (escape) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    std::uint32_t code = 0U;
                    if (!hex4(text_.substr(position_), code)) return bad("invalid \\u escape");
                    position_ += 4U;
                    if (code >= 0xDC00U && code <= 0xDFFFU) return bad("lone low surrogate");
                    if (code >= 0xD800U && code <= 0xDBFFU) {
                        std::uint32_t low = 0U;
                        if (text_.compare(position_, 2U, "\\u") != 0 || !hex4(text_.substr(position_ + 2U), low) ||
                            low < 0xDC00U || low > 0xDFFFU) {
                            return bad("lone high surrogate");
                        }
                        position_ += 6U;
                        code = 0x10000U + ((code - 0xD800U) << 10U) + (low - 0xDC00U);
                    }
                    append_utf8(out, code);
                    break;
                }
                default: return bad("invalid escape");
            }
        }
        return bad("unterminated string");
    }

    bool number(json_value& out) {
        const auto begin = position_;
        bool negative = false;
        if (text_[position_] == '-') {
            negative = true;
            ++position_;
        }
        const auto digits_begin = position_;
        if (position_ >= text_.size() || text_[position_] < '0' || text_[position_] > '9') return bad("invalid number");
        if (text_[position_] == '0') {
            ++position_;
            if (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') return bad("leading zero");
        } else {
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
        }
        const auto integer_end = position_;
        bool real = false;
        if (position_ < text_.size() && text_[position_] == '.') {
            real = true;
            ++position_;
            const auto fraction = position_;
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
            if (position_ == fraction) return bad("digits expected after '.'");
        }
        if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
            real = true;
            ++position_;
            if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) ++position_;
            const auto exponent = position_;
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
            if (position_ == exponent) return bad("digits expected in exponent");
        }
        if (!real) {
            std::uint64_t magnitude = 0U;
            const auto parsed = std::from_chars(text_.data() + digits_begin, text_.data() + integer_end, magnitude);
            if (parsed.ec != std::errc{}) return bad("integer is out of range");
            out.kind_ = json_value::kind::integer;
            out.negative_ = negative;
            out.magnitude_ = magnitude;
            return true;
        }
        double parsed_value = 0.0;
        const auto parsed = std::from_chars(text_.data() + begin, text_.data() + position_, parsed_value);
        if (parsed.ec != std::errc{} || !std::isfinite(parsed_value)) return bad("number is out of range");
        out.kind_ = json_value::kind::real;
        out.real_ = parsed_value;
        return true;
    }

    std::string_view text_;
    json_limits limits_;
    std::size_t position_{};
    std::size_t values_{};
    std::string reason_;
};

std::optional<json_value> parse_json(const std::string_view text, const json_limits& limits, std::string* error) {
    return json_parser{text, limits}.run(error);
}

}  // namespace panopticon::linux_agent::sensor
