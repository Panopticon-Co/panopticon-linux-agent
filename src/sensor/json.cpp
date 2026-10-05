#include "panopticon/linux_agent/sensor/json.hpp"

#include <cassert>
#include <charconv>

namespace panopticon::linux_agent::sensor {
namespace {

constexpr char hex_digits[] = "0123456789abcdef";

// Length of the UTF-8 sequence starting at `data[0]`, or 0 when it is not a valid, minimal,
// non-surrogate encoding.
std::size_t valid_utf8_sequence(const unsigned char* data, const std::size_t available) {
    const unsigned char lead = data[0];
    if (lead < 0x80U) return 1U;
    std::size_t length = 0U;
    std::uint32_t code_point = 0U;
    if ((lead & 0xE0U) == 0xC0U) { length = 2U; code_point = lead & 0x1FU; }
    else if ((lead & 0xF0U) == 0xE0U) { length = 3U; code_point = lead & 0x0FU; }
    else if ((lead & 0xF8U) == 0xF0U) { length = 4U; code_point = lead & 0x07U; }
    else return 0U;
    if (length > available) return 0U;
    for (std::size_t index = 1U; index < length; ++index) {
        if ((data[index] & 0xC0U) != 0x80U) return 0U;
        code_point = (code_point << 6U) | (data[index] & 0x3FU);
    }
    if ((length == 2U && code_point < 0x80U) || (length == 3U && code_point < 0x800U) ||
        (length == 4U && (code_point < 0x10000U || code_point > 0x10FFFFU)) ||
        (code_point >= 0xD800U && code_point <= 0xDFFFU)) {
        return 0U;
    }
    return length;
}

}  // namespace

bool append_json_string_body(std::string& out, const std::string_view value) {
    bool replaced = false;
    const auto* data = reinterpret_cast<const unsigned char*>(value.data());
    std::size_t index = 0U;
    while (index < value.size()) {
        // Fast path: copy a run of printable ASCII that needs no escaping in one append.
        std::size_t run = index;
        while (run < value.size() && data[run] >= 0x20U && data[run] < 0x7FU && data[run] != '"' && data[run] != '\\') ++run;
        if (run > index) {
            out.append(value.data() + index, run - index);
            index = run;
            continue;
        }
        const unsigned char c = data[index];
        if (c >= 0x80U) {
            const auto length = valid_utf8_sequence(data + index, value.size() - index);
            if (length == 0U) {
                out += "\xEF\xBF\xBD";  // U+FFFD
                replaced = true;
                ++index;
            } else {
                out.append(value.data() + index, length);
                index += length;
            }
            continue;
        }
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
            if (c < 0x20U || c == 0x7FU) {
                out += "\\u00";
                out += hex_digits[c >> 4U];
                out += hex_digits[c & 0x0FU];
            } else {
                out += static_cast<char>(c);
            }
        }
        ++index;
    }
    return replaced;
}

void json_writer::separate() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!first_.empty()) {
        if (!first_.back()) out_ += ',';
        first_.back() = false;
    }
}

json_writer& json_writer::begin_object() {
    separate();
    out_ += '{';
    first_.push_back(true);
    return *this;
}

json_writer& json_writer::end_object() {
    assert(!first_.empty() && !after_key_);
    out_ += '}';
    first_.pop_back();
    return *this;
}

json_writer& json_writer::begin_array() {
    separate();
    out_ += '[';
    first_.push_back(true);
    return *this;
}

json_writer& json_writer::end_array() {
    assert(!first_.empty() && !after_key_);
    out_ += ']';
    first_.pop_back();
    return *this;
}

json_writer& json_writer::key(const std::string_view name) {
    assert(!after_key_);
    separate();
    out_ += '"';
    replaced_ |= append_json_string_body(out_, name);
    out_ += "\":";
    after_key_ = true;
    return *this;
}

json_writer& json_writer::value(const std::string_view text) {
    separate();
    out_ += '"';
    replaced_ |= append_json_string_body(out_, text);
    out_ += '"';
    return *this;
}

json_writer& json_writer::value(const std::uint64_t number) {
    separate();
    char buffer[24];
    const auto [end, error] = std::to_chars(buffer, buffer + sizeof(buffer), number);
    (void)error;
    out_.append(buffer, end);
    return *this;
}

json_writer& json_writer::value(const std::int64_t number) {
    separate();
    char buffer[24];
    const auto [end, error] = std::to_chars(buffer, buffer + sizeof(buffer), number);
    (void)error;
    out_.append(buffer, end);
    return *this;
}

json_writer& json_writer::value(const bool flag) {
    separate();
    out_ += flag ? "true" : "false";
    return *this;
}

json_writer& json_writer::null() {
    separate();
    out_ += "null";
    return *this;
}

json_writer& json_writer::raw(const std::string_view json) {
    separate();
    out_ += json;
    return *this;
}

}  // namespace panopticon::linux_agent::sensor
