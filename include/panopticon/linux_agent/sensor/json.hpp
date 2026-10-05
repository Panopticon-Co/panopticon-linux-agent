#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Appends `value` to `out` as the body of a JSON string (no surrounding quotes).
// Input is treated as raw bytes from the kernel or the filesystem: control characters are
// escaped, and byte sequences that are not valid UTF-8 are replaced by U+FFFD so the output is
// always valid JSON. Returns true when a replacement was necessary.
bool append_json_string_body(std::string& out, std::string_view value);

// Minimal streaming JSON writer. Structure errors (a value without a key inside an object,
// unbalanced end calls) are programming errors and are guarded by assertions in debug builds;
// the writer never emits invalid string content.
class json_writer {
public:
    json_writer& begin_object();
    json_writer& end_object();
    json_writer& begin_array();
    json_writer& end_array();
    json_writer& key(std::string_view name);

    json_writer& value(std::string_view text);
    json_writer& value(const char* text) { return value(std::string_view{text}); }
    json_writer& value(const std::string& text) { return value(std::string_view{text}); }
    json_writer& value(std::uint64_t number);
    json_writer& value(std::int64_t number);
    json_writer& value(std::uint32_t number) { return value(static_cast<std::uint64_t>(number)); }
    json_writer& value(std::int32_t number) { return value(static_cast<std::int64_t>(number)); }
    json_writer& value(bool flag);
    json_writer& null();
    // Inserts an already-serialised JSON value verbatim (used to embed sub-documents).
    json_writer& raw(std::string_view json);

    template <typename value_type>
    json_writer& field(std::string_view name, const value_type& v) {
        key(name);
        return value(v);
    }
    json_writer& field_null(std::string_view name) {
        key(name);
        return null();
    }

    [[nodiscard]] bool replaced_invalid_utf8() const noexcept { return replaced_; }
    [[nodiscard]] const std::string& str() const noexcept { return out_; }
    [[nodiscard]] std::string take() { return std::move(out_); }

private:
    void separate();

    std::string out_;
    std::vector<bool> first_;  // per open container: no element written yet
    bool after_key_{false};
    bool replaced_{false};
};

}  // namespace panopticon::linux_agent::sensor
