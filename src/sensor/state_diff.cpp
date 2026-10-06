#include "panopticon/linux_agent/sensor/state_diff.hpp"

#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <array>
#include <cstdio>

namespace panopticon::linux_agent::sensor {

namespace {

struct diff_rule {
    std::string_view object;
    std::string_view type;
    std::array<std::string_view, 2> key_fields;  // an empty entry ends the list
    bool flatten;
};

constexpr std::array<diff_rule, 6> rules{{
    {"posture", "posture.changed", {"", ""}, true},
    {"interfaces", "interface.changed", {"name", ""}, false},
    {"users", "account.changed", {"name", ""}, false},
    {"groups", "account.changed", {"name", ""}, false},
    {"packages", "package.changed", {"name", "architecture"}, false},
    {"devices", "device.changed", {"path", ""}, false},
}};

const diff_rule* rule_for(const std::string_view object) {
    for (const auto& rule : rules) {
        if (rule.object == object) return &rule;
    }
    return nullptr;
}

std::string json_quoted(const std::string_view text) {
    std::string out{"\""};
    for (const unsigned char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20U) {
            char buffer[8];
            std::snprintf(buffer, sizeof buffer, "\\u%04x", c);
            out += buffer;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out + "\"";
}

// Compact rendering of a parsed value, members in source order.
std::string render(const json_value& value) {
    switch (value.type()) {
        case json_value::kind::null: return "null";
        case json_value::kind::boolean: return value.as_boolean().value_or(false) ? "true" : "false";
        case json_value::kind::integer:
            if (const auto number = value.as_integer()) return std::to_string(*number);
            return std::to_string(value.as_unsigned().value_or(0U));
        case json_value::kind::real: return std::to_string(value.as_double_or(0.0));
        case json_value::kind::string: return json_quoted(value.as_string().value_or(""));
        case json_value::kind::array: {
            std::string out{"["};
            for (std::size_t i = 0U; i < value.items().size(); ++i) {
                if (i != 0U) out += ',';
                out += render(value.items()[i]);
            }
            return out + "]";
        }
        case json_value::kind::object: {
            std::string out{"{"};
            for (std::size_t i = 0U; i < value.items().size(); ++i) {
                if (i != 0U) out += ',';
                out += json_quoted(value.keys()[i]) + ":" + render(value.items()[i]);
            }
            return out + "}";
        }
    }
    return "null";
}

// One entry per leaf; arrays are leaves. Depth is bounded by the parser's own limit.
void flatten(const json_value& value, const std::string& path, std::map<std::string, std::string>& out) {
    if (value.is_object()) {
        for (std::size_t i = 0U; i < value.items().size(); ++i) {
            flatten(value.items()[i], path.empty() ? value.keys()[i] : path + "." + value.keys()[i], out);
        }
        return;
    }
    out[path] = render(value);
}

std::string key_text(const json_value& value) {
    if (const auto text = value.as_string()) return std::string{*text};
    if (value.type() == json_value::kind::integer) return render(value);
    return {};
}

}  // namespace

std::string_view change_type_for(const std::string_view object) {
    const auto* rule = rule_for(object);
    return rule == nullptr ? std::string_view{} : rule->type;
}

std::optional<state_change> state_differ::observe(const state_snapshot& snapshot) {
    const auto* rule = rule_for(snapshot.object);
    if (rule == nullptr) return std::nullopt;

    std::map<std::string, std::string> current;
    json_limits limits;
    limits.maximum_bytes = 256U * 1024U;
    for (const auto& item : snapshot.items) {
        const auto parsed = parse_json(item, limits);
        if (!parsed || !parsed->is_object()) continue;
        if (rule->flatten) {
            flatten(*parsed, {}, current);
            continue;
        }
        std::string key;
        for (const auto field : rule->key_fields) {
            if (field.empty()) break;
            const auto* member = parsed->find(field);
            if (member == nullptr) continue;
            if (!key.empty()) key += '|';
            key += key_text(*member);
        }
        if (!key.empty()) current[key] = item;
    }

    const auto found = previous_.find(snapshot.object);
    if (found == previous_.end()) {
        previous_.emplace(snapshot.object, std::move(current));
        return std::nullopt;
    }
    const auto& before = found->second;
    state_change change;
    change.object = snapshot.object;
    change.type = std::string{rule->type};
    const auto record = [&](state_change_entry entry) {
        ++change.total;
        if (change.entries.size() < maximum_entries_) change.entries.push_back(std::move(entry));
        else change.truncated = true;
    };
    for (const auto& [key, value] : current) {
        const auto old = before.find(key);
        if (old == before.end()) record({key, "added", std::nullopt, value});
        else if (old->second != value) record({key, "modified", old->second, value});
    }
    // A missing item only means "removed" when the snapshot was complete, and never for posture,
    // where a setting that failed to read this time would look like a removed sysctl.
    if (!snapshot.truncated && !rule->flatten) {
        for (const auto& [key, value] : before) {
            if (current.find(key) == current.end()) record({key, "removed", value, std::nullopt});
        }
    }
    found->second = std::move(current);
    if (change.total == 0U) return std::nullopt;
    return change;
}

}  // namespace panopticon::linux_agent::sensor
