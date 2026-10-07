#include "panopticon/linux_agent/sensor/policy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <utility>

namespace panopticon::linux_agent::sensor {

namespace {

constexpr std::array<std::pair<std::string_view, policy_field>, 6> field_names{{
    {"exe", policy_field::exe},
    {"cmdline", policy_field::cmdline},
    {"sha256", policy_field::sha256},
    {"file_path", policy_field::file_path},
    {"dest_ip", policy_field::dest_ip},
    {"dest_domain", policy_field::dest_domain},
}};

template <typename value_type, std::size_t count>
bool lookup(const std::array<std::pair<std::string_view, value_type>, count>& table, const std::string_view name, value_type& out) {
    for (const auto& [key, value] : table) {
        if (key == name) {
            out = value;
            return true;
        }
    }
    return false;
}

bool parse_operator(const std::string_view name, policy_operator& out) {
    static constexpr std::array<std::pair<std::string_view, policy_operator>, 5> names{{
        {"equals", policy_operator::equals}, {"prefix", policy_operator::prefix}, {"suffix", policy_operator::suffix},
        {"contains", policy_operator::contains}, {"ioc", policy_operator::ioc}}};
    return lookup(names, name, out);
}

bool parse_action(const std::string_view name, policy_action& out) {
    static constexpr std::array<std::pair<std::string_view, policy_action>, 4> names{{
        {"alert", policy_action::alert}, {"recommend_terminate", policy_action::recommend_terminate},
        {"recommend_quarantine", policy_action::recommend_quarantine}, {"recommend_block", policy_action::recommend_block}}};
    return lookup(names, name, out);
}

bool parse_severity(const std::string_view name, policy_severity& out) {
    static constexpr std::array<std::pair<std::string_view, policy_severity>, 4> names{{
        {"low", policy_severity::low}, {"medium", policy_severity::medium}, {"high", policy_severity::high}, {"critical", policy_severity::critical}}};
    return lookup(names, name, out);
}

bool parse_field(const std::string_view name, policy_field& out) { return lookup(field_names, name, out); }

bool plain_identifier(const std::string_view text) {
    if (text.empty() || text.size() > 64U) return false;
    return std::all_of(text.begin(), text.end(), [](const unsigned char c) { return std::isalnum(c) != 0 || c == '_' || c == '-' || c == '.' || c == '*'; });
}

bool is_lower_hex(const std::string_view text, const std::size_t length) {
    return text.size() == length && std::all_of(text.begin(), text.end(), [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

std::string lowered(std::string_view text) {
    std::string out{text};
    std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Splits off the next space-separated token; returns false when none is left.
bool next_token(std::string_view& rest, std::string_view& token) {
    while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1U);
    if (rest.empty()) return false;
    const auto space = rest.find(' ');
    token = rest.substr(0U, space);
    rest.remove_prefix(space == std::string_view::npos ? rest.size() : space);
    return true;
}

const std::string& field_of(const policy_input& input, const policy_field field) {
    switch (field) {
        case policy_field::exe: return input.exe;
        case policy_field::cmdline: return input.cmdline;
        case policy_field::sha256: return input.sha256;
        case policy_field::file_path: return input.file_path;
        case policy_field::dest_ip: return input.dest_ip;
        case policy_field::dest_domain: return input.dest_domain;
    }
    return input.exe;
}

bool starts_with(const std::string_view text, const std::string_view prefix) { return text.size() >= prefix.size() && text.compare(0U, prefix.size(), prefix) == 0; }
bool ends_with(const std::string_view text, const std::string_view suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// A prefix rule on a path matches on a component boundary: /tmp matches /tmp and /tmp/x, not /tmpfoo.
bool path_prefix(const std::string_view text, const std::string_view prefix) {
    if (!starts_with(text, prefix)) return false;
    return text.size() == prefix.size() || prefix.back() == '/' || text[prefix.size()] == '/';
}

bool in_set(const std::set<std::string>& set, const policy_field field, const std::string& value) {
    if (value.empty()) return false;
    if (field == policy_field::dest_domain) {
        // evil.example matches a.b.evil.example: walk the parent domains.
        std::string_view name{value};
        while (true) {
            if (set.count(lowered(name)) != 0U) return true;
            const auto dot = name.find('.');
            if (dot == std::string_view::npos) return false;
            name.remove_prefix(dot + 1U);
        }
    }
    return set.count(field == policy_field::sha256 ? lowered(value) : value) != 0U;
}

}  // namespace

const char* to_string(const policy_action action) noexcept {
    switch (action) {
        case policy_action::alert: return "alert";
        case policy_action::recommend_terminate: return "recommend_terminate";
        case policy_action::recommend_quarantine: return "recommend_quarantine";
        case policy_action::recommend_block: return "recommend_block";
    }
    return "alert";
}

const char* to_string(const policy_severity severity) noexcept {
    switch (severity) {
        case policy_severity::low: return "low";
        case policy_severity::medium: return "medium";
        case policy_severity::high: return "high";
        case policy_severity::critical: return "critical";
    }
    return "low";
}

const char* to_string(const policy_field field) noexcept {
    for (const auto& [name, value] : field_names) {
        if (value == field) return name.data();
    }
    return "exe";
}

std::size_t policy_engine::ioc_count() const noexcept {
    std::size_t total{};
    for (const auto& set : iocs_) total += set.size();
    return total;
}

result<policy_engine> policy_engine::parse(const std::string_view text, const policy_limits& limits) {
    policy_engine engine;
    engine.limits_ = limits;
    std::set<std::string> rule_ids;
    std::size_t line_number{};
    std::size_t cursor{};
    const auto fail = [&](const std::string& why) -> result<policy_engine> {
        return error{error_code::invalid_input, "policy line " + std::to_string(line_number) + ": " + why};
    };
    while (cursor <= text.size()) {
        const auto newline = text.find('\n', cursor);
        auto line = text.substr(cursor, newline == std::string_view::npos ? std::string_view::npos : newline - cursor);
        cursor = newline == std::string_view::npos ? text.size() + 1U : newline + 1U;
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1U);
        if (line.size() > limits.maximum_line_bytes) return fail("line is too long");
        if (std::any_of(line.begin(), line.end(), [](const unsigned char c) { return c < 0x20U && c != '\t'; })) return fail("control character");
        std::string_view rest = line;
        std::string_view directive;
        if (!next_token(rest, directive) || directive.front() == '#') continue;

        if (directive == "rule") {
            std::string_view id, kind, field_name, operator_name, action_name, severity_name;
            if (!next_token(rest, id) || !next_token(rest, kind) || !next_token(rest, field_name) || !next_token(rest, operator_name) ||
                !next_token(rest, action_name) || !next_token(rest, severity_name)) {
                return fail("rule needs id kind field operator action severity");
            }
            policy_rule rule;
            if (!plain_identifier(id) || !plain_identifier(kind)) return fail("bad rule id or kind");
            if (!parse_field(field_name, rule.field)) return fail("unknown field");
            if (!parse_operator(operator_name, rule.op)) return fail("unknown operator");
            if (!parse_action(action_name, rule.action)) return fail("unknown action");
            if (!parse_severity(severity_name, rule.severity)) return fail("unknown severity");
            while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1U);
            if (rule.op != policy_operator::ioc && rest.empty()) return fail("rule has no value");
            if (rule.op == policy_operator::ioc && !rest.empty()) return fail("an ioc rule takes no value");
            if (!rule_ids.insert(std::string{id}).second) return fail("duplicate rule id");
            if (engine.rules_.size() >= limits.maximum_rules) return fail("too many rules");
            rule.id = std::string{id};
            rule.kind = std::string{kind};
            rule.value = rule.field == policy_field::sha256 ? lowered(rest) : std::string{rest};
            engine.rules_.push_back(std::move(rule));
        } else if (directive == "ioc") {
            std::string_view field_name, value;
            policy_field field{};
            if (!next_token(rest, field_name) || !next_token(rest, value) || !parse_field(field_name, field) || field == policy_field::cmdline) {
                return fail("ioc needs a field (not cmdline) and a value");
            }
            std::string_view extra;
            if (next_token(rest, extra)) return fail("ioc takes exactly one value");
            std::string stored{value};
            if (field == policy_field::sha256) {
                stored = lowered(value);
                if (!is_lower_hex(stored, 64U)) return fail("sha256 must be 64 hex digits");
            } else if (field == policy_field::dest_domain) {
                stored = lowered(value);
            }
            if (engine.ioc_count() >= limits.maximum_iocs) return fail("too many indicators");
            engine.iocs_[static_cast<std::size_t>(field)].insert(std::move(stored));
        } else if (directive == "allow") {
            std::string_view what, prefix;
            if (!next_token(rest, what) || what != "exe" || !next_token(rest, prefix) || prefix.front() != '/') return fail("allow needs: exe <absolute path prefix>");
            std::string_view extra;
            if (next_token(rest, extra)) return fail("allow takes exactly one path");
            engine.allow_exe_.emplace_back(prefix);
        } else {
            return fail("unknown directive");
        }
    }
    // An indicator only matters through an `ioc` rule on its field. Indicators no rule consults would load and
    // never match, a policy that looks in force while part of it is dead, so the whole policy is refused.
    for (std::size_t index = 0U; index < std::size(engine.iocs_); ++index) {
        if (engine.iocs_[index].empty()) continue;
        const bool used = std::any_of(engine.rules_.begin(), engine.rules_.end(), [&](const policy_rule& rule) {
            return rule.op == policy_operator::ioc && static_cast<std::size_t>(rule.field) == index;
        });
        if (!used) {
            return error{error_code::invalid_input,
                         "policy: " + std::string{to_string(static_cast<policy_field>(index))} + " indicators have no ioc rule on that field"};
        }
    }
    return engine;
}

bool policy_engine::has_rules_on(const policy_field field) const noexcept {
    return std::any_of(rules_.begin(), rules_.end(), [field](const policy_rule& rule) { return rule.field == field; });
}

std::vector<policy_decision> policy_engine::evaluate(const policy_input& input, const std::optional<policy_field> only) const {
    std::vector<policy_decision> decisions;
    for (const auto& prefix : allow_exe_) {
        if (!input.exe.empty() && path_prefix(input.exe, prefix)) return decisions;
    }
    for (const auto& rule : rules_) {
        if (decisions.size() >= limits_.maximum_decisions) break;
        if (only && rule.field != *only) continue;
        if (rule.kind != "*" && rule.kind != input.kind) continue;
        const auto& value = field_of(input, rule.field);
        if (value.empty()) continue;
        bool matched{};
        switch (rule.op) {
            case policy_operator::equals: matched = rule.field == policy_field::sha256 ? lowered(value) == rule.value : value == rule.value; break;
            case policy_operator::prefix:
                matched = rule.field == policy_field::exe || rule.field == policy_field::file_path ? path_prefix(value, rule.value) : starts_with(value, rule.value);
                break;
            case policy_operator::suffix: matched = ends_with(value, rule.value); break;
            case policy_operator::contains: matched = value.find(rule.value) != std::string::npos; break;
            case policy_operator::ioc: matched = in_set(iocs_[static_cast<std::size_t>(rule.field)], rule.field, value); break;
        }
        if (!matched) continue;
        policy_decision decision;
        decision.rule_id = rule.id;
        decision.action = rule.action;
        decision.severity = rule.severity;
        decision.field = to_string(rule.field);
        decision.matched = value.substr(0U, limits_.maximum_matched_bytes);
        decisions.push_back(std::move(decision));
    }
    return decisions;
}

}  // namespace panopticon::linux_agent::sensor
