#pragma once

#include "panopticon/linux_agent/error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

// Local policy: indicators of compromise and simple rules evaluated against facts about one event
// (ADR 016). It decides; it never acts. A decision names a recommended action and becomes a
// policy.match record (ADR 032); nothing on the endpoint carries it out. Acting on it takes a
// Manager-authorized, signed command.
//
// There are no regular expressions: matching is equals, prefix, suffix, contains or set membership,
// so evaluation cost is linear in the input and cannot be driven into backtracking by an attacker
// who chooses a command line or a file name.

struct policy_input {
    std::string kind;       // "process.exec", "file.created", "network.connect", ...
    std::string exe;        // absolute executable path
    std::string cmdline;    // joined argument vector
    std::string sha256;     // lowercase hex of the executed image, when known
    std::string file_path;  // for file events
    std::string dest_ip;    // for network events
    std::string dest_domain;
};

enum class policy_action : std::uint8_t { alert, recommend_terminate, recommend_quarantine, recommend_block };
enum class policy_severity : std::uint8_t { low, medium, high, critical };
enum class policy_field : std::uint8_t { exe, cmdline, sha256, file_path, dest_ip, dest_domain };
enum class policy_operator : std::uint8_t { equals, prefix, suffix, contains, ioc };

[[nodiscard]] const char* to_string(policy_action action) noexcept;
[[nodiscard]] const char* to_string(policy_severity severity) noexcept;
[[nodiscard]] const char* to_string(policy_field field) noexcept;

struct policy_rule {
    std::string id;
    std::string kind;  // event kind the rule applies to; "*" for any
    policy_field field{};
    policy_operator op{};
    policy_action action{};
    policy_severity severity{};
    std::string value;  // unused for `ioc`
};

struct policy_decision {
    std::string rule_id;
    policy_action action{};
    policy_severity severity{};
    std::string field;    // which fact matched
    std::string matched;  // the value that matched, bounded
};

struct policy_limits {
    std::size_t maximum_rules{1024U};
    std::size_t maximum_iocs{100000U};
    std::size_t maximum_line_bytes{4096U};
    std::size_t maximum_decisions{16U};
    std::size_t maximum_matched_bytes{256U};
};

// Policy file, one directive per line, `#` comments:
//   rule <id> <kind> <field> <operator> <action> <severity> <value...>
//   ioc  <field> <value>            (field: sha256, dest_ip, dest_domain, file_path, exe)
//   allow exe <absolute-path-prefix>
// Unknown directives, duplicate rule ids, bad enumerations, oversize lines and counts over the
// limits are errors: a policy that half-loads would silently stop protecting.
class policy_engine {
public:
    [[nodiscard]] static result<policy_engine> parse(std::string_view text, const policy_limits& limits = {});

    // Rules that match, in rule order, at most `maximum_decisions`. Empty when the executable is
    // allow-listed. With `only`, rules on other fields are skipped: a fact that arrives late (the
    // hash of an executed image) is decided on its own, without deciding the event's other facts again.
    [[nodiscard]] std::vector<policy_decision> evaluate(const policy_input& input, std::optional<policy_field> only = std::nullopt) const;

    [[nodiscard]] std::size_t rule_count() const noexcept { return rules_.size(); }
    [[nodiscard]] std::size_t ioc_count() const noexcept;

private:
    policy_limits limits_;
    std::vector<policy_rule> rules_;
    std::set<std::string> iocs_[6];  // per policy_field
    std::vector<std::string> allow_exe_;
};

}  // namespace panopticon::linux_agent::sensor
