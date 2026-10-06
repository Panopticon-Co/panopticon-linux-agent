#include "panopticon/linux_agent/sensor/file_actions.hpp"
#include "panopticon/linux_agent/sensor/json_reader.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

void require_result(const file_action_result& result, const char* outcome, const char* reason, const char* what) {
    if (result.outcome != outcome || result.reason != reason) {
        throw std::runtime_error{std::string{what} + ": got " + result.outcome + "/" + result.reason + " (" + result.detail + ")"};
    }
}

std::string slurp(const fs::path& path) {
    std::ifstream in{path, std::ios::binary};
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

void write_file(const fs::path& path, const std::string& text, const mode_t mode = 0644) {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out << text;
    out.close();
    ::chmod(path.c_str(), mode);
}

// Each test works in its own directory under /tmp (the build's temp dir may sit behind a symlink).
struct sandbox {
    fs::path root;
    file_action_options options;
    explicit sandbox(const char* name) {
        char pattern[] = "/tmp/panopticon-fileact-XXXXXX";
        const char* made = ::mkdtemp(pattern);
        require(made != nullptr, "temporary directory");
        root = fs::path{made} / name;
        fs::create_directories(root / "work");
        options.roots = {root / "work"};
        options.quarantine_dir = root / "store";
    }
    ~sandbox() {
        std::error_code ec;
        fs::remove_all(root.parent_path(), ec);
    }
    [[nodiscard]] fs::path work(const std::string& name) const { return root / "work" / name; }
};

const char* const hello_sha256 = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
const char* const empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ---- COLLECT_FILE ---------------------------------------------------------------------------

void test_collect_regular_file() {
    sandbox box{"collect"};
    write_file(box.work("a"), "hello\n", 0750);
    const auto result = collect_file(box.work("a").string(), box.options);
    require_result(result, "succeeded", "ok", "a regular file");
    require(result.detail.find(std::string{"sha256="} + hello_sha256) != std::string::npos, "the SHA-256 of the content");
    require(result.detail.find("type=regular size=6 mode=0750") != std::string::npos, "type, size and mode");
    require(result.affected == 1U, "one file");
    write_file(box.work("empty"), "");
    const auto empty = collect_file(box.work("empty").string(), box.options);
    require_result(empty, "succeeded", "ok", "an empty file");
    require(empty.detail.find(empty_sha256) != std::string::npos, "the SHA-256 of nothing");
}

void test_collect_refusals() {
    sandbox box{"refusals"};
    write_file(box.work("a"), "hello\n");
    const auto path = box.work("a").string();
    require_result(collect_file("relative/path", box.options), "rejected", "invalid_target", "relative");
    require_result(collect_file(box.root.string() + "/work/../work/a", box.options), "rejected", "invalid_target", "dot-dot");
    require_result(collect_file(path + "/", box.options), "rejected", "invalid_target", "trailing slash");
    require_result(collect_file(box.root.string() + "//work/a", box.options), "rejected", "invalid_target", "empty component");
    require_result(collect_file(box.root.string() + "/work/./a", box.options), "rejected", "invalid_target", "dot component");
    require_result(collect_file("/", box.options), "rejected", "invalid_target", "the root");
    require_result(collect_file(box.work("missing").string(), box.options), "rejected", "not_found", "missing file");
    require_result(collect_file(box.root.string() + "/nodir/a", box.options), "rejected", "not_found", "missing directory");
    fs::create_directories(box.work("d"));
    require_result(collect_file(box.work("d").string(), box.options), "rejected", "not_a_file", "a directory");
    require(::mkfifo(box.work("pipe").c_str(), 0600) == 0, "mkfifo");
    require_result(collect_file(box.work("pipe").string(), box.options), "rejected", "not_a_file", "a fifo is never opened");
    auto small = box.options;
    small.maximum_bytes = 4U;
    require_result(collect_file(path, small), "rejected", "file_too_large", "over the size bound");
}

void test_collect_symlinks() {
    sandbox box{"symlinks"};
    write_file(box.work("real"), "hello\n");
    fs::create_symlink(box.work("real"), box.work("link"));
    const auto link = collect_file(box.work("link").string(), box.options);
    require_result(link, "succeeded", "ok", "the link itself");
    require(link.detail.find("type=symlink") != std::string::npos && link.detail.find("target=") != std::string::npos, "reported as a link with its target");
    require(link.detail.find("sha256=") == std::string::npos, "the target's content is not read through a link");
    fs::create_directories(box.root / "elsewhere");
    write_file(box.root / "elsewhere" / "f", "x");
    fs::create_directory_symlink(box.root / "elsewhere", box.work("dirlink"));
    require_result(collect_file((box.work("dirlink") / "f").string(), box.options), "rejected", "path_symlink", "a symlinked directory on the path");
}

void test_collect_budget() {
    sandbox box{"budget"};
    write_file(box.work("big"), std::string(8U * 1024U * 1024U, 'x'));
    auto none = box.options;
    none.budget = std::chrono::milliseconds{0};
    const auto late = collect_file(box.work("big").string(), none);
    require(late.outcome == "failed" && late.reason == "budget_exceeded", "a hash that cannot finish in its budget fails, it does not hang or guess");
}

// ---- QUARANTINE_FILE ------------------------------------------------------------------------

void test_quarantine_refusals() {
    sandbox box{"qrefuse"};
    write_file(box.work("a"), "hello\n");
    const auto path = box.work("a").string();
    file_action_options unconfigured;
    require_result(quarantine_file(path, "c1", false, unconfigured), "rejected", "quarantine_unavailable", "nothing configured");
    auto no_roots = box.options;
    no_roots.roots.clear();
    require_result(quarantine_file(path, "c1", false, no_roots), "rejected", "quarantine_unavailable", "no permitted directory");
    write_file(box.root / "outside", "x");
    require_result(quarantine_file((box.root / "outside").string(), "c2", false, box.options), "rejected", "outside_roots", "outside the roots");
    fs::create_directories(box.root / "workshop");
    write_file(box.root / "workshop" / "f", "x");
    require_result(quarantine_file((box.root / "workshop" / "f").string(), "c3", false, box.options), "rejected", "outside_roots", "a sibling that shares a name prefix");
    auto wide = box.options;
    wide.roots = {fs::path{"/proc"}, fs::path{"/etc"}};
    require_result(quarantine_file("/proc/self/status", "c4", false, wide), "rejected", "target_protected", "pseudo-filesystems are protected even inside a root");
    auto guarded = box.options;
    guarded.protected_paths = {box.work("a")};
    require_result(quarantine_file(path, "c5", false, guarded), "rejected", "target_protected", "a protected path");
    auto in_store = box.options;
    in_store.roots = {box.root};
    fs::create_directories(box.options.quarantine_dir);
    write_file(box.options.quarantine_dir / "x.blob", "x");
    require_result(quarantine_file((box.options.quarantine_dir / "x.blob").string(), "c6", false, in_store), "rejected", "target_protected", "the store itself");
    fs::create_symlink(box.work("a"), box.work("link"));
    require_result(quarantine_file(box.work("link").string(), "c7", false, box.options), "rejected", "not_a_file", "a symlink is not quarantined");
    fs::create_directories(box.work("d"));
    require_result(quarantine_file(box.work("d").string(), "c8", false, box.options), "rejected", "not_a_file", "a directory");
    auto self = box.options;
    char exe[4096];
    const auto length = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1U);
    require(length > 0, "readlink exe");
    exe[length] = '\0';
    self.roots = {fs::path{exe}.parent_path()};
    require_result(quarantine_file(exe, "c9", false, self), "rejected", "target_protected", "the sensor's own executable");
    require(fs::exists(path), "no refusal moved anything");
}

void test_quarantine_dry_run_changes_nothing() {
    sandbox box{"qdry"};
    write_file(box.work("a"), "hello\n");
    const auto result = quarantine_file(box.work("a").string(), "dry1", true, box.options);
    require_result(result, "rejected", "dry_run", "dry run");
    require(result.detail.find(hello_sha256) != std::string::npos, "the dry run still examined and hashed the file");
    require(fs::exists(box.work("a")) && slurp(box.work("a")) == "hello\n", "the file is untouched");
    require(!fs::exists(box.options.quarantine_dir), "and no store was created");
}

void test_quarantine_moves_and_records() {
    sandbox box{"qmove"};
    write_file(box.work("evil"), "hello\n", 04755);
    const auto result = quarantine_file(box.work("evil").string(), "cmd-1", false, box.options);
    require_result(result, "succeeded", "ok", "quarantine");
    require(result.detail.find("moved") != std::string::npos && result.detail.find(hello_sha256) != std::string::npos, "detail names how and what");
    require(!fs::exists(box.work("evil")), "the original is gone");
    const auto blob = box.options.quarantine_dir / "cmd-1.blob";
    require(slurp(blob) == "hello\n", "the stored copy is byte for byte the file");
    struct stat info {};
    require(::stat(blob.c_str(), &info) == 0 && (info.st_mode & 07777U) == 0400U, "stored read-only, no execute, no setuid");
    require(::stat(box.options.quarantine_dir.c_str(), &info) == 0 && (info.st_mode & 077U) == 0U, "the store is private");
    std::string why;
    const auto meta = parse_json(slurp(box.options.quarantine_dir / "cmd-1.json"), json_limits{}, &why);
    require(meta.has_value(), "the record is JSON");
    require(meta->find("original_path")->as_string() == box.work("evil").string(), "the record names the original path");
    require(meta->find("sha256")->as_string() == std::string{hello_sha256}, "and the hash");
    require(meta->find("mode")->as_unsigned() == 04755U, "and the original mode");
    // The same command id again cannot overwrite what is stored.
    write_file(box.work("evil"), "other\n");
    require_result(quarantine_file(box.work("evil").string(), "cmd-1", false, box.options), "failed", "store_conflict", "reused command id");
    require(slurp(box.work("evil")) == "other\n" && slurp(blob) == "hello\n", "nothing was overwritten or lost");
}

void test_quarantine_hard_link_is_reported() {
    sandbox box{"qlink"};
    write_file(box.work("a"), "hello\n");
    fs::create_hard_link(box.work("a"), box.work("b"));
    const auto result = quarantine_file(box.work("a").string(), "hl", false, box.options);
    require_result(result, "succeeded", "ok", "one name of a hard link");
    require(result.detail.find("other_links=1") != std::string::npos, "the remaining name is reported, not hidden");
    require(fs::exists(box.work("b")), "and it is still there");
}

void test_quarantine_store_limits() {
    sandbox box{"qlimit"};
    auto limited = box.options;
    limited.store_maximum_entries = 1U;
    write_file(box.work("a"), "one");
    write_file(box.work("b"), "two");
    require_result(quarantine_file(box.work("a").string(), "l1", false, limited), "succeeded", "ok", "first fits");
    require_result(quarantine_file(box.work("b").string(), "l2", false, limited), "rejected", "quarantine_full", "second does not");
    require(fs::exists(box.work("b")), "a refused quarantine leaves the file");
    auto bytes = box.options;
    bytes.quarantine_dir = box.root / "store2";
    bytes.store_maximum_bytes = 2U;
    require_result(quarantine_file(box.work("b").string(), "l3", false, bytes), "rejected", "quarantine_full", "a file larger than the byte limit");
    auto too_big = box.options;
    too_big.maximum_bytes = 2U;
    require_result(quarantine_file(box.work("b").string(), "l4", false, too_big), "rejected", "file_too_large", "over the size bound");
}

void test_quarantine_insecure_store_refused() {
    sandbox box{"qinsecure"};
    write_file(box.work("a"), "hello\n");
    fs::create_directories(box.options.quarantine_dir);
    ::chmod(box.options.quarantine_dir.c_str(), 0755);
    require_result(quarantine_file(box.work("a").string(), "ins", false, box.options), "failed", "store_insecure", "a store others can enter");
    require(fs::exists(box.work("a")), "the file stays");
}

void test_quarantine_across_filesystems() {
    // /run is a different filesystem from /tmp on the validation host; where it is not, the case cannot be exercised.
    char pattern[] = "/run/panopticon-fileact-XXXXXX";
    const char* made = ::mkdtemp(pattern);
    if (made == nullptr) {
        std::printf("SKIP quarantine_across_filesystems (no writable /run)\n");
        return;
    }
    const fs::path source_root{made};
    struct Cleanup {
        fs::path path;
        ~Cleanup() {
            std::error_code ec;
            fs::remove_all(path, ec);
        }
    } cleanup{source_root};
    sandbox box{"qxdev"};
    struct stat a {}, b {};
    require(::stat(source_root.c_str(), &a) == 0 && ::stat(box.root.c_str(), &b) == 0, "stat");
    if (a.st_dev == b.st_dev) {
        std::printf("SKIP quarantine_across_filesystems (/run and /tmp are one filesystem)\n");
        return;
    }
    auto options = box.options;
    options.roots = {source_root};
    write_file(source_root / "f", std::string(3U * 1024U * 1024U + 17U, 'z'), 0755);
    const auto result = quarantine_file((source_root / "f").string(), "xdev", false, options);
    require_result(result, "succeeded", "ok", "a copy across filesystems");
    require(result.detail.find("copied") != std::string::npos, "it says it copied");
    require(!fs::exists(source_root / "f"), "the original is removed only after the copy was verified");
    require(fs::file_size(box.options.quarantine_dir / "xdev.blob") == 3U * 1024U * 1024U + 17U, "the whole file is stored");
    // An interrupted copy leaves only a .part file, which the next quarantine removes.
    write_file(box.options.quarantine_dir / "junk.blob.part", "partial");
    write_file(box.work("n"), "x");
    require_result(quarantine_file(box.work("n").string(), "after", false, box.options), "succeeded", "ok", "next quarantine");
    require(!fs::exists(box.options.quarantine_dir / "junk.blob.part"), "the partial copy was cleaned up");
}

}  // namespace

int main() {
    struct test {
        const char* name;
        void (*run)();
    };
    const test tests[] = {
        {"collect_regular_file", test_collect_regular_file},
        {"collect_refusals", test_collect_refusals},
        {"collect_symlinks", test_collect_symlinks},
        {"collect_budget", test_collect_budget},
        {"quarantine_refusals", test_quarantine_refusals},
        {"quarantine_dry_run_changes_nothing", test_quarantine_dry_run_changes_nothing},
        {"quarantine_moves_and_records", test_quarantine_moves_and_records},
        {"quarantine_hard_link_is_reported", test_quarantine_hard_link_is_reported},
        {"quarantine_store_limits", test_quarantine_store_limits},
        {"quarantine_insecure_store_refused", test_quarantine_insecure_store_refused},
        {"quarantine_across_filesystems", test_quarantine_across_filesystems},
    };
    int failures = 0;
    for (const auto& item : tests) {
        try {
            item.run();
            std::printf("PASS %s\n", item.name);
        } catch (const std::exception& error) {
            std::printf("FAIL %s: %s\n", item.name, error.what());
            ++failures;
        }
    }
    std::printf(failures == 0 ? "ALL PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
