// Self-integrity (ADR 033): the signed build manifest and the monitor that checks the installed files against it.
#include "panopticon/linux_agent/event.hpp"
#include "panopticon/linux_agent/keypair.hpp"
#include "panopticon/linux_agent/sensor/command_auth.hpp"
#include "panopticon/linux_agent/sensor/integrity.hpp"
#include "policy_test_support.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace panopticon::linux_agent;
using namespace panopticon::linux_agent::sensor;
namespace fs = std::filesystem;

namespace {

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

fs::path fresh(const std::string& name) {
    const auto path = fs::temp_directory_path() / ("panopticon-integrity-tests-" + std::to_string(::getpid()) + "-" + name);
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

std::string slurp(const fs::path& path) {
    std::ifstream in{path, std::ios::binary};
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::int64_t now_s() { return static_cast<std::int64_t>(std::time(nullptr)); }

// A signed manifest for these files as they are now.
std::string manifest_for(const ec_keypair& key, const std::vector<fs::path>& files, const std::string& version = "0.1.0", const std::int64_t built = 0) {
    std::vector<manifest_entry> entries;
    for (const auto& file : files) {
        const auto content = slurp(file);
        entries.push_back({sha256_hex(content), content.size(), file.string()});
    }
    build_manifest header;
    header.package = "panopticon-sensord";
    header.version = version;
    header.built_unix = built != 0 ? built : now_s();
    header.key_id = signing_key_id(key.public_point);
    const auto body = render_manifest_body(entries);
    const auto input = manifest_signing_input(header, sha256_hex(body));
    const auto signature = sign_raw(key, std::vector<std::uint8_t>(input.begin(), input.end()));
    require(succeeded(signature), "cannot sign a test manifest");
    header.signature = std::get<ec_raw_signature>(signature);
    return render_build_manifest(header, body);
}

// An install: a stand-in for the running sensor binary, one more installed file, a manifest and the pinned key.
struct install {
    fs::path dir;
    fs::path sensord, helper, manifest, keys;
    ec_keypair key = policy_test_support::make_key();

    explicit install(const std::string& name) : dir{fresh(name)} {
        sensord = dir / "sensord";
        helper = dir / "helper";
        manifest = dir / "build-manifest";
        keys = dir / "integrity.keys";
        put(sensord, "sensor image v1 " + std::string(4096U, 's'), 0700);
        put(helper, "helper v1 " + std::string(1024U, 'h'), 0700);
        put(keys, policy_test_support::key_line(key));
        sign();
    }
    void sign(const std::vector<fs::path>& files = {}) { put(manifest, manifest_for(key, files.empty() ? std::vector<fs::path>{sensord, helper} : files)); }
    fs::path state() const { return dir / "integrity.state"; }
    integrity_options options() const {
        integrity_options o;
        o.manifest_path = manifest;
        o.keys_path = keys;
        o.state_path = state();
        o.running_image = sensord;
        o.full_check_seconds = 600U;
        return o;
    }
};

const integrity_change* find(const std::vector<integrity_change>& changes, const std::string& technique, const std::string& status) {
    for (const auto& change : changes) {
        if (change.finding.technique == technique && change.status == status) return &change;
    }
    return nullptr;
}

std::string describe(const std::vector<integrity_change>& changes) {
    std::string out;
    for (const auto& change : changes) out += change.status + " " + change.finding.technique + " " + change.finding.target + ": " + change.finding.detail + "; ";
    return out.empty() ? "no changes" : out;
}

void test_manifest_parses_and_is_strict() {
    install fx{"parse"};
    const auto text = slurp(fx.manifest);
    auto parsed = parse_build_manifest(text);
    require(succeeded(parsed), "a signed manifest parses");
    const auto& manifest = std::get<build_manifest>(parsed);
    require(manifest.package == "panopticon-sensord" && manifest.version == "0.1.0" && manifest.entries.size() == 2U, "header and entries");
    require(manifest.entries[0].path == fx.sensord.string() && manifest.entries[0].sha256.size() == 64U && manifest.entries[0].size > 4096U, "entry fields");
    const auto input = manifest_signing_input(manifest, manifest.body_sha256);
    require(input.rfind("panopticon-build-manifest/1\npackage:18:panopticon-sensord\nversion:5:0.1.0\nbuilt_at:", 0U) == 0U, "length-prefixed signing input: " + input);

    const auto bad = [&](const std::string& variant, const char* what) { require(!succeeded(parse_build_manifest(variant)), what); };
    const auto replace = [&](const std::string& from, const std::string& to) {
        auto copy = text;
        const auto at = copy.find(from);
        require(at != std::string::npos, "test setup: text to replace: " + from);
        return copy.replace(at, from.size(), to);
    };
    bad(text.substr(1U), "the magic line is required");
    bad(replace("panopticon-build-manifest 1", "panopticon-build-manifest 2"), "an unknown format version");
    bad(replace("package panopticon-sensord", "package bad name"), "a package that is not an identifier");
    bad(replace("\nbuilt_at ", "\nbuilt_at 0"), "a leading zero");
    bad(replace("key_id ", "key_id A"), "a key id that is not 16 lowercase hex digits");
    bad(replace("signature ", "signature !"), "a signature that is not base64");
    bad(replace("\n---\n", "\n--\n"), "the separator is exact");
    bad(text.substr(0U, text.find("\n---\n") + 5U), "no files");
    bad(text + "nonsense\n", "a body line that is not a file line");
    bad(text + std::string(64U, 'A') + " 1 /x\n", "an upper-case hash");
    bad(text + std::string(64U, 'a') + " 1 relative/path\n", "a relative path");
    bad(text + std::string(64U, 'a') + " 1 /usr/../bin/x\n", "a path with ..");
    bad(text + std::string(64U, 'a') + " 1 /usr//bin/x\n", "a path with //");
    bad(text + std::string(64U, 'a') + " 1 /usr/bin/\n", "a path ending in /");
    bad(text + std::string(64U, 'a') + " 01 /usr/bin/x\n", "a size with a leading zero");
    bad(text + manifest.entries[0].sha256 + " 1 " + manifest.entries[0].path + "\n", "a path listed twice");
    bad(text.substr(0U, text.size() - 1U), "a body that does not end in a newline");
    std::string many = text.substr(0U, text.find("\n---\n") + 5U);
    for (std::size_t index = 0U; index <= maximum_manifest_entries; ++index) many += std::string(64U, 'a') + " 1 /f" + std::to_string(index) + "\n";
    bad(many, "more files than the limit");
    bad(text + std::string(maximum_manifest_bytes, 'x'), "a manifest over the size limit");
}

void test_a_verified_install_is_quiet_and_healthy() {
    install fx{"quiet"};
    integrity_monitor monitor{fx.options()};
    const auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "a matching install reports nothing");
    require(monitor.refresh(t + 60).empty(), "and nothing again");
    const auto health = monitor.health();
    require(health.state == "active" && health.reason.find("2 file(s) match build manifest version 0.1.0") != std::string::npos, "healthy: " + health.reason);
    const auto watched = monitor.watched_paths();
    require(watched.count(fx.sensord.string()) == 1U && watched.count(fx.helper.string()) == 1U && watched.count(fx.manifest.string()) == 1U, "watched paths");
}

void test_a_changed_file_is_reported_after_two_looks_and_restored_when_fixed() {
    install fx{"modified"};
    integrity_monitor monitor{fx.options()};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    const auto original = slurp(fx.helper);
    put(fx.helper, "helper v2 (tampered) " + std::string(1024U, 'x'), 0700);
    require(monitor.refresh(t += 60).empty(), "a first look at a changed file is not yet reported (an upgrade replaces files before it restarts the sensor)");
    auto changes = monitor.refresh(t += 60);
    const auto* modified = find(changes, "binary_modified", "violated");
    require(modified != nullptr && changes.size() == 1U, "the second look reports it: " + describe(changes));
    require(modified->finding.target == fx.helper.string() && modified->finding.expected_sha256 == sha256_hex(original) &&
                modified->finding.observed_sha256 == sha256_hex(slurp(fx.helper)),
            "target and both hashes");
    require(modified->files_checked == 2U && modified->files_in_violation == 1U && modified->manifest_version == "0.1.0" && modified->key_id.size() == 16U, "counts and identity");
    require(monitor.health().state == "degraded" && monitor.health().reason.find("binary_modified") != std::string::npos, "degraded while in violation");
    require(monitor.refresh(t += 60).empty(), "a finding is reported once, not at every look");
    put(fx.helper, original, 0700);
    changes = monitor.refresh(t += 60);
    require(find(changes, "binary_modified", "restored") != nullptr && changes.size() == 1U && changes[0].files_in_violation == 0U, "put back: restored at once: " + describe(changes));
    require(monitor.health().state == "active", "healthy again");
}

void test_a_change_that_goes_away_before_the_second_look_is_never_reported() {
    install fx{"transient"};
    integrity_monitor monitor{fx.options()};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    const auto original = slurp(fx.helper);
    put(fx.helper, "something else entirely", 0700);
    require(monitor.refresh(t += 60).empty(), "seen once");
    put(fx.helper, original, 0700);
    require(monitor.refresh(t += 60).empty(), "gone at the second look: nothing was ever reported");
    require(monitor.refresh(t += 60).empty(), "and nothing is owed afterwards");
}

void test_a_same_size_edit_with_restored_timestamps_is_found() {
    install fx{"timestamps"};
    integrity_options options = fx.options();
    options.full_check_seconds = 3600U;
    integrity_monitor monitor{options};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    struct stat before {};
    require(::stat(fx.helper.c_str(), &before) == 0, "stat");
    // Past the kernel's timestamp tick (a few milliseconds), so the edit's ctime is not the creation's. The racy case, an
    // edit inside the tick of the last change, is the next test.
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    auto content = slurp(fx.helper);
    content[3] = content[3] == 'X' ? 'Y' : 'X';
    put(fx.helper, content, 0700);
    const timespec times[2] = {before.st_atim, before.st_mtim};
    require(::utimensat(AT_FDCWD, fx.helper.c_str(), times, 0) == 0, "restore mtime");
    require(monitor.refresh(t += 60).empty(), "first look");
    require(find(monitor.refresh(t += 60), "binary_modified", "violated") != nullptr, "same size and mtime, but the change time moved: the file is hashed again and found");
}

// The edit lands in the same timestamp tick as the file's last change, after the file was hashed, and the mtime is put
// back: size, mtime and ctime are all what the cache holds. A file written within the last two seconds is not trusted
// from the cache, so it is hashed again and found. (Real clock: the synthetic ones of the other tests would call the
// file settled.)
void test_an_edit_in_the_tick_of_the_last_change_is_found() {
    install fx{"racy-hash"};
    integrity_monitor monitor{fx.options()};
    require(monitor.refresh(now_s()).empty(), "start clean");
    struct stat before {};
    require(::stat(fx.helper.c_str(), &before) == 0, "stat");
    auto content = slurp(fx.helper);
    content[3] = content[3] == 'X' ? 'Y' : 'X';
    put(fx.helper, content, 0700);
    const timespec times[2] = {before.st_atim, before.st_mtim};
    require(::utimensat(AT_FDCWD, fx.helper.c_str(), times, 0) == 0, "restore mtime");
    require(monitor.refresh(now_s()).empty(), "first look");
    require(find(monitor.refresh(now_s()), "binary_modified", "violated") != nullptr, "found although size and mtime are as cached");
}

void test_missing_and_symlinked_files() {
    install fx{"missing"};
    integrity_monitor monitor{fx.options()};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    const auto original = slurp(fx.helper);
    fs::remove(fx.helper);
    require(monitor.refresh(t += 60).empty(), "first look");
    auto changes = monitor.refresh(t += 60);
    require(find(changes, "binary_missing", "violated") != nullptr && changes[0].finding.expected_sha256 == sha256_hex(original), "a listed file that is gone: " + describe(changes));
    // A symbolic link in its place is not the installed file, whatever it points at.
    put(fx.dir / "elsewhere", original, 0700);
    fs::create_symlink(fx.dir / "elsewhere", fx.helper);
    changes = monitor.refresh(t += 60);
    require(find(changes, "binary_missing", "restored") != nullptr, "no longer missing: " + describe(changes));
    require(find(changes, "binary_modified", "violated") == nullptr, "a changed finding is seen once first");
    changes = monitor.refresh(t += 60);
    const auto* linked = find(changes, "binary_modified", "violated");
    require(linked != nullptr && linked->finding.detail.find("symbolic link") != std::string::npos, "a symlink is refused: " + describe(changes));
}

void test_the_running_image_is_what_counts() {
    install fx{"running"};
    integrity_options options = fx.options();
    options.full_check_seconds = 60U;
    integrity_monitor monitor{options};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");

    // Another copy of the same build put in the place of the running binary: the image running is still right, but the
    // file at its path is not the one that was started.
    const auto original = slurp(fx.sensord);
    require(::link(fx.sensord.c_str(), (fx.dir / "saved").c_str()) == 0, "keep the original inode");
    put(fx.dir / "replacement", original, 0700);
    fs::rename(fx.dir / "replacement", fx.sensord);
    require(monitor.refresh(t += 60).empty(), "first look");
    auto changes = monitor.refresh(t += 60);
    require(find(changes, "binary_replaced", "violated") != nullptr && changes.size() == 1U, "replaced on disk: " + describe(changes));
    fs::rename(fx.dir / "saved", fx.sensord);
    changes = monitor.refresh(t += 60);
    require(find(changes, "binary_replaced", "restored") != nullptr, "the original back in place: " + describe(changes));
    require(monitor.refresh(t += 60).empty(), "quiet again");

    // The image that is running is edited in place. The descriptor the monitor holds sees the new content.
    {
        const int fd = ::open(fx.sensord.c_str(), O_WRONLY);
        require(fd >= 0, "open for write");
        require(::pwrite(fd, "EVIL", 4, 0) == 4, "overwrite");
        ::close(fd);
    }
    require(monitor.refresh(t += 60).empty(), "first look");
    changes = monitor.refresh(t += 60);
    bool running = false;
    bool on_disk = false;
    for (const auto& change : changes) {
        if (change.status != "violated" || change.finding.technique != "binary_modified") continue;
        if (change.finding.detail.find("running image") != std::string::npos) running = true;
        else on_disk = true;
    }
    require(running && on_disk, "the running image and the file are both reported: " + describe(changes));
    require(monitor.health().state == "degraded", "degraded: " + monitor.health().reason);
}

void test_a_running_binary_the_manifest_does_not_list_is_reported_at_start() {
    install fx{"unlisted"};
    fx.sign({fx.helper});
    integrity_monitor monitor{fx.options()};
    const auto changes = monitor.refresh(now_s() + 10);
    const auto* found = find(changes, "binary_modified", "violated");
    require(found != nullptr && found->finding.detail.find("not listed") != std::string::npos,
            "the first look after a start reports at once, without waiting for a second: " + describe(changes));
}

void test_a_manifest_that_does_not_verify() {
    {
        install fx{"badsig"};
        auto text = slurp(fx.manifest);
        const auto at = text.find(" " + fx.helper.string());
        require(at != std::string::npos && at >= 2U, "setup");
        text[at - 1U] = text[at - 1U] == '7' ? '8' : '7';  // the size of a listed file: the body no longer matches the signature
        put(fx.manifest, text);
        integrity_monitor monitor{fx.options()};
        const auto changes = monitor.refresh(now_s() + 10);
        const auto* bad = find(changes, "manifest_invalid", "violated");
        require(bad != nullptr && bad->finding.detail.find("bad_signature") != std::string::npos, "an edited manifest: " + describe(changes));
    }
    {
        install fx{"unknownkey"};
        const auto other = policy_test_support::make_key();
        put(fx.manifest, manifest_for(other, {fx.sensord, fx.helper}));
        integrity_monitor monitor{fx.options()};
        const auto changes = monitor.refresh(now_s() + 10);
        const auto* bad = find(changes, "manifest_invalid", "violated");
        require(bad != nullptr && bad->finding.detail.find("unknown_key") != std::string::npos, "signed by a key this endpoint does not pin: " + describe(changes));
        require(monitor.health().state == "degraded", "degraded");
    }
    {
        install fx{"garbage"};
        put(fx.manifest, "this is not a manifest\n");
        integrity_monitor monitor{fx.options()};
        require(find(monitor.refresh(now_s() + 10), "manifest_invalid", "violated") != nullptr, "garbage");
    }
    {
        install fx{"nomanifest"};
        fs::remove(fx.manifest);
        integrity_monitor monitor{fx.options()};
        const auto changes = monitor.refresh(now_s() + 10);
        require(find(changes, "manifest_missing", "violated") != nullptr, "a missing manifest: " + describe(changes));
    }
    {
        install fx{"writable"};
        ::chmod(fx.manifest.c_str(), 0666);
        integrity_monitor monitor{fx.options()};
        const auto changes = monitor.refresh(now_s() + 10);
        const auto* bad = find(changes, "manifest_invalid", "violated");
        require(bad != nullptr && bad->finding.detail.find("untrusted_file") != std::string::npos, "a world-writable manifest is not trusted: " + describe(changes));
    }
    {
        install fx{"revoked"};
        put(fx.keys, "# every key revoked\n");
        integrity_monitor monitor{fx.options()};
        const auto changes = monitor.refresh(now_s() + 10);
        const auto* bad = find(changes, "manifest_invalid", "violated");
        require(bad != nullptr && bad->finding.detail.find("unknown_key") != std::string::npos, "an emptied key file revokes the signing key: " + describe(changes));
    }
    {
        install fx{"nokeys"};
        fs::remove(fx.keys);
        integrity_monitor monitor{fx.options()};
        const auto changes = monitor.refresh(now_s() + 10);
        const auto* bad = find(changes, "manifest_invalid", "violated");
        require(bad != nullptr && bad->finding.detail.find("no_keys") != std::string::npos, "no key file: " + describe(changes));
    }
}

void test_a_verified_manifest_stays_in_force_when_it_is_replaced_by_garbage() {
    install fx{"stays"};
    integrity_monitor monitor{fx.options()};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    const auto good = slurp(fx.manifest);
    put(fx.manifest, "garbage\n");
    // The attacker also swaps a file: the files are still checked against the last manifest that verified.
    put(fx.helper, "payload", 0700);
    require(monitor.refresh(t += 60).empty(), "first look");
    auto changes = monitor.refresh(t += 60);
    require(find(changes, "manifest_invalid", "violated") != nullptr && find(changes, "binary_modified", "violated") != nullptr, "both are reported: " + describe(changes));
    put(fx.manifest, good);
    put(fx.helper, "helper v1 " + std::string(1024U, 'h'), 0700);
    changes = monitor.refresh(t += 60);
    require(find(changes, "manifest_invalid", "restored") != nullptr && find(changes, "binary_modified", "restored") != nullptr, "both put right: " + describe(changes));
}

void test_a_new_signed_manifest_is_adopted() {
    install fx{"upgrade"};
    integrity_monitor monitor{fx.options()};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    // An upgrade: a new helper and a new manifest that lists it, put in place together.
    put(fx.helper, "helper v2 " + std::string(2000U, 'z'), 0700);
    // A longer version string: the file's size differs, so its identity changes whatever the timestamp granularity.
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.10.0"));
    require(monitor.refresh(t += 60).empty(), "a consistent new install: nothing to report");
    require(monitor.health().reason.find("version 0.10.0") != std::string::npos, "the new manifest is in force: " + monitor.health().reason);
}

// Same size, same timestamp tick, and the check runs at the real time: a manifest written in the last two seconds is
// read again, so the rewrite is not missed (the synthetic clocks of the other tests switch this guard off).
void test_a_same_size_manifest_rewrite_in_the_same_tick_is_seen() {
    install fx{"racy"};
    integrity_monitor monitor{fx.options()};
    require(monitor.refresh(now_s()).empty(), "start clean");
    put(fx.helper, "helper v2 " + std::string(2000U, 'z'), 0700);
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.2.0"));
    require(monitor.refresh(now_s()).empty(), "a consistent new install: nothing to report");
    require(monitor.health().reason.find("version 0.2.0") != std::string::npos, "the rewrite was seen: " + monitor.health().reason);
}

// ADR 036: a manifest that verifies but was built before the newest one this endpoint has run is a rollback.
void test_an_older_signed_build_is_reported_as_a_rollback() {
    install fx{"rollback"};
    const std::int64_t base = now_s() - 100000;
    // The first manifest seen is the starting point (trust on first use), and it is remembered durably.
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.2.0", base + 2000));
    {
        integrity_monitor monitor{fx.options()};
        require(monitor.refresh(now_s() + 10).empty(), "the first build is the starting point");
        require(fs::exists(fx.state()), "and is written down");
    }
    // A newer build moves the mark forward; nothing to report.
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.3.0", base + 4000));
    {
        integrity_monitor monitor{fx.options()};
        require(monitor.refresh(now_s() + 20).empty(), "a newer build is an upgrade");
    }
    // An older signed build, in place while the sensor was stopped: reported at once on the first look.
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.2.5", base + 3000));
    {
        integrity_monitor monitor{fx.options()};
        const auto first = monitor.refresh(now_s() + 30);
        const auto* rollback = find(first, "manifest_rollback", "violated");
        require(rollback != nullptr, "an older build is reported: " + describe(first));
        require(rollback->finding.detail.find("0.2.5") != std::string::npos && rollback->finding.detail.find("0.3.0") != std::string::npos &&
                    rollback->finding.detail.find(fx.state().string()) != std::string::npos,
                "the record names both builds and how to accept it: " + rollback->finding.detail);
        require(rollback->manifest_version == "0.2.5", "the manifest in force is the older one");
        require(monitor.health().state == "degraded" && monitor.health().reason.find("manifest_rollback") != std::string::npos, "health is degraded");
        require(monitor.refresh(now_s() + 40).empty(), "reported once while it lasts");
        // Rolling forward again clears it.
        // A longer version string: the size differs, so the rewrite is noticed whatever the timestamp granularity.
        put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.3.10", base + 5000));
        const auto after = monitor.refresh(now_s() + 50);
        require(find(after, "manifest_rollback", "restored") != nullptr, "a newer build clears it: " + describe(after));
        require(monitor.health().state == "active", "and health recovers");
    }
    // The mark moved with the newer build, so the older one is still a rollback after a restart.
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.3.0", base + 4000));
    {
        integrity_monitor monitor{fx.options()};
        require(find(monitor.refresh(now_s() + 60), "manifest_rollback", "violated") != nullptr, "the mark survives a restart");
    }
    // Deleting the state file accepts an older build on purpose.
    fs::remove(fx.state());
    {
        integrity_monitor monitor{fx.options()};
        require(monitor.refresh(now_s() + 70).empty(), "with the mark gone the manifest in place is the starting point");
    }
}

void test_a_rollback_is_also_reported_while_the_sensor_runs_after_two_looks() {
    install fx{"rollback-live"};
    const std::int64_t base = now_s() - 100000;
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.5.0", base + 5000));
    integrity_monitor monitor{fx.options()};
    auto t = now_s() + 10;
    require(monitor.refresh(t).empty(), "start clean");
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.4.0-rc1", base + 1000));
    require(monitor.refresh(t += 60).empty(), "seen once: not yet reported");
    const auto second = monitor.refresh(t += 60);
    require(find(second, "manifest_rollback", "violated") != nullptr, "seen twice: reported: " + describe(second));
}

void test_an_unusable_state_file_is_a_fresh_start_and_an_unsigned_older_manifest_is_not_a_rollback() {
    install fx{"rollback-state"};
    put(fx.state(), "garbage\n");
    put(fx.manifest, manifest_for(fx.key, {fx.sensord, fx.helper}, "0.1.0", now_s() - 5000));
    {
        integrity_monitor monitor{fx.options()};
        require(monitor.refresh(now_s() + 10).empty(), "a corrupt state file is replaced, not trusted");
    }
    {
        integrity_monitor monitor{fx.options()};
        const auto stranger = policy_test_support::make_key();
        put(fx.manifest, manifest_for(stranger, {fx.sensord, fx.helper}, "0.0.9", now_s() - 9000));
        const auto changes = monitor.refresh(now_s() + 20);
        require(find(changes, "manifest_invalid", "violated") != nullptr && find(changes, "manifest_rollback", "violated") == nullptr,
                "an unverified manifest is invalid, never a rollback: " + describe(changes));
    }
}

}  // namespace

int main() {
    struct named {
        const char* name;
        void (*run)();
    };
    const named tests[]{
        {"manifest_parses_and_is_strict", test_manifest_parses_and_is_strict},
        {"verified_install_is_quiet_and_healthy", test_a_verified_install_is_quiet_and_healthy},
        {"changed_file_reported_after_two_looks_and_restored", test_a_changed_file_is_reported_after_two_looks_and_restored_when_fixed},
        {"transient_change_is_never_reported", test_a_change_that_goes_away_before_the_second_look_is_never_reported},
        {"same_size_edit_with_restored_timestamps", test_a_same_size_edit_with_restored_timestamps_is_found},
        {"edit_in_the_tick_of_the_last_change", test_an_edit_in_the_tick_of_the_last_change_is_found},
        {"missing_and_symlinked_files", test_missing_and_symlinked_files},
        {"running_image_is_what_counts", test_the_running_image_is_what_counts},
        {"unlisted_running_binary_reported_at_start", test_a_running_binary_the_manifest_does_not_list_is_reported_at_start},
        {"manifest_that_does_not_verify", test_a_manifest_that_does_not_verify},
        {"verified_manifest_stays_in_force", test_a_verified_manifest_stays_in_force_when_it_is_replaced_by_garbage},
        {"new_signed_manifest_is_adopted", test_a_new_signed_manifest_is_adopted},
        {"same_size_manifest_rewrite_in_the_same_tick_is_seen", test_a_same_size_manifest_rewrite_in_the_same_tick_is_seen},
        {"older_signed_build_is_a_rollback", test_an_older_signed_build_is_reported_as_a_rollback},
        {"rollback_while_running_needs_two_looks", test_a_rollback_is_also_reported_while_the_sensor_runs_after_two_looks},
        {"unusable_state_is_a_fresh_start", test_an_unusable_state_file_is_a_fresh_start_and_an_unsigned_older_manifest_is_not_a_rollback},
    };
    ::umask(022);
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
