# Build

Validated toolchain (the only one the project claims): **Ubuntu 22.04 x86_64, GCC 11.4, CMake 3.22.1, Clang 14,
kernel 5.15**. Other toolchains may work and are not tested; GitHub Actions builds on Ubuntu 24.04 / kernel 6.x,
where the eBPF network objects are known to fail the verifier (that step is non-blocking), so a green CI run is
not evidence about the validation platform.

```bash
sudo apt-get install -y build-essential cmake ninja-build pkg-config git clang llvm lld \
  libelf-dev zlib1g-dev libzstd-dev libcurl4-openssl-dev libssl-dev libmnl-dev libnftnl-dev \
  libsystemd-dev libcap-dev libseccomp-dev libpam0g-dev libaudit-dev python3-jsonschema \
  bpftrace linux-tools-$(uname -r) dpkg-dev fakeroot
git submodule update --init                       # third_party/libbpf
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure -j1    # 21 targets; several need root and a real kernel
```

Options:

| Option | Purpose |
| --- | --- |
| `-DCMAKE_BUILD_TYPE=Release` | The configuration the performance and soak numbers refer to |
| `-DPANOPTICON_ENABLE_ASAN=ON`, `-DPANOPTICON_ENABLE_UBSAN=ON` | Sanitizer builds (use `MEMCAP_MB=512` for chaos runs; ASan needs a larger envelope than Release) |
| `-DPANOPTICON_ENABLE_TSAN=ON` | ThreadSanitizer (mutually exclusive with ASan) |
| `-DPANOPTICON_ENABLE_FUZZ=ON` | libFuzzer harnesses (clang only) |
| `-DPANOPTICON_LAB_UNSIGNED_COMMANDS=ON` | Lab only: allows `response_allow_unsigned=true`. Default OFF; `packaging/build_signed_deb.sh` refuses such a binary (ADR 034) |

Keep a separate build directory per configuration (`build`, `build-asan`, `build-tsan`, `build-fuzz`, `build-rel`);
`/build-*/` is git-ignored. The eBPF objects are compiled by clang and embedded in the binary; `bpf/vmlinux.h` is a
vendored x86_64 5.15 BTF header, so the BPF build is not portable to other architectures.

Packaging (`.deb`, signed apt repository): see [docs/endpoint/LINUX_ENDPOINT_CONFIGURATION.md](docs/endpoint/LINUX_ENDPOINT_CONFIGURATION.md)
and the headers of `packaging/build_signed_deb.sh` and `packaging/build_apt_repo.sh`. **The package path is
implemented; its end-to-end validation (`tests/e2e/run_package_e2e.sh`) is pending.**

## Foundation notes (original text)

The portable core requires CMake 3.20+, Ninja, and a C++20 compiler. It has been built on the
development host with GCC 15.2; this does not validate Linux-only adapters.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Linux sanitizer builds use Clang:

```bash
cmake -S . -B build-sanitized -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DPANOPTICON_ENABLE_ASAN=ON -DPANOPTICON_ENABLE_UBSAN=ON
cmake --build build-sanitized --parallel
ctest --test-dir build-sanitized --output-on-failure
```

The development Windows GCC lacks sanitizer runtimes, so sanitizer execution is a Linux CI
requirement. Do not interpret a portable build as verification of procfs, systemd, permissions,
or network behavior.
