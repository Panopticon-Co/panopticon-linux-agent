# Build

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
