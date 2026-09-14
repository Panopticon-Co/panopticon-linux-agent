# Contributing to panopticon-linux-agent

Thanks for your interest in contributing. This is a capstone/research security project; response
times to issues and PRs are best-effort, not SLA-backed.

## Prerequisites

- Linux (development and CI target Ubuntu 24.04).
- CMake 3.20+ and Ninja.
- A C++20 compiler: GCC is used for the normal build; Clang is required for the sanitizer build.
- `libcurl4-openssl-dev` (or equivalent) if you want the HTTPS transport enabled.
- `libmnl-dev` and `libnftnl-dev` if you are working on `panopticon-isolation-helper` or the
  isolation e2e/spike executables -- these targets only get configured when both libraries are
  found via `pkg-config`.

There is no vcpkg/Conan manifest in this repo; dependencies are pulled from the system package
manager (see `.github/workflows/ci.yml` for the exact `apt-get` package list CI installs).

## Clone and build

```bash
git clone https://github.com/Panopticon-Co/panopticon-linux-agent.git
cd panopticon-linux-agent
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

See [BUILD.md](BUILD.md) for the sanitizer build invocation and platform caveats.

## Testing expectations

- `panopticon-linux-core-tests` (CTest) must stay green. It covers PID-reuse-safe identity,
  spool corruption/recovery, command gate/replay/expiry logic, and bounded procfs parsing -- see
  [TESTING.md](TESTING.md).
- CI also runs an ASan + UBSan build (`sanitizers` job in `.github/workflows/ci.yml`). Treat a
  sanitizer failure as a real bug, not a false positive, unless you can show otherwise.
- Shell-driven e2e suites under `tests/e2e/` exercise the isolation helper, including a
  real non-loopback, network-namespace-based packet verification test. Do not weaken or remove
  a test to make it pass -- if a scenario is genuinely flaky (see
  [TESTING.md](TESTING.md) for the one known intermittent case), document it, don't delete it.
- No test may kill a real user process, alter the CI runner's default-namespace firewall, or
  quarantine real user data.
- Do not confuse a portable (non-Linux) build with validation of procfs, systemd, permissions, or
  network behavior -- these paths are only exercised in Linux CI.

## Branch workflow

- Work on a feature branch off `main`; do not commit directly to `main`.
- Keep commits focused and single-purpose rather than large mixed changes.
- Rebase on `main` before opening a PR if your branch has drifted; avoid merge commits in feature
  branches.

## Commit style

Follow the existing history's conventional-commit-style prefixes, e.g.:

```text
feat(response): send DISPATCHED->ACCEPTED acknowledgement before executing a command
fix(isolation): reject oversized IPC frames instead of parsing a truncated prefix
docs: correct stale claims in README
ci(isolation): run packet-verification step even if the robustness step fails
test(isolation): add real non-loopback packet-level isolation verification
```

Use `feat`, `fix`, `docs`, `test`, `ci`, `build`, `refactor`, or `chore` as appropriate, with an
optional `(scope)` naming the affected subsystem.

## Pull request expectations

- Fill out the PR template (`.github/pull_request_template.md`).
- State whether the change affects the event/command wire contract shared with other Panopticon
  repos (`panopticon-contracts`, `panopticon-manager`, `panopticon-agent`,
  `panopticon-detection-engine`); if it does, explain compatibility impact -- see
  [docs/CROSS_REPO_IMPACT.md](docs/CROSS_REPO_IMPACT.md).
- Do not add a shell execution path, arbitrary executable dispatcher, or an 8th response action --
  the closed 7-action response set (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`,
  `COLLECT_NETWORK_CONNECTIONS`, `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`,
  `RELEASE_HOST_ISOLATION`) is a deliberate security boundary; see [RESPONSE.md](RESPONSE.md) and
  [SECURITY.md](SECURITY.md).
- Do not widen `panopticon-isolation-helper`'s capabilities beyond `CAP_NET_ADMIN`, and do not
  introduce a shell/`nft`-CLI call path into it -- see
  [ADR 004](docs/adr/004-host-isolation-privilege-boundary.md).
- Architectural changes (touching the event/command contract, the privilege boundary, or the
  agent/Manager integration surface) should be discussed in an issue or PR description before
  large-scale implementation.

## Reporting security issues

Do not open a public issue for a suspected vulnerability. See [SECURITY.md](SECURITY.md) for how
to report privately.
