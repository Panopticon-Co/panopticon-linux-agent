#!/usr/bin/env bash
# Replays every fuzz corpus through a source-coverage build and reports, per parser file, how much of it the
# corpora reach. This is the evidence of what fuzzing exercised; exec counts alone say nothing about depth.
#
# usage: tests/fuzz/coverage_report.sh [target ...]
# Needs a build made with (no sanitizers, so it is fast and the counts are not perturbed):
#   cmake -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DPANOPTICON_ENABLE_FUZZ=ON -DBUILD_TESTING=OFF \
#         -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" -B build-fuzzcov
# Environment: BUILD (default build-fuzzcov), CORPUS (default /var/tmp/panopticon-fuzz/corpus),
#              LLVM_SUFFIX (default -14: llvm-profdata-14, llvm-cov-14).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=${BUILD:-$ROOT/build-fuzzcov}
CORPUS=${CORPUS:-/var/tmp/panopticon-fuzz/corpus}
SUFFIX=${LLVM_SUFFIX:--14}
TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(json commands config policy auth_line audit dns fanotify sockdiag proc_event ebpf_sample procfs cgroup hostfiles fim wal)
OUT=$(mktemp -d /tmp/panopticon-fuzzcov.XXXXXX)
objects=()
for t in "${TARGETS[@]}"; do
  bin=$BUILD/fuzz-$t
  [ -x "$bin" ] || { echo "missing $bin" >&2; exit 2; }
  [ -d "$CORPUS/$t" ] || { echo "no corpus for $t" >&2; continue; }
  # -runs=0 executes each corpus input once and stops.
  LLVM_PROFILE_FILE="$OUT/$t.profraw" "$bin" -runs=0 "$CORPUS/$t" >"$OUT/$t.log" 2>&1
  [ ${#objects[@]} -eq 0 ] && objects=("$bin") || objects+=(-object "$bin")
done
"llvm-profdata$SUFFIX" merge -sparse "$OUT"/*.profraw -o "$OUT/merged.profdata" || exit 2
# The files whose input an attacker can influence; the report is restricted to them.
files=(src/command.cpp src/sensor/json_reader.cpp src/sensor/command_auth.cpp src/sensor/command_channel.cpp
       src/sensor/audit_netlink.cpp src/sensor/auth_log.cpp src/sensor/dns_message.cpp src/sensor/fanotify_file.cpp
       src/sensor/sockdiag_network.cpp src/sensor/netlink_proc.cpp src/sensor/ebpf_process.cpp src/sensor/process_info.cpp
       src/sensor/container_identity.cpp src/sensor/host_state.cpp src/sensor/fim.cpp src/sensor/wal.cpp
       src/sensor/policy.cpp src/sensor/pipeline.cpp)
paths=()
for f in "${files[@]}"; do [ -f "$ROOT/$f" ] && paths+=("$ROOT/$f"); done
"llvm-cov$SUFFIX" report "${objects[@]}" -instr-profile="$OUT/merged.profdata" "${paths[@]}" | sed "s#$ROOT/##"
echo "(profiles in $OUT)"
