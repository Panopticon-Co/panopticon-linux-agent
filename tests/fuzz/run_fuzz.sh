#!/usr/bin/env bash
# Runs every libFuzzer harness for a fixed time and reports crashes, hangs, leaks and the coverage reached.
#
# usage: tests/fuzz/run_fuzz.sh [seconds-per-target] [target ...]
# Needs a build made with:  cmake -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DPANOPTICON_ENABLE_ASAN=ON \
#                             -DPANOPTICON_ENABLE_UBSAN=ON -DPANOPTICON_ENABLE_FUZZ=ON -B build-fuzz
# Environment: BUILD (default build-fuzz), CORPUS (default /var/tmp/panopticon-fuzz/corpus),
#              ARTIFACTS (default /var/tmp/panopticon-fuzz/artifacts), WAL_SEED_DIR (a directory with real
#              wal-*.log segments to seed the WAL target), PARALLEL (default 1), RSS_MB (per-fuzzer memory
#              limit, default 2048).
# Exit status: 0 when no target crashed, 1 otherwise. A crash leaves its input in ARTIFACTS; copy it into
# tests/fuzz/regressions/<target>/ with a test that fails without the fix.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=${BUILD:-$ROOT/build-fuzz}
CORPUS=${CORPUS:-/var/tmp/panopticon-fuzz/corpus}
ARTIFACTS=${ARTIFACTS:-/var/tmp/panopticon-fuzz/artifacts}
SECONDS_EACH=${1:-120}
RSS_MB=${RSS_MB:-2048}
[ $# -gt 0 ] && shift
TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(json commands config policy auth_line audit dns fanotify sockdiag proc_event ebpf_sample procfs cgroup hostfiles fim wal)
mkdir -p "$CORPUS" "$ARTIFACTS"

seed() {  # seed <target> <name> <content>: a small valid input so the fuzzer starts inside the grammar
  mkdir -p "$CORPUS/$1"; printf '%s' "$3" >"$CORPUS/$1/seed-$2"
}
seed json 1 '{"a":[1,-2,3.5e2,"xé",true,null],"b":{"c":{}}}'
seed commands 1 '{"commands":[{"command_id":"c1","action":"KILL_PROCESS","agent_id":"a","target":{"pid":1234,"start_time_ticks":99},"expires_at":"2030-01-01T00:00:00Z"}]}'
seed config 1 $'sensor_id=s1\nhost_id=abc\nwal_path=/var/lib/panopticon/wal\nresponse_mode=dry_run\nmanager_url=https://m.example/\n'
seed policy 1 $'rule tmp process.exec exe prefix recommend_terminate high /tmp\nrule h * sha256 ioc alert low\nrule d * dest_domain ioc recommend_block high\nioc sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nioc dest_domain evil.example\nallow exe /usr/bin\n'
seed policy 2 $'panopticon-policy 1\npolicy_id p1\nversion 2\nissued_at 1791000000\nexpires_at 1792000000\nscope host:abc\nkey_id 0123456789abcdef\nsignature AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n---\nrule c * cmdline contains alert low | sh\n'
seed auth_line 1 'Oct  7 10:00:01 host sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2'
seed auth_line 2 'Oct  7 10:00:02 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls'
seed cgroup 1 '0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope'
seed hostfiles 1 $'\x00NAME="Ubuntu"\nVERSION_ID="22.04"\n'
seed hostfiles 2 $'\x05Package: bash\nStatus: install ok installed\nVersion: 5.1-6\n\n'
seed hostfiles 3 $'\x01root:x:0:0:root:/root:/bin/bash\n'
seed dns 1 $'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
# procfs: this shell's own /proc entry, in the harness's 0xFF-separated layout.
mkdir -p "$CORPUS/procfs"
{ for f in stat status cmdline environ cgroup loginuid sessionid; do head -c 8192 "/proc/$$/$f" 2>/dev/null; printf '\377'; done
  printf '%s\377%s' "$(readlink "/proc/$$/exe")" "$(readlink "/proc/$$/cwd")"; } >"$CORPUS/procfs/seed-self"
if [ -n "${WAL_SEED_DIR:-}" ]; then
  mkdir -p "$CORPUS/wal"; n=0
  for f in "$WAL_SEED_DIR"/wal-*.log; do [ -f "$f" ] || continue; n=$((n+1)); head -c 65536 "$f" >"$CORPUS/wal/seed-real-$n"; [ $n -ge 4 ] && break; done
fi

run_target() {  # run_target <name>: one fuzzer for SECONDS_EACH, leaves one summary line in $ARTIFACTS/<name>/result
  local t=$1 bin=$BUILD/fuzz-$1 log rc execs cov corpus res note maxlen
  mkdir -p "$CORPUS/$t" "$ARTIFACTS/$t"
  if [ ! -x "$bin" ]; then
    printf '%-12s MISSING (build with -DPANOPTICON_ENABLE_FUZZ=ON)\n' "$t" >"$ARTIFACTS/$t/result"; return
  fi
  log=$ARTIFACTS/$t/run.log
  maxlen=65536; [ "$t" = wal ] && maxlen=131072
  ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    "$bin" "$CORPUS/$t" -max_total_time="$SECONDS_EACH" -max_len=$maxlen -timeout=10 -rss_limit_mb="$RSS_MB" \
           -artifact_prefix="$ARTIFACTS/$t/" -print_final_stats=1 >"$log" 2>&1
  rc=$?
  execs=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$log" | tail -1 | grep -o '[0-9]*$')
  cov=$(grep -o 'cov: [0-9]*' "$log" | tail -1 | grep -o '[0-9]*$')
  corpus=$(find "$CORPUS/$t" -type f | wc -l)
  if [ $rc -eq 0 ]; then res=ok; else res=CRASH; fi
  note=""
  if [ $rc -ne 0 ]; then
    note="$(grep -m1 -E 'ERROR: |SUMMARY: |runtime error' "$log" | cut -c1-140) -> $(ls "$ARTIFACTS/$t" | grep -E '^(crash|leak|timeout|oom|slow-unit)' | head -1)"
  fi
  printf '%-12s %-9s %-11s %-9s %-7s %s\n' "$t" "$res" "${execs:-?}" "${cov:-?}" "$corpus" "$note" >"$ARTIFACTS/$t/result"
}

# PARALLEL (default 1) targets run at once; each fuzzer is single-threaded. Keep PARALLEL x RSS_MB within the
# machine's memory: on a 4 GiB VM, 6 ASan fuzzers at 2 GiB each stalled the guest (soft lockups) and every
# fuzzer running then reported a spurious timeout.
PARALLEL=${PARALLEL:-1}
running=0
for t in "${TARGETS[@]}"; do
  run_target "$t" &
  running=$((running + 1))
  if [ "$running" -ge "$PARALLEL" ]; then wait -n; running=$((running - 1)); fi
done
wait

status=0
printf '%-12s %-9s %-11s %-9s %-7s %s\n' target result execs coverage corpus notes
for t in "${TARGETS[@]}"; do
  cat "$ARTIFACTS/$t/result"
  grep -q '^[^ ]* *ok ' "$ARTIFACTS/$t/result" || status=1
done
exit $status
