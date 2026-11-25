#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

passed=0; failed=0

# 1) Known-answer oracle over the libraries (RTSP request/Range/Scale parsing, Base64, SDP, MIKEY).
oracle="$SRC/mayhem/build-normal/live555_oracle"
if [ ! -x "$oracle" ]; then echo "missing $oracle (build.sh should have built it)" >&2; emit_ctrf live555-oracle 0 1; exit 1; fi
out=$("$oracle" 2>&1); rc=$?
echo "$out"
p=$(grep -c '^PASS ' <<<"$out"); f=$(grep -c '^FAIL ' <<<"$out")
expected=15
if [ "$rc" -ne 0 ] || [ "$p" -ne "$expected" ]; then
  # A missing check (crash, early exit, no output) counts as a failure.
  missing=$(( expected - p - f )); [ "$missing" -gt 0 ] || missing=0
  f=$(( f + missing )); [ "$f" -gt 0 ] || f=1
fi
passed=$(( passed + p )); failed=$(( failed + f ))

# 2) Upstream's own unit suites (test/test_*.cpp, built by build.sh). Each prints its verdict and
#    exits non-zero on any failed check; a suite that prints nothing did not run.
shopt -s nullglob
suites=0
for src in "$SRC"/test/test_*.cpp; do
  t="${src%.cpp}"; suites=$((suites + 1))
  if [ ! -x "$t" ]; then echo "missing $t" >&2; failed=$((failed + 1)); continue; fi
  o=$("$t" 2>&1); r=$?
  if [ "$r" -eq 0 ] && [ -n "$o" ]; then passed=$((passed + 1)); echo "PASS $(basename "$t")"
  else failed=$((failed + 1)); echo "FAIL $(basename "$t") (rc=$r)"; echo "$o" | tail -5; fi
done
[ "$suites" -gt 0 ] || { echo "no upstream unit suites found" >&2; failed=$((failed + 1)); }

emit_ctrf live555-oracle+unit "$passed" "$failed" 0
