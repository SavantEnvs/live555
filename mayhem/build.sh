#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

LIBDIRS="UsageEnvironment groupsock BasicUsageEnvironment liveMedia"
LIBS="liveMedia/libliveMedia.a groupsock/libgroupsock.a BasicUsageEnvironment/libBasicUsageEnvironment.a UsageEnvironment/libUsageEnvironment.a"
INCS="-IUsageEnvironment/include -Igroupsock/include -IliveMedia/include -IBasicUsageEnvironment/include"
DEFS="-std=c++20 -DSOCKLEN_T=socklen_t -D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DNO_OPENSSL=1 -DBSD=1"
OUT="$SRC/mayhem/out"
NORMAL="$SRC/mayhem/build-normal"
mkdir -p "$OUT" "$NORMAL"

# Upstream's own makefile generator (writes a gitignored Makefile into each subdirectory).
./genMakefiles linux-no-openssl

# The config hard-codes cc/c++; reach the compiler by name through $CC/$CXX instead.
mk() { make -j"$MAYHEM_JOBS" C_COMPILER="$CC" CPLUSPLUS_COMPILER="$CXX" LINK="$CXX -o " "$@"; }
build_libs() {
  for d in $LIBDIRS; do make -C "$d" clean >/dev/null; done
  for d in $LIBDIRS; do mk -C "$d" "$@"; done
}

# 1) Functional-test build with the project's NORMAL flags (-O2 from the config): the libraries,
#    the known-answer oracle over them, and upstream's own unit tests (test/, header-only helpers).
build_libs CFLAGS="$COVERAGE_FLAGS" CXXFLAGS="$COVERAGE_FLAGS"
cp $LIBS "$NORMAL/"
$CXX -O1 $COVERAGE_FLAGS $DEFS $INCS mayhem/oracle/live555_oracle.cpp \
  "$NORMAL/libliveMedia.a" "$NORMAL/libgroupsock.a" "$NORMAL/libBasicUsageEnvironment.a" "$NORMAL/libUsageEnvironment.a" \
  -o "$NORMAL/live555_oracle"
make -C test CXX="$CXX" CXXFLAGS="-O0 -g -Wall $COVERAGE_FLAGS" all

# 2) Sanitized, coverage-instrumented libraries for the fuzzers.
#    UBSan relaxations (ASan and the rest of UBSan stay on and halting):
#    - "function": live555 registers every socket/task handler by casting a typed function
#      (e.g. void(ByteStreamFileSource*, int)) to its generic void(void*, int) handler type — the
#      library's core callback design, flagged on the very first event-loop dispatch of any input.
#    - "signed-integer-overflow" in groupsock/inet.c only: the bundled BSD random() seeding
#      (our_srandom) multiplies a 64-bit long state by 1103515245 and overflows on first use; it is
#      the PRNG, not input-handling code.
#    - "array-bounds" in liveMedia/RTSPServer.cpp only: resetRequestBuffer() deliberately points
#      fLastCRLF at &fRequestBuffer[-3] ("hack" per its own comment) on every new connection. ASan
#      still checks every access to the buffer.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
[ -n "$SANITIZER_FLAGS" ] && FUZZ_CFLAGS="$FUZZ_CFLAGS -fno-sanitize=function"
build_libs CFLAGS="$FUZZ_CFLAGS" CXXFLAGS="$FUZZ_CFLAGS"
if [ -n "$SANITIZER_FLAGS" ]; then
  relax() { # <dir> <object> <extra flags>: rebuild one object with a relaxed check, re-archive it
    rm -f "$1/$2"
    mk -C "$1" CFLAGS="$FUZZ_CFLAGS $3" CXXFLAGS="$FUZZ_CFLAGS $3" "$2"
    ar r "$1/$4" "$1/$2"
  }
  relax groupsock inet.o -fno-sanitize=signed-integer-overflow libgroupsock.a
  relax liveMedia RTSPServer.o -fno-sanitize=array-bounds libliveMedia.a
fi

# 3) Harnesses: a libFuzzer binary and a standalone reproducer each.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
$CXX $FUZZ_CFLAGS $DEFS $INCS -c mediaServer/DynamicRTSPServer.cpp -o "$OUT/DynamicRTSPServer.o"
for h in rtsp_server rtsp_client rtp_rtcp sdp mikey mkv ogg ts_demux mpeg1or2_demux h264or5_framer; do
  extra=""
  [ "$h" = rtsp_server ] && extra="$OUT/DynamicRTSPServer.o"
  $CXX $FUZZ_CFLAGS $DEFS $INCS -c "mayhem/harnesses/fuzz_$h.cpp" -o "$OUT/fuzz_$h.o"
  $CXX $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "$OUT/fuzz_$h.o" $extra $LIBS "$OUT/lsan_off.o" -o "$OUT/fuzz_$h"
  $CXX $FUZZ_CFLAGS "$OUT/standalone_main.o" "$OUT/fuzz_$h.o" $extra $LIBS "$OUT/lsan_off.o" -o "$OUT/fuzz_$h-standalone"
done
ls -l "$OUT"/fuzz_*
