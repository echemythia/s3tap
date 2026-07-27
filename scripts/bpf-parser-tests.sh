#!/usr/bin/env bash
# bpf-parser-tests.sh — unit-test the eBPF program's byte parsers on the HOST.
#
# This is the per-PR gate the kernel matrix can never be. It needs no kernel, no
# root, no VM and no KVM: bpf/include/s3tap_parse.h holds the pure parsers, and
# this compiles that header a SECOND time for the host (under -DS3TAP_HOST_TEST,
# with bpf/tests/s3tap_host_shim.h supplying the few BPF names it uses) and runs
# it against constructed byte buffers.
#
# Why it is worth a job of its own: `bpf-matrix.sh` proves the object LOADS on a
# spread of kernels, and nothing else. The verifier only walks REACHABLE code, so
# a CO-RE relocation that returns early makes everything downstream dead code it
# never examines — a PASS is then indistinguishable from "compiled out". And even
# a real PASS says nothing about whether a parser honours a length field. The
# parsers tested here read attacker-influenced bytes (DNS messages, TLS hellos,
# HTTP heads), which is exactly the code that needs the stronger claim.
#
# Over-reads are the bug class that matters here: in the kernel these parsers mask
# every offset into a per-CPU map, so a read past the bytes actually copied still
# lands INSIDE the map and silently returns the previous message's bytes. The
# tests reproduce that geometry with a GUARD PAGE exactly where the copied bytes
# end, which turns a silent over-read into an immediate fault with the offending
# offset. That detector needs no sanitizer, and the build verifies it is armed
# (--overread-selfcheck) before trusting a green run.
#
# ASan/UBSan are layered on top for what guard pages cannot see: overruns of the
# OUTPUT buffers (each malloc'd at exactly the size of the event field it models)
# and integer/shift UB. They are not the primary detector — ASan's shadow is
# 8-byte granular and misses a 2-byte read straddling the boundary, which is the
# exact shape of tls_be16.
#
# Usage:  scripts/bpf-parser-tests.sh          (or: just bpf-test)
#         CC=clang-18 scripts/bpf-parser-tests.sh
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # scripts/ -> repo root

CC="${CC:-clang}"
OUT=target/s3tap-bpf-parser-tests
command -v "$CC" >/dev/null || { echo "ABORT: $CC not found (install clang)"; exit 2; }
mkdir -p target

# -fno-sanitize-recover=all so a UBSan finding FAILS the run instead of printing
# a note and carrying on. -O1 keeps the sanitizers' reports precise while still
# exercising the optimizer on the parser bodies.
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
if ! echo 'int main(void){return 0;}' | "$CC" -x c - $SAN -o /dev/null 2>/dev/null; then
  echo "WARNING: $CC has no address/undefined sanitizer runtime here."
  echo "         Building WITHOUT it. Over-read detection (guard pages) is"
  echo "         unaffected, but output-buffer overruns and UB go unchecked."
  SAN=""
fi

echo "== building the host parser tests =="
# The same -Werror discipline the BPF build uses: this compiles the same header.
"$CC" -std=gnu11 -O1 -g -Wall -Wextra -Werror $SAN \
  -I bpf/include -I bpf/tests \
  bpf/tests/parser_tests.c -o "$OUT"

# Prove the over-read detector is live BEFORE trusting the suite. The self-check
# deliberately reads one byte past the copied data; it must die. A build where
# this returns cleanly would let every "no over-read" assertion pass vacuously,
# which is the precise failure this whole gate exists to avoid.
echo "== verifying the over-read detector is armed =="
if "$OUT" --overread-selfcheck >/dev/null 2>&1; then
  echo "ABORT: the deliberate over-read was NOT detected, so the guard page is not"
  echo "       where it should be and every bounds assertion in the suite is"
  echo "       vacuous. Refusing to report a green run."
  exit 2
fi
echo "  ok   a read straddling the end of the copied data faults as intended"

echo "== running =="
exec "$OUT"
