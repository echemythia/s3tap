#!/usr/bin/env bash
# bpf-verify.sh — compile the s3tap eBPF object and LOAD it, so the kernel
# VERIFIER runs on every program. This is the check `cargo test` cannot do: the
# verifier only executes at load time. Kernel-agnostic — run it on the host, in
# a vmtest/virtme VM (the kernel matrix), or on a CI runner.
#
# Exit 0  => every program passed the verifier and every map was created on THIS
#            kernel (uname -r is printed).
# Exit 1  => a program was rejected (the verifier log is shown) or a tool is missing.
#
#   Env:  S3TAP_FORCE_REBUILD=1   recompile even if target/s3tap.bpf.o exists
#         S3TAP_RUN_TESTS=1       also run `cargo test --workspace` under this kernel
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # scripts/kernel-compat -> repo root

KREL="$(uname -r)"
OBJ="target/s3tap.bpf.o"
PIN="/sys/fs/bpf/s3tap-verify-$$"
# vmtest/virtme run the guest command as root (no sudo); on the host we elevate.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; O=$'\e[0m'; else G= R= B= O=; fi
ok()  { printf '  %sPASS%s %s\n' "$G" "$O" "$1"; }
bad() { printf '  %sFAIL%s %s\n' "$R" "$O" "$1"; }
have(){ command -v "$1" >/dev/null; }

printf '%s== bpf-verify on kernel %s ==%s\n' "$B" "$KREL" "$O"

# --- resolve bpftool ---------------------------------------------------------
# Ubuntu/Pop often ship bpftool only as a version-suffixed binary under
# /usr/lib/linux-tools/<kver>/ with no PATH symlink (and the installed <kver> may
# differ from the running kernel — that's fine, bpftool loads objects via syscalls
# regardless). Fall back to the newest one we can find.
BPFTOOL="$(command -v bpftool || true)"
# The PATH entry may be the linux-tools-common wrapper, which dispatches only to a
# binary matching the *running* kernel and exits non-zero when that per-version
# package isn't installed (common on cloud kernels). If it doesn't actually run,
# fall back to the newest real versioned binary.
if [ -z "$BPFTOOL" ] || ! "$BPFTOOL" version >/dev/null 2>&1; then
  BPFTOOL="$(ls -1 /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1 || true)"
fi

# --- preflight ---------------------------------------------------------------
fail=0
[ -r /sys/kernel/btf/vmlinux ] || { bad "no /sys/kernel/btf/vmlinux (kernel needs CONFIG_DEBUG_INFO_BTF=y)"; fail=1; }
have clang            || { bad "clang not found"; fail=1; }
[ -n "$BPFTOOL" ]     || { bad "bpftool not found (install linux-tools-common + linux-tools-generic, or the bpftool package)"; fail=1; }
[ "$fail" = 0 ] || { echo "preflight failed"; exit 1; }
echo "using bpftool: $BPFTOOL"

# --- arch → libbpf __TARGET_ARCH_* -------------------------------------------
case "$(uname -m)" in
  x86_64)  TARCH=x86 ;;
  aarch64) TARCH=arm64 ;;
  *)       TARCH="$(uname -m)" ;;
esac

# --- vmlinux.h: reuse the committed/generated one; else dump THIS kernel's BTF -
# One comprehensive header is enough — the object is CO-RE, so it relocates
# against each kernel's own BTF at load. Only generate if absent.
if [ ! -f bpf/vmlinux/vmlinux.h ]; then
  echo "generating bpf/vmlinux/vmlinux.h from the running kernel's BTF"
  mkdir -p bpf/vmlinux
  $SUDO "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux/vmlinux.h \
    || { bad "could not dump vmlinux BTF"; exit 1; }
fi

# --- compile (only if missing, or forced) — same flags as the justfile `bpf` --
if [ ! -f "$OBJ" ] || [ "${S3TAP_FORCE_REBUILD:-0}" = 1 ]; then
  echo "compiling $OBJ (clang -target bpf, arch=$TARCH)"
  mkdir -p target
  if ! clang -O2 -g -Werror -target bpf "-D__TARGET_ARCH_${TARCH}" \
        -I bpf/include -I bpf/vmlinux \
        -c bpf/src/s3tap.bpf.c -o "$OBJ"; then
    bad "clang failed to compile the eBPF object"; exit 1
  fi
  ok "compiled $OBJ"
else
  echo "using existing $OBJ (set S3TAP_FORCE_REBUILD=1 to rebuild)"
fi

# --- THE verifier gate: load every program (+ create every map) --------------
# `loadall` runs the verifier on each SEC() program as it loads; a rejection
# makes it exit non-zero and print the verifier log. Attaching is not needed to
# exercise the verifier, so we don't autoattach (avoids attach-type quirks).
# Elevation is separate from verification: a sudo failure is NOT a rejection.
if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
  echo "  (bpftool load needs root; sudo will prompt for your password)"
fi

# The pin path must live on a mounted bpffs. /sys/fs/bpf is mounted on the host
# and most guests, but minimal VM guests (some virtme-ng/vmtest kernels) don't
# mount it — the pin would then fail on a missing dir and look exactly like a
# verifier rejection (a spurious matrix FAIL). When we're root and /sys/fs/bpf
# isn't a bpffs, mount a private one in a temp dir and pin there instead.
BPFFS_MNT=""
cleanup_bpffs(){ [ -n "$BPFFS_MNT" ] && { $SUDO umount "$BPFFS_MNT" 2>/dev/null; rmdir "$BPFFS_MNT" 2>/dev/null; }; }
trap cleanup_bpffs EXIT
if ! mount 2>/dev/null | grep -qE ' /sys/fs/bpf .*type bpf '; then
  if [ "$(id -u)" -eq 0 ]; then
    BPFFS_MNT="$(mktemp -d)"
    if mount -t bpf bpf "$BPFFS_MNT" 2>/dev/null; then
      PIN="$BPFFS_MNT/s3tap-verify-$$"
      echo "  (/sys/fs/bpf not mounted here — pinning to a private bpffs at $BPFFS_MNT)"
    else
      rmdir "$BPFFS_MNT" 2>/dev/null; BPFFS_MNT=""
    fi
  fi
fi

err="$(mktemp)"
lserr="$(mktemp)"
if $SUDO "$BPFTOOL" prog loadall "$OBJ" "$PIN" 2>"$err"; then
  # The pin directory is the ONLY evidence that programs were actually CREATED, so it
  # has to be read with the same privilege that created it: bpffs is root-owned mode
  # 700, so an unprivileged `ls` here returns EACCES, and swallowing that with
  # 2>/dev/null reported a confident "0 object(s) loaded" next to a PASS (measured: 22
  # objects via sudo, 0 without). Count through $SUDO, and treat zero as a FAILURE —
  # "loadall exited 0 but pinned nothing" proves nothing about the verifier, which is
  # the one thing this gate exists to prove.
  n="$($SUDO ls -1 "$PIN" 2>"$lserr" | wc -l)"
  if [ "${n:-0}" -le 0 ]; then
    bad "bpftool exited 0 but pinned NOTHING under $PIN on kernel $KREL — no program was created, so this is not a verifier pass:"
    sed 's/^/      /' "$lserr" | tail -5
    $SUDO rm -rf "$PIN" 2>/dev/null
    rm -f "$err" "$lserr"; exit 1
  fi
  ok "verifier ACCEPTED the program — ${n} object(s) loaded on kernel $KREL"
  $SUDO rm -rf "$PIN" 2>/dev/null
elif grep -qiE 'sudo:.*(password|terminal|askpass)' "$err"; then
  bad "could not elevate — this step needs sudo. Run it in an interactive terminal (it prompts once), or enable passwordless sudo for bpftool. (This is NOT a verifier result.)"
  rm -f "$err" "$lserr"; exit 2
else
  bad "verifier REJECTED the program on kernel $KREL — log:"
  sed 's/^/      /' "$err" | tail -40
  $SUDO rm -rf "$PIN" 2>/dev/null; rm -f "$err" "$lserr"
  exit 1
fi
rm -f "$err" "$lserr"

# --- optional: unit tests under this kernel ----------------------------------
if [ "${S3TAP_RUN_TESTS:-0}" = 1 ]; then
  echo "running cargo test --workspace under kernel $KREL"
  if cargo test --workspace --quiet; then ok "cargo test passed"; else bad "cargo test failed"; exit 1; fi
fi

printf '%s== bpf-verify PASSED on %s ==%s\n' "$G" "$KREL" "$O"
