#!/usr/bin/env bash
# bpf-matrix.sh — run the eBPF verifier gate (scripts/kernel-compat/bpf-verify.sh) across a
# MATRIX of kernel versions, so a change that loads on your dev kernel but is
# rejected on an older/newer one is caught. This is the coverage `cargo test`
# and a single-kernel CI runner cannot give a CO-RE program.
#
# Uses virtme-ng (vng), which DOWNLOADS a precompiled upstream kernel per version
# and boots it with this repo as the rootfs — building a small initramfs that
# loads the virtio/9p modules. That last part is why we use vng and not vmtest:
# every distro/mainline kernel here ships 9p/virtio as MODULES, so vmtest (which
# boots a bare kernel and mounts the host over 9p with no initramfs) panics at
# boot before the verifier ever runs. vng handles the modular case.
#
# Requires:
#   - virtme-ng (vng)   sudo apt install virtme-ng   (or pip install virtme-ng)
#   - KVM               (/dev/kvm present; be in the `kvm` group to run rootless)
#   - clang + bpftool   (bpftool may be the version-suffixed one under /usr/lib)
#
# Usage:
#   scripts/kernel-compat/bpf-matrix.sh                       # default version spread
#   VERSIONS="v6.1 v6.8 v6.12 v6.16" scripts/kernel-compat/bpf-matrix.sh
#
# vng caches each downloaded kernel under ~/.cache/virtme-ng, so re-runs are fast.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # scripts/kernel-compat -> repo root

# A spread across the range: an LTS floor, mids, and a recent kernel. vng takes
# upstream tags (v6.1, v6.12.3, …) and pulls the matching Ubuntu mainline build.
# Floor (v5.8 — the documented ringbuf minimum), an LTS mid, the two kernels whose
# verifier quirks we specifically fixed (v6.1 CO-RE, v6.8 complexity), and a recent
# one. Override with VERSIONS="v6.1 v6.12 v6.16".
VERSIONS="${VERSIONS:-v5.8 v5.15 v6.1 v6.8 v6.16}"
if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; O=$'\e[0m'; else G= R= B= O=; fi
die(){ printf '\n\033[31mABORT\033[0m %s\n' "$1"; exit 2; }

command -v vng >/dev/null || die "virtme-ng (vng) not found — install it:
  sudo apt install virtme-ng    (or: pip install virtme-ng)
  It boots each downloaded kernel + this repo and runs the gate. https://github.com/arighi/virtme-ng"
[ -e /dev/kvm ] || die "/dev/kvm missing — vng needs KVM (enable VT-x/AMD-V in BIOS)."
[ -r /dev/kvm ] && [ -w /dev/kvm ] || echo "${R}note:${O} you can't R/W /dev/kvm — add yourself to the 'kvm' group (or run under sudo), else boots are slow/fail."

# Build the CO-RE object ONCE on the host; every kernel then LOADS the same
# artifact (exactly how it ships), so the matrix tests relocation + verification,
# not re-compilation. bpf-verify.sh in the guest finds this and skips the compile.
printf '%s== building the eBPF object on the host ==%s\n' "$B" "$O"
BPFTOOL="$(command -v bpftool || ls -1 /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1)"
if [ ! -f bpf/vmlinux/vmlinux.h ]; then
  echo "generating vmlinux.h"; mkdir -p bpf/vmlinux
  [ -n "$BPFTOOL" ] || die "bpftool not found (install linux-tools-generic) — needed to dump vmlinux BTF."
  sudo "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux/vmlinux.h
fi
case "$(uname -m)" in x86_64) TA=x86 ;; aarch64) TA=arm64 ;; *) TA="$(uname -m)" ;; esac
mkdir -p target
clang -O2 -g -Werror -target bpf "-D__TARGET_ARCH_${TA}" -I bpf/include -I bpf/vmlinux \
  -c bpf/src/s3tap.bpf.c -o target/s3tap.bpf.o || die "host clang compile failed"
command -v llvm-strip >/dev/null && llvm-strip -g target/s3tap.bpf.o
echo "built target/s3tap.bpf.o"

# Run the gate in each kernel. vng boots the kernel with THIS repo as the rootfs
# and runs the command as ROOT (--user root — bpftool load needs it); the guest
# reuses the prebuilt object and just loads it (the verifier runs there, on that
# kernel). NOTE: vng does NOT propagate the guest command's exit code, so we
# decide PASS/FAIL by scanning the output for the gate's ACCEPTED/REJECTED lines.
declare -a NAMES RESULTS
fails=0
for v in $VERSIONS; do
  printf '\n%s== kernel %s ==%s\n' "$B" "$v" "$O"
  log="$(mktemp)"
  vng --run "$v" --user root --exec 'bash scripts/kernel-compat/bpf-verify.sh' 2>&1 \
    | grep -vE '^\s+[0-9]+: \(' | tee "$log"      # drop the per-insn verifier dump; keep the reason
  if grep -q 'verifier ACCEPTED' "$log" && ! grep -q 'REJECTED' "$log"; then
    RESULTS+=("PASS")
  else
    RESULTS+=("FAIL"); fails=$((fails+1))
  fi
  NAMES+=("$v"); rm -f "$log"
done

printf '\n%s== kernel matrix summary ==%s\n' "$B" "$O"
for i in "${!NAMES[@]}"; do
  c="$G"; [ "${RESULTS[$i]}" = FAIL ] && c="$R"
  printf '  %s%-6s%s  %s\n' "$c" "${RESULTS[$i]}" "$O" "${NAMES[$i]}"
done
if [ "$fails" -eq 0 ]; then
  printf '\n%sALL %d kernels passed the verifier gate.%s\n' "$G" "${#NAMES[@]}" "$O"; exit 0
else
  printf '\n%s%d of %d kernels FAILED.%s\n' "$R" "$fails" "${#NAMES[@]}" "$O"; exit 1
fi
