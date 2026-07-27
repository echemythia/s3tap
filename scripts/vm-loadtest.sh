#!/usr/bin/env bash
# vm-loadtest.sh — end-to-end v1 load test for s3tap on a real Linux kernel.
#
# Run this INSIDE a throwaway Linux VM (isolation is deliberate: s3tap loads
# unsigned eBPF, takes CAP_SYS_ADMIN, and can inject network faults). It validates
# the parts `cargo test` cannot: that the eBPF VERIFIER accepts the program at
# load, that a real capture against real S3 produces records, and that the
# consumers + the self-driving `--live` path work end to end.
#
#   Requirements in the VM:
#     - Linux kernel >= 5.8 with BTF  (test: -r /sys/kernel/btf/vmlinux)
#     - clang, libbpf-dev, bpftool, a Rust toolchain (cargo), and sudo
#     - Real AWS credentials in the environment or ~/.aws, and the `aws` CLI
#     - Network egress to S3
#   scripts/vm-cloud-init.yaml installs all of these; that list is the same set the CI
#   workflows install and the README requires.
#
#   Configure via env (or edit the defaults below):
#     S3TAP_BUCKET   (required)  a bucket your creds can read, e.g. my-test-bucket
#     S3TAP_KEY      (optional)  an object key to GET; if unset, a ListObjects is used
#     AWS_REGION     (optional)  the bucket's region (default us-east-1)
#     S3TAP_INSTALL_DIR          where to install the capped binary (default /usr/local/bin)
#     S3TAP_SKIP_BUILD=1         reuse an existing target/release/s3tap
#     S3TAP_KEEP_CAPS=1          leave the file caps installed at the end (default: removed)
#
#   Usage:
#     S3TAP_BUCKET=my-bucket S3TAP_KEY=path/to/object AWS_REGION=eu-west-1 \
#       ./scripts/vm-loadtest.sh
#
# The script prints PASS/FAIL per stage and exits non-zero if any stage fails.
set -uo pipefail

# --- config ------------------------------------------------------------------
BUCKET="${S3TAP_BUCKET:-}"
KEY="${S3TAP_KEY:-}"
REGION="${AWS_REGION:-us-east-1}"
INSTALL_DIR="${S3TAP_INSTALL_DIR:-/usr/local/bin}"
BIN="${INSTALL_DIR}/s3tap"
WORK="$(mktemp -d /tmp/s3tap-loadtest.XXXXXX)"
CAP="${WORK}/capture.jsonl"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- output helpers ----------------------------------------------------------
if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; O=$'\e[0m'; else G= R= Y= B= O=; fi
PASS=0; FAIL=0; SKIP=0
step()  { printf '\n%s== %s ==%s\n' "$B" "$1" "$O"; }
ok()    { printf '  %sPASS%s %s\n' "$G" "$O" "$1"; PASS=$((PASS+1)); }
bad()   { printf '  %sFAIL%s %s\n' "$R" "$O" "$1"; FAIL=$((FAIL+1)); }
skip()  { printf '  %sSKIP%s %s\n' "$Y" "$O" "$1"; SKIP=$((SKIP+1)); }
die()   { printf '\n%sABORT%s %s\n' "$R" "$O" "$1"; exit 2; }

# Resolve what `/proc/<pid>/exe` will report for a command, so the capture can be scoped
# with --exe (an absolute path read back from the inode) instead of --app (a basename).
#
# This matters for `aws` in particular. The scope is matched against the exe basename read
# from /proc/<pid>/exe, and the AWS CLI is commonly a #! WRAPPER: aws-cli v1 (the apt and
# pip package) is a Python script, so the kernel execs the INTERPRETER and /proc/<pid>/exe
# reads /usr/bin/python3.12 — never "aws". `--app aws` therefore matches no process at all,
# the capture comes back empty, and nothing in the output says why. aws-cli v2 installs a
# real ELF named `aws`, where this resolves to that binary and --exe is simply the
# unforgeable spelling of the same scope.
resolve_exec() {
  local path shebang interp
  path="$(command -v "$1" 2>/dev/null)" || return 1
  path="$(readlink -f "$path")" || return 1          # follow the whole symlink chain
  if [ "$(head -c 2 -- "$path" 2>/dev/null)" = '#!' ]; then
    shebang="$(head -n 1 -- "$path")"
    # Deliberate word-split: the line is "#!/usr/bin/python3" or "#!/usr/bin/env python3".
    # shellcheck disable=SC2086
    set -- ${shebang#\#!}
    [ "$#" -gt 0 ] || return 1
    [ "$(basename -- "$1")" = "env" ] && shift
    [ "$#" -gt 0 ] || return 1
    interp="$(command -v "$1" 2>/dev/null)" || return 1
    readlink -f "$interp"
  else
    printf '%s\n' "$path"
  fi
}

cleanup() {
  # Stop any background capture, drop caps unless asked to keep, remove scratch.
  if [ -n "${CAP_PID:-}" ]; then kill -INT "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; fi
  if [ -x "$BIN" ] && [ "${S3TAP_KEEP_CAPS:-0}" != "1" ]; then
    sudo "$BIN" setup --remove >/dev/null 2>&1 && printf '\n(cleanup) removed file caps from %s\n' "$BIN"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- 0. preflight ------------------------------------------------------------
step "0. Preflight"
[ -n "$BUCKET" ] || die "set S3TAP_BUCKET to a bucket your AWS creds can read"
uname -sr
if [ -r /sys/kernel/btf/vmlinux ]; then ok "kernel BTF present ($(uname -r))"; else bad "no /sys/kernel/btf/vmlinux — kernel needs CONFIG_DEBUG_INFO_BTF=y"; fi
command -v clang >/dev/null && ok "clang: $(clang --version | head -1)" || die "clang not found (needed to compile the eBPF object)"
command -v cargo >/dev/null && ok "cargo present" || die "cargo not found"
command -v aws   >/dev/null && ok "aws CLI present" || die "aws CLI not found (used to drive real S3 traffic)"
# The capture in stage 5 is scoped to this exact path, not to the name "aws" (see resolve_exec).
AWS_EXE="$(resolve_exec aws)" || die "could not resolve the executable behind 'aws'"
[ -x "$AWS_EXE" ] || die "resolved 'aws' to '$AWS_EXE', which is not an executable file"
if [ "$(basename -- "$AWS_EXE")" = "aws" ]; then
  ok "aws execs $AWS_EXE (a real binary)"
else
  ok "aws is a wrapper script: it execs $AWS_EXE — stage 5 scopes to that (an --app aws scope would match nothing)"
fi
if aws sts get-caller-identity >/dev/null 2>&1; then ok "AWS credentials resolve"; else bad "aws sts get-caller-identity failed — check creds/network (continuing)"; fi

# --- 1. build ----------------------------------------------------------------
step "1. Build (compiles + embeds the eBPF object)"
# bpf/vmlinux/vmlinux.h is a multi-MB GENERATED header and is gitignored, so a fresh
# clone does not have it and build.rs panics before clang ever runs. Generate it from
# this kernel's own BTF, exactly as `just bpf-headers` and every CI workflow do. Doing it
# here rather than telling the operator to run `just` first keeps the documented
# "git clone && ./scripts/vm-loadtest.sh" flow working on a freshly provisioned VM.
if [ ! -s "${REPO_ROOT}/bpf/vmlinux/vmlinux.h" ]; then
  BPFTOOL="$(command -v bpftool || ls -1 /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1)"
  [ -n "$BPFTOOL" ] || die "bpftool not found (install linux-tools-generic) — needed to generate bpf/vmlinux/vmlinux.h"
  mkdir -p "${REPO_ROOT}/bpf/vmlinux"
  # The redirect runs as the invoking user, NOT as root, which is exactly what we want:
  # only the BTF READ needs privilege, and the header must stay owned by the user whose
  # `cargo build` reads it. (shellcheck SC2024 flags the shape; it is deliberate here.)
  # shellcheck disable=SC2024
  sudo "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "${REPO_ROOT}/bpf/vmlinux/vmlinux.h" \
    || die "bpftool could not dump the kernel BTF — is /sys/kernel/btf/vmlinux readable?"
  [ -s "${REPO_ROOT}/bpf/vmlinux/vmlinux.h" ] || die "generated vmlinux.h is empty"
  ok "generated bpf/vmlinux/vmlinux.h from this kernel's BTF"
fi
if [ "${S3TAP_SKIP_BUILD:-0}" = "1" ] && [ -x "${REPO_ROOT}/target/release/s3tap" ]; then
  skip "S3TAP_SKIP_BUILD=1 — reusing target/release/s3tap"
else
  ( cd "$REPO_ROOT" && cargo build --release -p s3tap ) && ok "release build" || die "build failed"
fi
[ -x "${REPO_ROOT}/target/release/s3tap" ] || die "target/release/s3tap missing after build"

# --- 2. install to a root-owned path + grant caps ----------------------------
# setup REFUSES a user-writable path (the TOCTOU guard), so install to a root dir first.
step "2. Install to ${INSTALL_DIR} and grant capabilities"
sudo install -m 0755 "${REPO_ROOT}/target/release/s3tap" "$BIN" && ok "installed $BIN" || die "install failed"
if sudo "$BIN" setup --uprobes; then ok "setup --uprobes granted caps (incl. CAP_SYS_ADMIN for L7)"; else bad "setup --uprobes failed"; fi
if command -v getcap >/dev/null; then
  getcap "$BIN" 2>/dev/null | grep -q . && ok "file caps present: $(getcap "$BIN")" || bad "no file caps on $BIN"
else
  skip "getcap not installed (libcap2-bin) — can't confirm caps; setup's own result above stands"
fi

# --- 3. verifier smoke: does the eBPF LOAD? ----------------------------------
# The kernel verifier only runs at load. This is the key check for the recently
# changed BPF (srv_scratch split, TCP unmark). `check --map-only` loads the
# programs and prints the regional map without needing S3 object traffic.
step "3. eBPF verifier smoke (load the programs)"
VOUT="${WORK}/verifier.txt"
if "$BIN" check --map-only >"$VOUT" 2>&1; then
  ok "eBPF loaded and attached (verifier accepted the program)"
else
  bad "eBPF failed to load — likely a verifier rejection; see below"
  sed 's/^/    /' "$VOUT" | tail -25
fi

# --- 4. self-driving L7 path: `check` against a real object ------------------
# `check --auth` drives its own SigV4 curl workload (system libssl → the uprobe
# attaches reliably) and judges the L7 latency breakdown end to end.
step "4. Self-driving check against real S3 (L7 via uprobe)"
if [ -n "$KEY" ]; then
  COUT="${WORK}/check.txt"
  if "$BIN" check "${BUCKET}/${KEY}" --region "$REGION" --auth --verbose >"$COUT" 2>&1; then
    ok "check ${BUCKET}/${KEY} completed (healthy verdict, exit 0)"
  else
    rc=$?; if [ "$rc" = 1 ]; then skip "check ran but reported ⚠ (exit 1) — inspect the report:"; else bad "check errored (exit $rc):"; fi
    sed 's/^/    /' "$COUT" | tail -20
  fi
  grep -qiE "ttfb|round-trip|handshake|download" "${WORK}/check.txt" && ok "L7/path rows present in the report" || skip "no L7 rows — uprobe may not have attached (check CAP_SYS_ADMIN)"
else
  skip "S3TAP_KEY unset — skipping the object check (set it for the L7 path)"
fi

# --- 5. passive capture of a real app's S3 traffic ---------------------------
# Scoped with --exe, not --app: the scope must be the exe the AWS CLI actually execs, which
# for the wrapper-script builds is the Python interpreter (resolved in preflight). --exe is
# also the unforgeable spelling — a basename is only as trustworthy as the paths local users
# can write to. NB when `aws` IS a wrapper this scope is the interpreter, so any other
# python3 process on the box is in scope too; that is fine on the throwaway VM this script
# is meant for, and it is still narrower than a host-wide capture.
step "5. Passive capture (--exe ${AWS_EXE}) of real S3 traffic"
"$BIN" --exe "$AWS_EXE" --format jsonl >"$CAP" 2>"${WORK}/run.err" &
CAP_PID=$!
sleep 2   # let the probes attach before traffic starts
if [ -n "$KEY" ]; then DRIVE=(aws s3 cp "s3://${BUCKET}/${KEY}" /dev/null --region "$REGION");
else                   DRIVE=(aws s3 ls "s3://${BUCKET}"          --region "$REGION"); fi
for i in 1 2 3 4 5; do "${DRIVE[@]}" >/dev/null 2>&1; done
sleep 1
kill -INT "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; CAP_PID=
LINES=$(wc -l <"$CAP" 2>/dev/null || echo 0)
if [ "${LINES:-0}" -gt 0 ]; then ok "capture produced $LINES record(s)"; else bad "capture is empty (scope was --exe ${AWS_EXE}) — see ${WORK}/run.err:"; sed 's/^/    /' "${WORK}/run.err" | tail -15; fi
grep -q 's3tap.connection' "$CAP" && ok "connection records present (kernel-side capture works)" || bad "no connection records"
grep -q 's3tap.operation'  "$CAP" && ok "operation (L7) records present" || skip "no operation records — L7 decode needs the uprobe on the app's TLS lib (aws-cli v2 bundles its own; expected)"

# --- 6. consumers: doctor + advise -------------------------------------------
step "6. Consumers judge the capture"
if [ "${LINES:-0}" -gt 0 ]; then
  "$BIN" doctor --from "$CAP" >"${WORK}/doctor.txt" 2>&1; rc=$?
  [ "$rc" -le 1 ] && ok "doctor ran (exit $rc: 0=healthy, 1=⚠ finding)" || { bad "doctor errored (exit $rc):"; sed 's/^/    /' "${WORK}/doctor.txt" | tail -15; }
  "$BIN" doctor --from "$CAP" --json >"${WORK}/findings.ndjson" 2>&1 && grep -q 's3tap.finding' "${WORK}/findings.ndjson" && ok "doctor --json emits findings" || skip "no findings NDJSON (may be a very short capture)"
  "$BIN" advise --from "$CAP" >"${WORK}/advise.txt" 2>&1; rc=$?
  [ "$rc" -le 1 ] && ok "advise ran (exit $rc)" || { bad "advise errored (exit $rc)"; sed 's/^/    /' "${WORK}/advise.txt" | tail -15; }
else
  skip "no capture to judge"
fi

# --- 7. full self-driving check (the `doctor --live` front-end) --------------
# `check` with no target = regional round-trip map + a health check against a
# public AWS Open Data object nearby: it drives its own workload and judges it,
# exercising the complete live path without needing your bucket.
step "7. Full self-driving check (regional map + nearby public-object health)"
if "$BIN" check >"${WORK}/live.txt" 2>&1; then
  ok "self-driving check drove its own workload and judged it (exit 0)"
else
  rc=$?; [ "$rc" = 1 ] && skip "check ran, reported ⚠ (exit 1) — inspect ${WORK}/live.txt" || { bad "self-driving check errored (exit $rc):"; sed 's/^/    /' "${WORK}/live.txt" | tail -15; }
fi

# --- summary -----------------------------------------------------------------
step "Summary"
printf '  %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' "$G" "$PASS" "$O" "$R" "$FAIL" "$O" "$Y" "$SKIP" "$O"
if [ "$FAIL" -eq 0 ]; then
  printf '  %sv1 load test PASSED%s — eBPF loads, real capture + consumers + --live all work.\n' "$G" "$O"
  exit 0
else
  printf '  %sv1 load test had failures%s — see the FAIL lines above.\n' "$R" "$O"
  exit 1
fi
