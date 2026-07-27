#!/usr/bin/env bash
# The shell equivalent of `sudo s3tap setup [--uprobes]` (elevate.rs), kept for
# build scripts and the dev loop — the two MUST grant the same caps; the
# cap_string() unit test pins the strings below.
#
# Grant the s3tap agent the capabilities it needs to load + attach its eBPF so
# it can run WITHOUT sudo:
#   cap_bpf            — load BPF programs and create maps
#   cap_perfmon       — attach via perf_event_open (tracepoint/kprobe)
#   cap_dac_read_search — read the attach metadata under tracefs
#                         (/sys/kernel/tracing/.../id), which is root-only (0700)
#                         and is a filesystem DAC check that cap_bpf/perfmon do
#                         NOT bypass. Without it, attach fails with EACCES even
#                         though the program loads fine.
#
# Those three cover the KERNEL-probe path (M1..M3 E2): the tracepoint + kprobes.
#
# UPROBES (opt-in, the bigger hammer): the libc `getaddrinfo` enhancement (M2)
# and the `SSL_write`/`SSL_read` plaintext probes (M3 E3) attach via the uprobe
# perf PMU. On this kernel (+AppArmor) that perf_event_open returns EACCES with
# only cap_perfmon — uprobe creation needs the broader CAP_SYS_ADMIN, which also
# bypasses perf_event_paranoid and permits the tracefs uprobe_events fallback.
# We keep it OUT of the default (least privilege: most runs only need the kernel
# probes) and gate it behind `UPROBES=1`, so only the TLS-plaintext path pays the
# extra privilege:
#   UPROBES=1 ./setcap.sh release
#
# Capabilities attach to the binary's inode, so `cargo build` wipes them —
# re-run this after every recompile. Run it from a real terminal (it calls
# sudo for the setcap itself; the agent afterwards runs as your normal user).
#
# SAFETY, and the limit of it: like `s3tap setup`, this REFUSES a target a local user
# could rewrite (see the gate below). A normal dev tree is exactly that, so the dev loop
# either installs to a root-owned path first or opts out with S3TAP_SETCAP_INSECURE=1.
#
# That gate is about who can REWRITE the binary. It says nothing about who can RUN it, and
# a file capability is granted to EVERYONE who can execute the inode. A root-owned mode-0755
# s3tap therefore hands cap_bpf/cap_perfmon/cap_dac_read_search (and cap_sys_admin under
# UPROBES=1) to every local user, who can then run `s3tap --capture-plaintext` with no scope
# and read every other user's and root's decrypted S3 traffic. On a multi-user host, pass the
# execute bit through a dedicated group as well (see SECURITY.md):
#   sudo groupadd -f s3tap && sudo usermod -aG s3tap <user>
#   sudo install -m 0750 -g s3tap target/release/s3tap /usr/local/bin/s3tap
#
# Usage:
#   ./setcap.sh                 # tags target/release/s3tap (kernel-probe caps)
#   ./setcap.sh debug           # tags target/debug/s3tap
#   ./setcap.sh path/to/s3tap
#   UPROBES=1 ./setcap.sh       # also grant cap_sys_admin (uprobes / TLS plaintext)
#   S3TAP_SETCAP_INSECURE=1 ./setcap.sh   # accept a user-writable target (dev boxes)
set -euo pipefail

cd "$(dirname "$0")"

case "${1:-release}" in
    release) bin="target/release/s3tap" ;;
    debug)   bin="target/debug/s3tap" ;;
    *)       bin="$1" ;;
esac

if [[ ! -x "$bin" ]]; then
    echo "error: '$bin' not found — build it first (e.g. 'just build' or 'cargo build --release')." >&2
    exit 1
fi

# --- safety gate: the shell twin of `insecure_setcap_target` (elevate.rs) -----
# `sudo s3tap setup` REFUSES to cap a binary a local user can rewrite, or one under a
# directory they can rename/replace. This script claims to be its shell equivalent, so
# it has to refuse the same targets: otherwise the documented dev loop is a way around
# the Rust guard. File caps belong to whoever can put bytes in that inode, so
# cap_sys_admin on a writable binary lets EVERY local user read host-wide decrypted
# traffic, and a writable ancestor allows the same swap by rename after the check.
#
# Policy (kept identical to elevate.rs, component by component): on the symlink-RESOLVED
# path — so a symlinked segment can't smuggle a writable directory past the walk — the
# binary and every ancestor directory up to `/` must be root-owned and not group/other-
# writable (mode & 022). An un-stattable component fails closed.
unsafe_component() {   # <what> <path> -> prints the reason, prints nothing when safe
    local what="$1" path="$2" st
    st="$(stat -c '%u %a' -- "$path" 2>/dev/null)" || st=""
    if [[ -z "$st" ]]; then
        printf 'cannot stat the %s' "$what"
    elif [[ "${st%% *}" != 0 ]]; then
        printf 'the %s is owned by uid %s, not root' "$what" "${st%% *}"
    elif (( 8#${st##* } & 8#22 )); then
        printf 'the %s is group- or world-writable (mode %s)' "$what" "${st##* }"
    fi
    return 0   # the reason is the OUTPUT; a non-zero status here would kill `set -e`
}

real="$(readlink -f -- "$bin" 2>/dev/null || true)"
if [[ -z "$real" ]]; then real="$bin"; fi
reason="$(unsafe_component binary "$real")"
dir="$(dirname -- "$real")"
while [[ -z "$reason" ]]; do
    if [[ "$dir" == / ]]; then
        reason="$(unsafe_component "root directory" "$dir")"
        break
    fi
    reason="$(unsafe_component "directory $dir" "$dir")"
    parent="$(dirname -- "$dir")"
    # A path that never reaches `/` (readlink -f missing, so `$bin` stayed relative):
    # stop rather than spin on dirname's fixed point. Everything walked so far still had
    # to pass, and the binary check alone already rejects a user-owned dev build.
    if [[ "$parent" == "$dir" ]]; then break; fi
    dir="$parent"
done

if [[ -n "$reason" ]]; then
    # The opt-out exists because THIS script is the documented dev loop (the documented dev loop: re-run
    # after every build; the demos print it): a hard refusal would leave no way to run a
    # freshly built binary uncapped-but-sudo-free, and devs would paste a raw `sudo setcap`
    # that has no gate at all. So keep the refusal the default and make the unsafe case an
    # explicit, per-invocation decision that says out loud what it costs.
    if [[ "${S3TAP_SETCAP_INSECURE:-0}" != 1 ]]; then
        cat >&2 <<EOF
error: refusing to grant capabilities to $real: $reason.
  A file capability is available to EVERY user who can execute the file. Ownership and
  mode only decide who can REWRITE it, so this refusal buys you one thing: that the code
  running with these caps stays the code you capped. It does NOT make the caps yours
  alone. A writable binary (or a writable ancestor directory, which allows the same swap
  by rename after the check) additionally lets any local user CHOOSE that code.
  This is the SAME refusal \`sudo s3tap setup\` gives on this binary (elevate.rs); the two
  paths grant the same caps, so they must refuse the same targets.
  Install s3tap under a root-owned path and cap that copy:
      sudo install -m 0755 "$bin" /usr/local/bin/s3tap
      sudo s3tap setup [--uprobes]        # or: $0 /usr/local/bin/s3tap
  On a MULTI-USER host that root-owned copy is still runnable by everyone, and
  \`s3tap --capture-plaintext\` with no scope reads every other user's and root's decrypted
  S3 traffic. Restrict who may execute it as well:
      sudo groupadd -f s3tap && sudo usermod -aG s3tap "\$USER"
      sudo install -m 0750 -g s3tap "$bin" /usr/local/bin/s3tap
      sudo s3tap setup [--uprobes]
  or just keep running under sudo. On a single-user dev box where you accept that any
  local user could then use these caps, re-run with:
      S3TAP_SETCAP_INSECURE=1 ${UPROBES:+UPROBES=$UPROBES }$0 ${1:-}
EOF
        exit 1
    fi
    echo "warning: S3TAP_SETCAP_INSECURE=1 — capping an unsafe target ($reason)." >&2
    echo "         Anyone who can write $real (or an ancestor directory) chooses what runs" >&2
    echo "         with these caps, and anyone who can EXECUTE it already holds them." >&2
fi

caps="cap_bpf,cap_perfmon,cap_dac_read_search"
if [[ "${UPROBES:-0}" == 1 ]]; then
    caps="$caps,cap_sys_admin"   # enable uprobe attach (getaddrinfo M2, SSL_* M3 E3)
fi

# Cap `$real`, not `$bin`. The gate above validated the symlink-RESOLVED path, so capping
# the un-resolved argument would leave the same TOCTOU the ancestor walk was added to close:
# `sudo ./setcap.sh /tmp/attacker/link` pointed at a root-owned binary passes the check, and
# the owner of that link can re-point it at their own binary before this line runs. Checking
# one path and capping another is a seam `s3tap setup` does not have. Keep them the same path.
sudo setcap "$caps+ep" "$real"

echo "tagged $real (${UPROBES:+uprobes }caps: $caps):"
getcap "$real"
echo "run it without sudo:  $real"
# Say the part the refusal above cannot enforce, so it is never inferred from silence:
# passing the ownership gate is not the same as holding these caps privately.
echo "note: these caps are held by EVERY user who can execute this file, not just you." >&2
echo "      On a shared host restrict the execute bit too (see SECURITY.md)." >&2

# Discoverability: point users at the uprobe path when they didn't opt into it. The
# default caps cover connections / wire DNS / SNI; the plaintext (--capture-plaintext)
# and `selftest` HTTP path need the SSL uprobes (cap_sys_admin), kept opt-in for
# least privilege since cap_sys_admin is near-root.
if [[ "${UPROBES:-0}" != 1 ]]; then
    echo "hint: for --capture-plaintext / 'selftest' (HTTP semantics + getaddrinfo)," >&2
    echo "      re-run with:  UPROBES=1 $0 ${1:-}" >&2
fi
