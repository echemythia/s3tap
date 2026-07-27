#!/bin/sh
# s3tap installer. Downloads a prebuilt, self-contained binary from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/echemythia/s3tap/main/install.sh | sh
#
# Config via env:
#   S3TAP_VERSION       release tag to install (default: latest; `latest` or vX.Y.Z only)
#   S3TAP_BINDIR        install directory (default: ~/.local/bin)
#   S3TAP_ATTESTATION   auto (default) | require | skip — see "verify" below
set -eu

REPO="echemythia/s3tap"
BINDIR="${S3TAP_BINDIR:-$HOME/.local/bin}"
VERSION="${S3TAP_VERSION:-latest}"
ATTESTATION="${S3TAP_ATTESTATION:-auto}"

fail() { echo "s3tap install: $*" >&2; exit 1; }

# --- platform detection -----------------------------------------------------
os="$(uname -s)"
[ "$os" = "Linux" ] || fail "capture needs Linux with eBPF (detected $os). On macOS the pure consumers build from source."

# x86_64 and aarch64 are published; see the matrix in .github/workflows/release.yml.
case "$(uname -m)" in
  x86_64 | amd64)  arch="x86_64" ;;
  aarch64 | arm64) arch="aarch64" ;;
  *) fail "no prebuilt binary for $(uname -m). x86_64 and aarch64 are published. Build from source instead." ;;
esac
asset="s3tap-linux-$arch"

# --- version validation (same fail-closed bar as the arch check) -------------
# $VERSION is interpolated straight into the download URL, and curl NORMALIZES dot
# segments in a path — so an unvalidated S3TAP_VERSION of
# `../../../attacker/evil/releases/download/v1` repoints BOTH fetches at a DIFFERENT
# repository, and the checksum below then happily verifies the attacker's binary against
# the attacker's own digest. This value is set by copy-pasteable snippets (a blog post, a
# GitHub issue, a Dockerfile ENV, a CI variable), which is exactly how such a string
# travels. Accept only `latest` or a plain vMAJOR.MINOR.PATCH, which is the only shape
# release.yml will build a release for, and refuse everything else.
bad_version() { fail "invalid S3TAP_VERSION '$VERSION': expected 'latest' or vMAJOR.MINOR.PATCH (e.g. v1.2.3)"; }
case "$VERSION" in
  latest) : ;;
  v*.*.*)
    _v="${VERSION#v}"
    _maj="${_v%%.*}"; _rest="${_v#*.}"; _min="${_rest%%.*}"; _pat="${_rest#*.}"
    # Each component must be non-empty and all-digits. That rejects `v0.7.0/../x`,
    # `v0.7.0-rc1` and an embedded newline alike (a newline is a non-digit here).
    for _f in "$_maj" "$_min" "$_pat"; do
      case "$_f" in '' | *[!0-9]*) bad_version ;; esac
    done
    unset _v _rest _maj _min _pat _f
    ;;
  *) bad_version ;;
esac

case "$ATTESTATION" in
  auto | require | skip) : ;;
  *) fail "invalid S3TAP_ATTESTATION '$ATTESTATION': expected auto, require or skip" ;;
esac

# BTF is a hard runtime requirement. Warn early but do not block the install.
[ -r /sys/kernel/btf/vmlinux ] || echo "s3tap install: warning: /sys/kernel/btf/vmlinux not found. Capture needs Linux 5.8+ with BTF." >&2

# --- download ---------------------------------------------------------------
command -v curl >/dev/null 2>&1 || fail "curl is required"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "s3tap install: downloading $asset ($VERSION)"
curl -fSL "$base/$asset" -o "$tmp/s3tap" \
  || fail "download failed from $base/$asset. Check the version and that a release binary exists for this arch (and that the repo is public)."

# --- verify -----------------------------------------------------------------
# TWO checks, because they answer two different questions and only one of them is
# meaningful against a hostile release.
#
#   1. the .sha256 answers "did the bytes arrive intact". It CANNOT answer "who built
#      this", because it ships from the same origin and the same trust root as the binary
#      it describes: anyone who can write a release asset (a leaked contents:write token,
#      an account takeover, a dispatched workflow) replaces the binary AND its digest, and
#      the check still passes.
#   2. the build provenance attestation is the check that survives that. It is signed
#      through Sigstore with an OIDC identity GitHub mints for the release JOB, so it
#      binds these bytes to a repo, a workflow file and a commit, and nothing you can
#      write into a release can forge it.
#
# Verifying (2) needs the GitHub CLI, which not every machine has, so it is preferred
# rather than mandatory. It is never skipped SILENTLY: the script says which level it
# reached, and S3TAP_ATTESTATION=require makes the strong check the only acceptable
# outcome. That matters because the next thing this script tells you to do is
# `sudo s3tap setup`, which grants the binary CAP_BPF/CAP_PERFMON (and CAP_SYS_ADMIN
# with --uprobes).
verify_level="checksum only (transfer integrity)"

# The release always publishes the .sha256 alongside the binary, so a missing one is a
# real problem (wrong URL, partial release), not a reason to skip verification.
curl -fsSL "$base/$asset.sha256" -o "$tmp/sum" || fail "checksum unavailable at $base/$asset.sha256; refusing to install unverified"
want="$(cut -d' ' -f1 "$tmp/sum")"
got="$(sha256sum "$tmp/s3tap" | cut -d' ' -f1)"
[ "$want" = "$got" ] || fail "checksum mismatch (expected $want, got $got)"
echo "s3tap install: checksum ok"

# Why gh has to be BOTH present and usable before we attempt (2): `gh attestation verify`
# exits non-zero for "the attestation is bad" and for "I could not ask" alike, and we fail
# closed on a non-zero exit. So rule out the "could not ask" causes up front, where they
# can be reported honestly, instead of letting a missing login read as tampering.
skip_why=""
if [ "$ATTESTATION" = skip ]; then
  skip_why="S3TAP_ATTESTATION=skip"
elif ! command -v gh >/dev/null 2>&1; then
  skip_why="the GitHub CLI (gh) is not installed"
elif ! gh attestation verify --help >/dev/null 2>&1; then
  skip_why="this gh has no 'gh attestation' subcommand (needs gh 2.49 or newer)"
elif ! gh auth token >/dev/null 2>&1; then
  skip_why="gh is not authenticated (run 'gh auth login', or set GH_TOKEN)"
fi

if [ -z "$skip_why" ]; then
  # --signer-workflow ties the attestation to THIS workflow file rather than to merely
  # some workflow in the repo, so another workflow that could be dispatched with
  # id-token:write cannot vouch for a binary it built. Older gh has no such flag: use
  # --repo alone and say which check was made, rather than dropping the check.
  set -- --repo "$REPO"
  if gh attestation verify --help 2>/dev/null | grep -q -- '--signer-workflow'; then
    set -- "$@" --signer-workflow "$REPO/.github/workflows/release.yml"
  else
    echo "s3tap install: note: this gh predates --signer-workflow; checking the repo identity only" >&2
  fi
  if gh attestation verify "$tmp/s3tap" "$@" >"$tmp/attest.log" 2>&1; then
    verify_level="build provenance attestation + checksum"
    echo "s3tap install: build provenance verified (built by $REPO's release workflow)"
  else
    echo "s3tap install: gh said:" >&2
    while IFS= read -r line; do echo "  $line" >&2; done < "$tmp/attest.log"
    echo "s3tap install: refusing to install $asset ($VERSION): no valid build provenance from" >&2
    echo "s3tap install: $REPO's release workflow. An asset that does not match such an" >&2
    echo "s3tap install: attestation is exactly the tampering the checksum alone cannot see." >&2
    echo "s3tap install: If gh reports 404/no attestations, the release may instead have been" >&2
    echo "s3tap install: built without one: attestations are unavailable to private repositories," >&2
    echo "s3tap install: so a release cut while $REPO was private carries no provenance, as do" >&2
    echo "s3tap install: releases published before attestations were added. Check the release" >&2
    echo "s3tap install: page, and" >&2
    echo "s3tap install: only if you accept a checksum-only install re-run with" >&2
    echo "s3tap install:   curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | S3TAP_ATTESTATION=skip sh" >&2
    fail "build provenance verification FAILED"
  fi
else
  [ "$ATTESTATION" != require ] \
    || fail "S3TAP_ATTESTATION=require, but the build provenance could not be checked: $skip_why"
  echo "s3tap install: WARNING: build provenance NOT verified ($skip_why)." >&2
  echo "s3tap install: WARNING: the .sha256 comes from the same release as the binary, so it proves" >&2
  echo "s3tap install: WARNING: the download was not corrupted, NOT that this binary is the one built" >&2
  echo "s3tap install: WARNING: from the source. For the strong check install gh (https://cli.github.com)" >&2
  echo "s3tap install: WARNING: and re-run with S3TAP_ATTESTATION=require, e.g." >&2
  echo "s3tap install: WARNING:   curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | S3TAP_ATTESTATION=require sh" >&2
fi

# --- install ----------------------------------------------------------------
mkdir -p "$BINDIR"
# 0755 explicitly, NOT `chmod +x`. `+x` adds the execute bit to whatever the umask left on the
# temp file, so a umask of 002 yields 775 — group-writable, which `s3tap setup` REFUSES to
# grant capabilities to (a binary your group can rewrite would inherit CAP_BPF). That made the
# whole thing umask-dependent on exactly the install people then try to `setup`.
chmod 0755 "$tmp/s3tap"
mv "$tmp/s3tap" "$BINDIR/s3tap"
echo "s3tap install: installed to $BINDIR/s3tap"
echo "s3tap install: verification level: $verify_level"

case ":$PATH:" in
  *":$BINDIR:"*) : ;;
  *) echo "s3tap install: note: $BINDIR is not on your PATH. Add it, or run $BINDIR/s3tap directly." ;;
esac

# `setup` grants FILE CAPABILITIES, so it refuses any binary that is not root-owned with
# no group/other-writable component on its whole path — otherwise the user who can rewrite
# the binary inherits CAP_BPF. The default BINDIR is under $HOME and so is exactly that
# case, and printing a bare `sudo s3tap setup` there sent every first-time reader into a
# refusal. Show the copy recipe unless the install target is already safe.
# Root-owned install target: `setup` will accept it, so show the direct commands.
if [ "$(stat -c %u "$BINDIR/s3tap" 2>/dev/null || echo 1)" = "0" ]; then
  setup_cmds="  sudo s3tap setup            grant the caps once so it runs without sudo
  sudo s3tap setup --uprobes  add the L7 / TLS-plaintext path"
else
  setup_cmds="  # \`setup\` needs a root-owned binary (a capability on a binary you can
  # rewrite would hand your own user CAP_BPF), so copy it out of $BINDIR first.
  # Remove this copy too: $BINDIR usually comes EARLIER on PATH, so leaving it
  # means a bare \`s3tap\` keeps running the uncapped one and setup looks broken.
  sudo install -m 0755 $BINDIR/s3tap /usr/local/bin/s3tap
  rm $BINDIR/s3tap
  sudo /usr/local/bin/s3tap setup            grant the caps once
  sudo /usr/local/bin/s3tap setup --uprobes  add the L7 / TLS-plaintext path"
fi

cat <<EOF

Next steps:
  s3tap check                 zero-config health probe (offers sudo to load eBPF)
$setup_cmds

A file capability is available to EVERY user who can execute the binary, so on a
multi-user host restrict the execute bit too (see SECURITY.md) before running setup.

Requires Linux kernel 5.8 or newer with BTF. More at https://github.com/$REPO
EOF
