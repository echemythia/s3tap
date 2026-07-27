#!/usr/bin/env bash
# vm-run.sh — one-command in-VM runner for the s3tap load test.
#
# Waits for cloud-init to finish, clones/updates the repo, sources the Rust
# toolchain, and runs scripts/vm-loadtest.sh — so after `aws configure` your
# whole test is a single paste. Run it INSIDE the load-test VM.
#
# Usage (env vars pass straight through to vm-loadtest.sh):
#   curl -fsSL https://raw.githubusercontent.com/echemythia/s3tap/main/scripts/vm-run.sh \
#     | S3TAP_BUCKET=my-bucket S3TAP_KEY=path/to/object AWS_REGION=eu-west-1 bash
#
# Prereq: AWS credentials configured in the VM first (`aws configure`, or export
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).
set -euo pipefail

REPO="${S3TAP_REPO:-https://github.com/echemythia/s3tap.git}"
DIR="${S3TAP_DIR:-$HOME/s3tap}"

echo "[vm-run] waiting for cloud-init to finish installing deps (first boot only)..."
if command -v cloud-init >/dev/null; then sudo cloud-init status --wait || true; fi

# Pull in the rustup toolchain the cloud-init step installed.
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v cargo >/dev/null || { echo "[vm-run] cargo not on PATH — is provisioning done? try: source ~/.cargo/env"; exit 2; }

if [ -d "$DIR/.git" ]; then
  echo "[vm-run] updating $DIR"; git -C "$DIR" pull --ff-only
else
  echo "[vm-run] cloning $REPO -> $DIR"; git clone "$REPO" "$DIR"
fi

cd "$DIR"
echo "[vm-run] launching the load test..."
exec ./scripts/vm-loadtest.sh    # env (S3TAP_BUCKET/KEY, AWS_REGION) inherited
