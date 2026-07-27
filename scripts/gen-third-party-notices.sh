#!/usr/bin/env bash
# Regenerate THIRD-PARTY-NOTICES.md from Cargo.lock.
#
# Scoped to what is actually REDISTRIBUTED: the dependency graph of the published
# s3tap-linux-* binaries. Build- and dev-dependencies are excluded — they never reach a
# user. musl libc is added by hand because it is linked statically and is not a Cargo
# dependency, so no Cargo-based tool can see it.
#
# The `--target` below is the Rust triple those binaries are built from; it is build
# vocabulary and deliberately does not appear in the generated file, which names the
# artifacts the way the release page does.
#
# Run after any dependency change; CI checks the file is in sync.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fetch --locked >/dev/null
cargo tree -p s3tap -e normal --target x86_64-unknown-linux-musl --prefix none --no-dedupe \
  | sed 's/ (\*)$//' | awk 'NF{print $1" "$2}' | sort -u > /tmp/s3tap-shipped.txt
python3 scripts/gen-third-party-notices.py /tmp/s3tap-shipped.txt
