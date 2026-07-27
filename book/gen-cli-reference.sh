#!/usr/bin/env bash
# Regenerate book/src/reference/cli.md from the binary's own --help, so the command
# reference can never drift from the actual clap parser. Run after any CLI change:
#   cargo build -p s3tap && book/gen-cli-reference.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=target/debug/s3tap
[ -x "$BIN" ] || { echo "build first: cargo build -p s3tap" >&2; exit 1; }

OUT=book/src/reference/cli.md
# Derive the subcommand list from the parser's own `Commands:` block rather than hardcoding
# it — a hardcoded list silently omits new subcommands (e.g. `scorecard`), which is exactly
# the drift this generator promises to prevent. Take the first token of each indented command
# line in the Commands: section, minus clap's built-in `help`.
mapfile -t SUBS < <(
  "$BIN" --help |
    awk '/^Commands:/{f=1;next} f&&/^[^ ]/{f=0} f&&/^  [a-z]/ && $1!="help"{print $1}'
)

# clap wraps a long option's help text across paragraphs with a BLANK line that still
# carries the paragraph's indent — trailing whitespace that means nothing to a terminal
# but fails `git diff --check` on every regeneration. Strip trailing whitespace per line;
# the visible content of the captured --help text is otherwise untouched.
strip_trailing_ws() { sed -E 's/[[:space:]]+$//'; }

{
  echo "# CLI reference"
  echo
  # No dash punctuation in the emitted prose: this line is the one sentence the generator
  # writes itself, so it follows the house style the rest of the book follows.
  echo "> Generated from \`s3tap --help\` by \`book/gen-cli-reference.sh\`. Do not edit by hand."
  echo
  echo "## s3tap"
  echo
  echo '```text'
  "$BIN" --help | strip_trailing_ws
  echo '```'
  for s in "${SUBS[@]}"; do
    echo
    echo "## s3tap $s"
    echo
    echo '```text'
    "$BIN" "$s" --help | strip_trailing_ws
    echo '```'
  done
} > "$OUT"

echo "wrote $OUT"
