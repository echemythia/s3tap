# assets/readme/check.tape — generate assets/readme/check.gif for the README.
#
# `s3tap check --map-only`: the zero-config front door — "where am I, relative to S3?".
# It probes S3's regions and prints a round-trip latency map. No bucket, no credentials.
#
# The map text in assets/readme/check-map.txt is REAL output, captured from an actual
# `s3tap check --map-only` run inside a rootless virtme-ng VM (root guest, live AWS) —
# because check loads eBPF and VHS can't. It's replayed here through stand-in `sudo`
# (password prompt) and `s3tap` (prints the captured map) so the recording is
# reproducible on any machine. HONESTY NOTE: the round-trips are the host's real path to
# each region, but the ±jitter column is inflated by the VM's user-mode networking — a
# real host shows far lower jitter. The map's ranking (near→far) is accurate.
#
# Re-capture (updates assets/readme/check-map.txt) on a machine with the caps + network:
#   s3tap check --map-only > assets/readme/check-map.txt
#
# Prerequisites: vhs (https://github.com/charmbracelet/vhs); a build so assets/readme/check-map.txt exists.
# Generate:  vhs assets/readme/check.tape   (writes assets/readme/check.gif)

Output assets/readme/check.gif

Set FontSize 18
Set Width 1500
Set Height 640
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 30ms

# Stand-ins so the front door looks real but stays reproducible:
#   sudo  — prints the password prompt, reads a hidden password, then runs the command.
#   s3tap — for `check`, prints the captured map: the intro line, a beat to "probe", the map.
Hide
Type `s3tap(){ if [ "$1" = check ]; then head -1 assets/readme/check-map.txt; sleep 2; tail -n +2 assets/readme/check-map.txt; fi; }`
Enter
Type `sudo(){ printf '[sudo] password for you: ' >&2; read -rs; printf '\n' >&2; "$@"; }`
Enter
Type "clear"
Enter
Show

Sleep 600ms

# The zero-config front door: where do I sit relative to S3? No bucket, no credentials.
Type "# where am I, relative to S3? one command — no bucket, no credentials:"
Enter
Sleep 300ms
Type "sudo s3tap check --map-only"
Sleep 500ms
Enter
Sleep 900ms
Type "hunter2"
Enter
# The intro line prints, then a beat while it probes the regions, then the map.
Sleep 3s
# Hold on the map so it can be read (it's dense — give it time).
Sleep 13s

# Cleanup after the final frame (not shown).
Hide
Type "unset -f s3tap sudo"
Enter
Show
