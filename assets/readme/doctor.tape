# assets/readme/doctor.tape — generate assets/readme/doctor.gif for the README.
#
# Story: capture your app's S3 traffic (privileged), then judge the capture (not).
#   1. CAPTURE — `sudo s3tap … --format jsonl`, with the [sudo] password prompt, shown
#      running for a beat then stopped with Ctrl-C. It is EMULATED: shell stand-ins for
#      `sudo` (prompts, reads a hidden password) and `s3tap` (emits a committed sample)
#      replace the real thing, which loads eBPF probes and needs a live workload — neither
#      reproducible in a GIF.
#   2. JUDGE   — the REAL `s3tap doctor` reads the capture and scores each latency span
#      against the connection's round-trip floor. No probes, no privilege — so the whole
#      recording still reproduces on any machine (like assets/readme/demo.tape did).
#
# Prerequisites:
#   - vhs        (https://github.com/charmbracelet/vhs)
#   - a release build so ./target/release/s3tap exists:  just build
#
# Generate:  vhs assets/readme/doctor.tape   (writes assets/readme/doctor.gif)

Output assets/readme/doctor.gif

Set FontSize 18
Set Width 1500
Set Height 700
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 30ms

# Hidden setup. Two stand-ins so the capture looks real but stays reproducible:
#   sudo  — prints the password prompt, reads a hidden password, then runs the command.
#   s3tap — `doctor` runs the real binary; anything else (the capture) emits a committed
#           sample and idles until interrupted, so `s3tap … --format jsonl` behaves live.
Hide
Type `s3tap(){ if [ "$1" = doctor ]; then "$PWD/target/release/s3tap" "$@"; else echo "capturing… Ctrl-C to stop" >&2; cat crates/s3tap-cli/tests/fixtures/doctor_sample.jsonl; sleep 30; fi; }`
Enter
Type `sudo(){ printf '[sudo] password for you: ' >&2; read -rs; printf '\n' >&2; "$@"; }`
Enter
Type "clear"
Enter
Show

Sleep 600ms

# Capture needs root — s3tap loads eBPF probes. Leave it running as long as you want.
Type "# watch your app's live S3 traffic — leave it running as long as you want:"
Enter
Sleep 300ms
Type "sudo s3tap --app myapp --format jsonl > capture.jsonl"
Sleep 500ms
Enter
Sleep 900ms
# The password is typed but not echoed (sudo hides it), then capture runs.
Type "hunter2"
Enter
Sleep 2s
Ctrl+C
Sleep 800ms

# Judging the capture needs no privilege — doctor is a pure consumer.
Type "# now check it — no root needed:"
Enter
Sleep 300ms
Type "s3tap doctor --from capture.jsonl"
Sleep 600ms
Enter
# Hold on the verdict so it can actually be read.
Sleep 10s

# Cleanup after the final frame (not shown).
Hide
Type "unset -f s3tap sudo; rm -f capture.jsonl"
Enter
Show
