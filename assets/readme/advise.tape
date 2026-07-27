# assets/readme/advise.tape — generate assets/readme/advise.gif for the s3tap-advisor README.
#
# `s3tap advise`: read a capture and report how the app USES S3 (connection churn,
# missing parallelism, redundant re-fetches, throttling, a caching go/no-go), per process.
# A pure consumer of the committed sample capture, so no probes and no privilege, and
# `vhs assets/readme/advise.tape` reproduces on any machine (like assets/readme/demo.tape did).
#
# Prerequisites: vhs (https://github.com/charmbracelet/vhs); a release build so
# ./target/release/s3tap exists (just build).
# Generate:  vhs assets/readme/advise.tape   (writes assets/readme/advise.gif)

Output assets/readme/advise.gif

Set FontSize 18
Set Width 1500
Set Height 380
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 30ms

# Setup, hidden: put the binary on PATH and stage the sample capture as `capture.jsonl`.
Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "cp crates/s3tap-cli/tests/fixtures/advise_demo.jsonl capture.jsonl && clear"
Enter
Show

Sleep 600ms

# What should I fix? Advice on how the app uses S3, read straight from a capture.
Type "# what should I fix? advice on how the app uses S3, no privilege needed:"
Enter
Sleep 300ms
Type "s3tap advise --from capture.jsonl"
Sleep 600ms
Enter
# Hold on the advisories so they can be read.
Sleep 11s

# Cleanup after the final frame (not shown).
Hide
Type "rm -f capture.jsonl"
Enter
Show
