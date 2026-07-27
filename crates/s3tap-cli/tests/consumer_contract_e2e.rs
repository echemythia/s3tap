//! The two pure-consumer contracts that every subcommand must honor and
//! that nothing else pins end to end:
//!
//!   * "A closed pipe (`… | head`) is a clean `exit(0)`, never a panic."
//!   * "`--no-color` is honored AND auto-off on a non-tty."
//!
//! Both are implemented by hand at nine-ish call sites rather than by a shared wrapper,
//! and the closed-pipe mapping has already regressed once and shipped. A unit test can
//! only reach the predicate (`is_broken_pipe`) or the decision (`want_color`); only a real
//! process with a real closed pipe covers the write path each subcommand actually takes.
//!
//! Every consumer is exercised in BOTH renderings (human and `--json`), because they are
//! different write paths: `--json` writes per record, the human render writes one buffer.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_s3tap");

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Every (subcommand, rendering) pair a consumer contract has to hold for. `analyze` reads
/// the advisor capture: it is the same s3tap JSONL, and its trace loader accepts it.
fn consumer_invocations() -> Vec<Vec<String>> {
    let mut v = Vec::new();
    for (cmd, fx) in [
        ("doctor", "doctor_sample.jsonl"),
        ("advise", "advisor_sample.jsonl"),
        ("scorecard", "scorecard_sample.jsonl"),
        ("analyze", "advisor_sample.jsonl"),
    ] {
        for json in [false, true] {
            let mut args = vec![cmd.to_string(), "--from".into(), fixture(fx)];
            if json {
                args.push("--json".into());
            }
            v.push(args);
        }
    }
    v
}

/// Neither failure mode may appear on stderr: a panic (the regression that shipped) nor a
/// reported "Broken pipe" (anyhow printing the error instead of treating it as a clean stop).
fn assert_stderr_is_quiet(stderr: &str, what: &str) {
    assert!(!stderr.contains("panicked"), "{what} panicked on a closed pipe:\n{stderr}");
    assert!(
        !stderr.to_ascii_lowercase().contains("broken pipe"),
        "{what} reported the closed pipe as an error instead of stopping cleanly:\n{stderr}"
    );
}

#[test]
fn a_pipe_closed_before_the_first_write_is_a_clean_exit_zero() {
    // The deterministic half: the read end is gone BEFORE the child writes a byte, so the
    // very first write returns EPIPE. (The read-one-line variant below is the shape a user
    // actually types, but a small report fits entirely in the pipe buffer, so it does not
    // reliably reach the EPIPE path — this one always does.)
    for args in consumer_invocations() {
        let what = args.join(" ");
        let (reader, writer) = std::io::pipe().expect("pipe");
        let mut child = Command::new(BIN)
            .args(&args)
            .stdout(Stdio::from(writer))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
        drop(reader); // no reader remains: every write the child attempts is EPIPE
        let mut stderr = String::new();
        child.stderr.take().expect("piped stderr").read_to_string(&mut stderr).expect("read stderr");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(0), "{what} exited {status:?}, want a clean 0\n{stderr}");
        assert_stderr_is_quiet(&stderr, &what);
    }
}

#[test]
fn reading_one_line_then_closing_the_pipe_never_panics() {
    // The documented shape: `s3tap doctor --from capture.jsonl | head -1`.
    //
    // NB this one deliberately does NOT assert exit 0, and that is not a weakening. These
    // reports are summaries of a few kilobytes, so they fit entirely in the pipe buffer
    // before the reader goes away: the write genuinely SUCCEEDS and the command is right to
    // return its verdict code (a `doctor` that found something is exit 1 whether or not the
    // reader stayed). Asserting 0 here would only pass by accident of the fixture's verdict.
    // What must hold in this shape is that the process still terminates on a documented
    // code with nothing on stderr — the exit-0 mapping itself is pinned by the test above,
    // which guarantees the EPIPE.
    for args in consumer_invocations() {
        let what = args.join(" ");
        let mut child = Command::new(BIN)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
        {
            let mut r = BufReader::new(child.stdout.take().expect("piped stdout"));
            let mut line = String::new();
            r.read_line(&mut line).unwrap_or_else(|e| panic!("read one line of {what}: {e}"));
            assert!(!line.is_empty(), "{what} produced no output to close the pipe on");
        } // reader dropped here: the pipe is closed under the child
        let mut stderr = String::new();
        child.stderr.take().expect("piped stderr").read_to_string(&mut stderr).expect("read stderr");
        let status = child.wait().expect("wait");
        assert_documented_exit(status.code(), &what, &stderr);
        assert_stderr_is_quiet(&stderr, &what);
    }
}

/// A documented consumer exit code: 0 healthy/clean stop, 1 attention (or `--strict`),
/// 2 no baseline. Anything else — 101 from a panic, `None` from a signal — is the failure.
fn assert_documented_exit(code: Option<i32>, what: &str, stderr: &str) {
    assert!(
        matches!(code, Some(0..=2)),
        "{what} exited {code:?}; only the documented verdict codes are allowed\n{stderr}"
    );
}

#[test]
fn no_consumer_writes_ansi_to_a_non_tty() {
    // stdout here is a pipe, so color must be off WITHOUT being asked: a consumer that
    // only checks `--no-color` would leak escapes into every redirected report and into
    // `… | grep`. Both the default and the explicit flag are checked, so a subcommand that
    // wires up one of the two halves still fails.
    for mut args in consumer_invocations() {
        for explicit in [false, true] {
            if explicit {
                args.push("--no-color".into());
            }
            let what = args.join(" ");
            let out = Command::new(BIN).args(&args).output().unwrap_or_else(|e| panic!("run {what}: {e}"));
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            // The verdict code is the fixture's business; what matters here is that the
            // command RAN and rendered (a usage error would trivially contain no escapes).
            assert_documented_exit(out.status.code(), &what, &stderr);
            let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
            assert!(!stdout.is_empty(), "{what} rendered nothing, so the check is vacuous");
            assert!(
                !stdout.contains('\x1b'),
                "{what} wrote an ANSI escape to a non-tty:\n{stdout:?}"
            );
        }
    }
}
