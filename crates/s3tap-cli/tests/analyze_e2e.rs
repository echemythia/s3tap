//! End-to-end test of `s3tap analyze`, the one pure consumer that had no e2e coverage at
//! all — so nothing pinned the repo rule it exists to encode:
//!
//! > `--strict` gates the exit code on `doctor`, `advise` and `scorecard` only. `analyze`
//! > has no `--strict`, so a "no-go" is an answer rather than a failure and still exits 0.
//! > It is NOT always 0 though: a file it cannot read at all is 4, and a capture it read
//! > with no demand read in it is 2 — the same nothing-judgeable code its sibling consumers
//! > return for the same shape. Its answer is a cache-suitability verdict, so
//! > "DON'T CACHE" is a legitimate finding about the workload rather than a failure of it.
//!
//! That rule is enforced by the ABSENCE of a flag and by a hardcoded `Ok(0)`, which is
//! exactly the kind of thing a well-meaning "make it consistent with its siblings" change
//! removes. Both halves are pinned here.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_s3tap");

fn fixture() -> String {
    format!("{}/tests/fixtures/advisor_sample.jsonl", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn analyze_renders_both_forms_and_always_exits_zero() {
    for extra in [&[][..], &["--json"][..]] {
        let out = Command::new(BIN)
            .args(["analyze", "--from", &fixture()])
            .args(extra)
            .output()
            .expect("run s3tap analyze");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "analyze {extra:?} must exit 0\n{stderr}");
        let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
        assert!(!stdout.is_empty(), "analyze {extra:?} produced no report");
        if extra.is_empty() {
            // The human render is a report, not an empty shell: it names the verdict it
            // was asked for. (Which verdict is the advisor's business, not the CLI's.)
            assert!(
                stdout.to_ascii_uppercase().contains("CACHE"),
                "the human render must state a cache verdict:\n{stdout}"
            );
        } else {
            // --json is machine output: one parseable object, nothing else on the stream.
            let v: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("analyze --json emits one JSON object");
            assert!(v.is_object(), "expected a report object, got {v}");
        }
        // The exit code must not be a hidden gate in either direction.
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
}

#[test]
fn analyze_has_no_strict_flag() {
    // The load-bearing half: `--strict` must be REJECTED BY CLAP (usage error, exit 2),
    // not accepted-and-ignored and not honored. A CI job that wants a gate on this
    // question runs `advise --strict`, which judges it as a finding.
    let out = Command::new(BIN)
        .args(["analyze", "--from", &fixture(), "--strict"])
        .output()
        .expect("run s3tap analyze --strict");
    assert_eq!(
        out.status.code(),
        Some(2),
        "analyze must reject --strict as a usage error; got {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--strict"),
        "the usage error must name the offending flag:\n{stderr}"
    );
}
