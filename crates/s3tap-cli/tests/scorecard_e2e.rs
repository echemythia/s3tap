//! End-to-end test of `s3tap scorecard` over static JSONL fixtures. Mirrors
//! `advise_e2e.rs`: exercises the CLI plumbing (arg wiring, the two-rail JSON
//! ordering — `scorecard/1` rows THEN `finding/1` records — and the exit code)
//! that the module's unit tests can't reach. Linux-only in practice: the s3tap
//! binary (aya/eBPF) does not build on macOS, so this runs where the binary does.

use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn scorecard_json_emits_rows_then_findings_and_exits_zero() {
    // The fixture has 90x200 + 10x403 GetObject on one bucket: one scorecard/1 row
    // followed by the gated scorecard-error-403 finding.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["scorecard", "--from", &fixture("scorecard_sample.jsonl"), "--json"])
        .output()
        .expect("run s3tap scorecard");
    assert!(out.status.success(), "exit: {:?}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    // Rail 1: the descriptive row comes first.
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("a row line");
    assert_eq!(first["schema"], "s3tap.scorecard/1");
    assert_eq!(first["bucket"], "assets");
    assert_eq!(first["ops"], 100);

    // Rail 2: a finding/1 with a scorecard id appears, after all rows.
    let first_finding = lines.iter().position(|l| l.contains(r#""schema":"s3tap.finding/1""#));
    let last_row = lines.iter().rposition(|l| l.contains(r#""schema":"s3tap.scorecard/1""#));
    let (first_finding, last_row) = (first_finding.expect("a finding line"), last_row.unwrap());
    assert!(last_row < first_finding, "all scorecard/1 rows must precede the finding/1 records");
    let f: serde_json::Value = serde_json::from_str(lines[first_finding]).unwrap();
    assert!(f["finding_id"].as_str().unwrap().starts_with("scorecard-"));
}

#[test]
fn scorecard_strict_gates_on_a_reliability_finding() {
    // The 403 fixture trips scorecard-error-403 (Warn), so --strict must exit 1.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["scorecard", "--from", &fixture("scorecard_sample.jsonl"), "--strict"])
        .output()
        .expect("run s3tap scorecard --strict");
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn scorecard_without_strict_is_a_report_not_a_failure() {
    // Same fixture, no --strict: a scorecard is a report, so exit 0 even with a finding.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["scorecard", "--from", &fixture("scorecard_sample.jsonl")])
        .output()
        .expect("run s3tap scorecard");
    assert!(out.status.success(), "a report must not fail by default: {:?}", out.status);
}
