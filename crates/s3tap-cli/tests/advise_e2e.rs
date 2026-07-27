//! End-to-end test of `s3tap advise` over a static JSONL fixture (generated
//! from the real serializers by s3tap-advisor's `regenerate_cli_fixture`).
//! Linux-only in practice: the s3tap binary (aya/eBPF) does not build on
//! macOS, so this compiles and runs where the binary does.

use std::process::Command;

fn fixture() -> String {
    format!("{}/tests/fixtures/advisor_sample.jsonl", env!("CARGO_MANIFEST_DIR"))
}

fn demo_fixture() -> String {
    format!("{}/tests/fixtures/advise_demo.jsonl", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn advise_demo_capture_fires_its_three_showcase_findings() {
    // advise_demo.jsonl is the capture the advisor README GIF is built from: a naive pipeline
    // that should trip churn + serial + refetch. If a check or the fixture drifts and one stops
    // firing, the GIF silently loses a finding, so pin all three here.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["advise", "--from", &demo_fixture(), "--json"])
        .output()
        .expect("run s3tap advise");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let ids: Vec<String> = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["finding_id"].as_str().map(String::from))
        .collect();
    for want in ["advisor-connection-churn", "advisor-serial-requests", "advisor-redundant-refetch"] {
        assert!(ids.iter().any(|id| id == want), "demo fixture no longer fires {want}; got {ids:?}");
    }
}

#[test]
fn advise_json_emits_findings_and_exits_zero() {
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["advise", "--from", &fixture(), "--json"])
        .output()
        .expect("run s3tap advise");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "exit: {:?}\n{stderr}", out.status);

    // The INPUT must have been fully understood. Without this, a schema rename that made 99
    // of the fixture's 100 lines unparseable would keep every assertion below green while
    // advise silently judged a one-operation capture — the failure this fixture exists to
    // catch, reported only on stderr. `advise` prints the skip counts there and nowhere else.
    assert!(
        !stderr.contains("skipped"),
        "advise skipped input lines, so it judged less than the fixture:\n{stderr}"
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let findings: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("every stdout line is a finding object"))
        .collect();
    assert!(!findings.is_empty(), "at least one finding line");
    for f in &findings {
        assert_eq!(f["schema"], "s3tap.finding/1");
        assert!(f["finding_id"].as_str().unwrap().starts_with("advisor-"));
    }
    // Pin the SET, not just the prefix of the first line. A check that stops firing, or a
    // new one that starts, is a change in what this capture is judged to be — a decision to
    // make deliberately (and to re-pin here), not a silent drift.
    let ids: Vec<&str> = findings.iter().map(|f| f["finding_id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["advisor-connection-churn"], "the fixture's finding set changed");
}

#[test]
fn advise_streams_stdin_and_bounds_a_pathological_line() {
    // The pure consumers read their input as a STREAM (no whole-file String), so this
    // covers both halves of that: the documented `s3tap --format jsonl | s3tap advise`
    // pipe composition, and the per-line bound — a single absurd 4 MiB line is skipped
    // and REPORTED rather than buffered, with every record around it still judged.
    use std::io::Write;
    use std::process::Stdio;
    let mut input = std::fs::read_to_string(fixture()).expect("read fixture");
    input.push_str(&"x".repeat(4 * 1024 * 1024));
    input.push('\n');
    let mut child = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["advise", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn s3tap advise");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("feed stdin");
    let out = child.wait_with_output().expect("wait for s3tap advise");
    assert!(out.status.success(), "exit: {:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipped 1 unparseable"),
        "the over-long line must be counted, never hidden; stderr: {stderr}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.lines().any(|l| l.contains("s3tap.finding/1")),
        "findings must still be emitted around the skipped line"
    );
}

#[test]
fn advise_strict_gates_on_advisories() {
    // The churny fixture fires Advisory findings, so --strict must exit 1.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["advise", "--from", &fixture(), "--json", "--strict"])
        .output()
        .expect("run s3tap advise --strict");
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
}
