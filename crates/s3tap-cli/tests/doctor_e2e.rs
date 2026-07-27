//! End-to-end guard for the committed doctor demo capture — `doctor_sample.jsonl`, the
//! fixture the README hero GIF (assets/readme/doctor.tape) is generated from. A schema change
//! (which must bump the schema + regenerate goldens) would otherwise
//! invalidate this capture silently, surfacing only when the GIF is next regenerated —
//! after a broken hero already shipped. This pins the two things the demo depends on:
//! every record still parses, and the `connection/2` line still yields the RTT floor
//! doctor judges every span against.
//!
//! Linux-only in practice: the s3tap binary (aya/eBPF) does not build on macOS, so this
//! runs where the binary does — same as `scorecard_e2e.rs` / `advise_e2e.rs`.

use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn doctor_demo_capture_parses_and_keeps_its_rtt_floor() {
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["doctor", "--from", &fixture("doctor_sample.jsonl"), "--json"])
        .output()
        .expect("run s3tap doctor");
    // No assertion on the exit code: the capture trips the HTTP-errors envelope (10x 403),
    // so doctor deliberately exits non-zero. The JSON is still emitted before it exits.

    // Every record in the demo capture MUST parse. doctor emits a `note: skipped N
    // unparseable …` line to stderr when it can't; seeing it here means schema drift has
    // broken the fixture the GIF is built from.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("skipped") && !stderr.contains("unparseable"),
        "doctor skipped record(s) in the demo capture — schema drift?\n{stderr}"
    );

    // The `connection/2` record must still produce the RTT floor. Without it doctor renders
    // 'NO BASELINE' and the whole 'each span vs the round-trip floor' story collapses — a
    // silently useless demo. Assert the floor finding is present and well-formed.
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let baseline = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("each --json line is a finding/1"))
        .find(|v| v["finding_id"] == "baseline_rtt")
        .expect("a baseline_rtt finding (the connection/2 RTT floor)");
    assert_eq!(baseline["schema"], "s3tap.finding/1");
    assert_eq!(baseline["verdict"], "floor");

    // The floor's sample is the population that SUPPLIED the floor, not the op split.
    // Reporting the op counts here told a fleet gate normalizing on sample.judged that 90
    // records backed a floor drawn from one.
    //
    // `excluded` is 0 and not 100: an excluded count is a claim that the record COULD have
    // contributed and did not, and an operation never carries a close-time srtt (the schema
    // pins the field null on every op s3tap emits). So the candidate pool here is the one
    // connection, which supplied the floor, and nothing was passed over.
    assert_eq!(baseline["sample"]["judged"], 1, "one connection supplied the RTT floor");
    assert_eq!(baseline["sample"]["excluded"], 0, "an op is not a floor candidate");

    // Pin the capture's shape (1 connection + 100 ops: 90 judged, 10 excluded 4xx) on a
    // finding whose population IS the timed ops, so an edit to the fixture is a conscious
    // decision, not an accident that dulls the demo.
    let finding = |id: &str| {
        stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).expect("each --json line is a finding/1")
            })
            .find(|v| v["finding_id"] == id)
            .unwrap_or_else(|| panic!("a {id} finding"))
    };
    let ttfb = finding("ttfb_reused");
    assert_eq!(ttfb["sample"]["judged"], 90);
    // `excluded` counts CANDIDATES THAT WERE DROPPED, not "every other op in the capture".
    // Here the two happen to coincide at 10 and the distinction still matters: all 100 ops are
    // on reused connections and all carry a TTFB, so all 100 are candidates for this row, and
    // the 10 the eligibility gate drops are 403s. Read as "100 - 90" the number would be right
    // by accident; read as "10 candidates dropped" it is right by construction, and it is the
    // reading that makes judged/(judged+excluded) a real coverage figure.
    assert_eq!(ttfb["sample"]["excluded"], 10, "the 10 dropped candidates are the 403s");

    // Reuse is deliberately NOT that population: `connection_reused` is present on every op,
    // so the rate counts all 100 and excludes none. This pin used to ride on `reuse_rate`,
    // which made the two facts indistinguishable — if reuse ever silently reverted to the
    // latency subset, the 90/10 pin above would have gone on passing.
    let reuse = finding("reuse_rate");
    assert_eq!(reuse["sample"]["judged"], 100, "every op carries connection_reused");
    assert_eq!(reuse["sample"]["excluded"], 0);
}

#[test]
fn cost_over_a_connection_only_capture_says_unknown_rather_than_zero() {
    // `conns_only.jsonl` is a capture with no operation record: the shape a Go or rustls
    // client produces, and the shape any capture taken without the uprobe caps produces.
    // `--cost` used to render "requests: $0.000000   data returned: 0.000 GiB" over it. Every
    // other figure in that table is a measurement, so a zero there reads as one: the operator
    // is told their capture cost nothing when what actually happened is that the request
    // stream was never decoded. The verdict path already refuses this exact shape (NO
    // OPERATIONS, exit 2); the cost path has to make the same refusal in its own words,
    // because `--cost` replaces the body and deliberately keeps exit 0.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["doctor", "--from", &fixture("conns_only.jsonl"), "--cost", "--no-color"])
        .output()
        .expect("run s3tap doctor --cost");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");

    // Informational by contract: --cost never gates, so the honesty has to live in the text.
    assert_eq!(out.status.code(), Some(0), "--cost stays informational\n{stdout}");
    assert!(stdout.contains("request cost is unknown"), "{stdout}");
    // The zero total must be GONE, not merely annotated. A caveat under a $0.000000 line
    // still leaves the number there to be copied into a capacity plan or a ticket.
    assert!(!stdout.contains("requests: $"), "no priced total over zero operations:\n{stdout}");
    assert!(!stdout.contains("0.000 GiB"), "no measured-looking byte total:\n{stdout}");
    // And it names the remedy, which is the same one NO OPERATIONS gives.
    assert!(stdout.contains("--capture-plaintext"), "{stdout}");

    // The other half: a capture that DID decode operations still gets its table, so the guard
    // above cannot be silently swallowing the normal path.
    let out = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args(["doctor", "--from", &fixture("doctor_sample.jsonl"), "--cost", "--no-color"])
        .output()
        .expect("run s3tap doctor --cost");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("requests: $"), "a real capture still prices its requests:\n{stdout}");
    assert!(!stdout.contains("unknown"), "{stdout}");
}
