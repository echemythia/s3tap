//! The exit-code split: 0/1/2/3 are VERDICTS about the capture, and everything that stops
//! s3tap from producing a verdict at all is a separate, reserved code.
//!
//! Before this, anyhow's `Termination` exited 1 for every error, which is also ATTENTION.
//! So `s3tap doctor --from typo.jsonl` failed a CI gate identically to a capture with a
//! retransmit warning, and no script could tell "the workload regressed" from "the command
//! was wrong". Only a real process shows the mapping: the exit code is chosen in `main`,
//! below every function a unit test can call.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_s3tap");

/// Kept in step with `EXIT_TOOL_FAILURE` in main.rs. Deliberately restated rather than
/// imported: this test exists to pin the number a script sees, so it must fail if the
/// constant moves, not silently follow it.
const EXIT_TOOL_FAILURE: i32 = 4;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(BIN).args(args).output().unwrap_or_else(|e| panic!("run {args:?}: {e}"));
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_broken_invocation_exits_on_the_tool_failure_code_not_a_verdict_code() {
    // Each of these is s3tap being unable to answer, never an answer about a workload.
    let missing = format!("{}/no-such-capture.jsonl", std::env::temp_dir().display());
    let capture = fixture("doctor_sample.jsonl");
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["doctor", "--from", &missing], "an unreadable --from path"),
        (vec!["advise", "--from", &missing], "an unreadable --from path"),
        (vec!["scorecard", "--from", &missing], "an unreadable --from path"),
        (vec!["analyze", "--from", &missing], "an unreadable --from path"),
        (
            vec!["doctor", "--from", &capture, "--baseline", &missing],
            "an unreadable --baseline path",
        ),
    ];
    for (args, what) in cases {
        let (code, stderr) = run(&args);
        assert_eq!(
            code,
            Some(EXIT_TOOL_FAILURE),
            "{what} ({args:?}) exited {code:?}, want the reserved tool-failure code\n{stderr}"
        );
        // The error still has to be REPORTED, not just coded: a silent exit 4 would be a
        // worse contract than the exit 1 it replaces.
        assert!(!stderr.trim().is_empty(), "{what} exited {code:?} with nothing on stderr");
    }
}

#[test]
fn wrong_input_is_a_tool_failure_and_never_a_clean_gate_pass() {
    // The zero-record guard. `advise --strict` over a file that is not a capture must not
    // print "nothing to flag" and exit 0: a gate that cannot tell "clean" from "no data" is
    // not a gate. It must also not exit 1, which would read as a real advisory.
    let dir = std::env::temp_dir().join(format!("s3tap_exit_codes_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let empty = dir.join("empty.jsonl");
    std::fs::write(&empty, "").expect("write empty");
    let not_a_capture = dir.join("findings.jsonl");
    // A `doctor --json` findings file: the exact wrong-file mistake the guard was written for.
    std::fs::write(&not_a_capture, "{\"schema\":\"s3tap.finding/1\",\"finding_id\":\"x\"}\n")
        .expect("write findings");

    for path in [&empty, &not_a_capture] {
        for cmd in ["doctor", "advise", "scorecard"] {
            let p = path.display().to_string();
            let (code, stderr) = run(&[cmd, "--from", &p, "--strict"]);
            assert_eq!(
                code,
                Some(EXIT_TOOL_FAILURE),
                "{cmd} --from {p} exited {code:?}, want the tool-failure code\n{stderr}"
            );
            assert!(
                stderr.contains("no s3tap records"),
                "{cmd} must say the input held no records, not report a verdict:\n{stderr}"
            );
        }
    }
    let _ = std::fs::remove_file(&empty);
    let _ = std::fs::remove_file(&not_a_capture);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn an_empty_baseline_is_refused_and_names_the_baseline() {
    // The zero-record guard on the OTHER input. A `--live --save` killed by a signal used to
    // leave an empty file behind, and an empty baseline is not a lenient comparison but no
    // comparison: every metric is absent on the reference side, so the diff finds no
    // regression and a gate built on `--baseline` reads green against a file that was never
    // a capture. Only the real binary proves the guard is wired into the exit code.
    let dir = std::env::temp_dir().join(format!("s3tap_empty_baseline_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let empty = dir.join("baseline.jsonl");
    std::fs::write(&empty, "").expect("write empty");
    let empty = empty.display().to_string();
    let capture = fixture("doctor_sample.jsonl");
    let (code, stderr) = run(&["doctor", "--from", &capture, "--baseline", &empty, "--strict"]);
    assert_eq!(code, Some(EXIT_TOOL_FAILURE), "an empty baseline is a tool failure\n{stderr}");
    // The message has to name the BASELINE. The consumer's usual wording would send the
    // operator off checking their main input, which is fine.
    assert!(stderr.contains("no s3tap records"), "{stderr}");
    assert!(stderr.contains("baseline"), "the message must name the baseline input\n{stderr}");
    let _ = std::fs::remove_file(&empty);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn a_capture_with_no_operations_does_not_read_green() {
    // A connection-only capture: a Go/rustls client (no OpenSSL symbols to hook), or any
    // capture taken without the uprobe caps. The network rows can all be ✓ and that says
    // NOTHING about S3, so this must not exit 0. It used to, while the same run's --json
    // published the run finding as "severity":"unjudged" and its own table said "0
    // operations in this capture" — a green a script had no way to distrust.
    let conns_only = fixture("conns_only.jsonl");
    for extra in [vec![], vec!["--strict"]] {
        let mut args = vec!["doctor", "--from", &conns_only, "--no-color"];
        args.extend(extra.iter().copied());
        let out = Command::new(BIN).args(&args).output().expect("run doctor");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} must exit 2 (nothing judgeable), like NO BASELINE\n{stdout}"
        );
        // The human render, the exit code and the machine severity must agree.
        assert!(stdout.contains("NO OPERATIONS"), "{stdout}");
        assert!(stdout.contains("0 operations in this capture"), "{stdout}");
    }
    let out = Command::new(BIN)
        .args(["doctor", "--from", &conns_only, "--json"])
        .output()
        .expect("run doctor --json");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("\"severity\":\"unjudged\""), "the run finding stays unjudged\n{stdout}");
    // Still a VERDICT and never the tool-failure code: the input WAS a capture and WAS read.
    assert_eq!(out.status.code(), Some(2), "{stdout}");
}

#[test]
fn a_real_capture_still_exits_on_its_verdict_code() {
    // The other half of the split, and the one that would make the change above worthless if
    // it broke: a capture that WAS judged keeps returning its verdict. The demo fixture trips
    // the HTTP-errors envelope (10x 403), so it is a genuine ATTENTION.
    let (code, stderr) = run(&["doctor", "--from", &fixture("doctor_sample.jsonl"), "--no-color"]);
    assert_eq!(code, Some(1), "a judged capture keeps its verdict code\n{stderr}");
    // And a clean advisory run over a real capture is still 0 without --strict.
    let (code, stderr) = run(&["advise", "--from", &fixture("advisor_sample.jsonl"), "--no-color"]);
    assert_eq!(code, Some(0), "advice is not a failure without --strict\n{stderr}");
    // Whatever a verdict is, it is never the tool-failure code.
    for cmd in [
        vec!["doctor", "--from", &fixture("doctor_sample.jsonl")],
        vec!["scorecard", "--from", &fixture("scorecard_sample.jsonl"), "--strict"],
        vec!["analyze", "--from", &fixture("advisor_sample.jsonl"), "--fast"],
    ] {
        let (code, stderr) = run(&cmd);
        assert!(
            matches!(code, Some(0..=3)),
            "{cmd:?} exited {code:?}: a judged run must stay on a verdict code\n{stderr}"
        );
    }
}

#[test]
fn a_usage_error_never_reads_as_a_verdict() {
    // clap's own rejections keep clap's exit 2... which collides with NO BASELINE. That is
    // fine and deliberate: clap writes a usage block to stderr and produces no report, so no
    // consumer can mistake it for a judgment. What must NOT happen is s3tap's own validation
    // landing on a verdict code, so the flags it rejects itself are checked here.
    // --no-elevate so the test never reaches a sudo prompt: `--live` loads eBPF, and without
    // it a CI box lacking the caps would sit on a password prompt instead of failing.
    //
    // Each case asserts the MESSAGE as well as the code, and that is the point rather than
    // belt-and-braces. `--live` also loads eBPF, which fails on a runner with no caps and
    // ALSO yields 4, so a code-only assertion passes just as happily when the validation
    // never ran. Only the wording tells the two apart.
    let (code, stderr) = run(&[
        "doctor", "--live", "--no-elevate", "--endpoint", "https://example.invalid",
        "--timeout-secs", "0",
    ]);
    assert_eq!(code, Some(EXIT_TOOL_FAILURE), "a rejected --timeout-secs is a tool failure\n{stderr}");
    assert!(
        stderr.contains("--timeout-secs must be between 1 and 3600"),
        "exit 4 here must come from the --timeout-secs check, not from the eBPF load\n{stderr}"
    );
    let (code, stderr) = run(&["check", "--requests", "0"]);
    assert_eq!(code, Some(EXIT_TOOL_FAILURE), "a rejected --requests is a tool failure\n{stderr}");
    assert!(
        stderr.contains("--requests must be between 1 and"),
        "exit 4 here must come from the --requests check\n{stderr}"
    );
    // ...and it is rejected BEFORE the ~20 s regional sweep prints anything.
    assert!(
        !stderr.contains("regional S3 round-trip probe"),
        "check --requests 0 must fail before the sweep runs:\n{stderr}"
    );
}

#[test]
fn json_mode_explains_a_missing_denominator_instead_of_writing_nothing() {
    // Both consumers exited 2 over an unjudgeable capture while writing an EMPTY NDJSON
    // stream. That is scriptable by exit code but not self-describing: an ingest that stores
    // findings kept no record of why the run produced nothing, and could not tell this from
    // any other empty result. `doctor --json` has always published a run roll-up for the
    // equivalent state, so the two rails disagreed about the same class of capture.
    //
    // Both missing-denominator causes are covered, because they need different fixes:
    //   conns_only.jsonl     -> no operation record at all (uprobe caps)
    //   unanswered_ops.jsonl -> operations decoded, not one answered (capture ended mid-flight)
    let cases = [
        (fixture("conns_only.jsonl"), "advisor-run", "scorecard-run", "0 operations", "no operations"),
        (fixture("unanswered_ops.jsonl"), "advisor-run", "scorecard-run", "not one was answered", "none carried an HTTP status"),
    ];
    for (capture, adv_id, sc_id, adv_msg, sc_msg) in cases {
        for (cmd, id, msg) in
            [("advise", adv_id, adv_msg), ("scorecard", sc_id, sc_msg)]
        {
            let out = Command::new(BIN)
                .args([cmd, "--from", &capture, "--json"])
                .output()
                .unwrap_or_else(|e| panic!("run {cmd}: {e}"));
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            assert_eq!(out.status.code(), Some(2), "{cmd} over {capture}\n{stdout}");
            assert!(!stdout.trim().is_empty(), "{cmd} --json must not write an empty stream");
            // Every line is a well-formed finding, and the run row is present and unjudged.
            let rows: Vec<serde_json::Value> = stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).expect("each --json line parses"))
                .collect();
            let run = rows
                .iter()
                .find(|v| v["finding_id"] == id)
                .unwrap_or_else(|| panic!("{cmd} must emit a {id} row:\n{stdout}"));
            assert_eq!(run["severity"], "unjudged", "{stdout}");
            assert_eq!(run["domain"], "run", "{stdout}");
            // It names WHICH missing denominator, so the two causes stay distinguishable on
            // the machine rail exactly as they are in the human render.
            assert!(
                run["summary"].as_str().is_some_and(|s| s.contains(msg)),
                "{cmd} run row must name the cause ({msg}):\n{stdout}"
            );
        }
    }

    // The other half: a capture that WAS judged gets no run row, so a consumer seeing none
    // can read that as "the population was fine" rather than "the feature is missing".
    for (cmd, capture, id) in [
        ("advise", fixture("advisor_sample.jsonl"), "advisor-run"),
        ("scorecard", fixture("scorecard_sample.jsonl"), "scorecard-run"),
    ] {
        let out = Command::new(BIN).args([cmd, "--from", &capture, "--json"]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(!stdout.contains(id), "{cmd} must not emit {id} for a judged capture:\n{stdout}");
    }
}

#[test]
fn advisory_findings_name_only_the_stream_they_came_from() {
    // Every advisory used to publish both `s3tap.operation/1` and `s3tap.connection/2`
    // regardless of what it read, so a machine consumer could not tell which half of a
    // capture a finding rested on. Each check reads exactly one of the two.
    let out = Command::new(BIN)
        .args(["advise", "--from", &fixture("advisor_sample.jsonl"), "--json"])
        .output()
        .expect("run advise --json");
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each --json line parses"))
        .collect();
    assert!(!rows.is_empty(), "the fixture must raise advisories for this to prove anything");
    check_sources(&rows);
    // That fixture is operation-only, so it can only ever exercise the Ops branch. The
    // connection-derived half needs a capture that fires an `advisor-latency-*` finding,
    // or `Src::Conns` would be asserted nowhere outside the builder's own unit test.
    let out = Command::new(BIN)
        .args(["advise", "--from", &fixture("crossregion_conns.jsonl"), "--json"])
        .output()
        .expect("run advise --json");
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each --json line parses"))
        .collect();
    assert!(
        rows.iter().any(|r| r["finding_id"].as_str().is_some_and(|i| i.starts_with("advisor-latency-"))),
        "the cross-region fixture must raise a connection-derived finding:\n{rows:#?}"
    );
    check_sources(&rows);
}

/// Every finding names exactly ONE record stream, and it is the one the check actually reads.
fn check_sources(rows: &[serde_json::Value]) {
    for r in rows {
        let id = r["finding_id"].as_str().unwrap_or_default();
        let src = r["source_schema"].as_array().expect("source_schema is an array");
        assert_eq!(src.len(), 1, "{id} must name exactly one stream: {src:?}");
        let want = if id.starts_with("advisor-latency-") {
            "s3tap.connection/2" // the path findings are built from connection records
        } else {
            "s3tap.operation/1"
        };
        assert_eq!(src[0], want, "{id} names the wrong stream");
    }
}

#[test]
fn reuse_rate_counts_every_op_not_just_the_latency_eligible_ones() {
    // `connection_reused` is present on EVERY operation record. Judging the rate over the
    // latency-eligible subset (non-partial, status < 400, non-ambiguous) threw away ops that
    // are perfectly good evidence of reuse, and the row did not merely skew — it stated a
    // falsehood and took the run to ATTENTION on its own.
    //
    // The fixture: 26 ops, 21 of them on a reused connection (81%, comfortably healthy). The
    // 21 are `ambiguous` — a second request raced the response — so `is_eligible` drops them
    // from the LATENCY population while `connection_reused` stays trustworthy. Deliberately
    // not `partial`: the schema says that field cannot be attributed on a partial op, so
    // those are excluded from this rate too. And deliberately not 4xx, so no HTTP-errors row
    // can mask the result: reuse is the only row that can warn here.
    let out = Command::new(BIN)
        .args(["doctor", "--from", &fixture("reuse_partial_ops.jsonl"), "--no-color"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("21/26 ops reused a connection"), "the real population:\n{stdout}");
    assert!(!stdout.contains("⚠"), "nothing here is outside its envelope:\n{stdout}");
    assert_eq!(out.status.code(), Some(0), "a healthy capture must not gate CI\n{stdout}");

    // The machine rail publishes the population it actually counted, so `value` and
    // `sample.judged` describe the same set. Publishing `op_judged` here would hand a
    // consumer a denominator the ratio was never taken over.
    let out = Command::new(BIN)
        .args(["doctor", "--from", &fixture("reuse_partial_ops.jsonl"), "--json"])
        .output()
        .expect("run doctor --json");
    let f: serde_json::Value = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("a finding per line"))
        .find(|v| v["finding_id"] == "reuse_rate")
        .expect("a reuse_rate finding");
    assert_eq!(f["sample"]["judged"], 26, "every op is in the population");
    assert_eq!(f["sample"]["excluded"], 0);
    let ratio = f["value"].as_f64().expect("a ratio");
    assert!((ratio - 21.0 / 26.0).abs() < 1e-9, "value must match the printed row: {ratio}");
}

#[test]
fn the_tail_judges_each_op_against_its_own_floor_not_a_pooled_blend() {
    // Two regions, every op healthy against ITS OWN round-trip floor:
    //   4 near connections x 8 ops: 3.5 ms over a 1 ms floor  -> 3.5x
    //   1 far connection   x 5 ops: 80 ms  over a 70 ms floor -> 1.14x
    //
    // Judged against the POOLED floor the p95 lands on a far op (80 ms) and is divided by the
    // near-region median (1 ms), reporting `p95 = 80.0×RTT ⚠` for a request that is 1.14x its
    // own floor — the multi-region blend this project forbids, and it took the verdict while
    // the per-op-class row over the same ops said `✓ expected`. Reuse is 86% and every status
    // is 200, so the tail is the only row that can warn.
    let out = Command::new(BIN)
        .args(["doctor", "--from", &fixture("multiregion_tail.jsonl"), "--no-color"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!stdout.contains("⚠"), "every op is healthy against its own floor:\n{stdout}");
    assert_eq!(out.status.code(), Some(0), "a healthy capture must not gate CI\n{stdout}");
    // The two rows that judge the same ops must agree rather than contradict each other.
    assert!(stdout.contains("TTFB p95, reused conn"), "the p95 row must be emitted:\n{stdout}");
    // The JUDGED number is the p95 of ×RTT, ranked over ratios — 3.5×, the near-region ops —
    // not the p95 of raw latency, which is the 80 ms far-region op at 1.14x its own floor.
    assert!(
        stdout.contains("p95 of ×RTT = 3.5×"),
        "the verdict must be ranked by ratio, not by raw latency:\n{stdout}"
    );
    // And the row's VALUE column is the latency percentile — 80 ms, the far-region op — so the
    // two numbers sit side by side and neither is inferable from the other.
    let p95_row = stdout
        .lines()
        .find(|l| l.contains("TTFB p95, reused conn"))
        .expect("the p95 row");
    assert!(p95_row.contains("80.0 ms"), "the value column is the latency p95: {p95_row}");
    assert!(p95_row.contains("3.5×"), "and the note carries the judged ratio: {p95_row}");
    let out = Command::new(BIN)
        .args(["doctor", "--from", &fixture("multiregion_tail.jsonl"), "--json"])
        .output()
        .expect("run doctor --json");
    let f: serde_json::Value = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("a finding per line"))
        .find(|v| v["finding_id"] == "ttfb_reused_p95")
        .expect("a ttfb_reused_p95 finding");
    let value = f["value"].as_f64().expect("value");
    let ratio = f["ratio_to_rtt"].as_f64().expect("ratio");
    // `value` is a LATENCY percentile and `ratio_to_rtt` is a RATIO percentile, taken over
    // different orderings, so they need not name the same op and `value / baseline` is NOT
    // the ratio. This capture is the clearest case: 80 ms is the far-region op, 3.5× is a
    // near-region one. Publishing the ratio-ranked op's TTFB as `value` used to make the
    // quotient hold exactly, which read like a guarantee but silently changed what `value`
    // MEANT whenever floors were present — the same series meant a ratio-ranked latency on
    // one run and a plain p95 on the next.
    assert!((value - 80.0).abs() < 1e-9, "value is the p95 of TTFB: {value}");
    assert!((ratio - 3.5).abs() < 1e-9, "ratio is the p95 of ×RTT: {ratio}");
    // And NO denominator is published. This assertion replaced one that pinned the DIVERGENCE
    // of `value / baseline_rtt_us` from `ratio_to_rtt` as desired behaviour — which was the
    // wrong conclusion: two order statistics over different orderings have no common floor, so
    // any denominator here reconstructs a wrong answer. On this very fixture the published
    // median floor made `value / baseline` read 80× on a ✓ row gated at `<= 8.0×RTT`. Absent
    // is the only honest value; a consumer has `value`, `ratio_to_rtt` and the threshold.
    assert!(
        f["baseline_rtt_us"].is_null(),
        "a per-op-ranked row must publish no pooled denominator: {}",
        f["baseline_rtt_us"]
    );
}

#[test]
fn a_capture_spanning_two_paths_exits_2_rather_than_reading_green() {
    // A pooled floor across a 1 ms path and a 200 ms path fits neither, so it is withheld and
    // nothing is judged against it. The run must NOT read green: keyed on `rtt_ms` (which is
    // still Some) rather than on what was actually judged, this printed "HEALTHY — latencies
    // track the round-trip floor" beneath three rows all reading "not judged", at exit 0.
    let out = Command::new(BIN)
        .args(["doctor", "--from", &fixture("mixed_paths.jsonl"), "--no-color"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("MIXED PATHS"), "the verdict must name the reason:\n{stdout}");
    assert!(
        !stdout.contains("HEALTHY"),
        "a run that judged nothing must not read green:\n{stdout}"
    );
    assert_eq!(out.status.code(), Some(2), "and it maps to the nothing-judgeable code\n{stdout}");

    // The pooled floor is still REPORTED — withholding it must not delete the row that says
    // what was measured and why it is not a denominator.
    assert!(stdout.contains("NOT used as a floor"), "the baseline row explains itself:\n{stdout}");

    // On the machine rail the roll-up is `unjudged`, not `healthy`, so a fleet gate keying on
    // severity sees the same thing the exit code says.
    let out = Command::new(BIN)
        .args(["doctor", "--from", &fixture("mixed_paths.jsonl"), "--json"])
        .output()
        .expect("run doctor --json");
    let run: serde_json::Value = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("a finding per line"))
        .find(|v| v["finding_id"] == "run")
        .expect("a run finding");
    assert_eq!(run["severity"], "unjudged", "{run}");
}
