// Parity tests: the Rust doctor must agree with demo/s3stats.py (the reference
// oracle) on the per-check ⚠ marks and the run-level verdict, for the same
// input. Compared by mark + verdict keyword (robust to formatting), not byte-for-byte.
//
// Shells out to `python3 demo/s3stats.py`; skips (passes) if python3 is unavailable.

use std::io::Write;
use std::process::{Command, Stdio};

use s3tap_doctor::{analyze, Mark, Record};
use s3tap_schema::{Connection, Delimitation, Dns, Operation, TcpSample};

mod common;
use common::running_in_ci;

const LABELS: &[&str] = &[
    "baseline RTT (srtt)",
    "DNS, cold resolve",
    "TCP connect",
    "TTFB, new conn",
    "TTFB, reused conn",
    "retransmit rate",
    "HTTP errors",
];

fn op(ttfb_ms: u64, tcp_ms: u64, reused: bool, status: u16, partial: bool) -> Record {
    Record::Operation(Operation {
        http_status: Some(status),
        partial,
        connection_reused: reused,
        ttfb_ns: Some(ttfb_ms * 1_000_000),
        tcp_connect_ns: Some(tcp_ms * 1_000_000),
        ..Default::default()
    })
}
// An op carrying a DNS block — the cold-resolve metric is read from OPERATIONS, not
// connections (both impls iterate ops), so DNS coverage must live on an op.
fn op_dns(ttfb_ms: u64, tcp_ms: u64, status: u16, dns_ms: u64, cache_hit: bool) -> Record {
    Record::Operation(Operation {
        http_status: Some(status),
        partial: false,
        connection_reused: false,
        ttfb_ns: Some(ttfb_ms * 1_000_000),
        tcp_connect_ns: Some(tcp_ms * 1_000_000),
        dns: Some(Dns {
            latency_ns: dns_ms * 1_000_000,
            cache_hit,
            resolved_ip: None,
            n_answers: 1,
            ttl_s: None,
            via: "wire".into(),
        }),
        ..Default::default()
    })
}
// A PARTIAL op carrying a (slow) cold resolve — both impls must drop it from the DNS-cold
// median (the eligibility gate applies to DNS too), so its timing never reaches a median.
fn op_dns_partial(dns_ms: u64) -> Record {
    Record::Operation(Operation {
        http_status: Some(200),
        partial: true,
        connection_reused: false,
        ttfb_ns: Some(30 * 1_000_000),
        tcp_connect_ns: Some(17 * 1_000_000),
        dns: Some(Dns {
            latency_ns: dns_ms * 1_000_000,
            cache_hit: false,
            resolved_ip: None,
            n_answers: 1,
            ttl_s: None,
            via: "wire".into(),
        }),
        ..Default::default()
    })
}
fn conn(srtt_us: Option<u32>, retransmits: u32, bytes_sent: u64) -> Record {
    Record::Connection(Connection { srtt_us, retransmits, bytes_sent, ..Default::default() })
}
// A delimitation:ambiguous op (a 2nd request raced the response) — both impls must drop
// it from latency stats, so its wild timing never reaches a median.
fn op_ambiguous(ttfb_ms: u64, tcp_ms: u64, status: u16) -> Record {
    Record::Operation(Operation {
        http_status: Some(status),
        partial: false,
        connection_reused: false,
        ttfb_ns: Some(ttfb_ms * 1_000_000),
        tcp_connect_ns: Some(tcp_ms * 1_000_000),
        delimitation: Delimitation::Ambiguous,
        ..Default::default()
    })
}

fn jsonl(records: &[Record]) -> String {
    records
        .iter()
        .map(|r| match r {
            Record::Operation(o) => serde_json::to_string(o).unwrap(),
            Record::Connection(c) => serde_json::to_string(c).unwrap(),
            Record::TcpSample(s) => serde_json::to_string(s).unwrap(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_ansi(s: &str) -> String {
    // remove CSI sequences \x1b[ ... m
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn s3stats_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/s3stats.py")
}

fn python3_available() -> bool {
    Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
}

/// Run the oracle; return its de-ANSI'd stdout, or None if the oracle could not be run —
/// python3 missing, OR s3stats.py failed (renamed/crashed → non-zero exit) or emitted nothing.
/// Returning None on a broken script (not `Some("")`) is what lets the CI gate and the canary
/// below catch an oracle that is present-but-broken, not merely a missing interpreter.
fn run_oracle(fixture: &str) -> Option<String> {
    if !python3_available() {
        return None;
    }
    let mut child = Command::new("python3")
        .arg(s3stats_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn python3 s3stats.py");
    // Ignore a BrokenPipe here: a script that exits before reading stdin is a broken oracle,
    // caught below by the exit-status check — it must surface as None, not a write panic.
    let _ = child.stdin.take().unwrap().write_all(fixture.as_bytes());
    let out = child.wait_with_output().expect("s3stats.py output");
    if !out.status.success() {
        return None;
    }
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    if stdout.trim().is_empty() {
        return None;
    }
    Some(stdout)
}

/// Labels whose row in the oracle output carries a ⚠.
fn oracle_warn_labels(out: &str) -> Vec<String> {
    let mut warned: Vec<String> = LABELS
        .iter()
        .filter(|label| {
            out.lines().any(|l| l.contains(*label) && l.contains('⚠'))
        })
        .map(|s| (*s).to_string())
        .collect();
    warned.sort();
    warned
}

/// The verdict keyword from the oracle's `verdict:` line.
fn oracle_verdict(out: &str) -> String {
    let line = out.lines().find(|l| l.trim_start().starts_with("verdict:")).unwrap_or("");
    let after = line.split("verdict:").nth(1).unwrap_or("").trim();
    // The keyword is the leading run of UPPERCASE words, taken independently of
    // whatever separator (— or :) the oracle uses before its explanation clause —
    // stop at the first word containing a lowercase letter, then strip any trailing
    // punctuation the separator left glued to the last keyword ("HEALTHY:").
    let kw = after
        .split_whitespace()
        .take_while(|w| {
            w.chars().any(|c| c.is_alphabetic())
                && w.chars().filter(|c| c.is_alphabetic()).all(|c| c.is_uppercase())
        })
        .map(|w| w.trim_matches(|c: char| !c.is_alphabetic()))
        .collect::<Vec<_>>()
        .join(" ");
    kw
}

fn rust_warn_labels(records: &[Record]) -> Vec<String> {
    let r = analyze(records);
    let mut w: Vec<String> = r
        .rows
        .iter()
        .filter(|x| x.mark == Mark::Warn)
        .map(|x| x.label.to_string())
        .collect();
    w.sort();
    w
}

fn assert_parity(name: &str, records: &[Record]) {
    let fixture = jsonl(records);
    let Some(oracle) = run_oracle(&fixture) else {
        assert!(
            !running_in_ci(),
            "parity oracle unavailable (python3 missing, or demo/s3stats.py failed) but CI is \
             set — the oracle is required in CI (fixture {name}). Install python3 in the CI \
             image; unset CI only to skip locally."
        );
        eprintln!("parity oracle unavailable — skipping parity for {name}");
        return;
    };
    // The oracle ran and produced output; a malformed run must fail loudly, not pass
    // vacuously (empty warn-labels == empty warn-labels). Every real run emits a verdict line.
    assert!(
        oracle.contains("verdict:"),
        "{name}: s3stats.py produced output with no verdict line — oracle likely malformed\n\
         --- oracle ---\n{oracle}"
    );
    let report = analyze(records);
    assert_eq!(
        rust_warn_labels(records),
        oracle_warn_labels(&oracle),
        "{name}: ⚠ marks diverge from s3stats.py\n--- oracle ---\n{oracle}"
    );
    assert_eq!(
        report.verdict.keyword(),
        oracle_verdict(&oracle),
        "{name}: verdict diverges from s3stats.py\n--- oracle ---\n{oracle}"
    );
}

// One loud, single-point guard that the oracle is actually present. Every assert_parity
// call skips silently without python3; in CI that would quietly retire the entire parity
// suite. This canary fails CI in ONE obvious place if the oracle goes missing, and is a
// visible (passing) skip locally so contributors know parity did not run.
#[test]
fn python3_oracle_is_available() {
    if python3_available() {
        // Prove the script itself RUNS and emits real output — not merely that a python3
        // binary exists. `run_oracle` returns None on a renamed/crashed script, so this
        // `.expect` fires (locally too) the moment s3stats.py breaks; the verdict-line check
        // guards against a script that exits 0 but prints garbage. The empty fixture is the
        // cheapest end-to-end exercise of the oracle (it still emits a verdict line).
        let out = run_oracle("").expect("python3 present but demo/s3stats.py did not run");
        assert!(
            out.contains("verdict:"),
            "s3stats.py ran but emitted no verdict line — oracle malformed\n--- oracle ---\n{out}"
        );
        return;
    }
    assert!(
        !running_in_ci(),
        "python3 unavailable but CI is set — the parity oracle (demo/s3stats.py) is required \
         in CI. Install python3, or unset CI to allow a local skip."
    );
    eprintln!("python3 unavailable — parity oracle skipped (local run)");
}

#[test]
fn parity_healthy_with_reuse() {
    assert_parity(
        "healthy",
        &[
            conn(Some(17_000), 0, 1_000_000),
            op(30, 17, false, 200, false),
            op(34, 17, true, 200, false),
        ],
    );
}

#[test]
fn parity_http_error_attention() {
    assert_parity("http-error", &[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 503, false)]);
}

#[test]
fn parity_high_ttfb_attention() {
    assert_parity("high-ttfb", &[conn(Some(17_000), 0, 1_000_000), op(250, 17, false, 200, false)]);
}

#[test]
fn parity_high_ttfb_reused_attention() {
    // The reused-conn TTFB branch — never driven to ⚠ by any other fixture (the one
    // reused op elsewhere sits at 2× RTT). 120ms on a reused conn / 17ms floor = 7×.
    assert_parity(
        "high-ttfb-reused",
        &[conn(Some(17_000), 0, 1_000_000), op(120, 17, true, 200, false)],
    );
}

#[test]
fn parity_tcp_connect_slow_attention() {
    // tcp_connect is judged one-sided: 85ms / 17ms floor = 5.0× (> 3.0) -> warn in both.
    assert_parity("tcp-slow", &[conn(Some(17_000), 0, 1_000_000), op(30, 85, false, 200, false)]);
}

#[test]
fn parity_tcp_connect_fast_is_healthy() {
    // A connect FASTER than the floor (5ms / 17ms = 0.29×) is benign — pins that the Rust
    // doctor and the oracle BOTH treat it as healthy (no warn) after the band went one-sided.
    assert_parity("tcp-fast", &[conn(Some(17_000), 0, 1_000_000), op(30, 5, false, 200, false)]);
}

#[test]
fn parity_no_srtt_no_baseline() {
    assert_parity("no-srtt", &[op(30, 17, false, 200, false)]);
}

#[test]
fn parity_all_partial_checks_passed() {
    assert_parity("all-partial", &[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, true)]);
}

#[test]
fn parity_retransmit_loss_attention() {
    // 50 retransmits over 1 MB sent (~684 segments) = 7.3%, past the 0.1% tolerance in both.
    // The megabyte is load-bearing: both implementations refuse to rate loss below
    // MIN_RATE_SEGMENTS (~44), so a 1 KB fixture would exercise the n/a branch instead.
    assert_parity("retransmits", &[conn(Some(17_000), 50, 1_000_000), op(30, 17, false, 200, false)]);
}

#[test]
fn parity_tiny_send_leg_is_not_rated_in_either() {
    // The default `doctor --live --requests 12` shape: one keep-alive connection whose send
    // leg is request headers only (~15 KB, ~10 segments) with a single retransmit. Rating that
    // gave a healthy path "10.00% ⚠ loss" and exit 1. Both sides must now report the row n/a,
    // so this fixture pins the minimum-denominator floor in LOCK-STEP — a one-sided revert
    // (Rust or python) makes the ⚠ sets diverge and fails here.
    assert_parity("tiny-send-leg", &[conn(Some(17_000), 1, 15_000), op(30, 17, false, 200, false)]);
}

#[test]
fn parity_empty_input() {
    assert_parity("empty", &[]);
}

#[test]
fn parity_all_aborted_ops_affirm_nothing_in_either() {
    // Operations decoded but NONE answered — the shape `flush_open_ops` emits at SIGINT. Both
    // implementations must report the HTTP-errors row n/a rather than the affirmative
    // "0 / 3 ✓ healthy — all operations 2xx/204": the error numerator only counts an op that
    // HAS a status, so its 0 is a construction, not a measurement. A one-sided revert of either
    // `op_statused == 0` gate leaves one side printing a ✓ the other calls n/a.
    let aborted = || {
        Record::Operation(Operation {
            // no http_status: the response never came. A 100-continue interim still timed it.
            ttfb_ns: Some(30 * 1_000_000),
            tcp_connect_ns: Some(17 * 1_000_000),
            connection_reused: true,
            ..Default::default()
        })
    };
    let recs = vec![conn(Some(17_000), 0, 1_000_000), aborted(), aborted(), aborted()];
    assert_parity("all-aborted", &recs);
    // The ⚠ sets agree trivially here (neither warns), so pin the mark itself: this fixture's
    // teeth are that the row is UNJUDGED, which `assert_parity` alone cannot see.
    let r = analyze(&recs);
    let errs = r.rows.iter().find(|x| x.id == "http_errors").expect("http_errors row");
    assert_eq!(errs.mark, Mark::Na, "nothing answered => nothing to affirm: {}", errs.note);
    if let Some(oracle) = run_oracle(&jsonl(&recs)) {
        let line = oracle.lines().find(|l| l.contains("HTTP errors")).expect("oracle row");
        assert!(!line.contains('✓'), "the oracle must not affirm either: {line}");
        assert!(line.contains("n/a"), "the oracle marks it n/a: {line}");
    }
}

#[test]
fn parity_slow_dns_is_fyi_in_both() {
    // A 60 ms cold resolve on an OP. Neither implementation judges it: the invented "> 50 ms"
    // absolute threshold this fixture once pinned is gone from both (there is no honest
    // absolute bound, and the resolver is on a different path than the endpoint, so the RTT
    // floor is not its baseline either). "DNS, cold resolve" is still in LABELS, so this is now
    // a NEGATIVE pin: it fails the moment either side re-introduces a DNS ⚠. (DNS must be on an
    // operation, not the connection — the cold-resolve metric reads ops only.)
    assert_parity(
        "slow-dns",
        &[conn(Some(17_000), 0, 1_000_000), op_dns(30, 17, 200, 60, false)],
    );
}

#[test]
fn parity_ambiguous_op_excluded_from_latency() {
    // A clean healthy op + an ambiguous op with a wild 900ms ttfb. Both impls must drop
    // the ambiguous one; if either counted it, its ttfb_new median would
    // warn and the two would diverge. Pins the eligibility gate agreement.
    assert_parity(
        "ambiguous-excluded",
        &[
            conn(Some(17_000), 0, 1_000_000),
            op(30, 17, false, 200, false),
            op_ambiguous(900, 17, 200),
        ],
    );
}

#[test]
fn parity_dns_cold_excludes_ineligible_ops() {
    // A clean 30 ms cold resolve + a PARTIAL op carrying a slow 200 ms resolve. Both impls must
    // exclude the partial from the DNS-cold median (eligibility gates DNS too). NOTE the teeth
    // this fixture used to have are gone with the DNS threshold: the exclusion no longer changes
    // any ⚠ (the row is fyi in both), so what survives here is the agreement that a DNS-bearing,
    // partially-ineligible capture reaches the same verdict. The exclusion ITSELF is pinned by
    // the Rust unit test `dns_cold_median_excludes_partial_and_error_ops` (value, not mark) —
    // a one-sided python revert of `ops`→`good` would now only move the reported median.
    assert_parity(
        "dns-cold-ineligible-excluded",
        &[
            conn(Some(17_000), 0, 1_000_000),
            op_dns(30, 17, 200, 30, false),
            op_dns_partial(200),
        ],
    );
}

#[test]
fn parity_dns_ok_and_cache_hit_excluded() {
    // Exercises the DNS path with a cache_hit present: a cold 3 ms resolve plus a 99 ms
    // CACHE-HIT resolve that must be EXCLUDED from the median. Same caveat as above — with the
    // 50 ms threshold gone from both impls, a broken exclusion moves the reported median but no
    // longer flips a ⚠, so this pins verdict agreement on a cache-hit-bearing capture rather
    // than the exclusion itself (unit-tested Rust-side in `dns_cold_median_excludes_partial_and_error_ops`).
    assert_parity(
        "dns-ok-cache-hit",
        &[
            conn(Some(17_000), 0, 1_000_000),
            op_dns(30, 17, 200, 3, false),
            op_dns(30, 17, 200, 99, true),
        ],
    );
}

// Positive parity pin: adding s3tap.sample/1 records to a capture must NOT move the
// median verdict or the ⚠ warn-labels. Samples are telemetry consumed by the (Plan 2)
// time-series analysis — they must never feed the parity-pinned median path.
#[test]
fn samples_do_not_move_the_verdict_or_warn_labels() {
    // A FLOOR-SENSITIVE base: srtt floor = 16 ms (the lone conn srtt); a reused-conn
    // ttfb of 90 ms = 5.6x the floor -> a reused-TTFB ⚠ + ATTENTION. The samples below
    // carry srtt 40/80 ms — IF they leaked into the srtt median the floor would jump to
    // ~40 ms, 90 ms would fall to 2.25x, and the ⚠ would VANISH (verdict -> HEALTHY).
    // So this pin actually FAILS on a leak (the prior 30 ms base was green-on-green and
    // could not). The code keeps samples out of `ops`/`conns`, so the floor stays 16 ms
    // and base == with.
    let base = vec![conn(Some(16_000), 0, 1_000_000), op(90, 17, true, 200, false)];
    let mut with_samples = base.clone();
    with_samples.push(Record::TcpSample(TcpSample {
        sock_cookie: 1,
        srtt_us: Some(40_000), // would shrink every ratio if it reached the floor median
        min_rtt_us: Some(15_000),
        bytes_recv: 9_000_000,
        snd_cwnd: 64,
        ts_ns: Some(1_000), // would also widen the capture window if it leaked
        ..Default::default()
    }));
    with_samples.push(Record::TcpSample(TcpSample {
        sock_cookie: 1,
        srtt_us: Some(80_000),
        bytes_recv: 18_000_000,
        ts_ns: Some(2_000),
        ..Default::default()
    }));

    let base_report = analyze(&base);
    let with_report = analyze(&with_samples);
    // Sanity: the base really does carry the floor-sensitive warn we rely on.
    assert!(!rust_warn_labels(&base).is_empty(), "base must have a floor-sensitive ⚠ for this pin to bite");
    assert_eq!(
        base_report.verdict.keyword(),
        with_report.verdict.keyword(),
        "samples moved the median verdict"
    );
    assert_eq!(
        rust_warn_labels(&base),
        rust_warn_labels(&with_samples),
        "samples moved the ⚠ warn-labels"
    );
}
