//! Gated live integration test for `s3tap doctor --live`.
//!
//! The live capture needs root / probe caps + curl, so this is OPT-IN: set
//! `S3TAP_LIVE_TEST=1` (on a host with `UPROBES=1 ./setcap.sh` applied) to run it.
//! Otherwise it skips with a printed reason — mirroring the doctor parity tests that skip
//! when `python3` is unavailable (crates/s3tap-doctor/tests/parity.rs).
//!
//! What it pins: the review-#1 fix that `--timeout-secs` is an actual wall-clock bound.
//! It points `--live` at a black-hole TCP listener (accepts, never replies), so the
//! keep-alive curl's TLS handshake stalls; without the child-kill fix the run would block
//! for up to N × curl `--max-time`, with it the deadline bounds the run.

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

/// Startup + teardown a `--live` run is allowed on TOP of its `--timeout-secs` budget:
/// loading and attaching the eBPF object, spawning curl, then the final drain, the
/// analysis and the render. Generous for that work, and nowhere near the failure being
/// guarded — without the child-kill fix the run takes N × curl `--max-time`, i.e. minutes.
const LIVE_OVERHEAD_GRACE: Duration = Duration::from_secs(5);

/// The wall-clock ceiling for a `--live` run with the given capture budget. Pure, so the
/// POLICY ("the timeout is a real bound, plus bounded overhead") is pinned by the unit test
/// below on every CI run — the capture itself needs root and is opt-in, so without this the
/// rule was pinned nowhere at all.
fn live_deadline_budget(timeout_secs: u64) -> Duration {
    Duration::from_secs(timeout_secs) + LIVE_OVERHEAD_GRACE
}

#[test]
fn live_deadline_budget_tracks_the_timeout() {
    // Linear in --timeout-secs with a constant, bounded overhead: any change that makes the
    // budget a MULTIPLE of the timeout (the old assertion was 10x) fails here, because such
    // a bound stops distinguishing "the deadline worked" from "curl's --max-time expired".
    assert_eq!(live_deadline_budget(2), Duration::from_secs(7));
    assert_eq!(live_deadline_budget(15), Duration::from_secs(20));
    let (a, b) = (live_deadline_budget(2), live_deadline_budget(3));
    assert_eq!(b - a, Duration::from_secs(1), "the grace must be additive, not proportional");
    // And it must stay far below the failure it guards: 3 requests x curl's 30 s --max-time.
    assert!(live_deadline_budget(2) < Duration::from_secs(3 * 30));
}

#[test]
fn live_capture_is_bounded_by_timeout() {
    if std::env::var("S3TAP_LIVE_TEST").as_deref() != Ok("1") {
        eprintln!(
            "skipping live --live test — set S3TAP_LIVE_TEST=1 on a host with the probe caps \
             (UPROBES=1 ./setcap.sh) + curl to run it"
        );
        return;
    }

    // A black-hole listener: accept connections and hold them open, never replying — so
    // curl's TLS handshake stalls and only the timeout (or the child-kill) ends the run.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind black-hole listener");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // keep each accepted connection open, never writing a reply
        let _held: Vec<_> = listener.incoming().flatten().collect();
    });

    let timeout_secs = 2;
    let start = Instant::now();
    let status = Command::new(env!("CARGO_BIN_EXE_s3tap"))
        .args([
            "doctor",
            "--live",
            "--endpoint",
            &format!("https://127.0.0.1:{port}"),
            "--timeout-secs",
            &timeout_secs.to_string(),
            "--requests",
            "3",
            "--no-color",
        ])
        .status()
        .expect("spawn s3tap");
    let elapsed = start.elapsed();

    // The timeout must be an ACTUAL wall-clock bound, not merely better than N × curl
    // --max-time. The old 20 s ceiling against a 2 s budget was 10x slack: a regression
    // that reverted the deadline to curl's per-transfer timeout would still have passed
    // for small --requests. The exact exit code depends on caps/capture; only the bound
    // is asserted.
    let budget = live_deadline_budget(timeout_secs);
    assert!(
        elapsed < budget,
        "doctor --live hung past its --timeout-secs budget: {elapsed:?} > {budget:?} (exit {status:?})"
    );
}
