//! Compare the new hybrid (W-LFU eviction + stingy top-1 prefetch) against plain
//! LRU and the current adaptive, on the Pareto goal: hide latency without losing
//! money. Prints, at cap 64 / 8M chunks, hit_rate, net_savings, instant pf_latency,
//! and the lead-time-aware effective latency hidden.
//!
//!   cargo run --release --bin hybrid_eval -- <trace> [cap] [fetch_ms]
//! env: S3TAP_MAX (event cap, default 3_000_000)

use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use s3tap_replay::driver::run;
use s3tap_replay::hybrid::{run_hybrid, run_lead_gated, run_self_tuned};
use s3tap_replay::ibm::{from_ibm_line, to_blocks};
use s3tap_replay::predict::{AdaptivePredictor, NullPredictor};

const CHUNK: u64 = 8 * 1024 * 1024;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => { eprintln!("usage: hybrid_eval <trace> [cap] [fetch_ms]"); return ExitCode::from(2); }
    };
    // Optional positional args. A present-but-unparseable value is an ERROR (exit 2),
    // not a silent fallback (matching `replay`), so a typo can't report numbers under
    // the wrong parameters. `cap >= 2` is required so every row (including the LRU
    // floor via `run`, whose `Sim` does not self-clamp) runs at the same capacity as
    // the WLfu-based rows (which clamp to `cap.max(2)`).
    let cap: u64 = match std::env::args().nth(2) {
        None => 64,
        Some(s) => match s.parse::<u64>() {
            Ok(c) if c >= 2 => c,
            _ => { eprintln!("error: invalid cap '{s}' (integer >= 2)"); return ExitCode::from(2); }
        },
    };
    let fetch_ms: u64 = match std::env::args().nth(3) {
        None => 100,
        Some(s) => match s.parse::<u64>() {
            Ok(m) if m > 0 => m,
            _ => { eprintln!("error: invalid fetch_ms '{s}' (positive integer)"); return ExitCode::from(2); }
        },
    };
    let l_ns = fetch_ms.saturating_mul(1_000_000);
    // Present-but-invalid is an error, never a silent fall-back to the default: a typo in a
    // study run must not quietly produce numbers under parameters nobody chose. 0 keeps its
    // documented meaning here (use the default cap).
    let max_events: usize = match s3tap_replay::env::from_env::<usize>("S3TAP_MAX", "a non-negative integer") {
        Ok(v) => v.filter(|&n| n > 0).unwrap_or(3_000_000),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => { eprintln!("cannot open {path}: {e}"); return ExitCode::from(1); }
    };
    let mut trace = Vec::new();
    let mut skipped = 0u64;
    for line in BufReader::new(file).lines() {
        // A mid-stream read error (truncated tar member, broken pipe) must FAIL,
        // not silently report metrics computed on a partial trace as complete.
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: reading {path} after {} events: {e}", trace.len());
                return ExitCode::from(1);
            }
        };
        match from_ibm_line(&line) {
            Some(ev) => trace.push(ev),
            None => skipped += 1,
        }
        if trace.len() >= max_events { break; }
    }
    let sampled = if trace.len() >= max_events { " (S3TAP_MAX sample)" } else { "" };
    let blocks = to_blocks(&trace, CHUNK);
    eprintln!("{}: {} events ({skipped} skipped){sampled} -> {} chunks, cap={cap} ({} MiB), fetch={fetch_ms}ms",
              path, trace.len(), blocks.len(), cap * CHUNK / (1024 * 1024));
    if blocks.is_empty() { eprintln!("no usable events"); return ExitCode::from(1); }

    // Policies compared. (The k=16 "adaptive-old" rung is dropped here for speed —
    // it is already in the main sweep report; this run is about the hybrids.)
    // The LEAD-GATED policy runs at THREE modelled fetch latencies, because the
    // prefetch depth k = ceil(L/Δ) and the latency credit min(1, lead/L) both
    // scale with the network: ~10ms is in-cloud (EC2 -> same-region S3), ~100ms a
    // WAN client, ~1000ms a slow/constrained link fetching 8 MiB chunks.
    let lru = run(&blocks, &mut NullPredictor, cap);
    let wlfu = run_hybrid(&blocks, cap, l_ns, &mut NullPredictor);
    let hybrid = run_hybrid(&blocks, cap, l_ns, &mut AdaptivePredictor::with_ref_cap(1, cap));

    println!("{:<16} {:>9} {:>11} {:>11} {:>11}", "policy", "hit_rate", "net_save", "pf_lat", "eff_lat");
    // LRU uses the Sim path (no lead-time model -> eff_lat n/a; it never prefetches).
    println!("{:<16} {:>9.3} {:>11.3} {:>11.3} {:>11}", "LRU (floor)",
             lru.hit_rate(), lru.net_savings(), lru.prefetch_latency_saved(), "-");
    println!("{:<16} {:>9.3} {:>11.3} {:>11.3} {:>11.3}", "W-LFU (demand)",
             wlfu.hit_rate(), wlfu.net_savings(), wlfu.pf_latency(), wlfu.eff_latency());
    println!("{:<16} {:>9.3} {:>11.3} {:>11.3} {:>11.3}", "HYBRID (wlfu)",
             hybrid.hit_rate(), hybrid.net_savings(), hybrid.pf_latency(), hybrid.eff_latency());
    for ms in [10u64, 100, 1000] {
        let g = run_lead_gated(&blocks, cap, ms * 1_000_000, 0.5, 32);
        println!("{:<16} {:>9.3} {:>11.3} {:>11.3} {:>11.3}", format!("LG@{ms}ms"),
                 g.hit_rate(), g.net_savings(), g.pf_latency(), g.eff_latency());
    }
    // The closed-loop gate (probationary buffer + waste budget + adaptive conf).
    for ms in [10u64, 100, 1000] {
        let s = run_self_tuned(&blocks, cap, ms * 1_000_000, 32);
        println!("{:<16} {:>9.3} {:>11.3} {:>11.3} {:>11.3}", format!("ST@{ms}ms"),
                 s.hit_rate(), s.net_savings(), s.pf_latency(), s.eff_latency());
    }
    ExitCode::SUCCESS
}
