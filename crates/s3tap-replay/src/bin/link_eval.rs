//! Bandwidth-contention study: the same workload and policy through an
//! EC2-class link (1 ms RTT, 25 Gbps) versus a WAN-class link (40 ms RTT,
//! 1 Gbps). Fetches serialize on the link, so a wasted prefetch here DELAYS the
//! demand traffic behind it — the cost the request-count model can't see.
//!
//!   cargo run --release --bin link_eval -- <trace> [cap]
//! env: S3TAP_MAX (event cap, default 3_000_000)

use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use s3tap_replay::ibm::{from_ibm_line, to_blocks};
use s3tap_replay::link::{run_contended, Discipline, LinkCfg, LinkPolicy};

const CHUNK: u64 = 8 * 1024 * 1024;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => { eprintln!("usage: link_eval <trace> [cap]"); return ExitCode::from(2); }
    };
    // A present-but-unparseable/too-small cap is an ERROR (exit 2), not a silent fall-back to
    // 64 — otherwise a typo (`link_eval trace 6r4`) reports numbers under the wrong capacity.
    // Mirrors hybrid_eval; `>= 2` matches ReadyLru's floor so the printed cap isn't a mislabel.
    let cap: u64 = match std::env::args().nth(2) {
        None => 64,
        Some(s) => match s.parse::<u64>() {
            Ok(c) if c >= 2 => c,
            _ => {
                eprintln!("error: invalid cap '{s}' (integer >= 2)");
                return ExitCode::from(2);
            }
        },
    };
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
    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: reading {path} after {} events: {e}", trace.len());
                return ExitCode::from(1);
            }
        };
        if let Some(ev) = from_ibm_line(&line) { trace.push(ev); }
        if trace.len() >= max_events { break; }
    }
    let blocks = to_blocks(&trace, CHUNK);
    eprintln!("{path}: {} events -> {} chunks, cap={cap}", trace.len(), blocks.len());
    if blocks.is_empty() { eprintln!("no usable events"); return ExitCode::from(1); }

    let regimes = [
        ("ec2", LinkCfg { rtt_ns: 1_000_000, bw_bps: 25_000_000_000, chunk_bytes: CHUNK }),
        ("wan", LinkCfg { rtt_ns: 40_000_000, bw_bps: 1_000_000_000, chunk_bytes: CHUNK }),
    ];
    println!(
        "{:<6} {:<10} {:>13} {:>10} {:>10}",
        "link", "policy", "mean_wait_ms", "zero_wait", "pf/access"
    );
    for (name, cfg) in regimes {
        eprintln!("[{name}] uncontended fetch = {:.1} ms", cfg.fetch_ns() as f64 / 1e6);
        let rows: [(&str, LinkPolicy); 4] = [
            ("no-cache", LinkPolicy::NoCache),
            ("lru", LinkPolicy::Demand),
            ("lg-fifo", LinkPolicy::LeadGated(Discipline::Fifo)),
            ("lg-prio", LinkPolicy::LeadGated(Discipline::DemandPriority)),
        ];
        for (pname, pol) in rows {
            let r = run_contended(&blocks, cap, &cfg, &pol, 0.5, 32);
            println!(
                "{:<6} {:<10} {:>13.2} {:>10.3} {:>10.3}",
                name, pname, r.mean_wait_ms(), r.zero_wait_frac(), r.pf_per_access()
            );
        }
    }
    ExitCode::SUCCESS
}
