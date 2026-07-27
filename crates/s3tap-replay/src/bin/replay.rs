use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use s3tap_replay::adapt::parse_trace_line as parse_line;
use s3tap_replay::driver::sweep;
use s3tap_replay::trace::Op;

/// Parse a size that may carry a K/M/G suffix (binary units): "4M" -> 4194304,
/// "64K" -> 65536, "1048576" -> 1048576. Returns None on a malformed value.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (digits, mult): (&str, u64) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some('G' | 'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    digits.trim().parse::<u64>().ok().and_then(|n| n.checked_mul(mult))
}

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: s3tap-replay <trace> [block_size|object]");
            eprintln!("  each line (auto-detected): a NormEvent, an s3tap");
            eprintln!("  operation record, or an IBM COS trace line");
            eprintln!("  2nd arg (optional): CHUNK size (e.g. 1M, 4M, 8M, 64K).");
            eprintln!("    Default is CHUNK mode at 8M. Pass 'object' for");
            eprintln!("    whole-object (non-chunked) residency instead.");
            return ExitCode::from(2);
        }
    };
    // The cache is CHUNK-based by default: the 2nd positional arg is the chunk
    // size (raw bytes or a K/M/G suffix). With no arg we default to 8M chunks.
    // The literal `object` opts out to whole-object residency. A present but
    // unparseable value is an ERROR (not a silent fall-back).
    const DEFAULT_BLOCK: u64 = 8 * 1024 * 1024; // 8 MiB
    let block_bytes: Option<u64> = match std::env::args().nth(2) {
        None => Some(DEFAULT_BLOCK), // default: chunk mode @ 8M
        Some(s) if s.eq_ignore_ascii_case("object") => None, // opt out -> whole objects
        Some(s) => match parse_size(&s) {
            Some(b) if b > 0 => Some(b),
            _ => {
                eprintln!("error: invalid chunk size '{s}' (a size like 8M, or 'object')");
                return ExitCode::from(2);
            }
        },
    };

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot open {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let mut trace = Vec::new();
    let mut skipped = 0u64;
    // Optional S3TAP_MAX=<n>: stop after N parsed events (a leading time-slice
    // sample), so a multi-GB trace can be run in bounded time. 0 / unset = no cap.
    // Unset or `0` means no cap. A present, unparseable value is an error, never a silent
    // fall-back to "unbounded": see `s3tap_replay::env`, which `mrc` shares.
    let max_events: usize =
        match s3tap_replay::env::raw("S3TAP_MAX").and_then(|v| s3tap_replay::env::max_events(v.as_deref())) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(l) => l,
            // Surface a mid-file read error instead of silently truncating the
            // input and reporting on partial data.
            Err(e) => {
                eprintln!("error: reading {path} after {} events: {e}", trace.len());
                return ExitCode::from(1);
            }
        };
        if line.trim().is_empty() { continue; }
        match parse_line(&line) {
            Some(ev) => trace.push(ev),
            None => skipped += 1,
        }
        if trace.len() >= max_events { break; }
    }

    let sampled = if max_events != usize::MAX && trace.len() >= max_events { " (S3TAP_MAX sample)" } else { "" };
    eprintln!("loaded {} events ({skipped} lines skipped){sampled}", trace.len());
    if trace.is_empty() {
        eprintln!("no usable events");
        return ExitCode::from(1);
    }

    // BLOCK mode: expand ranged GETs into fixed-size blocks; capacity is then in
    // BLOCKS and the sweep includes the sequential read-ahead predictor.
    if let Some(b) = block_bytes {
        trace = s3tap_replay::ibm::to_blocks(&trace, b);
        eprintln!("BLOCK mode: {}-byte blocks, {} block accesses", b, trace.len());
    }
    eprintln!(
        "NOTE: 'cap' is in {} units, not bytes; 'hit_rate' is an UPPER BOUND \
         (instant prefetch, and in object mode range fragmentation). See caveats.",
        if block_bytes.is_some() { "BLOCK-COUNT" } else { "OBJECT-COUNT" }
    );
    if trace.is_empty() {
        eprintln!("no usable events after block expansion");
        return ExitCode::from(1);
    }

    // Capacity sweep: powers of two from 2 up to ~the distinct-object count.
    // We start at 2, not 1: at cap=1 a prefetch predictor evicts the just-
    // accessed object (k == cap degeneracy), producing a misleading row.
    // GETs ONLY, matching `mrc`'s ladder and `analyze::distinct_keys`: the sweep inserts
    // on Op::Get alone, so a key that is only ever written or HEADed is not a cache key
    // and only stretches the top of the ladder. `to_blocks` forwards writes as per-chunk
    // invalidations, so write-only keys do reach here on the block path.
    let distinct = {
        let mut s = std::collections::HashSet::new();
        for e in trace.iter().filter(|e| e.op == Op::Get) { s.insert(&e.object_id); }
        s.len() as u64
    };
    // The default cache size is 64 chunks (64 * 8M = 512 MiB). Sweep up to at
    // least 64 so that anchor is always present, and beyond it up to the working
    // set when the trace has more distinct chunks than that.
    const DEFAULT_CAP: u64 = 64;
    let top = distinct.max(DEFAULT_CAP).max(2);
    let mut caps = Vec::new();
    let mut c = 2u64;
    while c < top {
        caps.push(c);
        c *= 2;
    }
    caps.push(top);
    caps.dedup(); // collapse the degenerate distinct <= 2 case

    // Optional override: S3TAP_CAP=<n> evaluates a SINGLE capacity instead of the
    // full ladder. The per-capacity rungs (adaptive/opt/admission) each run one
    // pass per cap, so pinning one cap is ~ladder-length faster — the way to get a
    // cap-64 summary over large traces without paying for the whole curve.
    // `env::raw`, not `env::var`: the latter's Err arm swallows a non-UTF-8 value into the
    // same "unset" branch, which is the silent fall-back the env module exists to prevent.
    let s3tap_cap = match s3tap_replay::env::raw("S3TAP_CAP") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(v) = s3tap_cap {
        match v.trim().parse::<u64>() {
            Ok(c) if c >= 2 => caps = vec![c],
            _ => {
                eprintln!("error: S3TAP_CAP='{v}' must be an integer >= 2");
                return ExitCode::from(2);
            }
        }
    }

    // 'net_savings' = origin fetches ELIMINATED per access vs no-cache = reuse
    // benefit (hit_rate) minus prefetch cost (pf/access); positive cuts origin
    // calls, negative means speculation costs more than reuse saves. 'pf_latency'
    // = fraction of accesses whose latency was hidden specifically by prefetching
    // (vs 'hit_rate', which is ALL latency-free hits including plain-cache reuse).
    println!(
        "{:<10} {:>8} {:>10} {:>12} {:>10} {:>11} {:>11}",
        "predictor", "cap", "hit_rate", "pf_precision", "pf/access", "net_savings", "pf_latency"
    );
    let rows = match block_bytes {
        Some(_) => s3tap_replay::driver::sweep_blocks(&trace, &caps),
        None => sweep(&trace, &caps),
    };
    for r in rows {
        println!(
            "{:<10} {:>8} {:>10.3} {:>12.3} {:>10.3} {:>11.3} {:>11.3}",
            r.predictor, r.cap, r.hit_rate, r.pf_precision, r.pf_per_access, r.net_savings, r.pf_latency
        );
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::parse_size;
    use s3tap_replay::env::max_events as parse_max_events;

    #[test]
    fn parse_size_handles_units_and_bad_input() {
        assert_eq!(parse_size("4M"), Some(4 * 1024 * 1024));
        assert_eq!(parse_size("64K"), Some(64 * 1024));
        assert_eq!(parse_size("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("1048576"), Some(1_048_576));
        assert_eq!(parse_size("0"), Some(0)); // valid parse; caller rejects 0
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("4MB"), None); // two-letter unit unsupported
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("99999999999G"), None); // checked_mul overflow -> None
    }

    #[test]
    fn max_events_rejects_present_but_unparseable_values_and_zero_means_uncapped() {
        assert_eq!(parse_max_events(None), Ok(usize::MAX));
        assert_eq!(parse_max_events(Some("0")), Ok(usize::MAX));
        assert_eq!(parse_max_events(Some("1000")), Ok(1000));
        assert_eq!(parse_max_events(Some(" 1000 ")), Ok(1000));
        // Used to silently fall back to unbounded (`usize::MAX`) on any of these.
        for bad in ["1O00", "abc", "-1", "1.5"] {
            assert!(parse_max_events(Some(bad)).is_err(), "S3TAP_MAX='{bad}' must be rejected");
        }
    }
}
