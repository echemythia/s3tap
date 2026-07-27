// Miss-ratio-curve exporter: run the capacity sweep over ONE trace and emit tidy CSV
// (one row per predictor × cache size), so the fleet's cache curves can be plotted instead
// of a single headline size. This is `replay` in CSV form, always over the FULL ladder (no
// S3TAP_CAP pin) and tagged with a trace id for concatenation across the corpus.
//
//   s3tap-mrc <trace> [trace-id] [chunk|object]     # trace-id defaults to the file stem
//
// Loading mirrors the `replay` bin (a NormEvent, an s3tap operation record, or an IBM COS
// line; 8M chunk mode by default). Kept as its own bin so it composes with the existing
// sweep API and touches nothing else.

use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use s3tap_replay::adapt::parse_trace_line as parse_line;
use s3tap_replay::driver::{sweep, sweep_blocks, sweep_retention};
use s3tap_replay::trace::{NormEvent, Op};

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

/// Cap the ladder top so the per-cap rungs stay tractable on multi-GB traces (a full ladder to
/// millions of chunks is O(caps) passes). 4096 chunks = 32 GiB is 64x the anchor — well past
/// the knee for the report's regime. Override with MRC_MAXCAP.
const DEFAULT_MAXCAP: u64 = 4096;

/// Resolve `MRC_MAXCAP`. A present but unparseable value is an ERROR, not a silent fall-back:
/// the same discipline `S3TAP_CAP` enforces in the `replay` bin, so a typo can't quietly emit a
/// ladder under a ceiling nobody asked for.
///
/// A parseable value BELOW 2 is floored, matching the replay ladder and the MRC_CAP/S3TAP_CAP
/// validators. A cap of 0 makes the demand policies DISAGREE (Arc/S3Fifo clamp 0→1 and report
/// above the cap-0 OPT floor); a cap of 1 is degenerate for the PREFETCH rungs — k_for_cap(1)==1,
/// so every speculative insert evicts the just-accessed chunk (k==cap), collapsing their hit
/// rates into a whole CSV of misleading numbers.
fn parse_max_cap(raw: Option<&str>) -> Result<u64, String> {
    match raw {
        None => Ok(DEFAULT_MAXCAP),
        Some(_) => Ok(s3tap_replay::env::parse_env::<u64>("MRC_MAXCAP", raw, "an integer")?
            .expect("raw is Some")
            .max(2)),
    }
}

/// Resolve the `MRC_CAP` pin: `None` = unset (run the full ladder), `Some(c)` = evaluate that one
/// capacity. Present-but-invalid is an ERROR for the same reason as `parse_max_cap` — a corpus
/// driver that fed one `MRC_CAP=1` would otherwise append the whole ladder (~120 rows instead of
/// 10) into the aggregate CSV with no diagnostic at all.
fn parse_cap_pin(raw: Option<&str>) -> Result<Option<u64>, String> {
    match raw {
        None => Ok(None),
        Some(v) => match s3tap_replay::env::parse_env::<u64>("MRC_CAP", raw, "an integer >= 2")? {
            Some(c) if c >= 2 => Ok(Some(c)),
            _ => Err(format!("MRC_CAP='{v}' must be an integer >= 2")),
        },
    }
}

/// The capacity ladder: powers of two from 2 up to the distinct-object working set, with 64
/// (the report's 512 MiB anchor) always present. Identical to the `replay` bin's ladder and to
/// `s3tap_advisor::analyze`'s, so the three agree cap-for-cap.
///
/// GETs ONLY, the same filter `analyze::distinct_keys` applies. The simulator skips
/// `Head`/`Other` and never inserts on `Put`/`Delete`, so a key that is only ever written is
/// not a cache key. Counting it stretches the ladder top past anything the sweep can fill.
/// This was invisible while `to_blocks` dropped writes: it now forwards them as per-chunk
/// invalidations, so a write-only chunk reaches this function on the DEFAULT (chunk) path.
fn cap_ladder(trace: &[NormEvent], max_cap: u64) -> Vec<u64> {
    let distinct = {
        let mut s = std::collections::HashSet::new();
        for e in trace.iter().filter(|e| e.op == Op::Get) {
            s.insert(&e.object_id);
        }
        s.len() as u64
    };
    const DEFAULT_CAP: u64 = 64; // the report's 512 MiB anchor (64 * 8 MB chunks)
    let top = distinct.clamp(DEFAULT_CAP.min(max_cap), max_cap);
    let mut caps = Vec::new();
    let mut c = 2u64;
    while c < top {
        caps.push(c);
        c *= 2;
    }
    caps.push(top);
    caps.dedup();
    caps
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: s3tap-mrc <trace> [trace-id] [chunk|object]");
            eprintln!("  emits CSV: trace,predictor,cap,hit_rate,pf_precision,pf_per_access,\
                       net_savings,pf_latency  (one row per predictor x cache size)");
            return ExitCode::from(2);
        }
    };
    // trace-id: explicit arg, else the file stem (so `.../000.trace` -> `000`).
    let trace_id = args.next().unwrap_or_else(|| {
        std::path::Path::new(&path)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone())
    });
    // trace_id is the only free-text CSV column; a comma (or newline) in a filename stem or
    // an explicit id would add a field and shift every later column, silently corrupting the
    // concatenated corpus CSV. Neutralize the separators rather than emit a broken row.
    let trace_id: String =
        trace_id.chars().map(|c| if c == ',' || c == '\n' || c == '\r' { '_' } else { c }).collect();
    const DEFAULT_BLOCK: u64 = 8 * 1024 * 1024;
    let block_bytes: Option<u64> = match args.next() {
        None => Some(DEFAULT_BLOCK),
        Some(s) if s.eq_ignore_ascii_case("object") => None,
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
    // Shared with the `s3tap-replay` bin, which has the identical contract: see
    // `s3tap_replay::env::max_events`.
    let max_events: usize =
        match s3tap_replay::env::raw("S3TAP_MAX").and_then(|v| s3tap_replay::env::max_events(v.as_deref())) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
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
        if line.trim().is_empty() {
            continue;
        }
        if let Some(ev) = parse_line(&line) {
            trace.push(ev);
        }
        if trace.len() >= max_events {
            break;
        }
    }
    if trace.is_empty() {
        eprintln!("no usable events in {path}");
        return ExitCode::from(1);
    }
    let events = trace.len(); // raw op count (before chunk expansion)
    if let Some(b) = block_bytes {
        trace = s3tap_replay::ibm::to_blocks(&trace, b);
    }
    if trace.is_empty() {
        eprintln!("no usable events after block expansion");
        return ExitCode::from(1);
    }
    // CACHE ACCESSES, not expanded rows: the sweep counts an access only on `Op::Get`
    // (driver.rs), so this is the denominator every `hit_rate` in the CSV was computed
    // over. `trace.len()` also counted the per-chunk Put/Delete invalidations `to_blocks`
    // now emits, so anyone reconstructing `hits = hit_rate * block_accesses` off the
    // corpus CSV came out high by the write fraction (~5% on a realistic IBM COS trace).
    let block_accesses = trace.iter().filter(|e| e.op == Op::Get).count();

    // Full capacity ladder by default; MRC_CAP=<n> pins a SINGLE cap (e.g. 64), which runs each
    // per-cap rung (adaptive/opt/lru+adm/arc/s3fifo) only once — the fast path for the cap-64
    // fleet table.
    let pin = match s3tap_replay::env::raw("MRC_CAP").and_then(|v| parse_cap_pin(v.as_deref())) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let caps = match pin {
        Some(c) => vec![c],
        None => match s3tap_replay::env::raw("MRC_MAXCAP").and_then(|v| parse_max_cap(v.as_deref())) {
            Ok(m) => cap_ladder(&trace, m),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
    };
    // MRC_RETENTION_ONLY=1 runs just the cheap demand policies (null/opt/lru+adm/arc/s3fifo),
    // skipping the O(distinct)-expensive prefetch model-builders — the fast path for adding the
    // new retention schemes to the report without re-running the existing prefetch analysis.
    let rows = if std::env::var_os("MRC_RETENTION_ONLY").is_some() {
        sweep_retention(&trace, &caps)
    } else {
        match block_bytes {
            Some(_) => sweep_blocks(&trace, &caps),
            None => sweep(&trace, &caps),
        }
    };

    // CSV. `--no-header` (env MRC_NO_HEADER=1) suppresses the header so rows concatenate cleanly
    // across the corpus (the driver writes one header, then appends each trace). `events`/
    // `block_accesses` let the cap-64 slice reproduce the report's cap64.csv columns:
    // `events` is raw input ops, `block_accesses` is the hit_rate DENOMINATOR (Op::Get only),
    // so `hits = hit_rate * block_accesses` reconstructs exactly.
    if std::env::var_os("MRC_NO_HEADER").is_none() {
        println!(
            "trace,events,block_accesses,predictor,cap,hit_rate,pf_precision,pf_per_access,\
             net_savings,pf_latency"
        );
    }
    for r in rows {
        println!(
            "{trace_id},{events},{block_accesses},{},{},{:.4},{:.4},{:.4},{:.4},{:.4}",
            r.predictor, r.cap, r.hit_rate, r.pf_precision, r.pf_per_access, r.net_savings,
            r.pf_latency
        );
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{cap_ladder, parse_cap_pin, parse_max_cap, DEFAULT_MAXCAP};
    use s3tap_replay::env::max_events as parse_max_events;

    #[test]
    fn cap_pin_rejects_present_but_invalid_values() {
        assert_eq!(parse_cap_pin(None), Ok(None));
        assert_eq!(parse_cap_pin(Some("64")), Ok(Some(64)));
        assert_eq!(parse_cap_pin(Some(" 64 ")), Ok(Some(64)));
        // Every one of these used to fall back to the FULL ladder in silence, which is how a
        // corpus driver ends up with ~120 rows per trace in the aggregate CSV instead of 10.
        for bad in ["1", "0", "64x", "abc", "", "-1"] {
            assert!(parse_cap_pin(Some(bad)).is_err(), "MRC_CAP='{bad}' must be rejected");
        }
    }

    #[test]
    fn max_events_rejects_present_but_unparseable_values_and_zero_means_uncapped() {
        assert_eq!(parse_max_events(None), Ok(usize::MAX));
        assert_eq!(parse_max_events(Some("0")), Ok(usize::MAX));
        assert_eq!(parse_max_events(Some("1000")), Ok(1000));
        assert_eq!(parse_max_events(Some(" 1000 ")), Ok(1000));
        // Used to silently fall back to unbounded (`usize::MAX`) on any of these, the same
        // bug class MRC_CAP/MRC_MAXCAP were fixed for in this same file.
        for bad in ["1O00", "abc", "-1", "1.5"] {
            assert!(parse_max_events(Some(bad)).is_err(), "S3TAP_MAX='{bad}' must be rejected");
        }
    }

    #[test]
    fn max_cap_errors_on_garbage_but_floors_small_values() {
        assert_eq!(parse_max_cap(None), Ok(DEFAULT_MAXCAP));
        assert_eq!(parse_max_cap(Some("512")), Ok(512));
        assert_eq!(parse_max_cap(Some("0")), Ok(2)); // documented floor, not a fall-back
        assert_eq!(parse_max_cap(Some("1")), Ok(2));
        assert!(parse_max_cap(Some("4096x")).is_err());
        assert!(parse_max_cap(Some("")).is_err());
    }

    fn ev(i: u64, op: s3tap_replay::trace::Op, id: &str) -> s3tap_replay::trace::NormEvent {
        s3tap_replay::trace::NormEvent {
            ts_ns: i,
            op,
            object_id: id.to_string(),
            range: None,
            size: None,
            version: None,
            status: None,
        }
    }

    #[test]
    fn ladder_respects_the_ceiling() {
        use s3tap_replay::trace::Op;
        let trace: Vec<s3tap_replay::trace::NormEvent> =
            (0..300).map(|i| ev(i, Op::Get, &format!("k{i}"))).collect();
        assert_eq!(*cap_ladder(&trace, 4096).last().unwrap(), 300);
        assert_eq!(*cap_ladder(&trace, 64).last().unwrap(), 64);
    }

    #[test]
    fn ladder_counts_only_the_keys_a_cache_can_hold() {
        // Since `to_blocks` began forwarding writes as per-chunk invalidations, a chunk
        // that is only ever WRITTEN appears in the expanded trace. It is never a cache
        // key (the sweep inserts only on Op::Get), so counting it stretched the ladder
        // top past anything the sweep could fill and disagreed with `analyze`'s ladder
        // on the same trace.
        use s3tap_replay::trace::Op;
        let mut trace: Vec<s3tap_replay::trace::NormEvent> =
            (0..100).map(|i| ev(i, Op::Get, &format!("k{i}"))).collect();
        trace.extend((0..500).map(|i| ev(1000 + i, Op::Put, &format!("w{i}"))));
        trace.extend((0..40).map(|i| ev(2000 + i, Op::Head, &format!("h{i}"))));
        assert_eq!(*cap_ladder(&trace, 4096).last().unwrap(), 100);
    }
}
