//! Byte-capacity caching analysis — the honest sizing path.
//!
//! The count-based sweep (`driver.rs`) measures a cache whose capacity is an
//! object *count*; on real workloads object sizes span orders of magnitude, so
//! "cache N objects" says nothing about the RAM it costs or the egress $ it
//! saves. This module replays the SAME demand LRU (`Sim`) but caps in **bytes**
//! (`NormEvent.size`) and reports two savings axes:
//!
//! - `hit_rate` — fraction of GET *requests* served from cache.
//! - `byte_hit_rate` — fraction of GET *bytes* served from cache (the egress-$
//!   axis; diverges hard from `hit_rate` when the hot set is small — many cheap
//!   requests saved, few expensive bytes).
//!
//! plus `peak_resident`, the real bytes the cache held at its peak — the RAM the
//! count model is blind to.
//!
//! Demand-only (no prefetch), so the `Sim` prefetch-size caveats don't apply.
//! Whole-object: unsized events (`size == None`) default to 1 byte and are
//! negligible only when size coverage is high — the caller (the advisor) gates
//! on coverage before trusting these rows.

use crate::sim::{Access, Sim};
use crate::trace::{NormEvent, Op};

/// One byte-capacity sweep row: a demand LRU's metrics at one byte cap.
#[derive(Debug, Clone)]
pub struct ByteRow {
    /// Cache capacity, in bytes.
    pub cap: u64,
    /// Fraction of GET requests served from cache (request savings).
    pub hit_rate: f64,
    /// Fraction of GET bytes served from cache (egress-$ savings).
    pub byte_hit_rate: f64,
    /// Peak resident bytes — the physical footprint at its high-water mark
    /// (<= cap). This is the RAM the object-count model cannot report.
    pub peak_resident: u64,
}

/// Replay `trace` through a byte-capped demand LRU at each cap in `caps`.
pub fn sweep_bytes(trace: &[NormEvent], caps: &[u64]) -> Vec<ByteRow> {
    caps.iter().map(|&cap| replay_bytes(trace, cap)).collect()
}

fn replay_bytes(trace: &[NormEvent], cap: u64) -> ByteRow {
    let mut sim = Sim::new(cap);
    let (mut accesses, mut hits) = (0u64, 0u64);
    let (mut total_bytes, mut hit_bytes) = (0u64, 0u64);
    let mut peak = 0u64;

    for ev in trace {
        match ev.op {
            Op::Put | Op::Delete => {
                sim.invalidate(&ev.object_id);
                continue;
            }
            Op::Head | Op::Other => continue,
            Op::Get => {}
        }
        // Whole-object size; unsized -> 1 byte (negligible under the caller's
        // coverage gate). A hit serves the object's cached bytes; a miss fetches
        // from origin and inserts it (evicting by bytes to fit).
        let size = ev.size.unwrap_or(1);
        accesses += 1;
        total_bytes = total_bytes.saturating_add(size);
        match sim.access(&ev.object_id, size) {
            Access::Hit { .. } => {
                hits += 1;
                hit_bytes = hit_bytes.saturating_add(size);
            }
            Access::Miss => sim.insert(&ev.object_id, size, false),
        }
        peak = peak.max(sim.used());
    }

    ByteRow {
        cap,
        hit_rate: ratio(hits, accesses),
        byte_hit_rate: ratio(hit_bytes, total_bytes),
        peak_resident: peak,
    }
}

fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 { 0.0 } else { num as f64 / den as f64 }
}

/// Byte-cap ladder: powers of FOUR from a floor up to `total_bytes`, with
/// `total_bytes` appended as the final rung. Every cap is <= the working set, so
/// a knee can never be reported larger than the data it caches. `total_bytes` is
/// the distinct working-set size.
///
/// The floor is `min(1 MiB, total)`, then dropped 4x at a time until the ladder
/// has at least [`MIN_RUNGS`] rungs (bottoming out at 1 byte). Without that, a
/// small working set produced a ONE-RUNG ladder and the knee search then published
/// that single rung as "the knee of the miss-ratio curve" — a claim about smaller
/// cache sizes that were never simulated. Concretely, 5000 GETs over 20 distinct
/// 4 KiB objects gave `[81920]` and the finding "reuse needs ~the full working set
/// (80 KiB), no smaller knee", where a 12 KiB cache captures ~90% of the same
/// reuse. A miss-ratio CURVE needs several points; one point is not a curve.
///
/// Rungs stay powers of four off the floor (round, and comparable run to run)
/// rather than an interpolated geometric fit, so the same working set always
/// yields the same ladder.
pub fn byte_cap_ladder(total_bytes: u64) -> Vec<u64> {
    const MIB: u64 = 1 << 20;
    let total = total_bytes.max(1);
    // Rungs a floor would yield: the powers of four below `total`, plus `total`.
    let rungs = |floor: u64| {
        let (mut n, mut c) = (1usize, floor);
        while c < total {
            n += 1;
            c = c.saturating_mul(4);
        }
        n
    };
    let mut floor = MIB.min(total);
    while floor > 1 && rungs(floor) < MIN_RUNGS {
        floor = (floor / 4).max(1);
    }

    let mut caps = Vec::new();
    let mut c = floor;
    while c < total {
        caps.push(c);
        c = c.saturating_mul(4);
    }
    caps.push(total);
    caps.dedup();
    caps
}

/// How many rungs a byte ladder must have before its shape can be read as a
/// miss-ratio curve. Five gives four intervals between the floor and the working
/// set: enough for "the curve flattens HERE" to mean something. A ladder that
/// cannot reach this even with a 1-byte floor (a working set of a few bytes) is
/// reported by [`byte_cap_ladder`] as-is; the caller gates on `caps.len()`.
pub const MIN_RUNGS: usize = 5;

#[cfg(test)]
mod tests {
    use super::*;

    fn get(id: &str, size: u64) -> NormEvent {
        NormEvent {
            ts_ns: 0,
            op: Op::Get,
            object_id: id.into(),
            range: None,
            size: Some(size),
            version: None,
            status: Some(200),
        }
    }

    #[test]
    fn byte_cap_bounds_residency_and_larger_cap_hits_more() {
        // Four 1 MiB objects cycled. A 2 MiB byte cap holds ~2 of them, so the
        // working set (4 MiB) thrashes; a 4 MiB cap holds all four and the 2nd
        // pass is all hits. Proves capacity is enforced in BYTES.
        const MIB: u64 = 1 << 20;
        let mut trace = Vec::new();
        for _ in 0..50 {
            for o in 0..4 {
                trace.push(get(&format!("o{o}"), MIB));
            }
        }
        let small = &sweep_bytes(&trace, &[2 * MIB])[0];
        let big = &sweep_bytes(&trace, &[4 * MIB])[0];
        assert!(small.peak_resident <= 2 * MIB, "peak {} > 2 MiB", small.peak_resident);
        assert!(big.peak_resident <= 4 * MIB, "peak {} > 4 MiB", big.peak_resident);
        // 4 MiB holds the whole working set -> near-perfect reuse; 2 MiB thrashes.
        assert!(big.hit_rate > 0.9, "big hit {}", big.hit_rate);
        assert!(big.hit_rate > small.hit_rate + 0.3, "big {} vs small {}", big.hit_rate, small.hit_rate);
    }

    #[test]
    fn object_larger_than_cache_flushes_and_never_hits() {
        // A single object bigger than the cache can never be served: on insert,
        // byte eviction flushes it right back out. This is real LRU behavior (an
        // admission policy would bypass it) and must not loop or falsely "hit".
        const MIB: u64 = 1 << 20;
        let trace: Vec<_> = (0..20).map(|_| get("whale", 100 * MIB)).collect();
        let row = &sweep_bytes(&trace, &[4 * MIB])[0];
        assert_eq!(row.hit_rate, 0.0);
        assert!(row.peak_resident <= 4 * MIB);
    }

    #[test]
    fn hit_rate_is_monotonic_in_capacity() {
        const MIB: u64 = 1 << 20;
        // Zipf-ish reuse over 40 objects of varied size.
        let mut trace = Vec::new();
        let mut s = 0x1234_5678u64;
        for _ in 0..4000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let obj = (s % 40) as u32;
            trace.push(get(&format!("o{obj}"), MIB + u64::from(obj) * 64 * 1024));
        }
        let caps = byte_cap_ladder(60 * MIB);
        let rows = sweep_bytes(&trace, &caps);
        for w in rows.windows(2) {
            assert!(
                w[1].hit_rate >= w[0].hit_rate - 1e-9,
                "hit_rate dropped from cap {} ({}) to cap {} ({})",
                w[0].cap, w[0].hit_rate, w[1].cap, w[1].hit_rate
            );
            assert!(w[1].peak_resident <= w[1].cap, "peak exceeds cap");
        }
    }

    #[test]
    fn request_and_byte_savings_diverge_on_tiny_hot_set() {
        // The flip case: a tiny hot object read repeatedly between RARE huge cold
        // one-shots (10 hot reads per whale). Each whale flushes the cache, but
        // the hot object re-warms and is served for the other 9 reads -> high
        // request hit rate; the egress bill (dominated by whale bytes) is barely
        // touched -> near-zero byte hit rate. Requests saved != dollars saved.
        const MIB: u64 = 1 << 20;
        let mut trace = Vec::new();
        for i in 0..500 {
            for _ in 0..10 {
                trace.push(get("hot", 4 * 1024)); // 4 KiB, reused
            }
            trace.push(get(&format!("cold{i}"), 256 * MIB)); // huge, once
        }
        let row = &sweep_bytes(&trace, &[16 * MIB])[0];
        assert!(row.hit_rate > 0.7, "req hit {}", row.hit_rate); // most hot reads served
        assert!(row.byte_hit_rate < 0.01, "byte hit {}", row.byte_hit_rate); // ~0 of the bill
    }

    #[test]
    fn writes_invalidate_in_byte_mode() {
        let mut put = get("k", 1024);
        put.op = Op::Put;
        let trace = vec![get("k", 1024), get("k", 1024), put, get("k", 1024)];
        let row = &sweep_bytes(&trace, &[1 << 20])[0];
        // 3 GET accesses, exactly 1 hit (the 2nd); the PUT invalidates the 3rd.
        assert!((row.hit_rate - 1.0 / 3.0).abs() < 1e-9, "hit_rate {}", row.hit_rate);
    }

    #[test]
    fn ladder_is_powers_of_four_plus_total() {
        const MIB: u64 = 1 << 20;
        let caps = byte_cap_ladder(50 * MIB);
        assert_eq!(*caps.last().unwrap(), 50 * MIB);
        // Powers of four off the floor, strictly increasing, none above the set.
        for w in caps.windows(2) {
            assert!(w[1] > w[0]);
        }
        assert!(caps.iter().all(|&c| c <= 50 * MIB));
        assert!(caps.windows(2).all(|w| w[1] == 50 * MIB || w[1] == w[0] * 4));
        // The floor used to be a flat 1 MiB, which left this ladder 4 rungs long.
        assert_eq!(caps, vec![256 * 1024, MIB, 4 * MIB, 16 * MIB, 50 * MIB]);
    }

    #[test]
    fn ladder_never_exceeds_a_tiny_working_set() {
        // A sub-1-MiB working set must not be floored up to 1 MiB — else the knee
        // would be reported larger than the data it caches.
        let caps = byte_cap_ladder(500 * 1024);
        assert!(caps.iter().all(|&c| c <= 500 * 1024));
        assert_eq!(*caps.last().unwrap(), 500 * 1024);
    }

    #[test]
    fn a_small_working_set_still_gets_a_curve_not_a_single_point() {
        // 20 distinct 4 KiB objects = an 80 KiB working set. The old ladder started
        // at min(1 MiB, total) and stepped by 4, so it was the SINGLE rung [81920];
        // the knee search then published that one point as "the knee of the
        // miss-ratio curve" and the report read "reuse needs ~the full working set
        // (80 KiB), no smaller knee" — a claim about cache sizes never simulated.
        let caps = byte_cap_ladder(20 * 4096);
        assert!(caps.len() >= MIN_RUNGS, "a curve needs several points, got {caps:?}");
        assert_eq!(*caps.last().unwrap(), 20 * 4096);
        assert!(caps.iter().all(|&c| c <= 20 * 4096));

        // And the sweep over it finds the real knee well BELOW the working set: 98% of
        // the accesses cycle over 4 hot objects, so a cache a quarter the size of the
        // working set captures essentially all the reuse. The one-rung ladder could only
        // ever attribute that reuse to the full 80 KiB and report "no smaller knee".
        let trace: Vec<NormEvent> = (0..5000u32)
            .map(|i| {
                let obj = if i % 50 == 49 { 4 + (i / 50) % 16 } else { i % 4 };
                get(&format!("o{obj}"), 4096)
            })
            .collect();
        let rows = sweep_bytes(&trace, &caps);
        let ceiling = rows.iter().map(|r| r.hit_rate).fold(0.0f64, f64::max);
        let knee = rows.iter().find(|r| r.hit_rate >= ceiling * 0.95).expect("a knee");
        assert!(knee.cap < 20 * 4096, "knee {} must be under the working set", knee.cap);
        assert!(knee.hit_rate > 0.9, "knee hit {}", knee.hit_rate);
    }

    #[test]
    fn a_degenerate_working_set_yields_a_short_ladder_the_caller_must_gate_on() {
        // Nothing can produce five rungs between 1 byte and 4 bytes. The ladder says
        // so honestly (it never invents caps above the working set) and the caller
        // gates the knee claim on `caps.len()` rather than the ladder faking a curve.
        assert!(byte_cap_ladder(4).len() < MIN_RUNGS);
        assert_eq!(byte_cap_ladder(1), vec![1]);
    }

    #[test]
    fn accumulation_is_overflow_safe() {
        // Crafted huge sizes summed over many GETs must saturate, not panic/wrap.
        let trace: Vec<_> = (0..8).map(|i| get(&format!("o{i}"), u64::MAX / 4)).collect();
        let row = &sweep_bytes(&trace, &[u64::MAX])[0];
        assert!(row.hit_rate.is_finite() && row.byte_hit_rate.is_finite());
    }
}
