//! Task 4: request-pattern advisories.
//!
//! 4a HEAD-then-GET: the SDK `exists()`-then-read pattern — two round trips
//! where one GET suffices. Matching is pinned and deterministic: per OBJECT,
//! HEADs in ascending ts claim the not-yet-consumed GETs in (t, t+1s]; exactly
//! one -> a 1:1 pair (flagged), two or more -> the legitimate sizing-then-
//! ranged-fan-out (exempt), zero -> unpaired. Object identity is
//! `(bucket, key_hash)` — the hash covers the object KEY only, so the same file
//! name in two buckets is two objects (the identity `s3tap-replay`'s adapter and
//! the throttling check use).
//!
//! 4b small-object storm: per-request overhead dominates when objects are tiny.
//! Both sums run over one IDENTICAL judged set (200-GETs with both ttfb and
//! download present) — mismatched sets would bias the comparison. The median
//! size is only judged when most of that set actually carries a
//! `Content-Length` (`SIZE_COVERAGE_FLOOR`); below it the verdict would rest on
//! a handful of sized ops, so the check goes `Unjudged`.

use std::collections::BTreeMap;

use s3tap_doctor::Record;
use s3tap_schema::{
    Delimitation, Domain, Finding, FindingScope, MetricValue, Sample, SampleKind, Severity,
    TimeWindow, Unit,
};

use crate::checks::caching::SIZE_COVERAGE_FLOOR;
use crate::fields::{advisory, Src};

// 4a gates.
const PAIR_WINDOW_NS: u64 = 1_000_000_000;
const MIN_PAIRS: usize = 20;
const PAIR_RATIO_FLOOR: f64 = 0.2;
/// Beyond this share of paired HEADs missing `total_ns` the round-trip cost
/// can't be quantified honestly, so the finding goes `Unjudged` rather than
/// reading the missing timing as zero waste (same rule as `churn::judge_pid`).
const MAX_UNTIMED_FRAC: f64 = 0.20;

/// Object identity: bucket + key hash. `bucket` is `None` when the SNI/Host join
/// failed — those ops group together, which is the best identity the capture has.
type ObjId<'a> = (Option<&'a str>, &'a str);
// 4b gates.
const MIN_TINY_GETS: usize = 1000;
const TINY_MEDIAN_CEIL: u64 = 256 << 10; // 256 KiB
const OVERHEAD_FLOOR_NS: u64 = 10_000_000_000; // 10 s accumulated ttfb
const MAX_DROPPED_FRAC: f64 = 0.20;

pub(crate) fn check_head_then_get(records: &[Record]) -> Vec<Finding> {
    // pid -> object -> (heads (ts, total_ns), gets ts) with ts present (ordering key).
    type Heads = Vec<(u64, Option<u64>)>;
    let mut by_pid: BTreeMap<u32, BTreeMap<ObjId, (Heads, Vec<u64>)>> = BTreeMap::new();
    let mut per_pid_gets: BTreeMap<u32, usize> = BTreeMap::new();
    let mut per_pid_heads: BTreeMap<u32, usize> = BTreeMap::new();
    for r in records {
        if let Record::Operation(o) = r {
            let (Some(key), Some(ts)) = (o.key_hash.as_deref(), o.ts_ns) else { continue };
            let obj = (o.bucket.as_deref(), key);
            // A `partial` op enters BOTH the per-pid counts and the per-object pairing, and
            // is kept out of the TIMING only. Two separate defects taught this:
            //
            // Dropping it from `per_pid_gets` inflates `pairs/gets` — that is the denominator
            // the PAIR_RATIO_FLOOR gate divides by — so 30 clean pairs beside 200 partial GETs
            // read as 30/30 and exited 1 under `--strict` on a true ratio of 0.13.
            //
            // Dropping it from `by_pid` is worse and less obvious: `obj_gets` is not a timing
            // input, it decides the FAN-OUT EXEMPTION. One GET after a HEAD is a flagged pair;
            // two or more is the legitimate size-then-ranged-read pattern and is exempt.
            // Removing a partial GET turns the second into the first, so marking ONE GET of an
            // exempt 25-object fan-out `partial` — nothing about the request changed —
            // manufactured 25 pairs and an Advisory that gates `--strict`.
            //
            // The pairing is request-side: both request writes were observed regardless of
            // what happened to the response. Only the duration the finding quotes is
            // untrustworthy, and that takes the same `None` path `Ambiguous` already takes,
            // landing in `untimed_pairs` where the coverage gate decides.
            match o.s3_op.as_deref() {
                Some("HeadObject") => {
                    // An AMBIGUOUS op carries no usable duration even when `total_ns` is
                    // populated: a second request raced this one, so the response those
                    // nanoseconds were measured to may belong to the other request. The
                    // pairing itself is request-side and survives that (both request writes
                    // were observed), so the HEAD still counts as a pair — its TIMING does
                    // not. Feeding it through the same `None` path a missing duration takes
                    // means it lands in `untimed_pairs` and the coverage gate below decides,
                    // rather than the population silently shrinking under `MIN_PAIRS` and the
                    // check going quiet with no trace of why.
                    let timed = match (o.partial, o.delimitation) {
                        (false, Delimitation::Clean) => o.total_ns,
                        _ => None,
                    };
                    *per_pid_heads.entry(o.app.pid).or_default() += 1;
                    by_pid.entry(o.app.pid).or_default().entry(obj).or_default().0.push((ts, timed));
                }
                Some("GetObject") => {
                    *per_pid_gets.entry(o.app.pid).or_default() += 1;
                    by_pid.entry(o.app.pid).or_default().entry(obj).or_default().1.push(ts);
                }
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    for (&pid, objs) in &by_pid {
        let gets = *per_pid_gets.get(&pid).unwrap_or(&0);
        let mut pairs = 0usize;
        let mut untimed_pairs = 0usize;
        let mut wasted_ns: u64 = 0;
        for (heads, obj_gets) in objs.values() {
            let mut heads = heads.clone();
            let mut obj_gets = obj_gets.clone();
            heads.sort_unstable();
            obj_gets.sort_unstable();
            let mut consumed = vec![false; obj_gets.len()];
            // Both sequences are ascending, so the first still-claimable GET only
            // moves FORWARD: a GET at or before this HEAD is unclaimable by it and
            // by every later HEAD, and a consumed GET stays consumed. One monotone
            // cursor makes this O(heads + gets); the old per-HEAD rescan (plus a
            // Vec per HEAD) was O(heads x gets), so a 500K capture with ~250K HEADs
            // and ~250K GETs on one object hung `advise` for hours on a file the
            // doctor handles in seconds (checks/service.rs guards the same shape).
            let mut cursor = 0usize;
            for &(h, h_total) in &heads {
                cursor = cursor.max(obj_gets.partition_point(|&g| g <= h));
                while cursor < obj_gets.len() && consumed[cursor] {
                    cursor += 1;
                }
                // Every unconsumed GET in the window is consumed either way (one
                // -> a flagged 1:1 pair; two or more -> the legitimate
                // sizing-then-ranged fan-out, exempt), so count and mark in one
                // forward walk and let the count pick the branch.
                let hi = h.saturating_add(PAIR_WINDOW_NS);
                let mut claimed = 0usize;
                let mut j = cursor;
                while j < obj_gets.len() && obj_gets[j] <= hi {
                    if !consumed[j] {
                        consumed[j] = true;
                        claimed += 1;
                    }
                    j += 1;
                }
                if claimed == 1 {
                    pairs += 1;
                    // The waste is the redundant HEAD's own round trip (its
                    // total_ns), NOT the HEAD->GET gap — the gap includes
                    // arbitrary client think time and can overstate 10-30x.
                    match h_total {
                        // saturating: record durations are unvalidated input.
                        Some(t) => wasted_ns = wasted_ns.saturating_add(t),
                        // A missing duration must NEVER read as zero waste (it
                        // would fabricate "~0 ms of extra round trips"); count it
                        // and let the coverage gate below decide.
                        None => untimed_pairs += 1,
                    }
                }
            }
        }
        if pairs < MIN_PAIRS || gets == 0 || (pairs as f64 / gets as f64) < PAIR_RATIO_FLOOR {
            continue;
        }
        let ts_all: Vec<u64> = objs
            .values()
            .flat_map(|(h, g)| h.iter().map(|(ts, _)| *ts).chain(g.iter().copied()))
            .collect();
        let window = TimeWindow {
            ts_start: ts_all.iter().copied().min().unwrap_or(0),
            ts_end: ts_all.iter().copied().max().unwrap_or(0),
        };
        let judged = gets + per_pid_heads.get(&pid).copied().unwrap_or(0);
        if untimed_pairs as f64 > MAX_UNTIMED_FRAC * pairs as f64 {
            // Paired by count, but the timing to price the extra round trips is
            // missing: Unjudged, never a fabricated ~0 ms.
            out.push(advisory(
                "advisor-head-then-get",
                Src::Ops,
                Domain::Client,
                Severity::Unjudged,
                "HEAD-then-GET pairs (cost unquantifiable)",
                format!(
                    "pid {pid}: {pairs} HEAD-then-GET pairs, but {untimed_pairs} of those HEADs \
                     carry no usable duration (no total_ns, or one measured across an ambiguous \
                     request/response pairing) — the extra round-trip time cannot be honestly \
                     quantified from this capture."
                ),
                "head_get_pairs",
                Some(MetricValue::Num(pairs as f64)),
                Unit::Count,
                format!(
                    "pairs >= {MIN_PAIRS}, pairs/gets >= {PAIR_RATIO_FLOOR}, timing missing on \
                     > 20% of paired HEADs"
                ),
                FindingScope { app_pid: Some(pid), ..Default::default() },
                window,
                Sample { judged, excluded: untimed_pairs, kind: SampleKind::Operation },
            ));
            continue;
        }
        let untimed_clause = if untimed_pairs > 0 {
            format!("; {untimed_pairs} paired HEADs carry no usable timing and are excluded")
        } else {
            String::new()
        };
        out.push(advisory(
            "advisor-head-then-get",
            Src::Ops,
            Domain::Client,
            Severity::Advisory,
            "HEAD-then-GET pairs",
            format!(
                "pid {pid}: {pairs} HEAD-then-GET pairs (~{:.0} ms of extra round \
                 trips{untimed_clause}). GET \
                 returns the same metadata in its response headers — drop the HEAD and handle the \
                 error path. (If the HEAD sizes a ranged download, s3tap cannot see the Range \
                 header — verify before changing; one-HEAD-to-many-GETs fan-outs are already \
                 exempted.)",
                wasted_ns as f64 / 1e6
            ),
            "head_get_pairs",
            Some(MetricValue::Num(pairs as f64)),
            Unit::Count,
            format!("pairs >= {MIN_PAIRS}, pairs/gets >= {PAIR_RATIO_FLOOR}"),
            FindingScope { app_pid: Some(pid), ..Default::default() },
            window,
            Sample { judged, excluded: untimed_pairs, kind: SampleKind::Operation },
        ));
    }
    out
}

pub(crate) fn check_small_objects(records: &[Record]) -> Vec<Finding> {
    // pid -> judged 200-GETs (ttfb, download, size, ts) + dropped count + the WHOLE
    // population's [min, max] ts. The span has to be tracked separately because the Unjudged
    // branches below fire exactly when `judged` is empty, and deriving the window from
    // `judged` there published `{0, 0}` — indistinguishable from a real window starting at
    // boot, since 0 is a legal boot-relative monotonic value.
    type Pop = (Vec<(u64, u64, Option<u64>, u64)>, usize, Option<(u64, u64)>);
    let mut by_pid: BTreeMap<u32, Pop> = BTreeMap::new();
    for r in records {
        if let Record::Operation(o) = r {
            if o.s3_op.as_deref() != Some("GetObject") || o.http_status != Some(200) {
                continue;
            }
            let e = by_pid.entry(o.app.pid).or_default();
            if let Some(ts) = o.ts_ns {
                e.2 = Some(match e.2 {
                    None => (ts, ts),
                    Some((lo, hi)) => (lo.min(ts), hi.max(ts)),
                });
            }
            // A `partial` op is IN the population and DROPPED from the timing math, not
            // skipped outright. It is a 200-GET this pid really issued; what the capture
            // lost is the end of it. `continue`ing here erased it from both sides of
            // `MAX_DROPPED_FRAC`, so a capture that truncated 90% of its GETs still
            // published a confident overhead share computed from the surviving 10% and
            // said nothing about the other 90%. Falling through leaves it to the timing
            // match below, which routes a missing ttfb/download into `dropped` exactly as
            // it does for an ambiguous op — same reason, same destination.
            // Unlike 4a there is nothing request-side to keep here: this check is ENTIRELY
            // timing (the overhead share is ttfb summed against download). An ambiguous op's
            // ttfb and download were measured against a response that may belong to the
            // request that raced it, so it joins the dropped bucket rather than the judged
            // set — which routes it through `MAX_DROPPED_FRAC` into an honest Unjudged
            // instead of quietly biasing the overhead share it would otherwise contribute to.
            // `!o.partial` as well as Clean, matching `s3tap_doctor::is_eligible` — the one
            // definition of a timeable op this workspace allows. Dropping the `partial` guard
            // at the top of the loop was right (those ops belong in the POPULATION), but
            // relying on the timing match below to catch them was not: `partial` does not
            // mean "the capture ended mid-op". `correlate.rs` sets it as
            // `conn.is_none() || head_truncated || resp.truncated`, and the dominant cause —
            // no (tgid,fd)->cookie join — leaves the op FULLY TIMED, because ttfb/download are
            // op-local TLS timestamps (see `partial_join_op_still_measures_ttfb`). So a
            // 100%-partial capture sailed into `judged` and published a confident "95% of the
            // request time went to per-request overhead" beside a sibling check reporting
            // "1500 of 1500 GETs lack clean timing", and `advise --strict` exited 1 on it.
            let clean = o.delimitation == Delimitation::Clean && !o.partial;
            match (o.ttfb_ns, o.download_ns) {
                (Some(t), Some(d)) if clean => {
                    e.0.push((t, d, o.content_length, o.ts_ns.unwrap_or(0)))
                }
                _ => e.1 += 1,
            }
        }
    }

    let mut out = Vec::new();
    for (&pid, (judged, dropped, span)) in &by_pid {
        let window_all = TimeWindow {
            ts_start: span.map_or(0, |(lo, _)| lo),
            ts_end: span.map_or(0, |(_, hi)| hi),
        };
        let total = judged.len() + dropped;
        // Population gate on the WHOLE set, then the coverage gate, then the judged floor —
        // the order `check_serial_requests` already uses. Gating on `judged` FIRST undid the
        // point of routing ambiguous ops into `dropped`: moving them there shrank `judged`
        // below the minimum, so the check `continue`d and fell silent instead of reaching the
        // Unjudged branch below. A pid between ~1000 and ~5000 tiny GETs with just over 20%
        // ambiguity — a client racing requests on a pooled connection — hit exactly that.
        if total < MIN_TINY_GETS {
            continue;
        }
        if *dropped as f64 > MAX_DROPPED_FRAC * total as f64 {
            out.push(advisory(
                "advisor-small-objects",
                Src::Ops,
                Domain::Client,
                Severity::Unjudged,
                "small-object analysis (unjudgeable)",
                format!(
                    "pid {pid}: {dropped} of {total} GETs lack ttfb/download timing — the \
                     overhead share cannot be judged from this capture."
                ),
                "dropped_frac",
                Some(MetricValue::Num(*dropped as f64 / total as f64)),
                Unit::Ratio,
                format!("> {MAX_DROPPED_FRAC:.0}% of ops dropped from timing math"),
                FindingScope { app_pid: Some(pid), ..Default::default() },
                window_all,
                Sample { judged: judged.len(), excluded: *dropped, kind: SampleKind::Operation },
            ));
            continue;
        }
        if judged.len() < MIN_TINY_GETS {
            continue;                 // enough ops overall, too few timed ones to judge
        }
        let mut sizes: Vec<u64> = judged.iter().filter_map(|(_, _, s, _)| *s).collect();
        // The whole verdict turns on the median size, so it needs the same size
        // coverage the caching check demands before it sizes anything. Without
        // this gate 3 sized ops out of 1500 chunked-transfer GETs of 4 MiB objects
        // decided "median 1 KB — pack small objects".
        let sizeless = judged.len() - sizes.len();
        let coverage = sizes.len() as f64 / judged.len() as f64;
        if coverage < SIZE_COVERAGE_FLOOR {
            out.push(advisory(
                "advisor-small-objects",
                Src::Ops,
                Domain::Client,
                Severity::Unjudged,
                "small-object analysis (unjudgeable)",
                format!(
                    "pid {pid}: {sizeless} of {} judged GETs carry no Content-Length — the object \
                     size distribution cannot be judged from this capture (chunked transfers and \
                     unseen response heads leave the size out).",
                    judged.len()
                ),
                "size_coverage",
                Some(MetricValue::Num(coverage)),
                Unit::Ratio,
                format!("size coverage < {SIZE_COVERAGE_FLOOR}"),
                FindingScope { app_pid: Some(pid), ..Default::default() },
                TimeWindow {
                    ts_start: judged.iter().map(|(_, _, _, ts)| *ts).min().unwrap_or(0),
                    ts_end: judged.iter().map(|(_, _, _, ts)| *ts).max().unwrap_or(0),
                },
                Sample { judged: judged.len(), excluded: sizeless, kind: SampleKind::Operation },
            ));
            continue;
        }
        sizes.sort_unstable();
        let median_size = sizes[sizes.len() / 2];
        if median_size > TINY_MEDIAN_CEIL {
            continue;
        }
        // saturating: ttfb/download are unvalidated record durations — a crafted
        // capture asserting near-u64::MAX spans must not panic (debug) / wrap
        // (release) into an arbitrary overhead percentage.
        let sum_ttfb: u64 = judged.iter().fold(0u64, |a, (t, _, _, _)| a.saturating_add(*t));
        let sum_dl: u64 = judged.iter().fold(0u64, |a, (_, d, _, _)| a.saturating_add(*d));
        if sum_ttfb < sum_dl || sum_ttfb < OVERHEAD_FLOOR_NS {
            continue;
        }
        let overhead_frac = sum_ttfb as f64 / sum_ttfb.saturating_add(sum_dl).max(1) as f64;
        out.push(advisory(
            "advisor-small-objects",
            Src::Ops,
            Domain::Client,
            Severity::Advisory,
            "small-object storm",
            format!(
                "pid {pid}: {} GETs with median size {} KB — {:.0}% of the request time went to \
                 per-request overhead, not data. Pack small objects (tar/parquet/manifest) or \
                 batch reads; each request costs ~1 RTT + a request fee regardless of size.",
                judged.len(),
                median_size >> 10,
                overhead_frac * 100.0
            ),
            "overhead_fraction",
            Some(MetricValue::Num(overhead_frac)),
            Unit::Ratio,
            format!(
                "gets >= {MIN_TINY_GETS}, median <= 256 KiB, sum(ttfb) >= sum(download), \
                 sum(ttfb) >= 10 s"
            ),
            FindingScope { app_pid: Some(pid), ..Default::default() },
            window_all,
            // Sizeless ops still feed the timing sums but not the median, so they
            // count as excluded (refetch.rs's convention for missing sizes).
            Sample {
                judged: judged.len(),
                excluded: *dropped + sizeless,
                kind: SampleKind::Operation,
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {

    #[test]
    fn truncated_gets_are_dropped_from_the_math_not_erased_from_the_population() {
        // 1200 clean tiny GETs is on its own enough to clear MIN_TINY_GETS, so skipping the
        // 2000 truncated ones outright published a confident "95% overhead, pack small
        // objects" verdict computed from 37% of the GETs this pid actually issued — with
        // nothing in the output saying so. A `partial` op is in the population and dropped
        // from the timing math, which is what MAX_DROPPED_FRAC exists to notice.
        let mut recs: Vec<Record> = (0..1200u32)
            .map(|i| fixtures::op(9, 7000, i, u64::from(i) * 1_000_000, 40_000_000,
                                  "GetObject", &format!("k{i}"), 200, Some(8192)))
            .collect();
        for i in 0..2000u32 {
            let mut r = fixtures::op(9, 7000, 1200 + i, u64::from(1200 + i) * 1_000_000,
                                     40_000_000, "GetObject", &format!("t{i}"), 200, None);
            if let Record::Operation(o) = &mut r {
                o.partial = true;
                o.ttfb_ns = None;
                o.download_ns = None;
            }
            recs.push(r);
        }
        let f = check_small_objects(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(matches!(f[0].severity, Severity::Unjudged), "{:?}", f[0].severity);
        assert_eq!(f[0].sample.excluded, 2000, "{:?}", f[0].sample);
        assert!(f[0].summary.contains("2000 of 3200"), "{}", f[0].summary);
    }
    use super::*;
    use crate::fixtures;

    #[test]
    fn adversarial_timestamp_does_not_overflow_the_pair_window() {
        // A HEAD whose ts is within a hair of u64::MAX: computing the pairing window
        // (h + PAIR_WINDOW_NS) must saturate, not panic (debug) / wrap (release).
        let recs = fixtures::head_then_get("k", u64::MAX - 10, 5);
        let _ = check_head_then_get(&recs); // must not panic
    }

    #[test]
    fn one_to_one_pairs_fire() {
        let mut recs = Vec::new();
        for i in 0..30u64 {
            recs.extend(fixtures::head_then_get(&format!("k{i}"), i * 3_000_000_000, 200_000_000));
        }
        let f = check_head_then_get(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-head-then-get");
    }

    #[test]
    fn ranged_fanout_is_exempt() {
        let mut recs = Vec::new();
        for i in 0..30u64 {
            recs.extend(fixtures::head_then_ranged_fanout(&format!("k{i}"), i * 10_000_000_000, 4));
        }
        assert!(check_head_then_get(&recs).is_empty(), "fan-outs must be exempt");
    }

    #[test]
    fn tiny_get_storm_fires() {
        let recs = fixtures::tiny_gets(5, 1500, 32 << 10); // 1500 x 32 KB, ttfb-dominated
        let f = check_small_objects(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-small-objects");
        assert!(matches!(f[0].value, Some(MetricValue::Num(v)) if v > 0.5));
    }

    #[test]
    fn dropped_timing_beyond_20pct_goes_unjudged() {
        let mut recs = fixtures::tiny_gets(5, 1500, 32 << 10);
        for (i, r) in recs.iter_mut().enumerate() {
            if i % 3 == 0 {
                if let Record::Operation(o) = r {
                    o.download_ns = None; // a third lack timing
                }
            }
        }
        let f = check_small_objects(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(matches!(f[0].severity, Severity::Unjudged));
    }

    #[test]
    fn healthy_sizes_are_silent() {
        let recs = fixtures::tiny_gets(5, 1500, 4 << 20); // 4 MB objects: size gate blocks
        assert!(check_small_objects(&recs).is_empty());
    }

    #[test]
    fn ambiguous_heads_do_not_price_the_round_trips_they_cannot_measure() {
        // An op flagged `Ambiguous` raced a second request on the same connection, so the
        // response its `total_ns` was measured to may belong to the OTHER request. The crate
        // contract excludes such ops from timing math; this check used to take their
        // durations at face value and bill them as HEAD round-trip waste.
        //
        // The pairing is request-side, so the pairs still COUNT (both request writes were
        // seen). Only the price is withheld, which routes them through the existing coverage
        // gate: past MAX_UNTIMED_FRAC the finding is Unjudged rather than a confident number
        // built on attribution the capture cannot vouch for.
        let mut recs = Vec::new();
        for i in 0..30u64 {
            recs.extend(fixtures::head_then_get(&format!("k{i}"), i * 3_000_000_000, 200_000_000));
        }
        // Baseline: all Clean, so the check prices the waste and speaks with confidence.
        let clean = check_head_then_get(&recs);
        assert_eq!(clean.len(), 1);
        assert!(matches!(clean[0].severity, Severity::Advisory), "{:#?}", clean[0]);
        assert!(clean[0].summary.contains("ms of extra round trips"), "{}", clean[0].summary);

        // Now mark every HEAD ambiguous, changing NOTHING else — the durations stay populated,
        // which is exactly the shape that made this silent.
        for r in recs.iter_mut() {
            if let Record::Operation(o) = r {
                if o.s3_op.as_deref() == Some("HeadObject") {
                    o.delimitation = Delimitation::Ambiguous;
                    assert!(o.total_ns.is_some(), "the fixture must still carry a duration");
                }
            }
        }
        let f = check_head_then_get(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(matches!(f[0].severity, Severity::Unjudged), "{:#?}", f[0]);
        // The pairs are still counted and reported: the pattern was observed, only its cost
        // is unquantifiable. A silently shrunk population would have said nothing at all.
        assert!(matches!(f[0].value, Some(MetricValue::Num(v)) if v >= MIN_PAIRS as f64));
        assert_eq!(f[0].sample.excluded, 30, "every paired HEAD is excluded from timing");
        assert!(!f[0].summary.contains("ms of extra round trips"), "{}", f[0].summary);
    }

    #[test]
    fn ambiguous_gets_leave_the_small_object_overhead_share_unjudged() {
        // 4b is entirely timing (ttfb summed against download), so unlike 4a there is no
        // request-side fact worth keeping: an ambiguous GET joins the dropped bucket. Past
        // MAX_DROPPED_FRAC that is an honest Unjudged instead of an overhead share biased by
        // spans measured against someone else's response.
        let mut recs = fixtures::tiny_gets(5, 1500, 32 << 10);
        let fired = check_small_objects(&recs);
        assert!(matches!(fired[0].severity, Severity::Advisory), "baseline fires confidently");

        for (i, r) in recs.iter_mut().enumerate() {
            if i % 3 == 0 {
                if let Record::Operation(o) = r {
                    // Timing left fully populated. Only the delimitation changes.
                    o.delimitation = Delimitation::Ambiguous;
                }
            }
        }
        let f = check_small_objects(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(matches!(f[0].severity, Severity::Unjudged), "{:#?}", f[0]);
        assert_eq!(f[0].finding_id, "advisor-small-objects");
    }
}
