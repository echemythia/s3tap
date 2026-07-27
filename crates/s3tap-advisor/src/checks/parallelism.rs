//! Task 2: serial requests (missing parallelism). HTTP/1.1 S3 connections are
//! serial per connection BY CONSTRUCTION, so concurrency is measured per pid
//! ACROSS connections: a sweep-line over `[ts_ns, ts_ns + total_ns]` of the
//! pid's Clean, non-partial GETs (both fields `Some`). The pinned statistic is
//! `overlap_frac` — the fraction of the pid's busy wall-time (union of the
//! intervals) spent at concurrency >= 2 (counting distinct sock_cookies in
//! flight). `busy_time == 0` never reaches the ratio (NaN would hard-error
//! MetricValue's finite-only serializer).

use std::collections::BTreeMap;

use s3tap_doctor::Record;
use s3tap_schema::{
    Delimitation, Domain, Finding, FindingScope, MetricValue, Operation, Sample, SampleKind,
    Severity, Unit,
};

use crate::fields::{advisory, Src};

const MIN_OPS: usize = 50;
const OVERLAP_FRAC_CEIL: f64 = 0.05;
const BUSY_FLOOR_NS: u64 = 10_000_000_000; // 10 s
const BUSY_WINDOW_FRAC: f64 = 0.20;
const MAX_DROPPED_FRAC: f64 = 0.20;

pub(crate) fn check_serial_requests(records: &[Record]) -> Vec<Finding> {
    // The third element is the WHOLE population's [min, max] ts. The Unjudged branch below
    // fires exactly when `ops` is empty, and `window_and_sample` derives its window from
    // `ops` — so a 100%-dropped capture published `{0, 0}`, which a consumer cannot tell from
    // a real window starting at boot (0 is a legal boot-relative monotonic value).
    let mut by_pid: BTreeMap<u32, (Vec<&Operation>, usize, Option<(u64, u64)>)> = BTreeMap::new();
    for r in records {
        if let Record::Operation(o) = r {
            if o.s3_op.as_deref() != Some("GetObject") {
                continue;
            }
            let e = by_pid.entry(o.app.pid).or_default();
            if let Some(ts) = o.ts_ns {
                e.2 = Some(match e.2 {
                    None => (ts, ts),
                    Some((lo, hi)) => (lo.min(ts), hi.max(ts)),
                });
            }
            let judged = !o.partial
                && o.delimitation == Delimitation::Clean
                && o.ts_ns.is_some()
                && o.total_ns.is_some();
            if judged {
                e.0.push(o);
            } else {
                e.1 += 1;
            }
        }
    }

    let mut out = Vec::new();
    for (&pid, (ops, dropped, span)) in &by_pid {
        let total_seen = ops.len() + dropped;
        if total_seen < MIN_OPS {
            continue;
        }
        if *dropped as f64 > MAX_DROPPED_FRAC * total_seen as f64 {
            let window = s3tap_schema::TimeWindow {
                ts_start: span.map_or(0, |(lo, _)| lo),
                ts_end: span.map_or(0, |(_, hi)| hi),
            };
            out.push(advisory(
                "advisor-serial-requests",
                Src::Ops,
                Domain::Client,
                Severity::Unjudged,
                "request concurrency (unjudgeable)",
                format!(
                    "pid {pid}: {dropped} of {total_seen} GETs lack clean timing \
                     (partial/ambiguous/no timestamp) — concurrency cannot be judged."
                ),
                "dropped_frac",
                Some(MetricValue::Num(*dropped as f64 / total_seen as f64)),
                Unit::Ratio,
                format!("> {MAX_DROPPED_FRAC:.0}% of ops dropped from timing math"),
                FindingScope { app_pid: Some(pid), ..Default::default() },
                window,
                Sample { judged: ops.len(), excluded: *dropped, kind: SampleKind::Operation },
            ));
            continue;
        }
        if ops.len() < MIN_OPS {
            continue;
        }
        if let Some(f) = judge_pid(pid, ops, *dropped) {
            out.push(f);
        }
    }
    out
}

fn judge_pid(pid: u32, ops: &[&Operation], dropped: usize) -> Option<Finding> {
    // Sweep-line over interval endpoints; concurrency = distinct cookies in flight.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    enum Kind {
        End,   // process ends before starts at the same instant (half-open intervals)
        Start,
    }
    let mut events: Vec<(u64, Kind, u64)> = Vec::with_capacity(ops.len() * 2);
    for o in ops {
        let (ts, total) = (o.ts_ns.unwrap(), o.total_ns.unwrap());
        // Skip a zero-duration op: its [ts,ts] interval has no concurrency footprint, and
        // including it would leak a PHANTOM in-flight entry — `End` sorts before its own
        // `Start` at the same instant, so the End no-ops and the Start is never removed,
        // inflating concurrency for every later span (and suppressing a real serial finding).
        if total == 0 {
            continue;
        }
        events.push((ts, Kind::Start, o.sock_cookie));
        events.push((ts.saturating_add(total), Kind::End, o.sock_cookie));
    }
    events.sort();

    let mut in_flight: BTreeMap<u64, u32> = BTreeMap::new(); // cookie -> refcount
    let mut busy_ns: u64 = 0;
    let mut overlap_ns: u64 = 0;
    let mut prev_ts: Option<u64> = None;
    for (ts, kind, cookie) in events {
        if let Some(p) = prev_ts {
            let span = ts - p;
            let conc = in_flight.len() as u64;
            if conc >= 1 {
                busy_ns += span;
            }
            if conc >= 2 {
                overlap_ns += span;
            }
        }
        match kind {
            Kind::Start => *in_flight.entry(cookie).or_insert(0) += 1,
            Kind::End => {
                if let Some(c) = in_flight.get_mut(&cookie) {
                    *c -= 1;
                    if *c == 0 {
                        in_flight.remove(&cookie);
                    }
                }
            }
        }
        prev_ts = Some(ts);
    }

    // Gates, in an order that guarantees busy_ns > 0 before the ratio.
    let active_window =
        ops.iter().map(|o| o.ts_ns.unwrap().saturating_add(o.total_ns.unwrap())).max().unwrap_or(0)
            - ops.iter().map(|o| o.ts_ns.unwrap()).min().unwrap_or(0);
    let busy_floor = BUSY_FLOOR_NS.max((BUSY_WINDOW_FRAC * active_window as f64) as u64);
    if busy_ns < busy_floor || busy_ns == 0 {
        return None;
    }
    let overlap_frac = overlap_ns as f64 / busy_ns as f64;
    if overlap_frac >= OVERLAP_FRAC_CEIL {
        return None;
    }

    let mut latencies: Vec<u64> = ops.iter().map(|o| o.total_ns.unwrap()).collect();
    latencies.sort_unstable();
    let med_ms = latencies[latencies.len() / 2] as f64 / 1e6;

    let (window, _) = super::churn::window_and_sample(ops, dropped);
    Some(advisory(
        "advisor-serial-requests",
        Src::Ops,
        Domain::Client,
        Severity::Advisory,
        "requests issued serially",
        format!(
            "pid {pid}: {} requests issued strictly one at a time (~{med_ms:.0} ms each => \
             ~{:.0} s of serialized transfer time — think-time between requests not counted). \
             Issuing them over K parallel connections cuts the transfer time roughly K times.",
            ops.len(),
            busy_ns as f64 / 1e9
        ),
        // Milliseconds with `Unit::Ms`, not seconds with `Unit::None`. The value always WAS a
        // duration, and publishing it unitless made every structured consumer special-case the
        // metric NAME to recover that — the one thing `unit` exists to prevent. The prose above
        // still reads in seconds, which is the right scale for a human looking at ten-second-plus
        // serialized transfer; `ms` is the scale the schema offers that keeps sub-second values
        // representable. The name carries the unit too, so a consumer that keys on either agrees.
        "serialized_busy_ms",
        Some(MetricValue::Num(busy_ns as f64 / 1e6)),
        Unit::Ms,
        format!(
            "ops >= {MIN_OPS}, busy >= max(10 s, {:.0}% of window), overlap < {:.0}%",
            BUSY_WINDOW_FRAC * 100.0,
            OVERLAP_FRAC_CEIL * 100.0
        ),
        FindingScope { app_pid: Some(pid), ..Default::default() },
        window,
        Sample { judged: ops.len(), excluded: dropped, kind: SampleKind::Operation },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn serial_stream_is_flagged() {
        // 100 GETs, 200 ms each, back to back on fresh connections: 20 s busy, serial.
        let recs = fixtures::serial_ops(3, 100, 200_000_000, 200_000_000);
        let f = check_serial_requests(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-serial-requests");
        assert!(matches!(f[0].severity, Severity::Advisory));
        assert!(f[0].summary.contains("serialized transfer time"));
    }

    #[test]
    fn the_headline_metric_carries_its_own_unit() {
        // The value is a DURATION, so it must publish one of the schema's time units rather
        // than `Unit::None`. Unitless forced every structured consumer to special-case the
        // metric name to learn what the number meant, which is the job `unit` exists to do.
        // Name and unit are pinned together: a consumer keying on either must reach the same
        // reading, so they can never be changed apart.
        let recs = fixtures::serial_ops(3, 100, 200_000_000, 200_000_000);
        let f = check_serial_requests(&recs);
        assert_eq!(f[0].metric, "serialized_busy_ms");
        assert_eq!(f[0].unit, Unit::Ms);
        // 100 ops x 200 ms = 20 s busy, so the value must read in MILLISECONDS (20_000),
        // not the seconds it used to publish (20). That is the number a consumer would have
        // silently misread by three orders of magnitude once the unit said `ms`.
        assert!(
            matches!(f[0].value, Some(MetricValue::Num(v)) if (v - 20_000.0).abs() < 1.0),
            "{:?}",
            f[0].value
        );
        // The prose still speaks in seconds, which is the right scale for a human.
        assert!(f[0].summary.contains("~20 s of serialized transfer time"), "{}", f[0].summary);
    }

    #[test]
    fn zero_duration_op_does_not_leak_a_phantom_in_flight() {
        // A serial stream fires the finding. Adding a single instantaneous op (total_ns=0)
        // must not corrupt the concurrency sweep — before the fix its End sorted before its
        // own Start, leaking a phantom in-flight cookie that inflated overlap for every later
        // span and suppressed the finding (false negative).
        let mut recs = fixtures::serial_ops(3, 100, 200_000_000, 200_000_000);
        recs.push(fixtures::op(3, 9999, 0, 50_000_000, 0, "GetObject", "z", 200, Some(1)));
        let f = check_serial_requests(&recs);
        assert_eq!(f.len(), 1, "serial finding must still fire despite a zero-duration op: {f:#?}");
        assert_eq!(f[0].finding_id, "advisor-serial-requests");
    }

    #[test]
    fn parallel_stream_is_silent() {
        // 400 GETs overlapping 4-wide across distinct cookies, one pid.
        let recs = fixtures::parallel_ops(3, 400, 4, 200_000_000);
        assert!(check_serial_requests(&recs).is_empty());
    }

    #[test]
    fn single_cookie_repeats_never_count_as_overlap() {
        // Same cookie, overlapping intervals (physically impossible on HTTP/1.1,
        // but the sweep must not read same-cookie ops as concurrency 2).
        let recs: Vec<Record> = (0..100u32)
            .map(|i| fixtures::op(3, 42, i, u64::from(i) * 100_000_000, 200_000_000,
                                  "GetObject", &format!("k{i}"), 200, Some(1024)))
            .collect();
        let f = check_serial_requests(&recs);
        assert_eq!(f.len(), 1, "same-cookie overlap must still read as serial");
    }

    #[test]
    fn ambiguous_and_untimed_ops_go_unjudged_beyond_20pct() {
        let mut recs = fixtures::serial_ops(3, 100, 200_000_000, 200_000_000);
        for (i, r) in recs.iter_mut().enumerate() {
            if i % 3 == 0 {
                if let Record::Operation(o) = r {
                    o.total_ns = None; // untimed third
                }
            }
        }
        let f = check_serial_requests(&recs);
        assert_eq!(f.len(), 1);
        assert!(matches!(f[0].severity, Severity::Unjudged));
    }

    #[test]
    fn short_busy_time_is_silent() {
        // 60 ops x 1 ms = 60 ms busy: under both floors.
        let recs = fixtures::serial_ops(3, 60, 1_000_000, 1_000_000);
        assert!(check_serial_requests(&recs).is_empty());
    }
}
