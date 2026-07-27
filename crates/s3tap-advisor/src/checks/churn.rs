//! Task 1: connection churn. The records carry reuse directly — per pid over
//! `partial == false` GET/PUT ops, `single_shot_frac` is the fraction with
//! `connection_reused == false`, and the wasted time is the summed TCP-connect
//! cost of the fresh connections beyond the first. `tls_handshake_ns` is
//! ~always `None` at this milestone, so the number is TCP-only and the message
//! says the true cost is higher. Fresh ops with no connect timing go
//! `Unjudged` beyond 20% (missing timing must never silently read as 0).

use std::collections::BTreeMap;

use s3tap_doctor::Record;
use s3tap_schema::{
    Domain, Finding, FindingScope, MetricValue, Operation, Sample, SampleKind, Severity,
    TimeWindow, Unit,
};

use crate::fields::{advisory, Src};

const MIN_OPS: usize = 50;
const SINGLE_SHOT_FLOOR: f64 = 0.5;
const WASTED_MS_FLOOR: f64 = 500.0;
// Aggregate (process-per-request fleet) path.
const AGG_MIN_PIDS: usize = 20;
const AGG_SINGLE_SHOT_FLOOR: f64 = 0.8;
const AGG_MIN_FRESH: usize = 100;

pub(crate) fn check_connection_churn(records: &[Record]) -> Vec<Finding> {
    let mut by_pid: BTreeMap<u32, Vec<&Operation>> = BTreeMap::new();
    let mut partial_by_pid: BTreeMap<u32, usize> = BTreeMap::new();
    for r in records {
        if let Record::Operation(o) = r {
            if !matches!(o.s3_op.as_deref(), Some("GetObject" | "PutObject")) {
                continue;
            }
            if o.partial {
                *partial_by_pid.entry(o.app.pid).or_default() += 1;
            }
            // Partial ops stay IN the population, because `n = ops.len()` is the DENOMINATOR
            // of `single_shot_frac = fresh/n`. Dropping reused-but-truncated ops inflates that
            // ratio: 60 reused GETs with truncated heads beside 51 fresh ones is a true share
            // of 51/111 = 0.46, under the floor, and it reported "100% of 51 requests opened a
            // fresh connection" against a pid that had reused 60.
            //
            // They are kept out of the NUMERATOR below, which is the other half of the same
            // rule. `connection_reused` is one of the facts `partial` says was not attributable
            // (it is `req_seq > 0`, and on a truncated op the connection join is exactly what
            // failed), so counting a partial op as "fresh" would invent churn — the mirror of
            // the false warn this direction test exists to prevent. In the denominator, out of
            // the numerator, and out of the timing sums.
            by_pid.entry(o.app.pid).or_default().push(o);
        }
    }

    let mut out = Vec::new();
    let mut all_below_floor = true;
    for (&pid, ops) in &by_pid {
        if ops.len() < MIN_OPS {
            continue;
        }
        all_below_floor = false;
        if let Some(f) = judge_pid(pid, ops, *partial_by_pid.get(&pid).unwrap_or(&0)) {
            out.push(f);
        }
    }

    // Aggregate path: ONLY when every pid is below the per-pid floor (provably
    // mutually exclusive with the per-pid finding), many short-lived pids, and
    // capture-wide churn is extreme.
    if all_below_floor && by_pid.len() >= AGG_MIN_PIDS {
        let all: Vec<&Operation> = by_pid.values().flatten().copied().collect();
        let fresh: Vec<&&Operation> = all.iter().filter(|o| !o.connection_reused && !o.partial).collect();
        let frac = fresh.len() as f64 / all.len().max(1) as f64;
        if fresh.len() >= AGG_MIN_FRESH && frac > AGG_SINGLE_SHOT_FLOOR {
            // The real dropped count, not a literal 0. `partial_by_pid` has held it all along
            // and passing 0 published "every op in this capture was judged" on the one path
            // that is explicitly about a capture too thin to judge per-pid.
            let dropped: usize = partial_by_pid.values().sum();
            let (window, sample) = window_and_sample(&all, dropped);
            out.push(advisory(
                "advisor-connection-churn",
                Src::Ops,
                Domain::Client,
                Severity::Advisory,
                "process-per-request connection churn",
                format!(
                    "{} short-lived processes issued {} requests, {:.0}% on fresh connections — \
                     the process-per-request pattern (e.g. one CLI/lambda per object) pays a TCP+TLS \
                     handshake per request by construction. Batch work into longer-lived processes, \
                     or front them with a shared local proxy/cache.",
                    by_pid.len(),
                    all.len(),
                    frac * 100.0
                ),
                "single_shot_frac",
                Some(MetricValue::Num(frac)),
                Unit::Ratio,
                format!(">= {AGG_MIN_PIDS} pids all < {MIN_OPS} ops, frac > {AGG_SINGLE_SHOT_FLOOR}, fresh >= {AGG_MIN_FRESH}"),
                FindingScope::default(), // capture-scoped: app_pid None
                window,
                sample,
            ));
        }
    }
    out
}

fn judge_pid(pid: u32, ops: &[&Operation], partials: usize) -> Option<Finding> {
    let n = ops.len();
    let fresh: Vec<&&Operation> = ops.iter().filter(|o| !o.connection_reused && !o.partial).collect();
    let single_shot_frac = fresh.len() as f64 / n as f64;
    if single_shot_frac <= SINGLE_SHOT_FLOOR {
        return None;
    }

    // Wasted time: connect cost of fresh connections beyond the earliest one.
    let timed: Vec<&&&Operation> = fresh.iter().filter(|o| o.tcp_connect_ns.is_some()).collect();
    let untimed = fresh.len() - timed.len();
    // No fresh-count qualifier: missing timing must never silently read as 0
    // (the pid already passed the ops >= MIN_OPS gate).
    if untimed as f64 > 0.2 * fresh.len() as f64 {
        // Churny by count, but the timing to quantify it is missing: Unjudged.
        let (window, sample) = window_and_sample(ops, untimed + partials);
        return Some(advisory(
            "advisor-connection-churn",
            Src::Ops,
            Domain::Client,
            Severity::Unjudged,
            "connection churn (impact unquantifiable)",
            format!(
                "pid {pid}: {:.0}% of {n} requests opened a fresh connection, but {untimed} of \
                 {} fresh connections carry no connect timing — the time cost cannot be honestly \
                 quantified from this capture.",
                single_shot_frac * 100.0,
                fresh.len()
            ),
            "single_shot_frac",
            Some(MetricValue::Num(single_shot_frac)),
            Unit::Ratio,
            format!("> {SINGLE_SHOT_FLOOR} single-shot, timing missing on > 20% of fresh ops"),
            FindingScope { app_pid: Some(pid), ..Default::default() },
            window,
            sample,
        ));
    }

    // Sum the connect cost of every timed fresh op, then exclude the single
    // earliest fresh op (by ts over ALL fresh, per the plan) — its cost is
    // subtracted only if it was timed (an untimed earliest contributed 0).
    // saturating: connect/handshake ns are unvalidated record durations — a crafted capture
    // near u64::MAX must not panic (debug) / wrap (release), matching the crate's convention.
    let total_cost: u64 = timed
        .iter()
        .map(|o| o.tcp_connect_ns.unwrap_or(0).saturating_add(o.tls_handshake_ns.unwrap_or(0)))
        .fold(0u64, u64::saturating_add);
    let earliest_cost = fresh
        .iter()
        .min_by_key(|o| o.ts_ns.unwrap_or(u64::MAX))
        .map(|o| o.tcp_connect_ns.unwrap_or(0).saturating_add(o.tls_handshake_ns.unwrap_or(0)))
        .unwrap_or(0);
    let wasted_ms = total_cost.saturating_sub(earliest_cost) as f64 / 1e6;
    if wasted_ms < WASTED_MS_FLOOR {
        return None;
    }

    let (window, sample) = window_and_sample(ops, untimed + partials);
    Some(advisory(
        "advisor-connection-churn",
        Src::Ops,
        Domain::Client,
        Severity::Advisory,
        "connection churn",
        format!(
            "pid {pid}: {:.0}% of {n} requests opened a fresh connection (>= {wasted_ms:.0} ms \
             in TCP connects — TLS handshakes are not yet timed, so the true cost is higher). \
             Modern SDKs keep connections alive by default; this pattern means the client/session \
             object is being recreated, or the process is short-lived. Reuse one client per process \
             and check pool size. (Doctor's `reuse_rate` flags the same signal; this finding adds \
             the time cost.)",
            single_shot_frac * 100.0
        ),
        "wasted_connect_ms",
        Some(MetricValue::Num(wasted_ms)),
        Unit::Ms,
        format!(
            "ops >= {MIN_OPS}, single_shot > {SINGLE_SHOT_FLOOR}, wasted >= {WASTED_MS_FLOOR} ms"
        ),
        FindingScope { app_pid: Some(pid), ..Default::default() },
        window,
        sample,
    ))
}

pub(crate) fn window_and_sample(ops: &[&Operation], excluded: usize) -> (TimeWindow, Sample) {
    let ts: Vec<u64> = ops.iter().filter_map(|o| o.ts_ns).collect();
    let window = TimeWindow {
        ts_start: ts.iter().copied().min().unwrap_or(0),
        ts_end: ts.iter().copied().max().unwrap_or(0),
    };
    let sample = Sample { judged: ops.len(), excluded, kind: SampleKind::Operation };
    (window, sample)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    /// Give fresh ops a connect timing so the impact is quantifiable.
    fn with_connect_timing(mut recs: Vec<Record>, connect_ns: u64) -> Vec<Record> {
        for r in &mut recs {
            if let Record::Operation(o) = r {
                if !o.connection_reused {
                    o.tcp_connect_ns = Some(connect_ns);
                }
            }
        }
        recs
    }

    #[test]
    fn churny_pid_is_flagged_with_time_cost() {
        // 100 GETs, every one a fresh connection at 20 ms connect => ~2 s wasted.
        let recs = with_connect_timing(fixtures::serial_ops(7, 100, 1_000_000_000, 40_000_000), 20_000_000);
        let f = check_connection_churn(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-connection-churn");
        assert!(matches!(f[0].severity, Severity::Advisory));
        assert_eq!(f[0].scope.app_pid, Some(7));
        assert!(f[0].summary.contains("TCP connects"));
    }

    #[test]
    fn warm_pool_is_silent() {
        // High req_seq: everything reused on a couple of connections.
        let recs: Vec<Record> = (0..100u32)
            .map(|i| fixtures::op(7, 1 + u64::from(i % 2), i / 2 + 1, u64::from(i) * 1_000_000,
                                  1_000_000, "GetObject", &format!("k{i}"), 200, Some(1024)))
            .collect();
        assert!(check_connection_churn(&recs).is_empty());
    }

    #[test]
    fn missing_connect_timing_goes_unjudged() {
        // Churny, but no fresh op carries tcp_connect_ns.
        let recs = fixtures::serial_ops(7, 100, 1_000_000_000, 40_000_000);
        let f = check_connection_churn(&recs);
        assert_eq!(f.len(), 1);
        assert!(matches!(f[0].severity, Severity::Unjudged));
    }

    #[test]
    fn partial_ops_are_excluded() {
        let mut recs = with_connect_timing(fixtures::serial_ops(7, 100, 1_000_000_000, 40_000_000), 20_000_000);
        for r in &mut recs {
            if let Record::Operation(o) = r {
                o.partial = true;
            }
        }
        assert!(check_connection_churn(&recs).is_empty());
    }

    #[test]
    fn wasted_math_excludes_the_earliest_connect() {
        // 100 fresh x 20 ms, minus the one unavoidable earliest connect = 1980 ms.
        let recs = with_connect_timing(fixtures::serial_ops(7, 100, 1_000_000_000, 40_000_000), 20_000_000);
        let f = check_connection_churn(&recs);
        assert!(matches!(f[0].value, Some(s3tap_schema::MetricValue::Num(v)) if (v - 1980.0).abs() < 1e-9),
                "{:?}", f[0].value);
    }

    #[test]
    fn small_fresh_set_with_missing_timing_still_goes_unjudged() {
        // Regression: 70 ops, 40 fresh (57% single-shot), 30 of them untimed.
        // The old `fresh >= MIN_OPS` qualifier silently skipped this band.
        let mut recs: Vec<Record> = Vec::new();
        for i in 0..70u32 {
            let fresh = i < 40;
            let mut r = fixtures::op(7, if fresh { 100 + u64::from(i) } else { 50 },
                                     if fresh { 0 } else { i }, u64::from(i) * 1_000_000_000,
                                     40_000_000, "GetObject", &format!("k{i}"), 200, Some(1024));
            if let Record::Operation(o) = &mut r {
                o.connection_reused = !fresh;
                if fresh && i < 10 {
                    o.tcp_connect_ns = Some(20_000_000); // only 10 of 40 timed
                }
            }
            recs.push(r);
        }
        let f = check_connection_churn(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(matches!(f[0].severity, Severity::Unjudged));
    }

    #[test]
    fn mixed_pids_do_not_fire_the_aggregate() {
        // One busy pid (fires per-pid) + 25 tiny pids: the aggregate must stay
        // silent (it requires EVERY pid below the floor).
        let mut recs = with_connect_timing(fixtures::serial_ops(1, 100, 1_000_000_000, 40_000_000), 20_000_000);
        for pid in 2..=26u32 {
            recs.extend(with_connect_timing(
                fixtures::serial_ops(pid, 5, 1_000_000_000, 40_000_000), 20_000_000));
        }
        let f = check_connection_churn(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].scope.app_pid, Some(1), "only the per-pid finding may fire");
    }

    #[test]
    fn process_per_request_fleet_fires_aggregate() {
        // 30 pids x 5 fresh ops each: every pid below MIN_OPS, capture-wide churn.
        let mut recs = Vec::new();
        for pid in 1..=30u32 {
            recs.extend(with_connect_timing(
                fixtures::serial_ops(pid, 5, 1_000_000_000, 40_000_000), 20_000_000));
        }
        let f = check_connection_churn(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-connection-churn");
        assert_eq!(f[0].scope.app_pid, None, "aggregate finding is capture-scoped");
        assert!(f[0].summary.contains("process-per-request"));
    }
}
