//! Task 5: service-response advisories.
//!
//! 5a throttling: 503s gated on rate + absolute count over a pinned
//! denominator (partial==false ops with a status). Recovery linkage is
//! approximate and same-process: a 503 at t is recovered iff a 2xx from the
//! SAME pid exists on the same pid+bucket+key (or pid+bucket when the 503 has
//! no key) within (t, t+30s] — a recovery is that client's own retry
//! succeeding, so a different process's success on the key does not count.
//! 503s in the trailing 30s never had a full window — recovery-indeterminate,
//! excluded from the unrecovered count; all-indeterminate => Unjudged.
//!
//! 5b high-latency path: grouped by endpoint_ip. `cross_region`/`via_vpce`
//! are plain bools with no "unpopulated" state — only `true` is trusted.
//! Findings: advisor-latency-cross-region (cross_region == true),
//! advisor-latency-high-rtt (min_rtt median >= 50 ms over >= 5 connections in
//! the group, not via_vpce; the Transfer-Acceleration clause is suppressed
//! when the SNI shows s3-accelerate), advisor-latency-unjudged (no usable
//! signal, or a high-RTT VPCe anomaly). Only a PLAUSIBLE min_rtt counts, using
//! the doctor's own bound (`s3tap_doctor::MAX_PLAUSIBLE_RTT_US`): the field
//! comes off untrusted JSONL and carries kernel sentinels.
//!
//! advisor-latency-high-rtt is `Severity::Unjudged`, so it REPORTS the floor and
//! never gates `--strict`. See [`RTT_REPORT_FLOOR_US`].

use std::collections::BTreeMap;

use s3tap_doctor::{Record, MAX_PLAUSIBLE_RTT_US};
use s3tap_schema::{
    Connection, Domain, Finding, FindingScope, MetricValue, Sample, SampleKind, Severity,
    TimeWindow, Unit,
};

use crate::fields::{advisory, Src};

// 5a gates.
const MIN_TOTAL_OPS: usize = 50;
const RATE_FLOOR: f64 = 0.01;
const MIN_503S: usize = 5;
const RECOVERY_WINDOW_NS: u64 = 30_000_000_000;
// 5b gates.
const MIN_CONNS: usize = 5;
/// The min-RTT median at which the path floor is worth SHOWING the operator. It is a
/// reporting trigger, never a gate: the finding it raises is `Severity::Unjudged`, so
/// it can no longer change an exit code.
///
/// 50 ms is an invented number and there is no honest way to make it not one. Latency
/// has no absolute "good" without a baseline, and the RTT floor IS the baseline: it is
/// the quantity every ratio verdict in this workspace is measured against, so nothing
/// is left to judge it by. The doctor reached the same conclusion on the same quantity
/// first — its `path_min_rtt` row is `Mark::Fyi` and can never gate — and the two
/// commands used to disagree in the field: an on-prem client 60 ms from its bucket's
/// region with healthy ~2x-RTT TTFBs got HEALTHY exit 0 from `doctor --strict` ("path
/// RTT stable") and a build-failing exit 1 from `advise --strict` ("High network floor
/// … something is off"), off the same 60 ms. The prose keeps its guidance ("if this
/// client should be co-located, something is off") because that is a useful question to
/// put to an operator. Answering it needs a fact the capture does not contain: where
/// the client is SUPPOSED to be.
const RTT_REPORT_FLOOR_US: u32 = 50_000; // 50 ms

pub(crate) fn check_throttling(records: &[Record]) -> Vec<Finding> {
    // EVERY answered op, `partial` included — the denominator of a rate and the recovery
    // index below are the same set, and both want the whole of it.
    //
    // This was pinned to `partial == false` and that was backwards. The rate's denominator is
    // exactly the place the module contract says never to drop a partial op from: `partial` is
    // dominated by a failed `(tgid,fd)` join, which is a per-CONNECTION property uncorrelated
    // with status, so a capture where one socket joined and another did not skews hard. 5000
    // successful GETs on an unjoined connection beside 40 clean 200s and 20 clean 503s is a
    // true throttle rate of 0.40%, under the floor — and it reported "32.8% of 61 requests",
    // ⚠ Warn, exit 1 under `--strict`.
    //
    // A status is a status whether or not the connection facts joined. What `partial` makes
    // untrustworthy is the connection attribution and the timing, and this check reads
    // neither.
    let mut ops: Vec<(u64, u32, Option<&str>, Option<&str>, u16)> = Vec::new(); // ts, pid, bucket, key, status
    for r in records {
        if let Record::Operation(o) = r {
            if let (Some(ts), Some(st)) = (o.ts_ns, o.http_status) {
                ops.push((ts, o.app.pid, o.bucket.as_deref(), o.key_hash.as_deref(), st));
            }
        }
    }
    let answered = &ops;
    // Every operation record, so `excluded` can name what the rate did NOT cover — the ops
    // that never came back with a status at all. It used to be hardcoded `0`, which denied
    // they existed.
    let op_records =
        records.iter().filter(|r| matches!(r, Record::Operation(_))).count();
    let total = ops.len();
    if total < MIN_TOTAL_OPS {
        return Vec::new();
    }
    let throttled: Vec<&(u64, u32, Option<&str>, Option<&str>, u16)> =
        ops.iter().filter(|(_, _, _, _, st)| *st == 503).collect();
    let rate = throttled.len() as f64 / total as f64;
    if throttled.len() < MIN_503S || rate <= RATE_FLOOR {
        return Vec::new();
    }
    let capture_end = ops.iter().map(|(ts, ..)| *ts).max().unwrap_or(0);

    // Success indexes (sorted ts per linkage key) so recovery lookups are
    // binary searches — the naive per-503 scan is O(n^2) on an adversarial
    // all-503 capture (500K ops -> minutes of hang).
    use std::collections::BTreeMap;
    let mut ok_by_key: BTreeMap<(u32, Option<&str>, Option<&str>), Vec<u64>> = BTreeMap::new();
    let mut ok_by_bucket: BTreeMap<(u32, Option<&str>), Vec<u64>> = BTreeMap::new();
    // Built from EVERY answered op, `partial` included — deliberately a WIDER set than the
    // `ops` denominator above. The two serve opposite roles and so take opposite defaults.
    // `ops` is the rate's denominator, so it stays pinned: a truncated record must not dilute
    // the throttle rate. This index only ever DE-ESCALATES (a hit turns `unrecovered` into
    // `recovered`, Warn into Advisory), so excluding a record from it can only invent a
    // failure. And `partial` does not say the request failed or was imagined: it is
    // `conn.is_none() || head_truncated || resp.truncated`, so a 200 on a partial record is a
    // retry that demonstrably reached the service and came back answered.
    // Building this from `ops` meant a run whose successful retry landed in the capture tail
    // exited 1 under `--strict`, blaming the client for a truncation in our own capture.
    for &(ts2, pid2, b2, k2, st2) in answered {
        // A recovery is any SUCCESS class, judged by the ONE classifier this workspace allows.
        // A local `(200..300)` predicate disagreed with it on the 3xx band, so a 503 retried
        // into a 304 was a success to the doctor and the scorecard but not a recovery here,
        // and `advise --strict` exited 1 on a client whose retry demonstrably worked. The
        // `== 503` scoping above stays, and the finding's own prose discloses it.
        if s3tap_doctor::classify_status(st2) == s3tap_doctor::StatusClass::Success {
            ok_by_key.entry((pid2, b2, k2)).or_default().push(ts2);
            ok_by_bucket.entry((pid2, b2)).or_default().push(ts2);
        }
    }
    for v in ok_by_key.values_mut() {
        v.sort_unstable();
    }
    for v in ok_by_bucket.values_mut() {
        v.sort_unstable();
    }
    let has_ok_in_window = |ts_list: Option<&Vec<u64>>, t: u64| -> bool {
        ts_list.is_some_and(|v| {
            let i = v.partition_point(|&x| x <= t);
            i < v.len() && v[i] <= t.saturating_add(RECOVERY_WINDOW_NS)
        })
    };

    let (mut recovered, mut unrecovered, mut indeterminate) = (0usize, 0usize, 0usize);
    for &&(t, pid, bucket, key, _) in &throttled {
        if t.saturating_add(RECOVERY_WINDOW_NS) > capture_end {
            indeterminate += 1;
            continue;
        }
        let ok = match key {
            Some(_) => has_ok_in_window(ok_by_key.get(&(pid, bucket, key)), t),
            None => has_ok_in_window(ok_by_bucket.get(&(pid, bucket)), t),
        };
        if ok {
            recovered += 1;
        } else {
            unrecovered += 1;
        }
    }

    let severity = if unrecovered > 0 {
        Severity::Warn
    } else if recovered > 0 {
        Severity::Advisory
    } else {
        Severity::Unjudged // every 503 sat in the capture tail
    };
    let window = TimeWindow {
        ts_start: ops.iter().map(|(ts, ..)| *ts).min().unwrap_or(0),
        ts_end: capture_end,
    };
    vec![advisory(
        "advisor-throttling",
        Src::Ops,
        Domain::S3,
        severity,
        "S3 throttling responses",
        format!(
            "{} 503 responses ({:.1}% of {total} requests; {unrecovered} without a later success \
             on the same key — approximate linkage; {indeterminate} with no full 30 s of judged \
             records after them). 503 is usually SlowDown (throttling) but may be ServiceUnavailable \
             (s3_error_code not yet captured). First confirm the SDK's adaptive retry with \
             jittered backoff. If throttling is sustained, spread objects across more key \
             prefixes — S3 auto-partitions prefixes (~3,500 write / 5,500 read req/s each); \
             legacy random-hash prefixes are unnecessary. (Doctor's `s3_throttle` covers 429/503; \
             this finding scopes the 503s and adds rate and recovery analysis.)",
            throttled.len(),
            rate * 100.0
        ),
        "rate_503",
        Some(MetricValue::Num(rate)),
        Unit::Ratio,
        format!("ops >= {MIN_TOTAL_OPS}, rate > {RATE_FLOOR}, count >= {MIN_503S}; Warn iff a full-window unrecovered 503 exists"),
        FindingScope::default(),
        window,
        Sample { judged: total, excluded: op_records - total, kind: SampleKind::Operation },
    )]
}

pub(crate) fn check_latency_path(records: &[Record]) -> Vec<Finding> {
    // Group connections by endpoint_ip (label: region > sni > ip).
    let mut groups: BTreeMap<String, Vec<&Connection>> = BTreeMap::new();
    for r in records {
        if let Record::Connection(c) = r {
            let ip = c.endpoint.endpoint_ip.clone().unwrap_or_else(|| "unknown".into());
            groups.entry(ip).or_default().push(c);
        }
    }

    let mut out = Vec::new();
    for (ip, conns) in &groups {
        let label = conns
            .iter()
            .find_map(|c| c.endpoint.region.clone())
            .or_else(|| conns.iter().find_map(|c| c.tls.sni.clone()))
            .unwrap_or_else(|| ip.clone());
        let window = TimeWindow {
            ts_start: conns.iter().filter_map(|c| c.ts_ns).min().unwrap_or(0),
            ts_end: conns.iter().filter_map(|c| c.ts_ns).max().unwrap_or(0),
        };
        let sample = |judged: usize, excluded: usize| Sample {
            judged,
            excluded,
            kind: SampleKind::Connection,
        };
        // Endpoint groups routinely span processes: attribute to a pid only
        // when the whole group belongs to one, else the finding is
        // capture-scoped (app_pid None).
        let pids: std::collections::BTreeSet<u32> = conns.iter().map(|c| c.app.pid).collect();
        let pid = (pids.len() == 1).then(|| *pids.iter().next().unwrap());

        // Trust only `true` (the bools have no unpopulated state).
        if conns.iter().any(|c| c.endpoint.cross_region) {
            out.push(advisory(
                "advisor-latency-cross-region",
                Src::Conns,
                Domain::Network,
                Severity::Advisory,
                "cross-region access",
                format!(
                    "Cross-region access to {label} confirmed ({} connections). Co-locate the \
                     client with the bucket, or cache locally.",
                    conns.len()
                ),
                "connections",
                Some(MetricValue::Num(conns.len() as f64)),
                Unit::Count,
                "endpoint.cross_region == true".into(),
                FindingScope { region: conns.iter().find_map(|c| c.endpoint.region.clone()), app_pid: pid, ..Default::default() },
                window,
                sample(conns.len(), 0),
            ));
            continue;
        }

        // Same sentinel/plausibility filter as the doctor's `conn_floor_us`/`live_min_rtt`,
        // and the SAME constant, so the two consumers of this untrusted field cannot drift:
        // 0 is the kernel "never sampled" / LRU-evicted sentinel, and anything at or above
        // MAX_PLAUSIBLE_RTT_US is corrupt or crafted (`u32::MAX` is the kernel's own
        // never-sampled marker for min_rtt and any hand-written JSONL line can carry it).
        // Unfiltered, five such records medianed to a 4294967 ms "high network floor" that
        // `advise --strict` failed the build on while `doctor` on the same records saw no
        // floor at all; a `0` was the mirror bug, silently sinking the median below the
        // gate. Rejects fall into `excluded`, so a group made only of sentinels still
        // reaches advisor-latency-unjudged rather than going quiet.
        let mut rtts: Vec<u32> = conns
            .iter()
            .filter_map(|c| c.min_rtt_us.filter(|&v| v != 0 && v < MAX_PLAUSIBLE_RTT_US))
            .collect();
        let excluded = conns.len() - rtts.len();
        if rtts.len() < MIN_CONNS {
            // No usable signal for this group: not silence, not a guess.
            if conns.len() >= MIN_CONNS {
                out.push(advisory(
                    "advisor-latency-unjudged",
                    Src::Conns,
                    Domain::Network,
                    Severity::Unjudged,
                    "network path (unjudgeable)",
                    format!(
                        "{label}: {} connections but only {} carry a usable min_rtt — the path \
                         cannot be judged from this capture.",
                        conns.len(),
                        rtts.len()
                    ),
                    "rtt_samples",
                    Some(MetricValue::Num(rtts.len() as f64)),
                    Unit::Count,
                    format!("usable min_rtt (0 < v < {MAX_PLAUSIBLE_RTT_US} us) on < {MIN_CONNS} connections"),
                    FindingScope { app_pid: pid, ..Default::default() },
                    window,
                    sample(rtts.len(), excluded),
                ));
            }
            continue;
        }
        rtts.sort_unstable();
        let median_us = rtts[rtts.len() / 2];
        if median_us < RTT_REPORT_FLOOR_US {
            continue; // judged fine: silent
        }
        if conns.iter().any(|c| c.endpoint.via_vpce) {
            // A slow VPC endpoint is an anomaly we can't explain: Unjudged, not hidden.
            out.push(advisory(
                "advisor-latency-unjudged",
                Src::Conns,
                Domain::Network,
                Severity::Unjudged,
                "high RTT through a VPC endpoint",
                format!(
                    "{label}: median min-RTT {:.0} ms through a VPC endpoint — a VPCe should be \
                     low-latency; this is anomalous but unjudgeable from the capture.",
                    f64::from(median_us) / 1e3
                ),
                "median_min_rtt_us",
                Some(MetricValue::Num(f64::from(median_us))),
                Unit::Us,
                format!(">= {RTT_REPORT_FLOOR_US} us via vpce"),
                FindingScope { app_pid: pid, ..Default::default() },
                window,
                sample(rtts.len(), excluded),
            ));
            continue;
        }
        let accelerated = conns
            .iter()
            .any(|c| c.tls.sni.as_deref().is_some_and(|s| s.contains("s3-accelerate")));
        let ta_clause = if accelerated {
            " (already using Transfer Acceleration — a high floor despite TA is itself notable)"
        } else {
            " or Transfer Acceleration"
        };
        // Unjudged, not Advisory: this REPORTS the floor and never gates. The floor is
        // the baseline every other latency verdict is measured against, so there is
        // nothing left to judge it by (see RTT_REPORT_FLOOR_US). The guidance stays,
        // because the operator holds the fact the capture doesn't: where the client is
        // meant to sit relative to the bucket.
        out.push(advisory(
            "advisor-latency-high-rtt",
            Src::Conns,
            Domain::Network,
            Severity::Unjudged,
            "network floor (reported, not judged)",
            format!(
                "Network floor to {label} is {:.0} ms min RTT over {} connections (region \
                 unconfirmed). Reported, not judged: an RTT floor is the baseline latency is \
                 measured against, so there is no honest absolute threshold for it and this \
                 never gates --strict (the doctor's `path_min_rtt` row reports the same \
                 quantity as FYI). If this client should be co-located with the bucket, \
                 something is off (VPN/proxy/wrong region); if it is remote by design, a local \
                 cache{ta_clause} is the lever.",
                f64::from(median_us) / 1e3,
                rtts.len()
            ),
            "median_min_rtt_us",
            Some(MetricValue::Num(f64::from(median_us))),
            Unit::Us,
            format!(
                "reported (never gated) when median min_rtt >= {RTT_REPORT_FLOOR_US} us over \
                 >= {MIN_CONNS} connections"
            ),
            FindingScope { app_pid: pid, ..Default::default() },
            window,
            sample(rtts.len(), excluded),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn recovered_503s_are_advisory_not_warn() {
        let recs = fixtures::throttled_ops(600, 10, true);
        let f = check_throttling(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(matches!(f[0].severity, Severity::Advisory), "{:?}", f[0].severity);
    }

    #[test]
    fn unrecovered_503s_warn() {
        let recs = fixtures::throttled_ops(600, 10, false);
        let f = check_throttling(&recs);
        assert_eq!(f.len(), 1);
        assert!(matches!(f[0].severity, Severity::Warn));
    }

    #[test]
    fn a_partial_retry_still_counts_as_a_recovery() {
        // The recovery index is built from EVERY answered op, `partial` included, while the
        // rate's denominator stays pinned to non-partial ones. Truncate the successful
        // retries — a capture that ended mid-body — and the severity must not move: the
        // retry reached the service either way, and only OUR record of it is incomplete.
        // Built from the pinned set instead, all 10 read as unrecovered and this was a Warn,
        // i.e. `advise` blamed the client for a truncation in the capture.
        let mut recs = fixtures::throttled_ops(600, 10, true);
        let mut truncated = 0;
        for r in &mut recs {
            if let Record::Operation(o) = r {
                if o.http_status == Some(200) && o.key_hash.as_deref() == Some("hotkey") {
                    o.partial = true;
                    o.download_ns = None;
                    truncated += 1;
                }
            }
        }
        assert_eq!(truncated, 10, "the fixture must have 10 retries to truncate");
        let f = check_throttling(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(
            matches!(f[0].severity, Severity::Advisory),
            "a truncated retry is still a recovery, got {:?}",
            f[0].severity
        );
        assert!(f[0].summary.contains("0 without a later success"), "{}", f[0].summary);
    }

    #[test]
    fn lone_503_is_silent() {
        let recs = fixtures::throttled_ops(600, 1, false);
        assert!(check_throttling(&recs).is_empty());
    }

    #[test]
    fn cross_region_true_fires() {
        let recs: Vec<Record> = (0..6u64)
            .map(|i| fixtures::conn(1, i, i, Some(2_000), Some("eu-west-1"), true, false))
            .collect();
        let f = check_latency_path(&recs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].finding_id, "advisor-latency-cross-region");
    }

    #[test]
    fn the_rtt_floor_is_reported_and_can_never_gate_strict() {
        // An on-prem client 60 ms from its bucket's region, with a perfectly healthy
        // path otherwise: the doctor reports the same 60 ms as an FYI row and exits 0
        // under --strict, while this finding was Advisory, which `advisory_exit` gates
        // on — so `advise --strict` failed the build on a client that is simply remote
        // by design. The floor is the baseline every latency RATIO is measured against,
        // so an absolute millisecond threshold on it is exactly the invented number the
        // Core discipline forbids. Report it, never judge it.
        let recs: Vec<Record> = (0..6u64)
            .map(|i| fixtures::conn(1, i, i, Some(60_000), None, false, false))
            .collect();
        let f = check_latency_path(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-latency-high-rtt");
        assert!(matches!(f[0].severity, Severity::Unjudged), "{:?}", f[0].severity);
        assert_eq!(f[0].verdict, "unjudged");
        // ops_seen=1: this test is about SEVERITY gating (an Unjudged finding must not gate
        // --strict), not the separate ops_seen==0 gate `advisory_exit` also checks, so a
        // representative nonzero count keeps the two concerns apart.
        assert_eq!(crate::advisory_exit(&f, crate::render::OpPopulation { seen: 1, answered: 1 }, true), 0, "an unjudged floor must not gate --strict");
        // The operator-facing guidance survives the demotion: it is a question for a
        // human who knows where the client is meant to sit, not a verdict.
        assert!(f[0].summary.contains("should be co-located"), "{}", f[0].summary);
        assert!(f[0].summary.contains("Reported, not judged"), "{}", f[0].summary);
    }

    #[test]
    fn high_rtt_fires_and_accelerate_suppresses_ta_advice() {
        let mk = |sni: Option<&str>| -> Vec<Record> {
            (0..6u64)
                .map(|i| {
                    let mut r = fixtures::conn(1, i, i, Some(80_000), None, false, false);
                    if let Record::Connection(c) = &mut r {
                        c.tls.sni = sni.map(Into::into);
                    }
                    r
                })
                .collect()
        };
        let plain = check_latency_path(&mk(None));
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].finding_id, "advisor-latency-high-rtt");
        assert!(plain[0].summary.contains("or Transfer Acceleration"));

        let ta = check_latency_path(&mk(Some("bucket.s3-accelerate.amazonaws.com")));
        assert!(ta[0].summary.contains("already using Transfer Acceleration"));
    }

    #[test]
    fn rtt_sentinels_are_excluded_not_medianed_into_a_verdict() {
        // u32::MAX is the kernel "never sampled" marker for min_rtt and rides in on any
        // hand-written/replayed JSONL line. Medianed, it printed a 4294967 ms "high network
        // floor" and failed `advise --strict` — on records the doctor judges as having no
        // floor at all. The group must fall through to Unjudged with the sentinels counted
        // as excluded, never to advisor-latency-high-rtt.
        let recs: Vec<Record> = (0..6u64)
            .map(|i| fixtures::conn(1, i, i, Some(u32::MAX), None, false, false))
            .collect();
        let f = check_latency_path(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-latency-unjudged");
        assert_eq!((f[0].sample.judged, f[0].sample.excluded), (0, 6));

        // 0 is the mirror sentinel (never sampled / LRU-evicted): it must not sink a real
        // median below the 50 ms gate. 5 genuine 80 ms floors + 4 zeros still fire.
        let recs: Vec<Record> = (0..9u64)
            .map(|i| {
                let rtt = if i < 5 { 80_000 } else { 0 };
                fixtures::conn(1, i, i, Some(rtt), None, false, false)
            })
            .collect();
        let f = check_latency_path(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-latency-high-rtt");
        assert_eq!((f[0].sample.judged, f[0].sample.excluded), (5, 4));
    }

    #[test]
    fn multi_pid_endpoint_group_is_capture_scoped() {
        // One endpoint, connections from several pids: the finding must not be
        // attributed to whichever pid happened to come first.
        let recs: Vec<Record> = (0..6u64)
            .map(|i| fixtures::conn(1 + (i % 3) as u32, i, i, Some(80_000), None, false, false))
            .collect();
        let f = check_latency_path(&recs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].scope.app_pid, None, "multi-pid group must be capture-scoped");
    }

    #[test]
    fn few_rtt_samples_go_unjudged_and_low_rtt_is_silent() {
        // 6 connections, only 2 with rtt -> Unjudged.
        let recs: Vec<Record> = (0..6u64)
            .map(|i| fixtures::conn(1, i, i, (i < 2).then_some(80_000), None, false, false))
            .collect();
        let f = check_latency_path(&recs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].finding_id, "advisor-latency-unjudged");

        // Healthy 2 ms floor -> silent.
        let ok: Vec<Record> = (0..6u64)
            .map(|i| fixtures::conn(1, i, i, Some(2_000), None, false, false))
            .collect();
        assert!(check_latency_path(&ok).is_empty());
    }
}
