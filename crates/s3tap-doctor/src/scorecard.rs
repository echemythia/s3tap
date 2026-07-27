//! The observed-SLO scorecard: a per-`(bucket, s3_op)` rollup of the traffic a
//! capture actually saw. Two outputs on two rails, matching what each consumer wants:
//!
//!   * DESCRIPTIVE `s3tap.scorecard/1` rows — request/error counts, the status mix,
//!     and TTFB p50/p95/p99. Pure telemetry: "here are the numbers", no verdict. This
//!     is the passive analogue of a speedtest — the app's own production latencies,
//!     not a synthetic probe.
//!   * JUDGED `s3tap.finding/1` records — the reliability taxonomy (403/404/400/
//!     throttle[429·503]/5xx and a generic-4xx catch-all, each with tailored advice) and
//!     a tail-shape flag (p99 ≫ p50). These ride the SAME finding rails the doctor and
//!     advisor use, so a fleet gate ingests them uniformly.
//!
//! The split is deliberate: latency has no absolute "good" without a per-group RTT
//! floor, and the project never guesses one — so the percentiles stay descriptive and
//! the ONLY latency judgment made is a within-group tail RATIO (p99/p50), which needs
//! no external baseline. Reliability, by contrast, has an honest gate: an error rate.
//!
//! Everything reuses the doctor's private primitives — [`is_timeable`], [`pctl`],
//! [`median`], [`evidence_of`], and the tail-sample floors — so the scorecard's timing
//! math can't drift from the doctor's. [`is_timeable`] is `is_eligible` intersected with
//! the row's status-carrying denominator (`http_status` present), because `is_eligible`
//! alone admits a status-LESS aborted op that isn't in `ops` — see the population note on
//! `ScorecardRow`. The doctor's latency rows now gate on the same predicate, so the timing
//! SET here is exactly the doctor's per-group latency set, not a subset of it. The STATISTIC
//! matches too: `ttfb_p50_ns` is [`median`], the same primitive the doctor's per-op-class row
//! uses, because agreeing on the population but not on the estimator still yields two answers
//! (nearest-rank p50 of [10 ms, 20 ms] is 10 ms, the median is 15 ms). One capture can no
//! longer yield two different p50s depending on which subcommand read it.

use std::collections::BTreeMap;

use s3tap_schema::{
    Domain, Evidence, Finding, FindingSchemaTag, FindingScope, MetricValue, Sample, SampleKind,
    ScorecardRow, ScorecardSchemaTag, Severity, TimeWindow, Unit, OPERATION_SCHEMA,
};

use crate::{
    classify_status, evidence_of, is_timeable, median, pctl, Operation, Record, StatusClass,
    MIN_P99_SAMPLE,
};

// --- reliability gates (mirrors service.rs: rate AND absolute AND per-group floor) ---
/// Per-group denominator floor: below this a rate is too noisy to judge, so no
/// reliability finding fires (the descriptive row is still emitted).
const MIN_OPS: u64 = 50;
/// A status class must be at least this fraction of the group to be flagged.
const ERR_RATE_FLOOR: f64 = 0.01;
/// …AND at least this many absolute occurrences (a 100% rate over 3 ops is noise).
const MIN_ERRORS: u64 = 5;
// --- tail-shape gate ---
/// p99 must be at least this multiple of p50 to flag a heavy tail. A within-group
/// ratio, so it needs no RTT baseline — a first cut, deliberately lenient.
const TAIL_RATIO_FLOOR: f64 = 10.0;

/// The scorecard: descriptive rows plus the judged findings computed alongside them.
#[derive(Debug, Clone, PartialEq)]
pub struct Scorecard {
    /// One per `(bucket, s3_op)` group, sorted by that key. The `--json` telemetry.
    pub rows: Vec<ScorecardRow>,
    /// Reliability + tail-shape judgments over the same groups. The `--json` gate feed.
    pub findings: Vec<Finding>,
    /// Total `s3tap.operation/1` records in the capture, before the status filter drops
    /// any. Lets `render` tell "no operations captured" (a caps/uprobe issue) apart from
    /// "operations captured, but none carried an HTTP status" (a parse/visibility issue),
    /// so the empty-scorecard message can't misdirect debugging.
    pub ops_seen: u64,
    /// The widest timestamp span in the capture, across EVERY record kind. Taken over all
    /// records rather than the scored ops because the capture that most needs describing is
    /// the one with no scoreable op in it, where an op-only span would be zero-width.
    pub window: TimeWindow,
}

/// A `(bucket, s3_op)` grouping key, built from the SANITIZED values. `None` keeps
/// unclassified traffic visible as its own row rather than silently dropping it.
type GroupKey = (Option<String>, Option<String>);

/// Build the scorecard from a decoded record stream. A pure consumer — no privilege.
#[must_use]
pub fn scorecard(records: &[Record]) -> Scorecard {
    // Group ops by (bucket, s3_op), preserving iteration for evidence.
    let mut groups: BTreeMap<GroupKey, Vec<&Operation>> = BTreeMap::new();
    let mut ops_seen: u64 = 0;
    for r in records {
        if let Record::Operation(o) = r {
            ops_seen += 1;
            // Group on the SANITIZED key, exactly as the doctor's `s3_domain` does. Grouping on
            // the raw value while sanitizing only at render time let two distinct raw keys that
            // scrub to the same text (e.g. `b\u{200b}` and `b\u{200c}`) become two rows and two
            // findings that are byte-identical on screen — indistinguishable to the reader and
            // to anyone matching on the rendered label.
            let key = (
                o.bucket.as_deref().map(s3tap_schema::sanitize_term),
                o.s3_op.as_deref().map(s3tap_schema::sanitize_term),
            );
            groups.entry(key).or_default().push(o);
        }
    }

    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for ((bucket, s3_op), ops) in &groups {
        // Denominator: every op that got an HTTP status — a parsed status IS a real server
        // response, so it counts regardless of capture completeness. This matches the
        // doctor's status-mix population (`s3_domain`'s `by_status`), so the two tools tally
        // the same ops. (Latency below still excludes partials via `is_eligible` — a
        // partial op's TIMING is untrustworthy even when its status isn't.)
        let scored: Vec<&&Operation> = ops.iter().filter(|o| o.http_status.is_some()).collect();
        let n_ops = scored.len() as u64;
        if n_ops == 0 {
            continue; // socket-only group (no op carried a status): nothing to score
        }

        // Status mix over the denominator.
        let mut status_counts: BTreeMap<u16, u64> = BTreeMap::new();
        for o in &scored {
            if let Some(st) = o.http_status {
                *status_counts.entry(st).or_default() += 1;
            }
        }
        let errors: u64 = status_counts.iter().filter(|(&st, _)| st >= 400).map(|(_, &c)| c).sum();
        let error_rate = errors as f64 / n_ops as f64;

        // TTFB percentiles over the doctor's exact TIMING gate ([`is_timeable`] = eligible
        // AND answered). `is_eligible` alone passes a status-LESS op
        // (`http_status.unwrap_or(0) < 400`), i.e. an aborted in-flight request whose ttfb_ns
        // came from a 100-Continue interim — such an op is NOT in this row's `ops` denominator,
        // so timing it here would let `latency_sample` exceed `ops` and make the percentiles
        // describe requests that never got a response. Requiring a status keeps
        // `latency_sample <= ops` by construction and the percentiles over real responses.
        let ttfb: Vec<f64> = ops
            .iter()
            .filter(|o| is_timeable(o))
            .filter_map(|o| o.ttfb_ns)
            .map(|n| n as f64)
            .collect();
        let latency_sample = ttfb.len() as u64;
        // p50 via [`median`], NOT `pctl(…, 50.0)`: the doctor's per-op-class TTFB row medians the
        // same population, and nearest-rank vs mean-of-the-two-middles disagree at small even n
        // ([10 ms, 20 ms] is 15 ms medianed, 10 ms nearest-rank). Two commands reporting a
        // different p50 for the same group is exactly what the population fix above set out to
        // end. `median` is the constrained side of the pair (demo/s3stats.py pins it for the
        // doctor's rows; nothing pins this p50), so aligning onto it is free. p95/p99 stay
        // nearest-rank — a tail estimate must be a value that was actually observed, never an
        // average of two, and no other command reports them.
        let p50 = median(ttfb.clone());
        // p95/p99 only above the tail-sample floors — never sell a small capture's max
        // as a deep-tail estimate.
        let p95 = (ttfb.len() >= crate::MIN_TAIL_SAMPLE).then(|| pctl(ttfb.clone(), 95.0)).flatten();
        let p99 = (ttfb.len() >= MIN_P99_SAMPLE).then(|| pctl(ttfb.clone(), 99.0)).flatten();

        // GET single-stream throughput (body size / download span), same shape as the
        // doctor's s3_throughput row.
        let throughput_bytes_per_s = if s3_op.as_deref() == Some("GetObject") {
            let tputs: Vec<f64> = ops
                .iter()
                .filter(|o| is_timeable(o))
                .filter_map(|o| Some((o.content_length?, o.download_ns?)))
                // `download_ns == 0` is REAL, not hypothetical: the correlator emits it
                // whenever the body is coalesced into the head read (every small object).
                // Dividing by it yields +Inf, which the finite-only `ScorecardRow`
                // serializer rejects — and `scorecard --json` turns that error into a
                // panic. Drop the sample instead: a zero-length span carries no rate.
                .filter(|&(_, dl)| dl > 0)
                .map(|(cl, dl)| cl as f64 / dl as f64 * 1e9) // bytes/ns -> bytes/s
                .collect();
            median(tputs)
        } else {
            None
        };

        let window = op_window(ops);

        rows.push(ScorecardRow {
            schema: ScorecardSchemaTag,
            bucket: bucket.clone(),
            s3_op: s3_op.clone(),
            ops: n_ops,
            errors,
            error_rate,
            status_counts: status_counts.clone(),
            ttfb_p50_ns: p50.map(|v| v.round() as u64),
            ttfb_p95_ns: p95.map(|v| v.round() as u64),
            ttfb_p99_ns: p99.map(|v| v.round() as u64),
            latency_sample,
            throughput_bytes_per_s,
            window,
        });

        // --- gated findings over this group ---
        // The fully-unclassified group (bucket AND s3_op absent) is kept as a DESCRIPTIVE row
        // above but never JUDGED: its finding would carry an all-null `FindingScope`, which the
        // schema contract reads as "the whole capture" (s3tap-schema FindingScope doc). Emitting
        // it would let a fleet gate mistake "10% of the unclassified subset 403'd" for "10% of
        // the whole capture 403'd". A group with at least one key dimension is still scoped by it.
        if bucket.is_none() && s3_op.is_none() {
            continue;
        }
        let scope = FindingScope {
            s3_op: s3_op.clone(),
            bucket: bucket.clone(),
            prefix_hash: None,
            region: None,
            app_pid: None,
        };
        let group_total = ops.len() as u64;

        // Reliability taxonomy: one finding per StatusClass that breaches the gate. Counting
        // via the shared `classify_status` (a total function) means each status is claimed by
        // exactly one class — no predicate can overlap another (the 429 double-count is
        // structurally impossible now). ERROR_ORDER fixes the finding emission order.
        if n_ops >= MIN_OPS {
            for &class in ERROR_ORDER {
                let Some(meta) = error_class_meta(class) else { continue };
                let count: u64 = status_counts
                    .iter()
                    .filter(|(&st, _)| classify_status(st) == class)
                    .map(|(_, &c)| c)
                    .sum();
                // Rate boundary is strict (`>`), matching service.rs's 503 gate so the two
                // tools agree on the same concept at exactly the floor.
                if count < MIN_ERRORS || (count as f64 / n_ops as f64) <= ERR_RATE_FLOOR {
                    continue;
                }
                let rate = count as f64 / n_ops as f64;
                let ev = evidence_of(
                    scored
                        .iter()
                        .copied()
                        .copied()
                        .filter(|o| o.http_status.is_some_and(|st| classify_status(st) == class)),
                );
                findings.push(finding(
                    meta.id,
                    meta.domain,
                    Severity::Warn,
                    meta.title,
                    format!(
                        "{} · {} of {} ops ({:.1}%) — {}",
                        group_label(bucket, s3_op),
                        count,
                        n_ops,
                        rate * 100.0,
                        meta.advice,
                    ),
                    "error_rate",
                    Some(MetricValue::Num(rate)),
                    Unit::Ratio,
                    format!(
                        "ops >= {}, rate > {:.0}%, count >= {}",
                        MIN_OPS,
                        ERR_RATE_FLOOR * 100.0,
                        MIN_ERRORS
                    ),
                    scope.clone(),
                    window,
                    Sample {
                        judged: n_ops as usize,
                        excluded: (group_total - n_ops) as usize,
                        kind: SampleKind::Operation,
                    },
                    ev,
                ));
            }
        }

        // Tail-shape: p99 ≫ p50 within the group (needs no baseline). Only with a deep
        // enough sample for a trustworthy p99.
        if let (Some(p50v), Some(p99v)) = (p50, p99) {
            if p50v > 0.0 && p99v / p50v >= TAIL_RATIO_FLOOR {
                let ratio = p99v / p50v;
                // Evidence must point at the TAIL the finding is about — the ops at/above the
                // p99 latency — not the first arbitrary (typically fast) eligible ops.
                let p99_ns = p99v.round() as u64;
                let ev = evidence_of(
                    ops.iter()
                        .copied()
                        .filter(|o| is_timeable(o) && o.ttfb_ns.is_some_and(|t| t >= p99_ns)),
                );
                findings.push(finding(
                    "scorecard-latency-tail",
                    Domain::S3,
                    Severity::Advisory,
                    "latency tail",
                    format!(
                        "{} · p99 {:.1}× the median ({} vs {}) — a heavy tail (throttle-adjacent \
                         / GC pause / cold cache), not the typical request",
                        group_label(bucket, s3_op),
                        ratio,
                        fmt_ns(Some(p99v.round() as u64)),
                        fmt_ns(Some(p50v.round() as u64)),
                    ),
                    "p99_over_p50",
                    Some(MetricValue::Num(ratio)),
                    Unit::Ratio,
                    format!(">= {TAIL_RATIO_FLOOR:.0}×"),
                    scope.clone(),
                    window,
                    Sample {
                        judged: latency_sample as usize,
                        excluded: (group_total - latency_sample) as usize,
                        kind: SampleKind::Operation,
                    },
                    ev,
                ));
            }
        }
    }

    Scorecard { rows, findings, ops_seen, window: capture_window(records) }
}

/// A reliability finding's presentation: stable id, domain, title, and tailored advice.
struct ClassMeta {
    id: &'static str,
    domain: Domain,
    title: &'static str,
    advice: &'static str,
}

/// The order the reliability findings are emitted in (deterministic; most-specific first).
/// `StatusClass::Success` is deliberately absent — it is not an error.
const ERROR_ORDER: &[StatusClass] = &[
    StatusClass::Forbidden,
    StatusClass::NotFound,
    StatusClass::BadRequest,
    StatusClass::Throttle,
    StatusClass::ServerError,
    StatusClass::ClientError,
];

/// The finding presentation for an error [`StatusClass`]. `Success` → `None` (no finding).
/// The class → code mapping itself lives in [`classify_status`] (shared with the doctor),
/// so this table only carries the scorecard's copy: ids, domains, and advice.
fn error_class_meta(class: StatusClass) -> Option<ClassMeta> {
    use StatusClass::*;
    Some(match class {
        Forbidden => ClassMeta {
            id: "scorecard-error-403",
            domain: Domain::Client,
            title: "forbidden (403)",
            advice: "403 Forbidden — credentials / bucket policy / request signing, NOT the \
                     network; check the IAM identity and the resource policy",
        },
        NotFound => ClassMeta {
            id: "scorecard-error-404",
            domain: Domain::Client,
            title: "not-found probing (404)",
            advice: "404 NotFound — the code is probing keys that don't exist; cache the negative \
                     or restructure the lookup so it doesn't pay per miss",
        },
        BadRequest => ClassMeta {
            id: "scorecard-error-400",
            domain: Domain::Client,
            title: "malformed requests (400)",
            advice: "400 Bad Request — a malformed request (SDK or signing bug), not the network",
        },
        Throttle => ClassMeta {
            id: "scorecard-throttle",
            domain: Domain::S3,
            title: "throttling (429/503)",
            advice: "throttled — back off with jitter and spread keys across prefixes (503 is \
                     likely SlowDown; s3_error_code isn't emitted yet to prove it)",
        },
        ServerError => ClassMeta {
            id: "scorecard-server-5xx",
            domain: Domain::S3,
            title: "server errors (5xx)",
            advice: "5xx — retryable S3-side blips; verify your retry policy handles them",
        },
        ClientError => ClassMeta {
            id: "scorecard-error-4xx",
            domain: Domain::Client,
            title: "client errors (4xx)",
            advice: "4xx — a request / permission / signing issue, not the network",
        },
        Success => return None,
    })
}

/// The [ts_start, ts_end] span of a group's ops (monotonic ns). `{0,0}` when no op
/// carried a timestamp — an unknown window is reported as empty, never faked.
fn op_window(ops: &[&Operation]) -> TimeWindow {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for o in ops {
        if let Some(ts) = o.ts_ns {
            lo = lo.min(ts);
            hi = hi.max(ts);
        }
    }
    if lo == u64::MAX {
        TimeWindow { ts_start: 0, ts_end: 0 }
    } else {
        TimeWindow { ts_start: lo, ts_end: hi }
    }
}

/// A sanitized `bucket / op` label for a finding summary (attacker-influenceable on an
/// untrusted stream and reaches a tty — CWE-117 / Trojan Source). The group key is already
/// sanitized (see [`scorecard`]); `sanitize_term` is idempotent, so this stays as the
/// belt-and-braces gate for any caller that isn't the grouped key.
fn group_label(bucket: &Option<String>, s3_op: &Option<String>) -> String {
    let b = bucket.as_deref().map_or("(no bucket)".to_string(), s3tap_schema::sanitize_term);
    let o = s3_op.as_deref().map_or("(unclassified)".to_string(), s3tap_schema::sanitize_term);
    format!("{b} / {o}")
}

/// Human-readable ns → "…µs"/"…ms"/"…s", or "—" for `None`. A compact, table-friendly
/// rendering; the machine path reads the raw ns off the record.
fn fmt_ns(ns: Option<u64>) -> String {
    match ns {
        None => "—".to_string(),
        Some(n) if n < 1_000 => format!("{n}ns"),
        Some(n) if n < 1_000_000 => format!("{}µs", n / 1_000),
        Some(n) if n < 1_000_000_000 => format!("{}ms", n / 1_000_000),
        Some(n) => format!("{:.1}s", n as f64 / 1e9),
    }
}

/// The widest timestamp span across every record kind in the capture. See `Scorecard::window`.
fn capture_window(records: &[Record]) -> TimeWindow {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for r in records {
        let ts = match r {
            Record::Operation(o) => o.ts_ns,
            Record::Connection(c) => c.ts_ns,
            Record::TcpSample(s) => s.ts_ns,
        };
        if let Some(t) = ts {
            lo = lo.min(t);
            hi = hi.max(t);
        }
    }
    if lo == u64::MAX {
        TimeWindow { ts_start: 0, ts_end: 0 }
    } else {
        TimeWindow { ts_start: lo, ts_end: hi }
    }
}

/// The run-level record for a capture with nothing scoreable, or `None` when at least one row
/// was scored. `Some` exactly when [`scorecard_exit`] would return 2 on its own account, so the
/// NDJSON rail can explain an exit the human rail already explains in prose.
///
/// Without it `scorecard --json` over such a capture wrote an empty stream and exited 2, which
/// is scriptable but not self-describing: an ingest storing NDJSON kept no record of WHY, and
/// could not tell this from any other empty result. `doctor --json` has always published a run
/// roll-up for the equivalent state.
///
/// Emitted ONLY for the unscoreable case. A run row on every invocation would be a broader
/// contract change than the gap requires, and a consumer that sees no `scorecard-run` line can
/// read that as "rows were produced" without ambiguity.
#[must_use]
pub fn unjudged_run_finding(sc: &Scorecard) -> Option<Finding> {
    if !sc.rows.is_empty() {
        return None;
    }
    // The two causes `render` already separates, carried onto the machine rail for the same
    // reason: they need different fixes. No operation record at all points at the uprobe caps.
    // Operations that carry no status points at responses that were never parsed.
    let summary = if sc.ops_seen == 0 {
        "no operations in this capture: nothing to score (need s3tap.operation/1 records — run \
         with the uprobe caps for the HTTP layer)"
            .to_string()
    } else {
        format!(
            "{} operation(s) captured, but none carried an HTTP status: nothing to score (the \
             response head was never parsed)",
            sc.ops_seen
        )
    };
    Some(finding(
        "scorecard-run",
        Domain::Run,
        Severity::Unjudged,
        "scorecard run",
        summary,
        "scoreable_groups",
        Some(MetricValue::Num(0.0)),
        Unit::Count,
        "groups >= 1 (a group needs at least one op carrying an HTTP status)".into(),
        FindingScope::default(),
        sc.window,
        Sample { judged: 0, excluded: sc.ops_seen as usize, kind: SampleKind::Operation },
        Evidence::default(),
    ))
}

/// Fill every field of a scorecard [`Finding`] — the one constructor for this module
/// (mirrors the advisor's `advisory()` builder; the scorecard is a per-op consumer,
/// so `source_schema` is the operation record and there is no RTT baseline).
#[allow(clippy::too_many_arguments)]
fn finding(
    finding_id: &str,
    domain: Domain,
    severity: Severity,
    title: &str,
    summary: String,
    metric: &str,
    value: Option<MetricValue>,
    unit: Unit,
    threshold: String,
    scope: FindingScope,
    window: TimeWindow,
    sample: Sample,
    evidence: Evidence,
) -> Finding {
    Finding {
        schema: FindingSchemaTag,
        emitted_at: None,
        source_schema: vec![OPERATION_SCHEMA.into()],
        finding_id: finding_id.into(),
        domain,
        title: title.into(),
        severity,
        verdict: match severity {
            Severity::Healthy => "healthy",
            Severity::Warn => "warn",
            Severity::Advisory => "advisory",
            Severity::Unjudged => "unjudged",
        }
        .into(),
        summary,
        recommendation_ref: None,
        metric: metric.into(),
        value,
        unit,
        baseline_rtt_us: None,
        ratio_to_rtt: None,
        threshold,
        sample,
        scope,
        window,
        evidence,
    }
}

/// Render the scorecard for a terminal: the descriptive percentile table, then the
/// judged findings as a reliability block. Untrusted strings are sanitized on the way
/// out (the machine path uses `--json`).
#[must_use]
pub fn render(sc: &Scorecard, color: bool) -> String {
    if sc.rows.is_empty() {
        // Two very different causes land here; don't blame caps when ops clearly arrived.
        return if sc.ops_seen == 0 {
            "no operations in this capture: nothing to score (need s3tap.operation/1 records — \
             run with the uprobe caps for the HTTP layer)\n"
                .to_string()
        } else {
            format!(
                "{} operation(s) captured, but none carried an HTTP status: nothing to score \
                 (the response head was never parsed — e.g. connections that were still \
                 in-flight, or aborted before any status line)\n",
                sc.ops_seen
            )
        };
    }
    let total_ops: u64 = sc.rows.iter().map(|r| r.ops).sum();
    let mut out = String::new();
    out.push_str(&format!(
        "observed SLO scorecard — {total_ops} ops across {} group(s)\n",
        sc.rows.len()
    ));
    // Account for every op that did NOT make it into a row. A group in which no op carried an
    // HTTP status is correctly kept out of `rows` (there is nothing to score), but dropping it
    // silently means e.g. 500 in-flight PutObjects vanish here while `doctor` still shows them,
    // and the two-cause message above only fires when rows is ENTIRELY empty. Say it out loud.
    if total_ops < sc.ops_seen {
        out.push_str(&format!(
            "  ({} further op(s) carried no HTTP status — still in-flight, or aborted before a \
             status line; described by `doctor`, not scorable here)\n",
            sc.ops_seen - total_ops
        ));
    }
    out.push('\n');
    // Header. TTFB percentiles are the responsiveness columns; MB/s is GET-only.
    out.push_str(&format!(
        "{:<38} {:>7} {:>6} {:>8} {:>8} {:>8} {:>8}\n",
        "bucket / op", "ops", "err%", "p50", "p95", "p99", "MB/s"
    ));
    out.push_str(&format!("{}\n", "─".repeat(89)));
    for r in &sc.rows {
        let label = group_label(&r.bucket, &r.s3_op);
        let mbps = r
            .throughput_bytes_per_s
            .map_or("—".to_string(), |b| format!("{:.1}", b / 1e6));
        let line = format!(
            "{:<38} {:>7} {:>5.1}% {:>8} {:>8} {:>8} {:>8}\n",
            truncate(&label, 38),
            r.ops,
            r.error_rate * 100.0,
            fmt_ns(r.ttfb_p50_ns),
            fmt_ns(r.ttfb_p95_ns),
            fmt_ns(r.ttfb_p99_ns),
            mbps,
        );
        // Tint a row with any error red so the eye finds it in a long table.
        if color && r.errors > 0 {
            out.push_str(&format!("\x1b[31m{line}\x1b[0m"));
        } else {
            out.push_str(&line);
        }
    }

    if !sc.findings.is_empty() {
        // "findings", not "reliability": the block is what `--strict` gates on, and naming it
        // after one taxonomy invited the reading that a clean block means reliable. It means
        // no finding fired, which is a different claim and the one the exit code makes.
        out.push_str("\nfindings\n");
        for f in &sc.findings {
            let (glyph, tint) = match f.severity {
                Severity::Warn => ("⚠", "\x1b[33m"),
                _ => ("→", ""),
            };
            let line = format!("  {glyph} {}\n", s3tap_schema::sanitize_term(&f.summary));
            if color && !tint.is_empty() {
                out.push_str(&format!("{tint}{line}\x1b[0m"));
            } else {
                out.push_str(&line);
            }
        }
    }
    out
}

/// Exit-code gate, matching the advisor's contract: 0 by default (a scorecard is a
/// report, not a failure); under `--strict`, 1 when any `Warn`/`Advisory` finding fired.
///
/// `ops_seen == 0` is checked FIRST and UNCONDITIONALLY (not gated by `strict`), matching
/// doctor's own `Verdict::NoOperations` (`main.rs::verdict_exit_code`, exit 2 regardless of
/// `--strict`): a connection-only capture has no operation records to judge at all, so
/// `sc.findings` is empty not because the workload is healthy but because there was nothing
/// to score. Exiting 0 there — even without `--strict` — is the same "missing denominator
/// reads green" shape doctor already refuses; `scorecard --strict` in particular would
/// otherwise be a CI gate that cannot tell "clean" from "no data".
#[must_use]
pub fn scorecard_exit(sc: &Scorecard, strict: bool) -> i32 {
    // A real judgment outranks a missing denominator, mirroring doctor's own precedence
    // (Attention above NoOperations/NoResponses).
    if strict
        && sc.findings.iter().any(|f| matches!(f.severity, Severity::Warn | Severity::Advisory))
    {
        return 1;
    }
    // Nothing scorable is a missing denominator, not a clean bill of health, and it has TWO
    // causes that `render` already tells apart: no operation records at all, or operations
    // that all lack an HTTP status (every request aborted before a response line). Gating on
    // `ops_seen == 0` alone caught only the first, so a capture of 500 statusless operations
    // printed "none carried an HTTP status" and still exited 0. A row exists only for a group
    // with at least one STATUSED op, so an empty `rows` is exactly "nothing was scorable" and
    // covers both. Unconditional, not `--strict`-gated: doctor's equivalents are not either.
    if sc.rows.is_empty() {
        return 2;
    }
    0
}

/// Clip a display label to `n` chars with an ellipsis (the label is already sanitized;
/// this is purely column-fit). Char-based so a multibyte name isn't split mid-scalar.
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let keep: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{keep}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3tap_schema::{Connection, Operation};

    /// An op in `(bucket, s3_op)` with the given TTFB (ms) and status. `eligible` is
    /// implied by status < 400 + clean delimitation (the default).
    fn op(bucket: &str, s3_op: &str, ttfb_ms: u64, status: u16) -> Record {
        Record::Operation(Operation {
            bucket: Some(bucket.into()),
            s3_op: Some(s3_op.into()),
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            http_status: Some(status),
            ..Default::default()
        })
    }

    fn find<'a>(sc: &'a Scorecard, id: &str) -> Option<&'a Finding> {
        sc.findings.iter().find(|f| f.finding_id == id)
    }

    #[test]
    fn the_run_row_explains_an_exit_2_the_ndjson_rail_could_not() {
        use s3tap_schema::Connection;
        // Cause 1: a connection-only capture. Both `--json` loops write nothing, so before
        // this row the whole stream was empty and the exit code was the only signal.
        let conns = vec![
            Record::Connection(Connection { ts_ns: Some(10), ..Default::default() }),
            Record::Connection(Connection { ts_ns: Some(90), ..Default::default() }),
        ];
        let sc = scorecard(&conns);
        assert!(sc.rows.is_empty() && sc.findings.is_empty(), "nothing on either rail");
        let f = unjudged_run_finding(&sc).expect("an unscoreable capture gets a run row");
        assert_eq!(f.finding_id, "scorecard-run");
        assert_eq!(f.domain, Domain::Run);
        assert!(matches!(f.severity, Severity::Unjudged));
        assert!(f.summary.contains("no operations in this capture"), "{}", f.summary);
        // The window comes from the CONNECTION records: an op-only span would be zero-width
        // for exactly the capture this row describes.
        assert_eq!((f.window.ts_start, f.window.ts_end), (10, 90));

        // Cause 2: operations captured, none carrying a status. A different fix, so the row
        // must not collapse it into the first.
        let statusless = vec![Record::Operation(Operation {
            bucket: Some("b".into()),
            s3_op: Some("GetObject".into()),
            ts_ns: Some(50),
            http_status: None,
            ..Default::default()
        })];
        let sc = scorecard(&statusless);
        assert!(sc.rows.is_empty(), "a statusless group is not scoreable");
        let f = unjudged_run_finding(&sc).expect("all-statusless is unscoreable too");
        assert!(f.summary.contains("none carried an HTTP status"), "{}", f.summary);
        assert_eq!(f.sample.excluded, 1, "the statusless op is the excluded population");

        // A scored capture gets NO row.
        let scored = scorecard(&[op("b", "GetObject", 10, 200)]);
        assert!(!scored.rows.is_empty());
        assert!(unjudged_run_finding(&scored).is_none());

        // The row exists exactly when the exit code is 2 on its own account. If the two ever
        // disagreed, the rail would explain an exit that did not happen, or stay silent about
        // one that did.
        for sc in [scorecard(&conns), scorecard(&statusless), scorecard(&[op("b", "G", 1, 200)])] {
            assert_eq!(
                unjudged_run_finding(&sc).is_some(),
                scorecard_exit(&sc, false) == 2,
                "run row and exit 2 must agree"
            );
        }
    }

    #[test]
    fn empty_input_scores_nothing() {
        let sc = scorecard(&[]);
        assert!(sc.rows.is_empty() && sc.findings.is_empty());
        assert!(render(&sc, false).contains("nothing to score"));
        // Zero operations is a missing denominator, not a health verdict — exit 2
        // UNCONDITIONALLY, matching doctor's `Verdict::NoOperations`. `--strict` must not
        // be required to catch this: a false green here is exactly what a CI gate cannot
        // afford, strict or not.
        assert_eq!(scorecard_exit(&sc, true), 2);
        assert_eq!(scorecard_exit(&sc, false), 2, "unconditional: not gated by --strict");
    }

    #[test]
    fn a_connection_only_capture_is_not_a_silent_pass_under_strict() {
        // The exact shape codex's review flagged: nonzero RECORDS (so `require_records`'s
        // zero-record guard at the CLI layer does not fire), but zero of them are
        // operations. `scorecard --strict` used to print "nothing to score" and still
        // exit 0 — a false-green CI gate indistinguishable from a genuinely clean run.
        let recs = vec![Record::Connection(Connection {
            srtt_us: Some(17_000),
            ..Default::default()
        })];
        let sc = scorecard(&recs);
        assert_eq!(sc.ops_seen, 0);
        assert!(sc.rows.is_empty() && sc.findings.is_empty());
        assert_eq!(scorecard_exit(&sc, true), 2, "connection-only must not read as a pass");
        assert_eq!(scorecard_exit(&sc, false), 2, "unconditional: not gated by --strict either");
    }

    #[test]
    fn an_all_statusless_capture_is_not_a_silent_pass_either() {
        // The sibling missing denominator: operations DID arrive (so `ops_seen > 0` and the
        // zero-operations gate does not fire) but S3 answered none of them, so nothing is
        // scorable. `render` already says so; the exit code used to disagree and return 0.
        // Doctor calls this shape `Verdict::NoResponses` and exits 2.
        let recs: Vec<Record> = (0..5)
            .map(|_| {
                Record::Operation(Operation {
                    bucket: Some("b".into()),
                    s3_op: Some("GetObject".into()),
                    http_status: None,
                    ..Default::default()
                })
            })
            .collect();
        let sc = scorecard(&recs);
        assert_eq!(sc.ops_seen, 5, "the operations were seen");
        assert!(sc.rows.is_empty(), "…but none was scorable");
        assert!(render(&sc, false).contains("none carried an HTTP status"));
        assert_eq!(scorecard_exit(&sc, true), 2, "all-statusless must not read as a pass");
        assert_eq!(scorecard_exit(&sc, false), 2, "unconditional here too");
    }

    #[test]
    fn statusless_only_capture_reports_ops_seen_not_a_caps_error() {
        // Operations arrived (so uprobe caps are clearly present) but none carried a status.
        // The message must say THAT, not send the user hunting for missing caps.
        let recs: Vec<Record> = (0..3)
            .map(|_| {
                Record::Operation(Operation {
                    bucket: Some("b".into()),
                    s3_op: Some("GetObject".into()),
                    http_status: None,
                    ..Default::default()
                })
            })
            .collect();
        let sc = scorecard(&recs);
        assert!(sc.rows.is_empty(), "no statused op -> no rows");
        assert_eq!(sc.ops_seen, 3, "but the operation records were seen");
        let msg = render(&sc, false);
        assert!(msg.contains("3 operation(s) captured"), "names the count: {msg}");
        assert!(!msg.contains("uprobe caps"), "does not misdirect to caps: {msg}");
    }

    #[test]
    fn groups_by_bucket_and_op_with_error_rate_and_status_mix() {
        let mut recs = vec![op("b", "GetObject", 20, 404)];
        recs.extend((0..9).map(|_| op("b", "GetObject", 20, 200)));
        let sc = scorecard(&recs);
        assert_eq!(sc.rows.len(), 1);
        let r = &sc.rows[0];
        assert_eq!(r.ops, 10);
        assert_eq!(r.errors, 1);
        assert!((r.error_rate - 0.1).abs() < 1e-9);
        assert_eq!(r.status_counts[&200], 9);
        assert_eq!(r.status_counts[&404], 1);
    }

    #[test]
    fn statusless_ops_are_excluded_but_partial_with_status_counts() {
        // Harmonized with the doctor's status-mix population: a parsed status is a real
        // response, so a PARTIAL op that carried one still counts toward reliability; only a
        // status-LESS op (no response ever seen) is dropped.
        let mut recs = vec![
            Record::Operation(Operation {
                bucket: Some("b".into()),
                s3_op: Some("GetObject".into()),
                http_status: Some(503),
                partial: true, // still counts — the 503 was really returned
                ..Default::default()
            }),
            Record::Operation(Operation {
                bucket: Some("b".into()),
                s3_op: Some("GetObject".into()),
                http_status: None, // no response -> excluded
                ..Default::default()
            }),
        ];
        recs.push(op("b", "GetObject", 20, 200));
        let sc = scorecard(&recs);
        assert_eq!(sc.rows[0].ops, 2, "the partial-with-503 and the clean 200 both count");
        assert_eq!(sc.rows[0].errors, 1, "the partial 503 is a counted error");
        assert_eq!(sc.rows[0].status_counts[&503], 1);
    }

    #[test]
    fn tail_sample_floors_gate_p95_and_p99() {
        // 30 eligible ops: above the p95 floor (20), below the p99 floor (100).
        let recs: Vec<Record> = (0..30).map(|_| op("b", "GetObject", 20, 200)).collect();
        let r = &scorecard(&recs).rows[0];
        assert!(r.ttfb_p50_ns.is_some());
        assert!(r.ttfb_p95_ns.is_some(), "30 >= MIN_TAIL_SAMPLE");
        assert!(r.ttfb_p99_ns.is_none(), "30 < MIN_P99_SAMPLE — max not sold as p99");
    }

    #[test]
    fn reliability_gate_fires_for_403_and_404_over_threshold() {
        // 100 ops: 90x200, 6x403, 4x404. 403 >= 5 & >= 1% -> fires; 404 (4) < MIN_ERRORS -> not.
        let mut recs: Vec<Record> = (0..90).map(|_| op("b", "PutObject", 20, 200)).collect();
        recs.extend((0..6).map(|_| op("b", "PutObject", 20, 403)));
        recs.extend((0..4).map(|_| op("b", "PutObject", 20, 404)));
        let sc = scorecard(&recs);
        assert!(find(&sc, "scorecard-error-403").is_some(), "6 forbidden clears the gate");
        assert!(find(&sc, "scorecard-error-404").is_none(), "4 not-founds is below MIN_ERRORS");
        let f = find(&sc, "scorecard-error-403").unwrap();
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(f.domain, Domain::Client);
        assert_eq!(f.scope.bucket.as_deref(), Some("b"));
    }

    #[test]
    fn below_min_ops_group_emits_a_row_but_no_reliability_finding() {
        // 10 ops, all 403: 100% error rate but under MIN_OPS -> descriptive only, never judged.
        let recs: Vec<Record> = (0..10).map(|_| op("b", "GetObject", 20, 403)).collect();
        let sc = scorecard(&recs);
        assert_eq!(sc.rows.len(), 1);
        assert!(sc.findings.is_empty(), "a tiny sample is too noisy to judge");
    }

    #[test]
    fn heavy_tail_fires_when_p99_dwarfs_p50_with_enough_samples() {
        // 100 fast + 5 very slow eligible ops -> p99 ~ 30x p50, sample >= MIN_P99_SAMPLE.
        let mut recs: Vec<Record> = (0..100).map(|_| op("b", "GetObject", 20, 200)).collect();
        recs.extend((0..5).map(|_| op("b", "GetObject", 600, 200)));
        let sc = scorecard(&recs);
        let f = find(&sc, "scorecard-latency-tail").expect("heavy tail flagged");
        assert_eq!(f.severity, Severity::Advisory, "a tail is advisory, never a gate on its own");
    }

    #[test]
    fn strict_exit_gates_on_any_finding() {
        let mut recs: Vec<Record> = (0..90).map(|_| op("b", "PutObject", 20, 200)).collect();
        recs.extend((0..8).map(|_| op("b", "PutObject", 20, 403)));
        let sc = scorecard(&recs);
        assert_eq!(scorecard_exit(&sc, false), 0, "a report is not a failure by default");
        assert_eq!(scorecard_exit(&sc, true), 1, "--strict gates on the reliability finding");
    }

    #[test]
    fn http_429_is_claimed_only_by_throttle_never_the_generic_4xx() {
        // Regression: the generic-4xx predicate must exclude 429 (it's routed to throttle),
        // else a 429 double-counts into both scorecard-throttle AND scorecard-error-4xx.
        let mut recs: Vec<Record> = (0..90).map(|_| op("b", "GetObject", 20, 200)).collect();
        recs.extend((0..10).map(|_| op("b", "GetObject", 20, 429)));
        let sc = scorecard(&recs);
        assert!(find(&sc, "scorecard-throttle").is_some(), "429 fires throttle");
        assert!(
            find(&sc, "scorecard-error-4xx").is_none(),
            "429 must NOT also fire the generic-4xx finding"
        );
        // And it is counted exactly once (throttle count == the 429s, not doubled anywhere).
        let t = find(&sc, "scorecard-throttle").unwrap();
        assert!(matches!(t.value, Some(MetricValue::Num(r)) if (r - 0.1).abs() < 1e-9));
    }

    #[test]
    fn throttle_fires_for_503_and_5xx_and_400_route_to_their_own_classes() {
        // 200 ops: 5x503 (throttle/S3), 6x500 (server-5xx/S3), 7x400 (malformed/Client).
        let mut recs: Vec<Record> = (0..182).map(|_| op("b", "GetObject", 20, 200)).collect();
        recs.extend((0..5).map(|_| op("b", "GetObject", 20, 503)));
        recs.extend((0..6).map(|_| op("b", "GetObject", 20, 500)));
        recs.extend((0..7).map(|_| op("b", "GetObject", 20, 400)));
        let sc = scorecard(&recs);
        let throttle = find(&sc, "scorecard-throttle").expect("503 -> throttle");
        assert_eq!(throttle.domain, Domain::S3);
        assert_eq!(find(&sc, "scorecard-server-5xx").expect("500 -> 5xx").domain, Domain::S3);
        assert_eq!(find(&sc, "scorecard-error-400").expect("400 -> malformed").domain, Domain::Client);
        // 503 is not double-claimed by the 5xx class.
        let n5xx = find(&sc, "scorecard-server-5xx").unwrap();
        assert!(matches!(n5xx.value, Some(MetricValue::Num(r)) if (r - 6.0 / 200.0).abs() < 1e-9));
    }

    #[test]
    fn get_throughput_is_computed_and_absent_for_non_get() {
        let g = Record::Operation(Operation {
            bucket: Some("b".into()),
            s3_op: Some("GetObject".into()),
            http_status: Some(200),
            content_length: Some(1_048_576), // 1 MiB
            download_ns: Some(10_000_000),   // 10 ms -> ~104.9 MB/s
            ttfb_ns: Some(20_000_000),
            ..Default::default()
        });
        let sc = scorecard(&[g]);
        let row = &sc.rows[0];
        let mbps = row.throughput_bytes_per_s.expect("GET throughput present") / 1e6;
        assert!((mbps - 104.857_6).abs() < 0.01, "got {mbps} MB/s");
        // A PUT group carries no throughput — and this must be BECAUSE of the GetObject gate,
        // not because the op lacks the size/timing fields. So the PUT op is given the SAME
        // content_length/download_ns as the GET above: the None can then only come from the
        // `s3_op == GetObject` gate, so removing that gate would fail this test.
        let put = scorecard(&[Record::Operation(Operation {
            bucket: Some("b".into()),
            s3_op: Some("PutObject".into()),
            http_status: Some(200),
            content_length: Some(1_048_576),
            download_ns: Some(10_000_000),
            ttfb_ns: Some(20_000_000),
            ..Default::default()
        })]);
        assert!(
            put.rows[0].throughput_bytes_per_s.is_none(),
            "throughput is GET-only even when a PUT carries size/timing"
        );
    }

    #[test]
    fn latency_sample_never_exceeds_ops_when_statusless_ops_are_present() {
        // Regression for the percentile-population bug: an aborted in-flight op (http_status
        // None, clean, non-partial, a ttfb_ns from a 100-Continue interim) passes `is_eligible`
        // but is NOT in the row's `ops` denominator. The timing population must exclude it, so
        // `latency_sample <= ops` holds and the percentiles describe only real responses.
        let aborted = |ttfb_ms: u64| {
            Record::Operation(Operation {
                bucket: Some("b".into()),
                s3_op: Some("PutObject".into()),
                http_status: None, // no response head ever parsed
                ttfb_ns: Some(ttfb_ms * 1_000_000),
                ..Default::default() // partial: false, delimitation: Clean by default
            })
        };
        let mut recs: Vec<Record> = (30..80).map(aborted).collect(); // 50 aborted @ 30..79 ms
        recs.push(op("b", "PutObject", 5, 200)); // 1 real 200 @ 5 ms
        recs.push(op("b", "PutObject", 5, 200)); // 1 real 200 @ 5 ms
        let r = &scorecard(&recs).rows[0];
        assert_eq!(r.ops, 2, "only the two statused ops are counted");
        assert!(r.latency_sample <= r.ops, "timing population can't exceed the denominator");
        assert_eq!(r.latency_sample, 2, "exactly the two real responses are timed");
        assert_eq!(r.ttfb_p50_ns, Some(5_000_000), "p50 is the real requests', not the aborted");
    }

    #[test]
    fn rows_are_sorted_by_group_key_across_buckets_and_ops() {
        let recs = vec![
            op("photos", "PutObject", 20, 200),
            op("logs", "ListObjectsV2", 20, 200),
            op("photos", "GetObject", 20, 200),
        ];
        let keys: Vec<(Option<String>, Option<String>)> =
            scorecard(&recs).rows.into_iter().map(|r| (r.bucket, r.s3_op)).collect();
        assert_eq!(
            keys,
            vec![
                (Some("logs".into()), Some("ListObjectsV2".into())),
                (Some("photos".into()), Some("GetObject".into())),
                (Some("photos".into()), Some("PutObject".into())),
            ],
            "BTreeMap key order: bucket then op"
        );
    }

    #[test]
    fn unclassified_group_none_bucket_or_op_stays_visible() {
        let recs = vec![Record::Operation(Operation {
            bucket: None,
            s3_op: None,
            http_status: Some(200),
            ttfb_ns: Some(20_000_000),
            ..Default::default()
        })];
        let sc = scorecard(&recs);
        assert_eq!(sc.rows.len(), 1, "unclassified traffic is never dropped");
        assert!(sc.rows[0].bucket.is_none() && sc.rows[0].s3_op.is_none());
        assert!(render(&sc, false).contains("(no bucket) / (unclassified)"));
    }

    #[test]
    fn fully_unclassified_group_is_described_but_never_judged() {
        // (None, None) group over the gate: it MUST still get a descriptive row, but MUST NOT
        // emit a finding — an all-null FindingScope reads as "the whole capture" to a consumer.
        let mut recs: Vec<Record> = (0..90).map(|_| {
            Record::Operation(Operation { http_status: Some(200), ttfb_ns: Some(20_000_000), ..Default::default() })
        }).collect();
        recs.extend((0..10).map(|_| {
            Record::Operation(Operation { http_status: Some(403), ttfb_ns: Some(20_000_000), ..Default::default() })
        }));
        let sc = scorecard(&recs);
        assert_eq!(sc.rows.len(), 1, "the unclassified traffic still shows up as a row");
        assert!(sc.rows[0].bucket.is_none() && sc.rows[0].s3_op.is_none());
        assert_eq!(sc.rows[0].errors, 10, "the row still reports its 403s descriptively");
        assert!(sc.findings.is_empty(), "but no finding: an all-null scope would read as capture-wide");
    }

    #[test]
    fn a_partially_classified_group_bucket_only_is_still_judged() {
        // Contrast: a group with a bucket but no s3_op IS scoped (by the bucket), so it is judged.
        let mut recs: Vec<Record> = (0..90).map(|_| {
            Record::Operation(Operation { bucket: Some("b".into()), http_status: Some(200), ttfb_ns: Some(20_000_000), ..Default::default() })
        }).collect();
        recs.extend((0..10).map(|_| {
            Record::Operation(Operation { bucket: Some("b".into()), http_status: Some(403), ttfb_ns: Some(20_000_000), ..Default::default() })
        }));
        let sc = scorecard(&recs);
        let f = find(&sc, "scorecard-error-403").expect("a bucket-scoped group is still judged");
        assert_eq!(f.scope.bucket.as_deref(), Some("b"));
        assert!(f.scope.s3_op.is_none(), "s3_op null here means the op-class was absent for this bucket");
    }

    #[test]
    fn a_malicious_bucket_name_is_sanitized_before_reaching_the_tty() {
        // A bucket carrying an ANSI escape + CR + a bidi override must be scrubbed to
        // U+FFFD in BOTH the table row and any finding summary (CWE-117 / Trojan Source).
        let evil = "b\x1b[31m\r\u{202e}";
        let mut recs: Vec<Record> = (0..90).map(|_| op(evil, "GetObject", 20, 200)).collect();
        recs.extend((0..8).map(|_| op(evil, "GetObject", 20, 403)));
        // color=false so the ONLY ESC/CR that could appear would be from the unsanitized
        // bucket data itself (render adds no tint codes of its own in this mode).
        let rendered = render(&scorecard(&recs), false);
        assert!(!rendered.contains('\x1b'), "no raw ESC reaches the tty: {rendered:?}");
        assert!(!rendered.contains('\r'), "no raw CR reaches the tty");
        assert!(!rendered.contains('\u{202e}'), "no bidi override reaches the tty");
        assert!(rendered.contains('\u{fffd}'), "unsafe chars replaced with U+FFFD");
    }

    #[test]
    fn coalesced_body_zero_download_span_cannot_produce_a_non_finite_throughput() {
        // download_ns == 0 is what the correlator emits when the body arrives in the SAME read
        // as the response head (every small object) — see s3tap-core's
        // `body_coalesced_into_head_completes_at_head`. Without the `dl > 0` guard,
        // content_length / 0 is +Inf; `throughput_bytes_per_s` uses the finite-only serializer,
        // so the row would fail to serialize and `scorecard --json` would panic on its
        // `.expect(...)`. Pin that the value stays finite and that the row serializes.
        let get = |cl: u64, dl: u64| {
            Record::Operation(Operation {
                bucket: Some("b".into()),
                s3_op: Some("GetObject".into()),
                http_status: Some(200),
                ttfb_ns: Some(20_000_000),
                content_length: Some(cl),
                download_ns: Some(dl),
                ..Default::default()
            })
        };
        let sc = scorecard(&[get(1_024, 0), get(1_048_576, 10_000_000)]);
        let row = &sc.rows[0];
        let v = row.throughput_bytes_per_s.expect("a rate from the one measurable span");
        assert!(v.is_finite(), "a zero download span must never reach the row as ±Inf: {v}");
        assert!((v / 1e6 - 104.857_6).abs() < 0.01, "the coalesced op is dropped, not rated: {v}");
        // The serialize step is the one that PANICS in the CLI on a non-finite f64.
        serde_json::to_string(row).expect("scorecard row serializes");
    }

    #[test]
    fn an_all_coalesced_get_group_reports_no_throughput_rather_than_infinity() {
        // Every GET coalesced (the small-object workload): no span has a duration, so there is
        // no honest rate. `throughput_bytes_per_s` must be None — never Inf, never a 0 stand-in.
        let get = || {
            Record::Operation(Operation {
                bucket: Some("b".into()),
                s3_op: Some("GetObject".into()),
                http_status: Some(200),
                ttfb_ns: Some(20_000_000),
                content_length: Some(1_024),
                download_ns: Some(0),
                ..Default::default()
            })
        };
        let sc = scorecard(&[get(), get()]);
        let row = &sc.rows[0];
        assert_eq!(row.throughput_bytes_per_s, None, "no measurable span -> no rate");
        serde_json::to_string(row).expect("scorecard row serializes");
        assert!(render(&sc, false).contains('—'), "the MB/s cell renders as an em dash");
    }

    #[test]
    fn render_color_is_purely_additive_and_off_by_default() {
        // The colored render is what an actual `s3tap scorecard` user sees on a tty and was
        // entirely unpinned: a dropped reset would bleed colour across the rest of the
        // terminal, and a colored-only width shift would misalign the table with every test
        // green. 90x200 + 8x403 gives BOTH tints: an errored (red) row and a Warn (yellow)
        // reliability line.
        let mut recs: Vec<Record> = (0..90).map(|_| op("b", "GetObject", 20, 200)).collect();
        recs.extend((0..8).map(|_| op("b", "GetObject", 20, 403)));
        let sc = scorecard(&recs);
        let plain = render(&sc, false);
        let colored = render(&sc, true);
        assert!(!sc.findings.is_empty(), "the fixture must carry a Warn finding for the tint");
        assert!(!plain.contains('\x1b'), "render(_, false) must emit no ANSI:\n{plain}");
        assert!(colored.contains("\x1b[31m"), "an errored row is tinted red");
        assert!(colored.contains("\x1b[33m"), "a Warn finding is tinted yellow");
        // Every tint is closed, so colour can't bleed past the table.
        assert_eq!(
            colored.matches('\x1b').count(),
            colored.matches("\x1b[0m").count() * 2,
            "each tint is paired with exactly one reset"
        );
        // Stripping the colour yields the plain render byte for byte: purely additive.
        let stripped: String = {
            let mut out = String::with_capacity(colored.len());
            let mut chars = colored.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for x in chars.by_ref() {
                        if x == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        assert_eq!(stripped, plain, "colored minus ANSI must equal plain");
    }
}
