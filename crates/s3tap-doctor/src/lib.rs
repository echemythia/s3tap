// crates/s3tap-doctor/src/lib.rs
//
// `s3tap doctor` engine. A PURE
// CONSUMER of the public records: it reads s3tap.operation/1 + s3tap.connection/2 and
// judges each latency span relative to the connection's RTT floor (srtt). This is the
// Rust generalization of demo/s3stats.py, which stays the reference oracle the parity
// tests pin against. Step 2: the global Network/Client checks + verdict precedence
// (parity with s3stats.py). Step 3 (this): the per-`s3_op` S3 domain (think-time,
// status mix, GET throughput) layered on top — the superset beyond the flat oracle.
// Step 4 (this): `Report::findings()` projects the report into `s3tap.finding/1`
// records for `s3tap doctor --json` (the machine/fleet-ingest format).

use std::collections::HashMap;

use s3tap_schema::{
    Connection, Delimitation, Domain, Evidence, Finding, FindingSchemaTag, FindingScope,
    MetricValue, Operation, Sample, SampleKind, Severity, TcpSample, TimeWindow, Unit,
    CONNECTION_SCHEMA, OPERATION_SCHEMA, SAMPLE_SCHEMA,
};

/// The observed-SLO scorecard (`s3tap scorecard`) — per-`(bucket, s3_op)` percentile
/// telemetry plus gated reliability findings. Lives here so it can reuse the doctor's
/// private eligibility/percentile primitives without duplicating them.
pub mod scorecard;

/// sock_cookie → the connection that owns it (colliding cookies are dropped at build time —
/// see [`build_floor_maps`]). The op↔connection join key for per-op RTT floors.
type ConnByCookie<'a> = HashMap<u64, &'a Connection>;
/// Endpoint region (`None` = unknown) → that region's median RTT floor, in µs.
type RegionFloor = HashMap<Option<String>, f64>;

/// One decoded public record off the JSONL stream.
#[derive(Debug, Clone)]
pub enum Record {
    Operation(Operation),
    Connection(Connection),
    /// An in-flight TCP sample (`s3tap.sample/1`). Accepted and set aside — the
    /// time-series analysis that consumes it lands in Plan 2; for now it is parsed
    /// (so it isn't miscounted as unknown-schema) but not analyzed.
    TcpSample(TcpSample),
}

/// Counts of lines the parser couldn't use, so a mostly-broken capture can't read as
/// clean (reported, never hidden).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ParseStats {
    pub bad_lines: usize,      // not valid JSON, or a known schema that failed to decode
    pub unknown_schema: usize, // a JSON object whose `schema` we don't recognize
}

/// Parse a JSONL stream into records. Blank lines are skipped; a malformed line or an
/// unknown schema is counted and skipped, never fatal — a capture may be truncated.
#[must_use]
pub fn parse_records(input: &str) -> (Vec<Record>, ParseStats) {
    let mut out = Vec::new();
    let mut stats = ParseStats::default();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Peek the schema discriminant, then decode into the matching record. (Peek-
        // then-decode rather than an internally-tagged enum: it lets an unknown schema
        // be skipped gracefully instead of erroring the whole line.)
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            stats.bad_lines += 1;
            continue;
        };
        // A record is a JSON object; a bare number/string/array is valid JSON but not a
        // record, so it's a bad line — `unknown_schema` is reserved for objects whose
        // `schema` we don't recognize (keeps the two counters' meanings honest).
        if !value.is_object() {
            stats.bad_lines += 1;
            continue;
        }
        match value.get("schema").and_then(serde_json::Value::as_str) {
            Some(OPERATION_SCHEMA) => match serde_json::from_value::<Operation>(value) {
                Ok(op) => out.push(Record::Operation(op)),
                Err(_) => stats.bad_lines += 1,
            },
            Some(CONNECTION_SCHEMA) => match serde_json::from_value::<Connection>(value) {
                Ok(c) => out.push(Record::Connection(c)),
                Err(_) => stats.bad_lines += 1,
            },
            // Accepted but not yet analyzed (Plan 2). Parsed so a sampling capture
            // doesn't flood `unknown_schema`; a malformed sample still counts bad_lines.
            Some(SAMPLE_SCHEMA) => match serde_json::from_value::<TcpSample>(value) {
                Ok(s) => out.push(Record::TcpSample(s)),
                Err(_) => stats.bad_lines += 1,
            },
            _ => stats.unknown_schema += 1,
        }
    }
    (out, stats)
}

/// The mark a finding carries. `Na` is unjudgeable (no RTT floor) —
/// never silently upgraded to `Ok`. `Advisory` is a heuristic hint (e.g. throughput)
/// that informs but never escalates the run verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Ok,       // ✓
    Warn,     // ⚠
    Na,       // (blank) — shown but not judged
    Advisory, // · — a heuristic soft-concern; escalates ONLY under --strict (e.g. throughput)
    Fyi,      // · — pure telemetry (the network-path rows); NEVER gates, even under --strict
}

impl Mark {
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            Mark::Ok => "✓",
            Mark::Warn => "⚠",
            Mark::Na => " ",
            Mark::Advisory | Mark::Fyi => "·",
        }
    }

    /// The public [`Severity`] this mark maps to in a `finding/1` record. `Na`/`Fyi` ⇒
    /// `Unjudged` — neither a no-floor span nor pure telemetry is ever silently upgraded to
    /// healthy or treated as a gate-worthy concern.
    fn severity(self) -> Severity {
        match self {
            Mark::Ok => Severity::Healthy,
            Mark::Warn => Severity::Warn,
            Mark::Advisory => Severity::Advisory,
            Mark::Na | Mark::Fyi => Severity::Unjudged,
        }
    }
}

/// The structured measurement behind a row, carried so the `--json` finding emitter
/// reads numbers directly rather than reverse-parsing the formatted display strings.
/// `render` uses the row's formatted `value`/`note`; the machine path uses this.
/// (Provisional alongside [`Finding`].)
#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    /// The finding's `metric` name, e.g. "tcp_connect" or "ttfb_new".
    pub name: &'static str,
    /// Numeric value in `unit`; `None` ⇒ unjudged / not applicable.
    pub value: Option<f64>,
    pub unit: Unit,
    /// This row's value is meant to be read against the RTT floor. NECESSARY but no longer
    /// SUFFICIENT for the finding to inherit the report-wide `baseline_rtt_us`: the row must
    /// also have actually divided by it (`ratio_to_rtt.is_some()`) and not have opted out via
    /// [`Self::per_op_baseline`]. Keying the inheritance on this flag alone handed the pooled
    /// floor to rows that had just declined to judge against one.
    pub rtt_relative: bool,
    /// `value` as a multiple of the floor (latency checks); `None` otherwise.
    pub ratio_to_rtt: Option<f64>,
    /// The healthy envelope judged against, e.g. "<= 4.0×RTT".
    pub threshold: &'static str,
    /// The floor (µs) this row's `ratio_to_rtt` was ACTUALLY taken against, when it differs
    /// from the report-level pooled baseline — set by the per-op-joined S3 rows so the emitted
    /// finding's `baseline_rtt_us` matches its own denominator instead of the global blend.
    /// `None` ⇒ the row used the pooled baseline (the global rows), UNLESS
    /// [`Self::per_op_baseline`] says there is no single one.
    pub baseline_us: Option<f64>,
    /// This row's `ratio_to_rtt` was taken PER OP, against each op's own floor, so no single
    /// denominator relates it to `value` and the report-wide floor must not be substituted.
    /// Set by the TTFB tail rows, whose `value` and `ratio_to_rtt` are order statistics over
    /// different orderings. Without it, `baseline_us: None` fell through to the inherit arm —
    /// the row has a ratio, so the gate let it take the pooled floor — and a consumer dividing
    /// `value` by it got a number contradicting the published ratio by up to 200x.
    pub per_op_baseline: bool,
}

impl Default for Metric {
    fn default() -> Self {
        Metric {
            name: "",
            value: None,
            unit: Unit::None,
            rtt_relative: false,
            ratio_to_rtt: None,
            threshold: "",
            baseline_us: None,
            per_op_baseline: false,
        }
    }
}

/// One global report row — the shape demo/s3stats.py prints. Carries a [`Metric`] for
/// the `--json` path (no `Eq`: the metric holds `f64`s).
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub id: &'static str,
    pub label: &'static str,
    pub value: String,
    pub mark: Mark,
    pub verdict: &'static str,
    pub note: String,
    pub metric: Metric,
}

/// One S3-domain row — per op-class (the label is dynamic, e.g. "GetObject TTFB"), so
/// it carries a `String` label rather than the global rows' `&'static str`. `id` is the
/// stable finding slug and `s3_op` the (sanitized) op-class for the finding scope.
#[derive(Debug, Clone, PartialEq)]
pub struct S3Row {
    pub id: &'static str,
    pub label: String,
    pub value: String,
    pub mark: Mark,
    pub verdict: &'static str,
    pub note: String,
    pub s3_op: Option<String>,
    pub metric: Metric,
    /// `(judged, excluded)` for a row whose population is its OP-CLASS, not the whole capture.
    /// Carried on the row because the class is the key and `Report::row_pop` is keyed by
    /// finding id alone — `s3_ttfb` is one id shared by every class. Without it a capture of 5
    /// GetObject and 95 PutObject published `judged: 100` on BOTH class rows, which cannot be
    /// true of either. `None` for the status-mix rows, whose population is `op_statused` and
    /// is resolved centrally.
    pub population: Option<(usize, usize)>,
}

/// The run-level verdict, resolved in precedence order (the
/// s3stats.py refinement): any `⚠` → Attention; no RTT floor → NoBaseline; a floor but
/// no latency span judged (all ops partial) → ChecksPassed; else Healthy.
///
/// [`Verdict::NoOperations`] is the one variant the parity-pinned global verdict never
/// takes: it is resolved in [`Report::overall_verdict`], over the full superset, because
/// s3stats.py has no notion of the S3 population.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A round-trip floor was found, but the capture spans more than one network path, so the
    /// pooled median is a blend that fits none of them and was withheld from every span. The
    /// floor exists; it is just not a denominator. Distinct from [`Verdict::NoBaseline`], which
    /// says none was found at all — saying that here would send an operator looking for a
    /// capture problem that isn't there.
    MixedPaths,
    Attention,
    NoBaseline,
    /// Zero `s3tap.operation/1` records in the capture: nothing at the S3 layer was judged.
    /// The network path may well be clean, and that is all this capture can say. Sibling of
    /// [`Verdict::NoBaseline`] ("no floor to judge against") for the other missing
    /// denominator, and non-green for the same reason: a Go/rustls client, or any capture
    /// taken without the uprobe caps, produces exactly this shape, and "CHECKS PASSED" over
    /// an empty S3 population reads as a clean bill of health to a CI gate.
    NoOperations,
    /// Operations were DECODED (unlike [`Verdict::NoOperations`]) but not one of them was ever
    /// ANSWERED (`op_statused == 0`): every request aborted in flight (a client timeout/reset,
    /// or a capture that ended mid-request and `flush_open_ops` emitted). `ChecksPassed` used
    /// to cover this too, on the reasoning that no operation was "timeable" — but that phrasing
    /// is silent on WHY, and its exit code (0, the same as `Healthy`) is the exact "missing
    /// denominator reads green" shape `NoOperations`/`NoBaseline` exist to refuse. `NoOperations`
    /// itself would be a false remedy here (re-capturing with the uprobe caps changes nothing;
    /// S3 WAS reached, nothing about it was ever observed), so this is its own variant rather
    /// than reusing that one's wording.
    NoResponses,
    ChecksPassed,
    Healthy { reuse_working: bool },
}

impl Verdict {
    /// The stable keyword for parity/diffing (the first words of the rendered line).
    #[must_use]
    pub fn keyword(self) -> &'static str {
        match self {
            Verdict::Attention => "ATTENTION",
            Verdict::NoBaseline => "NO BASELINE",
            Verdict::NoOperations => "NO OPERATIONS",
            Verdict::NoResponses => "NO RESPONSES",
            Verdict::ChecksPassed => "CHECKS PASSED",
            Verdict::MixedPaths => "MIXED PATHS",
            Verdict::Healthy { .. } => "HEALTHY",
        }
    }

    fn message(self) -> String {
        match self {
            Verdict::Attention => {
                "ATTENTION — one or more metrics are outside the expected envelope (⚠ above)".into()
            }
            Verdict::NoBaseline => "NO BASELINE — no round-trip floor: no connection closed in \
                 the window (a long-lived pool) and no in-flight RTT samples were captured. \
                 Absolute checks passed, but latencies were not judged. Re-capture with \
                 `--sample-interval-ms` to get a live floor from a persistent pool"
                .into(),
            // The other missing denominator. Deliberately NOT phrased as a health claim: the
            // network rows may all be ✓ and that says nothing about S3, so this must not read
            // as CHECKS PASSED. The remedy is the one that produces operation records at all.
            Verdict::NoOperations => "NO OPERATIONS — no S3 request was decoded, so nothing at \
                 the S3 layer was judged: only the network path below. A Go/rustls client, or a \
                 capture taken without the uprobe caps, produces exactly this. Re-capture with \
                 `--capture-plaintext` after `sudo s3tap setup --uprobes` to decode operations"
                .into(),
            // Distinct remedy from NoOperations on purpose: S3 traffic WAS decoded here, so
            // re-capturing with the uprobe caps changes nothing. The absent responses point at
            // the client/network side (timeouts, resets) or the capture window ending mid-request.
            Verdict::NoResponses => "NO RESPONSES — operations were decoded but not one ever \
                 received an answer: every request aborted in flight (a client timeout/reset, or \
                 the capture ending mid-request). Nothing about S3's behavior — status, latency — \
                 was ever observed, so this is not a health verdict either way"
                .into(),
            // "(all ops partial)" was one of the two ways to get here and a flat untruth for the
            // other: a capture with NO operations at all reaches ChecksPassed too. Name the
            // condition both share; the denominator line (`judged_denominator_line`) says which.
            Verdict::ChecksPassed => "CHECKS PASSED — no latency spans available to judge against \
                 the floor (no timeable operations)"
                .into(),
            Verdict::MixedPaths => "MIXED PATHS — a round-trip floor was measured, but this \
                 capture spans more than one network path (distinct endpoint regions, or a \
                 near and a far path together). A single pooled floor fits none of them, so \
                 the pooled-floor spans above were not judged; only ops joined to their own \
                 connection could be. Scope the capture to one path, or read the \
                 per-connection view, which separates them"
                .into(),
            Verdict::Healthy { reuse_working } => {
                let reuse = if reuse_working {
                    "; connection reuse is working"
                } else {
                    ""
                };
                format!("HEALTHY — latencies track the round-trip floor{reuse}")
            }
        }
    }
}

/// A judged capture window: the global rows (the s3stats.py-compatible summary), the
/// per-op-class S3 domain, and the run-level verdict. No `Eq` (rows carry `f64`s).
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Global Network/Client checks (the s3stats.py port; parity-tested).
    pub rows: Vec<Row>,
    /// Per-`s3_op` S3-domain rows (think-time, status mix, GET throughput) — the
    /// superset beyond the flat oracle (step 3); empty when no op-class is identified.
    pub s3: Vec<S3Row>,
    /// Tail-latency (p95) rows for the TTFB populations — a superset like `s3` (escalates
    /// `overall_verdict`, not the parity `verdict`); empty below the min tail sample.
    pub tail: Vec<Row>,
    /// Connection-reuse-rate check — a superset (escalates `overall_verdict`, not the
    /// parity `verdict`); `None` below the min sample.
    pub reuse: Option<Row>,
    /// Connection-level PATH diagnosis (min_rtt/jitter, send-bottleneck, BDP ceiling, loss
    /// shape) from the extended tcp_sock fields — ADVISORY only (never escalates), and the
    /// sole signal for Go/non-OpenSSL clients. Empty when the fields aren't present.
    pub path: Vec<Row>,
    /// In-flight TIME-SERIES rows (throughput ramp, bufferbloat onset) from the
    /// `s3tap.sample/1` stream — pure FYI (never escalates), the "what happened, and
    /// when" the close snapshot can't show. Empty unless the capture carries samples.
    pub timeseries: Vec<Row>,
    /// Number of throughput streams the time-series analysis judged — the `--json`
    /// finding population for the UNDIRECTED timeseries rows (`throughput_ramp`,
    /// `bufferbloat_onset`). NOT the connection count, which is 0 on a samples-only capture.
    pub ts_stream_count: usize,
    /// The same population split by DIRECTION (`ts_down_stream_count + ts_up_stream_count ==
    /// ts_stream_count`). The aggregate/loss-timeline rows are emitted per direction and each
    /// gets its own `finding_id`, so each must publish its own direction's stream count:
    /// publishing the undirected total told a consumer a 3-download capture judged the 5 upload
    /// streams too, over-counting each row's population by the other direction's — the exact
    /// mistake the sibling `bdp_ceiling`/`recv_ceiling` split was written to avoid.
    pub ts_down_stream_count: usize,
    pub ts_up_stream_count: usize,
    /// Sample-STREAM populations the sampled-path fallback (`path_domain_sampled`) judged,
    /// PER DIRECTION — the `--json` population for the `recv_ceiling` (download) and
    /// `bdp_ceiling` (upload) rows when they come from the in-flight sample stream (no
    /// connection closed). Both 0 unless that fallback ran, i.e. `conn_count == 0`; the
    /// connection-sourced ceilings use `conn_count` as before.
    pub sampled_recv_stream_count: usize,
    pub sampled_send_stream_count: usize,
    /// The GLOBAL run verdict (matches s3stats.py exactly — parity pins this).
    pub verdict: Verdict,
    pub parse: ParseStats,
    /// The round-trip floor latency spans were judged against (µs; close-time srtt, or a
    /// sampled min_rtt/srtt when no connection closed); `None` ⇒ no baseline. Set on each
    /// `--json` finding's `baseline_rtt_us` (step 4).
    pub baseline_rtt_us: Option<u64>,
    /// Best-effort deployment-environment estimate (same-region / cross-region / far path)
    /// from the round-trip floor + endpoint flags. FYI only — never escalates the verdict. `None`
    /// when there's no signal to estimate from.
    pub environment: Option<EnvEstimate>,
    /// Op-timeability counts for a finding's `Sample`: `judged` = good ops (eligible AND
    /// answered — see `is_timeable`), `excluded` = the rest. The status-mix / HTTP-error
    /// findings report `op_statused` instead, since they can only judge an op that has one.
    pub op_judged: usize,
    pub op_excluded: usize,
    /// Ops carrying an `http_status` — the population the status-mix / reliability rows are
    /// judged over, and the ONLY denominator that yields the same error rate the scorecard
    /// reports for the same capture. Their numerators count statused ops only, so publishing
    /// `op_total()` as `sample.judged` made `doctor --json` and `scorecard --json` disagree by
    /// the statusless share (in-flight aborts, which `flush_open_ops` makes routine at SIGINT).
    pub op_statused: usize,
    /// Operation records that were NOT `partial` — the population `reuse_rate` counts.
    ///
    /// Neither `op_judged` (the timeable subset, which drops errors and ambiguity that reuse
    /// legitimately covers) nor `op_total()` (which includes partial ops, whose
    /// `connection_reused` the schema says cannot be attributed) describes it. Without a
    /// field of its own, `Report::finding` and the diff's `cur_pop` had no way to express
    /// what the row actually counted, and both published `op_total()` while the row counted
    /// this — so the human rail said "6/6 ops reused" beside a machine rail claiming a
    /// population of 20 with nothing excluded.
    pub op_nonpartial: usize,
    /// Per-tail-row `(id, judged, excluded)`: the floored subset each percentile was actually
    /// taken over. The tail is the one family whose population is neither the report-wide
    /// timeable set nor a connection count, so it has to carry its own.
    /// Per-ROW populations: `(finding id, judged, excluded)` for every row whose verdict was
    /// drawn from a SUB-population rather than from the whole op set — the TTFB tails, and the
    /// four global op rows that each filter `good` differently. `Report::finding` publishes
    /// these as the row's `sample`, and the `--baseline` diff reads them as `cur_pop`.
    ///
    /// Absence of an entry means the row was NOT produced this run, which is a population of
    /// 0, not a licence to fall back to `op_judged`. Falling back was how a ⚠ drawn from 5 ops
    /// told a fleet ingest it judged 100, and how a vanished row read as `resolved`.
    pub row_pop: Vec<(&'static str, usize, usize)>,
    /// The capture spans more than one network path, so the pooled floor was withheld from the
    /// global rt-relative rows. On its own this is NOT a verdict — see `overall_verdict`.
    pub mixed_paths: bool,
    /// Connection-record count (the sample population for the connection-sourced path
    /// findings; op counts read 0 on a Go/connection-only capture — review #3).
    pub conn_count: usize,
    /// The population the RTT floor itself rests on: records that supplied a usable
    /// srtt/min_rtt, and records of the same kind that could have but didn't. Published as the
    /// `baseline_rtt` finding's `Sample` — a floor from one connection and a floor from 500 are
    /// different claims, and neither is described by the op counts.
    pub floor_judged: usize,
    pub floor_excluded: usize,
    /// `Some(n)` when the retransmit rate came from the in-flight SAMPLE stream (no connection
    /// closed), `n` being the streams that moved send-side bytes; `None` when it came from the
    /// closed connections, whose population is `conn_count`.
    pub rtx_stream_count: Option<usize>,
    /// Capture window (min/max `ts_ns` over all records); `(0, 0)` if none carry a ts.
    pub window: (u64, u64),
    /// Per-check drill-down evidence for `--json`, keyed by the row's (unique) label:
    /// the contributing ops a consumer can trace back to. Only the per-op-actionable
    /// checks carry it (HTTP errors, the S3 domain rows); aggregate median/tail rows
    /// don't pin individual ops. (Provisional, like `Finding`.)
    pub evidence: Vec<(String, Evidence)>,
}

impl Report {
    /// The OVERALL verdict shown to the user: the global verdict, escalated to
    /// `Attention` when an S3-domain row OR a tail-latency row warns (an `Advisory` never
    /// escalates), and resolved to [`Verdict::NoOperations`] when the capture holds no
    /// operation record at all. The global `verdict` field stays s3stats.py-faithful for
    /// parity; this is the roll-up over the full superset.
    #[must_use]
    /// Did ANY row actually divide by a floor? The tails and the per-`s3_op` rows can judge
    /// per-connection even when the pooled floor was withheld, so this is the honest test for
    /// "nothing was judged", where the capture's shape is not.
    fn anything_judged_against_a_floor(&self) -> bool {
        self.rows.iter().any(|r| r.metric.ratio_to_rtt.is_some())
            || self.tail.iter().any(|r| r.metric.ratio_to_rtt.is_some())
            || self.s3.iter().any(|r| r.metric.ratio_to_rtt.is_some())
    }

    pub fn overall_verdict(&self) -> Verdict {
        let s3_warn = self.s3.iter().any(|r| r.mark == Mark::Warn);
        let tail_warn = self.tail.iter().any(|r| r.mark == Mark::Warn);
        let reuse_warn = self.reuse.as_ref().is_some_and(|r| r.mark == Mark::Warn);
        if self.verdict == Verdict::Attention || s3_warn || tail_warn || reuse_warn {
            return Verdict::Attention;
        }
        // Zero operations: the S3 half of the report was judged over nothing, so neither
        // CHECKS PASSED nor NO BASELINE describes the run — the first claims the checks ran,
        // the second blames a floor that may be perfectly good. Below the Attention branch on
        // purpose: the connection-sourced checks (retransmits, path) CAN warn with no
        // operations at all, and that judgment is real, so a ⚠ is never masked by this.
        if self.op_total() == 0 {
            return Verdict::NoOperations;
        }
        // Operations exist but none were ever answered: the same "missing denominator" shape
        // as the check above, just one layer further in. `self.verdict` (s3stats.py-faithful)
        // resolves this to ChecksPassed, whose exit code sits in the same bucket as Healthy —
        // exactly what "neither missing denominator may read green" forbids. Below the
        // Attention branch for the same reason NoOperations is: a connection-sourced ⚠ (a
        // retransmit rate, a path row) is real even when nothing S3-shaped was ever answered.
if self.op_statused == 0 {
            return Verdict::NoResponses;
        }
        // A floor EXISTS but was withheld as a cross-path blend, and NOTHING ended up judged
        // against any floor. Reaching `Healthy` here printed "latencies track the round-trip
        // floor" beneath rows all reading "no round-trip baseline — not judged", at exit 0 —
        // the missing-denominator-reads-green failure the branches above exist to stop, walked
        // past because they test `rtt_ms` while the withdrawal changes `row_rtt_ms`.
        //
        // BELOW `NoResponses` deliberately. Both are exit 2, so nothing green rides on the
        // order, but they answer different questions and the sharper one should win: if no
        // operation was ever answered, that is the operator's actual problem and no op was
        // timeable anyway, so "mixed paths" would be true and useless. Pinned by a test rather
        // than left to the reader.
        //
        // Gated on "did ANY row publish a ratio", not on "is the capture mixed". Those differ:
        // a mixed capture whose ops all join their own connections is judged per-connection
        // throughout and is perfectly judgeable — `multiregion_tail.jsonl` is exactly that, and
        // keying on the capture shape reported it MIXED PATHS at exit 2 while every one of its
        // ops had been judged against its own floor.
        //
        // NOT `NoBaseline`: that says no floor was found, the false statement in the other
        // direction.
        if self.mixed_paths && !self.anything_judged_against_a_floor() {
            return Verdict::MixedPaths;
        }
        self.verdict
    }

    /// True when the overall health warrants attention (drives the CLI exit code).
    #[must_use]
    pub fn is_attention(&self) -> bool {
        self.overall_verdict() == Verdict::Attention
    }

    /// Whether any check is `Advisory` (e.g. GET throughput). Advisory never escalates by
    /// default, but `--strict` treats it as attention for the exit code.
    #[must_use]
    pub fn has_advisory(&self) -> bool {
        let advisory = |r: &&Row| r.mark == Mark::Advisory;
        self.rows
            .iter()
            .chain(self.tail.iter())
            .chain(self.reuse.iter())
            .chain(self.path.iter())
            .any(|r| advisory(&r))
            || self.s3.iter().any(|r| r.mark == Mark::Advisory)
    }

    /// Project the report into `s3tap.finding/1` records: one per
    /// check row (global, then S3-domain), then the `domain:"run"` roll-up last. This is
    /// the machine/fleet-ingest format behind `s3tap doctor --json`. The per-op-actionable
    /// checks carry `evidence` (the contributing ops to drill into) and a
    /// `recommendation_ref`; `emitted_at` stays `None` so the record is deterministic. The
    /// `Finding` shape is PROVISIONAL (see s3tap-schema).
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        let window = TimeWindow { ts_start: self.window.0, ts_end: self.window.1 };
        let mut out =
            Vec::with_capacity(self.rows.len() + self.s3.len() + self.tail.len() + 2);

        for r in self
            .rows
            .iter()
            .chain(self.tail.iter())
            .chain(self.reuse.iter())
            .chain(self.path.iter())
            .chain(self.timeseries.iter())
        {
            out.push(self.finding(
                r.id,
                global_domain(r.id),
                r.label.to_string(),
                r.mark,
                r.verdict,
                &r.note,
                &r.metric,
                FindingScope::default(),
                window,
                self.evidence_for(r.label),
            ));
        }
        for r in &self.s3 {
            let scope = FindingScope { s3_op: r.s3_op.clone(), ..Default::default() };
            let mut f = self.finding(
                r.id, Domain::S3, r.label.clone(), r.mark, r.verdict, &r.note, &r.metric, scope,
                window, self.evidence_for(&r.label),
            );
            // A class-keyed population overrides the id-keyed resolution, because the id alone
            // cannot distinguish `s3_ttfb`-for-GetObject from `s3_ttfb`-for-PutObject. The
            // status-mix rows leave it `None` and keep `op_statused`, which is right for them.
            if let Some((judged, excluded)) = r.population {
                f.sample = Sample { judged, excluded, kind: SampleKind::Operation };
            }
            out.push(f);
        }

        out.extend(self.environment_finding(window));
        out.push(self.run_finding(window));
        out
    }

    /// The deployment-environment estimate as an Unjudged finding (FYI): a consumer sees the
    /// same-region/cross-region/far call without it gating anything. `None` when unestimated.
    fn environment_finding(&self, window: TimeWindow) -> Option<Finding> {
        let env = self.environment.as_ref()?;
        Some(Finding {
            schema: FindingSchemaTag,
            emitted_at: None,
            source_schema: vec![CONNECTION_SCHEMA.into()],
            finding_id: "environment".into(),
            domain: Domain::Network,
            title: "deployment environment (estimated)".into(),
            severity: Severity::Unjudged,
            verdict: env.class.keyword().into(),
            summary: format!("estimated environment: {}", env.line()),
            recommendation_ref: None,
            metric: "environment".into(),
            value: Some(MetricValue::Str(env.class.label().into())),
            unit: Unit::None,
            baseline_rtt_us: self.baseline_rtt_us,
            ratio_to_rtt: None,
            threshold: String::new(),
            sample: self.sample(SampleKind::Connection),
            scope: FindingScope::default(),
            window,
            evidence: Evidence::default(),
        })
    }

    /// The run roll-up finding — the overall verdict over the full superset of checks.
    fn run_finding(&self, window: TimeWindow) -> Finding {
        let overall = self.overall_verdict();
        // A capture with NO operations judged nothing at the S3 layer, so its roll-up must not
        // publish as `Healthy` to a fleet ingest — that is the machine-side half of the "green
        // because it saw nothing" failure (a connection-only capture from a Go/rustls client).
        // `overall_verdict` names that case `NoOperations`, which `verdict_severity` maps to
        // Unjudged exactly like a missing RTT floor, so there is no special case left here.
        // A ⚠ still stands: the connection-sourced checks (retransmits) CAN warn with no
        // operations, and that judgment is real — there the verdict IS Attention, so the count
        // is appended instead, to say which layer the warning could have come from.
        let no_ops = self.op_total() == 0;
        let severity = verdict_severity(overall);
        let summary = if no_ops && overall == Verdict::Attention {
            format!(
                "{} (0 operations in this capture: only the network path was judged, not any S3 \
                 request)",
                overall.message()
            )
        } else {
            overall.message()
        };
        Finding {
            schema: FindingSchemaTag,
            emitted_at: None,
            source_schema: vec![OPERATION_SCHEMA.into(), CONNECTION_SCHEMA.into()],
            finding_id: "run".into(),
            domain: Domain::Run,
            title: "run health".into(),
            severity,
            verdict: overall.keyword().into(),
            summary,
            recommendation_ref: None,
            metric: "verdict".into(),
            value: None,
            unit: Unit::None,
            baseline_rtt_us: self.baseline_rtt_us,
            ratio_to_rtt: None,
            threshold: String::new(),
            sample: self.sample(SampleKind::Mixed),
            scope: FindingScope::default(),
            window,
            evidence: Evidence::default(),
        }
    }

    /// Build one `Finding` from a row's display fields + structured [`Metric`] + its
    /// drill-down [`Evidence`].
    #[allow(clippy::too_many_arguments)] // assembled from one row; each field is distinct.
    fn finding(
        &self,
        id: &str,
        domain: Domain,
        title: String,
        mark: Mark,
        verdict: &str,
        summary: &str,
        m: &Metric,
        scope: FindingScope,
        window: TimeWindow,
        evidence: Evidence,
    ) -> Finding {
        // Only the run roll-up is Mixed. `baseline_rtt` was, on the claim that it "blends conn +
        // op records (both carry srtt)" — it does not: an operation is emitted while its socket
        // is still open, so `build_op` pins `srtt_us` null on every one of them, and every branch
        // that sets `floor_judged`/`floor_excluded` counts CONNECTIONS or SAMPLES, never an
        // operation. Calling it Mixed told a fleet ingest the floor blends two populations it
        // never blends. (In the sampled fallback the floor rests on `s3tap.sample/1` records,
        // which are per-connection telemetry — Connection-kinded there too, exactly as
        // `retransmit_rate`'s own sampled fallback already is.) `retransmit_rate` was Mixed for
        // the same wrong reason, and therefore
        // published the OP counts, i.e. `judged: 0` on the connection-only captures where it is
        // the only check that can fire and the only thing gating the exit code (review #3).
        // The path-diagnosis rows are likewise purely connection-sourced; the rest are op-based.
        let kind = match id {
            "baseline_rtt" | "retransmit_rate" | "path_min_rtt" | "tls_handshake" | "send_bottleneck" | "bdp_ceiling" | "recv_ceiling"
            | "loss_shape" | "throughput_ramp" | "throughput_aggregate_down"
            | "throughput_aggregate_up" | "bufferbloat_onset" | "loss_timeline_reorder"
            | "loss_timeline_retrans" => SampleKind::Connection,
            _ => SampleKind::Operation,
        };
        // The time-series rows are derived from the s3tap.sample/1 stream — name that as
        // their source, not the op/conn records the rest are built from.
        let source_schema = if is_timeseries(id) {
            vec![SAMPLE_SCHEMA.into()]
        } else {
            vec![OPERATION_SCHEMA.into(), CONNECTION_SCHEMA.into()]
        };
        Finding {
            schema: FindingSchemaTag,
            emitted_at: None,
            source_schema,
            finding_id: id.to_string(),
            domain,
            title,
            severity: mark.severity(),
            verdict: verdict.to_string(),
            summary: summary.to_string(),
            recommendation_ref: None,
            metric: m.name.to_string(),
            value: m.value.map(MetricValue::Num),
            unit: m.unit,
            // Prefer the row's OWN floor (the per-op-joined S3 rows set this) so the finding's
            // baseline matches the denominator its ratio was taken against; else the pooled
            // report baseline for the global rt-relative rows.
            // ROUND, don't truncate: `as u64` discarded the fraction, so a pooled floor of
            // 1001.5 µs published 1001. Under 1 µs either way, but a published denominator
            // should be the one that was used.
            //
            // The fallback to the report-wide floor is for a JUDGED rt-relative row that
            // carries no floor of its own. An UNJUDGED one must not take it: a row that just
            // said "no round-trip baseline — not judged" was still publishing
            // `baseline_rtt_us: 100500` on a two-region capture — handing a consumer the exact
            // blended denominator the row had refused, ready to divide by. The human rail and
            // the machine rail have to agree about whether a floor existed.
            //
            // `baseline_rtt` is the exception, because it is Na for an unrelated reason: it
            // reports the floor rather than judging anything, so it is the ONE row that must
            // publish it. A blanket `mark != Na` gate stripped `baseline_rtt_us` from it on
            // every normal capture — 16000 became null on the fixture — which is why the
            // exception is by id and not by mark.
            baseline_rtt_us: m.baseline_us.map(|u| u.round() as u64).or(
                // Inherit the report floor only when this row actually DIVIDED by it — which
                // is what `ratio_to_rtt.is_some()` says. Keying on `mark != Na` instead let
                // `tls_handshake`, a `Fyi` row with no ratio and no floor of its own, publish
                // the pooled blend on a capture where every sibling row had refused it; and
                // an earlier blanket `mark != Na` stripped the floor from `baseline_rtt` on
                // every normal capture. `baseline_rtt` stays the one exception: it REPORTS the
                // floor rather than judging against it, so it is the row that must carry it.
                if m.rtt_relative
                    && !m.per_op_baseline
                    && (m.ratio_to_rtt.is_some() || id == "baseline_rtt")
                {
                    self.baseline_rtt_us
                } else {
                    None
                },
            ),
            ratio_to_rtt: m.ratio_to_rtt,
            threshold: m.threshold.to_string(),
            // The time-series findings are judged over sample STREAMS, not connections —
            // report that population (conn_count is 0 on a samples-only capture), and for the
            // rows that exist once PER DIRECTION report that direction's streams only.
            sample: if is_timeseries(id) {
                let judged = match id {
                    "throughput_aggregate_down" | "loss_timeline_reorder" => {
                        self.ts_down_stream_count
                    }
                    "throughput_aggregate_up" | "loss_timeline_retrans" => {
                        self.ts_up_stream_count
                    }
                    // throughput_ramp / bufferbloat_onset are one row over every stream.
                    _ => self.ts_stream_count,
                };
                Sample { judged, excluded: 0, kind }
            } else if is_status_mix(id) {
                // These count over the ANSWERED ops, not the latency-eligible subset (the
                // eligibility gate excludes a status >= 400 by construction, i.e. exactly the
                // ops they count — reporting that split made a consumer's `value /
                // sample.judged` read 100% for a true 50% error rate) and not over every op
                // either: the numerators are `http_status.is_some_and(…)`, so a statusless
                // in-flight abort can never be in them. Publishing `op_total()` here diluted
                // the rate by the statusless share, so `doctor --json` and `scorecard --json`
                // reported different error rates for the SAME capture (2× apart when half the
                // ops aborted). Same population on both sides, one rate.
                Sample {
                    judged: self.op_statused,
                    excluded: self.op_total() - self.op_statused,
                    kind,
                }
            } else if let Some(&(_, j, e)) = self.row_pop.iter().find(|(i, _, _)| *i == id) {
                Sample { judged: j, excluded: e, kind }
            } else if is_reuse_rate(id) {
                // The NON-PARTIAL ops, matching what `reuse_row` counted. Publishing
                // `op_total()` here handed a consumer a denominator the ratio was never taken
                // over, and an `excluded: 0` that denied the partial ops had been dropped.
                Sample {
                    judged: self.op_nonpartial,
                    excluded: self.op_total() - self.op_nonpartial,
                    kind,
                }
            } else if id == "baseline_rtt" {
                Sample { judged: self.floor_judged, excluded: self.floor_excluded, kind }
            } else if id == "retransmit_rate" {
                // Closed connections, or the sample streams the fallback rated instead.
                Sample {
                    judged: self.rtx_stream_count.unwrap_or(self.conn_count),
                    excluded: 0,
                    kind,
                }
            } else if self.conn_count == 0 && matches!(id, "bdp_ceiling" | "recv_ceiling") {
                // Sampled-path fallback: these ceilings came from the s3tap.sample/1 stream
                // (no connection closed), so judge over that stream population PER DIRECTION
                // — recv_ceiling over download streams, bdp_ceiling over upload — not
                // conn_count (0 here) and not their union (which over-counts each row).
                let judged = if id == "recv_ceiling" {
                    self.sampled_recv_stream_count
                } else {
                    self.sampled_send_stream_count
                };
                Sample { judged, excluded: 0, kind }
            } else {
                self.sample(kind)
            },
            scope,
            window,
            evidence,
        }
    }

    /// Every operation record in the capture — the denominator the status-mix / http_errors
    /// counts are taken over. Derived, not stored, so it can't drift from the two halves.
    fn op_total(&self) -> usize {
        self.op_judged + self.op_excluded
    }

    /// The population a finding of `kind` is judged over. Each kind reports the population it
    /// NAMES: a Connection-sourced finding the connection count, a Mixed one (the run roll-up)
    /// both — never the op counts alone, which read 0 on a Go/connection-only capture where the
    /// judgment is nonetheless real (review #3).
    fn sample(&self, kind: SampleKind) -> Sample {
        match kind {
            SampleKind::Connection => Sample { judged: self.conn_count, excluded: 0, kind },
            SampleKind::Mixed => Sample {
                judged: self.op_judged + self.conn_count,
                excluded: self.op_excluded,
                kind,
            },
            SampleKind::Operation => {
                Sample { judged: self.op_judged, excluded: self.op_excluded, kind }
            }
        }
    }

    /// The drill-down evidence for a row, looked up by its (unique) label; empty when the
    /// check didn't record any (aggregate median/tail rows).
    fn evidence_for(&self, label: &str) -> Evidence {
        self.evidence.iter().find(|(l, _)| l == label).map(|(_, e)| e.clone()).unwrap_or_default()
    }
}

/// The health domain of a global check (S3-domain rows are always [`Domain::S3`]).
fn global_domain(id: &str) -> Domain {
    match id {
        // send_bottleneck/bdp_ceiling describe the SENDER (local send buffer, app feed),
        // not the path — Client. path_min_rtt/loss_shape are path/Network (review #5/#14).
        "http_errors" | "reuse_rate" | "send_bottleneck" | "bdp_ceiling" | "recv_ceiling" => Domain::Client,
        _ => Domain::Network,
    }
}

/// ELIGIBILITY — the parity gate, shared verbatim with demo/s3stats.py: non-partial,
/// status < 400 (a missing status counts as 0), and not delimitation:ambiguous (a
/// concurrent request → untrustworthy timing). This is the single source of truth for
/// "did this op survive the oracle's filter"; nothing may re-derive it locally.
///
/// It admits an op with NO `http_status` (`unwrap_or(0)` coerces the absent status to 0). The
/// oracle no longer does: its `good` list requires a status, in lock-step with [`is_timeable`].
/// So this gate alone is NOT the oracle's filter and nothing may use it for a LATENCY
/// population — it survives as the shared status-independent half, composed by [`is_timeable`]
/// (the doctor and the scorecard's only caller).
fn is_eligible(o: &Operation) -> bool {
    o.http_status.unwrap_or(0) < 400 && !o.partial && o.delimitation == Delimitation::Clean
}

/// TIMEABILITY — [`is_eligible`] AND the op actually got a response (`http_status`
/// present). The gate for every LATENCY population: the medians/percentiles, the tail,
/// and the throughput rows. Strictly narrower than [`is_eligible`], never a separate
/// rule: the eligibility logic still lives in exactly one place and this composes it.
///
/// The narrowing exists because `is_eligible`'s `unwrap_or(0) < 400` coerces an ABSENT
/// status to 0, so an aborted in-flight request — one S3 never answered — passes it.
/// Such an op can still carry a `ttfb_ns` (an `Expect: 100-continue` interim, or a
/// partial head), and timing it makes a median describe requests that got no response.
/// The scorecard already required a status for exactly this reason (its `latency_sample`
/// must not exceed the row's statused `ops` denominator); the doctor timing the SAME
/// capture on the wider gate meant `s3tap doctor` and `s3tap scorecard` reported
/// contradictory p50s for one file, and the doctor could warn about a TTFB nobody served.
///
/// The split is between LATENCY and RELIABILITY, not between the two commands:
///   * latency (medians, tail, throughput, and the judged/excluded split they report) →
///     `is_timeable`;
///   * status mix + HTTP errors → neither gate, and their NUMERATOR is not their published
///     POPULATION. The numerator ranges over every op in the capture (eligibility would drop a
///     status >= 400 by construction, i.e. exactly what they count) but is written
///     `http_status.is_some_and(…)`, so only an ANSWERED op can enter it. What they publish as
///     `sample.judged` is therefore `op_statused`, not `op_total()`. See [`is_status_mix`].
fn is_timeable(o: &Operation) -> bool {
    is_eligible(o) && o.http_status.is_some()
}

/// The reliability class of an HTTP response status — the SINGLE source of truth for
/// "what kind of failure is this", shared by the doctor's S3-domain status mix
/// ([`s3_domain`]) and the scorecard's reliability taxonomy ([`scorecard`]), so the two
/// can never disagree on a code (a 429 is throttling in BOTH, never a generic client
/// error in one and throttle in the other). Exhaustive AND mutually exclusive BY
/// CONSTRUCTION — a single `match`, not the independent per-class predicates that once
/// let a 429 fall into two buckets at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// 429 Too Many Requests / 503 (SlowDown or ServiceUnavailable) — throttling/backpressure.
    Throttle,
    /// Other 5xx (500/502/504…) — retryable server-side.
    ServerError,
    /// 403 — credentials / bucket policy / request signing.
    Forbidden,
    /// 404 — a missing key.
    NotFound,
    /// 400 — a malformed request.
    BadRequest,
    /// Any other 4xx — a client / permission / signing issue.
    ClientError,
    /// < 400 — not an error.
    Success,
}

/// Classify an HTTP status into its [`StatusClass`]. 429 and 503 are throttling; the
/// specific client codes (400/403/404) are split out from the generic 4xx; everything
/// ≥ 500 that isn't 503 is a retryable server error.
pub fn classify_status(status: u16) -> StatusClass {
    match status {
        429 | 503 => StatusClass::Throttle,
        403 => StatusClass::Forbidden,
        404 => StatusClass::NotFound,
        400 => StatusClass::BadRequest,
        s if (400..500).contains(&s) => StatusClass::ClientError,
        s if s >= 500 => StatusClass::ServerError,
        _ => StatusClass::Success,
    }
}

/// A RELIABILITY finding (the status mix + the global HTTP-error count), as opposed to the
/// latency rows judged over the timeable subset. Its NUMERATOR and its PUBLISHED POPULATION are
/// two different sets, and neither is the latency split:
///   * numerator: scanned over every op in the capture, but written `http_status.is_some_and(…)`,
///     so only an ANSWERED op can be counted;
///   * published population (`sample.judged` in [`Report::finding`]): `op_statused`, the answered
///     ops — the only population that numerator can be drawn from. NOT `op_total()`, which
///     diluted the rate by the statusless share and made `doctor --json` and `scorecard --json`
///     report different error rates for one capture, and NOT the latency `op_judged`, which
///     drops a status >= 400 by construction, i.e. exactly what these rows count.
///
/// [`gate_value`] and the diff's `cur_pop` both depend on that population being `op_statused`.
fn is_status_mix(id: &str) -> bool {
    matches!(id, "http_errors" | "s3_throttle" | "s3_server_errors" | "s3_client_errors")
}

/// The connection-reuse rate, whose population is every NON-PARTIAL operation record.
///
/// Not the latency-eligible subset: an errored or ambiguous op still tells you whether the
/// client reused a connection, and gating on eligibility made the row state a falsehood (a
/// capture with 21 of 26 ops on a reused connection printed "0/5 ops reused ⚠ low"). Not
/// every op either: on a `partial` op the schema says `connection_reused` cannot be
/// attributed, and counting those turned a warm-pool capture into the same false warn
/// mirrored. The same defect `is_status_mix` exists to prevent, one row over.
///
/// Single source of truth for the same reason: [`Report::finding`]'s published population and
/// the diff's `cur_pop` must both agree with what `reuse_row` actually counted, or the two
/// sides of a `--baseline` comparison are drawn from different sets.
fn is_reuse_rate(id: &str) -> bool {
    id == "reuse_rate"
}

/// A row whose population is a SUB-population of the op set, carried per-row in
/// [`Report::row_pop`] rather than inferred. The TTFB tails (the floored subset of one
/// connection-reuse class) and the four global op rows (each filtering `good` on a different
/// field). Single source of truth for the same reason as the two predicates above:
/// [`Report::finding`]'s published `sample` and the diff's `cur_pop` both look the row up in
/// `row_pop`, and a row missing from that list has a population of 0, not `op_judged`.
fn is_row_populationed(id: &str) -> bool {
    matches!(
        id,
        "ttfb_new_p95"
            | "ttfb_new_p99"
            | "ttfb_reused_p95"
            | "ttfb_reused_p99"
            | "dns_cold"
            | "tcp_connect"
            | "ttfb_new"
            | "ttfb_reused"
    )
}

/// A finding derived from the s3tap.sample/1 time-series stream (judged over sample STREAMS,
/// not connections). Single source of truth so [`Report::finding`] can't drift between the
/// `source_schema` and `sample` selections.
fn is_timeseries(id: &str) -> bool {
    matches!(
        id,
        "throughput_ramp"
            | "throughput_aggregate_down"
            | "throughput_aggregate_up"
            | "bufferbloat_onset"
            | "loss_timeline_reorder"
            | "loss_timeline_retrans"
    )
}

/// Max contributing ops named in a finding's [`Evidence`] — a bounded, representative
/// sample so a consumer can drill from the verdict back to the raw records, NOT every op.
const MAX_EVIDENCE: usize = 5;

/// A bounded [`Evidence`] sample from the contributing ops (the Finding contract):
/// each op's `sock_cookie:req_seq` id, its connection cookie (deduped), and any S3
/// `aws_request_id` (the field a support ticket needs). Capped at [`MAX_EVIDENCE`].
fn evidence_of<'a>(ops: impl IntoIterator<Item = &'a Operation>) -> Evidence {
    let mut ev = Evidence::default();
    for o in ops {
        if ev.op_ids.len() < MAX_EVIDENCE {
            ev.op_ids.push(o.op_id.clone()); // the record's canonical op id (schema field)
            ev.sock_cookies.push(o.sock_cookie.to_string());
        }
        // aws_request_id is the support-ticket field and is SPORADIC, so harvest it across
        // all contributing ops (capped separately) — not just the first MAX_EVIDENCE, whose
        // ops might happen to lack the header.
        if ev.aws_request_ids.len() < MAX_EVIDENCE {
            if let Some(id) = &o.aws_request_id {
                ev.aws_request_ids.push(id.clone());
            }
        }
    }
    ev.sock_cookies.sort_unstable();
    ev.sock_cookies.dedup();
    ev
}

/// The finding [`Severity`] for the run roll-up verdict.
fn verdict_severity(v: Verdict) -> Severity {
    match v {
        Verdict::Attention => Severity::Warn,
        // Both "missing denominator" verdicts publish as Unjudged: a fleet ingest must be able
        // to tell "we looked and it was fine" from "there was nothing to look at".
        // `MixedPaths` joins them: a floor exists but nothing was judged against it, which a
        // fleet ingest must be able to tell apart from "we looked and it was fine".
        Verdict::NoBaseline
        | Verdict::NoOperations
        | Verdict::NoResponses
        | Verdict::MixedPaths => Severity::Unjudged,
        Verdict::ChecksPassed | Verdict::Healthy { .. } => Severity::Healthy,
    }
}

// --- median, matching demo/s3stats.py: drop None, sort, even => mean of the two
// middles, odd => the middle. Computed in f64 so the even case can be fractional. ---
fn median(mut xs: Vec<f64>) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(f64::total_cmp);
    let n = xs.len();
    Some(if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    })
}

/// The `p`th percentile (0–100) by the nearest-rank method: sort, take the value at rank
/// `ceil(p/100 · n)` (1-based). Distinct from [`median`] (no interpolation) — a tail
/// estimate, not a parity check, so no oracle constrains the method. `None` if empty.
fn pctl(mut xs: Vec<f64>, p: f64) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(f64::total_cmp);
    let n = xs.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize; // 1-based
    Some(xs[rank.clamp(1, n) - 1])
}

/// Minimum sample size for a meaningful p95 tail estimate — below this the tail check is
/// omitted (the median rows still judge), so a tiny capture's "max" isn't sold as a p95.
const MIN_TAIL_SAMPLE: usize = 20;
/// Minimum sample for a p99 estimate — the deeper the tail, the more samples it needs.
const MIN_P99_SAMPLE: usize = 100;
/// Healthy envelope for the p95 tail: the slow 5% may run hotter than the 4×RTT median
/// line, but a p95 beyond this many RTTs is a real tail problem (GC/throttle-adjacent/
/// cold caches). A first cut, deliberately lenient relative to the median threshold.
const TAIL_RTT_MULT: f64 = 8.0;
/// Healthy envelope for the p99 tail — the worst 1% runs hotter still than the p95.
const P99_RTT_MULT: f64 = 12.0;
/// Healthy envelope for a per-`s3_op` class TTFB median: think-time up to 4×RTT is normal S3
/// server work; beyond it the class warns. The sibling of [`TAIL_RTT_MULT`]/[`P99_RTT_MULT`]
/// for the median line (the display string `"<= 4.0×RTT"` mirrors this value).
const TTFB_RTT_MULT: f64 = 4.0;
/// Healthy TCP-connect envelope: a handshake beyond this many RTTs is a setup problem.
const TCP_CONNECT_RTT_MULT: f64 = 3.0;
/// Healthy retransmit rate (retransmitted segments / segments sent).
const RTX_RATE_MAX: f64 = 0.001;
/// Standard Ethernet-MTU TCP payload (bytes) — estimates segment count from bytes sent.
const TCP_MSS_BYTES: u64 = 1460;
/// A direction (send/recv) must move at least this many bytes before we classify it — stops a
/// small GET being read as an upload, or a small response as a download.
const MIN_DIRECTIONAL_BYTES: u64 = 65_536;
/// Minimum send-side segments before a retransmit RATE means anything — the sample floor this
/// row was missing while every other statistic here had one (MIN_TAIL_SAMPLE, MIN_P99_SAMPLE,
/// MIN_JUDGE_SAMPLE, MIN_REUSE_SAMPLE, the scorecard's MIN_OPS). Derived from
/// [`MIN_DIRECTIONAL_BYTES`], the same "this direction actually moved data" floor the path rows
/// use, so there is one notion of a real send leg (≈44 segments).
///
/// Without it the default `doctor --live --requests 12` GET run — one keep-alive connection
/// sending ~15 KB of request headers, i.e. ~10 segments — rated loss over a denominator so small
/// that the 0.1% tolerance admitted 0.01 retransmits: ONE SYN retransmit or one TLP printed
/// "10.00% ⚠ loss" and exited 1 on a perfectly healthy path. `total_retrans` includes TLP and
/// spurious retransmits, so the numerator is never a pure loss count and needs a denominator big
/// enough for the tolerance to absorb them. This is a floor, not a cure: at exactly 44 segments a
/// single retransmit is still 2.3%. It bounds the row to captures whose send leg moved real data.
const MIN_RATE_SEGMENTS: u64 = MIN_DIRECTIONAL_BYTES / TCP_MSS_BYTES;
/// A real network RTT floor sits far below this; anything larger is a corrupt/adversarial
/// counter — the kernel sentinel `u32::MAX` (≈71 min) or a near-sentinel injected via the
/// untrusted JSONL. Such a value must NEVER become the latency denominator: a huge floor
/// would make every span read as "fast" and silently suppress all latency verdicts. 30 s is
/// orders of magnitude above any real path (satellite WAN is ~0.6 s), so a valid capture
/// never trips it and parity with the oracle is unaffected (never read wrong on
/// untrusted input). A too-LOW floor is not capped — it only inflates ratios (over-warns, the
/// safe direction), never suppresses.
///
/// PUBLIC because the advisor judges the same `min_rtt_us` field off the same untrusted
/// JSONL and must apply the SAME bound (`v != 0 && v < MAX_PLAUSIBLE_RTT_US`). It was
/// re-derived there once and the two drifted: `doctor` rejected a `u32::MAX` floor while
/// `advise` medianed it into a 4294967 ms "high network floor". One constant, one bound.
pub const MAX_PLAUSIBLE_RTT_US: u32 = 30_000_000;

/// A single connection's RTT floor (µs). Prefers `srtt` — the SAME basis as the pooled global
/// floor (`close_srtt`) and the basis the `×RTT` thresholds are calibrated on — and, for the
/// think-time metric (ttfb − network round-trip), the *current* smoothed RTT is the right thing
/// to subtract, not the best-ever propagation floor. Falls back to `min_rtt` only when `srtt`
/// is absent (better a propagation floor than none). Same per-value sentinel/plausibility filter
/// as the pooled floor (0 = never sampled / LRU-evicted; huge = corrupt). `None` when neither
/// field is usable.
fn conn_floor_us(c: &Connection) -> Option<f64> {
    let usable = |v: Option<u32>| v.filter(|&r| r != 0 && r < MAX_PLAUSIBLE_RTT_US).map(f64::from);
    usable(c.srtt_us).or_else(|| usable(c.min_rtt_us))
}

/// The RTT floor (µs) an operation's latency must be judged against. The
/// ladder: (1) join the op to its connection on `sock_cookie` and use THAT connection's floor;
/// (2) else the median floor of the op's region — knowable only via the join, so this applies
/// when the op joined but its own connection had no usable srtt/min_rtt; (3) else the pooled
/// global floor; (4) else `None` (no denominator anywhere → never judged). The ladder exists to
/// avoid a multi-region blend: a us-east op and a cross-region op keep separate floors, never a
/// mean of the two that fits neither and hides a slow op behind the far one.
///
/// The region rung is only consulted for a KNOWN region: pooling every unknown-region (`None`)
/// connection into one bucket would recreate a blend of possibly-distinct paths, so an unknown
/// region falls straight through to the pooled global instead.
///
/// And rung 3 is WITHDRAWN when the capture holds floors for more than one known region,
/// because there it IS the blend the ladder exists to prevent. A capture with us-east-1 at
/// 1 ms and ap-southeast-2 at 200 ms pools a 100.5 ms median that fits neither, and an op that
/// could not be attributed to a region was judged against it: a real 300 ms TTFB read
/// "✓ expected 3.0×RTT (vs its own 100.5 ms floor)". That is a floor that is WRONG rather than
/// absent — false-healthy, the direction this file refuses everywhere else. With two paths in
/// the capture and no way to say which one an op took, there is no honest denominator for it,
/// so it gets none and the row renders Na. Threshold-free on purpose: "more than one known
/// region" is a fact about the capture, not a tuned number.
fn floor_for(
    op: &Operation,
    conn_by_cookie: &ConnByCookie,
    region_floor: &RegionFloor,
    global_us: Option<f64>,
    // `true` when `region_floor` holds floors for 2+ KNOWN regions, i.e. the pooled global is a
    // blend of distinct paths. Computed once by [`multi_region`] and passed down.
    mixed_regions: bool,
) -> Option<f64> {
    if let Some(c) = conn_by_cookie.get(&op.sock_cookie) {
        if let Some(f) = conn_floor_us(c) {
            return Some(f);
        }
        if c.endpoint.region.is_some() {
            // Known region only (the `is_some` guard) — see the doc-comment above.
            if let Some(&rf) = region_floor.get(&c.endpoint.region) {
                return Some(rf);
            }
        }
    }
    // Rung 3, unless it would be a cross-region blend — see the doc comment.
    if mixed_regions {
        return None;
    }
    global_us
}

/// Does this capture hold more than one distinct network PATH, so that a pooled floor would be
/// a blend of paths rather than a floor?
///
/// Two signals, either sufficient, and both taken over CONNECTIONS rather than over
/// `region_floor`'s keys. Keying on the map missed three real shapes, each of which restored
/// the exact false-healthy the withdrawal exists to prevent:
///   - two genuinely distinct paths with NO region label on either (the map has one `None` key);
///   - a region whose connections carry no usable floor, so it never becomes a key at all —
///     yet its ops are still in the capture and may be the slow ones;
///   - the same region spelled differently. The key was the raw `Option<String>` off untrusted
///     JSONL, so `us-east-1` vs `US-EAST-1` read as two paths and turned a 285×RTT ⚠ into a
///     green run. Normalised here, as `s3_op` and `tls.version` already are.
///
/// The bimodal test is the same one [`estimate_environment`] uses to print
/// "mixed (multiple regions/paths)". Sharing it is the point: the report used to say `mixed` on
/// one line and judge against the blend four lines below, two predicates disagreeing inside one
/// render.
fn multi_path(conns: &[&Connection]) -> bool {
    let mut regions: Vec<String> = conns
        .iter()
        .filter_map(|c| c.endpoint.region.as_deref())
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .collect();
    regions.sort_unstable();
    regions.dedup();
    if regions.len() > 1 {
        return true;
    }
    let srtts: Vec<f64> = conns
        .iter()
        .filter_map(|c| c.srtt_us)
        .filter(|&v| v != 0 && v < MAX_PLAUSIBLE_RTT_US)
        .map(f64::from)
        .collect();
    let (lo, hi) = (
        srtts.iter().copied().reduce(f64::min),
        srtts.iter().copied().reduce(f64::max),
    );
    matches!((lo, hi),
        (Some(l), Some(h)) if l > 0.0 && h / l >= ENV_MIXED_SRTT_RATIO && h / 1000.0 >= ENV_FAR_MS)
}

/// Build the two per-op floor lookups for a capture: the `sock_cookie`→
/// connection join and the per-region median floor, both consumed by [`floor_for`].
///
/// A `sock_cookie` is unique per socket LIFETIME, but the kernel `struct sock *` it derives
/// from is reused after free, so a long capture can carry two connection records with the same
/// cookie (a reconnect). A colliding cookie is therefore left OUT of the join map entirely —
/// its ops fall back to the region/global rung rather than trust an ambiguous, possibly
/// cross-region floor. Both records still feed the region medians.
fn build_floor_maps<'a>(conns: &[&'a Connection]) -> (ConnByCookie<'a>, RegionFloor) {
    let mut cookie_counts: HashMap<u64, usize> = HashMap::with_capacity(conns.len());
    for c in conns {
        *cookie_counts.entry(c.sock_cookie).or_default() += 1;
    }
    let conn_by_cookie: ConnByCookie = conns
        .iter()
        .filter(|c| cookie_counts[&c.sock_cookie] == 1) // drop reused (ambiguous) cookies
        .map(|c| (c.sock_cookie, *c))
        .collect();

    let mut floors_by_region: HashMap<Option<String>, Vec<f64>> = HashMap::new();
    for c in conns {
        if let Some(f) = conn_floor_us(c) {
            floors_by_region.entry(c.endpoint.region.clone()).or_default().push(f);
        }
    }
    let region_floor: RegionFloor =
        floors_by_region.into_iter().filter_map(|(k, v)| median(v).map(|m| (k, m))).collect();

    (conn_by_cookie, region_floor)
}

/// Where the client sits relative to S3, estimated from the measured round-trip floor plus the
/// endpoint's region/VPCe/cross-region flags. An ESTIMATE, never a certainty: above ~10 ms
/// with no cross-region flag, cross-region EC2 and WAN/on-prem overlap and can't be split by
/// latency alone — so that case is reported as the honest union, not a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEstimate {
    pub class: EnvClass,
    pub confidence: Confidence,
    /// The srtt and which signal drove the call — the human tail of the report line.
    pub detail: String,
}

/// The estimated deployment environment (see [`EnvEstimate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvClass {
    /// A sub-2 ms floor: the client is in-cloud, same region as the bucket.
    SameRegion,
    /// The endpoint's cross-region flag is set — a different AWS region (authoritative).
    CrossRegion,
    /// A long floor with no cross-region flag: cross-region EC2 or WAN/on-prem, which the
    /// RTT alone can't separate.
    FarPath,
    /// The capture spans more than one region or a bimodal round-trip floor — no single
    /// scalar environment applies, so committing to one class would be misleading.
    Mixed,
}

/// How firm the [`EnvClass`] call is: a flag pinned it (`High`), the RTT sits cleanly in one
/// band (`Likely`), or the bands overlap (`Uncertain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Likely,
    Uncertain,
}

impl EnvClass {
    /// The human label shown in the report.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            EnvClass::SameRegion => "same-region (in-cloud)",
            EnvClass::CrossRegion => "cross-region",
            EnvClass::FarPath => "WAN / on-premises (or cross-region)",
            EnvClass::Mixed => "mixed (multiple regions/paths)",
        }
    }

    /// A short machine keyword for the `--json` finding's `verdict`.
    #[must_use]
    pub fn keyword(self) -> &'static str {
        match self {
            EnvClass::SameRegion => "same-region",
            EnvClass::CrossRegion => "cross-region",
            EnvClass::FarPath => "wan-or-cross-region",
            EnvClass::Mixed => "mixed",
        }
    }
}

impl EnvEstimate {
    /// The text after `environment: ` in the human report (confidence prefix + label + detail).
    #[must_use]
    pub fn line(&self) -> String {
        let prefix = match self.confidence {
            Confidence::High => "",
            Confidence::Likely => "likely ",
            Confidence::Uncertain => "uncertain — ",
        };
        format!("{prefix}{} — {}", self.class.label(), self.detail)
    }
}

/// A sub-2 ms floor is in-datacenter; below this ⇒ same-region.
const ENV_SAME_REGION_MS: f64 = 2.0;
/// Below this a low floor is still most consistent with same-region/metro; at or above it the
/// client is far enough that cross-region EC2 and WAN/on-prem overlap.
const ENV_FAR_MS: f64 = 10.0;
/// A max/min srtt ratio at or above this across connections means two distinct paths (one
/// path's floor varies far less), so a single aggregate estimate would be misleading.
const ENV_MIXED_SRTT_RATIO: f64 = 5.0;

/// The `Mixed` estimate: a heterogeneous capture where no single class applies. `lo`/`hi` are
/// the connection srtt bounds (µs); `why` names the heterogeneity (distinct regions / bimodal).
fn mixed_estimate(lo: Option<f64>, hi: Option<f64>, rtt_str: &str, why: &str) -> EnvEstimate {
    let spread = match (lo, hi) {
        (Some(l), Some(h)) => format!("srtt spans {:.1}–{:.1} ms", l / 1000.0, h / 1000.0),
        _ => rtt_str.to_string(),
    };
    EnvEstimate {
        class: EnvClass::Mixed,
        confidence: Confidence::Uncertain,
        detail: format!("{spread}; {why} in one capture — the per-connection view separates them"),
    }
}

/// Estimate the deployment environment from the round-trip floor + endpoint flags (see
/// [`EnvEstimate`]). `None` when there's no signal at all — no floor AND no cross-region flag.
fn estimate_environment(
    rtt_ms: Option<f64>,
    floor_src: &str,
    conns: &[&Connection],
) -> Option<EnvEstimate> {
    let cross_any = conns.iter().any(|c| c.endpoint.cross_region);
    let cross_all = !conns.is_empty() && conns.iter().all(|c| c.endpoint.cross_region);
    let via_vpce = conns.iter().any(|c| c.endpoint.via_vpce);
    let rtt_str = rtt_ms
        .map_or_else(|| "no round-trip floor".to_string(), |m| format!("{floor_src} {m:.1} ms"));

    // Heterogeneity signals: more than one distinct endpoint region, or a bimodal srtt spread
    // (a near AND a far path coexist — a large ratio whose slow mode is itself far; the
    // `h >= FAR` guard stops same-region srtt jitter among tiny values reading as mixed).
    let mut regions: Vec<&str> = conns.iter().filter_map(|c| c.endpoint.region.as_deref()).collect();
    regions.sort_unstable();
    regions.dedup();
    // Same sentinel + plausibility discipline as every other floor computation
    // (conn_floor_us, close_srtt, path_domain{,_sampled}): a corrupt/crafted srtt in
    // [MAX_PLAUSIBLE_RTT_US, u32::MAX) must not trip the bimodal test and print an
    // implausible span the RTT floor itself rejected.
    let srtts: Vec<f64> = conns
        .iter()
        .filter_map(|c| c.srtt_us)
        .filter(|&s| s != 0 && s < MAX_PLAUSIBLE_RTT_US)
        .map(f64::from)
        .collect();
    let lo = srtts.iter().copied().reduce(f64::min);
    let hi = srtts.iter().copied().reduce(f64::max);
    let bimodal = matches!((lo, hi),
        (Some(l), Some(h)) if l > 0.0 && h / l >= ENV_MIXED_SRTT_RATIO && h / 1000.0 >= ENV_FAR_MS);

    let cross_region_estimate = || EnvEstimate {
        class: EnvClass::CrossRegion,
        confidence: Confidence::High,
        detail: format!("{rtt_str}; the endpoint's cross-region flag is set"),
    };
    // Precedence matters (the flag is authoritative, so it must beat the srtt heuristic):
    // 1. More than one distinct region ⇒ genuine heterogeneity, even if all cross-region.
    if regions.len() > 1 {
        return Some(mixed_estimate(lo, hi, &rtt_str, &format!("{} distinct endpoint regions", regions.len())));
    }
    // 2. UNIFORMLY cross-region ⇒ the authoritative flag wins over an srtt-jitter spread.
    if cross_all {
        return Some(cross_region_estimate());
    }
    // 3. A bimodal floor not explained by a uniform flag ⇒ two paths in one capture.
    if bimodal {
        return Some(mixed_estimate(lo, hi, &rtt_str, "a bimodal round-trip floor"));
    }
    // 4. A cross-region flag on some path (single region, no bimodal) ⇒ cross-region.
    if cross_any {
        return Some(cross_region_estimate());
    }
    // No distance signal and no flag ⇒ nothing to estimate from.
    let ms = rtt_ms?;
    // NB a VPC endpoint means AWS-side traffic but does NOT override the floor: reached from
    // on-prem over Direct Connect / VPN a VPCe still carries a WAN round-trip, so it only
    // FIRMS UP a low-floor same-region call — a long floor is still a far path.
    if ms < ENV_SAME_REGION_MS {
        Some(EnvEstimate {
            class: EnvClass::SameRegion,
            confidence: Confidence::High,
            detail: format!("{rtt_str}, a sub-{ENV_SAME_REGION_MS:.0} ms floor (in-datacenter)"),
        })
    } else if ms < ENV_FAR_MS {
        Some(EnvEstimate {
            class: EnvClass::SameRegion,
            // A VPC endpoint at a low floor is confidently in-region; otherwise just likely.
            confidence: if via_vpce { Confidence::High } else { Confidence::Likely },
            detail: if via_vpce {
                format!("{rtt_str}, a low floor via a VPC endpoint (in-AWS, same-region)")
            } else {
                format!("{rtt_str}, a low floor most consistent with same-region")
            },
        })
    } else {
        Some(EnvEstimate {
            class: EnvClass::FarPath,
            confidence: Confidence::Uncertain,
            detail: if via_vpce {
                format!(
                    "{rtt_str}, a long floor via a VPC endpoint — AWS-side but far \
                     (on-prem over Direct Connect, or cross-region)"
                )
            } else {
                format!(
                    "{rtt_str}, a long floor; cross-region EC2 and WAN/on-prem overlap here \
                     (check the endpoint's region to tell them apart)"
                )
            },
        })
    }
}

/// Judge a capture. Faithful port of demo/s3stats.py (the reference oracle): the two agree
/// on marks + verdict for any capture with a send-byte denominator (parity-tested). Both
/// refuse to rate loss below [`MIN_RATE_SEGMENTS`] segments sent, reporting the retransmit row
/// `Na` rather than dividing by a fabricated or meaningless denominator (see
/// `persistent_pool_retransmits_without_send_bytes_is_na_not_a_false_loss` and
/// `a_tiny_send_leg_cannot_rate_loss`). The doctor's supersets (the S3 domain, tail, reuse,
/// path and time-series sections) have no oracle counterpart and are pinned by unit tests.
#[must_use]
pub fn analyze(records: &[Record]) -> Report {
    analyze_with(records, ParseStats::default())
}

/// Like [`analyze`] but carrying the [`ParseStats`] from [`parse_records`] for the report.
#[must_use]
pub fn analyze_with(records: &[Record], parse: ParseStats) -> Report {
    let ops: Vec<&Operation> = records
        .iter()
        .filter_map(|r| match r {
            Record::Operation(o) => Some(o),
            Record::Connection(_) | Record::TcpSample(_) => None,
        })
        .collect();
    let conns: Vec<&Connection> = records
        .iter()
        .filter_map(|r| match r {
            Record::Connection(c) => Some(c),
            Record::Operation(_) | Record::TcpSample(_) => None,
        })
        .collect();
    // In-flight samples (s3tap.sample/1) — their OWN population. Deliberately NOT in
    // `ops`/`conns`, so they never feed the parity-pinned CLOSE-TIME srtt floor. (Their
    // timestamps DO widen the reported capture `window` — see there.) They also supply, when
    // no connection closed (a persistent pool): the
    // FALLBACK RTT floor below, the FALLBACK retransmit-rate denominator (`sample_send_deltas`),
    // and the FYI time-series section.
    let samples: Vec<&TcpSample> = records
        .iter()
        .filter_map(|r| match r {
            Record::TcpSample(s) => Some(s),
            Record::Operation(_) | Record::Connection(_) => None,
        })
        .collect();

    // The network floor (µs), every latency span's denominator. Primary source: srtt read at
    // connection CLOSE (parity-pinned), i.e. CONNECTION records only. This used to chain the
    // operations' `srtt_us` too, on the claim that it was "present on both ops+conns" — it is
    // not: an operation record is emitted while its socket is still open, so `build_op` pins
    // that field null on every op s3tap has ever emitted (the schema now says so field by
    // field). Chaining it added an always-empty source AND, through `pool` below, counted every
    // operation as a record that "could have supplied a floor but didn't", so an 8-op capture
    // published the floor as 1 of 9 when 1 of 1 is the truth. Sentinel 0 filtered out, and an
    // implausibly huge value (corrupt/adversarial) rejected so it can't suppress verdicts.
    // Kept as a vec (not folded straight into `median`) so the COUNT of values that actually
    // entered the floor can be published as the baseline_rtt finding's population — a floor
    // resting on one srtt and one resting on 500 are not the same claim (review #3).
    let close_srtt_vals: Vec<f64> = conns
        .iter()
        .filter_map(|c| c.srtt_us)
        .map(f64::from)
        // Filter PER VALUE (not the median result): a sentinel 0 (socket never sampled /
        // LRU-evicted) or an implausibly huge corrupt value is not a data
        // point and must not enter the median at all. Mirrors the sampled path below.
        .filter(|&s| s != 0.0 && s < f64::from(MAX_PLAUSIBLE_RTT_US))
        .collect();
    let close_srtt_n = close_srtt_vals.len();
    let close_srtt = median(close_srtt_vals);
    // Fallback: when NO connection closed in the window (a long-lived pool — the *common*
    // persistent-pool case, not an edge case), the close-time floor is absent, but the
    // in-flight sample stream (`--sample-interval-ms`) still carries a live floor. Prefer
    // `min_rtt` (the true propagation floor — it doesn't inflate under load), then sampled
    // srtt. This is what turns a "NO BASELINE" on a steady pool into a real verdict.
    // Returns the floor AND how many samples supplied it, for the same reason as above.
    let sample_floor = |pick: fn(&TcpSample) -> Option<u32>| -> (Option<f64>, usize) {
        let vals: Vec<f64> = samples
            .iter()
            .filter_map(|s| pick(s))
            // Excludes the kernel sentinels (0, u32::MAX) AND any near-sentinel/corrupt
            // value — `r < MAX_PLAUSIBLE_RTT_US` subsumes `!= u32::MAX`.
            .filter(|&r| r != 0 && r < MAX_PLAUSIBLE_RTT_US)
            .map(f64::from)
            .collect();
        let n = vals.len();
        (median(vals), n)
    };
    // `floor_src` names the floor's true source (srtt / min_rtt) so every consumer — the
    // baseline row AND the environment estimate — labels it the same way, never calling a
    // sampled min_rtt "srtt". `floor_judged`/`floor_excluded` are the population the floor
    // itself rests on: the records that supplied a usable value, and the records of that same
    // kind that could have but didn't. Never the op counts, which are 0 on a connection-only
    // (Go/rustls) capture where the floor is nevertheless real.
    let sampled_min_rtt = sample_floor(|s| s.min_rtt_us);
    let sampled_srtt = sample_floor(|s| s.srtt_us);
    let (floor_us, floor_label, floor_src, floor_judged, floor_excluded) =
        if let Some(s) = close_srtt {
            // The population is the CONNECTIONS: the records of the kind that supplies a
            // close-time srtt. Operations are not in it (they never carry one), so they are
            // not counted as excluded either — an excluded count is a claim that a record
            // could have contributed.
            (Some(s), "baseline RTT (srtt)", "srtt", close_srtt_n, conns.len() - close_srtt_n)
        } else if let (Some(m), n) = sampled_min_rtt {
            (Some(m), "baseline RTT (min_rtt, sampled)", "min_rtt (sampled)", n, samples.len() - n)
        } else if let (Some(s), n) = sampled_srtt {
            // `srtt` is measurable on
            // BOTH connections (the close-time value `close_srtt` just failed to find any of)
            // — as, in fact, is `min_rtt`: `Connection` carries `min_rtt_us` too, and
            // `conn_floor_us` uses it. This ladder deliberately does not, which is why a
            // capture whose connections carry only `min_rtt` reports every GLOBAL row as
            // "no round-trip baseline" while the per-op rows judge the same ops off the
            // cookie join. Widening it is a behaviour change to the parity-pinned floor, so
            // it is recorded here rather than done in passing.
            // and samples, so both are "of that same kind" here. `close_srtt_n` is 0 whenever
            // this branch runs (the `close_srtt` match above returned `None`), so every
            // connection failed to supply one and belongs in the excluded count alongside the
            // samples that didn't carry a usable sampled srtt either.
            (Some(s), "baseline RTT (srtt, sampled)", "srtt (sampled)", n, conns.len() + samples.len() - n)
        } else {
            // No denominator anywhere — the honesty corollary: no latency verdict. Everything
            // that could have carried one is `excluded`, so the 0 reads as "nothing supplied a
            // floor", not as "there was nothing to look at". Connections and samples are that
            // "everything": an operation record carries no srtt to supply (see above), so
            // including the ops here inflated the excluded count with records that were never
            // candidates.
            (None, "baseline RTT (srtt)", "srtt", 0, conns.len() + samples.len())
        };
    // The per-op floor lookups, built HERE rather than beside their first use further down,
    // because the global rt-relative rows below need `mixed_regions` and they are built first.
    // Hoisting it is what keeps ONE definition of "is the pooled floor a blend": a second,
    // hand-rolled copy guarded by a `debug_assert` was two implementations of one predicate,
    // compiled out in release exactly where a drift would matter.
    let (conn_by_cookie, region_floor) = build_floor_maps(&conns);
    let mixed_regions = multi_path(&conns);
    let rtt_ms = floor_us.map(|s| s / 1000.0);
    let baseline_rtt_us = floor_us.map(|s| s as u64);
    // What the GLOBAL rt-relative rows are allowed to divide by. A blended floor is withheld
    // from them — judging a 300 ms TTFB as "3.0×RTT ✓ expected" against a 100.5 ms median of a
    // 1 ms path and a 200 ms path is a floor that is wrong rather than absent — while
    // `rtt_ms` itself stays intact for the baseline row, the environment estimate and the run
    // verdict. Withdrawing it globally instead made the run report NO BASELINE and exit 2 on a
    // capture where every op HAD joined its own connection and been judged against it, with a
    // verdict line claiming no connection closed in the window. The blend is a problem for the
    // pooled DENOMINATOR, not for the existence of a floor.
    let row_rtt_ms = if mixed_regions { None } else { rtt_ms };

    // Capture window for the finding records (step 4): min/max ts over ALL records, samples
    // included. The samples are excluded from every JUDGED population (the srtt floor, the
    // retransmit denominator, the eligible-op set) because they'd move a verdict there; the
    // window moves no verdict and is asserted by no parity test, so leaving them out only
    // made a samples-only capture report a false (0, 0) span on every finding.
    let ts: Vec<u64> = ops
        .iter()
        .filter_map(|o| o.ts_ns)
        .chain(conns.iter().filter_map(|c| c.ts_ns))
        .chain(samples.iter().filter_map(|s| s.ts_ns))
        .collect();
    let window = (ts.iter().copied().min().unwrap_or(0), ts.iter().copied().max().unwrap_or(0));

    // Timeability: a "good" op is eligible (non-partial, status < 400, NOT
    // delimitation:ambiguous — a second request arrived before the response, so its
    // ttfb/connect timing isn't cleanly attributable) AND carries a status, i.e. S3
    // really answered it. Latency stats + the judged/excluded counts use good ops only.
    // (s3stats.py gates the first three, kept in lock-step for parity; the status
    // requirement is the doctor-side narrowing documented on `is_timeable` — the status
    // mix and the HTTP-error count below deliberately stay off both gates.)
    let good: Vec<&&Operation> = ops
        .iter()
        .filter(|o| is_timeable(o))
        .collect();

    // Cold-resolve median reads the ELIGIBLE (`good`) ops, not raw ops: DNS timing off a
    // partial/ambiguous/error op isn't trustworthy, and eligibility gates live in one place.
    // Kept in lock-step with s3stats.py (which now also reads `good`).
    let dns_cold = median(
        good.iter()
            .filter_map(|o| o.dns.as_ref())
            .filter(|d| !d.cache_hit)
            .map(|d| d.latency_ns as f64)
            .collect(),
    );
    let tcp = median(good.iter().filter_map(|o| o.tcp_connect_ns).map(|n| n as f64).collect());
    // Keep the TTFB sample vectors so the tail (p95) is computed over the same population
    // as the median headline (the slow-tail check below).
    let ttfb_new_samples: Vec<f64> = good
        .iter()
        .filter(|o| !o.connection_reused)
        .filter_map(|o| o.ttfb_ns)
        .map(|n| n as f64)
        .collect();
    let ttfb_new = median(ttfb_new_samples.clone());
    let ttfb_reu_samples: Vec<f64> = good
        .iter()
        .filter(|o| o.connection_reused)
        .filter_map(|o| o.ttfb_ns)
        .map(|n| n as f64)
        .collect();
    let ttfb_reu = median(ttfb_reu_samples.clone());
    let error_ops: Vec<&Operation> =
        ops.iter().copied().filter(|o| o.http_status.is_some_and(|s| s >= 400)).collect();
    let errors: Vec<u16> = error_ops.iter().filter_map(|o| o.http_status).collect();
    // Retransmit rate = retransmitted segments / segments sent. Primary denominator: the
    // closed connections' cumulative bytes_sent (parity-pinned with s3stats.py). Saturate,
    // don't `.sum()`: bytes_sent is an unvalidated u64 from the JSONL, so a corrupt/adversarial
    // capture with near-u64::MAX values would otherwise panic (debug) or wrap to a bogus
    // denominator (release) — a broken capture must be reported, never crash or read wrong.
    let close_sent: u64 = conns.iter().fold(0u64, |a, c| a.saturating_add(c.bytes_sent));
    // Numerator from the SAME population as the denominator: CONNECTION records only.
    // `Operation.retransmits` is documented (s3tap-schema) as cumulative for the WHOLE
    // connection, not for that op, so N ops sharing one socket each repeat the same counter —
    // adding them to the connection's own copy multiplied the numerator by N+1 over a
    // single-socket `close_sent`, flipping HEALTHY→ATTENTION (and exit 0→1) on a clean
    // capture. The sampled fallback below already avoids this for the same reason.
    // Saturating, like `close_sent`: keep the file's "never wrap on untrusted counts" discipline
    // even though overflowing u64 here would need ~2^32 records (the `.sum()` it replaces could
    // wrap in debug on a crafted count).
    let close_rtx: u64 =
        conns.iter().map(|c| u64::from(c.retransmits)).fold(0u64, u64::saturating_add);
    // Fallback (mirrors the RTT-floor fallback): a persistent pool that closed NO connection
    // in the window has `close_sent == 0`, so the close-time denominator is absent. Take BOTH
    // the numerator and the denominator from the in-flight sample stream then — one consistent
    // population. This matters for correctness, not just coverage: `op.retransmits`/`bytes_sent`
    // are cumulative FOR THE WHOLE CONNECTION, so summing them across a pool's
    // reused ops would over-count; the per-segment sample deltas are true in-window counts.
    // `rtx_streams` carries the POPULATION of the sampled branch so the emitted finding can
    // publish it (review #3): on that path conn_count is 0 by construction, so reporting the
    // connection count would tell a fleet gate this row was judged over nothing.
    let (rtx, sent_bytes, rtx_sampled, rtx_streams) = if close_sent > 0 {
        (close_rtx, close_sent, false, None)
    } else {
        let (s_sent, s_rtx, s_streams) = sample_send_deltas(&samples);
        (s_rtx, s_sent, true, Some(s_streams))
    };

    let mut rows = Vec::new();

    // Keyed on `floor_us`, not on `rtt_ms`: a blended floor is WITHHELD from the rt-relative
    // rows but must still be REPORTED, or a mixed-region capture loses the one row that says
    // what was measured and why nothing below is being judged against it.
    if let Some(rtt) = floor_us.map(|s| s / 1000.0) {
        let sampled = floor_label.contains("sampled");
        rows.push(Row {
            id: "baseline_rtt",
            label: floor_label,
            value: format!("{rtt:>5.1} ms"),
            mark: Mark::Na,
            verdict: "floor",
            note: if mixed_regions {
                "the pooled round-trip median, NOT used as a floor: this capture spans two or \
                 more endpoint regions, so a single median fits neither path — the spans below \
                 are judged per-connection or not at all"
                    .into()
            } else if sampled {
                "the network round-trip floor, from in-flight samples (no connection closed \
                 in the window) — every span below is judged against it"
                    .into()
            } else {
                "the network round-trip floor — every span below is judged against it".into()
            },
            metric: Metric {
                name: "baseline_rtt",
                value: Some(rtt),
                unit: Unit::Ms,
                rtt_relative: true,
                ..Default::default()
            },
        });
    }

    // Cold resolve: REPORTED, never judged. There is no honest envelope for it. An absolute
    // "< 50 ms" is exactly the invented number the Core discipline forbids — it exits 1 on a
    // clean on-prem/WAN capture whose own environment estimate calls the path far. Nor can it
    // be made RTT-relative like every other span here: the floor is the round-trip to the S3
    // ENDPOINT, and the resolver sits on a different path doing recursion, so a same-region
    // capture (sub-ms floor, a routine 15 ms recursive resolve) would read as 30×RTT and warn
    // on every run. With no denominator that means anything, this is telemetry — Mark::Fyi, so
    // it never gates, not even under --strict.
    if let Some(dns) = dns_cold {
        let ms = dns / 1e6;
        rows.push(Row {
            id: "dns_cold",
            label: "DNS, cold resolve",
            value: format!("{ms:>5.1} ms"),
            mark: Mark::Fyi,
            verdict: "fyi",
            note: "first lookup (cached resolves are ~0) — not judged: the resolver is on a \
                   different path than the endpoint, so the RTT floor is not its baseline"
                .into(),
            metric: Metric {
                name: "dns_cold",
                value: Some(ms),
                unit: Unit::Ms,
                ..Default::default()
            },
        });
    }

    // The TCP/TTFB spans are judged RELATIVE to the RTT floor; with no floor they are
    // shown but marked n/a — never a false ✓ (corollary).
    if let Some(t) = tcp {
        let ms = t / 1e6;
        rows.push(ratio_row(
            "tcp_connect",
            "TCP connect",
            ms,
            row_rtt_ms,
            // One-sided: only a SLOW handshake is a problem. A connect FASTER than the floor
            // is benign — `srtt` is lifetime-smoothed and routinely exceeds the clean initial
            // SYN/SYN-ACK RTT, so a low ratio (e.g. 0.4×) is normal, not "high" (don't cry
            // wolf on a healthy connection — a real CDN/S3 GET hit exactly this).
            |r| r <= TCP_CONNECT_RTT_MULT,
            ("expected", "high"),
            "<= 3.0×RTT",
            |r| {
                if r <= TCP_CONNECT_RTT_MULT {
                    format!("≈{r:.1}×RTT — a single SYN/SYN-ACK, as expected")
                } else {
                    format!("{r:.1}×RTT — slow handshake (SYN retransmit or a slow server accept)")
                }
            },
        ));
    }
    if let Some(t) = ttfb_new {
        let ms = t / 1e6;
        rows.push(ratio_row(
            "ttfb_new",
            "TTFB, new conn",
            ms,
            row_rtt_ms,
            |r| r <= 4.0,
            ("expected", "high"),
            "<= 4.0×RTT",
            |r| format!("{r:.1}×RTT — request round-trip + server think (excludes setup)"),
        ));
    }
    if let Some(t) = ttfb_reu {
        let ms = t / 1e6;
        // reuse saving = the avoided setup (median tcp_connect), NOT a ttfb delta.
        let saved = tcp.map(|t| t / 1e6).filter(|&s| s > 0.0);
        rows.push(ratio_row(
            "ttfb_reused",
            "TTFB, reused conn",
            ms,
            row_rtt_ms,
            |r| r <= 4.0,
            ("good", "high"),
            "<= 4.0×RTT",
            move |r| {
                let mut note = format!("{r:.1}×RTT — setup already paid");
                if let Some(s) = saved {
                    note += &format!("; reuse avoids ~{s:.1} ms tcp_connect/op (+ TLS)");
                }
                note
            },
        ));
    }

    // Retransmits: a RATE vs segments-sent with a small TLP tolerance, not a bare != 0.
    // Two ways there is no honest rate, both Mark::Na so neither can gate:
    //   * no send-bytes denominator at all (`sent_bytes == 0`) — either no connection closed AND
    //     no samples, or the samples show no send-side byte movement (a download-only / idle
    //     pool). Report n/a rather than divide by a fabricated 1-segment floor.
    //   * a denominator too SMALL to rate ([`MIN_RATE_SEGMENTS`]) — the same honesty corollary
    //     one step up: on ~10 segments the 0.1% tolerance admits 0.01 retransmits, so one TLP
    //     reads as "10.00% loss" on a healthy path. A sample floor, like every other statistic
    //     in this file has.
    let segs = sent_bytes / TCP_MSS_BYTES;
    if segs < MIN_RATE_SEGMENTS {
        rows.push(Row {
            id: "retransmit_rate",
            label: "retransmit rate",
            value: "  n/a".into(),
            mark: Mark::Na,
            verdict: "n/a",
            // The cause differs by what's present — don't assert "no samples" when samples
            // exist (the baseline row may itself be sample-derived): only steer to
            // --sample-interval-ms when there were genuinely no samples to rate against.
            note: if sent_bytes == 0 && samples.is_empty() {
                "no send-side bytes to rate loss against, and no in-flight samples — re-capture \
                 with `--sample-interval-ms` to rate loss on a pool that closes no connection"
                    .into()
            } else if sent_bytes == 0 {
                "no send-side bytes moved in the window to rate loss against — a download-only \
                 or idle pool sends too little to estimate send-side loss"
                    .into()
            } else {
                format!(
                    "too few send-side segments to rate loss: ~{segs} sent (< {MIN_RATE_SEGMENTS}), \
                     {rtx} retransmit(s) counted — at this denominator one tail-loss probe alone \
                     would read as {:.2}% \"loss\", so the count is shown and not judged",
                    100.0 / segs.max(1) as f64
                )
            },
            metric: Metric { name: "retransmit_rate", unit: Unit::Ratio, ..Default::default() },
        });
    } else {
    let rtx_rate = rtx as f64 / segs as f64;
    let rtx_ok = rtx_rate <= RTX_RATE_MAX;
    // Honest retransmit VOLUME (tcp_sock.bytes_retrans) — appended to the NOTE only. The
    // rate/verdict stay on the segment estimate so the parity oracle (demo/s3stats.py) is
    // unchanged; the byte count is supplementary evidence, never a gating input.
    // (bytes_retrans rides the connection record, so the KB-volume suffix is a close-path
    // extra; in the sampled fallback there are no such closed conns to sum, so it's absent.)
    let bret: u64 = conns.iter().fold(0u64, |a, c| a.saturating_add(c.bytes_retrans.unwrap_or(0)));
    rows.push(Row {
        id: "retransmit_rate",
        label: "retransmit rate",
        value: format!("{:>6.2}%", rtx_rate * 100.0),
        mark: if rtx_ok { Mark::Ok } else { Mark::Warn },
        verdict: if rtx_ok { "clean" } else { "loss" },
        note: {
            // NOT "(TLP excluded)" — nothing excludes them. `total_retrans` counts tail-loss
            // probes and spurious (DSACK'd) retransmits alongside real ones; what makes this
            // clean is that the RATE stayed inside the tolerance, over a denominator big enough
            // (MIN_RATE_SEGMENTS) for that tolerance to mean something. Say what is true.
            let mut n = if rtx_ok {
                format!(
                    "no real loss on the path ({rtx} retransmit(s) / ~{segs} segs — TLP and \
                     spurious retransmits are counted here, absorbed by the {:.1}% tolerance)",
                    RTX_RATE_MAX * 100.0
                )
            } else {
                format!("{rtx} retransmit(s) / ~{segs} segs — the path dropped packets, latency suffered")
            };
            if rtx_sampled {
                // The close-time denominator was absent (persistent pool); this rate is the
                // send-side loss from the in-flight sample deltas, over the same window.
                n.push_str(" [from in-flight samples; no connection closed in the window]");
            }
            if bret > 0 {
                // On the clean branch the rate gate already ruled out real loss, so a nonzero
                // byte volume is TLP/spurious — say so, else "no real loss ... (8.2 KB
                // retransmitted)" reads as self-contradictory.
                n.push_str(&if rtx_ok {
                    format!(" ({:.1} KB retransmitted, within TLP/spurious tolerance)", bret as f64 / 1e3)
                } else {
                    format!(" ({:.1} KB retransmitted)", bret as f64 / 1e3)
                });
            }
            n
        },
        metric: Metric {
            name: "retransmit_rate",
            value: Some(rtx_rate),
            unit: Unit::Ratio,
            threshold: "<= 0.001",
            ..Default::default()
        },
    });
    }

    let nerr = errors.len();
    // Ops S3 actually answered. The human row below keeps `ops.len()` as its denominator for
    // parity with the oracle, but the JSON finding rates the error count over THIS — the only
    // population the numerator can be drawn from (see `Report::op_statused`).
    let op_statused = ops.iter().filter(|o| o.http_status.is_some()).count();
    if op_statused == 0 {
        // "0 / N ✓ healthy — all operations 2xx/204" is an affirmative claim over a set in which
        // NOTHING was answered: no op could have been 2xx, and none could have been an error
        // either, because the numerator is `http_status.is_some_and(…)`. The 0 is then a
        // construction, not a measurement. TWO capture shapes land here and both used to print
        // that green tick:
        //   * ZERO operation records — a Go/rustls client, or a capture without the uprobe caps:
        //     connection records and nothing at the HTTP layer;
        //   * operations that were ALL aborted in flight, which `flush_open_ops` makes routine
        //     at SIGINT. `op_statused == 0` with `ops.len()` > 0.
        // Report both n/a with NO value — the same honesty corollary the latency rows apply
        // without a floor. (Gating only on `ops.is_empty()` left the second shape affirming
        // "HTTP errors 0 / 5 ✓ healthy" and publishing `value: 0.0` beside `sample.judged: 0`,
        // i.e. a 0/0 NaN for any consumer computing an error rate.)
        //
        // The run VERDICT is deliberately not widened to [`Verdict::NoOperations`] for the
        // second shape: that verdict's message and remedy ("no S3 request was decoded …
        // re-capture with `--capture-plaintext`") are false for a capture that decoded every
        // request and merely never saw the responses, and it would send an operator after the
        // wrong fix. That capture reaches CHECKS PASSED, whose "no latency spans available to
        // judge against the floor (no timeable operations)" is exactly true of it.
        rows.push(Row {
            id: "http_errors",
            label: "HTTP errors",
            value: "  n/a".into(),
            mark: Mark::Na,
            verdict: "n/a",
            note: if ops.is_empty() {
                "no operations in this capture — the HTTP layer was not observed (a client \
                 whose TLS s3tap could not read, or a capture without the uprobe caps), so \
                 nothing was judged 2xx"
                    .into()
            } else {
                format!(
                    "none of the {} operations in this capture was answered (no http_status: \
                     every request was still in flight when the capture ended), so nothing was \
                     judged 2xx and no error could have been counted",
                    ops.len()
                )
            },
            metric: Metric {
                name: "http_errors",
                // No value: 0 errors over 0 ANSWERED ops is not a measurement, and a consumer
                // computing value/sample.judged must not read it as a clean 0% error rate.
                unit: Unit::Count,
                threshold: "== 0",
                ..Default::default()
            },
        });
    } else {
    rows.push(Row {
        id: "http_errors",
        label: "HTTP errors",
        value: format!("{nerr:>4} / {}", ops.len()),
        mark: if nerr == 0 { Mark::Ok } else { Mark::Warn },
        verdict: if nerr == 0 { "healthy" } else { "errors" },
        note: {
            let mut n = if nerr == 0 {
                "all operations 2xx/204".to_string()
            } else {
                let codes: Vec<String> = errors.iter().map(u16::to_string).collect();
                format!("status >=400: {}", codes.join(", "))
            };
            // Name the denominator whenever it is NOT the population the count came from.
            // "0 / 200 — all operations 2xx/204" over 100 answered ops is an affirmative claim
            // about 100 requests nobody saw the end of; the JSON finding rates the 100.
            if op_statused < ops.len() {
                n.push_str(&format!(
                    " (of {} ops, only {op_statused} were answered — the /{} denominator counts \
                     every op, for parity with the oracle, while the --json finding rates the \
                     answered ones)",
                    ops.len(),
                    ops.len(),
                ));
            }
            n
        },
        metric: Metric {
            name: "http_errors",
            value: Some(nerr as f64),
            unit: Unit::Count,
            threshold: "== 0",
            ..Default::default()
        },
    });
    }

    // Verdict precedence (GLOBAL — kept s3stats.py-faithful for parity).
    let attention = rows.iter().any(|r| r.mark == Mark::Warn);
    let judged = tcp.is_some() || ttfb_new.is_some() || ttfb_reu.is_some();
    let verdict = if attention {
        Verdict::Attention
    } else if rtt_ms.is_none() {
        Verdict::NoBaseline
    } else if !judged {
        Verdict::ChecksPassed
    } else {
        Verdict::Healthy { reuse_working: ttfb_reu.is_some() }
    };

    // The per-op-class S3 rows judge each op against ITS OWN connection's floor (or its
    // region's median), never the pooled blend. The global rows above use `row_rtt_ms`, which
    // is the pooled floor EXCEPT on a multi-path capture, where it is withheld — see
    // `multi_path`. (This comment used to say the global rows "stay on the pooled `rtt_ms`",
    // which stopped being true the moment the withdrawal landed.) See `build_floor_maps` for
    // the cookie-reuse handling.

    // S3 domain (step 3): per-op-class detail beyond the flat oracle. Empty when no
    // op-class is identified (so a capture without HTTP semantics is unchanged). Also
    // yields the per-row drill-down evidence for the S3 checks.
    let (s3, mut evidence) = s3_domain(&ops, &conn_by_cookie, &region_floor, floor_us, mixed_regions);
    // HTTP-errors drill-down: the failing ops' ids/cookies/aws_request_ids (step-2 fix #2).
    if !error_ops.is_empty() {
        evidence.push(("HTTP errors".to_string(), evidence_of(error_ops.iter().copied())));
    }

    // Tail latency (p95): the slow 5% the median hides — for SLA/throttling the tail IS
    // the story. A superset like the S3 domain: it can escalate overall_verdict() but
    // leaves the median-only global `verdict` (parity-pinned) untouched. Emitted only
    // with enough samples (MIN_TAIL_SAMPLE) so a tiny capture's max isn't sold as a p95.
    // Each tail sample carries the op's OWN floor (the same join `s3_domain` uses), not the
    // pooled `rtt_ms` — see `tail_rows`. `floor_for` falls back to the pooled global, so the
    // `None` arm means the capture has no floor at all, which is the case that renders Na.
    let tail_pairs = |reused: bool| -> Vec<(f64, Option<f64>)> {
        good.iter()
            .filter(|o| o.connection_reused == reused)
            .filter_map(|o| {
                let t = o.ttfb_ns? as f64 / 1e6;
                Some((t, floor_for(o, &conn_by_cookie, &region_floor, floor_us, mixed_regions).map(|f| f / 1e3)))
            })
            .collect()
    };
    let (tail, mut row_pop) = tail_rows(&tail_pairs(false), &tail_pairs(true));
    // The four global op rows each filter `good` differently, so each has its own population
    // and none of them is `op_judged`. Publishing `op_judged` for all four told a consumer that
    // `dns_cold` judged 100 when 3 ops carried a cold resolve, and that `ttfb_new` — a ⚠ at
    // 100xRTT drawn from 5 new-connection ops — judged 100 as well.
    //
    // `excluded` counts CANDIDATES THAT WERE DROPPED, never "everything else in the capture".
    // That is the convention `tail_rows` already used, and mixing the two made `ttfb_new` and
    // `ttfb_new_p95` — computed from the very same vector — publish 25/75 and 25/0, so a
    // consumer taking `judged/(judged+excluded)` as coverage read 25% and 100% for one set of
    // 25 samples. An op on the other side of the reuse split was never a candidate for
    // `ttfb_new`; it is not "excluded", it is a different population.
    // A CANDIDATE is a record that carried what this row needs and could therefore have
    // contributed; `judged` is the subset that also passed eligibility. So the candidate set is
    // drawn from ALL ops, not from `good` — an ambiguous or partial op that carries a TTFB is
    // precisely the record `excluded` exists to account for, and counting candidates over
    // `good` would silently drop it from both sides and report a perfect 100% coverage.
    fn cold_dns(o: &Operation) -> bool {
        o.dns.as_ref().is_some_and(|d| !d.cache_hit)
    }
    let cgood = |f: fn(&Operation) -> bool| good.iter().filter(|o| f(o)).count();
    let cops = |f: fn(&Operation) -> bool| ops.iter().filter(|o| f(o)).count();
    for (id, judged, candidates) in [
        ("dns_cold", cgood(cold_dns), cops(cold_dns)),
        (
            "tcp_connect",
            cgood(|o| o.tcp_connect_ns.is_some()),
            cops(|o| o.tcp_connect_ns.is_some()),
        ),
        (
            "ttfb_new",
            ttfb_new_samples.len(),
            cops(|o| !o.connection_reused && o.ttfb_ns.is_some()),
        ),
        (
            "ttfb_reused",
            ttfb_reu_samples.len(),
            cops(|o| o.connection_reused && o.ttfb_ns.is_some()),
        ),
    ] {
        if judged > 0 {
            row_pop.push((id, judged, candidates.saturating_sub(judged)));
        }
    }

    // Connection-reuse rate: a first-class, diffable check (a superset, escalates overall
    // but not the parity verdict). Low reuse means paying TCP+TLS setup repeatedly; a
    // reuse COLLAPSE across deploys is exactly the regression the baseline gate catches.
    // Over every NON-PARTIAL op. Errored and ambiguous ops belong here — that is the fix in
    // `is_reuse_rate` — but partial ones do not, and the schema says why on the field itself:
    // "trust it only when `partial == false`; on a partial op the connection facts (and thus
    // whether it was truly reused) couldn't be attributed". `connection_reused` is
    // `req_seq > 0`, and `req_seq` counts from the first request S3TAP saw on that fd, not
    // the socket's first. Attach to a warm keep-alive pool and the first observed op on every
    // socket is `partial` AND reports `connection_reused: false`, so counting those turned a
    // 100%-reuse capture into a ⚠ — the same false warn this row was just fixed to stop
    // producing, mirrored.
    let counted: Vec<_> = ops.iter().filter(|o| !o.partial).collect();
    let reuse = reuse_row(counted.len(), counted.iter().filter(|o| o.connection_reused).count());

    // Connection-level path diagnosis (advisory; the only signal for Go/non-OpenSSL
    // clients). Empty unless the records carry the extended tcp_sock fields.
    let mut path = path_domain(&conns);
    // When NO connection closed (a persistent pool), path_domain is empty — recover the
    // single-stream throughput ceilings from the in-flight sample stream instead (advisory,
    // labelled sampled). Gated on `conns.is_empty()` so the close-time rows stay authoritative
    // whenever a connection did close.
    let (mut sampled_recv_stream_count, mut sampled_send_stream_count) = (0, 0);
    if conns.is_empty() {
        let (sampled_rows, recv_n, send_n) = path_domain_sampled(&samples);
        path.extend(sampled_rows);
        sampled_recv_stream_count = recv_n;
        sampled_send_stream_count = send_n;
    }

    // In-flight time-series (throughput ramp + bufferbloat onset) from the sample stream.
    // Pure FYI; empty unless --sample-interval-ms produced s3tap.sample/1 records.
    let (timeseries, ts_stream_count, ts_down_stream_count, ts_up_stream_count) =
        timeseries_domain(&samples);

    // Deployment-environment estimate (FYI): the round-trip floor + endpoint flags placed on the
    // same-region / cross-region / WAN-or-on-prem spectrum. Never touches the verdict.
    let environment = estimate_environment(rtt_ms, floor_src, &conns);

    Report {
        rows,
        s3,
        tail,
        reuse,
        path,
        timeseries,
        ts_stream_count,
        ts_down_stream_count,
        ts_up_stream_count,
        sampled_recv_stream_count,
        sampled_send_stream_count,
        verdict,
        parse,
        baseline_rtt_us,
        environment,
        op_judged: good.len(),
        op_excluded: ops.len() - good.len(),
        op_nonpartial: ops.iter().filter(|o| !o.partial).count(),
        row_pop,
        mixed_paths: mixed_regions,
        op_statused,
        conn_count: conns.len(),
        floor_judged,
        floor_excluded,
        rtx_stream_count: rtx_streams,
        window,
        evidence,
    }
}

/// Minimum eligible ops to judge connection reuse — below this the ratio is too noisy.
const MIN_REUSE_SAMPLE: usize = 5;
/// Minimum ops in a per-`s3_op` class to claim it HEALTHY — below this a would-be ✓ degrades
/// to Na ("insufficient data"). A ⚠ (a class far above the floor) is surfaced regardless, since
/// even one clear outlier is worth flagging. Lower than
/// [`MIN_REUSE_SAMPLE`] (5): reuse is a RATE over the non-partial op population (needs more samples to
/// stabilize), whereas a class row is a per-op latency median where 3 is the smallest count that
/// isn't a single point masquerading as a verdict.
const MIN_JUDGE_SAMPLE: usize = 3;
/// Healthy connection-reuse floor (`reuse_ratio_min`): below this the
/// client is repaying TCP+TLS setup it could amortize.
const REUSE_RATIO_MIN: f64 = 0.8;

/// The connection-reuse-rate row (a HIGHER-is-better check): fraction of `total` eligible ops on
/// a reused connection. `None` below [`MIN_REUSE_SAMPLE`] (too few ops to judge).
///
/// `total` is the caller's NON-PARTIAL op count, not the whole population: an op whose record
/// was truncated never reliably recorded whether its connection was reused, so counting it in
/// the denominator drags the rate toward 0 and reports "low reuse" for a capture that ended
/// mid-flight. The caller filters; `Report::op_nonpartial` publishes the same number as the
/// finding's `sample.judged`, so the human row and the JSON agree.
fn reuse_row(total: usize, reused: usize) -> Option<Row> {
    if total < MIN_REUSE_SAMPLE {
        return None;
    }
    let ratio = reused as f64 / total as f64;
    let ok = ratio >= REUSE_RATIO_MIN;
    Some(Row {
        id: "reuse_rate",
        label: "connection reuse",
        value: format!("{:>5.0}%", ratio * 100.0),
        mark: if ok { Mark::Ok } else { Mark::Warn },
        verdict: if ok { "good" } else { "low" },
        note: format!(
            "{reused}/{total} ops reused a connection — high reuse avoids repeated TCP+TLS setup"
        ),
        metric: Metric {
            name: "reuse_rate",
            value: Some(ratio),
            unit: Unit::Ratio,
            threshold: ">= 0.8",
            ..Default::default()
        },
    })
}

/// Build the tail-latency rows (p95, and p99 when there are enough samples) for the
/// new/reused TTFB populations. A percentile is skipped below its min sample — the absence
/// claims nothing, the median row still judged.
///
/// Each sample is `(ttfb_ms, floor_ms)`: the op's own round-trip floor, joined the same way
/// [`s3_ttfb_row`] joins it, NOT the pooled capture-wide floor. The pooled floor is right for
/// the global median rows, which are pinned against the reference oracle, and it was wrong
/// here for the reason the per-op ladder exists at all: on a two-region capture the p95 lands
/// on a far-region op while the pooled floor sits on the near region, so a request 1.14× its
/// own floor was reported as `p95 = 80.0×RTT ⚠` and took the run to ATTENTION while the
/// per-op-class row over the same ops said `✓ expected`. Two rows, one capture, contradictory
/// answers, and the blended one won the verdict. Nothing required this row to use the pooled
/// floor: it is a superset with no oracle counterpart (see [`pctl`], "a tail estimate, not a
/// parity check"), so it inherited the parity denominator without being bound by it.
///
/// The row carries TWO order statistics over the same set, taken over different orderings:
/// `value` is the percentile of TTFB (a latency percentile, which is what the label says) and
/// `ratio_to_rtt` is the percentile of `ttfb / its own floor`, which is what the verdict gates
/// on. They generally name different ops, so no single floor relates them, and `baseline_us`
/// is published only when every op in the set shared one floor — see [`uniform_floor`]. An
/// earlier revision reported the ratio-ranked op's own ttfb/floor/quotient so the three agreed
/// by construction; that made `value` mean a ratio-ranked latency when floors existed and a
/// plain percentile when they did not, i.e. one metric id with two meanings.
///
/// A sample whose floor is `None` cannot be judged. That happens when the capture has no floor
/// anywhere, and now also when the pooled rung is WITHDRAWN as a cross-path blend
/// ([`floor_for`]), so the partially-floored shapes below are reachable on ordinary captures
/// rather than only on floorless ones.
fn tail_rows(ttfb_new: &[(f64, Option<f64>)], ttfb_reu: &[(f64, Option<f64>)]) -> (Vec<Row>, Vec<(&'static str, usize, usize)>) {
    // (id, label, percentile, min_sample, rtt_mult, threshold). p99 needs more samples and
    // a higher envelope than p95 (the worst 1% runs hotter than the worst 5%).
    type Spec = (&'static str, &'static str, f64, usize, f64, &'static str);
    /// One TTFB population: each op's `(ttfb_ms, its own floor_ms)`, floor absent only when
    /// the capture has none at all.
    type Pop<'a> = &'a [(f64, Option<f64>)];
    let mut rows = Vec::new();
    let mut pops: Vec<(&'static str, usize, usize)> = Vec::new();
    let populations: [(Pop, [Spec; 2]); 2] = [
        (
            ttfb_new,
            [
                ("ttfb_new_p95", "TTFB p95, new conn", 95.0, MIN_TAIL_SAMPLE, TAIL_RTT_MULT, "<= 8.0×RTT"),
                ("ttfb_new_p99", "TTFB p99, new conn", 99.0, MIN_P99_SAMPLE, P99_RTT_MULT, "<= 12.0×RTT"),
            ],
        ),
        (
            ttfb_reu,
            [
                ("ttfb_reused_p95", "TTFB p95, reused conn", 95.0, MIN_TAIL_SAMPLE, TAIL_RTT_MULT, "<= 8.0×RTT"),
                ("ttfb_reused_p99", "TTFB p99, reused conn", 99.0, MIN_P99_SAMPLE, P99_RTT_MULT, "<= 12.0×RTT"),
            ],
        ),
    ];
    for (samples, specs) in populations {
        for (id, label, p, min_n, mult, threshold) in specs {
            // The sample floor is checked against the WHOLE population, before dropping the
            // unfloorable ones, so "enough samples to estimate a p95" keeps meaning the same
            // thing it did and an all-unfloorable capture still renders its Na row below
            // rather than vanishing.
            if samples.len() < min_n {
                continue;
            }
            let judged: Vec<(f64, f64)> =
                samples.iter().filter_map(|&(t, f)| Some((t, f?))).collect();
            // The gate above admits enough SAMPLES to speak of a p95; this one requires enough
            // FLOORED samples to judge one. Without it a capture where only a handful of ops
            // could be floored reported a confident ✓ over a population of one while
            // publishing `sample.judged` as the whole set — a regression from unjudged to
            // false-healthy, the direction this file treats as unacceptable. `s3_ttfb_row`
            // one function away already gates its MIN_JUDGE_SAMPLE on the floored subset.
            if judged.len() < min_n {
                // Two DIFFERENT reasons land here and the row must say which: no op in this
                // set could be floored at all, or some could and there were too few to judge
                // a percentile over. `na_tail_row` words it from the counts.
                let Some(v) = pctl(samples.iter().map(|&(t, _)| t).collect(), p) else { continue };
                rows.push(na_tail_row(id, label, v, threshold, judged.len(), samples.len()));
                // Judged nothing, so the published population is nothing judged and every
                // sample passed over. Anything else would claim a denominator it never used.
                pops.push((id, 0, samples.len()));
                continue;
            }
            // TWO percentiles over the same set, taken over DIFFERENT orderings, because they
            // answer different questions and one number cannot do both:
            //
            //   `value`        = the p95 of TTFB. A latency percentile, which is what the row
            //                    is labelled and what a dashboard tracking `ttfb_new_p95`
            //                    expects. It means the same thing in the Na branch above, so
            //                    the series does not change definition when a run loses its
            //                    floors.
            //   `ratio_to_rtt` = the p95 of ttfb/floor, and the number the VERDICT gates on.
            //                    Ranking by ratio is the whole point: on a mixed-floor capture
            //                    the slowest op in milliseconds may be the healthiest one
            //                    relative to its own path, and the reverse.
            //
            // Reporting the ratio-ranked op's TTFB as `value` made `value / baseline == ratio`
            // hold exactly, which reads like a guarantee but was an artefact of the ranking —
            // and it silently changed what `value` MEANT whenever floors were present. The
            // identity is gone; both numbers are now honest, and the note prints both.
            let Some(ttfb_ms) = pctl(judged.iter().map(|&(t, _)| t).collect(), p) else { continue };
            let Some(ratio) = pctl(judged.iter().map(|&(t, f)| t / f).collect(), p) else { continue };
            // A ✓ is only honest if the DROPPED ops could not have occupied the tail. With
            // `n` samples and `j` floored, the unfloorable share is `(n-j)/n`; above the tail
            // fraction `1 - p/100` those ops could fill the whole band the percentile reports,
            // so the row cannot say the tail is fine. 20 fast joined ops plus 5 slow
            // unfloorable ones read "p95 2.0 ms ✓ expected" while dropping a real 900 ms tail
            // — the hazard the population comment two blocks down already names, applied to
            // the VERDICT rather than only to the published counts.
            //
            // One-sided: a ⚠ still stands. Warning on a tail computed from a subset is the
            // safe direction; a ✓ is not.
            let dropped_frac = (samples.len() - judged.len()) as f64 / samples.len() as f64;
            let tail_frac = 1.0 - p / 100.0;
            let uniform = uniform_floor(judged.iter().map(|&(_, f)| f * 1e3));
            let good = ratio <= mult;
            if good && dropped_frac > tail_frac {
                let Some(v) = pctl(samples.iter().map(|&(t, _)| t).collect(), p) else { continue };
                rows.push(na_tail_row(id, label, v, threshold, judged.len(), samples.len()));
                pops.push((id, judged.len(), samples.len() - judged.len()));
                continue;
            }
            rows.push(Row {
                id,
                label,
                value: format!("{ttfb_ms:>5.1} ms"),
                mark: if good { Mark::Ok } else { Mark::Warn },
                verdict: if good { "expected" } else { "high" },
                note: format!(
                    "p{p:.0} of ×RTT = {ratio:.1}× — the judged number, ranked over ratios, so \
                     it names a different op than the {p:.0}th-percentile latency beside it; \
                     each op is measured against its own floor. The median is the headline"
                ),
                metric: Metric {
                    name: id,
                    value: Some(ttfb_ms),
                    unit: Unit::Ms,
                    rtt_relative: true,
                    ratio_to_rtt: Some(ratio),
                    threshold,
                    // A denominator ONLY when every op in this set shared one floor. There,
                    // the ratio order and the ttfb order coincide, so `value / baseline`
                    // reproduces `ratio_to_rtt` exactly — the relation a consumer assumes and
                    // this file's own tests call a contract. Otherwise the two are order
                    // statistics over DIFFERENT orderings and no single floor relates them:
                    // publishing the median let a consumer compute a number contradicting the
                    // published ratio by up to 200x in both directions across the threshold (a
                    // ⚠ row recomputing as 2.97x under a <= 8.0x gate, a ✓ row as 400x), and
                    // on a multi-path capture that median WAS the pooled blend this report had
                    // just refused to hand out.
                    baseline_us: uniform,
                    per_op_baseline: uniform.is_none(),
                },
            });
            // The FLOORED subset, which is what the percentile was taken over. Falling
            // through to the report-wide op counts published the whole population beside a
            // percentile computed from part of it — and where the unfloorable ops were the
            // slow ones, a confident ✓ that had silently dropped the actual tail.
            pops.push((id, judged.len(), samples.len() - judged.len()));
        }
    }
    (rows, pops)
}

/// The tail row when the percentile cannot be judged: the percentile is shown, no ratio is
/// claimed. Same shape [`ratio_row`] produced for `rtt_ms: None`.
///
/// `floored` / `total` decide the WORDING, because two different failures reach here and a
/// single hardcoded reason was true for only one of them. ("round-trip", not "srtt": the
/// floor falls back to `min_rtt`, and the capture shape this wording was written for — five
/// connections carrying only a `min_rtt` — is exactly one where saying srtt sends the operator
/// hunting a probe failure twice over.) `floored == 0` really is
/// "no baseline anywhere in this set". `0 < floored < min_n` is the opposite situation — some
/// ops WERE floored, just too few to take a percentile over — and telling that operator their
/// capture has no srtt sends them looking for a probe failure that isn't there.
fn na_tail_row(
    id: &'static str,
    label: &'static str,
    ms: f64,
    threshold: &'static str,
    floored: usize,
    total: usize,
) -> Row {
    Row {
        id,
        label,
        value: format!("{ms:>5.1} ms"),
        mark: Mark::Na,
        verdict: "n/a",
        note: if floored == 0 {
            "no round-trip baseline — not judged".into()
        } else {
            format!("only {floored}/{total} ops had a round-trip baseline — too few to judge")
        },
        metric: Metric {
            name: id,
            value: Some(ms),
            unit: Unit::Ms,
            rtt_relative: true,
            ratio_to_rtt: None,
            threshold,
            baseline_us: None,
            per_op_baseline: false,
        },
    }
}

/// The single floor shared by every op in `floors`, or `None` when they differ.
///
/// A published `baseline_rtt_us` is only honest when `value / baseline == ratio_to_rtt`, and
/// for both the per-class rows and the tails those three numbers are SEPARATE aggregations
/// (a median or percentile of TTFBs, of ratios, and of floors). They coincide exactly when the
/// floors are uniform and diverge otherwise — which is the case per-op floors exist for. So the
/// denominator is published when it means something and withheld when it does not, rather than
/// always (a number that reconstructs a wrong answer) or never (losing it on the common
/// single-path capture).
///
/// Exact equality, not a tolerance: these come from the same `u32` µs fields via one
/// conversion, so ops on one path give bit-identical f64s, and anything else is a different
/// path however close.
fn uniform_floor(mut floors: impl Iterator<Item = f64>) -> Option<f64> {
    let first = floors.next()?;
    floors.all(|f| f == first).then_some(first)
}

/// A per-`s3_op` TTFB row marked Na (not judged) — the shared shape for both "no floor for any
/// op" and "too few ops to judge healthy". Carries no ratio/baseline so an Unjudged finding
/// never looks judged to a `--json` consumer, whichever way the row went unjudged.
fn s3_na_ttfb_row(class: &str, median_ttfb_ms: f64, note: String) -> S3Row {
    S3Row {
        id: "s3_ttfb",
        label: format!("{class} TTFB"),
        value: format!("{median_ttfb_ms:>5.1} ms"),
        mark: Mark::Na,
        verdict: "n/a",
        note,
        s3_op: Some(class.to_string()),
        metric: Metric {
            name: "s3_ttfb",
            value: Some(median_ttfb_ms),
            unit: Unit::Ms,
            rtt_relative: true,
            ratio_to_rtt: None,
            threshold: "<= 4.0×RTT",
            baseline_us: None,
            per_op_baseline: false,
        },
        population: None,
    }
}

/// The per-`s3_op` TTFB think-time row for one op-class. Each op is judged against ITS OWN
/// floor (joined via `sock_cookie` → its region → the global fallback), never a cross-region
/// blend, then the per-op ratios/think-times are medianed — so a class spanning two regions
/// can't hide a slow op behind a far one. When the floor is uniform (the common single-region
/// case) this equals the old median-ttfb / floor exactly. Returns `None` when the class has no
/// TTFB at all (skip it). The row is:
///   - Na "no RTT baseline"    when no op could be floored;
///   - Na "insufficient data"  when it would be ✓ but has < [`MIN_JUDGE_SAMPLE`] ops (never a
///     false ✓; a ⚠ is NOT gated — one op far above the floor is a real outlier worth surfacing);
///   - ✓/⚠                     on the median ratio vs [`TTFB_RTT_MULT`].
fn s3_ttfb_row(
    class: &str,
    class_ops: &[&Operation],
    floor_for_op: impl Fn(&Operation) -> Option<f64>,
) -> Option<S3Row> {
    // (ttfb_ms, floor_ms) for the ops that carry both a ttfb and a floor.
    let judged: Vec<(f64, f64)> = class_ops
        .iter()
        .filter_map(|o| {
            let ttfb = o.ttfb_ns? as f64 / 1e6;
            let floor = floor_for_op(o)? / 1e3; // µs → ms
            Some((ttfb, floor))
        })
        .collect();

    // Display the median ttfb over the judged ops (or all class ops when none judged, so a
    // no-baseline row still shows the timing). No ttfb anywhere → skip the class.
    let shown: Vec<f64> = if judged.is_empty() {
        class_ops.iter().filter_map(|o| o.ttfb_ns).map(|n| n as f64 / 1e6).collect()
    } else {
        judged.iter().map(|(t, _)| *t).collect()
    };
    let median_ttfb_ms = median(shown)?;

    if judged.is_empty() {
        return Some(s3_na_ttfb_row(class, median_ttfb_ms, "no RTT baseline — not judged".into()));
    }

    // `expect` is safe here (judged is non-empty) and a loud panic beats a silent 0.0 →
    // false-healthy default. `floor_us` is the median of the per-op floors actually used, so the
    // finding's baseline_rtt_us matches the denominator this ratio was taken against.
    let med = |xs: Vec<f64>| median(xs).expect("judged is non-empty");
    let ratio = med(judged.iter().map(|(t, f)| t / f).collect());
    let think = med(judged.iter().map(|(t, f)| (t - f).max(0.0)).collect());
    // See `uniform_floor`: only a class whose ops all sat on one floor has a denominator that
    // relates `value` to `ratio`. A mixed class published the MEDIAN floor, so a consumer
    // dividing got ~2x away from the ratio the verdict was made on (issue #24) — and after the
    // tail rows stopped publishing a denominator at all, the two halves of the same report
    // disagreed about whether one existed.
    let floor_us = uniform_floor(judged.iter().map(|(_, f)| f * 1e3));
    let ok = ratio <= TTFB_RTT_MULT;

    if ok && judged.len() < MIN_JUDGE_SAMPLE {
        return Some(s3_na_ttfb_row(
            class,
            median_ttfb_ms,
            format!("insufficient data (n<{MIN_JUDGE_SAMPLE}) — not judged"),
        ));
    }

    Some(S3Row {
        id: "s3_ttfb",
        label: format!("{class} TTFB"),
        value: format!("{median_ttfb_ms:>5.1} ms"),
        mark: if ok { Mark::Ok } else { Mark::Warn },
        verdict: if ok { "expected" } else { "high" },
        note: format!("think-time ≈ {think:.1} ms ({ratio:.1}×RTT) — S3 server work, not the network"),
        s3_op: Some(class.to_string()),
        metric: Metric {
            name: "s3_ttfb",
            value: Some(median_ttfb_ms),
            unit: Unit::Ms,
            rtt_relative: true,
            ratio_to_rtt: Some(ratio),
            threshold: "<= 4.0×RTT",
            baseline_us: floor_us,
            // A mixed-floor class has no single denominator, so it must not inherit the pooled
            // one either — the same rule the tail rows follow.
            per_op_baseline: floor_us.is_none(),
        },
        population: None,
    })
}

/// The S3 health domain, segmented per `s3_op` — the part of the
/// doctor that surpasses the flat s3stats.py oracle. Three check kinds:
///   1. per-op-class TTFB (the "money metric": think-time = ttfb − rtt = S3 server
///      work, separating a far server from a slow one);
///   2. status mix — 503 throttling vs other 5xx vs 4xx, each with S3-specific advice;
///   3. GET throughput (advisory) — content_length / download_ns.
fn s3_domain(
    ops: &[&Operation],
    conn_by_cookie: &ConnByCookie,
    region_floor: &RegionFloor,
    global_us: Option<f64>,
    // Passed in rather than recomputed: it is a capture-wide fact and the caller already has
    // it. Recomputing it here put a third call site of the predicate inside a per-op-class
    // loop, which is both wasted work and the drift risk the single definition exists to stop.
    mixed: bool,
) -> (Vec<S3Row>, Vec<(String, Evidence)>) {
    let mut rows = Vec::new();
    let mut evidence: Vec<(String, Evidence)> = Vec::new();
    // Same TIMING gate as the global rows (`is_timeable` = eligible + a real response) —
    // kept in one place so the two latency populations can't drift. The status-mix rows
    // below deliberately count over `ops` instead: they judge reliability, not timing.
    let good: Vec<&Operation> = ops.iter().copied().filter(|o| is_timeable(o)).collect();

    // 1) Per-s3_op TTFB think-time. Group good ops by the SANITIZED op-class (one row per
    // class, sorted). `s3_op` is attacker-influenceable on an untrusted JSONL stream and
    // reaches a tty, so it's cleaned (CWE-117 / Trojan Source) BEFORE grouping — so two
    // raw classes that differ only in unsafe chars merge into one row instead of colliding
    // under the same label in the evidence map (which is keyed by label).
    let mut by_class: std::collections::BTreeMap<String, Vec<&Operation>> =
        std::collections::BTreeMap::new();
    for o in &good {
        if let Some(raw) = o.s3_op.as_deref() {
            by_class.entry(s3tap_schema::sanitize_term(raw)).or_default().push(o);
        }
    }
    for (class, class_ops) in by_class {
        let floor_for_op = |o: &Operation| floor_for(o, conn_by_cookie, region_floor, global_us, mixed);
        if let Some(mut row) = s3_ttfb_row(&class, &class_ops, floor_for_op) {
            // THIS class, not the capture. `s3_ttfb` is one finding id shared by every class,
            // so `Report::row_pop` (keyed by id) cannot hold it: a capture of 5 GetObject and
            // 95 PutObject published `judged: 100` on BOTH rows, which cannot be true of
            // either, and one of them was a ⚠ drawn from 5 ops.
            let judged = class_ops
                .iter()
                .filter(|o| o.ttfb_ns.is_some() && floor_for_op(o).is_some())
                .count();
            // Candidates are THIS class's ops — an op of another class was never a candidate —
            // counted over ALL ops rather than `good`, so an errored or ambiguous op of this
            // class shows up as a DROPPED candidate rather than vanishing from both sides.
            // Same convention as the tails and the four global rows.
            let candidates = ops
                .iter()
                .filter(|o| {
                    o.ttfb_ns.is_some()
                        && o.s3_op.as_deref().is_some_and(|raw| {
                            s3tap_schema::sanitize_term(raw) == class
                        })
                })
                .count();
            row.population = Some((judged, candidates.saturating_sub(judged)));
            evidence.push((row.label.clone(), evidence_of(class_ops.iter().copied())));
            rows.push(row);
        }
    }

    // 2) Status mix — the S3-specific breakdown (a 503 is a different verdict than a 4xx
    //    client bug). Only emit a row for a category that actually occurred. NB a 503 is
    //    SlowDown (throttling) OR ServiceUnavailable (a transient blip); only the parsed
    // s3_error_code distinguishes them and the record doesn't carry it
    // yet, so the note hedges rather than asserting SlowDown.
    let by_status = |pred: fn(u16) -> bool| -> Vec<&Operation> {
        ops.iter().copied().filter(|o| o.http_status.is_some_and(pred)).collect()
    };
    // Shared classifier (see [`classify_status`]) so a 429/503 is throttle here AND in the
    // scorecard — the two tools can't disagree on what a status means.
    let throttle_ops = by_status(|s| classify_status(s) == StatusClass::Throttle);
    let server_ops = by_status(|s| classify_status(s) == StatusClass::ServerError);
    let client_ops = by_status(|s| {
        matches!(
            classify_status(s),
            StatusClass::Forbidden | StatusClass::NotFound | StatusClass::BadRequest | StatusClass::ClientError
        )
    });
    if !throttle_ops.is_empty() {
        evidence.push(("throttling (429/503)".to_string(), evidence_of(throttle_ops.iter().copied())));
        rows.push(S3Row {
            id: "s3_throttle",
            label: "throttling (429/503)".into(),
            value: format!("{:>4}", throttle_ops.len()),
            mark: Mark::Warn,
            verdict: "throttle",
            note: "429/503 — throttling (back off + spread keys across prefixes); a 503 may \
                   instead be a transient ServiceUnavailable, s3_error_code not yet \
                   emitted to disambiguate".into(),
            s3_op: None,
            metric: Metric { name: "s3_status_throttle", value: Some(throttle_ops.len() as f64),
                unit: Unit::Count, threshold: "== 0", ..Default::default() },
            population: None,
        });
    }
    if !server_ops.is_empty() {
        evidence.push(("server errors (5xx)".to_string(), evidence_of(server_ops.iter().copied())));
        rows.push(S3Row {
            id: "s3_server_errors",
            label: "server errors (5xx)".into(),
            value: format!("{:>4}", server_ops.len()),
            mark: Mark::Warn,
            verdict: "retryable",
            note: "500/502/504 — retryable S3-side blips; check your retry policy".into(),
            s3_op: None,
            metric: Metric { name: "s3_status_server", value: Some(server_ops.len() as f64),
                unit: Unit::Count, threshold: "== 0", ..Default::default() },
            population: None,
        });
    }
    if !client_ops.is_empty() {
        evidence.push(("client errors (4xx)".to_string(), evidence_of(client_ops.iter().copied())));
        rows.push(S3Row {
            id: "s3_client_errors",
            label: "client errors (4xx)".into(),
            value: format!("{:>4}", client_ops.len()),
            mark: Mark::Warn,
            verdict: "client",
            note: "4xx — a client/permission/signing bug, not the network".into(),
            s3_op: None,
            metric: Metric { name: "s3_status_client", value: Some(client_ops.len() as f64),
                unit: Unit::Count, threshold: "== 0", ..Default::default() },
            population: None,
        });
    }

    // 3) GET throughput (advisory; never escalates) — body size / download span.
    let get_ops = ops
        .iter()
        .filter(|o| {
            o.s3_op.as_deref() == Some("GetObject")
                && o.content_length.is_some()
                && o.download_ns.is_some_and(|d| d > 0)
        })
        .count();
    let tputs: Vec<f64> = good
        .iter()
        .filter(|o| o.s3_op.as_deref() == Some("GetObject"))
        .filter_map(|o| Some((o.content_length?, o.download_ns?)))
        // `download_ns == 0` is REAL, not hypothetical: the correlator emits it whenever the
        // body is coalesced into the head read (every small object). Dividing by it yields
        // +Inf, which then reaches the finding's finite-only serializer as a hard error.
        // Drop the sample instead: a zero-length span carries no rate to report.
        .filter(|&(_, dl)| dl > 0)
        .map(|(cl, dl)| cl as f64 / dl as f64 * 1e3) // bytes/ns -> MB/s
        .collect();
    let tput_n = tputs.len();
    if let Some(mbps) = median(tputs) {
        rows.push(S3Row {
            id: "s3_throughput",
            label: "GetObject throughput".into(),
            value: format!("{mbps:>5.1} MB/s"),
            mark: Mark::Advisory,
            verdict: "fyi",
            note: "single-stream GET; the BDP ceiling (window/RTT) needs the TCP window (not in the \
                   record) — parallelize for more".into(),
            s3_op: Some("GetObject".into()),
            metric: Metric { name: "s3_get_throughput", value: Some(mbps * 1e6), // MB/s -> bytes/s
                unit: Unit::BytesPerS, ..Default::default() },
            // Candidates are the GETs that carried both a length and a span, over ALL ops.
            population: Some((tput_n, get_ops.saturating_sub(tput_n))),
        });
    }
    (rows, evidence)
}

// ----------------------------------------------------------------------------
// In-flight time-series analysis (Plan 2): turn the s3tap.sample/1 stream into a
// "what happened, and when" — throughput ramp + bufferbloat onset. Pure FYI; the
// series machinery (group/segment/sort/direction) is shared with future analyses.
// ----------------------------------------------------------------------------

/// Below this many usable intervals, the localization (time-to-peak / the steady-bursty-
/// still-ramping shape) is suppressed — the scalar rate is still reported.
const MIN_TS_INTERVALS: usize = 6;
/// Steady: sustained rate ≥ this fraction of the burst peak (else "bursty").
const TS_HELD_FRACTION: f64 = 0.8;
/// "Still ramping": the last time-third's mean rate must exceed the middle third's by at
/// least this factor (a real continued climb, not a plateau's noise uptick).
const TS_RAMP_MARGIN: f64 = 1.2;
/// srtt/floor thresholds for the bufferbloat label. `HI` matches `path_domain`'s
/// `>= 2.0×` "inflated under load" flag so the two sections can't contradict each other
/// on the same ratio (review finding C); the 1.2–2.0× band is informational "mild".
const TS_BLOAT_HI: f64 = 2.0;
const TS_BLOAT_LO: f64 = 1.2;

/// Direction of a sample segment, by its final cumulative totals (the close-path
/// `send_heavy`/`recv_heavy` predicate + the 65 KiB floor, re-expressed on a sample).
enum SegDir {
    Up,
    Down,
}
fn seg_direction(seg: &[&TcpSample]) -> Option<SegDir> {
    let last = seg.last()?;
    if last.bytes_sent > last.bytes_recv && last.bytes_sent >= MIN_DIRECTIONAL_BYTES {
        Some(SegDir::Up)
    } else if last.bytes_recv > last.bytes_sent && last.bytes_recv >= MIN_DIRECTIONAL_BYTES {
        Some(SegDir::Down)
    } else {
        None // tiny / balanced — don't default a small GET/HEAD to a throughput row
    }
}

/// Send-side loss from the in-flight sample stream, for the persistent-pool case where NO
/// connection closed (so the close-time `bytes_sent` denominator is 0). Groups by cookie,
/// splits on the reuse boundary (a byte-counter reset — see [`ts_segments`]), and sums each
/// segment's cumulative deltas: `bytes_sent` and `total_retrans` (both monotonic WITHIN a
/// segment). Returns `(sent_bytes, retransmits, streams)` over the capture window — the same
/// window for all three, so the ratio is a valid rate even though the absolute counters predate
/// the capture on a long-lived socket. `streams` is the count of distinct sample streams that
/// moved send-side bytes OR contributed a retransmit: the POPULATION this rate was taken over,
/// published as the finding's `sample.judged` (the connection count is 0 here by construction
/// no connection closed, and the same per-direction stream counting `path_domain_sampled` does).
/// A stream whose retransmits land on a segment with no byte-counter advance (a stalled sender
/// re-sending already-sent data) still counts: it fed the numerator, so it belongs in the
/// denominator too.
/// `(0, 0, 0)` when there are no samples.
fn sample_send_deltas(samples: &[&TcpSample]) -> (u64, u64, usize) {
    let mut by: std::collections::BTreeMap<u64, Vec<&TcpSample>> = std::collections::BTreeMap::new();
    for s in samples {
        by.entry(s.sock_cookie).or_default().push(s);
    }
    let (mut sent, mut retrans) = (0u64, 0u64);
    let mut streams: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for (cookie, mut series) in by {
        series.sort_by_key(|s| s.ts_ns.unwrap_or(0));
        for seg in ts_segments(&series) {
            if let (Some(first), Some(last)) = (seg.first(), seg.last()) {
                let d = last.bytes_sent.saturating_sub(first.bytes_sent);
                let rt = last.total_retrans.saturating_sub(first.total_retrans);
                // A stream that contributed retransmits to the numerator is part of the
                // population this rate is over even on a segment where `bytes_sent` didn't
                // advance (a stalled sender retransmitting already-sent data, or keep-alive
                // probing) — otherwise its retransmits count but it never shows up as judged.
                if d > 0 || rt > 0 {
                    streams.insert(cookie);
                }
                sent = sent.saturating_add(d);
                retrans = retrans.saturating_add(u64::from(rt));
            }
        }
    }
    (sent, retrans, streams.len())
}

/// Split a cookie's TIME-SORTED series wherever a strictly-monotonic byte counter
/// decreases — a reused sk-pointer restarts `bytes_*` at 0, so a decrease is an exact
/// reuse boundary. NOT cwnd/in-flight (those drop mid-lifetime — round-3 blocker).
fn ts_segments<'a>(series: &'a [&'a TcpSample]) -> Vec<&'a [&'a TcpSample]> {
    let mut segs = Vec::new();
    let mut start = 0;
    for i in 1..series.len() {
        if series[i].bytes_recv < series[i - 1].bytes_recv
            || series[i].bytes_sent < series[i - 1].bytes_sent
        {
            segs.push(&series[start..i]);
            start = i;
        }
    }
    if start < series.len() {
        segs.push(&series[start..]);
    }
    segs
}

/// Format a throughput in adaptive units: MB/s at ≥1 MB/s, else KB/s — so a
/// small-object workload (16 KiB GETs that finish within a sample interval) reads
/// "160 KB/s", not a useless "0 MB/s".
fn fmt_rate_mbps(mbps: f64) -> String {
    if mbps >= 1.0 {
        format!("{mbps:.0} MB/s")
    } else {
        format!("{:.0} KB/s", mbps * 1000.0)
    }
}

/// Abbreviate a count for display (139221 -> "139k") — the exact value stays in the
/// machine metric. Keeps the value column terse and avoids a false-precision read.
fn fmt_count(n: f64) -> String {
    if n >= 1e6 {
        format!("{:.1}M", n / 1e6)
    } else if n >= 1e4 {
        format!("{:.0}k", n / 1e3)
    } else {
        format!("{n:.0}")
    }
}

/// Robust peak: max of a 3-point moving average (a lone catch-up interval can't define
/// the peak). Falls back to the plain max below 3 points.
fn robust_peak(rates: &[f64]) -> Option<f64> {
    if rates.is_empty() {
        return None;
    }
    if rates.len() < 3 {
        return Some(rates.iter().copied().fold(f64::MIN, f64::max));
    }
    let mut best = f64::MIN;
    for w in rates.windows(3) {
        best = best.max((w[0] + w[1] + w[2]) / 3.0);
    }
    Some(best)
}

enum ThruShape {
    Steady,       // sustained held near the (burst) peak
    Bursty,       // peak well above the sustained rate (token-bucket burst, or fell off)
    StillRamping, // the active window's last third is still climbing (slow-start unfinished)
}
struct SegThru {
    sustained_bps: f64, // the HEADLINE: median of ACTIVE (non-idle) interval rates
    peak_bps: f64,      // burst peak (note only — a single-burst max overstates throughput)
    shape: Option<ThruShape>, // None ⇒ too short to localize
    t90_pct: Option<f64>,
    app_limited: bool,
    is_download: bool, // direction (for the loss-timeline: download=reorder, upload=retrans)
    /// Loss/reorder counts per active-window time-third (early/mid/late): download =
    /// Δrcv_ooopack, upload = Δtotal_retrans. `None` when too short to localize.
    loss_thirds: Option<[f64; 3]>,
}
/// An interval below this fraction of the peak is treated as IDLE (keep-alive gap /
/// transfer finished) and excluded from the sustained rate + the shape classification —
/// so a healthy completed transfer that then idles isn't mislabeled (review finding B).
const TS_IDLE_FRAC: f64 = 0.05;

/// Throughput for one segment — DIRECTION-AWARE (there is no kernel receive-side
/// delivery rate): uploads use the EWMA `delivery_rate_bps`; downloads use a self-
/// smoothed Δbytes_recv/Δt. `None` when the segment isn't directional or has no usable
/// rate series (degrade honestly).
fn throughput_of_segment(seg: &[&TcpSample]) -> Option<SegThru> {
    let dir = seg_direction(seg)?;
    let t0 = seg.first()?.ts_ns? as f64;
    let span = (seg.last()?.ts_ns? as f64 - t0).max(0.0);
    // (t_rel, bytes/s) points.
    let mut rates: Vec<(f64, f64)> = Vec::new();
    match dir {
        SegDir::Down => {
            for w in seg.windows(2) {
                let (a, b) = (w[0].ts_ns?, w[1].ts_ns?);
                let dt = b.saturating_sub(a) as f64;
                if dt > 0.0 {
                    let dbytes = w[1].bytes_recv.saturating_sub(w[0].bytes_recv) as f64;
                    // Sum in f64 — a u64 `a + b` overflows on crafted ts_ns near u64::MAX
                    // (the untrusted-JSONL no-crash mandate); the midpoint only buckets time.
                    rates.push(((a as f64 + b as f64) / 2.0 - t0, dbytes / (dt / 1e9)));
                }
            }
        }
        SegDir::Up => {
            for s in seg {
                if let Some(d) = s.delivery_rate_bps {
                    rates.push((s.ts_ns? as f64 - t0, d as f64));
                }
            }
        }
    }
    let peak = robust_peak(&rates.iter().map(|(_, r)| *r).collect::<Vec<_>>())?;
    // SUSTAINED = median of ACTIVE (non-idle) intervals — the throughput an operator
    // actually wants, vs the burst `peak` a token bucket inflates 2–4× (review finding A).
    // Excluding idle (keep-alive gap / finished transfer) also stops a healthy transfer
    // reading as "decayed" (finding B).
    let active: Vec<f64> =
        rates.iter().map(|(_, r)| *r).filter(|&r| r >= TS_IDLE_FRAC * peak).collect();
    let sustained = median(active).unwrap_or(peak);
    // app-limited is a SEND-path flag — meaningful only for an UPLOAD plateau. On a
    // download the trivial request-send is app-limited and says nothing about the
    // transfer, so never surface it on a recv-heavy row (caught on real GET data).
    let app_limited = matches!(dir, SegDir::Up)
        && span > 0.0
        && seg.iter().any(|s| {
            s.rate_app_limited && (s.ts_ns.unwrap_or(0) as f64 - t0) >= 2.0 / 3.0 * span
        });
    // Active transfer WINDOW: first..last non-idle interval. t90 and the shape thirds are
    // measured over THIS window, not the full span — leading/trailing keep-alive idle
    // would otherwise push "% in" and the still-ramping thirds (the idle->active boundary
    // landing inside the middle third) into misleading territory (review round-4: a ~40%
    // idle prefix made "reached 90% by ~51%" and 2/3 "still ramping" wrong). Same idle
    // exclusion the sustained rate already uses, now applied to the timing.
    let idle = TS_IDLE_FRAC * peak;
    let aw_start = rates.iter().find(|(_, r)| *r >= idle).map(|(t, _)| *t);
    let aw_end = rates.iter().rev().find(|(_, r)| *r >= idle).map(|(t, _)| *t);
    let (shape, t90_pct, loss_thirds) = match (aw_start, aw_end) {
        (Some(s), Some(e)) if rates.len() >= MIN_TS_INTERVALS && (e - s) > 0.0 && peak > 0.0 => {
            let aw = e - s;
            // rate points within the active window (incl. mid-transfer dips — real variance).
            let win: Vec<(f64, f64)> = rates.iter().copied().filter(|(t, _)| *t >= s && *t <= e).collect();
            let t90 = win.iter().find(|(_, r)| *r >= 0.9 * peak).map(|(t, _)| (t - s) / aw * 100.0);
            // Loss/reorder per active-window third (the "when": download=Δrcv_ooopack,
            // upload=Δtotal_retrans) — bucket each interval's Δ by its midpoint's third.
            let mut loss = [0.0f64; 3];
            for w in seg.windows(2) {
                if let (Some(ta), Some(tb)) = (w[0].ts_ns, w[1].ts_ns) {
                    let mid = (ta as f64 + tb as f64) / 2.0 - t0;
                    if mid >= s && mid <= e {
                        let d = match dir {
                            SegDir::Down => w[1].rcv_ooopack.saturating_sub(w[0].rcv_ooopack),
                            SegDir::Up => w[1].total_retrans.saturating_sub(w[0].total_retrans),
                        } as f64;
                        let rel = (mid - s) / aw;
                        let idx = if rel < 1.0 / 3.0 { 0 } else if rel < 2.0 / 3.0 { 1 } else { 2 };
                        loss[idx] += d;
                    }
                }
            }
            // Mean rate per time-third OF THE ACTIVE WINDOW.
            let third = |lo: f64, hi: f64| -> Option<f64> {
                let xs: Vec<f64> =
                    win.iter().filter(|(t, _)| (*t - s) >= lo && (*t - s) <= hi).map(|(_, r)| *r).collect();
                (!xs.is_empty()).then(|| xs.iter().sum::<f64>() / xs.len() as f64)
            };
            let (m, l) = (third(aw / 3.0, 2.0 * aw / 3.0), third(2.0 * aw / 3.0, aw));
            // "Still ramping" = the LAST third still climbing MEANINGFULLY over the middle
            // (> TS_RAMP_MARGIN). A flat 12->13 plateau uptick must NOT count (review #5);
            // a genuine cut-off slow-start (5->12->25) does. Positive middle guards an
            // idle-then-active restart.
            let rising = matches!((m, l), (Some(m), Some(l)) if m > 0.0 && l > TS_RAMP_MARGIN * m);
            // honest: a token-bucket settle or a fall-off read "bursty" (peak >> sustained);
            // a flat-at-cap transfer reads "steady"; only a genuinely-climbing tail is ramping.
            let shape = if rising {
                ThruShape::StillRamping
            } else if sustained >= TS_HELD_FRACTION * peak {
                ThruShape::Steady
            } else {
                ThruShape::Bursty
            };
            (Some(shape), t90, Some(loss))
        }
        _ => (None, None, None), // too short / no active window → scalar rate only
    };
    Some(SegThru {
        sustained_bps: sustained,
        peak_bps: peak,
        shape,
        t90_pct,
        app_limited,
        is_download: matches!(dir, SegDir::Down),
        loss_thirds,
    })
}

/// Bufferbloat for one segment: max per-sample `srtt/floor` and the time-third where it
/// first crossed the inflation flag. Floor = segment-wide min `min_rtt` (sentinels
/// filtered). `None` when no usable floor or no srtt sample.
fn bufferbloat_of_segment(seg: &[&TcpSample]) -> Option<(f64, &'static str)> {
    let floor = seg
        .iter()
        .filter_map(|s| s.min_rtt_us.filter(|&v| v != 0 && v < MAX_PLAUSIBLE_RTT_US))
        .min()? as f64;
    if floor <= 0.0 {
        return None;
    }
    let t0 = seg.first()?.ts_ns? as f64;
    let span = (seg.last()?.ts_ns? as f64 - t0).max(1.0);
    let mut max_ratio = f64::MIN;
    let mut onset = "";
    for s in seg {
        // srtt 0 is "no sample" (a crafted literal 0; the producer maps it to None) — skip
        // it so it can't render a bogus 0.0x row. Also reject implausible (corrupt/crafted)
        // srtt >= MAX_PLAUSIBLE_RTT_US, matching every other floor path, so one bad sample
        // can't dominate `max_ratio` and print/emit an absurd inflation ratio.
        if let Some(srtt) = s.srtt_us.filter(|&v| v != 0 && v < MAX_PLAUSIBLE_RTT_US) {
            let ratio = srtt as f64 / floor;
            max_ratio = max_ratio.max(ratio);
            if onset.is_empty() && ratio >= TS_BLOAT_HI {
                let rel = (s.ts_ns.unwrap_or(0) as f64 - t0) / span;
                onset = if rel < 1.0 / 3.0 { "early" } else if rel < 2.0 / 3.0 { "mid" } else { "late" };
            }
        }
    }
    (max_ratio > f64::MIN).then_some((max_ratio, onset))
}

/// Wall-clock bucket for the cross-stream aggregate (sum concurrent streams per 1s).
const TS_AGG_BUCKET_NS: f64 = 1_000_000_000.0;
/// A bucket must cover at least this fraction of its own second before its rate is trusted.
/// The sliver at either end of a transfer (an interval whose midpoint lands in a bucket it
/// barely occupies) is a partial measurement, not a slow/fast second, and it must not be
/// allowed to define the peak or drag the median. Not a health threshold: a data-sufficiency
/// gate on the denominator.
const TS_AGG_MIN_COVER: f64 = 0.25;

/// One 1-second wall-clock bucket of the cross-stream aggregate: the bytes every stream moved
/// inside this second, which cookies contributed (concurrency), and the wall clock those
/// contributions actually SPAN. The span is the rate's denominator, and every contribution is
/// clamped to the bucket's own second by [`add_interval`], so it can never exceed 1 s.
#[derive(Debug, Default, Clone)]
struct AggBucket {
    bytes: f64,
    cookies: std::collections::HashSet<u64>,
    /// Earliest start / latest end (ns) contributed to this bucket, both already clamped into
    /// the bucket. The SPAN (not the sum of the contributions) is right for an aggregate:
    /// concurrent streams covering the same second must divide by that one second, never by two
    /// stream-seconds.
    t0: u64,
    t1: u64,
}

impl AggBucket {
    /// Wall clock this bucket's contributions cover, in seconds (0 if it holds nothing); at most
    /// [`TS_AGG_BUCKET_NS`] since every contribution is clamped to the bucket.
    fn covered_s(&self) -> f64 {
        (self.t1.saturating_sub(self.t0)) as f64 / 1e9
    }

    fn add(&mut self, cookie: u64, bytes: f64, ta: u64, tb: u64) {
        if self.cookies.is_empty() {
            self.t0 = ta;
            self.t1 = tb;
        } else {
            self.t0 = self.t0.min(ta);
            self.t1 = self.t1.max(tb);
        }
        self.bytes += bytes;
        self.cookies.insert(cookie);
    }
}

type AggBuckets = std::collections::BTreeMap<i64, AggBucket>;

/// Most 1s buckets one sample interval may be spread over. An interval wider than ~68 minutes
/// is a crafted or corrupt timestamp gap carrying no throughput information, and walking a
/// bucket per second of it is how untrusted JSONL turns into an unbounded loop. Dropped.
const TS_AGG_MAX_SPAN_BUCKETS: i64 = 4096;

/// Spread one sample interval's bytes across EVERY 1s wall-clock bucket it overlaps, in
/// proportion to the overlap, clamping the wall clock it contributes to each bucket's own second.
///
/// The interval used to be assigned whole to its MIDPOINT's bucket, with the bucket's rate taken
/// over the full extent of the intervals that landed there. That made the denominator exceed one
/// second whenever concurrent streams were sampled OUT OF PHASE: two streams each sustaining X,
/// sampled 500 ms apart at a 1 s interval, put a [1.0, 2.0] and a [0.5, 1.5] interval in the same
/// bucket, covered 1.5 s and reported 1.33X where the truth is 2X (~5% at the default 100 ms
/// interval, growing with it).
///
/// Clamping the extent ALONE would have re-broken what the extent was introduced to fix, so the
/// bytes are apportioned by the same overlap: with `--sample-interval-ms 5000` a single 5-second
/// interval now contributes a fifth of its bytes to each of five buckets, each over 1 s, so it
/// is still rated at bytes/5s and never 5× that.
fn add_interval(buckets: &mut AggBuckets, cookie: u64, bytes: f64, ta: u64, tb: u64) {
    debug_assert!(tb > ta, "callers gate on tb > ta");
    let bucket_of = |t: u64| (t as f64 / TS_AGG_BUCKET_NS) as i64;
    let (first, last) = (bucket_of(ta), bucket_of(tb - 1));
    if last.saturating_sub(first) >= TS_AGG_MAX_SPAN_BUCKETS {
        return;
    }
    let dt = (tb - ta) as f64;
    for bk in first..=last {
        // `as u64` on an f64 saturates in Rust, so a bucket index near the i64 ceiling clamps
        // rather than wrapping into a bogus overlap.
        let lo = ta.max((bk as f64 * TS_AGG_BUCKET_NS) as u64);
        let hi = tb.min(((bk + 1) as f64 * TS_AGG_BUCKET_NS) as u64);
        if hi <= lo {
            continue;
        }
        let overlap = (hi - lo) as f64;
        buckets.entry(bk).or_default().add(cookie, bytes * overlap / dt, lo, hi);
    }
}

/// From the 1s buckets: the peak and typical (median) AGGREGATE rate across concurrent
/// streams, plus the max concurrency. Each bucket's rate is its bytes over the wall clock
/// its intervals actually covered (see [`AggBucket`]), and a bucket covering less than
/// [`TS_AGG_MIN_COVER`] of a second is dropped entirely — from the rates AND the concurrency,
/// so a partial edge bucket can neither define the peak nor claim a concurrency the transfer
/// never sustained. `None` when nothing survives.
fn agg_from_buckets(buckets: &AggBuckets) -> Option<(f64, f64, usize)> {
    let covered: Vec<&AggBucket> = buckets
        .values()
        .filter(|b| b.covered_s() >= TS_AGG_MIN_COVER * TS_AGG_BUCKET_NS / 1e9)
        .collect();
    if covered.is_empty() {
        return None;
    }
    let rates: Vec<f64> = covered.iter().map(|b| b.bytes / b.covered_s()).collect();
    let peak = rates.iter().copied().fold(f64::MIN, f64::max);
    let typical = median(rates)?;
    let maxc = covered.iter().map(|b| b.cookies.len()).max().unwrap_or(0);
    Some((peak, typical, maxc))
}

/// Build the in-flight time-series FYI rows from the sample stream. Groups by cookie,
/// segments on a byte-counter reset, then aggregates throughput + bufferbloat across
/// segments. Returns the rows + the number of throughput streams analyzed, as
/// `(total, download, upload)` — the finding population (distinct from the connection count),
/// split so the per-direction rows can each publish their own. Empty when no samples qualify.
fn timeseries_domain(samples: &[&TcpSample]) -> (Vec<Row>, usize, usize, usize) {
    if samples.is_empty() {
        return (Vec::new(), 0, 0, 0);
    }
    let mut by: std::collections::BTreeMap<u64, Vec<&TcpSample>> = std::collections::BTreeMap::new();
    for s in samples {
        by.entry(s.sock_cookie).or_default().push(s);
    }

    let mut sustained_mbps: Vec<f64> = Vec::new();
    let mut peaks_mbps: Vec<f64> = Vec::new();
    let mut t90s: Vec<f64> = Vec::new();
    let (mut steady, mut bursty, mut still, mut short, mut n_str) = (0usize, 0usize, 0usize, 0usize, 0usize);
    // The same stream count split by direction, so each per-direction row publishes its own
    // population rather than the union (which over-counts each by the other's streams).
    let (mut n_dn, mut n_up) = (0usize, 0usize);
    let mut applimited_uploads = 0usize;
    let mut worst_bloat: Option<(f64, &'static str)> = None;
    // Loss/reorder per time-third summed across streams (download reorder, upload retrans).
    let (mut dn_loss, mut up_loss) = ([0.0f64; 3], [0.0f64; 3]);
    // Cross-stream aggregate: sum each direction's per-interval bytes into global 1s
    // wall-clock buckets, tracking which cookies contributed (concurrency).
    let (mut dn_buckets, mut up_buckets): (AggBuckets, AggBuckets) = Default::default();

    for (cookie, mut series) in by {
        series.sort_by_key(|s| s.ts_ns.unwrap_or(0));
        for seg in ts_segments(&series) {
            if let Some(d) = seg_direction(seg) {
                let buckets = match d {
                    SegDir::Down => &mut dn_buckets,
                    SegDir::Up => &mut up_buckets,
                };
                for w in seg.windows(2) {
                    if let (Some(ta), Some(tb)) = (w[0].ts_ns, w[1].ts_ns) {
                        if tb > ta {
                            let dbytes = match d {
                                SegDir::Down => w[1].bytes_recv.saturating_sub(w[0].bytes_recv),
                                SegDir::Up => w[1].bytes_sent.saturating_sub(w[0].bytes_sent),
                            };
                            add_interval(buckets, cookie, dbytes as f64, ta, tb);
                        }
                    }
                }
            }
            if let Some(t) = throughput_of_segment(seg) {
                n_str += 1;
                if t.is_download {
                    n_dn += 1;
                } else {
                    n_up += 1;
                }
                sustained_mbps.push(t.sustained_bps / 1e6);
                peaks_mbps.push(t.peak_bps / 1e6);
                if t.app_limited {
                    applimited_uploads += 1;
                }
                if let Some(p) = t.t90_pct {
                    t90s.push(p);
                }
                match t.shape {
                    Some(ThruShape::Steady) => steady += 1,
                    Some(ThruShape::Bursty) => bursty += 1,
                    Some(ThruShape::StillRamping) => still += 1,
                    None => short += 1,
                }
                if let Some(lt) = t.loss_thirds {
                    let dst = if t.is_download { &mut dn_loss } else { &mut up_loss };
                    for i in 0..3 {
                        dst[i] += lt[i];
                    }
                }
            }
            if let Some((ratio, third)) = bufferbloat_of_segment(seg) {
                if worst_bloat.is_none_or(|(w, _)| ratio > w) {
                    worst_bloat = Some((ratio, third));
                }
            }
        }
    }

    let mut rows = Vec::new();
    // Headline is the SUSTAINED rate (what was actually achieved), not the burst peak.
    // NB: "stream" = one connection segment, which on a keep-alive socket may carry
    // several objects; the peak is across the whole segment.
    if let Some(sustained) = median(sustained_mbps) {
        // Guard the displayed peak >= sustained (a lone-burst 3-pt-MA can dilute below the
        // active-median, which would read "sustained > burst peak"); machine metric is sustained.
        let peak = median(peaks_mbps).unwrap_or(sustained).max(sustained);
        let mut note = format!(
            "{n_str} stream(s), per-stream sustained ~{} (burst peak {})",
            fmt_rate_mbps(sustained),
            fmt_rate_mbps(peak)
        );
        if let Some(t90) = median(t90s) {
            note.push_str(&format!("; reached 90% of peak by ~{t90:.0}% in"));
        }
        if steady + bursty + still > 0 {
            note.push_str(&format!("; {steady} steady / {bursty} bursty / {still} still ramping"));
        }
        if short > 0 {
            note.push_str(&format!("; {short} too short to localize"));
        }
        if applimited_uploads > 0 {
            // app-limited is a SEND-path flag — scope the caveat to the upload streams so it
            // can't read as "the download was sender-idle" (review #2).
            note.push_str(&format!("; {applimited_uploads} upload stream(s) app-limited (sender idle, not the network)"));
        }
        rows.push(Row {
            id: "throughput_ramp",
            label: "throughput",
            value: fmt_rate_mbps(sustained),
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric: Metric {
                name: "throughput_sustained_bps",
                value: Some(sustained * 1e6),
                unit: Unit::BytesPerS,
                ..Default::default()
            },
        });
    }
    // Cross-stream AGGREGATE (per direction): the total throughput across CONCURRENT
    // streams — what a concurrency benchmark actually asks. Only emitted when there was
    // genuine concurrency (>=2 streams in a 1s bucket), since otherwise the per-stream
    // row already says it. Summed in 1s wall-clock buckets (peak = busiest second).
    // Each direction gets its OWN finding_id: the two rows share an (empty) FindingScope, so a
    // single id would emit two findings that are indistinguishable by identity — breaking the
    // "filter rows by stable finding_id" contract and silently dropping one in `diff`, whose
    // map is keyed `finding_id|scope`.
    for (id, buckets, label, dir) in [
        ("throughput_aggregate_down", &dn_buckets, "aggregate \u{2193}", "download"),
        ("throughput_aggregate_up", &up_buckets, "aggregate \u{2191}", "upload"),
    ] {
        if let Some((peak, typical, maxc)) = agg_from_buckets(buckets) {
            if maxc >= 2 {
                rows.push(Row {
                    id,
                    label,
                    value: fmt_rate_mbps(peak / 1e6),
                    mark: Mark::Fyi,
                    verdict: "fyi",
                    note: format!(
                        "{dir}: peak {} across up to {maxc} concurrent streams (typical {}); the per-stream row above is one connection's share",
                        fmt_rate_mbps(peak / 1e6),
                        fmt_rate_mbps(typical / 1e6)
                    ),
                    metric: Metric {
                        name: "throughput_aggregate_bps",
                        value: Some(peak),
                        unit: Unit::BytesPerS,
                        ..Default::default()
                    },
                });
            }
        }
    }
    // Loss TIMELINE (the follow-on): WHEN loss/reorder concentrated in the transfer —
    // the thing the close-snapshot totals can't show. Per direction, summed over the
    // active-window thirds. Reorder on a download is often diffuse → "spread" (honest).
    // The retrans (upload) count is RAW Δtotal_retrans — it includes TLP/spurious, which
    // the headline "retransmit rate" deducts as "clean". Caveat it so the two can't read
    // as contradictory (review). Reorder (rcv_ooopack) is its own counter — no caveat.
    // Per-direction ids, for the same identity reason as the aggregate rows above.
    for (id, thirds, label, unit, caveat) in [
        ("loss_timeline_reorder", dn_loss, "reorder timeline \u{2193}", "out-of-order pkt(s) received", ""),
        ("loss_timeline_retrans", up_loss, "retrans timeline \u{2191}", "retransmit(s) sent", " (incl. TLP/spurious — see the retransmit-rate row)"),
    ] {
        let total: f64 = thirds.iter().sum();
        if total > 0.0 {
            let (mi, &mx) = thirds
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).expect("finite"))
                .expect("3 thirds");
            // Concentrated only if one third holds a STRICT majority; else honestly "spread".
            // Non-strict (`>=`) called an exact even split concentrated — thirds [2,2,0] has
            // two co-maxima at exactly half, and `max_by` returns the LAST of them, so the
            // report picked "mid" out of a genuine tie. A strict majority is unique by
            // construction, so the tie-break order stops mattering.
            let when = if mx > 0.5 * total {
                format!("concentrated {} in the transfer", ["early", "mid", "late"][mi])
            } else {
                "spread across the transfer (no single phase)".to_string()
            };
            rows.push(Row {
                id,
                label,
                value: fmt_count(total),
                mark: Mark::Fyi,
                verdict: "fyi",
                note: format!("{} {unit} — {when}{caveat}", fmt_count(total)),
                metric: Metric {
                    name: "loss_events",
                    value: Some(total), // exact count for machine consumers
                    unit: Unit::Count,
                    ..Default::default()
                },
            });
        }
    }
    if let Some((ratio, onset)) = worst_bloat {
        let (verdict, note) = if ratio >= TS_BLOAT_HI {
            let where_ = if onset.is_empty() { String::new() } else { format!(", onset {onset}") };
            // This is the PEAK over time (the worst moment under load) — distinct from the
            // path row's steady-state median, so the two can read differently and not conflict.
            ("bloated", format!("srtt peaked at {ratio:.1}x the floor{where_} — queue filling under load (bufferbloat; this is the peak over time, vs the path row's median)"))
        } else if ratio > TS_BLOAT_LO {
            ("mild", format!("srtt peaked at {ratio:.1}x the floor over the transfer — mild queueing (under the 2x inflation flag)"))
        } else {
            ("flat", format!("srtt stayed within {ratio:.1}x the floor — no queue growth"))
        };
        rows.push(Row {
            id: "bufferbloat_onset",
            label: "bufferbloat",
            value: format!("{ratio:>4.1}x"),
            mark: Mark::Fyi,
            verdict,
            note,
            metric: Metric {
                name: "srtt_inflation_ratio",
                value: Some(ratio),
                unit: Unit::Ratio,
                ..Default::default()
            },
        });
    }
    (rows, n_str, n_dn, n_up)
}

/// Connection-level PATH diagnosis (the extended tcp_sock fields: true-floor min_rtt +
/// jitter, the send-bottleneck chronos, the single-stream BDP ceiling, loss shape).
/// Aggregates across the capture's connections. Every row is ADVISORY — it enriches the
/// report (and is the ONLY signal available for Go/non-OpenSSL clients, which produce
/// connection records but no operations) and never escalates the verdict. Empty when the
/// fields aren't present (records from before the capture enrichment), so it's parity-safe.
fn path_domain(conns: &[&Connection]) -> Vec<Row> {
    let mut rows = Vec::new();
    let ms = |xs: Vec<f64>| median(xs);
    // snd_cwnd / delivery_rate / the busy-time chronos are all SEND-path — they describe the
    // bytes WE pushed. On a download (GET: bytes_recv >> bytes_sent) the client barely sends,
    // so they're ~0 and would misframe a fast GET as "app-limited, parallelize". Gate the
    // send-side rows on send/upload-heavy connections; the L7 GetObject-throughput row already
    // covers download speed. (min RTT / jitter / loss shape are direction-agnostic — always.)
    // A real UPLOAD: sent dominates received AND moved enough to actually open the send window.
    // The bytes floor (64 KiB) stops a small GET/HEAD/4xx — whose request bytes can exceed a
    // tiny response — from being mistaken for an upload (review #7). Used on iter().copied().
    let send_heavy = |c: &&Connection| c.bytes_sent > c.bytes_recv && c.bytes_sent >= MIN_DIRECTIONAL_BYTES;
    // Re-apply the producer's sentinel filter on the CONSUMER side too: a record parsed from
    // hand-crafted/untrusted JSONL can carry min_rtt 0 or U32_MAX (the kernel "never sampled"
    // values the correlator strips), which would render a bogus 0.0 ms / ~4.3M ms floor
    // (review#3 #1). Use the SAME plausibility bound as `conn_floor_us`/`path_domain_sampled`
    // (< MAX_PLAUSIBLE_RTT_US, a strict superset of the u32::MAX exclusion) so a crafted value
    // in the [30 s, u32::MAX) band can't slip through here where it does not elsewhere.
    // ONE closure for the whole RTT family (min_rtt, srtt AND rttvar): the predicate was
    // identical for the first two, and the third — jitter — was the field that skipped it and
    // printed "jitter ±4294967.3 ms" beside two values the same bound had just rejected
    // (review#4 #5). Sharing it is what makes "a fourth RTT field forgets the guard"
    // unrepresentable. (0 is the producer's "never sampled" sentinel for all three:
    // correlate.rs maps rttvar_us 0 → None exactly as it does srtt.)
    let live_rtt = |m: Option<u32>| m.filter(|&v| v != 0 && v < MAX_PLAUSIBLE_RTT_US);

    // 1) True propagation floor (min_rtt) + jitter + srtt inflation under load. The inflation
    // is the MEDIAN of per-connection srtt/min_rtt — not a ratio of two independent population
    // medians, which a mix of connections could skew (review #13).
    let min_rtts: Vec<f64> = conns.iter().filter_map(|c| live_rtt(c.min_rtt_us)).map(|v| f64::from(v) / 1e3).collect();
    if let Some(min_rtt) = ms(min_rtts) {
        // Third `unwrap_or` in this expression, and the one the first pass missed while
        // removing the other two — `±0.0 ms` reads as a perfectly jitter-free path on a
        // capture where nothing measured jitter at all (`live_rtt` maps the rttvar 0 sentinel
        // to None, so this is reachable from ordinary records).
        let jitter = ms(conns.iter().filter_map(|c| live_rtt(c.rttvar_us)).map(|v| f64::from(v) / 1e3).collect());
        // NO `unwrap_or` on either of these. `.unwrap_or(min_rtt)` and `.unwrap_or(1.0)` made
        // a capture whose connections carry no srtt at all print "srtt 1.0 ms, ~1.0× the floor
        // — path RTT stable": a measurement and a conclusion both manufactured from an absent
        // value. Mark::Fyi means it never gated, but it was still asserted as fact, and "never
        // guess a number" does not have an exception for FYI rows.
        let srtt = ms(conns.iter().filter_map(|c| live_rtt(c.srtt_us)).map(|v| f64::from(v) / 1e3).collect());
        let infl = ms(conns
            .iter()
            .filter_map(|c| {
                let mr = f64::from(live_rtt(c.min_rtt_us)?);
                let sr = f64::from(live_rtt(c.srtt_us)?);
                (mr > 0.0).then_some(sr / mr)
            })
            .collect());
        // The stability call rests on the inflation ratio, so with no ratio there is no call.
        // The ratio's population is connections carrying BOTH a min_rtt and an srtt, which is
        // narrower than "some connection has an srtt". Saying "no srtt on any connection" here
        // contradicted the srtt this same note prints two clauses earlier, on a capture where
        // one connection carried min_rtt and another carried srtt.
        let tail = match infl {
            Some(i) if i >= 2.0 => "RTT inflated under load (queueing / bufferbloat)",
            Some(_) => "path RTT stable",
            None => "inflation under load not judged: no connection carried both a min_rtt \
                     and an srtt",
        };
        rows.push(Row {
            id: "path_min_rtt",
            label: "min RTT (true floor)",
            value: format!("{min_rtt:>5.1} ms"),
            mark: Mark::Fyi,
            verdict: "fyi",
            // srtt and the inflation ratio are aggregated independently (median srtt vs median
            // per-conn srtt/min_rtt), so present them as separate stats, not an equation (#13).
            // Each clause appears only if its own number was measured. Nothing here is
            // defaulted: the row is Fyi, and "never guess a number" has no Fyi exception.
            note: {
                let mut parts: Vec<String> = Vec::new();
                if let Some(j) = jitter {
                    parts.push(format!("jitter ±{j:.1} ms"));
                }
                match (srtt, infl) {
                    (Some(sr), Some(i)) => parts.push(format!("srtt {sr:.1} ms, ~{i:.1}× the floor")),
                    (Some(sr), None) => parts.push(format!("srtt {sr:.1} ms")),
                    _ => {}
                }
                parts.push(tail.to_string());
                parts.join("; ")
            },
            metric: Metric { name: "min_rtt", value: Some(min_rtt), unit: Unit::Ms, ..Default::default() },
        });
    }

    // 1b) TLS handshake duration (ClientHello -> first app-data egress) as a multiple of the
    // floor: ~1x = TLS 1.3 / a resumed session; ~2x = a full handshake (TLS 1.2 or no session
    // resumption) — a wasted round-trip. Connection-level + library-agnostic (kernel-timed).
    if let Some(hs_ms) = ms(conns.iter().filter_map(|c| c.tls.handshake_ns).map(|v| v as f64 / 1e6).collect()) {
        let floor = ms(conns.iter().filter_map(|c| live_rtt(c.min_rtt_us)).map(|v| f64::from(v) / 1e3).collect());
        let ratio = floor.and_then(|f| (f > 0.0).then_some(hs_ms / f));
        // Prefer the NEGOTIATED version/cipher from the ServerHello (S2) when captured;
        // otherwise INFER it from the RTT ratio (~1x = 1.3/resumed, ~2x = full 1.2).
        // `tls.version` is a free-form string off the untrusted JSONL stream and lands in a
        // note `render` prints verbatim to a tty, so it MUST be scrubbed first (CWE-117 /
        // Trojan Source) — the same gate `s3_op` passes through before grouping. Without it a
        // crafted version could emit ANSI/CR and rewrite the rows already printed above it,
        // forging a healthy report.
        let ver = conns.iter().find_map(|c| c.tls.version.as_deref()).map(s3tap_schema::sanitize_term);
        let cipher = conns.iter().find_map(|c| c.tls.cipher);
        let note = match (ver.as_deref(), ratio) {
            // A real negotiated version is authoritative — don't append the RTT-ratio
            // suffix. The ratio is only the *inference* fallback, and it is a fleet
            // median while ver/cipher come from one connection, so pairing them can read
            // as self-contradictory (e.g. "TLS 1.3 — 2.0× the floor").
            (Some(v), _) => {
                let c = cipher.map(|c| format!(", cipher 0x{c:04x}")).unwrap_or_default();
                format!("{v}{c}")
            }
            (None, Some(r)) if r >= 1.8 => {
                format!("{r:.1}× the floor — a full handshake (likely TLS 1.2 or no session resumption), a wasted round-trip")
            }
            (None, Some(r)) => format!("{r:.1}× the floor — ~1 RTT (likely TLS 1.3 or a resumed session)"),
            (None, None) => "ClientHello → first app-data".into(),
        };
        rows.push(Row {
            id: "tls_handshake",
            label: "TLS handshake",
            value: format!("{hs_ms:>5.1} ms"),
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric: Metric {
                name: "tls_handshake",
                value: Some(hs_ms),
                unit: Unit::Ms,
                rtt_relative: true,
                ratio_to_rtt: ratio,
                // The ratio's OWN denominator (the median min_rtt), not the pooled close-time
                // srtt the `rtt_relative` fallback would supply. Leaving it None published a
                // finding whose `value / baseline_rtt_us` contradicted its own `ratio_to_rtt`
                // (3 ms over a 1 ms floor is a 3× full handshake; recomputed against a 3 ms
                // srtt it reads 1.0× — a clean TLS 1.3, the opposite call). `s3_ttfb` already
                // carries its own floor for exactly this reason (review#4 #3).
                baseline_us: floor.map(|f_ms| f_ms * 1e3),
                ..Default::default()
            },
        });
    }

    // 2) Send-side bottleneck (upload-heavy conns only). The three TCP chronos are DISJOINT
    // (a single-state machine): busy = time SENDING FREELY, rwnd/sndbuf = time blocked on the
    // receiver window / local send buffer. Total send-busy = their SUM (= tcpi_busy_time), so
    // the denominator is the sum, NOT busy alone (review #2). Summing the sum also means a
    // fully receiver/buffer-limited connection (busy==0) still shows up (review #4).
    let busy: f64 = conns.iter().copied().filter(send_heavy).filter_map(|c| c.busy_jiffies).map(f64::from).sum();
    let rwnd: f64 = conns.iter().copied().filter(send_heavy).filter_map(|c| c.rwnd_limited_jiffies).map(f64::from).sum();
    let sndbuf: f64 = conns.iter().copied().filter(send_heavy).filter_map(|c| c.sndbuf_limited_jiffies).map(f64::from).sum();
    let total = busy + rwnd + sndbuf;
    if total > 0.0 {
        let free_pct = busy / total * 100.0;
        let rwnd_pct = rwnd / total * 100.0;
        let sndbuf_pct = sndbuf / total * 100.0;
        rows.push(Row {
            id: "send_bottleneck",
            label: "send bottleneck",
            value: format!("{free_pct:>4.0}% free"),
            mark: Mark::Fyi,
            verdict: "fyi",
            note: format!(
                "of busy time: {free_pct:.0}% sending freely, {rwnd_pct:.0}% receiver-window-limited, \
                 {sndbuf_pct:.0}% send-buffer-limited"
            ),
            metric: Metric { name: "send_free_pct", value: Some(free_pct), unit: Unit::None, ..Default::default() },
        });
    }

    // 3) Single-stream BDP ceiling (cwnd·mss / min_rtt) vs the kernel delivery rate, paired
    // PER connection (same socket) then aggregated — not two independent population medians
    // (review #10). Upload-heavy conns only (both are send-path).
    let pairs: Vec<(&Connection, f64, Option<f64>)> = conns
        .iter()
        .copied()
        .filter(send_heavy)
        .filter_map(|c| {
            // Require cwnd>0 AND mss>0 (a 0 is "no sample", as the correlator maps it): a 0
            // ceiling would make achieved/ceiling = 0/0 = NaN, which panics median()'s sort
            // (review #2 — reachable via hand-crafted untrusted JSONL).
            let cwnd = f64::from(c.snd_cwnd.filter(|&v| v > 0)?);
            let mss = f64::from(c.mss.filter(|&v| v > 0)?);
            let mr = f64::from(live_rtt(c.min_rtt_us)?);
            // delivery_rate==0 is the same "no sample" sentinel (correlator maps it to None);
            // re-filter it here too so a crafted 0 doesn't enter the `complete` subset as a
            // genuine 0 MB/s and trip the false "app-limited; parallelize" verdict below.
            let drate = c.delivery_rate_bps.filter(|&v| v > 0).map(|v| v as f64);
            (mr > 0.0).then(|| (c, cwnd * mss / (mr / 1e6), drate)) // (conn, ceiling, achieved) bytes/s
        })
        .collect();
    if let Some(ceil) = ms(pairs.iter().map(|(_, c, _)| *c).collect()) {
        // Judge "achieved vs ceiling" over the SAME subset — connections with BOTH a ceiling
        // and a delivery rate — so the displayed achieved and the verdict can't disagree
        // (review #10). The displayed ceiling value is over all pairs; the comparison is over
        // the complete subset (its own ceiling median as the reference).
        let complete: Vec<(&Connection, f64, f64)> = pairs.iter().filter_map(|(c, cl, a)| a.map(|a| (*c, *cl, a))).collect();
        let ach = ms(complete.iter().map(|(_, _, a)| *a).collect());
        let ceil_j = ms(complete.iter().map(|(_, cl, _)| *cl).collect());
        // Ground-truth the "well under ceiling → app-limited?" GUESS with the kernel flag
        // (tcp_sock.rate_app_limited). Count only conns that are app-limited AND themselves
        // well under their OWN ceiling — those are the ones actually dragging the median down.
        // Counting every app-limited conn in `complete` (even fast ones at/above their ceiling)
        // would attribute a low median to conns that aren't its cause (the population/verdict
        // mismatch of review #10). NOT wired into recv_ceiling (send-path concept).
        let app_lim = complete.iter()
            .filter(|(c, cl, a)| c.app_limited == Some(true) && *a < 0.5 * *cl)
            .count();
        let note = match (ach, ceil_j) {
            (Some(a), Some(cj)) if a < 0.5 * cj && app_lim > 0 => format!(
                "achieved {:.0} MB/s, well under the window ceiling — APP-LIMITED ({app_lim} conn(s): kernel rate_app_limited set; the sender waited on the app, not the network)",
                a / 1e6
            ),
            (Some(a), Some(cj)) if a < 0.5 * cj => format!(
                "achieved {:.0} MB/s — well under the window ceiling: single-stream (no app-limited flag set); parallelize",
                a / 1e6
            ),
            (Some(a), _) => format!("achieved {:.0} MB/s, near the single-stream ceiling — parallelize for more", a / 1e6),
            _ => "single-stream window ceiling (cwnd·mss / min_rtt); parallelize to exceed it".into(),
        };
        rows.push(Row {
            id: "bdp_ceiling",
            label: "1-stream ceiling",
            value: format!("{:>4.0} MB/s", ceil / 1e6),
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric: Metric { name: "bdp_ceiling", value: Some(ceil), unit: Unit::BytesPerS, ..Default::default() },
        });
    }

    // 3b) RECEIVE-side ceiling for DOWNLOADS (the S3 GET case). The client's receive window
    // caps how fast it can pull a single stream: window_clamp / min_rtt. The send-side
    // cwnd/delivery_rate above are ~0 on a GET, so this is the ONLY throughput ceiling for a
    // download. Gated on download-heavy connections (the inverse of send_heavy). Achieved is
    // the connection-average bytes_recv/lifetime (a LOWER bound — idle time on a keep-alive
    // connection inflates lifetime), so we only assert "receive-window-limited" when even that
    // floor reaches the ceiling; otherwise we report headroom, not a false "server-limited".
    let recv_heavy = |c: &&Connection| c.bytes_recv > c.bytes_sent && c.bytes_recv >= MIN_DIRECTIONAL_BYTES;
    let recv: Vec<(f64, f64)> = conns
        .iter()
        .copied()
        .filter(recv_heavy)
        .filter_map(|c| {
            let clamp = f64::from(c.window_clamp.filter(|&v| v > 0)?);
            let mr = f64::from(live_rtt(c.min_rtt_us)?);
            let life = c.lifetime_ns? as f64;
            (mr > 0.0 && life > 0.0)
                .then(|| (clamp / (mr / 1e6), c.bytes_recv as f64 / (life / 1e9))) // (ceiling, avg) bytes/s
        })
        .collect();
    if let Some(ceil) = ms(recv.iter().map(|(c, _)| *c).collect()) {
        let avg = ms(recv.iter().map(|(_, a)| *a).collect()).unwrap_or(0.0);
        // Decide from the SAME medians we print, so the number and the verdict can't disagree
        // (review #10 / the bdp_ceiling invariant — not median-of-ratios). avg is a LOWER bound
        // (keep-alive idle inflates lifetime), so >=0.7 is a SOUND assertion of "limited"; the
        // converse is NOT — a short rcv-limited transfer that then idled also lands in the else
        // — so phrase the else as INCONCLUSIVE, never "not the bottleneck" (review: false-neg).
        let note = if ceil > 0.0 && avg / ceil >= 0.7 {
            format!(
                "avg {:.0} MB/s ≈ the {:.0} MB/s receive-window ceiling — RECEIVE-WINDOW-LIMITED; raise SO_RCVBUF / net.ipv4.tcp_rmem",
                avg / 1e6,
                ceil / 1e6
            )
        } else {
            format!(
                "single-stream download cap {:.0} MB/s (rcv window / min_rtt); connection-avg pull {:.0} MB/s is under it, but keep-alive idle deflates that average — can't rule the receive window in or out",
                ceil / 1e6,
                avg / 1e6
            )
        };
        rows.push(Row {
            id: "recv_ceiling",
            label: "download ceiling",
            value: format!("{:>4.0} MB/s", ceil / 1e6),
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric: Metric { name: "recv_window_ceiling", value: Some(ceil), unit: Unit::BytesPerS, ..Default::default() },
        });
    }

    // 4) Loss shape: above-default reordering, or connections that closed in real loss
    // recovery. Only ca_state >= 3 (Recovery/Loss) counts — 1 (Disorder) and 2 (CWR) are
    // normal congestion-control states, not loss (review #9/#11). Surfaced only when present.
    let reord = conns.iter().filter_map(|c| c.reordering).max();
    let recov = conns.iter().filter(|c| c.ca_state.is_some_and(|s| s >= 3)).count();
    let reorder_high = reord.is_some_and(|r| r > 3);
    // Two new loss-quality counters: rcv_ooopack (out-of-order pkts RECEIVED, summed over ALL
    // conns) is the download-leg reorder/loss signal the durable `reordering` degree can't show
    // — the GET win. dsack_dups (summed over SEND-heavy conns only) is upload-leg spurious
    // retransmits: the original DID arrive (DSACK), so it's reordering/RTO, NOT loss.
    // Sum as u64 (promote before adding, like `rtx` above): a long lossy download's per-conn
    // rcv_ooopack summed across many conns from untrusted JSONL could overflow a u32 (panic in
    // debug / wrap in release).
    let ooo: u64 = conns.iter().filter_map(|c| c.rcv_ooopack).map(u64::from).sum();
    let dsack: u64 = conns.iter().copied().filter(send_heavy).filter_map(|c| c.dsack_dups).map(u64::from).sum();
    if reorder_high || recov > 0 || ooo > 0 || dsack > 0 {
        let r = reord.unwrap_or(0);
        // Lead with whichever signal actually fired so we never print "reorder 0" when the
        // trigger was loss recovery (review #6), and emit the MATCHING machine metric — not the
        // reordering degree on a loss-recovery-only event (review#3 #2: reordering defaults to
        // the kernel's 3, so it would otherwise mislabel a loss-recovery finding as reorder=3).
        // The new ooo/dsack counters lead only when nothing else fired; otherwise they append.
        let (value, mut note, metric) = match (reorder_high, recov) {
            (true, n) if n > 0 => (
                format!("reorder {r:>3}"),
                format!("max reordering degree {r}; {n} connection(s) closed in loss recovery"),
                Metric { name: "reordering", value: Some(f64::from(r)), unit: Unit::Count, ..Default::default() },
            ),
            (true, _) => (
                format!("reorder {r:>3}"),
                format!("max reordering degree {r}"),
                Metric { name: "reordering", value: Some(f64::from(r)), unit: Unit::Count, ..Default::default() },
            ),
            (false, n) if n > 0 => (
                format!("loss x{n:>2}"),
                format!("{n} connection(s) closed in loss recovery (Recovery/Loss)"),
                Metric { name: "loss_recovery", value: Some(n as f64), unit: Unit::Count, ..Default::default() },
            ),
            // Only the new recv/send counters fired: lead with the download-leg reorder (ooo),
            // else the send-leg DSACK. The appended clauses below carry the human detail.
            (false, _) if ooo > 0 => (
                format!("ooo {ooo:>5}"),
                String::new(),
                Metric { name: "rcv_ooopack", value: Some(ooo as f64), unit: Unit::Count, ..Default::default() },
            ),
            (false, _) => (
                format!("dsack {dsack:>3}"),
                String::new(),
                Metric { name: "dsack_dups", value: Some(dsack as f64), unit: Unit::Count, ..Default::default() },
            ),
        };
        // Append the new evidence (when present) regardless of what led, so a reorder/recovery
        // row also surfaces the receive-leg reorder and send-leg spurious-retransmit counts.
        if ooo > 0 {
            if !note.is_empty() {
                note.push_str("; ");
            }
            note.push_str(&format!("{ooo} out-of-order pkt(s) received (download-leg reorder/loss)"));
        }
        if dsack > 0 {
            if !note.is_empty() {
                note.push_str("; ");
            }
            note.push_str(&format!("{dsack} spurious (DSACK) retransmit(s) — reordering/RTO, not loss"));
        }
        rows.push(Row {
            id: "loss_shape",
            label: "loss shape",
            value,
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric,
        });
    }

    rows
}

/// Assumed MSS for the SAMPLED send BDP ceiling: `TcpSample` carries `snd_cwnd` (in segments)
/// but not the connection's mss, so the sampled fallback assumes the standard 1500-byte-MTU
/// Ethernet MSS. Disclosed in the row. The close-time path uses the real per-conn mss.
const ASSUMED_MSS_BYTES: f64 = 1460.0;

/// Sample-based single-stream throughput ceilings, for the persistent-pool case where NO
/// connection closed (so `path_domain(conns)` is empty). Groups samples by cookie, segments on
/// the reuse boundary (see [`ts_segments`]), and — per direction — derives the same two ceilings
/// `path_domain` reads off a closed connection, but each from a PROXY the sample carries rather
/// than the exact close-time field: the DOWNLOAD receive-window ceiling (peak `rcv_wnd` — a
/// LOWER-BOUND proxy for `window_clamp`, since `rcv_wnd ≤ window_clamp` — over `min_rtt`) and the
/// SEND BDP ceiling (`snd_cwnd · MSS / min_rtt`, MSS assumed — see [`ASSUMED_MSS_BYTES`]). Both
/// proxies are disclosed in the row notes. Achieved throughput + the app-limited flag come from
/// [`throughput_of_segment`] (direction-aware); each ceiling is judged/displayed over the SAME
/// segment subset that has a measurable rate (the close path's review-#10 invariant). Every row
/// is ADVISORY (`Mark::Fyi`) and labelled "sampled"; nothing here gates the verdict. Empty when
/// no directional segment carries the needed fields.
/// Returns `(rows, recv_stream_count, send_stream_count)`: the per-direction judged
/// population for the sampled recv_ceiling (download) and bdp_ceiling (upload) rows.
fn path_domain_sampled(samples: &[&TcpSample]) -> (Vec<Row>, usize, usize) {
    if samples.is_empty() {
        return (Vec::new(), 0, 0);
    }
    // Re-apply the floor plausibility guard on the consumer side (crafted min_rtt 0/sentinel).
    let live_min_rtt = |m: Option<u32>| m.filter(|&v| v != 0 && v < MAX_PLAUSIBLE_RTT_US);
    // A segment's true propagation floor (s): the min live min_rtt across its samples.
    let seg_min_rtt_s = |seg: &[&TcpSample]| -> Option<f64> {
        seg.iter().filter_map(|s| live_min_rtt(s.min_rtt_us)).min().map(|v| f64::from(v) / 1e6)
    };

    let mut by: std::collections::BTreeMap<u64, Vec<&TcpSample>> = std::collections::BTreeMap::new();
    for s in samples {
        by.entry(s.sock_cookie).or_default().push(s);
    }

    // Per directional segment: (ceiling bytes/s, achieved bytes/s or None). Upload also carries
    // whether the kernel flagged it app-limited.
    let mut dn: Vec<(f64, Option<f64>)> = Vec::new();
    let mut up: Vec<(f64, Option<f64>, bool)> = Vec::new();
    // Distinct sample streams that contributed at least one ceiling segment, tracked PER
    // DIRECTION: recv_ceiling is judged over download streams, bdp_ceiling over upload ones,
    // so a mixed GET/PUT capture must not report each row's judged population as the union
    // (that would over-count each by the streams that only ran the other direction).
    let mut dn_streams: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut up_streams: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for (cookie, mut series) in by {
        series.sort_by_key(|s| s.ts_ns.unwrap_or(0));
        for seg in ts_segments(&series) {
            let Some(mr) = seg_min_rtt_s(seg) else { continue }; // mr > 0 (min_rtt != 0 filtered)
            let thru = throughput_of_segment(seg);
            match seg_direction(seg) {
                Some(SegDir::Down) => {
                    // window_clamp proxy: the PEAK advertised receive window over the segment
                    // (rcv_wnd grows toward the clamp under load). Already bytes — no MSS.
                    if let Some(clamp) = seg.iter().map(|s| s.rcv_wnd).filter(|&w| w > 0).max() {
                        dn.push((f64::from(clamp) / mr, thru.as_ref().map(|t| t.sustained_bps)));
                        dn_streams.insert(cookie);
                    }
                }
                Some(SegDir::Up) => {
                    let cwnd = median(
                        seg.iter().map(|s| s.snd_cwnd).filter(|&c| c > 0).map(f64::from).collect(),
                    );
                    if let Some(cwnd) = cwnd {
                        up.push((
                            cwnd * ASSUMED_MSS_BYTES / mr,
                            thru.as_ref().map(|t| t.sustained_bps),
                            thru.as_ref().is_some_and(|t| t.app_limited),
                        ));
                        up_streams.insert(cookie);
                    }
                }
                None => {}
            }
        }
    }

    let mut rows = Vec::new();
    // Download receive-window ceiling (the S3 GET case). Judge AND display over the SAME
    // population — the segments that carry a measurable throughput sample — so the printed
    // ceiling and the verdict can't be drawn from different subsets and disagree (the close
    // path's review-#10 invariant; `dn`'s ceilings and rates would otherwise be medianed over
    // different segments). Fall back to a ceiling-only row when no segment had a rate. Rates go
    // through `fmt_rate_mbps` so a sub-1-MB/s stream reads "…KB/s", not a useless "0 MB/s".
    let dn_ok: Vec<(f64, f64)> = dn.iter().filter_map(|(cl, a)| a.map(|a| (*cl, a))).collect();
    if let (Some(ceil), Some(avg)) = (
        median(dn_ok.iter().map(|(c, _)| *c).collect()),
        median(dn_ok.iter().map(|(_, a)| *a).collect()),
    ) {
        let note = if ceil > 0.0 && avg / ceil >= 0.7 {
            format!(
                "sustained {} ≈ the {} receive-window ceiling (sampled: peak rcv window / min_rtt, \
                 a lower-bound estimate) — likely RECEIVE-WINDOW-LIMITED; if raising SO_RCVBUF / \
                 net.ipv4.tcp_rmem doesn't lift it, the window wasn't the cap",
                fmt_rate_mbps(avg / 1e6),
                fmt_rate_mbps(ceil / 1e6)
            )
        } else {
            format!(
                "single-stream download cap {} (sampled: peak rcv window / min_rtt, a lower-bound \
                 estimate); sustained {} is under it — receive window not the sustained bottleneck here",
                fmt_rate_mbps(ceil / 1e6),
                fmt_rate_mbps(avg / 1e6)
            )
        };
        rows.push(Row {
            id: "recv_ceiling",
            label: "download ceiling",
            value: fmt_rate_mbps(ceil / 1e6),
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric: Metric { name: "recv_window_ceiling", value: Some(ceil), unit: Unit::BytesPerS, ..Default::default() },
        });
    } else if let Some(ceil) = median(dn.iter().map(|(c, _)| *c).collect()) {
        rows.push(Row {
            id: "recv_ceiling",
            label: "download ceiling",
            value: fmt_rate_mbps(ceil / 1e6),
            mark: Mark::Fyi,
            verdict: "fyi",
            note: format!(
                "single-stream download cap {} (sampled: peak rcv window / min_rtt, a lower-bound \
                 estimate) — throughput not measurable this window",
                fmt_rate_mbps(ceil / 1e6)
            ),
            metric: Metric { name: "recv_window_ceiling", value: Some(ceil), unit: Unit::BytesPerS, ..Default::default() },
        });
    }
    // Send BDP ceiling (upload) — MSS assumed (disclosed), unlike the close path's real mss. Same
    // same-population judging as the download row above (review-#10 invariant).
    let up_ok: Vec<(f64, f64, bool)> =
        up.iter().filter_map(|(cl, a, flag)| a.map(|a| (*cl, a, *flag))).collect();
    if let (Some(ceil), Some(ach)) = (
        median(up_ok.iter().map(|(c, _, _)| *c).collect()),
        median(up_ok.iter().map(|(_, a, _)| *a).collect()),
    ) {
        // App-limited only counts segments flagged AND themselves well under their OWN ceiling
        // (the ones dragging the median down), mirroring the close path's guard.
        let app = up_ok.iter().filter(|(cl, a, flag)| *flag && *a < 0.5 * *cl).count();
        let note = if ach < 0.5 * ceil && app > 0 {
            format!(
                "achieved {}, well under the window ceiling — APP-LIMITED ({app} segment(s): kernel \
                 rate_app_limited set); sampled, MSS assumed ~1460",
                fmt_rate_mbps(ach / 1e6)
            )
        } else if ach < 0.5 * ceil {
            format!(
                "achieved {} — well under the window ceiling; parallelize (sampled, MSS assumed ~1460)",
                fmt_rate_mbps(ach / 1e6)
            )
        } else {
            format!(
                "achieved {}, near the single-stream ceiling — parallelize for more (sampled, MSS assumed ~1460)",
                fmt_rate_mbps(ach / 1e6)
            )
        };
        rows.push(Row {
            id: "bdp_ceiling",
            label: "1-stream ceiling",
            value: fmt_rate_mbps(ceil / 1e6),
            mark: Mark::Fyi,
            verdict: "fyi",
            note,
            metric: Metric { name: "bdp_ceiling", value: Some(ceil), unit: Unit::BytesPerS, ..Default::default() },
        });
    } else if let Some(ceil) = median(up.iter().map(|(c, _, _)| *c).collect()) {
        rows.push(Row {
            id: "bdp_ceiling",
            label: "1-stream ceiling",
            value: fmt_rate_mbps(ceil / 1e6),
            mark: Mark::Fyi,
            verdict: "fyi",
            note: "single-stream window ceiling (cwnd · MSS / min_rtt; sampled, MSS assumed ~1460); \
                   parallelize to exceed it"
                .into(),
            metric: Metric { name: "bdp_ceiling", value: Some(ceil), unit: Unit::BytesPerS, ..Default::default() },
        });
    }
    (rows, dn_streams.len(), up_streams.len())
}

// ANSI codes for the human renderers. `ansi(color)` gates them: identity on a tty, blanks on
// redirect / golden tests, so captured output stays plain text (one home for the color rule).
const DIM: &str = "\x1b[2m";
const OK: &str = "\x1b[32m";
const WARN: &str = "\x1b[33m";
const OFF: &str = "\x1b[0m";
fn ansi(color: bool) -> impl Fn(&'static str) -> &'static str {
    move |s| if color { s } else { "" }
}

/// Build an RTT-relative row: shows the value, marks n/a when there's no floor, else
/// judges the ratio with `ok`. Centralizes the "no floor → not judged" rule.
#[allow(clippy::too_many_arguments)] // a centralized row builder; each arg is distinct.
fn ratio_row(
    id: &'static str,
    label: &'static str,
    ms: f64,
    rtt_ms: Option<f64>,
    ok: impl Fn(f64) -> bool,
    words: (&'static str, &'static str), // (ok_word, bad_word)
    threshold: &'static str,
    note: impl Fn(f64) -> String,
) -> Row {
    match rtt_ms {
        None => Row {
            id,
            label,
            value: format!("{ms:>5.1} ms"),
            mark: Mark::Na,
            verdict: "n/a",
            note: "no round-trip baseline — not judged".into(),
            metric: Metric {
                name: id,
                value: Some(ms),
                unit: Unit::Ms,
                rtt_relative: true,
                ratio_to_rtt: None,
                threshold,
                baseline_us: None,
                per_op_baseline: false,
            },
        },
        Some(rtt) => {
            let ratio = ms / rtt;
            let good = ok(ratio);
            Row {
                id,
                label,
                value: format!("{ms:>5.1} ms"),
                mark: if good { Mark::Ok } else { Mark::Warn },
                verdict: if good { words.0 } else { words.1 },
                note: note(ratio),
                metric: Metric {
                    name: id,
                    value: Some(ms),
                    unit: Unit::Ms,
                    rtt_relative: true,
                    ratio_to_rtt: Some(ratio),
                    threshold,
                    baseline_us: None,
                    per_op_baseline: false,
                },
            }
        }
    }
}

impl Report {
    /// Render the human report. `color` adds ANSI; off for a non-tty
    /// or a golden test.
    #[must_use]
    pub fn render(&self, color: bool) -> String {
        let c = ansi(color);
        let mark_col = |m: Mark| match m {
            Mark::Ok => OK,
            Mark::Warn => WARN,
            Mark::Na | Mark::Advisory | Mark::Fyi => DIM,
        };

        // Column widths span the global, S3, tail, reuse, AND path rows so every section aligns.
        let label_w = |r: &Row| r.label.chars().count();
        let wlab = self
            .rows
            .iter()
            .chain(self.tail.iter())
            .chain(self.reuse.iter())
            .chain(self.path.iter())
            .chain(self.timeseries.iter())
            .map(label_w)
            .chain(self.s3.iter().map(|r| r.label.chars().count()))
            .max()
            .unwrap_or(0);
        let val_w = |r: &Row| r.value.chars().count();
        let wval = self
            .rows
            .iter()
            .chain(self.tail.iter())
            .chain(self.reuse.iter())
            .chain(self.path.iter())
            .chain(self.timeseries.iter())
            .map(val_w)
            .chain(self.s3.iter().map(|r| r.value.chars().count()))
            .max()
            .unwrap_or(0);

        let fmt_row = |label: &str, value: &str, mark: Mark, verdict: &str, note: &str| -> String {
            format!(
                "  {label:<wlab$} {value:>wval$}  {mc}{glyph} {verdict:<9}{off} {dim}{note}{off}\n",
                mc = c(mark_col(mark)),
                glyph = mark.glyph(),
                off = c(OFF),
                dim = c(DIM),
            )
        };

        // A dim section header line: `  <title>` in DIM. One home for the color scaffold so
        // every section header reads as just its title.
        let section = |title: &str| format!("  {}{title}{}\n", c(DIM), c(OFF));

        let mut out = String::new();
        out.push_str(&section("are these numbers healthy? (each span vs the round-trip floor)"));
        if let Some(env) = &self.environment {
            out.push_str(&format!("  environment: {}\n", env.line()));
        }
        for r in &self.rows {
            out.push_str(&fmt_row(r.label, &r.value, r.mark, r.verdict, &r.note));
        }
        if let Some(r) = &self.reuse {
            out.push_str(&fmt_row(r.label, &r.value, r.mark, r.verdict, &r.note));
        }
        if !self.s3.is_empty() {
            out.push_str(&section("S3 operations (per op-class):"));
            for r in &self.s3 {
                out.push_str(&fmt_row(&r.label, &r.value, r.mark, r.verdict, &r.note));
            }
        }
        if !self.tail.is_empty() {
            out.push_str(&section("tail latency (worst 5%):"));
            for r in &self.tail {
                out.push_str(&fmt_row(r.label, &r.value, r.mark, r.verdict, &r.note));
            }
        }
        if !self.path.is_empty() {
            out.push_str(&section("network path (advisory):"));
            for r in &self.path {
                out.push_str(&fmt_row(r.label, &r.value, r.mark, r.verdict, &r.note));
            }
        }
        if !self.timeseries.is_empty() {
            out.push_str(&section("in-flight over time (sampled):"));
            for r in &self.timeseries {
                out.push_str(&fmt_row(r.label, &r.value, r.mark, r.verdict, &r.note));
            }
        }

        let overall = self.overall_verdict();
        let vcol = match overall {
            Verdict::Attention => WARN,
            Verdict::Healthy { .. } => OK,
            _ => DIM,
        };
        out.push_str(&format!("\n  verdict: {}{}{}\n", c(vcol), overall.message(), c(OFF)));
        out.push_str(&self.judged_denominator_line(color));
        out
    }

    /// A compact, plain-language summary for non-technical users (`--brief`): a one-line
    /// verdict, and on ATTENTION the specific issues to look at with their remedies. The full
    /// [`render`](Self::render) table stays the default; this hides the per-span detail but is
    /// derived from the same verdict + marks, so it never disagrees with the full report.
    #[must_use]
    pub fn render_brief(&self, color: bool) -> String {
        let c = ansi(color);

        // The ⚠ issues, across every section that can escalate the verdict (rows + reuse + the
        // S3-domain + tail rows — the same set `overall_verdict` consults). The note carries the
        // plain-language "why + remedy" already, so it doubles as the action line.
        let mut issues: Vec<(&str, &str)> = Vec::new();
        issues.extend(self.rows.iter().filter(|r| r.mark == Mark::Warn).map(|r| (r.label, r.note.as_str())));
        if let Some(r) = &self.reuse {
            if r.mark == Mark::Warn {
                issues.push((r.label, r.note.as_str()));
            }
        }
        issues.extend(self.s3.iter().filter(|r| r.mark == Mark::Warn).map(|r| (r.label.as_str(), r.note.as_str())));
        issues.extend(self.tail.iter().filter(|r| r.mark == Mark::Warn).map(|r| (r.label, r.note.as_str())));

        let overall = self.overall_verdict();
        let (glyph, col, headline) = match overall {
            Verdict::Healthy { reuse_working } => (
                "✓",
                OK,
                if reuse_working {
                    "Healthy — S3 latency tracks the network round-trip floor, and connection reuse is working."
                        .to_string()
                } else {
                    "Healthy — S3 latency tracks the network round-trip floor.".to_string()
                },
            ),
            Verdict::ChecksPassed => (
                "✓",
                DIM,
                "Checks passed — the absolute checks are clean; there were no latency spans to judge."
                    .to_string(),
            ),
            Verdict::Attention => (
                "⚠",
                WARN,
                format!(
                    "Attention — {} to look at:",
                    if issues.len() == 1 { "1 issue".to_string() } else { format!("{} issues", issues.len()) }
                ),
            ),
            Verdict::NoBaseline => (
                "?",
                DIM,
                "No baseline — couldn't measure a round-trip floor to judge latency against. Let a \
                 connection close in the window, or capture in-flight RTT samples, so there's a floor."
                    .to_string(),
            ),
            Verdict::MixedPaths => (
                "?",
                DIM,
                "Mixed paths — a round-trip floor was measured, but this capture spans more than \
                 one network path, so no single floor fits and nothing was judged against it. \
                 Scope the capture to one path, or read the per-connection view."
                    .to_string(),
            ),
            // Same "?" as NoBaseline: a missing denominator, not a health call. The brief report
            // is the one a non-technical reader acts on, so it must not open with a ✓ here.
            Verdict::NoOperations => (
                "?",
                DIM,
                "No operations — no S3 request was decoded, so nothing about S3 was judged (only \
                 the network path). Re-capture with --capture-plaintext, and the uprobe caps, to \
                 see operations."
                    .to_string(),
            ),
            // Same "?" and the same non-health stance as NoOperations, but a different remedy:
            // S3 WAS reached here, so re-capturing with the uprobe caps changes nothing.
            Verdict::NoResponses => (
                "?",
                DIM,
                "No responses — operations were decoded but none was ever answered (every request \
                 aborted in flight). Nothing about S3's behavior was observed either way."
                    .to_string(),
            ),
        };

        let mut out = format!("{}{} {}{}\n", c(col), glyph, headline, c(OFF));
        if overall == Verdict::Attention {
            for (label, note) in &issues {
                out.push_str(&format!("  {}•{} {}: {}{}{}\n", c(WARN), c(OFF), label, c(DIM), note, c(OFF)));
            }
        }
        out.push_str(&self.judged_denominator_line(color));
        out
    }

    /// The honesty tail: `(judged N of M operations)` — the denominator the
    /// verdict rests on. Shared by `render` + `render_brief` so the full and brief reports state
    /// the same numbers and can't drift apart.
    ///
    /// The denominator is NEVER suppressed, least of all when it is 0. Suppressing it was the
    /// "green because it saw nothing" failure: a Go/rustls client, or any capture taken without
    /// the uprobe caps, yields connection records and no operation records, and the resulting
    /// report was byte-identical to a real green apart from absent rows. A capture that judged
    /// 30 000 operations and one that judged none must not read the same.
    fn judged_denominator_line(&self, color: bool) -> String {
        let total = self.op_total();
        let c = ansi(color);
        if total == 0 {
            return format!(
                "  {}(0 operations in this capture: only the network path was judged, not any S3 \
                 request){}\n",
                c(DIM),
                c(OFF)
            );
        }
        format!("  {}(judged {} of {} operations){}\n", c(DIM), self.op_judged, total, c(OFF))
    }
}

// ============================================================================
// Baseline diff (`s3tap doctor --baseline <file>`): is the current capture worse
// than a reference one? Compares the two reports' checks and flags regressions.
// ============================================================================

/// How a single check changed between the baseline and the current capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaKind {
    /// Present in both, and the current value is meaningfully worse.
    Regressed,
    /// A warn that appeared only in the current capture (a new problem).
    NewIssue,
    /// Present in both, and the current value is meaningfully better.
    Improved,
    /// A warn present in the baseline that is gone now.
    Resolved,
    /// The baseline judged this check but the current capture can't (lost its RTT floor):
    /// a loss of signal, NOT a resolution — the gate must not read green.
    Unjudgeable,
    /// Present in both, within the noise band.
    Unchanged,
}

/// One check's baseline→current change. Latency checks compare the RTT-relative ratio
/// (not raw ms) so two captures under different network conditions are comparable.
#[derive(Debug, Clone, PartialEq)]
pub struct Delta {
    /// The source finding's stable `finding_id` (e.g. `"retransmit_rate"`), so a consumer
    /// can filter rows by identity rather than a brittle title-string match. Matched pairs
    /// share a `finding_id` (the diff keys on it), so it is well-defined on every kind.
    pub id: String,
    pub label: String,
    pub baseline: Option<f64>,
    pub current: Option<f64>,
    pub unit: Unit,
    /// The compared quantity is `ratio_to_rtt` (a multiple of the floor) vs an absolute.
    pub rtt_relative: bool,
    /// The check's severity — an `Advisory` delta (e.g. GET throughput) never fails the
    /// gate, mirroring `overall_verdict`'s "an Advisory never escalates" (needs `--strict`).
    pub severity: Severity,
    pub kind: DeltaKind,
}

/// The result of [`diff`]: per-check deltas + each side's overall verdict, plus a caveat
/// when the two captures are too dissimilar in size to compare.
#[derive(Debug, Clone, PartialEq)]
pub struct DiffReport {
    pub deltas: Vec<Delta>,
    pub baseline_verdict: Verdict,
    pub current_verdict: Verdict,
    pub caveat: Option<String>,
}

/// The quantity a finding DISPLAYS in a diff row: its RTT-relative ratio when it has one
/// (latency checks — comparable across captures), else its raw numeric value (counts,
/// throughput). See [`gate_value`] for the quantity actually JUDGED.
fn cmp_value(f: &Finding) -> Option<f64> {
    f.ratio_to_rtt.or(match &f.value {
        Some(MetricValue::Num(n)) => Some(*n),
        _ => None,
    })
}

/// The quantity a finding is JUDGED on in a diff — [`cmp_value`] normalized by its own
/// population for the RELIABILITY rows.
///
/// The status-mix / http-error rows carry a raw error COUNT ([`Unit::Count`]), and comparing
/// counts made the gate a function of workload SIZE: 100 baseline ops with 2× HTTP 500 (2.0%)
/// vs 400 current ops with 6× HTTP 500 (1.5%) is 6 > 2×1.25 with a delta of 4 ≥ 1, i.e.
/// "Regressed → exit 1" on a capture whose reliability IMPROVED. `comparability_caveat` does
/// not fire either (400 < 100×5), so nothing warned. That inverts the Core discipline: the only
/// thing reliability may gate on is an honest error RATE. Every such row already reports the
/// population it counted over (`sample.judged` = the ANSWERED ops, the only ones its numerator
/// can contain — see [`Report::finding`]), so divide by it. The raw counts stay in the rendered
/// delta: the operator wants "2 → 6 errors", judged as 2.0% → 1.5%.
///
/// `None` when there is no population to rate over (a capture where no op was answered), which reads as
/// "not comparable" rather than a fabricated 0% — the same honesty corollary as a missing floor.
fn gate_value(f: &Finding) -> Option<f64> {
    let raw = cmp_value(f)?;
    if !is_status_mix(&f.finding_id) {
        return Some(raw);
    }
    let ops = f.sample.judged;
    (ops > 0).then(|| raw / ops as f64)
}

/// The minimum absolute change worth flagging, so tiny wiggles aren't "regressions": half
/// an RTT for a ratio, one for a count, an absolute noise floor for raw rates/durations.
///
/// Absolute-valued lower-is-better metrics (a retransmit_rate, or any raw ms duration with
/// no RTT-relative ratio) previously fell through to a 0.0 floor, leaving only the ±25%
/// relative band. Off a near-zero baseline that band collapses (0 × 1.25 == 0), so a
/// single spurious retransmit or a few ms of jitter — well within the check's own
/// "clean" envelope — false-reddened `--baseline`. Give them a real floor keyed to the
/// metric's healthy threshold.
fn min_delta(f: &Finding) -> f64 {
    if is_status_mix(&f.finding_id) {
        // Compared as a RATE ([`gate_value`]), so the floor must be in rate units too: one
        // more failing op at THIS capture's population — the smallest movement the capture can
        // actually represent. (The `Unit::Count` arm below would be 1.0, i.e. a 100-point rate
        // swing, and would silence every real reliability regression.)
        1.0 / f.sample.judged.max(1) as f64
    } else if f.ratio_to_rtt.is_some() {
        0.5
    } else if f.unit == Unit::Count {
        1.0
    } else if f.unit == Unit::Ratio {
        // e.g. retransmit_rate — its own "no real loss" threshold.
        RTX_RATE_MAX
    } else if f.unit == Unit::Ms {
        // a raw duration with no floor to normalize it — a few ms of jitter is noise,
        // not a regression.
        DIFF_MS_NOISE_FLOOR
    } else {
        0.0
    }
}

/// Worsening rank of an overall verdict (higher = worse) so a verdict regression counts.
fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Healthy { .. } | Verdict::ChecksPassed => 0,
        // A lost signal, not a health change: same rank as a lost floor. A baseline that
        // judged operations against a current capture that judged none IS a regression of the
        // gate's evidence, and ranking it above 0 is what makes the diff say so.
        Verdict::NoBaseline
        | Verdict::NoOperations
        | Verdict::NoResponses
        | Verdict::MixedPaths => 1,
        Verdict::Attention => 2,
    }
}

/// A current value above `baseline * REGRESS_FACTOR` (+25%) is the regression band; below
/// `baseline * IMPROVE_FACTOR` (−25%) is the improvement band. Between them is run-to-run
/// noise. (The two directions swap meaning for higher-is-better metrics — see [`diff`].)
const REGRESS_FACTOR: f64 = 1.25;
const IMPROVE_FACTOR: f64 = 0.75;

/// Absolute noise floor for raw (non-RTT-relative) millisecond durations in [`min_delta`]:
/// changes under a few ms are run-to-run jitter, not a regression.
const DIFF_MS_NOISE_FLOOR: f64 = 5.0;

/// Compare a current capture against a baseline: per-check deltas
/// flagging regressions. Checks are matched by `(finding_id, scope.s3_op)`; latency
/// checks compare the RTT-relative ratio so different network conditions don't masquerade
/// as a change. The run roll-up is compared as the overall verdict, not a per-check row.
#[must_use]
pub fn diff(current: &Report, baseline: &Report) -> DiffReport {
    use std::collections::{HashMap, HashSet};
    let cur = current.findings();
    let base = baseline.findings();
    let key = |f: &Finding| format!("{}|{}", f.finding_id, f.scope.s3_op.as_deref().unwrap_or(""));
    // The current side keeps Unjudged rows (so a lost floor is detected, not silently
    // dropped → false "Resolved"); the run roll-up is compared as the overall verdict.
    let is_cur = |f: &&Finding| f.finding_id != "run";
    // A baseline reference must itself be JUDGED — an Unjudged baseline row (e.g. the RTT
    // floor, or a no-floor span) is not a comparison anchor.
    let is_ref = |f: &&Finding| f.finding_id != "run" && f.severity != Severity::Unjudged;

    let base_map: HashMap<String, &Finding> =
        base.iter().filter(is_ref).map(|f| (key(f), f)).collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut deltas = Vec::new();

    for f in cur.iter().filter(is_cur) {
        let k = key(f);
        seen.insert(k.clone());
        match base_map.get(&k) {
            // The baseline judged this check but the current capture can't (no floor, or a
            // healthy class fell below the min-sample gate). Gate it (Unjudgeable, never a green
            // "Resolved") ONLY when the baseline was a watched WARN we can no
            // longer confirm is fixed; a lost healthy/advisory row is not a regression, else
            // `--baseline` reddens on benign workload shrinkage. Current carries no comparable
            // value, so this never falls through to the value/ratio comparison below.
            Some(b) if f.severity == Severity::Unjudged => {
                let lost_watched_warn = b.severity == Severity::Warn;
                deltas.push(Delta {
                    id: f.finding_id.clone(),
                    label: f.title.clone(),
                    baseline: cmp_value(b),
                    current: None,
                    unit: f.unit,
                    rtt_relative: b.ratio_to_rtt.is_some(),
                    severity: b.severity,
                    kind: if lost_watched_warn { DeltaKind::Unjudgeable } else { DeltaKind::Unchanged },
                });
            }
            Some(b) => {
                // Two quantities, deliberately: `bv`/`cv` are DISPLAYED (raw counts, ms, MB/s),
                // while the comparison runs on `gate_value` — identical except for the
                // reliability counts, which are judged as rates over their own populations.
                let (bv, mut cv) = (cmp_value(b), cmp_value(f));
                let kind = match (gate_value(b), gate_value(f)) {
                    // The baseline row was judgeable and the current one is not — a LOSS OF
                    // SIGNAL, the case this file gates on everywhere else, and it fell through to
                    // `Unchanged` here. Baseline 100 answered ops with 20 × 503 (a Warn) against a
                    // current capture of 100 ops none of which was answered rendered
                    // "HTTP errors 20 → 0 · unchanged": a green row asserting the errors went away
                    // on a capture that could not judge them, whose exit code survived only
                    // because a sibling row happened to gate. Drop the current VALUE too — a raw
                    // count that could not be rated is not a comparison point.
                    //
                    // Today the reliability rows reach the sibling Unjudged arm above first: a
                    // capture with no answered op renders `http_errors` `Mark::Na`. This arm is
                    // the STRUCTURAL guard — `gate_value` returning None is the definition of
                    // "cannot judge", and it must never mean "unchanged" whatever row hits it.
                    (Some(_), None) => {
                        cv = None;
                        DeltaKind::Unjudgeable
                    }
                    (Some(b), Some(c)) => {
                        // throughput (bytes/s) and reuse rate are HIGHER-is-better; every
                        // other metric (latency ratios, error counts, retransmit) is lower.
                        let higher_better = f.unit == Unit::BytesPerS || f.metric == "reuse_rate";
                        // A metric must move past ±25% (and, for lower-is-better, by an absolute
                        // min_delta) before it counts as a change rather than run-to-run noise.
                        let worse = b * REGRESS_FACTOR;
                        let better = b * IMPROVE_FACTOR;
                        if higher_better {
                            if c < better {
                                DeltaKind::Regressed
                            } else if c > worse {
                                DeltaKind::Improved
                            } else {
                                DeltaKind::Unchanged
                            }
                        } else if c > worse && (c - b) >= min_delta(f) {
                            DeltaKind::Regressed
                        } else if c < better && (b - c) >= min_delta(f) {
                            DeltaKind::Improved
                        } else {
                            DeltaKind::Unchanged
                        }
                    }
                    _ => DeltaKind::Unchanged,
                };
                deltas.push(Delta {
                    id: f.finding_id.clone(),
                    label: f.title.clone(),
                    baseline: bv,
                    current: cv,
                    unit: f.unit,
                    rtt_relative: f.ratio_to_rtt.is_some(),
                    severity: f.severity,
                    kind,
                });
            }
            // A warn present only in the current capture — a new problem. (A new healthy
            // or advisory check appearing is not an issue.)
            None if f.severity == Severity::Warn => deltas.push(Delta {
                id: f.finding_id.clone(),
                label: f.title.clone(),
                baseline: None,
                current: cmp_value(f),
                unit: f.unit,
                rtt_relative: f.ratio_to_rtt.is_some(),
                severity: f.severity,
                kind: DeltaKind::NewIssue,
            }),
            None => {}
        }
    }
    // A baseline Warn whose row is gone from the current capture. This is a true "Resolved"
    // only when the current capture had the DATA to re-judge the check and it came back clean;
    // if the row vanished because the capture fell below a min-sample gate, that's loss of
    // signal and must gate as Unjudgeable, never read green — else an unseeable
    // regression reports as fixed and `--baseline` passes.
    //
    // The re-judge population must be measured in the SAME population the baseline row's own
    // `sample.judged` counts, or the two sides aren't comparable. The reliability rows count over
    // the ANSWERED ops (`op_statused`); every other row that can reach here (latency, reuse) is
    // judged over the TIMEABLE subset (`op_judged`). Testing a status-mix row's denominator against
    // `op_judged` compared two different populations: the bar sat above `op_judged` by exactly
    // the baseline's error + partial count, so it ROSE with the number of errors in the baseline
    // — backwards — and a genuinely FIXED capture (4 baseline ops, 2 of them 403 ⇒ bar 4, vs
    // `op_judged` 3) reported as "unjudgeable (population shrank)" and gated.
    //
    // Still a GENEROUS upper bound for the per-`s3_op` class rows, which can false-Resolve a
    // lost sub-population (an all-PutObject current capture hides a vanished GetObject class).
    // Closing that needs a per-class count on Report, which nothing else wants yet.
    //
    // The TAIL rows DO have one and it is consulted below. A previous revision removed that
    // branch as "dead code", reasoning that a tail row losing its floor re-emits as an `Na`
    // row and so lands in `seen` where this loop cannot reach it. That premise is true and the
    // conclusion does not follow: a tail row has a SECOND way to vanish. When its
    // sub-population falls below `MIN_TAIL_SAMPLE`, `tail_rows` `continue`s BEFORE the `Na`
    // branch, so the row is genuinely absent from the current findings, reaches this loop, and
    // gets answered with `op_judged` — a count drawn from a different population entirely. A
    // capture whose new-connection tail regressed 10x while its new-conn count slipped to 19
    // (with 100 fast reused ops holding `op_judged` at 119) reported `✓ resolved` and exit 0.
    //
    // Absence of a `row_pop` entry IS the signal, so it maps to 0 rather than falling through.
    //
    // (Only op-based checks reach here anyway: the loop drops Unjudged + non-Warn, so the
    // conn/stream-populationed rows — all Mark::Fyi → Unjudged — can never be the vanished Warn.)
    let cur_pop = |b: &Finding| {
        if is_status_mix(&b.finding_id) {
            // The ANSWERED ops — the same population the baseline row's `sample.judged` now
            // counts. Against `op_total()` a capture in which NOTHING was answered (every op
            // aborted in flight, routine at SIGINT since `flush_open_ops`) cleared the bar on
            // op count alone, so a baseline reliability ⚠ was reported RESOLVED and the run
            // printed NO REGRESSION at exit 0 while the check was in fact unjudgeable.
            current.op_statused
        } else if is_reuse_rate(&b.finding_id) {
            // The non-partial ops, the population `reuse_row` counts. Against `op_total()` a
            // current capture could clear the bar on partial ops the check never counted, so
            // a reuse warn that VANISHED for want of samples reported as `resolved` and the
            // gate passed — the loss-of-signal hole this whole block exists to close.
            current.op_nonpartial
        } else if is_row_populationed(&b.finding_id) {
            // The FLOORED subset this tail row's percentile was taken over. NO entry means the
            // row was not produced at all this run — its sub-population fell below the sample
            // floor — which is a population of 0, not a licence to substitute `op_judged`.
            current
                .row_pop
                .iter()
                .find(|(i, _, _)| *i == b.finding_id)
                .map_or(0, |&(_, judged, _)| judged)
        } else if b.finding_id == "s3_ttfb" {
            // THIS class's population, matched on the finding's scope. `s3_ttfb` is one id per
            // class, so `row_pop` cannot hold it — but `S3Row::population` can, and does since
            // the per-class sweep. Without this an all-PutObject current capture answered with
            // `op_judged` and reported a vanished GetObject ⚠ as `✓ resolved` at exit 0. An
            // absent class means population 0, the same rule the tails follow.
            current
                .s3
                .iter()
                .find(|r| r.id == "s3_ttfb" && r.s3_op == b.scope.s3_op)
                .and_then(|r| r.population)
                .map_or(0, |(judged, _)| judged)
        } else {
            current.op_judged
        }
    };
    for b in base.iter().filter(is_ref) {
        if !seen.contains(&key(b)) && b.severity == Severity::Warn {
            let kind = if cur_pop(b) >= b.sample.judged {
                DeltaKind::Resolved
            } else {
                DeltaKind::Unjudgeable
            };
            deltas.push(Delta {
                id: b.finding_id.clone(),
                label: b.title.clone(),
                baseline: cmp_value(b),
                current: None,
                unit: b.unit,
                rtt_relative: b.ratio_to_rtt.is_some(),
                severity: b.severity,
                kind,
            });
        }
    }
    // Worst first.
    deltas.sort_by_key(|d| match d.kind {
        DeltaKind::NewIssue => 0,
        DeltaKind::Regressed => 1,
        DeltaKind::Unjudgeable => 2,
        DeltaKind::Improved => 3,
        DeltaKind::Resolved => 4,
        DeltaKind::Unchanged => 5,
    });
    DiffReport {
        deltas,
        baseline_verdict: baseline.overall_verdict(),
        current_verdict: current.overall_verdict(),
        caveat: comparability_caveat(current, baseline),
    }
}

/// A caveat when the two captures are too different in size to compare fairly
///: the smaller has under a fifth of the larger's ops.
fn comparability_caveat(current: &Report, baseline: &Report) -> Option<String> {
    let cur = current.op_judged + current.op_excluded;
    let base = baseline.op_judged + baseline.op_excluded;
    let (lo, hi) = (cur.min(base), cur.max(base));
    (lo > 0 && hi >= lo * 5).then(|| {
        format!(
            "dissimilar workloads ({cur} current vs {base} baseline ops) — the diff may not be comparable"
        )
    })
}

impl DiffReport {
    /// True when the current capture is worse than the baseline — a new issue, a non-
    /// advisory regression, a lost-signal (judged→unjudgeable) check, or a worsened overall
    /// verdict. Drives the `--baseline` exit code. An `Advisory` regression (e.g. GET
    /// throughput) never gates, mirroring `overall_verdict` (it needs `--strict`).
    #[must_use]
    pub fn regressed(&self) -> bool {
        self.regressed_with(false)
    }

    /// Like [`regressed`](Self::regressed) but `strict` also counts an `Advisory`
    /// regression (e.g. a GET-throughput drop) as a gate failure.
    #[must_use]
    pub fn regressed_with(&self, strict: bool) -> bool {
        self.deltas.iter().any(|d| match d.kind {
            DeltaKind::Regressed => strict || d.severity != Severity::Advisory,
            DeltaKind::NewIssue | DeltaKind::Unjudgeable => true,
            _ => false,
        }) || verdict_rank(self.current_verdict) > verdict_rank(self.baseline_verdict)
    }

    /// Render the diff as a human table (baseline → current per check, worst first).
    #[must_use]
    pub fn render(&self, color: bool) -> String {
        let c = ansi(color);
        let fmt = |v: Option<f64>, unit: Unit, rtt_relative: bool| -> String {
            match v {
                None => "—".to_string(),
                Some(x) if rtt_relative => format!("{x:.1}×RTT"),
                Some(x) => match unit {
                    Unit::BytesPerS => format!("{:.1} MB/s", x / 1e6),
                    Unit::Count => format!("{x:.0}"),
                    Unit::Ms => format!("{x:.1} ms"),
                    Unit::Ratio => format!("{:.2}%", x * 100.0), // e.g. retransmit rate
                    _ => format!("{x:.1}"),
                },
            }
        };

        let mut out = String::new();
        out.push_str(&format!(
            "  {dim}baseline → current{off}  ({base} → {cur}){nl}",
            dim = c(DIM),
            off = c(OFF),
            base = self.baseline_verdict.keyword(),
            cur = self.current_verdict.keyword(),
            nl = "\n",
        ));
        if let Some(caveat) = &self.caveat {
            out.push_str(&format!("  {}⚠ {}{}\n", c(WARN), caveat, c(OFF)));
        }
        let wlab = self.deltas.iter().map(|d| d.label.chars().count()).max().unwrap_or(0);
        for d in &self.deltas {
            let (glyph, col, word) = match d.kind {
                // an advisory regression is shown dim/informational — it doesn't gate.
                DeltaKind::Regressed if d.severity == Severity::Advisory => ("·", DIM, "regressed (advisory)"),
                DeltaKind::Regressed => ("⚠", WARN, "regressed"),
                DeltaKind::NewIssue => ("⚠", WARN, "new"),
                DeltaKind::Unjudgeable => ("⚠", WARN, "unjudgeable (population shrank)"),
                DeltaKind::Improved => ("✓", OK, "improved"),
                DeltaKind::Resolved => ("✓", OK, "resolved"),
                DeltaKind::Unchanged => ("·", DIM, "unchanged"),
            };
            out.push_str(&format!(
                "  {label:<wlab$}  {b:>10} → {cur:>10}  {mc}{glyph} {word}{off}\n",
                label = d.label,
                b = fmt(d.baseline, d.unit, d.rtt_relative),
                cur = fmt(d.current, d.unit, d.rtt_relative),
                mc = c(col),
                off = c(OFF),
            ));
        }
        let regressed = self.regressed();
        let (vcol, verdict) = if regressed {
            (WARN, "REGRESSED — the current capture is worse than the baseline")
        } else {
            (OK, "NO REGRESSION — the current capture holds up against the baseline")
        };
        out.push_str(&format!("\n  verdict: {}{}{}\n", c(vcol), verdict, c(OFF)));
        out
    }
}

// ============================================================================
// Cost estimate (`s3tap doctor --cost`): attribute approximate
// request $ to the capture, per op-class. Informational — never gates.
// ============================================================================

/// One op-class's request cost: how many calls, which pricing tier, and the $ total.
#[derive(Debug, Clone, PartialEq)]
pub struct CostLine {
    pub s3_op: String,
    pub count: usize,
    pub tier: &'static str,
    pub usd: f64,
}

/// An approximate request-cost breakdown for a capture. Request pricing only — data
/// egress depends on the destination (free in-region) and is reported, not priced.
#[derive(Debug, Clone, PartialEq)]
pub struct CostReport {
    pub lines: Vec<CostLine>,
    pub request_usd: f64,
    pub gib_returned: f64,
    /// 2xx GETs whose body never completed, so their declared `content_length` is NOT in
    /// `gib_returned`. Excluding them is right — a declared length is not a transferred body —
    /// but a reader has to be told, or a capture that truncated every download reads as a
    /// measured zero rather than as an unmeasured one.
    pub unmeasured_gets: usize,
    /// Priced requests whose HTTP status was a 4xx/5xx error. AWS bills these variably (a 404
    /// GET is charged, a 403 is not, most 5xx are not), so the flat per-request estimate is an
    /// UPPER BOUND on the real charge — surfaced as a caveat rather than guessed at.
    /// 3xx (304/redirects) are normal billed requests, so excluded.
    pub error_requests: usize,
    /// Every `s3tap.operation/1` record the capture held, priced or not. The denominator that
    /// separates "the capture measured no cost" from "the capture could not measure a cost":
    /// a connection-only capture (a Go/rustls client, or one taken without the uprobe caps)
    /// decodes no operation at all, and its `$0.000000` is the ABSENCE of a measurement rather
    /// than a measured zero. [`CostReport::render`] refuses to print the total when this is 0.
    pub operations: usize,
}

/// The AWS S3 Standard request tier + $/1,000 for an op-class (us-east-1 list prices,
/// ~2024 — an ESTIMATE, not billing). Tier-1 = PUT/COPY/POST/LIST; Tier-2 = GET/SELECT/
/// HEAD/other; DELETE/Abort are free.
fn request_tier(s3_op: &str) -> (&'static str, f64) {
    const TIER1: f64 = 0.005; // per 1,000
    const TIER2: f64 = 0.0004; // per 1,000
    let starts = |p: &str| s3_op.starts_with(p);
    if starts("Delete") || starts("Abort") {
        ("free", 0.0)
    } else if starts("Put")
        || starts("Post")
        || starts("Copy")
        || starts("List")
        || starts("Create")
        || starts("Upload")
        || starts("Complete")
    {
        ("tier-1", TIER1)
    } else {
        ("tier-2", TIER2)
    }
}

/// A 4xx/5xx HTTP error — one AWS may not bill (a 404 GET is charged, a 403 is not, most 5xx
/// aren't). A missing status is unknown (not an error); 3xx is a normal billed request. The
/// complement of [`is_2xx`] except on the 3xx band, which is neither an error nor a 2xx success,
/// and on a MISSING status, which is neither.
fn is_http_error(status: Option<u16>) -> bool {
    status.is_some_and(|s| s >= 400)
}
/// A PRESENT 2xx status. A missing status is `false`: an op nobody answered is not a success,
/// and treating it as one is how an unanswered GET's declared `content_length` used to be
/// tallied as bytes that came back.
fn is_2xx(status: Option<u16>) -> bool {
    status.is_some_and(|s| (200..300).contains(&s))
}

/// Estimate the request cost of a capture, grouped by op-class.
/// Op-class names are sanitized (they reach a tty). Data bytes returned are tallied but
/// NOT priced (egress is destination-dependent — free in-region).
#[must_use]
pub fn cost(records: &[Record]) -> CostReport {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut bytes: u64 = 0;
    let mut error_requests: usize = 0;
    let mut operations: usize = 0;
    let mut unmeasured_gets: usize = 0;
    for r in records {
        if let Record::Operation(o) = r {
            operations += 1;
            if let Some(op) = o.s3_op.as_deref() {
                *counts.entry(s3tap_schema::sanitize_term(op)).or_default() += 1;
                // Count 4xx/5xx among the PRICED requests (those with an s3_op) so the caveat
                // matches the request total.
                if is_http_error(o.http_status) {
                    error_requests += 1;
                }
            }
            // "Data returned" approximates transfer, so count content_length only for a
            // SUCCESSFUL GET body (it's the GET download size; don't
            // bill 4xx like 2xx). A HEAD declares the full size with no body transferred,
            // and LIST/PUT bodies aren't a downloaded object — exclude both.
            //
            // `download_ns` is the third condition and the one that makes this a MEASUREMENT
            // rather than a declaration. `content_length` is what the response header CLAIMED,
            // so a 2xx GET whose body never finished (a Ctrl-C mid-transfer, a reset, a capture
            // that ended first) carries the full declared size with `download_ns: None` — see
            // the field's contract in s3tap-schema. Counting those tallied bytes that never
            // arrived, and a 1 GiB object aborted after 4 KiB read as a full gibibyte returned.
            let is_get = o.s3_op.as_deref().is_some_and(|s| s.starts_with("Get"))
                || o.verb.as_deref() == Some("GET");
            if is_get && is_2xx(o.http_status) {
                // `download_ns: None` alone is NOT "the body never finished". The schema is
                // explicit that it pairs with `content_length` and the two combinations mean
                // opposite things: `(None, Some(n))` is a declared length whose transfer never
                // completed, and `(None, None)` is the normal healthy shape of a CHUNKED
                // response — which is every S3 LIST. Counting the latter made `--cost` tell
                // essentially every real capture that its ListObjectsV2 calls "had no
                // completed body", which is the same state-a-construction-as-a-measurement
                // failure this note was added to remove.
                if o.download_ns.is_some() {
                    bytes = bytes.saturating_add(o.content_length.unwrap_or(0));
                } else if o.content_length.is_some() {
                    // Excluded from the tally and COUNTED, so the figure can say so. Suppressing
                    // these bytes was right; printing the resulting "0.000 GiB" unqualified was
                    // not. 50 successful GETs of a 1 GiB object each, every body cut off by
                    // capture end, read as a measured zero — the same silence-as-measurement
                    // shape the `operations == 0` refusal exists to stop, one line down.
                    unmeasured_gets += 1;
                }
            }
        }
    }
    let mut lines = Vec::new();
    let mut request_usd = 0.0;
    for (s3_op, count) in counts {
        let (tier, per_1k) = request_tier(&s3_op);
        let usd = count as f64 / 1000.0 * per_1k;
        request_usd += usd;
        lines.push(CostLine { s3_op, count, tier, usd });
    }
    CostReport {
        lines,
        request_usd,
        gib_returned: bytes as f64 / (1u64 << 30) as f64,
        error_requests,
        operations,
        unmeasured_gets,
    }
}

impl CostReport {
    /// Render the cost estimate as a human table.
    #[must_use]
    pub fn render(&self, color: bool) -> String {
        let c = ansi(color);
        let mut out = String::new();
        out.push_str(&format!(
            "  {}estimated S3 request cost (AWS Standard us-east-1 list prices — estimate){}\n",
            c(DIM),
            c(OFF),
        ));
        // Nothing to price, and the two ways of getting here are NOT the same claim. Say which,
        // and print no total either way: a `$0.000000` line is a measured figure everywhere else
        // in this table, so rendering one over an absent population states as a result what is
        // really the absence of one. The `--cost` exit stays 0 (it is informational and never
        // gates), which is exactly why the text has to carry the caveat on its own.
        if self.operations == 0 {
            out.push_str(&format!(
                "  {dim}no S3 operation records decoded, so request cost is unknown{off}\n  \
                 {dim}(a connection-only capture: re-capture with `--capture-plaintext` and the \
                 uprobe caps){off}\n",
                dim = c(DIM),
                off = c(OFF),
            ));
            return out;
        }
        if self.lines.is_empty() {
            // The REQUEST cost is unknown here, but "data returned" may be a real measurement:
            // the byte tally admits a GET recognised by its verb alone, which is exactly the
            // shape an unrecognised S3-compatible endpoint produces (no `s3_op`, `verb: GET`).
            // Returning early discarded it, so whether a measured figure appeared depended on
            // an unrelated priced op being present in the same capture.
            out.push_str(&format!(
                "  {dim}{n} operation{s} decoded but none carried an S3 op-class, so request \
                 cost is unknown (for an S3-compatible endpoint, re-capture with \
                 `--s3-endpoint <host>`){off}\n",
                dim = c(DIM),
                off = c(OFF),
                n = self.operations,
                s = if self.operations == 1 { "" } else { "s" },
            ));
            if self.gib_returned > 0.0 {
                out.push_str(&format!(
                    "  {dim}data returned:{off} {gib:.3} GiB {dim}(measured from the GET bodies \
                     that did complete){off}\n",
                    dim = c(DIM),
                    off = c(OFF),
                    gib = self.gib_returned,
                ));
            }
            if self.unmeasured_gets > 0 {
                out.push_str(&format!(
                    "  {dim}note:{off} {n} successful GET(s) had no completed body, so no \
                     transfer figure can be drawn from them.\n",
                    dim = c(DIM),
                    off = c(OFF),
                    n = self.unmeasured_gets,
                ));
            }
            return out;
        }
        let wlab = self.lines.iter().map(|l| l.s3_op.chars().count()).max().unwrap_or(0).max(5);
        for l in &self.lines {
            out.push_str(&format!(
                "  {op:<wlab$} {count:>7} {tier:>8}  ${usd:>9.6}\n",
                op = l.s3_op,
                count = l.count,
                tier = l.tier,
                usd = l.usd,
            ));
        }
        out.push_str(&format!(
            "\n  {dim}requests:{off} ${req:.6}   {dim}data returned:{off} {gib:.3} GiB \
             {dim}(egress $ depends on destination — free in-region — not included){off}\n",
            dim = c(DIM),
            off = c(OFF),
            req = self.request_usd,
            gib = self.gib_returned,
        ));
        if self.unmeasured_gets > 0 {
            out.push_str(&format!(
                "  {dim}note:{off} {n} successful GET(s) had no completed body, so their \
                 declared size is NOT in that figure — the bytes actually moved are higher \
                 by an unknown amount.\n",
                dim = c(DIM),
                off = c(OFF),
                n = self.unmeasured_gets,
            ));
        }
        // Status-mix caveat: the flat per-request price counts every op, but AWS bills 4xx/5xx
        // variably (a 404 GET is charged, a 403 is not, most 5xx aren't), so the estimate is an
        // upper bound — it may over-count. (3xx are normal billed requests, not flagged.)
        if self.error_requests > 0 {
            out.push_str(&format!(
                "  {dim}(includes {n} 4xx/5xx request{s} — AWS doesn't bill some of these \
                 (e.g. 403, most 5xx), so this may over-count){off}\n",
                dim = c(DIM),
                off = c(OFF),
                n = self.error_requests,
                s = if self.error_requests == 1 { "" } else { "s" },
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3tap_schema::{
        Connection, Delimitation, Dns, Domain, Endpoint, Finding, MetricValue, Operation, Severity,
        Unit,
    };

    fn op(ttfb_ms: u64, tcp_ms: u64, reused: bool, status: u16, partial: bool) -> Record {
        Record::Operation(Operation {
            http_status: Some(status),
            partial,
            connection_reused: reused,
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            tcp_connect_ns: Some(tcp_ms * 1_000_000),
            ..Default::default()
        })
    }
    fn conn(srtt_us: Option<u32>, retransmits: u32, bytes_sent: u64) -> Record {
        Record::Connection(Connection { srtt_us, retransmits, bytes_sent, ..Default::default() })
    }

    // A region-tagged connection joined by `cookie`, carrying `srtt_us` (µs) as its floor —
    // the shape the sock_cookie-join tests need (the plain `conn` helper carries neither a
    // cookie nor a region).
    fn conn_in_region(cookie: u64, srtt_us: u32, region: &str) -> Record {
        Record::Connection(Connection {
            sock_cookie: cookie,
            srtt_us: Some(srtt_us),
            endpoint: Endpoint { region: Some(region.into()), ..Default::default() },
            bytes_sent: 1_000_000,
            ..Default::default()
        })
    }

    // A 200 op joined to `cookie`, in op-class `class`, with the given TTFB (ms).
    fn s3op_on(cookie: u64, class: &str, ttfb_ms: u64) -> Record {
        Record::Operation(Operation {
            sock_cookie: cookie,
            s3_op: Some(class.into()),
            http_status: Some(200),
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            ..Default::default()
        })
    }

    fn warns(r: &Report) -> Vec<&str> {
        r.rows.iter().filter(|x| x.mark == Mark::Warn).map(|x| x.id).collect()
    }

    #[test]
    fn median_matches_python_even_and_odd() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![3.0]), Some(3.0));
        assert_eq!(median(vec![1.0, 3.0, 2.0]), Some(2.0)); // odd -> middle
        assert_eq!(median(vec![1.0, 2.0, 3.0, 4.0]), Some(2.5)); // even -> mean of middles
    }

    #[test]
    fn healthy_capture_is_healthy_with_reuse() {
        // srtt 17ms floor; tcp 1.0xRTT; ttfb new 1.8x, reused 2.0x -> all ok.
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            op(30, 17, false, 200, false),
            op(34, 17, true, 200, false),
        ];
        let r = analyze(&recs);
        assert!(warns(&r).is_empty(), "no warnings: {:?}", warns(&r));
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: true });
    }

    #[test]
    fn no_srtt_floor_is_no_baseline_never_false_healthy() {
        // ops present (latency spans exist) but no srtt anywhere -> latency rows n/a.
        let recs = vec![op(30, 17, false, 200, false)];
        let r = analyze(&recs);
        assert_eq!(r.verdict, Verdict::NoBaseline);
        // the TCP/TTFB rows are Na, not Ok.
        for id in ["tcp_connect", "ttfb_new"] {
            let row = r.rows.iter().find(|x| x.id == id).unwrap();
            assert_eq!(row.mark, Mark::Na, "{id} must be n/a without a floor");
        }
    }

    #[test]
    fn all_partial_ops_with_srtt_is_checks_passed() {
        // srtt present (from the conn) but every op partial -> no latency span judged.
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, true)];
        let r = analyze(&recs);
        assert_eq!(r.verdict, Verdict::ChecksPassed);
    }

    #[test]
    fn an_http_error_raises_attention() {
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 500, false)];
        let r = analyze(&recs);
        assert_eq!(warns(&r), vec!["http_errors"]);
        assert_eq!(r.verdict, Verdict::Attention);
    }

    #[test]
    fn high_ttfb_relative_to_floor_warns() {
        // ttfb 200ms over a 17ms floor = 11.8xRTT (> 4x) -> warn.
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(200, 17, false, 200, false)];
        let r = analyze(&recs);
        assert_eq!(warns(&r), vec!["ttfb_new"]);
        assert_eq!(r.verdict, Verdict::Attention);
    }

    #[test]
    fn retransmits_over_segments_warn_as_a_rate() {
        // 50 retransmits over ~684 segments (1 MB) is 7.3% -> loss. The denominator has to
        // clear MIN_RATE_SEGMENTS for the row to be rated at all (see
        // `a_tiny_send_leg_cannot_rate_loss`), so this fixture sends a real megabyte.
        let recs = vec![conn(Some(17_000), 50, 1_000_000), op(30, 17, false, 200, false)];
        let r = analyze(&recs);
        // Pin the EXACT warn set (not just `.contains`) so a regression that spuriously
        // adds a tcp_connect/ttfb warn here would also fail this test.
        assert_eq!(warns(&r), vec!["retransmit_rate"]);
    }

    #[test]
    fn a_tiny_send_leg_cannot_rate_loss() {
        // The DEFAULT `doctor --live --requests 12` GET run: one keep-alive connection whose
        // send leg is request headers only (~15 KB ≈ 10 segments) and ONE retransmit — a SYN
        // retransmit or a tail-loss probe, both routine on a healthy path. Rated over 10
        // segments that is 10.00%, which blew past the 0.1% tolerance and printed
        // "⚠ loss — the path dropped packets" + exit 1 on a clean capture. Below
        // MIN_RATE_SEGMENTS the row must be n/a, exactly like the no-bytes-at-all branch.
        let recs = vec![conn(Some(17_000), 1, 15_000), op(30, 17, false, 200, false)];
        let r = analyze(&recs);
        let row = r.rows.iter().find(|x| x.id == "retransmit_rate").expect("row present");
        assert_eq!(row.mark, Mark::Na, "~10 segments cannot rate loss: {}", r.render(false));
        assert!(row.note.contains("too few send-side segments to rate loss"), "{}", row.note);
        assert!(row.metric.value.is_none(), "no rate is published either: {:?}", row.metric.value);
        assert!(!warns(&r).contains(&"retransmit_rate"), "must not warn 'loss'");
        assert_ne!(r.overall_verdict(), Verdict::Attention, "{}", r.render(false));
        // …and the finding is Unjudged, so a --strict CI gate can't be tripped by it either.
        let f = r.findings().into_iter().find(|f| f.finding_id == "retransmit_rate").unwrap();
        assert_eq!(f.severity, Severity::Unjudged);

        // The boundary in the other direction: exactly MIN_RATE_SEGMENTS of send-side data is a
        // real denominator, so the same single retransmit IS rated (and 1/44 = 2.3% is loss).
        // Pins that the floor gates the row rather than silencing the check.
        let at_floor =
            vec![conn(Some(17_000), 1, MIN_RATE_SEGMENTS * TCP_MSS_BYTES), op(30, 17, false, 200, false)];
        let r2 = analyze(&at_floor);
        let row2 = r2.rows.iter().find(|x| x.id == "retransmit_rate").expect("row present");
        assert_eq!(row2.mark, Mark::Warn, "at the floor the rate is judged: {}", r2.render(false));
    }

    #[test]
    fn persistent_pool_retransmits_without_send_bytes_is_na_not_a_false_loss() {
        // The bug the sampled-RTT-floor feature exposed: a persistent pool that closes NO
        // connection has no close-time bytes_sent, so `segs` used to fall to max(0,1)=1 and any
        // stray op-level retransmit (a CUMULATIVE per-connection counter) divided
        // by that 1-segment fiction read as a ~huge rate => a spurious ATTENTION "loss".
        // A sample supplies the RTT floor (so we're judged, not NO BASELINE) but carries no
        // bytes_sent, so there is no honest send denominator: the row must be n/a, not loss.
        let floor = Record::TcpSample(TcpSample {
            sock_cookie: 1,
            min_rtt_us: Some(900),
            ..Default::default()
        });
        let mut recs = vec![floor];
        recs.extend((0..4).map(|_| {
            Record::Operation(Operation {
                http_status: Some(200),
                ttfb_ns: Some(2_000_000),
                connection_reused: true,
                retransmits: 7, // cumulative per-conn; would blow up a segs=1 denominator
                ..Default::default()
            })
        }));
        let r = analyze(&recs);
        let row = r.rows.iter().find(|x| x.id == "retransmit_rate").expect("row present");
        assert_eq!(row.mark, Mark::Na, "no send denominator => n/a, not a rate: {}", r.render(false));
        assert!(!warns(&r).contains(&"retransmit_rate"), "must not warn 'loss'");
        assert_ne!(r.overall_verdict(), Verdict::Attention, "{}", r.render(false));
    }

    #[test]
    fn sampled_retransmit_rate_uses_in_flight_deltas_over_the_window() {
        // A persistent pool WITH samples: the rate comes from the sample stream's per-socket
        // bytes_sent + total_retrans DELTAS (same window for both), NOT the cumulative fields.
        // The cumulative BASELINE is deliberately huge (50 MB / 100 retransmits) so a
        // delta→cumulative regression is caught in BOTH terms: with deltas the rate is
        // 30 / (1_460_000/1460=1000 segs) = 3.00% (Warn); a cumulative DENOMINATOR
        // (51_460_000/1460 ≈ 35k segs) would drop it under the 0.1% floor → clean, and a
        // cumulative NUMERATOR (130) would read 13.00% — so pinning the exact value + segs
        // count nails the delta semantics the name advertises.
        let smp = |ts: u64, sent: u64, retrans: u32| {
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                ts_ns: Some(ts),
                min_rtt_us: Some(900),
                bytes_sent: sent,
                total_retrans: retrans,
                ..Default::default()
            })
        };
        let recs = vec![
            smp(1_000, 50_000_000, 100), // cumulative baseline, predates the window
            smp(2_000, 51_460_000, 130), // delta: +1_460_000 bytes (=1000 segs), +30 retransmits
            Record::Operation(Operation {
                http_status: Some(200),
                ttfb_ns: Some(2_000_000),
                connection_reused: true,
                ..Default::default()
            }),
        ];
        let r = analyze(&recs);
        let row = r.rows.iter().find(|x| x.id == "retransmit_rate").expect("row present");
        assert_eq!(row.mark, Mark::Warn, "30/~1000 segs is a real loss rate: {}", r.render(false));
        assert!(row.value.contains("3.00%"), "delta rate must be 3.00%, got {}", row.value);
        assert!(row.note.contains("30 retransmit(s) / ~1000 segs"), "{}", row.note);
        assert!(row.note.contains("from in-flight samples"), "{}", row.note);
        // The finding's population is the SAMPLE STREAM the rate came off, not conn_count —
        // which is 0 on this path by construction (no connection closed), the same "judged: 0
        // on a real judgment" hole the connection-only capture had.
        assert_eq!(r.rtx_stream_count, Some(1), "one stream moved send-side bytes");
        let f = r.findings().into_iter().find(|f| f.finding_id == "retransmit_rate").unwrap();
        assert_eq!((f.sample.judged, f.sample.kind), (1, SampleKind::Connection));
    }

    #[test]
    fn a_connection_only_capture_publishes_the_connection_population() {
        // A Go/rustls client (or any capture without the uprobe caps) yields connection records
        // and NO operations. `retransmit_rate` is then the only check that can fire and the only
        // thing gating the exit code — yet it, `baseline_rtt` and the `run` roll-up were
        // SampleKind::Mixed, which reported the OP counts, i.e. `judged: 0`. A fleet gate
        // filtering on `sample.judged >= N` dropped the one real judgment, and a consumer
        // normalizing `value / sample.judged` divided by zero.
        let recs = vec![
            conn(Some(17_000), 50, 1_000_000), // 7.3% -> a real ⚠ loss judgment
            conn(Some(19_000), 0, 1_000_000),
        ];
        let r = analyze(&recs);
        assert_eq!((r.op_judged, r.op_excluded, r.conn_count), (0, 0, 2));
        assert!(r.is_attention(), "the loss judgment stands on a capture with no ops");

        let f = r.findings();
        let by = |id: &str| f.iter().find(|x| x.finding_id == id).unwrap().sample.clone();
        assert_eq!(
            (by("retransmit_rate").judged, by("retransmit_rate").kind),
            (2, SampleKind::Connection),
            "rated over the two closed connections, not over the 0 ops"
        );
        assert_eq!((by("baseline_rtt").judged, by("baseline_rtt").excluded), (2, 0),
            "both connections supplied an srtt");
        assert_eq!(by("run").judged, 2, "the roll-up names ops + connections, and there are 2 conns");
    }

    #[test]
    fn the_rtt_floor_publishes_the_records_that_supplied_it() {
        // The floor is a median over the srtt-carrying records, so its population is those
        // records — not the timeable-op split. One connection with an srtt plus 5 ops without
        // one is a floor resting on ONE sample, and the finding must say so (a consumer weighing
        // a floor by its support can't do that if the number describes a different population).
        //
        // The 5 ops are not `excluded` either: an operation record NEVER carries a close-time
        // srtt (the schema pins the field null on every op s3tap emits), so counting them as
        // records that could have supplied a floor and didn't overstated the pool. 1 of 1
        // connections supplied it.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..5).map(|_| op(30, 17, true, 200, false)));
        let r = analyze(&recs);
        assert_eq!((r.floor_judged, r.floor_excluded), (1, 0));
        let f = r.findings().into_iter().find(|f| f.finding_id == "baseline_rtt").unwrap();
        assert_eq!((f.sample.judged, f.sample.excluded), (1, 0));

        // A second connection that closed WITHOUT a usable srtt (the 0 sentinel: never
        // sampled, or LRU-evicted) IS a candidate that didn't supply one, so it is excluded.
        // That is the distinction the count exists to draw.
        let mut with_dud = vec![conn(Some(17_000), 0, 1_000_000), conn(Some(0), 0, 1_000_000)];
        with_dud.extend((0..5).map(|_| op(30, 17, true, 200, false)));
        assert_eq!(
            {
                let r2 = analyze(&with_dud);
                (r2.floor_judged, r2.floor_excluded)
            },
            (1, 1)
        );
    }

    #[test]
    fn an_operation_srtt_is_not_a_floor_source() {
        // The doctor used to blend `op.srtt_us` into the close-time floor, with a comment
        // claiming the field was "present on both ops+conns". It never is: `build_op` pins it
        // null on every operation record s3tap emits, and the schema documents it as always
        // null. So an ops-only capture has NO floor, exactly as `no_srtt_floor_is_no_baseline`
        // pins — this test pins the other half, that a hand-written op-side srtt is not quietly
        // promoted into the denominator every `×RTT` verdict is taken against.
        let op_with_srtt = Record::Operation(Operation {
            http_status: Some(200),
            ttfb_ns: Some(30_000_000),
            srtt_us: Some(17_000), // not a field s3tap populates here
            ..Default::default()
        });
        let r = analyze(&[op_with_srtt]);
        assert_eq!(r.baseline_rtt_us, None, "the floor comes from connections, not operations");
        assert_eq!(r.verdict, Verdict::NoBaseline);
        assert_eq!((r.floor_judged, r.floor_excluded), (0, 0), "no candidate record either");
    }

    #[test]
    fn a_sampled_srtt_floor_still_counts_the_connections_that_failed_close_time_srtt() {
        // Two connections that both closed with the 0 sentinel (never sampled / LRU-evicted),
        // so `close_srtt` finds nothing and the floor falls back to the sampled stream. `srtt` is
        // a field both connections AND samples carry (unlike `min_rtt`, which only `TcpSample`
        // has), so when the fallback resolves via sampled srtt, the connections that failed the
        // close-time attempt are "of that same kind" and belong in `floor_excluded` alongside any
        // samples that didn't carry a usable value either.
        let mut recs = vec![conn(Some(0), 0, 1_000_000), conn(Some(0), 0, 1_000_000)];
        recs.push(Record::TcpSample(TcpSample { srtt_us: Some(15_000), ..Default::default() }));
        let r = analyze(&recs);
        assert_eq!(
            (r.floor_judged, r.floor_excluded),
            (1, 2),
            "1 sample supplied the srtt floor; both dud connections are candidates that didn't"
        );
    }

    #[test]
    fn sample_send_deltas_sums_per_segment_and_excludes_the_reuse_reset() {
        // Direct unit test of the delta helper: one cookie carrying TWO connection lifetimes on
        // the same reused sk-ptr. The byte-counter RESET (6.46M → 0.2M) is a reuse boundary
        // (ts_segments splits there), so the negative jump must NOT count — each lifetime's
        // delta is summed independently. sent = 1_460_000 + 300_000; retrans = 30 + 3.
        let s = |ts: u64, sent: u64, retrans: u32| TcpSample {
            sock_cookie: 1,
            ts_ns: Some(ts),
            bytes_sent: sent,
            total_retrans: retrans,
            ..Default::default()
        };
        let samples = [
            s(1_000, 5_000_000, 100),
            s(2_000, 6_460_000, 130), // seg 1: +1_460_000 sent, +30 retrans
            s(3_000, 200_000, 5),     // RESET → seg 2 starts here (the drop is excluded)
            s(4_000, 500_000, 8),     // seg 2: +300_000 sent, +3 retrans
        ];
        let refs: Vec<&TcpSample> = samples.iter().collect();
        // …and the one cookie counts ONCE as the judged stream population, not once per segment.
        assert_eq!(sample_send_deltas(&refs), (1_760_000, 33, 1));

        // A cookie that never advances its send counter contributes nothing (→ n/a upstream),
        // and is not counted as a judged stream either.
        let flat = [s(1_000, 9_000, 0), s(2_000, 9_000, 0)];
        let flat_refs: Vec<&TcpSample> = flat.iter().collect();
        assert_eq!(sample_send_deltas(&flat_refs), (0, 0, 0));
    }

    #[test]
    fn sample_send_deltas_counts_a_stream_that_only_retransmits() {
        // A stalled sender: `bytes_sent` never advances (cookie 2, e.g. keep-alive probing or
        // re-sending already-sent data) but `total_retrans` does. It must still land in the
        // judged stream count: it fed the retransmit numerator, so dropping it from the
        // denominator understates how many streams the published rate actually rests on.
        let s = |cookie: u64, ts: u64, sent: u64, retrans: u32| TcpSample {
            sock_cookie: cookie,
            ts_ns: Some(ts),
            bytes_sent: sent,
            total_retrans: retrans,
            ..Default::default()
        };
        let samples = [
            s(1, 1_000, 0, 0),
            s(1, 2_000, 1_000_000, 0), // cookie 1: real traffic, no retransmits
            s(2, 1_000, 9_000, 0),
            s(2, 2_000, 9_000, 7), // cookie 2: 0 bytes_sent delta, +7 retrans
        ];
        let refs: Vec<&TcpSample> = samples.iter().collect();
        assert_eq!(
            sample_send_deltas(&refs),
            (1_000_000, 7, 2),
            "both cookies are judged: one moved bytes, the other only retransmitted"
        );
    }

    #[test]
    fn a_closed_connection_rates_retransmits_on_close_time_bytes_not_samples() {
        // Parity guard (the retransmit analogue of the RTT-floor close-first guard): when a
        // connection closed, the rate uses its close-time bytes_sent and the note is NOT
        // labelled sample-derived — even when samples with nonzero deltas coexist. A bug that
        // preferred the samples would rate 30/1000 = 3% → Warn; the close path sees 0
        // retransmits over 1000 segs → clean.
        let recs = vec![
            conn(Some(17_000), 0, 1_460_000), // close_sent > 0 → close path; 0 retransmits → clean
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                ts_ns: Some(1_000),
                bytes_sent: 5_000_000,
                total_retrans: 100,
                ..Default::default()
            }),
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                ts_ns: Some(2_000),
                bytes_sent: 6_460_000,
                total_retrans: 130,
                ..Default::default()
            }),
            op(30, 17, true, 200, false),
        ];
        let r = analyze(&recs);
        let row = r.rows.iter().find(|x| x.id == "retransmit_rate").expect("row present");
        assert_eq!(row.mark, Mark::Ok, "close-time bytes, 0 retransmits → clean: {}", r.render(false));
        assert!(!row.note.contains("from in-flight samples"), "must use the close path: {}", row.note);
    }

    #[test]
    fn an_absurd_injected_rtt_floor_is_rejected_not_used_as_a_denominator() {
        // Untrusted JSONL: a near-sentinel RTT (u32::MAX-1 ≈ 71 min) must NOT become the floor.
        // A huge denominator would make every latency span read "fast" and silently suppress
        // all latency verdicts. With no plausible floor left, the run honestly degrades to
        // NO BASELINE rather than reading wrong. Both the sampled path...
        let absurd = u32::MAX - 1;
        let sampled = vec![
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                min_rtt_us: Some(absurd),
                srtt_us: Some(absurd),
                ..Default::default()
            }),
            op(30, 17, true, 200, false),
        ];
        let rs = analyze(&sampled);
        assert!(rs.baseline_rtt_us.is_none(), "sampled: absurd floor rejected: {:?}", rs.baseline_rtt_us);
        assert_eq!(rs.overall_verdict(), Verdict::NoBaseline);

        // ...and the close-time (parity-pinned) path reject the absurd value identically.
        let closed = vec![conn(Some(absurd), 0, 1_000_000), op(30, 17, false, 200, false)];
        let rc = analyze(&closed);
        assert!(rc.baseline_rtt_us.is_none(), "close: absurd floor rejected: {:?}", rc.baseline_rtt_us);
        assert_eq!(rc.overall_verdict(), Verdict::NoBaseline);
    }

    // A sampled TcpSample builder for the path-ceiling tests (one cookie, a growing byte counter).
    fn smp(ts: u64, min_rtt: u32, rcv_wnd: u32, snd_cwnd: u32, sent: u64, recv: u64) -> Record {
        Record::TcpSample(TcpSample {
            sock_cookie: 1,
            ts_ns: Some(ts),
            min_rtt_us: Some(min_rtt),
            rcv_wnd,
            snd_cwnd,
            bytes_sent: sent,
            bytes_recv: recv,
            ..Default::default()
        })
    }
    // metric.value is bytes/s computed via a µs→s division, so compare with a tolerance.
    fn approx(v: Option<f64>, want: f64) -> bool {
        v.is_some_and(|v| (v - want).abs() < 10.0)
    }

    #[test]
    fn brief_summarizes_healthy_attention_and_no_baseline_plainly() {
        // HEALTHY: one plain line, the reuse clause, and the honesty tail; no issue bullets.
        let healthy = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, true, 200, false)];
        let hb = analyze(&healthy).render_brief(false);
        assert!(hb.starts_with("✓ Healthy"), "{hb}");
        assert!(hb.contains("connection reuse is working"), "{hb}");
        assert!(hb.contains("judged 1 of 1 operations"), "{hb}");
        assert!(!hb.contains('•'), "healthy has no issue bullets: {hb}");

        // ATTENTION: the headline counts the issues and each is listed with its remedy note.
        let lossy = vec![conn(Some(17_000), 50, 1_000_000), op(30, 17, false, 200, false)];
        let ab = analyze(&lossy).render_brief(false);
        assert!(ab.starts_with("⚠ Attention — 1 issue to look at:"), "{ab}");
        assert!(ab.contains("• retransmit rate:"), "{ab}");

        // NO BASELINE: names the fix (context-neutral, no capture-only flag), no issue bullets.
        let floorless = vec![op(30, 17, false, 200, false)];
        let nb = analyze(&floorless).render_brief(false);
        assert!(nb.starts_with("? No baseline"), "{nb}");
        assert!(nb.contains("connection close") || nb.contains("in-flight RTT samples"), "{nb}");
        assert!(!nb.contains('•'), "{nb}");
    }

    #[test]
    fn brief_lists_an_escalation_only_attention_issue() {
        // The base verdict is NOT Attention (rows are clean) — the ATTENTION comes only from the
        // reuse-rate row, which lives OUTSIDE self.rows. render_brief must still list it (the
        // "wrong-section gathering" guard): 6 healthy ops, all NEW connections => reuse 0%.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..6).map(|_| op(30, 17, false, 200, false))); // non-reused, healthy latencies
        let r = analyze(&recs);
        assert_eq!(r.overall_verdict(), Verdict::Attention);
        assert_ne!(r.verdict, Verdict::Attention, "base verdict is clean; escalation is reuse-only");
        let b = r.render_brief(false);
        assert!(b.starts_with("⚠ Attention — 1 issue"), "{b}");
        assert!(b.contains("• connection reuse:"), "the reuse issue must be listed: {b}");
    }

    #[test]
    fn brief_counts_and_lists_multiple_issues() {
        // A 500 with loss fires three warns across TWO sections: retransmit rate + HTTP errors
        // (self.rows) and the S3-domain "server errors (5xx)" row (self.s3) — so this also pins
        // that brief gathers issues from the s3 section, and that the count matches the bullets.
        let recs = vec![conn(Some(17_000), 50, 1_000_000), op(30, 17, false, 500, false)];
        let b = analyze(&recs).render_brief(false);
        assert!(b.starts_with("⚠ Attention — 3 issues to look at:"), "{b}");
        assert_eq!(b.matches('•').count(), 3, "the headline count must equal the bullet count: {b}");
        assert!(b.contains("• retransmit rate:"), "{b}");
        assert!(b.contains("• HTTP errors:"), "{b}");
        assert!(b.contains("• server errors (5xx):"), "{b}");
    }

    #[test]
    fn brief_checks_passed_and_conns_only_states_a_zero_denominator() {
        // A floor but every op partial => CHECKS PASSED, with the honesty tail naming the
        // denominator (judged 0 of 1).
        let partial = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, true)];
        let cp = analyze(&partial).render_brief(false);
        assert!(cp.starts_with("✓ Checks passed"), "{cp}");
        assert!(cp.contains("(judged 0 of 1 operations)"), "{cp}");

        // A conns-only capture (total == 0) USED to suppress the tail entirely — this test
        // pinned that suppression as intended, and it was the "green because it saw nothing"
        // bug: the brief report for a capture with no S3 operations at all was byte-identical
        // to one that judged thousands. The denominator is now always stated, and 0 says so
        // in words rather than by absence.
        let conns_only = vec![conn(Some(17_000), 0, 1_000_000)];
        let co = analyze(&conns_only).render_brief(false);
        assert!(
            co.contains("(0 operations in this capture: only the network path was judged, not \
                         any S3 request)"),
            "a zero denominator must be stated, never suppressed: {co}"
        );
        assert!(co.starts_with("? No operations"), "and the headline is not a ✓: {co}");
    }

    #[test]
    fn a_capture_with_no_operations_is_no_operations_not_checks_passed() {
        // The exit-code half of the "green because it saw nothing" failure. A Go/rustls client
        // (or any capture taken without the uprobe caps) yields connections and no operations:
        // the floor is real and every network row is clean, so the verdict read CHECKS PASSED
        // and `doctor --strict` exited 0 while the same run's --json said `"severity":
        // "unjudged"`. The two halves now agree.
        let conns_only = vec![conn(Some(17_000), 0, 1_000_000)];
        let r = analyze(&conns_only);
        // The parity-pinned global verdict is untouched (s3stats.py has no S3 population).
        assert_eq!(r.verdict, Verdict::ChecksPassed);
        assert_eq!(r.overall_verdict(), Verdict::NoOperations);
        assert!(!r.is_attention(), "a missing denominator is not a warning");
        assert!(!r.has_advisory(), "…and nothing here is advisory either, so --strict can only \
                                    gate on the verdict itself");
        let f = r.findings().into_iter().find(|f| f.finding_id == "run").unwrap();
        assert_eq!(f.severity, Severity::Unjudged, "the run roll-up never publishes Healthy here");
        assert_eq!(f.verdict, "NO OPERATIONS");
        let full = r.render(false);
        assert!(full.contains("verdict: NO OPERATIONS"), "{full}");
        assert!(
            full.contains("(0 operations in this capture"),
            "the human render still states the denominator: {full}"
        );
    }

    #[test]
    fn no_operations_outranks_no_baseline_when_both_are_missing() {
        // Neither a floor nor an operation (a scope that matched nothing but a half-open
        // socket). Both denominators are absent; name the one that explains the other, since
        // "no latency was judged" is a consequence of there being no request to judge. Both
        // are Unjudged and both are non-green, so this decides the WORDING, not the gate.
        let no_floor_no_ops = vec![conn(None, 0, 1_000_000)];
        let r = analyze(&no_floor_no_ops);
        assert_eq!(r.verdict, Verdict::NoBaseline);
        assert_eq!(r.overall_verdict(), Verdict::NoOperations);
    }

    #[test]
    fn no_operations_never_masks_a_real_connection_level_warning() {
        // The connection-sourced checks judge with zero operations, and that judgment is real:
        // 50 retransmits over ~684 segments is loss on the path whether or not S3 was decoded.
        // So Attention wins over NoOperations, and the roll-up still names the denominator so a
        // reader knows which layer could have produced the ⚠.
        let recs = vec![conn(Some(17_000), 50, 1_000_000)];
        let r = analyze(&recs);
        assert_eq!(r.overall_verdict(), Verdict::Attention, "{}", r.render(false));
        assert!(r.is_attention());
        let f = r.findings().into_iter().find(|f| f.finding_id == "run").unwrap();
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.summary.contains("0 operations in this capture"), "{}", f.summary);
    }

    #[test]
    fn losing_the_operation_stream_is_a_baseline_regression() {
        // The gate this variant exists for: yesterday's capture judged operations, today's
        // (same job, uprobe caps lost) judged none. Every S3 check simply vanishes, so no
        // delta can be a regression — only the verdict rank says the evidence went away.
        let base = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)];
        let now = vec![conn(Some(17_000), 0, 1_000_000)];
        let d = diff(&analyze(&now), &analyze(&base)); // diff(current, baseline)
        assert_eq!(d.current_verdict, Verdict::NoOperations);
        assert!(d.regressed(), "a capture that judged nothing must not pass a baseline gate");
    }

    #[test]
    fn sampled_path_domain_recovers_the_download_ceiling_for_a_persistent_pool() {
        // No connection closed (path_domain empty), but the sample stream shows a download-heavy
        // single stream: peak rcv_wnd / min_rtt gives the receive-window ceiling. 2 MB window /
        // 20 ms floor => EXACTLY 100 MB/s ceiling; ~100 MB/s pulled (1 MB / 10 ms) => receive-
        // limited. Pin the VALUE so a unit/aggregation bug can't pass on the label alone.
        let mut recs: Vec<Record> =
            (0..8).map(|i| smp(i * 10_000_000, 20_000, 2_000_000, 0, 200, i * 1_000_000)).collect();
        recs.push(op(30, 17, true, 200, false));
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "recv_ceiling").expect("sampled download ceiling");
        assert_eq!(row.label, "download ceiling");
        assert!(approx(row.metric.value, 100_000_000.0), "ceiling must be 100 MB/s: {:?}", row.metric.value);
        assert!(row.note.contains("sampled") && row.note.contains("lower-bound"), "{}", row.note);
        assert!(row.note.contains("RECEIVE-WINDOW-LIMITED"), "~100/100 MB/s: {}", row.note);
    }

    #[test]
    fn sampled_download_ceiling_with_headroom_is_not_flagged_limited() {
        // A big window (10 MB / 10 ms = 1000 MB/s ceiling) but a slow pull (~10 MB/s): well under
        // 0.7× => the inconclusive "not the sustained bottleneck" branch, NOT receive-limited.
        let mut recs: Vec<Record> =
            (0..8).map(|i| smp(i * 10_000_000, 10_000, 10_000_000, 0, 200, i * 100_000)).collect();
        recs.push(op(30, 17, true, 200, false));
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "recv_ceiling").expect("sampled download ceiling");
        assert!(approx(row.metric.value, 1_000_000_000.0), "ceiling 1000 MB/s: {:?}", row.metric.value);
        assert!(!row.note.contains("RECEIVE-WINDOW-LIMITED"), "has headroom: {}", row.note);
        assert!(row.note.contains("not the sustained bottleneck"), "{}", row.note);
    }

    #[test]
    fn sampled_path_domain_recovers_the_send_ceiling_with_disclosed_mss() {
        // Upload-heavy pool: snd_cwnd · MSS(assumed 1460) / min_rtt gives the send ceiling.
        // 100 segs · 1460 / 10 ms = EXACTLY 14.6 MB/s. The delivery_rate is 5 MB/s — pinning the
        // ceiling VALUE to 14.6 MB/s proves cwnd·MSS drives it, NOT the delivery rate, and that
        // ASSUMED_MSS_BYTES is applied.
        let up = |ts: u64, sent: u64| {
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                ts_ns: Some(ts),
                min_rtt_us: Some(10_000),
                snd_cwnd: 100,
                delivery_rate_bps: Some(5_000_000),
                bytes_sent: sent,
                bytes_recv: 100, // upload-heavy
                ..Default::default()
            })
        };
        let mut recs: Vec<Record> = (0..8).map(|i| up(i * 10_000_000, i * 1_000_000)).collect();
        recs.push(op(30, 17, true, 200, false));
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "bdp_ceiling").expect("sampled send ceiling");
        assert_eq!(row.label, "1-stream ceiling");
        assert!(approx(row.metric.value, 14_600_000.0), "cwnd·MSS ceiling 14.6 MB/s: {:?}", row.metric.value);
        assert!(row.note.contains("MSS assumed"), "must disclose the assumption: {}", row.note);
    }

    #[test]
    fn sampled_send_ceiling_flags_app_limited_from_the_kernel_flag() {
        // Upload well under a big ceiling (146 MB/s) at 5 MB/s, WITH the kernel rate_app_limited
        // flag set in the tail => the APP-LIMITED branch (not a network "parallelize").
        let up = |ts: u64, sent: u64| {
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                ts_ns: Some(ts),
                min_rtt_us: Some(10_000),
                snd_cwnd: 1000,
                delivery_rate_bps: Some(5_000_000),
                rate_app_limited: true,
                bytes_sent: sent,
                bytes_recv: 100,
                ..Default::default()
            })
        };
        let mut recs: Vec<Record> = (0..8).map(|i| up(i * 10_000_000, i * 1_000_000)).collect();
        recs.push(op(30, 17, true, 200, false));
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "bdp_ceiling").expect("sampled send ceiling");
        assert!(row.note.contains("APP-LIMITED"), "kernel flag set + under ceiling: {}", row.note);
    }

    #[test]
    fn sampled_ceiling_shows_without_a_throughput_sample() {
        // A single sample per cookie: no Δt to measure a rate (throughput_of_segment => None), so
        // the ceiling still renders on its own with the honest "not measurable" note — never a
        // fabricated rate.
        let recs = vec![smp(1_000, 20_000, 2_000_000, 0, 200, 5_000_000), op(30, 17, true, 200, false)];
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "recv_ceiling").expect("ceiling-only row");
        assert!(approx(row.metric.value, 100_000_000.0), "{:?}", row.metric.value);
        assert!(row.note.contains("not measurable"), "{}", row.note);
        assert!(!row.note.contains("RECEIVE-WINDOW-LIMITED"), "no rate => no verdict: {}", row.note);
    }

    #[test]
    fn sampled_ceilings_are_computed_per_segment_across_a_reuse_boundary() {
        // One cookie, TWO connection lifetimes on the reused sk-ptr. A byte-counter RESET splits
        // them (ts_segments); the two segments carry DIFFERENT windows (2 MB, 4 MB) => ceilings
        // 100 and 200 MB/s => median 150. If the reset were NOT split, max(rcv_wnd)=4 MB over one
        // segment would give 200 — so 150 proves the per-segment split.
        let recs = vec![
            smp(0, 20_000, 2_000_000, 0, 100, 1_000_000),
            smp(10_000_000, 20_000, 2_000_000, 0, 100, 2_000_000),
            smp(20_000_000, 20_000, 2_000_000, 0, 100, 3_000_000),
            // RESET: bytes_recv drops (3M -> 0.5M) => a new segment with a 4 MB window.
            smp(30_000_000, 20_000, 4_000_000, 0, 100, 500_000),
            smp(40_000_000, 20_000, 4_000_000, 0, 100, 1_500_000),
            smp(50_000_000, 20_000, 4_000_000, 0, 100, 2_500_000),
            op(30, 17, true, 200, false),
        ];
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "recv_ceiling").expect("sampled download ceiling");
        assert!(approx(row.metric.value, 150_000_000.0), "median of 100 & 200 MB/s: {:?}", row.metric.value);
    }

    #[test]
    fn a_closed_connection_uses_conn_path_diagnosis_not_the_sampled_ceilings() {
        // Parity guard: with a connection closed, path_domain runs on it and the sampled
        // fallback is NOT invoked — even when samples coexist. Pin BOTH that exactly ONE
        // recv_ceiling exists AND that NO path row is sampled, so a reverted `conns.is_empty()`
        // gate (which would append a second, sampled recv_ceiling) fails the test.
        let recs = vec![
            Record::Connection(Connection {
                srtt_us: Some(17_000),
                min_rtt_us: Some(20_000),
                window_clamp: Some(2_000_000),
                bytes_recv: 5_000_000,
                bytes_sent: 200,
                lifetime_ns: Some(100_000_000),
                ..Default::default()
            }),
            smp(0, 20_000, 9_000_000, 0, 100, 1_000_000), // a very different ceiling if wrongly used
            smp(10_000_000, 20_000, 9_000_000, 0, 100, 5_000_000),
            op(30, 17, true, 200, false),
        ];
        let r = analyze(&recs);
        assert_eq!(
            r.path.iter().filter(|x| x.id == "recv_ceiling").count(),
            1,
            "exactly one recv_ceiling (close path only): {}",
            r.render(false)
        );
        assert!(
            r.path.iter().all(|x| !x.note.contains("sampled")),
            "no path row may be sampled when a connection closed: {}",
            r.render(false)
        );
    }

    #[test]
    fn path_domain_surfaces_advisory_diagnosis_from_tcp_sock_fields() {
        // A connection carrying the extended tcp_sock fields yields the advisory path rows
        // (min_rtt/jitter, send bottleneck, BDP ceiling, loss shape) — and NEVER escalates
        // the verdict (advisory). This is the signal available even for Go/non-OpenSSL
        // clients (connection records, no ops).
        // An UPLOAD-heavy connection (bytes_sent >> bytes_recv) so the send-path rows apply.
        let upload = Connection {
            bytes_sent: 50_000_000,
            bytes_recv: 2_000,
            srtt_us: Some(40_000),              // 40 ms smoothed ...
            min_rtt_us: Some(16_000),           // ... vs a 16 ms true floor => 2.5x inflation
            rttvar_us: Some(3_000),
            snd_cwnd: Some(100),
            mss: Some(1_400),                   // ceiling = 100*1400 / 0.016s = 8.75 MB/s
            delivery_rate_bps: Some(2_000_000), // 2 MB/s achieved => "well under" the ceiling
            busy_jiffies: Some(1_000),          // disjoint chronos: total = 1000+400+100 = 1500
            rwnd_limited_jiffies: Some(400),    // 400/1500 = 27% receiver-window-limited
            sndbuf_limited_jiffies: Some(100),  // 100/1500 = 7% send-buffer; 1000/1500 = 67% free
            reordering: Some(9),                // > default 3 => loss-shape row
            ca_state: Some(3),                  // closed in Recovery
            ..Default::default()
        };
        let r = analyze(&[Record::Connection(upload.clone())]);
        let ids: Vec<&str> = r.path.iter().map(|x| x.id).collect();
        assert!(ids.contains(&"path_min_rtt") && ids.contains(&"send_bottleneck"));
        assert!(ids.contains(&"bdp_ceiling") && ids.contains(&"loss_shape"), "{ids:?}");
        assert!(r.path.iter().all(|x| x.mark == Mark::Fyi), "path rows are pure-FYI telemetry");
        assert!(!r.has_advisory(), "FYI path rows must NOT feed the --strict gate");
        assert_ne!(r.overall_verdict(), Verdict::Attention, "FYI never escalates");
        let sb = r.path.iter().find(|x| x.id == "send_bottleneck").unwrap();
        // disjoint chronos => share = field/(busy+rwnd+sndbuf): 400/1500 = 27%, free 1000/1500 = 67%.
        assert!(sb.note.contains("27% receiver-window-limited"), "{}", sb.note);
        assert!(sb.note.contains("67% sending freely"), "{}", sb.note);

        // A DOWNLOAD (bytes_recv >> bytes_sent: a GET) must SUPPRESS the send-path rows —
        // they'd misframe a fast GET as app-limited — but keep the direction-agnostic ones.
        let download = Connection { bytes_sent: 2_000, bytes_recv: 50_000_000, ..upload };
        let d = analyze(&[Record::Connection(download)]);
        let dids: Vec<&str> = d.path.iter().map(|x| x.id).collect();
        assert!(dids.contains(&"path_min_rtt") && dids.contains(&"loss_shape"), "{dids:?}");
        assert!(!dids.contains(&"send_bottleneck") && !dids.contains(&"bdp_ceiling"),
            "send-path rows must be suppressed for a download: {dids:?}");

        // No extended fields -> no path rows (keeps existing fixtures/parity untouched).
        let bare = analyze(&[Record::Connection(Connection { srtt_us: Some(16_000), ..Default::default() })]);
        assert!(bare.path.is_empty());
    }

    #[test]
    fn path_domain_edge_cases() {
        let base = |c: Connection| analyze(&[Record::Connection(c)]);
        let ids = |r: &Report| r.path.iter().map(|x| x.id).collect::<Vec<_>>();

        // #1: a hand-crafted min_rtt sentinel (0 or U32_MAX) must NOT render a floor row.
        for v in [0, u32::MAX] {
            let r = base(Connection { min_rtt_us: Some(v), srtt_us: Some(20_000), ..Default::default() });
            assert!(!ids(&r).contains(&"path_min_rtt"), "sentinel min_rtt={v} must be suppressed");
        }

        // #5: a tiny GET/HEAD (bytes_sent > bytes_recv but < 64KiB) is NOT an upload -> the
        // send-path rows are suppressed; the direction-agnostic min RTT stays.
        let tiny = base(Connection {
            bytes_sent: 2_000, bytes_recv: 200, min_rtt_us: Some(16_000), srtt_us: Some(20_000),
            snd_cwnd: Some(10), mss: Some(1_440), delivery_rate_bps: Some(1_000_000),
            busy_jiffies: Some(100), rwnd_limited_jiffies: Some(10), ..Default::default()
        });
        assert!(ids(&tiny).contains(&"path_min_rtt"));
        assert!(!ids(&tiny).contains(&"send_bottleneck") && !ids(&tiny).contains(&"bdp_ceiling"),
            "a tiny request is not an upload: {:?}", ids(&tiny));

        // #4: loss_shape gate negatives — ca_state 2 (CWR) + reordering 3 (kernel default) -> no
        // row; ca_state 3 alone -> "loss x" with a loss_recovery metric (not reordering).
        let normal = base(Connection { ca_state: Some(2), reordering: Some(3), srtt_us: Some(20_000), ..Default::default() });
        assert!(!ids(&normal).contains(&"loss_shape"), "CWR + default reordering is not loss");
        let lr = base(Connection { ca_state: Some(3), srtt_us: Some(20_000), ..Default::default() });
        let row = lr.path.iter().find(|x| x.id == "loss_shape").unwrap();
        assert!(row.value.contains("loss x"), "{}", row.value);
        assert_eq!(row.metric.name, "loss_recovery", "metric matches the loss-recovery signal");

        // #3: BDP over a PARTIAL complete-pairs subset — one upload with a delivery rate, one
        // without. The ceiling value spans both pairs; the achieved/verdict only the complete one.
        let up = |rate: Option<u64>| Connection {
            bytes_sent: 10_000_000, bytes_recv: 2_000, min_rtt_us: Some(16_000),
            snd_cwnd: Some(100), mss: Some(1_400), delivery_rate_bps: rate, ..Default::default()
        };
        let r = analyze(&[Record::Connection(up(Some(2_000_000))), Record::Connection(up(None))]);
        let bdp = r.path.iter().find(|x| x.id == "bdp_ceiling").unwrap();
        assert!(bdp.note.contains("achieved 2 MB/s"), "achieved from the complete subset: {}", bdp.note);
    }

    #[test]
    fn bdp_ceiling_treats_crafted_delivery_rate_zero_as_no_sample() {
        // delivery_rate_bps==0 is the kernel "no sample" sentinel (the correlator maps it to
        // None). A hand-crafted/foreign JSONL can carry Some(0) instead; without the consumer-
        // side >0 filter it would enter the complete subset as a genuine 0 MB/s and trip the
        // false "app-limited; parallelize" verdict. With the filter it's excluded, so the row
        // falls back to the plain single-stream-ceiling note.
        let up0 = Connection {
            bytes_sent: 10_000_000, bytes_recv: 2_000, min_rtt_us: Some(16_000),
            snd_cwnd: Some(100), mss: Some(1_400), delivery_rate_bps: Some(0), ..Default::default()
        };
        let r = analyze(&[Record::Connection(up0)]);
        let bdp = r.path.iter().find(|x| x.id == "bdp_ceiling").expect("bdp_ceiling row");
        assert!(!bdp.note.contains("app-limited"), "a no-sample (0) delivery rate must not read as 0 MB/s app-limited: {}", bdp.note);
        assert!(!bdp.note.contains("achieved 0 MB/s"), "{}", bdp.note);
    }

    #[test]
    fn recv_ceiling_diagnoses_download_throughput() {
        // A download (bytes_recv >> bytes_sent) gets a RECEIVE-window ceiling (window_clamp /
        // min_rtt) — the only throughput ceiling available for a GET (send-side cwnd is ~0).
        let dl = |clamp: u32, recv: u64, life_ns: u64| Connection {
            bytes_recv: recv,
            bytes_sent: 2_000,
            min_rtt_us: Some(16_000), // 16 ms
            window_clamp: Some(clamp),
            lifetime_ns: Some(life_ns),
            ..Default::default()
        };
        // 2 MB window -> 125 MB/s ceiling; pulling ~100 MB/s = 0.8x -> receive-window-limited.
        let r = analyze(&[Record::Connection(dl(2_000_000, 100_000_000, 1_000_000_000))]);
        let row = r.path.iter().find(|x| x.id == "recv_ceiling").expect("recv_ceiling for a download");
        assert!(row.note.contains("RECEIVE-WINDOW-LIMITED"), "{}", row.note);
        assert_eq!(row.mark, Mark::Fyi);
        // send-side rows must NOT appear for a download.
        assert!(r.path.iter().all(|x| x.id != "send_bottleneck" && x.id != "bdp_ceiling"));
        // 6 MB window -> 375 MB/s ceiling; a 10 MB/s pull is well under -> not the bottleneck.
        let r2 = analyze(&[Record::Connection(dl(6_000_000, 10_000_000, 1_000_000_000))]);
        let row2 = r2.path.iter().find(|x| x.id == "recv_ceiling").unwrap();
        // Honest: under the ceiling on a lower-bound average is INCONCLUSIVE, not "not limited".
        assert!(row2.note.contains("can't rule the receive window in or out"), "{}", row2.note);
        assert!(!row2.note.contains("RECEIVE-WINDOW-LIMITED"));
    }

    #[test]
    fn tls_handshake_row_infers_version_from_rtt() {
        let conn = |hs_ns: u64| Connection {
            min_rtt_us: Some(16_000), // 16 ms floor
            tls: s3tap_schema::Tls { seen: true, handshake_ns: Some(hs_ns), version: None, sni: None, cipher: None },
            ..Default::default()
        };
        // ~1x the floor -> TLS 1.3 / resumed session.
        let r13 = analyze(&[Record::Connection(conn(16_000_000))]);
        let row = r13.path.iter().find(|x| x.id == "tls_handshake").expect("tls_handshake row");
        assert_eq!(row.mark, Mark::Fyi);
        assert!(row.note.contains("TLS 1.3 or a resumed session"), "{}", row.note);
        // ~2x the floor -> a full handshake (TLS 1.2 / no resumption).
        let r12 = analyze(&[Record::Connection(conn(32_000_000))]);
        let row2 = r12.path.iter().find(|x| x.id == "tls_handshake").unwrap();
        assert!(row2.note.contains("full handshake"), "{}", row2.note);
    }

    #[test]
    fn tls_handshake_finding_baseline_is_the_floor_its_ratio_used() {
        // One finding, ONE denominator. The row's ratio_to_rtt is taken against the median
        // min_rtt, so the emitted finding's baseline_rtt_us must be that same floor. Falling
        // back to the report-level pooled close-time srtt published a finding that contradicted
        // its own note: 3 ms over a 1 ms floor is the 3.0x full handshake the note calls out,
        // but recomputed against a 3 ms srtt it reads 1.0x — a clean one-RTT TLS 1.3.
        let recs = vec![Record::Connection(Connection {
            min_rtt_us: Some(1_000), // the ratio's denominator
            srtt_us: Some(3_000),    // the pooled report baseline — deliberately different
            tls: s3tap_schema::Tls {
                seen: true,
                handshake_ns: Some(3_000_000),
                version: None,
                sni: None,
                cipher: None,
            },
            ..Default::default()
        })];
        let r = analyze(&recs);
        assert_eq!(r.baseline_rtt_us, Some(3_000), "the report-level floor is the srtt");
        let row = r.path.iter().find(|x| x.id == "tls_handshake").expect("tls_handshake row");
        assert_eq!(row.metric.ratio_to_rtt, Some(3.0));
        assert!(row.note.contains("full handshake"), "{}", row.note);

        let f = r.findings().into_iter().find(|x| x.finding_id == "tls_handshake").unwrap();
        assert_eq!(f.baseline_rtt_us, Some(1_000), "not the pooled srtt the note never used");
        // The contract a consumer relies on: value / baseline == the published ratio.
        let Some(MetricValue::Num(ms)) = f.value else { panic!("tls_handshake carries a value") };
        let recomputed = ms * 1e3 / f.baseline_rtt_us.unwrap() as f64;
        assert!((recomputed - f.ratio_to_rtt.unwrap()).abs() < 1e-9, "{recomputed}");
    }

    #[test]
    fn crafted_rttvar_sentinel_never_reaches_the_jitter_note() {
        // rttvar_us is part of the RTT family and takes the SAME sentinel/plausibility filter as
        // min_rtt and srtt. Skipping it printed "jitter ±4294967.3 ms" on the very row where the
        // identical crafted value had just been rejected for the other two fields.
        for v in [0, u32::MAX] {
            let r = analyze(&[Record::Connection(Connection {
                min_rtt_us: Some(16_000),
                srtt_us: Some(20_000),
                rttvar_us: Some(v),
                ..Default::default()
            })]);
            let row = r.path.iter().find(|x| x.id == "path_min_rtt").expect("path_min_rtt row");
            // The clause is OMITTED, not defaulted. This used to assert "jitter ±0.0 ms",
            // which pinned the fabricated fallback as the evidence that the sentinel had been
            // dropped — and ±0.0 ms reads as a perfectly jitter-free path, which is a claim
            // nothing measured. Absent is what "dropped, not printed" actually means.
            assert!(
                !row.note.contains("jitter"),
                "sentinel rttvar={v} must be dropped, not printed as a number: {}",
                row.note
            );
            assert!(
                !row.note.contains("4294967"),
                "and certainly not the crafted value: {}",
                row.note
            );
        }
        // ...while a plausible value is still reported.
        let ok = analyze(&[Record::Connection(Connection {
            min_rtt_us: Some(16_000),
            srtt_us: Some(20_000),
            rttvar_us: Some(3_000),
            ..Default::default()
        })]);
        let row = ok.path.iter().find(|x| x.id == "path_min_rtt").unwrap();
        assert!(row.note.contains("jitter ±3.0 ms"), "{}", row.note);
    }

    #[test]
    fn tls_handshake_row_shows_real_version_and_drops_ratio_suffix() {
        // When a real negotiated version is captured (ServerHello), the note shows the
        // version + cipher and DROPS the inferred-ratio suffix — the ratio is only the
        // inference fallback, and it's a fleet median while ver/cipher come from one conn,
        // so pairing them reads as self-contradictory. The structured metric still keeps
        // ratio_to_rtt for consumers / the --baseline diff.
        let conn = Connection {
            min_rtt_us: Some(16_000), // 16 ms floor
            tls: s3tap_schema::Tls {
                seen: true,
                handshake_ns: Some(32_000_000), // 2x the floor — would read "2.0x" if inferred
                version: Some("TLS 1.3".into()),
                sni: None,
                cipher: Some(0x1301),
            },
            ..Default::default()
        };
        let r = analyze(&[Record::Connection(conn)]);
        let row = r.path.iter().find(|x| x.id == "tls_handshake").expect("tls_handshake row");
        assert!(row.note.contains("TLS 1.3"), "{}", row.note);
        assert!(row.note.contains("0x1301"), "{}", row.note);
        assert!(!row.note.contains("the floor"), "ratio suffix must be dropped: {}", row.note);
        // the ratio is still carried structurally (consumers/diff read it, not the prose)
        assert_eq!(row.metric.ratio_to_rtt, Some(2.0));
    }

    #[test]
    fn tcp_connect_warns_only_when_slow_not_when_fast() {
        // tcp_connect is judged ONE-SIDED (<= 3.0× RTT): only a slow handshake warns.
        // Too slow: 85ms over a 17ms floor = 5.0× (> 3.0) -> warn.
        let slow = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 85, false, 200, false)]);
        assert_eq!(warns(&slow), vec!["tcp_connect"]);
        // Faster than the floor: 5ms over a 17ms floor = 0.29× — benign (srtt is lifetime-
        // smoothed, above the clean SYN/SYN-ACK), so NO warn. This is the false-positive a
        // real CDN/S3 GET tripped before the band went one-sided.
        let fast = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 5, false, 200, false)]);
        assert!(warns(&fast).is_empty(), "a fast connect is healthy: {:?}", warns(&fast));
    }

    #[test]
    fn high_ttfb_on_a_reused_conn_warns() {
        // The reused-conn TTFB branch (distinct from ttfb_new): 120ms on a REUSED conn
        // over a 17ms floor = 7× (> 4×) -> warn. tcp 1.0× stays ok, so warns == [reused].
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(120, 17, true, 200, false)];
        let r = analyze(&recs);
        assert_eq!(warns(&r), vec!["ttfb_reused"]);
        assert_eq!(r.verdict, Verdict::Attention);
    }

    #[test]
    fn zero_srtt_floor_is_no_baseline_like_absent_srtt() {
        // A present-but-ZERO srtt (socket never sampled / LRU-evicted) must take the same
        // honesty path as an absent floor — the `.filter(|s| s != 0.0)` branch: NoBaseline
        // with latency rows n/a, never dividing a span by a 0 ms floor.
        let recs = vec![conn(Some(0), 0, 1_000_000), op(30, 17, false, 200, false)];
        let r = analyze(&recs);
        assert_eq!(r.verdict, Verdict::NoBaseline);
        for id in ["tcp_connect", "ttfb_new"] {
            let row = r.rows.iter().find(|x| x.id == id).unwrap();
            assert_eq!(row.mark, Mark::Na, "{id} must be n/a over a zero floor");
        }
    }

    #[test]
    fn dns_cold_median_excludes_partial_and_error_ops() {
        // DNS timing off a partial/error op isn't trustworthy — eligibility gates live in one
        // place, so the cold-resolve median must read the `good` set, not raw
        // ops. A clean 30 ms resolve + a PARTIAL op carrying a 200 ms resolve + an ERRORED op
        // carrying a 300 ms one: including them medians to 200 ms, excluding them leaves 30 ms.
        // The reported VALUE is the assertion now that the row no longer marks (see
        // `dns_cold_is_reported_but_never_gates`).
        let dns = |ms: u64| {
            Some(Dns { latency_ns: ms * 1_000_000, cache_hit: false, resolved_ip: None, n_answers: 1, ttl_s: None, via: "wire".into() })
        };
        let clean = Record::Operation(Operation {
            http_status: Some(200),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            dns: dns(30),
            ..Default::default()
        });
        let partial = Record::Operation(Operation {
            http_status: Some(200),
            partial: true, // excluded from eligibility
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            dns: dns(200),
            ..Default::default()
        });
        let errored = Record::Operation(Operation {
            http_status: Some(500), // status >= 400 -> excluded from eligibility
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            dns: dns(300),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), clean, partial, errored]);
        let dns_row = r.rows.iter().find(|x| x.id == "dns_cold").expect("dns_cold row");
        assert!(
            dns_row.metric.value.is_some_and(|v| (v - 30.0).abs() < 1e-6),
            "cold-resolve median must be 30 ms (good only), got {:?}",
            dns_row.metric.value
        );
    }

    #[test]
    fn zero_srtt_socket_does_not_dilute_the_floor() {
        // A mix of one evicted/unsampled socket (srtt==0, "never sampled or
        // LRU-evicted") and one real 17 ms socket. The zero is NOT a data point — it must be
        // dropped PER VALUE before the median, leaving the floor at 17 ms. The old code
        // filtered the median RESULT instead: median([0, 17000]) = 8500 passed `!= 0`, giving
        // an 8.5 ms floor that inflated every latency ratio. Mirrors the sampled path, which
        // already filters per value.
        let recs = vec![
            conn(Some(0), 0, 1_000_000),      // evicted — contributes no sample
            conn(Some(17_000), 0, 1_000_000), // the only real floor
            op(30, 17, false, 200, false),
        ];
        let r = analyze(&recs);
        assert_eq!(
            r.baseline_rtt_us,
            Some(17_000),
            "zero-srtt socket diluted the floor (want 17 ms, got {:?})",
            r.baseline_rtt_us
        );
    }

    #[test]
    fn floor_joins_op_to_its_connection_srtt() {
        // An op joins to its connection on sock_cookie and takes THAT connection's floor,
        // on the SAME srtt basis as the pooled global (and the ×RTT thresholds), never the
        // pooled global value itself. (per-op join is the primary floor source.)
        let c = Connection {
            sock_cookie: 42,
            srtt_us: Some(9_000),
            min_rtt_us: Some(2_000),
            endpoint: Endpoint { region: Some("us-east-1".into()), ..Default::default() },
            ..Default::default()
        };
        let cbc: std::collections::HashMap<u64, &Connection> = std::iter::once((42u64, &c)).collect();
        let rf = std::collections::HashMap::new();
        let o = Operation { sock_cookie: 42, ..Default::default() };
        // srtt (9 ms) preferred over min_rtt (2 ms), and NOT the global 50 ms.
        assert_eq!(floor_for(&o, &cbc, &rf, Some(50_000.0), false), Some(9_000.0));

        // min_rtt is only a FALLBACK when srtt is absent (better a propagation floor than none).
        let c2 = Connection { sock_cookie: 7, srtt_us: None, min_rtt_us: Some(2_000), ..Default::default() };
        let cbc2: std::collections::HashMap<u64, &Connection> = std::iter::once((7u64, &c2)).collect();
        let o2 = Operation { sock_cookie: 7, ..Default::default() };
        assert_eq!(floor_for(&o2, &cbc2, &rf, Some(50_000.0), false), Some(2_000.0));
    }

    #[test]
    fn same_class_two_region_ops_keep_their_own_floors() {
        // The BLEND the join exists to kill, WITHIN one op-class: two GetObject ops, one on a
        // ~1 ms us-east conn (slow: 20 ms ttfb = 20×) and one on a ~70 ms cross-region conn
        // (benign: 100 ms = 1.4×). A per-CLASS pooled floor would median to ~35.5 ms and read
        // median(20,100)=60 ms / 35.5 = 1.7× → Ok, hiding the slow op. Per-op judging medians
        // the RATIOS (20×, 1.4×) → 10.7× → WARN. This is the case the different-class test
        // cannot catch (there each class holds a single op).
        let recs = vec![
            conn_in_region(1, 1_000, "us-east-1"), // ~1 ms floor
            conn_in_region(2, 70_000, "eu-west-1"), // ~70 ms floor
            s3op_on(1, "GetObject", 20), // 20 ms = 20× its floor (slow)
            s3op_on(2, "GetObject", 100), // 100 ms = 1.4× (benign)
        ];
        let r = analyze(&recs);
        let get = r
            .s3
            .iter()
            .find(|row| row.id == "s3_ttfb" && row.label.starts_with("GetObject"))
            .expect("GetObject TTFB row");
        assert_eq!(get.mark, Mark::Warn, "same-class blend hid a slow op (ratio={:?})", get.metric.ratio_to_rtt);
    }

    #[test]
    fn s3_ttfb_finding_baseline_matches_its_own_denominator() {
        // A finding's baseline_rtt_us must be the floor its ratio was ACTUALLY taken against,
        // not the pooled global blend. One us-east GetObject (srtt 2 ms floor) beside a distant
        // conn that drags the pooled floor up: the GetObject finding must report ~2 ms, and
        // value/baseline must ≈ ratio_to_rtt (coherent triple for a machine consumer).
        let recs = vec![
            conn_in_region(1, 2_000, "us-east-1"),
            conn_in_region(2, 80_000, "eu-west-1"), // pulls the pooled/global floor far from us-east's 2 ms
            s3op_on(1, "GetObject", 10),            // 10 ms on a 2 ms floor = 5×
        ];
        let findings = analyze(&recs).findings();
        let f = findings
            .iter()
            .find(|f| f.finding_id == "s3_ttfb" && f.scope.s3_op.as_deref() == Some("GetObject"))
            .expect("GetObject s3_ttfb finding");
        assert_eq!(f.baseline_rtt_us, Some(2_000), "finding must report its OWN 2 ms floor, not the blend");
        let value = match f.value { Some(MetricValue::Num(v)) => v, _ => panic!("numeric value") };
        let ratio = f.ratio_to_rtt.expect("ratio");
        // value(ms)/baseline(ms) ≈ ratio — coherent, unlike the old global-blend baseline.
        assert!((value / 2.0 - ratio).abs() < 1e-6, "value/baseline {} != ratio {}", value / 2.0, ratio);
    }

    #[test]
    fn op_with_no_joinable_connection_falls_back_to_region_then_global() {
        // The full ladder: an op joining a conn whose OWN floor is unusable (srtt 0, no
        // min_rtt) falls back to that conn's REGION median; an op joining nothing falls back
        // to the pooled global; with no global either, None (never judged).
        let unusable = Connection {
            sock_cookie: 1,
            srtt_us: Some(0), // evicted -> no per-conn floor
            min_rtt_us: None,
            endpoint: Endpoint { region: Some("us-east-1".into()), ..Default::default() },
            ..Default::default()
        };
        let cbc: std::collections::HashMap<u64, &Connection> = std::iter::once((1u64, &unusable)).collect();
        let mut rf = std::collections::HashMap::new();
        rf.insert(Some("us-east-1".to_string()), 3_000.0); // region median from a sibling conn
        let joined = Operation { sock_cookie: 1, ..Default::default() };
        assert_eq!(floor_for(&joined, &cbc, &rf, Some(50_000.0), false), Some(3_000.0), "region fallback");
        let orphan = Operation { sock_cookie: 999, ..Default::default() };
        assert_eq!(floor_for(&orphan, &cbc, &rf, Some(50_000.0), false), Some(50_000.0), "global fallback");
        assert_eq!(floor_for(&orphan, &cbc, &rf, None, false), None, "no floor anywhere -> not judged");
    }

    #[test]
    fn two_region_capture_uses_two_floors_not_a_blend() {
        // A us-east conn (~1 ms floor) carrying SLOW GetObjects (20 ms ttfb = 20× its floor)
        // and a cross-region conn (~70 ms floor) carrying benign PutObjects (100 ms = 1.4×).
        // A POOLED blend floors at median(1,70)=35.5 ms, so GetObject reads 20/35.5 = 0.56× —
        // FAST — hiding the slow op (exact failure). The per-op join judges
        // GetObject against its own 1 ms floor -> 20× -> WARN, and PutObject against 70 ms -> OK.
        // 3 ops per class so both clear the min-sample gate (a benign PutObject is genuinely ✓).
        let recs = vec![
            conn_in_region(1, 1_000, "us-east-1"), // ~1 ms floor
            conn_in_region(2, 70_000, "eu-west-1"), // ~70 ms floor
            s3op_on(1, "GetObject", 20), // slow: 20 ms = 20× its floor
            s3op_on(1, "GetObject", 20),
            s3op_on(1, "GetObject", 20),
            s3op_on(2, "PutObject", 100), // benign: 100 ms = 1.4×
            s3op_on(2, "PutObject", 100),
            s3op_on(2, "PutObject", 100),
        ];
        let r = analyze(&recs);
        let get = r
            .s3
            .iter()
            .find(|row| row.id == "s3_ttfb" && row.label.starts_with("GetObject"))
            .expect("GetObject TTFB row");
        assert_eq!(
            get.mark,
            Mark::Warn,
            "slow us-east op hidden by a blended floor (ratio={:?})",
            get.metric.ratio_to_rtt
        );
        let put = r
            .s3
            .iter()
            .find(|row| row.id == "s3_ttfb" && row.label.starts_with("PutObject"))
            .expect("PutObject TTFB row");
        assert_eq!(put.mark, Mark::Ok, "cross-region op must be judged against its OWN 70 ms floor");
    }

    #[test]
    fn huge_bytes_sent_saturates_instead_of_overflowing() {
        // bytes_sent is an unvalidated u64 from the JSONL; two near-u64::MAX connections
        // must NOT panic (debug) or wrap to a bogus retransmit denominator (release).
        let recs = vec![
            conn(Some(17_000), 0, u64::MAX),
            conn(Some(17_000), 0, u64::MAX),
            op(30, 17, false, 200, false),
        ];
        let r = analyze(&recs); // would panic on `.sum()` overflow before the fix
        // a clean capture with an enormous byte count still reads healthy (rtx rate ~0).
        assert!(warns(&r).is_empty(), "unexpected warns: {:?}", warns(&r));
    }

    #[test]
    fn parse_records_counts_kinds_and_junk() {
        let dns = Dns { latency_ns: 1, cache_hit: false, resolved_ip: None, n_answers: 0, ttl_s: None, via: "wire".into() };
        let op_json = serde_json::to_string(&Operation { dns: Some(dns), ..Default::default() }).unwrap();
        let conn_json = serde_json::to_string(&Connection::default()).unwrap();
        let input = format!(
            "{op_json}\n{conn_json}\n\nnot json\n42\n{{\"schema\":\"s3tap.unknown/9\"}}\n"
        );
        let (recs, stats) = parse_records(&input);
        assert_eq!(recs.len(), 2);
        // "not json" (invalid) + bare `42` (valid JSON, but not a record-object) = 2 bad.
        assert_eq!(stats.bad_lines, 2);
        assert_eq!(stats.unknown_schema, 1);
    }

    fn s3op(s3_op: &str, ttfb_ms: u64, status: u16) -> Record {
        Record::Operation(Operation {
            http_status: Some(status),
            partial: false,
            connection_reused: false,
            s3_op: Some(s3_op.into()),
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            tcp_connect_ns: Some(17_000_000),
            ..Default::default()
        })
    }

    fn s3_labels_warn(r: &Report) -> Vec<&str> {
        r.s3.iter().filter(|x| x.mark == Mark::Warn).map(|x| x.label.as_str()).collect()
    }

    #[test]
    fn per_s3_op_ttfb_is_judged_per_class_and_escalates() {
        // GetObject think-time fine (30ms/17 = 1.8x), ListObjectsV2 slow (200ms = 11.8x).
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            s3op("GetObject", 30, 200),
            s3op("ListObjectsV2", 200, 200),
        ];
        let r = analyze(&recs);
        // global ttfb (median over both = 115ms = 6.8x) warns too, but the per-class
        // detail pinpoints WHICH op-class: only ListObjectsV2 is high (11.8× -> not gated).
        assert_eq!(s3_labels_warn(&r), vec!["ListObjectsV2 TTFB"]);
        // GetObject is a lone FAST op: the min-sample gate degrades a would-be ✓ to Na
        // (insufficient data), so it is neither a false ✓ nor a warn.
        let get = r.s3.iter().find(|x| x.label == "GetObject TTFB").unwrap();
        assert_eq!(get.mark, Mark::Na);
        assert!(get.note.contains("insufficient data"));
        assert!(r.is_attention());
    }

    #[test]
    fn s3_warn_escalates_an_otherwise_healthy_global_verdict() {
        // One slow ListObjectsV2 alongside a fast GetObject: the global ttfb median
        // (over both) could stay under 4x, but the per-class List row warns -> overall
        // ATTENTION even if the GLOBAL verdict is Healthy.
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            s3op("GetObject", 20, 200),
            s3op("GetObject", 22, 200),
            s3op("GetObject", 24, 200),
            s3op("ListObjectsV2", 120, 200), // 7x -> per-class warn
        ];
        let r = analyze(&recs);
        // global ttfb_new median over [20,22,24,120] = 23ms = 1.35x -> global Healthy.
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: false });
        // but the S3 domain flags ListObjectsV2 -> overall escalates.
        assert!(s3_labels_warn(&r).contains(&"ListObjectsV2 TTFB"));
        assert_eq!(r.overall_verdict(), Verdict::Attention);
        assert!(r.is_attention());
    }

    #[test]
    fn status_mix_separates_throttle_from_client_errors() {
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            s3op("GetObject", 30, 503),  // throttle
            s3op("GetObject", 30, 429),  // throttle too (shared classify_status)
            s3op("GetObject", 30, 403),  // client
            s3op("PutObject", 30, 500),  // server
        ];
        let r = analyze(&recs);
        let labels = s3_labels_warn(&r);
        // 429 and 503 both land in throttle via the shared classifier — NOT the 4xx bucket.
        assert!(labels.contains(&"throttling (429/503)"));
        assert!(labels.contains(&"client errors (4xx)"));
        assert!(labels.contains(&"server errors (5xx)"));
        // Assert the COUNTS, not just the labels: if 429 ever slid back into the 4xx bucket,
        // the labels would all still be present (503/403/500 each produce theirs independently),
        // so only the counts prove 429 is claimed by throttle and NOT double-counted as a 4xx.
        let count = |id: &str| {
            r.s3.iter().find(|x| x.id == id).and_then(|x| x.metric.value).unwrap_or(0.0)
        };
        assert_eq!(count("s3_throttle"), 2.0, "the 503 AND the 429 -> throttle");
        assert_eq!(count("s3_client_errors"), 1.0, "only the 403 -> 4xx (429 is NOT here)");
        assert_eq!(count("s3_server_errors"), 1.0, "the 500 -> 5xx");
        // NB: this run is Attention via the GLOBAL HTTP-errors row (every status here is
        // ≥400) — a status-mix warn can't escalate on its own, since any ≥400 op also
        // trips that global row. Genuine S3-ONLY escalation (a per-class TTFB warn on an
        // all-2xx, globally-Healthy run) is proved by the dedicated escalation test
        // `s3_warn_escalates_an_otherwise_healthy_global_verdict` above.
    }

    #[test]
    fn environment_estimate_reads_rtt_and_endpoint_flags() {
        let mk = |srtt: Option<u32>, cross: bool, vpce: bool| Connection {
            srtt_us: srtt,
            endpoint: Endpoint { cross_region: cross, via_vpce: vpce, ..Default::default() },
            ..Default::default()
        };

        // Sub-2 ms floor, no flags -> same-region, high confidence.
        let c = mk(Some(800), false, false);
        let e = estimate_environment(Some(0.8), "srtt", &[&c]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::SameRegion, Confidence::High));

        // 2-10 ms floor -> same-region, but only likely.
        let c = mk(Some(6_000), false, false);
        let e = estimate_environment(Some(6.0), "srtt", &[&c]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::SameRegion, Confidence::Likely));

        // Cross-region flag is authoritative even over a low floor.
        let c = mk(Some(800), true, false);
        let e = estimate_environment(Some(0.8), "srtt", &[&c]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::CrossRegion, Confidence::High));

        // A VPC endpoint at a low (2-10 ms) floor firms same-region up to High (vs Likely).
        let c = mk(Some(6_000), false, true);
        let e = estimate_environment(Some(6.0), "srtt", &[&c]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::SameRegion, Confidence::High));

        // But a VPC endpoint does NOT override a long floor: on-prem over Direct Connect to a
        // VPCe still reads far, not "same-region (in-cloud)".
        let c = mk(Some(45_000), false, true);
        assert_eq!(estimate_environment(Some(45.0), "srtt", &[&c]).unwrap().class, EnvClass::FarPath);

        // Heterogeneous capture (a near AND a far path) -> mixed, never one confident class.
        let near = mk(Some(1_000), false, false);
        let far = mk(Some(70_000), false, false);
        let e = estimate_environment(Some(35.0), "srtt", &[&near, &far]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::Mixed, Confidence::Uncertain));

        // But a >5x srtt ratio among small in-datacenter values is NOT "mixed" (both near).
        let a = mk(Some(200), false, false); // 0.2 ms
        let b = mk(Some(1_500), false, false); // 1.5 ms
        assert_eq!(estimate_environment(Some(0.85), "srtt", &[&a, &b]).unwrap().class, EnvClass::SameRegion);

        // A UNIFORMLY cross-region capture with a bimodal srtt (jitter) stays CrossRegion — the
        // authoritative flag must beat the spread heuristic, not read as "mixed".
        let x1 = mk(Some(12_000), true, false);
        let x2 = mk(Some(70_000), true, false);
        let e = estimate_environment(Some(35.0), "srtt", &[&x1, &x2]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::CrossRegion, Confidence::High));

        // Two distinct endpoint regions -> mixed even at a uniform low floor.
        let mkr = |region: &str| Connection {
            srtt_us: Some(1_000),
            endpoint: Endpoint { region: Some(region.into()), ..Default::default() },
            ..Default::default()
        };
        let (r1, r2) = (mkr("us-east-1"), mkr("eu-west-1"));
        assert_eq!(estimate_environment(Some(1.0), "srtt", &[&r1, &r2]).unwrap().class, EnvClass::Mixed);

        // A long floor with no flag -> the honest union, uncertain.
        let c = mk(Some(45_000), false, false);
        let e = estimate_environment(Some(45.0), "srtt", &[&c]).unwrap();
        assert_eq!((e.class, e.confidence), (EnvClass::FarPath, Confidence::Uncertain));
        assert!(e.line().starts_with("uncertain — "));

        // No floor AND no flag -> nothing to say.
        let c = mk(None, false, false);
        assert!(estimate_environment(None, "srtt", &[&c]).is_none());
        // No floor but a cross-region flag still speaks.
        let c = mk(None, true, false);
        assert_eq!(estimate_environment(None, "srtt", &[&c]).unwrap().class, EnvClass::CrossRegion);
    }

    #[test]
    fn environment_finding_is_unjudged_and_never_gates() {
        // A far-path capture: the estimate is emitted as an Unjudged FYI finding and does
        // NOT change the health verdict (still driven purely by the health rows).
        let op = Record::Operation(Operation {
            http_status: Some(200),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(45_000_000),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(45_000), 0, 1_000_000), op]);
        assert!(r.render(false).contains("environment: uncertain — WAN / on-premises"));
        let env = r.findings().into_iter().find(|f| f.finding_id == "environment").unwrap();
        assert!(matches!(env.severity, Severity::Unjudged));
        assert_eq!(env.verdict, "wan-or-cross-region");
    }

    #[test]
    fn sampled_floor_rescues_a_persistent_pool_from_no_baseline() {
        // A long-lived connection pool that closes NO connection during the capture: the ops
        // carry no close-time srtt (it lives on the connection record, read at close), so the
        // primary floor is absent. But --sample-interval-ms emitted in-flight TcpSamples with
        // a live min_rtt. The doctor must judge against that sampled floor, not NO BASELINE.
        let smp_rtt = |min_rtt: u32, srtt: u32| {
            Record::TcpSample(TcpSample {
                sock_cookie: 1,
                min_rtt_us: Some(min_rtt),
                srtt_us: Some(srtt),
                ..Default::default()
            })
        };
        let mut recs = vec![smp_rtt(900, 1_200), smp_rtt(950, 1_300)];
        recs.extend((0..6).map(|_| {
            Record::Operation(Operation {
                http_status: Some(200),
                ttfb_ns: Some(2_000_000), // ~2 ms over a 0.9 ms floor => healthy
                connection_reused: true,
                ..Default::default()
            })
        }));
        let r = analyze(&recs);
        assert!(r.baseline_rtt_us.is_some(), "the sampled min_rtt must supply a floor");
        assert_ne!(r.overall_verdict(), Verdict::NoBaseline);
        let out = r.render(false);
        assert!(out.contains("baseline RTT (min_rtt, sampled)"), "{out}");
        // The environment estimate must name the SAME source — never call a sampled min_rtt
        // floor "srtt" (the floor-source honesty this feature is about). Anchor on the floor
        // VALUE (0.9 ms) so the check pins the env row's own label, not an unrelated row that
        // happens to mention srtt (e.g. a bufferbloat/path row in a richer fixture).
        assert!(out.contains("min_rtt (sampled)"), "{out}");
        assert!(!out.contains("srtt 0.9"), "env row must not mislabel the min_rtt floor: {out}");
    }

    #[test]
    fn a_closed_connection_still_uses_the_close_time_srtt_floor() {
        // Parity guard: when a connection DID close, its close-time srtt is the floor (never
        // the sample), so existing captures are unchanged.
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            Record::TcpSample(TcpSample { sock_cookie: 1, min_rtt_us: Some(500), ..Default::default() }),
            op(30, 17, false, 200, false),
        ];
        let r = analyze(&recs);
        assert_eq!(r.baseline_rtt_us, Some(17_000));
        assert!(r.render(false).contains("baseline RTT (srtt)"));
    }

    #[test]
    fn crafted_s3_op_label_is_sanitized_before_render() {
        // s3_op comes from an untrusted JSONL stream (a file/pipe the doctor ingests);
        // a crafted one must not inject ANSI/CR/NUL into the rendered terminal output
        // (CWE-117 / Trojan Source) — review step-3.
        let op = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("Get\u{1b}[31mEVIL\r\u{0}\u{202e}".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), op]);
        let out = r.render(false);
        for bad in ['\u{1b}', '\r', '\u{0}', '\u{202e}'] {
            assert!(!out.contains(bad), "control/format char {bad:?} leaked into render output");
        }
        assert!(out.contains('\u{fffd}'), "unsafe chars replaced with U+FFFD");
    }

    #[test]
    fn get_throughput_is_advisory_and_does_not_escalate() {
        // A GetObject with a measured body: throughput row is Advisory, never Warn, so
        // a healthy capture stays HEALTHY.
        let op = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("GetObject".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            content_length: Some(2_097_152),   // 2 MiB
            download_ns: Some(100_000_000),     // 100 ms -> ~21 MB/s
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), op]);
        let tput = r.s3.iter().find(|x| x.label == "GetObject throughput").unwrap();
        assert_eq!(tput.mark, Mark::Advisory);
        assert!(tput.value.contains("MB/s"));
        assert!(!r.is_attention(), "an advisory must not escalate");
        assert_eq!(r.overall_verdict(), Verdict::Healthy { reuse_working: false });
    }

    #[test]
    fn no_s3_op_means_no_s3_rows() {
        // ops without an s3_op (e.g. socket-only capture) produce no per-class rows, so
        // the report is unchanged from the global (s3stats.py-parity) shape.
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)];
        let r = analyze(&recs);
        assert!(r.s3.is_empty());
    }

    #[test]
    fn single_op_capture_does_not_emit_a_confident_per_class_verdict() {
        // A lone fast GetObject (well under the floor multiple) must NOT read a confident ✓ —
        // one sample isn't proof the class is healthy. It degrades to Na "insufficient data",
        // does not count as a healthy row, and does not escalate. (A SLOW lone op is a separate
        // case: it still warns — see below.)
        let healthy = analyze(&[conn(Some(17_000), 0, 1_000_000), s3op("GetObject", 30, 200)]);
        let get = healthy.s3.iter().find(|x| x.label == "GetObject TTFB").expect("row");
        assert_eq!(get.mark, Mark::Na, "one fast op must not read a confident ✓: {:?}", get.mark);
        assert!(get.note.contains("insufficient data"), "note: {}", get.note);
        // An insufficient-data row is Unjudged: no judged-looking ratio/baseline on it.
        assert_eq!(get.metric.ratio_to_rtt, None, "Na row must not carry a ratio");
        assert!(!healthy.is_attention(), "a gated (unjudged) class must not escalate");

        // A lone op far above the floor (200 ms / 17 ms ≈ 11.8×) is a real outlier — NOT gated,
        // still warns and escalates, so a genuine single-op slowdown is never hidden.
        let slow = analyze(&[conn(Some(17_000), 0, 1_000_000), s3op("GetObject", 200, 200)]);
        let get = slow.s3.iter().find(|x| x.label == "GetObject TTFB").expect("row");
        assert_eq!(get.mark, Mark::Warn, "a lone slow op must still warn: {:?}", get.mark);
        assert!(slow.is_attention(), "a lone clear outlier must still escalate");
    }

    #[test]
    fn full_render_shows_judged_of_total_denominator() {
        // The full report must expose the denominator (judged N of M ops) the
        // same as --brief, so the reader can see how much of the capture backed the verdict.
        // One eligible GetObject + one excluded (partial) op -> "judged 1 of 2 operations".
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            op(30, 17, false, 200, false),
            op(30, 17, false, 200, true), // partial -> excluded
        ];
        let out = analyze(&recs).render(false);
        assert!(
            out.contains("judged 1 of 2 operations"),
            "full render must show the judged/total denominator:\n{out}"
        );
    }

    #[test]
    fn a_capture_with_no_operations_never_reads_as_a_real_green() {
        // The "green because it saw nothing" failure: a Go or rustls client, or any capture
        // taken without the uprobe caps, yields connection records and NO operation records.
        // The report then affirmed "HTTP errors 0 / 0 ✓ healthy — all operations 2xx/204" (a
        // claim over an EMPTY set) and, because the honesty tail was suppressed exactly when
        // the total was 0, was byte-identical to a real green apart from absent rows.
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000)]);
        assert_eq!(r.op_total(), 0);

        let errs = r.rows.iter().find(|x| x.id == "http_errors").expect("http_errors row");
        assert_eq!(errs.mark, Mark::Na, "nothing to affirm over an empty set");
        assert!(!errs.note.contains("all operations 2xx"), "{}", errs.note);
        assert_eq!(errs.metric.value, None, "0 of 0 is not a measured 0% error rate");

        let out = r.render(false);
        assert!(
            out.contains("(0 operations in this capture: only the network path was judged, not \
                          any S3 request)"),
            "the zero denominator must be stated:\n{out}"
        );
        // The verdict names the zero-op case outright. It used to fall through to CHECKS
        // PASSED, whose "no timeable operations" wording is about ops that were captured and
        // could not be timed — true here only vacuously, and green to a CI gate.
        assert!(out.contains("verdict: NO OPERATIONS"), "not a checks-passed fall-through:\n{out}");
        assert!(!out.contains("no timeable operations"), "and not blamed on partial ops:\n{out}");
        // The distinguishing test: the SAME shape of capture with an op reads differently.
        let with_ops = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, true, 200, false)]);
        assert!(with_ops.render(false).contains("(judged 1 of 1 operations)"));

        // ...and the machine roll-up must not publish Healthy to a fleet ingest either.
        let f = r.findings();
        let run = f.iter().find(|x| x.finding_id == "run").unwrap();
        assert_eq!(run.severity, Severity::Unjudged, "judged nothing -> not Healthy");
        // The verdict itself now carries the fact (it used to be a suffix bolted onto a
        // CHECKS PASSED summary). The run sample is Mixed, so its `judged: 1` is the one
        // CONNECTION — which is exactly why the verdict has to say the op count is zero.
        assert_eq!(run.verdict, "NO OPERATIONS");
        assert!(run.summary.contains("nothing at the S3 layer was judged"), "{}", run.summary);
        let http = f.iter().find(|x| x.finding_id == "http_errors").unwrap();
        assert_eq!((http.severity, http.value.clone(), http.sample.judged), (Severity::Unjudged, None, 0));
    }

    #[test]
    fn a_capture_whose_operations_were_all_aborted_cannot_affirm_zero_http_errors() {
        // The other half of "green because it saw nothing", and the one the `ops.is_empty()`
        // guard above missed. 5 operations were decoded but NONE was answered — the shape
        // `flush_open_ops` emits at SIGINT. The error numerator is `http_status.is_some_and(…)`,
        // so its 0 is a construction, not a measurement, yet the row printed
        // "HTTP errors 0 / 5 ✓ healthy — all operations 2xx/204" and the finding published
        // `value: 0.0` beside `sample.judged: 0`, i.e. a 0/0 NaN for anyone rating it.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..5).map(|_| {
            Record::Operation(Operation {
                ttfb_ns: Some(30_000_000), // a 100-continue interim; the response never came
                connection_reused: true,
                ..Default::default()
            })
        }));
        let r = analyze(&recs);
        assert_eq!((r.op_statused, r.op_total()), (0, 5), "5 ops decoded, none answered");

        let errs = r.rows.iter().find(|x| x.id == "http_errors").expect("http_errors row");
        assert_eq!(errs.mark, Mark::Na, "nothing to affirm when nothing was answered");
        assert_eq!(errs.metric.value, None, "0 of 0 ANSWERED ops is not a measured 0% rate");
        assert!(!errs.note.contains("all operations 2xx"), "{}", errs.note);
        assert!(errs.note.contains("none of the 5 operations"), "names the shape: {}", errs.note);

        let out = r.render(false);
        assert!(!out.contains("0 / 5"), "no affirmative count over an unanswered set:\n{out}");
        assert!(out.contains("(judged 0 of 5 operations)"), "the denominator is stated:\n{out}");

        let f = r.findings();
        let http = f.iter().find(|x| x.finding_id == "http_errors").unwrap();
        assert_eq!(
            (http.severity, http.value.clone(), http.sample.judged),
            (Severity::Unjudged, None, 0),
            "an unjudgeable reliability row publishes no value to divide by its empty population"
        );
        // The run verdict is deliberately NOT widened to NO OPERATIONS here: 5 requests WERE
        // decoded, so that verdict's "no S3 request was decoded — re-capture with
        // --capture-plaintext" remedy would be wrong. It must also not read as CHECKS
        // PASSED (exit 0, the same bucket as HEALTHY): 0 of 5 answered is a missing
        // denominator exactly like 0 raw operations is, so it gets its OWN verdict/exit
        // code (2, alongside NO BASELINE/NO OPERATIONS) with the true remedy named.
        assert_eq!(r.overall_verdict(), Verdict::NoResponses);
        assert!(
            out.contains("operations were decoded but not one ever received an answer"),
            "the true condition is named:\n{out}"
        );
    }

    #[test]
    fn the_rtt_floor_finding_is_connection_kinded_never_mixed() {
        // `baseline_rtt` was SampleKind::Mixed on the claim that it blends conn + op records
        // (both carry srtt). No operation ever carries one — `build_op` pins the field null —
        // and every branch setting floor_judged/floor_excluded counts connections or samples.
        // A fleet ingest reading `kind: "mixed"` was told this floor blends a population it
        // never blends. (The COUNTS were already right; only the kind lied.)
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            conn(None, 0, 1_000_000), // could have supplied a floor and didn't -> excluded
            op(30, 17, false, 200, false),
            op(30, 17, true, 200, false),
        ];
        let f = analyze(&recs).findings();
        let floor = f.iter().find(|x| x.finding_id == "baseline_rtt").expect("floor finding");
        assert_eq!(
            (floor.sample.kind, floor.sample.judged, floor.sample.excluded),
            (SampleKind::Connection, 1, 1),
            "1 of 2 CONNECTIONS supplied the floor; the 2 operations are in neither count"
        );
        // The sampled fallback rests on s3tap.sample/1 records, which are per-connection
        // telemetry — Connection there too, exactly like retransmit_rate's own fallback.
        let sampled = analyze(&[Record::TcpSample(TcpSample {
            sock_cookie: 1,
            min_rtt_us: Some(4_000),
            ts_ns: Some(1_000),
            ..Default::default()
        })])
        .findings();
        let sf = sampled.iter().find(|x| x.finding_id == "baseline_rtt").expect("sampled floor");
        assert_eq!((sf.sample.kind, sf.sample.judged), (SampleKind::Connection, 1));
    }

    #[test]
    fn dns_cold_is_reported_but_never_gates() {
        // Round 1 removed the invented "< 50 ms" DNS threshold: there is no honest absolute
        // bound (a clean on-prem/WAN capture resolves slowly and is not sick) and no
        // RTT-relative one either — the resolver sits on a different path than the S3 endpoint,
        // so a sub-ms floor would make a routine 15 ms recursive resolve read as 30xRTT. The row
        // is therefore pure telemetry (Mark::Fyi), and a HUGE cold resolve must move NOTHING:
        // not the ⚠ set, not the verdict, not --strict (Fyi is not Advisory), not the finding
        // severity. Load-bearing and, until now, pinned by nothing.
        let slow_dns = Record::Operation(Operation {
            http_status: Some(200),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            dns: Some(Dns {
                latency_ns: 5_000_000_000, // 5 SECONDS
                cache_hit: false,
                resolved_ip: None,
                n_answers: 1,
                ttl_s: None,
                via: "wire".into(),
            }),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), slow_dns]);
        let row = r.rows.iter().find(|x| x.id == "dns_cold").expect("dns_cold row");
        assert_eq!(row.value.trim(), "5000.0 ms", "reported verbatim: {}", row.value);
        assert_eq!(row.mark, Mark::Fyi);
        assert!(warns(&r).is_empty(), "a 5 s resolve is telemetry, not a ⚠: {:?}", warns(&r));
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: false });
        assert_eq!(r.overall_verdict(), Verdict::Healthy { reuse_working: false });
        assert!(!r.is_attention(), "Fyi never escalates");
        assert!(!r.has_advisory(), "...and is not Advisory either, so --strict cannot gate on it");
        let f = r.findings().into_iter().find(|x| x.finding_id == "dns_cold").unwrap();
        assert_eq!(f.severity, Severity::Unjudged);
    }

    #[test]
    fn s3_ttfb_row_is_na_without_a_floor() {
        // An s3_op-bearing op but NO srtt anywhere: the per-class S3 TTFB row must be Na
        // (the no-floor corollary — never a false ✓/⚠ without a floor), it must not count
        // as an S3 warn, and the run stays NoBaseline. Guards the s3_domain None arm,
        // which is a separate code path from the global ratio_row Na branch.
        let r = analyze(&[s3op("GetObject", 30, 200)]);
        let row = r.s3.iter().find(|x| x.label == "GetObject TTFB").unwrap();
        assert_eq!(row.mark, Mark::Na);
        assert!(s3_labels_warn(&r).is_empty());
        assert_eq!(r.overall_verdict(), Verdict::NoBaseline);
    }

    // --- step 4: --json finding/1 projection --------------------------------------

    #[test]
    fn findings_cover_every_row_plus_the_run_rollup() {
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            s3op("GetObject", 30, 200),
            s3op("ListObjectsV2", 200, 200),
        ];
        let r = analyze(&recs);
        let f = r.findings();
        // one per global row + tail row + S3 row + the environment FYI (this capture has an
        // srtt floor, so it's present) + exactly one run roll-up (last).
        assert_eq!(
            f.len(),
            r.rows.len() + r.tail.len() + r.s3.len() + usize::from(r.environment.is_some()) + 1
        );
        let run = f.last().unwrap();
        assert_eq!(run.domain, Domain::Run);
        assert_eq!(run.finding_id, "run");
        assert_eq!(run.verdict, r.overall_verdict().keyword());
        assert_eq!(run.severity, Severity::Warn); // ListObjectsV2 is 11.8× -> attention
    }

    #[test]
    fn finding_carries_the_structured_rtt_judgment() {
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(200, 17, false, 200, false)];
        let f = analyze(&recs).findings();
        let ttfb = f.iter().find(|x| x.finding_id == "ttfb_new").unwrap();
        assert_eq!(ttfb.domain, Domain::Network);
        assert_eq!(ttfb.severity, Severity::Warn); // 11.8× over the floor
        assert_eq!(ttfb.unit, Unit::Ms);
        assert_eq!(ttfb.baseline_rtt_us, Some(17_000));
        assert!(ttfb.ratio_to_rtt.unwrap() > 4.0);
        assert!(matches!(ttfb.value, Some(MetricValue::Num(_))));
        // http_errors is a Client-domain check, not Network.
        let errs = f.iter().find(|x| x.finding_id == "http_errors").unwrap();
        assert_eq!(errs.domain, Domain::Client);
        // a non-latency check carries no RTT baseline.
        assert_eq!(errs.baseline_rtt_us, None);
        assert_eq!(errs.ratio_to_rtt, None);
    }

    #[test]
    fn s3_finding_scope_names_the_op_class() {
        // 3 GetObject ops so the class clears the min-sample gate and is actually judged.
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            s3op("GetObject", 30, 200),
            s3op("GetObject", 30, 200),
            s3op("GetObject", 30, 200),
        ];
        let f = analyze(&recs).findings();
        let get = f.iter().find(|x| x.finding_id == "s3_ttfb").unwrap();
        assert_eq!(get.domain, Domain::S3);
        assert_eq!(get.scope.s3_op.as_deref(), Some("GetObject"));
        // The S3 TTFB enrichment is a separate Metric literal from the global ratio_row,
        // so pin its RTT judgment too: 30ms / 17ms floor = 1.76× against the same floor.
        assert_eq!(get.unit, Unit::Ms);
        assert_eq!(get.baseline_rtt_us, Some(17_000));
        assert!((get.ratio_to_rtt.unwrap() - 30.0 / 17.0).abs() < 1e-6);
    }

    #[test]
    fn findings_round_trip_through_serde() {
        // The fleet-ingest format must survive the same string-u64 serde as the records.
        // The capture is chosen to cover every finding variant: an Unjudged baseline row,
        // a warn latency (Ms/ratio), a status-mix Count (the 503), a GET with a measured
        // body (the BytesPerS advisory — a large-magnitude f64, the only BytesPerS path),
        // and the null-value run roll-up.
        let getobj = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("GetObject".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            content_length: Some(2_097_152), // 2 MiB
            download_ns: Some(100_000_000),  // 100 ms -> ~21 MB/s -> BytesPerS finding
            ..Default::default()
        });
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            op(200, 17, false, 200, false),
            s3op("ListObjectsV2", 30, 503),
            getobj,
        ];
        let findings = analyze(&recs).findings();
        // sanity: the BytesPerS advisory really is in the set we're round-tripping.
        assert!(findings.iter().any(|f| f.unit == Unit::BytesPerS));
        // round-trip this capture AND the degenerate empty-input report (only the
        // unconditional rows + the run roll-up).
        for f in findings.into_iter().chain(analyze(&[]).findings()) {
            let json = serde_json::to_string(&f).expect("serialize finding");
            let back: Finding = serde_json::from_str(&json).expect("round-trip finding");
            assert_eq!(back, f);
        }
    }

    #[test]
    fn crafted_s3_op_is_sanitized_in_a_finding_scope() {
        // JSON escapes control chars, but a downstream terminal consumer of the scope is
        // still protected: scope.s3_op is sanitized just like the label (CWE-117).
        let op = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("Get\u{1b}\u{202e}".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            ..Default::default()
        });
        let f = analyze(&[conn(Some(17_000), 0, 1_000_000), op]).findings();
        let s3 = f.iter().find(|x| x.finding_id == "s3_ttfb").unwrap();
        let scope = s3.scope.s3_op.as_deref().unwrap();
        assert!(!scope.contains('\u{1b}') && !scope.contains('\u{202e}'));
    }

    #[test]
    fn run_finding_severity_maps_every_verdict_branch() {
        // The run roll-up severity is verdict_severity(overall) — pin all four branches at
        // the FINDING level (the Attention arm is covered above). A NoBaseline run must map
        // to Unjudged, NEVER Healthy: a false-green is the honesty failure the honesty rules
        // forbid. ChecksPassed/Healthy are both a pass (groups them at exit 0).
        let run_finding = |recs: &[Record]| {
            let f = analyze(recs).findings();
            f.into_iter().find(|x| x.finding_id == "run").unwrap()
        };

        let healthy = run_finding(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        assert_eq!(healthy.severity, Severity::Healthy);
        assert_eq!(healthy.verdict, "HEALTHY");

        let no_baseline = run_finding(&[op(30, 17, false, 200, false)]); // no srtt anywhere
        assert_eq!(no_baseline.severity, Severity::Unjudged);
        assert_eq!(no_baseline.verdict, "NO BASELINE");
        assert_eq!(no_baseline.baseline_rtt_us, None);

        // floor present but every op partial -> CHECKS PASSED, still a pass (Healthy).
        let checks = run_finding(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, true)]);
        assert_eq!(checks.severity, Severity::Healthy);
        assert_eq!(checks.verdict, "CHECKS PASSED");
    }

    #[test]
    fn ambiguous_op_is_excluded_from_latency_and_counted_in_the_denominator() {
        // A delimitation:ambiguous op (a 2nd request raced the response, so
        // its timing isn't attributable) must NOT feed latency medians and must land in
        // the excluded count. The ambiguous op below carries a wild 900ms ttfb that, if it
        // leaked into ttfb_new, would warn; eligibility must drop it.
        let clean = Record::Operation(Operation {
            http_status: Some(200),
            connection_reused: false,
            ttfb_ns: Some(30_000_000), // 30ms ~ 1.8× the floor -> healthy
            tcp_connect_ns: Some(17_000_000),
            ts_ns: Some(1_000),
            ..Default::default()
        });
        let ambiguous = Record::Operation(Operation {
            http_status: Some(200),
            connection_reused: false,
            ttfb_ns: Some(900_000_000), // 900ms — would be ~53× the floor if counted
            tcp_connect_ns: Some(17_000_000),
            ts_ns: Some(2_000),
            delimitation: Delimitation::Ambiguous,
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), clean, ambiguous]);
        // the ambiguous op's 900ms timing did NOT skew the verdict.
        assert!(warns(&r).is_empty(), "ambiguous timing leaked into a warn: {:?}", warns(&r));
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: false });
        // eligibility accounting: 1 judged (the clean op), 1 excluded (the ambiguous op).
        assert_eq!(r.op_judged, 1);
        assert_eq!(r.op_excluded, 1);
        // and that accounting reaches the finding Sample.
        let ttfb = r.findings().into_iter().find(|f| f.finding_id == "ttfb_new").unwrap();
        assert_eq!(ttfb.sample.judged, 1);
        assert_eq!(ttfb.sample.excluded, 1);
        // window spans the records' ts_ns (min .. max over all records that carry one).
        assert_eq!(ttfb.window.ts_start, 1_000);
        assert_eq!(ttfb.window.ts_end, 2_000);
    }

    // --- tail latency (p95) -------------------------------------------------------

    #[test]
    fn pctl_nearest_rank() {
        assert_eq!(pctl(vec![], 95.0), None);
        let xs: Vec<f64> = (1..=100).map(|n| n as f64).collect();
        assert_eq!(pctl(xs.clone(), 95.0), Some(95.0)); // rank ceil(0.95·100)=95 -> xs[94]
        assert_eq!(pctl(xs.clone(), 50.0), Some(50.0));
        assert_eq!(pctl(xs, 100.0), Some(100.0));
    }

    #[test]
    fn fat_tail_warns_via_p95_while_median_stays_healthy() {
        // 18 fast ops (~1.8×RTT) + 2 slow ops -> median ~30ms (healthy) but p95 ~300ms
        // (17×RTT). The tail must warn and escalate overall, while the GLOBAL (median)
        // verdict — the parity-pinned one — stays Healthy.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..18).map(|_| op(30, 17, false, 200, false)));
        recs.extend((0..2).map(|_| op(300, 17, false, 200, false)));
        let r = analyze(&recs);
        assert!(warns(&r).is_empty(), "global rows must not warn: {:?}", warns(&r));
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: false });
        let p95 = r.tail.iter().find(|x| x.id == "ttfb_new_p95").unwrap();
        assert_eq!(p95.mark, Mark::Warn);
        assert_eq!(r.overall_verdict(), Verdict::Attention);
        assert!(r.is_attention());
        // the tail finding is Network-domain, RTT-relative, and round-trips through serde.
        let tf = r.findings().into_iter().find(|f| f.finding_id == "ttfb_new_p95").unwrap();
        assert_eq!(tf.domain, Domain::Network);
        assert!(tf.ratio_to_rtt.unwrap() > TAIL_RTT_MULT);
        let json = serde_json::to_string(&tf).unwrap();
        assert_eq!(serde_json::from_str::<Finding>(&json).unwrap(), tf);
    }

    #[test]
    fn p99_tail_row_appears_only_with_enough_samples() {
        // 50 ops -> p95 only (>=20, <100). 100 ops -> p95 AND p99.
        let r50 = analyze(
            &(0..50).map(|_| op(30, 17, true, 200, false)).collect::<Vec<_>>(),
        );
        // (no floor here, so the rows are Na, but they still appear by id)
        assert!(r50.tail.iter().any(|x| x.id == "ttfb_reused_p95"));
        assert!(!r50.tail.iter().any(|x| x.id == "ttfb_reused_p99"));

        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..98).map(|_| op(30, 17, true, 200, false))); // fast
        recs.extend((0..2).map(|_| op(400, 17, true, 200, false))); // worst 1% (2 of 100)
        let r = analyze(&recs);
        let p95 = r.tail.iter().find(|x| x.id == "ttfb_reused_p95").unwrap();
        assert_eq!(p95.mark, Mark::Ok); // p95 = 30ms/17 = 1.8× -> still healthy
        let p99 = r.tail.iter().find(|x| x.id == "ttfb_reused_p99").unwrap();
        assert_eq!(p99.mark, Mark::Warn); // p99 = 400ms/17 = 23.5×RTT > 12× -> warn
        // The p99-only warn escalates the OVERALL verdict but leaves the parity verdict
        // Healthy (the superset contract, mirroring the p95 test).
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: true });
        assert_eq!(r.overall_verdict(), Verdict::Attention);
        assert!(r.is_attention());
    }

    #[test]
    fn tail_is_omitted_below_the_min_sample() {
        // A handful of ops -> no p95 row (the median still judges; a max isn't sold as p95).
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)];
        assert!(analyze(&recs).tail.is_empty());
    }

    #[test]
    fn tail_is_na_without_a_floor() {
        // Enough samples but no srtt -> the p95 row exists but is n/a (never a false ✓),
        // mirroring the median rows. Use reused ops so the reuse check stays
        // clean (100%) and the only verdict driver is the absent floor.
        let recs: Vec<Record> = (0..20).map(|_| op(30, 17, true, 200, false)).collect();
        let r = analyze(&recs);
        let p95 = r.tail.iter().find(|x| x.id == "ttfb_reused_p95").unwrap();
        assert_eq!(p95.mark, Mark::Na);
        assert_eq!(r.overall_verdict(), Verdict::NoBaseline);
    }

    // --- evidence + recommendation_ref (drill-down) -------------------------------

    fn op_with_id(status: u16, s3_op: &str, cookie: u64, req_seq: u32, aws_id: &str) -> Record {
        Record::Operation(Operation {
            op_id: format!("op-{cookie}-{req_seq}"),
            http_status: Some(status),
            s3_op: Some(s3_op.into()),
            sock_cookie: cookie,
            req_seq,
            aws_request_id: Some(aws_id.into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            ..Default::default()
        })
    }

    #[test]
    fn http_error_finding_carries_drill_down_evidence() {
        // The failing op's aws_request_id / cookie / op-id reach the finding so a consumer
        // can trace the verdict back to the exact request (the point of --json evidence).
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            op_with_id(403, "GetObject", 42, 7, "REQ-DENIED-123"),
        ];
        let errs = analyze(&recs)
            .findings()
            .into_iter()
            .find(|f| f.finding_id == "http_errors")
            .unwrap();
        assert_eq!(errs.evidence.aws_request_ids, vec!["REQ-DENIED-123"]);
        assert_eq!(errs.evidence.sock_cookies, vec!["42"]);
        assert_eq!(errs.evidence.op_ids, vec!["op-42-7"]); // the record's canonical op_id
    }

    #[test]
    fn throttle_finding_carries_evidence() {
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            op_with_id(503, "PutObject", 9, 1, "REQ-SLOWDOWN-9"),
        ];
        let f = analyze(&recs).findings();
        let throttle = f.iter().find(|x| x.finding_id == "s3_throttle").unwrap();
        assert_eq!(throttle.evidence.aws_request_ids, vec!["REQ-SLOWDOWN-9"]);
        // recommendation_ref is reserved/provisional — no finding populates it yet.
        assert_eq!(throttle.recommendation_ref, None);
    }

    #[test]
    fn evidence_is_capped_and_round_trips() {
        // 8 failing ops -> evidence is bounded to MAX_EVIDENCE; and a finding carrying
        // evidence still round-trips through serde.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend(
            (0..8).map(|i| op_with_id(500, "GetObject", 100 + i as u64, i, &format!("REQ-{i}"))),
        );
        let errs = analyze(&recs)
            .findings()
            .into_iter()
            .find(|f| f.finding_id == "http_errors")
            .unwrap();
        assert_eq!(errs.evidence.op_ids.len(), MAX_EVIDENCE);
        assert!(errs.evidence.aws_request_ids.len() <= MAX_EVIDENCE);
        let json = serde_json::to_string(&errs).unwrap();
        assert_eq!(serde_json::from_str::<Finding>(&json).unwrap(), errs);
    }

    #[test]
    fn aggregate_rows_carry_no_evidence() {
        // median/tail rows summarize a population, so they don't pin individual ops.
        let recs = vec![conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)];
        let ttfb = analyze(&recs)
            .findings()
            .into_iter()
            .find(|f| f.finding_id == "ttfb_new")
            .unwrap();
        assert!(ttfb.evidence.op_ids.is_empty());
    }

    // --- baseline diff ------------------------------------------------------------

    fn delta<'a>(d: &'a DiffReport, label: &str) -> &'a Delta {
        d.deltas.iter().find(|x| x.label == label).unwrap_or_else(|| panic!("no delta {label:?}"))
    }

    #[test]
    fn delta_carries_the_source_finding_id_for_identity_filtering() {
        // A new 4xx-error category appears in the current capture. The delta must expose the
        // source finding's stable id (not just the human title) so a consumer can filter
        // rows by identity rather than a brittle label match.
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 403, false)]);
        let d = diff(&cur, &base);
        let by_label = delta(&d, "client errors (4xx)");
        assert_eq!(by_label.id, "s3_client_errors");
        // and it is reachable by id alone.
        assert!(d.deltas.iter().any(|x| x.id == "s3_client_errors" && x.kind == DeltaKind::NewIssue));
    }

    #[test]
    fn diff_flags_a_latency_regression_by_ratio_not_raw_ms() {
        // Baseline: ttfb 30ms over a 17ms floor (1.8×). Current: ttfb 150ms over a 17ms
        // floor (8.8×) -> a real regression. Crucially this compares the RATIO.
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), op(150, 17, false, 200, false)]);
        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "TTFB, new conn").kind, DeltaKind::Regressed);
        assert!(d.regressed());
    }

    #[test]
    fn diff_absolute_ratio_noise_floor_ignores_a_single_spurious_retransmit() {
        // Lower-is-better raw ratios (retransmit_rate) have no RTT ratio, so before the
        // absolute min_delta floor the ±25% band collapsed off a 0 baseline (0 × 1.25 == 0)
        // and ANY nonzero current rate false-flagged a regression. Baseline: 0 retransmits
        // over 5 MB (~3424 segs) => rate 0.0. Current: a single retransmit the doctor itself
        // marks "clean" (1/3424 ≈ 0.00029 < RTX_RATE_MAX 0.001). This is run-to-run noise,
        // NOT a regression — the Unit::Ratio noise floor must absorb it.
        let base = analyze(&[conn(Some(17_000), 0, 5_000_000)]);
        let cur = analyze(&[conn(Some(17_000), 1, 5_000_000)]);
        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "retransmit rate").kind, DeltaKind::Unchanged);
        assert!(!d.regressed(), "a single clean retransmit must not redden --baseline");

        // …but a genuine loss jump (50 retransmits => ~1.5%, well past the 0.1% threshold)
        // still flags — the floor absorbs noise without masking real regressions.
        let loss = analyze(&[conn(Some(17_000), 50, 5_000_000)]);
        let d2 = diff(&loss, &base);
        assert_eq!(delta(&d2, "retransmit rate").kind, DeltaKind::Regressed);
        assert!(d2.regressed());
    }

    #[test]
    fn diff_is_fair_across_different_network_floors() {
        // Same RELATIVE health (both ~1.8×RTT) but very different raw ms because the floor
        // differs (17ms vs 85ms). Comparing ratios, this is NOT a regression — the whole
        // point of RTT-relative diffing.
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let cur = analyze(&[conn(Some(85_000), 0, 1_000_000), op(150, 85, false, 200, false)]);
        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "TTFB, new conn").kind, DeltaKind::Unchanged);
        assert!(!d.regressed());
    }

    #[test]
    fn diff_flags_a_new_error_category_as_a_new_issue() {
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 403, false)]);
        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "client errors (4xx)").kind, DeltaKind::NewIssue);
        assert!(d.regressed());
        // and the overall verdict worsened Healthy -> Attention.
        assert!(verdict_rank(d.current_verdict) > verdict_rank(d.baseline_verdict));
    }

    /// A capture of `n` reused 200-ops of which `errs` are HTTP 500s — the shape the
    /// reliability-diff tests need (a whole-op population with a known error RATE).
    fn capture_with_errors(n: usize, errs: usize) -> Report {
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..errs).map(|_| op(30, 17, true, 500, false)));
        recs.extend((0..n - errs).map(|_| op(30, 17, true, 200, false)));
        analyze(&recs)
    }

    #[test]
    fn diff_judges_reliability_as_a_rate_not_a_raw_count() {
        // Growing the workload must not redden --baseline when reliability IMPROVED.
        // Baseline: 100 ops with 2x HTTP 500 = 2.0%. Current: 400 ops with 6x HTTP 500 = 1.5%.
        // Compared as raw COUNTS, 6 > 2*1.25 and 6-2 >= min_delta(1) => "Regressed", REGRESSED,
        // exit 1 — on a capture that got BETTER. Nothing warned either: comparability_caveat
        // needs 5x (400 < 500). Compared as the honest error RATE it is a small improvement
        // inside the noise band.
        let (base, cur) = (capture_with_errors(100, 2), capture_with_errors(400, 6));
        let d = diff(&cur, &base);
        assert!(d.caveat.is_none(), "400 vs 100 ops does not trip the dissimilar-workload caveat");
        for label in ["HTTP errors", "server errors (5xx)"] {
            let x = delta(&d, label);
            assert_eq!(x.kind, DeltaKind::Unchanged, "{label}: 2.0% -> 1.5% is not a regression");
            // ...while the DISPLAY still shows the raw counts the operator counted.
            assert_eq!((x.baseline, x.current), (Some(2.0), Some(6.0)), "{label} display");
        }
        assert!(!d.regressed(), "a capture whose error rate improved must not fail the gate");
    }

    #[test]
    fn diff_still_flags_a_genuine_error_rate_regression() {
        // The teeth the rate normalization must keep: same 100-op population, 1% -> 10%. Past
        // the +25% band and past the one-op rate floor (0.01) => Regressed, and it gates.
        let (base, cur) = (capture_with_errors(100, 1), capture_with_errors(100, 10));
        let d = diff(&cur, &base);
        for label in ["HTTP errors", "server errors (5xx)"] {
            assert_eq!(delta(&d, label).kind, DeltaKind::Regressed, "{label}: 1% -> 10%");
        }
        assert!(d.regressed(), "a real error-rate regression must still fail the gate");
    }

    #[test]
    fn diff_rejudges_a_reliability_row_over_the_population_it_counted() {
        // Baseline: 4 ops, two of them 403 -> the client-error row counts over every ANSWERED
        // op (all four here, so sample.judged == 4) while op_judged is only 2 (a 403 is not
        // timeable — see `no_answered_op_cannot_resolve_a_reliability_warn` for the case where
        // the two populations differ in the other direction). Current: the
        // same 4-op workload with the 403s fixed (so the row is gone) and one op partial ->
        // op_judged 3, op_total 4. Testing the row's total-op denominator against op_judged
        // compared two different populations and called a FIXED check "unjudgeable (lost
        // floor)", exit 1 — with a bar that RISES with the baseline's error count. Re-judged
        // over the population the row itself counted: 4 >= 4 -> Resolved.
        let mut brecs = vec![conn(Some(17_000), 0, 1_000_000)];
        brecs.extend((0..2).map(|_| op(30, 17, true, 403, false)));
        brecs.extend((0..2).map(|_| op(30, 17, true, 200, false)));
        let base = analyze(&brecs);
        assert_eq!((base.op_judged, base.op_total()), (2, 4));
        let bf = base.findings().into_iter().find(|f| f.finding_id == "s3_client_errors").unwrap();
        assert_eq!((bf.sample.judged, bf.severity), (4, Severity::Warn));

        let mut crecs = vec![conn(Some(17_000), 0, 1_000_000)];
        crecs.extend((0..3).map(|_| op(30, 17, true, 200, false)));
        crecs.push(op(30, 17, true, 200, true)); // partial: eligible, not timeable
        let cur = analyze(&crecs);
        assert_eq!((cur.op_judged, cur.op_total()), (3, 4));
        assert!(!cur.s3.iter().any(|x| x.id == "s3_client_errors"), "the 4xx row is gone");

        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "client errors (4xx)").kind, DeltaKind::Resolved);
        assert!(!d.regressed(), "a fixed reliability check must not gate as lost signal");
    }

    #[test]
    fn no_answered_op_cannot_resolve_a_reliability_warn() {
        // The other side of the re-judge bar. Baseline: 4 ops, two 403s -> a client-error ⚠
        // over 4 answered ops. Current: the same 4 requests, ALL aborted in flight (no
        // http_status — routine since `flush_open_ops` emits the open ops at SIGINT), so the
        // 4xx row is simply absent. Nothing was re-judged: no op carried a status, so the
        // check is UNJUDGEABLE, not fixed. Against the old op_TOTAL bar (4 >= 4) this reported
        // "Resolved" and printed NO REGRESSION at exit 0 while the 403s may well still be
        // there — the exact shape of a gate that passes because it saw nothing.
        let mut brecs = vec![conn(Some(17_000), 0, 1_000_000)];
        brecs.extend((0..2).map(|_| op(30, 17, true, 403, false)));
        brecs.extend((0..2).map(|_| op(30, 17, true, 200, false)));
        let base = analyze(&brecs);

        let mut crecs = vec![conn(Some(17_000), 0, 1_000_000)];
        crecs.extend((0..4).map(|_| {
            Record::Operation(Operation {
                ttfb_ns: Some(30_000_000), // a 100-continue interim; the response never came
                connection_reused: true,
                ..Default::default()
            })
        }));
        let cur = analyze(&crecs);
        assert_eq!((cur.op_statused, cur.op_total()), (0, 4), "nothing was answered");

        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "client errors (4xx)").kind, DeltaKind::Unjudgeable);
        assert!(d.regressed(), "a reliability ⚠ nobody could re-judge must gate, not read green");
    }

    #[test]
    fn a_reliability_warn_the_current_capture_cannot_rate_is_never_unchanged() {
        // The matched-pair arm's loss-of-signal hole. Baseline: 100 answered ops, 20 of them
        // 503 -> an HTTP-errors ⚠ rated over 100. Current: the same 100 requests, ALL aborted
        // in flight, so there is no population to rate 0 errors over. `gate_value` returns None
        // and the arm fell through to Unchanged, rendering "HTTP errors 20 → 0 · unchanged":
        // a green row asserting the errors went away on a capture that could not judge them.
        // The exit code survived only incidentally, through a sibling row.
        //
        // Both halves are pinned here: the row's `Mark::Na` routes this to the Unjudged arm, and
        // the `(Some, None)` guard in the matched-pair arm is what keeps the answer Unjudgeable
        // if the row ever becomes judged-but-unrateable again. Reverting EITHER alone still
        // passes; reverting both reproduces the "20 → 0 · unchanged" row.
        let mut brecs = vec![conn(Some(17_000), 0, 1_000_000)];
        brecs.extend((0..20).map(|_| op(30, 17, true, 503, false)));
        brecs.extend((0..80).map(|_| op(30, 17, true, 200, false)));
        let base = analyze(&brecs);
        let bf = base.findings().into_iter().find(|f| f.finding_id == "http_errors").unwrap();
        assert_eq!((bf.severity, bf.sample.judged), (Severity::Warn, 100), "20/100 = 20% ⚠");

        let mut crecs = vec![conn(Some(17_000), 0, 1_000_000)];
        crecs.extend((0..100).map(|_| {
            Record::Operation(Operation {
                ttfb_ns: Some(30_000_000),
                connection_reused: true,
                ..Default::default()
            })
        }));
        let cur = analyze(&crecs);
        assert_eq!((cur.op_statused, cur.op_total()), (0, 100), "nothing was answered");

        let d = diff(&cur, &base);
        let errs = delta(&d, "HTTP errors");
        assert_eq!(errs.kind, DeltaKind::Unjudgeable, "lost signal, not a resolution");
        assert_eq!(errs.current, None, "a count nobody could rate is not a comparison point");
        assert!(d.regressed(), "an unjudgeable reliability ⚠ must gate");
        let out = d.render(false);
        assert!(!out.contains("20 →          0"), "no green 20 -> 0 row:\n{out}");
    }

    #[test]
    fn a_tail_row_with_too_few_floored_ops_says_so_instead_of_no_baseline() {
        // The mixed case, which is why `na_tail_row` words its note from the counts rather than
        // hardcoding one reason. No connection carries an srtt and there are no TcpSamples, so
        // the POOLED floor is None — but five connections carry a min_rtt, and an op joined to
        // one of those gets a floor from the cookie join. Result: 30 tail samples of which 5
        // are floored, which is above zero and below MIN_TAIL_SAMPLE. Telling that operator
        // "no srtt baseline" sends them hunting a probe failure that isn't there; the capture
        // has baselines, just not enough of them to take a percentile over.
        let mut recs: Vec<Record> = Vec::new();
        for c in 1..=5u64 {
            recs.push(Record::Connection(Connection {
                sock_cookie: c,
                srtt_us: None,
                min_rtt_us: Some(1_000),
                bytes_sent: 1_000_000,
                ..Default::default()
            }));
            recs.push(Record::Operation(Operation {
                sock_cookie: c,
                http_status: Some(200),
                ttfb_ns: Some(100_000_000),
                tcp_connect_ns: Some(17_000_000),
                ..Default::default()
            }));
        }
        // 25 more new-connection ops that join nothing and so can be floored by nothing.
        recs.extend((0..25).map(|_| Record::Operation(Operation {
            sock_cookie: 999,
            http_status: Some(200),
            ttfb_ns: Some(100_000_000),
            tcp_connect_ns: Some(17_000_000),
            ..Default::default()
        })));
        let r = analyze(&recs);
        let row = r.tail.iter().find(|x| x.id == "ttfb_new_p95").expect("a p95 row");
        assert_eq!(row.mark, Mark::Na, "{row:?}");
        // The PUBLISHED population is (0, 30), and that is not in tension with the note. The
        // row judged nothing, so claiming 5 judged would assert a denominator no verdict was
        // drawn from. `sample.judged` answers "how many did this row judge"; the note answers
        // "why couldn't it judge more". Different questions, both honest.
        assert_eq!(
            r.row_pop.iter().find(|(i, _, _)| *i == "ttfb_new_p95").map(|&(_, j, e)| (j, e)),
            Some((0, 30)),
            "an Na row judged nothing"
        );
        assert!(row.note.contains("only 5/30"), "must name the real reason: {}", row.note);
        assert!(!row.note.contains("no round-trip baseline"), "that reason is false here: {}", row.note);
        // "round-trip", not "srtt": these five ops were floored from `min_rtt`, and this is
        // the exact capture shape where naming srtt would be the second false statement.
        assert!(!row.note.contains("srtt"), "the baseline here is min_rtt: {}", row.note);
    }

    #[test]
    fn a_tail_row_whose_sub_population_shrank_is_unjudgeable_not_resolved() {
        // The vanish mode the sibling test CANNOT reach, and the reason a `row_pop` branch in
        // `cur_pop` was once removed as "dead code": when a tail row's sub-population falls
        // below MIN_TAIL_SAMPLE, `tail_rows` `continue`s BEFORE the Na branch, so the row is
        // genuinely absent rather than re-emitted — it reaches the vanished-warn loop, where
        // `op_judged` is a count from a different population entirely.
        //
        // Baseline: 25 new-conn ops, one 30x outlier -> p95 Warn, judged 25.
        // 25 samples: p95 is nearest-rank 24, so the top 4 decide the row.
        let mut base_recs = vec![conn(Some(1_000), 0, 1_000_000)];
        base_recs.extend((0..21).map(|_| op(2, 17, false, 200, false)));
        base_recs.extend((0..4).map(|_| op(30, 17, false, 200, false)));
        let base = analyze(&base_recs);
        assert_eq!(
            base.tail.iter().find(|r| r.id == "ttfb_new_p95").map(|r| r.mark),
            Some(Mark::Warn)
        );

        // Current: the new-conn tail is TEN TIMES WORSE, but only 19 new-conn ops survive, so
        // the row is not produced at all. 100 fast reused ops keep op_judged at 119, and
        // 119 >= 25 read as `Resolved` — a green diff over a 10x tail regression.
        let mut cur_recs = vec![conn(Some(1_000), 0, 1_000_000)];
        cur_recs.extend((0..15).map(|_| op(2, 17, false, 200, false)));
        cur_recs.extend((0..4).map(|_| op(300, 17, false, 200, false)));
        cur_recs.extend((0..100).map(|_| op(2, 17, true, 200, false)));
        let cur = analyze(&cur_recs);
        assert!(
            cur.tail.iter().all(|r| r.id != "ttfb_new_p95"),
            "the row must VANISH, not re-emit — otherwise this tests the other mode"
        );
        assert!(cur.op_judged >= 100, "op_judged stays high: {}", cur.op_judged);
        assert!(
            !cur.row_pop.iter().any(|(i, _, _)| *i == "ttfb_new_p95"),
            "and row_pop has no entry, which is what must read as population 0"
        );

        let d = diff(&cur, &base);
        let t = delta(&d, "TTFB p95, new conn");
        assert_eq!(t.kind, DeltaKind::Unjudgeable, "a vanished tail row is not a resolution");
        assert!(d.regressed(), "it must gate");
    }

    #[test]
    fn a_tail_row_that_lost_its_floor_is_unjudgeable_not_resolved() {
        // Baseline: 25 new-connection ops on a connection with a close-time srtt -> the p95
        // tail row is floored, judged = 25, and the TTFB is far enough above the floor to warn.
        let mut base_recs = vec![conn(Some(1_000), 0, 1_000_000)];
        base_recs.extend((0..25).map(|_| op(100, 17, false, 200, false)));
        let base = analyze(&base_recs);
        let p95 = base.tail.iter().find(|r| r.id == "ttfb_new_p95").expect("a p95 row");
        assert_eq!(p95.mark, Mark::Warn, "{p95:?}");

        // Current: the SAME 25 ops, but no record anywhere supplies a round-trip floor. The
        // ops are still timeable, so `op_judged` is still 25 — a count that says nothing about
        // whether this percentile could be judged. What saves the row is that it does not
        // vanish: it re-emits at the same id as an `Na` row publishing `judged: 0`, and the
        // ordinary delta path reads that as a loss of signal. Pinned here because the row's
        // Na-instead-of-vanish behaviour is the ONLY thing standing between a lost floor and a
        // green "resolved" on a percentile that was never recomputed.
        let mut cur_recs = vec![conn(None, 0, 1_000_000)];
        cur_recs.extend((0..25).map(|_| op(100, 17, false, 200, false)));
        let cur = analyze(&cur_recs);
        assert_eq!(cur.op_judged, 25, "the ops are still timeable");
        assert_eq!(
            cur.row_pop.iter().find(|(i, _, _)| *i == "ttfb_new_p95").map(|&(_, j, _)| j),
            Some(0),
            "nothing could be floored"
        );

        let d = diff(&cur, &base);
        let t = delta(&d, "TTFB p95, new conn");
        assert_eq!(t.kind, DeltaKind::Unjudgeable, "a lost floor is not a resolution");
        assert!(d.regressed(), "an unjudgeable tail ⚠ must gate");
    }

    #[test]
    fn a_vanished_op_class_warning_is_unjudgeable_not_resolved() {
        // Issue #9. Baseline warns on GetObject; the current capture has plenty of timeable
        // ops but not one GetObject. Answered with `op_judged` the vanished ⚠ read
        // "✓ resolved" at exit 0 — a lost sub-population reported as a fix.
        let mut base_recs = vec![conn(Some(1_000), 0, 1_000_000)];
        base_recs.extend((0..20).map(|_| {
            Record::Operation(Operation {
                s3_op: Some("GetObject".into()),
                http_status: Some(200),
                ttfb_ns: Some(100_000_000), // 100x the floor -> ⚠
                tcp_connect_ns: Some(1_000_000),
                connection_reused: true,
                ..Default::default()
            })
        }));
        let base = analyze(&base_recs);
        assert!(
            base.s3.iter().any(|r| r.id == "s3_ttfb" && r.mark == Mark::Warn),
            "the baseline must warn on GetObject: {:?}",
            base.s3
        );

        let mut cur_recs = vec![conn(Some(1_000), 0, 1_000_000)];
        cur_recs.extend((0..100).map(|_| {
            Record::Operation(Operation {
                s3_op: Some("PutObject".into()),
                http_status: Some(200),
                ttfb_ns: Some(2_000_000),
                tcp_connect_ns: Some(1_000_000),
                connection_reused: true,
                ..Default::default()
            })
        }));
        let cur = analyze(&cur_recs);
        assert!(cur.op_judged >= 100, "the current capture is rich in ops: {}", cur.op_judged);
        assert!(
            !cur.s3.iter().any(|r| r.s3_op.as_deref() == Some("GetObject")),
            "and holds no GetObject class at all"
        );

        let d = diff(&cur, &base);
        let t = delta(&d, "GetObject TTFB");
        assert_eq!(t.kind, DeltaKind::Unjudgeable, "a vanished class is not a resolution");
        assert!(d.regressed(), "and it must gate");
    }

    #[test]
    fn a_denominator_is_published_only_when_it_reproduces_the_ratio() {
        // Issue #24. `value`, `ratio_to_rtt` and the floor are three separate aggregations, so
        // they coincide only when every op shared one floor. On a mixed-floor class the
        // published median put `value / baseline` ~2x away from the ratio the verdict was made
        // on; the tail rows had the same shape, up to 200x apart.
        let quotient_matches = |recs: &[Record], id: &str| -> Option<bool> {
            let f = analyze(recs).findings().into_iter().find(|f| f.finding_id == id)?;
            let b = f.baseline_rtt_us? as f64 / 1000.0;
            let v = match f.value? {
                MetricValue::Num(n) => n,
                MetricValue::Str(_) => return None,
            };
            Some((v / b - f.ratio_to_rtt?).abs() < 1e-9)
        };

        // Uniform floor: the denominator is published AND reproduces the ratio exactly.
        let mut uni = vec![conn(Some(1_000), 0, 1_000_000)];
        uni.extend((0..25).map(|_| {
            Record::Operation(Operation {
                s3_op: Some("GetObject".into()),
                http_status: Some(200),
                ttfb_ns: Some(3_000_000),
                tcp_connect_ns: Some(1_000_000),
                connection_reused: true,
                ..Default::default()
            })
        }));
        assert_eq!(quotient_matches(&uni, "s3_ttfb"), Some(true), "uniform: exact");
        assert_eq!(quotient_matches(&uni, "ttfb_reused_p95"), Some(true), "uniform: exact");

        // Mixed floors: no denominator, so no consumer can compute a contradicting one.
        let mut mix = vec![
            conn_in_region(1, 1_000, "us-east-1"),
            conn_in_region(2, 70_000, "us-east-1"),
        ];
        for i in 0..25u64 {
            let (ck, ttfb) = if i % 2 == 0 { (1, 3_500_000) } else { (2, 80_000_000) };
            mix.push(Record::Operation(Operation {
                sock_cookie: ck,
                s3_op: Some("GetObject".into()),
                http_status: Some(200),
                ttfb_ns: Some(ttfb),
                tcp_connect_ns: Some(1_000_000),
                connection_reused: true,
                ..Default::default()
            }));
        }
        let mixed = analyze(&mix);
        for id in ["s3_ttfb", "ttfb_reused_p95"] {
            let f = mixed.findings().into_iter().find(|f| f.finding_id == id);
            if let Some(f) = f {
                assert!(
                    f.baseline_rtt_us.is_none(),
                    "{id} must publish no denominator on mixed floors: {:?}",
                    f.baseline_rtt_us
                );
            }
        }
    }

    #[test]
    fn a_two_region_capture_refuses_the_pooled_floor_instead_of_blending() {
        // us-east at 1 ms and ap-southeast at 200 ms pool to a ~100 ms median that fits
        // neither. An op that cannot be attributed to a region was judged against it, so a
        // real 300 ms TTFB read "✓ expected 3.0×RTT (vs its own 100.5 ms floor)" — a floor
        // that is WRONG rather than absent, which is the false-healthy direction this file
        // refuses everywhere else.
        let mut recs = vec![
            Record::Connection(Connection {
                sock_cookie: 1,
                srtt_us: Some(1_000),
                bytes_sent: 1_000_000,
                endpoint: Endpoint { region: Some("us-east-1".into()), ..Default::default() },
                ..Default::default()
            }),
            Record::Connection(Connection {
                sock_cookie: 2,
                srtt_us: Some(200_000),
                bytes_sent: 1_000_000,
                endpoint: Endpoint { region: Some("ap-southeast-2".into()), ..Default::default() },
                ..Default::default()
            }),
        ];
        // Ops on cookie 999, which joins neither connection.
        // `connection_reused: true` so the reuse row is healthy and cannot warn — otherwise
        // Attention outranks and the verdict assertion below tests nothing.
        recs.extend((0..25).map(|_| {
            Record::Operation(Operation {
                sock_cookie: 999,
                http_status: Some(200),
                ttfb_ns: Some(300_000_000),
                tcp_connect_ns: Some(1_000_000),
                connection_reused: true,
                ..Default::default()
            })
        }));
        let r = analyze(&recs);

        let row = |id: &str| r.rows.iter().find(|x| x.id == id).map(|x| x.mark);
        // Every op here is on a reused connection, so the reused row is the one emitted.
        assert_eq!(row("ttfb_reused"), Some(Mark::Na), "a blended floor must not judge: {:?}", r.rows);
        assert_eq!(row("tcp_connect"), Some(Mark::Na));
        // The floor is still REPORTED — withholding it from the rows must not delete the one
        // line that says what was measured and why nothing is judged against it.
        assert_eq!(row("baseline_rtt"), Some(Mark::Na));
        assert!(
            r.rows.iter().any(|x| x.id == "baseline_rtt" && x.note.contains("NOT used as a floor")),
            "the baseline row must say why"
        );
        // And the run is NOT reported as having no floor: it has one, it is just not a
        // denominator. Claiming "no connection closed in the window" here would be false.
        assert_ne!(r.verdict, Verdict::NoBaseline, "a blend is not an absent floor");

        // The VERDICT itself, not just the rows: a capture where the blend was withheld and
        // nothing ended up judged must not read green.
        assert_eq!(r.overall_verdict(), Verdict::MixedPaths, "rows all Na, so the run is not judgeable");
        assert_eq!(verdict_severity(r.overall_verdict()), Severity::Unjudged);

        // Precedence, pinned deliberately rather than left to branch order: both are exit 2,
        // but `NoResponses` is the sharper diagnosis. If no operation was ever answered that is
        // the operator's actual problem, and no op was timeable anyway — "mixed paths" would be
        // true and useless. Same two-region capture, statuses removed.
        let unanswered: Vec<Record> = recs
            .iter()
            .cloned()
            .map(|r| match r {
                Record::Operation(mut o) => {
                    o.http_status = None;
                    Record::Operation(o)
                }
                other => other,
            })
            .collect();
        assert_eq!(
            analyze(&unanswered).overall_verdict(),
            Verdict::NoResponses,
            "NoResponses outranks MixedPaths"
        );

        // One region: nothing changes.
        let mut single = vec![Record::Connection(Connection {
            sock_cookie: 1,
            srtt_us: Some(1_000),
            bytes_sent: 1_000_000,
            endpoint: Endpoint { region: Some("us-east-1".into()), ..Default::default() },
            ..Default::default()
        })];
        single.extend((0..25).map(|_| {
            Record::Operation(Operation {
                sock_cookie: 999,
                http_status: Some(200),
                ttfb_ns: Some(300_000_000),
                tcp_connect_ns: Some(1_000_000),
                connection_reused: true,
                ..Default::default()
            })
        }));
        let s = analyze(&single);
        assert_eq!(
            s.rows.iter().find(|x| x.id == "ttfb_reused").map(|x| x.mark),
            Some(Mark::Warn),
            "a single-path capture still judges against the pooled floor"
        );
    }

    #[test]
    fn every_row_publishes_the_population_it_actually_measured() {
        // The bug class found three separate times in one day: a row's `sample` reporting
        // `op_judged` rather than the subset its verdict came from. 5 new-connection ops and
        // 95 reused ones, so no two of these rows share a population — and every one of them
        // published 100 before the sweep, including a ⚠ drawn from 5 ops.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..5).map(|_| op(30, 17, false, 200, false)));
        recs.extend((0..95).map(|_| op(30, 17, true, 200, false)));
        let r = analyze(&recs);
        let pop = |id: &str| {
            r.findings()
                .into_iter()
                .find(|f| f.finding_id == id)
                .map(|f| (f.sample.judged, f.sample.excluded))
        };
        // `excluded` = candidates dropped, never "the rest of the capture". Every new-conn op
        // here carries a TTFB, so nothing was dropped from either population; the 95 reused ops
        // are a different population, not an exclusion from this one.
        assert_eq!(pop("ttfb_new"), Some((5, 0)), "5 new-conn ops, all of them judged");
        assert_eq!(pop("ttfb_reused"), Some((95, 0)));
        assert_eq!(pop("tcp_connect"), Some((100, 0)), "every op carries a connect time here");
        // And a row missing from `row_pop` must not silently borrow `op_judged`.
        assert!(
            r.row_pop.iter().any(|(i, _, _)| *i == "ttfb_new"),
            "the sweep must register these rows: {:?}",
            r.row_pop
        );
    }

    #[test]
    fn reuse_counts_non_partial_ops_and_the_json_agrees_with_the_row() {
        // A warm keep-alive pool attached to mid-flight: the first op S3TAP sees on each
        // socket is `partial` and reports `connection_reused: false`, because `req_seq`
        // counts from the first request S3TAP saw, not the socket's first. 14 of those beside
        // 6 genuinely reused ops turned a healthy pool into "0/20 ops reused ⚠ low".
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..6).map(|_| op(30, 17, true, 200, false)));
        recs.extend((0..14).map(|_| op(30, 17, false, 200, true)));
        let r = analyze(&recs);

        let row = r.reuse.as_ref().expect("a reuse row");
        assert_eq!(row.mark, Mark::Ok, "6/6 non-partial ops reused is a healthy pool: {row:?}");
        assert!(row.note.contains("6/6 ops reused"), "{}", row.note);
        assert_eq!(r.op_nonpartial, 6);

        // And the JSON must publish the SAME denominator the row printed. It once said
        // judged: 20 beside a row reading 6/6 — one capture, two populations, and a
        // `--baseline` diff drawn from whichever the reader happened to trust.
        let f = r
            .findings()
            .into_iter()
            .find(|f| f.finding_id == "reuse_rate")
            .expect("a reuse finding");
        assert_eq!((f.sample.judged, f.sample.excluded), (6, 14), "{:?}", f.sample);
        assert_eq!(f.value, Some(MetricValue::Num(1.0)), "{:?}", f.value);
    }

    #[test]
    fn environment_finding_does_not_mask_a_baseline_regression() {
        // Baseline: 6 non-reused ops -> the connection-reuse row warns (judged = 6).
        let mut base_recs = vec![conn(Some(17_000), 0, 1_000_000)];
        base_recs.extend((0..6).map(|_| op(30, 17, false, 200, false)));
        let base = analyze(&base_recs);
        assert!(base.reuse.as_ref().is_some_and(|r| r.mark == Mark::Warn));

        // Current: only 3 eligible ops (reuse row vanishes, < MIN_REUSE_SAMPLE) but 6
        // connection records -> the environment FYI finding's judged == conn_count == 6. If
        // that fed the diff's cur_pop it would mark the vanished reuse warn "Resolved" (6 >= 6)
        // and pass the gate; excluded, cur_pop == 3 < 6 -> Unjudgeable -> a real regression.
        let mut cur_recs: Vec<Record> = (0..6).map(|_| conn(Some(17_000), 0, 1_000_000)).collect();
        cur_recs.extend((0..3).map(|_| op(30, 17, false, 200, false)));
        let cur = analyze(&cur_recs);
        assert!(cur.reuse.is_none(), "reuse row must vanish below the min sample");
        assert!(cur.environment.is_some(), "the far-path env finding must be present");

        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "connection reuse").kind, DeltaKind::Unjudgeable);
        assert!(d.regressed(), "loss of the reuse signal must gate, not read as resolved");
    }

    #[test]
    fn diff_does_not_read_green_when_ops_vanish_but_connections_remain() {
        // The broader loss-of-signal hole (beyond the environment FYI): a current capture
        // rich in CONNECTIONS but poor in OPS. Baseline: 6 non-reused ops -> reuse Warn
        // (judged = 6). Current: only 3 eligible ops (reuse vanishes) but 6 connections that
        // carry min_rtt -> a `path_min_rtt` finding whose judged == conn_count == 6 (a
        // Connection-sourced population, NOT the environment finding the old code excluded).
        // If cur_pop scanned that finding it would read 6 >= 6 -> Resolved (false green);
        // pinned to current.op_judged == 3 < 6 -> Unjudgeable, so the lost reuse signal gates.
        let mut base_recs = vec![conn(Some(17_000), 0, 1_000_000)];
        base_recs.extend((0..6).map(|_| op(30, 17, false, 200, false)));
        let base = analyze(&base_recs);
        assert_eq!(base.reuse.as_ref().unwrap().mark, Mark::Warn);

        let mut cur_recs: Vec<Record> = (0..6)
            .map(|_| {
                Record::Connection(Connection {
                    srtt_us: Some(17_000),
                    min_rtt_us: Some(17_000), // -> a path_min_rtt finding, judged = conn_count = 6
                    bytes_sent: 1_000_000,
                    ..Default::default()
                })
            })
            .collect();
        cur_recs.extend((0..3).map(|_| op(30, 17, false, 200, false)));
        let cur = analyze(&cur_recs);
        assert!(cur.reuse.is_none(), "reuse row must vanish below the min sample");
        assert!(
            cur.findings().iter().any(|f| f.finding_id == "path_min_rtt" && f.sample.judged == 6),
            "current must carry a non-environment conn-count finding to exercise the hole"
        );

        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "connection reuse").kind, DeltaKind::Unjudgeable);
        assert!(d.regressed(), "ops vanished; a conn-rich capture must not read the loss as resolved");
    }

    #[test]
    fn diff_surfaces_a_resolved_issue_and_does_not_regress() {
        // Baseline had a 403; current is clean -> Resolved, no regression.
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 403, false)]);
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "client errors (4xx)").kind, DeltaKind::Resolved);
        assert!(!d.regressed());
    }

    #[test]
    fn diff_does_not_regress_a_still_healthy_class_that_merely_shrank() {
        // A benign workload change must NOT fail --baseline. Baseline: a healthy GetObject
        // class (4 fast ops, ✓). Current: the SAME class still fast but only 2 ops, so the
        // min-sample gate degrades it to Na "insufficient data". That is NOT a regression —
        // the user just issued fewer GETs. The matched-pair diff must gate a current-Unjudged
        // as a loss-of-signal ONLY when the baseline was a WARN (a watched problem we can no
        // longer confirm), never when the baseline was healthy.
        let mut brecs = vec![conn(Some(17_000), 0, 1_000_000)];
        brecs.extend((0..4).map(|_| s3op("GetObject", 30, 200))); // 30/17 = 1.8x -> ✓
        let base = analyze(&brecs);
        assert_eq!(
            base.s3.iter().find(|x| x.label == "GetObject TTFB").unwrap().mark,
            Mark::Ok
        );

        let mut crecs = vec![conn(Some(17_000), 0, 1_000_000)];
        crecs.extend((0..2).map(|_| s3op("GetObject", 30, 200))); // still fast, but n<3 -> Na
        let cur = analyze(&crecs);
        assert_eq!(
            cur.s3.iter().find(|x| x.label == "GetObject TTFB").unwrap().mark,
            Mark::Na
        );

        let d = diff(&cur, &base);
        assert!(!d.regressed(), "a still-healthy class that merely shrank must not gate --baseline");
    }

    #[test]
    fn diff_does_not_read_green_when_a_check_is_suppressed_by_too_few_samples() {
        // Baseline: 10 eligible ops, none reused -> connection-reuse Warn (judged = 10).
        // Current: only 3 ops -> below MIN_REUSE_SAMPLE, so the reuse check VANISHES (no
        // row). Its absence is a LOSS OF SIGNAL, not a resolution: the diff must mark it
        // Unjudgeable and regress (gate), never report the reuse regression as fixed.
        let mut brecs = vec![conn(Some(17_000), 0, 1_000_000)];
        brecs.extend((0..10).map(|_| op(30, 17, false, 200, false)));
        let base = analyze(&brecs);
        let mut crecs = vec![conn(Some(17_000), 0, 1_000_000)];
        crecs.extend((0..3).map(|_| op(30, 17, false, 200, false)));
        let cur = analyze(&crecs);
        assert_eq!(base.reuse.as_ref().unwrap().mark, Mark::Warn);
        assert!(cur.reuse.is_none(), "current has too few ops to judge reuse");
        let d = diff(&cur, &base);
        assert_eq!(delta(&d, "connection reuse").kind, DeltaKind::Unjudgeable);
        assert!(d.regressed(), "a suppressed baseline warn must gate, not read green");
    }

    #[test]
    fn diff_renders_without_control_bytes_and_shows_the_verdict() {
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), op(150, 17, false, 200, false)]);
        let out = diff(&cur, &base).render(false);
        assert!(out.contains("REGRESSED"));
        assert!(out.contains("TTFB, new conn"));
        assert!(!out.contains('\u{1b}')); // no ANSI when color=false
    }

    #[test]
    fn diff_floor_loss_is_unjudgeable_not_resolved() {
        // Baseline judged ttfb_new as a Warn (11.8×RTT); the current capture has NO srtt
        // floor, so it can't judge that span. This must read as a LOST SIGNAL, never as
        // "resolved" (which would pass the CI gate green on a still-unknown latency). The
        // headline floor-loss honesty bug from the review.
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), op(200, 17, false, 200, false)]);
        let cur = analyze(&[op(200, 17, false, 200, false)]); // no conn -> NoBaseline
        let d = diff(&cur, &base);
        let ttfb = delta(&d, "TTFB, new conn");
        assert_eq!(ttfb.kind, DeltaKind::Unjudgeable);
        assert!(d.regressed(), "lost floor must not pass the gate green");
    }

    #[test]
    fn diff_advisory_throughput_drop_does_not_gate() {
        // A >25% GET-throughput drop is classified Regressed but is ADVISORY, so it must
        // NOT fail the --baseline gate (mirrors 'an Advisory never escalates' / --strict).
        let getobj = |dl_ms: u64| {
            Record::Operation(Operation {
                http_status: Some(200),
                s3_op: Some("GetObject".into()),
                ttfb_ns: Some(30_000_000),
                tcp_connect_ns: Some(17_000_000),
                content_length: Some(2_097_152),
                download_ns: Some(dl_ms * 1_000_000),
                ..Default::default()
            })
        };
        let base = analyze(&[conn(Some(17_000), 0, 1_000_000), getobj(100)]); // ~21 MB/s
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), getobj(250)]); // ~8 MB/s (drop)
        let d = diff(&cur, &base);
        let tput = delta(&d, "GetObject throughput");
        assert_eq!(tput.kind, DeltaKind::Regressed);
        assert_eq!(tput.severity, Severity::Advisory);
        assert!(!d.regressed(), "an advisory throughput drop must not fail the gate");
    }

    #[test]
    fn diff_caveats_dissimilar_workloads() {
        let mut base_recs = vec![conn(Some(17_000), 0, 1_000_000)];
        base_recs.extend((0..25).map(|_| op(30, 17, false, 200, false)));
        let base = analyze(&base_recs);
        let cur = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        let d = diff(&cur, &base);
        assert!(d.caveat.is_some(), "1 vs 25 ops should caveat as dissimilar");
        assert!(d.render(false).contains("dissimilar"));
    }

    #[test]
    fn evidence_harvests_aws_request_id_past_the_op_cap() {
        // The first MAX_EVIDENCE failing ops lack an aws_request_id; a later one carries it.
        // It must still be harvested (the support-ticket field is sporadic).
        let err = |i: u64, aws: Option<&str>| {
            Record::Operation(Operation {
                op_id: format!("op-{i}"),
                http_status: Some(500),
                sock_cookie: i,
                aws_request_id: aws.map(Into::into),
                ttfb_ns: Some(30_000_000),
                tcp_connect_ns: Some(17_000_000),
                ..Default::default()
            })
        };
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..MAX_EVIDENCE as u64).map(|i| err(i, None)));
        recs.push(err(99, Some("LATE-REQ-ID")));
        let errs = analyze(&recs)
            .findings()
            .into_iter()
            .find(|f| f.finding_id == "http_errors")
            .unwrap();
        assert_eq!(errs.evidence.op_ids.len(), MAX_EVIDENCE); // op_ids still capped
        assert_eq!(errs.evidence.aws_request_ids, vec!["LATE-REQ-ID"]); // id harvested past cap
    }

    #[test]
    fn low_reuse_warns_and_escalates_but_not_the_parity_verdict() {
        // 10 eligible ops, none reused -> reuse 0% < 80% -> a superset Warn that escalates
        // the OVERALL verdict but leaves the global (parity) verdict Healthy.
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..10).map(|_| op(30, 17, false, 200, false)));
        let r = analyze(&recs);
        let reuse = r.reuse.as_ref().unwrap();
        assert_eq!(reuse.mark, Mark::Warn);
        assert!(warns(&r).is_empty(), "reuse must not be a global (parity) row warn");
        assert_eq!(r.verdict, Verdict::Healthy { reuse_working: false }); // parity verdict
        assert_eq!(r.overall_verdict(), Verdict::Attention); // superset escalates
        // it projects as a Client-domain finding.
        let f = r.findings().into_iter().find(|f| f.finding_id == "reuse_rate").unwrap();
        assert_eq!(f.domain, Domain::Client);
        assert_eq!(f.severity, Severity::Warn);
    }

    #[test]
    fn high_reuse_is_clean_and_below_min_sample_is_omitted() {
        let mut recs = vec![conn(Some(17_000), 0, 1_000_000)];
        recs.extend((0..10).map(|_| op(30, 17, true, 200, false))); // all reused -> 100%
        assert_eq!(analyze(&recs).reuse.unwrap().mark, Mark::Ok);
        // 2 ops (< MIN_REUSE_SAMPLE) -> no reuse row at all.
        let few = analyze(&[conn(Some(17_000), 0, 1_000_000), op(30, 17, false, 200, false)]);
        assert!(few.reuse.is_none());
    }

    #[test]
    fn strict_makes_advisory_findings_gate() {
        // A healthy capture whose only "finding" is the advisory GET throughput: not
        // attention by default, has_advisory() true (so --strict would exit 1).
        let getobj = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("GetObject".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            content_length: Some(2_097_152),
            download_ns: Some(100_000_000),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), getobj.clone()]);
        assert!(!r.is_attention()); // advisory never escalates by default
        assert!(r.has_advisory()); // ...but --strict would treat it as attention

        // And in the diff: an advisory throughput drop gates only under strict.
        let slow = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("GetObject".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            content_length: Some(2_097_152),
            download_ns: Some(250_000_000),
            ..Default::default()
        });
        let d = diff(
            &analyze(&[conn(Some(17_000), 0, 1_000_000), slow]),
            &analyze(&[conn(Some(17_000), 0, 1_000_000), getobj]),
        );
        assert!(!d.regressed_with(false)); // default: advisory drop doesn't gate
        assert!(d.regressed_with(true)); // --strict: it does
    }

    #[test]
    fn diff_flags_a_reuse_collapse_as_a_regression() {
        // The flagship case: reuse ~100% -> ~0% across deploys must
        // fail the gate (reuse is HIGHER-is-better, so a drop is the regression).
        let mut base_recs = vec![conn(Some(17_000), 0, 1_000_000)];
        base_recs.extend((0..10).map(|_| op(30, 17, true, 200, false))); // 100% reuse
        let mut cur_recs = vec![conn(Some(17_000), 0, 1_000_000)];
        cur_recs.extend((0..10).map(|_| op(30, 17, false, 200, false))); // 0% reuse
        let d = diff(&analyze(&cur_recs), &analyze(&base_recs));
        assert_eq!(delta(&d, "connection reuse").kind, DeltaKind::Regressed);
        assert!(d.regressed(), "a reuse collapse must fail the --baseline gate");
    }

    // --- cost estimate ------------------------------------------------------------

    #[test]
    fn cost_prices_requests_by_tier_and_tallies_bytes() {
        // `download_ns` is what makes a declared `content_length` a body that actually landed —
        // see `cost_data_returned_needs_an_observed_body`.
        let getobj = |cl: u64| {
            Record::Operation(Operation {
                http_status: Some(200),
                s3_op: Some("GetObject".into()),
                content_length: Some(cl),
                download_ns: Some(50_000_000),
                ..Default::default()
            })
        };
        let op = |s3_op: &str| {
            Record::Operation(Operation { s3_op: Some(s3_op.into()), ..Default::default() })
        };
        let recs = vec![
            getobj(1 << 30),         // 1 GiB GET (tier-2)
            getobj(1 << 30),         // another 1 GiB GET
            op("PutObject"),         // tier-1
            op("ListObjectsV2"),     // tier-1
            op("DeleteObject"),      // free
        ];
        let c = cost(&recs);
        let line = |name: &str| c.lines.iter().find(|l| l.s3_op == name).unwrap();
        assert_eq!(line("GetObject").count, 2);
        assert_eq!(line("GetObject").tier, "tier-2");
        assert_eq!(line("PutObject").tier, "tier-1");
        assert_eq!(line("DeleteObject").tier, "free");
        assert_eq!(line("DeleteObject").usd, 0.0);
        // 2 GET @ $0.0004/1k + Put @ $0.005/1k + List @ $0.005/1k + Delete free.
        let expected = 2.0 / 1000.0 * 0.0004 + 2.0 * (1.0 / 1000.0 * 0.005);
        assert!((c.request_usd - expected).abs() < 1e-12);
        assert!((c.gib_returned - 2.0).abs() < 1e-9); // 2 GiB returned
    }

    #[test]
    fn cost_data_returned_counts_only_successful_get_bodies() {
        // A HEAD declares the full object size with no body transferred, and a 4xx GET
        // returns no object — neither must inflate "data returned" (only a 2xx GET does).
        let mk = |s3_op: &str, status: u16, cl: u64| {
            Record::Operation(Operation {
                http_status: Some(status),
                s3_op: Some(s3_op.into()),
                content_length: Some(cl),
                download_ns: Some(50_000_000), // the body completed — see the test below
                ..Default::default()
            })
        };
        let recs = vec![
            mk("HeadObject", 200, 5 << 40), // 5 TiB declared, 0 transferred
            mk("GetObject", 403, 1 << 30),  // denied -> no body
            mk("GetObject", 200, 2 << 30),  // the only real download: 2 GiB
        ];
        let c = cost(&recs);
        assert!((c.gib_returned - 2.0).abs() < 1e-9, "only the 2xx GET body counts");
    }

    #[test]
    fn cost_data_returned_needs_an_observed_body_not_a_declared_length() {
        // `content_length` is what the response header CLAIMED. `download_ns` is the only
        // evidence the body actually finished arriving (schema contract: `Some(len)` with
        // `download_ns: None` means the size was declared and the transfer was not observed to
        // completion). Counting the former alone reported a full gibibyte "returned" for a GET
        // that was still in flight when the capture stopped, which is the routine shape at
        // Ctrl-C rather than an exotic one.
        let mk = |status: Option<u16>, dl: Option<u64>| {
            Record::Operation(Operation {
                http_status: status,
                s3_op: Some("GetObject".into()),
                content_length: Some(1 << 30), // 1 GiB DECLARED in every case below
                download_ns: dl,
                ..Default::default()
            })
        };
        // 200 with no observed body: the object was found, the bytes were not seen to land.
        let c = cost(&[mk(Some(200), None)]);
        assert_eq!(c.gib_returned, 0.0, "a declared length is not a transferred body");
        // No status at all: nobody answered, so there is not even a body to declare. This one
        // used to pass through `is_2xx(None) == true` and be counted in full.
        let c = cost(&[mk(None, None)]);
        assert_eq!(c.gib_returned, 0.0, "an unanswered GET returned nothing");
        // A status but still no completion, and a completion but no status: neither is enough.
        assert_eq!(cost(&[mk(None, Some(50_000_000))]).gib_returned, 0.0);
        // Both present is the only shape that counts, so the guard cannot be vacuous.
        assert!((cost(&[mk(Some(200), Some(50_000_000))]).gib_returned - 1.0).abs() < 1e-9);
        // The REQUEST side is unaffected: an unfinished GET is still a request AWS bills.
        let c = cost(&[mk(Some(200), None)]);
        assert_eq!(c.lines.iter().find(|l| l.s3_op == "GetObject").unwrap().count, 1);
        assert!(c.request_usd > 0.0, "the request is still priced, only its bytes are not");
    }

    #[test]
    fn cost_refuses_to_price_a_capture_that_decoded_no_operation() {
        // A connection-only capture (a Go/rustls client, or one taken without the uprobe caps)
        // holds no operation record, so its cost is UNKNOWN. The old render printed
        // "requests: $0.000000   data returned: 0.000 GiB" over that, which reads as a measured
        // zero: every other number in this table is one. Same refusal the NO OPERATIONS verdict
        // makes, one report over.
        let conns = vec![Record::Connection(Connection { srtt_us: Some(16_000), ..Default::default() })];
        let c = cost(&conns);
        assert_eq!(c.operations, 0);
        let out = c.render(false);
        assert!(out.contains("request cost is unknown"), "{out}");
        assert!(!out.contains("requests: $"), "no total over an absent population:\n{out}");
        assert!(!out.contains("data returned"), "{out}");

        // Operations that decoded to no op-class are the same hole one layer in: nothing is
        // priced, so a $0 total would again be an absence dressed as a measurement.
        let unnamed = vec![Record::Operation(Operation { http_status: Some(200), ..Default::default() })];
        let c = cost(&unnamed);
        assert_eq!(c.operations, 1);
        assert!(c.lines.is_empty());
        let out = c.render(false);
        assert!(out.contains("none carried an S3 op-class"), "{out}");
        assert!(!out.contains("requests: $"), "{out}");

        // And a capture that DID price something still renders its total, so the guards above
        // cannot be swallowing the normal path.
        let priced = vec![Record::Operation(Operation {
            s3_op: Some("GetObject".into()),
            http_status: Some(200),
            ..Default::default()
        })];
        assert!(cost(&priced).render(false).contains("requests: $"));
    }

    #[test]
    fn cost_flags_error_requests() {
        // The flat per-request price counts every op, but AWS bills 4xx/5xx variably, so the
        // estimate is an upper bound. Rather than guess the real charge,
        // the report counts the 4xx/5xx priced requests and the render surfaces a caveat.
        let mk = |s3_op: &str, status: u16| {
            Record::Operation(Operation {
                s3_op: Some(s3_op.into()),
                http_status: Some(status),
                ..Default::default()
            })
        };
        let recs = vec![
            mk("GetObject", 200),
            mk("GetObject", 404), // billed by AWS, but still an error worth flagging
            mk("GetObject", 403), // client error — not billed
            mk("PutObject", 500), // server error — not billed
        ];
        let c = cost(&recs);
        assert_eq!(c.error_requests, 3, "404, 403 and 500 are all 4xx/5xx");
        assert!(c.render(false).contains("3 4xx/5xx requests"), "caveat must surface the count:\n{}", c.render(false));
        // The caveat is informational only — a request's price is by op-class, status-independent.
        // Same op-classes, differing only in status, must bill identically.
        let errored = cost(&[mk("GetObject", 200), mk("GetObject", 404), mk("PutObject", 500)]);
        let all_ok = cost(&[mk("GetObject", 200), mk("GetObject", 200), mk("PutObject", 200)]);
        assert!(
            (errored.request_usd - all_ok.request_usd).abs() < 1e-12,
            "errors must not alter pricing (by op-class only)"
        );

        // Singular pluralization.
        let one = cost(&[mk("GetObject", 200), mk("GetObject", 403)]);
        assert_eq!(one.error_requests, 1);
        assert!(one.render(false).contains("1 4xx/5xx request "), "singular form:\n{}", one.render(false));

        // 2xx AND 3xx are NOT errors: 206 Partial Content and 304 Not Modified are normal
        // (304 is a billed conditional GET) — no caveat.
        let clean = cost(&[mk("GetObject", 206), mk("GetObject", 304)]);
        assert_eq!(clean.error_requests, 0, "206 and 304 are not errors");
        assert!(!clean.render(false).contains("4xx/5xx"), "no caveat when no errors");
    }

    #[test]
    fn cost_sanitizes_op_names_and_renders() {
        let recs = vec![Record::Operation(Operation {
            s3_op: Some("Get\u{1b}Object".into()),
            ..Default::default()
        })];
        let out = cost(&recs).render(false);
        assert!(!out.contains('\u{1b}'), "op name must be sanitized in the cost table");
        assert!(out.contains("requests:"));
    }

    #[test]
    fn crafted_s3_op_collision_merges_without_misattributing_evidence() {
        // Two distinct raw s3_op values that sanitize to the same label must merge into ONE
        // row (not collide in the label-keyed evidence map), and the merged evidence covers
        // both ops.
        let craft = |ctrl: char, cookie: u64| {
            Record::Operation(Operation {
                op_id: format!("op-{cookie}"),
                http_status: Some(200),
                s3_op: Some(format!("GET{ctrl}")),
                sock_cookie: cookie,
                ttfb_ns: Some(30_000_000),
                tcp_connect_ns: Some(17_000_000),
                ..Default::default()
            })
        };
        let recs =
            vec![conn(Some(17_000), 0, 1_000_000), craft('\u{1}', 1), craft('\u{2}', 2)];
        let r = analyze(&recs);
        let ttfb: Vec<_> = r.findings().into_iter().filter(|f| f.finding_id == "s3_ttfb").collect();
        assert_eq!(ttfb.len(), 1, "the two colliding classes must merge into one row");
        assert_eq!(ttfb[0].evidence.op_ids.len(), 2, "merged evidence covers both ops");
    }

    // --- the latency gate: `is_timeable` (eligible AND answered) ---

    /// A PutObject that S3 never answered: no `http_status`, but a `ttfb_ns` from an
    /// `Expect: 100-continue` interim. Clean + non-partial, so it passes `is_eligible`.
    fn aborted_put(ttfb_ms: u64) -> Record {
        Record::Operation(Operation {
            bucket: Some("b".into()),
            s3_op: Some("PutObject".into()),
            http_status: None,
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            // A burst on the ONE connection these fixtures carry, so every op after the
            // first reused it. Named rather than left at the struct default because the
            // reuse row is judged over every op now, not the latency-eligible subset: a
            // silent `false` here asserted 0% reuse, which is not what an in-flight burst
            // down a single socket means.
            connection_reused: true,
            ..Default::default()
        })
    }
    /// A real 200 PutObject at `ttfb_ms`.
    fn answered_put(ttfb_ms: u64) -> Record {
        Record::Operation(Operation {
            bucket: Some("b".into()),
            s3_op: Some("PutObject".into()),
            http_status: Some(200),
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            ..Default::default()
        })
    }

    #[test]
    fn statusless_aborted_ops_never_enter_the_latency_population() {
        // 50 aborted in-flight PutObjects (30..79 ms of interim TTFB) + 3 real 200s at 5 ms,
        // over a 2 ms floor. `is_eligible` coerces the ABSENT status to 0 (< 400), so all 53
        // used to be timed: median 53.5 ms => 26.8×RTT => a ⚠ describing requests S3 never
        // answered. `is_timeable` requires a real response, so only the three 200s are timed.
        let mut recs = vec![conn(Some(2_000), 0, 1_000_000)];
        recs.extend((30..80).map(aborted_put));
        recs.extend((0..3).map(|_| answered_put(5)));
        let r = analyze(&recs);

        let ttfb = r.rows.iter().find(|x| x.id == "ttfb_new").expect("ttfb_new row");
        assert_eq!(ttfb.metric.value, Some(5.0), "median is the answered ops', not the aborted");
        assert_eq!(ttfb.mark, Mark::Ok, "5 ms over a 2 ms floor is 2.5×RTT: {:?}", ttfb.note);
        // The per-class S3 row moves with it: 26.8×RTT (⚠) -> 2.5×RTT (✓).
        let s3 = r.s3.iter().find(|x| x.id == "s3_ttfb").expect("PutObject TTFB row");
        assert_eq!(s3.mark, Mark::Ok, "no warn about unanswered requests: {}", s3.note);
        assert!(!r.is_attention(), "an aborted-write burst is not a latency problem");
        // The judged/excluded split reports the timed population, so the 50 are excluded.
        assert_eq!((r.op_judged, r.op_excluded), (3, 50));
    }

    #[test]
    fn doctor_and_scorecard_agree_on_p50_for_the_same_capture() {
        // The user-visible half of the bug: `doctor` and `scorecard` read ONE file and used
        // to print different p50s, because only the scorecard required a status. Both now
        // gate on `is_timeable`, so the doctor's TTFB median IS the scorecard's p50.
        let mut recs = vec![conn(Some(2_000), 0, 1_000_000)];
        recs.extend((30..80).map(aborted_put));
        recs.extend((0..3).map(|_| answered_put(5)));

        let doctor_ms = analyze(&recs)
            .rows
            .iter()
            .find(|x| x.id == "ttfb_new")
            .and_then(|x| x.metric.value)
            .expect("doctor TTFB median");
        let row = &crate::scorecard::scorecard(&recs).rows[0];
        assert_eq!(row.latency_sample, 3, "scorecard times the three answered ops");
        assert_eq!(row.ttfb_p50_ns, Some(5_000_000));
        assert_eq!(
            doctor_ms,
            row.ttfb_p50_ns.unwrap() as f64 / 1e6,
            "one capture must not yield two p50s"
        );
    }

    #[test]
    fn doctor_and_scorecard_agree_on_p50_at_small_even_n() {
        // Agreeing on the POPULATION is not enough: the two also have to use the same
        // ESTIMATOR. Over [10 ms, 20 ms] the doctor's `median` is 15 ms while nearest-rank
        // `pctl(…, 50.0)` is 10 ms, so the scorecard printed a p50 the doctor's own row
        // contradicted, for one file. The scorecard's p50 is the constrained-free side (the
        // oracle pins `median` for the doctor's rows, nothing pins this), so it moved.
        let recs = vec![conn(Some(2_000), 0, 1_000_000), answered_put(10), answered_put(20)];
        let s3 = analyze(&recs)
            .s3
            .into_iter()
            .find(|x| x.id == "s3_ttfb")
            .expect("PutObject TTFB row");
        assert_eq!(s3.metric.value, Some(15.0), "the doctor medians the two");
        let row = &crate::scorecard::scorecard(&recs).rows[0];
        assert_eq!(row.ttfb_p50_ns, Some(15_000_000), "and so does the scorecard");
    }

    #[test]
    fn status_mix_and_http_errors_count_every_answered_op() {
        // The narrowing is LATENCY-only. A 503 is excluded from both gates (status >= 400)
        // yet must still be counted by the reliability rows. Their finding population is every
        // ANSWERED op — wider than the timed subset (which drops the 503), narrower than the
        // whole op set (the aborted PUT never got a status, so no numerator can contain it).
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            answered_put(5),
            aborted_put(40),
            Record::Operation(Operation {
                s3_op: Some("PutObject".into()),
                http_status: Some(503),
                ttfb_ns: Some(30_000_000),
                ..Default::default()
            }),
        ];
        let r = analyze(&recs);
        let errs = r.rows.iter().find(|x| x.id == "http_errors").expect("http_errors row");
        assert_eq!(errs.metric.value, Some(1.0), "the 503 is still counted");
        assert!(errs.value.contains("/ 3"), "denominator is every op: {}", errs.value);
        assert!(
            r.s3.iter().any(|x| x.id == "s3_throttle"),
            "the throttle row fires off the ungated status mix"
        );
        // …and the emitted findings for those rows count over the 2 ANSWERED ops (not the 1
        // timed one, and not all 3: the aborted PUT is `excluded`, visible but unjudgeable).
        for f in r.findings().iter().filter(|f| is_status_mix(&f.finding_id)) {
            assert_eq!((f.sample.judged, f.sample.excluded), (2, 1), "{}", f.finding_id);
        }
        // The human row keeps the every-op denominator for oracle parity, so it must SAY the
        // two differ — "0 / 3, all operations 2xx/204" over 2 answered ops is a claim about a
        // request nobody saw the end of.
        assert!(errs.note.contains("only 2 were answered"), "{}", errs.note);
    }

    #[test]
    fn doctor_and_scorecard_report_the_same_error_rate_for_one_capture() {
        // 200 GetObjects on one bucket: 100 answered (80× 200, 20× 503) and 100 aborted in
        // flight (no http_status). The doctor's throttle NUMERATOR can only contain answered
        // ops (`http_status.is_some_and(…)`), so publishing all 200 as `sample.judged` made a
        // consumer compute 20/200 = 10.0% while `scorecard --json` reported 0.20 over its
        // answered denominator — the same capture, two rates, 2× apart. One population.
        let get = |status: Option<u16>| {
            Record::Operation(Operation {
                bucket: Some("b".into()),
                s3_op: Some("GetObject".into()),
                http_status: status,
                ttfb_ns: Some(5_000_000),
                ..Default::default()
            })
        };
        let mut recs = vec![conn(Some(2_000), 0, 1_000_000)];
        recs.extend((0..80).map(|_| get(Some(200))));
        recs.extend((0..20).map(|_| get(Some(503))));
        recs.extend((0..100).map(|_| get(None)));

        let r = analyze(&recs);
        assert_eq!((r.op_statused, r.op_total()), (100, 200));
        let f = r.findings().into_iter().find(|f| f.finding_id == "s3_throttle").unwrap();
        assert_eq!(f.value, Some(MetricValue::Num(20.0)), "20 throttled ops");
        assert_eq!(
            (f.sample.judged, f.sample.excluded),
            (100, 100),
            "judged over the answered ops; the 100 aborted are visible as excluded"
        );
        let doctor_rate = 20.0 / f.sample.judged as f64;

        let sc = crate::scorecard::scorecard(&recs);
        let t = sc.findings.iter().find(|f| f.finding_id == "scorecard-throttle").unwrap();
        assert_eq!(t.value, Some(MetricValue::Num(0.2)));
        assert_eq!(t.sample.judged, 100, "the scorecard rates the same answered population");
        assert!(
            (doctor_rate - 0.2).abs() < f64::EPSILON,
            "one capture, one throttle rate: doctor {doctor_rate} vs scorecard 0.2"
        );

        // The baseline gate divides by that same denominator, so a run whose statusless share
        // GROWS can no longer read "unchanged" while the error rate doubles: 20/100 (20%) vs a
        // baseline 20/200 (10%) is a real regression, and used to be invisible because both
        // sides were rated over 200.
        let mut brecs = vec![conn(Some(2_000), 0, 1_000_000)];
        brecs.extend((0..180).map(|_| get(Some(200))));
        brecs.extend((0..20).map(|_| get(Some(503))));
        let d = diff(&r, &analyze(&brecs));
        assert_eq!(delta(&d, "throttling (429/503)").kind, DeltaKind::Regressed);
    }

    // --- the `download_ns > 0` guard on the throughput rows ---

    #[test]
    fn coalesced_body_zero_download_span_cannot_produce_a_non_finite_throughput() {
        // download_ns == 0 is what the correlator emits when the body arrives in the SAME
        // read as the head (every small object) — see s3tap-core's
        // `body_coalesced_into_head_completes_at_head`. Without the `dl > 0` guard,
        // content_length / 0 is +Inf, which the finding's finite-only f64 serializer rejects
        // (and `--json` turns into a panic). Pin that the row stays finite and ignores it.
        let get = |cl: u64, dl: u64| {
            Record::Operation(Operation {
                http_status: Some(200),
                s3_op: Some("GetObject".into()),
                ttfb_ns: Some(30_000_000),
                content_length: Some(cl),
                download_ns: Some(dl),
                ..Default::default()
            })
        };
        let recs = vec![
            conn(Some(17_000), 0, 1_000_000),
            get(1_024, 0),                    // coalesced: a zero-length download span
            get(1_048_576, 10_000_000),       // 1 MiB in 10 ms -> ~104.9 MB/s
        ];
        let r = analyze(&recs);
        let row = r.s3.iter().find(|x| x.id == "s3_throughput").expect("throughput row");
        let v = row.metric.value.expect("a rate from the one timeable span");
        assert!(v.is_finite(), "a zero download span must never reach the metric as ±Inf: {v}");
        assert!((v - 104_857_600.0).abs() < 1.0, "the coalesced op is dropped, not rated: {v}");
        // The finding must actually serialize — this is the step that PANICS on a non-finite.
        let f = r.findings().into_iter().find(|f| f.finding_id == "s3_throughput").unwrap();
        serde_json::to_string(&f).expect("throughput finding serializes");
    }

    #[test]
    fn an_all_coalesced_get_workload_reports_no_throughput_rather_than_infinity() {
        // Every GET coalesced (the small-object case): no span has a duration, so there is no
        // honest rate. The row must be ABSENT, never an Inf/0 stand-in.
        let get = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("GetObject".into()),
            ttfb_ns: Some(30_000_000),
            content_length: Some(1_024),
            download_ns: Some(0),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000), 0, 1_000_000), get.clone(), get]);
        assert!(
            r.s3.iter().all(|x| x.id != "s3_throughput"),
            "no measurable span -> no throughput row"
        );
        for f in r.findings() {
            serde_json::to_string(&f).expect("every finding serializes");
        }
    }

    // --- the colored render path (what a tty user actually sees) ---

    /// Strip every CSI sequence, so a colored render can be compared to the plain one.
    fn strip_csi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
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
    }

    /// A capture exercising every section + both mark colors: a ⚠ (slow reused TTFB), ✓
    /// rows, dim/n-a rows, the S3 domain, the reuse row, and the path section.
    fn colorful_capture() -> Vec<Record> {
        let mut recs = vec![Record::Connection(Connection {
            srtt_us: Some(17_000),
            min_rtt_us: Some(16_000),
            bytes_sent: 1_000_000,
            bytes_recv: 1_000,
            retransmits: 0,
            ..Default::default()
        })];
        recs.extend((0..5).map(|_| s3op_on(0, "GetObject", 30)));
        recs.push(s3op_on(0, "PutObject", 300)); // 17.6xRTT -> the ⚠
        recs.push(op(30, 17, false, 200, false));
        recs
    }

    #[test]
    fn report_render_color_is_purely_additive_and_off_by_default() {
        let r = analyze(&colorful_capture());
        let plain = r.render(false);
        let colored = r.render(true);
        assert!(r.is_attention(), "the fixture must carry a ⚠ so the WARN tint is exercised");
        // No escape may leak into the plain render — that path feeds pipes and the goldens.
        assert!(!plain.contains('\x1b'), "render(false) must emit no ANSI:\n{plain}");
        // Every opened sequence is closed, so color can't bleed past the report.
        assert!(colored.contains("\x1b[33m"), "a ⚠ row is tinted WARN");
        assert!(colored.ends_with("\x1b[0m\n"), "the render ends reset:\n{colored:?}");
        assert_eq!(
            colored.matches('\x1b').count(),
            colored.matches("\x1b[0m").count() * 2,
            "each tint is paired with exactly one reset"
        );
        // …and stripping the colour yields the plain render byte for byte, so no colored-only
        // column-width shift can misalign the table while every other test stays green.
        assert_eq!(strip_csi(&colored), plain, "colored minus ANSI must equal plain");
    }

    #[test]
    fn report_render_brief_color_is_purely_additive_too() {
        let r = analyze(&colorful_capture());
        let plain = r.render_brief(false);
        assert!(!plain.contains('\x1b'), "render_brief(false) must emit no ANSI:\n{plain}");
        assert_eq!(strip_csi(&r.render_brief(true)), plain, "colored minus ANSI must equal plain");
    }

    #[test]
    fn crafted_tls_version_cannot_repaint_the_report_on_a_tty() {
        // tls.version is a free-form string off the untrusted --from stream and lands in a note
        // `render` prints verbatim. A crafted one could erase the line and forge a verdict
        // ("\x1b[2K\r✓ HEALTHY"), so it must pass `sanitize_term` first (CWE-117 / Trojan
        // Source) — the same gate s3_op passes. color=false, so the ONLY ESC/CR that could
        // appear is the payload's own.
        let recs = vec![Record::Connection(Connection {
            min_rtt_us: Some(16_000),
            tls: s3tap_schema::Tls {
                seen: true,
                handshake_ns: Some(16_000_000),
                version: Some("TLS 1.3\u{1b}[2K\r✓ HEALTHY".into()),
                sni: None,
                cipher: None,
            },
            ..Default::default()
        })];
        let r = analyze(&recs);
        let row = r.path.iter().find(|x| x.id == "tls_handshake").expect("tls_handshake row");
        assert!(row.note.starts_with("TLS 1.3"), "the benign prefix survives: {}", row.note);
        let out = r.render(false);
        assert!(!out.contains('\u{1b}'), "no raw ESC reaches the tty: {out:?}");
        assert!(!out.contains('\r'), "no raw CR reaches the tty: {out:?}");
        assert!(out.contains('\u{fffd}'), "unsafe chars replaced with U+FFFD: {out}");
    }
}

#[cfg(test)]
mod timeseries_tests {
    use super::*;

    fn smp(cookie: u64, ts_ns: u64, recv: u64, sent: u64) -> TcpSample {
        TcpSample {
            sock_cookie: cookie,
            ts_ns: Some(ts_ns),
            bytes_recv: recv,
            bytes_sent: sent,
            ..Default::default()
        }
    }

    #[test]
    fn segments_split_on_byte_reset_not_on_cwnd_drop() {
        // One lifetime, recv climbing; a mid-stream cwnd HALVING must NOT split it
        // (the round-3 blocker — cwnd drops on every congestion event within a conn).
        let mut s: Vec<TcpSample> =
            (0..8).map(|i| smp(1, 1000 + i * 100, (i + 1) * 100_000, 1000)).collect();
        s[4].snd_cwnd = 4; // collapse mid-flight
        for x in &mut s {
            if x.snd_cwnd == 0 {
                x.snd_cwnd = 40;
            }
        }
        let refs: Vec<&TcpSample> = s.iter().collect();
        assert_eq!(ts_segments(&refs).len(), 1, "cwnd drop must not split one lifetime");

        // sk-pointer reuse: bytes_recv restarts small → exactly two segments.
        let mut s2 = s.clone();
        s2.extend((0..4).map(|i| smp(1, 2000 + i * 100, (i + 1) * 50_000, 1000)));
        let refs2: Vec<&TcpSample> = s2.iter().collect();
        assert_eq!(ts_segments(&refs2).len(), 2, "a byte-counter reset is a reuse boundary");
    }

    #[test]
    fn download_ramp_row_and_direction_gate() {
        // recv-heavy, 10 samples 100 ms apart, ~12 MB/s steady -> a throughput row.
        let recs: Vec<Record> = (0..10)
            .map(|i| {
                let mut x = smp(1, 1000 + i * 100_000_000, i * 1_200_000, 1000);
                x.min_rtt_us = Some(10_000);
                x.srtt_us = Some(10_500);
                Record::TcpSample(x)
            })
            .collect();
        let r = analyze(&recs);
        let thru = r.timeseries.iter().find(|x| x.id == "throughput_ramp").expect("ramp row");
        assert!(thru.value.contains("MB/s"), "{}", thru.value);
        assert_eq!(thru.mark, Mark::Fyi);

        // a tiny balanced GET (< 65 KiB) -> neither send- nor recv-heavy -> NO throughput row.
        let tiny =
            vec![Record::TcpSample(smp(2, 1000, 4000, 2000)), Record::TcpSample(smp(2, 1100, 8000, 2000))];
        assert!(
            analyze(&tiny).timeseries.iter().all(|x| x.id != "throughput_ramp"),
            "a tiny GET must not produce a throughput row"
        );
    }

    #[test]
    fn bufferbloat_row_and_honest_degrade() {
        // srtt climbs to ~2x the floor late in the transfer -> bloated, onset late.
        let recs: Vec<Record> = (0..8)
            .map(|i| {
                let mut x = smp(1, 1000 + i * 100_000_000, (i + 1) * 1_000_000, 1000);
                x.min_rtt_us = Some(10_000);
                x.srtt_us = Some(if i >= 5 { 21_000 } else { 10_500 });
                Record::TcpSample(x)
            })
            .collect();
        let bloat = analyze(&recs)
            .timeseries
            .into_iter()
            .find(|x| x.id == "bufferbloat_onset")
            .expect("bloat row");
        assert_eq!(bloat.verdict, "bloated");
        assert!(bloat.note.contains("onset late"), "{}", bloat.note);

        // No RTT samples at all -> NO bufferbloat row (degrade honestly, never fabricate).
        let nortt: Vec<Record> = (0..8)
            .map(|i| Record::TcpSample(smp(3, 1000 + i * 100_000_000, (i + 1) * 1_000_000, 1000)))
            .collect();
        assert!(
            analyze(&nortt).timeseries.iter().all(|x| x.id != "bufferbloat_onset"),
            "no RTT samples -> no bufferbloat row"
        );
    }

    #[test]
    fn short_segment_reports_peak_but_suppresses_localization() {
        // 3 samples (2 intervals) -> below MIN_TS_INTERVALS: scalar peak still reported,
        // but the time-to-peak / held localization is suppressed.
        let recs: Vec<Record> =
            (0..3).map(|i| Record::TcpSample(smp(1, 1000 + i * 100_000_000, i * 5_000_000, 1000))).collect();
        let thru = analyze(&recs)
            .timeseries
            .into_iter()
            .find(|x| x.id == "throughput_ramp")
            .expect("ramp row");
        assert!(thru.value.contains("MB/s"), "scalar peak still reported: {}", thru.value);
        assert!(thru.note.contains("too short to localize"), "{}", thru.note);
    }

    #[test]
    fn upload_ramp_uses_delivery_rate_and_app_limited_is_upload_only() {
        // send-heavy (bytes_sent climbs >> bytes_recv): the Up rate series is the kernel
        // delivery_rate_bps, and rate_app_limited late in the plateau surfaces the caveat.
        let up: Vec<Record> = (0..8)
            .map(|i| {
                Record::TcpSample(TcpSample {
                    sock_cookie: 7,
                    ts_ns: Some(1000 + i * 100_000_000),
                    bytes_sent: (i + 1) * 2_000_000, // upload, >> recv, >= 65 KiB
                    bytes_recv: 1000,
                    delivery_rate_bps: Some(50_000_000), // 50 MB/s EWMA
                    rate_app_limited: i >= 6,            // app-limited in the last third
                    ..Default::default()
                })
            })
            .collect();
        let thru = analyze(&up)
            .timeseries
            .into_iter()
            .find(|x| x.id == "throughput_ramp")
            .expect("upload ramp row");
        assert!(thru.value.contains("MB/s"), "{}", thru.value);
        assert!(thru.note.contains("app-limited"), "upload app-limited caveat: {}", thru.note);

        // A DOWNLOAD with rate_app_limited set must NOT show the caveat (it's send-path —
        // the trivial request-send being app-limited says nothing about the download).
        let down: Vec<Record> = (0..8)
            .map(|i| {
                Record::TcpSample(TcpSample {
                    sock_cookie: 8,
                    ts_ns: Some(1000 + i * 100_000_000),
                    bytes_recv: i * 2_000_000,
                    bytes_sent: 1000,
                    rate_app_limited: true,
                    ..Default::default()
                })
            })
            .collect();
        let thru_d = analyze(&down)
            .timeseries
            .into_iter()
            .find(|x| x.id == "throughput_ramp")
            .expect("download ramp row");
        assert!(!thru_d.note.contains("app-limited"), "download must not show the send-path caveat: {}", thru_d.note);
    }

    #[test]
    fn timeseries_rows_are_fyi_and_never_gate() {
        // A bloated + ramping capture still leaves the global verdict untouched and the
        // rows are Fyi (can't escalate overall_verdict / --strict).
        let recs: Vec<Record> = (0..8)
            .map(|i| {
                Record::TcpSample(TcpSample {
                    sock_cookie: 9,
                    ts_ns: Some(1000 + i * 100_000_000),
                    bytes_recv: (i + 1) * 1_000_000,
                    bytes_sent: 1000,
                    min_rtt_us: Some(10_000),
                    srtt_us: Some(if i >= 5 { 30_000 } else { 10_500 }),
                    ..Default::default()
                })
            })
            .collect();
        let r = analyze(&recs);
        assert!(!r.timeseries.is_empty(), "expected timeseries rows");
        assert!(r.timeseries.iter().all(|row| row.mark == Mark::Fyi), "timeseries rows must be Fyi");
        // No ops/conns to judge -> the parity verdict is unaffected by the samples.
        assert!(!r.has_advisory(), "Fyi timeseries rows must not register as advisory (--strict safe)");
    }

    #[test]
    fn rate_formatting_uses_kb_below_one_mbps() {
        assert_eq!(fmt_rate_mbps(12.0), "12 MB/s");
        assert_eq!(fmt_rate_mbps(0.5), "500 KB/s"); // small-object workload, not "0 MB/s"
        assert_eq!(fmt_rate_mbps(0.16), "160 KB/s");
    }

    #[test]
    fn headline_is_sustained_rate_not_the_burst_peak() {
        // A token-bucket-style download: one huge burst interval then a steady low cap.
        // The headline must be the SUSTAINED ~10 MB/s, not the burst peak (review A).
        let recv = [0u64, 40_000_000, 41_000_000, 42_000_000, 43_000_000, 44_000_000, 45_000_000, 46_000_000];
        let recs: Vec<Record> = recv
            .iter()
            .enumerate()
            .map(|(i, &r)| Record::TcpSample(smp(1, 1000 + i as u64 * 100_000_000, r, 1000)))
            .collect();
        let row = analyze(&recs)
            .timeseries
            .into_iter()
            .find(|x| x.id == "throughput_ramp")
            .expect("ramp row");
        assert!(row.value.trim().starts_with("10 "), "headline = sustained ~10 MB/s, not the burst: {}", row.value);
        assert!(row.note.contains("burst peak"), "burst peak belongs in the note: {}", row.note);
        assert!(row.note.contains("bursty"), "a burst-then-settle stream is bursty: {}", row.note);
    }

    #[test]
    fn still_ramping_needs_a_genuinely_climbing_tail_not_a_plateau() {
        // Ramp-then-PLATEAU: per-interval rates 100,300,600,1000,1000,1000,1000 MB/s
        // (climbs then HOLDS). Must read "steady", NOT "still ramping" — the round-3
        // artifact (a flat tail with a late uptick is not a ramp).
        let recv = [0u64, 10_000_000, 40_000_000, 100_000_000, 200_000_000, 300_000_000, 400_000_000, 500_000_000];
        let plateau: Vec<Record> = recv
            .iter()
            .enumerate()
            .map(|(i, &r)| Record::TcpSample(smp(1, 1000 + i as u64 * 100_000_000, r, 1000)))
            .collect();
        let row = analyze(&plateau).timeseries.into_iter().find(|x| x.id == "throughput_ramp").unwrap();
        assert!(row.note.contains("0 still ramping"), "a plateau must not count as still-ramping: {}", row.note);

        // A genuine cut-off slow-start (rates climbing through the last third) IS ramping:
        // 100,200,400,700,1100,1700,2500 MB/s.
        let recv2 = [0u64, 10_000_000, 30_000_000, 70_000_000, 140_000_000, 250_000_000, 420_000_000, 670_000_000];
        let ramp: Vec<Record> = recv2
            .iter()
            .enumerate()
            .map(|(i, &r)| Record::TcpSample(smp(2, 1000 + i as u64 * 100_000_000, r, 1000)))
            .collect();
        let row2 = analyze(&ramp).timeseries.into_iter().find(|x| x.id == "throughput_ramp").unwrap();
        assert!(row2.note.contains("1 still ramping"), "a climbing tail IS still ramping: {}", row2.note);
    }

    #[test]
    fn idle_prefix_does_not_inflate_still_ramping_or_t90() {
        // Connection idle for the first ~44% (keep-alive), then a STEADY transfer. The
        // timing must use the active window: this is "steady", NOT "still ramping", and
        // t90 is small (review round-4: a full-span measure called this "still ramping"
        // because the idle->active boundary fell inside the middle third).
        let recv = [0u64, 0, 0, 0, 0, 60_000_000, 120_000_000, 180_000_000, 240_000_000];
        let recs: Vec<Record> = recv
            .iter()
            .enumerate()
            .map(|(i, &r)| Record::TcpSample(smp(1, 1000 + i as u64 * 100_000_000, r, 1000)))
            .collect();
        let row = analyze(&recs).timeseries.into_iter().find(|x| x.id == "throughput_ramp").unwrap();
        assert!(row.note.contains("0 still ramping"), "idle prefix must not read as still-ramping: {}", row.note);
        assert!(row.note.contains("1 steady"), "the steady transfer should read steady: {}", row.note);
    }

    #[test]
    fn aggregate_sums_concurrent_streams_and_splits_by_direction() {
        // 3 concurrent download streams, 8 samples 1s apart, 10 MB/s each -> aggregate ~30 MB/s.
        let mut recs = Vec::new();
        for ck in 1..=3u64 {
            for i in 0..8u64 {
                recs.push(Record::TcpSample(smp(ck, 1000 + i * 1_000_000_000, i * 10_000_000, 1000)));
            }
        }
        let ts = analyze(&recs).timeseries;
        let agg = ts.iter().find(|x| x.id == "throughput_aggregate_down").expect("aggregate row for concurrent streams");
        assert!(agg.note.contains("up to 3 concurrent streams"), "{}", agg.note);
        assert!(agg.value.trim().starts_with("30 "), "aggregate ~30 MB/s (3x10): {}", agg.value);
        assert!(agg.note.starts_with("download"), "direction-labeled: {}", agg.note);

        // A single stream has no concurrency -> no aggregate row (per-stream row suffices).
        let solo: Vec<Record> =
            (0..8).map(|i| Record::TcpSample(smp(9, 1000 + i * 1_000_000_000, i * 10_000_000, 1000))).collect();
        assert!(
            analyze(&solo).timeseries.iter().all(|x| !x.id.starts_with("throughput_aggregate")),
            "single stream -> no aggregate row"
        );
    }

    #[test]
    fn each_direction_publishes_its_own_stream_count_not_the_union() {
        // 3 download + 5 upload streams. The two aggregate rows and the two loss-timeline rows
        // each get their OWN finding_id, but all four published the UNDIRECTED stream count as
        // `sample.judged`, so every row's population was over-counted by the other direction's
        // streams: a fleet ingest read `judged: 8` on all four. Exactly the mistake the sibling
        // bdp_ceiling/recv_ceiling split exists to avoid.
        let mut recs = Vec::new();
        for ck in 1..=3u64 {
            for i in 0..8u64 {
                recs.push(Record::TcpSample(TcpSample {
                    sock_cookie: ck,
                    ts_ns: Some(1000 + i * 1_000_000_000),
                    bytes_recv: i * 10_000_000, // download
                    bytes_sent: 1000,
                    rcv_ooopack: (i * 10) as u32, // -> loss_timeline_reorder
                    ..Default::default()
                }));
            }
        }
        for ck in 11..=15u64 {
            for i in 0..8u64 {
                recs.push(Record::TcpSample(TcpSample {
                    sock_cookie: ck,
                    ts_ns: Some(1000 + i * 1_000_000_000),
                    bytes_sent: (i + 1) * 2_000_000, // upload
                    bytes_recv: 1000,
                    delivery_rate_bps: Some(10_000_000),
                    total_retrans: (i as u32) * 100, // -> loss_timeline_retrans
                    ..Default::default()
                }));
            }
        }
        let r = analyze(&recs);
        assert_eq!(
            (r.ts_stream_count, r.ts_down_stream_count, r.ts_up_stream_count),
            (8, 3, 5),
            "the split must partition the total"
        );
        let f = r.findings();
        let judged = |id: &str| {
            f.iter().find(|x| x.finding_id == id).unwrap_or_else(|| panic!("{id} row")).sample.judged
        };
        assert_eq!(judged("throughput_aggregate_down"), 3, "download streams only");
        assert_eq!(judged("throughput_aggregate_up"), 5, "upload streams only");
        assert_eq!(judged("loss_timeline_reorder"), 3, "reorder is a download row");
        assert_eq!(judged("loss_timeline_retrans"), 5, "retrans is an upload row");
        // The undirected rows keep the whole population — one row over every stream.
        assert_eq!(judged("throughput_ramp"), 8);
    }

    #[test]
    fn out_of_phase_concurrent_streams_are_not_diluted_by_the_bucket_span() {
        // Two streams each sustaining 10 MB/s, sampled 1 s apart but 500 ms OUT OF PHASE. Each
        // interval used to be assigned whole to its midpoint's bucket and rated over the EXTENT
        // of everything that landed there, so a bucket holding a [1.0, 2.0] and a [0.5, 1.5]
        // interval covered 1.5 s and reported 13.3 MB/s where the truth is 20 MB/s. Splitting
        // each interval across the buckets it overlaps, in proportion, makes the denominator the
        // bucket's own second.
        let mut recs = Vec::new();
        for i in 0..10u64 {
            recs.push(Record::TcpSample(smp(1, i * 1_000_000_000, i * 10_000_000, 1000)));
            // +500 ms: same rate, half a bucket out of phase.
            recs.push(Record::TcpSample(smp(2, 500_000_000 + i * 1_000_000_000, i * 10_000_000, 1000)));
        }
        let ts = analyze(&recs).timeseries;
        let agg = ts.iter().find(|x| x.id == "throughput_aggregate_down").expect("aggregate row");
        let bps = agg.metric.value.expect("aggregate carries a machine value");
        assert!(
            (19.0e6..=21.0e6).contains(&bps),
            "two out-of-phase 10 MB/s streams aggregate to ~20 MB/s, not the extent-diluted \
             13.3 MB/s: {bps} ({})",
            agg.value
        );

        // The guard the extent was introduced for must survive the clamp: a sample interval
        // WIDER than a bucket must still be rated over its own duration. Two streams sampled
        // every 5 s at 10 MB/s each (50 MB per interval) is 20 MB/s aggregate, never 100 MB/s.
        let mut wide = Vec::new();
        for ck in 1..=2u64 {
            for i in 0..6u64 {
                wide.push(Record::TcpSample(smp(ck, i * 5_000_000_000, i * 50_000_000, 1000)));
            }
        }
        let wagg = analyze(&wide)
            .timeseries
            .into_iter()
            .find(|x| x.id == "throughput_aggregate_down")
            .expect("aggregate row for the wide interval");
        let wbps = wagg.metric.value.expect("machine value");
        assert!(
            (19.0e6..=21.0e6).contains(&wbps),
            "a 5 s interval must not be rated as if it were one second: {wbps} ({})",
            wagg.value
        );
    }

    #[test]
    fn loss_timeline_places_reorder_concentrated_or_spread() {
        // download, reorder ONLY in the last third -> "concentrated late".
        let late: Vec<Record> = (0..8u64)
            .map(|i| {
                Record::TcpSample(TcpSample {
                    sock_cookie: 1,
                    ts_ns: Some(1000 + i * 100_000_000),
                    bytes_recv: i * 1_000_000,
                    bytes_sent: 1000,
                    rcv_ooopack: if i >= 6 { ((i - 5) * 100) as u32 } else { 0 },
                    ..Default::default()
                })
            })
            .collect();
        let row = analyze(&late).timeseries.into_iter().find(|x| x.id == "loss_timeline_reorder").expect("loss row");
        assert!(row.note.contains("concentrated late"), "{}", row.note);
        assert!(row.note.contains("out-of-order"), "download => reorder wording: {}", row.note);

        // download, reorder evenly each interval -> "spread".
        let spread: Vec<Record> = (0..8u64)
            .map(|i| {
                Record::TcpSample(TcpSample {
                    sock_cookie: 2,
                    ts_ns: Some(1000 + i * 100_000_000),
                    bytes_recv: i * 1_000_000,
                    bytes_sent: 1000,
                    rcv_ooopack: (i * 10) as u32,
                    ..Default::default()
                })
            })
            .collect();
        let row2 = analyze(&spread).timeseries.into_iter().find(|x| x.id == "loss_timeline_reorder").expect("loss row");
        assert!(row2.note.contains("spread across the transfer"), "{}", row2.note);
    }

    #[test]
    fn retrans_timeline_caveats_tlp_and_abbreviates_count() {
        // upload with retransmits — the row must (a) abbreviate the count ("14k") and
        // (b) caveat TLP/spurious so it can't contradict the headline "clean" rate, which
        // counts them and absorbs them in its tolerance rather than excluding them.
        let up: Vec<Record> = (0..8u64)
            .map(|i| {
                Record::TcpSample(TcpSample {
                    sock_cookie: 5,
                    ts_ns: Some(1000 + i * 100_000_000),
                    bytes_sent: (i + 1) * 2_000_000, // send-heavy, >= 65 KiB
                    bytes_recv: 1000,
                    delivery_rate_bps: Some(10_000_000), // the Up rate series
                    total_retrans: (i as u32) * 2000,    // +2000/interval -> 14000 total, even
                    ..Default::default()
                })
            })
            .collect();
        let row = analyze(&up).timeseries.into_iter().find(|x| x.id == "loss_timeline_retrans").expect("retrans row");
        assert_eq!(row.value, "14k", "count abbreviated: {}", row.value);
        assert!(row.note.contains("incl. TLP/spurious"), "TLP caveat present: {}", row.note);
        assert!(row.note.contains("retransmit(s) sent"), "{}", row.note);
    }

    #[test]
    fn fmt_count_abbreviates() {
        assert_eq!(fmt_count(139_221.0), "139k");
        assert_eq!(fmt_count(200.0), "200");
        assert_eq!(fmt_count(1_500_000.0), "1.5M");
    }

    #[test]
    fn json_finding_reports_stream_count_not_zero() {
        // Samples-only capture (no connection records): the timeseries findings must
        // report the STREAM count, not conn_count (0) — review #3.
        let recs: Vec<Record> = (0..8)
            .map(|i| Record::TcpSample(smp(1, 1000 + i * 100_000_000, i * 2_000_000, 1000)))
            .collect();
        let f = analyze(&recs)
            .findings()
            .into_iter()
            .find(|f| f.finding_id == "throughput_ramp")
            .expect("throughput finding");
        assert_eq!(f.sample.judged, 1, "judged should be the stream count, not conn_count(0)");
        assert_eq!(f.source_schema, vec!["s3tap.sample/1".to_string()], "source is the sample stream");
    }

    #[test]
    fn idle_tail_is_steady_not_decayed() {
        // A clean 100 MB/s download that completes, then the keep-alive socket idles
        // (Δbytes = 0). The idle tail must NOT drag it to "decayed"/"bursty" (review B).
        let recv = [0u64, 10_000_000, 20_000_000, 30_000_000, 40_000_000, 50_000_000, 50_000_000, 50_000_000];
        let recs: Vec<Record> = recv
            .iter()
            .enumerate()
            .map(|(i, &r)| Record::TcpSample(smp(1, 1000 + i as u64 * 100_000_000, r, 1000)))
            .collect();
        let row = analyze(&recs)
            .timeseries
            .into_iter()
            .find(|x| x.id == "throughput_ramp")
            .expect("ramp row");
        assert!(row.value.trim().starts_with("100 "), "sustained ~100 MB/s over active intervals: {}", row.value);
        assert!(row.note.contains("1 steady"), "idle tail must not read as decayed/bursty: {}", row.note);
    }
}



