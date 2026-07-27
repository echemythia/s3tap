//! `s3tap analyze` — the offline caching study, run on ONE trace.
//!
//! `advise` answers "should you cache?" fast and object-level (LRU + Markov,
//! capped at 500k events, terse findings). This is the deep, opt-in sibling: it
//! runs the FULL retention ladder (LRU / ARC / S3-FIFO / OPT) in chunk mode plus
//! the prefetch tradeoff, and returns a structured [`TraceAnalysis`] the CLI
//! renders as a human report or JSON. It shares the study's decision floors with
//! the advisor's caching check ([`crate::checks::caching`]), so the two agree.
//!
//! Everything analytical is reused from `s3tap-replay` (the same no-future-leak
//! engine the report trusts); this module is orchestration + a verdict + a
//! renderer, nothing more.

use serde::Serialize;

use s3tap_replay::adapt::{classify_trace_line, LineOutcome};
use s3tap_replay::driver::{sweep_blocks, sweep_demand, sweep_retention, Row};
use s3tap_replay::hybrid::run_self_tuned;
use s3tap_replay::ibm::to_blocks;
use s3tap_replay::trace::{NormEvent, Op};

use crate::checks::caching::{
    byte_sizing, human_bytes, is_whole_object_get, knee_floor, ranged_share, GO_FLOOR, LAT_FLOOR,
    POLICY_FETCH_NS, POLICY_MAX_DEPTH, RANGED_FRAC_MAX, SIZE_COVERAGE_FLOOR, STRUCTURE_FLOOR,
};

/// 8 MB chunks — the study's granularity (`64 chunks = 512 MiB` anchor).
pub const DEFAULT_BLOCK: u64 = 8 * 1024 * 1024;
/// Study parity: the first 3M events of a large trace (a leading time slice).
/// `--max-events 0` disables the cap and analyses the whole trace.
pub const DEFAULT_MAX_EVENTS: usize = 3_000_000;
const MAX_CAP: u64 = 4096; // ladder top (32 GiB at the 64-chunk anchor); matches `mrc`
const ANCHOR_CAP: u64 = 64; // 512 MiB — the report's headline size, always in the ladder
const NOGO_MIN_GETS: usize = 2000; // below this + low reuse ⇒ Unjudged, not NoGo

/// The shippable demand caches, best-first preference on ties (ARC is the study's
/// recommended default; LRU the safe floor; S3-FIFO the newcomer).
const RETENTION: &[&str] = &["null", "lru+adm", "arc", "s3fifo", "opt"];
/// SEQUENCE prefetchers: rungs whose prediction is a function of the recent access
/// sequence. Only these may define `structure` — the go-latency verdict reads
/// "the next access is predictable from the last ones", and the shippable overlay
/// it recommends (`run_self_tuned`) is itself a lead-gated sequence prefetcher.
const PREFETCHERS: &[&str] = &["markov", "markov2", "cooc", "sequential", "adaptive"];
/// Rungs `--deep` computes that are NOT sequence prefetchers. They get a row in the
/// per-policy table (the deep pass paid for them) but are kept out of `structure`
/// and `best_prefetcher`. `frequency` predicts the globally hottest objects
/// regardless of what was just accessed: it is an LFU *pin* expressed through the
/// prefetch interface, a demand-side popularity policy. Folding it into `structure`
/// would report "the sequence is predictable" on a merely popularity-skewed trace
/// and then hand it to an overlay that can hide nothing. Popularity skew already
/// has an honest home in the retention ladder (`lru+adm`, ARC, S3-FIFO).
const NON_SEQ_RUNGS: &[&str] = &["frequency"];

/// Capacity unit for the mode.
fn unit(mode: &str) -> &'static str {
    if mode == "chunk" {
        "chunks"
    } else {
        "objects"
    }
}

/// Singular capacity unit, for attributive use ("the 4096-chunk cap").
fn unit1(mode: &str) -> &'static str {
    if mode == "chunk" {
        "chunk"
    } else {
        "object"
    }
}

/// "GET" / "GETs" — avoids the "1 GETs" grammar nit on a one-request capture.
fn gets_word(n: usize) -> &'static str {
    if n == 1 {
        "GET"
    } else {
        "GETs"
    }
}

/// Display label for a policy id (matches the report's figures).
fn label(pred: &str) -> &'static str {
    match pred {
        "null" => "LRU (floor)",
        "lru+adm" => "LRU+admission",
        "arc" => "ARC",
        "s3fifo" => "S3-FIFO",
        "opt" => "OPT (ceiling)",
        "markov" => "Markov-1",
        "markov2" => "Markov-2",
        "cooc" => "Co-occurrence",
        "sequential" => "Sequential",
        "adaptive" => "Adaptive",
        // Named for what it does, so a reader can't mistake it for a sequence
        // prefetcher: it pins the globally hottest keys (see NON_SEQ_RUNGS).
        "frequency" => "Frequency (LFU pin)",
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

/// How to run the analysis. Three cost levels (`fast` < default < `deep`):
/// - `fast`: retention bake-off only (LRU/ARC/S3-FIFO/OPT) — no prefetch pass.
/// - default: retention bake-off + a Markov structure signal + the self-tuning
///   lead-gated overlay — the study's exact methodology, seconds to ~a minute.
/// - `deep`: additionally the full prediction ladder (Co-occurrence/Sequential/
///   **Adaptive**, plus the Frequency LFU-pin rung, which is reported but is not a
///   sequence prefetcher — see [`NON_SEQ_RUNGS`]). The Adaptive rung runs a
///   per-capacity shadow cache and is minutes-to-much-more on a large trace — opt
///   in deliberately.
pub struct AnalyzeOpts {
    /// `Some(bytes)` = chunk mode (within-object structure visible); `None` = object mode.
    pub block_bytes: Option<u64>,
    /// Analyse at most this many raw ops (a leading slice); `0` = the whole trace.
    pub max_events: usize,
    /// Retention-only: skip the prefetch pass entirely (fastest).
    pub fast: bool,
    /// Run the full, expensive prediction ladder (adds Co-occurrence/Sequential/
    /// Adaptive, and the Frequency LFU-pin rung). Ignored when `fast` is set.
    pub deep: bool,
}
impl Default for AnalyzeOpts {
    fn default() -> Self {
        Self {
            block_bytes: Some(DEFAULT_BLOCK),
            max_events: DEFAULT_MAX_EVENTS,
            fast: false,
            deep: false,
        }
    }
}

/// The headline classification (same matrix as `advise`).
#[derive(Serialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Reuse pays: cache on cost.
    Go,
    /// Low reuse but predictable sequence: cache only to hide latency.
    GoLatency,
    /// No reuse and no structure: do not cache.
    NoGo,
    /// Too short / too few GETs to rule caching out.
    Unjudged,
}

/// One policy's metrics at the reported cache size.
#[derive(Serialize, Clone)]
pub struct PolicyRow {
    pub policy: String,
    pub label: String,
    pub hit_rate: f64,
    pub net_savings: f64,
    pub pf_per_access: f64,
    pub pf_precision: f64,
    pub pf_latency: f64,
}
fn policy_row(r: &Row) -> PolicyRow {
    PolicyRow {
        policy: r.predictor.clone(),
        label: label(&r.predictor).to_string(),
        hit_rate: r.hit_rate,
        net_savings: r.net_savings,
        pf_per_access: r.pf_per_access,
        pf_precision: r.pf_precision,
        pf_latency: r.pf_latency,
    }
}

/// Byte-level (egress-$) sizing, object-level and whole-object only.
#[derive(Serialize)]
pub struct ByteVerdict {
    pub working_set_bytes: u64,
    pub distinct_objects: u64,
    pub knee_bytes: u64,
    /// Request savings AT `knee_bytes`, measured on the BYTE ladder. Carried so the
    /// byte knee can be quoted with its own hit-rate — the count ladder's
    /// `knee_hit` was measured at a different cache size on a different ladder.
    pub knee_hit: f64,
    pub req_savings_max: f64,
    pub egress_savings_max: f64,
}

/// The prefetch tradeoff (absent in `--fast`, or when there is no sequence structure).
#[derive(Serialize)]
pub struct PrefetchVerdict {
    /// Sequence is predictable enough to be worth an overlay (`structure >= floor`).
    pub has_structure: bool,
    /// The shippable overlay actually hides meaningful fetch latency here.
    pub hides_latency: bool,
    pub structure: f64,
    pub structure_cap: u64,
    pub best_prefetcher: String,
    pub best_prefetcher_label: String,
    pub best_pf_hit: f64,
    pub best_pf_latency: f64, // instant upper bound
    pub best_pf_cost: f64,    // prefetches issued per access
    pub best_pf_precision: f64,
    // The shippable overlay: the self-tuning lead-gated prefetcher at the structure cap.
    pub overlay_net: f64,          // held at ~the LRU floor
    pub overlay_latency_hidden: f64, // lead-time-aware (eff_latency)
    pub lru_net_at_cap: f64,
}

/// The full result of analysing one trace.
#[derive(Serialize)]
pub struct TraceAnalysis {
    pub verdict: Verdict,
    pub mode: &'static str, // "chunk" | "object"
    pub fast: bool,
    // scope
    pub events: usize,    // raw ops analysed (post-sampling)
    pub gets: usize,      // object-level GETs
    pub accesses: usize,  // cache accesses (blocks in chunk mode)
    pub distinct: u64,    // distinct cache keys
    pub sampled: bool,
    /// Ranged (206) body reads present in the input but NOT modelled. They carry no
    /// Range header from an s3tap capture, so object identity is the whole object and
    /// chunk expansion has nothing to expand: both modes would map every ranged read of
    /// an object onto one key. They are excluded from `gets`/`accesses` and disclosed
    /// here so a reader can see how much of the workload the verdict does not cover.
    pub ranged_excluded: usize,
    /// The capture is ranged-heavy (`ranged_share > RANGED_FRAC_MAX`), so the
    /// object-level question is UNJUDGEABLE and `verdict` is forced to
    /// [`Verdict::Unjudged`] with no `recommended_cap`. Same gate, same constant, as
    /// `advise`'s `advisor-cache-unjudged`. It used to live only in `advise_caching`:
    /// `analyze`'s verdict matrix consulted `ranged_share` solely inside `byte_verdict`
    /// (which merely suppressed the BYTE axis), so 3000 whole-object GETs beside 400
    /// ranged reads made `advise` say the workload could not be judged while `analyze`
    /// on the identical file said CACHE IT and published a recommended size.
    pub ranged_unjudged: bool,
    /// Ranged body reads and total body reads behind [`Self::ranged_unjudged`] — the
    /// numerator and denominator the disclosure quotes. The numerator counts only the
    /// ranged reads whose EXTENT is unknown (a 206 that carries its span is modelled
    /// honestly, so it is not evidence that the workload is unjudgeable). The
    /// denominator is body reads, which excludes every 304 Not Modified: the adapter
    /// drops a body-less GET before it can become an event. See `RANGED_FRAC_MAX`.
    pub ranged_reads: usize,
    pub body_reads: usize,
    pub ladder_capped: bool, // working set exceeds the ladder top (knee may lie beyond)
    /// The ladder top expressed in bytes — `MAX_CAP * block_bytes`. `None` in object
    /// mode, where a capacity unit is one whole object of unknown size and there is
    /// no byte equivalent to quote.
    pub ladder_cap_bytes: Option<u64>,
    // retention
    pub cache_go: bool,
    pub lru_max: f64,          // best LRU net_savings over the ladder
    pub opt_max: f64,          // OPT ceiling over the ladder
    /// The cap every per-knee figure below (`rows`, `arc_delta`, `s3fifo_delta`,
    /// `opt_gap_at_knee`) was MEASURED at: the smallest rung within `KNEE_EPS_FRAC` of
    /// the LRU ceiling. It is a measurement site, not necessarily a recommendation —
    /// see `recommended_cap`.
    pub knee_cap: u64,
    pub knee_hit: f64,
    /// `Some(knee_cap)` only when reuse actually pays (`cache_go`). On a flat curve
    /// every rung is within tolerance of the ceiling, so the knee search returns the
    /// SMALLEST cap: a 5000-unique-key one-shot workload has net_savings 0.0 at every
    /// cap and used to print "DON'T CACHE" three lines above "Recommended size (knee):
    /// 2 objects (captures 0% of the reuse)". There is no size to recommend for a
    /// workload with no reuse, so this is `None` and the renderer omits the line.
    pub recommended_cap: Option<u64>,
    pub best_retention: String,     // policy id
    pub best_retention_label: String,
    pub best_retention_net: f64,
    pub arc_delta: f64,        // ARC − LRU at the knee (net_savings)
    pub s3fifo_delta: f64,     // S3-FIFO − LRU at the knee
    /// OPT − LRU AT `knee_cap`. The headline `opt_max`/`lru_max` are maxima over the
    /// WHOLE ladder and can come from different rungs, so a "gap to optimal" built from
    /// them sits next to `arc_delta`/`s3fifo_delta` (measured at the knee) while being
    /// measured somewhere else entirely, inviting a reader to divide one by the other.
    pub opt_gap_at_knee: f64,
    pub rows: Vec<PolicyRow>,  // per policy at the knee cap
    pub byte: Option<ByteVerdict>,
    // prefetch
    pub prefetch: Option<PrefetchVerdict>,
    // one-line summary
    pub headline: String,
}

/// Distinct cache keys in the (already block-expanded) trace — the cap-ladder top.
///
/// GETs ONLY: the simulator skips `Head`/`Other` and never inserts on `Put`/`Delete`
/// (s3tap-replay::driver), so a key that is only ever HEADed or WRITTEN is not a cache
/// key. Counting it inflates the reported working set, stretches the ladder past
/// anything the sweep can fill, and makes the "knee == the full working set" branch
/// unreachable.
///
/// **The filter is load-bearing in BOTH modes.** It used to bite object mode only,
/// because `to_blocks` dropped everything that was not a GET. It no longer does: it
/// forwards writes as per-chunk invalidations, so a chunk that is only ever written
/// reaches this function on the chunk path too, and this filter is the only thing
/// keeping it out of the ladder top. Deleting it as dead code is a real regression,
/// and it is exactly the one the `mrc` bin's ladder shipped.
fn distinct_keys(trace: &[NormEvent]) -> u64 {
    let mut s = std::collections::HashSet::new();
    for e in trace.iter().filter(|e| e.op == Op::Get) {
        s.insert(e.object_id.as_str());
    }
    s.len() as u64
}

/// The capacity ladder: powers of two up to the working set, clamped to `MAX_CAP`,
/// with the 64-chunk anchor always present. Identical to the `mrc` bin's ladder so
/// `analyze` agrees with the study's `cap64.csv` cap-for-cap.
fn cap_ladder(distinct: u64) -> Vec<u64> {
    let top = distinct.clamp(ANCHOR_CAP.min(MAX_CAP), MAX_CAP);
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

/// Object-level egress-$ sizing, when the workload is whole-object and mostly sized.
fn byte_verdict(otrace: &[NormEvent], gets: usize) -> Option<ByteVerdict> {
    if gets == 0 {
        return None;
    }
    let (_, _, ranged_frac) = ranged_share(otrace);
    let whole = otrace.iter().filter(|e| is_whole_object_get(e)).count();
    let sized = otrace.iter().filter(|e| is_whole_object_get(e) && e.size.is_some()).count();
    let coverage = if whole > 0 { sized as f64 / whole as f64 } else { 0.0 };
    if coverage < SIZE_COVERAGE_FLOOR || ranged_frac > RANGED_FRAC_MAX {
        return None;
    }
    let b = byte_sizing(otrace)?;
    Some(ByteVerdict {
        working_set_bytes: b.total_bytes,
        distinct_objects: b.distinct_objects,
        knee_bytes: b.knee_cap,
        knee_hit: b.knee_hit,
        req_savings_max: b.req_max,
        egress_savings_max: b.egress_max,
    })
}

/// The prefetch tradeoff over the sweep rows. `strace` is the (block-expanded)
/// policy trace; `rows` its full sweep; `caps` the ladder.
fn prefetch_verdict(strace: &[NormEvent], rows: &[Row], caps: &[u64]) -> Option<PrefetchVerdict> {
    let get = |pred: &str, cap: u64| rows.iter().find(|r| r.predictor == pred && r.cap == cap);
    // structure = max over caps of (best prefetcher hit − LRU hit) at the SAME cap;
    // remember the peak cap (the overlay runs there). Per-cap so a top-rung LRU
    // can't mask a small-cap prediction win.
    let mut structure = 0.0f64;
    let mut structure_cap = caps[0];
    for &cap in caps {
        let Some(null) = get("null", cap).map(|r| r.hit_rate) else { continue };
        let best_pf = PREFETCHERS
            .iter()
            .filter_map(|&p| get(p, cap).map(|r| r.hit_rate))
            .fold(0.0f64, f64::max);
        if best_pf - null > structure {
            structure = best_pf - null;
            structure_cap = cap;
        }
    }
    // Best prefetcher AT the structure cap (by hit-rate — what defines the structure).
    // The tie-break is EXPLICIT. `max_by` returns the LAST maximum, and which rungs are
    // in `rows` depends on the cost level (default computes only the Markov rungs, --deep
    // the whole ladder), so an exact tie shipped a different recommendation under --deep
    // than in default mode on byte-identical data. Preference order: higher hit rate,
    // then lower prefetch cost (fewer speculative fetches for the same benefit), then the
    // earlier — simpler, and always-present — rung, since we scan PREFETCHERS in order
    // and only replace on a strict improvement.
    let (bp, br) = PREFETCHERS
        .iter()
        .filter_map(|&p| get(p, structure_cap).map(|r| (p, r)))
        .reduce(|best, cand| {
            let d = cand.1.hit_rate - best.1.hit_rate;
            let better = d > 1e-12
                || (d.abs() <= 1e-12 && cand.1.pf_per_access < best.1.pf_per_access - 1e-12);
            if better {
                cand
            } else {
                best
            }
        })?;
    // The shippable overlay: the self-tuning lead-gated prefetcher at that cap.
    let st = run_self_tuned(strace, structure_cap, POLICY_FETCH_NS, POLICY_MAX_DEPTH);
    let lru_net_at_cap = get("null", structure_cap).map(|r| r.net_savings).unwrap_or(0.0);
    Some(PrefetchVerdict {
        has_structure: structure >= STRUCTURE_FLOOR,
        hides_latency: structure >= STRUCTURE_FLOOR && st.eff_latency() >= LAT_FLOOR,
        structure,
        structure_cap,
        best_prefetcher: bp.to_string(),
        best_prefetcher_label: label(bp).to_string(),
        best_pf_hit: br.hit_rate,
        best_pf_latency: br.pf_latency,
        best_pf_cost: br.pf_per_access,
        best_pf_precision: br.pf_precision,
        overlay_net: st.net_savings(),
        overlay_latency_hidden: st.eff_latency(),
        lru_net_at_cap,
    })
}

/// Load a trace from raw input text, auto-detecting the format line by line
/// (s3tap JSONL / NormEvent JSON / IBM COS). Returns the parsed events and the
/// count of skipped lines. Keeps the CLI free of replay types.
///
/// **The skipped count is not just junk.** A line is skipped when it is blank,
/// unparseable, an identity-less op (a Connection record, a `ListObjects`) OR a
/// well-formed GET the origin served no body for. That last group is the one a
/// caller must not describe as "unparseable": it includes every 4xx/5xx, and it
/// includes `304 Not Modified`, which is a SUCCESS to `doctor` and `scorecard` and
/// is precisely the response `advisor-refetch` tells clients to aim for. A client
/// that took that advice (4500 x 304, 500 x 200) parses as 500 events with 4500
/// skipped lines, so any note rendered off this number has to name the case. See
/// `s3tap_replay::adapt::demand_op` for why a body-less GET cannot be a demand read.
/// [`load_trace_counted`] returns that group as its own number.
///
/// `limit` caps the number of parsed events (`0` = unlimited) so a huge trace
/// doesn't materialize millions of events the caller would only sample away. It
/// reads ONE past the limit, so the caller's sampler still detects truncation
/// (and shows the "(sampled)" note) while the parsed `Vec` stays bounded.
///
/// Use [`load_trace_counted`] when the skipped count is going to be shown to a
/// human: it splits out the lines that WERE a capture.
pub fn load_trace(input: &str, limit: usize) -> (Vec<NormEvent>, usize) {
    let (trace, counts) = load_trace_counted(input, limit);
    (trace, counts.skipped)
}

/// How the input broke down, for a caller that has to explain an EMPTY trace.
///
/// `skipped` alone cannot: an all-503 capture, an all-403 bucket and a mid-flight
/// attach (every op carrying `"ts_ns":null`) each parse to zero events with a large
/// skipped count, and so does a file of random text. Naming the accepted formats at
/// an operator whose 6300 records `doctor` reads back happily (6300 operations, 100%
/// error rate) tells them a valid capture is not a trace.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoadCounts {
    /// Every line that yielded no event: junk, other record kinds, and dropped ops.
    /// Blank lines are not counted (they are not input the user wrote).
    pub skipped: usize,
    /// Of `skipped`: lines that WERE correctly tagged `s3tap.operation/1` records and
    /// were dropped by a content gate, not by a parse failure. A GET the origin served
    /// no body for (4xx/5xx/**304**), a ranged 206, an op with no object identity (a
    /// `ListObjects`), a record with no readable timestamp, or one flagged `partial`.
    /// `skipped == operations_dropped` on a non-empty input means the file is a capture
    /// in which nothing was a demand read a cache could have served.
    pub operations_dropped: usize,
    /// Of `skipped`: lines that were VALID `s3tap.*` records of a kind carrying no demand
    /// read — connections, in-flight samples, findings, scorecard rows. Capture data, exactly
    /// like `operations_dropped`. Kept separate so the caller can tell "I read your capture
    /// and none of it was a demand read" from "I could not read this file at all", which are
    /// different exit codes and different advice.
    pub other_records: usize,
}

impl std::ops::AddAssign for LoadCounts {
    fn add_assign(&mut self, o: Self) {
        self.skipped += o.skipped;
        self.operations_dropped += o.operations_dropped;
        self.other_records += o.other_records;
    }
}

/// A bare count of lines the CALLER skipped before the parser ever saw them (an over-long
/// line, a non-UTF-8 one). Those are junk by definition, never a dropped operation, so
/// they land in `skipped` alone. Lets a streaming reader accumulate into this type.
impl From<usize> for LoadCounts {
    fn from(skipped: usize) -> Self {
        Self { skipped, operations_dropped: 0, other_records: 0 }
    }
}

/// [`load_trace`] with the skip reasons split out. See [`LoadCounts`].
pub fn load_trace_counted(input: &str, limit: usize) -> (Vec<NormEvent>, LoadCounts) {
    let hard = if limit == 0 { usize::MAX } else { limit.saturating_add(1) };
    let mut trace = Vec::new();
    let mut counts = LoadCounts::default();
    for line in input.lines() {
        if trace.len() >= hard {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        match classify_trace_line(line) {
            LineOutcome::Event(ev) => trace.push(ev),
            LineOutcome::OperationDropped => {
                counts.skipped += 1;
                counts.operations_dropped += 1;
            }
            LineOutcome::OtherRecord => {
                counts.skipped += 1;
                counts.other_records += 1;
            }
            LineOutcome::Unusable => counts.skipped += 1,
        }
    }
    (trace, counts)
}

/// Analyse one trace end to end and return a structured verdict.
pub fn analyze_trace(otrace_in: &[NormEvent], opts: &AnalyzeOpts) -> TraceAnalysis {
    // Leading-slice sampling (study parity), 0 = whole trace.
    let sampled = opts.max_events > 0 && otrace_in.len() > opts.max_events;
    let otrace: &[NormEvent] =
        if sampled { &otrace_in[..opts.max_events] } else { otrace_in };
    let events = otrace.len();
    let gets = otrace.iter().filter(|e| e.op == Op::Get).count();
    // Ranged reads the adapter demoted out of the simulator (206 with no usable extent).
    // A ranged read that DID arrive with a real span — a raw NormEvent trace, or an IBM
    // COS line — is still an `Op::Get` and is modelled honestly, so it is not counted here.
    let ranged_excluded =
        otrace.iter().filter(|e| e.status == Some(206) && e.op != Op::Get).count();

    // The policy trace: block-expanded in chunk mode so within-object (streaming)
    // structure and the sequential prefetcher are visible; object-level otherwise.
    let expanded;
    let strace: &[NormEvent] = match opts.block_bytes {
        Some(b) => {
            expanded = to_blocks(otrace, b);
            &expanded
        }
        None => otrace,
    };
    let mode = if opts.block_bytes.is_some() { "chunk" } else { "object" };
    let accesses = strace.iter().filter(|e| e.op == Op::Get).count();
    let distinct = distinct_keys(strace);
    let caps = cap_ladder(distinct);

    // The sweep, by cost level. Default = the retention bake-off (all caps, cheap)
    // PLUS a Markov structure pass (single pass, cheap) — the study's methodology
    // without the per-capacity Adaptive shadow cache that makes `sweep_blocks`
    // minutes-slow. `--deep` opts into the full ladder; `--fast` drops prefetch.
    let rows: Vec<Row> = if opts.fast {
        sweep_retention(strace, &caps)
    } else if opts.deep {
        sweep_blocks(strace, &caps)
    } else {
        let mut v = sweep_retention(strace, &caps);
        // Add only the Markov rungs from the cheap demand pass (null already present).
        v.extend(
            sweep_demand(strace, &caps)
                .into_iter()
                .filter(|r| r.predictor == "markov" || r.predictor == "markov2"),
        );
        v
    };
    let get = |pred: &str, cap: u64| rows.iter().find(|r| r.predictor == pred && r.cap == cap);

    // Retention ceilings + the knee (smallest cap within EPS of the LRU ceiling).
    let lru_max =
        caps.iter().filter_map(|&c| get("null", c).map(|r| r.net_savings)).fold(0.0f64, f64::max);
    let opt_max =
        caps.iter().filter_map(|&c| get("opt", c).map(|r| r.net_savings)).fold(0.0f64, f64::max);
    let knee_cap = caps
        .iter()
        .copied()
        .find(|&c| get("null", c).is_some_and(|r| r.net_savings >= knee_floor(lru_max)))
        .unwrap_or_else(|| *caps.last().unwrap());
    let knee_hit = get("null", knee_cap).map(|r| r.net_savings).unwrap_or(0.0);

    // Retention winner AT the knee (among the shippable demand caches).
    let net_at = |pred: &str| get(pred, knee_cap).map(|r| r.net_savings);
    let lru_net = net_at("null").unwrap_or(0.0);
    let arc_net = net_at("arc").unwrap_or(lru_net);
    let s3_net = net_at("s3fifo").unwrap_or(lru_net);
    let mut best_pred = "null";
    let mut best_net = lru_net;
    for (p, n) in [("arc", arc_net), ("s3fifo", s3_net)] {
        if n > best_net + 1e-9 {
            best_pred = p;
            best_net = n;
        }
    }

    // Per-policy rows at the knee (demand ladder always; prefetchers in full mode).
    let mut rows_at: Vec<PolicyRow> = RETENTION
        .iter()
        .filter_map(|&p| get(p, knee_cap).map(policy_row))
        .collect();
    if !opts.fast {
        rows_at.extend(PREFETCHERS.iter().filter_map(|&p| get(p, knee_cap).map(policy_row)));
        // `--deep` computes these too; show the rung it paid for rather than
        // silently dropping it. They are NOT sequence prefetchers, so they stay out
        // of `structure`/`best_prefetcher` (see NON_SEQ_RUNGS). Absent on the
        // cheaper paths, where `get` simply finds no row.
        rows_at.extend(NON_SEQ_RUNGS.iter().filter_map(|&p| get(p, knee_cap).map(policy_row)));
    }

    // Prefetch tradeoff (full mode only).
    let prefetch = if opts.fast { None } else { prefetch_verdict(strace, &rows, &caps) };

    // The RANGED gate, ahead of the verdict matrix and on the same constant `advise`
    // uses. A ranged (206) read carries no Range header in an s3tap capture, so its
    // extent is unknown and NEITHER mode can place it: object mode keys every range of
    // an object on the object, chunk mode has nothing to expand and maps them all onto
    // `#0`. Past a small ranged share, `gets` (and therefore every ratio built on it)
    // describes only the whole-object remainder while the report reads as a verdict on
    // the whole workload. This gate lived only in `advise_caching`, where it returns a
    // lone `advisor-cache-unjudged`; here `ranged_share` was consulted only inside
    // `byte_verdict`, which suppresses the BYTE axis and nothing else — so the same
    // capture got "can't be judged" from `advise` and "CACHE IT" from `analyze`.
    //
    // The subject is UNPLACEABLE ranged reads, not 206s: a raw NormEvent trace can carry
    // a 206 WITH its span, and `to_blocks` expands exactly that span, so gating on the
    // status alone refused to judge traces this code models correctly.
    let (ranged_reads, body_reads, ranged_frac) = ranged_share(otrace);
    let ranged_unjudged = ranged_frac > RANGED_FRAC_MAX;

    // The verdict matrix. GoLatency requires the overlay to ACTUALLY hide latency,
    // not merely that structure exists: a large object linearizes into a perfectly
    // predictable chunk chain (high `structure`) that hides nothing (same-timestamp
    // chunks, `hides_latency == false`), and the top-line verdict must not read
    // "cache for latency" there. Structure-without-hideable-latency falls through to
    // NoGo (the headline still explains the structure). `cache_go` stays on the LRU
    // ceiling, matching `advise` and the study — except that a ranged-heavy capture
    // has no object-level answer to publish at all, so the gate above clears BOTH
    // decision flags rather than letting a subset measurement become a recommendation.
    let cache_go = !ranged_unjudged && lru_max >= GO_FLOOR;
    let hides = !ranged_unjudged && prefetch.as_ref().is_some_and(|p| p.hides_latency);
    let verdict = if ranged_unjudged {
        Verdict::Unjudged
    } else if cache_go {
        Verdict::Go
    } else if hides {
        Verdict::GoLatency
    } else if gets >= NOGO_MIN_GETS {
        Verdict::NoGo
    } else {
        Verdict::Unjudged
    };

    let byte = byte_verdict(otrace, gets);
    let headline = headline(verdict, best_pred, best_net, lru_net, knee_cap, distinct, mode,
        prefetch.as_ref(), opts.fast, gets,
        ranged_unjudged.then_some((ranged_reads, body_reads, ranged_frac)));

    TraceAnalysis {
        verdict,
        mode,
        fast: opts.fast,
        events,
        gets,
        accesses,
        distinct,
        sampled,
        ranged_excluded,
        ranged_unjudged,
        ranged_reads,
        body_reads,
        ladder_capped: distinct > MAX_CAP,
        ladder_cap_bytes: opts.block_bytes.map(|b| b.saturating_mul(MAX_CAP)),
        cache_go,
        lru_max,
        opt_max,
        knee_cap,
        knee_hit,
        recommended_cap: cache_go.then_some(knee_cap),
        best_retention: best_pred.to_string(),
        best_retention_label: label(best_pred).to_string(),
        best_retention_net: best_net,
        arc_delta: arc_net - lru_net,
        s3fifo_delta: s3_net - lru_net,
        opt_gap_at_knee: (net_at("opt").unwrap_or(lru_net) - lru_net).max(0.0),
        rows: rows_at,
        byte,
        prefetch,
        headline,
    }
}

#[allow(clippy::too_many_arguments)]
fn headline(
    verdict: Verdict,
    best_pred: &str,
    best_net: f64,
    lru_net: f64,
    knee_cap: u64,
    distinct: u64,
    mode: &str,
    prefetch: Option<&PrefetchVerdict>,
    fast: bool,
    gets: usize,
    // `Some((ranged, body_reads, frac))` when the ranged gate fired — the verdict is
    // then Unjudged for a reason that has nothing to do with capture LENGTH, so it
    // needs its own sentence rather than "capture longer and re-run".
    ranged: Option<(usize, usize, f64)>,
) -> String {
    // The size the quoted `best_net` was actually MEASURED at: the count ladder's
    // knee, in chunks/objects. The byte knee is a different ladder run over a
    // different (object-level) trace, so quoting it here attached a count-ladder
    // savings figure to a cache size that never produced it — "saves +0.412 at
    // 8.0 GiB" where +0.412 came from a 4096-chunk run. The byte axis gets its own
    // line in `render`.
    let size = if knee_cap >= distinct {
        format!("~the full working set ({distinct} {})", unit(mode))
    } else {
        format!("{knee_cap} {}", unit(mode))
    };
    // How prefetching reads, honestly: it needs both structure AND deep-enough
    // prediction to hide the fetch. The three cases the study separates.
    let pf_tail = |p: Option<&PrefetchVerdict>| match p {
        Some(p) if p.hides_latency => format!(
            " Prefetching also hides ~{:.0}% of a fetch on the predictable subset, at ~no cost.",
            p.overlay_latency_hidden * 100.0
        ),
        Some(p) if p.has_structure => format!(
            " The sequence has structure ({:+.0}%) but isn't predictable far enough ahead to hide a \
             fetch here — a prefetch overlay would correctly stay idle.",
            p.structure * 100.0
        ),
        Some(_) => " Prefetching would not pay: no exploitable sequence structure.".to_string(),
        None if fast => " (prefetch not assessed — drop --fast for the latency verdict).".to_string(),
        None => String::new(),
    };
    // The headline is the descriptive sentence; the verdict TAG is supplied
    // separately (by the terminal banner, or the JSON `verdict` field), so it is
    // NOT repeated here.
    match verdict {
        Verdict::Go => {
            let policy = label(best_pred);
            let edge = if best_pred != "null" {
                format!(" — {policy} beats plain LRU by {:+.3}", best_net - lru_net)
            } else {
                String::new()
            };
            format!(
                "best demand policy {policy} saves {:+.3} origin fetches/access at {size}{edge}.{}",
                best_net, pf_tail(prefetch),
            )
        }
        // Only reached when the overlay genuinely hides latency (verdict matrix).
        Verdict::GoLatency => {
            let (st, hid) = prefetch
                .map(|p| (p.structure * 100.0, p.overlay_latency_hidden * 100.0))
                .unwrap_or((0.0, 0.0));
            format!(
                "reuse is low, but the sequence is predictable (structure {st:+.0}%) and a prefetch \
                 overlay hides ~{hid:.0}% of a fetch — cache to hide latency, not to cut origin cost."
            )
        }
        Verdict::NoGo => match prefetch {
            // Structure present but not hideable (e.g. a linearized chunk chain): say
            // so rather than claiming "no structure".
            Some(p) if p.has_structure => format!(
                "reuse is low and, though the sequence shows structure ({:+.0}%), it isn't predictable \
                 far enough ahead to hide fetch latency — an overlay would stay idle. Little to gain here.",
                p.structure * 100.0
            ),
            _ => {
                let tail = if fast {
                    " (prefetch not assessed — drop --fast to check for latency-hiding structure)"
                } else {
                    ""
                };
                format!("no meaningful reuse or structure over {gets} {}{tail}.", gets_word(gets))
            }
        },
        // Two ways to land here, and they ask for different things from the reader:
        // a capture that is too SHORT wants a longer run, a capture that is too
        // RANGED wants chunk-level capture and will never resolve by running longer.
        Verdict::Unjudged => match ranged {
            Some((ranged, body_reads, frac)) => format!(
                "{ranged} of {body_reads} body reads were ranged (206) with no captured extent, so \
                 {:.0}% of this workload is sub-object and object-level caching can't be judged. A \
                 ranged read carries no Range header in the capture, so every range of an object \
                 would land on the same key and invent reuse that isn't there. Judging the \
                 remaining {gets} whole-object {} alone would describe only part of the workload. \
                 The denominator is BODY reads: a 304 Not Modified serves no body, so it is not \
                 in it.",
                frac * 100.0,
                gets_word(gets)
            ),
            None => format!(
                "only {gets} {} with low observed reuse — capture longer and re-run.",
                gets_word(gets)
            ),
        },
    }
}

// ── terminal rendering ──────────────────────────────────────────────────────
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const AMBER: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Render a [`TraceAnalysis`] as a human report (ANSI colour optional).
pub fn render(a: &TraceAnalysis, color: bool) -> String {
    let paint = |s: &str, code: &str| if color { format!("{code}{s}{RESET}") } else { s.to_string() };
    let bold = |s: &str| paint(s, BOLD);
    let dim = |s: &str| paint(s, DIM);
    // The banner tag reflects the ACTUAL recommendation. GoLatency now implies the
    // overlay hides latency (verdict matrix), so it's an unqualified amber. A NoGo
    // that still has (un-hideable) structure reads "little to gain", not a flat
    // "don't cache"; and a --fast NoGo never assessed latency at all.
    let has_struct = a.prefetch.as_ref().is_some_and(|p| p.has_structure);
    let (vcolor, vtag) = match a.verdict {
        Verdict::Go => (GREEN, "CACHE IT"),
        Verdict::GoLatency => (AMBER, "CACHE FOR LATENCY"),
        Verdict::NoGo if a.fast => (AMBER, "LOW REUSE (latency not assessed)"),
        Verdict::NoGo if has_struct => (AMBER, "LITTLE TO GAIN"),
        Verdict::NoGo => (RED, "DON'T CACHE"),
        // Unjudged has two causes and only one of them is about capture length; a
        // ranged-heavy capture will read exactly the same however long it runs.
        Verdict::Unjudged if a.ranged_unjudged => (AMBER, "CAN'T JUDGE (RANGED-HEAVY)"),
        Verdict::Unjudged => (AMBER, "TOO SHORT TO SAY"),
    };
    let mut o = String::new();
    let rule = "─".repeat(64);
    o.push_str(&format!("{}\n", bold("s3tap caching analysis")));
    o.push_str(&format!("{rule}\n"));

    // Scope line.
    let sampled = if a.sampled { " (sampled, leading slice)" } else { "" };
    // "GETs" alone was a denominator the reader could not check. `gets` counts only the
    // GETs the origin served a WHOLE body for, so a conditional-GET client (4500 x 304
    // beside 500 x 200 — exactly what `advise`'s refetch check recommends) read as "500
    // events, 500 GETs" here while `doctor` and `scorecard` counted all 5000 as
    // successes with zero errors. Say which GETs these are.
    o.push_str(&format!(
        "{} events, {} whole-body GETs, {} cache accesses, {} distinct keys  [{} mode]{}\n",
        a.events, a.gets, a.accesses, a.distinct, a.mode, dim(sampled)
    ));
    // Ranged reads the capture cannot place: disclose them rather than let the reader
    // assume the GET count is the whole read workload.
    if a.ranged_excluded > 0 {
        o.push_str(&format!(
            "{}\n",
            dim(&format!(
                "note: {} ranged (206) reads are excluded — the capture carries no Range \
                 header, so their extent is unknown and an object-level or chunk-level model \
                 would map every range of an object onto the same key",
                a.ranged_excluded
            ))
        ));
    }
    // When the working set exceeds the ladder cap, reuse that only materializes with
    // a larger cache is untested — so a LOW-reuse verdict is only a lower bound. Show
    // this in EVERY path (the knee note below fires only when the knee hits the cap).
    if a.ladder_capped {
        // The cap is MAX_CAP *capacity units*, and a capacity unit is whatever the
        // mode says it is. Only chunk mode has a byte equivalent (MAX_CAP x the
        // block size); in object mode a unit is one object of unknown size, so
        // quoting "32 GiB" there modelled nothing.
        let bytes = a
            .ladder_cap_bytes
            .map(|b| format!(" ({})", human_bytes(b)))
            .unwrap_or_default();
        o.push_str(&format!(
            "{}\n",
            dim(&format!(
                "note: working set ({} keys) exceeds the {}-{}{bytes} analysis cap — reuse that \
                 needs a larger cache is untested, so a low-reuse verdict here is a lower bound",
                a.distinct,
                MAX_CAP,
                unit1(a.mode)
            ))
        ));
    }
    o.push('\n');

    // Verdict banner.
    o.push_str(&format!("{}  {}\n\n", paint(vtag, vcolor), a.headline));

    // Retention block.
    o.push_str(&format!("{}\n", bold("Retention (which cache, and how big)")));
    // Two different ladders can produce a "recommended size", and each figure must be
    // quoted with the hit-rate measured on ITS OWN ladder:
    //   - byte mode: the BYTE ladder's knee (bytes), run over the object trace;
    //   - count mode: the count ladder's knee, in chunks/objects.
    // Mixing them printed "8.0 GiB (captures 63% of the reuse)" where the 63% came
    // from a 4096-chunk count run at a wholly different cache size.
    let count_size = format!("{} {}", a.knee_cap, unit(a.mode));
    let (size, size_axis, knee_note) = match &a.byte {
        Some(b) => {
            let note = if b.knee_bytes >= b.working_set_bytes {
                format!(
                    "needs ~the full working set for {:.0}% of the reuse; no smaller knee",
                    b.knee_hit * 100.0
                )
            } else {
                format!("captures {:.0}% of the reuse; larger buys little", b.knee_hit * 100.0)
            };
            // Labelled, because it is NOT the axis the per-policy table below runs on.
            (human_bytes(b.knee_bytes), " [object-level byte axis]", note)
        }
        None => {
            let note = if a.ladder_capped && a.knee_cap >= MAX_CAP {
                format!(
                    "captures {:.0}% within the {}-{} cap (lower bound; see note above)",
                    a.knee_hit * 100.0,
                    MAX_CAP,
                    unit1(a.mode)
                )
            } else if a.knee_cap >= a.distinct {
                format!(
                    "needs ~the full working set for {:.0}% of the reuse; no smaller knee",
                    a.knee_hit * 100.0
                )
            } else {
                format!("captures {:.0}% of the reuse; larger buys little", a.knee_hit * 100.0)
            };
            (count_size.clone(), "", note)
        }
    };
    // A knee is only a RECOMMENDATION when there is reuse to size for. On a flat curve
    // every rung is within tolerance of the ceiling and the search returns the smallest
    // cap, so a one-shot workload printed "DON'T CACHE" and then, three lines down,
    // "Recommended size (knee): 2 objects (captures 0% of the reuse)". Below the go
    // floor there is no size to recommend, and the per-policy table header still names
    // the cap its rows were measured at.
    if a.ranged_unjudged {
        // Every figure in this and the following blocks (best-policy line, ARC/S3-FIFO
        // deltas, the per-policy table, Egress-$, Prefetching) was measured over the
        // whole-object REMAINDER only, which is not this workload: a ranged-heavy capture
        // with a reusable whole-object subset would otherwise print a confident "LRU saves
        // X%" or even "YES, for latency" headline directly beneath a CAN'T JUDGE banner.
        // So none of it renders here; the disclaimer below is the whole story.
        o.push_str(&format!(
            "  {}\n",
            dim(&format!(
                "no size recommended: {} of {} body reads were ranged (206) with no captured \
                 extent, so retention and prefetching cannot be judged for this workload \
                 (a 304 serves no body, so it is not in that denominator)",
                a.ranged_reads, a.body_reads
            ))
        ));
        return o;
    } else if a.recommended_cap.is_some() {
        o.push_str(&format!(
            "  Recommended size (knee): {}{}  ({knee_note})\n",
            bold(&size),
            dim(size_axis)
        ));
    } else {
        o.push_str(&format!(
            "  {}\n",
            dim(&format!(
                "no size recommended: LRU saves at most {:+.3} at any simulated cache size, \
                 so there is no knee to size to",
                a.lru_max
            ))
        ));
    }
    o.push_str(&format!(
        "  Best demand policy: {}  net {:+.3}   {} LRU {:+.3} · OPT ceiling {:+.3}\n",
        bold(a.rows.iter().find(|r| r.policy == a.best_retention).map(|r| r.label.as_str()).unwrap_or(&a.best_retention_label)),
        a.best_retention_net, dim("|"), a.lru_max, a.opt_max
    ));
    // Every figure on this line is measured at ONE cache size, `knee_cap`, and says so.
    // `opt_max - lru_max` is a difference of two maxima taken over the whole ladder,
    // potentially at different rungs, so printing it beside the knee-measured ARC and
    // S3-FIFO deltas invited dividing one by the other.
    o.push_str(&format!(
        "  ARC vs LRU: {:+.3}   S3-FIFO vs LRU: {:+.3}   {}\n",
        a.arc_delta, a.s3fifo_delta,
        dim(&format!("(gap to optimal @ {count_size}: {:.3})", a.opt_gap_at_knee))
    ));
    if let Some(b) = &a.byte {
        o.push_str(&format!(
            "  Egress-$: saves up to {:.0}% of GET requests, {:.0}% of egress bytes ({} working set)\n",
            b.req_savings_max * 100.0, b.egress_savings_max * 100.0, human_bytes(b.working_set_bytes)
        ));
    }

    // Per-policy table at the knee.
    o.push('\n');
    // Labelled with the cache size the rows were ACTUALLY simulated at (`knee_cap`,
    // the count ladder), not with the byte knee — every row here is `get(p,
    // knee_cap)`, so a byte header put "8.0 GiB" above rows run at 4096 chunks.
    o.push_str(&format!("  {}\n", dim(&format!("per-policy @ {count_size}:"))));
    o.push_str(&format!(
        "  {:<16}{:>9}{:>11}{:>9}{:>8}\n",
        "policy", "hit", "net", "pf/acc", "pf_lat"
    ));
    for r in &a.rows {
        o.push_str(&format!(
            "  {:<16}{:>9.3}{:>11.3}{:>9.3}{:>8.3}\n",
            r.label, r.hit_rate, r.net_savings, r.pf_per_access, r.pf_latency
        ));
    }

    // Prefetch block.
    o.push('\n');
    o.push_str(&format!("{}\n", bold("Prefetching (will it help?)")));
    match &a.prefetch {
        None if a.fast => {
            o.push_str(&format!("  {}\n", dim("not assessed — re-run without --fast for the latency verdict")));
        }
        None => {
            o.push_str(&format!("  {}\n", dim("no prefetch pass run")));
        }
        // Structure present AND the shippable overlay actually hides latency.
        Some(p) if p.hides_latency => {
            o.push_str(&format!(
                "  {}: structure {:+.0}% (best predictor: {} at {:.0}% hit).\n",
                paint("YES, for latency", GREEN), p.structure * 100.0, p.best_prefetcher_label, p.best_pf_hit * 100.0
            ));
            o.push_str(&format!(
                "  Ship the self-tuning lead-gated overlay: it held origin cost at the LRU floor \
                 (net {:+.3} vs {:+.3}) and hid {:.0}% of a fetch on the predictable subset.\n",
                p.overlay_net, p.lru_net_at_cap, p.overlay_latency_hidden * 100.0
            ));
            o.push_str(&format!(
                "  {}\n",
                dim("caveats: assumes spare bandwidth + background-priority prefetch; 100 ms modelled fetch")
            ));
        }
        // Structure present, but not deep enough to hide the fetch (the study's common case).
        Some(p) if p.has_structure => {
            // "at X% hit" — matching the hides_latency branch above. `best_pf_hit` is the
            // rung's whole-cache HIT RATE, most of which the demand cache would have served
            // anyway; phrasing it as "{predictor} predicts X% of accesses" turned it into a
            // prediction-accuracy claim. With LRU at 0.60 and Markov-1 at 0.72 that read
            // "Markov-1 predicts 72% of accesses" for a predictor contributing 12 points, so
            // a reader sizing a prefetcher off it was out by 6x. The prediction contribution
            // is `structure`, which the same line already prints.
            o.push_str(&format!(
                "  {}: structure {:+.0}% (best predictor: {} at {:.0}% hit), but the self-tuning overlay \
                 hid only {:.0}% of a fetch — the sequence isn't predictable far enough ahead to cover \
                 a 100 ms fetch, so the overlay correctly declines and stays at the LRU cost floor.\n",
                paint("STRUCTURE, BUT NO HIDEABLE LATENCY", AMBER),
                p.structure * 100.0, p.best_prefetcher_label, p.best_pf_hit * 100.0,
                p.overlay_latency_hidden * 100.0
            ));
            o.push_str(&format!("  {}\n", dim("a faster link (smaller fetch) or deeper structure could change this")));
        }
        // No exploitable structure at all.
        Some(p) => {
            o.push_str(&format!(
                "  {}: structure {:+.0}% < 10% — guessing would cost more origin fetches than the reuse it buys.\n",
                paint("NO", RED), p.structure * 100.0
            ));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3tap_replay::trace::{NormEvent, Op};

    // Build a NormEvent GET on `object_id`.
    fn get(ts: u64, id: &str) -> NormEvent {
        NormEvent { ts_ns: ts, op: Op::Get, object_id: id.to_string(), range: None, size: Some(1 << 20), version: None, status: Some(200) }
    }

    fn obj_opts() -> AnalyzeOpts {
        AnalyzeOpts { block_bytes: None, max_events: 0, fast: false, deep: false }
    }

    #[test]
    fn high_reuse_workload_says_cache_it() {
        // 30 hot objects looped 200 times = heavy reuse; LRU alone caches it.
        let mut t = Vec::new();
        for pass in 0..200u64 {
            for o in 0..30u64 {
                t.push(get(pass * 100 + o, &format!("o{o}")));
            }
        }
        let a = analyze_trace(&t, &obj_opts());
        assert_eq!(a.verdict, Verdict::Go, "{}", a.headline);
        assert!(a.cache_go && a.lru_max > 0.5);
    }

    // Exercise the terminal-rendering section (`render`) across every verdict branch and both
    // color modes. render() had no test, so a panic or a broken format string there would ship
    // silently. This drives the object-size, byte-size and fast paths, and both color modes.
    #[test]
    fn render_covers_every_verdict_and_both_color_modes() {
        let hot: Vec<NormEvent> = (0..200u64)
            .flat_map(|pass| (0..30u64).map(move |o| get(pass * 100 + o, &format!("o{o}"))))
            .collect();
        let unique: Vec<NormEvent> = (0..5_000u64).map(|i| get(i, &format!("u{i}"))).collect();
        let short: Vec<NormEvent> = (0..500u64).map(|i| get(i, &format!("u{i}"))).collect();

        let go = analyze_trace(&hot, &obj_opts());
        let nogo = analyze_trace(&unique, &obj_opts());
        let unjudged = analyze_trace(&short, &obj_opts());

        for a in [&go, &nogo, &unjudged] {
            for color in [false, true] {
                let out = render(a, color);
                assert!(out.contains("s3tap caching analysis"), "banner missing");
                assert!(out.contains("Retention"), "retention block missing");
                assert!(out.contains(a.headline.as_str()), "render must include the verdict headline");
            }
        }
        // The verdict tags are branch-specific.
        assert!(render(&go, false).contains("CACHE IT"));
        assert!(render(&unjudged, false).contains("TOO SHORT TO SAY"));

        // Byte-sizing path (a distinct branch from object-count sizing).
        let byte = analyze_trace(&hot, &AnalyzeOpts { block_bytes: Some(DEFAULT_BLOCK), max_events: 0, fast: false, deep: false });
        assert!(render(&byte, false).contains("s3tap caching analysis"));

        // --fast NoGo: latency never assessed, its own banner tag + prefetch tail.
        let fast = analyze_trace(&unique, &AnalyzeOpts { block_bytes: None, max_events: 0, fast: true, deep: false });
        assert!(render(&fast, false).contains("LOW REUSE"));
    }

    #[test]
    fn one_shot_workload_says_dont_cache() {
        // Every object unique -> no reuse, no structure -> NoGo above the gate.
        let t: Vec<NormEvent> = (0..5_000u64).map(|i| get(i, &format!("u{i}"))).collect();
        let a = analyze_trace(&t, &obj_opts());
        assert_eq!(a.verdict, Verdict::NoGo, "{}", a.headline);
        assert!(a.prefetch.is_some_and(|p| !p.has_structure));
    }

    #[test]
    fn short_capture_is_unjudged_not_nogo() {
        let t: Vec<NormEvent> = (0..500u64).map(|i| get(i, &format!("u{i}"))).collect();
        let a = analyze_trace(&t, &obj_opts());
        assert_eq!(a.verdict, Verdict::Unjudged, "{}", a.headline);
    }

    #[test]
    fn streaming_sequence_is_latency_only() {
        // Low reuse (each object seen ~once) but a deterministic A->B->C chain:
        // low LRU, high structure -> cache-for-latency.
        let mut t = Vec::new();
        let mut ts = 0u64;
        for base in 0..2_000u64 {
            for step in 0..3u64 {
                ts += 1;
                t.push(get(ts, &format!("s{}_{}", base % 400, step)));
            }
        }
        let a = analyze_trace(&t, &obj_opts());
        // The Markov predictor should see the fixed step chain as structure.
        assert!(a.prefetch.as_ref().is_some_and(|p| p.structure > 0.0), "{}", a.headline);
    }

    #[test]
    fn fast_mode_skips_the_prefetch_pass() {
        let mut t = Vec::new();
        for pass in 0..200u64 {
            for o in 0..30u64 {
                t.push(get(pass * 100 + o, &format!("o{o}")));
            }
        }
        let a = analyze_trace(&t, &AnalyzeOpts { block_bytes: None, max_events: 0, fast: true, deep: false });
        assert!(a.prefetch.is_none() && a.fast);
        assert_eq!(a.verdict, Verdict::Go); // retention verdict still stands
    }

    #[test]
    fn structure_without_hideable_latency_is_nogo_not_golatency() {
        // A deterministic cycle LONGER than the max cap, all at one timestamp: LRU
        // thrashes (no reuse at any size, lru_max ~ 0), yet Markov predicts the next
        // object perfectly (high structure) — but with zero lead the overlay hides
        // nothing. The top-line verdict must be NoGo (honest for a machine reading
        // the `verdict` field), NOT GoLatency, even though structure is present.
        let cycle = (MAX_CAP + 1) as usize; // > the ladder top, so LRU never caches it
        let mut t = Vec::new();
        for _ in 0..3 {
            for i in 0..cycle {
                t.push(NormEvent {
                    ts_ns: 0, // one batch: no lead, so nothing is hideable
                    op: Op::Get,
                    object_id: format!("c{i}"),
                    range: None,
                    size: None,
                    version: None,
                    status: Some(200),
                });
            }
        }
        let opts = AnalyzeOpts { block_bytes: None, max_events: 0, fast: false, deep: false };
        let a = analyze_trace(&t, &opts);
        let p = a.prefetch.as_ref().expect("prefetch assessed");
        assert!(a.lru_max < GO_FLOOR, "cycle > cap: no cacheable reuse (lru_max {})", a.lru_max);
        assert!(p.has_structure, "Markov should predict the cycle (structure {})", p.structure);
        assert!(!p.hides_latency, "zero-lead batch hides no latency");
        assert_eq!(a.verdict, Verdict::NoGo, "structure w/o hideable latency is NoGo: {}", a.headline);
    }

    #[test]
    fn load_trace_reads_all_formats_and_skips_junk() {
        // A NormEvent JSON line, an IBM COS line, a blank, and garbage.
        let nj = serde_json::to_string(&get(5, "abc")).unwrap();
        let input = format!("{nj}\n1000 REST.GET.OBJECT obj1 4096\n\nnot a trace line\n");
        let (t, skipped) = load_trace(&input, 0);
        assert_eq!(t.len(), 2, "NormEvent + IBM both parse: {t:?}");
        assert_eq!(skipped, 1, "one junk line counted; the blank is silent");
    }

    #[test]
    fn load_trace_caps_the_parse_but_reads_one_past_for_truncation() {
        // 10 GETs, limit 3 -> parse at most 4 (limit+1), so the caller's sampler
        // sees len > limit and can flag truncation while the Vec stays bounded.
        let input: String =
            (0..10).map(|i| format!("{i} REST.GET.OBJECT obj{i} 4096\n")).collect();
        let (t, _) = load_trace(&input, 3);
        assert_eq!(t.len(), 4, "capped at limit+1");
        let (all, _) = load_trace(&input, 0);
        assert_eq!(all.len(), 10, "0 = unlimited");
    }

    /// The rendered "Recommended size (knee): …" line.
    fn size_line(a: &TraceAnalysis) -> String {
        render(a, false)
            .lines()
            .find(|l| l.contains("Recommended size"))
            .expect("size line")
            .to_string()
    }

    #[test]
    fn distinct_counts_get_keys_only_not_head_keys() {
        // 4 hot objects GETed 400 times, amid 2000 HEADs of unique keys. Every
        // simulator rung skips HEAD, so the working set (and therefore the cap
        // ladder top and the "full working set" branch) must be the GET one.
        let mut t = Vec::new();
        for i in 0..2_000u64 {
            t.push(NormEvent { op: Op::Head, ..get(i * 2, &format!("h{i}")) });
            if i % 5 == 0 {
                t.push(get(i * 2 + 1, &format!("g{}", i % 4)));
            }
        }
        let a = analyze_trace(&t, &obj_opts());
        assert_eq!(a.distinct, 4, "HEAD-only keys are not cache keys");
        assert_eq!(a.gets, 400);
        assert!(!a.ladder_capped, "4 keys is nowhere near the ladder top");
    }

    #[test]
    fn ladder_cap_note_names_the_mode_unit_and_only_bytes_a_chunk_cap() {
        // Working set past the ladder top in BOTH modes. The note's unit must follow
        // the mode, and "32 GiB" (MAX_CAP x the block size) models nothing in object
        // mode, where a capacity unit is one whole object.
        let big: Vec<NormEvent> = (0..5_000u64).map(|i| get(i, &format!("u{i}"))).collect();

        let obj = analyze_trace(&big, &obj_opts());
        assert!(obj.ladder_capped && obj.ladder_cap_bytes.is_none());
        let out = render(&obj, false);
        assert!(out.contains("exceeds the 4096-object analysis cap"), "{out}");
        assert!(!out.contains("32 GiB") && !out.contains("chunk"), "no chunk fiction: {out}");

        let chunk = analyze_trace(
            &big,
            &AnalyzeOpts { block_bytes: Some(DEFAULT_BLOCK), max_events: 0, fast: true, deep: false },
        );
        assert_eq!(chunk.ladder_cap_bytes, Some(MAX_CAP * DEFAULT_BLOCK));
        assert!(
            render(&chunk, false).contains("exceeds the 4096-chunk (32.0 GiB) analysis cap"),
            "{}",
            render(&chunk, false)
        );
    }

    #[test]
    fn per_policy_table_is_labelled_with_the_size_it_was_run_at() {
        // A byte-sized workload: the byte ladder recommends a size in bytes while
        // every table row is `get(policy, knee_cap)` on the COUNT ladder. The header
        // must name the count size — it used to print the byte knee above rows
        // simulated at a different cache size entirely.
        let hot: Vec<NormEvent> = (0..200u64)
            .flat_map(|pass| (0..30u64).map(move |o| get(pass * 100 + o, &format!("o{o}"))))
            .collect();
        let a = analyze_trace(&hot, &obj_opts());
        let b = a.byte.as_ref().expect("sized trace -> byte verdict");
        let out = render(&a, false);
        assert!(
            out.contains(&format!("per-policy @ {} {}:", a.knee_cap, unit(a.mode))),
            "table header must carry the count-ladder size: {out}"
        );
        // …and the byte figure stays on the size line, marked as its own axis.
        let line = size_line(&a);
        assert!(line.contains(&human_bytes(b.knee_bytes)), "{line}");
        assert!(line.contains("[object-level byte axis]"), "{line}");
    }

    #[test]
    fn byte_knee_is_quoted_with_the_byte_ladders_own_hit_rate() {
        // The percentage next to a byte knee must come from the BYTE ladder, not from
        // `knee_hit` (the count ladder's, measured at a different cache size).
        let hot: Vec<NormEvent> = (0..200u64)
            .flat_map(|pass| (0..30u64).map(move |o| get(pass * 100 + o, &format!("o{o}"))))
            .collect();
        let a = analyze_trace(&hot, &obj_opts());
        let b = a.byte.as_ref().expect("byte verdict");
        assert!(
            size_line(&a).contains(&format!("{:.0}%", b.knee_hit * 100.0)),
            "size line {} should quote the byte knee hit {}",
            size_line(&a),
            b.knee_hit
        );
    }

    #[test]
    fn headline_quotes_the_size_its_savings_were_measured_at() {
        // `best_net` is a count-ladder number; the headline must not attach it to the
        // byte knee (a different ladder over a different trace).
        let hot: Vec<NormEvent> = (0..200u64)
            .flat_map(|pass| (0..30u64).map(move |o| get(pass * 100 + o, &format!("o{o}"))))
            .collect();
        let a = analyze_trace(&hot, &obj_opts());
        assert_eq!(a.verdict, Verdict::Go);
        assert!(a.byte.is_some(), "byte sizing is on, so this is the mixing case");
        assert!(a.headline.contains("objects"), "{}", a.headline);
        assert!(
            !a.headline.contains("MiB") && !a.headline.contains("GiB"),
            "no byte size on a count-ladder savings figure: {}",
            a.headline
        );
    }

    #[test]
    fn deep_reports_the_frequency_rung_but_never_calls_it_structure() {
        // Popularity-skewed, NO sequence chain: successor is random, only the
        // popularity distribution is learnable. `frequency` is an LFU pin, not a
        // sequence prefetcher, so it must appear as a row (--deep paid for it) yet
        // never define `structure` or win `best_prefetcher`.
        let mut seed = 0x2545F491_4F6CDD1Du64;
        let t: Vec<NormEvent> = (0..1_500u64)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let r = (seed % 1000) as f64 / 1000.0;
                let obj = (30f64.powf(r) - 1.0) as u64 % 30;
                get(i, &format!("z{obj}"))
            })
            .collect();
        let deep = analyze_trace(
            &t,
            &AnalyzeOpts { block_bytes: None, max_events: 0, fast: false, deep: true },
        );
        let freq = deep.rows.iter().find(|r| r.policy == "frequency").expect("--deep frequency row");
        assert_eq!(freq.label, "Frequency (LFU pin)", "labelled as the demand policy it is");
        let p = deep.prefetch.as_ref().expect("prefetch assessed");
        assert!(
            PREFETCHERS.contains(&p.best_prefetcher.as_str()),
            "structure/best_prefetcher are sequence-only, got {}",
            p.best_prefetcher
        );
        // The cheap default path never computes it, so it must not appear there.
        let shallow = analyze_trace(&t, &obj_opts());
        assert!(!shallow.rows.iter().any(|r| r.policy == "frequency"));
    }

    /// One s3tap `s3tap.operation/1` JSONL line — the format `analyze --from` reads.
    fn op_line(key: &str, ts: u64, status: u16, len: u64) -> String {
        format!(
            r#"{{"schema":"{}","s3_op":"GetObject","bucket":"b","key_hash":"{key}",
               "ts_ns":"{ts}","http_status":{status},"content_length":{len}}}"#,
            s3tap_replay::adapt::OPERATION_SCHEMA
        )
        .replace('\n', "")
    }

    #[test]
    fn a_503_storm_is_not_reuse_through_the_analyze_ingest_path() {
        // `analyze` has its own ingest path (load_trace -> parse_trace_line ->
        // from_record) and used to have NO status gate, so 300 keys retried 21 times
        // through a 503 storm (6300 records, 300 served bodies) arrived as 6300 Op::Get
        // over 300 keys: lru_max ~0.95 and "CACHE IT — best demand policy LRU saves
        // +0.95 origin fetches/access". Not one of those hits was a body a cache could
        // have served. `advise`, which filtered at its own bridge, stayed quiet on the
        // same capture. The gate now lives in the shared adapter, so both agree.
        let mut lines = String::new();
        let mut ts = 0u64;
        for k in 0..300u32 {
            for attempt in 0..21u32 {
                ts += 1;
                let status = if attempt == 20 { 200 } else { 503 };
                lines.push_str(&op_line(&format!("k{k}"), ts, status, 4096));
                lines.push('\n');
            }
        }
        let (trace, skipped) = load_trace(&lines, 0);
        assert_eq!(trace.len(), 300, "only the served bodies are trace events");
        assert_eq!(skipped, 6000, "the failed attempts are counted as skipped, not hidden");

        let a = analyze_trace(&trace, &obj_opts());
        assert_eq!(a.gets, 300);
        assert_eq!(a.distinct, 300, "one access per key: nothing to reuse");
        assert!(a.lru_max < 1e-9, "no reuse at any cache size, got {}", a.lru_max);
        assert_ne!(a.verdict, Verdict::Go, "{}", a.headline);
        assert!(!render(&a, false).contains("CACHE IT"), "{}", render(&a, false));
    }

    #[test]
    fn a_ranged_stream_does_not_collapse_onto_one_key() {
        // A 1 GiB object streamed as 1000 x 1 MiB ranged GETs. Every one is a 206 whose
        // `content_length` is the RANGE length and whose Range header the capture never
        // saw, so object mode keyed all 1000 on the object and chunk mode mapped all
        // 1000 onto "<obj>#0": distinct 1, hit rate 0.999, "CACHE IT" for a workload
        // whose true reuse is ZERO. The adapter now refuses to call a 206 an
        // object-level read, so the collapse is unreachable and the excluded reads are
        // disclosed instead of being silently converted into reuse.
        let lines: String = (0..1000u64)
            .map(|i| op_line("onegig", i + 1, 206, 1 << 20) + "\n")
            .collect();
        let (trace, _) = load_trace(&lines, 0);
        assert_eq!(trace.len(), 1000);

        for opts in [obj_opts(), AnalyzeOpts::default()] {
            let a = analyze_trace(&trace, &opts);
            assert_eq!(a.gets, 0, "[{}] no whole-object read was observed", a.mode);
            assert_eq!(a.accesses, 0, "[{}] nothing for a cache to serve", a.mode);
            assert_eq!(a.distinct, 0, "[{}] and no key to serve it from", a.mode);
            assert_eq!(a.ranged_excluded, 1000);
            assert_ne!(a.verdict, Verdict::Go, "[{}] {}", a.mode, a.headline);
            let out = render(&a, false);
            assert!(!out.contains("CACHE IT"), "{out}");
            assert!(out.contains("1000 ranged (206) reads are excluded"), "{out}");
        }
    }

    #[test]
    fn a_ranged_read_that_carries_its_extent_is_judged_not_refused() {
        // The gate's justification is that a ranged read's extent is UNKNOWN, so neither
        // mode can place it. A raw NormEvent trace can carry `Op::Get` WITH a populated
        // `range` and a 206 status, and `to_blocks` expands exactly that span — so this
        // is a trace the code models correctly. Keying the gate on the status alone
        // refused it anyway: an 8 MiB object re-read 500 times as 8 x 1 MiB ranged reads
        // expands into 8 chunk keys with ~0.998 reuse (a genuine CACHE IT) and printed
        // CAN'T JUDGE (RANGED-HEAVY) with a null recommendation, while the SAME events
        // with `status` omitted got the right verdict. The flag turned on a field
        // carrying no information about modellability.
        const MIB: u64 = 1 << 20;
        let ranged: Vec<NormEvent> = (0..500u64)
            .flat_map(|pass| {
                (0..8u64).map(move |part| NormEvent {
                    ts_ns: pass * 8 + part,
                    op: Op::Get,
                    object_id: "eightmib".into(),
                    range: Some((part * MIB, (part + 1) * MIB - 1)),
                    size: Some(MIB), // a 206's Content-Length is the RANGE length
                    version: None,
                    status: Some(206),
                })
            })
            .collect();
        // The same events with the status omitted: identical extents, so the verdict
        // must be identical too.
        let untagged: Vec<NormEvent> =
            ranged.iter().map(|e| NormEvent { status: None, ..e.clone() }).collect();

        let opts = || AnalyzeOpts { block_bytes: Some(MIB), max_events: 0, fast: true, deep: false };
        let a = analyze_trace(&ranged, &opts());
        let b = analyze_trace(&untagged, &opts());
        assert_eq!(a.distinct, 8, "1 MiB chunks of an 8 MiB object: {}", a.distinct);
        assert!(!a.ranged_unjudged, "the extents are known, so the gate must not fire");
        assert_eq!(a.ranged_reads, 0, "a placeable 206 is not evidence of unjudgeability");
        assert_eq!(a.verdict, Verdict::Go, "{}", a.headline);
        assert_eq!(
            (a.verdict, a.recommended_cap),
            (b.verdict, b.recommended_cap),
            "the status field must not change the verdict here"
        );
        assert!(!render(&a, false).contains("CAN'T JUDGE"), "{}", render(&a, false));

        // …and a 206 with NO extent still trips the gate, which is the case it is for.
        let unplaceable: Vec<NormEvent> =
            ranged.iter().map(|e| NormEvent { range: None, ..e.clone() }).collect();
        let c = analyze_trace(&unplaceable, &opts());
        assert!(c.ranged_unjudged, "an unplaceable 206 is still unjudgeable");
        assert_eq!(c.verdict, Verdict::Unjudged);
    }

    #[test]
    fn an_all_error_capture_is_reported_as_a_capture_not_as_junk() {
        // 6300 well-formed s3tap records in which no GET succeeded. The trace is empty,
        // and the caller's only number used to be `skipped`, so `analyze` answered "no
        // usable trace events in the input (6300 line(s) skipped). Expected s3tap JSONL
        // records, NormEvent JSON, or IBM COS lines." — telling an operator that a valid
        // capture is not a trace, while `doctor` on the same file reports 6300 operations
        // and a 100% error rate. The split count is what lets the message say which.
        let mut lines = String::new();
        for k in 0..300u32 {
            for attempt in 0..21u32 {
                lines.push_str(&op_line(&format!("k{k}"), u64::from(attempt) + 1, 503, 4096));
                lines.push('\n');
            }
        }
        let (trace, counts) = load_trace_counted(&lines, 0);
        assert!(trace.is_empty());
        assert_eq!(counts.skipped, 6300);
        assert_eq!(
            counts.operations_dropped, 6300,
            "every line was a capture record, not junk"
        );

        // A mid-flight attach: every op carries "ts_ns": null, so nothing is placeable
        // in time. Still a capture.
        let midflight: String = (0..50)
            .map(|i| {
                format!(
                    r#"{{"schema":"{}","s3_op":"GetObject","bucket":"b","key_hash":"k{i}","ts_ns":null,"http_status":200}}"#,
                    s3tap_replay::adapt::OPERATION_SCHEMA
                ) + "\n"
            })
            .collect();
        let (t, c) = load_trace_counted(&midflight, 0);
        assert!(t.is_empty());
        assert_eq!((c.skipped, c.operations_dropped), (50, 50));

        // Genuine junk stays junk, so the two counts never collapse into one.
        let (t, c) = load_trace_counted("not a trace line\n{\"schema\":\"s3tap.connection/2\"}\n", 0);
        assert!(t.is_empty());
        assert_eq!((c.skipped, c.operations_dropped), (2, 0));

        // And a healthy capture reports neither.
        let ok: String = (0..10).map(|i| op_line("k", i + 1, 200, 4096) + "\n").collect();
        let (t, c) = load_trace_counted(&ok, 0);
        assert_eq!(t.len(), 10);
        assert_eq!(c, LoadCounts::default());
    }

    #[test]
    fn no_knee_is_published_when_there_is_no_reuse_to_size_for() {
        // A 5000-unique-key one-shot has net_savings 0.0 at EVERY cap, so every rung is
        // within tolerance of the ceiling and the knee search returns the smallest one.
        // The report printed "DON'T CACHE" and three lines below "Recommended size
        // (knee): 2 objects (captures 0% of the reuse)", with "knee_cap": 2 in --json.
        let t: Vec<NormEvent> = (0..5_000u64).map(|i| get(i, &format!("u{i}"))).collect();
        let a = analyze_trace(&t, &obj_opts());
        assert_eq!(a.verdict, Verdict::NoGo);
        assert_eq!(a.recommended_cap, None, "no reuse -> no size to recommend");
        let out = render(&a, false);
        assert!(out.contains("DON'T CACHE"), "{out}");
        assert!(!out.contains("Recommended size"), "{out}");
        assert!(out.contains("no size recommended"), "{out}");
        // `knee_cap` survives as the site the per-policy rows were measured at, and the
        // table header still names it, so nothing is unattributed.
        assert!(out.contains(&format!("per-policy @ {} objects:", a.knee_cap)), "{out}");
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["recommended_cap"].is_null(), "{j}");

        // …and a workload that DOES pay still gets its size.
        let hot: Vec<NormEvent> = (0..200u64)
            .flat_map(|pass| (0..30u64).map(move |o| get(pass * 100 + o, &format!("o{o}"))))
            .collect();
        let go = analyze_trace(&hot, &obj_opts());
        assert_eq!(go.recommended_cap, Some(go.knee_cap));
        assert!(render(&go, false).contains("Recommended size"));
    }

    #[test]
    fn the_gap_to_optimal_is_measured_at_the_same_cap_as_the_deltas_beside_it() {
        // `arc_delta`/`s3fifo_delta` are measured AT the knee while the gap used to be
        // `opt_max - lru_max`, two maxima over the WHOLE ladder that need not come from
        // the same rung — so dividing one by the other, which the shared line invites,
        // compared numbers from different cache sizes.
        let mut t = Vec::new();
        for pass in 0..100u64 {
            for o in 0..80u64 {
                t.push(get(pass * 1000 + o, &format!("o{o}")));
            }
        }
        let a = analyze_trace(&t, &obj_opts());
        let at = |p: &str| a.rows.iter().find(|r| r.policy == p).unwrap().net_savings;
        assert!((a.opt_gap_at_knee - (at("opt") - at("null")).max(0.0)).abs() < 1e-12);
        let line = render(&a, false)
            .lines()
            .find(|l| l.contains("gap to optimal"))
            .expect("gap line")
            .to_string();
        assert!(line.contains(&format!("gap to optimal @ {} objects", a.knee_cap)), "{line}");
        assert!(line.contains(&format!("{:.3}", a.opt_gap_at_knee)), "{line}");
    }

    #[test]
    fn the_no_hideable_latency_line_never_claims_prediction_accuracy() {
        // `best_pf_hit` is the rung's whole-cache HIT RATE, most of which the demand
        // cache serves on its own. Printed as "{predictor} predicts X% of accesses" it
        // read as prediction accuracy: LRU 0.60 with Markov-1 0.72 announced "Markov-1
        // predicts 72% of accesses" for a predictor worth 12 points, so a reader sizing
        // a prefetcher off it was out by 6x. The prediction contribution is `structure`,
        // which the same line already prints.
        let cycle = (MAX_CAP + 1) as usize;
        let mut t = Vec::new();
        for _ in 0..3 {
            for i in 0..cycle {
                t.push(NormEvent { ts_ns: 0, ..get(0, &format!("c{i}")) });
            }
        }
        let a = analyze_trace(&t, &obj_opts());
        let p = a.prefetch.as_ref().expect("prefetch assessed");
        assert!(p.has_structure && !p.hides_latency, "the branch under test");
        let out = render(&a, false);
        assert!(out.contains("STRUCTURE, BUT NO HIDEABLE LATENCY"), "{out}");
        assert!(
            out.contains(&format!("best predictor: {} at", p.best_prefetcher_label)),
            "{out}"
        );
        assert!(!out.contains("predicts"), "a hit rate is not a prediction rate: {out}");
    }

    #[test]
    fn a_tied_prefetcher_race_is_broken_explicitly_not_by_array_order() {
        // `max_by` returns the LAST maximum, over an array whose rows exist only at the
        // cost level that computed them — so an exact tie recommended Markov-1 in default
        // mode and Adaptive under --deep on byte-identical data. Ties now go to the
        // cheaper rung, then to the earlier (simpler) one.
        let row = |pred: &str, hit: f64, pf: f64| Row {
            predictor: pred.to_string(),
            cap: 4,
            hit_rate: hit,
            pf_precision: 0.5,
            pf_per_access: pf,
            net_savings: hit,
            pf_latency: 0.0,
        };
        let strace = [get(1, "a"), get(2, "b")];

        // Exact tie on hit rate AND cost: the earlier, always-present rung wins, so the
        // answer does not depend on which rungs this cost level happened to compute.
        let rows = vec![row("null", 0.5, 0.0), row("markov", 0.8, 0.3), row("adaptive", 0.8, 0.3)];
        let p = prefetch_verdict(&strace, &rows, &[4]).expect("verdict");
        assert_eq!(p.best_prefetcher, "markov");
        // Same rows, reversed: order of arrival must not matter either.
        let mut rev = rows.clone();
        rev.reverse();
        assert_eq!(prefetch_verdict(&strace, &rev, &[4]).unwrap().best_prefetcher, "markov");

        // Tie on hit rate, cheaper speculation: the cheaper rung wins on merit.
        let cheap = vec![row("null", 0.5, 0.0), row("markov", 0.8, 0.3), row("adaptive", 0.8, 0.1)];
        assert_eq!(prefetch_verdict(&strace, &cheap, &[4]).unwrap().best_prefetcher, "adaptive");
    }

    #[test]
    fn a_ranged_heavy_capture_is_unjudged_in_analyze_exactly_as_in_advise() {
        // THE SAME records through BOTH commands. 3000 whole-object 200 GETs over 50
        // keys plus 400 ranged 206 reads = 11.8% ranged, above RANGED_FRAC_MAX.
        // `advise_caching` bailed out with a lone `advisor-cache-unjudged`; `analyze`
        // had no ranged gate in its verdict matrix at all (it consulted `ranged_share`
        // only inside `byte_verdict`, which suppresses the BYTE axis and nothing else)
        // and answered CACHE IT with a recommended_cap on the identical file. The gate
        // is the same constant and now fires on both paths.
        let ops = crate::fixtures::ranged_heavy_ops(50, 3_000, 400);
        let trace = s3tap_replay::adapt::from_records(&ops);

        let findings = crate::checks::caching::advise_caching(&ops, 0);
        assert!(
            findings.iter().any(|f| f.finding_id == "advisor-cache-unjudged"),
            "{findings:#?}"
        );
        assert!(
            !findings.iter().any(|f| f.finding_id == "advisor-cache-go"),
            "{findings:#?}"
        );

        // Both modes: chunk is the `analyze` default, object is `--object`.
        for opts in [obj_opts(), AnalyzeOpts { max_events: 0, ..AnalyzeOpts::default() }] {
            let a = analyze_trace(&trace, &opts);
            assert!(a.ranged_unjudged, "[{}] the gate must fire", a.mode);
            assert_eq!(a.verdict, Verdict::Unjudged, "[{}] {}", a.mode, a.headline);
            assert_eq!(a.recommended_cap, None, "[{}] nothing to size", a.mode);
            assert!(!a.cache_go, "[{}] no go decision above the gate", a.mode);
            assert_eq!((a.ranged_reads, a.body_reads), (400, 3_400), "[{}]", a.mode);
            assert!(a.headline.contains("400 of 3400 body reads were ranged"), "{}", a.headline);

            let out = render(&a, false);
            assert!(out.contains("CAN'T JUDGE (RANGED-HEAVY)"), "{out}");
            assert!(!out.contains("CACHE IT"), "{out}");
            assert!(!out.contains("Recommended size"), "{out}");
            assert!(
                out.contains("retention and prefetching cannot be judged for this workload"),
                "{out}"
            );
            // Every figure below the disclaimer was measured over the whole-object
            // REMAINDER only, which is not this workload: none of it may render, however
            // confident it looks in isolation. On this exact fixture the remainder DOES
            // have reuse, so a leaked "Best demand policy"/table/prefetch block would look
            // like a real recommendation directly beneath a CAN'T JUDGE banner.
            assert!(!out.contains("Best demand policy"), "{out}");
            assert!(!out.contains("ARC vs LRU"), "{out}");
            assert!(!out.contains("per-policy"), "{out}");
            assert!(!out.contains("Prefetching"), "{out}");
            assert!(!out.contains("Egress-$"), "{out}");

            let j = serde_json::to_value(&a).unwrap();
            assert_eq!(j["verdict"], "unjudged", "{j}");
            assert!(j["recommended_cap"].is_null(), "{j}");
            assert_eq!(j["ranged_unjudged"], true, "{j}");
        }

        // Under the gate the verdict still stands, in both commands.
        let few = crate::fixtures::ranged_heavy_ops(50, 3_000, 100);
        let a = analyze_trace(&s3tap_replay::adapt::from_records(&few), &obj_opts());
        assert!(!a.ranged_unjudged);
        assert_eq!(a.verdict, Verdict::Go, "{}", a.headline);
        assert!(crate::checks::caching::advise_caching(&few, 0)
            .iter()
            .any(|f| f.finding_id == "advisor-cache-go"));
    }

    #[test]
    fn chunk_mode_models_write_invalidation_like_object_mode_and_advise() {
        // A read-after-write workload on ONE key: 2500 pairs of {PutObject k,
        // GetObject k}. Every GET follows an invalidating PUT, so the true saving is
        // zero. `advise` (object mode) said `advisor-cache-nogo`, "even an ideal-sized
        // LRU saves only 0% of origin requests" — correct. `analyze` with no flags is
        // CHUNK mode, and `to_blocks` dropped every PUT and DELETE, so the modelled
        // cache served bytes the client had overwritten: "CACHE IT, saves +0.999 origin
        // fetches/access", while `analyze --object` on the same file agreed with
        // `advise`. A flag documented as a granularity choice was changing the
        // semantics. Writes now expand into per-chunk invalidations.
        let mk = |s3_op: &str, ts: u64, len: Option<u64>| s3tap_replay::adapt::OpRecord {
            verb: None,
            s3_op: Some(s3_op.into()),
            bucket: Some("b".into()),
            key_hash: Some("k".into()),
            ts_ns: Some(ts.to_string()),
            http_status: Some(200),
            content_length: len,
        };
        let mut ops = Vec::new();
        for i in 0..2_500u64 {
            ops.push(mk("PutObject", i * 2, None));
            ops.push(mk("GetObject", i * 2 + 1, Some(1 << 20)));
        }
        let trace = s3tap_replay::adapt::from_records(&ops);
        assert_eq!(trace.iter().filter(|e| e.op == Op::Get).count(), 2_500);
        assert_eq!(trace.iter().filter(|e| e.op == Op::Put).count(), 2_500);

        let nogo = crate::checks::caching::advise_caching(&ops, 0);
        assert!(nogo.iter().any(|f| f.finding_id == "advisor-cache-nogo"), "{nogo:#?}");

        // chunk (the default) and object must now give the SAME answer.
        for opts in [AnalyzeOpts { max_events: 0, ..AnalyzeOpts::default() }, obj_opts()] {
            let a = analyze_trace(&trace, &opts);
            assert_eq!(a.verdict, Verdict::NoGo, "[{}] {}", a.mode, a.headline);
            assert!(a.lru_max < 1e-9, "[{}] lru_max {}", a.mode, a.lru_max);
            assert!(a.opt_max < 1e-9, "[{}] not even Belady: {}", a.mode, a.opt_max);
            assert_eq!(a.recommended_cap, None, "[{}]", a.mode);
            assert!(!render(&a, false).contains("CACHE IT"), "{}", render(&a, false));
        }
    }

    #[test]
    fn chunk_mode_invalidates_every_chunk_of_a_multi_chunk_object() {
        // The write's own extent is not the object's: an s3tap `content_length` is a
        // RESPONSE body length, so a PUT arrives sizeless. Invalidating only the extent
        // it declares would clear chunk #0 and leave #1..#2 of a 20 MiB object resident
        // and stale, which is the unsafe direction.
        let get = |ts: u64| NormEvent {
            ts_ns: ts, op: Op::Get, object_id: "k".into(), range: None,
            size: Some(20 * 1024 * 1024), version: None, status: Some(200),
        };
        let mut t = Vec::new();
        for i in 0..2_000u64 {
            t.push(NormEvent { ts_ns: i * 2, op: Op::Put, size: None, ..get(i * 2) });
            t.push(get(i * 2 + 1));
        }
        let a = analyze_trace(&t, &AnalyzeOpts { max_events: 0, ..AnalyzeOpts::default() });
        assert_eq!(a.accesses, 2_000 * 3, "20 MiB at 8 MiB blocks = 3 chunks per read");
        assert!(a.lru_max < 1e-9, "every chunk is overwritten before it is re-read: {}", a.lru_max);
        assert_ne!(a.verdict, Verdict::Go, "{}", a.headline);
    }

    #[test]
    fn arc_never_below_lru_and_opt_is_the_ceiling() {
        let mut t = Vec::new();
        for pass in 0..100u64 {
            for o in 0..80u64 {
                t.push(get(pass * 1000 + o, &format!("o{o}")));
            }
        }
        let a = analyze_trace(&t, &obj_opts());
        // Demand invariant: OPT >= every shippable cache at the knee.
        let at = |p: &str| a.rows.iter().find(|r| r.policy == p).map(|r| r.net_savings).unwrap();
        assert!(at("opt") >= at("null") - 1e-9);
        assert!(at("opt") >= at("arc") - 1e-9);
        assert!(a.arc_delta >= -1e-9, "ARC should not trail LRU here: {}", a.arc_delta);
    }
}
