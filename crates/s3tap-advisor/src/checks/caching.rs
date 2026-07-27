//! Task 6: the caching & capacity advisory — the bridge to the offline replay
//! study. Reads whole-object GETs; when the capture carries `Content-Length` for
//! most GETs (`SIZE_COVERAGE_FLOOR`) it sizes the cache in **bytes** and reports
//! a second savings axis (egress bytes, i.e. the $ bill) — otherwise it falls
//! back to object-count sizing with the historical caveat. Within-object
//! (ranged/streaming) structure is still invisible until Range capture.
//!
//! Axes, rows selected by `row.predictor`/field (never by position):
//!   lru_max    = max over caps of null.net_savings          (request savings)
//!   structure  = max over caps of (max(markov, markov2).hit_rate - null.hit_rate)
//!                at the SAME cap
//!   egress_max = max over byte caps of byte_hit_rate         (egress-$ savings)
//! Behavior matrix (gets = Op::Get events in the adapted trace):
//!   gets < 200            -> nothing (below the gate)
//!   ranged_frac > 0.05    -> advisor-cache-unjudged (sub-object; not modellable)
//!   200..1999, both low   -> advisor-cache-unjudged (too short to rule out)
//!   >= 2000, low LRU + no hideable latency -> advisor-cache-nogo
//! > lru_max >= 0.10       -> advisor-cache-go (+ size; byte or object)
//! >   + byte mode & egress_max < 0.10 -> advisor-cache-requests-not-dollars
//! > low LRU, structure, overlay hides the fetch -> advisor-cache-go-latency
//! > structure >= 0.10     -> advisor-cache-policy (cross-cutting, any branch)

use s3tap_doctor::Record;
use s3tap_replay::adapt::{from_records, record_op_kind, OpRecord};
use s3tap_replay::bytes::{byte_cap_ladder, sweep_bytes};
use s3tap_replay::driver::{sweep_demand, Row};
use s3tap_replay::hybrid::run_self_tuned;
use s3tap_replay::trace::{NormEvent, Op};
use s3tap_schema::{
    Domain, Finding, FindingScope, MetricValue, Sample, SampleKind, Severity, TimeWindow, Unit,
};

use crate::fields::{advisory, Src};

const MAX_EVENTS: usize = 500_000;
const MIN_GETS: usize = 200;
const NOGO_MIN_GETS: usize = 2000;
// Gates shared with the deep `analyze` command (crate::analyze) so both speak
// the same decision matrix — the study's floors live here, once.
pub(crate) const GO_FLOOR: f64 = 0.10;
pub(crate) const STRUCTURE_FLOOR: f64 = 0.10;
/// The self-tuning overlay must hide at least this fraction of a fetch before we call
/// prefetching a latency win — structure alone (a predictable sequence with too little
/// lead to cover the modelled fetch) is NOT enough. Shared with `analyze` so the
/// go-latency verdict is gated identically in both commands.
pub(crate) const LAT_FLOOR: f64 = 0.05;
/// The knee is the smallest cap whose savings come within this FRACTION of the
/// ceiling. It used to be an ABSOLUTE 0.02, which is a different claim at every
/// scale: on a ceiling of 0.95 it means "within 2%", on a ceiling of 0.03 it means
/// "anywhere at all", and on a FLAT curve every rung qualifies, so the smallest one
/// was published as a sizing recommendation on a workload with no reuse to size
/// for. A fraction of the ceiling asks the same question at every scale.
///
/// A zero ceiling is still degenerate (every rung is within any fraction of zero),
/// so the tolerance alone is not enough: callers must also refuse to PUBLISH a knee
/// when there is no reuse to size for. `advise` emits its sizing finding only under
/// the go verdict; `analyze` gates the rendered line on `cache_go`.
pub(crate) const KNEE_EPS_FRAC: f64 = 0.05;

/// The value at or above which a rung counts as "at the ceiling" — see
/// [`KNEE_EPS_FRAC`].
pub(crate) fn knee_floor(ceiling: f64) -> f64 {
    ceiling - ceiling.abs() * KNEE_EPS_FRAC
}
pub(crate) const POLICY_FETCH_NS: u64 = 100_000_000; // modelled 100 ms fetch (documented)
pub(crate) const POLICY_MAX_DEPTH: usize = 32;
/// Fraction of GETs that must carry a captured `Content-Length` before we trust
/// byte-capacity sizing. Below this, sizes are too sparse to size a byte cache,
/// so we fall back to object-count sizing with the historical caveat.
pub(crate) const SIZE_COVERAGE_FLOOR: f64 = 0.80;
/// Max fraction of BODY READS that may be ranged-and-unplaceable before the
/// object-level verdict bows out — such a read is sub-object with an extent the
/// capture never saw, so past this share the analysis would describe only the
/// whole-object remainder while reading as a verdict on the whole workload. Gates
/// byte sizing AND, in `advise_caching`, the lru_max headline itself.
///
/// **Read the denominator carefully: it is body reads, not GET records.** A body
/// read is a `Op::Get` or a 206. Every other GET response is absent from the trace
/// entirely (`s3tap_replay::adapt::demand_op` drops it), and the one to keep in mind
/// is `304 Not Modified`: it is a success to `doctor` and `scorecard`, it is exactly
/// what `advisor-refetch` tells clients to aim for, and it is NOT in this
/// denominator. So a conditional-GET client (9000 x 304, 900 x 200, 100 x 206) reads
/// as 10% ranged here and as 1% of its GET records, and the same client crosses this
/// constant without its ranged traffic changing at all.
///
/// That is the honest denominator rather than an oversight: a 304 serves no body, so
/// a cache could not have answered it, and asking "what share of the bytes-serving
/// reads is sub-object" must not count requests that moved no bytes. The cost is
/// that the number is not the one a reader assumes, so `ranged_share` documents it
/// and every unjudged summary that quotes the ratio says "body reads" out loud.
pub(crate) const RANGED_FRAC_MAX: f64 = 0.05;

/// Bridge: doctor records -> replay OpRecords (Connection/TcpSample skipped).
///
/// `partial == true` ops are dropped here, per the crate contract. This is the
/// only place the caching check could honour it: `OpRecord` has no `partial`
/// field, so the flag is not visible downstream. (The JSONL path that `analyze`
/// uses reads the same flag off the wire tag in `s3tap_replay::adapt`.)
///
/// The DEMAND-READ gates — a GET counts only when the origin served a whole body,
/// and a 206 is not an object-level read — deliberately do NOT live here any more.
/// They live in `s3tap_replay::adapt::from_record`, the adapter BOTH ingest paths
/// share, because a bridge-local copy could only ever cover `advise`: `analyze`
/// parses JSONL straight through `parse_trace_line` and had no gate at all, so the
/// same 503 storm produced opposite verdicts from the two commands. The old
/// predicate here also keyed on `s3_op == Some("GetObject")` while the classifier
/// falls back to the raw verb, so a record with `verb:"GET"`, no `s3_op` and a 503
/// passed the bridge and still became `Op::Get`. Filtering after the mapping, once,
/// means the two cannot drift again.
///
/// Writes are forwarded REGARDLESS of status: they are invalidation signals, and
/// over-invalidating only understates the savings (the safe direction), whereas
/// trusting a status we may have misread would let a cache serve stale bytes in
/// the model.
///
/// That argument applies to `partial` too, and used to be applied backwards here: a partial
/// WRITE was dropped, which REMOVES an invalidation and so over-states savings — the unsafe
/// direction, in the one place that had just argued for the safe one. A large PutObject or
/// UploadPart is exactly the op whose head gets truncated, so this was not a corner: on 40
/// objects each written then read 15x, flipping the writes' `partial` flag alone moved the
/// modelled hit ratio 0.933 -> 0.996 and the recommended cache size 16 MiB -> 320 MiB.
/// Partial READS stay out (they cannot stand in for a demand read); partial WRITES stay in.
/// A write, for the invalidation rule above. Matches the same op set `refetch::WRITE_OPS`
/// does, so the two files cannot drift on what counts as one.
fn is_write_op(o: &s3tap_schema::Operation) -> bool {
    o.s3_op.as_deref().is_some_and(|s| super::refetch::WRITE_OPS.contains(&s))
}

pub(crate) fn to_op_records(records: &[Record]) -> Vec<OpRecord> {
    records
        .iter()
        .filter(|r| !matches!(r, Record::Operation(o) if o.partial && !is_write_op(o)))
        .filter_map(|r| match r {
            Record::Operation(o) => Some(OpRecord {
                verb: o.verb.clone(),
                s3_op: o.s3_op.clone(),
                bucket: o.bucket.clone(),
                key_hash: o.key_hash.clone(),
                ts_ns: o.ts_ns.map(|t| t.to_string()),
                http_status: o.http_status,
                content_length: o.content_length, // the object size for byte sizing
            }),
            Record::Connection(_) | Record::TcpSample(_) => None,
        })
        .collect()
}

/// Byte-capacity sizing over the trace: the miss-ratio knee in bytes and the two
/// savings axes. `None` when the trace carries no usable object sizes. Shared
/// with the deep `analyze` command (fields are `pub(crate)`).
pub(crate) struct ByteSizing {
    pub(crate) total_bytes: u64,       // whole-object working set, bytes
    pub(crate) distinct_objects: u64,  // distinct GET objects sized
    pub(crate) knee_cap: u64,          // recommended cache size, bytes
    pub(crate) knee_hit: f64,          // request savings at the knee
    pub(crate) req_max: f64,           // request-savings ceiling (whole-object)
    pub(crate) egress_max: f64,        // egress-byte savings ceiling (the $ axis)
}

/// A GET is whole-object unless the response was a 206 (partial/ranged) — those
/// need chunk-level modelling (deferred), so they are excluded from byte sizing.
pub(crate) fn is_whole_object_get(e: &NormEvent) -> bool {
    e.op == Op::Get && !is_ranged_read(e)
}

/// A 206 response is a RANGED (sub-object) body read. The status is the marker
/// rather than the op, because the two ingest paths classify it differently: the
/// s3tap adapter maps a 206 to `Op::Other` (it carries no `range` and a range-length
/// `size`, so it cannot be modelled at object OR chunk level), while a raw
/// `NormEvent` trace may legitimately carry `Op::Get` with a populated `range`.
/// Byte sizing excludes ALL of them, including the ones that carry an extent: a
/// 206's `size` is the RANGE length, so it cannot stand in for an object size.
pub(crate) fn is_ranged_read(e: &NormEvent) -> bool {
    e.status == Some(206)
}

/// A ranged read whose EXTENT IS UNKNOWN — the only kind the ranged gate is about.
///
/// The gate's whole justification is that a ranged read carries no Range header in
/// an s3tap capture, so neither mode can place it: object mode keys every range of
/// an object on the object, chunk mode has nothing to expand and maps them all onto
/// `#0`. That argument does not apply to a 206 that DID arrive with a real span (a
/// raw `NormEvent` trace, or an IBM COS line), which `to_blocks` expands honestly
/// into exactly the chunks it touched. Keying the gate on the status alone made the
/// report refuse to judge traces it models correctly: an 8 MiB object re-read 500
/// times as 8 x 1 MiB ranged reads, each line carrying its `range`, expands into 8
/// distinct chunk keys with ~0.998 reuse (a genuine CACHE IT) and was published as
/// CAN'T JUDGE (RANGED-HEAVY) with a null recommendation — while the SAME events
/// with `status` omitted got the right verdict, so the flag turned on a field that
/// carried no information about modellability.
pub(crate) fn is_unplaceable_ranged_read(e: &NormEvent) -> bool {
    is_ranged_read(e) && e.range.is_none()
}

/// `(unplaceable_ranged, body_reads, fraction)` — the share of body reads that are
/// ranged AND unplaceable (see [`is_unplaceable_ranged_read`]). The denominator
/// counts an event once whether it arrived as a `Get` or as a ranged `Other`, so the
/// fraction means the same thing on both ingest paths.
///
/// **The denominator is body reads, so it excludes every `304 Not Modified`** — the
/// adapter's demand gate drops a 304 before it can become a trace event, because a
/// 304 carries no body a cache could have served. That is the right denominator for
/// the question this gate asks ("how much of the traffic that MOVES BYTES is
/// sub-object"), but it is not the one a reader assumes: a conditional-GET client
/// following `advisor-refetch`'s own advice (9000 x 304, 900 x 200, 100 x 206) has
/// 1% of its GET RECORDS ranged and 10% of its body reads, so it crosses
/// [`RANGED_FRAC_MAX`] on traffic that never changed. The disclosure text names the
/// denominator for exactly this reason.
pub(crate) fn ranged_share(trace: &[NormEvent]) -> (usize, usize, f64) {
    let ranged = trace.iter().filter(|e| is_unplaceable_ranged_read(e)).count();
    let body = trace.iter().filter(|e| e.op == Op::Get || is_ranged_read(e)).count();
    (ranged, body, if body > 0 { ranged as f64 / body as f64 } else { 0.0 })
}

/// A knee is a claim about the SHAPE of the miss-ratio curve, so the ladder needs
/// enough rungs to have a shape. `byte_cap_ladder` targets five; below three there
/// is no interior point at all and the only cap simulated would be published as
/// "the knee". Byte sizing then bows out entirely and the caller falls back to
/// object-count sizing with its caveat. Only reachable on a working set of a
/// handful of bytes, where byte sizing means nothing anyway.
const MIN_BYTE_RUNGS: usize = 3;

/// The size to credit a single whole-object GET with: its OWN observed size when it has
/// one, else `fallback` (the per-object aggregate, for a genuinely unsized touch). Pure
/// and separated out so the actual rule — an access's own size always wins over any
/// aggregate computed from OTHER accesses of the same key — is unit-tested directly,
/// not only inferred from a cap-ladder aggregate that a wrong implementation could still
/// pass by coincidence (see the fix's history: it used to always return `fallback`).
fn credit_size(own: Option<u64>, fallback: u64) -> u64 {
    own.unwrap_or(fallback)
}

pub(crate) fn byte_sizing(trace: &[NormEvent]) -> Option<ByteSizing> {
    use std::collections::HashMap;
    // Per-object aggregate size — the size from its MOST RECENT (highest `ts_ns`)
    // whole-object read (ignoring unsized events; a single unsized first touch must not
    // poison the object's size). Objects never sized get the median. Used for the
    // WORKING-SET total (`total_bytes` below: "how big is this object NOW, while
    // resident") and as the FALLBACK for a specific access that carries no size of its
    // own. It is deliberately NOT used to override an access that DOES carry its own size
    // — see the `btrace` comment below. Tracking the LATEST size rather than the MAX
    // matters here specifically: an object that shrank (a re-upload with a smaller body)
    // is genuinely smaller now, and reporting its old, larger peak as the current working
    // set is the same "which claim is this" confusion the max-everywhere bug below was,
    // just for the one number this function still aggregates rather than reads per access.
    let mut per_obj: HashMap<&str, Option<(u64, u64)>> = HashMap::new(); // id -> (ts_ns, size)
    for e in trace.iter().filter(|e| is_whole_object_get(e)) {
        let slot = per_obj.entry(e.object_id.as_str()).or_insert(None);
        if let Some(sz) = e.size {
            if slot.is_none_or(|(ts, _)| e.ts_ns >= ts) {
                *slot = Some((e.ts_ns, sz));
            }
        }
    }
    if per_obj.is_empty() {
        return None;
    }
    let mut known: Vec<u64> = per_obj.values().filter_map(|s| s.map(|(_, sz)| sz)).collect();
    if known.is_empty() {
        return None;
    }
    known.sort_unstable();
    let median = known[known.len() / 2].max(1);
    let size_of = |id: &str| per_obj.get(id).and_then(|s| *s).map_or(median, |(_, sz)| sz);

    // Byte trace: each GET keeps its OWN observed size when it has one, falling back to
    // `size_of` (the per-object aggregate) only for a genuinely unsized touch. Using the
    // per-object MAX for every access (as this used to) retroactively resized every EARLIER
    // access to a key once a LATER, bigger one was seen anywhere in the trace: a 1 KiB GET
    // at t=1 followed by a re-upload and a 1 GiB GET of the same key at t=100 credited the
    // t=1 access as if it had also moved 1 GiB, inflating working-set size and egress
    // savings by orders of magnitude for a key that changed size at all. `size_of` still
    // covers the case this aggregation exists for: a genuinely unsized record borrows a
    // consistent size from its object's other sized reads instead of defaulting to 1 byte.
    let btrace: Vec<NormEvent> = trace
        .iter()
        .filter_map(|e| match e.op {
            Op::Get if is_whole_object_get(e) => {
                let sz = credit_size(e.size, size_of(&e.object_id));
                Some(NormEvent { size: Some(sz), ..e.clone() })
            }
            Op::Put | Op::Delete => Some(e.clone()),
            _ => None,
        })
        .collect();

    let total_bytes: u64 = per_obj.keys().fold(0u64, |a, id| a.saturating_add(size_of(id)));
    if total_bytes == 0 {
        return None;
    }
    let caps = byte_cap_ladder(total_bytes);
    if caps.len() < MIN_BYTE_RUNGS {
        return None;
    }
    let brows = sweep_bytes(&btrace, &caps);
    let req_max = brows.iter().map(|r| r.hit_rate).fold(0.0f64, f64::max);
    let egress_max = brows.iter().map(|r| r.byte_hit_rate).fold(0.0f64, f64::max);
    // Knee: smallest byte cap within KNEE_EPS_FRAC of the request-savings ceiling.
    let knee = brows.iter().find(|r| r.hit_rate >= knee_floor(req_max))?;
    Some(ByteSizing {
        total_bytes,
        distinct_objects: per_obj.len() as u64,
        knee_cap: knee.cap,
        knee_hit: knee.hit_rate,
        req_max,
        egress_max,
    })
}

/// Human-readable byte size (binary units). No `Bytes` unit exists in the schema,
/// so byte findings carry the plain number as the metric and this string in prose.
pub(crate) fn human_bytes(b: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let f = b as f64;
    if f >= GIB {
        format!("{:.1} GiB", f / GIB)
    } else if f >= MIB {
        format!("{:.0} MiB", f / MIB)
    } else if f >= KIB {
        format!("{:.0} KiB", f / KIB)
    } else {
        format!("{b} B")
    }
}

/// `pre_dropped` is what `to_op_records` removed BEFORE this ever saw it — the partial reads.
/// Passed in because `excluded` computed here alone was measured against a set those records
/// had already left, so they appeared in neither `judged` nor `excluded`: a capture holding
/// 9600 operation records published a sample summing to 9000.
pub(crate) fn advise_caching(ops: &[OpRecord], pre_dropped: usize) -> Vec<Finding> {
    let sampled = ops.len() > MAX_EVENTS;
    let considered = &ops[..ops.len().min(MAX_EVENTS)];
    let trace: Vec<NormEvent> = from_records(considered);
    // `excluded` = records dropped before the model could use them: the ones `to_op_records`
    // removed, plus those the adapter dropped WITHIN the analyzed window (identity-less/unknown
    // ops, and GETs the origin never served a body for). Truncation is "(sampled)".
    let adapter_dropped = pre_dropped + (considered.len() - trace.len());
    let gets = trace.iter().filter(|e| e.op == Op::Get).count();
    if gets < MIN_GETS {
        return Vec::new();
    }
    let sampled_note = if sampled { " (sampled)" } else { "" };
    // The GET records the capture HELD, before the demand-read gates. Every ratio in
    // this check has `gets` as its denominator, and `gets` counts only the GETs the
    // origin served a whole body for. The gap is the failed GETs, the ranged 206s and
    // every `304 Not Modified` — and a 304 is not an error, it is what
    // `advisor-refetch` tells clients to aim for, so a conditional-GET client can put
    // 90% of its GET records in that gap while `doctor` and `scorecard` count all of
    // them as successes. Naming the denominator is the difference between "an LRU
    // saves 40% of your GETs" and "…of the GETs it could have served".
    let get_records = considered.iter().filter(|r| record_op_kind(r) == Op::Get).count();
    // Only worth spelling out when the two differ; otherwise it is noise.
    let denom = |n: usize| {
        if get_records > n {
            format!("{n} whole-body (200) GETs of {get_records} GET records")
        } else {
            format!("{n} GETs")
        }
    };
    let whole_denom = |n: usize| {
        if get_records > n {
            format!("{n} whole-object (200) GETs of {get_records} GET records")
        } else {
            format!("{n} whole-object GETs")
        }
    };

    let window = TimeWindow {
        ts_start: trace.iter().map(|e| e.ts_ns).min().unwrap_or(0),
        ts_end: trace.iter().map(|e| e.ts_ns).max().unwrap_or(0),
    };
    let sample = Sample { judged: gets, excluded: adapter_dropped, kind: SampleKind::Operation };
    // Each finding documents ITS OWN gate in `threshold` (DoD requirement).
    let mk_finding =
        |id: &str, sev: Severity, title: &str, summary: String, metric: &str, v: f64, threshold: &str| {
            advisory(
                id,
                Src::Ops,
                Domain::Client,
                sev,
                title,
                summary,
                metric,
                Some(MetricValue::Num(v)),
                Unit::Ratio,
                threshold.to_string(),
                FindingScope::default(),
                window,
                sample.clone(),
            )
        };

    // Ranged (206) reads whose extent the capture never saw are sub-object and cannot
    // be placed at object OR chunk level: with no Range header every ranged read of an
    // object lands on the object's single key. The adapter keeps them out of the
    // simulator for that reason, which means `gets` (and therefore every ratio below)
    // describes only the WHOLE-object part of the workload. Past a small share that is
    // no longer a verdict about this workload, so say so instead of judging a subset
    // and presenting it as the whole. Byte sizing bows out on the same gate. A 206 that
    // DOES carry its span is modelled honestly and is not counted here (see
    // `is_unplaceable_ranged_read`).
    let (ranged, body_reads, ranged_frac) = ranged_share(&trace);
    if ranged_frac > RANGED_FRAC_MAX {
        return vec![mk_finding(
            "advisor-cache-unjudged",
            Severity::Unjudged,
            "capture is ranged-heavy: object-level caching can't be judged",
            format!(
                "{ranged} of {body_reads} body reads were ranged (206) with no captured \
                 extent{sampled_note}, so {:.0}% of this workload is sub-object. Ranged reads \
                 carry no Range header in the capture, so an object-level model would count each \
                 range as a whole-object read of the same key and invent reuse that isn't there \
                 (a 1 GiB object streamed as 1000 ranged GETs would read as a 99.9% hit rate on \
                 one key). Judging the remaining {gets} whole-object GETs alone would describe \
                 only part of the workload. Chunk-level capture is deferred. The denominator is \
                 BODY reads: a 304 Not Modified serves no body, so it is not in it.",
                ranged_frac * 100.0
            ),
            "ranged_read_frac",
            ranged_frac,
            "ranged_read_frac > 0.05 of body reads (object-level analysis does not model \
             sub-object reads; 304s serve no body and are not in the denominator)",
        )];
    }

    // Byte-capacity sizing when most whole-object GETs carry a captured size; else
    // object-count. (The ranged gate above already established the workload is
    // whole-object.)
    let whole_gets = trace.iter().filter(|e| is_whole_object_get(e)).count();
    let sized_whole = trace.iter().filter(|e| is_whole_object_get(e) && e.size.is_some()).count();
    let coverage = if whole_gets > 0 { sized_whole as f64 / whole_gets as f64 } else { 0.0 };
    let byte = if coverage >= SIZE_COVERAGE_FLOOR && ranged_frac <= RANGED_FRAC_MAX {
        byte_sizing(&trace)
    } else {
        None
    };

    // Object-count ladder: powers of two, appending `distinct` as the final rung.
    // GETs ONLY. The simulator skips `Head`/`Other` outright and never inserts on
    // `Put`/`Delete` (s3tap-replay::driver), so a key that is only ever HEADed is
    // not a cache key. Counting it inflated the very number printed next to the GET
    // denominator ("over 5000 GETs, 100010 distinct objects" for a trace whose GET
    // working set is 10) and stretched the ladder past anything the sweep can fill,
    // which also made the `knee >= distinct` "needs the full working set" branch
    // unreachable on a HEAD-heavy trace.
    let distinct = {
        let mut s = std::collections::HashSet::new();
        for e in trace.iter().filter(|e| e.op == Op::Get) {
            s.insert(e.object_id.as_str());
        }
        s.len() as u64
    };
    let mut caps: Vec<u64> = Vec::new();
    let mut c = 2u64;
    while c < distinct.max(2) {
        caps.push(c);
        c *= 2;
    }
    caps.push(distinct.max(2));
    caps.dedup();

    let rows = sweep_demand(&trace, &caps);
    let get_row = |pred: &str, cap: u64| -> Option<&Row> {
        rows.iter().find(|r| r.predictor == pred && r.cap == cap)
    };

    let lru_max = caps
        .iter()
        .filter_map(|&cap| get_row("null", cap).map(|r| r.net_savings))
        .fold(0.0f64, f64::max);
    // Per-cap difference (max-vs-max would let the top-rung LRU mask small-cap
    // wins); remember WHERE structure peaks — the policy run uses that cap.
    let (structure, structure_cap) = caps
        .iter()
        .filter_map(|&cap| {
            let null = get_row("null", cap)?.hit_rate;
            let mk = get_row("markov", cap)?.hit_rate;
            let mk2 = get_row("markov2", cap)?.hit_rate;
            Some((mk.max(mk2) - null, cap))
        })
        .fold((0.0f64, caps[0]), |acc, x| if x.0 > acc.0 { x } else { acc });

    // The self-tuning prefetch overlay at the structure-peak cap — computed once (only when
    // structure is present, since the run is the study's expensive step) and shared by the
    // go-latency gate and the cross-cutting policy finding. `hides_latency` mirrors
    // `analyze`'s gate: the overlay must ACTUALLY hide a fetch (eff_latency >= LAT_FLOOR),
    // not merely that the sequence is predictable — otherwise `advise` would claim "cache for
    // latency" on a structure-without-lead trace that `analyze` (correctly) calls NoGo.
    let overlay = (structure >= STRUCTURE_FLOOR)
        .then(|| run_self_tuned(&trace, structure_cap, POLICY_FETCH_NS, POLICY_MAX_DEPTH));
    let hides_latency = overlay.as_ref().is_some_and(|st| st.eff_latency() >= LAT_FLOOR);

    let mut out = Vec::new();
    if lru_max >= GO_FLOOR {
        // Headline: request savings always; egress-$ savings too when byte-sized.
        // Byte mode quotes its OWN whole-object numbers (req_max/distinct/working
        // set), never the count-mode ceiling, so the figures are self-consistent.
        let go_summary = match &byte {
            Some(b) => format!(
                "Cacheable{sampled_note}: an LRU saves up to {:.0}% of origin GET requests and \
                 {:.0}% of egress bytes on this workload ({}, {} distinct \
                 objects, {} working set).",
                b.req_max * 100.0,
                b.egress_max * 100.0,
                whole_denom(whole_gets),
                b.distinct_objects,
                human_bytes(b.total_bytes),
            ),
            None => format!(
                "Cacheable{sampled_note}: an LRU saves up to {:.0}% of origin GETs on this \
                 workload (object-level analysis over {}, {distinct} distinct objects).",
                lru_max * 100.0,
                denom(gets)
            ),
        };
        out.push(mk_finding(
            "advisor-cache-go",
            Severity::Advisory,
            "caching is worth it",
            go_summary,
            "lru_net_savings_max",
            lru_max,
            "lru_net_savings_max >= 0.10",
        ));

        // Sizing: byte knee when sized, else the object-count knee (with caveat).
        match &byte {
            Some(b) => {
                let summary = if b.knee_cap >= b.total_bytes {
                    format!(
                        "Reuse needs ~the full working set ({}); no smaller knee.",
                        human_bytes(b.total_bytes)
                    )
                } else {
                    format!(
                        "~{} of cache captures {:.0}% of the reuse; larger buys little (the knee \
                         of the miss-ratio curve). Whole-object sizing — ranged/streaming reads \
                         need chunk-level capture (deferred).",
                        human_bytes(b.knee_cap),
                        b.knee_hit * 100.0,
                    )
                };
                out.push(advisory(
                    "advisor-cache-size",
                    Src::Ops,
                    Domain::Client,
                    Severity::Advisory,
                    "cache sizing",
                    summary,
                    "knee_cap_bytes",
                    Some(MetricValue::Num(b.knee_cap as f64)),
                    Unit::None, // no Bytes unit in the schema; prose carries the size
                    "smallest byte cap within 5% of the request-savings ceiling".to_string(),
                    FindingScope::default(),
                    window,
                    sample.clone(),
                ));
                // Split verdict: many requests saved, few egress bytes -> the hot
                // set is small; a cache trims request count/latency, not the bill.
                if b.egress_max < GO_FLOOR {
                    out.push(mk_finding(
                        "advisor-cache-requests-not-dollars",
                        Severity::Advisory,
                        "caching saves requests, not egress $",
                        format!(
                            "The cache would cut up to {:.0}% of GET *requests* but only {:.0}% of \
                             egress *bytes* — the reused objects are small, so caching trims \
                             request count and latency, not the transfer bill. Worth it if \
                             request-rate or latency is the pain; not for egress cost.",
                            b.req_max * 100.0,
                            b.egress_max * 100.0,
                        ),
                        "egress_byte_savings_max",
                        b.egress_max,
                        "lru_max >= 0.10 AND egress_byte_savings_max < 0.10",
                    ));
                }
            }
            None => {
                if let Some(&knee) = caps.iter().find(|&&cap| {
                    get_row("null", cap).is_some_and(|r| r.net_savings >= knee_floor(lru_max))
                }) {
                    let pct = get_row("null", knee).map(|r| r.net_savings * 100.0).unwrap_or(0.0);
                    let summary = if knee >= distinct {
                        format!(
                            "Reuse needs ~the full working set ({distinct} objects); no smaller \
                             knee. (Sizing is in OBJECTS — this capture carried too few object \
                             sizes to size in bytes.)"
                        )
                    } else {
                        format!(
                            "~{knee} objects captures {pct:.0}% of the reuse; larger buys little \
                             (the knee of the miss-ratio curve). (Sizing is in OBJECTS — this \
                             capture carried too few object sizes to size in bytes.)"
                        )
                    };
                    out.push(mk_finding(
                        "advisor-cache-size",
                        Severity::Advisory,
                        "cache sizing",
                        summary,
                        "knee_cap_objects",
                        knee as f64,
                        "smallest cap within 5% of lru_max",
                    ));
                }
            }
        }
    } else if hides_latency {
        out.push(mk_finding(
            "advisor-cache-go-latency",
            Severity::Advisory,
            "cache for latency, not cost",
            format!(
                "Reuse is low (LRU saves at most {:.0}%) but the access sequence is predictable \
                 (structure {:+.0}%){sampled_note} and a prefetch overlay hides the modelled \
                 fetch — cache for latency, not cost.",
                lru_max * 100.0,
                structure * 100.0
            ),
            "structure",
            structure,
            "lru_max < 0.10 AND structure >= 0.10 AND overlay hides latency (eff_latency >= 0.05)",
        ));
    } else if gets >= NOGO_MIN_GETS {
        // Structure may be present yet still NoGo: a predictable sequence with too little
        // lead to cover the modelled fetch hides no latency (matches `analyze`'s matrix).
        let (structure_clause, threshold) = if structure >= STRUCTURE_FLOOR {
            (
                format!(
                    "and the sequence is predictable (structure {:+.0}%) but a prefetch overlay \
                     can't hide the modelled fetch (too little lead)",
                    structure * 100.0
                ),
                "lru_max < 0.10, gets >= 2000, structure present but overlay hides no latency",
            )
        } else {
            (
                "and the object sequence shows no predictable structure (reuse is low)".to_string(),
                "lru_max < 0.10, structure < 0.10, gets >= 2000",
            )
        };
        out.push(mk_finding(
            "advisor-cache-nogo",
            Severity::Advisory,
            "not worth caching",
            format!(
                "Not worth caching{sampled_note}: even an ideal-sized LRU saves only {:.0}% of \
                 origin requests, {structure_clause} ({}, {distinct} distinct objects). \
                 Note: within-object (block/streaming) structure is invisible until Range capture.",
                lru_max * 100.0,
                denom(gets)
            ),
            "lru_net_savings_max",
            lru_max,
            threshold,
        ));
    } else {
        // Structure may be present here too (predictable but too little lead to hide a
        // fetch), so don't claim "both axes low" — only reuse is low; the window is just
        // too short to rule caching out either way.
        let (reuse_clause, threshold) = if structure >= STRUCTURE_FLOOR {
            (
                format!(
                    "low reuse and a predictable sequence (structure {:+.0}%) that can't yet hide a \
                     fetch",
                    structure * 100.0
                ),
                "200 <= gets < 2000, low reuse (structure may be present without hideable latency)",
            )
        } else {
            ("low observed reuse".to_string(), "200 <= gets < 2000, both axes low")
        };
        out.push(mk_finding(
            "advisor-cache-unjudged",
            Severity::Unjudged,
            "capture too short to rule caching out",
            format!(
                "Only {} with {reuse_clause} — too short a window to say 'don't \
                 cache' (reuse may simply not have recurred yet). Capture longer and re-run.",
                denom(gets)
            ),
            "gets",
            gets as f64,
            threshold,
        ));
    }

    // Cross-cutting policy verdict: fires whenever structure is present. The
    // run happens at the cap where STRUCTURE peaked (the LRU knee can be a
    // degenerate cap-2 on low-reuse workloads and doesn't match the message's
    // "at best cap" claim).
    if let Some(st) = &overlay {
        let policy_cap = structure_cap;
        let lru_at_cap = get_row("null", policy_cap).map(|r| r.net_savings).unwrap_or(0.0);
        // The latency claim must track the SAME `hides_latency` gate the go-latency/nogo
        // verdicts use — otherwise, on a predictable-but-no-lead trace, this cross-cutting
        // finding would assert "can hide fetch latency" while the nogo/unjudged finding it
        // co-fires with says the overlay can't hide the fetch (a self-contradiction).
        let latency_clause = if hides_latency {
            "and can hide fetch latency on the predictable subset"
        } else {
            "but the sequence lacks the lead to hide the modelled fetch here — it stays at the \
             LRU cost floor"
        };
        out.push(mk_finding(
            "advisor-cache-policy",
            Severity::Advisory,
            "cache policy",
            format!(
                "Sequence structure detected (structure {:+.0}% at cap {policy_cap}). A \
                 self-tuning prefetch overlay held net origin cost at the LRU floor here \
                 (net {:+.2} vs {:+.2}) {latency_clause} — \
                 subject to the study's caveats: assumes spare bandwidth and background-priority \
                 prefetch; modelled 100 ms fetch; object-level analysis only (within-object/block \
                 streaming is invisible until Range capture). Recency-dominated otherwise: ship \
                 plain LRU; skip admission/frequency.",
                structure * 100.0,
                st.net_savings(),
                lru_at_cap
            ),
            "self_tuned_net_savings",
            st.net_savings(),
            "structure >= 0.10 (policy runs at the structure-peak cap)",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn high_reuse_trace_recommends_a_cache() {
        let f = advise_caching(&fixtures::zipf_ops(50, 5_000), 0);
        assert!(f.iter().any(|x| x.finding_id == "advisor-cache-go"), "{f:#?}");
        assert!(f.iter().any(|x| x.finding_id == "advisor-cache-size"));
    }

    #[test]
    fn sized_trace_sizes_in_bytes_and_reports_egress() {
        // Uniform 1 MiB objects: request and byte savings track, so cache-go
        // names both axes, sizing is in bytes, and the split does NOT fire.
        let f = advise_caching(&fixtures::sized_zipf_ops(50, 5_000, |_| 1 << 20), 0);
        let go = f.iter().find(|x| x.finding_id == "advisor-cache-go").expect("go");
        assert!(go.summary.contains("egress bytes"), "{}", go.summary);
        let size = f.iter().find(|x| x.finding_id == "advisor-cache-size").expect("size");
        assert!(
            size.summary.contains("MiB") || size.summary.contains("GiB") || size.summary.contains("KiB"),
            "byte sizing should carry a byte unit: {}",
            size.summary
        );
        assert!(!size.summary.contains("OBJECTS"), "byte mode drops the OBJECTS caveat: {}", size.summary);
        assert!(
            !f.iter().any(|x| x.finding_id == "advisor-cache-requests-not-dollars"),
            "uniform sizes: egress savings ~ request savings, no split: {f:#?}"
        );
    }

    #[test]
    fn tiny_hot_huge_cold_flags_requests_not_dollars() {
        // Hot 4 KiB object reused between 256 MiB cold one-shots: many requests
        // saved, ~no egress bytes -> the split verdict fires alongside cache-go.
        let f = advise_caching(&fixtures::hot_small_cold_huge_ops(500, 10), 0);
        assert!(f.iter().any(|x| x.finding_id == "advisor-cache-go"), "{f:#?}");
        let split = f
            .iter()
            .find(|x| x.finding_id == "advisor-cache-requests-not-dollars")
            .expect("split verdict");
        assert!(split.summary.contains("not the transfer bill"), "{}", split.summary);
        // And sizing is byte-based (no OBJECTS caveat).
        let size = f.iter().find(|x| x.finding_id == "advisor-cache-size").expect("size");
        assert!(!size.summary.contains("OBJECTS"), "{}", size.summary);
    }

    #[test]
    fn working_set_size_uses_the_objects_latest_touch_not_its_historical_peak_or_max() {
        // An object that shrank (re-uploaded smaller) is genuinely smaller NOW. The
        // regression: `total_bytes` used to take the MAX ever observed for an object,
        // which is the same "which claim is this" confusion the per-access sizing bug
        // was for `sweep_bytes`'s crediting — just for the one aggregate this function
        // still computes rather than reading straight off each access.
        let ev = |ts: u64, id: &str, size: u64| NormEvent {
            ts_ns: ts,
            op: Op::Get,
            object_id: id.into(),
            range: None,
            size: Some(size),
            version: None,
            status: Some(200),
        };
        let mut trace = vec![
            ev(0, "shrinker", 100_000_000), // first upload: 100 MB
            ev(10, "shrinker", 1_000),      // re-uploaded smaller: 1 KB, and now current
        ];
        // Filler objects purely so the byte-cap ladder clears MIN_BYTE_RUNGS.
        for i in 0..5u64 {
            trace.push(ev(100 + i, &format!("f{i}"), 2_000_000));
        }
        let sizing = byte_sizing(&trace).expect("enough sized objects to size in bytes");
        assert_eq!(
            sizing.total_bytes,
            1_000 + 5 * 2_000_000,
            "working set must reflect the object's CURRENT (latest) size, not its historical peak"
        );
    }

    #[test]
    fn credit_size_always_prefers_an_accesss_own_size_over_the_per_object_fallback() {
        // The rule the whole fix rests on: an access's own observed size always wins.
        // The fallback (the per-object aggregate) is reached ONLY when this specific
        // access carries none — never used to override a size the access DOES have,
        // which is exactly what the bug did (every access rewritten to a per-object max
        // regardless of what it actually reported).
        assert_eq!(credit_size(Some(1_000), 100_000_000), 1_000, "own size wins, however small");
        assert_eq!(credit_size(Some(100_000_000), 1_000), 100_000_000, "own size wins, however large");
        assert_eq!(credit_size(None, 100_000_000), 100_000_000, "no own size -> the fallback applies");
    }

    #[test]
    fn unsized_first_touch_does_not_shrink_the_object() {
        // "big" (100 MiB) first appears unsized. Its size must be imputed from a
        // later sized read, not frozen at 1 byte — so the reported working set is
        // ~400 MiB (100 MiB whale + 300x 1 MiB), not ~300 MiB.
        let f = advise_caching(&fixtures::hot_object_unsized_first_touch_ops(300), 0);
        let go = f.iter().find(|x| x.finding_id == "advisor-cache-go").expect("go");
        assert!(
            go.summary.contains("400 MiB"),
            "working set must include the 100 MiB object at full size: {}",
            go.summary
        );
    }

    #[test]
    fn a_ranged_heavy_capture_is_unjudged_not_a_cache_verdict() {
        // 3000 whole-object GETs + 400 ranged (206) = 12% of the body reads are
        // sub-object. This USED to print "cacheable, an LRU saves N% of origin GETs"
        // off the whole-object subset alone (byte sizing bowed out, but the object-count
        // headline did not), reading as a verdict on the whole workload. A ranged read
        // carries no Range header in the capture, so its extent is unknown and nothing
        // here can model it: the only honest answer is that the question is unjudged.
        let f = advise_caching(&fixtures::ranged_heavy_ops(50, 3_000, 400), 0);
        let u = f
            .iter()
            .find(|x| x.finding_id == "advisor-cache-unjudged")
            .expect("ranged-heavy -> unjudged");
        assert!(matches!(u.severity, Severity::Unjudged));
        assert!(u.summary.contains("400 of 3400 body reads were ranged"), "{}", u.summary);
        assert!(u.summary.contains("12%"), "{}", u.summary);
        // No go/nogo verdict may be published beside it.
        assert!(
            !f.iter().any(|x| x.finding_id == "advisor-cache-go"
                || x.finding_id == "advisor-cache-nogo"
                || x.finding_id == "advisor-cache-requests-not-dollars"),
            "{f:#?}"
        );
    }

    #[test]
    fn a_few_ranged_reads_do_not_block_the_verdict() {
        // Under the 5% gate the whole-object analysis still describes the workload, so
        // the go verdict stands (the ranged reads themselves stay out of the sim).
        let f = advise_caching(&fixtures::ranged_heavy_ops(50, 3_000, 100), 0);
        assert!(f.iter().any(|x| x.finding_id == "advisor-cache-go"), "{f:#?}");
        assert!(!f.iter().any(|x| x.finding_id == "advisor-cache-unjudged"), "{f:#?}");
    }

    #[test]
    fn a_503_retry_storm_is_not_cacheable_demand() {
        // 300 keys, each retried 20 times through a 503 storm (19x503 then 1x200):
        // 6300 records, 300 served bodies, ZERO reuse. `advise` filtered this at its own
        // bridge from round 1; the gate now lives in the shared adapter, so this pins
        // that moving it did not lose it. There must be no cache-go here — the only
        // successful reads are one per key.
        let mut ops = Vec::new();
        let mut i = 0u64;
        for k in 0..300u32 {
            for attempt in 0..21u32 {
                let status = if attempt == 20 { 200 } else { 503 };
                ops.push(fixtures::status_op_record(&format!("k{k}"), i, None, status));
                i += 1;
            }
        }
        assert_eq!(ops.len(), 6300);
        let f = advise_caching(&ops, 0);
        assert!(!f.iter().any(|x| x.finding_id == "advisor-cache-go"), "{f:#?}");
        // 300 served bodies is below the NoGo gate, so the honest answer is "too short
        // to say" — not a confident verdict either way, and emphatically not "cacheable".
        let u = f.iter().find(|x| x.finding_id == "advisor-cache-unjudged").expect("unjudged");
        // The headline names BOTH numbers. "Only 300 GETs" beside a capture the doctor
        // reports as 6300 GET records left the reader to guess which 300, and the same
        // gap swallows 304s, which `advisor-refetch` actively recommends.
        assert!(
            u.summary.contains("Only 300 whole-body (200) GETs of 6300 GET records"),
            "{}",
            u.summary
        );
        // The denominator is the 300 bodies actually served, not the 6300 attempts, and
        // the 6000 failures are disclosed as excluded rather than silently dropped.
        assert_eq!(u.sample.judged, 300);
        assert_eq!(u.sample.excluded, 6000);
    }

    #[test]
    fn one_shot_trace_gets_nogo() {
        let f = advise_caching(&fixtures::unique_ops(5_000), 0);
        assert!(f.iter().any(|x| x.finding_id == "advisor-cache-nogo"), "{f:#?}");
    }

    #[test]
    fn short_low_reuse_capture_is_unjudged_not_nogo() {
        let f = advise_caching(&fixtures::unique_ops(500), 0);
        assert!(
            f.iter().any(|x| x.finding_id == "advisor-cache-unjudged"
                && matches!(x.severity, Severity::Unjudged)),
            "{f:#?}"
        );
    }

    #[test]
    fn cyclic_trace_fires_go_and_policy() {
        // 300-object cycle x 40 passes: markov structure at small caps AND full
        // reuse at the top rung -> cache-go co-firing with cache-policy (the
        // run_self_tuned path, at the structure-peak cap).
        let f = advise_caching(&fixtures::cyclic_ops(300, 40), 0);
        assert!(f.iter().any(|x| x.finding_id == "advisor-cache-go"), "{f:#?}");
        let policy = f.iter().find(|x| x.finding_id == "advisor-cache-policy");
        assert!(policy.is_some(), "{f:#?}");
        assert!(policy.unwrap().summary.contains("Sequence structure detected"));
    }

    #[test]
    fn below_min_gets_is_silent() {
        assert!(advise_caching(&fixtures::unique_ops(150), 0).is_empty());
    }

    #[test]
    fn distinct_counts_get_keys_only_not_head_keys() {
        // 400 GETs over 4 hot keys, interleaved with 2000 HEADs of unique keys.
        // HEAD is a no-op for every simulator rung, so the reported working set
        // must be the GET one (4), not 2004 — the figure sits directly next to the
        // GET denominator in the summary.
        let mk = |s3_op: &str, key: &str, i: u64| OpRecord {
            verb: None,
            s3_op: Some(s3_op.into()),
            bucket: Some("b".into()),
            key_hash: Some(key.into()),
            ts_ns: Some((i * 1_000_000).to_string()),
            http_status: Some(200),
            content_length: None,
        };
        let mut ops = Vec::new();
        for i in 0..2000u64 {
            ops.push(mk("HeadObject", &format!("h{i}"), i * 2));
            if i % 5 == 0 {
                ops.push(mk("GetObject", &format!("g{}", i % 4), i * 2 + 1));
            }
        }
        let f = advise_caching(&ops, 0);
        let go = f.iter().find(|x| x.finding_id == "advisor-cache-go").expect("go");
        assert!(go.summary.contains("400 GETs, 4 distinct objects"), "{}", go.summary);
    }

    #[test]
    fn bridge_maps_operations_and_skips_others() {
        let recs = vec![
            fixtures::op(1, 1, 0, 5, 1_000, "GetObject", "k", 200, Some(10)),
            fixtures::conn(1, 1, 0, Some(500), None, false, false),
        ];
        let ops = to_op_records(&recs);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].s3_op.as_deref(), Some("GetObject"));
        assert_eq!(ops[0].ts_ns.as_deref(), Some("5"));
    }
}
