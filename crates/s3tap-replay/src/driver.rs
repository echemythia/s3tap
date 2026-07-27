use crate::metrics::Report;
use crate::predict::Predictor;
use crate::sim::{Access, Sim};
use crate::trace::{NormEvent, Op};

/// One output row of a sweep: a predictor's metrics at one capacity. A named
/// struct (rather than a tuple of five bare `f64`s) so field order can't silently
/// transpose `net_savings` with `pf_latency`, etc.
#[derive(Debug, Clone)]
pub struct Row {
    pub predictor: String,
    pub cap: u64,
    /// Fraction of accesses served from cache. In CHUNK mode this is also the
    /// "no origin latency" fraction (uniform chunks -> each hit ≈ one avoided RTT).
    pub hit_rate: f64,
    /// Of prefetched objects, the fraction later used (wasted-bandwidth proxy).
    pub pf_precision: f64,
    /// Prefetches issued per access — the speculative fetch (bandwidth) cost.
    pub pf_per_access: f64,
    /// Reuse benefit minus prefetch cost: net origin fetches saved per access vs
    /// no-cache. Positive = cuts origin traffic; negative = speculation costs more.
    pub net_savings: f64,
    /// Fraction of accesses whose latency was hidden specifically by prefetching.
    pub pf_latency: f64,
}

impl Row {
    /// Build a row from a completed `Report` (a prefetching predictor's result).
    fn from_report(predictor: &str, cap: u64, r: &Report) -> Self {
        Row {
            predictor: predictor.to_string(),
            cap,
            hit_rate: r.hit_rate(),
            pf_precision: r.prefetch_precision(),
            pf_per_access: r.prefetch_cost(),
            net_savings: r.net_savings(),
            pf_latency: r.prefetch_latency_saved(),
        }
    }

    /// Build a demand-only row (opt / admission / arc / s3fifo): no prefetch, so net savings ==
    /// the hit-rate and the prefetch columns are all zero.
    pub(crate) fn demand(predictor: &str, cap: u64, hit_rate: f64) -> Self {
        Row {
            predictor: predictor.to_string(),
            cap,
            hit_rate,
            pf_precision: 0.0,
            pf_per_access: 0.0,
            net_savings: hit_rate,
            pf_latency: 0.0,
        }
    }
}

/// Replay `trace` through `predictor` against a cache of `cap` units. Ordering
/// is strict: query the cache, THEN observe, THEN predict+prefetch — so no
/// predictor can ever see the future.
///
/// Op handling: only GET populates/serves the byte cache AND trains the
/// predictor. HEAD holds no body and is ignored entirely — feeding it to the
/// predictor would double-train on a HEAD-then-GET of the same key (inflated
/// frequency counts, a spurious `a->a` Markov self-transition), and the
/// following GET already carries the signal. PUT/DELETE invalidate the object
/// and are not fed to the predictor (mutations aren't part of the read
/// sequence). Everything else is ignored.
pub fn run<P: Predictor>(trace: &[NormEvent], predictor: &mut P, cap: u64) -> Report {
    let mut sim = Sim::new(cap);
    let mut rep = Report::default();

    for ev in trace {
        match ev.op {
            Op::Put | Op::Delete => {
                sim.invalidate(&ev.object_id);
                continue;
            }
            // HEAD carries no body and is NOT fed to the predictor (see above);
            // Other is ignored. Both are pure no-ops for the cache and model.
            Op::Head | Op::Other => continue,
            Op::Get => {}
        }

        // Phase-0 count-capacity: force unit size so demand fills match the
        // prefetch/admission/belady rungs (all size 1). Using `ev.size` here would
        // mix bytes into a count-sized cap for a NormEvent trace that carries real
        // sizes (a documented replay input), silently corrupting the hit-rate.
        let size = 1u64;
        rep.accesses += 1;
        match sim.access(&ev.object_id, size) {
            Access::Hit { prefetch_first_use } => {
                rep.hits += 1;
                if prefetch_first_use {
                    rep.prefetch_used += 1;
                }
            }
            Access::Miss => sim.insert(&ev.object_id, size, false),
        }

        predictor.observe(ev);
        for pid in predictor.predict(ev) {
            if !sim.contains(&pid) {
                rep.prefetch_issued += 1;
                sim.insert(&pid, 1, true); // predicted size unknown -> 1 unit
            }
        }
    }
    rep
}

/// Max prefetch breadth. A real prefetcher never issues thousands of speculative
/// fetches per access, and capping k here makes `predict()` cost independent of
/// cache capacity (an unbounded k made it O(cap) per GET — the sweep hung on
/// real high-distinct traces).
const K_MAX: usize = 64;

/// Prefetch breadth for a given capacity: scales gently but is bounded. Stays
/// strictly below cap for every cap >= 2 (the CLI ladder starts at 2), so the
/// prefetcher never evicts the just-accessed object.
fn k_for_cap(cap: u64) -> usize {
    ((cap / 4).max(1)).min(K_MAX as u64) as usize
}

/// Run every predictor across a set of capacities. Returns rows of
/// (label, capacity, hit_rate, prefetch_precision).
///
/// The capacity-INDEPENDENT rungs (null/frequency/markov/markov2/cooc) each run in
/// a SINGLE pass across ALL capacities: `predict(ev)` depends only on the trained
/// model and the current object, not on any cache, so we `observe`/`predict` once
/// per event and apply the ranked top-K_MAX list to every capacity (sliced to k).
/// The capacity-DEPENDENT rungs — `adaptive` (shadow-cache veto), `opt` (Belady),
/// and `lru+adm` (admission vs the LRU victim) — genuinely differ per cache size,
/// so each runs `len(caps)` passes. Total ≈ 5 shared passes + 3·len(caps).
pub fn sweep(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    sweep_impl(trace, caps, false)
}

/// Demand + object-level structure rungs (null, markov, markov2): one pass each
/// across all caps — the advisor's cheap path (no per-capacity rungs: no
/// adaptive/opt/admission). NOTE: `sequential` is NOT here — it parses
/// `"base#N"` block ids and is a documented no-op on object-mode traces, so it
/// would only fake a structure signal.
pub fn sweep_demand(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    use crate::predict::{MarkovPredictor, NullPredictor};
    let mut rows = Vec::new();
    rows.extend(eval_all_caps("null", trace, caps, NullPredictor));
    rows.extend(eval_all_caps("markov", trace, caps, MarkovPredictor::new(K_MAX)));
    rows.extend(eval_all_caps("markov2", trace, caps, MarkovPredictor::with_order(K_MAX, 2)));
    rows
}

/// Chunk-level sweep. Expects a BLOCK trace (ids like `"obj#N"`, from
/// `ibm::to_blocks`) and runs the SAME full predictor ladder as `sweep` plus the
/// model-free Sequential read-ahead rung, which directly targets within-object
/// streaming. This is the primary path (the CLI defaults to chunk mode).
pub fn sweep_blocks(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    sweep_impl(trace, caps, true)
}

/// RETENTION-ONLY sweep: the cheap demand policies (null=LRU floor, opt=Belady ceiling, lru+adm,
/// arc, s3fifo) with NO prefetch predictors. The prefetch rungs (markov/cooc/adaptive) build
/// per-object models that are O(distinct)-expensive on real high-cardinality traces; the report
/// already has their numbers, so this path adds only the retention comparison (incl. the new arc
/// and s3fifo) at a fraction of the cost. Rows are grouped cap-asc, then a fixed predictor order.
#[must_use]
pub fn sweep_retention(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    use crate::predict::NullPredictor;
    let mut rows = Vec::new();
    rows.extend(eval_all_caps("null", trace, caps, NullPredictor));
    rows.extend(belady_hit_rates(trace, caps)); // opt (ceiling)
    rows.extend(eval_admission_caps(trace, caps)); // lru+adm
    rows.extend(crate::arc::eval_arc_caps(trace, caps));
    rows.extend(crate::s3fifo::eval_s3fifo_caps(trace, caps));
    let rank = |l: &str| match l {
        "null" => 0,
        "lru+adm" => 1,
        "arc" => 2,
        "s3fifo" => 3,
        _ => 4, // opt (ceiling last)
    };
    rows.sort_by(|a, b| a.cap.cmp(&b.cap).then_with(|| rank(&a.predictor).cmp(&rank(&b.predictor))));
    rows
}

/// Run every predictor across `caps`. `block_mode` adds the Sequential read-ahead
/// rung (only meaningful when ids carry a `#N` chunk suffix).
///
/// The capacity-INDEPENDENT rungs (null/frequency/markov/markov2/cooc/sequential)
/// each run in a SINGLE pass across ALL capacities: `predict(ev)` depends only on
/// the trained model and the current object, not on any cache, so we
/// `observe`/`predict` once per event and apply the ranked top-`K_MAX` list to
/// every capacity (sliced to k). The capacity-DEPENDENT rungs — `adaptive`
/// (shadow-cache veto), `opt` (Belady), and `lru+adm` (admission vs the LRU
/// victim) — genuinely differ per cache size, so each runs `len(caps)` passes.
fn sweep_impl(trace: &[NormEvent], caps: &[u64], block_mode: bool) -> Vec<Row> {
    use crate::predict::{
        AdaptivePredictor, CoOccurrencePredictor, FrequencyPredictor, MarkovPredictor,
        NullPredictor, SequentialPredictor,
    };
    let mut rows = Vec::new();
    rows.extend(eval_all_caps("null", trace, caps, NullPredictor));
    rows.extend(eval_all_caps("frequency", trace, caps, FrequencyPredictor::new(K_MAX)));
    rows.extend(eval_all_caps("markov", trace, caps, MarkovPredictor::new(K_MAX)));
    rows.extend(eval_all_caps("markov2", trace, caps, MarkovPredictor::with_order(K_MAX, 2)));
    rows.extend(eval_all_caps("cooc", trace, caps, CoOccurrencePredictor::new(K_MAX)));
    if block_mode {
        rows.extend(eval_all_caps("sequential", trace, caps, SequentialPredictor::new(K_MAX)));
    }
    // Adaptive is capacity-DEPENDENT: its shadow-cache veto must be judged at the
    // cache size it drives. So (unlike the shared single-pass predictors above) it
    // runs once PER capacity with a cap-matched shadow and cap-matched breadth k.
    for &cap in caps {
        let k = k_for_cap(cap);
        let r = run(trace, &mut AdaptivePredictor::with_ref_cap(k, cap), cap);
        rows.push(Row::from_report("adaptive", cap, &r));
    }
    rows.extend(belady_hit_rates(trace, caps)); // OPT reference ceiling
    rows.extend(eval_admission_caps(trace, caps)); // LRU + TinyLFU admission
    rows.extend(crate::arc::eval_arc_caps(trace, caps)); // ARC: adaptive recency/frequency
    rows.extend(crate::s3fifo::eval_s3fifo_caps(trace, caps)); // S3-FIFO: FIFO + ghost
    // Preserve the by-capacity grouping of the output (cap asc, then a fixed
    // predictor order within each capacity). Demand baselines (null / lru+adm /
    // arc / s3fifo / opt) first, then the prefetch rungs.
    let rank = |l: &str| match l {
        "null" => 0,
        "lru+adm" => 1,
        "arc" => 2,
        "s3fifo" => 3,
        "opt" => 4,
        "frequency" => 5,
        "markov" => 6,
        "markov2" => 7,
        "cooc" => 8,
        "sequential" => 9,
        _ => 10, // adaptive
    };
    rows.sort_by(|a, b| a.cap.cmp(&b.cap).then_with(|| rank(&a.predictor).cmp(&rank(&b.predictor))));
    rows
}

/// One pass over `trace`, evaluating every capacity in `caps` at once for a
/// single predictor. The predictor is built with breadth `K_MAX` and its
/// `predict` returns a ranked (best-first) list; capacity `c` prefetches the
/// first `k_for_cap(c)` of them. Per-event ordering is preserved: every cache is
/// queried BEFORE the (shared) observe/predict, so no future-leak.
fn eval_all_caps<P: Predictor>(
    label: &str,
    trace: &[NormEvent],
    caps: &[u64],
    mut predictor: P,
) -> Vec<Row> {
    let mut sims: Vec<Sim> = caps.iter().map(|&c| Sim::new(c)).collect();
    let mut reps: Vec<Report> = vec![Report::default(); caps.len()];
    let ks: Vec<usize> = caps.iter().map(|&c| k_for_cap(c)).collect();

    for ev in trace {
        match ev.op {
            Op::Put | Op::Delete => {
                for s in &mut sims {
                    s.invalidate(&ev.object_id);
                }
                continue;
            }
            Op::Head | Op::Other => continue,
            Op::Get => {}
        }

        // Phase-0 count-capacity: force unit size so demand fills match the
        // prefetch/admission/belady rungs (all size 1). Using `ev.size` here would
        // mix bytes into a count-sized cap for a NormEvent trace that carries real
        // sizes (a documented replay input), silently corrupting the hit-rate.
        let size = 1u64;
        // Query + demand-fill each capacity's cache (the only per-cap work besides
        // the cheap prefetch application below).
        for (i, s) in sims.iter_mut().enumerate() {
            reps[i].accesses += 1;
            match s.access(&ev.object_id, size) {
                Access::Hit { prefetch_first_use } => {
                    reps[i].hits += 1;
                    if prefetch_first_use {
                        reps[i].prefetch_used += 1;
                    }
                }
                Access::Miss => s.insert(&ev.object_id, size, false),
            }
        }

        // Train + predict ONCE (capacity-independent), then prefetch per cap.
        predictor.observe(ev);
        let ranked = predictor.predict(ev); // ranked best-first, up to K_MAX
        for (i, s) in sims.iter_mut().enumerate() {
            for pid in ranked.iter().take(ks[i]) {
                if !s.contains(pid) {
                    reps[i].prefetch_issued += 1;
                    s.insert(pid, 1, true);
                }
            }
        }
    }

    caps.iter()
        .enumerate()
        .map(|(i, &cap)| Row::from_report(label, cap, &reps[i]))
        .collect()
}

/// OPT / Belady reference: the optimal DEMAND cache — on a miss with a full
/// cache, evict the resident whose NEXT use is farthest in the future. Not a
/// predictor (it needs the future), but as a reference ceiling it gives the max
/// hit-rate any no-prefetch cache could reach at each capacity. Read it two ways:
/// the null(LRU)→opt gap is how much better smarter *eviction* could do; a
/// prefetcher that *exceeds* opt is turning compulsory misses into hits by
/// fetching before first use — which is prefetching's whole point. Returns the
/// predictors' 5-tuple shape (precision and pf/access are 0 — OPT prefetches
/// nothing).
pub fn belady_hit_rates(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    use std::collections::{BTreeSet, HashMap, HashSet};
    // Cacheable-op stream (GET serves; PUT/DELETE invalidate; HEAD/Other skipped).
    let mut objs: Vec<&str> = Vec::new();
    let mut is_get: Vec<bool> = Vec::new();
    for ev in trace {
        match ev.op {
            Op::Get => { objs.push(&ev.object_id); is_get.push(true); }
            Op::Put | Op::Delete => { objs.push(&ev.object_id); is_get.push(false); }
            _ => {}
        }
    }
    let n = objs.len();
    // next_use[i] = index of the next GET to the same object after i (MAX = never).
    let mut next_use = vec![usize::MAX; n];
    let mut last: HashMap<&str, usize> = HashMap::new();
    for i in (0..n).rev() {
        if is_get[i] {
            next_use[i] = *last.get(objs[i]).unwrap_or(&usize::MAX);
            last.insert(objs[i], i);
        } else {
            // A PUT/DELETE invalidates the cached copy, so a GET before this write
            // cannot reuse it — break the reuse chain here. (Without this, OPT
            // "keeps" an object across a write it can't actually reuse, evicting a
            // live object instead and biasing the ceiling LOW on write traces.)
            last.remove(objs[i]);
        }
    }

    let mut rows = Vec::new();
    for &capu in caps {
        let cap = capu as usize;
        let mut resident: HashSet<&str> = HashSet::new();
        let mut order: BTreeSet<(usize, &str)> = BTreeSet::new(); // (next_use, obj); evict max
        let mut key: HashMap<&str, usize> = HashMap::new();
        let (mut accesses, mut hits) = (0u64, 0u64);
        for i in 0..n {
            let o = objs[i];
            if !is_get[i] {
                if resident.remove(o) {
                    if let Some(ku) = key.remove(o) { order.remove(&(ku, o)); }
                }
                continue;
            }
            accesses += 1;
            let nu = next_use[i];
            if resident.contains(o) {
                hits += 1;
                if let Some(ku) = key.insert(o, nu) { order.remove(&(ku, o)); }
                order.insert((nu, o));
            } else {
                // Demand-fetch, then evict the farthest-future entry (which may be
                // the one just inserted) if we're over capacity — correct Belady.
                resident.insert(o);
                key.insert(o, nu);
                order.insert((nu, o));
                if resident.len() > cap {
                    if let Some(&(mku, mo)) = order.iter().next_back() {
                        order.remove(&(mku, mo));
                        key.remove(mo);
                        resident.remove(mo);
                    }
                }
            }
        }
        let hr = if accesses > 0 { hits as f64 / accesses as f64 } else { 0.0 };
        // Demand-only: no prefetch cost, so net savings == the hit-rate (every
        // hit is one origin fetch avoided; nothing speculative to pay for).
        rows.push(Row::demand("opt", capu, hr));
    }
    rows
}

/// LRU + TinyLFU-style ADMISSION control (demand-only, no prefetch). On a miss
/// with a full cache, admit the incoming object only if its estimated frequency
/// beats the LRU eviction victim's — so one-shots bypass and never pollute the
/// cache. This is the lever the prefetch ladder lacks: it attacks the one-shot /
/// low-reuse regime by NOT caching, rather than by fetching ahead. Returns the
/// 6-tuple shape (precision/pf = 0 — it issues no prefetches; net_savings is its
/// hit-rate. Note a BYPASSED miss still fetches from origin — admission only
/// decides whether to STORE the object, not whether to fetch it — so the reuse
/// benefit is hit_rate with no prefetch cost, same form as any demand cache).
pub fn eval_admission_caps(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    use crate::admission::FreqSketch;
    let mut rows = Vec::new();
    for &capu in caps {
        let cap = capu as usize;
        let mut sim = Sim::new(capu);
        // Phase-0 size assumption: like the other rungs, this uses unit sizes
        // (`sim.len() < cap` count-capacity). If real byte sizes ever land, this
        // must switch to `ev.size` + byte-capacity to stay comparable to `null`.
        // Age the frequency sketch relative to cache size (TinyLFU-style: reset
        // when the sample size reaches a multiple of capacity), so it tracks
        // RECENT frequency and adapts to workload shifts — a fixed huge sample_max
        // would never age on sub-500K-access traces, freezing stale hot sets.
        let mut sketch = FreqSketch::new(1 << 16, capu.saturating_mul(16).max(1 << 14));
        let (mut accesses, mut hits) = (0u64, 0u64);
        for ev in trace {
            match ev.op {
                Op::Put | Op::Delete => {
                    sim.invalidate(&ev.object_id);
                    continue;
                }
                Op::Head | Op::Other => continue,
                Op::Get => {}
            }
            accesses += 1;
            sketch.incr(&ev.object_id);
            match sim.access(&ev.object_id, 1) {
                Access::Hit { .. } => hits += 1,
                Access::Miss => {
                    let admit = if sim.len() < cap {
                        true // room to spare -> always admit
                    } else {
                        match sim.lru_victim() {
                            Some(v) => sketch.est(&ev.object_id) > sketch.est(v),
                            None => true,
                        }
                    };
                    if admit {
                        sim.insert(&ev.object_id, 1, false);
                    }
                }
            }
        }
        let hr = if accesses > 0 { hits as f64 / accesses as f64 } else { 0.0 };
        rows.push(Row::demand("lru+adm", capu, hr));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predict::NullPredictor;
    use crate::synth::sequential;

    #[test]
    fn second_pass_of_sequential_hits_when_cache_is_large() {
        // 4 objects, 2 passes; capacity 4 holds the whole set.
        let trace = sequential(4, 2);
        let mut p = NullPredictor;
        let r = run(&trace, &mut p, 4);
        assert_eq!(r.accesses, 8);
        // First pass all miss (cold); second pass all hit.
        assert_eq!(r.hits, 4);
    }

    #[test]
    fn writes_invalidate() {
        use crate::trace::{NormEvent, Op};
        let mk = |op, id: &str| NormEvent {
            ts_ns: 0, op, object_id: id.into(), range: None,
            size: Some(1), version: None, status: Some(200),
        };
        let trace = vec![
            mk(Op::Get, "a"),   // miss, insert
            mk(Op::Get, "a"),   // hit
            mk(Op::Put, "a"),   // invalidate
            mk(Op::Get, "a"),   // miss again
        ];
        let mut p = NullPredictor;
        let r = run(&trace, &mut p, 10);
        assert_eq!(r.accesses, 3); // Put is not a cacheable read
        assert_eq!(r.hits, 1);
    }

    #[test]
    fn head_is_ignored_and_does_not_populate() {
        use crate::trace::{NormEvent, Op};
        let mk = |op, id: &str| NormEvent {
            ts_ns: 0, op, object_id: id.into(), range: None,
            size: Some(1), version: None, status: Some(200),
        };
        // HEAD then GET of the same key: HEAD is ignored (no body, no training),
        // so the GET must MISS (a real cache can't serve a body off a HEAD).
        let trace = vec![mk(Op::Head, "a"), mk(Op::Get, "a")];
        let mut p = NullPredictor;
        let r = run(&trace, &mut p, 10);
        assert_eq!(r.accesses, 1); // only the GET counts as a cache access
        assert_eq!(r.hits, 0);     // GET misses; HEAD did not populate
    }

    #[test]
    fn markov_prefetch_is_counted_and_used() {
        use crate::predict::MarkovPredictor;
        use crate::synth::{cyclic_matrix, markov};
        // A near-cyclic trace lets Markov learn i->i+1 and prefetch ahead, so
        // both prefetch counters must be non-zero and used <= issued.
        let trace = markov(&cyclic_matrix(10, 0.95), 3_000, 1);
        let mut p = MarkovPredictor::new(1);
        let r = run(&trace, &mut p, 4);
        assert!(r.prefetch_issued > 0, "issued={}", r.prefetch_issued);
        assert!(r.prefetch_used > 0, "used={}", r.prefetch_used);
        assert!(r.prefetch_used <= r.prefetch_issued);
    }

    #[test]
    fn sweep_covers_all_predictors_and_caps() {
        let trace = sequential(8, 3);
        let rows = sweep(&trace, &[2, 4, 8]);
        // 10 rows (null/lru+adm/arc/s3fifo/opt/frequency/markov/markov2/cooc/adaptive) x 3 caps
        assert_eq!(rows.len(), 30);
    }

    #[test]
    fn admission_beats_lru_on_oneshot_pollution() {
        use crate::trace::{NormEvent, Op};
        let mk = |id: String| NormEvent {
            ts_ns: 0, op: Op::Get, object_id: id, range: None,
            size: Some(1), version: None, status: Some(200),
        };
        // A 4-object hot set, heavily reused, interleaved 1:1 with unique
        // one-shots. Under plain LRU the one-shots keep evicting the hot set
        // (reuse distance > cap); TinyLFU admission bypasses the one-shots and
        // protects the hot set.
        let mut trace = Vec::new();
        for i in 0..3000u32 {
            trace.push(mk(format!("hot{}", i % 4)));
            trace.push(mk(format!("u{i}"))); // one-shot, never repeats
        }
        let adm = eval_admission_caps(&trace, &[4])[0].hit_rate;
        let lru = run(&trace, &mut NullPredictor, 4).hit_rate();
        assert!(
            adm > lru + 0.1,
            "admission {adm:.3} should beat LRU {lru:.3} on one-shot pollution"
        );
    }

    #[test]
    fn opt_honors_write_invalidation() {
        use crate::trace::{NormEvent, Op};
        let mk = |op, id: &str| NormEvent {
            ts_ns: 0, op, object_id: id.into(), range: None,
            size: Some(1), version: None, status: Some(200),
        };
        // At cap 1: `a`'s cached copy is killed by the PUT, so OPT must keep `b`
        // (reused at index 4) and evict `a` — true optimum = 1 hit (final b).
        // The pre-fix next_use ignored the PUT, made `a` look reusable, kept it,
        // evicted `b`, and reported 0 hits. This locks the write-invalidation fix.
        let trace = vec![
            mk(Op::Get, "a"),
            mk(Op::Get, "b"),
            mk(Op::Put, "a"),
            mk(Op::Get, "a"),
            mk(Op::Get, "b"),
        ];
        let opt = belady_hit_rates(&trace, &[1])[0].hit_rate;
        assert!((opt - 0.25).abs() < 1e-9, "opt={opt} (expected 1/4)");
        let lru = run(&trace, &mut NullPredictor, 1).hit_rate();
        assert!(opt >= lru - 1e-9, "opt {opt} must be >= lru {lru}");
    }

    #[test]
    fn sweep_blocks_sequential_beats_lru_on_streaming() {
        use crate::trace::{NormEvent, Op};
        // Repeated scans of one object's 50 blocks via 4 KB ranged GETs. In block
        // mode this is big#0..big#49 repeated; a sequential read-ahead should hit
        // where a same-size LRU (working set 50 > cap 8) cannot.
        let mut trace = Vec::new();
        for _ in 0..20 {
            for blk in 0..50u64 {
                trace.push(NormEvent {
                    ts_ns: 0, op: Op::Get, object_id: "big".into(),
                    range: Some((blk * 4096, blk * 4096 + 4095)),
                    size: None, version: None, status: Some(200),
                });
            }
        }
        let blocks = crate::ibm::to_blocks(&trace, 4096);
        let rows = sweep_blocks(&blocks, &[8]);
        let get = |l: &str| rows.iter().find(|r| r.predictor == l && r.cap == 8).unwrap().hit_rate;
        assert!(
            get("sequential") > get("null") + 0.2,
            "sequential {} should beat LRU {} on streaming",
            get("sequential"),
            get("null")
        );
    }

    #[test]
    fn sweep_and_admission_paths_honor_invalidation() {
        use crate::trace::{NormEvent, Op};
        let mk = |op, id: &str| NormEvent {
            ts_ns: 0, op, object_id: id.into(), range: None,
            size: Some(1), version: None, status: Some(200),
        };
        // GET a, GET a, PUT a, GET a -> 3 GET accesses, 1 hit (the 2nd); the PUT
        // invalidates so the final GET misses. `eval_all_caps` (the sweep) and
        // `eval_admission_caps` each have their OWN invalidation loop, separate
        // from run()'s (the only one `writes_invalidate` covers) — pin both here.
        let trace = vec![
            mk(Op::Get, "a"),
            mk(Op::Get, "a"),
            mk(Op::Put, "a"),
            mk(Op::Get, "a"),
        ];
        let null_row = sweep(&trace, &[10]).into_iter().find(|r| r.predictor == "null").unwrap().hit_rate;
        assert!((null_row - 1.0 / 3.0).abs() < 1e-9, "sweep null={null_row}");
        let adm = eval_admission_caps(&trace, &[10])[0].hit_rate;
        assert!((adm - 1.0 / 3.0).abs() < 1e-9, "admission={adm}");
    }

    #[test]
    fn opt_upper_bounds_lru() {
        // OPT is the optimal demand cache, so its hit-rate must be >= LRU's at
        // every capacity (and, being demand-only, <= 1.0).
        use crate::synth::zipf;
        let trace = zipf(200, 1.0, 5000, 1);
        let caps = [4u64, 16, 64];
        let rows = sweep(&trace, &caps);
        for &cap in &caps {
            let g = |l: &str| rows.iter().find(|r| r.predictor == l && r.cap == cap).unwrap().hit_rate;
            assert!(g("opt") >= g("null") - 1e-9, "opt {} < lru {} @cap {cap}", g("opt"), g("null"));
            assert!(g("opt") <= 1.0 + 1e-9);
        }
    }

    #[test]
    fn arc_and_s3fifo_are_demand_caches_bounded_by_opt() {
        // ARC and S3-FIFO are demand caches: their hit-rate must sit in [0, opt] at every cap
        // (opt = Belady is the optimal demand ceiling). A capacity overflow or a botched
        // access-count would break this — the cheapest broad correctness net for both policies.
        use crate::synth::zipf;
        let trace = zipf(200, 1.0, 5000, 1);
        let caps = [4u64, 16, 64];
        let rows = sweep(&trace, &caps);
        for &cap in &caps {
            let g = |l: &str| rows.iter().find(|r| r.predictor == l && r.cap == cap).unwrap().hit_rate;
            let opt = g("opt");
            for pol in ["arc", "s3fifo"] {
                let hr = g(pol);
                assert!((0.0..=1.0).contains(&hr), "{pol} hr {hr} out of range @cap {cap}");
                assert!(hr <= opt + 1e-9, "{pol} {hr} > opt {opt} @cap {cap}");
            }
        }
    }

    #[test]
    fn arc_and_s3fifo_bounded_by_opt_with_invalidations() {
        // The zipf trace is GET-only; interleave DELETEs so the arc/s3fifo INVALIDATE path is
        // exercised under the same [0, opt] bound (a capacity overflow on the invalidate path
        // would push hit_rate above the cap-optimal opt).
        use crate::synth::zipf;
        let base = zipf(100, 1.0, 4000, 7);
        let mut trace = Vec::with_capacity(base.len() + base.len() / 5);
        for (i, ev) in base.iter().enumerate() {
            trace.push(ev.clone());
            if i % 5 == 0 {
                trace.push(NormEvent { op: Op::Delete, ..ev.clone() });
            }
        }
        let caps = [4u64, 16, 64];
        let rows = sweep(&trace, &caps);
        for &cap in &caps {
            let g = |l: &str| rows.iter().find(|r| r.predictor == l && r.cap == cap).unwrap().hit_rate;
            let opt = g("opt");
            for pol in ["arc", "s3fifo"] {
                let hr = g(pol);
                assert!((0.0..=1.0).contains(&hr), "{pol} hr {hr} @cap {cap} (invalidate path)");
                assert!(hr <= opt + 1e-9, "{pol} {hr} > opt {opt} @cap {cap} (invalidate path)");
            }
        }
    }

    #[test]
    fn sweep_demand_null_row_matches_sweep() {
        use crate::synth::zipf;
        let trace = zipf(100, 1.0, 3000, 3);
        let caps = [4u64, 16, 64];
        let full = sweep(&trace, &caps);
        let demand = sweep_demand(&trace, &caps);
        for &cap in &caps {
            let a = full.iter().find(|r| r.predictor == "null" && r.cap == cap).unwrap();
            let b = demand.iter().find(|r| r.predictor == "null" && r.cap == cap).unwrap();
            assert!((a.hit_rate - b.hit_rate).abs() < 1e-12);
            assert!((a.net_savings - b.net_savings).abs() < 1e-12);
        }
        // And the demand path carries exactly the three advertised rungs.
        let preds: std::collections::BTreeSet<&str> =
            demand.iter().map(|r| r.predictor.as_str()).collect();
        assert_eq!(preds.into_iter().collect::<Vec<_>>(), ["markov", "markov2", "null"]);
    }

    #[test]
    fn sweep_matches_reference_run_per_cap() {
        // The optimized single-pass sweep must agree with the per-cap reference
        // run(). Null (no prefetch) and Markov (fully-ranked successors, sliced
        // to k = top-k) match EXACTLY; Frequency uses top-K_MAX-then-slice vs
        // top-k maintenance, so it agrees within a small tolerance.
        use crate::predict::{FrequencyPredictor, MarkovPredictor, NullPredictor};
        use crate::synth::{cyclic_matrix, markov};
        let trace = markov(&cyclic_matrix(12, 0.8), 4_000, 7);
        let caps = [2u64, 8, 32];
        let rows = sweep(&trace, &caps);
        let get = |label: &str, cap: u64| {
            rows.iter().find(|r| r.predictor == label && r.cap == cap).unwrap().hit_rate
        };
        for &cap in &caps {
            let k = k_for_cap(cap);
            let null = run(&trace, &mut NullPredictor, cap).hit_rate();
            let mk = run(&trace, &mut MarkovPredictor::new(k), cap).hit_rate();
            let freq = run(&trace, &mut FrequencyPredictor::new(k), cap).hit_rate();
            assert!((get("null", cap) - null).abs() < 1e-12, "null cap {cap}");
            assert!((get("markov", cap) - mk).abs() < 1e-12, "markov cap {cap}");
            assert!((get("frequency", cap) - freq).abs() < 0.03, "frequency cap {cap}");
        }
    }
}
