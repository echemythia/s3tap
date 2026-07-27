use crate::trace::NormEvent;

/// A prefetch policy. `observe` is called for every event in trace order (past
/// only). `predict` returns object ids to prefetch *after* observing the current
/// access. Implementations MUST NOT look at future events.
pub trait Predictor {
    fn observe(&mut self, ev: &NormEvent);
    fn predict(&mut self, ev: &NormEvent) -> Vec<String>;
}

/// Reactive baseline: no prefetching. Measures the pure LRU floor.
#[derive(Default)]
pub struct NullPredictor;

impl Predictor for NullPredictor {
    fn observe(&mut self, _ev: &NormEvent) {}
    fn predict(&mut self, _ev: &NormEvent) -> Vec<String> {
        Vec::new()
    }
}

use crate::sim::{Access, Sim};
use std::collections::{HashMap, HashSet, VecDeque};

/// Keeps the globally hottest `k` objects warm. Tier 2 (popularity).
///
/// The top-k set is maintained INCREMENTALLY in `observe` (O(1) membership via
/// `top_set`, O(k) only on a displacement), so `predict` is O(k) — not a
/// full re-sort of the whole popularity map every access. That full sort was
/// O(distinct·log distinct) per GET and did not terminate on real-sized traces
/// (10^4–10^6 distinct keys). The trade-off: the maintained set is an
/// *approximate* top-k — a newcomer only displaces the current weakest member
/// when it is observed AND strictly exceeds it, so at the margin the set can
/// differ slightly from an exact top-k. For skewed/real popularity the hot set
/// converges correctly, and marginal membership barely moves hit-rate, so this
/// is well within the harness's upper-bound framing.
pub struct FrequencyPredictor {
    k: usize,
    counts: HashMap<String, u64>,
    top: Vec<String>,
    top_set: HashSet<String>,
}

impl FrequencyPredictor {
    pub fn new(k: usize) -> Self {
        FrequencyPredictor {
            k,
            counts: HashMap::new(),
            top: Vec::new(),
            top_set: HashSet::new(),
        }
    }
}

impl Predictor for FrequencyPredictor {
    fn observe(&mut self, ev: &NormEvent) {
        let id = &ev.object_id;
        let c = {
            let e = self.counts.entry(id.clone()).or_insert(0);
            *e += 1;
            *e
        };
        if self.k == 0 || self.top_set.contains(id) {
            return; // already tracked; its count only rose, so it stays in top
        }
        if self.top.len() < self.k {
            self.top.push(id.clone());
            self.top_set.insert(id.clone());
            return;
        }
        // Top is full and id is new: displace the weakest member if id now
        // strictly beats it. min_by_key returns the first minimum -> deterministic.
        let (weak_idx, weak_count) = self
            .top
            .iter()
            .enumerate()
            .map(|(i, t)| (i, self.counts[t]))
            .min_by_key(|&(_, cnt)| cnt)
            .unwrap();
        if c > weak_count {
            let evicted = std::mem::replace(&mut self.top[weak_idx], id.clone());
            self.top_set.remove(&evicted);
            self.top_set.insert(id.clone());
        }
    }

    fn predict(&mut self, ev: &NormEvent) -> Vec<String> {
        // Return the tracked top set RANKED (hottest first), excluding the
        // current object. Sorting <= K_MAX (~64) elements is cheap, and a ranked
        // result lets a caller take a prefix and get the true top-k (the sweep
        // slices this per capacity). Ties broken by id for determinism.
        let mut ranked: Vec<&String> =
            self.top.iter().filter(|t| **t != ev.object_id).collect();
        ranked.sort_by(|a, b| {
            let (ca, cb) = (self.counts[*a], self.counts[*b]);
            cb.cmp(&ca).then_with(|| a.cmp(b))
        });
        ranked.into_iter().cloned().collect()
    }
}

/// Order-N Markov: counts `(last N objects) -> next` transitions and prefetches
/// the top-`k` successors of the current N-object context. Order 1 is classic
/// successor prediction (Tier 3); higher orders capture longer patterns (more
/// context, but sparser statistics). It keys on the last N *observed* objects, so
/// — matching the driver's observe-then-predict order — `predict` reflects the
/// context ending at the just-observed access.
pub struct MarkovPredictor {
    k: usize,
    order: usize,
    history: Vec<String>, // last `order` observed ids, oldest..newest
    trans: HashMap<String, HashMap<String, u64>>,
    ctx_order: VecDeque<String>, // FIFO of context keys, for bounded eviction
    max_contexts: usize,
    max_successors: usize,
}

impl MarkovPredictor {
    pub fn new(k: usize) -> Self {
        Self::with_order(k, 1)
    }

    pub fn with_order(k: usize, order: usize) -> Self {
        MarkovPredictor {
            k,
            order: order.max(1),
            history: Vec::new(),
            trans: HashMap::new(),
            ctx_order: VecDeque::new(),
            // Bounded like CoOccurrencePredictor: the transition map is otherwise
            // O(distinct contexts) — and for order >= 2 a context is a TUPLE of
            // ids, so the key space can exceed the object count and OOM a
            // high-distinct trace. FIFO-evict whole contexts, cap successors.
            max_contexts: 200_000,
            max_successors: 256,
        }
    }

    /// The current context key (the last `order` observed ids joined), or `None`
    /// until enough history has accumulated. Uses a unit-separator (U+001F) which
    /// S3 keys / block ids never contain, so distinct histories can't collide.
    fn context_key(&self) -> Option<String> {
        (self.history.len() == self.order).then(|| self.history.join("\u{1f}"))
    }

    /// Follow the most-likely transition chain `depth` steps forward from `start`,
    /// returning the predicted object at that depth. Used for LEAD-ADAPTIVE
    /// prefetch: to hide a fetch that takes `L` seconds when requests arrive every
    /// `Δ`, you must prefetch ~`L/Δ` steps ahead, not one.
    ///
    /// The gate bounds the JOINT confidence of the whole chain: the product of
    /// each step's top-successor share must stay >= `conf`. (A per-step gate would
    /// let a 32-step chain of 0.5-share steps through with joint probability
    /// ~2^-32 — the waste a deep guess must not incur.) Each step additionally
    /// needs `MIN_SUPPORT` observations of its context: a transition seen exactly
    /// once is 1/1 = 100% by ratio but is a single sample, not evidence.
    /// Returns `None` if the chain leaves the trained model, a step is
    /// under-supported, or the joint confidence falls below the gate.
    /// Order-1 only (single-object contexts); higher orders return `None`.
    pub fn chain_ahead(&self, start: &str, depth: usize, conf: f64) -> Option<String> {
        if self.order != 1 {
            return None;
        }
        const MIN_SUPPORT: u64 = 2;
        let mut cur = start.to_string();
        let mut chain_conf = 1.0f64;
        for _ in 0..depth.max(1) {
            let succ = self.trans.get(&cur)?;
            let total: u64 = succ.values().sum();
            if total < MIN_SUPPORT {
                return None; // single-sample link -> no evidence to chase
            }
            // Same ranking as `predict`: highest count, ties by smallest id.
            let (best, &cnt) = succ
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))?;
            chain_conf *= cnt as f64 / total as f64;
            if chain_conf < conf {
                return None; // JOINT chain confidence below the gate
            }
            cur = best.clone();
        }
        Some(cur)
    }
}

impl Predictor for MarkovPredictor {
    fn observe(&mut self, ev: &NormEvent) {
        // Record: the N objects observed so far -> this object (bounded).
        if let Some(key) = self.context_key() {
            let is_new = !self.trans.contains_key(&key);
            {
                let succ = self.trans.entry(key.clone()).or_default();
                if let Some(c) = succ.get_mut(&ev.object_id) {
                    *c += 1;
                } else if succ.len() < self.max_successors {
                    succ.insert(ev.object_id.clone(), 1);
                } // else: successor map full of distinct nexts -> drop the newcomer
            }
            if is_new {
                self.ctx_order.push_back(key);
                if self.trans.len() > self.max_contexts {
                    if let Some(old) = self.ctx_order.pop_front() {
                        self.trans.remove(&old);
                    }
                }
            }
        }
        self.history.push(ev.object_id.clone());
        if self.history.len() > self.order {
            self.history.remove(0);
        }
    }

    fn predict(&mut self, _ev: &NormEvent) -> Vec<String> {
        let Some(key) = self.context_key() else { return Vec::new() };
        let Some(succ) = self.trans.get(&key) else { return Vec::new() };
        let mut ranked: Vec<(&String, &u64)> = succ.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        ranked.into_iter().take(self.k).map(|(id, _)| id.clone()).collect()
    }
}

/// Sequential read-ahead (ladder Tier 1). On a BLOCK trace, object ids look like
/// `"<base>#<N>"` (block N of object base); on an access to block N this prefetches
/// the next `k` contiguous blocks (`base#N+1 … base#N+k`), nearest first. It's
/// model-free — no warm-up, no state — the classic streaming prefetcher. On a
/// non-block id (no `#<digits>` suffix) it predicts nothing, so it's a harmless
/// no-op on object-level traces.
pub struct SequentialPredictor {
    k: usize,
}

impl SequentialPredictor {
    pub fn new(k: usize) -> Self {
        SequentialPredictor { k }
    }
}

impl Predictor for SequentialPredictor {
    fn observe(&mut self, _ev: &NormEvent) {}

    fn predict(&mut self, ev: &NormEvent) -> Vec<String> {
        if let Some((base, num)) = ev.object_id.rsplit_once('#') {
            if let Ok(n) = num.parse::<u64>() {
                // checked_add guards against a block number near u64::MAX (parsed
                // from trace data, not a bounded internal counter).
                return (1..=self.k as u64)
                    .filter_map(|d| n.checked_add(d).map(|nb| format!("{base}#{nb}")))
                    .collect();
            }
        }
        Vec::new()
    }
}

/// Windowed co-occurrence (association) predictor. Tracks which objects are
/// accessed close together (within a sliding window of `window` accesses) and,
/// on an access to X, prefetches the objects that most often co-occur with X.
/// Captures SET-structured workloads — objects fetched together but not in a
/// fixed order (a manifest pulling many objects, parallel range GETs) — that a
/// sequence model (Markov) sees only as noise.
///
/// The association graph is BOUNDED to avoid OOM on high-distinct traces (the
/// unbounded version is O(distinct^2) worst case — GBs on a 10^6-distinct trace):
/// the outer map is capped at `max_objects` with FIFO eviction, and each object's
/// partner map at `max_partners`. Bounds memory to ~`max_objects * max_partners`
/// entries. Evicting an object only drops its own row; stale references to it as
/// someone else's partner are harmless (it's still a valid object id).
pub struct CoOccurrencePredictor {
    k: usize,
    window: usize,
    max_objects: usize,
    max_partners: usize,
    recent: VecDeque<String>,
    co: HashMap<String, HashMap<String, u64>>,
    order: VecDeque<String>, // FIFO of outer keys, for bounded eviction
}

impl CoOccurrencePredictor {
    pub fn new(k: usize) -> Self {
        CoOccurrencePredictor {
            k,
            window: 32,
            max_objects: 100_000,
            max_partners: 256,
            recent: VecDeque::new(),
            co: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Increment co[a][b], respecting the per-object partner cap and the bounded
    /// outer map (FIFO eviction of whole rows).
    fn bump(&mut self, a: &str, b: &str) {
        let is_new_outer = !self.co.contains_key(a);
        {
            let inner = self.co.entry(a.to_string()).or_default();
            if let Some(c) = inner.get_mut(b) {
                *c += 1;
            } else if inner.len() < self.max_partners {
                inner.insert(b.to_string(), 1);
            } // else: partner map full of distinct partners -> drop the newcomer
        }
        if is_new_outer {
            self.order.push_back(a.to_string());
            if self.co.len() > self.max_objects {
                if let Some(old) = self.order.pop_front() {
                    self.co.remove(&old);
                }
            }
        }
    }
}

impl Predictor for CoOccurrencePredictor {
    fn observe(&mut self, ev: &NormEvent) {
        let cur = ev.object_id.clone();
        // DISTINCT window partners, in a DETERMINISTIC order. (A HashSet's
        // per-process-random iteration order would decide which partners survive
        // the bounded `bump` caps, making cooc's output non-reproducible.)
        let mut partners: Vec<String> =
            self.recent.iter().filter(|o| **o != cur).cloned().collect();
        partners.sort();
        partners.dedup();
        for o in &partners {
            self.bump(&cur, o);
            self.bump(o, &cur);
        }
        self.recent.push_back(cur);
        if self.recent.len() > self.window {
            self.recent.pop_front();
        }
    }

    fn predict(&mut self, ev: &NormEvent) -> Vec<String> {
        let Some(m) = self.co.get(&ev.object_id) else { return Vec::new() };
        let mut ranked: Vec<(&String, &u64)> = m.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        ranked.into_iter().take(self.k).map(|(id, _)| id.clone()).collect()
    }
}

/// One expert in the adaptive pool: a sub-predictor, its last prediction (for
/// scoring), and a running accuracy EWMA.
struct Expert {
    pred: Box<dyn Predictor>,
    last: Vec<String>,
    acc: f64,
}

/// Online meta-predictor — "choose the model while reading the data." Holds a
/// pool of experts (frequency, order-1 and order-2 Markov, co-occurrence), scores
/// each by RECENT prediction accuracy (did its set contain what came next?), and
/// follows the most accurate. Two-part engage gate:
///   1. the best expert's accuracy must clear `floor` (else disengage — the
///      no-reuse / nothing-predictable case), and
///   2. a SHADOW-CACHE veto: two internal ghost LRU caches (one applying the
///      chosen prefetch, one demand-only) must not show prefetch *hurting* by
///      more than `margin`.
///
/// Using the shadow as a VETO (not a "must beat") is deliberate: when the working
/// set fits and prefetch is merely moot, the ghosts tie and we still engage on
/// accuracy; we only disengage when prefetch demonstrably displaces useful cache
/// entries — the high-locality case a stream-accuracy-only policy got wrong.
pub struct AdaptivePredictor {
    experts: Vec<Expert>,
    alpha: f64,
    ghost_on: Sim,  // demand LRU + the chosen prefetch (counterfactual "with")
    ghost_off: Sim, // pure demand LRU (counterfactual "without")
    hit_on: f64,
    hit_off: f64,
    floor: f64,  // min expert accuracy to consider prefetching at all
    margin: f64, // shadow veto: disengage if prefetch trails demand by more than this
}

impl AdaptivePredictor {
    /// Standalone constructor (fixed 256-object shadow) — for tests / direct use.
    pub fn new(k: usize) -> Self {
        Self::with_ref_cap(k, 256)
    }

    /// `ref_cap` sizes the shadow ghost caches. The sweep runs adaptive PER
    /// CAPACITY with `ref_cap = cap`, so the engage/disengage veto is judged at
    /// the very cache size it's applied to — fixing the mis-decision a single
    /// fixed shadow made at the extremes of the capacity sweep.
    pub fn with_ref_cap(k: usize, ref_cap: u64) -> Self {
        let cap = ref_cap.max(1);
        let experts = vec![
            Expert { pred: Box::new(FrequencyPredictor::new(k)), last: Vec::new(), acc: 0.0 },
            Expert { pred: Box::new(MarkovPredictor::new(k)), last: Vec::new(), acc: 0.0 },
            Expert { pred: Box::new(MarkovPredictor::with_order(k, 2)), last: Vec::new(), acc: 0.0 },
            Expert { pred: Box::new(CoOccurrencePredictor::new(k)), last: Vec::new(), acc: 0.0 },
            // Sequential is inert on object ids (no `#N`) but lets adaptive engage
            // on a block/streaming trace instead of seeing it as unpredictable.
            Expert { pred: Box::new(SequentialPredictor::new(k)), last: Vec::new(), acc: 0.0 },
        ];
        AdaptivePredictor {
            experts,
            alpha: 0.02,
            ghost_on: Sim::new(cap),
            ghost_off: Sim::new(cap),
            hit_on: 0.0,
            hit_off: 0.0,
            floor: 0.05,
            margin: 0.02,
        }
    }
}

impl Predictor for AdaptivePredictor {
    fn observe(&mut self, ev: &NormEvent) {
        let alpha = self.alpha;
        let id = &ev.object_id;
        // Score each expert's previous prediction against what actually came
        // next, then update its model.
        for e in &mut self.experts {
            let hit = if e.last.iter().any(|p| p == id) { 1.0 } else { 0.0 };
            e.acc = alpha * hit + (1.0 - alpha) * e.acc;
            e.pred.observe(ev);
        }
        // Shadow caches: demand-access outcome WITH vs WITHOUT prefetch. (The
        // prefetch was applied to ghost_on at the previous predict.)
        let on_hit = matches!(self.ghost_on.access(id, 1), Access::Hit { .. });
        if !on_hit {
            self.ghost_on.insert(id, 1, false);
        }
        self.hit_on = alpha * (on_hit as u8 as f64) + (1.0 - alpha) * self.hit_on;

        let off_hit = matches!(self.ghost_off.access(id, 1), Access::Hit { .. });
        if !off_hit {
            self.ghost_off.insert(id, 1, false);
        }
        self.hit_off = alpha * (off_hit as u8 as f64) + (1.0 - alpha) * self.hit_off;
    }

    fn predict(&mut self, ev: &NormEvent) -> Vec<String> {
        // Refresh each expert's prediction (stored for next-step scoring).
        for e in &mut self.experts {
            e.last = e.pred.predict(ev);
        }
        // Pick the most accurate expert; on a near-tie prefer the SMALLER
        // prediction set — same recall, fewer speculative fetches (better
        // precision / lower pf-per-access). Without this, when every expert
        // saturates recall (cache >= working set) the fixed index-0 (frequency,
        // widest set) won every tie, needlessly inflating pf/access.
        const TIE: f64 = 1e-9;
        let max_acc = self.experts.iter().map(|e| e.acc).fold(f64::NEG_INFINITY, f64::max);
        let best = self
            .experts
            .iter()
            .enumerate()
            .filter(|(_, e)| e.acc >= max_acc - TIE)
            .min_by_key(|(_, e)| e.last.len())
            .map(|(i, _)| i)
            .unwrap_or(0);
        let chosen = self.experts[best].last.clone();
        // ghost_on ALWAYS tries the chosen prefetch (the counterfactual), so the
        // shadow keeps measuring whether prefetching would help even while the
        // real output is disengaged — letting it re-engage when the regime shifts.
        for pid in &chosen {
            if !self.ghost_on.contains(pid) {
                self.ghost_on.insert(pid, 1, true);
            }
        }
        // Engage if (1) the best expert is accurate enough AND (2) the shadow
        // doesn't show prefetch actively hurting vs demand-only.
        let engage = max_acc >= self.floor && self.hit_on >= self.hit_off - self.margin;
        if engage {
            chosen
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{NormEvent, Op};

    fn get(id: &str) -> NormEvent {
        NormEvent { ts_ns: 0, op: Op::Get, object_id: id.into(),
                    range: None, size: Some(1), version: None, status: Some(200) }
    }

    #[test]
    fn null_predictor_never_prefetches() {
        let mut p = NullPredictor;
        p.observe(&get("a"));
        assert!(p.predict(&get("a")).is_empty());
    }

    #[test]
    fn chain_ahead_follows_multi_step_chain() {
        let mut p = MarkovPredictor::new(1);
        for _ in 0..5 {
            p.observe(&get("a"));
            p.observe(&get("b"));
            p.observe(&get("c"));
        }
        // Deterministic a->b->c: depth 1 = next, depth 2 = two ahead.
        assert_eq!(p.chain_ahead("a", 1, 0.5), Some("b".to_string()));
        assert_eq!(p.chain_ahead("a", 2, 0.5), Some("c".to_string()));
        assert_eq!(p.chain_ahead("never-seen", 1, 0.5), None); // leaves the model
    }

    #[test]
    fn chain_ahead_compounds_confidence_across_steps() {
        // a -> {b:5, x:5} and b -> {c:5, y:5}: each step's top share is 0.5.
        // A per-step gate at conf=0.5 would chase 2 steps; the JOINT gate must
        // refuse (0.5 * 0.5 = 0.25 < 0.5). A loose gate (0.2) accepts.
        let mut p = MarkovPredictor::new(1);
        for _ in 0..5 { p.observe(&get("a")); p.observe(&get("b")); p.observe(&get("c")); }
        for _ in 0..5 { p.observe(&get("a")); p.observe(&get("x")); }
        for _ in 0..5 { p.observe(&get("b")); p.observe(&get("y")); }
        assert_eq!(p.chain_ahead("a", 1, 0.5), Some("b".to_string())); // 0.5 >= 0.5
        assert_eq!(p.chain_ahead("a", 2, 0.5), None); // joint 0.25 < 0.5
        assert_eq!(p.chain_ahead("a", 2, 0.2), Some("c".to_string())); // ties -> smallest id
    }

    #[test]
    fn chain_ahead_requires_min_support() {
        // A transition seen exactly ONCE is 1/1 by ratio but a single sample:
        // it must not pass the gate (this was the support-of-1 waste bug).
        let mut p = MarkovPredictor::new(1);
        p.observe(&get("a"));
        p.observe(&get("b")); // a->b, seen once
        assert_eq!(p.chain_ahead("a", 1, 0.99), None);
        // A second observation makes it evidence.
        p.observe(&get("a"));
        p.observe(&get("b"));
        assert_eq!(p.chain_ahead("a", 1, 0.99), Some("b".to_string()));
    }

    #[test]
    fn chain_ahead_cycle_terminates_and_order2_returns_none() {
        let mut p = MarkovPredictor::new(1);
        for _ in 0..6 { p.observe(&get("a")); p.observe(&get("b")); } // a<->b cycle
        let out = p.chain_ahead("a", 10, 0.5); // deep walk over a 2-cycle: bounded
        assert!(out == Some("a".to_string()) || out == Some("b".to_string()));

        let mut p2 = MarkovPredictor::with_order(1, 2);
        for _ in 0..5 { p2.observe(&get("a")); p2.observe(&get("b")); }
        assert_eq!(p2.chain_ahead("a", 1, 0.0), None); // order != 1 unsupported
    }

    #[test]
    fn chain_ahead_tie_breaks_to_smallest_id_deterministically() {
        let mut p = MarkovPredictor::new(1);
        for _ in 0..4 { p.observe(&get("a")); p.observe(&get("b")); }
        for _ in 0..4 { p.observe(&get("a")); p.observe(&get("c")); }
        // Equal counts b/c: the smaller id must win, every time.
        for _ in 0..3 {
            assert_eq!(p.chain_ahead("a", 1, 0.5), Some("b".to_string()));
        }
    }

    #[test]
    fn frequency_prefetches_the_hottest_unseen() {
        let mut p = FrequencyPredictor::new(2);
        for _ in 0..10 { p.observe(&get("hot")); }
        for _ in 0..3 { p.observe(&get("warm")); }
        p.observe(&get("cold"));
        // predicting after touching "cold" should surface hot/warm (top-2),
        // excluding the current object.
        let out = p.predict(&get("cold"));
        assert!(out.contains(&"hot".to_string()));
        assert!(out.contains(&"warm".to_string()));
        assert!(!out.contains(&"cold".to_string()));
        assert!(out.len() <= 2);
    }

    #[test]
    fn frequency_displaces_when_a_newcomer_gets_hotter() {
        // k=1: "a" holds the top slot until "b" strictly overtakes its count.
        let mut p = FrequencyPredictor::new(1);
        for _ in 0..3 { p.observe(&get("a")); } // top = [a] (count 3)
        for _ in 0..5 { p.observe(&get("b")); } // b passes a at count 4 -> top = [b]
        assert_eq!(p.predict(&get("x")), vec!["b".to_string()]);
    }

    #[test]
    fn markov_predicts_the_common_successor() {
        let mut p = MarkovPredictor::new(1);
        // Teach it a->b repeatedly, plus one a->c.
        for _ in 0..5 {
            p.observe(&get("a"));
            p.observe(&get("b"));
        }
        p.observe(&get("a"));
        p.observe(&get("c"));
        // Markov keys on the last observed object, so put it in the "just saw a"
        // state (as the driver does: observe then predict) before predicting.
        p.observe(&get("a"));
        let out = p.predict(&get("a"));
        assert_eq!(out.first(), Some(&"b".to_string()));
    }

    #[test]
    fn adaptive_follows_markov_on_sequence_and_disengages_on_no_reuse() {
        use crate::synth::sequential;
        // Sequential: Markov becomes highly accurate, so adaptive follows it and
        // predicts the (non-empty) successor set.
        let seq = sequential(40, 25);
        let mut p = AdaptivePredictor::new(8);
        for ev in &seq {
            p.observe(ev);
            let _ = p.predict(ev);
        }
        assert!(
            !p.predict(seq.last().unwrap()).is_empty(),
            "should follow Markov on a sequential trace"
        );

        // No-reuse: every object is brand new, so no predictor is ever accurate;
        // adaptive must DISENGAGE (predict nothing).
        let mut q = AdaptivePredictor::new(8);
        for i in 0..5000u32 {
            let ev = get(&format!("u-{i}")); // unique object every access
            q.observe(&ev);
            let _ = q.predict(&ev);
        }
        assert!(
            q.predict(&get("u-999999")).is_empty(),
            "should disengage on a no-reuse stream"
        );
    }

    #[test]
    fn sequential_prefetches_the_next_blocks() {
        let mut p = SequentialPredictor::new(3);
        assert_eq!(
            p.predict(&get("obj#5")),
            vec!["obj#6".to_string(), "obj#7".to_string(), "obj#8".to_string()]
        );
        // A non-block id has nothing to read ahead into.
        assert!(p.predict(&get("plain-object")).is_empty());
    }

    #[test]
    fn cooccurrence_prefetches_co_accessed_objects() {
        let mut p = CoOccurrencePredictor::new(4);
        // "a" and "b" are always accessed together (with some noise between).
        for _ in 0..10 {
            p.observe(&get("a"));
            p.observe(&get("b"));
            p.observe(&get("noise"));
        }
        assert!(
            p.predict(&get("a")).contains(&"b".to_string()),
            "expected b among a's co-occurring objects"
        );
    }

    #[test]
    fn order2_markov_uses_two_object_context() {
        // ASYMMETRIC counts so order-1 and order-2 give DIFFERENT answers:
        //   (x,a) -> b  (5x)  ;  (y,a) -> c  (10x)
        // Order-1 keyed on "a" sees {b:5, c:10} -> predicts c.
        // Order-2 keyed on (x,a) sees {b:5}     -> predicts b.
        // (The old version used equal counts, so the id tie-break returned "b"
        // for BOTH orders — it couldn't actually distinguish them.)
        let feed = |p: &mut MarkovPredictor| {
            for _ in 0..5 {
                p.observe(&get("x"));
                p.observe(&get("a"));
                p.observe(&get("b"));
            }
            for _ in 0..10 {
                p.observe(&get("y"));
                p.observe(&get("a"));
                p.observe(&get("c"));
            }
            // Leave the predictor in the "...x, a" context.
            p.observe(&get("x"));
            p.observe(&get("a"));
        };
        let mut o1 = MarkovPredictor::with_order(2, 1);
        feed(&mut o1);
        assert_eq!(
            o1.predict(&get("a")).first(),
            Some(&"c".to_string()),
            "order-1 follows the more frequent global successor"
        );
        let mut o2 = MarkovPredictor::with_order(2, 2);
        feed(&mut o2);
        assert_eq!(
            o2.predict(&get("a")).first(),
            Some(&"b".to_string()),
            "order-2 uses the (x,a) context"
        );
    }
}
