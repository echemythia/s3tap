//! A better hybrid cache policy, and an honest (lead-time-aware) latency metric.
//!
//! The fleet study showed two things: (1) on origin-request count (`net_savings`)
//! a plain LRU beats every prefetcher, because a *used* prefetch is request-neutral
//! and a *wasted* one is pure loss — so prefetching can only cost, never save; and
//! (2) prefetching's real product is HIDDEN LATENCY, which `net_savings` does not
//! score. So the right objective is Pareto: hide as much latency as possible while
//! keeping `net_savings >= plain LRU`.
//!
//! This module builds toward that with two pieces:
//!
//! * `WLfu` — a Window-TinyLFU eviction policy: a small recency WINDOW (LRU) in
//!   front of a frequency-admitted MAIN region. The window protects just-inserted
//!   and recency-reused objects (the exact failure of standalone admission control,
//!   which rejected reused objects), while the frequency sketch keeps the hot set —
//!   closing the LRU->OPT eviction headroom for free (no prefetch cost).
//!
//! * lead-time latency — every prefetch records its issue timestamp; on first use
//!   we compare the lead `t(use) - t(issue)` against a modelled fetch time `L`, and
//!   credit `min(1, lead/L)` of a hidden fetch. A prefetch that lands just before
//!   its use hides little; one issued well ahead hides all of it. This replaces the
//!   instant-prefetch UPPER BOUND with an achievable estimate.

use std::collections::{BTreeMap, HashMap};

use crate::admission::FreqSketch;
use crate::predict::{MarkovPredictor, Predictor};
use crate::trace::{NormEvent, Op};

struct Entry {
    seq: u64,
    /// True until the first real hit on a prefetched entry (prefetch usefulness).
    pf_unused: bool,
    /// Timestamp (ns) this entry was inserted — used for prefetch lead time.
    issue_ts: u64,
}

/// A count-capacity LRU segment (each entry is one unit — chunk-mode sizing).
struct Seg {
    clock: u64,
    by_id: HashMap<String, Entry>,
    order: BTreeMap<u64, String>, // seq -> id
}

impl Seg {
    fn new() -> Self {
        Seg { clock: 0, by_id: HashMap::new(), order: BTreeMap::new() }
    }
    fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }
    fn len(&self) -> usize {
        self.by_id.len()
    }
    /// Move `id` to MRU, clearing its prefetch flag. Returns `(was_pf_unused,
    /// issue_ts)` if present.
    fn touch(&mut self, id: &str) -> Option<(bool, u64)> {
        let e = self.by_id.get_mut(id)?;
        let was = e.pf_unused;
        let its = e.issue_ts;
        e.pf_unused = false;
        self.order.remove(&e.seq);
        self.clock += 1;
        e.seq = self.clock;
        self.order.insert(self.clock, id.to_string());
        Some((was, its))
    }
    /// Move `id` to MRU WITHOUT consuming its prefetch credit. `insert` on an
    /// already-resident id must use this, not `touch`: only a real `access` may
    /// count as the prefetched entry's first use.
    fn bump(&mut self, id: &str) -> bool {
        let Some(e) = self.by_id.get_mut(id) else { return false };
        self.order.remove(&e.seq);
        self.clock += 1;
        e.seq = self.clock;
        self.order.insert(self.clock, id.to_string());
        true
    }

    fn push(&mut self, id: String, pf_unused: bool, issue_ts: u64) {
        self.clock += 1;
        let seq = self.clock;
        self.order.insert(seq, id.clone());
        self.by_id.insert(id, Entry { seq, pf_unused, issue_ts });
    }
    /// Re-insert an entry moved from another segment (preserves its flags).
    fn push_entry(&mut self, id: String, mut e: Entry) {
        self.clock += 1;
        e.seq = self.clock;
        self.order.insert(self.clock, id.clone());
        self.by_id.insert(id, e);
    }
    fn peek_lru(&self) -> Option<&str> {
        self.order.iter().next().map(|(_, id)| id.as_str())
    }
    fn pop_lru(&mut self) -> Option<(String, Entry)> {
        let (&seq, _) = self.order.iter().next()?;
        let id = self.order.remove(&seq).unwrap();
        let e = self.by_id.remove(&id).unwrap();
        Some((id, e))
    }
    /// Evict the least-recently-used entry that is still an UNUSED prefetch
    /// (skipping demand entries and already-used prefetches). Bounded scan from
    /// the LRU end; trims speculation over budget without touching demand.
    fn pop_lru_pf_unused(&mut self) -> Option<(String, Entry)> {
        let id = self
            .order
            .values()
            .find(|id| self.by_id.get(*id).is_some_and(|e| e.pf_unused))
            .cloned()?;
        let e = self.by_id.remove(&id)?;
        self.order.remove(&e.seq);
        Some((id, e))
    }
    fn remove(&mut self, id: &str) -> Option<Entry> {
        let e = self.by_id.remove(id)?;
        self.order.remove(&e.seq);
        Some(e)
    }
}

/// Window-TinyLFU cache. `access`/`insert` mirror `Sim` but carry timestamps so
/// prefetch lead time can be measured. Capacity is in units (chunks).
pub struct WLfu {
    window: Seg,
    main: Seg,
    wcap: usize,
    mcap: usize,
    sketch: FreqSketch,
    /// Prefetched entries dropped (evicted or invalidated) before their first
    /// use — each is one WASTED origin fetch. The self-tuning gate drains this
    /// via `take_pf_drops` as its negative feedback signal.
    pf_drops: u64,
}

/// Result of an access: whether it hit, whether this was a prefetched entry's
/// first use, and (if so) the lead time in ns between prefetch and this use.
pub struct AccessInfo {
    pub hit: bool,
    pub pf_first_use: bool,
    pub lead_ns: u64,
}

impl WLfu {
    pub fn new(cap: u64) -> Self {
        let cap = cap.max(2) as usize;
        // ~10% recency window (min 1), the rest is the frequency-admitted main.
        let wcap = (cap / 10).max(1);
        let mcap = (cap - wcap).max(1);
        WLfu {
            window: Seg::new(),
            main: Seg::new(),
            wcap,
            mcap,
            sketch: FreqSketch::new(1 << 16, (cap as u64).saturating_mul(16).max(1 << 14)),
            pf_drops: 0,
        }
    }

    /// A plain LRU (with the same timestamp/lead-tracking machinery): the whole
    /// capacity is the recency window, main is empty, so on overflow the LRU tail
    /// is simply evicted. Used as the base for the lead-gated hybrid, which the
    /// fleet showed should keep LRU's eviction (W-LFU underperformed it on IBM COS).
    pub fn new_lru(cap: u64) -> Self {
        let cap = cap.max(2) as usize;
        WLfu {
            window: Seg::new(),
            main: Seg::new(),
            wcap: cap,
            mcap: 0,
            sketch: FreqSketch::new(1 << 16, (cap as u64).saturating_mul(16).max(1 << 14)),
            pf_drops: 0,
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.window.contains(id) || self.main.contains(id)
    }

    pub fn len(&self) -> usize {
        self.window.len() + self.main.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn access(&mut self, id: &str, now: u64) -> AccessInfo {
        self.sketch.incr(id);
        if let Some((pfu, its)) = self.window.touch(id).or_else(|| self.main.touch(id)) {
            return AccessInfo {
                hit: true,
                pf_first_use: pfu,
                lead_ns: if pfu { now.saturating_sub(its) } else { 0 },
            };
        }
        AccessInfo { hit: false, pf_first_use: false, lead_ns: 0 }
    }

    pub fn insert(&mut self, id: &str, prefetched: bool, now: u64) {
        // Already resident: refresh recency but do NOT consume the prefetch
        // credit (that belongs to `access` alone). Both current callers guard
        // with `!contains`, so this path is defensive.
        if self.window.bump(id) || self.main.bump(id) {
            return;
        }
        self.window.push(id.to_string(), prefetched, now);
        if self.window.len() > self.wcap {
            let (cid, centry) = self.window.pop_lru().expect("window over cap");
            if self.main.len() < self.mcap {
                self.main.push_entry(cid, centry);
            } else if let Some(victim) = self.main.peek_lru().map(str::to_string) {
                // TinyLFU admission: the window candidate enters main only if it is
                // estimated hotter than main's LRU victim; else it is dropped. The
                // window already gave it a chance to prove recency-reuse.
                if self.sketch.est(&cid) > self.sketch.est(&victim) {
                    if let Some(ve) = self.main.remove(&victim) {
                        self.note_drop(&ve);
                    }
                    self.main.push_entry(cid, centry);
                } else {
                    self.note_drop(&centry); // candidate dropped — bypass
                }
            } else {
                self.note_drop(&centry); // mcap == 0 (plain LRU): tail evicted
            }
        }
    }

    pub fn invalidate(&mut self, id: &str) {
        if let Some(e) = self.window.remove(id) {
            self.note_drop(&e);
        }
        if let Some(e) = self.main.remove(id) {
            self.note_drop(&e);
        }
    }

    fn note_drop(&mut self, e: &Entry) {
        if e.pf_unused {
            self.pf_drops += 1;
        }
    }

    /// Drain the count of prefetched entries dropped UNUSED since the last call
    /// — the self-tuning gate's negative outcome signal (each is a wasted fetch).
    pub fn take_pf_drops(&mut self) -> u64 {
        std::mem::take(&mut self.pf_drops)
    }
}

/// Metrics for one policy run, including the lead-time latency estimate.
#[derive(Default, Clone)]
pub struct HybridReport {
    pub accesses: u64,
    pub hits: u64,
    pub pf_issued: u64,
    pub pf_used: u64,
    /// Sum of `min(1, lead/L)` over prefetch first-uses — fractional hidden fetches.
    pub lat_hidden_units: f64,
}

impl HybridReport {
    pub fn hit_rate(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.hits as f64 / self.accesses as f64 }
    }
    pub fn pf_per_access(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.pf_issued as f64 / self.accesses as f64 }
    }
    /// Reuse benefit minus prefetch cost (origin requests saved per access).
    pub fn net_savings(&self) -> f64 {
        if self.accesses == 0 { 0.0 }
        else { (self.hits as f64 - self.pf_issued as f64) / self.accesses as f64 }
    }
    /// Instant-prefetch latency hidden (upper bound): prefetch first-uses / access.
    pub fn pf_latency(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.pf_used as f64 / self.accesses as f64 }
    }
    /// Lead-time-aware latency hidden: credits each prefetch only for the fraction
    /// of the fetch it actually got ahead of. Always <= `pf_latency`.
    pub fn eff_latency(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.lat_hidden_units / self.accesses as f64 }
    }
}

/// Replay `trace` through a `WLfu` cache with a stingy top-1 prefetch overlay
/// (`predictor`, breadth 1), crediting hidden latency against a modelled fetch time
/// `fetch_latency_ns`. Pass a `NullPredictor` to get the demand-only W-LFU policy.
pub fn run_hybrid<P: Predictor>(
    trace: &[NormEvent],
    cap: u64,
    fetch_latency_ns: u64,
    predictor: &mut P,
) -> HybridReport {
    let l = fetch_latency_ns.max(1) as f64;
    let mut cache = WLfu::new(cap);
    let mut r = HybridReport::default();
    for ev in trace {
        match ev.op {
            Op::Put | Op::Delete => {
                cache.invalidate(&ev.object_id);
                continue;
            }
            Op::Head | Op::Other => continue,
            Op::Get => {}
        }
        let now = ev.ts_ns;
        r.accesses += 1;
        let info = cache.access(&ev.object_id, now);
        if info.hit {
            r.hits += 1;
            if info.pf_first_use {
                r.pf_used += 1;
                r.lat_hidden_units += (info.lead_ns as f64 / l).min(1.0);
            }
        } else {
            cache.insert(&ev.object_id, false, now);
        }
        predictor.observe(ev);
        // Stingy: apply only the single top prediction.
        if let Some(pid) = predictor.predict(ev).into_iter().next() {
            if !cache.contains(&pid) {
                r.pf_issued += 1;
                cache.insert(&pid, true, now);
            }
        }
    }
    r
}

/// The lead-gated hybrid: plain LRU eviction (so `net_savings` stays at the LRU
/// floor) plus a LEAD-ADAPTIVE prefetch. Each access, we track the recent mean
/// inter-arrival `Δ` (EWMA) and prefetch the object predicted `k = ceil(L/Δ)`
/// steps ahead (clamped to `max_depth`), so the fetch has ~`L` of lead and can
/// actually hide its latency — a one-step prefetch was too late on IBM's tight
/// timing. The deep guess is gated on chain confidence (`conf`): an ambiguous
/// chain issues nothing, keeping waste (and the cost to `net_savings`) small.
pub fn run_lead_gated(
    trace: &[NormEvent],
    cap: u64,
    fetch_latency_ns: u64,
    conf: f64,
    max_depth: usize,
) -> HybridReport {
    let l = fetch_latency_ns.max(1) as f64;
    let mut cache = WLfu::new_lru(cap);
    let mut mk = MarkovPredictor::new(1); // order-1 model for chain-following
    let mut r = HybridReport::default();
    let mut ewma_delta = l; // optimistic start: assume one step suffices
    let mut last_ts: Option<u64> = None;
    for ev in trace {
        match ev.op {
            Op::Put | Op::Delete => {
                cache.invalidate(&ev.object_id);
                continue;
            }
            Op::Head | Op::Other => continue,
            Op::Get => {}
        }
        let now = ev.ts_ns;
        r.accesses += 1;
        if let Some(lt) = last_ts {
            let gap = now.saturating_sub(lt) as f64;
            // Robust Δ update. Zero gaps are intra-batch (chunk expansion emits
            // every chunk of one GET at the same ts): feeding them would collapse
            // Δ to the floor and pin the depth at max_depth. A single huge idle
            // gap would conversely suppress prefetch depth for ~1/alpha events,
            // so clamp outliers to 16 fetch-times before they enter the average.
            if gap > 0.0 {
                ewma_delta = 0.95 * ewma_delta + 0.05 * gap.min(16.0 * l);
            }
        }
        last_ts = Some(now);

        let info = cache.access(&ev.object_id, now);
        if info.hit {
            r.hits += 1;
            if info.pf_first_use {
                r.pf_used += 1;
                r.lat_hidden_units += (info.lead_ns as f64 / l).min(1.0);
            }
        } else {
            cache.insert(&ev.object_id, false, now);
        }
        mk.observe(ev);
        // Depth that buys ~L of lead at the current request rate.
        let k = ((l / ewma_delta.max(1.0)).ceil() as usize).clamp(1, max_depth.max(1));
        if let Some(pid) = mk.chain_ahead(&ev.object_id, k, conf) {
            if pid != ev.object_id && !cache.contains(&pid) {
                r.pf_issued += 1;
                cache.insert(&pid, true, now);
            }
        }
    }
    r
}

/// The SELF-TUNING gate: `run_lead_gated` with the loop closed and speculation
/// structurally quarantined at ZERO fixed capacity cost. Three mechanisms, all
/// driven by outcomes the cache observes at runtime:
///
/// 1. **Adaptive prefetch budget (the pollution fix, no fixed tax).** One unified
///    LRU pool of the full `cap`. Prefetched-but-unused entries may occupy at most
///    `pf_budget` slots, a limit that GROWS on each first use and SHRINKS
///    multiplicatively on each waste. Excess speculation is trimmed from the pool's
///    LRU end via `pop_lru_pf_unused`, touching only unused prefetches, never the
///    demand working set. So on non-prefetchable workloads the budget collapses to
///    ~0 and the demand cache keeps the full `cap` (unlike a fixed side buffer,
///    which reserved slots the demand cache never got back); on streaming it grows
///    to hold the outstanding prefetches, which displace only cold demand entries
///    that LRU would evict anyway.
/// 2. **Waste budget (the cost clamp).** A token bucket refilling at `WASTE_RATE`
///    per access: issuing costs a token, first use REFUNDS it. High-precision
///    streams run free on refunds; waste is bounded by ~`WASTE_RATE`·accesses plus
///    the cold-start burst.
/// 3. **Adaptive confidence (the learner).** Realised precision (first use = good;
///    unused drop, via `take_pf_drops`, = waste) tightens the joint-chain gate
///    multiplicatively on every waste and releases it under sustained precision —
///    ambiguous workloads stop qualifying instead of burning budget.
pub fn run_self_tuned(
    trace: &[NormEvent],
    cap: u64,
    fetch_latency_ns: u64,
    max_depth: usize,
) -> HybridReport {
    const WASTE_RATE: f64 = 0.01; // budget: wasted prefetches allowed per access
    const BURST: f64 = 32.0; // bucket cap (cold-start allowance)
    const CONF_MIN: f64 = 0.40;
    const CONF_MAX: f64 = 0.98;
    const PREC_TARGET: f64 = 0.80;
    const ALPHA: f64 = 0.1; // precision-EWMA weight per resolved outcome
    // The gate must relax by the SAME factor it tightens by, or the feedback is
    // asymmetric: with a ×1.15 tighten and a ×0.99 relax the break-even precision
    // is ~93%, so a genuinely-prefetchable 80–93%-precision workload ratchets the
    // gate shut and then starves (no prefetch → no first-use → conf can never come
    // back down). Symmetric steps balance the gate at PREC_TARGET instead.
    const CONF_UP: f64 = 1.15; // tighten factor on a wasted prefetch; relax = /CONF_UP
    // Starvation re-probe: if the gate has rejected every candidate for this many
    // accesses, relax one notch so a gate that closed on a bad patch can reopen
    // and re-sample. (Harmless on true no-reuse traces: chain_ahead still returns
    // None there regardless of conf, so no bad prefetch is issued.)
    const REPROBE_IDLE: u64 = 1024;

    let l = fetch_latency_ns.max(1) as f64;
    let budget_max = (cap / 2).max(1) as usize;
    let mut pool = AdaptivePool::new(cap, budget_max);
    let mut mk = MarkovPredictor::new(1);
    let mut r = HybridReport::default();
    let mut ewma_delta = l;
    let mut last_ts: Option<u64> = None;
    let mut conf = 0.5f64;
    let mut prec = PREC_TARGET; // start neutral: no initial bias either way
    let mut tokens = BURST;
    let mut idle: u64 = 0; // accesses since the gate last let a prefetch through

    for ev in trace {
        match ev.op {
            Op::Put | Op::Delete => {
                pool.invalidate(&ev.object_id);
                continue;
            }
            Op::Head | Op::Other => continue,
            Op::Get => {}
        }
        let now = ev.ts_ns;
        r.accesses += 1;
        tokens = (tokens + WASTE_RATE).min(BURST);
        if let Some(lt) = last_ts {
            let gap = now.saturating_sub(lt) as f64;
            if gap > 0.0 {
                ewma_delta = 0.95 * ewma_delta + 0.05 * gap.min(16.0 * l);
            }
        }
        last_ts = Some(now);

        let info = pool.access(&ev.object_id, now);
        if info.hit {
            r.hits += 1;
            if info.pf_first_use {
                // A prefetch paid off: count it, credit the lead, refund the
                // token, grow the budget, and (when precision is healthy) relax
                // the gate. The entry is now demand-class inside the pool.
                r.pf_used += 1;
                r.lat_hidden_units += (info.lead_ns as f64 / l).min(1.0);
                tokens = (tokens + 1.0).min(BURST);
                prec = (1.0 - ALPHA) * prec + ALPHA;
                pool.reward();
                if prec > PREC_TARGET {
                    conf = (conf / CONF_UP).max(CONF_MIN);
                }
            }
        } else {
            pool.insert_demand(&ev.object_id, now);
        }

        mk.observe(ev);
        let k = ((l / ewma_delta.max(1.0)).ceil() as usize).clamp(1, max_depth.max(1));
        let mut issued = false;
        if tokens >= 1.0 {
            if let Some(pid) = mk.chain_ahead(&ev.object_id, k, conf) {
                if pid != ev.object_id && !pool.contains(&pid) {
                    tokens -= 1.0; // charged now, refunded on first use
                    r.pf_issued += 1;
                    pool.insert_prefetch(&pid, now);
                    issued = true;
                }
            }
        }
        if issued {
            idle = 0;
        } else {
            idle += 1;
            if idle >= REPROBE_IDLE {
                conf = (conf / CONF_UP).max(CONF_MIN); // re-probe a starved gate
                idle = 0;
            }
        }

        // Drain resolved negative outcomes (unused prefetches the pool dropped by
        // budget-trim, eviction, or invalidation): debit precision, shrink the
        // budget, tighten the gate.
        let drops = pool.take_pf_drops();
        for _ in 0..drops {
            prec *= 1.0 - ALPHA;
            pool.penalize();
            conf = (conf * CONF_UP).min(CONF_MAX);
        }
    }
    r
}

/// A single LRU pool of `cap` in which unused prefetches may occupy at most a
/// dynamic `pf_budget` slots. Mispredictions are trimmed from the pool's LRU end
/// without evicting demand entries, and the budget itself adapts to realised
/// precision — so speculation costs demand capacity only in proportion to how
/// well it is working (no fixed reservation).
struct AdaptivePool {
    seg: Seg,
    cap: usize,
    pf_unused: usize,   // resident prefetched-but-unused entries
    pf_budget: usize,   // dynamic cap on pf_unused
    budget_max: usize,
    pf_drops: u64,      // unused prefetches dropped since last drain
}

impl AdaptivePool {
    fn new(cap: u64, budget_max: usize) -> Self {
        AdaptivePool {
            seg: Seg::new(),
            cap: cap.max(2) as usize,
            pf_unused: 0,
            pf_budget: 1,
            budget_max: budget_max.max(1),
            pf_drops: 0,
        }
    }
    fn contains(&self, id: &str) -> bool {
        self.seg.contains(id)
    }
    fn reward(&mut self) {
        self.pf_budget = (self.pf_budget + 1).min(self.budget_max);
    }
    fn penalize(&mut self) {
        self.pf_budget = (self.pf_budget / 2).max(1);
    }
    fn take_pf_drops(&mut self) -> u64 {
        std::mem::take(&mut self.pf_drops)
    }
    /// Access: on a hit that is a prefetch's first use, it becomes demand-class
    /// (`pf_unused` decremented; `Seg::touch` already cleared the flag).
    fn access(&mut self, id: &str, now: u64) -> AccessInfo {
        match self.seg.touch(id) {
            Some((pfu, its)) => {
                if pfu {
                    self.pf_unused = self.pf_unused.saturating_sub(1);
                }
                AccessInfo { hit: true, pf_first_use: pfu, lead_ns: if pfu { now.saturating_sub(its) } else { 0 } }
            }
            None => AccessInfo { hit: false, pf_first_use: false, lead_ns: 0 },
        }
    }
    fn insert_demand(&mut self, id: &str, now: u64) {
        if self.seg.bump(id) {
            return;
        }
        self.seg.push(id.to_string(), false, now);
        self.evict_to_fit();
    }
    fn insert_prefetch(&mut self, id: &str, now: u64) {
        if self.seg.bump(id) {
            return;
        }
        self.seg.push(id.to_string(), true, now);
        self.pf_unused += 1;
        self.evict_to_fit();
    }
    fn invalidate(&mut self, id: &str) {
        if let Some(e) = self.seg.remove(id) {
            if e.pf_unused {
                self.pf_unused = self.pf_unused.saturating_sub(1);
                self.pf_drops += 1;
            }
        }
    }
    fn evict_to_fit(&mut self) {
        // First trim unused prefetches over budget (never touches demand).
        while self.pf_unused > self.pf_budget {
            if self.seg.pop_lru_pf_unused().is_some() {
                self.pf_unused -= 1;
                self.pf_drops += 1;
            } else {
                break;
            }
        }
        // Then enforce total capacity by global LRU (may be demand or a within-
        // budget prefetch that has aged to the cold end).
        while self.seg.len() > self.cap {
            match self.seg.pop_lru() {
                Some((_, e)) => {
                    if e.pf_unused {
                        self.pf_unused = self.pf_unused.saturating_sub(1);
                        self.pf_drops += 1;
                    }
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predict::NullPredictor;
    use crate::trace::{NormEvent, Op};

    fn get(id: &str, ts: u64) -> NormEvent {
        NormEvent { ts_ns: ts, op: Op::Get, object_id: id.into(), range: None,
                    size: Some(1), version: None, status: Some(200) }
    }

    #[test]
    fn wlfu_scan_resistant_keeps_hot_set() {
        // A 4-object hot set hammered, interleaved with unique one-shot "scan"
        // objects. Plain LRU thrashes (working set 4 but scan evicts them); W-LFU's
        // frequency admission should keep the hot set and bypass the one-shots.
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for i in 0..3000u32 {
            ts += 1; trace.push(get(&format!("hot{}", i % 4), ts));
            ts += 1; trace.push(get(&format!("scan{i}"), ts)); // never repeats
        }
        let r = run_hybrid(&trace, 8, 1, &mut NullPredictor);
        // The 4 hot objects should mostly hit once warm; LRU at cap 8 would be
        // repeatedly flushed by the scan stream.
        assert!(r.hit_rate() > 0.30, "W-LFU hit_rate {} too low (scan not resisted)", r.hit_rate());
    }

    #[test]
    fn lead_time_credits_early_prefetch_more() {
        // Manually exercise the cache: a prefetch used long after issue hides more
        // latency than one used immediately.
        let mut early = WLfu::new(8);
        early.insert("x", true, 0);
        let a = early.access("x", 1_000_000_000); // 1s lead
        assert!(a.pf_first_use && a.lead_ns == 1_000_000_000);

        let mut late = WLfu::new(8);
        late.insert("y", true, 0);
        let b = late.access("y", 5_000_000); // 5ms lead
        assert!(b.pf_first_use && b.lead_ns == 5_000_000);
    }

    #[test]
    fn lead_gated_hides_latency_where_one_step_cannot() {
        // A deterministic cyclic sequence of 200 objects (working set > cap) with
        // TIGHT 10ms spacing, and a 100ms fetch. A one-step prefetch lands only
        // 10ms ahead (hides ~10%); the lead-gated policy looks ~10 steps ahead so
        // the prefetch lands ~100ms early and hides the whole fetch.
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..40 {
            for i in 0..200 {
                ts += 10_000_000; // 10 ms
                trace.push(get(&format!("s{i}"), ts));
            }
        }
        let l = 100_000_000; // 100 ms fetch
        let one_step = run_hybrid(&trace, 64, l, &mut crate::predict::MarkovPredictor::new(1));
        let gated = run_lead_gated(&trace, 64, l, 0.5, 32);
        assert!(
            gated.eff_latency() > one_step.eff_latency() + 0.2,
            "lead-gated eff_lat {} should beat one-step {}",
            gated.eff_latency(), one_step.eff_latency()
        );
        // And it must not have wrecked net_savings (LRU base + confident chain).
        assert!(gated.net_savings() >= -0.05, "net {}", gated.net_savings());
    }

    #[test]
    fn demand_run_never_net_negative() {
        // With no prefetch, net_savings == hit_rate >= 0 always.
        let trace: Vec<_> = (0..500u32).map(|i| get(&format!("o{}", i % 20), i as u64)).collect();
        let r = run_hybrid(&trace, 16, 1, &mut NullPredictor);
        assert_eq!(r.pf_issued, 0);
        assert!((r.net_savings() - r.hit_rate()).abs() < 1e-9);
        assert!(r.net_savings() >= 0.0);
    }

    #[test]
    fn new_lru_evicts_lru_and_never_promotes_to_main() {
        let mut c = WLfu::new_lru(2); // wcap=2, mcap=0 -> plain LRU
        c.insert("a", false, 0);
        c.insert("b", false, 1);
        c.insert("c", false, 2); // evicts "a" (LRU tail)
        assert!(!c.contains("a"));
        assert!(c.contains("b") && c.contains("c"));
        assert_eq!(c.len(), 2);
        // Touch "b" to MRU; next insert must evict "c", not "b".
        assert!(c.access("b", 3).hit);
        c.insert("d", false, 4);
        assert!(c.contains("b") && !c.contains("c"));
    }

    #[test]
    fn new_lru_no_panic_at_small_caps() {
        for cap in [1u64, 2, 3] {
            let mut c = WLfu::new_lru(cap);
            for i in 0..20u64 {
                c.insert(&format!("o{i}"), false, i);
            }
            assert!(c.len() <= cap.max(2) as usize);
        }
    }

    #[test]
    fn wlfu_admission_rejects_cold_candidate_protects_hot_main() {
        // cap 20 -> wcap 2, mcap 18. Build frequency for "hot", promote it to
        // main, then flood with cold one-shots: the TinyLFU admission must keep
        // "hot" resident (a cold candidate never beats it).
        let mut c = WLfu::new(20);
        for i in 0..50u64 {
            c.access("hot", i);
            c.insert("hot", false, i);
        }
        for i in 0..200u64 {
            let k = format!("cold{i}");
            c.access(&k, 100 + i);
            c.insert(&k, false, 100 + i);
        }
        assert!(c.contains("hot"), "cold scan displaced the hot object (admission failed)");
    }

    #[test]
    fn invalidate_removes_from_both_segments() {
        let mut c = WLfu::new(20); // wcap 2, mcap 18
        // "m" ends up promoted to main by the window overflow flow; "w" stays in
        // the window. Invalidate must remove either.
        for i in 0..30u64 { c.access("m", i); c.insert("m", false, i); }
        for i in 0..10u64 { c.insert(&format!("f{i}"), false, 100 + i); } // pushes m to main
        c.insert("w", false, 500);
        assert!(c.contains("m") && c.contains("w"));
        c.invalidate("m");
        c.invalidate("w");
        assert!(!c.contains("m") && !c.contains("w"));
    }

    #[test]
    fn insert_bump_preserves_prefetch_credit() {
        // Defensive path: insert on an already-resident prefetched-unused entry
        // must NOT consume its first-use credit (only `access` may).
        let mut c = WLfu::new_lru(8);
        c.insert("p", true, 0);
        c.insert("p", true, 5); // resident -> bump, credit intact
        let a = c.access("p", 100);
        assert!(a.hit && a.pf_first_use, "prefetch credit was erased by re-insert");
        assert_eq!(a.lead_ns, 100); // measured from the ORIGINAL issue at t=0
    }

    #[test]
    fn lead_gated_disengages_on_no_reuse() {
        // Every object unique: the Markov chain leaves the model at step 1, so
        // the overlay must issue ZERO prefetches (emergent disengage).
        let trace: Vec<_> = (0..2000u64).map(|i| get(&format!("u{i}"), i * 1_000)).collect();
        let r = run_lead_gated(&trace, 64, 1_000, 0.5, 16);
        assert_eq!(r.pf_issued, 0);
        assert!(r.net_savings() >= 0.0);
    }

    #[test]
    fn lead_gated_honors_put_invalidation() {
        let mut put = get("x", 2);
        put.op = Op::Put;
        let trace = vec![get("x", 1), put, get("x", 3)];
        let r = run_lead_gated(&trace, 8, 1, 0.5, 4);
        assert_eq!(r.accesses, 2); // PUT is not a cacheable read
        assert_eq!(r.hits, 0, "PUT between the GETs must invalidate x");
    }

    #[test]
    fn lead_gated_survives_same_timestamp_batches() {
        // All events share one timestamp (the chunk-expansion shape): gap is
        // always 0, the EWMA must not collapse, and nothing may panic.
        let mut trace = Vec::new();
        for _ in 0..40 {
            for i in 0..50 {
                trace.push(get(&format!("s{i}"), 1_000));
            }
        }
        let r = run_lead_gated(&trace, 32, 100_000_000, 0.5, 32);
        assert!(r.net_savings() > -0.5, "runaway prefetch on batched timestamps");
        // Zero-lead consumption must credit zero hidden latency.
        assert!(r.eff_latency() < 1e-9);
    }

    #[test]
    fn lead_credit_caps_at_one_fetch() {
        let l = 100.0; // modelled fetch time (ns, toy scale)
        let cases = [(100u64, 1.0), (300, 1.0), (25, 0.25)]; // lead==L, lead>L, fractional
        for (use_ts, want) in cases {
            let mut c = WLfu::new_lru(8);
            c.insert("x", true, 0);
            let a = c.access("x", use_ts);
            assert!(a.pf_first_use);
            let credit = (a.lead_ns as f64 / l).min(1.0);
            assert!((credit - want).abs() < 1e-9, "lead {use_ts}: credit {credit} != {want}");
        }
    }

    #[test]
    fn net_savings_identity_with_prefetch() {
        use crate::predict::MarkovPredictor;
        let mut trace = Vec::new();
        for c in 0..20u64 {
            for i in 0..30u64 {
                trace.push(get(&format!("s{i}"), c * 1_000 + i));
            }
        }
        let r = run_hybrid(&trace, 16, 1, &mut MarkovPredictor::new(1));
        assert!(r.pf_issued > 0);
        let want = (r.hits as f64 - r.pf_issued as f64) / r.accesses as f64;
        assert!((r.net_savings() - want).abs() < 1e-12);
    }

    #[test]
    fn eff_latency_never_exceeds_pf_latency() {
        use crate::predict::MarkovPredictor;
        let mut trace = Vec::new();
        for c in 0..30u64 {
            for i in 0..40u64 {
                trace.push(get(&format!("s{i}"), (c * 40 + i) * 5_000_000));
            }
        }
        let hy = run_hybrid(&trace, 64, 100_000_000, &mut MarkovPredictor::new(1));
        let lg = run_lead_gated(&trace, 64, 100_000_000, 0.5, 32);
        assert!(hy.eff_latency() <= hy.pf_latency() + 1e-12);
        assert!(lg.eff_latency() <= lg.pf_latency() + 1e-12);
    }

    #[test]
    fn pf_drop_counter_counts_only_unused() {
        let mut c = WLfu::new_lru(2);
        // Unused prefetch evicted -> one drop.
        c.insert("p", true, 0);
        c.insert("a", false, 1);
        c.insert("b", false, 2); // evicts p (still unused)
        assert_eq!(c.take_pf_drops(), 1);
        // Used prefetch evicted -> NOT a drop (its fetch paid off).
        c.invalidate("a");
        c.invalidate("b");
        c.insert("q", true, 3);
        assert!(c.access("q", 4).pf_first_use);
        c.insert("x", false, 5);
        c.insert("y", false, 6); // evicts q (already used)
        assert_eq!(c.take_pf_drops(), 0);
        // Invalidated unused prefetch -> one drop.
        c.insert("r", true, 7);
        c.invalidate("r");
        assert_eq!(c.take_pf_drops(), 1);
    }

    #[test]
    fn self_tuned_clamps_waste_by_construction() {
        // Adversarial shifting workload: 80 objects re-permuted every epoch, 4
        // passes per epoch, working set 80 >> cap 16 (LRU floor ~ 0). Chains
        // learned in one epoch keep "predicting" stale successors into the next
        // — sustained plausible-but-wrong speculation. The budget must clamp
        // wasted prefetches to ~WASTE_RATE + the cold-start burst, keeping net
        // within a whisker of the LRU floor.
        let mut order: Vec<u32> = (0..80).collect();
        let mut seed = 0x9E3779B9u64;
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..12 {
            // Fisher-Yates with a tiny xorshift (deterministic, no rand dep).
            for i in (1..order.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                order.swap(i, (seed as usize) % (i + 1));
            }
            for _ in 0..4 {
                for &o in &order {
                    ts += 200_000_000; // 200 ms spacing -> k = 1
                    trace.push(get(&format!("o{o}"), ts));
                }
            }
        }
        let l = 100_000_000u64;
        // PLAIN-LRU floor at the full capacity (run_hybrid's demand rung is the
        // windowed W-LFU, which is a different policy — on this workload its
        // frozen frequent set would overstate the floor).
        let mut c = WLfu::new_lru(16);
        let (mut lru_hits, mut acc) = (0u64, 0u64);
        for ev in &trace {
            acc += 1;
            if c.access(&ev.object_id, ev.ts_ns).hit { lru_hits += 1; }
            else { c.insert(&ev.object_id, false, ev.ts_ns); }
        }
        let lru_net = lru_hits as f64 / acc as f64;
        let st = run_self_tuned(&trace, 16, l, 32);
        let wasted = st.pf_issued.saturating_sub(st.pf_used) as f64;
        let bound = 0.01 * st.accesses as f64 + 32.0 + 1.0;
        assert!(wasted <= bound, "wasted {wasted} exceeds budget bound {bound}");
        // With the adaptive pool (no fixed buffer reservation) the budget
        // collapses under sustained waste and the demand cache keeps ~full cap,
        // so net stays right at the plain-LRU floor.
        assert!(
            st.net_savings() >= lru_net - 0.01,
            "self-tuned net {} fell below plain-LRU floor {} - 0.01",
            st.net_savings(), lru_net
        );
    }

    #[test]
    fn self_tuned_keeps_the_streaming_win() {
        // Deterministic 200-object cycle at tight 10ms spacing (100ms fetch):
        // high-precision prefetching must run FREE on token refunds, keeping
        // both the latency win and the cost floor.
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..40 {
            for i in 0..200 {
                ts += 10_000_000;
                trace.push(get(&format!("s{i}"), ts));
            }
        }
        // The adaptive budget grows to hold the outstanding prefetches (no fixed
        // k-cap), so the tight-timing latency win is kept near-fully.
        let st = run_self_tuned(&trace, 64, 100_000_000, 32);
        assert!(st.eff_latency() > 0.8, "streaming eff_lat lost: {}", st.eff_latency());
        assert!(st.net_savings() >= -0.02, "net {}", st.net_savings());
    }

    #[test]
    fn adaptive_pool_charges_no_tax_when_prefetch_useless() {
        // Prefetches that are never used must not cost demand capacity: the
        // budget collapses and the pool behaves like plain LRU. Compare hit
        // counts of self-tuned (with a predictor that will mispredict on a
        // shifting stream) against plain LRU at the SAME cap — within a hair.
        let mut order: Vec<u32> = (0..120).collect();
        let mut seed = 0x1234_5678u64;
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..20 {
            for i in (1..order.len()).rev() {
                seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                order.swap(i, (seed as usize) % (i + 1));
            }
            for &o in &order {
                ts += 50_000_000;
                trace.push(get(&format!("o{o}"), ts));
            }
        }
        let mut c = WLfu::new_lru(32);
        let (mut lru_hits, mut acc) = (0u64, 0u64);
        for ev in &trace {
            acc += 1;
            if c.access(&ev.object_id, ev.ts_ns).hit { lru_hits += 1; }
            else { c.insert(&ev.object_id, false, ev.ts_ns); }
        }
        let st = run_self_tuned(&trace, 32, 100_000_000, 32);
        let lru_hr = lru_hits as f64 / acc as f64;
        // Within 1% hit-rate of plain LRU — the fixed-buffer version lost ~12%.
        assert!(st.hit_rate() >= lru_hr - 0.01,
                "adaptive pool taxed demand: st {} vs lru {}", st.hit_rate(), lru_hr);
    }

    #[test]
    fn new_lru_matches_sim_lru_hit_count() {
        // Fairness pin for hybrid_eval: its LRU floor uses Sim (driver::run)
        // while the lead-gated policy runs on WLfu::new_lru. Demand-only, the
        // two LRU implementations must produce IDENTICAL hit counts.
        use crate::driver;
        let trace: Vec<_> =
            (0..1000u32).map(|i| get(&format!("o{}", (i * i) % 37), i as u64)).collect();
        let cap = 16u64;
        let sim = driver::run(&trace, &mut NullPredictor, cap);
        let mut c = WLfu::new_lru(cap);
        let (mut hits, mut acc) = (0u64, 0u64);
        for ev in &trace {
            acc += 1;
            if c.access(&ev.object_id, ev.ts_ns).hit {
                hits += 1;
            } else {
                c.insert(&ev.object_id, false, ev.ts_ns);
            }
        }
        assert_eq!(acc, sim.accesses);
        assert_eq!(hits, sim.hits, "WLfu::new_lru diverged from Sim-LRU");
    }
}
