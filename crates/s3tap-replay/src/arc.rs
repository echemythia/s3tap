//! ARC — Adaptive Replacement Cache (Megiddo & Modha, FAST '03).
//!
//! The missing retention baseline for the caching study. The report shows LRU (`lru+adm`),
//! W-LFU, and the OPT ceiling, and concludes "IBM COS is recency-friendly, so W-LFU's
//! frequency-admission made it WORSE than LRU." ARC is the canonical policy that SELF-TUNES the
//! recency↔frequency balance per workload — exactly the axis W-LFU got wrong — so it is the
//! decisive test of that verdict: if even ARC can't beat LRU here the "just use LRU" story gets
//! much stronger, and if it can it reframes what the self-tuned controller contributes.
//!
//! Algorithm (unchanged from the paper). Four lists over the key space, plus an adaptive target
//! `p` for the size of the recency half:
//!   T1  recency  — pages seen once recently          (in cache)
//!   T2  frequency— pages seen ≥ 2 times              (in cache)
//!   B1  ghosts evicted from T1                        (keys only, no data)
//!   B2  ghosts evicted from T2                        (keys only, no data)
//! Invariants: |T1|+|T2| ≤ c ; |T1|+|B1| ≤ c ; |T1|+|T2|+|B1|+|B2| ≤ 2c. A ghost hit in B1
//! grows `p` (favor recency); a ghost hit in B2 shrinks it (favor frequency).
//!
//! Interface parity with `driver::eval_admission_caps` so the row is directly comparable to
//! `null`/`lru+adm`: capacity is in COUNT (unit sizes), only `Op::Get` counts as an access,
//! `Op::Put`/`Op::Delete` invalidate the key, `Op::Head`/`Op::Other` are ignored, and
//! `hit_rate = hits / accesses`. No prefetch, so `net_savings == hit_rate` (a demand policy).

use std::collections::{BTreeMap, HashMap};

use crate::driver::Row;
use crate::trace::{NormEvent, Op};

/// An LRU-ordered key set with O(log n) touch / pop-LRU / remove and O(1) membership. A
/// monotonic stamp gives the order (lowest = LRU, highest = MRU); the `BTreeMap` keeps it
/// sorted so the LRU end is `iter().next()`. Ghost lists need the same ops (pop their LRU,
/// test membership), so all four ARC lists reuse this.
#[derive(Default)]
struct LruList {
    stamp: HashMap<String, u64>,
    order: BTreeMap<u64, String>,
    next: u64,
}

impl LruList {
    fn len(&self) -> usize {
        self.stamp.len()
    }
    fn contains(&self, k: &str) -> bool {
        self.stamp.contains_key(k)
    }
    /// Insert `k`, or move it to the MRU end if already present.
    fn touch(&mut self, k: &str) {
        self.remove(k);
        let s = self.next;
        self.next += 1;
        self.stamp.insert(k.to_string(), s);
        self.order.insert(s, k.to_string());
    }
    fn remove(&mut self, k: &str) -> bool {
        match self.stamp.remove(k) {
            Some(s) => {
                self.order.remove(&s);
                true
            }
            None => false,
        }
    }
    /// Remove and return the LRU key.
    fn pop_lru(&mut self) -> Option<String> {
        let (&s, _) = self.order.iter().next()?;
        let k = self.order.remove(&s).expect("stamp present in order");
        self.stamp.remove(&k);
        Some(k)
    }
}

/// An Adaptive Replacement Cache over string keys, capacity `c` items.
pub struct Arc {
    c: usize,
    p: usize, // adaptive target for |T1|, in [0, c]
    t1: LruList,
    t2: LruList,
    b1: LruList,
    b2: LruList,
}

impl Arc {
    #[must_use]
    pub fn new(c: usize) -> Self {
        Arc { c: c.max(1), p: 0, t1: LruList::default(), t2: LruList::default(), b1: LruList::default(), b2: LruList::default() }
    }

    /// Access `key`; returns `true` on a cache HIT. Ghost-list hits (B1/B2) are misses that
    /// only adapt `p` and promote the key to T2.
    pub fn access(&mut self, key: &str) -> bool {
        // Case I — hit in the cache (T1 or T2): promote to MRU of T2 (now seen ≥ 2×).
        if self.t1.contains(key) || self.t2.contains(key) {
            self.t1.remove(key);
            self.t2.touch(key);
            return true;
        }
        // Case II — ghost hit in B1 (recency ghost): grow p toward recency, then replace.
        if self.b1.contains(key) {
            let delta = ratio_at_least_one(self.b2.len(), self.b1.len());
            self.p = (self.p + delta).min(self.c);
            self.evict_if_full(key);
            self.b1.remove(key);
            self.t2.touch(key);
            return false;
        }
        // Case III — ghost hit in B2 (frequency ghost): shrink p toward frequency, then replace.
        if self.b2.contains(key) {
            let delta = ratio_at_least_one(self.b1.len(), self.b2.len());
            self.p = self.p.saturating_sub(delta);
            self.evict_if_full(key);
            self.b2.remove(key);
            self.t2.touch(key);
            return false;
        }
        // Case IV — a true miss (not in any list); x is inserted at the MRU of T1.
        if self.resident() >= self.c {
            // Cache full (canonical ARC): make room by evicting one RESIDENT page.
            let l1 = self.t1.len() + self.b1.len();
            if l1 == self.c {
                // Recency half full: drop a B1 ghost + REPLACE, else (B1 empty) evict LRU of T1.
                if self.t1.len() < self.c {
                    self.b1.pop_lru();
                    self.replace(key);
                } else {
                    self.t1.pop_lru();
                }
            } else {
                let total = self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len();
                if total >= self.c {
                    if total == 2 * self.c {
                        self.b2.pop_lru();
                    }
                    self.replace(key);
                }
            }
        } else {
            // A free slot exists (invalidate left a hole): fill it WITHOUT evicting a resident,
            // trimming only a GHOST so the directory invariants (|T1|+|B1|<=c, total<=2c) still
            // hold after the T1 insert. This is a no-op for canonical ARC (a ghost exists only
            // when resident==c) and mirrors the LRU baseline's admit-with-room, for a fair
            // comparison on write-bearing traces.
            let l1 = self.t1.len() + self.b1.len();
            if l1 == self.c {
                self.b1.pop_lru(); // B1 non-empty here (T1 <= resident < c), so a ghost is dropped
            } else {
                let total = self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len();
                if total == 2 * self.c {
                    self.b2.pop_lru();
                }
            }
        }
        self.t1.touch(key);
        false
    }

    /// REPLACE(x, p): evict one cache page to its ghost list, choosing T1 vs T2 by the target
    /// `p`. `incoming` is the page being requested — its presence in B2 tips a boundary case.
    fn replace(&mut self, incoming: &str) {
        let t1_over = self.t1.len() > self.p;
        let boundary = self.t1.len() == self.p && self.b2.contains(incoming);
        if self.t1.len() >= 1 && (t1_over || boundary) {
            if let Some(k) = self.t1.pop_lru() {
                self.b1.touch(&k);
            }
        } else if let Some(k) = self.t2.pop_lru() {
            self.b2.touch(&k);
        }
    }

    /// A ghost hit promotes the key into T2 (+1 resident). Canonical ARC is always full at a
    /// ghost hit, so it REPLACEs (evicts one) to stay at c — and this gate is a no-op there
    /// (whenever a ghost exists, resident == c). But `invalidate` can leave the cache BELOW c;
    /// then there is a free slot, and filling it without eviction mirrors how the LRU baseline
    /// admits on a miss with room — keeping the ARC-vs-LRU comparison fair on write-bearing traces.
    fn evict_if_full(&mut self, incoming: &str) {
        if self.resident() >= self.c {
            self.replace(incoming);
        }
    }

    /// Drop `key` from the cache AND the ghost lists — a mutation (PUT/DELETE) invalidates any
    /// cached copy and its history, so a later GET is a cold miss.
    pub fn invalidate(&mut self, key: &str) {
        self.t1.remove(key);
        self.t2.remove(key);
        self.b1.remove(key);
        self.b2.remove(key);
    }

    /// Resident (cached) item count — for invariant checks.
    #[must_use]
    pub fn resident(&self) -> usize {
        self.t1.len() + self.t2.len()
    }
}

/// `max(1, a/b)` in integer arithmetic (the paper's `max(|B2|/|B1|, 1)` adaptation step),
/// guarding `b == 0`.
fn ratio_at_least_one(a: usize, b: usize) -> usize {
    a.checked_div(b).unwrap_or(1).max(1)
}

/// Sweep ARC over a trace at each capacity, one demand row per cap (predictor `"arc"`). Mirrors
/// `driver::eval_admission_caps` so the rows drop straight into the same table as `lru+adm`.
#[must_use]
pub fn eval_arc_caps(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    let mut rows = Vec::with_capacity(caps.len());
    for &capu in caps {
        let mut arc = Arc::new(capu as usize);
        let (mut accesses, mut hits) = (0u64, 0u64);
        for ev in trace {
            match ev.op {
                Op::Put | Op::Delete => {
                    arc.invalidate(&ev.object_id);
                    continue;
                }
                Op::Head | Op::Other => continue,
                Op::Get => {}
            }
            accesses += 1;
            if arc.access(&ev.object_id) {
                hits += 1;
            }
        }
        let hr = if accesses > 0 { hits as f64 / accesses as f64 } else { 0.0 };
        rows.push(Row::demand("arc", capu, hr)); // demand policy: net_savings == hit_rate
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(id: &str) -> NormEvent {
        NormEvent {
            ts_ns: 0,
            op: Op::Get,
            object_id: id.to_string(),
            range: None,
            size: None,
            version: None,
            status: None,
        }
    }

    fn hit_rate(cap: u64, ids: &[&str]) -> f64 {
        let trace: Vec<NormEvent> = ids.iter().map(|s| get(s)).collect();
        eval_arc_caps(&trace, &[cap])[0].hit_rate
    }

    #[test]
    fn immediate_reaccess_is_a_hit_and_capacity_is_enforced() {
        let mut arc = Arc::new(2);
        assert!(!arc.access("a")); // cold
        assert!(arc.access("a")); // reuse -> hit
        arc.access("b");
        arc.access("c"); // evicts something; residency never exceeds c
        assert!(arc.resident() <= 2, "resident {} > c", arc.resident());
    }

    #[test]
    fn never_exceeds_capacity_over_a_long_stream() {
        let mut arc = Arc::new(4);
        for i in 0..1000 {
            arc.access(&format!("k{}", i % 20));
            assert!(arc.resident() <= 4);
            // total footprint (cache + ghosts) is bounded by 2c
            let total = arc.t1.len() + arc.t2.len() + arc.b1.len() + arc.b2.len();
            assert!(total <= 2 * 4, "footprint {total} > 2c");
        }
    }

    #[test]
    fn zero_hits_on_all_unique_and_full_hits_on_all_repeat() {
        // Every key distinct -> no reuse -> 0 hits regardless of cap.
        assert_eq!(hit_rate(8, &["a", "b", "c", "d", "e", "f"]), 0.0);
        // One key repeated -> first is a miss, the rest hit -> 5/6.
        let hr = hit_rate(4, &["a", "a", "a", "a", "a", "a"]);
        assert!((hr - 5.0 / 6.0).abs() < 1e-9, "hr={hr}");
    }

    /// A plain-LRU hit rate over the same key stream, so a test can assert ARC's scan
    /// resistance directly against the policy it must not lose to.
    fn lru_hit_rate(cap: usize, ids: &[String]) -> f64 {
        let mut l = LruList::default();
        let (mut acc, mut hits) = (0u64, 0u64);
        for id in ids {
            acc += 1;
            if l.contains(id) {
                hits += 1;
                l.touch(id);
            } else {
                if l.len() >= cap {
                    l.pop_lru();
                }
                l.touch(id);
            }
        }
        hits as f64 / acc as f64
    }

    #[test]
    fn arc_is_scan_resistant_and_beats_lru() {
        // The textbook ARC win: a hot set builds FREQUENCY (accessed repeatedly while resident,
        // so it lands in T2), then a long UNIQUE scan floods the cache. ARC's T2 protects the
        // hot set through the scan (the scan keys are one-shots — no ghost hits, so p stays 0
        // and REPLACE only evicts the recency half T1). Plain LRU, keeping just the most-recent
        // c keys, evicts the hot set during the scan. So the post-scan hot re-accesses HIT under
        // ARC and MISS under LRU. cap 4, hot set {h0,h1}, a 20-key scan (> cap).
        let mut ids: Vec<String> = Vec::new();
        for _ in 0..3 {
            ids.push("h0".into());
            ids.push("h1".into()); // build: h0,h1 each accessed 3x -> frequency (T2)
        }
        for s in 0..20 {
            ids.push(format!("s{s}")); // scan: 20 unique one-shots
        }
        ids.push("h0".into());
        ids.push("h1".into()); // test: protected under ARC, evicted under LRU

        let trace: Vec<NormEvent> = ids.iter().map(|s| get(s)).collect();
        let arc_hr = eval_arc_caps(&trace, &[4])[0].hit_rate;
        let lru_hr = lru_hit_rate(4, &ids);
        // ARC keeps the 2 post-scan hot hits that LRU loses to the scan.
        assert!(arc_hr > lru_hr, "ARC {arc_hr} did not beat LRU {lru_hr} under scan pollution");
        assert!(arc_hr > 0.15, "ARC failed to retain the reused hot set: {arc_hr}");
    }

    #[test]
    fn invalidate_hole_is_refilled_not_left_below_cap() {
        // With a GHOST present, a post-invalidate miss must FILL the free slot, not evict a
        // resident (the Case IV under-fill bug). cap 2: build T2={a,b}, a miss evicts a to the
        // B2 ghost, invalidate b leaves a hole, then a fresh miss must bring resident back to cap.
        let mut arc = Arc::new(2);
        for k in ["a", "a", "b", "b"] {
            arc.access(k); // T2 = {a, b}, resident 2
        }
        arc.access("c"); // miss evicts a -> B2 ghost; resident 2
        assert_eq!(arc.resident(), 2);
        arc.invalidate("b"); // hole: resident 1, ghost still present
        assert_eq!(arc.resident(), 1);
        arc.access("d"); // fresh miss with a hole AND a ghost -> must fill, not evict a resident
        assert_eq!(arc.resident(), 2, "invalidate hole not refilled (Case IV under-fill)");
    }

    #[test]
    fn edge_cases_do_not_panic() {
        // empty trace -> 0 accesses -> 0.0
        assert_eq!(eval_arc_caps(&[], &[4])[0].hit_rate, 0.0);
        // cap 0 clamps to 1; every cap yields a hit_rate in [0,1] with no panic.
        let ids: Vec<NormEvent> = ["a", "a", "b", "a", "c", "a"].iter().map(|s| get(s)).collect();
        for &cap in &[0u64, 1, 2, 100] {
            let hr = eval_arc_caps(&ids, &[cap])[0].hit_rate;
            assert!((0.0..=1.0).contains(&hr), "cap {cap}: hr {hr} out of range");
        }
        // a write-/head-only trace has 0 accesses -> 0.0.
        let writes = vec![NormEvent { op: Op::Put, ..get("x") }, NormEvent { op: Op::Head, ..get("y") }];
        assert_eq!(eval_arc_caps(&writes, &[4])[0].hit_rate, 0.0);
    }

    #[test]
    fn invalidate_makes_a_later_get_a_cold_miss() {
        let mut arc = Arc::new(4);
        arc.access("x");
        assert!(arc.access("x")); // resident -> hit
        arc.invalidate("x"); // a PUT/DELETE drops it
        assert!(!arc.access("x"), "GET after invalidate should be a cold miss");
    }

    #[test]
    fn put_delete_invalidate_in_the_sweep() {
        // get x, get x (hit), PUT x (invalidate), get x (cold miss) => 1 hit of 3 GETs.
        let trace = vec![
            get("x"),
            get("x"),
            NormEvent { op: Op::Put, ..get("x") },
            get("x"),
        ];
        let hr = eval_arc_caps(&trace, &[4])[0].hit_rate;
        assert!((hr - 1.0 / 3.0).abs() < 1e-9, "hr={hr} (expected 1/3: PUT must invalidate)");
    }
}
