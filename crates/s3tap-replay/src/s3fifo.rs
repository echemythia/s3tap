//! S3-FIFO — "FIFO queues are all you need for cache eviction" (Yang et al., SOSP '23).
//!
//! A second modern retention baseline for the study, and a thematically apt one for an *S3*
//! tool. Three FIFO queues + a 2-bit frequency counter, no LRU list at all:
//!   S  small queue (~10% of cache) — every new object enters here
//!   M  main  queue (~90%)          — objects promoted out of S
//!   G  ghost queue (keys only)     — fingerprints of objects that left S without reuse
//! On a miss, an object seen before (in G) enters M directly; a brand-new object enters S. On
//! eviction from S, an object accessed enough (freq >= `S_PROMOTE_MIN_FREQ`) is promoted to M,
//! otherwise it goes to the ghost (so one-shot scan objects never pollute M — the scan
//! resistance). M evicts FIFO with a
//! second chance (freq-decrement-and-reinsert). It matches or beats LRU/ARC on many web/object
//! workloads at lower metadata cost.
//!
//! Interface parity with `driver::eval_admission_caps`/`arc::eval_arc_caps`: count capacity
//! (unit sizes), only `Op::Get` is an access, `Op::Put`/`Op::Delete` invalidate, `hit_rate =
//! hits / accesses`, predictor `"s3fifo"`. A demand policy, so `net_savings == hit_rate`.
//!
//! Implementation notes: the queues hold keys; `invalidate` is O(1) via LAZY deletion — the key
//! is dropped from the authoritative `entries` map and its now-stale queue slot is skipped when
//! popped. Live `s_len`/`m_len` counters track true queue occupancy for the eviction choice.

use std::collections::{HashMap, VecDeque};

use crate::driver::Row;
use crate::trace::{NormEvent, Op};

const FREQ_MAX: u8 = 3; // 2-bit counter, saturating
const S_FRACTION: f64 = 0.10; // small-queue target, fraction of capacity
/// Promote an object out of the small queue S into the main queue M only once its frequency has
/// reached this — i.e. it was accessed at least twice while in S. Matches the authors' reference
/// (libCacheSim `move-to-main-threshold = 2`): one-hit wonders are filtered to the ghost rather
/// than promoted, which is the scan-resistance the policy is known for.
const S_PROMOTE_MIN_FREQ: u8 = 2;

struct Entry {
    freq: u8,
    in_m: bool, // which FIFO the key currently belongs to
    seq: u64,   // epoch of the key's CURRENT live queue slot; any slot with an older seq is stale
}

/// An S3-FIFO cache over string keys, capacity `cap` items.
///
/// Queue slots are `(key, seq)`. A slot is LIVE iff the key still has an entry, that entry's
/// `in_m` names this queue, AND its `seq` equals the slot's seq. Every push mints a fresh seq and
/// records it on the entry, so each key has EXACTLY ONE live slot at a time. This epoch tag is
/// what makes lazy deletion sound: an invalidated-then-reinserted key cannot "resurrect" its old
/// (earlier-FIFO-position) slot, and `maybe_compact` provably keeps only the live slot per key —
/// so compaction never changes an eviction decision (the hit-rate is independent of when it runs).
/// The GHOST FIFO is seq-tagged the same way (`ghost`: key -> current epoch, `ghost_q`:
/// `(key, seq)`), so a re-ghosted key sits at its current age and the size trim drops the truly
/// oldest LIVE fingerprint — matching canonical S3-FIFO rather than a stale duplicate's position.
pub struct S3Fifo {
    cap: usize,
    s_target: usize,
    entries: HashMap<String, Entry>, // authoritative residency + freq + live-slot epoch
    s: VecDeque<(String, u64)>,      // (key, seq); may hold stale slots (skipped by seq mismatch)
    m: VecDeque<(String, u64)>,
    s_len: usize, // LIVE counts = #entries in each queue (each live key has one live slot)
    m_len: usize,
    ghost: HashMap<String, u64>,      // key -> current ghost epoch (older ghost_q slots are stale)
    ghost_q: VecDeque<(String, u64)>, // FIFO age order for bounding |G| (seq-tagged like s/m)
    next_seq: u64,
}

impl S3Fifo {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        S3Fifo {
            cap,
            s_target: ((cap as f64 * S_FRACTION) as usize).max(1),
            entries: HashMap::new(),
            s: VecDeque::new(),
            m: VecDeque::new(),
            s_len: 0,
            m_len: 0,
            ghost: HashMap::new(),
            ghost_q: VecDeque::new(),
            next_seq: 0,
        }
    }

    fn bump_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }

    /// Access `key`; returns `true` on a cache HIT (bumps its frequency, capped at 3).
    pub fn access(&mut self, key: &str) -> bool {
        if let Some(e) = self.entries.get_mut(key) {
            e.freq = (e.freq + 1).min(FREQ_MAX);
            return true;
        }
        self.insert(key);
        false
    }

    fn insert(&mut self, key: &str) {
        while self.s_len + self.m_len >= self.cap {
            self.evict_one();
        }
        let seq = self.bump_seq();
        if self.ghost.remove(key).is_some() {
            // seen before -> straight into the main queue
            self.entries.insert(key.to_string(), Entry { freq: 0, in_m: true, seq });
            self.m.push_back((key.to_string(), seq));
            self.m_len += 1;
        } else {
            self.entries.insert(key.to_string(), Entry { freq: 0, in_m: false, seq });
            self.s.push_back((key.to_string(), seq));
            self.s_len += 1;
        }
    }

    /// Remove exactly one object from the cache (promotions/second-chances don't free space, so
    /// this loops until a real removal or the cache is empty).
    fn evict_one(&mut self) {
        loop {
            let from_s = self.s_len > 0 && (self.s_len >= self.s_target || self.m_len == 0);
            let removed = if from_s { self.evict_s() } else { self.evict_m() };
            match removed {
                Some(true) => return,           // an object was evicted from the cache
                Some(false) => continue,        // promoted / given a second chance — keep going
                None => return,                 // that queue is empty of live keys
            }
        }
    }

    /// Pop the S head. Some(true)=evicted to ghost, Some(false)=promoted to M, None=S empty.
    fn evict_s(&mut self) -> Option<bool> {
        let key = self.pop_live(false)?;
        self.s_len -= 1;
        let freq = self.entries.get(&key).map(|e| e.freq).unwrap_or(0);
        if freq >= S_PROMOTE_MIN_FREQ {
            // accessed enough while in S -> promote to the main queue (keep the object)
            let seq = self.bump_seq();
            if let Some(e) = self.entries.get_mut(&key) {
                e.in_m = true;
                e.seq = seq; // its old S slot is now stale (seq no longer matches)
                // Reset the counter, as the paper's evictS does. The S counter has
                // already served its purpose (it decided the promotion), and carrying it
                // into M hands a 4x-accessed object three extra second-chance rotations
                // there, which is a divergence from the published algorithm and makes
                // this rung non-comparable to published S3-FIFO results.
                //
                // It is NOT a bias in a known direction, and an earlier version of this
                // comment claimed it was. A differential test against a transcription of
                // the paper's evictS/evictM over 2999 random traces had the no-reset
                // variant score HIGHER on 643 and LOWER on 663: a wash. The extra second
                // chances keep one object alive at the cost of evicting others that were
                // also live. Matching the paper is the reason to reset. "It flatters the
                // bake-off" is not, so do not restate it as one.
                e.freq = 0;
            }
            self.m.push_back((key, seq));
            self.m_len += 1;
            Some(false)
        } else {
            self.entries.remove(&key);
            self.ghost_add(&key);
            Some(true)
        }
    }

    /// Pop the M head. Some(true)=evicted, Some(false)=second-chance reinsert, None=M empty.
    fn evict_m(&mut self) -> Option<bool> {
        let key = self.pop_live(true)?;
        let freq = self.entries.get(&key).map(|e| e.freq).unwrap_or(0);
        if freq > 0 {
            let seq = self.bump_seq();
            if let Some(e) = self.entries.get_mut(&key) {
                e.freq -= 1;
                e.seq = seq; // the popped slot becomes stale; this fresh one is the live slot
            }
            self.m.push_back((key, seq)); // second chance (m_len unchanged — same live key)
            Some(false)
        } else {
            self.entries.remove(&key);
            self.m_len -= 1;
            Some(true)
        }
    }

    /// Pop slots off the front until a LIVE one for this queue is found, discarding stale slots.
    /// A slot is stale if the key was invalidated (no entry), promoted to the other queue
    /// (`in_m` mismatch), or superseded by a newer push (`seq` mismatch — the resurrection guard).
    fn pop_live(&mut self, in_m: bool) -> Option<String> {
        loop {
            let (key, seq) = if in_m { self.m.pop_front()? } else { self.s.pop_front()? };
            match self.entries.get(&key) {
                Some(e) if e.in_m == in_m && e.seq == seq => return Some(key),
                _ => continue,
            }
        }
    }

    fn ghost_add(&mut self, key: &str) {
        // Fresh epoch: any older ghost_q slot for this key (left by a prior admit/invalidate) is
        // now stale, so the fingerprint sits at its CURRENT age, and the trim below drops the
        // truly-oldest LIVE fingerprint — matching canonical S3-FIFO's ghost FIFO.
        let g = self.bump_seq();
        self.ghost.insert(key.to_string(), g);
        self.ghost_q.push_back((key.to_string(), g));
        while self.ghost.len() > self.cap {
            while let Some((k, seq)) = self.ghost_q.pop_front() {
                if self.ghost.get(&k) == Some(&seq) {
                    self.ghost.remove(&k); // drop the oldest live fingerprint
                    break;
                }
                // else stale (admitted/invalidated/superseded) -> keep popping
            }
        }
        self.compact_ghost_q(); // reclaim stale slots on the eviction path (no invalidate needed)
    }

    /// Drop `key` from the cache AND the ghost — a PUT/DELETE changes the object, so its cache
    /// copy and its "seen recently" fingerprint are both stale (a later GET is a cold miss). This
    /// matches ARC's `invalidate`, so the two policies treat post-write reappearance the same way
    /// (a fair bake-off). O(1): the now-stale queue/ghost slots are skipped/compacted later.
    pub fn invalidate(&mut self, key: &str) {
        if let Some(e) = self.entries.remove(key) {
            if e.in_m {
                self.m_len -= 1;
            } else {
                self.s_len -= 1;
            }
        }
        self.ghost.remove(key); // ghost_q slot goes stale -> reclaimed by maybe_compact
        self.maybe_compact();
    }

    /// Drop stale slots from the queues (and the ghost FIFO) once they have grown past a small
    /// multiple of the live count. Each `retain` keeps exactly the live slots — for `s`/`m` the ONE
    /// live slot per resident key (entry present, right queue, seq match), for `ghost_q` the keys
    /// still in the ghost set — in FIFO order, so the live pop sequence is identical with or without
    /// compaction. Bounds every FIFO to O(cap) instead of O(trace length) under invalidate churn.
    fn maybe_compact(&mut self) {
        {
            let Self { s, m, entries, s_len, m_len, .. } = self;
            if s.len() > 2 * *s_len + 8 {
                s.retain(|(k, seq)| matches!(entries.get(k), Some(e) if !e.in_m && e.seq == *seq));
            }
            if m.len() > 2 * *m_len + 8 {
                m.retain(|(k, seq)| matches!(entries.get(k), Some(e) if e.in_m && e.seq == *seq));
            }
        }
        self.compact_ghost_q();
    }

    /// Reclaim stale `ghost_q` slots (left by ghost->M admits and invalidations). Unlike `s`/`m`,
    /// which self-clean via `pop_live` during eviction, `ghost_q` is drained only by the size trim
    /// — dormant while |ghost| <= cap — so it needs its own opportunistic compaction, driven from
    /// `ghost_add` (the eviction path) and `maybe_compact` (the invalidate path).
    fn compact_ghost_q(&mut self) {
        let Self { ghost, ghost_q, .. } = self;
        if ghost_q.len() > 2 * ghost.len() + 8 {
            ghost_q.retain(|(k, seq)| ghost.get(k) == Some(seq));
        }
    }

    /// Resident (cached) item count — for invariant checks.
    #[must_use]
    pub fn resident(&self) -> usize {
        self.s_len + self.m_len
    }
}

/// Sweep S3-FIFO over a trace at each capacity, one demand row per cap (predictor `"s3fifo"`).
#[must_use]
pub fn eval_s3fifo_caps(trace: &[NormEvent], caps: &[u64]) -> Vec<Row> {
    let mut rows = Vec::with_capacity(caps.len());
    for &capu in caps {
        let mut c = S3Fifo::new(capu as usize);
        let (mut accesses, mut hits) = (0u64, 0u64);
        for ev in trace {
            match ev.op {
                Op::Put | Op::Delete => {
                    c.invalidate(&ev.object_id);
                    continue;
                }
                Op::Head | Op::Other => continue,
                Op::Get => {}
            }
            accesses += 1;
            if c.access(&ev.object_id) {
                hits += 1;
            }
        }
        let hr = if accesses > 0 { hits as f64 / accesses as f64 } else { 0.0 };
        rows.push(Row::demand("s3fifo", capu, hr)); // demand policy: net_savings == hit_rate
    }
    rows
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

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
    fn hr_of(cap: u64, ids: &[String]) -> f64 {
        let trace: Vec<NormEvent> = ids.iter().map(|s| get(s)).collect();
        eval_s3fifo_caps(&trace, &[cap])[0].hit_rate
    }
    fn lru_hr(cap: usize, ids: &[String]) -> f64 {
        let mut order: VecDeque<String> = VecDeque::new();
        let mut set: HashSet<String> = HashSet::new();
        let (mut acc, mut hits) = (0u64, 0u64);
        for id in ids {
            acc += 1;
            if set.contains(id) {
                hits += 1;
                order.retain(|k| k != id);
                order.push_back(id.clone());
            } else {
                if set.len() >= cap {
                    if let Some(ev) = order.pop_front() {
                        set.remove(&ev);
                    }
                }
                set.insert(id.clone());
                order.push_back(id.clone());
            }
        }
        hits as f64 / acc as f64
    }

    #[test]
    fn immediate_reaccess_hits_and_capacity_holds() {
        let mut c = S3Fifo::new(4);
        assert!(!c.access("a"));
        assert!(c.access("a"));
        for k in ["b", "c", "d", "e", "f", "g"] {
            c.access(k);
            assert!(c.resident() <= 4, "resident {} > cap", c.resident());
        }
    }

    #[test]
    fn all_unique_zero_hits_all_repeat_full_hits() {
        let uniq: Vec<String> = (0..10).map(|i| format!("u{i}")).collect();
        assert_eq!(hr_of(4, &uniq), 0.0);
        let rep: Vec<String> = std::iter::repeat_n("x".to_string(), 6).collect();
        assert!((hr_of(4, &rep) - 5.0 / 6.0).abs() < 1e-9);
    }

    #[test]
    fn one_shot_scan_does_not_evict_a_reused_hot_set() {
        // S3-FIFO's raison d'être: a hot set that has built frequency survives a flood of unique
        // one-shot keys, because one-shots leave S straight to the ghost and never reach M.
        let mut ids: Vec<String> = Vec::new();
        for _ in 0..3 {
            ids.push("h0".into());
            ids.push("h1".into()); // build frequency
        }
        for s in 0..30 {
            ids.push(format!("s{s}")); // scan >> cap
        }
        ids.push("h0".into());
        ids.push("h1".into()); // post-scan re-access

        let s3 = hr_of(8, &ids);
        let lru = lru_hr(8, &ids);
        assert!(s3 > lru, "S3-FIFO {s3} did not beat LRU {lru} under scan pollution");
        assert!(s3 > 0.15, "S3-FIFO failed to retain the hot set: {s3}");
    }

    #[test]
    fn promotion_out_of_s_resets_the_frequency_counter() {
        // The paper's evictS clears freq on promotion. The S counter has already done its
        // job (it decided the promotion), and carrying a saturated counter into M buys
        // FREQ_MAX extra second-chance rotations there — a divergence from the published
        // algorithm, which is the whole reason to reset. It does NOT reliably inflate the
        // retention numbers: measured over 2999 random traces against a transcription of
        // the paper, the no-reset variant scored higher on 643 and lower on 663.
        let mut c = S3Fifo::new(4);
        for _ in 0..4 {
            c.access("hot"); // 1 miss + 3 hits -> freq saturates in S
        }
        assert_eq!(c.entries["hot"].freq, FREQ_MAX, "freq should saturate while in S");
        for k in ["b", "c", "d", "e"] {
            c.access(k); // fill to cap, then force an eviction round
        }
        let e = &c.entries["hot"];
        assert!(e.in_m, "a freq>=2 object must be promoted to M, not ghosted");
        assert_eq!(e.freq, 0, "promotion must reset freq to 0 (paper's evictS)");
    }

    #[test]
    fn put_delete_invalidate_in_the_sweep() {
        let trace = vec![get("x"), get("x"), NormEvent { op: Op::Put, ..get("x") }, get("x")];
        let hr = eval_s3fifo_caps(&trace, &[4])[0].hit_rate;
        assert!((hr - 1.0 / 3.0).abs() < 1e-9, "hr={hr} (PUT must invalidate)");
    }

    #[test]
    fn survives_a_long_churny_stream_within_capacity() {
        let mut c = S3Fifo::new(4);
        for i in 0..2000 {
            c.access(&format!("k{}", i % 25));
            if i % 7 == 0 {
                c.invalidate(&format!("k{}", i % 25));
            }
            assert!(c.resident() <= 4);
            // the core bookkeeping invariant: live counters track the entries map exactly.
            assert_eq!(c.resident(), c.entries.len());
        }
    }

    #[test]
    fn invalidate_churn_stays_bounded() {
        // Repeated get+put of one key on a big cache never fills it, so eviction (the usual GC)
        // never runs. Without compaction the stale-slot deque would grow O(N); it must stay small.
        let mut c = S3Fifo::new(1000);
        for _ in 0..10_000 {
            c.access("hot");
            c.invalidate("hot");
        }
        assert!(c.s.len() < 64, "S deque grew unbounded from stale slots: {}", c.s.len());
        assert_eq!(c.resident(), c.entries.len(), "counter invariant broken under churn");
    }

    #[test]
    fn compaction_is_transparent_regression() {
        // Round-2 differential counterexample (cap 2): an invalidate+reinsert used to "resurrect"
        // the key's old FIFO slot, and whether maybe_compact had purged it changed the hit-rate.
        // With seq-tagged slots the result is the clean value (which here ties OPT at 1 hit).
        let seq = [
            ("g", "k0"), ("d", "k0"), ("g", "k1"), ("d", "k1"), ("g", "k2"), ("d", "k2"),
            ("g", "k1"), ("g", "k2"), ("d", "k2"), ("g", "k2"), ("d", "k1"), ("d", "k2"),
            ("g", "k1"), ("d", "k1"), ("g", "k2"), ("g", "k1"), ("d", "k1"), ("d", "k2"),
            ("g", "k2"), ("g", "k1"), ("g", "k0"), ("g", "k2"),
        ];
        let trace: Vec<NormEvent> = seq
            .iter()
            .map(|&(op, k)| if op == "d" { NormEvent { op: Op::Delete, ..get(k) } } else { get(k) })
            .collect();
        let hr = eval_s3fifo_caps(&trace, &[2])[0].hit_rate;
        // Canonical S3-FIFO gets 0 hits here (at the crunch its FIFO evicts k2 — the key OPT would
        // keep — so the final GET k2 misses; 0 <= opt's 1/13). The old lazy-deletion could
        // "resurrect" a stale slot and accidentally score 1 hit, and whether maybe_compact had
        // purged that slot flipped the result. Seq-tagged slots give this deterministic 0
        // regardless of compaction timing.
        assert_eq!(hr, 0.0, "resurrection/compaction-timing regression: hr={hr} (expected 0)");
    }

    #[test]
    fn ghost_fifo_evicts_oldest_not_a_reghosted_stale_slot() {
        // Round-4 gate GET-only counterexample (cap 3). A re-ghosted key used to be evicted from
        // the ghost at its OLD FIFO position (a stale duplicate ghost_q slot), so the lazy policy
        // diverged from canonical S3-FIFO. Seq-tagged ghost slots make the trim drop the truly
        // OLDEST live fingerprint, so the final k1 is a ghost-hit->M admit, i.e. a HIT here.
        let ids = [
            "k4", "k1", "k6", "k6", "k6", "k7", "k4", "k2", "k1", "k2", "k5", "k1", "k0", "k1",
            "k5", "k1",
        ];
        let mut c = S3Fifo::new(3);
        let mut last_hit = false;
        for k in ids {
            last_hit = c.access(k);
        }
        assert!(last_hit, "final k1 must hit — ghost FIFO must evict the oldest live fingerprint");
    }

    #[test]
    fn ghost_q_stays_bounded_under_admits() {
        // A working set slightly larger than the cache keeps ghosting keys and re-admitting them
        // from the ghost (ghost->M), each admit leaving a stale ghost_q slot while |ghost| stays
        // <= cap so the size trim never fires. maybe_compact's ghost_q pass must keep it bounded.
        let mut c = S3Fifo::new(10);
        for i in 0..5000 {
            c.access(&format!("k{}", i % 15)); // W=15 > cap=10
        }
        assert!(c.ghost_q.len() < 200, "ghost_q grew unbounded: {}", c.ghost_q.len());
        assert!(c.ghost.len() <= 10, "ghost set exceeds cap: {}", c.ghost.len());
        assert_eq!(c.resident(), c.entries.len());
    }

    #[test]
    fn edge_cases_do_not_panic() {
        assert_eq!(eval_s3fifo_caps(&[], &[4])[0].hit_rate, 0.0);
        let ids: Vec<String> = ["a", "a", "b", "a", "c", "a"].iter().map(|s| s.to_string()).collect();
        for &cap in &[0u64, 1, 2, 100] {
            let hr = hr_of(cap, &ids);
            assert!((0.0..=1.0).contains(&hr), "cap {cap}: hr {hr} out of range");
        }
        let writes = vec![NormEvent { op: Op::Put, ..get("x") }, NormEvent { op: Op::Head, ..get("y") }];
        assert_eq!(eval_s3fifo_caps(&writes, &[4])[0].hit_rate, 0.0);
    }
}
