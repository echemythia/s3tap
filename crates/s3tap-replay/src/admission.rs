//! Frequency-sketch admission control (TinyLFU-style).
//!
//! Every current predictor *prefetches* — pulls objects INTO the cache. This is
//! the opposite lever: it decides, on a demand miss with a full cache, whether an
//! object is worth admitting at all, versus bypassing it (serving the miss but
//! not caching). It targets the pathology the prefetch ladder can't touch:
//! one-shot objects (accessed once, never reused) that, under plain LRU, pollute
//! the cache and evict genuinely reusable entries. On the observed traces ~47% of
//! some workloads' accesses are one-shot, and the LRU→OPT gap there is precisely
//! the room a good admission policy can recover.
//!
//! The decision (canonical TinyLFU): admit the incoming object only if its
//! estimated frequency exceeds that of the LRU eviction victim. One-shots
//! (frequency 1) never beat a resident, so they bypass and never pollute.

use std::hash::{Hash, Hasher};

/// A small Count-Min Sketch with periodic aging — a bounded, deterministic
/// frequency estimator. Bounded memory (`depth * width` u16 counters); counts are
/// halved when the running sample size crosses `sample_max`, so it tracks
/// *recent* frequency (a hot-then-cold object decays) rather than lifetime totals.
pub struct FreqSketch {
    width: usize,
    rows: Vec<Vec<u16>>,
    seeds: [u64; DEPTH],
    sample: u64,
    sample_max: u64,
}

const DEPTH: usize = 4;

impl FreqSketch {
    /// `width` counters per row (rounded to the given value), aging every
    /// `sample_max` increments.
    pub fn new(width: usize, sample_max: u64) -> Self {
        let width = width.max(1);
        FreqSketch {
            width,
            rows: vec![vec![0u16; width]; DEPTH],
            // Fixed seeds -> deterministic across runs (no RandomState).
            seeds: [0x9E37_79B9, 0x85EB_CA6B, 0xC2B2_AE35, 0x27D4_EB2F],
            sample: 0,
            sample_max,
        }
    }

    fn idx(&self, seed: u64, s: &str) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h);
        s.hash(&mut h);
        (h.finish() as usize) % self.width
    }

    /// Record one access to `s`, aging (halving all counters) when the sample
    /// budget is exhausted.
    pub fn incr(&mut self, s: &str) {
        for r in 0..DEPTH {
            let i = self.idx(self.seeds[r], s);
            let c = &mut self.rows[r][i];
            *c = c.saturating_add(1);
        }
        self.sample += 1;
        if self.sample >= self.sample_max {
            for row in &mut self.rows {
                for c in row.iter_mut() {
                    *c >>= 1;
                }
            }
            self.sample >>= 1;
        }
    }

    /// Estimated frequency of `s` (the min across rows — CMS never underestimates).
    pub fn est(&self, s: &str) -> u16 {
        (0..DEPTH)
            .map(|r| self.rows[r][self.idx(self.seeds[r], s)])
            .min()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequent_beats_rare_and_is_deterministic() {
        let mut a = FreqSketch::new(1024, 1_000_000);
        let mut b = FreqSketch::new(1024, 1_000_000);
        for _ in 0..100 {
            a.incr("hot");
            b.incr("hot");
        }
        a.incr("cold");
        b.incr("cold");
        assert!(a.est("hot") > a.est("cold"));
        // CMS never underestimates, so est("hot") >= its true count of 100.
        assert!(a.est("hot") >= 100, "est(hot)={}", a.est("hot"));
        // Deterministic: identical inputs -> identical estimates.
        assert_eq!(a.est("hot"), b.est("hot"));
        assert_eq!(a.est("cold"), b.est("cold"));
    }

    #[test]
    fn aging_halves_counts() {
        // sample_max small so aging triggers; hot count should not grow unbounded.
        let mut s = FreqSketch::new(64, 8);
        for _ in 0..100 {
            s.incr("x");
        }
        assert!(s.est("x") < 100, "aging should keep the count bounded: {}", s.est("x"));
    }
}
