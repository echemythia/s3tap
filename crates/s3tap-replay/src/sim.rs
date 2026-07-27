use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `prefetch_first_use` is true exactly once: the first real hit on an entry
    /// that arrived via prefetch (this is how we count prefetch *usefulness*).
    Hit { prefetch_first_use: bool },
    Miss,
}

struct Entry {
    seq: u64,
    size: u64,
    prefetched_unused: bool,
}

/// LRU cache simulator. Holds no object bytes — models residency only.
///
/// Capacity is in abstract units. The count-mode callers (`driver.rs` sweep,
/// admission, belady) pass size 1, so capacity == object count. The byte-mode
/// caller (`bytes.rs::sweep_bytes`) passes real `NormEvent.size` and caps in
/// bytes; `insert`/`invalidate`/`evict_to_fit` account `used` in bytes and are
/// covered by tests (`evicts_by_byte_size_and_saturates`, plus the `bytes`
/// module). `access` RE-SIZES a resident entry to the size the current access
/// reports, because an object's observed size genuinely does change between
/// accesses once each GET is credited at its own `Content-Length` rather than a
/// per-object maximum. Leaving the first-insert size in place made the two halves
/// of the byte model disagree: `bytes.rs` credited a 1 GiB hit while `used` still
/// charged the 1 KiB the object measured on its first touch, so a cache could
/// report serving far more bytes than it could physically hold. One residual
/// Phase-1 caveat remains, and it bites ONLY a prefetching byte cache (not
/// today's demand-only byte path): `insert` freezes a PREFETCHED object's size at
/// its insert value, which must be revisited before any byte-capacity *prefetch*
/// rung is added.
pub struct Sim {
    cap: u64,
    used: u64,
    clock: u64,
    by_id: HashMap<String, Entry>,
    order: BTreeMap<u64, String>, // seq -> id, for O(log n) LRU eviction
}

impl Sim {
    pub fn new(cap: u64) -> Self {
        Sim { cap, used: 0, clock: 0, by_id: HashMap::new(), order: BTreeMap::new() }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    /// Number of resident objects (for admission control: is the cache full?).
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Resident bytes currently held (== object count in count-mode, real bytes
    /// in byte-mode). Lets a byte sweep track the cache's peak physical footprint.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// The object that would be evicted next (the LRU tail: lowest seq). Lets an
    /// admission policy compare an incoming object against the eviction victim.
    pub fn lru_victim(&self) -> Option<&str> {
        self.order.iter().next().map(|(_, id)| id.as_str())
    }

    fn touch(&mut self, id: &str) {
        self.clock += 1;
        let new_seq = self.clock;
        if let Some(e) = self.by_id.get_mut(id) {
            self.order.remove(&e.seq);
            e.seq = new_seq;
            self.order.insert(new_seq, id.to_string());
        }
    }

    pub fn access(&mut self, id: &str, size: u64) -> Access {
        let (first_use, was) = match self.by_id.get_mut(id) {
            None => return Access::Miss,
            Some(e) => {
                let f = e.prefetched_unused;
                e.prefetched_unused = false;
                let was = e.size;
                // The bytes this access actually moved are what the caller credits as a hit,
                // so they must also be what capacity charges. Count-mode callers always pass
                // 1 and never take this branch.
                e.size = size;
                (f, was)
            }
        };
        // TOUCH BEFORE EVICTING. `evict_to_fit` takes the lowest seq, and until `touch` runs
        // this entry still carries the seq it had BEFORE the hit — so an entry that was the
        // LRU victim and then grew would evict ITSELF, which no LRU does: a hit makes an
        // object the most recently used, and the bytes it needs come from something older.
        self.touch(id);
        if was != size {
            self.used = self.used.saturating_sub(was).saturating_add(size);
            // Growing a resident object can push the cache over cap — a real one would evict
            // to make room, and so must the model, or `used` drifts above `cap` unboundedly.
            self.evict_to_fit();
        }
        Access::Hit { prefetch_first_use: first_use }
    }

    pub fn insert(&mut self, id: &str, size: u64, prefetched: bool) {
        if self.by_id.contains_key(id) {
            self.touch(id);
            return;
        }
        self.clock += 1;
        let seq = self.clock;
        self.by_id.insert(
            id.to_string(),
            Entry { seq, size, prefetched_unused: prefetched },
        );
        self.order.insert(seq, id.to_string());
        // Saturating: `size` comes from a NormEvent, which the CLI accepts
        // unvalidated — a crafted huge size must not panic (debug) or wrap
        // (release) the accounting.
        self.used = self.used.saturating_add(size);
        self.evict_to_fit();
    }

    pub fn invalidate(&mut self, id: &str) {
        if let Some(e) = self.by_id.remove(id) {
            self.order.remove(&e.seq);
            self.used = self.used.saturating_sub(e.size);
        }
    }

    fn evict_to_fit(&mut self) {
        while self.used > self.cap {
            let Some((&seq, victim)) = self.order.iter().next() else { break };
            let victim = victim.clone();
            self.order.remove(&seq);
            if let Some(e) = self.by_id.remove(&victim) {
                self.used = self.used.saturating_sub(e.size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hit_recharges_capacity_at_the_size_the_access_actually_moved() {
        // Once each GET is credited at its OWN Content-Length (rather than a per-object
        // maximum), the same key legitimately arrives at different sizes. If the resident
        // entry kept its first-insert size, `bytes.rs` would credit a 1 GiB hit while `used`
        // still charged 1 KiB, so the modelled cache reports serving bytes it could not hold.
        let mut s = Sim::new(4096);
        s.insert("k", 1_024, false);
        assert_eq!(s.used(), 1_024);
        // Same key, now much larger: the hit is real, and capacity must charge the new size.
        assert!(matches!(s.access("k", 4_096), Access::Hit { .. }));
        assert_eq!(s.used(), 4_096, "capacity charges what the hit credited");
        // And shrinking gives the bytes back rather than stranding them.
        assert!(matches!(s.access("k", 512), Access::Hit { .. }));
        assert_eq!(s.used(), 512);
        // Growth past the cap evicts rather than letting `used` drift above it — and the
        // entry that GREW must not be the victim. "a" is the LRU here, so evicting to fit
        // before marking it most-recently-used would evict the very object just hit. A real
        // LRU takes the bytes from something older instead. Asserting only `used <= cap`
        // does NOT catch that: self-eviction satisfies the cap too.
        let mut s = Sim::new(1_000);
        s.insert("a", 400, false);
        s.insert("b", 400, false); // "a" is now the LRU
        assert!(matches!(s.access("a", 900), Access::Hit { .. }));
        assert!(s.used() <= 1_000, "used {} must stay within cap", s.used());
        assert!(s.contains("a"), "the object just hit must not evict itself");
        assert!(!s.contains("b"), "the older object is what makes room");
        assert_eq!(s.used(), 900);
    }

    #[test]
    fn evicts_by_byte_size_and_saturates() {
        // Byte-capacity eviction: cap 5, two size-3 objects -> first is evicted.
        let mut s = Sim::new(5);
        s.insert("a", 3, false);
        s.insert("b", 3, false); // used=6 > 5 -> evict LRU (a)
        assert_eq!(s.access("a", 3), Access::Miss);
        assert!(matches!(s.access("b", 3), Access::Hit { .. }));

        // Saturating accounting: a crafted huge size must not panic or corrupt
        // the cache — the oversized object self-evicts and the cache stays usable.
        let mut t = Sim::new(10);
        t.insert("x", 1, false);
        t.insert("big", u64::MAX, false);
        t.insert("y", 1, false);
        assert!(matches!(t.access("y", 1), Access::Hit { .. }));
    }

    #[test]
    fn miss_then_hit_after_insert() {
        let mut s = Sim::new(10);
        assert_eq!(s.access("a", 1), Access::Miss);
        s.insert("a", 1, false);
        assert_eq!(s.access("a", 1), Access::Hit { prefetch_first_use: false });
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut s = Sim::new(2); // capacity 2 units
        s.insert("a", 1, false);
        s.insert("b", 1, false);
        s.access("a", 1);        // a now most-recent
        s.insert("c", 1, false); // evicts b (LRU)
        assert_eq!(s.access("b", 1), Access::Miss);
        assert_eq!(s.access("a", 1), Access::Hit { prefetch_first_use: false });
        assert_eq!(s.access("c", 1), Access::Hit { prefetch_first_use: false });
    }

    #[test]
    fn prefetch_first_use_is_reported_once() {
        let mut s = Sim::new(10);
        s.insert("p", 1, true); // prefetched, not yet used
        assert_eq!(s.access("p", 1), Access::Hit { prefetch_first_use: true });
        assert_eq!(s.access("p", 1), Access::Hit { prefetch_first_use: false });
    }

    #[test]
    fn invalidate_removes_entry() {
        let mut s = Sim::new(10);
        s.insert("a", 1, false);
        s.invalidate("a");
        assert_eq!(s.access("a", 1), Access::Miss);
    }
}
