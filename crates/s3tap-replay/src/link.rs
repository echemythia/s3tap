//! Link-contention replay: what the request-count and instant-fetch models hide.
//!
//! Every origin fetch — demand miss or prefetch — must cross a finite access
//! link. Its latency is `RTT + chunk/BW` PLUS queueing behind whatever else the
//! link is carrying, and that last term is what the rest of the harness ignores:
//! a wasted prefetch there costs one request fee; here it also *delays the
//! demand traffic behind it*. Bandwidth is the regime divider the fetch-time
//! sweep only approximates: EC2-to-S3 has 10-50 Gbps (speculation is nearly
//! free), a WAN client has ~1 Gbps (an 8 MiB chunk is 64 ms of serialization,
//! and speculative bytes queue in front of demand bytes).
//!
//! Model (deterministic, open-loop):
//! - One access link of `bw_bps`; each fetch occupies it for `chunk/BW` after an
//!   `rtt_ns` request delay. Transfers serialize per discipline:
//!   - `Fifo`: all fetches share one queue — prefetch CAN delay demand.
//!   - `DemandPriority`: demand fetches queue only behind demand (idealized
//!     preemptive priority); prefetches queue behind everything. Preemption
//!     REORDERS work, it never creates bandwidth: both disciplines occupy the
//!     link for exactly `transfer` per fetch, so a demand fetch that jumps the
//!     queue still pushes every queued prefetch back by one transfer.
//! - The cache stores `ready_at` per entry: an access to an in-flight chunk
//!   waits the remainder, a resident-and-ready chunk costs zero.
//! - Replay is OPEN-LOOP: arrivals follow the trace clock and do not slow down
//!   when latency grows (real clients would back-pressure), and the IBM traces
//!   are server-side aggregates of many clients pushed through one modelled
//!   link — results are illustrative of contention effects, not absolute.

use std::collections::{BTreeMap, HashMap};

use crate::predict::{MarkovPredictor, Predictor};
use crate::trace::{NormEvent, Op};

#[derive(Clone, Copy)]
pub struct LinkCfg {
    pub rtt_ns: u64,
    pub bw_bps: u64,
    pub chunk_bytes: u64,
}

impl LinkCfg {
    /// Time the link is occupied by one chunk transfer.
    pub fn transfer_ns(&self) -> u64 {
        // bits * ns_per_sec / bits_per_sec, in u128 to avoid overflow.
        ((self.chunk_bytes as u128 * 8 * 1_000_000_000) / self.bw_bps.max(1) as u128) as u64
    }

    /// Uncontended fetch latency (RTT + transfer) — the `L` a prefetch must lead.
    pub fn fetch_ns(&self) -> u64 {
        self.rtt_ns.saturating_add(self.transfer_ns())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Discipline {
    Fifo,
    DemandPriority,
}

pub enum LinkPolicy {
    /// No cache: every access is a demand fetch through the link.
    NoCache,
    /// Plain LRU, demand fetches only.
    Demand,
    /// LRU + the lead-gated prefetch overlay, under the given link discipline.
    LeadGated(Discipline),
}

/// Single-server link queue with an optional demand-priority lane.
struct Link {
    demand_free: u64, // when the demand lane's queue drains
    any_free: u64,    // when the link drains including prefetch transfers
    transfer: u64,
    rtt: u64,
}

impl Link {
    fn new(cfg: &LinkCfg) -> Self {
        Link { demand_free: 0, any_free: 0, transfer: cfg.transfer_ns(), rtt: cfg.rtt_ns }
    }

    /// Issue a DEMAND fetch at `now`; returns its completion time, plus a
    /// `Some((cutoff, delta))` when this fetch cut in front of already-queued
    /// prefetch work: the caller must push every cached-but-not-yet-landed
    /// PREFETCH entry with `ready_at > cutoff` forward by `delta`. Under
    /// DemandPriority the demand lane ignores queued prefetch transfers
    /// (idealized preemption); under Fifo it queues behind everything, so a
    /// Fifo fetch's `start` is always >= every previously scheduled
    /// completion and nothing is ever left to push back (see
    /// `demand_priority_is_work_conserving`/the doc module comment).
    fn fetch_demand(&mut self, now: u64, disc: Discipline) -> (u64, Option<(u64, u64)>) {
        let queue_from = match disc {
            Discipline::Fifo => self.any_free,
            Discipline::DemandPriority => self.demand_free,
        };
        let start = now.saturating_add(self.rtt).max(queue_from);
        // Saturating: `now` is a trace timestamp the CLI accepts unvalidated (and
        // `from_ibm_line` already saturates ts to u64::MAX), so a crafted huge
        // value must not panic (debug) or wrap (release) the link clock.
        let done = start.saturating_add(self.transfer);
        self.demand_free = self.demand_free.max(done);
        let any_free_before = self.any_free;
        // The link is WORK-CONSERVING: priority reorders transfers, it does not
        // create bandwidth. So a demand transfer occupies the shared cursor for
        // `transfer` even when it jumped the prefetch queue — charging only
        // `max(done)` here would leave `any_free` untouched whenever prefetches
        // were already queued past `done`, letting the modelled link deliver up
        // to 2x its configured bandwidth and never pushing prefetches back.
        // Advancing from `max(any_free, now+rtt)` makes `any_free` evolve
        // identically under both disciplines (same expression as
        // `fetch_prefetch`), so total occupancy matches FIFO exactly.
        self.any_free =
            self.any_free.max(now.saturating_add(self.rtt)).saturating_add(self.transfer).max(done);
        // This fetch actually cut in front of scheduled prefetch work only when
        // there WAS backlog past its own start (`any_free_before > start`):
        // every entry the cache is holding was itself scheduled by this same
        // sequential model, so its `ready_at` sits at a slot boundary derived
        // from a past `any_free` — an entry with `ready_at > start` is exactly
        // one this demand jumped ahead of, and it now lands one whole
        // `transfer` later. (Under Fifo, `start >= any_free_before` always, so
        // this is never Some there — nothing to push back.)
        let push_back = (any_free_before > start).then_some((start, self.transfer));
        (done, push_back)
    }

    /// Issue a PREFETCH at `now`; always queues behind ALL traffic.
    fn fetch_prefetch(&mut self, now: u64) -> u64 {
        let start = now.saturating_add(self.rtt).max(self.any_free);
        let done = start.saturating_add(self.transfer); // saturating: see fetch_demand
        self.any_free = self.any_free.max(done);
        done
    }
}

/// Count-capacity LRU whose entries carry `ready_at` (the fetch completion
/// time), so an access during the flight waits only the remainder.
struct ReadyLru {
    cap: usize,
    clock: u64,
    // id -> (seq, ready_at, is_prefetch). `is_prefetch` marks an entry inserted by
    // `fetch_prefetch` rather than a demand miss: only those can still be pushed
    // back by a later demand fetch that preempts them (see `push_back_prefetches`).
    by_id: HashMap<String, (u64, u64, bool)>,
    order: BTreeMap<u64, String>,
}

impl ReadyLru {
    fn new(cap: u64) -> Self {
        ReadyLru { cap: cap.max(1) as usize, clock: 0, by_id: HashMap::new(), order: BTreeMap::new() }
    }
    fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }
    /// Touch to MRU; returns `ready_at` if resident.
    fn touch(&mut self, id: &str) -> Option<u64> {
        let (seq, ready, is_pf) = *self.by_id.get(id)?;
        self.order.remove(&seq);
        self.clock += 1;
        self.by_id.insert(id.to_string(), (self.clock, ready, is_pf));
        self.order.insert(self.clock, id.to_string());
        Some(ready)
    }
    fn insert(&mut self, id: &str, ready_at: u64, is_prefetch: bool) {
        if self.touch(id).is_some() {
            return;
        }
        self.clock += 1;
        self.by_id.insert(id.to_string(), (self.clock, ready_at, is_prefetch));
        self.order.insert(self.clock, id.to_string());
        if self.by_id.len() > self.cap {
            if let Some((&seq, _)) = self.order.iter().next() {
                if let Some(victim) = self.order.remove(&seq) {
                    self.by_id.remove(&victim);
                }
            }
        }
    }
    fn invalidate(&mut self, id: &str) {
        if let Some((seq, _, _)) = self.by_id.remove(id) {
            self.order.remove(&seq);
        }
    }
    /// A demand fetch just cut in front of link work scheduled at or after
    /// `cutoff`: every cached PREFETCH entry still scheduled to land after that
    /// point (`ready_at > cutoff`) now lands `delta` later, matching what the
    /// `Link`'s own `any_free` cursor already accounts for in aggregate. A
    /// demand-inserted entry is never touched here: demand-vs-demand ordering
    /// is unaffected by priority (see `Link::fetch_demand`).
    fn push_back_prefetches(&mut self, cutoff: u64, delta: u64) {
        for (_seq, ready, is_pf) in self.by_id.values_mut() {
            if *is_pf && *ready > cutoff {
                *ready = ready.saturating_add(delta);
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct ContendedReport {
    pub accesses: u64,
    /// Sum of demand-visible wait (ns): 0 for ready hits, remainder for
    /// in-flight hits, full queued fetch latency for misses.
    pub total_wait_ns: u128,
    pub zero_wait: u64,
    pub pf_issued: u64,
    pub demand_fetches: u64,
}

impl ContendedReport {
    pub fn mean_wait_ms(&self) -> f64 {
        if self.accesses == 0 { 0.0 }
        else { self.total_wait_ns as f64 / self.accesses as f64 / 1e6 }
    }
    pub fn zero_wait_frac(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.zero_wait as f64 / self.accesses as f64 }
    }
    pub fn pf_per_access(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.pf_issued as f64 / self.accesses as f64 }
    }
}

/// Replay `trace` through a capacity-`cap` cache and a finite link. The
/// lead-gated overlay mirrors `hybrid::run_lead_gated` (robust EWMA, joint-
/// confidence chain), with `L = cfg.fetch_ns()` as the lead target.
pub fn run_contended(
    trace: &[NormEvent],
    cap: u64,
    cfg: &LinkCfg,
    policy: &LinkPolicy,
    conf: f64,
    max_depth: usize,
) -> ContendedReport {
    let mut link = Link::new(cfg);
    let mut cache = ReadyLru::new(cap);
    let mut mk = MarkovPredictor::new(1);
    let mut r = ContendedReport::default();
    let l = cfg.fetch_ns().max(1) as f64;
    let mut ewma_delta = l;
    let mut last_ts: Option<u64> = None;
    let disc = match policy {
        LinkPolicy::LeadGated(d) => *d,
        _ => Discipline::Fifo, // no prefetch traffic -> disciplines coincide
    };

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

        match policy {
            LinkPolicy::NoCache => {
                let (done, push_back) = link.fetch_demand(now, disc);
                if let Some((cutoff, delta)) = push_back {
                    cache.push_back_prefetches(cutoff, delta);
                }
                r.demand_fetches += 1;
                r.total_wait_ns += (done - now) as u128;
            }
            LinkPolicy::Demand | LinkPolicy::LeadGated(_) => {
                match cache.touch(&ev.object_id) {
                    Some(ready) if ready <= now => {
                        r.zero_wait += 1; // resident and landed -> free
                    }
                    Some(ready) => {
                        // In flight (demand- or prefetch-initiated): wait the rest.
                        r.total_wait_ns += (ready - now) as u128;
                    }
                    None => {
                        let (done, push_back) = link.fetch_demand(now, disc);
                        if let Some((cutoff, delta)) = push_back {
                            cache.push_back_prefetches(cutoff, delta);
                        }
                        r.demand_fetches += 1;
                        r.total_wait_ns += (done - now) as u128;
                        cache.insert(&ev.object_id, done, false);
                    }
                }
            }
        }

        if let LinkPolicy::LeadGated(_) = policy {
            if let Some(lt) = last_ts {
                let gap = now.saturating_sub(lt) as f64;
                // Same robust update as run_lead_gated: skip intra-batch zero
                // gaps, clamp idle outliers.
                if gap > 0.0 {
                    ewma_delta = 0.95 * ewma_delta + 0.05 * gap.min(16.0 * l);
                }
            }
            last_ts = Some(now);
            mk.observe(ev);
            let k = ((l / ewma_delta.max(1.0)).ceil() as usize).clamp(1, max_depth.max(1));
            if let Some(pid) = mk.chain_ahead(&ev.object_id, k, conf) {
                if pid != ev.object_id && !cache.contains(&pid) {
                    let done = link.fetch_prefetch(now);
                    r.pf_issued += 1;
                    cache.insert(&pid, done, true);
                }
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(id: &str, ts: u64) -> NormEvent {
        NormEvent { ts_ns: ts, op: Op::Get, object_id: id.into(), range: None,
                    size: Some(1), version: None, status: Some(200) }
    }

    /// 1 Gbps, 1 MiB chunks -> ~8.4 ms transfer; 1 ms RTT.
    fn thin() -> LinkCfg {
        LinkCfg { rtt_ns: 1_000_000, bw_bps: 1_000_000_000, chunk_bytes: 1 << 20 }
    }

    #[test]
    fn transfers_serialize_on_the_link() {
        let cfg = thin();
        let t = cfg.transfer_ns();
        let mut link = Link::new(&cfg);
        // Two demand fetches at the same instant: the second queues behind the
        // first and completes one transfer later.
        let (d1, pb1) = link.fetch_demand(0, Discipline::Fifo);
        let (d2, pb2) = link.fetch_demand(0, Discipline::Fifo);
        assert_eq!(d1, cfg.rtt_ns + t);
        assert_eq!(d2, d1 + t);
        assert!(pb1.is_none() && pb2.is_none(), "no prefetch backlog exists on this trace");
    }

    /// Priority reorders link work; it must not manufacture bandwidth. For the
    /// same multiset of transfers the link drains at the same instant under
    /// either discipline — otherwise `DemandPriority` would deliver up to 2x the
    /// configured BW and understate every reported wait.
    #[test]
    fn demand_priority_is_work_conserving() {
        let cfg = thin();
        let t = cfg.transfer_ns();
        // 10 prefetches then 10 demand fetches, all offered at t=0.
        let issue = |disc: Discipline| {
            let mut link = Link::new(&cfg);
            for _ in 0..10 {
                link.fetch_prefetch(0);
            }
            for _ in 0..10 {
                let _ = link.fetch_demand(0, disc);
            }
            link.any_free
        };
        let fifo = issue(Discipline::Fifo);
        let prio = issue(Discipline::DemandPriority);
        assert_eq!(fifo, cfg.rtt_ns + 20 * t, "fifo must serialize all 20 transfers");
        assert_eq!(prio, fifo, "priority delivered {prio} vs fifo {fifo} — link work not conserved");
    }

    /// The point of preemption: the demand fetch lands early (it does not wait
    /// behind the queued prefetch) while the prefetch is pushed back by exactly
    /// one transfer, so the two together still take two transfer-times.
    #[test]
    fn demand_preempts_but_still_charges_the_link() {
        let cfg = thin();
        let t = cfg.transfer_ns();
        let mut link = Link::new(&cfg);
        let pf = link.fetch_prefetch(0);
        let (d, push_back) = link.fetch_demand(0, Discipline::DemandPriority);
        assert_eq!(d, cfg.rtt_ns + t, "demand must not queue behind a prefetch");
        assert_eq!(pf, cfg.rtt_ns + t, "the prefetch was already in flight when the demand arrived");
        // The demand DID cut in front of the still-queued prefetch (its old
        // ready_at, `pf`, is past the demand's own start), so the caller must be
        // told to push it back — this is the regression codex's review caught:
        // a `ReadyLru` entry left holding the STALE `pf` value would report the
        // prefetched chunk ready before the link could physically have
        // delivered it.
        let (cutoff, delta) = push_back.expect("a demand cutting in front of backlog must push it back");
        assert_eq!(delta, t, "the push-back amount is exactly one transfer");
        assert!(pf > cutoff, "the prefetch's stale ready_at must be past the push-back cutoff");
        // A second prefetch offered now starts only after BOTH transfers.
        let pf2 = link.fetch_prefetch(0);
        assert_eq!(pf2, cfg.rtt_ns + 3 * t, "the demand transfer must push queued prefetches back");
    }

    /// The regression itself, at the cache level: a prefetch cached BEFORE a
    /// demand cuts in front of it must report the pushed-back `ready_at`, not
    /// the stale value it was inserted with. Before this fix `ReadyLru` stored
    /// a frozen `u64` that `Link::fetch_demand` had no way to revise, so a
    /// consumer touching the prefetched entry between its old and new
    /// `ready_at` would read a zero-wait hit for data the link could not have
    /// delivered yet.
    #[test]
    fn a_preempted_prefetch_reports_its_pushed_back_ready_at_not_the_stale_one() {
        let cfg = thin();
        let t = cfg.transfer_ns();
        let mut link = Link::new(&cfg);
        let mut cache = ReadyLru::new(8);

        let pf_a = link.fetch_prefetch(0);
        cache.insert("a", pf_a, true);

        let (done_b, push_back) = link.fetch_demand(0, Discipline::DemandPriority);
        cache.insert("b", done_b, false);
        if let Some((cutoff, delta)) = push_back {
            cache.push_back_prefetches(cutoff, delta);
        }

        let expected = pf_a + t;
        assert_eq!(
            cache.touch("a"),
            Some(expected),
            "the cached prefetch must be pushed back, not left at its stale ready_at"
        );
        // A demand entry is never subject to push-back (see `Link::fetch_demand`).
        assert_eq!(cache.touch("b"), Some(done_b));
    }

    /// End to end: the same trace under both disciplines issues the same fetches
    /// but priority may not report a smaller aggregate link occupancy.
    #[test]
    fn contended_replay_conserves_work_across_disciplines() {
        let cfg = thin();
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..30 {
            for i in 0..40 {
                ts += 3_000_000;
                trace.push(get(&format!("s{i}"), ts));
            }
        }
        let fifo = run_contended(&trace, 16, &cfg, &LinkPolicy::LeadGated(Discipline::Fifo), 0.5, 16);
        let prio = run_contended(&trace, 16, &cfg,
                                 &LinkPolicy::LeadGated(Discipline::DemandPriority), 0.5, 16);
        // Same transfer count => the same total bytes crossed the link.
        assert_eq!(fifo.demand_fetches + fifo.pf_issued, prio.demand_fetches + prio.pf_issued,
                   "disciplines must issue the same fetches on this trace");
        // Waiting can only be redistributed, never removed wholesale: priority
        // must not report less than the demand-only lower bound of one full
        // fetch per demand miss.
        let floor = prio.demand_fetches as u128 * cfg.fetch_ns() as u128;
        assert!(prio.total_wait_ns >= floor,
                "priority wait {} below the uncontended floor {floor}", prio.total_wait_ns);
    }

    #[test]
    fn caching_sheds_link_load() {
        // One hot chunk hammered faster than the link could re-fetch it: the
        // no-cache queue diverges, the LRU pays one fetch then rides for free.
        let cfg = thin();
        let trace: Vec<_> = (0..500u64).map(|i| get("hot", i * 1_000_000)).collect(); // 1ms apart
        let none = run_contended(&trace, 8, &cfg, &LinkPolicy::NoCache, 0.5, 8);
        let lru = run_contended(&trace, 8, &cfg, &LinkPolicy::Demand, 0.5, 8);
        assert!(lru.mean_wait_ms() < 1.0, "LRU should serve hot chunk freely: {}", lru.mean_wait_ms());
        assert!(none.mean_wait_ms() > 50.0 * lru.mean_wait_ms().max(0.02),
                "no-cache must queue-diverge: {}", none.mean_wait_ms());
    }

    #[test]
    fn in_flight_access_waits_only_the_remainder() {
        let cfg = thin();
        let full = (cfg.fetch_ns()) as u128;
        // Access X at t=0 (miss, waits full fetch), again at t=2ms (in flight).
        let trace = vec![get("x", 0), get("x", 2_000_000)];
        let r = run_contended(&trace, 8, &cfg, &LinkPolicy::Demand, 0.5, 8);
        let expect = full + (full - 2_000_000); // second waits remainder
        assert_eq!(r.total_wait_ns, expect);
        assert_eq!(r.demand_fetches, 1, "in-flight access must not re-fetch");
    }

    #[test]
    fn fifo_prefetch_delays_demand_priority_does_not() {
        // A predictable cycle bigger than the cache, arriving faster than the
        // link serves: prefetch traffic contends with demand traffic. Under
        // FIFO the speculative transfers sit in front of demand fetches; under
        // demand-priority they yield. Mean demand wait must be <= under priority.
        let cfg = thin();
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..30 {
            for i in 0..40 {
                ts += 3_000_000; // 3 ms spacing < 9.4 ms fetch: link is scarce
                trace.push(get(&format!("s{i}"), ts));
            }
        }
        let fifo = run_contended(&trace, 16, &cfg, &LinkPolicy::LeadGated(Discipline::Fifo), 0.5, 16);
        let prio = run_contended(&trace, 16, &cfg,
                                 &LinkPolicy::LeadGated(Discipline::DemandPriority), 0.5, 16);
        assert!(fifo.pf_issued > 0, "overlay should engage on the cycle");
        assert!(
            prio.mean_wait_ms() <= fifo.mean_wait_ms() + 1e-9,
            "priority {} must not exceed fifo {}",
            prio.mean_wait_ms(), fifo.mean_wait_ms()
        );
    }

    #[test]
    fn fat_link_makes_prefetch_cheap() {
        // Same workload, 25 Gbps in-cloud link: transfers are ~0.3ms, spacing
        // 3ms, so even FIFO prefetching leaves demand waits tiny.
        let fat = LinkCfg { rtt_ns: 1_000_000, bw_bps: 25_000_000_000, chunk_bytes: 1 << 20 };
        let mut trace = Vec::new();
        let mut ts = 0u64;
        for _ in 0..30 {
            for i in 0..40 {
                ts += 3_000_000;
                trace.push(get(&format!("s{i}"), ts));
            }
        }
        let fifo = run_contended(&trace, 16, &fat, &LinkPolicy::LeadGated(Discipline::Fifo), 0.5, 16);
        let none = run_contended(&trace, 16, &fat, &LinkPolicy::NoCache, 0.5, 16);
        assert!(fifo.mean_wait_ms() < none.mean_wait_ms(),
                "on a fat link the prefetching cache must beat no-cache: {} vs {}",
                fifo.mean_wait_ms(), none.mean_wait_ms());
    }
}
