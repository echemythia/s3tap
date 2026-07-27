use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Report {
    pub accesses: u64,
    pub hits: u64,
    pub prefetch_issued: u64,
    pub prefetch_used: u64,
}

impl Report {
    /// Fraction of cacheable-read accesses served from cache.
    pub fn hit_rate(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.hits as f64 / self.accesses as f64 }
    }

    /// Of the objects we prefetched, the fraction later actually used. Low
    /// precision = wasted bandwidth / request cost / cache pollution.
    pub fn prefetch_precision(&self) -> f64 {
        if self.prefetch_issued == 0 { 0.0 }
        else { self.prefetch_used as f64 / self.prefetch_issued as f64 }
    }

    /// Total origin (S3) fetches this policy generates: one per demand miss plus
    /// one per prefetch. A demand miss always fetches from origin (the read must
    /// be served); a hit — whether demand- or prefetch-filled — does not, since
    /// the prefetch's origin fetch was already counted when it was issued.
    /// (`hits <= accesses`, so the subtraction never underflows.)
    pub fn origin_fetches(&self) -> u64 {
        (self.accesses - self.hits) + self.prefetch_issued
    }

    /// REUSE BENEFIT — the good half of the combined score. Fraction of accesses
    /// served from cache; each one is an origin fetch avoided by reusing stored
    /// data. Identical to `hit_rate`, named here to read as the benefit term of
    /// `net_savings`.
    pub fn reuse_benefit(&self) -> f64 {
        self.hit_rate()
    }

    /// PREFETCH COST — the bad half. Speculative origin fetches issued per access.
    /// Every prefetch is an origin call whether or not it is later used, so this
    /// is the extra request/bandwidth cost the reuse benefit has to outrun.
    pub fn prefetch_cost(&self) -> f64 {
        if self.accesses == 0 { 0.0 }
        else { self.prefetch_issued as f64 / self.accesses as f64 }
    }

    /// PREFETCH LATENCY WIN — of all accesses, the fraction whose origin latency
    /// was hidden specifically by PREFETCHING: a would-be miss that speculation
    /// turned into a ready hit, i.e. `prefetch_used / accesses`. Distinct from
    /// `hit_rate` (which counts every latency-free hit, including plain-cache
    /// reuse) — this isolates what the prefetcher itself bought. Zero for any
    /// demand-only policy. Under the harness's instant-prefetch idealization this
    /// is an upper bound (a prefetch still in flight at access time would only
    /// partly hide the latency).
    pub fn prefetch_latency_saved(&self) -> f64 {
        if self.accesses == 0 { 0.0 }
        else { self.prefetch_used as f64 / self.accesses as f64 }
    }

    /// COMBINED: net origin fetches ELIMINATED per access versus the no-cache
    /// baseline (which fetches on every access) = `reuse_benefit - prefetch_cost`.
    /// Positive means the policy cuts origin traffic; negative means speculative
    /// prefetching costs more calls than reuse saves. Equivalently this equals
    /// (demand hits - WASTED prefetches) / accesses: a *used* prefetch is
    /// call-neutral (it just moves an unavoidable fetch earlier), so only wasted
    /// prefetches are true added cost — the two views are algebraically identical.
    pub fn net_savings(&self) -> f64 {
        self.reuse_benefit() - self.prefetch_cost()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_are_computed() {
        let r = Report { accesses: 100, hits: 40, prefetch_issued: 20, prefetch_used: 10 };
        assert!((r.hit_rate() - 0.40).abs() < 1e-9);
        assert!((r.prefetch_precision() - 0.50).abs() < 1e-9);
    }

    #[test]
    fn net_savings_is_reuse_benefit_minus_prefetch_cost() {
        // 100 accesses, 40 hits, 20 prefetches -> 80 origin fetches (60 misses +
        // 20 prefetch), i.e. 0.80x no-cache. Net saved per access = benefit 0.40
        // - cost 0.20 = 0.20, and 1 - net_savings == origin fetches / accesses.
        let r = Report { accesses: 100, hits: 40, prefetch_issued: 20, prefetch_used: 10 };
        assert_eq!(r.origin_fetches(), 80);
        assert!((r.reuse_benefit() - 0.40).abs() < 1e-9);
        assert!((r.prefetch_cost() - 0.20).abs() < 1e-9);
        assert!((r.net_savings() - 0.20).abs() < 1e-9);
        assert!((r.net_savings() - (1.0 - r.origin_fetches() as f64 / 100.0)).abs() < 1e-9);
        // pf_latency isolates the prefetcher's own latency win: 10 used / 100.
        assert!((r.prefetch_latency_saved() - 0.10).abs() < 1e-9);

        // Prefetch-heavy, low-payoff: speculation outruns reuse -> NEGATIVE net.
        let wasteful = Report { accesses: 100, hits: 30, prefetch_issued: 90, prefetch_used: 5 };
        assert!(wasteful.net_savings() < 0.0, "net={}", wasteful.net_savings());

        // A pure demand cache (no prefetch): net savings == the hit rate.
        let demand = Report { accesses: 100, hits: 40, prefetch_issued: 0, prefetch_used: 0 };
        assert!((demand.net_savings() - 0.40).abs() < 1e-9);
    }

    #[test]
    fn empty_report_is_zero_not_nan() {
        let r = Report::default();
        assert_eq!(r.hit_rate(), 0.0);
        assert_eq!(r.prefetch_precision(), 0.0);
        assert_eq!(r.origin_fetches(), 0);
        assert_eq!(r.reuse_benefit(), 0.0);
        assert_eq!(r.prefetch_cost(), 0.0);
        assert_eq!(r.net_savings(), 0.0);
        assert_eq!(r.prefetch_latency_saved(), 0.0);
    }
}
