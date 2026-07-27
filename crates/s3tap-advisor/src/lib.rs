//! Optimization advisories over captured s3tap records. A pure consumer of the
//! public schema (no probes, no privilege): records in, `s3tap.finding/1` out.
//! Health checks live in `s3tap-doctor`; this crate is optimization advice
//! (efficiency + caching) on the same finding rails, scoped per process.
//!
//! Contract:
//! - every check obeys the three-part noise gate (rate AND absolute impact AND
//!   per-scope MIN_OPS) and emits `Severity::Unjudged` — never a guess — when
//!   the inputs to judge are absent;
//! - `partial == true` and `Ambiguous` ops are excluded from TIMING math and from any
//!   numerator, as are `None` timestamps — but NOT from a denominator, and NOT from a set
//!   that can only DE-ESCALATE a finding. `partial` does not mean "this did not happen": it
//!   is `conn.is_none() || head_truncated || resp.truncated`, and the dominant cause (no
//!   `(tgid,fd)` join) leaves the op fully timed. So dropping one from a rate's denominator
//!   inflates the rate, and dropping a write from an invalidation index or a success from a
//!   recovery index INVENTS a failure. Ask which direction the exclusion can err in, and
//!   take the one that cannot manufacture a finding;
//! - findings carry a stable `finding_id`, ONE headline metric, and the gate
//!   that fired in `threshold`.

#![allow(clippy::type_complexity)] // internal grouping maps; typedefs would obscure them

use s3tap_doctor::Record;
use s3tap_schema::Finding;

pub(crate) mod fields;
#[cfg(test)]
pub(crate) mod fixtures;
mod render;
pub use render::{advisory_exit, op_population, render, unjudged_run_finding, OpPopulation};

pub(crate) mod checks;

pub mod analyze;
pub use analyze::{analyze_trace, AnalyzeOpts, TraceAnalysis, Verdict};

pub fn advise(records: &[Record]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(checks::churn::check_connection_churn(records));
    out.extend(checks::parallelism::check_serial_requests(records));
    out.extend(checks::refetch::check_redundant_refetch(records));
    out.extend(checks::patterns::check_head_then_get(records));
    out.extend(checks::patterns::check_small_objects(records));
    out.extend(checks::service::check_throttling(records));
    out.extend(checks::service::check_latency_path(records));
    let op_records = records.iter().filter(|r| matches!(r, Record::Operation(_))).count();
    let cache_ops = checks::caching::to_op_records(records);
    let pre_dropped = op_records.saturating_sub(cache_ops.len());
    out.extend(checks::caching::advise_caching(&cache_ops, pre_dropped));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_findings() {
        assert!(advise(&[]).is_empty());
    }
}
