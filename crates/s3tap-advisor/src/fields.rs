//! The one `Finding` constructor every check uses. `Finding` has ~20 required
//! fields and no `Default`, so this is where they are all filled — explicitly,
//! once — and where an advisory's neutral values live (`emitted_at: None`,
//! no RTT baseline: advisories are not RTT-relative judgments).

use s3tap_schema::{
    Domain, Evidence, Finding, FindingSchemaTag, FindingScope, MetricValue, Sample, Severity,
    TimeWindow, Unit, CONNECTION_SCHEMA, OPERATION_SCHEMA,
};

/// Which record stream a finding was actually derived from, published as its
/// `source_schema`. Every advisory used to name BOTH streams regardless, which told a machine
/// consumer nothing: it could not tell an operation-derived finding from a connection-derived
/// one, so it could not know which half of a capture to go look at. Every check reads exactly
/// one of the two, so this is a real property of the check rather than a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Src {
    /// Derived from `s3tap.operation/1` records: churn, parallelism, refetch, the request
    /// patterns, throttling and caching.
    Ops,
    /// Derived from `s3tap.connection/2` records: the `advisor-latency-*` path findings.
    Conns,
}

impl Src {
    fn schemas(self) -> Vec<String> {
        match self {
            Src::Ops => vec![OPERATION_SCHEMA.into()],
            Src::Conns => vec![CONNECTION_SCHEMA.into()],
        }
    }
}

/// Build an advisory `Finding` with every required field set.
#[allow(clippy::too_many_arguments)] // deliberate: forces every call site to supply the lot
pub(crate) fn advisory(
    finding_id: &str,
    src: Src,
    domain: Domain,
    severity: Severity,
    title: &str,
    summary: String,
    metric: &str,
    value: Option<MetricValue>,
    unit: Unit,
    threshold: String,
    scope: FindingScope,
    window: TimeWindow,
    sample: Sample,
) -> Finding {
    Finding {
        schema: FindingSchemaTag,
        emitted_at: None,
        source_schema: src.schemas(),
        finding_id: finding_id.into(),
        domain,
        title: title.into(),
        severity,
        verdict: verdict_label(severity).into(),
        summary,
        recommendation_ref: None,
        metric: metric.into(),
        value,
        unit,
        baseline_rtt_us: None,
        ratio_to_rtt: None,
        threshold,
        sample,
        scope,
        window,
        evidence: Evidence::default(),
    }
}

fn verdict_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Healthy => "healthy",
        Severity::Warn => "warn",
        Severity::Advisory => "advisory",
        Severity::Unjudged => "unjudged",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3tap_schema::SampleKind;

    #[test]
    fn builder_fills_every_field_and_serializes() {
        let f = advisory(
            "advisor-test",
            Src::Ops,
            Domain::Client,
            Severity::Advisory,
            "test finding",
            "a summary with numbers 42".into(),
            "test_metric",
            Some(MetricValue::Num(42.0)),
            Unit::Count,
            ">= 1".into(),
            FindingScope { app_pid: Some(7), ..Default::default() },
            TimeWindow { ts_start: 1, ts_end: 2 },
            Sample { judged: 10, excluded: 0, kind: SampleKind::Operation },
        );
        let json = serde_json::to_string(&f).expect("must serialize");
        assert!(json.contains("\"s3tap.finding/1\""));
        assert!(json.contains("\"advisor-test\""));
        assert!(json.contains("\"s3tap.operation/1\""));
        // An operation-derived finding names ONLY the operation stream. Naming both told a
        // consumer nothing about which half of the capture the finding actually rests on.
        assert!(!json.contains("\"s3tap.connection/2\""), "{json}");

        // The connection-derived side of the same builder.
        let c = advisory(
            "advisor-latency-test",
            Src::Conns,
            Domain::Network,
            Severity::Advisory,
            "test finding",
            "a summary".into(),
            "test_metric",
            Some(MetricValue::Num(1.0)),
            Unit::Us,
            ">= 1".into(),
            FindingScope::default(),
            TimeWindow { ts_start: 1, ts_end: 2 },
            Sample { judged: 3, excluded: 0, kind: SampleKind::Connection },
        );
        let json = serde_json::to_string(&c).expect("must serialize");
        assert!(json.contains("\"s3tap.connection/2\""), "{json}");
        assert!(!json.contains("\"s3tap.operation/1\""), "{json}");
    }
}
