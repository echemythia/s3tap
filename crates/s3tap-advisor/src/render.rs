//! Human rendering of advisory findings, and the `--strict` exit gate.

use s3tap_doctor::Record;
use s3tap_schema::{
    sanitize_term, Domain, Finding, FindingScope, MetricValue, Sample, SampleKind, Severity,
    TimeWindow, Unit,
};

use crate::fields::{advisory, Src};

/// The S3 operation population an advisory run was taken over, so an empty `findings` list
/// can say WHY it is empty. Three outcomes read identically without it, and only one of them
/// is health: a connection-only capture (nothing to look at), a capture whose operations were
/// all aborted before a response (nothing answered to judge), and a capture full of answered
/// operations that genuinely raised nothing. The first two are MISSING DENOMINATORS, the same
/// shape doctor publishes as `NoOperations`/`NoResponses`, and neither may read as clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpPopulation {
    /// Raw `s3tap.operation/1` record count, before any check's own gates.
    pub seen: u64,
    /// Of those, how many carried an `http_status` (i.e. S3 actually answered).
    pub answered: u64,
}

impl OpPopulation {
    /// Was there anything at the S3 layer to judge at all? An unanswered operation is not a
    /// judgeable one: every rate an advisory could compute over it has a zero denominator.
    #[must_use]
    pub fn nothing_judgeable(self) -> bool {
        self.seen == 0 || self.answered == 0
    }
}

/// The S3 operation population of a record stream, before any check's own gates.
#[must_use]
pub fn op_population(records: &[Record]) -> OpPopulation {
    let mut seen = 0u64;
    let mut answered = 0u64;
    for r in records {
        if let Record::Operation(o) = r {
            seen += 1;
            if o.http_status.is_some() {
                answered += 1;
            }
        }
    }
    OpPopulation { seen, answered }
}

/// The widest timestamp span in the stream, over EVERY record kind. A connection-only
/// capture has no operation to take a window from, and that is exactly the capture this
/// module most needs to describe, so falling back to the operation records alone would
/// report a zero-width window for the one case that matters.
fn capture_window(records: &[Record]) -> TimeWindow {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for r in records {
        let ts = match r {
            Record::Operation(o) => o.ts_ns,
            Record::Connection(c) => c.ts_ns,
            Record::TcpSample(s) => s.ts_ns,
        };
        if let Some(t) = ts {
            lo = lo.min(t);
            hi = hi.max(t);
        }
    }
    if lo == u64::MAX {
        TimeWindow { ts_start: 0, ts_end: 0 }
    } else {
        TimeWindow { ts_start: lo, ts_end: hi }
    }
}

/// The run-level record for a capture with nothing to judge, or `None` when there WAS a
/// judgeable population. `Some` exactly when [`advisory_exit`] would return 2 on its own
/// account, so the NDJSON rail can explain an exit the human rail already explains in prose.
///
/// Without it `advise --json` over a connection-only capture wrote an empty stream and exited
/// 2, which is scriptable but not self-describing: an ingest storing NDJSON kept no record of
/// why, and could not tell this from any other empty result. `doctor --json` has always
/// published a run roll-up for the equivalent state, so this closes a gap between two commands
/// that are meant to be read the same way.
///
/// Emitted for the unjudgeable case only, deliberately: a run row on every invocation would be
/// a broader contract change than the gap requires, and a consumer that sees no `advisor-run`
/// line can read that as "the population was fine" without ambiguity.
///
/// Keyed on the POPULATION, never on the exit code. Keying it on the exit made `--strict`
/// drop the row whenever a connection-sourced advisory pushed the run to 1, which turned a
/// gating flag into an output filter. The row may therefore accompany an exit 1: the advisory
/// was judged and the S3 population was still missing, and both are worth saying.
#[must_use]
pub fn unjudged_run_finding(records: &[Record]) -> Option<Finding> {
    let pop = op_population(records);
    if !pop.nothing_judgeable() {
        return None;
    }
    // The same two causes the human render distinguishes, and for the same reason: they need
    // different fixes. No operations at all points at the uprobe caps, while operations that
    // were never answered points at a capture that stopped mid-flight.
    let summary = if pop.seen == 0 {
        "0 operations in this capture, so there was nothing to check (need s3tap.operation/1 \
         records — run with the uprobe caps for the HTTP layer)"
            .to_string()
    } else {
        format!(
            "{} operation(s) captured but not one was answered, so there was nothing to judge \
             (every request aborted before a response line)",
            pop.seen
        )
    };
    Some(advisory(
        "advisor-run",
        Src::Ops,
        Domain::Run,
        Severity::Unjudged,
        "advisory run",
        summary,
        "judgeable_operations",
        Some(MetricValue::Num(pop.answered as f64)),
        Unit::Count,
        "operations >= 1 and answered >= 1".into(),
        FindingScope::default(),
        capture_window(records),
        Sample {
            judged: pop.answered as usize,
            excluded: (pop.seen - pop.answered) as usize,
            kind: SampleKind::Operation,
        },
    ))
}

/// Render findings grouped by domain, one line each: glyph, id, summary.
/// Untrusted record-derived strings are sanitized before they reach a terminal
/// (same defense as the doctor; CWE-117 / Trojan Source).
///
/// `pop` lets an empty `findings` list name its cause rather than defaulting to the one
/// reading that is not true: "nothing to flag". See [`OpPopulation`].
pub fn render(findings: &[Finding], pop: OpPopulation, color: bool) -> String {
    if findings.is_empty() {
        return if pop.seen == 0 {
            "no advisories: 0 operations in this capture, so there was nothing to check \
             (need s3tap.operation/1 records — run with the uprobe caps for the HTTP layer)\n"
                .to_string()
        } else if pop.answered == 0 {
            format!(
                "no advisories: {} operation(s) captured but not one was answered, so there \
                 was nothing to judge (every request aborted before a response line — a \
                 client timeout or reset, or a capture that ended mid-request)\n",
                pop.seen
            )
        } else {
            "no advisories: nothing to flag in this capture\n".to_string()
        };
    }
    let mut out = String::new();
    for domain in [Domain::Client, Domain::S3, Domain::Network, Domain::Run] {
        let group: Vec<&Finding> = findings.iter().filter(|f| f.domain == domain).collect();
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!("{:?}\n", domain));
        for f in group {
            let glyph = match f.severity {
                Severity::Healthy => "✓",
                Severity::Warn => "⚠",
                Severity::Advisory => "→",
                Severity::Unjudged => "?",
            };
            let line = format!(
                "  {glyph} {} — {}\n",
                sanitize_term(&f.finding_id),
                sanitize_term(&f.summary)
            );
            if color && matches!(f.severity, Severity::Warn) {
                out.push_str(&format!("\x1b[33m{line}\x1b[0m"));
            } else {
                out.push_str(&line);
            }
        }
    }
    // Findings were printed AND the S3 population is missing. That combination is reachable:
    // a connection-sourced advisory (the `advisor-latency-*` family) fires on a capture with
    // no operations at all. Without this the run exited 2 having shown the operator nothing
    // that explains the 2, which is the same silence the `--json` run row was added to end.
    if pop.nothing_judgeable() {
        out.push_str(&format!(
            "\n{}\n",
            if pop.seen == 0 {
                "note: 0 operations in this capture, so nothing at the S3 layer was judged \
                 (the advice above is drawn from the connection records alone)"
            } else {
                "note: no operation in this capture was answered, so nothing at the S3 layer \
                 was judged (the advice above is drawn from the connection records alone)"
            }
        ));
    }
    out
}

/// Exit-code gate: 0 by default (advice is not a failure); under `--strict`,
/// 1 when any `Warn` OR `Advisory` finding fired (the doctor's promotion rule —
/// stated explicitly because most advisor findings are `Advisory`).
/// `Unjudged`/`Healthy` never gate.
///
/// A missing operation population returns **2**, the same way doctor's `Verdict::NoOperations`
/// and the scorecard's own `ops_seen` check do: a connection-only capture has no operations to
/// run any check against at all, so an empty `findings` there means "nothing to judge", not
/// "judged and clean". `advise --strict` is the CI gate for this exact question, so it must not
/// be able to read a capture that decoded no S3 traffic as a pass.
///
/// That check is NOT gated by `strict` (a plain `advise` returns 2 for such a capture too), but
/// it is not first either: a Warn/Advisory that actually fired outranks it, per the precedence
/// noted in the body. Both halves matter, and an earlier version of this comment claimed the
/// check ran first and unconditionally, which stopped being true when that precedence was added.
pub fn advisory_exit(findings: &[Finding], pop: OpPopulation, strict: bool) -> i32 {
    // A real judgment outranks a missing denominator, mirroring doctor's own precedence
    // (Attention above NoOperations/NoResponses): a connection-sourced advisory can fire on a
    // capture with no judgeable S3 population at all, and that judgment is real.
    if strict
        && findings
            .iter()
            .any(|f| matches!(f.severity, Severity::Warn | Severity::Advisory))
    {
        return 1;
    }
    if pop.nothing_judgeable() {
        return 2;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::{advisory, Src};
    use s3tap_schema::{FindingScope, Sample, SampleKind, TimeWindow, Unit};

    /// A population with `seen` operations of which `answered` carried a status.
    fn pop(seen: u64, answered: u64) -> OpPopulation {
        OpPopulation { seen, answered }
    }

    fn mk(severity: Severity) -> Finding {
        advisory(
            "advisor-render-test",
            Src::Ops,
            Domain::Client,
            severity,
            "t",
            "the summary".into(),
            "m",
            None,
            Unit::None,
            "gate".into(),
            FindingScope::default(),
            TimeWindow { ts_start: 0, ts_end: 1 },
            Sample { judged: 1, excluded: 0, kind: SampleKind::Operation },
        )
    }

    #[test]
    fn render_groups_and_pins_finding_id() {
        let s = render(&[mk(Severity::Advisory)], pop(1, 1), false);
        assert!(s.contains("advisor-render-test"));
        assert!(s.contains("Client"));
    }

    #[test]
    fn empty_findings_names_why_it_is_empty_rather_than_defaulting_to_nothing_to_flag() {
        // THREE outcomes leave `findings` empty and only the last is health. The message
        // must say which, because "nothing to flag" reads as a clean bill for all three.
        let no_ops = render(&[], pop(0, 0), false);
        assert!(no_ops.contains("0 operations in this capture"), "{no_ops}");

        let none_answered = render(&[], pop(5, 0), false);
        assert!(none_answered.contains("not one was answered"), "{none_answered}");
        assert!(!none_answered.contains("nothing to flag"), "{none_answered}");

        let clean = render(&[], pop(5, 5), false);
        assert!(!clean.contains("0 operations"), "{clean}");
        assert!(clean.contains("nothing to flag"), "{clean}");
    }

    #[test]
    fn the_run_row_explains_an_exit_2_the_ndjson_rail_could_not() {
        use s3tap_doctor::Record;
        use s3tap_schema::{Connection, Operation};
        let conn = |ts: u64| {
            Record::Connection(Connection { ts_ns: Some(ts), ..Default::default() })
        };
        let op = |status: Option<u16>| {
            Record::Operation(Operation { ts_ns: Some(50), http_status: status, ..Default::default() })
        };

        // Cause 1: a connection-only capture. `advise --json` wrote an empty stream and exited
        // 2, so an ingest storing NDJSON kept no record of why.
        let recs = vec![conn(10), conn(90)];
        let f = unjudged_run_finding(&recs).expect("an unjudgeable capture gets a run row");
        assert_eq!(f.finding_id, "advisor-run");
        assert_eq!(f.domain, Domain::Run);
        assert!(matches!(f.severity, Severity::Unjudged));
        assert!(f.summary.contains("0 operations in this capture"), "{}", f.summary);
        // The window spans the CONNECTION records: an op-only span would be zero-width here,
        // which is exactly the capture this row exists to describe.
        assert_eq!(f.window.ts_start, 10);
        assert_eq!(f.window.ts_end, 90);

        // Cause 2: operations decoded, none answered. A different remedy, so a different
        // summary — the row must not collapse the two.
        let recs = vec![conn(10), op(None), op(None)];
        let f = unjudged_run_finding(&recs).expect("all-unanswered is unjudgeable too");
        assert!(f.summary.contains("not one was answered"), "{}", f.summary);
        assert!(!f.summary.contains("0 operations"), "{}", f.summary);
        assert_eq!(f.sample.judged, 0);
        assert_eq!(f.sample.excluded, 2, "the unanswered ops are the excluded population");

        // A judgeable capture gets NO row, so a consumer seeing none can read that as "the
        // population was fine" without ambiguity.
        assert!(unjudged_run_finding(&[conn(10), op(Some(200))]).is_none());

        // The row exists exactly when the exit code is 2 on its own account. If these two ever
        // disagreed, the rail would explain an exit that did not happen, or stay silent about
        // one that did.
        for recs in [vec![conn(10)], vec![op(None)], vec![op(Some(200))]] {
            let pop = op_population(&recs);
            assert_eq!(
                unjudged_run_finding(&recs).is_some(),
                advisory_exit(&[], pop, false) == 2,
                "run row and exit 2 must agree"
            );
        }
    }

    #[test]
    fn golden_json_pins_schema_tag_and_finite_num() {
        // Golden shape: the NDJSON line opens with the schema tag, carries the
        // id, and round-trips losslessly.
        let f = mk(Severity::Advisory);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.starts_with("{\"schema\":\"s3tap.finding/1\""), "{json}");
        assert!(json.contains("\"finding_id\":\"advisor-render-test\""));
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
        // The finite-Num serializer must reject NaN loudly.
        let mut bad = mk(Severity::Advisory);
        bad.value = Some(s3tap_schema::MetricValue::Num(f64::NAN));
        assert!(serde_json::to_string(&bad).is_err(), "NaN must not serialize");
    }

    #[test]
    fn a_malicious_summary_is_sanitized_before_reaching_the_tty() {
        // Advisory summaries interpolate record-derived text (bucket, SNI, s3_op) straight
        // off an untrusted JSONL stream, so `advise --from evil.jsonl` is a tty-injection
        // path. Nothing tested the two `sanitize_term` calls in `render`: both could be
        // deleted with the whole workspace still green. (Doctor's
        // `a_malicious_bucket_name_is_sanitized_before_reaching_the_tty` is the sibling.)
        let evil = "b\x1b[31m\r\u{202e}";
        let mut f = mk(Severity::Advisory);
        f.summary = format!("High network floor to {evil}");
        f.finding_id = format!("advisor-{evil}");
        // color=false so any ESC in the output could only have come from the data itself.
        let out = render(&[f], pop(1, 1), false);
        assert!(!out.contains('\x1b'), "no raw ESC reaches the tty: {out:?}");
        assert!(!out.contains('\r'), "no raw CR reaches the tty: {out:?}");
        assert!(!out.contains('\u{202e}'), "no bidi override reaches the tty: {out:?}");
        assert!(out.contains('\u{fffd}'), "unsafe chars replaced with U+FFFD: {out:?}");
    }

    #[test]
    fn strict_gates_on_warn_and_advisory_only() {
        assert_eq!(advisory_exit(&[], pop(1, 1), true), 0);
        assert_eq!(advisory_exit(&[mk(Severity::Advisory)], pop(1, 1), false), 0);
        assert_eq!(advisory_exit(&[mk(Severity::Advisory)], pop(1, 1), true), 1);
        assert_eq!(advisory_exit(&[mk(Severity::Warn)], pop(1, 1), true), 1);
        assert_eq!(advisory_exit(&[mk(Severity::Unjudged)], pop(1, 1), true), 0);
    }

    #[test]
    fn zero_operations_exits_non_zero_unconditionally() {
        // The regression: a connection-only capture (ops_seen=0) used to leave `findings`
        // empty and exit 0 regardless of `--strict`, making `advise --strict` a CI gate
        // that cannot tell "clean" from "no data".
        assert_eq!(advisory_exit(&[], pop(0, 0), true), 2);
        assert_eq!(advisory_exit(&[], pop(0, 0), false), 2, "unconditional: not gated by --strict");
        // …and the sibling missing denominator: operations exist, but S3 answered none of
        // them, so every rate an advisory could compute has a zero denominator. Doctor calls
        // this `Verdict::NoResponses` and exits 2; `advise` must not call it clean either.
        assert_eq!(advisory_exit(&[], pop(5, 0), true), 2);
        assert_eq!(advisory_exit(&[], pop(5, 0), false), 2, "unconditional here too");
        // A real judgment still outranks a missing denominator (doctor's own precedence).
        assert_eq!(advisory_exit(&[mk(Severity::Warn)], pop(5, 0), true), 1);
    }
}
