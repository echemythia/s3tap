use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use crate::trace::{NormEvent, Op};

/// The ONE schema tag this mirror mirrors. Declared here, not imported, so the
/// replay crate keeps its zero-dependency stance on `s3tap-schema` (see
/// [`OpRecord`]); it must equal `s3tap_schema::OPERATION_SCHEMA`. Drift fails
/// CLOSED and is therefore safe: if the schema crate bumps to `/2` and this
/// string stays `/1`, every `/2` record is REJECTED (the correct handling of a
/// version we were not written against), never silently read as a `/1`.
pub const OPERATION_SCHEMA: &str = "s3tap.operation/1";

/// Just the version tag (and the usability flag) off a candidate JSONL line.
/// Every field of [`OpRecord`] is optional (a mirror of a partially-populated
/// record), so `OpRecord` alone deserializes from ANY JSON object and cannot be
/// the version guard — the tag has to be read and checked separately, which is
/// what this exists for.
/// Keep the tag as RAW JSON and always wrap it in `Some`. A plain
/// `Option<Box<RawValue>>` would fold an explicit `"schema": null` back into `None`, i.e.
/// into "absent", which is exactly the distinction the presence check needs.
fn some_raw<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Box<RawValue>>, D::Error> {
    <Box<RawValue> as Deserialize>::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
struct WireTag {
    #[serde(default, deserialize_with = "some_raw")]
    schema: Option<Box<RawValue>>,
    /// s3tap's own "this record may be incomplete" flag: the connection facts
    /// were never joined, or a request/response head was truncated at the capture
    /// cap, so bucket/key/status are not guaranteed to be what the wire carried.
    ///
    /// It is read HERE rather than on [`OpRecord`] because the two ingest paths
    /// reach the flag differently. The in-memory bridge (`s3tap-advisor`'s
    /// `to_op_records`) holds the decoded `s3tap_schema::Operation` and already
    /// drops `partial` records at the source; the JSONL line path had no way to
    /// see the flag at all, which is the gap this closes. A record without the
    /// field (older capture) is treated as usable.
    #[serde(default)]
    partial: bool,
}

/// Local deserializable mirror of the fields we need from an s3tap
/// `s3tap.operation/1` record. We do NOT deserialize into
/// `s3tap_schema::Operation` (serialize-only, string-encoded ints), so the
/// replay crate needs no dependency on the schema crate. Unknown fields in a
/// real record are ignored by default.
///
/// NOTE this type carries no schema field of its own, and every field defaults,
/// so it is NOT self-validating: constructing one in memory (the `s3tap-advisor`
/// bridge does, from already-decoded `s3tap.operation/1` records) is fine, but
/// anything built from an untrusted LINE must go through [`parse_trace_line`],
/// which checks the tag first. Deserializing a line straight into `OpRecord`
/// would accept a `/2` record — or a tagless blob — as a `/1` operation.
#[derive(Debug, Deserialize)]
pub struct OpRecord {
    #[serde(default)]
    pub verb: Option<String>,
    #[serde(default)]
    pub s3_op: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub key_hash: Option<String>,
    /// Wire-encoded as a decimal STRING by s3tap; parsed to u64 here.
    #[serde(default)]
    pub ts_ns: Option<String>,
    #[serde(default)]
    pub http_status: Option<u16>,
    /// Declared response-body size (`Content-Length`) — the downloaded object
    /// size for a GET; a PLAIN number in the record (s3tap keeps object sizes
    /// unencoded). Populates `NormEvent.size` for byte-capacity analysis. NOTE:
    /// deliberately NOT `op_bytes_recv`, which is response *header* bytes, not the
    /// body. Null when no `Content-Length` was present (chunked / head unseen).
    #[serde(default)]
    pub content_length: Option<u64>,
}

/// Map a captured record into a normalized event. Returns `None` when the record
/// is not a usable trace event:
///   * no object identity (e.g. a ListObjects) — not a cache access we can key on;
///   * no readable timestamp — `ts_ns` absent (a legitimately null one: the agent
///     emits `"ts_ns":null` when the op's start wasn't observed) or present but
///     unparseable. [`NormEvent::ts_ns`] is a plain `u64` with no "unknown" state,
///     so the old `unwrap_or(0)` turned both cases into an event AT monotonic 0:
///     indistinguishable from a real t=0, out of order against every timestamped
///     event around it, and collapsing the inter-arrival spacing the prefetch/TTL
///     models read off `ev.ts_ns`. Dropping is the conservative direction (it can
///     only understate reuse, the same stance the caching bridge takes for an
///     absent status) and it is honest, where a fabricated 0 is not.
///   * a GET the origin never served a body for — see [`demand_op`].
pub fn from_record(r: &OpRecord) -> Option<NormEvent> {
    let bucket = r.bucket.as_deref()?;
    let key_hash = r.key_hash.as_deref()?;
    let object_id = format!("{bucket}/{key_hash}");

    Some(NormEvent {
        ts_ns: r.ts_ns.as_deref()?.parse().ok()?,
        op: demand_op(r)?,
        object_id,
        range: None,             // Phase 1: parse Range header in s3tap-core::http
        // Whole-object body size (Content-Length); None when not captured. On a 206
        // this is the RANGE length rather than the object length, which is exactly
        // why `demand_op` refuses to call that event a `Get` (see below).
        size: r.content_length,
        version: None,           // Phase 1: parse ETag / versionId
        status: r.http_status,
    })
}

/// Resolve the op AND apply the two demand-read gates, in ONE place, AFTER the
/// classification — so no ingest path can skip them and no consumer can drift.
/// Both gates concern a GET only; writes are forwarded regardless of status
/// because they are invalidation signals and over-invalidating only understates
/// savings (the safe direction), where trusting a status we may have misread
/// would let a modelled cache serve stale bytes.
///
/// 1. **A GET the origin served no body for is not a cacheable demand read.** Only
///    `200` (whole body) counts. A 4xx/5xx served no body a cache could ever have
///    supplied, so counting it invents reuse out of the client's retries: 300 keys
///    retried ~20 times through a 503 storm is 6300 records over 300 keys, which
///    reads as a 0.95 LRU saving on a workload whose successful reads (300, one per
///    key) have ZERO reuse. `advise` filtered this at its own bridge; `analyze`
///    ingests JSONL through [`parse_trace_line`] and had no gate at all, so the same
///    capture produced opposite verdicts from the two commands. Gating here, on
///    the MAPPED op rather than on the raw `s3_op` string, also closes the drift
///    the bridge's `s3_op == Some("GetObject")` test left open: a line carrying
///    `verb:"GET"` with no `s3_op` still reaches `Op::Get` through the verb
///    fallback, and used to skip the status check entirely. An ABSENT status is
///    dropped too: on an `OpRecord` (the only format that reaches this function —
///    IBM COS lines and raw `NormEvent` traces are parsed by their own branches in
///    [`classify_trace_line`] and never call `demand_op`) a null `http_status` is
///    `s3tap-core::correlate::on_close`'s "aborted in-flight op" signal, a request
///    whose connection closed before any response arrived. That is not a served
///    body either, so counting it invented reuse from requests the origin never
///    answered at all, the same shape of bug the 4xx/5xx gate exists to close.
///
///    **`304 Not Modified` is dropped by this same rule**, and that deserves saying
///    out loud because it is neither an error nor rare: `s3tap-advisor`'s `refetch`
///    check actively RECOMMENDS conditional GETs, so a client that took the advice
///    turns most of its GET records into 304s. A 304 carries no body, so a cache
///    could not have served one and counting it would credit the cache with a
///    request the ORIGIN already answered cheaply. The exclusion is right, but it
///    is invisible in the counts: 4500 x 304 beside 500 x 200 is "500 GETs" to the
///    replay trace while `doctor`/`scorecard` see all 5000 as successes with zero
///    errors (`classify_status` puts everything below 400 in `Success`). Anything
///    quoting a GET denominator off this trace must say which denominator it is.
/// 2. **A 206 is a RANGED read, and we cannot model it honestly yet.** The record
///    carries no `range` (s3tap does not parse the Range header) and its
///    `content_length` is the range length, not the object length. Object-level
///    identity is the whole object, so a 1 GiB object streamed as 1000 x 1 MiB
///    ranged GETs would read as 1000 accesses to ONE key: distinct 1, hit rate
///    0.999, "CACHE IT", for a workload whose true reuse is zero. Chunk mode does
///    not save this either, because `to_blocks` derives its chunk span from
///    `range`/`size` and so maps every one of those reads onto chunk `#0`. So a
///    206 becomes `Op::Other`: kept in the trace (its `status` still lets a caller
///    measure the ranged fraction and say so) but invisible to every simulator,
///    which all skip `Other`. That is the same conservative direction this
///    function already takes for an unclassifiable op, and it makes the collapse
///    unreachable rather than silently wrong.
fn demand_op(r: &OpRecord) -> Option<Op> {
    let op = op_kind(r.s3_op.as_deref(), r.verb.as_deref());
    if op != Op::Get {
        return Some(op);
    }
    match r.http_status {
        Some(200) => Some(Op::Get),
        Some(206) => Some(Op::Other),
        Some(_) | None => None,
    }
}

/// Classify from the resolved `s3_op` — s3tap's taxonomy (see
/// `crates/s3tap-core/src/http.rs`; CONFIRM the exact names there before relying
/// on this). Only an object GET is a cacheable read; every write/multipart op
/// invalidates; sub-resource reads (`GetObjectAcl`/`GetObjectTagging`), `List*`,
/// session/bucket ops, and anything unrecognized are `Op::Other` (ignored) so
/// they never inflate the cache. Broad prefix matching is deliberately avoided —
/// `starts_with("get")` would swallow `GetObjectAcl` as a body GET. Note s3tap
/// resolves unclassifiable requests to `"UNKNOWN"` (→ `Op::Other`), so a real
/// GET it failed to classify is conservatively DROPPED rather than counted — the
/// safe direction for an upper-bound measurement. The raw-verb fallback below
/// only fires when `s3_op` is entirely absent — a tagged record whose request
/// head we saw but couldn't classify, or an in-memory bridge record.
fn op_kind(s3_op: Option<&str>, verb: Option<&str>) -> Op {
    if let Some(op) = s3_op {
        return match op {
            "GetObject" => Op::Get,
            "HeadObject" => Op::Head,
            "PutObject" | "UploadPart" | "CreateMultipartUpload"
                | "CompleteMultipartUpload" | "CopyObject" => Op::Put,
            "DeleteObject" | "DeleteObjects" | "AbortMultipartUpload" => Op::Delete,
            _ => Op::Other, // List*, GetObjectAcl/Tagging, CreateSession, UNKNOWN, …
        };
    }
    match verb {
        Some("GET") => Op::Get,
        Some("HEAD") => Op::Head,
        Some("PUT") => Op::Put,
        Some("DELETE") => Op::Delete,
        _ => Op::Other,
    }
}

/// Convenience: adapt a slice of records, dropping ones without identity.
pub fn from_records(records: &[OpRecord]) -> Vec<NormEvent> {
    records.iter().filter_map(from_record).collect()
}

/// The op a record CLASSIFIES as, before [`demand_op`]'s status gates run. Exposed
/// so a caller can name the denominator its ratios are actually built on: `Op::Get`
/// here counts every object-GET record in the capture, where the trace `from_records`
/// returns counts only the ones the origin served a whole body for (200). Those two
/// numbers differ by the failed GETs, the ranged 206s and — the easy one to miss —
/// every `304 Not Modified` (see [`demand_op`]).
pub fn record_op_kind(r: &OpRecord) -> Op {
    op_kind(r.s3_op.as_deref(), r.verb.as_deref())
}

/// Parse ONE trace line into a `NormEvent`, auto-detecting the format. Tried in
/// order: a raw `NormEvent` JSON (the canonical replay format), an s3tap
/// `s3tap.operation/1` record (via `OpRecord`), then an IBM COS text line.
/// `None` when the line is blank, unparseable, or an op without object identity
/// (a Connection record, a `ListObjects`, …). This is the single loader the
/// `replay`/`mrc` bins and the `analyze` command share, so every entry point
/// ingests the same three formats.
///
/// The s3tap branch is TAG-GATED: only a line explicitly tagged
/// [`OPERATION_SCHEMA`] is read as an operation, matching the contract every other
/// consumer of these records enforces ("deserialization rejects a wrong/absent tag
/// exactly"). Without the gate, `OpRecord`'s all-optional fields accepted any JSON
/// object: 500 lines tagged `s3tap.operation/2` were counted as unknown-schema by
/// `s3tap_doctor::parse_records` (so `doctor`/`advise` correctly saw nothing) while
/// `analyze` ingested all 500 as `/1` GETs and printed a cache verdict over a schema
/// it had never seen. A wrongly-tagged or tagless JSON object now falls through to
/// the IBM branch, which rejects it, so the line is skipped rather than misread. The
/// other two formats are deliberately tagless and keep their own branches.
pub fn parse_trace_line(line: &str) -> Option<NormEvent> {
    match classify_trace_line(line) {
        LineOutcome::Event(ev) => Some(ev),
        LineOutcome::OperationDropped | LineOutcome::OtherRecord | LineOutcome::Unusable => None,
    }
}
/// The CAPTURE record kinds this build reads that carry no demand read. Matched EXACTLY, like
/// the operation tag, and deliberately not by prefix: a prefix admitted
/// `s3tap.connection/../../etc` and, worse, `s3tap.connection/3` — a version no reader in this
/// build can parse, so `analyze` alone would call it capture data while every sibling consumer
/// exits 4 on the same file. The one case the prefix existed for is the one case it
/// manufactured a split.
///
/// `s3tap.finding/*` and `s3tap.scorecard/*` are NOT here. They are this tool's own OUTPUT, and
/// the book states the rule plainly: a findings file is not a capture, and feeding one to a
/// consumer is a tool failure (exit 4), not a capture with nothing in it.
const KNOWN_NON_TRACE_SCHEMAS: [&str; 2] = ["s3tap.connection/2", "s3tap.sample/1"];


/// What one line of input turned into. [`parse_trace_line`] collapses the two
/// non-event arms into `None`; this keeps them apart, because they mean opposite
/// things to an operator.
///
/// A caller that reports "0 usable events" MUST be able to tell the two apart. A
/// capture in which no GET succeeded (a 503 storm, an all-403 bucket, or a
/// mid-flight attach where every op carries `"ts_ns":null`) produces an empty trace
/// out of thousands of PERFECTLY WELL-FORMED s3tap records, and the honest message
/// there is "N records parsed, none of them was a demand read a cache could serve",
/// not a list of the file formats we accept. `doctor` on the same file reports every
/// one of those records and a 100% error rate, so telling the operator the file is
/// not a trace contradicts the tool standing next to it.
#[derive(Debug)]
pub enum LineOutcome {
    /// A usable trace event.
    Event(NormEvent),
    /// The line WAS a correctly tagged `s3tap.operation/1` record. It produced no
    /// event because of a CONTENT gate, not a parse failure: the demand-read gates in
    /// [`demand_op`] (a 4xx/5xx/304 GET, a 206), no object identity (a `ListObjects`),
    /// no readable timestamp, or the record's own `partial` flag. This is capture
    /// data, not junk.
    OperationDropped,
    /// The line was a VALID `s3tap.*` record of a kind that carries no demand read — a
    /// `s3tap.connection/2`, a `s3tap.sample/1`, a finding, a scorecard row. Capture data,
    /// like [`Self::OperationDropped`], and kept apart from junk for the same reason: telling
    /// an operator that their connection-only capture is "not a trace" contradicts `doctor`
    /// standing next to it reading the same file happily.
    OtherRecord,
    /// Blank, unparseable, wrongly tagged as an s3tap schema this build does not know, or
    /// not JSON at all.
    Unusable,
}

/// [`parse_trace_line`] with the drop REASON preserved — see [`LineOutcome`].
pub fn classify_trace_line(line: &str) -> LineOutcome {
    // A `schema` field means the line belongs to a PUBLIC RECORD, so it is routed by that tag
    // and by nothing else. Trying raw `NormEvent` first let a tagged object be modelled as a
    // replay event purely because its fields happened to overlap: an
    // `{"schema":"s3tap.operation/2", "op":"get", "object_id":…}` line — a future record shape
    // this build has never seen — parsed as a raw event and produced a report, which is
    // exactly the exact-schema boundary the first-order records are built to enforce. A new
    // record version must be an explicit compatibility decision, never a coincidence of field
    // names. Raw `NormEvent` JSON is intentionally TAGLESS, so it is unaffected by the
    // reordering: it has no `schema` field to route on.
    // Route on the PRESENCE of a `schema` key, not on it deserializing as a string.
    // `from_str::<WireTag>().ok()` discarded type errors too, so a line whose `schema` was a
    // number, array, object, bool or null failed the tag parse and fell through to the raw
    // branch — modelled as a replay event purely because its other fields matched. That is
    // the hole this ordering exists to close, so it has to close for a tag encoded any way at
    // all, not just the one shape today's records happen to use.
    // Capture the tag RAW, so its PRESENCE survives whatever shape it has. Deserializing it
    // as `Option<String>` folded three different things together — absent, JSON null, and
    // "some other type" — and the first attempt to separate them parsed the line a second
    // time as a `serde_json::Value`. That was both unsound and slow: unsound because a
    // `Value` parse can fail where `WireTag` succeeds (it is recursive, so it rejects past a
    // depth limit, and it validates numbers and escapes that unknown-field skipping ignores),
    // so a deeply-nested or `1e999`-bearing line read as "no tag" and fell through to the raw
    // branch anyway; slow because materialising a `Map` of owned `String`s for every line
    // cost more than the two parses it was added beside, ~2.6x on ingest.
    let wire = serde_json::from_str::<WireTag>(line).ok();
    // Presence must NOT depend on the rest of the object deserializing. `WireTag` is a
    // derived impl, so it also rejects lines that ARE tagged objects: a duplicate `schema`
    // or `partial` key, or a `partial` that is not a bool. Deriving `owns_tag` from that
    // parse alone therefore reopened the very bypass this code closed — `{"schema":"…/2",
    // "partial":"none", …}` read as UNTAGGED and was modelled as a raw replay event, which
    // is the exact-schema boundary gone. The re-check runs only on the failure path, so a
    // well-formed trace pays nothing for it, and it borrows rather than materialising owned
    // Strings (the reason the old `Value` check was removed).
    let owns_tag = match &wire {
        Some(w) => w.schema.is_some(),
        // `BTreeMap<String, _>`, not `<&str, _>`: serde cannot BORROW a key that needs
        // unescaping, so `{"sch\u0065ma":…}` — or any line with an escaped key at all —
        // failed the whole re-check and read as untagged, reopening the bypass. Owning only
        // the keys, only on this failure path, costs nothing measurable (+2% on a line that
        // reaches it; junk dies at byte 0).
        None => serde_json::from_str::<BTreeMap<String, &RawValue>>(line)
            .is_ok_and(|m| m.contains_key("schema")),
    };
    let tagged = wire.and_then(|w| {
        let raw = w.schema?;
        Some((serde_json::from_str::<String>(raw.get()).ok()?, w.partial))
    });
    if owns_tag && tagged.is_none() {
        return LineOutcome::Unusable;   // carries a tag we cannot read as a schema string
    }
    if let Some((tag, partial)) = tagged {
        if tag == OPERATION_SCHEMA {
            // A partial record's bucket/key/status are not guaranteed to be what the wire
            // carried, so it cannot stand in for a demand read: counting one would invent
            // reuse on a key we are not sure was requested.
            if partial {
                return LineOutcome::OperationDropped;
            }
            // A tagged record whose FIELDS don't deserialize is malformed, not dropped
            // by a gate: it stays `Unusable` so the "this is a valid capture" count
            // never covers for a broken writer.
            let Ok(r) = serde_json::from_str::<OpRecord>(line) else {
                return LineOutcome::Unusable;
            };
            return match from_record(&r) {
                Some(ev) => LineOutcome::Event(ev),
                None => LineOutcome::OperationDropped,
            };
        }
        // Tagged with a schema this build KNOWS but does not model as a demand read: a
        // connection, an in-flight sample, a finding, a scorecard row. That is capture data,
        // so it is reported apart from junk — `analyze` on a connection-only capture used to
        // print the list of accepted file formats while `doctor` read the same file fine.
        if KNOWN_NON_TRACE_SCHEMAS.contains(&tag.as_str()) {
            return LineOutcome::OtherRecord;
        }
        // Tagged with a schema this build does not know at all — a FUTURE record shape.
        // Unusable rather than smuggled in through the tagless path below, whatever its
        // fields look like: modelling it with old code makes no compatibility decision.
        return LineOutcome::Unusable;
    }
    if let Ok(ev) = serde_json::from_str::<NormEvent>(line) {
        return LineOutcome::Event(ev);
    }
    match crate::ibm::from_ibm_line(line) {
        Some(ev) => LineOutcome::Event(ev),
        None => LineOutcome::Unusable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Op;

    #[test]
    fn a_schema_tagged_line_is_never_modelled_as_a_raw_replay_event() {
        // Raw NormEvent JSON is deliberately tagless, so a line carrying `schema` belongs to
        // a public record and must be routed by that tag alone. Trying NormEvent first let a
        // tagged object through purely because its fields overlapped, which is the opposite
        // of the exact-schema boundary the first-order records enforce: a FUTURE record shape
        // this build has never seen would be modelled by old code with no compatibility
        // decision ever being made.
        let unknown = r#"{"schema":"s3tap.operation/2","ts_ns":1,"op":"get","object_id":"b/k","size":1}"#;
        assert!(
            matches!(classify_trace_line(unknown), LineOutcome::Unusable),
            "an unknown schema tag is unusable however NormEvent-shaped its fields are"
        );

        // The tagless raw form still works — the reordering must not cost the documented
        // replay input.
        let raw = r#"{"ts_ns":1,"op":"get","object_id":"b/k","size":1}"#;
        assert!(matches!(classify_trace_line(raw), LineOutcome::Event(_)), "tagless raw JSON");

        // And the known tag is still routed to the record path rather than the raw one.
        let known = format!(
            r#"{{"schema":"{OPERATION_SCHEMA}","ts_ns":"1","op_id":"o","verb":"GET","s3_op":"GetObject","bucket":"b","key_hash":"k","http_status":200}}"#
        );
        assert!(
            matches!(classify_trace_line(&known), LineOutcome::Event(_) | LineOutcome::OperationDropped),
            "a known tag goes through the record path"
        );
    }

    #[test]
    fn a_schema_tag_that_is_not_a_string_still_counts_as_a_tag() {
        // Tag PRESENCE decides routing, and it used to be decided by a second parse into
        // `Option<String>` — so `schema` present but not a string read as ABSENT and the
        // line fell through to the tagless raw-NormEvent path. Five shapes did it, and each
        // is a way to smuggle a record past the exact-schema boundary the test above defends.
        // Keeping the tag as a RawValue makes presence independent of the value's type.
        for bad in [r#"7"#, r#"{}"#, r#"[]"#, r#"true"#, r#"null"#, r#"1.5"#, r#"[1,2]"#] {
            let line = format!(
                r#"{{"schema":{bad},"ts_ns":1,"op":"get","object_id":"b/k","size":1}}"#
            );
            assert!(
                matches!(classify_trace_line(&line), LineOutcome::Unusable),
                "`\"schema\":{bad}` owns a tag and must not be modelled as a raw event"
            );
        }
        // An explicit null is the one that a plain `Option<Box<RawValue>>` folds back into
        // `None`; it is covered above and called out here because the `some_raw`
        // deserializer exists for exactly that case and nothing else would catch its loss.
        assert!(matches!(
            classify_trace_line(r#"{"schema":null,"ts_ns":1,"op":"get","object_id":"b/k","size":1}"#),
            LineOutcome::Unusable
        ));
    }

    #[test]
    fn maps_a_get_operation() {
        // A real s3tap record has many more fields; the mirror ignores them.
        // ts_ns is wire-encoded as a decimal STRING — the mirror reads it as such.
        let json = r#"{ "verb": "GET", "s3_op": "GetObject",
            "bucket": "my-bucket", "key_hash": "sha256:deadbeef",
            "ts_ns": "1000", "http_status": 200, "content_length": 4096 }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        let ev = from_record(&r).unwrap();
        assert_eq!(ev.op, Op::Get);
        assert_eq!(ev.object_id, "my-bucket/sha256:deadbeef");
        assert_eq!(ev.ts_ns, 1000);
        assert_eq!(ev.status, Some(200));
        assert_eq!(ev.range, None);         // not parsed today
        assert_eq!(ev.size, Some(4096));    // Content-Length -> byte-capacity size
    }

    #[test]
    fn a_record_without_a_readable_timestamp_is_dropped() {
        // ts_ns absent, explicitly null, and present-but-garbage: all three used to
        // become an event at monotonic 0 — a fabricated position in the trace that
        // sorts before every real event and gives a finding a {0,0} window
        // indistinguishable from a genuine one. `NormEvent.ts_ns` has no "unknown"
        // state, so the only honest answer is to drop the record.
        for json in [
            r#"{ "s3_op": "GetObject", "bucket": "b", "key_hash": "sha256:x" }"#,
            r#"{ "s3_op": "GetObject", "bucket": "b", "key_hash": "sha256:x", "ts_ns": null }"#,
            r#"{ "s3_op": "GetObject", "bucket": "b", "key_hash": "sha256:x", "ts_ns": "" }"#,
            r#"{ "s3_op": "GetObject", "bucket": "b", "key_hash": "sha256:x", "ts_ns": "-1" }"#,
        ] {
            let r: OpRecord = serde_json::from_str(json).unwrap();
            assert!(from_record(&r).is_none(), "must not become t=0: {json}");
        }
    }

    #[test]
    fn only_the_exact_operation_tag_is_read_as_an_operation() {
        // The contract: a wrong or absent schema tag is rejected exactly. `OpRecord`'s
        // fields all default, so without the tag gate ANY JSON object parsed as a /1 op
        // — a future /2 record (which parse_records counts as unknown-schema) was being
        // ingested by `analyze` as a /1 GET.
        let body =
            r#""verb":"GET","s3_op":"GetObject","bucket":"b","key_hash":"sha256:x","ts_ns":"1000","http_status":200"#;
        let tagged = format!(r#"{{"schema":"{OPERATION_SCHEMA}",{body}}}"#);
        let ev = parse_trace_line(&tagged).expect("a correctly tagged op is ingested");
        assert_eq!((ev.op, ev.ts_ns), (Op::Get, 1000));

        for bad in [
            format!(r#"{{{body}}}"#),                             // no tag at all
            format!(r#"{{"schema":"s3tap.operation/2",{body}}}"#), // a future major
            format!(r#"{{"schema":"s3tap.connection/2",{body}}}"#), // another record
            format!(r#"{{"schema":null,{body}}}"#),               // an explicit null tag
        ] {
            assert!(parse_trace_line(&bad).is_none(), "wrong/absent tag must be skipped: {bad}");
        }

        // The two deliberately tagless formats keep their own branches, unaffected.
        let norm = r#"{"ts_ns":7,"op":"get","object_id":"b/k"}"#;
        assert_eq!(parse_trace_line(norm).unwrap().ts_ns, 7);
        assert!(crate::ibm::from_ibm_line("1232488 REST.GET.OBJECT k 0 1023").is_some());
    }

    #[test]
    fn absent_content_length_leaves_size_none() {
        // A GET whose head carried no Content-Length (chunked / unseen) has no
        // reliable size — the byte-capacity path must see None, not a fake 0/1.
        let json = r#"{ "s3_op": "GetObject", "bucket": "b", "key_hash": "sha256:x",
            "ts_ns": "1", "http_status": 200 }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        assert_eq!(from_record(&r).unwrap().size, None);
    }

    #[test]
    fn skips_record_without_object_identity() {
        // A ListObjects call has no object key -> not a cache access.
        let json = r#"{ "verb": "GET", "s3_op": "ListObjectsV2" }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        assert!(from_record(&r).is_none());
    }

    #[test]
    fn multi_object_delete_maps_via_s3_op() {
        // POST-based multi-delete: verb is POST but s3_op is DeleteObjects; it
        // must invalidate, so it maps to Op::Delete. Verb alone would miss this.
        let json = r#"{ "verb": "POST", "s3_op": "DeleteObjects",
            "bucket": "b", "key_hash": "sha256:x", "ts_ns": "1" }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        assert_eq!(from_record(&r).unwrap().op, Op::Delete);
    }

    #[test]
    fn write_and_multipart_ops_invalidate() {
        for op in ["PutObject", "UploadPart", "CompleteMultipartUpload"] {
            let json = format!(
                r#"{{ "s3_op": "{op}", "bucket": "b", "key_hash": "sha256:x", "ts_ns": "1" }}"#
            );
            let r: OpRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(from_record(&r).unwrap().op, Op::Put, "{op}");
        }
        let json = r#"{ "s3_op": "AbortMultipartUpload", "bucket": "b", "key_hash": "sha256:x",
            "ts_ns": "1" }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        assert_eq!(from_record(&r).unwrap().op, Op::Delete);
    }

    #[test]
    fn sub_resource_reads_are_ignored() {
        // GetObjectAcl carries a key but is NOT a body read — must be Op::Other,
        // not a cacheable GET (the broad-prefix bug this guards against).
        let json = r#"{ "s3_op": "GetObjectAcl", "bucket": "b", "key_hash": "sha256:x",
            "ts_ns": "1" }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        assert_eq!(from_record(&r).unwrap().op, Op::Other);
    }

    #[test]
    fn verb_fallback_when_s3_op_absent() {
        let json = r#"{ "verb": "PUT", "bucket": "b", "key_hash": "sha256:x", "ts_ns": "1" }"#;
        let r: OpRecord = serde_json::from_str(json).unwrap();
        assert_eq!(from_record(&r).unwrap().op, Op::Put);
    }

    /// Build one s3tap-shaped operation record.
    fn rec(s3_op: Option<&str>, verb: Option<&str>, key: &str, ts: u64, status: Option<u16>,
           len: Option<u64>) -> OpRecord {
        OpRecord {
            verb: verb.map(Into::into),
            s3_op: s3_op.map(Into::into),
            bucket: Some("b".into()),
            key_hash: Some(key.into()),
            ts_ns: Some(ts.to_string()),
            http_status: status,
            content_length: len,
        }
    }

    #[test]
    fn a_failed_get_is_never_a_demand_read() {
        // Only a served body is demand a cache could have answered. An absent status
        // is DROPPED too: on an OpRecord it is the aborted-in-flight-op signal (the
        // request's connection closed before any response arrived), not a served
        // body. A write is kept regardless, as an invalidation.
        for st in [400u16, 403, 404, 429, 500, 503, 304] {
            let r = rec(Some("GetObject"), None, "k", 1, Some(st), None);
            assert!(from_record(&r).is_none(), "{st} GET must not be a demand read");
        }
        assert_eq!(from_record(&rec(Some("GetObject"), None, "k", 1, Some(200), None)).unwrap().op, Op::Get);
        assert!(
            from_record(&rec(Some("GetObject"), None, "k", 1, None, None)).is_none(),
            "an aborted in-flight GET (no status) must not be a demand read"
        );
        // A failed WRITE still invalidates: over-invalidating only understates savings.
        assert_eq!(from_record(&rec(Some("PutObject"), None, "k", 1, Some(500), None)).unwrap().op, Op::Put);
    }

    #[test]
    fn the_status_gate_sits_after_classification_not_on_the_raw_s3_op() {
        // The bridge's old predicate keyed on `s3_op == Some("GetObject")`, while the
        // classifier falls back to the raw verb when `s3_op` is absent. An untrusted
        // line with verb GET, no s3_op and a 503 therefore skipped the status check and
        // still became Op::Get. Gating on the MAPPED op closes that drift for good.
        assert!(from_record(&rec(None, Some("GET"), "k", 1, Some(503), None)).is_none());
        assert_eq!(from_record(&rec(None, Some("GET"), "k", 1, Some(200), None)).unwrap().op, Op::Get);
    }

    #[test]
    fn a_503_retry_storm_counts_only_the_bodies_that_were_served() {
        // The concrete regression: 300 keys, each retried ~20 times under a 503 storm
        // (19 x 503 then 1 x 200) = 6300 records. Before the gate, `analyze` ingested
        // all 6300 as Op::Get over 300 keys — lru_max ~0.95, "CACHE IT, saves +0.95
        // origin fetches/access" — for a workload where not one of those hits was a
        // body a cache could have served. The truth is 300 successful GETs, one per
        // key, with ZERO reuse.
        let mut recs = Vec::new();
        let mut ts = 0u64;
        for k in 0..300u32 {
            for attempt in 0..21u32 {
                ts += 1;
                let status = if attempt == 20 { 200 } else { 503 };
                recs.push(rec(Some("GetObject"), None, &format!("k{k}"), ts, Some(status), Some(4096)));
            }
        }
        assert_eq!(recs.len(), 6300);
        let trace = from_records(&recs);
        assert_eq!(trace.len(), 300, "only the 200s survive");
        assert!(trace.iter().all(|e| e.op == Op::Get && e.status == Some(200)));
        let distinct: std::collections::HashSet<&str> =
            trace.iter().map(|e| e.object_id.as_str()).collect();
        assert_eq!(distinct.len(), 300, "one access per key: no reuse to cache");
    }

    #[test]
    fn a_ranged_get_is_not_an_object_level_read() {
        // A 206 carries no `range` (s3tap doesn't parse the header yet) and a `size`
        // that is the RANGE length, so object identity is the whole object and every
        // read of it collapses onto one key — and, in chunk mode, onto block #0.
        // Concrete: a 1 GiB object streamed as 1000 x 1 MiB ranged GETs used to read
        // as 1000 accesses to a single key (distinct 1, hit rate 0.999, "CACHE IT")
        // for a workload with ZERO reuse. It is now Op::Other: present in the trace,
        // invisible to every simulator.
        let stream: Vec<OpRecord> = (0..1000u64)
            .map(|i| rec(Some("GetObject"), None, "onegig", i + 1, Some(206), Some(1 << 20)))
            .collect();
        let trace = from_records(&stream);
        assert_eq!(trace.len(), 1000, "the events are kept, so the ranged fraction stays measurable");
        assert!(trace.iter().all(|e| e.op == Op::Other && e.status == Some(206)));
        assert_eq!(trace.iter().filter(|e| e.op == Op::Get).count(), 0);
        // Chunk mode drops non-GETs, so the #0 collapse is now unreachable rather
        // than silently reported as reuse.
        assert!(crate::ibm::to_blocks(&trace, 8 << 20).is_empty());
    }
}
