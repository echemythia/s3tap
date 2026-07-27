//! Task 3: redundant re-fetch. Per pid, 200-GETs repeated on the same OBJECT
//! with no write observed from this client in between. Object identity is
//! `(bucket, key_hash)`, never `key_hash` alone: the hash covers the object KEY
//! only (see `s3tap-schema`), so `s3://shard-001/manifest.json` and
//! `s3://shard-060/manifest.json` share a hash. Keying on the hash alone folded
//! a fan-out over N buckets into one "object re-downloaded N times" run — the
//! same identity `s3tap-replay`'s adapter and the throttling check already use.
//! Writes reset the run: per object the 200-GET stream is partitioned into maximal runs
//! delimited by writes (`PutObject`, `UploadPart`, `CompleteMultipartUpload`,
//! `DeleteObject` — `CopyObject` classifies as `PutObject` on the wire; batch
//! `DeleteObjects` is bucket-level with no key_hash, a documented blind spot),
//! and the first GET after a write is NOT redundant:
//! `redundant(key) = Σ_runs (run_len − 1)`.

use std::collections::BTreeMap;

use s3tap_doctor::Record;
use s3tap_schema::{
    Domain, Finding, FindingScope, MetricValue, Sample, SampleKind, Severity,
    TimeWindow, Unit,
};

use crate::fields::{advisory, Src};

const MIN_OPS: usize = 50;
const RUN_REPEAT_FLOOR: u32 = 3; // a run of >= 4 GETs (repeats >= 3) marks the key
const WASTED_BYTES_FLOOR: u64 = 100 << 20; // 100 MiB
const REDUNDANT_COUNT_FLOOR: u64 = 1000; // OR-arm: catches tiny-object storms

pub(crate) const WRITE_OPS: [&str; 4] = ["PutObject", "UploadPart", "CompleteMultipartUpload", "DeleteObject"];

/// Object identity: bucket + key hash. `bucket` is `None` when the SNI/Host join
/// failed — those ops group together, which is the best identity the capture has.
type ObjId<'a> = (Option<&'a str>, &'a str);

pub(crate) fn check_redundant_refetch(records: &[Record]) -> Vec<Finding> {
    // pid -> object -> time-ordered GETs (ts, content_length). Writes are indexed
    // CAPTURE-WIDE per object: a write from ANY pid on this host changes the
    // object, so it must reset every pid's run on that object ("this client" =
    // the capture, not one process).
    let mut gets_by_pid: BTreeMap<u32, BTreeMap<ObjId, Vec<(u64, Option<u64>)>>> = BTreeMap::new();
    let mut writes_by_obj: BTreeMap<ObjId, Vec<u64>> = BTreeMap::new();
    let mut no_ts_by_pid: BTreeMap<u32, usize> = BTreeMap::new();
    // Partial GETs: in the population, out of the run detection, and so `excluded`.
    let mut partial_gets_by_pid: BTreeMap<u32, usize> = BTreeMap::new();
    for r in records {
        if let Record::Operation(o) = r {
            let Some(key) = o.key_hash.as_deref() else { continue };
            let obj = (o.bucket.as_deref(), key);
            let is_get_200 = o.s3_op.as_deref() == Some("GetObject") && o.http_status == Some(200);
            let is_write = o.s3_op.as_deref().is_some_and(|s| WRITE_OPS.contains(&s));
            // `partial` excludes a GET from the numerator but NOT a write from the
            // invalidation index. The two sets have opposite failure directions: a GET we are
            // unsure of would INVENT a redundant re-fetch, while a write we drop REMOVES the
            // very thing that makes a re-fetch legitimate. `writes_by_obj` only ever
            // de-escalates, so leaving records out of it can only manufacture a finding — the
            // same argument `check_throttling`'s recovery index makes. A large PutObject or
            // UploadPart is exactly the op that reads `partial` (its head is truncated at the
            // capture cap), so this was not a corner: a client that PUT then re-GET 3x, 400
            // times over, reported "1 object re-downloaded unchanged 4+ times; 1199 redundant
            // GET requests" purely because the PUTs carried the flag.
            if o.partial && !is_write {
                if is_get_200 {
                    *partial_gets_by_pid.entry(o.app.pid).or_default() += 1;
                }
                continue;
            }
            if !is_get_200 && !is_write {
                continue;
            }
            let Some(ts) = o.ts_ns else {
                *no_ts_by_pid.entry(o.app.pid).or_default() += 1; // ts is the ordering key
                continue;
            };
            if is_write {
                writes_by_obj.entry(obj).or_default().push(ts);
            } else {
                gets_by_pid
                    .entry(o.app.pid)
                    .or_default()
                    .entry(obj)
                    .or_default()
                    .push((ts, o.content_length));
            }
        }
    }
    for w in writes_by_obj.values_mut() {
        w.sort_unstable();
    }

    let mut out = Vec::new();
    for (&pid, objs) in &gets_by_pid {
        // The gate counts GETs (the redundancy story is GET-centric; writes
        // partition runs but are not evidence of over-fetching).
        let ops: usize = objs.values().map(Vec::len).sum();
        if ops < MIN_OPS {
            continue;
        }
        // (object, redundant, bytes, sizeless-repeats)
        let mut flagged: Vec<(ObjId, u64, u64, usize)> = Vec::new();
        for (&obj, evs) in objs {
            let mut evs = evs.clone();
            evs.sort_unstable_by_key(|(ts, _)| *ts);
            let writes = writes_by_obj.get(&obj).map(Vec::as_slice).unwrap_or(&[]);
            let (mut key_redundant, mut key_bytes) = (0u64, 0u64);
            let mut key_size_excluded = 0usize;
            let mut run_len: u32 = 0;
            let mut max_run: u32 = 0;
            let mut w_idx = 0usize; // next capture-wide write not yet consumed
            for (ts, size) in &evs {
                // Any write (from any pid) before this GET resets the run.
                if w_idx < writes.len() && writes[w_idx] < *ts {
                    while w_idx < writes.len() && writes[w_idx] < *ts {
                        w_idx += 1;
                    }
                    run_len = 0;
                }
                run_len += 1;
                max_run = max_run.max(run_len);
                if run_len > 1 {
                    key_redundant += 1; // this GET repeats within the run
                    match size {
                        // content_length is unvalidated record input; a crafted capture
                        // asserting near-u64::MAX object sizes must not panic (debug) /
                        // wrap (release). Matches churn.rs's saturating convention.
                        Some(s) => key_bytes = key_bytes.saturating_add(*s),
                        None => key_size_excluded += 1,
                    }
                }
            }
            if max_run > RUN_REPEAT_FLOOR {
                flagged.push((obj, key_redundant, key_bytes, key_size_excluded));
            }
        }
        if flagged.is_empty() {
            continue;
        }
        // Impact and headline are summed over the FLAGGED objects only. Summing
        // every object made the gate (and the "N MiB wasted" number) describe
        // traffic the check itself declined to name — a 3 KB finding could carry
        // a 60 GiB headline sourced entirely from unflagged short runs.
        let redundant_gets = flagged.iter().fold(0u64, |a, (_, r, _, _)| a.saturating_add(*r));
        let wasted_bytes = flagged.iter().fold(0u64, |a, (_, _, b, _)| a.saturating_add(*b));
        let size_excluded: usize = flagged.iter().map(|(_, _, _, x)| *x).sum();
        if wasted_bytes < WASTED_BYTES_FLOOR && redundant_gets < REDUNDANT_COUNT_FLOOR {
            continue;
        }
        flagged.sort_unstable_by_key(|(_, r, b, _)| std::cmp::Reverse((*b, *r)));
        let (top_obj, top_r, ..) = flagged[0];
        let top_key = top_obj.1;
        let ts_all: Vec<u64> = objs.values().flatten().map(|(ts, _)| *ts).collect();
        let window = TimeWindow {
            ts_start: ts_all.iter().copied().min().unwrap_or(0),
            ts_end: ts_all.iter().copied().max().unwrap_or(0),
        };
        out.push(advisory(
            "advisor-redundant-refetch",
            Src::Ops,
            Domain::Client,
            Severity::Advisory,
            "objects re-downloaded unchanged",
            format!(
                "pid {pid}: {} object(s) re-downloaded unchanged 4+ times; {redundant_gets} \
                 redundant GET requests across those objects ({:.0} MiB wasted; top: {}.. \
                 x{top_r}). A conditional GET (If-None-Match) \
                 returns 304 when unchanged — it still bills as a GET but skips the body (saves \
                 egress: free same-region, billed cross-region/internet). A local cache skips the \
                 request too (see the caching advisory). Caveats: 'unchanged' means no write \
                 observed from THIS client (external writers are invisible); ETag headers are not \
                 captured; ranged (206) re-reads are not counted.",
                flagged.len(),
                wasted_bytes as f64 / (1u64 << 20) as f64,
                top_key.chars().take(8).collect::<String>(),
            ),
            "wasted_bytes",
            Some(MetricValue::Num(wasted_bytes as f64)),
            Unit::None, // the schema has no Bytes unit; the summary carries MiB
            format!(
                "run repeats >= {RUN_REPEAT_FLOOR}, ops >= {MIN_OPS}, wasted >= 100 MiB OR \
                 redundant >= {REDUNDANT_COUNT_FLOOR}"
            ),
            FindingScope { app_pid: Some(pid), ..Default::default() },
            window,
            Sample {
                judged: ops,
                // Partial GETs are dropped from the run detection (their key may not be what
                // the wire carried), and were previously counted in neither field — a capture
                // holding 560 GETs of one key, 500 of them partial, published 60/0.
                excluded: no_ts_by_pid.get(&pid).copied().unwrap_or(0)
                    + size_excluded
                    + partial_gets_by_pid.get(&pid).copied().unwrap_or(0),
                kind: SampleKind::Operation,
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn repeat_200s_fire_with_byte_math() {
        // 60 GETs of one 4 MiB object, no writes: 59 redundant x 4 MiB = 236 MiB.
        let recs = fixtures::refetch_ops("bigkey", 60, 200, Some(4 << 20));
        let f = check_redundant_refetch(&recs);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].finding_id, "advisor-redundant-refetch");
        assert!(f[0].summary.contains("236 MiB"), "{}", f[0].summary);
        assert!(f[0].summary.contains("59 redundant"));
    }

    #[test]
    fn intervening_write_resets_the_run() {
        // GET x30, PUT, GET x30: runs of 30+30 -> 58 redundant (not 59), and the
        // GET right after the write is not redundant.
        let mut recs = fixtures::refetch_ops("k", 30, 200, Some(8 << 20));
        recs.push(fixtures::op(9, 3000, 90, 30 * 2_000_000_000, 40_000_000,
                               "PutObject", "k", 200, Some(8 << 20)));
        recs.extend((0..30u32).map(|i| fixtures::op(
            9, 3000, 100 + i, (40 + u64::from(i)) * 2_000_000_000, 40_000_000,
            "GetObject", "k", 200, Some(8 << 20))));
        let f = check_redundant_refetch(&recs);
        assert_eq!(f.len(), 1);
        assert!(f[0].summary.contains("58 redundant"), "{}", f[0].summary);
    }

    #[test]
    fn count_arm_catches_tiny_object_storm() {
        // 1200 GETs of a 1 KB object: ~1.2 MB (far under the byte floor) but
        // >= 1000 redundant requests -> fires via the OR-count arm.
        let recs = fixtures::refetch_ops("tiny", 1200, 200, Some(1024));
        let f = check_redundant_refetch(&recs);
        assert_eq!(f.len(), 1, "count arm must fire");
    }

    #[test]
    fn missing_sizes_are_excluded_not_zeroed() {
        // 1200 repeats with None sizes: byte arm can't fire, count arm does;
        // exclusions are counted in the sample.
        let recs = fixtures::refetch_ops("k", 1200, 200, None);
        let f = check_redundant_refetch(&recs);
        assert_eq!(f.len(), 1);
        assert!(f[0].sample.excluded >= 1199);
    }

    #[test]
    fn cross_pid_write_resets_the_run() {
        // pid 9 GETs key k 60x; pid 8 PUTs k midway: the object changed, so
        // pid 9's run must reset (58 redundant, not 59).
        let mut recs = fixtures::refetch_ops("k", 60, 200, Some(8 << 20));
        let mut put = fixtures::op(8, 9000, 0, 29 * 2_000_000_000 + 1, 40_000_000,
                                   "PutObject", "k", 200, Some(8 << 20));
        if let Record::Operation(o) = &mut put {
            o.connection_reused = false;
        }
        recs.push(put);
        let f = check_redundant_refetch(&recs);
        assert_eq!(f.len(), 1);
        assert!(f[0].summary.contains("58 redundant"), "{}", f[0].summary);
    }

    #[test]
    fn non_ascii_key_hash_does_not_panic() {
        // Crafted JSONL can carry non-ASCII key hashes; the top-key prefix must
        // not byte-slice across a char boundary.
        let recs = fixtures::refetch_ops("ключ-объекта-显示", 1200, 200, Some(1024));
        let f = check_redundant_refetch(&recs);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn non_200_repeats_are_silent() {
        let recs = fixtures::refetch_ops("k", 1200, 304, None);
        assert!(check_redundant_refetch(&recs).is_empty());
    }
}
