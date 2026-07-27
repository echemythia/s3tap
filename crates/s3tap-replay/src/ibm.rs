//! Adapter for the IBM Cloud Object Storage trace format (SNIA IOTTA #36305) —
//! a public production object-store trace, used here to cross-check the harness
//! against real access patterns (not just synthetic ground truth).
//!
//! Line format (whitespace-separated):
//!   <ts_ms> <REST.VERB.RESOURCE> <object_id> [<size>] [<start_off> <end_off>]
//! e.g. `1232488 REST.GET.OBJECT 95d363d3fbdc0b03 1168 0 1167`
//! (timestamp is milliseconds from the start of trace collection).
//!
//! We populate `range` (the byte span this GET touched, from the offset columns,
//! or `[0, size-1]` for a whole-object read) but leave `size = None`. That's
//! deliberate: OBJECT-mode capacity is object-count-based (the driver keys on
//! `object_id` and ignores `range`), so object-mode numbers are unchanged and
//! comparable to the synthetic/s3tap paths — while BLOCK mode (`to_blocks`) uses
//! `range` to expand each access into the blocks it touched.

use crate::trace::{NormEvent, Op};

/// Parse one IBM COS trace line into a normalized event. Returns `None` for a
/// blank/malformed line (fewer than 3 fields, non-numeric timestamp, or a
/// second field that isn't a `REST.*` operation). Populates `range` from the
/// offset columns (or `[0, size-1]` for a whole-object read); `size` stays
/// `None` so object-mode capacity remains count-based.
pub fn from_ibm_line(line: &str) -> Option<NormEvent> {
    let mut f = line.split_whitespace();
    let ts_ms: u64 = f.next()?.parse().ok()?;
    let req = f.next()?;
    let object_id = f.next()?.to_string();
    let size = f.next().and_then(|s| s.parse::<u64>().ok());
    let start = f.next().and_then(|s| s.parse::<u64>().ok());
    let end = f.next().and_then(|s| s.parse::<u64>().ok());
    // Chunk-based model: every GET carries the byte span it touched, so block
    // mode expands it into the `ceil(span/B)` fixed-size chunks it occupies —
    // a large whole-object read fills many chunks, a small one a single chunk.
    //   - explicit offsets present -> that span (covers both partial reads and a
    //     whole-object read, whose IBM offsets are `[0, size-1]`);
    //   - no offsets but a known size -> the whole object spans `[0, size-1]`;
    //   - neither known -> `None`, a single-chunk (`#0`) fallback.
    // (`size == 0` guards the `sz - 1` underflow; an empty object -> single chunk.)
    let range = match (start, end) {
        (Some(s), Some(e)) if e >= s => Some((s, e)),
        _ => match size {
            Some(sz) if sz > 0 => Some((0, sz - 1)),
            _ => None,
        },
    };
    let op = ibm_op(req)?;
    Some(NormEvent {
        ts_ns: ts_ms.saturating_mul(1_000_000),
        op,
        object_id,
        range,
        size: None, // keep object-mode capacity count-based; block mode uses `range`
        version: None,
        status: None,
    })
}

/// Object-scoped resource tokens in the `REST.VERB.RESOURCE` request type. Only a read of
/// one of these is a read of an OBJECT. `REST.GET.BUCKET` (a LIST), `REST.GET.ACL`,
/// `REST.GET.LOGGING_STATUS` and the rest of the bucket-scoped family are requests about
/// metadata, and the trace still carries an id in the object column for them, so reading the
/// verb alone turned every LIST into a cacheable read of that id: repeated LISTs of one
/// bucket looked like repeated hits on one hot object, inflating the hit rate, the distinct
/// count and the cache verdict for IBM input.
/// Deliberately NOT `UPLOADS` or `UPLOAD`. The resource token's scope depends on the verb:
/// `POST /key?uploads` (initiate MPU) logs `REST.POST.UPLOADS` and is object-scoped, but
/// `GET /?uploads` is **ListMultipartUploads** and logs the same token while being
/// bucket-scoped — so listing one bucket repeatedly read as repeated hits on one hot object,
/// which is the exact defect this gate was added to stop. Only reads consult this list, and
/// `POST.UPLOADS` is a write that never reaches it. `REST.GET.UPLOAD` is ListParts, an XML
/// part manifest rather than object bytes, so it is out for the same reason `GET.ACL` is.
const OBJECT_RESOURCES: [&str; 2] = ["OBJECT", "PART"];

/// Map a `REST.VERB.RESOURCE` request type to our op kind. Returns `None` when
/// the token isn't a `REST.*` op at all (so the line is skipped). Unknown REST
/// verbs map to `Op::Other` (kept, but ignored by the driver).
///
/// READS require an object-scoped resource; anything else is `Op::Other`. WRITES do not,
/// deliberately, and this is the one place the two directions differ. A write's only role in
/// the model is invalidation, and this file already states the rule for that: over-
/// invalidating understates savings, which is the safe direction. Demoting a bucket-scoped
/// write to `Op::Other` would DROP an invalidation, the unsafe direction, to avoid a cost
/// that is at worst evicting an id nothing reads. So an unrecognised resource still
/// invalidates on a write and still fails to count as a read.
fn ibm_op(req: &str) -> Option<Op> {
    let mut parts = req.strip_prefix("REST.")?.split('.');
    let verb = parts.next()?;
    let on_object = parts.next().is_some_and(|r| OBJECT_RESOURCES.contains(&r));
    Some(match verb {
        "GET" if on_object => Op::Get,
        "HEAD" if on_object => Op::Head,
        // A read of something that is not an object: kept as a line, never as a demand read.
        "GET" | "HEAD" => Op::Other,
        "PUT" | "POST" | "COPY" => Op::Put, // writes / multipart / copy: invalidate
        "DELETE" => Op::Delete,
        _ => Op::Other,
    })
}

/// Expand a trace into BLOCK-granular accesses for chunk-level analysis — the
/// chunk-based cache model. A GET whose `range` is `[s, e]` touches blocks
/// `s/B ..= e/B`; we emit one access per touched block, id `"<object>#<blk>"` in
/// ascending (read) order. Because `from_ibm_line` gives every sized GET a span
/// (`[0, size-1]` for a whole-object read), a large object naturally occupies
/// `ceil(size/B)` chunks and a small one a single chunk; only a GET of unknown
/// extent collapses to a single block `#0`. Each access is capped at 4096 blocks
/// (below), so a pathological huge object is truncated rather than exploding.
/// HEAD/Other are dropped (they are no-ops for every simulator rung anyway).
///
/// **PUT/DELETE are forwarded as per-chunk invalidations.** They used to be
/// dropped here, which meant the DEFAULT `analyze` mode did not model write
/// invalidation at all while object mode did, so the two disagreed on the same
/// capture: a read-after-write workload (2500 x {PUT k, GET k}) came out
/// `advisor-cache-nogo` / "saves 0%" object-level and "CACHE IT, saves +0.999
/// origin fetches/access" in chunk mode, off a modelled cache serving bytes the
/// client had just overwritten. Writes are invalidation SIGNALS (see
/// `adapt::demand_op`, which forwards them regardless of status because
/// over-invalidating only understates savings, the safe direction), so the same
/// safe direction applies per chunk: a write to an object invalidates every chunk
/// of that object the trace has already touched, not merely the extent the write
/// itself declares. That extent is usually unknown anyway — an s3tap capture's
/// `content_length` is a RESPONSE body length, so a PUT arrives with no size and
/// would otherwise invalidate chunk `#0` alone and leave `#1..N` stale.
///
/// Invalidating exactly the already-emitted chunk keys is what makes the fan-out
/// bounded rather than bounded by the address space: a chunk the trace has never
/// touched cannot be resident, so an invalidation for it would be a no-op. The
/// same argument runs a second time, and it is what keeps the EXPANSION linear:
/// once a chunk has been invalidated it is not resident either, so re-invalidating
/// it on the next write is equally a no-op. The write therefore CONSUMES the
/// object's touched set instead of accumulating it, and only a fresh read puts a
/// chunk back in play.
///
/// That is not a micro-optimization, it is the difference between a linear and a
/// QUADRATIC expansion. Accumulating made every write emit the object's whole
/// cumulative chunk history, which itself grows without limit: a trace alternating
/// `{GET o range=[k*20GiB, k*20GiB+16MiB]}` with `{PUT o}` at 4 KiB blocks turned
/// 401 input lines (~36 KB of JSONL) into 83,148,801 events, each with its own
/// allocated object id (~8 GB), and a 2001-line file was OOM-killed. The 4096-block
/// cap below guards a READ's own extent and had no counterpart on the write path.
/// Consuming the set bounds the total write expansion by the total READ expansion
/// (a write can only emit chunks some read already emitted, plus its own capped
/// extent), so the whole output is linear in the input at the same 4096 ceiling
/// the read path already carries. `analyze --max-events` is no help here: it bounds
/// PARSED events, not expanded ones.
///
/// The residual hole is a chunk a PREFETCHER speculatively inserted and no demand
/// read has touched since the last write, which stays resident across the next one.
/// It is a modelling artifact of the same class as the pre-existing one (a
/// prefetched chunk beyond every observed extent) rather than a demand-path claim.
/// This function cannot close it on its own: `to_blocks` only knows the DEMAND-
/// touched set (`touched`, above), not what any downstream predictor speculatively
/// inserted into a simulator it never sees. Closing it means teaching every
/// cache type in this crate that consumes a block trace (`Sim`, `Arc`, `S3Fifo`,
/// `hybrid::WLfu`/`AdaptivePool`) to invalidate by OBJECT PREFIX (`"<base>"` and
/// every `"<base>#N"`) instead of by the exact emitted chunk id, since a write
/// event's own id is always one specific already-touched chunk. Left open
/// uniformly across every retention/prefetch rung rather than fixed for some and
/// not others, which would make otherwise-comparable rows in the same
/// per-policy table (`driver::sweep`/`sweep_blocks`) disagree on this axis.
///
/// A separate simplification: a whole-object read is linearized into its per-chunk
/// accesses, so a prefetcher can appear to "read ahead" within a single physical
/// fetch — real gains come from RE-reads of already-resident chunks.
pub fn to_blocks(trace: &[NormEvent], block_bytes: u64) -> Vec<NormEvent> {
    use std::collections::{BTreeSet, HashMap};
    let b = block_bytes.max(1);
    let mut out = Vec::new();
    // Chunk keys emitted for each object SINCE ITS LAST WRITE == the keys that can
    // still be resident, which is exactly what the next write has to invalidate.
    // Only built when the trace HAS writes: the study's IBM traces are read-only, and
    // a set per object would cost more memory than the expanded trace itself on a
    // multi-million-key one for bookkeeping nothing would ever read.
    let has_writes = trace.iter().any(|e| matches!(e.op, Op::Put | Op::Delete));
    let mut touched: HashMap<&str, BTreeSet<u64>> = HashMap::new();
    for ev in trace {
        match ev.op {
            Op::Get | Op::Put | Op::Delete => {}
            // No body, no residency effect: a pure no-op for the cache and the model.
            Op::Head | Op::Other => continue,
        }
        // The touched byte span. `range` is authoritative (IBM lines carry it);
        // when only a whole-object `size` is known — e.g. an s3tap capture, which
        // records Content-Length in `size` but has no Range header — treat it as
        // the whole object `[0, size-1]` so a large object still expands into its
        // chunks instead of collapsing to a single `#0`. Neither known -> `#0`.
        let (s, e) = ev
            .range
            .or_else(|| ev.size.filter(|&sz| sz > 0).map(|sz| (0, sz - 1)))
            .unwrap_or((0, 0));
        // Normalize an inverted range (start > end). `from_ibm_line` rejects `e < s` at
        // parse time, but a hand-authored / corrupted raw NormEvent JSON line reaches here
        // unchecked; without this, `b0 > b1` makes `b0..=b1` empty and the access silently
        // vanishes from block mode while object mode still counts it (a mode divergence).
        let (s, e) = if e >= s { (s, e) } else { (e, s) };
        let b0 = s / b;
        // Safety cap: never expand a single access into more than 4096 blocks
        // (partial reads are bounded chunks; this guards against a pathological span).
        // saturating_add avoids overflow when b0 is near u64::MAX (malformed line).
        let b1 = (e / b).min(b0.saturating_add(4095));
        // A read touches exactly its own extent. A write invalidates the UNION of its
        // own (usually unknown) extent and every chunk of the object already in play.
        let emit = |blk: u64, out: &mut Vec<NormEvent>| {
            out.push(NormEvent {
                ts_ns: ev.ts_ns,
                op: ev.op,
                object_id: format!("{}#{}", ev.object_id, blk),
                range: None,
                size: None,
                version: None,
                status: ev.status,
            });
        };
        if ev.op == Op::Get {
            for blk in b0..=b1 {
                emit(blk, &mut out);
            }
            if has_writes {
                touched.entry(ev.object_id.as_str()).or_default().extend(b0..=b1);
            }
        } else {
            // REMOVE, not read: the chunks this write invalidates stop being resident,
            // so the next write owes them nothing until a read puts them back. Keeping
            // them made the expansion quadratic (see above).
            let mut seen = touched.remove(ev.object_id.as_str()).unwrap_or_default();
            seen.extend(b0..=b1); // the write's own extent, capped like a read's
            for blk in seen {
                emit(blk, &mut out);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_object_scoped_reads_are_demand_reads() {
        let op = |req: &str| from_ibm_line(&format!("100 {req} id 8 0 7")).map(|e| e.op);

        // Object-scoped reads are demand reads, multipart resources included.
        assert_eq!(op("REST.GET.OBJECT"), Some(Op::Get));
        assert_eq!(op("REST.HEAD.OBJECT"), Some(Op::Head));
        assert_eq!(op("REST.GET.PART"), Some(Op::Get));

        // Bucket-scoped reads are NOT. The trace still carries an id in the object column
        // for them, so reading the verb alone made every LIST a cacheable read of that id:
        // repeated LISTs of one bucket read as repeated hits on one hot object.
        assert_eq!(op("REST.GET.BUCKET"), Some(Op::Other), "a LIST is not an object read");
        assert_eq!(op("REST.GET.ACL"), Some(Op::Other));
        assert_eq!(op("REST.GET.LOGGING_STATUS"), Some(Op::Other));
        assert_eq!(op("REST.HEAD.BUCKET"), Some(Op::Other));
        // No resource part at all is not an object read either.
        assert_eq!(op("REST.GET"), Some(Op::Other));

        // WRITES keep invalidating whatever the resource says, which is the asymmetry this
        // check is built on: over-invalidating understates savings (the safe direction this
        // file already follows), while demoting a write to Other would DROP an invalidation.
        assert_eq!(op("REST.PUT.OBJECT"), Some(Op::Put));
        assert_eq!(op("REST.PUT.BUCKETPOLICY"), Some(Op::Put), "a write still invalidates");
        assert_eq!(op("REST.DELETE.OBJECT"), Some(Op::Delete));
        assert_eq!(op("REST.POST.UPLOADS"), Some(Op::Put));

        // Not a REST line at all: skipped, as before.
        assert_eq!(op("BATCH.DELETE.OBJECT"), None);

        // The end-to-end shape the issue reported: three LISTs of one bucket must not read
        // as three demand accesses to one object.
        let lines = "1 REST.GET.BUCKET b 8 0 7\n2 REST.GET.BUCKET b 8 0 7\n3 REST.GET.BUCKET b 8 0 7";
        let evs: Vec<NormEvent> = lines.lines().filter_map(from_ibm_line).collect();
        assert_eq!(evs.len(), 3, "the lines are still parsed, not dropped");
        assert!(evs.iter().all(|e| e.op == Op::Other), "none is a demand read");
    }

    #[test]
    fn whole_object_get_carries_full_span_for_chunking() {
        // The canonical SNIA example reads bytes 0..1167 of a 1168-byte object —
        // the WHOLE object. In the chunk-based model it carries its full span so
        // block mode can split it into ceil(size/B) chunks (here 1 at 4 KB, 3 at
        // 512 B). `size` stays None so OBJECT-mode capacity remains count-based.
        let ev = from_ibm_line("1232488 REST.GET.OBJECT 95d363d3fbdc0b03 1168 0 1167").unwrap();
        assert_eq!(ev.op, Op::Get);
        assert_eq!(ev.object_id, "95d363d3fbdc0b03");
        assert_eq!(ev.ts_ns, 1_232_488 * 1_000_000);
        assert_eq!(ev.range, Some((0, 1167))); // full extent -> expands by size
        assert_eq!(ev.size, None);
        assert_eq!(to_blocks(std::slice::from_ref(&ev), 4096).len(), 1); // small object -> 1 chunk
        let small = to_blocks(&[ev], 512);
        let ids: Vec<&str> = small.iter().map(|e| e.object_id.as_str()).collect();
        assert_eq!(ids, ["95d363d3fbdc0b03#0", "95d363d3fbdc0b03#1", "95d363d3fbdc0b03#2"]);
    }

    #[test]
    fn size_only_get_expands_by_size_for_s3tap_captures() {
        // An s3tap capture records Content-Length in `size` and leaves `range`
        // None (it has no Range header). Chunk mode must still expand a large
        // object into its chunks rather than collapsing to a single `#0`.
        let ev = NormEvent {
            ts_ns: 1,
            op: Op::Get,
            object_id: "obj".into(),
            range: None,
            size: Some(20 * 1024 * 1024), // 20 MB
            version: None,
            status: Some(200),
        };
        let blocks = to_blocks(&[ev], 8 * 1024 * 1024); // ceil(20/8) = 3 chunks
        let ids: Vec<&str> = blocks.iter().map(|e| e.object_id.as_str()).collect();
        assert_eq!(ids, ["obj#0", "obj#1", "obj#2"]);
    }

    #[test]
    fn whole_object_get_without_offsets_uses_size() {
        // No offset columns, only a size -> the whole object spans [0, size-1],
        // so a 10 KB object at 4 KB blocks occupies chunks #0..#2.
        let ev = from_ibm_line("5 REST.GET.OBJECT big 10240").unwrap();
        assert_eq!(ev.range, Some((0, 10239)));
        assert_eq!(to_blocks(&[ev], 4096).len(), 3);
    }

    #[test]
    fn partial_range_is_captured() {
        // A seek/chunk read (not whole-object): bytes 4096..8191 of a 1 MB object.
        let ev = from_ibm_line("10 REST.GET.OBJECT k 1048576 4096 8191").unwrap();
        assert_eq!(ev.range, Some((4096, 8191)));
    }

    #[test]
    fn zero_size_get_does_not_panic() {
        // Empty object / malformed line: `sz = 0` must not underflow `sz - 1`.
        // The explicit `0 0` offsets span byte 0 -> a single chunk (#0), no panic.
        let ev = from_ibm_line("1 REST.GET.OBJECT x 0 0 0").unwrap();
        assert_eq!(ev.op, Op::Get);
        assert_eq!(ev.range, Some((0, 0)));
        assert_eq!(to_blocks(&[ev], 4096).len(), 1);
    }

    #[test]
    fn to_blocks_expands_a_ranged_get() {
        // Bytes 0..9999 at 4096-byte blocks -> blocks 0,1,2.
        let ev = from_ibm_line("1 REST.GET.OBJECT obj 100000 0 9999").unwrap();
        let blocks = to_blocks(&[ev], 4096);
        let ids: Vec<&str> = blocks.iter().map(|e| e.object_id.as_str()).collect();
        assert_eq!(ids, ["obj#0", "obj#1", "obj#2"]);
    }

    #[test]
    fn writes_are_forwarded_as_per_chunk_invalidations() {
        // Chunk mode used to DROP every PUT/DELETE, so it modelled no invalidation at
        // all — and it is the default for `analyze`. A whole-object write must reach
        // every chunk of the object the trace has touched, not just the one its own
        // (usually unknown) extent implies.
        let get = |ts, sz: Option<u64>| NormEvent {
            ts_ns: ts, op: Op::Get, object_id: "k".into(), range: None,
            size: sz, version: None, status: Some(200),
        };
        // 20 MiB read at 8 MiB blocks -> k#0..k#2, then an extent-less PUT.
        let trace = vec![
            get(1, Some(20 * 1024 * 1024)),
            NormEvent { ts_ns: 2, op: Op::Put, size: None, ..get(2, None) },
            get(3, Some(20 * 1024 * 1024)),
        ];
        let blocks = to_blocks(&trace, 8 * 1024 * 1024);
        let puts: Vec<&str> = blocks
            .iter()
            .filter(|e| e.op == Op::Put)
            .map(|e| e.object_id.as_str())
            .collect();
        assert_eq!(puts, ["k#0", "k#1", "k#2"], "the write invalidates every touched chunk");
        assert_eq!(blocks.iter().filter(|e| e.op == Op::Get).count(), 6);
        // A DELETE behaves the same way, and HEAD/Other stay dropped.
        let trace = vec![
            get(1, Some(9 * 1024 * 1024)), // k#0, k#1
            NormEvent { ts_ns: 2, op: Op::Delete, ..get(2, None) },
            NormEvent { ts_ns: 3, op: Op::Head, ..get(3, None) },
            NormEvent { ts_ns: 4, op: Op::Other, ..get(4, None) },
        ];
        let blocks = to_blocks(&trace, 8 * 1024 * 1024);
        let ids: Vec<(&str, Op)> =
            blocks.iter().map(|e| (e.object_id.as_str(), e.op)).collect();
        assert_eq!(
            ids,
            [("k#0", Op::Get), ("k#1", Op::Get), ("k#0", Op::Delete), ("k#1", Op::Delete)]
        );
    }

    #[test]
    fn a_write_before_any_read_invalidates_nothing_resident() {
        // Nothing of the object can be resident yet, so the write's fan-out is bounded
        // by its own extent rather than by the address space.
        let put = NormEvent {
            ts_ns: 1, op: Op::Put, object_id: "k".into(), range: None,
            size: None, version: None, status: None,
        };
        let blocks = to_blocks(&[put], 8 * 1024 * 1024);
        assert_eq!(blocks.len(), 1, "one no-op invalidation, not a scan of the key space");
        assert_eq!(blocks[0].object_id, "k#0");
    }

    #[test]
    fn the_write_expansion_is_linear_in_the_input_not_quadratic() {
        // The DoS shape: every GET touches a FRESH span of the same object, so the
        // object's cumulative chunk history grows without limit, and an accumulating
        // write set made each PUT re-emit all of it. Measured on the shipped code at
        // 4 KiB blocks with 16 MiB reads (4096 chunks each): 21 input lines produced
        // 266,241 events, 101 produced 5,427,201, 401 produced 83,148,801 (~8 GB of
        // allocated object ids) and 2001 was OOM-killed, off ~36 KB of JSONL.
        //
        // Scaled down here (8 chunks per read) so the test is fast, but the SHAPE and
        // the growth law are the same: the assertion is a per-line bound, checked at
        // two sizes, so a quadratic term cannot hide inside a constant.
        const BLOCK: u64 = 4096;
        const CHUNKS_PER_READ: u64 = 8;
        let build = |pairs: u64| -> Vec<NormEvent> {
            let mut t = Vec::new();
            for k in 0..pairs {
                // A fresh, non-overlapping span each time (the growth driver).
                let start = k * CHUNKS_PER_READ * BLOCK;
                t.push(NormEvent {
                    ts_ns: k * 2,
                    op: Op::Get,
                    object_id: "o".into(),
                    range: Some((start, start + CHUNKS_PER_READ * BLOCK - 1)),
                    size: None,
                    version: None,
                    status: Some(200),
                });
                t.push(NormEvent {
                    ts_ns: k * 2 + 1,
                    op: Op::Put,
                    object_id: "o".into(),
                    range: None,
                    size: None,
                    version: None,
                    status: Some(200),
                });
            }
            t
        };
        // Per {GET, PUT} PAIR, at most: the read's capped extent, plus the write's
        // (the same chunks, plus the single block its own sizeless extent implies).
        // Quadratic growth blows this at any size — at 250 pairs it is ~55x over.
        let bound = |pairs: u64| (pairs * (2 * CHUNKS_PER_READ + 2)) as usize;
        let small = to_blocks(&build(250), BLOCK).len();
        let large = to_blocks(&build(500), BLOCK).len();
        assert!(small <= bound(250), "250 pairs expanded to {small} events");
        assert!(large <= bound(500), "500 pairs expanded to {large} events");
        // …and doubling the input doubles the output. Quadratic would quadruple it.
        assert!(
            large <= small * 2 + 16,
            "doubling the input must not more than double the expansion: {small} -> {large}"
        );

        // The saturating s3tap-capture shape: a 64 GiB object at 8 MiB blocks is 8192
        // chunks, so the READ is truncated at the 4096-block cap. The write may then
        // invalidate 4096 chunks (all of them are resident, so this is the honest cost,
        // not fan-out), and never more than that: a write can only emit what a read
        // already emitted, so the read cap bounds both.
        let huge = vec![
            NormEvent {
                ts_ns: 1, op: Op::Get, object_id: "o".into(), range: None,
                size: Some(64 << 30), version: None, status: Some(200),
            },
            NormEvent {
                ts_ns: 2, op: Op::Put, object_id: "o".into(), range: None,
                size: None, version: None, status: Some(200),
            },
        ];
        let blocks = to_blocks(&huge, 8 << 20);
        assert_eq!(blocks.iter().filter(|e| e.op == Op::Get).count(), 4096);
        assert_eq!(blocks.iter().filter(|e| e.op == Op::Put).count(), 4096);
    }

    #[test]
    fn a_write_still_invalidates_every_chunk_read_since_the_last_write() {
        // Consuming the touched set must not weaken the invalidation itself: a chunk
        // read AFTER the previous write is still resident and must be cleared.
        let get = |ts: u64, sz: u64| NormEvent {
            ts_ns: ts, op: Op::Get, object_id: "k".into(), range: None,
            size: Some(sz), version: None, status: Some(200),
        };
        let put = |ts: u64| NormEvent {
            ts_ns: ts, op: Op::Put, object_id: "k".into(), range: None,
            size: None, version: None, status: Some(200),
        };
        // read 3 chunks, write (clears all 3), read 2 chunks, write again.
        let trace = vec![get(1, 20 << 20), put(2), get(3, 9 << 20), put(4)];
        let blocks = to_blocks(&trace, 8 << 20);
        let writes: Vec<(&str, u64)> = blocks
            .iter()
            .filter(|e| e.op == Op::Put)
            .map(|e| (e.object_id.as_str(), e.ts_ns))
            .collect();
        assert_eq!(
            writes,
            [("k#0", 2), ("k#1", 2), ("k#2", 2), ("k#0", 4), ("k#1", 4)],
            "the second write clears what was re-read after the first, and no more"
        );
    }

    #[test]
    fn a_read_after_write_loop_has_no_chunk_level_reuse() {
        // The concrete divergence: 2500 pairs of {PUT k, GET k} on ONE key. Object mode
        // (and `advise`) call this zero reuse, because every GET follows an invalidating
        // PUT. Chunk mode reported a 0.999 hit rate on `k#0` off a cache serving bytes
        // the client had just overwritten.
        let mut trace = Vec::new();
        for i in 0..2_500u64 {
            trace.push(NormEvent {
                ts_ns: i * 2, op: Op::Put, object_id: "k".into(), range: None,
                size: None, version: None, status: Some(200),
            });
            trace.push(NormEvent {
                ts_ns: i * 2 + 1, op: Op::Get, object_id: "k".into(), range: None,
                size: Some(1 << 20), version: None, status: Some(200),
            });
        }
        let blocks = to_blocks(&trace, 8 * 1024 * 1024);
        let rows = crate::driver::sweep_retention(&blocks, &[2]);
        let lru = rows.iter().find(|r| r.predictor == "null").unwrap();
        assert!(lru.hit_rate < 1e-9, "every GET follows a PUT: {}", lru.hit_rate);
        let opt = rows.iter().find(|r| r.predictor == "opt").unwrap();
        assert!(opt.hit_rate < 1e-9, "not even Belady can serve overwritten bytes: {}", opt.hit_rate);
    }

    #[test]
    fn maps_the_rest_verbs() {
        assert_eq!(from_ibm_line("1 REST.PUT.OBJECT x 10").unwrap().op, Op::Put);
        assert_eq!(from_ibm_line("2 REST.HEAD.OBJECT x").unwrap().op, Op::Head);
        assert_eq!(from_ibm_line("3 REST.DELETE.OBJECT x").unwrap().op, Op::Delete);
        assert_eq!(from_ibm_line("4 REST.COPY.OBJECT x").unwrap().op, Op::Put);
        assert_eq!(from_ibm_line("5 REST.POST.OBJECT x").unwrap().op, Op::Put);
    }

    #[test]
    fn get_without_size_or_range_still_parses() {
        let ev = from_ibm_line("5 REST.GET.OBJECT abc").unwrap();
        assert_eq!(ev.op, Op::Get);
        assert_eq!(ev.object_id, "abc");
    }

    #[test]
    fn unknown_rest_verb_is_other_kept() {
        // A bucket LIST (REST.GET.BUCKET) would be Op::Get here (verb GET);
        // a genuinely unknown verb maps to Other, not dropped.
        assert_eq!(from_ibm_line("6 REST.OPTIONS.OBJECT x").unwrap().op, Op::Other);
    }

    #[test]
    fn malformed_lines_are_none() {
        assert!(from_ibm_line("").is_none());
        assert!(from_ibm_line("justonefield").is_none());
        assert!(from_ibm_line("100 REST.GET.OBJECT").is_none()); // no object id
        assert!(from_ibm_line("notanumber REST.GET.OBJECT x").is_none());
        assert!(from_ibm_line("100 NOTREST x").is_none()); // 2nd field isn't REST.*
    }
}

#[cfg(test)]
mod object_resource_tests {
    use super::*;

    #[test]
    fn only_object_scoped_reads_count_as_demand_reads() {
        // The list is two entries and the two that were REMOVED are the whole point, so pin
        // both directions. `GET /?uploads` is ListMultipartUploads — bucket-scoped — and logs
        // `REST.GET.UPLOADS`, so counting it made repeated listings of ONE bucket read as
        // repeated hits on one hot object and inflated the cache verdict. `REST.GET.UPLOAD`
        // is ListParts, an XML manifest rather than object bytes.
        assert_eq!(ibm_op("REST.GET.OBJECT"), Some(Op::Get));
        assert_eq!(ibm_op("REST.HEAD.OBJECT"), Some(Op::Head));
        assert_eq!(ibm_op("REST.GET.PART"), Some(Op::Get));
        for bucket_scoped in ["REST.GET.UPLOADS", "REST.GET.UPLOAD", "REST.GET.BUCKET",
                              "REST.GET.ACL", "REST.HEAD.UPLOADS"] {
            assert_eq!(ibm_op(bucket_scoped), Some(Op::Other), "{bucket_scoped} is not a read");
        }

        // Writes deliberately do NOT require an object scope: their only role is
        // invalidation, and over-invalidating is the safe direction.
        assert_eq!(ibm_op("REST.POST.UPLOADS"), Some(Op::Put));
        assert_eq!(ibm_op("REST.PUT.OBJECT"), Some(Op::Put));
        assert_eq!(ibm_op("REST.DELETE.UPLOAD"), Some(Op::Delete));

        // Not a REST op at all: the line is skipped rather than modelled.
        assert_eq!(ibm_op("WEBSITE.GET.OBJECT"), None);
    }
}
