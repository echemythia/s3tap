# s3tap-replay: offline predictability harness

Replay S3 access traces through a cache simulator and a set of predictors to
measure **how predictable** the workload is. The output is the cache-hit-rate a
smart cache could reach. That number sits between two bookends: a plain-LRU floor
at the bottom (LRU means "least recently used", the standard reactive cache) and
the Belady/OPT optimal ceiling at the top (OPT is the best any cache could do if
it knew the future). This checks whether a smart cache is even worth building
*before* you build the serving path. It runs entirely in userspace: no eBPF, no
kernel and no real object bytes. The simulator only tracks which objects are held
in the cache (this is called residency).

## The ladder

The word "ladder" just means a set of rows, from the simplest cache up to the
smartest. Every row is tested across a range (sweep) of cache sizes. Three rows
are **demand baselines**, meaning they only cache what was actually requested and
never prefetch. The rest are **prefetch predictors**: they guess what will be read
next and pull it in early, layered on the same LRU cache. Reading the rows in
pairs tells you where the wins come from. `null → opt` shows how much smarter
*eviction* (choosing what to drop) could do. `null → a predictor` shows the value
of *prefetching*. `null → lru+adm` shows the value of *admission control*
(deciding what is even worth caching).

| Row | Kind | What it does |
|-----|------|--------------|
| `null` | demand baseline | plain LRU, the reactive floor everything is measured against |
| `lru+adm` | demand baseline | LRU + TinyLFU **admission**: bypass one-shots so they don't pollute the cache |
| `opt` | reference ceiling | Belady optimal demand cache (needs the future, not deployable) |
| `frequency` | prefetch | keep the hottest objects warm (popularity) |
| `markov` | prefetch | order-1 successor prediction (sequence) |
| `markov2` | prefetch | order-2 successor prediction (2-object context) |
| `cooc` | prefetch | windowed co-occurrence (objects fetched *together*, unordered) |
| `adaptive` | prefetch (meta) | expert pool over all of the above plus a shadow-cache disengage, follows the winner per workload |
| `sequential` | prefetch (block mode only) | next-block read-ahead on streaming/chunked reads |

Output columns: `predictor  cap  hit_rate  pf_precision  pf/access  net_savings  pf_latency`.
`pf/access` is the number of prefetches issued per cacheable access. It shows how
much speculation is wasted and makes it clear when `adaptive` decides to stop
prefetching. `net_savings` is the bottom line. It is the number of origin (S3)
fetches **eliminated per access** compared to doing nothing. You get it by taking
the reuse benefit (`hit_rate`, since each hit avoids a fetch) and subtracting the
prefetch cost (`pf/access`, since each speculative fetch is an origin call whether
or not it gets used). A positive number means the policy cuts origin traffic. A
**negative number means prefetching costs more calls than reuse saves**: a high
`hit_rate` paid for with an equal `pf/access` nets out to about zero. One way to
read it: a cache with no prefetching has `net_savings` equal to its `hit_rate`, so
a prefetcher is only worth it when its `net_savings` beats that demand baseline.
`pf_latency` is `prefetch_used / accesses`. It isolates just the **latency** the
prefetcher hid, meaning the would-be misses it turned into ready hits. This is
different from `hit_rate`, which counts *all* latency-free hits including plain
reuse from the cache. In chunk mode (uniform chunks) `hit_rate` also reads as the
"fraction of chunks served with zero origin latency", while `pf_latency` is the part
of that the prefetcher is responsible for. Both are upper bounds because the model
assumes prefetches are instant.

## Running the sweep

The binary **auto-detects** the line format, so all three inputs work through the
same command:

1. A normalized `NormEvent` (JSON): `{"ts_ns":1,"op":"get","object_id":"bucket/sha256:abc"}`
2. A raw s3tap `s3tap.operation/1` record (JSON). This is adapted via a local
   deserializable mirror, so this crate does **not** depend on `s3tap-schema`.
3. An **IBM Cloud Object Storage** trace line (whitespace-separated):
   `1232488 REST.GET.OBJECT 95d363d3fbdc0b03 1168 0 1167`

```bash
cargo run --release -p s3tap-replay -- trace            # DEFAULT: CHUNK mode @ 8M
cargo run --release -p s3tap-replay -- trace 1M         # CHUNK mode, 1 MB chunks
cargo run --release -p s3tap-replay -- trace object     # OBJECT mode (whole objects)
```

The cache is **chunk-based by default**. With no 2nd arg it runs CHUNK mode at
**8 MB** chunks. The capacity sweep is anchored at the default cache size of
**64 chunks** (64 × 8 MB = 512 MiB), always shown even on small traces. Chunk mode
splits each GET into the `ceil(size/chunk)` fixed-size chunks it touches. A large
whole-object read fills many chunks and a small one fills a single chunk (each
access is capped at 4096 chunks so nothing explodes). It then runs the full
predictor ladder plus the `sequential` read-ahead rung. Capacity is measured in
chunk-count units. Pass a size (`K`/`M`/`G` suffixes) to change the chunk size, or
the literal `object` to switch to whole-object residency (capacity in object-count
units). If the 2nd arg is present but cannot be parsed, that is an error, not a
silent fallback.

Generate a synthetic trace with the `synth` generators (`sequential`, `zipf`,
`markov`, `uniform_random`), or point the binary at a JSONL capture from the live
agent, or at an IBM COS trace.

### Cross-checking against real production traces (IBM COS)

The synthetic generators validate the *harness* (the tool itself). Real public
traces validate the *premise* (whether the workload is actually predictable). The
**IBM Cloud Object Storage** traces (SNIA IOTTA dataset #36305) are a real
production object-store workload and drop straight in:

```bash
# Register + download from http://iotta.snia.org/traces/key-value/36305
cargo run --release -p s3tap-replay -- IBMObjectStoreTrace000Part0
```

Line format: `<ts_ms> <REST.VERB.RESOURCE> <object_id> [<size>] [<start_off> <end_off>]`.
READS require an object-scoped RESOURCE (`OBJECT` or `PART`), so `REST.GET.UPLOADS`
(ListMultipartUploads, bucket-scoped) and `REST.GET.UPLOAD` (ListParts) are kept as lines but
never counted as demand reads. Writes do not require one — over-invalidating is the safe
direction.
Object mode maps timestamp/op/object_id. The byte-range columns are parsed and
drive **block mode**. `REST.PUT/POST/COPY` and `REST.DELETE` invalidate.
`REST.HEAD` is ignored (no body, so it is not fed to the predictors).

## Correctness backbone

`tests/known_answer.rs` generates traces whose predictability is known
analytically and asserts the *direction* the predictors must recover:

- Markov beats the floor on a near-cyclic Markov trace.
- Frequency beats the floor on a Zipf popularity trace.
- **Nothing** beats the floor on a uniform-random trace. This is the future-leak guard.

Unit tests additionally pin: OPT ≥ LRU (ceiling invariant), the single-pass sweep
matches the reference per-cap `run()`, admission beats LRU under one-shot
pollution and each predictor's core behavior.

## Validity caveats (read before trusting any number)

1. **`hit_rate` / `pf_latency` are UPPER BOUNDS**, not rates you can actually hit.
   Prefetch is modeled as instant and with unlimited lead time, so a prefetch that
   is still in flight at access time still counts as a zero-latency hit. In
   *object* mode, splitting one object across many ranged reads also inflates
   `hit_rate`: one large object streamed as N ranged GETs shows N−1 fake "hits" on
   one `object_id`. Chunk mode models that honestly **only for a trace that carries
   byte offsets**, which not every trace format has.

   **Which formats carry byte offsets.** An IBM COS line's `<start_off> <end_off>` columns
   populate `range`. A hand-written `NormEvent` can set it directly. Chunk mode expands such a read
   into exactly the chunks its byte span touched, which is the honest model.
   **An s3tap capture carries no range at all.** s3tap does not parse the `Range`
   header. On a `206` the `content_length` it records is the *range* length rather
   than the object length, so there is nothing to derive a span from. Left
   alone, all N reads of one object would map onto chunk `#0` and report a hit rate
   near 1.0 for a workload whose true reuse is zero. A `206` is therefore not a
   cacheable demand read: the adapter maps it to `Op::Other`, which keeps it in the
   trace (its status still lets you measure the ranged fraction and say so) while
   every simulator skips it. The collapse is unreachable rather than silently
   wrong. A `200` whole-object GET from an s3tap capture is unaffected: chunk mode
   derives its span from `Content-Length` as `[0, size-1]`, which is correct for a
   whole-body read.
2. **The capacity axis is CHUNK-COUNT in chunk mode (the default) and OBJECT-COUNT
   in object mode. It is not measured in bytes.** The CLI prints which one. In
   chunk mode, uniform chunks make it proportional to bytes (cap × chunk-size =
   cache bytes, so the default 64 × 8M = 512 MiB).
3. **Chunk mode breaks a whole-object read into its per-chunk accesses**, so a
   prefetcher can look like it is "reading ahead" within a single physical fetch.
   Real gains come from RE-reads of chunks that are already resident. A whole read
   is also capped at 4096 chunks, so a multi-GB object at a small chunk size gets
   truncated.

   A write is expanded the same way, into one invalidation per chunk of that object
   that a read has touched since the object's last write. Its own declared extent is
   usually unknown (an s3tap `content_length` is a response body length), so
   invalidating only that extent would leave chunks `#1..N` of an overwritten object
   resident and stale. Chunks already invalidated are dropped from the set rather
   than re-invalidated, because a chunk that was invalidated and not re-read cannot
   be resident. That keeps the expansion linear in the input. The residual hole is a
   chunk a prefetcher inserted and no demand read has touched since the last write.
4. `pf_precision` depends on both the predictor and the capacity together. Low
   precision at small caps reflects capacity pressure, not necessarily bad
   prediction.
5. `opt` is the best possible *demand* cache, so a *prefetcher* can legitimately
   beat it (prefetching turns first-time "compulsory" misses into hits). `opt`
   accounts for write-invalidation, so it is a true ceiling for demand caching on
   write traces.
6. `adaptive` is run once **per capacity** with a shadow cache matched to that
   capacity, so its decision to engage or disengage fits the cache it drives. It is
   the most expensive row, so sample large traces.
7. `frequency` counts never decay. `cooc`'s association graph is bounded (FIFO
   outer cap plus per-object partner cap). Both are approximations.

## Status

Both object-level and block-level (chunk) replay ship today. The ideas still
unbuilt are the ones with a higher ceiling that are blocked on better data. The
main two are **per-connection demultiplexing** (splitting the trace out by
connection, which needs s3tap capture identity like `sock_cookie` that the IBM
traces do not have) and variable-order (PPM) Markov prediction.
