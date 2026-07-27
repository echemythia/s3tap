# Public records

s3tap's capture emits **stable, public JSONL records**: one JSON object per line, each tagged
with a versioned `schema` field. Every consumer reads these, so the record *is* the contract. A
capture taken once can be re-judged offline, diffed or fed to a different tool.

> **Source of truth:** the exact fields, types and (de)serialization live in the
> [`s3tap-schema`](https://github.com/echemythia/s3tap/tree/main/crates/s3tap-schema) crate. This page is an orientation, not the field-by-field spec. Consult the
> crate for authoritative shapes and to avoid drift.

## The record kinds

| Schema | Emitted at | Carries |
|--------|-----------|---------|
| `s3tap.operation/1` | one per S3 request | the request lifecycle + timings |
| `s3tap.connection/2` | one per connection close | connection-level `tcp_sock` stats |
| `s3tap.sample/1` | periodic (opt-in) | an in-flight TCP snapshot |
| `s3tap.finding/1` | by the consumers | one judged check / advisory + run roll-up |
| `s3tap.scorecard/1` | by `scorecard --json` | one `bucket / s3_op` rollup of observed traffic |

## Timestamps: `emitted_at` vs `ts_ns`

Every record the AGENT ships carries `emitted_at`: an RFC3339 wall clock (UTC, millisecond
precision) for the moment s3tap wrote the record out — **not** for the traffic it describes.
That is `ts_ns`, which is boot-relative monotonic and therefore comparable only within one
host's capture.

`emitted_at` is the only wall clock in the pipeline, so it is the field a fleet ingest orders
and ages records on across hosts. Two properties matter to a consumer:

- **One clock read per drained batch**, not per record. Every record flushed together carries
  the same `emitted_at`, deliberately: reading the clock per record would split one flush into
  N distinct emit times, which a consumer cannot tell apart from N separate flushes.
- **It is absent on a record that never reached the emitter** — one built in-process, or in a
  test — and on the two SECOND-ORDER records. `s3tap.finding/1` declares the field but no
  producer stamps it, so it is omitted from the JSON entirely; `s3tap.scorecard/1` has no such
  field at all. Both are deliberate: those records are derived from a capture rather than
  observed, and a wall clock in them would also make every golden non-reproducible. **Do not
  order, age or dedupe findings on it** — carry your own receive time, or join back to the
  first-order records the finding was derived from.

## `s3tap.operation/1`

The per-request record. Key fields:

- **Identity / join:** `op_id`, `sock_cookie` (join key to its connection), `app`, `bucket`,
  `key_hash`. Note there is no `region` here — the endpoint's region lives on the CONNECTION
  (`endpoint.region` on `s3tap.connection/2`), reachable through the `sock_cookie` join.
- **Timings (ns):** `tcp_connect_ns`, `ttfb_ns`, `download_ns`.
- **Semantics:** `verb`, `http_status`, `s3_op` (op-class), `content_length`, `aws_request_id`.
- **Eligibility flags:** `partial`, `connection_reused`, `delimitation` (`clean` | `ambiguous`),
  `dns` (a nested resolve block with `latency_ns`, `cache_hit`).

Fields whose absent values are easy to misread:

- **`app.pid` is 0 when the process is UNKNOWN**, not when the pid is genuinely 0. It happens
  when s3tap never saw the connect, typically because it attached mid-flight. The close
  event's own tgid is deliberately not used as a fallback: it is stamped wherever the socket
  is torn down, routinely in softirq context, so it would name an unrelated task. A consumer
  that groups by pid should treat 0 as "unattributed" rather than as a real process.
- **`content_length` is null in five distinct cases**, all of which mean "we have no
  trustworthy body length", never "the body was empty": no `Content-Length` header at all, a
  `Transfer-Encoding` header (whose framing supersedes any declared length), duplicate
  `Content-Length` headers that disagree, a declared value above 5 TiB (the largest object S3
  stores, the bound that keeps this field safe as a plain JSON number), or a response head
  s3tap never saw in full. It MAY be set when `download_ns` is null: a HEAD declares a size
  with no body to time.
- **Five connection-scoped fields are placeholders on this record, never measurements.**
  `bytes_sent`, `bytes_recv` and `retransmits` are always `0` here. `srtt_us` and
  `lifetime_ns` are always null. They are read off `tcp_sock` at CLOSE and are cumulative for
  the whole connection, while an operation record is emitted the moment its response
  completes, with the socket still open, so at that instant there is nothing to read.
  Deferring the record until close is not an option: a pooled connection can outlive the
  workload. So a `0` here means "not measured on this record", never "no bytes moved" or "no
  retransmits". **Do not aggregate them.** Byte volume or loss summed across operation records
  is zero by construction and reads as a healthy fleet. The real values live on the
  `s3tap.connection/2` record for the same socket: join on `sock_cookie`. For per-op byte
  accounting use `op_bytes_sent` / `op_bytes_recv`. The fields keep their place at those
  constants because removing them is a `/1` to `/2` contract change for fields that carry no
  information either way. They are the first thing to drop when `s3tap.operation` next bumps.

## `s3tap.connection/2`

The per-connection record, read off `tcp_sock` at close. Key fields:

- **Identity:** `sock_cookie`, `app`, `endpoint` (`region`, …).
- **Floor / quality:** `srtt_us`, `min_rtt_us` (true propagation floor), `rttvar_us`,
  `retransmits`.
- **Volume / window:** `bytes_sent`, `bytes_recv`, `snd_cwnd`, `mss`, delivery-rate.
- **Setup:** `tls` (handshake timing), `dns`, `connect_failed`.

Fields whose values are easy to misread:

- **`endpoint.via_vpce` and `endpoint.cross_region` are always `false` today.** s3tap does not
  yet derive either, so read them as *not determined*, never as *no*. A genuinely cross-region
  capture still reports `"cross_region": false`. (The `advise` check that keys on the flag
  therefore cannot fire on a real capture; it is kept for the record shape.)
- **`endpoint.region` IS real** — taken from the SNI, falling back to the observed DNS
  resolution. It is `null` only when neither was available.

> `sock_cookie` is the join key between operations and their connection. It is derived from the
> kernel `struct sock *` but **obscured with a per-run random key** at emit time, so shipped
> records carry only a stable opaque id, never a real pointer.

## `s3tap.sample/1`

A periodic in-flight snapshot (opt in with `--sample-interval-ms`): `sock_cookie`, `ts_ns`,
`srtt_us`, `min_rtt_us`, `snd_cwnd`, `bytes_recv`, delivery-rate. It feeds `doctor`'s
time-series section, which is FYI and never gates.

**Samples are not purely telemetry.** Which part is which matters. They never enter the
eligible-op population and never feed the parity-pinned close-time floor, so on a capture
where a connection closed they change nothing. But when NO connection closed, which is the normal
shape for a long-lived pool, they become the FALLBACK. The round-trip floor comes from their
`min_rtt`/`srtt`. The retransmit denominator comes from their byte deltas. Every latency verdict
in the report is then judged against a number the samples supplied. The baseline row says so
on its face (`baseline RTT (min_rtt, sampled)`). Without `--sample-interval-ms` that same
capture reports NO BASELINE and judges nothing.

## `s3tap.finding/1`

The **output** contract, emitted by `doctor --json`, `advise --json` and `scorecard --json`:
one finding per check or advisory, plus a run roll-up. Each carries a `finding_id`, `domain`, `severity`, `verdict`,
the `metric`/`value`/`threshold`, `baseline_rtt_us` and `ratio_to_rtt` for latency checks, a
bounded `evidence` sample of contributing ops and a `scope` (e.g. the `s3_op` for per-class
rows). This is the format a fleet ingests.

### What is stable and what is not

The answer has two parts, because the two halves of this record move at different speeds.

**The envelope is a contract, at 0.x already.** The field set, their names, their types and
their encodings hold. Adding, removing or renaming a field is a schema change and bumps the tag
to `s3tap.finding/2`, exactly as for the first-order records. Parse this shape and expect it to
keep working.

**The finding vocabulary is not frozen at 0.x.** Which `finding_id`s exist, what a `metric` is
called, what unit it carries, the `summary` prose and which severity a given condition earns:
these move as checks are added and corrected, in a minor release, without a tag bump. The
work since 0.7.0 has already renamed `serialized_busy_s` to `serialized_busy_ms`, added the
`advisor-run` and `scorecard-run` rows and narrowed `source_schema` to name only the stream a
finding reads. None of it has shipped yet, which is why the rule is written down now.

So write a consumer that parses the envelope, switches on `severity` (a closed enum in the
envelope) and treats `finding_id` and `metric` as data that can gain members. A gate written
that way survives a minor upgrade. One that matches on a hardcoded list of ids will need
revisiting.

## `s3tap.scorecard/1`

The observed-SLO rollup, emitted by `scorecard --json`: one row per `(bucket, s3_op)` group,
describing the traffic that group actually saw. Key fields:

- **Group key:** `bucket`, `s3_op` (either may be null, which keeps unclassified traffic
  visible as its own row instead of dropping it).
- **Reliability:** `ops` (the denominator: ops that carried an HTTP status), `errors`,
  `error_rate`, `status_counts` (an object keyed by the stringified status code).
- **Latency:** `ttfb_p50_ns`, `ttfb_p95_ns`, `ttfb_p99_ns` plus `latency_sample`, the number of
  eligible ops behind them. p95 is null below 20 eligible ops and p99 below 100 — two
  different floors, because the worst 1% needs more samples to mean anything than the worst
  5% does — so a tiny capture's maximum is never sold as a deep-tail estimate.
- **Throughput / span:** `throughput_bytes_per_s` (GET groups only, null otherwise) and
  `window`, the `[ts_start, ts_end]` the group's ops fell in.

These rows are **descriptive telemetry, never a verdict**. Latency has no absolute "good"
without a per-group RTT floor, so the percentiles are reported as-is. The judgments computed
beside them (the reliability taxonomy and the within-group p99/p50 tail ratio) ride the
`s3tap.finding/1` rails instead. So `scorecard --json` writes **both** kinds of line: the
scorecard rows first, then the findings. A consumer that wants only the numbers reads the
scorecard rows. A fleet gate reads the findings.
