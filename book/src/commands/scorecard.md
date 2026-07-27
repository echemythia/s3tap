# `scorecard`: observed-SLO scorecard

`scorecard` reads a capture and reports, for each `bucket / s3_op`, the latency and
reliability it actually saw: request and error counts, the status-code mix and TTFB
p50 / p95 / p99. It is the passive analogue of a speed test. The numbers are your own
production traffic rather than a synthetic probe. Like `doctor` and `advise` it only reads
records, so it loads no probes and needs no privileges.

```console
$ s3tap scorecard --from capture.jsonl
$ s3tap --format jsonl | s3tap scorecard
```

## What it shows

- **A row per bucket and operation**: request count, error count, the status-code mix.
- **Latency percentiles**: TTFB p50 / p95 / p99, so both the typical case and the tail are
  visible.
- **Reliability findings**: gated judgments (for example a 4xx or 503 rate above the floor)
  raised as `s3tap.finding/1` records.

## Report, not a gate

A scorecard is a report, so a judged capture exits 0 by default even when a finding fired.
Pass `--strict` to exit 1 when any Warn or Advisory finding fired. `--json` emits the
`s3tap.scorecard/1` rows followed by the gated `s3tap.finding/1` records instead of the
human table, with the same exit-code contract.

| Code | Meaning |
|------|---------|
| 0 | scored: either nothing fired, or findings are not being gated on |
| 1 | `--strict` only: a Warn or Advisory finding fired |
| 2 | the capture was read but nothing in it was scoreable |
| 4 | tool failure: the input could not be read, or parsed to zero records |

**Exit 2 is a report that could not be written, not a clean one.** A row exists only for a
`bucket / s3_op` group with at least one op carrying an HTTP status, so no rows means nothing
was scoreable. Two shapes reach it. One is a capture holding no operation record at all (a Go
or rustls client, or one taken without the uprobe caps). The other is a capture whose
operations all lack a status, because every request aborted before its response line. The
human render tells the two apart. Gating on the operation count alone caught only the first,
so a capture of 500 statusless operations printed "none carried an HTTP status" and still
exited 0.

It is not gated by `--strict`: a plain `scorecard` returns 2 for such a capture as well,
because the rows are missing whether or not you asked to gate on findings. A finding that did
fire still gates under `--strict` and exits 1. Note that this is not the precedence `doctor`
and `advise` have: a scorecard row exists only for a group with at least one statused op, and
every finding is derived from a row, so "a finding fired" and "there was nothing to score"
cannot both be true here. The `--strict` branch is a real gate, not a tie-break.

Keep 2 and 4 apart when scripting. Exit 2 means s3tap read a capture and found nothing in it
to score, so the fix is to the capture. Exit 4 means it never got a capture, so the fix is to
the invocation.

Under `--json` the exit-2 case also emits one `s3tap.finding/1` row, `scorecard-run`, with
severity `unjudged`. It names which of the two causes applied, so an ingest that stores NDJSON
keeps the reason rather than an unexplained empty stream. It appears ONLY for that case, so no
row means rows were produced.

Health verdicts live in [`doctor`](doctor.md). This is the descriptive view: what the
traffic actually experienced, per bucket and operation.

## The input must be a capture

`scorecard` refuses an input that parsed to zero `s3tap.*` records. It names what it actually
read and exits **4** (tool failure), which is distinct from every verdict code. A findings
file is not a capture. Neither is an empty file, a truncated one, or any other log. Rendering
a scorecard over nothing would be a report about no traffic, which is not a report.

See the [CLI reference](../reference/cli.md#s3tap-scorecard) for every flag.
