# `analyze`: deep caching + prefetch report

`analyze` studies caching for **one trace**, offline. It then prints a recommendation: *should you
cache this workload, with which policy, at what size and will prefetching help?* It is the deep,
opt-in sibling of [`advise`](advise.md). advise gives a fast object-level yes or no. analyze runs
the full retention bake-off (it replays the trace against several cache policies, LRU / ARC /
S3-FIFO / OPT, to see which keeps the most useful data) in chunk mode, plus the prefetch tradeoff
(prefetch means fetching data before it is asked for). It only reads data. It loads no probes and
needs no privilege.

```console
$ s3tap analyze --from capture.jsonl        # deep report (8 MB chunk mode)
$ s3tap --format jsonl | s3tap analyze      # analyse a live capture
$ s3tap analyze --from trace --fast         # retention only, no prefetch pass
$ s3tap analyze --from trace --json         # structured verdict, one JSON object
```

It auto-detects three trace formats, line by line: **s3tap JSONL** (`s3tap.operation/1`
records), **NormEvent JSON** (the replay format) and **IBM COS** text lines.


## Exit codes

| Code | Meaning |
|------|---------|
| 0 | judged: a cache verdict was produced |
| 2 | nothing judgeable: the input WAS read, and nothing in it was a demand read a cache could serve — an all-503 capture, a connection-only one, a bucket of 403s |
| 4 | tool failure: the input could not be read, or parsed to zero `s3tap.*` records |

`analyze` has no `--strict`: its answer is a cache-suitability verdict, not a health
judgment, so a "no-go" is an answer rather than a failure and still exits 0.

Exit **2** is the same code `doctor`, `advise` and `scorecard` return for a capture with no
population to judge, and it means the same thing here: s3tap read your file and found nothing
to work with, so the fix is to the capture. Reserve **4** for "s3tap never got a capture at
all" — the fix there is to the invocation.

## Cost levels

The prefetch *Adaptive* rung runs a per-capacity shadow cache and is minutes-slow on a large
trace, so the ladder is tiered:

| mode | runs | speed | answers |
|---|---|---|---|
| `--fast` | retention bake-off only | fastest | which cache, how big |
| *default* | + Markov structure + the self-tuning lead-gated overlay | seconds to a minute | + will prefetching help |
| `--deep` | + the full prefetch ladder (Frequency/Co-occurrence/Sequential/Adaptive) | minutes+ | + every predictor, for completeness |

For a large trace, analyze looks at only the first `--max-events` ops (default **3,000,000** to
match the study, or `0` for the whole trace). The capacity ladder tops out at 4096 chunks
(32 GiB). Above that size the verdict is flagged a **lower bound**.

## The verdict

The machine-readable `verdict` field (`--json`) is one of four values. It reports the real
recommendation. `go-latency` fires only when prefetching *actually* hides latency, not just
when a sequence looks predictable:

| `verdict` | means |
|---|---|
| `go` | reuse pays: cache on cost |
| `go-latency` | low reuse, but prefetching hides real fetch latency |
| `no-go` | pure overhead (may still show *un-hideable* structure) |
| `unjudged` | too few GETs to say, capture longer |

The human banner adds nuance (`CACHE IT`, `CACHE FOR LATENCY`, `LITTLE TO GAIN`, `DON'T CACHE`,
`TOO SHORT TO SAY`). The retention section names the winning cache (**ARC** is usually the
study's pick, a free upgrade over LRU). It shows how much ARC beats LRU by and how far it sits
from the OPT ceiling (OPT is the perfect cache that can see the future, so it marks the best
result possible).

## advise vs analyze

[`advise`](advise.md) is the quick gate everyone runs: object-level, capped at 500k events,
LRU plus Markov prediction, short findings. `analyze` is the deep report you opt into when the
gate says it is worth it: the full policy ladder, chunk by chunk, with a per-trace story. Both
use the same decision thresholds from the study. `analyze` reproduces the report's numbers on
the same trace.

See the [CLI reference](../reference/cli.md#s3tap-analyze) for every flag.
