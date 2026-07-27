# `advise`: optimization advice

`advise` reads the same capture as `doctor` but answers a different question: not *"is it
healthy?"* but *"how is the application **using** S3 and what could be better?"*, attributed
per process. Like `doctor`, it only reads records, so it loads no probes and needs no privileges.

```console
$ s3tap advise --from capture.jsonl
$ s3tap --format jsonl | s3tap advise
```

## What it surfaces

- **Client churn**: connections created and thrown away instead of reused.
- **Missing parallelism**: serial fetches that could overlap.
- **Redundant re-fetches**: the same object pulled repeatedly.
- **Throttling**: 503 SlowDown patterns.
- **Caching go/no-go**: whether a local cache would pay off.

## Health vs advice

Health judgments live in [`doctor`](doctor.md). This is optimization advice. By default advice
is **not** a failure, so a clean run and a run full of advisories both exit 0. Pass `--strict`
to exit 1 when any Warn or Advisory finding fired. `--json` emits `s3tap.finding/1` records
instead of the human table.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | judged: either nothing fired, or advice is not being gated on |
| 1 | `--strict` only: a Warn or Advisory finding fired |
| 2 | nothing judgeable: the capture has no S3 operation population to run a check against |
| 4 | tool failure: the input could not be read, or parsed to zero records |

**Exit 2 is not a quiet 0.** A connection-only capture (a Go or rustls client, or one taken
without the uprobe caps) decodes no operation at all. A capture whose operations were never
answered has nothing for the checks to draw on either. An empty `findings` there means
"nothing to judge", not "judged and clean". It is not gated by `--strict`, so a plain `advise`
returns 2 for that capture as well: the population is missing whether or not you asked to gate
on advice.

A real judgment still outranks it. An advisory sourced from the connection records can fire on
a capture with no judgeable S3 population. That judgment is real, so under `--strict` the 1
wins. This mirrors `doctor`, where ATTENTION sits above its own missing-denominator verdicts.

Keep 2 and 4 apart when scripting. Exit 2 says s3tap read a capture and found nothing in it to
judge, so the fix is to the capture. Exit 4 says s3tap never got a capture at all, so the fix
is to the invocation.

Under `--json` a capture with no judgeable S3 population also emits one `s3tap.finding/1`
row, `advisor-run`, with severity `unjudged`. It names which of the two denominators was
missing, so an ingest that stores NDJSON keeps the reason rather than an unexplained empty
stream. It is keyed on the population, not on the exit code, so `--strict` never changes the
set of records written — and the row can therefore sit beside an exit 1, when a
connection-sourced advisory fired on a capture that had no operations. No row means the
population was fine.

## The input must be a capture

`advise` refuses an input that parsed to zero `s3tap.*` records. It names what it actually
read and exits **4** (tool failure), which is distinct from every verdict code. A findings
file is not a capture. Neither is an empty file, a truncated one, or any other log.

This is worth stating plainly because of what it replaced. `advise --strict` over a broken
`--from` path used to print "nothing to flag" and exit **0**, so a CI gate reported a clean
run for a file that was never read. A gate that cannot tell "clean" from "no data" is not a
gate.

See the [CLI reference](../reference/cli.md#s3tap-advise) for every flag.
