# s3tap-advisor

This tool reviews captured s3tap records and points out ways an app is using S3
inefficiently. It flags reconnecting instead of reusing connections, downloads that
could run in parallel, repeated re-fetches, throttling and whether a cache would help.
It also says what to change. It only reads captured records, so it never touches the
kernel and needs no privileges. It reads `s3tap.operation/1` and `s3tap.connection/2`
records and writes `s3tap.finding/1` records, in the same format the `doctor` uses.
Because the format is shared, a fleet-wide tool can read the output, `--json` produces
newline-delimited JSON and the exit-code rules (see below) are the same.

Pass/fail health checks live in `s3tap-doctor`. This crate gives **optimization advice**
instead. It tells you how to run faster and whether to cache. It attributes each finding
to a specific process wherever the check allows.

![s3tap advise flagging connection churn, missing parallelism and redundant re-fetches in one capture](../../assets/readme/advise.gif)

*One capture, three fixes: reuse connections, parallelize the downloads, stop re-fetching
unchanged objects.*

```sh
# live pipe
s3tap --format jsonl | s3tap advise

# offline capture, machine output, CI gate
s3tap advise --from capture.jsonl --json --strict
```

Exit codes: `0` when the capture was judged, since advice is not a failure. With `--strict`,
`1` if any `Warn` or `Advisory` finding fired. An `Unjudged` finding never changes the exit
code.

`2` when there is no judgeable S3 operation population at all: a connection-only capture, or
one whose operations were never answered. Empty findings there mean "nothing to judge" rather
than "judged and clean", so this is returned with or without `--strict`. A Warn or Advisory
that did fire still outranks it under `--strict`, mirroring the doctor's precedence.

`4` stays tool failure: an input that could not be read, or that parsed to zero records.

Each check documents what it looks at, when it fires, its severity, its scope and its
caveats in its own file under `src/checks/` (one file per finding code).

## Contract

- Results are repeatable. Given the same input, each check makes one pass and produces
  the same output. (The caching check runs the bounded `sweep_demand`, a byte-capacity
  `sweep_bytes` and one `run_self_tuned` pass, sampled at 500 K events.)
- **Caching is byte-aware.** When ≥80% of GETs carry a captured `Content-Length`, the
  caching check sizes the cache in **bytes** (miss-ratio knee in MiB/GiB) and reports two
  savings axes: GET requests avoided and egress bytes avoided (the $ bill). They diverge
  when the hot set is small, so a workload can be a request-GO and a dollar-no-go
  (`advisor-cache-requests-not-dollars`). If too few GETs report their size, it falls back
  to sizing by object count instead. It only tracks whole objects. Reuse of parts of an
  object (ranged or streaming reads) is invisible until Range capture exists.
- **Avoiding false alarms.** A check fires only when three conditions all hold: the
  problem rate is high enough, the absolute impact is large enough and there are enough
  operations to judge (`MIN_OPS`). If the data needed to judge is missing, it reports
  `Severity::Unjudged` or says nothing. It never guesses. `partial` ops are always
  excluded. Ops with an `Ambiguous` or `None` timestamp are left out of timing math (still
  counted and marked `Unjudged` once they exceed 20%).
- Every finding carries a stable `finding_id`, a `Domain`, a single headline
  `metric`/`value`/`unit`, the condition that triggered it in `threshold` and
  `scope.app_pid` for per-process checks.
