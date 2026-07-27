# doctor metrics

`doctor` judges latency **relative to the network RTT floor** (the connection's smoothed
round-trip, `srtt_us`, falling back to its lowest observed one), so a verdict means the same
thing whether you are 1 ms or 70 ms from S3. This page explains how each metric is derived.

## The RTT floor

Every latency span is judged as a multiple of a floor (in µs). The floor comes from a ladder of
sources, most trustworthy first:

1. **Per-operation join**: each op is matched to its connection by `sock_cookie` (the join key)
   and judged against *that connection's* floor. This keeps a multi-region capture honest. A
   us-east op (~1 ms) and a cross-region op (~70 ms) get **separate** floors. They never share
   a blended floor that fits neither and hides a slow op behind the far one.
2. **Per-region median**: if the joined connection has no usable floor, doctor uses the median
   floor of the op's region (found through the join).
3. **Pooled global median**: the median srtt across the whole capture. This is the single
   headline number the parity oracle checks.
4. **None**: with no floor anywhere, the span is marked *n/a* and **never judged**. Doctor
   never reads green on missing data.

A connection's floor prefers **srtt** (the current smoothed round-trip time, the right value to
subtract when isolating think-time, the server's own processing time) and falls back to
`min_rtt`. The sentinel `0` (an unsampled or LRU-evicted socket) and implausibly huge values are
dropped **per value** before the median.

## Global rows

| Row | Judged against | Warns when |
|-----|----------------|-----------|
| DNS, cold resolve | not judged | never (reported only) |
| TCP connect | RTT floor | > 3× RTT |
| TTFB, new conn | RTT floor | > 4× RTT |
| TTFB, reused conn | RTT floor | > 4× RTT |
| retransmit rate | segments sent | > 0.1 %, min 44 segments |
| HTTP errors | n/a | any 4xx/5xx present |

The **latency** rows above (TCP connect, both TTFB rows) are computed over the **eligible** ops
only. An eligible op is non-partial, has status < 400 and is not `delimitation: ambiguous` (a
second request raced the response, so its timing is not cleanly attributable). The reference
oracle applies the same gate.

**Neither the HTTP errors row nor the S3 status mix uses that population**
(throttling, server errors, client errors). Both are judged over the **answered** ops: every
operation carrying an `http_status`, which is what `sample.judged` publishes for them. The
eligibility gate would be nonsense here, because it drops a status ≥ 400 by construction, which
is exactly what these rows count. Using the whole capture would be wrong the other way: it
dilutes the rate by the ops nobody answered. That is what made `doctor --json` and `scorecard
--json` report different error rates for one file. When some ops went unanswered the row says
so on its own line ("of N ops, only M were answered"). When NONE were, it refuses to publish a
rate at all. See [NO RESPONSES](#verdict--exit-code).

### Why cold resolve is never judged

The cold-resolve row is pure telemetry. It is printed with a `·` and never contributes to the
verdict, not even under `--strict`. There is no honest envelope for it. It cannot be made
RTT-relative like every other span on this page: the floor measures the round trip to the S3
**endpoint**, while the resolver sits on a different path doing recursion, so the floor is not
its baseline. A same-region capture (a sub-millisecond floor, a routine 15 ms recursive resolve)
would read as 30× RTT and warn on every run. An absolute millisecond ceiling is the other way
out and it is exactly the invented number this tool refuses to use: it would fail a clean
on-prem or WAN capture whose own path is simply far away. So the number is shown and left
unjudged.

## S3 per-op-class TTFB: the "money metric"

For each S3 op-class (GetObject, PutObject, …), doctor reports **think-time = ttfb − RTT**. This
is the server-side work with the network time taken out. Each op is judged against its own joined
floor. The per-op ratios are then medianed, so a class that spans two regions is still judged
fairly. A class warns above **4× RTT**.

A would-be-healthy class with **fewer than 3 judged ops** degrades to *insufficient data*
rather than claiming a confident ✓. One fast op is not proof a class is fine. A clearly-slow
class still warns even on one op (a real outlier is worth surfacing).

## Tail, reuse, path, time-series

- **Tail**: p95 (≥ 20 samples) and p99 (≥ 100 samples) of the TTFB populations, judged against
  a wider envelope than the median line. Like the per-op-class rows, each op is scored against
  **its own** floor rather than the pooled one.

  The row carries **two** numbers, taken over two different orderings:
  `value` is the percentile of TTFB — a latency percentile, which is what the label says — and
  `ratio_to_rtt` is the percentile of `ttfb / its own floor`, which is the number the verdict
  gates on. Ranking the judgment by ratio is the point: on a capture spanning two paths, the
  slowest op in milliseconds may be the healthiest one relative to the path it took.

  Because they are order statistics over different orderings, **they generally describe
  different operations**, and no single floor relates them. The record therefore publishes no
  `baseline_rtt_us` for these rows: `value / baseline` would reconstruct a ratio that
  contradicts the published one. Use `ratio_to_rtt` against the `threshold`, and read `value`
  as the latency it says it is.

  A tail row also refuses a ✓ when the ops it could not floor are numerous enough to have
  occupied the tail themselves — above `1 - p/100` of the population it renders `n/a` instead,
  since a percentile computed from the survivors could hide exactly the ops that mattered. A ⚠
  still stands: warning from a subset errs in the safe direction.
- **Reuse rate**: fraction of all **non-partial** ops on a reused connection (below ~80 %
  warns). Requires ≥ 5 ops to judge. It is deliberately not restricted to the latency-eligible
  set — an errored or ambiguous op still tells you whether the client reused a connection —
  but a **partial** op does not, and the record schema says so on the field itself: on a
  partial op the connection facts could not be attributed, so whether it truly reused is
  unknown rather than false.
- **Path diagnosis**: advisory rows from the extended `tcp_sock` fields: propagation floor plus
  jitter, send or recv bottleneck, the BDP / receive-window ceiling (BDP means bandwidth-delay
  product, the most data the receive window allows in flight) and loss shape.
- **Time-series**: from the in-flight sample stream: throughput ramp, bufferbloat onset and a
  loss timeline. Judged over sample *streams*, not connections. **FYI, not advisory**: these
  rows are marked `·` and never gate, not even under `--strict`, which is the difference
  between them and the path and throughput rows above. They answer "what happened and when"
  rather than "is this outside its envelope". They are also empty unless the capture was taken
  with `--sample-interval-ms`. An advisory row would exit 1 under `--strict`. These never do.

## Verdict & exit code

The run rolls up to one verdict, mapped to an exit code for scripting:

| Verdict | Meaning | Exit |
|---------|---------|------|
| HEALTHY / CHECKS PASSED | nothing outside its envelope | 0 |
| ATTENTION | at least one ⚠ | 1 |
| NO BASELINE | no RTT floor anywhere, so nothing was judged | 2 |
| NO OPERATIONS | no S3 request was decoded, so nothing at the S3 layer was judged | 2 |
| NO RESPONSES | requests were decoded but not one was ever answered | 2 |
| MIXED PATHS | a floor was measured, but the capture spans two or more network paths, so no span could be judged against it | 2 |
| (no report) | `--live` only: the capture produced no records | 3 |
| (tool failure) | s3tap never got as far as a verdict | 4 |

**MIXED PATHS** is the newest of these and the least obvious. A pooled round-trip median across
a 1 ms path and a 200 ms path fits neither, so judging an op against it produces a ratio that is
wrong rather than absent — a 300 ms request reading "✓ 3.0×RTT". The floor is therefore withheld
from every span that cannot be attributed to one path, and if that leaves nothing judged, the
run says so. Two paths are detected either from distinct endpoint regions or from a bimodal
round-trip spread, so an unlabelled capture with a near and a far connection is caught too.

A capture can span several paths and still be perfectly judgeable: when each operation joins its
own connection, every one is scored against that connection's floor and the verdict is whatever
those rows say. MIXED PATHS is reserved for the case where nothing was judged at all.

**NO BASELINE is deliberately not 0**, because a run that could not judge anything must not
read green in CI. Treat 2 as "re-run me", not as a pass. Exit 3 is the `--live` counterpart:
the workload ran but nothing was captured, usually for want of probe caps, so there is no
report at all.

**NO OPERATIONS is the same refusal for the other missing denominator**, which is why it
shares code 2. Both mean "nothing was judged", so a script can do the same one thing with
either. The report line tells you which, since the remedies differ. The capture holds
connections but not a single `s3tap.operation/1` record, so the whole S3 half of the report
was computed over an empty population. A Go or rustls client produces exactly that shape, as
does any capture taken without the uprobe caps, because nothing decodes the HTTP layer. The
network rows can be perfectly clean at the same time, which is precisely why this is not
CHECKS PASSED: a green line would tell a CI gate that S3 looked fine when no S3 request was
ever seen. It sits below ATTENTION in precedence, so a ⚠ from a connection-sourced check
(retransmits, path) still wins and is never masked. The fix is to re-capture with
`--capture-plaintext` and the uprobe caps (`sudo s3tap setup --uprobes`), which is what
produces operation records at all. On the machine side the same run publishes as *Unjudged*
rather than *Healthy*, alongside NO BASELINE, so a fleet ingest can tell "we looked and it
was fine" from "there was nothing to look at".

**NO RESPONSES is the third missing denominator.** Operations WERE decoded here, but not one
of them carries an `http_status`. Every request was
still in flight when the capture ended, which is routine at Ctrl-C. The HTTP errors row counts
its numerator over answered ops only, so its `0` there is a construction rather than a
measurement, yet it used to print "0 / 5 ✓ healthy, all operations 2xx/204" and publish
`value: 0.0` beside `sample.judged: 0`, a 0/0 for any consumer computing a rate. That row is
now `n/a` with NO value. It names the shape instead ("none of the N operations in this capture
was answered"). The finding publishes *Unjudged*. `--baseline` carries the same rule: a metric that
was judgeable in the baseline and is not judgeable now is reported as unjudgeable rather than
as "unchanged", which is what "HTTP errors 20 → 0 · unchanged" used to claim about a capture
that could not judge them.

It gets its own verdict rather than being folded into NO OPERATIONS because the two remedies
differ. NO OPERATIONS says "re-capture with `--capture-plaintext`", which is wrong advice for a
capture that decoded every request and simply never saw the responses. The fix there is to let
the workload finish, or to capture for longer. Both share exit **2** all the same, since a
script can do the same one thing with either. Like NO OPERATIONS it sits below ATTENTION, so a
connection-sourced ⚠ still wins. `--strict` does not move it either.

This shape used to reach CHECKS PASSED with "no timeable operations" on the line. That reading
was defensible for the latency rows and wrong for the run: the reliability rows had an empty
population too, so a green line told a CI gate that S3 looked fine when no S3 response had ever
been seen. It is the same refusal as the two verdicts above.

**Exit 1 is a VERDICT and never a tool error.** It means s3tap read your capture, judged it
and found something outside its envelope. It never means s3tap itself broke. Everything in
that second category gets **exit 4**, reserved for exactly this: an input that could not be
read, an input that held no records at all, a `--save` target that already exists, a
baseline file that could not be read OR that parsed to zero records, a kernel below the 5.8
floor or without BTF, probes that would not load and the argument checks s3tap makes itself
(`--timeout-secs`,
`--requests`, `--concurrency`, `--live` without `--endpoint`, `--live` with `--from`). Read
1 as "the workload has a problem" and 4 as "fix the invocation". The distinction is what
makes exit 1 usable as a CI gate. A gate that cannot tell "your storage path regressed"
from "you pointed me at the wrong file" is not a gate. For a while this one could not.

One seam is worth knowing before you script against this. Arguments rejected by the
argument parser itself, rather than by s3tap, keep the parser's own **exit 2**: an unknown
flag, an unparseable value, or a `--live`-only flag such as `--save` passed without
`--live`. That collides numerically with the two verdicts that use 2. It is deliberate and
harmless to read correctly, because the parser writes a usage block to stderr and produces
no report at all,
so nothing on stdout can be mistaken for a judgment. If your gate distinguishes 2 from 4,
distinguish it on whether a report was produced, not on the number alone.

This table judges a capture that exists. The capture command itself exits 0 for an empty
capture, with one exception that reuses code 3: an `--app`/`--exe` scope that never had a
process in it. See [`run`](../commands/run.md#exit-code).

`--strict` widens the exit-1 case. An otherwise-healthy run that raised any advisory exits 1
too. It does not touch the missing-denominator verdicts: NO BASELINE, NO OPERATIONS, NO
RESPONSES and MIXED PATHS all stay 2. Nor does it promote an FYI row, which is what
separates FYI from advisory. `--cost` steps outside the mapping entirely: it is informational
and always exits 0.

`--baseline` does not. A missing denominator OUTRANKS the diff, so a current capture that
judged nothing exits **2** even under `--baseline` — the verdicts above really do stay 2
in every mode. Only when the current capture *had* a population does the code come from the
diff below (1 on a regression, 0 otherwise). Keying it on the diff alone made 2 structurally
unreachable, so a gate that lost its uprobe caps diffed "NO OPERATIONS → NO OPERATIONS",
printed "NO REGRESSION" and exited 0.

Because `--cost` keeps exit 0 by design, its honesty has to live in the text. A capture that
decoded no operation prints **"no S3 operation records decoded, so request cost is unknown"**
and no total at all, rather than a `$0.000000` that reads like a measured figure. "Data
returned" is counted only for a GET whose body was observed to completion, so a transfer still
in flight at Ctrl-C does not contribute its declared `content_length` as bytes that arrived.

## The input must be a capture

`doctor`, `advise` and `scorecard` **refuse** an input that parsed to zero `s3tap.*` records.
They exit **4** (tool failure) and print what they actually read, instead of rendering a
verdict over nothing. A findings file is not a capture. Neither is an empty file, a truncated
one, or any other log you happened to point at `--from`. The error names the count that
diagnoses it: a `doctor --json` findings file lands entirely in the unknown-schema count, a
truncated or non-JSONL file in the bad-line count, an empty file in neither.

This closes a real hole rather than a theoretical one. Before the guard, `doctor --from
findings.jsonl` rendered every row as n/a and reported NO BASELINE with capture-tuning advice,
so the operator re-captured forever against a file that was never a capture. Worse,
`advise --strict --from <empty>` printed "no advisories" and exited **0**. The CI gate had been
dead for as long as the path was broken. Nothing said so.

`analyze` has always refused an empty trace the same way. **`--baseline` now carries the same
guard.** It used to refuse only a path it could not open, so a file that opened and parsed to
zero records was accepted as a baseline of nothing. It is refused with exit 4 too, on the same
reasoning: a gate is not a gate if the reference side of the comparison can quietly be empty.
See the `--baseline` section below.

Global rows are pinned to match the parity oracle, a separate reference implementation that
recomputes the same checks. The S3-domain, tail, reuse, path and time-series rows are
**supersets**. They can raise the overall verdict but they never change the parity-pinned
per-row marks.

## `--baseline` diff

`doctor --baseline <capture.jsonl>` compares the current run against an earlier one and flags
regressions.

The baseline is a **capture of records**, not a findings file. It is re-analyzed from scratch,
so it must hold the same `s3tap.operation/1` + `s3tap.connection/2` JSONL that `--from` takes.
Feeding it the NDJSON of `doctor --json` does not work. A `s3tap.finding/1` line is not a
record, so the whole file parses to zero records and is refused. Two
things produce a usable baseline: a normal `s3tap --format jsonl` capture, or
`doctor --live --save <file>`, which writes the workload it just drove in exactly that format.

**A baseline that holds no records is refused, the same way `--from` is.** It opens the file,
parses it and, on zero `s3tap.*` records, reports what it actually read and exits 4 rather
than diffing against a baseline of nothing.

That closes the last instance of the pattern the zero-record guard was written for. Before it,
the flag refused only a path it could not open. What a zero-record file cost you depended
on the file. A `doctor --json` findings file printed one note on stderr (`note:
baseline: skipped N unparseable + M unknown-schema line(s)`) and then read every current warn
as brand new. An **empty or truncated** file had nothing to skip, so not even that note fired:
the baseline held no checks, a healthy current capture raised no new-issue delta and the gate
**exited 0** against a file that was never a capture. A CI job could sit green for months on a
baseline path someone had typo'd.

```console
$ s3tap doctor --live --endpoint https://… --save baseline.jsonl   # record a good run once
$ s3tap doctor --from today.jsonl --baseline baseline.jsonl        # gate on a regression
```

### `--save` writes a NEW file, mode 0600

`--save` creates its file with `O_CREAT|O_EXCL|O_NOFOLLOW` at mode 0600. Two consequences for
the recipe above.

**It refuses a path that already exists.** Re-running the record step over the same filename
fails rather than overwriting, so "record a baseline" is a once-per-filename operation. Delete
or rename the old file first, or save to a new name. There is no `--force`. Refusing an
existing path is the only version of this with no TOCTOU window, because the existence check
and the create are one atomic syscall. The path is claimed **up front**, beside the rest of
the usage validation, so a second run against an existing filename fails before a single
packet is sent rather than after driving a full billable workload. If the run then fails
before it has a capture, the reservation is released so the re-run is not refused by the empty
placeholder it just made. The reason it matters is that `doctor --live` routinely
re-execs itself under sudo, so this write commonly runs as **root** with the path taken from
an argument. The old behaviour followed symlinks and truncated, which let any user who could
pre-create the path aim a root-owned truncating write anywhere on the filesystem.

**It is owner-readable only.** A capture names your buckets, endpoint IPs, SNI hostnames,
per-request timings and key hashes. That is a map of your storage. At the old default mode it
was readable by every local user on a shared host.

A check that has vanished is treated as **loss of signal** (it gates as
*Unjudgeable*), never as a green "Resolved". A baseline warn only counts as resolved when it was
*watched* and the current capture can genuinely re-judge it. This stops a smaller or differently
shaped capture from hiding a regression.
