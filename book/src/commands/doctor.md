# `doctor`: health verdict

`doctor` reads a capture (`s3tap.operation/1` + `s3tap.connection/2`, from `--from` or stdin)
and judges whether each latency span is healthy **relative to the connection's RTT floor**. The
floor is the connection's smoothed round-trip time (`srtt_us`), falling back to its lowest
observed round-trip (`min_rtt_us`) when no smoothed value was sampled. Smoothed rather than
lowest on purpose: it is the basis the `×RTT` thresholds are calibrated on, and for think-time
(TTFB minus the network round-trip) the round-trip the connection is CURRENTLY seeing is the
right thing to subtract, not its best-ever propagation floor. `doctor`
only reads records, so it loads no probes and needs no privileges. It composes in a pipe:

```console
$ s3tap --format jsonl | s3tap doctor
$ s3tap doctor --from capture.jsonl
```

It **exits non-zero** when any metric falls outside its healthy range (⚠), so it works as a CI gate.

Exit 1 is always a **verdict** about your traffic. If s3tap itself could not do the job (a
`--from` path it could not read, an input holding no records, probes that would not load) it
exits **4** instead, so a gate can tell "the workload regressed" from "fix the invocation".
The full table is in the [doctor metrics reference](../reference/doctor-metrics.md#verdict--exit-code).

`--from` wants a capture and it checks: an input that parsed to zero `s3tap.*` records is
refused with exit 4, never rendered as a verdict over nothing. `--baseline` is held to the
same standard, so the reference side of a regression gate cannot quietly be empty either.

A capture that holds connections but no S3 operation is a third answer, not a pass. `doctor`
reports **NO OPERATIONS** and exits 2: the network path was judged, the S3 layer was not.
That is what a Go or rustls client looks like, or any capture taken without the uprobe caps.

A capture whose operations were decoded but never answered is the fourth. `doctor` reports
**NO RESPONSES** and also exits 2. Every request was still in flight when the capture ended,
which is what Ctrl-C mid-workload produces, so the reliability rows had nothing to judge
either. It is a separate verdict from NO OPERATIONS because the remedy differs: let the
workload finish, rather than re-capture with the uprobe caps.

## What it judges

- **Global rows**: DNS cold-resolve, TCP connect, TTFB (new / reused), retransmit rate, HTTP errors.
- **S3 per-op-class TTFB**: think-time = ttfb − RTT, separating a far server from a slow one.
- **Tail latency**: p95 / p99 of the TTFB populations (the slowest 5% and 1% of requests, so you see worst-case delays not just the average).
- **Connection reuse rate**: are you repaying TCP+TLS setup unnecessarily?
- **Connection path diagnosis**: min_rtt/jitter, send/recv bottleneck, BDP ceiling (the most data that can be in flight at once, which caps throughput), loss shape.
- **In-flight time-series**: throughput ramp, bufferbloat onset (delay that builds up when buffers overfill), loss timeline (from samples).
- **Deployment environment estimate**: same-region / cross-region / far.

See the [doctor metrics reference](../reference/doctor-metrics.md) for how each is computed.

## Modes

| Flag | Effect |
|------|--------|
| `--json` | Emit one `s3tap.finding/1` per check plus a run roll-up (fleet-ingest format, meant for gathering results across many machines) |
| `--baseline <file>` | Diff against a prior **capture** (records, not findings) to gate on regressions |
| `--cost` | Approximate per-op-class request-cost breakdown (informational, always exits 0). A capture that decoded no operation reports the cost as **unknown** rather than as $0 |
| `--live` | Drive + capture its own workload instead of reading records (loads eBPF, needs caps) |
| `--no-color` | Disable ANSI (also auto-off when piped) |

`--live` is what the friendlier [`check`](check.md) wraps.

## What `--live` says about the capture itself

A capture can be thin for reasons that have nothing to do with your storage path. The record
set looks the same either way. So `--live` reports what the capture actually did
**before** the verdict, on stderr. Read those lines first: they tell you how much the table
below them is worth.

| Line | What it means |
|------|---------------|
| the traffic driver could not run | Nothing was driven at all. The capture says nothing about the target |
| the workload never completed a request | Every curl invocation failed, on the exit code named. The capture describes that failure, not the target's health |
| the run hit its time budget with the driver still going | Truncated. It captured N of the M requested requests. Raise `--timeout-secs` for the full sample |
| this capture is INCOMPLETE | The kernel dropped events with a ring buffer full. Every rate and percentile below is drawn from a population missing exactly the events a full ring sheds |
| undecodable ring-buffer record(s) | A probe/agent ABI mismatch. Also incomplete |
| dropped process-exec notification(s) | A forked worker may have been missed by the capture scope |
| dropped in-flight TCP sample(s) | Only the sample stream lost data. No connection, DNS or SNI data was lost |

The drop warnings matter more than they look. A full ring sheds events under load. Load is
exactly when the slow operations happen. A "healthy" median computed after the slow tail
was dropped is not a healthy median. Treat any INCOMPLETE line as reason to re-run with lower
`--concurrency` or `--requests` before believing a percentile.

The zero-record case is separate: if nothing at all was captured there is no report, and
`--live` exits 3.

Only `doctor --live` and a targeted `check` print these. The zero-config regional sweep
suppresses them, because it drives one short probe per region and summarizes those itself.

## Parity

A parity test suite pins `doctor`'s verdicts against a small reference oracle (a second, simple
implementation kept as the source of truth). For any input the Rust engine and the oracle must
agree on the marks and the run verdict. This keeps the judgments honest and reproducible.

See the [CLI reference](../reference/cli.md#s3tap-doctor) for every flag.
