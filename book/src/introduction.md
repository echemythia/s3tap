# s3tap

**s3tap** watches what an application does with S3, then *judges* it. It uses eBPF (a way to
run small, safe programs inside the Linux kernel) to record the traffic. From one capture it
produces a plain-language health verdict, an optimization advisory or a machine-readable
findings stream.

It splits cleanly into two halves:

1. **Capture** (privileged, uses eBPF): quietly records what an app does with S3: DNS
   lookups, TCP connects, TLS handshakes, HTTP operations and the kernel's own `tcp_sock`
   stats (srtt is the smoothed round-trip time, plus min_rtt, retransmits and cwnd). These
   come out as versioned public JSONL records.
2. **Consumers** (unprivileged, pure): read those records and reason about them. Nothing
   here needs a probe or a privilege, so they compose in a pipe:

   ```console
   $ s3tap --format jsonl | s3tap doctor
   ```

## The commands at a glance

| Command | What it does | Privilege |
|---------|--------------|-----------|
| [no subcommand](commands/run.md) | Capture an app's S3 traffic → JSONL records | eBPF caps |
| [`doctor`](commands/doctor.md) | Judge a capture's health vs the RTT floor | none (pure) |
| [`check`](commands/check.md) | Self-driving probe + one-line verdict / region map | eBPF caps |
| [`advise`](commands/advise.md) | Optimization advice on how the app *uses* S3 | none (pure) |
| [`analyze`](commands/analyze.md) | Deep caching + prefetch report for one trace | none (pure) |
| [`scorecard`](commands/scorecard.md) | Per bucket/op latency + reliability, like a speed test | none (pure) |
| [`setup`](commands/setup-selftest.md) / [`selftest`](commands/setup-selftest.md) | Grant caps without sudo / prove the pipeline | mixed |

## Design principle: the record is the contract

Every consumer reads the same [public records](reference/records.md). So you can capture once,
then re-judge it offline, diff it against a baseline or feed it to a different tool. `doctor`
is checked against a small reference implementation (a "parity oracle") that works out the
same verdicts a second way, so its output stays honest and reproducible.

> This site documents the **implemented** commands and records. Exploratory or
> not-yet-built ideas are intentionally out of scope here.
