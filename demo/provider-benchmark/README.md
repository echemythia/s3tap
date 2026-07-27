# provider-benchmark

A fair head-to-head of **AWS S3 vs Storj**, measured from the **kernel** (TCP + HTTP off the
wire), so the comparison rests on the network path itself, not a client timer or a provider
dashboard. Built on `s3tap doctor --live` (the self-driving mode: it loads the
eBPF probes, drives N keep-alive GETs itself, captures them and judges each latency span
against the connection's own RTT floor, `srtt`).

Both providers serve **byte-identical** objects across three size tiers, so every number is
comparing like with like.

## Prerequisites

- A **capped** release binary (see the [top-level demo README](../README.md)):
  `cargo build --release -p s3tap && UPROBES=1 S3TAP_SETCAP_INSECURE=1 ./setcap.sh release`.
  The opt-out is needed because `setcap.sh` refuses a build-tree target by default. A
  root-owned install plus `S3TAP=/usr/local/bin/s3tap` is the alternative this demo honours.
- **Storj S3 credentials** in `~/.aws/credentials` under `[default]`. The AWS side is public
  (AWS Open Data, anonymous), so no AWS credentials are needed.
- ⚠️ **Egress cost:** a full `run` downloads ~650 MB from *each* provider. The **Storj
  ~650 MB is billable** (the AWS Open Data side is free egress).

## The three steps

```bash
./demo/provider-benchmark/run.sh mirror   # one-time: copy the AWS objects into your Storj bucket
./demo/provider-benchmark/run.sh run      # capture + judge every tier on both providers
./demo/provider-benchmark/run.sh table    # side-by-side TTFB + throughput from the saved captures
```

- **`mirror`** copies each public AWS object into your Storj bucket so both providers serve
  identical bytes. That is the only way the throughput comparison is fair. Idempotent (re-PUT
  is harmless). The secret is kept off `argv` (curl `-K` config) and the temp config is
  removed even if a transfer fails.
- **`run`** drives + captures each tier on both providers and saves JSONL per
  `(provider, tier)` under `$OUT`, which defaults to
  `${XDG_STATE_HOME:-$HOME/.local/state}/s3tap/bakeoff` and is created mode 700. It used to be
  a fixed `/tmp/s3tap-bakeoff`, which is a hole: `/tmp` is world-writable and `mkdir -p`
  silently accepts a directory somebody else already owns, so a local user could pre-plant that
  path (or a symlink inside it) and receive a capture naming your buckets, endpoint IPs, SNI
  hostnames, timings and key hashes. Since `doctor --live` re-execs under sudo, the same
  pre-planted symlink also aimed a root-owned write at a file of the attacker's choosing.
- **`table`** summarizes the saved captures.

## Why a size ladder

TTFB and throughput are two different regimes. A single object size can't isolate them. The
tiers (tunable at the top of `run.sh`) do:

| Tier | ~Size | Requests | Isolates |
|------|-------|----------|----------|
| `8k`  | ~11 KB | 120 | **latency & tail**: TTFB is size-independent, so small objects expose server think-time and the p99 tail (hence the high request count) |
| `1m`  | ~1.5 MB | 40 | the **TCP slow-start** transition |
| `32m` | ~38 MB | 16 | sustained **single-stream throughput**: the only tier where `MB/s` is a real number (it converges fast, so few requests) |

## Reading the table

```
tier  prov      srtt  TTFB p50   think    MB/s*
8k    aws      ...       ...      ...        —
8k    storj    ...       ...      ...        —
...
32m   aws      ...       ...      ...      ...
* MB/s is single-stream goodput (RTT-bound); only meaningful at the 32m tier.
```

- **`srtt`**: the network round-trip floor (how *far* the provider is from you).
- **`TTFB p50`**: median time-to-first-byte.
- **`think` = `TTFB p50 − srtt`**: the key column. It subtracts the network round-trip, so
  it's the provider's **own server-side latency, distance-normalized**. A nearer provider
  doesn't automatically "win" on `think`.
- **`MB/s`**: single-stream goodput. RTT-bound, so only trustworthy at the 32m tier.

(Exact numbers depend on your location, network and the Storj region. The value is the
*comparison* between the two columns, not any single figure.)

## Notes

- This is a self-driving capture, so it needs the eBPF caps. `run` loads probes and drives
  its own workload (contrast `parallelism/`, which captures an external client).
- `srtt` is read off `tcp_sock` at connection close. The `think` normalization is why this
  is more honest than a bare TTFB race between a near and a far provider.
