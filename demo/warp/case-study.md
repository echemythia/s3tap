# s3tap × warp: results and metric guide

A walkthrough of what the `warp/run.sh` run produces and the numbers from a real
capture against a cloud-provider gateway (`gateway.cloud-provider.example`). For each metric it covers **what it
is** and **how to read its value**.

> **The one-sentence pitch.** [warp](https://github.com/minio/warp) (MinIO's S3
> benchmark) tells you *what* happened at the application layer: ops/sec,
> throughput, request latency. s3tap watches the same traffic from inside the
> kernel and tells you *why*: the true network round-trip floor, packet loss,
> reordering and where a connection was actually bottlenecked. warp is a Go
> program (no OpenSSL to hook), so everything here comes from the kernel's TCP
> stack and is **library-agnostic**: it works for any client, in any language,
> with zero instrumentation.

---

## How the demo runs

```bash
./demo/warp/run.sh run        # warp drives traffic, s3tap observes passively
./demo/warp/run.sh analyze    # prints warp's numbers + s3tap's kernel view + a verdict
```

It exercises two deliberately different workloads:

| Profile | Workload | What it stresses |
|---|---|---|
| **iops** | 16 KiB objects, 64 concurrent, 15 s | Many small requests on a fat connection pool: connection-layer activity, low data volume |
| **throughput** | 8 MiB objects, 12 concurrent, 10 s | A few fat, long-lived download streams, where loss and reordering show up |

The contrast is the point: the **iops** path was clean, the **throughput** path
hit real congestion. Same tool, two very different kernel stories.

---

## Results

### Profile 1: `iops` (small objects, high concurrency)

**warp's own report (the *what*):**

```
Average: 4.81 MiB/s, 307.95 obj/s
Reqs:  Avg 199.7ms   50% 114.8ms   90% 362.8ms   99% 1333.6ms
TTFB:  Avg 195ms     Median 110ms                99th 1.329s
```

**s3tap's kernel view (the *why*):**

```
connections:        64   (TLS 1.3, TLS_AES_256_GCM_SHA384)
min_rtt (floor):    15.4 ms   jitter: 13.9 ms   srtt: 25.4 ms   (srtt ~1.6x the floor)
retransmits:        0 across 0/64 conns         max reordering: 3
download reorder:   none observed (recv-leg clean across 64 conns)
retrans volume:     0 B retransmitted (clean send path)
egress (bytes_recv): 87 MB
=> PATH STABLE: warp's p99 tail (1333.6 ms) is NOT path queueing — look server-side / at object size.
```

**Reading it:** the network is healthy. srtt (the current smoothed round-trip time) sits
at only 1.6× the floor, with zero loss and zero reorder. So warp's ugly 1.3 s p99 tail
(its slowest 1-in-100 request) is **not** the network. It's the S3 service or the
small-object overhead. The kernel rules out the path so you stop debugging the wrong
layer.

### Profile 2: `throughput` (fat objects, fewer streams)

**warp's own report (the *what*):**

```
Average: 110.34 MiB/s, 13.79 obj/s
Reqs:  Avg 923.4ms   50% 834.0ms   90% 1575.7ms   99% 2690.6ms
TTFB:  Avg 177ms     Median 178ms                 99th 264ms
```

**s3tap's kernel view (the *why*):**

```
connections:        12   (TLS 1.3, TLS_AES_256_GCM_SHA384)
min_rtt (floor):    16.1 ms   jitter: 12.9 ms   srtt: 36.7 ms   (srtt ~2.2x the floor)
retransmits:        174 across 4/12 conns        max reordering: 6
download reorder:   3413 out-of-order pkts across 7/12 conns
retrans volume:     250.6 KB retransmitted (0.08% of bytes_sent)
egress (bytes_recv): 1210 MB
=> CONGESTION+LOSS: srtt 2.2x the floor AND loss on 4/12 conns — the path is dropping packets under load.
```

**Reading it:** notice TTFB (time to first byte) is actually *better* here (178 ms
median). The **first byte** arrives fast. The pain is in the **transfer**. Pushing fat
streams fills the bottleneck buffer. srtt inflates to 2.2× the floor, packets drop
(174 retransmits) and arrive out of order (3413 packets across 7 of 12 streams).
That's a genuine *network* story. The kernel names it where warp's
first-byte-centric numbers can't.

---

## Metric glossary

Grouped by who produces it and what layer it describes.

### Application layer: warp's own numbers (*the what*)

- **Throughput (MiB/s)**: bytes moved per second, app-observed. Higher is better.
  *16 KiB objects → 4.8 MiB/s (request overhead dominates). 8 MiB objects →
  110 MiB/s (the pipe fills).*
- **obj/s**: completed operations per second. The small-object workload does far
  more *operations* (308/s) at far less *volume*.
- **Request latency percentiles (50% / 90% / 99%)**: end-to-end time per request.
  The **99th percentile (p99)** is the slow tail, the 1-in-100 request that
  defines your worst-case SLA. A median that looks fine with a fat p99 is the
  classic "most users are happy, some are furious" shape.
- **TTFB (Time To First Byte)**: request sent → first response byte back.
  Isolates *server think-time + the first round-trip* from the *transfer time*.
  When TTFB is low but total latency is high, the bottleneck is the **transfer**,
  not the server (exactly the throughput profile above).

### Connection & path: s3tap from the kernel (*the why*)

- **connections**: distinct TCP sockets s3tap saw (scoped to the `warp` process).
  Mirrors warp's concurrency + connection pooling.
- **TLS version / cipher**: the *negotiated* TLS parameters, parsed from the
  ServerHello **in the kernel** (no OpenSSL needed). Confirms TLS 1.3 + the AEAD
  suite actually in use. A silent downgrade to TLS 1.2 would show here.
- **min_rtt, the true round-trip floor (ms)**: the *fastest* round trip the
  kernel ever measured on the connection. This is the speed-of-light-plus-routing
  baseline to the server: it can't be beaten, only added to. **Everything else is
  judged relative to this floor.** *~15 to 16 ms here = the physical distance to the
  cloud-provider gateway.*
- **jitter (ms)**: round-trip variance (kernel `rttvar`). High jitter means an
  unstable path (variable queueing). *~13 ms: moderate, consistent with a shared
  internet path.*
- **srtt, smoothed round-trip time (ms)**: the *current* averaged round-trip time (RTT),
  which **includes queueing delay** the floor doesn't. The gap between srtt and min_rtt
  *is* the queueing.
- **srtt ÷ floor ratio**: **the headline health number.** ≈1× means no queueing
  (healthy). A large multiple means packets are sitting in buffers (bufferbloat /
  congestion). *iops 1.6× (fine) vs throughput 2.2× (the path is congested under
  the fat streams).*

### Loss & quality: the path-quality signals

These separate two things: *the path dropped data* versus *the path merely reordered
data*. The difference matters. Reordering looks like loss to a naive counter but
needs no fix.

- **retransmits**: TCP segments the kernel had to **send again** because they
  were lost or presumed lost. The primary loss signal. *iops: 0 (clean). throughput:
  174 across 4/12 connections (real loss under load).*
- **max reordering**: how far out of order the network delivered segments, as a
  *degree* (the kernel's reordering "window"). Linux defaults to **3**, so a
  value of 3 means "nothing notable", while 6 (throughput) means the path genuinely
  shuffled packet order.
- **download reorder: `rcv_ooopack`** *(new)*: out-of-order packets the client
  **received**. This is the **download-direction** signal. A GET's payload travels
  *to* the client, so reorder or loss on that leg is what actually slows the
  transfer. The static "max reordering" degree (stuck at the default) can't
  show it. *iops: none (clean download). throughput: 3413 packets across 7/12
  streams: the fat downloads were genuinely shuffled by the congested path.*
- **retrans volume: `bytes_retrans`** *(new)*: the **byte count** of
  retransmitted data, the honest companion to the *segment count* above. "174
  retransmits" doesn't tell you how much data that was. "250.6 KB (0.08% of bytes
  sent)" does. The percentage keeps it in proportion: here loss was real but tiny
  relative to the ~313 MB the client SENT. The denominator is `bytes_sent`, not
  the 1.2 GB downloaded: a retransmit is a resend on the send path, and on this
  profile most of those bytes are warp's own object-prepare upload. *iops: 0 B.*
- **spurious retrans: `dsack_dups`** *(new, send/upload-path)*: retransmits the
  receiver later confirmed were **unnecessary** (via DSACK): the original *did*
  arrive, so the resend was over-eager (reordering or a premature timeout), **not
  loss**. Correctly **silent** on these GET workloads. It's an upload-leg signal.
- **app-limited: `rate_app_limited`** *(new, send/upload-path)*: a kernel flag
  meaning the connection's send rate was capped by **the application not having
  data ready**, not by the network. It tells you "don't blame the network, the
  sender was idle." Silent here by design (GET workload). Under 64-way
  concurrency the connections were network-saturated, not app-starved (the sender always had data to push). *In a
  side test, a lone tiny request set this flag `true`: the app sent its request
  and then had nothing more to send, exactly what the flag is for.*

### Volume & verdict

- **egress (bytes_recv)**: total bytes the client pulled down, summed across
  connections. *87 MB (iops) vs 1210 MB (throughput).* These kernel-attributed
  byte counts are invisible to warp's own output.
- **The verdict line** (`PATH STABLE` / `CONGESTION+LOSS`): s3tap's `doctor`
  pairing warp's app-level tail with the kernel-level cause. It either **clears
  the network** ("your tail is server-side / object-size, stop tuning TCP") or
  **indicts it** ("srtt inflated *and* loss: the path is the problem"). That
  attribution is the whole value: it points you at the right layer.

---

## The takeaway

The same benchmark produced two opposite diagnoses. **Only the kernel view
could tell them apart**:

- **iops**: warp shows a fat p99 tail, s3tap shows a clean path → **the tail is
  not the network.** Go look at the S3 service or small-object overhead.
- **throughput**: warp shows high transfer latency, s3tap shows srtt inflation +
  loss + download reordering → **the tail *is* the network.** The path is
  congesting under fat streams.

warp (or `curl -w`, or your app's own metrics) can measure the symptom. It cannot
see the round-trip floor, the retransmits, or the out-of-order packets that
explain it. Those live in the kernel's TCP state. s3tap reads them passively
for any client, with no code changes.
