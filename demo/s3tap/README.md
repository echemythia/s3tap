# s3tap demo

A guided, repeatable demo of what **s3tap** can reconstruct from real S3 traffic, with
**no changes to the client**. The traffic comes from plain `curl` and a Python client
built on the standard library. Neither one calls s3tap or knows it is there. s3tap
watches from the kernel using eBPF and rebuilds the connection, DNS, TLS and the decoded
S3 operations on its own.

> The probes don't care which library the client uses. s3tap reads the server name from
> the TLS handshake. To see the HTTP traffic, it hooks OpenSSL's read and write calls,
> both the older ones and the newer variants that modern clients like Python/`boto3` use.
> So `curl`, `boto3`, `aws-cli` and any other OpenSSL client are decoded the same way.
> Clients built on Go or rustls still get the connection and server name, just not the
> decoded HTTP. This demo uses `curl` + Python against a **cloud-provider** S3 gateway,
> but nothing here is tied to curl or to one provider.

## Run it

```sh
# 1. build (build.rs compiles + embeds the eBPF object)
cargo build --release

# 2. grant file caps once so it runs without sudo (re-run after every build,
#    since caps live on the binary inode). --uprobes is required: the demo uses
#    --capture-plaintext, whose OpenSSL uprobes need cap_sys_admin.
#
#    NB `s3tap setup` REFUSES a build-tree binary: it requires the binary and every
#    ancestor directory up to / to be root-owned and not group/world-writable, so
#    caps never land on a target a local user could rewrite. Two ways through:
UPROBES=1 S3TAP_SETCAP_INSECURE=1 ./setcap.sh release   # dev box, opts out explicitly
#    ...or install somewhere root-owned and cap that copy (then run THAT binary):
#      sudo install -m 0755 target/release/s3tap /usr/local/bin/s3tap
#      sudo /usr/local/bin/s3tap setup --uprobes
#    Or skip the grant entirely and run run.sh under sudo. NB run.sh always invokes
#    target/release/s3tap, so a /usr/local/bin copy needs run.sh edited to match.

# 3. credentials: either export S3-compatible keys…
export AWS_ACCESS_KEY_ID=…  AWS_SECRET_ACCESS_KEY=…
#    …or drop your cloud-provider S3 credentials file in ~/Documents (auto-detected).

# 4. go
./demo/s3tap/run.sh
```

Configurable via env: `S3TAP_DEMO_ENDPOINT` (an S3-compatible gateway, whose built-in
default is set at the top of `run.sh`), `S3TAP_DEMO_BUCKET` (default `test`),
`S3TAP_DEMO_REGION` (default `us-east-1`). The transcripts below are from a run against
one such gateway, shown here as `gateway.cloud-provider.example`.

The demo passes `--s3-endpoint <host>` so that s3tap can work out the bucket and key for
this non-AWS endpoint (see the last section for why this flag is needed).

The bucket is expected to contain a few objects (the demo reads `docs/hello.txt`,
`data/config.json`, `docs/readme.md`, `data/sample.bin`). It creates and deletes two
temporary objects of its own (`demo/_demo_upload.txt` and a 1 MiB `demo/_big.bin`).

## What it shows

### 1) `selftest`: pipeline health check

Loads the probes, sends a couple of real requests, checks that each capability actually
produced a record and exits with an error if any of them did not:

```
s3tap selftest — capability check (endpoint host: gateway.cloud-provider.example)

  DNS resolution   PASS  resolved 203.0.113.10 (10.0 ms, via getaddrinfo)
  TCP connect      PASS  connect 16.7 ms
  TLS / SNI        PASS  SNI gateway.cloud-provider.example
  HTTP semantics   PASS  GET ListObjects → 401

  result: PASS
```

### 2) `waterfall`: a per-operation latency timeline

Each S3 operation, decoded and split into phases. Note the **honesty**: a phase that
can't be measured on this path (`TLS handshake`, `download`, `total`) is labeled
`(not measured)`, never faked as zero. When one connection is reused for several
operations, it is marked `[reused]` and skips the setup phases it already paid for on
the first request:

```
GetObject s3://test/<key>   → 203.0.113.10   32.4 ms (ttfb)  ✓ 200

  DNS            ──  2.0 ms  cold resolve
  TCP connect      ────────────  15.5 ms
  TLS handshake  (not measured)
  request ▸ TTFB               ──────────────────────────  32.4 ms
  download       (not measured)

  op sent 349 B · recv 480 B · reused=false

GetObject s3://test/<key>   39.5 ms (ttfb)  ✓ 200

  connection     [reused]
  request ▸ TTFB ────────────────────────────────────────  39.5 ms
  download       (not measured)

  op sent 351 B · recv 500 B · reused=true

203.0.113.10:443  pid=223670  connect=15.47ms  sent=1736B recv=6327B  rtx=0  srtt=20.1ms  life=0.2s  sni=gateway.cloud-provider.example
```

### 3) Structured records: the stable public schema

The same events as machine-readable JSONL (`s3tap.connection/2` + `s3tap.operation/1`).
The object key is **hashed** (`sha256:…`), so the real key is never written out. The
SigV4 signing credential never leaves the kernel:

```json
{
  "schema": "s3tap.operation/1",
  "req_seq": 0,
  "app": { "pid": 223534 },
  "verb": "GET",
  "s3_op": "GetObject",
  "bucket": "test",
  "key_hash": "sha256:c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff",
  "dns": { "latency_ns": 2003110, "cache_hit": false, "resolved_ip": "203.0.113.10", "via": "getaddrinfo" },
  "tcp_connect_ns": 15470000,
  "ttfb_ns": 26800000,
  "op_bytes_sent": 349,
  "op_bytes_recv": 480,
  "connection_reused": false,
  "http_status": 200,
  "aws_request_id": "EXAMPLE1234567890",
  "partial": false
}
```

> `bucket` is `"test"` because the demo runs with `--s3-endpoint gateway.cloud-provider.example`
> (see the limitations note). Without that flag, a non-AWS host yields `bucket: null`.

A full workload, summarized. Note `req_seq` / `reused` tracking three GETs over one
reused TCP connection:

```
  ListObjectsV2 req_seq=0 reused=False status=200 ttfb=118.9ms key=sha256:c0ffee0001…
  GetObject     req_seq=0 reused=False status=200 ttfb= 28.5ms key=sha256:c0ffee0002…
  GetObject     req_seq=1 reused=True  status=200 ttfb= 26.3ms key=sha256:c0ffee0003…
  GetObject     req_seq=2 reused=True  status=200 ttfb= 28.3ms key=sha256:c0ffee0004…
  HeadObject    req_seq=0 reused=False status=200 ttfb= 23.9ms key=sha256:c0ffee0003…
  PutObject     req_seq=0 reused=False status=200 ttfb= 16.7ms key=sha256:c0ffee0005…
  DeleteObject  req_seq=0 reused=False status=204 ttfb= 58.3ms key=sha256:c0ffee0005…
```

### 4) Library-agnostic: curl and Python, decoded identically

The same `GetObject`, run by two different clients (`curl` and a standard-library Python
client) and decoded the same way, even though each uses a different set of OpenSSL calls.
s3tap sits in neither client's code path. `boto3` and `aws-cli` use the same
Python/OpenSSL path:

```
  pid=235160  GET    GetObject   bucket=test status=200 ttfb= 27.5ms
  pid=235162  GET    GetObject   bucket=test status=200 ttfb= 40.1ms
```

(Clients built on Go or rustls still get the connection and server name. Decoding the
HTTP contents needs OpenSSL.)

### 5) Failures: problems, not just happy paths

A missing object (`404`), an unsigned request (`403` denied) and a refused connection,
all captured:

```
operations (the error status is captured, not just success):
  GetObject   status=404  <-- error
  GetObject   status=403  <-- error
connections (a refused connect is flagged; no bytes ever flowed):
  connect_failed=true  ip=203.0.113.10:81  (SYN sent, never established)
```

### 6) Table view + byte counters

The `--format table` scanning view (one row per operation), then a 1 MiB GET that shows
the important distinction between **operation** bytes (just the HTTP headers s3tap sees)
and the **connection**'s full transfer (the whole 1 MiB):

```
OP             BUCKET                 CODE      TTFB  CONN      RECV FLG
ListObjectsV2  test                    200   24.8 ms   new   2.1 KiB
GetObject      test                    200   39.8 ms   new     480 B
GetObject      test                    200   31.9 ms reuse     500 B
GetObject      test                    200   31.4 ms reuse     496 B
HeadObject     test                    200   23.9 ms   new     431 B
PutObject      test                    200   17.0 ms   new     314 B
DeleteObject   test                    204   36.8 ms   new     261 B

  operation  GetObject   op_bytes_recv=4096 B  (HTTP head only — not object size)
  connection             bytes_sent=991  bytes_recv=1055381  srtt=21.2ms  (the full 1 MiB transfer)
```

### 7) Per-app scope: in-kernel filtering

When you scope to `--app curl`, a `python3` client hitting the **same endpoint** is
dropped **in the kernel**, before any of its data ever reaches s3tap:

```
  records captured            : 2 (curl)
  python3 (pid 235308) records  : 0  ← dropped in-kernel by --app curl
```

Scope can be a single process (`--pid`), an app name or executable (`--app`/`--exe`), or
a cgroup/container (`--cgroup`/`--container`). If a tracked process spawns child worker
processes, those are followed automatically in the kernel.

### 8) Analytics: are the profiled values good/expected?

s3tap *measures* the numbers. This step *judges* them. Every latency is compared to the
connection's smoothed round-trip time (`srtt`), the network's baseline latency, which
s3tap reads from the kernel. Comparing against that baseline means the verdicts hold
whether the endpoint is 2 ms or 200 ms away. "A few times the round-trip time" is healthy,
while a raw millisecond count on its own tells you nothing. The analyzer
(`demo/s3stats.py`) reads the same JSONL:

```
are these numbers healthy? (each span vs the round-trip floor)
  baseline RTT (srtt)  20.1 ms    floor    the network round-trip floor, every span below is judged against it
  DNS, cold resolve     2.0 ms  · fyi      first lookup (cached resolves are ~0), not judged: the resolver is on a different path than the endpoint, so the RTT floor is not its baseline
  TCP connect          15.3 ms  ✓ expected ≈0.8×RTT, a single SYN/SYN-ACK, as expected
  TTFB, new conn       28.5 ms  ✓ expected 1.4×RTT, request round-trip + server think (excludes setup)
  TTFB, reused conn    27.3 ms  ✓ good     1.4×RTT, setup already paid, reuse avoids ~15.3 ms tcp_connect/op (+ TLS)
  retransmit rate        0.00%  ✓ clean    no real loss on the path (TLP excluded)
  HTTP errors            0 / 7  ✓ healthy  all operations 2xx/204

  verdict: HEALTHY: latencies track the round-trip floor, connection reuse is working
```

When the path degrades, the affected **judged** rows flip to `⚠`. Dropped packets show up as
`loss`, `4xx/5xx` responses as `errors` and a `TCP connect` far above one round-trip as
`high`. The overall verdict then becomes `ATTENTION`. The cold-resolve row is the one that
never flips: it carries a `·` and is reported, never judged. The floor above it measures the
round trip to the S3 endpoint, while the resolver sits on a different path doing recursion, so
that floor is not its baseline. Any absolute millisecond ceiling would be a number this demo
invented, which is the thing it set out not to do. This judging step is deliberately
thin. The real point is that the raw schema already carries everything an SRE needs to
reason about S3 health, with no client changes.

## Notes & honest limitations

- **Finding the bucket name on non-AWS endpoints needs the opt-in `--s3-endpoint <host>`
  flag** (which this demo passes). By default s3tap only recognizes AWS hostname
  patterns: the server name `<bucket>.s3.<region>.amazonaws.com`, or the first path
  segment on an `s3.…amazonaws.com` host. It won't assume some arbitrary host is S3 and
  wrongly treat a non-S3 API's first path segment as a "bucket". Passing
  `--s3-endpoint gateway.cloud-provider.example` tells s3tap to treat that host as an S3
  endpoint. It then finds the bucket either in the path (`<endpoint>/<bucket>/<key>`) or
  in the hostname (`<bucket>.<endpoint>`). Without the flag, s3tap still captures the
  operation type, key hash, status, latency and request ID. Only `bucket` comes out
  `null`.
- **`download` / `total` are measured** whenever the response has a `Content-Length`,
  the common case for a GET. s3tap counts how many response bytes have been read against
  that length, without ever copying the object's contents. They show `(not measured)`
  only when the length can't be known ahead of time (chunked responses, no
  `Content-Length`, HEAD, 204 or 304) or when the body didn't finish before the
  connection closed. **`TLS handshake` is always `(not measured)`** here: s3tap only sees
  the start of the handshake being sent, so it can't time how long the handshake took.
  Either way, s3tap labels phases it can't measure honestly, instead of showing a
  misleading `0`.
- **Decoding the HTTP layer only works for OpenSSL clients.** s3tap hooks OpenSSL's read
  and write calls (both the older and newer variants), so curl, Python/`boto3`,
  `aws-cli` and other OpenSSL clients are decoded. A client that uses Go's `crypto/tls`,
  rustls or a statically-linked BoringSSL has no OpenSSL functions to hook, so s3tap
  still captures its connection, DNS and TLS/server name. It just has no per-operation
  record.
- A `⚠ partial` op (you might see one on a larger GET) means s3tap couldn't tie the
  operation back to its connection details in time, because a setup event arrived late
  or out of order. The operation is still reported and flagged, rather than silently
  dropped or shown with wrong numbers.
- `--capture-plaintext` can see decrypted bytes from every process on the host, so it's
  **opt-in** and best used together with a scope (`--app`/`--pid`/…), which is what this
  demo does.

## See also

For a deeper case study, a [warp](https://github.com/minio/warp) benchmark under load
where s3tap's kernel-level view explains a latency spike the application couldn't account
for, see [`warp/case-study.md`](../warp/case-study.md).
