# CLI reference

> Generated from `s3tap --help` by `book/gen-cli-reference.sh`. Do not edit by hand.

## s3tap

```text
Observe TCP/S3 connections and operations via eBPF (waterfall/table/jsonl)

Usage: s3tap [OPTIONS] [COMMAND]

Commands:
  selftest   Prove the pipeline works on this host: load the probes, drive a few real S3 requests, and assert each capability (DNS/TCP/TLS/HTTP) produced a record. Prints a pass/fail table and exits non-zero on any failed capability
  doctor     Judge a capture's health: read `s3tap.operation/1` + `s3tap.connection/2` JSONL (stdin or a file) and report whether each latency span is healthy, relative to the connection's RTT floor. A PURE CONSUMER of the public records — no probes, no privilege; composes as `s3tap --format jsonl | s3tap doctor`. Exits non-zero when a metric is outside its envelope (⚠). EXCEPTION: `--live` drives + captures its own workload (loads eBPF, needs caps) instead of reading records
  advise     Optimization advisories over a capture: read `s3tap.operation/1` + `s3tap.connection/2` JSONL (stdin or a file) and report how the application USES S3 — client churn, missing parallelism, redundant re-fetches, throttling, caching go/no-go — attributed per process. A PURE CONSUMER of the public records (no probes, no privilege); composes as `s3tap --format jsonl | s3tap advise`. Health judgments live in `doctor`; this is optimization advice
  scorecard  Observed-SLO scorecard over a capture: read `s3tap.operation/1` JSONL (stdin or a file) and report each `bucket / s3_op` with the latency + reliability it ACTUALLY saw — request/error counts, the status-code mix, and TTFB p50/p95/p99. The passive analogue of a speedtest (your own production numbers, no synthetic probe). A PURE CONSUMER (no probes, no privilege); composes as `s3tap --format jsonl | s3tap scorecard`. `--json` emits `s3tap.scorecard/1` rows plus the gated `s3tap.finding/1` reliability judgments; `--strict` exits non-zero when any judgment fired
  analyze    Deep caching + prefetch report for ONE trace: the offline study, run on your workload. Reads a trace (s3tap JSONL, NormEvent JSON, or an IBM COS line — a file or stdin), runs the FULL retention ladder (LRU / ARC / S3-FIFO / OPT) in chunk mode plus the prefetch tradeoff, and prints a recommendation: cache or not, which policy, what size, and whether prefetching will help. Heavier than `advise` (seconds to minutes) — a PURE CONSUMER (no probes, no privilege). `--fast` runs retention-only (~12× quicker); `--json` emits the structured verdict. Composes as `s3tap --format jsonl | s3tap analyze`
  check      The easy front-end to `doctor --live`: probe an S3 object and print a one-line plain-language verdict. Give it a `bucket/key` (expanded to the S3 endpoint) or a full URL for a verdict on YOUR path (strict exit code). Omit the target for the zero-config check: a regional round-trip map, then a health check against a public AWS Open Data object in the nearest covered region (informational exit; `--map-only` prints just the map). Loads eBPF: the L7 rows want the uprobe caps (`sudo s3tap setup --uprobes`), the map needs only the base caps (`sudo s3tap setup`) — without them s3tap offers sudo itself and, lacking uprobes, judges the network floor only. Full flags: `doctor --live`
  setup      Grant this s3tap binary the file capabilities to load its probes WITHOUT sudo — the programmatic `setcap.sh`. Asks for sudo itself (once); re-run after every rebuild (caps live on the binary inode, which `cargo build` replaces)
  help       Print this message or the help of the given subcommand(s)

Options:
      --no-elevate
          Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo

      --format <FORMAT>
          Output format. Default: `waterfall` on an interactive terminal, `jsonl` when piped/redirected (so the machine path stays clean for scripts)

          Possible values:
          - jsonl:     One JSON record per line (s3tap.connection/2 + s3tap.operation/1)
          - human:     A compact human-readable line per record
          - waterfall: A phase-aligned latency timeline per operation
          - table:     One fixed-width row per operation, for scanning a live stream

      --include-loopback
          Include loopback connections (127.0.0.0/8, ::1). They are dropped in-kernel by default as noise — S3 traffic is never loopback. Useful against a local S3-compatible endpoint (MinIO, LocalStack, a test proxy)

      --dump-events
          Print a one-line summary of every raw EVT_* to stderr as it is drained. A diagnostic for confirming a probe FIRES end-to-end (especially the uprobes: getaddrinfo and the OpenSSL read/write family) — independent of whether the event then correlates. Records still go to stdout as usual

      --pid <PID>
          Restrict capture to these process ids (low-level escape hatch)

      --app <NAME>
          Restrict to an app by its EXE BASENAME, e.g. "python3" (resolved from /proc/<pid>/exe). Matched at exec (plus a startup /proc scan), and a tracked process's fork()ed children are followed in-kernel — so a pre-fork server's workers (gunicorn/uWSGI/Spark) are captured even though they never exec (best-effort: needs the sched_process_fork tracepoint; a warning prints if it's unavailable, where --cgroup is the churn-immune fallback). NB the process's own `comm` is NOT matched: any process can rename itself (prctl PR_SET_NAME) and so walk into the capture. A basename is still only as trustworthy as the paths local users can write, so on an untrusted multi-tenant host use --exe (exact path), --cgroup, or --pid, which can't be forged. A run scoped by name alone that never matched a process and captured nothing exits 3, so a script can tell a scope that missed from an app that was quiet.

          A trailing VERSION SUFFIX is stripped before the compare, so --app python3 matches /usr/bin/python3.12 and --app gcc matches gcc-11. That is required rather than a convenience: /proc/<pid>/exe is the symlink-RESOLVED path, so on every mainstream distro the interpreter you name only ever appears under its versioned name. The suffix must start at a `-` or `.` and be digits from there, so python311 and python3-shim stay out.

          Resolving ANOTHER user's process needs CAP_SYS_PTRACE, which `s3tap setup` does not grant (cap_dac_read_search bypasses DAC, not the ptrace check), so a capability-tagged s3tap matches only processes owned by the user running it. It warns once when that happens. Run as root, or scope with --pid, --cgroup or --container.

      --exe <PATH>
          Restrict to an exact executable path. Like --app, matched at exec / the startup scan and followed across fork(), so forked workers are captured. The path is resolved to its absolute form (via /proc/<pid>/exe) at both exec and scan time, so a relative `./server` invocation still matches an absolute --exe. Same exit-3 contract as --app for a scope that never matched anything

      --cgroup <ID>
          Restrict to a cgroup id (as `bpf_get_current_cgroup_id`; see a PROC_EXEC line under --dump-events). Churn-immune — all the cgroup's processes are in scope

      --container <ID|NAME>
          Restrict to a container by a (full) id/name substring of its v2 cgroup path. Best-effort: if it captures nothing, cross-check the resolved id against a PROC_EXEC `cgroup=` line under --dump-events and pass it as --cgroup instead

      --capture-plaintext
          Capture TLS PLAINTEXT (the HTTP request/response heads) via OpenSSL uprobes. Hooks SSL_write/SSL_read plus the OpenSSL 1.1.1+ size_t API, SSL_write_ex/SSL_read_ex, which is what modern clients call. The _ex pair is attached only where libssl exports it, so an older library still works. OFF by default and deliberately so: these are host-wide probes that see DECRYPTED bytes, including AWS SigV4 Authorization headers and `x-amz-security-token` STS tokens — usable credentials — for EVERY process on the host. The default run (connections + SNI) never buffers those. Enable only when you need L7/HTTP semantics and accept that exposure (also requires the uprobe caps: `sudo s3tap setup --uprobes`)

      --s3-endpoint <HOST>
          Treat this host as an S3-compatible endpoint so its bucket is resolved from the request — path-style `<endpoint>/<bucket>/<key>`, or `<bucket>.<endpoint>` virtual-hosted. Repeatable. Opt-in: s3tap otherwise recognizes only AWS hostname patterns and won't guess an arbitrary host is S3 (which could mis-split a non-S3 API's path). Accepts a bare host or a URL — scheme and port are stripped — e.g. `--s3-endpoint gateway.storjshare.io` or `--s3-endpoint https://minio.local:9000`. Only affects bucket/key decoding on the --capture-plaintext path

      --sample-interval-ms [<MS>]
          Emit periodic in-flight TCP samples (`s3tap.sample/1`) every N ms while a connection moves data — the EVOLUTION of cwnd/RTT/throughput/loss the close snapshot can't show. Library-agnostic (kernel TCP); OFF by default and pays ZERO overhead when unset (the probe isn't even attached). With no value it defaults to 100 ms; the minimum is 10 ms. jsonl only. Loud warning if used without a scope flag (--pid/--app/--exe/--cgroup): in TRACK_ALL the probe runs on every host-wide RX softirq

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## s3tap selftest

```text
Prove the pipeline works on this host: load the probes, drive a few real S3 requests, and assert each capability (DNS/TCP/TLS/HTTP) produced a record. Prints a pass/fail table and exits non-zero on any failed capability

Usage: s3tap selftest [OPTIONS]

Options:
      --endpoint <ENDPOINT>  S3-style HTTPS endpoint to probe (default: real AWS S3). An unauthenticated request still exercises DNS→TCP→TLS→HTTP, which is all selftest checks [default: https://s3.amazonaws.com]
      --requests <REQUESTS>  Number of requests the driver issues [default: 3]
      --no-elevate           Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
  -h, --help                 Print help
```

## s3tap doctor

```text
Judge a capture's health: read `s3tap.operation/1` + `s3tap.connection/2` JSONL (stdin or a file) and report whether each latency span is healthy, relative to the connection's RTT floor. A PURE CONSUMER of the public records — no probes, no privilege; composes as `s3tap --format jsonl | s3tap doctor`. Exits non-zero when a metric is outside its envelope (⚠). EXCEPTION: `--live` drives + captures its own workload (loads eBPF, needs caps) instead of reading records

Usage: s3tap doctor [OPTIONS]

Options:
      --from <FILE>                  JSONL of public records to judge: a file, or `-`/absent for stdin
      --no-color                     Disable ANSI color (also auto-off when stdout isn't a terminal)
      --json                         Emit `s3tap.finding/1` records (NDJSON, one per check + the run roll-up) instead of the human table — the machine/fleet-ingest format. Still reads from `--from`/stdin and keeps the same exit-code contract
      --baseline <FILE>              Compare the current capture against a baseline JSONL file and print a regression diff instead of the report. Latency checks are compared RTT-relative, so a capture from a different network still compares fairly. Exits 1 if the current capture regressed, 2 if the current capture had nothing to judge, 0 otherwise. A structured diff is future, so this conflicts with `--json` rather than silently writing a human table where NDJSON was asked for
      --strict                       Stricter gate: treat ADVISORY findings (e.g. a GET-throughput drop) as attention too, so they affect the exit code / fail the `--baseline` gate. Off by default — advisory metrics are deliberately unjudged (BDP/window-dependent)
      --cost                         Print an approximate S3 request-cost breakdown (per op-class) instead of the health report. Estimate only (AWS Standard us-east-1 request prices; data egress not included). Informational — always exits 0
      --brief                        Collapse the report to a one-line, plain-language verdict (plus the specific issues to look at on ATTENTION) — the easy read for non-technical users. Same verdict + exit code as the full report, just without the per-span table. Ignored under --json/--cost/--baseline
      --live                         Drive a small keep-alive workload against `--endpoint`, capture it, and report — instead of reading records from `--from`/stdin. Loads eBPF, so it needs the probe caps (`sudo s3tap setup --uprobes` for the L7/operation rows). Composes with `--strict`, and with ONE of `--json` / `--cost` / `--baseline` — those three each replace the report body, so they are mutually exclusive. Exit 3 if it captured nothing
      --no-elevate                   Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
      --endpoint <URL>               (`--live`) The readable S3 endpoint/object the workload hits — REQUIRED under `--live`. An endpoint the workload can't read 2xx from will read unhealthy, by design. Repeatable: with `--rotate`, the requests cycle through all the given objects (one per request) so every fetch is COLD — defeats per-object caching for a cold-fetch measure
      --rotate                       (`--live`) Rotate through the `--endpoint` objects, one per request (round-robin), instead of hammering a single object. Use it to measure COLD-fetch latency: pass at least `--requests` DISTINCT, similar-size objects so none is revisited (and warmed) within the run. Without it, all requests hit the first `--endpoint`
      --requests <REQUESTS>          (`--live`) Number of keep-alive requests to issue (a median + a reuse signal; raise for the p95/p99 tail). Capped at 10000, and lower for a long `--endpoint` URL: the whole sequence is materialized as one curl argv [default: 12]
      --timeout-secs <TIMEOUT_SECS>  (`--live`) Capture budget in seconds. Must be 1..=3600 [default: 15]
      --save <FILE>                  (`--live`) Also write the (cookie-obscured) captured JSONL here — reusable later as a `--baseline`. Created new, mode 0600: the path must not already exist (`--live` often re-execs under sudo, so this write can be root's) and a capture names your buckets, endpoints and SNI
      --auth                         (`--live`) SigV4-sign the workload so a PRIVATE bucket returns 2xx. Creds: AWS_ACCESS_KEY_ID/SECRET (+ AWS_SESSION_TOKEN) env, else ~/.aws/credentials (AWS_PROFILE or `default`). Errors if no creds resolve. The secret is fed to curl off the command line
      --region <REGION>              (`--live --auth`) Region for SigV4 (default: AWS_REGION / ~/.aws/config / us-east-1)
      --s3-endpoint <HOST>           (`--live`) Treat this host as an S3-compatible endpoint so the per-`s3_op` rows resolve a path-style bucket/key (e.g. `--s3-endpoint gateway.storjshare.io`). AWS hosts are recognized natively; repeatable. Without it the global/floor/tail rows still judge, but the S3-domain rows are thin for a non-AWS gateway
      --concurrency <N>              (`--live`) Drive the workload over N parallel connections at once, to measure the path under CONCURRENT load — RTT inflation, retransmits, and the throughput/BDP ceiling only show up under contention, and low reuse only bites when several sockets compete. Each of the N workers runs the full `--requests` sequence on its OWN curl invocation (its own connection), so the doctor sees N connections in flight and total requests = N × `--requests`. Default 1 (serial keep-alive, one connection). Capped at 256 [default: 1]
  -h, --help                         Print help
```

## s3tap advise

```text
Optimization advisories over a capture: read `s3tap.operation/1` + `s3tap.connection/2` JSONL (stdin or a file) and report how the application USES S3 — client churn, missing parallelism, redundant re-fetches, throttling, caching go/no-go — attributed per process. A PURE CONSUMER of the public records (no probes, no privilege); composes as `s3tap --format jsonl | s3tap advise`. Health judgments live in `doctor`; this is optimization advice

Usage: s3tap advise [OPTIONS]

Options:
      --from <FILE>  JSONL of public records to analyze: a file, or `-`/absent for stdin
      --no-color     Disable ANSI color (also auto-off when stdout isn't a terminal)
      --json         Emit `s3tap.finding/1` records (NDJSON, one per advisory) instead of the human table. Same exit-code contract
      --strict       Gate the exit code on advice: exit 1 when any Warn or Advisory finding fired. Off by default — advice is not a failure
      --no-elevate   Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
  -h, --help         Print help
```

## s3tap scorecard

```text
Observed-SLO scorecard over a capture: read `s3tap.operation/1` JSONL (stdin or a file) and report each `bucket / s3_op` with the latency + reliability it ACTUALLY saw — request/error counts, the status-code mix, and TTFB p50/p95/p99. The passive analogue of a speedtest (your own production numbers, no synthetic probe). A PURE CONSUMER (no probes, no privilege); composes as `s3tap --format jsonl | s3tap scorecard`. `--json` emits `s3tap.scorecard/1` rows plus the gated `s3tap.finding/1` reliability judgments; `--strict` exits non-zero when any judgment fired

Usage: s3tap scorecard [OPTIONS]

Options:
      --from <FILE>  JSONL of public records to score: a file, or `-`/absent for stdin
      --no-color     Disable ANSI color (also auto-off when stdout isn't a terminal)
      --json         Emit `s3tap.scorecard/1` rows followed by the gated `s3tap.finding/1` records (NDJSON) instead of the human table. Same exit-code contract
      --strict       Gate the exit code on the scorecard findings: exit 1 when any Warn or Advisory finding fired. Off by default — a scorecard is a report. Independent of exit 2, which a capture with nothing scoreable returns either way
      --no-elevate   Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
  -h, --help         Print help
```

## s3tap analyze

```text
Deep caching + prefetch report for ONE trace: the offline study, run on your workload. Reads a trace (s3tap JSONL, NormEvent JSON, or an IBM COS line — a file or stdin), runs the FULL retention ladder (LRU / ARC / S3-FIFO / OPT) in chunk mode plus the prefetch tradeoff, and prints a recommendation: cache or not, which policy, what size, and whether prefetching will help. Heavier than `advise` (seconds to minutes) — a PURE CONSUMER (no probes, no privilege). `--fast` runs retention-only (~12× quicker); `--json` emits the structured verdict. Composes as `s3tap --format jsonl | s3tap analyze`

Usage: s3tap analyze [OPTIONS]

Options:
      --from <FILE>     The trace to analyze: a file, or `-`/absent for stdin. Auto-detects s3tap JSONL records, NormEvent JSON, or IBM COS text lines
      --fast            Retention-only: skip the prefetch pass entirely (fastest). Answers "which cache, how big" but not "will prefetching help"
      --deep            Run the full, expensive prefetch ladder too (Frequency/Co-occurrence/ Sequential/Adaptive). The Adaptive rung runs a per-size shadow cache and is minutes-to-much-more on a large trace. The default already gives the study's verdict (Markov structure + the shippable self-tuned overlay) fast
      --object          Analyze in object mode (whole objects) instead of the default 8 MB chunk mode. Chunk mode sees within-object/streaming structure; object mode is faster and matches how `advise` sizes
      --max-events <N>  Analyze at most N leading ops (a time slice) so huge traces stay bounded. 0 = the whole trace. Default 3,000,000 (study parity)
      --no-color        Disable ANSI color (also auto-off when stdout isn't a terminal)
      --json            Emit the structured verdict as one JSON object instead of the human report
      --no-elevate      Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
  -h, --help            Print help
```

## s3tap check

```text
The easy front-end to `doctor --live`: probe an S3 object and print a one-line plain-language verdict. Give it a `bucket/key` (expanded to the S3 endpoint) or a full URL for a verdict on YOUR path (strict exit code). Omit the target for the zero-config check: a regional round-trip map, then a health check against a public AWS Open Data object in the nearest covered region (informational exit; `--map-only` prints just the map). Loads eBPF: the L7 rows want the uprobe caps (`sudo s3tap setup --uprobes`), the map needs only the base caps (`sudo s3tap setup`) — without them s3tap offers sudo itself and, lacking uprobes, judges the network floor only. Full flags: `doctor --live`

Usage: s3tap check [OPTIONS] [BUCKET/KEY|URL]

Arguments:
  [BUCKET/KEY|URL]  The S3 object to probe: `bucket/key` (expanded to `bucket.s3[.REGION].amazonaws.com/key`) or a full URL. A bare bucket with no key is rejected — there is no object to GET. OMIT it to run the built-in regional latency probes (a where-am-I-relative-to-S3 read)

Options:
      --region <REGION>      (bucket form) Target a specific region's endpoint, e.g. `eu-west-1`. Default: the global endpoint. The probe does NOT follow redirects, so a bucket OUTSIDE us-east-1 needs this (or a regional URL) — otherwise S3's region redirect reads as unhealthy. Also the SigV4 signing region under `--auth`
      --auth                 SigV4-sign the probe so a PRIVATE bucket returns 2xx (creds from env or `~/.aws`)
      --verbose              Show the full detailed report instead of the one-line summary
      --requests <REQUESTS>  Keep-alive requests to issue (default 12; raise for a p95/p99 tail) [default: 12]
      --triage               (target form) After the health check, sweep the probed regions and report how much round-trip is lower at the nearest one — with the standard remedies. The ms figures are measured (not geo-estimated); "nearest" is nearest of the few probed regions, not every S3 region. Adds the regional sweep time (a few seconds per probed region). Needs a target (the no-target run already sweeps the regions)
      --map-only             (no-target form) Print only the regional round-trip map — skip the follow-up health check against a public test object in the nearest covered region. Needs only the base caps (the map is connection-floor only; the object check drives the L7/uprobe path)
      --no-elevate           Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
  -h, --help                 Print help
```

## s3tap setup

```text
Grant this s3tap binary the file capabilities to load its probes WITHOUT sudo — the programmatic `setcap.sh`. Asks for sudo itself (once); re-run after every rebuild (caps live on the binary inode, which `cargo build` replaces)

Usage: s3tap setup [OPTIONS]

Options:
      --uprobes     Also grant cap_sys_admin — required by the SSL/getaddrinfo uprobe paths (`--capture-plaintext`, `selftest`, the full `check`/`doctor --live` L7 rows). Near-root, and the plaintext path sees decrypted bytes host-wide — opt in deliberately (same posture as `UPROBES=1 ./setcap.sh`)
      --remove      Remove the file-capability grant from this binary instead
      --no-elevate  Never self-elevate: when privileges are missing, fail with the normal permission error instead of re-running under sudo
  -h, --help        Print help
```
