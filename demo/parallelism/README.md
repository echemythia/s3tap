# parallelism demo

Turns a vague "my S3 downloads feel slow" into a specific, quantified fix, then proves
the fix works. It fetches the same set of public objects twice:

1. **serially** (one connection): s3tap, watching from the kernel, sees every GetObject
   and the advisor fires **`advisor-serial-requests`**: *"issued strictly one at a time …
   over K parallel connections cuts the transfer time roughly K times."*
2. **in parallel** (K connections): the advisor goes silent and the wall clock drops.

The client is a small pure-Python script (standard library only, no boto3, no
credentials) that downloads public objects over HTTPS, using one connection or several.
s3tap isn't part of the client. It reads the requests from the kernel by watching OpenSSL.

## Prerequisites

- A **capped** release binary (see the [top-level demo README](../README.md)):
  `cargo build --release -p s3tap && UPROBES=1 S3TAP_SETCAP_INSECURE=1 ./setcap.sh release`.
  The opt-out is needed because `setcap.sh` refuses a build-tree target by default. Running
  `run.sh` under plain `sudo` works too and needs no grant.
- `python3` (standard library only, nothing to `pip install`).
- Network egress to the public bucket. No credentials: it uses a public AWS Open Data
  bucket with anonymous GETs.

## Run

```bash
./demo/parallelism/run.sh
```

Tunable via env (defaults target the public `sentinel-cogs` bucket):

| Var | Default | Meaning |
|-----|---------|---------|
| `S3TAP_DEMO_BUCKET` | `sentinel-cogs` | public bucket |
| `S3TAP_DEMO_REGION` | `us-west-2` | its region |
| `S3TAP_DEMO_PREFIX` | `sentinel-s2-l2a-cogs/1/C/CV/2018/` | prefix to list objects from |
| `S3TAP_DEMO_N` | `60` | objects per pass (must clear the advisor's ≥50-op gate) |
| `S3TAP_DEMO_PAR` | `10` | parallel connections in the fast pass |
| `S3TAP_DEMO_MIN_MB` | `1` | skip tiny sidecar files so the transfer is real |
| `S3TAP_DEMO_MAX_MB` | `0` | optional upper size cap (0 = none) that bounds the download |

## Expected output

Real output from a validation run (with `S3TAP_DEMO_N=55` over slower VM networking, so
the exact counts/times differ from the `N=60` default and your link):

```
1) SERIAL — one connection at a time
  → advisor-serial-requests — 55 requests issued strictly one at a time (~786 ms each
    => ~60 s of serialized transfer time). Issuing them over K parallel connections cuts
    the transfer time roughly K times.

2) PARALLEL — the same objects over 10 connections
  no advisories: nothing to flag in this capture

3) THE PAYOFF
  serial   (1 connection):    60.32s
  parallel (10 connections):  13.33s
  speedup:                    4.5×
```

## Notes

- The advisor only judges a process that made at least 50 cleanly-timed GETs, spent at
  least 10 s transferring and ran almost entirely one-request-at-a-time (under 5% of the
  time with two or more requests in flight). See
  `crates/s3tap-advisor/src/checks/parallelism.rs`. If the serial pass is too fast to reach
  the 10 s mark on a quick link, the demo tells you to raise `S3TAP_DEMO_N` or point
  `S3TAP_DEMO_PREFIX` at larger objects.
- The measured speedup is limited by available bandwidth. If the link (not concurrency) is
  the bottleneck, expect less than K times. The point is that s3tap **identified** the
  serialized transfer before you measured anything.
