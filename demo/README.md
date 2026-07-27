# s3tap demos

Each demo lives in its own subdirectory with a `run.sh` and its own README/notes.
All of them observe real S3 traffic passively. The client is never modified.

**Common prerequisite**: a capped release binary (caps live on the inode, so re-cap
after every rebuild):

```bash
cargo build --release -p s3tap
UPROBES=1 S3TAP_SETCAP_INSECURE=1 ./setcap.sh release   # --capture-plaintext needs cap_sys_admin
```

`setcap.sh` **refuses a build-tree binary** by default, because a target any local user can
rewrite would hand those caps to all of them. `S3TAP_SETCAP_INSECURE=1` is the explicit
single-user-dev-box opt-out and it prints what it costs. The alternative on a shared machine
is to install to a root-owned path and cap that copy:

```bash
sudo install -m 0755 target/release/s3tap /usr/local/bin/s3tap
sudo /usr/local/bin/s3tap setup --uprobes
```

`warp/` and `provider-benchmark/` then honour `S3TAP=/usr/local/bin/s3tap`. `s3tap/` and
`parallelism/` always run `target/release/s3tap`, so those two need either the opt-out
above or a plain `sudo ./demo/<name>/run.sh` with no grant at all.

| Demo | What it shows | Setup | Run |
|------|---------------|-------|-----|
| [`s3tap/`](s3tap/) | The capture pipeline end to end: selftest, latency waterfall, the stable JSONL schema, failures, per-app scope, analytics. | S3-compatible credentials (env or a Storj creds file) | `./demo/s3tap/run.sh`. Full walkthrough in [`s3tap/README.md`](s3tap/README.md) |
| [`parallelism/`](parallelism/) | s3tap catching a **missed-parallelism** opportunity: the same objects fetched serially vs. over K connections, flagged by the advisor and the speedup measured. | **Public bucket, no credentials** + `python3` (stdlib only) | `./demo/parallelism/run.sh`. Details in [`parallelism/README.md`](parallelism/README.md) |
| [`warp/`](warp/) | s3tap × [warp](https://github.com/minio/warp) (a Go client): the connection/network layer under concurrency that the app's own stats can't see. | `warp` on `PATH`, an S3 bucket | `./demo/warp/run.sh run` then `analyze`. See [`warp/case-study.md`](warp/case-study.md) |
| [`provider-benchmark/`](provider-benchmark/) | A cross-provider size-sweep (AWS vs. Storj) built on `s3tap doctor --live`. | Storj credentials (+ billable egress) | `./demo/provider-benchmark/run.sh mirror\|run\|table`. Details in [`provider-benchmark/README.md`](provider-benchmark/README.md) |

## Validation

`s3tap/` and `parallelism/` have been run **end-to-end in a rootless VM** (virtme-ng
booting a downloaded mainline kernel with user-mode networking, so the eBPF probes load
and attach for real) against live endpoints:

- **`s3tap/`**: a full run against a Storj gateway. All 8 sections pass, every
  authenticated operation returns 2xx/204 and the analytics verdict is `HEALTHY`
  (connection reuse working, 0 retransmits, 0 HTTP errors).
- **`parallelism/`**: a full run against the public `sentinel-cogs` bucket. The serial pass
  trips `advisor-serial-requests` and the parallel pass is clean, with the measured speedup
  printed.

`warp/` and `provider-benchmark/` are reviewed but not part of the automated run (they need
an external `warp` binary / billable Storj egress). Re-validate after changing a `run.sh` or
the eBPF program.

## Shared helpers (at `demo/` root, not tied to one demo)

- **`s3stats.py`**: the reference S3-stats oracle. It is also what the Rust doctor's
  parity test checks itself against (`crates/s3tap-doctor/tests/parity.rs`), so its path is
  load-bearing. Keep it here.
- **`s3get.py`**: a tiny standalone GET helper used by `s3tap/run.sh`.
