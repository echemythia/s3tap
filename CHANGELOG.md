# Changelog

All notable changes to s3tap are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and s3tap uses
[semantic versioning](https://semver.org).

## [Unreleased]

Nothing yet.

## [0.7.0] - 2026-07-27

First release. Watches an application's S3 traffic from outside the process with eBPF, and
judges it. The application is never modified.

### Added

- **Capture** — connections, DNS, TLS/SNI and decoded S3 operations, as versioned JSONL.
- **`doctor`** — is this capture healthy? Every latency span is scored against the
  connection's own round-trip floor, so a verdict holds at any distance from the endpoint.
- **`check`** — a one-line verdict, plus a regional round-trip map.
- **`advise`** — per-process advisories: connection churn, missing parallelism, redundant
  re-fetches, throttling, cache suitability.
- **`scorecard`** — the observed SLO per bucket and operation.
- **`analyze`** — an offline caching and prefetch study.
- Scoping with `--pid`, `--app`, `--exe`, `--cgroup` and `--container`, applied in-kernel.
- Prebuilt x86_64 and aarch64 binaries, and a `curl` installer that verifies build
  provenance (Sigstore attestation) plus the checksum.
- `THIRD-PARTY-NOTICES.md`, shipped as a release asset: the licence notices for every
  crate linked into the static binary, plus musl libc.

`doctor`, `advise`, `scorecard` and `analyze` read records only: no probes, no privilege.

### Worth knowing

- **Exit codes are shared by every command**: `0` judged clean, `1` a judgment fired,
  `2` nothing judgeable, `3` nothing captured, `4` tool failure. **2 is never a quiet 0** — a
  run that could not judge anything must not read green in CI.
- **Record envelopes are a contract at 0.x** (a field added or renamed bumps the tag). The
  finding *vocabulary* is not: switch on `severity`, treat `finding_id` as data.
- **The HTTP layer needs the OpenSSL uprobes**, so Go and rustls clients yield connections,
  SNI and the network picture but no S3 operations.

Requires Linux 5.8 or newer with BTF. 24 eBPF programs, verified on v5.8, v5.15, v6.1, v6.8
and v6.16.

0.x on purpose: settled enough to build on, not frozen. Experimental, and not intended for
production or business-critical systems.

[0.7.0]: https://github.com/echemythia/s3tap/releases/tag/v0.7.0
