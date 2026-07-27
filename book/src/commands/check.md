# `check`: self-driving probe

`check` is the easy front-end to [`doctor --live`](doctor.md): it drives its own probe and
prints a one-line, plain-language verdict. Two modes:

## Targeted: "is my path healthy?"

```console
$ s3tap check my-bucket/my-key      # bucket/key, expanded to the S3 endpoint
$ s3tap check https://…/object      # or a full URL
```

This mode sends keep-alive requests to your object and prints a verdict with a **strict exit code**, so
it drops into CI. Add `--triage` to also sweep nearby regions and report how much round-trip a
closer region would save (with remedies). `--auth` SigV4-signs the probe for a private bucket.
`--region` targets a specific endpoint. `--verbose` shows the full report.

### `--auth` and credentials

`--auth` takes credentials from `AWS_ACCESS_KEY_ID` plus `AWS_SECRET_ACCESS_KEY`, else from
`~/.aws/credentials` under `AWS_PROFILE` or `default`. Environment credentials are never
gated: they are the caller's own and reading them needs no privilege.

The file read has one guard, worth understanding because it is easy to mistake for a bug. A
capability-tagged s3tap can read files the invoking user cannot. `HOME` is not scrubbed on
exec, so `HOME=/root s3tap check … --auth` would otherwise hand root's 0600 credentials
to any local user. s3tap therefore asks whether the REAL user could have read that file, and
refuses only when the answer is no. Your own `~/.aws/credentials` after the documented
`sudo s3tap setup` install passes, since you can read it yourself. `HOME=/root` still fails.
The check is made against the inode actually opened, not only against the path.

## Zero-config: "where am I relative to S3?"

```console
$ s3tap check                       # regional round-trip map + a health check nearby
$ s3tap check --map-only            # just the latency map
```

With no target, `check` prints a regional round-trip map, then health-checks a public AWS Open
Data object in the nearest covered region (informational exit).

## Privileges

`check` loads eBPF. The L7 rows want the uprobe caps (`sudo s3tap setup --uprobes`). The map
needs only the base caps (`sudo s3tap setup`). Without them, s3tap offers to run sudo for you.
With no uprobes it judges the **network floor only** (just the raw network timing, not the HTTP
layer).

That has a consequence for the targeted mode's exit code. With no uprobe caps there is no S3
operation to judge, so a targeted `check` reports **NO OPERATIONS** and exits **2** instead of
passing on the strength of the network rows. It is the same refusal as NO BASELINE: a run that
judged nothing must not read green in CI. Grant the uprobe caps for a verdict about S3 itself.
The zero-config sweep is informational either way and does not gate on this.

## Stopping it early

Ctrl-C ends the whole command and reports what it already holds. It is not a kill: the run
tears the probes down, notes that it was interrupted along with how many of the requested
requests it managed, then prints a verdict over that shorter capture. Read the interruption
note before the verdict, since a partial capture is a smaller sample rather than a different
workload. A `--save` target is claimed before any traffic is driven, so an interrupted run
does not leave a placeholder file behind blocking the re-run.

That holds for the zero-config regional sweep too, which drives one capture per region. One
Ctrl-C ends the sweep rather than skipping to the next region, which is what a sequence of
per-capture handlers used to do.

## Capture-honesty warnings

A targeted `check` drives its own workload, so it prints the same capture-honesty lines that
[`doctor --live`](doctor.md#what---live-says-about-the-capture-itself) does, on stderr, above
the verdict. They say whether the workload actually completed a request, whether the kernel
dropped events (which makes every rate and percentile below them partial) and whether the
time budget truncated the run. Read them before the verdict. The zero-config regional sweep
suppresses them and summarizes its own probes instead.

See the [CLI reference](../reference/cli.md#s3tap-check) for every flag.
