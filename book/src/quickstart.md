# Quickstart

## 1. Is my path to S3 healthy? (zero-config)

No capture needed. `check` drives its own probe:

```console
$ s3tap check                    # regional round-trip map + a health check nearby
$ s3tap check my-bucket/my-key   # a verdict on YOUR object (strict exit code)
```

`check` is the friendly front-end to `doctor --live`. It loads eBPF. Without the uprobe caps
it only judges the network floor: the fastest round trip the network physically allows. See
[check](commands/check.md).

## 2. Capture an app, then judge it

Capture the S3 traffic of a workload as JSONL, then pipe it into `doctor`:

```console
$ sudo s3tap --app python3 --format jsonl > capture.jsonl
# ...run your workload...
$ s3tap doctor --from capture.jsonl
```

Or straight through in one pipe:

```console
$ sudo s3tap --app python3 --format jsonl | s3tap doctor
```

`doctor` exits non-zero when any metric is outside its envelope (⚠). So it drops into CI as a
gate. See [doctor](commands/doctor.md).

**`--from` wants a capture and it checks.** `doctor`, `advise` and `scorecard` refuse an
input that parsed to zero `s3tap.*` records: they print what they actually read and exit 4
(tool failure), rather than judging an empty set. A `doctor --json` findings file is not a
capture. Neither is an empty file, a truncated one, or the wrong log. This matters because
the old behaviour was silent: `advise --strict` over a broken path printed "no advisories"
and exited **0**, so the gate had been dead for as long as the path was wrong. Exit 1 always
means a verdict about your traffic. Exit 4 means fix the command.

**A capture with no S3 request in it is not a pass either.** If nothing decoded the HTTP layer
(a Go or rustls client, or a capture taken without the uprobe caps) `doctor` reports NO
OPERATIONS and exits 2. Only the network path below S3 was judged, so a green verdict there
would say something the capture cannot support. A capture whose requests were decoded but
never answered, which is what Ctrl-C mid-workload leaves behind, reports NO RESPONSES and
exits 2 on the same reasoning.

## 3. How is the app *using* S3?

```console
$ s3tap advise --from capture.jsonl
```

Optimization advice (client churn, missing parallelism, redundant re-fetches, throttling,
caching go/no-go), attributed per process. See [advise](commands/advise.md).

## 4. Machine-readable output

Every consumer speaks NDJSON findings for fleet ingest:

```console
$ s3tap doctor --from capture.jsonl --json     # one s3tap.finding/1 per check + a run roll-up
```

## 5. Track a regression

```console
$ s3tap doctor --from after.jsonl --baseline before.jsonl   # gate: fails on a regression
```

`--baseline` takes a **capture** of records, the same JSONL `--from` reads, not a findings
file. Keep a known-good capture around as the reference. If you have no capture to keep,
`s3tap doctor --live --endpoint <url> --save baseline.jsonl` drives its own workload and writes
one.

**`--baseline` is checked the same way `--from` is.** A baseline path that opens but parses to
zero `s3tap.*` records is refused with exit 4 rather than accepted as a baseline of nothing.
It used to be accepted. An empty one did not even print a note, so a healthy capture passed
the gate against a file that was never a capture. The `--baseline` section of the
[doctor metrics reference](reference/doctor-metrics.md) has the detail.

`--save` creates its file with `O_EXCL` at mode 0600, so it **refuses a path that already
exists** and never truncates or follows a symlink. Re-running the recipe above over the same
filename therefore fails, up front, before any traffic is driven. Delete or rename the old
capture first, or save to a new name. There is no `--force`. The reason is that `doctor --live` routinely re-execs under sudo, so
that write commonly happens as root with a path taken from an argument. Mode 0600 is for the
same reason: a capture names your buckets, endpoint IPs, SNI hostnames and key hashes.

## Composition

Because the [record](reference/records.md) is the contract, you can capture once, then
re-judge it offline, diff it or feed it to a different tool. The capture and the analysis
never have to happen at the same time or place.
