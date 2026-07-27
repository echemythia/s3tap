# `run`: capture traffic

`run` is the **default** command (no subcommand). It loads the eBPF probes and passively records
an application's S3 traffic as public JSONL records.

```console
$ sudo s3tap --app python3 --format jsonl > capture.jsonl
```

## What it captures

- **DNS** resolves (via the `getaddrinfo` uprobe), **TCP** connects, **TLS** handshakes.
- **HTTP L7** operations (method, status, TTFB, S3 op-class). Needs the uprobe caps.
- **Connection close-time `tcp_sock` stats**: srtt, min_rtt, retransmits, cwnd, mss, bytes.
- **Periodic in-flight TCP samples**: opt in with `--sample-interval-ms`.

These become [`s3tap.operation/1`, `s3tap.connection/2`, `s3tap.sample/1`](../reference/records.md).

## Scoping to an app

Restrict capture so you only see the workload you care about. `fork()`ed children of a tracked
process are followed in-kernel, so pre-fork servers (gunicorn/uWSGI/Spark) are captured:

| Flag | Match by | Notes |
|------|----------|-------|
| `--app <name>` | exe basename, read from `/proc/<pid>/exe` | Convenient. Not forge-proof. Needs to be able to read that link: see below |
| `--exe <path>` | absolute exe path, read from `/proc/<pid>/exe` | Cannot be forged by a peer process. Same read requirement |
| `--cgroup <id>` | cgroup id | Churn-immune, cannot be forged. Reads no `/proc` |
| `--container <id\|name>` | a whole component of the v2 cgroup path | Resolved to cgroup ids, cannot be forged |
| `--pid <pid>` | process id | Low-level escape hatch, cannot be forged. Reads no `/proc` |

### What `--app` actually matches

`--app` matches the **exe basename** that s3tap reads from `/proc/<pid>/exe`. A process's
`comm` is deliberately **not** matched. Any process can rename its own `comm` to anything
(`prctl(PR_SET_NAME)`) without privilege, without exec, at any time after exec. Matching on
it let an unrelated local process walk into a privileged capture. That mattered
for two reasons. An admitted process writes its own request line and Host header, so it could
inject records with any bucket, verb or status into your capture and flip a verdict or an
`advise --strict` gate. It could also blind the capture, because the in-kernel pid allowlist
is capped and spawning enough renamed processes evicts the real target.

The residual limit is worth stating plainly: an exe basename names a real inode and is fixed
for the life of the exec, so forging it costs an actual executable at a path the attacker
controls. That is a narrower door, not a sealed one. A user who can drop a binary named
`python3` somewhere they can execute it is still admitted. On an untrusted multi-tenant host
use `--pid`, `--exe`, `--cgroup` or `--container`, none of which a peer process can influence.

One practical note: the basename compared is the one the symlink RESOLVES to.
`/usr/bin/python3` is commonly a symlink to `python3.12`. `/proc/<pid>/exe` gives the resolved
target, so a strictly exact match would never fire for `--app python3`. `--app`
therefore matches the basename exactly OR with a trailing version suffix stripped:
`python3` matches `python3.12`, `gcc` matches `gcc-11`. The suffix has to start at a `-` or
`.` and be digits and dots to the end, so `--app python` still matches nothing and
`python311` is left alone. If a scope matches no process at startup, s3tap says so rather
than sitting quietly and writing an empty capture.

### When `--app` and `--exe` cannot see the process

Both name-based scopes answer exactly one question: what is `/proc/<pid>/exe` pointing at?
That link is the only identity s3tap will admit on, in the startup scan and at every later
exec alike. **There is no fallback.** The kernel event that reports an exec also carries
the execve `filename` argument, which is the name the process chose to launch itself under. A
symlink called `python3` pointing at any binary at all is enough to set it, so admitting on it
would hand any local user a way into a privileged capture. It is never consulted.

Having no fallback has a cost worth planning around. Reading **another user's**
`/proc/<pid>/exe` is gated by `ptrace_may_access`, which wants the same uid or
`CAP_SYS_PTRACE`. `s3tap setup` deliberately grants neither. It tags the binary with
`cap_bpf`, `cap_perfmon` and `cap_dac_read_search` (plus `cap_sys_admin` under `--uprobes`).
Of those `cap_dac_read_search` bypasses the DAC check, not the ptrace one. The link is mode
0777, so DAC was never the gate. A capability-tagged s3tap running as you therefore resolves **your
own** processes only. Another user's app is left out of the capture rather than admitted on a
name it picked for itself.

s3tap says so when it happens, once per run. The warning names `CAP_SYS_PTRACE` rather than
leaving you to retype the app name. Two ways forward:

- run s3tap as **root** (`sudo`) to scope another user's app by name, or
- use `--pid`, `--cgroup` or `--container`, none of which read `/proc/<pid>/exe` at all.

One case stays quiet by design. A process with no exe link (a kernel thread, a zombie, one
that exited mid-scan) is skipped without a word, because its pid could never have captured
anything. A `hidepid=2` `/proc` hides the directory outright, which arrives looking exactly
like that and is skipped the same way. It still fails closed, it just fails silently.

## Output formats

`--format` selects `waterfall` (default on a TTY), `table`, `human`, or `jsonl` (default when
piped, so scripts get clean machine-readable output). `--capture-plaintext` records decrypted HTTP via the
OpenSSL uprobes. `--s3-endpoint` points bucket/key decoding at a custom endpoint (MinIO, etc.).

## Exit code

A capture exits **0** normally, whether it recorded a thousand records or none. An application
that was simply quiet is a legitimate empty capture and not an error.

One shape is different and exits **3**: a run that emitted no record at all, whose scope was
`--app`/`--exe` only, which matched no process at the start of the run or at the end of it.
That is a scope which missed rather than an app which was quiet. By exit code alone a script
could not otherwise tell those two apart. It is the same 3 that `doctor --live` returns for a
run that captured nothing. It means the same thing: s3tap ran, saw nothing and has no answer
to give. The message on stderr names the scope it resolved and points at `readlink
/proc/<pid>/exe`, `--pid` and `--cgroup`/`--container`.

Only the name scopes can end this way. `--pid`, `--cgroup` and `--container` name a target
that either exists or fails closed at startup, so an empty capture under them is unambiguous
already. The check is also made at BOTH ends of the run, because a process that execs into
scope halfway through is a legitimate late match. That is why the startup warning is a
prediction rather than a refusal. The closing scan is what turns it into a fact. One gap is
worth naming: a matching process that both execs and exits inside the window without
moving a byte reads as a miss.

See the [CLI reference](../reference/cli.md#s3tap) for every flag.
