# Contributing

s3tap is a personal project, written to learn eBPF and Rust (see the Disclaimer in the
[README](README.md)). It is shared in the hope that it is useful and is not positioned as
a supported product.

Feedback is still welcome:

- **Issues**: bug reports, questions and ideas are all welcome. A clear reproduction helps
  a lot.
- **Pull requests**: considered case by case. For anything non-trivial, please open an
  issue first so we can agree on the approach before you spend time on it.
- **Security**: please do not open a public issue for a vulnerability. See
  [SECURITY.md](SECURITY.md) for private reporting.

Before sending a change, run the same checks the CI gate uses:

```sh
just test
cargo clippy --workspace --all-targets --locked -- -D warnings
```

If you touched `bpf/`, also run the eBPF parser unit tests:

```sh
just bpf-test          # needs clang only: no kernel, no root, no VM
```

That last one is worth knowing about even if you never touch the eBPF C. It is the only
gate that judges the C program's BEHAVIOUR. `cargo test` never loads it. The kernel
gates (`just bpf-verify`, `just bpf-matrix`) only prove it LOADS: the verifier walks
reachable code only, so a relocation that returns early turns everything downstream into
dead code it never examines. `just bpf-test` compiles the pure byte parsers for the host
and drives them against constructed inputs, with a guard page where the input ends so an
over-read faults instead of silently returning stale bytes. Add cases when you change a
parser. The full picture is in
[`scripts/kernel-compat/BPF-TESTING.md`](scripts/kernel-compat/BPF-TESTING.md).

The kernel gates are NOT part of the per-PR checks, because they need root or KVM. Run
`just bpf-matrix` out of band after a change to `bpf/`, then record the result in that same
page.

A few repo conventions are load-bearing enough to state here, since breaking one is easy to
do by accident and the code will still compile:

- **Never guess a number.** Latency has no absolute "good" without a round-trip floor to
  judge it against, so the only latency verdicts are RATIOS. If you are about to hardcode
  "N ms is slow", stop. Reliability may gate on a measured error rate.
- **One source of truth for status to class.** `classify_status` in `s3tap-doctor` is the
  only status-code classifier. Never add a local per-status predicate.
- **A missing denominator never reads green.** A command whose relevant population is empty
  reports that it could not judge, rather than reporting health.
- **Goldens are regenerated deliberately, never edited by hand**, and the diff is read
  before it is committed. A golden that "just changed" is a decision.
