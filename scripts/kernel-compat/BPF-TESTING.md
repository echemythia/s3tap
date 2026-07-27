# eBPF parser, verifier & kernel-matrix testing

`cargo test` exercises all the userspace logic, but it can never tell you whether
the eBPF program **loads**. The kernel verifier only runs at load time. For
a CO-RE program that acceptance can differ across kernel versions. This harness
fills that gap in three tiers.

The three answer three different questions and none of them substitutes for another:

| Tier | Command | Question it answers | Needs |
|---|---|---|---|
| 0 | `just bpf-test` | do the byte parsers compute the RIGHT answer while staying inside the bytes they were given | clang |
| 1 | `just bpf-verify` | does the object LOAD on this kernel | clang, bpftool, root |
| 2 | `just bpf-matrix` | does it load on every kernel in the supported range | virtme-ng, KVM |

Tiers 1 and 2 are load gates. They prove the verifier accepted what it walked. Tier 0
is a behaviour gate. It proves a parser honours a length field, which no load gate can
see. Read the "Why tier 0 exists" section below before treating any of them as a
substitute for another, because the project spent five rounds believing tiers 1 and 2
were enough.

## Tier 0: the parser unit tests (no kernel, no root, no VM)

```console
$ just bpf-test                       # or: ./scripts/bpf-parser-tests.sh
$ CC=clang-18 ./scripts/bpf-parser-tests.sh
```

`bpf/include/s3tap_parse.h` holds the program's PURE byte parsers, lifted out of
`bpf/src/s3tap.bpf.c` so they can be compiled twice: once into the BPF object as before,
once for the host under `-DS3TAP_HOST_TEST` with `bpf/tests/s3tap_host_shim.h` supplying
the handful of BPF names they use (`__always_inline`, `barrier_var`, the probe-read
helper). `bpf/tests/parser_tests.c` then drives that same source text against
constructed byte buffers. The header is the code under test, not a copy of it.

What is covered, 49 cases in five groups:

- the DNS question walk and name decode (compression pointers, cycles, a label length
  running past the copied bytes, the 63-byte label cap, the longest legal 253-byte name,
  the iteration budget, the scratch limit)
- the DNS response copy-length clamp (an over-claiming `uh->len`, a span clipped below a
  DNS header, an exhaustive sweep asserting the result never exceeds either the bytes
  available or the scratch cap)
- the TLS ClientHello SNI parse (an over-claiming `name_length`, a name that would pull
  bytes out of a later extension, `SNI_MAX` exactly and one over, a zero-length name, a
  non-`host_name` name type, the extension-walk cap, plus a sweep over every truncation
  point of a well-formed hello)
- the TLS ServerHello version and cipher parse (`supported_versions` versus the legacy
  version field, a body outside its block, an over-claimed extensions length, the same
  truncation sweep)
- the HTTP head recognizers, including the two cases where a body that begins with a
  status line or a request line IS accepted as a head. That is a known limit of a
  4-byte-prefix recognizer and the test pins it as accepted rather than pretending
  otherwise.

**How an over-read is caught. And why not with ASan.** In the kernel these parsers read
out of a per-CPU array map and mask every offset with `(map_size - 1)`, so an offset the
length checks should have rejected still lands INSIDE the map. The read succeeds and
returns whatever the previous message on that CPU left behind. That is what makes this
bug class silent. It is also why a test that merely compares outputs would miss it.
`scratch_init` reproduces the geometry exactly, a region of the map's size holding `len`
valid bytes. It then places a **guard page** (`mprotect(PROT_NONE)`) where the copied
bytes end. Reading one byte past `len` is a SIGSEGV the harness reports with the
offending offset. ASan poisoning was tried first and is not sufficient: its shadow is
8-byte granular and the inline check consults only the FIRST byte of an access, so a
2-byte read straddling the last valid granule is missed entirely. That is the exact shape
of `tls_be16`. A real off-by-one mutation survived because of it. A `PROT_NONE`
boundary is byte-exact and works in a build with no sanitizer at all.

ASan and UBSan are still enabled when the runtime is present, for what guard pages cannot
see: overruns of the OUTPUT buffers (each `malloc`'d at exactly the size of the event
field it models) and integer or shift UB. `-fno-sanitize-recover=all` makes a finding fail
the run rather than print a note. If the runtime is missing the script says so and carries
on, since the primary detector does not depend on it.

**The self-check.** Before running the suite, `scripts/bpf-parser-tests.sh` invokes
`--overread-selfcheck`, which deliberately reads two bytes straddling the end of the
copied data. That run MUST die. If it returns cleanly the guard page is not where it
should be, every bounds assertion in the suite is vacuous and the script aborts with exit
2 rather than report a green run. A detector that can silently disarm itself is the exact
failure this gate exists to avoid, so it is checked rather than assumed.

**Mutation-tested.** 24 mutations were seeded into the parsers (off-by-one bounds, dropped
length checks, flipped comparisons). 22 were caught. The 2 survivors were examined and
proven equivalent to the original, so the suite has no known blind spot rather than an
unmeasured one.

It runs per-push/PR in CI as the `bpf-parser-tests` job in `.github/workflows/ci.yml`,
deliberately first and deliberately on its own: it needs clang and nothing else, so it
finishes in seconds and fails fast. No Rust toolchain, no `vmlinux.h`, no kernel, no root,
no KVM.

## Tier 1: the verifier gate (single kernel)

`scripts/kernel-compat/bpf-verify.sh` compiles the eBPF object and `bpftool prog loadall`s it,
so the verifier runs on every `SEC()` program and every map is created, on
whatever kernel the script runs on. Exit 0 means accepted. On rejection it prints the
verifier log.

```console
$ just bpf-verify            # on your dev kernel
$ ./scripts/kernel-compat/bpf-verify.sh    # same thing; run it anywhere (host, VM, CI runner)
```

It runs per-push/PR in CI (`.github/workflows/bpf-verify.yml`, `verifier-gate`
job) on the runner's kernel, catching most verifier regressions automatically.
This is what would have flagged, e.g., the `srv_scratch`/`tls_scratch` split if it
had broken the verifier.

## Tier 2: the kernel matrix (portability)

A single kernel can't prove the supported-range claim. `scripts/kernel-compat/bpf-matrix.sh`
runs the same gate across several kernels using
[`virtme-ng`](https://github.com/arighi/virtme-ng) (`vng`), which **downloads** a
precompiled upstream kernel per version and boots it with this repo as the rootfs,
in seconds, with nothing left running.

```console
$ sudo apt install virtme-ng        # once (or: pip install virtme-ng). Needs KVM.
$ just bpf-matrix                    # boots each kernel, prints a PASS/FAIL table
$ VERSIONS="v6.1 v6.12 v6.16" just bpf-matrix    # pick your own spread
```

The object is compiled **once** on the host and loaded on each kernel, exactly
how it ships, so the matrix tests CO-RE relocation + verification, not
recompilation. A good spread: an LTS floor, a mid and a recent kernel.

**That "compiled once" is also a blind spot. It cost a round.** `bpf/vmlinux/vmlinux.h`
is gitignored and regenerated from the BUILD HOST's own BTF, so the source has to PARSE
against whatever that host's kernel calls each field. Naming a post-6.4 member directly
(`msg->msg_iter.__iov`) is a hard clang error on any older build host. `build.rs`
compiles this file with `-Werror` on every `cargo build`, so it is the whole agent failing
to build rather than the probe degrading. The matrix cannot see that: it compiles on ONE
host and only ships the object outward. Every kernel-version-specific member name is
therefore spelled in a CO-RE **flavour struct** and every enumerator in a flavour enum
(`bpf/src/s3tap.bpf.c`), which makes the source parse against any `vmlinux.h`, old or new,
while CO-RE still resolves it against the target kernel at load. That was verified by
compiling with `build.rs`'s flags against `vmlinux.h` copies doctored to the real v5.8,
v5.15 and v6.1 definitions. **If you add a field read that only newer kernels have, add
the flavour and check the build against an older header rather than against the matrix.**

Two things the script handles for you, worth knowing if you run `vng` by hand:
- **`--user root`**: `bpftool prog loadall` needs root. vng otherwise runs the
  guest command as your (non-root) user.
- **bpffs**: minimal vng guests don't mount `/sys/fs/bpf`, so `bpf-verify.sh`
  mounts a private bpffs to pin into. Without that the pin fails on a missing
  dir and looks exactly like a verifier rejection (a spurious FAIL).
- vng does **not** propagate the guest command's exit code, so the matrix decides
  PASS/FAIL by scanning the gate's `ACCEPTED`/`REJECTED` output, not `$?`.

## Why virtme-ng and not vmtest / bare distro kernels

`vmtest` boots a **bare** kernel (no initramfs) and shares the host `/` over
**9p**, so the kernel must have the 9p/virtio drivers **built in** (`CONFIG_9P_FS=y`,
`CONFIG_NET_9P_VIRTIO=y`, `CONFIG_VIRTIO_PCI=y`, …). Every distro/mainline kernel
(incl. the Ubuntu mainline builds and this box's own kernel) ships them as
**modules**, so under vmtest they *panic at boot* ("Unable to mount root fs")
before the verifier ever runs. That is a FAIL that is a boot failure, NOT a verifier
result. That was the wall the old vmtest-based matrix hit.

virtme-ng sidesteps it by generating a small initramfs that `modprobe`s the
virtio/9p modules from the kernel's own module tree, so a kernel with **modular**
9p boots fine. It also downloads the kernel itself (`vng --run v6.12`), so there's
no separate fetch step and no `linux-modules` deb to wrangle. (If you
*do* have vmtest-compatible kernels with built-in 9p, e.g. the kernel-patches CI
images, `bpf-verify.sh` is kernel-agnostic and runs fine under vmtest too.)

## The portability floor (measured, not aspirational)

The v5.8 floor is **verified evidence**, not a claim about what ought to work. The matrix has
been run and it passed:

```console
$ VERSIONS="v5.8 v5.15 v6.1 v6.8 v6.16" just bpf-matrix
```

**v5.8, v5.15, v6.1, v6.8 and v6.16 all PASS, loading all 24 `SEC()` programs on each.** That
run was made against the eBPF source as it stands now, after the CO-RE relocation fix described
below, the two v5.8 verifier fixes it exposed, the removal of the `chaos` classifier and the
split of the OpenSSL write probes into an entry/exit pair (which is why the count is 24, having
been 23 before the classifier went and 22 before the write pair arrived). v5.8 is the documented
hard floor and v6.16 is well past the newest kernel any supported distro ships, so the range is
covered at both ends plus the two kernels whose verifier quirks were fixed specifically
(v6.1 CO-RE, v6.8 complexity).

**The matrix loads through `bpftool`, not through the agent.** That is a real gap and it
hid a real bug: `bpftool` raises `RLIMIT_MEMLOCK` itself, so a green v5.8 row said the
programs VERIFY while saying nothing about whether `s3tap` could load them there. It could
not — below 5.11 every BPF map is charged against `RLIMIT_MEMLOCK`, whose default soft
limit is 64 KiB, so map creation failed with EPERM even as root and the error blamed
capabilities. `load_and_attach` now raises the limit before loading, and `s3tap selftest`
passes end to end on v5.8, v5.15, v6.8 and v6.12. Prefer a `selftest` run over a matrix row
when
the question is "does the agent work on this kernel".

**Re-run the matrix after touching `bpf/`**, which is the whole point of having it: a CO-RE
relocation or a complexity limit is only ever discovered at load time on the kernel in
question. Record the new result here, including which source it was run against.

**Nothing is owed right now.** The result recorded above WAS re-run against the source as it
stands, after the three changes that touched `bpf/`: the parsers moving into
`bpf/include/s3tap_parse.h`, the `iov_iter` members moving behind CO-RE flavour structs, and
the removal of the `chaos` classifier and the OpenSSL write entry/exit split (24 now, 23
before the classifier went, 22 between the two). The fork
handler's provenance propagation, which reads the parent's map value rather than writing a
constant, was re-run through the same five kernels afterwards and also loads on all of them,
v5.8 floor included.

Getting there took five portability fixes the matrix surfaced. Each is a good example of what
it's for:
- **CO-RE guards in `msg_first_base`**: `msg_iter`'s `iter_type` / `__iov` /
  `__ubuf_iovec` were renamed/added across ~5.14 and ~6.4. `bpf_core_field_exists()`
  guards make the missing-field reads dead code so the object loads on older kernels
  (was a hard `<invalid CO-RE relocation>` reject on v6.1 / v5.10). Since extended from
  load portability to full FUNCTIONAL portability. See the caveat below.
- **single bounded SNI copy in `parse_client_hello_sni`**: the old 255-iteration
  byte loop blew the verifier complexity limit (`BPF program is too large`) on v6.8.
  One `bpf_probe_read_kernel` collapses the state space.
- **`barrier_var` + re-mask at the `handle_skb_consume_udp` copy**: v5.8/v5.9's
  weaker scalar tracking lost the size bound before the payload copy. Re-asserting it
  at the call site satisfies them (`var &= const`).
- **`barrier_var` + re-mask at the SNI copy too**: once the relocation fix made that path
  reachable on v5.8, the same weaker scalar tracking rejected it with `R2 min value is
  negative`. The house mask idiom fixes it the same way.
- **staging both parses in stack buffers**: v5.8 then rejected with `R1 type=inv expected=fp`.
  Kernels 5.8 and 5.9 do not list the ringbuf's `PTR_TO_MEM` in `is_spillable_regtype`, so
  once register pressure spilled the reserved pointer it came back a scalar. The DNS qname and
  the ClientHello SNI are now parsed into zero-initialized stack buffers and copied into the
  ringbuf record afterwards. Stack slots spill cleanly on every kernel in the range.

## Why tier 0 exists: a load-only gate cannot see dead code

**LOADING is not WORKING. The gap is larger than "some fields come back empty".** This is
the single most important limitation of the project's own testing story, so it gets its own
section rather than a footnote. It is also the reason tier 0 was added.

The verifier only examines code it can REACH. If a CO-RE relocation resolves to something that
makes a function return early, every parser downstream of that return becomes dead code that
the verifier walks straight past. A green matrix row then means "the object loaded", which
is indistinguishable from "the interesting half of the program was compiled out on this
kernel". **A PASS on this gate is evidence of load portability and of nothing else.**

That is not hypothetical. It is exactly what happened here. It is also how a wrong claim
survived a passing matrix.

`msg_first_base` reads the first buffer of a `sendmsg`. Both `struct iov_iter`'s member names
and the `iter_type` enum's VALUES changed across the supported range. Three layouts
exist: `unsigned int type` with `iov` below 5.14, `u8 iter_type` with `iov` (and `ubuf` from
6.0) on 5.14 to 6.3, then `u8 iter_type` with `__iov` / `__ubuf_iovec` from 6.4. Prepending
`ITER_UBUF` at 6.4 also renumbered `ITER_IOVEC`, so comparing against a compile-time constant
matched nothing below 6.4 and the function returned NULL on every one of those kernels.
`handle_tcp_sendmsg` calls it as its first statement and returns on NULL, so on those kernels
the ClientHello parse, the SNI emit and the handshake stamping were unreachable. The matrix
still reported v5.8 PASS, because there was nothing there to reject. Both v5.8 verifier fixes
listed above were only discovered once the relocation fix made that code live.

The damage was **wider than the DNS-query and TLS-SNI loss this page used to document**.
`handle_tcp_sendmsg` returns before it stamps `ch_ts` or `tid_cookie`, so on every pre-6.4
kernel `handshake_us` was 0 on EVERY connection (a close-stat, indistinguishable from "no TLS
was seen") and BIO-client plaintext operations resolved cookie 0 and went partial. That covered
RHEL 9 / AL2 (5.14), Ubuntu 22.04 (5.15) and Debian 12 / AL2023 (6.1), all comfortably above
the 5.8 floor.

The current source handles all three layouts: CO-RE flavour structs match the older member
names. `bpf_core_enum_value` resolves `ITER_UBUF` / `ITER_IOVEC` against the **target
kernel's** BTF at load time rather than against our compile-time headers. A kernel whose BTF
carries neither the fields nor the enum still falls through to NULL, which is the old graceful
no-op rather than a load failure. `handshake_us`, wire DNS-query capture and TLS-SNI capture
all ride that one function, so all three work across the whole supported range now rather than
only on 6.4+.

The relocation fix was validated FUNCTIONALLY rather than by compiling: each matrix kernel's
real BTF was dumped, confirming the three distinct layouts. An isolated probe was then run
under each kernel before and after, showing the iovec base go from `0x0` to a real address on v5.8
and v6.1. Full-pipeline functional capture is confirmed on **v5.8, v5.15, 6.8 and 6.12** via
`s3tap selftest` (DNS / TCP / TLS-SNI / HTTP all PASS). The two 5.x runs are what closed the
sub-6.4 question: the relocation path is confirmed by a real capture there, not only by the
isolated probe above.

Getting a 5.x run at all required the `RLIMIT_MEMLOCK` fix recorded earlier on this page. That
is the more useful result of the exercise. It is also why a `selftest` run is worth more than
a matrix row.

The honest residual is now narrower. Both 5.x runs were under virtme-ng with **user-mode
(slirp) networking**, so the round-trip floor is an emulator artifact rather than a real
network floor: min RTT reads ~0.1 ms and srtt ~1.2 ms. That is enough to prove every capability
fires and every record is produced. It is not enough to trust a latency VERDICT taken there.
**A `selftest` run below 6.4 on real hardware, against real S3, is still owed.** When you have
one, record it here and say which kernel.

One capture limit is worth separating from all of this, because it reads like a version
problem and is not. `msg_first_base` looks at `iov[0]` only. A ClientHello split across several
iovecs, or across two `tcp_sendmsg` calls, is missed on EVERY kernel including the newest. That
is a design limit of the probe, not something the matrix can catch or the relocation fix
changed.

### What tier 0 closes. And what it does not

The parser tests do not make the matrix redundant. The matrix never covered what they
cover. Keep both. Know which one is answering.

**Only tier 0 can catch:** a parser that reads the wrong bytes. A length field believed
instead of clamped. An off-by-one at a buffer end that the kernel's own offset mask turns
into a silent read of the previous message. A truncated ClientHello handled by luck rather
than by a bound. A DNS compression-pointer cycle that runs the iteration budget instead of
terminating. None of these is a verifier question: the verifier proves memory safety within
the program's own maps, which is exactly why the mask that makes an over-read safe is also
what makes it invisible. It also runs on a plain runner with no kernel, so it can be a
required per-PR gate, which neither of the others can.

**Only tiers 1 and 2 can catch:** a verifier rejection. Complexity-limit blowups. A CO-RE
relocation that fails against a real kernel's BTF. Register spills the older verifiers
handle differently. Everything about the code tier 0 does NOT contain, which is most of the
program: the probe attachments, the map plumbing, the socket and task reads, the event
emission. Tier 0 compiles pure functions for the host, so it says nothing at all about how
the object behaves in the kernel.

**The overlap is empty by construction and the pairing is the point.** The msg_first_base
failure needed both halves to hide. The matrix went green because the parsers were
unreachable. The parsers were never exercised anywhere else. Two v5.8 verifier rejects
sat behind that until round 6. With tier 0 in place a parser regression fails on every PR
without a kernel. The matrix goes back to answering the only question it was ever good at,
which is whether the object loads across the range.

## Where this fits

- `just bpf-test` / `bpf-parser-tests` job: the eBPF byte parsers compute the right answer
  and stay in bounds. No kernel, every PR.
- `cargo test` / `ci.yml`: userspace correctness (no kernel). Includes
  `crates/s3tap-events/tests/layout.rs`, which pins the Rust mirrors against the TEXT of
  `bpf/include/s3tap_events.h`, so a schema-version or field-order change on the C side
  fails there rather than silently at runtime.
- `bpf-verify.sh` / `verifier-gate`: the program loads (verifier) on one kernel, every PR.
- `bpf-matrix.sh`: the program loads across the supported kernel range (portability).
- `scripts/vm-loadtest.sh`: the full end-to-end smoke against real S3 (needs creds, run occasionally).
