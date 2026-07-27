# Install & capabilities

## Requirements

- **Linux kernel 5.8 or newer** with **BTF** (BPF Type Format: kernel type information the
  loader reads to match your exact kernel). The agent uses the BPF ring buffer (`bpf_ringbuf`,
  5.8+), a fast channel that streams events from the kernel to user space. It also relies on
  CO-RE (Compile Once, Run Everywhere, which lets one build run across different kernels). Optional fields are
  guarded with `bpf_core_field_exists`, so a kernel that lacks one still loads. The
  `iov_iter` layout and its enum values both shifted across ~5.14 and ~6.4, so s3tap resolves
  the member names and the enumerators against the kernel it loaded on rather than against
  its own headers. That keeps DNS-query capture, TLS-SNI capture and the TLS handshake timing
  working across the whole range instead of only on 6.4+. The 5.8 floor is verified by the
  kernel matrix (see `scripts/kernel-compat/BPF-TESTING.md`).
- **Build tools:** `clang`, `llvm-strip`, `bpftool` (`libbpf-dev`) and a **stable Rust**
  toolchain (see `rust-toolchain.toml`).

## Build

`build.rs` compiles and embeds the eBPF object, so the agent is self-contained.

```console
$ just bpf-headers      # one-time: vendor the kernel BPF headers
$ just build            # == cargo build --release
```

The pure consumers (`doctor`, `advise`, `analyze`, `scorecard`) need no kernel, no probes and
no privilege: they read records and nothing else. Their crates carry no eBPF dependency and
build anywhere.

The shipped `s3tap` **binary** is nonetheless Linux-only, so running `s3tap doctor` on macOS is
not possible today. It links `aya` unconditionally and its `build.rs` compiles the eBPF object
against a `vmlinux.h` generated from the build host's own BTF, so the build fails before any
consumer code is reached. Judging a capture on a Mac means building the consumer crates into
your own tool, not running this one.

## Privileges: `setup` instead of sudo

Loading eBPF needs privilege. Rather than running the whole agent as root, grant the **binary**
its file capabilities once:

```console
$ sudo s3tap setup            # base caps: load probes + attach
$ sudo s3tap setup --uprobes  # also grant the L7 / TLS-plaintext path
```

### `setup` refuses a binary a local user could rewrite

This catches most people the first time. `setup` requires the binary **and every ancestor
directory up to `/`** to be root-owned and not group- or world-writable, on the
symlink-resolved path. A build tree (`./target/release/s3tap`) and the installer's default
`~/.local/bin` both fail that test, so `sudo s3tap setup` on either one errors out rather
than granting anything. There is no flag to override it.

File capabilities belong to whoever can put bytes in the inode. Capping a binary under a
directory you can rename would hand `cap_sys_admin` to every local user, along with the
host-wide decrypted traffic it unlocks. So install to a root-owned path and cap that copy:

```console
$ sudo install -m 0755 ./target/release/s3tap /usr/local/bin/s3tap
$ sudo /usr/local/bin/s3tap setup --uprobes
```

`./setcap.sh` is the shell equivalent and applies the identical refusal. It does carry one
opt-out for single-user dev boxes, `S3TAP_SETCAP_INSECURE=1 ./setcap.sh`, which caps the
build-tree binary in place after saying out loud what that costs. Running s3tap under
`sudo` every time needs no grant at all.

| Grant | Capabilities | Enables |
|-------|--------------|---------|
| `setup` | `cap_bpf`, `cap_perfmon`, `cap_dac_read_search` | Kernel probes: DNS, TCP, TLS-handshake, connection stats |
| `setup --uprobes` | + `cap_sys_admin` | OpenSSL / `getaddrinfo` uprobes → the HTTP L7 operation rows and `--capture-plaintext` |

> Capabilities live on the **binary file itself**, which `cargo build` replaces, so **re-run
> `setup` after every rebuild**. `--uprobes` (probes that hook user-space library calls such
> as OpenSSL) grants more power. It adds `cap_sys_admin`, a broad capability close to full
> root. The plaintext path can then see decrypted bytes across the whole host. Opt in on
> purpose.

If privileges are missing, s3tap offers to self-elevate with sudo. Pass `--no-elevate` to fail
with the normal permission error instead.

## Verify

```console
$ sudo s3tap selftest    # loads probes, drives a few real S3 requests, asserts each capability
```

See [setup & selftest](commands/setup-selftest.md) for details.
