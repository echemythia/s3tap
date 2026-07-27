# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue for a
suspected vulnerability. Use GitHub **private vulnerability reporting** for this
repository (Security → *Report a vulnerability*).

Please include a description, affected version/commit and a reproduction if you
have one. We aim to acknowledge a report within a few days and will coordinate a
fix and disclosure timeline with you.

## Threat model & what to know before deploying

`s3tap` is a privileged host observability agent. Operators should understand:

- **Elevated capabilities.** Capture needs `CAP_BPF`, `CAP_PERFMON` and
  `CAP_DAC_READ_SEARCH`. The uprobe (plaintext HTTP) path additionally
  needs `CAP_SYS_ADMIN`. `CAP_SYS_ADMIN` is effectively host-root-equivalent, so grant
  it deliberately. `s3tap setup` installs file capabilities and **refuses** to do so
  unless the binary and *every* ancestor directory up to `/` are root-owned and not
  group/other-writable, so that the code running with those capabilities stays the code
  you capped.

- **A file capability belongs to everyone who can execute the file.** The refusal above
  governs who may REWRITE the binary. It does not govern who may RUN it. A root-owned
  mode-0755 `s3tap` carrying file capabilities hands `CAP_BPF`, `CAP_PERFMON` and
  `CAP_DAC_READ_SEARCH` (plus `CAP_SYS_ADMIN` after `setup --uprobes`) to **every local
  user**. Any of them can then run `s3tap --capture-plaintext` with no scope and read
  every other user's and root's decrypted S3 traffic, including SigV4 `Authorization`
  headers and STS tokens. A root-owned install is safe on a single-user host and is not
  safe on a shared one. On a multi-user host restrict the execute bit too, via a
  dedicated group:

      sudo groupadd -f s3tap
      sudo usermod -aG s3tap <user>     # only users you trust with host-wide capture
      sudo install -m 0750 -g s3tap target/release/s3tap /usr/local/bin/s3tap
      sudo s3tap setup [--uprobes]

  `./setcap.sh` grants the same capabilities, so the same rule applies to it. If you
  would not give a user `sudo s3tap`, do not give them execute permission on a capped
  `s3tap`.

- **Sensitive data.** The agent observes S3/HTTP traffic and can read **decrypted**
  request/response metadata (via the TLS-write uprobe) and TLS SNI. Emitted records
  are structured metadata (buckets, keys are hashed, latency/path counters), not
  payload bodies, but treat captures as sensitive and store them accordingly. Object
  keys are emitted as SHA-256 hashes with a random per-run salt, so the same key hashes
  differently across captures and resists offline dictionary or rainbow lookup. The raw
  kernel `sock_cookie` is obscured at emit.

- **Scope.** In-kernel per-app/cgroup filtering drops out-of-scope traffic before it
  reaches userspace.

- **Untrusted input.** The offline consumers (`doctor`, `advise`, `analyze`, replay)
  are hardened to never panic or emit a wrong verdict on corrupt/crafted record input.
  A malformed capture is reported, not trusted.

- **Verifying a release.** A binary published from a PUBLIC repository carries a Sigstore
  build provenance attestation, signed with the GitHub OIDC identity minted for the release
  job itself, binding those exact bytes to this repository, its release workflow and a
  commit. GitHub does not offer attestations to user-owned private repositories, so a
  release cut while this repository is private has none, and is verifiable by checksum
  alone. The release workflow says so in its own log when it skips the step. The
  `.sha256` published beside a binary proves only that the download arrived intact: it
  ships from the same release under the same trust root, so anyone able to write a release
  asset replaces both. Verify the attestation, which writing to a release cannot forge:

      gh attestation verify s3tap-linux-x86_64 \
        --repo echemythia/s3tap \
        --signer-workflow echemythia/s3tap/.github/workflows/release.yml

  `install.sh` performs this check when `gh` is installed and authenticated, and always
  prints which level of verification it reached. Set `S3TAP_ATTESTATION=require` to make
  the attestation mandatory and refuse a checksum-only install.

If you find a way to escalate privileges, escape the configured scope, exfiltrate
payload data the tool claims not to capture, or crash the privileged data plane from
untrusted input, that is in scope for a report.
