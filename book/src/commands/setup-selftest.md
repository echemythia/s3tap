# `setup` & `selftest`

Two supporting commands for getting the capture pipeline running on a host.

## `setup`: grant capabilities without sudo

The programmatic equivalent of `setcap.sh`: it grants this binary the file capabilities it needs
to load its probes (file capabilities are fine-grained permissions attached to a program, so it
gets just those powers instead of full root). You then avoid running the whole agent as root. It
asks for sudo itself, once.

```console
$ sudo s3tap setup            # base caps
$ sudo s3tap setup --uprobes  # + cap_sys_admin for the L7 / TLS-plaintext path
$ sudo s3tap setup --remove   # revoke the grant
```

> Capabilities live on the binary's **inode** (the file's on-disk identity), which `cargo build`
> replaces. **Re-run after every rebuild.** See [Install & capabilities](../install.md) for the
> full grant table.

`setup` **refuses** a binary that a local user could rewrite: it requires the binary and
every ancestor directory up to `/` to be root-owned and not group- or world-writable. A
build tree and a `~/.local/bin` install both fail that test, so install to a root-owned
path and cap that copy. `--remove` skips the check, since dropping caps is always safe.
[Install & capabilities](../install.md#setup-refuses-a-binary-a-local-user-could-rewrite)
has the reasoning and the dev-box opt-out that `setcap.sh` carries.

## `selftest`: prove the pipeline

It loads the probes, drives a few real S3 requests and checks which capabilities
(DNS / TCP / TLS / HTTP) actually produced a record. It prints a pass/fail table for all four
and exits non-zero when **TCP, TLS or HTTP** failed. Those three are what prove the probes work
end to end. This is the fastest way to confirm s3tap works on a new host.

**DNS is informational and does not gate the exit code.** selftest scopes its capture to
**s3tap's own pid**. The curl driver it spawns is picked up as a forked child in-kernel.
Nothing else is ever enrolled, which is the point: an earlier version scoped by app name and
so folded any other `curl` on the host into the run. Under an out-of-process resolver (nscd)
the wire query is sent in the daemon's context, outside that scope. No DNS record then
appears on an otherwise-healthy pipeline. A DNS row reading FAIL beside a PASS result is that
case, not a broken install. The table says so on the row itself.

selftest also prints the capture-honesty lines described under
[`doctor --live`](doctor.md#what---live-says-about-the-capture-itself) before its table, so a
run that never completed a request or that lost events to a full ring is not mistaken for a
broken probe.

```console
$ sudo s3tap selftest
```

See the [CLI reference](../reference/cli.md#s3tap-setup) for every flag.
