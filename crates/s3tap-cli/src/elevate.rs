//! Self-elevation: when a command needs eBPF privileges this process lacks,
//! re-exec the SAME invocation under `sudo` (which does its own password prompt
//! on the tty) instead of failing with "re-run with sudo". s3tap never reads a
//! password itself — sudo owns that interaction end to end.
//!
//! Policy (all four gates must open before we exec):
//!   1. the invoked command actually needs privileges we don't have (`lacking`),
//!   2. we haven't already been elevated (the `S3TAP_ELEVATED` marker — a
//!      mis-configured sudo that grants nothing must fail with the normal error,
//!      not loop),
//!   3. the user didn't opt out (`--no-elevate`),
//!   4. stdin AND stderr are a terminal — sudo needs a tty to prompt, so a
//!      CI/cron/piped run must fail fast with the existing clear message, never
//!      hang on a password prompt nobody will answer.
//!
//! Everything decision-shaped is a pure function (unit-tested below); the one
//! I/O wrapper `maybe_elevate` reads /proc/self/status + euid + tty-ness and
//! either returns (caller proceeds, existing error paths speak) or never
//! returns (exec).

use anyhow::Context;
use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;

/// Env marker set on the elevated child. Presence means "we already went
/// through sudo once" — never elevate again (gate 2), and after a successful
/// run it triggers the one-line `s3tap setup` tip.
pub const ELEVATED_MARKER: &str = "S3TAP_ELEVATED";

// Capability bit numbers (linux/capability.h). CapEff in /proc/self/status is
// a hex bitmask of these.
const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// What a given invocation needs before its probes/state can work. Computed
/// per-command in main(): `base` = load+attach kernel probes (cap_bpf +
/// cap_perfmon + cap_dac_read_search — the `./setcap.sh` set), `uprobes` =
/// the SSL/getaddrinfo uprobe paths (cap_sys_admin on top), `root` = actual
/// euid 0 (`setup`: setcap on our own inode, caps are not enough).
#[derive(Debug, PartialEq, Eq)]
pub struct Needs {
    pub base: bool,
    pub uprobes: bool,
    /// The command produces L7/operation rows when the uprobe caps are present,
    /// and a DOCUMENTED degraded (connection-floor-only) report without them
    /// (the "judging the network floor only" path). Wanted,
    /// not required: it never forces elevation — a user who deliberately granted
    /// only the base caps must not be prompted for cap_sys_admin on every run —
    /// it only decides whether the `setup` tip suggests `--uprobes`.
    pub wants_l7: bool,
    pub root: bool,
}

/// Extract the effective-capability bitmask from /proc/self/status content.
/// Returns None when the line is missing or unparseable (treat as "unknown",
/// never as "has everything").
pub(crate) fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

/// Does this process lack privileges the invocation needs? euid 0 satisfies
/// everything (root holds the full capability set); otherwise each needed
/// capability bit must be present in CapEff.
pub(crate) fn lacking(cap_eff: u64, euid: u32, needs: &Needs) -> bool {
    if needs.root {
        return euid != 0;
    }
    if euid == 0 {
        return false;
    }
    let mut want: u64 = 0;
    if needs.base {
        want |= (1 << CAP_BPF) | (1 << CAP_PERFMON) | (1 << CAP_DAC_READ_SEARCH);
    }
    if needs.uprobes {
        want |= 1 << CAP_SYS_ADMIN;
    }
    cap_eff & want != want
}

/// Does this process hold the capability the TLS-plaintext uprobes need?
///
/// Used to explain an UNATTACHED uprobe rather than to gate anything: "the probes are not
/// attached" has two very different causes, and only the privilege one has a one-line fix.
/// Answers false when CapEff cannot be read, since claiming a privilege we could not verify
/// would send the operator to the wrong remedy.
pub(crate) fn holds_uprobe_caps() -> bool {
    // SAFETY: geteuid is always safe to call (reads a process credential).
    if unsafe { libc::geteuid() } == 0 {
        return true; // root holds the full capability set
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(|eff| eff & (1 << CAP_SYS_ADMIN) != 0)
}

/// The elevation decision, given the four gates.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Have what we need, or elevation is unavailable/declined — run the
    /// command and let the existing permission-error paths speak.
    Proceed,
    /// Missing privileges, no tty to prompt on — proceed, but first print a
    /// one-line hint that a terminal run would have offered sudo.
    NoteAndProceed,
    /// Re-exec under sudo.
    Elevate,
}

pub(crate) fn decide(lacking: bool, already_elevated: bool, no_elevate: bool, is_tty: bool) -> Decision {
    if !lacking || already_elevated || no_elevate {
        return Decision::Proceed;
    }
    if is_tty { Decision::Elevate } else { Decision::NoteAndProceed }
}

/// Credential env vars — never forwarded (see `elevation_env`).
const SECRET_VARS: &[&str] = &["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"];

/// The exact env vars the elevated child needs and that are safe to place on a
/// world-readable argv (see `elevation_env`). Explicit — never a prefix match —
/// so no future/secret-bearing variable is auto-forwarded into a root process:
/// - `HOME`: so the child resolves the SAME `~/.aws` and `~/.curlrc` the user has.
/// - `AWS_PROFILE`/`AWS_REGION` (+ `_DEFAULT_` aliases): the only AWS vars
///   `resolve_aws_creds`/`aws_dir` in main.rs actually read. (No `_CREDENTIALS_FILE`
///   / `_CONFIG_FILE` / `_ENDPOINT_URL`: unread today, and `_ENDPOINT_URL` can
///   structurally embed `user:pass@` — keep it off argv.)
/// - TLS trust overrides curl/openssl honor, so a custom CA bundle still applies.
const FORWARD_VARS: &[&str] = &[
    "HOME",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// Select which of the parent's env vars ride across the sudo boundary.
/// sudo resets the environment (HOME becomes root's, AWS_* vanish), which would
/// otherwise break `--auth` credential resolution — so the child gets HOME (so
/// `~/.aws` still resolves), the AWS *config* vars main.rs reads, and the TLS
/// trust overrides.
///
/// **Credentials are deliberately NOT forwarded.** They would have to ride on
/// the `sudo env K=V` argv, and argv is world-readable via `/proc/PID/cmdline`
/// — that would leak the secret to every local user, breaking the same posture
/// that keeps the secret off curl's command line. The
/// env-only-creds case is detected by `secrets_in_env` and explained instead.
///
/// Values stay `OsString` (an env value need not be UTF-8); keys are matched via
/// `to_str` — a non-UTF-8 key can never equal one of our ASCII allowlist entries,
/// so it is simply skipped. Deterministic order (sorted by key) so the exec'd
/// command line is testable.
pub(crate) fn elevation_env(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut kept: Vec<(OsString, OsString)> = vars
        .filter(|(k, _)| k.to_str().is_some_and(|k| FORWARD_VARS.contains(&k)))
        .collect();
    kept.sort();
    kept
}

/// Does the parent hold AWS credentials in ENV vars (rather than `~/.aws`)?
/// Those can't cross the sudo boundary safely (see `elevation_env`), so the
/// caller warns before elevating instead of leaking or silently failing.
pub(crate) fn secrets_in_env(mut vars: impl Iterator<Item = (OsString, OsString)>) -> bool {
    vars.any(|(k, _)| k.to_str().is_some_and(|k| SECRET_VARS.contains(&k)))
}

/// Build the full argv for the elevated re-exec:
/// `sudo env S3TAP_ELEVATED=1 K=V… <exe> <args…>`.
/// `env(1)` carries the vars because default sudoers forbids both `sudo -E`
/// and `sudo K=V cmd` (SETENV tag) — but running /usr/bin/env as the command
/// is always allowed. All `OsString` — an argv element or path need not be UTF-8.
///
/// A `--` before the exe would terminate env's assignment parsing so an exe path
/// containing `=` (e.g. `/tmp/build=1/s3tap`) isn't mistaken for a `NAME=VALUE`,
/// BUT coreutils 8.32 (Ubuntu/Pop!_OS 22.04) has a bug: once assignments precede
/// it, `--` is no longer recognized as a terminator and env tries to exec a
/// program literally named `--` (`env: '--': No such file or directory`). Since
/// a normal exe path never contains `=`, we emit the `--` guard ONLY when it
/// actually does — the common path then works on every coreutils version, and
/// the pathological `=`-in-path case is still guarded on non-buggy env.
pub(crate) fn sudo_argv(exe: &OsStr, args: &[OsString], env: &[(OsString, OsString)]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["sudo".into(), "env".into()];
    argv.push(kv(OsStr::new(ELEVATED_MARKER), OsStr::new("1")));
    argv.extend(env.iter().map(|(k, v)| kv(k, v)));
    use std::os::unix::ffi::OsStrExt;
    if exe.as_bytes().contains(&b'=') {
        argv.push("--".into());
    }
    argv.push(exe.to_os_string());
    argv.extend(args.iter().cloned());
    argv
}

/// `K=V` as an OsString, preserving non-UTF-8 bytes in the value.
fn kv(k: &OsStr, v: &OsStr) -> OsString {
    let mut s = k.to_os_string();
    s.push("=");
    s.push(v);
    s
}

/// The setcap capability string for `s3tap setup` — the same grant
/// `setcap.sh` applies, so the two paths can never drift apart silently.
pub(crate) fn cap_string(uprobes: bool) -> String {
    if uprobes {
        "cap_bpf,cap_perfmon,cap_dac_read_search,cap_sys_admin+ep".to_string()
    } else {
        "cap_bpf,cap_perfmon,cap_dac_read_search+ep".to_string()
    }
}

/// The I/O wrapper: read CapEff + euid + tty-ness, decide, and on `Elevate`
/// exec sudo (never returns). On `NoteAndProceed` prints the hint. Returns
/// Ok(()) whenever the caller should just run the command.
pub fn maybe_elevate(needs: &Needs, no_elevate: bool) -> anyhow::Result<()> {
    let cap_eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        // Unknown mask: claim nothing. `lacking` will then report true iff the
        // invocation needs anything, which errs toward offering sudo — the
        // harmless direction (worst case: a prompt the user can ^C).
        .unwrap_or(0);
    // SAFETY: geteuid is always safe to call (reads a process credential).
    let euid = unsafe { libc::geteuid() };
    let lack = lacking(cap_eff, euid, needs);
    let already = std::env::var_os(ELEVATED_MARKER).is_some();
    let tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    // The elevated child announces itself once, with the way out of the prompt
    // treadmill. Not for a root-requiring command (`setup`): capabilities
    // can't replace sudo there, so the tip would be wrong.
    if already && euid == 0 && !needs.root {
        enote!(
            "s3tap: running via sudo — grant capabilities once with `sudo s3tap setup{}` and \
             plain `s3tap` will work from then on.",
            // Suggest the grant that keeps THIS command's output intact: a command
            // that renders L7 rows needs --uprobes, or the sudo-free re-run would
            // silently thin out to the connection-floor report.
            if needs.uprobes || needs.wants_l7 { " --uprobes" } else { "" }
        );
    }
    match decide(lack, already, no_elevate, tty) {
        Decision::Proceed => Ok(()),
        Decision::NoteAndProceed => {
            // For a root-requiring command (`setup`) capabilities can't
            // substitute for sudo, so the `setup` half of the tip would mislead.
            let fix = if needs.root { "run under sudo" } else { "grant caps once with `sudo s3tap setup`, or run under sudo" };
            enote!(
                "s3tap: this command needs privileges this process lacks; from a terminal s3tap \
                 would offer sudo automatically. To fix: {fix}."
            );
            Ok(())
        }
        Decision::Elevate => {
            // OsString end-to-end: argv/env/path need not be UTF-8, and the
            // panicking `args()`/`vars()` would abort a valid invocation whose
            // argv or environment carried non-Unicode bytes.
            let exe = std::env::current_exe()?;
            let args: Vec<OsString> = std::env::args_os().skip(1).collect();
            let env = elevation_env(std::env::vars_os());
            let argv = sudo_argv(exe.as_os_str(), &args, &env);
            enote!(
                "s3tap: needs elevated privileges to load its eBPF probes — asking sudo… \
                 (skip with --no-elevate; grant caps once with `sudo s3tap setup`)"
            );
            // `--auth` resolves creds from env FIRST, then ~/.aws. The env pair
            // can't cross this boundary (it would land in world-readable argv),
            // so warn BEFORE the prompt rather than let --auth fail confusingly
            // on the other side. HOME rides across, so a ~/.aws profile is
            // unaffected — hence "may".
            if secrets_in_env(std::env::vars_os()) {
                enote!(
                    "s3tap: note — AWS credentials in environment variables are NOT passed \
                     through sudo (they would be visible in `ps`). If `--auth` then finds no \
                     credentials, either grant the caps once (`sudo s3tap setup --uprobes`) and \
                     re-run WITHOUT sudo, or use a `~/.aws/credentials` profile."
                );
            }
            use std::os::unix::process::CommandExt;
            // exec replaces this process on success; reaching the line below
            // means sudo itself couldn't start (not installed?) — fall through
            // to the normal permission-error paths rather than dying here.
            let err = std::process::Command::new(&argv[0]).args(&argv[1..]).exec();
            enote!("s3tap: could not run sudo ({err}) — continuing unprivileged.");
            Ok(())
        }
    }
}

/// Whether a single path component `(uid, mode)` is unsafe to trust for a setcap
/// target: un-stattable, owned by a non-root user (they can rewrite or chmod it
/// writable), or group/other-writable. `None` means safe. `022` = group-write |
/// other-write. Pure so the policy is unit-tested without touching the fs.
fn component_unsafe(what: &str, probe: Option<(u32, u32)>) -> Option<String> {
    match probe {
        None => Some(format!("cannot stat the {what}")),
        Some((uid, _)) if uid != 0 => Some(format!("the {what} is owned by uid {uid}, not root")),
        Some((_, mode)) if mode & 0o022 != 0 => {
            Some(format!("the {what} is group- or world-writable (mode {:o})", mode & 0o777))
        }
        Some(_) => None,
    }
}

/// Whether it is unsafe to setcap a binary, given its `(uid, mode)` and its parent
/// directory's — the pure two-probe policy the unit test pins. The real check
/// ([`insecure_setcap_target`]) walks the FULL ancestor chain, not just the immediate
/// parent, so this now serves only the test.
#[cfg(test)]
fn setcap_target_unsafe(
    file: Option<(u32, u32)>, // (uid, mode) of the binary
    dir: Option<(u32, u32)>,  // (uid, mode) of its parent directory
) -> Option<String> {
    component_unsafe("binary", file).or_else(|| component_unsafe("parent directory", dir))
}

/// Filesystem probe feeding the setcap safety gate for a real path. Canonicalizes
/// first (so a symlinked component can't smuggle a writable segment past the check),
/// then requires the binary AND EVERY ancestor directory up to `/` to be root-owned
/// and not group/other-writable. Checking only the immediate parent is insufficient:
/// a user who controls ANY higher ancestor can rename a root-owned parent dir and
/// substitute the binary in the window between this check and `setcap` (TOCTOU).
fn insecure_setcap_target(exe: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // Resolve symlinks so each walked component is a real directory; fall back to the
    // given path if resolution fails (fail-closed — a missing component still stats None).
    let real = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    insecure_setcap_walk(&real, |p| std::fs::metadata(p).ok().map(|m| (m.uid(), m.mode())))
}

/// The ancestor-walk policy over an injectable `(uid, mode)` probe, so the TOCTOU-hardening
/// (binary + every ancestor to `/` must be root-owned and non-group/other-writable) is unit-
/// tested without a real filesystem. `exe` must already be canonicalized by the caller.
fn insecure_setcap_walk(
    exe: &std::path::Path,
    probe: impl Fn(&std::path::Path) -> Option<(u32, u32)>,
) -> Option<String> {
    if let Some(reason) = component_unsafe("binary", probe(exe)) {
        return Some(reason);
    }
    for dir in exe.ancestors().skip(1) {
        let what =
            if dir.parent().is_none() { "root directory".to_string() } else { format!("directory {}", dir.display()) };
        if let Some(reason) = component_unsafe(&what, probe(dir)) {
            return Some(reason);
        }
    }
    None
}

/// Where a helper program may be picked up from. Fixed and absolute: PATH is NEVER
/// consulted. glibc's AT_SECURE scrub (which runs when the binary carries file
/// capabilities) drops the `LD_*` variables but leaves `PATH` and `HOME` exactly as the
/// caller set them, so a PATH lookup inside a capability-holding process is a lookup the
/// caller controls. That is how `curl` became an attacker-supplied program handed root's
/// SigV4 secret on stdin. Same order a login shell would search.
const HELPER_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Resolve a helper program (`curl`, `tc`, `ip`, `ethtool`, `logger`, `ldconfig`) to an
/// absolute path we are willing to execute: the first candidate in [`HELPER_DIRS`] that
/// exists AND passes the same ownership/writability policy `s3tap setup` applies to its own
/// binary. A candidate owned by a non-root user, or reachable through a group/other-writable
/// directory, is refused rather than run: this process may hold `cap_dac_read_search`, so
/// whatever it executes gets handed whatever it read.
///
/// Err carries the operator-facing reason (which candidates were refused and why).
pub(crate) fn helper_path(name: &str) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    pick_helper(
        name,
        HELPER_DIRS,
        // Resolve symlinks (`/bin` is `/usr/bin` on a merged-usr host) so the walked path is
        // the real one. A candidate that does not exist canonicalizes to None and is skipped.
        |p| std::fs::canonicalize(p).ok(),
        |p| std::fs::metadata(p).ok().map(|m| (m.uid(), m.mode())),
    )
}

/// [`helper_path`] as a ready-to-run [`std::process::Command`], for the many call sites that
/// only want to swap `Command::new("curl")` for the resolved one.
pub(crate) fn helper_command(name: &str) -> anyhow::Result<std::process::Command> {
    match helper_path(name) {
        Ok(p) => Ok(std::process::Command::new(p)),
        Err(reason) => Err(anyhow::anyhow!(reason)),
    }
}

/// The trusted-path search over injectable `canonicalize`/`(uid, mode)` probes, so the policy
/// is unit-tested without a real filesystem. Each candidate is walked by
/// [`insecure_setcap_walk`], i.e. the file AND every ancestor directory must be root-owned and
/// not group/other-writable. An unsafe candidate is skipped (a later directory may hold a safe
/// copy) but its reason is kept, so "found nothing" can say what it rejected.
fn pick_helper(
    name: &str,
    dirs: &[&str],
    canon: impl Fn(&std::path::Path) -> Option<std::path::PathBuf>,
    probe: impl Fn(&std::path::Path) -> Option<(u32, u32)>,
) -> Result<std::path::PathBuf, String> {
    let mut refused: Vec<String> = Vec::new();
    for dir in dirs {
        let cand = std::path::Path::new(dir).join(name);
        let Some(real) = canon(&cand) else { continue };
        match insecure_setcap_walk(&real, |p| probe(p)) {
            None => return Ok(real),
            Some(reason) => {
                let line = format!("{}: {reason}", real.display());
                if !refused.contains(&line) {
                    refused.push(line);
                }
            }
        }
    }
    let detail = if refused.is_empty() {
        "nothing of that name is installed there".to_string()
    } else {
        format!("refused {}", refused.join(", "))
    };
    Err(format!(
        "cannot run `{name}`: no trusted copy in {}. s3tap resolves helper programs by \
         absolute path and never through PATH, because this binary can carry file \
         capabilities that a PATH lookup would hand to any local user ({detail})",
        dirs.join(", ")
    ))
}

/// Is this process running on BORROWED privilege: not root, yet holding effective
/// capabilities? That combination means the caps came from the FILE capability on the
/// binary rather than from the invoking user, so every ambient input (`HOME`, `PATH`, the
/// cwd) belongs to whoever ran us and not to whoever the privilege belongs to.
pub(crate) fn borrowed_privilege(euid: u32, cap_eff: u64) -> bool {
    euid != 0 && cap_eff != 0
}

/// [`borrowed_privilege`] against this process. An unreadable/unparseable CapEff answers
/// false: without /proc we cannot establish that privilege was borrowed, and refusing every
/// caller on a hidden /proc would break more than it protects (a capability grant that the
/// kernel honors always comes with a readable status file for its own process).
pub(crate) fn on_borrowed_privilege() -> bool {
    let cap_eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .unwrap_or(0);
    // SAFETY: geteuid is always safe to call (reads a process credential).
    let euid = unsafe { libc::geteuid() };
    borrowed_privilege(euid, cap_eff)
}

/// `s3tap setup`: apply (or remove) the file-capability grant on THIS binary —
/// the programmatic `setcap.sh`. Runs as the elevated child (main routes it
/// through `maybe_elevate` with `root: true`), so plain `setcap` works here;
/// `current_exe` resolves /proc/self/exe, i.e. the real inode even when the
/// user invoked a relative path or the sudo re-exec.
pub fn setup(uprobes: bool, remove: bool) -> anyhow::Result<i32> {
    let exe = std::env::current_exe().context("resolve own binary path")?;
    // Granting caps to a binary any local user can rewrite (or that sits in a
    // user-writable directory) hands those near-root caps — cap_sys_admin sees
    // host-wide decrypted plaintext — to every local user. Refuse unless the
    // binary and its parent dir are safely owned, so a `sudo s3tap setup` in a
    // scratch/home build dir doesn't quietly become local privilege escalation.
    // (Skip on --remove: dropping caps is always safe.)
    if !remove {
        if let Some(reason) = insecure_setcap_target(&exe) {
            anyhow::bail!(
                "refusing to grant capabilities to {}: {reason}.\n  \
                 A file capability is available to EVERY user who can execute the file. \
                 Ownership and mode decide only who can REWRITE it, so this refusal buys one \
                 thing: the code running with these caps stays the code you capped. It does \
                 NOT make the caps yours alone. A writable binary (or a writable ancestor \
                 directory) additionally lets any local user CHOOSE that code.\n  \
                 Install s3tap under a root-owned path (e.g. `sudo install -m 0755 {} \
                 /usr/local/bin/s3tap`) and run `sudo s3tap setup` on that copy, or just keep \
                 running under sudo.\n  \
                 On a MULTI-USER host that root-owned copy is still runnable by everyone, and \
                 `s3tap --capture-plaintext` with no scope reads every other user's and root's \
                 decrypted S3 traffic. Restrict who may execute it as well:\n      \
                 sudo groupadd -f s3tap && sudo usermod -aG s3tap <user>\n      \
                 sudo install -m 0750 -g s3tap {} /usr/local/bin/s3tap\n      \
                 sudo s3tap setup [--uprobes]",
                exe.display(),
                exe.display(),
                exe.display()
            );
        }
    }
    let caps = cap_string(uprobes);
    // Resolved by absolute path like every other helper this process execs, never through
    // PATH: `setup` runs as root (via sudo re-exec), so a `setcap` earlier on the invoking
    // admin's PATH than the real one would otherwise run as root the moment they type
    // `sudo s3tap setup` — the exact command this project tells operators to trust.
    let mut cmd = match helper_command("setcap") {
        Ok(c) => c,
        Err(e) => anyhow::bail!(
            "{e}\n  If it's simply not installed: Debian/Ubuntu `apt install libcap2-bin`; \
             Fedora/RHEL `dnf install libcap`. Or keep running under sudo."
        ),
    };
    if remove {
        cmd.arg("-r");
    } else {
        cmd.arg(&caps);
    }
    let out = cmd.arg(&exe).output().context("run setcap")?;
    if !out.status.success() {
        anyhow::bail!(
            "setcap failed on {}: {}",
            exe.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // Write the report through ONE locked handle with the project's BrokenPipe mapping,
    // as advise_cmd/scorecard_cmd do. `println!` PANICS on a write error, so
    // `sudo s3tap setup --uprobes | head -1` turned a SUCCESSFUL grant into an exit-101
    // panic — and a wrapper keying on the exit status then concluded the grant had failed.
    // The caps are applied by this point either way, so a closed reader is a clean stop.
    use std::io::Write;
    let report = setup_report(&caps, &exe.display().to_string(), uprobes, remove);
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(report.as_bytes()).and_then(|()| out.flush()) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(anyhow::Error::from(e).context("writing the setup report"));
        }
    }
    Ok(0)
}

/// The `setup` report text (the testable core of [`setup`]): what was granted or removed,
/// plus the two standing caveats — the uprobe caps are a separate opt-in, and caps live on
/// the binary INODE so a rebuild silently drops them.
fn setup_report(caps: &str, exe: &str, uprobes: bool, remove: bool) -> String {
    use std::fmt::Write;
    if remove {
        return format!("removed file capabilities from {exe} — probe commands need sudo again.\n");
    }
    let mut out = format!("granted {caps}\n     on {exe}\ns3tap now loads its probes without sudo.\n");
    if !uprobes {
        let _ = writeln!(
            out,
            "note: the SSL/getaddrinfo uprobe paths (--capture-plaintext, selftest, the \
             full check/doctor --live L7 rows) additionally need cap_sys_admin — grant \
             with `sudo s3tap setup --uprobes` if you want those sudo-free too."
        );
    }
    let _ = writeln!(
        out,
        "note: capabilities live on the binary inode — a rebuild wipes them; re-run \
         `s3tap setup` after `cargo build`."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CapEff mask for the default `./setcap.sh` grant.
    const BASE_MASK: u64 = (1 << CAP_BPF) | (1 << CAP_PERFMON) | (1 << CAP_DAC_READ_SEARCH);
    const UPROBE_MASK: u64 = BASE_MASK | (1 << CAP_SYS_ADMIN);

    const NEED_BASE: Needs = Needs { base: true, uprobes: false, wants_l7: false, root: false };
    const NEED_UPROBES: Needs = Needs { base: true, uprobes: true, wants_l7: true, root: false };
    const NEED_ROOT: Needs = Needs { base: false, uprobes: false, wants_l7: false, root: true };
    const NEED_NONE: Needs = Needs { base: false, uprobes: false, wants_l7: false, root: false };
    /// `check` / `doctor --live`: base required, L7 wanted (degrades).
    const NEED_BASE_WANT_L7: Needs =
        Needs { base: true, uprobes: false, wants_l7: true, root: false };

    #[test]
    fn parse_cap_eff_reads_the_hex_mask() {
        // Realistic /proc/self/status excerpt (unprivileged process).
        let status = "Name:\ts3tap\nUid:\t1000\t1000\t1000\t1000\n\
                      CapInh:\t0000000000000000\nCapPrm:\t000000c000000004\n\
                      CapEff:\t000000c000000004\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x000000c000000004));
    }

    #[test]
    fn parse_cap_eff_missing_line_is_none() {
        assert_eq!(parse_cap_eff("Name:\ts3tap\nUid:\t1000\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnot-hex\n"), None);
    }

    #[test]
    fn lacking_root_requirement_is_euid_only() {
        // `setup` needs real root: a full capability mask does NOT satisfy it
        // (setcap writes the security xattr on our own inode), euid 0 does.
        assert!(lacking(u64::MAX, 1000, &NEED_ROOT));
        assert!(!lacking(0, 0, &NEED_ROOT));
    }

    #[test]
    fn lacking_base_checks_the_three_probe_caps() {
        assert!(!lacking(BASE_MASK, 1000, &NEED_BASE));
        // Missing cap_perfmon (e.g. someone hand-set only cap_bpf).
        assert!(lacking(1 << CAP_BPF, 1000, &NEED_BASE));
        assert!(lacking(0, 1000, &NEED_BASE));
        // Root satisfies everything regardless of the mask.
        assert!(!lacking(0, 0, &NEED_UPROBES));
    }

    #[test]
    fn lacking_uprobes_needs_sys_admin_on_top_of_base() {
        // The `./setcap.sh` default grant is NOT enough for the L7 paths.
        assert!(lacking(BASE_MASK, 1000, &NEED_UPROBES));
        assert!(!lacking(UPROBE_MASK, 1000, &NEED_UPROBES));
    }

    #[test]
    fn lacking_nothing_needed_never_lacks() {
        // advise / offline doctor: pure record consumers, euid and caps moot.
        assert!(!lacking(0, 1000, &NEED_NONE));
    }

    #[test]
    fn wanting_l7_never_forces_elevation_on_a_base_caps_host() {
        // The deliberate least-privilege user (`sudo s3tap setup`, no --uprobes)
        // must NOT be prompted for cap_sys_admin on every `check` — the L7 rows
        // degrade to the documented connection-floor report instead.
        // Only a MISSING BASE cap may trigger sudo.
        assert!(!lacking(BASE_MASK, 1000, &NEED_BASE_WANT_L7));
        // With no caps at all there is nothing to degrade to — offer sudo.
        assert!(lacking(0, 1000, &NEED_BASE_WANT_L7));
    }

    #[test]
    fn decide_elevates_only_when_all_gates_open() {
        assert_eq!(decide(true, false, false, true), Decision::Elevate);
    }

    #[test]
    fn decide_has_privileges_proceeds() {
        assert_eq!(decide(false, false, false, true), Decision::Proceed);
    }

    #[test]
    fn decide_marker_present_never_reelevates() {
        // A sudo that granted nothing must NOT loop — fall through to the
        // normal permission error.
        assert_eq!(decide(true, true, false, true), Decision::Proceed);
    }

    #[test]
    fn decide_no_elevate_flag_wins() {
        assert_eq!(decide(true, false, true, true), Decision::Proceed);
    }

    #[test]
    fn decide_no_tty_notes_and_proceeds() {
        // CI/cron/pipe: never hang on a password prompt nobody will answer.
        assert_eq!(decide(true, false, false, false), Decision::NoteAndProceed);
    }

    /// Build an env iterator from &str pairs for the OsString-typed functions.
    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect()
    }

    #[test]
    fn decide_no_tty_root_command_still_notes_and_proceeds() {
        assert_eq!(decide(true, false, false, false), Decision::NoteAndProceed);
    }

    #[test]
    fn elevation_env_keeps_home_config_and_tls_overrides_sorted() {
        let kept = elevation_env(
            env(&[
                ("PATH", "/usr/bin"),
                ("HOME", "/home/user"),
                ("AWS_PROFILE", "dev"),
                ("AWS_REGION", "eu-west-1"),
                ("LANG", "C"),
                ("CURL_CA_BUNDLE", "/etc/ca.pem"),
            ])
            .into_iter(),
        );
        assert_eq!(
            kept,
            env(&[
                ("AWS_PROFILE", "dev"),
                ("AWS_REGION", "eu-west-1"),
                ("CURL_CA_BUNDLE", "/etc/ca.pem"),
                ("HOME", "/home/user"),
            ])
        );
    }

    #[test]
    fn elevation_env_never_forwards_a_secret_or_an_unread_var() {
        // argv is world-readable via /proc/PID/cmdline — forwarding a secret
        // through `sudo env K=V` would leak it to every local user. HOME rides
        // instead, so ~/.aws still resolves in the child; env-only creds are
        // reported by `secrets_in_env`. And an allowlist WIDER than what main.rs
        // reads is the wrong direction — AWS_ENDPOINT_URL (can embed user:pass@)
        // and the *_FILE config vars are NOT forwarded.
        let kept = elevation_env(
            env(&[
                ("AWS_SECRET_ACCESS_KEY", "s3cr3t"),
                ("AWS_ACCESS_KEY_ID", "AKIA…"),
                ("AWS_SESSION_TOKEN", "tok"),
                ("AWS_ENDPOINT_URL", "https://user:pass@evil"),
                ("AWS_SHARED_CREDENTIALS_FILE", "/attacker/creds"),
                ("S3TAP_LOG", "debug"), // no longer prefix-forwarded
                ("AWS_PROFILE", "dev"),
            ])
            .into_iter(),
        );
        assert_eq!(kept, env(&[("AWS_PROFILE", "dev")]));
    }

    #[test]
    fn secrets_in_env_spots_credential_variables_only() {
        let has = |k: &str| secrets_in_env(env(&[(k, "x")]).into_iter());
        assert!(has("AWS_SECRET_ACCESS_KEY"));
        assert!(has("AWS_ACCESS_KEY_ID"));
        assert!(has("AWS_SESSION_TOKEN"));
        assert!(!has("AWS_PROFILE"));
        assert!(!has("AWS_REGION"));
        assert!(!has("HOME"));
    }

    #[test]
    fn elevation_env_never_forwards_the_marker_itself() {
        // The marker is not in FORWARD_VARS, so a stale copy can't duplicate the
        // one sudo_argv adds.
        assert_eq!(elevation_env(env(&[(ELEVATED_MARKER, "1")]).into_iter()), env(&[]));
    }

    #[test]
    fn elevation_env_skips_non_utf8_keys_without_panicking() {
        use std::os::unix::ffi::OsStringExt;
        let weird = OsString::from_vec(vec![0x41, 0xff, 0x42]); // "A\xffB"
        let vars = vec![(weird, OsString::from("x")), (OsString::from("HOME"), OsString::from("/h"))];
        assert_eq!(elevation_env(vars.into_iter()), env(&[("HOME", "/h")]));
    }

    #[test]
    fn sudo_argv_shape_marker_env_exe_args_no_terminator_for_normal_path() {
        // A normal exe path has no `=`, so NO `--` is emitted — coreutils 8.32
        // (Ubuntu/Pop!_OS 22.04) rejects `--` once assignments precede it.
        let e = env(&[("HOME", "/home/user")]);
        let args: Vec<OsString> =
            ["check", "--auth", "b/k with space"].iter().map(OsString::from).collect();
        let got = sudo_argv(OsStr::new("/usr/local/bin/s3tap"), &args, &e);
        let want: Vec<OsString> = [
            "sudo",
            "env",
            &format!("{ELEVATED_MARKER}=1"),
            "HOME=/home/user",
            "/usr/local/bin/s3tap",
            "check",
            "--auth",
            "b/k with space",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn sudo_argv_guards_exe_path_containing_equals() {
        // Only the pathological `=`-in-path exe gets the `--` guard, so env
        // doesn't parse it as another NAME=VALUE assignment.
        let e = env(&[("HOME", "/h")]);
        let got = sudo_argv(OsStr::new("/tmp/build=1/s3tap"), &[], &e);
        let want: Vec<OsString> = [
            "sudo",
            "env",
            &format!("{ELEVATED_MARKER}=1"),
            "HOME=/h",
            "--",
            "/tmp/build=1/s3tap",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn sudo_argv_preserves_non_utf8_value_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let val = OsString::from_vec(vec![0xff, 0xfe]);
        let e = vec![(OsString::from("HOME"), val)];
        let got = sudo_argv(OsStr::new("/s3tap"), &[], &e);
        // The HOME=… element carries the raw bytes, not U+FFFD replacements.
        let home = got.iter().find(|a| a.as_bytes().starts_with(b"HOME=")).unwrap();
        assert_eq!(home.as_bytes(), b"HOME=\xff\xfe");
    }

    #[test]
    fn setcap_target_policy_refuses_unsafe_locations() {
        // root-owned binary in a root-owned, non-writable dir → safe.
        assert!(setcap_target_unsafe(Some((0, 0o755)), Some((0, 0o755))).is_none());
        // binary owned by a normal user → refuse (they can rewrite it).
        assert!(setcap_target_unsafe(Some((1000, 0o755)), Some((0, 0o755))).is_some());
        // world-writable binary → refuse.
        assert!(setcap_target_unsafe(Some((0, 0o757)), Some((0, 0o755))).is_some());
        // safe binary but the parent dir is user-owned (swap-the-file) → refuse.
        assert!(setcap_target_unsafe(Some((0, 0o755)), Some((1000, 0o755))).is_some());
        // group-writable parent dir → refuse.
        assert!(setcap_target_unsafe(Some((0, 0o755)), Some((0, 0o775))).is_some());
        // un-stattable → refuse (fail closed).
        assert!(setcap_target_unsafe(None, Some((0, 0o755))).is_some());
    }

    #[test]
    fn setcap_walk_refuses_a_writable_grandparent() {
        use std::collections::HashMap;
        use std::path::{Path, PathBuf};
        // A layout where the binary AND its immediate parent are root-safe, but a HIGHER
        // ancestor (/home/user) is user-owned. The immediate-parent-only check accepted this;
        // the full ancestor walk must reject it (a user who owns /home/user can rename the
        // root-owned /home/user/bin and swap the binary before setcap resolves the path).
        let safe = (0u32, 0o755u32); // root-owned, not group/other-writable
        let mut tree: HashMap<PathBuf, (u32, u32)> = HashMap::new();
        tree.insert(PathBuf::from("/home/user/bin/s3tap"), safe);
        tree.insert(PathBuf::from("/home/user/bin"), safe);
        tree.insert(PathBuf::from("/home/user"), (1000, 0o755)); // the hole: user-owned
        tree.insert(PathBuf::from("/home"), safe);
        tree.insert(PathBuf::from("/"), safe);
        let probe = |p: &Path| tree.get(p).copied();

        let reason = insecure_setcap_walk(Path::new("/home/user/bin/s3tap"), probe);
        assert!(reason.is_some(), "a user-owned grandparent must be refused");
        assert!(reason.unwrap().contains("/home/user"), "the reason should name the unsafe ancestor");

        // An all-root tree (a normal /usr/local/bin install) passes.
        let mut ok_tree: HashMap<PathBuf, (u32, u32)> = HashMap::new();
        for p in ["/usr/local/bin/s3tap", "/usr/local/bin", "/usr/local", "/usr", "/"] {
            ok_tree.insert(PathBuf::from(p), safe);
        }
        assert!(insecure_setcap_walk(Path::new("/usr/local/bin/s3tap"), |p| ok_tree.get(p).copied()).is_none());
    }

    /// A fake filesystem for [`pick_helper`]: `(uid, mode)` per path, with canonicalize
    /// answering the identity for anything present.
    fn helper_tree(entries: &[(&str, (u32, u32))]) -> std::collections::HashMap<std::path::PathBuf, (u32, u32)> {
        entries.iter().map(|(p, m)| (std::path::PathBuf::from(p), *m)).collect()
    }

    /// The root-owned skeleton every case needs (`/`, `/usr`, `/usr/bin`, `/bin`, …), so each
    /// test only states the interesting entry.
    const SAFE: (u32, u32) = (0, 0o755);

    #[test]
    fn pick_helper_takes_the_first_root_owned_candidate() {
        let tree = helper_tree(&[
            ("/", SAFE),
            ("/usr", SAFE),
            ("/usr/bin", SAFE),
            ("/usr/bin/curl", SAFE),
        ]);
        let got = pick_helper(
            "curl",
            &["/usr/bin", "/bin"],
            |p| tree.contains_key(p).then(|| p.to_path_buf()),
            |p| tree.get(p).copied(),
        );
        assert_eq!(got.unwrap(), std::path::PathBuf::from("/usr/bin/curl"));
    }

    #[test]
    fn pick_helper_refuses_a_non_root_owned_or_writable_candidate() {
        // The PATH-injection shape, with the attacker's copy sitting where we look: a
        // user-owned binary must never be executed by a process holding file capabilities.
        let owned_by_user = helper_tree(&[
            ("/", SAFE),
            ("/usr", SAFE),
            ("/usr/bin", SAFE),
            ("/usr/bin/curl", (1000, 0o755)),
        ]);
        let err = pick_helper(
            "curl",
            &["/usr/bin"],
            |p| owned_by_user.contains_key(p).then(|| p.to_path_buf()),
            |p| owned_by_user.get(p).copied(),
        )
        .expect_err("a uid-1000-owned curl must be refused");
        assert!(err.contains("/usr/bin/curl") && err.contains("owned by uid 1000"), "{err}");

        // Root-owned but world-writable is the same hole with an extra step.
        let world_writable = helper_tree(&[
            ("/", SAFE),
            ("/usr", SAFE),
            ("/usr/bin", SAFE),
            ("/usr/bin/curl", (0, 0o777)),
        ]);
        let err = pick_helper(
            "curl",
            &["/usr/bin"],
            |p| world_writable.contains_key(p).then(|| p.to_path_buf()),
            |p| world_writable.get(p).copied(),
        )
        .expect_err("a world-writable curl must be refused");
        assert!(err.contains("group- or world-writable"), "{err}");

        // And a writable ANCESTOR: the file itself is fine, but anyone owning the directory
        // can swap it between this check and the exec.
        let writable_dir = helper_tree(&[
            ("/", SAFE),
            ("/usr", SAFE),
            ("/usr/bin", (0, 0o777)),
            ("/usr/bin/curl", SAFE),
        ]);
        assert!(
            pick_helper(
                "curl",
                &["/usr/bin"],
                |p| writable_dir.contains_key(p).then(|| p.to_path_buf()),
                |p| writable_dir.get(p).copied(),
            )
            .is_err(),
            "a world-writable /usr/bin must be refused"
        );
    }

    #[test]
    fn pick_helper_skips_an_unsafe_candidate_for_a_later_safe_one() {
        // /usr/bin/tc is user-owned, /sbin/tc is not: the search continues rather than
        // failing, and never returns the unsafe one.
        let tree = helper_tree(&[
            ("/", SAFE),
            ("/usr", SAFE),
            ("/usr/bin", SAFE),
            ("/usr/bin/tc", (1000, 0o755)),
            ("/sbin", SAFE),
            ("/sbin/tc", SAFE),
        ]);
        let got = pick_helper(
            "tc",
            &["/usr/bin", "/sbin"],
            |p| tree.contains_key(p).then(|| p.to_path_buf()),
            |p| tree.get(p).copied(),
        );
        assert_eq!(got.unwrap(), std::path::PathBuf::from("/sbin/tc"));
    }

    #[test]
    fn pick_helper_missing_program_names_the_directories_it_searched() {
        let empty = helper_tree(&[]);
        let err = pick_helper("curl", &["/usr/bin", "/bin"], |p| empty.contains_key(p).then(|| p.to_path_buf()), |p| empty.get(p).copied())
            .expect_err("nothing installed");
        assert!(err.contains("/usr/bin, /bin"), "{err}");
        assert!(err.contains("never through PATH"), "{err}");
    }

    #[test]
    fn helper_path_resolves_the_real_curl_when_one_is_installed() {
        // Against the REAL filesystem: on any host with a packaged curl this must resolve to
        // an absolute path under one of the trusted directories. Skipped where curl isn't
        // installed (a minimal build container) rather than failing the build.
        match helper_path("curl") {
            Ok(p) => {
                assert!(p.is_absolute(), "{}", p.display());
                assert!(HELPER_DIRS.iter().any(|d| p.starts_with(d)), "{}", p.display());
            }
            Err(reason) => assert!(reason.contains("cannot run `curl`"), "{reason}"),
        }
    }

    #[test]
    fn borrowed_privilege_is_caps_without_root() {
        const BASE: u64 = (1 << CAP_BPF) | (1 << CAP_PERFMON) | (1 << CAP_DAC_READ_SEARCH);
        // The file-capability case: the caps did not come from the invoking user, so HOME
        // and PATH are that user's rather than the privilege owner's.
        assert!(borrowed_privilege(1000, BASE));
        // Real root (sudo): the ambient environment and the privilege belong together.
        assert!(!borrowed_privilege(0, BASE));
        assert!(!borrowed_privilege(0, 0));
        // An ordinary unprivileged run holds nothing to borrow.
        assert!(!borrowed_privilege(1000, 0));
    }

    /// The REAL `setcap.sh`, compiled in, so the pin below reads the same text `./setcap.sh`
    /// runs. (`src/elevate.rs` → three levels up is the repo root.) Same source-text pinning
    /// as `bpf_c_declares_the_maps_the_loader_looks_up` in main.rs: the two grants are
    /// coupled only by convention, and a drift is invisible until an attach fails with
    /// EACCES on whichever path granted less.
    const SETCAP_SH: &str = include_str!("../../../setcap.sh");

    /// Reconstruct the cap list `setcap.sh` builds: the `caps="…"` seed, plus each
    /// `caps="$caps,…"` append (which the script gates behind `UPROBES=1`).
    fn setcap_sh_caps(uprobes: bool) -> String {
        let mut caps = String::new();
        for line in SETCAP_SH.lines() {
            let Some(rest) = line.trim_start().strip_prefix("caps=\"") else { continue };
            let value = rest.split('"').next().expect("an unterminated caps= assignment");
            match value.strip_prefix("$caps") {
                Some(extra) if uprobes => caps.push_str(extra), // the UPROBES append
                Some(_) => {}
                None => caps = value.to_string(), // the base seed
            }
        }
        assert!(!caps.is_empty(), "setcap.sh has no caps=\"…\" assignment — did it move?");
        caps
    }

    #[test]
    fn cap_string_matches_setcap_sh() {
        // Literal pins, so a reader sees what is granted…
        assert_eq!(cap_string(false), "cap_bpf,cap_perfmon,cap_dac_read_search+ep");
        assert_eq!(cap_string(true), "cap_bpf,cap_perfmon,cap_dac_read_search,cap_sys_admin+ep");
        // …and the actual pin: the strings `s3tap setup` passes to setcap must equal the ones
        // the shell script passes. Restating cap_string's own literals here (which is all this
        // test used to do) pinned nothing — dropping cap_dac_read_search from setcap.sh stayed
        // green while the two paths granted different sets.
        assert_eq!(
            format!("{}+ep", setcap_sh_caps(false)),
            cap_string(false),
            "setcap.sh's default grant drifted from `s3tap setup`"
        );
        assert_eq!(
            format!("{}+ep", setcap_sh_caps(true)),
            cap_string(true),
            "setcap.sh's UPROBES=1 grant drifted from `s3tap setup --uprobes`"
        );
        // The `+ep` flags (and the UPROBES gate on the append) live in the script's shape, not
        // in the cap list — pin them separately so the reconstruction above stays honest.
        assert!(SETCAP_SH.contains(r#"sudo setcap "$caps+ep""#), "setcap.sh no longer applies +ep");
        assert!(
            SETCAP_SH.contains(r#"if [[ "${UPROBES:-0}" == 1 ]]; then"#),
            "the cap_sys_admin append is no longer gated on UPROBES=1"
        );
    }

    /// The two paths must agree on the PRECONDITION, not just on the cap list. `s3tap setup`
    /// refuses to cap a binary (or an ancestor directory) that is not root-owned or is
    /// group/other-writable, because file caps belong to whoever can put bytes in that inode.
    /// `setcap.sh` grants the SAME caps and is the documented dev loop (which says to
    /// re-run it after every build), so a script without that gate is simply the way around
    /// the Rust guard. `cap_string_matches_setcap_sh` above pinned only the strings, which is
    /// how the two drifted on policy while staying green. Deleting the shell gate must fail CI.
    #[test]
    fn setcap_sh_refuses_the_same_unsafe_targets_as_setup() {
        // The gate exists, and is the same three-part component check as `component_unsafe`:
        // un-stattable, non-root owner, group/other-writable.
        assert!(SETCAP_SH.contains("unsafe_component"), "setcap.sh lost its safety gate");
        assert!(SETCAP_SH.contains("stat -c '%u %a'"), "the gate no longer reads uid + mode");
        assert!(
            SETCAP_SH.contains(r#"[[ "${st%% *}" != 0 ]]"#),
            "setcap.sh no longer refuses a non-root-owned target"
        );
        assert!(
            SETCAP_SH.contains("8#22"),
            "setcap.sh no longer refuses a group/world-writable target (the 022 mask is gone)"
        );
        // Same TOCTOU hardening as `insecure_setcap_walk`: resolve symlinks, then walk EVERY
        // ancestor up to `/` rather than trusting the immediate parent.
        assert!(SETCAP_SH.contains("readlink -f"), "a symlinked segment could smuggle a writable dir past the check");
        assert!(
            SETCAP_SH.contains(r#"while [[ -z "$reason" ]]"#) && SETCAP_SH.contains(r#"dirname -- "$dir""#),
            "setcap.sh no longer walks the ancestor directories"
        );
        // Refusing is the DEFAULT: the only way past is an explicit per-invocation opt-out.
        assert!(
            SETCAP_SH.contains(r#"if [[ "${S3TAP_SETCAP_INSECURE:-0}" != 1 ]]; then"#),
            "the refusal is no longer the default (or the opt-out variable was renamed)"
        );
        assert!(
            SETCAP_SH.contains("error: refusing to grant capabilities"),
            "setcap.sh no longer refuses, it only warns"
        );
        // And the two describe the same two failures in the same words, so a policy change on
        // either side reads as a diff on both.
        let by_owner = component_unsafe("binary", Some((1000, 0o755))).expect("uid 1000 is unsafe");
        let by_mode = component_unsafe("binary", Some((0, 0o777))).expect("world-writable is unsafe");
        assert!(by_owner.contains("is owned by uid") && SETCAP_SH.contains("is owned by uid"));
        assert!(
            by_mode.contains("is group- or world-writable")
                && SETCAP_SH.contains("is group- or world-writable")
        );
    }

    // The report is a plain String written through one locked handle (so `setup | head`
    // can't panic a successful grant). Pin what each variant says: the base grant must
    // point at `--uprobes`, the uprobe grant must not, and both must carry the
    // rebuild-wipes-caps caveat. Every line ends in a newline (the writer adds none).
    #[test]
    fn setup_report_says_what_was_granted_and_what_is_still_missing() {
        let base = setup_report(&cap_string(false), "/usr/local/bin/s3tap", false, false);
        assert!(base.starts_with("granted cap_bpf,cap_perfmon,cap_dac_read_search+ep\n"));
        assert!(base.contains("     on /usr/local/bin/s3tap\n"));
        assert!(base.contains("sudo s3tap setup --uprobes"), "base grant points at the uprobe opt-in");
        assert!(base.contains("capabilities live on the binary inode"));
        assert!(base.ends_with('\n'));

        let full = setup_report(&cap_string(true), "/usr/local/bin/s3tap", true, false);
        assert!(full.contains("cap_sys_admin+ep"));
        assert!(!full.contains("sudo s3tap setup --uprobes"), "already granted — no upsell");
        assert!(full.contains("capabilities live on the binary inode"));

        // --remove: one line, no grant caveats (there is nothing left to re-grant).
        let removed = setup_report(&cap_string(false), "/usr/local/bin/s3tap", false, true);
        assert_eq!(
            removed,
            "removed file capabilities from /usr/local/bin/s3tap — probe commands need sudo again.\n"
        );
    }
}
