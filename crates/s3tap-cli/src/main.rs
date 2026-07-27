// crates/s3tap-cli/src/main.rs
//
// The s3tap agent: load the eBPF object, attach the inet_sock_set_state
// tracepoint, drain the ring buffer, fold raw connect/close events into
// s3tap.connection/2 + s3tap.operation/1 records (via s3tap-core), and emit them.
// Output is the human waterfall/table (render.rs) on a tty, or jsonl when piped.

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as BpfHashMap, RingBuf},
    programs::{BtfTracePoint, FEntry, KProbe, TracePoint, UProbe},
    Btf, Ebpf,
};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, ValueEnum};
use filter::{Filter, FilterSpec};
use s3tap_core::Correlator;
use s3tap_events::Event;
use s3tap_schema::{Connection, Operation, TcpSample};

/// `eprintln!` for a diagnostic that must never kill the process: `eprintln!` PANICS on a
/// write error, so `s3tap advise --from capture.jsonl 2>&1 | head -1` (a closed stderr)
/// would exit 101 with a panic trace where the pure-consumer contract pins a clean exit.
/// Status/note lines go through this; only the RECORD stream on stdout keeps the explicit
/// BrokenPipe mapping, because there a failed write means the report is incomplete.
/// Declared before the `mod`s: `macro_rules!` scope is textual, so this is what makes it
/// usable from selftest/elevate too.
macro_rules! enote {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// [`enote!`] without the trailing newline, for the in-place progress line (which redraws
/// with a leading `\r` and needs an explicit flush).
macro_rules! enote_raw {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stderr(), $($arg)*);
        let _ = std::io::stderr().flush();
    }};
}

mod elevate;
mod filter;
mod render;
mod selftest;

/// One emittable public record. `fold` produces a `Connection` (per socket, at
/// close) or an `Operation` (per S3 request, when its response completes — E5).
/// Both boxed — they're large structs and only one is produced per folded event.
pub(crate) enum Record {
    Connection(Box<Connection>),
    Operation(Box<Operation>),
    /// A periodic in-flight TCP sample (`s3tap.sample/1`) — opt-in `--sample-interval-ms`.
    TcpSample(Box<TcpSample>),
}
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{BufWriter, IsTerminal, Write};
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{signal, SignalKind};

#[derive(Parser)]
#[command(
    name = "s3tap",
    version,
    about = "Observe TCP/S3 connections and operations via eBPF (waterfall/table/jsonl)"
)]
struct Cli {
    /// Subcommand; absent ⇒ `run` (observe live traffic) with the options below.
    #[command(subcommand)]
    command: Option<Command>,
    /// Never self-elevate: when privileges are missing, fail with the normal
    /// permission error instead of re-running under sudo.
    #[arg(long, global = true)]
    no_elevate: bool,
    #[command(flatten)]
    run: RunOpts,
}

/// s3tap subcommands. `run` is the default (no subcommand) and carries all the
/// observe-time options; `selftest` is a one-shot pipeline health check.
#[derive(clap::Subcommand)]
enum Command {
    /// Prove the pipeline works on this host: load the probes, drive a few real S3
    /// requests, and assert each capability (DNS/TCP/TLS/HTTP) produced a record.
    /// Prints a pass/fail table and exits non-zero on any failed capability.
    Selftest(SelftestArgs),
    /// Judge a capture's health: read `s3tap.operation/1` + `s3tap.connection/2` JSONL
    /// (stdin or a file) and report whether each latency span is healthy, relative to
    /// the connection's RTT floor. A PURE CONSUMER of the public records — no probes,
    /// no privilege; composes as `s3tap --format jsonl | s3tap doctor`. Exits non-zero
    /// when a metric is outside its envelope (⚠). EXCEPTION: `--live` drives + captures
    /// its own workload (loads eBPF, needs caps) instead of reading records.
    Doctor(DoctorArgs),
    /// Optimization advisories over a capture: read `s3tap.operation/1` +
    /// `s3tap.connection/2` JSONL (stdin or a file) and report how the application
    /// USES S3 — client churn, missing parallelism, redundant re-fetches, throttling,
    /// caching go/no-go — attributed per process. A PURE CONSUMER of the public
    /// records (no probes, no privilege); composes as `s3tap --format jsonl | s3tap
    /// advise`. Health judgments live in `doctor`; this is optimization advice.
    Advise(AdviseArgs),
    /// Observed-SLO scorecard over a capture: read `s3tap.operation/1` JSONL (stdin or a
    /// file) and report each `bucket / s3_op` with the latency + reliability it ACTUALLY saw —
    /// request/error counts, the status-code mix, and TTFB p50/p95/p99. The passive
    /// analogue of a speedtest (your own production numbers, no synthetic probe). A PURE
    /// CONSUMER (no probes, no privilege); composes as `s3tap --format jsonl | s3tap
    /// scorecard`. `--json` emits `s3tap.scorecard/1` rows plus the gated `s3tap.finding/1`
    /// reliability judgments; `--strict` exits non-zero when any judgment fired.
    Scorecard(ScorecardArgs),
    /// Deep caching + prefetch report for ONE trace: the offline study, run on your
    /// workload. Reads a trace (s3tap JSONL, NormEvent JSON, or an IBM COS line — a
    /// file or stdin), runs the FULL retention ladder (LRU / ARC / S3-FIFO / OPT) in
    /// chunk mode plus the prefetch tradeoff, and prints a recommendation: cache or
    /// not, which policy, what size, and whether prefetching will help. Heavier than
    /// `advise` (seconds to minutes) — a PURE CONSUMER (no probes, no privilege).
    /// `--fast` runs retention-only (~12× quicker); `--json` emits the structured
    /// verdict. Composes as `s3tap --format jsonl | s3tap analyze`.
    Analyze(AnalyzeArgs),
    /// The easy front-end to `doctor --live`: probe an S3 object and print a one-line
    /// plain-language verdict. Give it a `bucket/key` (expanded to the S3 endpoint) or a full
    /// URL for a verdict on YOUR path (strict exit code). Omit the target for the zero-config
    /// check: a regional round-trip map, then a health check against a public AWS Open Data
    /// object in the nearest covered region (informational exit; `--map-only` prints just the
    /// map). Loads eBPF: the L7 rows want the uprobe caps (`sudo s3tap setup --uprobes`), the
    /// map needs only the base caps (`sudo s3tap setup`) — without them s3tap offers sudo
    /// itself and, lacking uprobes, judges the network floor only. Full flags: `doctor --live`.
    Check(CheckArgs),
    /// Grant this s3tap binary the file capabilities to load its probes WITHOUT
    /// sudo — the programmatic `setcap.sh`. Asks for sudo itself (once); re-run
    /// after every rebuild (caps live on the binary inode, which `cargo build`
    /// replaces).
    Setup(SetupArgs),
}

#[derive(clap::Args)]
struct CheckArgs {
    /// The S3 object to probe: `bucket/key` (expanded to `bucket.s3[.REGION].amazonaws.com/key`)
    /// or a full URL. A bare bucket with no key is rejected — there is no object to GET. OMIT it
    /// to run the built-in regional latency probes (a where-am-I-relative-to-S3 read).
    #[arg(value_name = "BUCKET/KEY|URL")]
    target: Option<String>,
    /// (bucket form) Target a specific region's endpoint, e.g. `eu-west-1`. Default: the global
    /// endpoint. The probe does NOT follow redirects, so a bucket OUTSIDE us-east-1 needs this
    /// (or a regional URL) — otherwise S3's region redirect reads as unhealthy. Also the SigV4
    /// signing region under `--auth`.
    // requires = "target": the no-target regional map never reads either flag (it probes
    // service endpoints anonymously), so accepting them there silently promised a signed
    // or region-pinned probe that never happened.
    #[arg(long, value_name = "REGION", requires = "target")]
    region: Option<String>,
    /// SigV4-sign the probe so a PRIVATE bucket returns 2xx (creds from env or `~/.aws`).
    #[arg(long, requires = "target")]
    auth: bool,
    /// Show the full detailed report instead of the one-line summary.
    #[arg(long)]
    verbose: bool,
    /// Keep-alive requests to issue (default 12; raise for a p95/p99 tail).
    #[arg(long, default_value_t = 12)]
    requests: u32,
    /// (target form) After the health check, sweep the probed regions and report how much
    /// round-trip is lower at the nearest one — with the standard remedies. The ms figures are
    /// measured (not geo-estimated); "nearest" is nearest of the few probed regions, not every S3
    /// region. Adds the regional sweep time (a few seconds per probed region). Needs a target
    /// (the no-target run already sweeps the regions).
    // requires = "target": with no target this was ACCEPTED and then ignored, so a run asked
    // for the comparison and got the plain regional map back with nothing saying why.
    #[arg(long, requires = "target")]
    triage: bool,
    /// (no-target form) Print only the regional round-trip map — skip the follow-up health
    /// check against a public test object in the nearest covered region. Needs only the base
    /// caps (the map is connection-floor only; the object check drives the L7/uprobe path).
    // conflicts_with = "target": with a target this was ignored, so a request to SKIP the live
    // L7 probe instead drove 12 real GETs against the user's own bucket (and prompted for
    // elevation to do it). The opposite of what the flag says, so reject the pair.
    #[arg(long, conflicts_with = "target")]
    map_only: bool,
}

#[derive(clap::Args)]
struct SetupArgs {
    /// Also grant cap_sys_admin — required by the SSL/getaddrinfo uprobe paths
    /// (`--capture-plaintext`, `selftest`, the full `check`/`doctor --live` L7 rows).
    /// Near-root, and the plaintext path sees decrypted bytes host-wide — opt in
    /// deliberately (same posture as `UPROBES=1 ./setcap.sh`).
    // conflicts_with = "remove": `setup --remove --uprobes` reads as "drop only the uprobe
    // cap", but --remove strips the WHOLE grant and ignores this flag — so reject the
    // combination instead of quietly doing something else.
    #[arg(long, conflicts_with = "remove")]
    uprobes: bool,
    /// Remove the file-capability grant from this binary instead.
    #[arg(long)]
    remove: bool,
}

#[derive(clap::Args)]
struct AdviseArgs {
    /// JSONL of public records to analyze: a file, or `-`/absent for stdin.
    #[arg(long, value_name = "FILE")]
    from: Option<std::path::PathBuf>,
    /// Disable ANSI color (also auto-off when stdout isn't a terminal).
    #[arg(long)]
    no_color: bool,
    /// Emit `s3tap.finding/1` records (NDJSON, one per advisory) instead of the
    /// human table. Same exit-code contract.
    #[arg(long)]
    json: bool,
    /// Gate the exit code on advice: exit 1 when any Warn or Advisory finding
    /// fired. Off by default — advice is not a failure.
    #[arg(long)]
    strict: bool,
}

#[derive(clap::Args)]
struct ScorecardArgs {
    /// JSONL of public records to score: a file, or `-`/absent for stdin.
    #[arg(long, value_name = "FILE")]
    from: Option<std::path::PathBuf>,
    /// Disable ANSI color (also auto-off when stdout isn't a terminal).
    #[arg(long)]
    no_color: bool,
    /// Emit `s3tap.scorecard/1` rows followed by the gated `s3tap.finding/1`
    /// records (NDJSON) instead of the human table. Same exit-code contract.
    #[arg(long)]
    json: bool,
    /// Gate the exit code on the scorecard findings: exit 1 when any Warn or Advisory
    /// finding fired. Off by default — a scorecard is a report. Independent of exit 2,
    /// which a capture with nothing scoreable returns either way.
    #[arg(long)]
    strict: bool,
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    /// The trace to analyze: a file, or `-`/absent for stdin. Auto-detects
    /// s3tap JSONL records, NormEvent JSON, or IBM COS text lines.
    #[arg(long, value_name = "FILE")]
    from: Option<std::path::PathBuf>,
    /// Retention-only: skip the prefetch pass entirely (fastest). Answers "which
    /// cache, how big" but not "will prefetching help".
    #[arg(long)]
    fast: bool,
    /// Run the full, expensive prefetch ladder too (Frequency/Co-occurrence/
    /// Sequential/Adaptive). The Adaptive rung runs a per-size shadow cache and is
    /// minutes-to-much-more on a large trace. The default already gives the
    /// study's verdict (Markov structure + the shippable self-tuned overlay) fast.
    #[arg(long, conflicts_with = "fast")]
    deep: bool,
    /// Analyze in object mode (whole objects) instead of the default 8 MB chunk
    /// mode. Chunk mode sees within-object/streaming structure; object mode is
    /// faster and matches how `advise` sizes.
    #[arg(long)]
    object: bool,
    /// Analyze at most N leading ops (a time slice) so huge traces stay bounded.
    /// 0 = the whole trace. Default 3,000,000 (study parity).
    #[arg(long, value_name = "N")]
    max_events: Option<usize>,
    /// Disable ANSI color (also auto-off when stdout isn't a terminal).
    #[arg(long)]
    no_color: bool,
    /// Emit the structured verdict as one JSON object instead of the human report.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct DoctorArgs {
    /// JSONL of public records to judge: a file, or `-`/absent for stdin.
    #[arg(long, value_name = "FILE")]
    from: Option<std::path::PathBuf>,
    /// Disable ANSI color (also auto-off when stdout isn't a terminal).
    #[arg(long)]
    no_color: bool,
    /// Emit `s3tap.finding/1` records (NDJSON, one per check + the run roll-up) instead
    /// of the human table — the machine/fleet-ingest format. Still
    /// reads from `--from`/stdin and keeps the same exit-code contract.
    #[arg(long)]
    json: bool,
    /// Compare the current capture against a baseline JSONL file and print a
    /// regression diff instead of the report. Latency checks are
    /// compared RTT-relative, so a capture from a different network still compares fairly.
    /// Exits 1 if the current capture regressed, 2 if the current capture had nothing to
    /// judge, 0 otherwise. A structured diff is future, so this conflicts with `--json`
    /// rather than silently writing a human table where NDJSON was asked for.
    // conflicts_with = "json" for the same reason `--cost` has it: --baseline REPLACES the
    // body, so `--json --baseline` discarded every `s3tap.finding/1` record a fleet ingest
    // asked for (6 rows -> 0) and wrote a human diff instead. Adding a flag for gating must
    // not silently drop records; the doc-comment admitting it did is not a substitute.
    #[arg(long, value_name = "FILE", conflicts_with = "json")]
    baseline: Option<std::path::PathBuf>,
    /// Stricter gate: treat ADVISORY findings (e.g. a GET-throughput drop)
    /// as attention too, so they affect the exit code / fail the `--baseline` gate. Off by
    /// default — advisory metrics are deliberately unjudged (BDP/window-dependent).
    #[arg(long)]
    strict: bool,
    /// Print an approximate S3 request-cost breakdown (per op-class) instead of the health
    /// report. Estimate only (AWS Standard us-east-1 request prices;
    /// data egress not included). Informational — always exits 0.
    // conflicts_with_all: --cost REPLACES the body and forces exit 0, so pairing it with a
    // flag that asks for something else silently discards that ask. `--json --cost` wrote a
    // human table where NDJSON was requested, and `--baseline ref.jsonl --cost --strict` read
    // and analyzed the whole baseline, built the diff, threw it away and exited 0 — a
    // regression gate that had stopped gating without ever saying so.
    #[arg(long, conflicts_with_all = ["json", "baseline"])]
    cost: bool,
    /// Collapse the report to a one-line, plain-language verdict (plus the specific issues to
    /// look at on ATTENTION) — the easy read for non-technical users. Same verdict + exit code
    /// as the full report, just without the per-span table. Ignored under --json/--cost/--baseline.
    #[arg(long)]
    brief: bool,
    /// Drive a small keep-alive workload against `--endpoint`, capture it, and report —
    /// instead of reading records from `--from`/stdin. Loads eBPF, so it
    /// needs the probe caps (`sudo s3tap setup --uprobes` for the L7/operation rows). Composes
    /// with `--strict`, and with ONE of `--json` / `--cost` / `--baseline` — those three each
    /// replace the report body, so they are mutually exclusive. Exit 3 if it captured nothing.
    #[arg(long)]
    live: bool,
    // Every flag below is `requires = "live"`: without --live the doctor is a pure record
    // consumer that reads none of them, and clap silently accepting them made
    // `doctor --from capture.jsonl --save baseline.jsonl` exit 0 having written no baseline
    // — the user then believed a reference capture existed. Rejecting up front is the only
    // honest answer. (`check` builds DoctorArgs in code, not through clap, so it is
    // unaffected.)
    /// (`--live`) The readable S3 endpoint/object the workload hits — REQUIRED under
    /// `--live`. An endpoint the workload can't read 2xx from will read unhealthy, by design.
    /// Repeatable: with `--rotate`, the requests cycle through all the given objects (one per
    /// request) so every fetch is COLD — defeats per-object caching for a cold-fetch measure.
    #[arg(long, value_name = "URL", requires = "live")]
    endpoint: Vec<String>,
    /// (`--live`) Rotate through the `--endpoint` objects, one per request (round-robin),
    /// instead of hammering a single object. Use it to measure COLD-fetch latency: pass at
    /// least `--requests` DISTINCT, similar-size objects so none is revisited (and warmed)
    /// within the run. Without it, all requests hit the first `--endpoint`.
    #[arg(long, requires = "live")]
    rotate: bool,
    /// (`--live`) Number of keep-alive requests to issue (a median + a reuse signal; raise
    /// for the p95/p99 tail). Capped at 10000, and lower for a long `--endpoint` URL: the
    /// whole sequence is materialized as one curl argv.
    #[arg(long, default_value_t = 12, requires = "live")]
    requests: u32,
    /// (`--live`) Capture budget in seconds. Must be 1..=3600.
    #[arg(long, default_value_t = 15, requires = "live")]
    timeout_secs: u64,
    /// (`--live`) Also write the (cookie-obscured) captured JSONL here — reusable later as
    /// a `--baseline`. Created new, mode 0600: the path must not already exist (`--live`
    /// often re-execs under sudo, so this write can be root's) and a capture names your
    /// buckets, endpoints and SNI.
    #[arg(long, value_name = "FILE", requires = "live")]
    save: Option<std::path::PathBuf>,
    /// (`--live`) SigV4-sign the workload so a PRIVATE bucket returns 2xx.
    /// Creds: AWS_ACCESS_KEY_ID/SECRET (+ AWS_SESSION_TOKEN) env, else
    /// ~/.aws/credentials (AWS_PROFILE or `default`). Errors if no creds resolve. The
    /// secret is fed to curl off the command line.
    #[arg(long, requires = "live")]
    auth: bool,
    /// (`--live --auth`) Region for SigV4 (default: AWS_REGION / ~/.aws/config / us-east-1).
    // requires = "auth" (not "live"): the value is read ONLY by resolve_aws_creds, which runs
    // only under --auth. `doctor --live --region eu-west-1` was accepted, never validated and
    // never used, so the operator believed the probe was region-pinned when nothing had
    // changed. Same fix already applied to CheckArgs::region (see the comment there). --auth
    // itself requires --live, so this still keeps the flag off the pure-consumer path.
    #[arg(long, value_name = "REGION", requires = "auth")]
    region: Option<String>,
    /// (`--live`) Treat this host as an S3-compatible endpoint so the per-`s3_op` rows
    /// resolve a path-style bucket/key (e.g. `--s3-endpoint gateway.storjshare.io`). AWS
    /// hosts are recognized natively; repeatable. Without it the global/floor/tail rows
    /// still judge, but the S3-domain rows are thin for a non-AWS gateway.
    #[arg(long, value_name = "HOST", requires = "live")]
    s3_endpoint: Vec<String>,
    /// (`--live`) Drive the workload over N parallel connections at once, to measure the path
    /// under CONCURRENT load — RTT inflation, retransmits, and the throughput/BDP ceiling only
    /// show up under contention, and low reuse only bites when several sockets compete. Each of
    /// the N workers runs the full `--requests` sequence on its OWN curl invocation (its own
    /// connection), so the doctor sees N connections in flight and total requests = N ×
    /// `--requests`. Default 1 (serial keep-alive, one connection). Capped at 256.
    #[arg(long, value_name = "N", default_value_t = 1, requires = "live")]
    concurrency: u32,
}

// The `doctor` subcommand. A PURE CONSUMER by default (--from/stdin → report; no kernel,
// no caps); `--live` is the exception — it drives + captures its own workload (needs caps).

/// Longest input line we will hold, in bytes. A public record is a few hundred bytes, so a
/// mebibyte is orders of magnitude of headroom for even a pathological key/header. The cap
/// exists because the reader must not be steerable into an unbounded allocation by a single
/// line: a truncated capture whose tail is a gigabyte with no newline, or a file that isn't
/// JSONL at all, would otherwise be read into memory in full before anything could reject
/// it. An over-long line is DROPPED WHOLE (never truncated into a shorter "record" that
/// might parse) and counted like any other unusable line, so the skip is always reported.
const MAX_INPUT_LINE: usize = 1 << 20;

/// How much text to accumulate before handing a batch to the parser. Big enough that the
/// per-call overhead is noise, small enough that the transient buffer stays tiny next to
/// the input (which is the whole point — the input is never materialized).
const PARSE_BATCH_BYTES: usize = 1 << 20;

/// Exit code for "s3tap itself could not do the job", as distinct from every VERDICT code.
///
/// 0/1/2/3 are answers about the capture: healthy, attention, nothing judgeable, nothing
/// captured. Everything that stops s3tap from producing an answer at all (an unreadable
/// `--from` path, a malformed baseline, a serialize failure, a refused `--save`, a
/// capability check that came back FAILED) used to land on anyhow's exit 1, i.e. on the
/// same code as a capture with a retransmit warning. `s3tap doctor --from typo.jsonl` then
/// failed a CI gate identically to a real regression, and no script could tell the two
/// apart. This code is reserved for that second meaning, so a gate can treat 1 as "the
/// workload has a problem" and 4 as "fix the invocation".
const EXIT_TOOL_FAILURE: i32 = 4;
/// Nothing judgeable: s3tap READ the capture and found no population to judge against. Shared
/// by every consumer — `doctor`'s missing-denominator verdicts, `advise`'s missing operation
/// population, `scorecard`'s empty row set and `analyze`'s "no demand read here". Distinct
/// from [`EXIT_TOOL_FAILURE`] because the fix is to the capture, not to the invocation.
const EXIT_NOTHING_JUDGEABLE: i32 = 2;

/// Exit code for "the run produced no records at all", the third VERDICT code.
///
/// Long the `--live` code for a workload whose traffic nothing captured. A bare capture run
/// reaches it too, on exactly one shape: an `--app`/`--exe` scope that never once had a
/// process in it (see [`scope_never_matched`]). Both mean the same thing to a script, which
/// is why they share a number: s3tap ran, saw nothing and has no verdict to give.
const EXIT_NOTHING_CAPTURED: i32 = 3;

/// The one place the `--no-color` contract is decided: color is on only when the user did
/// not ask for it off AND stdout is a terminal. Both halves matter and only one of them is
/// visible in a review diff — a subcommand that forgets `is_tty` writes ANSI escapes into
/// a redirected file or a `| grep`, which is exactly what a pure consumer's output must
/// never do. Pure, so the four combinations are pinned by a unit test rather than by
/// reading four call sites and hoping they agree.
fn want_color(no_color: bool, is_tty: bool) -> bool {
    !no_color && is_tty
}

/// Read one line (without its terminator) from `r` into `buf`, holding at most `max` bytes.
/// `Ok(None)` = EOF with nothing left; `Ok(Some(true))` = the line EXCEEDED the cap, so
/// `buf` is empty and the rest of that line has been consumed and discarded;
/// `Ok(Some(false))` = a normal line in `buf`. Unlike `BufRead::read_line` this NEVER grows
/// the buffer past `max`, which is what makes a pathological line bounded rather than an
/// allocation the caller can't refuse.
fn read_line_capped<R: std::io::BufRead + ?Sized>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Option<bool>> {
    buf.clear();
    let mut over = false;
    let mut read_any = false;
    loop {
        let chunk = match r.fill_buf() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            // EOF. A final line without a trailing newline still counts as a line.
            return Ok(if read_any { Some(over) } else { None });
        }
        read_any = true;
        let (take, consumed, eol) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i, i + 1, true),
            None => (chunk.len(), chunk.len(), false),
        };
        if !over {
            if buf.len() + take > max {
                // Drop what we already held: a PREFIX of a record is not a record, and
                // feeding one to the parser risks a partial line that happens to decode.
                over = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&chunk[..take]);
            }
        }
        r.consume(consumed);
        if eol {
            return Ok(Some(over));
        }
    }
}

/// Open a pure-consumer command's JSONL input as a STREAM: `--from FILE`, or `-`/absent =
/// stdin. Returns the reader plus a label for error context. If stdin is an INTERACTIVE
/// TERMINAL (no pipe, no file), don't block silently on a blank read — a bare `s3tap
/// doctor` in a terminal would look hung. Print a usage hint and bail instead.
fn open_consumer_input(
    from: Option<&std::path::Path>,
    cmd: &str,
    live_hint: bool,
) -> anyhow::Result<(Box<dyn std::io::BufRead>, String)> {
    use std::io::IsTerminal;
    match from {
        Some(p) if p != std::path::Path::new("-") => {
            let f = std::fs::File::open(p)
                .with_context(|| format!("reading {}", p.display()))?;
            Ok((Box::new(std::io::BufReader::new(f)), p.display().to_string()))
        }
        _ => {
            if std::io::stdin().is_terminal() {
                let mut msg = format!(
                    "s3tap {cmd}: no input. It reads s3tap JSONL records from a pipe or --from FILE.\n  \
                     pipe a live capture:  s3tap --format jsonl | s3tap {cmd}\n  \
                     read a saved file:    s3tap {cmd} --from capture.jsonl"
                );
                if live_hint {
                    msg.push_str(
                        "\n  drive + judge live:   s3tap doctor --live --endpoint <bucket/key|url>",
                    );
                }
                anyhow::bail!(msg);
            }
            Ok((Box::new(std::io::stdin().lock()), "stdin".to_string()))
        }
    }
}

/// Parse a record stream WITHOUT materializing it: read bounded lines, hand them to the
/// same [`s3tap_doctor::parse_records`] in small batches, keep only the records. The parser
/// judges every line independently, so batching is accounting-identical to one call over
/// the whole text — the two `ParseStats` counters just sum. Reading `--from` (or a piped
/// capture) into one `String` first meant a capture only had to be bigger than RAM to turn
/// a report into an OOM kill, which is the one failure a diagnostic tool must not have.
///
/// Two line-level skips the whole-string reader could not express, both counted as
/// `bad_lines` (a line that cannot be a record, which is exactly what that counter means):
/// a line over [`MAX_INPUT_LINE`], and a line that isn't UTF-8 (previously the ENTIRE read
/// failed on the first stray byte).
fn stream_records<R: std::io::BufRead>(
    mut r: R,
    what: &str,
) -> anyhow::Result<(Vec<s3tap_doctor::Record>, s3tap_doctor::ParseStats)> {
    let mut records = Vec::new();
    let mut stats = s3tap_doctor::ParseStats::default();
    let mut batch = String::new();
    let mut line = Vec::new();
    // A batch is a plain slice of the input, so `parse_records` sees byte-identical lines.
    fn flush(
        batch: &mut String,
        records: &mut Vec<s3tap_doctor::Record>,
        stats: &mut s3tap_doctor::ParseStats,
    ) {
        if batch.is_empty() {
            return;
        }
        let (recs, st) = s3tap_doctor::parse_records(batch);
        records.extend(recs);
        stats.bad_lines += st.bad_lines;
        stats.unknown_schema += st.unknown_schema;
        batch.clear();
    }
    loop {
        let over = read_line_capped(&mut r, &mut line, MAX_INPUT_LINE)
            .with_context(|| format!("reading {what}"))?;
        match over {
            None => break,
            Some(true) => {
                stats.bad_lines += 1;
                continue;
            }
            Some(false) => {}
        }
        let Ok(s) = std::str::from_utf8(&line) else {
            stats.bad_lines += 1;
            continue;
        };
        batch.push_str(s);
        batch.push('\n');
        if batch.len() >= PARSE_BATCH_BYTES {
            flush(&mut batch, &mut records, &mut stats);
        }
    }
    flush(&mut batch, &mut records, &mut stats);
    Ok((records, stats))
}

/// [`stream_records`] over a pure-consumer command's `--from`/stdin input, plus the label of
/// where it came from (so a message about the input can NAME it).
fn read_consumer_records(
    from: Option<&std::path::Path>,
    cmd: &str,
    live_hint: bool,
) -> anyhow::Result<(Vec<s3tap_doctor::Record>, s3tap_doctor::ParseStats, String)> {
    let (reader, what) = open_consumer_input(from, cmd, live_hint)?;
    let (records, stats) = stream_records(reader, &what)?;
    Ok((records, stats, what))
}

/// The message for an input that yielded NO `s3tap.*` records, naming what was actually read.
/// Pure, so the wording is pinned by a test rather than by running the binary.
///
/// This is the difference between "you gave me the wrong file" and a health verdict. Without
/// it `doctor --from findings.jsonl` (or an empty/truncated file, or any non-JSONL log)
/// rendered the whole table with every row n/a and reported NO BASELINE plus capture-tuning
/// advice, so the operator re-captured forever against a file that was never a capture. Worse,
/// `advise --strict --from <empty>` printed "no advisories" and exited 0, so the CI gate had
/// been dead for as long as the path was broken. Named counts do the diagnosing: a findings
/// file lands entirely in `unknown_schema`, a truncated or non-JSONL file in `bad_lines`, and
/// an empty file in neither.
fn no_records_message(cmd: &str, what: &str, stats: s3tap_doctor::ParseStats) -> String {
    let seen = match (stats.bad_lines, stats.unknown_schema) {
        (0, 0) => "it held no lines at all".to_string(),
        (bad, 0) => format!("{bad} line(s) were not usable records"),
        (0, unknown) => {
            format!("{unknown} line(s) carried a schema tag this command does not read")
        }
        (bad, unknown) => format!(
            "{bad} line(s) were not usable records and {unknown} carried a schema tag this \
             command does not read"
        ),
    };
    format!(
        "s3tap {cmd}: no s3tap records in {what} ({seen}). This reads a CAPTURE: \
         `s3tap.connection/2` + `s3tap.operation/1` JSONL, as written by `s3tap --format jsonl` \
         or `s3tap doctor --live --save FILE`. A `doctor --json` findings file is not a capture, \
         nor is an empty or truncated one. Nothing was judged, so there is no verdict to report."
    )
}

/// Bail (exit [`EXIT_TOOL_FAILURE`], distinct from every verdict code) when a pure consumer's
/// input parsed to zero records. `analyze` has always had this guard; doctor, advise and
/// scorecard reported the empty set as a verdict instead. See [`no_records_message`].
fn require_records(
    records: &[s3tap_doctor::Record],
    stats: s3tap_doctor::ParseStats,
    cmd: &str,
    what: &str,
) -> anyhow::Result<()> {
    if records.is_empty() {
        anyhow::bail!(no_records_message(cmd, what, stats));
    }
    Ok(())
}

/// The `analyze` twin of [`stream_records`]: stream the input through a per-line `parse`
/// (the shared multi-format `load_trace`), stopping the moment the parsed trace reaches
/// `hard` items. `parse` returns the items a chunk yielded plus its skipped-line count, and
/// must judge each line independently — as `load_trace` does — for batching to be
/// accounting-identical to one call over the whole text. Lines after the stop are neither
/// parsed nor counted as skipped, again matching `load_trace`.
///
/// This is what makes `analyze --from 40GB-trace.log --max-events 1000` a thousand-event
/// parse instead of a 40 GB allocation, which is the entire point of that flag. Generic
/// over the item so the CLI needn't name the replay crate's event type (and so the bound
/// can be unit-tested with a trivial parser).
fn stream_bounded<R: std::io::BufRead, T, C>(
    mut r: R,
    what: &str,
    hard: usize,
    parse: impl Fn(&str) -> (Vec<T>, C),
) -> anyhow::Result<(Vec<T>, C)>
where
    // Generic over the COUNT so a caller can carry more than a total. `analyze` needs to
    // tell "this file is not a trace" from "this file is a capture in which nothing was a
    // demand read", which are the same number but opposite diagnoses.
    C: Default + std::ops::AddAssign<C> + From<usize>,
{
    let mut items: Vec<T> = Vec::new();
    let mut skipped = C::default();
    let mut batch = String::new();
    let mut batch_lines = 0usize;
    let mut line = Vec::new();
    loop {
        // Checked post-flush, so the stop lands exactly where `load_trace`'s own would.
        if items.len() >= hard {
            break;
        }
        let read = read_line_capped(&mut r, &mut line, MAX_INPUT_LINE)
            .with_context(|| format!("reading {what}"))?;
        match read {
            None => break,
            Some(true) => {
                skipped += C::from(1);
                continue;
            }
            Some(false) => {}
        }
        let Ok(s) = std::str::from_utf8(&line) else {
            skipped += C::from(1);
            continue;
        };
        batch.push_str(s);
        batch.push('\n');
        batch_lines += 1;
        // A line yields at most ONE item, so capping the batch at the remaining budget
        // means a batch can never overshoot `hard` — the truncation point is exact.
        if batch_lines >= hard - items.len() || batch.len() >= PARSE_BATCH_BYTES {
            let (parsed, sk) = parse(&batch);
            items.extend(parsed);
            skipped += sk;
            batch.clear();
            batch_lines = 0;
        }
    }
    if !batch.is_empty() {
        let (parsed, sk) = parse(&batch);
        items.extend(parsed);
        skipped += sk;
    }
    Ok((items, skipped))
}

// `advise` consumer: read records, run the advisory checks, print. Mirrors the
// doctor's contract (--from/stdin, --json NDJSON, ParseStats surfaced, exit code
// returned so `main` owns the single process::exit).
fn advise_cmd(args: &AdviseArgs) -> anyhow::Result<i32> {
    let (records, stats, what) = read_consumer_records(args.from.as_deref(), "advise", false)?;
    require_records(&records, stats, "advise", &what)?;
    let findings = s3tap_advisor::advise(&records);
    // The S3 population, before any check's own gates: what tells a connection-only capture
    // and an all-aborted one apart from a genuinely clean run, all three of which leave
    // `findings` empty. See `s3tap_advisor::OpPopulation`.
    let pop = s3tap_advisor::op_population(&records);
    if args.json {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        // The run row goes LAST, where doctor puts its own roll-up, and says one thing: the S3
        // population was missing. It is NOT keyed on the exit code. Keying it there made
        // `--strict` change the set of records written — a connection-sourced advisory on a
        // capture with no operations exits 1 under `--strict`, which dropped the row — and
        // `--strict` is an exit-code gate, not an output filter. A fleet ingest that adds it
        // for gating must not silently lose records.
        //
        // So the row can sit beside an exit 1. That is correct and not a contradiction: the
        // advisory was judged (from the connection records) AND the S3 population was missing.
        // Both facts are true, and the row is the only place the second one is said.
        let run = s3tap_advisor::unjudged_run_finding(&records);
        for f in findings.iter().chain(run.iter()) {
            if let Err(e) = writeln!(out, "{}", serde_json::to_string(f)?) {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return Ok(0); // closed reader: clean stop
                }
                return Err(e.into());
            }
        }
    } else {
        // print! PANICS on a write error; a closed pipe (`advise | head`) must be
        // a clean stop instead — mirror doctor's write_all + BrokenPipe mapping.
        use std::io::Write;
        // Honor `--no-color` AND auto-off on a non-tty, matching the `no_color` help text and
        // the scorecard/analyze/doctor siblings (avoids ANSI codes leaking into a pipe/file).
        let color = want_color(args.no_color, std::io::stdout().is_terminal());
        let rendered = s3tap_advisor::render(&findings, pop, color);
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        if let Err(e) = out.write_all(rendered.as_bytes()).and_then(|()| out.flush()) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(0);
            }
            return Err(e.into());
        }
    }
    if stats.bad_lines > 0 || stats.unknown_schema > 0 {
        enote!(
            "note: skipped {} unparseable + {} unknown-schema line(s)",
            stats.bad_lines, stats.unknown_schema
        );
    }
    Ok(s3tap_advisor::advisory_exit(&findings, pop, args.strict))
}

// The `scorecard` consumer: read records, roll them up per (bucket, s3_op), print the
// descriptive percentile table (or the scorecard/1 rows + gated finding/1 under --json).
// Mirrors advise_cmd's contract (--from/stdin, ParseStats surfaced, BrokenPipe = clean stop).
fn scorecard_cmd(args: &ScorecardArgs) -> anyhow::Result<i32> {
    let (records, stats, what) = read_consumer_records(args.from.as_deref(), "scorecard", false)?;
    require_records(&records, stats, "scorecard", &what)?;
    let sc = s3tap_doctor::scorecard::scorecard(&records);
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let write_res = if args.json {
        // Descriptive rows first (the telemetry), then the judged findings (the gate feed).
        (|| -> std::io::Result<()> {
            for r in &sc.rows {
                writeln!(out, "{}", serde_json::to_string(r).expect("scorecard row serializes"))?;
            }
            for f in &sc.findings {
                writeln!(out, "{}", serde_json::to_string(f).expect("finding serializes"))?;
            }
            // Present only when nothing was scoreable, which is precisely when the two loops
            // above wrote nothing at all. Without it the stream was empty and the exit code
            // was the only signal.
            if let Some(run) = s3tap_doctor::scorecard::unjudged_run_finding(&sc) {
                writeln!(out, "{}", serde_json::to_string(&run).expect("finding serializes"))?;
            }
            Ok(())
        })()
    } else {
        let color = want_color(args.no_color, std::io::stdout().is_terminal());
        let rendered = s3tap_doctor::scorecard::render(&sc, color);
        out.write_all(rendered.as_bytes()).and_then(|()| out.flush())
    };
    if let Err(e) = write_res {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(0); // closed reader (`scorecard | head`): clean stop
        }
        return Err(e.into());
    }
    if stats.bad_lines > 0 || stats.unknown_schema > 0 {
        enote!(
            "note: skipped {} unparseable + {} unknown-schema line(s)",
            stats.bad_lines, stats.unknown_schema
        );
    }
    Ok(s3tap_doctor::scorecard::scorecard_exit(&sc, args.strict))
}

// `analyze` consumer: read a trace (any of the three formats), run the deep caching +
// prefetch study on it, and print the report (or JSON). A pure consumer like `advise`,
// but it drives the FULL replay ladder rather than the advisor's cheap path.
fn analyze_cmd(args: &AnalyzeArgs) -> anyhow::Result<i32> {
    use s3tap_advisor::analyze::{self, AnalyzeOpts};
    use std::io::{IsTerminal, Write};

    let max_events = args.max_events.unwrap_or(analyze::DEFAULT_MAX_EVENTS);
    let (reader, what) = open_consumer_input(args.from.as_deref(), "analyze", false)?;
    // One shared multi-format loader: s3tap JSONL / NormEvent JSON / IBM COS lines, fed a
    // batch at a time off the stream. `max_events` bounds the parse itself, so a huge file
    // is never materialized (nor millions of events we'd only sample away) — reading one
    // PAST the cap, as `load_trace` does, so the sampler still detects truncation.
    let hard = if max_events == 0 { usize::MAX } else { max_events.saturating_add(1) };
    let (trace, counts) =
        stream_bounded(reader, &what, hard, |batch| analyze::load_trace_counted(batch, 0))?;
    if trace.is_empty() {
        // Distinguish "this is not a trace" from "this IS a capture, and nothing in it was a
        // demand read a cache could serve". Naming the accepted formats at a well-formed
        // 6300-record capture of nothing but 503s told the operator their valid file was junk,
        // while `doctor` on the same file reported 6300 operations and a 100% error rate.
        // A capture s3tap READ but could draw no demand read from is exit 2 (nothing
        // judgeable), NOT exit 4 (tool failure). README states one shared mapping across every
        // command, where 4 means "could not be read, or parsed to zero `s3tap.*` records" —
        // and `doctor`, `advise` and `scorecard` all answer 2 for these same files. Bailing
        // here made `analyze` the one command that disagreed, so a script branching on 4 was
        // told to fix an invocation that was correct.
        let dropped = counts.operations_dropped;
        let others = counts.other_records;
        if dropped > 0 || others > 0 {
            let junk = counts.skipped.saturating_sub(dropped + others);
            let mut parts = Vec::new();
            if dropped > 0 {
                parts.push(format!("{dropped} s3tap operation record(s)"));
            }
            if others > 0 {
                parts.push(format!("{others} other s3tap record(s) (connections/samples)"));
            }
            if junk > 0 {
                parts.push(format!("{junk} unreadable line(s)"));
            }
            enote!(
                "s3tap: read {} — none of them a demand read a cache could serve. A GET \
                 counts only when the origin served a whole body, so 4xx/5xx, 206 (ranged) \
                 and 304 Not Modified are excluded, as are records with no object key or no \
                 timestamp, and connection records carry no read at all. Nothing to judge, so \
                 this exits {EXIT_NOTHING_JUDGEABLE} rather than 0. Run `s3tap doctor` on \
                 this file to see what it does contain.",
                parts.join(", ")
            );
            return Ok(EXIT_NOTHING_JUDGEABLE);
        }
        // Genuinely not a capture: nothing in the file parsed to an `s3tap.*` record.
        anyhow::bail!(
            "no usable trace events in the input ({} line(s) skipped). Expected s3tap \
             JSONL records, NormEvent JSON, or IBM COS lines.",
            counts.skipped
        );
    }

    let opts = AnalyzeOpts {
        block_bytes: if args.object { None } else { Some(analyze::DEFAULT_BLOCK) },
        max_events,
        fast: args.fast,
        deep: args.deep,
    };
    let report = s3tap_advisor::analyze_trace(&trace, &opts);

    // Compute color BEFORE locking stdout (don't re-fetch the handle mid-render).
    let color = want_color(args.no_color, std::io::stdout().is_terminal());
    let rendered = if args.json {
        format!("{}\n", serde_json::to_string(&report)?)
    } else {
        s3tap_advisor::analyze::render(&report, color)
    };
    // Closed-pipe (`analyze | head`) is a clean stop, not a panic — mirror advise/doctor.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = out.write_all(rendered.as_bytes()).and_then(|()| out.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(0);
        }
        return Err(e.into());
    }
    if counts.skipped > 0 {
        // Split the reasons. Lumping them made the note call a valid `s3tap.connection/2`
        // record "unparseable", which is the same misdirection the zero-event branch above
        // was rewritten to stop — a reader cannot act on a count that mixes junk with records
        // this command simply has no use for.
        let junk = counts.skipped.saturating_sub(counts.operations_dropped + counts.other_records);
        let mut why = Vec::new();
        if counts.operations_dropped > 0 {
            why.push(format!("{} not a demand read", counts.operations_dropped));
        }
        if counts.other_records > 0 {
            why.push(format!("{} other s3tap record(s)", counts.other_records));
        }
        if junk > 0 {
            why.push(format!("{junk} unreadable"));
        }
        enote!("note: skipped {} line(s): {}", counts.skipped, why.join(", "));
    }
    Ok(0)
}

// Returns the process exit code (the actual `process::exit` is confined to `main`, so the
// code mapping stays testable).
async fn doctor_cmd(args: &DoctorArgs) -> anyhow::Result<i32> {
    if args.live {
        return doctor_live(args).await;
    }
    let (records, stats, what) = read_consumer_records(args.from.as_deref(), "doctor", true)?;
    require_records(&records, stats, "doctor", &what)?;
    let report = s3tap_doctor::analyze_with(&records, stats);
    let code = report_and_code(&report, &records, args)?;
    if stats.bad_lines > 0 || stats.unknown_schema > 0 {
        enote!(
            "note: skipped {} unparseable + {} unknown-schema line(s)",
            stats.bad_lines, stats.unknown_schema
        );
    }
    Ok(code)
}

/// Regions `s3tap check` (no target) probes. Each is hit at its PERMANENT S3 service endpoint
/// (`s3.<region>.amazonaws.com`) — a 403 is expected (no bucket, no creds); we read the TCP
/// round-trip FLOOR, not the HTTP status. So there is no public object to rot, and only the base
/// caps are needed (the floor is connection-level srtt; no SSL uprobes). A curated global spread
/// (5 continents) so "nearest" is meaningful without probing all ~30 regions; each is probed
/// SEQUENTIALLY, so more regions = more wall-clock (~2–3 s each — see the `--triage` help). Edit
/// to add/trim; all must be long-standing regions (no new-region opt-in redirect quirk).
const REGIONAL_PROBES: &[&str] = &[
    "us-east-1",      // N. Virginia
    "us-west-2",      // Oregon
    "eu-west-1",      // Ireland
    "eu-central-1",   // Frankfurt
    "ap-southeast-1", // Singapore
    "ap-northeast-1", // Tokyo
    "ap-south-1",     // Mumbai
    "sa-east-1",      // São Paulo
];

/// Human city label for a region code, for the `check` map's `location` column. A region
/// without a mapping falls back to its own code (never blank), so adding a probe never panics.
fn region_city(code: &str) -> &str {
    match code {
        "us-east-1" => "N. Virginia",
        "us-west-2" => "Oregon",
        "eu-west-1" => "Ireland",
        "eu-central-1" => "Frankfurt",
        "ap-southeast-1" => "Singapore",
        "ap-northeast-1" => "Tokyo",
        "ap-south-1" => "Mumbai",
        "sa-east-1" => "São Paulo",
        other => other,
    }
}

/// Coarse distance class for a round-trip floor, for the `location` cell's `· ~band` suffix.
/// APPROXIMATE (hence the `~`) and REACH-based, not geographic: RTT can't tell a US coast-to-
/// coast hop (~70 ms) from a trans-Atlantic one (~78 ms), so the labels describe distance-of-
/// path, never "same continent". Thresholds are round-trip ms: sub-5 ≈ same region, sub-40 ≈
/// regional (adjacent metros/countries), sub-100 ≈ a long-haul hop, beyond ≈ the far side.
fn region_band(rtt_ms: f64) -> &'static str {
    match rtt_ms {
        x if x < 5.0 => "~in-region",
        x if x < 40.0 => "~regional",
        x if x < 100.0 => "~long-haul",
        _ => "~global",
    }
}

/// Small, long-standing PUBLIC objects (AWS Open Data) the no-target `check` GETs to add a
/// real L7 waterfall on top of the regional floor map. Each entry was GET-verified anonymously
/// (2026-07-16); all are multi-year-stable datasets, chosen tiny (3–30 KB) so the default check
/// stays fast. The floor sweep stays the primary mechanism — permanent service endpoints,
/// nothing to rot (see REGIONAL_PROBES) — and a rotted entry is caught by a preflight and
/// degrades to a note + the map, never a false verdict. Regions here must be a subset of
/// REGIONAL_PROBES (unit-enforced) so every entry always has a comparable floor.
const PUBLIC_PROBE_OBJECTS: &[(&str, &str)] = &[
    ("us-east-1", "https://noaa-ghcn-pds.s3.us-east-1.amazonaws.com/readme.txt"),
    (
        "us-west-2",
        "https://usgs-lidar-public.s3.us-west-2.amazonaws.com/AK_BrooksCamp_2012/boundary.json",
    ),
    ("eu-central-1", "https://esa-worldcover.s3.eu-central-1.amazonaws.com/readme.html"),
];

/// Choose the no-target check's public-object probe: the COVERED region (one with a
/// PUBLIC_PROBE_OBJECTS entry) with the lowest measured floor. An uncovered region may be
/// genuinely nearer — the caller names the chosen region so that's never implied. None when
/// no covered region measured a floor (nothing worth GETting blind).
fn pick_public_probe(rows: &[(&str, ProbeOutcome)]) -> Option<(&'static str, &'static str)> {
    rows.iter()
        .filter_map(|(region, outcome)| match outcome {
            ProbeOutcome::Floor(ms, _) => PUBLIC_PROBE_OBJECTS
                .iter()
                .find(|(r, _)| r == region)
                .map(|(r, url)| (*r, *url, *ms)),
            _ => None,
        })
        .min_by(|a, b| a.2.partial_cmp(&b.2).expect("finite floors"))
        .map(|(r, url, _)| (r, url))
}

/// Did our curated public probe object ROT (deleted, or its permissions changed) rather than
/// the user's path being unhealthy? True when the L7 decode worked — we have operation records
/// — but EVERY one returned a status that specifically means "this object isn't anonymously
/// GETtable": 403 (access denied / bucket policy changed) or 404 (deleted/moved). That is a
/// fact about our hardcoded URL, so the caller prints a "report it" note rather than a verdict.
///
/// Deliberately NARROW: other 4xx are NOT rot and must not be swallowed —
/// 407 (proxy auth) and 451 mean a captive portal / corporate proxy sits in the path,
/// 429 means throttling; those are real conditions of the USER's network, and reporting them
/// as "s3tap's bug, exit 0" would both misdiagnose and mask a failure. 5xx is a real S3 problem
/// the doctor verdicts on. "No ops at all" (uprobe caps absent) is handled by the doctor's own
/// floor-only messaging, not here. Pure — unit-tested.
fn probe_object_rotted(records: &[s3tap_doctor::Record]) -> bool {
    let mut ops = records.iter().filter_map(|r| match r {
        s3tap_doctor::Record::Operation(o) => Some(o),
        _ => None,
    });
    let mut any = false;
    let all_rot = ops.all(|o| {
        any = true;
        matches!(o.http_status, Some(403) | Some(404))
    });
    any && all_rot
}

/// Build a `doctor --live` arg set with easy-mode defaults, shared by both `check` paths.
fn live_doctor_args(
    endpoint: Vec<String>,
    brief: bool,
    requests: u32,
    timeout_secs: u64,
    auth: bool,
    region: Option<String>,
) -> DoctorArgs {
    DoctorArgs {
        from: None,
        no_color: false,
        json: false,
        baseline: None,
        strict: false,
        cost: false,
        brief,
        live: true,
        endpoint,
        rotate: false,
        requests,
        timeout_secs,
        save: None,
        auth,
        region,
        s3_endpoint: Vec::new(),
        concurrency: 1,
    }
}

/// The `check` easy front-end. With a target: normalize it to a URL and run it through the
/// `doctor --live` machinery with brief output. Without one: run the built-in regional probes.
async fn check_cmd(args: &CheckArgs) -> anyhow::Result<i32> {
    let Some(t) = &args.target else {
        // No target: the regional map, then (unless --map-only) a real health
        // check against a public test object in the nearest covered region.
        //
        // The signal streams are installed HERE, before the first of the nine captures this
        // command runs, and handed down. A stream installed later covers only its own await,
        // which is how a Ctrl-C came to end one region and let the sweep carry on (see
        // SignalStop). They are installed nowhere else in `check`: a stream that exists but
        // that nothing polls is worse than none at all, since creating it also takes the
        // signal away from the kernel's default disposition.
        let mut signals = SignalStop::install()?;
        return check_regional(args, &mut signals).await;
    };
    let url = normalize_check_target(t, args.region.as_deref())?;
    let dargs =
        live_doctor_args(vec![url], !args.verbose, args.requests, 15, args.auth, args.region.clone());
    if !args.triage {
        // ONE capture, which catches both signals itself and reports what it holds. Nothing
        // follows it, so there is nothing for a second listener here to stop.
        return doctor_cmd(&dargs).await;
    }
    // --triage: run the health probe (render it + keep the Report for the bucket's own floor),
    // then sweep the regions and print the avoidable-latency comparison. The health verdict/exit
    // code is unchanged — triage is additive advice.
    //
    // Two captures in sequence, so the streams go in before the first one. A Ctrl-C during the
    // probe ends that capture (the capture's own listeners) AND is latched here, so the sweep
    // below stops immediately instead of starting eight more captures the operator just asked
    // to stop.
    let mut signals = SignalStop::install()?;
    let opt = probe_report(&dargs, true).await?;
    let bucket_ms = opt.as_ref().and_then(|(r, _)| r.baseline_rtt_us).map(|us| us as f64 / 1000.0);
    let code = report_or_diagnostic(opt, &dargs)?;
    match bucket_ms {
        None => enote!(
            "s3tap check --triage: no round-trip floor from the bucket probe — nothing to compare."
        ),
        Some(bucket_ms) => {
            enote!(
                "s3tap check --triage: sweeping {} region(s) ({}) to compare…",
                REGIONAL_PROBES.len(),
                REGIONAL_PROBES.join(", ")
            );
            // A sweep failure (systemic, e.g. missing curl) shouldn't fail the health check we
            // already rendered — note it and keep the health exit code. A SIGNAL is not that:
            // the operator asked the command to stop, so carrying on to print an advisory block
            // would be ignoring the ask.
            match probe_regions(true, &mut signals).await {
                // The health verdict above is already printed and is a real verdict, so it
                // stands: only the additive advice is skipped.
                Err(e) if e.downcast_ref::<Interrupted>().is_some() => {
                    enote!("{e} The health check above still stands.");
                    return Ok(code);
                }
                Err(e) => enote!("s3tap check --triage: region sweep failed ({e:#})"),
                // Disambiguate render_triage's two None reasons (it can't): if NO region yielded a
                // floor there was nothing to compare — don't claim "near-optimal".
                Ok(regions) if !regions.iter().any(|(_, o)| matches!(o, ProbeOutcome::Floor(..))) => {
                    enote!(
                        "s3tap check --triage: no region floor was measured to compare against \
                         (the sweep captured no round-trip) — re-run."
                    );
                }
                Ok(regions) => match render_triage(bucket_ms, &regions) {
                    Some(block) => {
                        use std::io::Write;
                        let mut out = std::io::stdout().lock();
                        if let Err(e) = out.write_all(block.as_bytes()).and_then(|()| out.flush()) {
                            if e.kind() != std::io::ErrorKind::BrokenPipe {
                                return Err(e.into());
                            }
                        }
                    }
                    None => enote!(
                        "s3tap check --triage: your bucket is already about as near as any of the \
                         {} probed regions — no meaningful avoidable latency.",
                        REGIONAL_PROBES.len()
                    ),
                },
            }
        }
    }
    Ok(code)
}

/// One region's probe outcome. Distinguishing these is the honest taxonomy: a `Floor` is a
/// real measurement; `NotMeasured` means we captured the connection but no close-time srtt
/// landed in the window (reachable, just no floor); `CaptureFailed` means the local eBPF
/// capture itself failed (caps/setup) — a LOCAL problem, not S3 being down.
///
/// `Floor(ms, jitter_ms)`: the round-trip floor and, when the extended tcp_sock fields landed,
/// the connection's RTT variation (`rttvar`/mdev) — a stability signal. `jitter_ms` is `None`
/// when those fields aren't present (older kernel/BTF), so stability degrades to "not shown".
#[derive(Clone, Copy, PartialEq)]
enum ProbeOutcome {
    Floor(f64, Option<f64>),
    NotMeasured,
    CaptureFailed,
}

/// Median RTT variation (`rttvar`/mdev, ms) across the capture's connections — the per-region
/// jitter/stability signal. `None` when no connection carried the extended field (0 = "unknown").
fn median_rttvar_ms(records: &[s3tap_doctor::Record]) -> Option<f64> {
    let mut v: Vec<u32> = records
        .iter()
        .filter_map(|r| match r {
            s3tap_doctor::Record::Connection(c) => c.rttvar_us.filter(|&x| x != 0),
            _ => None,
        })
        .collect();
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let mid = v.len() / 2;
    let m = if v.len() % 2 == 1 {
        f64::from(v[mid])
    } else {
        (f64::from(v[mid - 1]) + f64::from(v[mid])) / 2.0
    };
    Some(m / 1000.0)
}

/// A catchable signal ended the command before it reached a verdict. Typed rather than a bare
/// message for two reasons: `main` prints it as the ordinary stop it is instead of as a
/// failure, and a caller that treats other errors as "that step failed, carry on" (`--triage`
/// does, so a missing curl cannot fail a health check it already rendered) can tell this one
/// apart and stop. The exit code is the reserved tool-failure 4, which is the honest reading:
/// s3tap never got as far as a verdict.
#[derive(Debug)]
struct Interrupted(&'static str);

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s3tap: {} received. Stopping before a verdict.", self.0)
    }
}

impl std::error::Error for Interrupted {}

/// Persistent SIGINT/SIGTERM streams, created ONCE before a sequence of captures and selected
/// against every step of it.
///
/// Creating a tokio signal stream replaces the process's DEFAULT disposition for that signal,
/// permanently and process-wide (tokio never unregisters its libc handler). So the first
/// capture that installs one takes Ctrl-C away from the kernel for the rest of the run, and any
/// listener created later covers only its own await: a `check` sweep whose per-region capture
/// installed the handlers ended that one capture on Ctrl-C and calmly moved to the next region,
/// while a Ctrl-C in the gap between regions reached no listener at all and was discarded. The
/// command was killable only by SIGKILL. Owning the streams ABOVE the loop is what makes one
/// Ctrl-C end the whole sequence.
struct SignalStop {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

impl SignalStop {
    fn install() -> anyhow::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            sigint: signal(SignalKind::interrupt()).context("hook SIGINT")?,
            sigterm: signal(SignalKind::terminate()).context("hook SIGTERM")?,
        })
    }

    /// Resolves when either arrives, naming it for the message. Cancel-safe (both arms are),
    /// so it can be an arm of a `select!` that loses the race and is polled again next round.
    async fn hit(&mut self) -> &'static str {
        tokio::select! {
            _ = self.sigint.recv() => "Ctrl-C",
            _ = self.sigterm.recv() => "SIGTERM",
        }
    }

    /// Has one already landed? For the seams where there is no `select!` to lose: synchronous
    /// setup work between two captures.
    ///
    /// MUST be async, racing `hit()` against a short timer rather than a bare synchronous
    /// `poll_recv`. The OS signal handler only sets an internal pending flag; it takes tokio's
    /// own signal driver actually being POLLED (which happens when the runtime's reactor parks)
    /// to turn that into something `poll_recv` reports as ready. A one-shot `poll_recv` called
    /// synchronously right after a signal lands — with nothing before it that yields to the
    /// runtime — can run in the gap before the driver ever gets scheduled and see nothing, even
    /// though the signal genuinely already arrived. A zero-duration/already-ready alternative
    /// in the `select!` has the same problem (it can resolve without the runtime ever parking);
    /// a real, nonzero sleep forces `park_timeout`, which is what lets the driver observe the
    /// already-queued self-pipe byte and wake `hit()` before the timer would otherwise fire.
    async fn tripped(&mut self) -> Option<&'static str> {
        tokio::select! {
            sig = self.hit() => Some(sig),
            () = tokio::time::sleep(std::time::Duration::from_millis(1)) => None,
        }
    }
}

/// Probe each region's S3 endpoint and return its round-trip outcome. Shared by the regional
/// `check` and the `--triage` comparison. Each probe reads the connection-level srtt FLOOR (a
/// 403 is expected — status-independent), so it needs only the base caps.
///
/// `signals` is the CALLER's signal pair, deliberately: see [`SignalStop`] for why a per-probe
/// listener cannot end a sweep.
async fn probe_regions(
    progress: bool,
    signals: &mut SignalStop,
) -> anyhow::Result<Vec<(&'static str, ProbeOutcome)>> {
    use std::io::IsTerminal;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    // The sweep is sequential (~2–3 s/region), so without feedback the caller sits silent for
    // ~20 s. Show an animated bar naming the region in flight — but only on a stderr TTY, so a
    // redirect/pipe (or a captured log) never accretes carriage-return spew.
    let live = progress && std::io::stderr().is_terminal();
    let color = std::env::var_os("NO_COLOR").is_none();
    let total = REGIONAL_PROBES.len();

    // Animate on a DEDICATED OS thread rather than on the async runtime: each probe's per-region
    // setup (eBPF load/attach) is SYNCHRONOUS CPU work that doesn't yield, which would freeze a
    // cooperative on-runtime spinner right at every increment. An OS thread is preemptively
    // scheduled, so it keeps redrawing smoothly regardless of what the runtime thread is doing.
    // `cur` = the in-flight region index (== regions completed); the thread reads it each frame.
    let cur = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    // Backstop for an abnormal exit: if a probe panics and unwinds this function before the
    // explicit teardown, this guard's Drop flips `stop` so the (now-detached) render thread stops
    // drawing on its next tick instead of scribbling over the unwind. Normal exit still does the
    // explicit stop+join+erase below (this then no-ops).
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let _stop_guard = live.then(|| StopOnDrop(Arc::clone(&stop)));
    let ticker = live.then(|| {
        let (cur, stop) = (Arc::clone(&cur), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut frame = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let done = cur.load(Ordering::Relaxed);
                if let Some(region) = REGIONAL_PROBES.get(done) {
                    draw_sweep_progress(done, total, region, frame, color);
                }
                frame += 1;
                std::thread::sleep(std::time::Duration::from_millis(90));
            }
        })
    });

    // No `?` inside the loop: capture any error and fall through to the guaranteed teardown so the
    // ticker is always stopped/joined and the line erased — on both the success and error paths.
    let mut rows: Vec<(&'static str, ProbeOutcome)> = Vec::new();
    let mut sweep_err = None;
    for (i, region) in REGIONAL_PROBES.iter().enumerate() {
        cur.store(i, Ordering::Relaxed);
        let url = format!("https://s3.{region}.amazonaws.com/");
        // Few requests, short budget — a quick position read, not a tail measure. announce=false:
        // the caller prints its own output, not the per-region live banners.
        let dargs = live_doctor_args(vec![url], true, 4, 8, false, None);
        // One signal ends the SWEEP, not just the region in flight. Racing the probe against the
        // caller's streams is what makes that true: the losing arm is dropped, which cancels the
        // probe through the same Drops a completed one runs. A signal arriving in the SEAM
        // between two regions is caught too, because these streams (unlike a per-probe listener)
        // exist for the whole sweep, so the notification is latched and this select finds the
        // arm already ready.
        let outcome = tokio::select! {
            r = probe_report(&dargs, false) => r,
            sig = signals.hit() => {
                sweep_err = Some(anyhow::Error::new(Interrupted(sig)));
                break;
            }
        };
        match outcome {
            Ok(Some((report, records))) => {
                let outcome = match report.baseline_rtt_us {
                    // Floor from the report; jitter (rttvar) from the same capture's connections.
                    Some(us) => ProbeOutcome::Floor(us as f64 / 1000.0, median_rttvar_ms(&records)),
                    None => ProbeOutcome::NotMeasured,
                };
                rows.push((region, outcome));
            }
            Ok(None) => rows.push((region, ProbeOutcome::CaptureFailed)),
            Err(e) => {
                sweep_err = Some(e);
                break;
            }
        }
    }

    // Stop + join the render thread (so no frame lands after this), THEN erase the line clean.
    if let Some(t) = ticker {
        stop.store(true, Ordering::Relaxed);
        let _ = t.join();
        enote_raw!("\r{:60}\r", ""); // widest drawn line is ~54 cols (see draw_sweep_progress)
    }
    match sweep_err {
        Some(e) => Err(e),
        None => Ok(rows),
    }
}

/// The sub-cell block bar for the sweep progress: `done`/`total` filled across `width` cells,
/// with a 1/8th-cell partial head (like cargo/pip) for a smooth fill. Pure and exactly `width`
/// CHARS wide. That equals `width` display columns on any normal terminal — the block glyphs are
/// East-Asian-Width *Ambiguous*, i.e. 1 column unless the terminal is a CJK locale rendering
/// ambiguous-as-wide (2 cols), the one regime where the fixed erase could leave a tail.
fn sweep_bar(done: usize, total: usize, width: usize) -> String {
    const EIGHTHS: [&str; 8] = ["░", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    let units = (done * width * 8 / total.max(1)).min(width * 8); // eighths filled, clamped
    let full = units / 8;
    let rem = units % 8;
    let mut bar = String::new();
    for _ in 0..full.min(width) {
        bar.push('█');
    }
    if full < width {
        bar.push_str(EIGHTHS[rem]); // partial head (░ when rem == 0)
        for _ in 0..(width - full - 1) {
            bar.push('░');
        }
    }
    bar
}

/// Draw one frame of the region-sweep progress bar in place on stderr: a braille spinner, the
/// block bar, `done/total`, and the region in flight (padded to the widest region so a shorter
/// name never leaves a tail). Cyan when `color`. Ephemeral status — never captured (the caller
/// gates on a stderr TTY and erases it before the table).
fn draw_sweep_progress(done: usize, total: usize, region: &str, frame: usize, color: bool) {
    const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let spin = SPIN[frame % SPIN.len()];
    let bar = sweep_bar(done, total, 18);
    let paint = |s: &str| if color { format!("\x1b[36m{s}\x1b[0m") } else { s.to_string() };
    // `{region:<14}`: 14 = the longest REGIONAL_PROBES code (`ap-southeast-1`), so every frame is a
    // constant width and a shorter name never leaves a tail from a longer previous frame.
    enote_raw!("\r  {} probing  [{}]  {done}/{total}  {region:<14}", paint(spin), paint(&bar));
}

/// `s3tap check` with no target: probe each region's S3 endpoint and print where this host sits
/// relative to S3 (lowest round-trip = nearest). Then — unless `--map-only` — GET a small PUBLIC
/// object in the nearest COVERED region so the bare `s3tap check` ends in a real health verdict
/// (a full DNS→connect→TTFB waterfall), not just a latency map. The map itself is a position
/// read, never a verdict on any bucket.
async fn check_regional(args: &CheckArgs, signals: &mut SignalStop) -> anyhow::Result<i32> {
    enote!(
        "s3tap check: regional S3 round-trip probe across {} region(s) — a 403 is expected \
         (no bucket/creds); this measures the network path, not access, and is NOT a verdict on \
         any bucket. (Needs the base caps: `sudo s3tap setup`.)",
        REGIONAL_PROBES.len()
    );
    let rows = probe_regions(true, signals).await?;
    // ALL regions failing to capture is a LOCAL problem (connectivity or the base caps), not S3
    // — say so once and exit non-zero, rather than a table implying every region is unreachable.
    if rows.iter().all(|(_, o)| *o == ProbeOutcome::CaptureFailed) {
        enote!(
            "s3tap check: couldn't capture on any region — a local problem (no network route to \
             S3, or the base caps aren't set: `sudo s3tap setup`), not S3 being unreachable."
        );
        return Ok(EXIT_NOTHING_CAPTURED);
    }
    use std::io::{IsTerminal, Write};
    // Color only for an interactive stdout, and honor the NO_COLOR convention (piped/redirected
    // output stays plain, so a saved map has no escape codes).
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let out = render_regional(&rows, color);
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout.write_all(out.as_bytes()).and_then(|()| stdout.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(0);
        }
        return Err(e.into());
    }
    if args.map_only {
        return Ok(0);
    }
    // A signal that landed in THIS seam (the sweep is over, the next capture has not installed
    // its listeners yet) is latched in `signals` and would otherwise reach nobody. Act on it
    // here rather than drive one more capture the operator just asked to stop.
    if let Some(sig) = signals.tripped().await {
        return Err(Interrupted(sig).into());
    }
    // The last capture of the command, and it catches both signals itself: nothing follows it,
    // so there is nothing left to stop and its partial report is worth having.
    check_public_object(&rows, args).await
}

/// The no-target check's second half: a real health check against a small PUBLIC test object
/// (AWS Open Data) in the nearest COVERED region. Returns the health exit code, EXCEPT where
/// the outcome is a fact about our curated URL rather than the user's path (rot, or no covered
/// region measured) — those degrade to a note over the already-printed map (exit 0), never a
/// false verdict.
async fn check_public_object(rows: &[(&str, ProbeOutcome)], args: &CheckArgs) -> anyhow::Result<i32> {
    let Some((region, url)) = pick_public_probe(rows) else {
        enote!(
            "s3tap check: no round-trip floor from a region with a public test object ({}) — \
             skipping the health check; the map above still stands. Point the check at your own \
             object for a verdict:  s3tap check <bucket>/<key>",
            PUBLIC_PROBE_OBJECTS.iter().map(|(r, _)| *r).collect::<Vec<_>>().join(", ")
        );
        return Ok(0);
    };
    // The overall-nearest region (lowest measured floor) may carry no public test object, so
    // the probe can land on a farther but COVERED region. When they differ, name the gap — else
    // the map's "nearest" row and this "nearest region with a public test object" line read as a
    // contradiction.
    let overall_nearest = rows
        .iter()
        .filter_map(|(r, o)| match o {
            ProbeOutcome::Floor(ms, _) => Some((*r, *ms)),
            _ => None,
        })
        .min_by(|a, b| a.1.partial_cmp(&b.1).expect("finite floors"))
        .map(|(r, _)| r);
    let coverage_note = match overall_nearest {
        Some(n) if n != region => format!(" ({n} is nearer but has no catalogued public test object)"),
        _ => String::new(),
    };
    enote!(
        "s3tap check: health-checking {region}, the nearest region with a public test \
         object{coverage_note} — GET {url}\n  (a public AWS Open Data object; this verdict \
         covers THIS host's path to {region}, not any bucket of yours. `--map-only` skips it.)"
    );
    let dargs = live_doctor_args(vec![url.to_string()], !args.verbose, args.requests, 15, false, None);
    let opt = probe_report(&dargs, true).await?;
    // Rot check BEFORE rendering: every request refused means our hardcoded object moved —
    // our bug, not the user's network. Say so plainly and keep the map's clean exit.
    if let Some((_, records)) = &opt {
        if probe_object_rotted(records) {
            enote!(
                "s3tap check: the public test object appears to have moved or changed \
                 permissions (every request was refused) — that's a bug in s3tap's curated \
                 list, NOT a problem with your S3 path. Please report it: \
                 https://github.com/echemythia/s3tap/issues\n  \
                 The regional map above is unaffected. For a verdict on your own traffic: \
                 s3tap check <bucket>/<key>"
            );
            return Ok(0);
        }
    }
    // Pull the measured waterfall (TTFB / reuse / throughput) BEFORE opt is consumed by the
    // verdict render — render_brief collapses to just the headline on a healthy report, so these
    // real numbers would otherwise be discarded unless `--verbose`.
    let waterfall = opt.as_ref().and_then(|(r, _)| check_waterfall(r));
    // A section header on stdout so the health verdict sits in its own titled block, aligned with
    // the map/position sections above.
    {
        use std::io::{IsTerminal, Write};
        let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        let _ = writeln!(std::io::stdout(), "\n{}", section_rule(&format!("health check · {region}"), color));
    }
    // Exit-code contract: bare `s3tap check` historically exited {0, 3} — the
    // regional map (already printed) is the deliverable, and this public-object
    // health check is an additive BONUS. So render its verdict for the human but
    // keep the informational exit: a capture failure is still 3 (a local
    // problem), but an Attention/NoBaseline on OUR test object must NOT newly
    // fail a base-caps CI job that runs `s3tap check` for the map. A strict,
    // scriptable verdict is what `s3tap check <bucket>/<key>` is for (see its help).
    let code = report_or_diagnostic(opt, &dargs)?;
    if code != EXIT_NOTHING_CAPTURED {
        if let Some(w) = waterfall {
            use std::io::Write;
            // Ignore a BrokenPipe (reader went away) rather than panic, like the verdict writer.
            let _ = writeln!(std::io::stdout(), "{w}");
        }
    }
    Ok(if code == EXIT_NOTHING_CAPTURED { EXIT_NOTHING_CAPTURED } else { 0 })
}

/// A one-line measured summary of the health check — TTFB and connection-reuse — pulled from
/// the doctor Report by stable metric name (not by fragile label text). `None` when neither
/// landed (e.g. an all-partial capture), so a thin/empty line is never printed. This surfaces
/// numbers `render_brief` hides behind its healthy one-liner.
///
/// GET throughput is DELIBERATELY omitted: the public probe objects are 3–30 KB, so the
/// transfer never leaves TCP slow-start and `content_length / download_ns` is a ~bytes/RTT
/// artifact (scales with 1/RTT, not link capacity), not a sustained rate. TTFB and reuse are
/// meaningful on a small object; a sustained-rate number needs `check <bucket>/<big-key>`.
fn check_waterfall(report: &s3tap_doctor::Report) -> Option<String> {
    // TTFB lives in the S3-domain rows; reuse is its own typed field. Trim because the row values
    // are width-padded for the aligned table.
    let ttfb = report.s3.iter().find(|r| r.metric.name == "s3_ttfb").map(|r| r.value.trim().to_string());
    let reuse = report.reuse.as_ref().map(|r| r.value.trim().to_string());
    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = ttfb {
        parts.push(format!("TTFB {t}"));
    }
    if let Some(r) = reuse {
        parts.push(format!("reuse {r}"));
    }
    if parts.is_empty() {
        return None;
    }
    let judged = report.op_judged;
    Some(format!("  measured: {} (over {judged} judged op(s))", parts.join(", ")))
}

/// The geographic-triage block (`check <bucket> --triage`): compare the bucket's own endpoint
/// round-trip against the NEAREST PROBED region (only [`REGIONAL_PROBES`] are swept — not every
/// S3 region), and if a meaningful amount is avoidable, name the gap + the standard remedies. Pure
/// (no I/O) so it's unit-tested. `bucket_ms` is the health probe's own measured floor. Returns None
/// when there is no region floor to compare against OR the bucket is already about as near as any
/// probed region — the caller disambiguates those two before choosing a message.
fn render_triage(bucket_ms: f64, regions: &[(&str, ProbeOutcome)]) -> Option<String> {
    let floors: Vec<(&str, f64)> = regions
        .iter()
        .filter_map(|(r, o)| match o {
            ProbeOutcome::Floor(f, _) => Some((*r, *f)),
            _ => None,
        })
        .collect();
    let (near_region, near_ms) =
        floors.iter().copied().min_by(|a, b| a.1.partial_cmp(&b.1).expect("finite floors"))?;
    let avoidable = bucket_ms - near_ms;
    // Only worth surfacing when the gap is BOTH absolutely (>10 ms) and proportionally (>1.3x)
    // large — otherwise the bucket is already near-optimal (among the probed regions) and moving
    // it wouldn't pay off. Conservative on purpose: under-advise rather than push a costly move.
    if avoidable < 10.0 || bucket_ms < 1.3 * near_ms {
        return None;
    }
    // A soft "similar RTT to X" hint at the bucket's region — but ONLY when a probed region's
    // floor is actually close to the bucket's (within 25%). With just a few regions swept, a
    // bucket in an UN-probed region would otherwise be mislabelled as the nearest coarse match.
    // Never a location claim; we never read the bucket's region off the wire.
    let like = floors
        .iter()
        .copied()
        .min_by(|a, b| (a.1 - bucket_ms).abs().partial_cmp(&(b.1 - bucket_ms).abs()).expect("finite"));
    let like_hint = match like {
        Some((r, f)) if r != near_region && (f - bucket_ms).abs() <= 0.25 * bucket_ms => {
            format!(" (similar RTT to {r})")
        }
        _ => String::new(),
    };
    Some(format!(
        "\ngeographic triage:\n  \
         your bucket's endpoint  {bucket_ms:>7.1} ms{like_hint}\n  \
         nearest probed region   {near_ms:>7.1} ms   {near_region}\n  \
         → this host's round-trip to S3 is ~{avoidable:.0} ms lower at {near_region} than at your \
         bucket. If your readers are near this host, consider a {near_region} bucket/replica, \
         S3 Transfer Acceleration, a Multi-Region Access Point, or CloudFront (only if the same \
         objects are re-read — cache misses add an origin hop).\n"
    ))
}

/// A titled section rule — `──── where you sit ─────────` at a fixed width — that breaks the
/// `check` output into scannable sections. Dashes dimmed, title bold; gated on `color`.
fn section_rule(title: &str, color: bool) -> String {
    const WIDTH: usize = 52;
    let lead = "────";
    let used = lead.chars().count() + 1 + title.chars().count() + 1; // "──── title "
    let tail = "─".repeat(WIDTH.saturating_sub(used));
    if color {
        format!("\x1b[2m{lead}\x1b[0m \x1b[1m{title}\x1b[0m \x1b[2m{tail}\x1b[0m")
    } else {
        format!("{lead} {title} {tail}")
    }
}

/// Format the regional-probe results as scannable sections: a titled map (one row per region —
/// its round-trip floor, `not measured`, or `local capture failed`, nearest flagged) and a "where you sit"
/// block that turns the position synthesis into an aligned label→value list instead of prose.
/// Pure (no I/O), so it is unit-tested independently of a live capture. `color` gates ANSI so the
/// plain text is unchanged when piped (and the tests assert on the uncolored form).
fn render_regional(rows: &[(&str, ProbeOutcome)], color: bool) -> String {
    // Restrained palette: DIM the secondary detail (header, band, degraded status), GREEN the
    // nearest marker. Everything is gated on `color` so a pipe/redirect stays plain.
    let dim = |s: &str| if color { format!("\x1b[2m{s}\x1b[0m") } else { s.to_string() };
    let green = |s: &str| if color { format!("\x1b[32m{s}\x1b[0m") } else { s.to_string() };
    let wr = rows.iter().map(|(r, _)| r.len()).max().unwrap_or(0).max("region".len());
    // Measured floors, sorted nearest→farthest so the map reads top-to-bottom; the lowest is
    // "nearest" and every row's penalty is measured against it. Floors are finite positive f64.
    let mut measured: Vec<(&str, f64, Option<f64>)> = rows
        .iter()
        .filter_map(|(r, o)| match o {
            ProbeOutcome::Floor(f, j) => Some((*r, *f, *j)),
            _ => None,
        })
        .collect();
    measured.sort_by(|a, b| a.1.partial_cmp(&b.1).expect("finite floors"));
    let nearest = measured.first().copied();
    let farthest = measured.last().copied();

    let mut out = String::new();
    out.push_str(&section_rule(&format!("S3 latency map · {} regions", rows.len()), color));
    out.push('\n');
    // `location` is the last column, so it is left-unpadded (no trailing whitespace). The header
    // is dimmed as a whole (its column widths are computed before coloring so alignment holds).
    // `jitter` (RTT variation) sits between the floor and the penalty as the stability signal.
    let header = format!("  {:<wr$}  {:>10}  {:>8}  {:>10}  {}", "region", "round-trip", "jitter", "vs nearest", "location");
    out.push_str(&dim(&header));
    out.push('\n');
    for (i, (region, ms, jit)) in measured.iter().enumerate() {
        // First row IS the nearest (sorted): em dash for its own penalty, `← nearest` marker.
        let (delta, mark) = if i == 0 {
            ("—".to_string(), green("   ← nearest"))
        } else {
            (format!("+{:>3.0} ms", ms - nearest.expect("i>0 ⇒ nearest exists").1), String::new())
        };
        // Jitter cell: `±0.4 ms` when the extended field landed, else blank (dimmed as secondary).
        let jitter = dim(&format!("{:>8}", jit.map(|j| format!("±{j:.1} ms")).unwrap_or_default()));
        // `location` carries the city AND a coarse distance band (`Ireland · ~regional`) — the
        // band turns the raw ms into meaning without a fifth column; the band is dimmed as the
        // secondary detail. Color is added AFTER width padding so column offsets are unaffected.
        out.push_str(&format!(
            "  {region:<wr$}  {ms:>7.1} ms  {jitter}  {delta:>10}  {} {}{mark}\n",
            region_city(region),
            dim(&format!("· {}", region_band(*ms)))
        ));
    }
    // Reachable-but-no-floor and hard failures sit below the ranked rows, kept distinct so a
    // transient "no srtt" isn't reported as "S3 unreachable".
    //
    // `CaptureFailed` says LOCAL, never "unreachable", which is what it used to print. That
    // word names the far end, so a mixed map (most regions measured, one or two failed) read
    // as a partial S3 outage and an operator escalated an AWS/network incident for a probe
    // that never left their own host. The all-failed case was already handled by the caller,
    // which is exactly why only the mixed one bit: the map still looked credible.
    let mut local_failures = false;
    for (region, outcome) in rows {
        let note = match outcome {
            ProbeOutcome::NotMeasured => "not measured",
            ProbeOutcome::CaptureFailed => {
                local_failures = true;
                "local capture failed"
            }
            ProbeOutcome::Floor(..) => continue,
        };
        // Left-fill the status across the whole round-trip+jitter+penalty span (10 + 2 + 8 + 2 +
        // 10 = 32) so `location` stays aligned with the measured rows. Pad BEFORE dimming so the
        // color codes don't count toward the field width.
        let status = dim(&format!("{note:<32}"));
        out.push_str(&format!("  {region:<wr$}  {status}  {}\n", region_city(region)));
    }
    // The footnote is what makes the row actionable. Without it "local capture failed" is
    // still a status the reader has to guess the owner of, and the guess a latency map
    // invites is "the region".
    if local_failures {
        out.push_str(&dim(
            "  note: `local capture failed` is a failure of the eBPF capture on THIS host \
             (usually the base caps: `sudo s3tap setup`). It says nothing about that region.",
        ));
        out.push('\n');
    }

    // "where you sit" — the position synthesis as an aligned label→value list (scannable, vs a
    // prose paragraph). `row` is a labelled line; `hedge` is a dim continuation aligned under the
    // value. The honesty hedges the reviews pinned (of-those-probed / may-be-nearer / consider /
    // replication-cost / ceiling-only-when-window-limited) live on in the dim hedge lines.
    const LW: usize = 11;
    let row = |label: &str, value: &str| format!("  {label:<LW$}{value}\n");
    let hedge = |text: &str| format!("  {:<LW$}{}\n", "", dim(text));

    out.push('\n');
    out.push_str(&section_rule("where you sit", color));
    out.push('\n');
    match (nearest, farthest) {
        // Two-plus regions with a real spread: position, redundancy, and the throughput cost of
        // distance. Scope stays honest — only the curated few are swept, so an un-probed region may
        // be nearer (cf. pick_public_probe's doc). Advice stays "consider", not an imperative.
        (Some((nr, nms, njit)), Some((fr, fms, _))) if fms - nms >= 1.0 => {
            out.push_str(&row("nearest", &format!("{nr} · {nms:.1} ms")));
            out.push_str(&hedge("(of those probed; an un-probed region may be nearer)"));
            stability_row(&mut out, row, nr, nms, njit);
            // Redundancy: the runner-up, and whether several regions cluster close (a failover /
            // replica option). `close_gap` scales with the floor so it's meaningful both in-region
            // and on a WAN link.
            if let Some((rr, rms, _)) = measured.get(1).copied() {
                // One decimal so a sub-1 ms runner-up gap doesn't render a contradictory "+0 ms".
                out.push_str(&row("runner-up", &format!("{rr} · +{:.1} ms", rms - nms)));
                let close_gap = 5.0_f64.max(0.25 * nms);
                let clustered = measured.iter().filter(|(_, f, _)| *f <= nms + close_gap).count();
                if clustered >= 2 {
                    out.push_str(&row(
                        "redundancy",
                        &format!("{clustered} regions within ~{close_gap:.0} ms — failover/replica option"),
                    ));
                    out.push_str(&hedge("(replication adds cost and is eventually consistent)"));
                }
            }
            // The latency penalty always. The throughput point is a CEILING (single-stream ≈
            // window ÷ RTT, so the ceiling scales ~1/RTT) — reported as a ratio only when it's
            // clearly meaningful (≥2×), and framed as a ceiling the stream hits only when
            // window-limited (with autotuning it often isn't; cf. the doctor's throughput row).
            let ratio = fms / nms;
            if ratio >= 2.0 {
                out.push_str(&row(
                    "spread",
                    &format!("+{:.0} ms at {fr} · single-stream ceiling ~{ratio:.0}× lower", fms - nms),
                ));
                out.push_str(&hedge("(ceiling ≈ window ÷ RTT; only when window-limited — parallel connections help)"));
            } else {
                out.push_str(&row("spread", &format!("+{:.0} ms at the farthest probed ({fr})", fms - nms)));
            }
            out.push_str(&row("advice", &format!("latency-sensitive buckets → consider {nr}")));
        }
        // One floor, or every floor within ~1 ms of each other: position only, no penalty to cite.
        (Some((nr, nms, njit)), _) => {
            out.push_str(&row("nearest", &format!("{nr} · {nms:.1} ms (lowest round-trip)")));
            out.push_str(&hedge("(of those probed; an un-probed region may be nearer)"));
            stability_row(&mut out, row, nr, nms, njit);
            if measured.len() >= 2 {
                out.push_str(&row("note", "all probed regions within ~1 ms — centrally placed"));
            }
        }
        (None, _) => out.push_str(
            "  no region returned a round-trip floor — check connectivity and the base caps \
             (`sudo s3tap setup`)\n",
        ),
    }
    out
}

/// Push a "stability" synthesis row for the nearest region's jitter (RTT variation), tagging a
/// steady vs variable path. No-op when jitter wasn't measured (the extended tcp_sock fields were
/// absent). `row` formats a labelled line exactly as the caller's other synthesis rows do.
fn stability_row(out: &mut String, row: impl Fn(&str, &str) -> String, nr: &str, nms: f64, jitter: Option<f64>) {
    if let Some(j) = jitter {
        // "variable" when jitter is non-trivial (>2 ms) AND either a large fraction of the floor
        // (RTO ≈ srtt + 4·rttvar, so relative jitter tightens timeouts) OR large in ABSOLUTE terms
        // (>15 ms). The absolute arm matters because jitter is largely absolute — a congested/
        // satellite hop adds ~fixed ms regardless of baseline — so a purely proportional bar would
        // read 25 ms of real jitter on a 200 ms floor as "steady".
        let tag = if j > 2.0 && (j > 0.15 * nms || j > 15.0) { "variable path" } else { "steady" };
        out.push_str(&row("stability", &format!("±{j:.1} ms jitter at {nr} — {tag}")));
    }
}

/// Turn a friendly `check` target into a probe URL. Accepts a full URL (used as-is, `https://`
/// prepended when the scheme is bare), or `bucket/key` — a first path segment WITHOUT a dot is
/// read as a bucket name and expanded to the S3 virtual-hosted endpoint. A dotted first segment
/// is treated as a hostname (a real endpoint). A bucket with no key is an error: there is no
/// object to GET, so the probe would have nothing to measure.
fn normalize_check_target(target: &str, region: Option<&str>) -> anyhow::Result<String> {
    let target = target.trim();
    if target.is_empty() {
        anyhow::bail!("empty check target — pass a `bucket/key` or a URL");
    }
    // Validate --region BEFORE interpolating it into a hostname (it would otherwise let a
    // crafted value redirect the probe to another host, e.g. `--region evil.com/`); same LDH
    // guard the SigV4 path uses.
    if let Some(r) = region {
        if !region_is_valid(r) {
            anyhow::bail!("invalid --region `{r}` — letters, digits, and hyphens only (e.g. eu-west-1)");
        }
    }
    if target.contains("://") {
        return Ok(target.to_string());
    }
    let (head, key) = match target.split_once('/') {
        Some((h, k)) => (h, k),
        None => (target, ""),
    };
    // A dotted first segment is already a hostname/endpoint (e.g. bucket.s3.amazonaws.com),
    // not a bucket name to expand — pass it through with a scheme.
    if head.contains('.') {
        return Ok(format!("https://{target}"));
    }
    if key.is_empty() {
        anyhow::bail!(
            "`{head}` is a bucket with no object key — there's nothing to GET. Try \
             `s3tap check {head}/<key>` (a readable object), or pass a full URL."
        );
    }
    let host = match region {
        Some(r) => format!("{head}.s3.{r}.amazonaws.com"),
        None => format!("{head}.s3.amazonaws.com"),
    };
    Ok(format!("https://{host}/{key}"))
}

/// Render the doctor output for an analyzed capture and return the process exit code,
/// shared by the consumer (`--from`/stdin) and `--live` paths. A broken pipe is a clean
/// stop (returns `Ok(0)`); the actual `process::exit` is done by the caller so this stays
/// a returnable, testable mapping.
fn report_and_code(
    report: &s3tap_doctor::Report,
    records: &[s3tap_doctor::Record],
    args: &DoctorArgs,
) -> anyhow::Result<i32> {
    use std::io::{IsTerminal, Write};
    let color = want_color(args.no_color, std::io::stdout().is_terminal());
    // Baseline mode (if --baseline): analyze the reference capture and diff against it.
    let mut baseline_stats = None;
    let baseline_diff = match &args.baseline {
        Some(bpath) => {
            // Streamed like the primary input: a baseline is a capture too, so it must not
            // be the one path that can still be read into memory whole.
            let what = format!("baseline {}", bpath.display());
            let bfile = std::fs::File::open(bpath).with_context(|| format!("reading {what}"))?;
            let (brecords, bstats) = stream_records(std::io::BufReader::new(bfile), &what)?;
            // The SAME zero-record guard the primary input carries. A baseline that parsed to
            // nothing is not a lenient comparison, it is no comparison: `diff` then finds every
            // metric absent on the reference side, reports NO REGRESSION and exits 0, so a gate
            // built on `--baseline` passes green while judging against an empty file. That is
            // not hypothetical here: a `--live --save` run killed by a signal used to leave
            // exactly such an empty file behind. Exit 4 (tool failure) rather than a verdict.
            require_records(&brecords, bstats, "doctor", &what)?;
            baseline_stats = Some(bstats);
            let breport = s3tap_doctor::analyze_with(&brecords, bstats);
            Some(s3tap_doctor::diff(report, &breport))
        }
        None => None,
    };
    // The body is the diff table (baseline mode), NDJSON findings (--json), the cost table,
    // or the human report. Built up-front so a serialize error is reported, not half-written.
    let body = if args.cost {
        s3tap_doctor::cost(records).render(color)
    } else if let Some(d) = &baseline_diff {
        d.render(color)
    } else if args.json {
        let mut s = String::new();
        for f in report.findings() {
            s.push_str(&serde_json::to_string(&f).context("serializing a doctor finding")?);
            s.push('\n');
        }
        s
    } else if args.brief {
        report.render_brief(color)
    } else {
        report.render(color)
    };
    // Write via a locked handle (+ flush) so a closed reader (`… | head`) surfaces as a
    // BrokenPipe we treat as a clean stop, not a panic (review step-2).
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(body.as_bytes()).and_then(|_| out.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(0); // reader went away — a clean stop
        }
        return Err(anyhow::Error::from(e).context("writing the doctor report"));
    }
    // The baseline's own parse health, so a mostly-broken reference can't silently read as
    // a (near-empty) baseline that makes the current capture look like all regressions.
    if let Some(bstats) = baseline_stats {
        if bstats.bad_lines > 0 || bstats.unknown_schema > 0 {
            enote!(
                "note: baseline: skipped {} unparseable + {} unknown-schema line(s)",
                bstats.bad_lines, bstats.unknown_schema
            );
        }
    }
    // Cost is informational (exit 0); baseline keys on the diff; else the verdict mapping.
    let code = if args.cost {
        0
    } else if let Some(d) = &baseline_diff {
        // A missing denominator OUTRANKS the diff. `regressed_with` is a bool, so keying the
        // exit on it alone made 2 structurally unreachable under `--baseline`: a CI job
        // running `doctor --from today --baseline ref --strict` that lost its uprobe caps
        // captured connections only, diffed "NO OPERATIONS → NO OPERATIONS", printed
        // "NO REGRESSION" and exited 0. That is the missing-denominator-reads-green failure
        // the rest of this file refuses everywhere else, and adding `--baseline` must not be
        // the way to opt out of it. A diff against a capture that judged nothing is not a
        // comparison, so the verdict answers first and the diff only when there was one.
        match verdict_exit_code(report, args.strict) {
            2 => {
                // Say it on the human rail too. The rendered diff had already printed
                // "verdict: REGRESSED" (its own comparison did regress) while the exit code
                // said 2, so the two rails disagreed about what happened.
                enote!(
                    "note: the CURRENT capture had nothing to judge, so this exits \
                     {EXIT_NOTHING_JUDGEABLE} rather than a diff verdict — the comparison \
                     above rests on a population that is not there."
                );
                EXIT_NOTHING_JUDGEABLE
            }
            _ => i32::from(d.regressed_with(args.strict)),
        }
    } else {
        verdict_exit_code(report, args.strict)
    };
    Ok(code)
}

/// The scriptable verdict→exit-code mapping: 1 = ATTENTION (any ⚠, or with
/// `--strict` any advisory), 2 = nothing judgeable, 0 = healthy / checks-passed. Pure, so
/// it's unit-testable.
///
/// Three verdicts share code 2, because a script can do only one thing with any of them:
/// re-run. NO BASELINE has no round-trip floor, so no latency was judged. NO OPERATIONS has no
/// S3 request at all, so the whole S3 half of the report was judged over an empty population.
/// NO RESPONSES decoded requests but never saw one answered, so the status-mix rows have the
/// same empty population one layer in.
/// The second used to fall through to 0 while the same run's `--json` published the run
/// finding as `"severity":"unjudged"` and its table said "0 operations in this capture", so
/// a Go/rustls client (no OpenSSL symbols to hook) or any capture taken without the uprobe
/// caps read GREEN in CI on the strength of the network rows alone. Neither is a health
/// claim, and a run that judged nothing must not read green.
fn verdict_exit_code(report: &s3tap_doctor::Report, strict: bool) -> i32 {
    match report.overall_verdict() {
        s3tap_doctor::Verdict::Attention => 1,
        // Below Attention on purpose, mirroring `overall_verdict`: the connection-sourced
        // checks (retransmits, path) can warn with no operations at all, and that judgment
        // is real, so a ⚠ is never downgraded to "nothing judged". NoResponses joins this
        // bucket too: operations existed but none was ever answered, the same missing-
        // denominator shape as zero operations, just one layer further in.
        // `MixedPaths` is the same shape: a floor exists but no span was judged against it,
        // so the run is not judgeable and must not read green.
        s3tap_doctor::Verdict::NoBaseline
        | s3tap_doctor::Verdict::NoOperations
        | s3tap_doctor::Verdict::NoResponses
        | s3tap_doctor::Verdict::MixedPaths => 2,
        _ if strict && report.has_advisory() => 1,
        s3tap_doctor::Verdict::ChecksPassed | s3tap_doctor::Verdict::Healthy { .. } => 0,
    }
}

/// `s3tap doctor --live`: drive a small keep-alive workload against `--endpoint`, capture
/// it (eBPF, scoped to the curl driver), and run the doctor over the result. The privileged
/// counterpart to the pure-consumer doctor. Returns the exit code.
async fn doctor_live(args: &DoctorArgs) -> anyhow::Result<i32> {
    report_or_diagnostic(probe_report(args, true).await?, args)
}

/// Map a `probe_report` result to the process exit code: None (capture failed / nothing
/// captured) is the exit-3 diagnostic; Some renders + returns the health exit code. Extracted
/// so the None→3 contract is unit-testable without a live capture.
fn report_or_diagnostic(
    opt: Option<(s3tap_doctor::Report, Vec<s3tap_doctor::Record>)>,
    args: &DoctorArgs,
) -> anyhow::Result<i32> {
    match opt {
        None => Ok(EXIT_NOTHING_CAPTURED),
        Some((report, records)) => report_and_code(&report, &records, args),
    }
}

/// Drive+capture the live workload and analyze it into a doctor Report — the shared core of
/// `doctor --live` and `check`. Returns None for the exit-3 diagnostics (capture failed or
/// nothing was captured), with the message already printed; the caller renders/summarizes the
/// Some. Factored out so `check`'s regional loop can read each probe's floor.
async fn probe_report(
    args: &DoctorArgs,
    announce: bool,
) -> anyhow::Result<Option<(s3tap_doctor::Report, Vec<s3tap_doctor::Record>)>> {
    if args.from.is_some() {
        anyhow::bail!("--live drives its own capture; it can't be combined with --from");
    }
    if args.endpoint.is_empty() {
        anyhow::bail!("--live requires --endpoint <URL> (a readable S3 object/endpoint)");
    }
    // Multiple endpoints only make sense with --rotate (one object per request); without it
    // we'd silently drop all but the first, so make the mistake loud.
    if args.endpoint.len() > 1 && !args.rotate {
        anyhow::bail!(
            "{} --endpoint given without --rotate — add --rotate to cycle through them (one \
             object per request, for a cold-fetch measure), or pass a single --endpoint",
            args.endpoint.len()
        );
    }
    // Concurrency is a fan-out of curl workers; 0 would drive nothing, and an unbounded
    // value is a fork-bomb footgun — bound it to a sane range with a clear message.
    if args.concurrency == 0 || args.concurrency > 256 {
        anyhow::bail!(
            "--concurrency must be between 1 and 256 (got {}); 1 is serial keep-alive",
            args.concurrency
        );
    }
    // --requests is pre-materialized into ONE curl argv, so the real ceiling is the
    // kernel's execve budget, not an allocation limit. See `max_requests_for_argv`: the
    // old 100000 bound was five times past what a single argv can carry, so `--requests
    // 100000` failed with E2BIG inside the driver and surfaced as the misleading
    // "captured nothing — check your caps" exit 3. Reject it HERE, where we can still say
    // why.
    let cap = max_requests_for_argv(args.endpoint.iter().map(String::len).max().unwrap_or(0));
    if args.requests == 0 || args.requests > cap {
        anyhow::bail!(
            "--requests must be between 1 and {cap} (got {}); the whole request sequence \
             becomes one curl argv, and a longer --endpoint URL lowers the ceiling. For a \
             larger sample, raise --concurrency (each worker gets its own argv) or re-run.",
            args.requests
        );
    }
    // --timeout-secs feeds `Instant::now() + Duration::from_secs(n)`, which PANICS on
    // overflow — and it panics inside the capture, i.e. after the probes are attached, so
    // a typo'd budget became an exit-101 stack trace instead of a usage error. 0 is
    // likewise rejected: it yields an already-elapsed deadline, so the run captures
    // nothing and reports the misleading exit-3 "no traffic reached the probe". The upper
    // bound is an hour — far past any keep-alive probe, and comfortably overflow-free.
    if args.timeout_secs == 0 || args.timeout_secs > 3600 {
        anyhow::bail!(
            "--timeout-secs must be between 1 and 3600 (got {}); it is a capture budget, \
             not a deadline for the whole workload",
            args.timeout_secs
        );
    }
    // Signal streams BEFORE the reservation below. The reservation creates a real 0600 file
    // that only `SaveTarget`'s Drop removes, and everything between it and the capture's own
    // listeners (the curl check, credential resolution, the eBPF load of 22 programs plus the
    // uprobes: ~0.2 to 1 s) used to run under the DEFAULT signal disposition on the first
    // capture of a process. A Ctrl-C there killed us outright, ran no Drop and left a permanent
    // empty placeholder that refused every later run with "Nothing was captured, so no run was
    // wasted", which was then false. Merely EXISTING is most of the fix: an installed stream
    // takes the signal off the default disposition and latches it, so it is still there to be
    // acted on. `tripped()` below is where it gets acted on.
    let mut signals = SignalStop::install()?;
    // Reserve `--save` HERE, beside the rest of the usage validation, not after the run.
    // The atomic O_CREAT|O_EXCL|O_NOFOLLOW open is the whole point of the flag's safety
    // (see SaveTarget), and doing it last meant `--save <existing path>` loaded the eBPF,
    // drove every real billable request, and only then failed on "File exists" with the
    // completed capture thrown away. The benchmark demo re-runs exactly this way, so its
    // table then tabulated the STALE file as if it were the new run. Reserving up front
    // keeps the same no-TOCTOU property and turns the failure into a usage error before a
    // single packet is sent.
    let save = args.save.as_deref().map(SaveTarget::create).transpose()?;
    selftest::check_curl("--live")?;
    let endpoints: Vec<String> = args.endpoint.iter().map(|e| selftest::normalize_endpoint(e)).collect();
    // host/local (drop-loopback decision + report host) come from the first object; a rotate
    // set is normally same-host (distinct keys), and curl reuses per host either way.
    let host = selftest::host_of(&endpoints[0]);
    let local = selftest::is_local(&host);
    let rotating = args.rotate && endpoints.len() > 1;
    // Resolve SigV4 creds up front (before loading probes) so a missing-creds --auth fails
    // fast with a clear message, not after a capture.
    let auth = if args.auth { Some(resolve_aws_creds(args)?) } else { None };
    // The progress banner is suppressed for the regional sweep (announce=false), which drives
    // this per region and prints its own concise table. Neutral "s3tap:" prefix so it reads
    // correctly whether invoked via `doctor --live` or `check`.
    if announce {
        enote!(
            "s3tap: driving {} {}request(s) {}{}… (L7 rows need `sudo s3tap setup --uprobes`)",
            args.requests,
            if auth.is_some() { "signed keep-alive " } else { "keep-alive " },
            if rotating {
                format!(
                    "rotating {} objects ({}, first: {})",
                    endpoints.len(),
                    rotation_coldness(args.concurrency, args.requests, endpoints.len()),
                    endpoints[0]
                )
            } else {
                format!("at {}", endpoints[0])
            },
            if args.concurrency > 1 {
                format!(" over {} parallel connections", args.concurrency)
            } else {
                String::new()
            },
        );
    }

    // Non-AWS gateways (Storj/MinIO): resolve path-style bucket/key for the per-s3_op rows.
    let s3_endpoints: Vec<String> =
        args.s3_endpoint.iter().filter_map(|s| normalize_endpoint_host(s)).collect();

    // Hand over to the capture, which installs its own listeners and ends itself on either
    // signal. Before that, act on anything that landed during the setup above: returning here
    // unwinds through `SaveTarget`'s Drop, so the reservation is released instead of outliving
    // the run. A signal arriving AFTER this check is not lost either: the capture's own
    // listeners pick it up on their own `select!`. `tripped()` itself must be awaited (see its
    // doc comment) so it actually gives the runtime a chance to observe an already-delivered
    // signal rather than synchronously polling a driver that hasn't run yet.
    if let Some(sig) = signals.tripped().await {
        return Err(Interrupted(sig).into());
    }

    let captured = match selftest::capture_workload(
        !local,
        std::time::Duration::from_secs(args.timeout_secs),
        selftest::Workload::KeepAlive {
            endpoints,
            requests: args.requests,
            rotate: args.rotate,
            concurrency: args.concurrency,
            auth,
        },
        s3_endpoints,
        |_, _| false, // drain until the driver finishes — need every op for the medians/tail
    )
    .await
    {
        Ok(c) => c,
        // A capture/driver failure (no caps, network down, …) is exit 3 — a diagnostic,
        // distinct from a health verdict, not anyhow's exit 1.
        Err(e) => {
            // The regional sweep (announce=false) summarizes capture failures itself; the base
            // caps (not UPROBES) are what the floor-only path needs, so don't misdirect there.
            if announce {
                // Blame capabilities only when the kernel actually said EACCES/EPERM. The old
                // text asserted a cause nothing had checked, so a too-old kernel, an absent BTF
                // blob or a verifier reject all read as "missing caps": the operator ran
                // `s3tap setup`, it succeeded, and the identical error came back. `run` has
                // discriminated on this since round 1; this path had not.
                //
                // A cause the capture already ESTABLISHED (no entropy source, no
                // sched_process_fork) passes through untouched: re-diagnosing it would send
                // the operator to `s3tap setup` for a kernel-config or an entropy problem.
                if let Some(known) = e.downcast_ref::<selftest::CaptureSetupError>() {
                    enote!("s3tap: could not capture: {known}");
                } else if is_permission_error(&e) {
                    enote!(
                        "s3tap: could not capture: permission denied. Grant the probe caps \
                         once with `sudo s3tap setup` (`sudo s3tap setup --uprobes` for the \
                         L7 rows), or run under sudo. (underlying error: {e:#})"
                    );
                } else {
                    enote!(
                        "s3tap: could not capture: {e:#}. This is not a permissions failure, \
                         so capabilities will not fix it and `s3tap setup` will not help. \
                         s3tap needs Linux 5.8 or newer with kernel BTF at {BTF_VMLINUX}."
                    );
                }
            }
            return Ok(None);
        }
    };

    finish_live_report(captured, &host, announce, save)
}

/// What `--rotate` actually measures, for the run banner. "cold-fetch" is a CLAIM about
/// the measurement, so it must hold on both counts the rotation can break it on:
///
/// * `--concurrency > 1`: the workers run the same rotation at once and warm each other's
///   objects, so no fetch after the first is reliably cold.
/// * more `--requests` than objects: the rotation WRAPS, so every request past the first
///   pass revisits an object the run already fetched. That is precisely the per-object
///   caching `--rotate` exists to defeat, and the help already asks for "at least
///   `--requests` DISTINCT objects" for that reason.
///
/// The banner said "cold-fetch" whenever concurrency was 1, so `--rotate --endpoint a
/// --endpoint b --requests 12` announced a cold-fetch measure over ten warm re-reads. Pure,
/// so the honesty correction is pinned by a test rather than by reading the banner.
fn rotation_coldness(concurrency: u32, requests: u32, objects: usize) -> &'static str {
    if concurrency > 1 {
        "warm across workers"
    } else if requests as usize > objects {
        "warm after the first pass, fewer objects than --requests"
    } else {
        "cold-fetch"
    }
}

/// The largest `--requests` whose curl argv still fits an `execve`, given the longest
/// `--endpoint` URL.
///
/// The keep-alive driver builds the ENTIRE request sequence as one argv (`-o /dev/null
/// --url <URL>` per request), so `--requests` is bounded by the kernel's argv+envp budget,
/// which is `RLIMIT_STACK / 4` — 2 MiB under the usual 8 MiB stack. Past it `execve`
/// returns E2BIG, the driver never runs, and the run reports "captured nothing" as if the
/// probe caps were missing. We spend at most HALF that budget because envp rides the same
/// allowance and we do not control the caller's environment.
///
/// The absolute ceiling is separate and is a measurement judgment: a keep-alive probe is
/// for a median plus a p95/p99 tail, and no tail estimate needs a five-figure sample. It
/// also keeps the bound stable (and the error message honest) for the ordinary short URL.
fn max_requests_for_argv(longest_url_bytes: usize) -> u32 {
    /// Half of the 2 MiB `RLIMIT_STACK / 4` argv+envp allowance.
    const ARGV_BUDGET: usize = 1 << 20;
    /// Absolute cap, regardless of how short the URL is (see above).
    const ABSOLUTE: u32 = 10_000;
    // `-o`, `/dev/null`, `--url`, `<URL>` — each argv string costs its bytes + a NUL.
    let per_request = 3 + 10 + 6 + longest_url_bytes + 1;
    let fits = (ARGV_BUDGET / per_request).min(ABSOLUTE as usize) as u32;
    // Always allow at least one request: a URL so long that not even one fits is the
    // driver's E2BIG to report, not a bound we can express as "between 1 and 0".
    fits.max(1)
}

/// The analyze half of the live path: obscure the capture, optionally `--save` it, and analyze
/// it into a Report. Returns None for the exit-3 degenerate case (nothing captured), message
/// already printed (when `announce`). Split from [`doctor_live`] so `check`'s regional loop can
/// read the floor without the per-region progress/diagnostic banners.
fn finish_live_report(
    captured: selftest::Captured,
    host: &str,
    announce: bool,
    save: Option<SaveTarget>,
) -> anyhow::Result<Option<(s3tap_doctor::Report, Vec<s3tap_doctor::Record>)>> {
    // What the CAPTURE did, before anything judges what it holds. A run that lost events to
    // a full ring, or stopped on its time budget with the driver still going, produces the
    // same-shaped record set as a clean one, and every rate and percentile below is then
    // drawn from a population missing exactly the events load sheds. Say so first, so the
    // operator reads the caveat above the verdict rather than after it.
    //
    // Gated on `announce` like every other diagnostic here: the regional sweep drives this
    // eight times over and prints its own table.
    if announce {
        for line in selftest::capture_warnings(&captured) {
            enote!("s3tap: {line}");
        }
    }
    // Capture precedes everything: nothing captured is exit 3 (a diagnostic), NOT a
    // NO-BASELINE health verdict.
    if captured.conns.is_empty() && captured.ops.is_empty() {
        if announce {
            enote!(
                "s3tap: captured no records: no traffic reached the probe (an exec→connect scope \
                 race, or missing caps). Re-run. If it persists, check `sudo s3tap setup` and that \
                 {host} is reachable."
            );
        }
        return Ok(None);
    }
    // A capture with NO L7 evidence whose driver never completed one request is a record of
    // the workload failing, not a reading of the target. The connection still carries a good
    // srtt, so without this the report judged that floor, found nothing wrong and returned
    // CHECKS PASSED with exit 0 while blaming the absent uprobe caps for the missing
    // operations. A TLS or certificate failure against a documented-to-fail endpoint then
    // passed a CI gate green with every single request refused. Refuse the verdict and name
    // curl's own reason instead.
    //
    // Only under `announce`: the regional map is explicitly floor-only and status-blind (a
    // 403 is the expected answer there), so its rows are a network measurement, never a
    // verdict, and must keep reporting a real floor.
    if announce && captured.ops.is_empty() {
        if let Some((code, n)) = captured.driver.never_completed_a_request() {
            enote!(
                "s3tap: no verdict. Nothing was read from {host}: curl exited {code} ({}) \
                 on every one of {n} attempt(s) and no operation was captured, so the \
                 round-trip floor is a measurement of the path and not a health signal. Fix \
                 the transport, then re-run.",
                selftest::curl_exit_meaning(code)
            );
            return Ok(None);
        }
        if let Some(err) = &captured.driver.error {
            enote!(
                "s3tap: no verdict. The traffic driver could not run ({err}), so nothing \
                 was driven at {host} and this capture says nothing about it."
            );
            return Ok(None);
        }
        // WHY there is no L7 row, from what the capture actually knows. Naming the uprobe
        // caps unconditionally was wrong for two common cases and sent both down a fix that
        // changes nothing: a Go/rustls/BoringSSL client exports no SSL_* symbols to hook, and
        // a handshake that never completed has no plaintext to see either.
        match captured.uprobes {
            selftest::UprobeStatus::Unattached { permission: true } => enote!(
                "s3tap: no operation records: the SSL uprobes are not attached because this \
                 process lacks cap_sys_admin. Grant it with `sudo s3tap setup --uprobes`. \
                 Judging the network floor only."
            ),
            selftest::UprobeStatus::Unattached { permission: false } => enote!(
                "s3tap: no operation records: the SSL uprobes are not attached, though not \
                 for want of privilege (see the load error above). Usually there is no \
                 OpenSSL libssl on this host to hook. Judging the network floor only."
            ),
            selftest::UprobeStatus::Attached => enote!(
                "s3tap: no operation records, though the SSL uprobes ARE attached, so this is \
                 not a capability problem and `s3tap setup --uprobes` will not change it. The \
                 traffic carried no OpenSSL plaintext: either the TLS handshake never \
                 completed, or the client does not use OpenSSL (Go's crypto/tls, rustls and a \
                 statically linked BoringSSL export no SSL_* symbols to hook). Judging the \
                 network floor only."
            ),
        }
    }

    let mut conns = captured.conns;
    let mut ops = captured.ops;
    let obscure = CookieObscurer::new();
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    obscure_records(&mut conns, &mut ops, &obscure, &now);

    // --save: the obscured JSONL (byte-compatible with a `run --format jsonl` capture, so it
    // can serve as a later --baseline). The destination was already reserved before the
    // capture ran (see SaveTarget); this only fills it.
    if let Some(target) = save {
        let mut s = String::new();
        for c in &conns {
            s.push_str(&serde_json::to_string(c).expect("serialize connection"));
            s.push('\n');
        }
        for o in &ops {
            s.push_str(&serde_json::to_string(o).expect("serialize operation"));
            s.push('\n');
        }
        target.write(&s)?;
    }

    let records: Vec<s3tap_doctor::Record> = conns
        .into_iter()
        .map(s3tap_doctor::Record::Connection)
        .chain(ops.into_iter().map(s3tap_doctor::Record::Operation))
        .collect();
    let report = s3tap_doctor::analyze_with(&records, s3tap_doctor::ParseStats::default());
    Ok(Some((report, records)))
}

/// A `--save` destination, RESERVED before the capture runs and filled after it.
///
/// The file is created up front by [`SaveTarget::create`], which is what makes "the path
/// must not already exist" a usage error rather than the way a finished run gets thrown
/// away. Two properties `std::fs::write` does not have, both of which bite here
/// specifically because `doctor --live` routinely re-execs itself under sudo (see
/// `elevate::maybe_elevate`), so this write commonly runs as ROOT with the path taken from
/// an argument:
///
/// * `create_new` + `O_NOFOLLOW`: `std::fs::write` follows symlinks and truncates whatever
///   it lands on. Pointing `--save` at a path an unprivileged user can pre-create (a
///   world-writable directory, a shared workspace) let that user aim a root-owned
///   truncating write anywhere on the filesystem. Refusing to write to anything that
///   already exists is the only version of this with no TOCTOU window: the create and the
///   existence check are one atomic `O_CREAT|O_EXCL`. (`O_NOFOLLOW` is belt and braces —
///   `O_EXCL` already fails on a dangling symlink — but it states the intent at the
///   syscall, so a future refactor to a truncating open does not silently reopen the hole.)
/// * mode 0600 rather than `0666 & ~umask` (0644 in practice): a capture names buckets,
///   endpoint IPs, SNI hostnames, per-request timings and `key_hash` values. That is a map
///   of the operator's storage, and on a shared host it was readable by every local user.
struct SaveTarget {
    path: std::path::PathBuf,
    /// The DIRECTORY the reservation lives in, opened once at create time, plus the final
    /// component's name. Both the create and the release go through this fd, so they cannot
    /// disagree about which directory that is: see [`SaveTarget::create`].
    dir: std::fs::File,
    name: std::ffi::CString,
    /// The reserved handle, released by [`SaveTarget::write`] once the write SUCCEEDS. Still
    /// `Some` at drop means the run ended without producing a capture, so `Drop` releases the
    /// name again.
    file: Option<std::fs::File>,
}

impl SaveTarget {
    /// Atomically claim `path`, empty and owner-only. Fails if anything is already there.
    ///
    /// Everything happens RELATIVE TO AN OPEN DIRECTORY FD rather than to the path string.
    /// `remove_file` (and any other path-based call) re-resolves the whole path at the moment
    /// it runs: `unlink` does not follow the final component, but it does follow every
    /// intermediate one, so with an attacker-owned ancestor (`sudo s3tap doctor --live --save
    /// /tmp/build-out/cap.jsonl`, where `/tmp/build-out` is swapped for a symlink to `/etc`
    /// mid-run) the release became a root unlink of a file we never created. Resolving the
    /// directory ONCE and doing both the `openat` and the `unlinkat` against that fd removes
    /// the second resolution entirely, so the entry dropped is the entry made.
    fn create(path: &std::path::Path) -> anyhow::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let ctx = || {
            format!(
                "reserving --save {} (it must not already exist: s3tap never truncates \
                 or follows a symlink here, because --live often runs as root). Nothing \
                 was captured, so no run was wasted. Pick a new path, or remove that one.",
                path.display()
            )
        };
        // A trailing slash names a DIRECTORY. `file_name()` would quietly drop it and reserve
        // `foo` for `--save foo/`, where the path-based open this replaced returned ENOTDIR.
        anyhow::ensure!(
            path.as_os_str().as_bytes().last() != Some(&b'/'),
            "--save {} names a directory, not a file to write",
            path.display()
        );
        let name = path.file_name().with_context(|| {
            format!("--save {} does not name a file to write", path.display())
        })?;
        let name = std::ffi::CString::new(name.as_bytes())
            .with_context(|| format!("--save {} is not a usable file name", path.display()))?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => std::path::PathBuf::from("."),
        };
        // O_DIRECTORY so a non-directory can never stand in for it, O_NOFOLLOW so the last
        // component of the parent is not a symlink either.
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent)
            .with_context(|| format!("opening the --save directory {}", parent.display()))?;
        // SAFETY: `dir` is an open fd we own and `name` outlives the call. O_EXCL|O_CREAT is
        // the atomic claim (no TOCTOU between checking and creating) and O_NOFOLLOW states the
        // intent at the syscall, so a later refactor cannot silently reopen the symlink hole.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                libc::mode_t::from(0o600u16),
            )
        };
        if fd < 0 {
            return Err(anyhow::Error::new(std::io::Error::last_os_error())).with_context(ctx);
        }
        // SAFETY: `fd` was just returned by openat and is owned by nothing else.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Self { path: path.to_path_buf(), dir, name, file: Some(file) })
    }

    /// Fill the reserved file and give up the handle, so `Drop` leaves it in place.
    ///
    /// The handle is released only once the write has SUCCEEDED. Taking it first meant a write
    /// that failed part-way (ENOSPC on a capture that can be megabytes) left `file == None`, so
    /// `Drop` did nothing: the path kept a truncated capture with no marker of any kind, and the
    /// re-run was refused with "Nothing was captured, so no run was wasted", which was false.
    fn write(mut self, body: &str) -> anyhow::Result<()> {
        let f = self.file.as_mut().expect("the handle is released exactly once, here");
        f.write_all(body.as_bytes())
            .with_context(|| format!("writing --save {}", self.path.display()))?;
        self.file = None;
        Ok(())
    }
}

impl Drop for SaveTarget {
    fn drop(&mut self) {
        // Reserved but never written (or written only in part): the run produced no capture to
        // keep. Release the name so the re-run is not refused by the placeholder this very
        // reservation created.
        if self.file.is_some() {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `dir` is still open (we own it) and `name` outlives the call. unlinkat
            // against that fd drops the entry we made in the directory we made it in, with no
            // second path resolution to redirect.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

/// Obscure each captured record's raw sk-pointer through ONE per-run obscurer + stamp
/// `emitted_at`, IN PLACE, BEFORE analyze — so the finding evidence and `--save` never
/// carry a raw kernel `struct sock *` (KASLR) pointer. `req_seq`/
/// `connection_reused` don't read the cookie value, so the verdict is unchanged.
fn obscure_records(
    conns: &mut [s3tap_schema::Connection],
    ops: &mut [s3tap_schema::Operation],
    obscure: &CookieObscurer,
    now: &str,
) {
    for c in conns {
        c.sock_cookie = obscure.apply(c.sock_cookie);
        c.emitted_at.get_or_insert_with(|| now.to_string());
    }
    for o in ops {
        o.sock_cookie = obscure.apply(o.sock_cookie);
        o.emitted_at.get_or_insert_with(|| now.to_string());
    }
}

/// Resolve SigV4 creds for `--live --auth`, SDK-like: env first
/// (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`), else the
/// `~/.aws/credentials` profile (`AWS_PROFILE` or `default`). Region: `--region` →
/// `AWS_REGION` → `AWS_DEFAULT_REGION` → `~/.aws/config` → `us-east-1`. Errors (never sends
/// unsigned) if no key/secret resolves.
fn resolve_aws_creds(args: &DoctorArgs) -> anyhow::Result<selftest::AwsCreds> {
    let env = std::env::var;
    let profile = env("AWS_PROFILE").unwrap_or_else(|_| "default".into());
    // Asked once: is the privilege doing the file reads below BORROWED from the binary's file
    // capabilities rather than from the invoking user? Both `~/.aws` reads are steered by HOME,
    // which survives the AT_SECURE scrub, so both consult it (see `read_credentials_file` and
    // the region fallback).
    let borrowed = elevate::on_borrowed_privilege();

    // 1) env, 2) ~/.aws/credentials [profile].
    let (access_key, secret_key, session_token) = match (
        env("AWS_ACCESS_KEY_ID").ok().filter(|s| !s.is_empty()),
        env("AWS_SECRET_ACCESS_KEY").ok().filter(|s| !s.is_empty()),
    ) {
        (Some(ak), Some(sk)) => (ak, sk, env("AWS_SESSION_TOKEN").ok().filter(|s| !s.is_empty())),
        _ => {
            // The ~/.aws read is the one privileged read in this command, so it is gated on
            // whether the borrowed capability is what MAKES it possible. See
            // `read_credentials_file` for the attack and for why the gate cannot simply be
            // "are we holding capabilities".
            //
            // Credentials in the ENVIRONMENT are handled above and are deliberately not
            // gated: reading them needs no privilege and they are the caller's own, so there
            // is nothing to steal.
            let path = aws_dir().join("credentials");
            let body = read_credentials_file(&path, borrowed)?;
            let ak = ini_get(&body, &profile, "aws_access_key_id");
            let sk = ini_get(&body, &profile, "aws_secret_access_key");
            match (ak, sk) {
                (Some(ak), Some(sk)) => {
                    (ak, sk, ini_get(&body, &profile, "aws_session_token"))
                }
                _ => anyhow::bail!(
                    "--auth: profile [{profile}] in {} is missing aws_access_key_id / \
                     aws_secret_access_key",
                    path.display()
                ),
            }
        }
    };

    // STS/temporary creds need curl to SIGN the x-amz-security-token header, which curl only
    // does from 7.86.0 (older curl signs only host;x-amz-date → the token rides UNSIGNED →
    // 403 → a false ATTENTION on valid creds). Fail fast with a clear diagnostic rather than
    // emit a misleading verdict. Only blocks when we KNOW curl is old.
    if session_token.is_some() {
        if let Some((maj, min)) = curl_version() {
            if sts_gate_blocks(Some((maj, min))) {
                anyhow::bail!(
                    "--auth with a session token (temporary/STS creds) needs curl >= 7.86.0 to \
                     sign the x-amz-security-token header — this curl is {maj}.{min}. Upgrade \
                     curl, or use permanent (non-STS) credentials."
                );
            }
        }
    }

    // Region precedence: --region, env, ~/.aws/config (profile section is `[profile X]`,
    // or `[default]`), else us-east-1. Empty-filter the flag like the env sources.
    let region = args
        .region
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| env("AWS_REGION").ok().filter(|s| !s.is_empty()))
        .or_else(|| env("AWS_DEFAULT_REGION").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            // HOME steers this read exactly as it steers the credentials read above, and it
            // runs even when the credentials came from the environment. It is not credential
            // material, so refusing the whole command over it would be a bad trade: when the
            // borrowed capability is what would make the read succeed, skip the file and let
            // the default region below apply.
            let path = aws_dir().join("config");
            if borrowed && !real_user_can_read(&path) {
                // Only worth a word when the file is really there and really out of the
                // caller's reach. A missing config file is the common case and says nothing.
                if path.exists() {
                    enote!(
                        "s3tap: --auth is not reading {} for the region. This s3tap runs on \
                         borrowed file capabilities and the invoking user cannot read that \
                         file without them. Pass --region or AWS_REGION to choose the region.",
                        path.display()
                    );
                }
                return None;
            }
            // Same shape as `read_credentials_file`, and opened the same way. `openat2` makes
            // each RESOLUTION atomic and forbids symlinks in every component — it does NOT
            // close the gap between `real_user_can_read` above and this open, which are still
            // two syscalls. An attacker who owns a directory in the path can rename a real
            // directory into place between them and the result is perfectly symlink-free.
            // What closes that gap is what follows: the fstat binds the answer to the leaf
            // inode actually opened, and `real_user_can_traverse_to` walks the ancestors of
            // that fd. Do not remove either on the strength of the atomic open.
            // Contained only on borrowed privilege, for the reason given on `open_creds`: a
            // symlinked `$HOME` is ordinary, and without borrowed privilege it leads nowhere
            // the caller could not already read.
            let mut file = if borrowed {
                match open_no_symlinks(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        // SAY SO. Every other failure here is `.ok()?` into `None`, which the
                        // caller turns into us-east-1 — fine when the file is simply absent,
                        // wrong when we refused a file that IS there. A symlink anywhere in
                        // the path to $HOME is ordinary (a home on another mount, a distro
                        // that links /home), so on borrowed privilege this refuses and the
                        // run then signs for the wrong region against a valid bucket and
                        // reports ATTENTION on perfectly good credentials.
                        if e.raw_os_error() == Some(libc::ELOOP) {
                            enote!(
                                "note: --auth is not reading {} on borrowed privilege because a \
                                 symlink appears in its path; falling back to {} for signing. \
                                 Pass --region, set AWS_REGION, or run under sudo with your own \
                                 HOME preserved.",
                                path.display(),
                                "us-east-1"
                            );
                        }
                        return None;
                    }
                }
            } else {
                std::fs::File::open(&path).ok()?
            };
            if borrowed {
                use std::os::unix::fs::MetadataExt;
                let md = file.metadata().ok()?;
                let (uid, groups) = real_user_ids();
                if !dac_readable_by(md.mode(), md.uid(), md.gid(), uid, &groups) {
                    return None;
                }
                if !real_user_can_traverse_to(&file, uid, &groups) {
                    return None;
                }
            }
            let mut cfg = String::new();
            use std::io::Read as _;
            file.read_to_string(&mut cfg).ok()?;
            ini_get(&cfg, &config_section(&profile), "region").filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "us-east-1".into());
    // The region is interpolated into the curl -K config; it's not credential material, so
    // validate its charset (real AWS/S3 region names are LDH) — rejecting any quote/newline
    // that could corrupt or smuggle a directive into the config.
    if !region_is_valid(&region) {
        anyhow::bail!("--auth: region {region:?} is not a valid region name (expected [A-Za-z0-9-])");
    }

    let creds = selftest::AwsCreds { access_key, secret_key, session_token, region };
    // Validate HERE, not only where the curl config is built. A credential comes from an
    // assume-role/OIDC/vault helper, i.e. from a remote service, so a newline in it can
    // smuggle curl directives. Rejected deep in the driver it surfaced as a warning and the
    // run ended on "captured no records — check `sudo s3tap setup`", sending the operator to
    // re-run setcap for a credential problem. Fail fast, as this function's contract promises.
    selftest::reject_unsafe_creds(&creds)?;
    Ok(creds)
}

/// Read the `--auth` credentials file, refusing when the capability this binary carries is
/// what MAKES the read possible.
///
/// After the documented install (`sudo install … /usr/local/bin/s3tap && sudo s3tap setup`)
/// the binary carries `cap_dac_read_search+ep` and is executable by every local user, and
/// glibc's AT_SECURE scrub drops only the `LD_*` family, so HOME survives untouched. Any local
/// user can therefore run `HOME=/root s3tap doctor --live --auth …`: the capability bypasses
/// the DAC check on root's 0600 credentials file and the key plus secret end up in a curl
/// config.
///
/// The gate is "was the capability NEEDED", not "is a capability held". Gating on the latter
/// refused the flag's own documented example: after `sudo s3tap setup` there is no sudo left
/// in the recipe, so `s3tap check my-bucket/key --auth` runs with euid != 0 and a non-empty
/// CapEff on EVERY invocation, and the operator was refused their OWN `$HOME` credentials with
/// a workaround (`sudo env HOME=$HOME …`) that undoes the point of `s3tap setup`. Asking
/// whether the real user could have read the file answers the security question exactly and
/// leaves the documented workflow alone: `HOME=/root` still fails (root's file is 0600), while
/// the caller's own file passes.
///
/// Three checks, because they cover different halves. [`real_user_can_read`] answers the whole
/// PATH question (including the directory traversal a capability also bypasses) but is a
/// separate syscall from the open, so a swap in between could widen it. The fstat re-check
/// binds the answer to the LEAF inode actually opened, which is the one whose bytes become a
/// credential. [`real_user_can_traverse_to`] covers what neither of those two do: the
/// directories in between, re-walked against the path the kernel actually resolved rather than
/// the string that was passed in. Credentials in the ENVIRONMENT are never gated: reading them
/// needs no privilege and they are the caller's own.
fn read_credentials_file(path: &std::path::Path, borrowed: bool) -> anyhow::Result<String> {
    if borrowed && !real_user_can_read(path) {
        return Err(borrowed_cred_refusal(path));
    }
    let mut file = open_creds(path, borrowed)?;
    if borrowed {
        use std::os::unix::fs::MetadataExt;
        let md = file
            .metadata()
            .with_context(|| format!("stat the credentials file {}", path.display()))?;
        let (uid, groups) = real_user_ids();
        if !dac_readable_by(md.mode(), md.uid(), md.gid(), uid, &groups) {
            return Err(borrowed_cred_refusal(path));
        }
        if !real_user_can_traverse_to(&file, uid, &groups) {
            return Err(borrowed_cred_refusal(path));
        }
    }
    let mut body = String::new();
    use std::io::Read as _;
    file.read_to_string(&mut body)
        .with_context(|| format!("--auth: reading {}", path.display()))?;
    Ok(body)
}

/// Open the credentials file, contained ONLY when the privilege is borrowed.
///
/// The containment is not free and must not be charged to everyone. `RESOLVE_NO_SYMLINKS`
/// refuses a symlink in any component, and a symlink in the path to `$HOME` is an ordinary,
/// innocent thing: a home directory on another mount, a distro that links `/home`, a
/// container image that links half of `/`. Applying it unconditionally broke `--auth` for
/// those users with "Too many levels of symbolic links", to defend against an attack that
/// cannot happen to them.
///
/// It cannot happen because the whole guard is about BORROWED privilege. Without it s3tap
/// holds exactly the caller's own authority: it can read what they can read and nothing more,
/// so a symlink in their own `$HOME` leads somewhere they could have read anyway. Following
/// it is what they asked for. With borrowed privilege the same symlink is the attack, so it
/// is refused and the message says why rather than leaving an errno to be interpreted.
fn open_creds(path: &std::path::Path, borrowed: bool) -> anyhow::Result<std::fs::File> {
    let unreadable = |e: &dyn std::fmt::Display| {
        anyhow::anyhow!(
            "--auth: no creds in env (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY) and \
             couldn't read {} ({e})",
            path.display()
        )
    };
    if !borrowed {
        return std::fs::File::open(path).map_err(|e| unreadable(&e));
    }
    open_no_symlinks(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            anyhow::anyhow!(
                "--auth will not follow a symlink to {} on borrowed privilege. This s3tap \
                 carries file capabilities and the effective user is not root, so a symlink \
                 anywhere in that path could point the read at a file you could not otherwise \
                 open. Two ways to run it: under sudo with your own HOME preserved (`sudo env \
                 HOME=$HOME s3tap …`, which is what s3tap's own elevation does) or with the \
                 credentials in AWS_ACCESS_KEY_ID plus AWS_SECRET_ACCESS_KEY.",
                path.display()
            )
        } else {
            unreadable(&e)
        }
    })
}

/// The refusal itself. Pure, so its wording is pinned by a test rather than by a host that
/// happens to be capped.
fn borrowed_cred_refusal(path: &std::path::Path) -> anyhow::Error {
    anyhow::anyhow!(
        "--auth will not read {} on borrowed privilege. This s3tap carries file capabilities, \
         the effective user is not root and the invoking user could not read that file without \
         those capabilities, so HOME is pointing this read at someone else's credentials. Two \
         ways to run it: under sudo with your own HOME preserved (`sudo env HOME=$HOME s3tap \
         …`, which is what s3tap's own elevation does) or with the credentials in \
         AWS_ACCESS_KEY_ID plus AWS_SECRET_ACCESS_KEY.",
        path.display()
    )
}

/// `struct open_how` for [`openat2`]. Mirrored rather than taken from `libc`, whose
/// `open_how` is `#[non_exhaustive]` and so cannot be constructed outside that crate.
/// Three `__u64`s, 24 bytes, no padding — the kernel rejects a `size` it does not know.
#[repr(C)]
#[derive(Default)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open `path` with the WHOLE path resolved in one atomic step and no symlink permitted in
/// any component.
///
/// This is the containment half of the borrowed-privilege credential guard. It does NOT
/// replace the `access(2)` check in [`real_user_can_read`], and that distinction is the whole
/// point: `openat2` opens with the PROCESS's credentials, which on borrowed privilege include
/// `cap_dac_read_search`, so it will happily open a file the invoking user could never read.
/// Only `access(2)` answers "could the REAL user have read this", because the kernel clears
/// the effective capability set for the duration of that call. There is no `openat2`
/// equivalent.
///
/// What it does fix is the RACE the checks were left with. Previously the path was resolved
/// three separate times — once by `access`, once by `open`, once by the `/proc/self/fd`
/// ancestor walk — so a component could be swapped for a symlink between them and the file
/// finally read need not be the file that was checked. `RESOLVE_NO_SYMLINKS` forbids a
/// symlink in EVERY component (not just the last, as `O_NOFOLLOW` would), and
/// `RESOLVE_BENEATH` from `/` makes the resolution refuse to escape. One resolution, one
/// answer, and the fstat/traverse checks below then run against that same fd.
///
/// `RESOLVE_NO_SYMLINKS` is the flag doing the work. `RESOLVE_BENEATH` earns little rooted at
/// `/` — nothing can escape `/`, and every symlink is already refused — but it costs nothing
/// and keeps the intent explicit if the root ever becomes narrower than `/`.
/// `RESOLVE_NO_MAGICLINKS` is passed explicitly rather than relied on: `BENEATH` implies it on
/// today's kernels, and the man page says that may change.
///
/// Falls back to a plain open when the syscall is unavailable (`ENOSYS` below Linux 5.6, or
/// `EPERM` under an old seccomp profile that does not know the number). That is the behaviour
/// this function replaced, and every credential check still runs on the result — a kernel too
/// old for `openat2` is no worse off than before.
fn open_no_symlinks(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    // RESOLVE_BENEATH rejects an ABSOLUTE pathname outright — lexically, on the leading `/`,
    // even when it would land inside the dirfd. So an absolute path is split: `/` becomes the
    // dirfd and the remainder is passed relative to it.
    let (dir, rel) = if path.is_absolute() {
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let rel = path.strip_prefix("/").unwrap_or(path).as_os_str().as_bytes().to_vec();
        (Some(root), rel)
    } else {
        (None, path.as_os_str().as_bytes().to_vec())
    };
    let Ok(c_rel) = std::ffi::CString::new(rel) else {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };
    let dirfd = dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0, // must be 0 without O_CREAT/O_TMPFILE, or the kernel returns EINVAL
        resolve: libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_BENEATH,
    };

    // EAGAIN under BENEATH means the kernel could not prove a rename race was safe, and the
    // man page says the caller may retry. Bounded, because an attacker renaming in a loop
    // could otherwise keep us here forever: a few attempts, then report it.
    for _ in 0..4 {
        // SAFETY: `c_rel` is NUL-terminated and outlives the call; `how` is a fully
        // initialised 24-byte struct whose size we pass explicitly, so the kernel reads
        // nothing beyond it; `dirfd` is either AT_FDCWD or an fd owned by `dir`, which is
        // still alive here.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                c_rel.as_ptr(),
                std::ptr::addr_of!(how),
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd >= 0 {
            // SAFETY: a non-negative openat2 return is a fresh owned fd.
            return Ok(unsafe { std::fs::File::from_raw_fd(fd as std::os::unix::io::RawFd) });
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) => continue,
            // The syscall itself is unavailable: fall back to the pre-openat2 behaviour.
            Some(libc::ENOSYS) | Some(libc::EPERM) => return std::fs::File::open(path),
            _ => return Err(err),
        }
    }
    Err(std::io::Error::other(
        "path kept changing under us while opening (openat2 EAGAIN); refusing to read it",
    ))
}

/// Could the REAL user have read `path` without the capability this binary carries?
///
/// `access(2)`, not `faccessat(…, AT_EACCESS)`: the check has to run as the invoking user, and
/// the kernel's `access_override_creds` CLEARS the effective capability set for the duration of
/// the check whenever the real uid is not root. That is precisely the question here.
/// `AT_EACCESS` would check the EFFECTIVE credentials, capability and all, and answer "yes"
/// every time, gating nothing.
fn real_user_can_read(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false; // an interior NUL is not a path we will open either
    };
    // SAFETY: `c` is NUL-terminated and outlives the call, which only reads through it.
    unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 }
}

/// The real user's uid and its full group list (real gid plus supplementary), for the
/// inode-level re-check. The REAL ids, because they are who the caller is: euid/egid are
/// unchanged by a file-capability grant, but the whole point is to judge the read against the
/// user rather than against what the inode lends us.
fn real_user_ids() -> (u32, Vec<u32>) {
    // SAFETY: getuid/getgid read process credentials and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let mut groups = vec![gid];
    // SAFETY: size 0 with a null pointer is the POSIX "how many groups are there" call, which
    // never writes through the pointer.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n > 0 {
        let mut buf = vec![0 as libc::gid_t; n as usize];
        // SAFETY: `buf` has room for exactly `n` gid_t, which is the count passed in.
        let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
        if got > 0 {
            buf.truncate(got as usize);
            groups.extend(buf);
        }
    }
    (uid, groups)
}

/// Would the DAC bits alone have let `uid` (in `groups`) read this inode? The classic
/// owner/group/other ladder: the FIRST matching class decides, so a 0604 file owned by the
/// caller is NOT readable by them even though "other" may read it. Pure, so the ladder is
/// unit-pinned rather than inferred from whichever file a test host happens to have.
fn dac_readable_by(mode: u32, st_uid: u32, st_gid: u32, uid: u32, groups: &[u32]) -> bool {
    if st_uid == uid {
        return mode & 0o400 != 0;
    }
    if groups.contains(&st_gid) {
        return mode & 0o040 != 0;
    }
    mode & 0o004 != 0
}

/// Could the real user have TRAVERSED to the file already open behind `file`?
///
/// `real_user_can_read`'s `access(2)` answers this for the path string at the moment it runs,
/// and the leaf `dac_readable_by` re-check binds the answer to the inode actually opened, but
/// neither re-verifies the DIRECTORIES in between at open time: a path component (not
/// necessarily the leaf) swapped between the `access(2)` check and the `open(2)` call can steer
/// the open through a directory chain the real user could never enter, onto a world-readable
/// leaf whose own mode bits pass the leaf check regardless of who could reach it. Resolving the
/// path fresh from `/proc/self/fd` (the kernel's own record of what got opened, not the string
/// the caller passed in) and walking every ancestor's search (`x`) bit by the real uid/groups
/// closes that: an attacker now has to win a SECOND race, across this whole walk, rather than
/// one swap in the gap between two syscalls.
fn real_user_can_traverse_to(file: &std::fs::File, uid: u32, groups: &[u32]) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    let Ok(real) = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) else {
        return false;
    };
    let mut dir = real.parent();
    while let Some(d) = dir {
        let Ok(md) = std::fs::symlink_metadata(d) else { return false };
        let mode = md.mode();
        let searchable = if md.uid() == uid {
            mode & 0o100 != 0
        } else if groups.contains(&md.gid()) {
            mode & 0o010 != 0
        } else {
            mode & 0o001 != 0
        };
        if !searchable {
            return false;
        }
        dir = d.parent();
    }
    true
}

/// The `~/.aws/config` section for a profile: `[default]` for the default profile, else
/// `[profile X]` (the config-file convention, distinct from credentials' bare `[X]`).
fn config_section(profile: &str) -> String {
    if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {profile}")
    }
}

/// curl's (major, minor) version from `curl --version` (first line `curl X.Y.Z …`), or
/// `None` if unparseable — used to gate STS-token signing (needs >= 7.86.0).
fn curl_version() -> Option<(u32, u32)> {
    // Absolute, ownership-checked path, never a PATH lookup (see `elevate::helper_path`): a
    // capability-holding s3tap must not run a program the caller's environment chose.
    let out = elevate::helper_command("curl").ok()?.arg("--version").output().ok()?;
    parse_curl_version(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `(major, minor)` from a `curl --version` banner (`curl X.Y.Z …`), or `None` if the
/// second whitespace token isn't an `X.Y…` version. Pure half of [`curl_version`], so the
/// boundary is unit-testable without shelling out.
fn parse_curl_version(banner: &str) -> Option<(u32, u32)> {
    let ver = banner.split_whitespace().nth(1)?; // "curl" "7.81.0" …
    let mut parts = ver.split('.');
    let maj = parts.next()?.parse().ok()?;
    let min = parts.next()?.parse().ok()?;
    Some((maj, min))
}

/// Whether a known curl version is too old to SIGN the `x-amz-security-token` header (needs
/// >= 7.86.0). `None` (unparseable version) is lenient — we don't block when unsure.
fn sts_gate_blocks(curl: Option<(u32, u32)>) -> bool {
    curl.is_some_and(|v| v < (7, 86))
}

/// A region name is valid iff it's non-empty and LDH (`[A-Za-z0-9-]`). Real AWS/S3-compatible
/// region names are LDH; the gate also keeps any quote/newline out of the curl -K config the
/// region is interpolated into.
fn region_is_valid(region: &str) -> bool {
    !region.is_empty() && region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `$AWS_CONFIG_FILE`-style dir: `$HOME/.aws` (HOME via env; falls back to `.`).
fn aws_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&home).join(".aws")
}

/// Minimal AWS-INI reader: the first `key = value` under `[section]` (case-sensitive
/// section + key, `;`/`#` comments ignored). Enough for the credentials/config files.
fn ini_get(body: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = name.trim() == section;
            continue;
        }
        if in_section {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == key {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

#[derive(clap::Args)]
struct SelftestArgs {
    /// S3-style HTTPS endpoint to probe (default: real AWS S3). An unauthenticated
    /// request still exercises DNS→TCP→TLS→HTTP, which is all selftest checks.
    #[arg(long, default_value = "https://s3.amazonaws.com")]
    endpoint: String,
    /// Number of requests the driver issues.
    #[arg(long, default_value_t = 3)]
    requests: u32,
}

/// The observe-time options for the default `run` path.
#[derive(clap::Args)]
struct RunOpts {
    /// Output format. Default: `waterfall` on an interactive terminal, `jsonl`
    /// when piped/redirected (so the machine path stays clean for scripts).
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Include loopback connections (127.0.0.0/8, ::1). They are dropped
    /// in-kernel by default as noise — S3 traffic is never loopback. Useful
    /// against a local S3-compatible endpoint (MinIO, LocalStack, a test proxy).
    #[arg(long)]
    include_loopback: bool,

    /// Print a one-line summary of every raw EVT_* to stderr as it is drained.
    /// A diagnostic for confirming a probe FIRES end-to-end (especially the
    /// uprobes: getaddrinfo and the OpenSSL read/write family) — independent of
    /// whether the event then correlates. Records still go to stdout as usual.
    #[arg(long)]
    dump_events: bool,

    // --- M4 per-app scope (any flag ⇒ in-kernel ALLOWLIST; none ⇒ track all) ---
    /// Restrict capture to these process ids (low-level escape hatch).
    #[arg(long, value_name = "PID")]
    pid: Vec<u32>,
    /// Restrict to an app by its EXE BASENAME, e.g. "python3" (resolved from
    /// /proc/<pid>/exe). Matched at exec (plus a startup /proc scan), and a tracked
    /// process's fork()ed children are followed in-kernel — so a pre-fork server's
    /// workers (gunicorn/uWSGI/Spark) are captured even though they never exec
    /// (best-effort: needs the sched_process_fork tracepoint; a warning prints if it's
    /// unavailable, where --cgroup is the churn-immune fallback). NB the process's own
    /// `comm` is NOT matched: any process can rename itself (prctl PR_SET_NAME) and so
    /// walk into the capture. A basename is still only as trustworthy as the paths local
    /// users can write, so on an untrusted multi-tenant host use --exe (exact path),
    /// --cgroup, or --pid, which can't be forged. A run scoped by name alone that never
    /// matched a process and captured nothing exits 3, so a script can tell a scope that
    /// missed from an app that was quiet.
    ///
    /// A trailing VERSION SUFFIX is stripped before the compare, so --app python3 matches
    /// /usr/bin/python3.12 and --app gcc matches gcc-11. That is required rather than a
    /// convenience: /proc/<pid>/exe is the symlink-RESOLVED path, so on every mainstream
    /// distro the interpreter you name only ever appears under its versioned name. The
    /// suffix must start at a `-` or `.` and be digits from there, so python311 and
    /// python3-shim stay out.
    ///
    /// Resolving ANOTHER user's process needs CAP_SYS_PTRACE, which `s3tap setup` does not
    /// grant (cap_dac_read_search bypasses DAC, not the ptrace check), so a
    /// capability-tagged s3tap matches only processes owned by the user running it. It
    /// warns once when that happens. Run as root, or scope with --pid, --cgroup or
    /// --container.
    #[arg(long, value_name = "NAME")]
    app: Vec<String>,
    /// Restrict to an exact executable path. Like --app, matched at exec / the startup
    /// scan and followed across fork(), so forked workers are captured. The path is
    /// resolved to its absolute form (via /proc/<pid>/exe) at both exec and scan time,
    /// so a relative `./server` invocation still matches an absolute --exe. Same exit-3
    /// contract as --app for a scope that never matched anything.
    #[arg(long, value_name = "PATH")]
    exe: Vec<String>,
    /// Restrict to a cgroup id (as `bpf_get_current_cgroup_id`; see a PROC_EXEC line
    /// under --dump-events). Churn-immune — all the cgroup's processes are in scope.
    #[arg(long, value_name = "ID")]
    cgroup: Vec<u64>,
    /// Restrict to a container by a (full) id/name substring of its v2 cgroup path.
    /// Best-effort: if it captures nothing, cross-check the resolved id against a
    /// PROC_EXEC `cgroup=` line under --dump-events and pass it as --cgroup instead.
    #[arg(long, value_name = "ID|NAME", value_parser = non_blank_container)]
    container: Vec<String>,

    /// Capture TLS PLAINTEXT (the HTTP request/response heads) via OpenSSL uprobes.
    /// Hooks SSL_write/SSL_read plus the OpenSSL 1.1.1+ size_t API,
    /// SSL_write_ex/SSL_read_ex, which is what modern clients call. The _ex pair
    /// is attached only where libssl exports it, so an older library still works.
    /// OFF by default and deliberately so: these are host-wide probes that see
    /// DECRYPTED bytes, including AWS SigV4 Authorization
    /// headers and `x-amz-security-token` STS tokens — usable credentials — for
    /// EVERY process on the host. The default run (connections + SNI) never buffers
    /// those. Enable only when you need L7/HTTP semantics and accept that exposure
    /// (also requires the uprobe caps: `sudo s3tap setup --uprobes`).
    #[arg(long)]
    capture_plaintext: bool,

    /// Treat this host as an S3-compatible endpoint so its bucket is resolved from the
    /// request — path-style `<endpoint>/<bucket>/<key>`, or `<bucket>.<endpoint>`
    /// virtual-hosted. Repeatable. Opt-in: s3tap otherwise recognizes only AWS
    /// hostname patterns and won't guess an arbitrary host is S3 (which could mis-split
    /// a non-S3 API's path). Accepts a bare host or a URL — scheme and port are
    /// stripped — e.g. `--s3-endpoint gateway.storjshare.io` or
    /// `--s3-endpoint https://minio.local:9000`. Only affects bucket/key decoding on
    /// the --capture-plaintext path.
    #[arg(long, value_name = "HOST")]
    s3_endpoint: Vec<String>,

    /// Emit periodic in-flight TCP samples (`s3tap.sample/1`) every N ms while a
    /// connection moves data — the EVOLUTION of cwnd/RTT/throughput/loss the close
    /// snapshot can't show. Library-agnostic (kernel TCP); OFF by default and pays
    /// ZERO overhead when unset (the probe isn't even attached). With no value it
    /// defaults to 100 ms; the minimum is 10 ms. jsonl only. Loud warning if used
    /// without a scope flag (--pid/--app/--exe/--cgroup): in TRACK_ALL the probe
    /// runs on every host-wide RX softirq.
    #[arg(long, value_name = "MS", num_args = 0..=1, default_missing_value = "100")]
    sample_interval_ms: Option<u32>,
}

/// Reject a `--container` token that cannot name a container, at PARSE time.
///
/// A blank one is the case that matters, and it is an accident rather than a typo: an unset
/// `$CID` in a wrapper (`--container "$CID"`) hands the flag whose only job is to RESTRICT the
/// capture a value that means "match everything". `filter::resolve_container` fails closed on
/// it and always must (it is the second line of defence, and the one that also covers a value
/// arriving from anywhere else), but failing closed there costs the operator a whole run to
/// find out. Saying so at the front door costs them a re-typed command.
fn non_blank_container(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() || t.chars().all(|c| c == '/') {
        return Err(
            "a blank --container token cannot name a container, and matching everything is the \
             opposite of what the flag does. Pass the container id or name (a shell variable \
             that expanded to nothing is the usual cause)."
                .to_string(),
        );
    }
    Ok(s.to_string())
}

// Normalize a --s3-endpoint value to a bare lowercase host: strip the scheme, any
// trailing path, and an explicit `:port`. `https://gateway.storjshare.io/` ->
// `gateway.storjshare.io`. Returns None for an empty/garbage value. An IPv6 literal
// (multiple colons) keeps its colons — never an S3 endpoint anyway.
fn normalize_endpoint_host(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s); // drop any path
    let host = match s.rsplit_once(':') {
        Some((h, port))
            if !h.is_empty()
                && !h.contains(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            h
        }
        _ => s,
    };
    let host = host.trim();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

// Config-map slot indices — must match the CFG_* defines in s3tap.bpf.c.
const CFG_DROP_LOOPBACK: u32 = 0;
const CFG_CAPTURE_PLAINTEXT: u32 = 1;
// M4: per-app filter mode (0 = TRACK_ALL, 1 = ALLOWLIST). Set from the scope flags;
// the default run leaves it TRACK_ALL, so the kernel gating is inert.
const CFG_FILTER_MODE: u32 = 2;
const FILTER_ALLOWLIST: u32 = 1;
// In-flight sampler interval in MILLISECONDS (0 = off). The kernel computes
// interval_ns = ms * 1e6 in u64 (no overflow); stored as ms in the u32 slot.
const CFG_SAMPLE_INTERVAL_MS: u32 = 3;

// eBPF map names, as declared in s3tap.bpf.c. These are the lookup keys aya uses
// (the C variable name), so a typo here surfaces only at runtime (map creation
// needs root, so `cargo test` can't catch it) — the `bpf_c_declares_*` tests
// below guard the coupling by reading the C source. NOTE: `config` collides with
// a vmlinux.h typedef, hence `s3tap_config`.
pub(crate) const EVENTS_MAP: &str = "events";
pub(crate) const TLS_EVENTS_MAP: &str = "tls_events";
pub(crate) const SAMPLE_EVENTS_MAP: &str = "sample_events";
const CONFIG_MAP: &str = "s3tap_config";
const RINGBUF_DROPS_MAP: &str = "ringbuf_drops";
/// Scope-loss counters (see `scope_drops` in the C). Slot 0 = a fork()ed child that could not
/// be added to `filter_pids` because the map was full.
const SCOPE_DROPS_MAP: &str = "scope_drops";
/// `scope_drops` slot for a fork-propagation insert that failed.
const SCOPE_FORK_FULL: u32 = 0;
const FILTER_PIDS_MAP: &str = "filter_pids";
const FILTER_CGROUPS_MAP: &str = "filter_cgroups";

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    /// One JSON record per line (s3tap.connection/2 + s3tap.operation/1).
    Jsonl,
    /// A compact human-readable line per record.
    Human,
    /// A phase-aligned latency timeline per operation.
    Waterfall,
    /// One fixed-width row per operation, for scanning a live stream.
    Table,
}

// current_thread: two ring buffers (events + tls_events) but one consumer that
// drains both in one select! — no need for a multi-thread runtime, and it pairs
// with the lean tokio feature set.
/// Which privileges this invocation will need, decided BEFORE anything runs so
/// `elevate::maybe_elevate` can offer sudo up front — instead of failing after
/// the fact with "re-run with sudo". Must stay in sync with what each command
/// actually attaches: `base` = the kernel probes (`./setcap.sh` caps), `uprobes`
/// = the SSL/getaddrinfo uprobe paths (cap_sys_admin), `root` = euid 0 (setcap
/// itself). Pure — unit-tested per command line below.
fn needs_for(cli: &Cli) -> elevate::Needs {
    let (base, uprobes, wants_l7, root) = match &cli.command {
        // Observe live traffic: kernel probes. `--capture-plaintext` is an explicit
        // ask for the decrypted path — REQUIRED there (silently capturing no
        // plaintext would defeat the flag the user typed).
        None => (true, cli.run.capture_plaintext, cli.run.capture_plaintext, false),
        // Asserts the HTTP capability produced a record — it FAILS without the
        // uprobes, so they're required, not merely wanted.
        Some(Command::Selftest(_)) => (true, true, true, false),
        // Offline doctor/advise are pure record consumers. `--live` drives + captures
        // its own workload: it WANTS the L7 rows but degrades to the network floor
        // without them — so it must not force a cap_sys_admin
        // prompt on a base-caps host.
        Some(Command::Doctor(a)) => (a.live, false, a.live, false),
        Some(Command::Advise(_)) => (false, false, false, false),
        // A pure record consumer, like advise.
        Some(Command::Scorecard(_)) => (false, false, false, false),
        // Deep offline study over a trace file — a pure consumer, like advise.
        Some(Command::Analyze(_)) => (false, false, false, false),
        // Same as `doctor --live` (it IS that, with easy-mode defaults). `--map-only`
        // (no-target) never reaches the L7 path at all.
        Some(Command::Check(a)) => (true, false, !(a.target.is_none() && a.map_only), false),
        Some(Command::Setup(_)) => (false, false, false, true),
    };
    elevate::Needs { base, uprobes, wants_l7, root }
}

/// Cheap, PURE argument validation that runs BEFORE self-elevation, so a doomed
/// command line fails immediately instead of asking for a sudo password and
/// *then* rejecting the args. Only the common typos whose check needs no I/O and
/// no privilege — the real command re-validates regardless, this just front-runs
/// the sudo prompt. Returns the same error the command would have produced.
fn preflight(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        // `check my-bucket` (bare bucket, no key) / a bad --region — normalize is
        // pure and is called again in check_cmd; catching it here avoids the prompt.
        Some(Command::Check(a)) => {
            let url = match &a.target {
                Some(t) => Some(normalize_check_target(t, a.region.as_deref())?),
                None => None,
            };
            // `--requests` was validated only deep inside probe_report, so `check
            // --requests 0` ran the whole ~20 s regional sweep and PRINTED the map before
            // failing, on an exit code `check` documents it never produces, in a message
            // naming `--concurrency` (not a `check` flag at all). Judge it here, where the
            // answer is already knowable and nothing has run yet.
            let cap = check_requests_cap(url.as_deref());
            if a.requests == 0 || a.requests > cap {
                anyhow::bail!(
                    "s3tap check --requests must be between 1 and {cap} (got {}). It is how \
                     many keep-alive requests the probe issues against the target. The whole \
                     sequence is materialized as one curl argv, so a longer target URL lowers \
                     the ceiling.",
                    a.requests
                );
            }
        }
        // `doctor --live` with no --endpoint has nothing to drive.
        Some(Command::Doctor(a)) if a.live && a.endpoint.is_empty() => {
            anyhow::bail!("--live requires --endpoint <URL> (a readable S3 object/endpoint)");
        }
        _ => {}
    }
    Ok(())
}

/// The `--requests` ceiling for a `check` invocation, from the URL it will actually drive:
/// the normalized target, or (no target) the longest catalogued public probe object, which
/// is what the map's follow-up health check GETs. Same argv budget as `doctor --live` (see
/// [`max_requests_for_argv`]) so the two commands cannot disagree about the same limit.
fn check_requests_cap(target_url: Option<&str>) -> u32 {
    let longest = match target_url {
        Some(u) => u.len(),
        None => PUBLIC_PROBE_OBJECTS.iter().map(|(_, u)| u.len()).max().unwrap_or(0),
    };
    max_requests_for_argv(longest)
}

/// Where the kernel publishes its own BTF. Its absence is the single clearest signal that
/// this kernel cannot carry a CO-RE object, whatever the capabilities say.
const BTF_VMLINUX: &str = "/sys/kernel/btf/vmlinux";

/// Parse `major.minor` out of a kernel release string (`6.8.0-51-generic`, `5.15.0`, `6.1`).
/// `None` when it is not of that shape, which is deliberately treated as "don't judge".
fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The kernel/BTF gate, split from its I/O so the wording and both refusals are unit-tested.
/// `release` is `/proc/sys/kernel/osrelease`, `btf_present` whether [`BTF_VMLINUX`] exists.
///
/// FAIL CLOSED ONLY ON WHAT WE KNOW. An unparseable release is not a verdict, so it passes:
/// the load will produce its own error and we would rather that than refuse to run on an
/// exotic-but-fine kernel. What we DO know is worth stopping for, because neither cause is
/// fixable by the remedy s3tap otherwise offers. The operator ran `sudo s3tap setup`, it
/// SUCCEEDED, the identical "could not load its probes" came back, and nothing in the loop
/// ever named the kernel.
fn btf_preflight_at(release: Option<&str>, btf_present: bool) -> anyhow::Result<()> {
    if let Some((major, minor)) = release.and_then(parse_kernel_release) {
        if (major, minor) < (5, 8) {
            anyhow::bail!(
                "s3tap needs Linux 5.8 or newer to load its probes. This host runs \
                 {major}.{minor}. Capabilities cannot lift that floor, so `s3tap setup` will \
                 not help. Run s3tap on a newer kernel."
            );
        }
    }
    if !btf_present {
        anyhow::bail!(
            "s3tap needs kernel BTF at {BTF_VMLINUX} to relocate its CO-RE probes. This \
             host has no such file. Either the kernel was built without \
             CONFIG_DEBUG_INFO_BTF (rebuild it or use a distribution kernel), or this is a \
             container that does not expose the host's /sys. In a container, bind-mount it \
             read-only:  -v {BTF_VMLINUX}:{BTF_VMLINUX}:ro  (docker) or the equivalent \
             hostPath volume. This is not a capability problem, so `s3tap setup` will not \
             fix it."
        );
    }
    Ok(())
}

/// [`btf_preflight_at`] against the real host. Called for every command that will load the
/// eBPF object (`needs.base`), before elevation.
fn btf_preflight() -> anyhow::Result<()> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok();
    btf_preflight_at(release.as_deref(), std::path::Path::new(BTF_VMLINUX).exists())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    match dispatch().await {
        // A closed output pipe (e.g. `s3tap | head`) is a normal, clean stop —
        // not an error to print or exit non-zero on.
        Err(e) if is_broken_pipe(&e) => Ok(()),
        // A signal the operator sent is not a failure to report as one: print the stop itself,
        // with no "Error:" and no `Caused by` chain, and take the no-verdict exit code.
        Err(e) if e.downcast_ref::<Interrupted>().is_some() => {
            enote!("{e}");
            std::process::exit(EXIT_TOOL_FAILURE);
        }
        // Every other failure is s3tap failing, NOT a verdict about the capture. Returning
        // the Err would let anyhow's Termination exit 1, which is also ATTENTION: a typo'd
        // `--from` path and a capture with a retransmit warning were the same code, so a CI
        // gate could not distinguish "the workload regressed" from "the command was wrong".
        // Print exactly what anyhow would have (`{:?}` renders the message, the `Caused by`
        // chain and a backtrace when asked) and exit on the reserved code instead.
        Err(e) => {
            enote!("Error: {e:?}");
            std::process::exit(EXIT_TOOL_FAILURE);
        }
        Ok(()) => Ok(()),
    }
}

/// Parse, preflight, elevate, run. Split from `main` so EVERY failure route (including the
/// two that ran before the subcommand did) lands on the one exit-code mapping above rather
/// than on anyhow's implicit exit 1.
async fn dispatch() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Reject obvious typos before prompting for sudo (never ask for a password
    // to then reject the command line).
    preflight(&cli)?;
    let needs = needs_for(&cli);
    // Anything that loads the eBPF object needs a kernel that can carry it. Checked BEFORE
    // elevation because sudo cannot fix a 5.8-floor violation or a missing BTF blob: without
    // this the operator was told to run `s3tap setup`, which SUCCEEDED, and the identical
    // error came back on the re-run with nothing ever naming the real cause.
    if needs.base {
        btf_preflight()?;
    }
    elevate::maybe_elevate(&needs, cli.no_elevate)?;
    match cli.command {
        Some(Command::Selftest(args)) => selftest::run(&args).await,
        // The doctor returns its exit code; the single process::exit is confined here so
        // the code mapping stays a testable pure function.
        Some(Command::Doctor(args)) => match doctor_cmd(&args).await {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Command::Advise(args)) => match advise_cmd(&args) {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Command::Scorecard(args)) => match scorecard_cmd(&args) {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Command::Analyze(args)) => match analyze_cmd(&args) {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Command::Check(args)) => match check_cmd(&args).await {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Command::Setup(args)) => match elevate::setup(args.uprobes, args.remove) {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        None => match run(cli.run).await {
            Ok(0) => Ok(()),
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
    }
}

/// The bare capture agent (no subcommand). Returns the process exit code, like every other
/// command here, so the single `process::exit` stays in `dispatch`: 0 normally, and
/// [`EXIT_NOTHING_CAPTURED`] for a run whose `--app`/`--exe` scope never had a target.
async fn run(cli: RunOpts) -> anyhow::Result<i32> {
    // The eBPF object, compiled by build.rs and embedded here. include_bytes_-
    // aligned! (not plain include_bytes!) because aya's ELF parser needs the
    // bytes aligned.
    let bpf_object = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/s3tap.bpf.o"));

    // M4 F2: resolve the per-app scope flags into a spec BEFORE load — load_and_attach
    // engages the filter (populates the allowlist + flips to ALLOWLIST) before
    // attaching the producer, so no out-of-scope connection is recorded during startup
    // (review round-3 #1). build_filter_spec is pure /proc + cgroup resolution (no bpf).
    let spec = build_filter_spec(&cli)?;
    // A bare capture stays best-effort about fork tracking: it may legitimately be scoped by
    // cgroup or pid to a process that never forks, so a failure there is a warning, not a
    // blocker. `capture_workload` is the one that structurally depends on it.
    let (mut bpf, mut filter) =
        match load_and_attach(
            bpf_object,
            !cli.include_loopback,
            cli.capture_plaintext,
            cli.sample_interval_ms,
            &spec,
        ) {
            Ok(l) => (l.bpf, l.filter),
            Err(e) if is_permission_error(&e) => {
                // args_os, not args(): argv need not be valid Unicode, and the panicking
                // `args()` would turn this friendly "try sudo" message into a panic on a
                // non-UTF-8 argv[0] (elevate.rs takes the same care on the sudo path).
                let exe = std::env::args_os()
                    .next()
                    .map_or_else(|| "s3tap".to_string(), |a| a.to_string_lossy().into_owned());
                anyhow::bail!(
                    "loading eBPF was denied — s3tap needs root or CAP_BPF + CAP_PERFMON.\n\
                     Try:  sudo {exe}\n\
                     (underlying error: {e:#})"
                );
            }
            Err(e) => return Err(e),
        };
    // Was anything in scope once the run STARTED? `engage_filter` has just run this same scan
    // to seed the allowlist, but it cannot hand the count back without changing
    // `load_and_attach`'s signature for its other caller, and the answer is needed at the far
    // end of the run (see `scope_never_matched`). Read AFTER the load, so a run that never
    // gets to capture never pays for it. Only a name-only scope pays at all, being the only
    // shape that can end in the exit-3 refusal.
    let matched_at_start = name_only_scope(&spec) && !filter::scan_matching_pids(&spec).is_empty();
    if let Some(n) = scope_summary(&spec) {
        enote!("s3tap: per-app scope active — {n}");
    } else if cli.sample_interval_ms.is_some() {
        // In TRACK_ALL the sampler's fentry hook runs on every host-wide RX softirq.
        // Loudly warn so the low-overhead edge isn't lost silently.
        enote!(
            "s3tap: WARNING — --sample-interval-ms without a scope flag samples ALL host TCP \
             connections (the fentry hook runs on every received segment system-wide). \
             Pair it with --pid/--app/--exe/--cgroup/--container to bound overhead."
        );
    }

    let ring = RingBuf::try_from(bpf.take_map(EVENTS_MAP).context("no events map")?)?;
    let mut async_fd = AsyncFd::new(ring).context("failed to register ring buffer fd")?;
    // The TLS-plaintext events live on their OWN ring (see s3tap.bpf.c) so a
    // plaintext burst can't drop connect/DNS/SNI. Drained by the same fold; empty
    // unless --capture-plaintext attached the SSL uprobes.
    let tls_ring = RingBuf::try_from(bpf.take_map(TLS_EVENTS_MAP).context("no tls_events map")?)?;
    let mut tls_fd = AsyncFd::new(tls_ring).context("failed to register tls ring buffer fd")?;
    // In-flight TCP samples ride a THIRD isolated ring so a sample burst can't drop
    // connect/close/DNS. Always taken (the map is always allocated); empty unless
    // --sample-interval-ms attached the fentry sampler.
    let sample_ring =
        RingBuf::try_from(bpf.take_map(SAMPLE_EVENTS_MAP).context("no sample_events map")?)?;
    let mut sample_fd = AsyncFd::new(sample_ring).context("failed to register sample ring buffer fd")?;

    // try_new, not new: the correlator needs an OS entropy source for the per-run key-hash
    // salt and REFUSES to run without one (a guessable salt would defeat the dictionary
    // resistance SECURITY.md promises). `new()` expresses that refusal as a panic, so in a
    // distroless/scratch container or a chroot with no /dev/urandom the operator got an
    // exit-101 backtrace instead of the message the correlator went to the trouble of
    // writing. We are already in an anyhow fn, so report it.
    let mut correlator = Correlator::try_new()
        .context("starting the correlator: no usable OS entropy source for the key-hash salt")?;
    // Opt-in custom S3 endpoints (--s3-endpoint): resolve bucket/key for non-AWS
    // S3-compatible hosts (Storj/MinIO/R2/…). Normalized to bare lowercase hosts.
    let s3_endpoints: Vec<String> = cli
        .s3_endpoint
        .iter()
        .filter_map(|s| normalize_endpoint_host(s))
        .collect();
    if !s3_endpoints.is_empty() {
        correlator.set_s3_endpoints(s3_endpoints);
    }
    // Per-run key that obscures the raw sk-pointer in emitted records (see
    // CookieObscurer). Created once so a socket maps to one stable id all run.
    let obscure = CookieObscurer::new();
    // Count ring-buffer records we couldn't decode (see `fold`). Reported once
    // at shutdown so a probe/agent ABI skew can't masquerade as a quiet network.
    let mut undecoded: u64 = 0;
    // Records actually EMITTED this run. Read once at shutdown by `scope_never_matched`:
    // "the scope admitted nothing" only means anything alongside "and nothing was captured".
    let mut emitted: u64 = 0;
    // Record output goes through a channel to a BLOCKING writer task, never straight
    // to stdout on this thread — see RecordSink for why that distinction is the
    // difference between a responsive agent and a silently-dropping one. Status goes to
    // stderr so stdout carries only the records (clean jsonl).
    let (mut out, writer) = RecordSink::spawn();
    // Resolve the output format once: an explicit --format wins; otherwise a tty
    // gets the human waterfall and a pipe/file gets jsonl (scripts stay clean).
    let format = cli.format.unwrap_or_else(|| {
        if std::io::stdout().is_terminal() {
            Format::Waterfall
        } else {
            Format::Jsonl
        }
    });
    // Both signals use a persistent Signal stream created once. A fresh
    // tokio::signal::ctrl_c() future (recreated each select! iteration) is backed
    // by a newly-registered listener that only sees *future* deliveries, so a
    // Ctrl-C arriving during the ring drain — between dropping one future and
    // creating the next — could be missed and need a second press. A persistent
    // Signal latches a pending delivery, so the first Ctrl-C always wins.
    let mut sigint = signal(SignalKind::interrupt()).context("failed to hook SIGINT")?;
    let mut sigterm = signal(SignalKind::terminate()).context("failed to hook SIGTERM")?;
    let scope = if cli.include_loopback {
        "all TCP (incl. loopback)"
    } else {
        "non-loopback TCP"
    };
    enote!("s3tap: listening on {scope}. generate traffic (e.g. curl https://example.com)… (Ctrl-C to stop)");

    // The table format prints its column header once, before the row stream.
    if format == Format::Table {
        writeln!(out, "{}", render::table_header())?;
        out.flush()?;
    }

    // Periodically reap dead pids from the allowlist (filter_pids), so exec churn
    // can't grow it to its cap and a reused pid can't inherit a dead target's slot.
    // 5s (not longer): on a fork-heavy / small-pid_max host the pid space can wrap in
    // tens of seconds, so a long window would let a reused pid be wrongly captured;
    // a reap is just a /proc stat per allowlisted pid — cheap. Inert (arm disabled)
    // when not filtering.
    let mut reap = tokio::time::interval(std::time::Duration::from_secs(5));
    // Delay, not the default Burst: after any stall (a slow consumer, a long drain) Burst
    // replays EVERY missed tick back-to-back, so the loop would run consecutive full /proc
    // scans exactly when the rings are already backed up — piling work onto the recovery.
    // A reap is a liveness sweep, not an accounting tick: skipping the missed ones and
    // resuming the 5s cadence from now loses nothing.
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = reap.tick(), if filter.is_some() => {
                if let Some(f) = filter.as_mut() {
                    f.reap_dead();
                }
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard.context("ring buffer poll failed")?;
                let drained = drain_batch(
                    guard.get_inner_mut(), &mut correlator, &mut out, format,
                    &obscure, &mut undecoded, &mut emitted, cli.dump_events, &mut filter,
                )?;
                out.flush()?;
                // Clear readiness ONLY when the ring emptied; on a batch-cap stop we
                // leave it set so the loop re-polls and the reaper/signal arms run
                // between batches (review M5).
                if drained {
                    guard.clear_ready();
                }
            }
            guard = tls_fd.readable_mut() => {
                let mut guard = guard.context("tls ring buffer poll failed")?;
                // Bounded drain (review M5): a sustained plaintext flood no longer
                // drains to empty before yielding, so it can't starve the 5s reaper or
                // add unbounded head-of-line latency to connect/close/signal handling.
                // No LOSS either way — the kernel ring buffers. TLS plaintext events
                // finalize nothing yet on their own; fold routes them and --dump-events
                // shows them.
                let drained = drain_batch(
                    guard.get_inner_mut(), &mut correlator, &mut out, format,
                    &obscure, &mut undecoded, &mut emitted, cli.dump_events, &mut filter,
                )?;
                out.flush()?;
                if drained {
                    guard.clear_ready();
                }
            }
            guard = sample_fd.readable_mut() => {
                // The isolated sample ring (opt-in --sample-interval-ms). Same bounded
                // drain; a sample burst degrades only samples, never connect/close/DNS.
                let mut guard = guard.context("sample ring buffer poll failed")?;
                let drained = drain_batch(
                    guard.get_inner_mut(), &mut correlator, &mut out, format,
                    &obscure, &mut undecoded, &mut emitted, cli.dump_events, &mut filter,
                )?;
                out.flush()?;
                if drained {
                    guard.clear_ready();
                }
            }
            _ = sigint.recv() => {
                enote!("\ns3tap: Ctrl-C — shutting down.");
                break;
            }
            _ = sigterm.recv() => {
                enote!("\ns3tap: SIGTERM — shutting down.");
                break;
            }
        }
    }

    // The capture loop is over, so nothing else needs this thread: hand the remaining
    // output over by BLOCKING rather than dropping under backpressure. Everything below
    // (the final ring drain, the flush_open_ops aborted operations) is unrecoverable by a
    // re-run, so it is worth waiting for in a way the steady-state loop is not.
    out.block_on_send();

    // Read the kernel-side drop counters BEFORE detaching: once the program is
    // gone no more events (or drops) are produced, and drop(bpf) frees the map.
    // Slot 0 = critical `events` ring; slot 1 = the isolated `tls_events` ring.
    let (crit_drops, tls_drops, proc_drops, sample_drops) = (
        ringbuf_drops(&bpf, 0),
        ringbuf_drops(&bpf, 1),
        ringbuf_drops(&bpf, 2),
        ringbuf_drops(&bpf, 3), // DROP_SAMPLE — the isolated in-flight sample ring
    );
    // Read on the same "before detach" rule as the ring counters above.
    let fork_scope_drops = scope_drops(&bpf, SCOPE_FORK_FULL);

    // Detach the program FIRST so the probe stops producing events. The ring
    // buffer map outlives this drop — we moved it out of `bpf` with take_map, so
    // it is owned by `async_fd`, not freed here — which lets us then drain a
    // quiescent ring with no producer racing behind us. (drop(bpf) also frees
    // the config + sock_ts maps, which the drain does not need.)
    drop(bpf);

    // Final non-blocking drain of ALL THREE rings: emit records for everything still
    // queued at shutdown, including events produced between the signal and detach.
    //
    // ORDER MATTERS: tls_events FIRST, then events (`capture_workload` drains in the same
    // order, for the same reason, and says why at length). `on_close` REMOVES the conns/tls
    // entries that `build_op` reads, so draining a queued close before a response head still
    // sitting in the other ring tears down the state that head needs: a Ctrl-C during a
    // completing GET then recorded a served request as an unanswered abort. The sample ring is
    // independent of both (it folds to its own record type), so it stays last.
    // One timestamp for the entire shutdown flush, the three rings and the open-op flush
    // below included. A consumer sees the capture end as ONE emit event, which is what it
    // was — stamping each ring (or each record) separately would invent boundaries that
    // nothing on the producer side actually has.
    let shutdown_now = batch_now();
    for ring in [tls_fd.get_mut(), async_fd.get_mut(), sample_fd.get_mut()] {
        while let Some(item) = ring.next() {
            if let Some(rec) = fold(&mut correlator, &item, &mut undecoded, cli.dump_events.then_some(&obscure), &mut filter) {
                emit(&mut out, format, &obscure, rec, &shutdown_now)?;
                emitted += 1;
            }
            for op in correlator.take_flushed_ops() {
                emit(&mut out, format, &obscure, Record::Operation(Box::new(op)), &shutdown_now)?;
                emitted += 1;
            }
        }
    }

    // The rings are empty but the CORRELATOR may still hold requests that were in flight
    // when the capture stopped (Ctrl-C mid-request). Without this they vanish, while the
    // identical request interrupted by a TCP close IS emitted by on_close — so "the
    // capture stopped" and "the request never happened" would be indistinguishable in the
    // output. Flush them as aborted ops (the response never completed; a response HEAD
    // already seen keeps its status) and emit exactly as the main loop does. Once, here,
    // after the last fold: an earlier call would emit an op that is still live.
    correlator.flush_open_ops();
    for op in correlator.take_flushed_ops() {
        emit(&mut out, format, &obscure, Record::Operation(Box::new(op)), &shutdown_now)?;
        emitted += 1;
    }

    // Hand the last partial chunk over, read the loss counters while the sink is still
    // alive, then DROP it so the writer task sees end-of-stream and JOIN it. The join is
    // what makes the shutdown drain (and the flush_open_ops flush above) actually reach
    // stdout: without it the process could exit with chunks still queued. Deliberately
    // unbounded — truncating the record stream to escape a wedged downstream reader would
    // trade a visible hang for silent data loss.
    out.flush()?;
    let (out_dropped, out_dropped_bytes) = out.dropped();
    drop(out);
    writer.await.context("the stdout writer task panicked")??;

    // Two distinct loss modes, both reported to stderr (stdout stays clean jsonl)
    // so a lossy run can't masquerade as a quiet network:
    //   - `undecoded`: records the kernel delivered but THIS build couldn't decode
    //     (ABI skew with bpf/include/s3tap_events.h, or an unhandled event type).
    //   - critical-ring drops: connect/close/DNS/SNI the kernel never delivered
    //     (ring full) — these silently strip dns/region or whole records.
    //   - tls-ring drops: plaintext (L7 op) lost on the isolated ring — never a
    //     correctness-critical event (that's the point of the two-ring split).
    if undecoded > 0 {
        enote!(
            "s3tap: WARNING — {undecoded} undecodable ring-buffer record(s) \
             (probe/agent ABI mismatch or an unhandled event type)."
        );
    }
    if crit_drops > 0 {
        enote!(
            "s3tap: WARNING — kernel dropped {crit_drops} critical event(s): ring buffer full. \
             Some connections may be missing DNS/region or whole records."
        );
    }
    if tls_drops > 0 {
        enote!(
            "s3tap: note — dropped {tls_drops} TLS-plaintext event(s) under load \
             (isolated ring; no connection/DNS/SNI data lost)."
        );
    }
    if proc_drops > 0 {
        enote!(
            "s3tap: note — dropped {proc_drops} process-exec notification(s) under load \
             (isolated ring); a forking worker may have been missed by --app/--exe scope."
        );
    }
    // Scope loss, not transport loss. A WARNING rather than a note: a full ring costs
    // records, while this costs whole PROCESSES, and every downstream verdict is then
    // computed over a population that shrank with nothing in the output to say so. The
    // userspace rescan cannot recover these — a descendant admitted purely by
    // fork-propagation is in neither `spec.pids` nor `spec.cgroups` and its exe need match
    // no name scope, so there is nothing to re-derive it from.
    if fork_scope_drops > 0 {
        enote!(
            "s3tap: WARNING — {fork_scope_drops} forked process(es) could not be added to the \
             capture scope: the in-kernel pid allowlist is full (65536 entries). Their S3 \
             traffic is MISSING from this capture. Prefer --cgroup or --container, which need \
             one entry per tree instead of one per process."
        );
    }
    if sample_drops > 0 {
        enote!(
            "s3tap: note — dropped {sample_drops} in-flight TCP sample(s) under load \
             (isolated ring; no connection/DNS/SNI data lost). Raise --sample-interval-ms \
             or narrow the scope if the series looks sparse."
        );
    }
    // A downstream reader slower than the capture: the output queue filled and whole
    // batches of already-formatted records were dropped rather than block the runtime
    // thread (see RecordSink). Reported as a WARNING, like a critical-ring drop, because
    // the emitted stream is INCOMPLETE — a consumer must not read it as a quiet network.
    if out_dropped > 0 {
        enote!(
            "s3tap: WARNING — dropped {out_dropped} output batch(es) ({out_dropped_bytes} bytes) \
             of records: the downstream reader could not keep up with the capture. Write to a \
             file (or a faster consumer) and re-run if you need the full stream."
        );
    }
    // Plaintext writes the kernel admitted (began with an HTTP method) but the parser
    // couldn't turn into an op — a request head split across writes, or a method the
    // kernel gate admits more loosely. Reported so "no S3 traffic" is distinguishable
    // from "S3 traffic the parser dropped" (review Gap C).
    let parse_failures = correlator.parse_failures();
    if parse_failures > 0 {
        enote!(
            "s3tap: note — {parse_failures} captured request head(s) could not be parsed \
             (split across writes, or an unusual method); those S3 ops were not emitted."
        );
    }
    // A name scope that never had a target, now that the run is over and it is a fact rather
    // than the startup warning's prediction. The closing /proc scan runs only when the cheap
    // facts already point at a miss, so an ordinary run never pays for it (and `false` is
    // then the value `scope_never_matched` would ignore anyway).
    let cheap_miss = emitted == 0 && !matched_at_start && name_only_scope(&spec);
    let matching_at_end = cheap_miss && !filter::scan_matching_pids(&spec).is_empty();
    if scope_never_matched(&spec, matched_at_start, matching_at_end, emitted) {
        enote!(
            "s3tap: captured nothing and the scope ({}) matched no process at the start of \
             the run or at the end of it. That is a scope that missed rather than an app \
             that was quiet, so this exits {EXIT_NOTHING_CAPTURED} instead of 0. --app \
             matches the basename of /proc/<pid>/exe, so check yours with `readlink \
             /proc/<pid>/exe`. For a process already running use --pid <tgid>, or \
             --cgroup/--container for a whole tree.",
            scope_summary(&spec).unwrap_or_default()
        );
        return Ok(EXIT_NOTHING_CAPTURED);
    }
    Ok(0)
}

// Read a cumulative ring-buffer-full drop count (by slot) from the BPF counter
// map. A missing/unreadable map or slot yields 0 — a best-effort diagnostic must
// never itself fail the run.
fn ringbuf_drops(bpf: &Ebpf, slot: u32) -> u64 {
    bpf.map(RINGBUF_DROPS_MAP)
        .and_then(|m| Array::<_, u64>::try_from(m).ok())
        .and_then(|a| a.get(&slot, 0).ok())
        .unwrap_or(0)
}

/// Capture the FILTER lost, as opposed to what the transport lost. Separate from
/// [`ringbuf_drops`] on purpose: a ring drop points at ring sizing, a scope drop points at
/// an allowlist that ran out of room, and the remedies share nothing.
///
/// `unwrap_or(0)` covers the kernel that could not attach the fork tracepoint at all, which
/// already warned on its own at attach time.
fn scope_drops(bpf: &Ebpf, slot: u32) -> u64 {
    bpf.map(SCOPE_DROPS_MAP)
        .and_then(|m| Array::<_, u64>::try_from(m).ok())
        .and_then(|a| a.get(&slot, 0).ok())
        .unwrap_or(0)
}

// Assemble the per-app FilterSpec from the scope flags, resolving each --container
// to its cgroup id(s) (warning if a token resolves nothing — likely cgroup v1 or a
// bad id, where --cgroup <id> is the fallback).
pub(crate) fn build_filter_spec(cli: &RunOpts) -> anyhow::Result<FilterSpec> {
    let mut spec = FilterSpec {
        pids: cli.pid.clone(),
        apps: cli.app.clone(),
        exes: cli.exe.clone(),
        cgroups: cli.cgroup.clone(),
    };
    for c in &cli.container {
        let ids = filter::resolve_container(c);
        if ids.is_empty() {
            enote!(
                "warning: --container {c:?} resolved no cgroup (cgroup v1 host or unknown \
                 id?); use --cgroup <id> from a --dump-events PROC_EXEC line instead"
            );
        }
        spec.cgroups.extend(ids);
    }
    // FAIL CLOSED (review M6): the operator asked to RESTRICT capture to a container,
    // but it resolved nothing and no other scope flag is active — so the spec is empty
    // and `install_filter` would leave the kernel in TRACK_ALL, capturing the whole
    // host (including, under --capture-plaintext, every process's decrypted SigV4/STS
    // credentials). A scope that can't be satisfied must never broaden capture: bail
    // rather than silently fall open.
    if !cli.container.is_empty() && !spec.is_active() {
        anyhow::bail!(
            "--container matched no cgroup and no other scope (--pid/--app/--exe/--cgroup) \
             is set — refusing to fall back to host-wide capture. Re-run with --cgroup <id> \
             (from a --dump-events PROC_EXEC line) or a different scope flag."
        );
    }
    Ok(spec)
}

// Populate the kernel allowlist from the spec and flip the mode to ALLOWLIST — using
// borrows only, NO take_map. Called by load_and_attach BEFORE the producer tracepoint
// attaches, so the filter is already engaged when the first event can fire: otherwise
// the producer runs in TRACK_ALL until the flip and emits connect/close events for
// out-of-scope sockets that happen to transition during that window (review round-3 #1
// — a pid=0 husk leaked in the load-test before this). The owned filter_pids handle
// for live exec churn is taken separately AFTER attach (take_map before a program that
// references the map loads makes BPF_PROG_LOAD fail: "fd N is not pointing to valid
// bpf_map"). Ordering within: write the maps FIRST, flip the mode LAST (no empty-
// allowlist window). No-op when no scope flag was given (TRACK_ALL stays inert).
fn engage_filter(bpf: &mut Ebpf, spec: &FilterSpec) -> anyhow::Result<()> {
    if !spec.is_active() {
        return Ok(());
    }
    {
        // cgroup scope is churn-immune (a container's children inherit it).
        let mut cgroups: BpfHashMap<_, u64, u8> =
            BpfHashMap::try_from(bpf.map_mut(FILTER_CGROUPS_MAP).context("no filter_cgroups map")?)?;
        for cg in &spec.cgroups {
            cgroups.insert(*cg, 1u8, 0).context("filter_cgroups insert")?;
        }
    }
    {
        // pid scope: the fixed --pid set + a startup /proc scan for already-running
        // --app/--exe matches.
        let mut pids: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(bpf.map_mut(FILTER_PIDS_MAP).context("no filter_pids map")?)?;
        // The VALUE is the seat's provenance, not a bare "tracked" flag: an explicit --pid is
        // exec-immune, a name match is not, and `handle_sched_process_fork` propagates the
        // byte so descendants inherit the distinction. See `filter::admission_for`.
        for pid in &spec.pids {
            pids.insert(*pid, filter::ADMIT_EXPLICIT, 0).context("filter_pids insert")?;
        }
        let scanned = filter::scan_matching_pids(spec);
        for pid in &scanned {
            // Best-effort in that a full map is not fatal (the periodic rescan retries), but
            // NOT silent: these are workers that were ALREADY RUNNING and matched the scope,
            // so a dropped insert here means the capture starts out missing traffic the
            // operator explicitly asked for. Same invariant as the two live paths in
            // `filter.rs` — surface an insertion failure that can permanently shrink a
            // capture rather than let a thin capture read as a quiet application.
            if pids.insert(*pid, filter::ADMIT_BY_NAME, 0).is_err() {
                filter::warn_allowlist_full_once();
            }
        }
        // An --app/--exe scope that matched nothing engages ALLOWLIST with an empty set, so the
        // run captures nothing and exits 0 with an empty file. Without this the operator cannot
        // tell "my filter missed" from "my app was quiet" and goes off debugging the app.
        if let Some(w) = filter::unmatched_scope_warning(spec, scanned.len()) {
            enote!("s3tap: {w}");
        }
    }
    let mut config: Array<_, u32> =
        Array::try_from(bpf.map_mut(CONFIG_MAP).context("no s3tap_config map")?)?;
    config
        .set(CFG_FILTER_MODE, FILTER_ALLOWLIST, 0)
        .context("failed to set filter mode ALLOWLIST")?;
    Ok(())
}

// Take the owned filter_pids handle for live exec-driven churn, AFTER attach (see
// engage_filter for why the take is deferred). The map was already populated +
// the mode flipped by engage_filter; this only wraps the handle in a `Filter`.
fn take_filter_handle(bpf: &mut Ebpf, spec: &FilterSpec) -> anyhow::Result<Option<Filter>> {
    if !spec.is_active() {
        return Ok(None);
    }
    let pids: BpfHashMap<_, u32, u8> =
        BpfHashMap::try_from(bpf.take_map(FILTER_PIDS_MAP).context("no filter_pids map")?)?;
    Ok(Some(Filter::new(spec.clone(), pids)))
}

/// Is `--app`/`--exe` the WHOLE scope? Those two are the only scope dimensions that can
/// silently match nothing: `--pid` and `--cgroup`/`--container` name a target that either
/// exists (so the scope has something in it) or fails closed at startup. So this is the one
/// shape where an empty capture is ambiguous between "the scope missed" and "the app was
/// quiet", and the only one [`scope_never_matched`] judges.
/// One definition, shared with [`filter::Filter::on_exec`]'s revocation: the same "is the exe
/// the whole story" question decides both.
fn name_only_scope(spec: &FilterSpec) -> bool {
    spec.is_name_only()
}

/// Did a finished run's `--app`/`--exe` scope never once have a target? Pure, so the exit
/// code is pinned by a test rather than by a live capture.
///
/// Round 6 warned at STARTUP and deliberately did not bail, which is right: a matching
/// process may exec later, and that is what `Filter::on_exec` is for. So the prediction is
/// never a refusal. At the END it is no longer a prediction. A scripted run that captured
/// nothing, whose name scope matched no process at either end of the run, has learned that
/// its scope missed, and it must be able to say so with an exit code. A run that DID admit
/// something keeps exit 0: an app that was simply quiet is a legitimate empty capture.
///
/// `matched_at_start` and `matching_at_end` are two /proc scans of the same spec. A process
/// that execed into scope mid-run and is still alive shows up in the second, so mid-run
/// exec churn (the case the startup warning refuses to bail on) keeps its exit 0. The one
/// gap is a matching process that both execed AND exited inside the window without moving a
/// byte, which reads as a miss. Closing it needs an admission flag off `Filter::on_exec`,
/// which is a bigger change than the ambiguity it removes.
fn scope_never_matched(
    spec: &FilterSpec,
    matched_at_start: bool,
    matching_at_end: bool,
    records: u64,
) -> bool {
    records == 0 && name_only_scope(spec) && !matched_at_start && !matching_at_end
}

// A short human summary of the active scope, for the startup banner (None ⇒ TRACK_ALL).
fn scope_summary(spec: &FilterSpec) -> Option<String> {
    if !spec.is_active() {
        return None;
    }
    let mut parts = Vec::new();
    if !spec.pids.is_empty() {
        parts.push(format!("{} pid(s)", spec.pids.len()));
    }
    if !spec.apps.is_empty() {
        parts.push(format!("app {:?}", spec.apps));
    }
    if !spec.exes.is_empty() {
        parts.push(format!("exe {:?}", spec.exes));
    }
    if !spec.cgroups.is_empty() {
        parts.push(format!("{} cgroup(s)", spec.cgroups.len()));
    }
    Some(parts.join(", "))
}

// Decode one raw ring-buffer record and feed it to the correlator, returning a
// finished Connection record when a close completes one. A record we cannot
// decode (bad schema version, unknown type, wrong length) bumps `undecoded`
// rather than vanishing silently — every record in OUR ring buffer comes from
// OUR probe, so a decode failure is always a probe/agent ABI skew (or a new
// event type the agent doesn't handle yet), never normal. Surfacing it at
// shutdown keeps an empty run from looking identical to "no traffic."
pub(crate) fn fold(
    c: &mut Correlator,
    bytes: &[u8],
    undecoded: &mut u64,
    // `Some(obscurer)` = `--dump-events`. Not a `bool`: the dump prints raw sock_cookies, so
    // the caller must supply the obscurer to get one at all.
    dump: Option<&CookieObscurer>,
    filter: &mut Option<Filter>,
) -> Option<Record> {
    let Some(event) = Event::parse(bytes) else {
        *undecoded += 1;
        return None;
    };
    if let Some(obscure) = dump {
        dump_event(&event, obscure);
    }
    match event {
        Event::TcpConnect(e) => c.on_connect(&e).map(|x| Record::Connection(Box::new(x))),
        Event::TcpClose(e) => c.on_close(&e).map(|x| Record::Connection(Box::new(x))),
        // Opt-in periodic in-flight TCP sample (EVT_TCP_SAMPLE). Stateless map to a
        // TcpSample record, emitted on the cookie alone (the doctor joins by cookie).
        Event::TcpSample(e) => c.on_tcp_sample(&e).map(|x| Record::TcpSample(Box::new(x))),
        // DNS events update resolution state but never finalize a record on
        // their own — they surface later as the `dns` block of a connection.
        Event::DnsQuery(e) => {
            c.on_dns_query(&e);
            None
        }
        Event::DnsResponse(e) => {
            c.on_dns_response(&e);
            None
        }
        Event::Getaddrinfo(e) => {
            c.on_getaddrinfo(&e);
            None
        }
        // A TLS ClientHello records the connection's SNI; it surfaces later as
        // the `tls` block (and SNI-derived region) of the connection record.
        Event::TlsHandshake(e) => {
            c.on_tls_handshake(&e);
            None
        }
        // S2: the ServerHello's NEGOTIATED version + cipher (parsed off ingress). Merges
        // into the connection's TLS facts; finalizes nothing.
        Event::TlsServer(e) => {
            c.on_tls_server(&e);
            None
        }
        // M3 E5: plaintext SSL_write/SSL_read prefixes -> S3 operation delimitation.
        // A request head opens an op; a response head closes + emits it. on_tls_write
        // also emits when the concurrency guard flushes a prior op as ambiguous.
        Event::TlsWrite(e) => c.on_tls_write(&e).map(|op| Record::Operation(Box::new(op))),
        Event::TlsRead(e) => c.on_tls_read(&e).map(|op| Record::Operation(Box::new(op))),
        // M3.5: a length-only response BODY read — tallied toward Content-Length; emits
        // the op (with download_ns/total_ns) once the body is fully observed.
        Event::TlsReadBody(e) => c.on_tls_read_body(&e).map(|op| Record::Operation(Box::new(op))),
        // M3 E4: the (tgid,fd)->cookie mapping. Recorded so the plaintext path (E5)
        // can resolve a TLS event's (tgid,fd) to its connection. Finalizes nothing.
        // CONN_ID and the EVT_TLS_* it maps share the `tls_events` ring, so for one
        // connection the CONN_ID (at connect) is always drained before its plaintext
        // (after handshake) — the join is reliably resolvable in-order. (CONN_ID is
        // cross-ring with EVT_TCP_CLOSE on `events`, but that only makes close-time
        // link cleanup best-effort, never a mis-join — see on_close.)
        Event::ConnId(e) => {
            c.on_conn_id(&e);
            None
        }
        // M4 F2: a process exec. If it matches --app/--exe, add its tgid to the
        // kernel filter_pids so a freshly-forked worker is captured immediately.
        // (Only arrives in ALLOWLIST mode, so `filter` is Some whenever this fires.)
        Event::ProcExec(e) => {
            if let Some(f) = filter.as_mut() {
                f.on_exec(&e);
            }
            None
        }
    }
}

/// Max records drained from one ring per readiness before yielding back to the
/// select! loop. Bounds the head-of-line stall a plaintext flood can impose on the
/// other arms — crucially the 5s reaper, which would otherwise be starved (its timer
/// never serviced) while a busy ring drains to empty, letting filter_pids grow to its
/// cap (review M5). Large enough that the per-batch select! overhead is negligible.
const DRAIN_BATCH: usize = 256;

/// Drain up to [`DRAIN_BATCH`] records from a ready ring, emitting each folded record.
/// Returns `true` if the ring EMPTIED (the caller clears readiness), `false` if the
/// batch cap was hit with more likely queued — in which case the caller leaves
/// readiness SET (does not call `clear_ready`), so the next select! iteration re-polls
/// and the reaper/signal arms get a fair turn between batches. Clearing readiness only
/// on a truly empty ring honors AsyncFd's edge-triggered contract (clear only on the
/// WouldBlock-equivalent), so no readiness edge is ever missed.
// Each parameter is genuinely distinct per-drain state (the ring, the fold/emit
// context, and the output sink); bundling them into a struct would only obscure.
#[allow(clippy::too_many_arguments)]
fn drain_batch<W: Write>(
    ring: &mut RingBuf<aya::maps::MapData>,
    correlator: &mut Correlator,
    out: &mut W,
    format: Format,
    obscure: &CookieObscurer,
    undecoded: &mut u64,
    emitted: &mut u64,
    dump: bool,
    filter: &mut Option<Filter>,
) -> anyhow::Result<bool> {
    // ONE clock read for the whole batch — this loop IS the unit the `emitted_at` contract
    // is written in terms of. Taken before the first `ring.next()` so an empty drain costs
    // nothing beyond it.
    let now = batch_now();
    for _ in 0..DRAIN_BATCH {
        let Some(item) = ring.next() else {
            return Ok(true); // ring drained — safe to clear readiness
        };
        if let Some(rec) = fold(correlator, &item, undecoded, dump.then_some(obscure), filter) {
            emit(out, format, obscure, rec, &now)?;
            *emitted += 1;
        }
        // A close may also flush an in-flight op (request sent, no response).
        for op in correlator.take_flushed_ops() {
            emit(out, format, obscure, Record::Operation(Box::new(op)), &now)?;
            *emitted += 1;
        }
    }
    Ok(false) // hit the batch cap; more may remain
}

/// One compact stderr line per raw event, for `--dump-events`. The E3 visibility
/// harness: it proves a probe FIRES (the event reached userspace) independent of
/// whether it then correlates — so an "attaches but no-ops" uprobe, or a fires-
/// but-doesn't-join event, is distinguishable from a quiet network. Lossy by
/// design (debug output); the big name tails are decoded leniently.
fn dump_event(event: &Event, obscure: &CookieObscurer) {
    enote!("s3tap[evt] {}", dump_line(event, obscure));
}

/// The formatted line, split out from [`dump_event`] so the obscuring is testable without
/// capturing stderr.
///
/// Every `sock_cookie` goes through the SAME `CookieObscurer` the record path uses. The raw
/// value is the kernel `struct sock *`, a KASLR signal, and this is debug output a user is
/// especially likely to tee into a file or paste into a bug report — so it was the one place
/// the pointer escaped while `README.md`, `SECURITY.md` and the schema all promised it never
/// leaves the process. Taking the obscurer by argument rather than reaching for a global is
/// what makes "dump without obscuring" unrepresentable: `fold` carries `Option<&CookieObscurer>`
/// rather than a bare `bool`, so there is no way to ask for the dump without supplying one.
fn dump_line(event: &Event, obscure: &CookieObscurer) -> String {
    fn name(buf: &[u8], len: u8) -> String {
        String::from_utf8_lossy(&buf[..(len as usize).min(buf.len())]).into_owned()
    }
    match event {
        Event::TcpConnect(e) => format!(
            "TCP_CONNECT  tgid={} cookie={} fam={} dport={} failed={}",
            e.hdr.tgid, obscure.apply(e.hdr.sock_cookie), e.family, e.dport, e.connect_failed
        ),
        Event::TcpClose(e) => format!(
            "TCP_CLOSE    tgid={} cookie={} sent={} recv={} rtx={}",
            e.hdr.tgid, obscure.apply(e.hdr.sock_cookie), e.bytes_sent, e.bytes_recv, e.retransmit_count
        ),
        Event::TcpSample(e) => format!(
            "TCP_SAMPLE   cookie={} cwnd={} srtt_us={} recv={} inflight={} ooo={}",
            obscure.apply(e.hdr.sock_cookie), e.snd_cwnd, e.srtt_us, e.bytes_recv, e.bytes_in_flight, e.rcv_ooopack
        ),
        Event::DnsQuery(e) => format!(
            "DNS_QUERY    tgid={} cookie={} txn={} qname={:?}",
            e.hdr.tgid, obscure.apply(e.hdr.sock_cookie), e.txn_id, name(&e.qname, e.qname_len)
        ),
        Event::DnsResponse(e) => format!(
            "DNS_RESPONSE tgid={} cookie={} payload_len={}",
            e.hdr.tgid, obscure.apply(e.hdr.sock_cookie), e.payload_len
        ),
        Event::Getaddrinfo(e) => format!(
            "GETADDRINFO  tgid={} ret={} latency_ns={} saw_wire={} host={:?}",
            e.hdr.tgid, e.ret, e.latency_ns, e.saw_wire_activity, name(&e.hostname, e.hostname_len)
        ),
        Event::TlsHandshake(e) => format!(
            "TLS_HELLO    tgid={} cookie={} sni={:?}",
            e.hdr.tgid, obscure.apply(e.hdr.sock_cookie), name(&e.sni, e.sni_len)
        ),
        Event::TlsServer(e) => format!(
            "TLS_SERVER   cookie={} version=0x{:04x} cipher=0x{:04x}",
            obscure.apply(e.hdr.sock_cookie), e.version, e.cipher
        ),
        Event::TlsWrite(e) => tls_data_line("TLS_WRITE", e),
        Event::TlsRead(e) => tls_data_line("TLS_READ ", e),
        Event::TlsReadBody(e) => format!(
            "TLS_BODY     tgid={} fd={} body_bytes={}",
            e.hdr.tgid, e.fd, e.plaintext_len
        ),
        Event::ConnId(e) => format!(
            "CONN_ID      tgid={} fd={} cookie={}",
            e.hdr.tgid, e.fd, obscure.apply(e.hdr.sock_cookie)
        ),
        // comm (prctl PR_SET_NAME) and exe (crafted exec'd filename) are attacker-
        // controlled; the `{:?}` Debug format ESCAPES control bytes (ANSI/CR/NL), so
        // this line can't be used to inject into the operator's terminal. Keep `{:?}`
        // here — switching to `{}` (Display) would reintroduce the injection.
        Event::ProcExec(e) => format!(
            "PROC_EXEC    tgid={} cgroup={} comm={:?} exe={:?}{}",
            e.hdr.tgid,
            e.cgroup_id,
            String::from_utf8_lossy(e.comm_str()),
            String::from_utf8_lossy(e.exe_path()),
            if e.exe_truncated != 0 { " (truncated)" } else { "" }
        ),
    }
}

/// Summary line for a plaintext SSL_write/SSL_read event. Shows ONLY the captured
/// prefix's first line (request/status line) — never header lines, so the
/// `Authorization` / `x-amz-security-token` headers are not printed. The request
/// PATH (the object key — which the record only ever stores hashed, and which can
/// be PII) is replaced with `/<key>`, and the query's SigV4 secrets are scrubbed;
/// the line is `{:?}`-escaped (no terminal injection). Bytes via `captured()`.
fn tls_data_line(label: &str, e: &s3tap_events::EvtTlsData) -> String {
    let first_line = e.captured().split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(&[]);
    let scrubbed = redact_request_line(&String::from_utf8_lossy(first_line));
    format!(
        "{label}   tgid={} fd={} plen={} cap={}{} first={scrubbed:?}",
        e.hdr.tgid,
        e.fd,
        e.plaintext_len,
        e.captured_len,
        if e.captured_truncated != 0 { " TRUNC" } else { "" },
    )
}

/// Redact the captured first line for `--dump-events`: if it's an HTTP request
/// line (`METHOD /path?query HTTP/1.x`), replace the PATH (the object key — stored
/// only hashed on the record, and possibly PII) with `/<key>` and scrub the query's
/// SigV4 secrets. Status lines and non-request-shaped lines pass through the SigV4
/// scrub unchanged.
fn redact_request_line(line: &str) -> String {
    // A request line is "METHOD SP target [SP HTTP/1.x]". The target — origin-form
    // "/path" or absolute-form "http://host/path" — IS the object key and must be
    // redacted even when the captured line was TRUNCATED past the version token (a
    // >4 KiB request line), is absolute-form, or carries an unexpected space (review
    // L3/L10). The old "exactly 3 space-parts ending in HTTP/1." shape let all three
    // fall through to the query-only scrub, leaking the path. Key the decision on the
    // METHOD + a path-shaped target instead, so the version token is irrelevant.
    if let Some((method, rest)) = line.split_once(' ') {
        if is_http_method(method) {
            let (target, tail) = match rest.split_once(' ') {
                Some((t, tail)) => (t, Some(tail)),
                None => (rest, None),
            };
            if is_request_target(target) {
                let q = target
                    .split_once('?')
                    .map(|(_, query)| format!("?{}", scrub_query(query)))
                    .unwrap_or_default();
                // Echo the version only when the tail is EXACTLY a clean HTTP/1.x
                // token — no trailing bytes. `HTTP/1.1 <anything>` would otherwise echo
                // the rest of the line verbatim (review F6: a smuggled SigV4 secret or
                // key after the version leaks unscrubbed). Anything else is omitted.
                let version = match tail {
                    Some(t) if t.starts_with("HTTP/1.") && !t.bytes().any(|b| b == b' ' || b == b'\t') => {
                        format!(" {t}")
                    }
                    _ => String::new(),
                };
                return format!("{method} /<key>{q}{version}");
            }
        }
    }
    scrub_aws_sigv4(line)
}

/// A plausible HTTP method token for redaction (short, all-uppercase) — mirrors the
/// in-kernel admission gate and `http::is_token`.
fn is_http_method(s: &str) -> bool {
    !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// A request target whose path is the object key: origin-form (`/…`) or absolute-form.
fn is_request_target(t: &str) -> bool {
    t.starts_with('/') || t.starts_with("http://") || t.starts_with("https://")
}

/// Query parameters whose VALUE may be shown in `--dump-events`. Everything else is
/// redacted, so this list is the entire attack surface of the request-line display: each
/// entry is a public S3 sub-resource or selector that identifies WHICH object/upload the
/// request addresses, never WHO may perform it.
///
/// Deliberately absent: anything that encodes a key or a prefix (`prefix`,
/// `continuation-token`, `marker`, `response-content-disposition`) — the object key is
/// stored only hashed and must not come back through the query — and, of course, every
/// credential parameter.
const SAFE_QUERY_KEYS: [&str; 7] =
    ["versionid", "partnumber", "uploadid", "list-type", "delete", "uploads", "session"];

/// Scrub a request-line QUERY STRING for display, by ALLOWLIST: parse it into `k=v` pairs
/// and keep a value only if its key is in [`SAFE_QUERY_KEYS`].
///
/// This inverts the policy that used to live here. A denylist of the SigV4 parameter names
/// only redacted the signing scheme it had been told about, and a presigned URL is a
/// complete, replayable capability for that object until it expires — printed into the
/// operator's terminal and any teed log. SigV2 presigning (`Signature`, `AWSAccessKeyId`,
/// `Expires`) sailed straight through, and it is neither dead nor obscure: S3 still accepts
/// it on legacy buckets and it is the DEFAULT presign format of several S3-compatible
/// gateways. The next scheme, or a gateway's proprietary token parameter, would have
/// sailed through too. With an allowlist the default for an unrecognized parameter is
/// "redact", so being wrong costs a diagnostic detail instead of a credential.
///
/// The key NAME is kept (it says which parameter was redacted, which is the diagnostic
/// value) and a valueless flag parameter (`?uploads`, `?acl`) passes through as-is.
fn scrub_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        let Some((key, value)) = pair.split_once('=') else {
            out.push_str(pair); // a bare sub-resource flag: no value to leak
            continue;
        };
        out.push_str(key);
        out.push('=');
        if SAFE_QUERY_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
            out.push_str(value);
        } else {
            // Uniform regardless of the value (an empty one included), so the output
            // never hints at the length or presence of a secret.
            out.push_str("REDACTED");
        }
    }
    out
}

/// Redact presigned-URL secrets from a line that is NOT a parsed query string — the
/// fallback for a status line, a truncated head, or any captured first line that isn't
/// request-shaped, where there is no `k=v` structure to apply [`scrub_query`]'s allowlist
/// to and blanking the whole line would destroy the diagnostic. Needle-based by necessity,
/// so it covers BOTH presigning schemes: SigV4 (`X-Amz-*`) and SigV2 (`Signature`,
/// `AWSAccessKeyId`, `Expires`), which S3 still honors on legacy buckets and which several
/// S3-compatible gateways presign with by default.
///
/// Case-insensitive on the param name; the value runs to the next `&`, whitespace, or end.
fn scrub_aws_sigv4(line: &str) -> String {
    let lower = line.to_ascii_lowercase(); // 1:1 on bytes, so offsets index `line` too
    let mut spans: Vec<(usize, usize)> = Vec::new();
    // NB `signature=` also covers the `x-amz-signature=` case, and `awsaccesskeyid=` the
    // SigV2 key id; they are listed separately so removing one never silently widens a gap.
    for needle in [
        "x-amz-signature=",
        "x-amz-credential=",
        "x-amz-security-token=",
        // SigV2 presigned parameters — a complete replayable capability on their own.
        "signature=",
        "awsaccesskeyid=",
        "expires=",
    ] {
        let mut from = 0;
        // `.get(from..)` (NOT `lower[from..]`): a needle at end-of-line drives `from`
        // to line.len(), and slicing there would panic — crashing the agent in the
        // drain loop (review F4, a DoS on `--capture-plaintext --dump-events`).
        while let Some(rel) = lower.get(from..).and_then(|s| s.find(needle)) {
            let val_start = from + rel + needle.len(); // just past "=" (a char boundary)
            let val_end = line[val_start..]
                .find(['&', ' ', '\t'])
                .map_or(line.len(), |d| val_start + d);
            spans.push((val_start, val_end));
            // Advance past this match; clamp so an empty value at EOL can't overshoot.
            from = val_end.max(val_start + 1).min(line.len());
        }
    }
    if spans.is_empty() {
        return line.to_string();
    }
    // Coalesce overlapping/nested spans — a secret value can lexically contain another
    // needle with no delimiter (review F3), which previously double-applied a stale
    // offset and garbled the output. Merge into disjoint ranges, then rebuild
    // left-to-right so every offset indexes the ORIGINAL line and stays valid.
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let mut out = String::with_capacity(line.len());
    let mut pos = 0;
    for (s, e) in merged {
        out.push_str(&line[pos..s]);
        out.push_str("REDACTED");
        pos = e;
    }
    out.push_str(&line[pos..]);
    out
}

// Obscures the raw sk-pointer `sock_cookie` at the output boundary. The cookie
// is the kernel `struct sock *` value — a KASLR signal we must not ship off-box,
// but which we DO need as a stable per-socket join key. A per-run random key
// (SipHash, via std's RandomState) maps each pointer to one stable opaque id for
// the life of the process: correlation across a socket's records still holds,
// the real address never leaves the host, and the id is meaningless across runs.
struct CookieObscurer(RandomState);

impl CookieObscurer {
    fn new() -> Self {
        CookieObscurer(RandomState::new())
    }

    // 0 is the "N/A" sentinel (header docs: 0 if not applicable) — keep it 0 so
    // the meaning survives. Any real pointer maps to a stable nonzero-ish hash.
    fn apply(&self, raw: u64) -> u64 {
        if raw == 0 {
            return 0;
        }
        let mut h = self.0.build_hasher();
        h.write_u64(raw);
        h.finish()
    }
}

/// How many finished output chunks may queue between the capture loop and the blocking
/// stdout writer. A chunk is one drain batch (at most [`DRAIN_BATCH`] records) or one
/// [`RECORD_CHUNK_BYTES`] slab, so this is a few MiB of slack: enough to ride out a
/// consumer that pauses to do work, small enough that a consumer which is permanently
/// slower than the capture is REPORTED as loss instead of buffered without bound.
const OUTPUT_QUEUE: usize = 256;

/// Hand the in-progress chunk over once it reaches this size. The shutdown drain emits a
/// whole ring with no intervening `flush`, so without this one chunk could grow to hold
/// the entire backlog.
const RECORD_CHUNK_BYTES: usize = 64 * 1024;

/// The record stream's output sink: formats on the runtime thread, writes on another.
///
/// WHY THIS EXISTS. The agent runs on a `current_thread` runtime, so a plain
/// `BufWriter<Stdout>` put a BLOCKING `write(2)` on the ONLY runtime thread. Under
/// `s3tap --format jsonl | <slow consumer>` the pipe fills, the flush parks that thread
/// inside the write, and while it is parked NOTHING is polled: not the three ring fds,
/// not the SIGINT/SIGTERM arms. The kernel `events` ring (256 KiB) then overflows and
/// drops connect/close/DNS/SNI events PERMANENTLY, and Ctrl-C is swallowed for the whole
/// stall so the agent merely looks hung. The slow consumer is the common case (`| jq`,
/// `| tee`, a terminal), which made this the loudest failure mode of the capture loop.
///
/// The split: rendering stays here — ordering and each record's `emitted_at` are still
/// decided at emit time, so the byte stream is unchanged — and only the I/O moves to a
/// `spawn_blocking` task behind a bounded channel. `flush` hands the finished chunk over
/// with a NON-blocking `try_send`. When the queue is full the chunk is DROPPED and
/// counted, mirroring how the kernel drops ring records under the same backpressure and
/// reported at shutdown next to those counters. Dropping records we can name and count is
/// strictly better than the old behaviour, which dropped kernel events we cannot.
struct RecordSink {
    /// The chunk being assembled. Split only at a newline, so a dropped chunk costs
    /// whole records rather than half a JSON line.
    buf: Vec<u8>,
    tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    /// Once the capture loop has stopped, wait for the writer instead of dropping — see
    /// [`RecordSink::block_on_send`].
    blocking: bool,
    dropped_chunks: u64,
    dropped_bytes: u64,
}

impl RecordSink {
    /// Spawn the writer task and return the sink feeding it. The task owns the only
    /// `BufWriter<Stdout>`; join its handle at shutdown so every queued chunk lands
    /// before the process exits.
    ///
    /// A std `sync_channel` rather than `tokio::sync::mpsc`: the consumer is a blocking
    /// thread that wants a blocking `recv`, the producer only ever does `try_send`, and
    /// neither side needs to be awaited — so this needs no extra tokio feature.
    fn spawn() -> (RecordSink, tokio::task::JoinHandle<std::io::Result<()>>) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(OUTPUT_QUEUE);
        let handle = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut out = BufWriter::new(std::io::stdout());
            // `recv` ends when the sink — the only sender — is dropped at shutdown.
            while let Ok(chunk) = rx.recv() {
                out.write_all(&chunk)?;
                // Flush per chunk, as the old per-drain flush did: records stay prompt
                // for a downstream `… | jq` rather than sitting in the buffer.
                out.flush()?;
            }
            out.flush()
        });
        let sink = RecordSink {
            buf: Vec::with_capacity(RECORD_CHUNK_BYTES),
            tx,
            blocking: false,
            dropped_chunks: 0,
            dropped_bytes: 0,
        };
        (sink, handle)
    }

    /// (chunks, bytes) dropped because the writer could not keep up.
    fn dropped(&self) -> (u64, u64) {
        (self.dropped_chunks, self.dropped_bytes)
    }

    /// Stop dropping under backpressure and WAIT for the writer instead. Called once the
    /// capture loop has broken out: from then on the probe is detached and the rings are
    /// quiescent, and no arm of the select! needs this thread, so blocking costs nothing —
    /// while dropping would lose the shutdown drain and the aborted in-flight operations
    /// `flush_open_ops` produces, which are the one part of the stream a re-run cannot
    /// recreate.
    fn block_on_send(&mut self) {
        self.blocking = true;
    }

    fn send(&mut self, chunk: Vec<u8>) -> std::io::Result<()> {
        if self.blocking {
            return self.tx.send(chunk).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the stdout writer stopped (downstream reader closed)",
                )
            });
        }
        match self.tx.try_send(chunk) {
            Ok(()) => Ok(()),
            // Full queue: the consumer is slower than the capture. Drop and COUNT rather
            // than block — blocking here is precisely the failure this type removes.
            Err(std::sync::mpsc::TrySendError::Full(chunk)) => {
                self.dropped_chunks += 1;
                self.dropped_bytes += chunk.len() as u64;
                Ok(())
            }
            // The writer task is gone, which for stdout means the reader closed the pipe
            // (`s3tap | head`). Surface the BrokenPipe `main` maps to a clean exit 0.
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the stdout writer stopped (downstream reader closed)",
            )),
        }
    }
}

impl Write for RecordSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= RECORD_CHUNK_BYTES {
            // Cut at the LAST newline so the boundary is a record boundary. `writeln!`
            // reaches this in several fragments per record, so splitting on size alone
            // could hand over half a line — and if the next chunk were then dropped, the
            // stream would carry a truncated JSON record instead of one fewer record.
            if let Some(nl) = self.buf.iter().rposition(|&b| b == b'\n') {
                let rest = self.buf.split_off(nl + 1);
                let chunk = std::mem::replace(&mut self.buf, rest);
                self.send(chunk)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::take(&mut self.buf);
        self.send(chunk)
    }
}

/// The wall clock for one emitted BATCH, in the format every `emitted_at` uses.
///
/// Taken ONCE per drain and handed to every `emit` in it. Reading it per record split a
/// single flush into N distinct emit times, which a consumer cannot tell from N separate
/// flushes — the schema states this contract on `Operation::emitted_at` and says explicitly
/// that the fix belongs here rather than in a loosened contract.
fn batch_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

// Stamp the wall-clock emit time, obscure the sk-pointer, and write the record in
// the chosen format. Both record types carry the raw sk-pointer cookie, so both go
// through the same obscurer at this single output boundary.
//
// `now` is the BATCH's timestamp (see `batch_now`), passed in rather than read here: every
// record from one drain must carry the same emit time.
fn emit<W: Write>(
    out: &mut W,
    format: Format,
    obscure: &CookieObscurer,
    rec: Record,
    now: &str,
) -> std::io::Result<()> {
    let now = now.to_string();
    match rec {
        Record::Connection(mut conn) => {
            conn.emitted_at = Some(now);
            conn.sock_cookie = obscure.apply(conn.sock_cookie);
            match format {
                // Our own struct always serializes; a failure is a bug, not input.
                Format::Jsonl => writeln!(out, "{}", serde_json::to_string(&conn).expect("serialize")),
                // The `table` is operation-scoped (fixed OP/BUCKET/… columns); a
                // socket-only Connection has no row schema, so emitting its free-form
                // line would break the column alignment — skip it in table mode (it
                // still appears in jsonl/human/waterfall).
                Format::Table => Ok(()),
                // Human/Waterfall are free-form; a Connection's compact line fits.
                _ => writeln!(out, "{}", human(&conn)),
            }
        }
        Record::Operation(mut op) => {
            op.emitted_at = Some(now);
            op.sock_cookie = obscure.apply(op.sock_cookie);
            match format {
                Format::Jsonl => writeln!(out, "{}", serde_json::to_string(&op).expect("serialize")),
                Format::Human => writeln!(out, "{}", human_op(&op)),
                Format::Waterfall => writeln!(out, "{}\n", render::waterfall(&op)),
                Format::Table => writeln!(out, "{}", render::table_row(&op)),
            }
        }
        // Telemetry, not a per-op row: jsonl only (skipped in human/waterfall/table).
        Record::TcpSample(mut s) => {
            s.emitted_at = Some(now);
            s.sock_cookie = obscure.apply(s.sock_cookie);
            match format {
                Format::Jsonl => writeln!(out, "{}", serde_json::to_string(&s).expect("serialize")),
                _ => Ok(()),
            }
        }
    }
}

// A compact one-line summary of an S3 operation record (--format human).
fn human_op(op: &Operation) -> String {
    let bytes = |b: Option<u64>| b.map_or_else(|| "-".to_string(), |n| format!("{n}B"));
    // ttfb is the headline op latency (request -> first response byte); omit the
    // segment entirely when it wasn't measured.
    let ttfb = op
        .ttfb_ns
        .map_or_else(String::new, |ns| format!("  ttfb={:.2}ms", ns as f64 / 1e6));
    format!(
        "op#{} {} {}{}{}  status={}{}  sent={} recv={}  pid={}{}",
        op.req_seq,
        // Non-S3 ops carry no s3_op, so show the raw HTTP verb instead of "?". Sanitized
        // for defense-in-depth (enum-constrained on the live path, but keep it safe anyway).
        render::sanitize_term(op.s3_op.as_deref().or(op.verb.as_deref()).unwrap_or("?")),
        // bucket is attacker-controlled (path-style request line); strip control
        // bytes so it can't inject ANSI/CR/NL into the terminal (see render::sanitize_term).
        render::sanitize_term(op.bucket.as_deref().unwrap_or("?")),
        op.key_hash.as_deref().map(|_| "/<key>").unwrap_or(""),
        if op.connection_reused { "  (reused)" } else { "" },
        op.http_status.map_or_else(|| "-".to_string(), |s| s.to_string()),
        ttfb,
        bytes(op.op_bytes_sent),
        bytes(op.op_bytes_recv),
        op.app.pid,
        if op.partial { "  partial" } else { "" },
    )
}

// A compact one-line summary of a connection record. `status` reflects what we
// actually observed (the Connection record has no "reused" concept — that's
// Operation-only — so we never claim reuse here).
fn human(c: &Connection) -> String {
    let ip = c.endpoint.endpoint_ip.as_deref().unwrap_or("?");
    let port = c.endpoint.dport.map_or_else(|| "?".to_string(), |p| p.to_string());
    let status = if c.connect_failed {
        "FAILED".to_string()
    } else if let Some(ns) = c.tcp_connect_ns {
        format!("connect={:.2}ms", ns as f64 / 1e6)
    } else if c.partial {
        "incomplete".to_string() // close seen, no connect — connection predated us
    } else {
        "established".to_string() // observed up, no connect-latency sample (e.g. passive)
    };
    let srtt = c
        .srtt_us
        .map_or_else(|| "-".to_string(), |u| format!("{:.1}ms", u as f64 / 1000.0));
    let life = c
        .lifetime_ns
        .map_or_else(|| "-".to_string(), |ns| format!("{:.1}s", ns as f64 / 1e9));
    // Surface the M3 SNI / region (the headline of the connection). The SNI is
    // hostname-charset-sanitized upstream (qname_str), so it's safe to print to a
    // terminal verbatim. Omit the segment entirely when neither is known.
    let s3 = match (c.endpoint.region.as_deref(), c.tls.sni.as_deref()) {
        (Some(r), Some(sni)) => format!("  region={r} sni={sni}"),
        (Some(r), None) => format!("  region={r}"),
        (None, Some(sni)) => format!("  sni={sni}"),
        (None, None) => String::new(),
    };
    format!(
        "{ip}:{port}  pid={}  {status}  sent={}B recv={}B  rtx={}  srtt={srtt}  life={life}{s3}",
        c.app.pid, c.bytes_sent, c.bytes_recv, c.retransmits,
    )
}

// Load the object, push runtime config, engage the per-app filter, attach the
// programs, and return the live Ebpf handle plus the `Filter` (if a scope is set).
// Config is set after load (the map exists once loaded) but before attach, so the
// program never observes an unset config. The filter is ENGAGED (maps populated +
// mode flipped to ALLOWLIST) before attaching the producer tracepoint, so no event
// ever fires in TRACK_ALL on a scoped run — closing the startup leak window (round-3
// #1). The owned filter_pids handle is taken AFTER attach (take_map before the
// referencing program loads breaks BPF_PROG_LOAD).
/// Raise `RLIMIT_MEMLOCK` before loading, because BELOW KERNEL 5.11 every BPF map is
/// charged against it and the default soft limit is 64 KiB — nowhere near enough for this
/// object's maps.
///
/// Without this, s3tap could not load on its own documented hard floor. On v5.8 map
/// creation failed with EPERM even as ROOT, and the error path then blamed capabilities
/// ("grant them with `sudo s3tap setup`, or run under sudo") at a user who was already
/// root, so the advice could not work. 5.11 moved BPF memory to memcg accounting, which is
/// why this never showed up on a modern dev box.
///
/// The kernel matrix does not catch it either, and that is worth stating: `bpf-verify.sh`
/// loads through `bpftool`, which raises this limit itself. So the matrix proves the
/// programs VERIFY on 5.8 while saying nothing about whether the AGENT can load them there.
///
/// Best-effort by design. Raising the SOFT limit up to the hard limit needs no privilege;
/// raising the hard limit needs CAP_SYS_RESOURCE, which `s3tap setup` deliberately does not
/// grant, so a capability-tagged run on an old kernel gets whatever the hard limit allows.
/// A failure here is never fatal: the load below reports the real outcome.
fn raise_memlock_rlimit() {
    // SAFETY: getrlimit/setrlimit only read and write this struct, which outlives the calls.
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) != 0 {
            return;
        }
        // Try for infinity first (succeeds as root / with CAP_SYS_RESOURCE), then settle for
        // soft = hard, which any process may do and is all an unprivileged run can get.
        let infinity =
            libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &infinity) == 0 {
            return;
        }
        if lim.rlim_cur < lim.rlim_max {
            let raised = libc::rlimit { rlim_cur: lim.rlim_max, rlim_max: lim.rlim_max };
            let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised);
        }
    }
}

/// What a successful load produced. `fork_tracking` is a field rather than a third tuple
/// slot because a bare `bool` at the call site says nothing about which of several
/// best-effort probes it refers to.
pub(crate) struct Loaded {
    pub(crate) bpf: Ebpf,
    pub(crate) filter: Option<Filter>,
    /// Whether `sched_process_fork` ATTACHED, not merely loaded.
    ///
    /// The distinction is the whole point. `attach_fork_tracking` reads BTF, loads the
    /// program, then attaches it, so the kernel-shaped failures (no BTF, no such tracepoint,
    /// a verifier reject) all leave it unloaded and were already detectable by inspecting the
    /// program set. What was NOT detectable is a load that succeeds and an attach that then
    /// fails — an LSM or seccomp policy permitting `BPF_PROG_LOAD` while refusing
    /// `BPF_RAW_TRACEPOINT_OPEN`. That reads as "attached" from the outside, and a
    /// pid-scoped capture whose workload is a forked child would then record nothing at all
    /// while reporting only a warning.
    pub(crate) fork_tracking: bool,
}

pub(crate) fn load_and_attach(
    obj: &[u8],
    drop_loopback: bool,
    capture_plaintext: bool,
    sample_interval_ms: Option<u32>,
    spec: &FilterSpec,
) -> anyhow::Result<Loaded> {
    raise_memlock_rlimit();
    let mut bpf = Ebpf::load(obj).context("failed to load eBPF object")?;

    let mut config: Array<_, u32> =
        Array::try_from(bpf.map_mut(CONFIG_MAP).context("no s3tap_config map")?)?;
    config
        .set(CFG_DROP_LOOPBACK, u32::from(drop_loopback), 0)
        .context("failed to set drop-loopback config")?;
    // Gate the EVT_CONN_ID (tgid,fd)->cookie join on plaintext capture — its only
    // consumer is the plaintext path, so the default run emits no conn-id events.
    config
        .set(CFG_CAPTURE_PLAINTEXT, u32::from(capture_plaintext), 0)
        .context("failed to set capture-plaintext config")?;
    // M4: per-app filter mode. Always start at TRACK_ALL (0) — the gating is inert;
    // install_filter() flips it to ALLOWLIST (1) only after the maps are populated
    // (so there's no empty-allowlist window). Set explicitly, not via zero-init.
    config
        .set(CFG_FILTER_MODE, 0, 0)
        .context("failed to set filter-mode config")?;
    // In-flight sampler interval (ms; 0 = off, the default). Written before attach so
    // the kernel never reads an unwritten slot; the program also bails on interval 0.
    // Floored at 10 ms to bound volume.
    let sample_ms = sample_interval_ms.map(|ms| ms.max(10)).unwrap_or(0);
    config
        .set(CFG_SAMPLE_INTERVAL_MS, sample_ms, 0)
        .context("failed to set sample-interval config")?;

    // Engage the per-app filter (populate maps + flip to ALLOWLIST) BEFORE attaching
    // any producer below, so a scoped run never emits a TRACK_ALL event during a
    // startup window (round-3 #1). Borrows only — the owned handle is taken after
    // attach via take_filter_handle.
    engage_filter(&mut bpf, spec)?;

    // M4 / review H2: propagate allowlist membership across fork() so pre-fork workers
    // that never exec (gunicorn/uWSGI/Spark) are captured. Self-gates on ALLOWLIST mode
    // like the exec tracepoint. Best-effort — a kernel that rejects/lacks it still runs,
    // just without fork propagation (the prior behavior), so don't fail the load on it.
    //
    // FIRST, before any producer. The invariant is that filtering is fully engaged before
    // anything can emit or make a scope decision, and attaching this after the TCP and exec
    // tracepoints broke it: a tracked parent could fork in that window and the child was
    // never propagated, so its later S3 connections were silently out of scope. The window
    // was small, which is exactly what makes it the kind of under-capture nobody notices.
    //
    // What that costs depends on the scope, and only ONE of the three is unrecoverable:
    //   * `--pid`      — lost for good if the child never execs. It is in no name scope, so
    //                    `reap_dead`'s rescan has nothing to re-derive it from.
    //   * `--app`/`--exe` — recovered by that rescan, since a fork shares the parent's exe.
    //   * `--cgroup`/`--container` — never affected: `in_scope()` looks the cgroup up per
    //                    event, so an inheriting child needs no `filter_pids` entry at all.
    //
    // A residual window remains and is worth stating rather than implying it is closed:
    // `engage_filter` above does the startup /proc scan, so a fork between that scan and
    // this attach is still unpropagated. Moving the attach ABOVE the scan would not help —
    // the handler looks the PARENT up in `filter_pids`, and during the scan the parent may
    // not be in it yet. Per the list above this leaves `--pid` with a microsecond-wide gap,
    // which is narrower than the one this reorder closes and needs a different design to
    // remove entirely.
    let fork_tracking = match attach_fork_tracking(&mut bpf) {
        Ok(()) => true,
        Err(e) => {
            enote!(
                "warning: fork-propagation tracepoint unavailable ({e:#}); pre-fork workers \
                 (gunicorn/uWSGI) may be missed under --app/--exe — prefer --cgroup for those"
            );
            false
        }
    };

    let prog: &mut TracePoint = bpf
        .program_mut("handle_set_state")
        .context("program handle_set_state not found in object")?
        .try_into()?;
    prog.load().context("kernel verifier rejected handle_set_state")?;
    prog.attach("sock", "inet_sock_set_state")
        .context("failed to attach inet_sock_set_state tracepoint")?;

    // M4 F1: process-exec tracking for per-app (--app/--exe) churn. Attached always
    // (cheap), but the program self-gates on ALLOWLIST mode, so it emits nothing on a
    // default TRACK_ALL run — only once a filter flag (F2) sets CFG_FILTER_MODE.
    let exec: &mut TracePoint = bpf
        .program_mut("handle_sched_process_exec")
        .context("program handle_sched_process_exec not found in object")?
        .try_into()?;
    exec.load().context("kernel verifier rejected handle_sched_process_exec")?;
    exec.attach("sched", "sched_process_exec")
        .context("failed to attach sched_process_exec tracepoint")?;

    // In-flight TCP sampler (opt-in --sample-interval-ms): attach the fentry probe ONLY
    // when sampling is requested, so a default run never pays the per-segment hook cost.
    // Best-effort — if fentry/tcp_rcv_established is unattachable on this kernel, warn
    // and continue (the rest of the capture is unaffected).
    if sample_interval_ms.is_some() {
        if let Err(e) = attach_tcp_sampler(&mut bpf) {
            enote!(
                "warning: in-flight sampler unavailable ({e:#}); --sample-interval-ms had no \
                 effect (no s3tap.sample/1 records will be emitted)"
            );
        }
    }

    // DNS wire probes (M2) + the TLS ClientHello probe (M3). kprobes on the
    // UDP/TCP send/recv paths; the programs self-filter (port 53 for DNS, the
    // ClientHello signature for TLS). (program name in the object, kernel fn.)
    for (prog_name, hook) in [
        ("handle_udp_sendmsg", "udp_sendmsg"),
        ("handle_skb_consume_udp", "skb_consume_udp"),
        ("handle_tcp_sendmsg", "tcp_sendmsg"),
    ] {
        let p: &mut KProbe = bpf
            .program_mut(prog_name)
            .with_context(|| format!("program {prog_name} not found in object"))?
            .try_into()?;
        p.load()
            .with_context(|| format!("kernel verifier rejected {prog_name}"))?;
        p.attach(hook, 0)
            .with_context(|| format!("failed to attach kprobe {hook}"))?;
    }

    // TLS ServerHello ingress probe (S2) — NEGOTIATED version + cipher. BEST-EFFORT: a new
    // hot-path program, so a verifier reject (or a kernel that lacks/inlines tcp_data_queue)
    // must NOT sink the rest of the load — we just lose the negotiated version and fall back
    // to the handshake-timing inference (~1x RTT = 1.3, ~2x = 1.2).
    {
        let p: &mut KProbe = bpf
            .program_mut("handle_tcp_data_queue")
            .context("program handle_tcp_data_queue not found in object")?
            .try_into()?;
        if let Err(e) = p.load() {
            enote!("warning: TLS ServerHello probe rejected by the verifier ({e:#}); \
                       negotiated version falls back to the handshake-timing inference");
        } else if let Err(e) = p.attach("tcp_data_queue", 0) {
            enote!("warning: TLS ServerHello probe could not attach ({e:#})");
        }
    }

    // getaddrinfo uprobe + uretprobe on libc (M2). OPTIONAL enhancement: supplies
    // resolver-call latency and the nscd/cache-hit signal. A failure here is a
    // warning, not fatal — the agent still captures connections and wire DNS;
    // only the getaddrinfo-derived latency/cache-hit is lost (records fall back
    // to dns.via = "wire"). Two reasons it can fail where the kprobes don't:
    // attaching a uprobe via perf_event_open needs more than CAP_BPF+CAP_PERFMON
    // on some kernels (observed: EPERM under cap_bpf,cap_perfmon,
    // cap_dac_read_search), and uprobes are inherently fragile (stripped or musl
    // libc, missing/renamed symbol). Don't let an optional probe sink capture.
    if let Err(e) = attach_getaddrinfo(&mut bpf) {
        enote!(
            "warning: getaddrinfo uprobe unavailable ({e:#}); continuing without \
             resolver latency / cache-hit detection (DNS falls back to via:\"wire\")"
        );
    }

    // OpenSSL plaintext uprobes on libssl (M3 E3) — OFF unless --capture-plaintext.
    // SECURITY: these see DECRYPTED bytes host-wide, including AWS credentials
    // (SigV4 Authorization, x-amz-security-token), so capturing them is an explicit
    // opt-in, not a default. When enabled it's still best-effort (same stance as
    // getaddrinfo): a failure warns and the agent keeps emitting connection records
    // + SNI. Reaches OpenSSL/libssl only (Go crypto/tls, rustls, static BoringSSL
    // have no SSL_* symbols — those keep socket metrics + SNI but no plaintext op).
    if capture_plaintext {
        // The (tgid,fd)->cookie join (E4) — attached ONLY under capture (its only
        // consumer is the plaintext path), so the default run pays no connect-rate
        // overhead and a no-IPv6 host (tcp_v6_connect absent) still starts. Best-
        // effort: a failure means plaintext ops degrade to fd-0/partial, not abort.
        if let Err(e) = attach_conn_id(&mut bpf) {
            enote!(
                "warning: conn-id join unavailable ({e:#}); TLS plaintext ops will be \
                 partial (no (tgid,fd)->connection mapping)"
            );
        }
        if let Err(e) = attach_openssl(&mut bpf) {
            enote!(
                "warning: OpenSSL uprobes unavailable ({e:#}); continuing without \
                 TLS plaintext / HTTP semantics (connection records + SNI still emitted)"
            );
        }
    }

    // Now that every program is loaded, take the owned filter_pids handle for live
    // exec churn (deferred until after attach — see engage_filter).
    let filter = take_filter_handle(&mut bpf, spec)?;
    Ok(Loaded { bpf, filter, fork_tracking })
}

// Attach the sched_process_fork tracepoint (review H2): in-kernel propagation of
// allowlist membership to forked children, so pre-fork workers that never exec are
// captured. Self-gates on ALLOWLIST mode, so it's inert on a default TRACK_ALL run.
// Called best-effort by load_and_attach — a kernel that rejects it must not abort the
// agent (it just loses fork propagation).
fn attach_fork_tracking(bpf: &mut Ebpf) -> anyhow::Result<()> {
    // A BTF tracepoint (tp_btf) so the program receives the typed child `task_struct`
    // and can read its tgid to skip thread clones (see the C). Needs kernel BTF, which
    // CO-RE already requires; attach is best-effort in the caller.
    let btf = Btf::from_sys_fs().context("read kernel BTF (/sys/kernel/btf/vmlinux)")?;
    let fork: &mut BtfTracePoint = bpf
        .program_mut("handle_sched_process_fork")
        .context("program handle_sched_process_fork not found in object")?
        .try_into()?;
    fork.load("sched_process_fork", &btf)
        .context("kernel verifier rejected handle_sched_process_fork")?;
    fork.attach().context("failed to attach sched_process_fork btf tracepoint")?;
    Ok(())
}

// Attach the in-flight TCP sampler (opt-in --sample-interval-ms). An fentry on
// tcp_rcv_established — fires per received segment of an ESTABLISHED socket (data on a
// GET, ACKs on a PUT), cheaper per-call than a kprobe, and needs kernel BTF (already a
// CO-RE requirement). Best-effort in the caller: if fentry is unavailable the run
// continues without samples. (A kprobe/tcp_rcv_established fallback reusing the same
// inline core is the documented break-glass.)
fn attach_tcp_sampler(bpf: &mut Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs().context("read kernel BTF (/sys/kernel/btf/vmlinux)")?;
    let prog: &mut FEntry = bpf
        .program_mut("handle_tcp_sample")
        .context("program handle_tcp_sample not found in object")?
        .try_into()?;
    prog.load("tcp_rcv_established", &btf)
        .context("kernel verifier rejected handle_tcp_sample")?;
    prog.attach().context("failed to attach fentry tcp_rcv_established")?;
    Ok(())
}

// Attach the E4 (tgid,fd)->cookie probes (only under --capture-plaintext). The
// connect() syscall entry stashes the fd; tcp_v{4,6}_connect emit the mapping with
// the sk cookie. tcp_v6_connect is best-effort — absent when IPv6 is compiled out
// (CONFIG_IPV6=n); IPv4 connects still map, IPv6 ones degrade to fd-0/partial.
fn attach_conn_id(bpf: &mut Ebpf) -> anyhow::Result<()> {
    // Attach the CONSUMERS (tcp_v*_connect, which read+delete connect_fd) BEFORE the
    // PRODUCER (handle_connect_enter, which stashes) — same discipline as getaddrinfo.
    // A partial failure then can't leave a producer stashing into connect_fd on every
    // host-wide connect() with no consumer to drain it.
    let p: &mut KProbe = bpf
        .program_mut("handle_tcp_v4_connect")
        .context("program handle_tcp_v4_connect not found")?
        .try_into()?;
    p.load().context("kernel verifier rejected handle_tcp_v4_connect")?;
    p.attach("tcp_v4_connect", 0).context("failed to attach kprobe tcp_v4_connect")?;

    // IPv6 best-effort: warn but don't fail the join if the symbol is absent.
    let p6: &mut KProbe = bpf
        .program_mut("handle_tcp_v6_connect")
        .context("program handle_tcp_v6_connect not found")?
        .try_into()?;
    p6.load().context("kernel verifier rejected handle_tcp_v6_connect")?;
    if let Err(e) = p6.attach("tcp_v6_connect", 0) {
        enote!("note: tcp_v6_connect kprobe not attached ({e}); IPv6 plaintext ops will be partial");
    }

    // Producer last.
    let tp: &mut TracePoint = bpf
        .program_mut("handle_connect_enter")
        .context("program handle_connect_enter not found in object")?
        .try_into()?;
    tp.load().context("kernel verifier rejected handle_connect_enter")?;
    tp.attach("syscalls", "sys_enter_connect")
        .context("failed to attach sys_enter_connect tracepoint")?;

    // The stash's EXACT lifetime: sys_exit_connect deletes it, so an entry exists only
    // while its own connect() is in flight. That replaces a wall-clock freshness bound
    // which failed both ways — a thread preempted past it (cgroup cpu.max, vCPU steal)
    // lost its conn_id silently, while a resolver's unconsumed UDP stash was still
    // FRESH enough for a later io_uring or TFO connect to pick up and misattribute.
    // Attached AFTER the enter probe so the consumers-before-producers rule above still
    // holds: this one only ever DELETES, so it can never orphan a stash. The kernel
    // reads a flag this sets to know the exit probe is live, and keeps the old bound
    // until it is, so a partial attach degrades rather than breaking the join.
    let tpx: &mut TracePoint = bpf
        .program_mut("handle_connect_exit")
        .context("program handle_connect_exit not found in object")?
        .try_into()?;
    tpx.load().context("kernel verifier rejected handle_connect_exit")?;
    tpx.attach("syscalls", "sys_exit_connect")
        .context("failed to attach sys_exit_connect tracepoint")?;
    Ok(())
}

// Attach the libssl uprobes (M3 E3): SSL_set_fd (SSL*->fd map), SSL_write (entry,
// request plaintext), SSL_read (entry-stash + uretprobe, response plaintext). Best
// -effort; resolves libssl by absolute path (aya's bare soname resolves to the
// wrong inode — same bug fixed for libc; the agent doesn't link libssl so we find
// it via ldconfig, not /proc/self/maps). Order: the SSL_read EXIT (uretprobe) goes
// on before its ENTRY so a half-attach can't leave a dangling entry filling
// ssl_read_inflight with nothing to delete it (same discipline as getaddrinfo).
fn attach_openssl(bpf: &mut Ebpf) -> anyhow::Result<()> {
    let libssl = ldconfig_lib_path("libssl.so")
        .or_else(|| host_lib_path("libssl.so"))
        .context("libssl not found (ldconfig / /proc/self/maps)")?;
    // (program in object, exported symbols it attaches to). One program may cover
    // several symbols (the fd-setters share a body); a symbol missing from this
    // libssl (e.g. SSL_set_rfd on an odd build) is best-effort — it warns but does
    // not sink the program, as long as AT LEAST ONE of its symbols attached.
    //
    // Order is DELETER-before-PRODUCER throughout (review L4): SSL_free (the sole
    // deleter of ssl_fd) goes on before SSL_set_fd (its producer), and each EXIT before
    // its ENTRY — so a half-attach that bails on `ensure!(any)` can never leave a
    // host-wide producer stashing into a map with no reaper attached. That now covers
    // the WRITE pair as well: its entry stashes into `ssl_write_inflight` and only its
    // exit deletes from it. (The uretprobe-vs-uprobe distinction comes from each
    // program's SEC(), so the attach call is identical.)
    for (prog_name, symbols) in [
        ("handle_ssl_free", &["SSL_free"][..]),
        ("handle_ssl_set_fd", &["SSL_set_fd", "SSL_set_rfd", "SSL_set_wfd"][..]),
        ("handle_ssl_write_exit", &["SSL_write"][..]),
        ("handle_ssl_write", &["SSL_write"][..]),
        ("handle_ssl_read_exit", &["SSL_read"][..]),
        ("handle_ssl_read_entry", &["SSL_read"][..]),
    ] {
        let p: &mut UProbe = bpf
            .program_mut(prog_name)
            .with_context(|| format!("program {prog_name} not found in object"))?
            .try_into()?;
        p.load()
            .with_context(|| format!("kernel verifier rejected {prog_name}"))?;
        let mut any = false;
        for symbol in symbols {
            match p.attach(Some(*symbol), 0, &libssl, None) {
                Ok(_) => any = true,
                Err(e) => enote!("note: libssl {symbol} not attached ({e})"),
            }
        }
        anyhow::ensure!(any, "no symbol attached for {prog_name}");
    }
    // OPTIONAL: OpenSSL 1.1.1+ SSL_write_ex / SSL_read_ex. Modern clients (Python's
    // _ssl, Node, anything built against OpenSSL 3) call these instead of the classic
    // SSL_write/SSL_read, so without them those clients' L7 plaintext is invisible
    // (their connection + SNI are still captured by the kernel probes). Purely
    // additive and best-effort: an OpenSSL 1.0 libssl lacks these symbols, so a miss
    // only notes — the required classic probes above stay attached. EXIT-before-ENTRY,
    // same dangling-entry discipline as the classic read pair.
    if attach_optional_uprobe(bpf, "handle_ssl_write_ex_exit", "SSL_write_ex", &libssl) {
        let _ = attach_optional_uprobe(bpf, "handle_ssl_write_ex", "SSL_write_ex", &libssl);
    }
    if attach_optional_uprobe(bpf, "handle_ssl_read_ex_exit", "SSL_read_ex", &libssl) {
        let _ = attach_optional_uprobe(bpf, "handle_ssl_read_ex_entry", "SSL_read_ex", &libssl);
    }
    Ok(())
}

// Load + attach a single uprobe, swallowing every failure into a `false` (with a
// note) rather than an error — for symbols that may legitimately be absent (e.g. the
// OpenSSL `_ex` variants on an old libssl). Never sinks the caller's other probes.
fn attach_optional_uprobe(bpf: &mut Ebpf, prog_name: &str, symbol: &str, lib: &str) -> bool {
    let Some(prog) = bpf.program_mut(prog_name) else {
        enote!("note: {prog_name} not in object");
        return false;
    };
    let p: &mut UProbe = match prog.try_into() {
        Ok(p) => p,
        Err(_) => {
            enote!("note: {prog_name} is not a uprobe");
            return false;
        }
    };
    if let Err(e) = p.load() {
        enote!("note: {prog_name} not loaded ({e})");
        return false;
    }
    match p.attach(Some(symbol), 0, lib, None) {
        Ok(_) => true,
        Err(e) => {
            enote!("note: libssl {symbol} not attached ({e})");
            false
        }
    }
}

// Resolve a shared library's absolute path from the ldconfig cache, by soname
// prefix (e.g. "libssl.so" matches "libssl.so.3"). For libs the agent does NOT
// itself map (so host_lib_path can't find them). None if ldconfig is unavailable
// or no match.
fn ldconfig_lib_path(prefix: &str) -> Option<String> {
    // Absolute, ownership-checked path, never a PATH lookup (see `elevate::helper_path`).
    // This one picks the libssl the uprobes attach to, so a caller-chosen `ldconfig` would
    // choose which library a privileged process instruments.
    let out = elevate::helper_command("ldconfig").ok()?.arg("-p").output().ok()?;
    let listing = String::from_utf8(out.stdout).ok()?;
    listing.lines().find_map(|line| {
        // "  libssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3"
        let line = line.trim_start();
        if !line.starts_with(prefix) {
            return None;
        }
        line.rsplit("=>").next().map(|p| p.trim().to_string())
    })
}

// Attach the getaddrinfo entry+exit uprobes on libc. `None` pid attaches to all
// processes; "libc" resolves to the system libc via the dynamic loader. Split
// out so the caller can treat the whole optional probe as best-effort.
//
// Order matters: attach the EXIT (uretprobe) first, ENTRY (uprobe) last. The
// attaches aren't transactional — if the second fails we warn and run with the
// first still live (load_and_attach treats this whole fn as best-effort). A
// dangling *exit* probe is harmless (it only looks up + deletes gai_inflight, so
// with no entry probe the map stays empty and it emits nothing). A dangling
// *entry* probe is NOT harmless: it would insert into gai_inflight on every
// host-wide getaddrinfo with nothing to delete them (LRU-bounded churn). So we
// attach entry only after exit has succeeded — a half-attach can then leave at
// most the harmless exit probe.
fn attach_getaddrinfo(bpf: &mut Ebpf) -> anyhow::Result<()> {
    // aya's bare "libc" target string resolves to the wrong inode on this system —
    // the uprobe attaches but never fires. Pin the ABSOLUTE path of the libc the
    // agent itself loaded (so it's the real glibc, whatever the distro path), which
    // shares its inode with every other process's libc, so the uprobe instruments
    // them all. (E3 will resolve libssl the same way for the SSL_* probes.)
    let libc = host_lib_path("libc.so").context("could not locate libc in /proc/self/maps")?;
    for (prog_name, is_ret) in [
        ("handle_getaddrinfo_exit", true),
        ("handle_getaddrinfo_entry", false),
    ] {
        let p: &mut UProbe = bpf
            .program_mut(prog_name)
            .with_context(|| format!("program {prog_name} not found in object"))?
            .try_into()?;
        p.load()
            .with_context(|| format!("kernel verifier rejected {prog_name}"))?;
        p.attach(Some("getaddrinfo"), 0, &libc, None).with_context(|| {
            format!("failed to attach {} getaddrinfo", if is_ret { "uretprobe" } else { "uprobe" })
        })?;
    }
    Ok(())
}

// Resolve the absolute path of a shared library the agent itself has mapped, by
// scanning /proc/self/maps for a basename starting with `prefix` (e.g. "libc.so").
// We pin the absolute path because aya's library-NAME resolution attaches the
// uprobe to the wrong inode here (it silently no-ops); the mapped path is the real
// inode every other process shares, so the uprobe instruments them all. None if no
// such mapping exists (the agent doesn't link it) — the caller treats that as the
// optional probe being unavailable.
fn host_lib_path(prefix: &str) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    maps.lines()
        .filter_map(|line| line.split_whitespace().nth(5)) // the pathname column
        .find(|path| {
            path.rsplit('/')
                .next()
                .is_some_and(|base| base.starts_with(prefix))
        })
        .map(String::from)
}

// True if any error in the cause chain is an OS permission-denied error.
fn is_permission_error(e: &anyhow::Error) -> bool {
    has_io_kind(e, std::io::ErrorKind::PermissionDenied)
}

// True if any error in the cause chain is a broken-pipe error (downstream
// reader closed, e.g. `s3tap | head`).
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    has_io_kind(e, std::io::ErrorKind::BrokenPipe)
}

fn has_io_kind(e: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == kind)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a command line and return its privilege needs (see `needs_for`).
    fn needs_of(argv: &[&str]) -> elevate::Needs {
        needs_for(&Cli::try_parse_from(argv).expect("valid test argv"))
    }

    fn needs(base: bool, uprobes: bool, wants_l7: bool, root: bool) -> elevate::Needs {
        elevate::Needs { base, uprobes, wants_l7, root }
    }

    #[test]
    fn elevation_needs_match_what_each_command_attaches() {
        // run (default): kernel probes only. --capture-plaintext is an explicit
        // ask → uprobes REQUIRED (and wanted).
        assert_eq!(needs_of(&["s3tap"]), needs(true, false, false, false));
        assert_eq!(needs_of(&["s3tap", "--capture-plaintext"]), needs(true, true, true, false));
        // selftest asserts the HTTP capability → uprobes required.
        assert_eq!(needs_of(&["s3tap", "selftest"]), needs(true, true, true, false));
        // offline doctor/advise are pure record consumers — no probes, no privilege.
        assert_eq!(needs_of(&["s3tap", "doctor"]), needs(false, false, false, false));
        assert_eq!(needs_of(&["s3tap", "advise"]), needs(false, false, false, false));
        assert_eq!(needs_of(&["s3tap", "scorecard"]), needs(false, false, false, false));
        // doctor --live WANTS the L7 rows but degrades to the network floor without
        // the uprobes — so uprobes are wanted, not required, and
        // a base-caps host is never prompted for cap_sys_admin.
        assert_eq!(
            needs_of(&["s3tap", "doctor", "--live", "--endpoint", "https://b.s3.amazonaws.com/k"]),
            needs(true, false, true, false)
        );
        // check: base required, L7 wanted; --map-only never reaches the L7 path.
        assert_eq!(needs_of(&["s3tap", "check", "b/k"]), needs(true, false, true, false));
        assert_eq!(needs_of(&["s3tap", "check"]), needs(true, false, true, false));
        assert_eq!(needs_of(&["s3tap", "check", "--map-only"]), needs(true, false, false, false));
    }

    fn preflight_of(argv: &[&str]) -> anyhow::Result<()> {
        preflight(&Cli::try_parse_from(argv).expect("valid test argv"))
    }

    #[test]
    fn preflight_rejects_doomed_commands_before_elevation() {
        // The common typos fail here (no sudo prompt): bare bucket, bad region,
        // --live with no endpoint.
        assert!(preflight_of(&["s3tap", "check", "my-bucket"]).is_err());
        assert!(preflight_of(&["s3tap", "check", "my-bucket/k", "--region", "evil.com/"]).is_err());
        assert!(preflight_of(&["s3tap", "doctor", "--live"]).is_err());
        // Valid invocations pass preflight untouched.
        assert!(preflight_of(&["s3tap", "check", "my-bucket/key"]).is_ok());
        assert!(preflight_of(&["s3tap", "check"]).is_ok()); // regional map
        assert!(preflight_of(&["s3tap", "check", "--map-only"]).is_ok());
        assert!(preflight_of(&["s3tap", "doctor"]).is_ok()); // offline consumer
        assert!(preflight_of(&["s3tap"]).is_ok());
    }

    #[test]
    fn elevation_needs_root_for_setup() {
        // setup runs setcap on its own binary — real root. Capabilities cannot stand in
        // for it, which is what `Needs.root` exists to express (see `lacking`).
        assert_eq!(needs_of(&["s3tap", "setup"]), needs(false, false, false, true));
        assert_eq!(needs_of(&["s3tap", "setup", "--uprobes"]), needs(false, false, false, true));
    }

    /// An operation record with just the field the rot check reads.
    fn op_status(status: Option<u16>) -> s3tap_doctor::Record {
        s3tap_doctor::Record::Operation(s3tap_schema::Operation {
            http_status: status,
            ..Default::default()
        })
    }

    #[test]
    fn probe_rot_is_every_op_403_or_404_not_a_slow_path() {
        // Our curated object is gone/forbidden: L7 decoded fine, every GET 403/404.
        assert!(probe_object_rotted(&[op_status(Some(404)), op_status(Some(404))]));
        assert!(probe_object_rotted(&[op_status(Some(403))]));
        // A healthy (or merely slow) probe — not rot.
        assert!(!probe_object_rotted(&[op_status(Some(200)), op_status(Some(200))]));
        // Mixed: the object is there; something else refused one request.
        assert!(!probe_object_rotted(&[op_status(Some(200)), op_status(Some(404))]));
        // 5xx is a REAL S3 problem the doctor should verdict on, never rot.
        assert!(!probe_object_rotted(&[op_status(Some(503))]));
    }

    #[test]
    fn probe_rot_excludes_proxy_and_throttle_statuses() {
        // A captive portal / corporate proxy (407, 451) or throttling (429) is a
        // condition of the USER's network — reporting it as "s3tap's bug, exit 0"
        // would misdiagnose AND mask a real failure. Only 403/404 are rot.
        assert!(!probe_object_rotted(&[op_status(Some(407)), op_status(Some(407))]));
        assert!(!probe_object_rotted(&[op_status(Some(451))]));
        assert!(!probe_object_rotted(&[op_status(Some(429)), op_status(Some(429))]));
        // Mixed rot statuses (deleted from one region view, forbidden in another).
        assert!(probe_object_rotted(&[op_status(Some(403)), op_status(Some(404))]));
    }

    #[test]
    fn probe_rot_needs_operation_records_to_conclude_anything() {
        // No ops at all = the uprobe caps are missing (the doctor's own message
        // owns that), NOT a rotted object.
        assert!(!probe_object_rotted(&[]));
        assert!(!probe_object_rotted(&[s3tap_doctor::Record::Connection(Default::default())]));
        // An op with no decoded status can't prove refusal.
        assert!(!probe_object_rotted(&[op_status(None)]));
    }

    #[test]
    fn public_probe_picks_the_lowest_floor_covered_region() {
        // eu-central-1 is covered and nearest among covered — wins even though
        // us-east-1 (covered) was probed first.
        let rows = vec![
            ("us-east-1", ProbeOutcome::Floor(80.0, None)),
            ("eu-west-1", ProbeOutcome::Floor(9.0, None)), // nearer but UNCOVERED — never picked
            ("eu-central-1", ProbeOutcome::Floor(12.0, None)),
        ];
        let (region, url) = pick_public_probe(&rows).expect("covered region measured");
        assert_eq!(region, "eu-central-1");
        assert!(url.starts_with("https://esa-worldcover.s3.eu-central-1.amazonaws.com/"));
    }

    #[test]
    fn public_probe_ignores_unmeasured_and_failed_regions() {
        let rows = vec![
            ("us-east-1", ProbeOutcome::NotMeasured),
            ("us-west-2", ProbeOutcome::CaptureFailed),
            ("eu-central-1", ProbeOutcome::Floor(40.0, None)),
        ];
        assert_eq!(pick_public_probe(&rows).map(|(r, _)| r), Some("eu-central-1"));
        // No covered region measured a floor → nothing to GET blind.
        let none = vec![
            ("us-east-1", ProbeOutcome::CaptureFailed),
            ("eu-west-1", ProbeOutcome::Floor(9.0, None)), // uncovered
        ];
        assert_eq!(pick_public_probe(&none), None);
    }

    #[test]
    fn public_probe_regions_are_a_subset_of_the_swept_regions() {
        // Every curated object must have a comparable floor from the sweep —
        // an entry outside REGIONAL_PROBES could never be picked (dead weight).
        for (region, url) in PUBLIC_PROBE_OBJECTS {
            assert!(
                REGIONAL_PROBES.contains(region),
                "public probe object region {region} is not swept ({url})"
            );
            assert!(url.starts_with("https://"), "probe object must be https ({url})");
        }
    }

    #[test]
    fn check_target_normalizes_bucket_key_urls_and_regions() {
        // bucket/key -> the global virtual-hosted endpoint.
        assert_eq!(
            normalize_check_target("my-bucket/probe.bin", None).unwrap(),
            "https://my-bucket.s3.amazonaws.com/probe.bin"
        );
        // a nested key is preserved verbatim.
        assert_eq!(
            normalize_check_target("my-bucket/a/b/c.bin", None).unwrap(),
            "https://my-bucket.s3.amazonaws.com/a/b/c.bin"
        );
        // --region targets the regional endpoint.
        assert_eq!(
            normalize_check_target("my-bucket/probe.bin", Some("eu-west-1")).unwrap(),
            "https://my-bucket.s3.eu-west-1.amazonaws.com/probe.bin"
        );
        // a dotted first segment is a hostname/endpoint, not a bucket to expand.
        assert_eq!(
            normalize_check_target("my-bucket.s3.amazonaws.com/probe.bin", None).unwrap(),
            "https://my-bucket.s3.amazonaws.com/probe.bin"
        );
        // a full URL passes through untouched.
        assert_eq!(
            normalize_check_target("https://host/obj", None).unwrap(),
            "https://host/obj"
        );
        // a bare bucket (no key) is a helpful error — nothing to GET.
        let err = normalize_check_target("my-bucket", None).unwrap_err().to_string();
        assert!(err.contains("no object key") && err.contains("my-bucket/<key>"), "{err}");
        // a trailing slash is still a keyless bucket -> the same error.
        assert!(normalize_check_target("my-bucket/", None).is_err());
        // empty/whitespace -> a clear error, not a panic.
        assert!(normalize_check_target("   ", None).is_err());
        // --region is validated before interpolation (would otherwise redirect the host).
        let bad = normalize_check_target("my-bucket/k", Some("evil.com/")).unwrap_err().to_string();
        assert!(bad.contains("invalid --region"), "{bad}");
        // --region is ignored for a full-URL target (the URL is authoritative).
        assert_eq!(
            normalize_check_target("https://host/obj", Some("eu-west-1")).unwrap(),
            "https://host/obj"
        );
    }

    #[test]
    fn triage_thresholds_hint_bounds_and_remedies() {
        use ProbeOutcome::{CaptureFailed, Floor, NotMeasured};
        let three =
            [("us-east-1", Floor(78.0, None)), ("eu-west-1", Floor(15.0, None)), ("ap-southeast-1", Floor(234.0, None))];

        // Far bucket (78) vs nearest PROBED region (eu-west-1, 15) => ~63 ms lower + remedies, and
        // the "similar RTT to us-east-1" hint (us-east-1's 78 ms is within 25% of the bucket's 78).
        let t = render_triage(78.0, &three).expect("far bucket => triage");
        assert!(t.contains("~63 ms lower at eu-west-1"), "{t}");
        // line-anchor the nearest value to its own row (not a free-floating substring).
        let near_line = t.lines().find(|l| l.contains("nearest probed region")).unwrap();
        assert!(near_line.contains("15.0 ms") && near_line.contains("eu-west-1"), "{near_line}");
        assert!(t.contains("similar RTT to us-east-1"), "{t}");
        assert!(t.contains("Multi-Region Access Point") && t.contains("cache misses add an origin hop"), "{t}");

        // Absolute-gate boundary: 24 (gap 9) is quiet; 25 (gap exactly 10) fires.
        assert!(render_triage(24.0, &[("eu-west-1", Floor(15.0, None))]).is_none());
        assert!(render_triage(25.0, &[("eu-west-1", Floor(15.0, None))]).is_some(), "gap==10 fires");

        // Proportional gate: a 25 ms gap is suppressed when the nearest region is itself far
        // (125 < 1.3×100); the exact 1.3× boundary (130) fires.
        assert!(render_triage(125.0, &[("eu-west-1", Floor(100.0, None))]).is_none(), "1.25x suppressed");
        assert!(render_triage(130.0, &[("eu-west-1", Floor(100.0, None))]).is_some(), "1.3x fires");

        // The "similar RTT" hint is omitted when the closest region IS the nearest...
        let n = render_triage(30.0, &[("eu-west-1", Floor(15.0, None)), ("us-east-1", Floor(78.0, None))]).unwrap();
        assert!(!n.contains("similar RTT"), "closest==nearest => no hint: {n}");
        // ...and when the bucket is far from EVERY probed region (likely an un-probed region).
        let far = render_triage(200.0, &[("eu-west-1", Floor(15.0, None)), ("us-east-1", Floor(78.0, None))]).unwrap();
        assert!(!far.contains("similar RTT"), "bucket far from all probed => no hint: {far}");

        // A bucket faster than every probed region => nothing to advise.
        assert!(render_triage(5.0, &[("eu-west-1", Floor(15.0, None))]).is_none());
        // No region floor at all => None (the caller distinguishes this from near-optimal).
        assert!(render_triage(78.0, &[("x", NotMeasured), ("y", CaptureFailed)]).is_none());
        // A mixed slice still picks the single real Floor.
        assert!(
            render_triage(78.0, &[("x", NotMeasured), ("eu-west-1", Floor(15.0, None)), ("y", CaptureFailed)])
                .is_some()
        );
    }

    #[test]
    fn live_doctor_args_sets_easy_mode_defaults() {
        let a = live_doctor_args(vec!["https://x/o".into()], true, 7, 9, true, Some("eu-west-1".into()));
        assert!(a.live && a.brief && a.auth);
        assert_eq!(a.requests, 7);
        assert_eq!(a.timeout_secs, 9);
        assert_eq!(a.concurrency, 1); // serial keep-alive
        assert_eq!(a.region.as_deref(), Some("eu-west-1"));
        assert_eq!(a.endpoint, vec!["https://x/o".to_string()]);
        // easy mode never turns on the power-user modes
        assert!(!a.rotate && !a.strict && !a.cost && !a.json && a.baseline.is_none() && a.from.is_none());
        // --verbose flips brief off (brief == !verbose at the call site)
        assert!(!live_doctor_args(vec!["https://x/o".into()], false, 12, 15, false, None).brief);
    }

    #[test]
    fn regional_probe_marks_the_nearest_and_distinguishes_failure_modes() {
        use ProbeOutcome::{CaptureFailed, Floor, NotMeasured};
        // Lowest floor flagged nearest; a reachable-but-no-floor region reads "not measured";
        // a hard capture failure reads "local capture failed" — the three are kept distinct.
        // Deliberately UNSORTED input (far region first) to prove render sorts nearest→farthest.
        let out = render_regional(&[
            ("eu-west-1", Floor(82.0, None)),
            ("us-east-1", Floor(8.2, None)),
            ("ap-southeast-1", NotMeasured),
            ("sa-east-1", CaptureFailed),
        ], false);
        assert!(out.contains("us-east-1") && out.contains("8.2 ms"), "{out}");
        // exactly one nearest marker, on the lowest floor (not eu-west-1)
        assert_eq!(out.matches("← nearest").count(), 1, "{out}");
        assert!(out.lines().find(|l| l.contains("us-east-1")).unwrap().contains("← nearest"), "{out}");
        // Sorted: the nearest (us-east-1, floor row) appears above the farther eu-west-1.
        let idx = |needle: &str| out.lines().position(|l| l.contains(needle)).unwrap();
        assert!(idx("us-east-1") < idx("eu-west-1"), "nearest sorts above farther\n{out}");
        // Penalty column: eu-west-1 is +74 ms vs the 8.2 ms nearest.
        assert!(out.lines().find(|l| l.contains("eu-west-1")).unwrap().contains("+ 74 ms"), "{out}");
        // City labels present, each with a coarse distance band folded into the location cell.
        assert!(out.contains("N. Virginia") && out.contains("Ireland"), "{out}");
        assert!(out.lines().find(|l| l.contains("us-east-1")).unwrap().contains("~regional"), "band\n{out}");
        assert!(out.lines().find(|l| l.contains("eu-west-1")).unwrap().contains("~long-haul"), "band\n{out}");
        assert!(out.lines().find(|l| l.contains("ap-southeast-1")).unwrap().contains("not measured"), "{out}");
        // A LOCAL capture failure must never be rendered as a statement about the region.
        // "unreachable" (what this used to print) names the far end, so on a mixed map the
        // one failed row read as a partial S3 outage worth escalating.
        let failed_row = out.lines().find(|l| l.contains("sa-east-1")).unwrap();
        assert!(failed_row.contains("local capture failed"), "{out}");
        assert!(!out.contains("unreachable"), "a local failure must not claim the region is down\n{out}");
        // ...and the footnote that says whose failure it is, only when there is one to explain.
        assert!(out.contains("failure of the eBPF capture on THIS host"), "footnote\n{out}");
        assert!(
            !render_regional(&[("us-east-1", Floor(8.2, None))], false).contains("THIS host"),
            "no footnote without a local failure"
        );
        // Sectioned synthesis: a "where you sit" block with a label→value `nearest` row, scoped
        // to the probed set (honest hedge, not an absolute nearest), and the section rules.
        assert!(out.contains("S3 latency map") && out.contains("where you sit"), "section rules\n{out}");
        let nearest_line = out.lines().find(|l| l.trim_start().starts_with("nearest")).unwrap();
        assert!(nearest_line.contains("us-east-1"), "nearest row\n{out}");
        assert!(out.contains("of those probed") && out.contains("may be nearer"), "honest scope\n{out}");
        // Spread quantified as the ms penalty (74 ms) in the spread row.
        assert!(out.lines().any(|l| l.trim_start().starts_with("spread") && l.contains("+74 ms")), "spread\n{out}");
        // Header row present.
        assert!(out.contains("region") && out.contains("round-trip") && out.contains("vs nearest") && out.contains("location"), "header\n{out}");
        // Degraded-row `location` stays aligned with the measured rows (the wide status is
        // left-filled across the numeric span, so the city column starts at the same offset).
        // Compare byte offsets on ASCII-prefixed rows only: eu-west-1's "+ 74 ms" penalty is
        // ASCII (byte==column), whereas the nearest row's em dash would inflate the byte offset.
        let col = |needle: &str| out.lines().find(|l| l.contains(needle)).unwrap().find(needle).unwrap();
        assert_eq!(col("Ireland"), col("Singapore"), "location column aligned across row kinds\n{out}");

        // No floor anywhere => no nearest, a helpful closing line.
        let none = render_regional(&[("us-east-1", NotMeasured), ("eu-west-1", CaptureFailed)], false);
        assert!(!none.contains("← nearest"), "{none}");
        assert!(none.contains("no region returned a round-trip floor"), "{none}");
        assert!(none.contains("sudo s3tap setup"), "no-floor arm keeps the base-caps hint\n{none}");

        // Single measured region → the position-only arm (no penalty to cite), still scoped.
        let one = render_regional(&[("eu-central-1", Floor(11.0, None))], false);
        let one_near = one.lines().find(|l| l.trim_start().starts_with("nearest")).unwrap();
        assert!(one_near.contains("eu-central-1") && one_near.contains("lowest round-trip"), "{one}");
        assert!(!one.contains("spread") && !one.contains("runner-up"), "no penalty with one floor\n{one}");
        assert_eq!(one.matches("← nearest").count(), 1, "{one}");
    }

    #[test]
    fn regional_map_reports_jitter_and_stability() {
        use ProbeOutcome::{Floor, NotMeasured};
        // Nearest with a low jitter → "steady"; a jitter column shows ±X ms per measured row.
        let steady = render_regional(&[("eu-west-1", Floor(15.0, Some(0.4))), ("us-east-1", Floor(80.0, Some(3.0)))], false);
        assert!(steady.contains("jitter"), "jitter header\n{steady}");
        assert!(steady.lines().find(|l| l.contains("eu-west-1")).unwrap().contains("±0.4 ms"), "jitter cell\n{steady}");
        assert!(steady.lines().any(|l| l.trim_start().starts_with("stability") && l.contains("steady")), "steady tag\n{steady}");

        // Nearest with a high jitter (±18 ms on a 78 ms floor) → "variable path".
        let flaky = render_regional(&[("us-east-1", Floor(78.0, Some(18.0))), ("eu-west-1", Floor(200.0, Some(2.0)))], false);
        assert!(flaky.lines().any(|l| l.trim_start().starts_with("stability") && l.contains("variable path")), "variable tag\n{flaky}");

        // Long-haul: 20 ms jitter on a 200 ms floor is under 15% (30 ms) but over the absolute
        // 15 ms arm → still "variable" (a purely proportional bar would wrongly read "steady").
        let longhaul = render_regional(&[("ap-southeast-1", Floor(200.0, Some(20.0))), ("us-east-1", Floor(400.0, Some(1.0)))], false);
        assert!(longhaul.lines().any(|l| l.trim_start().starts_with("stability") && l.contains("variable path")), "absolute-jitter arm\n{longhaul}");

        // Single measured region WITH jitter → the stability row still renders (position-only arm).
        let one = render_regional(&[("eu-central-1", Floor(11.0, Some(0.5)))], false);
        assert!(one.lines().any(|l| l.trim_start().starts_with("stability") && l.contains("steady")), "single-arm stability\n{one}");

        // No jitter measured anywhere → no stability row, blank jitter cells, still aligned.
        let none = render_regional(&[("eu-west-1", Floor(15.0, None)), ("us-east-1", Floor(80.0, None))], false);
        assert!(!none.contains("stability"), "no stability row without jitter\n{none}");
        // Degraded row still aligns with the wider (jitter-inclusive) numeric span. Compare a
        // NON-nearest measured row (ASCII "+NN ms" delta → byte==column) against the degraded row;
        // the nearest row's em dash would inflate the byte offset.
        let mixed = render_regional(
            &[("eu-west-1", Floor(15.0, Some(0.4))), ("us-east-1", Floor(80.0, None)), ("sa-east-1", NotMeasured)],
            false,
        );
        let col = |n: &str| mixed.lines().find(|l| l.contains(n)).unwrap().find(n).unwrap();
        assert_eq!(col("N. Virginia"), col("São Paulo"), "location aligned across jitter/degraded rows\n{mixed}");
    }

    // The per-region jitter signal: the median rttvar across connection records, in ms,
    // ignoring the 0 sentinel ("field not present"), and None when nothing carries it.
    #[test]
    fn median_rttvar_picks_the_middle_ignoring_the_zero_sentinel() {
        use s3tap_doctor::Record;
        use s3tap_schema::{Connection, Operation};
        let conn = |rttvar: Option<u32>| Record::Connection(Connection { rttvar_us: rttvar, ..Default::default() });
        // No connections / none carry rttvar ⇒ None.
        assert_eq!(median_rttvar_ms(&[]), None);
        assert_eq!(median_rttvar_ms(&[conn(None)]), None);
        // A 0 is the "unknown" sentinel and is filtered out — here it leaves nothing.
        assert_eq!(median_rttvar_ms(&[conn(Some(0))]), None);
        // Odd count: the middle value (µs → ms). 1000, 2000, 3000 µs ⇒ median 2000 µs = 2.0 ms.
        assert_eq!(median_rttvar_ms(&[conn(Some(3000)), conn(Some(1000)), conn(Some(2000))]), Some(2.0));
        // Even count: the mean of the two middles. 1000, 3000 µs ⇒ 2000 µs = 2.0 ms.
        assert_eq!(median_rttvar_ms(&[conn(Some(1000)), conn(Some(3000))]), Some(2.0));
        // Operation records and 0-sentinel connections are both ignored in the population.
        let mixed = [
            Record::Operation(Operation::default()),
            conn(Some(0)),
            conn(Some(4000)),
            conn(Some(2000)),
        ];
        assert_eq!(median_rttvar_ms(&mixed), Some(3.0)); // median of {2000, 4000} µs
    }

    #[test]
    fn regional_map_reports_redundancy_and_throughput_ceiling() {
        use ProbeOutcome::Floor;
        // A realistic spread: two close European regions + two distant ones.
        let out = render_regional(&[
            ("eu-west-1", Floor(15.4, None)),
            ("eu-central-1", Floor(16.5, None)),
            ("us-east-1", Floor(78.1, None)),
            ("ap-southeast-1", Floor(231.8, None)),
        ], false);
        // Runner-up row with its delta (one decimal: 16.5 − 15.4 = 1.1 ms).
        assert!(out.lines().any(|l| l.trim_start().starts_with("runner-up") && l.contains("eu-central-1") && l.contains("+1.1 ms")), "runner-up\n{out}");
        // Two regions cluster close → a redundancy row, hedged with the cost/consistency tail.
        assert!(out.lines().any(|l| l.trim_start().starts_with("redundancy") && l.contains("failover")), "redundancy\n{out}");
        assert!(out.contains("eventually consistent"), "cluster hedge\n{out}");
        // Throughput ceiling as a ratio (231.8/15.4 ≈ 15×), framed as a ceiling, no fabricated MB/s.
        assert!(out.contains("~15× lower"), "throughput ratio\n{out}");
        assert!(out.contains("window ÷ RTT") && out.contains("window-limited"), "ceiling framing\n{out}");
        assert!(!out.contains("Transfer Acceleration"), "TA over-claim dropped\n{out}");
        // Advice row keeps the hedged "consider" (not an imperative), naming the nearest.
        assert!(out.lines().any(|l| l.trim_start().starts_with("advice") && l.contains("consider eu-west-1")), "advice\n{out}");
        // Distance bands (reach-based, no false geography) span the map.
        assert!(out.contains("~regional") && out.contains("~long-haul") && out.contains("~global"), "bands\n{out}");

        // A modest spread (<2×) still cites the ms penalty but omits the ceiling clause (no "~1×").
        let modest = render_regional(&[("eu-west-1", Floor(15.0, None)), ("eu-central-1", Floor(16.2, None))], false);
        assert!(modest.lines().any(|l| l.trim_start().starts_with("spread") && l.contains("at the farthest probed")), "{modest}");
        assert!(!modest.contains("× lower"), "no nonsensical ~1× ceiling clause\n{modest}");

        // Tight cluster (all within ~1 ms) → the centrally-placed arm, no spread/runner-up.
        let tight = render_regional(&[("eu-west-1", Floor(15.0, None)), ("eu-central-1", Floor(15.6, None))], false);
        assert!(tight.contains("centrally placed"), "{tight}");
        assert!(!tight.contains("runner-up") && !tight.contains("spread"), "{tight}");
    }

    #[test]
    fn render_regional_color_is_gated() {
        use ProbeOutcome::Floor;
        // Include a non-blank jitter cell so the dim-wrapped `±0.4 ms` is exercised colored-vs-plain.
        let rows = [("eu-west-1", Floor(15.0, Some(0.4))), ("us-east-1", Floor(80.0, None))];
        let plain = render_regional(&rows, false);
        let colored = render_regional(&rows, true);
        // Plain output carries no escape codes; colored wraps the nearest marker in green.
        assert!(!plain.contains('\x1b'), "no ANSI when color=false\n{plain:?}");
        assert!(colored.contains("\x1b[32m") && colored.contains("← nearest"), "green nearest\n{colored:?}");
        // Stripping the escape codes from the colored form yields exactly the plain form — proving
        // color is purely additive and never shifts the layout.
        let stripped: String = {
            let mut s = String::new();
            let mut chars = colored.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for x in chars.by_ref() {
                        if x == 'm' {
                            break;
                        }
                    }
                } else {
                    s.push(c);
                }
            }
            s
        };
        assert_eq!(stripped, plain, "colored minus ANSI must equal plain");
    }

    #[test]
    fn sweep_bar_is_fixed_width_and_monotonic() {
        // Always exactly `width` display columns (chars), regardless of progress — so the caller's
        // fixed-width erase covers every frame.
        for done in 0..=8 {
            assert_eq!(sweep_bar(done, 8, 18).chars().count(), 18, "done={done}");
        }
        // Empty at the start, all full blocks at completion, and fill only grows.
        assert!(sweep_bar(0, 8, 18).starts_with('░'), "{}", sweep_bar(0, 8, 18));
        assert_eq!(sweep_bar(8, 8, 18), "█".repeat(18));
        let count_full = |s: &str| s.chars().filter(|&c| c == '█').count();
        assert!(count_full(&sweep_bar(2, 8, 18)) < count_full(&sweep_bar(6, 8, 18)), "monotonic");
        // A non-8-multiple fill renders a partial-head cell (the point of the sub-cell bar):
        // done=1 → units=18, full=2, rem=2 → a `▎` head.
        assert!(sweep_bar(1, 8, 18).contains('▎'), "partial head: {}", sweep_bar(1, 8, 18));
        // Degenerate inputs don't panic or overflow the width.
        assert_eq!(sweep_bar(0, 0, 18).chars().count(), 18);
        assert_eq!(sweep_bar(99, 8, 18).chars().count(), 18);
    }

    #[test]
    fn region_band_tiers_by_round_trip() {
        assert_eq!(region_band(0.4), "~in-region");
        assert_eq!(region_band(4.9), "~in-region");
        assert_eq!(region_band(5.0), "~regional");
        assert_eq!(region_band(39.9), "~regional");
        assert_eq!(region_band(40.0), "~long-haul");
        assert_eq!(region_band(99.9), "~long-haul");
        assert_eq!(region_band(100.0), "~global");
        assert_eq!(region_band(400.0), "~global");
    }

    #[test]
    fn every_swept_region_has_a_city_label() {
        // Mirrors public_probe_regions_are_a_subset_of_the_swept_regions: a REGIONAL_PROBES entry
        // without a city silently shows the bare code in the map (region_city falls back to it) —
        // a quiet quality regression, so enforce coverage at build time.
        for region in REGIONAL_PROBES {
            assert_ne!(region_city(region), *region, "REGIONAL_PROBES entry {region} has no city label");
        }
    }

    #[test]
    fn verdict_exit_code_maps_the_contract() {
        use s3tap_doctor::{analyze, Record};
        use s3tap_schema::{Connection, Operation};
        let conn = |srtt: Option<u32>| {
            Record::Connection(Connection { srtt_us: srtt, ..Default::default() })
        };
        let op = |ttfb_ms: u64, status: u16| {
            Record::Operation(Operation {
                http_status: Some(status),
                ttfb_ns: Some(ttfb_ms * 1_000_000),
                tcp_connect_ns: Some(17_000_000),
                ..Default::default()
            })
        };
        // healthy floor + fast op -> 0; slow op -> 1 (attention); no floor -> 2.
        assert_eq!(verdict_exit_code(&analyze(&[conn(Some(17_000)), op(30, 200)]), false), 0);
        assert_eq!(verdict_exit_code(&analyze(&[conn(Some(17_000)), op(300, 200)]), false), 1);
        assert_eq!(verdict_exit_code(&analyze(&[op(30, 200)]), false), 2);
        // ...and the other missing denominator: a connection-only capture (a Go/rustls
        // client, or no uprobe caps) judged NO S3 operation, so it must not read green
        // either. It used to exit 0 while the same run's --json published the run finding as
        // "unjudged" and its table said "0 operations in this capture".
        let conns_only = analyze(&[conn(Some(17_000))]);
        assert_eq!(conns_only.overall_verdict(), s3tap_doctor::Verdict::NoOperations);
        assert_eq!(verdict_exit_code(&conns_only, false), 2);
        assert_eq!(verdict_exit_code(&conns_only, true), 2, "--strict cannot make it worse");
        // --strict turns an advisory (GET throughput) into a gate failure.
        let getobj = Record::Operation(Operation {
            http_status: Some(200),
            s3_op: Some("GetObject".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            content_length: Some(2_097_152),
            download_ns: Some(100_000_000),
            ..Default::default()
        });
        let r = analyze(&[conn(Some(17_000)), getobj]);
        assert_eq!(verdict_exit_code(&r, false), 0); // advisory doesn't gate by default
        assert_eq!(verdict_exit_code(&r, true), 1); // ...but --strict gates it

        // Regression (review#2 #1): the FYI network-path rows (min_rtt is populated on
        // essentially every real capture) must NOT make --strict fail a healthy run.
        let healthy = Record::Connection(Connection {
            srtt_us: Some(17_000),
            min_rtt_us: Some(16_000), // emits the path_min_rtt FYI row
            ..Default::default()
        });
        let hr = analyze(&[healthy, op(30, 200)]);
        assert!(!hr.path.is_empty(), "path row present");
        assert_eq!(verdict_exit_code(&hr, true), 0, "FYI path telemetry must not gate --strict");
    }

    // check_waterfall surfaces the measured TTFB (and reuse, when present) the brief
    // verdict hides. Empty report ⇒ nothing to show ⇒ None; a GetObject capture ⇒ Some,
    // naming TTFB and the count of judged ops.
    #[test]
    fn check_waterfall_summarizes_ttfb_or_is_none_when_empty() {
        use s3tap_doctor::{analyze, Record};
        use s3tap_schema::{Connection, Operation};
        // No records ⇒ no s3_ttfb row, no reuse ⇒ None (never a thin empty line).
        assert!(check_waterfall(&analyze(&[])).is_none());

        // A floor + a GetObject op produces a per-op s3_ttfb row, so the waterfall names TTFB.
        let conn = Record::Connection(Connection { srtt_us: Some(17_000), ..Default::default() });
        let get = Record::Operation(Operation {
            verb: Some("GET".into()),
            s3_op: Some("GetObject".into()),
            http_status: Some(200),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            content_length: Some(65_536),
            download_ns: Some(5_000_000),
            ..Default::default()
        });
        let w = check_waterfall(&analyze(&[conn, get])).expect("a GetObject capture yields a waterfall");
        assert!(w.contains("TTFB"), "names the TTFB metric: {w}");
        assert!(w.contains("judged op"), "reports the judged-op count: {w}");
    }

    /// A closed connection carrying a healthy round-trip floor and nothing else. This is
    /// EXACTLY what a run in which every HTTP request failed leaves behind: the TCP path is
    /// fine, so the floor is real, and there is no operation to contradict it.
    fn floor_only_capture() -> Vec<s3tap_schema::Connection> {
        vec![s3tap_schema::Connection { srtt_us: Some(17_000), ..Default::default() }]
    }

    #[test]
    fn live_empty_capture_is_exit_3_not_a_verdict() {
        // Nothing captured -> exit 3 (a diagnostic), never folded into a health verdict.
        // Returnable so it's testable without a live capture.
        let empty = selftest::Captured { conns: vec![], ops: vec![], ..Default::default() };
        // None == the exit-3 diagnostic (doctor_live maps None -> 3 via report_or_diagnostic).
        assert!(finish_live_report(empty, "x", true, None).unwrap().is_none());
    }

    #[test]
    fn a_driver_that_never_completed_a_request_cannot_produce_a_green_verdict() {
        // The regression this pins: `s3tap check bucket/key` where curl's TLS handshake fails
        // on every attempt still captures ONE connection with a good srtt and zero
        // operations. That report is Healthy and exits 0 CHECKS PASSED, so a CI gate on "an
        // endpoint the workload can't read 2xx from will read unhealthy, by design" passed
        // green with every request refused. The driver's outcome has to reach the verdict.
        let failed = selftest::Captured {
            conns: floor_only_capture(),
            ops: vec![],
            driver: selftest::DriverOutcome {
                finished: 12,
                succeeded: 0,
                exit_codes: vec![(60, 12)], // server certificate not trusted
                ..Default::default()
            },
            ..Default::default()
        };
        // None is the exit-3 diagnostic. Anything else here is a verdict drawn from a
        // workload that never completed one request.
        assert!(
            finish_live_report(failed, "x", true, None).unwrap().is_none(),
            "a failed driver with no L7 evidence must not reach a health verdict"
        );

        // Control: the SAME floor-only capture with a driver that DID succeed is still a
        // legitimate (floor-only) report. Otherwise the guard above would just be disabling
        // the base-caps path, which is a supported way to run.
        let ok = selftest::Captured {
            conns: floor_only_capture(),
            ops: vec![],
            driver: selftest::DriverOutcome { finished: 12, succeeded: 12, ..Default::default() },
            ..Default::default()
        };
        let (report, _) = finish_live_report(ok, "x", true, None).unwrap().expect("a report");
        // A report rather than the None refusal, which is the control's whole point: the
        // base-caps path is a supported way to run and it still measures the floor. Its exit
        // code is 2 (NO OPERATIONS), not the 0 it once was, because measuring the floor is
        // not judging S3 — the two are separate claims and only the first was made here.
        assert_eq!(verdict_exit_code(&report, false), 2, "a floor-only capture judged no S3 operation");

        // A driver that could not RUN at all is the same refusal: nothing was driven, so the
        // floor describes no workload.
        let never_ran = selftest::Captured {
            conns: floor_only_capture(),
            ops: vec![],
            driver: selftest::DriverOutcome {
                error: Some("No such file or directory".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(finish_live_report(never_ran, "x", true, None).unwrap().is_none());
    }

    #[test]
    fn the_regional_sweep_keeps_its_floor_when_the_driver_fails() {
        // announce=false is the regional map, which is explicitly floor-only and
        // status-blind (a 403 from a bare service endpoint is the EXPECTED answer). It draws
        // no verdict, so a transport failure there must still yield the measured round-trip
        // rather than collapse to CaptureFailed, which the map reports as a LOCAL problem.
        let failed = selftest::Captured {
            conns: floor_only_capture(),
            ops: vec![],
            driver: selftest::DriverOutcome {
                finished: 4,
                succeeded: 0,
                exit_codes: vec![(35, 4)],
                ..Default::default()
            },
            ..Default::default()
        };
        let (report, _) =
            finish_live_report(failed, "x", false, None).unwrap().expect("a floor read");
        assert_eq!(report.baseline_rtt_us, Some(17_000));
    }

    #[test]
    fn rotation_only_claims_cold_fetch_when_it_is_cold() {
        // One request per distinct object, serially: genuinely cold.
        assert_eq!(rotation_coldness(1, 4, 4), "cold-fetch");
        assert_eq!(rotation_coldness(1, 3, 4), "cold-fetch");
        // The rotation wraps, so requests past the object count are revisits.
        assert_ne!(rotation_coldness(1, 12, 2), "cold-fetch");
        assert_ne!(rotation_coldness(1, 5, 4), "cold-fetch");
        // Parallel workers warm each other's objects whatever the counts.
        assert_ne!(rotation_coldness(4, 4, 4), "cold-fetch");
    }

    #[test]
    fn the_kernel_preflight_names_the_kernel_not_the_capabilities() {
        // Below the documented 5.8 floor: named as a kernel problem, with `s3tap setup`
        // ruled out. The whole point is that the operator stops re-running setup.
        let e = btf_preflight_at(Some("5.4.0-150-generic"), true).unwrap_err().to_string();
        assert!(e.contains("5.8"), "names the floor: {e}");
        assert!(e.contains("setup"), "rules out the capability remedy: {e}");
        // No BTF blob: names the config symbol AND the container remedy, because a
        // bind-mount is the fix in the case that actually happens.
        let e = btf_preflight_at(Some("6.8.0-51-generic"), false).unwrap_err().to_string();
        assert!(e.contains("CONFIG_DEBUG_INFO_BTF"), "names the kernel config: {e}");
        assert!(e.contains(BTF_VMLINUX), "names the path: {e}");
        assert!(e.contains("bind-mount"), "names the container remedy: {e}");
        // A supported kernel with BTF passes, and an unparseable release is NOT judged: we
        // refuse only on what was actually established.
        assert!(btf_preflight_at(Some("6.8.0-51-generic"), true).is_ok());
        assert!(btf_preflight_at(None, true).is_ok());
        assert!(btf_preflight_at(Some("not-a-version"), true).is_ok());
        // The floor itself is inclusive: 5.8 is supported, 5.7 is not.
        assert!(btf_preflight_at(Some("5.8.0"), true).is_ok());
        assert!(btf_preflight_at(Some("5.7.19"), true).is_err());
        assert_eq!(parse_kernel_release("6.12.1-arch1-1"), Some((6, 12)));
        assert_eq!(parse_kernel_release("6.1"), Some((6, 1)));
    }

    #[test]
    fn check_validates_its_own_requests_flag_in_preflight() {
        // Before the fix this ran the full regional sweep and PRINTED the map, then failed
        // from inside probe_report on a message naming --concurrency, which check does not
        // have. Now it is a usage error, and the message stays inside check's own vocabulary.
        let err = preflight_of(&["s3tap", "check", "--requests", "0"]).unwrap_err().to_string();
        assert!(err.contains("--requests"), "names the flag the user typed: {err}");
        assert!(!err.contains("--concurrency"), "must not name a flag check has not got: {err}");
        assert!(preflight_of(&["s3tap", "check", "b/k", "--requests", "0"]).is_err());
        // Past the argv ceiling is rejected here too, rather than after the sweep.
        assert!(preflight_of(&["s3tap", "check", "b/k", "--requests", "999999"]).is_err());
        // The ordinary values still pass untouched.
        assert!(preflight_of(&["s3tap", "check", "--requests", "1"]).is_ok());
        assert!(preflight_of(&["s3tap", "check", "b/k", "--requests", "200"]).is_ok());
    }

    /// The `--live`-only and mode-replacing flags whose silent acceptance made s3tap report
    /// on something other than what was asked for. Each pair is rejected by clap, so the
    /// only thing pinning them is a parse test.
    #[test]
    fn flag_combinations_that_would_silently_discard_the_ask_are_rejected() {
        let parses = |argv: &[&str]| Cli::try_parse_from(argv).is_ok();
        // --cost REPLACES the body and forces exit 0, so with --json it wrote a human table
        // where NDJSON was asked for, and with --baseline it built the regression diff, threw
        // it away and exited 0: a gate that had stopped gating without ever saying so.
        assert!(!parses(&["s3tap", "doctor", "--from", "c.jsonl", "--json", "--cost"]));
        assert!(!parses(&["s3tap", "doctor", "--from", "c.jsonl", "--baseline", "b.jsonl", "--cost"]));
        assert!(parses(&["s3tap", "doctor", "--from", "c.jsonl", "--cost"]));
        // --region is read only by resolve_aws_creds, which runs only under --auth, so
        // without --auth it was accepted, never validated and never used, while the operator
        // believed the probe was region-pinned.
        assert!(!parses(&["s3tap", "doctor", "--live", "--endpoint", "https://x", "--region", "eu-west-1"]));
        assert!(parses(&["s3tap", "doctor", "--live", "--endpoint", "https://x", "--auth", "--region", "eu-west-1"]));
        // --map-only asks to SKIP the live L7 probe, so with a target it drove 12 real GETs
        // against the user's own bucket. --triage is the symmetric case: accepted and ignored
        // with no target.
        assert!(!parses(&["s3tap", "check", "b/k", "--map-only"]));
        assert!(!parses(&["s3tap", "check", "--triage"]));
        assert!(parses(&["s3tap", "check", "--map-only"]));
        assert!(parses(&["s3tap", "check", "b/k", "--triage"]));
        // check's own --region/--auth are equally target-only.
        assert!(!parses(&["s3tap", "check", "--region", "eu-west-1"]));
        assert!(!parses(&["s3tap", "check", "--auth"]));
    }

    // resolve_aws_creds walks the AWS precedence chain (env → ~/.aws), reading real
    // process env + files. It is serialized behind its own mutex and every touched
    // variable is saved/restored, so it can't race or leak into sibling tests. No
    // session tokens are used, so the STS/curl-version subprocess is never reached.
    #[test]
    fn resolve_aws_creds_walks_the_env_then_file_precedence() {
        use std::sync::Mutex;
        // Guards the process-global env for the duration of this test (the only test
        // that mutates AWS_*/HOME). Poison is irrelevant — we only need mutual exclusion.
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        const VARS: &[&str] = &[
            "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AWS_REGION", "AWS_DEFAULT_REGION", "HOME",
        ];
        let saved: Vec<(&str, Option<String>)> = VARS.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        let clear_all = || VARS.iter().for_each(|k| std::env::remove_var(k));

        // A private HOME so ~/.aws never touches the developer's real credentials.
        let home = std::env::temp_dir().join(format!("s3tap_creds_test_{}", std::process::id()));
        let aws = home.join(".aws");
        std::fs::create_dir_all(&aws).unwrap();
        std::fs::write(
            aws.join("credentials"),
            "[default]\naws_access_key_id = AK_FILE\naws_secret_access_key = SK_FILE\n\
             [alt]\naws_access_key_id = AK_ALT\naws_secret_access_key = SK_ALT\n",
        )
        .unwrap();
        std::fs::write(
            aws.join("config"),
            "[default]\nregion = eu-west-1\n[profile alt]\nregion = ap-south-1\n",
        )
        .unwrap();

        let args = |region: Option<&str>| DoctorArgs {
            from: None, json: false, no_color: true, baseline: None, strict: false, cost: false,
            brief: false, live: true, endpoint: vec![], rotate: false, requests: 1, timeout_secs: 15,
            save: None, auth: true, region: region.map(str::to_string), s3_endpoint: vec![], concurrency: 1,
        };

        // 1) Env creds win over the file for the KEYS; with no env/flag region the config
        //    file's [default] region is still consulted (creds and region resolve apart).
        clear_all();
        std::env::set_var("HOME", &home);
        std::env::set_var("AWS_ACCESS_KEY_ID", "AK_ENV");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "SK_ENV");
        let c = resolve_aws_creds(&args(None)).unwrap();
        assert_eq!((c.access_key.as_str(), c.secret_key.as_str()), ("AK_ENV", "SK_ENV"));
        assert!(c.session_token.is_none());
        assert_eq!(c.region, "eu-west-1", "region falls through to ~/.aws/config [default]");

        // 1b) With NO region anywhere (HOME has no config), the built-in default applies.
        std::env::set_var("HOME", home.join("empty"));
        assert_eq!(resolve_aws_creds(&args(None)).unwrap().region, "us-east-1", "no source ⇒ default");
        std::env::set_var("HOME", &home);

        // 2) --region beats every other source; AWS_REGION beats the config file.
        assert_eq!(resolve_aws_creds(&args(Some("us-west-2"))).unwrap().region, "us-west-2");
        std::env::set_var("AWS_REGION", "eu-central-1");
        assert_eq!(resolve_aws_creds(&args(None)).unwrap().region, "eu-central-1");
        std::env::remove_var("AWS_REGION");

        // 3) No env creds ⇒ fall back to ~/.aws/credentials [default] + config region.
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        let f = resolve_aws_creds(&args(None)).unwrap();
        assert_eq!((f.access_key.as_str(), f.secret_key.as_str()), ("AK_FILE", "SK_FILE"));
        assert_eq!(f.region, "eu-west-1", "region from ~/.aws/config [default]");

        // 4) AWS_PROFILE selects the [alt] creds and the [profile alt] config region.
        std::env::set_var("AWS_PROFILE", "alt");
        let p = resolve_aws_creds(&args(None)).unwrap();
        assert_eq!((p.access_key.as_str(), p.secret_key.as_str()), ("AK_ALT", "SK_ALT"));
        assert_eq!(p.region, "ap-south-1");
        std::env::remove_var("AWS_PROFILE");

        // 5) No env creds and no file ⇒ a clear error (nothing to sign with).
        std::env::set_var("HOME", home.join("empty"));
        assert!(resolve_aws_creds(&args(None)).is_err(), "no creds anywhere ⇒ Err");

        // Restore the environment exactly and clean up the fixture.
        clear_all();
        for (k, v) in saved {
            if let Some(v) = v {
                std::env::set_var(k, v);
            }
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn ini_get_reads_the_named_profile() {
        let body = "\
            [default]\n\
            aws_access_key_id = AK_DEFAULT\n\
            aws_secret_access_key = SK_DEFAULT\n\
            \n\
            ; a comment\n\
            [storj]\n\
            aws_access_key_id = AK_STORJ\n\
            aws_secret_access_key = SK_STORJ\n\
            aws_session_token = TOK\n";
        assert_eq!(ini_get(body, "default", "aws_access_key_id").as_deref(), Some("AK_DEFAULT"));
        assert_eq!(ini_get(body, "storj", "aws_secret_access_key").as_deref(), Some("SK_STORJ"));
        assert_eq!(ini_get(body, "storj", "aws_session_token").as_deref(), Some("TOK"));
        assert_eq!(ini_get(body, "default", "aws_session_token"), None); // not in [default]
        assert_eq!(ini_get(body, "missing", "aws_access_key_id"), None);
        // [profile X] (config-file form) is matched literally by section name.
        let cfg = "[profile p]\nregion = eu-west-1\n";
        assert_eq!(ini_get(cfg, "profile p", "region").as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn config_section_matches_aws_naming() {
        // ~/.aws/config uses [default] for the default profile but [profile X] otherwise
        // (whereas ~/.aws/credentials uses a bare [X]) — pin that asymmetry.
        assert_eq!(config_section("default"), "default");
        assert_eq!(config_section("prod"), "profile prod");
    }

    #[test]
    fn parse_curl_version_reads_the_banner() {
        assert_eq!(parse_curl_version("curl 7.86.0 (x86_64) libcurl/7.86.0"), Some((7, 86)));
        assert_eq!(parse_curl_version("curl 7.81.0 (x86_64-pc-linux-gnu)"), Some((7, 81)));
        assert_eq!(parse_curl_version("curl 8.5.0 (...)"), Some((8, 5)));
        // Unparseable second token (or none) → None, so the STS gate stays lenient.
        assert_eq!(parse_curl_version("curl 7"), None);
        assert_eq!(parse_curl_version("my-curl-wrapper v2"), None);
        assert_eq!(parse_curl_version(""), None);
    }

    #[test]
    fn sts_gate_blocks_only_known_old_curl() {
        // Boundary: 7.86.0 signs x-amz-security-token (allowed); 7.85.x doesn't (blocked).
        assert!(!sts_gate_blocks(Some((7, 86))));
        assert!(sts_gate_blocks(Some((7, 85))));
        assert!(sts_gate_blocks(Some((7, 81))));
        assert!(!sts_gate_blocks(Some((8, 5))));
        // Unknown version → never block (lenient).
        assert!(!sts_gate_blocks(None));
    }

    /// The `--auth` privilege gate, both directions.
    ///
    /// A capped binary (`sudo s3tap setup`) is executable by every local user and keeps their
    /// HOME, so reading `~/.aws` through cap_dac_read_search reads whatever HOME points at:
    /// root's credentials file, handed straight to the curl config as `user = "AK:SK"`. That
    /// must be refused. But the SAME run shape is the flag's documented example (`s3tap check
    /// my-bucket/key --auth`, no sudo, capabilities on the inode), so refusing every capped run
    /// broke the workflow the README prints. The gate is therefore "was the capability needed",
    /// which separates the two cases exactly.
    #[test]
    fn auth_reads_the_callers_own_credentials_and_refuses_someone_elses() {
        let dir = std::env::temp_dir().join(format!("s3tap-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // The DOCUMENTED workflow: capabilities on the inode, HOME the operator's own, so the
        // file is theirs and the capability is not what makes the read work.
        let own = dir.join("credentials");
        std::fs::write(&own, "[default]\naws_access_key_id = AK\n").expect("own creds");
        let body = read_credentials_file(&own, true).expect("the caller's own file is readable");
        assert!(body.contains("aws_access_key_id"), "{body}");

        // The HOME=/root attack, modelled without needing root: a file the invoking user
        // cannot read, which only the borrowed capability could open. (Skipped as root, where
        // there is no such file and no borrowed privilege either.)
        // SAFETY: getuid reads a process credential.
        if unsafe { libc::getuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let theirs = dir.join("someone-elses");
            std::fs::write(&theirs, "[default]\naws_secret_access_key = SK\n").expect("bait");
            std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o000)).unwrap();
            let err = read_credentials_file(&theirs, true).expect_err("must refuse");
            let msg = err.to_string();
            assert!(msg.contains("someone-elses"), "{msg}");
            assert!(msg.contains("borrowed privilege"), "{msg}");
            // The way out has to be in the message, or the refusal just breaks the command.
            assert!(msg.contains("sudo env HOME=$HOME"), "{msg}");
            assert!(msg.contains("AWS_ACCESS_KEY_ID"), "{msg}");
            // Not borrowed (real sudo, or an uncapped run): the gate does not apply at all, so
            // the read is attempted and fails on its own merits, never on the refusal.
            let plain = read_credentials_file(&theirs, false).expect_err("unreadable either way");
            assert!(!plain.to_string().contains("borrowed privilege"), "{plain}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The inode re-check behind the gate: the owner/group/other ladder decides on the FIRST
    /// matching class, so a file whose owner bits deny reading is unreadable by its owner even
    /// when "other" may read it. Getting that backwards would let a swapped-in inode pass.
    #[test]
    fn dac_read_ladder_stops_at_the_first_matching_class() {
        // Owner class: 0600 mine yes, 0004 mine no (owner bits are what count for the owner).
        assert!(dac_readable_by(0o600, 1000, 1000, 1000, &[1000]));
        assert!(!dac_readable_by(0o004, 1000, 1000, 1000, &[1000]));
        // Group class: in the group, so the group bits decide, not "other".
        assert!(dac_readable_by(0o040, 0, 50, 1000, &[1000, 50]));
        assert!(!dac_readable_by(0o004, 0, 50, 1000, &[1000, 50]));
        // Other: root's 0600 credentials file is exactly the HOME=/root case.
        assert!(!dac_readable_by(0o600, 0, 0, 1000, &[1000]));
        assert!(dac_readable_by(0o644, 0, 0, 1000, &[1000]));
    }

    /// `real_user_can_read` must answer for the REAL user. A path that does not exist is not
    /// readable, and one the caller owns is.
    #[test]
    fn a_symlinked_home_only_costs_you_on_borrowed_privilege() {
        // The containment must not be charged to everyone. A symlink in the path to $HOME is
        // ordinary — a home on another mount, a distro that links /home, a container image
        // that links half of /. Without borrowed privilege s3tap holds exactly the caller's
        // own authority, so that symlink leads somewhere they could have read anyway and
        // refusing it is pure breakage. An earlier version of this fix did exactly that.
        let dir = std::env::temp_dir().join(format!("s3tap-symhome-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real/.aws")).expect("mkdir");
        std::fs::write(dir.join("real/.aws/credentials"), "[default]\n").expect("write");
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).expect("symlink");
        let via_link = dir.join("link/.aws/credentials");

        // Not borrowed: it just works, as it did before any of this.
        let body = read_credentials_file(&via_link, false).expect("a symlinked HOME still reads");
        assert_eq!(body, "[default]\n");

        // Borrowed: refused, and the message explains the symlink rather than leaving an
        // errno to interpret. It also names both documented escapes.
        let e = read_credentials_file(&via_link, true).expect_err("refused on borrowed privilege");
        let m = format!("{e}");
        assert!(m.contains("will not follow a symlink"), "{m}");
        assert!(m.contains("HOME=$HOME"), "names the sudo escape: {m}");
        assert!(m.contains("AWS_ACCESS_KEY_ID"), "names the env escape: {m}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn contained_open_refuses_a_symlink_in_any_component() {
        // The property `O_NOFOLLOW` cannot give: a symlink is refused in EVERY component, not
        // only the last. That is what closes the swap window — the old code resolved the path
        // three separate times (access, open, the /proc/self/fd walk), so a component could be
        // replaced between them and the file finally read need not be the file checked.
        use std::io::Read as _;
        let dir = std::env::temp_dir().join(format!("s3tap-openat2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).expect("mkdir");
        std::fs::write(dir.join("real/creds"), "[default]\n").expect("write");
        std::fs::write(dir.join("secret"), "SECRET\n").expect("write");

        // A plain file opens and reads normally.
        let mut f = open_no_symlinks(&dir.join("real/creds")).expect("a plain file opens");
        let mut body = String::new();
        f.read_to_string(&mut body).expect("read");
        assert_eq!(body, "[default]\n");

        // Final component is a symlink -> refused. `File::open` would have followed it and
        // handed back someone else's file, which is the attack this guards.
        std::os::unix::fs::symlink(dir.join("secret"), dir.join("link-creds")).expect("symlink");
        let e = open_no_symlinks(&dir.join("link-creds")).expect_err("a symlinked leaf");
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        assert!(
            std::fs::File::open(dir.join("link-creds")).is_ok(),
            "the plain open this replaced DOES follow it — that is the point"
        );

        // INTERMEDIATE component is a symlink -> also refused. O_NOFOLLOW would not catch
        // this one, and it is the shape a real attack takes: swap a directory, not the file.
        std::os::unix::fs::symlink(dir.join("real"), dir.join("via")).expect("symlink dir");
        let e = open_no_symlinks(&dir.join("via/creds")).expect_err("a symlinked directory");
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        assert!(std::fs::File::open(dir.join("via/creds")).is_ok(), "plain open follows it");

        // A relative path takes the AT_FDCWD branch instead of the `/` dirfd one, and reaches
        // the kernel: ENOENT, not the InvalidInput this returns before it ever syscalls.
        // Asserted this way rather than by chdir'ing, because the cwd is process-global and
        // the test harness runs these concurrently.
        let e = open_no_symlinks(std::path::Path::new("s3tap-no-such-relative-path"))
            .expect_err("a relative path that does not exist");
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT), "reached the kernel: {e}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_user_can_read_answers_for_the_invoking_user() {
        let dir = std::env::temp_dir().join(format!("s3tap-access-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let f = dir.join("mine");
        std::fs::write(&f, "x").expect("write");
        assert!(real_user_can_read(&f), "the caller's own file");
        assert!(!real_user_can_read(&dir.join("absent")), "a missing path is not readable");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `real_user_can_traverse_to` catches what the leaf-only `dac_readable_by` check cannot:
    /// an ancestor DIRECTORY that a "real user" (simulated here by an id matching neither the
    /// owner nor its group, so the check falls to the "other" bit) could not search into, even
    /// though the leaf file itself is perfectly world-readable. This is the exact shape a
    /// path-component swap between the initial `access(2)` check and the `open(2)` call could
    /// otherwise steer an elevated read through undetected.
    #[test]
    fn real_user_can_traverse_to_checks_every_ancestor_not_just_the_leaf() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("s3tap-traverse-{}", std::process::id()));
        let locked = base.join("locked");
        std::fs::create_dir_all(&locked).expect("dirs");
        // Pin every level we created to a known-permissive mode, so the umask of whatever
        // host runs this test cannot accidentally make `base` itself the blocker.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = locked.join("leaf");
        std::fs::write(&f, "x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let file = std::fs::File::open(&f).expect("open");

        // Matches neither the real owner nor any real group, so both checks below fall to
        // the "other" bit, exactly like `dac_readable_by`'s ladder for a leaf file.
        let stranger_uid = 999_999;
        let stranger_groups = [999_998];

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o740)).unwrap();
        assert!(
            !real_user_can_traverse_to(&file, stranger_uid, &stranger_groups),
            "a non-searchable ancestor must refuse, even though the leaf file is world-readable"
        );

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o741)).unwrap();
        assert!(
            real_user_can_traverse_to(&file, stranger_uid, &stranger_groups),
            "the ancestor is searchable by 'other' now, so the walk reaches the root"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// Both `SignalStop` properties, in ONE test ON PURPOSE. Do not split this back into two.
    ///
    /// A signal is delivered to the PROCESS, and tokio broadcasts it to EVERY registered
    /// `Signal` stream, so two `#[tokio::test]`s that each `install()` a stream and `raise()`
    /// are not independent: cargo runs them concurrently in one binary, and either one's
    /// `raise` trips the other's streams. Split across two tests, the phase-1 assertion below
    /// ("nothing has been sent yet") failed whenever the sibling raised first — reproducibly,
    /// 8 runs out of 8. The properties are about process-global state, so they have to be
    /// asserted in a single sequential test that owns that state for its whole duration.
    ///
    /// Phase 1 — `check` runs up to nine captures back to back. The per-capture listener that
    /// round 7 added ends ONE capture, so Ctrl-C during region 3 let the sweep continue to
    /// region 4, and a Ctrl-C in the seam between two regions reached no listener at all and
    /// was discarded. Since tokio never unregisters its libc handler the default disposition
    /// was gone too, so the command was killable only by SIGKILL. The fix rests on the stream
    /// LATCHING a signal that arrives when nobody is selecting.
    ///
    /// Phase 2 — the seam calls `tripped()` DIRECTLY rather than `hit()`. The OS handler only
    /// sets tokio's internal pending flag and writes its self-pipe; the driver has to actually
    /// run (which happens when the runtime parks) before a poll of the stream reports ready.
    /// A synchronous `poll_recv` with nothing before it that yields could run in that gap and
    /// report nothing though the signal had genuinely landed, which is why `tripped()` awaits.
    /// Is SIGINT masked for this thread? A blocked signal stays pending instead of being
    /// delivered, so it is ONE way a raise can go unobserved. Kept purely as a DIAGNOSTIC
    /// for the probe below, never as the gate: it was tried as the gate and was not
    /// sufficient — the test still timed out in an environment where nothing was masked.
    fn sigint_masked() -> bool {
        // SAFETY: reads this thread's current signal mask into a zeroed set and writes
        // nothing (a null `set` argument means "query only").
        unsafe {
            let mut cur: libc::sigset_t = std::mem::zeroed();
            if libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur) != 0 {
                return false;
            }
            libc::sigismember(&cur, libc::SIGINT) == 1
        }
    }

    /// Can this environment deliver a raised SIGINT to a tokio signal stream at all?
    ///
    /// Probed EMPIRICALLY rather than inferred, because inference was tried and was wrong.
    /// Checking the signal mask covers only one of the ways delivery can fail, and the test
    /// went on failing where nothing was masked. The cause does not actually matter here —
    /// a mask, a sandbox that intercepts signals, a harness that reaps them, a runtime whose
    /// signal driver never gets to read the self-pipe — because the question the assertions
    /// below depend on is just this one: raise a signal, and see whether a stream observes
    /// it. If it does not, those assertions measure the environment and not `SignalStop`.
    ///
    /// Costs nothing when delivery works: `hit()` returns as soon as the signal lands, so
    /// the timeout is only ever paid on the way to a skip.
    async fn signal_delivery_works() -> bool {
        let Ok(mut probe) = SignalStop::install() else {
            return false;
        };
        // SAFETY: the stream above is registered, so this cannot reach the default
        // disposition and kill the test runner.
        unsafe {
            libc::raise(libc::SIGINT);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), probe.hit()).await.is_ok()
    }

    #[tokio::test]
    async fn signal_stop_latches_a_signal_and_tripped_sees_one_raised_just_before_it() {
        if !signal_delivery_works().await {
            // Loud, not silent: a skipped signal test is worth noticing, and this states
            // exactly what was measured rather than guessing at a cause.
            eprintln!(
                "SKIPPED signal_stop_latches…: this environment did not deliver a raised \
                 SIGINT to a tokio signal stream within 2 s{}, so the assertions below would \
                 be measuring the environment rather than SignalStop. Not a result either \
                 way — re-run somewhere signals reach the process to get one.",
                if sigint_masked() { " (SIGINT is BLOCKED for this thread)" } else { "" }
            );
            return;
        }
        // ---- phase 1: a signal that lands while nothing is awaiting is latched, not lost.
        let mut signals = SignalStop::install().expect("install the streams");
        assert!(signals.tripped().await.is_none(), "nothing has been sent yet");
        // SAFETY: the stream above is already registered, so this cannot reach the default
        // disposition and kill the test runner.
        unsafe {
            libc::raise(libc::SIGINT);
        }
        // Nothing was awaiting when it arrived, exactly as in the seam between two regions.
        // One await afterwards still finds it.
        let sig = tokio::time::timeout(std::time::Duration::from_secs(5), signals.hit())
            .await
            .expect("a latched signal is delivered to the next await, not dropped");
        assert_eq!(sig, "Ctrl-C");
        // And it travels as a typed error, so a caller that shrugs off other failures (the
        // --triage sweep does) can tell "stop" from "that step failed".
        let e = anyhow::Error::new(Interrupted(sig));
        assert!(e.downcast_ref::<Interrupted>().is_some());
        assert!(e.to_string().contains("Ctrl-C"), "{e}");

        // ---- phase 2: `tripped()` sees a signal raised immediately before it, with no
        // intervening await — the synchronous seam `check_regional` relies on. A fresh
        // `SignalStop` so phase 1's consumed signal cannot be what phase 2 observes.
        let mut signals = SignalStop::install().expect("re-install the streams");
        assert!(signals.tripped().await.is_none(), "phase 1's signal was already consumed");
        // SAFETY: as above.
        unsafe {
            libc::raise(libc::SIGINT);
        }
        let sig = tokio::time::timeout(std::time::Duration::from_secs(5), signals.tripped())
            .await
            .expect("tripped() must not hang")
            .expect("a signal raised immediately before tripped() must still be seen");
        assert_eq!(sig, "Ctrl-C");
    }

    /// A `--baseline` that parsed to ZERO records is not a lenient comparison, it is no
    /// comparison: every metric is absent on the reference side, so the diff reports NO
    /// REGRESSION and exits 0 while judging against nothing. An empty file is exactly what a
    /// signal-killed `--live --save` used to leave behind, so this was reachable by accident.
    #[test]
    fn an_empty_baseline_is_a_tool_failure_not_a_silent_no_regression() {
        use s3tap_schema::Connection;
        let path = std::env::temp_dir().join(format!("s3tap_empty_baseline_{}", std::process::id()));
        std::fs::write(&path, "").unwrap();
        let records = vec![s3tap_doctor::Record::Connection(Connection {
            srtt_us: Some(17_000),
            ..Default::default()
        })];
        let report = s3tap_doctor::analyze_with(&records, s3tap_doctor::ParseStats::default());
        let args = DoctorArgs {
            from: None, json: false, no_color: true, baseline: Some(path.clone()), strict: false,
            cost: false, brief: false, live: false, endpoint: vec![], rotate: false, requests: 12,
            timeout_secs: 15, save: None, auth: false, region: None, s3_endpoint: vec![],
            concurrency: 1,
        };
        let err = report_and_code(&report, &records, &args).expect_err("an empty baseline");
        let msg = err.to_string();
        assert!(msg.contains("no s3tap records"), "{msg}");
        assert!(msg.contains("baseline"), "{msg}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn region_is_valid_accepts_ldh_rejects_injection() {
        assert!(region_is_valid("us-east-1"));
        assert!(region_is_valid("eu-west-2"));
        assert!(region_is_valid("US-EAST-1")); // uppercase accepted by design
        // Empty + anything that could corrupt/smuggle into the curl -K config.
        assert!(!region_is_valid(""));
        assert!(!region_is_valid("us east"));
        assert!(!region_is_valid("us-east-1\nheader = \"x: y\""));
        assert!(!region_is_valid("\"x\""));
        assert!(!region_is_valid("eu.west"));
    }

    #[test]
    fn finish_live_returns_the_floor_verdict_for_healthy_and_conns_only() {
        use s3tap_schema::{Connection, Operation};
        let args = DoctorArgs {
            from: None, json: false, no_color: true, baseline: None, strict: false,
            cost: false, brief: false, live: true, endpoint: vec!["https://x".into()], rotate: false, requests: 12,
            timeout_secs: 15, save: None, auth: false, region: None, s3_endpoint: vec![],
            concurrency: 1,
        };
        let conn = || Connection { srtt_us: Some(17_000), ..Default::default() };
        // Exactly what `doctor_live` does with a capture: analyze → the real None→3 mapping.
        let code = |cap: selftest::Captured| -> i32 {
            report_or_diagnostic(finish_live_report(cap, "x", true, None).unwrap(), &args).unwrap()
        };
        // Healthy floor + a fast 2xx op -> exit 0 (the headline "healthy -> 0" promise);
        // exercises the full body (obscure -> analyze -> report_and_code).
        let healthy = selftest::Captured {
            conns: vec![conn()],
            ops: vec![Operation {
                http_status: Some(200),
                ttfb_ns: Some(30_000_000),
                tcp_connect_ns: Some(17_000_000),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(code(healthy), 0);
        // Conns-only (uprobe caps missing, or a Go/rustls client): a clean floor and not one
        // S3 operation judged -> NO OPERATIONS -> exit 2, not the 0 this used to return. The
        // network rows alone are not a health claim about S3, and a --live run that saw no
        // operation must not pass a gate on the strength of them.
        let conns_only = selftest::Captured { conns: vec![conn()], ops: vec![], ..Default::default() };
        assert_eq!(code(conns_only), 2);
        // Nothing captured -> the exit-3 diagnostic (None -> report_or_diagnostic maps to 3).
        let empty = selftest::Captured { conns: vec![], ops: vec![], ..Default::default() };
        assert!(finish_live_report(empty, "x", true, None).unwrap().is_none());
        assert_eq!(report_or_diagnostic(None, &args).unwrap(), 3);
    }

    #[test]
    fn live_obscures_sock_cookies_before_analyze() {
        // The --live security contract: a finding's evidence must never carry the raw kernel
        // sk-pointer. Obscure a record with a known raw cookie, analyze,
        // and assert the raw value appears in NO finding's evidence.
        use s3tap_doctor::{analyze, Record};
        use s3tap_schema::{Connection, Operation};
        const RAW: u64 = 0xdead_beef_1234;
        let mut conns = vec![Connection { srtt_us: Some(17_000), sock_cookie: RAW, ..Default::default() }];
        let mut ops = vec![Operation {
            op_id: "op-1".into(),
            http_status: Some(403), // a 4xx -> http_errors evidence carries the cookie
            sock_cookie: RAW,
            aws_request_id: Some("REQ-1".into()),
            ttfb_ns: Some(30_000_000),
            tcp_connect_ns: Some(17_000_000),
            ..Default::default()
        }];
        let obscure = CookieObscurer::new();
        obscure_records(&mut conns, &mut ops, &obscure, "2026-01-01T00:00:00Z");
        assert_ne!(ops[0].sock_cookie, RAW, "the record's cookie must be obscured");
        let records: Vec<Record> = conns.into_iter().map(Record::Connection)
            .chain(ops.into_iter().map(Record::Operation)).collect();
        let raw_str = RAW.to_string();
        for f in analyze(&records).findings() {
            assert!(
                !f.evidence.sock_cookies.contains(&raw_str),
                "finding {} leaked the raw sk-pointer in evidence",
                f.finding_id
            );
        }
    }

    #[test]
    fn normalize_endpoint_host_strips_scheme_path_port() {
        assert_eq!(normalize_endpoint_host("gateway.storjshare.io").as_deref(), Some("gateway.storjshare.io"));
        assert_eq!(normalize_endpoint_host("https://gateway.storjshare.io/").as_deref(), Some("gateway.storjshare.io"));
        assert_eq!(normalize_endpoint_host("http://minio.local:9000").as_deref(), Some("minio.local"));
        assert_eq!(normalize_endpoint_host("https://s3.example.com/bucket/key").as_deref(), Some("s3.example.com"));
        assert_eq!(normalize_endpoint_host("  Gateway.StorjShare.IO  ").as_deref(), Some("gateway.storjshare.io"));
        // Empty / scheme-only -> None.
        assert_eq!(normalize_endpoint_host(""), None);
        assert_eq!(normalize_endpoint_host("https://"), None);
        // A non-numeric ":suffix" is not a port — keep it (defensive; unusual input).
        assert_eq!(normalize_endpoint_host("host:notaport").as_deref(), Some("host:notaport"));
    }

    #[test]
    fn scrub_redacts_presigned_sigv4_secrets() {
        let line = "GET /b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE%2F20260622%2Feu-west-1%2Fs3&X-Amz-Signature=deadbeefcafef00d&X-Amz-Expires=900 HTTP/1.1";
        let out = scrub_aws_sigv4(line);
        assert!(!out.contains("deadbeefcafef00d"), "signature must be redacted: {out}");
        assert!(!out.contains("AKIAEXAMPLE"), "credential must be redacted: {out}");
        assert!(out.contains("X-Amz-Signature=REDACTED"));
        assert!(out.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"), "non-secret params kept");
        assert!(out.contains("HTTP/1.1"), "request-line tail kept");
        // Case-insensitive on the param name; security-token too.
        let tok = scrub_aws_sigv4("GET /?x-amz-security-token=FwoGZXIvSECRET HTTP/1.1");
        assert!(!tok.contains("FwoGZXIvSECRET"));
        // A normal request line is untouched.
        assert_eq!(scrub_aws_sigv4("GET /bucket/key HTTP/1.1"), "GET /bucket/key HTTP/1.1");
        // EXACT multi-span: two secrets with a NON-sensitive param between them must
        // redact both and leave the middle param byte-for-byte (the right-to-left
        // span replacement must not shift a wrong offset).
        assert_eq!(
            scrub_aws_sigv4("GET /?X-Amz-Signature=AAA&X-Amz-Date=20260622T0000Z&X-Amz-Credential=BBB e"),
            "GET /?X-Amz-Signature=REDACTED&X-Amz-Date=20260622T0000Z&X-Amz-Credential=REDACTED e",
        );
        // Secret as the LAST query param, no trailing delimiter (the val_end ->
        // line.len() branch — the common presigned-URL shape).
        assert_eq!(scrub_aws_sigv4("X-Amz-Signature=deadbeef"), "X-Amz-Signature=REDACTED");
    }

    #[test]
    fn dump_redacts_the_object_key_path() {
        // The request-line PATH is the object key (PII) — replaced with /<key>.
        assert_eq!(
            redact_request_line("GET /private/salaries/alice-ssn-123.pdf HTTP/1.1"),
            "GET /<key> HTTP/1.1"
        );
        // Path redacted AND the presigned signature in the query scrubbed.
        assert_eq!(
            redact_request_line("GET /secret/key?X-Amz-Signature=deadbeef&versionId=3 HTTP/1.1"),
            "GET /<key>?X-Amz-Signature=REDACTED&versionId=3 HTTP/1.1"
        );
        // A status line has no path — passes through (SigV4-scrubbed, here a no-op).
        assert_eq!(
            redact_request_line("HTTP/1.1 404 Not Found"),
            "HTTP/1.1 404 Not Found"
        );
    }

    #[test]
    fn dump_redacts_key_even_when_truncated_or_absolute_form() {
        // Truncated past the version token (a >4 KiB request line): still redact the
        // path — the old "exactly 3 parts ending in HTTP/1." shape leaked it (L3).
        assert_eq!(
            redact_request_line("GET /private/salaries/alice-ssn-123.pdf"),
            "GET /<key>"
        );
        // Absolute-form target: host+path replaced, the presigned query scrubbed+kept (L10).
        assert_eq!(
            redact_request_line("GET https://b.s3.amazonaws.com/secret/key?X-Amz-Signature=deadbeef HTTP/1.1"),
            "GET /<key>?X-Amz-Signature=REDACTED HTTP/1.1"
        );
        // A space-bearing (malformed) target must not echo its unredacted tail.
        let out = redact_request_line("GET /secret/key extra HTTP/1.1");
        assert!(!out.contains("secret") && !out.contains("extra"), "must not leak: {out}");
    }

    #[test]
    fn scrub_sigv4_never_panics_and_coalesces_nested_spans() {
        // F4: a needle at end-of-line (empty value) must NOT panic — that crashed the
        // agent in the drain loop. It redacts to a marker instead.
        assert_eq!(scrub_aws_sigv4("x-amz-signature="), "x-amz-signature=REDACTED");
        assert_eq!(scrub_aws_sigv4("GET /?x-amz-security-token="), "GET /?x-amz-security-token=REDACTED");
        // F3: a value lexically containing another needle (no delimiter) must coalesce
        // to ONE clean REDACTED, not the old garbled "REDACTEDACTED".
        assert_eq!(
            scrub_aws_sigv4("GET /?x-amz-credential=AAAx-amz-signature=BBB HTTP/1.1"),
            "GET /?x-amz-credential=REDACTED HTTP/1.1"
        );
        // Critic D: multibyte value + nested needle, no delimiter — must not panic and
        // must stay char-boundary-safe.
        let out = scrub_aws_sigv4("x-amz-credential=ÀÀÀx-amz-signature=Ø HTTP/1.1");
        assert!(out.contains("REDACTED") && out.contains("HTTP/1.1"), "{out}");
        assert!(!out.contains("ÀÀÀ"), "the multibyte secret must be redacted: {out}");
        // The ordinary &-separated presigned shape still redacts each value precisely.
        assert_eq!(
            scrub_aws_sigv4("GET /?X-Amz-Signature=AAA&X-Amz-Date=Z&X-Amz-Credential=BBB e"),
            "GET /?X-Amz-Signature=REDACTED&X-Amz-Date=Z&X-Amz-Credential=REDACTED e",
        );
    }

    #[test]
    fn redact_request_line_does_not_echo_bytes_after_the_version() {
        // F6: `HTTP/1.1 <junk>` previously echoed the whole tail verbatim, leaking a
        // smuggled SigV4 secret / key path after the version token.
        let out = redact_request_line(
            "GET /private/key.pdf HTTP/1.1 X-Amz-Signature=LEAKEDSECRET trailing/key/data",
        );
        assert!(!out.contains("LEAKEDSECRET"), "secret after the version leaked: {out}");
        assert!(!out.contains("trailing/key/data"), "trailing bytes echoed: {out}");
        assert_eq!(out, "GET /<key>", "an unclean tail is dropped, key redacted");
        // A genuinely clean line still keeps its version token.
        assert_eq!(redact_request_line("GET /k HTTP/1.1"), "GET /<key> HTTP/1.1");
    }

    #[test]
    fn unresolvable_container_only_scope_fails_closed() {
        // A --container that resolves nothing, with no other scope, must NOT fall open
        // to host-wide capture — build_filter_spec bails (review M6).
        let mk = |container: Vec<String>, pid: Vec<u32>| RunOpts {
            format: None,
            include_loopback: false,
            dump_events: false,
            pid,
            app: vec![],
            exe: vec![],
            cgroup: vec![],
            container,
            capture_plaintext: false,
            s3_endpoint: vec![],
            sample_interval_ms: None,
        };
        assert!(
            build_filter_spec(&mk(vec!["__s3tap_no_such_container__".into()], vec![])).is_err(),
            "container-only scope that resolves nothing must fail, not capture host-wide"
        );
        // With another scope present, it proceeds (the satisfiable scope still applies).
        assert!(build_filter_spec(&mk(vec!["__s3tap_no_such_container__".into()], vec![1234])).is_ok());
        // No scope flags at all ⇒ TRACK_ALL is the explicit default, not a failure.
        assert!(build_filter_spec(&mk(vec![], vec![])).is_ok());
    }

    /// A RunOpts with the given scope flags and no container (the pure assembly path).
    fn run_opts_scoped(pid: Vec<u32>, app: Vec<String>, exe: Vec<String>, cgroup: Vec<u64>) -> RunOpts {
        RunOpts {
            format: None,
            include_loopback: false,
            dump_events: false,
            pid,
            app,
            exe,
            cgroup,
            container: vec![],
            capture_plaintext: false,
            s3_endpoint: vec![],
            sample_interval_ms: None,
        }
    }

    // With no --container, build_filter_spec is a pure copy of the scope flags into the
    // FilterSpec — every flag lands verbatim, and the spec is active iff any flag is set.
    #[test]
    fn build_filter_spec_copies_the_scope_flags_verbatim() {
        let spec = build_filter_spec(&run_opts_scoped(
            vec![10, 20],
            vec!["python3".into()],
            vec!["/opt/app/server".into()],
            vec![4242],
        ))
        .expect("no container ⇒ pure assembly, never fails");
        assert_eq!(spec.pids, vec![10, 20]);
        assert_eq!(spec.apps, vec!["python3".to_string()]);
        assert_eq!(spec.exes, vec!["/opt/app/server".to_string()]);
        assert_eq!(spec.cgroups, vec![4242]);
        assert!(spec.is_active());
        // No flags ⇒ TRACK_ALL (inactive) spec, still Ok.
        assert!(!build_filter_spec(&run_opts_scoped(vec![], vec![], vec![], vec![])).unwrap().is_active());
    }

    // scope_summary is the startup banner's one-liner: None under TRACK_ALL, else a
    // comma-joined count/label per active scope dimension.
    #[test]
    fn scope_summary_describes_the_active_scope() {
        assert_eq!(scope_summary(&FilterSpec::default()), None);
        let s = scope_summary(&FilterSpec {
            pids: vec![1, 2],
            apps: vec!["nginx".into()],
            exes: vec!["/bin/x".into()],
            cgroups: vec![7, 8, 9],
        })
        .expect("an active spec summarizes");
        assert!(s.contains("2 pid(s)"), "{s}");
        assert!(s.contains("app [\"nginx\"]"), "{s}");
        assert!(s.contains("exe [\"/bin/x\"]"), "{s}");
        assert!(s.contains("3 cgroup(s)"), "{s}");
        // Only the set dimensions appear (a pid-only scope names just pids).
        assert_eq!(scope_summary(&FilterSpec { pids: vec![5], ..Default::default() }).unwrap(), "1 pid(s)");
    }

    /// An `--app`/`--exe` scope that never had a process in it, on a run that captured
    /// nothing, is a scope that MISSED. Round 6 warned about it at startup and rightly
    /// refused to bail (a matching process may exec later), which left a scripted run
    /// unable to tell that from an app that was simply quiet. At the end of the run it is
    /// no longer a prediction, so it gets an exit code.
    #[test]
    fn a_name_scope_that_never_matched_and_captured_nothing_is_not_a_clean_run() {
        let app = FilterSpec { apps: vec!["myapp".into()], ..Default::default() };
        let exe = FilterSpec { exes: vec!["/usr/bin/myapp".into()], ..Default::default() };
        // The refusal: nothing captured, nothing matched at either end of the run.
        assert!(scope_never_matched(&app, false, false, 0));
        assert!(scope_never_matched(&exe, false, false, 0));
        // Any one of the three facts flipping keeps exit 0.
        assert!(!scope_never_matched(&app, false, false, 1), "records make it a real capture");
        assert!(!scope_never_matched(&app, true, false, 0), "matched at start: the app was quiet");
        assert!(!scope_never_matched(&app, false, true, 0), "execed into scope mid-run");
        // TRACK_ALL (no scope at all) is never judged: an empty capture there is a quiet host.
        assert!(!scope_never_matched(&FilterSpec::default(), false, false, 0));
        // Nor is a scope that carries a target of its own. --pid/--cgroup name something
        // that exists or fail closed at startup, so an empty capture under them is not the
        // "did my filter miss?" ambiguity this judges.
        let with_pid = FilterSpec { pids: vec![42], ..app.clone() };
        assert!(!scope_never_matched(&with_pid, false, false, 0));
        let with_cgroup = FilterSpec { cgroups: vec![7], ..app.clone() };
        assert!(!scope_never_matched(&with_cgroup, false, false, 0));
        // name_only_scope is the shape predicate the run path also gates its second /proc
        // scan on, so pin it directly too.
        assert!(name_only_scope(&app) && name_only_scope(&exe));
        assert!(!name_only_scope(&FilterSpec::default()) && !name_only_scope(&with_pid));
    }

    // `captured()` is the structural bound on the plaintext payload. EvtTlsData has
    // no `serde` dependency in scope, so it CANNOT derive Serialize (the trait isn't
    // importable) — that, plus reading only through `captured()`, keeps the
    // uninitialized `data` tail (a prior request's bytes) from ever being shipped.
    #[test]
    fn captured_bounds_the_payload_and_never_panics() {
        let mut e = s3tap_events::EvtTlsData::default();
        e.data[0] = b'G';
        e.data[1] = b'E';
        e.data[5] = b'X'; // past captured_len — must NOT appear
        e.captured_len = 2;
        assert_eq!(e.captured(), b"GE");
        // A corrupt/hostile captured_len > the array is clamped, not a panic (DoS).
        e.captured_len = 9999;
        assert_eq!(e.captured().len(), s3tap_events::HDR_CAP);
        e.captured_len = 0;
        assert_eq!(e.captured(), b"");
    }

    #[test]
    fn fold_routes_tls_events_to_none_without_undecodable() {
        let mut c = s3tap_core::Correlator::new();
        let mut undecoded = 0u64;
        let mut buf = vec![0u8; 4144];
        buf[0..2].copy_from_slice(&s3tap_events::SCHEMA_VERSION.to_ne_bytes());
        buf[2..4].copy_from_slice(&s3tap_events::EVT_TLS_WRITE.to_ne_bytes());
        assert!(fold(&mut c, &buf, &mut undecoded, None, &mut None).is_none(), "TLS event finalizes nothing");
        assert_eq!(undecoded, 0, "a decodable TLS event is not undecodable");
    }

    #[test]
    fn human_op_summarizes_without_leaking_the_key() {
        let op = Operation {
            req_seq: 2,
            s3_op: Some("GetObject".into()),
            bucket: Some("b".into()),
            key_hash: Some("sha256:deadbeef".into()),
            http_status: Some(200),
            op_bytes_sent: Some(100),
            op_bytes_recv: Some(50),
            connection_reused: true,
            ..Default::default()
        };
        let line = human_op(&op);
        assert!(line.contains("GetObject") && line.contains('b') && line.contains("status=200"));
        assert!(line.contains("/<key>"), "key shown as a placeholder");
        assert!(!line.contains("sha256") && !line.contains("deadbeef"), "neither the hash nor key printed");
        assert!(line.contains("(reused)"));
    }

    #[test]
    fn fold_request_response_round_trips_to_an_operation() {
        // Integration: CONN_ID + request write + response read, through fold -> emit,
        // yields an Operation jsonl with an OBSCURED cookie (never the raw pointer).
        let mut c = s3tap_core::Correlator::new();
        let mut undecoded = 0u64;
        let obscure = CookieObscurer::new();

        let mut cid = vec![0u8; 40];
        cid[0..2].copy_from_slice(&s3tap_events::SCHEMA_VERSION.to_ne_bytes());
        cid[2..4].copy_from_slice(&s3tap_events::EVT_CONN_ID.to_ne_bytes());
        cid[16..20].copy_from_slice(&100u32.to_ne_bytes()); // tgid
        cid[24..32].copy_from_slice(&0xdead_beefu64.to_ne_bytes()); // sock_cookie
        cid[32..36].copy_from_slice(&5u32.to_ne_bytes()); // fd
        assert!(fold(&mut c, &cid, &mut undecoded, None, &mut None).is_none());

        let tls = |typ: u16, ts: u64, payload: &[u8]| {
            let mut b = vec![0u8; 4144];
            b[0..2].copy_from_slice(&s3tap_events::SCHEMA_VERSION.to_ne_bytes());
            b[2..4].copy_from_slice(&typ.to_ne_bytes());
            b[8..16].copy_from_slice(&ts.to_ne_bytes()); // ts_ns
            b[16..20].copy_from_slice(&100u32.to_ne_bytes()); // tgid
            b[32..36].copy_from_slice(&5u32.to_ne_bytes()); // fd
            b[36..40].copy_from_slice(&(payload.len() as u32).to_ne_bytes()); // plaintext_len
            b[40..42].copy_from_slice(&(payload.len() as u16).to_ne_bytes()); // captured_len
            b[44..44 + payload.len()].copy_from_slice(payload);
            b
        };
        let req = tls(s3tap_events::EVT_TLS_WRITE, 2000, b"GET /key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n");
        assert!(fold(&mut c, &req, &mut undecoded, None, &mut None).is_none(), "request opens, no record");
        let resp = tls(s3tap_events::EVT_TLS_READ, 2500, b"HTTP/1.1 200 OK\r\n\r\n");
        let rec = fold(&mut c, &resp, &mut undecoded, None, &mut None).expect("response emits an Operation");

        let mut buf = Vec::new();
        emit(&mut buf, Format::Jsonl, &obscure, rec, &batch_now()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains(r#""schema":"s3tap.operation/1""#));
        assert!(s.contains(r#""s3_op":"GetObject""#));
        assert!(s.contains(r#""http_status":200"#));
        assert!(!s.contains("3735928559"), "raw cookie 0xdeadbeef must be obscured: {s}");
        assert_eq!(undecoded, 0);
    }

    #[test]
    fn fold_routes_conn_id_to_the_correlator() {
        // EVT_CONN_ID folds to None (finalizes nothing) but DOES record the join.
        let mut c = s3tap_core::Correlator::new();
        let mut undecoded = 0u64;
        let mut buf = vec![0u8; 40];
        buf[0..2].copy_from_slice(&s3tap_events::SCHEMA_VERSION.to_ne_bytes());
        buf[2..4].copy_from_slice(&s3tap_events::EVT_CONN_ID.to_ne_bytes());
        buf[16..20].copy_from_slice(&100u32.to_ne_bytes()); // tgid
        buf[24..32].copy_from_slice(&42u64.to_ne_bytes()); // sock_cookie
        buf[32..36].copy_from_slice(&5u32.to_ne_bytes()); // fd
        assert!(fold(&mut c, &buf, &mut undecoded, None, &mut None).is_none(), "conn_id finalizes nothing");
        assert_eq!(undecoded, 0);
        assert_eq!(c.cookie_for_fd(100, 5), Some(42), "the routed conn_id is recorded");
    }

    // Read the eBPF C source the loader is coupled to. Map/program names are
    // matched by string at load time, and map creation needs root — so a name
    // drift between C and Rust is invisible to `cargo test` and only fails at
    // runtime as a denied/"no map" error. These tests pin the coupling.
    fn bpf_source() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/src/s3tap.bpf.c");
        std::fs::read_to_string(path).expect("read s3tap.bpf.c")
    }

    #[test]
    fn bpf_c_declares_the_maps_the_loader_looks_up() {
        let src = bpf_source();
        for name in [
            EVENTS_MAP,
            TLS_EVENTS_MAP,
            CONFIG_MAP,
            SAMPLE_EVENTS_MAP,
            RINGBUF_DROPS_MAP,
            SCOPE_DROPS_MAP,
            FILTER_PIDS_MAP,
            FILTER_CGROUPS_MAP,
        ] {
            assert!(
                src.contains(&format!("}} {name} SEC(\".maps\")")),
                "loader looks up map {name:?} but the C source declares no such map"
            );
        }
    }

    #[test]
    fn bpf_c_drop_loopback_slot_matches() {
        // The agent writes drop-loopback into slot CFG_DROP_LOOPBACK; the C must
        // read the same slot. Pin the shared index so the two can't drift.
        let src = bpf_source();
        assert!(
            src.contains(&format!("#define CFG_DROP_LOOPBACK {CFG_DROP_LOOPBACK}")),
            "CFG_DROP_LOOPBACK index disagrees between main.rs and s3tap.bpf.c"
        );
        assert!(
            src.contains(&format!("#define CFG_CAPTURE_PLAINTEXT {CFG_CAPTURE_PLAINTEXT}")),
            "CFG_CAPTURE_PLAINTEXT index disagrees between main.rs and s3tap.bpf.c"
        );
        assert!(
            src.contains(&format!("#define CFG_FILTER_MODE {CFG_FILTER_MODE}")),
            "CFG_FILTER_MODE index disagrees between main.rs and s3tap.bpf.c"
        );
        assert!(
            src.contains(&format!("#define CFG_SAMPLE_INTERVAL_MS {CFG_SAMPLE_INTERVAL_MS}")),
            "CFG_SAMPLE_INTERVAL_MS index disagrees between main.rs and s3tap.bpf.c"
        );
    }

    #[test]
    fn bpf_c_declares_the_programs_the_loader_attaches() {
        // Program names are string-coupled at attach (program_mut("...")); a typo
        // fails only at runtime (needs root). Pin them like the map names. (Parity
        // gap the E4 review flagged — three new conn-id programs were unguarded.)
        let src = bpf_source();
        for name in [
            "handle_set_state",
            "handle_sched_process_exec",
            "handle_sched_process_fork",
            "handle_udp_sendmsg",
            "handle_skb_consume_udp",
            "handle_tcp_sendmsg",
            "handle_tcp_data_queue",
            "handle_connect_enter",
            "handle_tcp_v4_connect",
            "handle_tcp_v6_connect",
            "handle_getaddrinfo_entry",
            "handle_getaddrinfo_exit",
            "handle_ssl_set_fd",
            "handle_ssl_free",
            "handle_ssl_write",
            "handle_ssl_write_exit",
            "handle_ssl_write_ex",
            "handle_ssl_write_ex_exit",
            "handle_ssl_read_entry",
            "handle_ssl_read_exit",
            "handle_ssl_read_ex_entry",
            "handle_ssl_read_ex_exit",
            "handle_tcp_sample",
        ] {
            let defined = src.contains(&format!("BPF_KPROBE({name}"))
                || src.contains(&format!("BPF_KRETPROBE({name}"))
                || src.contains(&format!("BPF_PROG({name}"))
                || src.contains(&format!("int {name}("));
            assert!(defined, "loader attaches program {name:?} but the C declares no such function");
        }
    }

    #[test]
    // The pure-consumer contract says a closed pipe (`… | head`) is a clean exit 0, and
    // `main` implements that by asking this predicate. Nine call sites hand-roll the
    // io::ErrorKind::BrokenPipe half; this pins the anyhow-chain half they all funnel into.
    fn is_broken_pipe_matches_epipe_in_chain() {
        let pipe = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        let err = anyhow::Error::from(pipe).context("writing the doctor report");
        assert!(is_broken_pipe(&err));
        // Nested deeper than one context layer — the chain walk, not just the head.
        let deep = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            .context("emitting a record")
            .context("draining the ring buffer");
        assert!(is_broken_pipe(&deep));
        // A different io error is NOT a clean stop: it must still surface as a failure.
        let other = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("missing thing");
        assert!(!is_broken_pipe(&other));
        // An error with no io::Error anywhere in the chain.
        assert!(!is_broken_pipe(&anyhow::anyhow!("not an io error at all")));
        // The two predicates don't answer for each other.
        assert!(!is_permission_error(&err));
    }

    // `--no-color` is honored AND color is off on a non-tty. Both halves of the contract,
    // all four combinations, in one place — the four call sites now share this function,
    // so a subcommand can no longer implement half of it.
    #[test]
    fn want_color_honors_the_flag_and_the_tty() {
        assert!(want_color(false, true), "a tty with no --no-color is the only colored case");
        assert!(!want_color(true, true), "--no-color wins over a tty");
        assert!(!want_color(false, false), "a pipe/file gets no ANSI even without the flag");
        assert!(!want_color(true, false));
    }

    // The bound exists to keep `--requests` inside a single execve, so pin the arithmetic
    // rather than the constant: the old 100000 ceiling was ~3x what an argv carries, so the
    // driver died with E2BIG and the run reported the misleading "captured nothing" exit 3.
    #[test]
    fn max_requests_stays_inside_one_argv() {
        // A typical endpoint URL: bounded by the absolute measurement ceiling, not by bytes.
        let typical = "https://my-bucket.s3.eu-west-1.amazonaws.com/probe.bin".len();
        assert_eq!(max_requests_for_argv(typical), 10_000);
        // Every allowed count must still fit the half-budget we spend (1 MiB).
        for url in [0, typical, 512, 4096] {
            let n = max_requests_for_argv(url) as usize;
            assert!(n >= 1);
            assert!((3 + 10 + 6 + url + 1) * n <= 1 << 20, "url {url} x {n} overruns the argv");
        }
        // A long (presigned) URL lowers the ceiling below the absolute cap — the point of
        // deriving it rather than hardcoding one number.
        assert!(max_requests_for_argv(4096) < 10_000);
        // Even an absurd URL leaves a usable bound rather than "between 1 and 0".
        assert_eq!(max_requests_for_argv(usize::MAX / 2), 1);
    }

    // The --save target is RESERVED (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600) before the
    // capture runs and filled after it. `doctor --live` routinely re-execs under sudo, so
    // this write is commonly ROOT's: following a symlink (or truncating an existing file) at
    // an attacker-chosen path is a root-owned write anywhere, and 0644 published the
    // operator's buckets/endpoints/SNI to every local user.
    #[test]
    fn save_reserves_the_path_up_front_refuses_an_existing_one_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("s3tap-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let target = dir.join("capture.jsonl");

        // Reserving CREATES the file, which is what turns "the path already exists" into a
        // usage error before any traffic is driven. Previously the refusal happened after the
        // capture, so `--live --save <existing>` loaded eBPF, drove every real request and
        // then discarded the completed run.
        let first = SaveTarget::create(&target).expect("the path was free");
        assert!(target.exists(), "the reservation claims the name immediately");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a capture is owner-only, not 0644");
        // A second reservation of the SAME path is refused, not a truncate.
        assert!(SaveTarget::create(&target).is_err(), "an existing --save target must be refused");

        first.write("{\"schema\":\"s3tap.connection/2\"}\n").expect("fill the reservation");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "{\"schema\":\"s3tap.connection/2\"}\n"
        );
        // Still refused once written, and the original is intact.
        assert!(SaveTarget::create(&target).is_err());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "{\"schema\":\"s3tap.connection/2\"}\n",
            "the refused reservation must leave the original intact"
        );

        // A reservation dropped WITHOUT a capture (every exit-3 path) releases the name, so
        // the placeholder this reservation created cannot refuse the operator's re-run.
        let unused = dir.join("never-written.jsonl");
        drop(SaveTarget::create(&unused).expect("free"));
        assert!(!unused.exists(), "an unused reservation releases the name again");

        // A write that FAILS part-way is not a capture either. The handle is released only on
        // success, so the reservation's Drop still runs and the truncated file does not survive
        // to refuse the re-run with "Nothing was captured". /dev/full ENOSPCs on every write,
        // which is exactly that failure (a capture can be megabytes).
        if std::path::Path::new("/dev/full").exists() {
            let partial = dir.join("partial.jsonl");
            let mut t = SaveTarget::create(&partial).expect("free");
            t.file = Some(
                std::fs::OpenOptions::new().write(true).open("/dev/full").expect("/dev/full"),
            );
            assert!(t.write("{\"schema\":\"s3tap.connection/2\"}\n").is_err(), "ENOSPC");
            assert!(!partial.exists(), "a half-written capture releases the name again");
        }

        // A symlink is refused too, and the link TARGET is untouched — the root-write
        // primitive this closes.
        let bait = dir.join("bait");
        std::fs::write(&bait, "original\n").expect("bait");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&bait, &link).expect("symlink");
        assert!(SaveTarget::create(&link).is_err(), "must not follow a symlink");
        assert_eq!(std::fs::read_to_string(&bait).unwrap(), "original\n");
        assert!(link.exists(), "the refused reservation must not unlink the symlink either");

        std::fs::remove_dir_all(&dir).ok();
    }

    // The query string is scrubbed by ALLOWLIST: only a known-harmless selector keeps its
    // value. Before this, a denylist of the SigV4 parameter names printed a SigV2 presigned
    // URL — a complete, replayable capability for that object — verbatim.
    #[test]
    fn dump_scrubs_every_query_value_it_does_not_recognize() {
        // SigV2 presigning: all three parameters redacted, none of them named in a denylist.
        let v2 = redact_request_line(
            "GET /b/k?AWSAccessKeyId=AKIAEXAMPLE&Expires=1780000000&Signature=vJbW%2Bsecret HTTP/1.1",
        );
        assert!(!v2.contains("AKIAEXAMPLE"), "SigV2 key id leaked: {v2}");
        assert!(!v2.contains("vJbW"), "SigV2 signature leaked: {v2}");
        assert_eq!(
            v2,
            "GET /<key>?AWSAccessKeyId=REDACTED&Expires=REDACTED&Signature=REDACTED HTTP/1.1"
        );
        // An unknown gateway's token parameter — the case a denylist can never cover.
        let unknown = redact_request_line("GET /b/k?x-storj-access-grant=SECRET HTTP/1.1");
        assert!(!unknown.contains("SECRET"), "an unrecognized parameter must default to redacted: {unknown}");
        // Allowlisted selectors keep their values (the diagnostic value of the dump).
        assert_eq!(
            redact_request_line("GET /b/k?versionId=abc&partNumber=7&uploadId=xyz HTTP/1.1"),
            "GET /<key>?versionId=abc&partNumber=7&uploadId=xyz HTTP/1.1"
        );
        // A valueless sub-resource flag passes through; a neighbouring secret does not.
        assert_eq!(
            redact_request_line("POST /b/k?uploads&X-Amz-Signature=deadbeef HTTP/1.1"),
            "POST /<key>?uploads&X-Amz-Signature=REDACTED HTTP/1.1"
        );
        // Key names are matched case-insensitively, like every other S3 client does.
        assert_eq!(
            redact_request_line("GET /b/k?VERSIONID=abc HTTP/1.1"),
            "GET /<key>?VERSIONID=abc HTTP/1.1"
        );
        // Empty/odd shapes must neither panic nor leak.
        assert_eq!(redact_request_line("GET /b/k? HTTP/1.1"), "GET /<key>? HTTP/1.1");
        assert_eq!(scrub_query("=v"), "=REDACTED");
        assert_eq!(scrub_query("&&"), "&&");
    }

    // The non-request-shaped fallback stays needle-based (there is no k=v structure to
    // apply the allowlist to), so it must know BOTH presigning schemes.
    #[test]
    fn scrub_fallback_covers_sigv2_as_well_as_sigv4() {
        let out = scrub_aws_sigv4("Signature=vJbWsecret&AWSAccessKeyId=AKIAEXAMPLE&Expires=1780000000");
        assert!(!out.contains("vJbWsecret") && !out.contains("AKIAEXAMPLE"), "{out}");
        assert_eq!(
            out,
            "Signature=REDACTED&AWSAccessKeyId=REDACTED&Expires=REDACTED"
        );
        // The SigV4 names still work, and the nested `signature=` needle inside
        // `x-amz-signature=` coalesces to one marker rather than double-applying.
        assert_eq!(scrub_aws_sigv4("X-Amz-Signature=abc"), "X-Amz-Signature=REDACTED");
    }

    // A slow downstream reader must cost RECORDS WE COUNT, never a blocked runtime thread
    // (which cost kernel events + a swallowed Ctrl-C — see RecordSink).
    #[test]
    fn record_sink_drops_whole_batches_instead_of_blocking() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        let mut sink =
            RecordSink { buf: Vec::new(), tx, blocking: false, dropped_chunks: 0, dropped_bytes: 0 };
        writeln!(sink, "one").unwrap();
        sink.flush().unwrap(); // fills the one-slot queue
        writeln!(sink, "two").unwrap();
        sink.flush().unwrap(); // queue full: dropped and counted, NOT blocked
        assert_eq!(sink.dropped(), (1, 4), "the dropped batch is counted, bytes and all");
        assert_eq!(rx.recv().unwrap(), b"one\n");
        // Writer gone (stdout's reader closed) surfaces as the BrokenPipe `main` maps to 0.
        drop(rx);
        writeln!(sink, "three").unwrap();
        assert_eq!(sink.flush().unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }

    // …but the SHUTDOWN drain must lose nothing. Once the capture loop has broken out, no
    // arm needs the runtime thread, and the final ring drain plus the aborted in-flight
    // operations are the one part of the stream a re-run cannot recreate — so the sink
    // waits for the writer there instead of dropping.
    #[test]
    fn record_sink_waits_instead_of_dropping_once_the_capture_stops() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        let mut sink =
            RecordSink { buf: Vec::new(), tx, blocking: false, dropped_chunks: 0, dropped_bytes: 0 };
        sink.block_on_send();
        // A reader that lags, so the one-slot queue is full on nearly every hand-off —
        // exactly the condition the steady-state loop answers by dropping.
        let reader = std::thread::spawn(move || {
            let mut got = Vec::new();
            while let Ok(c) = rx.recv() {
                std::thread::yield_now();
                got.push(c);
            }
            got
        });
        for i in 0..64 {
            writeln!(sink, "op-{i}").unwrap();
            sink.flush().unwrap();
        }
        assert_eq!(sink.dropped(), (0, 0), "the shutdown drain must drop nothing");
        drop(sink); // closes the channel so the reader finishes
        assert_eq!(reader.join().expect("reader thread").len(), 64);
    }

    // The size-based chunk split must land on a record boundary: a dropped chunk has to
    // cost whole records, never half a JSON line that a downstream parser would choke on.
    #[test]
    fn record_sink_splits_only_between_records() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(64);
        let mut sink =
            RecordSink { buf: Vec::new(), tx, blocking: false, dropped_chunks: 0, dropped_bytes: 0 };
        let record = "x".repeat(1000);
        for _ in 0..200 {
            writeln!(sink, "{record}").unwrap(); // ~200 KiB, several 64 KiB chunks
        }
        sink.flush().unwrap();
        assert_eq!(sink.dropped(), (0, 0));
        drop(sink); // closes the channel so the drain below terminates
        let mut chunks = 0;
        let mut all = Vec::new();
        while let Ok(c) = rx.recv() {
            assert_eq!(c.last(), Some(&b'\n'), "chunk {chunks} ended mid-record");
            chunks += 1;
            all.extend_from_slice(&c);
        }
        assert!(chunks > 1, "the size cap must actually have split the stream ({chunks})");
        // And the bytes are the stream, in order, complete.
        assert_eq!(all.len(), 200 * 1001);
        assert!(all.chunks_exact(1001).all(|r| r[..1000] == record.as_bytes()[..] && r[1000] == b'\n'));
    }

    #[test]
    fn is_permission_error_matches_eperm_in_chain() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let err = anyhow::Error::from(denied).context("failed to load eBPF object");
        assert!(is_permission_error(&err));

        let other = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("missing thing");
        assert!(!is_permission_error(&other));
    }

    #[test]
    fn human_labels_each_connection_kind() {
        // Failed connect.
        let mut f = Connection {
            connect_failed: true,
            ..Default::default()
        };
        f.endpoint.endpoint_ip = Some("127.0.0.1".into());
        f.endpoint.dport = Some(9);
        let line = human(&f);
        assert!(line.contains("127.0.0.1:9") && line.contains("FAILED"));

        // Active connect with a measured latency.
        let a = Connection {
            tcp_connect_ns: Some(11_200_000),
            ..Default::default()
        };
        assert!(human(&a).contains("connect=11.20ms"));

        // Partial: a close with no observed connect.
        let p = Connection {
            partial: true,
            ..Default::default()
        };
        let pl = human(&p);
        assert!(pl.contains("incomplete"));
        assert!(!pl.contains("reused"), "must not claim reuse (not a Connection concept)");

        // Established but no connect-latency sample (e.g. passive open).
        let e = Connection::default();
        assert!(human(&e).contains("established"));

        // SNI/region surface when known; the segment is omitted when neither is.
        let mut s = Connection::default();
        s.endpoint.region = Some("eu-west-1".into());
        s.tls.sni = Some("b.s3.eu-west-1.amazonaws.com".into());
        let sl = human(&s);
        assert!(sl.contains("region=eu-west-1") && sl.contains("sni=b.s3.eu-west-1.amazonaws.com"));
        assert!(!human(&e).contains("sni="), "no SNI segment when unknown");
    }

    #[test]
    fn fold_counts_only_undecodable_records() {
        let mut c = Correlator::new();
        let mut undecoded = 0u64;

        // A runt slice can't even hold a header -> not decodable -> counted.
        assert!(fold(&mut c, &[0u8; 4], &mut undecoded, None, &mut None).is_none());
        assert_eq!(undecoded, 1);

        // A well-formed close record decodes cleanly: it yields a Connection and
        // must NOT bump the counter (None-vs-record is unrelated to decodability).
        let mut close = vec![0u8; std::mem::size_of::<s3tap_events::EvtTcpClose>()];
        close[0..2].copy_from_slice(&s3tap_events::SCHEMA_VERSION.to_ne_bytes());
        close[2..4].copy_from_slice(&s3tap_events::EVT_TCP_CLOSE.to_ne_bytes());
        assert!(fold(&mut c, &close, &mut undecoded, None, &mut None).is_some());
        assert_eq!(undecoded, 1, "a decodable record must not be counted");
    }

    #[test]
    fn obscure_cookie_hides_pointer_but_stays_stable() {
        let o = CookieObscurer::new();
        let raw = 0xffff_8881_2345_0000u64; // a kernel-pointer-shaped value
        let id = o.apply(raw);
        assert_ne!(id, raw, "the raw sk-pointer must never be emitted");
        assert_eq!(id, o.apply(raw), "same socket -> same id within a run");
        assert_ne!(id, o.apply(raw ^ 0x1000), "different sockets -> different ids");
        assert_eq!(o.apply(0), 0, "the 0 == N/A sentinel is preserved");
    }

    #[test]
    fn dump_events_never_prints_a_raw_kernel_pointer() {
        // `--dump-events` is debug output a user tees into a file or pastes into a bug
        // report, and it was the one path where the raw `struct sock *` escaped: the record
        // path obscures at emit, but `dump_event` formatted `hdr.sock_cookie` directly. That
        // made three documents false at once — README ("never leave the process"),
        // SECURITY.md ("obscured at emit") and the schema's own field docs.
        const PTR: u64 = 0xffff_8881_07a3_b800; // a plausible kernel heap address
        let obscure = CookieObscurer::new();

        let mut hdr = s3tap_events::EventHdr { sock_cookie: PTR, tgid: 42, ..Default::default() };
        let line = dump_line(
            &Event::TcpConnect(s3tap_events::EvtTcpConnect { hdr, ..Default::default() }),
            &obscure,
        );
        assert!(line.contains("TCP_CONNECT"), "{line}");
        assert!(!line.contains(&PTR.to_string()), "the raw pointer must not appear:\n{line}");
        assert!(!line.contains(&format!("{PTR:x}")), "nor in hex:\n{line}");
        // It is obscured, not dropped: the cookie is still the join key a reader needs.
        assert!(
            line.contains(&obscure.apply(PTR).to_string()),
            "the obscured id must be printed:\n{line}"
        );

        // 0 is the "not applicable" sentinel and must survive as 0, exactly as on the record
        // path — otherwise a reader cannot tell "no socket" from "some socket".
        hdr.sock_cookie = 0;
        let line = dump_line(
            &Event::TcpConnect(s3tap_events::EvtTcpConnect { hdr, ..Default::default() }),
            &obscure,
        );
        assert!(line.contains("cookie=0 "), "the 0 sentinel stays 0:\n{line}");
    }

    #[test]
    fn every_cookie_carrying_dump_line_obscures_it() {
        // The test above pinned ONE variant, and `dump_line` has eight that print a cookie.
        // A new variant (or a new `format!` in an old one) that reaches for
        // `hdr.sock_cookie` directly is exactly the regression that shipped once, so cover
        // the whole set rather than the one that happened to be found.
        use s3tap_events::*;
        const PTR: u64 = 0xffff_8881_07a3_b800;
        let obscure = CookieObscurer::new();
        let hdr = EventHdr { sock_cookie: PTR, tgid: 42, ..Default::default() };
        let events: Vec<(&str, Event)> = vec![
            ("TCP_CONNECT", Event::TcpConnect(EvtTcpConnect { hdr, ..Default::default() })),
            ("TCP_CLOSE", Event::TcpClose(EvtTcpClose { hdr, ..Default::default() })),
            ("TCP_SAMPLE", Event::TcpSample(EvtTcpSample { hdr, ..Default::default() })),
            ("DNS_QUERY", Event::DnsQuery(Box::new(EvtDnsQuery { hdr, ..Default::default() }))),
            ("DNS_RESPONSE",
                Event::DnsResponse(Box::new(EvtDnsResponse { hdr, ..Default::default() }))),
            ("TLS_HELLO",
                Event::TlsHandshake(Box::new(EvtTlsHandshake { hdr, ..Default::default() }))),
            ("TLS_SERVER", Event::TlsServer(EvtTlsServer { hdr, ..Default::default() })),
            ("CONN_ID", Event::ConnId(EvtConnId { hdr, ..Default::default() })),
        ];
        assert_eq!(events.len(), 8, "every cookie-printing variant must be listed");
        for (label, e) in &events {
            let line = dump_line(e, &obscure);
            assert!(line.contains(label), "wrong variant for {label}: {line}");
            assert!(!line.contains(&PTR.to_string()), "{label} leaked the raw pointer:\n{line}");
            assert!(!line.contains(&format!("{PTR:x}")), "{label} leaked it in hex:\n{line}");
            assert!(
                line.contains(&obscure.apply(PTR).to_string()),
                "{label} must still print the obscured join key:\n{line}"
            );
        }
    }

    #[test]
    fn emit_obscures_the_sock_cookie() {
        // A record whose raw cookie is a pointer-shaped value must not serialize
        // that value; emit replaces it with the obscured id.
        let raw = 0xffff_8881_dead_beefu64;
        let conn = Connection {
            sock_cookie: raw,
            ..Default::default()
        };
        let mut buf = Vec::new();
        emit(&mut buf, Format::Jsonl, &CookieObscurer::new(), Record::Connection(Box::new(conn)), &batch_now())
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.contains(&raw.to_string()),
            "the raw sk-pointer must not appear in the emitted record: {s}"
        );
        assert!(s.contains(r#""sock_cookie":""#), "cookie still a decimal string");
    }

    #[test]
    fn every_record_in_a_batch_carries_the_same_emit_time() {
        // The `emitted_at` contract (see `Operation::emitted_at` in s3tap-schema) is ONE
        // timestamp per emitted BATCH. `emit` used to call `Utc::now()` itself, which split a
        // single drain into N distinct emit times — indistinguishable downstream from N
        // separate flushes, and the schema comment called out the fix as belonging here.
        //
        // A sentinel `now` rather than a real clock: it proves `emit` USES what it was given
        // and never reads a clock of its own. Comparing two real `batch_now()` values could
        // not prove that, since both could land in the same millisecond.
        const STAMP: &str = "2026-07-27T12:00:00.000Z";
        let obscure = CookieObscurer::new();
        let mut buf = Vec::new();
        for rec in [
            Record::Connection(Box::default()),
            Record::Operation(Box::default()),
            Record::TcpSample(Box::default()),
        ] {
            emit(&mut buf, Format::Jsonl, &obscure, rec, STAMP).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        let stamps: Vec<&str> = out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                l.split(r#""emitted_at":""#)
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .expect("every first-order record stamps emitted_at")
            })
            .collect();
        assert_eq!(stamps.len(), 3, "all three record kinds emit in jsonl:\n{out}");
        assert!(stamps.iter().all(|&t| t == STAMP), "one batch, one emit time: {stamps:?}");
    }

    #[test]
    fn emit_jsonl_stamps_emitted_at() {
        let mut buf = Vec::new();
        emit(
            &mut buf,
            Format::Jsonl,
            &CookieObscurer::new(),
            Record::Connection(Box::default()),
            &batch_now(),
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains(r#""emitted_at":""#), "emit must stamp emitted_at");
        assert!(s.contains("s3tap.connection/2"));
        assert!(s.ends_with('\n'), "jsonl record must end with a newline");

        // Pin the emitted_at shape: RFC3339, UTC, fixed millisecond precision
        // (SecondsFormat::Millis). Consumers parse this field, so a format change
        // — e.g. variable-length or no fractional seconds — must be a conscious
        // decision, not a silent SecondsFormat edit.
        let ts = s
            .split(r#""emitted_at":""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("emitted_at value");
        let frac = ts
            .strip_suffix('Z')
            .and_then(|t| t.rsplit_once('.'))
            .map(|(_, f)| f)
            .expect("emitted_at must end in .<frac>Z");
        assert_eq!(frac.len(), 3, "emitted_at must carry exactly 3 (milli) digits, got {ts:?}");
        assert!(frac.chars().all(|c| c.is_ascii_digit()), "millis must be digits: {ts:?}");
    }

    /// One line at a time, terminator stripped, with a final unterminated line still a
    /// line and EOF reported exactly once.
    #[test]
    fn read_line_capped_splits_lines_and_signals_eof() {
        let mut r = std::io::Cursor::new(b"a\nbb\n\nccc".to_vec());
        let mut buf = Vec::new();
        let mut got = Vec::new();
        while let Some(over) = read_line_capped(&mut r, &mut buf, 64).unwrap() {
            assert!(!over);
            got.push(String::from_utf8(buf.clone()).unwrap());
        }
        assert_eq!(got, ["a", "bb", "", "ccc"]);
        // EOF is sticky: another call still reports nothing left.
        assert!(read_line_capped(&mut r, &mut buf, 64).unwrap().is_none());
    }

    /// The bound: a line past the cap is reported as over-long, DROPPED WHOLE (no prefix
    /// survives to be mis-parsed), and the stream resumes cleanly on the next line — the
    /// buffer never grows past the cap no matter how long the line is.
    #[test]
    fn read_line_capped_drops_an_overlong_line_and_resumes() {
        let mut data = b"ok\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', 10_000));
        data.extend(b"\ntail\n");
        let mut r = std::io::Cursor::new(data);
        let mut buf = Vec::new();
        assert_eq!(read_line_capped(&mut r, &mut buf, 16).unwrap(), Some(false));
        assert_eq!(buf, b"ok");
        assert_eq!(read_line_capped(&mut r, &mut buf, 16).unwrap(), Some(true), "over the cap");
        assert!(buf.is_empty(), "an over-long line must not leave a truncated prefix");
        assert_eq!(read_line_capped(&mut r, &mut buf, 16).unwrap(), Some(false));
        assert_eq!(buf, b"tail");
        assert!(read_line_capped(&mut r, &mut buf, 16).unwrap().is_none());
    }

    /// A line with no terminator at all (the pathological "one 10 MB line" input) is
    /// bounded too: it reads as a single over-long line, then EOF.
    #[test]
    fn read_line_capped_bounds_an_unterminated_flood() {
        let data = vec![b'z'; 10 * 1024 * 1024];
        let mut r = std::io::Cursor::new(data);
        let mut buf = Vec::new();
        assert_eq!(read_line_capped(&mut r, &mut buf, 4096).unwrap(), Some(true));
        assert!(buf.is_empty());
        assert!(read_line_capped(&mut r, &mut buf, 4096).unwrap().is_none());
    }

    const OP_LINE: &str = r#"{"schema":"s3tap.operation/1","op_id":"op-0","ts_ns":"0","sock_cookie":"1000","req_seq":0,"app":{"pid":7},"verb":null,"s3_op":"GetObject","bucket":"b","key_hash":"k0","dns":null,"tcp_connect_ns":null,"tls_handshake_ns":null,"tls_version":null,"ttfb_ns":28000000,"download_ns":12000000,"total_ns":null,"content_length":1048576,"op_bytes_sent":null,"op_bytes_recv":null,"bytes_sent":0,"bytes_recv":0,"retransmits":0,"srtt_us":null,"lifetime_ns":null,"connection_reused":true,"http_status":200,"aws_request_id":null,"partial":false,"delimitation":"clean"}"#;

    /// The streaming reader must be accounting-identical to the whole-string parse it
    /// replaced: same records, same bad_lines/unknown_schema — including blank lines, junk,
    /// an unknown schema, CRLF terminators and a final line with no newline.
    #[test]
    fn stream_records_matches_the_whole_string_parse() {
        let input = format!(
            "{OP_LINE}\r\n\nnot json\n{{\"schema\":\"who/9\"}}\n[1,2,3]\n{OP_LINE}"
        );
        let (want, want_stats) = s3tap_doctor::parse_records(&input);
        let (got, got_stats) =
            stream_records(std::io::Cursor::new(input.as_bytes()), "test").unwrap();
        assert_eq!(got.len(), want.len(), "same record count");
        assert_eq!(got_stats.bad_lines, want_stats.bad_lines);
        assert_eq!(got_stats.unknown_schema, want_stats.unknown_schema);
        assert_eq!(got_stats.bad_lines, 2, "junk + the bare array");
        assert_eq!(got_stats.unknown_schema, 1);
        assert_eq!(got.len(), 2);
    }

    /// A pathological line (far past MAX_INPUT_LINE) is skipped as a bad line rather than
    /// buffered — the record before and after it still parse, so one absurd line degrades
    /// the report by exactly one line instead of ending the process.
    #[test]
    fn stream_records_skips_a_pathological_line_without_buffering_it() {
        let mut input = String::with_capacity(4 * MAX_INPUT_LINE);
        input.push_str(OP_LINE);
        input.push('\n');
        input.push_str(&"x".repeat(3 * MAX_INPUT_LINE));
        input.push('\n');
        input.push_str(OP_LINE);
        input.push('\n');
        let (got, stats) =
            stream_records(std::io::Cursor::new(input.as_bytes()), "test").unwrap();
        assert_eq!(got.len(), 2, "both real records survive");
        assert_eq!(stats.bad_lines, 1, "the over-long line is counted, never hidden");
        assert_eq!(stats.unknown_schema, 0);
    }

    /// Invalid UTF-8 is a bad LINE, not a failed read: previously one stray byte anywhere
    /// in a capture failed the whole command.
    #[test]
    fn stream_records_counts_a_non_utf8_line_as_bad() {
        let mut data = Vec::new();
        data.extend_from_slice(OP_LINE.as_bytes());
        data.extend_from_slice(b"\n\xff\xfe not utf8\n");
        let (got, stats) = stream_records(std::io::Cursor::new(data), "test").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(stats.bad_lines, 1);
    }

    /// `stream_bounded` stops at the cap: it parses at most `hard` items, and — matching
    /// `load_trace` — neither parses nor counts the lines after the stop. This is what
    /// keeps `--max-events N` a bound on WORK, not just on what's analyzed afterwards.
    #[test]
    fn stream_bounded_stops_at_the_cap_without_reading_on() {
        // A trivial parser: each non-empty line is one item, "skip" lines are skipped.
        let parse = |chunk: &str| -> (Vec<String>, usize) {
            let mut out = Vec::new();
            let mut skipped = 0;
            for l in chunk.lines() {
                if l.trim().is_empty() {
                    continue;
                }
                if l == "skip" {
                    skipped += 1;
                } else {
                    out.push(l.to_string());
                }
            }
            (out, skipped)
        };
        let input = "a\nskip\nb\nc\nskip\nd\n";
        // Unbounded: everything, including every skip.
        let (all, sk) = stream_bounded(std::io::Cursor::new(input), "t", usize::MAX, parse).unwrap();
        assert_eq!(all, ["a", "b", "c", "d"]);
        assert_eq!(sk, 2);
        // Bounded at 3 items: stops there, and the trailing "skip"/"d" are never seen.
        let (some, sk) = stream_bounded(std::io::Cursor::new(input), "t", 3, parse).unwrap();
        assert_eq!(some, ["a", "b", "c"]);
        assert_eq!(sk, 1, "only the skip BEFORE the stop is counted");
        // A cap of 1 is the tightest boundary the batching has to get right.
        let (one, sk) = stream_bounded(std::io::Cursor::new(input), "t", 1, parse).unwrap();
        assert_eq!(one, ["a"]);
        assert_eq!(sk, 0);
    }

    /// The same bound over the REAL analyze loader, at the exact ratio `analyze_cmd` uses
    /// (`max_events + 1`, one past the cap so the sampler still detects truncation).
    #[test]
    fn stream_bounded_truncates_a_real_trace_one_past_max_events() {
        let line = |i: u32| {
            format!(
                r#"{{"schema":"s3tap.operation/1","op_id":"op-{i}","ts_ns":"{i}","sock_cookie":"1","req_seq":0,"app":{{"pid":7}},"verb":null,"s3_op":"GetObject","bucket":"b","key_hash":"k{i}","dns":null,"tcp_connect_ns":null,"tls_handshake_ns":null,"tls_version":null,"ttfb_ns":1,"download_ns":1,"total_ns":null,"content_length":1024,"op_bytes_sent":null,"op_bytes_recv":null,"bytes_sent":0,"bytes_recv":0,"retransmits":0,"srtt_us":null,"lifetime_ns":null,"connection_reused":true,"http_status":200,"aws_request_id":null,"partial":false,"delimitation":"clean"}}"#
            )
        };
        let input: String = (0..50).map(|i| format!("{}\n", line(i))).collect();
        let load = |b: &str| s3tap_advisor::analyze::load_trace(b, 0);
        let (all, _) =
            stream_bounded(std::io::Cursor::new(input.clone()), "t", usize::MAX, load).unwrap();
        assert_eq!(all.len(), 50, "the loader reads this fixture as 50 events");
        // max_events = 10 ⇒ hard = 11: ten to analyze plus the one that proves truncation.
        let (capped, _) = stream_bounded(std::io::Cursor::new(input), "t", 11, load).unwrap();
        assert_eq!(capped.len(), 11);
    }
}
