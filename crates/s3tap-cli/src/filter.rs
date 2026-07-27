// crates/s3tap-cli/src/filter.rs
//
// M4 F2 — per-app scope resolution (the userspace half of the in-kernel filter).
// Turns --pid/--app/--exe/--cgroup/--container into
// the kernel's filter_pids / filter_cgroups allowlist, then keeps filter_pids live
// as matching processes exec (EVT_PROC_EXEC). The MATCH logic is pure and unit-
// tested; the /proc + cgroup reads are thin I/O wrappers around it.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use aya::maps::{HashMap as BpfHashMap, MapData};
use s3tap_events::EvtProcExec;

/// The parsed --filter flags. `apps`/`exes` drive live process matching (a forking
/// worker is picked up on its exec); `pids`/`cgroups` are fixed sets written once.
#[derive(Debug, Default, Clone)]
pub struct FilterSpec {
    /// --pid: exact tgids.
    pub pids: Vec<u32>,
    /// --app: matches a process's exe BASENAME, with or without a version suffix
    /// (`python3` matches `/usr/bin/python3.12`). Not `comm` — see
    /// [`FilterSpec::matches_app_exe`].
    pub apps: Vec<String>,
    /// --exe: exact executable path (disambiguates two interpreters).
    pub exes: Vec<String>,
    /// --cgroup + resolved --container: cgroup ids (as `bpf_get_current_cgroup_id`).
    pub cgroups: Vec<u64>,
}

impl FilterSpec {
    /// Any scope flag set ⇒ ALLOWLIST mode. Empty ⇒ TRACK_ALL (default run).
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.pids.is_empty()
            || !self.apps.is_empty()
            || !self.exes.is_empty()
            || !self.cgroups.is_empty()
    }

    /// Is the whole scope decided ONLY by the exe name/path, with no `--pid`/`--cgroup`
    /// clause anywhere? A whole-config question — used where an ambiguous EMPTY capture
    /// needs an answer for the config as a whole (`scope_never_matched`'s "did a name
    /// scope simply never match anyone" check). NOT used for per-process exec
    /// revocation: [`admission_for`] answers that per-tgid instead, since a `--pid 42
    /// --app python3` config must still revoke an `--app`-admitted process OTHER than
    /// pid 42, and this predicate can't see which process is being asked about.
    #[must_use]
    pub fn is_name_only(&self) -> bool {
        (!self.apps.is_empty() || !self.exes.is_empty())
            && self.pids.is_empty()
            && self.cgroups.is_empty()
    }

    /// Does a process with this `exe` path match --app (basename) or --exe (full path)?
    /// Pure — the one piece both the startup /proc scan and the live exec handler share.
    ///
    /// `comm` is deliberately NOT consulted, though it used to be. This predicate decides
    /// ADMISSION INTO A PRIVILEGED AGENT'S CAPTURE SCOPE, and `comm` is chosen by the
    /// unprivileged owner of the candidate process: any process can `prctl(PR_SET_NAME)`
    /// itself to "python3" with no filesystem access, no exec and no privilege, and can do
    /// so AFTER exec, so no admission-time check can ever pin it. That bought a local
    /// attacker two things against the operator running `s3tap --app python3`:
    ///
    /// * RECORD FORGERY. An admitted process controls its own request line and Host
    ///   header, so it can inject `s3tap.operation` records with any bucket/verb/status
    ///   into the operator's capture — enough to flip a doctor/scorecard verdict or an
    ///   `advise --strict` CI gate.
    /// * BLINDING. `filter_pids` is capped at 65536 (bpf/src/s3tap.bpf.c) and `on_exec`
    ///   only ever ADDS, so spawning that many self-renamed processes evicts the real
    ///   target and the capture silently goes quiet.
    ///
    /// The exe basename is read by the agent from `/proc/<pid>/exe`, is fixed for the life
    /// of the exec, and names a real inode, so forging it costs an actual executable at a
    /// path the attacker controls. That is a much narrower door, not a sealed one: a user
    /// who can run a binary they named `python3` is still admitted. On an untrusted
    /// multi-tenant host use `--exe` (exact path), `--cgroup`/`--container`, or `--pid`,
    /// none of which a peer process can influence.
    ///
    /// VERSION SUFFIXES. `--app <name>` matches the basename exactly OR with a trailing
    /// version suffix stripped ([`strip_version_suffix`]), so `--app python3` matches
    /// `/usr/bin/python3.12`. That is not a convenience. `/proc/<pid>/exe` is the
    /// symlink-RESOLVED path, so on every mainstream distro the interpreter an operator
    /// names only ever appears under its versioned name (`/usr/bin/python3` is a symlink to
    /// `python3.12`), and an exact-basename rule matched NOTHING for the flag's own
    /// documented example. The suffix has to start at a `-` or `.` and be digits from
    /// there, so `python311` and `not-python3-really` stay out.
    ///
    /// It costs the threat model nothing. Admission still requires a real executable INODE
    /// the attacker had to put on disk under that name: the admitted set widens from
    /// {`python3`} to {`python3`, `python3.12`, `python3-2`, …}, every member of which is
    /// exactly as expensive to forge as the first. What is never consulted is a string the
    /// candidate merely CHOSE: `comm`, argv[0], or the execve `filename` argument. The last
    /// of those is tempting (it is on `EvtProcExec`, and it is what an interpreter is
    /// launched by) but it is the same door as `comm`: a symlink named `python3` pointing
    /// at any binary at all is enough, so it would restore the opt-in this narrowing closed.
    /// Neither reader ever falls back to it, on ANY error path (see [`resolve_exe`]).
    ///
    /// Correcting a claim that used to sit here: `comm` and the exe basename do NOT
    /// normally agree. The kernel sets `comm` from the basename of the execve FILENAME
    /// ARGUMENT (truncated to 15 chars), not from the resolved inode. A process launched
    /// through `/usr/bin/python3` therefore has `comm` "python3" while its exe basename is
    /// "python3.12". The versioned interpreter symlink is precisely the case where the two
    /// never agreed, which is why dropping the `comm` arm silently broke the flag.
    #[must_use]
    pub fn matches_app_exe(&self, exe: &str) -> bool {
        if self.exes.iter().any(|x| x == exe) {
            return true;
        }
        let base = exe.rsplit('/').next().unwrap_or(exe);
        let stem = strip_version_suffix(base);
        self.apps.iter().any(|a| a == base || stem == Some(a.as_str()))
    }
}

/// An exe basename with a trailing VERSION suffix removed: `python3.12` → `python3`,
/// `gcc-11` → `gcc`, `libreoffice-7.4` → `libreoffice`. `None` when there is nothing to
/// strip, which is the common case (`curl`, `java`, `python3`).
///
/// The suffix must START at a `-` or `.` separator and be digits and dots from there to the
/// end, over a non-empty stem. That separator requirement is what keeps the rule from
/// widening `--app`: `python3` keeps its `3` (so `--app python` still matches nothing),
/// `python311` is untouched, and `not-python3-really` has no numeric tail. The EARLIEST
/// qualifying separator wins, so `python3.12.1` also stems to `python3` rather than
/// `python3.12`.
fn strip_version_suffix(base: &str) -> Option<&str> {
    for (i, c) in base.char_indices() {
        if c != '-' && c != '.' {
            continue;
        }
        let (stem, tail) = base.split_at(i);
        let tail = &tail[c.len_utf8()..];
        // A bare separator, a stemless name (".12") or a non-numeric tail ("-really") is
        // not a version: keep looking further right rather than stripping something real.
        if stem.is_empty() || !tail.starts_with(|t: char| t.is_ascii_digit()) {
            continue;
        }
        if tail.chars().all(|t| t.is_ascii_digit() || t == '.') {
            return Some(stem);
        }
    }
    None
}

/// The warning an `--app`/`--exe` scope owes the operator when the startup /proc scan
/// matched NOTHING, given how many pids it did match. `None` when there is nothing to say
/// (something matched, or no name-based scope was asked for).
///
/// Without it the failure is silent and indistinguishable from success: an unmatched scope
/// still engages ALLOWLIST mode, so the run sits quiet, exits 0 and writes an empty file,
/// from which the operator concludes their app never talks to S3. `--container` already
/// warns and bails when it resolves nothing. `--app`/`--exe` cannot bail, because a
/// matching process may legitimately exec later (that is what `Filter::on_exec` is for), so
/// it says so instead. Returned as text rather than printed so the caller can place it with
/// the rest of the startup banner and so the wording is unit-tested.
//
#[must_use]
pub fn unmatched_scope_warning(spec: &FilterSpec, matched: usize) -> Option<String> {
    if matched > 0 || (spec.apps.is_empty() && spec.exes.is_empty()) {
        return None;
    }
    let mut tokens: Vec<String> = spec.apps.iter().map(|a| format!("--app {a}")).collect();
    tokens.extend(spec.exes.iter().map(|x| format!("--exe {x}")));
    // Only claim an EMPTY scope when there is genuinely nothing else in it: with --pid or
    // --cgroup also given the capture still has a target, so overstating it would send the
    // operator hunting a scope bug that isn't there.
    let rest = if spec.pids.is_empty() && spec.cgroups.is_empty() {
        "so the capture starts with an EMPTY scope"
    } else {
        "so nothing was added to the scope beyond the --pid/--cgroup entries"
    };
    Some(format!(
        "WARNING: {} matched no running process, {rest}. Nothing is captured until a \
         matching process execs. An empty result then means the scope missed rather than \
         that the app was quiet. --app matches the basename of /proc/<pid>/exe with an \
         optional version suffix, so check yours with `readlink /proc/<pid>/exe`. For a \
         process that is already running use --pid <tgid>, or --cgroup/--container for a \
         whole tree.",
        tokens.join(" ")
    ))
}

/// What `/proc/<pid>/exe` answered. The ONLY identity either reader will admit on: it is
/// the symlink-RESOLVED path of the inode the kernel actually execed, so the process being
/// judged cannot choose it.
///
/// The two failure modes are kept apart because they mean opposite things. ENOENT is a
/// process that is gone, or a kernel thread / zombie that never had an exe, so there is
/// nothing to capture and nothing to say. EACCES is a LIVE process we are not allowed to
/// identify, which is a permission problem the operator has to hear about because it silently
/// shrinks the scope they asked for.
enum ExeLink {
    /// The resolved absolute path of the running executable.
    Resolved(String),
    /// ENOENT: no exe link to read (exited, kernel thread, zombie).
    Absent,
    /// EACCES/EPERM: the link is there and we may not read it.
    Denied,
}

/// Read `/proc/<pid>/exe`, classified by [`ExeLink`].
///
/// Classified by ERRNO rather than by a follow-up `/proc/<pid>` existence probe: the probe
/// races the very exit it is trying to detect, and ENOENT already covers every "there is no
/// executable to admit" case. One gap worth naming: a `hidepid=2` /proc hides the directory
/// outright, so a denial there arrives as ENOENT and is read as Absent. That still fails
/// closed, it just fails quietly.
fn resolve_exe(proc_dir: &Path) -> ExeLink {
    match std::fs::read_link(proc_dir.join("exe")) {
        Ok(p) => ExeLink::Resolved(p.to_string_lossy().into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => ExeLink::Denied,
        Err(_) => ExeLink::Absent,
    }
}

/// What an operator is owed when `/proc/<pid>/exe` is unreadable for a LIVE process. That is
/// the one case where `--app`/`--exe` cannot answer its own question, and the honest answer
/// is that the process stays out of scope.
///
/// It has to be said out loud. A scope that quietly stops matching is worse than an error:
/// the run still exits 0 with a smaller capture, from which the operator concludes their app
/// was quiet rather than that s3tap could not see it. The wording names the real cause
/// (CAP_SYS_PTRACE, not a bad `--app` string) and the scopes that need no /proc read, because
/// the first thing anyone does with a scope that missed is retype the app name.
///
/// Returned as text rather than printed so the wording is unit-tested.
#[must_use]
pub fn exe_denied_warning() -> &'static str {
    "WARNING: /proc/<pid>/exe was unreadable for a live process, so --app/--exe cannot tell \
     what that process is running and leaves it OUT of the capture. s3tap never falls back to \
     the name a process was launched under, because the process itself chooses that name. \
     Reading another user's exe link needs CAP_SYS_PTRACE, which `s3tap setup` deliberately \
     does not grant, so a capability-tagged s3tap resolves only processes owned by the user \
     running it. Run s3tap as root to scope another user's app by name, or use --pid <tgid>, \
     --cgroup <id> or --container <name>, none of which read /proc/<pid>/exe."
}

/// Emit [`exe_denied_warning`] at most once per run. Both readers share this flag so they
/// cannot drift into two different behaviours, and so a busy host reports the condition once
/// rather than per exec: the live reader sits on the drain path and EVERY exec on the box
/// reaches it while a filter is active.
/// The `filter_pids` allowlist could not take another entry. Warned ONCE: the condition is
/// sticky (a full map stays full until something exits), so per-occurrence output would bury
/// the records the operator actually wants while adding nothing after the first line.
pub fn warn_allowlist_full_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        enote!(
            "s3tap: WARNING the in-kernel scope allowlist is full, so at least one matching \
             process is NOT being captured and this capture is incomplete. It holds 65536 \
             pids; a fork-heavy target under a broad --app/--exe scope can fill it. Narrow \
             the scope (--pid/--exe), or use --cgroup/--container, which needs one entry for \
             the whole tree instead of one per process."
        );
    }
}

fn warn_exe_denied_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        enote!("s3tap: {}", exe_denied_warning());
    }
}

/// Does this exec admit its process into an `--app`/`--exe` scope? Split out of
/// [`Filter::on_exec`] so the /proc READ is testable against a real process (the map insert
/// is not, it needs a loaded BPF map). It takes the whole event and uses NOTHING from it but
/// `hdr.tgid`, which is the point rather than an oversight: the tests hand it an event whose
/// `exe_path()` names the scoped app while the pid runs something else entirely.
///
/// TRUSTED vs CHOSEN. The only identity consulted is `/proc/<tgid>/exe`. The event also
/// carries the execve `filename` ARGUMENT, which the exec'ing process picks: a symlink named
/// `python3` pointing at any binary at all is enough, so admitting on it hands any local user
/// a way into the privileged capture (record forgery and `filter_pids` eviction, both spelled
/// out on [`FilterSpec::matches_app_exe`]). That argument used to be the fallback here,
/// justified by "the agent runs as root and the tgid is live at drain time". Both halves are
/// false for the deployment this project documents. `s3tap setup` tags the BINARY with
/// cap_bpf/cap_perfmon/cap_dac_read_search and the agent then runs under the invoking USER,
/// while reading another user's `/proc/<pid>/exe` is gated by
/// `ptrace_may_access(PTRACE_MODE_READ)`, which wants same-uid or CAP_SYS_PTRACE.
/// cap_dac_read_search bypasses DAC and NOT that check (the link is mode 0777, so DAC was
/// never the gate), so the readlink returns EACCES for every process owned by anyone else and
/// the fallback took over in exactly the case that mattered.
///
/// Hence: a resolution failure is never an admission. `Absent` is silent, since a process
/// with no exe link is one whose pid would capture nothing anyway. `Denied` is a scope the
/// operator asked for and is not getting, so it warns once.
fn exec_is_in_scope(spec: &FilterSpec, e: &EvtProcExec) -> bool {
    match resolve_exe(Path::new(&format!("/proc/{}", e.hdr.tgid))) {
        ExeLink::Resolved(exe) => spec.matches_app_exe(&exe),
        ExeLink::Denied => {
            // Only a NAME-based scope loses anything here. Under --pid/--cgroup alone this
            // event was never going to admit a pid, so the warning would be noise.
            if !spec.apps.is_empty() || !spec.exes.is_empty() {
                warn_exe_denied_once();
            }
            false
        }
        ExeLink::Absent => false,
    }
}

/// `filter_pids` VALUE: how this tgid earned its seat, which is what decides whether a later
/// exec may take it away. The kernel side only ever tests the key's PRESENCE
/// (`bpf_map_lookup_elem` non-NULL in `s3tap.bpf.c`), so the byte is free to carry provenance
/// for userspace, and `handle_sched_process_fork` propagates the PARENT's byte to a forked
/// child so a descendant inherits the reason it was admitted, not just the fact.
///
/// Admitted by an identity an exec cannot invalidate: an explicit `--pid`/`--cgroup`, or a
/// fork descendant of one. The kernel deliberately propagates explicit scope down a process
/// tree (a pre-fork server's workers), and those workers routinely exec.
pub const ADMIT_EXPLICIT: u8 = 1;
/// Admitted because the exe MATCHED `--app`/`--exe`. An exec republishes exactly that fact,
/// so an exec away from the scope withdraws the seat (see [`Filter::on_exec`]).
pub const ADMIT_BY_NAME: u8 = 2;

/// What one exec does to the allowlist. Split from [`Filter::on_exec`] for the same reason
/// [`exec_is_in_scope`] is: the decision is testable against a REAL process, the map operation
/// is not (it needs a loaded BPF map).
#[derive(Debug, PartialEq, Eq)]
pub enum ExecAdmission {
    /// The exec'd image is in scope: track this tgid from now on, under this provenance tag.
    Admit(u8),
    /// It is NOT, and the seat it holds was earned by NAME, which this exec just disproved:
    /// withdraw it.
    Revoke,
    /// Not in scope, but the seat (if any) was not the exe's to give, so it is not the exe's
    /// to take: an explicit `--pid`/`--cgroup`, or a fork descendant of one.
    Leave,
}

/// The admission decision for one `EVT_PROC_EXEC`, given the provenance byte this tgid
/// already holds in `filter_pids` (`None` when it holds no seat). See [`Filter::on_exec`]
/// for why a non-matching exec must be able to REVOKE and why an explicit scope must not.
///
/// Revocation keys on the SEAT'S PROVENANCE, not on the shape of the config, and the two
/// wrong answers this has already produced say why neither simpler rule works:
///
/// * Gating on `FilterSpec::is_name_only` (is the whole scope decided by name?) meant
///   `--pid 42 --app python3` disabled exe-revocation for EVERY process, not just pid 42, so
///   a process admitted via `--app` kept its seat forever after exec-ing away from python3.
///   That is the forged-record/eviction hole `on_exec` exists to close.
/// * Gating instead on "is THIS tgid explicitly named" revoked the descendants of an explicit
///   `--pid`. The kernel propagates explicit scope down a process tree on purpose (a pre-fork
///   server's workers), those workers are never themselves in `spec.pids`, and they routinely
///   exec, so every one of them lost its seat the moment it did.
///
/// The provenance byte answers both at once, because it records WHY the seat was granted and
/// is inherited across fork. [`ADMIT_BY_NAME`] is the only tag an exec can disprove.
#[must_use]
pub fn admission_for(spec: &FilterSpec, e: &EvtProcExec, current: Option<u8>) -> ExecAdmission {
    if exec_is_in_scope(spec, e) {
        // An explicitly named identity keeps the exec-immune tag even when its exe also
        // happens to match, so a later exec away from the name cannot strip a seat that
        // `--pid`/`--cgroup` (not the exe) granted.
        let tag = if spec.pids.contains(&e.hdr.tgid) || spec.cgroups.contains(&e.cgroup_id) {
            ADMIT_EXPLICIT
        } else {
            ADMIT_BY_NAME
        };
        ExecAdmission::Admit(tag)
    } else if current == Some(ADMIT_BY_NAME) {
        ExecAdmission::Revoke
    } else {
        // ADMIT_EXPLICIT, or no seat at all — nothing here is the exe's to withdraw.
        ExecAdmission::Leave
    }
}

/// The live filter held across the drain loop: the spec plus an owned handle to the
/// kernel `filter_pids` map, so a worker that execs into scope is added immediately.
pub struct Filter {
    spec: FilterSpec,
    pids: BpfHashMap<MapData, u32, u8>,
    /// Reaps since the last full `/proc` rescan — see [`Filter::reap_dead`] for why the two
    /// run on different cadences even though one call drives both.
    since_rescan: u32,
}

/// Reap ticks per full `/proc` rescan. The reap itself must stay frequent (pid reuse), but
/// the rescan is a directory walk plus an exe resolution per live process, on the same
/// single-threaded task that drains the rings — at the reap's own 5 s cadence that is a
/// recurring stall the ring has to absorb. The rescan only recovers admissions that a
/// momentarily-full map dropped, so a slower cadence costs a missed worker at most this much
/// extra latency, and the ring keeps buffering meanwhile.
const RESCAN_EVERY: u32 = 6;

impl Filter {
    #[must_use]
    pub fn new(spec: FilterSpec, pids: BpfHashMap<MapData, u32, u8>) -> Self {
        Filter { spec, pids, since_rescan: 0 }
    }

    /// Handle one EVT_PROC_EXEC: if the exec'd process matches --app/--exe, add its
    /// tgid to filter_pids so its connections are captured from now on, and if it does NOT,
    /// remove any admission that tgid was already holding. (--pid and cgroup scopes need no
    /// exec handling: pids are fixed, a container's children inherit its cgroup.)
    ///
    /// The removal is what keeps the exe-inode requirement from being one exec deep. Admission
    /// is inherited across fork() in-kernel and, without this, was never withdrawn: a local
    /// user could exec a world-executable system binary that happens to match the scope (no
    /// attacker-owned inode needed, so `matches_app_exe`'s inode discipline buys nothing),
    /// be admitted, then immediately exec their OWN binary and stay in scope. That is a
    /// forged-record path into the operator's capture and a way to evict real workers by
    /// filling the 65536-entry map one cheap exec at a time. An exec is exactly when a
    /// process's identity changes and exactly when this code is already looking at it, so it
    /// is where the answer has to be recomputed rather than merely extended. `reap_dead` is
    /// no help: those pids are alive.
    ///
    /// Only a NAME scope revokes. Under `--pid`/`--cgroup`/`--container` the allowlist entries
    /// were put there by a scope that has nothing to do with the exe, so an exec that does not
    /// match a (possibly empty) `--app` set must not withdraw them.
    ///
    /// RACE (inherent, no kernel fix): this insert is userspace, but the SYN_SENT
    /// scope decision is in-kernel. A brand-new worker that connects to S3 *instantly*
    /// on exec — before the agent drains its EVT_PROC_EXEC and inserts here — has its
    /// FIRST connection dropped (the kernel reads filter_pids before we wrote it). The
    /// kernel can't match --app itself (no string match in BPF — that's why this event
    /// exists). Real workers (gunicorn/Spark) do seconds of setup before connecting, so
    /// it effectively never fires; for instant-connect workloads use --cgroup (race-
    /// free: children inherit the cgroup, which the kernel reads directly).
    pub fn on_exec(&mut self, e: &EvtProcExec) {
        // The decision reads /proc/<tgid>/exe and NOTHING off the event but its tgid: see
        // exec_is_in_scope for which path is trusted, why the event's own execve `filename`
        // argument is not, and what happens when the read is denied. Resolving the same
        // symlink the startup /proc scan reads is also what keeps --exe symmetric: the probe
        // captures the raw execve argument, which can be relative ("./server") or bare
        // ("server"), so matching it verbatim captured a worker only when it predated the
        // agent (the scan saw the absolute link target) and not when it execed later.
        // The seat's provenance decides whether this exec may withdraw it, so read the
        // byte we already hold before deciding (see `admission_for`). A failed read is
        // `None`, which resolves to Leave: never revoke on an answer we could not get.
        let current = self.pids.get(&e.hdr.tgid, 0).ok();
        match admission_for(&self.spec, e, current) {
            // Best-effort in that it is never a crash, but NOT silent: a failed insert here
            // drops this process's traffic in-kernel until a later rescan happens to
            // re-admit it, which is a capture that is quietly missing data rather than one
            // whose target was quiet. Surfaced once (see `warn_allowlist_full_once`).
            ExecAdmission::Admit(tag) => {
                if self.pids.insert(e.hdr.tgid, tag, 0).is_err() {
                    warn_allowlist_full_once();
                }
            }
            // Best-effort in the same sense: a removal that fails leaves the pid tracked,
            // which is the pre-existing behaviour, never a crash. Unconditional rather than
            // "remove if present", because the lookup would cost the same syscall as the
            // remove.
            ExecAdmission::Revoke => {
                let _ = self.pids.remove(&e.hdr.tgid);
            }
            ExecAdmission::Leave => {}
        }
    }

    /// Drop filter_pids entries whose process has exited. on_exec only ever ADDS, so
    /// without this the map grows with churn (gunicorn/Spark workers) toward its
    /// 65536 cap — after which new workers silently stop being added — AND a dead
    /// target's tgid lingers, so a later process REUSING that pid would be captured
    /// though it never matched. We reap by /proc liveness (the agent runs as root):
    /// `/proc/<tgid>` exists as long as ANY thread of the group lives, so this is
    /// correct regardless of thread topology (unlike a sched_process_exit probe,
    /// which fires per-thread). Called on a timer from the drain loop.
    ///
    /// Synchronous (a map-iteration + a /proc stat per allowlisted pid) on the
    /// single-threaded runtime, so it briefly pauses ring draining — negligible at
    /// realistic allowlist sizes (tens–hundreds of pids), but a pathological
    /// near-cap allowlist would stall the drain for the scan. No loss (the kernel
    /// rings buffer); revisit with a bounded/offloaded reap if that ever bites.
    pub fn reap_dead(&mut self) {
        // Two passes — can't mutate the map while iterating its keys.
        let dead: Vec<u32> = self
            .pids
            .keys()
            .flatten()
            .filter(|pid| !Path::new(&format!("/proc/{pid}")).exists())
            .collect();
        for pid in dead {
            let _ = self.pids.remove(&pid);
        }
        // Re-run admission for the scope, not just cleanup: `on_exec`'s insert (and the
        // kernel's own fork-propagation insert) are BEST-EFFORT, so a tgid that should have
        // been admitted can be silently missing if the map was momentarily full when it
        // execed. There is no record of WHICH attempts failed, so a rescan against the live
        // process table is the only way to recover a missed worker — matching `on_exec`'s
        // own doc comment ("a full map just means we miss a worker until the next scan").
        //
        // On its OWN cadence, though (see `RESCAN_EVERY`): unlike the reap, which is a stat
        // per allowlisted pid, this walks all of `/proc` and resolves an exe link per live
        // process, and it runs on the task that drains the rings. `scan_matching_pids`
        // returns immediately when the scope has no --app/--exe clause, so a --pid/--cgroup
        // run pays nothing either way; re-inserting an already-tracked pid is a harmless
        // overwrite, EXCEPT that it must not downgrade an explicit seat, so only tgids the
        // map does not already hold are (re-)admitted by name.
        self.since_rescan += 1;
        if self.since_rescan < RESCAN_EVERY {
            return;
        }
        self.since_rescan = 0;
        for pid in scan_matching_pids(&self.spec) {
            if self.pids.get(&pid, 0).is_ok() {
                continue; // already seated; leave its provenance alone
            }
            if self.pids.insert(pid, ADMIT_BY_NAME, 0).is_err() {
                // An insert that fails here permanently shrinks the capture: this pid's
                // traffic is dropped in-kernel and nothing else will retry it beyond the
                // next rescan. Say so once rather than letting a silently thin capture read
                // as a quiet application.
                warn_allowlist_full_once();
            }
        }
    }
}

/// Resolve a `--container <id|name>` to the cgroup id(s) its processes run under, by
/// scanning /proc for a task whose unified (v2) cgroup line names the token and
/// taking that cgroup directory's inode — which is what `bpf_get_current_cgroup_id`
/// returns on a cgroup-v2 unified hierarchy (the modern default). Best-effort: if it
/// resolves nothing (cgroup v1, an unknown runtime), fall back to `--cgroup <id>`
/// using an id from a `--dump-events` PROC_EXEC line. Returns the distinct ids found.
///
/// FAIL CLOSED on a degenerate token. The match used to be `rest.contains(token)` over the
/// whole `0::/…` path, so an EMPTY token (an unset `$CID` in a wrapper: `--container
/// "$CID"`) matched every process on the box: the flag whose only job is to RESTRICT
/// capture returned every cgroup instead, `ids` was non-empty so neither the caller's
/// "resolved no cgroup" warning nor its fail-closed bail fired, and the banner read like a
/// working scope while `--capture-plaintext` recorded every other tenant's decrypted SigV4
/// headers. A blank (or all-`/`) token resolves NOTHING here, and the match is scoped to a
/// single `/`-delimited component (see [`path_component_contains`]) so no separator-only
/// token can ever match either. The CLI rejects a blank token up front too (clap's
/// `non_blank_container` value parser, so it costs a re-typed command rather than a whole run),
/// which makes this the second line of defence rather than the only one.
#[must_use]
pub fn resolve_container(token: &str) -> Vec<u64> {
    let mut ids = Vec::new();
    let token = token.trim();
    // An empty scope token can only mean "everything", which is the opposite of the ask.
    if token.is_empty() || token.chars().all(|c| c == '/') {
        return ids;
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return ids;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.parse::<u32>().is_err() {
            continue; // not a pid dir
        }
        let cg_path = entry.path().join("cgroup");
        let Ok(content) = std::fs::read_to_string(&cg_path) else {
            continue;
        };
        // The unified-hierarchy line is `0::/<path>`. Match the container token inside ONE
        // component of that path (a docker/containerd id or name is one directory name).
        for line in content.lines() {
            let Some(rest) = line.strip_prefix("0::") else { continue };
            if path_component_contains(rest, token) {
                if let Some(id) = cgroup_id_for_unified_path(rest) {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
            }
        }
    }
    ids
}

/// Does any `/`-delimited COMPONENT of a unified-hierarchy cgroup path contain `token`?
/// Component-scoped rather than whole-path, because a runtime always puts the container's
/// id or name inside ONE directory name (`docker-<id>.scope`, `crio-<id>.scope`, a pod's
/// leaf directory), so the narrowing costs nothing real. What it drops is a token that
/// matched only by crossing a directory boundary (a path fragment, or a lone `/`), which
/// was never a container id and, matching every line, silently turned a restricting flag
/// into a host-wide capture. Pure, so the degenerate tokens are unit-pinned.
fn path_component_contains(path: &str, token: &str) -> bool {
    path.split('/').any(|c| !c.is_empty() && c.contains(token))
}

/// The cgroup id (== directory inode on cgroup v2) for a unified-hierarchy path like
/// `/system.slice/docker-abc.scope`, found under the cgroup2 mount. This is what
/// [`resolve_container`] turns a `--container` token into, and it is the same id
/// `bpf_get_current_cgroup_id` reports in-kernel, which is what makes the two comparable.
pub fn cgroup_id_for_unified_path(rel: &str) -> Option<u64> {
    let full = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    std::fs::metadata(full).ok().map(|m| m.ino())
}

/// Scan /proc for processes matching --app/--exe and return their tgids. Run once at
/// startup so already-running workers are in scope before the first exec arrives.
///
/// The COUNT is meaningful to the caller, not just the pids: an empty result means the
/// scope matched nothing, which is a run that will capture nothing until something execs.
/// Feed `len()` to [`unmatched_scope_warning`] so the banner can say so.
#[must_use]
pub fn scan_matching_pids(spec: &FilterSpec) -> Vec<u32> {
    let mut pids = Vec::new();
    if spec.apps.is_empty() && spec.exes.is_empty() {
        return pids; // nothing to scan for
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };
        // The SAME resolver the live exec path uses, so the two cannot drift into two
        // different answers about what an --app scope means. /proc/<pid>/exe is the only
        // thing consulted: /proc/<pid>/comm is process-controlled, so admitting on it let
        // any local user opt into a privileged capture (see matches_app_exe).
        //
        // This used to be `unwrap_or_default()`, which was fail-closed only by luck: an
        // unreadable exe became "", which matches nothing UNLESS the operator passed an
        // empty --app/--exe token, in which case every unreadable process on the box
        // matched. Skipping the entry outright removes that edge with the drift.
        let exe = match resolve_exe(&entry.path()) {
            ExeLink::Resolved(exe) => exe,
            // A live process this scope cannot identify. Same one-time warning as the exec
            // path: on a setcap'd agent this is every OTHER user's process, so the scan
            // silently returning fewer pids is exactly the "did my filter miss?" failure.
            ExeLink::Denied => {
                warn_exe_denied_once();
                continue;
            }
            ExeLink::Absent => continue, // kernel thread, zombie, or exited mid-scan
        };
        if spec.matches_app_exe(&exe) {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_active_only_when_a_flag_is_set() {
        assert!(!FilterSpec::default().is_active());
        assert!(FilterSpec { pids: vec![1], ..Default::default() }.is_active());
        assert!(FilterSpec { apps: vec!["x".into()], ..Default::default() }.is_active());
        assert!(FilterSpec { cgroups: vec![42], ..Default::default() }.is_active());
    }

    #[test]
    fn app_matches_the_exe_basename() {
        let s = FilterSpec { apps: vec!["python3".into()], ..Default::default() };
        assert!(s.matches_app_exe("/usr/bin/python3"), "exe basename match");
        assert!(!s.matches_app_exe("/usr/bin/bash"), "no match");
        // A bare basename in --app must not match a substring of a longer name.
        assert!(!s.matches_app_exe("/x/python311"));
        // A bare (relative/argument) path still resolves its basename.
        assert!(s.matches_app_exe("python3"));
    }

    // THE REGRESSION THIS RULE EXISTS FOR. `/proc/<pid>/exe` is symlink-RESOLVED, so on
    // every mainstream distro `--app python3` is asked about `/usr/bin/python3.12`. Matching
    // the basename exactly made the flag's own documented example (quickstart step 3, two
    // demo scripts) match NOTHING, on every machine, silently. A version suffix is therefore
    // stripped before the comparison.
    #[test]
    fn app_matches_a_versioned_interpreter_symlink_target() {
        let s = FilterSpec { apps: vec!["python3".into()], ..Default::default() };
        assert!(s.matches_app_exe("/usr/bin/python3.12"), "the shape `readlink` really returns");
        assert!(s.matches_app_exe("/usr/bin/python3.11"));
        assert!(s.matches_app_exe("/usr/local/bin/python3.13.2"), "a two-part version too");
        // Naming the versioned binary exactly still works (it matches before any stripping).
        let exact = FilterSpec { apps: vec!["python3.12".into()], ..Default::default() };
        assert!(exact.matches_app_exe("/usr/bin/python3.12"));
        // The other distro shapes this covers: a `-` separator, and a versioned toolchain.
        let gcc = FilterSpec { apps: vec!["gcc".into()], ..Default::default() };
        assert!(gcc.matches_app_exe("/usr/bin/gcc-11"));
        // What it must NOT widen into: the version suffix has to start at a separator, so a
        // shorter --app never reaches a longer real name.
        let py = FilterSpec { apps: vec!["python".into()], ..Default::default() };
        assert!(!py.matches_app_exe("/usr/bin/python3"), "python is not python3");
        assert!(!py.matches_app_exe("/usr/bin/python3.12"));
    }

    // The stripping rule itself, at the boundaries. Pure, so pin the exact shapes rather
    // than only their effect on a match.
    #[test]
    fn version_stripping_needs_a_separator_and_a_numeric_tail() {
        assert_eq!(strip_version_suffix("python3.12"), Some("python3"));
        assert_eq!(strip_version_suffix("python3.12.1"), Some("python3"), "earliest separator wins");
        assert_eq!(strip_version_suffix("gcc-11"), Some("gcc"));
        assert_eq!(strip_version_suffix("libreoffice-7.4"), Some("libreoffice"));
        // Nothing to strip: no separator, a non-numeric tail, an empty stem, a bare tail.
        assert_eq!(strip_version_suffix("python3"), None);
        assert_eq!(strip_version_suffix("python311"), None);
        assert_eq!(strip_version_suffix("curl"), None);
        assert_eq!(strip_version_suffix("not-python3-really"), None);
        assert_eq!(strip_version_suffix(".12"), None);
        assert_eq!(strip_version_suffix("-1"), None);
        assert_eq!(strip_version_suffix("python3."), None);
        assert_eq!(strip_version_suffix("python3.."), None);
        assert_eq!(strip_version_suffix(""), None);
    }

    // The admission predicate must key ONLY on the exe path. `comm` is set by the
    // candidate process itself (prctl PR_SET_NAME), so admitting on it let any local user
    // walk into a privileged capture and forge records into it (or evict the real target
    // by filling the 65536-entry filter_pids). Pinned here because the regression is a
    // one-line `|| a == comm` away and is invisible in ordinary use, where comm and the
    // basename agree.
    //
    // SCOPE, because this test reads stronger than it is: `matches_app_exe` takes a path and
    // structurally cannot see a process-chosen name, so what it pins is the MATCH rule, not
    // the door. The door is which string the /proc readers hand it, and that is pinned by
    // `admission_follows_the_resolved_inode_not_the_name_it_was_launched_under` and
    // `a_resolution_failure_never_admits_the_path_the_event_carries` below. The real hole
    // this file has had lived in the reader, not here.
    #[test]
    fn app_never_admits_on_a_self_chosen_process_name() {
        let s = FilterSpec { apps: vec!["python3".into()], ..Default::default() };
        // The attacker's process: renamed itself to the target, real exe is elsewhere.
        assert!(!s.matches_app_exe("/tmp/evil"));
        // Even an exe whose basename merely CONTAINS the name stays out.
        assert!(!s.matches_app_exe("/tmp/not-python3-really"));
        // Version stripping must not become a wildcard: the tail after the separator has to
        // be numeric, so a decorated name is still a different binary.
        assert!(!s.matches_app_exe("/tmp/python3.evil"));
        assert!(!s.matches_app_exe("/tmp/python3-shim"));
    }

    // The fix for `--app python3` proven against a REAL process with the real shape: an exe
    // basename carrying a version suffix (`s3tapfake9.9`) reached through an unversioned
    // symlink, which is exactly how every distro ships an interpreter. The test asserts the
    // shape it depends on (comm without the version, /proc/<pid>/exe with it) before
    // asserting the scan finds the pid, so if a future kernel changed either the assertion
    // that fails names the reason. Runs the real /proc walk, no fixture.
    #[test]
    fn scan_matches_a_live_process_whose_exe_is_versioned() {
        use std::path::PathBuf;
        // A copy, not a symlink: /proc/<pid>/exe resolves to the final inode, so the
        // versioned NAME has to be a real file. `sleep` keeps the child alive with no shell
        // in between (a shell can exec-optimize its last command and change /proc/exe).
        let Some(src) = ["/bin/sleep", "/usr/bin/sleep"].iter().map(PathBuf::from).find(|p| p.exists())
        else {
            return; // no coreutils in this environment: nothing to prove, don't fail
        };
        // Named after the real case: `s3tapfake3` -> `s3tapfake3.9`, i.e. `python3` ->
        // `python3.12`. The major digit belongs to the NAME the operator types.
        let dir = std::env::temp_dir().join(format!("s3tap-filter-{}", std::process::id()));
        let versioned = dir.join("s3tapfake3.9");
        let plain = dir.join("s3tapfake3");
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        cleanup();
        if std::fs::create_dir_all(&dir).is_err() || std::fs::copy(&src, &versioned).is_err() {
            cleanup();
            return; // an unwritable TMPDIR is an environment fact, not a regression
        }
        if std::os::unix::fs::symlink(&versioned, &plain).is_err() {
            cleanup();
            return;
        }
        let Ok(mut child) = std::process::Command::new(&plain).arg("30").spawn() else {
            cleanup();
            return;
        };
        let pid = child.id();
        // Wait for the exec before reading anything: until it lands, /proc/<pid> still
        // describes THIS binary, and every assertion below reads as a filter regression.
        let execed = wait_for_exec(pid, "s3tapfake3.9");
        // The premise: launched through the unversioned symlink, the kernel takes `comm`
        // from the basename of the execve FILENAME, while /proc/<pid>/exe is the resolved
        // versioned inode. This is the disagreement the old exact-basename rule tripped on.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
        let matched = scan_matching_pids(&FilterSpec {
            apps: vec!["s3tapfake3".into()],
            ..Default::default()
        });
        // Naming the versioned binary exactly must work too.
        let exact = scan_matching_pids(&FilterSpec {
            apps: vec!["s3tapfake3.9".into()],
            ..Default::default()
        });
        // A name that is neither the stem nor the full basename must stay out (the stripped
        // stem keeps its major digit, exactly as `python3` does).
        let miss = scan_matching_pids(&FilterSpec {
            apps: vec!["s3tapfake".into()],
            ..Default::default()
        });
        let _ = child.kill();
        let _ = child.wait();
        cleanup();
        assert!(execed, "premise: the child never execed, so nothing below was measured");
        assert_eq!(comm.trim(), "s3tapfake3", "premise: comm has no version suffix");
        assert_eq!(
            exe.file_name().and_then(|n| n.to_str()),
            Some("s3tapfake3.9"),
            "premise: /proc/<pid>/exe is symlink-resolved, so its basename IS versioned"
        );
        assert!(matched.contains(&pid), "--app s3tapfake3 must find the versioned process");
        assert!(exact.contains(&pid), "--app s3tapfake3.9 must find it too");
        assert!(!miss.contains(&pid), "a partial version must not match");
    }

    #[test]
    fn exe_requires_an_exact_path() {
        let s = FilterSpec { exes: vec!["/opt/app/server".into()], ..Default::default() };
        assert!(s.matches_app_exe("/opt/app/server"));
        // Same basename, different path ⇒ no match (the disambiguation point).
        assert!(!s.matches_app_exe("/usr/bin/server"));
    }

    #[test]
    fn app_and_exe_compose() {
        let s = FilterSpec {
            apps: vec!["java".into()],
            exes: vec!["/opt/spark/bin/exec".into()],
            ..Default::default()
        };
        assert!(s.matches_app_exe("/usr/lib/jvm/bin/java"));
        assert!(s.matches_app_exe("/opt/spark/bin/exec"));
        assert!(!s.matches_app_exe("/usr/bin/ruby"));
    }

    // An empty spec (no --app/--exe) has nothing to scan for, so the /proc scan is
    // skipped entirely and returns empty — the early-return guard, exercised without
    // touching the filesystem.
    #[test]
    fn scan_matching_pids_is_empty_for_a_spec_with_no_app_or_exe() {
        assert!(scan_matching_pids(&FilterSpec::default()).is_empty());
        // --pid/--cgroup are fixed sets, not scan targets, so they too scan for nothing.
        let pid_only = FilterSpec { pids: vec![1, 2, 3], ..Default::default() };
        assert!(scan_matching_pids(&pid_only).is_empty());
    }

    // With an --app that no live process can match, the real /proc scan runs to
    // completion and finds nothing — a deterministic result (no process is named the
    // sentinel) that exercises the full read_dir/comm/exe loop without a fixture.
    #[test]
    fn scan_matching_pids_finds_nothing_for_an_impossible_app() {
        let spec = FilterSpec {
            apps: vec!["__s3tap_no_such_process_name__".into()],
            exes: vec!["/nonexistent/__s3tap_no_such_exe__".into()],
            ..Default::default()
        };
        assert!(scan_matching_pids(&spec).is_empty());
    }

    // An --app/--exe scope that matched nothing must SAY so: an empty allowlist captures
    // nothing, exits 0 and writes an empty file, which reads exactly like "my app never
    // talks to S3". The warning names the tokens, says what an empty result would mean, and
    // points at the two race-free scopes.
    #[test]
    fn an_unmatched_app_scope_warns_with_the_tokens_it_tried() {
        let spec = FilterSpec {
            apps: vec!["python3".into()],
            exes: vec!["/opt/app/server".into()],
            ..Default::default()
        };
        let w = unmatched_scope_warning(&spec, 0).expect("a scope that matched nothing warns");
        assert!(w.contains("--app python3"), "names the token that missed");
        assert!(w.contains("--exe /opt/app/server"));
        assert!(w.contains("EMPTY scope"), "says the allowlist is empty");
        assert!(w.contains("the scope missed"), "says what an empty result would mean");
        assert!(w.contains("--pid") && w.contains("--cgroup"), "offers the alternatives");
        // A match, or no name-based scope at all, has nothing to warn about.
        assert!(unmatched_scope_warning(&spec, 1).is_none(), "something matched");
        assert!(unmatched_scope_warning(&FilterSpec::default(), 0).is_none(), "no --app/--exe");
        let pid_only = FilterSpec { pids: vec![7], ..Default::default() };
        assert!(unmatched_scope_warning(&pid_only, 0).is_none(), "--pid is not a scan target");
    }

    // With --pid/--cgroup also given the scope is NOT empty, so the warning must not claim
    // it is: overstating sends the operator hunting a bug that isn't there.
    #[test]
    fn an_unmatched_app_scope_alongside_a_pid_scope_does_not_claim_emptiness() {
        let spec = FilterSpec {
            apps: vec!["python3".into()],
            pids: vec![42],
            ..Default::default()
        };
        let w = unmatched_scope_warning(&spec, 0).expect("the --app half still missed");
        assert!(!w.contains("EMPTY scope"));
        assert!(w.contains("beyond the --pid/--cgroup entries"));
    }

    // A container token that appears in no process's cgroup line resolves to no ids —
    // the /proc walk completes and returns empty (the caller then fails closed).
    #[test]
    fn resolve_container_returns_empty_for_an_unknown_token() {
        assert!(resolve_container("__s3tap_no_such_container_token__").is_empty());
    }

    // A BLANK --container token must resolve NOTHING. The old `rest.contains(token)` was
    // true for every cgroup line, so `--container "$CID"` with an unset CID returned every
    // cgroup on the host: the caller then saw a non-empty id list, skipped both its warning
    // and its fail-closed bail, and captured host-wide with a banner that read like a
    // working scope. This runs the real /proc walk, so a regression here shows up as a
    // non-empty result on any live machine.
    #[test]
    fn resolve_container_never_matches_everything_on_a_degenerate_token() {
        assert!(resolve_container("").is_empty(), "an empty token is not a scope");
        assert!(resolve_container("   ").is_empty(), "whitespace is not a scope");
        assert!(resolve_container("/").is_empty(), "every cgroup path contains a slash");
        assert!(resolve_container("//").is_empty());
    }

    // The match is scoped to ONE path component, so a token that only matches by spanning a
    // `/` resolves nothing (and the caller fails closed) rather than matching a whole
    // subtree. A real id/name lives inside a single component and still matches.
    #[test]
    fn container_token_matches_within_a_single_path_component() {
        let path = "/system.slice/docker-abc123def.scope";
        assert!(path_component_contains(path, "abc123def"), "an id inside the component");
        assert!(path_component_contains(path, "docker-abc123def.scope"), "the whole component");
        assert!(path_component_contains("/kubepods/besteffort/pod7/xyz789", "xyz789"));
        // Spanning the separator: never a container id, so it must not match.
        assert!(!path_component_contains(path, "system.slice/docker"));
        assert!(!path_component_contains(path, "/"));
        // A token that is simply absent.
        assert!(!path_component_contains(path, "podman-zzz"));
    }

    // A unified-hierarchy path that has no directory under the cgroup2 mount yields no
    // inode, so the id is None (never a panic, never a bogus id).
    #[test]
    fn cgroup_id_is_none_for_a_missing_path() {
        assert!(cgroup_id_for_unified_path("/__s3tap_no_such_cgroup_dir__/leaf").is_none());
    }

    /// Block until a freshly spawned child has actually EXECED, i.e. until /proc/<pid>/exe
    /// resolves to `basename`. `Command::spawn` returns once the clone succeeds, so reading
    /// /proc/<pid>/{comm,exe} straight after it can still see the PARENT's image (this test
    /// binary), which makes both the premise assertions and the scan results fail for a
    /// reason that has nothing to do with the filter. Only ever observed under the full
    /// suite's parallelism, which is exactly when it is hardest to read. Bounded at ~2s so a
    /// genuinely wrong exe still fails the test rather than hanging it.
    fn wait_for_exec(pid: u32, basename: &str) -> bool {
        for _ in 0..200 {
            let resolved = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
            if resolved.as_ref().and_then(|p| p.file_name()).and_then(|n| n.to_str())
                == Some(basename)
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    }

    /// The event the BPF probe would really deliver for an exec: `hdr.tgid` plus the raw
    /// execve `filename` ARGUMENT, which is whatever string the exec'ing process passed.
    fn exec_event(tgid: u32, filename_arg: &str) -> EvtProcExec {
        let mut e = EvtProcExec::default();
        e.hdr.tgid = tgid;
        let bytes = filename_arg.as_bytes();
        let n = bytes.len().min(e.exe.len() - 1);
        e.exe[..n].copy_from_slice(&bytes[..n]);
        e.exe_len = n as u8;
        e
    }

    // THE ADMISSION DOOR, exercised through the READER rather than the match rule. A real
    // child is launched through a symlink whose basename differs from its target's, which
    // splits the two identities apart: the name the process was launched under (the execve
    // filename argument on the event, and `comm`) says one thing, the inode the kernel
    // actually execed (/proc/<pid>/exe) says another. Admission must follow the inode.
    //
    // Both directions are asserted, and the NEGATIVE is the one that matters: scoping to the
    // launch name must NOT admit the process. A local user picks that name freely (a symlink
    // costs nothing), so an admission on it is an opt-in to the operator's privileged capture,
    // where a peer can forge s3tap.operation records or evict the real target from
    // filter_pids. Catches: keying on `e.exe_path()`, keying on comm, or matching the link
    // rather than its target.
    #[test]
    fn admission_follows_the_resolved_inode_not_the_name_it_was_launched_under() {
        use std::path::PathBuf;
        // A COPY, not a symlink, for the target: /proc/<pid>/exe resolves to the final
        // inode, so the target name has to be a real file. `sleep` keeps the child alive
        // with no shell in between (a shell can exec-optimize its last command).
        let Some(src) =
            ["/bin/sleep", "/usr/bin/sleep"].iter().map(PathBuf::from).find(|p| p.exists())
        else {
            return; // no coreutils here: nothing to prove, don't fail
        };
        let dir = std::env::temp_dir().join(format!("s3tap-reader-{}", std::process::id()));
        let real = dir.join("s3taprealinode"); // what actually runs
        let decoy = dir.join("s3tapchosenname"); // the name it is launched under
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        cleanup();
        if std::fs::create_dir_all(&dir).is_err() || std::fs::copy(&src, &real).is_err() {
            cleanup();
            return; // an unwritable TMPDIR is an environment fact, not a regression
        }
        if std::os::unix::fs::symlink(&real, &decoy).is_err() {
            cleanup();
            return;
        }
        let Ok(mut child) = std::process::Command::new(&decoy).arg("30").spawn() else {
            cleanup();
            return;
        };
        let pid = child.id();
        let execed = wait_for_exec(pid, "s3taprealinode");
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        let link = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
        // Re-confirm the pid is still OUR child before trusting anything read from it. A pid is
        // recycled the moment it is reaped, and this test process is full of threads whose TIDs
        // come from the same number space — so a stale pid does not read as "gone", it reads as
        // some thread of the test harness. CI caught exactly that: `comm` came back
        // "filter::tests::", the harness's own 15-char thread name, and the assertion below
        // reported it as the kernel disagreeing about `comm`.
        //
        // If the child is no longer there, that is an environment fact (a slow or loaded
        // runner), not a regression — take the same early return the unwritable-TMPDIR and
        // missing-coreutils cases take, rather than asserting on another process's /proc.
        let still_ours = link.file_name().and_then(|n| n.to_str()) == Some("s3taprealinode");
        // The event as the probe would deliver it: its exe field carries the DECOY path.
        let ev = exec_event(pid, decoy.to_str().unwrap_or_default());
        let app = |n: &str| FilterSpec { apps: vec![n.into()], ..Default::default() };
        let exe = |p: &Path| FilterSpec {
            exes: vec![p.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let live_by_real = exec_is_in_scope(&app("s3taprealinode"), &ev);
        let live_by_chosen = exec_is_in_scope(&app("s3tapchosenname"), &ev);
        let live_exe_real = exec_is_in_scope(&exe(&real), &ev);
        let live_exe_chosen = exec_is_in_scope(&exe(&decoy), &ev);
        // The startup scan is the other reader and must answer identically.
        let scan_real = scan_matching_pids(&app("s3taprealinode"));
        let scan_chosen = scan_matching_pids(&app("s3tapchosenname"));
        let _ = child.kill();
        let _ = child.wait();
        cleanup();
        // Premise: the two identities really do disagree here, so the assertions below are
        // testing something. If a future kernel changed either, this names the reason.
        if !execed || !still_ours {
            return; // the child never execed, or its pid was recycled out from under us
        }
        assert_eq!(comm.trim(), "s3tapchosenname", "premise: comm follows the launch name");
        assert_eq!(
            link.file_name().and_then(|n| n.to_str()),
            Some("s3taprealinode"),
            "premise: /proc/<pid>/exe is the RESOLVED inode, not the symlink it was reached by"
        );
        assert!(live_by_real, "--app must match the exe the process is really running");
        assert!(
            !live_by_chosen,
            "ADMISSION ON A CHOSEN NAME: the exec was admitted under the name it was launched \
             with, which any local user picks freely with a symlink"
        );
        assert!(live_exe_real, "--exe must match the resolved path");
        assert!(!live_exe_chosen, "--exe must not match the symlink path it was launched by");
        assert!(scan_real.contains(&pid), "the startup scan must agree with the exec path");
        assert!(!scan_chosen.contains(&pid), "and must reject the chosen name just the same");
    }

    // ADMISSION IS NOT PERMANENT. The exe-inode requirement was one exec deep: `on_exec` only
    // ever inserted, fork propagates membership in-kernel and `reap_dead` removes only DEAD
    // pids, so a local user could exec any world-executable binary that happens to match the
    // scope (no attacker-owned inode needed), be admitted, then exec their own binary and stay
    // in scope for the rest of the capture. A non-matching exec must therefore REVOKE.
    #[test]
    fn a_re_exec_out_of_scope_revokes_the_admission_it_was_holding() {
        use std::path::PathBuf;
        let Some(src) =
            ["/bin/sleep", "/usr/bin/sleep"].iter().map(PathBuf::from).find(|p| p.exists())
        else {
            return; // no coreutils here: nothing to prove, don't fail
        };
        let dir = std::env::temp_dir().join(format!("s3tap-revoke-{}", std::process::id()));
        let admitted = dir.join("s3tapinscope"); // the image the scope names
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        cleanup();
        if std::fs::create_dir_all(&dir).is_err() || std::fs::copy(&src, &admitted).is_err() {
            cleanup();
            return; // an unwritable TMPDIR is an environment fact, not a regression
        }
        let Ok(mut child) = std::process::Command::new(&admitted).arg("30").spawn() else {
            cleanup();
            return;
        };
        let pid = child.id();
        let execed = wait_for_exec(pid, "s3tapinscope");
        // First exec: the image matches, so the tgid is admitted.
        let in_scope = FilterSpec { apps: vec!["s3tapinscope".into()], ..Default::default() };
        let first = admission_for(&in_scope, &exec_event(pid, "s3tapinscope"), None);
        // The SECOND exec, into something the scope does not name. The live process is the
        // only identity consulted, so a scope that no longer matches it is the same state as
        // "this pid execed away": a seat it earned BY NAME has to be withdrawn, not kept.
        let out_of_scope = FilterSpec { apps: vec!["s3tapelsewhere".into()], ..Default::default() };
        let second =
            admission_for(&out_of_scope, &exec_event(pid, "s3tapinscope"), Some(ADMIT_BY_NAME));
        // With a --pid scope in play the seat did not come from the exe at all, so the same
        // non-matching exec must leave it alone.
        let mixed = FilterSpec {
            apps: vec!["s3tapelsewhere".into()],
            pids: vec![pid],
            ..Default::default()
        };
        let third = admission_for(&mixed, &exec_event(pid, "s3tapinscope"), Some(ADMIT_EXPLICIT));
        // The mixed-scope hole: an UNRELATED pid (not the one --pid names) holding a
        // NAME-earned seat must still be revoked, even though the SAME FilterSpec carries a
        // --pid clause for someone else. Gating revocation on "does this config carry any
        // --pid/--cgroup at all" left `--pid 42 --app python3` unable to ever revoke a
        // python3-matching process other than 42.
        let unrelated_pid = pid.wrapping_add(1).max(1);
        let mixed_unrelated = FilterSpec {
            apps: vec!["s3tapelsewhere".into()],
            pids: vec![unrelated_pid],
            ..Default::default()
        };
        let fourth = admission_for(
            &mixed_unrelated,
            &exec_event(pid, "s3tapinscope"),
            Some(ADMIT_BY_NAME),
        );
        // And the regression the PROVENANCE byte exists to close: a fork descendant of an
        // explicit --pid holds an ADMIT_EXPLICIT seat (propagated by the kernel) while being
        // in NEITHER spec.pids NOR any name scope. Gating on "is THIS tgid explicitly named"
        // revoked every such worker on its first exec, which is exactly what the kernel's
        // fork propagation exists to prevent.
        let descendant = admission_for(
            &mixed_unrelated,
            &exec_event(pid, "s3tapinscope"),
            Some(ADMIT_EXPLICIT),
        );
        // A tgid holding NO seat is nothing to withdraw, whatever the scope says.
        let unseated = admission_for(&mixed_unrelated, &exec_event(pid, "s3tapinscope"), None);
        let _ = child.kill();
        let _ = child.wait();
        cleanup();
        assert!(execed, "premise: the child never execed, so nothing below was measured");
        assert_eq!(
            first,
            ExecAdmission::Admit(ADMIT_BY_NAME),
            "the matching image is admitted, and the seat records that the NAME earned it"
        );
        assert_eq!(
            second,
            ExecAdmission::Revoke,
            "ADMISSION SURVIVED AN EXEC OUT OF SCOPE: one cheap exec of a matching system \
             binary would buy a local user a permanent seat in the operator's capture"
        );
        assert_eq!(third, ExecAdmission::Leave, "a --pid admission is not the exe's to withdraw");
        assert_eq!(
            fourth,
            ExecAdmission::Revoke,
            "MIXED SCOPE REVOCATION BYPASS: a --pid clause naming a DIFFERENT process must not \
             exempt this one from exe-based revocation"
        );
        assert_eq!(
            descendant,
            ExecAdmission::Leave,
            "PID DESCENDANT REVOKED: a fork child of an explicit --pid inherits an exec-immune \
             seat, and execing is exactly what those workers do"
        );
        assert_eq!(unseated, ExecAdmission::Leave, "no seat held, so nothing to revoke");
    }

    // The FALLBACK that reopened the hole, pinned shut. When /proc/<tgid>/exe cannot be
    // read, the event still carries an execve `filename` argument that the exec'ing process
    // chose, and this code used to fall back to it. It must not: an unresolvable process is
    // never admitted, whatever it claims to be running. Uses a tgid that can never be live
    // (pids are allocated below pid_max), so the resolution is deterministically a failure.
    #[test]
    fn a_resolution_failure_never_admits_the_path_the_event_carries() {
        let dead: u32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(4_194_304);
        if Path::new(&format!("/proc/{dead}")).exists() {
            return; // pid_max itself is never allocated, but don't assert on a surprise
        }
        // The event claims the scoped app. Nothing backs that claim.
        let ev = exec_event(dead, "/usr/bin/python3");
        let by_app = FilterSpec { apps: vec!["python3".into()], ..Default::default() };
        let by_exe = FilterSpec { exes: vec!["/usr/bin/python3".into()], ..Default::default() };
        assert!(
            !exec_is_in_scope(&by_app, &ev),
            "an unreadable /proc/<tgid>/exe must never fall back to the event's own path"
        );
        assert!(!exec_is_in_scope(&by_exe, &ev), "same for --exe");
        // An empty spec is not a wildcard either, whatever the event says.
        assert!(!exec_is_in_scope(&FilterSpec::default(), &ev));
    }

    // THE PREMISE OF THE FIX, checked against this machine rather than asserted. A
    // capability-tagged s3tap runs as the invoking user, and reading another user's
    // /proc/<pid>/exe is gated by ptrace_may_access(PTRACE_MODE_READ), which wants same-uid
    // or CAP_SYS_PTRACE. cap_dac_read_search does not bypass it (the link is mode 0777, so
    // DAC was never the gate), so the read is DENIED rather than merely failing, and the old
    // code's fallback fired on exactly those processes. Skipped when running as root or in a
    // namespace with no other user's process, since then there is nothing to observe.
    #[test]
    fn another_users_live_process_resolves_to_denied_not_to_a_path() {
        let me = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| uid_from_status(&s))
            .unwrap_or(0);
        if me == 0 {
            return; // root reads every link: the denial this test is about cannot happen
        }
        let Ok(entries) = std::fs::read_dir("/proc") else { return };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.parse::<u32>().is_err() {
                continue;
            }
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            if uid_from_status(&status) == Some(me) {
                continue;
            }
            let link = resolve_exe(&entry.path());
            if !entry.path().exists() {
                continue; // it exited under us: says nothing either way
            }
            assert!(
                matches!(link, ExeLink::Denied),
                "another user's exe link must be DENIED (this is why the fallback was \
                 reachable), got {}",
                match link {
                    ExeLink::Resolved(p) => format!("Resolved({p})"),
                    ExeLink::Absent => "Absent".to_string(),
                    ExeLink::Denied => unreachable!(),
                }
            );
            return; // one confirmed case is the whole point
        }
    }

    /// The real uid out of a /proc/<pid>/status blob (`Uid:\treal\teff\tsaved\tfs`).
    fn uid_from_status(status: &str) -> Option<u32> {
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|u| u.parse().ok())
    }

    // The startup scan must SKIP a process it could not identify, not substitute a stand-in
    // string for it. It used to `unwrap_or_default()`, i.e. call an unreadable exe "", which
    // is fail-closed only while no token equals "": with a blank --app (an unset `$APP` in a
    // wrapper, the same shape that once made --container match every cgroup) every process
    // s3tap could not read matched instead. Every machine has kernel threads with no exe
    // link, so a regression here shows up as a non-empty result anywhere, root or not.
    #[test]
    fn the_scan_never_admits_a_process_it_could_not_identify() {
        let blank = FilterSpec { apps: vec![String::new()], ..Default::default() };
        assert!(scan_matching_pids(&blank).is_empty(), "a blank --app is not a wildcard");
        let blank_exe = FilterSpec { exes: vec![String::new()], ..Default::default() };
        assert!(scan_matching_pids(&blank_exe).is_empty(), "nor is a blank --exe");
    }

    // The two error paths must not be conflated: a live process we may not read is a
    // PERMISSION problem worth reporting, a missing one is not.
    #[test]
    fn resolve_exe_separates_a_missing_process_from_a_resolved_one() {
        assert!(
            matches!(resolve_exe(Path::new("/proc/self")), ExeLink::Resolved(_)),
            "our own exe always resolves"
        );
        assert!(matches!(
            resolve_exe(Path::new("/proc/__s3tap_no_such_pid__")),
            ExeLink::Absent
        ));
    }

    // Failing closed has to be OBSERVABLE. A scope that quietly stops matching is the worst
    // failure this filter has: the run exits 0 with a smaller capture and the operator reads
    // it as a quiet app. So the warning must name the real cause (a capability, not a
    // mistyped --app) and the scopes that need no /proc read.
    #[test]
    fn the_denied_warning_names_the_cause_and_the_scopes_that_still_work() {
        let w = exe_denied_warning();
        assert!(w.contains("/proc/<pid>/exe"), "names what could not be read");
        assert!(w.contains("CAP_SYS_PTRACE"), "names the real cause, not a typo in --app");
        assert!(w.contains("OUT of the capture"), "says what happened to the process");
        assert!(w.contains("--pid") && w.contains("--cgroup"), "offers the scopes that work");
        assert!(w.contains("--container"));
        // House prose rules apply to anything an operator reads.
        assert!(!w.contains('—') && !w.contains('–'), "no dash connectors");
        assert!(!w.contains(';'), "no semicolons");
        assert!(!w.contains(", and "), "no Oxford comma");
    }
}
