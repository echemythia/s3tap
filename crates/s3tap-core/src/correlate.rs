// crates/s3tap-core/src/correlate.rs
//
// The correlation engine: folds raw per-socket events into public Connection
// records (s3tap.connection/2 — M1 is socket-only). A
// small state machine keyed by sock_cookie:
//
//   on_connect  -> opens (or replaces) per-connection state; emits nothing yet
//   on_close    -> pairs with the opening connect (if any) and emits one record
//
// Pure logic, no kernel — every transition is unit-tested in tests/correlate.rs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{hash, http};
use s3tap_events::{
    EvtConnId, EvtDnsQuery, EvtDnsResponse, EvtGetaddrinfo, EvtTcpClose, EvtTcpConnect,
    EvtTcpSample, EvtTlsBody, EvtTlsData, EvtTlsHandshake, EvtTlsServer,
};
use s3tap_schema::{
    App, ConnSchemaTag, Connection, Delimitation, Dns, Endpoint, Operation, SchemaTag, TcpSample, Tls,
};

const AF_INET: u8 = 2;

/// Cap on each DNS-tracking map. A missed response / unmatched resolution would
/// otherwise leak; over the cap the oldest entry is evicted (same rationale as
/// the connection map). Generous — DNS churn is far below the connection rate.
const DNS_MAP_CAP: usize = 16_384;

/// What we remember about a connection between its connect and its close.
struct ConnState {
    /// The process that opened the connection (more reliable than the close
    /// event's tgid, which can be a kernel/softirq context).
    pid: u32,
    /// SYN→ESTABLISHED latency in ns (0 == not measured, e.g. passive open).
    connect_latency_ns: u64,
    /// CLOCK_MONOTONIC at connection start (SYN). Derived from the connect
    /// event: established ts minus connect latency (for a failed connect the
    /// probe already stamps the SYN time, with latency 0).
    ts_ns: u64,
    family: u8,
    daddr: [u8; 16],
    dport: u16,
    /// The connection was abandoned before ESTABLISHED (refused/timed out).
    connect_failed: bool,
}

/// Default open-connection cap. Mirrors the eBPF `sock_ts` LRU_HASH
/// `max_entries` (65536), so the two layers bound their state alike.
const DEFAULT_MAX_OPEN: usize = 65_536;

/// An in-flight DNS query awaiting its response, keyed by `(sock_cookie, txn_id)`.
struct PendingQuery {
    qname: String,
    query_ts: u64, // CLOCK_MONOTONIC of the query, for the wire latency
}

/// What a completed wire resolution tells us about one resolved IP: which name
/// it belongs to and when/how it resolved. Keyed by the resolved address so a
/// later connection to that IP can be labeled.
struct Resolution {
    hostname: String,
    wire_latency_ns: u64, // query -> response
    ttl_s: Option<u32>,
    n_answers: u8,
    query_ts: u64,    // CLOCK_MONOTONIC of the query that produced this
    resolved_ts: u64, // ...and of its response
}

/// The resolver-call facts from a `getaddrinfo` return, keyed by hostname. This
/// is the latency the application actually paid (including the nscd/cache path).
struct Gai {
    latency_ns: u64,
    cache_hit: bool,
    ts: u64,
}

/// What a TLS ClientHello told us about a connection, keyed by its sock_cookie.
/// The SNI is the client's requested server_name (present even when DNS was
/// bypassed) and is the highest-confidence source for the endpoint hostname. The
/// event also carries the offered (legacy) version, but we don't surface it as
/// the connection's TLS version — that is the *negotiated* version, which needs
/// the supported_versions extension (a later slice), so `tls.version` stays null.
struct TlsInfo {
    sni: String, // "" when only a ServerHello (no SNI ClientHello) was seen
    ts: u64,
    version: Option<u16>, // negotiated TLS version (ServerHello); 0x0304 = 1.3
    cipher: Option<u16>,  // negotiated cipher suite (ServerHello)
}

/// Render a negotiated TLS version code (ServerHello) as a human label.
fn tls_version_str(v: u16) -> String {
    match v {
        0x0304 => "TLS 1.3".into(),
        0x0303 => "TLS 1.2".into(),
        0x0302 => "TLS 1.1".into(),
        0x0301 => "TLS 1.0".into(),
        other => format!("0x{other:04x}"),
    }
}

/// One eviction pass reclaims `cap / EVICT_BATCH_DIVISOR` entries of headroom (or the whole
/// excess, whichever is larger) rather than the single oldest entry.
///
/// WHY A BATCH — this is the difference between a bounded cost and a death spiral. Every
/// capped map here evicts by a linear min-by-ts scan, and a map that has reached its cap
/// STAYS at its cap: one insert, one eviction. Evicting one at a time therefore runs a FULL
/// O(n) scan on every subsequent insert, for the rest of the run. The failure is not
/// hypothetical: when the critical ring overflows (a condition the tool reports), the dropped
/// EVT_TCP_CLOSE events leak `conns` entries that nothing ever removes, so after `max_open`
/// connects the map is pinned at 65536 and every later `on_connect` walks 65536 entries on
/// the single-threaded fold path. The slower fold overflows the ring harder, which drops more
/// closes, which leaks more entries. Self-reinforcing, and the run never recovers.
///
/// Reclaiming a batch breaks the loop: the map lands at 0.9 × cap and the next `cap/10`
/// inserts are plain O(1) hash inserts that never touch the scan. Cost per insert amortizes
/// to `O(n) / (n/10)` ≈ 10 element visits plus ~10 key clones (the scan materializes a
/// `(u64, K)` vector), against ~65536 visits before — a ~6500x cut at the default cap, and
/// unlike the old cost it does not grow with the cap. The worst case of a SINGLE pass is
/// unchanged (one O(n) scan, no `n log n`: the batch is chosen by `select_nth_unstable`, a
/// partition, and only the batch itself is sorted). What drops by `cap/10` is how OFTEN a
/// pass runs.
///
/// ANY fixed fraction makes the amortized cost a constant, so the choice is only about that
/// constant against how much is over-evicted. 10% keeps ~10 visits per insert while costing a
/// leak 6553 of 65536 slots — and those are by construction the oldest entries, which in the
/// failure this guards are already dead.
const EVICT_BATCH_DIVISOR: usize = 10;

/// How many entries one pass over `map` should reclaim: the larger of the excess above `cap`
/// and a batch of `cap/EVICT_BATCH_DIVISOR` headroom, so the next `cap/EVICT_BATCH_DIVISOR`
/// inserts need no scan at all. Always at least 1 (a pass that evicted nothing would leave
/// the map over cap and re-scan on the next insert), and always at least the excess (a burst
/// insert must be fully cleared in the one pass). The floor means a tiny cap — the tests use
/// 1 or 2 — keeps the exact single-victim behaviour it had.
fn evict_target(len: usize, cap: usize) -> usize {
    len.saturating_sub(cap).max(cap / EVICT_BATCH_DIVISOR).max(1)
}

/// The `n` oldest keys of `map` by the timestamp `ts` extracts, OLDEST FIRST, skipping every
/// key `keep` accepts. Linear in `map.len()`: `select_nth_unstable` partitions around
/// the n-th oldest instead of sorting the whole map, and only the returned batch is ordered
/// (n log n on n = cap/10, i.e. ~13 comparisons per amortized insert). Both the selection
/// and the ordering run on the composite `(ts, key)`, so an identical event stream evicts an
/// identical SET in an identical order regardless of HashMap iteration order.
///
/// Oldest-first ordering is not cosmetic: callers that own in-flight state flush each victim
/// as it goes, and the emitted order must be the one repeated single-victim eviction gave.
fn oldest_keys<K, V>(
    map: &HashMap<K, V>,
    n: usize,
    ts: impl Fn(&V) -> u64,
    keep: impl Fn(&K) -> bool,
) -> Vec<K>
where
    K: std::hash::Hash + Eq + Clone + Ord,
{
    if n == 0 {
        return Vec::new();
    }
    let mut cand: Vec<(u64, K)> = Vec::with_capacity(map.len());
    cand.extend(map.iter().filter(|(k, _)| !keep(k)).map(|(k, v)| (ts(v), k.clone())));
    let n = n.min(cand.len());
    if n == 0 {
        return Vec::new(); // everything resident is exempt (all just-inserted)
    }
    if n < cand.len() {
        // Partition on the COMPOSITE `(ts, key)`, not on `ts` alone. Selecting on the
        // timestamp alone leaves ties to be broken by HashMap iteration order, which is
        // randomized per map — so with more entries sharing the cut-off timestamp than the
        // batch has room for, WHICH of them got evicted varied run to run for one identical
        // event stream (measured: six different victims across six runs on 11 entries sharing
        // a timestamp). Sorting afterwards can't repair that; it only orders a set already
        // chosen at random. The key is the tiebreak, so the chosen SET is a function of the
        // events alone.
        cand.select_nth_unstable(n - 1);
        cand.truncate(n);
    }
    // Oldest-first within the chosen batch (callers flush each victim as it goes, and the
    // emitted order must match what repeated single-victim eviction gave). Same composite
    // order as the selection above, so the two agree.
    cand.sort_unstable();
    cand.into_iter().map(|(_, k)| k).collect()
}

/// Evict the oldest entries (by the timestamp `ts` extracts) when `map` exceeds `cap`, never
/// evicting `keep` (the entry the caller just inserted). Same bounded-map discipline as the
/// connection map; scans only when over cap, and then in one amortized batch — see
/// [`EVICT_BATCH_DIVISOR`] for why a single-victim policy is a trap.
///
/// The `keep` exclusion matters because the inserted entry can carry the minimum
/// `ts`: an out-of-order fold (probes are unordered) or a clock glitch can stamp
/// it below every resident entry, so without the guard a just-recorded
/// ClientHello SNI / resolution could evict ITSELF the instant it lands. Mirrors
/// the same just-inserted guard `on_connect`/`on_conn_id` already apply by hand.
fn evict_oldest_over<K, V>(map: &mut HashMap<K, V>, cap: usize, keep: &K, ts: impl Fn(&V) -> u64)
where
    K: std::hash::Hash + Eq + Clone + Ord,
{
    if map.len() > cap {
        for victim in oldest_keys(map, evict_target(map.len(), cap), ts, |k| k == keep) {
            map.remove(&victim);
        }
    }
}

/// Folds connect/close events into one [`Connection`] record per connection.
pub struct Correlator {
    /// Open connections keyed by sock_cookie. Entries are removed on close, so
    /// in steady state this is bounded by currently-open connections. A *missed*
    /// close (the ring buffer dropped events under load) would otherwise leak
    /// its entry forever; `max_open` caps the map and evicts the oldest entry,
    /// the way the eBPF side bounds its maps with LRU_HASH.
    conns: HashMap<u64, ConnState>,
    /// Hard cap on `conns`; over it, `on_connect` evicts the oldest-by-start.
    max_open: usize,
    /// In-flight wire queries, `(sock_cookie, txn_id)` -> query, cleared on
    /// response. Keyed by the resolver's UDP socket (not pid) so the join is
    /// independent of which task context consumes the response skb.
    pending_dns: HashMap<(u64, u16), PendingQuery>,
    /// Resolved IP -> the name/timing it came from; joins DNS to a connection.
    resolutions: HashMap<IpAddr, Resolution>,
    /// hostname -> resolver-call facts from `getaddrinfo`.
    gai: HashMap<String, Gai>,
    /// sock_cookie -> the TLS ClientHello facts (SNI) seen on that connection.
    tls: HashMap<u64, TlsInfo>,
    /// (tgid, fd) -> sock_cookie (M3 E4): the join the plaintext path needs, since
    /// EVT_TLS_WRITE/READ carry (tgid,fd) but no cookie. `fd_links_rev` is the
    /// reverse (cookie -> (tgid,fd)) so a TCP close drops the entry in O(1) — fd
    /// numbers are recycled, so a stale (tgid,fd) would mis-attribute a later
    /// connection's plaintext. Populated only under --capture-plaintext.
    fd_links: HashMap<(u32, u32), FdLink>,
    fd_links_rev: HashMap<u64, (u32, u32)>,
    /// (tgid, fd) -> in-flight S3 operation state on that connection (E5). The
    /// plaintext path delimits ops here: a request head opens one, a response head
    /// closes + emits it. Keyed by (tgid,fd) — the same key the TLS events carry —
    /// then joined to the connection via `cookie_for_fd` at emit time.
    ops: HashMap<(u32, u32), ConnOps>,
    /// Monotonic per-run op-id source.
    op_counter: u64,
    /// Ops flushed by `on_close` — a request was in flight (sent, no final response)
    /// when the connection closed, so it's emitted here rather than silently dropped.
    /// The caller drains this after each fold via [`Correlator::take_flushed_ops`].
    flushed_ops: Vec<Operation>,
    /// Count of plaintext writes the kernel admitted (it began with an HTTP method)
    /// but `http::parse_request` then rejected — a request line split across writes,
    /// or a method the kernel gate admits more loosely than the parser. Surfaced at
    /// shutdown so "no S3 traffic" is distinguishable from "S3 traffic the parser
    /// dropped" (review Gap C). Best-effort observability, never a hard error.
    parse_failures: u64,
    /// Opt-in custom S3 endpoint hosts (the `--s3-endpoint` flag), lowercased and
    /// port-free. A captured request to one of these resolves its bucket path-style
    /// (or `<bucket>.<endpoint>` virtual-hosted) — see [`http::resolve_with`]. Empty
    /// by default, so the standard run recognizes AWS hostname patterns only.
    s3_endpoints: Vec<String>,
    /// Per-run random salt that KEYS the object-key hash (HMAC-SHA256, see
    /// [`hash::key_hash_salted`]). Generated once per Correlator so identical keys hash
    /// the same WITHIN a capture (refetch / caching analysis still works) but differently
    /// ACROSS captures, which defeats offline dictionary / rainbow precomputation on
    /// low-entropy keys. Held in memory only, never serialized.
    key_salt: [u8; 16],
}

/// Per-connection operation state (E5).
#[derive(Default)]
struct ConnOps {
    /// 0-based index of the NEXT operation on this connection.
    next_seq: u32,
    /// The operation awaiting its response, if any.
    open: Option<OpenOp>,
    /// Last write/read time on this connection — so the leak guard evicts the
    /// least-recently-active connection, never a live in-flight op.
    last_ts: u64,
    /// The BIO-fallback cookie last seen on this op slot. BIO ops all key on `(tgid,0)`
    /// (fd unobserved) and emit no `conn_id`, so `on_close` can't reset the slot — the
    /// `next_seq` would leak across sequential BIO connections and falsely mark the 2nd+
    /// connection's first op `connection_reused`. When this changes, a NEW connection reused
    /// the slot → reset `next_seq`. `None` on the fd path (op.cookie is None there).
    last_bio_cookie: Option<u64>,
}

/// An operation whose request was seen, awaiting its response.
struct OpenOp {
    op_id: String,
    ts_ns: u64,
    req_seq: u32,
    verb: String,
    /// The classified S3 op — `None` when the host wasn't recognized as S3 (a plain GET
    /// to a non-S3 host is not a GetObject). `verb` always carries the raw HTTP method.
    s3_op: Option<String>,
    /// Bucket resolved from the request (host subdomain or path-style first
    /// segment) — the SNI-derived bucket is preferred at emit time, this is the
    /// fallback / the path-style source.
    bucket: Option<String>,
    key_hash: Option<String>,
    op_bytes_sent: u64,
    /// Time of the FIRST interim (1xx) response on this op, if any — e.g. the
    /// "100 Continue" S3 sends before a PUT/UploadPart body. That interim IS the
    /// first response byte, so ttfb measures to it (not the post-upload final
    /// status), keeping ttfb = time-to-first-byte and excluding the body upload.
    interim_ts: Option<u64>,
    /// The request head was longer than the capture (HDR_CAP) — Host / trailing
    /// headers may have been cut, so the op is reported `partial`, not clean.
    head_truncated: bool,
    /// A second request opened on this connection before this op's response.
    ambiguous: bool,
    /// Set once the response HEAD is seen for an op whose body we can tally
    /// (a known Content-Length > 0). While present, the op stays open awaiting
    /// EVT_TLS_READ_BODY events; when the body is fully observed it emits with
    /// download_ns/total_ns. None for the common case (no measurable body — emitted
    /// at the head as before).
    resp: Option<RespState>,
    /// The BIO-fallback cookie (`Some` only when this op opened with `fd==0` and the
    /// kernel stamped a tid-inferred `hdr.sock_cookie`). `build_op` prefers it over
    /// `cookie_for_fd` so a BIO client (curl ≥7.84, no `SSL_set_fd`) still joins its
    /// connection. `None` on the `fd` path (cookie resolves late via `cookie_for_fd`).
    cookie: Option<u64>,
}

/// Response state for an op whose body we are tallying toward Content-Length (M3.5
/// download/total). Captured at the response head; `body_seen` accumulates the
/// length-only EVT_TLS_READ_BODY events until it reaches `body_target`.
struct RespState {
    head_ts: u64,
    status: u16,
    aws_request_id: Option<String>,
    op_bytes_recv: u64,
    resp_truncated: bool,
    body_target: u64, // Content-Length: bytes of body expected after the head
    body_seen: u64,   // body bytes observed so far (head coalesce + body events)
}

/// A `(tgid,fd) -> cookie` entry plus the connect time, for cap-eviction of leaked
/// entries (a missed close) the same way the other maps bound themselves.
struct FdLink {
    cookie: u64,
    ts: u64,
}

/// The response-side facts that close an op, gathered together at emit time. All
/// "absent" (status/ts None, bytes 0) when an op is flushed as ambiguous — a second
/// request arrived before any response, so none of these were observed.
#[derive(Default)]
struct RespFacts {
    status: Option<u16>,
    aws_request_id: Option<String>,
    op_bytes_recv: u64,
    truncated: bool,
    /// Response-head time -> ttfb = this minus the request-write time.
    ts_ns: Option<u64>,
    /// Time the response BODY finished (last body byte), when observed via the
    /// Content-Length tally -> download_ns = this minus the head time, total_ns = this
    /// minus the request-write time. None when there's no measurable body or the body
    /// didn't complete before a flush (download/total stay None — honest).
    body_complete_ts: Option<u64>,
    /// Declared `Content-Length` of the response body (the object size for a GET),
    /// surfaced so a consumer can compute per-op throughput against `download_ns`.
    /// None when absent (chunked) or the head wasn't seen.
    content_length: Option<u64>,
}

/// Response facts for flushing an op early (close, fd reuse, eviction, or a new
/// request). `Some` when the op's response head was already seen (emit with its status,
/// but download/total None — the body didn't finish); `None` when no response was seen
/// at all (the caller emits it as an aborted/ambiguous op via `RespFacts::default`).
fn resp_facts_on_flush(op: &OpenOp) -> Option<RespFacts> {
    op.resp.as_ref().map(|rs| RespFacts {
        status: Some(rs.status),
        aws_request_id: rs.aws_request_id.clone(),
        op_bytes_recv: rs.op_bytes_recv,
        truncated: rs.resp_truncated,
        ts_ns: Some(rs.head_ts),
        body_complete_ts: None, // flushed before the body completed
        content_length: Some(rs.body_target), // size known from the head even if body unfinished
    })
}

/// The OS entropy sources tried, in order, for the per-run key salt. Both are the kernel
/// CSPRNG; `/dev/random` is only here for a stripped container image whose `/dev` happens to
/// carry one and not the other. There is no third option in-tree: this crate has no external
/// dependencies and no `libc`, so `getrandom(2)` is not reachable without adding one.
const ENTROPY_SOURCES: [&str; 2] = ["/dev/urandom", "/dev/random"];

/// Read 16 bytes of OS entropy for the per-run key salt, or FAIL.
///
/// Fails closed, deliberately. The former fallback — `(nanos_since_epoch ^ pid)` as a u128 —
/// was not a salt: its top 8 bytes are always ZERO, and the remaining ~61 bits are a wall
/// clock the capture itself discloses. Records carry `emitted_at` to millisecond precision
/// and the observed `app.pid`, which bounds a search to roughly 2^20 candidate nanoseconds
/// times a narrow pid window — a few million SHA-256s per dictionary word to strip the salt
/// off every key in the capture. SECURITY.md promises these hashes "resist offline dictionary
/// or rainbow lookup", and the fallback fired SILENTLY (a minimal container or namespace with
/// no `/dev/urandom`, or fd exhaustion), so the operator would ship a capture believing it
/// was salted. Aborting the run is the honest failure: no capture beats a capture whose
/// privacy property quietly does not hold.
fn random_salt() -> std::io::Result<[u8; 16]> {
    random_salt_from(&ENTROPY_SOURCES)
}

/// [`random_salt`] against an explicit source list, so a test can exercise the
/// no-entropy-available path without unmounting `/dev`.
fn random_salt_from(sources: &[&str]) -> std::io::Result<[u8; 16]> {
    use std::io::Read;
    let mut last_err = None;
    for path in sources {
        let mut salt = [0u8; 16];
        // read_exact, not read: a source that returns a short read (a truncated regular file
        // standing in for the device) must fail rather than leave the tail zeroed.
        match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut salt)) {
            Ok(()) => return Ok(salt),
            Err(e) => last_err = Some(e),
        }
    }
    let detail = last_err.map_or_else(|| "no source configured".to_string(), |e| e.to_string());
    Err(std::io::Error::other(
        format!(
            "no OS entropy source for the per-run key-hash salt (tried {}): {detail}. \
             Refusing to emit object-key hashes under a guessable salt — see SECURITY.md. \
             Ensure /dev/urandom exists in the capture environment (mount devtmpfs, or \
             bind-mount /dev/urandom into the container/namespace).",
            sources.join(", ")
        ),
    ))
}

/// The message a caller that cannot handle the entropy failure dies with. The fallible
/// constructors ([`Correlator::try_new`]) exist so the CLI can report it as a normal error.
const NO_ENTROPY_PANIC: &str = "s3tap: cannot start the correlator";

impl Correlator {
    /// # Panics
    /// If no OS entropy source is available for the per-run key-hash salt (see
    /// [`random_salt`]) — the capture is aborted rather than emitting object-key hashes
    /// under a guessable salt. Callers that can report an error should use
    /// [`Correlator::try_new`] instead.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect(NO_ENTROPY_PANIC)
    }

    /// [`Correlator::new`], but surfaces the no-entropy failure as an error instead of
    /// aborting. Preferred by anything with an error path to report on (the capture agent).
    ///
    /// # Errors
    /// When no OS entropy source can be read for the per-run key-hash salt.
    pub fn try_new() -> std::io::Result<Self> {
        Self::try_with_max_open(DEFAULT_MAX_OPEN)
    }

    /// Like [`Correlator::new`] but with an explicit open-connection cap (the
    /// eviction bound). Mainly for tests that exercise eviction without opening
    /// 65536 connections.
    ///
    /// # Panics
    /// As [`Correlator::new`], when no OS entropy source is available.
    #[must_use]
    pub fn with_max_open(max_open: usize) -> Self {
        Self::try_with_max_open(max_open).expect(NO_ENTROPY_PANIC)
    }

    /// [`Correlator::with_max_open`] with the no-entropy failure as an error.
    ///
    /// # Errors
    /// When no OS entropy source can be read for the per-run key-hash salt.
    pub fn try_with_max_open(max_open: usize) -> std::io::Result<Self> {
        Ok(Correlator {
            conns: HashMap::new(),
            max_open: max_open.max(1), // a cap of 0 would evict every insert
            pending_dns: HashMap::new(),
            resolutions: HashMap::new(),
            gai: HashMap::new(),
            tls: HashMap::new(),
            fd_links: HashMap::new(),
            fd_links_rev: HashMap::new(),
            ops: HashMap::new(),
            op_counter: 0,
            flushed_ops: Vec::new(),
            parse_failures: 0,
            s3_endpoints: Vec::new(),
            key_salt: random_salt()?,
        })
    }

    /// Register opt-in custom S3 endpoint hosts (the `--s3-endpoint` flag) so a
    /// captured request to one of them resolves its bucket path-style (or
    /// `<bucket>.<endpoint>` virtual-hosted). Hosts are lowercased here; the caller
    /// should strip any scheme/port first.
    pub fn set_s3_endpoints(&mut self, hosts: Vec<String>) {
        self.s3_endpoints = hosts.iter().map(|h| h.to_ascii_lowercase()).collect();
    }

    /// Drain the ops flushed by `on_close` (an in-flight request whose connection
    /// closed before its response). Call after each fold; usually empty.
    pub fn take_flushed_ops(&mut self) -> Vec<Operation> {
        std::mem::take(&mut self.flushed_ops)
    }

    /// Flush every operation still in flight, as aborted ops (no final response), into the
    /// [`Correlator::take_flushed_ops`] queue. Meant to be called ONCE at shutdown, right
    /// before the final `take_flushed_ops` — on SIGINT the requests that were in flight
    /// would otherwise vanish, even though the identical request interrupted by a TCP close
    /// IS emitted. Draining them keeps "what was outstanding when the capture ended"
    /// observable instead of silently lost.
    pub fn flush_open_ops(&mut self) {
        // Collect first: flush_and_drop_op mutates `ops` (and joins through fd_links).
        let keys: Vec<(u32, u32)> = self.ops.keys().copied().collect();
        for key in keys {
            self.flush_and_drop_op(key);
        }
    }

    /// Cumulative count of kernel-admitted plaintext writes that `parse_request`
    /// rejected (see `parse_failures`). The CLI reports it at shutdown so a parser
    /// blind spot (e.g. a split request head) can't masquerade as a quiet network.
    #[must_use]
    pub fn parse_failures(&self) -> u64 {
        self.parse_failures
    }

    /// A connect opens connection state. A later connect on the same cookie
    /// (sk-pointer reuse) supersedes the earlier one. Emits no record yet — a
    /// connection only becomes a record when it closes.
    pub fn on_connect(&mut self, e: &EvtTcpConnect) -> Option<Connection> {
        let cookie = e.hdr.sock_cookie;
        // This cookie is a raw `struct sock *`, so a connect on a cookie that STILL has an
        // fd link means the pointer was recycled after a missed close: the link, its op slot
        // and its next_seq belong to a connection that is already dead. Tear the old life
        // down here — the same defence, and for the same reason, as the `self.tls` clear
        // below — so a later plaintext event on that fd cannot read a dead connection's
        // slot. Done BEFORE the conns/tls entries are replaced, so the flushed op still
        // joins the OLD connection's facts.
        //
        // The discriminator is the OWNING PID, not a timestamp. This connection's own
        // conn_id is stamped at `tcp_v4_connect` — at the SYN, i.e. at or a hair before
        // this event's SYN start — and it rides tls_events while the connect rides
        // events, so with no inter-ring order it is routinely folded FIRST. A time
        // comparison therefore cannot tell "my own conn_id, seen early" from "a previous
        // life", and getting it wrong the destructive way costs the LIVE connection its
        // cookie join (sock_cookie 0, partial, no dns) for the rest of its life. A link
        // held by a different tgid cannot be this connection's own: `emit_connect` stamps
        // the connecting task's pid, the same one its conn_id carries.
        //
        // A recycled pointer reused by the SAME process is left alone here, since it is
        // indistinguishable at this event. That case is covered where it is decidable: the
        // new connection's own conn_id necessarily precedes its plaintext on `tls_events`,
        // and `on_conn_id` tears down any op slot the key already holds — cookie match or
        // not — so the slot can never be read by the new connection.
        let stale_link = self
            .fd_links_rev
            .get(&cookie)
            .copied()
            .filter(|k| k.0 != e.hdr.tgid && self.fd_links.contains_key(k));
        if let Some(old_key) = stale_link {
            self.flush_and_drop_op(old_key);
            self.fd_links.remove(&old_key);
            self.fd_links_rev.remove(&cookie);
        }
        self.conns.insert(
            cookie,
            ConnState {
                pid: e.hdr.tgid,
                connect_latency_ns: e.connect_latency_ns,
                ts_ns: e.hdr.ts_ns.saturating_sub(e.connect_latency_ns), // SYN start
                family: e.family,
                daddr: e.daddr,
                dport: e.dport,
                connect_failed: e.connect_failed != 0,
            },
        );
        // A fresh connect on this cookie supersedes any prior life of the same
        // sk-pointer: drop stale TLS facts so a NEW connection can't inherit an
        // OLD one's SNI/region after a missed close + pointer reuse. For a normal
        // connection its own ClientHello arrives AFTER connect, so it re-populates
        // this entry. (The conns map gets the same treatment via the insert above.)
        //
        // KNOWN under-report: with TCP Fast Open the ClientHello rides the SYN, so
        // its event is produced BEFORE the ESTABLISHED connect event — this clear
        // then drops that connection's own SNI (it reports tls.seen=false). We
        // accept it: TFO can't be distinguished from a stale-reuse entry by cookie
        // or timestamp (both land just before the connect), and a missing label is
        // the honest choice over the wrong-label we'd get by not clearing. TFO TLS
        // to S3 is near-nonexistent (servers rarely enable it), so the cost is tiny.
        self.tls.remove(&cookie);

        // Enforce the cap. A leaked entry is never updated, so its `ts_ns`
        // (connection start) stays old and it is reclaimed before any live
        // connection. Never evict the entry we just opened (it is the newest,
        // but a saturated ts_ns of 0 could otherwise make it the minimum).
        //
        // Batched (see EVICT_BATCH_DIVISOR): this is THE map the ring-overflow leak pins at
        // its cap, and a per-insert O(65536) scan here is what turns a transient overflow
        // into an unrecoverable fold-throughput collapse. One pass per cap/10 connects.
        if self.conns.len() > self.max_open {
            let target = evict_target(self.conns.len(), self.max_open);
            for victim in oldest_keys(&self.conns, target, |s| s.ts_ns, |&c| c == cookie) {
                self.conns.remove(&victim);
            }
        }
        None
    }

    /// A close finalizes the connection record. If we saw the opening connect
    /// we fill the endpoint + connect timing; otherwise the record is `partial`
    /// (we attached mid-connection, so connect-level facts are unknown).
    pub fn on_close(&mut self, e: &EvtTcpClose) -> Option<Connection> {
        let cookie = e.hdr.sock_cookie;

        // Flush an IN-FLIGHT op: a request was sent but its final response never
        // arrived before the connection closed (client timeout / reset / abort). Done
        // FIRST, while the connection facts are still joinable (the conns entry is
        // removed just below). The op carries ttfb_ns from a 100-Continue interim when
        // one was seen, http_status None, delimitation Clean — the "aborted in-flight
        // op" signal. Only reachable
        // under --capture-plaintext (no ops without the conn_id join); otherwise it
        // would be silently dropped at the `ops.remove` below.
        // Which (tgid,fd) link, if any, does THIS close own? `sock_cookie` is the raw
        // `struct sock *` (bpf/src/s3tap.bpf.c), so pointer recycling is routine and a close
        // for the pointer's PREVIOUS life can be folded after its successor already claimed
        // the link (close rides `events`, conn_id rides `tls_events` — no inter-ring order).
        // Acting on it then would flush the successor's live in-flight request as a false
        // abort AND drop its link, leaving every later op on that connection with
        // sock_cookie 0 / partial / no dns. A link stamped AFTER this close cannot belong to
        // the connection that is closing, so leave it (and its ops) alone. An unstamped
        // close (ts 0 — the probe always stamps one, so this is synthetic/degraded input)
        // keeps the unconditional behaviour rather than silently skipping the flush.
        let linked = self.fd_links_rev.get(&cookie).copied();
        let own_link = linked.filter(|k| {
            self.fd_links
                .get(k)
                .is_none_or(|l| e.hdr.ts_ns == 0 || l.ts <= e.hdr.ts_ns)
        });
        if let Some(key) = own_link {
            self.flush_and_drop_op(key);
        } else if linked.is_none() {
            // BIO fallback: a BIO op (curl >= 7.84, fd==0, no conn_id) lives at a `(tgid,0)`
            // slot keyed by cookie, so `fd_links_rev` never maps it. The close event's tgid
            // is unreliable here (it can be a softirq/kernel context — see the EventHdr
            // note), so locate the slot by matching its cookie instead. `ops` is
            // capped, so this scan is bounded, and it only runs for a close whose cookie has
            // no fd link (i.e. a BIO close). Flush it so an aborted in-flight BIO op is
            // emitted, never silently dropped (by design); the cookie match ensures we
            // never flush a concurrent BIO connection's op that holds the slot.
            //
            // TWO passes, in this order, because `ops` is a HashMap and `.find()` would
            // otherwise resolve a multi-slot match in randomized iteration order. Slots are
            // keyed (tgid,0), so a recycled sock pointer can leave two DIFFERENT processes
            // both naming this cookie: one with a live in-flight op, one holding only a
            // residual `last_bio_cookie` from a completed request. Coin-flipping between
            // them means the abort contract silently depends on hash seeding.
            //
            // Pass 1 — an OPEN op whose cookie is exactly this one. That is positive
            // evidence the slot is using this connection RIGHT NOW, and it is the only kind
            // of slot this scan exists to serve: flushing it emits the aborted in-flight
            // request, which is the whole point.
            //
            // Pass 2 — slot OWNERSHIP via `last_bio_cookie`, when no slot has an open op for
            // the cookie. Nothing is emitted (no open op), but the slot must still be
            // reclaimed: after a COMPLETED BIO request it carries this connection's
            // `next_seq`, and leaving it behind means the next BIO connection reusing the
            // recycled pointer sees no cookie change in `bio_conn_changed`, so its
            // genuinely-first op ships req_seq=1 — connection_reused, with its dns and
            // tcp_connect_ns suppressed.
            let bio_key = self
                .ops
                .iter()
                .find(|(k, c)| k.1 == 0 && c.open.as_ref().and_then(|o| o.cookie) == Some(cookie))
                .map(|(&k, _)| k)
                .or_else(|| {
                    self.ops
                        .iter()
                        .find(|(k, c)| k.1 == 0 && c.last_bio_cookie == Some(cookie))
                        .map(|(&k, _)| k)
                });
            if let Some(bio_key) = bio_key {
                self.flush_and_drop_op(bio_key);
            }
        }

        let state = self.conns.remove(&cookie);
        let saw_connect = state.is_some();

        // Best-effort invalidation of the (tgid,fd)->cookie join. Note this is NOT
        // the load-bearing safety against fd-reuse mis-attribution: conn_id rides
        // the tls_events ring while close rides `events`, so a close can be drained
        // BEFORE the conn_id it would invalidate (then it no-ops here, and the late
        // conn_id leaves a stale link reclaimed only by overwrite/cap-eviction). The
        // REAL guarantee is the overwrite in on_conn_id: a recycled fd's new connect
        // emits a conn_id on the SAME ring as the plaintext, so the new conn_id is
        // always drained before any new plaintext (FIFO) and overwrites the stale
        // link before it can be read. This remove just reclaims promptly in the
        // common (same-ring-as-it-used-to-be) ordering. O(1) via the reverse map.
        // Guarded by the same `own_link` test as the flush above: a link a SUCCESSOR
        // connection on the recycled pointer already claimed is not ours to remove.
        if let Some(key) = own_link {
            self.fd_links.remove(&key); // ops already dropped by flush_and_drop_op above
            self.fd_links_rev.remove(&cookie);
        }

        // Resolve the endpoint IP once, then use it to attach any DNS we saw for
        // it (the resolution that led here) and to derive the S3 region. NB: this
        // joins purely on the connect's daddr — a `partial` record (no connect
        // seen, so `state` is None) has no IP to join on, so it loses BOTH the dns
        // block and the endpoint even if a resolution for that IP exists. The
        // close event carries no daddr; fixing that is a future ABI change.
        let resolved = state.as_ref().map(|s| classify_endpoint(s.family, &s.daddr));
        let (dns, dns_region) = match resolved {
            Some((ip, _)) => self.dns_for_ip(ip, state.as_ref().map_or(0, |s| s.ts_ns)),
            None => (None, None),
        };

        // TLS ClientHello facts for THIS connection (keyed by the same sk-cookie
        // the connection uses). The SNI is the name the client actually requested
        // for this connection — higher confidence than a shared-IP DNS reverse
        // lookup and present even when DNS was bypassed — so prefer it for the
        // region; fall back to the DNS-derived region (and its shared-IP caveat).
        let tls_info = self.tls.remove(&cookie);
        let region = tls_info
            .as_ref()
            .and_then(|t| aws_region_from_host(&t.sni))
            .or(dns_region);
        // TLS handshake duration: ClientHello egress -> first app-data egress, timed in-kernel
        // and shipped on the close event (µs). Present even for an SNI-less (IP-based) TLS
        // connection that produced no tls_info, so set `seen` if EITHER signal is here.
        let handshake_ns = (e.handshake_us != 0).then(|| u64::from(e.handshake_us) * 1000);
        let version = tls_info.as_ref().and_then(|t| t.version).map(tls_version_str);
        let cipher = tls_info.as_ref().and_then(|t| t.cipher);
        let tls = match &tls_info {
            Some(t) => Tls {
                seen: true,
                handshake_ns,
                version,
                cipher,
                // "" == a ServerHello-only entry (SNI-less connection) -> no SNI to report.
                sni: (!t.sni.is_empty()).then(|| t.sni.clone()),
            },
            None if handshake_ns.is_some() => {
                Tls { seen: true, handshake_ns, version: None, cipher: None, sni: None }
            }
            None => Tls::default(), // seen=false
        };

        let endpoint = match (&state, resolved) {
            (Some(s), Some((ip, family))) => Endpoint {
                // SNI-first (the name the client requested for this connection),
                // else DNS-derived with its shared-IP caveat (on an anycast/shared
                // address that region is only as good as the last name resolved
                // to this IP).
                region,
                endpoint_ip: Some(ip.to_string()),
                family: Some(family.to_string()),
                dport: Some(s.dport),
                via_vpce: false,
                cross_region: false,
            },
            // Partial record (connect missed, so no IP/family/dport): still surface
            // the SNI-derived region — it's connection-local, needs no IP join, so
            // there's no reason to drop it just because we lack the endpoint IP.
            _ => Endpoint { region, ..Endpoint::default() },
        };

        let connect_failed = state.as_ref().is_some_and(|s| s.connect_failed);
        // None when unmeasured (no connect seen, or latency 0 == passive open),
        // and forced None on a failed connect: it never reached ESTABLISHED, so
        // there is no SYN→ESTABLISHED latency — keep the record internally
        // consistent regardless of what the probe happens to stamp.
        let tcp_connect_ns = if connect_failed {
            None
        } else {
            state
                .as_ref()
                .map(|s| s.connect_latency_ns)
                .filter(|&ns| ns != 0)
        };

        // The chrono busy-time accumulators are disjoint; their sum is the total send-busy
        // time. Gate the group on the sum so a fully-limited (busy==0) connection survives.
        let chrono_sum = e
            .busy_jiffies
            .saturating_add(e.rwnd_limited_jiffies)
            .saturating_add(e.sndbuf_limited_jiffies);

        Some(Connection {
            schema: ConnSchemaTag,
            emitted_at: None, // stamped by the emitter (CLI) at output time
            ts_ns: state.as_ref().map(|s| s.ts_ns),
            sock_cookie: cookie,
            app: App {
                // 0 == unknown when we never saw the connect. The close event's own
                // hdr.tgid is NOT a fallback: EVT_TCP_CLOSE is stamped wherever the socket
                // is torn down, routinely NET_RX softirq context (see the note above), so
                // it names an unrelated task — a connection s3tap attached to mid-flight
                // would be published as belonging to e.g. sshd. Robust either way: if the
                // probe manages to stamp the owning pid on the close, it reaches us as the
                // connect-side `pid` through `conns`, never through this fallback.
                pid: state.as_ref().map_or(0, |s| s.pid),
            },
            endpoint,
            dns,
            tcp_connect_ns,
            connect_failed,
            tls,
            bytes_sent: e.bytes_sent,
            bytes_recv: e.bytes_recv,
            retransmits: e.retransmit_count,
            srtt_us: (e.srtt_us != 0).then_some(e.srtt_us), // 0 == never sampled
            lifetime_ns: (e.lifetime_ns != 0).then_some(e.lifetime_ns), // 0 == unknown
            // Extended path diagnosis — 0 == unknown/no-sample (the probe sentinel),
            // mapped to None. min_rtt also uses ~0u32 (U32_MAX) as "never sampled"
            // (tcp_min_rtt's sentinel) — filter it too, or it surfaces as a ~4.3M ms
            // "floor" and corrupts the BDP/inflation math (review #3).
            min_rtt_us: (e.min_rtt_us != 0 && e.min_rtt_us != u32::MAX).then_some(e.min_rtt_us),
            rttvar_us: (e.rttvar_us != 0).then_some(e.rttvar_us),
            snd_cwnd: (e.snd_cwnd != 0).then_some(e.snd_cwnd),
            mss: (e.mss_cache != 0).then_some(e.mss_cache),
            delivery_rate_bps: (e.delivery_rate_bps != 0).then_some(e.delivery_rate_bps),
            // The three chronos are disjoint and sum to the total busy-time; gate the GROUP
            // on their SUM (not busy alone) so a fully receiver/buffer-limited connection
            // (busy==0 but rwnd/sndbuf>0) still keeps its signal (review #4).
            busy_jiffies: (chrono_sum != 0).then_some(e.busy_jiffies),
            rwnd_limited_jiffies: (chrono_sum != 0).then_some(e.rwnd_limited_jiffies),
            sndbuf_limited_jiffies: (chrono_sum != 0).then_some(e.sndbuf_limited_jiffies),
            lost: (e.lost != 0).then_some(e.lost),
            sacked: (e.sacked_out != 0).then_some(e.sacked_out),
            reordering: (e.reordering != 0).then_some(e.reordering),
            // ca_state 0 (Open) is both the healthy norm and the no-info value;
            // surface only a non-Open close (the interesting "closed mid-recovery").
            ca_state: (e.ca_state != 0).then_some(e.ca_state),
            // Receive window (download-throughput ceiling input); 0 == unknown -> None.
            rcv_wnd: (e.rcv_wnd != 0).then_some(e.rcv_wnd),
            window_clamp: (e.window_clamp != 0).then_some(e.window_clamp),
            // Loss-quality / receive-reorder / send rate-limit — 0 == none / no sample → None
            // (the probe sentinel for these counters). app_limited surfaces only when the kernel
            // set the rate_app_limited bit (send-path; meaningful on uploads).
            bytes_retrans: (e.bytes_retrans != 0).then_some(e.bytes_retrans),
            dsack_dups: (e.dsack_dups != 0).then_some(e.dsack_dups),
            rcv_ooopack: (e.rcv_ooopack != 0).then_some(e.rcv_ooopack),
            app_limited: (e.rate_app_limited != 0).then_some(true),
            partial: !saw_connect,
        })
    }

    /// A DNS query went out. Remember it by `(sock_cookie, txn_id)` so the
    /// response can pair with it. The cookie is the resolver's UDP socket, which
    /// is the same for the query (sendmsg) and the response (recv) regardless of
    /// which task context consumes the response — more robust than a pid join.
    pub fn on_dns_query(&mut self, e: &EvtDnsQuery) {
        if e.qname_truncated != 0 {
            // A clipped query name is only a prefix; the response echoes the FULL name,
            // so the Gap F question<->query match would reject the real response and the
            // connection would lose its dns block (review F5). Drop the query like
            // on_tls_handshake drops a truncated SNI. (Conformant names are <= 253 < 255,
            // so this only fires on pathological names that never address S3.)
            return;
        }
        let Some(qname) = qname_str(&e.qname, e.qname_len) else {
            return; // non-UTF8 / empty name: nothing to join on
        };
        let key = (e.hdr.sock_cookie, e.txn_id);
        self.pending_dns
            .insert(key, PendingQuery { qname, query_ts: e.hdr.ts_ns });
        evict_oldest_over(&mut self.pending_dns, DNS_MAP_CAP, &key, |q| q.query_ts);
    }

    /// A DNS response arrived. Pair it with its query and record, per resolved
    /// IP, the name + wire latency so a later connection to that IP is labeled.
    pub fn on_dns_response(&mut self, e: &EvtDnsResponse) {
        let payload = &e.payload[..(e.payload_len as usize).min(e.payload.len())];
        let Some((txn_id, resp_qname, answers)) = parse_dns_response(payload) else {
            return; // too short / unparseable
        };
        let key = (e.hdr.sock_cookie, txn_id);
        // Gap F: the (sock_cookie, 16-bit txn_id) key can collide — a resolver UDP
        // socket is freed and its pointer (hence cookie) reused, and 16-bit txn ids
        // recur — so a response could pair to the WRONG pending query (wrong hostname
        // / latency). The response echoes its question name, so reject a pairing whose
        // name doesn't match the stored query: it's a collision, not our answer — keep
        // the pending entry for its real response.
        //
        // A response carrying NO decodable question (qdcount 0, or a malformed name) fails
        // that verification rather than skipping it: real resolvers always echo the
        // question, so a nameless response is malformed or forged, and pairing it anyway
        // would poison `resolutions` with a confidently wrong hostname/region for whatever
        // addresses it names. Keep the pending query for its genuine answer.
        match &resp_qname {
            Some(rq) => {
                if self.pending_dns.get(&key).is_some_and(|q| &q.qname != rq) {
                    return;
                }
            }
            None => return,
        }
        let Some(q) = self.pending_dns.remove(&key) else {
            return; // unmatched (query predated attach, or already paired)
        };
        let latency = e.hdr.ts_ns.saturating_sub(q.query_ts);
        let n_answers = answers.len().min(u8::MAX as usize) as u8; // A/AAAA count
        for &(ip, ttl_s) in &answers {
            self.resolutions.insert(
                ip,
                Resolution {
                    hostname: q.qname.clone(),
                    wire_latency_ns: latency,
                    ttl_s,
                    n_answers,
                    query_ts: q.query_ts,
                    resolved_ts: e.hdr.ts_ns,
                },
            );
        }
        // One response can carry up to 64 answers, so the map can land up to 63 entries over
        // cap (review L7). `evict_target` reclaims the whole excess in ONE pass (plus the
        // amortizing batch) instead of re-scanning per entry — and never evicts an IP we just
        // inserted (L9), or a burst of answers from one response could drop each other before
        // any is read. `oldest_keys` returns fewer than asked when only fresh IPs remain,
        // which is the old loop's `break`.
        if self.resolutions.len() > DNS_MAP_CAP {
            let fresh: std::collections::HashSet<IpAddr> = answers.iter().map(|&(ip, _)| ip).collect();
            let target = evict_target(self.resolutions.len(), DNS_MAP_CAP);
            for victim in oldest_keys(&self.resolutions, target, |r| r.resolved_ts, |ip| fresh.contains(ip)) {
                self.resolutions.remove(&victim);
            }
        }
    }

    /// A `getaddrinfo` returned. Record the resolver-call latency (what the app
    /// paid) for the hostname. `cache_hit` is inferred here, not by the probe: a
    /// hit is a call that paid latency with NO wire query for the host inside its
    /// window (resolved from nscd/glibc cache).
    pub fn on_getaddrinfo(&mut self, e: &EvtGetaddrinfo) {
        if e.ret != 0 {
            return; // failed lookup: nothing to attach to a connection
        }
        if e.hostname_truncated != 0 {
            return; // a clipped host is only a prefix; it would join the wrong wire
                    // resolution / flip cache_hit. Drop it (mirrors on_dns_query, F5).
        }
        let Some(host) = qname_str(&e.hostname, e.hostname_len) else {
            return;
        };
        // A wire lookup for this host overlapping the call window [start, exit]
        // means the resolver actually went to the network -> not a cache hit.
        //   - A paired resolution spans [query_ts, resolved_ts]; it counts if that
        //     interval intersects the window. Keying on resolved_ts alone would
        //     miss a query that landed in-window whose response was stamped (or
        //     folded, probes are unordered) just after exit -> a real miss
        //     mislabeled as a hit. Interval overlap: a <= d && c <= b.
        //   - A still-pending (unanswered) query counts only if its query_ts is
        //     within the window on BOTH sides: a stale never-answered entry from
        //     an earlier call must not force a false miss.
        // If latency_ns ever exceeded ts_ns (a clock glitch / garbage entry_ts),
        // window_start saturates to 0 and the resolutions branch below matches any
        // prior resolution for this host -> reports cache_hit=false. That's the
        // CONSERVATIVE direction (treat an unknowable call as a wire miss), never
        // a false hit, so we leave it: do not "fix" it into a default hit.
        let window_start = e.hdr.ts_ns.saturating_sub(e.latency_ns);
        let exit = e.hdr.ts_ns;
        let saw_wire = self
            .resolutions
            .values()
            .any(|r| r.hostname == host && r.query_ts <= exit && window_start <= r.resolved_ts)
            || self
                .pending_dns
                .values()
                .any(|q| q.qname == host && (window_start..=exit).contains(&q.query_ts));
        self.gai.insert(
            host.clone(),
            Gai { latency_ns: e.latency_ns, cache_hit: !saw_wire, ts: e.hdr.ts_ns },
        );
        evict_oldest_over(&mut self.gai, DNS_MAP_CAP, &host, |g| g.ts);
    }

    /// A TLS ClientHello was seen on a connection. Remember its SNI by the
    /// connection's sock_cookie so `on_close` can fill the `tls` block and prefer
    /// the SNI (higher confidence than DNS) for the endpoint region.
    pub fn on_tls_handshake(&mut self, e: &EvtTlsHandshake) {
        if e.sni_truncated != 0 {
            return; // a clipped prefix isn't the real server_name — report
                    // tls.seen=false rather than a confident, mangled host.
                    // (Can't happen for conformant SNI: hostnames are <= 253 < 255.)
        }
        let Some(sni) = qname_str(&e.sni, e.sni_len) else {
            return; // non-UTF8 / empty SNI: nothing to record
        };
        // Merge (don't clobber): a ServerHello (on_tls_server) may have created the entry
        // first with the negotiated version/cipher — keep those, just fill the SNI.
        let entry = self
            .tls
            .entry(e.hdr.sock_cookie)
            .or_insert_with(|| TlsInfo { sni: String::new(), ts: e.hdr.ts_ns, version: None, cipher: None });
        entry.sni = sni;
        entry.ts = e.hdr.ts_ns;
        // Bound to the SAME cap as the conns map: a TLS entry is per live
        // connection (one ClientHello per connect), so its churn tracks the
        // connection rate, not DNS churn — capping at the smaller DNS_MAP_CAP
        // could evict a still-open connection's SNI and report tls.seen=false.
        evict_oldest_over(&mut self.tls, self.max_open, &e.hdr.sock_cookie, |t| t.ts);
    }

    /// The ServerHello's NEGOTIATED version + cipher (S2), parsed off the ingress path.
    /// Merges into the same per-cookie TLS facts the ClientHello SNI populates (either may
    /// arrive first; an SNI-less connection gets an entry with an empty sni).
    pub fn on_tls_server(&mut self, e: &EvtTlsServer) {
        let entry = self
            .tls
            .entry(e.hdr.sock_cookie)
            .or_insert_with(|| TlsInfo { sni: String::new(), ts: e.hdr.ts_ns, version: None, cipher: None });
        // Merge field by field (don't clobber), the same discipline the SNI path above
        // applies. The kernel can emit a PARTIAL EVT_TLS_SERVER — a cipher with version 0
        // when the ServerHello's supported_versions extension wasn't decodable — and a
        // second event for the same cookie must not erase a version (or cipher) already
        // learned. 0 is the probe's "unknown" sentinel, so only a non-zero value is news.
        if e.version != 0 {
            entry.version = Some(e.version);
        }
        if e.cipher != 0 {
            entry.cipher = Some(e.cipher);
        }
        evict_oldest_over(&mut self.tls, self.max_open, &e.hdr.sock_cookie, |t| t.ts);
    }

    /// Record the `(tgid, fd) -> sock_cookie` mapping (M3 E4). The plaintext path
    /// (E5) resolves a TLS event's `(tgid, fd)` to its connection cookie through
    /// this. Kept consistent with the reverse map so `on_close` can invalidate in
    /// O(1); a reused `(tgid,fd)` or cookie drops its stale partner first.
    pub fn on_conn_id(&mut self, e: &EvtConnId) {
        let key = (e.hdr.tgid, e.fd);
        let cookie = e.hdr.sock_cookie;

        // A conn_id is emitted ONCE PER connect(): `emit_conn_id` (bpf/src/s3tap.bpf.c) is
        // called only from the tcp_v{4,6}_connect kprobes, and it deletes its connect_fd
        // stash on every exit path, so no connection ever produces a second one. A conn_id
        // arriving for a (tgid,fd) that ALREADY holds an op slot therefore names a NEW
        // connection, unconditionally — the slot is a previous life's and MUST NOT bleed
        // into it. Left in place, the new connection's first on_tls_write would (1) flush the
        // old still-open op joined to the NEW cookie/SNI/bucket (cross-connection
        // mis-attribution — review H1/M2) and (2) inherit the old `next_seq`, so the
        // genuinely-fresh connection's first op is mislabeled connection_reused, which
        // suppresses its real dns + tcp_connect_ns (review H1/M1). Flush the old op against
        // whatever the key resolves to NOW — we haven't rebound the link yet, so a distinct
        // old cookie still resolves — then drop the slot, exactly as on_close would have.
        //
        // NOT qualified on the cookie DIFFERING, deliberately. `sock_cookie` is a raw
        // `struct sock *`, so the kernel routinely hands the same pointer to the next
        // connect in the SAME process: cookie C on (tgid,fd) dies with its close still
        // queued on the `events` ring, the pointer is reallocated, and the new connection's
        // conn_id arrives on `tls_events` carrying the same C and the same (tgid,fd). A
        // `l.cookie != cookie` qualifier reads that as "my own conn_id" and skips the flush,
        // while the two other fd-reuse guards also miss it (on_close's `l.ts <= close_ts`
        // test fails once this conn_id has bumped the link's ts, and on_connect's stale-link
        // rule requires a DIFFERENT tgid). All three defences fail on the same input, which
        // is the one case the pre-guard code handled by tearing the slot down every time.
        // Slot occupancy alone is the right test, and it costs nothing: no live connection
        // can own both this key's op slot and a conn_id it has not yet emitted.
        if self.ops.contains_key(&key) {
            self.flush_and_drop_op(key);
        }

        if let Some(old) = self.fd_links.insert(key, FdLink { cookie, ts: e.hdr.ts_ns }) {
            if old.cookie != cookie {
                self.fd_links_rev.remove(&old.cookie); // this (tgid,fd) had another cookie
            }
        }
        if let Some(old_key) = self.fd_links_rev.insert(cookie, key) {
            if old_key != key {
                // This cookie was last seen on a DIFFERENT (tgid,fd). Not an fd migration:
                // dup/dup2 move an fd without any connect(), and `emit_conn_id` fires only
                // from the connect kprobes, so nothing re-announces a live connection under
                // a new fd. The only way here is a second connect() on a recycled
                // `struct sock *`, i.e. the old_key slot belongs to a connection that is
                // already DEAD. Flush its in-flight op (against old_key, whose link still
                // resolves) and drop the slot — carrying it onto `key` would hand the dead
                // connection's op and `next_seq` to a brand-new one, exactly what the guard
                // above exists to prevent. `flush_and_drop_op` runs BEFORE the link removal
                // so the op still joins through it.
                self.flush_and_drop_op(old_key);
                self.fd_links.remove(&old_key); // this cookie had another (tgid,fd)
            }
        }
        // Bound leaked entries (a missed close) the way conns/tls are bounded:
        // evict the oldest, cleaning both maps. Never evict the entry we just
        // inserted (as on_connect guards) — a ts_ns of 0 would otherwise make the
        // new link the minimum and destroy it immediately. Only fires when over cap,
        // and then a batch at a time (EVICT_BATCH_DIVISOR) so a leak that pins the map
        // doesn't put an O(max_open) scan on every conn_id. Victims are collected first:
        // `flush_and_drop_op` mutates `ops` and reads `fd_links` to join.
        if self.fd_links.len() > self.max_open {
            let target = evict_target(self.fd_links.len(), self.max_open);
            for k in oldest_keys(&self.fd_links, target, |v| v.ts, |&kk| kk == key) {
                // The op map is keyed the same way (tgid,fd), so evicting only the
                // fd_links entry would orphan ops[k] until its own cap AND silently
                // lose its in-flight op (review L8). Flush+drop it BEFORE removing the
                // link, so the op still joins to its (about-to-be-evicted) connection.
                self.flush_and_drop_op(k);
                if let Some(v) = self.fd_links.remove(&k) {
                    // Remove the reverse entry only if it actually points back at the
                    // evicted key (exact-pairing, like on_close) — never clobber a
                    // live entry for the same cookie. Today the insert path keeps the
                    // maps bijective so this always matches; the check future-proofs it.
                    if self.fd_links_rev.get(&v.cookie) == Some(&k) {
                        self.fd_links_rev.remove(&v.cookie);
                    }
                }
            }
        }
    }

    /// Resolve a TLS event's `(tgid, fd)` to its connection's sock_cookie, if a
    /// CONN_ID mapped it and no close has invalidated it. The join key the E5
    /// plaintext path uses. `None` ⇒ the op is `partial` (fd unobserved).
    #[must_use]
    pub fn cookie_for_fd(&self, tgid: u32, fd: u32) -> Option<u64> {
        self.fd_links.get(&(tgid, fd)).map(|l| l.cookie)
    }

    /// A captured SSL_write plaintext head (E5). If it's an HTTP request line it
    /// OPENS an operation on the connection. Returns a finished `Operation` only in
    /// the concurrency case — a new request arriving before the prior op's
    /// response flushes the prior op as `ambiguous`. Otherwise None (the op is open,
    /// awaiting its response).
    pub fn on_tls_write(&mut self, e: &EvtTlsData) -> Option<Operation> {
        let Some(req) = http::parse_request(e.captured()) else {
            // The kernel admitted this write (it began with an HTTP method) but the
            // parser couldn't complete the request line — the head was split across
            // writes, or the method was admitted more loosely in-kernel than here.
            // Count it so the loss is observable at shutdown (review Gap C) instead of
            // a request silently vanishing. Don't count an empty/no-op capture.
            if !e.captured().is_empty() {
                self.parse_failures += 1;
            }
            return None;
        };
        let key = (e.hdr.tgid, e.fd);
        // BIO-fallback cookie: when the kernel couldn't resolve the fd (curl ≥7.84 never
        // calls SSL_set_fd → fd==0), handle_tcp_sendmsg stamped the thread's current TLS
        // connection into hdr.sock_cookie. Use it here (SNI lookup) and carry it on the op
        // for build_op. `None` on the fd path, which resolves late via `cookie_for_fd`.
        let bio_cookie = (e.fd == 0 && e.hdr.sock_cookie != 0).then_some(e.hdr.sock_cookie);
        // Path-style requests carry the bucket as the request line's first segment but
        // need the HOST to confirm the endpoint is S3 (else the segment is treated as
        // part of the key). That Host header can be ABSENT from this captured write —
        // pushed past HDR_CAP behind a long Authorization/SigV4 header, or sent in a
        // later write (review Gap B). Fall back to the connection's SNI (the host the
        // TLS handshake actually used — authoritative, and harder to spoof than Host)
        // so path-style key+bucket still resolve. No effect when Host is present.
        let sni = bio_cookie
            .or_else(|| self.cookie_for_fd(e.hdr.tgid, e.fd))
            .and_then(|c| self.tls.get(&c))
            .map(|t| t.sni.clone());
        let host = req.host.or(sni.as_deref());
        // Resolve op + bucket + key, handling both addressing styles (path-style
        // folds the bucket into the path, which `resolve` splits out).
        let r = http::resolve_with(req.method, req.path, req.query, host, &self.s3_endpoints);
        // Only label an s3_op when the host was recognized as S3 — `r.op` is classified
        // from the verb for any request, so a plain GET to a non-S3 host would otherwise
        // masquerade as GetObject (and surface a bogus "S3 server work" doctor row).
        let s3_op = r.is_s3.then(|| r.op.as_str().to_string());
        let bucket = r.bucket.map(str::to_string);
        let key_hash = r.key.map(|k| hash::key_hash_salted(&self.key_salt, k));

        // BIO connection change on the (tgid,0) slot: a different fallback cookie means a NEW
        // connection reused the slot (BIO clients emit no conn_id, so on_close can't reset it).
        // Reset next_seq so the new connection's first op is req_seq 0 (not falsely
        // connection_reused with its dns/tcp_connect_ns dropped — review: sequential-BIO leak);
        // any prior op flushed below belongs to the OLD connection, not this one (so it's an
        // aborted op, not an ambiguous same-connection race).
        //
        // KNOWN LIMITATION (architectural): this reasoning is exact only for SEQUENTIAL BIO
        // connections. Two CONCURRENT BIO connections in one process both collapse onto the
        // single (tgid,0) slot, so each interleaved write flushes the other connection's
        // still-live op as a (false) abort and the non-owning connection's response is dropped
        // by the cookie guard in on_tls_read. Correctly separating concurrent BIO streams would
        // need a cookie-keyed op slot (a cross-cutting change); until then, concurrent BIO under
        // --capture-plaintext is a documented best-effort gap, not a clean-capture guarantee.
        let bio_conn_changed = bio_cookie.is_some()
            && self
                .ops
                .get(&key)
                .and_then(|c| c.last_bio_cookie)
                .is_some_and(|prev| Some(prev) != bio_cookie);
        // Concurrency guard: a request while an op is still open. "Unanswered" means
        // no response head was seen yet (resp None) — that's the truly ambiguous case.
        // If the prior op DID get its response and is only awaiting its body tally
        // (resp Some), the new request isn't ambiguous; we just flush the prior with
        // its status and download/total None (body never finished).
        let prev = self.ops.get_mut(&key).and_then(|c| c.open.take());
        // A prior op from a DIFFERENT (now-closed) BIO connection is aborted, not an
        // ambiguous same-connection race.
        let prev_unanswered = prev.as_ref().is_some_and(|p| p.resp.is_none()) && !bio_conn_changed;
        let op_id = self.next_op_id();
        let seq = {
            let c = self.ops.entry(key).or_default();
            c.last_ts = e.hdr.ts_ns;
            if bio_conn_changed {
                c.next_seq = 0;
            }
            if let Some(bc) = bio_cookie {
                c.last_bio_cookie = Some(bc);
            }
            let s = c.next_seq;
            c.next_seq += 1;
            s
        };
        let new = OpenOp {
            op_id,
            ts_ns: e.hdr.ts_ns,
            req_seq: seq,
            verb: req.method.to_string(),
            s3_op,
            bucket,
            key_hash,
            op_bytes_sent: u64::from(e.plaintext_len),
            interim_ts: None,
            // A capture overflow when the client wrote the head AND body in one
            // SSL_write is the BODY spilling past the buffer, not a cut head. The
            // head is trustworthy iff we saw its terminator, so only call it
            // truncated when we overflowed AND never saw the head end (mirrors the
            // response path). Otherwise a large PutObject/UploadPart reads `partial`
            // and is wrongly excluded from latency/tail judgement.
            head_truncated: e.captured_truncated != 0 && http::header_end(e.captured()).is_none(),
            ambiguous: prev_unanswered,
            resp: None,
            cookie: bio_cookie,
        };
        // Emit the interrupted prior op: ambiguous + incomplete if it never got a
        // response, else with its known response facts (download/total unobserved).
        let flushed = prev.map(|mut p| {
            if let Some(facts) = resp_facts_on_flush(&p) {
                self.build_op(key, &p, facts)
            } else {
                // No response seen: a same-connection race makes the prior op ambiguous.
                // But if a DIFFERENT (now-closed) BIO connection reused this slot
                // (`bio_conn_changed`), the prior op was ABORTED by that close, not raced —
                // don't mislabel it Ambiguous (it is already flagged `partial`), per the
                // contract noted where `bio_conn_changed` is computed above.
                if !bio_conn_changed {
                    p.ambiguous = true;
                }
                self.build_op(key, &p, RespFacts::default())
            }
        });
        self.ops.entry(key).or_default().open = Some(new);

        // Leak guard (a missed close): bound `ops` like the other maps, evicting the
        // LEAST-RECENTLY-ACTIVE connections (never the one we just touched) — a leaked
        // entry's last_ts stays old, so live in-flight ops are spared. Steady state is
        // bounded by on_close cleanup; this only fires on a leak, and then reclaims a
        // batch (EVICT_BATCH_DIVISOR) so a pinned map doesn't scan on every request.
        if self.ops.len() > self.max_open {
            let target = evict_target(self.ops.len(), self.max_open);
            // Oldest first, so the flushed ops come out in the same order a repeated
            // single-victim eviction produced.
            for victim in oldest_keys(&self.ops, target, |v| v.last_ts, |&k| k == key) {
                // Flush, don't bare-remove: a leaked-but-still-in-flight op must be
                // emitted as an aborted op (no final response) rather than vanish — the
                // abort contract, same as on_close and the fd_links eviction above
                // (review L8). The victim key still resolves via fd_links, so the op
                // joins to its connection before the slot is reclaimed.
                self.flush_and_drop_op(victim);
            }
        }
        flushed
    }

    /// A captured SSL_read plaintext head (E5). If it's an HTTP status line it
    /// CLOSES the connection's open operation and returns the finished `Operation`.
    /// None if no op is open (we missed the request) or it isn't a status line.
    ///
    /// One exception outranks the parse: when the op at this key is still short of a
    /// Content-Length it already declared, the bytes are counted as that BODY and never
    /// read as a head (see the `awaiting_body` guard below).
    pub fn on_tls_read(&mut self, e: &EvtTlsData) -> Option<Operation> {
        let data = e.captured();
        let key = (e.hdr.tgid, e.fd);
        // BIO-fallback safety guard: with fd==0 the op-slot key (tgid,0) can't distinguish
        // concurrent BIO connections, so a read must pair only with an open op on the SAME
        // connection. If this read's tid-inferred cookie disagrees with the open op's, DON'T
        // pair (return None → the op stays open, flushed partial at close) rather than
        // mis-join a response to the wrong live connection. No-op for single-connection
        // clients (read and write resolve the same cookie), which covers the driven tools.
        // Runs before everything below, including the body tally, so a foreign connection's
        // read can neither close nor feed this slot's op.
        if e.fd == 0 && e.hdr.sock_cookie != 0 {
            if let Some(open_cookie) =
                self.ops.get(&key).and_then(|c| c.open.as_ref()).and_then(|o| o.cookie)
            {
                if open_cookie != e.hdr.sock_cookie {
                    return None;
                }
            }
        }
        // A DECLARED Content-Length is authoritative until it is met. The kernel routes a
        // read here purely on a 7-byte `HTTP/1.` prefix (it cannot know where a body
        // starts), so an OBJECT whose first bytes are a stored HTTP response — a WARC
        // record, a saved capture, an S3 error page kept as an artifact — arrives looking
        // exactly like a response head. Re-parsing it as one would close the still-open op
        // with the OBJECT's status and length: a 5 GB GET declaring
        // `Content-Length: 5368709120` gets overwritten by an embedded
        // `HTTP/1.1 503 ... Content-Length: 12`, whose 12 bytes are all present, so the
        // "whole body arrived with the head" path takes `c.open` and DISCARDS the real
        // RespState. The op ships as a 12-byte 503 that downloaded instantly and every
        // later chunk of the real object is dropped. While the op is awaiting a body these
        // bytes ARE that body, whatever they spell, so tally them and say nothing about
        // their content. (Checked before the parse, too: an unparseable head-looking chunk
        // must still count toward the target rather than vanish.)
        let awaiting_body = self
            .ops
            .get(&key)
            .and_then(|c| c.open.as_ref())
            .and_then(|o| o.resp.as_ref())
            .is_some_and(|rs| rs.body_seen < rs.body_target);
        if awaiting_body {
            return self.tally_body(key, e.hdr.ts_ns, e.plaintext_len);
        }
        let status = http::parse_status(data)?;
        // Ignore 1xx INTERIM responses (e.g. "100 Continue" — boto3/aws-cli send
        // Expect: 100-continue on PUT/UploadPart by default). They are NOT the final
        // response: closing the op here would record status=100 and then drop the
        // real 2xx/4xx. Keep the op open for the real status; just refresh activity.
        if (100..=199).contains(&status) {
            if let Some(c) = self.ops.get_mut(&key) {
                c.last_ts = e.hdr.ts_ns;
                // The FIRST interim is the op's first response byte -> ttfb measures
                // to here, so a 100-continue PUT's ttfb is the request->go-ahead RTT,
                // NOT request->post-upload-200 (which would fold in the body upload).
                if let Some(open) = c.open.as_mut() {
                    open.interim_ts.get_or_insert(e.hdr.ts_ns);
                }
            }
            return None;
        }
        let aws_request_id = http::header_value(data, "x-amz-request-id").map(str::to_string);
        let content_length = http::content_length(data);
        let header_end = http::header_end(data);
        // `captured_truncated` only means the ~4KB plaintext buffer overflowed — for any
        // response bigger than the buffer that's the BODY spilling past the head, NOT a cut
        // head. The response head is trustworthy iff we saw its terminator (`header_end`),
        // so only call it truncated when we dropped bytes AND never saw the head end. Else
        // every object larger than the capture buffer would read `partial` and be excluded
        // from latency/tail judgement (live-validated: a 64KiB GET marked all-ops-partial).
        let resp_head_truncated = e.captured_truncated != 0 && header_end.is_none();
        // Will a measurable body follow this head? Only with a known Content-Length > 0,
        // not a HEAD request, not a bodyless status, and a head we saw in full (so we
        // know where the body starts). Otherwise (chunked / no CL / HEAD / 204 / 304 /
        // truncated head) we can't tally — finalize at the head, download/total None,
        // exactly as before.
        let verb_is_head = self
            .ops
            .get(&key)
            .and_then(|c| c.open.as_ref())
            .is_some_and(|o| o.verb.eq_ignore_ascii_case("HEAD"));
        let expects_body = content_length.is_some_and(|n| n > 0)
            && !verb_is_head
            && !matches!(status, 204 | 304)
            && header_end.is_some();

        if expects_body {
            let body_target = content_length.unwrap();
            // Body bytes that already coalesced into this head read.
            let body_in_head =
                u64::from(e.plaintext_len).saturating_sub(header_end.unwrap() as u64);
            if body_in_head < body_target {
                // Defer: keep the op open, accumulate EVT_TLS_READ_BODY toward the target.
                if let Some(c) = self.ops.get_mut(&key) {
                    c.last_ts = e.hdr.ts_ns;
                    if let Some(open) = c.open.as_mut() {
                        open.resp = Some(RespState {
                            head_ts: e.hdr.ts_ns,
                            status,
                            aws_request_id,
                            op_bytes_recv: u64::from(e.plaintext_len),
                            resp_truncated: resp_head_truncated,
                            body_target,
                            body_seen: body_in_head,
                        });
                    }
                }
                return None;
            }
            // The whole body arrived with the head — complete immediately.
            let open = {
                let c = self.ops.get_mut(&key)?;
                c.last_ts = e.hdr.ts_ns;
                c.open.take()?
            };
            return Some(self.build_op(
                key,
                &open,
                RespFacts {
                    status: Some(status),
                    aws_request_id,
                    op_bytes_recv: u64::from(e.plaintext_len),
                    truncated: resp_head_truncated,
                    ts_ns: Some(e.hdr.ts_ns),
                    body_complete_ts: Some(e.hdr.ts_ns), // body coalesced into the head read
                    content_length, // = body_target (a known, > 0 Content-Length)
                },
            ));
        }

        // No measurable body — finalize at the head (download/total None), as before.
        let open = {
            let c = self.ops.get_mut(&key)?;
            c.last_ts = e.hdr.ts_ns; // keep an active keep-alive connection recent
            c.open.take()?
        };
        Some(self.build_op(
            key,
            &open,
            RespFacts {
                status: Some(status),
                aws_request_id,
                op_bytes_recv: u64::from(e.plaintext_len),
                truncated: resp_head_truncated,
                ts_ns: Some(e.hdr.ts_ns), // -> ttfb = response head minus request write
                body_complete_ts: None,
                content_length, // declared size if present (HEAD/chunked/204/304 -> None)
            },
        ))
    }

    /// A length-only response BODY read (EVT_TLS_READ_BODY). Accumulates toward the
    /// op's Content-Length; when the body is fully observed, emits the op with
    /// download_ns/total_ns. None until then (or if no op on this fd is awaiting a
    /// body). No object bytes are involved — the kernel sent only the length, in the
    /// 40-byte `EvtTlsBody` (this is the highest-rate event in the system, so it does
    /// NOT ride the 4144-byte `EvtTlsData` the heads use).
    ///
    /// The lookup keys on `(tgid,fd)`, with an op-id-free cookie check only on the BIO
    /// (fd==0) path. Keying on `(tgid,fd)` alone is SAFE against
    /// fd-reuse: body events share the `tls_events` ring with the request write, the
    /// response head, AND `conn_id` (all on tls_events), so a stale body event from a
    /// prior connection on this fd is consumed in FIFO order BEFORE the fd-reuse
    /// `conn_id` that would rebind the slot — it can never cross that boundary to
    /// cross-tally a later op (TCP close, on the OTHER ring, is the only event that can
    /// reorder here, and it doesn't touch the body tally).
    ///
    /// That FIFO argument is WHY the body event stays on `tls_events` and gets a smaller
    /// struct instead of a ring of its own. Giving it a dedicated ring would relieve the
    /// same pressure but destroy this guarantee: body events would then be unordered
    /// against `conn_id`, and a stale one could arrive after the rebind and cross-tally
    /// into the next connection's op. Shrinking the record is the fix; a separate ring
    /// is not.
    pub fn on_tls_read_body(&mut self, e: &EvtTlsBody) -> Option<Operation> {
        let key = (e.hdr.tgid, e.fd);
        // BIO-fallback safety guard, identical to `on_tls_read`'s and load-bearing for the
        // same reason: with fd==0 the (tgid,0) slot is shared by every concurrent BIO
        // connection in the process, so a body chunk must only be tallied against an open op
        // on the SAME connection. Without it, connection B's chunks accumulate into
        // connection A's `body_seen`, cross A's `body_target` early, and emit A with a
        // download_ns/total_ns measured to B's chunk timestamp and a content_length A never
        // received — wrong data, not under-capture. The kernel stamps the tid-inferred cookie
        // on the body event's `hdr.sock_cookie` (emit_tls_len), so there is something to
        // compare. Dropping the chunk leaves the op open, flushed partial at close.
        // No-op for single-connection clients and for the fd path (fd != 0), which cover
        // every driven tool.
        if e.fd == 0 && e.hdr.sock_cookie != 0 {
            if let Some(open_cookie) =
                self.ops.get(&key).and_then(|c| c.open.as_ref()).and_then(|o| o.cookie)
            {
                if open_cookie != e.hdr.sock_cookie {
                    return None;
                }
            }
        }
        self.tally_body(key, e.hdr.ts_ns, e.plaintext_len)
    }

    /// Add `len` plaintext bytes to the op at `key` as response BODY, emitting the finished
    /// operation once the declared `Content-Length` is met (and `None` until then, or when
    /// no op there is awaiting a body). Shared by the length-only body events and by
    /// `on_tls_read`'s "these head-looking bytes are actually body" path, so both count into
    /// one tally and complete on identical terms. Callers own the BIO cookie guard: this
    /// takes the slot's ownership as already settled.
    fn tally_body(&mut self, key: (u32, u32), ts_ns: u64, len: u32) -> Option<Operation> {
        let open = {
            let c = self.ops.get_mut(&key)?;
            c.last_ts = ts_ns;
            let rs = c.open.as_mut().and_then(|o| o.resp.as_mut())?;
            rs.body_seen = rs.body_seen.saturating_add(u64::from(len));
            if rs.body_seen < rs.body_target {
                return None; // more body to come
            }
            c.open.take()? // body complete — take the op to emit it
        };
        let rs = open.resp.as_ref()?;
        Some(self.build_op(
            key,
            &open,
            RespFacts {
                status: Some(rs.status),
                aws_request_id: rs.aws_request_id.clone(),
                op_bytes_recv: rs.op_bytes_recv,
                truncated: rs.resp_truncated,
                ts_ns: Some(rs.head_ts),
                body_complete_ts: Some(ts_ns),
                content_length: Some(rs.body_target), // tallied body completed at this size
            },
        ))
    }

    /// Map a periodic in-flight TCP sample (EVT_TCP_SAMPLE) to a `TcpSample` record.
    /// Stateless: emitted on the cookie ALONE — NO live-`conns` requirement. Samples
    /// ride their own ring with no inter-ring ordering guarantee vs connect/close, so
    /// gating on `conns` would drop the first (pre-connect) and last (post-close)
    /// samples. The kernel already gated scope; the doctor joins by (obscured) cookie.
    /// 0/sentinel -> None mirrors `on_close` (srtt/delivery_rate 0; min_rtt 0 or U32_MAX).
    pub fn on_tcp_sample(&self, e: &EvtTcpSample) -> Option<TcpSample> {
        Some(TcpSample {
            ts_ns: (e.hdr.ts_ns != 0).then_some(e.hdr.ts_ns),
            sock_cookie: e.hdr.sock_cookie,
            bytes_sent: e.bytes_sent,
            bytes_recv: e.bytes_recv,
            bytes_in_flight: e.bytes_in_flight,
            snd_cwnd: e.snd_cwnd,
            rcv_wnd: e.rcv_wnd,
            snd_wnd: e.snd_wnd,
            total_retrans: e.total_retrans,
            rcv_ooopack: e.rcv_ooopack,
            lost: e.lost,
            sacked_out: e.sacked_out,
            ca_state: e.ca_state,
            rate_app_limited: e.flags & 1 != 0,
            srtt_us: (e.srtt_us != 0).then_some(e.srtt_us),
            min_rtt_us: (e.min_rtt_us != 0 && e.min_rtt_us != u32::MAX).then_some(e.min_rtt_us),
            delivery_rate_bps: (e.delivery_rate_bps != 0).then_some(e.delivery_rate_bps),
            ..Default::default()
        })
    }

    fn next_op_id(&mut self) -> String {
        self.op_counter += 1;
        format!("{:016x}", self.op_counter)
    }

    /// Drop a `(tgid,fd)` op slot that no longer belongs to its connection — on a
    /// close, an fd reuse, or a cap-eviction. Any in-flight op is flushed FIRST as an
    /// aborted op (no final response), joined to whatever connection `key` currently
    /// resolves to via `cookie_for_fd` — so callers MUST invoke this BEFORE rebinding
    /// or removing the fd link, while the OLD connection still resolves. Then the slot
    /// is removed so a later connection on the same key can't inherit its `next_seq`
    /// or its still-open op (review H1/M1-M4/L8). The single chokepoint that keeps the
    /// `ops` map from outliving the fd links it is joined through.
    fn flush_and_drop_op(&mut self, key: (u32, u32)) {
        if let Some(open) = self.ops.get_mut(&key).and_then(|c| c.open.take()) {
            // If the response head was seen (body just didn't finish), keep its status;
            // else it's a true abort (no response observed).
            let facts = resp_facts_on_flush(&open).unwrap_or_default();
            let flushed = self.build_op(key, &open, facts);
            self.flushed_ops.push(flushed);
        }
        self.ops.remove(&key);
    }

    /// Assemble an `Operation` from an open op + its response, joining the
    /// connection facts (cookie, app, SNI-derived bucket) via `cookie_for_fd`.
    fn build_op(&self, key: (u32, u32), op: &OpenOp, resp: RespFacts) -> Operation {
        // Prefer the op's BIO-fallback cookie (set at open when fd==0); else resolve the fd
        // path late via cookie_for_fd (a CONN_ID may have arrived after the op opened).
        let cookie = op.cookie.or_else(|| self.cookie_for_fd(key.0, key.1));
        let conn = cookie.and_then(|c| self.conns.get(&c));
        let sni = cookie.and_then(|c| self.tls.get(&c)).map(|t| t.sni.as_str());
        // Bucket: the connection's SNI first (the virtual-hosted name the client
        // actually requested), else the bucket resolved from the request (Host
        // subdomain, or the path-style first segment).
        let bucket = sni
            .and_then(http::bucket_from_host)
            .map(str::to_string)
            .or_else(|| op.bucket.clone());
        // req_seq 0 is the first op (paid connect+handshake); later ops reused it.
        let connection_reused = op.req_seq > 0;
        // Latency breakdown (M3.5). PHASE HONESTY: the setup phases (dns, connect)
        // belong ONLY to the first op — a reused connection resolved + connected
        // earlier, so its later ops report None (not a misleading repeat or 0). The
        // DNS block is the same one the connection record carries: join the conn's
        // resolved IP to any resolution we saw, gated by the connect time. ttfb is
        // op-local (request→response head), so it survives even a partial join.
        // dns=None covers BOTH a reused op (resolved earlier) and a first op whose
        // connect was DNS-bypassed (IP-literal / no resolution seen) — the
        // `connection_reused` flag disambiguates the two for a consumer.
        let dns = if connection_reused {
            None
        } else {
            conn.and_then(|c| {
                let (ip, _) = classify_endpoint(c.family, &c.daddr);
                // Same inputs as the Connection record's dns block (on_close), so the
                // first op's block is byte-identical to its connection's — they join.
                self.dns_for_ip(ip, c.ts_ns).0
            })
        };
        // ttfb = request-head write -> FIRST response byte. An interim 1xx (100
        // Continue) is that first byte when present, so a 100-continue PUT measures
        // request->go-ahead (excludes the body upload), staying comparable to a GET's
        // request->200-head. Falls back to the final response when no interim was seen.
        let first_resp_ts = op.interim_ts.or(resp.ts_ns);
        let ttfb_ns = first_resp_ts
            .map(|t| t.saturating_sub(op.ts_ns))
            .filter(|&n| n != 0); // 0 == clock skew / reorder, not a real RTT
        // download = response head -> last body byte; total = request write -> last
        // body byte. Both only when the body completion was observed (Content-Length
        // tally, M3.5). download can legitimately be 0 (body coalesced into the head
        // read), so it is NOT 0-filtered — unlike ttfb, a 0 here is a real measurement.
        let download_ns = match (resp.ts_ns, resp.body_complete_ts) {
            (Some(head), Some(done)) => Some(done.saturating_sub(head)),
            _ => None,
        };
        let total_ns = resp.body_complete_ts.map(|done| done.saturating_sub(op.ts_ns));
        Operation {
            schema: SchemaTag,
            emitted_at: None, // stamped by the emitter
            op_id: op.op_id.clone(),
            ts_ns: Some(op.ts_ns),
            sock_cookie: cookie.unwrap_or(0),
            req_seq: op.req_seq,
            app: App { pid: conn.map_or(key.0, |c| c.pid) },
            verb: Some(op.verb.clone()),
            s3_op: op.s3_op.clone(),
            bucket,
            key_hash: op.key_hash.clone(),
            dns,
            // Only the first op paid for connect; a reused conn's op has none.
            tcp_connect_ns: if connection_reused {
                None
            } else {
                conn.map(|c| c.connect_latency_ns).filter(|&n| n != 0)
            },
            tls_handshake_ns: None, // a send-side ClientHello hook can't time the handshake
            tls_version: None,      // negotiated version not surfaced (needs supported_versions)
            ttfb_ns,
            download_ns, // response-head -> last body byte (Content-Length tally), else None
            total_ns,    // request write -> last body byte, else None
            content_length: resp.content_length, // declared body/object size; pair w/ download_ns
            // CAVEAT: these are the HEAD write/read plaintext_len — the full request
            // for bodyless ops (GET/HEAD/DELETE/List), but only the HEADER bytes for a
            // PUT/POST, since the kernel head-gate drops the body writes/reads (they
            // don't begin with a method / "HTTP/1."). NOT the object size. (Object
            // byte accounting would need a kernel per-op tally — a future ABI change.)
            op_bytes_sent: Some(op.op_bytes_sent),
            op_bytes_recv: Some(resp.op_bytes_recv),
            // Connection-cumulative counters are read at CLOSE; unknown at op time. This op is
            // being emitted BECAUSE its response completed, with the socket still open, so
            // there is nothing to join to yet: the values the consumer wants land later, on
            // this connection's own `s3tap.connection/2` record, which shares `sock_cookie`.
            // Deferring the op until close is not an option (a pooled connection may live for
            // the whole process, and the point of the op record is to stream).
            //
            // So these are CONSTANTS, not measurements, and the schema says so field by field.
            // `pinned_connection_counters_are_a_documented_placeholder` pins them: if a future
            // slice ever populates them, that test fails and the schema comment plus
            // book/src/reference/records.md have to be corrected in the same change.
            bytes_sent: 0,
            bytes_recv: 0,
            retransmits: 0,
            srtt_us: None,
            lifetime_ns: None,
            connection_reused,
            http_status: resp.status,
            aws_request_id: resp.aws_request_id,
            // partial when the connection facts couldn't be joined OR a head was
            // truncated (Host/headers may have been cut) — don't advertise a
            // possibly-incomplete parse as clean. NB: gate on `conn`, not `cookie`:
            // a conn_id can map the fd (cookie resolves) while the connect event is
            // still unfolded — dropped, cap-evicted, or cross-ring-reordered behind
            // the plaintext (conn_id rides tls_events, connect rides events). In that
            // window `dns`/`tcp_connect_ns`/the SNI-bucket all silently go None, so
            // the op must be flagged partial, never shipped as clean-with-no-setup.
            partial: conn.is_none() || op.head_truncated || resp.truncated,
            delimitation: if op.ambiguous {
                Delimitation::Ambiguous
            } else {
                Delimitation::Clean
            },
        }
    }

    /// Build the `dns` block (and the S3 region) for a connection's resolved IP.
    /// The IP -> hostname link comes from the wire response; `getaddrinfo`, when
    /// we saw one for that hostname, supplies the latency the app actually paid.
    ///
    /// Best-effort, by design: the `resolutions` map is keyed by IP only, with no
    /// TTL expiry and last-writer-wins. We deliberately do NOT drop a connection's
    /// label once `ttl_s` elapses — the common S3 pattern is resolve-once then
    /// reuse the address (connection pools, long-lived SDK clients) for the whole
    /// process lifetime, well past the record TTL, with no re-resolution to
    /// observe; expiring would strip the label from exactly those connections.
    /// The trade-off: if two hostnames resolve to the same IP, the most recent
    /// resolution wins, so a shared/anycast IP can carry the wrong name (and thus
    /// a confidently-wrong `region`). `ttl_s` is surfaced in the record so a
    /// consumer can judge staleness itself. `conn_ts` is the connection's SYN
    /// start, used to avoid decorating it with a *later* resolver call.
    fn dns_for_ip(&self, ip: IpAddr, conn_ts: u64) -> (Option<Dns>, Option<String>) {
        let Some(res) = self.resolutions.get(&ip) else {
            return (None, None);
        };
        let region = aws_region_from_host(&res.hostname);
        // Prefer the getaddrinfo-measured latency only if that call happened
        // before this connection — the `gai` map is last-writer-wins per host, so
        // without the `g.ts <= conn_ts` guard a later, unrelated resolver call
        // (e.g. a cache hit long after this connection's wire miss) would be
        // attributed to it. If the relevant call was overwritten we fall back to
        // the wire latency, which is honest rather than wrong.
        let (latency_ns, via, cache_hit) = match self.gai.get(&res.hostname) {
            Some(g) if g.ts <= conn_ts => (g.latency_ns, "getaddrinfo", g.cache_hit),
            _ => (res.wire_latency_ns, "wire", false),
        };
        let dns = Dns {
            latency_ns,
            cache_hit,
            resolved_ip: Some(ip.to_string()),
            n_answers: res.n_answers,
            ttl_s: res.ttl_s,
            via: via.to_string(),
        };
        (Some(dns), region)
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a length-prefixed, non-NUL-terminated name field into an owned String,
/// canonicalized (lowercased, trailing dot stripped). None if the bytes aren't
/// valid UTF-8 or the name is empty after canonicalization.
///
/// Two canonicalizations, because both the wire qname and the getaddrinfo node
/// string pass through here and are later compared with `==` / used as map keys:
///   - case: DNS is case-insensitive (RFC 4343) but the wire keeps the app's /
///     0x20-randomizer's case, so `curl https://S3.US-EAST-1.amazonaws.com` would
///     otherwise break the join and the region parse.
///   - trailing dot: a fully-qualified `getaddrinfo("host.com.")` yields a dotted
///     node string, but the in-kernel decoder stops at the root label so the wire
///     qname is never dotted — mismatching sides drop the gai latency / flip
///     cache_hit. Strip it so both sides are canonical.
///
/// ASCII-only by design: DNS names on the wire are ASCII (IDNs are punycode).
fn qname_str(buf: &[u8], len: u8) -> Option<String> {
    let len = (len as usize).min(buf.len());
    if len == 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..len]).ok()?;
    let s = s.trim_end_matches('.').to_ascii_lowercase();
    // SECURITY: this name is attacker-controlled (any local process crafts its own
    // ClientHello SNI / DNS query) and `tls.sni` is shipped verbatim in the jsonl
    // record. serde_json escapes it for JSON, but a downstream `jq -r`/grep/journald
    // consumer would see raw bytes — a control char, ANSI escape, or embedded newline
    // could rewrite a terminal or forge a log line (CWE-117). A real hostname on the
    // wire is LDH + dots + the leading `_` used by service labels, so reject anything
    // else: an honest dropped name (seen=false) over a poisoned one — same stance as
    // the truncation guard in `on_tls_handshake`.
    let host_legal = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_');
    if s.is_empty() || !s.bytes().all(|b| host_legal(&b)) {
        return None; // empty (was only ".") or non-hostname bytes
    }
    Some(s)
}

/// Advance past a DNS name in `buf` starting at `off`, returning the offset just
/// past it. A trailing compression pointer (the common answer case) ends the
/// name in 2 bytes; we do NOT follow it (we only need to skip the name). None if
/// the name runs off the end. Bounded to 128 labels.
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    for _ in 0..128 {
        let b = *buf.get(off)?;
        if b == 0 {
            return Some(off + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(off + 2); // 2-byte pointer ends the name
        }
        off = off.checked_add(b as usize + 1)?;
    }
    None
}

/// A resolved address and its TTL, as parsed from a DNS answer.
type Answer = (IpAddr, Option<u32>);

/// Parse a raw DNS response: return its transaction id, the first question's name
/// (for response↔query verification, review Gap F — None if absent/undecodable), and
/// the resolved A/AAAA addresses (with TTLs). Lenient — stops at the first malformed
/// record and returns what it has. AAAA v4-mapped addresses are normalized to IPv4
/// (the [`classify_endpoint`] convention) so they match a connection's daddr.
fn parse_dns_response(payload: &[u8]) -> Option<(u16, Option<String>, Vec<Answer>)> {
    if payload.len() < 12 {
        return None;
    }
    let txn_id = u16::from_be_bytes([payload[0], payload[1]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    // The first question's name (immediately after the 12-byte header), canonicalized
    // to match the stored query's qname. Best-effort — None when there's no question.
    let qname = (qdcount >= 1).then(|| read_qname(payload, 12)).flatten();

    let mut off = 12;
    for _ in 0..qdcount.min(64) {
        match skip_name(payload, off) {
            Some(o) => off = o + 4, // qtype(2) + qclass(2)
            None => return Some((txn_id, qname, Vec::new())),
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount.min(64) {
        let Some(o) = skip_name(payload, off) else { break };
        off = o;
        if off + 10 > payload.len() {
            break;
        }
        let rtype = u16::from_be_bytes([payload[off], payload[off + 1]]);
        let ttl = u32::from_be_bytes([payload[off + 4], payload[off + 5], payload[off + 6], payload[off + 7]]);
        let rdlen = u16::from_be_bytes([payload[off + 8], payload[off + 9]]) as usize;
        off += 10; // type(2) class(2) ttl(4) rdlen(2)
        if off + rdlen > payload.len() {
            break;
        }
        match (rtype, rdlen) {
            (1, 4) => {
                let ip = IpAddr::V4(Ipv4Addr::new(payload[off], payload[off + 1], payload[off + 2], payload[off + 3]));
                answers.push((ip, Some(ttl)));
            }
            (28, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&payload[off..off + 16]);
                let v6 = Ipv6Addr::from(b);
                let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
                answers.push((ip, Some(ttl)));
            }
            _ => {} // CNAME and others: skip the rdata
        }
        off += rdlen;
    }
    Some((txn_id, qname, answers))
}

/// Decode the question-section QNAME at `off` into a canonical lowercased string (no
/// trailing dot), to match a response against its pending query (review Gap F). The
/// same canonicalization as [`qname_str`] (lowercase) so a 0x20-case-randomized query
/// still matches. Question names aren't compressed; a pointer is treated as
/// end-of-name defensively. None if it runs off the end or decodes empty.
fn read_qname(buf: &[u8], mut off: usize) -> Option<String> {
    let mut out = String::new();
    for _ in 0..128 {
        let len = *buf.get(off)? as usize;
        if len == 0 || len & 0xC0 == 0xC0 {
            break; // root label, or a compression pointer (questions aren't compressed)
        }
        off += 1;
        let label = buf.get(off..off + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        off += len;
    }
    if out.is_empty() {
        return None;
    }
    Some(out.to_ascii_lowercase())
}

/// Extract the AWS region from an S3-style hostname, e.g.
/// `b.s3.us-east-1.amazonaws.com` -> `us-east-1`, `s3-eu-west-1.amazonaws.com`
/// -> `eu-west-1`, and the regionless `s3.amazonaws.com` -> `us-east-1`. None
/// for any non-`amazonaws.com` host. Conservative: only well-formed regions.
///
/// STANDARD partition only: the isolated China partition (`*.amazonaws.com.cn`,
/// regions `cn-north-1`/`cn-northwest-1`) ends in `.cn`, fails the suffix gate, and
/// yields `None` — a known limitation (China uses separate accounts/credentials), not a
/// misparse. GovCloud (`us-gov-*`) rides the ordinary `.amazonaws.com` suffix and works.
fn aws_region_from_host(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    if !host.ends_with(".amazonaws.com") && host != "amazonaws.com" {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let mut saw_s3 = false;
    for (i, label) in labels.iter().enumerate() {
        // Legacy dash form: s3-<region>.amazonaws.com. Only when this label is in the
        // ENDPOINT position (immediately before `amazonaws`), so a virtual-hosted bucket
        // literally named `s3-<region>` — e.g. s3-eu-west-1.s3.amazonaws.com — doesn't
        // hijack the parse; that must resolve via the `s3` anchor below (us-east-1), the
        // same anchoring the exact-`s3` branch relies on.
        if labels.get(i + 1) == Some(&"amazonaws") {
            if let Some(rest) = label.strip_prefix("s3-") {
                if looks_like_region(rest) {
                    return Some(rest.to_string());
                }
            }
        }
        // The region is the next region-shaped label after `s3`, skipping an
        // optional `dualstack` (s3.dualstack.<region>...). Anchoring on `s3`
        // (rather than scanning every label) means a bucket NAMED like a region
        // — e.g. eu-west-1.s3.amazonaws.com — is correctly read as the regionless
        // global endpoint (us-east-1), not "eu-west-1".
        if *label == "s3" {
            saw_s3 = true;
            let mut j = i + 1;
            if labels.get(j) == Some(&"dualstack") {
                j += 1;
            }
            if let Some(next) = labels.get(j) {
                if looks_like_region(next) {
                    return Some((*next).to_string());
                }
            }
            // This `s3` is not followed by a region — keep scanning for a LATER
            // `s3` anchor before defaulting, so a bucket literally named `s3` (or
            // `dualstack`) doesn't short-circuit the real endpoint: e.g.
            // s3.s3.eu-west-1.amazonaws.com must read as eu-west-1, not us-east-1.
        }
    }
    // An `s3` host with no region-shaped label anywhere is the global endpoint.
    saw_s3.then(|| "us-east-1".to_string())
}

/// A loose AWS-region shape check: `xx-word(-word)-N`, e.g. `us-east-1`,
/// `ap-southeast-2`, and the 4-part GovCloud form `us-gov-east-1`.
fn looks_like_region(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let (Some(first), Some(last)) = (parts.first(), parts.last()) else {
        return false;
    };
    (3..=4).contains(&parts.len())
        && first.len() == 2
        && first.chars().all(|c| c.is_ascii_lowercase())
        && !last.is_empty()
        && last.chars().all(|c| c.is_ascii_digit())
        && parts[1..parts.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
}

/// Resolve the endpoint's IP and address-family label together so they can't
/// disagree. For AF_INET the IPv4 octets live in bytes [12..16]. For AF_INET6 a
/// v4-mapped address (::ffff:a.b.c.d — common on dual-stack sockets) is really
/// IPv4 traffic, so we normalize it to v4 and label it "inet" — otherwise the
/// family signal can't separate IPv6 from IPv4 (it grounds Happy-Eyeballs /
/// per-family analysis).
fn classify_endpoint(family: u8, addr: &[u8; 16]) -> (IpAddr, &'static str) {
    if family == AF_INET {
        return (
            IpAddr::V4(Ipv4Addr::new(addr[12], addr[13], addr[14], addr[15])),
            "inet",
        );
    }
    let v6 = Ipv6Addr::from(*addr);
    match v6.to_ipv4_mapped() {
        Some(v4) => (IpAddr::V4(v4), "inet"),
        None => (IpAddr::V6(v6), "inet6"),
    }
}

#[cfg(test)]
mod region_tests {
    use super::{aws_region_from_host, looks_like_region};

    #[test]
    fn looks_like_region_boundaries() {
        // Accept: 2-char first label, 3-4 dash parts, digit-last (incl. >1 digit).
        for ok in ["us-east-1", "ap-southeast-2", "us-gov-east-1", "eu-west-12"] {
            assert!(looks_like_region(ok), "{ok} should be region-shaped");
        }
        // Reject: 1-char first label, 5 parts, non-digit last, empty middle, non-lc.
        for bad in [
            "u-east-1",        // first label not 2 chars
            "us-too-long-east-1", // 5 parts
            "us-east-x",       // last not a digit
            "us--1",           // empty middle part
            "US-east-1",       // uppercase
            "useast1",         // no dashes
        ] {
            assert!(!looks_like_region(bad), "{bad} should NOT be region-shaped");
        }
    }

    #[test]
    fn aws_region_from_host_direct() {
        // Direct (no connect/close drive): isolate the parser from the DNS path.
        let cases = [
            ("s3.amazonaws.com", Some("us-east-1")),
            ("b.s3.eu-west-1.amazonaws.com", Some("eu-west-1")),
            ("s3-ap-southeast-1.amazonaws.com", Some("ap-southeast-1")),
            ("s3.dualstack.us-gov-east-1.amazonaws.com", Some("us-gov-east-1")),
            ("s3.s3.eu-west-1.amazonaws.com", Some("eu-west-1")), // bucket named `s3`
            ("eu-west-1.s3.amazonaws.com", Some("us-east-1")),    // bucket named like a region
            // bucket literally named `s3-<region>` on the global endpoint must NOT hijack the
            // parse — the dash form only anchors in endpoint position (before `amazonaws`).
            ("s3-eu-west-1.s3.amazonaws.com", Some("us-east-1")),
            // …but a legit virtual-hosted bucket on the legacy dash endpoint still resolves.
            ("mybucket.s3-ap-southeast-1.amazonaws.com", Some("ap-southeast-1")),
            ("s3-mybucket.amazonaws.com", None),                  // s3- prefix, not a region
            ("example.com", None),                                // non-AWS
            ("ec2.us-west-2.amazonaws.com", None),                // AWS but no s3 anchor
        ];
        for (host, want) in cases {
            assert_eq!(aws_region_from_host(host).as_deref(), want, "host {host}");
        }
    }
}

#[cfg(test)]
mod sample_tests {
    use super::Correlator;
    use s3tap_events::EvtTcpSample;

    #[test]
    fn on_tcp_sample_maps_fields_and_sentinels() {
        let c = Correlator::new();
        // 0 / U32_MAX sentinels -> None; flags bit0 -> rate_app_limited true.
        let mut e = EvtTcpSample {
            bytes_recv: 1_000_000,
            snd_cwnd: 32,
            srtt_us: 0,
            min_rtt_us: u32::MAX,
            delivery_rate_bps: 0,
            flags: 1,
            ..Default::default()
        };
        e.hdr.sock_cookie = 0xdead;
        e.hdr.ts_ns = 1_000;
        let s = c.on_tcp_sample(&e).expect("sample maps");
        assert_eq!(s.sock_cookie, 0xdead);
        assert_eq!(s.ts_ns, Some(1_000));
        assert_eq!(s.bytes_recv, 1_000_000);
        assert_eq!(s.snd_cwnd, 32);
        assert_eq!(s.srtt_us, None);
        assert_eq!(s.min_rtt_us, None);
        assert_eq!(s.delivery_rate_bps, None);
        assert!(s.rate_app_limited);

        // Real samples survive; flags bit0 clear -> false.
        let e2 = EvtTcpSample {
            min_rtt_us: 15_000,
            srtt_us: 30_000,
            delivery_rate_bps: 98_000_000,
            flags: 0,
            ..Default::default()
        };
        let s2 = c.on_tcp_sample(&e2).expect("maps");
        assert_eq!(s2.min_rtt_us, Some(15_000));
        assert_eq!(s2.srtt_us, Some(30_000));
        assert_eq!(s2.delivery_rate_bps, Some(98_000_000));
        assert!(!s2.rate_app_limited);
    }
}

#[cfg(test)]
mod salt_tests {
    use super::{evict_target, random_salt_from, ENTROPY_SOURCES, EVICT_BATCH_DIVISOR};

    #[test]
    fn missing_entropy_source_is_a_hard_error_not_a_clock_fallback() {
        // The old code silently substituted (nanos ^ pid) here, which is guessable from the
        // capture's own `emitted_at` + `app.pid`. There must be no fallback left: an
        // unreadable source has to abort the run.
        let err = random_salt_from(&["/nonexistent/s3tap/urandom"])
            .expect_err("no entropy source must fail, never fall back to the clock");
        let msg = err.to_string();
        assert!(msg.contains("entropy"), "actionable message: {msg}");
        assert!(msg.contains("/nonexistent/s3tap/urandom"), "names what it tried: {msg}");
    }

    #[test]
    fn short_entropy_source_is_a_hard_error() {
        // A source that yields fewer than 16 bytes must fail rather than hand back a salt
        // whose tail is zero (the exact shape of the old fallback's dead high bytes).
        let path = std::env::temp_dir().join(format!("s3tap-salt-short-{}", std::process::id()));
        std::fs::write(&path, b"1234").expect("write short source");
        let got = random_salt_from(&[path.to_str().expect("utf8 temp path")]);
        let _ = std::fs::remove_file(&path);
        assert!(got.is_err(), "a short read must not produce a partially-zeroed salt");
    }

    #[test]
    fn real_entropy_source_yields_a_fresh_unpredictable_salt() {
        let a = random_salt_from(&ENTROPY_SOURCES).expect("/dev/urandom readable in test env");
        let b = random_salt_from(&ENTROPY_SOURCES).expect("/dev/urandom readable in test env");
        assert_ne!(a, b, "two reads must not repeat (a 1-in-2^128 flake is not a real risk)");
        assert_ne!(a, [0u8; 16], "all-zero salt");
        // The old fallback packed a u128 whose top 8 bytes were ALWAYS zero. Real entropy
        // fills them (each read has a ~1-in-2^64 chance of looking like the weak form).
        assert!(a[8..] != [0u8; 8] || b[8..] != [0u8; 8], "high bytes look like the weak fallback");
    }

    #[test]
    fn eviction_target_is_a_batch_not_a_single_entry() {
        // At the default cap one pass must reclaim ~10% so the following inserts skip the
        // scan entirely; a tiny cap still evicts exactly the one entry it is over by.
        assert_eq!(evict_target(65_537, 65_536), 65_536 / EVICT_BATCH_DIVISOR);
        assert_eq!(evict_target(3, 2), 1, "small caps keep single-victim behaviour");
        assert_eq!(evict_target(2, 1), 1);
        // A burst insert (one DNS response carries up to 64 answers) is cleared in one pass,
        // and never leaves the map above cap.
        assert_eq!(evict_target(16_384 + 63, 16_384), 16_384 / EVICT_BATCH_DIVISOR);
        assert_eq!(evict_target(11, 3), 8, "excess wins when it exceeds the batch");
    }
}
