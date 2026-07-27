// crates/s3tap-schema/src/lib.rs
//
// The public, stable contracts. External consumers
// depend ONLY on these — the raw EVT_* ABI is internal. Two records:
//   * Operation  (s3tap.operation/1)  — per S3 request; needs HTTP plaintext.
//   * Connection (s3tap.connection/2) — per socket; the degraded / socket-only
//     path. M1 has no TLS/HTTP probes, so M1 emits Connection records.
// EVOLUTION RULE (the code and the round-trip goldens encode exactly this):
//   * ADDITIVE — a new field that is `Option`/`#[serde(default)]` and whose
//     absence means "not observed" is backward-compatible and does NOT bump the
//     tag. An old consumer ignores it (serde skips unknown fields); a new
//     consumer reads an old record with the field defaulted to None. The 18
//     path-diagnosis fields on `s3tap.connection/2` landed this way.
//   * BUMPING — a rename, a removal, a field-encoding change (number → string),
//     or any change to the MEANING of an existing field bumps the tag, as `/2`
//     did (see below). An additive field must never redefine what a field that
//     shipped before it means: that is the one thing a consumer pinned to the
//     old tag cannot survive.
// Consequence a consumer must plan for: because additions do not bump, the tag
// is a COMPATIBILITY version, not a content hash. A validator generated from one
// capture's records must therefore be open (allow unknown fields), never a
// closed/strict schema, or the next additive field will make it reject every
// live record with no version signal to explain why. See the schema-tag rules on the record types below.

use serde::{Deserialize, Deserializer, Serialize};

pub const OPERATION_SCHEMA: &str = "s3tap.operation/1";
// Bumped /1 -> /2 when `lifetime_ns` changed from a JSON number to a decimal
// STRING (a nanosecond delta crosses 2^53 at ~104 days, so jq/JS would lose
// precision — same rationale as `ts_ns`/`sock_cookie`).
pub const CONNECTION_SCHEMA: &str = "s3tap.connection/2";

/// Always serializes to the constant [`OPERATION_SCHEMA`] — the tag can't be
/// set wrong or forgotten.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SchemaTag;

impl Serialize for SchemaTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(OPERATION_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for SchemaTag {
    /// Accepts only the exact [`OPERATION_SCHEMA`] string — a record tagged with a
    /// different/incompatible version is rejected, not coerced. (An ABSENT tag is also
    /// rejected: `schema` is a required, non-defaulted field, so a tagless record fails
    /// to deserialize — review step-1 #2.)
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == OPERATION_SCHEMA {
            Ok(SchemaTag)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected schema {OPERATION_SCHEMA}, got {s:?}"
            )))
        }
    }
}

/// Always serializes to the constant [`CONNECTION_SCHEMA`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnSchemaTag;

impl Serialize for ConnSchemaTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(CONNECTION_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for ConnSchemaTag {
    /// Accepts only the exact [`CONNECTION_SCHEMA`] string (see [`SchemaTag`]).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == CONNECTION_SCHEMA {
            Ok(ConnSchemaTag)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected schema {CONNECTION_SCHEMA}, got {s:?}"
            )))
        }
    }
}

/// Process attribution. M1 only knows the pid (from the event header); comm /
/// exe / cgroup / K8s enrichment arrive with EVT_PROC_EXEC in M4.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct App {
    /// The process that opened the connection. **0 means UNKNOWN**, never a real pid 0: it
    /// is what a connection whose connect s3tap never saw reports (attached mid-flight).
    /// The close event's own `hdr.tgid` is deliberately NOT a fallback. `EVT_TCP_CLOSE` is
    /// stamped wherever the socket is torn down, routinely in NET_RX softirq context, so it
    /// names an unrelated task: a mid-flight attach was published as belonging to e.g.
    /// sshd. A consumer grouping by pid must treat 0 as "unattributed".
    pub pid: u32,
}

/// Endpoint classification. M1 fills endpoint_ip/family/dport from
/// EVT_TCP_CONNECT. `region` IS derived today (SNI first, else the observed DNS resolution).
/// `via_vpce` and `cross_region` are NOT: both are written as literal `false` on every record
/// (`correlate.rs`), so a consumer must read them as "not determined", never as "no".
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Endpoint {
    pub region: Option<String>,
    pub endpoint_ip: Option<String>,
    /// "inet" | "inet6".
    pub family: Option<String>,
    pub dport: Option<u16>,
    pub via_vpce: bool,
    pub cross_region: bool,
}

/// TLS facts. `seen` is true once we observe ANY TLS signal on the connection: a
/// ClientHello carrying a usable SNI (M3), a ServerHello (negotiated `version`/`cipher`,
/// S2), or a measured `handshake_ns`. So `sni` MAY be null while `seen` is true — an
/// IP-based (SNI-less) TLS connection, an unparseable/truncated name (real SNI > 255 B),
/// or a non-hostname/non-LDH name (rejected as untrusted) yields `seen=true, sni=null`
/// if a ServerHello or handshake timing was captured, else `seen=false`. `sni` is the
/// client's requested server_name, present even when DNS was bypassed. `handshake_ns` is
/// the ClientHello→first-app-data egress duration (null if not timed); `version`/`cipher`
/// are the negotiated values parsed from the ServerHello (null if not captured).
///
/// Two protocol-evolution caveats: (1) ECH (encrypted ClientHello) — the real SNI
/// is encrypted; the cleartext `server_name` we read is then the PUBLIC cover name,
/// so `sni` may be a cover name rather than the true host. We cannot detect this on
/// the wire (the `encrypted_client_hello` extension is also sent as GREASE by Chrome
/// /Firefox on non-ECH connections, indistinguishable by design), and real ECH to S3
/// is currently nonexistent. (2) QUIC / HTTP-3 (UDP 443) is not observed — only TCP
/// ClientHellos are parsed. S3 REST is TCP-only, but CloudFront-fronted HTTP-3 yields
/// `seen=false`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tls {
    pub seen: bool,
    pub handshake_ns: Option<u64>,
    /// Negotiated TLS version, e.g. "TLS 1.3" (from the ServerHello). `None` when the
    /// ServerHello wasn't captured — the handshake-timing ratio still infers 1.3-vs-1.2.
    pub version: Option<String>,
    pub sni: Option<String>,
    /// Negotiated cipher-suite code from the ServerHello (e.g. 0x1301). Additive/optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<u16>,
}

/// DNS resolution facts (EVT_DNS_*/EVT_GETADDRINFO). Populated in M2 when the
/// connection's resolved IP matches a DNS resolution we observed; `null`
/// otherwise (no resolution seen, or we attached after it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dns {
    pub latency_ns: u64,
    pub cache_hit: bool,
    pub resolved_ip: Option<String>,
    pub n_answers: u8,
    pub ttl_s: Option<u32>,
    pub via: String,
}

/// One folded S3 operation (`s3tap.operation/1`). Field order IS the JSON order
/// — the golden test pins it. Only the M3 E5 plaintext path emits this (M1–M3 E2
/// emit `Connection`); the S3-semantic + op-byte fields are filled from M3 E5
/// onward, the latency breakdown (`dns`/`ttfb_ns`/…) from M3.5. Richer sub-blocks
/// (qualifiers/endpoint/error/retry/prefix) are deferred to M4 and not present yet.
// Forward/back-compat: serde IGNORES unknown fields (a newer
// agent's extra field) and treats a missing Option field as None (an older agent's
// not-yet-present field, e.g. content_length) — both WITHOUT a container default. The
// required, non-Option identity/core fields (schema, op_id, sock_cookie, …) are NOT
// defaulted, so a record that omits the version tag or the join key is a hard parse
// error, not a silently-accepted default-tagged / cookie-0 record (review step-1 #2).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Operation {
    pub schema: SchemaTag,
    /// RFC3339 wall-clock (UTC, millisecond precision) of the moment the AGENT wrote this
    /// record out, not of the traffic it describes — that is `ts_ns`, boot-relative
    /// monotonic. The agent's output boundary stamps it, so it is present on every shipped
    /// record and absent only on one built in-process (a test, or a record that never
    /// reached the emitter). It is the only wall clock in the pipeline: the second-order
    /// records deliberately carry none (see [`Finding::emitted_at`]), so a fleet ingest
    /// ages and orders across hosts on THIS field. The emitter should take the clock ONCE
    /// per drained batch: reading it per record splits one flush into N distinct emit
    /// times, which a consumer cannot tell from N separate flushes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_at: Option<String>,
    /// Agent-generated, unique per operation.
    pub op_id: String,
    /// CLOCK_MONOTONIC at op start. STRING (u64 > 2^53 would lose precision in
    /// jq/JS). Null when unknown.
    #[serde(default, serialize_with = "opt_u64_as_dec_string", deserialize_with = "opt_u64_from_dec_string")]
    pub ts_ns: Option<u64>,
    /// The sk-pointer join key — STRING for the same reason as `ts_ns`.
    /// SECURITY: like [`Connection::sock_cookie`], this is the raw kernel
    /// `struct sock *` pointer (KASLR signal). When M3 emits this record it MUST
    /// run the cookie through the agent's per-run obscurer (as the Connection
    /// emit path does) so shipped records carry only a stable opaque id.
    #[serde(serialize_with = "u64_as_dec_string", deserialize_with = "u64_from_dec_string")]
    pub sock_cookie: u64,
    /// 0-based index of this operation on its connection (E5 delimitation).
    pub req_seq: u32,
    pub app: App,

    // --- S3 semantics (E5; parsed from the HTTP plaintext + the SNI/Host join) ---
    /// Raw HTTP method (`GET`, `PUT`, …); null if the request head wasn't seen.
    pub verb: Option<String>,
    /// Resolved S3 operation (taxonomy), e.g. `GetObject`, `UploadPart`.
    pub s3_op: Option<String>,
    /// Bucket, from the SNI (virtual-hosted) or the `Host` header.
    pub bucket: Option<String>,
    /// `sha256:<hex>` of the object key — the key is never stored in clear.
    pub key_hash: Option<String>,

    // --- latency breakdown (M3.5; null when not applicable: a reused conn paid no
    // setup this op, or the phase wasn't observed). The waterfall the op decomposes
    // into. ---
    /// DNS resolution this op paid for — only the FIRST op on a connection (a
    /// reused connection resolved earlier); null on reuse, or when no resolution
    /// was observed for the endpoint IP. Same block shape as [`Connection::dns`].
    pub dns: Option<Dns>,
    /// SYN→ESTABLISHED — first op only (null on a reused conn / socket-only path).
    pub tcp_connect_ns: Option<u64>,
    /// TLS handshake duration — null: a send-side ClientHello hook can't time it
    /// (a later slice with a handshake-completion probe may fill it). NB while null,
    /// the handshake (1-2 RTT on a cold connection) lives UNACCOUNTED between
    /// `tcp_connect_ns` (ends at ESTABLISHED) and `ttfb_ns` (starts at request write),
    /// so the phases do not sum to the observed wall-clock on a fresh connection.
    pub tls_handshake_ns: Option<u64>,
    /// Negotiated TLS version — null (needs the `supported_versions` extension).
    pub tls_version: Option<String>,
    /// Request-head write → FIRST response byte. A 1xx interim counts as that first
    /// byte: for a PUT/UploadPart with `Expect: 100-continue` (the boto3/aws-cli
    /// default) this is the request→"100 Continue" go-ahead RTT, which deliberately
    /// EXCLUDES the body-upload time that precedes the final 2xx — so a write's ttfb
    /// stays comparable to a GET's request→200-head and isn't inflated by upload
    /// size. (That upload+commit span is `total_ns`, deferred.) The op-local
    /// round-trip; measured even on a reused or partial connection.
    pub ttfb_ns: Option<u64>,
    /// Response head → response COMPLETE (the body-download span), measured by the
    /// M3.5 length-only `Content-Length` tally. Null when not tallyable (chunked /
    /// no `Content-Length` / HEAD / 204 / 304) or the body didn't finish before close.
    ///
    /// Those two nulls mean OPPOSITE things and are distinguishable: read this field
    /// together with `content_length`.
    /// - `download_ns: null`, `content_length: null` — there was no declared length to tally
    ///   against, so no download span exists to measure. Nothing failed and nothing is
    ///   missing. Every S3 LIST lands here (`ListObjectsV2` responds chunked), as does every
    ///   HEAD / 204 / 304. The record is still `partial: false` and `delimitation: "clean"`,
    ///   because both of those describe the PARSE and the request interleaving, not the
    ///   measurement.
    /// - `download_ns: null`, `content_length: <n>` — the body size WAS declared and the
    ///   download was not seen through to it: the op was flushed when the connection closed
    ///   or the capture ended. This one is an unfinished measurement.
    ///
    /// The converse never occurs: `download_ns` is set only by the tally, so a non-null
    /// `download_ns` always comes with a non-null `content_length`.
    pub download_ns: Option<u64>,
    /// Request write → response COMPLETE (= `ttfb_ns` + `download_ns`). Same
    /// nullability as `download_ns`, including the two-null distinction documented there.
    pub total_ns: Option<u64>,
    /// Declared response-body size from the `Content-Length` header — the downloaded
    /// object size for a GET. Pair with `download_ns` for per-op GET throughput
    /// (`content_length / download_ns`). A PLAIN number (an S3 object is ≤ 5 TB, well
    /// under 2^53, so no string encoding needed).
    ///
    /// Null in FIVE distinct cases, every one of which means "no trustworthy body length"
    /// rather than "the body was empty" (see `s3tap_core::http::content_length`):
    /// 1. no `Content-Length` header at all;
    /// 2. a `Transfer-Encoding` header. Its chunked framing supersedes any declared length
    ///    (RFC 9112 6.3), so tallying to the number would end the download span mid-body;
    /// 3. duplicate `Content-Length` headers that DISAGREE, so there is no trustworthy target;
    /// 4. a value above 5 TiB, the largest object S3 stores. The header is the peer's to
    ///    choose and this field ships as a PLAIN JSON number, so the ceiling is what keeps
    ///    it under 2^53;
    /// 5. a response head that was never seen in full.
    ///
    /// MAY be set even when `download_ns` is null (a HEAD declares the size with no body to
    /// time). NOT `op_bytes_recv`, which is the response HEADER bytes, not the body.
    pub content_length: Option<u64>,

    // --- per-operation byte accounting (OpenSSL plaintext; null socket-only) ---
    pub op_bytes_sent: Option<u64>,
    pub op_bytes_recv: Option<u64>,

    // --- connection-scoped network quality: NOT MEASURED ON THIS RECORD ---
    //
    // These five are read off `tcp_sock` at CLOSE, and they are cumulative for the whole
    // connection rather than for this op. An operation record is emitted the moment its
    // response completes, with the connection still open, so at that instant the close-time
    // counters do not exist yet. s3tap therefore emits them CONSTANT on every operation
    // record: `bytes_sent`/`bytes_recv`/`retransmits` are always `0` and `srtt_us`/
    // `lifetime_ns` are always `null`. That is a placeholder, never a measurement: a `0` here
    // means "not measured on this record", NOT "zero bytes moved" or "no retransmits".
    //
    // DO NOT aggregate them. Byte volume or loss summed over operation records is zero by
    // construction and will silently read as a healthy fleet. The real values live on the
    // `s3tap.connection/2` record for the same socket: join on `sock_cookie`. For per-op byte
    // accounting use `op_bytes_sent` / `op_bytes_recv` above (with their header-only caveat).
    //
    // They are kept, at their constants, because removing them is a `/1` -> `/2` contract
    // change that would break every pinned consumer for fields that carry no information
    // either way. They are the first thing to drop whenever `s3tap.operation` next bumps.
    // (`s3tap_core::correlate::build_op` is where the constants are written, and a unit test
    // there pins them so this comment cannot quietly go stale.)
    /// ALWAYS `0` on an operation record: not measured. See the block comment above.
    pub bytes_sent: u64,
    /// ALWAYS `0` on an operation record: not measured. See the block comment above.
    pub bytes_recv: u64,
    /// ALWAYS `0` on an operation record: not measured. See the block comment above.
    pub retransmits: u32,
    /// ALWAYS `null` on an operation record: the smoothed RTT is read at close, which has not
    /// happened when this record is emitted. The floor for judging this op's latency comes
    /// from the connection record it joins to on `sock_cookie`.
    pub srtt_us: Option<u32>,
    /// ALWAYS `null` on an operation record: the connection had not closed, so it has no
    /// lifetime yet. STRING u64 (same precision reason as `ts_ns`) when a producer does set it.
    #[serde(default, serialize_with = "opt_u64_as_dec_string", deserialize_with = "opt_u64_from_dec_string")]
    pub lifetime_ns: Option<u64>,

    /// false => the first op we delimited on this connection (it paid for
    /// connect+handshake). Reflects ops WE observed, so trust it only when
    /// `partial == false`; on a partial op the connection facts (and thus whether
    /// it was truly reused) couldn't be attributed.
    pub connection_reused: bool,

    // --- response (E5; from the response head) ---
    /// HTTP status code; null if the response head wasn't seen.
    pub http_status: Option<u16>,
    /// `x-amz-request-id`, if present (for AWS support correlation).
    pub aws_request_id: Option<String>,

    /// Set when the record may be incomplete: the connection facts couldn't be
    /// joined — no `(tgid,fd)->cookie` mapping, OR the cookie resolved but its
    /// connect was never folded (so `dns`/`tcp_connect_ns`/bucket went None) — OR a
    /// request/response head was truncated at the capture cap (Host/headers possibly
    /// cut), so a clean parse isn't guaranteed.
    pub partial: bool,
    /// `"clean"` normally; `"ambiguous"` when a second request was seen on the
    /// connection before this op's response completed (concurrency guard).
    ///
    /// This is a REQUEST-INTERLEAVING flag and nothing else. It never comments on how much of
    /// the response was measured, so `"clean"` alongside null `download_ns` / `total_ns` /
    /// `content_length` is the normal, healthy shape of a chunked response (every S3 LIST)
    /// rather than a measurement failure. To ask about measurement, read the
    /// `download_ns`/`content_length` pair; to ask whether the PARSE may be incomplete, read
    /// `partial`. Three questions, three fields.
    pub delimitation: Delimitation,
}

/// Operation delimitation outcome. Serializes lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Delimitation {
    /// Request opened and its response closed it without interleaving.
    #[default]
    Clean,
    /// A second request line arrived before this op's response completed.
    Ambiguous,
}

/// One connection (`s3tap.connection/2`) — the socket-only / degraded path.
/// This is what M1 emits. Field order IS the JSON
/// order; the golden test pins it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
// forward/back-compat without a container default, as Operation (review step-1 #2).
pub struct Connection {
    pub schema: ConnSchemaTag,
    /// Agent wall-clock at emit; see [`Operation::emitted_at`] for the contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_at: Option<String>,
    /// CLOCK_MONOTONIC at connect start. STRING u64; null when no connect seen.
    #[serde(default, serialize_with = "opt_u64_as_dec_string", deserialize_with = "opt_u64_from_dec_string")]
    pub ts_ns: Option<u64>,
    /// Per-socket join key, STRING (u64 > 2^53 precision; see `u64_as_dec_string`).
    /// SECURITY: in-process this is the raw kernel `struct sock *` pointer (a
    /// KASLR signal) used as the join key, but the agent obscures it with a
    /// per-run random key at emit time, so shipped records carry only a stable
    /// opaque id — never the real pointer.
    #[serde(serialize_with = "u64_as_dec_string", deserialize_with = "u64_from_dec_string")]
    pub sock_cookie: u64,
    pub app: App,
    pub endpoint: Endpoint,
    pub dns: Option<Dns>,
    pub tcp_connect_ns: Option<u64>,
    /// SYN sent, never reached ESTABLISHED (connection refused / timed out).
    pub connect_failed: bool,
    pub tls: Tls,

    // --- connection-cumulative, read off tcp_sock at close ---
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub retransmits: u32,
    pub srtt_us: Option<u32>,
    /// STRING u64: a ns delta exceeds 2^53 at ~104 days, so jq/JS would lose
    /// precision (same reason as `ts_ns`). 0 == unknown (LRU-evicted) → null.
    #[serde(default, serialize_with = "opt_u64_as_dec_string", deserialize_with = "opt_u64_from_dec_string")]
    pub lifetime_ns: Option<u64>,

    // --- extended path diagnosis (kernel-TCP, so present for ANY client incl.
    // Go/rustls). All read off tcp_sock at close; None == unknown/no sample. ---
    /// True propagation floor (`tcp_min_rtt`) — a better RTT base than smoothed
    /// `srtt_us`, which inflates under load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rtt_us: Option<u32>,
    /// RTT variation / jitter (`mdev`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rttvar_us: Option<u32>,
    /// Congestion window, packets; `snd_cwnd * mss` ≈ the in-flight ceiling (BDP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snd_cwnd: Option<u32>,
    /// Current MSS, bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss: Option<u32>,
    /// Kernel delivery-rate estimate, bytes/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_rate_bps: Option<u64>,
    /// Chrono busy-time accumulators (RAW jiffies — meaningful only as RATIOS). These three
    /// are DISJOINT partitions of the connection's send-busy time (the kernel chronograph is
    /// a single-state machine): `busy` = time SENDING FREELY, `rwnd_limited` = blocked on the
    /// receiver window, `sndbuf_limited` = blocked on the local send buffer. Total send-busy
    /// time = their SUM (= `tcpi_busy_time`); compute each share as field/sum, NOT field/busy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busy_jiffies: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rwnd_limited_jiffies: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sndbuf_limited_jiffies: Option<u32>,
    /// Loss shape (close-time snapshots): packets believed lost / SACK'd in flight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sacked: Option<u32>,
    /// Durable reordering-degree estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reordering: Option<u32>,
    /// Congestion-avoidance state at close: 0 Open, 1 Disorder, 2 CWR, 3 Recovery, 4 Loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_state: Option<u8>,
    /// Receive window, bytes — the CLIENT-side ceiling that caps download throughput
    /// (`rcv_wnd / RTT`). `rcv_wnd` is the last advertised window; `window_clamp` is the
    /// autotuning cap. The download counterpart of `snd_cwnd` (which is ~0 on a GET).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv_wnd: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_clamp: Option<u32>,
    /// Retransmitted bytes (`tcp_sock.bytes_retrans`) — retransmit VOLUME (the honest denominator
    /// vs a segment estimate). Plain number (per-conn volume never approaches 2^53). None == none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_retrans: Option<u64>,
    /// Spurious retransmits (`tcp_sock.dsack_dups`): DSACK'd dups — the original DID arrive, so the
    /// resend was over-eager RTO / reordering, NOT loss. Send-path. None == none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsack_dups: Option<u32>,
    /// Out-of-order packets RECEIVED (`tcp_sock.rcv_ooopack`) — reorder/loss evidence on the
    /// DOWNLOAD leg (the GET direction the durable `reordering` degree can't show). None == none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv_ooopack: Option<u32>,
    /// The last delivery-rate sample was app-limited (`tcp_sock.rate_app_limited`): the SEND path
    /// waited on the app, not the network. Send-path; meaningful on uploads. None == not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_limited: Option<bool>,

    pub partial: bool,
}

pub const SAMPLE_SCHEMA: &str = "s3tap.sample/1";

/// Always serializes to the constant [`SAMPLE_SCHEMA`] (cf. [`ConnSchemaTag`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpSampleSchemaTag;

impl Serialize for TcpSampleSchemaTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(SAMPLE_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for TcpSampleSchemaTag {
    /// Accepts only the exact [`SAMPLE_SCHEMA`] string (see [`SchemaTag`]).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == SAMPLE_SCHEMA {
            Ok(TcpSampleSchemaTag)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected schema {SAMPLE_SCHEMA}, got {s:?}"
            )))
        }
    }
}

/// One in-flight TCP time-series sample (`s3tap.sample/1`) — the periodic
/// `tcp_sock` snapshot emitted while a connection is alive.
/// The library-agnostic kernel-TCP path (any client; no plaintext). `ts_ns` and
/// `sock_cookie` are dec-string u64 (jq/JS precision); the `bytes_*` are PLAIN
/// numbers (a single connection's volume ≪ 2^53, matching [`Connection`]).
///
/// Field order IS the JSON order — the golden test pins it. That pinned order is
/// also the CANONICAL COLUMN ORDER for a future columnar `s3tap.sample/2`
/// encoding, so keep it stable.
// forward/back-compat without a container default, as Operation (review step-1 #2).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpSample {
    pub schema: TcpSampleSchemaTag,
    /// Agent wall-clock at emit; see [`Operation::emitted_at`] for the contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_at: Option<String>,
    /// Sample time (CLOCK_MONOTONIC). STRING u64; null when unknown.
    #[serde(default, serialize_with = "opt_u64_as_dec_string", deserialize_with = "opt_u64_from_dec_string")]
    pub ts_ns: Option<u64>,
    /// Per-socket join key, STRING (u64 > 2^53 precision; see `u64_as_dec_string`).
    /// SECURITY: the raw kernel `struct sock *` pointer (KASLR signal) in-process;
    /// the agent obscures it with the per-run key at emit time (as the Connection
    /// emit path does), so shipped records carry only a stable opaque id. The same
    /// run-wide obscurer maps a sample and its Connection to the same value.
    #[serde(serialize_with = "u64_as_dec_string", deserialize_with = "u64_from_dec_string")]
    pub sock_cookie: u64,

    // --- always-emitted evolving counters/gauges (uniform rows to diff). The
    // bytes_* are cumulative → per-interval deltas downstream; PLAIN numbers. ---
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub bytes_in_flight: u64,
    pub snd_cwnd: u32,
    pub rcv_wnd: u32,
    pub snd_wnd: u32,
    pub total_retrans: u32,
    pub rcv_ooopack: u32,
    pub lost: u32,
    pub sacked_out: u32,
    /// Congestion-avoidance state: 0 Open, 1 Disorder, 2 CWR, 3 Recovery, 4 Loss.
    pub ca_state: u8,
    /// The last delivery-rate sample was app-limited (the SEND path waited on the app).
    pub rate_app_limited: bool,

    // --- optional sampled fields (omitted when the kernel had no sample) ---
    /// Smoothed RTT (µs); None when not yet sampled (kernel sentinel 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srtt_us: Option<u32>,
    /// True propagation floor (`tcp_min_rtt`, µs); None when not yet sampled
    /// (kernel sentinels 0 AND U32_MAX).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rtt_us: Option<u32>,
    /// Kernel delivery-rate estimate, bytes/s; None when no sample (kernel 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_rate_bps: Option<u64>,
}

/// Serialize a u64 as a decimal string, so values above 2^53 survive JSON
/// consumers (jq, JavaScript) that parse numbers as f64.
fn u64_as_dec_string<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

/// Like [`u64_as_dec_string`] but for `Option<u64>`: `Some` → decimal string,
/// `None` → JSON null.
fn opt_u64_as_dec_string<S: serde::Serializer>(
    v: &Option<u64>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(n) => s.serialize_str(&n.to_string()),
        None => s.serialize_none(),
    }
}

/// Inverse of [`u64_as_dec_string`]: parse a decimal-string u64 back. Symmetric so a
/// consumer (e.g. `s3tap doctor`) round-trips the records the agent emits.
fn u64_from_dec_string<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

/// Inverse of [`opt_u64_as_dec_string`]: a decimal string → `Some`, JSON null → `None`.
fn opt_u64_from_dec_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    match Option::<String>::deserialize(d)? {
        Some(s) => s.parse::<u64>().map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Serialize a REQUIRED `f64` but ERROR on a non-finite value (NaN/±Inf) — serde_json
/// would silently encode it as `null`, and a null does not read back into a non-Option
/// `f64` ("invalid type: null, expected f64"), so the record would emit clean and fail
/// to parse (review step-1 #1). A non-finite rate means the producer divided by a zero
/// denominator, which is a producer bug: fail loudly at emit rather than ship a record
/// nobody can read.
fn f64_finite<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.is_finite() {
        s.serialize_f64(*v)
    } else {
        Err(serde::ser::Error::custom(
            "non-finite f64 (NaN/Inf) is not serializable — a rate with no denominator must \
             not be emitted at all",
        ))
    }
}

/// `Option<f64>` form of [`f64_finite`] (`None` → JSON null). Same reason: serde_json
/// encodes NaN/Inf as `null`, which then fails to READ BACK as an `f64` — a silent
/// round-trip break (review step-1 #1). Deserialization is the default (`Option<f64>`
/// reads a number or null), which never yields a non-finite value.
fn opt_f64_finite<S: serde::Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(n) if n.is_finite() => s.serialize_f64(*n),
        Some(_) => Err(serde::ser::Error::custom(
            "non-finite f64 (NaN/Inf) is not serializable — emit null instead",
        )),
        None => s.serialize_none(),
    }
}

// ============================================================================
// Finding record (`s3tap.finding/1`) — the second-order public record.
//
// The verdict `doctor`, `advise` and `scorecard` derive from the two first-order
// records above (never from raw events). It ships from all three `--json` modes and
// is the format a fleet ingests, so its stability is a real question with a
// deliberately two-part answer. An earlier note here said "do not code an external
// consumer against it", which was never true of a record the book documents as the
// machine interface, and which said nothing useful about WHAT could move.
//
// THE ENVELOPE IS A CONTRACT, at 0.x already: the field set, their names, their types
// and their encodings. Adding, removing or renaming a field is a schema change and
// bumps the tag to `s3tap.finding/2`, exactly as for the first-order records. A
// consumer may parse this shape and expect it to hold.
//
// THE VOCABULARY IS NOT FROZEN at 0.x: which `finding_id`s exist, what a `metric` is
// called, what units it carries, the `summary` prose, and which severity a given
// condition earns. These move as checks are added and corrected, in a minor release
// and without a tag bump. The work since 0.7.0 has already renamed `serialized_busy_s`
// to `serialized_busy_ms` (a unitless seconds value that should always have been `ms`),
// added the `advisor-run` / `scorecard-run` rows, and narrowed `source_schema` from
// "both streams" to the one a finding actually reads. None of those has shipped yet — they
// are why the split is written down now, before a consumer pins something that will move.
//
// What that means in practice: parse the envelope, switch on `severity` (a closed
// enum in the envelope) rather than on a hardcoded list of ids, and treat
// `finding_id` / `metric` as data that can gain members. A gate written that way
// survives a minor upgrade; one that matches on an id list will need revisiting.
// ============================================================================

pub const FINDING_SCHEMA: &str = "s3tap.finding/1";

/// Always (de)serializes to the constant [`FINDING_SCHEMA`] (cf. [`SchemaTag`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FindingSchemaTag;

impl Serialize for FindingSchemaTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(FINDING_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for FindingSchemaTag {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == FINDING_SCHEMA {
            Ok(FindingSchemaTag)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected schema {FINDING_SCHEMA}, got {s:?}"
            )))
        }
    }
}

/// The three-state mark a finding carries. `Unjudged` is for a span
/// with no RTT floor or below the minimum sample — never silently upgraded to healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Healthy,
    Warn,
    Advisory,
    Unjudged,
}

/// Which health domain a finding belongs to; `Run` is the roll-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Domain {
    Network,
    Client,
    S3,
    Run,
}

/// Unit of a finding's `value`, so a consumer renders it without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Ratio,
    Ns,
    Us,
    Ms,
    Count,
    BytesPerS,
    None,
}

/// The kind of record a finding's sample is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleKind {
    Operation,
    Connection,
    Mixed,
}

/// A finding's measured statistic: a number, a categorical string, or null.
///
/// `Serialize` is hand-written to REJECT a non-finite `Num` (NaN/±Inf): serde_json
/// would otherwise emit it as the JSON literal `null`, which deserializes back to a
/// different value (`Some(Num(NaN)) → null → None`) — a silent round-trip break
/// (review step-1 #1). A non-finite metric is a doctor bug (e.g. an `x/0` ratio with
/// no RTT floor — which must be reported `Unjudged` with a null value instead), so we
/// fail loudly at emit rather than ship an unreadable record.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum MetricValue {
    Num(f64),
    Str(String),
}

impl Serialize for MetricValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            MetricValue::Num(n) if n.is_finite() => s.serialize_f64(*n),
            MetricValue::Num(_) => Err(serde::ser::Error::custom(
                "MetricValue::Num is non-finite (NaN/Inf); a doctor must emit a null value \
                 (Unjudged), never a non-finite number",
            )),
            MetricValue::Str(t) => s.serialize_str(t),
        }
    }
}

/// How strong the finding is — the eligibility-gate counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub judged: usize,
    pub excluded: usize,
    pub kind: SampleKind,
}

/// What the finding is segmented by; a `None` field means the whole capture.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingScope {
    pub s3_op: Option<String>,
    pub bucket: Option<String>,
    pub prefix_hash: Option<String>,
    pub region: Option<String>,
    pub app_pid: Option<u32>,
}

/// The capture interval the finding was computed over (STRING u64 ns; see `ts_ns`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    #[serde(serialize_with = "u64_as_dec_string", deserialize_with = "u64_from_dec_string")]
    pub ts_start: u64,
    #[serde(serialize_with = "u64_as_dec_string", deserialize_with = "u64_from_dec_string")]
    pub ts_end: u64,
}

/// A bounded, representative sample of the contributing records, so a consumer can
/// drill from the verdict back into the raw records (NOT every contributing op).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Evidence {
    pub op_ids: Vec<String>,
    /// STRING u64 — the per-run obscured ids (never raw sk pointers).
    pub sock_cookies: Vec<String>,
    pub aws_request_ids: Vec<String>,
}

/// A doctor verdict over a window of the first-order records (`s3tap.finding/1`).
/// See the note above for what is and is not frozen: this SHAPE is, the finding
/// vocabulary is not. No `Eq` (it carries `f64`s).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub schema: FindingSchemaTag,
    /// RFC3339 wall-clock of the moment this verdict was WRITTEN OUT (not of the traffic
    /// it judges — that is [`window`](Finding::window), which is boot-relative monotonic ns
    /// and therefore meaningless across hosts or reboots).
    ///
    /// ALWAYS `None` today, deliberately: every second-order producer (`doctor`, `advise`,
    /// `scorecard`) is a pure function of its input records, and the byte-exact goldens pin
    /// that — a wall clock in the output would make every golden non-reproducible. So a
    /// consumer MUST NOT rely on this field to order, age or dedupe findings; today the only
    /// wall clock in the pipeline is the `emitted_at` the agent stamps on the FIRST-ORDER
    /// records, and a fleet ingest should carry its own receive time.
    ///
    /// If a producer ever does stamp it, the contract is: ONE timestamp per emitted BATCH,
    /// taken once before the drain loop and cloned. Calling `now()` per record gives the
    /// findings of a single report N different times, which reads downstream as N distinct
    /// emit events. (The agent's first-order `emit()` did exactly that THROUGH 0.7.0. It takes
    /// the clock once per drain now, in `batch_now`, but that fix is unreleased: a 0.7.0
    /// binary still stamps per record.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitted_at: Option<String>,
    /// The first-order public-record version(s) this verdict was derived from.
    pub source_schema: Vec<String>,

    // --- identity ---
    /// Stable slug identifying the finding.
    pub finding_id: String,
    pub domain: Domain,
    pub title: String,
    pub severity: Severity,
    /// The one-word envelope verdict shown in the report row (e.g. "high").
    pub verdict: String,
    pub summary: String,
    pub recommendation_ref: Option<String>,

    // --- measurement (the RTT-relative judgment) ---
    pub metric: String,
    pub value: Option<MetricValue>,
    pub unit: Unit,
    /// The srtt floor this was judged against (µs); `None` ⇒ unjudged.
    pub baseline_rtt_us: Option<u64>,
    /// `value` as a multiple of the RTT floor (latency checks); `None` otherwise.
    /// Rejects a non-finite value at serialize (see [`MetricValue`] / review step-1 #1).
    #[serde(serialize_with = "opt_f64_finite")]
    pub ratio_to_rtt: Option<f64>,
    /// The healthy envelope judged against, e.g. ">= 0.8".
    pub threshold: String,

    // --- support / scope / window / evidence ---
    pub sample: Sample,
    pub scope: FindingScope,
    pub window: TimeWindow,
    pub evidence: Evidence,
}

// --- terminal-safe rendering of untrusted record strings --------------------
//
// The public records carry attacker-influenceable strings (a path-style `bucket`, a
// crafted `s3_op` in a hand-written JSONL line, an SNI). Any tool that renders them to
// a terminal must clean them first — this lives here, the one crate every renderer
// (the agent's `render`, `s3tap doctor`) shares, so the defense can't drift between them.

pub const SCORECARD_SCHEMA: &str = "s3tap.scorecard/1";

/// Always serializes to the constant [`SCORECARD_SCHEMA`] (cf. [`ConnSchemaTag`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScorecardSchemaTag;

impl Serialize for ScorecardSchemaTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(SCORECARD_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for ScorecardSchemaTag {
    /// Accepts only the exact [`SCORECARD_SCHEMA`] string (see [`SchemaTag`]).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == SCORECARD_SCHEMA {
            Ok(ScorecardSchemaTag)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected schema {SCORECARD_SCHEMA}, got {s:?}"
            )))
        }
    }
}

/// One row of the observed-SLO scorecard (`s3tap.scorecard/1`) — a DESCRIPTIVE
/// per-`(bucket, s3_op)` rollup of the traffic actually seen: request/error counts,
/// the status-code mix, and the TTFB percentiles. Pure telemetry, never a verdict —
/// the judgments (error-rate gates, tail-shape) ride the separate `s3tap.finding/1`
/// rails alongside it, so a consumer that wants "just the numbers" reads these rows
/// and a fleet gate reads the findings.
///
/// Percentiles are over the doctor's latency-row eligibility gate (non-partial, clean
/// delimitation) INTERSECTED with the `ops` denominator (a *present* status < 400) — so
/// the timing population is always a subset of `ops` and `latency_sample <= ops` holds.
/// The intersection matters: the doctor's `is_eligible` alone passes a status-LESS op (an
/// aborted in-flight request, `http_status` None), which is NOT in `ops`; timing it would
/// let the percentiles describe requests that never got a response. `error_rate`/
/// `status_counts` are over that same `ops` denominator — every op that got an HTTP status
/// (partial included — a parsed status is a real response, matching the doctor's status-mix
/// population), since an error IS the thing being counted and can't be gated out of its
/// own rate.
///
/// No `emitted_at`: like [`Finding::emitted_at`] there is nothing honest to put in it (the
/// producer is a pure function of the records and the goldens pin that), and unlike a
/// `Finding` the field does not exist at all, so adding one is a field addition that bumps
/// the tag to `s3tap.scorecard/2`. That bump is not worth spending on a field that would ship
/// `null` forever. A consumer that needs wall-clock ordering uses its own ingest time, or the
/// `emitted_at` on the first-order records this row was derived from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScorecardRow {
    pub schema: ScorecardSchemaTag,
    /// Bucket (SNI/Host); null when the request head wasn't seen.
    pub bucket: Option<String>,
    /// Resolved S3 op-class (taxonomy); null when unclassified.
    pub s3_op: Option<String>,
    /// Denominator: ops that carried an HTTP status (a request that got a response),
    /// partial included. PLAIN number (op counts ≪ 2^53).
    pub ops: u64,
    /// Ops in `ops` whose status was a 4xx/5xx.
    pub errors: u64,
    /// `errors / ops` — always finite (a row is emitted only when `ops >= 1`). Guarded
    /// like [`throughput_bytes_per_s`](ScorecardRow::throughput_bytes_per_s): a non-finite
    /// value errors at serialize. Defense-in-depth, and here it is the ONLY protection
    /// against a one-way record — this field is not an `Option`, so a NaN silently
    /// serialized as `null` would not even deserialize back.
    #[serde(serialize_with = "f64_finite")]
    pub error_rate: f64,
    /// Per-status-code counts over the `ops` denominator (the reliability taxonomy).
    /// JSON object keyed by the stringified status code.
    pub status_counts: std::collections::BTreeMap<u16, u64>,
    /// TTFB percentiles over the ELIGIBLE ops (ns). p95/p99 are null below the tail-
    /// sample floor — a tiny capture's "max" is never sold as a p95/p99.
    pub ttfb_p50_ns: Option<u64>,
    pub ttfb_p95_ns: Option<u64>,
    pub ttfb_p99_ns: Option<u64>,
    /// How many eligible ops fed the percentiles (the tail-estimate sample size). Always
    /// `<= ops` — the timing population is a subset of the status-carrying denominator.
    pub latency_sample: u64,
    /// Median single-stream throughput (bytes/s) for a GET group — `content_length /
    /// download_ns`; null for a non-GET group or when no op was tallyable. Guarded like
    /// [`Finding::ratio_to_rtt`]: a non-finite value errors at serialize rather than
    /// silently becoming JSON `null` (defense-in-depth — the producer only feeds finite).
    #[serde(serialize_with = "opt_f64_finite")]
    pub throughput_bytes_per_s: Option<f64>,
    /// The [ts_start, ts_end] monotonic span the group's ops fell in.
    pub window: TimeWindow,
}

/// Replace unsafe characters with U+FFFD so an attacker-controlled string can't inject
/// ANSI escapes / carriage returns / newlines into a terminal or a teed log (CWE-117),
/// nor SPOOF the rendered text with Unicode bidi / format controls (Trojan Source,
/// CWE-1007). A legitimate bucket/SNI/op name is LDH-ASCII, so rejecting all of Cc+Cf
/// can never mangle a real label.
#[must_use]
pub fn sanitize_term(s: &str) -> String {
    if s.chars().any(is_unsafe_term_char) {
        s.chars().map(|c| if is_unsafe_term_char(c) { '\u{fffd}' } else { c }).collect()
    } else {
        s.to_string()
    }
}

/// A character that must not reach a terminal verbatim: any Unicode control
/// (`char::is_control` — category Cc: C0 + DEL + C1), any Unicode FORMAT character
/// (category Cf — the whole Trojan-Source / invisible-smuggling class: bidi overrides/
/// isolates, zero-width joiners, invisible operators, the language-TAG block, etc., none
/// of which `char::is_control` catches), plus the two line/paragraph separators U+2028/
/// U+2029 (Zl/Zp) which are newline-like and thus a log-injection vector. We enumerate the
/// Cf ranges (no extra deps, matching the project's stance) from the Unicode
/// `General_Category=Cf` set.
fn is_unsafe_term_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'                // soft hyphen
            | '\u{0600}'..='\u{0605}' // Arabic number signs
            | '\u{061C}'              // Arabic letter mark
            | '\u{06DD}'              // Arabic end of ayah
            | '\u{070F}'              // Syriac abbreviation mark
            | '\u{0890}'..='\u{0891}' // Arabic pound/piastre marks
            | '\u{08E2}'              // Arabic disputed end of ayah
            | '\u{180E}'              // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width space/joiners + LRM/RLM
            | '\u{2028}'..='\u{2029}' // LINE/PARAGRAPH SEPARATOR (Zl/Zp) — newline-like, log-injection
            | '\u{202A}'..='\u{202E}' // bidi embeddings + overrides
            | '\u{2060}'..='\u{2064}' // word joiner + invisible operators
            | '\u{2066}'..='\u{206F}' // bidi isolates + deprecated format controls
            | '\u{FEFF}'              // ZWNBSP / BOM
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
            | '\u{110BD}' | '\u{110CD}' // Kaithi number signs
            | '\u{13430}'..='\u{1343F}' // Egyptian hieroglyph format controls
            | '\u{1BCA0}'..='\u{1BCA3}' // Duployan shorthand format
            | '\u{1D173}'..='\u{1D17A}' // musical beam/slur/phrase controls
            | '\u{E0001}'               // language tag
            | '\u{E0020}'..='\u{E007F}' // TAG block (invisible-character smuggling)
        )
}
