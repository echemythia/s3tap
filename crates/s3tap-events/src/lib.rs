// crates/s3tap-events/src/lib.rs
//
// Rust mirror of bpf/include/s3tap_events.h. Byte-for-byte identical layout so
// the agent can read kernel ring-buffer events directly. KEEP IN SYNC with the
// C header — tests/layout.rs is the guard that fails if the two ever drift.
//
// We don't add explicit padding fields: #[repr(C)] applies the same alignment
// rules as the C compiler, so identical field order + types => identical
// layout (verified offset-by-offset in the test).

use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Common header on every event (mirrors `struct s3tap_event_hdr`, 32 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EventHdr {
    pub schema_version: u16,
    /// `enum s3tap_event_type`; named `type_` because `type` is a Rust keyword.
    pub type_: u16,
    pub cpu: u32,
    pub ts_ns: u64,
    pub tgid: u32,
    pub tid: u32,
    pub sock_cookie: u64,
}

/// The ABI version this build understands (mirrors `S3TAP_SCHEMA_VERSION` in
/// the C header). [`Event::parse`] refuses to decode a record stamped with any
/// other version — the documented probe/agent mismatch guard.
///
/// v2: `EVT_TLS_READ_BODY` (tag 23) moved from [`EvtTlsData`] (4144 B) to the
/// 40-byte [`EvtTlsBody`]. The exact-length decode would reject the mismatch on its
/// own, but silently: a v1 agent fed v2 body events drops every one and reports
/// `download_ns`/`total_ns` as None, which reads as a quiet workload rather than a
/// version skew.
pub const SCHEMA_VERSION: u16 = 2;

/// Event type tags (mirror `enum s3tap_event_type`).
pub const EVT_DNS_QUERY: u16 = 1;
pub const EVT_DNS_RESPONSE: u16 = 2;
pub const EVT_GETADDRINFO: u16 = 3;
pub const EVT_CONN_ID: u16 = 10;
pub const EVT_TCP_CONNECT: u16 = 11;
pub const EVT_TCP_CLOSE: u16 = 13;
pub const EVT_TCP_SAMPLE: u16 = 14;
pub const EVT_TLS_HANDSHAKE: u16 = 20;
pub const EVT_TLS_WRITE: u16 = 21;
pub const EVT_TLS_READ: u16 = 22;
pub const EVT_TLS_READ_BODY: u16 = 23;
pub const EVT_TLS_SERVER: u16 = 24;
pub const EVT_PROC_EXEC: u16 = 30;

/// Bounded variable-length tails (mirror the C `#define`s). A presentation-form
/// DNS name is at most 253 chars; 255 caps it. The raw response payload tracks
/// the classic 512-byte UDP DNS limit (the kernel masks with `DNS_PAYLOAD_MAX-1`
/// for a verifier-provable copy bound, so the effective cap is 511 bytes; EDNS0
/// responses past this are clipped).
pub const QNAME_MAX: usize = 255;
/// SNI server_name is a hostname, RFC 6066-bounded at 255 chars (mirror `SNI_MAX`).
pub const SNI_MAX: usize = 255;
pub const DNS_PAYLOAD_MAX: usize = 512;
/// Bounded plaintext prefix captured per SSL_write/SSL_read (mirror `HDR_CAP`).
pub const HDR_CAP: usize = 4096;
/// Short process name (mirror `COMM_LEN`, kernel TASK_COMM_LEN).
pub const COMM_LEN: usize = 16;
/// Bounded exec'd path captured per EVT_PROC_EXEC (mirror `EXE_MAX`).
pub const EXE_MAX: usize = 256;

/// Mirrors `struct evt_conn_id` (40 bytes) — the `(hdr.tgid, fd) -> hdr.sock_cookie`
/// mapping (M3 E4) that lets the L7 plaintext events (which carry `(tgid,fd)`) join
/// the connection identified by `sock_cookie`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EvtConnId {
    pub hdr: EventHdr,
    pub fd: u32,
    pub _pad: u32,
}

/// Mirrors `struct evt_tcp_connect` (80 bytes). Addresses are stored in the
/// kernel's v4-mapped IPv6 form: for AF_INET the IPv4 octets are in bytes
/// [12..16], not [0..4].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EvtTcpConnect {
    pub hdr: EventHdr,
    pub family: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    /// 1 if SYN was sent but the connection never reached ESTABLISHED. Occupies
    /// the byte that was padding at offset 65, so the struct is still 80 bytes.
    pub connect_failed: u8,
    pub dport: u16, // host order — do NOT byte-swap (the tracepoint already did)
    pub sport: u16,
    pub connect_latency_ns: u64,
}

/// Mirrors `struct evt_tcp_close` (152 bytes). Counters are read straight off
/// tcp_sock at close (bytes_sent =
/// accepted-not-acked, bytes_recv = in-order; srtt_us/lifetime_ns 0-sentinels).
/// The extended path-diagnosis fields are all kernel-TCP (present for any client,
/// Go/rustls included); 0 == unknown for each.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EvtTcpClose {
    pub hdr: EventHdr,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub retransmit_count: u32,
    pub srtt_us: u32,
    pub lifetime_ns: u64,
    pub delivery_rate_bps: u64,
    /// `tcp_min_rtt` propagation floor (microseconds); 0 OR `u32::MAX` == no sample (both map to None).
    pub min_rtt_us: u32,
    pub rttvar_us: u32,
    pub snd_cwnd: u32,
    pub mss_cache: u32,
    pub busy_jiffies: u32,
    pub rwnd_limited_jiffies: u32,
    pub sndbuf_limited_jiffies: u32,
    pub lost: u32,
    pub sacked_out: u32,
    pub reordering: u32,
    pub ca_state: u8,
    pub rcv_wnd: u32,
    pub window_clamp: u32,
    pub handshake_us: u32,
    /// Retransmitted bytes (`tcp_sock.bytes_retrans`) — retransmit VOLUME (the honest rate
    /// denominator vs a segment estimate). 0 == none / no sample.
    pub bytes_retrans: u64,
    /// DSACK'd duplicate retransmits (`tcp_sock.dsack_dups`) — spurious (reorder/RTO), NOT loss.
    pub dsack_dups: u32,
    /// Out-of-order packets RECEIVED (`tcp_sock.rcv_ooopack`) — download-leg reorder evidence.
    pub rcv_ooopack: u32,
    /// The delivery-rate sample was app-limited (`tcp_sock.rate_app_limited`, a :1 bitfield) —
    /// the send path waited on the app, not the network. Send-path signal. 0 == not / no sample.
    pub rate_app_limited: u8,
}

/// Mirrors `struct evt_tcp_sample` (104 bytes) — an in-flight `tcp_sock` sample (Plan 1).
/// Read periodically during a connection's life; every field mirrors the `EvtTcpClose`
/// read of the same name (same units, same 0/sentinel "no sample" conventions). The
/// cumulative counters (`bytes_*`, `total_retrans`, `rcv_ooopack`) are differenced
/// between consecutive samples by the correlator. `hdr.ts_ns` = sample time,
/// `hdr.sock_cookie` = the connection's sk-pointer (joins to the TCP record).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EvtTcpSample {
    pub hdr: EventHdr,
    /// Cumulative `tcp_sock.bytes_sent`; Δ between samples == per-interval UPLOAD bytes.
    pub bytes_sent: u64,
    /// Cumulative `tcp_sock.bytes_received`; Δ between samples == per-interval DOWNLOAD bytes.
    pub bytes_recv: u64,
    /// `(u32)(snd_nxt - snd_una)` widened — outstanding/unacked bytes (a cwnd-utilization
    /// proxy, NOT the CC-sense `tcp_packets_in_flight()`; don't compare 1:1 to `snd_cwnd*mss`).
    pub bytes_in_flight: u64,
    /// Computed `mss*rate_delivered*1e6/rate_interval_us` (bytes/s); 0 == no sample.
    pub delivery_rate_bps: u64,
    /// `tcp_sock.snd_cwnd`: congestion window (packets) — the ramp/collapse curve.
    pub snd_cwnd: u32,
    /// `tcp_sock.srtt_us >> 3` (microseconds); 0 == no sample.
    pub srtt_us: u32,
    /// `tcp_min_rtt` floor (microseconds); 0 OR `u32::MAX` == no sample (both map to None).
    pub min_rtt_us: u32,
    /// Cumulative `tcp_sock.total_retrans`; Δ between samples == UPLOAD retransmits this interval.
    pub total_retrans: u32,
    /// Cumulative `tcp_sock.rcv_ooopack`; Δ between samples == DOWNLOAD out-of-order this interval.
    pub rcv_ooopack: u32,
    /// `tcp_sock.rcv_wnd`: receive window — the download flow-control ceiling.
    pub rcv_wnd: u32,
    /// `tcp_sock.snd_wnd`: peer's advertised window — the upload flow-control ceiling.
    pub snd_wnd: u32,
    /// `tcp_sock.lost_out`: packets believed lost in-flight (loss shape).
    pub lost: u32,
    /// `tcp_sock.sacked_out`: SACK'd packets in-flight.
    pub sacked_out: u32,
    /// `icsk_ca_state`: 0 Open, 1 Disorder, 2 CWR, 3 Recovery, 4 Loss.
    pub ca_state: u8,
    /// Bit0 = `rate_app_limited` (the send path waited on the app, not the network).
    pub flags: u8,
}

/// Mirrors `struct evt_dns_query` (296 bytes). `qname` is presentation form and
/// is NOT NUL-terminated — read exactly `qname_len` bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
pub struct EvtDnsQuery {
    pub hdr: EventHdr,
    pub txn_id: u16,
    pub proto: u8,
    pub qname_len: u8,
    pub qname_truncated: u8,
    pub qname: [u8; QNAME_MAX],
}

/// Mirrors `struct evt_dns_response` (552 bytes). Carries the RAW DNS message in
/// `payload[..payload_len]` (starting at the DNS header) — the agent parses the
/// answers in userspace. `txn_id` is `payload[0..2]` big-endian.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
pub struct EvtDnsResponse {
    pub hdr: EventHdr,
    pub payload_len: u16,
    pub payload: [u8; DNS_PAYLOAD_MAX],
}

/// Mirrors `struct evt_getaddrinfo` (304 bytes). `hostname` is NOT
/// NUL-terminated — read exactly `hostname_len` bytes. `saw_wire_activity` is
/// RESERVED and always 0: the correlator ignores it and derives cache-hit from
/// the :53 events it tracks (see `Correlator::on_getaddrinfo`).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
pub struct EvtGetaddrinfo {
    pub hdr: EventHdr,
    pub latency_ns: u64,
    pub ret: i32,
    pub hostname_len: u8,
    pub hostname_truncated: u8,
    pub saw_wire_activity: u8,
    pub hostname: [u8; QNAME_MAX],
}

// Arrays only auto-derive `Default` up to length 32, so every struct with a
// large fixed tail (QNAME_MAX/DNS_PAYLOAD_MAX/SNI_MAX) gets a hand-written
// zeroing impl — keeping `..Default::default()` ergonomics for tests and future
// constructors.
impl Default for EvtDnsQuery {
    fn default() -> Self {
        EvtDnsQuery {
            hdr: EventHdr::default(),
            txn_id: 0,
            proto: 0,
            qname_len: 0,
            qname_truncated: 0,
            qname: [0; QNAME_MAX],
        }
    }
}

impl Default for EvtDnsResponse {
    fn default() -> Self {
        EvtDnsResponse {
            hdr: EventHdr::default(),
            payload_len: 0,
            payload: [0; DNS_PAYLOAD_MAX],
        }
    }
}

impl Default for EvtGetaddrinfo {
    fn default() -> Self {
        EvtGetaddrinfo {
            hdr: EventHdr::default(),
            latency_ns: 0,
            ret: 0,
            hostname_len: 0,
            hostname_truncated: 0,
            saw_wire_activity: 0,
            hostname: [0; QNAME_MAX],
        }
    }
}

/// Mirrors `struct evt_tls_handshake` (296 bytes). `sni` is NOT NUL-terminated —
/// read exactly `sni_len` bytes. `hdr.sock_cookie` is the connection's sk-pointer
/// (joins directly to the TCP record — the SNI is parsed from the ClientHello in
/// the kernel, so it's library-agnostic).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
pub struct EvtTlsHandshake {
    pub hdr: EventHdr,
    pub tls_version: u16,
    pub sni_len: u8,
    pub sni_truncated: u8,
    pub sni: [u8; SNI_MAX],
}

/// Mirrors `struct evt_tls_server` (40 bytes) — the NEGOTIATED TLS version + cipher parsed
/// off the ingress ServerHello (library-agnostic). `version`: 0x0304=TLS 1.3, 0x0303=1.2.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EvtTlsServer {
    pub hdr: EventHdr,
    pub version: u16,
    pub cipher: u16,
}

impl Default for EvtTlsHandshake {
    fn default() -> Self {
        EvtTlsHandshake {
            hdr: EventHdr::default(),
            tls_version: 0,
            sni_len: 0,
            sni_truncated: 0,
            sni: [0; SNI_MAX],
        }
    }
}

/// Mirrors `struct evt_tls_data` (4144 bytes) — the plaintext prefix of an
/// `SSL_write` (EVT_TLS_WRITE) or `SSL_read` (EVT_TLS_READ). `data[..captured_len]`
/// is the captured bytes; `plaintext_len` is the true buffer size. `hdr.sock_cookie`
/// is unset (0) — the join key is `(hdr.tgid, fd)`, resolved to a connection via
/// the SSL*->fd chain (E4 adds fd->cookie). `fd == 0` means no SSL_set_fd/rfd/wfd
/// was observed (e.g. an SSL_set_bio client, or attach mid-connection), so the op
/// is `partial`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
pub struct EvtTlsData {
    pub hdr: EventHdr,
    pub fd: u32,
    pub plaintext_len: u32,
    pub captured_len: u16,
    pub captured_truncated: u8,
    pub _pad: u8,
    pub data: [u8; HDR_CAP],
}

impl Default for EvtTlsData {
    fn default() -> Self {
        EvtTlsData {
            hdr: EventHdr::default(),
            fd: 0,
            plaintext_len: 0,
            captured_len: 0,
            captured_truncated: 0,
            _pad: 0,
            data: [0; HDR_CAP],
        }
    }
}

impl EvtTlsData {
    /// The captured plaintext, bounded to `captured_len`. ALWAYS read the payload
    /// through this — the kernel does NOT zero `data[captured_len..]` (a 4 KiB
    /// memset is an unsupported BPF libcall), so the tail holds stale bytes from a
    /// PRIOR event, which on a host-wide capture is plausibly another process's
    /// request — i.e. a credential. `EvtTlsData` must never derive `Serialize`
    /// (that would ship the whole `data` incl. the tail); convert to a scrubbed,
    /// exact-length type at the boundary instead.
    #[must_use]
    pub fn captured(&self) -> &[u8] {
        &self.data[..(self.captured_len as usize).min(self.data.len())]
    }
}

/// Mirrors `struct evt_tls_body` (40 bytes) — a response BODY read (EVT_TLS_READ_BODY),
/// LENGTH ONLY: `plaintext_len` is the byte count of one `SSL_read` body chunk and no
/// object bytes are shipped. The join key is `(hdr.tgid, fd)`, the same slot the response
/// head opened. `hdr.sock_cookie` is unset (0) on the normal `SSL_set_fd` path; on the BIO
/// path (`fd == 0`, curl >= 7.84) the kernel stamps the thread's tid-inferred connection
/// cookie there, and the consumer REQUIRES it: with `fd == 0` the `(tgid, 0)` slot is
/// shared by every concurrent BIO connection in the process, so without the cookie one
/// connection's chunks would tally into another's open op.
///
/// This is the highest-rate event in the system (one per body chunk of every download),
/// which is why it is 40 bytes rather than reusing the 4144-byte [`EvtTlsData`]: it
/// shares the `tls_events` ring with `EvtConnId` and the request/response heads, so its
/// volume is what decides whether an unrelated connection's `EvtConnId` survives.
///
/// NB the layout is coincidentally identical to [`EvtConnId`] (40 B, `u32` at 32, `u32`
/// at 36). Harmless, because [`Event::parse`] dispatches on the TAG before the length —
/// but do NOT reuse `EvtConnId` here: its offset-36 field is `_pad`, so the two types
/// would agree on bytes while disagreeing on meaning.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct EvtTlsBody {
    pub hdr: EventHdr,
    pub fd: u32,
    pub plaintext_len: u32,
}

/// Mirrors `struct evt_proc_exec` (320 bytes) — a process exec (M4 F1). Lets the
/// agent track `--app`/`--exe` process churn: on each exec it re-matches and updates
/// `filter_pids`. `hdr.tgid` is the exec'ing pid; `hdr.sock_cookie` is 0. The `exe`
/// path is best-effort from the tracepoint filename; read it bounded to `exe_len`.
/// Emitted only while an allowlist is active.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
pub struct EvtProcExec {
    pub hdr: EventHdr,
    pub cgroup_id: u64,
    pub comm: [u8; COMM_LEN],
    pub exe_len: u8,
    pub exe_truncated: u8,
    pub _pad: u16,
    pub exe: [u8; EXE_MAX],
}

impl Default for EvtProcExec {
    fn default() -> Self {
        EvtProcExec {
            hdr: EventHdr::default(),
            cgroup_id: 0,
            comm: [0; COMM_LEN],
            exe_len: 0,
            exe_truncated: 0,
            _pad: 0,
            exe: [0; EXE_MAX],
        }
    }
}

impl EvtProcExec {
    /// The exec'd path, bounded to `exe_len` (the kernel zeroes the tail, but stay
    /// exact). Empty if the tracepoint filename couldn't be read.
    #[must_use]
    pub fn exe_path(&self) -> &[u8] {
        &self.exe[..(self.exe_len as usize).min(self.exe.len())]
    }
    /// The short process name (comm), trimmed at the first NUL.
    #[must_use]
    pub fn comm_str(&self) -> &[u8] {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(self.comm.len());
        &self.comm[..end]
    }
}

/// A decoded ring-buffer record. Grows a variant per event type as later
/// phases add probes. The DNS and TLS variants carry large fixed tails (a
/// 255-byte name, the 512-byte raw payload, or the 255-byte SNI), so they are
/// boxed: the common TCP path keeps a small enum, and an infrequent
/// DNS/TLS event pays one allocation.
#[derive(Debug, Clone)]
pub enum Event {
    DnsQuery(Box<EvtDnsQuery>),
    DnsResponse(Box<EvtDnsResponse>),
    Getaddrinfo(Box<EvtGetaddrinfo>),
    TlsHandshake(Box<EvtTlsHandshake>),
    TlsServer(EvtTlsServer),
    TlsWrite(Box<EvtTlsData>),
    TlsRead(Box<EvtTlsData>),
    /// A response BODY read — `plaintext_len` is the byte count, no object bytes are
    /// copied. Tallied for the download/total latency span. Small (40 B) and the
    /// highest-rate variant, so unboxed like `ConnId`/`TcpSample`.
    TlsReadBody(EvtTlsBody),
    ConnId(EvtConnId),
    TcpConnect(EvtTcpConnect),
    TcpClose(EvtTcpClose),
    /// An in-flight `tcp_sock` sample (Plan 1) — small (104 B), so unboxed like `TcpClose`.
    TcpSample(EvtTcpSample),
    ProcExec(Box<EvtProcExec>),
}

impl Event {
    /// Decode one raw ring-buffer record. Returns None if the slice is too
    /// short to hold a header, the schema version is unrecognized, the type tag
    /// is unknown, or the payload length does not exactly match the struct.
    /// `read_from_bytes` is exact-length: a record shorter OR longer than its
    /// struct is refused, never read partially — a deliberate strict-ABI guard
    /// that pairs with the schema-version check. The decode is zero-copy. NB:
    /// these catch only SIZE/TAG drift. A field repurposed in place (same size,
    /// same tag, e.g. flipping `saw_wire_activity`'s meaning) decodes silently to
    /// the wrong semantics — guard that by bumping `SCHEMA_VERSION` by hand.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Event> {
        // Refuse a record whose ABI version we don't recognize —
        // guards against decoding a mismatched probe object as if it were ours.
        if peek_schema_version(bytes)? != SCHEMA_VERSION {
            return None;
        }
        match peek_type(bytes)? {
            EVT_DNS_QUERY => EvtDnsQuery::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::DnsQuery(Box::new(e))),
            EVT_DNS_RESPONSE => EvtDnsResponse::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::DnsResponse(Box::new(e))),
            EVT_GETADDRINFO => EvtGetaddrinfo::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::Getaddrinfo(Box::new(e))),
            EVT_TLS_HANDSHAKE => EvtTlsHandshake::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::TlsHandshake(Box::new(e))),
            EVT_TLS_SERVER => EvtTlsServer::read_from_bytes(bytes).ok().map(Event::TlsServer),
            EVT_TLS_WRITE => EvtTlsData::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::TlsWrite(Box::new(e))),
            EVT_TLS_READ => EvtTlsData::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::TlsRead(Box::new(e))),
            EVT_TLS_READ_BODY => EvtTlsBody::read_from_bytes(bytes).ok().map(Event::TlsReadBody),
            EVT_CONN_ID => EvtConnId::read_from_bytes(bytes).ok().map(Event::ConnId),
            EVT_TCP_CONNECT => EvtTcpConnect::read_from_bytes(bytes).ok().map(Event::TcpConnect),
            EVT_TCP_CLOSE => EvtTcpClose::read_from_bytes(bytes).ok().map(Event::TcpClose),
            EVT_TCP_SAMPLE => EvtTcpSample::read_from_bytes(bytes).ok().map(Event::TcpSample),
            EVT_PROC_EXEC => EvtProcExec::read_from_bytes(bytes)
                .ok()
                .map(|e| Event::ProcExec(Box::new(e))),
            _ => None,
        }
    }
}

/// Read the ABI version (offset 0) from a raw record. None if too short.
#[must_use]
pub fn peek_schema_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < size_of::<EventHdr>() {
        return None;
    }
    Some(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

/// Read the event type tag from a raw ring-buffer slice without assuming which
/// struct it is. Returns None if the slice is too short to hold a header.
#[must_use]
pub fn peek_type(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < size_of::<EventHdr>() {
        return None;
    }
    // `type_` is at offset 2 (after schema_version: u16). Native-endian: the
    // probe and agent share the host, so no byte-swap.
    Some(u16::from_ne_bytes([bytes[2], bytes[3]]))
}
