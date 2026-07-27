// bpf/include/s3tap_events.h
//
// THE shared contract between the eBPF programs (producer) and the Rust
// agent (consumer). Mirrors the shared on-wire event schema. If you change a struct
// here, you MUST change the Rust mirror in crates/s3tap-events/ to match,
// or the agent will misread bytes. The layout test in Phase C guards this.

#ifndef S3TAP_EVENTS_H
#define S3TAP_EVENTS_H

// Fixed-width integer aliases (vmlinux.h already provides u8/u16/u32/u64).
// We use them so the struct layout is identical on both sides.

// Bump this if the ABI changes incompatibly. The agent checks it on EVERY record
// (Event::parse refuses a record stamped with any other version), so a mismatched
// probe object is refused loudly rather than misread.
//
// v2: EVT_TLS_READ_BODY (tag 23) moved from `struct evt_tls_data` (4144 B) to the new
//     `struct evt_tls_body` (40 B). Same tag, different payload struct — the exact-length
//     decode would reject the mismatch anyway, but silently: a v1 agent fed v2 body events
//     would drop every one and just report download_ns/total_ns as None, which reads as a
//     quiet workload rather than a version skew. The bump makes it say so.
#define S3TAP_SCHEMA_VERSION 2

// Every event begins with this header. The agent reads `type` first, then
// casts the bytes to the matching struct below.
enum s3tap_event_type {
    EVT_DNS_QUERY      = 1,   // M2: a DNS query left the host (udp :53)
    EVT_DNS_RESPONSE   = 2,   // M2: a DNS response arrived (udp :53)
    EVT_GETADDRINFO    = 3,   // M2: a libc getaddrinfo() call returned (uprobe)
    EVT_CONN_ID        = 10,  // M3 E4: (tgid,fd) <-> sock_cookie, joins TLS plaintext to a connection
    EVT_TCP_CONNECT    = 11,
    EVT_TCP_CLOSE      = 13,
    EVT_TCP_SAMPLE     = 14,  // Plan 1: an in-flight tcp_sock sample (periodic, per-connection time-series)
    EVT_TLS_HANDSHAKE  = 20,  // M3: a TLS ClientHello with a kernel-parsed SNI left on egress (no-SNI hellos are dropped)
    EVT_TLS_WRITE      = 21,  // M3 E3: plaintext prefix of an SSL_write (libssl uprobe)
    EVT_TLS_READ       = 22,  // M3 E3: plaintext prefix of an SSL_read  (libssl uretprobe)
    EVT_TLS_READ_BODY  = 23,  // M3.5: a response BODY read — LENGTH ONLY, no data (download/total tally).
                              //   Carries `struct evt_tls_body` (40 B), NOT evt_tls_data.
    EVT_TLS_SERVER     = 24,  // M-path S2: ServerHello parsed off ingress — NEGOTIATED version + cipher
    EVT_PROC_EXEC      = 30,  // M4 F1: a process exec'd — lets the agent track --app/--exe churn
};

struct s3tap_event_hdr {
    __u16 schema_version; // == S3TAP_SCHEMA_VERSION
    __u16 type;           // enum s3tap_event_type
    __u32 cpu;            // which CPU produced it (for debugging)
    __u64 ts_ns;          // CLOCK_MONOTONIC nanoseconds (bpf_ktime_get_ns)
    __u32 tgid;           // thread-group id == the userspace PID
    __u32 tid;            // thread id
    __u64 sock_cookie;    // stable per-socket id (0 if N/A)
};

// (tgid, fd) <-> sock_cookie mapping (M3 E4). Emitted from tcp_v{4,6}_connect (which
// has the `sk`, hence the cookie) paired with the fd stashed at the connect()
// syscall entry — so it runs once per active TCP connect. This is the join the L7
// plaintext path needs: EVT_TLS_WRITE/READ carry (tgid,fd) but no cookie; this maps
// that (tgid,fd) to the connection's cookie. fd numbers are recycled by close(), so
// the agent MUST drop a (tgid,fd) entry when that cookie's TCP close fires.
// Emitted only under --capture-plaintext (the only consumer is the plaintext join).
struct evt_conn_id {
    struct s3tap_event_hdr hdr;  // hdr.sock_cookie = the cookie (sk pointer); hdr.tgid = connecting pid
    __u32 fd;                    // the fd connect() was called on
    __u32 _pad;
};

// Emitted when a TCP connection reaches ESTABLISHED, or — for a failed connect
// (SYN sent, never established) — reconstructed at close with connect_failed=1.
struct evt_tcp_connect {
    struct s3tap_event_hdr hdr;
    __u8  family;            // AF_INET (2) or AF_INET6 (10)
    // IPs are stored in the kernel's v4-mapped IPv6 form (from saddr_v6).
    // For AF_INET the IPv4 octets live in bytes [12..16] (::ffff:a.b.c.d),
    // NOT [0..4]. The decoder must read [12..16] when family == AF_INET.
    __u8  saddr[16];         // source IP, v4-mapped for IPv4
    __u8  daddr[16];         // destination IP, v4-mapped for IPv4
    __u8  connect_failed;    // 1 if SYN was sent but ESTABLISHED never reached
                             //   (reconstructed & emitted at close); was pad@65,
                             //   so this does not change the struct size (80)
    __u16 dport;             // destination port, host byte order
    __u16 sport;             // source port, host byte order
    __u64 connect_latency_ns;// SYN_SENT -> ESTABLISHED duration (0 if failed/passive)
};

// Emitted at TCP_CLOSE. Counters are read straight off struct tcp_sock at the
// full-socket close transition (NOT accumulated by us).
struct evt_tcp_close {
    struct s3tap_event_hdr hdr;
    __u64 bytes_sent;        // tcp_sock.bytes_sent: payload accepted into TCP,
                             //   not peer-acked (may exceed delivered on RST)
    __u64 bytes_recv;        // tcp_sock.bytes_received: in-order bytes consumed
    __u32 retransmit_count;  // tcp_sock.total_retrans: segment-level, incl. TLP
    __u32 srtt_us;           // tcp_sock.srtt_us >> 3 (microseconds); 0 == no sample
    __u64 lifetime_ns;       // since ESTABLISHED (or SYN_SENT if never established);
                             //   0 == birth unknown (LRU-evicted)
    // --- extended path diagnosis (also read off tcp_sock at close) ---
    // All kernel-TCP, so present for ANY client (incl. Go/rustls — no OpenSSL needed).
    __u64 delivery_rate_bps; // kernel delivery-rate estimate, bytes/s (0 == unknown)
    __u32 min_rtt_us;        // tcp_min_rtt: true propagation floor (0 OR u32::MAX == no sample)
    __u32 rttvar_us;         // mdev_us>>2: RTT variation / jitter
    __u32 snd_cwnd;          // congestion window, packets (x mss_cache = cwnd bytes)
    __u32 mss_cache;         // current MSS, bytes
    // Bottleneck attribution (chrono busy-time, RAW jiffies — use as ratios):
    __u32 busy_jiffies;          // time with data queued to send (the ratio base)
    __u32 rwnd_limited_jiffies;  // time blocked on the RECEIVER's window
    __u32 sndbuf_limited_jiffies;// time blocked on the LOCAL send buffer
    // Loss shape (snapshots at close unless noted):
    __u32 lost;              // tcp_sock.lost_out: packets believed lost in-flight
    __u32 sacked_out;        // tcp_sock.sacked_out: SACK'd packets in-flight
    __u32 reordering;        // tcp_sock.reordering: estimated reordering degree (durable)
    __u8  ca_state;          // icsk_ca_state: 0 Open,1 Disorder,2 CWR,3 Recovery,4 Loss
    // Receive-side window (bytes) — caps DOWNLOAD throughput (rcv_wnd / RTT). This is the
    // client-side ceiling the send-side cwnd/delivery_rate can't give for a GET.
    __u32 rcv_wnd;           // tcp_sock.rcv_wnd: current advertised receive window
    __u32 window_clamp;      // tcp_sock.window_clamp: max receive window (the autotuning cap)
    __u32 handshake_us;      // TLS handshake µs: ClientHello -> first app-data egress (0 == none)
    // --- loss-quality / receive-reorder / send rate-limit (all tcp_sock at close; library-agnostic) ---
    __u64 bytes_retrans;     // tcp_sock.bytes_retrans: retransmitted bytes (volume; the honest rate denominator)
    __u32 dsack_dups;        // tcp_sock.dsack_dups: DSACK'd dup retransmits — spurious (reorder/RTO), NOT loss
    __u32 rcv_ooopack;       // tcp_sock.rcv_ooopack: out-of-order packets RECEIVED (download-leg reorder evidence)
    __u8  rate_app_limited;  // tcp_sock.rate_app_limited (:1): the delivery-rate sample was app-limited (send-path)
};

// In-flight TCP sample (Plan 1) — read off struct tcp_sock periodically during a
// connection's life (fentry/tcp_rcv_established tick, rate-limited per connection).
// Every field MIRRORS the evt_tcp_close read of the same name (same units, same
// 0/sentinel "no sample" conventions); the cumulative counters (bytes_*,
// total_retrans, rcv_ooopack) are differenced between consecutive samples by the
// agent (robust to a dropped sample). hdr.ts_ns = sample time, hdr.sock_cookie = sk.
struct evt_tcp_sample {
    struct s3tap_event_hdr hdr;
    __u64 bytes_sent;        // tcp_sock.bytes_sent: cumulative -> Δ = per-interval UPLOAD bytes
    __u64 bytes_recv;        // tcp_sock.bytes_received: cumulative -> Δ = per-interval DOWNLOAD bytes
    __u64 bytes_in_flight;   // (u32)(snd_nxt - snd_una) widened: outstanding/unacked bytes (cwnd-util proxy)
    __u64 delivery_rate_bps; // mss*rate_delivered*1e6/rate_interval_us (bytes/s; 0 == no sample)
    __u32 snd_cwnd;          // tcp_sock.snd_cwnd: congestion window, packets (the ramp/collapse curve)
    __u32 srtt_us;           // tcp_sock.srtt_us >> 3 (microseconds); 0 == no sample
    __u32 min_rtt_us;        // tcp_min_rtt floor (bufferbloat denom); 0 OR U32_MAX == no sample
    __u32 total_retrans;     // tcp_sock.total_retrans: cumulative -> Δ = UPLOAD retransmits this interval
    __u32 rcv_ooopack;       // tcp_sock.rcv_ooopack: cumulative -> Δ = DOWNLOAD out-of-order this interval
    __u32 rcv_wnd;           // tcp_sock.rcv_wnd: receive window — download flow-control ceiling
    __u32 snd_wnd;           // tcp_sock.snd_wnd: peer's advertised window — upload flow-control ceiling
    __u32 lost;              // tcp_sock.lost_out: packets believed lost in-flight (loss shape)
    __u32 sacked_out;        // tcp_sock.sacked_out: SACK'd packets in-flight
    __u8  ca_state;          // icsk_ca_state: 0 Open,1 Disorder,2 CWR,3 Recovery,4 Loss
    __u8  flags;             // bit0 = rate_app_limited (send path waited on the app)
    // 2 B trailing pad -> size 104, align 8, zero internal padding
};

// --- DNS (M2) -----------------------------------------------------------
// QNAME_MAX bounds the in-kernel qname decode (a presentation-form DNS name is
// at most 253 chars; 255 is a safe cap). DNS_PAYLOAD_MAX bounds the raw response
// payload we ship for userspace parsing — 512 tracks the classic UDP DNS limit
// (a larger response sets the TC bit and retries over TCP, which we don't
// follow; EDNS0 responses past this are clipped). The copy masks
// with DNS_PAYLOAD_MAX-1 for a verifier-provable bound, so the effective cap is
// 511 bytes. Keep these in sync with the Rust mirror (offsets verified against a
// native compile, see tests/layout.rs).
#define QNAME_MAX       255
#define DNS_PAYLOAD_MAX 512

// Emitted when a DNS query is sent to udp/:53 (active resolver path). The qname
// is decoded from wire labels into presentation form ("b.s3.us-east-1.amazonaws.com").
struct evt_dns_query {
    // hdr.sock_cookie = the resolver's UDP sk-pointer; with txn_id it is the
    // query<->response join key. KASLR-bearing but host-private: DNS events never
    // produce a Connection, so this cookie is never emitted (only the TCP
    // Connection.sock_cookie reaches output, and the CLI obscures that).
    struct s3tap_event_hdr hdr;
    __u16 txn_id;                // DNS header ID — joins this query to its response
    __u8  proto;                 // IPPROTO_UDP (17); TCP DNS is a later addition
    __u8  qname_len;             // bytes of `qname` used (<= QNAME_MAX)
    __u8  qname_truncated;       // 1 if the real name was longer than QNAME_MAX
    char  qname[QNAME_MAX];      // presentation form, NOT NUL-terminated (use qname_len)
};

// Emitted when a DNS response arrives from udp/:53. Carries the RAW DNS message
// (header + question + answer RRs) for the agent to parse in userspace — in-kernel
// RR-walking blows the verifier's instruction budget, and Rust parsing is both
// safe and far more testable. `payload[0..payload_len]` is the message starting
// at the DNS header (txn_id is payload[0..2], big-endian).
struct evt_dns_response {
    struct s3tap_event_hdr hdr;
    __u16 payload_len;               // valid bytes in `payload` (<= DNS_PAYLOAD_MAX)
    __u8  payload[DNS_PAYLOAD_MAX];   // raw DNS message from the UDP datagram
};

// Emitted at the RETURN of a libc getaddrinfo() call (uprobe entry+exit folded
// into one exit event). Captures the resolver-call latency the application
// actually paid — including the nscd / glibc-cache path that has no udp/:53 wire
// traffic. NB: `saw_wire_activity` is currently UNUSED/RESERVED — the agent does
// NOT read it; it derives cache-hit itself by overlapping this call's window
// against the :53 query/response events it already tracks (see
// Correlator::on_getaddrinfo). Kept as a zero-filled field so the layout stays
// stable; wire it up or drop it in a future ABI change, but don't trust it.
struct evt_getaddrinfo {
    struct s3tap_event_hdr hdr;
    __u64 latency_ns;            // exit_ts - entry_ts
    __s32 ret;                   // getaddrinfo() return code (0 == success)
    __u8  hostname_len;          // bytes of `hostname` used (<= QNAME_MAX)
    __u8  hostname_truncated;    // 1 if the real hostname was longer
    __u8  saw_wire_activity;     // RESERVED, always 0 — see note above (agent ignores it)
    char  hostname[QNAME_MAX];   // the node argument, NOT NUL-terminated (use hostname_len)
};

// --- TLS (M3) -----------------------------------------------------------
// SNI server_name is a hostname, so RFC 6066 bounds it at 255 chars; 255 caps it
// (same as QNAME_MAX). The `sni_truncated` flag is set if a longer name was
// clipped. Keep in sync with the Rust mirror (offsets verified against a native
// compile, see tests/layout.rs).
#define SNI_MAX 255

// Emitted when a TLS ClientHello is seen on a connection's egress (kprobe on the
// TCP send path). Library-agnostic: the SNI is parsed straight off the wire, not
// from any TLS library, so it covers OpenSSL, Go crypto/tls, BoringSSL, etc.
// hdr.sock_cookie is the connection's sk-pointer, so this joins directly to the
// TCP connection record (no SSL*->fd->cookie chain needed). `sni` is the client's
// requested server_name in presentation form, NOT NUL-terminated (use sni_len).
// No handshake timing here: a single send-side hook can't measure it (a later
// slice may add it from the response side or an OpenSSL uprobe).
// ServerHello parsed off the INGRESS path (M-path Stage 2): the NEGOTIATED TLS version
// (supported_versions if present, else legacy server_version) and the chosen cipher suite.
struct evt_tls_server {
    struct s3tap_event_hdr hdr;
    __u16 version;               // negotiated version: 0x0304 = TLS 1.3, 0x0303 = 1.2, ...
    __u16 cipher;                // negotiated cipher suite code (e.g. 0x1301)
};

struct evt_tls_handshake {
    struct s3tap_event_hdr hdr;
    __u16 tls_version;           // legacy client_version at hello offset 9 (e.g. 0x0303); NOT
                                 // negotiated — supported_versions is not parsed. Currently unread.
    __u8  sni_len;               // bytes of `sni` used (<= SNI_MAX)
    __u8  sni_truncated;         // 1 if the real SNI was longer than SNI_MAX
    char  sni[SNI_MAX];          // client SNI, NOT NUL-terminated (use sni_len)
};

// Bounded plaintext prefix captured at an SSL_write / SSL_read boundary (libssl
// uprobes, M3 E3). 4096 holds an HTTP request line + headers (or a status line +
// headers); the probe never copies more than this — `plaintext_len` carries the
// uncapped length for byte accounting (see its caveat below).
//
// Library-specific (OpenSSL/libssl), and needs the SSL*->fd chain to join the
// connection: `fd` comes from SSL_set_fd / SSL_set_rfd / SSL_set_wfd (0 when
// unobserved -> the op is `partial`). E4 maps (tgid,fd)->sock_cookie; until then
// events stage by (tgid,fd). hdr.sock_cookie is UNSET (0) here.
//
// JOIN-KEY CAVEAT for E4: (tgid,fd) is valid ONLY within a connection's open
// interval — fd numbers are recycled by close(), so the same (tgid,fd) names
// different sockets over time (constant under connection-pool keep-alive). E4's
// (tgid,fd)->cookie table MUST be invalidated when that socket's TCP close fires;
// a bare global (tgid,fd) lookup would mis-attribute plaintext under fd reuse.
//
// COVERAGE LIMITS (capture absent/partial): SSL_set_bio-only clients (e.g. Node's
// BIO pairs) -> fd 0 / partial; non-OpenSSL TLS (Go, rustls, static BoringSSL) has
// no SSL_* symbols at all. The common S3 clients (Python ssl / boto3, curl) use
// SSL_set_fd + SSL_write/SSL_read and are captured. SSL_write_ex/SSL_read_ex (the
// OpenSSL 1.1.1+ size_t API) ARE hooked -- handle_ssl_write_ex and the
// handle_ssl_read_ex_entry/_exit pair, attached optionally since the symbols are
// absent on older libssl.
#define HDR_CAP 4096
struct evt_tls_data {            // EVT_TLS_WRITE / EVT_TLS_READ (the HEADS only)
    struct s3tap_event_hdr hdr;
    __u32 fd;                    // target socket fd (0 == unknown; no SSL_set_fd/rfd/wfd seen)
    __u32 plaintext_len;         // length passed to SSL_write/read at the boundary. CAVEAT: for
                                 // SSL_write this is the INTENDED (entry `num`), not bytes written
                                 // — under SSL_MODE_ENABLE_PARTIAL_WRITE it can exceed wire bytes.
    __u16 captured_len;          // bytes actually copied into `data` (<= HDR_CAP)
    __u8  captured_truncated;    // 1 if plaintext_len > captured_len
    __u8  _pad;
    __u8  data[HDR_CAP];         // header prefix only; request/status line + headers
};

// EVT_TLS_READ_BODY: a response BODY read, LENGTH ONLY. This is the HIGHEST-RATE event
// in the system — one per SSL_read chunk of every download, so a 1 GiB GetObject read in
// 16 KiB chunks emits ~65k of them. It therefore gets its OWN 40-byte struct instead of
// the 4144-byte evt_tls_data: at 4144 B that GET pushes 271 MB through the 2 MiB
// tls_events ring vs 2.6 MB here, and a full ring makes bpf_ringbuf_reserve fail for an
// UNRELATED event on the same ring (an EVT_CONN_ID drop leaves a whole connection's
// Operation partial: no bucket, no dns, no tcp_connect_ns). The consumer
// (Correlator::on_tls_read_body) only ever reads hdr.tgid, hdr.ts_ns, hdr.sock_cookie, fd
// and plaintext_len, so the other 4104 bytes were pure ring pressure.
//
// It KEEPS tag 23: the agent dispatches on the tag BEFORE the length, and the .o is
// embedded in the binary via build.rs, so probe and agent always ship from one build.
// NB the layout is coincidentally identical to evt_conn_id (40 B, u32 at 32, u32 at 36).
// That is harmless because dispatch is tag-first — but do NOT be tempted to reuse
// evt_conn_id for this: its offset-36 field is `_pad`, so the two types would silently
// agree on bytes while disagreeing on meaning.
struct evt_tls_body {            // EVT_TLS_READ_BODY — 32+4+4 = 40, align 8, no padding
    struct s3tap_event_hdr hdr;  // join key is (tgid,fd). hdr.sock_cookie is UNSET (0) on the
                                 //   SSL_set_fd path; on the BIO path (fd==0) it carries the
                                 //   tid-inferred cookie, which the consumer needs to keep
                                 //   concurrent BIO connections' chunks apart.
    __u32 fd;                    // target socket fd (0 == unknown, as in evt_tls_data)
    __u32 plaintext_len;         // bytes SSL_read returned for this body chunk
};

// Process exec (M4 F1) — emitted from the sched_process_exec tracepoint
// in process context, so comm/cgroup_id are reliable. Lets the agent track --app/--exe
// process churn (JVM/gunicorn/Spark worker forks): on each exec it re-evaluates the
// match and updates filter_pids live. Emitted ONLY in ALLOWLIST mode (no need when
// not filtering). hdr.tgid = the exec'ing process; hdr.sock_cookie = 0.
#define COMM_LEN 16
#define EXE_MAX  256
struct evt_proc_exec {
    struct s3tap_event_hdr hdr;
    __u64 cgroup_id;             // bpf_get_current_cgroup_id()
    __u8  comm[COMM_LEN];        // bpf_get_current_comm() — the short name
    __u8  exe_len;               // bytes of `exe` used (excl. NUL)
    __u8  exe_truncated;         // 1 if the path was longer than EXE_MAX
    __u16 _pad;
    char  exe[EXE_MAX];          // exec'd path from the tracepoint filename (best-effort)
};

#endif // S3TAP_EVENTS_H
