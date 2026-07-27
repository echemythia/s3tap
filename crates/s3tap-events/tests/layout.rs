// crates/s3tap-events/tests/layout.rs
//
// THE ABI guard, in two halves that only work together.
//
//  1. The offset pins below (`*_layout`): every Rust mirror's size, alignment and
//     field offsets, against literals taken from a native compile of the C. These
//     pin the WIDTHS and the padding the Rust side computes.
//  2. `c_header_matches_the_rust_mirrors`: the same Rust mirrors against the ACTUAL
//     TEXT of bpf/include/s3tap_events.h, compiled in with `include_str!`. Schema
//     version, the `EVT_*` tag values, the bounded-tail `#define`s, and every struct's
//     member names IN DECLARATION ORDER with their element types and array extents.
//
// Half 1 alone pinned nothing about the C: it asserted that the Rust struct matched
// integers a human transcribed into this file, so reverting S3TAP_SCHEMA_VERSION to 1,
// or inserting a `__u32 pad;` into `struct evt_tls_body`, left the whole workspace green
// while the agent decoded nothing (or the wrong field) at runtime. That is the same
// defect `cap_string_matches_setcap_sh` found in the setcap pin: restating your own
// literals is not a pin. Half 2 is the fix, in the same source-text-pinning style as
// `bpf_c_declares_the_maps_the_loader_looks_up` (s3tap-cli/src/main.rs) and
// `setcap_sh_caps` (s3tap-cli/src/elevate.rs).
//
// `mutation_proofs` at the bottom is the guard's own test suite: each mutation is applied
// to a COPY of the real header and the guard must complain about it by name. A guard whose
// parser silently matches nothing reports a pass, which is exactly the failure being fixed.
//
// Authoritative numbers (from compiling the C structs): hdr=32, connect=80,
// close=152. Note connect is 80, NOT 88: `saddr` is a u8 array (1-byte aligned)
// so it sits immediately after `family` with no padding. `connect_failed`
// reuses the former pad byte right after `daddr` (@65), so the struct's only
// remaining padding is 2 bytes (@70-71) before the 8-aligned `connect_latency_ns`.

use s3tap_events::{
    EventHdr, EvtTcpClose, EvtTcpConnect, EVT_TCP_CLOSE, EVT_TCP_CONNECT,
};
use std::mem::{align_of, offset_of, size_of};

#[test]
fn header_layout() {
    assert_eq!(size_of::<EventHdr>(), 32);
    assert_eq!(align_of::<EventHdr>(), 8);
    assert_eq!(offset_of!(EventHdr, schema_version), 0);
    assert_eq!(offset_of!(EventHdr, type_), 2);
    assert_eq!(offset_of!(EventHdr, cpu), 4);
    assert_eq!(offset_of!(EventHdr, ts_ns), 8);
    assert_eq!(offset_of!(EventHdr, tgid), 16);
    assert_eq!(offset_of!(EventHdr, tid), 20);
    assert_eq!(offset_of!(EventHdr, sock_cookie), 24);
}

#[test]
fn connect_layout() {
    assert_eq!(size_of::<EvtTcpConnect>(), 80);
    assert_eq!(offset_of!(EvtTcpConnect, hdr), 0);
    assert_eq!(offset_of!(EvtTcpConnect, family), 32);
    assert_eq!(offset_of!(EvtTcpConnect, saddr), 33);
    assert_eq!(offset_of!(EvtTcpConnect, daddr), 49);
    assert_eq!(offset_of!(EvtTcpConnect, connect_failed), 65); // reused pad byte
    assert_eq!(offset_of!(EvtTcpConnect, dport), 66);
    assert_eq!(offset_of!(EvtTcpConnect, sport), 68);
    assert_eq!(offset_of!(EvtTcpConnect, connect_latency_ns), 72);
}

#[test]
fn close_layout() {
    assert_eq!(size_of::<EvtTcpClose>(), 152);
    assert_eq!(offset_of!(EvtTcpClose, hdr), 0);
    assert_eq!(offset_of!(EvtTcpClose, bytes_sent), 32);
    assert_eq!(offset_of!(EvtTcpClose, bytes_recv), 40);
    assert_eq!(offset_of!(EvtTcpClose, retransmit_count), 48);
    assert_eq!(offset_of!(EvtTcpClose, srtt_us), 52);
    assert_eq!(offset_of!(EvtTcpClose, lifetime_ns), 56);
    assert_eq!(offset_of!(EvtTcpClose, delivery_rate_bps), 64);
    assert_eq!(offset_of!(EvtTcpClose, min_rtt_us), 72);
    assert_eq!(offset_of!(EvtTcpClose, rttvar_us), 76);
    assert_eq!(offset_of!(EvtTcpClose, snd_cwnd), 80);
    assert_eq!(offset_of!(EvtTcpClose, mss_cache), 84);
    assert_eq!(offset_of!(EvtTcpClose, busy_jiffies), 88);
    assert_eq!(offset_of!(EvtTcpClose, rwnd_limited_jiffies), 92);
    assert_eq!(offset_of!(EvtTcpClose, sndbuf_limited_jiffies), 96);
    assert_eq!(offset_of!(EvtTcpClose, lost), 100);
    assert_eq!(offset_of!(EvtTcpClose, sacked_out), 104);
    assert_eq!(offset_of!(EvtTcpClose, reordering), 108);
    assert_eq!(offset_of!(EvtTcpClose, ca_state), 112);
    assert_eq!(offset_of!(EvtTcpClose, rcv_wnd), 116);
    assert_eq!(offset_of!(EvtTcpClose, window_clamp), 120);
    assert_eq!(offset_of!(EvtTcpClose, handshake_us), 124);
    assert_eq!(offset_of!(EvtTcpClose, bytes_retrans), 128);
    assert_eq!(offset_of!(EvtTcpClose, dsack_dups), 136);
    assert_eq!(offset_of!(EvtTcpClose, rcv_ooopack), 140);
    assert_eq!(offset_of!(EvtTcpClose, rate_app_limited), 144);
}

// Authoritative numbers (native compile of struct evt_tcp_sample): size=104, with a
// 2-byte trailing pad after `flags`@101 to the 8-byte alignment. Every field offset
// mirrors the plan's struct table.
#[test]
fn tcp_sample_layout() {
    use s3tap_events::EvtTcpSample;
    assert_eq!(size_of::<EvtTcpSample>(), 104);
    assert_eq!(align_of::<EvtTcpSample>(), 8);
    assert_eq!(offset_of!(EvtTcpSample, hdr), 0);
    assert_eq!(offset_of!(EvtTcpSample, bytes_sent), 32);
    assert_eq!(offset_of!(EvtTcpSample, bytes_recv), 40);
    assert_eq!(offset_of!(EvtTcpSample, bytes_in_flight), 48);
    assert_eq!(offset_of!(EvtTcpSample, delivery_rate_bps), 56);
    assert_eq!(offset_of!(EvtTcpSample, snd_cwnd), 64);
    assert_eq!(offset_of!(EvtTcpSample, srtt_us), 68);
    assert_eq!(offset_of!(EvtTcpSample, min_rtt_us), 72);
    assert_eq!(offset_of!(EvtTcpSample, total_retrans), 76);
    assert_eq!(offset_of!(EvtTcpSample, rcv_ooopack), 80);
    assert_eq!(offset_of!(EvtTcpSample, rcv_wnd), 84);
    assert_eq!(offset_of!(EvtTcpSample, snd_wnd), 88);
    assert_eq!(offset_of!(EvtTcpSample, lost), 92);
    assert_eq!(offset_of!(EvtTcpSample, sacked_out), 96);
    assert_eq!(offset_of!(EvtTcpSample, ca_state), 100);
    assert_eq!(offset_of!(EvtTcpSample, flags), 101);
}

// The tag VALUES. These are literals on purpose (a reader wants to see 23 next to
// EVT_TLS_READ_BODY), but literals alone pinned nothing: `event_tags_match_c_enum`
// in the C-header section below is what makes them a pin, by reading the same
// numbers out of `enum s3tap_event_type`.
#[test]
fn event_type_tags_match_c_enum() {
    assert_eq!(s3tap_events::EVT_DNS_QUERY, 1);
    assert_eq!(s3tap_events::EVT_DNS_RESPONSE, 2);
    assert_eq!(s3tap_events::EVT_GETADDRINFO, 3);
    assert_eq!(s3tap_events::EVT_CONN_ID, 10);
    assert_eq!(EVT_TCP_CONNECT, 11);
    assert_eq!(EVT_TCP_CLOSE, 13);
    assert_eq!(s3tap_events::EVT_TCP_SAMPLE, 14);
    assert_eq!(s3tap_events::EVT_TLS_HANDSHAKE, 20);
    assert_eq!(s3tap_events::EVT_TLS_WRITE, 21);
    assert_eq!(s3tap_events::EVT_TLS_READ, 22);
    assert_eq!(s3tap_events::EVT_TLS_READ_BODY, 23);
    assert_eq!(s3tap_events::EVT_TLS_SERVER, 24);
}

#[test]
fn tls_server_layout() {
    use s3tap_events::EvtTlsServer;
    assert_eq!(size_of::<EvtTlsServer>(), 40);
    assert_eq!(offset_of!(EvtTlsServer, hdr), 0);
    assert_eq!(offset_of!(EvtTlsServer, version), 32);
    assert_eq!(offset_of!(EvtTlsServer, cipher), 34);
}

// Authoritative DNS numbers (from a native compile of the C structs): query=296,
// response=552, getaddrinfo=304. Each event has tail padding to its 8-byte
// alignment, reproduced by `#[repr(C)]`.
#[test]
fn dns_query_layout() {
    use s3tap_events::EvtDnsQuery;
    assert_eq!(size_of::<EvtDnsQuery>(), 296);
    assert_eq!(offset_of!(EvtDnsQuery, hdr), 0);
    assert_eq!(offset_of!(EvtDnsQuery, txn_id), 32);
    assert_eq!(offset_of!(EvtDnsQuery, proto), 34);
    assert_eq!(offset_of!(EvtDnsQuery, qname_len), 35);
    assert_eq!(offset_of!(EvtDnsQuery, qname_truncated), 36);
    assert_eq!(offset_of!(EvtDnsQuery, qname), 37);
}

#[test]
fn dns_response_layout() {
    use s3tap_events::EvtDnsResponse;
    assert_eq!(size_of::<EvtDnsResponse>(), 552);
    assert_eq!(offset_of!(EvtDnsResponse, hdr), 0);
    assert_eq!(offset_of!(EvtDnsResponse, payload_len), 32);
    assert_eq!(offset_of!(EvtDnsResponse, payload), 34);
}

// Authoritative TLS numbers (from a native compile of struct evt_tls_handshake):
// size=296, tls_version=32, sni_len=34, sni_truncated=35, sni=36.
#[test]
fn tls_handshake_layout() {
    use s3tap_events::EvtTlsHandshake;
    assert_eq!(size_of::<EvtTlsHandshake>(), 296);
    assert_eq!(offset_of!(EvtTlsHandshake, hdr), 0);
    assert_eq!(offset_of!(EvtTlsHandshake, tls_version), 32);
    assert_eq!(offset_of!(EvtTlsHandshake, sni_len), 34);
    assert_eq!(offset_of!(EvtTlsHandshake, sni_truncated), 35);
    assert_eq!(offset_of!(EvtTlsHandshake, sni), 36);
}

// Authoritative numbers (native compile of struct evt_tls_data): size=4144, data@44.
#[test]
fn tls_data_layout() {
    use s3tap_events::EvtTlsData;
    assert_eq!(size_of::<EvtTlsData>(), 4144);
    assert_eq!(align_of::<EvtTlsData>(), 8);
    assert_eq!(offset_of!(EvtTlsData, hdr), 0);
    assert_eq!(offset_of!(EvtTlsData, fd), 32);
    assert_eq!(offset_of!(EvtTlsData, plaintext_len), 36);
    assert_eq!(offset_of!(EvtTlsData, captured_len), 40);
    assert_eq!(offset_of!(EvtTlsData, captured_truncated), 42);
    assert_eq!(offset_of!(EvtTlsData, data), 44);
}

// Authoritative numbers (native compile of struct evt_tls_body): size=40 (32+4+4, no
// padding — the whole point of splitting EVT_TLS_READ_BODY off the 4144-byte
// evt_tls_data). Deliberately the SAME shape as evt_conn_id: harmless because parse
// dispatches on the tag first, but it means these offsets must be pinned independently
// so a future edit to either can't quietly make them disagree in meaning at offset 36.
// NB size+offsets do NOT catch an inserted `__u32 pad;` before `plaintext_len` on the C
// side (still 40 B, still decodes, reads 0) — the member-NAME order check does.
#[test]
fn tls_body_layout() {
    use s3tap_events::EvtTlsBody;
    assert_eq!(size_of::<EvtTlsBody>(), 40);
    assert_eq!(align_of::<EvtTlsBody>(), 8);
    assert_eq!(offset_of!(EvtTlsBody, hdr), 0);
    assert_eq!(offset_of!(EvtTlsBody, fd), 32);
    assert_eq!(offset_of!(EvtTlsBody, plaintext_len), 36);
}

#[test]
fn conn_id_layout() {
    use s3tap_events::EvtConnId;
    assert_eq!(size_of::<EvtConnId>(), 40);
    assert_eq!(offset_of!(EvtConnId, hdr), 0);
    assert_eq!(offset_of!(EvtConnId, fd), 32);
}

#[test]
fn getaddrinfo_layout() {
    use s3tap_events::EvtGetaddrinfo;
    assert_eq!(size_of::<EvtGetaddrinfo>(), 304);
    assert_eq!(offset_of!(EvtGetaddrinfo, hdr), 0);
    assert_eq!(offset_of!(EvtGetaddrinfo, latency_ns), 32);
    assert_eq!(offset_of!(EvtGetaddrinfo, ret), 40);
    assert_eq!(offset_of!(EvtGetaddrinfo, hostname_len), 44);
    assert_eq!(offset_of!(EvtGetaddrinfo, hostname_truncated), 45);
    assert_eq!(offset_of!(EvtGetaddrinfo, saw_wire_activity), 46);
    assert_eq!(offset_of!(EvtGetaddrinfo, hostname), 47);
}

// Authoritative numbers (native compile of struct evt_proc_exec): size=320,
// cgroup_id@32, comm@40, exe_len@56, exe_truncated@57, _pad@58, exe@60. The u16
// _pad keeps `exe` deterministically 4-aligned-equivalent at 60 (no compiler gap).
#[test]
fn proc_exec_layout() {
    use s3tap_events::EvtProcExec;
    assert_eq!(size_of::<EvtProcExec>(), 320);
    assert_eq!(align_of::<EvtProcExec>(), 8);
    assert_eq!(offset_of!(EvtProcExec, hdr), 0);
    assert_eq!(offset_of!(EvtProcExec, cgroup_id), 32);
    assert_eq!(offset_of!(EvtProcExec, comm), 40);
    assert_eq!(offset_of!(EvtProcExec, exe_len), 56);
    assert_eq!(offset_of!(EvtProcExec, exe_truncated), 57);
    assert_eq!(offset_of!(EvtProcExec, exe), 60);
}

#[test]
fn proc_exec_tag_matches_c_enum() {
    assert_eq!(s3tap_events::EVT_PROC_EXEC, 30);
}

#[test]
fn peek_type_reads_the_tag() {
    // A buffer exactly header-sized with the type field (offset 2) set.
    let mut buf = vec![0u8; size_of::<EventHdr>()];
    buf[2..4].copy_from_slice(&EVT_TCP_CONNECT.to_ne_bytes());
    assert_eq!(s3tap_events::peek_type(&buf), Some(EVT_TCP_CONNECT));

    // Too short to hold a header -> None.
    assert_eq!(s3tap_events::peek_type(&[0u8; 4]), None);
}

// ===========================================================================
// Half 2: the C header itself.
// ===========================================================================

mod c_header {
    //! A small, deliberately strict C parser plus the Rust<->C comparison.
    //!
    //! Strict is the point. The input is one known file, so anything this parser does
    //! not understand is a construct that arrived without anyone updating the guard,
    //! and the guard's job is to say so rather than skip the struct and report a pass.
    //! Every "unsupported" path below records an error; `check_c_header` returns them
    //! all and the test fails on a non-empty list.

    use std::collections::{BTreeMap, BTreeSet};
    use std::mem::{offset_of, size_of};

    use s3tap_events::{
        EventHdr, EvtConnId, EvtDnsQuery, EvtDnsResponse, EvtGetaddrinfo, EvtProcExec,
        EvtTcpClose, EvtTcpConnect, EvtTcpSample, EvtTlsBody, EvtTlsData, EvtTlsHandshake,
        EvtTlsServer, COMM_LEN, DNS_PAYLOAD_MAX, EXE_MAX, HDR_CAP, QNAME_MAX, SCHEMA_VERSION,
        SNI_MAX,
    };

    /// The REAL header, compiled in, so this reads the same text `clang` compiles into
    /// the probe object. (`tests/layout.rs` -> three levels up is the repo root.) Same
    /// source-text pinning as `setcap_sh_caps` in s3tap-cli/src/elevate.rs.
    pub const HEADER: &str = include_str!("../../../bpf/include/s3tap_events.h");

    /// Every `struct` the C header defines must be accounted for. A count, not just a
    /// per-struct lookup: a parser that quietly matched nothing would otherwise report a
    /// clean pass, which is the exact failure mode this file exists to fix.
    const EXPECTED_STRUCTS: usize = 13;

    // -----------------------------------------------------------------------
    // The Rust side of the comparison.
    // -----------------------------------------------------------------------

    /// One field of a Rust mirror, as declared in the `mirror!` table below.
    #[derive(Debug)]
    pub struct RustField {
        /// The Rust identifier (`stringify!`d from the real field, so it cannot be a typo).
        pub rust_name: &'static str,
        /// The C member it must mirror (see [`c_ident`]).
        pub c_name: String,
        /// The element type, checked against the real field type at COMPILE time.
        pub elem: &'static str,
        /// Array extent, if the field is an array.
        pub extent: Option<usize>,
        /// Where the field actually sits, for the failure message.
        pub offset: usize,
    }

    #[derive(Debug)]
    pub struct RustStruct {
        pub rust_name: &'static str,
        pub c_name: &'static str,
        pub size: usize,
        pub fields: Vec<RustField>,
    }

    /// The C member name a Rust field mirrors: identical, except that a trailing
    /// underscore escapes a Rust keyword (`type_` mirrors C's `type`).
    fn c_ident(rust: &str) -> String {
        match rust {
            "type_" => "type".to_string(),
            other => other.to_string(),
        }
    }

    /// Pins one listed field's ELEMENT TYPE to the real Rust field type. `&$elem` /
    /// `&[$elem; $n]` admit no coercion, so `__u64 -> __s64` on the C side (which moves
    /// no offset and changes no size) becomes a mismatch here.
    macro_rules! mirror_ty {
        ($v:expr, $f:ident : $elem:ident) => {
            let _: &$elem = &$v.$f;
        };
        ($v:expr, $f:ident : $elem:ident [$n:expr]) => {
            let _: &[$elem; $n] = &$v.$f;
        };
    }

    macro_rules! mirror_extent {
        () => {
            None
        };
        ([$n:expr]) => {
            Some($n)
        };
    }

    /// Declare a Rust mirror and the C struct it mirrors, field by field.
    ///
    /// The field list is NOT a transcription: `offset_of!` and the destructuring pattern
    /// make the compiler prove every listed identifier is a real field, `mirror_ty!` proves
    /// the element type, and the pattern (which has no `..`) proves the list is EXHAUSTIVE,
    /// so a field added to the Rust mirror without being listed here fails to compile.
    macro_rules! mirror {
        ($rust:ident => $c:literal { $( $f:ident : $elem:ident $([$n:expr])? ),+ $(,)? }) => {{
            #[allow(dead_code, unused_variables)]
            fn compile_time_pin(v: &$rust) {
                $( mirror_ty!(v, $f : $elem $([$n])?); )+
                // No `..`: this is the exhaustiveness proof. A field added to the Rust
                // mirror without being added here fails the BUILD with "pattern requires
                // `..`", pointing at the mirror!() invocation that fell behind. Do NOT
                // "fix" it by adding `..` — that would let a Rust field go unpinned.
                let $rust { $( $f: _ ),+ } = v;
            }
            RustStruct {
                rust_name: stringify!($rust),
                c_name: $c,
                size: size_of::<$rust>(),
                fields: vec![$(
                    RustField {
                        rust_name: stringify!($f),
                        c_name: c_ident(stringify!($f)),
                        elem: stringify!($elem),
                        extent: mirror_extent!($([$n])?),
                        offset: offset_of!($rust, $f),
                    }
                ),+],
            }
        }};
    }

    /// Every Rust mirror, in the order the header declares them.
    pub fn mirrors() -> Vec<RustStruct> {
        vec![
            mirror!(EventHdr => "s3tap_event_hdr" {
                schema_version: u16,
                type_: u16,
                cpu: u32,
                ts_ns: u64,
                tgid: u32,
                tid: u32,
                sock_cookie: u64,
            }),
            mirror!(EvtConnId => "evt_conn_id" {
                hdr: EventHdr,
                fd: u32,
                _pad: u32,
            }),
            mirror!(EvtTcpConnect => "evt_tcp_connect" {
                hdr: EventHdr,
                family: u8,
                saddr: u8[16],
                daddr: u8[16],
                connect_failed: u8,
                dport: u16,
                sport: u16,
                connect_latency_ns: u64,
            }),
            mirror!(EvtTcpClose => "evt_tcp_close" {
                hdr: EventHdr,
                bytes_sent: u64,
                bytes_recv: u64,
                retransmit_count: u32,
                srtt_us: u32,
                lifetime_ns: u64,
                delivery_rate_bps: u64,
                min_rtt_us: u32,
                rttvar_us: u32,
                snd_cwnd: u32,
                mss_cache: u32,
                busy_jiffies: u32,
                rwnd_limited_jiffies: u32,
                sndbuf_limited_jiffies: u32,
                lost: u32,
                sacked_out: u32,
                reordering: u32,
                ca_state: u8,
                rcv_wnd: u32,
                window_clamp: u32,
                handshake_us: u32,
                bytes_retrans: u64,
                dsack_dups: u32,
                rcv_ooopack: u32,
                rate_app_limited: u8,
            }),
            mirror!(EvtTcpSample => "evt_tcp_sample" {
                hdr: EventHdr,
                bytes_sent: u64,
                bytes_recv: u64,
                bytes_in_flight: u64,
                delivery_rate_bps: u64,
                snd_cwnd: u32,
                srtt_us: u32,
                min_rtt_us: u32,
                total_retrans: u32,
                rcv_ooopack: u32,
                rcv_wnd: u32,
                snd_wnd: u32,
                lost: u32,
                sacked_out: u32,
                ca_state: u8,
                flags: u8,
            }),
            mirror!(EvtDnsQuery => "evt_dns_query" {
                hdr: EventHdr,
                txn_id: u16,
                proto: u8,
                qname_len: u8,
                qname_truncated: u8,
                qname: u8[QNAME_MAX],
            }),
            mirror!(EvtDnsResponse => "evt_dns_response" {
                hdr: EventHdr,
                payload_len: u16,
                payload: u8[DNS_PAYLOAD_MAX],
            }),
            mirror!(EvtGetaddrinfo => "evt_getaddrinfo" {
                hdr: EventHdr,
                latency_ns: u64,
                ret: i32,
                hostname_len: u8,
                hostname_truncated: u8,
                saw_wire_activity: u8,
                hostname: u8[QNAME_MAX],
            }),
            mirror!(EvtTlsServer => "evt_tls_server" {
                hdr: EventHdr,
                version: u16,
                cipher: u16,
            }),
            mirror!(EvtTlsHandshake => "evt_tls_handshake" {
                hdr: EventHdr,
                tls_version: u16,
                sni_len: u8,
                sni_truncated: u8,
                sni: u8[SNI_MAX],
            }),
            mirror!(EvtTlsData => "evt_tls_data" {
                hdr: EventHdr,
                fd: u32,
                plaintext_len: u32,
                captured_len: u16,
                captured_truncated: u8,
                _pad: u8,
                data: u8[HDR_CAP],
            }),
            mirror!(EvtTlsBody => "evt_tls_body" {
                hdr: EventHdr,
                fd: u32,
                plaintext_len: u32,
            }),
            mirror!(EvtProcExec => "evt_proc_exec" {
                hdr: EventHdr,
                cgroup_id: u64,
                comm: u8[COMM_LEN],
                exe_len: u8,
                exe_truncated: u8,
                _pad: u16,
                exe: u8[EXE_MAX],
            }),
        ]
    }

    /// The `EVT_*` tags, paired with the Rust constant each must equal. The VALUES come
    /// from Rust; the names are the coupling key, and every C enumerator must be listed
    /// (checked below), so a tag added to the C forces a Rust constant.
    fn rust_tags() -> Vec<(&'static str, i64)> {
        use s3tap_events as e;
        vec![
            ("EVT_DNS_QUERY", i64::from(e::EVT_DNS_QUERY)),
            ("EVT_DNS_RESPONSE", i64::from(e::EVT_DNS_RESPONSE)),
            ("EVT_GETADDRINFO", i64::from(e::EVT_GETADDRINFO)),
            ("EVT_CONN_ID", i64::from(e::EVT_CONN_ID)),
            ("EVT_TCP_CONNECT", i64::from(e::EVT_TCP_CONNECT)),
            ("EVT_TCP_CLOSE", i64::from(e::EVT_TCP_CLOSE)),
            ("EVT_TCP_SAMPLE", i64::from(e::EVT_TCP_SAMPLE)),
            ("EVT_TLS_HANDSHAKE", i64::from(e::EVT_TLS_HANDSHAKE)),
            ("EVT_TLS_WRITE", i64::from(e::EVT_TLS_WRITE)),
            ("EVT_TLS_READ", i64::from(e::EVT_TLS_READ)),
            ("EVT_TLS_READ_BODY", i64::from(e::EVT_TLS_READ_BODY)),
            ("EVT_TLS_SERVER", i64::from(e::EVT_TLS_SERVER)),
            ("EVT_PROC_EXEC", i64::from(e::EVT_PROC_EXEC)),
        ]
    }

    /// The bounded tails, paired with the Rust constant each `#define` must equal. These
    /// are invisible to the offset pins: the Rust structs size their arrays from the Rust
    /// consts, so `#define QNAME_MAX 254` shrinks only the C struct.
    fn rust_defines() -> Vec<(&'static str, i64)> {
        vec![
            ("QNAME_MAX", QNAME_MAX as i64),
            ("SNI_MAX", SNI_MAX as i64),
            ("DNS_PAYLOAD_MAX", DNS_PAYLOAD_MAX as i64),
            ("HDR_CAP", HDR_CAP as i64),
            ("COMM_LEN", COMM_LEN as i64),
            ("EXE_MAX", EXE_MAX as i64),
        ]
    }

    // -----------------------------------------------------------------------
    // The C side: parsing.
    // -----------------------------------------------------------------------

    #[derive(Debug)]
    pub struct CMember {
        pub name: String,
        /// The C type text as written, e.g. `__u32` or `struct s3tap_event_hdr`.
        pub ctype: String,
        /// The Rust element type that C type must be mirrored by.
        pub rust_elem: &'static str,
        pub extent: Option<usize>,
    }

    #[derive(Debug)]
    pub struct CStruct {
        pub name: String,
        pub members: Vec<CMember>,
    }

    /// Replace every comment with equivalent whitespace, preserving line structure.
    /// String and char literals are skipped over so a `//` inside one survives (the
    /// header has none today; a parser that only works on today's text is not a guard).
    fn strip_comments(src: &str) -> Result<String, String> {
        let ch: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0usize;
        while i < ch.len() {
            let c = ch[i];
            let next = ch.get(i + 1).copied();
            if c == '/' && next == Some('/') {
                while i < ch.len() && ch[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            } else if c == '/' && next == Some('*') {
                out.push_str("  ");
                i += 2;
                loop {
                    if i >= ch.len() {
                        return Err(
                            "unterminated /* block comment in bpf/include/s3tap_events.h"
                                .to_string(),
                        );
                    }
                    if ch[i] == '*' && ch.get(i + 1) == Some(&'/') {
                        out.push_str("  ");
                        i += 2;
                        break;
                    }
                    out.push(if ch[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            } else if c == '"' || c == '\'' {
                let quote = c;
                out.push(c);
                i += 1;
                loop {
                    if i >= ch.len() {
                        return Err(format!("unterminated {quote} literal in the C header"));
                    }
                    if ch[i] == '\\' {
                        out.push(ch[i]);
                        i += 1;
                        if i < ch.len() {
                            out.push(ch[i]);
                            i += 1;
                        }
                        continue;
                    }
                    out.push(ch[i]);
                    let done = ch[i] == quote;
                    i += 1;
                    if done {
                        break;
                    }
                }
            } else {
                out.push(c);
                i += 1;
            }
        }
        Ok(out)
    }

    fn is_ident_byte(b: u8) -> bool {
        b == b'_' || b.is_ascii_alphanumeric()
    }

    fn is_ident(s: &str) -> bool {
        !s.is_empty()
            && !s.as_bytes()[0].is_ascii_digit()
            && s.bytes().all(is_ident_byte)
    }

    /// `#define NAME <decimal>` only. Anything else that looks like an object-like macro
    /// (an expression, a shift, a cast) is reported rather than ignored: the guard cannot
    /// evaluate it, and silently ignoring it would drop an array bound from the check.
    fn parse_defines(clean: &str, errs: &mut Vec<String>) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        for line in clean.lines() {
            let Some(rest) = line.trim_start().strip_prefix("#define") else { continue };
            let mut toks = rest.split_whitespace();
            let Some(name) = toks.next() else { continue };
            if !is_ident(name) {
                errs.push(format!(
                    "`#define {name}`: function-like or non-identifier macros are not \
                     supported by the ABI guard's C parser"
                ));
                continue;
            }
            // An include guard (`#define S3TAP_EVENTS_H`) has no value: not a constant.
            let Some(value) = toks.next() else { continue };
            if toks.next().is_some() {
                errs.push(format!(
                    "`#define {name}`: multi-token value is not supported by the ABI \
                     guard's C parser (it must be a decimal integer)"
                ));
                continue;
            }
            match value.parse::<i64>() {
                Ok(v) => {
                    if out.insert(name.to_string(), v).is_some() {
                        errs.push(format!("`#define {name}` appears twice in the C header"));
                    }
                }
                Err(_) => errs.push(format!(
                    "`#define {name} {value}`: the ABI guard's C parser only understands \
                     decimal integers"
                )),
            }
        }
        out
    }

    fn resolve_int(tok: &str, defines: &BTreeMap<String, i64>) -> Option<i64> {
        tok.parse::<i64>().ok().or_else(|| defines.get(tok).copied())
    }

    /// Enumerators of `enum <name>`, in declaration order. Handles a trailing comma and
    /// implicit (unassigned) values; reports anything else.
    fn parse_enum(
        clean: &str,
        name: &str,
        defines: &BTreeMap<String, i64>,
        errs: &mut Vec<String>,
    ) -> Vec<(String, i64)> {
        let mut out = Vec::new();
        let needle = format!("enum {name}");
        let Some(at) = clean.find(&needle) else {
            errs.push(format!("the C header declares no `{needle}`"));
            return out;
        };
        let rest = &clean[at + needle.len()..];
        let Some(open) = rest.find('{') else {
            errs.push(format!("`{needle}` has no body"));
            return out;
        };
        if !rest[..open].trim().is_empty() {
            errs.push(format!("unexpected text between `{needle}` and its body"));
            return out;
        }
        let Some(close) = rest.find('}') else {
            errs.push(format!("`{needle}`'s body is unterminated"));
            return out;
        };
        let body = &rest[open + 1..close];
        if body.contains('{') {
            errs.push(format!("`{needle}` has a nested `{{`, which the guard cannot parse"));
            return out;
        }
        let mut implicit = 0i64;
        for item in body.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue; // trailing comma
            }
            let (ident, value) = match item.split_once('=') {
                Some((i, v)) => {
                    let v = v.trim();
                    match resolve_int(v, defines) {
                        Some(v) => (i.trim(), v),
                        None => {
                            errs.push(format!(
                                "enum {name}: `{}` has value `{v}`, which the ABI guard's C \
                                 parser cannot evaluate (decimal or a #define only)",
                                i.trim()
                            ));
                            continue;
                        }
                    }
                }
                None => (item, implicit),
            };
            if !is_ident(ident) {
                errs.push(format!("enum {name}: `{ident}` is not an identifier"));
                continue;
            }
            implicit = value + 1;
            out.push((ident.to_string(), value));
        }
        out
    }

    /// The Rust element type a C type must be mirrored by. `char` appears only as a byte
    /// buffer in this header (qname/hostname/sni/exe), which the Rust side types `[u8; N]`.
    fn rust_elem_for(ctype: &str) -> Option<&'static str> {
        Some(match ctype {
            "__u8" | "unsigned char" => "u8",
            "__s8" | "signed char" => "i8",
            "char" => "u8",
            "__u16" => "u16",
            "__s16" => "i16",
            "__u32" => "u32",
            "__s32" => "i32",
            "__u64" => "u64",
            "__s64" => "i64",
            "struct s3tap_event_hdr" => "EventHdr",
            _ => return None,
        })
    }

    fn parse_members(
        sname: &str,
        body: &str,
        defines: &BTreeMap<String, i64>,
        errs: &mut Vec<String>,
    ) -> Vec<CMember> {
        let mut out = Vec::new();
        let mut decls: Vec<&str> = body.split(';').collect();
        let tail = decls.pop().unwrap_or("");
        if !tail.trim().is_empty() {
            errs.push(format!(
                "struct {sname}: text `{}` after the last `;` — the ABI guard's C parser \
                 expects one `;`-terminated member per declaration",
                tail.trim()
            ));
        }
        'decls: for decl in decls {
            let decl = decl.trim();
            if decl.is_empty() {
                continue;
            }
            for (bad, what) in [
                (':', "a bitfield"),
                (',', "multiple declarators in one declaration"),
                ('(', "a function pointer or a macro invocation"),
                ('*', "a pointer member"),
                ('=', "an initializer"),
            ] {
                if decl.contains(bad) {
                    errs.push(format!(
                        "struct {sname}: member `{decl}` uses {what}, which the ABI guard's C \
                         parser does not understand — teach the parser rather than letting \
                         this struct go unchecked"
                    ));
                    continue 'decls;
                }
            }
            let (base, extent) = match decl.find('[') {
                None => (decl, None),
                Some(open) => {
                    if !decl.ends_with(']') {
                        errs.push(format!(
                            "struct {sname}: member `{decl}` has an array bound the guard \
                             cannot read"
                        ));
                        continue 'decls;
                    }
                    let inner = decl[open + 1..decl.len() - 1].trim();
                    if inner.contains('[') || inner.contains(']') {
                        errs.push(format!(
                            "struct {sname}: member `{decl}` is multi-dimensional, which the \
                             ABI guard's C parser does not support"
                        ));
                        continue 'decls;
                    }
                    let Some(n) = resolve_int(inner, defines) else {
                        errs.push(format!(
                            "struct {sname}: member `{decl}` has extent `{inner}`, which the \
                             ABI guard's C parser cannot evaluate (decimal or a #define only)"
                        ));
                        continue 'decls;
                    };
                    match usize::try_from(n) {
                        Ok(n) => (&decl[..open], Some(n)),
                        Err(_) => {
                            errs.push(format!(
                                "struct {sname}: member `{decl}` has a negative extent {n}"
                            ));
                            continue 'decls;
                        }
                    }
                }
            };
            let toks: Vec<&str> = base.split_whitespace().collect();
            if toks.len() < 2 {
                errs.push(format!(
                    "struct {sname}: `{decl}` is not a `<type> <name>` member declaration"
                ));
                continue 'decls;
            }
            let name = toks[toks.len() - 1];
            if !is_ident(name) {
                errs.push(format!("struct {sname}: `{name}` is not a member identifier"));
                continue 'decls;
            }
            let ctype = toks[..toks.len() - 1].join(" ");
            let Some(rust_elem) = rust_elem_for(&ctype) else {
                errs.push(format!(
                    "struct {sname}: member `{name}` has type `{ctype}`, which the ABI guard \
                     does not know how to mirror in Rust — add it to `rust_elem_for`"
                ));
                continue 'decls;
            };
            out.push(CMember { name: name.to_string(), ctype, rust_elem, extent });
        }
        out
    }

    /// Every `struct NAME { … };` DEFINITION in the header, in order. A `struct X y;`
    /// member (no brace) is skipped; an anonymous struct/union or a typedef'd body is
    /// reported, because either would change the layout in a way the guard cannot model.
    fn parse_structs(
        clean: &str,
        defines: &BTreeMap<String, i64>,
        errs: &mut Vec<String>,
    ) -> Vec<CStruct> {
        let b = clean.as_bytes();
        let mut out: Vec<CStruct> = Vec::new();
        let mut i = 0usize;
        while let Some(rel) = clean[i..].find("struct") {
            let at = i + rel;
            i = at + "struct".len();
            // Whole word only: not `structure`, not `my_struct`.
            if at > 0 && is_ident_byte(b[at - 1]) {
                continue;
            }
            let mut j = at + "struct".len();
            if j < b.len() && is_ident_byte(b[j]) {
                continue;
            }
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < b.len() && is_ident_byte(b[j]) {
                j += 1;
            }
            if j == name_start {
                // `struct {` — anonymous. Nothing the agent can mirror by name.
                if j < b.len() && b[j] == b'{' {
                    errs.push(
                        "the C header defines an anonymous struct, which the ABI guard cannot \
                         pin to a Rust mirror"
                            .to_string(),
                    );
                }
                continue;
            }
            let name = clean[name_start..j].to_string();
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= b.len() || b[j] != b'{' {
                continue; // a member/parameter/forward declaration, not a definition
            }
            let body_start = j + 1;
            let mut k = body_start;
            let mut depth = 1usize;
            while k < b.len() && depth > 0 {
                match b[k] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                k += 1;
            }
            if depth != 0 {
                errs.push(format!("struct {name}: unterminated body"));
                break;
            }
            let body = &clean[body_start..k - 1];
            i = k;
            if body.contains('{') {
                errs.push(format!(
                    "struct {name}: contains a nested `{{` (an anonymous struct or union), \
                     which the ABI guard's C parser does not model"
                ));
                continue;
            }
            let mut m = k;
            while m < b.len() && b[m].is_ascii_whitespace() {
                m += 1;
            }
            if m >= b.len() || b[m] != b';' {
                errs.push(format!(
                    "struct {name}: expected `;` right after the closing brace (a typedef or \
                     a declared instance is not supported by the ABI guard's C parser)"
                ));
            }
            if out.iter().any(|s| s.name == name) {
                errs.push(format!("struct {name} is defined twice in the C header"));
            }
            out.push(CStruct { name: name.clone(), members: parse_members(&name, body, defines, errs) });
        }
        out
    }

    // -----------------------------------------------------------------------
    // The comparison.
    // -----------------------------------------------------------------------

    /// Compare the Rust mirrors to the given C header text. Returns EVERY complaint;
    /// an empty vec means the two agree on version, tags, bounds and every struct's
    /// members in declaration order.
    pub fn check_c_header(src: &str) -> Vec<String> {
        let mut errs: Vec<String> = Vec::new();
        let clean = match strip_comments(src) {
            Ok(c) => c,
            Err(e) => {
                errs.push(e);
                return errs;
            }
        };
        if !clean.is_ascii() {
            errs.push(
                "the C header has non-ASCII text outside comments, which the ABI guard's \
                 parser refuses to tokenize"
                    .to_string(),
            );
            return errs;
        }
        let defines = parse_defines(&clean, &mut errs);

        // 1. The schema version. Reverting this to 1 leaves the object compiling clean and
        //    the whole suite green while `Event::parse` rejects EVERY event the agent
        //    receives, so the capture reports nothing and reads like a quiet workload.
        match defines.get("S3TAP_SCHEMA_VERSION") {
            None => errs.push(
                "the C header no longer defines S3TAP_SCHEMA_VERSION — Event::parse checks \
                 it on every record"
                    .to_string(),
            ),
            Some(&v) if v != i64::from(SCHEMA_VERSION) => errs.push(format!(
                "S3TAP_SCHEMA_VERSION is {v} in bpf/include/s3tap_events.h but \
                 s3tap_events::SCHEMA_VERSION is {SCHEMA_VERSION}: Event::parse would reject \
                 EVERY event, so the capture would silently report nothing"
            )),
            Some(_) => {}
        }

        // 2. The bounded tails. Invisible to the offset pins (the Rust arrays are sized
        //    from the Rust consts), so only the C text can catch a shrunk bound.
        for (name, rust_value) in rust_defines() {
            match defines.get(name) {
                None => errs.push(format!("the C header no longer defines {name}")),
                Some(&v) if v != rust_value => errs.push(format!(
                    "#define {name} is {v} in the C header but s3tap_events::{name} is \
                     {rust_value}"
                )),
                Some(_) => {}
            }
        }

        // 3. The event tags.
        let c_tags = parse_enum(&clean, "s3tap_event_type", &defines, &mut errs);
        let c_tag_map: BTreeMap<&str, i64> =
            c_tags.iter().map(|(n, v)| (n.as_str(), *v)).collect();
        let rust_tags = rust_tags();
        for (name, rust_value) in &rust_tags {
            match c_tag_map.get(name) {
                None => errs.push(format!(
                    "s3tap_events::{name} exists but `enum s3tap_event_type` has no such \
                     enumerator"
                )),
                Some(&v) if v != *rust_value => errs.push(format!(
                    "{name} is {v} in `enum s3tap_event_type` but s3tap_events::{name} is \
                     {rust_value} — the agent would dispatch the wrong struct"
                )),
                Some(_) => {}
            }
        }
        let rust_tag_names: BTreeSet<&str> = rust_tags.iter().map(|(n, _)| *n).collect();
        for (name, value) in &c_tags {
            if !rust_tag_names.contains(name.as_str()) {
                errs.push(format!(
                    "`enum s3tap_event_type` declares {name} = {value} with no Rust constant \
                     — the agent would drop every event of that type"
                ));
            }
        }

        // 4. The structs, member by member, in declaration order.
        let c_structs = parse_structs(&clean, &defines, &mut errs);
        if c_structs.len() != EXPECTED_STRUCTS {
            errs.push(format!(
                "found {} struct definitions in bpf/include/s3tap_events.h, expected \
                 {EXPECTED_STRUCTS} (found: {:?}) — a parser that matches the wrong number of \
                 structs is not a guard",
                c_structs.len(),
                c_structs.iter().map(|s| s.name.as_str()).collect::<Vec<_>>()
            ));
        }
        let c_by_name: BTreeMap<&str, &CStruct> =
            c_structs.iter().map(|s| (s.name.as_str(), s)).collect();
        let mirrors = mirrors();
        for m in &mirrors {
            let Some(c) = c_by_name.get(m.c_name) else {
                errs.push(format!(
                    "the C header defines no `struct {}` for the Rust mirror {}",
                    m.c_name, m.rust_name
                ));
                continue;
            };
            compare_struct(m, c, &mut errs);
        }
        let mirrored: BTreeSet<&str> = mirrors.iter().map(|m| m.c_name).collect();
        for c in &c_structs {
            if !mirrored.contains(c.name.as_str()) {
                errs.push(format!(
                    "the C header defines `struct {}` with no Rust mirror in tests/layout.rs \
                     — add one (with its offset pins) or say why the agent never decodes it",
                    c.name
                ));
            }
        }
        errs
    }

    fn compare_struct(m: &RustStruct, c: &CStruct, errs: &mut Vec<String>) {
        for (i, (rf, cm)) in m.fields.iter().zip(c.members.iter()).enumerate() {
            if rf.c_name != cm.name {
                errs.push(format!(
                    "struct {}: member #{i} is `{}` in C but the Rust mirror {} has `{}` \
                     there (offset {}) — a reorder, a rename, an inserted or a dropped field",
                    c.name, cm.name, m.rust_name, rf.rust_name, rf.offset
                ));
                continue;
            }
            if rf.elem != cm.rust_elem {
                errs.push(format!(
                    "struct {}.{}: C type `{}` mirrors Rust `{}` but {}.{} is `{}`",
                    c.name, cm.name, cm.ctype, cm.rust_elem, m.rust_name, rf.rust_name, rf.elem
                ));
            }
            if rf.extent != cm.extent {
                errs.push(format!(
                    "struct {}.{}: C extent {:?} but {}.{} has extent {:?}",
                    c.name, cm.name, cm.extent, m.rust_name, rf.rust_name, rf.extent
                ));
            }
        }
        if m.fields.len() != c.members.len() {
            errs.push(format!(
                "struct {} has {} members in C but the Rust mirror {} ({} B) has {}: \
                 C={:?} Rust={:?}",
                c.name,
                c.members.len(),
                m.rust_name,
                m.size,
                m.fields.len(),
                c.members.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
                m.fields.iter().map(|x| x.c_name.as_str()).collect::<Vec<_>>()
            ));
        }
    }

    /// The guard itself: the Rust mirrors against the real header.
    #[test]
    fn c_header_matches_the_rust_mirrors() {
        assert_eq!(
            mirrors().len(),
            EXPECTED_STRUCTS,
            "the mirror table lost a struct — every C struct must be checked"
        );
        let errs = check_c_header(HEADER);
        assert!(
            errs.is_empty(),
            "the Rust mirrors in s3tap-events have drifted from \
             bpf/include/s3tap_events.h:\n  - {}",
            errs.join("\n  - ")
        );
    }

    /// The parser must actually SEE the header. A guard whose parser matched nothing
    /// would pass every check above vacuously, which is the bug this file was written
    /// to fix — so pin what it found.
    #[test]
    fn the_parser_actually_read_the_header() {
        let clean = strip_comments(HEADER).expect("the header strips cleanly");
        let mut errs = Vec::new();
        let defines = parse_defines(&clean, &mut errs);
        let tags = parse_enum(&clean, "s3tap_event_type", &defines, &mut errs);
        let structs = parse_structs(&clean, &defines, &mut errs);
        assert!(errs.is_empty(), "parse errors: {errs:#?}");
        assert_eq!(structs.len(), EXPECTED_STRUCTS, "struct count");
        assert_eq!(tags.len(), 13, "event tag count");
        // S3TAP_SCHEMA_VERSION + the six bounded tails. (The include guard has no value,
        // so it is not a constant and does not appear here.)
        assert_eq!(defines.len(), 7, "integer #define count: {defines:?}");
        // The biggest struct is fully walked (comments between members and all).
        let close = structs.iter().find(|s| s.name == "evt_tcp_close").expect("evt_tcp_close");
        assert_eq!(close.members.len(), 25, "evt_tcp_close members: {:#?}", close.members);
        // Comments never become members.
        assert!(
            structs.iter().flat_map(|s| &s.members).all(|m| is_ident(&m.name)),
            "a comment leaked into the member list"
        );
    }
}

// ===========================================================================
// The guard's own test suite: mutate a COPY of the header, prove the guard bites.
// ===========================================================================

mod mutation_proofs {
    //! Every entry below is a change that leaves `cargo build` and (before this file
    //! read the header) the whole workspace green, while breaking the capture at
    //! runtime. Each must produce a complaint that NAMES the problem.

    use super::c_header::{check_c_header, HEADER};

    /// `find` -> `replace`, once, loudly: a mutation that did not apply would make the
    /// proof vacuous (the guard would "catch" nothing because nothing changed).
    fn sub(src: &str, find: &str, replace: &str) -> String {
        assert!(
            src.contains(find),
            "mutation anchor {find:?} is not in the header any more — this proof would be \
             vacuous, so fix the anchor"
        );
        src.replacen(find, replace, 1)
    }

    /// Rewrite one `#define NAME <value>` line, whatever its spacing.
    fn set_define(name: &str, value: i64) -> String {
        let prefix = format!("#define {name} ");
        let mut out = String::with_capacity(HEADER.len());
        let mut hit = false;
        for line in HEADER.lines() {
            if line.trim_start().starts_with(&prefix) {
                out.push_str(&format!("#define {name} {value}"));
                hit = true;
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
        assert!(hit, "the header has no `#define {name} <value>` line any more");
        out
    }

    /// Apply a mutation inside ONE struct's body, so anchors like `__u32 plaintext_len;`
    /// (which appears in two structs) stay unambiguous.
    fn mutate_struct(name: &str, f: impl FnOnce(&str) -> String) -> String {
        let open = format!("\nstruct {name} {{");
        let start = HEADER
            .find(&open)
            .unwrap_or_else(|| panic!("no `struct {name} {{` definition in the header"))
            + 1;
        let end = start
            + HEADER[start..]
                .find("\n};")
                .unwrap_or_else(|| panic!("`struct {name}` has no closing `\\n}};`"));
        format!("{}{}{}", &HEADER[..start], f(&HEADER[start..end]), &HEADER[end..])
    }

    /// Run the guard over a mutated header and require it to complain, by name.
    fn expect_caught(what: &str, src: &str, needle: &str) -> Vec<String> {
        let errs = check_c_header(src);
        assert!(
            !errs.is_empty(),
            "MUTATION NOT CAUGHT: {what} — the ABI guard stayed green, so that assertion \
             is not earning its keep"
        );
        assert!(
            errs.iter().any(|e| e.contains(needle)),
            "{what}: caught, but no complaint mentions {needle:?}:\n  - {}",
            errs.join("\n  - ")
        );
        errs
    }

    /// Mutation 1 (from the review): revert the schema bump. The object compiles clean,
    /// the suite stays green, and `Event::parse` rejects every event — a capture that
    /// reports NOTHING, indistinguishable from a quiet workload.
    #[test]
    fn schema_version_revert_is_caught() {
        let src = set_define("S3TAP_SCHEMA_VERSION", 1);
        expect_caught("S3TAP_SCHEMA_VERSION 2 -> 1", &src, "S3TAP_SCHEMA_VERSION is 1");
    }

    /// Mutation 2 (from the review): a `__u32 pad;` inserted before `plaintext_len` in
    /// evt_tls_body. Size stays 40, `read_from_bytes` still succeeds, `plaintext_len`
    /// reads 0, and every download_ns/total_ns silently becomes None.
    #[test]
    fn inserted_padding_field_is_caught() {
        let src = mutate_struct("evt_tls_body", |b| {
            sub(b, "__u32 plaintext_len;", "__u32 pad;\n    __u32 plaintext_len;")
        });
        expect_caught(
            "evt_tls_body gains a `__u32 pad;` before plaintext_len",
            &src,
            "struct evt_tls_body: member #2 is `pad` in C",
        );
    }

    /// Mutation 3: two same-width fields swapped. Every size and offset is unchanged, so
    /// the offset pins cannot see it; the agent reads `lost` out of `sacked_out`.
    #[test]
    fn reordered_fields_are_caught() {
        let src = mutate_struct("evt_tcp_close", |b| {
            let b = sub(b, "__u32 lost;", "__u32 SWAP_TMP;");
            let b = sub(&b, "__u32 sacked_out;", "__u32 lost;");
            sub(&b, "__u32 SWAP_TMP;", "__u32 sacked_out;")
        });
        expect_caught(
            "evt_tcp_close swaps `lost` and `sacked_out`",
            &src,
            "struct evt_tcp_close: member #14 is `sacked_out` in C",
        );
    }

    /// Mutation 4: a renamed field. Same type, same offset, so only the name check sees it.
    #[test]
    fn renamed_field_is_caught() {
        let src = mutate_struct("evt_tcp_close", |b| {
            sub(b, "__u32 rcv_ooopack;", "__u32 rcv_oopack;")
        });
        expect_caught(
            "evt_tcp_close renames rcv_ooopack -> rcv_oopack",
            &src,
            "struct evt_tcp_close: member #23 is `rcv_oopack` in C",
        );
    }

    /// Mutation 5: a dropped field. Shifts every later C offset while the Rust side keeps
    /// its own; the exact-length decode would reject the record, i.e. silence again.
    #[test]
    fn dropped_field_is_caught() {
        let src = mutate_struct("evt_tcp_close", |b| sub(b, "__u32 window_clamp;", ""));
        expect_caught(
            "evt_tcp_close drops window_clamp",
            &src,
            "struct evt_tcp_close: member #19 is `handshake_us` in C",
        );
    }

    /// Mutation 6: a changed tag. The agent would dispatch the wrong struct (or drop the
    /// event); nothing about size or offset moves.
    #[test]
    fn changed_event_tag_is_caught() {
        let src = sub(HEADER, "= 23,", "= 25,");
        expect_caught("EVT_TLS_READ_BODY 23 -> 25", &src, "EVT_TLS_READ_BODY is 25");
    }

    /// Mutation 7: a new tag with no Rust constant. Every event of that type is dropped.
    #[test]
    fn unmirrored_event_tag_is_caught() {
        let src = sub(HEADER, "= 30,", "= 30,\n    EVT_SOMETHING_NEW = 31,");
        expect_caught(
            "a new EVT_SOMETHING_NEW = 31 tag",
            &src,
            "declares EVT_SOMETHING_NEW = 31 with no Rust constant",
        );
    }

    /// Mutation 8: a signedness flip. Same width, same offset, same size — invisible to
    /// every offset pin, and it turns a byte counter into a negative number.
    #[test]
    fn signedness_flip_is_caught() {
        let src = mutate_struct("evt_tcp_close", |b| {
            sub(b, "__u64 bytes_retrans;", "__s64 bytes_retrans;")
        });
        expect_caught(
            "evt_tcp_close bytes_retrans __u64 -> __s64",
            &src,
            "struct evt_tcp_close.bytes_retrans",
        );
    }

    /// Mutation 9: a shrunk array bound. The Rust mirror sizes its arrays from the RUST
    /// consts, so the C struct shrinks alone and the size pins never notice.
    #[test]
    fn shrunk_define_is_caught() {
        let src = set_define("QNAME_MAX", 254);
        expect_caught("#define QNAME_MAX 255 -> 254", &src, "#define QNAME_MAX is 254");
    }

    /// Mutation 10: a shrunk extent written in place, bypassing the `#define`.
    #[test]
    fn shrunk_array_extent_is_caught() {
        let src = mutate_struct("evt_tcp_connect", |b| sub(b, "saddr[16]", "saddr[12]"));
        expect_caught(
            "evt_tcp_connect saddr[16] -> saddr[12]",
            &src,
            "struct evt_tcp_connect.saddr: C extent Some(12)",
        );
    }

    /// Mutation 11: a whole new event struct with no Rust mirror. The count check and the
    /// unmirrored-struct check must both fire; neither may be a silent skip.
    #[test]
    fn unmirrored_struct_is_caught() {
        let src = sub(
            HEADER,
            "#endif // S3TAP_EVENTS_H",
            "struct evt_brand_new {\n    struct s3tap_event_hdr hdr;\n    __u64 x;\n};\n\n#endif // S3TAP_EVENTS_H",
        );
        let errs = expect_caught(
            "a new `struct evt_brand_new` with no Rust mirror",
            &src,
            "defines `struct evt_brand_new` with no Rust mirror",
        );
        assert!(
            errs.iter().any(|e| e.contains("found 14 struct definitions")),
            "the struct COUNT check did not fire:\n  - {}",
            errs.join("\n  - ")
        );
    }

    /// Mutation 12: a construct the parser was never taught. It must say so rather than
    /// skip the member and report a pass — a parser that quietly matches nothing is the
    /// failure mode this whole file exists to prevent.
    #[test]
    fn unparseable_construct_fails_loudly() {
        let bitfield = mutate_struct("evt_tcp_close", |b| {
            sub(b, "__u8  rate_app_limited;", "__u32 rate_app_limited : 1;")
        });
        expect_caught("a bitfield member", &bitfield, "uses a bitfield");

        let two_declarators = mutate_struct("evt_tcp_sample", |b| {
            sub(b, "__u32 lost;", "__u32 lost, extra;")
        });
        expect_caught(
            "two declarators in one member",
            &two_declarators,
            "multiple declarators in one declaration",
        );

        let unknown_type = mutate_struct("evt_tls_body", |b| {
            sub(b, "__u32 plaintext_len;", "size_t plaintext_len;")
        });
        expect_caught("an unmapped C type", &unknown_type, "which the ABI guard does not know");

        let anon_union = mutate_struct("evt_tls_body", |b| {
            sub(b, "__u32 plaintext_len;", "union { __u32 plaintext_len; __u32 other; };")
        });
        expect_caught("an anonymous union", &anon_union, "nested `{`");
    }

    /// The other half of "loud": no FALSE positives. Comments (both kinds, including ones
    /// holding braces, semicolons and things that look like members) must not become
    /// members, or the guard would cry wolf and get deleted.
    #[test]
    fn comments_are_not_members() {
        let src = mutate_struct("evt_tls_body", |b| {
            format!(
                "{b}\n    // __u32 ghost;\n    /* struct fake {{ __u32 ghost2; }} ; more text */\n"
            )
        });
        let errs = check_c_header(&src);
        assert!(errs.is_empty(), "a comment was parsed as C:\n  - {}", errs.join("\n  - "));
    }

    /// And the header as shipped is green, so every "caught" above is a real signal.
    #[test]
    fn the_unmutated_header_is_green() {
        assert!(check_c_header(HEADER).is_empty());
    }
}
