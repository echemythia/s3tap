// crates/s3tap-core/tests/correlate.rs
//
// The correlation engine is pure logic — no kernel — so we test it thoroughly
// by feeding synthetic events and asserting the folded Connection record.

use s3tap_core::Correlator;
use s3tap_schema::Delimitation;
use s3tap_events::{
    EventHdr, EvtConnId, EvtTcpClose, EvtTcpConnect, EvtTlsBody, EvtTlsData, EvtTlsHandshake,
    EvtTlsServer,
    EVT_CONN_ID, EVT_TCP_CLOSE, EVT_TCP_CONNECT, EVT_TLS_HANDSHAKE, EVT_TLS_SERVER,
};

#[test]
fn server_hello_fills_negotiated_version_and_cipher() {
    // The ServerHello (ingress) supplies the NEGOTIATED version + cipher; the correlator
    // merges them into the connection's tls block (here with no ClientHello SNI -> sni None).
    let mut c = Correlator::new();
    c.on_connect(&connect(0xA7, 100, 7_000_000));
    let sh = EvtTlsServer {
        hdr: EventHdr { type_: EVT_TLS_SERVER, sock_cookie: 0xA7, ..Default::default() },
        version: 0x0304, // TLS 1.3
        cipher: 0x1301,  // TLS_AES_128_GCM_SHA256
    };
    c.on_tls_server(&sh);
    let rec = c.on_close(&close(0xA7, 0, 0, 0, 1000)).unwrap();
    assert!(rec.tls.seen);
    assert_eq!(rec.tls.version.as_deref(), Some("TLS 1.3"));
    assert_eq!(rec.tls.cipher, Some(0x1301));
    assert_eq!(rec.tls.sni, None, "no ClientHello -> no SNI");
}

#[test]
fn on_close_maps_path_diagnosis_sentinels() {
    // The extended tcp_sock fields use 0 (and U32_MAX for min_rtt) as "no sample"; the chrono
    // group is gated on the SUM so a fully-limited (busy==0) connection survives. Pin all of it.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xF1, 100, 7_000_000));
    let e = EvtTcpClose {
        hdr: EventHdr { type_: EVT_TCP_CLOSE, sock_cookie: 0xF1, ..Default::default() },
        min_rtt_us: u32::MAX,                // tcp_min_rtt "never sampled" sentinel -> None
        rttvar_us: 0,                        // 0 -> None
        snd_cwnd: 10,
        mss_cache: 1440,
        delivery_rate_bps: 0,                // 0 -> None
        busy_jiffies: 0,                     // fully receiver-window-limited ...
        rwnd_limited_jiffies: 500,           // ... sum > 0, so the GROUP survives (busy==0 Some)
        sndbuf_limited_jiffies: 0,
        lost: 0,                             // 0 -> None
        sacked_out: 0,
        reordering: 7,
        ca_state: 2,                         // CWR -> Some(2) (doctor only counts >=3 as loss)
        ..Default::default()
    };
    let r = c.on_close(&e).unwrap();
    assert_eq!(r.min_rtt_us, None, "U32_MAX sentinel must be filtered");
    assert_eq!(r.rttvar_us, None);
    assert_eq!(r.snd_cwnd, Some(10));
    assert_eq!(r.delivery_rate_bps, None);
    assert_eq!((r.busy_jiffies, r.rwnd_limited_jiffies, r.sndbuf_limited_jiffies), (Some(0), Some(500), Some(0)));
    assert_eq!(r.lost, None);
    assert_eq!(r.reordering, Some(7));
    assert_eq!(r.ca_state, Some(2));

    // A real min_rtt but all-zero chronos -> the whole chrono group is None (sum==0).
    c.on_connect(&connect(0xF2, 100, 7_000_000));
    let e2 = EvtTcpClose {
        hdr: EventHdr { type_: EVT_TCP_CLOSE, sock_cookie: 0xF2, ..Default::default() },
        min_rtt_us: 16_000,
        ..Default::default()
    };
    let r2 = c.on_close(&e2).unwrap();
    assert_eq!(r2.min_rtt_us, Some(16_000));
    assert_eq!((r2.busy_jiffies, r2.rwnd_limited_jiffies, r2.sndbuf_limited_jiffies), (None, None, None));
    assert_eq!(r2.ca_state, None, "ca_state 0 (Open) -> None");
}

fn connect(cookie: u64, pid: u32, latency_ns: u64) -> EvtTcpConnect {
    let mut daddr = [0u8; 16];
    daddr[10] = 0xff; // v4-mapped prefix ::ffff:
    daddr[11] = 0xff;
    daddr[12..16].copy_from_slice(&[52, 216, 0, 1]);
    EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: cookie,
            tgid: pid,
            ts_ns: 51_200_000_000,
            ..Default::default()
        },
        family: 2, // AF_INET
        daddr,
        dport: 443,
        connect_latency_ns: latency_ns,
        ..Default::default()
    }
}

fn close(cookie: u64, sent: u64, recv: u64, rtx: u32, srtt: u32) -> EvtTcpClose {
    EvtTcpClose {
        hdr: EventHdr {
            type_: EVT_TCP_CLOSE,
            sock_cookie: cookie,
            ..Default::default()
        },
        bytes_sent: sent,
        bytes_recv: recv,
        retransmit_count: rtx,
        srtt_us: srtt,
        lifetime_ns: 4_200_000_000,
        ..Default::default()
    }
}

#[test]
fn connect_then_close_yields_one_record() {
    let mut c = Correlator::new();

    // A connect alone finalizes nothing.
    assert!(c.on_connect(&connect(42, 100, 11_000_000)).is_none());

    // The close finalizes the connection record.
    let rec = c
        .on_close(&close(42, 100, 2310, 0, 27))
        .expect("expected a finalized record");

    assert_eq!(rec.sock_cookie, 42);
    assert_eq!(rec.app.pid, 100);
    // ts_ns is the SYN start = established ts (51.2e9) - latency (11e6).
    assert_eq!(rec.ts_ns, Some(51_189_000_000));
    assert!(!rec.connect_failed);
    assert_eq!(rec.bytes_sent, 100);
    assert_eq!(rec.bytes_recv, 2310);
    assert_eq!(rec.retransmits, 0);
    assert_eq!(rec.tcp_connect_ns, Some(11_000_000));
    assert_eq!(rec.srtt_us, Some(27));
    assert_eq!(rec.lifetime_ns, Some(4_200_000_000));
    assert!(!rec.partial);

    // endpoint filled from the connect (v4-mapped IPv4 read from [12..16]).
    assert_eq!(rec.endpoint.endpoint_ip.as_deref(), Some("52.216.0.1"));
    assert_eq!(rec.endpoint.family.as_deref(), Some("inet"));
    assert_eq!(rec.endpoint.dport, Some(443));

    // socket-only path: no TLS, no DNS, not a failed connect.
    assert!(!rec.tls.seen);
    assert!(rec.dns.is_none());
    assert!(!rec.connect_failed);
}

#[test]
fn close_without_connect_is_partial() {
    let mut c = Correlator::new();
    let rec = c
        .on_close(&close(99, 5, 5, 1, 0))
        .expect("a close always yields a record, even unpaired");

    assert_eq!(rec.sock_cookie, 99);
    assert!(rec.partial, "connect-level facts unattributable => partial");
    assert_eq!(rec.tcp_connect_ns, None);
    assert_eq!(rec.ts_ns, None);
    assert_eq!(rec.srtt_us, None, "srtt 0 sentinel => None");
    // The close-time counters come straight off tcp_sock and DO survive into a
    // partial record — attaching mid-connection costs us the connect facts, not
    // the connection-cumulative metrics. (This is the whole point of the
    // socket-only / degraded path: bytes + lifetime are still reported.)
    assert_eq!(rec.bytes_sent, 5);
    assert_eq!(rec.bytes_recv, 5);
    assert_eq!(rec.retransmits, 1);
    assert_eq!(rec.lifetime_ns, Some(4_200_000_000), "lifetime is a close-time fact");
    // endpoint is empty without a connect to source it from.
    assert!(rec.endpoint.endpoint_ip.is_none());
    assert!(rec.endpoint.family.is_none());
    assert!(rec.endpoint.dport.is_none());
}

#[test]
fn v4_mapped_inet6_endpoint_normalizes_to_inet() {
    // A dual-stack AF_INET6 (family 10) socket carrying ::ffff:52.216.0.1 is
    // really IPv4 traffic — the record must say family "inet" with the v4 IP,
    // or per-family analysis can't tell IPv6 from IPv4.
    let mut daddr = [0u8; 16];
    daddr[10] = 0xff;
    daddr[11] = 0xff;
    daddr[12..16].copy_from_slice(&[52, 216, 0, 1]);
    let conn = EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: 3,
            tgid: 1,
            ts_ns: 100,
            ..Default::default()
        },
        family: 10, // AF_INET6
        daddr,
        dport: 443,
        connect_latency_ns: 50,
        ..Default::default()
    };
    let mut c = Correlator::new();
    c.on_connect(&conn);
    let rec = c.on_close(&close(3, 0, 0, 0, 1)).unwrap();
    assert_eq!(rec.endpoint.family.as_deref(), Some("inet"));
    assert_eq!(rec.endpoint.endpoint_ip.as_deref(), Some("52.216.0.1"));
}

#[test]
fn genuine_ipv6_endpoint_is_labeled_inet6() {
    // A real (non-v4-mapped) IPv6 destination must keep family "inet6" and the
    // full address. Every other test uses ::ffff:..., so this is the only
    // coverage of classify_endpoint's genuine-IPv6 branch.
    let mut daddr = [0u8; 16]; // 2606:4700:10::6814:179a
    daddr[0..6].copy_from_slice(&[0x26, 0x06, 0x47, 0x00, 0x00, 0x10]);
    daddr[12..16].copy_from_slice(&[0x68, 0x14, 0x17, 0x9a]);
    let conn = EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: 4,
            tgid: 1,
            ts_ns: 100,
            ..Default::default()
        },
        family: 10, // AF_INET6
        daddr,
        dport: 443,
        connect_latency_ns: 50,
        ..Default::default()
    };
    let mut c = Correlator::new();
    c.on_connect(&conn);
    let rec = c.on_close(&close(4, 0, 0, 0, 1)).unwrap();
    assert_eq!(rec.endpoint.family.as_deref(), Some("inet6"));
    assert_eq!(rec.endpoint.endpoint_ip.as_deref(), Some("2606:4700:10::6814:179a"));
}

#[test]
fn ts_ns_saturates_when_latency_exceeds_timestamp() {
    // A corrupt/reused-pointer record where latency > established ts must not
    // panic; ts_ns degrades to Some(0) (saturating_sub, not plain `-`).
    let conn = EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: 6,
            tgid: 1,
            ts_ns: 100,
            ..Default::default()
        },
        family: 2,
        connect_latency_ns: 1_000, // > ts_ns
        ..Default::default()
    };
    let mut c = Correlator::new();
    c.on_connect(&conn);
    let rec = c.on_close(&close(6, 0, 0, 0, 1)).unwrap();
    assert_eq!(rec.ts_ns, Some(0));
}

#[test]
fn two_connects_same_cookie_latest_wins() {
    // sk-pointer reuse: a fresh connect on the same cookie supersedes the old.
    let mut c = Correlator::new();
    c.on_connect(&connect(7, 1, 1_000));
    c.on_connect(&connect(7, 2, 2_000));
    let rec = c.on_close(&close(7, 0, 0, 0, 10)).unwrap();
    assert_eq!(rec.tcp_connect_ns, Some(2_000));
    assert_eq!(rec.app.pid, 2);
}

#[test]
fn passive_open_has_no_connect_latency_but_is_not_partial() {
    // A passive/inbound open reaches ESTABLISHED with latency 0 (no SYN_SENT).
    // We DID observe it establish (endpoint is filled, not partial), but the
    // connect latency is unmeasurable => tcp_connect_ns is None. This is the
    // one branch the other tests don't hit (they use nonzero latency).
    let mut c = Correlator::new();
    c.on_connect(&connect(8, 200, 0)); // latency 0
    let rec = c.on_close(&close(8, 10, 20, 0, 5)).unwrap();
    assert_eq!(rec.tcp_connect_ns, None);
    assert!(!rec.partial);
    assert_eq!(rec.app.pid, 200, "pid still comes from the observed connect");
    assert_eq!(rec.endpoint.dport, Some(443), "endpoint still filled");
}

#[test]
fn partial_record_reports_unknown_pid_not_the_close_tgid() {
    // With no connect observed, app.pid is 0 (unknown) — NOT the close event's
    // tgid. EVT_TCP_CLOSE is stamped wherever the socket is torn down, routinely
    // NET_RX softirq context, so its tgid names whatever task was interrupted. A
    // connection s3tap attached to mid-flight used to be published as belonging
    // to that unrelated process.
    let mut c = Correlator::new();
    let close_evt = EvtTcpClose {
        hdr: EventHdr {
            type_: EVT_TCP_CLOSE,
            sock_cookie: 77,
            tgid: 4242,
            ..Default::default()
        },
        ..Default::default()
    };
    let rec = c.on_close(&close_evt).unwrap();
    assert!(rec.partial);
    assert_eq!(rec.app.pid, 0);
}

#[test]
fn failed_connect_is_flagged_with_endpoint_and_syn_ts() {
    // For a failed connect the probe emits the connect event at close time,
    // flagged (connect_failed=1, latency=0, ts = SYN start, dport=80 here).
    let mut daddr = [0u8; 16];
    daddr[10] = 0xff;
    daddr[11] = 0xff;
    daddr[12..16].copy_from_slice(&[52, 216, 0, 1]);
    let failed = EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: 11,
            tgid: 100,
            ts_ns: 51_000_000_000,
            ..Default::default()
        },
        family: 2,
        daddr,
        dport: 80, // a plaintext attempt
        connect_failed: 1,
        connect_latency_ns: 0,
        ..Default::default()
    };
    let mut c = Correlator::new();
    assert!(c.on_connect(&failed).is_none());
    let rec = c.on_close(&close(11, 0, 0, 1, 0)).unwrap();

    assert!(rec.connect_failed);
    assert!(!rec.partial, "we DID observe it (via the flagged connect event)");
    assert_eq!(rec.ts_ns, Some(51_000_000_000), "ts = SYN start, latency 0");
    assert_eq!(rec.tcp_connect_ns, None, "never established");
    assert_eq!(rec.endpoint.dport, Some(80));
    assert_eq!(rec.endpoint.endpoint_ip.as_deref(), Some("52.216.0.1"));
}

#[test]
fn failed_connect_suppresses_any_connect_latency() {
    // Invariant: a failed connect never reached ESTABLISHED, so it has no
    // SYN->ESTABLISHED latency. Even if the probe were to ship a nonzero
    // connect_latency_ns alongside connect_failed=1 (it shouldn't), the record
    // must report tcp_connect_ns=None — the two facts can't coexist.
    let failed = EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: 12,
            tgid: 100,
            ts_ns: 51_000_000_000,
            ..Default::default()
        },
        family: 2,
        connect_failed: 1,
        connect_latency_ns: 7_000_000, // bogus for a failed connect
        ..Default::default()
    };
    let mut c = Correlator::new();
    c.on_connect(&failed);
    let rec = c.on_close(&close(12, 0, 0, 0, 0)).unwrap();
    assert!(rec.connect_failed);
    assert_eq!(rec.tcp_connect_ns, None, "failed connect must not report a latency");
}

#[test]
fn close_consumes_state_so_a_second_close_is_partial() {
    let mut c = Correlator::new();
    c.on_connect(&connect(5, 1, 9_000));
    let first = c.on_close(&close(5, 0, 0, 0, 5)).unwrap();
    assert!(!first.partial);
    // State was consumed; a duplicate close has no connect to pair with.
    let second = c.on_close(&close(5, 0, 0, 0, 5)).unwrap();
    assert!(second.partial);
}

// A connect with an explicit start timestamp (latency 0, so ts_ns == hdr.ts_ns),
// used to control eviction ordering in the bounded-map tests below.
fn connect_at(cookie: u64, ts_ns: u64) -> EvtTcpConnect {
    EvtTcpConnect {
        hdr: EventHdr {
            type_: EVT_TCP_CONNECT,
            sock_cookie: cookie,
            tgid: 1,
            ts_ns,
            ..Default::default()
        },
        family: 2,
        connect_latency_ns: 0,
        ..Default::default()
    }
}

#[test]
fn over_capacity_evicts_the_oldest_open_connection() {
    // A missed close would otherwise leak forever; the cap reclaims the oldest.
    let mut c = Correlator::with_max_open(2);
    c.on_connect(&connect_at(1, 100)); // oldest
    c.on_connect(&connect_at(2, 200));
    c.on_connect(&connect_at(3, 300)); // exceeds cap(2) -> evicts min-ts_ns (1)

    // cookie 1 was evicted, so its close can't pair -> partial.
    let r1 = c.on_close(&close(1, 0, 0, 0, 5)).unwrap();
    assert!(r1.partial, "the oldest open connection should have been evicted");

    // cookies 2 and 3 survived: their closes pair (not partial).
    assert!(!c.on_close(&close(2, 0, 0, 0, 5)).unwrap().partial);
    assert!(!c.on_close(&close(3, 0, 0, 0, 5)).unwrap().partial);
}

#[test]
fn over_capacity_evicts_a_batch_of_the_oldest_and_then_stops_scanning() {
    // Eviction is BATCHED (cap/10) so a map pinned at its cap doesn't pay a full linear scan
    // on every single insert. With cap 100 the 101st connect reclaims the 10 oldest, leaving
    // 91 — the next 9 connects then fit under the cap and evict nothing at all, and the 111th
    // reclaims the next 10. Oldest-first order is unchanged from single-victim eviction.
    let cap = 100u64;
    let mut c = Correlator::with_max_open(cap as usize);
    for i in 1..=111u64 {
        c.on_connect(&connect_at(i, i * 10)); // ts ordered by cookie
    }

    // Evicted: exactly the 20 oldest (two passes of 10). Everything newer survived.
    let mut partial = Vec::new();
    for i in 1..=111u64 {
        if c.on_close(&close(i, 0, 0, 0, 5)).unwrap().partial {
            partial.push(i);
        }
    }
    assert_eq!(partial, (1..=20).collect::<Vec<_>>(), "the 20 oldest were evicted, oldest first");
}

#[test]
fn eviction_at_the_default_cap_does_not_collapse_throughput() {
    // The failure this guards: when the ring overflows, dropped closes leak `conns` entries
    // until the map is PINNED at max_open. Evicting one entry per insert then runs a full
    // 65536-entry scan on every later connect, on the single-threaded fold path — the fold
    // slows, the ring overflows harder, more closes are dropped, more entries leak. With
    // one-at-a-time eviction this loop is ~134k scans x 65536 entries (~9e9 visits, minutes
    // even in release); batched it is ~20 scans (~1.3e6 visits). The bound below is ~50x the
    // expected debug-build time, so it cannot flake on a loaded CI box but still fails hard
    // if single-victim eviction comes back.
    let mut c = Correlator::with_max_open(65_536);
    let start = std::time::Instant::now();
    for i in 1..=200_000u64 {
        c.on_connect(&connect_at(i, i * 10)); // no closes: every entry leaks, as under overflow
    }
    let elapsed = start.elapsed();
    assert!(elapsed < std::time::Duration::from_secs(20), "200k leaked connects took {elapsed:?}");

    // ...and the cap still holds: the oldest connections are gone, the newest are not.
    assert!(c.on_close(&close(1, 0, 0, 0, 5)).unwrap().partial, "oldest evicted");
    assert!(!c.on_close(&close(200_000, 0, 0, 0, 5)).unwrap().partial, "newest retained");
}

// --- E5 plaintext op path: fd reuse after a missed close (review H1/M1-M4) -----

fn conn_id(tgid: u32, fd: u32, cookie: u64, ts: u64) -> EvtConnId {
    EvtConnId {
        hdr: EventHdr {
            type_: EVT_CONN_ID,
            sock_cookie: cookie,
            tgid,
            ts_ns: ts,
            ..Default::default()
        },
        fd,
        _pad: 0,
    }
}

fn tls_data(tgid: u32, fd: u32, ts: u64, payload: &[u8]) -> EvtTlsData {
    let mut e = EvtTlsData {
        fd,
        plaintext_len: payload.len() as u32,
        captured_len: payload.len() as u16,
        ..Default::default()
    };
    e.hdr.tgid = tgid;
    e.hdr.ts_ns = ts;
    e.data[..payload.len()].copy_from_slice(payload);
    e
}

// A length-only response BODY read (EVT_TLS_READ_BODY): the kernel sends only the
// byte count, in the dedicated 40-byte EvtTlsBody (no data field to fill).
fn tls_body(tgid: u32, fd: u32, ts: u64, nbytes: u32) -> EvtTlsBody {
    let mut e = EvtTlsBody { fd, plaintext_len: nbytes, ..Default::default() };
    e.hdr.type_ = s3tap_events::EVT_TLS_READ_BODY;
    e.hdr.tgid = tgid;
    e.hdr.ts_ns = ts;
    e
}

// A BIO-client TLS event (curl ≥7.84): fd is 0 (SSL_set_fd never observed) and the kernel
// stamped the tid-inferred fallback cookie into hdr.sock_cookie.
fn tls_bio(tgid: u32, ts: u64, cookie: u64, payload: &[u8]) -> EvtTlsData {
    let mut e = tls_data(tgid, 0, ts, payload);
    e.hdr.sock_cookie = cookie;
    e
}

#[test]
fn bio_client_fd0_resolves_cookie_via_tid_fallback() {
    // curl ≥7.84 never calls SSL_set_fd, so TLS events carry fd=0 and NO conn_id maps them.
    // The kernel's tid→cookie fallback stamps hdr.sock_cookie; the op must still join its
    // connection (non-partial, setup facts present) via that cookie.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC, 100, 7_000_000)); // conns[0xC] populated; NO conn_id (BIO client)
    assert!(c
        .on_tls_write(&tls_bio(100, 2_000, 0xC, b"GET /o HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    let op = c
        .on_tls_read(&tls_bio(100, 5_000, 0xC, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        .expect("BIO op emits on its response");
    assert!(!op.partial, "the tid-fallback cookie joins the connection → not partial");
    assert_eq!(op.http_status, Some(200));
    assert_eq!(op.tcp_connect_ns, Some(7_000_000), "first op joined its connect via the fallback cookie");
    assert_eq!(op.ttfb_ns, Some(3_000));
}

#[test]
fn bio_read_with_mismatched_cookie_does_not_wrong_join() {
    // Two concurrent BIO connections collapse onto op-key (tgid,0). A response whose fallback
    // cookie DISAGREES with the open op's must NOT pair (the guard) → no wrong-join, returns None.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC1, 100, 7_000_000));
    c.on_connect(&connect(0xC2, 100, 7_000_000));
    assert!(c
        .on_tls_write(&tls_bio(100, 2_000, 0xC1, b"GET /a HTTP/1.1\r\nHost: a.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert!(
        c.on_tls_read(&tls_bio(100, 5_000, 0xC2, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
            .is_none(),
        "mismatched fallback cookie must not wrong-join a response to the wrong connection"
    );
}

#[test]
fn sequential_bio_connections_reset_seq_no_false_reuse() {
    // Two SEQUENTIAL BIO connections in ONE process (both op-key (tgid,0), no conn_id). Because
    // on_close can't reset the (tgid,0) slot for BIO, next_seq would leak → C2's first op would
    // be req_seq=1 → falsely connection_reused with tcp_connect_ns/dns dropped. The fallback-
    // cookie-change reset must make C2's first op req_seq=0 with its real connect facts.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC1, 100, 5_000_000));
    c.on_tls_write(&tls_bio(100, 2_000, 0xC1, b"GET /a HTTP/1.1\r\nHost: a.s3.amazonaws.com\r\n\r\n"));
    let op1 = c
        .on_tls_read(&tls_bio(100, 4_000, 0xC1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        .expect("C1 op emits");
    assert_eq!(op1.req_seq, 0);
    assert!(!op1.connection_reused);
    c.on_close(&close(0xC1, 100, 200, 0, 17_000));
    // A fresh connection C2 reuses the (tgid,0) op slot.
    c.on_connect(&connect(0xC2, 100, 9_000_000));
    c.on_tls_write(&tls_bio(100, 12_000, 0xC2, b"GET /b HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    let op2 = c
        .on_tls_read(&tls_bio(100, 14_000, 0xC2, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        .expect("C2 op emits");
    assert_eq!(op2.req_seq, 0, "C2 is a fresh connection — not seq 1 leaked from C1's slot");
    assert!(!op2.connection_reused, "C2's first op is not a reuse");
    assert_eq!(op2.tcp_connect_ns, Some(9_000_000), "C2's real connect facts are NOT dropped");
}

#[test]
fn bio_in_flight_op_is_flushed_on_close_not_dropped() {
    // A BIO op (fd==0, no conn_id) whose response never arrives before the socket closes
    // must still be emitted as an aborted in-flight op — not silently dropped. `on_close`
    // reaches BIO ops via the (tgid,0) slot + a cookie guard, since `fd_links` has no BIO
    // entry to find them by. (Regression: previously dropped until a later BIO write or a
    // cap-eviction happened to flush the stale slot.)
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC, 100, 7_000_000));
    assert!(c
        .on_tls_write(&tls_bio(100, 2_000, 0xC, b"GET /o HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    // No response — the connection closes with the op still open.
    c.on_close(&close(0xC, 100, 0, 0, 17_000)).expect("connection record");
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1, "the aborted in-flight BIO op is flushed, not dropped");
    assert_eq!(flushed[0].http_status, None, "no response was seen → aborted op");
}

#[test]
fn bio_close_with_foreign_cookie_does_not_flush_the_slot() {
    // The cookie guard: a DIFFERENT connection closing must not flush a BIO op that a
    // concurrent connection still owns in the (tgid,0) slot.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC1, 100, 7_000_000));
    c.on_tls_write(&tls_bio(100, 2_000, 0xC1, b"GET /a HTTP/1.1\r\nHost: a.s3.amazonaws.com\r\n\r\n"));
    // A different socket (0xC2) closes; it does not own the open op (0xC1) → no flush.
    c.on_close(&close(0xC2, 100, 0, 0, 17_000));
    assert!(c.take_flushed_ops().is_empty(), "foreign-cookie close must not flush 0xC1's op");
}

// A BIO-client body-length event: fd 0, with the kernel's tid-inferred fallback cookie on
// hdr.sock_cookie (emit_tls_len stamps it exactly as emit_tls_data does for the heads).
fn tls_body_bio(tgid: u32, ts: u64, cookie: u64, nbytes: u32) -> EvtTlsBody {
    let mut e = tls_body(tgid, 0, ts, nbytes);
    e.hdr.sock_cookie = cookie;
    e
}

#[test]
fn bio_body_with_mismatched_cookie_does_not_cross_tally() {
    // Two CONCURRENT BIO connections in one process share the op-key (tgid,0). A body chunk
    // belonging to connection B must NOT be tallied into connection A's open op: doing so
    // crosses A's Content-Length early and emits A with B's timestamp and a content_length A
    // never received (wrong data, not under-capture). The cookie guard drops the foreign
    // chunk; A completes only on its OWN body bytes.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC1, 100, 7_000_000));
    c.on_connect(&connect(0xC2, 100, 7_000_000));
    assert!(c
        .on_tls_write(&tls_bio(100, 2_000, 0xC1, b"GET /a HTTP/1.1\r\nHost: a.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    assert!(c.on_tls_read(&tls_bio(100, 5_000, 0xC1, head)).is_none(), "op defers awaiting its body");
    // Connection B's chunk, big enough to complete A on its own if it were mis-tallied.
    assert!(
        c.on_tls_read_body(&tls_body_bio(100, 6_000, 0xC2, 100)).is_none(),
        "a foreign connection's body chunk must not complete this op"
    );
    // A's own body finishes it, with A's timings.
    let op = c
        .on_tls_read_body(&tls_body_bio(100, 9_000, 0xC1, 100))
        .expect("the owning connection's body completes the op");
    assert_eq!(op.download_ns, Some(4_000), "measured to A's chunk (9000), not B's (6000)");
    assert_eq!(op.total_ns, Some(7_000));
    assert_eq!(op.content_length, Some(100));
}

#[test]
fn download_total_measured_via_content_length_tally() {
    // A GET whose body arrives across separate reads: the response head defers the op
    // (Content-Length: 100, none coalesced), and the body-length events tally to the
    // target, completing it with download_ns/total_ns.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xA, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 5, 0xA, 1_000));
    assert!(c
        .on_tls_write(&tls_data(100, 5, 2_000, b"GET /a HTTP/1.1\r\nHost: a.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    // Response head (no body coalesced) -> op DEFERS, no emit yet. The head carries an
    // x-amz-request-id so we can prove head-captured fields SURVIVE the deferral.
    let head = b"HTTP/1.1 200 OK\r\nx-amz-request-id: TESTREQ123\r\nContent-Length: 100\r\n\r\n";
    assert!(c.on_tls_read(&tls_data(100, 5, 5_000, head)).is_none(), "op defers awaiting the body tally");
    // First body chunk: 60 of 100 -> still incomplete.
    assert!(c.on_tls_read_body(&tls_body(100, 5, 7_000, 60)).is_none());
    // Final chunk reaches 100 -> the op emits with download/total.
    let op = c.on_tls_read_body(&tls_body(100, 5, 9_000, 40)).expect("body complete emits the op");
    assert_eq!(op.http_status, Some(200));
    assert_eq!(op.ttfb_ns, Some(3_000), "req(2000)->head(5000)");
    assert_eq!(op.download_ns, Some(4_000), "head(5000)->last body(9000)");
    assert_eq!(op.total_ns, Some(7_000), "req(2000)->last body(9000)");
    assert_eq!(op.content_length, Some(100), "declared body size surfaced for per-op throughput");
    // Head-captured fields must survive being stashed in RespState and re-emitted:
    assert_eq!(op.aws_request_id.as_deref(), Some("TESTREQ123"), "request id survives the deferral");
    assert_eq!(
        op.op_bytes_recv,
        Some(head.len() as u64),
        "op_bytes_recv is the HEAD read length only — body bytes are tallied, not added here"
    );
    assert!(!op.partial);
}

#[test]
fn non_s3_host_get_is_not_labeled_an_s3_op() {
    // A plain GET to a non-S3 host (e.g. a CDN web page) must NOT be labeled GetObject —
    // s3_op stays None so the doctor emits no bogus "S3 server work" row. The raw verb is
    // still kept. An S3 host (next test / others) keeps its s3_op.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xE, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 9, 0xE, 1_000));
    c.on_tls_write(&tls_data(100, 9, 2_000, b"GET /s3/ HTTP/1.1\r\nHost: aws.amazon.com\r\n\r\n"));
    let op = c
        .on_tls_read(&tls_data(100, 9, 5_000, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        .expect("response completes the op");
    assert_eq!(op.s3_op, None, "non-S3 host -> no s3_op label");
    assert_eq!(op.bucket, None);
    assert_eq!(op.verb.as_deref(), Some("GET"), "raw HTTP verb is still recorded");
    assert_eq!(op.http_status, Some(200));
    assert!(!op.partial, "a clean non-S3 GET still judges as a normal op");
}

#[test]
fn large_body_truncates_capture_not_the_head_so_op_is_not_partial() {
    // A GET whose first read overflows the ~4KB plaintext capture buffer: the kernel sets
    // captured_truncated because the BODY spilled past it, but the response HEAD is fully
    // captured (header_end found). The op MUST NOT be partial — else every object larger
    // than the buffer is excluded from latency/tail judgement (regression: a live 64KiB GET
    // read all-ops-partial, so the doctor found "no latency spans to judge").
    let mut c = Correlator::new();
    c.on_connect(&connect(0xD, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 8, 0xD, 1_000));
    c.on_tls_write(&tls_data(100, 8, 2_000, b"GET /big HTTP/1.1\r\nHost: d.s3.amazonaws.com\r\n\r\n"));
    // Head read: full head + the first 16KB slice of a 65536-byte body; capture overflowed.
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n";
    let mut e = tls_data(100, 8, 5_000, head);
    e.plaintext_len = 16_384; // the real SSL_read returned 16KB (head + a body slice)
    e.captured_truncated = 1; // but only the ~4KB head region was captured; body dropped
    assert!(c.on_tls_read(&e).is_none(), "complete head + body pending -> defers");
    let seen_in_head = 16_384 - head.len() as u32; // body bytes coalesced into the head read
    let op = c
        .on_tls_read_body(&tls_body(100, 8, 9_000, 65_536 - seen_in_head))
        .expect("body tally completes -> emits");
    assert_eq!(op.http_status, Some(200));
    assert_eq!(op.content_length, Some(65_536));
    assert!(op.download_ns.is_some(), "download span measured across the body");
    assert_eq!(op.delimitation, s3tap_schema::Delimitation::Clean);
    assert!(!op.partial, "a complete head with a truncated-CAPTURE body is NOT partial");
}

#[test]
fn request_body_truncates_capture_not_the_head_so_op_is_not_partial() {
    // Symmetric to the response case: a PUT whose SSL_write coalesces the head AND a large
    // body overflows the ~4KB capture buffer (captured_truncated=1), but the request HEAD is
    // fully captured and parses. The op MUST NOT be partial -- else a large PutObject/
    // UploadPart is wrongly excluded from latency/tail judgement (the request-side analogue
    // of the response regression above).
    let mut c = Correlator::new();
    c.on_connect(&connect(0xE, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 9, 0xE, 1_000));
    let reqhead = b"PUT /obj HTTP/1.1\r\nHost: e.s3.amazonaws.com\r\nContent-Length: 65536\r\n\r\n";
    let mut w = tls_data(100, 9, 2_000, reqhead);
    w.plaintext_len = 16_384; // real SSL_write returned 16KB (head + a body slice)
    w.captured_truncated = 1; // but only the head region was captured; body dropped
    assert!(c.on_tls_write(&w).is_none());
    // A small clean response completes the op.
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let mut r = tls_data(100, 9, 5_000, resp);
    r.plaintext_len = resp.len() as u32;
    let op = c.on_tls_read(&r).expect("clean empty response completes the op");
    assert_eq!(op.verb.as_deref(), Some("PUT"));
    assert!(!op.partial, "a complete request head with a truncated-CAPTURE body is NOT partial");
}

#[test]
fn body_coalesced_into_head_completes_at_head() {
    // The whole body arrives in the same read as the head (plaintext_len covers head +
    // body) -> the op completes immediately, download_ns = 0 (no separate body span).
    let mut c = Correlator::new();
    c.on_connect(&connect(0xB, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 6, 0xB, 1_000));
    assert!(c
        .on_tls_write(&tls_data(100, 6, 2_000, b"GET /b HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let mut e = tls_data(100, 6, 5_000, head);
    e.plaintext_len = head.len() as u32 + 5; // 5 body bytes coalesced after the head
    let op = c.on_tls_read(&e).expect("complete-at-head emits immediately");
    assert_eq!(op.http_status, Some(200));
    assert_eq!(op.download_ns, Some(0), "body arrived with the head");
    assert_eq!(op.total_ns, Some(3_000), "req(2000)->head(5000)");
}

#[test]
fn body_incomplete_on_close_keeps_status_without_download() {
    // A GET whose body never finishes before the connection closes: the op flushes with
    // its status (not aborted/ambiguous), but download_ns/total_ns stay None — honest.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xC, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 7, 0xC, 1_000));
    c.on_tls_write(&tls_data(100, 7, 2_000, b"GET /c HTTP/1.1\r\nHost: c.s3.amazonaws.com\r\n\r\n"));
    assert!(c
        .on_tls_read(&tls_data(100, 7, 5_000, b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"))
        .is_none());
    c.on_tls_read_body(&tls_body(100, 7, 6_000, 200)); // only 200 of 1000
    // The connection closes mid-download -> the op is flushed with status, no download.
    c.on_close(&close(0xC, 0, 0, 0, 5));
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1, "the in-flight op is flushed, not dropped");
    let op = &flushed[0];
    assert_eq!(op.http_status, Some(200), "the response status is kept");
    assert_eq!(op.download_ns, None, "body never completed -> no download span");
    assert_eq!(op.total_ns, None);
    assert_eq!(
        op.delimitation,
        s3tap_schema::Delimitation::Clean,
        "got a response -> not ambiguous"
    );
}

#[test]
fn fd_reuse_after_missed_close_does_not_corrupt_the_next_connection() {
    // Connection A opens an op on (tgid 100, fd 5), then its close is DROPPED. fd 5 is
    // recycled by connection B (a new cookie via a new conn_id). Without invalidating
    // the op slot, B would inherit A's open op (flushed and mis-joined to B) and A's
    // next_seq (so B's genuine first op is mislabeled connection_reused). Assert the
    // fix: A's op is flushed against A, and B starts clean (req_seq 0, not reused).
    let mut c = Correlator::new();
    c.on_connect(&connect(0xA, 100, 11_000_000));
    c.on_conn_id(&conn_id(100, 5, 0xA, 1_000));
    // A sends a request — opens an in-flight op, emits nothing yet.
    assert!(c
        .on_tls_write(&tls_data(100, 5, 2_000, b"GET /a HTTP/1.1\r\nHost: a.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert!(c.take_flushed_ops().is_empty(), "A's op is still open");

    // A's close is NEVER observed. fd 5 is reused by connection B (new cookie).
    c.on_connect(&connect(0xB, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 5, 0xB, 3_000));

    // The fd rebind must have flushed A's aborted op, joined to A (cookie 0xA), NOT B.
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1, "A's in-flight op is flushed on the fd rebind");
    let a = &flushed[0];
    assert_eq!(a.sock_cookie, 0xA, "the flushed op stays joined to connection A");
    assert_eq!(a.bucket.as_deref(), Some("a"));
    assert_eq!(a.req_seq, 0);
    assert_eq!(a.http_status, None, "aborted in-flight op: no final response");

    // B now sends its FIRST request and gets a response. It must be a clean first op.
    assert!(c
        .on_tls_write(&tls_data(100, 5, 4_000, b"GET /b HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert!(c.take_flushed_ops().is_empty(), "B's first write must not flush a stale op");
    let b = c
        .on_tls_read(&tls_data(100, 5, 5_000, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("B's response closes its op");
    assert_eq!(b.sock_cookie, 0xB, "B's op is joined to B");
    assert_eq!(b.bucket.as_deref(), Some("b"));
    assert_eq!(b.req_seq, 0, "B's first op must NOT inherit A's next_seq");
    assert!(!b.connection_reused, "a genuinely-fresh connection is not 'reused'");
    assert_eq!(b.http_status, Some(200));
    use s3tap_schema::Delimitation;
    assert_eq!(b.delimitation, Delimitation::Clean, "B's op is not ambiguous");
}

fn tls_hello(cookie: u64, sni: &str, ts: u64) -> EvtTlsHandshake {
    let mut e = EvtTlsHandshake {
        sni_len: sni.len() as u8,
        ..Default::default()
    };
    e.hdr.type_ = EVT_TLS_HANDSHAKE;
    e.hdr.sock_cookie = cookie;
    e.hdr.ts_ns = ts;
    e.sni[..sni.len()].copy_from_slice(sni.as_bytes());
    e
}

#[test]
fn path_style_bucket_resolves_from_sni_when_host_header_is_absent() {
    // The captured request head has NO Host (pushed past HDR_CAP behind a long SigV4
    // header), but the connection's SNI is a path-style S3 endpoint. The op must still
    // split the bucket from the path via the SNI fallback (review Gap B), not treat
    // the whole "/bucket/key" as the object key.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xD, 100, 1_000_000));
    c.on_conn_id(&conn_id(100, 5, 0xD, 1_000));
    c.on_tls_handshake(&tls_hello(0xD, "s3.us-east-1.amazonaws.com", 1_500));
    assert!(c
        .on_tls_write(&tls_data(100, 5, 2_000, b"GET /my-bucket/the/key HTTP/1.1\r\n\r\n"))
        .is_none());
    let op = c
        .on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("response closes the op");
    assert_eq!(op.bucket.as_deref(), Some("my-bucket"), "bucket split from path via SNI");
    assert_eq!(op.s3_op.as_deref(), Some("GetObject"));
    assert!(op.key_hash.is_some(), "the key (the/key) is hashed, not the bucket");
}

#[test]
fn admitted_write_that_fails_to_parse_is_counted() {
    // The kernel admits a write that BEGINS with a method, but the parser can't
    // complete the request line (e.g. a split head). It must be counted, not vanish.
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(100, 5, 0xC, 1_000));
    // "GET /partial" with no HTTP-version token: admitted in-kernel, rejected here.
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, b"GET /partial-head-no-version")).is_none());
    assert_eq!(c.parse_failures(), 1, "an admitted-but-unparseable write is counted");
    // A genuine request does not bump the counter.
    assert!(c
        .on_tls_write(&tls_data(100, 5, 3_000, b"GET /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert_eq!(c.parse_failures(), 1, "a parseable request must not be counted");
}

#[test]
fn eviction_never_drops_the_just_opened_connection() {
    // The new entry is the newest, but a saturated start ts of 0 would make it
    // the numeric minimum — it must still be excluded from eviction.
    let mut c = Correlator::with_max_open(1);
    c.on_connect(&connect_at(1, 500));
    c.on_connect(&connect_at(2, 0)); // cap(1) exceeded -> evicts the OLD one (1)

    assert!(
        !c.on_close(&close(2, 0, 0, 0, 5)).unwrap().partial,
        "the connection just opened must survive eviction"
    );
    assert!(
        c.on_close(&close(1, 0, 0, 0, 5)).unwrap().partial,
        "the older connection was evicted"
    );
}

#[test]
fn pinned_connection_counters_are_a_documented_placeholder() {
    // `s3tap.operation/1` carries bytes_sent/bytes_recv/retransmits/srtt_us/lifetime_ns and
    // measures NONE of them: an op is emitted the moment its response completes, while those
    // are read off tcp_sock at CLOSE, which has not happened yet. `build_op` therefore writes
    // constants (0/0/0/null/null), and the schema documents each field as exactly that, with
    // the consumer pointed at the connection record for the real values.
    //
    // This test is what keeps that documentation true. If a later slice ever populates one of
    // these, it fails here — and the schema doc comments plus book/src/reference/records.md
    // have to be corrected in the same change, rather than the record quietly starting to
    // mean something new under an unchanged /1 tag.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xB1, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 4, 0xB1, 1_000));
    c.on_tls_write(&tls_data(100, 4, 2_000, b"GET /o HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    let op = c
        .on_tls_read(&tls_data(100, 4, 5_000, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        .expect("the response completes the op");
    assert_eq!(
        (op.bytes_sent, op.bytes_recv, op.retransmits),
        (0, 0, 0),
        "placeholders — NOT a measurement that this connection moved no bytes and lost none"
    );
    assert_eq!((op.srtt_us, op.lifetime_ns), (None, None));
    assert!(!op.partial, "and the op is otherwise clean: the zeros are not a partial-parse artifact");

    // The same socket then closes carrying the real counters, under the same `sock_cookie` —
    // the join the schema tells a consumer to make instead of aggregating the op fields.
    let rec = c.on_close(&close(0xB1, 5_242_880, 312, 2, 1_100)).expect("a connection record");
    assert_eq!(rec.sock_cookie, op.sock_cookie, "joinable: one socket, both records");
    assert_eq!((rec.bytes_sent, rec.bytes_recv, rec.retransmits), (5_242_880, 312, 2));
    assert_eq!((rec.srtt_us, rec.lifetime_ns), (Some(1_100), Some(4_200_000_000)));
}

#[test]
fn a_chunked_response_is_clean_with_no_span_to_measure() {
    // A chunked response (S3 answers every LIST that way) declares no length, so there is
    // nothing to tally a download against: download_ns / total_ns / content_length are all
    // null. The op is nonetheless CLEAN and non-partial — `delimitation` is about request
    // interleaving and `partial` is about the parse, and neither has anything to say about a
    // measurement that does not exist. This is the normal shape of a LIST, not a failure, and
    // the schema documents it field by field.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xF1, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 6, 0xF1, 1_000));
    c.on_tls_write(&tls_data(
        100,
        6,
        2_000,
        b"GET /?list-type=2&prefix=x HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n",
    ));
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nTransfer-Encoding: chunked\r\n\r\n";
    let op = c.on_tls_read(&tls_data(100, 6, 5_000, head)).expect("the head completes the op");
    assert_eq!(op.http_status, Some(200));
    assert_eq!(op.ttfb_ns, Some(3_000), "the op IS measured where a measurement exists");
    assert_eq!((op.content_length, op.download_ns, op.total_ns), (None, None, None));
    assert!(!op.partial, "the parse was complete");
    assert_eq!(op.delimitation, Delimitation::Clean, "no second request interleaved");

    // The OTHER null: a declared length whose body was never seen through. Same three timing
    // fields, but `content_length` is set — that is the pair a consumer reads to tell "there
    // was nothing to measure" from "the measurement was lost".
    c.on_tls_write(&tls_data(100, 6, 6_000, b"GET /o HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    assert!(
        c.on_tls_read(&tls_data(100, 6, 7_000, b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n"))
            .is_none(),
        "the op defers, awaiting a body that never arrives"
    );
    c.on_close(&close(0xF1, 100, 0, 0, 17_000)).expect("connection record");
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1);
    assert_eq!(
        (flushed[0].content_length, flushed[0].download_ns),
        (Some(4096), None),
        "declared but unfinished: a lost measurement, distinguishable from the chunked case"
    );
}

// --- sock-POINTER recycling: the same (tgid,fd) reused by the same process ---------

// A close stamped with an explicit time. The default `close()` leaves ts_ns 0, which
// on_close reads as "synthetic/unstamped input" and treats unconditionally — these tests
// need the real ordering, where a delayed close carries a time EARLIER than the link that
// superseded it.
fn close_at(cookie: u64, ts_ns: u64) -> EvtTcpClose {
    let mut e = close(cookie, 0, 0, 0, 17_000);
    e.hdr.ts_ns = ts_ns;
    e
}

#[test]
fn recycled_sock_pointer_in_one_process_does_not_hand_over_the_dead_op_slot() {
    // The kernel reallocates the same `struct sock *` to the next connect in the SAME
    // process, on the SAME fd number — so a new connection's conn_id can be identical to a
    // dead one's in every field the correlator can see. Fed in the ADVERSARIAL order (the
    // new conn_id rides tls_events and lands BEFORE the dead connection's close, which rides
    // `events`), that once defeated all three fd-reuse guards at once: on_conn_id skipped the
    // flush because the cookie matched, on_close skipped it because the link was now stamped
    // AFTER the close, and on_connect skipped it because the tgid was unchanged. The dead
    // request then got published under the new connection's identity and the new connection's
    // genuinely-first op shipped as a reuse.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xA, 100, 11_000_000)); // connection A
    c.on_conn_id(&conn_id(100, 5, 0xA, 100));
    assert!(c
        .on_tls_write(&tls_data(100, 5, 200, b"GET /d HTTP/1.1\r\nHost: dead.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert!(c.take_flushed_ops().is_empty(), "A's op is still open");

    // A's response never comes; A closes at ts 500 with its close still queued. The pointer
    // is reallocated to a new connect at ts 600 (same pid, same fd) whose conn_id is folded
    // FIRST — no inter-ring order.
    c.on_conn_id(&conn_id(100, 5, 0xA, 600));
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1, "the new connect's conn_id must retire the dead op slot");
    assert_eq!(flushed[0].bucket.as_deref(), Some("dead"), "flushed against A, not the newcomer");
    assert_eq!(flushed[0].req_seq, 0);
    assert_eq!(flushed[0].http_status, None, "aborted in flight: no response was seen");

    // A's delayed close, then B's own connect event.
    c.on_close(&close_at(0xA, 500));
    assert!(c.take_flushed_ops().is_empty(), "already flushed — a close must not re-emit it");
    c.on_connect(&connect(0xA, 100, 7_000_000)); // connection B, same pointer

    // B's first request must be a clean first op with B's own setup facts.
    assert!(c
        .on_tls_write(&tls_data(100, 5, 700, b"GET /f HTTP/1.1\r\nHost: fresh.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert!(c.take_flushed_ops().is_empty(), "B's write must not flush a stale op");
    let b = c
        .on_tls_read(&tls_data(100, 5, 800, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("B's response closes its op");
    assert_eq!(b.bucket.as_deref(), Some("fresh"));
    assert_eq!(b.req_seq, 0, "B's first op must not inherit A's next_seq");
    assert!(!b.connection_reused, "a genuinely-fresh connection is not a reuse");
    assert_eq!(b.tcp_connect_ns, Some(7_000_000), "so B keeps its real connect cost");
    assert_eq!(b.delimitation, Delimitation::Clean);
}

#[test]
fn a_recycled_pointer_on_a_new_fd_is_a_dead_connection_not_an_fd_migration() {
    // Same cookie, DIFFERENT fd. That cannot be a live connection moving fds: dup/dup2 emit
    // no conn_id, and emit_conn_id fires only from the connect kprobes — so a second conn_id
    // for one cookie means a second connect() on a recycled pointer, i.e. the old key's slot
    // belongs to a connection that is already dead. Carrying that slot across (as "migration"
    // once did) hands a dead connection's in-flight op and next_seq to a brand-new one.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xA, 100, 11_000_000)); // connection A on fd 5
    c.on_conn_id(&conn_id(100, 5, 0xA, 100));
    assert!(c
        .on_tls_write(&tls_data(100, 5, 200, b"GET /d HTTP/1.1\r\nHost: dead.s3.amazonaws.com\r\n\r\n"))
        .is_none());

    // A's close is DROPPED. The pointer is recycled by a new connect that landed on fd 9;
    // its conn_id is folded before its connect event (different rings).
    c.on_conn_id(&conn_id(100, 9, 0xA, 600));
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1, "the dead slot is flushed, not carried onto fd 9");
    assert_eq!(flushed[0].bucket.as_deref(), Some("dead"));
    assert_eq!(flushed[0].req_seq, 0);
    assert_eq!(flushed[0].http_status, None);
    assert_eq!(c.cookie_for_fd(100, 5), None, "the old link is gone with it");

    c.on_connect(&connect(0xA, 100, 7_000_000)); // connection B
    assert!(c
        .on_tls_write(&tls_data(100, 9, 700, b"GET /f HTTP/1.1\r\nHost: fresh.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    assert!(c.take_flushed_ops().is_empty(), "B's write must not flush a stale op");
    let b = c
        .on_tls_read(&tls_data(100, 9, 800, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("B's response closes its op");
    assert_eq!(b.bucket.as_deref(), Some("fresh"));
    assert_eq!(b.req_seq, 0, "B's first op must not inherit the dead connection's next_seq");
    assert!(!b.connection_reused);
    assert_eq!(b.tcp_connect_ns, Some(7_000_000));
    assert_eq!(b.delimitation, Delimitation::Clean);
}

#[test]
fn an_object_that_begins_with_an_http_response_does_not_close_its_own_op() {
    // The kernel routes a read to the head parser purely on a 7-byte `HTTP/1.` prefix, so a
    // WARC-style object whose bytes BEGIN with a stored HTTP response arrives looking exactly
    // like a response head. The declared Content-Length of the REAL head outranks it: while
    // the op is short of that target these bytes are body, whatever they spell. Without the
    // guard the embedded `Content-Length: 12` is satisfied inside its own chunk, so the
    // "whole body arrived with the head" path takes the op and discards the real response
    // state — the GET is published as a 12-byte 503 that downloaded instantly, and every
    // later chunk of the object is dropped.
    let mut c = Correlator::new();
    c.on_connect(&connect(0xA9, 100, 7_000_000));
    c.on_conn_id(&conn_id(100, 5, 0xA9, 1_000));
    assert!(c
        .on_tls_write(&tls_data(100, 5, 2_000, b"GET /w HTTP/1.1\r\nHost: warc.s3.amazonaws.com\r\n\r\n"))
        .is_none());
    // The real response head: a large object, so the op defers on its body tally.
    assert!(c
        .on_tls_read(&tls_data(100, 5, 5_000, b"HTTP/1.1 200 OK\r\nContent-Length: 5000000\r\n\r\n"))
        .is_none(), "the op defers, awaiting 5000000 body bytes");

    // The object's first bytes: a complete, self-consistent HTTP response of its own.
    let stored: &[u8] = b"HTTP/1.1 503 Slow Down\r\nContent-Length: 12\r\n\r\nthrottled!!!";
    assert!(
        c.on_tls_read(&tls_data(100, 5, 6_000, stored)).is_none(),
        "an object chunk must not be re-parsed as this op's response head"
    );

    // ...and those bytes counted toward the REAL target, so the remainder completes the op.
    let rest = 5_000_000 - stored.len() as u32;
    let op = c
        .on_tls_read_body(&tls_body(100, 5, 9_000, rest))
        .expect("the declared body completes the op");
    assert_eq!(op.http_status, Some(200), "the object's own 503 is not this op's status");
    assert_eq!(op.content_length, Some(5_000_000), "nor is the object's own 12-byte length");
    assert_eq!(op.download_ns, Some(4_000), "head(5000) -> last body byte(9000)");
    assert_eq!(op.total_ns, Some(7_000), "request(2000) -> last body byte(9000)");
    assert!(c.take_flushed_ops().is_empty(), "nothing was discarded along the way");
}

#[test]
fn a_partial_server_hello_does_not_erase_an_already_learned_field() {
    // The kernel can emit a cipher-only EVT_TLS_SERVER (version 0 when supported_versions
    // wasn't decodable), so two events can arrive for one cookie. Assigning each field
    // unconditionally means the second erases whatever the first taught us. Fed in both
    // orders, since either event can be the partial one.
    let mut c = Correlator::new();
    let server = |cookie: u64, version: u16, cipher: u16| EvtTlsServer {
        hdr: EventHdr { type_: EVT_TLS_SERVER, sock_cookie: cookie, ..Default::default() },
        version,
        cipher,
    };

    // Cipher first, then a version-only event: the cipher must survive.
    c.on_connect(&connect(0xA8, 100, 7_000_000));
    c.on_tls_server(&server(0xA8, 0, 0x1301));
    c.on_tls_server(&server(0xA8, 0x0304, 0));
    let rec = c.on_close(&close(0xA8, 0, 0, 0, 1000)).unwrap();
    assert_eq!(rec.tls.version.as_deref(), Some("TLS 1.3"));
    assert_eq!(rec.tls.cipher, Some(0x1301), "a version-only follow-up must not drop the cipher");

    // ...and the mirror image: version first, then a cipher-only event.
    c.on_connect(&connect(0xA6, 100, 7_000_000));
    c.on_tls_server(&server(0xA6, 0x0303, 0));
    c.on_tls_server(&server(0xA6, 0, 0xc02f));
    let rec = c.on_close(&close(0xA6, 0, 0, 0, 1000)).unwrap();
    assert_eq!(rec.tls.version.as_deref(), Some("TLS 1.2"), "a cipher-only follow-up must not drop the version");
    assert_eq!(rec.tls.cipher, Some(0xc02f));
}

#[test]
fn bio_close_prefers_the_slot_that_actually_holds_the_cookies_open_op() {
    // BIO ops all key on (tgid,0), so a recycled sock pointer can leave TWO processes naming
    // one cookie: process 200's slot keeps a residual `last_bio_cookie` from a request that
    // already completed, while process 100 has a LIVE in-flight request on the same pointer.
    // Matching on ownership alone let `.find()` pick between them in HashMap iteration order,
    // so whether the aborted request was emitted at all came down to hash seeding. Loop the
    // whole scenario so a per-map random order cannot let a coin-flip pass.
    for _ in 0..32 {
        let mut c = Correlator::new();
        // Process 200 completes a BIO request on cookie 0xC. Its close is DROPPED, so the
        // (200,0) slot survives carrying last_bio_cookie = 0xC.
        c.on_connect(&connect(0xC, 200, 5_000_000));
        c.on_tls_write(&tls_bio(200, 1_000, 0xC, b"GET /o HTTP/1.1\r\nHost: old.s3.amazonaws.com\r\n\r\n"));
        c.on_tls_read(&tls_bio(200, 2_000, 0xC, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
            .expect("process 200's op completes");

        // The pointer is recycled by process 100, which has a request in flight.
        c.on_connect(&connect(0xC, 100, 7_000_000));
        c.on_tls_write(&tls_bio(100, 3_000, 0xC, b"GET /l HTTP/1.1\r\nHost: live.s3.amazonaws.com\r\n\r\n"));

        c.on_close(&close(0xC, 0, 0, 0, 17_000));
        let flushed = c.take_flushed_ops();
        assert_eq!(flushed.len(), 1, "the in-flight request must be emitted, every run");
        assert_eq!(
            flushed[0].bucket.as_deref(),
            Some("live"),
            "the slot holding an OPEN op for this cookie wins over a residual last_bio_cookie"
        );
        assert_eq!(flushed[0].http_status, None, "aborted in flight");
    }
}
