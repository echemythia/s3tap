// crates/s3tap-core/tests/dns.rs
//
// D4 (M2) DNS correlation: feed synthetic query / response / getaddrinfo events
// plus a connect/close, and assert the folded Connection record's `dns` block
// and `endpoint.region`. Pure logic — no kernel.

use s3tap_core::Correlator;
use s3tap_events::{
    EventHdr, EvtDnsQuery, EvtDnsResponse, EvtGetaddrinfo, EvtTcpClose, EvtTcpConnect,
    EvtTlsHandshake, EVT_DNS_QUERY, EVT_DNS_RESPONSE, EVT_GETADDRINFO, EVT_TCP_CLOSE,
    EVT_TCP_CONNECT, EVT_TLS_HANDSHAKE,
};

// A TLS ClientHello event for `cookie` carrying `sni` (cookie = the connection's
// sk-cookie, the same key on_connect/on_close use).
fn tls_handshake(cookie: u64, sni: &str, ts: u64) -> EvtTlsHandshake {
    let mut h = EvtTlsHandshake {
        hdr: EventHdr {
            type_: EVT_TLS_HANDSHAKE,
            sock_cookie: cookie,
            ts_ns: ts,
            ..Default::default()
        },
        tls_version: 0x0303,
        sni_len: sni.len() as u8,
        ..Default::default()
    };
    h.sni[..sni.len()].copy_from_slice(sni.as_bytes());
    h
}

#[test]
fn tls_sni_fills_the_tls_block_and_region() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    c.on_tls_handshake(&tls_handshake(42, "b.s3.eu-west-1.amazonaws.com", 2_100));
    let rec = c.on_close(&close(42)).unwrap();

    assert!(rec.tls.seen, "a ClientHello marks tls.seen");
    assert_eq!(rec.tls.sni.as_deref(), Some("b.s3.eu-west-1.amazonaws.com"));
    assert_eq!(rec.tls.version, None, "negotiated version not derivable yet");
    assert_eq!(rec.endpoint.region.as_deref(), Some("eu-west-1"), "region from SNI");
}

#[test]
fn tls_sni_region_overrides_a_conflicting_dns_region() {
    // The IP resolved via a us-east-1 name, but the client's SNI for THIS
    // connection is eu-west-1 (shared/anycast IP). SNI wins — it's the name the
    // client actually requested, not a last-writer-wins reverse lookup.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_dns_query(&query(100, 1, "x.s3.us-east-1.amazonaws.com", 1_000));
    c.on_dns_response(&response_named(100, 1, "x.s3.us-east-1.amazonaws.com", 1_500, &[(2, ip, 60)]));
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    c.on_tls_handshake(&tls_handshake(42, "y.s3.eu-west-1.amazonaws.com", 2_100));
    let rec = c.on_close(&close(42)).unwrap();

    assert_eq!(rec.endpoint.region.as_deref(), Some("eu-west-1"), "SNI region wins");
    assert_eq!(rec.tls.sni.as_deref(), Some("y.s3.eu-west-1.amazonaws.com"));
}

#[test]
fn partial_record_keeps_the_sni_region() {
    // Connect was missed (partial), but we saw the ClientHello. The SNI is
    // connection-local (no IP join needed), so its region survives even though
    // the endpoint IP/family/dport don't.
    let mut c = Correlator::new();
    c.on_tls_handshake(&tls_handshake(42, "b.s3.eu-west-1.amazonaws.com", 2_100));
    let rec = c.on_close(&close(42)).unwrap(); // no on_connect -> partial

    assert!(rec.partial, "no connect seen");
    assert!(rec.tls.seen);
    assert_eq!(rec.tls.sni.as_deref(), Some("b.s3.eu-west-1.amazonaws.com"));
    assert_eq!(rec.endpoint.region.as_deref(), Some("eu-west-1"), "SNI region survives");
    assert_eq!(rec.endpoint.endpoint_ip, None, "no IP without the connect");
}

#[test]
fn sk_pointer_reuse_does_not_inherit_stale_tls() {
    // Connection A sends a ClientHello on cookie 7, then its close is dropped
    // under load. The kernel reuses the sk-pointer (cookie 7) for a new
    // connection B that sends no ClientHello. B must NOT inherit A's SNI/region.
    let mut c = Correlator::new();
    c.on_connect(&connect_to(7, 100, v4mapped(52, 216, 0, 1), 1_000));
    c.on_tls_handshake(&tls_handshake(7, "a.s3.eu-west-1.amazonaws.com", 1_100));
    // (A's on_close is missed.) New connection B reuses cookie 7:
    c.on_connect(&connect_to(7, 100, v4mapped(10, 0, 0, 9), 5_000));
    let rec = c.on_close(&close(7)).unwrap();

    assert!(!rec.tls.seen, "B must not inherit A's ClientHello");
    assert_eq!(rec.tls.sni, None);
    assert_ne!(rec.endpoint.region.as_deref(), Some("eu-west-1"), "no stale SNI region");
}

#[test]
fn no_tls_leaves_the_block_unseen() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(!rec.tls.seen);
    assert_eq!(rec.tls.sni, None);
}

#[test]
fn tls_sni_is_canonicalized_lowercase() {
    // SNI goes through the same qname_str canonicalization as DNS names.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    c.on_tls_handshake(&tls_handshake(42, "B.S3.EU-West-1.AmazonAWS.CoM", 2_100));
    let rec = c.on_close(&close(42)).unwrap();
    assert_eq!(rec.tls.sni.as_deref(), Some("b.s3.eu-west-1.amazonaws.com"));
    assert_eq!(rec.endpoint.region.as_deref(), Some("eu-west-1"));
}

#[test]
fn tls_sni_with_control_bytes_is_rejected() {
    // SECURITY (CWE-117): a malicious local process can put a newline / ANSI escape
    // in its ClientHello SNI to forge a log line or rewrite an operator's terminal
    // when the jsonl `tls.sni` is consumed by `jq -r`/grep. A non-hostname SNI must
    // be dropped (seen=false), never shipped verbatim.
    for poison in [
        "evil.com\n2026-06-22 forged log line",
        "evil.com\x1b]0;pwned\x07",
        "ev\til.com",
        "evil.com\u{2028}x",
        // S3-shaped with an embedded control byte: rejection must happen BEFORE
        // region parsing, so no region leaks from a poisoned name.
        "b.s3.eu-west-1.amazonaws.com\nX",
    ] {
        let mut c = Correlator::new();
        let ip = v4mapped(52, 216, 0, 1);
        c.on_connect(&connect_to(42, 100, ip, 2_000));
        c.on_tls_handshake(&tls_handshake(42, poison, 2_100));
        let rec = c.on_close(&close(42)).unwrap();
        assert_eq!(rec.tls.sni, None, "poison {poison:?} must be dropped");
        assert!(!rec.tls.seen, "poison {poison:?} must report seen=false");
        assert_eq!(rec.endpoint.region, None, "no region from a rejected name {poison:?}");
    }
    // Positive control: the SAME path records a clean SNI, so the false above is
    // meaningful (proves rejection, not a dead ingest path).
    let mut c = Correlator::new();
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 2_000));
    c.on_tls_handshake(&tls_handshake(42, "good.s3.eu-west-1.amazonaws.com", 2_100));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(rec.tls.seen && rec.tls.sni.is_some(), "clean SNI on the same path is recorded");
}

#[test]
fn two_connections_do_not_cross_contaminate_sni() {
    // Two sockets open at once with different SNIs/regions. Each close must return
    // its OWN SNI — a bug keying the tls map by anything but the cookie (e.g. last
    // -writer-wins) would pass every other test but fail here.
    let mut c = Correlator::new();
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 2_000));
    c.on_connect(&connect_to(99, 100, v4mapped(52, 216, 0, 2), 2_010));
    c.on_tls_handshake(&tls_handshake(42, "a.s3.eu-west-1.amazonaws.com", 2_100));
    c.on_tls_handshake(&tls_handshake(99, "b.s3.ap-southeast-2.amazonaws.com", 2_110));
    let r99 = c.on_close(&close(99)).unwrap();
    let r42 = c.on_close(&close(42)).unwrap();
    assert_eq!(r42.tls.sni.as_deref(), Some("a.s3.eu-west-1.amazonaws.com"));
    assert_eq!(r42.endpoint.region.as_deref(), Some("eu-west-1"));
    assert_eq!(r99.tls.sni.as_deref(), Some("b.s3.ap-southeast-2.amazonaws.com"));
    assert_eq!(r99.endpoint.region.as_deref(), Some("ap-southeast-2"));
}

#[test]
fn second_close_on_same_cookie_is_unseen() {
    // on_close must REMOVE the tls entry, not just read it: a stale entry left
    // behind would re-attach to a later (reused-cookie) connection's close.
    let mut c = Correlator::new();
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 2_000));
    c.on_tls_handshake(&tls_handshake(42, "b.s3.eu-west-1.amazonaws.com", 2_100));
    let first = c.on_close(&close(42)).unwrap();
    assert!(first.tls.seen);
    // A second close on the same cookie (no new handshake) must be unseen.
    let second = c.on_close(&close(42)).unwrap();
    assert!(!second.tls.seen, "tls entry must not survive the first close");
    assert_eq!(second.tls.sni, None);
}

#[test]
fn tls_map_evicts_oldest_at_capacity() {
    // Guards the deliberate `self.max_open` cap (not the smaller DNS_MAP_CAP): with
    // a cap of 2, a third handshake evicts the oldest SNI, so cookie 1 closes unseen
    // while 2 and 3 keep theirs.
    let mut c = Correlator::with_max_open(2);
    for (cookie, ts) in [(1u64, 1_000u64), (2, 2_000), (3, 3_000)] {
        c.on_connect(&connect_to(cookie, 100, v4mapped(52, 216, 0, cookie as u8), ts));
        c.on_tls_handshake(&tls_handshake(cookie, "b.s3.eu-west-1.amazonaws.com", ts + 50));
    }
    assert!(!c.on_close(&close(1)).unwrap().tls.seen, "oldest SNI evicted at cap");
    assert!(c.on_close(&close(2)).unwrap().tls.seen);
    assert!(c.on_close(&close(3)).unwrap().tls.seen);
}

#[test]
fn tls_sni_region_parses_legacy_and_govcloud_forms() {
    // The region table test drives region through the DNS path; prove the SNI path
    // (aws_region_from_host on tls_info.sni) agrees for the trickier forms too.
    for (sni, want) in [
        ("s3-ap-southeast-1.amazonaws.com", "ap-southeast-1"), // legacy dash
        ("b.s3.us-gov-east-1.amazonaws.com", "us-gov-east-1"), // 4-part govcloud
        ("s3.dualstack.eu-west-1.amazonaws.com", "eu-west-1"), // dualstack via SNI
    ] {
        let mut c = Correlator::new();
        c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 2_000));
        c.on_tls_handshake(&tls_handshake(42, sni, 2_100));
        let rec = c.on_close(&close(42)).unwrap();
        assert_eq!(rec.endpoint.region.as_deref(), Some(want), "SNI-path region for {sni}");
    }
}

#[test]
fn truncated_sni_is_dropped_not_shipped() {
    // The kernel sets sni_truncated when the real name ran past SNI_MAX. A clipped
    // prefix isn't the real server_name, so we report seen=false rather than a
    // confident, mangled host (the same stance as the control-byte rejection).
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let mut h = tls_handshake(42, "b.s3.eu-west-1.amazonaws.com", 2_100);
    h.sni_truncated = 1;
    c.on_tls_handshake(&h);
    let rec = c.on_close(&close(42)).unwrap();
    assert!(!rec.tls.seen, "a truncated SNI is not a confident name");
    assert_eq!(rec.tls.sni, None);
    assert_eq!(rec.endpoint.region.as_deref(), None, "no region from a dropped SNI");
}

#[test]
fn empty_sni_does_not_mark_seen() {
    // sni_len == 0 (a ClientHello the kernel would have discarded, or a zeroed
    // name): qname_str returns None, so nothing is recorded.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    c.on_tls_handshake(&tls_handshake(42, "", 2_100));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(!rec.tls.seen);
    assert_eq!(rec.tls.sni, None);
}

#[test]
fn non_s3_sni_falls_through_to_the_dns_region() {
    // SNI is present but non-S3 (no region), so the region must fall through to a
    // valid DNS resolution — the `.or(dns_region)` branch. A regression dropping
    // the DNS region whenever any SNI exists would silently strip region here.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_dns_query(&query(100, 1, "b.s3.us-east-1.amazonaws.com", 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)]));
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    c.on_tls_handshake(&tls_handshake(42, "example.com", 2_100));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(rec.tls.seen, "a non-S3 ClientHello is still a TLS handshake");
    assert_eq!(rec.tls.sni.as_deref(), Some("example.com"));
    assert_eq!(rec.endpoint.region.as_deref(), Some("us-east-1"), "region from DNS, not SNI");
}

#[test]
fn non_s3_sni_without_dns_has_no_region() {
    // TLS seen, SNI non-S3, no resolution: seen=true with the sni populated, but
    // region stays None — a non-S3 name must NOT be defaulted to a region.
    let mut c = Correlator::new();
    let ip = v4mapped(93, 184, 216, 34);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    c.on_tls_handshake(&tls_handshake(42, "example.com", 2_100));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(rec.tls.seen);
    assert_eq!(rec.tls.sni.as_deref(), Some("example.com"));
    assert_eq!(rec.endpoint.region, None);
}

fn v4mapped(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    let mut x = [0u8; 16];
    x[10] = 0xff;
    x[11] = 0xff;
    x[12] = a;
    x[13] = b;
    x[14] = c;
    x[15] = d;
    x
}

// `tgid` doubles as the resolver-socket cookie here: the query<->response join
// is on (sock_cookie, txn_id), so a query and its response must share it.
fn query(tgid: u32, txn: u16, name: &str, ts: u64) -> EvtDnsQuery {
    let mut q = EvtDnsQuery {
        hdr: EventHdr {
            type_: EVT_DNS_QUERY,
            tgid,
            sock_cookie: tgid as u64,
            ts_ns: ts,
            ..Default::default()
        },
        txn_id: txn,
        proto: 17,
        qname_len: name.len() as u8,
        ..Default::default()
    };
    q.qname[..name.len()].copy_from_slice(name.as_bytes());
    q
}

// Build a RAW DNS response for the common case: its question name is HOST, the name
// most tests query. Use [`response_named`] when a test queries a different name (the
// response must echo it, or the Gap F question<->query check rejects the pairing).
fn response(tgid: u32, txn: u16, ts: u64, answers: &[(u8, [u8; 16], u32)]) -> EvtDnsResponse {
    response_named(tgid, txn, HOST, ts, answers)
}

// Build a RAW DNS response wire message (header + 1 question echoing `name` + N
// answers) and pack it into the event's payload, mirroring what the kernel ships.
// answers: (family 2=A / 10=AAAA, v4-mapped-or-v6 addr, ttl).
fn response_named(tgid: u32, txn: u16, name: &str, ts: u64, answers: &[(u8, [u8; 16], u32)]) -> EvtDnsResponse {
    let mut w = Vec::new();
    w.extend_from_slice(&txn.to_be_bytes());
    w.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: standard response, NOERROR
    w.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    w.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
    w.extend_from_slice(&0u16.to_be_bytes()); // nscount
    w.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // question (name at offset 12): the echoed query name, qtype A, qclass IN.
    for label in name.split('.') {
        w.push(label.len() as u8);
        w.extend_from_slice(label.as_bytes());
    }
    w.extend_from_slice(&[0, 0, 1, 0, 1]); // root label + qtype(A) + qclass(IN)
    for (fam, addr, ttl) in answers {
        w.extend_from_slice(&[0xC0, 0x0C]); // name: compression pointer to offset 12
        let (rtype, rdata): (u16, &[u8]) = if *fam == 2 {
            (1, &addr[12..16]) // A: the v4-mapped octets
        } else {
            (28, &addr[..16]) // AAAA: full 16 bytes
        };
        w.extend_from_slice(&rtype.to_be_bytes());
        w.extend_from_slice(&1u16.to_be_bytes()); // class IN
        w.extend_from_slice(&ttl.to_be_bytes());
        w.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        w.extend_from_slice(rdata);
    }
    let mut r = EvtDnsResponse {
        hdr: EventHdr {
            type_: EVT_DNS_RESPONSE,
            tgid,
            sock_cookie: tgid as u64,
            ts_ns: ts,
            ..Default::default()
        },
        payload_len: w.len() as u16,
        ..Default::default()
    };
    r.payload[..w.len()].copy_from_slice(&w);
    r
}

fn getaddrinfo(tgid: u32, host: &str, latency_ns: u64, ts: u64, ret: i32) -> EvtGetaddrinfo {
    let mut g = EvtGetaddrinfo {
        hdr: EventHdr { type_: EVT_GETADDRINFO, tgid, ts_ns: ts, ..Default::default() },
        latency_ns,
        ret,
        hostname_len: host.len() as u8,
        ..Default::default()
    };
    g.hostname[..host.len()].copy_from_slice(host.as_bytes());
    g
}

fn connect_to(cookie: u64, tgid: u32, addr: [u8; 16], ts: u64) -> EvtTcpConnect {
    EvtTcpConnect {
        hdr: EventHdr { type_: EVT_TCP_CONNECT, sock_cookie: cookie, tgid, ts_ns: ts, ..Default::default() },
        family: 2,
        daddr: addr,
        dport: 443,
        connect_latency_ns: 0,
        ..Default::default()
    }
}

fn close(cookie: u64) -> EvtTcpClose {
    EvtTcpClose {
        hdr: EventHdr { type_: EVT_TCP_CLOSE, sock_cookie: cookie, ..Default::default() },
        ..Default::default()
    }
}

// An EVT_CONN_ID mapping (tgid, fd) -> cookie.
fn conn_id(cookie: u64, tgid: u32, fd: u32, ts: u64) -> s3tap_events::EvtConnId {
    s3tap_events::EvtConnId {
        hdr: EventHdr {
            type_: s3tap_events::EVT_CONN_ID,
            tgid,
            sock_cookie: cookie,
            ts_ns: ts,
            ..Default::default()
        },
        fd,
        _pad: 0,
    }
}

#[test]
fn conn_id_join_resolves_and_invalidates_on_close() {
    let mut c = Correlator::new();
    // (tgid 100, fd 5) -> cookie 42.
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    assert_eq!(c.cookie_for_fd(100, 5), Some(42), "the plaintext join resolves");
    assert_eq!(c.cookie_for_fd(100, 6), None, "unmapped fd is None");

    // Close cookie 42 -> the (tgid,fd) link is invalidated (fd reuse safety).
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 2_000));
    c.on_close(&close(42));
    assert_eq!(c.cookie_for_fd(100, 5), None, "close invalidates the link (fd is recycled)");

    // fd 5 reused by a NEW connection (cookie 99) -> resolves to the new cookie.
    c.on_conn_id(&conn_id(99, 100, 5, 3_000));
    assert_eq!(c.cookie_for_fd(100, 5), Some(99), "fd reuse maps to the new connection");
}

#[test]
fn conn_id_fd_reuse_without_close_keeps_live_link() {
    // fd K1 is reused by a NEW connection (C2) WITHOUT C1's close arriving first
    // (a missed/late close). The new link must win, and the LATE close of the old
    // cookie must NOT nuke the live new link. Also pins two-map consistency: a
    // cookie that migrated to a different fd no longer resolves on its old fd.
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(1, 100, 5, 1_000)); // K1=(100,5) -> C1=1
    c.on_conn_id(&conn_id(2, 100, 9, 1_100)); // K2=(100,9) -> C2=2
    // C2 now reported against fd 5 (cookie reused for a different fd while C1 lives):
    c.on_conn_id(&conn_id(2, 100, 5, 2_000)); // K1 -> C2, displacing C1 and K2
    assert_eq!(c.cookie_for_fd(100, 5), Some(2), "fd 5 now maps to C2");
    assert_eq!(c.cookie_for_fd(100, 9), None, "C2's old fd no longer resolves (consistency)");
    // The LATE close of the superseded C1 must be a no-op for the live link.
    c.on_close(&close(1));
    assert_eq!(c.cookie_for_fd(100, 5), Some(2), "late close of C1 must not nuke the live K1->C2");
}

#[test]
fn conn_id_after_close_is_recoverable_by_overwrite() {
    // Cross-ring reorder: conn_id rides tls_events, close rides events, so on_close
    // can run BEFORE the conn_id it would invalidate. That leaves a stale link the
    // close didn't catch — but a reuse of the fd overwrites it (the real guarantee).
    let mut c = Correlator::new();
    // Close arrives first (no link yet) -> no-op, no panic.
    c.on_close(&close(42));
    // Late conn_id inserts the (now post-close) link.
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    assert_eq!(c.cookie_for_fd(100, 5), Some(42), "late conn_id still inserts (stale but present)");
    // The fd is reused by a new connection -> its conn_id OVERWRITES the stale link,
    // before any of its plaintext could read it (same-ring FIFO in production).
    c.on_conn_id(&conn_id(99, 100, 5, 2_000));
    assert_eq!(c.cookie_for_fd(100, 5), Some(99), "overwrite-on-reuse corrects the link");
}

#[test]
fn conn_id_eviction_never_drops_the_just_inserted_link() {
    // With cap 2, a third CONN_ID whose ts is the SMALLEST must still evict an
    // OLDER entry, not itself (the ts_ns=0 / min-ts self-evict guard).
    let mut c = Correlator::with_max_open(2);
    c.on_conn_id(&conn_id(1, 100, 1, 5_000));
    c.on_conn_id(&conn_id(2, 100, 2, 6_000));
    c.on_conn_id(&conn_id(3, 100, 3, 0)); // smallest ts — must NOT evict itself
    assert_eq!(c.cookie_for_fd(100, 3), Some(3), "just-inserted link survives eviction");
}

// A captured SSL_write/read plaintext head for (tgid, fd).
fn tls_data(tgid: u32, fd: u32, ts: u64, payload: &[u8]) -> s3tap_events::EvtTlsData {
    let mut e = s3tap_events::EvtTlsData {
        hdr: EventHdr { tgid, ts_ns: ts, ..Default::default() },
        fd,
        plaintext_len: payload.len() as u32,
        captured_len: payload.len() as u16,
        ..Default::default()
    };
    e.data[..payload.len()].copy_from_slice(payload);
    e
}

#[test]
fn op_delimitation_emits_a_clean_operation() {
    use s3tap_schema::Delimitation;
    let mut c = Correlator::new();
    // Establish the connection + SNI + the (tgid,fd)->cookie join.
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));
    c.on_tls_handshake(&tls_handshake(42, "b.s3.eu-west-1.amazonaws.com", 1_200));

    let req = b"GET /my/key HTTP/1.1\r\nHost: b.s3.eu-west-1.amazonaws.com\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, req)).is_none(), "request opens, no emit");

    let resp = b"HTTP/1.1 200 OK\r\nx-amz-request-id: ABC123\r\n\r\n";
    let op = c.on_tls_read(&tls_data(100, 5, 2_500, resp)).expect("op emitted on response");
    assert_eq!(op.verb.as_deref(), Some("GET"));
    assert_eq!(op.s3_op.as_deref(), Some("GetObject"));
    assert_eq!(op.bucket.as_deref(), Some("b"), "bucket from SNI");
    assert!(op.key_hash.as_deref().unwrap().starts_with("sha256:"), "key hashed, not clear");
    assert_eq!(op.http_status, Some(200));
    assert_eq!(op.aws_request_id.as_deref(), Some("ABC123"));
    assert_eq!(op.sock_cookie, 42, "joined to the connection cookie");
    assert_eq!(op.req_seq, 0);
    assert!(!op.connection_reused, "first op paid connect");
    assert!(!op.partial);
    assert_eq!(op.delimitation, Delimitation::Clean);
    assert_eq!(op.op_bytes_sent, Some(req.len() as u64));
}

#[test]
fn second_request_before_response_marks_both_ambiguous() {
    use s3tap_schema::Delimitation;
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    let r1 = b"GET /a HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
    let r2 = b"GET /b HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, r1)).is_none());
    // 2nd request before r1's response -> flushes r1 as ambiguous + incomplete.
    let flushed = c.on_tls_write(&tls_data(100, 5, 2_100, r2)).expect("prior op flushed");
    assert_eq!(flushed.delimitation, Delimitation::Ambiguous);
    assert_eq!(flushed.req_seq, 0);
    assert_eq!(flushed.http_status, None, "flushed without a response");
    // r2's response closes r2 (also ambiguous), with req_seq 1.
    let op2 = c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).expect("r2 emitted");
    assert_eq!(op2.req_seq, 1);
    assert_eq!(op2.delimitation, Delimitation::Ambiguous);
}

#[test]
fn op_without_conn_id_join_is_partial_but_uses_host_bucket() {
    let mut c = Correlator::new();
    // No conn_id -> cookie_for_fd is None.
    c.on_tls_write(&tls_data(100, 9, 1_000, b"PUT /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    let op = c.on_tls_read(&tls_data(100, 9, 1_500, b"HTTP/1.1 200 OK\r\n\r\n")).expect("emitted");
    assert!(op.partial, "no (tgid,fd)->cookie join");
    assert_eq!(op.sock_cookie, 0);
    assert_eq!(op.app.pid, 100, "falls back to tgid");
    assert_eq!(op.s3_op.as_deref(), Some("PutObject"));
    assert_eq!(op.bucket.as_deref(), Some("b"), "bucket from Host header when SNI unjoined");
}

#[test]
fn op_leak_guard_evicts_least_recently_active_not_the_live_op() {
    // With cap 1, opening a 2nd op evicts the OLDEST connection's op — never the one
    // just opened. (Guards against the arbitrary-eviction bug that could drop a live op.)
    let mut c = Correlator::with_max_open(1);
    c.on_tls_write(&tls_data(100, 1, 1_000, b"GET /a HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    c.on_tls_write(&tls_data(100, 2, 2_000, b"GET /b HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    // The most-recent op (fd 2) survives; the oldest (fd 1) was evicted.
    assert!(
        c.on_tls_read(&tls_data(100, 2, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).is_some(),
        "the just-opened live op survives eviction"
    );
    assert!(
        c.on_tls_read(&tls_data(100, 1, 2_600, b"HTTP/1.1 200 OK\r\n\r\n")).is_none(),
        "the least-recently-active op was the eviction victim"
    );
}

#[test]
fn op_leak_guard_evicts_a_batch_oldest_first_and_still_flushes_each_op() {
    // The leak guard evicts cap/10 slots per pass (so a pinned `ops` map doesn't put an O(cap)
    // scan on every request), and every victim must still be FLUSHED as an aborted op rather
    // than silently dropped. One bucket per fd labels the ops so the order is checkable.
    let cap = 100u32;
    let mut c = Correlator::with_max_open(cap as usize);
    for fd in 1..=cap + 1 {
        let req = format!("GET /k HTTP/1.1\r\nHost: b{fd}.s3.amazonaws.com\r\n\r\n");
        assert!(c.on_tls_write(&tls_data(100, fd, u64::from(fd) * 1_000, req.as_bytes())).is_none());
    }

    // 101 slots over a cap of 100 -> one pass reclaims the 10 least-recently-active, and each
    // is emitted as an aborted op (no response seen), oldest first.
    let flushed = c.take_flushed_ops();
    let buckets: Vec<String> = flushed.iter().filter_map(|o| o.bucket.clone()).collect();
    assert_eq!(
        buckets,
        (1..=10).map(|fd| format!("b{fd}")).collect::<Vec<_>>(),
        "the 10 oldest op slots were flushed, oldest first"
    );
    assert!(flushed.iter().all(|o| o.http_status.is_none()), "flushed in flight, no response");

    // The 91 newer slots kept their open op: their responses still pair.
    assert!(
        c.on_tls_read(&tls_data(100, 11, 200_000, b"HTTP/1.1 200 OK\r\n\r\n")).is_some(),
        "a slot just outside the evicted batch survives"
    );
    assert!(
        c.on_tls_read(&tls_data(100, 10, 200_000, b"HTTP/1.1 200 OK\r\n\r\n")).is_none(),
        "the last evicted slot is gone"
    );
}

#[test]
fn keep_alive_two_ops_increment_req_seq_and_mark_reuse() {
    use s3tap_schema::Delimitation;
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));
    c.on_tls_handshake(&tls_handshake(42, "b.s3.eu-west-1.amazonaws.com", 1_200));
    let host = b"GET /a HTTP/1.1\r\nHost: b.s3.eu-west-1.amazonaws.com\r\n\r\n";
    // op 1: first op pays connect.
    c.on_tls_write(&tls_data(100, 5, 2_000, host));
    let op1 = c.on_tls_read(&tls_data(100, 5, 2_100, b"HTTP/1.1 200 OK\r\n\r\n")).expect("op1");
    assert_eq!(op1.req_seq, 0);
    assert!(!op1.connection_reused, "first op pays connect");
    assert_eq!(op1.delimitation, Delimitation::Clean);
    // op 2 on the SAME connection: req_seq 1, reused, no connect cost.
    c.on_tls_write(&tls_data(100, 5, 3_000, b"GET /b HTTP/1.1\r\nHost: b.s3.eu-west-1.amazonaws.com\r\n\r\n"));
    let op2 = c.on_tls_read(&tls_data(100, 5, 3_100, b"HTTP/1.1 200 OK\r\n\r\n")).expect("op2");
    assert_eq!(op2.req_seq, 1);
    assert!(op2.connection_reused, "second op reuses the connection");
    assert_eq!(op2.delimitation, Delimitation::Clean);
    assert_eq!(op2.tcp_connect_ns, None, "reused op didn't pay connect");
}

#[test]
fn close_reaps_op_state_and_a_reused_fd_starts_fresh() {
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_tls_write(&tls_data(100, 5, 2_000, b"GET /a HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    c.on_close(&close(42)); // reaps the open op state for (100,5)
    assert!(
        c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).is_none(),
        "op state was reaped on close"
    );
    // fd 5 reused by a NEW connection -> req_seq restarts at 0.
    c.on_conn_id(&conn_id(99, 100, 5, 3_000));
    c.on_tls_write(&tls_data(100, 5, 3_100, b"GET /b HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    let op = c.on_tls_read(&tls_data(100, 5, 3_200, b"HTTP/1.1 200 OK\r\n\r\n")).expect("new op");
    assert_eq!(op.req_seq, 0, "reused fd starts a fresh op sequence");
}

#[test]
fn multipart_upload_part_classified_through_the_correlator() {
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    let req = b"PUT /key?partNumber=2&uploadId=abc HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
    c.on_tls_write(&tls_data(100, 5, 2_000, req));
    let op = c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).expect("op");
    assert_eq!(op.s3_op.as_deref(), Some("UploadPart"), "resolved s3_op reaches the record");
    assert!(op.key_hash.is_some());
}

#[test]
fn interim_100_continue_does_not_close_the_op() {
    // boto3/aws-cli PUT with Expect: 100-continue: S3 sends "100 Continue" then the
    // real "200". The 100 must NOT close the op (else status=100 + lost completion).
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_tls_write(&tls_data(100, 5, 2_000, b"PUT /key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nExpect: 100-continue\r\n\r\n"));
    // Interim 100 -> no emit, op stays open.
    assert!(
        c.on_tls_read(&tls_data(100, 5, 2_100, b"HTTP/1.1 100 Continue\r\n\r\n")).is_none(),
        "100 Continue is interim, not the final response"
    );
    // The real 200 closes + emits the op with the CORRECT status.
    let op = c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\nx-amz-request-id: R1\r\n\r\n")).expect("real response emits");
    assert_eq!(op.http_status, Some(200), "final status, not the interim 100");
    assert_eq!(op.s3_op.as_deref(), Some("PutObject"));
    assert_eq!(op.aws_request_id.as_deref(), Some("R1"));
}

#[test]
fn truncated_request_head_is_reported_partial() {
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    let mut req = tls_data(100, 5, 2_000, b"GET /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n");
    req.captured_truncated = 1; // the head ran past the capture
    c.on_tls_write(&req);
    let op = c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).expect("emits");
    assert!(op.partial, "a truncated head is not advertised as a clean parse");
}

#[test]
fn response_with_no_open_request_emits_nothing() {
    let mut c = Correlator::new();
    assert!(
        c.on_tls_read(&tls_data(100, 5, 1_000, b"HTTP/1.1 200 OK\r\n\r\n")).is_none(),
        "a response with no open op (missed request) is dropped, not a phantom op"
    );
}

const HOST: &str = "b.s3.us-east-1.amazonaws.com";

#[test]
fn mixed_case_hostname_still_parses_region_and_joins_getaddrinfo() {
    // DNS is case-insensitive (RFC 4343); the wire preserves the app's case (e.g.
    // `curl https://S3.US-EAST-1.amazonaws.com`). The correlator must normalize so
    // the region parse and the gai<->wire join still work.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 7);
    let mixed = "B.S3.US-East-1.AmazonAWS.CoM";

    c.on_dns_query(&query(100, 1, mixed, 1_000));
    // The resolver echoes the (case-randomized) question name; both sides lowercase.
    c.on_dns_response(&response_named(100, 1, mixed, 1_500, &[(2, ip, 60)]));
    // getaddrinfo for a differently-cased spelling of the same host must still
    // join (both sides normalize to lowercase).
    c.on_getaddrinfo(&getaddrinfo(100, "b.s3.us-east-1.AMAZONAWS.com", 4_000, 1_600, 0));

    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.expect("mixed-case resolution still gets a dns block");
    assert_eq!(dns.via, "getaddrinfo", "case-insensitive gai<->wire join");
    assert_eq!(dns.latency_ns, 4_000);
    assert_eq!(
        rec.endpoint.region.as_deref(),
        Some("us-east-1"),
        "region must parse despite the uppercase on the wire"
    );
}

#[test]
fn fully_qualified_trailing_dot_host_still_joins_getaddrinfo() {
    // getaddrinfo("host.") (fully-qualified, trailing dot to skip search domains)
    // yields a dotted node string, but the wire qname is never dotted (the decoder
    // stops at the root label). qname_str must canonicalize both so the join holds
    // and the getaddrinfo latency isn't dropped.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 8);

    c.on_dns_query(&query(100, 1, HOST, 1_000)); // wire: no trailing dot
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)]));
    let fqdn = format!("{HOST}."); // app asked with a trailing dot
    c.on_getaddrinfo(&getaddrinfo(100, &fqdn, 3_000, 1_600, 0));

    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let dns = c.on_close(&close(42)).unwrap().dns.unwrap();
    assert_eq!(dns.via, "getaddrinfo", "FQDN trailing dot must not break the join");
    assert_eq!(dns.latency_ns, 3_000, "the getaddrinfo latency must be kept");
    assert!(!dns.cache_hit, "the overlapping wire query must still be detected");
}

#[test]
fn wire_resolution_labels_the_connection() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);

    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)])); // wire latency 500ns

    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.expect("connection to a resolved IP gets a dns block");
    assert_eq!(dns.via, "wire");
    assert_eq!(dns.latency_ns, 500);
    assert!(!dns.cache_hit);
    assert_eq!(dns.resolved_ip.as_deref(), Some("52.216.0.1"));
    assert_eq!(dns.n_answers, 1);
    assert_eq!(dns.ttl_s, Some(60));
    // region is derived from the resolved hostname.
    assert_eq!(rec.endpoint.region.as_deref(), Some("us-east-1"));
}

#[test]
fn getaddrinfo_supplies_the_paid_latency_and_via() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);

    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)]));
    // getaddrinfo call spanned the wire query (window covers ts 1_000) -> not a hit.
    c.on_getaddrinfo(&getaddrinfo(100, HOST, 5_000_000, 1_600, 0));

    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.unwrap();
    assert_eq!(dns.via, "getaddrinfo");
    assert_eq!(dns.latency_ns, 5_000_000, "the resolver-call latency the app paid");
    assert!(!dns.cache_hit, "a wire query overlapped the call");
}

#[test]
fn getaddrinfo_with_no_overlapping_wire_is_a_cache_hit() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);

    // An earlier wire resolution populated the IP->host map (and the OS cache).
    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)]));
    // A much later getaddrinfo whose window does NOT include any wire query.
    c.on_getaddrinfo(&getaddrinfo(100, HOST, 1_000, 10_000_000, 0));

    c.on_connect(&connect_to(42, 100, ip, 10_001_000));
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.unwrap();
    assert_eq!(dns.via, "getaddrinfo");
    assert!(dns.cache_hit, "no wire query in the call window => served from cache");
}

#[test]
fn wire_query_in_window_with_response_after_exit_is_not_a_cache_hit() {
    // The query lands inside the call window but its response is stamped just
    // AFTER getaddrinfo returned (probes are unordered; the response event can be
    // folded first with a slightly-later ts). Keying the check on resolved_ts
    // alone would miss this and mislabel a real network lookup as a cache hit;
    // the resolution's [query_ts, resolved_ts] interval overlaps the window, so
    // it must count. Regression for the resolved_ts-only cache-hit check.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);

    c.on_dns_query(&query(100, 1, HOST, 1_000_000)); // query in window
    c.on_dns_response(&response(100, 1, 1_001_000, &[(2, ip, 60)])); // response stamped after exit, folded first
    c.on_getaddrinfo(&getaddrinfo(100, HOST, 600, 1_000_500, 0)); // window [999_900, 1_000_500]

    c.on_connect(&connect_to(42, 100, ip, 1_002_000));
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.unwrap();
    assert_eq!(dns.via, "getaddrinfo");
    assert!(!dns.cache_hit, "a wire query overlapping the call window is not a cache hit");
}

#[test]
fn unmatched_response_records_no_resolution() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    // Response with no prior query (query predated attach) -> dropped.
    c.on_dns_response(&response(100, 9, 1_500, &[(2, ip, 60)]));
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(rec.dns.is_none(), "no paired query => no resolution => no dns block");
}

#[test]
fn truncated_query_is_dropped_rather_than_stored_as_a_prefix() {
    // F5: a truncated query name is only a prefix. Storing it would make the Gap F
    // question-name check reject the (full-name) response. Drop the query at ingest
    // (mirrors on_tls_handshake's sni_truncated guard). Outcome: no resolution, but no
    // stale prefix that could mis-pair a later response on the same (cookie, txn).
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 3);
    let mut q = query(100, 1, "a-pathologically-long-prefix", 1_000);
    q.qname_truncated = 1;
    c.on_dns_query(&q);
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)]));
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    assert!(c.on_close(&close(42)).unwrap().dns.is_none(), "truncated query records nothing");
}

#[test]
fn response_with_a_mismatched_question_name_does_not_mispair() {
    // (sock_cookie, 16-bit txn) collision on a reused resolver socket (review Gap F):
    // a query for HOST is pending when a response with the SAME (cookie, txn) but a
    // DIFFERENT question name arrives. It must NOT pair — the answer would attach the
    // wrong hostname/IP. The pending query stays, so the correct response still pairs.
    let mut c = Correlator::new();
    let ip_wrong = v4mapped(10, 0, 0, 1);
    let ip_right = v4mapped(52, 216, 0, 9);
    c.on_dns_query(&query(100, 1, HOST, 1_000));
    // Same (cookie, txn) but a foreign question name: ignored.
    c.on_dns_response(&response_named(100, 1, "evil.example.com", 1_200, &[(2, ip_wrong, 60)]));
    c.on_connect(&connect_to(40, 100, ip_wrong, 2_000));
    assert!(
        c.on_close(&close(40)).unwrap().dns.is_none(),
        "a mismatched-name answer must not be recorded for this query"
    );
    // The correct response (matching question name) still resolves.
    c.on_dns_response(&response_named(100, 1, HOST, 1_500, &[(2, ip_right, 60)]));
    c.on_connect(&connect_to(41, 100, ip_right, 2_100));
    assert!(
        c.on_close(&close(41)).unwrap().dns.is_some(),
        "the matching response must still pair after the collision was rejected"
    );
}

#[test]
fn connection_to_an_unresolved_ip_has_no_dns() {
    let mut c = Correlator::new();
    // Resolution exists for one IP, but we connect to a different one.
    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, v4mapped(52, 216, 0, 1), 60)]));
    c.on_connect(&connect_to(42, 100, v4mapped(10, 0, 0, 9), 2_000));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(rec.dns.is_none());
    assert!(rec.endpoint.region.is_none());
}

#[test]
fn region_parsing_covers_the_common_s3_forms() {
    // (hostname, expected region)
    let cases = [
        ("bucket.s3.eu-west-2.amazonaws.com", Some("eu-west-2")),
        ("s3.amazonaws.com", Some("us-east-1")), // regionless global endpoint
        ("s3-ap-southeast-1.amazonaws.com", Some("ap-southeast-1")), // legacy dash form
        ("s3.dualstack.eu-west-1.amazonaws.com", Some("eu-west-1")), // dualstack: region not adjacent to s3
        ("s3.us-gov-east-1.amazonaws.com", Some("us-gov-east-1")), // 4-part GovCloud region
        ("eu-west-1.s3.amazonaws.com", Some("us-east-1")), // bucket NAMED like a region -> still global
        ("s3.s3.eu-west-1.amazonaws.com", Some("eu-west-1")), // bucket literally named `s3`: don't stop at the first `s3`
        ("s3.dualstack.s3.eu-west-1.amazonaws.com", Some("eu-west-1")), // `dualstack` + `s3`-named bucket before the real anchor
        ("s3-mybucket.amazonaws.com", None), // `s3-`prefix that isn't a region: no bogus region
        ("s3-accelerate.amazonaws.com", None), // accelerate is global: no single region
        ("example.com", None), // non-AWS: no region, but still gets a dns block
    ];
    for (i, (host, want)) in cases.iter().enumerate() {
        let mut c = Correlator::new();
        let ip = v4mapped(52, 216, 0, i as u8);
        c.on_dns_query(&query(100, 1, host, 1_000));
        c.on_dns_response(&response_named(100, 1, host, 1_500, &[(2, ip, 60)]));
        c.on_connect(&connect_to(42, 100, ip, 2_000));
        let rec = c.on_close(&close(42)).unwrap();
        assert_eq!(rec.endpoint.region.as_deref(), *want, "host {host}");
        assert!(rec.dns.is_some(), "host {host} still gets a dns block");
    }
}

#[test]
fn aaaa_resolution_labels_an_ipv6_connection() {
    // A real (non-v4-mapped) IPv6 AAAA answer must resolve to an IpAddr::V6 that
    // matches the daddr key of an IPv6 connection (classify_endpoint convention).
    let mut c = Correlator::new();
    let mut a = [0u8; 16];
    a[0] = 0x26;
    a[1] = 0x00;
    a[2] = 0x1f;
    a[3] = 0x18;
    a[15] = 0x01; // 2600:1f18::1

    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(10, a, 120)]));

    let mut conn = connect_to(42, 100, a, 2_000);
    conn.family = 10; // AF_INET6
    c.on_connect(&conn);
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.expect("AAAA-resolved IPv6 connection gets a dns block");
    assert_eq!(dns.n_answers, 1);
    assert_eq!(dns.ttl_s, Some(120));
    assert_eq!(dns.resolved_ip.as_deref(), Some("2600:1f18::1"));
}

#[test]
fn multi_answer_resolves_every_ip() {
    let mut c = Correlator::new();
    let ip1 = v4mapped(52, 216, 0, 1);
    let ip2 = v4mapped(52, 216, 0, 2);

    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip1, 60), (2, ip2, 60)]));

    // Each answer IP is independently labeled, and n_answers reflects the count.
    for (cookie, ip) in [(42u64, ip1), (43, ip2)] {
        c.on_connect(&connect_to(cookie, 100, ip, 2_000));
        let rec = c.on_close(&close(cookie)).unwrap();
        let dns = rec.dns.expect("each resolved IP gets a dns block");
        assert_eq!(dns.n_answers, 2);
    }
}

#[test]
fn cname_before_a_record_is_skipped() {
    // host.example.com CNAME alias, then an A record — the parser must skip the
    // CNAME's rdata (a domain name) and still surface the A address.
    let txn = 7u16;
    let mut w = Vec::new();
    w.extend_from_slice(&txn.to_be_bytes());
    w.extend_from_slice(&0x8180u16.to_be_bytes());
    w.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    w.extend_from_slice(&2u16.to_be_bytes()); // ancount: CNAME + A
    w.extend_from_slice(&0u16.to_be_bytes());
    w.extend_from_slice(&0u16.to_be_bytes());
    for label in HOST.split('.') {
        // question echoes the query name (HOST), so the Gap F check pairs it.
        w.push(label.len() as u8);
        w.extend_from_slice(label.as_bytes());
    }
    w.extend_from_slice(&[0, 0, 1, 0, 1]); // root + qtype A + qclass IN
    // answer 1: CNAME, owner = ptr->12, rdata = "alias." (label + root).
    w.extend_from_slice(&[0xC0, 0x0C]);
    w.extend_from_slice(&5u16.to_be_bytes()); // type CNAME
    w.extend_from_slice(&1u16.to_be_bytes()); // class IN
    w.extend_from_slice(&300u32.to_be_bytes());
    let cname_rdata = [5u8, b'a', b'l', b'i', b'a', b's', 0];
    w.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
    w.extend_from_slice(&cname_rdata);
    // answer 2: A 52.216.0.5.
    w.extend_from_slice(&[0xC0, 0x0C]);
    w.extend_from_slice(&1u16.to_be_bytes()); // type A
    w.extend_from_slice(&1u16.to_be_bytes()); // class IN
    w.extend_from_slice(&60u32.to_be_bytes());
    w.extend_from_slice(&4u16.to_be_bytes());
    w.extend_from_slice(&[52, 216, 0, 5]);

    let mut e = EvtDnsResponse {
        hdr: EventHdr {
            type_: EVT_DNS_RESPONSE,
            tgid: 100,
            sock_cookie: 100, // matches query(100, ...) for the (cookie, txn) join
            ts_ns: 1_500,
            ..Default::default()
        },
        payload_len: w.len() as u16,
        ..Default::default()
    };
    e.payload[..w.len()].copy_from_slice(&w);

    let mut c = Correlator::new();
    c.on_dns_query(&query(100, txn, HOST, 1_000));
    c.on_dns_response(&e);
    let ip = v4mapped(52, 216, 0, 5);
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();

    let dns = rec.dns.expect("an A record following a CNAME is still resolved");
    assert_eq!(dns.resolved_ip.as_deref(), Some("52.216.0.5"));
    // n_answers counts only A/AAAA, so the CNAME does not inflate it.
    assert_eq!(dns.n_answers, 1);
}

#[test]
fn empty_answer_response_records_no_resolution() {
    // A NOERROR/NXDOMAIN response with zero answers pairs (and consumes) the
    // query but yields no IP->host mapping, so a later connection has no dns.
    let mut c = Correlator::new();
    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[]));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 2_000));
    let rec = c.on_close(&close(42)).unwrap();
    assert!(rec.dns.is_none(), "no answers => no resolution => no dns block");
}

#[test]
fn pending_query_after_the_call_window_does_not_mask_a_cache_hit() {
    // The ring buffer gives no cross-probe ordering, so a wire query stamped
    // LATER than a getaddrinfo's exit can be folded BEFORE it. Such a query (and
    // any stale never-answered pending entry) is outside the call window and must
    // not count as wire activity — otherwise a genuine cache hit reads as a miss.
    // Regression for the pending-branch missing its upper time bound.
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);

    // Seed the IP->host map with an answered resolution so the connection can be
    // labeled. Its resolved_ts (1_400) is well before the gai window below.
    c.on_dns_query(&query(100, 2, HOST, 1_300));
    c.on_dns_response(&response(100, 2, 1_400, &[(2, ip, 60)]));

    // A pending query stamped AFTER the gai exit (reordered arrival), never
    // answered. query_ts 10_005_000 is past the window's upper bound 10_000_000.
    c.on_dns_query(&query(100, 3, HOST, 10_005_000));

    // getaddrinfo: window [9_999_000, 10_000_000]. The pending query at
    // 10_005_000 is out of range -> this is a cache hit.
    c.on_getaddrinfo(&getaddrinfo(100, HOST, 1_000, 10_000_000, 0));

    c.on_connect(&connect_to(42, 100, ip, 10_001_000));
    let dns = c.on_close(&close(42)).unwrap().dns.unwrap();
    assert_eq!(dns.via, "getaddrinfo");
    assert!(dns.cache_hit, "a query outside the call window must not force a miss");
}

#[test]
fn getaddrinfo_after_the_connection_does_not_decorate_it() {
    // The gai map is last-writer-wins per host. A resolver call stamped AFTER
    // this connection's SYN is a different episode and must not supply its
    // latency/cache_hit; the record falls back to the wire facts (via:"wire").
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);

    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)])); // wire latency 500
    c.on_connect(&connect_to(42, 100, ip, 2_000)); // SYN at 2_000

    // A later, unrelated cache-hit getaddrinfo (ts 3_000 > connect 2_000).
    c.on_getaddrinfo(&getaddrinfo(100, HOST, 9_000_000, 3_000, 0));

    let dns = c.on_close(&close(42)).unwrap().dns.unwrap();
    assert_eq!(dns.via, "wire", "a getaddrinfo after the connect must not decorate it");
    assert_eq!(dns.latency_ns, 500, "falls back to the wire latency");
    assert!(!dns.cache_hit);
}

#[test]
fn failed_getaddrinfo_is_ignored() {
    let mut c = Correlator::new();
    let ip = v4mapped(52, 216, 0, 1);
    c.on_dns_query(&query(100, 1, HOST, 1_000));
    c.on_dns_response(&response(100, 1, 1_500, &[(2, ip, 60)]));
    c.on_getaddrinfo(&getaddrinfo(100, HOST, 9_000, 1_600, -2)); // EAI_NONAME-ish
    c.on_connect(&connect_to(42, 100, ip, 2_000));
    let rec = c.on_close(&close(42)).unwrap();
    // A failed lookup contributes nothing, so we fall back to the wire facts.
    let dns = rec.dns.unwrap();
    assert_eq!(dns.via, "wire");
}

// --- M3.5: latency decomposition on the operation record (E6-E8) ---

#[test]
fn op_first_on_connection_carries_ttfb_and_the_dns_block() {
    // The first op on a connection paid for resolution + connect, so it carries the
    // dns block; ttfb is the request->response-head delta. tls_handshake_ns/total_ns
    // stay null (unmeasured / response-completion not observed).
    let ip = v4mapped(52, 216, 0, 1);
    let mut c = Correlator::new();
    // Resolve HOST -> ip (wire latency 400), then connect + join + SNI.
    c.on_dns_query(&query(7, 0xABCD, HOST, 1_000));
    c.on_dns_response(&response(7, 0xABCD, 1_400, &[(2, ip, 60)]));
    c.on_conn_id(&conn_id(42, 100, 5, 1_500));
    c.on_connect(&connect_to(42, 100, ip, 1_600));
    c.on_tls_handshake(&tls_handshake(42, HOST, 1_700));

    let req = b"GET /k HTTP/1.1\r\nHost: b.s3.us-east-1.amazonaws.com\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, req)).is_none());
    let op = c
        .on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("op emitted");

    assert_eq!(op.ttfb_ns, Some(500), "request 2000 -> response head 2500");
    let dns = op.dns.as_ref().expect("first op carries the dns block");
    assert_eq!(dns.latency_ns, 400, "the wire resolution latency this op paid");
    assert_eq!(dns.resolved_ip.as_deref(), Some("52.216.0.1"));
    assert_eq!(op.tls_handshake_ns, None, "send-side hook can't time the handshake");
    assert_eq!(op.total_ns, None, "response completion not observed (body head-gated)");
    assert!(!op.connection_reused);
}

#[test]
fn reused_op_drops_setup_phases_but_keeps_ttfb() {
    // PHASE HONESTY (E8): a reused connection's later op did NOT pay dns/connect, so
    // those collapse to None (never a misleading repeat or 0) — but ttfb is op-local
    // and is still measured for every op.
    let ip = v4mapped(52, 216, 0, 1);
    let mut c = Correlator::new();
    c.on_dns_query(&query(7, 1, HOST, 1_000));
    c.on_dns_response(&response(7, 1, 1_400, &[(2, ip, 60)]));
    c.on_conn_id(&conn_id(42, 100, 5, 1_500));
    c.on_connect(&connect_to(42, 100, ip, 1_600));

    let req = b"GET /k HTTP/1.1\r\nHost: b.s3.us-east-1.amazonaws.com\r\n\r\n";
    // op1 (req_seq 0): ttfb 200, dns present.
    c.on_tls_write(&tls_data(100, 5, 2_000, req));
    let op1 = c.on_tls_read(&tls_data(100, 5, 2_200, b"HTTP/1.1 200 OK\r\n\r\n")).unwrap();
    // op2 (req_seq 1, reused): ttfb 300, but no setup phases.
    c.on_tls_write(&tls_data(100, 5, 3_000, req));
    let op2 = c.on_tls_read(&tls_data(100, 5, 3_300, b"HTTP/1.1 200 OK\r\n\r\n")).unwrap();

    assert_eq!(op1.ttfb_ns, Some(200));
    assert!(op1.dns.is_some(), "first op paid resolution");
    assert!(!op1.connection_reused);

    assert_eq!(op2.ttfb_ns, Some(300), "ttfb is measured on every op");
    assert!(op2.dns.is_none(), "a reused op did not resolve — None, not a repeat");
    assert_eq!(op2.tcp_connect_ns, None, "a reused op did not connect");
    assert!(op2.connection_reused);
}

#[test]
fn partial_join_op_still_measures_ttfb() {
    // With no CONN_ID join the op is partial (no connection facts), so the dns block
    // can't attach — but ttfb is purely op-local (two TLS-event timestamps), so it
    // survives the missing join.
    let mut c = Correlator::new();
    c.on_tls_write(&tls_data(100, 9, 1_000, b"PUT /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    let op = c
        .on_tls_read(&tls_data(100, 9, 1_400, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("emitted");
    assert!(op.partial, "no cookie join -> partial");
    assert_eq!(op.ttfb_ns, Some(400), "ttfb survives a partial join");
    assert!(op.dns.is_none(), "no connection -> no dns block");
}

#[test]
fn ambiguous_flush_has_no_ttfb() {
    // An op flushed because a second request arrived before its response never saw a
    // response, so it has no ttfb (and stays delimitation=ambiguous).
    use s3tap_schema::Delimitation;
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));
    let req = b"GET /a HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, req)).is_none());
    let flushed = c.on_tls_write(&tls_data(100, 5, 2_100, req)).expect("prior op flushed");
    assert_eq!(flushed.delimitation, Delimitation::Ambiguous);
    assert_eq!(flushed.ttfb_ns, None, "no response was seen for the flushed op");
}

#[test]
fn first_op_dns_block_matches_the_connection_record() {
    // Cross-record lock: the first op's dns block is built from the SAME inputs as
    // the connection record's (same ip/conn_ts/dns_for_ip), so an analyst joining
    // op->connection sees identical blocks. Pins that the two paths can't desync.
    let ip = v4mapped(52, 216, 0, 1);
    let mut c = Correlator::new();
    c.on_dns_query(&query(7, 1, HOST, 1_000));
    c.on_dns_response(&response(7, 1, 1_450, &[(2, ip, 60)])); // wire latency 450
    c.on_conn_id(&conn_id(42, 100, 5, 1_500));
    c.on_connect(&connect_to(42, 100, ip, 1_600));
    c.on_tls_handshake(&tls_handshake(42, HOST, 1_700));

    let req = b"GET /k HTTP/1.1\r\nHost: b.s3.us-east-1.amazonaws.com\r\n\r\n";
    c.on_tls_write(&tls_data(100, 5, 2_000, req));
    let op = c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).unwrap();
    // Close the connection -> its record's dns block, built independently.
    let conn = c.on_close(&close(42)).unwrap();

    assert!(op.dns.is_some(), "first op carries a dns block");
    assert_eq!(op.dns, conn.dns, "op and connection dns blocks are identical");
}

#[test]
fn op_with_cookie_but_no_connstate_is_partial_not_clean() {
    // HONESTY: a conn_id maps (tgid,fd)->cookie, so the cookie resolves — but the
    // connect event was never folded (dropped / cap-evicted / cross-ring-reordered
    // behind the plaintext). dns/tcp_connect_ns silently go None; the op MUST be
    // flagged partial, never shipped as a clean first-op-with-no-setup.
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000)); // cookie 42 joins...
    // ...but NO on_connect(42) — so conns.get(42) misses.
    c.on_tls_write(&tls_data(100, 5, 2_000, b"GET /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    let op = c.on_tls_read(&tls_data(100, 5, 2_400, b"HTTP/1.1 200 OK\r\n\r\n")).expect("emitted");

    assert!(op.partial, "cookie resolved but no ConnState -> partial");
    assert!(op.dns.is_none(), "no connection -> no dns block");
    assert_eq!(op.tcp_connect_ns, None, "no connection -> no connect timing");
    assert_eq!(op.ttfb_ns, Some(400), "ttfb is op-local, still measured");
    assert_eq!(op.sock_cookie, 42, "the cookie still joined (it's the conns miss that's partial)");
}

#[test]
fn ttfb_measures_to_the_100_continue_not_the_post_upload_final() {
    // A boto3/aws-cli PUT: request head (T0), "100 Continue" go-ahead (T1), then the
    // body uploads for seconds (head-gated, unseen), then "200 OK" (T2). ttfb must be
    // T1-T0 (request->go-ahead RTT), NOT T2-T0 (which folds in the whole body upload
    // and would mislabel a big UploadPart as "S3 was slow to respond").
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));

    let put = b"PUT /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nExpect: 100-continue\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, put)).is_none(), "request opens"); // T0
    assert!(
        c.on_tls_read(&tls_data(100, 5, 2_100, b"HTTP/1.1 100 Continue\r\n\r\n")).is_none(),
        "interim keeps the op open"
    ); // T1
    // ...body upload happens here (T1..T2), head-gated, never seen...
    let op = c
        .on_tls_read(&tls_data(100, 5, 9_000, b"HTTP/1.1 200 OK\r\n\r\n"))
        .expect("final closes the op"); // T2

    assert_eq!(op.http_status, Some(200), "the FINAL status, not the interim");
    assert_eq!(op.ttfb_ns, Some(100), "ttfb = T1-T0 (go-ahead), not T2-T0 (7000, upload-inflated)");
}

#[test]
fn ambiguous_flush_after_a_100_keeps_the_interim_ttfb() {
    // Seam between the two M3.5-review fixes: an op that received a 100 Continue and
    // is THEN flushed (a second request arrived before its final response) still saw
    // its first response byte — so ttfb is measured to that interim, even though the
    // op closes with no final status. "ttfb Some + http_status None" is coherent.
    use s3tap_schema::Delimitation;
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));

    let put = b"PUT /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nExpect: 100-continue\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, put)).is_none()); // T0 opens op
    assert!(c.on_tls_read(&tls_data(100, 5, 2_150, b"HTTP/1.1 100 Continue\r\n\r\n")).is_none()); // T1 interim
    // A second request arrives before the final response -> the prior op is flushed.
    let flushed = c.on_tls_write(&tls_data(100, 5, 2_300, put)).expect("prior op flushed");

    assert_eq!(flushed.delimitation, Delimitation::Ambiguous);
    assert_eq!(flushed.http_status, None, "never saw a final status");
    assert_eq!(flushed.ttfb_ns, Some(150), "but DID see the first byte (100 at T1) -> ttfb=T1-T0");
}

// --- in-flight op flushed at connection close (the abort signal) ---

#[test]
fn in_flight_op_is_flushed_when_its_connection_closes() {
    // A request was sent but the connection closes before any response — the op must
    // be EMITTED (not silently dropped) carrying http_status=None.
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));
    let req = b"GET /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
    assert!(c.on_tls_write(&tls_data(100, 5, 2_000, req)).is_none(), "request opens, no emit");

    let conn = c.on_close(&close(42));
    assert!(conn.is_some(), "the connection record still emits");
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1, "the in-flight op is flushed, not dropped");
    assert_eq!(flushed[0].verb.as_deref(), Some("GET"));
    assert_eq!(flushed[0].s3_op.as_deref(), Some("GetObject"));
    assert_eq!(flushed[0].http_status, None, "no final response was seen");
    assert!(c.take_flushed_ops().is_empty(), "draining is one-shot");
}

#[test]
fn a_completed_op_is_not_reflushed_on_close() {
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));
    c.on_tls_write(&tls_data(100, 5, 2_000, b"GET /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"));
    assert!(
        c.on_tls_read(&tls_data(100, 5, 2_500, b"HTTP/1.1 200 OK\r\n\r\n")).is_some(),
        "the response closes the op"
    );
    c.on_close(&close(42));
    assert!(c.take_flushed_ops().is_empty(), "no in-flight op -> nothing flushed");
}

#[test]
fn aborted_after_100_continue_flushes_with_ttfb_and_no_status() {
    // A PUT got its 100-continue (ttfb measurable) then the
    // connection was aborted before the final status — ttfb_ns present, http_status None.
    let mut c = Correlator::new();
    c.on_conn_id(&conn_id(42, 100, 5, 1_000));
    c.on_connect(&connect_to(42, 100, v4mapped(52, 216, 0, 1), 1_100));
    let put = b"PUT /k HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nExpect: 100-continue\r\n\r\n";
    c.on_tls_write(&tls_data(100, 5, 2_000, put)); // T0
    assert!(c.on_tls_read(&tls_data(100, 5, 2_100, b"HTTP/1.1 100 Continue\r\n\r\n")).is_none()); // T1
    // ...body uploading, then the connection is reset before the 200...
    c.on_close(&close(42));
    let flushed = c.take_flushed_ops();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].ttfb_ns, Some(100), "ttfb measured to the 100-continue go-ahead");
    assert_eq!(flushed[0].http_status, None, "aborted before the final status");
}
