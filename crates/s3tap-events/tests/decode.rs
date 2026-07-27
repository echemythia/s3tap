// crates/s3tap-events/tests/decode.rs
//
// Decode-path tests: hand-build raw event bytes (as the kernel would lay them
// out) and assert Event::parse reads the fields back correctly — no kernel
// involved. Field offsets here must match bpf/include/s3tap_events.h.

use s3tap_events::{
    Event, EvtProcExec, EVT_CONN_ID, EVT_DNS_QUERY, EVT_DNS_RESPONSE, EVT_GETADDRINFO,
    EVT_TCP_CONNECT, EVT_TLS_HANDSHAKE, EVT_TLS_READ, EVT_TLS_READ_BODY, EVT_TLS_WRITE,
};

#[test]
fn proc_exec_extractors_bound_comm_and_exe() {
    // These feed every --app/--exe match (filter.rs), so a NUL-trim/bound bug here
    // silently mis-matches. Mirror the kernel's fill contract: comm is zero-padded
    // (bpf_get_current_comm), exe is bounded by exe_len.
    let mut e = EvtProcExec::default();
    e.comm[..7].copy_from_slice(b"python3");
    assert_eq!(e.comm_str(), b"python3", "comm trims at the first NUL");

    // A full 16-byte comm with no NUL falls back to the whole field (no over-read).
    e.comm = *b"0123456789abcdef";
    assert_eq!(e.comm_str(), b"0123456789abcdef");

    let path = b"/usr/bin/python3.11";
    e.exe[..path.len()].copy_from_slice(path);
    e.exe_len = path.len() as u8;
    assert_eq!(e.exe_path(), path, "exe bounded to exe_len");

    // An exe_len at/over the buffer is clamped — never an out-of-bounds slice.
    e.exe_len = 255;
    assert_eq!(e.exe_path().len(), 255);
}

#[test]
fn parses_a_conn_id_record() {
    let mut buf = vec![0u8; 40];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_CONN_ID.to_ne_bytes());
    put(&mut buf, 16, &4242u32.to_ne_bytes()); // tgid
    put(&mut buf, 24, &0xfeed_face_u64.to_ne_bytes()); // sock_cookie
    put(&mut buf, 32, &7u32.to_ne_bytes()); // fd
    match Event::parse(&buf) {
        Some(Event::ConnId(e)) => {
            assert_eq!(e.hdr.tgid, 4242);
            assert_eq!(e.hdr.sock_cookie, 0xfeed_face);
            assert_eq!(e.fd, 7);
        }
        other => panic!("expected ConnId, got {other:?}"),
    }
    assert!(Event::parse(&buf[..39]).is_none(), "39 (short) refused");
}

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn parses_tls_write_and_read_records() {
    // 4144-byte evt_tls_data: an HTTP request prefix on EVT_TLS_WRITE, and a
    // status-line prefix on EVT_TLS_READ — same struct, different tag.
    for (tag, payload, want_write) in [
        (EVT_TLS_WRITE, &b"GET /key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n"[..], true),
        (EVT_TLS_READ, &b"HTTP/1.1 200 OK\r\nx-amz-request-id: ABC\r\n\r\n"[..], false),
    ] {
        let mut buf = vec![0u8; 4144];
        put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
        put(&mut buf, 2, &tag.to_ne_bytes());
        put(&mut buf, 16, &4242u32.to_ne_bytes()); // tgid (the join key half)
        put(&mut buf, 32, &7u32.to_ne_bytes()); // fd
        put(&mut buf, 36, &(payload.len() as u32).to_ne_bytes()); // plaintext_len
        put(&mut buf, 40, &(payload.len() as u16).to_ne_bytes()); // captured_len
        put(&mut buf, 44, payload); // data tail

        match Event::parse(&buf) {
            Some(Event::TlsWrite(e)) if want_write => {
                assert_eq!(e.hdr.tgid, 4242);
                assert_eq!(e.fd, 7);
                assert_eq!(e.plaintext_len as usize, payload.len());
                assert_eq!(&e.data[..e.captured_len as usize], payload);
                assert_eq!(e.captured_truncated, 0);
            }
            Some(Event::TlsRead(e)) if !want_write => {
                assert_eq!(&e.data[..e.captured_len as usize], payload);
            }
            other => panic!("expected TlsWrite/TlsRead for {tag}, got {other:?}"),
        }
    }
    // Exact-length strict-ABI guard: a TLS record one byte short OR one byte long
    // is refused (never read partially) — the defense against decoding a different
    // -sized ABI as this struct.
    let mut buf = vec![0u8; 4144];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_TLS_WRITE.to_ne_bytes());
    assert!(Event::parse(&buf).is_some(), "exact 4144 decodes");
    assert!(Event::parse(&buf[..4143]).is_none(), "4143 (short) refused");
    let mut long = buf.clone();
    long.push(0);
    assert!(Event::parse(&long).is_none(), "4145 (long) refused");
}

#[test]
fn parses_a_tls_read_body_record() {
    // 40-byte evt_tls_body — NOT the 4144-byte evt_tls_data the heads use, even though
    // it shares tag 23's old meaning. Only (tgid, ts_ns, fd, plaintext_len) exist here.
    let mut buf = vec![0u8; 40];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_TLS_READ_BODY.to_ne_bytes());
    put(&mut buf, 8, &9_000u64.to_ne_bytes()); // ts_ns
    put(&mut buf, 16, &4242u32.to_ne_bytes()); // tgid (the join key half)
    put(&mut buf, 32, &7u32.to_ne_bytes()); // fd
    put(&mut buf, 36, &65_536u32.to_ne_bytes()); // plaintext_len = one 64 KiB chunk

    match Event::parse(&buf) {
        Some(Event::TlsReadBody(e)) => {
            assert_eq!(e.hdr.tgid, 4242);
            assert_eq!(e.hdr.ts_ns, 9_000);
            assert_eq!(e.fd, 7);
            assert_eq!(e.plaintext_len, 65_536);
        }
        other => panic!("expected TlsReadBody, got {other:?}"),
    }

    // Exact-length strict-ABI guard, and the reason the version bump matters: a v1
    // probe's 4144-byte body event carries the SAME tag 23, so only the length rejects
    // it. Short and long are both refused rather than read partially.
    assert!(Event::parse(&buf[..39]).is_none(), "39 (short) refused");
    let mut long = buf.clone();
    long.push(0);
    assert!(Event::parse(&long).is_none(), "41 (long) refused");
    let mut old = vec![0u8; 4144];
    put(&mut old, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut old, 2, &EVT_TLS_READ_BODY.to_ne_bytes());
    assert!(Event::parse(&old).is_none(), "the old 4144-byte body record is refused");
}

#[test]
fn parses_a_connect_record() {
    let mut buf = vec![0u8; 80];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes()); // schema_version
    put(&mut buf, 2, &EVT_TCP_CONNECT.to_ne_bytes()); // type_
    put(&mut buf, 24, &0xdead_beefu64.to_ne_bytes()); // sock_cookie
    buf[32] = 2; // family = AF_INET
    put(&mut buf, 49 + 12, &[10, 0, 0, 5]); // daddr, v4-mapped octets in [12..16]
    put(&mut buf, 66, &443u16.to_ne_bytes()); // dport (host order)
    put(&mut buf, 72, &12_000_000u64.to_ne_bytes()); // connect_latency_ns = 12ms

    match Event::parse(&buf) {
        Some(Event::TcpConnect(e)) => {
            assert_eq!(e.hdr.type_, EVT_TCP_CONNECT);
            assert_eq!(e.hdr.sock_cookie, 0xdead_beef);
            assert_eq!(e.family, 2);
            assert_eq!(&e.daddr[12..16], &[10, 0, 0, 5]);
            assert_eq!(e.dport, 443);
            assert_eq!(e.connect_latency_ns, 12_000_000);
            assert_eq!(e.connect_failed, 0);
        }
        other => panic!("expected TcpConnect, got {other:?}"),
    }
}

#[test]
fn parses_a_tls_handshake_record() {
    // 296-byte handshake: TLS 1.3 (0x0304), SNI "b.s3.us-east-1.amazonaws.com".
    let sni = b"b.s3.us-east-1.amazonaws.com";
    let mut buf = vec![0u8; 296];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_TLS_HANDSHAKE.to_ne_bytes());
    put(&mut buf, 24, &0xfeed_face_u64.to_ne_bytes()); // sock_cookie (the sk pointer)
    put(&mut buf, 32, &0x0304u16.to_ne_bytes()); // tls_version = TLS 1.3
    buf[34] = sni.len() as u8; // sni_len
    put(&mut buf, 36, sni); // sni tail

    match Event::parse(&buf) {
        Some(Event::TlsHandshake(e)) => {
            assert_eq!(e.hdr.sock_cookie, 0xfeed_face);
            assert_eq!(e.tls_version, 0x0304);
            assert_eq!(e.sni_len as usize, sni.len());
            assert_eq!(&e.sni[..e.sni_len as usize], sni);
            assert_eq!(e.sni_truncated, 0);
        }
        other => panic!("expected TlsHandshake, got {other:?}"),
    }
}

#[test]
fn parses_a_dns_query_record() {
    // 296-byte query: txn 0x1234, udp, qname "s3.amazonaws.com".
    let qname = b"s3.amazonaws.com";
    let mut buf = vec![0u8; 296];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_DNS_QUERY.to_ne_bytes());
    put(&mut buf, 32, &0x1234u16.to_ne_bytes()); // txn_id
    buf[34] = 17; // proto = IPPROTO_UDP
    buf[35] = qname.len() as u8; // qname_len
    put(&mut buf, 37, qname); // qname tail

    match Event::parse(&buf) {
        Some(Event::DnsQuery(e)) => {
            assert_eq!(e.txn_id, 0x1234);
            assert_eq!(e.proto, 17);
            assert_eq!(e.qname_len, 16);
            assert_eq!(&e.qname[..e.qname_len as usize], qname);
            assert_eq!(e.qname_truncated, 0);
        }
        other => panic!("expected DnsQuery, got {other:?}"),
    }
}

#[test]
fn parses_a_dns_response_payload() {
    // This crate's job for a response is only the zerocopy contract: copy
    // payload_len + the payload tail at the right offsets. It does NOT parse DNS
    // (that is parse_dns_response in s3tap-core, covered end-to-end with real
    // wire messages in s3tap-core/tests/dns.rs). The bytes below are an arbitrary
    // blob, NOT a valid DNS message — we only assert the round-trip and that
    // payload[0..2] is reachable as the (big-endian) txn_id the parser will read.
    let wire = [0x12u8, 0x34, 0x81, 0x80, 0, 1, 0, 1]; // arbitrary 8-byte blob
    let mut buf = vec![0u8; 552];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_DNS_RESPONSE.to_ne_bytes());
    put(&mut buf, 32, &(wire.len() as u16).to_ne_bytes()); // payload_len
    put(&mut buf, 34, &wire); // payload tail

    match Event::parse(&buf) {
        Some(Event::DnsResponse(e)) => {
            assert_eq!(e.payload_len, 8);
            assert_eq!(&e.payload[..8], &wire);
            // txn_id is payload[0..2], big-endian.
            assert_eq!(u16::from_be_bytes([e.payload[0], e.payload[1]]), 0x1234);
        }
        other => panic!("expected DnsResponse, got {other:?}"),
    }
}

#[test]
fn parses_a_getaddrinfo_record() {
    // 304-byte getaddrinfo exit: latency 1.84ms, ret 0, hostname "example.com".
    let host = b"example.com";
    let mut buf = vec![0u8; 304];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_GETADDRINFO.to_ne_bytes());
    put(&mut buf, 32, &1_840_000u64.to_ne_bytes()); // latency_ns
    put(&mut buf, 40, &0i32.to_ne_bytes()); // ret = success
    buf[44] = host.len() as u8; // hostname_len
    put(&mut buf, 47, host); // hostname tail

    match Event::parse(&buf) {
        Some(Event::Getaddrinfo(e)) => {
            assert_eq!(e.latency_ns, 1_840_000);
            assert_eq!(e.ret, 0);
            assert_eq!(e.hostname_len, 11);
            assert_eq!(&e.hostname[..e.hostname_len as usize], host);
        }
        other => panic!("expected Getaddrinfo, got {other:?}"),
    }
}

#[test]
fn parses_the_connect_failed_flag() {
    // connect_failed lives at offset 65 (the former pad byte).
    let mut buf = vec![0u8; 80];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_TCP_CONNECT.to_ne_bytes());
    buf[65] = 1;
    match Event::parse(&buf) {
        Some(Event::TcpConnect(e)) => assert_eq!(e.connect_failed, 1),
        other => panic!("expected TcpConnect, got {other:?}"),
    }
}

#[test]
fn rejects_runt_unknown_type_and_bad_version() {
    // Too short to hold a header.
    assert!(Event::parse(&[0u8; 4]).is_none());

    // Right version, header-sized, but an unknown type tag.
    let mut buf = vec![0u8; 80];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    buf[2..4].copy_from_slice(&999u16.to_ne_bytes());
    assert!(Event::parse(&buf).is_none(), "unknown type must be rejected");

    // Valid type but a schema version we don't recognize -> refused.
    let mut buf = vec![0u8; 80];
    buf[0..2].copy_from_slice(&(s3tap_events::SCHEMA_VERSION + 1).to_ne_bytes());
    put(&mut buf, 2, &EVT_TCP_CONNECT.to_ne_bytes());
    assert!(Event::parse(&buf).is_none(), "unknown schema version must be refused");

    // Valid version + known type, but the payload is shorter than the struct
    // (40 < 80): the past-header `read_from_bytes` is exact-length, so this must
    // be refused rather than read garbage past the slice end.
    let mut buf = vec![0u8; 40];
    put(&mut buf, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut buf, 2, &EVT_TCP_CONNECT.to_ne_bytes());
    assert!(Event::parse(&buf).is_none(), "truncated payload for a known type must be refused");
}
