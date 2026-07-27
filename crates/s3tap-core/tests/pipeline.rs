// crates/s3tap-core/tests/pipeline.rs
//
// End-to-end M1 data path: raw ring-buffer bytes -> Event::parse ->
// Correlator (via the same Event-enum dispatch the CLI will use in C6) ->
// Connection -> JSON. Guards that the layers actually compose — including the
// exact-length decode coupling and the connect->close folding — not just each
// layer in isolation.

use s3tap_core::Correlator;
use s3tap_events::{Event, EVT_TCP_CLOSE, EVT_TCP_CONNECT};

fn put(buf: &mut [u8], off: usize, b: &[u8]) {
    buf[off..off + b.len()].copy_from_slice(b);
}

// The Event dispatch C6 will write in the drain loop.
fn feed(c: &mut Correlator, bytes: &[u8]) -> Option<s3tap_schema::Connection> {
    match Event::parse(bytes).expect("parse") {
        Event::TcpConnect(e) => c.on_connect(&e),
        Event::TcpClose(e) => c.on_close(&e),
        other => panic!("this M1 pipeline test only feeds connect/close, got {other:?}"),
    }
}

#[test]
fn raw_bytes_fold_into_connection_json() {
    // An 80-byte connect record: v4-mapped 52.216.0.1:443, established ts and
    // latency (so ts_ns derives to the SYN start), cookie 0xabc, pid 4242.
    let mut connect = vec![0u8; 80];
    put(&mut connect, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes()); // hdr.schema_version
    put(&mut connect, 2, &EVT_TCP_CONNECT.to_ne_bytes()); // hdr.type_
    put(&mut connect, 8, &51_211_200_000u64.to_ne_bytes()); // hdr.ts_ns (established)
    put(&mut connect, 16, &4242u32.to_ne_bytes()); // hdr.tgid
    put(&mut connect, 24, &0xabcu64.to_ne_bytes()); // hdr.sock_cookie
    connect[32] = 2; // family AF_INET
    put(&mut connect, 49 + 12, &[52, 216, 0, 1]); // daddr v4-mapped octets
    put(&mut connect, 66, &443u16.to_ne_bytes()); // dport
    put(&mut connect, 72, &11_200_000u64.to_ne_bytes()); // connect_latency_ns

    // A close record on the same cookie (extended fields left zero -> None -> omitted).
    let mut close = vec![0u8; std::mem::size_of::<s3tap_events::EvtTcpClose>()];
    put(&mut close, 0, &s3tap_events::SCHEMA_VERSION.to_ne_bytes());
    put(&mut close, 2, &EVT_TCP_CLOSE.to_ne_bytes());
    put(&mut close, 24, &0xabcu64.to_ne_bytes()); // same cookie
    put(&mut close, 32, &5_242_880u64.to_ne_bytes()); // bytes_sent
    put(&mut close, 40, &312u64.to_ne_bytes()); // bytes_recv
    put(&mut close, 48, &2u32.to_ne_bytes()); // retransmit_count
    put(&mut close, 52, &1100u32.to_ne_bytes()); // srtt_us
    put(&mut close, 56, &4_200_000_000u64.to_ne_bytes()); // lifetime_ns

    let mut c = Correlator::new();
    assert!(feed(&mut c, &connect).is_none(), "connect alone emits nothing");
    let rec = feed(&mut c, &close).expect("close finalizes a record");

    // ts_ns = established (51_211_200_000) - latency (11_200_000) = 51_200_000_000;
    // sock_cookie 0xabc = 2748; v4-mapped IPv4 read back as 52.216.0.1.
    let json = serde_json::to_string(&rec).unwrap();
    let expected = concat!(
        r#"{"schema":"s3tap.connection/2","ts_ns":"51200000000","sock_cookie":"2748","#,
        r#""app":{"pid":4242},"endpoint":{"region":null,"endpoint_ip":"52.216.0.1","#,
        r#""family":"inet","dport":443,"via_vpce":false,"cross_region":false},"dns":null,"#,
        r#""tcp_connect_ns":11200000,"connect_failed":false,"#,
        r#""tls":{"seen":false,"handshake_ns":null,"version":null,"sni":null},"#,
        r#""bytes_sent":5242880,"bytes_recv":312,"retransmits":2,"srtt_us":1100,"#,
        r#""lifetime_ns":"4200000000","partial":false}"#,
    );
    assert_eq!(json, expected);
}
