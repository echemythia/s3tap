// crates/s3tap-schema/tests/golden.rs
//
// Golden tests for the public records. Assert the EXACT JSON, so any change to
// a wire shape (field name, order, type, new field) fails loudly — forcing a
// conscious decision (and a schema bump), since external consumers depend on
// these contracts.

use s3tap_schema::{
    App, Connection, Delimitation, Dns, Domain, Endpoint, Evidence, Finding, FindingSchemaTag,
    FindingScope, MetricValue, Operation, Sample, SampleKind, ScorecardRow, ScorecardSchemaTag,
    Severity, TcpSample, TimeWindow, Tls, Unit,
};

#[test]
fn operation_serializes_to_expected_json() {
    let op = Operation {
        op_id: "f3a1c0".into(),
        ts_ns: Some(51_230_000_000),
        sock_cookie: 184467440737,
        req_seq: 4,
        app: App { pid: 20413 },
        verb: Some("GET".into()),
        s3_op: Some("GetObject".into()),
        bucket: Some("b".into()),
        key_hash: Some("sha256:9c".into()),
        tcp_connect_ns: Some(11_200_000),
        bytes_sent: 5_242_880,
        bytes_recv: 312,
        retransmits: 2,
        srtt_us: Some(1100),
        connection_reused: false,
        http_status: Some(200),
        aws_request_id: Some("ABC".into()),
        partial: false,
        ..Default::default() // delimitation defaults to Clean
    };

    let json = serde_json::to_string(&op).unwrap();

    let expected = concat!(
        r#"{"schema":"s3tap.operation/1","op_id":"f3a1c0","ts_ns":"51230000000","#,
        r#""sock_cookie":"184467440737","req_seq":4,"app":{"pid":20413},"#,
        r#""verb":"GET","s3_op":"GetObject","bucket":"b","key_hash":"sha256:9c","#,
        r#""dns":null,"tcp_connect_ns":11200000,"tls_handshake_ns":null,"tls_version":null,"#,
        r#""ttfb_ns":null,"download_ns":null,"total_ns":null,"content_length":null,"#,
        r#""op_bytes_sent":null,"op_bytes_recv":null,"#,
        r#""bytes_sent":5242880,"bytes_recv":312,"retransmits":2,"srtt_us":1100,"#,
        r#""lifetime_ns":null,"connection_reused":false,"http_status":200,"#,
        r#""aws_request_id":"ABC","partial":false,"delimitation":"clean"}"#,
    );
    assert_eq!(json, expected);
    // u64s that can exceed 2^53 must be strings; emitted_at is omitted when unset.
    assert!(json.contains(r#""sock_cookie":"184467440737""#));
    assert!(!json.contains("emitted_at"));
}

#[test]
fn ambiguous_delimitation_serializes_to_its_wire_string() {
    // The null-form golden pins delimitation=clean; the correlator also emits
    // Ambiguous on the concurrency-guard path, and consumers must distinguish
    // it. Nothing else pins its wire form, so a dropped rename_all or a variant
    // rename could silently change the public JSON while the goldens stay green.
    let op = Operation { delimitation: Delimitation::Ambiguous, ..Default::default() };
    let json = serde_json::to_string(&op).unwrap();
    assert!(
        json.contains(r#""delimitation":"ambiguous""#),
        "ambiguous variant wire form drifted: {json}"
    );
}

#[test]
fn operation_populated_latency_breakdown_serializes_in_order() {
    // The null-form golden above pins field ORDER but not the POPULATED waterfall.
    // Pin the M3.5 latency block fully populated, so a rename/reorder of the
    // dns/tcp_connect/tls_handshake/ttfb/total run — or a plain-number→string
    // encoding slip — fails loudly.
    let op = Operation {
        op_id: "f3a1c0".into(),
        dns: Some(Dns {
            latency_ns: 1_840_000,
            cache_hit: false,
            resolved_ip: Some("52.216.0.1".into()),
            n_answers: 8,
            ttl_s: Some(60),
            via: "wire".into(),
        }),
        tcp_connect_ns: Some(11_200_000),
        tls_handshake_ns: Some(23_400_000),
        tls_version: Some("1.3".into()),
        ttfb_ns: Some(41_000_000),
        download_ns: Some(47_300_000),
        total_ns: Some(88_300_000),
        ..Default::default()
    };
    let json = serde_json::to_string(&op).unwrap();
    assert!(
        json.contains(concat!(
            r#""dns":{"latency_ns":1840000,"cache_hit":false,"resolved_ip":"52.216.0.1","#,
            r#""n_answers":8,"ttl_s":60,"via":"wire"},"tcp_connect_ns":11200000,"#,
            r#""tls_handshake_ns":23400000,"tls_version":"1.3","ttfb_ns":41000000,"#,
            r#""download_ns":47300000,"total_ns":88300000"#,
        )),
        "populated latency breakdown order/encoding drifted: {json}"
    );
    // Bounded durations stay PLAIN numbers (not strings) — they never cross 2^53 ns.
    assert!(json.contains(r#""ttfb_ns":41000000"#) && !json.contains(r#""ttfb_ns":"41000000""#));
}

#[test]
fn connection_serializes_to_expected_json() {
    let conn = Connection {
        ts_ns: Some(51_200_000_000),
        sock_cookie: 184467440737,
        app: App { pid: 20413 },
        endpoint: Endpoint {
            endpoint_ip: Some("52.216.0.1".into()),
            family: Some("inet".into()),
            dport: Some(443),
            ..Default::default()
        },
        tcp_connect_ns: Some(11_200_000),
        bytes_sent: 5_243_392,
        bytes_recv: 824,
        retransmits: 2,
        srtt_us: Some(1100),
        lifetime_ns: Some(4_200_000_000),
        ..Default::default()
    };

    let json = serde_json::to_string(&conn).unwrap();

    let expected = concat!(
        r#"{"schema":"s3tap.connection/2","ts_ns":"51200000000","#,
        r#""sock_cookie":"184467440737","app":{"pid":20413},"#,
        r#""endpoint":{"region":null,"endpoint_ip":"52.216.0.1","family":"inet","#,
        r#""dport":443,"via_vpce":false,"cross_region":false},"dns":null,"#,
        r#""tcp_connect_ns":11200000,"connect_failed":false,"#,
        r#""tls":{"seen":false,"handshake_ns":null,"version":null,"sni":null},"#,
        r#""bytes_sent":5243392,"bytes_recv":824,"retransmits":2,"srtt_us":1100,"#,
        r#""lifetime_ns":"4200000000","partial":false}"#,
    );
    assert_eq!(json, expected);
}

#[test]
fn connection_path_fields_round_trip_and_are_back_compatible() {
    // Forward: populated path-diagnosis fields serialize (delivery_rate_bps as a PLAIN JSON
    // number, < 2^53; the rest present) and round-trip back equal.
    let conn = Connection {
        sock_cookie: 1,
        min_rtt_us: Some(16_000),
        rttvar_us: Some(3_000),
        snd_cwnd: Some(10),
        mss: Some(1_440),
        delivery_rate_bps: Some(179_730),
        busy_jiffies: Some(100),
        rwnd_limited_jiffies: Some(40),
        sndbuf_limited_jiffies: Some(0),
        lost: Some(2),
        sacked: Some(1),
        reordering: Some(7),
        ca_state: Some(3),
        ..Default::default()
    };
    let json = serde_json::to_string(&conn).unwrap();
    assert!(json.contains(r#""delivery_rate_bps":179730"#), "plain number, not a string: {json}");
    assert!(json.contains(r#""min_rtt_us":16000"#) && json.contains(r#""ca_state":3"#), "{json}");
    let back: Connection = serde_json::from_str(&json).unwrap();
    assert_eq!(back.min_rtt_us, Some(16_000));
    assert_eq!(back.delivery_rate_bps, Some(179_730));
    assert_eq!(back.ca_state, Some(3));

    // Back-compat: an OLD connection record (no path fields at all) still deserializes, with
    // every new field defaulting to None — old captures parse under the enriched schema.
    let old = concat!(
        r#"{"schema":"s3tap.connection/2","sock_cookie":"1","app":{"pid":1},"#,
        r#""endpoint":{"region":null,"endpoint_ip":null,"family":null,"dport":null,"via_vpce":false,"cross_region":false},"#,
        r#""dns":null,"tcp_connect_ns":null,"connect_failed":false,"#,
        r#""tls":{"seen":false,"handshake_ns":null,"version":null,"sni":null},"#,
        r#""bytes_sent":0,"bytes_recv":0,"retransmits":0,"srtt_us":null,"lifetime_ns":null,"partial":true}"#,
    );
    let c: Connection = serde_json::from_str(old).unwrap();
    assert_eq!((c.min_rtt_us, c.snd_cwnd, c.delivery_rate_bps, c.busy_jiffies, c.ca_state), (None, None, None, None, None));
}

#[test]
fn connection_loss_quality_fields_round_trip() {
    // Forward: the loss/quality fields serialize (bytes_retrans as a PLAIN JSON number, not a
    // string; dsack_dups/rcv_ooopack as numbers; app_limited as a bool) and round-trip equal.
    let conn = Connection {
        sock_cookie: 1,
        bytes_retrans: Some(4096),
        dsack_dups: Some(2),
        rcv_ooopack: Some(7),
        app_limited: Some(true),
        ..Default::default()
    };
    let json = serde_json::to_string(&conn).unwrap();
    assert!(json.contains(r#""bytes_retrans":4096"#), "plain number, not a string: {json}");
    assert!(!json.contains(r#""bytes_retrans":"4096""#), "must not be a string: {json}");
    assert!(json.contains(r#""dsack_dups":2"#), "{json}");
    assert!(json.contains(r#""rcv_ooopack":7"#), "{json}");
    assert!(json.contains(r#""app_limited":true"#), "{json}");
    let back: Connection = serde_json::from_str(&json).unwrap();
    assert_eq!(back.bytes_retrans, Some(4096));
    assert_eq!(back.dsack_dups, Some(2));
    assert_eq!(back.rcv_ooopack, Some(7));
    assert_eq!(back.app_limited, Some(true));

    // skip_serializing_if None: a default connection carries none of these 4 keys.
    let json = serde_json::to_string(&Connection::default()).unwrap();
    assert!(!json.contains("bytes_retrans"), "{json}");
    assert!(!json.contains("dsack_dups"), "{json}");
    assert!(!json.contains("rcv_ooopack"), "{json}");
    assert!(!json.contains("app_limited"), "{json}");
}

#[test]
fn tcp_sample_serializes_to_expected_json() {
    // The in-flight time-series record (s3tap.sample/1). Pin the EXACT JSON: field
    // ORDER (= the canonical column order for a future columnar /2), the dec-STRING
    // ts_ns/sock_cookie, the PLAIN-number bytes_*, the always-emitted metrics, and the
    // bool rate_app_limited.
    let s = TcpSample {
        ts_ns: Some(51_230_000_000),
        sock_cookie: 184_467_440_737,
        bytes_sent: 5_242_880,
        bytes_recv: 312,
        bytes_in_flight: 14_400,
        snd_cwnd: 10,
        rcv_wnd: 262_144,
        snd_wnd: 65_535,
        total_retrans: 2,
        rcv_ooopack: 7,
        lost: 1,
        sacked_out: 3,
        ca_state: 3,
        rate_app_limited: true,
        srtt_us: Some(1100),
        min_rtt_us: Some(900),
        delivery_rate_bps: Some(179_730),
        ..Default::default()
    };

    let json = serde_json::to_string(&s).unwrap();

    let expected = concat!(
        r#"{"schema":"s3tap.sample/1","ts_ns":"51230000000","#,
        r#""sock_cookie":"184467440737","bytes_sent":5242880,"bytes_recv":312,"#,
        r#""bytes_in_flight":14400,"snd_cwnd":10,"rcv_wnd":262144,"snd_wnd":65535,"#,
        r#""total_retrans":2,"rcv_ooopack":7,"lost":1,"sacked_out":3,"ca_state":3,"#,
        r#""rate_app_limited":true,"srtt_us":1100,"min_rtt_us":900,"delivery_rate_bps":179730}"#,
    );
    assert_eq!(json, expected);

    // ts_ns/sock_cookie are dec-STRINGS; bytes_* are PLAIN numbers (not strings);
    // rate_app_limited is a bool; emitted_at omitted when unset.
    assert!(json.contains(r#""ts_ns":"51230000000""#));
    assert!(json.contains(r#""sock_cookie":"184467440737""#));
    assert!(json.contains(r#""bytes_sent":5242880"#) && !json.contains(r#""bytes_sent":"5242880""#));
    assert!(json.contains(r#""bytes_recv":312"#) && !json.contains(r#""bytes_recv":"312""#));
    assert!(json.contains(r#""bytes_in_flight":14400"#) && !json.contains(r#""bytes_in_flight":"14400""#));
    assert!(json.contains(r#""rate_app_limited":true"#));
    assert!(!json.contains("emitted_at"));

    // Round-trip: serialize → deserialize → equal.
    let back: TcpSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back, "TcpSample must round-trip exactly");
}

#[test]
fn tcp_sample_omits_none_optional_fields() {
    // srtt_us/min_rtt_us/delivery_rate_bps are skip_serializing_if = None: a sample with
    // them unset must carry none of the three keys. The always-emitted metrics stay.
    let s = TcpSample {
        sock_cookie: 1,
        bytes_sent: 100,
        bytes_recv: 200,
        snd_cwnd: 4,
        ca_state: 0,
        rate_app_limited: false,
        ..Default::default()
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(!json.contains("srtt_us"), "{json}");
    assert!(!json.contains("min_rtt_us"), "{json}");
    assert!(!json.contains("delivery_rate_bps"), "{json}");
    // the always-emitted metrics + the dec-string cookie are still present.
    assert!(json.contains(r#""sock_cookie":"1""#));
    assert!(json.contains(r#""snd_cwnd":4"#));
    assert!(json.contains(r#""rate_app_limited":false"#));
    assert!(json.contains(r#""lost":0"#) && json.contains(r#""sacked_out":0"#));

    let back: TcpSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn tcp_sample_tag_rejects_wrong_schema_and_tolerates_unknown_fields() {
    // The schema tag accepts only "s3tap.sample/1". Swap ONLY the tag on a VALID sample
    // body: a foreign record (a Connection) is missing this record's required fields, so it
    // errors whatever the guard does — which left this test green with the guard deleted.
    let mut v = serde_json::to_value(TcpSample { sock_cookie: 1, ..Default::default() }).unwrap();
    assert!(serde_json::from_value::<TcpSample>(v.clone()).is_ok(), "the base body is valid");

    // A future major (sample/2) — the deferred columnar encoding — must not be read as /1.
    v["schema"] = serde_json::json!("s3tap.sample/2");
    let err = serde_json::from_value::<TcpSample>(v.clone()).unwrap_err().to_string();
    assert!(err.contains("s3tap.sample/1"), "the error must come from the tag guard: {err}");

    // Another record's tag is likewise rejected.
    v["schema"] = serde_json::json!("s3tap.connection/2");
    let err = serde_json::from_value::<TcpSample>(v).unwrap_err().to_string();
    assert!(err.contains("s3tap.sample/1"), "the error must come from the tag guard: {err}");

    // A whole foreign record still fails (the tag guard fires before the field mismatch).
    let wrong = serde_json::to_string(&Connection { sock_cookie: 1, ..Default::default() }).unwrap();
    assert!(serde_json::from_str::<TcpSample>(&wrong).is_err(), "wrong schema tag must error");
    // Forward-compat: a newer agent's extra field is ignored, not fatal.
    let extra = r#"{"schema":"s3tap.sample/1","sock_cookie":"5","bytes_sent":0,"bytes_recv":0,"bytes_in_flight":0,"snd_cwnd":0,"rcv_wnd":0,"snd_wnd":0,"total_retrans":0,"rcv_ooopack":0,"lost":0,"sacked_out":0,"ca_state":0,"rate_app_limited":false,"a_future_field":42}"#;
    let s: TcpSample = serde_json::from_str(extra).expect("unknown field must be ignored");
    assert_eq!(s.sock_cookie, 5);
}

#[test]
fn populated_dns_block_serializes_in_order() {
    // M2 fills this block; pin its wire shape (field order + types) since it is
    // now a live part of the public contract.
    let conn = Connection {
        dns: Some(Dns {
            latency_ns: 1_840_000,
            cache_hit: false,
            resolved_ip: Some("52.216.0.1".into()),
            n_answers: 8,
            ttl_s: Some(60),
            via: "wire".into(),
        }),
        ..Default::default()
    };
    let json = serde_json::to_string(&conn).unwrap();
    assert!(json.contains(concat!(
        r#""dns":{"latency_ns":1840000,"cache_hit":false,"resolved_ip":"52.216.0.1","#,
        r#""n_answers":8,"ttl_s":60,"via":"wire"}"#
    )));
}

#[test]
fn populated_tls_block_serializes_in_order() {
    // M3 fills this block when a ClientHello with a usable SNI is seen; pin its
    // wire shape (field order + types) on the POPULATED path — the seen=false
    // golden above can't catch a rename/reorder of seen/sni when they carry data.
    let conn = Connection {
        endpoint: Endpoint {
            region: Some("eu-west-1".into()),
            ..Default::default()
        },
        tls: Tls {
            seen: true,
            handshake_ns: None,
            version: None,
            sni: Some("b.s3.eu-west-1.amazonaws.com".into()),
            cipher: None,
        },
        ..Default::default()
    };
    let json = serde_json::to_string(&conn).unwrap();
    assert!(json.contains(concat!(
        r#""tls":{"seen":true,"handshake_ns":null,"version":null,"#,
        r#""sni":"b.s3.eu-west-1.amazonaws.com"}"#
    )));
    assert!(json.contains(r#""region":"eu-west-1""#));
}

#[test]
fn null_fields_serialize_as_null_not_omitted() {
    // "latency breakdown (null when not applicable)" — a record that observed
    // nothing must still carry the fields as null (except emitted_at, which is
    // legitimately absent until stamped).
    let conn = Connection {
        partial: true,
        ..Default::default()
    };
    let json = serde_json::to_string(&conn).unwrap();
    assert!(json.contains(r#""ts_ns":null"#));
    assert!(json.contains(r#""tcp_connect_ns":null"#));
    assert!(json.contains(r#""srtt_us":null"#));
    assert!(json.contains(r#""lifetime_ns":null"#));
    assert!(json.contains(r#""dns":null"#));
    assert!(json.contains(r#""schema":"s3tap.connection/2""#));
    assert!(json.contains(r#""sock_cookie":"0""#)); // still a string
}

// --- Deserialize: the doctor reads back what the agent emits ---

#[test]
fn operation_round_trips_through_serde() {
    // A fully-populated op (incl. the string-u64 fields) must survive emit→read.
    let op = Operation {
        op_id: "f3a1c0".into(),
        ts_ns: Some(51_230_000_000),
        sock_cookie: 184_467_440_737,
        req_seq: 4,
        app: App { pid: 20413 },
        verb: Some("GET".into()),
        s3_op: Some("GetObject".into()),
        bucket: Some("b".into()),
        key_hash: Some("sha256:9c".into()),
        dns: Some(Dns {
            latency_ns: 3_932_043,
            cache_hit: false,
            resolved_ip: Some("52.217.0.1".into()),
            n_answers: 8,
            ttl_s: Some(3),
            via: "getaddrinfo".into(),
        }),
        tcp_connect_ns: Some(11_200_000),
        ttfb_ns: Some(30_100_000),
        download_ns: Some(117_800_000),
        total_ns: Some(147_900_000),
        content_length: Some(2_097_152),
        lifetime_ns: Some(268_627_952),
        srtt_us: Some(1100),
        http_status: Some(200),
        aws_request_id: Some("ABC".into()),
        ..Default::default()
    };
    let json = serde_json::to_string(&op).unwrap();
    let back: Operation = serde_json::from_str(&json).unwrap();
    assert_eq!(op, back, "Operation must round-trip exactly");
}

#[test]
fn connection_round_trips_through_serde() {
    let c = Connection {
        ts_ns: Some(51_200_000_000),
        sock_cookie: 184_467_440_737,
        app: App { pid: 7 },
        endpoint: Endpoint {
            region: Some("us-east-1".into()),
            endpoint_ip: Some("52.217.0.1".into()),
            family: Some("inet".into()),
            dport: Some(443),
            ..Default::default()
        },
        tls: Tls { seen: true, sni: Some("b.s3.amazonaws.com".into()), ..Default::default() },
        bytes_sent: 5_242_880,
        bytes_recv: 312,
        retransmits: 2,
        srtt_us: Some(1100),
        lifetime_ns: Some(268_627_952),
        ..Default::default()
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: Connection = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// A serialized op with all required fields, to derive "missing one field" cases from.
fn minimal_op_json() -> String {
    serde_json::to_string(&Operation {
        op_id: "y".into(),
        sock_cookie: 3,
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn deserialize_tolerates_unknown_and_missing_optional_fields() {
    // Forward-compat: a record from a NEWER agent (an unknown field) still parses;
    // serde ignores unknown fields. The record carries all REQUIRED fields.
    let with_unknown = minimal_op_json().replace("\"partial\":false", "\"partial\":false,\"future_field\":{\"nested\":true}");
    let op: Operation = serde_json::from_str(&with_unknown).unwrap();
    assert_eq!(op.op_id, "y");
    assert_eq!(op.sock_cookie, 3);

    // Back-compat: a record from BEFORE content_length existed (the field absent) parses,
    // with the additive Option defaulting to None — no container default needed, serde
    // treats a missing Option field as None.
    let old = minimal_op_json().replace(",\"content_length\":null", "");
    assert!(!old.contains("content_length"), "content_length removed for the back-compat case");
    let op: Operation = serde_json::from_str(&old).unwrap();
    assert_eq!(op.content_length, None);
}

#[test]
fn deserialize_rejects_a_missing_version_tag_or_join_key() {
    // review step-1 #2: dropping the container default makes the identity fields
    // REQUIRED, so a record that omits the schema tag or the sock_cookie join key is a
    // hard parse error — not silently accepted as a default-tagged / cookie-0 record.
    let no_schema = minimal_op_json().replace("\"schema\":\"s3tap.operation/1\",", "");
    assert!(serde_json::from_str::<Operation>(&no_schema).is_err(), "absent schema must error");

    let no_cookie = minimal_op_json().replace(",\"sock_cookie\":\"3\"", "");
    assert!(serde_json::from_str::<Operation>(&no_cookie).is_err(), "absent sock_cookie must error");

    // A present-but-null cookie is also rejected (the deserialize_with runs and refuses null).
    let null_cookie = minimal_op_json().replace("\"sock_cookie\":\"3\"", "\"sock_cookie\":null");
    assert!(serde_json::from_str::<Operation>(&null_cookie).is_err(), "null sock_cookie must error");
}

#[test]
fn schema_tag_rejects_a_wrong_or_mismatched_version() {
    // The tag is the version guard. Build the negatives from a FULL, otherwise-valid body
    // and swap ONLY the schema string, so the rejection can come from nothing but the tag
    // guard. (A sparse body errors on a missing required field no matter what the guard
    // does — that made this test vacuous: it stayed green with the guard deleted, and a
    // future /2 record would then be consumed as a /1. Same trap `scorecard_tag_rejects_a_
    // wrong_schema` documents.)
    let mut v: serde_json::Value = serde_json::from_str(&minimal_op_json()).unwrap();
    assert!(serde_json::from_value::<Operation>(v.clone()).is_ok(), "the base body is valid");

    // A future major (operation/2) is rejected, not silently misread as a /1 op.
    v["schema"] = serde_json::json!("s3tap.operation/2");
    let err = serde_json::from_value::<Operation>(v.clone()).unwrap_err().to_string();
    assert!(err.contains("s3tap.operation/1"), "the error must come from the tag guard: {err}");

    // Another record's tag (connection/2) is likewise rejected.
    v["schema"] = serde_json::json!("s3tap.connection/2");
    let err = serde_json::from_value::<Operation>(v).unwrap_err().to_string();
    assert!(err.contains("s3tap.operation/1"), "the error must come from the tag guard: {err}");
}

#[test]
fn connection_tag_rejects_a_wrong_schema() {
    // Connection had NO wrong-tag test at all, and it is the record the latency floor
    // (min_rtt/srtt) is read from — a /3 record misread as a /2 would feed a redefined
    // field straight into an RTT verdict. Same non-vacuous pattern: valid body, swap only
    // the tag.
    let mut v = serde_json::to_value(Connection {
        sock_cookie: 1,
        app: App { pid: 7 },
        min_rtt_us: Some(16_000),
        ..Default::default()
    })
    .unwrap();
    assert!(serde_json::from_value::<Connection>(v.clone()).is_ok(), "the base body is valid");

    v["schema"] = serde_json::json!("s3tap.connection/3");
    let err = serde_json::from_value::<Connection>(v.clone()).unwrap_err().to_string();
    assert!(err.contains("s3tap.connection/2"), "the error must come from the tag guard: {err}");

    // The superseded /1 is rejected too: /1 encoded lifetime_ns as a NUMBER, so accepting
    // it here would mis-parse the very field the bump was made for.
    v["schema"] = serde_json::json!("s3tap.connection/1");
    let err = serde_json::from_value::<Connection>(v.clone()).unwrap_err().to_string();
    assert!(err.contains("s3tap.connection/2"), "the error must come from the tag guard: {err}");

    // An ABSENT tag is a hard error as well (the field is required, never defaulted).
    let obj = v.as_object_mut().unwrap();
    obj.remove("schema");
    assert!(serde_json::from_value::<Connection>(v).is_err(), "absent schema must error");
}

#[test]
fn non_finite_f64_is_refused_at_serialize_not_silently_nulled() {
    // review step-1 #1: serde_json would encode NaN/Inf as JSON null, silently breaking
    // the round-trip. MetricValue::Num and ratio_to_rtt reject non-finite at serialize.
    assert!(serde_json::to_string(&MetricValue::Num(f64::NAN)).is_err());
    assert!(serde_json::to_string(&MetricValue::Num(f64::INFINITY)).is_err());
    // a finite Num and a Str still serialize fine.
    assert_eq!(serde_json::to_string(&MetricValue::Num(503.0)).unwrap(), "503.0");
    assert_eq!(serde_json::to_string(&MetricValue::Str("x".into())).unwrap(), r#""x""#);

    // A Finding carrying a non-finite ratio_to_rtt fails to serialize (loud, not lossy).
    let mut f = sample_finding();
    f.ratio_to_rtt = Some(f64::NAN);
    assert!(serde_json::to_string(&f).is_err(), "non-finite ratio_to_rtt must error at emit");
    // value=None and an integer-valued Num both round-trip exactly.
    let mut f = sample_finding();
    f.value = None;
    let back: Finding = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
    assert_eq!(f, back);
    let mut f = sample_finding();
    f.value = Some(MetricValue::Num(503.0));
    let back: Finding = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
    assert_eq!(f, back);
}

// A representative finding, reused by the round-trip + non-finite tests.
fn sample_finding() -> Finding {
    Finding {
        schema: FindingSchemaTag,
        emitted_at: Some("2026-06-24T14:03:11.482Z".into()),
        source_schema: vec!["s3tap.operation/1".into(), "s3tap.connection/2".into()],
        finding_id: "reuse-off".into(),
        domain: Domain::Client,
        title: "Connection reuse off".into(),
        severity: Severity::Warn,
        verdict: "high".into(),
        summary: "12% of ops reused a connection.".into(),
        recommendation_ref: None,
        metric: "connection_reuse_ratio".into(),
        value: Some(MetricValue::Num(0.12)),
        unit: Unit::Ratio,
        baseline_rtt_us: Some(45_000),
        ratio_to_rtt: None,
        threshold: ">= 0.8".into(),
        sample: Sample { judged: 412, excluded: 68, kind: SampleKind::Operation },
        scope: FindingScope { region: Some("us-east-1".into()), ..Default::default() },
        window: TimeWindow { ts_start: 51_200_000_000, ts_end: 98_700_000_000 },
        evidence: Evidence {
            op_ids: vec!["f3a1c0".into()],
            sock_cookies: vec!["184467440737".into()],
            aws_request_ids: vec!["ABC123".into()],
        },
    }
}

#[test]
fn finding_round_trips_through_serde() {
    // The provisional s3tap.finding/1 must (de)serialize for the doctor's --json.
    let f = sample_finding();
    let json = serde_json::to_string(&f).unwrap();
    // tag + string-u64 window are correct on the wire.
    assert!(json.contains(r#""schema":"s3tap.finding/1""#));
    assert!(json.contains(r#""ts_start":"51200000000""#));
    assert!(json.contains(r#""severity":"warn""#));
    assert!(json.contains(r#""domain":"client""#));
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back, "Finding must round-trip exactly");
}

#[test]
fn unit_and_value_wire_forms() {
    // bytes_per_s renders snake_case; a string metric value round-trips as a string.
    assert_eq!(serde_json::to_string(&Unit::BytesPerS).unwrap(), r#""bytes_per_s""#);
    let v = MetricValue::Str("503".into());
    let j = serde_json::to_string(&v).unwrap();
    assert_eq!(j, r#""503""#);
    assert_eq!(serde_json::from_str::<MetricValue>(&j).unwrap(), v);
    // an untagged number stays a number.
    assert_eq!(serde_json::from_str::<MetricValue>("0.5").unwrap(), MetricValue::Num(0.5));
}

// --- s3tap.scorecard/1 (the observed-SLO scorecard row) ---

// A fully-populated scorecard row, reused by the golden + round-trip tests.
fn sample_scorecard_row() -> ScorecardRow {
    ScorecardRow {
        schema: ScorecardSchemaTag,
        bucket: Some("photos".into()),
        s3_op: Some("GetObject".into()),
        ops: 200,
        errors: 20,
        error_rate: 0.1,
        // BTreeMap => keys ascend on the wire; serde_json renders the u16 keys as strings.
        status_counts: [(200u16, 180u64), (404, 15), (503, 5)].into_iter().collect(),
        ttfb_p50_ns: Some(28_000_000),
        ttfb_p95_ns: Some(61_000_000),
        ttfb_p99_ns: Some(340_000_000),
        latency_sample: 180,
        throughput_bytes_per_s: Some(84_000_000.0),
        window: TimeWindow { ts_start: 1_000_000_000, ts_end: 9_000_000_000 },
    }
}

#[test]
fn scorecard_row_serializes_to_expected_json() {
    // Pin the EXACT JSON: field ORDER, the status_counts map (string-keyed, ascending),
    // PLAIN-number counts + ns percentiles, the float error_rate/throughput, and the
    // dec-STRING window bounds. Any wire change fails loudly (external consumers depend
    // on this contract; a change means a schema bump).
    let json = serde_json::to_string(&sample_scorecard_row()).unwrap();
    let expected = concat!(
        r#"{"schema":"s3tap.scorecard/1","bucket":"photos","s3_op":"GetObject","#,
        r#""ops":200,"errors":20,"error_rate":0.1,"#,
        r#""status_counts":{"200":180,"404":15,"503":5},"#,
        r#""ttfb_p50_ns":28000000,"ttfb_p95_ns":61000000,"ttfb_p99_ns":340000000,"#,
        r#""latency_sample":180,"throughput_bytes_per_s":84000000.0,"#,
        r#""window":{"ts_start":"1000000000","ts_end":"9000000000"}}"#,
    );
    assert_eq!(json, expected);
    // Counts stay PLAIN numbers (never string-encoded — op counts ≪ 2^53); the window
    // bounds ARE dec-strings (monotonic ns can exceed 2^53).
    assert!(json.contains(r#""ops":200"#) && !json.contains(r#""ops":"200""#));
    assert!(json.contains(r#""ts_start":"1000000000""#));
    assert!(!json.contains("emitted_at"));
}

#[test]
fn scorecard_row_null_percentiles_and_empty_mix_serialize_as_null_not_omitted() {
    // A group below the tail floors (p95/p99 unset) and a GET-less group (no throughput)
    // must still carry the fields as null — a missing key would read as "absent", not
    // "not enough sample". An empty status mix renders as {}.
    let row = ScorecardRow {
        schema: ScorecardSchemaTag,
        bucket: None,
        s3_op: None,
        ops: 3,
        errors: 0,
        error_rate: 0.0,
        status_counts: std::collections::BTreeMap::new(),
        ttfb_p50_ns: Some(20_000_000),
        ttfb_p95_ns: None,
        ttfb_p99_ns: None,
        latency_sample: 3,
        throughput_bytes_per_s: None,
        window: TimeWindow { ts_start: 0, ts_end: 0 },
    };
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains(r#""bucket":null"#) && json.contains(r#""s3_op":null"#), "{json}");
    assert!(json.contains(r#""status_counts":{}"#), "empty mix is {{}}: {json}");
    assert!(json.contains(r#""ttfb_p95_ns":null"#) && json.contains(r#""ttfb_p99_ns":null"#), "{json}");
    assert!(json.contains(r#""throughput_bytes_per_s":null"#), "{json}");
    assert!(json.contains(r#""error_rate":0.0"#), "{json}");
}

#[test]
fn scorecard_row_round_trips_through_serde() {
    let row = sample_scorecard_row();
    let json = serde_json::to_string(&row).unwrap();
    let back: ScorecardRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back, "ScorecardRow must round-trip exactly");
    // The status-code keys survive the string-key map round-trip as u16s.
    assert_eq!(back.status_counts[&503], 5);
}

#[test]
fn scorecard_non_finite_floats_are_refused_at_serialize() {
    // Both f64s on the row go through the finite-only serializer. error_rate is the
    // dangerous one: it is NOT an Option, so serde_json's silent NaN → `null` produces a
    // record that emits clean and then fails to parse back ("invalid type: null, expected
    // f64") — the one-way record the guard exists to prevent.
    let mut row = sample_scorecard_row();
    row.error_rate = f64::NAN;
    assert!(serde_json::to_string(&row).is_err(), "NaN error_rate must error at emit");
    row.error_rate = f64::INFINITY;
    assert!(serde_json::to_string(&row).is_err(), "Inf error_rate must error at emit");

    // Proof of the break the guard prevents: a null in that slot does not read back.
    let mut v = serde_json::to_value(sample_scorecard_row()).unwrap();
    v["error_rate"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ScorecardRow>(v).is_err(), "null error_rate can't parse");

    // The Option sibling is guarded too (it would round-trip to None, silently).
    let mut row = sample_scorecard_row();
    row.throughput_bytes_per_s = Some(f64::NAN);
    assert!(serde_json::to_string(&row).is_err(), "NaN throughput must error at emit");
}

#[test]
fn scorecard_tag_rejects_a_wrong_schema() {
    // The tag is the version guard. Build the negatives from a FULL, otherwise-valid body
    // and swap ONLY the schema string — so the rejection can come from nothing but the tag
    // guard. (A sparse body would `is_err()` on a missing required field regardless of what
    // the guard does, giving false confidence that the version check works.)
    let mut v = serde_json::to_value(sample_scorecard_row()).unwrap();
    // Sanity: the untouched body IS accepted, so any error below is the tag's doing.
    assert!(serde_json::from_value::<ScorecardRow>(v.clone()).is_ok(), "the base body is valid");

    // A future major (scorecard/2) is rejected, not silently misread as a /1 row.
    v["schema"] = serde_json::json!("s3tap.scorecard/2");
    let err = serde_json::from_value::<ScorecardRow>(v.clone()).unwrap_err().to_string();
    assert!(err.contains("s3tap.scorecard/1"), "the error must come from the tag guard: {err}");

    // A different record's tag (operation/1) is likewise rejected.
    v["schema"] = serde_json::json!("s3tap.operation/1");
    let err = serde_json::from_value::<ScorecardRow>(v).unwrap_err().to_string();
    assert!(err.contains("s3tap.scorecard/1"), "the error must come from the tag guard: {err}");
}
