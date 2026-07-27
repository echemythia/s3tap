// Golden tests for `s3tap doctor`: pin the human report AND the
// `s3tap.finding/1` JSON for a canonical capture, so any drift in the rendered table or
// the machine contract fails loudly — forcing a conscious decision. Output is fully
// deterministic (emitted_at is None; the window comes from the records' ts_ns).
//
// Regenerate after an intentional change:  UPDATE_GOLDEN=1 cargo test -p s3tap-doctor --test golden

use std::path::PathBuf;

use s3tap_doctor::{analyze, Record};
use s3tap_schema::{Connection, Operation};

mod common;
use common::running_in_ci;

/// A small but representative capture: a reused + new GetObject mix (enough for the reuse
/// row), a 503, and a 403 with an aws_request_id — exercising global rows, the S3 domain,
/// reuse, evidence, and the run roll-up. (No tail: that needs ≥20 ops.)
fn capture() -> Vec<Record> {
    let mut recs = vec![Record::Connection(Connection {
        srtt_us: Some(17_000),
        retransmits: 0,
        bytes_sent: 1_000_000,
        ts_ns: Some(1_000),
        ..Default::default()
    })];
    let get = |op_id: &str, ttfb_ms: u64, reused: bool, status: u16, ts: u64, aws: Option<&str>| {
        Record::Operation(Operation {
            op_id: op_id.into(),
            http_status: Some(status),
            s3_op: Some(if status == 503 { "PutObject".into() } else { "GetObject".into() }),
            sock_cookie: 100,
            connection_reused: reused,
            ttfb_ns: Some(ttfb_ms * 1_000_000),
            tcp_connect_ns: Some(17_000_000),
            aws_request_id: aws.map(Into::into),
            ts_ns: Some(ts),
            ..Default::default()
        })
    };
    // 5 reused + 1 new healthy GetObject (6 good ops -> reuse row at 83%).
    recs.push(get("op-1", 30, true, 200, 1_100, None));
    recs.push(get("op-2", 32, true, 200, 1_110, None));
    recs.push(get("op-3", 34, true, 200, 1_120, None));
    recs.push(get("op-4", 36, true, 200, 1_130, None));
    recs.push(get("op-5", 38, true, 200, 1_140, None));
    recs.push(get("op-6", 50, false, 200, 1_150, None));
    // a 503 throttle and a 403 client error (the latter with a request id for evidence).
    recs.push(get("op-7", 30, true, 503, 1_300, Some("REQ-503")));
    recs.push(get("op-8", 30, true, 403, 1_400, Some("REQ-403")));
    recs
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name)
}

/// Compare `actual` to the committed golden file, or rewrite it under `UPDATE_GOLDEN`.
fn check_golden(name: &str, actual: &str) {
    let path = golden_path(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        // Regenerating is a LOCAL, deliberate act whose diff a human then reads. In CI the
        // same env var (a leftover export in a shell or a justfile recipe) would turn both
        // golden tests into unconditional passes that silently rewrite the committed files
        // to whatever the code now does — a fully green run that pinned nothing. Refuse.
        assert!(
            !running_in_ci(),
            "UPDATE_GOLDEN is set but CI is too: refusing to rewrite golden {name}. The \
             goldens are a committed contract — regenerate locally with \
             `UPDATE_GOLDEN=1 cargo test -p s3tap-doctor --test golden`, read the diff, \
             then commit it."
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing golden {name}; generate it with UPDATE_GOLDEN=1")
    });
    assert_eq!(
        actual, expected,
        "golden {name} drifted — if intentional, regenerate with \
         UPDATE_GOLDEN=1 cargo test -p s3tap-doctor --test golden"
    );
}

#[test]
fn golden_human_report() {
    check_golden("report.txt", &analyze(&capture()).render(false));
}

/// The fixture above sets none of the loss-quality / reorder / rate-limit fields, so a bare
/// regen of the golden files is a no-op for them. This builds a dedicated capture that DOES
/// populate the 4 new tcp_sock fields — one download-heavy conn (rcv_ooopack: the GET signal)
/// and one upload-heavy conn (dsack_dups + app_limited + bytes_retrans: the PUT/send signals)
/// — and pins the rendered loss_shape / bdp_ceiling / retransmit_rate notes they drive.
#[test]
fn path_quality_fields_render_in_loss_shape_and_bdp_ceiling() {
    let recs = vec![
        // Download leg (GET): bytes_recv >> bytes_sent; out-of-order pkts received on the leg
        // that carries the payload — the download-reorder evidence `reordering` can't show.
        Record::Connection(Connection {
            sock_cookie: 1,
            bytes_recv: 1_000_000,
            bytes_sent: 1_000,
            rcv_ooopack: Some(7),
            ts_ns: Some(1_000),
            ..Default::default()
        }),
        // Upload leg (PUT, send-heavy): a low delivery rate well under the cwnd·mss/min_rtt
        // ceiling WITH the kernel app-limited bit set (definitive, not a guess), plus spurious
        // DSACK retransmits and a retransmit byte volume.
        Record::Connection(Connection {
            sock_cookie: 2,
            bytes_sent: 1_000_000,
            bytes_recv: 1_000,
            snd_cwnd: Some(40),
            mss: Some(1_460),
            min_rtt_us: Some(10_000), // 10 ms -> ceiling 40*1460/0.01 = 5.84 MB/s
            delivery_rate_bps: Some(1_000_000), // 1 MB/s, < 0.5x ceiling -> "well under"
            dsack_dups: Some(3),
            app_limited: Some(true),
            bytes_retrans: Some(8_192),
            ts_ns: Some(1_010),
            ..Default::default()
        }),
    ];
    let r = analyze(&recs);

    // loss_shape: one row, leading with the download-leg ooo count, carrying BOTH legs' detail.
    let loss = r.path.iter().find(|x| x.id == "loss_shape").expect("loss_shape row present");
    assert_eq!(loss.value.split_whitespace().collect::<Vec<_>>(), ["ooo", "7"], "leads with the download-leg ooo count: {:?}", loss.value);
    assert_eq!(loss.metric.name, "rcv_ooopack", "ooo-led row carries the matching machine metric");
    assert!(loss.note.contains("7 out-of-order pkt(s) received (download-leg reorder/loss)"), "{}", loss.note);
    assert!(loss.note.contains("3 spurious (DSACK) retransmit(s)"), "{}", loss.note);

    // bdp_ceiling: the kernel app-limited flag replaces the "app-limited or single-stream?" guess.
    let bdp = r.path.iter().find(|x| x.id == "bdp_ceiling").expect("bdp_ceiling row present");
    assert!(bdp.note.contains("APP-LIMITED"), "definitive, not a guess: {}", bdp.note);
    assert!(bdp.note.contains("rate_app_limited"), "names the kernel flag: {}", bdp.note);

    // retransmit_rate: byte VOLUME appended to the note only; rate/verdict untouched (parity).
    let rtx = r.rows.iter().find(|x| x.id == "retransmit_rate").expect("retransmit_rate row present");
    assert!(rtx.note.contains("8.2 KB retransmitted"), "{}", rtx.note);
    assert_eq!(rtx.verdict, "clean", "volume note must not change the segment-rate verdict");
}

/// loss_shape with ONLY send-leg DSACKs (no recv ooo, no reorder, no recovery): the row must
/// still fire, LEAD with the dsack count + its matching metric, and render the spurious-retrans
/// note. This pins the `(false, _)` fall-through arm the main test (which always has ooo>0)
/// can't reach.
#[test]
fn loss_shape_dsack_only_leads_when_nothing_else_fired() {
    let recs = vec![Record::Connection(Connection {
        sock_cookie: 1,
        bytes_sent: 1_000_000, // send-heavy so dsack_dups is counted
        bytes_recv: 1_000,
        dsack_dups: Some(4),
        ts_ns: Some(1_000),
        ..Default::default()
    })];
    let r = analyze(&recs);
    let loss = r.path.iter().find(|x| x.id == "loss_shape").expect("loss_shape row present");
    assert_eq!(loss.value.split_whitespace().collect::<Vec<_>>(), ["dsack", "4"], "dsack leads: {:?}", loss.value);
    assert_eq!(loss.metric.name, "dsack_dups", "dsack-led row carries the matching machine metric");
    assert!(loss.note.contains("4 spurious (DSACK) retransmit(s)"), "{}", loss.note);
    assert!(!loss.note.contains("out-of-order"), "no recv-leg clause when ooo==0: {}", loss.note);
}

/// loss_shape where a reorder/recovery signal LEADS and the new recv-ooo evidence is APPENDED
/// onto the existing note (the `if !note.is_empty()` "; " join). Pins that a reorder-led row
/// keeps its reorder metric/value while still surfacing the download-leg count.
#[test]
fn loss_shape_appends_ooo_onto_a_reorder_led_row() {
    let recs = vec![Record::Connection(Connection {
        sock_cookie: 1,
        bytes_recv: 1_000_000,
        bytes_sent: 1_000,
        reordering: Some(9), // > kernel-default 3 -> reorder_high leads
        rcv_ooopack: Some(5),
        ts_ns: Some(1_000),
        ..Default::default()
    })];
    let r = analyze(&recs);
    let loss = r.path.iter().find(|x| x.id == "loss_shape").expect("loss_shape row present");
    assert_eq!(loss.value.split_whitespace().collect::<Vec<_>>(), ["reorder", "9"], "reorder leads: {:?}", loss.value);
    assert_eq!(loss.metric.name, "reordering", "lead metric stays the reorder degree, not ooo");
    assert!(loss.note.contains("max reordering degree 9"), "keeps the reorder note: {}", loss.note);
    assert!(loss.note.contains("; 5 out-of-order pkt(s) received"), "appends ooo after a \"; \": {}", loss.note);
}

#[test]
fn golden_findings_ndjson() {
    let ndjson: String = analyze(&capture())
        .findings()
        .iter()
        .map(|f| serde_json::to_string(f).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    check_golden("findings.ndjson", &(ndjson + "\n"));
}
