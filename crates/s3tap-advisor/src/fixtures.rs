//! Shared synthetic-record builders for the advisory checks' tests. Test-cfg
//! only (no cargo feature): every consumer is this crate's own unit tests —
//! the CLI e2e test uses a static JSONL fixture file instead, because this
//! module is invisible outside the crate.
//!
//! All inner schema types derive `Default`, so builders set only what a check
//! reads and default the rest. `s3tap_replay::adapt::OpRecord` does NOT derive
//! `Default` — its builders name all six fields (see `zipf_ops`).

use s3tap_doctor::Record;
use s3tap_replay::adapt::OpRecord;
use s3tap_schema::{Connection, Endpoint, Operation, Tls};

/// One operation record. `total_ns` also back-fills a plausible ttfb/download
/// split (70/30) so timing checks have both spans.
#[allow(clippy::too_many_arguments)]
pub(crate) fn op(
    pid: u32,
    cookie: u64,
    req_seq: u32,
    ts_ns: u64,
    total_ns: u64,
    s3_op: &str,
    key_hash: &str,
    status: u16,
    content_length: Option<u64>,
) -> Record {
    Record::Operation(Operation {
        op_id: format!("op-{cookie}-{req_seq}-{ts_ns}"),
        ts_ns: Some(ts_ns),
        sock_cookie: cookie,
        req_seq,
        app: s3tap_schema::App { pid },
        verb: None,
        s3_op: Some(s3_op.into()),
        bucket: Some("b".into()),
        key_hash: Some(key_hash.into()),
        ttfb_ns: Some(total_ns * 7 / 10),
        download_ns: Some(total_ns * 3 / 10),
        total_ns: Some(total_ns),
        content_length,
        http_status: Some(status),
        connection_reused: req_seq > 0,
        ..Default::default()
    })
}

/// A connection record (for the latency checks).
pub(crate) fn conn(
    pid: u32,
    cookie: u64,
    ts_ns: u64,
    min_rtt_us: Option<u32>,
    region: Option<&str>,
    cross_region: bool,
    via_vpce: bool,
) -> Record {
    Record::Connection(Connection {
        ts_ns: Some(ts_ns),
        sock_cookie: cookie,
        app: s3tap_schema::App { pid },
        min_rtt_us,
        endpoint: Endpoint {
            region: region.map(Into::into),
            endpoint_ip: Some("198.51.100.7".into()),
            cross_region,
            via_vpce,
            ..Default::default()
        },
        tls: Tls { seen: true, ..Default::default() },
        ..Default::default()
    })
}

/// `n` GETs one after another, one fresh connection per op (churn + serial).
pub(crate) fn serial_ops(pid: u32, n: u32, spacing_ns: u64, latency_ns: u64) -> Vec<Record> {
    (0..n)
        .map(|i| {
            op(pid, 1000 + u64::from(i), 0, u64::from(i) * spacing_ns, latency_ns,
               "GetObject", &format!("k{i}"), 200, Some(1 << 20))
        })
        .collect()
}

/// `n` GETs overlapping across `k_conns` distinct connections, one pid: real
/// concurrency (a single HTTP/1.1 cookie can never overlap).
pub(crate) fn parallel_ops(pid: u32, n: u32, k_conns: u32, latency_ns: u64) -> Vec<Record> {
    (0..n)
        .map(|i| {
            let cookie = 2000 + u64::from(i % k_conns);
            // Same start bucket for each group of k -> guaranteed overlap.
            let ts = u64::from(i / k_conns) * latency_ns;
            op(pid, cookie, i / k_conns, ts, latency_ns, "GetObject",
               &format!("k{i}"), 200, Some(1 << 20))
        })
        .collect()
}

/// The same key fetched `n` times with the given status (refetch check).
pub(crate) fn refetch_ops(key: &str, n: u32, status: u16, size: Option<u64>) -> Vec<Record> {
    (0..n)
        .map(|i| op(9, 3000, i, u64::from(i) * 2_000_000_000, 40_000_000, "GetObject", key, status, size))
        .collect()
}

/// One HEAD then one GET on the same key, `gap_ns` apart (1:1 pair).
pub(crate) fn head_then_get(key: &str, base_ts: u64, gap_ns: u64) -> Vec<Record> {
    vec![
        op(9, 4000, 0, base_ts, 20_000_000, "HeadObject", key, 200, None),
        op(9, 4000, 1, base_ts + gap_ns, 40_000_000, "GetObject", key, 200, Some(1 << 20)),
    ]
}

/// One HEAD then `n_gets` GETs on the same key (the legitimate ranged fan-out).
pub(crate) fn head_then_ranged_fanout(key: &str, base_ts: u64, n_gets: u32) -> Vec<Record> {
    let mut v = vec![op(9, 5000, 0, base_ts, 20_000_000, "HeadObject", key, 200, None)];
    for i in 0..n_gets {
        v.push(op(9, 5000 + u64::from(i) + 1, 0, base_ts + 50_000_000 + u64::from(i) * 1_000_000,
                  400_000_000, "GetObject", key, 206, Some(8 << 20)));
    }
    v
}

/// `n` tiny GETs of distinct keys (small-object storm).
pub(crate) fn tiny_gets(pid: u32, n: u32, size: u64) -> Vec<Record> {
    (0..n)
        .map(|i| {
            let mut r = op(pid, 6000, i, u64::from(i) * 20_000_000, 30_000_000,
                           "GetObject", &format!("t{i}"), 200, Some(size));
            // Overhead-dominated: ttfb >> download.
            if let Record::Operation(o) = &mut r {
                o.ttfb_ns = Some(25_000_000);
                o.download_ns = Some(2_000_000);
            }
            r
        })
        .collect()
}

/// `n_ok` successful GETs then `n_503` throttled ops; when `recovered`, each
/// 503 is followed 100 ms later by a 200 on the same key, well before the end.
pub(crate) fn throttled_ops(n_ok: u32, n_503: u32, recovered: bool) -> Vec<Record> {
    let mut v: Vec<Record> = (0..n_ok)
        .map(|i| op(9, 7000, i, u64::from(i) * 1_000_000_000, 30_000_000,
                    "GetObject", &format!("g{}", i % 5), 200, Some(1 << 20)))
        .collect();
    let base = u64::from(n_ok) * 1_000_000_000;
    for j in 0..n_503 {
        let t = base + u64::from(j) * 1_000_000_000;
        v.push(op(9, 7100, j, t, 30_000_000, "GetObject", "hotkey", 503, None));
        if recovered {
            v.push(op(9, 7101, j, t + 100_000_000, 30_000_000, "GetObject", "hotkey", 200, Some(1 << 20)));
        }
    }
    // Trailing successes push the capture window well past the last 503 + 30 s,
    // so recovery-indeterminacy doesn't kick in for these fixtures.
    let tail = base + u64::from(n_503) * 1_000_000_000 + 60_000_000_000;
    v.push(op(9, 7200, 0, tail, 30_000_000, "GetObject", "z", 200, Some(1024)));
    v
}

/// Zipf-popularity GET stream over `objects` keys → replay `OpRecord`s (the
/// caching check's input). Deterministic (no rand dep), >= 1 ms ts spacing.
pub(crate) fn zipf_ops(objects: u32, len: u32) -> Vec<OpRecord> {
    let mut seed = 0x2545F491_4F6CDD1Du64;
    (0..len)
        .map(|i| {
            // xorshift + inverse-CDF-ish skew: bias toward low object indexes.
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let r = (seed % 1000) as f64 / 1000.0;
            let obj = ((f64::from(objects)).powf(r) - 1.0) as u32 % objects;
            op_record(&format!("z{obj}"), u64::from(i))
        })
        .collect()
}

/// Tiny hot object reused between huge cold one-shots — the request-GO /
/// dollar-no-go case: `hot_reads` GETs of a 4 KiB hot key per 256 MiB cold whale.
pub(crate) fn hot_small_cold_huge_ops(cycles: u32, hot_reads: u32) -> Vec<OpRecord> {
    let mut v = Vec::new();
    let mut i = 0u64;
    for c in 0..cycles {
        for _ in 0..hot_reads {
            v.push(sized_op_record("hot", i, Some(4 * 1024)));
            i += 1;
        }
        v.push(sized_op_record(&format!("cold{c}"), i, Some(256 << 20)));
        i += 1;
    }
    v
}

/// Deterministic repeating cycle s0..s{n-1} (sequence structure for the
/// caching policy path) → replay `OpRecord`s.
pub(crate) fn cyclic_ops(objects: u32, passes: u32) -> Vec<OpRecord> {
    let mut v = Vec::new();
    let mut i = 0u64;
    for _ in 0..passes {
        for o in 0..objects {
            v.push(op_record(&format!("s{o}"), i));
            i += 1;
        }
    }
    v
}

/// Never-repeating GET stream (no reuse) → replay `OpRecord`s.
pub(crate) fn unique_ops(len: u32) -> Vec<OpRecord> {
    (0..len).map(|i| op_record(&format!("u{i}"), u64::from(i))).collect()
}

/// The plan recipe: ts stringified with 1 ms spacing, bucket/key present (the
/// adapter drops identity-less records). `content_length: None` keeps these
/// fixtures in object-count mode (the byte path is exercised by `sized_ops`).
fn op_record(key: &str, i: u64) -> OpRecord {
    sized_op_record(key, i, None)
}

fn sized_op_record(key: &str, i: u64, content_length: Option<u64>) -> OpRecord {
    status_op_record(key, i, content_length, 200)
}

pub(crate) fn status_op_record(key: &str, i: u64, content_length: Option<u64>, status: u16) -> OpRecord {
    OpRecord {
        verb: None,
        s3_op: Some("GetObject".into()),
        bucket: Some("b".into()),
        key_hash: Some(key.into()),
        ts_ns: Some((i * 1_000_000).to_string()),
        http_status: Some(status),
        content_length,
    }
}

/// A hot object whose FIRST touch is unsized, then reused `reuse` times at
/// 100 MiB, amid 300 ordinary 1 MiB objects. Regression fixture: the unsized
/// first touch must NOT pin the object's size to 1 byte.
pub(crate) fn hot_object_unsized_first_touch_ops(reuse: u32) -> Vec<OpRecord> {
    let mut v = Vec::new();
    let mut i = 0u64;
    v.push(sized_op_record("big", i, None)); // unsized first touch
    i += 1;
    for _ in 0..reuse {
        v.push(sized_op_record("big", i, Some(100 << 20)));
        i += 1;
    }
    for j in 0..300u32 {
        v.push(sized_op_record(&format!("o{j}"), i, Some(1 << 20)));
        i += 1;
    }
    v
}

/// Zipf-reuse whole-object GETs plus a slug of 206 ranged GETs — the ranged
/// fraction disables byte sizing (ranged reads are sub-object; chunk mode is
/// deferred).
pub(crate) fn ranged_heavy_ops(objects: u32, whole: u32, ranged: u32) -> Vec<OpRecord> {
    let mut v = sized_zipf_ops(objects, whole, |_| 1 << 20);
    let base = v.len() as u64;
    for k in 0..ranged {
        v.push(status_op_record(&format!("z{}", k % objects), base + u64::from(k), Some(64 * 1024), 206));
    }
    v
}

/// Zipf-popularity GETs where each object carries a size from `size_of(obj)` —
/// the byte-capacity caching path's input. Deterministic.
pub(crate) fn sized_zipf_ops(objects: u32, len: u32, size_of: impl Fn(u32) -> u64) -> Vec<OpRecord> {
    let mut seed = 0x2545F491_4F6CDD1Du64;
    (0..len)
        .map(|i| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let r = (seed % 1000) as f64 / 1000.0;
            let obj = ((f64::from(objects)).powf(r) - 1.0) as u32 % objects;
            sized_op_record(&format!("z{obj}"), u64::from(i), Some(size_of(obj)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regenerates the CLI e2e's static fixture from the real serializers, so
    /// it can never drift from the schema. Run manually:
    ///   cargo test -p s3tap-advisor regenerate_cli_fixture -- --ignored
    #[test]
    #[ignore]
    fn regenerate_cli_fixture() {
        let mut lines = Vec::new();
        // A churny pid with connect timing: trips advisor-connection-churn.
        for r in serial_ops(7, 100, 1_000_000_000, 40_000_000) {
            if let Record::Operation(mut o) = r {
                if !o.connection_reused {
                    o.tcp_connect_ns = Some(20_000_000);
                }
                lines.push(serde_json::to_string(&o).unwrap());
            }
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../s3tap-cli/tests/fixtures/advisor_sample.jsonl");
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
        // Sanity: the doctor's parser must accept every line.
        let written = std::fs::read_to_string(path).unwrap();
        let (recs, stats) = s3tap_doctor::parse_records(&written);
        assert_eq!(recs.len(), 100);
        assert_eq!(stats.bad_lines + stats.unknown_schema, 0);
        // And the advisor must fire on it.
        assert!(!crate::advise(&recs).is_empty());
    }

    #[test]
    fn builders_produce_parseable_records() {
        // Round-trip through serde: every builder's output serializes cleanly.
        for r in serial_ops(1, 3, 1_000_000, 500_000)
            .into_iter()
            .chain(parallel_ops(1, 8, 4, 1_000_000))
            .chain(refetch_ops("k", 3, 200, Some(10)))
            .chain(head_then_get("k", 0, 1_000_000))
            .chain(head_then_ranged_fanout("k", 0, 3))
            .chain(tiny_gets(1, 3, 1024))
            .chain(throttled_ops(3, 2, true))
        {
            match r {
                Record::Operation(o) => {
                    serde_json::to_string(&o).expect("op serializes");
                }
                Record::Connection(c) => {
                    serde_json::to_string(&c).expect("conn serializes");
                }
                Record::TcpSample(_) => {}
            }
        }
        let _ = conn(1, 1, 0, Some(500), None, false, false);
        assert_eq!(zipf_ops(50, 100).len(), 100);
        assert_eq!(unique_ops(10).len(), 10);
    }
}
