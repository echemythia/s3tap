// crates/s3tap-cli/src/render.rs
//
// The OPEN renderers: turn one s3tap.operation/1 record into
// a phase-aligned `waterfall` timeline or a `table` row. Pure formatting — no I/O,
// no kernel — so every shape is unit-tested against sample records below.
//
// HONESTY: the renderer never hides a flag or fakes a number. M3.5
// leaves tls_handshake_ns / download_ns / total_ns null (the handshake can't be
// timed from a send-side hook; the body is head-gated), so those phases render as
// "(not measured)" — a labeled lane, never a zero-width bar that would read as
// "instant". The timeline composes only the phases we actually measured
// (DNS → connect → request▸TTFB), and the per-op footer uses op_bytes_* (the head
// bytes), since the cumulative srtt/retransmits/bytes are connection-scoped and
// unknown at op time.

use s3tap_schema::{Delimitation, Operation};

/// Width (chars) of the waterfall bar track.
const TRACK: usize = 40;

// Terminal-safe rendering of attacker-influenceable strings (a path-style bucket here,
// a crafted s3_op in `s3tap doctor`) lives in s3tap-schema so the agent and the doctor
// share ONE hardened defense (CWE-117 / Trojan Source). Re-exported so existing
// `render::sanitize_term` / `super::sanitize_term` callers are unchanged.
pub(crate) use s3tap_schema::sanitize_term;

/// Render one operation as a multi-line waterfall timeline.
#[must_use]
pub fn waterfall(op: &Operation) -> String {
    let mut s = String::new();
    s.push_str(&headline(op));
    s.push('\n');

    // The measured, sequential phases that compose the op's latency. A reused
    // connection paid no setup, so its DNS/connect lanes collapse to a marker.
    let mut lanes: Vec<Lane> = Vec::new();
    if op.connection_reused {
        lanes.push(Lane::marker("connection", "[reused]"));
    } else {
        // Surface dns.cache_hit (an honesty flag): a fast DNS bar is
        // ambiguous between a cache hit and a fast cold resolve — the label says which.
        let dns = match op.dns.as_ref() {
            Some(d) => Lane::phase("DNS", Some(d.latency_ns))
                .with_suffix(if d.cache_hit { "cache hit" } else { "cold resolve" }),
            None => Lane::phase("DNS", None),
        };
        lanes.push(dns);
        lanes.push(Lane::phase("TCP connect", op.tcp_connect_ns));
        lanes.push(Lane::phase("TLS handshake", op.tls_handshake_ns));
    }
    lanes.push(Lane::phase("request \u{25b8} TTFB", op.ttfb_ns));
    lanes.push(Lane::phase("download", op.download_ns));

    // Scale bars to the sum of the MEASURED sequential phases (no total_ns yet).
    // Saturating: phase durations are attacker-influenced; a pathological pair of
    // near-u64::MAX phases must not overflow the u64 sum (debug-build panic).
    let scale: u64 = lanes
        .iter()
        .filter_map(|l| l.measured())
        .fold(0u64, u64::saturating_add);
    // Track the VISUAL column, not the ns offset: each bar starts exactly where the
    // previous one ended, so the lanes tile [0,TRACK] contiguously by construction —
    // even when a sub-1-char phase is bumped to width 1 (no stacking at col 0, no
    // reliance on a per-lane overflow clamp).
    let measured_total = lanes.iter().filter(|l| l.measured().is_some()).count();
    let mut col = 0usize;
    let mut measured_seen = 0usize;
    for lane in &lanes {
        // How many MEASURED lanes still come after this one — each needs >=1 column
        // reserved so a dominant earlier phase (e.g. a multi-second DNS) can't squeeze
        // a genuinely-measured later phase to a 0-width "instant" bar.
        if lane.measured().is_some() {
            measured_seen += 1;
        }
        let remaining_measured = measured_total - measured_seen;
        s.push_str("\n  ");
        let (line, consumed) = lane.render(col, scale, remaining_measured);
        s.push_str(&line);
        col += consumed;
    }

    // Honesty annotations: surface every flag, never hide it.
    for note in honesty_notes(op) {
        s.push_str("\n  ");
        s.push_str(&note);
    }

    s.push_str("\n\n  ");
    s.push_str(&footer(op));
    s
}

/// The headline: `VERB s3://bucket/<key>   → ip   <ms>  ✓/✗ status`.
fn headline(op: &Operation) -> String {
    // Sanitize verb/s3_op too (defense-in-depth). They are enum-constrained on the live
    // capture path, but these renderers must stay safe if ever fed deserialized records.
    let verb = sanitize_term(op.s3_op.as_deref().or(op.verb.as_deref()).unwrap_or("?"));
    // bucket is the one attacker-controlled, non-charset-validated field; clean it,
    // and cap it (a real bucket label is <= 63 chars) so a pathological 10k-char
    // bucket can't blow up the headline line — symmetric with the table column.
    let bucket = truncate(&sanitize_term(op.bucket.as_deref().unwrap_or("?")), 64);
    // The object key is only ever a hash in the record; show a placeholder, never
    // the hash itself (it's noise to a human and the key is intentionally opaque).
    let key = if op.key_hash.is_some() { "/<key>" } else { "" };
    // IP is on the op only via the first-op dns block (resolved_ip); reused/partial
    // ops don't carry it. Region isn't on the op record yet (M4 endpoint enrichment).
    let ip = op
        .dns
        .as_ref()
        .and_then(|d| d.resolved_ip.as_deref())
        .map_or_else(String::new, |ip| format!("   \u{2192} {ip}"));
    // The headline latency: the true end-to-end total when we have it, else ttfb —
    // and TAGGED `(ttfb)` in the fallback so the number isn't misread as the total
    // (handshake + download are unaccounted today, so ttfb < wall-clock).
    let latency = match (op.total_ns, op.ttfb_ns) {
        (Some(t), _) => fmt_ms(t).trim().to_string(),
        (None, Some(tt)) => format!("{} (ttfb)", fmt_ms(tt).trim()),
        (None, None) => "-".to_string(),
    };
    let status = match op.http_status {
        Some(c) if c < 400 => format!("\u{2713} {c}"), // ✓
        Some(c) => format!("\u{2717} {c}"),            // ✗
        None => "\u{2717} -".to_string(),
    };
    format!("{verb} s3://{bucket}{key}{ip}   {latency}  {status}")
}

/// The one column layout, shared by [`table_row`] and [`table_header`] so the two cannot
/// drift apart. Widths are set by the widest REALISTIC value, so ordinary output is never
/// truncated: CODE 5 fits any `u16`, TTFB 11 fits `300000.0 ms` (a five-minute request),
/// RECV 10 fits the widest [`human_bytes`] rendering (`1023.9 PiB`).
macro_rules! table_fmt {
    () => {
        "{:<14} {:<22} {:>5} {:>11} {:>5} {:>10} {:<3}"
    };
}

/// One row per op for `--format table`. Columns are the headline op fields; pair
/// with [`table_header`]. Fixed-width so a stream of ops scans cleanly.
#[must_use]
pub fn table_row(op: &Operation) -> String {
    let status = op.http_status.map_or_else(|| "-".into(), |c| c.to_string());
    let ttfb = op.ttfb_ns.map_or_else(|| "-".into(), |ns| fmt_ms(ns).trim().to_string());
    let reuse = if op.connection_reused { "reuse" } else { "new" };
    // Flags (honesty): P=partial, A=ambiguous, C=DNS cache hit.
    let mut flags = String::new();
    if op.partial {
        flags.push('P');
    }
    if op.delimitation == Delimitation::Ambiguous {
        flags.push('A');
    }
    if op.dns.as_ref().is_some_and(|d| d.cache_hit) {
        flags.push('C');
    }
    // EVERY field is truncated to its column, not just the two free-text ones. A table's
    // whole value is that the eye can run down a column, and one row is enough to destroy
    // that for the entire stream — so no field may be allowed to push its column, whatever
    // the record says. The widths below are sized so a REALISTIC value never truncates
    // (see `table_fmt`), which leaves truncation for the absurd: a corrupt u64::MAX timing,
    // a 5-digit status. Those lose precision, and the ellipsis says so, rather than
    // silently shearing the columns of every row that follows.
    format!(
        table_fmt!(),
        truncate(&sanitize_term(op.s3_op.as_deref().unwrap_or("?")), 14),
        truncate(&sanitize_term(op.bucket.as_deref().unwrap_or("?")), 22),
        truncate(&status, 5),
        truncate(&ttfb, 11),
        truncate(reuse, 5),
        truncate(&human_bytes(op.op_bytes_recv.unwrap_or(0)), 10),
        truncate(&flags, 3),
    )
}

/// The column header for [`table_row`] (printed once, before the stream).
#[must_use]
pub fn table_header() -> String {
    format!(table_fmt!(), "OP", "BUCKET", "CODE", "TTFB", "CONN", "RECV", "FLG")
}

/// The per-op footer line: op-scoped byte counts + the reuse flag. NB these are
/// op_bytes_* (the head write/read), not connection-cumulative wire bytes — those
/// are read at close and unknown at op time, so we don't pretend to show them.
fn footer(op: &Operation) -> String {
    format!(
        "op sent {} \u{b7} recv {} \u{b7} reused={}",
        op.op_bytes_sent.map_or_else(|| "-".into(), human_bytes),
        op.op_bytes_recv.map_or_else(|| "-".into(), human_bytes),
        op.connection_reused,
    )
}

/// Honesty annotations mapped from the record's flags. Returned in a
/// stable order so the output is deterministic.
fn honesty_notes(op: &Operation) -> Vec<String> {
    let mut notes = Vec::new();
    if op.delimitation == Delimitation::Ambiguous {
        notes.push("\u{26a0} delimitation=ambiguous \u{2014} overlapping requests; timings approximate".to_string());
    }
    if op.partial {
        notes.push("\u{26a0} partial \u{2014} connection facts unattributable; setup metrics may be missing".to_string());
    }
    notes
}

/// A single waterfall lane: either a measured/absent phase or a literal marker.
struct Lane {
    label: String,
    kind: LaneKind,
    /// Trailing annotation after the ms (e.g. the DNS lane's cache-hit/cold flag).
    suffix: String,
}

enum LaneKind {
    /// A timed phase: Some(ns) when measured, None when not observed.
    Phase(Option<u64>),
    /// A literal marker (e.g. the `[reused]` collapse), no bar.
    Marker(String),
}

impl Lane {
    fn phase(label: &str, ns: Option<u64>) -> Self {
        Lane { label: label.to_string(), kind: LaneKind::Phase(ns), suffix: String::new() }
    }
    fn marker(label: &str, text: &str) -> Self {
        Lane { label: label.to_string(), kind: LaneKind::Marker(text.to_string()), suffix: String::new() }
    }
    /// Attach a trailing annotation rendered after the duration (e.g. cache hit).
    fn with_suffix(mut self, suffix: &str) -> Self {
        self.suffix = format!("  {suffix}");
        self
    }
    /// The measured duration of this lane, if any (markers and absent phases: None).
    fn measured(&self) -> Option<u64> {
        match self.kind {
            LaneKind::Phase(d) => d,
            LaneKind::Marker(_) => None,
        }
    }
    /// Render `label  <bar/marker>  <ms>` for a bar starting at visual column
    /// `start` (chars already consumed by prior lanes). Returns the rendered line
    /// and the visual width this lane consumed (0 for markers / unmeasured phases),
    /// so the caller advances the column and the bars tile contiguously.
    fn render(&self, start: usize, scale: u64, remaining_measured: usize) -> (String, usize) {
        // Width 15 guarantees ≥1 space after even the longest label ("request ▸
        // TTFB" = 14 chars), so a bar starting at column 0 never butts the label.
        let label = format!("{:<15}", self.label);
        let suffix = &self.suffix;
        match &self.kind {
            LaneKind::Marker(text) => (format!("{label}{text}{suffix}"), 0),
            LaneKind::Phase(None) => (format!("{label}(not measured){suffix}"), 0),
            LaneKind::Phase(Some(d)) => {
                // A measured phase is NEVER 0-width (honesty: a non-zero phase must
                // not read as "instant"). Reserve ≥1 column for each later measured
                // lane so a dominant earlier phase can't fill the track and squeeze
                // this one — or a later one — to nothing. The result still tiles
                // within [0,TRACK] (e.g. a 4s-DNS waterfall becomes 36/1/1/1/1).
                let avail = TRACK
                    .saturating_sub(start)
                    .saturating_sub(remaining_measured)
                    .max(1);
                let width = scaled(*d, scale).max(1).min(avail);
                let pad = " ".repeat(start.min(TRACK));
                let bar = "\u{2500}".repeat(width);
                (format!("{label}{pad}{bar}  {}{suffix}", fmt_ms(*d).trim()), width)
            }
        }
    }
}

/// Map an ns value onto the [0, TRACK] char track for a given ns scale.
fn scaled(ns: u64, scale: u64) -> usize {
    if scale == 0 {
        return 0;
    }
    // round(ns / scale * TRACK), in integer math.
    ((ns as u128 * TRACK as u128 + scale as u128 / 2) / scale as u128) as usize
}

/// Format ns as a right-padded millisecond string, e.g. `   1.8 ms`. Field width 7
/// holds up to 99999.9 ms (~100 s) without breaking the column alignment.
fn fmt_ms(ns: u64) -> String {
    format!("{:>7.1} ms", ns as f64 / 1e6)
}

/// Human-readable byte count (B / KiB / MiB / GiB / TiB / PiB / EiB), 1 decimal above KiB.
fn human_bytes(n: u64) -> String {
    // Through EiB: u64 bytes reach 16 EiB, and a multipart S3 object legitimately
    // reaches TiB. Stopping at GiB rendered those as a five-digit GiB count, which both
    // reads badly and overflows the table's RECV column.
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Truncate a string to `max` chars with an ellipsis, for fixed-width columns.
///
/// Column widths here count Unicode scalar values (`{:<N}` / `chars().count()`),
/// which equals the terminal display width for ASCII and width-1 glyphs — the
/// common case (bucket names are DNS-label ASCII; the renderer's symbols ▸ … ✓ are
/// East-Asian-Width "Ambiguous" = width-1 in a Western locale). Under a CJK-
/// configured terminal an Ambiguous glyph renders width-2, drifting a column by 1;
/// accepted as cosmetic rather than pulling in a unicode-width dependency.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let keep = max.saturating_sub(1);
        format!("{}\u{2026}", s.chars().take(keep).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3tap_schema::{App, Dns};

    fn base_op() -> Operation {
        Operation {
            verb: Some("GET".into()),
            s3_op: Some("GetObject".into()),
            bucket: Some("my-bucket".into()),
            key_hash: Some("sha256:9c".into()),
            app: App { pid: 42 },
            http_status: Some(200),
            ..Default::default()
        }
    }

    fn cold_op() -> Operation {
        Operation {
            dns: Some(Dns {
                latency_ns: 1_800_000,
                cache_hit: false,
                resolved_ip: Some("52.216.0.1".into()),
                n_answers: 4,
                ttl_s: Some(60),
                via: "wire".into(),
            }),
            tcp_connect_ns: Some(11_200_000),
            ttfb_ns: Some(41_000_000),
            op_bytes_sent: Some(357),
            op_bytes_recv: Some(178),
            connection_reused: false,
            ..base_op()
        }
    }

    #[test]
    fn cold_op_waterfall_shows_measured_phases_and_marks_the_rest() {
        let out = waterfall(&cold_op());
        // Headline: verb, bucket, key placeholder (never the hash), ip, status.
        assert!(out.contains("GetObject s3://my-bucket/<key>"), "{out}");
        assert!(out.contains("52.216.0.1"));
        assert!(out.contains("\u{2713} 200")); // ✓ 200
        assert!(!out.contains("sha256:9c"), "the key hash must not be rendered");
        // Measured phases carry a duration; the unmeasured ones are labeled, not 0.
        assert!(out.contains("DNS") && out.contains("1.8 ms"));
        // cache_hit honesty: a cold resolve is labeled, not silent.
        assert!(out.contains("cold resolve"), "cold DNS resolve must be labeled: {out}");
        // The headline ttfb is tagged so it isn't misread as the (absent) total.
        assert!(out.contains("41.0 ms (ttfb)"), "headline ttfb must be tagged: {out}");
        assert!(out.contains("TCP connect") && out.contains("11.2 ms"));
        assert!(out.contains("request \u{25b8} TTFB") && out.contains("41.0 ms"));
        assert!(out.contains("TLS handshake") && out.contains("(not measured)"));
        assert!(out.contains("download") && out.contains("(not measured)"));
        // A measured phase draws a bar; the bar chars exist.
        assert!(out.contains('\u{2500}'), "measured phases draw a bar");
        // Footer uses op bytes.
        assert!(out.contains("op sent 357 B \u{b7} recv 178 B \u{b7} reused=false"));
    }

    #[test]
    fn reused_op_collapses_setup_to_a_marker() {
        let mut op = base_op();
        op.connection_reused = true;
        op.ttfb_ns = Some(10_100_000);
        op.op_bytes_sent = Some(412);
        op.op_bytes_recv = Some(1_258_291);
        let out = waterfall(&op);
        assert!(out.contains("connection   ") && out.contains("[reused]"), "{out}");
        // No DNS/connect/handshake lanes on a reused op.
        assert!(!out.contains("DNS"));
        assert!(!out.contains("TCP connect"));
        assert!(out.contains("request \u{25b8} TTFB") && out.contains("10.1 ms"));
        assert!(out.contains("recv 1.2 MiB"));
        assert!(out.contains("reused=true"));
    }

    #[test]
    fn error_status_renders_a_cross() {
        let mut op = cold_op();
        op.http_status = Some(503);
        let out = waterfall(&op);
        assert!(out.contains("\u{2717} 503"), "{out}"); // ✗ 503
    }

    #[test]
    fn honesty_flags_are_always_surfaced() {
        let mut op = cold_op();
        op.partial = true;
        op.delimitation = Delimitation::Ambiguous;
        let out = waterfall(&op);
        assert!(out.contains("delimitation=ambiguous"), "{out}");
        assert!(out.contains("partial"));
    }

    #[test]
    fn missing_status_is_a_cross_dash() {
        let mut op = cold_op();
        op.http_status = None;
        let out = waterfall(&op);
        assert!(out.contains("\u{2717} -"), "{out}");
    }

    #[test]
    fn table_row_aligns_and_flags() {
        let header = table_header();
        let mut op = cold_op();
        op.partial = true;
        let row = table_row(&op);
        assert!(header.contains("OP") && header.contains("BUCKET") && header.contains("TTFB"));
        assert!(row.contains("GetObject"));
        assert!(row.contains("my-bucket"));
        assert!(row.contains("200"));
        assert!(row.contains("41.0 ms"));
        assert!(row.contains("new"));
        assert!(row.trim_end().ends_with('P'), "partial flag P present: {row:?}");
        // Header and row share the same column width (chars — fill/align counts USVs).
        assert_eq!(header.chars().count(), row.chars().count(), "header/row widths must match");
    }

    #[test]
    fn table_row_reused_and_clean_has_no_flags() {
        let mut op = base_op();
        op.connection_reused = true;
        op.ttfb_ns = Some(9_000_000);
        let row = table_row(&op);
        assert!(row.contains("reuse"));
        // FLG is the final, left-aligned width-3 field: assert it is literally blank
        // (3 spaces) rather than asserting a proxy about the previous column's tail.
        let chars: Vec<char> = row.chars().collect();
        let flg: String = chars[chars.len() - 3..].iter().collect();
        assert_eq!(flg, "   ", "a reused+clean op must have an empty FLG field: {row:?}");
    }

    #[test]
    #[ignore = "visual: `cargo test -p s3tap render -- --ignored --nocapture`"]
    fn print_samples() {
        let mut err = cold_op();
        err.http_status = Some(503);
        err.partial = true;
        let mut reused = base_op();
        reused.connection_reused = true;
        reused.ttfb_ns = Some(10_100_000);
        reused.op_bytes_recv = Some(1_310_720);
        for op in [cold_op(), reused, err] {
            println!("\n{}\n", waterfall(&op));
        }
        println!("{}", table_header());
        println!("{}", table_row(&cold_op()));
    }

    #[test]
    fn fully_populated_op_shows_the_total_and_draws_every_phase() {
        // Future-proofing: when M3.5's nulls (handshake/download/total) become real,
        // the headline must show the UNTAGGED total (not the (ttfb) fallback) and
        // every lane must draw a bar — no "(not measured)". Locks that contract now.
        let op = Operation {
            s3_op: Some("GetObject".into()),
            bucket: Some("b".into()),
            key_hash: Some("sha256:9c".into()),
            dns: Some(Dns {
                latency_ns: 1_800_000,
                cache_hit: false,
                resolved_ip: Some("52.216.0.1".into()),
                n_answers: 4,
                ttl_s: Some(60),
                via: "wire".into(),
            }),
            tcp_connect_ns: Some(11_200_000),
            tls_handshake_ns: Some(23_400_000),
            ttfb_ns: Some(41_000_000),
            download_ns: Some(7_400_000),
            total_ns: Some(88_300_000),
            http_status: Some(200),
            ..Default::default()
        };
        let out = waterfall(&op);
        assert!(out.contains("88.3 ms"), "headline shows the total: {out}");
        assert!(!out.contains("(ttfb)"), "with a real total, the ttfb tag is gone: {out}");
        assert!(!out.contains("(not measured)"), "every phase is drawn: {out}");
        let mut total_bars = 0;
        for line in out.lines() {
            let bars = line.chars().filter(|&c| c == '\u{2500}').count();
            assert!(bars <= TRACK);
            total_bars += bars;
        }
        assert!(total_bars <= TRACK, "all five phases tile within the track");
        assert!(total_bars >= 5, "five measured phases each draw at least 1 char: {total_bars}");
    }

    #[test]
    fn long_bucket_is_capped_in_the_headline() {
        let mut op = cold_op();
        op.bucket = Some("z".repeat(10_000));
        let head = waterfall(&op).lines().next().unwrap().to_string();
        assert!(head.contains('\u{2026}'), "headline bucket truncated: {head}");
        assert!(head.chars().count() < 200, "headline bounded, not 10k chars: {}", head.chars().count());
    }

    #[test]
    fn dns_cache_hit_is_labeled_and_flagged() {
        let mut op = cold_op();
        op.dns.as_mut().unwrap().cache_hit = true;
        op.dns.as_mut().unwrap().latency_ns = 90_000; // a fast cached resolve
        let out = waterfall(&op);
        assert!(out.contains("cache hit"), "cache hit must be labeled: {out}");
        assert!(!out.contains("cold resolve"));
        // Table FLG column carries C for the cache hit.
        let row = table_row(&op);
        assert!(row.trim_end().ends_with('C'), "table FLG must carry C: {row:?}");
    }

    #[test]
    fn attacker_bucket_cannot_inject_terminal_escapes() {
        // A path-style bucket comes from the raw request line — an attacker can put
        // ANSI escapes / CR / NL in it. Neither renderer may emit them verbatim.
        let mut op = cold_op();
        op.bucket = Some("\x1b[2Kevil\r\nForged: line\x07".into());
        let wf = waterfall(&op);
        let row = table_row(&op);
        for out in [&wf, &row] {
            assert!(!out.contains('\x1b'), "ESC leaked: {out:?}");
            assert!(!out.contains('\x07'), "BEL leaked: {out:?}");
            assert!(!out.contains('\r'), "CR leaked: {out:?}");
            // The bucket's own bytes must not introduce a newline (the waterfall has
            // legitimate \n between lanes, so check the headline line specifically).
        }
        // The headline line (first line) must be a single line — no embedded NL.
        assert!(!wf.lines().next().unwrap().contains('\n'));
        assert_eq!(wf.lines().next().unwrap().matches("Forged").count(), 1, "no forged second line on the headline");
    }

    #[test]
    fn sanitize_term_passes_clean_strings_through() {
        assert_eq!(sanitize_term("my-bucket.prod"), "my-bucket.prod");
        assert_eq!(sanitize_term("a\x1bb"), "a\u{fffd}b");
    }

    #[test]
    fn sanitize_term_strips_bidi_and_zero_width_spoofers() {
        // Trojan-Source class (review L6): a path-style bucket carrying a bidi override
        // (U+202E) or zero-width char could visually reorder/hide the rendered name.
        // char::is_control (Cc) misses these Cf chars — they must still be replaced.
        // Includes the Cf chars the enumerated-range version originally missed (F2):
        // WORD JOINER, an invisible operator, SOFT HYPHEN, interlinear, and a TAG-block
        // char used for invisible-character smuggling.
        for spoof in [
            '\u{202E}', '\u{200B}', '\u{2066}', '\u{FEFF}', '\u{061C}', // already covered
            '\u{2060}', '\u{2061}', '\u{00AD}', '\u{FFF9}', '\u{E0041}', // previously leaked
        ] {
            let s = format!("good{spoof}evil");
            let out = sanitize_term(&s);
            assert!(!out.contains(spoof), "format char {spoof:?} leaked: {out:?}");
            assert!(out.contains('\u{fffd}'), "replaced with U+FFFD");
        }
        // And in the actual renderers via a crafted bucket.
        let mut op = cold_op();
        op.bucket = Some("real\u{202E}live".into());
        let wf = waterfall(&op);
        let row = table_row(&op);
        assert!(!wf.contains('\u{202e}') && !row.contains('\u{202e}'), "renderers strip bidi");
    }

    #[test]
    fn adv_default_and_pathological_never_panic() {
        // Fully-default op (the key adversarial case).
        let d = Operation::default();
        let _ = waterfall(&d);
        let _ = table_row(&d);
        let _ = table_header();
        // Pathological maxima — every duration/byte at u64::MAX, a giant bucket/IP.
        let p = Operation {
            ttfb_ns: Some(u64::MAX),
            tcp_connect_ns: Some(u64::MAX),
            tls_handshake_ns: Some(u64::MAX),
            download_ns: Some(u64::MAX),
            total_ns: Some(u64::MAX),
            op_bytes_sent: Some(u64::MAX),
            op_bytes_recv: Some(u64::MAX),
            bucket: Some("x".repeat(10_000)),
            http_status: Some(u16::MAX),
            dns: Some(Dns {
                latency_ns: u64::MAX,
                cache_hit: true,
                resolved_ip: Some("y".repeat(5000)),
                n_answers: 0,
                ttl_s: None,
                via: "wire".into(),
            }),
            ..Default::default()
        };
        // Not just "never panics": the pathological row must still LINE UP. Every field
        // here is past its column (a 10 000-char bucket, a u64::MAX timing that formats to
        // 19 chars, a 5-digit status), so this is the guard that a truncation regression
        // in any one of them cannot pass — an over-wide field shears the columns of every
        // subsequent row in the stream, which is the whole point of `--format table`.
        assert_eq!(
            table_header().chars().count(),
            table_row(&p).chars().count(),
            "pathological row must keep the header's width:\n{}\n{}",
            table_header(),
            table_row(&p)
        );
        // The all-default row too (the other extreme: every field absent).
        assert_eq!(table_header().chars().count(), table_row(&d).chars().count());
        let _ = waterfall(&p);
        // Scale-overflow trigger: two measured phases summing past u64::MAX (would
        // panic on a debug `.sum()` — the saturating fold makes it safe).
        let s = Operation { tcp_connect_ns: Some(u64::MAX), ttfb_ns: Some(1), ..Default::default() };
        let _ = waterfall(&s);
        // Reused + max ttfb: a single bar gets the full scale.
        let r = Operation { connection_reused: true, ttfb_ns: Some(u64::MAX), ..Default::default() };
        let _ = waterfall(&r);
        // The unit helpers at their boundaries.
        assert_eq!(scaled(u64::MAX, u64::MAX), 40);
        assert_eq!(scaled(5, 0), 0);
        let _ = fmt_ms(u64::MAX);
        assert_eq!(truncate("", 0), ""); // empty: count 0 <= 0, returns s
        assert_eq!(truncate("abc", 0), "\u{2026}"); // keep = saturating_sub(1) = 0
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(312), "312 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        // A multipart object is legitimately TiB-scale, and u64 tops out in EiB. Both
        // must render in their own unit — and, crucially, within the RECV column: the
        // widest possible rendering is "1023.9 PiB" (10 chars), which is that width.
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024 * 1024), "5.0 TiB");
        assert_eq!(human_bytes(u64::MAX), "16.0 EiB");
        for n in [0, 1, 1023, 1024, u64::MAX / 3, u64::MAX] {
            assert!(human_bytes(n).chars().count() <= 10, "{n} -> {:?}", human_bytes(n));
        }
    }

    #[test]
    fn long_bucket_name_is_truncated_in_the_table() {
        let mut op = base_op();
        op.bucket = Some("a-really-long-bucket-name-exceeding-the-column".into());
        let row = table_row(&op);
        assert!(row.contains('\u{2026}'), "long bucket truncated with ellipsis: {row}");
        assert_eq!(table_header().chars().count(), row.chars().count());
    }

    #[test]
    fn bars_never_overflow_the_track() {
        // A wildly skewed phase mix must still keep every bar within the track.
        let mut op = cold_op();
        op.dns = Some(Dns {
            latency_ns: 1,
            cache_hit: false,
            resolved_ip: None,
            n_answers: 0,
            ttl_s: None,
            via: "wire".into(),
        });
        op.tcp_connect_ns = Some(1);
        op.ttfb_ns = Some(10_000_000_000); // 10 s dominates
        let out = waterfall(&op);
        let mut total_bars = 0;
        for line in out.lines() {
            let bars = line.chars().filter(|&c| c == '\u{2500}').count();
            assert!(bars <= TRACK, "a lane exceeded the {TRACK}-char track: {line:?}");
            total_bars += bars;
        }
        // Contiguous tiling: the phases compose [0,TRACK], so the bars across ALL
        // lanes sum to at most the track — they don't stack/overlap at column 0.
        assert!(total_bars <= TRACK, "bars sum {total_bars} exceeded the track (stacking?)");
    }

    #[test]
    fn every_measured_phase_keeps_at_least_one_bar_under_skew() {
        // Honesty: a dominant earlier phase (a multi-second DNS) must NOT squeeze a
        // genuinely-measured later phase (connect / ttfb) to a 0-width "instant" bar.
        let mut op = cold_op();
        op.dns = Some(Dns {
            latency_ns: 4_000_000_000, // 4 s dominates the track
            cache_hit: false,
            resolved_ip: None,
            n_answers: 0,
            ttl_s: None,
            via: "wire".into(),
        });
        op.tcp_connect_ns = Some(1_000_000); // 1 ms
        op.ttfb_ns = Some(1_000_000); // 1 ms
        let out = waterfall(&op);
        for label in ["DNS", "TCP connect", "request \u{25b8} TTFB"] {
            let line = out.lines().find(|l| l.contains(label)).expect("lane present");
            let bars = line.chars().filter(|&c| c == '\u{2500}').count();
            assert!(bars >= 1, "measured lane {label:?} rendered 0-width (reads as instant): {line:?}");
        }
    }
}
