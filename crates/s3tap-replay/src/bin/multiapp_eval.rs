//! Client-side deployment study: on a host running SEVERAL applications, is the
//! cache better shared, partitioned per app, or shared-with-per-app-predictors?
//!
//! We compose a multi-app host from independent IBM tenants: each input trace is
//! one "app", chunk-expanded, tagged, and merged by timestamp. Three configs:
//!
//! - shared-global: ONE cache, ONE predictor/EWMA over the interleaved stream —
//!   cross-app transitions poison the Markov chains (the blur that per-connection
//!   demultiplexing removes).
//! - shared-demux:  ONE cache (capacity statistically shared), but predictor and
//!   inter-arrival state PER APP — what s3tap's sock_cookie/pid labels enable.
//! - partitioned:   per-app caches of cap/N each, per-app predictors — full
//!   isolation, statically split capacity.
//!
//! Caveat: the composition is synthetic (these tenants never shared a host); the
//! timestamp overlay makes them concurrent. Illustrative, like the link study.
//!
//!   cargo run --release --bin multiapp_eval -- <traceA> <traceB> ... [cap last]
//! env: S3TAP_MAX per-trace event cap (default 1_000_000), S3TAP_FETCH_MS (100).

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use s3tap_replay::hybrid::WLfu;
use s3tap_replay::ibm::{from_ibm_line, to_blocks};
use s3tap_replay::predict::{MarkovPredictor, Predictor};
use s3tap_replay::trace::NormEvent;

const CHUNK: u64 = 8 * 1024 * 1024;

#[derive(Default, Clone)]
struct AppStats {
    accesses: u64,
    hits: u64,
    pf_issued: u64,
    lat_units: f64,
}

impl AppStats {
    fn hit_rate(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.hits as f64 / self.accesses as f64 }
    }
    fn net(&self) -> f64 {
        if self.accesses == 0 { 0.0 }
        else { (self.hits as f64 - self.pf_issued as f64) / self.accesses as f64 }
    }
    fn eff(&self) -> f64 {
        if self.accesses == 0 { 0.0 } else { self.lat_units / self.accesses as f64 }
    }
    fn add(&mut self, o: &AppStats) {
        self.accesses += o.accesses;
        self.hits += o.hits;
        self.pf_issued += o.pf_issued;
        self.lat_units += o.lat_units;
    }
}

fn app_of(id: &str) -> &str {
    id.split('|').next().unwrap_or("")
}

/// Per-app model state for the lead-gated overlay.
struct AppModel {
    mk: MarkovPredictor,
    ewma: f64,
    last_ts: Option<u64>,
}

impl AppModel {
    fn new(l: f64) -> Self {
        AppModel { mk: MarkovPredictor::new(1), ewma: l, last_ts: None }
    }
}

/// One cache, model state either global (demux=false) or per app (demux=true).
/// Mirrors hybrid::run_lead_gated (robust EWMA, joint-confidence chain).
fn run_shared(events: &[NormEvent], cap: u64, l_ns: u64, demux: bool) -> BTreeMap<String, AppStats> {
    let l = l_ns.max(1) as f64;
    let mut cache = WLfu::new_lru(cap);
    let mut models: HashMap<String, AppModel> = HashMap::new();
    let mut stats: BTreeMap<String, AppStats> = BTreeMap::new();
    for ev in events {
        let now = ev.ts_ns;
        let app = app_of(&ev.object_id).to_string();
        let key = if demux { app.clone() } else { String::new() };
        let st = stats.entry(app).or_default();
        st.accesses += 1;
        let info = cache.access(&ev.object_id, now);
        if info.hit {
            st.hits += 1;
            if info.pf_first_use {
                st.lat_units += (info.lead_ns as f64 / l).min(1.0);
            }
        } else {
            cache.insert(&ev.object_id, false, now);
        }
        let m = models.entry(key).or_insert_with(|| AppModel::new(l));
        if let Some(lt) = m.last_ts {
            let gap = now.saturating_sub(lt) as f64;
            if gap > 0.0 {
                m.ewma = 0.95 * m.ewma + 0.05 * gap.min(16.0 * l);
            }
        }
        m.last_ts = Some(now);
        m.mk.observe(ev);
        let k = ((l / m.ewma.max(1.0)).ceil() as usize).clamp(1, 32);
        if let Some(pid) = m.mk.chain_ahead(&ev.object_id, k, 0.5) {
            if pid != ev.object_id && !cache.contains(&pid) {
                if let Some(s) = stats.get_mut(app_of(&pid)) {
                    s.pf_issued += 1;
                }
                cache.insert(&pid, true, now);
            }
        }
    }
    stats
}

/// Per-app private caches, per-app models (full isolation). The `cap_total` is
/// split EXACTLY across the `n` apps (app i gets `cap_total/n`, plus one extra
/// for the first `cap_total % n` apps), so the per-app shares sum to exactly
/// `cap_total` — the same total the shared architectures get. The caller only
/// invokes this when `cap_total/n >= 2`, so no share hits WLfu's 2-chunk floor
/// (which would otherwise silently over-allocate the partitioned total).
fn run_partitioned(events: &[NormEvent], cap_total: u64, n: u64, l_ns: u64) -> BTreeMap<String, AppStats> {
    let l = l_ns.max(1) as f64;
    let mut caches: HashMap<String, WLfu> = HashMap::new();
    let mut models: HashMap<String, AppModel> = HashMap::new();
    let mut stats: BTreeMap<String, AppStats> = BTreeMap::new();
    for ev in events {
        let now = ev.ts_ns;
        let app = app_of(&ev.object_id).to_string();
        let cache = caches.entry(app.clone()).or_insert_with(|| {
            let idx: u64 = app.strip_prefix('A').and_then(|s| s.parse().ok()).unwrap_or(0);
            let share = cap_total / n + if idx < cap_total % n { 1 } else { 0 };
            WLfu::new_lru(share)
        });
        let st = stats.entry(app.clone()).or_default();
        st.accesses += 1;
        let info = cache.access(&ev.object_id, now);
        if info.hit {
            st.hits += 1;
            if info.pf_first_use {
                st.lat_units += (info.lead_ns as f64 / l).min(1.0);
            }
        } else {
            cache.insert(&ev.object_id, false, now);
        }
        let m = models.entry(app.clone()).or_insert_with(|| AppModel::new(l));
        if let Some(lt) = m.last_ts {
            let gap = now.saturating_sub(lt) as f64;
            if gap > 0.0 {
                m.ewma = 0.95 * m.ewma + 0.05 * gap.min(16.0 * l);
            }
        }
        m.last_ts = Some(now);
        m.mk.observe(ev);
        let k = ((l / m.ewma.max(1.0)).ceil() as usize).clamp(1, 32);
        if let Some(pid) = m.mk.chain_ahead(&ev.object_id, k, 0.5) {
            if pid != ev.object_id && !cache.contains(&pid) {
                st.pf_issued += 1;
                cache.insert(&pid, true, now);
            }
        }
    }
    stats
}

fn print_stats(name: &str, stats: &BTreeMap<String, AppStats>) {
    let mut total = AppStats::default();
    for (app, s) in stats {
        println!("{:<14} {:<6} {:>9.3} {:>9.3} {:>9.3}", name, app, s.hit_rate(), s.net(), s.eff());
        total.add(s);
    }
    println!("{:<14} {:<6} {:>9.3} {:>9.3} {:>9.3}", name, "ALL", total.hit_rate(), total.net(), total.eff());
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: multiapp_eval <traceA> <traceB> [...] [cap]");
        return ExitCode::from(2);
    }
    // Trailing numeric arg = capacity.
    let (paths, cap): (&[String], u64) = match args.last().unwrap().parse::<u64>() {
        Ok(c) => (&args[..args.len() - 1], c),
        Err(_) => (&args[..], 64),
    };
    // Present-but-invalid is an error, never a silent fall-back to the default: a typo in a
    // study run must not quietly produce numbers under parameters nobody chose. 0 keeps its
    // documented meaning here (use the default cap).
    let max_events: usize = match s3tap_replay::env::from_env::<usize>("S3TAP_MAX", "a non-negative integer") {
        Ok(v) => v.filter(|&n| n > 0).unwrap_or(1_000_000),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let fetch_ms: u64 = match s3tap_replay::env::from_env::<u64>("S3TAP_FETCH_MS", "a non-negative integer") {
        Ok(v) => v.unwrap_or(100),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    // Saturating: `fetch_ms` is operator input, so a large value must clamp rather than wrap
    // to a tiny latency (release) or panic (debug). The other bins already use saturating
    // arithmetic on this conversion.
    let l_ns = fetch_ms.saturating_mul(1_000_000);

    // Load each app's trace, chunk-expand, tag ids with "A<i>|".
    let mut merged: Vec<NormEvent> = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let file = match std::fs::File::open(p) {
            Ok(f) => f,
            Err(e) => { eprintln!("cannot open {p}: {e}"); return ExitCode::from(1); }
        };
        let mut t = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => { eprintln!("error reading {p}: {e}"); return ExitCode::from(1); }
            };
            if let Some(ev) = from_ibm_line(&line) { t.push(ev); }
            if t.len() >= max_events { break; }
        }
        let mut blocks = to_blocks(&t, CHUNK);
        for ev in &mut blocks {
            ev.object_id = format!("A{i}|{}", ev.object_id);
        }
        eprintln!("app A{i} = {p}: {} events -> {} chunks", t.len(), blocks.len());
        merged.extend(blocks);
    }
    // Merge apps into one host timeline (stable: ties keep app order).
    merged.sort_by_key(|e| e.ts_ns);
    eprintln!("merged host stream: {} chunk accesses; cap={cap}, fetch={fetch_ms}ms", merged.len());

    println!("{:<14} {:<6} {:>9} {:>9} {:>9}", "config", "app", "hit_rate", "net_save", "eff_lat");
    print_stats("shared-global", &run_shared(&merged, cap, l_ns, false));
    print_stats("shared-demux", &run_shared(&merged, cap, l_ns, true));
    let n = paths.len() as u64;
    if cap / n >= 2 {
        print_stats("partitioned", &run_partitioned(&merged, cap, n, l_ns));
    } else {
        eprintln!("(partitioned skipped: cap {cap} too small to give {n} apps >= 2 chunks each)");
    }
    ExitCode::SUCCESS
}
