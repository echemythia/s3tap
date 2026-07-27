#!/usr/bin/env bash
# s3tap × warp: observe a REAL Go S3 client under concurrency, passively.
#
# warp (MinIO's S3 benchmark) is built on aws-sdk-go = Go `crypto/tls`. s3tap captures it
# by process name — ZERO instrumentation, no OpenSSL, no curl wrapper — and surfaces the
# library-agnostic CONNECTION/NETWORK layer the app's own stats (and `curl -w`) can't:
# per-connection min_rtt (true floor) + jitter, retransmits under load, the send-side
# bottleneck/BDP attribution, the SNI/endpoint hit, the NEGOTIATED TLS version + cipher,
# and connection-pool shape.
#
# WHY this is connection-only: warp is Go, so there's no libssl to hook — s3tap gets every
# connection (kernel TCP), the SNI (kernel ClientHello parse) AND the negotiated TLS
# version+cipher (kernel ServerHello parse on the ingress path) — all library-agnostic —
# but NOT per-operation L7 (TTFB/op-class/throughput). That's the point: the network +
# TLS-handshake layer is library-agnostic. For the per-OPERATION story use an OpenSSL
# client (curl/python) — see demo/provider-benchmark/run.sh.
#
# The pairing it enables: warp reports the WHAT (ops/s, throughput, latency); s3tap reports
# the WHY from the kernel (RTT floor, retransmits, pool reuse) underneath it.
#
# Prereqs:
#   go install github.com/minio/warp@latest     # or any `warp` on PATH
#   cargo build --release -p s3tap && UPROBES=1 ./setcap.sh release   # caps; re-cap after rebuilds
#   ~/.aws/credentials [default] = your Storj S3 keys (creds passed to warp via env, off argv)
#
# Egress note: the throughput profile pulls a few hundred MB from Storj (billable). warp
# DELETES all data in its --bucket — uses a dedicated `warp-bench`, never your real bucket.
#
# Usage:
#   ./demo/warp/run.sh run       # capture each profile (warp drives, s3tap observes)
#   ./demo/warp/run.sh analyze   # warp's numbers + s3tap's kernel view + the doctor
set -euo pipefail

S3TAP=${S3TAP:-./target/release/s3tap}
WARP=${WARP:-$(command -v warp || echo "$HOME/go/bin/warp")}
# Captures land under $HOME, never a fixed /tmp name. /tmp is world-writable and `mkdir -p`
# silently accepts a directory someone else already owns, so a pre-planted /tmp/s3tap-warp
# (or a symlink inside it) would hand an attacker the capture — endpoint IPs, SNI, timings —
# and a root-owned write aimed at a file of their choosing on any sudo-elevated path.
# `run` and `analyze` are separate invocations that must agree on the path, so this is a
# stable location rather than a mktemp -d.
OUT=${OUT:-${XDG_STATE_HOME:-$HOME/.local/state}/s3tap/warp}
mkdir -p "$OUT"; chmod 700 "$OUT"
BUCKET=${BUCKET:-warp-bench}
HOST=${HOST:-gateway.storjshare.io}

# profile = name | warp subcommand + flags. iops = small-object/high-concurrency (cheap,
# the richest connection-layer activity); throughput = fat single-streams (more egress).
PROFILES=(
  "iops|get --obj.size 16KiB --objects 800 --concurrent 64 --duration 15s"
  "throughput|get --obj.size 8MiB --objects 30 --concurrent 12 --duration 10s"
)

need_warp() {
  [ -x "$WARP" ] || { echo "warp not found at '$WARP' — install: go install github.com/minio/warp@latest"; exit 1; }
}

run() {
  need_warp
  local failed=0
  # Creds to warp via env (WARP_*), so the secret never lands on argv (/proc).
  export WARP_ACCESS_KEY WARP_SECRET_KEY WARP_HOST WARP_TLS
  WARP_ACCESS_KEY=$(awk -F' *= *' '/aws_access_key_id/{print $2;exit}' ~/.aws/credentials)
  WARP_SECRET_KEY=$(awk -F' *= *' '/aws_secret_access_key/{print $2;exit}' ~/.aws/credentials)
  WARP_HOST=$HOST WARP_TLS=true
  for p in "${PROFILES[@]}"; do
    IFS='|' read -r name flags <<<"$p"
    echo "########## warp $name ##########"
    # s3tap captures warp's connections (kernel TCP + library-agnostic SNI), scoped by comm.
    # Start it FIRST so the exec tracepoint catches warp; stop it AFTER warp exits so the
    # connection-close records (where the tcp_sock stats are read) are drained.
    # --sample-interval-ms adds the in-flight time series (cwnd/RTT/throughput EVOLUTION,
    # not just the close snapshot); scoped to warp, so no host-wide cost. The doctor's
    # "in-flight over time (sampled)" section in `analyze` reads it — best seen on the
    # throughput profile (fat 8 MiB streams ramp; the iops profile's tiny objects barely do).
    "$S3TAP" --app warp --sample-interval-ms 100 --format jsonl >"$OUT/$name.jsonl" 2>"$OUT/$name.s3err" &
    local sp=$!
    sleep 1
    # Run warp from $OUT so its result .json.zst lands there, not in the repo.
    # Keep warp's exit status instead of `|| true`-ing it away. warp IS the workload: if it
    # never ran (bad creds, missing bucket, a 240 s timeout kill) there is nothing to
    # observe, and `analyze` would go on to print a confident verdict about an empty or
    # truncated capture. The status is recorded rather than allowed to abort under `set -e`,
    # because the agent below must still be stopped and drained (an aborted iteration would
    # orphan it and lose the connection-close records that carry every tcp_sock stat).
    local rc=0
    ( cd "$OUT" && timeout 240 "$WARP" $flags --bucket "$BUCKET" --lookup path ) >"$OUT/$name.warp.txt" 2>&1 || rc=$?
    sleep 2
    kill -INT "$sp" 2>/dev/null || true
    wait "$sp" 2>/dev/null || true
    if [ "$rc" -ne 0 ]; then
      failed=$((failed+1))
      echo "  !! warp exited $rc — this profile's numbers are NOT valid. Its last lines:"
      tail -5 "$OUT/$name.warp.txt" | sed 's/^/     /'
    fi
    echo "  s3tap captured $(grep -c '"s3tap.connection' "$OUT/$name.jsonl") connection record(s)"
  done
  if [ "$failed" -gt 0 ]; then
    echo; echo "$failed of ${#PROFILES[@]} profiles did not complete — re-run before trusting \`analyze\`."
    return 1
  fi
  echo; echo "Now: ./demo/warp/run.sh analyze"
}

analyze() {
  for p in "${PROFILES[@]}"; do
    IFS='|' read -r name _ <<<"$p"
    [ -f "$OUT/$name.jsonl" ] || { echo "no capture for '$name' — run first"; continue; }
    echo "########## $name ##########"
    echo "--- warp's own report (the WHAT, app-level) ---"
    grep -iE "Average:|Reqs:|TTFB:" "$OUT/$name.warp.txt" | grep -vE "Prepar|Clear|Upload" | head -3 | sed 's/^/  /' || true
    echo "--- s3tap's kernel view (the WHY, library-agnostic — Go binary, no OpenSSL) ---"
    python3 - "$OUT/$name.jsonl" "$OUT/$name.warp.txt" <<'PY'
import json, sys, re, statistics as st
cs = [json.loads(l) for l in open(sys.argv[1]) if '"s3tap.connection' in l]
warp = open(sys.argv[2]).read() if len(sys.argv) > 2 else ""
def I(x): return int(x) if x not in (None, "") else 0
def med(g):
    g = [x for x in g if x]
    return st.median(g) if g else None
if not cs:
    print("  (no connections captured)"); sys.exit()
TLS_CIPHERS = {  # the TLS 1.3 suites a Go/aws-sdk-go client offers
    4865: "TLS_AES_128_GCM_SHA256", 4866: "TLS_AES_256_GCM_SHA384",
    4867: "TLS_CHACHA20_POLY1305_SHA256",
}
tlss = [c.get("tls") or {} for c in cs]
snis = {t.get("sni") for t in tlss}
# version + cipher come from the kernel ServerHello parse (ingress) — populated even though
# warp is a Go binary with no libssl to hook. count how many conns carried each.
def tally(vals):
    out = {}
    for v in vals:
        if v: out[v] = out.get(v, 0) + 1
    return out
vers = tally(t.get("version") for t in tlss)
def cipher_label(c):  # name a known suite, else hex (matches the doctor's 0x%04x); skip absent
    return None if not c else TLS_CIPHERS.get(c, f"0x{c:04x}")
ciphs = tally(cipher_label(t.get("cipher")) for t in tlss)  # all-str keys: sortable, no int/str mix
n_ver = sum(vers.values())
mr = med([I(c.get('min_rtt_us'))/1e3 for c in cs]) or 0.0
jit = med([I(c.get('rttvar_us'))/1e3 for c in cs]) or 0.0
sr = med([I(c.get('srtt_us'))/1e3 for c in cs]) or 0.0
rtx = sum(I(c.get("retransmits")) for c in cs)
hot = sum(1 for c in cs if I(c.get("retransmits")) > 0)
# New optional kernel signals (absent on older captures => treat as 0/not-observed).
# rcv_ooopack is THE download-leg signal (GET: bytes_recv >> bytes_sent, so the receive
# path is what matters); bytes_retrans is retransmit VOLUME. dsack_dups + app_limited are
# SEND-path signals — near-dead on a GET, they carry signal on the PUT/upload track, so the
# silence here is expected, not a bug.
# send_heavy mirrors the doctor's gate (lib.rs path_domain) EXACTLY so the two views agree:
# upload-heavy AND big enough to open the send window. dsack_dups + app_limited are send-path
# signals, so they're summed over this subset only (not all conns).
def send_heavy(c): return I(c.get("bytes_sent")) > I(c.get("bytes_recv")) and I(c.get("bytes_sent")) >= 65536
ooo = sum(I(c.get("rcv_ooopack")) for c in cs)            # recv-leg: ALL conns (download signal)
ooo_hot = sum(1 for c in cs if I(c.get("rcv_ooopack")) > 0)
bret = sum(I(c.get("bytes_retrans")) for c in cs)
bsent = sum(I(c.get("bytes_sent")) for c in cs)
dsack = sum(I(c.get("dsack_dups")) for c in cs if send_heavy(c))   # send-leg: send_heavy only
dsack_hot = sum(1 for c in cs if send_heavy(c) and I(c.get("dsack_dups")) > 0)
applim = [c for c in cs if c.get("app_limited") and send_heavy(c)]
# Per-connection srtt/min_rtt inflation (matches the doctor's aggregation).
infl = med([I(c.get('srtt_us'))/I(c.get('min_rtt_us'))
            for c in cs if I(c.get('min_rtt_us')) > 0 and I(c.get('srtt_us')) > 0]) or 1.0
print(f"  connections:        {len(cs)}   SNI decoded from the Go TLS handshake: {snis}")
# THE LIBRARY-AGNOSTIC TLS PROOF: version+cipher off the kernel ServerHello parse — a Go
# binary with no OpenSSL to hook, yet the negotiated handshake is fully visible.
vshow = ", ".join(f"{k} (x{n})" for k, n in sorted(vers.items())) or "none"
cshow = ", ".join(f"{k} (x{n})" for k, n in sorted(ciphs.items())) or "none"
print(f"  TLS negotiated:     version {vshow}   cipher {cshow}   ({n_ver}/{len(cs)} conns; kernel ServerHello, no libssl)")
print(f"  min_rtt (true floor): {mr:.1f} ms   jitter: {jit:.1f} ms   srtt: {sr:.1f} ms   (srtt ~{infl:.1f}x the floor)")
print(f"  retransmits:        {rtx} across {hot}/{len(cs)} conns   "
      f"max reordering: {max([I(c.get('reordering')) for c in cs] or [0])}")
# DOWNLOAD-leg reordering: out-of-order pkts on the RECEIVE path = reorder/loss on the
# leg that actually carries the GET payload. Print clean when none seen (no false alarm).
if ooo > 0:
    print(f"  download reorder:   {ooo} out-of-order pkts across {ooo_hot}/{len(cs)} conns "
          f"(recv-leg; reordering degree can't show this)")
else:
    print(f"  download reorder:   none observed (recv-leg clean across {len(cs)} conns)")
# Retransmit VOLUME — honest companion to the segment-count line above; % of bytes_sent.
if bret > 0 and bsent > 0:
    print(f"  retrans volume:     {bret/1e3:.1f} KB retransmitted ({100*bret/bsent:.2f}% of bytes_sent)")
elif bret > 0:
    print(f"  retrans volume:     {bret/1e3:.1f} KB retransmitted")
else:
    print(f"  retrans volume:     0 B retransmitted (clean send path)")
# SEND-path signals (PUT/upload track, near-dead on a GET) — only printed when they fire.
if dsack > 0:
    print(f"  spurious retrans:   {dsack} DSACK dup(s) across {dsack_hot}/{len(cs)} conns (send-path)")
if applim:
    print(f"  app-limited:        {len(applim)}/{len(cs)} send-heavy conns app-limited (send-path)")
print(f"  egress (bytes_recv): {sum(I(c.get('bytes_recv')) for c in cs)/1e6:.0f} MB   "
      f"(these kernel signals are invisible to warp's own output)")
# THE INSIGHT: pair warp's own p99 tail with the kernel-attributed cause. srtt inflated
# well above the (fixed) min_rtt floor = the path is queueing; if loss isn't pervasive it's
# bufferbloat (self-inflicted by concurrency/window), NOT the provider — something warp's
# app-level numbers can't distinguish.
# warp prints the percentiles WITHOUT a colon after the label:
#   Reqs:  Avg 199.7ms   50% 114.8ms   90% 362.8ms   99% 1333.6ms
# The old pattern required `99%:` and so never matched, leaving p99 at its "?" default —
# which silently gutted the verdict lines below (their whole point is pairing warp's
# app-level tail with the kernel's cause). Accept both spellings (`99%` and `99th`, with an
# optional colon) and both units, since warp switches to seconds once a tail crosses 1 s.
# \b before the 99 so `Avg 199.7ms` can't be mistaken for it.
m = re.search(r'Reqs:.*?\b99(?:%|th)\s*:?\s+([\d.]+)\s*(ms|s)\b', warp)
if m:
    v = float(m.group(1)) * (1000.0 if m.group(2) == "s" else 1.0)
    p99 = f"{v:.1f} ms"
else:
    p99 = "?"
loss_pervasive = hot * 5 > len(cs)  # retransmits spread across most conns => real loss
if infl >= 2.0 and not loss_pervasive:
    print(f"  => BUFFERBLOAT: warp's p99 tail ({p99}) is PATH QUEUEING — srtt inflated {infl:.1f}x the "
          f"{mr:.0f}ms floor with no pervasive loss. Self-inflicted by concurrency/window, not the provider.")
elif infl >= 2.0:
    print(f"  => CONGESTION+LOSS: warp's p99 tail ({p99}) — srtt {infl:.1f}x the floor AND loss on "
          f"{hot}/{len(cs)} conns. The path is genuinely dropping packets under load.")
else:
    print(f"  => PATH STABLE: srtt ~{infl:.1f}x the floor — warp's p99 tail ({p99}) is NOT path queueing "
          f"(look server-side / at object size).")
PY
    echo "--- s3tap doctor (network-path section populates; op rows absent for a Go client) ---"
    # `doctor` exits 1 (ATTENTION) / 2 (NO BASELINE) BY DESIGN — e.g. on the congested
    # throughput profile — and aborting here under `set -e`/`pipefail` would drop every
    # later profile, so those two are verdicts to keep going on. 3 (nothing captured) and 4
    # (tool failure) are NOT verdicts: there is no report at all, and a blanket `|| true`
    # rendered that as a silently empty section. Run it to a file so the status is the
    # doctor's own and not a sed's.
    local drc=0
    "$S3TAP" doctor --from "$OUT/$name.jsonl" >"$OUT/$name.doctor.txt" 2>/dev/null || drc=$?
    if [ "$drc" -le 2 ]; then
      sed -n '/are these/,/verdict/p' "$OUT/$name.doctor.txt" | sed 's/^/  /'
    else
      echo "  !! no report: s3tap doctor exited $drc (3 = nothing captured, 4 = s3tap itself failed)"
    fi
    echo
  done
}

"${1:-run}"
