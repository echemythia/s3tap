#!/usr/bin/env bash
# s3tap provider benchmark: AWS S3 (public, eu-central-1) vs Storj (authenticated),
# with IDENTICAL bytes per size tier. A size ladder isolates the two regimes the doctor
# judges: latency/server-think-time (small objects, TTFB is size-independent) and
# single-stream throughput (large objects). Built on `s3tap doctor --live`, the
# self-driving capture — it drives N keep-alive GETs, captures them via
# eBPF, and judges each span against the connection's RTT floor (srtt).
#
# Prereqs (one-time):
#   cargo build --release -p s3tap
#   UPROBES=1 ./setcap.sh release        # in a real terminal; sudo, grants the eBPF caps
#   ~/.aws/credentials [default] = your Storj S3 keys (the AWS side is public, no creds)
#   NB: `cargo build` wipes the binary's file caps — re-run setcap after every rebuild.
#
# Usage:
#   ./demo/provider-benchmark/run.sh mirror   # one-time: copy the AWS objects into your Storj bucket
#   ./demo/provider-benchmark/run.sh run      # capture + judge every tier on both providers (verdict per run)
#   ./demo/provider-benchmark/run.sh table    # cross-provider TTFB + throughput table from the saved captures
#
# `run` is re-runnable: it rotates each previous capture to <name>.prev before re-capturing,
# so `table` always reads the run you just paid for. It exits non-zero if any tier produced
# no result, because a partial sweep makes the table stale rather than merely shorter.
#
# Egress note: `run` pulls ~650 MB from Storj (billable). The large tier needs only a few
# requests (throughput converges fast); the small tier uses 120 for a p99 tail.
set -euo pipefail

S3TAP=${S3TAP:-./target/release/s3tap}
# Captures land under $HOME, never a fixed /tmp name. /tmp is world-writable and `mkdir -p`
# silently accepts a directory someone else already owns, so a pre-planted /tmp/s3tap-bakeoff
# (or a symlink inside it) would hand an attacker the capture — buckets, endpoint IPs, SNI,
# timings, key hashes — and, since `doctor --live` re-execs under sudo, a root-owned write
# aimed at a file of their choosing. `run` and `table` are separate invocations that must
# agree on the path, so this is a stable location rather than a mktemp -d.
OUT=${OUT:-${XDG_STATE_HOME:-$HOME/.local/state}/s3tap/bakeoff}
mkdir -p "$OUT"; chmod 700 "$OUT"
AWS=https://copernicus-dem-30m.s3.eu-central-1.amazonaws.com   # AWS Open Data, eu-central-1, anonymous
STORJ=https://gateway.storjshare.io
STORJ_HOST=gateway.storjshare.io

# tier = name | aws_key | storj_key | requests | timeout_secs
# ~11 KB -> latency/tail (TTFB is size-independent for a normal store)
# ~1.5 MB -> TCP slow-start transition
# ~38 MB -> sustained single-stream throughput (the only regime where MB/s is a real number)
TIERS=(
  "8k|Copernicus_DSM_COG_10_N00_00_E006_00_DEM/PREVIEW/Copernicus_DSM_10_N00_00_E006_00_SRC.kml|test/bakeoff/t8k.bin|120|40"
  "1m|Copernicus_DSM_COG_10_N00_00_E006_00_DEM/PREVIEW/Copernicus_DSM_10_N00_00_E006_00_DEM_QL.tif|test/bakeoff/t1m.bin|40|60"
  "32m|Copernicus_DSM_COG_10_N28_00_E086_00_DEM/Copernicus_DSM_COG_10_N28_00_E086_00_DEM.tif|test/bakeoff/t32m.bin|16|160"
)

# Copy each public AWS object into your Storj bucket so both providers serve identical
# bytes (the only way the throughput comparison is fair). Idempotent — re-PUT is harmless.
mirror() {
  local AK SK
  AK=$(awk -F' *= *' '/aws_access_key_id/{print $2;exit}' ~/.aws/credentials)
  SK=$(awk -F' *= *' '/aws_secret_access_key/{print $2;exit}' ~/.aws/credentials)
  # cfg is NOT `local`: the EXIT trap runs in global scope, so it must see the path to clean
  # the secret-bearing file even when a `curl -f` failure aborts mirror() under `set -e`.
  cfg=$(mktemp); chmod 600 "$cfg"; trap 'rm -f "$cfg"' EXIT   # secret stays off argv (curl -K config)
  printf 'user = "%s:%s"\naws-sigv4 = "aws:amz:us-east-1:s3"\n' "$AK" "$SK" >"$cfg"
  for t in "${TIERS[@]}"; do IFS='|' read -r n ak sk _ _ <<<"$t"
    curl -fsS --http1.1 --max-time 300 -o "$OUT/$n.bin" "$AWS/$ak"
    curl -fsS --http1.1 --max-time 300 -K "$cfg" -T "$OUT/$n.bin" -o /dev/null "$STORJ/$sk"
    echo "mirrored $n: $(stat -c%s "$OUT/$n.bin") B  sha=$(sha256sum "$OUT/$n.bin" | cut -c1-12)"
  done
  rm -f "$cfg"; trap - EXIT
}

# Move a previous capture aside so `--save` can write. `--save` REFUSES an existing path
# (it never truncates and never follows a symlink, because `--live` re-execs under sudo), so
# without this a second `run` drove every tier's real, billable egress and then died at the
# save with NO verdict for any of them — while `table` went on printing the FIRST run's
# numbers as though they were the second's. Keep one generation rather than deleting: a
# re-run must not silently destroy the capture it replaces.
rotate() { if [ -e "$1" ]; then mv -f -- "$1" "$1.prev"; fi; }

# Run one `doctor --live` tier and stay honest about WHY it exited.
#   0/1/2 are VERDICTS about the capture. 0 healthy, 1 attention, and 2 whenever a
#         denominator is missing: no RTT floor (NO BASELINE), no S3 request decoded
#         (NO OPERATIONS), or requests decoded but none answered (NO RESPONSES). They must
#         not abort the sweep: "attention" is a legitimate answer and the next tier still
#         runs, and a 2 says this tier could not be judged rather than that it failed.
#   3     the workload ran but nothing was captured (usually missing probe caps).
#   4     s3tap never got as far as a verdict (bad invocation, a refused --save, ...).
# 3 and 4 mean this tier HAS no result, so `table` must not be handed the previous run's
# file as if it were this one's. A blanket `|| true` made those indistinguishable from a
# clean pass, which is exactly how the re-run bug stayed invisible.
FAILED=0
probe() {   # <label> <save-path> <s3tap doctor args...>
  local label=$1 save=$2; shift 2
  local rc=0
  "$S3TAP" doctor --live "$@" --save "$save" || rc=$?
  case "$rc" in
    0|1|2) return 0 ;;
    3) echo "  !! $label: the workload ran but NOTHING was captured — no result for this tier" ;;
    *) echo "  !! $label: s3tap failed (exit $rc) — no result for this tier" ;;
  esac
  FAILED=$((FAILED+1))
  return 0
}

# Capture + judge each tier on both providers; the doctor prints its verdict per run.
run() {
  FAILED=0
  for t in "${TIERS[@]}"; do IFS='|' read -r n ak sk rq to <<<"$t"
    rotate "$OUT/aws_$n.jsonl"; rotate "$OUT/storj_$n.jsonl"
    echo; echo "########## $n  —  AWS S3 (public, eu-central-1) ##########"
    probe "aws $n" "$OUT/aws_$n.jsonl" --endpoint "$AWS/$ak" \
      --requests "$rq" --timeout-secs "$to"
    echo; echo "########## $n  —  Storj (authenticated) ##########"
    probe "storj $n" "$OUT/storj_$n.jsonl" --auth --endpoint "$STORJ/$sk" --s3-endpoint "$STORJ_HOST" \
      --requests "$rq" --timeout-secs "$to"
  done
  if [ "$FAILED" -gt 0 ]; then
    echo; echo "$FAILED of $(( ${#TIERS[@]} * 2 )) captures produced no result — the table below them"
    echo "would be incomplete or stale. Fix the cause and re-run before reading \`run.sh table\`."
    return 1
  fi
  echo; echo "all $(( ${#TIERS[@]} * 2 )) captures saved under $OUT — now: ./demo/provider-benchmark/run.sh table"
}

# Side-by-side TTFB + throughput across the sweep, from the saved captures.
table() {
  python3 - "$OUT" <<'PY'
import json, sys, statistics as st
OUT = sys.argv[1]
def summ(p):
    ops = [json.loads(l) for l in open(p) if '"s3tap.operation' in l]
    cn  = [json.loads(l) for l in open(p) if '"s3tap.connection' in l]
    srtts = [c['srtt_us']/1e3 for c in cn if c.get('srtt_us')]   # cn can be non-empty yet all-null srtt
    srtt = st.median(srtts) if srtts else 0.0
    tt   = sorted(o['ttfb_ns']/1e6 for o in ops if o.get('ttfb_ns') and not o['partial'])
    thr  = [o['content_length']/o['download_ns']*1e3 for o in ops
            if o.get('download_ns') and o.get('content_length')]   # MB/s
    p50  = tt[len(tt)//2] if tt else 0.0
    return srtt, p50, (st.median(thr) if thr else None)
print(f"{'tier':<6}{'prov':<7}{'srtt':>7}{'TTFB p50':>10}{'think':>8}{'MB/s*':>9}")
for n in ("8k", "1m", "32m"):
    for prov in ("aws", "storj"):
        try:
            s, p, thr = summ(f"{OUT}/{prov}_{n}.jsonl")
        except FileNotFoundError:
            print(f"{n:<6}{prov:<7}  (no capture — run first)"); continue
        print(f"{n:<6}{prov:<7}{s:>6.1f} {p:>9.1f}{p-s:>7.1f} {('%.1f'%thr) if thr else '—':>8}")
print("* MB/s is single-stream goodput (RTT-bound); only meaningful at the 32m tier.")
PY
}

"${1:-run}"
