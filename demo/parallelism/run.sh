#!/usr/bin/env bash
#
# s3tap parallelism demo — turn a vague "my downloads feel slow" into a specific,
# quantified fix, and then PROVE the fix works. All against a PUBLIC bucket, so
# there are no credentials to set up.
#
# The story, in one screen:
#
#   1. Download N objects ONE CONNECTION AT A TIME (serial). s3tap, watching from
#      the kernel with zero changes to the client, sees every GetObject and the
#      advisor fires `advisor-serial-requests`: "issued strictly one at a time …
#      over K parallel connections cuts the transfer time roughly K times."
#   2. Download the SAME objects over K parallel connections. The advisor goes
#      silent — the opportunity is gone — and the wall clock drops ~K×.
#
# So the demo closes the full loop: s3tap spots the missed parallelism, tells you
# what to do, and the after-run measures the payoff. The check it exercises lives
# in crates/s3tap-advisor/src/checks/parallelism.rs; it fires (per pid) only with
# >= 50 clean-timed GETs, >= 10 s of busy transfer, and < 5% of that time spent at
# concurrency >= 2 — so the driver is sized to clear those gates on the serial run
# and to blow past the overlap ceiling on the parallel run.
#
# The client is PURE Python stdlib (urllib, no boto3, no awscli): a
# ThreadPoolExecutor with 1 worker for the serial pass and K workers for the
# parallel pass, doing anonymous HTTPS GETs against the public bucket (a public
# object needs no signing — the SDK equivalent of --no-sign-request). s3tap is in
# neither the client's nor the kernel's way of the object — it just reads the
# plaintext off the OpenSSL uprobes. Records carry only a sha256 of the key, never
# the key or any credential.
#
# Config via env (defaults target the public AWS Open Data `sentinel-cogs` bucket):
#   S3TAP    path to the s3tap binary (default: the repo's target/release build)
#   S3TAP_DEMO_BUCKET   (default sentinel-cogs)
#   S3TAP_DEMO_REGION   (default us-west-2)
#   S3TAP_DEMO_PREFIX   (default sentinel-s2-l2a-cogs/1/C/CV/2018/)
#   S3TAP_DEMO_N        (default 60   — objects to download each pass; must clear the >=50 gate)
#   S3TAP_DEMO_PAR      (default 10   — parallel connections in the fast pass)
#   S3TAP_DEMO_MIN_MB   (default 1    — skip tiny sidecar files so the transfer is real)
#   S3TAP_DEMO_MAX_MB   (default 0    — optional upper size cap; 0 = none. Bounds the download.)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # demo/parallelism/ -> repo root
# S3TAP= lets you point the demo at a ROOT-OWNED install (e.g. /usr/local/bin/s3tap), which
# is the only target `sudo s3tap setup` / setcap.sh will cap without the insecure opt-out.
# Without it the demo could only ever run against the build tree, which is why its README
# had to recommend S3TAP_SETCAP_INSECURE=1. Same knob as demo/warp and demo/provider-benchmark.
S3TAP="${S3TAP:-$REPO/target/release/s3tap}"
BIN="$S3TAP"
BUCKET="${S3TAP_DEMO_BUCKET:-sentinel-cogs}"
REGION="${S3TAP_DEMO_REGION:-us-west-2}"
PREFIX="${S3TAP_DEMO_PREFIX:-sentinel-s2-l2a-cogs/1/C/CV/2018/}"
N="${S3TAP_DEMO_N:-60}"
PAR="${S3TAP_DEMO_PAR:-10}"
MIN_MB="${S3TAP_DEMO_MIN_MB:-1}"
MAX_MB="${S3TAP_DEMO_MAX_MB:-0}"

bold() { printf '\033[1;36m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
grn()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[1;33m%s\033[0m\n' "$*"; }
rule() { printf '\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────────────────"; }

# ---------------------------------------------------------------- preflight ---
[ -x "$BIN" ] || { echo "no s3tap at '$BIN'. Build it (cd '$REPO' && cargo build --release), or point the demo at an installed copy with S3TAP=/usr/local/bin/s3tap"; exit 1; }
# --capture-plaintext hooks OpenSSL, whose uprobes need cap_sys_admin. Caps live on
# the binary inode, so this must be re-run after every 'cargo build'.
# Root already holds every capability, so the FILE capability only matters for an
# unprivileged run. Gating on `getcap` alone refused the demo under sudo, in a
# container and in a VM — the environments where it is easiest to run — while the
# agent itself gets this right (`elevate::lacking` short-circuits on euid 0).
if [ "$(id -u)" -ne 0 ] && ! getcap "$BIN" 2>/dev/null | grep -q cap_sys_admin; then
  echo "s3tap needs the UPROBE capabilities to read the HTTP layer (the advisor works"
  echo "off L7 GetObject records, which only exist on the --capture-plaintext path)."
  echo "Caps live on the binary inode — re-run after every rebuild. Grant them once:"
  echo
  echo "    sudo install -m 0755 '$BIN' /usr/local/bin/s3tap"
  echo "    sudo s3tap setup --uprobes"
  echo "    S3TAP=/usr/local/bin/s3tap $0"
  echo
  echo "or, on a single-user dev box, cap the build tree in place:"
  echo
  echo "    UPROBES=1 S3TAP_SETCAP_INSECURE=1 '$REPO/setcap.sh'"
  echo
  echo "Note a file capability is available to every user who can execute the binary, so"
  echo "on a shared host restrict the execute bit too (see SECURITY.md)."
  exit 1
fi
command -v python3 >/dev/null || { echo "this demo drives the workload with python3 (stdlib only)."; exit 1; }

TMP=$(mktemp -d)
AGENT=""
cleanup() { [ -n "$AGENT" ] && kill -INT "$AGENT" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

# ---------------------------------------------------- stdlib urllib driver ---
# One process (one pid, as the per-pid concurrency check expects); `mode` picks the
# worker count. Anonymous HTTPS GETs against the public bucket — no signing, no SDK.
# Each worker thread holds ONE keep-alive connection and reuses it (like a real SDK
# session), so the ONLY variable between the passes is concurrency: 1 worker => one
# connection, strictly serial; K workers => K connections, K-wide overlap. (Keep-alive
# also keeps `advisor-connection-churn` out of it, so the demo isolates the parallelism
# axis rather than also flagging fresh-connection-per-request.) Streams each body to
# /dev/null so the transfer time is real. Prints wall-clock seconds to stdout; progress
# to stderr.
cat > "$TMP/driver.py" <<'PY'
import os, sys, time, threading, re, html, http.client
import urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor

mode    = sys.argv[1]                       # "serial" | "parallel"
bucket  = os.environ["DEMO_BUCKET"]
region  = os.environ["DEMO_REGION"]
prefix  = os.environ["DEMO_PREFIX"]
n       = int(os.environ["DEMO_N"])
par     = int(os.environ["DEMO_PAR"])
min_b   = int(os.environ["DEMO_MIN_MB"]) * (1 << 20)
max_b   = int(os.environ.get("DEMO_MAX_MB", "0")) * (1 << 20)   # 0 => no upper cap
workers = 1 if mode == "serial" else par

host = f"https://{bucket}.s3.{region}.amazonaws.com"

def list_keys(want):
    # Anonymous ListObjectsV2 on a public bucket returns XML; paginate to `want` keys
    # whose Size >= min_b (skip tiny sidecar files so the transfer time is meaningful).
    keys, token = [], None
    while len(keys) < want:
        q = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
        if token:
            q["continuation-token"] = token
        url = host + "/?" + urllib.parse.urlencode(q)
        for attempt in (1, 2):   # retry a transient list hiccup instead of aborting the demo
            try:
                xml = urllib.request.urlopen(url, timeout=20).read().decode()
                break
            except Exception:
                if attempt == 2:
                    raise
        for block in re.findall(r"<Contents>(.*?)</Contents>", xml, re.S):
            k = re.search(r"<Key>(.*?)</Key>", block, re.S)
            s = re.search(r"<Size>(\d+)</Size>", block)
            if k and s and int(s.group(1)) >= min_b and (max_b == 0 or int(s.group(1)) <= max_b):
                keys.append(html.unescape(k.group(1)))
                if len(keys) >= want:
                    break
        t = re.search(r"<NextContinuationToken>(.*?)</NextContinuationToken>", xml, re.S)
        if not (t and "<IsTruncated>true</IsTruncated>" in xml):
            break
        token = html.unescape(t.group(1))
    return keys

keys = list_keys(n)
if len(keys) < n:
    sys.stderr.write(f"only found {len(keys)} objects >= {min_b} B under {prefix}; "
                     f"lower S3TAP_DEMO_MIN_MB or widen S3TAP_DEMO_PREFIX\n")
    if not keys:
        sys.exit(2)

endpoint = f"{bucket}.s3.{region}.amazonaws.com"
tls = threading.local()   # one persistent (keep-alive) connection per worker thread
def conn():
    c = getattr(tls, "c", None)
    if c is None:
        c = http.client.HTTPSConnection(endpoint, timeout=60)
        tls.c = c
    return c

done = [0]
fail = [0]
lock = threading.Lock()
def fetch(k):
    path = "/" + urllib.parse.quote(k)
    for attempt in (1, 2):        # one retry on a dropped connection or transient error
        try:
            c = conn()
            c.request("GET", path)
            r = c.getresponse()
            status = r.status
            while r.read(1 << 20):  # MUST fully drain to reuse the connection
                pass
            if status != 200:      # a 4xx/5xx body is NOT a real download — don't count it
                raise OSError(f"HTTP {status}")
            break
        except Exception:
            try: tls.c.close()
            except Exception: pass
            tls.c = None
            if attempt == 2:       # give up on THIS object, but never abort the whole run:
                with lock:         # a single flaky/forbidden key shouldn't kill the demo
                    fail[0] += 1
                return
    with lock:
        done[0] += 1
        sys.stderr.write(f"\r  {mode}: {done[0]}/{len(keys)} objects")
        sys.stderr.flush()

t0 = time.monotonic()
with ThreadPoolExecutor(max_workers=workers) as pool:
    list(pool.map(fetch, keys))
elapsed = time.monotonic() - t0
sys.stderr.write("\n")
if fail[0]:  # surface failures — else a run full of 403/404/503 looks like a fast success
    sys.stderr.write(f"  WARNING: {fail[0]}/{len(keys)} objects failed after retries "
                     f"(their attempts ARE still in the wall-clock below; the finding may "
                     f"not fire — check the bucket/prefix/region)\n")
print(f"{elapsed:.2f}")       # stdout: the wall-clock the shell reads
PY

export DEMO_BUCKET="$BUCKET" DEMO_REGION="$REGION" DEMO_PREFIX="$PREFIX" \
       DEMO_N="$N" DEMO_PAR="$PAR" DEMO_MIN_MB="$MIN_MB" DEMO_MAX_MB="$MAX_MB"

# s3tap capture, scoped to the python driver process only (--app python3). Start it, give
# the uprobes a moment to attach, run the pass, then settle + SIGINT + drain. $1 = out file.
# The pre-SIGINT sleep lets the agent drain the last events off the ring buffer so a run
# near the op-count floor doesn't lose its tail.
start_agent() { "$BIN" --capture-plaintext --app python3 --format jsonl >"$1" 2>"$TMP/agent.err" & AGENT=$!; sleep 2.5; }
stop_agent()  { sleep 1; kill -INT "$AGENT" 2>/dev/null || true; wait "$AGENT" 2>/dev/null || true; AGENT=""; }

clear || true
bold "s3tap parallelism demo"
dim  "bucket=$BUCKET  region=$REGION  prefix=$PREFIX"
dim  "public bucket, no credentials (anonymous HTTPS GETs); s3tap watches from the kernel."
dim  "downloading $N objects (>= ${MIN_MB} MB each) per pass: serial (1 conn) then parallel ($PAR conns)."

# --- pass 1: serial ----------------------------------------------------------
echo; rule; bold "1) SERIAL — one connection at a time"; rule
start_agent "$TMP/serial.jsonl"
SERIAL_S=$(python3 "$TMP/driver.py" serial)
stop_agent
dim "s3tap captured $(grep -c '"schema":"s3tap.operation' "$TMP/serial.jsonl" 2>/dev/null || true) operations; the advisor's read:"
echo
"$BIN" advise --from "$TMP/serial.jsonl" || true

# --- pass 2: parallel --------------------------------------------------------
echo; rule; bold "2) PARALLEL — the same $N objects over $PAR connections"; rule
start_agent "$TMP/parallel.jsonl"
PARALLEL_S=$(python3 "$TMP/driver.py" parallel)
stop_agent
dim "the same advisor, same workload, now spread across $PAR connections:"
echo
"$BIN" advise --from "$TMP/parallel.jsonl" || true

# --- the payoff --------------------------------------------------------------
echo; rule; bold "3) THE PAYOFF — s3tap flagged it; following the advice measured the win"; rule
# Count ONLY the real Advisory firing. The check emits TWO findings that share the id
# `advisor-serial-requests`: the actual verdict (severity "advisory") AND an "unjudgeable"
# variant (severity "unjudged", when >20% of ops lack clean timing). Matching the id alone
# would print the success banner even when the advisor said it COULDN'T judge — so require
# the advisory severity on the same NDJSON line.
FIRED=$("$BIN" advise --from "$TMP/serial.jsonl" --json 2>/dev/null \
  | grep 'advisor-serial-requests' | grep -c '"severity":"advisory"' || true)
SPEEDUP=$(python3 -c "s=$SERIAL_S; p=$PARALLEL_S; print(f'{s/p:.1f}' if p>0 else 'n/a')")
printf '  %-28s %s\n' "serial   (1 connection):" "$(ylw "${SERIAL_S}s")"
printf '  %-28s %s\n' "parallel ($PAR connections):" "$(grn "${PARALLEL_S}s")"
printf '  %-28s %s\n' "speedup:" "$(grn "${SPEEDUP}×")"
echo
if [ "${FIRED:-0}" -ge 1 ]; then
  grn "s3tap called the serial run out BEFORE you touched a stopwatch, and the parallel"
  grn "run confirmed the estimate — a diagnosis you can act on, not just a number."
else
  ylw "NOTE: the serial pass did not trip advisor-serial-requests this run. Either fewer"
  ylw "than 50 objects cleared the size filter (see any 'only found N objects' line above —"
  ylw "lower S3TAP_DEMO_MIN_MB or widen S3TAP_DEMO_PREFIX), or the transfer stayed under the"
  ylw ">= 10 s busy floor on a fast link (bump S3TAP_DEMO_N / point at larger objects). Then"
  ylw "re-run. (Thresholds: crates/s3tap-advisor/src/checks/parallelism.rs.)"
fi
echo
