#!/usr/bin/env bash
#
# s3tap demo — observe real S3 traffic with eBPF, with ZERO changes to the client.
#
# Drives normal S3 workloads against an S3-compatible bucket while s3tap watches from
# the kernel — the clients (curl, a stdlib-Python client) are never modified, and
# s3tap is in neither's code path. Sections:
#
#   1. selftest        — a one-shot pipeline health check (DNS/TCP/TLS/HTTP)
#   2. waterfall        — a per-operation latency timeline (the headline view)
#   3. structured jsonl — the stable public schema (connection/2 + operation/1)
#   4. library-agnostic — curl AND python decoded identically (different TLS libs)
#   5. failures         — 404 / 403 / refused connect surfaced, not just happy paths
#   6. table view       — one row per op + byte counters (a 1 MiB transfer)
#   7. per-app scope    — in-kernel filtering: only the target app is captured
#   8. analytics        — are the profiled values good/expected? (judged vs RTT)
#
# The probes are library-agnostic: SNI is parsed from the TLS ClientHello, and the
# HTTP path hooks OpenSSL (classic SSL_write/read AND the SSL_*_ex variants modern
# clients like Python/boto3 use). Go/rustls clients still get connection + SNI.
#
# Credentials: reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the environment,
# or falls back to the newest ~/Documents/Storj-S3-Credentials*.txt. The demo never
# prints the secret, and s3tap records carry only a sha256 of the object key — never
# the key itself, never the SigV4 credential.
#
# Config via env (defaults target a Storj S3 gateway test bucket):
#   S3TAP    path to the s3tap binary (default: the repo's target/release build)
#   S3TAP_DEMO_ENDPOINT (default https://gateway.storjshare.io)
#   S3TAP_DEMO_BUCKET   (default test)
#   S3TAP_DEMO_REGION   (default us-east-1)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # demo/s3tap/ -> repo root
# S3TAP= lets you point the demo at a ROOT-OWNED install (e.g. /usr/local/bin/s3tap), which
# is the only target `sudo s3tap setup` / setcap.sh will cap without the insecure opt-out.
# Without it the demo could only ever run against the build tree, which is why its README
# had to recommend S3TAP_SETCAP_INSECURE=1. Same knob as demo/warp and demo/provider-benchmark.
S3TAP="${S3TAP:-$REPO/target/release/s3tap}"
BIN="$S3TAP"
ENDPOINT="${S3TAP_DEMO_ENDPOINT:-https://gateway.storjshare.io}"
BUCKET="${S3TAP_DEMO_BUCKET:-test}"
REGION="${S3TAP_DEMO_REGION:-us-east-1}"
HOST="${ENDPOINT#http://}"; HOST="${HOST#https://}"; HOST="${HOST%%/*}"  # bare host for --s3-endpoint

bold() { printf '\033[1;36m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
rule() { printf '\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────────────────"; }

# ---------------------------------------------------------------- preflight ---
[ -x "$BIN" ] || { echo "no s3tap at '$BIN'. Build it (cd '$REPO' && cargo build --release), or point the demo at an installed copy with S3TAP=/usr/local/bin/s3tap"; exit 1; }
# Root already holds every capability, so the FILE capability only matters for an
# unprivileged run. Gating on `getcap` alone refused the demo under sudo, in a
# container and in a VM — the environments where it is easiest to run — while the
# agent itself gets this right (`elevate::lacking` short-circuits on euid 0).
if [ "$(id -u)" -ne 0 ] && ! getcap "$BIN" 2>/dev/null | grep -q cap_sys_admin; then
  # Check cap_sys_admin specifically: the demo uses --capture-plaintext everywhere, whose
  # uprobes need it. A plain `./setcap.sh` (base caps: cap_bpf/perfmon/dac_read_search, no
  # cap_sys_admin) would pass a cap_bpf check yet capture NOTHING at the L7 layer.
  echo "s3tap needs file capabilities to run without sudo (caps live on the binary"
  echo "inode, so re-run this after every 'cargo build'). Grant them once (needs sudo):"
  echo
  echo "    sudo install -m 0755 '$BIN' /usr/local/bin/s3tap"
  echo "    sudo s3tap setup --uprobes"
  echo "    S3TAP=/usr/local/bin/s3tap $0"
  echo
  echo "or, on a single-user dev box, cap the build tree in place:"
  echo
  echo "    UPROBES=1 S3TAP_SETCAP_INSECURE=1 '$REPO/setcap.sh'"
  echo
  echo "UPROBES=1 / --uprobes is required here: the demo uses --capture-plaintext, whose"
  echo "OpenSSL uprobes need cap_sys_admin. Note a file capability is available to every"
  echo "user who can execute the binary, so on a shared host restrict the execute bit too."
  exit 1
fi

# ------------------------------------------------------------------- creds ---
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  CF=$(ls -t "$HOME"/Documents/Storj-S3-Credentials*.txt 2>/dev/null | head -1 || true)
  if [ -n "$CF" ]; then
    # `|| true`: a creds file that lacks these labels must fall through to the friendly
    # "no credentials" message below, not abort here under `set -e`/`pipefail` (grep exits 1).
    AWS_ACCESS_KEY_ID=$(grep -iA1 'access key' "$CF" | tail -1 | tr -d '[:space:]' || true)
    AWS_SECRET_ACCESS_KEY=$(grep -iA1 'secret key' "$CF" | tail -1 | tr -d '[:space:]' || true)
  fi
fi
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  echo "no credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (any"
  echo "S3-compatible keys), or drop a Storj credentials file in ~/Documents."
  exit 1
fi
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

TMP=$(mktemp -d)
AGENT=""
cleanup() { [ -n "$AGENT" ] && kill -INT "$AGENT" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

# Keep the secret OUT of curl's argv: /proc/<pid>/cmdline is world-readable, so `--user
# AK:SK` would expose the key to any local user for each curl's lifetime. Pass it via a 0600
# curl config file inside $TMP (itself 0700 + trap-cleaned) instead. (--aws-sigv4 is not a
# secret and stays on argv.)
CURLCFG="$TMP/curl.cfg"; touch "$CURLCFG"; chmod 600 "$CURLCFG"
printf 'user = "%s:%s"\n' "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" > "$CURLCFG"
SIG=(--aws-sigv4 "aws:amz:$REGION:s3" -K "$CURLCFG")

# The demo's default capture scope. --capture-plaintext attaches SSL_write/SSL_read uprobes
# HOST-WIDE, so an unscoped run folds any co-tenant process's DECRYPTED S3 traffic into a
# capture this script then prints to the terminal — a third party's buckets and keys riding
# along in a pasted transcript. Every start_agent therefore runs scoped, either to the
# caller's own scope or to this one. --exe rather than --app because the demo drives its own
# two clients and can name their exact binaries, which no other process can claim (--app
# matches a basename, and a local user can put their own `curl` on a path).
SCOPE=()
for c in curl python3; do
  p="$(command -v "$c" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    # Resolve symlinks: --exe is matched against /proc/<pid>/exe, which is already the
    # real binary (/usr/bin/python3 -> python3.12), so an unresolved path never matches.
    p="$(readlink -f -- "$p" 2>/dev/null || echo "$p")"
    SCOPE+=(--exe "$p")
  fi
done
[ ${#SCOPE[@]} -gt 0 ] || { echo "neither curl nor python3 found; this demo drives both."; exit 1; }

start_agent() { # <format> <extra s3tap args...>
  local fmt="$1"; shift
  # A caller that names its own scope (the --app sections) keeps it; scopes are an
  # allowlist union, so adding the default to those would defeat what they demonstrate.
  local a scoped=0
  for a in "$@"; do
    case "$a" in --app | --exe | --pid | --cgroup | --container) scoped=1 ;; esac
  done
  (( scoped )) || set -- "$@" "${SCOPE[@]}"
  # --s3-endpoint tells s3tap this (non-AWS) host is an S3 endpoint, so it resolves
  # the bucket from the request path (Storj/MinIO/R2/… are path-style by default).
  "$BIN" --capture-plaintext --s3-endpoint "$HOST" --format "$fmt" "$@" >"$TMP/out" 2>"$TMP/err" &
  AGENT=$!
  sleep 2.5   # let the probes attach before we generate traffic
}
stop_agent() { kill -INT "$AGENT" 2>/dev/null || true; wait "$AGENT" 2>/dev/null || true; AGENT=""; }

# A realistic S3 workload, all over plain HTTPS curl. The triple-GET in one curl
# invocation reuses a single TCP connection — so s3tap reports req_seq 0/1/2 with
# connection_reused on the later two.
workload() {
  curl -s "${SIG[@]}" -o /dev/null "$ENDPOINT/$BUCKET?list-type=2"                      # ListObjectsV2
  curl -s "${SIG[@]}" -o "$TMP/a" -o "$TMP/b" -o "$TMP/c" \
       "$ENDPOINT/$BUCKET/docs/hello.txt" \
       "$ENDPOINT/$BUCKET/data/config.json" \
       "$ENDPOINT/$BUCKET/docs/readme.md"                                               # 3× GetObject, one conn
  curl -s "${SIG[@]}" -o /dev/null "$ENDPOINT/$BUCKET/data/sample.bin"                  # GetObject (64 KiB)
  curl -s "${SIG[@]}" -o /dev/null -I "$ENDPOINT/$BUCKET/data/config.json"             # HeadObject
  echo "uploaded by s3tap-demo at $(date -u +%FT%TZ)" > "$TMP/up.txt"
  curl -s "${SIG[@]}" -o /dev/null -T "$TMP/up.txt" "$ENDPOINT/$BUCKET/demo/_demo_upload.txt"   # PutObject
  curl -s "${SIG[@]}" -o /dev/null -X DELETE "$ENDPOINT/$BUCKET/demo/_demo_upload.txt"          # DeleteObject (cleanup)
}

clear || true
bold "s3tap demo"
dim  "endpoint=$ENDPOINT  bucket=$BUCKET  region=$REGION"
dim  "clients are plain curl + python — s3tap is in neither's path; it watches from the kernel."

# --- 1. selftest -------------------------------------------------------------
echo; rule; bold "1) selftest — prove the pipeline works on this host"; rule
"$BIN" selftest --endpoint "$ENDPOINT" --requests 2 || true

# --- 2. waterfall ------------------------------------------------------------
echo; rule; bold "2) waterfall — a per-operation latency timeline"; rule
dim "generating S3 traffic (list, get×3 on one connection, get 64KiB, head, put, delete)…"
start_agent waterfall
workload
stop_agent
cat "$TMP/out"

# --- 3. structured schema ----------------------------------------------------
echo; rule; bold "3) structured records — the stable public schema (jsonl)"; rule
dim "the same events as machine-readable s3tap.operation/1 (one shown, key is hashed):"
start_agent jsonl
workload
stop_agent
grep '"schema":"s3tap.operation' "$TMP/out" | head -1 | python3 -m json.tool 2>/dev/null \
  || grep '"schema":"s3tap.operation' "$TMP/out" | head -1 || true   # empty capture must not abort the demo
echo
dim "operations captured this run:"
grep '"schema":"s3tap.operation' "$TMP/out" | python3 -c '
import sys,json
for l in sys.stdin:
    d=json.loads(l)
    print("  %-13s req_seq=%s reused=%-5s status=%s ttfb=%5.1fms key=%s" % (
        d["s3_op"], d["req_seq"], str(d["connection_reused"]),
        d["http_status"], (d["ttfb_ns"] or 0)/1e6, (d["key_hash"] or "")[:19]+"…"))' 2>/dev/null || true

# --- 4. library-agnostic -----------------------------------------------------
echo; rule; bold "4) library-agnostic — curl AND python, decoded identically"; rule
dim "the same GetObject over two different runtimes: curl (OpenSSL classic SSL_write/read)"
dim "and a stdlib-Python client (OpenSSL 3 SSL_*_ex). s3tap is in neither's code path."
start_agent jsonl --app curl --app python3
curl -s "${SIG[@]}" -o /dev/null "$ENDPOINT/$BUCKET/docs/hello.txt"
# Keep the python client's status. A bare `|| true` hid a client that never made a request,
# and this section's whole claim is "two pids, two TLS libraries, one decode" — with one of
# the two silently absent, the missing row reads as an s3tap decode gap instead of a driver
# that failed.
PYRC=0
python3 "$REPO/demo/s3get.py" "$ENDPOINT" "$BUCKET" docs/hello.txt >"$TMP/s3get.log" 2>&1 || PYRC=$?
stop_agent
[ "$PYRC" -eq 0 ] || { dim "note: the python client exited $PYRC, so only curl drove traffic here:"; sed 's/^/      /' "$TMP/s3get.log" | tail -3; }
grep '"schema":"s3tap.operation' "$TMP/out" | python3 -c '
import sys,json
for l in sys.stdin:
    d=json.loads(l)
    print("  pid=%-7s %-6s %-11s bucket=%s status=%s ttfb=%5.1fms" % (
        d["app"]["pid"], d["verb"], d["s3_op"], d["bucket"], d["http_status"], (d["ttfb_ns"] or 0)/1e6))' 2>/dev/null || true
dim "two pids, two TLS libraries, one decode (boto3/aws-cli use this same Python/OpenSSL"
dim "path). Go/rustls clients still get connection + SNI; L7 plaintext needs OpenSSL."

# --- 5. failure scenarios ----------------------------------------------------
echo; rule; bold "5) failures — s3tap surfaces problems, not just happy paths"; rule
dim "a missing key (404), an unsigned request (403 denied), and a refused connect."
start_agent jsonl --app curl
curl -s "${SIG[@]}" -o /dev/null "$ENDPOINT/$BUCKET/does/not-exist.txt"           # 404
curl -s            -o /dev/null "$ENDPOINT/$BUCKET/docs/hello.txt"                # unsigned -> 403
curl -s -o /dev/null --connect-timeout 3 "$ENDPOINT:81/$BUCKET/x" 2>/dev/null || true   # connect refused
stop_agent
dim "operations (the error status is captured, not just success):"
grep '"schema":"s3tap.operation' "$TMP/out" | python3 -c '
import sys,json
for l in sys.stdin:
    d=json.loads(l); print("  %-11s status=%s  %s"%(d["s3_op"],d["http_status"],"ok" if d["http_status"]<400 else "<-- error"))' 2>/dev/null || true
dim "connections (a refused connect is flagged; no bytes ever flowed):"
grep '"schema":"s3tap.connection' "$TMP/out" | python3 -c '
import sys,json
for l in sys.stdin:
    d=json.loads(l)
    if d["connect_failed"]:
        print("  connect_failed=true  ip=%s:%s  (SYN sent, never established)"%(
            d.get("endpoint",{}).get("endpoint_ip"), d.get("endpoint",{}).get("dport")))' 2>/dev/null || true

# --- 6. table view + a large transfer ----------------------------------------
echo; rule; bold "6) table view + byte counters"; rule
dim "the --format table scanning view — one fixed-width row per op:"
start_agent table
workload
stop_agent
cat "$TMP/out"
echo
dim "and a 1 MiB GET: the OPERATION reports head bytes; its CONNECTION carries the full transfer + srtt:"
head -c 1048576 /dev/urandom > "$TMP/big.bin"
start_agent jsonl
curl -s "${SIG[@]}" -o /dev/null -T "$TMP/big.bin" "$ENDPOINT/$BUCKET/demo/_big.bin"   # PutObject 1 MiB
curl -s "${SIG[@]}" -o /dev/null "$ENDPOINT/$BUCKET/demo/_big.bin"                      # GetObject 1 MiB
curl -s "${SIG[@]}" -o /dev/null -X DELETE "$ENDPOINT/$BUCKET/demo/_big.bin"            # cleanup
stop_agent
python3 -c '
import sys,json
ops=[]; conns=[]
for l in open(sys.argv[1]):
    d=json.loads(l)
    (ops if d["schema"].startswith("s3tap.operation") else conns).append(d)
g=[o for o in ops if o["s3_op"]=="GetObject"]
if g: print("  operation  GetObject   op_bytes_recv=%s B  (HTTP head only — not object size)"%g[-1]["op_bytes_recv"])
if conns:
    c=max(conns,key=lambda d:d["bytes_recv"])
    print("  connection             bytes_sent=%s  bytes_recv=%s  srtt=%.1fms  (the full 1 MiB transfer)"%(
        c["bytes_sent"], c["bytes_recv"], (c["srtt_us"] or 0)/1000))' "$TMP/out" 2>/dev/null || true

# --- 7. per-app scope --------------------------------------------------------
echo; rule; bold "7) per-app scope — in-kernel filtering"; rule
dim "scoped to --app curl: a python3 client to the SAME endpoint is dropped in the"
dim "kernel, before its data ever reaches userspace."
start_agent jsonl --app curl
python3 "$REPO/demo/s3get.py" "$ENDPOINT" "$BUCKET" docs/hello.txt >"$TMP/s3get7.log" 2>&1 & PYPID=$!
# Keep the client's status: "0 python records" only proves in-kernel filtering if the python
# client actually issued a request. A client that died on startup produces the same 0 and
# would let this section claim a filter that was never exercised.
PYRC=0; wait "$PYPID" || PYRC=$?
curl -s "${SIG[@]}" -o /dev/null "$ENDPOINT/$BUCKET/docs/hello.txt"
stop_agent
total=$(grep -c '"schema"' "$TMP/out" 2>/dev/null || true)
pyhit=$(grep -c "\"pid\":$PYPID\b" "$TMP/out" 2>/dev/null || true)
printf '  records captured            : %s (curl)\n' "${total:-0}"
if [ "$PYRC" -eq 0 ]; then
  printf '  python3 (pid %s) records  : %s  ← dropped in-kernel by --app curl\n' "$PYPID" "${pyhit:-0}"
else
  printf '  python3 (pid %s) records  : %s  — but the python client exited %s, so this run does\n' "$PYPID" "${pyhit:-0}" "$PYRC"
  printf '  %s\n' "not demonstrate the filter. Its output:"
  sed 's/^/      /' "$TMP/s3get7.log" | tail -3
fi

# --- 8. analytics ------------------------------------------------------------
echo; rule; bold "8) analytics — are the profiled values good/expected?"; rule
dim "s3tap profiles the numbers; this judges them. Each latency is compared to the"
dim "connection's srtt (the network round-trip floor), so the verdicts hold at any"
dim "distance from the endpoint — a TTFB of 'a few × RTT' is healthy, not a raw number."
start_agent jsonl
workload
stop_agent
grep '"schema"' "$TMP/out" | python3 "$REPO/demo/s3stats.py" 2>/dev/null || true

echo; rule; bold "done."
dim "try it live:  $BIN                       # waterfall on a tty"
dim "             $BIN --format table         # one row per op"
dim "scope it:     $BIN --app <name>|--pid <pid>|--cgroup <id>"
dim "S3-compatible: add --s3-endpoint <host> for bucket/key resolution"
