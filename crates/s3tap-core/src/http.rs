// crates/s3tap-core/src/http.rs
//
// Parse the captured HTTP message HEAD and classify S3 operations (E5). PURE: the
// input is the bounded plaintext prefix the kernel captured (EvtTlsData::captured(),
// i.e. data[..captured_len]) — a request line + headers, or a status line + headers.
// No kernel dependency; no allocation in the parse path (borrows from the input).
//
// The capture is gated to message HEADS in-kernel (see s3tap.bpf.c), so a request
// buffer begins with the method and a response buffer begins with "HTTP/1." — we
// don't need to find a message boundary, just parse from offset 0.

/// The S3 operation resolved from method + path + query (taxonomy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Op {
    GetObject,
    PutObject,
    HeadObject,
    DeleteObject,
    DeleteObjects,
    ListObjectsV2,
    ListObjects,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    CreateSession,
    /// Method/shape not in the taxonomy — the raw verb is retained on the record.
    Unknown,
}

impl S3Op {
    /// The wire name used in the `s3_op` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            S3Op::GetObject => "GetObject",
            S3Op::PutObject => "PutObject",
            S3Op::HeadObject => "HeadObject",
            S3Op::DeleteObject => "DeleteObject",
            S3Op::DeleteObjects => "DeleteObjects",
            S3Op::ListObjectsV2 => "ListObjectsV2",
            S3Op::ListObjects => "ListObjects",
            S3Op::CreateMultipartUpload => "CreateMultipartUpload",
            S3Op::UploadPart => "UploadPart",
            S3Op::CompleteMultipartUpload => "CompleteMultipartUpload",
            S3Op::AbortMultipartUpload => "AbortMultipartUpload",
            S3Op::CreateSession => "CreateSession",
            S3Op::Unknown => "UNKNOWN",
        }
    }
}

/// A parsed HTTP request head. Slices borrow from the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead<'a> {
    /// Raw HTTP method (`GET`, `PUT`, …) — the record's `verb`.
    pub method: &'a str,
    /// Request target path, before any `?` (e.g. `/my/key`).
    pub path: &'a str,
    /// Query string after `?` (without the `?`), or `""`.
    pub query: &'a str,
    /// `Host:` header value, if present (the bucket is derived from SNI or this).
    pub host: Option<&'a str>,
}

/// Parse the request line + headers from a captured request head. None if the
/// first line isn't a plausible `METHOD target HTTP/1.x` request line.
#[must_use]
pub fn parse_request(data: &[u8]) -> Option<RequestHead<'_>> {
    let text = head_str(data);
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;

    // "METHOD SP request-target SP HTTP-version"
    let mut parts = request_line.split(' ');
    let method = parts.next().filter(|m| is_token(m))?;
    let target = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return None; // not a clean origin-form HTTP/1.x request line
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    // Scan headers for Host (case-insensitive name). Stop at the blank line.
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                host = Some(value.trim());
                break;
            }
        }
    }

    Some(RequestHead { method, path, query, host })
}

/// Parse the status code from a captured response head (`HTTP/1.x NNN ...`). None
/// if the first line isn't a status line or the code isn't a 3-digit number.
#[must_use]
pub fn parse_status(data: &[u8]) -> Option<u16> {
    let text = head_str(data);
    let status_line = text.split("\r\n").next()?;
    let mut parts = status_line.split(' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse::<u16>().ok().filter(|&c| (100..=599).contains(&c))
}

/// Resolve the S3 operation from the method, path, and query string. The
/// `path` is the request-line path (key for virtual-hosted-style requests, the
/// dominant S3 form); `query` is the raw query string (no leading `?`).
#[must_use]
pub fn classify(method: &str, path: &str, query: &str) -> S3Op {
    // Object-level when the path names a key (more than just "/").
    let has_key = path.len() > 1;
    let q = Query(query);
    match method {
        "GET" if q.has("session") => S3Op::CreateSession,
        "GET" if q.value("list-type") == Some("2") => S3Op::ListObjectsV2,
        "GET" if !has_key => S3Op::ListObjects, // bucket-level GET, no list-type
        "GET" => S3Op::GetObject,
        // The object-level verbs need the SAME `has_key` guard the GET arm applies: a
        // bucket-level `HEAD /` (HeadBucket), `PUT /` (CreateBucket) or `DELETE /`
        // (DeleteBucket) is not an operation ON an object, and labelling it
        // HeadObject/PutObject/DeleteObject with key=None pollutes every per-s3_op
        // grouping downstream (doctor rows, the scorecard). These bucket-level ops have
        // no wire string in the taxonomy — which is pinned public contract — so they
        // report Unknown, keeping their raw verb on the record.
        "HEAD" if !has_key => S3Op::Unknown,
        "HEAD" => S3Op::HeadObject,
        "PUT" if q.has("partNumber") && q.has("uploadId") => S3Op::UploadPart,
        "PUT" if !has_key => S3Op::Unknown,
        "PUT" => S3Op::PutObject,
        "POST" if q.has("delete") => S3Op::DeleteObjects,
        "POST" if q.has("uploads") => S3Op::CreateMultipartUpload,
        "POST" if q.has("uploadId") => S3Op::CompleteMultipartUpload,
        "DELETE" if q.has("uploadId") => S3Op::AbortMultipartUpload,
        "DELETE" if !has_key => S3Op::Unknown,
        "DELETE" => S3Op::DeleteObject,
        _ => S3Op::Unknown,
    }
}

/// A header value from a captured head (case-insensitive name), or None. Skips the
/// request/status line and stops at the blank line. Borrows from `data`.
#[must_use]
pub fn header_value<'a>(data: &'a [u8], name: &str) -> Option<&'a str> {
    for line in head_str(data).split("\r\n").skip(1) {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((n, v)) = line.split_once(':') {
            if n.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

/// Ceiling on a declared body length: 5 TiB, the largest object S3 stores. The header is
/// attacker-influenceable (a hostile endpoint answers with whatever it likes) and the wire
/// schema serializes `content_length` as a PLAIN JSON number on exactly this premise — safe
/// only while the value stays under 2^53, past which a JS/`jq` consumer silently rounds it.
/// Enforce the premise at the parse boundary rather than trusting the peer.
const MAX_CONTENT_LENGTH: u64 = 5 << 40;

/// The declared response body length from `Content-Length`, or None when absent —
/// which includes `Transfer-Encoding: chunked` (no fixed length) and any head we
/// couldn't see in full. Used to tally body-completion for the download/total span.
///
/// None also for a head we can't trust to frame the body: a `Transfer-Encoding` header
/// (whose chunked framing supersedes any Content-Length per RFC 9112 §6.3, so tallying to
/// the declared number would end the download span at a mid-body instant), CONFLICTING
/// duplicate Content-Length values, and a value above [`MAX_CONTENT_LENGTH`].
#[must_use]
pub fn content_length(data: &[u8]) -> Option<u64> {
    let mut len: Option<u64> = None;
    for line in head_str(data).split("\r\n").skip(1) {
        if line.is_empty() {
            break; // end of headers
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None; // framing comes from the coding, not this header
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n = value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|&n| n <= MAX_CONTENT_LENGTH)?;
            if len.is_some_and(|prev| prev != n) {
                return None; // duplicate headers disagree: no trustworthy target
            }
            len = Some(n);
        }
    }
    len
}

/// Byte offset just past the end-of-headers (`\r\n\r\n`) in a captured head — i.e. the
/// number of head bytes, so anything beyond it in the same read is body. None when the
/// terminator isn't present in `data` (the head was truncated past the capture, so we
/// can't know where the body starts and won't attempt the body tally).
#[must_use]
pub fn header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The bucket from a virtual-hosted-style S3 host (`<bucket>.s3.<region>.amazonaws.com`
/// or `<bucket>.s3-<region>…` or `<bucket>.s3.amazonaws.com`) — everything before the
/// FINAL `.s3` label, so a bucket name that itself contains `.s3.` survives (bucket
/// names may have dots). None for a path-style host (`s3.<region>.amazonaws.com`,
/// bucket is in the path) or a non-S3 host.
#[must_use]
pub fn bucket_from_host(host: &str) -> Option<&str> {
    // AWS virtual-hosted ONLY: the host must end in `.amazonaws.com`. Without this, any
    // non-AWS host that merely contains a `.s3.`/`.s3-` label (e.g. `media.s3.cdn.internal`)
    // would be mis-split into a "bucket" and a plain web GET wrongly recorded as GetObject —
    // the exact false-positive the "s3tap won't guess an arbitrary host is S3" invariant
    // exists to prevent. Custom endpoints are handled by `bucket_from_endpoint_subdomain`.
    // Standard partition only: the China partition (`*.amazonaws.com.cn`) ends in `.cn` and
    // is intentionally not matched (separate accounts/credentials) — a known limitation.
    // AWS hostnames are case-insensitive DNS names, and the HTTP Host header (unlike SNI/DNS,
    // which `qname_str` lowercases) reaches here verbatim — a client sending
    // `B.S3.amazonaws.com` must still resolve. Match on an ASCII-lowercased copy; since
    // lowercasing preserves byte length and offsets, the index found in `lower` is valid in
    // `host`, so the returned bucket slice keeps its ORIGINAL case.
    // A Host header may arrive fully-qualified with the DNS root dot
    // (`b.s3.amazonaws.com.`), which the `.amazonaws.com` suffix gate would reject — the
    // host would not be recognized as S3 at all. Every other name path in the crate
    // canonicalizes that dot away (`qname_str`, `aws_region_from_host`), so do it here
    // too. Trimming only the TAIL keeps every index found in `lower` valid in `host`.
    let lower = host.to_ascii_lowercase();
    let lower = lower.trim_end_matches('.');
    if !lower.ends_with(".amazonaws.com") {
        return None;
    }
    // Anchor on the service label NEAREST the suffix across BOTH endpoint forms
    // (`.s3.` and `.s3-`) — the rightmost match wins. Per-separator rfind alone is
    // not enough: trying `.s3.` first and returning on it would mis-split a dotted
    // bucket whose name contains `.s3.` when the endpoint is the dash form
    // (`weird.s3.name.s3-eu-west-1...` -> the bucket is `weird.s3.name`, anchored on
    // the `.s3-`, not the `.s3.` inside the name). Taking the max index over both
    // forms picks the true service label regardless of which form the endpoint uses.
    let idx = [".s3.", ".s3-"]
        .iter()
        .filter_map(|sep| lower.rfind(sep))
        .max()?;
    let b = &host[..idx];
    if b.is_empty() {
        None
    } else {
        Some(b)
    }
}

/// Strip a trailing `:<port>` from an authority for S3-host classification. Real S3
/// hosts are DNS names, optionally with an explicit `:443`; `rsplit_once(':')` with an
/// all-digit right side removes it. Left untouched when the remainder still contains a
/// `:` (an IPv6 literal `2606:4700::1`, or a bracketed `[::1]:443`) — never an S3 host.
fn host_without_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((h, port))
            if !h.is_empty()
                && !h.contains(':')
                && !h.starts_with('[')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            h
        }
        _ => host,
    }
}

/// True if `host` is a bare AWS S3 endpoint (path-style addressing): `s3.…` or
/// `s3-…` with no bucket subdomain, so the bucket is the first path segment. Anchored
/// on the `amazonaws.com` suffix so a non-AWS host that merely starts with `s3.`
/// (e.g. a custom `s3.mycompany.internal`) is left UNrecognized — matching the
/// documented "custom S3-compatible endpoints → bucket=null" limitation, rather than
/// mis-splitting its first path segment as an AWS bucket.
#[must_use]
pub fn is_s3_endpoint(host: &str) -> bool {
    // Case-insensitive: the Host header can arrive mixed-case (`S3.amazonaws.com`), unlike the
    // SNI/DNS path which `qname_str` already lowercases. The trailing root dot of a
    // fully-qualified name is stripped for the same reason as in `bucket_from_host`.
    let lower = host.to_ascii_lowercase();
    let lower = lower.trim_end_matches('.');
    (lower.starts_with("s3.") || lower.starts_with("s3-")) && lower.ends_with(".amazonaws.com")
}

/// A fully-resolved request: the S3 op, the bucket, and the object key — handling
/// BOTH addressing styles. Slices borrow from the inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<'a> {
    pub op: S3Op,
    /// Bucket — from the host subdomain (virtual-hosted) or the first path segment
    /// (path-style on an AWS S3 endpoint). None when undeterminable.
    pub bucket: Option<&'a str>,
    /// Object key with EXACTLY ONE leading `/` stripped, or None for a bucket-level op.
    /// One, not all: the path `//a` yields `/a`, not `a`. Stripping every leading slash
    /// collapsed the distinct S3 keys `/a` and `a` onto a single hash.
    pub key: Option<&'a str>,
    /// Whether the host was RECOGNIZED as S3 (an AWS `s3.…` endpoint, a virtual-hosted
    /// bucket, or a configured `--s3-endpoint`). `op` is classified from the HTTP verb
    /// for ANY request, so callers must consult this before labeling a request an S3 op —
    /// a plain `GET` to a non-S3 host is not a `GetObject` (it just looks like one).
    pub is_s3: bool,
}

/// Resolve the op + bucket + key from a request, accounting for addressing style —
/// AWS hostname patterns only. See [`resolve_with`] to also recognize opt-in custom
/// S3-compatible endpoints.
#[must_use]
pub fn resolve<'a>(method: &str, path: &'a str, query: &str, host: Option<&'a str>) -> Resolved<'a> {
    resolve_with(method, path, query, host, &[])
}

/// Resolve the op + bucket + key, accounting for addressing style.
/// Virtual-hosted (the modern default): bucket in the host, path IS the key.
/// Path-style on an AWS `s3.`/`s3-` endpoint: bucket is the first path segment, the
/// remainder is the key — so a path-style `GET /bucket` is `ListObjects`, not a
/// `GetObject` of a key named `bucket`.
///
/// `s3_endpoints` is the opt-in `--s3-endpoint` set (lowercase, port-free hosts): a
/// captured request whose host EXACTLY matches one is treated path-style, and a
/// `<bucket>.<endpoint>` subdomain is virtual-hosted. This is how custom S3-compatible
/// endpoints (Storj/MinIO/R2/…) get a bucket. Without it (or for any other host) a
/// non-AWS host yields no bucket — s3tap won't guess an arbitrary host is S3 and
/// mis-split a non-S3 API's first path segment as a "bucket".
#[must_use]
pub fn resolve_with<'a>(
    method: &str,
    path: &'a str,
    query: &str,
    host: Option<&'a str>,
    s3_endpoints: &[String],
) -> Resolved<'a> {
    // Strip an explicit `:443` (or any `:<port>`) before host classification: the
    // path-style `is_s3_endpoint` check anchors on a `.amazonaws.com` SUFFIX, which a
    // trailing port defeats — so `s3.us-east-1.amazonaws.com:443` would lose its bucket
    // entirely (review L2). Virtual-hosted already survived (the bucket is a prefix),
    // but normalizing both styles here keeps them consistent. IPv6 literals are left
    // alone (never S3 endpoints anyway).
    let host = host.map(host_without_port);
    // Virtual-hosted on AWS: bucket in the host subdomain; the whole path is the key.
    if let Some(b) = host.and_then(bucket_from_host) {
        return finish(method, path, query, Some(b), true);
    }
    // Path-style on an AWS S3 endpoint OR an exact-match configured custom endpoint.
    if host.is_some_and(|h| is_s3_endpoint(h) || matches_endpoint(h, s3_endpoints)) {
        return path_style(method, path, query);
    }
    // Virtual-hosted against a configured custom endpoint: <bucket>.<endpoint>.
    if let Some(b) = host.and_then(|h| bucket_from_endpoint_subdomain(h, s3_endpoints)) {
        return finish(method, path, query, Some(b), true);
    }
    // Unknown host: NOT recognized as S3 — no bucket, and `op` must not be taken as an S3
    // op (a plain GET here is not a GetObject). Treat the path as the key.
    finish(method, path, query, None, false)
}

/// Path-style resolution: the first path segment is the bucket, the remainder is the
/// key. Shared by the AWS `s3.…` endpoints and the opt-in custom endpoints.
fn path_style<'a>(method: &str, path: &'a str, query: &str) -> Resolved<'a> {
    let tail = path.strip_prefix('/').unwrap_or(path);
    match tail.split_once('/') {
        // /<bucket>/<key…>: classify on the key portion (slice after the bucket).
        Some((b, _)) if !b.is_empty() => finish(method, &path[1 + b.len()..], query, Some(b), true),
        // /<bucket> (no further slash): a bucket-level op. Only treat it as a bucket if
        // it's a single clean segment — a malformed `//…` (empty first segment) yields
        // None, not a bogus slash-containing "bucket".
        _ => finish(method, "/", query, (!tail.is_empty() && !tail.contains('/')).then_some(tail), true),
    }
}

/// True if `h` exactly matches a configured custom endpoint (ASCII-case-insensitive).
fn matches_endpoint(h: &str, s3_endpoints: &[String]) -> bool {
    s3_endpoints.iter().any(|ep| h.eq_ignore_ascii_case(ep))
}

/// If `h` is `<bucket>.<endpoint>` for a configured endpoint, return `<bucket>` (the
/// labels before the endpoint suffix). None if `h` is the bare endpoint or unrelated.
fn bucket_from_endpoint_subdomain<'a>(h: &'a str, s3_endpoints: &[String]) -> Option<&'a str> {
    for ep in s3_endpoints {
        // Need at least one label + a '.' before the suffix.
        let Some(cut) = h.len().checked_sub(ep.len()).filter(|&c| c > 1) else {
            continue;
        };
        // Compare the suffix on BYTES. A Host header is arbitrary attacker-supplied text and
        // may hold a multi-byte character, so `split_at(cut)` on the &str would panic on a
        // non-char-boundary offset — and nothing on the fold path catches a panic, so it
        // would take the capture agent down. Byte slicing has no boundary rule.
        let (prefix, suffix) = h.as_bytes().split_at(cut);
        if !suffix.eq_ignore_ascii_case(ep.as_bytes()) {
            continue;
        }
        // The bucket is the labels before the separating dot. `prefix` ending in an ASCII
        // '.' makes `cut - 1` a char boundary, so the &str slice is always valid.
        if let Some(b) = prefix.strip_suffix(b".") {
            if !b.is_empty() {
                return h.get(..b.len());
            }
        }
    }
    None
}

fn finish<'a>(
    method: &str,
    key_path: &'a str,
    query: &str,
    bucket: Option<&'a str>,
    is_s3: bool,
) -> Resolved<'a> {
    // Strip exactly ONE leading '/' — the request-target separator — never a run of them.
    // S3 keys may legitimately begin with a slash, so `/a` and `a` are DIFFERENT objects;
    // collapsing them to one key_hash makes the advisor report a redundant refetch of one
    // object where two distinct objects were fetched. A target of `//` therefore yields the
    // key `/`, and a bare `/` yields no key at all (bucket-level).
    let key = key_path.strip_prefix('/').unwrap_or(key_path);
    Resolved {
        op: classify(method, key_path, query),
        bucket,
        key: (!key.is_empty()).then_some(key),
        is_s3,
    }
}

/// The request/status head as a `&str` borrowing `data`: the valid-UTF-8 prefix up
/// to the first NUL (or a non-UTF-8 byte). HTTP heads are ASCII — request/status
/// lines and header names/values — so this keeps the parse zero-copy; a stray
/// non-ASCII byte just bounds the slice there (anything past it is dropped).
fn head_str(data: &[u8]) -> &str {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let bytes = &data[..end];
    match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    }
}

/// True if `s` is a plausible HTTP method token: non-empty uppercase letters, and
/// short. The length bound keeps this in step with the in-kernel gate (s3tap.bpf.c
/// `looks_like_http_request`), which admits a write by matching only the first 5-7
/// method bytes with no trailing boundary — so it lets through e.g. `DELETEXYZ`. The
/// real S3 verbs are all <= 7 chars; capping at 16 means a long all-caps blob in a
/// malformed first line is rejected here rather than retained as a bogus `verb`
/// (review Gap D). Anything that passes still keeps its raw verb for the Unknown op.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// A thin wrapper for `&`-separated `name[=value]` query-string lookups.
struct Query<'a>(&'a str);

impl<'a> Query<'a> {
    /// Is the (possibly value-less) param present? e.g. `uploads`, `delete`.
    fn has(&self, name: &str) -> bool {
        self.pairs().any(|(k, _)| k == name)
    }

    /// The value of `name`, or None. Returns Some("") for a present-but-empty param.
    fn value(&self, name: &str) -> Option<&'a str> {
        self.pairs().find(|&(k, _)| k == name).map(|(_, v)| v)
    }

    fn pairs(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.0
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &str) -> RequestHead<'_> {
        parse_request(s.as_bytes()).expect("parse")
    }

    #[test]
    fn s3op_as_str_pins_the_public_taxonomy() {
        // `as_str` values are the wire `s3_op` strings in `s3tap.operation/1`, so they are a
        // public contract: renaming one silently breaks every downstream consumer. Pin each.
        // The inner `match` is exhaustive, so adding an S3Op variant fails to compile here
        // until its wire string is pinned too.
        for op in [
            S3Op::GetObject,
            S3Op::PutObject,
            S3Op::HeadObject,
            S3Op::DeleteObject,
            S3Op::DeleteObjects,
            S3Op::ListObjectsV2,
            S3Op::ListObjects,
            S3Op::CreateMultipartUpload,
            S3Op::UploadPart,
            S3Op::CompleteMultipartUpload,
            S3Op::AbortMultipartUpload,
            S3Op::CreateSession,
            S3Op::Unknown,
        ] {
            let want = match op {
                S3Op::GetObject => "GetObject",
                S3Op::PutObject => "PutObject",
                S3Op::HeadObject => "HeadObject",
                S3Op::DeleteObject => "DeleteObject",
                S3Op::DeleteObjects => "DeleteObjects",
                S3Op::ListObjectsV2 => "ListObjectsV2",
                S3Op::ListObjects => "ListObjects",
                S3Op::CreateMultipartUpload => "CreateMultipartUpload",
                S3Op::UploadPart => "UploadPart",
                S3Op::CompleteMultipartUpload => "CompleteMultipartUpload",
                S3Op::AbortMultipartUpload => "AbortMultipartUpload",
                S3Op::CreateSession => "CreateSession",
                S3Op::Unknown => "UNKNOWN",
            };
            assert_eq!(op.as_str(), want, "S3Op wire string drifted for {want}");
        }
    }

    #[test]
    fn parses_request_line_path_query_host() {
        let r = req("GET /my/key?versionId=3 HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nUser-Agent: x\r\n\r\n");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/my/key");
        assert_eq!(r.query, "versionId=3");
        assert_eq!(r.host, Some("b.s3.amazonaws.com"));
    }

    #[test]
    fn no_query_no_host() {
        let r = req("PUT /key HTTP/1.1\r\nContent-Length: 5\r\n\r\n");
        assert_eq!((r.method, r.path, r.query, r.host), ("PUT", "/key", "", None));
    }

    #[test]
    fn host_header_is_case_insensitive() {
        assert_eq!(req("GET / HTTP/1.1\r\nhOsT:  s3.amazonaws.com  \r\n\r\n").host, Some("s3.amazonaws.com"));
    }

    #[test]
    fn rejects_non_request_lines() {
        assert!(parse_request(b"HTTP/1.1 200 OK\r\n\r\n").is_none(), "status line is not a request");
        assert!(parse_request(b"garbage\r\n").is_none());
        assert!(parse_request(b"GET /key\r\n").is_none(), "missing HTTP version");
        assert!(parse_request(b"GET /key HTTP/1.1 extra\r\n").is_none(), "trailing junk on request line");
        assert!(parse_request(b"get /key HTTP/1.1\r\n").is_none(), "lowercase method (not a token)");
    }

    #[test]
    fn parses_status_codes() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\nx: y\r\n\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.1 307 Temporary Redirect\r\n"), Some(307));
        assert_eq!(parse_status(b"HTTP/1.0 503 Slow Down\r\n"), Some(503));
        assert_eq!(parse_status(b"GET / HTTP/1.1\r\n"), None, "request line is not a status");
        assert_eq!(parse_status(b"HTTP/1.1 20 OK\r\n"), None, "2-digit code");
        assert_eq!(parse_status(b"HTTP/1.1 999 ?\r\n"), None, "out of 100-599 range");
    }

    #[test]
    fn taxonomy_covers_the_schema_table() {
        // (method, path, query) -> expected s3_op.
        let cases = [
            ("GET", "/key", "", S3Op::GetObject),
            ("GET", "/key", "versionId=3", S3Op::GetObject),
            ("GET", "/", "", S3Op::ListObjects),
            ("GET", "/", "list-type=2", S3Op::ListObjectsV2),
            ("GET", "/", "list-type=2&max-keys=100", S3Op::ListObjectsV2),
            ("GET", "/", "session", S3Op::CreateSession),
            ("HEAD", "/key", "", S3Op::HeadObject),
            ("PUT", "/key", "", S3Op::PutObject),
            ("PUT", "/key", "partNumber=2&uploadId=abc", S3Op::UploadPart),
            ("POST", "/key", "uploads", S3Op::CreateMultipartUpload),
            ("POST", "/key", "uploadId=abc", S3Op::CompleteMultipartUpload),
            ("POST", "/", "delete", S3Op::DeleteObjects),
            ("DELETE", "/key", "", S3Op::DeleteObject),
            ("DELETE", "/key", "uploadId=abc", S3Op::AbortMultipartUpload),
            ("PATCH", "/key", "", S3Op::Unknown),
        ];
        for (m, p, q, want) in cases {
            assert_eq!(classify(m, p, q), want, "{m} {p}?{q}");
        }
    }

    #[test]
    fn upload_part_needs_both_params() {
        // partNumber alone (no uploadId) is not UploadPart — falls to PutObject.
        assert_eq!(classify("PUT", "/key", "partNumber=2"), S3Op::PutObject);
    }

    #[test]
    fn header_value_and_bucket() {
        let head = b"HTTP/1.1 503 Slow Down\r\nx-amz-request-id: ABC123\r\nx-amz-id-2: zzz\r\n\r\n";
        assert_eq!(header_value(head, "x-amz-request-id"), Some("ABC123"));
        assert_eq!(header_value(head, "X-AMZ-REQUEST-ID"), Some("ABC123"), "case-insensitive");
        assert_eq!(header_value(head, "missing"), None);
        // bucket from virtual-hosted host (incl. dotted bucket names + path-style None).
        assert_eq!(bucket_from_host("b.s3.eu-west-1.amazonaws.com"), Some("b"));
        assert_eq!(bucket_from_host("my.dotted.bucket.s3.amazonaws.com"), Some("my.dotted.bucket"));
        assert_eq!(bucket_from_host("b.s3-ap-southeast-2.amazonaws.com"), Some("b"));
        // A mixed-case Host header (the header, unlike SNI/DNS, isn't lowercased upstream)
        // must still resolve — AWS hostnames are case-insensitive DNS names. The returned
        // bucket keeps its original case.
        assert_eq!(bucket_from_host("MyBucket.S3.US-EAST-1.amazonaws.COM"), Some("MyBucket"));
        assert_eq!(bucket_from_host("b.S3-AP-SOUTHEAST-2.AMAZONAWS.COM"), Some("b"));
        assert_eq!(bucket_from_host("s3.eu-west-1.amazonaws.com"), None, "path-style: bucket in path");
        assert_eq!(bucket_from_host("example.com"), None);
        // A NON-AWS host that merely contains a `.s3.`/`.s3-` label must NOT be split into a
        // bucket (else a plain web GET would be mis-recorded as an S3 GetObject).
        assert_eq!(bucket_from_host("media.s3.cdn.internal"), None, "non-AWS host is not S3");
        assert_eq!(bucket_from_host("foo.s3-eu.company.example"), None, "non-AWS dash form is not S3");
        // A bucket name that itself contains `.s3.` — rfind anchors on the LAST one.
        assert_eq!(
            bucket_from_host("my.s3.bucket.s3.us-east-1.amazonaws.com"),
            Some("my.s3.bucket"),
            "dotted bucket containing .s3. survives"
        );
        // ...and survives even on the DASH-form endpoint: the anchor is the rightmost
        // service label across both forms, not whichever form matches first (else the
        // `.s3.` inside the bucket name would win over the real `.s3-` service label).
        assert_eq!(
            bucket_from_host("weird.s3.name.s3-eu-west-1.amazonaws.com"),
            Some("weird.s3.name"),
            "dotted bucket with .s3. on a dash-form endpoint anchors on the .s3-"
        );
    }

    #[test]
    fn content_length_parses_and_rejects_adversarial_values() {
        let with = |v: &str| {
            content_length(format!("HTTP/1.1 200 OK\r\nContent-Length: {v}\r\n\r\n").as_bytes())
        };
        assert_eq!(with("0"), Some(0));
        assert_eq!(with("12345"), Some(12345));
        assert_eq!(with(" 12 "), Some(12), "surrounding whitespace trimmed");
        // Header NAME is case-insensitive (via header_value).
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\n"), Some(7));
        // Adversarial -> None (the correlator's emit-at-head / download=None fallback).
        assert_eq!(with("-1"), None, "negative");
        assert_eq!(with("abc"), None, "non-numeric");
        assert_eq!(with("0x10"), None, "hex not decimal");
        assert_eq!(with("18446744073709551616"), None, "u64 overflow");
        assert_eq!(with("12 34"), None, "internal space");
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\n\r\n"), None, "absent");
        // Chunked has no Content-Length -> None (we don't tally; emit at head).
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            None
        );
    }

    #[test]
    fn content_length_rejects_untallyable_and_oversized_declarations() {
        // Transfer-Encoding frames the body, so a Content-Length beside it is not a tally
        // target — honoring it would end the download span at a mid-body instant. Either
        // header order must yield None.
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"),
            None
        );
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 100\r\n\r\n"),
            None
        );
        // Duplicate headers that DISAGREE leave no trustworthy target; agreeing ones are fine.
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Length: 5\r\n\r\n"),
            None
        );
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\ncontent-length: 100\r\n\r\n"),
            Some(100)
        );
        // The 5 TiB ceiling: the value is the peer's to choose and ships as a plain JSON
        // number, so anything past 2^53 would silently lose precision downstream.
        let with = |v: u64| {
            content_length(format!("HTTP/1.1 200 OK\r\nContent-Length: {v}\r\n\r\n").as_bytes())
        };
        assert_eq!(with(MAX_CONTENT_LENGTH), Some(MAX_CONTENT_LENGTH), "exactly 5 TiB is a real size");
        assert_eq!(with(MAX_CONTENT_LENGTH + 1), None, "past the S3 object ceiling");
        assert_eq!(with(9_007_199_254_740_993), None, "past 2^53: unrepresentable in a JS consumer");
    }

    #[test]
    fn bucket_level_object_verbs_are_not_object_ops() {
        // HeadBucket / CreateBucket / DeleteBucket name no key, so reporting them as
        // HeadObject/PutObject/DeleteObject with key=None pollutes every per-s3_op grouping.
        // They have no wire string in the (pinned, public) taxonomy -> Unknown.
        for m in ["HEAD", "PUT", "DELETE"] {
            assert_eq!(classify(m, "/", ""), S3Op::Unknown, "bucket-level {m}");
        }
        // The object-level forms are untouched...
        assert_eq!(classify("HEAD", "/key", ""), S3Op::HeadObject);
        assert_eq!(classify("PUT", "/key", ""), S3Op::PutObject);
        assert_eq!(classify("DELETE", "/key", ""), S3Op::DeleteObject);
        // ...as are the query-driven multipart ops.
        assert_eq!(classify("PUT", "/k", "partNumber=1&uploadId=x"), S3Op::UploadPart);
        assert_eq!(classify("DELETE", "/k", "uploadId=x"), S3Op::AbortMultipartUpload);
        // Path-style `HEAD /bucket` resolves the bucket with no key and no object op.
        let r = resolve("HEAD", "/bucket", "", Some("s3.amazonaws.com"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::Unknown, Some("bucket"), None));
    }

    #[test]
    fn leading_slashes_in_a_key_are_not_collapsed() {
        // `/a` and `a` are DIFFERENT S3 keys. Stripping EVERY leading slash collided their
        // key_hash, so the advisor reported a redundant refetch of one object where two
        // distinct objects were fetched.
        let vh = Some("b.s3.amazonaws.com");
        assert_eq!(resolve("GET", "/a", "", vh).key, Some("a"));
        assert_eq!(resolve("GET", "//a", "", vh).key, Some("/a"), "only the target separator goes");
        assert_eq!(resolve("GET", "//", "", vh).key, Some("/"), "the key is `/`, not empty");
        assert_eq!(resolve("GET", "/", "", vh).key, None, "bucket-level: no key");
        // Path-style applies the same rule to the remainder after the bucket segment.
        assert_eq!(resolve("GET", "/bucket//a", "", Some("s3.amazonaws.com")).key, Some("/a"));
    }

    #[test]
    fn a_trailing_root_dot_is_still_an_s3_host() {
        // A fully-qualified Host (`…amazonaws.com.`) names the same server; every other name
        // path in the crate canonicalizes the root dot away, so these must too — otherwise
        // the request isn't recognized as S3 at all (no bucket, no s3_op).
        assert_eq!(bucket_from_host("b.s3.eu-west-1.amazonaws.com."), Some("b"));
        assert_eq!(bucket_from_host("MyBucket.S3.amazonaws.com."), Some("MyBucket"), "case preserved");
        assert!(is_s3_endpoint("s3.us-east-1.amazonaws.com."));
        let r = resolve("GET", "/k", "", Some("b.s3.amazonaws.com."));
        assert_eq!((r.op, r.bucket, r.is_s3), (S3Op::GetObject, Some("b"), true));
        let r = resolve("GET", "/bucket/k", "", Some("s3.amazonaws.com.:443"));
        assert_eq!((r.bucket, r.key), (Some("bucket"), Some("k")), "root dot + explicit port");
    }

    #[test]
    fn a_multibyte_host_does_not_panic_the_endpoint_subdomain_split() {
        // The Host header is arbitrary attacker-supplied text. Splitting the endpoint suffix
        // off at a byte offset that lands mid-character used to panic — and nothing on the
        // fold path catches a panic, so it took the capture agent down.
        let eps = vec!["minio.local".to_string()];
        let r = resolve_with("GET", "/k", "", Some("xé0123456789"), &eps);
        assert_eq!((r.bucket, r.is_s3), (None, false), "unrelated host: no bucket, no panic");
        // A genuine `<bucket>.<endpoint>` with a multi-byte bucket still splits cleanly.
        let r = resolve_with("GET", "/k", "", Some("bücket.minio.local"), &eps);
        assert_eq!(r.bucket, Some("bücket"));
        // The bare endpoint is still path-style (no subdomain bucket).
        let r = resolve_with("GET", "/b/k", "", Some("minio.local"), &eps);
        assert_eq!((r.bucket, r.key), (Some("b"), Some("k")));
    }

    #[test]
    fn header_end_finds_the_terminator_or_none() {
        assert_eq!(header_end(b"HTTP/1.1 200 OK\r\n\r\nBODY"), Some(19), "offset past CRLFCRLF");
        assert_eq!(header_end(b"a\r\n\r\nB"), Some(5));
        // Only a real CRLFCRLF terminates: LF-only, absent, and short slices -> None.
        assert_eq!(header_end(b"a\n\nB"), None, "LF-only is not the HTTP terminator");
        assert_eq!(header_end(b"no terminator here"), None, "truncated head");
        assert_eq!(header_end(b"ab"), None, "slice shorter than 4 bytes, no panic");
        assert_eq!(header_end(b""), None, "empty, no panic");
    }

    #[test]
    fn host_with_explicit_port_still_resolves_the_bucket() {
        // Path-style with an explicit :443 must NOT lose its bucket (review L2): the
        // is_s3_endpoint suffix check would otherwise fail on the trailing port.
        let r = resolve("GET", "/bucket/the/key", "", Some("s3.us-east-1.amazonaws.com:443"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::GetObject, Some("bucket"), Some("the/key")));
        // Virtual-hosted with a port resolves too (the bucket is a prefix).
        let r = resolve("GET", "/my/key", "", Some("b.s3.eu-west-1.amazonaws.com:443"));
        assert_eq!((r.op, r.bucket), (S3Op::GetObject, Some("b")));
        // An IPv6 literal authority is left intact (not an S3 host; no bucket).
        assert_eq!(host_without_port("2606:4700::1"), "2606:4700::1");
        assert_eq!(host_without_port("[::1]:443"), "[::1]:443");
        assert_eq!(host_without_port("s3.amazonaws.com:443"), "s3.amazonaws.com");
        assert_eq!(host_without_port("s3.amazonaws.com"), "s3.amazonaws.com");
    }

    #[test]
    fn an_overlong_uppercase_method_is_not_a_request() {
        // The kernel gate admits a write on the first method bytes with no boundary,
        // so a malformed `DELETEXYZWVUTSRQPONM /x ...` reaches the parser; the method
        // length bound rejects it rather than retaining a 19-char "verb" (review Gap D).
        assert!(parse_request(b"DELETEXYZWVUTSRQPONM /x HTTP/1.1\r\n").is_none());
        // A real (if non-taxonomy) short verb still parses, keeping its raw verb.
        let r = req("PATCH /x HTTP/1.1\r\n\r\n");
        assert_eq!(r.method, "PATCH");
    }

    #[test]
    fn resolve_handles_both_addressing_styles() {
        // Virtual-hosted: bucket in host, path IS the key.
        let r = resolve("GET", "/my/key", "", Some("b.s3.eu-west-1.amazonaws.com"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::GetObject, Some("b"), Some("my/key")));
        let r = resolve("GET", "/", "", Some("b.s3.amazonaws.com"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::ListObjects, Some("b"), None));

        // Path-style on an AWS endpoint: bucket is the first path segment.
        let r = resolve("GET", "/bucket/the/key", "", Some("s3.us-east-1.amazonaws.com"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::GetObject, Some("bucket"), Some("the/key")));
        // Path-style bucket-level GET must be ListObjects, NOT GetObject of "bucket".
        let r = resolve("GET", "/bucket", "", Some("s3.amazonaws.com"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::ListObjects, Some("bucket"), None));
        let r = resolve("PUT", "/bucket/obj", "partNumber=2&uploadId=x", Some("s3.amazonaws.com"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::UploadPart, Some("bucket"), Some("obj")));

        // Unknown host: no bucket, path is the key.
        let r = resolve("GET", "/k", "", Some("minio.internal"));
        assert_eq!((r.op, r.bucket, r.key), (S3Op::GetObject, None, Some("k")));
        // A custom host that merely STARTS with `s3.` but isn't AWS must NOT be split
        // path-style (no bucket) — it's an unrecognized endpoint, not mis-recognized.
        assert!(!is_s3_endpoint("s3.mycompany.internal"));
        assert!(is_s3_endpoint("s3.us-east-1.amazonaws.com"));
        assert!(is_s3_endpoint("S3.US-EAST-1.AMAZONAWS.COM"), "mixed-case Host header still S3");
        let r = resolve("GET", "/bucket/key", "", Some("s3.mycompany.internal"));
        assert_eq!((r.op, r.bucket), (S3Op::GetObject, None), "custom s3.* host -> bucket=null");
        // No host at all.
        let r = resolve("GET", "/k", "", None);
        assert_eq!(r.bucket, None);
        // Malformed path-style targets must not yield a slash-containing "bucket".
        assert_eq!(resolve("GET", "//key", "", Some("s3.amazonaws.com")).bucket, None);
        assert_eq!(resolve("GET", "///", "", Some("s3.amazonaws.com")).bucket, None);
    }

    #[test]
    fn is_s3_marks_only_recognized_hosts() {
        // Recognized as S3 -> is_s3 true (so the verb-classified op is a real S3 op).
        assert!(resolve("GET", "/k", "", Some("b.s3.amazonaws.com")).is_s3, "virtual-hosted");
        assert!(resolve("GET", "/bucket/k", "", Some("s3.us-east-1.amazonaws.com")).is_s3, "path-style AWS");
        let eps = vec!["gateway.storjshare.io".to_string()];
        assert!(resolve_with("GET", "/test/k", "", Some("gateway.storjshare.io"), &eps).is_s3, "custom endpoint");
        // NOT S3 -> is_s3 false, even though `op` still classifies the GET as GetObject.
        // (This is the signal that keeps a plain web GET from labeling as a GetObject.)
        let r = resolve("GET", "/s3/", "", Some("aws.amazon.com"));
        assert_eq!(r.op, S3Op::GetObject, "verb still classifies");
        assert!(!r.is_s3, "a non-S3 host is not S3 even when the verb looks like a get");
        assert!(!resolve("GET", "/k", "", Some("minio.internal")).is_s3, "unconfigured custom host");
        assert!(!resolve("GET", "/k", "", None).is_s3, "no host");
    }

    #[test]
    fn resolve_with_custom_s3_endpoint() {
        let eps = vec!["gateway.storjshare.io".to_string()];
        // Path-style against the configured endpoint: first path segment is the bucket.
        let r = resolve_with("GET", "/test/docs/hello.txt", "", Some("gateway.storjshare.io"), &eps);
        assert_eq!((r.op, r.bucket, r.key), (S3Op::GetObject, Some("test"), Some("docs/hello.txt")));
        // Bucket-level GET on the endpoint is ListObjects, not GetObject of "test".
        let r = resolve_with("GET", "/test", "", Some("gateway.storjshare.io"), &eps);
        assert_eq!((r.op, r.bucket, r.key), (S3Op::ListObjects, Some("test"), None));
        // ListObjectsV2 (the query marker) still classifies.
        let r = resolve_with("GET", "/test", "list-type=2", Some("gateway.storjshare.io"), &eps);
        assert_eq!((r.op, r.bucket), (S3Op::ListObjectsV2, Some("test")));
        // An explicit port on the host is stripped before matching.
        let r = resolve_with("PUT", "/test/obj", "", Some("gateway.storjshare.io:443"), &eps);
        assert_eq!((r.op, r.bucket, r.key), (S3Op::PutObject, Some("test"), Some("obj")));
        // Virtual-hosted against the endpoint: <bucket>.<endpoint>.
        let r = resolve_with("GET", "/k", "", Some("test.gateway.storjshare.io"), &eps);
        assert_eq!((r.op, r.bucket, r.key), (S3Op::GetObject, Some("test"), Some("k")));
        // A dotted bucket name survives the subdomain split.
        let r = resolve_with("GET", "/k", "", Some("my.bucket.gateway.storjshare.io"), &eps);
        assert_eq!(r.bucket, Some("my.bucket"));
        // Case-insensitive host match.
        let r = resolve_with("GET", "/test/k", "", Some("Gateway.StorjShare.IO"), &eps);
        assert_eq!(r.bucket, Some("test"));
        // A NON-configured host is still unrecognized (no bucket) — the opt-in is exact.
        let r = resolve_with("GET", "/test/k", "", Some("minio.internal"), &eps);
        assert_eq!(r.bucket, None);
        // Empty endpoint list == plain resolve(): custom host yields no bucket.
        assert_eq!(resolve_with("GET", "/test/k", "", Some("gateway.storjshare.io"), &[]).bucket, None);
        // AWS patterns still win even when custom endpoints are configured.
        let r = resolve_with("GET", "/my/key", "", Some("b.s3.eu-west-1.amazonaws.com"), &eps);
        assert_eq!(r.bucket, Some("b"));
    }

    #[test]
    fn handles_a_captured_buffer_with_nul_tail() {
        // EvtTlsData::captured() is already bounded, but be robust to a NUL.
        let mut buf = b"GET /k HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        let r = parse_request(&buf).expect("parse past the bounded head");
        assert_eq!(r.path, "/k");
    }
}
