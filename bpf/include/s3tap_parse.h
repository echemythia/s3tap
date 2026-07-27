// bpf/include/s3tap_parse.h
//
// The PURE byte parsers, split out of s3tap.bpf.c so they can be compiled TWICE:
// once for BPF (the real program, unchanged) and once for the host, where a test
// binary drives them with constructed byte buffers.
//
// WHY THIS EXISTS. A green `just bpf-matrix` proves the object LOADS, nothing
// more. The verifier only walks code it can REACH, so a CO-RE relocation that
// makes a function return early turns everything downstream into dead code it
// never examines — which is exactly how two genuine 5.8 rejects hid behind a
// passing v5.8 row. A load gate therefore cannot tell "verified" from "compiled
// out", and it says nothing at all about whether a parser reads the right bytes.
// These functions consume ATTACKER-INFLUENCED input (a DNS message, a TLS
// ClientHello/ServerHello, an HTTP head), so they are the part most worth
// testing and the part a load gate covers least. Everything here is pure: bytes
// in, bytes out, no maps, no kernel structs, no helper calls except the one
// bounded copy the host shim stubs.
//
// THE TWO BUILDS
//   BPF   : s3tap.bpf.c includes this after vmlinux.h + bpf_helpers.h + the event
//           ABI. `__u*`, `__always_inline` and `bpf_probe_read_kernel` come from
//           those. Nothing here is conditional on the build, so the bytecode is
//           the same as when this code lived inline in the .c.
//   HOST  : bpf/tests/parser_tests.c defines S3TAP_HOST_TEST, includes
//           bpf/tests/s3tap_host_shim.h FIRST (which supplies the same names:
//           fixed-width types, __always_inline, a no-op barrier_var and a
//           bounds-checked memcpy for bpf_probe_read_kernel), then includes this.
//
// RULE: keep this header free of anything kernel-specific. A map lookup, a
// BPF_CORE_READ or an skb field belongs in s3tap.bpf.c, and the pure arithmetic
// it feeds belongs here where it can be tested.

#ifndef S3TAP_PARSE_H
#define S3TAP_PARSE_H

#include "s3tap_events.h"       // QNAME_MAX, SNI_MAX, DNS_PAYLOAD_MAX

// Compiler barrier (libbpf's, but the vendored bpf_helpers.h here lacks it): an
// empty asm that "modifies" a variable so clang can't carry a value-range fact
// across it. Used before a `var &= const` copy bound so clang materializes the
// mask instead of reusing a wider pre-mask register the verifier can't prove
// bounded (the "R2 min value is negative" reject). The host shim defines it as a
// no-op before including this header, so the #ifndef leaves that in place.
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

// --- scratch geometry ---------------------------------------------------
//
// These bound the per-CPU scratch maps the parsers read out of, and every offset
// below is masked with (LEN - 1) so the verifier can prove each read lands inside
// the map. They are powers of two so the masks are exact. The maps themselves are
// declared in s3tap.bpf.c; the sizes live here because the parsers' masks are
// written in terms of them.
//
// A MASK IS NOT A LENGTH CHECK. Masking bounds a read to the MAP; only the
// `len` argument bounds it to the bytes actually COPIED into that map. The
// scratch is reused and never zeroed, so a read past `len` returns a previous
// message's bytes. Every parser here therefore gates on `len` first and masks
// second, and the host tests poison everything past `len` so a parser that gets
// that order wrong fails loudly instead of quietly emitting stale bytes.
#define DNS_SCRATCH_LEN 512
#define TLS_SCRATCH_LEN 4096

// --- DNS ----------------------------------------------------------------

#define DNS_HDR_LEN  12          // id, flags, qd/an/ns/ar counts (2 bytes each)
// The UDP header the DNS payload follows. Spelled as a constant (not
// sizeof(struct udphdr)) so the clamp arithmetic below compiles on the host too;
// s3tap.bpf.c static-asserts the two agree.
#define UDP_HDR_LEN  8

// Decode a DNS name at buf[start] into presentation form ("a.b.com") in out.
// One bounded pass over the bytes (single loop is easier on the verifier than
// nested label loops). Compression pointers are NOT followed — we stop and mark
// truncated, which is fine: the query name (the only name decoded in-kernel) is
// never compressed; answer names are parsed in userspace. Returns offset just
// past the name.
static __always_inline __u32
dns_decode_name(const __u8 *buf, __u32 buf_len, __u32 start,
                char *out, __u8 *name_len, __u8 *truncated)
{
    __u32 pos = start, olen = 0, label_left = 0;
    // TRUNCATED IS THE DEFAULT, cleared only by the one exit that proves the name is whole:
    // reading its root label. Written the other way round (start 0, set it on each bad exit)
    // the iteration budget below became a SILENT exit that left the flag clear, so a
    // hostile query yielded qname_len 255 with truncated 0 — an over-long name reported as
    // a complete, confident hostname. Defaulting to 1 makes every future exit added to this
    // loop truncated-by-construction unless it explicitly says otherwise.
    __u8 trunc = 1, need_dot = 0;

    // 256 iterations consume any valid name (the wire form is <= 255 bytes; pos
    // advances every iteration), at half the verifier cost of scanning all 512.
    // A LEGAL name cannot reach this cap: 253 presentation chars max, so only a
    // malformed query runs it out, and running it out means the name is unfinished.
    for (int i = 0; i < 256; i++) {
        if (pos >= buf_len) break;             // ran off the copied bytes
        __u8 b = buf[pos & (DNS_SCRATCH_LEN - 1)];
        pos++;
        if (label_left == 0) {                 // expecting a length byte
            if (b == 0) { trunc = 0; break; }  // root label: name complete
            if ((b & 0xC0) == 0xC0) { pos++; break; } // pointer: stop, name unfinished
            if (b > 63) break;                 // malformed
            label_left = b;
            if (need_dot) {
                if (olen < QNAME_MAX) out[olen++] = '.';
                else break;                    // no room: the name is longer than we report
            }
            need_dot = 1;
        } else {                               // a label character
            if (olen < QNAME_MAX) out[olen++] = b;
            else break;
            label_left--;
        }
    }
    *name_len = (__u8)olen;
    *truncated = trunc;
    return pos;
}

// Big-endian 16-bit read from the scratch buffer (DNS wire is network order).
static __always_inline __u16 dns_be16(const __u8 *buf, __u32 off)
{
    return ((__u16)buf[off & (DNS_SCRATCH_LEN - 1)] << 8) |
           (__u16)buf[(off + 1) & (DNS_SCRATCH_LEN - 1)];
}

// The two fixed DNS header fields we read in-kernel. Named rather than spelled as
// bare offsets so the header walk reads as a walk.
static __always_inline __u16 dns_txn_id(const __u8 *buf)  { return dns_be16(buf, 0); }
static __always_inline __u16 dns_qdcount(const __u8 *buf) { return dns_be16(buf, 4); }

// The DNS QUERY header + question walk: gate on qdcount, then decode the question
// name that follows the fixed header. Returns 1 if a name was decoded (the caller
// may emit), 0 if the message names nothing.
//
// The qdcount gate is load-bearing, not cosmetic: a message with qdcount == 0 has
// no question section, so whatever bytes sit at DNS_HDR_LEN are answers, options
// or padding. Decoding them anyway would ship an attacker-chosen string as "the
// hostname this process resolved" without any question to have verified it
// against (review round 1).
//
// PRECONDITION: len >= DNS_HDR_LEN. Both the fixed-offset header reads and the
// question start assume the header is present; every caller checks this before
// calling (the send path's `n < DNS_HDR_LEN` gate, the recv path's clamp below).
static __always_inline int
dns_query_walk(const __u8 *buf, __u32 len, char *out, __u8 *name_len, __u8 *truncated)
{
    *name_len = 0;
    *truncated = 0;
    if (dns_qdcount(buf) == 0)      // no question section: nothing to name
        return 0;
    dns_decode_name(buf, len, DNS_HDR_LEN, out, name_len, truncated);
    return 1;
}

// How many DNS payload bytes may be copied out of a RECEIVED datagram, given the
// UDP header's declared length and the bytes actually present at the payload in
// the skb's linear head. Pure arithmetic, extracted so the clamp is unit-testable:
// this is the round-6 over-read.
//
// `udp_len` is the on-wire uh->len, so it is ATTACKER-CONTROLLED and may claim far
// more than the datagram holds — bounding by it alone let a malformed datagram
// pull up to 511 bytes of adjacent kernel memory into the event and ship them as
// DNS answers. `avail` is derived from kernel pointers (linear-head end minus the
// payload start) and is the real bound, so the smaller of the two wins. Returns 0
// when there is nothing safe, or nothing useful (a span clipped below a DNS
// header names nothing), to copy.
static __always_inline __u32
dns_response_copy_len(__u32 udp_len, __u64 avail)
{
    if (udp_len < UDP_HDR_LEN + DNS_HDR_LEN)
        return 0;
    __u32 n = udp_len - UDP_HDR_LEN;
    if (n > DNS_PAYLOAD_MAX - 1)
        n = DNS_PAYLOAD_MAX - 1;
    n &= (DNS_PAYLOAD_MAX - 1); // verifier-provable size bound for the copy
    if (n > avail)
        n = (__u32)avail;       // lossless: avail < n <= DNS_PAYLOAD_MAX-1 here
    if (n < DNS_HDR_LEN)
        return 0;               // clipped below a DNS header
    return n;
}

// --- TLS ----------------------------------------------------------------

// Single bounded read from the TLS scratch buffer. The `barrier_var(off)` is
// load-bearing and must come BEFORE the mask: as the parse accumulates `off`
// through length-prefixed fields, clang proves `off < len <= LEN` from the
// source-level `off+N > len` guards and concludes the `& (LEN-1)` mask is
// redundant — so it ELIDES the mask. The kernel verifier tracks `off`'s range
// far less precisely across that accumulation (it sees `off` climb past LEN),
// so the un-masked read is rejected ("invalid access to map value ... max value
// is outside of the allowed memory range" — observed on the 7.0.x verifier).
// Barriering `off` first hides its provable range from clang, forcing the mask
// to survive; the verifier then sees the read bounded to [0, LEN-1].
static __always_inline __u8 tls_u8(const __u8 *buf, __u32 off)
{
    barrier_var(off);
    return buf[off & (TLS_SCRATCH_LEN - 1)];
}

// Big-endian 16-bit read from the TLS scratch buffer, via two independently
// bounded `tls_u8` reads (TLS_SCRATCH_LEN is a power of two).
static __always_inline __u16 tls_be16(const __u8 *buf, __u32 off)
{
    return ((__u16)tls_u8(buf, off) << 8) | (__u16)tls_u8(buf, off + 1);
}

// Parse the SNI out of a ClientHello already copied into buf[0..len]. Writes up
// to SNI_MAX bytes into `out`, returns the count (0 if no server_name extension),
// and sets *truncated if the real name ran past SNI_MAX or past what we copied.
// Bounded everywhere: a malformed hello yields 0, never an OOB read or an
// unbounded loop. Offsets into the scratch are masked; `out` is bounded by the
// constant loop limit (SNI_MAX) against the event's 255-byte sni field.
//
// INVARIANT: `len` MUST be the number of bytes actually copied into the per-CPU
// scratch (n below), NOT the on-wire handshake/record length. Every read here is
// gated `off+N > len`; passing a larger len would let reads hit STALE bytes left
// by a previous ClientHello on this CPU (the scratch is reused, never zeroed) and
// emit them as SNI. The masks only bound reads to the map, not to copied data.
static __always_inline __u8
parse_client_hello_sni(const __u8 *buf, __u32 len, char *out, __u8 *truncated)
{
    *truncated = 0;
    // Fixed prefix: record(5) + handshake header(4) + client_version(2) +
    // random(32) = 43. session_id length byte is at 43.
    __u32 off = 43;
    if (off + 1 > len) return 0;
    __u32 sid_len = tls_u8(buf, off);
    off += 1 + sid_len;                       // skip session_id
    if (off + 2 > len) return 0;
    off += 2 + tls_be16(buf, off);            // skip cipher_suites (len-prefixed u16)
    if (off + 1 > len) return 0;
    off += 1 + tls_u8(buf, off); // skip compression_methods (u8 len)
    if (off + 2 > len) return 0;
    __u32 ext_end = off + 2 + tls_be16(buf, off); // end of the extensions block
    off += 2;
    if (ext_end > len) ext_end = len;         // clamp to what we actually copied

    // Walk extensions (a hello carries a few dozen at most).
    for (int i = 0; i < 64; i++) {
        if (off + 4 > ext_end) break;
        __u16 etype = tls_be16(buf, off);
        __u16 elen = tls_be16(buf, off + 2);
        off += 4;
        if (etype == 0) {                     // server_name extension
            // ext data: server_name_list_len(2) name_type(1) name_len(2) name...
            if (off + 5 > len) return 0;
            // Only host_name (name_type 0) carries an SNI; reject anything else so
            // we don't read a non-name entry's bytes AS a name (RFC 6066 reserves
            // the type byte; real clients always send host_name first).
            if (tls_u8(buf, off + 2) != 0) return 0;
            __u32 nlen = tls_be16(buf, off + 3);
            __u32 nstart = off + 5;
            // Bound the name to THIS extension's own declared end (off+elen),
            // clamped to the extensions block (ext_end). Without this, a
            // name_length that overruns its extension would pull the FOLLOWING
            // extensions' bytes — or trailing post-hello data coalesced into the
            // same send — into the SNI, emitting a wrong hostname. A well-formed
            // single host_name entry has elen == 5 + name_length, so a real name
            // is never clipped; anything longer is malformed → flagged truncated
            // (and then dropped userspace-side as a non-confident name).
            __u32 ext_data_end = off + elen;
            if (ext_data_end > ext_end) ext_data_end = ext_end;
            if (nstart >= ext_data_end) return 0; // no room for a name byte (elen < 5)
            __u32 avail = ext_data_end - nstart;
            if (nlen > avail) { nlen = avail; *truncated = 1; }
            if (nlen > SNI_MAX) { nlen = SNI_MAX; *truncated = 1; }
            // Re-assert the bound AT the copy site, the same barrier_var idiom as the DNS
            // and tcp_data copies. The clamps above are derived from `off`, which the
            // 5.8/5.9 verifier tracks far less precisely than clang does, so it loses the
            // range and rejects the copy size ("R2 min value is negative, either use
            // unsigned or 'var &= const'"). SNI_MAX is 255, so the mask is exactly the
            // clamp already applied and changes no value. NB this path only became
            // reachable on pre-6.4 kernels when msg_first_base learned their iov_iter
            // layout — before that it was verifier-dead there and the reject never showed.
            barrier_var(nlen);
            nlen &= SNI_MAX;   // 0xff — provable [0, SNI_MAX] bound for the copy below
            // One bounded copy, NOT a 255-iteration byte loop. The per-byte version
            // made the verifier explore ~1M states and hit the complexity limit on
            // 6.8 ("BPF program is too large"); 6.12+ prune it and accept. nlen is
            // already clamped to avail (= ext_data_end - nstart, and ext_data_end <=
            // ext_end <= len), so [nstart, nstart+nlen) lies within BOTH the copied
            // bytes and the scratch map — masking nstart makes that bound explicit
            // for the verifier, and the probe read is fault-safe regardless. `out`
            // (e->sni) is SNI_MAX bytes and nlen <= SNI_MAX, so it fits. The old
            // per-byte `nstart+k >= len` truncation flag can't fire given the avail
            // clamp (nstart+nlen <= len), so removing the loop loses nothing.
            bpf_probe_read_kernel(out, nlen, buf + (nstart & (TLS_SCRATCH_LEN - 1)));
            return (__u8)nlen;
        }
        off += elen;                          // not SNI: skip its data
    }
    return 0;
}

// Parse a ServerHello already copied into buf[0..len]. Writes the negotiated version and
// cipher; bounded everywhere (offsets masked to the scratch, ext loop capped). Mirrors
// parse_client_hello_sni but ServerHello has a SINGLE cipher_suite + compression byte.
static __always_inline void
parse_server_hello(const __u8 *buf, __u32 len, __u16 *version, __u16 *cipher)
{
    *version = 0;
    *cipher = 0;
    if (11 > len) return;
    __u16 legacy = tls_be16(buf, 9);         // legacy server_version (0x0303 for 1.2 AND 1.3)
    __u32 off = 43;                          // session_id length byte
    if (off + 1 > len) return;
    off += 1 + tls_u8(buf, off); // skip session_id
    if (off + 2 > len) return;
    *cipher = tls_be16(buf, off);            // negotiated cipher suite (fixed prefix; reliable)
    off += 2 + 1;                            // skip cipher(2) + compression_method(1)
    if (off + 2 > len) return;
    __u32 ext_end = off + 2 + tls_be16(buf, off); // end of extensions
    off += 2;
    // truncated = the declared extensions block runs past the copied bytes (split across TCP
    // segments / clamped). Matters because the legacy field is 0x0303 for BOTH 1.2 and 1.3,
    // so the negotiated version is only knowable from the supported_versions ext. If that ext
    // wasn't reached because the block was truncated, a 0x0303 is an UNCONFIRMED 1.3 — we must
    // NOT fabricate "TLS 1.2". Only a fully-walked (untruncated) block with no 0x002b proves a
    // genuine <=1.2. (This is the clamp flag the earlier review thought couldn't distinguish
    // truncated-1.3 from real-1.2 — it can.)
    __u8 truncated = ext_end > len;
    if (truncated) ext_end = len;
    // Walk extensions for supported_versions (0x002b): in a ServerHello its data is the
    // single 2-byte NEGOTIATED version (0x0304 = TLS 1.3).
    for (int i = 0; i < 64; i++) {
        if (off + 4 > ext_end) {
            // Walked the whole block with no supported_versions: legacy is authoritative for a
            // genuine <=1.2 ONLY if we actually saw the whole block. If truncated, leave
            // *version=0 (correlate maps 0 -> None) rather than mislabel a 1.3 as 1.2.
            if (!truncated) *version = legacy;
            return;
        }
        __u16 etype = tls_be16(buf, off);
        __u16 elen = tls_be16(buf, off + 2);
        off += 4;
        if (etype == 0x002b) {               // supported_versions -> the negotiated version
            // Gate on the ext's OWN declared length (>=2) AND its block end, not just the copied
            // len, so a malformed elen==0/1 can't pull the next extension's bytes as the version
            // (mirrors the strict bounds discipline in parse_client_hello_sni).
            if (elen >= 2 && off + 2 <= ext_end) *version = tls_be16(buf, off);
            return;
        }
        off += elen;
    }
    // 64-extension cap hit without finding supported_versions: unconfirmed, leave *version=0.
}

// --- HTTP head recognizers ----------------------------------------------
//
// PRIVACY + FLOOD GATE: only capture a buffer that BEGINS an HTTP message — a
// request line (write) or a status line (read). This drops request/response BODIES
// (object data on PUT/POST, every SSL_read of a large GET — a flood + leak), AND
// any whole method not listed below. Tradeoffs: the request check requires
// `METHOD<sp>/` (the path), and the response check requires `HTTP/1.`, so an
// uploaded/served HTTP-log object that happens to start with those exact bytes is a
// rare false positive (captured as if it were a head). The S3 data-plane verbs
// (GET/PUT/POST/HEAD/DELETE) plus OPTIONS (CORS preflight) are captured; any verb
// not listed is dropped. (A small body coalesced INTO the header write is still
// captured up to HDR_CAP; the header/body split within one buffer is an E5
// refinement. OPTIONS/DELETE match the method token only — no trailing `/` — so
// they're marginally looser than the others; acceptable for control/rare verbs.)
//
// CONTRACT: `h` must hold at least 7 readable bytes. Both recognizers index up to
// h[6] (OPTIONS is the longest token, "HTTP/1." is exactly 7), and neither knows
// how much was written — so every caller gates on `count >= 7` and passes a
// zero-initialized 8-byte staging buffer, never the raw user pointer. A shorter
// read would test stale/unwritten bytes and could false-match (review L1).
static __always_inline int looks_like_http_request(const __u8 *h)
{
    // method + ' ' + '/': S3 always uses an absolute-path origin-form request line.
    if (h[0]=='G'&&h[1]=='E'&&h[2]=='T'&&h[3]==' '&&h[4]=='/') return 1;          // GET /
    if (h[0]=='P'&&h[1]=='U'&&h[2]=='T'&&h[3]==' '&&h[4]=='/') return 1;          // PUT /
    if (h[0]=='H'&&h[1]=='E'&&h[2]=='A'&&h[3]=='D'&&h[4]==' '&&h[5]=='/') return 1; // HEAD /
    if (h[0]=='P'&&h[1]=='O'&&h[2]=='S'&&h[3]=='T'&&h[4]==' '&&h[5]=='/') return 1; // POST /
    if (h[0]=='O'&&h[1]=='P'&&h[2]=='T'&&h[3]=='I'&&h[4]=='O'&&h[5]=='N'&&h[6]=='S') return 1; // OPTIONS (CORS preflight)
    if (h[0]=='D'&&h[1]=='E'&&h[2]=='L'&&h[3]=='E'&&h[4]=='T'&&h[5]=='E') return 1; // DELETE
    return 0;
}

static __always_inline int looks_like_http_response(const __u8 *h)
{
    // "HTTP/1." — tighter than "HTTP/" so an object body whose first bytes are
    // literally "HTTP/" is far less likely to be captured as a status line.
    return h[0]=='H'&&h[1]=='T'&&h[2]=='T'&&h[3]=='P'&&h[4]=='/'&&h[5]=='1'&&h[6]=='.';
}

#endif // S3TAP_PARSE_H
