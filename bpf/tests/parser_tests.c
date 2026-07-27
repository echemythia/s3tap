// bpf/tests/parser_tests.c
//
// Unit tests for the eBPF program's byte parsers — the FIRST tests the C has had.
//
// WHY THESE EXIST. Until now bpf/src/s3tap.bpf.c was checked by exactly one gate:
// does it load. That gate is weaker than it looks. The verifier only walks code it
// can REACH, so a CO-RE relocation that makes a function return early turns
// everything downstream into dead code it never examines — a PASS then means
// "loads" OR "compiled out on this kernel", indistinguishably. That is not a
// hypothetical: two genuine 5.8 verifier rejects sat hidden behind exactly that
// for several rounds. And even a real verifier PASS says nothing about whether a
// parser reads the RIGHT bytes: the verifier proves memory safety within the
// program's own maps, not that a length field was honoured.
//
// The parsers here all consume ATTACKER-INFLUENCED input — a DNS message from the
// network, a TLS ClientHello/ServerHello off the wire, the first bytes of an HTTP
// message — so they are simultaneously the most security-relevant code in the
// program and the code the load gate covers least. They are also pure (bytes in,
// bytes out), which is why they could be lifted into s3tap_parse.h and driven
// from here with no kernel, no root and no VM. That is the point: this runs as a
// per-PR gate on an ordinary CI runner.
//
// HOW AN OVER-READ IS CAUGHT. In the kernel these parsers read out of a per-CPU
// ARRAY map and mask every offset with (map_size - 1), so an offset the length
// checks should have rejected still lands INSIDE the map. The read succeeds and
// returns whatever the previous message on this CPU left there. That is what
// makes this bug class silent. `scratch_init` reproduces that geometry exactly —
// a region of the map's size holding `len` valid bytes — and then puts a GUARD
// PAGE where the copied bytes end, so reading even one byte past `len` is a
// SIGSEGV the harness reports with the exact offset.
//
// Guard pages rather than ASan poisoning, deliberately. Poisoning was tried
// first and is NOT sufficient here: ASan's shadow has 8-byte granularity and its
// inline check consults only the shadow byte of the access's FIRST byte, so a
// 2-byte read straddling the last valid granule into the poisoned one is missed
// entirely. That is exactly the shape of these parsers' reads (`tls_be16` is two
// bytes at an arbitrary offset), and a real off-by-one mutation slipped through
// undetected because of it. An mprotect(PROT_NONE) boundary is byte-exact, has
// no such blind spot, and works even in a build with no sanitizer at all.
// ASan/UBSan are still on: they cover the OUTPUT buffers (each sized to exactly
// the event field it models, so an overrun is a heap-buffer-overflow) and
// integer/shift UB in the parsers. `--overread-selfcheck` proves the guard is
// actually armed before the suite is believed.
//
// Run with `just bpf-test`.

#define S3TAP_HOST_TEST 1
#include "s3tap_host_shim.h"   // types, __always_inline, barrier_var, the read helper
#include "s3tap_parse.h"       // THE CODE UNDER TEST — the same text the BPF build compiles

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define S3TAP_ASAN 1
#  endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#  define S3TAP_ASAN 1
#endif

// ===========================================================================
// Tiny test harness
// ===========================================================================

static int g_fail;             // failed assertions, total
static int g_checks;           // assertions run
static int g_cases;            // test cases run
static const char *g_case = "";
static int g_case_fail;

static void case_begin(const char *name)
{
    g_case = name;
    g_case_fail = 0;
    g_cases++;
}

static void case_end(void)
{
    printf("  %s %s\n", g_case_fail ? "FAIL" : "ok  ", g_case);
}

static void fail(int line, const char *expr, const char *fmt, ...)
{
    va_list ap;
    g_fail++;
    g_case_fail = 1;
    printf("  FAIL %s (line %d)\n        %s\n", g_case, line, expr);
    if (fmt) {
        printf("        ");
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        printf("\n");
    }
}

#define CHECK(cond)                                                            \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) fail(__LINE__, #cond, NULL);                              \
    } while (0)

#define CHECK_EQ(got, want)                                                    \
    do {                                                                       \
        long long g_ = (long long)(got), w_ = (long long)(want);               \
        g_checks++;                                                            \
        if (g_ != w_)                                                          \
            fail(__LINE__, #got " == " #want,                                  \
                 "got %lld (0x%llx), want %lld (0x%llx)", g_, g_, w_, w_);     \
    } while (0)

#define CHECK_BYTES(got, want, n)                                              \
    do {                                                                       \
        g_checks++;                                                            \
        if (memcmp((got), (want), (n)) != 0)                                   \
            fail(__LINE__, #got " == " #want, "%u bytes differ", (unsigned)(n));\
    } while (0)

// ===========================================================================
// The modelled per-CPU scratch map
// ===========================================================================

// Filler for a freshly-allocated OUTPUT buffer. Nothing in a parser may leave it
// behind inside the range it reports as written: `has_unwritten(out, n)` after a
// call that returned n is how "never reports a length longer than what it
// actually copied" is checked.
#define UNWRITTEN 0xA5

static long g_pagesz;

struct scratch {
    unsigned char *base;  // the mapping
    size_t map_size;
    unsigned char *buf;   // what the parser is handed
    __u32 cap;            // the BPF map's value size (what offsets are masked to)
    __u32 len;            // bytes actually copied in — the parser's `len` argument
};

static struct scratch *g_live;   // the scratch in play, for the SIGSEGV reporter

// Build a scratch holding `len` valid bytes inside a `cap`-byte map slot, with a
// GUARD PAGE starting exactly at buf+len.
//
// The mapping is [readable pages][PROT_NONE pages] and `buf` is placed so that
// buf+len falls precisely on the boundary. So offsets [0, len) read normally and
// every offset in [len, cap) — the whole range the parsers' masks can still
// reach — faults. That is byte-exact, which ASan's 8-byte-granular poisoning is
// not (see the header comment): the point of this harness is to catch an
// off-by-one, and an approximate boundary cannot.
static void scratch_init(struct scratch *s, __u32 cap, const void *data, __u32 len)
{
    size_t head, tail;
    if (len > cap) {
        printf("BUG in test: len %u > cap %u\n", len, cap);
        exit(2);
    }
    head = ((size_t)len + (size_t)g_pagesz - 1) / (size_t)g_pagesz * (size_t)g_pagesz;
    tail = ((size_t)cap + (size_t)g_pagesz - 1) / (size_t)g_pagesz * (size_t)g_pagesz
           + (size_t)g_pagesz;
    s->map_size = head + tail;
    s->base = (unsigned char *)mmap(NULL, s->map_size, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (s->base == MAP_FAILED) { perror("mmap"); exit(2); }
    if (mprotect(s->base + head, tail, PROT_NONE) != 0) { perror("mprotect"); exit(2); }
    s->buf = s->base + head - len;
    s->cap = cap;
    s->len = len;
    memcpy(s->buf, data, len);
    s3tap_shim_set_valid(s->buf, len);
    g_live = s;
}

static void scratch_free(struct scratch *s)
{
    g_live = NULL;
    munmap(s->base, s->map_size);
    s->base = s->buf = NULL;
    s3tap_shim_set_valid(NULL, 0);
}

// Async-signal-safe-ish reporter for the guard page. A read past the copied bytes
// lands here, and the offset it prints is the offset the parser used — which is
// the whole diagnosis.
static void write_str(const char *p) { ssize_t r = write(2, p, strlen(p)); (void)r; }
static void write_long(long v)
{
    char b[32]; int i = 31; int neg = v < 0; unsigned long u = neg ? (unsigned long)-v : (unsigned long)v;
    b[i--] = '\0';
    do { b[i--] = (char)('0' + (u % 10)); u /= 10; } while (u);
    if (neg) b[i--] = '-';
    write_str(&b[i + 1]);
}

static void on_segv(int sig, siginfo_t *si, void *uctx)
{
    (void)sig; (void)uctx;
    write_str("\n*** OVER-READ DETECTED ***\n  case: ");
    write_str(g_case);
    if (g_live && g_live->buf) {
        write_str("\n  read at scratch offset ");
        write_long((long)((unsigned char *)si->si_addr - g_live->buf));
        write_str(", but only ");
        write_long((long)g_live->len);
        write_str(" bytes were copied in (map slot is ");
        write_long((long)g_live->cap);
        write_str(" bytes)\n");
    } else {
        write_str("\n  (no scratch in play — a genuine crash)\n");
    }
    write_str("  the guard page immediately after the copied bytes caught it\n");
    _exit(1);
}

static void install_guard_reporter(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

// Every parser call is followed by this. The guard page already makes a byte-read
// past `len` fatal; this covers the one path that copies in BULK
// (bpf_probe_read_kernel), where the shim can say exactly how far it ran.
static void check_no_overread(void)
{
    g_checks++;
    if (s3tap_shim_overreads != 0)
        fail(__LINE__, "bpf_probe_read_kernel stayed within the copied bytes",
             "%lu of %lu reads ran past len (furthest byte: %lu)",
             s3tap_shim_overreads, s3tap_shim_reads, s3tap_shim_max_end);
}

// An output buffer sized EXACTLY like the event field the parser writes into, so
// a one-byte overrun is an ASan heap-buffer-overflow rather than slack. Pre-filled
// with UNWRITTEN so the reported length can be checked against what was written.
static unsigned char *out_alloc(size_t n)
{
    unsigned char *p = (unsigned char *)malloc(n);
    if (!p) { perror("malloc"); exit(2); }
    memset(p, UNWRITTEN, n);
    return p;
}

// Does the range the parser CLAIMS to have written still contain filler? If so it
// reported a length longer than it actually copied.
static int has_unwritten(const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < n; i++)
        if (b[i] == UNWRITTEN) return 1;
    return 0;
}

// ===========================================================================
// Byte-buffer builder
// ===========================================================================

struct bb {
    unsigned char b[8192];
    __u32 len;
};

static void bb_reset(struct bb *w) { memset(w, 0, sizeof(*w)); }
static void bb_u8(struct bb *w, unsigned v) { w->b[w->len++] = (unsigned char)v; }
static void bb_be16(struct bb *w, unsigned v) { bb_u8(w, v >> 8); bb_u8(w, v); }
static void bb_be24(struct bb *w, unsigned v) { bb_u8(w, v >> 16); bb_u8(w, v >> 8); bb_u8(w, v); }
static void bb_rep(struct bb *w, unsigned char v, __u32 n)
{
    memset(w->b + w->len, v, n);
    w->len += n;
}
static void bb_mem(struct bb *w, const void *p, __u32 n)
{
    memcpy(w->b + w->len, p, n);
    w->len += n;
}

// The fixed 43-byte prefix shared by ClientHello and ServerHello:
// record header(5) + handshake header(4) + version(2) + random(32). The parsers
// index straight past it to the session_id length byte at offset 43, so its
// internal lengths are never read by them (only the caller reads offset 9..10).
static void tls_prefix(struct bb *w, unsigned hs_type, unsigned version)
{
    bb_u8(w, 0x16); bb_u8(w, 0x03); bb_u8(w, 0x01);  // handshake record, TLS 1.0 record ver
    bb_be16(w, 0);                                    // record length (unread by the parsers)
    bb_u8(w, hs_type);                                // 0x01 ClientHello / 0x02 ServerHello
    bb_be24(w, 0);                                    // handshake length (unread)
    bb_be16(w, version);                              // legacy client_/server_version @ 9
    bb_rep(w, 0x5a, 32);                              // random @ 11..42
}

// Wire-format DNS name: length-prefixed labels then the root 0.
static void dns_name(struct bb *w, const char *dotted)
{
    const char *p = dotted;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t n = dot ? (size_t)(dot - p) : strlen(p);
        bb_u8(w, (unsigned)n);
        bb_mem(w, p, (__u32)n);
        p = dot ? dot + 1 : p + n;
    }
    bb_u8(w, 0);
}

// A 12-byte DNS header with the given transaction id and counts.
static void dns_hdr(struct bb *w, unsigned id, unsigned flags, unsigned qd, unsigned an)
{
    bb_be16(w, id); bb_be16(w, flags);
    bb_be16(w, qd); bb_be16(w, an);
    bb_be16(w, 0);  bb_be16(w, 0);
}

// ===========================================================================
// DNS: the header/question walk and the name decoder
// ===========================================================================

static void test_dns(void)
{
    struct bb w;
    struct scratch s;
    unsigned char *out;
    __u8 nl, tr;
    __u32 end;

    // --- the qdcount gate -------------------------------------------------
    // A message with qdcount == 0 has NO question section, so the bytes sitting
    // at the question offset are answers, options or padding — attacker-chosen
    // either way. Decoding them anyway would ship a hostname the message never
    // asked about (review round 1). The walk must decline outright.
    case_begin("dns: qdcount == 0 names nothing, even with a valid name after the header");
    bb_reset(&w);
    dns_hdr(&w, 0x1234, 0x0100, /*qd*/0, /*an*/0);
    dns_name(&w, "evil.example.com");
    bb_be16(&w, 1); bb_be16(&w, 1);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    CHECK_EQ(dns_query_walk(s.buf, s.len, (char *)out, &nl, &tr), 0);
    CHECK_EQ(nl, 0);
    CHECK_EQ(tr, 0);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // The same message with qdcount == 1 IS decoded — otherwise the test above
    // would pass against a walk that never decodes anything at all.
    case_begin("dns: qdcount == 1 decodes the question name");
    bb_reset(&w);
    dns_hdr(&w, 0x1234, 0x0100, 1, 0);
    dns_name(&w, "bucket.s3.us-east-1.amazonaws.com");
    bb_be16(&w, 1); bb_be16(&w, 1);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    CHECK_EQ(dns_query_walk(s.buf, s.len, (char *)out, &nl, &tr), 1);
    CHECK_EQ(nl, strlen("bucket.s3.us-east-1.amazonaws.com"));
    CHECK_EQ(tr, 0);
    CHECK_BYTES(out, "bucket.s3.us-east-1.amazonaws.com", nl);
    CHECK_EQ(dns_txn_id(s.buf), 0x1234);
    CHECK_EQ(dns_qdcount(s.buf), 1);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- compression pointers --------------------------------------------
    // A pointer is not followed: the query name we decode in-kernel is never
    // compressed, and following one needs a visited-set the verifier will not
    // allow. Stop, flag truncated, keep only what was already decoded.
    case_begin("dns: a compression pointer stops the decode and flags truncated");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x8180, 1, 1);
    bb_u8(&w, 3); bb_mem(&w, "foo", 3);
    bb_u8(&w, 0xC0); bb_u8(&w, 0x0C);          // pointer back to the header
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    end = dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, 3);
    CHECK_EQ(tr, 1);
    CHECK_BYTES(out, "foo", 3);
    CHECK(end <= s.len + 1);                    // consumed the pointer, went no further
    CHECK(!has_unwritten(out, nl));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A pointer to ITSELF. A parser that followed pointers without a visited-set
    // would loop here; this one must terminate having decoded nothing. The
    // assertion that bites is name_len == 0: a follower would spin the 256-
    // iteration budget appending the same labels over and over.
    case_begin("dns: a self-referential compression pointer terminates with no name");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x8180, 1, 0);
    bb_u8(&w, 0xC0); bb_u8(&w, 0x0C);          // at offset 12, pointing at offset 12
    bb_u8(&w, 3); bb_mem(&w, "foo", 3); bb_u8(&w, 0);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    end = dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, 0);
    CHECK_EQ(tr, 1);
    CHECK_EQ(end, DNS_HDR_LEN + 2);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A two-pointer cycle (A -> B -> A), the shape a naive visited-check misses.
    case_begin("dns: a two-hop pointer cycle terminates with no name");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x8180, 1, 0);
    bb_u8(&w, 0xC0); bb_u8(&w, 0x0E);          // @12 -> 14
    bb_u8(&w, 0xC0); bb_u8(&w, 0x0C);          // @14 -> 12
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, 0);
    CHECK_EQ(tr, 1);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- lengths that run past the buffer --------------------------------
    // THE over-read case. A label claims 0x30 bytes but only 2 are present. The
    // decoder must stop at the end of the COPIED bytes, not at the end of the
    // 512-byte map its offsets are masked into. Without the `pos >= buf_len`
    // guard this reads the poisoned tail (ASan aborts) and emits it as a
    // hostname.
    case_begin("dns: a label length running past the copied bytes stops at the boundary");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x0100, 1, 0);
    bb_u8(&w, 0x30); bb_mem(&w, "ab", 2);      // claims 48 bytes, supplies 2
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    end = dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, 2);
    CHECK_EQ(tr, 1);
    CHECK_BYTES(out, "ab", 2);
    CHECK_EQ(end, s.len);                       // stopped exactly at the copied end
    CHECK(!has_unwritten(out, nl));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A label length byte above 63 is malformed (the top two bits are reserved
    // for the pointer form) and must not be read as a length.
    case_begin("dns: a label length above 63 is rejected as malformed");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x0100, 1, 0);
    bb_u8(&w, 2); bb_mem(&w, "hi", 2);
    bb_u8(&w, 0x7f);                            // 127: not a pointer, not a legal length
    bb_rep(&w, 'x', 100);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, 2);
    CHECK_EQ(tr, 1);
    CHECK_BYTES(out, "hi", 2);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- the QNAME_MAX boundary -------------------------------------------
    // 253 chars is the real DNS presentation maximum, and it is no accident: a
    // valid wire name is <= 255 bytes INCLUDING its length bytes and the root
    // label, and the decode drops exactly two of those (one length byte becomes
    // nothing, the root becomes nothing) while turning the rest into dots. So the
    // longest LEGAL name is 253, and the 255-byte qname field always has room.
    // 63.63.63.61 = 250 chars + 3 dots = 253.
    case_begin("dns: the longest legal name (253 chars) fits untruncated");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x0100, 1, 0);
    for (int i = 0; i < 3; i++) { bb_u8(&w, 63); bb_rep(&w, (unsigned char)('a' + i), 63); }
    bb_u8(&w, 61); bb_rep(&w, 'd', 61);
    bb_u8(&w, 0);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, 253);
    CHECK_EQ(tr, 0);
    CHECK_EQ(out[62], 'a');
    CHECK_EQ(out[63], '.');
    CHECK_EQ(out[252], 'd');
    CHECK(!has_unwritten(out, nl));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A name past the decoder's 256-iteration budget. The budget is what actually
    // bounds this loop: every iteration consumes exactly one wire byte and emits
    // at most one output byte, so output == iterations - 1 and the 255-byte field
    // can never be overrun no matter what the input says. `out` is allocated at
    // exactly QNAME_MAX so ASan would catch it if that ever stopped being true.
    //
    // THIS TEST FOUND A DEFECT, now FIXED: exhausting the budget used to be the one
    // exit that left `truncated` at 0, so an over-long name was reported as a COMPLETE
    // 255-byte hostname — a confident answer built from a hostile query. Every other
    // exit (buffer end, compression pointer, bad label length) already set the flag. A
    // legal name cannot reach the budget (253 chars max, ~255 iterations), so only a
    // malformed query gets here, which is exactly the input class that matters. The
    // decoder now defaults `truncated` to 1 and clears it only on the root label, so
    // this exit and any exit added later are truncated by construction.
    case_begin("dns: a name past the 256-iteration budget stops at 255 bytes and flags truncated");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x0100, 1, 0);
    for (int i = 0; i < 4; i++) { bb_u8(&w, 63); bb_rep(&w, (unsigned char)('a' + i), 63); }
    bb_u8(&w, 3); bb_mem(&w, "top", 3);
    bb_u8(&w, 0);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);           // exactly the field size: a 256th write aborts
    end = dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
    CHECK_EQ(nl, QNAME_MAX);              // filled the field, never past it
    CHECK_EQ(end, DNS_HDR_LEN + 256);     // stopped on the budget, not the buffer
    CHECK_EQ(tr, 1);                      // the name is unfinished, and says so
    CHECK(!has_unwritten(out, nl));
    CHECK_BYTES(out, "aaa", 3);           // what it did return is a genuine prefix
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- the 511-byte scratch boundary ------------------------------------
    // The copy into the DNS scratch is masked with (512 - 1), so the most that
    // can ever be present is 511 bytes — and offset 511 is then the FIRST byte of
    // the stale tail. This is the boundary behind the over-read closed in round 6.
    //
    // A name that starts at the header offset can never REACH 511 (the iteration
    // budget stops it at 268 first), so the boundary is exercised where it is
    // actually reachable: a name late in the message, with a label claiming more
    // bytes than remain. It must stop AT 511 and never read byte 511.
    case_begin("dns: a label at the 511-byte scratch limit stops without reading past it");
    bb_reset(&w);
    dns_hdr(&w, 1, 0x8180, 1, 1);
    bb_rep(&w, 0x2e, 499 - 12);                  // filler answer bytes up to offset 499
    CHECK_EQ(w.len, 499);
    bb_u8(&w, 60);                               // a label claiming 60 bytes...
    bb_rep(&w, 'z', 11);                         // ...with only 11 present before 511
    CHECK_EQ(w.len, DNS_SCRATCH_LEN - 1);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);   // len == 511; byte 511 is poisoned
    out = out_alloc(QNAME_MAX);
    end = dns_decode_name(s.buf, s.len, /*start*/499, (char *)out, &nl, &tr);
    CHECK_EQ(tr, 1);
    CHECK_EQ(end, DNS_SCRATCH_LEN - 1);          // stopped AT 511, never read it
    CHECK_EQ(nl, 11);                            // only the bytes that were really there
    CHECK(!has_unwritten(out, nl));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // The same message read as a full 511-byte scratch from the header offset:
    // a normal short name, with 400+ bytes of stale-adjacent payload after it.
    case_begin("dns: a full 511-byte scratch decodes its question and stops there");
    bb_reset(&w);
    dns_hdr(&w, 0x4242, 0x8180, 1, 4);
    dns_name(&w, "a.very.ordinary.example.com");
    bb_be16(&w, 1); bb_be16(&w, 1);
    bb_rep(&w, 0xc0, DNS_SCRATCH_LEN - 1 - w.len);   // answer RRs, full of pointer bytes
    CHECK_EQ(w.len, DNS_SCRATCH_LEN - 1);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    CHECK_EQ(dns_query_walk(s.buf, s.len, (char *)out, &nl, &tr), 1);
    CHECK_EQ(nl, strlen("a.very.ordinary.example.com"));
    CHECK_EQ(tr, 0);
    CHECK_BYTES(out, "a.very.ordinary.example.com", nl);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // The minimum the callers ever pass: a bare 12-byte header and nothing else.
    case_begin("dns: a bare header with qdcount 1 and no question decodes nothing");
    bb_reset(&w);
    dns_hdr(&w, 0xbeef, 0x0100, 1, 0);
    CHECK_EQ(w.len, DNS_HDR_LEN);
    scratch_init(&s, DNS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(QNAME_MAX);
    CHECK_EQ(dns_query_walk(s.buf, s.len, (char *)out, &nl, &tr), 1);
    CHECK_EQ(nl, 0);
    CHECK_EQ(tr, 1);                            // nothing there: truncated, not a name
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // The reported length must never exceed the wire bytes the decode consumed.
    // (Each label costs a length byte and yields at most one dot plus its chars,
    // so output is always strictly shorter than input.)
    case_begin("dns: reported name_len never exceeds the bytes consumed");
    for (__u32 cut = DNS_HDR_LEN; cut <= 60; cut++) {
        bb_reset(&w);
        dns_hdr(&w, 1, 0x0100, 1, 0);
        dns_name(&w, "some.rather.long.example.hostname.test");
        scratch_init(&s, DNS_SCRATCH_LEN, w.b, cut);   // truncate at every offset
        out = out_alloc(QNAME_MAX);
        end = dns_decode_name(s.buf, s.len, DNS_HDR_LEN, (char *)out, &nl, &tr);
        CHECK(nl <= end - DNS_HDR_LEN);
        CHECK(end <= cut + 1);
        CHECK(!has_unwritten(out, nl));
        check_no_overread();
        free(out); scratch_free(&s);
    }
    case_end();
}

// ===========================================================================
// DNS response: the copy-length clamp (the round-6 over-read)
// ===========================================================================

static void test_dns_response_clamp(void)
{
    // uh->len is on-wire and therefore attacker-controlled. `avail` comes from
    // kernel pointers. The smaller must win, or the fault-safe copy reads
    // adjacent kernel memory and ships it as DNS answers.
    case_begin("dns response: an over-claiming uh->len is clamped to the bytes present");
    CHECK_EQ(dns_response_copy_len(/*uh->len*/1000, /*avail*/100), 100);
    CHECK_EQ(dns_response_copy_len(60000, 40), 40);
    CHECK_EQ(dns_response_copy_len(0xffff, 12), 12);
    case_end();

    case_begin("dns response: the length is capped at the 511-byte scratch limit");
    // 600-byte payload, plenty available: still clipped to DNS_PAYLOAD_MAX - 1.
    CHECK_EQ(dns_response_copy_len(8 + 600, 4096), DNS_PAYLOAD_MAX - 1);
    // Exactly at the cap.
    CHECK_EQ(dns_response_copy_len(8 + 511, 4096), 511);
    // One under.
    CHECK_EQ(dns_response_copy_len(8 + 510, 4096), 510);
    // The cap and the availability bound agree at the boundary.
    CHECK_EQ(dns_response_copy_len(8 + 600, 511), 511);
    CHECK_EQ(dns_response_copy_len(8 + 600, 510), 510);
    case_end();

    case_begin("dns response: a span clipped below a DNS header is refused");
    CHECK_EQ(dns_response_copy_len(8 + 100, 11), 0);   // 11 < DNS_HDR_LEN
    CHECK_EQ(dns_response_copy_len(8 + 100, 12), 12);  // exactly a header: usable
    CHECK_EQ(dns_response_copy_len(8 + 100, 0), 0);    // payload entirely in page frags
    case_end();

    case_begin("dns response: a uh->len too short to hold a DNS header is refused");
    CHECK_EQ(dns_response_copy_len(0, 4096), 0);
    CHECK_EQ(dns_response_copy_len(8, 4096), 0);       // header only, no payload
    CHECK_EQ(dns_response_copy_len(8 + 11, 4096), 0);  // one byte short of a DNS header
    CHECK_EQ(dns_response_copy_len(8 + 12, 4096), 12); // exactly a DNS header
    case_end();

    // The property the call site depends on, over the whole interesting range:
    // the result never exceeds what is actually there, and never exceeds the
    // scratch. Either would be an out-of-bounds kernel read.
    case_begin("dns response: result <= avail and <= the scratch cap, exhaustively");
    for (__u32 ul = 0; ul < 1400; ul++) {
        for (__u64 av = 0; av < 600; av += 7) {
            __u32 n = dns_response_copy_len(ul, av);
            CHECK(n <= av);
            CHECK(n <= DNS_PAYLOAD_MAX - 1);
            CHECK(n == 0 || n >= DNS_HDR_LEN);
            CHECK(n == 0 || (__u64)n + UDP_HDR_LEN <= ul);
        }
    }
    case_end();
}

// ===========================================================================
// TLS ClientHello: the SNI parse
// ===========================================================================

// Assemble a ClientHello whose extensions block is `ext`. `sid_len`/`cs_len`/
// `comp_len` are the DECLARED lengths (which a hostile hello may over-state);
// the matching *_have counts are what is really written.
static void build_client_hello(struct bb *w,
                               unsigned sid_len, unsigned sid_have,
                               unsigned cs_len, unsigned cs_have,
                               unsigned comp_len, unsigned comp_have,
                               unsigned declared_ext_len, const struct bb *ext)
{
    bb_reset(w);
    tls_prefix(w, 0x01, 0x0303);
    bb_u8(w, sid_len);            bb_rep(w, 0x11, sid_have);
    bb_be16(w, cs_len);           bb_rep(w, 0x22, cs_have);
    bb_u8(w, comp_len);           bb_rep(w, 0x00, comp_have);
    bb_be16(w, declared_ext_len);
    if (ext) bb_mem(w, ext->b, ext->len);
}

// A well-formed server_name extension carrying `name`.
static void ext_server_name(struct bb *e, const char *name, __u32 name_len)
{
    bb_be16(e, 0x0000);              // extension_type = server_name
    bb_be16(e, 5 + name_len);        // extension_data length
    bb_be16(e, 3 + name_len);        // server_name_list length
    bb_u8(e, 0);                     // name_type = host_name
    bb_be16(e, name_len);            // name length
    bb_mem(e, name, name_len);
}

static void test_client_hello(void)
{
    struct bb w, e;
    struct scratch s;
    unsigned char *out;
    __u8 tr, n;
    char big[512];

    // The happy path first, so every "returns 0" test below means something.
    case_begin("clienthello: a well-formed hello yields its SNI");
    bb_reset(&e);
    bb_be16(&e, 0x000b); bb_be16(&e, 2); bb_be16(&e, 0x0100);   // ec_point_formats, first
    ext_server_name(&e, "bucket.s3.amazonaws.com", 23);
    bb_be16(&e, 0x0017); bb_be16(&e, 0);                        // extended_master_secret, after
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 23);
    CHECK_EQ(tr, 0);
    CHECK_BYTES(out, "bucket.s3.amazonaws.com", 23);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- no SNI -----------------------------------------------------------
    // IP-based TLS and many non-browser clients send no server_name at all. The
    // parser must return 0 rather than reach for whatever extension is there.
    case_begin("clienthello: a hello with no server_name extension yields nothing");
    bb_reset(&e);
    bb_be16(&e, 0x000b); bb_be16(&e, 2); bb_be16(&e, 0x0100);
    bb_be16(&e, 0x000a); bb_be16(&e, 4); bb_be16(&e, 2); bb_be16(&e, 0x001d);
    bb_be16(&e, 0x0017); bb_be16(&e, 0);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 0);
    CHECK_EQ(tr, 0);
    CHECK(!has_unwritten(out, n));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A hello with NO extensions block at all (the block length is 0).
    case_begin("clienthello: an empty extensions block yields nothing");
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, 0, NULL);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- the SNI_MAX boundary --------------------------------------------
    // 255 is both RFC 6066's hostname bound and the size of the event's `sni`
    // field. A name of exactly that length must land whole, with no flag.
    case_begin("clienthello: an SNI of exactly SNI_MAX lands whole and untruncated");
    memset(big, 'h', sizeof(big));
    bb_reset(&e);
    ext_server_name(&e, big, SNI_MAX);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);              // exactly the field: a 256th byte aborts
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, SNI_MAX);
    CHECK_EQ(tr, 0);
    CHECK_BYTES(out, big, SNI_MAX);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // One byte longer. The clamp must fire and flag it, not write byte 256.
    case_begin("clienthello: an SNI one byte over SNI_MAX is clamped and flagged");
    bb_reset(&e);
    ext_server_name(&e, big, SNI_MAX + 1);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, SNI_MAX);
    CHECK_EQ(tr, 1);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- a length field claiming more than the buffer holds ---------------
    // THE over-read case for this parser. The extension says the name is 4000
    // bytes; the hello is a few hundred. Bounding by the declared name length
    // would read the stale scratch tail (ASan aborts) and emit it as a hostname.
    // The name must be clipped to what the extension and the copied bytes really
    // contain, and flagged so userspace drops it as non-confident.
    case_begin("clienthello: an over-claiming name_length is clamped to the bytes present");
    bb_reset(&e);
    bb_be16(&e, 0x0000);
    bb_be16(&e, 5 + 10);              // extension_data length: honest (10-byte name)
    bb_be16(&e, 3 + 10);
    bb_u8(&e, 0);
    bb_be16(&e, 4000);                // name length: a lie
    bb_mem(&e, "short.name", 10);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 10);
    CHECK_EQ(tr, 1);
    CHECK_BYTES(out, "short.name", 10);
    CHECK(!has_unwritten(out, n));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // The same lie told by the EXTENSION length instead, with real bytes sitting
    // after it. Without the ext_data_end bound the name would swallow the
    // following extension's bytes and emit a hostname that was never requested.
    case_begin("clienthello: a name_length overrunning its extension cannot pull later extensions");
    bb_reset(&e);
    bb_be16(&e, 0x0000);
    bb_be16(&e, 5 + 4);               // extension_data length: 4-byte name
    bb_be16(&e, 3 + 4);
    bb_u8(&e, 0);
    bb_be16(&e, 200);                 // name length: overruns its own extension
    bb_mem(&e, "abcd", 4);
    bb_be16(&e, 0x0017); bb_be16(&e, 40); bb_rep(&e, 'Z', 40);  // the next extension
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 4);
    CHECK_EQ(tr, 1);
    CHECK_BYTES(out, "abcd", 4);
    CHECK(memchr(out, 'Z', SNI_MAX) == NULL);   // no bytes from the next extension
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A hello whose declared extensions-block length exceeds the copied bytes:
    // the block end must be clamped to `len`, not believed.
    case_begin("clienthello: an extensions length past the copied bytes is clamped");
    bb_reset(&e);
    ext_server_name(&e, "clamped.example", 15);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, /*declared*/60000, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 15);
    CHECK_BYTES(out, "clamped.example", 15);
    CHECK(!has_unwritten(out, n));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // --- truncation ------------------------------------------------------
    // A ClientHello split across sends, or clipped by the scratch, arrives with
    // its extensions cut mid-flight. Every cut must yield either the correct
    // prefix behaviour or nothing — never a read past the copied bytes. Sweeping
    // EVERY cut point is what makes this a real bound check rather than a spot
    // check: one of them lands mid-length-field, mid-name, mid-ext-header.
    case_begin("clienthello: every truncation point is safe (sweep)");
    bb_reset(&e);
    bb_be16(&e, 0x000b); bb_be16(&e, 2); bb_be16(&e, 0x0100);
    ext_server_name(&e, "sweep.s3.amazonaws.com", 22);
    bb_be16(&e, 0x0017); bb_be16(&e, 0);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    for (__u32 cut = 0; cut <= w.len; cut++) {
        scratch_init(&s, TLS_SCRATCH_LEN, w.b, cut);
        out = out_alloc(SNI_MAX);
        n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
        // Never reports more than it copied, and never emits a stale byte.
        CHECK(n <= cut);
        CHECK(n <= SNI_MAX);
        CHECK(!has_unwritten(out, n));
        if (n > 0) {
            // Whatever it did return must be a genuine prefix of the real name.
            CHECK_BYTES(out, "sweep.s3.amazonaws.com", n);
        }
        check_no_overread();
        free(out); scratch_free(&s);
    }
    case_end();

    // --- degenerate and hostile shapes ------------------------------------
    case_begin("clienthello: a hello shorter than the fixed prefix yields nothing");
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, 0, NULL);
    for (__u32 cut = 0; cut <= 44; cut++) {
        scratch_init(&s, TLS_SCRATCH_LEN, w.b, cut);
        out = out_alloc(SNI_MAX);
        CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
        check_no_overread();
        free(out); scratch_free(&s);
    }
    case_end();

    case_begin("clienthello: a zero-length SNI yields nothing (not an empty name)");
    bb_reset(&e);
    ext_server_name(&e, "", 0);       // elen == 5, no room for a name byte
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
    CHECK_EQ(tr, 0);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // A server_name extension whose DECLARED data length is shorter than the
    // 5-byte header that extension type is required to have. This is the case the
    // `nstart >= ext_data_end` guard exists for, and it is nastier than it looks:
    // without it `avail = ext_data_end - nstart` underflows to ~4 billion, so the
    // declared name length sails through the availability clamp, gets capped at
    // SNI_MAX and copies 255 bytes from beyond the hello. The guard page turns
    // that into a hard failure here.
    case_begin("clienthello: an extension shorter than the server_name header is refused");
    for (unsigned elen = 0; elen < 5; elen++) {
        bb_reset(&e);
        bb_be16(&e, 0x0000); bb_be16(&e, elen);
        bb_rep(&e, 0xEE, elen);
        bb_be16(&e, 0x0017); bb_be16(&e, 0);      // a following extension to steal from
        build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
        scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
        out = out_alloc(SNI_MAX);
        CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
        check_no_overread();
        free(out); scratch_free(&s);
    }
    case_end();

    // RFC 6066 reserves the name_type byte. A non-host_name entry must be
    // refused rather than have its bytes read AS a hostname.
    case_begin("clienthello: a non-host_name name_type is refused");
    bb_reset(&e);
    bb_be16(&e, 0x0000); bb_be16(&e, 5 + 8); bb_be16(&e, 3 + 8);
    bb_u8(&e, 9);                     // name_type != host_name
    bb_be16(&e, 8); bb_mem(&e, "notaname", 8);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
    CHECK(memchr(out, 'n', SNI_MAX) == NULL);
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();

    // Over-stated session_id / cipher_suites / compression lengths push `off`
    // past the copied bytes before the extensions are ever reached.
    case_begin("clienthello: over-stated prefix lengths push past the buffer and yield nothing");
    bb_reset(&e);
    ext_server_name(&e, "unreached.example", 17);
    build_client_hello(&w, /*sid*/250, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 0);
    CHECK(!has_unwritten(out, n));
    check_no_overread();
    scratch_free(&s);

    build_client_hello(&w, 32, 32, /*cs*/60000, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
    check_no_overread();
    scratch_free(&s);

    build_client_hello(&w, 32, 32, 4, 4, /*comp*/250, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    CHECK_EQ(parse_client_hello_sni(s.buf, s.len, (char *)out, &tr), 0);
    check_no_overread();
    scratch_free(&s);
    free(out);
    case_end();

    // The extension walk is capped at 64 iterations, so an SNI hidden behind a
    // long run of padding extensions is missed. Pinned deliberately: it is a
    // capture gap (no SNI recorded), never a wrong name, and lifting the cap
    // costs verifier budget. If the cap ever changes this test says so.
    case_begin("clienthello: an SNI past the 64-extension walk cap is missed, not misread");
    bb_reset(&e);
    for (int i = 0; i < 64; i++) { bb_be16(&e, 0x1000 + i); bb_be16(&e, 1); bb_u8(&e, 0); }
    ext_server_name(&e, "too.far.example", 15);
    build_client_hello(&w, 32, 32, 4, 4, 1, 1, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    out = out_alloc(SNI_MAX);
    n = parse_client_hello_sni(s.buf, s.len, (char *)out, &tr);
    CHECK_EQ(n, 0);
    CHECK(!has_unwritten(out, n));
    check_no_overread();
    free(out); scratch_free(&s);
    case_end();
}

// ===========================================================================
// TLS ServerHello: negotiated version + cipher
// ===========================================================================

static void build_server_hello(struct bb *w, unsigned sid_len, unsigned sid_have,
                               unsigned cipher, unsigned declared_ext_len,
                               const struct bb *ext)
{
    bb_reset(w);
    tls_prefix(w, 0x02, 0x0303);
    bb_u8(w, sid_len);  bb_rep(w, 0x33, sid_have);
    bb_be16(w, cipher);
    bb_u8(w, 0);                       // compression_method
    bb_be16(w, declared_ext_len);
    if (ext) bb_mem(w, ext->b, ext->len);
}

static void test_server_hello(void)
{
    struct bb w, e;
    struct scratch s;
    __u16 version, cipher;

    case_begin("serverhello: TLS 1.3 reports the supported_versions value, not the legacy field");
    bb_reset(&e);
    bb_be16(&e, 0x0033); bb_be16(&e, 4); bb_rep(&e, 0x44, 4);   // key_share, first
    bb_be16(&e, 0x002b); bb_be16(&e, 2); bb_be16(&e, 0x0304);   // supported_versions
    build_server_hello(&w, 32, 32, 0x1301, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0x0304);
    CHECK_EQ(cipher, 0x1301);
    check_no_overread();
    scratch_free(&s);
    case_end();

    case_begin("serverhello: a fully-walked block with no supported_versions reports the legacy version");
    bb_reset(&e);
    bb_be16(&e, 0x0017); bb_be16(&e, 0);
    bb_be16(&e, 0xff01); bb_be16(&e, 1); bb_u8(&e, 0);
    build_server_hello(&w, 32, 32, 0xc02f, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0x0303);          // genuine TLS 1.2: the whole block was seen
    CHECK_EQ(cipher, 0xc02f);
    check_no_overread();
    scratch_free(&s);
    case_end();

    // --- the round-6 case: cipher readable, version not -------------------
    // The cipher sits at a fixed offset in the prefix, so it is valid long before
    // the extensions are. When the extensions block is cut short the negotiated
    // version is genuinely UNKNOWN (the legacy field reads 0x0303 for both 1.2
    // and 1.3, so believing it would mislabel a truncated 1.3 as 1.2). The
    // parser must therefore report cipher != 0 with version == 0 — and the caller
    // must emit on EITHER field, which is what round 6 fixed. Discarding both
    // threw away a cipher that was never in doubt.
    case_begin("serverhello: a truncated extensions block leaves version unknown but keeps the cipher");
    bb_reset(&e);
    bb_be16(&e, 0x0033); bb_be16(&e, 400); bb_rep(&e, 0x44, 400);
    bb_be16(&e, 0x002b); bb_be16(&e, 2); bb_be16(&e, 0x0304);
    build_server_hello(&w, 32, 32, 0x1302, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, /*cut mid-key_share*/120);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0);               // NOT 0x0303: an unwalked block proves nothing
    CHECK_EQ(cipher, 0x1302);           // still valid — the caller emits on this alone
    check_no_overread();
    scratch_free(&s);
    case_end();

    case_begin("serverhello: a hello shorter than the fixed prefix yields nothing");
    build_server_hello(&w, 32, 32, 0x1301, 0, NULL);
    for (__u32 cut = 0; cut <= 11; cut++) {
        scratch_init(&s, TLS_SCRATCH_LEN, w.b, cut);
        parse_server_hello(s.buf, s.len, &version, &cipher);
        CHECK_EQ(version, 0);
        CHECK_EQ(cipher, 0);
        check_no_overread();
        scratch_free(&s);
    }
    // Between the version field and the session_id length byte: still no cipher.
    for (__u32 cut = 11; cut <= 43; cut++) {
        scratch_init(&s, TLS_SCRATCH_LEN, w.b, cut);
        parse_server_hello(s.buf, s.len, &version, &cipher);
        CHECK_EQ(cipher, 0);
        check_no_overread();
        scratch_free(&s);
    }
    case_end();

    // A malformed supported_versions with a 0- or 1-byte body must NOT have the
    // following extension's bytes read as the version.
    case_begin("serverhello: a supported_versions shorter than 2 bytes is refused");
    bb_reset(&e);
    bb_be16(&e, 0x002b); bb_be16(&e, 0);                        // elen 0
    bb_be16(&e, 0x0033); bb_be16(&e, 4); bb_rep(&e, 0xde, 4);   // would be misread
    build_server_hello(&w, 32, 32, 0x1303, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0);
    CHECK_EQ(cipher, 0x1303);
    check_no_overread();
    scratch_free(&s);

    bb_reset(&e);
    bb_be16(&e, 0x002b); bb_be16(&e, 1); bb_u8(&e, 0x03);       // elen 1
    bb_be16(&e, 0x0033); bb_be16(&e, 4); bb_rep(&e, 0xde, 4);
    build_server_hello(&w, 32, 32, 0x1303, e.len, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0);
    check_no_overread();
    scratch_free(&s);
    case_end();

    // supported_versions declared last with its 2 bytes falling outside the
    // block: the value must not be pulled from beyond ext_end.
    case_begin("serverhello: a supported_versions body outside the block is refused");
    bb_reset(&e);
    bb_be16(&e, 0x002b); bb_be16(&e, 2);         // header only; body is past the block
    build_server_hello(&w, 32, 32, 0x1304, /*declared*/4, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0);
    CHECK_EQ(cipher, 0x1304);
    check_no_overread();
    scratch_free(&s);
    case_end();

    case_begin("serverhello: every truncation point is safe (sweep)");
    bb_reset(&e);
    bb_be16(&e, 0x0033); bb_be16(&e, 32); bb_rep(&e, 0x44, 32);
    bb_be16(&e, 0x002b); bb_be16(&e, 2); bb_be16(&e, 0x0304);
    build_server_hello(&w, 32, 32, 0x1301, e.len, &e);
    for (__u32 cut = 0; cut <= w.len; cut++) {
        scratch_init(&s, TLS_SCRATCH_LEN, w.b, cut);
        parse_server_hello(s.buf, s.len, &version, &cipher);
        // The only values either field may ever take are the real ones or 0.
        CHECK(version == 0 || version == 0x0304 || version == 0x0303);
        CHECK(cipher == 0 || cipher == 0x1301);
        check_no_overread();
        scratch_free(&s);
    }
    case_end();

    // An over-claimed extensions length must clamp to the copied bytes rather
    // than let the walk run into the stale tail.
    case_begin("serverhello: an over-claimed extensions length is clamped, not believed");
    bb_reset(&e);
    bb_be16(&e, 0x002b); bb_be16(&e, 2); bb_be16(&e, 0x0304);
    build_server_hello(&w, 32, 32, 0x1301, /*declared*/60000, &e);
    scratch_init(&s, TLS_SCRATCH_LEN, w.b, w.len);
    parse_server_hello(s.buf, s.len, &version, &cipher);
    CHECK_EQ(version, 0x0304);          // the ext is inside the copied bytes: still found
    CHECK_EQ(cipher, 0x1301);
    check_no_overread();
    scratch_free(&s);
    case_end();
}

// ===========================================================================
// HTTP head recognizers
// ===========================================================================

// Both recognizers index up to h[6]. Hand them a heap block of EXACTLY 7 bytes so
// an eighth read is an ASan heap-buffer-overflow rather than slack.
static int http_req(const char *bytes)
{
    unsigned char *h = out_alloc(7);
    int r;
    memcpy(h, bytes, 7);
    r = looks_like_http_request(h);
    free(h);
    return r;
}

static int http_resp(const char *bytes)
{
    unsigned char *h = out_alloc(7);
    int r;
    memcpy(h, bytes, 7);
    r = looks_like_http_response(h);
    free(h);
    return r;
}

static void test_http(void)
{
    case_begin("http request: the captured S3 verbs match");
    CHECK_EQ(http_req("GET /ab"), 1);
    CHECK_EQ(http_req("PUT /ab"), 1);
    CHECK_EQ(http_req("HEAD /a"), 1);
    CHECK_EQ(http_req("POST /a"), 1);
    CHECK_EQ(http_req("OPTIONS"), 1);
    CHECK_EQ(http_req("DELETE "), 1);
    case_end();

    case_begin("http request: near-misses do not match");
    CHECK_EQ(http_req("GET/foo\0"), 0);     // no space: not a request line
    CHECK_EQ(http_req("GET  /a"), 0);       // two spaces: h[4] is not '/'
    CHECK_EQ(http_req("get /ab"), 0);       // lowercase
    CHECK_EQ(http_req("PATCH /"), 0);       // verb not in the captured set
    CHECK_EQ(http_req("TRACE /"), 0);
    CHECK_EQ(http_req("HEAD/ab"), 0);
    CHECK_EQ(http_req("POST/ab"), 0);
    CHECK_EQ(http_req("\0\0\0\0\0\0\0"), 0);
    case_end();

    // OPTIONS is matched on all 7 bytes of the token — the recognizer's furthest
    // read. A 6-byte prefix must NOT match, which also pins that h[6] is read.
    case_begin("http request: OPTIONS needs all 7 bytes, DELETE needs 6");
    CHECK_EQ(http_req("OPTIONX"), 0);
    CHECK_EQ(http_req("OPTION\0"), 0);
    CHECK_EQ(http_req("DELETEX"), 1);       // token-only match: documented as looser
    CHECK_EQ(http_req("DELETX "), 0);
    case_end();

    case_begin("http response: a status line matches");
    CHECK_EQ(http_resp("HTTP/1."), 1);
    CHECK_EQ(http_resp("HTTP/1.1 200"), 1);
    case_end();

    case_begin("http response: near-misses do not match");
    CHECK_EQ(http_resp("HTTP/2."), 0);      // HTTP/2 is never seen here (ALPN h2 is framed)
    CHECK_EQ(http_resp("HTTP/x."), 0);
    CHECK_EQ(http_resp("HTTP/1x"), 0);      // the 7th byte is checked
    CHECK_EQ(http_resp("HTTP/ 1"), 0);
    CHECK_EQ(http_resp("http/1."), 0);
    CHECK_EQ(http_resp("XHTTP/1"), 0);
    CHECK_EQ(http_resp("\0\0\0\0\0\0\0"), 0);
    case_end();

    // --- the accepted false positives, pinned -----------------------------
    // These are NOT bugs to fix here, they are the documented cost of a 7-byte
    // gate that has to run on every SSL_read: a response BODY chunk whose first
    // bytes are literally a status line is captured as if it were a response
    // head, and an object whose first bytes are a request line likewise. That is
    // why the gate is `HTTP/1.` and not `HTTP/` — tightening it further would
    // cost real captures. Pinned so that if anyone changes the recognizer, the
    // change is a decision rather than an accident.
    case_begin("http: a body chunk beginning with a status line IS misread as a head (accepted)");
    CHECK_EQ(http_resp("HTTP/1."), 1);
    case_end();

    case_begin("http: an object body beginning with a request line IS misread as a head (accepted)");
    CHECK_EQ(http_req("GET /lo"), 1);       // e.g. an uploaded access-log object
    case_end();

    // A non-HTTP binary payload that happens to open with the same bytes as a
    // near-miss must be rejected: only the exact tokens above may match.
    case_begin("http: binary payloads that merely resemble a head do not match");
    CHECK_EQ(http_req("\x47\x45\x54\x00\x2f\x00\x00"), 0);   // "GET\0/"
    CHECK_EQ(http_resp("\x48\x54\x54\x50\x2f\x31\x00"), 0);  // "HTTP/1\0"
    CHECK_EQ(http_resp("\xff\xd8\xff\xe0\x00\x10JF"), 0);    // a JPEG header
    CHECK_EQ(http_req("\x1f\x8b\x08\x00\x00\x00\x00"), 0);   // a gzip header
    case_end();
}

// ===========================================================================
// Poison self-check: proves the over-read detector is armed
// ===========================================================================
//
// Every "no over-read" assertion above rests on the guard page being fatal. If it
// were misplaced by even one byte they would all pass vacuously — the exact
// failure mode this whole file exists to prevent (a gate that cannot tell a
// working check from an absent one). So the build runs the binary once with
// --overread-selfcheck, which deliberately reads one byte past `len` at an
// awkward alignment, and REQUIRES it to die.
//
// The 2-byte straddling read is the interesting one: it is the shape of
// `tls_be16` and it is precisely what ASan's 8-byte-granular poisoning failed to
// catch, which is why this harness uses mprotect instead.
static int overread_selfcheck(void)
{
    struct scratch s;
    unsigned char data[100];
    volatile unsigned int sink;

    memset(data, 0x11, sizeof(data));
    scratch_init(&s, TLS_SCRATCH_LEN, data, sizeof(data));
    printf("over-read self-check: 2-byte read at buf[%u..%u], straddling the end of "
           "the %u copied bytes\n", s.len - 1, s.len, s.len);
    fflush(stdout);
    sink = ((unsigned int)s.buf[s.len - 1] << 8) | s.buf[s.len];   // must die here
    printf("over-read self-check: NOT DETECTED (read 0x%04x) — the guard is NOT "
           "armed, so every bounds assertion in this suite is vacuous\n", sink);
    scratch_free(&s);
    return 1;                            // reaching here is itself the failure
}

// ===========================================================================

int main(int argc, char **argv)
{
    g_pagesz = sysconf(_SC_PAGESIZE);
    if (g_pagesz <= 0) g_pagesz = 4096;
    install_guard_reporter();

    if (argc > 1 && strcmp(argv[1], "--overread-selfcheck") == 0)
        return overread_selfcheck();

    printf("s3tap eBPF parser tests (guard pages armed%s)\n",
#ifdef S3TAP_ASAN
           ", ASan/UBSan on"
#else
           ", no sanitizer: output-buffer overruns and UB are not checked"
#endif
    );

    printf("\nDNS query walk / name decode\n");
    test_dns();
    printf("\nDNS response copy-length clamp\n");
    test_dns_response_clamp();
    printf("\nTLS ClientHello SNI\n");
    test_client_hello();
    printf("\nTLS ServerHello version/cipher\n");
    test_server_hello();
    printf("\nHTTP head recognizers\n");
    test_http();

    printf("\n%d cases, %d checks, %d failed\n", g_cases, g_checks, g_fail);
    return g_fail ? 1 : 0;
}
