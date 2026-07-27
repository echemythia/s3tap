// bpf/tests/s3tap_host_shim.h
//
// The HOST half of the two-build scheme described at the top of
// bpf/include/s3tap_parse.h. Supplies, under plain userspace clang, the handful
// of names the pure parsers get from vmlinux.h / bpf_helpers.h when they are
// compiled for BPF — so the exact same source compiles and runs in a test binary
// that needs no kernel, no root and no VM.
//
// It is a SHIM, not a simulator. It must stay this thin: the moment it starts
// emulating kernel behaviour, a test passing here stops implying anything about
// the program that actually loads. The whole surface is:
//   - the fixed-width integer types
//   - __always_inline
//   - barrier_var, a no-op here (it exists to shape clang's BPF codegen)
//   - bpf_probe_read_kernel, a bounds-CHECKED memcpy
//
// Include this BEFORE s3tap_parse.h.

#ifndef S3TAP_HOST_SHIM_H
#define S3TAP_HOST_SHIM_H

#ifndef S3TAP_HOST_TEST
#error "s3tap_host_shim.h is for the host test build only (-DS3TAP_HOST_TEST)"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// vmlinux.h's fixed-width aliases. The event ABI header and the parsers are
// written in these, so the host build has to provide them.
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;

// bpf_helpers.h spells it exactly this way.
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

// A no-op on the host. In the BPF build this is an empty asm that hides a
// variable's value range from clang so a `var &= const` copy bound survives into
// the bytecode (see s3tap_parse.h). It constrains CODEGEN, never semantics, so
// dropping it changes nothing about what the parsers compute — which is the
// point: the host tests check the parsing, the kernel matrix checks the codegen.
#define barrier_var(var) ((void)(var))

// --- the modelled per-CPU scratch ---------------------------------------
//
// In the kernel the parsers read out of a per-CPU ARRAY map of a fixed size, and
// every offset is masked with (size - 1) so a bad offset lands SOMEWHERE INSIDE
// that map rather than out of bounds. That is what makes an over-read silent
// instead of fatal: the read succeeds and returns whatever the previous message
// on this CPU left behind. The test harness (parser_tests.c) reproduces that
// geometry exactly — a region of the map's size holding `len` valid bytes — and
// poisons everything past `len`, so a parser that reads past what was copied
// trips ASan instead of quietly emitting a stale hostname.
//
// These globals let the shim record what bpf_probe_read_kernel was asked to read,
// so the copy path is checked even in a build without sanitizers.
static const unsigned char *s3tap_shim_valid_base;  // start of the copied bytes
static unsigned long        s3tap_shim_valid_len;   // how many of them are real
static unsigned long        s3tap_shim_reads;       // calls seen since the reset
static unsigned long        s3tap_shim_overreads;   // calls that left [base, base+len)
static unsigned long        s3tap_shim_max_end;     // furthest byte touched, as an offset

// Tell the shim which region is the "bytes actually copied into the scratch".
// Called by the harness before each parser invocation.
static inline void s3tap_shim_set_valid(const void *base, unsigned long len)
{
    s3tap_shim_valid_base = (const unsigned char *)base;
    s3tap_shim_valid_len  = len;
    s3tap_shim_reads      = 0;
    s3tap_shim_overreads  = 0;
    s3tap_shim_max_end    = 0;
}

// The fault-safe bounded read. In BPF this copies from an address that may not be
// mapped and returns non-zero instead of faulting; the parsers only ever use it to
// copy a name out of the scratch they already bounds-checked, so on the host it is
// a memcpy plus the bounds check that BPF cannot make.
//
// Deliberately does NOT clamp or refuse: it records and copies. A parser bug must
// show up as a FAILED TEST, not be papered over by a shim that is safer than the
// kernel. (ASan, which intercepts memcpy, turns the poisoned tail into a hard
// error at the same moment.)
static inline long bpf_probe_read_kernel(void *dst, __u32 size, const void *src)
{
    const unsigned char *s = (const unsigned char *)src;
    s3tap_shim_reads++;
    if (s3tap_shim_valid_base) {
        unsigned long start = (unsigned long)(s - s3tap_shim_valid_base);
        unsigned long end   = start + size;
        if (size && end > s3tap_shim_max_end)
            s3tap_shim_max_end = end;
        if (size && (s < s3tap_shim_valid_base || end > s3tap_shim_valid_len))
            s3tap_shim_overreads++;
    }
    memcpy(dst, src, size);
    return 0;
}

#endif // S3TAP_HOST_SHIM_H
