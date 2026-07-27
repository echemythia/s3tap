#!/usr/bin/env python3
"""Profile s3tap's captured metrics and judge whether they're healthy/expected.

Reads s3tap JSONL (s3tap.operation/1 + s3tap.connection/2) on stdin and prints a
small analytics report. It does NOT invent thresholds in a vacuum: every latency is
judged RELATIVE to the connection's smoothed round-trip time (srtt), the network
floor for this path, so the verdicts hold whether the endpoint is 2 ms or 200 ms away.

  usage:  grep '"schema"' out.jsonl | s3stats.py
"""
import sys
import json

# ── ANSI (kept minimal; matches the demo's palette) ──────────────────────────
DIM = "\033[2m"; OK = "\033[32m"; WARN = "\033[33m"; OFF = "\033[0m"

# Kept in lock-step with lib.rs MAX_PLAUSIBLE_RTT_US: an srtt at/above this (µs) is corrupt
# or adversarial, not a real floor, and must never become a latency denominator.
MAX_PLAUSIBLE_RTT_US = 30_000_000

# Kept in lock-step with lib.rs MIN_RATE_SEGMENTS (= MIN_DIRECTIONAL_BYTES / TCP_MSS_BYTES):
# the minimum send-side segments before a retransmit RATE means anything. A default GET run
# (one keep-alive connection, ~15 KB of request headers = ~10 segments) gave the 0.1%
# tolerance a denominator so small it admitted 0.01 retransmits, so ONE tail-loss probe read
# as "10.00% loss" on a healthy path. Below the floor the row is n/a in both implementations.
MIN_RATE_SEGMENTS = 65_536 // 1460


def median(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def main():
    ops, conns = [], []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        # Split by schema EXPLICITLY — mirror the Rust doctor's typed populations. A bare
        # `else conns` catch-all would route s3tap.sample/1 time-series records into `conns`,
        # whose srtt_us/retransmits/bytes_sent would then pollute the close-time floor, the
        # retransmit rate, and the segment count — moving the verdict, which the doctor
        # deliberately avoids (samples live in their own population there). Drop anything that
        # is neither an operation nor a connection.
        schema = d.get("schema", "")
        if schema.startswith("s3tap.operation"):
            ops.append(d)
        elif schema.startswith("s3tap.connection"):
            conns.append(d)

    # srtt (µs) is the network floor — read off tcp_sock at close, so CONNECTION records are
    # its only source. This used to read the operations too, on the belief that the field was
    # present on both record kinds: it is not. An operation is emitted while its socket is
    # still open, so s3tap writes srtt_us null on every one of them (the schema says so field
    # by field), and chaining them only added an always-empty list. Lock-step with lib.rs
    # close_srtt, which dropped the same dead source.
    # Filter PER VALUE before the median: a sentinel 0 (socket never sampled / LRU-evicted) or
    # an implausibly huge corrupt value is not a data point and must not enter the median.
    # `0 < s < MAX` mirrors Rust's domain exactly: srtt_us deserializes to u32 there, so a
    # negative or fractional value never survives — the record is dropped as junk. Guarding
    # the low side here keeps the oracle from admitting a corrupt value Rust would reject.
    srtt_us = median(
        c.get("srtt_us")
        for c in conns
        if c.get("srtt_us") is not None and 0 < c["srtt_us"] < MAX_PLAUSIBLE_RTT_US
    )
    rtt_ms = (srtt_us / 1000) if srtt_us else None

    # Eligibility: ANSWERED, non-partial, status < 400, and not delimitation:ambiguous
    # (a concurrent request made the timing unattributable). Kept in lock-step with the
    # Rust doctor's is_timeable() = is_eligible() AND the status is present.
    #
    # The `is not None` clause is load-bearing: `or 0` coerces an ABSENT status to 0, which
    # is < 400, so an aborted in-flight request (no status, with a ttfb_ns from a 100-continue
    # interim) was TIMED as if S3 had answered it. One capture then reported a 53.5 ms median
    # here against 5 ms from the scorecard, which narrows the same way.
    good = [
        o
        for o in ops
        if o.get("http_status") is not None
        and (o.get("http_status") or 0) < 400
        and not o.get("partial")
        # Whitelist "clean" to MIRROR Rust's `== Delimitation::Clean` (not `!= "ambiguous"`):
        # if a third delimitation state is ever added, both sides exclude it in lock-step.
        and o.get("delimitation", "clean") == "clean"
    ]

    # Cold-resolve median reads the ELIGIBLE (`good`) ops, not raw ops: DNS off a
    # partial/ambiguous/error op isn't trustworthy. Lock-step with lib.rs.
    dns_cold = median(
        o["dns"].get("latency_ns") for o in good
        if o.get("dns") and not o["dns"].get("cache_hit")
    )
    tcp = median([o.get("tcp_connect_ns") for o in good])
    ttfb_new = median([o.get("ttfb_ns") for o in good if not o.get("connection_reused")])
    ttfb_reu = median([o.get("ttfb_ns") for o in good if o.get("connection_reused")])
    # Numerator from the SAME population as the denominator (sent_bytes below): CONNECTION
    # records only. An operation's `retransmits` is cumulative for the WHOLE connection, not
    # for that op, so N ops sharing a socket each repeat the same counter — adding them to the
    # connection's own copy multiplied the numerator by N+1 over a single-socket denominator
    # and turned a clean capture into "loss". Lock-step with lib.rs close_rtx.
    rtx = sum((c.get("retransmits") or 0) for c in conns)
    errors = [o for o in ops if (o.get("http_status") or 0) >= 400]

    rows = []   # (label, value-str, mark, verdict, note)

    def add(label, val, mark, verdict, note):
        rows.append((label, val, mark, verdict, note))

    if rtt_ms is not None:
        add("baseline RTT (srtt)", "%5.1f ms" % rtt_ms, " ", "floor",
            "the network round-trip floor, every span below is judged against it")

    # Cold resolve: REPORTED, never judged. An absolute "< 50 ms" is the invented number this
    # script exists to avoid, and it fails a clean on-prem capture on a 60 ms path. Nor can it
    # be judged against the RTT floor like the spans below: that floor is the round-trip to the
    # ENDPOINT, while the resolver sits on a different path doing recursion, so a same-region
    # capture (sub-ms floor, a routine 15 ms resolve) would read as 30xRTT and warn every run.
    # Lock-step with lib.rs, where this row is Mark::Fyi and cannot gate.
    if dns_cold is not None:
        add("DNS, cold resolve", "%5.1f ms" % (dns_cold / 1e6), "·", "fyi",
            "first lookup (cached resolves are ~0), not judged: the resolver is on a "
            "different path than the endpoint, so the RTT floor is not its baseline")

    # The TCP/TTFB spans are judged RELATIVE to the RTT floor. With no srtt baseline
    # (socket never sampled / LRU-evicted -> srtt_us 0/None), we cannot judge them:
    # show the value but mark it n/a — never a false ✓ — so the verdict stays honest.
    if tcp is not None:
        ms = tcp / 1e6
        ratio = (ms / rtt_ms) if rtt_ms else None
        if ratio is None:
            add("TCP connect", "%5.1f ms" % ms, " ", "n/a", "no srtt baseline, not judged")
        else:
            # One-sided: only a SLOW handshake is a problem. A connect faster than the floor
            # is benign — srtt is lifetime-smoothed and routinely exceeds the clean initial
            # SYN/SYN-ACK RTT, so a low ratio is normal, not "high".
            ok = ratio <= 3.0
            note = ("≈%.1f×RTT, a single SYN/SYN-ACK, as expected" % ratio if ok
                    else "%.1f×RTT, slow handshake (SYN retransmit or a slow server accept)" % ratio)
            add("TCP connect", "%5.1f ms" % ms, "✓" if ok else "⚠",
                "expected" if ok else "high", note)

    if ttfb_new is not None:
        ms = ttfb_new / 1e6
        ratio = (ms / rtt_ms) if rtt_ms else None
        if ratio is None:
            add("TTFB, new conn", "%5.1f ms" % ms, " ", "n/a", "no srtt baseline, not judged")
        else:
            # TTFB is request-write -> response-head; it EXCLUDES connect+TLS (separate
            # fields, paid before the request write). So a new-conn TTFB is NOT inherently
            # larger than a reused one — same threshold for both.
            ok = ratio <= 4.0
            add("TTFB, new conn", "%5.1f ms" % ms, "✓" if ok else "⚠",
                "expected" if ok else "high",
                "%.1f×RTT, request round-trip + server think (excludes setup)" % ratio)

    if ttfb_reu is not None:
        ms = ttfb_reu / 1e6
        ratio = (ms / rtt_ms) if rtt_ms else None
        # The per-op SAVING from reuse is the avoidable setup the reused op skips —
        # tcp_connect (+ unmeasured TLS handshake) — NOT a TTFB delta (TTFB excludes
        # setup, so ttfb_new ~= ttfb_reu). Quote the median tcp_connect.
        saved = (tcp / 1e6) if tcp else None
        if ratio is None:
            add("TTFB, reused conn", "%5.1f ms" % ms, " ", "n/a", "no srtt baseline, not judged")
        else:
            ok = ratio <= 4.0
            note = "%.1f×RTT, setup already paid" % ratio
            if saved is not None and saved > 0:
                note += ", reuse avoids ~%.1f ms tcp_connect/op (+ TLS)" % saved
            add("TTFB, reused conn", "%5.1f ms" % ms, "✓" if ok else "⚠",
                "good" if ok else "high", note)

    # Retransmits are connection-cumulative and INCLUDE TLP (tail-loss probes — not real
    # loss), so judge a RATE against segments sent, with a small tolerance, not a bare
    # != 0 (one TLP on a long connection isn't "the path dropped packets"). bytes_sent /
    # retransmits both come off tcp_sock at close, so sum over CONNECTION records only
    # (they're null/0 on ops — read at close, joined per connection).
    sent_bytes = sum((c.get("bytes_sent") or 0) for c in conns)
    segs = sent_bytes // 1460  # ~MSS; a rough segment estimate
    if segs < MIN_RATE_SEGMENTS:
        # No connection contributed bytes_sent -> no real segment denominator. Fabricating
        # segs=1 (as `max(1, …)` would) turns any stray retransmit into a false "loss"; the
        # Rust doctor marks this n/a for exactly this reason. Show the count, never judge it.
        # Same above 0: a handful of segments cannot rate loss either, because the tolerance
        # below is a RATE and a tiny denominator makes one TLP look like a double-digit one.
        add("retransmit rate", "%d rtx" % rtx, " ", "n/a",
            "no bytes_sent baseline, not judged" if sent_bytes == 0
            else "too few send-side segments to rate loss: ~%d sent (< %d), not judged"
                 % (segs, MIN_RATE_SEGMENTS))
    else:
        rtx_rate = rtx / segs
        rtx_ok = rtx_rate <= 0.001  # 0.1% tolerance absorbs the odd TLP
        add("retransmit rate", "%6.2f%%" % (rtx_rate * 100), "✓" if rtx_ok else "⚠",
            "clean" if rtx_ok else "loss",
            # NOT "(TLP excluded)": `retransmits` counts tail-loss probes and spurious
            # (DSACK'd) retransmits too. What makes this clean is the RATE staying inside the
            # tolerance over a denominator big enough for the tolerance to mean something.
            "no real loss on the path (%d retransmit(s) / ~%d segs, TLP and spurious "
            "retransmits are counted here, absorbed by the 0.1%% tolerance)" % (rtx, segs)
            if rtx_ok
            else "%d retransmit(s) / ~%d segs, the path dropped packets, latency suffered" % (rtx, segs))

    nerr = len(errors)
    # Ops S3 actually answered. `errors` is drawn from these alone (a missing status can never
    # be >= 400), so with none of them there is no error rate to report. Lock-step with lib.rs
    # op_statused.
    n_statused = sum(1 for o in ops if o.get("http_status") is not None)
    if n_statused == 0:
        # "0 / N ✓ healthy, all operations 2xx/204" is an affirmative claim over a set in which
        # NOTHING was answered: the 0 is a construction, not a measurement. Two captures take
        # this shape, and both used to print that green tick: one with no operation records at
        # all (a client whose TLS could not be read), and one whose operations were ALL aborted
        # in flight (routine at SIGINT). Report both as unjudged, with the same blank mark the
        # retransmit row uses when it has no denominator. Lock-step with lib.rs.
        add("HTTP errors", "   n/a", " ", "n/a",
            "no operations in this capture, so nothing was judged" if not ops
            else "none of the %d operations in this capture was answered (no http_status), "
                 "so nothing was judged 2xx" % len(ops))
    else:
        add("HTTP errors", "%4d / %d" % (nerr, len(ops)), "✓" if nerr == 0 else "⚠",
            "healthy" if nerr == 0 else "errors",
            "all operations 2xx/204" if nerr == 0
            else "status >=400: " + ", ".join(str(o.get("http_status")) for o in errors))

    if not rows:
        print("  (no metrics, no operations captured)")
        return

    print("  %sare these numbers healthy? (each span vs the round-trip floor)%s" % (DIM, OFF))
    wlab = max(len(r[0]) for r in rows)
    wval = max(len(r[1]) for r in rows)
    for label, val, mark, verdict, note in rows:
        col = OK if mark == "✓" else (WARN if mark == "⚠" else DIM)
        print("  %-*s %*s  %s%s %-8s%s %s%s%s" % (
            wlab, label, wval, val, col, mark, verdict, OFF, DIM, note, OFF))

    attention = any(r[2] == "⚠" for r in rows)
    # Was any latency span actually judged against the floor? With every op partial
    # (good[] empty) the TCP/TTFB spans are all None, so "no ⚠" does NOT mean the
    # latencies were validated — don't print the green HEALTHY claim in that case.
    judged = tcp is not None or ttfb_new is not None or ttfb_reu is not None
    if attention:
        msg, color = (
            "ATTENTION: one or more metrics are outside the expected envelope (⚠ above)",
            WARN,
        )
    elif rtt_ms is None:
        # Absolute checks (DNS / retransmits / HTTP errors) passed, but with no srtt we
        # never judged the latencies against a floor — don't claim they "track" it.
        msg, color = (
            "NO BASELINE: srtt unavailable (socket unsampled/evicted). Absolute checks "
            "passed, but latencies were not judged against a round-trip floor",
            DIM,
        )
    elif not judged:
        # srtt exists but no latency span survived — checks passed, but nothing
        # latency-related was compared to the floor. NOT necessarily "all ops partial":
        # a capture with no operations at all lands here too. Lock-step with lib.rs.
        msg, color = (
            "CHECKS PASSED: no latency spans available to judge against the floor "
            "(no timeable operations)",
            DIM,
        )
    else:
        # Only claim reuse "is working" when a reused-conn TTFB was actually observed.
        reuse = ", connection reuse is working" if ttfb_reu is not None else ""
        msg, color = (
            "HEALTHY: latencies track the round-trip floor" + reuse,
            OK,
        )
    print()
    print("  verdict: %s%s%s" % (color, msg, OFF))


if __name__ == "__main__":
    main()
