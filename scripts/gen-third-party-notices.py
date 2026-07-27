#!/usr/bin/env python3
"""Emit THIRD-PARTY-NOTICES.md. Driven by scripts/gen-third-party-notices.sh.

Shape of the output, and why:

MIT-style licences are one boilerplate body plus a per-holder copyright line, so 57 crates
produce only ~16 distinct bodies and a long tail of near-duplicates. Printing every crate's
file in full made a 2,700-line document nobody would read.

So files are GROUPED by their body with copyright lines set aside, one full verbatim text
is printed per group, and the copyright lines of every other file in that group are listed
with it. Nothing is paraphrased and no licence body is ever edited — the dedup key ignores
copyright lines, but the text that gets printed is a real file, complete.
"""
import glob
import hashlib
import os
import pathlib
import re
import sys
import textwrap
from collections import defaultdict

# Two DIFFERENT questions, and conflating them was the bug worth naming here.
#
# "Is this line a copyright notice I must reproduce?" is strict. A loose /copyright/i match
# scoops up things that are not notices at all: Apache-2.0's APPENDIX placeholder
# (`Copyright [yyyy] [name of copyright owner]` — a template, nobody's claim), mid-sentence
# prose that happens to begin a line (`copyright license to reproduce, prepare Derivative
# Works of,`), and section headings (`COPYRIGHT AND PERMISSION NOTICE`). Publishing those as
# attributions is nonsense, and an earlier version also *removed* them from the licence body,
# which silently truncated the licence itself.
#
# A notice therefore needs all three: a capitalised `Copyright`/`©` at the start, an
# attribution marker ((c), © or a year), and no template placeholder.
NOTICE_START = re.compile(r"^\s*(Copyright\b|©)")
NOTICE_MARK = re.compile(r"\(c\)|\(C\)|©|(?:1[89]|20)\d{2}")
PLACEHOLDER = re.compile(r"[\[{]\s*(?:yyyy|year|name of copyright owner)\s*[\]}]", re.I)

# "Do two files differ only in who holds the copyright?" is loose on purpose — it decides
# GROUPING only and never edits what gets printed, so over-matching here is harmless.
DEDUP_IGNORE = re.compile(r"^\s*(copyright\b|©)", re.I)


# Identify a licence by its TEXT, not by the filename a crate happened to choose. Crates put
# the same MIT text in `LICENSE`, `LICENSE-MIT` or `COPYING`, so filenames made the dropdown
# titles read as an arbitrary list — `LICENSE`, `LICENSE-BSD`, `COPYING` — telling a reader
# nothing about which licence they were looking at. Ordered: first match wins, so the
# combined-file case is tested before its constituents.
FINGERPRINTS = [
    (
        "MIT and Apache-2.0 (one combined file)",
        lambda t: "Permission is hereby granted, free of charge" in t and "Apache License" in t,
    ),
    # BEFORE MIT: the Unicode licence also opens "Permission is hereby granted, free of
    # charge", so a plain MIT test claims it.
    ("Unicode-3.0", lambda t: "UNICODE LICENSE" in t),
    ("MIT", lambda t: "Permission is hereby granted, free of charge" in t),
    ("Apache-2.0", lambda t: "Apache License" in t and "Version 2.0" in t),
    ("BSD-2-Clause", lambda t: "Redistribution and use in source and binary forms" in t),
    ("The Unlicense (public-domain dedication)", lambda t: "released into the public domain" in t),
    ("Zlib licence", lambda t: "altered source versions must be plainly marked" in t.lower()),
]

# A file that only POINTS at licences rather than granting anything — memchr's `COPYING` is
# three lines saying it is dual-licensed under the Unlicense and MIT. It carries no terms and
# no copyright notice, and both licences it names are reproduced in full elsewhere in this
# file, so printing it adds a dropdown that says nothing. Dropped, not summarised: there is
# nothing in it to preserve.
POINTER = re.compile(r"dual[- ]licen[sc]ed under", re.I)


def is_pointer(text):
    return bool(POINTER.search(text)) and len(text) < 400


def label_for(text, filenames):
    for name, test in FINGERPRINTS:
        if test(text):
            return name
    # Nothing recognised: fall back to the filename rather than guess, and say so out loud.
    base = {re.sub(r"\.(txt|md)$", "", n, flags=re.I).upper() for n in filenames}
    return " / ".join(sorted(base)) + " (unrecognised)"


def is_notice(line):
    return bool(
        NOTICE_START.search(line) and NOTICE_MARK.search(line) and not PLACEHOLDER.search(line)
    )


def notice_lines(text):
    return [l.strip() for l in text.splitlines() if is_notice(l)]


# A crate may ship ONE file containing several licences end to end — chrono's `LICENSE` is the
# MIT text followed by the whole Apache-2.0 text. Printing it whole duplicated ~12 KB already
# present as the standalone MIT and Apache entries, for the sake of one copyright line.
#
# So it is folded: the file is not printed, and its notices are carried into the groups for the
# licences it contains. That needs a LOOSER notice scan than `notice_lines`, because such files
# wrap a notice mid-sentence ("... Apache 2.0 License [2]. Copyright (c) 2014--2026, Kang
# Seonghoon and contributors."), which a line-anchored match never sees. Losing a copyright
# notice to save lines would be the wrong trade, so this errs toward capturing.
INLINE_NOTICE = re.compile(r"(Copyright\s*(?:\(c\)|©)?\s*[^.\n]{0,120})", re.I)


def is_combined(text):
    return "Permission is hereby granted, free of charge" in text and "Apache License" in text


def inline_notices(text):
    out = set()
    # Join wrapped lines FIRST. Scanning raw text truncated a notice at the line break —
    # "Copyright (c) 2014--2026, Kang Seonghoon and" — dropping "contributors" and leaving a
    # sentence fragment standing in for an attribution.
    flat = " ".join(text.split())
    for m in INLINE_NOTICE.finditer(flat):
        line = " ".join(m.group(1).split()).rstrip(",;")
        if is_notice(line) and len(line) > 12:
            out.add(line)
    return out


# Apache-2.0 files end with an optional APPENDIX titled "How to apply the Apache License to
# your work" — instructions for a would-be licensor, not terms binding on anyone. Crates ship
# it or omit it, and those that ship it use `[yyyy]` or `{yyyy}` interchangeably. Grouping on
# the whole file therefore produced THREE separate 200-line Apache dropdowns whose operative
# terms are byte-identical, which is noise for a reader and tells them nothing.
TERMS_END = "END OF TERMS AND CONDITIONS"

# A bare title line — "MIT License", "The MIT License (MIT)", "UNICODE LICENSE V3". Crates
# ship the same MIT text with, without, or with a differently-worded heading, which split one
# licence across three dropdowns. Deliberately narrow: the line must be ONLY a title, so no
# sentence and nothing carrying terms can match it.
TITLE = re.compile(r"^\s*(the\s+)?[a-z0-9 .\-]{0,30}licen[sc]e( v?[0-9.]+)?( \([^)]*\))?\s*$", re.I)


def dedup_key(text):
    """The OPERATIVE terms: appendix dropped, copyright lines and whitespace ignored.

    Grouping only — never edits what gets printed. The representative chosen for each group
    is the longest file in it, so the reader still sees a complete, verbatim licence.
    """
    cut = text.find(TERMS_END)
    terms = text[:cut] if cut > 0 else text
    body = "\n".join(
        l for l in terms.splitlines() if not DEDUP_IGNORE.match(l) and not TITLE.match(l)
    )
    return hashlib.sha256(re.sub(r"\s+", " ", body).strip().encode()).hexdigest()[:12]


shipped = set()
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    p = line.split()
    if len(p) == 2 and p[1].startswith("v"):
        shipped.add((p[0], p[1][1:]))
local = {p.name for p in pathlib.Path("crates").iterdir()} | {"s3tap"}
shipped = sorted({(n, v) for n, v in shipped if n not in local})
reg = os.path.expanduser("~/.cargo/registry/src")

by_licence = defaultdict(list)   # SPDX expression -> [(name, version)]
no_file = []
proc_macros = set()
combined = []   # (crate, text) for files holding several licences end to end
groups = {}  # key -> {"text": verbatim representative, "labels": set, "crates": set, "notices": set}

for name, ver in shipped:
    hits = glob.glob(f"{reg}/*/{name}-{ver}")
    if not hits:
        sys.exit(f"missing from the registry cache: {name} {ver} (run cargo fetch)")
    d = pathlib.Path(hits[0])
    tm = re.search(r'^license\s*=\s*"([^"]+)"', (d / "Cargo.toml").read_text(), re.M)
    expr = tm.group(1) if tm else "see crate"
    by_licence[expr].append((name, ver))
    if re.search(r"^\s*proc-macro\s*=\s*true", (d / "Cargo.toml").read_text(), re.M):
        proc_macros.add(name)
    had_file = False
    for g in ["LICENSE*", "LICENCE*", "COPYING*", "UNLICENSE*"]:
        for f in sorted(d.glob(g)):
            if not f.is_file():
                continue
            t = f.read_text(encoding="utf-8", errors="replace").strip()
            if not t or is_pointer(t):
                continue
            if is_combined(t):
                combined.append((name, t))
                had_file = True
                continue
            k = dedup_key(t)
            grp = groups.setdefault(k, {"text": t, "labels": set(), "crates": set(), "notices": set()})
            if len(t) > len(grp["text"]):
                grp["text"] = t  # keep the fullest variant (e.g. the one carrying the appendix)
            grp["labels"].add(re.sub(r"\.(txt|md)$", "", f.name, flags=re.I).upper())
            grp["crates"].add(name)
            grp["notices"].update(notice_lines(t))
            had_file = True
    if not had_file:
        # Some crates declare a licence but ship no licence FILE in the published package.
        # Silently omitting them would read as an oversight, so they are named explicitly and
        # pointed at the identical text another crate does ship.
        no_file.append((name, expr))

# Fold the combined files: their terms are already present as standalone groups, so only the
# copyright notices need a home. Attach each to every group whose licence the file contains,
# since the crate is offered under either.
for crate, text in combined:
    ns = inline_notices(text)
    for g in groups.values():
        lab = label_for(g["text"], g["labels"])
        if (lab == "MIT" and "Permission is hereby granted" in text) or (
            lab == "Apache-2.0" and "Apache License" in text
        ):
            g["notices"].update(ns)
            g["crates"].add(crate)

o = [
    "# Third-party notices\n",
    "The published `s3tap-linux-x86_64` and `s3tap-linux-aarch64` binaries are statically",
    "linked, so third-party code is redistributed inside them and these notices travel with",
    "them. This file ships as a release asset next to the binaries.\n",
    "Cargo `[dev-dependencies]` and `[build-dependencies]` are not listed: they never reach a",
    "user. Building from source links against your own system's C library, so the musl entry",
    "applies to the published binaries only.\n",
    "## What is redistributed\n",
    "**musl libc** — the C library the published binaries are built against. It is not a Cargo",
    "dependency, so no tooling reports it; it is recorded here by hand.\n",
    "> Copyright © 2005-2020 Rich Felker, et al.\n",
    "musl is under the MIT licence, whose text appears in full below. The authoritative",
    "notice, including the per-file contributor list, is at",
    "<https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT>.\n",
    f"**{len(shipped)} Rust crates**, by the licence each declares:\n",
]
for expr in sorted(by_licence, key=lambda e: (-len(by_licence[e]), e)):
    # A crate can ship at more than one version in one graph (hashbrown does), and a licence
    # can in principle change between versions — so the version is shown when it disambiguates
    # rather than silently collapsing two packages into one name. Counting packages, not
    # names, is also what makes this add up to the total stated above.
    vers = defaultdict(list)
    for n, v in by_licence[expr]:
        vers[n].append(v)
    parts = []
    for n in sorted(vers):
        vs = sorted(set(vers[n]))
        parts.append(f"`{n}`" if len(vs) == 1 else f"`{n}` ({', '.join('v' + x for x in vs)})")
    # Wrapped: one licence's crate list ran to 550 columns, which is unreadable in a plain
    # editor or a diff even though a browser reflows it.
    line = f"- **{expr}** ({len(by_licence[expr])}) — " + ", ".join(parts)
    o.extend(textwrap.wrap(line, width=92, subsequent_indent="  ", break_long_words=False,
                           break_on_hyphens=False))
if proc_macros:
    names = ", ".join(f"`{n}`" for n in sorted(proc_macros))
    o.append("")
    o.append(f"{len(proc_macros)} of those are **procedural macros**:")
    o.append(f"{names}.")
    o.append("They run during compilation, so their own code is not linked into the binary — the")
    o.append("code they generate is. They are listed anyway: attributing more than strictly")
    o.append("required costs nothing, and the opposite mistake would not be so cheap.")

if no_file:
    o.append("")
    o.append("Two crates declare a licence but ship no licence file in their published")
    o.append("package. The text each names is reproduced below, from a crate that does ship it:\n")
    for n, e in sorted(no_file):
        o.append(f"- `{n}` — {e}")

o += [
    "",
    "Where a crate offers a choice, any one of the listed licences may be relied on; where the",
    "expression says AND, every named licence applies.\n",
    "`Unlicense` is a licence, not the absence of one: it is a public-domain dedication, and",
    "SPDX spells it that way. `Zlib` is the zlib licence, which is not tied to the zlib",
    "library.\n",
    "## Licence texts\n",
    f"The {len(groups)} licences named above, each reproduced in full and exactly once, with",
    "the copyright notices that belong to them.\n",
]
for _, g in sorted(groups.items(), key=lambda kv: (-len(kv[1]["crates"]), sorted(kv[1]["crates"])[0])):
    # The crate NAMES are deliberately not repeated here: the section above already lists every
    # crate under the licence it declares, and printing them again in each dropdown title said
    # the same thing twice while making the titles unreadable.
    o.append("<details>")
    o.append(
        f"<summary><b>{label_for(g['text'], g['labels'])}</b></summary>\n"
    )
    # Only the notices this printed text does not already carry — otherwise the crate whose
    # file was chosen as the representative gets its notice printed twice.
    extra = sorted(x for x in g["notices"] if x not in g["text"])
    if extra:
        o.append("Also covers:\n")
        for x in extra:
            o.append(f"- {x}")
        o.append("")
    o.append("```")
    o.append(g["text"])
    o.append("```")
    o.append("</details>\n")
pathlib.Path("THIRD-PARTY-NOTICES.md").write_text("\n".join(o))
print(f"THIRD-PARTY-NOTICES.md: {len(shipped)} crates, {len(groups)} licence texts")
