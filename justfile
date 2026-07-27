# The header is gitignored and `bpf/vmlinux/` holds nothing else, so a fresh clone has no
# such directory and the redirect would die before bpftool ever ran. Create it first.
#
# Regenerate the kernel type header (run once on the Linux build host; sudo).
bpf-headers:
    mkdir -p bpf/vmlinux
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux/vmlinux.h

# Compile the eBPF object to a STABLE path for manual bpftool inspection /
# verifier tests, e.g.  sudo bpftool prog loadall target/s3tap.bpf.o /sys/fs/bpf/s3tap autoattach
#
# `target/` is gitignored, so on a clone that has not been built yet clang would fail writing
# its output. Create it first.
#
# NOTE: the agent binary does NOT use this file — its build.rs compiles and
# embeds the object itself (and is the authoritative build), so `cargo build` /
# `just build` are self-contained. This target exists purely for hands-on kernel
# testing and is x86-only (build.rs auto-detects arch; adjust __TARGET_ARCH_ and
# the host's llvm-strip here if you build on arm64).
bpf:
    mkdir -p target
    clang -O2 -g -Werror -target bpf -D__TARGET_ARCH_x86 \
        -I bpf/include -I bpf/vmlinux \
        -c bpf/src/s3tap.bpf.c -o target/s3tap.bpf.o
    llvm-strip -g target/s3tap.bpf.o

# Unit-test the eBPF program's byte parsers on the HOST — no kernel, no root, no
# VM, so this is the per-PR gate the verifier gates below can never be.
#
# bpf/include/s3tap_parse.h holds the pure parsers (DNS name/question walk, the
# DNS response length clamp, the TLS ClientHello SNI and ServerHello parses, the
# HTTP head recognizers) and is compiled TWICE: once into the BPF object, once
# here for the host under -DS3TAP_HOST_TEST. Every one of them reads
# attacker-influenced bytes, which is exactly what a load gate cannot judge: the
# verifier only walks REACHABLE code, so a CO-RE relocation that returns early
# makes everything downstream dead code it never examines, and a PASS becomes
# indistinguishable from "compiled out". See scripts/bpf-parser-tests.sh.
bpf-test:
    ./scripts/bpf-parser-tests.sh

# Compile + LOAD the eBPF object so the kernel verifier runs on it, on THIS
# kernel (the check `cargo test` can't do). Needs clang + bpftool + sudo.
bpf-verify:
    ./scripts/kernel-compat/bpf-verify.sh

# Run the verifier gate across a spread of kernel versions via virtme-ng, which
# downloads each kernel itself (CO-RE portability). Prereqs: virtme-ng + KVM.
# Override the spread with VERSIONS="v6.1 v6.12 v6.16".
bpf-matrix:
    ./scripts/kernel-compat/bpf-matrix.sh

# Build the agent. build.rs compiles + embeds the eBPF, so no `bpf` dep here.
build:
    cargo build --release

# Run the full test suite (pure userspace — no kernel/root needed).
test:
    cargo test --workspace

# Run the agent. Needs privileges to load eBPF.
run *ARGS: build
    sudo target/release/s3tap {{ARGS}}

# Build, then grant CAP_BPF + CAP_PERFMON to the binary so it runs without sudo.
# Caps attach to the inode, so each rebuild drops them — re-run after building.
setcap: build
    ./setcap.sh
