// build.rs — compile the eBPF C into a BPF object and stage it for embedding.
//
// Having cargo do this makes `cargo build` self-contained: editing the eBPF C
// (or the shared header, or vmlinux.h) triggers a rebuild and re-embed, with no
// separate `just bpf` step. The object is written to OUT_DIR and pulled in by
// main.rs via include_bytes_aligned!(concat!(env!("OUT_DIR"), "/s3tap.bpf.o")).
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest.join("../..").canonicalize().expect("resolve repo root");
    let bpf_src = repo.join("bpf/src/s3tap.bpf.c");
    let events_h = repo.join("bpf/include/s3tap_events.h");
    // The byte parsers the BPF program includes. Editing one changes the embedded object, so
    // it has to trigger a rebuild like any other input. (Cargo tolerates a rerun-if-changed
    // path that does not exist yet, so listing it is safe either way.)
    let parse_h = repo.join("bpf/include/s3tap_parse.h");
    let vmlinux = repo.join("bpf/vmlinux/vmlinux.h");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out.join("s3tap.bpf.o");

    // Recompile only when an eBPF input (or this script) changes.
    println!("cargo:rerun-if-changed={}", bpf_src.display());
    println!("cargo:rerun-if-changed={}", events_h.display());
    println!("cargo:rerun-if-changed={}", parse_h.display());
    println!("cargo:rerun-if-changed={}", vmlinux.display());
    println!("cargo:rerun-if-changed=build.rs");
    // Rebuild if the toolchain overrides change (else a CLANG/LLVM_STRIP swap
    // wouldn't retrigger the eBPF compile).
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=LLVM_STRIP");

    if !vmlinux.exists() {
        panic!(
            "missing {} — generate it once with `just bpf-headers` (needs sudo).",
            vmlinux.display()
        );
    }

    // Map the Rust target arch to libbpf's __TARGET_ARCH_* define so we don't
    // hard-code x86 (works if you later cross/native-build on arm64).
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_arch = match arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => other,
    };

    // Remove any prior object so a failed/partial compile can never leave a
    // stale one to be embedded.
    let _ = std::fs::remove_file(&obj);

    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let status = Command::new(&clang)
        // -Werror: BPF C should compile clean; a warning must not ride silently
        // into the embedded object.
        .args(["-O2", "-g", "-Werror", "-target", "bpf"])
        .arg(format!("-D__TARGET_ARCH_{target_arch}"))
        .arg("-I").arg(repo.join("bpf/include"))
        .arg("-I").arg(repo.join("bpf/vmlinux"))
        .arg("-c").arg(&bpf_src)
        .arg("-o").arg(&obj)
        .status()
        .expect("failed to run clang — is it installed?");
    assert!(status.success(), "clang failed to compile {}", bpf_src.display());

    // Strip DWARF (keep .BTF) so aya's ELF parser accepts the object. Default to
    // the unversioned tool (override with LLVM_STRIP=llvm-strip-NN if needed).
    let strip = std::env::var("LLVM_STRIP").unwrap_or_else(|_| "llvm-strip".into());
    let status = Command::new(&strip)
        .arg("-g")
        .arg(&obj)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {strip} ({e}); set LLVM_STRIP to override"));
    assert!(status.success(), "{strip} failed on {}", obj.display());
}
