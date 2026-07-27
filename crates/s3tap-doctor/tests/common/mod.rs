// Helpers shared by this crate's integration tests. Lives under `tests/common/` so cargo
// treats it as a module, not a test binary of its own.

/// True in CI. Used two ways, both about refusing to pass vacuously on a machine whose
/// result is authoritative: the parity suite hard-fails there instead of skipping a
/// missing oracle, and `check_golden` refuses to REWRITE a golden there instead of
/// asserting against it. Follows the common `is-ci` convention: `CI=false`/`CI=0`/`CI=`
/// count as NOT in CI, so a dev who exports `CI=false` to quiet other tooling isn't
/// hard-failed for lacking python3.
pub fn running_in_ci() -> bool {
    matches!(std::env::var("CI"), Ok(v) if !v.is_empty() && v != "false" && v != "0")
}
