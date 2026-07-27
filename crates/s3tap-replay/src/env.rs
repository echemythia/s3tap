//! Strict parsing of the `S3TAP_*` / `MRC_*` environment overrides the study binaries take.
//!
//! One rule, applied everywhere: **unset means use the default, present-but-invalid is an
//! error.** A silent fall-back is the failure this module exists to prevent. `S3TAP_MAX=1O00`
//! (letter O for zero) is a plausible typo, and `parse().ok()` turned it into "run the default
//! cap" with no diagnostic at all — so a study run reported numbers under parameters nobody
//! chose, and nothing in the output said so.
//!
//! Every parser takes the RAW value rather than reading the environment itself, so the rule is
//! testable without mutating process-global state. `from_env` is the thin convenience wrapper
//! the binaries actually call.

use std::str::FromStr;

/// Parse an optional environment override.
///
/// `None` in, `Ok(None)` out: unset, so the caller applies its own default. The defaults
/// differ per binary and stay documented at each call site. A present value must parse, or
/// this is an `Err` naming the variable, the offending text and what was expected.
///
/// # Errors
/// When `raw` is `Some` and does not parse as `T`.
pub fn parse_env<T: FromStr>(
    name: &str,
    raw: Option<&str>,
    expected: &str,
) -> Result<Option<T>, String> {
    match raw {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse::<T>()
            .map(Some)
            .map_err(|_| format!("{name}='{v}' must be {expected}")),
    }
}

/// The RAW value of an environment variable, distinguishing "unset" from "set but not UTF-8".
///
/// `std::env::var(..).ok()` collapses those two into `None`, which is the silent fall-back this
/// module exists to prevent — `S3TAP_MAX=$'\xff\xfe'` ran the default cap with no diagnostic
/// while `S3TAP_MAX=1O00` was correctly rejected. Every reader of a `S3TAP_*`/`MRC_*` VALUE
/// goes through here, including the ones that pass the raw string to a bespoke parser.
///
/// # Errors
/// When the variable is set and its value is not valid UTF-8.
pub fn raw(name: &str) -> Result<Option<String>, String> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .map(|t| Some(t.to_string()))
            .ok_or_else(|| format!("{name} is set but is not valid UTF-8")),
    }
}

/// Read and parse an environment override by name. The wrapper the binaries call; the tests
/// drive [`parse_env`] directly.
///
/// # Errors
/// When the variable is set and does not parse as `T`.
pub fn from_env<T: FromStr>(name: &str, expected: &str) -> Result<Option<T>, String> {
    parse_env(name, raw(name)?.as_deref(), expected)
}

/// Resolve `S3TAP_MAX` for the binaries whose contract is **unset or `0` means no cap**
/// (`s3tap-replay` and `mrc`). A present, non-zero, unparseable value is an error, so a typo
/// cannot quietly run the full trace instead of the intended bounded slice.
///
/// The `*_eval` binaries deliberately do NOT use this: their `0` means "use my default cap"
/// rather than "uncapped", so they call [`from_env`] and apply that themselves.
///
/// # Errors
/// When `S3TAP_MAX` is set and is not a non-negative integer.
pub fn max_events(raw: Option<&str>) -> Result<usize, String> {
    match parse_env::<usize>("S3TAP_MAX", raw, "a non-negative integer")? {
        None | Some(0) => Ok(usize::MAX),
        Some(n) => Ok(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_defers_to_the_caller_and_invalid_is_an_error() {
        assert_eq!(parse_env::<usize>("S3TAP_MAX", None, "an int"), Ok(None), "caller's default");
        assert_eq!(parse_env::<usize>("S3TAP_MAX", Some("1000"), "an int"), Ok(Some(1000)));
        assert_eq!(parse_env::<usize>("S3TAP_MAX", Some(" 1000 "), "an int"), Ok(Some(1000)));
        assert_eq!(parse_env::<usize>("S3TAP_MAX", Some("0"), "an int"), Ok(Some(0)), "caller's");

        // The whole point: a typo is an error, never a silent default. `1O00` is the letter O.
        let e = parse_env::<usize>("S3TAP_MAX", Some("1O00"), "a non-negative integer")
            .expect_err("must reject");
        assert!(e.contains("S3TAP_MAX"), "names the variable: {e}");
        assert!(e.contains("1O00"), "and the offending text: {e}");
        assert!(e.contains("must be a non-negative integer"), "and what was expected: {e}");
        assert!(parse_env::<usize>("S3TAP_MAX", Some(""), "an int").is_err(), "empty is not unset");
        assert!(parse_env::<usize>("S3TAP_MAX", Some("-1"), "an int").is_err(), "not a usize");
        assert!(parse_env::<u64>("S3TAP_FETCH_MS", Some("1.5"), "an int").is_err(), "not an int");
    }

    #[test]
    fn max_events_treats_unset_and_zero_as_uncapped() {
        // The contract `s3tap-replay` and `mrc` share, in one place rather than a copy each.
        assert_eq!(max_events(None), Ok(usize::MAX));
        assert_eq!(max_events(Some("0")), Ok(usize::MAX));
        assert_eq!(max_events(Some("1000")), Ok(1000));
        assert_eq!(max_events(Some(" 1000 ")), Ok(1000));
        for bad in ["1O00", "abc", "-1", "1.5", ""] {
            assert!(max_events(Some(bad)).is_err(), "S3TAP_MAX='{bad}' must be rejected");
        }
    }
}
