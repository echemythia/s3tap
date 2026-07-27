use serde::{Deserialize, Serialize};

/// The operation kind, collapsed to what the cache simulator cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Get,
    Head,
    Put,
    Delete,
    Other,
}

/// One access in the normalized trace. `range`/`size`/`version` are `None` when
/// unknown (e.g. today's s3tap capture doesn't parse them yet — Phase 1). The
/// object-level evaluator uses only `object_id`; the fields are here so the same
/// format serves chunk-level replay later without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormEvent {
    /// Monotonic-ish nanosecond timestamp; used only for ordering.
    pub ts_ns: u64,
    pub op: Op,
    /// Stable cache-key *identity* (a hash is fine; we never need cleartext).
    pub object_id: String,
    /// Inclusive byte range `[start, end]` for a ranged GET; `None` = whole/unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<(u64, u64)>,
    /// Object/transfer size in bytes; `None` = unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// ETag or versionId — lets the sim detect mutation/invalidation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normevent_roundtrips_through_json() {
        let ev = NormEvent {
            ts_ns: 42,
            op: Op::Get,
            object_id: "bucket/sha256:abc".to_string(),
            range: Some((0, 4095)),
            size: Some(4096),
            version: Some("etag-1".to_string()),
            status: Some(206),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: NormEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }
}
