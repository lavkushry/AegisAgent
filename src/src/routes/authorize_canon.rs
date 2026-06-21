//! Canonicalization and hashing helpers for the authorization pipeline.
//!
//! Extracted from `authorize.rs` for clarity. All functions are `pub(crate)` and
//! re-exported via `routes/mod.rs` so existing call sites are unaffected.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::models::*;

/// Recursively sort JSON object keys by Unicode code point (`aegis-jcs-1`).
/// Delegates to `aegis_canon` (TEST-002, #1162) so the fuzz targets in
/// `fuzz/` exercise the exact same implementation as the gateway.
pub(crate) fn canonicalize_json(value: Value) -> Value {
    aegis_canon::canonicalize_json(value)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Canonicalization scheme version. MUST stay byte-identical with the SDKs
/// (see `tests/canonical_action_vectors.json` and `aegisagent.decorator.CANON_VERSION`).
/// Scheme "aegis-jcs-1": keys sorted by Unicode code point, compact separators,
/// raw UTF-8 (serde_json does not escape non-ASCII), null for absent resource.
// Referenced by the cross-language corpus tests; unused in the non-test binary build.
#[allow(dead_code)]
pub const CANON_VERSION: &str = "aegis-jcs-1";

/// Deterministic canonical string for a tool call. The SDK hashes the exact same
/// string; byte-equality here is the foundation of the fail-closed approval guarantee.
pub(crate) fn canonical_action_string(tool_call: &AuthorizeToolCall) -> String {
    aegis_canon::canonical_value_string(tool_call)
}

pub(crate) fn hash_tool_call(tool_call: &AuthorizeToolCall) -> String {
    sha256_hex(canonical_action_string(tool_call).as_bytes())
}
