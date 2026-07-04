//! Canonical broker actions. [`BrokerAction`] serializes to the exact same
//! JSON shape as the gateway's `AuthorizeToolCall`, and hashing goes
//! through the shared `aegis-canon` implementation — so the broker, the
//! gateway, and every SDK agree byte-for-byte on what is being approved.
//! If these ever drifted, an approval could bind to a different action
//! than the broker executes, which is exactly the approve-then-swap class
//! AegisAgent exists to defeat.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonicalization scheme version. MUST stay byte-identical with the
/// gateway (`src/src/routes/authorize_canon.rs`) and the SDKs; locked by
/// `tests/canonical_action_vectors.json`.
pub const CANON_VERSION: &str = "aegis-jcs-1";

/// The action an agent asks the broker to perform. Field names and types
/// mirror the gateway's `AuthorizeToolCall` exactly — same canonical
/// bytes, same hash, same approval binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrokerAction {
    pub tool: String,
    pub action: String,
    pub resource: Option<String>,
    pub mutates_state: bool,
    pub parameters: serde_json::Value,
}

/// The deterministic `aegis-jcs-1` string for an action: keys sorted by
/// Unicode code point, compact separators, raw UTF-8, null for an absent
/// resource.
pub fn canonical_action_string(action: &BrokerAction) -> String {
    aegis_canon::canonical_value_string(action)
}

/// SHA-256 (lowercase hex) of the canonical action string — the
/// `action_hash` every approval binds to.
pub fn action_hash(action: &BrokerAction) -> String {
    let digest = Sha256::digest(canonical_action_string(action).as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn merge_action() -> BrokerAction {
        BrokerAction {
            tool: "github".to_string(),
            action: "merge".to_string(),
            resource: Some("repo:acme/api".to_string()),
            mutates_state: true,
            parameters: json!({"branch": "main", "pr": 42}),
        }
    }

    #[test]
    fn canonical_string_matches_the_locked_aegis_jcs_1_vector() {
        assert_eq!(
            canonical_action_string(&merge_action()),
            r#"{"action":"merge","mutates_state":true,"parameters":{"branch":"main","pr":42},"resource":"repo:acme/api","tool":"github"}"#
        );
    }

    #[test]
    fn action_hash_matches_the_locked_vector() {
        // Recomputed independently (python: json.dumps(sort_keys=True,
        // separators=(',',':'), ensure_ascii=False) + sha256). If this
        // breaks, approval binding across broker/gateway/SDKs is broken.
        assert_eq!(
            action_hash(&merge_action()),
            "832024154c9a04449aeb9130a400a2b5253d6de205c46a58a871aee80710241f"
        );
    }

    #[test]
    fn absent_resource_serializes_as_null_like_the_gateway() {
        let action = BrokerAction {
            tool: "github".to_string(),
            action: "merge".to_string(),
            resource: None,
            mutates_state: true,
            parameters: json!({}),
        };
        assert_eq!(
            canonical_action_string(&action),
            r#"{"action":"merge","mutates_state":true,"parameters":{},"resource":null,"tool":"github"}"#
        );
        assert_eq!(
            action_hash(&action),
            "815142c3ac227d2e97b0e869e92f0c84cef4613b4b55b9eaede2d3a55d39c3ab"
        );
    }

    #[test]
    fn parameter_key_order_does_not_change_the_hash() {
        let mut reordered = merge_action();
        reordered.parameters = json!({"pr": 42, "branch": "main"});
        assert_eq!(action_hash(&merge_action()), action_hash(&reordered));
    }

    #[test]
    fn a_single_changed_parameter_changes_the_hash() {
        let mut edited = merge_action();
        edited.parameters = json!({"branch": "main", "pr": 43});
        assert_ne!(action_hash(&merge_action()), action_hash(&edited));
    }
}
