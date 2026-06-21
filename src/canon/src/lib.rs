//! `aegis-jcs-1` JSON canonicalization — the foundation of the fail-closed
//! approval-integrity guarantee.
//!
//! This crate exists so the canonicalization logic can be exercised by
//! `cargo-fuzz` targets (TEST-002, #1162) without depending on the gateway's
//! binary crate. The gateway (`routes::canonicalize_json` /
//! `routes::canonical_action_string`) delegates here.
//!
//! **Scheme `aegis-jcs-1`**: object keys sorted by Unicode code point, compact
//! separators (`serde_json::to_string` default), raw UTF-8 (no `\uXXXX`
//! escaping of non-ASCII). MUST stay byte-identical with the Python/Go/TS SDKs
//! — see `tests/canonical_action_vectors.json`. A divergence here silently
//! breaks the fail-closed guarantee.

use serde::Serialize;
use serde_json::Value;

/// Recursively sort every JSON object's keys by Unicode code point. Arrays and
/// primitives are returned unchanged (order within arrays is meaningful and
/// preserved).
pub fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_json).collect()),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            let mut sorted = serde_json::Map::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize_json(value));
            }
            Value::Object(sorted)
        }
        primitive => primitive,
    }
}

/// Serialize `value`, canonicalize it (`aegis-jcs-1`), and render the compact
/// JSON string the SDKs hash. If serialization fails for any reason, returns
/// the empty string (fail-closed: an empty canonical string never hash-matches
/// a real action).
pub fn canonical_value_string<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(v) => serde_json::to_string(&canonicalize_json(v)).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_by_unicode_code_point() {
        let input = json!({"b": 1, "a": 2, "c": 3});
        let out = canonicalize_json(input);
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            r#"{"a":2,"b":1,"c":3}"#
        );
    }

    #[test]
    fn recurses_into_nested_objects_and_arrays() {
        let input = json!({"z": {"y": 1, "x": 2}, "a": [{"d": 1, "c": 2}]});
        let out = canonicalize_json(input);
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            r#"{"a":[{"c":2,"d":1}],"z":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn preserves_array_order() {
        let input = json!([3, 1, 2]);
        let out = canonicalize_json(input);
        assert_eq!(serde_json::to_string(&out).unwrap(), "[3,1,2]");
    }

    #[test]
    fn raw_utf8_not_escaped() {
        #[derive(Serialize)]
        struct S {
            name: String,
        }
        let s = canonical_value_string(&S {
            name: "héllo".to_string(),
        });
        assert_eq!(s, r#"{"name":"héllo"}"#);
    }

    #[test]
    fn empty_object_round_trips() {
        let input = json!({});
        let out = canonicalize_json(input);
        assert_eq!(serde_json::to_string(&out).unwrap(), "{}");
    }
}
