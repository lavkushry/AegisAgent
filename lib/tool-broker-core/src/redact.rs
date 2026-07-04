//! Output and event scrubbing. Two complementary passes, both applied to
//! anything that leaves the broker (connector output, events, receipts):
//!
//! - [`redact_secrets`]: *value-based* — every occurrence of a resolved
//!   secret's exact value, anywhere in a JSON tree (string values and
//!   object keys alike), becomes `[REDACTED]`. This is the hard guarantee
//!   behind "no raw credentials in logs/events": whatever a connector
//!   echoes back, the credential value itself cannot survive the pass.
//! - [`redact_sensitive_keys`]: *key-based* — values under conventionally
//!   sensitive key names (`token`, `password`, `authorization`, …) are
//!   masked defensively, even when they aren't a known secret.

use serde_json::Value;

pub const REDACTED: &str = "[REDACTED]";

const SENSITIVE_KEY_MARKERS: &[&str] = &[
    "token",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "session_key",
    "access_key",
];

fn key_is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn scrub_string(s: &str, secrets: &[&str]) -> String {
    let mut out = s.to_string();
    for secret in secrets {
        if !secret.is_empty() && out.contains(secret) {
            out = out.replace(secret, REDACTED);
        }
    }
    out
}

/// Replaces every occurrence of any of `secrets` in `value` — inside
/// string values, inside object keys, anywhere — with `[REDACTED]`.
pub fn redact_secrets(value: Value, secrets: &[&str]) -> Value {
    match value {
        Value::String(s) => Value::String(scrub_string(&s, secrets)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| redact_secrets(item, secrets))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, val)| (scrub_string(&key, secrets), redact_secrets(val, secrets)))
                .collect(),
        ),
        other => other,
    }
}

/// Masks the values of conventionally sensitive keys (recursively), no
/// matter what those values are.
pub fn redact_sensitive_keys(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(redact_sensitive_keys).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, val)| {
                    if key_is_sensitive(&key) {
                        (key, Value::String(REDACTED.to_string()))
                    } else {
                        (key, redact_sensitive_keys(val))
                    }
                })
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_secret_value_is_scrubbed_wherever_it_appears() {
        let output = json!({
            "stdout": "Authorization: Bearer ghp_leaky embedded in output",
            "nested": {"echo": ["prefix ghp_leaky suffix"]},
            "ghp_leaky": "even as an object key",
        });
        let scrubbed = redact_secrets(output, &["ghp_leaky"]);
        let text = scrubbed.to_string();
        assert!(!text.contains("ghp_leaky"), "leaked: {text}");
        assert_eq!(
            scrubbed["stdout"],
            json!(format!(
                "Authorization: Bearer {REDACTED} embedded in output"
            ))
        );
        assert_eq!(
            scrubbed["nested"]["echo"][0],
            json!(format!("prefix {REDACTED} suffix"))
        );
    }

    #[test]
    fn an_empty_secret_never_matches_everything() {
        let output = json!({"stdout": "plain output"});
        assert_eq!(redact_secrets(output.clone(), &[""]), output);
    }

    #[test]
    fn sensitive_key_names_are_masked_recursively_and_case_insensitively() {
        let output = json!({
            "result": "ok",
            "Api_Key": "abc123",
            "config": {"github_token": "ghp_x", "retries": 3},
            "items": [{"PASSWORD": "hunter2"}],
        });
        let scrubbed = redact_sensitive_keys(output);
        assert_eq!(scrubbed["Api_Key"], json!(REDACTED));
        assert_eq!(scrubbed["config"]["github_token"], json!(REDACTED));
        assert_eq!(scrubbed["config"]["retries"], json!(3));
        assert_eq!(scrubbed["items"][0]["PASSWORD"], json!(REDACTED));
        assert_eq!(scrubbed["result"], json!("ok"));
    }

    #[test]
    fn non_sensitive_content_passes_through_unchanged() {
        let output = json!({"status": 200, "body": "hello", "flags": [true, null]});
        assert_eq!(
            redact_sensitive_keys(redact_secrets(output.clone(), &["zzz"])),
            output
        );
    }
}
