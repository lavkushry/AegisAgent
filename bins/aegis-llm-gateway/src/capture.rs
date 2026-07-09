//! Pure capture helpers: hash bodies, extract OpenAI-style model/token
//! metadata, build lineage records. No I/O — unit-tested in isolation.

use sha2::{Digest, Sha256};

use crate::redact::{looks_unredacted, redact_preview, redact_text};

/// SHA-256 of `bytes` as lowercase hex (64 chars). Matches the gateway's
/// `is_sha256_hex` check on `request_hash` / `response_hash` / `prompt_hash`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Metadata pulled from an OpenAI-compatible chat/completions request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    pub model: String,
    /// Concatenated message contents used for the prompt hash/preview.
    /// Empty when the body has no messages array.
    pub prompt_text: String,
}

/// Metadata pulled from an OpenAI-compatible chat/completions response body.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseMeta {
    pub model: Option<String>,
    pub token_counts: Option<serde_json::Value>,
}

/// Parse model + prompt text from a JSON request body.
///
/// Accepts OpenAI chat-completions shape (`model`, `messages[].content`) and
/// a flat `prompt` string (completions/legacy). Missing model defaults to
/// `"unknown"` so capture still records a finished event on malformed input
/// rather than dropping evidence.
pub fn parse_request_meta(body: &[u8]) -> RequestMeta {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return RequestMeta {
            model: "unknown".to_string(),
            prompt_text: String::new(),
        };
    };
    let model = value
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut prompt_parts: Vec<String> = Vec::new();
    if let Some(messages) = value.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            match msg.get("content") {
                Some(serde_json::Value::String(s)) => prompt_parts.push(s.clone()),
                Some(serde_json::Value::Array(parts)) => {
                    for part in parts {
                        if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                            prompt_parts.push(t.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    } else if let Some(prompt) = value.get("prompt").and_then(|p| p.as_str()) {
        prompt_parts.push(prompt.to_string());
    }

    RequestMeta {
        model,
        prompt_text: prompt_parts.join("\n"),
    }
}

/// Parse token usage from an OpenAI-compatible response body.
pub fn parse_response_meta(body: &[u8]) -> ResponseMeta {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ResponseMeta {
            model: None,
            token_counts: None,
        };
    };
    let model = value
        .get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let token_counts = value.get("usage").cloned().and_then(|u| {
        // Only ship object-shaped usage; ignore unexpected shapes.
        if u.is_object() {
            Some(u)
        } else {
            None
        }
    });
    ResponseMeta {
        model,
        token_counts,
    }
}

/// Build a redacted prompt preview safe for gateway ingest. Returns `None`
/// when there is no prompt text. Guarantees `looks_unredacted` is false.
pub fn safe_prompt_preview(prompt_text: &str) -> Option<String> {
    if prompt_text.is_empty() {
        return None;
    }
    let preview = redact_preview(prompt_text);
    // Defense in depth: if scrubbing somehow left a marker, drop the preview
    // entirely rather than ship something the gateway would 400.
    if looks_unredacted(&preview) {
        None
    } else {
        Some(preview)
    }
}

/// Scrub a failure detail string so it is safe for event sinks and logs.
pub fn safe_failure_detail(detail: &str) -> String {
    let scrubbed = redact_text(detail, 500);
    if looks_unredacted(&scrubbed) {
        "[REDACTED]".to_string()
    } else {
        scrubbed
    }
}

/// Outcome status values accepted by `POST /v1/ingest/model-calls`.
pub fn normalize_status(status: &str) -> &'static str {
    match status {
        "success" => "success",
        "timeout" => "timeout",
        "cancelled" => "cancelled",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_64_lowercase_hex() {
        let h = sha256_hex(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, h.to_lowercase());
    }

    #[test]
    fn parse_request_meta_extracts_model_and_messages() {
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"},{"role":"system","content":"be brief"}]}"#;
        let meta = parse_request_meta(body);
        assert_eq!(meta.model, "gpt-4o-mini");
        assert!(meta.prompt_text.contains("hi"));
        assert!(meta.prompt_text.contains("be brief"));
    }

    #[test]
    fn parse_response_meta_extracts_usage_tokens() {
        let body = br#"{"model":"gpt-4o-mini","usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16},"choices":[]}"#;
        let meta = parse_response_meta(body);
        assert_eq!(meta.model.as_deref(), Some("gpt-4o-mini"));
        let usage = meta.token_counts.expect("usage present");
        assert_eq!(usage["prompt_tokens"], 12);
        assert_eq!(usage["completion_tokens"], 4);
    }

    #[test]
    fn safe_prompt_preview_never_leaks_api_keys() {
        let preview = safe_prompt_preview("call with sk-live-secret-value please").unwrap();
        assert!(!looks_unredacted(&preview));
        assert!(!preview.contains("sk-live"));
    }

    #[test]
    fn safe_failure_detail_redacts_bearer_tokens() {
        let detail = safe_failure_detail("upstream 401: Bearer sk-abc123 not accepted");
        assert!(!looks_unredacted(&detail));
        assert!(!detail.to_lowercase().contains("sk-abc"));
        assert!(!detail.to_lowercase().contains("bearer sk"));
    }
}
