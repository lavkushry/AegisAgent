//! SOC-004 (#1187) — agentless event ingestion.
//!
//! `POST /v1/ingest` lets external systems that don't run the AegisAgent SDK
//! (GitHub webhooks, OpenAI/LangSmith trace exporters, ...) feed activity into
//! the same SOC pipeline as `/v1/authorize`. Each normalizer here is a pure,
//! deterministic `(tenant_id, &serde_json::Value) -> Option<AseEvent>` function
//! (Law 1/2: no scoring, no model). The handler (`routes::ingest_event`) emits
//! the normalized [`AseEvent`] onto the same [`crate::events::EventSink`] the
//! inline authorize path uses, so it flows through the identical
//! detect -> correlate -> respond pipeline (Law 3: this never touches the
//! `/v1/authorize` budget — ingestion is its own request).
//!
//! Normalized events always carry `decision = "allow"` (ingestion only
//! *observes* external activity; it never grants or denies anything) and
//! `risk_score = 0` (advisory only, per Law 1).

use crate::events::AseEvent;
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

/// Sources accepted by `POST /v1/ingest`.
pub const SUPPORTED_SOURCES: &[&str] = &["github_webhook", "openai_trace"];

fn base_event(tenant_id: &str, kind: &str) -> AseEvent {
    AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: kind.to_string(),
        agent_id: "unknown".to_string(),
        decision: "allow".to_string(),
        tool: String::new(),
        action: String::new(),
        resource: None,
        risk_score: 0,
        reason: "ingested via /v1/ingest".to_string(),
        run_id: None,
        trace_id: None,
        matched_policies: Vec::new(),
    }
}

/// Normalize a GitHub webhook payload, e.g.:
///
/// ```json
/// {
///   "action": "opened",
///   "repository": {"full_name": "org/repo"},
///   "sender": {"login": "alice"}
/// }
/// ```
///
/// Maps to `tool = "github"`, `action = <action>`, `agent_id = sender.login`,
/// `resource = repository.full_name`. Returns `None` if `action` or
/// `sender.login` is missing — the minimal fields needed to attribute the
/// event to an actor.
pub fn normalize_github_webhook(tenant_id: &str, payload: &Value) -> Option<AseEvent> {
    let action = payload.get("action")?.as_str()?;
    let sender = payload.get("sender")?.get("login")?.as_str()?;
    let repo = payload
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(|v| v.as_str());

    let mut event = base_event(tenant_id, "external_event:github_webhook");
    event.agent_id = sender.to_string();
    event.tool = "github".to_string();
    event.action = action.to_string();
    event.resource = repo.map(|s| s.to_string());
    Some(event)
}

/// Normalize an OpenAI-style trace/log entry, e.g.:
///
/// ```json
/// {
///   "user": "agent-123",
///   "model": "gpt-4",
///   "choices": [
///     {"message": {"tool_calls": [{"function": {"name": "get_weather"}}]}}
///   ]
/// }
/// ```
///
/// Maps to `tool = "openai"`, `agent_id = user`, `action = <first tool_call's
/// function name>` (or `"completion"` if the response made no tool calls),
/// `resource = model`. Returns `None` if `user` is missing — the minimal field
/// needed to attribute the event to an actor.
pub fn normalize_openai_trace(tenant_id: &str, payload: &Value) -> Option<AseEvent> {
    let user = payload.get("user")?.as_str()?;
    let model = payload.get("model").and_then(|v| v.as_str());

    let action = payload
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|tc| tc.as_array())
        .and_then(|arr| arr.first())
        .and_then(|call| call.get("function"))
        .and_then(|f| f.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("completion");

    let mut event = base_event(tenant_id, "external_event:openai_trace");
    event.agent_id = user.to_string();
    event.tool = "openai".to_string();
    event.action = action.to_string();
    event.resource = model.map(|s| s.to_string());
    Some(event)
}

/// Dispatch to the normalizer for `source`. Returns `Ok(None)` for an
/// unrecognized payload shape (missing required fields), `Err(())` for an
/// unsupported `source` value.
pub fn normalize(tenant_id: &str, source: &str, payload: &Value) -> Result<Option<AseEvent>, ()> {
    match source {
        "github_webhook" => Ok(normalize_github_webhook(tenant_id, payload)),
        "openai_trace" => Ok(normalize_openai_trace(tenant_id, payload)),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn github_webhook_normalizes_pull_request_event() {
        let payload = json!({
            "action": "opened",
            "repository": {"full_name": "lavkushry/AegisAgent"},
            "sender": {"login": "alice"}
        });

        let event = normalize_github_webhook("tenant_a", &payload).unwrap();
        assert_eq!(event.tenant_id, "tenant_a");
        assert_eq!(event.tool, "github");
        assert_eq!(event.action, "opened");
        assert_eq!(event.agent_id, "alice");
        assert_eq!(event.resource.as_deref(), Some("lavkushry/AegisAgent"));
        assert_eq!(event.decision, "allow");
        assert_eq!(event.risk_score, 0);
        assert_eq!(event.kind, "external_event:github_webhook");
    }

    #[test]
    fn github_webhook_missing_sender_returns_none() {
        let payload = json!({"action": "opened", "repository": {"full_name": "org/repo"}});
        assert!(normalize_github_webhook("tenant_a", &payload).is_none());
    }

    #[test]
    fn openai_trace_normalizes_tool_call() {
        let payload = json!({
            "user": "agent-123",
            "model": "gpt-4",
            "choices": [
                {"message": {"tool_calls": [{"function": {"name": "get_weather"}}]}}
            ]
        });

        let event = normalize_openai_trace("tenant_a", &payload).unwrap();
        assert_eq!(event.tool, "openai");
        assert_eq!(event.action, "get_weather");
        assert_eq!(event.agent_id, "agent-123");
        assert_eq!(event.resource.as_deref(), Some("gpt-4"));
        assert_eq!(event.kind, "external_event:openai_trace");
    }

    #[test]
    fn openai_trace_without_tool_calls_defaults_to_completion() {
        let payload = json!({"user": "agent-123", "model": "gpt-4", "choices": []});
        let event = normalize_openai_trace("tenant_a", &payload).unwrap();
        assert_eq!(event.action, "completion");
    }

    #[test]
    fn openai_trace_missing_user_returns_none() {
        let payload = json!({"model": "gpt-4"});
        assert!(normalize_openai_trace("tenant_a", &payload).is_none());
    }

    #[test]
    fn normalize_rejects_unsupported_source() {
        assert!(normalize("tenant_a", "slack_webhook", &json!({})).is_err());
    }

    #[test]
    fn normalize_returns_none_for_unrecognized_payload_shape() {
        assert!(
            normalize("tenant_a", "github_webhook", &json!({"foo": "bar"}))
                .unwrap()
                .is_none()
        );
    }
}
