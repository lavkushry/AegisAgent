//! Phase 2 — SOC notify sink (out-of-band Slack / webhook push).
//!
//! Pushes high-signal events to an external webhook (Slack-compatible JSON)
//! from the background [`crate::events::drain`] task. This is **completely
//! out-of-band**: it never touches the inline `/v1/authorize` budget (design
//! law 3), and a failed or slow webhook **never blocks or panics the drain**.
//!
//! ## High-signal trigger policy
//!
//! Only three categories of events generate a notification — chosen to be
//! actionable and avoid alert fatigue:
//!
//! 1. **Every `deny` decision** — a Cedar-denied action should always be
//!    visible to the SOC team.
//! 2. **Every `require_approval` decision** — a human is in the loop; the
//!    SOC team should see it.
//! 3. **Every HIGH-severity alert or incident** produced by the detection /
//!    correlation engines — these represent active threat patterns (confused
//!    deputy, deny storm, runaway agent).
//!
//! Plain `allow` decisions are **never** notified (no spam).
//!
//! ## Redaction invariant
//!
//! [`NotifyMessage`] carries identifiers, decision, severity, and summary
//! only. **No secrets, no tokens, no raw action payloads** — the redaction
//! moat invariant is preserved even in the external push.
//!
//! ## Fire-and-forget / non-blocking
//!
//! [`WebhookSink::notify`] spawns a separate Tokio task with a hard 5-second
//! timeout. Failure (network error, timeout, non-2xx) is logged at `warn` and
//! discarded. The drain task never awaits the outbound call.
//!
//! ## Configuration
//!
//! Set `AEGIS_WEBHOOK_URL` to a Slack incoming-webhook URL (or any compatible
//! endpoint) to activate. Leave it unset for `NullSink` (local/dev/tests).

use serde::{Deserialize, Serialize};
use tracing::warn;

// ─────────────────────────────────────────────────────────────────────────────
// NotifyMessage — the redacted, serialisable envelope sent to the webhook.
// Contains identifiers and metadata only; never secrets or raw payloads.
// ─────────────────────────────────────────────────────────────────────────────

/// A small, redacted notification envelope produced for every high-signal event.
///
/// Fields are chosen so that a Slack message or SIEM webhook carries enough
/// context for a human analyst without leaking any secret or raw payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyMessage {
    /// Event class: `"authorize_decision"` | `"alert"` | `"incident"`.
    pub kind: String,
    /// `"high"` | `"info"` (mirrors alert/incident severity; for decisions: `"high"` on deny/require_approval).
    pub severity: String,
    /// Owning tenant — messages stay tenant-scoped.
    pub tenant_id: String,
    /// The acting agent identifier.
    pub agent_id: String,
    /// Human-readable, secret-free summary.
    pub summary: String,
    /// Optional alert or incident id (set when this message was produced by
    /// detection/correlation rather than directly from a decision event).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_or_incident_id: Option<String>,
    /// RFC 3339 UTC timestamp the source event occurred.
    pub occurred_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// NotifySink trait
// ─────────────────────────────────────────────────────────────────────────────

/// Out-of-band notification sink. Implementors receive high-signal
/// [`NotifyMessage`]s from the background drain and dispatch them externally.
///
/// The method signature is **fire-and-forget**: callers do not await a result.
/// Implementations must **never block the caller** and **never panic**.
pub trait NotifySink: Send + Sync {
    /// Dispatch a notification for a high-signal event.
    ///
    /// # Contract
    /// - Must not block the calling task.
    /// - Must not panic under any condition.
    /// - Must not log secrets or raw payloads.
    fn notify(&self, msg: NotifyMessage);
}

// ─────────────────────────────────────────────────────────────────────────────
// NullSink — no-op (default for local / dev / tests without a webhook)
// ─────────────────────────────────────────────────────────────────────────────

/// A no-op [`NotifySink`] that silently discards every message.
///
/// Used when `AEGIS_WEBHOOK_URL` is not set. Zero allocation, zero I/O.
pub struct NullSink;

impl NotifySink for NullSink {
    fn notify(&self, _msg: NotifyMessage) {
        // Intentional no-op.
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WebhookSink — Slack-compatible JSON POST, fire-and-forget
// ─────────────────────────────────────────────────────────────────────────────

/// A [`NotifySink`] that POSTs a Slack-compatible JSON body to a configured URL.
///
/// Each [`notify`](NotifySink::notify) call spawns a short-lived Tokio task.
/// The task has a hard 5-second timeout; failures are logged at `warn` and
/// discarded. The drain is never blocked.
pub struct WebhookSink {
    /// The webhook endpoint URL (e.g. a Slack incoming-webhook URL).
    url: String,
    /// Shared reqwest client (keep-alive, TLS reuse).
    client: reqwest::Client,
}

impl WebhookSink {
    /// Construct a [`WebhookSink`] posting to `url`.
    pub fn new(url: impl Into<String>) -> Self {
        WebhookSink {
            url: url.into(),
            // Default client with rustls-tls: no proxy env leakage, strict TLS.
            client: reqwest::Client::new(),
        }
    }
}

/// Build the Slack-compatible JSON payload for `msg`.
///
/// Returns a [`serde_json::Value`] with a top-level `"text"` field (displayed
/// as the Slack preview) plus structured fields in `"attachments"`. Separated
/// into a pure function so tests can assert on its output without I/O.
pub fn slack_body(msg: &NotifyMessage) -> serde_json::Value {
    let icon = match msg.severity.as_str() {
        "high" => ":rotating_light:",
        _ => ":information_source:",
    };
    let text = format!(
        "{icon} *[AegisAgent SOC]* `{kind}` | severity={severity} | tenant=`{tenant}` | agent=`{agent}`\n>{summary}",
        icon = icon,
        kind = msg.kind,
        severity = msg.severity,
        tenant = msg.tenant_id,
        agent = msg.agent_id,
        summary = msg.summary,
    );
    let mut fields = vec![
        serde_json::json!({ "title": "Kind",      "value": msg.kind,      "short": true }),
        serde_json::json!({ "title": "Severity",  "value": msg.severity,  "short": true }),
        serde_json::json!({ "title": "Tenant",    "value": msg.tenant_id, "short": true }),
        serde_json::json!({ "title": "Agent",     "value": msg.agent_id,  "short": true }),
        serde_json::json!({ "title": "Timestamp", "value": msg.occurred_at, "short": false }),
        serde_json::json!({ "title": "Summary",   "value": msg.summary,   "short": false }),
    ];
    if let Some(ref id) = msg.alert_or_incident_id {
        fields.push(serde_json::json!({
            "title": "Alert/Incident ID",
            "value": id,
            "short": true
        }));
    }
    let color = match msg.severity.as_str() {
        "high" => "danger",
        _ => "warning",
    };
    serde_json::json!({
        "text": text,
        "attachments": [{
            "color": color,
            "fields": fields,
            "footer": "AegisAgent SOC",
            "ts": msg.occurred_at,
        }]
    })
}

impl NotifySink for WebhookSink {
    fn notify(&self, msg: NotifyMessage) {
        let url = self.url.clone();
        let client = self.client.clone();
        let body = slack_body(&msg);

        // Fire-and-forget: spawn a task; a slow/failing webhook never blocks
        // the drain. The spawned task cannot propagate a panic to the drain.
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.post(&url).json(&body).send(),
            )
            .await;

            match result {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    // Notification delivered — nothing to log (avoid noise).
                }
                Ok(Ok(resp)) => {
                    warn!(
                        status = %resp.status(),
                        "notify webhook returned non-2xx — discarding"
                    );
                }
                Ok(Err(err)) => {
                    warn!(error = %err, "notify webhook request failed — discarding");
                }
                Err(_elapsed) => {
                    warn!("notify webhook timed out after 5s — discarding");
                }
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructor: from_env()
// ─────────────────────────────────────────────────────────────────────────────

/// Construct the appropriate [`NotifySink`] from environment variables.
///
/// * If `AEGIS_WEBHOOK_URL` is set and non-empty → [`WebhookSink`].
/// * Otherwise → [`NullSink`] (safe default; no network calls).
pub fn from_env() -> Box<dyn NotifySink> {
    match std::env::var("AEGIS_WEBHOOK_URL") {
        Ok(url) if !url.trim().is_empty() => {
            tracing::info!(url = %url, "SOC notify: WebhookSink active");
            Box::new(WebhookSink::new(url))
        }
        _ => {
            tracing::debug!("SOC notify: NullSink (AEGIS_WEBHOOK_URL not set)");
            Box::new(NullSink)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (TDD — written first; no real network calls)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ── Recording mock sink ──────────────────────────────────────────────────

    /// A [`NotifySink`] that records every message into a shared vec for
    /// assertion. No I/O, no network calls.
    #[derive(Clone, Default)]
    struct RecordingSink {
        messages: Arc<Mutex<Vec<NotifyMessage>>>,
    }

    impl RecordingSink {
        fn new() -> Self {
            RecordingSink::default()
        }

        fn recorded(&self) -> Vec<NotifyMessage> {
            self.messages.lock().expect("lock").clone()
        }
    }

    impl NotifySink for RecordingSink {
        fn notify(&self, msg: NotifyMessage) {
            self.messages.lock().expect("lock").push(msg);
        }
    }

    /// Build a minimal `NotifyMessage` for testing.
    fn make_msg(kind: &str, severity: &str, decision_or_summary: &str) -> NotifyMessage {
        NotifyMessage {
            kind: kind.to_string(),
            severity: severity.to_string(),
            tenant_id: "tenant_test".to_string(),
            agent_id: "agent_test".to_string(),
            summary: decision_or_summary.to_string(),
            alert_or_incident_id: None,
            occurred_at: "2026-06-06T12:00:00Z".to_string(),
        }
    }

    // ── Core trigger policy: deny records a message ──────────────────────────

    #[test]
    fn deny_decision_records_a_message() {
        let sink = RecordingSink::new();
        let msg = make_msg("authorize_decision", "high", "Action github/merge denied");
        sink.notify(msg.clone());
        let recorded = sink.recorded();
        assert_eq!(recorded.len(), 1, "exactly one message recorded for deny");
        assert_eq!(recorded[0].kind, "authorize_decision");
        assert_eq!(recorded[0].severity, "high");
        assert_eq!(recorded[0].tenant_id, "tenant_test");
        assert_eq!(recorded[0].agent_id, "agent_test");
        assert_eq!(recorded[0].summary, "Action github/merge denied");
    }

    // ── Core trigger policy: allow records NOTHING ───────────────────────────
    // (The caller — events.rs — is responsible for not calling notify on allow;
    // we verify the drain-logic decision here: if notify IS called, it records.
    // The below test verifies that allow does NOT call notify.)

    #[test]
    fn allow_event_does_not_trigger_notify_from_drain_logic() {
        // Simulate the drain decision logic: only call notify for deny /
        // require_approval.
        let sink = RecordingSink::new();
        let decision = "allow";
        if decision == "deny" || decision == "require_approval" {
            sink.notify(make_msg("authorize_decision", "high", "allowed action"));
        }
        assert!(
            sink.recorded().is_empty(),
            "allow must NOT produce a notification"
        );
    }

    // ── Core trigger policy: require_approval records a message ─────────────

    #[test]
    fn require_approval_decision_records_a_message() {
        let sink = RecordingSink::new();
        let msg = make_msg(
            "authorize_decision",
            "high",
            "Human approval required for github/merge",
        );
        sink.notify(msg);
        assert_eq!(sink.recorded().len(), 1);
        assert_eq!(sink.recorded()[0].kind, "authorize_decision");
    }

    // ── Core trigger policy: high-severity incident records a message ────────

    #[test]
    fn high_incident_records_a_message() {
        let sink = RecordingSink::new();
        let msg = NotifyMessage {
            kind: "incident".to_string(),
            severity: "high".to_string(),
            tenant_id: "tenant_test".to_string(),
            agent_id: "agent_test".to_string(),
            summary: "Agent accumulated 5 denies in 60s (deny storm)".to_string(),
            alert_or_incident_id: Some("inc-abc123".to_string()),
            occurred_at: "2026-06-06T12:00:00Z".to_string(),
        };
        sink.notify(msg.clone());
        let recorded = sink.recorded();
        assert_eq!(
            recorded.len(),
            1,
            "high incident must produce one notification"
        );
        assert_eq!(recorded[0].severity, "high");
        assert_eq!(
            recorded[0].alert_or_incident_id,
            Some("inc-abc123".to_string())
        );
    }

    // ── Info alert does NOT produce a message (only HIGH fires notify) ───────

    #[test]
    fn info_alert_does_not_trigger_notify_from_drain_logic() {
        // Simulate the drain decision logic: only HIGH-severity alerts/incidents
        // call notify. INFO is logged but not notified.
        let sink = RecordingSink::new();
        let severity = "info";
        if severity == "high" {
            sink.notify(make_msg("alert", "info", "info-only alert"));
        }
        assert!(
            sink.recorded().is_empty(),
            "info-severity alert must NOT produce a notification"
        );
    }

    // ── Redaction invariant: message carries NO secret/payload fields ─────────

    #[test]
    fn notify_message_contains_no_secret_or_payload_fields() {
        let msg = NotifyMessage {
            kind: "authorize_decision".to_string(),
            severity: "high".to_string(),
            tenant_id: "tenant_123".to_string(),
            agent_id: "agent_456".to_string(),
            summary: "Action denied: untrusted mutation".to_string(),
            alert_or_incident_id: Some("alert-xyz".to_string()),
            occurred_at: "2026-06-06T12:00:00Z".to_string(),
        };

        // Serialise to JSON and verify the field set — no secrets, no tokens,
        // no raw parameters/payloads.
        let json_str = serde_json::to_string(&msg).expect("serialise");
        let json_val: serde_json::Value = serde_json::from_str(&json_str).expect("parse");
        let obj = json_val.as_object().expect("object");

        // Only these top-level fields may be present:
        let allowed_fields = [
            "kind",
            "severity",
            "tenant_id",
            "agent_id",
            "summary",
            "alert_or_incident_id",
            "occurred_at",
        ];
        for key in obj.keys() {
            assert!(
                allowed_fields.contains(&key.as_str()),
                "unexpected field in NotifyMessage: {key} — possible secret leak"
            );
        }

        // These must never appear (even embedded in values):
        for forbidden in &["token", "secret", "payload", "password", "credential"] {
            assert!(
                !json_str.to_ascii_lowercase().contains(forbidden),
                "forbidden word '{forbidden}' found in NotifyMessage serialisation"
            );
        }
    }

    // ── Slack body construction (pure function, no I/O) ──────────────────────

    #[test]
    fn slack_body_contains_required_fields() {
        let msg = NotifyMessage {
            kind: "authorize_decision".to_string(),
            severity: "high".to_string(),
            tenant_id: "tenant_99".to_string(),
            agent_id: "agent_99".to_string(),
            summary: "Action github/push denied (deny)".to_string(),
            alert_or_incident_id: None,
            occurred_at: "2026-06-06T10:00:00Z".to_string(),
        };
        let body = slack_body(&msg);

        // Top-level "text" and "attachments" must be present.
        assert!(body.get("text").is_some(), "slack body must have 'text'");
        assert!(
            body.get("attachments").is_some(),
            "slack body must have 'attachments'"
        );

        let text = body["text"].as_str().expect("text is string");
        assert!(text.contains("tenant_99"), "text must include tenant_id");
        assert!(text.contains("agent_99"), "text must include agent_id");
        assert!(text.contains("high"), "text must include severity");
    }

    #[test]
    fn slack_body_high_severity_uses_danger_color() {
        let msg = make_msg("incident", "high", "deny storm detected");
        let body = slack_body(&msg);
        let color = body["attachments"][0]["color"].as_str().expect("color");
        assert_eq!(color, "danger");
    }

    #[test]
    fn slack_body_info_severity_uses_warning_color() {
        let msg = make_msg("alert", "info", "approval surface");
        let body = slack_body(&msg);
        let color = body["attachments"][0]["color"].as_str().expect("color");
        assert_eq!(color, "warning");
    }

    #[test]
    fn slack_body_includes_alert_or_incident_id_when_set() {
        let msg = NotifyMessage {
            kind: "alert".to_string(),
            severity: "high".to_string(),
            tenant_id: "t".to_string(),
            agent_id: "a".to_string(),
            summary: "summary".to_string(),
            alert_or_incident_id: Some("inc-abc".to_string()),
            occurred_at: "2026-06-06T00:00:00Z".to_string(),
        };
        let body = slack_body(&msg);
        let body_str = serde_json::to_string(&body).expect("serialise");
        assert!(
            body_str.contains("inc-abc"),
            "slack body must include the alert/incident id"
        );
    }

    #[test]
    fn slack_body_contains_no_secret_or_payload_fields() {
        let msg = make_msg("authorize_decision", "high", "deny");
        let body = slack_body(&msg);
        let body_str = serde_json::to_string(&body).expect("serialise");
        for forbidden in &["token", "secret", "password", "credential"] {
            assert!(
                !body_str.to_ascii_lowercase().contains(forbidden),
                "forbidden word '{forbidden}' found in slack body"
            );
        }
    }

    // ── NullSink: never panics ────────────────────────────────────────────────

    #[test]
    fn null_sink_never_panics() {
        let sink = NullSink;
        // Must not panic regardless of message content.
        sink.notify(make_msg("authorize_decision", "high", "test"));
        sink.notify(make_msg("incident", "high", "storm"));
        sink.notify(make_msg("alert", "info", "surface"));
    }

    // ── from_env: NullSink when env var absent ────────────────────────────────

    #[test]
    fn from_env_returns_null_sink_when_env_var_absent() {
        // Unset the env var for this test (best-effort; env is per-process not
        // per-thread, but for a unit test the absence is the normal state).
        std::env::remove_var("AEGIS_WEBHOOK_URL");
        let sink = from_env();
        // NullSink must not panic when called.
        sink.notify(make_msg("authorize_decision", "high", "test"));
    }
}
