//! Admission webhooks (#1143, API-004): an optional pre-authorize hook
//! letting an external system inspect, reject, or mutate an `/v1/authorize`
//! request before it reaches Cedar — Kubernetes' MutatingAdmissionWebhook /
//! ValidatingAdmissionWebhook, applied to AegisAgent's authorize hot path.
//!
//! Fully opt-in: when `AEGIS_ADMISSION_WEBHOOK_URL` is unset,
//! [`AdmissionWebhookClient::from_env`] returns `None` and `/v1/authorize`
//! makes no extra network call at all (pre-#1143 behavior, byte-for-byte).

use crate::models::AuthorizeRequest;
use serde::Deserialize;
use std::time::Duration;

/// Outcome of an admission webhook call.
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionOutcome {
    /// Proceed unchanged.
    Pass,
    /// Deny the request before it reaches Cedar, carrying the
    /// webhook-supplied (or failure-derived) reason.
    Reject(String),
    /// Proceed, but with `tool_call.parameters` replaced by this value.
    Mutate(serde_json::Value),
}

/// Wire shape an admission webhook is expected to return.
#[derive(Debug, Deserialize)]
struct AdmissionWebhookResponse {
    decision: String,
    reason: Option<String>,
    parameters: Option<serde_json::Value>,
}

/// Config + reusable HTTP client for the optional admission webhook.
/// Constructed once at gateway startup and stored in `AppState`.
pub struct AdmissionWebhookClient {
    url: String,
    http_client: reqwest::Client,
    timeout: Duration,
    /// On timeout/network/parse failure: `true` resolves to `Pass` (logged
    /// as a warning), `false` resolves to `Reject` (fail-closed). Defaults
    /// to fail-open per the issue's "fail-open configurable to fail-closed".
    fail_open: bool,
}

impl AdmissionWebhookClient {
    /// Reads `AEGIS_ADMISSION_WEBHOOK_URL` (required to enable the feature),
    /// `AEGIS_ADMISSION_WEBHOOK_TIMEOUT_SECS` (default 5), and
    /// `AEGIS_ADMISSION_WEBHOOK_FAIL_OPEN` (default `true`; any value other
    /// than `"false"`/`"0"` is treated as enabled).
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("AEGIS_ADMISSION_WEBHOOK_URL").ok()?;
        let timeout_secs = std::env::var("AEGIS_ADMISSION_WEBHOOK_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);
        let fail_open = std::env::var("AEGIS_ADMISSION_WEBHOOK_FAIL_OPEN")
            .ok()
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);
        Some(Self::new(url, timeout_secs, fail_open))
    }

    pub fn new(url: String, timeout_secs: u64, fail_open: bool) -> Self {
        Self {
            url,
            http_client: reqwest::Client::new(),
            timeout: Duration::from_secs(timeout_secs),
            fail_open,
        }
    }

    /// Call the configured admission webhook with `request`. Never panics —
    /// any network/timeout/parse failure resolves to `Pass` or `Reject`
    /// depending on `fail_open`.
    pub async fn call(&self, request: &AuthorizeRequest) -> AdmissionOutcome {
        let result = tokio::time::timeout(
            self.timeout,
            self.http_client.post(&self.url).json(request).send(),
        )
        .await;

        let response = match result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                return self.on_failure(&format!("admission webhook request failed: {e}"))
            }
            Err(_) => return self.on_failure("admission webhook timed out"),
        };

        if !response.status().is_success() {
            return self.on_failure(&format!(
                "admission webhook returned non-success status: {}",
                response.status()
            ));
        }

        let parsed: AdmissionWebhookResponse = match response.json().await {
            Ok(p) => p,
            Err(e) => {
                return self.on_failure(&format!("failed to parse admission webhook response: {e}"))
            }
        };

        match parsed.decision.as_str() {
            "pass" => AdmissionOutcome::Pass,
            "reject" => AdmissionOutcome::Reject(
                parsed
                    .reason
                    .unwrap_or_else(|| "rejected by admission webhook".to_string()),
            ),
            "mutate" => match parsed.parameters {
                Some(params) => AdmissionOutcome::Mutate(params),
                None => self.on_failure("admission webhook returned mutate without parameters"),
            },
            other => self.on_failure(&format!(
                "admission webhook returned unknown decision: {other}"
            )),
        }
    }

    fn on_failure(&self, reason: &str) -> AdmissionOutcome {
        if self.fail_open {
            tracing::warn!(
                "Admission webhook failure (fail-open, proceeding): {}",
                reason
            );
            AdmissionOutcome::Pass
        } else {
            tracing::error!(
                "Admission webhook failure (fail-closed, denying): {}",
                reason
            );
            AdmissionOutcome::Reject(format!("admission webhook unavailable: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AuthorizeAgentContext, AuthorizeDynamicContext, AuthorizeRequest, AuthorizeToolCall,
    };
    use axum::{routing::post, Json, Router};
    use serde_json::{json, Value};

    /// Spin up a real local HTTP server returning a fixed JSON body for
    /// every POST to `/admit` — same pattern `webhook_export.rs`'s tests use
    /// (a real `axum::serve` on an OS-assigned port) rather than pulling in
    /// a mocking library dependency.
    async fn admission_server_returning(body: Value) -> String {
        let app = Router::new().route("/admit", post(move || async move { Json(body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/admit")
    }

    fn sample_request() -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "agent-1".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "merge_pull_request".to_string(),
                resource: None,
                mutates_state: true,
                parameters: json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        }
    }

    #[tokio::test]
    async fn from_env_returns_none_when_url_unset() {
        let _guard = crate::routes::test_helpers::get_env_lock().lock().await;
        std::env::remove_var("AEGIS_ADMISSION_WEBHOOK_URL");
        assert!(AdmissionWebhookClient::from_env().is_none());
    }

    #[tokio::test]
    async fn from_env_defaults_to_fail_open() {
        let _guard = crate::routes::test_helpers::get_env_lock().lock().await;
        std::env::set_var("AEGIS_ADMISSION_WEBHOOK_URL", "http://127.0.0.1:1/admit");
        std::env::remove_var("AEGIS_ADMISSION_WEBHOOK_FAIL_OPEN");
        let client = AdmissionWebhookClient::from_env().unwrap();
        assert!(client.fail_open);
        std::env::remove_var("AEGIS_ADMISSION_WEBHOOK_URL");
    }

    #[tokio::test]
    async fn from_env_respects_fail_open_false() {
        let _guard = crate::routes::test_helpers::get_env_lock().lock().await;
        std::env::set_var("AEGIS_ADMISSION_WEBHOOK_URL", "http://127.0.0.1:1/admit");
        std::env::set_var("AEGIS_ADMISSION_WEBHOOK_FAIL_OPEN", "false");
        let client = AdmissionWebhookClient::from_env().unwrap();
        assert!(!client.fail_open);
        std::env::remove_var("AEGIS_ADMISSION_WEBHOOK_URL");
        std::env::remove_var("AEGIS_ADMISSION_WEBHOOK_FAIL_OPEN");
    }

    #[tokio::test]
    async fn call_returns_pass_on_pass_decision() {
        let url = admission_server_returning(json!({"decision": "pass"})).await;

        let client = AdmissionWebhookClient::new(url, 5, true);
        let outcome = client.call(&sample_request()).await;
        assert_eq!(outcome, AdmissionOutcome::Pass);
    }

    #[tokio::test]
    async fn call_returns_reject_with_reason_on_reject_decision() {
        let url = admission_server_returning(json!({
            "decision": "reject",
            "reason": "blocked by external policy"
        }))
        .await;

        let client = AdmissionWebhookClient::new(url, 5, true);
        let outcome = client.call(&sample_request()).await;
        assert_eq!(
            outcome,
            AdmissionOutcome::Reject("blocked by external policy".to_string())
        );
    }

    #[tokio::test]
    async fn call_returns_mutate_with_parameters_on_mutate_decision() {
        let url = admission_server_returning(json!({
            "decision": "mutate",
            "parameters": {"branch": "safe-branch"}
        }))
        .await;

        let client = AdmissionWebhookClient::new(url, 5, true);
        let outcome = client.call(&sample_request()).await;
        assert_eq!(
            outcome,
            AdmissionOutcome::Mutate(json!({"branch": "safe-branch"}))
        );
    }

    #[tokio::test]
    async fn call_fail_open_passes_on_unreachable_webhook() {
        // Port 1 never accepts connections (same convention webhook_export.rs's
        // tests use for "unreachable"), reliably simulating a down webhook
        // without depending on timing.
        let client = AdmissionWebhookClient::new("http://127.0.0.1:1/admit".to_string(), 1, true);
        let outcome = client.call(&sample_request()).await;
        assert_eq!(outcome, AdmissionOutcome::Pass);
    }

    #[tokio::test]
    async fn call_fail_closed_rejects_on_unreachable_webhook() {
        let client = AdmissionWebhookClient::new("http://127.0.0.1:1/admit".to_string(), 1, false);
        let outcome = client.call(&sample_request()).await;
        assert!(matches!(outcome, AdmissionOutcome::Reject(_)));
    }

    #[tokio::test]
    async fn call_fail_closed_rejects_on_unknown_decision() {
        let url = admission_server_returning(json!({"decision": "huh"})).await;

        let client = AdmissionWebhookClient::new(url, 5, false);
        let outcome = client.call(&sample_request()).await;
        assert!(matches!(outcome, AdmissionOutcome::Reject(_)));
    }
}
