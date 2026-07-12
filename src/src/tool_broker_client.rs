//! Client for the standalone `aegis-tool-broker` binary (Phase 1
//! extraction of the in-gateway tool broker — see `bins/aegis-tool-broker`
//! and `routes/broker.rs`). Modeled on `admission::AdmissionWebhookClient`'s
//! `from_env()`/reqwest-wrapper shape, but **always fail-closed**: a broker
//! call executes a real, potentially state-mutating side effect, unlike an
//! admission opinion, so there is no fail-open toggle.

use aegis_tool_broker_core::BrokerAction;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ToolBrokerError {
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotImplemented(String),
    #[error("{0}")]
    ServiceUnavailable(String),
}

#[derive(Serialize)]
struct ConsumedApprovalWire<'a> {
    approval_id: &'a str,
    action_hash: &'a str,
}

#[derive(Serialize)]
struct ExecuteRequest<'a> {
    tool_name: &'a str,
    connector_type: &'a str,
    credential_ref: Option<&'a str>,
    tool_status: &'a str,
    action: &'a BrokerAction,
    consumed_approval: Option<ConsumedApprovalWire<'a>>,
}

pub struct ToolBrokerClient {
    execute_url: String,
    api_token: String,
    http: reqwest::Client,
    timeout: Duration,
}

impl ToolBrokerClient {
    /// `None` if `AEGIS_TOOL_BROKER_URL` or `AEGIS_TOOL_BROKER_API_TOKEN` is
    /// unset/blank — the caller (`main.rs`) treats that as "the tool broker
    /// is not configured," and `POST /v1/broker/execute` fails closed with
    /// 501. There is no in-process fallback: this binary no longer links
    /// `aegis-tool-broker-connectors` at all.
    pub fn from_env() -> Option<Self> {
        let base = std::env::var("AEGIS_TOOL_BROKER_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())?;
        let api_token = std::env::var("AEGIS_TOOL_BROKER_API_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let timeout_secs = std::env::var("AEGIS_TOOL_BROKER_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        Some(Self::new(base, api_token, timeout_secs))
    }

    pub fn new(base_url: String, api_token: String, timeout_secs: u64) -> Self {
        Self {
            execute_url: format!("{base_url}/v1/execute"),
            api_token,
            http: reqwest::Client::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &self,
        tool_name: &str,
        connector_type: &str,
        credential_ref: Option<&str>,
        tool_status: &str,
        action: &BrokerAction,
        consumed_approval: Option<(&str, &str)>,
    ) -> Result<Value, ToolBrokerError> {
        let body = ExecuteRequest {
            tool_name,
            connector_type,
            credential_ref,
            tool_status,
            action,
            consumed_approval: consumed_approval.map(|(approval_id, action_hash)| {
                ConsumedApprovalWire {
                    approval_id,
                    action_hash,
                }
            }),
        };

        let result = tokio::time::timeout(
            self.timeout,
            self.http
                .post(&self.execute_url)
                .bearer_auth(&self.api_token)
                .json(&body)
                .send(),
        )
        .await;

        let response = match result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                return Err(ToolBrokerError::ServiceUnavailable(format!(
                    "tool broker request failed: {e} — failing closed"
                )))
            }
            Err(_) => {
                return Err(ToolBrokerError::ServiceUnavailable(
                    "tool broker request timed out — failing closed".to_string(),
                ))
            }
        };

        let status = response.status();
        if status.is_success() {
            #[derive(serde::Deserialize)]
            struct ExecuteResponse {
                output: Value,
            }
            return match response.json::<ExecuteResponse>().await {
                Ok(parsed) => Ok(parsed.output),
                Err(e) => Err(ToolBrokerError::ServiceUnavailable(format!(
                    "tool broker returned an unparseable success response: {e} — failing closed"
                ))),
            };
        }

        #[derive(serde::Deserialize)]
        struct ErrorBody {
            error: String,
        }
        let message = match response.json::<ErrorBody>().await {
            Ok(body) => body.error,
            Err(_) => format!("tool broker returned status {status} with an unparseable body"),
        };

        Err(match status.as_u16() {
            403 => ToolBrokerError::Forbidden(message),
            501 => ToolBrokerError::NotImplemented(message),
            _ => ToolBrokerError::ServiceUnavailable(format!(
                "tool broker returned unexpected status {status}: {message} — failing closed"
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use serde_json::json;

    fn sample_action() -> BrokerAction {
        BrokerAction {
            tool: "gh-read".to_string(),
            action: "read".to_string(),
            resource: Some("repo:acme/api".to_string()),
            mutates_state: false,
            parameters: json!({"path": "/repos/acme/api/issues"}),
        }
    }

    /// Spins up a real local HTTP server for `POST /v1/execute`, same
    /// pattern `admission.rs`'s tests use (a real `axum::serve` on an
    /// OS-assigned port, no mocking library dependency).
    async fn mock_broker_returning(status: axum::http::StatusCode, body: Value) -> String {
        let app = Router::new().route(
            "/v1/execute",
            post(move || async move { (status, Json(body)) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn from_env_is_none_unless_both_vars_are_set() {
        let _guard = crate::routes::test_helpers::get_env_lock().lock().await;
        std::env::remove_var("AEGIS_TOOL_BROKER_URL");
        std::env::remove_var("AEGIS_TOOL_BROKER_API_TOKEN");
        assert!(ToolBrokerClient::from_env().is_none());

        std::env::set_var("AEGIS_TOOL_BROKER_URL", "http://127.0.0.1:8899");
        assert!(ToolBrokerClient::from_env().is_none());

        std::env::set_var("AEGIS_TOOL_BROKER_API_TOKEN", "tok");
        assert!(ToolBrokerClient::from_env().is_some());

        std::env::remove_var("AEGIS_TOOL_BROKER_URL");
        std::env::remove_var("AEGIS_TOOL_BROKER_API_TOKEN");
    }

    #[tokio::test]
    async fn a_successful_response_returns_the_output() {
        let base = mock_broker_returning(
            axum::http::StatusCode::OK,
            json!({"output": {"result": "ok"}}),
        )
        .await;
        let client = ToolBrokerClient::new(base, "tok".to_string(), 5);
        let output = client
            .execute("gh-read", "github", None, "active", &sample_action(), None)
            .await
            .unwrap();
        assert_eq!(output["result"], json!("ok"));
    }

    #[tokio::test]
    async fn a_403_response_maps_to_forbidden() {
        let base = mock_broker_returning(
            axum::http::StatusCode::FORBIDDEN,
            json!({"error": "tool is not active", "kind": "tool_not_active"}),
        )
        .await;
        let client = ToolBrokerClient::new(base, "tok".to_string(), 5);
        let err = client
            .execute(
                "gh-read",
                "github",
                None,
                "disabled",
                &sample_action(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolBrokerError::Forbidden(_)));
    }

    #[tokio::test]
    async fn a_501_response_maps_to_not_implemented() {
        let base = mock_broker_returning(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            json!({"error": "no connector registered", "kind": "unknown_connector_type"}),
        )
        .await;
        let client = ToolBrokerClient::new(base, "tok".to_string(), 5);
        let err = client
            .execute("smtp", "smtp", None, "active", &sample_action(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolBrokerError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn an_unreachable_broker_fails_closed() {
        // Port 1 never accepts connections (same convention this codebase's
        // other satellite-client tests use for "unreachable").
        let client = ToolBrokerClient::new("http://127.0.0.1:1".to_string(), "tok".to_string(), 1);
        let err = client
            .execute("gh-read", "github", None, "active", &sample_action(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolBrokerError::ServiceUnavailable(_)));
    }

    #[tokio::test]
    async fn a_503_response_maps_to_service_unavailable() {
        let base = mock_broker_returning(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "credential resolution failed", "kind": "credential"}),
        )
        .await;
        let client = ToolBrokerClient::new(base, "tok".to_string(), 5);
        let err = client
            .execute("gh-read", "github", None, "active", &sample_action(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolBrokerError::ServiceUnavailable(_)));
    }
}
