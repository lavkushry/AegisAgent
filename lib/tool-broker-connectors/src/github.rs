//! GitHub connector — Phase 6.3. Two modes:
//!
//! - [`GithubMode::Mock`]: no network at all; deterministic canned output.
//!   This is the default the gateway registers, so CI and local dev never
//!   touch api.github.com.
//! - [`GithubMode::Real`]: HTTPS calls against a configurable base URL
//!   (production: `https://api.github.com`). The resolved credential — a
//!   PAT or a GitHub App installation token, both bearer-shaped — goes into
//!   the `Authorization` header and *nowhere else*.
//!
//! Action mapping is deliberately narrow: `read` → `GET`, `write` → `POST`.
//! A `write` with `mutates_state: false` is rejected outright — mislabeling
//! a write as non-mutating is exactly how an agent would dodge the
//! executor's approval gate, so the connector refuses to be the loophole.

use async_trait::async_trait;
use serde_json::{json, Value};

use aegis_tool_broker_core::{BrokerAction, Connector, ConnectorError, ConnectorOutput, Secret};

/// How [`GithubConnector`] reaches GitHub.
#[derive(Debug, Clone)]
pub enum GithubMode {
    /// Canned responses, zero network. Default for gateway registration.
    Mock,
    /// Real HTTP against `base_url` (no trailing slash), e.g.
    /// `https://api.github.com`.
    Real { base_url: String },
}

pub struct GithubConnector {
    mode: GithubMode,
    client: reqwest::Client,
}

impl GithubConnector {
    pub fn mock() -> Self {
        Self::new(GithubMode::Mock)
    }

    pub fn real(base_url: impl Into<String>) -> Self {
        Self::new(GithubMode::Real {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    pub fn new(mode: GithubMode) -> Self {
        Self {
            mode,
            client: reqwest::Client::new(),
        }
    }

    /// The GitHub API path (`/repos/{owner}/{repo}/issues`, …) from
    /// `parameters.path`. Required, must be absolute.
    fn api_path(action: &BrokerAction) -> Result<String, ConnectorError> {
        match action.parameters.get("path").and_then(Value::as_str) {
            Some(path) if path.starts_with('/') => Ok(path.to_string()),
            _ => Err(ConnectorError::ExecutionFailed(
                "github actions require parameters.path starting with '/'".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Connector for GithubConnector {
    fn connector_type(&self) -> &'static str {
        "github"
    }

    async fn execute(
        &self,
        action: &BrokerAction,
        credential: Option<&Secret>,
    ) -> Result<ConnectorOutput, ConnectorError> {
        let path = Self::api_path(action)?;
        let is_write = match action.action.as_str() {
            "read" => false,
            "write" => true,
            other => {
                return Err(ConnectorError::UnsupportedAction {
                    connector: "github".to_string(),
                    action: other.to_string(),
                })
            }
        };
        // A write mislabeled as non-mutating would sail past the executor's
        // approval gate. Refuse to be that loophole.
        if is_write && !action.mutates_state {
            return Err(ConnectorError::ExecutionFailed(
                "github write actions must set mutates_state: true".to_string(),
            ));
        }
        let body = action.parameters.get("body").cloned().unwrap_or(json!({}));

        match &self.mode {
            GithubMode::Mock => Ok(ConnectorOutput::new(json!({
                "mode": "mock",
                "action": action.action,
                "path": path,
                "delivered_body": if is_write { body } else { Value::Null },
                "result": if is_write { "created" } else { "ok" },
            }))),
            GithubMode::Real { base_url } => {
                let url = format!("{base_url}{path}");
                let mut request = if is_write {
                    self.client.post(&url).json(&body)
                } else {
                    self.client.get(&url)
                };
                request = request
                    .header("Accept", "application/vnd.github+json")
                    .header("User-Agent", "aegis-tool-broker");
                // The one audited place the raw credential is used: the
                // outbound Authorization header. It is never placed in the
                // URL, the body, or the returned output.
                if let Some(secret) = credential {
                    request =
                        request.header("Authorization", format!("Bearer {}", secret.expose()));
                }
                let response = request
                    .send()
                    .await
                    .map_err(|e| ConnectorError::ExecutionFailed(format!("github request: {e}")))?;
                let status = response.status().as_u16();
                let text = response
                    .text()
                    .await
                    .map_err(|e| ConnectorError::ExecutionFailed(format!("github body: {e}")))?;
                let body_json: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
                Ok(ConnectorOutput::new(json!({
                    "mode": "real",
                    "status": status,
                    "body": body_json,
                })))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(kind: &str, mutates: bool) -> BrokerAction {
        BrokerAction {
            tool: "gh-issues".to_string(),
            action: kind.to_string(),
            resource: Some("repo:acme/api".to_string()),
            mutates_state: mutates,
            parameters: json!({"path": "/repos/acme/api/issues", "body": {"title": "hi"}}),
        }
    }

    #[tokio::test]
    async fn mock_read_and_write_produce_canned_output_without_a_credential() {
        let connector = GithubConnector::mock();
        let read = connector
            .execute(&action("read", false), None)
            .await
            .expect("mock read");
        assert_eq!(read.output["result"], json!("ok"));

        let secret = Secret::new("ghp_mock_token");
        let write = connector
            .execute(&action("write", true), Some(&secret))
            .await
            .expect("mock write");
        assert_eq!(write.output["result"], json!("created"));
        // Mock mode never touches the credential at all.
        assert!(!write.output.to_string().contains("ghp_mock_token"));
    }

    #[tokio::test]
    async fn a_write_mislabeled_as_non_mutating_is_rejected() {
        let err = GithubConnector::mock()
            .execute(&action("write", false), None)
            .await
            .expect_err("mislabeled write must fail");
        assert!(err.to_string().contains("mutates_state"));
    }

    #[tokio::test]
    async fn unknown_actions_and_missing_paths_fail_closed() {
        let connector = GithubConnector::mock();
        let mut bad = action("merge", true);
        assert!(connector.execute(&bad, None).await.is_err());
        bad = action("read", false);
        bad.parameters = json!({});
        assert!(connector.execute(&bad, None).await.is_err());
    }
}
