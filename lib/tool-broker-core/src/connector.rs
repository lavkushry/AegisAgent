//! The connector seam. A [`Connector`] executes one family of tool
//! actions (GitHub, HTTP, scoped filesystem, scoped shell — Phase 6.3)
//! given a [`BrokerAction`] and a resolved [`Secret`]. The broker hands a
//! connector the credential; the connector hands back output that the
//! broker scrubs (see [`crate::redact`]) before anything reaches the
//! requesting agent, a log, or an event.

use async_trait::async_trait;
use serde_json::Value;

use crate::action::BrokerAction;
use crate::credential::Secret;
use crate::redact::{redact_secrets, redact_sensitive_keys};

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("action {action:?} is not supported by connector {connector:?}")]
    UnsupportedAction { connector: String, action: String },
    #[error("connector execution failed: {0}")]
    ExecutionFailed(String),
}

/// What a connector produced. `sanitize` is the only intended way to turn
/// this into something that leaves the broker.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorOutput {
    pub output: Value,
}

impl ConnectorOutput {
    pub fn new(output: Value) -> Self {
        Self { output }
    }

    /// Scrubs the output for release: every occurrence of any of
    /// `secrets` is value-redacted, then conventionally sensitive keys
    /// are masked. Consumes `self` so the unsanitized value doesn't
    /// linger at the call site.
    pub fn sanitize(self, secrets: &[&Secret]) -> Value {
        let exposed: Vec<&str> = secrets.iter().map(|secret| secret.expose()).collect();
        redact_sensitive_keys(redact_secrets(self.output, &exposed))
    }
}

/// One executable tool family. Implementations live in Phase 6.3; the
/// trait is deliberately narrow so connectors stay auditable.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Stable connector identifier (`github`, `http`, `filesystem`,
    /// `shell`), matched against `broker_tools.connector_type`.
    fn connector_type(&self) -> &'static str;

    /// Executes the action with the resolved credential. `credential` is
    /// `None` for connectors/tools registered without one. Implementations
    /// must put the credential only where the protocol needs it (e.g. an
    /// auth header) — never into the returned output.
    async fn execute(
        &self,
        action: &BrokerAction,
        credential: Option<&Secret>,
    ) -> Result<ConnectorOutput, ConnectorError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A connector that (wrongly) echoes its credential — the sanitize
    /// pass must still prevent the leak. Defense in depth over trust in
    /// connector discipline.
    struct LeakyEchoConnector;

    #[async_trait]
    impl Connector for LeakyEchoConnector {
        fn connector_type(&self) -> &'static str {
            "echo"
        }

        async fn execute(
            &self,
            action: &BrokerAction,
            credential: Option<&Secret>,
        ) -> Result<ConnectorOutput, ConnectorError> {
            let leaked = credential
                .map(|c| c.expose().to_string())
                .unwrap_or_default();
            Ok(ConnectorOutput::new(json!({
                "tool": action.tool,
                "stdout": format!("ran with {leaked}"),
                "api_key": leaked,
            })))
        }
    }

    #[tokio::test]
    async fn sanitized_output_cannot_contain_the_credential_even_if_the_connector_leaks_it() {
        let action = BrokerAction {
            tool: "echo".to_string(),
            action: "run".to_string(),
            resource: None,
            mutates_state: false,
            parameters: json!({}),
        };
        let secret = Secret::new("ghp_very_secret_value");
        let raw = LeakyEchoConnector
            .execute(&action, Some(&secret))
            .await
            .expect("execute");
        // The raw output really does contain the leak (the hazard is real)…
        assert!(raw.output.to_string().contains("ghp_very_secret_value"));
        // …and sanitize removes every trace of it.
        let sanitized = raw.sanitize(&[&secret]);
        let text = sanitized.to_string();
        assert!(!text.contains("ghp_very_secret_value"), "leaked: {text}");
        assert_eq!(sanitized["api_key"], json!(crate::redact::REDACTED));
        assert_eq!(sanitized["tool"], json!("echo"));
    }

    #[tokio::test]
    async fn a_credential_free_execution_sanitizes_cleanly() {
        let action = BrokerAction {
            tool: "echo".to_string(),
            action: "run".to_string(),
            resource: None,
            mutates_state: false,
            parameters: json!({}),
        };
        let raw = LeakyEchoConnector
            .execute(&action, None)
            .await
            .expect("execute");
        let sanitized = raw.sanitize(&[]);
        assert_eq!(sanitized["stdout"], json!("ran with "));
    }
}
