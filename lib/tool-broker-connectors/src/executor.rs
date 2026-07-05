//! The broker execution engine — where the Phase 6 guarantees meet. The
//! gateway's execute route (next PR) consumes the approval atomically via
//! storage, then delegates here. In order:
//!
//! 1. Tool must be `active` — anything else fails closed (Phase 6.2's
//!    enable/disable routes are the switch this honors).
//! 2. The `connector_type` must be registered — no default fallthrough.
//! 3. A state-mutating action requires a consumed approval whose
//!    `action_hash` equals the `aegis-jcs-1` hash of *this* action — the
//!    approve-then-swap defense, byte-identical with the gateway/SDK hash.
//! 4. The credential resolves fail-closed through the Phase 6.1
//!    [`CredentialResolver`]; the resolved [`Secret`] exists only for the
//!    duration of the call.
//! 5. Only sanitized output leaves: connector output goes through
//!    [`ConnectorOutput::sanitize`], and even connector *error messages*
//!    are scrubbed of the credential value before they propagate.

use std::sync::Arc;

use serde_json::Value;

use aegis_tool_broker_core::{
    action_hash, BrokerAction, ConnectorOutput, CredentialRef, CredentialResolver, ResolveError,
    Secret, REDACTED,
};

use crate::registry::ConnectorRegistry;

/// The slice of a Phase 6.2 `broker_tools` registration the engine needs.
/// The gateway maps its `BrokerToolRecord` into this; tests build it
/// directly.
#[derive(Debug, Clone)]
pub struct BrokerToolBinding {
    pub tool_name: String,
    /// Matched against [`ConnectorRegistry`] (`github`, `http`,
    /// `filesystem`, `shell`).
    pub connector_type: String,
    /// Opaque reference (`env:GITHUB_TOKEN`) — never a value. `None` for
    /// tools registered without a credential.
    pub credential_ref: Option<CredentialRef>,
    /// `active` | `disabled` — anything but `active` fails closed.
    pub status: String,
}

/// Proof that an approval was consumed (gateway: `db::consume_approval`,
/// atomic and hash-checked). The engine re-checks the hash anyway —
/// defense in depth against a future caller that forgets.
#[derive(Debug, Clone)]
pub struct ConsumedApproval {
    pub approval_id: String,
    /// The `action_hash` the approval was bound to at approve time.
    pub action_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("tool {tool_name:?} is not active (status {status:?})")]
    ToolNotActive { tool_name: String, status: String },
    #[error("no connector registered for connector_type {connector_type:?}")]
    UnknownConnectorType { connector_type: String },
    #[error("action mutates state and requires a consumed approval")]
    ApprovalRequired,
    #[error("approval {approval_id:?} is bound to a different action_hash")]
    ApprovalActionMismatch { approval_id: String },
    #[error("credential resolution failed: {0}")]
    Credential(#[from] ResolveError),
    /// Connector failure. The message has been scrubbed of the resolved
    /// credential value — safe for logs and events.
    #[error("connector execution failed: {0}")]
    Connector(String),
}

pub struct BrokerExecutor {
    registry: ConnectorRegistry,
    resolver: Arc<dyn CredentialResolver>,
}

impl BrokerExecutor {
    pub fn new(registry: ConnectorRegistry, resolver: Arc<dyn CredentialResolver>) -> Self {
        Self { registry, resolver }
    }

    /// Runs `action` through `tool`'s connector and returns **sanitized**
    /// output — the only kind this method can return. `approval` is the
    /// already-consumed approval for mutating actions (`None` is fine for
    /// reads).
    pub async fn execute(
        &self,
        tool: &BrokerToolBinding,
        action: &BrokerAction,
        approval: Option<&ConsumedApproval>,
    ) -> Result<Value, ExecuteError> {
        if tool.status != "active" {
            return Err(ExecuteError::ToolNotActive {
                tool_name: tool.tool_name.clone(),
                status: tool.status.clone(),
            });
        }
        let connector = self.registry.get(&tool.connector_type).ok_or_else(|| {
            ExecuteError::UnknownConnectorType {
                connector_type: tool.connector_type.clone(),
            }
        })?;

        if action.mutates_state {
            let approval = approval.ok_or(ExecuteError::ApprovalRequired)?;
            if approval.action_hash != action_hash(action) {
                return Err(ExecuteError::ApprovalActionMismatch {
                    approval_id: approval.approval_id.clone(),
                });
            }
        }

        // Fail closed: a tool registered with a credential_ref that no
        // longer resolves must not execute credential-less.
        let secret: Option<Secret> = match &tool.credential_ref {
            Some(reference) => Some(self.resolver.resolve(reference)?),
            None => None,
        };
        let secret_refs: Vec<&Secret> = secret.iter().collect();

        match connector.execute(action, secret.as_ref()).await {
            Ok(output) => Ok(ConnectorOutput::sanitize(output, &secret_refs)),
            Err(e) => {
                // Even the failure path must not leak: scrub the resolved
                // value out of the connector's error text.
                let mut message = e.to_string();
                if let Some(secret) = &secret {
                    let value = secret.expose();
                    if !value.is_empty() {
                        message = message.replace(value, REDACTED);
                    }
                }
                Err(ExecuteError::Connector(message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubConnector;
    use crate::shell::ShellConnector;
    use aegis_tool_broker_core::{
        Connector, ConnectorError, EnvCredentialResolver, StaticCredentialResolver,
    };
    use async_trait::async_trait;
    use serde_json::json;

    fn github_tool(status: &str) -> BrokerToolBinding {
        BrokerToolBinding {
            tool_name: "gh-issues".to_string(),
            connector_type: "github".to_string(),
            credential_ref: Some(CredentialRef::new("env:GITHUB_TOKEN")),
            status: status.to_string(),
        }
    }

    fn github_write() -> BrokerAction {
        BrokerAction {
            tool: "gh-issues".to_string(),
            action: "write".to_string(),
            resource: Some("repo:acme/api".to_string()),
            mutates_state: true,
            parameters: json!({"path": "/repos/acme/api/issues", "body": {"title": "hi"}}),
        }
    }

    fn executor_with_mock_github() -> BrokerExecutor {
        let registry = ConnectorRegistry::default().register(Arc::new(GithubConnector::mock()));
        let resolver =
            StaticCredentialResolver::default().with("env:GITHUB_TOKEN", "ghp_engine_secret");
        BrokerExecutor::new(registry, Arc::new(resolver))
    }

    #[tokio::test]
    async fn github_write_requires_a_consumed_approval() {
        // The PR 6.3 acceptance test, verbatim: a GitHub write with no
        // approval fails closed; a wrong-action approval fails closed; the
        // hash-bound approval goes through.
        let executor = executor_with_mock_github();
        let action = github_write();

        let err = executor
            .execute(&github_tool("active"), &action, None)
            .await
            .expect_err("write without approval must fail");
        assert!(matches!(err, ExecuteError::ApprovalRequired));

        let swapped = ConsumedApproval {
            approval_id: "ap-1".to_string(),
            action_hash: "0".repeat(64), // bound to some *other* action
        };
        let err = executor
            .execute(&github_tool("active"), &action, Some(&swapped))
            .await
            .expect_err("approval bound to another action must fail");
        assert!(matches!(err, ExecuteError::ApprovalActionMismatch { .. }));

        let bound = ConsumedApproval {
            approval_id: "ap-2".to_string(),
            action_hash: action_hash(&action),
        };
        let output = executor
            .execute(&github_tool("active"), &action, Some(&bound))
            .await
            .expect("hash-bound approval executes");
        assert_eq!(output["result"], json!("created"));
    }

    #[tokio::test]
    async fn a_read_needs_no_approval_and_output_is_sanitized() {
        let executor = executor_with_mock_github();
        let mut action = github_write();
        action.action = "read".to_string();
        action.mutates_state = false;
        let output = executor
            .execute(&github_tool("active"), &action, None)
            .await
            .expect("read executes without approval");
        assert!(!output.to_string().contains("ghp_engine_secret"));
    }

    #[tokio::test]
    async fn disabled_tools_fail_closed() {
        let executor = executor_with_mock_github();
        let err = executor
            .execute(&github_tool("disabled"), &github_write(), None)
            .await
            .expect_err("disabled tool must not execute");
        assert!(matches!(err, ExecuteError::ToolNotActive { .. }));
    }

    #[tokio::test]
    async fn an_unregistered_connector_type_fails_closed() {
        let executor = executor_with_mock_github();
        let mut tool = github_tool("active");
        tool.connector_type = "smtp".to_string();
        let err = executor
            .execute(&tool, &github_write(), None)
            .await
            .expect_err("unknown connector type must fail");
        assert!(matches!(err, ExecuteError::UnknownConnectorType { .. }));
    }

    #[tokio::test]
    async fn an_unresolvable_credential_fails_closed_not_credential_less() {
        let registry = ConnectorRegistry::default().register(Arc::new(GithubConnector::mock()));
        let executor = BrokerExecutor::new(registry, Arc::new(EnvCredentialResolver));
        let mut tool = github_tool("active");
        tool.credential_ref = Some(CredentialRef::new(
            "env:AEGIS_TEST_DEFINITELY_UNSET_VARIABLE",
        ));
        let mut action = github_write();
        action.action = "read".to_string();
        action.mutates_state = false;
        let err = executor
            .execute(&tool, &action, None)
            .await
            .expect_err("unresolvable credential must fail closed");
        assert!(matches!(err, ExecuteError::Credential(_)));
    }

    /// A connector that leaks its credential through both its output and
    /// its error message. The engine must neutralize both paths.
    struct LeakyConnector;

    #[async_trait]
    impl Connector for LeakyConnector {
        fn connector_type(&self) -> &'static str {
            "leaky"
        }
        async fn execute(
            &self,
            action: &BrokerAction,
            credential: Option<&Secret>,
        ) -> Result<aegis_tool_broker_core::ConnectorOutput, ConnectorError> {
            let leaked = credential
                .map(|c| c.expose().to_string())
                .unwrap_or_default();
            if action.action == "fail" {
                return Err(ConnectorError::ExecutionFailed(format!(
                    "upstream said: bad token {leaked}"
                )));
            }
            Ok(aegis_tool_broker_core::ConnectorOutput::new(json!({
                "stdout": format!("ran with {leaked}"),
            })))
        }
    }

    #[tokio::test]
    async fn neither_output_nor_error_messages_can_carry_the_credential() {
        let registry = ConnectorRegistry::default().register(Arc::new(LeakyConnector));
        let resolver = StaticCredentialResolver::default().with("env:LEAK", "tok_leak_me_please");
        let executor = BrokerExecutor::new(registry, Arc::new(resolver));
        let tool = BrokerToolBinding {
            tool_name: "leaky".to_string(),
            connector_type: "leaky".to_string(),
            credential_ref: Some(CredentialRef::new("env:LEAK")),
            status: "active".to_string(),
        };
        let mut action = github_write();
        action.action = "run".to_string();
        action.mutates_state = false;

        let output = executor
            .execute(&tool, &action, None)
            .await
            .expect("leaky output sanitizes");
        assert!(!output.to_string().contains("tok_leak_me_please"));

        action.action = "fail".to_string();
        let err = executor
            .execute(&tool, &action, None)
            .await
            .expect_err("leaky error path");
        let message = err.to_string();
        assert!(!message.contains("tok_leak_me_please"), "leaked: {message}");
        assert!(message.contains(REDACTED));
    }

    #[tokio::test]
    async fn credential_never_reaches_the_cage_even_through_the_engine() {
        // End-to-end variant of the PR 6.3 acceptance test: a shell tool
        // *with* a registered credential runs `env` inside the cage; the
        // sanitized output contains no trace of the credential.
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = ConnectorRegistry::default()
            .register(Arc::new(ShellConnector::new(dir.path()).expect("shell")));
        let resolver =
            StaticCredentialResolver::default().with("env:CAGE_TOKEN", "tok_cage_secret");
        let executor = BrokerExecutor::new(registry, Arc::new(resolver));
        let tool = BrokerToolBinding {
            tool_name: "cage-shell".to_string(),
            connector_type: "shell".to_string(),
            credential_ref: Some(CredentialRef::new("env:CAGE_TOKEN")),
            status: "active".to_string(),
        };
        let action = BrokerAction {
            tool: "cage-shell".to_string(),
            action: "run".to_string(),
            resource: None,
            mutates_state: false,
            parameters: json!({"command": ["/usr/bin/env"]}),
        };
        let output = executor
            .execute(&tool, &action, None)
            .await
            .expect("caged env run");
        assert!(!output.to_string().contains("tok_cage_secret"));
    }
}
