//! Builds the [`BrokerExecutor`] this binary serves. Moved verbatim (Phase 1
//! extraction) from the gateway's `routes/broker.rs::default_broker_executor`.

use std::sync::Arc;

use aegis_tool_broker_connectors::{
    BrokerExecutor, ConnectorRegistry, FilesystemConnector, GithubConnector, GithubMode,
    HttpConnector, ShellConnector,
};
use aegis_tool_broker_core::EnvCredentialResolver;
use tracing::error;

/// Builds the [`BrokerExecutor`] this process serves. GitHub runs in mock
/// mode unless `AEGIS_GITHUB_API_BASE` is set (real mode); `HttpConnector`
/// is always registered (HTTPS-only). The filesystem and shell connectors
/// are opt-in via `AEGIS_BROKER_WORKSPACE` — with no configured workspace
/// there is nothing safe to scope them to, so they're simply absent from
/// the registry (an execute against `filesystem`/`shell` then fails closed
/// with `UnknownConnectorType`, not a wide-open default).
pub fn build_broker_executor() -> Arc<BrokerExecutor> {
    let github_mode = match std::env::var("AEGIS_GITHUB_API_BASE") {
        Ok(base_url) if !base_url.trim().is_empty() => GithubMode::Real {
            base_url: base_url.trim_end_matches('/').to_string(),
        },
        _ => GithubMode::Mock,
    };
    let mut registry = ConnectorRegistry::default()
        .register(Arc::new(GithubConnector::new(github_mode)))
        .register(Arc::new(HttpConnector::new()));

    if let Ok(workspace) = std::env::var("AEGIS_BROKER_WORKSPACE") {
        if !workspace.trim().is_empty() {
            match FilesystemConnector::new(&workspace) {
                Ok(fs) => registry = registry.register(Arc::new(fs)),
                Err(e) => error!(
                    "AEGIS_BROKER_WORKSPACE {:?} unusable for filesystem connector: {}",
                    workspace, e
                ),
            }
            match ShellConnector::new(&workspace) {
                Ok(shell) => registry = registry.register(Arc::new(shell)),
                Err(e) => error!(
                    "AEGIS_BROKER_WORKSPACE {:?} unusable for shell connector: {}",
                    workspace, e
                ),
            }
        }
    }

    Arc::new(BrokerExecutor::new(
        registry,
        Arc::new(EnvCredentialResolver),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn github_defaults_to_mock_mode_when_api_base_unset() {
        std::env::remove_var("AEGIS_GITHUB_API_BASE");
        std::env::remove_var("AEGIS_BROKER_WORKSPACE");
        let executor = build_broker_executor();
        // Mock mode never makes a real network call; a benign read must
        // succeed synchronously without any credential configured.
        let output = executor
            .execute(
                &aegis_tool_broker_connectors::BrokerToolBinding {
                    tool_name: "gh".to_string(),
                    connector_type: "github".to_string(),
                    credential_ref: None,
                    status: "active".to_string(),
                },
                &aegis_tool_broker_core::BrokerAction {
                    tool: "gh".to_string(),
                    action: "read".to_string(),
                    resource: None,
                    mutates_state: false,
                    parameters: serde_json::json!({"path": "/repos/acme/api/issues"}),
                },
                None,
            )
            .await;
        assert!(output.is_ok());
    }

    #[tokio::test]
    async fn filesystem_and_shell_are_absent_without_a_configured_workspace() {
        std::env::remove_var("AEGIS_BROKER_WORKSPACE");
        let executor = build_broker_executor();
        let err = executor
            .execute(
                &aegis_tool_broker_connectors::BrokerToolBinding {
                    tool_name: "fs".to_string(),
                    connector_type: "filesystem".to_string(),
                    credential_ref: None,
                    status: "active".to_string(),
                },
                &aegis_tool_broker_core::BrokerAction {
                    tool: "fs".to_string(),
                    action: "read".to_string(),
                    resource: None,
                    mutates_state: false,
                    parameters: serde_json::json!({}),
                },
                None,
            )
            .await
            .expect_err("filesystem must be unregistered without AEGIS_BROKER_WORKSPACE");
        assert!(matches!(
            err,
            aegis_tool_broker_connectors::ExecuteError::UnknownConnectorType { .. }
        ));
    }

    #[tokio::test]
    async fn filesystem_and_shell_are_registered_with_a_configured_workspace() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AEGIS_BROKER_WORKSPACE", dir.path());
        let executor = build_broker_executor();
        let output = executor
            .execute(
                &aegis_tool_broker_connectors::BrokerToolBinding {
                    tool_name: "shell".to_string(),
                    connector_type: "shell".to_string(),
                    credential_ref: None,
                    status: "active".to_string(),
                },
                &aegis_tool_broker_core::BrokerAction {
                    tool: "shell".to_string(),
                    action: "run".to_string(),
                    resource: None,
                    mutates_state: false,
                    parameters: serde_json::json!({"command": ["/usr/bin/env"]}),
                },
                None,
            )
            .await;
        assert!(output.is_ok());
        std::env::remove_var("AEGIS_BROKER_WORKSPACE");
    }
}
