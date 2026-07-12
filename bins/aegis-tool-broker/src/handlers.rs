use std::sync::Arc;

use aegis_tool_broker_connectors::{BrokerExecutor, BrokerToolBinding, ConsumedApproval};
use aegis_tool_broker_core::CredentialRef;
use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{middleware, Router};

use crate::auth::require_bearer_token;
use crate::dto::{ExecuteRequest, ExecuteResponse};
use crate::error::execute_error_response;

/// Builds the full router: `POST /v1/execute` (bearer-token gated) plus
/// unauthenticated `GET /livez`/`GET /readyz`. Separate from `main()` so
/// tests can build a `Router` directly without a real process/CLI.
pub fn router(executor: Arc<BrokerExecutor>, api_token: String) -> Router {
    let execute_routes = Router::new()
        .route("/v1/execute", post(execute))
        .with_state(executor)
        .layer(middleware::from_fn_with_state(
            Arc::new(api_token),
            require_bearer_token,
        ));

    Router::new()
        .merge(execute_routes)
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
}

async fn livez() -> &'static str {
    "ok"
}

async fn readyz() -> &'static str {
    // No DB/external dependency: the registry is built once at startup and
    // is always non-empty (github + http are unconditionally registered),
    // so there is nothing this process could be "not ready" for.
    "ok"
}

async fn execute(
    State(executor): State<Arc<BrokerExecutor>>,
    Json(req): Json<ExecuteRequest>,
) -> Response {
    let binding = BrokerToolBinding {
        tool_name: req.tool_name,
        connector_type: req.connector_type,
        credential_ref: req.credential_ref.map(CredentialRef::new),
        status: req.tool_status,
    };
    let consumed = req.consumed_approval.map(|c| ConsumedApproval {
        approval_id: c.approval_id,
        action_hash: c.action_hash,
    });

    match executor
        .execute(&binding, &req.action, consumed.as_ref())
        .await
    {
        Ok(output) => Json(ExecuteResponse { output }).into_response(),
        Err(e) => {
            // `ExecuteError`'s Display is already scrubbed of any resolved
            // credential value (see `BrokerExecutor::execute`'s error path),
            // so logging it directly is safe.
            tracing::warn!(
                tool_name = %binding.tool_name,
                connector_type = %binding.connector_type,
                error = %e,
                "tool broker execute failed"
            );
            execute_error_response(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_tool_broker_connectors::{ConnectorRegistry, GithubConnector};
    use aegis_tool_broker_core::{BrokerAction, StaticCredentialResolver};
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "test-broker-token";

    fn mock_github_executor() -> Arc<BrokerExecutor> {
        let registry = ConnectorRegistry::default().register(Arc::new(GithubConnector::mock()));
        Arc::new(BrokerExecutor::new(
            registry,
            Arc::new(StaticCredentialResolver::default()),
        ))
    }

    fn read_request_body(tool_name: &str) -> Value {
        json!({
            "tool_name": tool_name,
            "connector_type": "github",
            "credential_ref": null,
            "tool_status": "active",
            "action": {
                "tool": tool_name,
                "action": "read",
                "resource": "repo:acme/api",
                "mutates_state": false,
                "parameters": {"path": "/repos/acme/api/issues"},
            },
            "consumed_approval": null,
        })
    }

    async fn post_execute(app: Router, token: Option<&str>, body: Value) -> Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let request = builder.body(Body::from(body.to_string())).unwrap();
        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn missing_bearer_token_is_rejected() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let response = post_execute(app, None, read_request_body("gh-read")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_bearer_token_is_rejected() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let response = post_execute(app, Some("wrong-token"), read_request_body("gh-read")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn correct_bearer_token_executes_a_read() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let response = post_execute(app, Some(TEST_TOKEN), read_request_body("gh-read")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["output"]["result"], json!("ok"));
    }

    #[tokio::test]
    async fn disabled_tool_is_forbidden() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let mut body = read_request_body("gh-read");
        body["tool_status"] = json!("disabled");
        let response = post_execute(app, Some(TEST_TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn unregistered_connector_type_is_not_implemented() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let mut body = read_request_body("smtp-tool");
        body["connector_type"] = json!("smtp");
        let response = post_execute(app, Some(TEST_TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn mutating_action_without_a_consumed_approval_is_forbidden() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let mut body = read_request_body("gh-write");
        body["action"]["action"] = json!("write");
        body["action"]["mutates_state"] = json!(true);
        let response = post_execute(app, Some(TEST_TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_hash_bound_consumed_approval_executes_a_write() {
        let app = router(mock_github_executor(), TEST_TOKEN.to_string());
        let action = BrokerAction {
            tool: "gh-write".to_string(),
            action: "write".to_string(),
            resource: Some("repo:acme/api".to_string()),
            mutates_state: true,
            parameters: json!({"path": "/repos/acme/api/issues", "body": {"title": "hi"}}),
        };
        let hash = aegis_tool_broker_core::action_hash(&action);
        let mut body = read_request_body("gh-write");
        body["action"]["action"] = json!("write");
        body["action"]["mutates_state"] = json!(true);
        body["action"]["parameters"] =
            json!({"path": "/repos/acme/api/issues", "body": {"title": "hi"}});
        body["consumed_approval"] = json!({"approval_id": "ap-1", "action_hash": hash});

        let response = post_execute(app, Some(TEST_TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["output"]["result"], json!("created"));
    }

    /// A connector that deliberately echoes its resolved credential into its
    /// output -- `GithubConnector::mock()` never touches the credential at
    /// all, so it can't prove the HTTP layer doesn't leak one. Mirrors
    /// `lib/tool-broker-connectors/src/executor.rs`'s own `LeakyConnector`
    /// test fixture, one layer up (asserting on the raw HTTP response body
    /// instead of the `Value` the executor returns directly).
    struct LeakyConnector;

    #[async_trait::async_trait]
    impl aegis_tool_broker_core::Connector for LeakyConnector {
        fn connector_type(&self) -> &'static str {
            "leaky"
        }
        async fn execute(
            &self,
            _action: &BrokerAction,
            credential: Option<&aegis_tool_broker_core::Secret>,
        ) -> Result<aegis_tool_broker_core::ConnectorOutput, aegis_tool_broker_core::ConnectorError>
        {
            let leaked = credential
                .map(|c| c.expose().to_string())
                .unwrap_or_default();
            Ok(aegis_tool_broker_core::ConnectorOutput::new(
                json!({"stdout": format!("ran with {leaked}")}),
            ))
        }
    }

    #[tokio::test]
    async fn a_resolved_credential_never_appears_in_the_http_response() {
        let registry = ConnectorRegistry::default().register(Arc::new(LeakyConnector));
        let resolver =
            StaticCredentialResolver::default().with("env:LEAK", "ghp_super_secret_value");
        let executor = Arc::new(BrokerExecutor::new(registry, Arc::new(resolver)));
        let app = router(executor, TEST_TOKEN.to_string());

        let mut body = read_request_body("leaky-tool");
        body["connector_type"] = json!("leaky");
        body["credential_ref"] = json!("env:LEAK");
        let response = post_execute(app, Some(TEST_TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains("ghp_super_secret_value"), "leaked: {text}");
        // Sanity check the fixture itself is wired correctly (the connector
        // really did receive and use the credential -- the redacted marker
        // stands in for it in the sanitized output).
        assert!(text.contains("ran with"));
    }
}
