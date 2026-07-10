//! The runner's HTTP client for the gateway's `/v1/agent-cage/runs/*` and
//! `/v1/control/commands/*` endpoints. Authenticates like any other API
//! client — `Authorization: Bearer <api_token>` — there is no
//! runner-specific auth mechanism (reuses the exact
//! `aegis-node-sensor`/`aegis-egress-proxy` bearer-token pattern rather than
//! a new per-run scoped credential).
//!
//! These request/response shapes are deliberately duplicated from the
//! gateway's route handlers rather than imported from a shared crate: this
//! is a network boundary, and this binary stays independent of the
//! gateway's internal model crate (`aegis-api` pulls in proto/build.rs
//! tooling this small binary doesn't need) — the same convention
//! `aegis-node-sensor`'s `gateway_client.rs` already uses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::CageError;
use crate::spec::{
    ControlledMount, ImageSpec, NetworkSpec, ResourceLimits, SandboxSpec, ToolingSpec,
    WorkspaceSpec,
};

#[derive(Debug, thiserror::Error)]
pub enum GatewayClientError {
    #[error("request to gateway failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("gateway rejected the request with status {status}: {body}")]
    RejectedRequest {
        status: reqwest::StatusCode,
        body: String,
    },
    /// A claim attempt lost the race (409) — expected, routine outcome
    /// when multiple runner instances poll concurrently, not a hard error.
    #[error("lost the claim race for this run")]
    ClaimLost,
}

/// Mirrors the cage-relevant subset of the gateway's `AgentRunRecord`
/// (`lib/api/src/models.rs`) — the wire shape returned by
/// `GET /v1/agent-cage/runs/:id`, `POST .../claim`, and `POST .../status`.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentRunPayload {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: Option<String>,
    pub mode: String,
    pub status: String,
    pub claimed_by: Option<String>,
    pub image_ref: Option<String>,
    pub image_digest: Option<String>,
    pub command_json: Option<String>,
    pub working_dir: Option<String>,
    pub resource_limits_json: Option<String>,
    pub network_spec_json: Option<String>,
    pub tooling_spec_json: Option<String>,
    pub environment_json: Option<String>,
    pub workspace_spec_json: Option<String>,
    pub controlled_mounts_json: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
}

impl AgentRunPayload {
    /// Reconstruct a full `SandboxSpec` from this run's stored `_json`
    /// columns. Errors if `image_ref`/`command_json` are absent (meaning
    /// this run was never meant for the cage runner — defense-in-depth;
    /// the gateway's claim route already guards `image_ref IS NOT NULL`,
    /// so a non-cage run should never reach here in the first place).
    pub fn build_sandbox_spec(&self, sandbox_id: &str) -> Result<SandboxSpec, CageError> {
        let image_ref = self.image_ref.clone().ok_or_else(|| {
            CageError::InvalidSpec("run has no image_ref -- not a cage run".into())
        })?;
        let command: Vec<String> = self
            .command_json
            .as_deref()
            .ok_or_else(|| {
                CageError::InvalidSpec("run has no command_json -- not a cage run".into())
            })
            .and_then(|s| {
                serde_json::from_str(s)
                    .map_err(|e| CageError::InvalidSpec(format!("invalid command_json: {e}")))
            })?;

        let resources: ResourceLimits = parse_json_field(
            &self.resource_limits_json,
            "resource_limits_json",
        )?
        .ok_or_else(|| {
            CageError::InvalidSpec("run has no resource_limits_json -- not a cage run".into())
        })?;
        let network: NetworkSpec =
            parse_json_field(&self.network_spec_json, "network_spec_json")?.unwrap_or_default();
        let tooling: ToolingSpec =
            parse_json_field(&self.tooling_spec_json, "tooling_spec_json")?.unwrap_or_default();
        let environment: std::collections::HashMap<String, String> =
            parse_json_field(&self.environment_json, "environment_json")?.unwrap_or_default();
        let workspace: WorkspaceSpec =
            parse_json_field(&self.workspace_spec_json, "workspace_spec_json")?.unwrap_or(
                WorkspaceSpec {
                    template_id: None,
                    max_bytes: 0,
                    max_files: 0,
                    preserve_on_failure: false,
                },
            );
        let controlled_mounts: Vec<ControlledMount> =
            parse_json_field(&self.controlled_mounts_json, "controlled_mounts_json")?
                .unwrap_or_default();

        Ok(SandboxSpec {
            tenant_id: self.tenant_id.clone(),
            run_id: self.id.clone(),
            agent_id: self.agent_id.clone().unwrap_or_else(|| "anon".to_string()),
            sandbox_id: sandbox_id.to_string(),
            mode: self.mode.clone(),
            image: ImageSpec {
                image_ref,
                digest: self.image_digest.clone().unwrap_or_default(),
                // Not yet exposed on CageRunSpecRequest (v1 simplification,
                // matching the project's "narrow initial PR" convention) --
                // defaults to the security-positive value.
                read_only_rootfs: true,
            },
            command,
            working_dir: self
                .working_dir
                .clone()
                .unwrap_or_else(|| "/workspace".to_string()),
            workspace,
            resources,
            network,
            tooling,
            environment,
            controlled_mounts,
        })
    }
}

fn parse_json_field<T: for<'de> Deserialize<'de>>(
    field: &Option<String>,
    field_name: &str,
) -> Result<Option<T>, CageError> {
    match field {
        None => Ok(None),
        Some(s) => serde_json::from_str(s)
            .map(Some)
            .map_err(|e| CageError::InvalidSpec(format!("invalid {field_name}: {e}"))),
    }
}

#[derive(Debug, Serialize)]
struct RunnerIdRequest<'a> {
    runner_id: &'a str,
}

#[derive(Debug, Serialize)]
struct UpdateRunStatusRequest<'a> {
    runner_id: &'a str,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

/// Mirrors the gateway's `ControlCommandRecord` — the wire shape returned
/// by `GET /v1/control/commands`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedCommand {
    pub command_id: String,
    pub tenant_id: String,
    pub target_type: String,
    pub target_id: String,
    pub action: String,
    pub reason: Option<String>,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
    pub requires_ack: bool,
    pub receipt_required: bool,
    pub signature: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
struct UpdateCommandStatusRequest {
    status: String,
}

/// Mirrors the gateway's `POST /v1/ingest/runtime-events` request body.
/// Hashes/identifiers only — never raw prompts, secrets, or payloads.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuntimeEventPayload {
    pub event_id: String,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    pub source_component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestResponse {
    pub ingested: bool,
}

pub struct GatewayClient {
    http: reqwest::Client,
    base_url: Url,
    api_token: String,
}

impl GatewayClient {
    pub fn new(base_url: Url, api_token: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            api_token,
        }
    }

    pub async fn get_agent_run(&self, run_id: &str) -> Result<AgentRunPayload, GatewayClientError> {
        let url = self
            .base_url
            .join(&format!("/v1/agent-cage/runs/{run_id}"))
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        Self::parse_response(response).await
    }

    /// `409` maps to [`GatewayClientError::ClaimLost`] rather than a hard
    /// error — losing a claim race to another runner instance is a
    /// routine, expected outcome.
    pub async fn claim_run(
        &self,
        run_id: &str,
        runner_id: &str,
    ) -> Result<AgentRunPayload, GatewayClientError> {
        let url = self
            .base_url
            .join(&format!("/v1/agent-cage/runs/{run_id}/claim"))
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&RunnerIdRequest { runner_id })
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(GatewayClientError::ClaimLost);
        }
        Self::parse_response(response).await
    }

    /// `Ok(())` only on success; a `409` (lease lost) surfaces as
    /// `RejectedRequest` for the caller to match on explicitly.
    pub async fn heartbeat_run(
        &self,
        run_id: &str,
        runner_id: &str,
    ) -> Result<(), GatewayClientError> {
        let url = self
            .base_url
            .join(&format!("/v1/agent-cage/runs/{run_id}/heartbeat"))
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&RunnerIdRequest { runner_id })
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GatewayClientError::RejectedRequest { status, body })
        }
    }

    pub async fn update_run_status(
        &self,
        run_id: &str,
        runner_id: &str,
        status: &str,
        finished_at: Option<DateTime<Utc>>,
        exit_code: Option<i32>,
    ) -> Result<AgentRunPayload, GatewayClientError> {
        let url = self
            .base_url
            .join(&format!("/v1/agent-cage/runs/{run_id}/status"))
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&UpdateRunStatusRequest {
                runner_id,
                status,
                finished_at,
                exit_code,
            })
            .send()
            .await?;
        Self::parse_response(response).await
    }

    /// Fetch all control commands visible to this tenant. The endpoint has
    /// no target-scoping filter yet, so the runner filters client-side for
    /// commands addressed to `target_type == "run"` with `status ==
    /// "issued"` — the same pattern `aegis-node-sensor` already uses for
    /// `target_type == "sensor"`.
    pub async fn list_control_commands(&self) -> Result<Vec<SignedCommand>, GatewayClientError> {
        let url = self
            .base_url
            .join("/v1/control/commands")
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        Self::parse_response(response).await
    }

    pub async fn update_command_status(
        &self,
        command_id: &str,
        status: &str,
    ) -> Result<(), GatewayClientError> {
        let url = self
            .base_url
            .join(&format!("/v1/control/commands/{command_id}/status"))
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&UpdateCommandStatusRequest {
                status: status.to_string(),
            })
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GatewayClientError::RejectedRequest { status, body })
        }
    }

    pub async fn ingest_runtime_event(
        &self,
        req: &RuntimeEventPayload,
    ) -> Result<IngestResponse, GatewayClientError> {
        let url = self
            .base_url
            .join("/v1/ingest/runtime-events")
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(req)
            .send()
            .await?;
        Self::parse_response(response).await
    }

    async fn parse_response<T: for<'de> Deserialize<'de>>(
        response: reqwest::Response,
    ) -> Result<T, GatewayClientError> {
        if response.status().is_success() {
            Ok(response.json::<T>().await?)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GatewayClientError::RejectedRequest { status, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use std::sync::{Arc, Mutex};

    fn sample_run_json(id: &str, status: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "tenant_id": "tenant_a",
            "agent_id": null,
            "mode": "observe",
            "status": status,
            "claimed_by": null,
            "image_ref": "alpine:latest",
            "image_digest": null,
            "command_json": "[\"sleep\",\"1\"]",
            "working_dir": "/workspace",
            "resource_limits_json": "{\"cpu_millis\":500,\"memory_bytes\":268435456,\"process_limit\":32,\"timeout_seconds\":60}",
            "network_spec_json": null,
            "tooling_spec_json": null,
            "environment_json": null,
            "workspace_spec_json": null,
            "controlled_mounts_json": null,
        })
    }

    #[tokio::test]
    async fn get_agent_run_deserializes_the_gateway_response() {
        let app = Router::new().route(
            "/v1/agent-cage/runs/:id",
            axum::routing::get(|| async { Json(sample_run_json("run-1", "started")) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let run = client.get_agent_run("run-1").await.unwrap();
        assert_eq!(run.id, "run-1");
        assert_eq!(run.status, "started");
    }

    #[tokio::test]
    async fn claim_run_maps_409_to_claim_lost() {
        let app = Router::new().route(
            "/v1/agent-cage/runs/:id/claim",
            post(|| async { axum::http::StatusCode::CONFLICT }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let err = client.claim_run("run-1", "runner-1").await.unwrap_err();
        assert!(matches!(err, GatewayClientError::ClaimLost));
    }

    #[tokio::test]
    async fn claim_run_parses_a_successful_response() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();
        let app = Router::new().route(
            "/v1/agent-cage/runs/:id/claim",
            post(move |Json(body): Json<serde_json::Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().unwrap() = Some(body);
                    Json(sample_run_json("run-1", "claimed"))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let run = client.claim_run("run-1", "runner-1").await.unwrap();
        assert_eq!(run.status, "claimed");
        assert_eq!(
            received.lock().unwrap().as_ref().unwrap()["runner_id"],
            "runner-1"
        );
    }

    #[tokio::test]
    async fn heartbeat_run_surfaces_a_409_conflict() {
        let app = Router::new().route(
            "/v1/agent-cage/runs/:id/heartbeat",
            post(|| async { axum::http::StatusCode::CONFLICT }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let err = client.heartbeat_run("run-1", "runner-1").await.unwrap_err();
        match err {
            GatewayClientError::RejectedRequest { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::CONFLICT);
            }
            other => panic!("expected RejectedRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_run_status_sends_the_expected_body() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();
        let app = Router::new().route(
            "/v1/agent-cage/runs/:id/status",
            post(move |Json(body): Json<serde_json::Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().unwrap() = Some(body);
                    Json(sample_run_json("run-1", "running"))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let run = client
            .update_run_status("run-1", "runner-1", "running", None, None)
            .await
            .unwrap();
        assert_eq!(run.status, "running");
        assert_eq!(
            received.lock().unwrap().as_ref().unwrap()["status"],
            "running"
        );
    }

    fn sample_command_json(command_id: &str) -> serde_json::Value {
        serde_json::json!({
            "command_id": command_id,
            "tenant_id": "tenant_a",
            "target_type": "run",
            "target_id": "run-1",
            "action": "start_run",
            "reason": null,
            "issued_by": "gateway",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "nonce": "n1",
            "requires_ack": true,
            "receipt_required": false,
            "signature": "deadbeef",
            "status": "issued",
        })
    }

    #[tokio::test]
    async fn list_control_commands_deserializes_the_gateway_response() {
        let app = Router::new().route(
            "/v1/control/commands",
            axum::routing::get(|| async {
                Json(serde_json::json!([sample_command_json("cmd-1")]))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let commands = client.list_control_commands().await.unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].action, "start_run");
    }

    #[tokio::test]
    async fn update_command_status_sends_the_expected_body() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();
        let app = Router::new().route(
            "/v1/control/commands/:id/status",
            post(move |Json(body): Json<serde_json::Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().unwrap() = Some(body);
                    Json(serde_json::json!({"status": "acked"}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        client
            .update_command_status("cmd-1", "acked")
            .await
            .unwrap();
        assert_eq!(
            received.lock().unwrap().as_ref().unwrap()["status"],
            "acked"
        );
    }

    #[tokio::test]
    async fn ingest_runtime_event_reports_dedup_via_ingested_false() {
        let app = Router::new().route(
            "/v1/ingest/runtime-events",
            post(|| async { Json(serde_json::json!({"ingested": false})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let payload = RuntimeEventPayload {
            event_id: "evt-1".to_string(),
            event_type: "agent_run_started".to_string(),
            source_component: "cage-runner".to_string(),
            ..Default::default()
        };
        let resp = client.ingest_runtime_event(&payload).await.unwrap();
        assert!(!resp.ingested);
    }

    #[test]
    fn build_sandbox_spec_reconstructs_from_json_columns() {
        let payload: AgentRunPayload =
            serde_json::from_value(sample_run_json("run-1", "claimed")).unwrap();
        let spec = payload.build_sandbox_spec("sandbox-1").unwrap();
        assert_eq!(spec.image.image_ref, "alpine:latest");
        assert_eq!(spec.command, vec!["sleep".to_string(), "1".to_string()]);
        assert_eq!(spec.resources.cpu_millis, 500);
        assert!(!spec.network.direct_internet);
        assert_eq!(spec.run_id, "run-1");
    }

    #[test]
    fn build_sandbox_spec_rejects_a_non_cage_run() {
        let mut value = sample_run_json("run-1", "started");
        value["image_ref"] = serde_json::Value::Null;
        value["command_json"] = serde_json::Value::Null;
        let payload: AgentRunPayload = serde_json::from_value(value).unwrap();
        assert!(payload.build_sandbox_spec("sandbox-1").is_err());
    }
}
