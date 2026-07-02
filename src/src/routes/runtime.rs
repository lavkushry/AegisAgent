//! Phase 2.6 (runtime control plane): HTTP routes wiring the runtime data-plane
//! storage (agent_runs, runtime_events) to the API. Every handler is
//! tenant-scoped via the `TenantId` extractor and delegates to the tenant-scoped
//! `StorageBackend` methods. Ingest is idempotent (dedup on `event_id`).
//!
//! Not yet wired: signature verification for sensor-shipped events and the
//! cage-run control operations (pause/kill) — those arrive with the sensor and
//! cage-runner phases.

#![allow(unused_imports)]
use crate::error::StatusError;
use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::models::*;

use super::{parse_pagination, AppState, TenantId};

/// Body for `POST /v1/agent-cage/runs`. Server assigns `id`, `status`,
/// `started_at`, and `created_at`; the caller supplies the run identity/context.
#[derive(Debug, Deserialize)]
pub struct CreateAgentRunRequest {
    pub run_key: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub source_component: String,
    /// `observe` | `enforce` | `lockdown` (default `observe`).
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub root_trace_id: Option<String>,
    #[serde(default)]
    pub root_trust_level: Option<String>,
}

/// POST /v1/agent-cage/runs — register a controlled agent run. Tenant-scoped.
/// A duplicate `run_key` for the tenant is a 409 (idempotency anchor).
pub async fn create_agent_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<CreateAgentRunRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = AgentRunRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        agent_id: req.agent_id,
        run_key: req.run_key,
        source_component: req.source_component,
        mode: req.mode.unwrap_or_else(|| "observe".to_string()),
        status: "started".to_string(),
        started_at: now,
        finished_at: None,
        root_trace_id: req.root_trace_id,
        root_trust_level: req.root_trust_level,
        policy_bundle_id: None,
        created_at: now,
    };
    match state.storage.insert_agent_run(&record).await {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            // A duplicate (tenant, run_key) trips the unique index.
            error!("Failed to create agent run: {:?}", e);
            StatusError::conflict("agent run already exists for this run_key").into_response()
        }
    }
}

/// GET /v1/agent-cage/runs/:id — fetch one run. Tenant-scoped (404 cross-tenant).
pub async fn get_agent_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_agent_run(&tenant_id, &run_id).await {
        Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
        Ok(None) => StatusError::not_found("agent run not found").into_response(),
        Err(e) => {
            error!("Failed to get agent run: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/agent-cage/runs — list the tenant's runs (paginated). Tenant-scoped.
pub async fn list_agent_runs(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_agent_runs(&tenant_id, limit, offset)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list agent runs: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/ingest/runtime-events`. Producer-supplied envelope; server
/// assigns the internal row `id` and stamps `received_at`. Carries
/// hashes/identifiers only — never raw prompts/secrets/payloads.
#[derive(Debug, Deserialize)]
pub struct IngestRuntimeEventRequest {
    pub event_id: String,
    pub event_type: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub parent_event_id: Option<String>,
    pub source_component: String,
    #[serde(default)]
    pub source_trust: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub action_hash: Option<String>,
    #[serde(default)]
    pub prompt_hash: Option<String>,
    #[serde(default)]
    pub request_hash: Option<String>,
    #[serde(default)]
    pub response_hash: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub receipt_hash: Option<String>,
    #[serde(default)]
    pub prev_receipt_hash: Option<String>,
    #[serde(default)]
    pub canonical_version: Option<String>,
    #[serde(default)]
    pub redaction_status: Option<String>,
    /// RFC-3339; defaults to now if omitted.
    #[serde(default)]
    pub observed_at: Option<chrono::DateTime<Utc>>,
}

/// POST /v1/ingest/runtime-events — idempotent ingest of a single runtime event.
/// Tenant-scoped. Returns `{ "ingested": bool }` — `false` means the
/// `(tenant, event_id)` was already recorded (a retried/replayed event).
pub async fn ingest_runtime_event(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<IngestRuntimeEventRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = RuntimeEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_id: req.event_id,
        event_type: req.event_type,
        severity: req.severity,
        agent_id: req.agent_id,
        run_id: req.run_id,
        sandbox_id: req.sandbox_id,
        trace_id: req.trace_id,
        parent_event_id: req.parent_event_id,
        source_component: req.source_component,
        source_trust: req.source_trust,
        decision: req.decision,
        reason: req.reason,
        action_hash: req.action_hash,
        prompt_hash: req.prompt_hash,
        request_hash: req.request_hash,
        response_hash: req.response_hash,
        receipt_id: req.receipt_id,
        receipt_hash: req.receipt_hash,
        prev_receipt_hash: req.prev_receipt_hash,
        canonical_version: req.canonical_version,
        redaction_status: req.redaction_status,
        schema_version: 1,
        observed_at: req.observed_at.unwrap_or(now),
        received_at: now,
    };
    match state.storage.insert_runtime_event(&record).await {
        Ok(ingested) => (StatusCode::OK, Json(json!({ "ingested": ingested }))).into_response(),
        Err(e) => {
            error!("Failed to ingest runtime event: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/runtime/runs/:id/events — the runtime-event timeline for one run,
/// oldest-first. Tenant-scoped.
pub async fn list_run_events(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, _offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_runtime_events_for_run(&tenant_id, &run_id, limit)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list run events: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::{register_tenant_helper, setup_state};
    use axum::body::to_bytes;
    use axum::extract::RawQuery;

    #[tokio::test]
    async fn create_agent_run_then_get_and_list_round_trip() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_create_run").await;

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateAgentRunRequest {
                run_key: "run-abc".to_string(),
                agent_id: Some("agent-1".to_string()),
                source_component: "sdk".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.run_key, "run-abc");
        assert_eq!(created.mode, "observe");
        assert_eq!(created.status, "started");

        let response = get_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let fetched: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched.id, created.id);

        let response = list_agent_runs(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<AgentRunRecord> = serde_json::from_slice(&body).unwrap();
        assert!(rows.iter().any(|r| r.id == created.id));
    }

    #[tokio::test]
    async fn create_agent_run_rejects_duplicate_run_key() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_dup_run_key").await;
        let req = || CreateAgentRunRequest {
            run_key: "dup-key".to_string(),
            agent_id: None,
            source_component: "sdk".to_string(),
            mode: None,
            root_trace_id: None,
            root_trust_level: None,
        };

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(req()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(req()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn get_agent_run_is_tenant_scoped() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_run_tenant_scope").await;
        let other_tenant_id = "tenant_runtime_other".to_string();
        register_tenant_helper(
            state.storage.as_ref(),
            &other_tenant_id,
            "Other",
            "developer",
        )
        .await;

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateAgentRunRequest {
                run_key: "scoped-run".to_string(),
                agent_id: None,
                source_component: "sdk".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
            }),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: AgentRunRecord = serde_json::from_slice(&body).unwrap();

        let response = get_agent_run(
            State(state.clone()),
            TenantId(other_tenant_id),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn sample_ingest_request(event_id: &str) -> IngestRuntimeEventRequest {
        IngestRuntimeEventRequest {
            event_id: event_id.to_string(),
            event_type: "tool_call".to_string(),
            severity: Some("info".to_string()),
            agent_id: None,
            run_id: None,
            sandbox_id: None,
            trace_id: None,
            parent_event_id: None,
            source_component: "sdk".to_string(),
            source_trust: None,
            decision: Some("allow".to_string()),
            reason: None,
            action_hash: None,
            prompt_hash: None,
            request_hash: None,
            response_hash: None,
            receipt_id: None,
            receipt_hash: None,
            prev_receipt_hash: None,
            canonical_version: None,
            redaction_status: None,
            observed_at: None,
        }
    }

    #[tokio::test]
    async fn ingest_runtime_event_dedupes_by_event_id() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_ingest_dedup").await;

        let response = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_ingest_request("evt-1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ingested"].as_bool(), Some(true));

        let response = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_ingest_request("evt-1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ingested"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn list_run_events_returns_only_events_for_that_run() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_list_run_events").await;

        let mut ev_a = sample_ingest_request("evt-a");
        ev_a.run_id = Some("run-a".to_string());
        let mut ev_b = sample_ingest_request("evt-b");
        ev_b.run_id = Some("run-b".to_string());

        let _ = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(ev_a),
        )
        .await
        .into_response();
        let _ = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(ev_b),
        )
        .await
        .into_response();

        let response = list_run_events(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("run-a".to_string()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<RuntimeEventRecord> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "evt-a");
    }
}
