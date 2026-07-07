//! Phase 7.1 (prompt/model capture): lineage-only ingest APIs.
//!
//! `POST /v1/ingest/prompt-events` and `POST /v1/ingest/model-calls` accept
//! only a hash and a caller-already-redacted preview — never a raw prompt,
//! request, or response body (there is no raw-text column in either table;
//! see `docs/AegisAgent_World_Class_LLD.md` section 5.2). As defense in
//! depth against a caller that forgot to redact, the gateway itself also
//! rejects a preview containing an obvious secret-shaped substring, mirroring
//! `register_broker_tool`'s rejection of a raw-secret-looking `credential_ref`.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::error::StatusError;
use crate::models::*;

use super::{AppState, TenantId};

const MAX_PREVIEW_LEN: usize = 2000;

/// Secret-shaped substrings a caller-redacted preview must never contain.
/// Checked case-insensitively; deliberately narrow (well-known token
/// prefixes) to avoid false positives on ordinary prose.
const UNREDACTED_MARKERS: &[&str] = &[
    "bearer ",
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "akia",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "-----begin",
];

fn looks_unredacted(text: &str) -> bool {
    let lower = text.to_lowercase();
    UNREDACTED_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Body for `POST /v1/ingest/prompt-events`.
#[derive(Debug, Deserialize)]
pub struct IngestPromptEventRequest {
    pub event_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    pub prompt_hash: String,
    #[serde(default)]
    pub redacted_prompt_preview: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub source_trust: Option<String>,
    #[serde(default)]
    pub model_provider: Option<String>,
    #[serde(default)]
    pub retention_policy: Option<String>,
    #[serde(default)]
    pub redaction_status: Option<String>,
}

/// POST /v1/ingest/prompt-events — idempotent ingest of a single prompt
/// lineage record. Tenant-scoped. Returns `{ "ingested": bool }` — `false`
/// means the `(tenant, event_id)` was already recorded (a retried/replayed
/// event).
pub async fn ingest_prompt_event(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<IngestPromptEventRequest>,
) -> impl IntoResponse {
    if req.event_id.trim().is_empty() {
        return StatusError::bad_request("event_id must not be empty").into_response();
    }
    if !is_sha256_hex(&req.prompt_hash) {
        return StatusError::bad_request(
            "prompt_hash must be a 64-character lowercase hex SHA-256 digest",
        )
        .into_response();
    }
    if let Some(preview) = &req.redacted_prompt_preview {
        if looks_unredacted(preview) {
            return StatusError::bad_request(
                "redacted_prompt_preview appears to contain an unredacted secret",
            )
            .into_response();
        }
    }
    let preview = req.redacted_prompt_preview.map(|mut preview| {
        preview.truncate(MAX_PREVIEW_LEN);
        preview
    });

    let now = Utc::now();
    let record = PromptEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_id: req.event_id,
        run_id: req.run_id,
        trace_id: req.trace_id,
        prompt_hash: req.prompt_hash,
        redacted_prompt_preview: preview,
        role: req.role,
        source_trust: req.source_trust,
        model_provider: req.model_provider,
        retention_policy: req.retention_policy,
        redaction_status: req
            .redaction_status
            .unwrap_or_else(|| "unknown".to_string()),
        created_at: now,
        received_at: now,
    };
    match state.storage.insert_prompt_event(&record).await {
        Ok(ingested) => (StatusCode::OK, Json(json!({ "ingested": ingested }))).into_response(),
        Err(e) => {
            error!("Failed to ingest prompt event: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

fn is_valid_model_call_status(status: &str) -> bool {
    matches!(status, "success" | "error" | "timeout" | "cancelled")
}

/// Body for `POST /v1/ingest/model-calls`.
#[derive(Debug, Deserialize)]
pub struct IngestModelCallRequest {
    pub event_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub request_hash: Option<String>,
    #[serde(default)]
    pub response_hash: Option<String>,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub token_counts: Option<serde_json::Value>,
    pub status: String,
    #[serde(default)]
    pub redaction_status: Option<String>,
}

/// POST /v1/ingest/model-calls — idempotent ingest of a single model-call
/// lineage record. Tenant-scoped. Returns `{ "ingested": bool }` — `false`
/// means the `(tenant, event_id)` was already recorded (a retried/replayed
/// event).
pub async fn ingest_model_call(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<IngestModelCallRequest>,
) -> impl IntoResponse {
    if req.event_id.trim().is_empty() {
        return StatusError::bad_request("event_id must not be empty").into_response();
    }
    if req.provider.trim().is_empty() || req.model.trim().is_empty() {
        return StatusError::bad_request("provider and model must not be empty").into_response();
    }
    if !is_valid_model_call_status(&req.status) {
        return StatusError::bad_request(
            "status must be one of: success, error, timeout, cancelled",
        )
        .into_response();
    }
    for (name, hash) in [
        ("request_hash", &req.request_hash),
        ("response_hash", &req.response_hash),
    ] {
        if let Some(h) = hash {
            if !is_sha256_hex(h) {
                return StatusError::bad_request(format!(
                    "{name} must be a 64-character lowercase hex SHA-256 digest"
                ))
                .into_response();
            }
        }
    }

    let now = Utc::now();
    let record = ModelCallEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_id: req.event_id,
        run_id: req.run_id,
        trace_id: req.trace_id,
        provider: req.provider,
        model: req.model,
        request_hash: req.request_hash,
        response_hash: req.response_hash,
        started_at: req.started_at,
        finished_at: req.finished_at,
        token_counts_json: req.token_counts.map(|v| v.to_string()),
        status: req.status,
        redaction_status: req
            .redaction_status
            .unwrap_or_else(|| "unknown".to_string()),
        received_at: now,
    };
    match state.storage.insert_model_call_event(&record).await {
        Ok(ingested) => (StatusCode::OK, Json(json!({ "ingested": ingested }))).into_response(),
        Err(e) => {
            error!("Failed to ingest model call event: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;
    use axum::body::to_bytes;

    fn sample_prompt_request(event_id: &str) -> IngestPromptEventRequest {
        IngestPromptEventRequest {
            event_id: event_id.to_string(),
            run_id: Some("run-1".to_string()),
            trace_id: Some("trace-1".to_string()),
            prompt_hash: "a".repeat(64),
            redacted_prompt_preview: Some("Summarize the attached [REDACTED] file".to_string()),
            role: Some("user".to_string()),
            source_trust: Some("untrusted_external".to_string()),
            model_provider: Some("openai".to_string()),
            retention_policy: Some("30d".to_string()),
            redaction_status: Some("redacted".to_string()),
        }
    }

    fn sample_model_call_request(event_id: &str) -> IngestModelCallRequest {
        IngestModelCallRequest {
            event_id: event_id.to_string(),
            run_id: Some("run-1".to_string()),
            trace_id: Some("trace-1".to_string()),
            provider: "openai".to_string(),
            model: "gpt-5".to_string(),
            request_hash: Some("b".repeat(64)),
            response_hash: Some("c".repeat(64)),
            started_at: Some(Utc::now()),
            finished_at: Some(Utc::now()),
            token_counts: Some(json!({"prompt": 10, "completion": 20})),
            status: "success".to_string(),
            redaction_status: Some("redacted".to_string()),
        }
    }

    #[tokio::test]
    async fn prompt_event_ingest_is_idempotent() {
        let (state, tenant_id, _agent_token) = setup_state("prompt_ingest_idempotent").await;

        let response = ingest_prompt_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_prompt_request("e1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ingested"], json!(true));

        let response = ingest_prompt_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_prompt_request("e1")),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["ingested"],
            json!(false),
            "replayed event_id is a no-op"
        );
    }

    #[tokio::test]
    async fn prompt_event_rejects_malformed_hash() {
        let (state, tenant_id, _agent_token) = setup_state("prompt_ingest_bad_hash").await;
        let mut req = sample_prompt_request("e1");
        req.prompt_hash = "not-a-hash".to_string();

        let response = ingest_prompt_event(State(state), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prompt_event_rejects_an_unredacted_preview() {
        let (state, tenant_id, _agent_token) = setup_state("prompt_ingest_unredacted").await;
        let mut req = sample_prompt_request("e1");
        req.redacted_prompt_preview =
            Some("Authorization: Bearer sk-abc123SecretValueNotRedacted".to_string());

        let response = ingest_prompt_event(State(state), TenantId(tenant_id), Json(req))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prompt_event_reads_are_tenant_scoped() {
        let (state, tenant_id, _agent_token) = setup_state("prompt_ingest_tenant_a").await;
        // A second tenant in the SAME pool — two independent `setup_state`
        // calls would each get their own SQLite file, which wouldn't
        // exercise the `WHERE tenant_id = ?` filter at all.
        let tenant_b = "tenant_b_prompt_ingest".to_string();
        crate::routes::test_helpers::register_tenant_helper(
            state.storage.as_ref(),
            &tenant_b,
            "Tenant B",
            "developer",
        )
        .await;

        let _ = ingest_prompt_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_prompt_request("shared-event-id")),
        )
        .await
        .into_response();

        assert!(state
            .storage
            .get_prompt_event_by_event_id(&tenant_id, "shared-event-id")
            .await
            .unwrap()
            .is_some());
        assert!(state
            .storage
            .get_prompt_event_by_event_id(&tenant_b, "shared-event-id")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn model_call_ingest_is_idempotent_and_stores_token_counts() {
        let (state, tenant_id, _agent_token) = setup_state("model_call_ingest_idempotent").await;

        let response = ingest_model_call(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_model_call_request("mc1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ingested"], json!(true));

        let fetched = state
            .storage
            .get_model_call_event_by_event_id(&tenant_id, "mc1")
            .await
            .unwrap()
            .expect("row persisted");
        let stored_token_counts: serde_json::Value =
            serde_json::from_str(fetched.token_counts_json.as_deref().unwrap()).unwrap();
        assert_eq!(stored_token_counts, json!({"prompt": 10, "completion": 20}));

        let response = ingest_model_call(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_model_call_request("mc1")),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["ingested"],
            json!(false),
            "replayed event_id is a no-op"
        );
    }

    #[tokio::test]
    async fn model_call_rejects_invalid_status_and_malformed_hashes() {
        let (state, tenant_id, _agent_token) = setup_state("model_call_ingest_invalid").await;

        let mut bad_status = sample_model_call_request("mc1");
        bad_status.status = "in_progress".to_string();
        let response = ingest_model_call(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(bad_status),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut bad_hash = sample_model_call_request("mc2");
        bad_hash.request_hash = Some("short".to_string());
        let response = ingest_model_call(State(state), TenantId(tenant_id), Json(bad_hash))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
