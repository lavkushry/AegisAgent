//! #1634 — tenant-owned dashboard schema CRUD (`/v1/soc/dashboards`).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::error::StatusError;
use crate::models::*;
use crate::routes::{AppState, TenantId};
use aegis_api::dashboard_schema::parse_and_validate_dashboard_json;

async fn audit_dashboard_event(
    state: &AppState,
    tenant_id: &str,
    event_type: &str,
    uid: &str,
    detail: serde_json::Value,
) {
    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: event_type.to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: Some(event_type.to_string()),
        resource: Some(uid.to_string()),
        event_json: serde_json::to_string(&detail).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        decision_id: None,
        approval_id: None,
        created_at: Utc::now(),
    };
    let _ = state.storage.insert_audit_event(&audit).await;
}

fn validate_body(raw: &str) -> Result<(String, String, i64, String), String> {
    let schema = parse_and_validate_dashboard_json(raw)?;
    let canonical =
        serde_json::to_string(&schema).map_err(|e| format!("serialize dashboard: {e}"))?;
    Ok((
        schema.uid,
        schema.title,
        i64::from(schema.schema_version),
        canonical,
    ))
}

pub async fn list_soc_dashboards(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.list_soc_dashboards(&tenant_id).await {
        Ok(records) => Json(records).into_response(),
        Err(e) => {
            error!("Failed to list soc dashboards: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn get_soc_dashboard(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(uid): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_soc_dashboard_by_uid(&tenant_id, &uid)
        .await
    {
        Ok(Some(record)) => Json(record).into_response(),
        Ok(None) => StatusError::not_found("Dashboard not found").into_response(),
        Err(e) => {
            error!("Failed to get soc dashboard: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn create_soc_dashboard(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let raw = match String::from_utf8(body.to_vec()) {
        Ok(v) => v,
        Err(_) => return StatusError::bad_request("Invalid UTF-8 payload").into_response(),
    };
    let (uid, title, schema_version, schema_json) = match validate_body(&raw) {
        Ok(v) => v,
        Err(msg) => return StatusError::bad_request(msg).into_response(),
    };

    if let Ok(Some(_)) = state
        .storage
        .get_soc_dashboard_by_uid(&tenant_id, &uid)
        .await
    {
        return StatusError::conflict(format!("Dashboard uid '{uid}' already exists"))
            .into_response();
    }

    match state
        .storage
        .insert_soc_dashboard(&tenant_id, &uid, &title, schema_version, &schema_json)
        .await
    {
        Ok(record) => {
            audit_dashboard_event(
                &state,
                &tenant_id,
                "soc_dashboard_created",
                &uid,
                json!({ "uid": uid, "title": title }),
            )
            .await;
            (StatusCode::CREATED, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to create soc dashboard: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn update_soc_dashboard(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(uid): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let raw = match String::from_utf8(body.to_vec()) {
        Ok(v) => v,
        Err(_) => return StatusError::bad_request("Invalid UTF-8 payload").into_response(),
    };
    let (body_uid, title, schema_version, schema_json) = match validate_body(&raw) {
        Ok(v) => v,
        Err(msg) => return StatusError::bad_request(msg).into_response(),
    };
    if body_uid != uid {
        return StatusError::bad_request("uid in body must match path parameter").into_response();
    }

    match state
        .storage
        .update_soc_dashboard(&tenant_id, &uid, &title, schema_version, &schema_json)
        .await
    {
        Ok(Some(record)) => {
            audit_dashboard_event(
                &state,
                &tenant_id,
                "soc_dashboard_updated",
                &uid,
                json!({ "uid": uid, "title": title }),
            )
            .await;
            Json(record).into_response()
        }
        Ok(None) => StatusError::not_found("Dashboard not found").into_response(),
        Err(e) => {
            error!("Failed to update soc dashboard: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn delete_soc_dashboard(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(uid): Path<String>,
) -> impl IntoResponse {
    match state.storage.delete_soc_dashboard(&tenant_id, &uid).await {
        Ok(true) => {
            audit_dashboard_event(
                &state,
                &tenant_id,
                "soc_dashboard_deleted",
                &uid,
                json!({ "uid": uid }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusError::not_found("Dashboard not found").into_response(),
        Err(e) => {
            error!("Failed to delete soc dashboard: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;

    const SAMPLE_SCHEMA: &str = r#"{
      "uid": "team-posture",
      "title": "Team posture",
      "schemaVersion": 1,
      "variables": [],
      "time": { "defaultRange": { "from": "now-24h", "to": "now" }, "refreshSec": 30 },
      "layout": [{
        "id": "row-1",
        "title": "Vitals",
        "panels": [{
          "panel": {
            "id": "stat-1",
            "type": "stat",
            "title": "Decisions",
            "datasourceId": "gateway-entity",
            "snapshot": "soc-summary",
            "options": { "valueField": "decisions_today" }
          },
          "w": 4,
          "h": 1
        }]
      }]
    }"#;

    #[tokio::test]
    async fn soc_dashboard_routes_are_tenant_scoped() {
        let (state_a, tenant_a, _) = setup_state("soc_dashboard_tenant_a").await;
        let (state_b, tenant_b, _) = setup_state("soc_dashboard_tenant_b").await;

        let created = create_soc_dashboard(
            State(state_a.clone()),
            TenantId(tenant_a.clone()),
            axum::body::Bytes::from(SAMPLE_SCHEMA),
        )
        .await
        .into_response();
        assert_eq!(created.status(), StatusCode::CREATED);

        let cross_tenant = get_soc_dashboard(
            State(state_b),
            TenantId(tenant_b),
            Path("team-posture".into()),
        )
        .await
        .into_response();
        assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rejects_reserved_system_uid() {
        let (state, tenant_id, _) = setup_state("soc_dashboard_reserved_uid").await;
        let bad = SAMPLE_SCHEMA.replace("team-posture", "overview");
        let resp = create_soc_dashboard(
            State(state),
            TenantId(tenant_id),
            axum::body::Bytes::from(bad),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
