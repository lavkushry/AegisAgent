use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::StatusError;
use crate::models::*;
use crate::routes::TenantId;
use crate::routes::AppState;

#[derive(Debug, Deserialize)]
pub struct MockIncidentRequest {
    pub kind: String,
    pub severity: String,
    pub agent_id: String,
    pub summary: String,
}

#[derive(serde::Serialize)]
pub struct PlaybookTestResponse {
    pub matched: bool,
    pub playbook_name: String,
    pub steps_to_execute: Vec<aegis_soc::playbook::PlaybookStep>,
}

pub async fn create_playbook(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusError> {
    let body_str = String::from_utf8(body.to_vec())
        .map_err(|_| StatusError::bad_request("Invalid UTF-8 payload"))?;
    
    // Parse YAML or JSON
    let playbook: aegis_soc::playbook::ResponsePlaybook = if body_str.trim().starts_with('{') {
        serde_json::from_str(&body_str)
            .map_err(|e| StatusError::bad_request(format!("Invalid JSON payload: {e}")))?
    } else {
        serde_yml::from_str(&body_str)
            .map_err(|e| StatusError::bad_request(format!("Invalid YAML payload: {e}")))?
    };

    // Validate
    playbook.validate()
        .map_err(|e| StatusError::bad_request(format!("Playbook validation failed: {e}")))?;

    // Store trigger fields and steps_json
    let steps_json = serde_json::to_string(&playbook.steps)
        .map_err(|e| StatusError::internal(e.to_string()))?;

    let record = state.storage.insert_playbook(
        &tenant_id,
        &playbook.name,
        &playbook.trigger.kind,
        &playbook.trigger.get_severities(),
        playbook.trigger.agent_id.as_deref(),
        playbook.trigger.environment.as_deref(),
        &steps_json,
    )
    .await
    .map_err(|e| StatusError::internal(e.to_string()))?;

    Ok((StatusCode::CREATED, Json(record)))
}

pub async fn list_playbooks(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> Result<impl IntoResponse, StatusError> {
    let records = state.storage.list_playbooks(&tenant_id)
        .await
        .map_err(|e| StatusError::internal(e.to_string()))?;
    Ok(Json(records))
}

pub async fn delete_playbook(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusError> {
    let success = state.storage.delete_playbook(&tenant_id, &id)
        .await
        .map_err(|e| StatusError::internal(e.to_string()))?;
    if success {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusError::not_found("Playbook not found"))
    }
}

pub async fn test_playbook(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(req): Json<MockIncidentRequest>,
) -> Result<impl IntoResponse, StatusError> {
    let record_opt = state.storage.get_playbook_by_id(&tenant_id, &id)
        .await
        .map_err(|e| StatusError::internal(e.to_string()))?;
    
    let record = match record_opt {
        Some(r) => r,
        None => return Err(StatusError::not_found("Playbook not found")),
    };

    let playbook = aegis_soc::playbook::ResponsePlaybook::from_record(&record)
        .map_err(|e| StatusError::internal(format!("Failed to parse playbook: {e}")))?;

    // Fetch the agent or build a mock one if not found
    let agent = match state.storage.get_agent_by_id(&tenant_id, &req.agent_id).await {
        Ok(Some(a)) => a,
        _ => aegis_api::models::AgentRecord {
            id: req.agent_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_key: req.agent_id.clone(),
            agent_token: "".to_string(),
            name: "Mock Agent".to_string(),
            owner_team: None,
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "low".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            quarantined_at: None,
            force_approval: false,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    };

    let incident_id = uuid::Uuid::new_v4().to_string();
    
    let incident_json = serde_json::json!({
        "incident_id": incident_id,
        "opened_at": chrono::Utc::now().to_rfc3339(),
        "tenant_id": tenant_id,
        "agent_id": req.agent_id,
        "kind": req.kind,
        "severity": req.severity,
        "summary": req.summary,
        "source_event_ids": ["test_event_id"],
    });
    
    let mock_incident: aegis_soc::correlate::Incident = serde_json::from_value(incident_json)
        .map_err(|e| StatusError::internal(format!("Failed to build mock incident: {e}")))?;

    let matched = playbook.matches(&mock_incident, &agent);
    
    let steps_to_execute = if matched {
        playbook.steps.clone()
    } else {
        Vec::new()
    };

    Ok(Json(PlaybookTestResponse {
        matched,
        playbook_name: playbook.name,
        steps_to_execute,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::*;
    use axum::body::to_bytes;
    use serde_json::Value;

    #[tokio::test]
    async fn test_playbook_crud_routes() {
        let (state, tenant_id, _) = setup_state("playbook_crud").await;

        // 1. Create a playbook via YAML payload
        let yaml_payload = r#"
name: "Quarantine MCP Playbook"
trigger:
  kind: "data_exfil_pattern"
  severity: ["high", "critical"]
steps:
  - action: "quarantine_mcp"
    server_key: "server-123"
"#;
        let response = create_playbook(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::body::Bytes::from(yaml_payload),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: Value = serde_json::from_slice(&body).unwrap();
        let playbook_id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["name"], "Quarantine MCP Playbook");

        // 2. List playbooks
        let response_list = list_playbooks(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response_list.status(), StatusCode::OK);
        let body_list = to_bytes(response_list.into_body(), usize::MAX).await.unwrap();
        let list: Value = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);

        // 3. Test/Dry-run playbook (should match)
        let mock_incident = MockIncidentRequest {
            kind: "data_exfil_pattern".to_string(),
            severity: "critical".to_string(),
            agent_id: "agent-123".to_string(),
            summary: "Data exfil detected".to_string(),
        };
        let response_test = test_playbook(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(playbook_id.clone()),
            Json(mock_incident),
        )
        .await
        .into_response();
        assert_eq!(response_test.status(), StatusCode::OK);
        let body_test = to_bytes(response_test.into_body(), usize::MAX).await.unwrap();
        let test_res: Value = serde_json::from_slice(&body_test).unwrap();
        assert!(test_res["matched"].as_bool().unwrap());
        assert_eq!(test_res["steps_to_execute"].as_array().unwrap().len(), 1);

        // 4. Test/Dry-run playbook (should not match because of kind)
        let mock_incident_mismatch = MockIncidentRequest {
            kind: "deny_storm".to_string(),
            severity: "critical".to_string(),
            agent_id: "agent-123".to_string(),
            summary: "Deny storm detected".to_string(),
        };
        let response_test_mismatch = test_playbook(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(playbook_id.clone()),
            Json(mock_incident_mismatch),
        )
        .await
        .into_response();
        let body_test_mismatch = to_bytes(response_test_mismatch.into_body(), usize::MAX).await.unwrap();
        let test_res_mismatch: Value = serde_json::from_slice(&body_test_mismatch).unwrap();
        assert!(!test_res_mismatch["matched"].as_bool().unwrap());

        // 5. Delete playbook
        let response_delete = delete_playbook(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(playbook_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete.status(), StatusCode::NO_CONTENT);

        // 6. List playbooks again (should be empty)
        let response_list_empty = list_playbooks(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        let body_list_empty = to_bytes(response_list_empty.into_body(), usize::MAX).await.unwrap();
        let list_empty: Value = serde_json::from_slice(&body_list_empty).unwrap();
        assert!(list_empty.as_array().unwrap().is_empty());
    }
}
