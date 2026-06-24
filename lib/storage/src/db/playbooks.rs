use crate::db::DbPool;
use aegis_api::models::PlaybookRecord;

#[allow(clippy::too_many_arguments)]
pub async fn insert_playbook(
    pool: &DbPool,
    tenant_id: &str,
    name: &str,
    trigger_kind: &str,
    trigger_severity: &[String],
    trigger_agent_id: Option<&str>,
    trigger_environment: Option<&str>,
    steps_json: &str,
) -> Result<PlaybookRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let trigger_severity_json = serde_json::to_string(trigger_severity)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    crate::execute_query!(pool, "INSERT INTO response_playbooks (id, tenant_id, name, trigger_kind, trigger_severity, trigger_agent_id, trigger_environment, steps_json, enabled) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)", &id, tenant_id, name, trigger_kind, &trigger_severity_json, trigger_agent_id, trigger_environment, steps_json)?;

    crate::fetch_one_as!(
        PlaybookRecord,
        pool,
        "SELECT * FROM response_playbooks WHERE tenant_id = ? AND id = ?",
        tenant_id,
        &id
    )
}

pub async fn list_playbooks(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<PlaybookRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        PlaybookRecord,
        pool,
        "SELECT * FROM response_playbooks WHERE tenant_id = ? ORDER BY created_at DESC",
        tenant_id
    )
}

pub async fn get_playbook_by_id(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<PlaybookRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        PlaybookRecord,
        pool,
        "SELECT * FROM response_playbooks WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )
}

pub async fn delete_playbook(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM response_playbooks WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}

pub async fn set_playbook_enabled(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let enabled_val = if enabled { 1 } else { 0 };
    let result = crate::execute_query!(
        pool,
        "UPDATE response_playbooks SET enabled = ? WHERE tenant_id = ? AND id = ?",
        enabled_val,
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}
