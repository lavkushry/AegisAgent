use aegis_api::models::PlaybookRecord;
use sqlx::SqlitePool;

pub async fn insert_playbook(
    pool: &SqlitePool,
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

    sqlx::query(
        "INSERT INTO response_playbooks (id, tenant_id, name, trigger_kind, trigger_severity, trigger_agent_id, trigger_environment, steps_json, enabled) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(name)
    .bind(trigger_kind)
    .bind(&trigger_severity_json)
    .bind(trigger_agent_id)
    .bind(trigger_environment)
    .bind(steps_json)
    .execute(pool)
    .await?;

    sqlx::query_as::<_, PlaybookRecord>(
        "SELECT * FROM response_playbooks WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_one(pool)
    .await
}

pub async fn list_playbooks(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<PlaybookRecord>, sqlx::Error> {
    sqlx::query_as::<_, PlaybookRecord>(
        "SELECT * FROM response_playbooks WHERE tenant_id = ? ORDER BY created_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub async fn get_playbook_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<PlaybookRecord>, sqlx::Error> {
    sqlx::query_as::<_, PlaybookRecord>(
        "SELECT * FROM response_playbooks WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn delete_playbook(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM response_playbooks WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn set_playbook_enabled(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let enabled_val = if enabled { 1 } else { 0 };
    let result =
        sqlx::query("UPDATE response_playbooks SET enabled = ? WHERE tenant_id = ? AND id = ?")
            .bind(enabled_val)
            .bind(tenant_id)
            .bind(id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}
