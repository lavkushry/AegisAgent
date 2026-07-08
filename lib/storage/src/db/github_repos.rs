//! Per-repo sensitivity labels for the GitHub App protection layer (#1380).
//! No row for a repo means "low" (see the migration's rationale comment).

use crate::db::DbPool;

/// Set (creating or replacing) `repo_full_name`'s sensitivity label. Not a
/// grant/revoke list like agent_mcp_server_permissions -- a repo has at most
/// one label, so this deletes any existing row before inserting the new one
/// rather than using an idempotent `INSERT OR IGNORE`.
pub async fn set_repo_sensitivity_label(
    pool: &DbPool,
    tenant_id: &str,
    repo_full_name: &str,
    sensitivity_label: &str,
) -> Result<aegis_api::models::RepoSensitivityLabel, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now_str = chrono::Utc::now().to_rfc3339();
    crate::execute_query!(
        pool,
        "DELETE FROM repo_sensitivity_labels WHERE tenant_id = ? AND repo_full_name = ?",
        tenant_id,
        repo_full_name
    )?;
    crate::execute_query!(
        pool,
        "INSERT INTO repo_sensitivity_labels
         (id, tenant_id, repo_full_name, sensitivity_label, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        &id,
        tenant_id,
        repo_full_name,
        sensitivity_label,
        &now_str,
        &now_str
    )?;

    crate::fetch_one_as!(
        aegis_api::models::RepoSensitivityLabel,
        pool,
        "SELECT id, tenant_id, repo_full_name, sensitivity_label, created_at, updated_at
         FROM repo_sensitivity_labels
         WHERE tenant_id = ? AND repo_full_name = ?",
        tenant_id,
        repo_full_name
    )
}

/// Return `repo_full_name`'s configured label, or `None` if unset (caller
/// treats that as "low").
pub async fn get_repo_sensitivity_label(
    pool: &DbPool,
    tenant_id: &str,
    repo_full_name: &str,
) -> Result<Option<aegis_api::models::RepoSensitivityLabel>, sqlx::Error> {
    crate::fetch_optional_as!(
        aegis_api::models::RepoSensitivityLabel,
        pool,
        "SELECT id, tenant_id, repo_full_name, sensitivity_label, created_at, updated_at
         FROM repo_sensitivity_labels
         WHERE tenant_id = ? AND repo_full_name = ?",
        tenant_id,
        repo_full_name
    )
}

/// Return every repo sensitivity label configured for `tenant_id`.
pub async fn list_repo_sensitivity_labels(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<aegis_api::models::RepoSensitivityLabel>, sqlx::Error> {
    crate::fetch_all_as!(
        aegis_api::models::RepoSensitivityLabel,
        pool,
        "SELECT id, tenant_id, repo_full_name, sensitivity_label, created_at, updated_at
         FROM repo_sensitivity_labels
         WHERE tenant_id = ?
         ORDER BY repo_full_name ASC",
        tenant_id
    )
}

/// Remove `repo_full_name`'s label (reverting it to the "low" default).
/// Returns `true` if a row was deleted.
pub async fn delete_repo_sensitivity_label(
    pool: &DbPool,
    tenant_id: &str,
    repo_full_name: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM repo_sensitivity_labels WHERE tenant_id = ? AND repo_full_name = ?",
        tenant_id,
        repo_full_name
    )?;
    Ok(result.rows_affected() > 0)
}
