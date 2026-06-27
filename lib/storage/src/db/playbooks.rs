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

/// #1142: cursor-paginated variant of `list_playbooks`.
pub async fn list_playbooks_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<PlaybookRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, crate::db::SOC_MAX_LIMIT);
    let query = "SELECT *, rowid FROM response_playbooks
         WHERE tenant_id = ?
           AND (? IS NULL OR rowid < ?)
         ORDER BY rowid DESC
         LIMIT ? OFFSET ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(cursor)
                .bind(cursor)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(query);
            let rows = sqlx::query(&pg_sql)
                .bind(tenant_id)
                .bind(cursor)
                .bind(cursor)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::register_tenant;
    use crate::db::test_utils::setup_pool;

    async fn insert_test_playbook(pool: &DbPool, tenant_id: &str, name: &str) -> PlaybookRecord {
        insert_playbook(
            pool,
            tenant_id,
            name,
            "incident_opened",
            &["high".to_string()],
            None,
            None,
            "[]",
        )
        .await
        .unwrap()
    }

    /// #1142: `list_playbooks_cursor` returns a `next_cursor` when more rows
    /// exist beyond the requested page.
    #[tokio::test]
    async fn list_playbooks_cursor_paginates_and_sets_next_cursor() {
        let pool = setup_pool("playbooks_cursor_paginate").await;
        let tenant_id = "tenant_playbooks_cursor_paginate".to_string();
        register_tenant(&pool, &tenant_id, "Cursor Test Tenant", "developer")
            .await
            .unwrap();
        for i in 0..3 {
            insert_test_playbook(&pool, &tenant_id, &format!("playbook-{i}")).await;
        }

        let (page, next_cursor) = list_playbooks_cursor(&pool, &tenant_id, 2, 0, None)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert!(next_cursor.is_some(), "a third row exists beyond the page");

        let (page2, next_cursor2) = list_playbooks_cursor(&pool, &tenant_id, 2, 0, next_cursor)
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(next_cursor2, None);
    }

    /// #1142: regression guard for the off-by-one in `paginate_rows` — a
    /// page that ends exactly on the result-set boundary must not claim a
    /// next page exists.
    #[tokio::test]
    async fn list_playbooks_cursor_no_false_next_cursor_at_exact_boundary() {
        let pool = setup_pool("playbooks_cursor_boundary").await;
        let tenant_id = "tenant_playbooks_cursor_boundary".to_string();
        register_tenant(&pool, &tenant_id, "Boundary Test Tenant", "developer")
            .await
            .unwrap();
        insert_test_playbook(&pool, &tenant_id, "playbook-a").await;

        let (page, next_cursor) = list_playbooks_cursor(&pool, &tenant_id, 1, 0, None)
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(next_cursor, None);
    }
}
