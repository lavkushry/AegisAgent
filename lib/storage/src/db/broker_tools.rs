//! Phase 6.2 (tool broker): `broker_tools` CRUD. A broker tool binds a
//! tenant-visible `tool_name` to a connector type and an *opaque* credential
//! reference — the credential value itself never touches this table (the
//! Phase 6.1 `CredentialResolver` resolves the ref inside the broker at
//! execution time, so an agent never sees a raw credential). All queries
//! parameterized and tenant-scoped; `(tenant_id, tool_name)` is unique.

use super::SOC_MAX_LIMIT;
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

const COLS: &str = "id, tenant_id, tool_name, connector_type, credential_ref, \
     allowed_scopes, status, created_at, updated_at";

/// Register a broker tool. Returns the new row's `id`. Fails with a
/// unique-constraint error if `(tenant_id, tool_name)` already exists —
/// the caller maps that to a 409.
pub async fn insert_broker_tool(
    pool: &DbPool,
    tenant_id: &str,
    tool_name: &str,
    connector_type: &str,
    credential_ref: &str,
    allowed_scopes_json: &str,
    now: DateTime<Utc>,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(
        pool,
        "INSERT INTO broker_tools
           (id, tenant_id, tool_name, connector_type, credential_ref,
            allowed_scopes, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
        &id,
        tenant_id,
        tool_name,
        connector_type,
        credential_ref,
        allowed_scopes_json,
        now,
        now
    )?;
    Ok(id)
}

/// Fetch a broker tool by id, tenant-scoped (cross-tenant lookups return
/// `None`).
pub async fn get_broker_tool(
    pool: &DbPool,
    tenant_id: &str,
    tool_id: &str,
) -> Result<Option<BrokerToolRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM broker_tools WHERE tenant_id = ? AND id = ?");
    crate::fetch_optional_as!(BrokerToolRecord, pool, sql.as_str(), tenant_id, tool_id)
}

/// Fetch a broker tool by its tenant-visible name. This is the lookup the
/// execute path uses; callers must fail closed unless the returned row has
/// `status == "active"`.
pub async fn get_broker_tool_by_name(
    pool: &DbPool,
    tenant_id: &str,
    tool_name: &str,
) -> Result<Option<BrokerToolRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM broker_tools WHERE tenant_id = ? AND tool_name = ?");
    crate::fetch_optional_as!(BrokerToolRecord, pool, sql.as_str(), tenant_id, tool_name)
}

/// List a tenant's broker tools, newest-first. `limit` is clamped.
pub async fn list_broker_tools(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<BrokerToolRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM broker_tools WHERE tenant_id = ?
         ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(
        BrokerToolRecord,
        pool,
        sql.as_str(),
        tenant_id,
        limit,
        offset
    )
}

/// Set a broker tool's status (`active` | `disabled`). Tenant-scoped;
/// returns `true` only if a row existed and was updated (`false` maps to a
/// 404 at the route layer).
pub async fn set_broker_tool_status(
    pool: &DbPool,
    tenant_id: &str,
    tool_id: &str,
    status: &str,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "UPDATE broker_tools SET status = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ?",
        status,
        now,
        tenant_id,
        tool_id
    )?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;

    async fn insert(pool: &DbPool, tenant: &str, name: &str) -> String {
        insert_broker_tool(
            pool,
            tenant,
            name,
            "http",
            "env:GITHUB_TOKEN",
            "[\"repo:read\"]",
            Utc::now(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn insert_and_fetch_roundtrip() {
        let pool = setup_pool("broker_tool_roundtrip").await;
        let id = insert(&pool, "t_a", "github").await;

        let tool = get_broker_tool(&pool, "t_a", &id).await.unwrap().unwrap();
        assert_eq!(tool.tool_name, "github");
        assert_eq!(tool.connector_type, "http");
        assert_eq!(tool.credential_ref, "env:GITHUB_TOKEN");
        assert_eq!(tool.allowed_scopes, "[\"repo:read\"]");
        assert_eq!(tool.status, "active");

        let by_name = get_broker_tool_by_name(&pool, "t_a", "github")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_name.id, id);
    }

    #[tokio::test]
    async fn lookups_are_tenant_scoped() {
        let pool = setup_pool("broker_tool_tenant_scope").await;
        let id = insert(&pool, "t_a", "github").await;

        assert!(get_broker_tool(&pool, "t_b", &id).await.unwrap().is_none());
        assert!(get_broker_tool_by_name(&pool, "t_b", "github")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn duplicate_name_in_same_tenant_is_rejected() {
        let pool = setup_pool("broker_tool_dup_name").await;
        insert(&pool, "t_a", "github").await;

        let dup = insert_broker_tool(
            &pool,
            "t_a",
            "github",
            "http",
            "env:OTHER",
            "[]",
            Utc::now(),
        )
        .await;
        assert!(dup.is_err());

        // Same name under a different tenant is a separate tool.
        insert(&pool, "t_b", "github").await;
    }

    #[tokio::test]
    async fn status_update_is_tenant_scoped() {
        let pool = setup_pool("broker_tool_status").await;
        let id = insert(&pool, "t_a", "github").await;

        // Cross-tenant update matches nothing.
        assert!(
            !set_broker_tool_status(&pool, "t_b", &id, "disabled", Utc::now())
                .await
                .unwrap()
        );

        assert!(
            set_broker_tool_status(&pool, "t_a", &id, "disabled", Utc::now())
                .await
                .unwrap()
        );
        let tool = get_broker_tool(&pool, "t_a", &id).await.unwrap().unwrap();
        assert_eq!(tool.status, "disabled");
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let pool = setup_pool("broker_tool_list").await;
        insert(&pool, "t_a", "github").await;
        insert(&pool, "t_a", "slack").await;
        insert(&pool, "t_b", "jira").await;

        let rows = list_broker_tools(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|t| t.tenant_id == "t_a"));
    }
}
