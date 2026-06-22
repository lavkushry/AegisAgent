use super::SOC_MAX_LIMIT;
use aegis_api::models::*;
use sqlx::SqlitePool;

pub async fn list_policies(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<PolicyRecord>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRecord>(
        "SELECT id, tenant_id, policy_key, name, language, body, version, status, created_by, created_at
         FROM policies
         WHERE tenant_id = ? AND deleted_at IS NULL
         ORDER BY created_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub async fn get_policy_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    policy_id: &str,
) -> Result<Option<PolicyRecord>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRecord>(
        "SELECT id, tenant_id, policy_key, name, language, body, version, status, created_by, created_at
         FROM policies
         WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(policy_id)
    .fetch_optional(pool)
    .await
}

pub async fn insert_policy(pool: &SqlitePool, record: &PolicyRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO policies (id, tenant_id, policy_key, name, language, body, version, status, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.policy_key)
    .bind(&record.name)
    .bind(&record.language)
    .bind(&record.body)
    .bind(record.version)
    .bind(&record.status)
    .bind(&record.created_by)
    .bind(record.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_policy(pool: &SqlitePool, record: &PolicyRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE policies
         SET policy_key = ?, name = ?, language = ?, body = ?, version = ?, status = ?, created_by = ?, created_at = ?
         WHERE tenant_id = ? AND id = ?"
    )
    .bind(&record.policy_key)
    .bind(&record.name)
    .bind(&record.language)
    .bind(&record.body)
    .bind(record.version)
    .bind(&record.status)
    .bind(&record.created_by)
    .bind(record.created_at)
    .bind(&record.tenant_id)
    .bind(&record.id)
    .execute(pool)
    .await?;
    Ok(())
}

/// TASK-0091 (#937): archive `record` (the pre-update policy row) into
/// `policy_versions` so it can be inspected/restored later. Called by
/// `routes::update_policy` before the `policies` row is overwritten in place.
/// Tenant-scoped, parameterized.
pub async fn insert_policy_version(
    pool: &SqlitePool,
    record: &PolicyRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO policy_versions (id, tenant_id, policy_id, policy_key, name, language, body, version, status, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&record.tenant_id)
    .bind(&record.id)
    .bind(&record.policy_key)
    .bind(&record.name)
    .bind(&record.language)
    .bind(&record.body)
    .bind(record.version)
    .bind(&record.status)
    .bind(&record.created_by)
    .bind(record.created_at)
    .execute(pool)
    .await?;

    // #1302: cap archived versions at 10 per (tenant_id, policy_id) — delete
    // anything beyond the 10 most recent (by version) to bound table growth.
    sqlx::query(
        "DELETE FROM policy_versions
         WHERE tenant_id = ? AND policy_id = ?
           AND id NOT IN (
             SELECT id FROM policy_versions
             WHERE tenant_id = ? AND policy_id = ?
             ORDER BY version DESC LIMIT 10
           )",
    )
    .bind(&record.tenant_id)
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// TASK-0091 (#937): list archived versions of a policy, most recent first.
/// Tenant-scoped, parameterized.
pub async fn list_policy_versions(
    pool: &SqlitePool,
    tenant_id: &str,
    policy_id: &str,
) -> Result<Vec<PolicyVersionRecord>, sqlx::Error> {
    sqlx::query_as::<_, PolicyVersionRecord>(
        "SELECT * FROM policy_versions WHERE tenant_id = ? AND policy_id = ? ORDER BY version DESC",
    )
    .bind(tenant_id)
    .bind(policy_id)
    .fetch_all(pool)
    .await
}

/// #1193: soft delete — marks `deleted_at` instead of removing the row, so
/// `list_policies`/`get_policy_by_id` (which filter `deleted_at IS NULL`)
/// stop surfacing it while the data stays recoverable. `deleted_at IS NULL`
/// in the `WHERE` clause makes this idempotent: a second delete of an
/// already-deleted policy affects zero rows, matching the existing
/// "delete non-existent policy returns 404" contract callers rely on.
pub async fn delete_policy(
    pool: &SqlitePool,
    tenant_id: &str,
    policy_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE policies SET deleted_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(policy_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// #1312: append a hash-chained entry to the tenant's `policy_audit_log`.
///
/// Mirrors [`append_action_receipt_atomic`]: `BEGIN IMMEDIATE` serializes
/// concurrent appenders, the current chain head is read, and `build` receives
/// that head's `entry_hash` (`""` for the genesis entry) and returns the
/// fully-hashed record to insert. The `policy_audit_log` table additionally
/// has SQLite triggers that abort any `UPDATE`/`DELETE`, making the chain
/// tamper-evident at the database level.
pub async fn append_policy_audit_log_entry_atomic<F>(
    pool: &SqlitePool,
    tenant_id: &str,
    build: F,
) -> Result<PolicyAuditLogRecord, sqlx::Error>
where
    F: FnOnce(String) -> PolicyAuditLogRecord,
{
    let mut conn = pool.acquire().await?;

    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    async fn rollback(conn: &mut sqlx::SqliteConnection) {
        let _ = sqlx::query("ROLLBACK").execute(conn).await;
    }

    let head: Option<(String,)> = match sqlx::query_as(
        "SELECT entry_hash FROM policy_audit_log WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(h) => h,
        Err(e) => {
            rollback(&mut conn).await;
            return Err(e);
        }
    };
    let prev = head.map(|(h,)| h).unwrap_or_default();

    let record = build(prev);

    if let Err(e) = sqlx::query(
        "INSERT INTO policy_audit_log (id, tenant_id, policy_id, policy_key, action, changed_by, body_hash, diff_summary, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.policy_id)
    .bind(&record.policy_key)
    .bind(&record.action)
    .bind(&record.changed_by)
    .bind(&record.body_hash)
    .bind(&record.diff_summary)
    .bind(&record.prev_hash)
    .bind(&record.entry_hash)
    .execute(&mut *conn)
    .await
    {
        rollback(&mut conn).await;
        return Err(e);
    }

    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(record)
}

/// #1312: tenant-scoped, paginated listing of the policy transparency log,
/// newest first.
pub async fn list_policy_audit_log(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<PolicyAuditLogRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    sqlx::query_as::<_, PolicyAuditLogRecord>(
        "SELECT * FROM policy_audit_log WHERE tenant_id = ? ORDER BY rowid DESC LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::register_tenant;
    use crate::db::test_utils::*;

    fn make_test_policy(id: &str, tenant_id: &str, policy_key: &str) -> PolicyRecord {
        PolicyRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            policy_key: policy_key.to_string(),
            name: "Test Policy".to_string(),
            language: "cedar".to_string(),
            body: "permit (principal, action, resource);".to_string(),
            version: 1,
            status: "active".to_string(),
            created_by: None,
            created_at: chrono::Utc::now(),
        }
    }

    /// #1193: `delete_policy` soft-deletes (sets `deleted_at`) instead of
    /// removing the row — it must disappear from `list_policies`/
    /// `get_policy_by_id` while the underlying row still exists.
    #[tokio::test]
    async fn delete_policy_soft_deletes_and_hides_from_reads() {
        let pool = setup_pool("policy_soft_delete").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        let policy = make_test_policy("pol_1", "tenant_a", "allow-all");
        insert_policy(&pool, &policy).await.unwrap();

        assert!(delete_policy(&pool, "tenant_a", "pol_1").await.unwrap());

        assert!(
            get_policy_by_id(&pool, "tenant_a", "pol_1")
                .await
                .unwrap()
                .is_none(),
            "a soft-deleted policy must not be returned by get_policy_by_id"
        );
        assert!(
            list_policies(&pool, "tenant_a").await.unwrap().is_empty(),
            "a soft-deleted policy must not appear in list_policies"
        );

        // The row itself must still exist (soft, not hard, delete).
        let raw: (Option<String>,) =
            sqlx::query_as("SELECT deleted_at FROM policies WHERE tenant_id = ? AND id = ?")
                .bind("tenant_a")
                .bind("pol_1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            raw.0.is_some(),
            "the row must persist with deleted_at set, not be removed"
        );
    }

    /// #1193: deleting an already-deleted policy must be a no-op (affects
    /// zero rows) rather than erroring or double-counting — this is the
    /// `deleted_at IS NULL` guard in the `UPDATE`'s `WHERE` clause.
    #[tokio::test]
    async fn delete_policy_is_idempotent() {
        let pool = setup_pool("policy_delete_idempotent").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        let policy = make_test_policy("pol_2", "tenant_a", "allow-all-2");
        insert_policy(&pool, &policy).await.unwrap();

        assert!(delete_policy(&pool, "tenant_a", "pol_2").await.unwrap());
        assert!(
            !delete_policy(&pool, "tenant_a", "pol_2").await.unwrap(),
            "deleting an already-deleted policy must affect zero rows"
        );
    }
}
