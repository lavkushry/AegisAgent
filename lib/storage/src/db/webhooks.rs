use crate::db::DbPool;
use aegis_api::models::*;

/// TASK-0092 (#938): register a tenant-managed webhook subscription.
/// `secret_hash` is `sha256(secret)`, computed by the caller — the plaintext
/// secret is never persisted. `delivery_secret` (#1285) is a separate,
/// server-generated plaintext secret the gateway keeps to HMAC-sign every
/// outbound delivery to this subscription. Tenant-scoped, parameterized.
#[allow(clippy::too_many_arguments)]
pub async fn insert_webhook_subscription(
    pool: &DbPool,
    tenant_id: &str,
    url: &str,
    secret_hash: Option<&str>,
    event_types: &str,
    delivery_secret: &str,
    min_severity: &str,
    format: &str,
) -> Result<WebhookSubscriptionRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(pool, "INSERT INTO webhook_subscriptions (id, tenant_id, url, secret_hash, event_types, status, delivery_secret, min_severity, format, delivery_status) \
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, 'healthy')", &id, tenant_id, url, secret_hash, event_types, delivery_secret, min_severity, format)?;
    crate::fetch_one_as!(
        WebhookSubscriptionRecord,
        pool,
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? AND id = ?",
        tenant_id,
        &id
    )
}

/// TASK-0092 (#938): list webhook subscriptions for a tenant, most recent first.
pub async fn list_webhook_subscriptions(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<WebhookSubscriptionRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        WebhookSubscriptionRecord,
        pool,
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? ORDER BY created_at DESC",
        tenant_id
    )
}

/// #1142: cursor-paginated variant of `list_webhook_subscriptions`.
pub async fn list_webhook_subscriptions_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<WebhookSubscriptionRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, crate::db::SOC_MAX_LIMIT);
    let query = "SELECT *, rowid FROM webhook_subscriptions
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

/// #1285: tenant-scoped subscriptions whose `event_types` filter matches
/// `event_kind` (`"*"` or an exact comma-separated membership match). Severity
/// is checked separately in application code (`webhook_export::passes_severity_filter`)
/// since SQLite has no clean way to rank a string enum in SQL.
///
/// #912: excludes `status != 'active'` (soft-deleted/disabled) and
/// `delivery_status = 'dead'` (>= 10 consecutive delivery failures, recorded
/// by `record_webhook_delivery_result`) subscriptions — this is the circuit
/// breaker for webhook export: a persistently-unreachable tenant-configured
/// URL stops being retried (3 attempts with exponential backoff, every
/// matching SOC event, forever) once it's been marked dead, mirroring the
/// `delivery_status != 'dead'` filter [`get_active_webhook_subscriptions`]
/// already applied — that function just had no caller on this dispatch path.
pub async fn list_matching_webhook_subscriptions(
    pool: &DbPool,
    tenant_id: &str,
    event_kind: &str,
) -> Result<Vec<WebhookSubscriptionRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        WebhookSubscriptionRecord,
        pool,
        "SELECT * FROM webhook_subscriptions
         WHERE tenant_id = ?
           AND status = 'active'
           AND delivery_status != 'dead'
           AND (event_types = '*' OR ',' || event_types || ',' LIKE '%,' || ? || ',%')",
        tenant_id,
        event_kind
    )
}

/// #1285: fetch a single tenant-scoped webhook subscription by id.
pub async fn get_webhook_subscription(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<WebhookSubscriptionRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        WebhookSubscriptionRecord,
        pool,
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )
}

/// TASK-0092 (#938): delete a tenant's webhook subscription. Returns `true`
/// if a row was deleted.
pub async fn delete_webhook_subscription(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM webhook_subscriptions WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}

/// #1285: update a subscription's delivery health after an attempt
/// (success, or failure after exhausting retries). Thresholds:
/// `consecutive_failures >= 10` -> `"dead"`, `>= 3` -> `"degraded"`,
/// else `"healthy"`.
pub async fn record_webhook_delivery_result(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
    success: bool,
) -> Result<(), sqlx::Error> {
    if success {
        crate::execute_query!(
            pool,
            "UPDATE webhook_subscriptions
             SET consecutive_failures = 0, delivery_status = 'healthy',
                 last_delivery_at = CURRENT_TIMESTAMP, last_success_at = CURRENT_TIMESTAMP
             WHERE tenant_id = ? AND id = ?",
            tenant_id,
            id
        )?;
    } else {
        crate::execute_query!(
            pool,
            "UPDATE webhook_subscriptions
             SET consecutive_failures = consecutive_failures + 1,
                 last_delivery_at = CURRENT_TIMESTAMP,
                 delivery_status = CASE
                     WHEN consecutive_failures + 1 >= 10 THEN 'dead'
                     WHEN consecutive_failures + 1 >= 3 THEN 'degraded'
                     ELSE 'healthy'
                 END
             WHERE tenant_id = ? AND id = ?",
            tenant_id,
            id
        )?;
    }
    Ok(())
}

/// Fetch all active (non-dead) webhook subscriptions for a tenant.
pub async fn get_active_webhook_subscriptions(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<WebhookSubscriptionRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        WebhookSubscriptionRecord,
        pool,
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? AND status = 'active' AND delivery_status != 'dead'",
        tenant_id
    )
}

pub async fn update_webhook_subscription(
    pool: &DbPool,
    record: &WebhookSubscriptionRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "UPDATE webhook_subscriptions SET \
         url = ?, secret_hash = ?, event_types = ?, status = ?, delivery_secret = ?, \
         min_severity = ?, format = ?, delivery_status = ?, consecutive_failures = ?, \
         last_delivery_at = ?, last_success_at = ? \
         WHERE tenant_id = ? AND id = ?",
        &record.url,
        &record.secret_hash,
        &record.event_types,
        &record.status,
        &record.delivery_secret,
        &record.min_severity,
        &record.format,
        &record.delivery_status,
        record.consecutive_failures,
        record.last_delivery_at,
        record.last_success_at,
        &record.tenant_id,
        &record.id
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup(test_name: &str) -> (DbPool, WebhookSubscriptionRecord) {
        let pool = crate::db::test_utils::setup_pool(test_name).await;
        let tenant_id = format!("tenant_{test_name}");
        crate::db::register_tenant(&pool, &tenant_id, "Webhook Test Tenant", "developer")
            .await
            .unwrap();
        let record = insert_webhook_subscription(
            &pool,
            &tenant_id,
            "http://127.0.0.1:1/unreachable",
            None,
            "deny,require_approval",
            "whsec_test",
            "info",
            "json",
        )
        .await
        .unwrap();
        (pool, record)
    }

    /// #912: a `dead` subscription (>= 10 consecutive delivery failures)
    /// must not be returned by the dispatch path's lookup query — this is
    /// the circuit breaker for webhook export.
    #[tokio::test]
    async fn list_matching_webhook_subscriptions_excludes_dead_subscription() {
        let (pool, mut record) = setup("webhooks_dead_excluded").await;
        record.delivery_status = "dead".to_string();
        update_webhook_subscription(&pool, &record).await.unwrap();

        let matches = list_matching_webhook_subscriptions(&pool, &record.tenant_id, "deny")
            .await
            .unwrap();
        assert!(matches.is_empty());
    }

    /// #912: an explicitly-deactivated subscription (`status != 'active'`)
    /// must also be excluded — same dispatch-path query, same fix.
    #[tokio::test]
    async fn list_matching_webhook_subscriptions_excludes_inactive_subscription() {
        let (pool, mut record) = setup("webhooks_inactive_excluded").await;
        record.status = "inactive".to_string();
        update_webhook_subscription(&pool, &record).await.unwrap();

        let matches = list_matching_webhook_subscriptions(&pool, &record.tenant_id, "deny")
            .await
            .unwrap();
        assert!(matches.is_empty());
    }

    /// #912 regression guard: a `healthy` (default) subscription is still
    /// returned — the new filter must not exclude the common case.
    #[tokio::test]
    async fn list_matching_webhook_subscriptions_includes_healthy_subscription() {
        let (pool, record) = setup("webhooks_healthy_included").await;

        let matches = list_matching_webhook_subscriptions(&pool, &record.tenant_id, "deny")
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, record.id);
    }

    /// #912: a `degraded` (1-9 consecutive failures, not yet `dead`)
    /// subscription is still retried — only `dead` stops dispatch.
    #[tokio::test]
    async fn list_matching_webhook_subscriptions_includes_degraded_subscription() {
        let (pool, mut record) = setup("webhooks_degraded_included").await;
        record.delivery_status = "degraded".to_string();
        record.consecutive_failures = 5;
        update_webhook_subscription(&pool, &record).await.unwrap();

        let matches = list_matching_webhook_subscriptions(&pool, &record.tenant_id, "deny")
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
    }

    /// #1142: `list_webhook_subscriptions_cursor` returns a `next_cursor`
    /// when more rows exist beyond the requested page.
    #[tokio::test]
    async fn list_webhook_subscriptions_cursor_paginates_and_sets_next_cursor() {
        let pool = crate::db::test_utils::setup_pool("webhooks_cursor_paginate").await;
        let tenant_id = "tenant_webhooks_cursor_paginate".to_string();
        crate::db::register_tenant(&pool, &tenant_id, "Cursor Test Tenant", "developer")
            .await
            .unwrap();
        for i in 0..3 {
            insert_webhook_subscription(
                &pool,
                &tenant_id,
                &format!("http://127.0.0.1:1/hook{i}"),
                None,
                "deny,require_approval",
                "whsec_test",
                "info",
                "json",
            )
            .await
            .unwrap();
        }

        let (page, next_cursor) = list_webhook_subscriptions_cursor(&pool, &tenant_id, 2, 0, None)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert!(next_cursor.is_some(), "a third row exists beyond the page");

        let (page2, next_cursor2) =
            list_webhook_subscriptions_cursor(&pool, &tenant_id, 2, 0, next_cursor)
                .await
                .unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(next_cursor2, None);
    }

    /// #1142: regression guard for the off-by-one in `paginate_rows` — a
    /// page that ends exactly on the result-set boundary must not claim a
    /// next page exists.
    #[tokio::test]
    async fn list_webhook_subscriptions_cursor_no_false_next_cursor_at_exact_boundary() {
        let (pool, record) = setup("webhooks_cursor_boundary").await;

        let (page, next_cursor) =
            list_webhook_subscriptions_cursor(&pool, &record.tenant_id, 1, 0, None)
                .await
                .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(next_cursor, None);
    }
}
