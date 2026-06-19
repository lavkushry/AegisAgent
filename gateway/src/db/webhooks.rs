use crate::models::*;
use sqlx::SqlitePool;

/// TASK-0092 (#938): register a tenant-managed webhook subscription.
/// `secret_hash` is `sha256(secret)`, computed by the caller — the plaintext
/// secret is never persisted. `delivery_secret` (#1285) is a separate,
/// server-generated plaintext secret the gateway keeps to HMAC-sign every
/// outbound delivery to this subscription. Tenant-scoped, parameterized.
#[allow(clippy::too_many_arguments)]
pub async fn insert_webhook_subscription(
    pool: &SqlitePool,
    tenant_id: &str,
    url: &str,
    secret_hash: Option<&str>,
    event_types: &str,
    delivery_secret: &str,
    min_severity: &str,
    format: &str,
) -> Result<WebhookSubscriptionRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO webhook_subscriptions (id, tenant_id, url, secret_hash, event_types, status, delivery_secret, min_severity, format, delivery_status) \
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, 'healthy')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(url)
    .bind(secret_hash)
    .bind(event_types)
    .bind(delivery_secret)
    .bind(min_severity)
    .bind(format)
    .execute(pool)
    .await?;

    sqlx::query_as::<_, WebhookSubscriptionRecord>(
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_one(pool)
    .await
}

/// TASK-0092 (#938): list webhook subscriptions for a tenant, most recent first.
pub async fn list_webhook_subscriptions(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<WebhookSubscriptionRecord>, sqlx::Error> {
    sqlx::query_as::<_, WebhookSubscriptionRecord>(
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? ORDER BY created_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

/// #1285: tenant-scoped subscriptions whose `event_types` filter matches
/// `event_kind` (`"*"` or an exact comma-separated membership match). Severity
/// is checked separately in application code (`webhook_export::passes_severity_filter`)
/// since SQLite has no clean way to rank a string enum in SQL.
pub async fn list_matching_webhook_subscriptions(
    pool: &SqlitePool,
    tenant_id: &str,
    event_kind: &str,
) -> Result<Vec<WebhookSubscriptionRecord>, sqlx::Error> {
    sqlx::query_as::<_, WebhookSubscriptionRecord>(
        "SELECT * FROM webhook_subscriptions
         WHERE tenant_id = ?
           AND (event_types = '*' OR ',' || event_types || ',' LIKE '%,' || ? || ',%')",
    )
    .bind(tenant_id)
    .bind(event_kind)
    .fetch_all(pool)
    .await
}

/// #1285: fetch a single tenant-scoped webhook subscription by id.
pub async fn get_webhook_subscription(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<WebhookSubscriptionRecord>, sqlx::Error> {
    sqlx::query_as::<_, WebhookSubscriptionRecord>(
        "SELECT * FROM webhook_subscriptions WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// TASK-0092 (#938): delete a tenant's webhook subscription. Returns `true`
/// if a row was deleted.
pub async fn delete_webhook_subscription(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM webhook_subscriptions WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// #1285: update a subscription's delivery health after an attempt
/// (success, or failure after exhausting retries). Thresholds:
/// `consecutive_failures >= 10` -> `"dead"`, `>= 3` -> `"degraded"`,
/// else `"healthy"`.
pub async fn record_webhook_delivery_result(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
    success: bool,
) -> Result<(), sqlx::Error> {
    if success {
        sqlx::query(
            "UPDATE webhook_subscriptions
             SET consecutive_failures = 0, delivery_status = 'healthy',
                 last_delivery_at = CURRENT_TIMESTAMP, last_success_at = CURRENT_TIMESTAMP
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE webhook_subscriptions
             SET consecutive_failures = consecutive_failures + 1,
                 last_delivery_at = CURRENT_TIMESTAMP,
                 delivery_status = CASE
                     WHEN consecutive_failures + 1 >= 10 THEN 'dead'
                     WHEN consecutive_failures + 1 >= 3 THEN 'degraded'
                     ELSE 'healthy'
                 END
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    }
    Ok(())
}
