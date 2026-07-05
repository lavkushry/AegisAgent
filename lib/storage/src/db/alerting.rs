use crate::db::DbPool;
use aegis_api::models::{AlertSilenceRecord, ContactPointRecord, NotificationPolicyRecord};
use chrono::{DateTime, Utc};

// --- Contact points ---

#[allow(clippy::too_many_arguments)]
pub async fn insert_contact_point(
    pool: &DbPool,
    tenant_id: &str,
    name: &str,
    channel_type: &str,
    url: Option<&str>,
    secret_hash: Option<&str>,
    webhook_subscription_id: Option<&str>,
    settings_json: &str,
    health_status: &str,
) -> Result<ContactPointRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    crate::execute_query!(
        pool,
        "INSERT INTO soc_contact_points (id, tenant_id, name, channel_type, url, secret_hash, webhook_subscription_id, settings_json, health_status, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &id,
        tenant_id,
        name,
        channel_type,
        url,
        secret_hash,
        webhook_subscription_id,
        settings_json,
        health_status,
        now,
        now
    )?;
    get_contact_point_by_id(pool, tenant_id, &id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

pub async fn list_contact_points_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<ContactPointRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, crate::db::SOC_MAX_LIMIT);
    let query = "SELECT id, tenant_id, name, channel_type, url, webhook_subscription_id, settings_json, health_status, created_at, updated_at, rowid \
         FROM soc_contact_points \
         WHERE tenant_id = ? AND (? IS NULL OR rowid < ?) \
         ORDER BY rowid DESC LIMIT ? OFFSET ?";
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

pub async fn get_contact_point_by_id(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<ContactPointRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        ContactPointRecord,
        pool,
        "SELECT id, tenant_id, name, channel_type, url, webhook_subscription_id, settings_json, health_status, created_at, updated_at \
         FROM soc_contact_points WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )
}

pub async fn update_contact_point(
    pool: &DbPool,
    record: &ContactPointRecord,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    crate::execute_query!(
        pool,
        "UPDATE soc_contact_points SET name = ?, channel_type = ?, url = ?, webhook_subscription_id = ?, settings_json = ?, health_status = ?, updated_at = ? \
         WHERE tenant_id = ? AND id = ?",
        &record.name,
        &record.channel_type,
        &record.url,
        &record.webhook_subscription_id,
        &record.settings_json,
        &record.health_status,
        now,
        &record.tenant_id,
        &record.id
    )?;
    Ok(())
}

pub async fn delete_contact_point(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM soc_contact_points WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}

// --- Notification policies ---

#[allow(clippy::too_many_arguments)]
pub async fn insert_notification_policy(
    pool: &DbPool,
    tenant_id: &str,
    name: &str,
    enabled: bool,
    matchers_json: &str,
    contact_point_ids_json: &str,
    group_by: Option<&str>,
    repeat_interval_secs: Option<i64>,
) -> Result<NotificationPolicyRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let enabled_val = if enabled { 1 } else { 0 };
    crate::execute_query!(
        pool,
        "INSERT INTO soc_notification_policies (id, tenant_id, name, enabled, matchers_json, contact_point_ids_json, group_by, repeat_interval_secs, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &id,
        tenant_id,
        name,
        enabled_val,
        matchers_json,
        contact_point_ids_json,
        group_by,
        repeat_interval_secs,
        now,
        now
    )?;
    get_notification_policy_by_id(pool, tenant_id, &id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

pub async fn list_notification_policies_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<NotificationPolicyRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, crate::db::SOC_MAX_LIMIT);
    let query = "SELECT *, rowid FROM soc_notification_policies \
         WHERE tenant_id = ? AND (? IS NULL OR rowid < ?) \
         ORDER BY rowid DESC LIMIT ? OFFSET ?";
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

pub async fn get_notification_policy_by_id(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<NotificationPolicyRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        NotificationPolicyRecord,
        pool,
        "SELECT * FROM soc_notification_policies WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )
}

pub async fn update_notification_policy(
    pool: &DbPool,
    record: &NotificationPolicyRecord,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let enabled_val = if record.enabled { 1 } else { 0 };
    crate::execute_query!(
        pool,
        "UPDATE soc_notification_policies SET name = ?, enabled = ?, matchers_json = ?, contact_point_ids_json = ?, group_by = ?, repeat_interval_secs = ?, updated_at = ? \
         WHERE tenant_id = ? AND id = ?",
        &record.name,
        enabled_val,
        &record.matchers_json,
        &record.contact_point_ids_json,
        &record.group_by,
        &record.repeat_interval_secs,
        now,
        &record.tenant_id,
        &record.id
    )?;
    Ok(())
}

pub async fn delete_notification_policy(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM soc_notification_policies WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}

// --- Silences ---

#[allow(clippy::too_many_arguments)]
pub async fn insert_alert_silence(
    pool: &DbPool,
    tenant_id: &str,
    rule_key: Option<&str>,
    agent_id: Option<&str>,
    comment: Option<&str>,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    created_by: Option<&str>,
) -> Result<AlertSilenceRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(
        pool,
        "INSERT INTO alert_silences (id, tenant_id, rule_key, agent_id, comment, starts_at, ends_at, created_by, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')",
        &id,
        tenant_id,
        rule_key,
        agent_id,
        comment,
        starts_at,
        ends_at,
        created_by
    )?;
    get_alert_silence_by_id(pool, tenant_id, &id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

pub async fn list_alert_silences_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<AlertSilenceRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, crate::db::SOC_MAX_LIMIT);
    expire_stale_silences(pool, tenant_id).await?;
    let query = "SELECT *, rowid FROM alert_silences \
         WHERE tenant_id = ? AND status = 'active' AND (? IS NULL OR rowid < ?) \
         ORDER BY rowid DESC LIMIT ? OFFSET ?";
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

pub async fn get_alert_silence_by_id(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<AlertSilenceRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        AlertSilenceRecord,
        pool,
        "SELECT * FROM alert_silences WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )
}

pub async fn delete_alert_silence(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "UPDATE alert_silences SET status = 'deleted' WHERE tenant_id = ? AND id = ? AND status = 'active'",
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}

/// Mark silences past `ends_at` as expired (deterministic expiry).
pub async fn expire_stale_silences(pool: &DbPool, tenant_id: &str) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    crate::execute_query!(
        pool,
        "UPDATE alert_silences SET status = 'expired' WHERE tenant_id = ? AND status = 'active' AND ends_at <= ?",
        tenant_id,
        now
    )?;
    Ok(())
}

/// Returns true when an active silence covers the given rule/agent at `at`.
pub async fn is_alert_silenced(
    pool: &DbPool,
    tenant_id: &str,
    rule_key: Option<&str>,
    agent_id: Option<&str>,
    at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    expire_stale_silences(pool, tenant_id).await?;
    let rows: Vec<AlertSilenceRecord> = crate::fetch_all_as!(
        AlertSilenceRecord,
        pool,
        "SELECT * FROM alert_silences WHERE tenant_id = ? AND status = 'active' AND starts_at <= ? AND ends_at > ?",
        tenant_id,
        at,
        at
    )?;
    Ok(rows
        .iter()
        .any(|s| silence_matches_row(s, rule_key, agent_id)))
}

fn silence_matches_row(
    silence: &AlertSilenceRecord,
    rule_key: Option<&str>,
    agent_id: Option<&str>,
) -> bool {
    if let Some(sk) = silence.rule_key.as_deref() {
        if rule_key != Some(sk) {
            return false;
        }
    }
    if let Some(aid) = silence.agent_id.as_deref() {
        if agent_id != Some(aid) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::register_tenant;
    use crate::db::test_utils::setup_pool;

    #[tokio::test]
    async fn silence_crud_and_expiry() {
        let pool = setup_pool("alerting_silence_crud").await;
        let tenant_id = "tenant_alerting_silence".to_string();
        register_tenant(&pool, &tenant_id, "Silence Tenant", "developer")
            .await
            .unwrap();

        let start = Utc::now();
        let end = start + chrono::Duration::minutes(30);
        let silence = insert_alert_silence(
            &pool,
            &tenant_id,
            Some("rule_x"),
            Some("agent_y"),
            Some("maintenance"),
            start,
            end,
            Some("analyst"),
        )
        .await
        .unwrap();
        assert_eq!(silence.status, "active");

        assert!(
            is_alert_silenced(&pool, &tenant_id, Some("rule_x"), Some("agent_y"), start)
                .await
                .unwrap()
        );
        assert!(!is_alert_silenced(
            &pool,
            &tenant_id,
            Some("rule_other"),
            Some("agent_y"),
            start
        )
        .await
        .unwrap());

        let past_end = end + chrono::Duration::seconds(1);
        expire_stale_silences(&pool, &tenant_id).await.unwrap();
        assert!(
            !is_alert_silenced(&pool, &tenant_id, Some("rule_x"), Some("agent_y"), past_end)
                .await
                .unwrap()
        );

        assert!(delete_alert_silence(&pool, &tenant_id, &silence.id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn contact_point_does_not_leak_secret_hash_in_list() {
        let pool = setup_pool("alerting_contact_redact").await;
        let tenant_id = "tenant_alerting_cp".to_string();
        register_tenant(&pool, &tenant_id, "CP Tenant", "developer")
            .await
            .unwrap();

        insert_contact_point(
            &pool,
            &tenant_id,
            "ops-slack",
            "slack",
            Some("https://hooks.slack.com/services/T/B/X"),
            Some("sha256:deadbeef"),
            None,
            "{}",
            "unknown",
        )
        .await
        .unwrap();

        let (items, _) = list_contact_points_cursor(&pool, &tenant_id, 10, 0, None)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        let json = serde_json::to_string(&items[0]).unwrap();
        assert!(!json.contains("deadbeef"));
    }
}
