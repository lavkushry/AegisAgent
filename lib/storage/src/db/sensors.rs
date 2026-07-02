//! Phase 3.2 (Agent Cage): sensor registration + heartbeat storage.
//!
//! Registration is an upsert keyed on `(tenant_id, node_key)` — a sensor
//! restarting with the same stable node identifier updates its existing row
//! rather than accumulating duplicates (mirrors `upsert_mcp_server`'s
//! pattern). Heartbeat is a plain tenant-scoped update. All queries
//! parameterized.

use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

const COLS: &str = "id, tenant_id, node_key, hostname, environment, sensor_version, \
     public_key, capabilities, mode, status, config_version, queue_depth_critical, \
     queue_depth_normal, disk_usage_bytes, active_cage_runs, last_event_watermark, \
     last_command_watermark, health_status, registered_at, last_heartbeat_at, created_at";

/// Register (or re-register) a sensor. Returns the sensor's `id` — either
/// freshly generated, or the existing row's id if `(tenant_id, node_key)`
/// already had one.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_sensor(
    pool: &DbPool,
    tenant_id: &str,
    node_key: &str,
    hostname: &str,
    environment: Option<&str>,
    sensor_version: &str,
    public_key: &str,
    capabilities_json: &str,
    mode: &str,
    now: DateTime<Utc>,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(
        pool,
        "INSERT INTO sensors
           (id, tenant_id, node_key, hostname, environment, sensor_version,
            public_key, capabilities, mode, status, registered_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered', ?, ?)
         ON CONFLICT(tenant_id, node_key) DO UPDATE SET
            hostname=excluded.hostname,
            environment=excluded.environment,
            sensor_version=excluded.sensor_version,
            public_key=excluded.public_key,
            capabilities=excluded.capabilities,
            mode=excluded.mode,
            status='registered',
            registered_at=excluded.registered_at",
        &id,
        tenant_id,
        node_key,
        hostname,
        environment,
        sensor_version,
        public_key,
        capabilities_json,
        mode,
        now,
        now
    )?;

    crate::fetch_one_scalar!(
        String,
        pool,
        "SELECT id FROM sensors WHERE tenant_id = ? AND node_key = ?",
        tenant_id,
        node_key,
    )
}

/// Fetch a sensor by id, tenant-scoped (cross-tenant lookups return `None`).
pub async fn get_sensor(
    pool: &DbPool,
    tenant_id: &str,
    sensor_id: &str,
) -> Result<Option<SensorRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM sensors WHERE tenant_id = ? AND id = ?");
    crate::fetch_optional_as!(SensorRecord, pool, sql.as_str(), tenant_id, sensor_id)
}

/// Apply a heartbeat: updates mode/version/queue-depth/health fields and
/// stamps `last_heartbeat_at`. Tenant-scoped; returns `true` only if a row
/// existed and was updated (`false` means the sensor id doesn't exist for
/// this tenant — the caller maps that to a 404).
#[allow(clippy::too_many_arguments)]
pub async fn heartbeat_sensor(
    pool: &DbPool,
    tenant_id: &str,
    sensor_id: &str,
    mode: &str,
    sensor_version: &str,
    queue_depth_critical: Option<i64>,
    queue_depth_normal: Option<i64>,
    disk_usage_bytes: Option<i64>,
    active_cage_runs: Option<i64>,
    last_event_watermark: Option<&str>,
    last_command_watermark: Option<&str>,
    health_status: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE sensors SET
                mode = ?,
                sensor_version = ?,
                status = 'heartbeating',
                queue_depth_critical = ?,
                queue_depth_normal = ?,
                disk_usage_bytes = ?,
                active_cage_runs = ?,
                last_event_watermark = COALESCE(?, last_event_watermark),
                last_command_watermark = COALESCE(?, last_command_watermark),
                health_status = ?,
                last_heartbeat_at = ?
             WHERE tenant_id = ? AND id = ?",
            mode,
            sensor_version,
            queue_depth_critical,
            queue_depth_normal,
            disk_usage_bytes,
            active_cage_runs,
            last_event_watermark,
            last_command_watermark,
            health_status,
            now,
            tenant_id,
            sensor_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// List a tenant's sensors, newest-registered-first. `limit` is clamped.
pub async fn list_sensors(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<SensorRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM sensors WHERE tenant_id = ?
         ORDER BY registered_at DESC, rowid DESC LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(SensorRecord, pool, sql.as_str(), tenant_id, limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;

    #[tokio::test]
    async fn register_creates_a_new_sensor() {
        let pool = setup_pool("sensor_register").await;
        let now = Utc::now();
        let id = upsert_sensor(
            &pool,
            "t_a",
            "node-1",
            "host-a",
            Some("prod"),
            "0.1.0",
            "deadbeef",
            "[]",
            "observe",
            now,
        )
        .await
        .unwrap();

        let sensor = get_sensor(&pool, "t_a", &id).await.unwrap().unwrap();
        assert_eq!(sensor.hostname, "host-a");
        assert_eq!(sensor.status, "registered");
        assert_eq!(sensor.mode, "observe");
    }

    #[tokio::test]
    async fn re_registering_same_node_key_updates_the_same_row() {
        let pool = setup_pool("sensor_reregister").await;
        let now = Utc::now();
        let first_id = upsert_sensor(
            &pool, "t_a", "node-1", "host-a", None, "0.1.0", "keyA", "[]", "observe", now,
        )
        .await
        .unwrap();

        let second_id = upsert_sensor(
            &pool,
            "t_a",
            "node-1",
            "host-a-renamed",
            None,
            "0.2.0",
            "keyB",
            "[]",
            "enforce",
            now,
        )
        .await
        .unwrap();

        assert_eq!(first_id, second_id);
        let sensor = get_sensor(&pool, "t_a", &first_id).await.unwrap().unwrap();
        assert_eq!(sensor.hostname, "host-a-renamed");
        assert_eq!(sensor.sensor_version, "0.2.0");
        assert_eq!(sensor.public_key, "keyB");
        assert_eq!(sensor.mode, "enforce");
    }

    #[tokio::test]
    async fn same_node_key_different_tenant_is_a_separate_sensor() {
        let pool = setup_pool("sensor_tenant_scope").await;
        let now = Utc::now();
        let id_a = upsert_sensor(
            &pool, "t_a", "node-1", "host-a", None, "0.1.0", "keyA", "[]", "observe", now,
        )
        .await
        .unwrap();
        let id_b = upsert_sensor(
            &pool, "t_b", "node-1", "host-b", None, "0.1.0", "keyB", "[]", "observe", now,
        )
        .await
        .unwrap();

        assert_ne!(id_a, id_b);
        assert!(get_sensor(&pool, "t_b", &id_a).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn heartbeat_updates_fields_and_is_tenant_scoped() {
        let pool = setup_pool("sensor_heartbeat").await;
        let now = Utc::now();
        let id = upsert_sensor(
            &pool, "t_a", "node-1", "host-a", None, "0.1.0", "keyA", "[]", "observe", now,
        )
        .await
        .unwrap();

        // Cross-tenant heartbeat matches nothing.
        assert!(!heartbeat_sensor(
            &pool,
            "t_b",
            &id,
            "enforce",
            "0.2.0",
            Some(3),
            Some(10),
            Some(1024),
            Some(2),
            Some("evt-100"),
            Some("cmd-5"),
            Some("ok"),
            now,
        )
        .await
        .unwrap());

        assert!(heartbeat_sensor(
            &pool,
            "t_a",
            &id,
            "enforce",
            "0.2.0",
            Some(3),
            Some(10),
            Some(1024),
            Some(2),
            Some("evt-100"),
            Some("cmd-5"),
            Some("ok"),
            now,
        )
        .await
        .unwrap());

        let sensor = get_sensor(&pool, "t_a", &id).await.unwrap().unwrap();
        assert_eq!(sensor.status, "heartbeating");
        assert_eq!(sensor.mode, "enforce");
        assert_eq!(sensor.sensor_version, "0.2.0");
        assert_eq!(sensor.queue_depth_critical, Some(3));
        assert_eq!(sensor.last_event_watermark.as_deref(), Some("evt-100"));
        assert!(sensor.last_heartbeat_at.is_some());
    }

    #[tokio::test]
    async fn heartbeat_for_unknown_sensor_id_returns_false() {
        let pool = setup_pool("sensor_heartbeat_unknown").await;
        assert!(!heartbeat_sensor(
            &pool,
            "t_a",
            "does-not-exist",
            "observe",
            "0.1.0",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Utc::now(),
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let pool = setup_pool("sensor_list").await;
        let now = Utc::now();
        upsert_sensor(
            &pool, "t_a", "node-1", "host-a", None, "0.1.0", "keyA", "[]", "observe", now,
        )
        .await
        .unwrap();
        upsert_sensor(
            &pool, "t_a", "node-2", "host-b", None, "0.1.0", "keyB", "[]", "observe", now,
        )
        .await
        .unwrap();
        upsert_sensor(
            &pool, "t_b", "node-3", "host-c", None, "0.1.0", "keyC", "[]", "observe", now,
        )
        .await
        .unwrap();

        let rows = list_sensors(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|s| s.tenant_id == "t_a"));
    }
}
