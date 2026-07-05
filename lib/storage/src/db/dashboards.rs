use crate::db::DbPool;
use aegis_api::models::SocDashboardRecord;
use chrono::Utc;

pub async fn insert_soc_dashboard(
    pool: &DbPool,
    tenant_id: &str,
    uid: &str,
    title: &str,
    schema_version: i64,
    schema_json: &str,
) -> Result<SocDashboardRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    crate::execute_query!(
        pool,
        "INSERT INTO soc_dashboards (id, tenant_id, uid, title, schema_version, schema_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &id,
        tenant_id,
        uid,
        title,
        schema_version,
        schema_json,
        now,
        now
    )?;
    get_soc_dashboard_by_uid(pool, tenant_id, uid)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

pub async fn update_soc_dashboard(
    pool: &DbPool,
    tenant_id: &str,
    uid: &str,
    title: &str,
    schema_version: i64,
    schema_json: &str,
) -> Result<Option<SocDashboardRecord>, sqlx::Error> {
    let now = Utc::now();
    let result = crate::execute_query!(
        pool,
        "UPDATE soc_dashboards
         SET title = ?, schema_version = ?, schema_json = ?, updated_at = ?
         WHERE tenant_id = ? AND uid = ?",
        title,
        schema_version,
        schema_json,
        now,
        tenant_id,
        uid
    )?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    get_soc_dashboard_by_uid(pool, tenant_id, uid).await
}

pub async fn list_soc_dashboards(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<SocDashboardRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        SocDashboardRecord,
        pool,
        "SELECT id, tenant_id, uid, title, schema_version, schema_json, created_at, updated_at
         FROM soc_dashboards
         WHERE tenant_id = ?
         ORDER BY updated_at DESC",
        tenant_id
    )
}

pub async fn get_soc_dashboard_by_uid(
    pool: &DbPool,
    tenant_id: &str,
    uid: &str,
) -> Result<Option<SocDashboardRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        SocDashboardRecord,
        pool,
        "SELECT id, tenant_id, uid, title, schema_version, schema_json, created_at, updated_at
         FROM soc_dashboards
         WHERE tenant_id = ? AND uid = ?",
        tenant_id,
        uid
    )
}

pub async fn delete_soc_dashboard(
    pool: &DbPool,
    tenant_id: &str,
    uid: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM soc_dashboards WHERE tenant_id = ? AND uid = ?",
        tenant_id,
        uid
    )?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tenant::insert_tenant;
    use crate::db::test_utils::*;
    use aegis_api::dashboard_schema::parse_and_validate_dashboard_json;
    use aegis_api::models::TenantRecord;
    use chrono::Utc;

    const SAMPLE_SCHEMA: &str = r#"{
      "uid": "team-posture",
      "title": "Team posture",
      "schemaVersion": 1,
      "variables": [],
      "time": { "defaultRange": { "from": "now-24h", "to": "now" }, "refreshSec": 30 },
      "layout": [{
        "id": "row-1",
        "title": "Vitals",
        "panels": [{
          "panel": {
            "id": "stat-1",
            "type": "stat",
            "title": "Decisions",
            "datasourceId": "gateway-entity",
            "snapshot": "soc-summary",
            "options": { "valueField": "decisions_today" }
          },
          "w": 4,
          "h": 1
        }]
      }]
    }"#;

    async fn seed_tenant(pool: &DbPool, id: &str, name: &str) {
        insert_tenant(
            pool,
            &TenantRecord {
                id: id.to_string(),
                name: name.to_string(),
                plan: "developer".to_string(),
                created_at: Utc::now(),
                auto_respond_enabled: false,
                auto_rotate_token_on_leak_enabled: true,
                slack_approver_group: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn soc_dashboard_crud_is_tenant_scoped() {
        let pool = setup_pool("soc_dashboard_crud").await;
        seed_tenant(&pool, "tenant_a", "Tenant A").await;
        seed_tenant(&pool, "tenant_b", "Tenant B").await;
        let schema = parse_and_validate_dashboard_json(SAMPLE_SCHEMA).unwrap();
        let raw = serde_json::to_string(&schema).unwrap();

        insert_soc_dashboard(&pool, "tenant_a", "team-posture", "Team posture", 1, &raw)
            .await
            .unwrap();

        let listed = list_soc_dashboards(&pool, "tenant_a").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].uid, "team-posture");

        assert!(get_soc_dashboard_by_uid(&pool, "tenant_b", "team-posture")
            .await
            .unwrap()
            .is_none());

        let mut updated_schema = schema.clone();
        updated_schema.title = "Updated posture".to_string();
        let updated_raw = serde_json::to_string(&updated_schema).unwrap();
        let updated = update_soc_dashboard(
            &pool,
            "tenant_a",
            "team-posture",
            "Updated posture",
            1,
            &updated_raw,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(updated.title, "Updated posture");

        assert!(delete_soc_dashboard(&pool, "tenant_a", "team-posture")
            .await
            .unwrap());
        assert!(list_soc_dashboards(&pool, "tenant_a")
            .await
            .unwrap()
            .is_empty());
    }
}
