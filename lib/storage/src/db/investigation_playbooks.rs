//! Investigation playbook persistence (#1392).

use super::DbPool;
use super::SOC_MAX_LIMIT;
use aegis_api::models::{InvestigationPlaybookRecord, SocIncidentRecord};

pub async fn has_investigation_playbook(
    pool: &DbPool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<bool, sqlx::Error> {
    let (count,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM investigation_playbooks
         WHERE tenant_id = ? AND incident_id = ?",
        tenant_id,
        incident_id
    )?;
    Ok(count > 0)
}

pub async fn get_investigation_playbook(
    pool: &DbPool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<Option<InvestigationPlaybookRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        InvestigationPlaybookRecord,
        pool,
        "SELECT id, tenant_id, incident_id, kind, severity, agent_id, summary,
                steps_json, evidence_hints_json, status, investigator_agent,
                generated_at, created_at
         FROM investigation_playbooks
         WHERE tenant_id = ? AND incident_id = ?",
        tenant_id,
        incident_id
    )
}

pub async fn delete_investigation_playbook(
    pool: &DbPool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "DELETE FROM investigation_playbooks WHERE tenant_id = ? AND incident_id = ?",
        tenant_id,
        incident_id
    )?;
    Ok(())
}

pub async fn insert_investigation_playbook(
    pool: &DbPool,
    record: &InvestigationPlaybookRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO investigation_playbooks
            (id, tenant_id, incident_id, kind, severity, agent_id, summary,
             steps_json, evidence_hints_json, status, investigator_agent,
             generated_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &record.id,
        &record.tenant_id,
        &record.incident_id,
        &record.kind,
        &record.severity,
        &record.agent_id,
        &record.summary,
        &record.steps_json,
        &record.evidence_hints_json,
        &record.status,
        &record.investigator_agent,
        &record.generated_at,
        &record.created_at
    )?;
    Ok(())
}

/// Open incidents missing an investigation playbook, newest first.
pub async fn list_open_incidents_needing_investigation(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
) -> Result<Vec<SocIncidentRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    crate::fetch_all_as!(
        SocIncidentRecord,
        pool,
        "SELECT i.id, i.tenant_id, i.kind, i.severity, i.agent_id, i.summary,
                i.source_event_ids, i.opened_at, i.status, i.closed_at
         FROM soc_incidents i
         LEFT JOIN investigation_playbooks p
           ON p.tenant_id = i.tenant_id AND p.incident_id = i.id
         WHERE i.tenant_id = ? AND i.status = 'open' AND p.id IS NULL
         ORDER BY i.opened_at DESC
         LIMIT ?",
        tenant_id,
        limit
    )
}

/// Agent lifecycle status for investigation context (read-only, tenant-scoped).
pub async fn get_agent_status_for_investigation(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    crate::fetch_optional_scalar!(
        Option<String>,
        pool,
        "SELECT status FROM agents WHERE tenant_id = ? AND id = ?",
        tenant_id,
        agent_id
    )
    .map(|opt| opt.flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::soc::insert_soc_incident;
    use crate::db::tenant::register_tenant;
    use crate::db::test_utils::setup_pool;
    use chrono::Utc;

    #[tokio::test]
    async fn list_open_incidents_needing_investigation_excludes_playbooked() {
        let pool = setup_pool("inv_playbook_list").await;
        let tenant_id = "tenant_inv_pb";
        register_tenant(&pool, tenant_id, "Tenant Inv", "developer")
            .await
            .unwrap();

        let now = Utc::now().to_rfc3339();
        let incident = SocIncidentRecord {
            id: "inc_need_inv".to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "ag_1".to_string(),
            summary: "Repeated denies".to_string(),
            source_event_ids: "[]".to_string(),
            opened_at: now.clone(),
            status: "open".to_string(),
            closed_at: None,
        };
        insert_soc_incident(&pool, &incident).await.unwrap();

        let pending = list_open_incidents_needing_investigation(&pool, tenant_id, 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "inc_need_inv");

        let record = InvestigationPlaybookRecord {
            id: "pb_1".to_string(),
            tenant_id: tenant_id.to_string(),
            incident_id: "inc_need_inv".to_string(),
            kind: incident.kind.clone(),
            severity: incident.severity.clone(),
            agent_id: incident.agent_id.clone(),
            summary: incident.summary.clone(),
            steps_json: "[]".to_string(),
            evidence_hints_json: "{}".to_string(),
            status: "active".to_string(),
            investigator_agent: "template".to_string(),
            generated_at: now.clone(),
            created_at: now,
        };
        insert_investigation_playbook(&pool, &record).await.unwrap();

        let pending2 = list_open_incidents_needing_investigation(&pool, tenant_id, 10)
            .await
            .unwrap();
        assert!(pending2.is_empty());
    }
}
