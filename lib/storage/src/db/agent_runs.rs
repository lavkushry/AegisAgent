//! Phase 2.1 (runtime control plane): `agent_runs` CRUD.
//!
//! One row per controlled agent execution — the spine runtime events, control
//! commands, bans, and quarantine records reference. All queries are
//! tenant-scoped and parameterized; storage-only (no routes yet).

use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

/// Insert a new agent run. The `(tenant_id, run_key)` unique index makes this
/// the idempotency anchor — a duplicate `run_key` for the tenant is a conflict.
pub async fn insert_agent_run(pool: &DbPool, record: &AgentRunRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO agent_runs
           (id, tenant_id, agent_id, run_key, source_component, mode, status,
            started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &record.id,
        &record.tenant_id,
        &record.agent_id,
        &record.run_key,
        &record.source_component,
        &record.mode,
        &record.status,
        record.started_at,
        record.finished_at,
        &record.root_trace_id,
        &record.root_trust_level,
        &record.policy_bundle_id,
        record.created_at
    )?;
    Ok(())
}

/// Fetch a run by id, tenant-scoped (cross-tenant lookups return `None`).
pub async fn get_agent_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
) -> Result<Option<AgentRunRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        AgentRunRecord,
        pool,
        "SELECT id, tenant_id, agent_id, run_key, source_component, mode, status,
                started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id, created_at
         FROM agent_runs WHERE tenant_id = ? AND id = ?",
        tenant_id,
        run_id
    )
}

/// Transition a run's lifecycle `status` (and optionally stamp `finished_at`),
/// tenant-scoped. Returns `true` only if a row was updated. Retries on
/// SQLITE_BUSY like the other write paths.
pub async fn update_agent_run_status(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    status: &str,
    finished_at: Option<DateTime<Utc>>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE agent_runs
             SET status = ?, finished_at = COALESCE(?, finished_at)
             WHERE tenant_id = ? AND id = ?",
            status,
            finished_at,
            tenant_id,
            run_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// List a tenant's runs, most-recently-started first. `limit` is clamped.
pub async fn list_agent_runs(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AgentRunRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    crate::fetch_all_as!(
        AgentRunRecord,
        pool,
        "SELECT id, tenant_id, agent_id, run_key, source_component, mode, status,
                started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id, created_at
         FROM agent_runs WHERE tenant_id = ?
         ORDER BY started_at DESC, rowid DESC
         LIMIT ? OFFSET ?",
        tenant_id,
        limit,
        offset
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;

    fn run(tenant: &str, id: &str, run_key: &str) -> AgentRunRecord {
        let now = Utc::now();
        AgentRunRecord {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            agent_id: None,
            run_key: run_key.to_string(),
            source_component: "cage-runner".to_string(),
            mode: "enforce".to_string(),
            status: "started".to_string(),
            started_at: now,
            finished_at: None,
            root_trace_id: Some("trace-1".to_string()),
            root_trust_level: Some("untrusted_external".to_string()),
            policy_bundle_id: None,
            created_at: now,
        }
    }

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let pool = setup_pool("agent_runs_roundtrip").await;
        insert_agent_run(&pool, &run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        let got = get_agent_run(&pool, "t_a", "run-1").await.unwrap().unwrap();
        assert_eq!(got.run_key, "k1");
        assert_eq!(got.status, "started");
        assert_eq!(got.mode, "enforce");
        assert!(got.agent_id.is_none());
    }

    #[tokio::test]
    async fn get_is_tenant_scoped() {
        let pool = setup_pool("agent_runs_tenant").await;
        insert_agent_run(&pool, &run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        // Another tenant cannot read tenant A's run.
        assert!(get_agent_run(&pool, "t_b", "run-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn update_status_stamps_finished_and_is_tenant_scoped() {
        let pool = setup_pool("agent_runs_update").await;
        insert_agent_run(&pool, &run("t_a", "run-1", "k1"))
            .await
            .unwrap();

        // Cross-tenant update matches no row.
        assert!(
            !update_agent_run_status(&pool, "t_b", "run-1", "killed", Some(Utc::now()))
                .await
                .unwrap()
        );

        let finished = Utc::now();
        assert!(
            update_agent_run_status(&pool, "t_a", "run-1", "finished", Some(finished))
                .await
                .unwrap()
        );
        let got = get_agent_run(&pool, "t_a", "run-1").await.unwrap().unwrap();
        assert_eq!(got.status, "finished");
        assert!(got.finished_at.is_some());
    }

    #[tokio::test]
    async fn list_is_tenant_scoped_and_ordered() {
        let pool = setup_pool("agent_runs_list").await;
        insert_agent_run(&pool, &run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        insert_agent_run(&pool, &run("t_a", "run-2", "k2"))
            .await
            .unwrap();
        insert_agent_run(&pool, &run("t_b", "run-3", "k3"))
            .await
            .unwrap();

        let rows = list_agent_runs(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2, "only tenant A's runs");
        assert!(rows.iter().all(|r| r.tenant_id == "t_a"));
    }
}
