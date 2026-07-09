//! Phase 2.1 (runtime control plane): `agent_runs` CRUD.
//!
//! One row per controlled agent execution — the spine runtime events, control
//! commands, bans, and quarantine records reference. All queries are
//! tenant-scoped and parameterized; storage-only (no routes yet).
//!
//! aegis-cage-runner execution loop: a subset of runs (those created with
//! `CreateAgentRunRequest.cage_spec` set) carry the full `SandboxSpec` fields
//! (`image_ref`, `command_json`, etc.) and go through an atomic claim/
//! heartbeat/status-transition lifecycle so exactly one runner instance ever
//! executes a given run. Non-cage runs (the pre-existing, more common case)
//! never populate those columns and are completely unaffected by the new
//! functions below.

use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

const AGENT_RUN_COLUMNS: &str = "id, tenant_id, agent_id, run_key, source_component, mode, status,
                started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id,
                claimed_by, claimed_at, last_heartbeat_at, image_ref, image_digest, command_json,
                working_dir, resource_limits_json, network_spec_json, tooling_spec_json,
                environment_json, workspace_spec_json, controlled_mounts_json, exit_code, created_at";

/// Insert a new agent run. The `(tenant_id, run_key)` unique index makes this
/// the idempotency anchor — a duplicate `run_key` for the tenant is a conflict.
pub async fn insert_agent_run(pool: &DbPool, record: &AgentRunRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO agent_runs
           (id, tenant_id, agent_id, run_key, source_component, mode, status,
            started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id,
            claimed_by, claimed_at, last_heartbeat_at, image_ref, image_digest, command_json,
            working_dir, resource_limits_json, network_spec_json, tooling_spec_json,
            environment_json, workspace_spec_json, controlled_mounts_json, exit_code, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        &record.claimed_by,
        record.claimed_at,
        record.last_heartbeat_at,
        &record.image_ref,
        &record.image_digest,
        &record.command_json,
        &record.working_dir,
        &record.resource_limits_json,
        &record.network_spec_json,
        &record.tooling_spec_json,
        &record.environment_json,
        &record.workspace_spec_json,
        &record.controlled_mounts_json,
        record.exit_code,
        record.created_at
    )?;
    Ok(())
}

/// Insert a cage-execution run and its signed `start_run` control command
/// atomically: a run is either fully registered along with a way for a
/// runner to discover it, or not created at all — never an orphan of
/// either. `BEGIN IMMEDIATE`/`pool.begin()` mirrors
/// `receipts::append_action_receipt_atomic`'s exact dual-backend shape.
/// `start_command` is `None` for a non-cage run (plain insert, same as
/// `insert_agent_run` — kept as a separate function since the vast
/// majority of callers need no transaction at all).
pub async fn insert_agent_run_with_start_command(
    pool: &DbPool,
    run: &AgentRunRecord,
    start_command: Option<&ControlCommandRecord>,
) -> Result<(), sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            let mut conn = p.acquire().await?;
            sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

            async fn rollback(conn: &mut sqlx::SqliteConnection) {
                let _ = sqlx::query("ROLLBACK").execute(conn).await;
            }

            if let Err(e) = insert_agent_run_stmt(&mut conn, run).await {
                rollback(&mut conn).await;
                return Err(e);
            }
            if let Some(cmd) = start_command {
                if let Err(e) = insert_control_command_stmt(&mut conn, cmd).await {
                    rollback(&mut conn).await;
                    return Err(e);
                }
            }
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pools) => {
            let p = pools.write_pool();
            let mut tx = p.begin().await?;
            insert_agent_run_stmt_pg(&mut tx, run).await?;
            if let Some(cmd) = start_command {
                insert_control_command_stmt_pg(&mut tx, cmd).await?;
            }
            tx.commit().await?;
            Ok(())
        }
    }
}

async fn insert_agent_run_stmt(
    conn: &mut sqlx::SqliteConnection,
    record: &AgentRunRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agent_runs
           (id, tenant_id, agent_id, run_key, source_component, mode, status,
            started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id,
            claimed_by, claimed_at, last_heartbeat_at, image_ref, image_digest, command_json,
            working_dir, resource_limits_json, network_spec_json, tooling_spec_json,
            environment_json, workspace_spec_json, controlled_mounts_json, exit_code, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.agent_id)
    .bind(&record.run_key)
    .bind(&record.source_component)
    .bind(&record.mode)
    .bind(&record.status)
    .bind(record.started_at)
    .bind(record.finished_at)
    .bind(&record.root_trace_id)
    .bind(&record.root_trust_level)
    .bind(&record.policy_bundle_id)
    .bind(&record.claimed_by)
    .bind(record.claimed_at)
    .bind(record.last_heartbeat_at)
    .bind(&record.image_ref)
    .bind(&record.image_digest)
    .bind(&record.command_json)
    .bind(&record.working_dir)
    .bind(&record.resource_limits_json)
    .bind(&record.network_spec_json)
    .bind(&record.tooling_spec_json)
    .bind(&record.environment_json)
    .bind(&record.workspace_spec_json)
    .bind(&record.controlled_mounts_json)
    .bind(record.exit_code)
    .bind(record.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn insert_control_command_stmt(
    conn: &mut sqlx::SqliteConnection,
    c: &ControlCommandRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO control_commands
           (command_id, tenant_id, target_type, target_id, action, reason, issued_by,
            issued_at, expires_at, nonce, requires_ack, receipt_required, signature, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&c.command_id)
    .bind(&c.tenant_id)
    .bind(&c.target_type)
    .bind(&c.target_id)
    .bind(&c.action)
    .bind(&c.reason)
    .bind(&c.issued_by)
    .bind(c.issued_at)
    .bind(c.expires_at)
    .bind(&c.nonce)
    .bind(c.requires_ack)
    .bind(c.receipt_required)
    .bind(&c.signature)
    .bind(&c.status)
    .bind(c.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn insert_agent_run_stmt_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: &AgentRunRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agent_runs
           (id, tenant_id, agent_id, run_key, source_component, mode, status,
            started_at, finished_at, root_trace_id, root_trust_level, policy_bundle_id,
            claimed_by, claimed_at, last_heartbeat_at, image_ref, image_digest, command_json,
            working_dir, resource_limits_json, network_spec_json, tooling_spec_json,
            environment_json, workspace_spec_json, controlled_mounts_json, exit_code, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
                 $19, $20, $21, $22, $23, $24, $25, $26, $27)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.agent_id)
    .bind(&record.run_key)
    .bind(&record.source_component)
    .bind(&record.mode)
    .bind(&record.status)
    .bind(record.started_at)
    .bind(record.finished_at)
    .bind(&record.root_trace_id)
    .bind(&record.root_trust_level)
    .bind(&record.policy_bundle_id)
    .bind(&record.claimed_by)
    .bind(record.claimed_at)
    .bind(record.last_heartbeat_at)
    .bind(&record.image_ref)
    .bind(&record.image_digest)
    .bind(&record.command_json)
    .bind(&record.working_dir)
    .bind(&record.resource_limits_json)
    .bind(&record.network_spec_json)
    .bind(&record.tooling_spec_json)
    .bind(&record.environment_json)
    .bind(&record.workspace_spec_json)
    .bind(&record.controlled_mounts_json)
    .bind(record.exit_code)
    .bind(record.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn insert_control_command_stmt_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    c: &ControlCommandRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO control_commands
           (command_id, tenant_id, target_type, target_id, action, reason, issued_by,
            issued_at, expires_at, nonce, requires_ack, receipt_required, signature, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(&c.command_id)
    .bind(&c.tenant_id)
    .bind(&c.target_type)
    .bind(&c.target_id)
    .bind(&c.action)
    .bind(&c.reason)
    .bind(&c.issued_by)
    .bind(c.issued_at)
    .bind(c.expires_at)
    .bind(&c.nonce)
    .bind(c.requires_ack)
    .bind(c.receipt_required)
    .bind(&c.signature)
    .bind(&c.status)
    .bind(c.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Fetch a run by id, tenant-scoped (cross-tenant lookups return `None`).
pub async fn get_agent_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
) -> Result<Option<AgentRunRecord>, sqlx::Error> {
    let sql = format!("SELECT {AGENT_RUN_COLUMNS} FROM agent_runs WHERE tenant_id = ? AND id = ?");
    crate::fetch_optional_as!(AgentRunRecord, pool, &sql, tenant_id, run_id)
}

/// Transition a run's lifecycle `status` (and optionally stamp `finished_at`),
/// tenant-scoped. Returns `true` only if a row was updated. Retries on
/// SQLITE_BUSY like the other write paths.
///
/// Unlike `update_claimed_agent_run_status` below, this is NOT
/// ownership-scoped by `claimed_by` — used only by `quarantine_run`, which is
/// gateway-authoritative and must land even if no runner ever cooperates.
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

/// Atomically claim a cage run: `started` -> `claimed`. `Ok(true)` iff this
/// call won the race — a single conditional `UPDATE` is already atomic in
/// both SQLite and Postgres, so no explicit transaction is needed for this
/// single-statement compare-and-swap. `image_ref IS NOT NULL` is
/// defense-in-depth (a non-cage run never gets a `start_run` command in the
/// first place, so this should never matter in practice, but it means a
/// runner can never claim a run that has no `SandboxSpec` to execute).
pub async fn claim_agent_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    runner_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE agent_runs
             SET status = 'claimed', claimed_by = ?, claimed_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'started' AND image_ref IS NOT NULL",
            runner_id,
            now,
            tenant_id,
            run_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// Refresh the lease on a claimed/running run. `Ok(false)` means the caller
/// no longer holds the claim (lost to a stall-sweep reclaim, or never held
/// it, or the run has already reached a terminal status) — the runner must
/// treat this as "stop, I don't own this anymore."
pub async fn heartbeat_agent_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    runner_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE agent_runs
             SET last_heartbeat_at = ?
             WHERE tenant_id = ? AND id = ? AND claimed_by = ? AND status IN ('claimed', 'running')",
            now,
            tenant_id,
            run_id,
            runner_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// Transition a run's status, but only while `runner_id` still holds the
/// claim — an ownership-scoped variant of `update_agent_run_status` for the
/// cage-runner's own status reports (`running`/`paused`/`finished`/`killed`/
/// `stalled`). `Ok(false)` means the caller has lost (or never held) the
/// claim.
pub async fn update_claimed_agent_run_status(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    runner_id: &str,
    status: &str,
    finished_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE agent_runs
             SET status = ?,
                 finished_at = COALESCE(?, finished_at),
                 exit_code = COALESCE(?, exit_code)
             WHERE tenant_id = ? AND id = ? AND claimed_by = ?",
            status,
            finished_at,
            exit_code,
            tenant_id,
            run_id,
            runner_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// Global (cross-tenant) lease-expiry sweep, mirroring the existing
/// `delete_expired_replay_nonces` global-sweep precedent — a claimed/running
/// run whose lease (`last_heartbeat_at`, or `claimed_at` before the first
/// heartbeat) is older than `threshold` is flipped to `stalled` so an
/// operator can see it's stuck. Deliberately does NOT auto-requeue the run
/// (resuming a possibly-partially-executed action is itself a security
/// decision). Returns the number of rows flipped.
pub async fn mark_stale_agent_runs_stalled(
    pool: &DbPool,
    threshold: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE agent_runs
             SET status = 'stalled'
             WHERE status IN ('claimed', 'running')
               AND COALESCE(last_heartbeat_at, claimed_at) < ?",
            threshold
        )?;
        Ok(result.rows_affected())
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
    let sql = format!(
        "SELECT {AGENT_RUN_COLUMNS} FROM agent_runs WHERE tenant_id = ?
         ORDER BY started_at DESC, rowid DESC
         LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(AgentRunRecord, pool, &sql, tenant_id, limit, offset)
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
            claimed_by: None,
            claimed_at: None,
            last_heartbeat_at: None,
            image_ref: None,
            image_digest: None,
            command_json: None,
            working_dir: None,
            resource_limits_json: None,
            network_spec_json: None,
            tooling_spec_json: None,
            environment_json: None,
            workspace_spec_json: None,
            controlled_mounts_json: None,
            exit_code: None,
            created_at: now,
        }
    }

    /// A cage-eligible run: has `image_ref` set, so `claim_agent_run`'s
    /// `image_ref IS NOT NULL` guard doesn't reject it.
    fn cage_run(tenant: &str, id: &str, run_key: &str) -> AgentRunRecord {
        AgentRunRecord {
            image_ref: Some("alpine:latest".to_string()),
            command_json: Some(r#"["sleep","1"]"#.to_string()),
            ..run(tenant, id, run_key)
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
        assert!(got.claimed_by.is_none());
        assert!(got.image_ref.is_none());
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

    #[tokio::test]
    async fn claim_succeeds_once_and_transitions_to_claimed() {
        let pool = setup_pool("agent_runs_claim_once").await;
        insert_agent_run(&pool, &cage_run("t_a", "run-1", "k1"))
            .await
            .unwrap();

        let now = Utc::now();
        assert!(claim_agent_run(&pool, "t_a", "run-1", "runner-1", now)
            .await
            .unwrap());

        let got = get_agent_run(&pool, "t_a", "run-1").await.unwrap().unwrap();
        assert_eq!(got.status, "claimed");
        assert_eq!(got.claimed_by.as_deref(), Some("runner-1"));
        assert!(got.claimed_at.is_some());
    }

    #[tokio::test]
    async fn second_claim_attempt_on_same_run_fails() {
        let pool = setup_pool("agent_runs_claim_second").await;
        insert_agent_run(&pool, &cage_run("t_a", "run-1", "k1"))
            .await
            .unwrap();

        assert!(
            claim_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
                .await
                .unwrap()
        );
        // A second runner (or a retry from the same one) must lose.
        assert!(
            !claim_agent_run(&pool, "t_a", "run-1", "runner-2", Utc::now())
                .await
                .unwrap()
        );
        let got = get_agent_run(&pool, "t_a", "run-1").await.unwrap().unwrap();
        assert_eq!(
            got.claimed_by.as_deref(),
            Some("runner-1"),
            "the second attempt must not have overwritten the first claimant"
        );
    }

    #[tokio::test]
    async fn claim_rejects_a_run_with_no_image_ref() {
        let pool = setup_pool("agent_runs_claim_no_image").await;
        // A plain (non-cage) run has no image_ref -- must never be claimable.
        insert_agent_run(&pool, &run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        assert!(
            !claim_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn concurrent_claim_attempts_only_one_wins() {
        let pool = setup_pool("agent_runs_claim_concurrent").await;
        insert_agent_run(&pool, &cage_run("t_a", "run-1", "k1"))
            .await
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                claim_agent_run(&pool, "t_a", "run-1", &format!("runner-{i}"), Utc::now())
                    .await
                    .unwrap()
            }));
        }
        let mut wins = 0;
        for h in handles {
            if h.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one concurrent claim attempt must win");
    }

    #[tokio::test]
    async fn heartbeat_fails_for_a_run_this_runner_never_claimed() {
        let pool = setup_pool("agent_runs_heartbeat_wrong_owner").await;
        insert_agent_run(&pool, &cage_run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        claim_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
            .await
            .unwrap();

        assert!(
            !heartbeat_agent_run(&pool, "t_a", "run-1", "runner-2", Utc::now())
                .await
                .unwrap()
        );
        assert!(
            heartbeat_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn heartbeat_fails_once_status_is_terminal() {
        let pool = setup_pool("agent_runs_heartbeat_terminal").await;
        insert_agent_run(&pool, &cage_run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        claim_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
            .await
            .unwrap();
        update_claimed_agent_run_status(
            &pool,
            "t_a",
            "run-1",
            "runner-1",
            "finished",
            None,
            Some(0),
        )
        .await
        .unwrap();

        assert!(
            !heartbeat_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
                .await
                .unwrap(),
            "a finished run must not accept a heartbeat"
        );
        assert_eq!(
            get_agent_run(&pool, "t_a", "run-1")
                .await
                .unwrap()
                .unwrap()
                .exit_code,
            Some(0)
        );
    }

    #[tokio::test]
    async fn update_claimed_status_rejects_a_non_claimant() {
        let pool = setup_pool("agent_runs_status_non_claimant").await;
        insert_agent_run(&pool, &cage_run("t_a", "run-1", "k1"))
            .await
            .unwrap();
        claim_agent_run(&pool, "t_a", "run-1", "runner-1", Utc::now())
            .await
            .unwrap();

        assert!(!update_claimed_agent_run_status(
            &pool, "t_a", "run-1", "runner-2", "running", None, None
        )
        .await
        .unwrap());
        assert!(update_claimed_agent_run_status(
            &pool, "t_a", "run-1", "runner-1", "running", None, None
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn mark_stale_agent_runs_stalled_only_touches_expired_claimed_or_running_rows() {
        let pool = setup_pool("agent_runs_stall_sweep").await;

        // Fresh claim -- must NOT be touched.
        insert_agent_run(&pool, &cage_run("t_a", "run-fresh", "k-fresh"))
            .await
            .unwrap();
        claim_agent_run(&pool, "t_a", "run-fresh", "runner-1", Utc::now())
            .await
            .unwrap();

        // Stale claim -- must flip to stalled.
        let stale_time = Utc::now() - chrono::Duration::seconds(300);
        insert_agent_run(&pool, &cage_run("t_a", "run-stale", "k-stale"))
            .await
            .unwrap();
        claim_agent_run(&pool, "t_a", "run-stale", "runner-2", stale_time)
            .await
            .unwrap();

        // Stale but already finished -- must NOT be touched.
        insert_agent_run(&pool, &cage_run("t_a", "run-finished", "k-finished"))
            .await
            .unwrap();
        claim_agent_run(&pool, "t_a", "run-finished", "runner-3", stale_time)
            .await
            .unwrap();
        update_claimed_agent_run_status(
            &pool,
            "t_a",
            "run-finished",
            "runner-3",
            "finished",
            None,
            Some(0),
        )
        .await
        .unwrap();

        let threshold = Utc::now() - chrono::Duration::seconds(120);
        let flipped = mark_stale_agent_runs_stalled(&pool, threshold)
            .await
            .unwrap();
        assert_eq!(flipped, 1);

        assert_eq!(
            get_agent_run(&pool, "t_a", "run-fresh")
                .await
                .unwrap()
                .unwrap()
                .status,
            "claimed"
        );
        assert_eq!(
            get_agent_run(&pool, "t_a", "run-stale")
                .await
                .unwrap()
                .unwrap()
                .status,
            "stalled"
        );
        assert_eq!(
            get_agent_run(&pool, "t_a", "run-finished")
                .await
                .unwrap()
                .unwrap()
                .status,
            "finished"
        );
    }

    fn start_run_command(tenant: &str, run_id: &str, command_id: &str) -> ControlCommandRecord {
        let now = Utc::now();
        ControlCommandRecord {
            command_id: command_id.to_string(),
            tenant_id: tenant.to_string(),
            target_type: "run".to_string(),
            target_id: run_id.to_string(),
            action: "start_run".to_string(),
            reason: None,
            issued_by: "gateway".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(3600),
            nonce: uuid::Uuid::new_v4().to_string(),
            requires_ack: true,
            receipt_required: false,
            signature: "ed25519:deadbeef".to_string(),
            status: "issued".to_string(),
            created_at: now,
        }
    }

    #[tokio::test]
    async fn insert_agent_run_with_start_command_is_all_or_nothing_on_duplicate_run_key() {
        let pool = setup_pool("agent_runs_atomic_dual_insert").await;
        let run1 = cage_run("t_a", "run-1", "dup-key");
        let cmd1 = start_run_command("t_a", "run-1", "cmd-1");
        insert_agent_run_with_start_command(&pool, &run1, Some(&cmd1))
            .await
            .unwrap();

        // A second run reusing the same run_key must roll back BOTH inserts.
        let run2 = cage_run("t_a", "run-2", "dup-key");
        let cmd2 = start_run_command("t_a", "run-2", "cmd-2");
        assert!(
            insert_agent_run_with_start_command(&pool, &run2, Some(&cmd2))
                .await
                .is_err()
        );

        assert!(get_agent_run(&pool, "t_a", "run-2")
            .await
            .unwrap()
            .is_none());
        assert!(
            crate::db::control_commands::get_control_command(&pool, "t_a", &cmd2.command_id)
                .await
                .unwrap()
                .is_none(),
            "the run-2 insert failing must roll back its control command too -- no orphan"
        );
    }
}
