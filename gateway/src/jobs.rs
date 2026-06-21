//! Background jobs (#0107, #0106): periodic integrity checks and maintenance
//! tasks that run independently of the request path.

use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::db;
use crate::models::SocAlertRecord;
use crate::routes::compute_receipt_hash;

/// Default interval between receipt chain integrity sweeps.
pub const DEFAULT_INTERVAL_SECS: u64 = 3600;

/// Default interval between audit event archival sweeps.
pub const DEFAULT_AUDIT_ARCHIVAL_INTERVAL_SECS: u64 = 86400;

/// Default audit_events retention window before rows are archived.
pub const DEFAULT_AUDIT_RETENTION_DAYS: i64 = 90;

/// Default interval between approval cleanup sweeps.
pub const DEFAULT_APPROVAL_CLEANUP_INTERVAL_SECS: u64 = 86400;

/// Default approvals retention window before stale rows are deleted.
pub const DEFAULT_APPROVAL_RETENTION_DAYS: i64 = 30;

/// Default interval between leader-election renewal attempts (REL-003,
/// #1149).
pub const DEFAULT_LEADER_ELECTION_INTERVAL_SECS: u64 = 5;

/// Default leader lease duration. Combined with the renewal interval above,
/// worst-case leadership transfer after a leader dies is
/// `lease + election_interval` ≈ 20s + 5s = 25s, under the issue's "within
/// 30s" criterion.
pub const DEFAULT_LEADER_LEASE_SECS: i64 = 20;

/// Walk a chain of receipts (oldest-first) and verify that every
/// `receipt_hash` matches its recomputed value and that `prev_receipt_hash`
/// links form a single unbroken chain starting from the empty string. Returns
/// `Err(reason)` describing the first break found, if any.
///
/// Pure (no DB access) so it can be exercised directly by property-based
/// tests (#1163) without needing a `SqlitePool`.
pub fn verify_chain_records(receipts: &[crate::models::ActionReceiptRecord]) -> Result<(), String> {
    let mut prev = String::new();
    for receipt in receipts {
        if receipt.prev_receipt_hash != prev {
            return Err(format!(
                "receipt {} has prev_receipt_hash '{}' but expected '{}'",
                receipt.id, receipt.prev_receipt_hash, prev
            ));
        }
        let recomputed = compute_receipt_hash(receipt);
        if recomputed != receipt.receipt_hash {
            return Err(format!(
                "receipt {} hash mismatch: stored '{}', recomputed '{}'",
                receipt.id, receipt.receipt_hash, recomputed
            ));
        }
        prev = receipt.receipt_hash.clone();
    }
    Ok(())
}

/// Walk a single tenant's receipt chain (oldest-first) and verify it via
/// [`verify_chain_records`]. Returns `Err(reason)` describing the first break
/// found, if any.
pub async fn verify_tenant_receipt_chain(pool: &SqlitePool, tenant_id: &str) -> Result<(), String> {
    let receipts = db::list_action_receipts_chain_order(pool, tenant_id)
        .await
        .map_err(|e| format!("failed to load receipt chain: {e}"))?;

    verify_chain_records(&receipts)
}

/// Verify the receipt chain for every tenant. Any tenant whose chain fails
/// integrity gets a `critical` SOC alert recorded so it surfaces on
/// `GET /v1/alerts` / the SOC dashboard.
pub async fn check_all_tenant_receipt_chains(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for tenant_id in db::list_all_tenant_ids(pool).await? {
        if let Err(reason) = verify_tenant_receipt_chain(pool, &tenant_id).await {
            warn!(
                "receipt chain integrity check failed for tenant {}: {}",
                tenant_id, reason
            );
            let alert = SocAlertRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                rule: "receipt_chain_integrity_failure".to_string(),
                severity: "critical".to_string(),
                agent_id: "system".to_string(),
                source_event_id: "receipt_chain_integrity_check".to_string(),
                summary: reason,
                created_at: Utc::now().to_rfc3339(),
            };
            db::insert_soc_alert(pool, &alert).await?;
        }
    }
    Ok(())
}

/// Run `check_all_tenant_receipt_chains` on a fixed interval until the process
/// exits. Intended to be `tokio::spawn`ed once at startup.
///
/// `is_leader` gates the actual work (REL-003, #1149): every instance ticks
/// on schedule, but only the current leader runs the check, so multiple
/// instances sharing one DB don't redundantly (and concurrently) sweep the
/// same rows.
pub async fn run_receipt_chain_integrity_job(
    pool: SqlitePool,
    interval_secs: u64,
    is_leader: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if !is_leader.load(Ordering::Relaxed) {
            debug!("receipt chain integrity job: standby (not leader)");
            continue;
        }
        if let Err(e) = check_all_tenant_receipt_chains(&pool).await {
            error!("receipt chain integrity job failed: {:?}", e);
        }
    }
}

/// Run `db::archive_audit_events_older_than` on a fixed interval until the
/// process exits, moving `audit_events` rows older than `retention_days` into
/// `audit_events_archive` (#0106). Intended to be `tokio::spawn`ed once at
/// startup. `is_leader` gates the work — see `run_receipt_chain_integrity_job`.
pub async fn run_audit_event_archival_job(
    pool: SqlitePool,
    interval_secs: u64,
    retention_days: i64,
    is_leader: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if !is_leader.load(Ordering::Relaxed) {
            debug!("audit event archival job: standby (not leader)");
            continue;
        }
        let cutoff = Utc::now() - Duration::days(retention_days);
        match db::archive_audit_events_older_than(&pool, cutoff).await {
            Ok(0) => {}
            Ok(n) => info!("archived {} audit_events rows older than {}", n, cutoff),
            Err(e) => error!("audit event archival job failed: {:?}", e),
        }
    }
}

/// Run `db::delete_expired_approvals_older_than` on a fixed interval until the
/// process exits, removing decided or expired-and-stale `approvals` rows
/// older than `retention_days` (#0105). Intended to be `tokio::spawn`ed once
/// at startup. `is_leader` gates the work — see `run_receipt_chain_integrity_job`.
pub async fn run_approval_cleanup_job(
    pool: SqlitePool,
    interval_secs: u64,
    retention_days: i64,
    is_leader: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if !is_leader.load(Ordering::Relaxed) {
            debug!("approval cleanup job: standby (not leader)");
            continue;
        }
        let cutoff = Utc::now() - Duration::days(retention_days);
        match db::delete_expired_approvals_older_than(&pool, cutoff).await {
            Ok(0) => {}
            Ok(n) => info!("deleted {} stale approvals rows older than {}", n, cutoff),
            Err(e) => error!("approval cleanup job failed: {:?}", e),
        }
    }
}

/// Default interval between database vacuum sweeps (#0061).
pub const DEFAULT_VACUUM_INTERVAL_SECS: u64 = 86400;

/// Run `db::vacuum_database` on a fixed interval until the process exits,
/// reclaiming free space left behind by the audit-event archival (#0106) and
/// approval-cleanup (#0105) jobs' deletes (#0061). Intended to be
/// `tokio::spawn`ed once at startup. `is_leader` gates the work — see
/// `run_receipt_chain_integrity_job` — since a full-file `VACUUM` running
/// concurrently from multiple instances sharing one DB would be wasteful and
/// lock-contentious.
pub async fn run_vacuum_job(pool: SqlitePool, interval_secs: u64, is_leader: Arc<AtomicBool>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if !is_leader.load(Ordering::Relaxed) {
            debug!("vacuum job: standby (not leader)");
            continue;
        }
        let start = std::time::Instant::now();
        match db::vacuum_database(&pool).await {
            Ok(()) => info!("database vacuum completed in {:?}", start.elapsed()),
            Err(e) => error!("database vacuum job failed: {:?}", e),
        }
    }
}

/// Default interval between debounced heartbeat flushes (#1511).
pub const DEFAULT_HEARTBEAT_FLUSH_INTERVAL_SECS: u64 = 30;

/// Drains every pending `(tenant_id, agent_id)` heartbeat from `debouncer`
/// and persists each as a `db::touch_agent_last_seen` write. Pulled out as
/// its own function (rather than inlined in the loop below) so graceful
/// shutdown can call it once more after the periodic loop stops, ensuring no
/// buffered heartbeat is silently dropped on shutdown.
pub async fn flush_heartbeats(pool: &SqlitePool, debouncer: &crate::routes::HeartbeatDebouncer) {
    let pending = debouncer.drain();
    for (tenant_id, agent_id) in pending {
        if let Err(e) = db::touch_agent_last_seen(pool, &tenant_id, &agent_id).await {
            warn!(
                "heartbeat flush failed for tenant={} agent={}: {:?}",
                tenant_id, agent_id, e
            );
        }
    }
}

/// Run [`flush_heartbeats`] on a fixed interval until the process exits.
/// Intended to be `tokio::spawn`ed once at startup.
///
/// Deliberately **not** `is_leader`-gated, unlike the maintenance jobs above:
/// heartbeats are inherently per-instance-observed activity (each gateway
/// instance only ever buffers touches from requests it personally handled),
/// and the write itself is idempotent/commutative — every instance sharing
/// one DB must flush its own buffered touches, or that instance's agents'
/// `last_seen_at` would never advance at all.
pub async fn run_heartbeat_flush_job(
    pool: SqlitePool,
    debouncer: Arc<crate::routes::HeartbeatDebouncer>,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        flush_heartbeats(&pool, &debouncer).await;
    }
}

/// #1286: periodic Splunk HTTP Event Collector (HEC) export. `is_leader`-gated
/// like the other maintenance jobs above — multiple gateway instances sharing
/// one DB must not each forward the same events to Splunk redundantly.
///
/// Loops over every tenant (`db::list_all_tenant_ids`) and queries each one's
/// new decisions/alerts/incidents via the existing tenant-scoped
/// `list_decisions_since`/`list_soc_alerts_since`/`list_soc_incidents_since`
/// — every query stays tenant-filtered even though the job itself is
/// cross-tenant by nature (it's an ops-wide SIEM forwarder, not anything
/// exposed via a tenant-facing API). Per-tenant rowid cursors are in-memory
/// only (reset on restart) — seeded at "current max" the first time a tenant
/// is seen, so a restart never re-floods Splunk with full history, only ever
/// missing whatever arrived in the gap between shutdown and the next tick
/// after startup. All three source types are batched into a single HTTP POST
/// per tick (`splunk_export::dispatch_batch`); cursors only advance after a
/// successful dispatch, so a failed POST retries the exact same window next
/// tick instead of silently dropping events.
pub async fn run_splunk_export_job(
    pool: SqlitePool,
    config: crate::splunk_export::SplunkHecConfig,
    is_leader: Arc<AtomicBool>,
) {
    use crate::splunk_export::{self, SplunkHecConfig};
    use std::collections::HashMap;

    let SplunkHecConfig {
        batch_interval_secs,
        ..
    } = &config;
    let client = reqwest::Client::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(*batch_interval_secs));
    let mut decision_cursors: HashMap<String, i64> = HashMap::new();
    let mut alert_cursors: HashMap<String, i64> = HashMap::new();
    let mut incident_cursors: HashMap<String, i64> = HashMap::new();

    loop {
        interval.tick().await;
        if !is_leader.load(Ordering::Relaxed) {
            debug!("splunk export job: standby (not leader)");
            continue;
        }

        let tenant_ids = match db::list_all_tenant_ids(&pool).await {
            Ok(ids) => ids,
            Err(e) => {
                error!("splunk export: failed to list tenants: {:?}", e);
                continue;
            }
        };

        let mut events = Vec::new();
        let mut decision_advances = Vec::new();
        let mut alert_advances = Vec::new();
        let mut incident_advances = Vec::new();

        for tenant_id in &tenant_ids {
            if !decision_cursors.contains_key(tenant_id) {
                let seed = db::max_decision_rowid(&pool, tenant_id).await.unwrap_or(0);
                decision_cursors.insert(tenant_id.clone(), seed);
            }
            let since = decision_cursors[tenant_id];
            match db::list_decisions_since(&pool, tenant_id, since).await {
                Ok(rows) if !rows.is_empty() => {
                    let max_seen = rows.iter().map(|(_, rowid)| *rowid).max().unwrap_or(since);
                    events.extend(
                        rows.iter()
                            .map(|(rec, _)| splunk_export::decision_to_hec_event(rec)),
                    );
                    decision_advances.push((tenant_id.clone(), max_seen));
                }
                Ok(_) => {}
                Err(e) => error!(
                    "splunk export: failed to list decisions for tenant {}: {:?}",
                    tenant_id, e
                ),
            }

            if !alert_cursors.contains_key(tenant_id) {
                let seed = db::max_soc_alert_rowid(&pool, tenant_id).await.unwrap_or(0);
                alert_cursors.insert(tenant_id.clone(), seed);
            }
            let since = alert_cursors[tenant_id];
            match db::list_soc_alerts_since(&pool, tenant_id, since, None, None).await {
                Ok(rows) if !rows.is_empty() => {
                    let max_seen = rows.iter().map(|(_, rowid)| *rowid).max().unwrap_or(since);
                    events.extend(
                        rows.iter()
                            .map(|(rec, _)| splunk_export::alert_to_hec_event(rec)),
                    );
                    alert_advances.push((tenant_id.clone(), max_seen));
                }
                Ok(_) => {}
                Err(e) => error!(
                    "splunk export: failed to list alerts for tenant {}: {:?}",
                    tenant_id, e
                ),
            }

            if !incident_cursors.contains_key(tenant_id) {
                let seed = db::max_soc_incident_rowid(&pool, tenant_id)
                    .await
                    .unwrap_or(0);
                incident_cursors.insert(tenant_id.clone(), seed);
            }
            let since = incident_cursors[tenant_id];
            match db::list_soc_incidents_since(&pool, tenant_id, since, None, None, None, None)
                .await
            {
                Ok(rows) if !rows.is_empty() => {
                    let max_seen = rows.iter().map(|(_, rowid)| *rowid).max().unwrap_or(since);
                    events.extend(
                        rows.iter()
                            .map(|(rec, _)| splunk_export::incident_to_hec_event(rec)),
                    );
                    incident_advances.push((tenant_id.clone(), max_seen));
                }
                Ok(_) => {}
                Err(e) => error!(
                    "splunk export: failed to list incidents for tenant {}: {:?}",
                    tenant_id, e
                ),
            }
        }

        if events.is_empty() {
            continue;
        }

        match splunk_export::dispatch_batch(&client, &config, &events).await {
            Ok(()) => {
                for (tenant_id, rowid) in decision_advances {
                    decision_cursors.insert(tenant_id, rowid);
                }
                for (tenant_id, rowid) in alert_advances {
                    alert_cursors.insert(tenant_id, rowid);
                }
                for (tenant_id, rowid) in incident_advances {
                    incident_cursors.insert(tenant_id, rowid);
                }
                splunk_export::global_health().record_success();
                debug!("splunk export: delivered {} events", events.len());
            }
            Err(e) => {
                warn!("splunk export: batch dispatch failed, will retry next tick: {e}");
                splunk_export::global_health().record_failure();
            }
        }
    }
}

/// Default interval between DB connection-pool health samples (REL-004, #1150).
pub const DEFAULT_POOL_HEALTH_SAMPLE_INTERVAL_SECS: u64 = 30;

/// Busy-ratio threshold above which `sample_pool_health` logs a warning
/// (REL-004, #1150's "alert threshold" acceptance criterion).
const POOL_BUSY_WARN_THRESHOLD: f64 = 0.8;

/// One DB connection-pool health sample: times a synthetic `pool.acquire()`
/// (released immediately back to the pool) into
/// `metrics.db_pool_acquire_wait`, and logs a warning if the pool is over
/// `POOL_BUSY_WARN_THRESHOLD` busy. A real query call already implicitly
/// acquires a connection on every request; this synthetic probe gives the
/// same acquire-latency signal under current load without instrumenting
/// every one of the codebase's call sites individually.
pub async fn sample_pool_health(
    pool: &SqlitePool,
    metrics: &crate::metrics::SecurityMetrics,
) -> Result<(), sqlx::Error> {
    let start = std::time::Instant::now();
    let conn = pool.acquire().await?;
    metrics.db_pool_acquire_wait.observe(start.elapsed());
    drop(conn); // release back to the pool immediately

    let max_connections = pool.options().get_max_connections();
    if max_connections > 0 {
        let active = pool.size().saturating_sub(pool.num_idle() as u32);
        let busy_ratio = f64::from(active) / f64::from(max_connections);
        if busy_ratio > POOL_BUSY_WARN_THRESHOLD {
            warn!(
                "DB connection pool {:.0}% busy: {}/{} connections active",
                busy_ratio * 100.0,
                active,
                max_connections
            );
        }
    }
    Ok(())
}

/// Run [`sample_pool_health`] on a fixed interval until the process exits.
/// Intended to be `tokio::spawn`ed once at startup.
pub async fn run_pool_health_sampler(
    pool: SqlitePool,
    interval_secs: u64,
    metrics: std::sync::Arc<crate::metrics::SecurityMetrics>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if let Err(e) = sample_pool_health(&pool, &metrics).await {
            error!("pool health sampler failed: {:?}", e);
        }
    }
}

/// Run [`db::try_acquire_or_renew_leadership`] on a fixed interval until the
/// process exits, keeping `is_leader` in sync so the three maintenance jobs
/// above can gate on it (REL-003, #1149). Logs at `info!` only on a
/// leader/standby *transition*, `debug!` on every unchanged tick, to avoid
/// flooding the info log every `interval_secs`.
pub async fn run_leader_election_loop(
    pool: SqlitePool,
    instance_id: String,
    is_leader: Arc<AtomicBool>,
    interval_secs: u64,
    lease_duration: Duration,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    let mut was_leader = false;
    loop {
        interval.tick().await;
        match db::try_acquire_or_renew_leadership(&pool, &instance_id, lease_duration).await {
            Ok(leader_now) => {
                is_leader.store(leader_now, Ordering::Relaxed);
                if leader_now != was_leader {
                    if leader_now {
                        info!("instance {} acquired leadership", instance_id);
                    } else {
                        info!("instance {} lost leadership; standby", instance_id);
                    }
                    was_leader = leader_now;
                } else {
                    debug!(
                        "instance {} leadership status: {}",
                        instance_id,
                        if leader_now { "leader" } else { "standby" }
                    );
                }
            }
            Err(e) => error!("leader election tick failed: {:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ActionReceiptRecord;
    use crate::routes::{compute_receipt_hash, CANON_VERSION};
    use chrono::Utc;
    use uuid::Uuid;

    async fn setup_pool(test_name: &str) -> SqlitePool {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        db::init_db(&db_url).await.unwrap()
    }

    fn make_receipt(tenant_id: &str, prev: String, action: &str) -> ActionReceiptRecord {
        let mut rec = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(Uuid::new_v4().to_string()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some("jobs-test-agent".to_string()),
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("github".to_string()),
            action: Some(action.to_string()),
            resource: None,
            source_trust: "trusted_internal_signed".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some("sha256:deadbeef".to_string()),
            prev_receipt_hash: prev,
            receipt_hash: String::new(),
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: Utc::now(),
        };
        rec.receipt_hash = compute_receipt_hash(&rec);
        rec
    }

    /// #1150: one pass of `sample_pool_health` must record exactly one
    /// `db_pool_acquire_wait` observation.
    #[tokio::test]
    async fn sample_pool_health_records_one_acquire_observation() {
        let pool = setup_pool("pool_health_sample").await;
        let metrics = crate::metrics::SecurityMetrics::new();

        assert_eq!(metrics.db_pool_acquire_wait.average_seconds(), 0.0);
        sample_pool_health(&pool, &metrics).await.unwrap();
        assert_eq!(metrics.db_pool_acquire_wait.count(), 1);

        sample_pool_health(&pool, &metrics).await.unwrap();
        assert_eq!(metrics.db_pool_acquire_wait.count(), 2);
    }

    #[tokio::test]
    async fn intact_chain_passes_verification() {
        let pool = setup_pool("jobs_intact_chain").await;
        db::register_tenant(&pool, "tenant_jobs_ok", "Jobs OK", "developer")
            .await
            .unwrap();

        for i in 0..3 {
            db::append_action_receipt_atomic(&pool, "tenant_jobs_ok", |prev| {
                make_receipt("tenant_jobs_ok", prev, &format!("op_{}", i))
            })
            .await
            .unwrap();
        }

        assert!(verify_tenant_receipt_chain(&pool, "tenant_jobs_ok")
            .await
            .is_ok());

        check_all_tenant_receipt_chains(&pool).await.unwrap();
        let alerts = db::list_soc_alerts(&pool, "tenant_jobs_ok", 50, 0, None, None)
            .await
            .unwrap();
        assert!(alerts
            .iter()
            .all(|a| a.rule != "receipt_chain_integrity_failure"));
    }

    #[tokio::test]
    async fn tampered_chain_is_detected_and_alerted() {
        let pool = setup_pool("jobs_tampered_chain").await;
        db::register_tenant(&pool, "tenant_jobs_bad", "Jobs Bad", "developer")
            .await
            .unwrap();

        db::append_action_receipt_atomic(&pool, "tenant_jobs_bad", |prev| {
            make_receipt("tenant_jobs_bad", prev, "op_0")
        })
        .await
        .unwrap();
        db::append_action_receipt_atomic(&pool, "tenant_jobs_bad", |prev| {
            make_receipt("tenant_jobs_bad", prev, "op_1")
        })
        .await
        .unwrap();

        // Tamper with the first receipt's stored hash directly in the DB.
        sqlx::query("UPDATE action_receipts SET receipt_hash = 'sha256:tampered' WHERE tenant_id = 'tenant_jobs_bad' AND action = 'op_0'")
            .execute(&pool)
            .await
            .unwrap();

        let result = verify_tenant_receipt_chain(&pool, "tenant_jobs_bad").await;
        assert!(result.is_err());

        check_all_tenant_receipt_chains(&pool).await.unwrap();
        let alerts = db::list_soc_alerts(&pool, "tenant_jobs_bad", 50, 0, None, None)
            .await
            .unwrap();
        assert!(alerts
            .iter()
            .any(|a| a.rule == "receipt_chain_integrity_failure" && a.severity == "critical"));
    }

    /// REL-003 (#1149): the sole instance running `run_leader_election_loop`
    /// must acquire leadership (transition `is_leader` to `true`) within a
    /// couple of ticks.
    #[tokio::test]
    async fn leader_election_loop_acquires_leadership_when_alone() {
        let pool = setup_pool("leader_loop_acquire").await;
        let is_leader = Arc::new(AtomicBool::new(false));

        let handle = tokio::spawn(run_leader_election_loop(
            pool,
            "test-instance".to_string(),
            is_leader.clone(),
            1, // tick every 1s — interval.tick() fires immediately on the first poll
            Duration::seconds(20),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(is_leader.load(Ordering::Relaxed));

        handle.abort();
    }

    /// REL-003 (#1149): `run_audit_event_archival_job` must not touch the DB
    /// while `is_leader` is false ("standby"), and must perform the archival
    /// once it becomes true — proving the gate applies to real work, not
    /// just a flag.
    #[tokio::test]
    async fn audit_event_archival_job_is_gated_by_is_leader() {
        let pool = setup_pool("archival_job_gated").await;
        db::register_tenant(&pool, "tenant_archival_gated", "Gated", "developer")
            .await
            .unwrap();

        let old_event = crate::models::AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: "tenant_archival_gated".to_string(),
            event_type: "decision".to_string(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: None,
            action: None,
            resource: None,
            event_json: "{}".to_string(),
            input_hash: None,
            output_hash: None,
            decision_id: None,
            approval_id: None,
            created_at: Utc::now() - Duration::days(200),
        };
        db::insert_audit_event(&pool, &old_event).await.unwrap();

        let is_leader = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(run_audit_event_archival_job(
            pool.clone(),
            1, // tick every 1s
            DEFAULT_AUDIT_RETENTION_DAYS,
            is_leader.clone(),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let still_present: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_events WHERE id = ?")
                .bind(&old_event.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            still_present.0, 1,
            "standby instance must not archive while not leader"
        );

        is_leader.store(true, Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let archived: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events WHERE id = ?")
            .bind(&old_event.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            archived.0, 0,
            "leader instance must archive the old row once leadership is held"
        );

        handle.abort();
    }

    /// Inserts and then deletes `count` audit_events rows with a sizable
    /// `event_json` payload each, leaving behind free (but un-reclaimed)
    /// pages for `db::vacuum_database`/`run_vacuum_job` to measurably shrink.
    async fn churn_audit_events(pool: &SqlitePool, tenant_id: &str, count: usize) {
        let padding = "x".repeat(2000);
        for _ in 0..count {
            let event = crate::models::AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                event_type: "decision".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: None,
                event_json: format!("{{\"padding\":\"{padding}\"}}"),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            };
            db::insert_audit_event(pool, &event).await.unwrap();
        }
        sqlx::query("DELETE FROM audit_events WHERE tenant_id = ?")
            .bind(tenant_id)
            .execute(pool)
            .await
            .unwrap();
    }

    /// #0061 (TASK-0061): `db::vacuum_database` must actually reclaim free
    /// space, not just run without error — proven by shrinking `page_count`
    /// after a bulk insert+delete leaves free pages behind.
    #[tokio::test]
    async fn vacuum_database_reclaims_space_after_bulk_delete() {
        let pool = setup_pool("vacuum_reclaims_space").await;
        db::register_tenant(&pool, "tenant_vacuum", "Vacuum", "developer")
            .await
            .unwrap();

        churn_audit_events(&pool, "tenant_vacuum", 500).await;

        let (page_count_before,): (i64,) = sqlx::query_as("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();

        db::vacuum_database(&pool).await.unwrap();

        let (page_count_after,): (i64,) = sqlx::query_as("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert!(
            page_count_after < page_count_before,
            "expected VACUUM to shrink page_count ({page_count_before} -> {page_count_after})"
        );
    }

    /// REL-003 (#1149): `run_vacuum_job` must not touch the DB while
    /// `is_leader` is false ("standby"), and must perform the vacuum once it
    /// becomes true — proving the gate applies to real work, not just a flag.
    #[tokio::test]
    async fn vacuum_job_is_gated_by_is_leader() {
        let pool = setup_pool("vacuum_job_gated").await;
        db::register_tenant(&pool, "tenant_vacuum_gated", "Vacuum Gated", "developer")
            .await
            .unwrap();

        churn_audit_events(&pool, "tenant_vacuum_gated", 500).await;
        let (page_count_before,): (i64,) = sqlx::query_as("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();

        let is_leader = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(run_vacuum_job(
            pool.clone(),
            1, // tick every 1s
            is_leader.clone(),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let (page_count_standby,): (i64,) = sqlx::query_as("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            page_count_standby, page_count_before,
            "standby instance must not vacuum while not leader"
        );

        is_leader.store(true, Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let (page_count_after,): (i64,) = sqlx::query_as("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            page_count_after < page_count_before,
            "leader instance must vacuum once leadership is held ({page_count_before} -> {page_count_after})"
        );

        handle.abort();
    }

    // ── #1286: Splunk HEC export job ────────────────────────────────────

    async fn register_decision_agent(pool: &SqlitePool, tenant_id: &str) {
        sqlx::query(
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_graph_perf', ?, 'agent_graph_perf', 'token_graph_perf', 'Graph Perf Agent', 'dev', 'low', 'active')",
        )
        .bind(tenant_id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// #1286: the job must batch newly authorized decisions into a single HEC
    /// POST against a real local server, advance its cursor so the same
    /// decision is never re-sent, and pick up a second decision on a later
    /// tick.
    #[tokio::test]
    async fn run_splunk_export_job_delivers_decisions_to_mock_hec_endpoint() {
        use crate::db::test_utils::graph_perf_decision;
        use axum::{routing::post, Router};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        let app = Router::new().route(
            "/services/collector/event",
            post(move |body: String| {
                let received_clone = received_clone.clone();
                async move {
                    received_clone.lock().await.push(body);
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let pool = setup_pool("splunk_export_job").await;
        db::register_tenant(&pool, "tenant_splunk", "Splunk Tenant", "developer")
            .await
            .unwrap();
        register_decision_agent(&pool, "tenant_splunk").await;

        let config = crate::splunk_export::SplunkHecConfig {
            url: format!("http://{addr}"),
            token: "test-hec-token".to_string(),
            batch_interval_secs: 1,
        };
        let is_leader = Arc::new(AtomicBool::new(true));
        let handle = tokio::spawn(crate::jobs::run_splunk_export_job(
            pool.clone(),
            config,
            is_leader.clone(),
        ));

        // The job's first tick only seeds each tenant's cursor at "current
        // max" (so a restart never re-floods Splunk with full history) — it
        // never exports anything that already existed before that first
        // tick. Wait for that seeding tick, then insert the decision under
        // test so it lands strictly after the seeded cursor.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        db::insert_decision(&pool, &graph_perf_decision("dec_splunk_1", "tenant_splunk"))
            .await
            .unwrap();

        let mut batches = Vec::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let snapshot = received.lock().await.clone();
            if !snapshot.is_empty() {
                batches = snapshot;
                break;
            }
        }
        assert_eq!(
            batches.len(),
            1,
            "expected exactly one delivered batch so far"
        );
        assert!(batches[0].contains("dec_splunk_1"));
        assert!(batches[0].contains("aegis:decision"));
        // input_json must never be forwarded to the third-party SIEM.
        assert!(!batches[0].contains("input_json"));

        db::insert_decision(&pool, &graph_perf_decision("dec_splunk_2", "tenant_splunk"))
            .await
            .unwrap();

        let mut second_batch_seen = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let snapshot = received.lock().await.clone();
            if snapshot.len() >= 2 {
                second_batch_seen = true;
                assert!(snapshot[1].contains("dec_splunk_2"));
                assert!(
                    !snapshot[1].contains("dec_splunk_1"),
                    "already-delivered decision must not be re-sent"
                );
                break;
            }
        }
        assert!(
            second_batch_seen,
            "expected a second delivered batch for the new decision"
        );

        handle.abort();
    }

    /// #1286: like the other maintenance jobs, a standby instance must never
    /// dispatch to Splunk while `is_leader` is false.
    #[tokio::test]
    async fn run_splunk_export_job_is_gated_by_is_leader() {
        use crate::db::test_utils::graph_perf_decision;
        use axum::{routing::post, Router};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let hit_count = Arc::new(Mutex::new(0u32));
        let hit_count_clone = hit_count.clone();
        let app = Router::new().route(
            "/services/collector/event",
            post(move || {
                let hit_count_clone = hit_count_clone.clone();
                async move {
                    *hit_count_clone.lock().await += 1;
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let pool = setup_pool("splunk_export_job_gated").await;
        db::register_tenant(
            &pool,
            "tenant_splunk_gated",
            "Splunk Gated Tenant",
            "developer",
        )
        .await
        .unwrap();
        register_decision_agent(&pool, "tenant_splunk_gated").await;

        let config = crate::splunk_export::SplunkHecConfig {
            url: format!("http://{addr}"),
            token: "test-hec-token".to_string(),
            batch_interval_secs: 1,
        };
        let is_leader = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(crate::jobs::run_splunk_export_job(
            pool.clone(),
            config,
            is_leader.clone(),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert_eq!(
            *hit_count.lock().await,
            0,
            "standby instance must not dispatch to Splunk while not leader"
        );

        is_leader.store(true, Ordering::Relaxed);
        // Same cursor-seeding caveat as the happy-path test above: the first
        // leader tick only seeds the cursor, so insert the decision under
        // test after giving it time to pass.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        db::insert_decision(
            &pool,
            &graph_perf_decision("dec_splunk_gated_1", "tenant_splunk_gated"),
        )
        .await
        .unwrap();

        let mut dispatched = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            if *hit_count.lock().await >= 1 {
                dispatched = true;
                break;
            }
        }
        assert!(
            dispatched,
            "leader instance must dispatch once leadership is held"
        );

        handle.abort();
    }

    // ── #1511: heartbeat flush job ──────────────────────────────────────

    /// #1511: a heartbeat buffered via `HeartbeatDebouncer::touch` is not
    /// written to the DB until `run_heartbeat_flush_job`'s periodic tick —
    /// and, unlike the maintenance jobs above, flushing happens **regardless**
    /// of `is_leader`, since each instance must flush the touches it
    /// personally buffered.
    #[tokio::test]
    async fn run_heartbeat_flush_job_writes_buffered_touch_on_first_tick() {
        let pool = setup_pool("heartbeat_flush_job").await;
        db::register_tenant(&pool, "tenant_hb", "Heartbeat Tenant", "developer")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_hb', 'tenant_hb', 'agent_hb', 'token_hb', 'Heartbeat Agent', 'dev', 'low', 'active')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let debouncer = Arc::new(crate::routes::HeartbeatDebouncer::new());
        debouncer.touch("tenant_hb", "agent_hb");

        // Deliberately never set to true — proves the flush isn't gated on
        // leadership the way the other jobs in this file are.
        let handle = tokio::spawn(crate::jobs::run_heartbeat_flush_job(
            pool.clone(),
            debouncer.clone(),
            1,
        ));

        let mut flushed = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            if debouncer.pending_count() == 0 {
                flushed = true;
                break;
            }
        }
        assert!(
            flushed,
            "expected the first tick to drain the buffered touch"
        );

        let (last_seen_at,): (Option<String>,) =
            sqlx::query_as("SELECT last_seen_at FROM agents WHERE id = 'agent_hb'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(last_seen_at.is_some());

        handle.abort();
    }
}

/// Property-based tests for `verify_chain_records` (#1163 / TEST-003).
///
/// These generate random but internally-consistent receipt chains (built with
/// real `compute_receipt_hash` calls) and check two invariants:
///  1. An intact chain always verifies as `Ok`.
///  2. A chain with exactly one tampered receipt (bad `receipt_hash`, bad
///     `prev_receipt_hash`, or a body field mutated post-hash) always
///     verifies as `Err`.
#[cfg(test)]
mod chain_proptests {
    use super::verify_chain_records;
    use crate::models::ActionReceiptRecord;
    use crate::routes::{compute_receipt_hash, CANON_VERSION};
    use chrono::Utc;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn action_strategy() -> impl Strategy<Value = String> {
        "[a-z_]{3,12}"
    }

    fn decision_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("allow".to_string()),
            Just("deny".to_string()),
            Just("require_approval".to_string()),
        ]
    }

    fn source_trust_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("trusted_internal_signed".to_string()),
            Just("trusted_internal_unsigned".to_string()),
            Just("semi_trusted_customer".to_string()),
            Just("untrusted_external".to_string()),
            Just("malicious_suspected".to_string()),
            Just("unknown".to_string()),
        ]
    }

    fn seed_strategy() -> impl Strategy<Value = (String, String, String)> {
        (
            action_strategy(),
            decision_strategy(),
            source_trust_strategy(),
        )
    }

    fn chain_seeds_strategy() -> impl Strategy<Value = Vec<(String, String, String)>> {
        proptest::collection::vec(seed_strategy(), 1..=10)
    }

    /// Build a chain of receipts whose `prev_receipt_hash`/`receipt_hash`
    /// links are computed for real via `compute_receipt_hash`, so the chain
    /// is internally consistent by construction.
    fn build_chain(
        seeds: &[(String, String, String)],
        tenant_id: &str,
    ) -> Vec<ActionReceiptRecord> {
        let mut chain = Vec::with_capacity(seeds.len());
        let mut prev = String::new();
        for (action, decision, source_trust) in seeds {
            let mut rec = ActionReceiptRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                decision_id: Some(Uuid::new_v4().to_string()),
                ts: Utc::now().to_rfc3339(),
                agent_id: Some("proptest-agent".to_string()),
                user_id: None,
                run_id: None,
                trace_id: None,
                tool: Some("github".to_string()),
                action: Some(action.clone()),
                resource: None,
                source_trust: source_trust.clone(),
                decision: decision.clone(),
                approver: None,
                action_hash: Some("sha256:deadbeef".to_string()),
                prev_receipt_hash: prev.clone(),
                receipt_hash: String::new(),
                canon_version: CANON_VERSION.to_string(),
                signature: None,
                signer_public_key: None,
                signer_key_id: None,
                created_at: Utc::now(),
            };
            rec.receipt_hash = compute_receipt_hash(&rec);
            prev = rec.receipt_hash.clone();
            chain.push(rec);
        }
        chain
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1000, .. ProptestConfig::default() })]

        /// Any chain built by `build_chain` is internally consistent and
        /// must verify as `Ok`.
        #[test]
        fn intact_chain_always_verifies(seeds in chain_seeds_strategy()) {
            let chain = build_chain(&seeds, "tenant_proptest_intact");
            prop_assert!(verify_chain_records(&chain).is_ok());
        }

        /// Tampering with exactly one receipt's `receipt_hash`,
        /// `prev_receipt_hash`, or a hashed body field must always be
        /// detected.
        #[test]
        fn tampered_chain_always_fails(
            seeds in chain_seeds_strategy(),
            idx_seed in any::<usize>(),
            tamper_kind in 0u8..3,
        ) {
            let mut chain = build_chain(&seeds, "tenant_proptest_tampered");
            let idx = idx_seed % chain.len();
            match tamper_kind {
                0 => {
                    chain[idx].receipt_hash = format!("sha256:tampered-{}", chain[idx].receipt_hash);
                }
                1 => {
                    chain[idx].prev_receipt_hash =
                        format!("sha256:bogus-prev-{}", chain[idx].prev_receipt_hash);
                }
                _ => {
                    let action = chain[idx].action.clone().unwrap_or_default();
                    chain[idx].action = Some(format!("{}-tampered", action));
                }
            }
            prop_assert!(verify_chain_records(&chain).is_err());
        }
    }
}
