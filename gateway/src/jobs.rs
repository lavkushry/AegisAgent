//! Background jobs (#0107, #0106): periodic integrity checks and maintenance
//! tasks that run independently of the request path.

use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use tracing::{error, info, warn};
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
pub async fn run_receipt_chain_integrity_job(pool: SqlitePool, interval_secs: u64) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if let Err(e) = check_all_tenant_receipt_chains(&pool).await {
            error!("receipt chain integrity job failed: {:?}", e);
        }
    }
}

/// Run `db::archive_audit_events_older_than` on a fixed interval until the
/// process exits, moving `audit_events` rows older than `retention_days` into
/// `audit_events_archive` (#0106). Intended to be `tokio::spawn`ed once at
/// startup.
pub async fn run_audit_event_archival_job(
    pool: SqlitePool,
    interval_secs: u64,
    retention_days: i64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
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
/// at startup.
pub async fn run_approval_cleanup_job(pool: SqlitePool, interval_secs: u64, retention_days: i64) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        let cutoff = Utc::now() - Duration::days(retention_days);
        match db::delete_expired_approvals_older_than(&pool, cutoff).await {
            Ok(0) => {}
            Ok(n) => info!("deleted {} stale approvals rows older than {}", n, cutoff),
            Err(e) => error!("approval cleanup job failed: {:?}", e),
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
            created_at: Utc::now(),
        };
        rec.receipt_hash = compute_receipt_hash(&rec);
        rec
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
