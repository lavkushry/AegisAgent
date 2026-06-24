//! Leader election (REL-003, #1149): SQLite advisory-lock-based leader
//! election so multiple gateway instances sharing one DB don't all run the
//! same periodic background jobs (receipt-chain integrity, audit archival,
//! approval cleanup) concurrently.
//!
//! Global (not tenant-scoped) — same precedent as `schema_meta` for
//! cross-tenant infrastructure state, not tenant-owned data.

use crate::db::DbPool;
use chrono::{DateTime, Utc};

/// `leader_lock` holds exactly one row, identified by this constant.
const LOCK_ID: &str = "singleton";

/// Attempts to become (or renew, if already) the leader. Returns `true` if
/// `instance_id` holds the lease after this call, `false` otherwise.
///
/// Two-step rather than a single `INSERT ... ON CONFLICT DO UPDATE`: the
/// `UPDATE ... WHERE` is the only step that runs once the row exists, and is
/// atomic by construction — it only succeeds (renews/takes over) when this
/// instance already holds the lease or the existing lease has expired,
/// silently affecting zero rows otherwise (another instance holds a live
/// lease), so two instances racing this call can never both believe they're
/// the leader. `INSERT OR IGNORE` only ever matters once, on the very first
/// boot before the row exists at all; if two instances race that, only one
/// insert lands and the other no-ops.
pub async fn try_acquire_or_renew_leadership(
    pool: &DbPool,
    instance_id: &str,
    lease_duration: chrono::Duration,
) -> Result<bool, sqlx::Error> {
    let now = Utc::now();
    let new_expiry = now + lease_duration;

    let renewed = crate::execute_query!(
        pool,
        "UPDATE leader_lock
         SET holder_id = ?,
             lease_expires_at = ?,
             acquired_at = CASE WHEN holder_id = ? THEN acquired_at ELSE ? END
         WHERE id = ? AND (holder_id = ? OR lease_expires_at < ?)",
        instance_id,
        new_expiry,
        instance_id,
        now,
        LOCK_ID,
        instance_id,
        now
    )?;

    if renewed.rows_affected() > 0 {
        return Ok(true);
    }

    // Either no row exists yet (first boot) or another instance holds a
    // live lease. ON CONFLICT DO NOTHING only succeeds in the first case.
    let inserted = crate::execute_query!(
        pool,
        "INSERT INTO leader_lock (id, holder_id, lease_expires_at, acquired_at)
         VALUES (?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
        LOCK_ID,
        instance_id,
        new_expiry,
        now
    )?;

    Ok(inserted.rows_affected() > 0)
}

/// Current leader's id and lease expiry, or `None` if no instance has ever
/// acquired the lock. Read-only introspection — never used to decide
/// leadership itself (see `try_acquire_or_renew_leadership`).
pub async fn current_leader(pool: &DbPool) -> Result<Option<(String, DateTime<Utc>)>, sqlx::Error> {
    let row: Option<(String, DateTime<Utc>)> = crate::fetch_optional_as!(
        (String, DateTime<Utc>),
        pool,
        "SELECT holder_id, lease_expires_at FROM leader_lock WHERE id = ?",
        LOCK_ID
    )?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;

    #[tokio::test]
    async fn first_instance_to_call_becomes_leader() {
        let pool = setup_pool("leader_first").await;

        let is_leader =
            try_acquire_or_renew_leadership(&pool, "instance_a", chrono::Duration::seconds(20))
                .await
                .unwrap();

        assert!(is_leader);
        let (holder, _) = current_leader(&pool).await.unwrap().unwrap();
        assert_eq!(holder, "instance_a");
    }

    #[tokio::test]
    async fn second_instance_does_not_take_over_a_live_lease() {
        let pool = setup_pool("leader_contend").await;

        let a_is_leader =
            try_acquire_or_renew_leadership(&pool, "instance_a", chrono::Duration::seconds(20))
                .await
                .unwrap();
        let b_is_leader =
            try_acquire_or_renew_leadership(&pool, "instance_b", chrono::Duration::seconds(20))
                .await
                .unwrap();

        assert!(a_is_leader);
        assert!(!b_is_leader);
        let (holder, _) = current_leader(&pool).await.unwrap().unwrap();
        assert_eq!(holder, "instance_a");
    }

    #[tokio::test]
    async fn leader_can_renew_its_own_lease() {
        let pool = setup_pool("leader_renew").await;

        try_acquire_or_renew_leadership(&pool, "instance_a", chrono::Duration::seconds(20))
            .await
            .unwrap();
        let (_, first_expiry) = current_leader(&pool).await.unwrap().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let still_leader =
            try_acquire_or_renew_leadership(&pool, "instance_a", chrono::Duration::seconds(20))
                .await
                .unwrap();
        let (holder, second_expiry) = current_leader(&pool).await.unwrap().unwrap();

        assert!(still_leader);
        assert_eq!(holder, "instance_a");
        assert!(
            second_expiry > first_expiry,
            "renewal must extend the lease"
        );
    }

    #[tokio::test]
    async fn another_instance_takes_over_after_lease_expires() {
        let pool = setup_pool("leader_takeover").await;

        // A negative lease duration means the lease is already expired the
        // instant it's written — simulates instance_a having died a while
        // ago, without needing to actually sleep past a real expiry.
        try_acquire_or_renew_leadership(&pool, "instance_a", chrono::Duration::seconds(-1))
            .await
            .unwrap();

        let b_is_leader =
            try_acquire_or_renew_leadership(&pool, "instance_b", chrono::Duration::seconds(20))
                .await
                .unwrap();

        assert!(b_is_leader);
        let (holder, _) = current_leader(&pool).await.unwrap().unwrap();
        assert_eq!(holder, "instance_b");
    }

    #[tokio::test]
    async fn current_leader_returns_none_when_never_acquired() {
        let pool = setup_pool("leader_none").await;
        assert!(current_leader(&pool).await.unwrap().is_none());
    }
}
