//! PR8: durable, multi-instance-safe replay-nonce store.
//!
//! Backs `AEGIS_REPLAY_STORE=db`. The dedup is the `(tenant_id, agent_id, nonce)`
//! primary key on `replay_nonces`; this module's check-and-insert is atomic via
//! `INSERT ... ON CONFLICT DO NOTHING` (the same pattern as the leader lock), so
//! two concurrent gateway instances sharing one database cannot both treat the
//! same nonce as first-seen.

use super::retry_on_busy;
use crate::db::DbPool;
use chrono::{DateTime, Utc};

/// Atomically record a `(tenant, agent, nonce)` triple. Returns `true` if this
/// is a **replay** (the triple was already present and not yet expired), or
/// `false` if it was first-seen now (and recorded with `expires_at`).
///
/// An expired prior row for the same triple is deleted first, so a nonce that
/// has aged past its window is accepted again (matching the in-memory cache's
/// timestamp-window semantics; stale-timestamp requests are already rejected
/// upstream). The `ON CONFLICT DO NOTHING` insert is the atomic source of
/// truth: `rows_affected == 0` means another row already holds the triple →
/// replay.
pub async fn check_and_insert_replay_nonce(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    nonce: &str,
    expires_at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        // Drop an expired prior row for this exact triple so it can be re-seen.
        // (Concurrent true-duplicates are unaffected — neither is expired, so
        // this is a no-op and the insert below decides the winner.)
        crate::execute_query!(
            pool,
            "DELETE FROM replay_nonces
             WHERE tenant_id = ? AND agent_id = ? AND nonce = ? AND expires_at <= ?",
            tenant_id,
            agent_id,
            nonce,
            now
        )?;

        let inserted = crate::execute_query!(
            pool,
            "INSERT INTO replay_nonces (tenant_id, agent_id, nonce, expires_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (tenant_id, agent_id, nonce) DO NOTHING",
            tenant_id,
            agent_id,
            nonce,
            expires_at
        )?;

        // Inserted exactly one row → first-seen (not a replay). Zero rows → the
        // triple already existed and is still live → replay.
        Ok(inserted.rows_affected() == 0)
    })
    .await
}

/// Delete replay-nonce rows whose window has fully elapsed. Returns the number
/// of rows removed. Called by the leader-gated cleanup job; the inline
/// expired-row delete above keeps actively-checked keys tidy, this reclaims
/// space from triples that are never re-checked.
pub async fn delete_expired_replay_nonces(
    pool: &DbPool,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let result =
        crate::execute_query!(pool, "DELETE FROM replay_nonces WHERE expires_at <= ?", now)?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;
    use chrono::Duration;

    async fn check(pool: &DbPool, nonce: &str, expires_at: DateTime<Utc>) -> bool {
        check_and_insert_replay_nonce(pool, "tenant_a", "agent_1", nonce, expires_at)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn first_seen_is_not_replay_then_duplicate_is() {
        let pool = setup_pool("replay_dup").await;
        let exp = Utc::now() + Duration::seconds(300);
        assert!(
            !check(&pool, "n1", exp).await,
            "first sighting is not a replay"
        );
        assert!(check(&pool, "n1", exp).await, "second sighting is a replay");
    }

    /// The DB store is the shared state, so a second logical instance reading the
    /// same pool/database sees the first instance's nonce — replay rejected
    /// across instances/after a restart (mirrors the leader-lock test pattern).
    #[tokio::test]
    async fn replay_detected_across_shared_database() {
        let pool = setup_pool("replay_shared").await;
        let exp = Utc::now() + Duration::seconds(300);
        // "Instance A" records the nonce.
        assert!(!check(&pool, "shared-nonce", exp).await);
        // "Instance B" (same database) must reject the replay.
        assert!(check(&pool, "shared-nonce", exp).await);
    }

    #[tokio::test]
    async fn expired_nonce_is_accepted_again() {
        let pool = setup_pool("replay_expired").await;
        let past = Utc::now() - Duration::seconds(1);
        let future = Utc::now() + Duration::seconds(300);
        // Seen with an already-elapsed window.
        assert!(!check(&pool, "n2", past).await);
        // The window elapsed, so the same nonce is first-seen again, not a replay.
        assert!(!check(&pool, "n2", future).await);
        // ...and now it's live, so an immediate repeat is a replay.
        assert!(check(&pool, "n2", future).await);
    }

    #[tokio::test]
    async fn nonce_is_tenant_and_agent_scoped() {
        let pool = setup_pool("replay_scope").await;
        let exp = Utc::now() + Duration::seconds(300);
        assert!(
            !check_and_insert_replay_nonce(&pool, "tenant_a", "agent_1", "dup", exp)
                .await
                .unwrap()
        );
        // Same nonce string, different agent → not a replay.
        assert!(
            !check_and_insert_replay_nonce(&pool, "tenant_a", "agent_2", "dup", exp)
                .await
                .unwrap()
        );
        // Same nonce string, different tenant → not a replay.
        assert!(
            !check_and_insert_replay_nonce(&pool, "tenant_b", "agent_1", "dup", exp)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn delete_expired_reclaims_only_elapsed_rows() {
        let pool = setup_pool("replay_cleanup").await;
        let _ = check(&pool, "live", Utc::now() + Duration::seconds(300)).await;
        let _ = check(&pool, "stale", Utc::now() - Duration::seconds(1)).await;

        let removed = delete_expired_replay_nonces(&pool, Utc::now())
            .await
            .unwrap();
        assert_eq!(removed, 1, "only the elapsed row is reclaimed");

        // The live nonce is still tracked (replay detected); the stale one is gone
        // (first-seen again).
        assert!(check(&pool, "live", Utc::now() + Duration::seconds(300)).await);
        assert!(!check(&pool, "stale", Utc::now() + Duration::seconds(300)).await);
    }
}
