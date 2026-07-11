//! OIDC console login: `oidc_identities` CRUD. A self-service link between
//! one external identity (issuer + subject, from a verified ID token) and
//! exactly one tenant. `UNIQUE(issuer, subject)` at the DB layer means an
//! identity can only ever be linked to one tenant; `link_oidc_identity`
//! surfaces an existing-but-different mapping as an error rather than
//! silently overwriting it, so a login flow can never be redirected to a
//! different tenant than the one that originally linked that identity.

use crate::db::DbPool;
use aegis_api::models::OidcIdentityRecord;

const COLS: &str = "id, tenant_id, issuer, subject, created_at";

/// Link `(issuer, subject)` to `tenant_id`. Fails with
/// `AlreadyLinkedToAnotherTenant` if that identity is already linked to a
/// *different* tenant (linking again to the *same* tenant is a harmless
/// no-op, so a repeated "Link SSO identity" click is idempotent).
///
/// Attempts the `INSERT` directly rather than checking-then-inserting: the
/// DB's own `UNIQUE(issuer, subject)` constraint is the atomic guard against
/// two concurrent requests linking the same identity to different tenants, a
/// race a separate `SELECT` followed by an `INSERT` cannot close. The
/// (rare) conflict path re-queries only to decide which of the two outcomes
/// above applies.
pub async fn link_oidc_identity(
    pool: &DbPool,
    id: &str,
    tenant_id: &str,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), LinkOidcIdentityError> {
    let insert_result = crate::execute_query!(
        pool,
        "INSERT INTO oidc_identities (id, tenant_id, issuer, subject, created_at)
         VALUES (?, ?, ?, ?, ?)",
        id,
        tenant_id,
        issuer,
        subject,
        now
    );

    match insert_result {
        Ok(_) => Ok(()),
        Err(e) => {
            let is_unique_violation =
                matches!(&e, sqlx::Error::Database(db_err) if db_err.is_unique_violation());
            if !is_unique_violation {
                return Err(LinkOidcIdentityError::Db(e));
            }
            match get_oidc_identity(pool, issuer, subject)
                .await
                .map_err(LinkOidcIdentityError::Db)?
            {
                Some(existing) if existing.tenant_id == tenant_id => Ok(()),
                Some(_) => Err(LinkOidcIdentityError::AlreadyLinkedToAnotherTenant),
                // Extremely unlikely: the unique constraint fired but the
                // conflicting row is gone by the time we re-query (e.g. a
                // concurrent delete). Surface the original DB error rather
                // than a confusing `None`.
                None => Err(LinkOidcIdentityError::Db(e)),
            }
        }
    }
}

#[derive(Debug)]
pub enum LinkOidcIdentityError {
    AlreadyLinkedToAnotherTenant,
    Db(sqlx::Error),
}

/// The hot login-time lookup: which tenant (if any) is `(issuer, subject)`
/// linked to? `None` means fail closed -- the caller must not auto-provision
/// a tenant or guess one.
pub async fn get_oidc_identity(
    pool: &DbPool,
    issuer: &str,
    subject: &str,
) -> Result<Option<OidcIdentityRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM oidc_identities WHERE issuer = ? AND subject = ?");
    crate::fetch_optional_as!(OidcIdentityRecord, pool, sql.as_str(), issuer, subject)
}

/// List a tenant's linked identities (for a future "manage SSO links" UI;
/// tenant-scoped so cross-tenant identities never leak).
pub async fn list_oidc_identities_for_tenant(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<OidcIdentityRecord>, sqlx::Error> {
    let sql =
        format!("SELECT {COLS} FROM oidc_identities WHERE tenant_id = ? ORDER BY created_at DESC");
    crate::fetch_all_as!(OidcIdentityRecord, pool, sql.as_str(), tenant_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;
    use uuid::Uuid;

    #[tokio::test]
    async fn link_then_lookup_round_trips() {
        let pool = setup_pool("oidc_link_lookup").await;
        let id = Uuid::new_v4().to_string();
        link_oidc_identity(
            &pool,
            &id,
            "tenant_a",
            "https://idp.example.com",
            "sub-123",
            chrono::Utc::now(),
        )
        .await
        .unwrap();

        let found = get_oidc_identity(&pool, "https://idp.example.com", "sub-123")
            .await
            .unwrap()
            .expect("identity must be found after linking");
        assert_eq!(found.tenant_id, "tenant_a");

        assert!(
            get_oidc_identity(&pool, "https://idp.example.com", "sub-unknown")
                .await
                .unwrap()
                .is_none(),
            "an unlinked subject must fail closed (None), never auto-provision"
        );
    }

    #[tokio::test]
    async fn relinking_same_tenant_is_a_no_op() {
        let pool = setup_pool("oidc_relink_same").await;
        for _ in 0..2 {
            link_oidc_identity(
                &pool,
                &Uuid::new_v4().to_string(),
                "tenant_a",
                "https://idp.example.com",
                "sub-123",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        }
        let rows = list_oidc_identities_for_tenant(&pool, "tenant_a")
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "re-linking the same identity must not duplicate rows"
        );
    }

    #[tokio::test]
    async fn relinking_to_a_different_tenant_is_rejected() {
        let pool = setup_pool("oidc_relink_different").await;
        link_oidc_identity(
            &pool,
            &Uuid::new_v4().to_string(),
            "tenant_a",
            "https://idp.example.com",
            "sub-123",
            chrono::Utc::now(),
        )
        .await
        .unwrap();

        let result = link_oidc_identity(
            &pool,
            &Uuid::new_v4().to_string(),
            "tenant_b",
            "https://idp.example.com",
            "sub-123",
            chrono::Utc::now(),
        )
        .await;
        assert!(matches!(
            result,
            Err(LinkOidcIdentityError::AlreadyLinkedToAnotherTenant)
        ));
        // Original mapping must be untouched.
        let found = get_oidc_identity(&pool, "https://idp.example.com", "sub-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.tenant_id, "tenant_a");
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let pool = setup_pool("oidc_list_scoped").await;
        link_oidc_identity(
            &pool,
            &Uuid::new_v4().to_string(),
            "tenant_a",
            "https://idp.example.com",
            "sub-a",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        link_oidc_identity(
            &pool,
            &Uuid::new_v4().to_string(),
            "tenant_b",
            "https://idp.example.com",
            "sub-b",
            chrono::Utc::now(),
        )
        .await
        .unwrap();

        let rows = list_oidc_identities_for_tenant(&pool, "tenant_a")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].subject, "sub-a");
    }
}
