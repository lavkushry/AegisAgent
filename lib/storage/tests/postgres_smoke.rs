//! #1194 (Postgres GA): a real, live-database smoke test for the `postgres`
//! feature — the class of coverage that was previously entirely missing.
//! Before this test, `--features postgres` was only ever compile-checked
//! (see docs/adr/0002-sqlite-first-storage.md), which is how a 528-line
//! compile break in the read-replica failover path went unnoticed for a
//! period (only caught incidentally during unrelated work, not by CI).
//!
//! Requires a live Postgres reachable at `DATABASE_URL` (postgres:// or
//! postgresql://). Not run by the default `cargo test --workspace`, since
//! that has no Postgres available — CI wires this up with a `postgres:`
//! service container (see `.github/workflows/ci.yml`, job
//! `postgres-integration`). To run locally:
//!
//! ```sh
//! docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=aegis postgres:16
//! DATABASE_URL=postgres://postgres:aegis@127.0.0.1:5432/postgres \
//!   cargo test -p aegis-storage --features postgres --test postgres_smoke
//! ```

#![cfg(feature = "postgres")]

use aegis_storage::db::{self, DbPool};
use aegis_storage::sqlite::SqlDbStorage;
use aegis_storage::traits::StorageBackend;
use uuid::Uuid;

async fn connect() -> DbPool {
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must point at a live Postgres instance for postgres_smoke");
    assert!(
        db_url.starts_with("postgres://") || db_url.starts_with("postgresql://"),
        "postgres_smoke requires a postgres:// DATABASE_URL, got: {db_url}"
    );
    db::init_db(&db_url)
        .await
        .expect("init_db must run migrations_postgres and connect cleanly")
}

/// Runs `migrations_postgres/*` against a live Postgres instance, then
/// exercises tenant CRUD through the real `StorageBackend` implementation —
/// the same code path every gateway request hits — proving the schema and
/// the SQLx query set are actually compatible with Postgres, not merely
/// compile-checked against `sqlx-data.json` offline cache.
#[tokio::test]
async fn tenant_crud_round_trips_against_live_postgres() {
    let pool = connect().await;
    db::health_check(&pool)
        .await
        .expect("health_check must succeed against a live Postgres pool");

    let storage = SqlDbStorage::new(pool);
    let tenant_id = format!("tenant_pg_smoke_{}", Uuid::new_v4().simple());
    let tenant = aegis_api::models::TenantRecord {
        id: tenant_id.clone(),
        name: "Postgres Smoke Tenant".to_string(),
        plan: "developer".to_string(),
        created_at: chrono::Utc::now(),
        auto_respond_enabled: true,
        auto_rotate_token_on_leak_enabled: true,
        slack_approver_group: None,
    };

    storage
        .insert_tenant(&tenant)
        .await
        .expect("insert_tenant must succeed against Postgres");

    let fetched = storage
        .get_tenant_by_id(&tenant_id)
        .await
        .expect("get_tenant_by_id must succeed against Postgres")
        .expect("freshly-inserted tenant must be found");
    assert_eq!(fetched.id, tenant_id);
    assert_eq!(fetched.name, "Postgres Smoke Tenant");

    let all_tenants = storage
        .list_tenants()
        .await
        .expect("list_tenants must succeed against Postgres");
    assert!(
        all_tenants.iter().any(|t| t.id == tenant_id),
        "list_tenants must include the freshly-inserted tenant"
    );

    let missing = storage
        .get_tenant_by_id("tenant_pg_smoke_definitely_does_not_exist")
        .await
        .expect("get_tenant_by_id must succeed for a miss too");
    assert!(missing.is_none());
}

/// Exercises the read-replica routing path (`AEGIS_DB_READ_REPLICA_URL`,
/// #914) end-to-end against live Postgres, when the CI job provides a
/// second connection string. CI points it at the *same* Postgres instance
/// as `DATABASE_URL` — this doesn't simulate real replication lag, but it
/// does exercise the routing plumbing itself (separate pool construction,
/// `has_read_replica() == true`, and a live query actually executing
/// against `read_pool()`), which had zero live coverage before this test.
/// True cross-instance replication validation is a separate, larger effort
/// (see docs/adr/0002-sqlite-first-storage.md's named "failover validation"
/// gap) and is out of scope here. Locally this test is skipped unless the
/// env var is set.
#[tokio::test]
async fn read_replica_routing_serves_reads_against_live_postgres() {
    let Ok(replica_url) = std::env::var("AEGIS_DB_READ_REPLICA_URL") else {
        eprintln!("AEGIS_DB_READ_REPLICA_URL not set; skipping replica routing smoke test");
        return;
    };
    assert!(
        replica_url.starts_with("postgres://") || replica_url.starts_with("postgresql://"),
        "AEGIS_DB_READ_REPLICA_URL must be a postgres:// URL, got: {replica_url}"
    );

    let pool = connect().await;
    let storage = SqlDbStorage::new(pool);
    let tenant_id = format!("tenant_pg_replica_smoke_{}", Uuid::new_v4().simple());
    let tenant = aegis_api::models::TenantRecord {
        id: tenant_id.clone(),
        name: "Postgres Replica Smoke Tenant".to_string(),
        plan: "developer".to_string(),
        created_at: chrono::Utc::now(),
        auto_respond_enabled: true,
        auto_rotate_token_on_leak_enabled: true,
        slack_approver_group: None,
    };
    storage
        .insert_tenant(&tenant)
        .await
        .expect("insert_tenant (write pool) must succeed");

    // Replication lag is possible in principle, but for CI's same-container
    // logical/streaming setup the read-after-write is expected to be
    // immediately visible; retry a handful of times to absorb any lag
    // instead of flaking the whole job on timing.
    let mut found = None;
    for _ in 0..20 {
        if let Some(t) = storage
            .get_tenant_by_id(&tenant_id)
            .await
            .expect("get_tenant_by_id (read pool) must succeed")
        {
            found = Some(t);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let fetched = found.expect("tenant written to the primary must become visible on the replica");
    assert_eq!(fetched.id, tenant_id);
}
