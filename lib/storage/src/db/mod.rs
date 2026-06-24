use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum DbPool {
    Sqlite(SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
}

impl DbPool {
    pub fn is_postgres(&self) -> bool {
        match self {
            Self::Sqlite(_) => false,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => true,
        }
    }

    pub fn sqlite_pool(&self) -> &SqlitePool {
        match self {
            Self::Sqlite(p) => p,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => panic!("Expected SQLite pool, found Postgres"),
        }
    }

    pub fn num_idle(&self) -> u32 {
        match self {
            Self::Sqlite(p) => p.num_idle() as u32,
            #[cfg(feature = "postgres")]
            Self::Postgres(p) => p.num_idle() as u32,
        }
    }

    pub fn size(&self) -> u32 {
        match self {
            Self::Sqlite(p) => p.size(),
            #[cfg(feature = "postgres")]
            Self::Postgres(p) => p.size(),
        }
    }

    pub fn get_pool_metrics(&self) -> (u32, u32) {
        match self {
            Self::Sqlite(p) => {
                let idle = p.num_idle() as u32;
                let size = p.size();
                (idle, size.saturating_sub(idle))
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(p) => {
                let idle = p.num_idle() as u32;
                let size = p.size();
                (idle, size.saturating_sub(idle))
            }
        }
    }

    pub async fn close(&self) {
        match self {
            Self::Sqlite(p) => p.close().await,
            #[cfg(feature = "postgres")]
            Self::Postgres(p) => p.close().await,
        }
    }

    pub fn max_connections(&self) -> u32 {
        match self {
            Self::Sqlite(p) => p.options().get_max_connections(),
            #[cfg(feature = "postgres")]
            Self::Postgres(p) => p.options().get_max_connections(),
        }
    }

    pub async fn acquire(&self) -> Result<DbPoolConnection, sqlx::Error> {
        match self {
            Self::Sqlite(p) => p.acquire().await.map(DbPoolConnection::Sqlite),
            #[cfg(feature = "postgres")]
            Self::Postgres(p) => p.acquire().await.map(DbPoolConnection::Postgres),
        }
    }
}

pub enum DbPoolConnection {
    Sqlite(sqlx::pool::PoolConnection<sqlx::Sqlite>),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::pool::PoolConnection<sqlx::Postgres>),
}

#[derive(Debug)]
pub enum DbQueryResult {
    Sqlite(sqlx::sqlite::SqliteQueryResult),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::postgres::PgQueryResult),
}

impl DbQueryResult {
    pub fn rows_affected(&self) -> u64 {
        match self {
            Self::Sqlite(r) => r.rows_affected(),
            #[cfg(feature = "postgres")]
            Self::Postgres(r) => r.rows_affected(),
        }
    }
}

pub fn to_postgres_sql(sql: &str) -> String {
    let mut sql_str = sql.to_string();
    if sql_str.contains("INSERT OR IGNORE INTO leader_lock") {
        sql_str = sql_str.replace(
            "INSERT OR IGNORE INTO leader_lock",
            "INSERT INTO leader_lock",
        );
        sql_str.push_str(" ON CONFLICT (id) DO NOTHING");
    } else if sql_str.contains("INSERT OR IGNORE INTO agent_tool_permissions") {
        sql_str = sql_str.replace(
            "INSERT OR IGNORE INTO agent_tool_permissions",
            "INSERT INTO agent_tool_permissions",
        );
        sql_str.push_str(" ON CONFLICT (tenant_id, agent_id, tool_key) DO NOTHING");
    }

    // Convert datetime functions
    sql_str = sql_str.replace(
        "datetime('now', '-24 hours')",
        "NOW() - INTERVAL '24 hours'",
    );
    sql_str = sql_str.replace(
        "datetime('now', '-48 hours')",
        "NOW() - INTERVAL '48 hours'",
    );
    sql_str = sql_str.replace(
        "datetime('now', '-30 hours')",
        "NOW() - INTERVAL '30 hours'",
    );
    sql_str = sql_str.replace("datetime('now', '-7 days')", "NOW() - INTERVAL '7 days'");
    sql_str = sql_str.replace(
        "strftime('%Y-%m-%dT%H', datetime('now', '-7 days'))",
        "to_char(NOW() - INTERVAL '7 days', 'YYYY-MM-DD\"T\"HH24')",
    );

    // Convert FTS MATCH operator
    sql_str = sql_str.replace("searchable_text MATCH ?", "searchable_text ILIKE ?");

    // Convert parameter placeholders ? to $1, $2, etc.
    let mut result = String::new();
    let mut param_index = 1;
    let chars = sql_str.chars().peekable();
    for c in chars {
        if c == '?' {
            result.push_str(&format!("${}", param_index));
            param_index += 1;
        } else {
            result.push(c);
        }
    }
    result
}

#[macro_export]
macro_rules! execute_query {
    ($pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query($sql)
                    $(.bind($bind))*
                    .execute(p)
                    .await
                    .map($crate::db::DbQueryResult::Sqlite)
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query(&pg_sql)
                    $(.bind($bind))*
                    .execute(p)
                    .await
                    .map($crate::db::DbQueryResult::Postgres)
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_optional {
    ($pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query($sql)
                    $(.bind($bind))*
                    .fetch_optional(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query(&pg_sql)
                    $(.bind($bind))*
                    .fetch_optional(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_all {
    ($pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query($sql)
                    $(.bind($bind))*
                    .fetch_all(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query(&pg_sql)
                    $(.bind($bind))*
                    .fetch_all(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_one {
    ($pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query($sql)
                    $(.bind($bind))*
                    .fetch_one(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query(&pg_sql)
                    $(.bind($bind))*
                    .fetch_one(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_one_as {
    ($ty:ty, $pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query_as::<_, $ty>($sql)
                    $(.bind($bind))*
                    .fetch_one(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query_as::<_, $ty>(&pg_sql)
                    $(.bind($bind))*
                    .fetch_one(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_optional_as {
    ($ty:ty, $pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query_as::<_, $ty>($sql)
                    $(.bind($bind))*
                    .fetch_optional(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query_as::<_, $ty>(&pg_sql)
                    $(.bind($bind))*
                    .fetch_optional(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_all_as {
    ($ty:ty, $pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query_as::<_, $ty>($sql)
                    $(.bind($bind))*
                    .fetch_all(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query_as::<_, $ty>(&pg_sql)
                    $(.bind($bind))*
                    .fetch_all(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_one_scalar {
    ($ty:ty, $pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query_scalar::<_, $ty>($sql)
                    $(.bind($bind))*
                    .fetch_one(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query_scalar::<_, $ty>(&pg_sql)
                    $(.bind($bind))*
                    .fetch_one(p)
                    .await
            }
        }
    };
}

#[macro_export]
macro_rules! fetch_optional_scalar {
    ($ty:ty, $pool:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
        match &$pool {
            $crate::db::DbPool::Sqlite(p) => {
                sqlx::query_scalar::<_, $ty>($sql)
                    $(.bind($bind))*
                    .fetch_optional(p)
                    .await
            }
            #[cfg(feature = "postgres")]
            $crate::db::DbPool::Postgres(p) => {
                let pg_sql = $crate::db::to_postgres_sql($sql);
                sqlx::query_scalar::<_, $ty>(&pg_sql)
                    $(.bind($bind))*
                    .fetch_optional(p)
                    .await
            }
        }
    };
}

// Submodules
pub mod agents;
pub mod approvals;
pub mod decisions;
pub mod leader;
pub mod mcp;
pub mod playbooks;
pub mod policies;
pub mod receipts;
pub mod soc;
pub mod tenant;
pub mod webhooks;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-exports
pub use agents::*;
pub use approvals::*;
pub use decisions::*;
pub use leader::*;
pub use mcp::*;
pub use playbooks::*;
pub use policies::*;
pub use receipts::*;
pub use soc::*;
pub use tenant::*;
pub use webhooks::*;

/// The schema version this binary expects (DB-005, #1195).
///
/// Bumped whenever a migration changes the schema in a way that an older
/// binary could not safely operate on. [`run_migrations`] writes this value
/// into `schema_meta` after migrations run; [`check_schema_version`] refuses
/// to start (fail closed) if the on-disk version is *newer* than this binary
/// understands — running an older binary against a newer DB has undefined
/// results.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

/// Liveness/readiness ping for the `/health` endpoint: a trivial `SELECT 1`
/// that confirms the pool can acquire a connection and the store answers.
/// Returns `Err` (fail-closed) on any pool/query failure.
pub async fn health_check(pool: &DbPool) -> Result<(), sqlx::Error> {
    fetch_one_scalar!(i64, pool, "SELECT 1").map(|_| ())
}

/// Returns `true` if `err` is a transient SQLite "database is locked"
/// (`SQLITE_BUSY`, code 5) or "table is locked" (`SQLITE_LOCKED`, code 6)
/// error — both are safe to retry, unlike e.g. constraint violations.
fn is_retryable_sqlite_busy(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => matches!(db_err.code().as_deref(), Some("5") | Some("6")),
        _ => false,
    }
}

/// Run a write operation, retrying up to `max_retries` additional times with
/// exponential backoff (1ms, 2ms, 4ms, ...) if it fails with a transient
/// `SQLITE_BUSY`/`SQLITE_LOCKED` error (#1151). Non-retryable errors and the
/// final attempt's error propagate immediately. Each retry is logged at
/// DEBUG level.
pub async fn retry_on_busy<F, Fut, T>(max_retries: u32, mut f: F) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempt = 0;
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < max_retries && is_retryable_sqlite_busy(&e) => {
                let delay_ms = 1u64 << attempt;
                tracing::debug!(
                    "retrying after SQLITE_BUSY/LOCKED (attempt {}/{}, backoff {}ms): {}",
                    attempt + 1,
                    max_retries,
                    delay_ms,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Default page size for `list_soc_alerts` / `list_soc_incidents`.
pub const SOC_DEFAULT_LIMIT: i64 = 50;
/// Hard cap to prevent accidentally returning enormous result sets.
pub const SOC_MAX_LIMIT: i64 = 200;
/// Per-poll batch cap for `GET /v1/alerts|incidents?watch=true` (#1146)'s
/// forward-watch queries — bounds how many new rows one SSE poll tick can
/// push at once.
pub const SOC_WATCH_BATCH_LIMIT: i64 = 100;

/// #1142: maps a fetched page of `SqliteRow`s (each carrying a trailing
/// `rowid` column, selected explicitly by every cursor-paginated query) into
/// `(items, next_cursor)`. Callers must fetch `limit + 1` rows (one more than
/// the page size) — that extra row is never returned to the client but its
/// presence is what tells us a next page exists; truncating to `limit` and
/// checking `rows.len() >= limit` instead would wrongly emit a next-cursor
/// whenever the result set ends exactly on a page boundary (off-by-one).
pub(crate) fn paginate_rows<T, R>(
    mut rows: Vec<R>,
    limit: i64,
) -> Result<(Vec<T>, Option<i64>), sqlx::Error>
where
    R: sqlx::Row,
    T: for<'r> sqlx::FromRow<'r, R>,
    usize: sqlx::ColumnIndex<R>,
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: sqlx::Type<R::Database> + for<'r> sqlx::Decode<'r, R::Database>,
{
    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        rows.last()
            .map(|r| r.try_get::<i64, _>("rowid"))
            .transpose()?
    } else {
        None
    };
    let items = rows
        .iter()
        .map(T::from_row)
        .collect::<Result<Vec<T>, _>>()?;
    Ok((items, next_cursor))
}

/// #1192: when `encryption_key_configured` is true (i.e. `AEGIS_DB_ENCRYPTION_KEY`
/// was set), confirms the connection is actually backed by a SQLCipher-enabled
/// SQLite — `PRAGMA cipher_version` returns SQLCipher's version string when
/// active, and an empty result set on a plain SQLite build (an unrecognized
/// pragma is a silent no-op there, never an error). Returns an error in that
/// mismatch case rather than starting up with an operator-requested
/// encryption key silently ignored. A no-op when encryption wasn't requested.
async fn verify_encryption_or_fail_closed(
    pool: &SqlitePool,
    encryption_key_configured: bool,
) -> Result<(), sqlx::Error> {
    if !encryption_key_configured {
        return Ok(());
    }
    let cipher_version: Vec<(Option<String>,)> = sqlx::query_as("PRAGMA cipher_version;")
        .fetch_all(pool)
        .await?;
    let cipher_active = matches!(cipher_version.first(), Some((Some(_),)));
    if !cipher_active {
        return Err(sqlx::Error::Configuration(
            "AEGIS_DB_ENCRYPTION_KEY is set, but this binary was not built with the \
             `sqlcipher` Cargo feature. PRAGMA key would be silently ignored and the \
             database would NOT be encrypted at rest. Refusing to start. Rebuild with \
             `--features sqlcipher`, or unset AEGIS_DB_ENCRYPTION_KEY."
                .into(),
        ));
    }
    Ok(())
}

/// Default per-connection prepared-statement LRU cache capacity — mirrors
/// sqlx-sqlite's own built-in default. Overridable via
/// `AEGIS_DB_STATEMENT_CACHE_CAPACITY`.
pub const DEFAULT_STATEMENT_CACHE_CAPACITY: usize = 100;

/// Read `AEGIS_DB_STATEMENT_CACHE_CAPACITY`, falling back to
/// [`DEFAULT_STATEMENT_CACHE_CAPACITY`]. Unlike batch/interval env vars
/// elsewhere, `0` is a valid, meaningful value here (disables statement
/// caching) rather than being filtered out.
pub fn statement_cache_capacity_from_env() -> usize {
    std::env::var("AEGIS_DB_STATEMENT_CACHE_CAPACITY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_STATEMENT_CACHE_CAPACITY)
}

pub async fn init_db(db_url: &str) -> Result<DbPool, sqlx::Error> {
    init_db_with_busy_timeout(db_url, std::time::Duration::from_secs(5)).await
}

pub async fn init_db_with_busy_timeout(
    db_url: &str,
    busy_timeout: std::time::Duration,
) -> Result<DbPool, sqlx::Error> {
    if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
        #[cfg(feature = "postgres")]
        {
            sqlx::any::install_default_drivers();

            let max_connections = std::env::var("AEGIS_DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(5);

            let idle_timeout = std::env::var("AEGIS_DB_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30);

            let acquire_timeout = std::env::var("AEGIS_DB_ACQUIRE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);

            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(max_connections)
                .idle_timeout(std::time::Duration::from_secs(idle_timeout))
                .acquire_timeout(std::time::Duration::from_secs(acquire_timeout))
                .connect(db_url)
                .await?;

            sqlx::migrate!("./migrations_postgres")
                .run(&pool)
                .await
                .map_err(|e| sqlx::Error::Protocol(format!("migration failed: {e}")))?;

            // Initialize schema version
            sqlx::query("INSERT INTO schema_meta (version) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(CURRENT_SCHEMA_VERSION)
                .execute(&pool)
                .await?;

            Ok(DbPool::Postgres(pool))
        }
        #[cfg(not(feature = "postgres"))]
        {
            Err(sqlx::Error::Configuration(
                "PostgreSQL feature not enabled".into(),
            ))
        }
    } else {
        let pool = init_sqlite_db_with_busy_timeout(db_url, busy_timeout).await?;
        Ok(DbPool::Sqlite(pool))
    }
}

async fn init_sqlite_db_with_busy_timeout(
    db_url: &str,
    busy_timeout: std::time::Duration,
) -> Result<SqlitePool, sqlx::Error> {
    // #1192: database encryption at rest. `SqliteConnectOptions` reserves the
    // "key" pragma slot FIRST in its internal pragma list specifically for
    // SQLCipher (see sqlx-sqlite's `SqliteConnectOptions::new()`), so it is
    // always emitted before journal_mode/foreign_keys/etc regardless of
    // builder call order here — required, since SQLCipher must decrypt the
    // first page before any other statement can touch the database file.
    let encryption_key = std::env::var("AEGIS_DB_ENCRYPTION_KEY").ok();

    // Enforce WAL mode and busy timeout on pool initialization
    let mut connection_options = sqlx::sqlite::SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(busy_timeout)
        // #0098: enforce FK constraints on every connection (SQLite defaults
        // this off per-connection; without it, ON DELETE/UPDATE actions and
        // referential integrity checks declared in the schema are silently
        // not enforced).
        .foreign_keys(true);
    if let Some(ref key) = encryption_key {
        // `.pragma()` splices the value into `PRAGMA key = <value>;` verbatim
        // (no auto-quoting — it's also used for unquoted idents like
        // `journal_mode=WAL`), so a raw passphrase must be quoted ourselves;
        // otherwise e.g. a hyphen is parsed as SQL subtraction, not a string.
        let quoted_key = format!("'{}'", key.replace('\'', "''"));
        connection_options = connection_options.pragma("key", quoted_key);
    }

    let max_connections = std::env::var("AEGIS_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(5);

    let idle_timeout = std::env::var("AEGIS_DB_IDLE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);

    let acquire_timeout = std::env::var("AEGIS_DB_ACQUIRE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);

    // #906: each pooled connection keeps its own LRU cache of prepared
    // statements (sqlx-sqlite's default capacity is 100); the hot-path
    // queries in routes/authorize.rs and routes/authorize_decision.rs are
    // identical across requests modulo bound parameters, so a warm cache
    // skips SQLite's parse/plan step on every repeat. Explicitly configured
    // (rather than left at sqlx's built-in default) so it's tunable per
    // deployment without a code change — e.g. lower on memory-constrained
    // hosts, `0` to disable caching entirely for debugging.
    connection_options =
        connection_options.statement_cache_capacity(statement_cache_capacity_from_env());

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .idle_timeout(std::time::Duration::from_secs(idle_timeout))
        .acquire_timeout(std::time::Duration::from_secs(acquire_timeout))
        .connect_with(connection_options)
        .await?;

    // #1192: fail closed if encryption was requested but can't actually be
    // honored. Without the `sqlcipher` Cargo feature, the linked SQLite is
    // plain SQLite, which silently treats an unrecognized "key" pragma as a
    // no-op (per SQLite's documented behavior for unknown pragmas) — the
    // operator would believe their database is encrypted when it is not.
    verify_encryption_or_fail_closed(&pool, encryption_key.is_some()).await?;

    // Performance tuning PRAGMAs for SQLite WAL mode autocheckpointing
    sqlx::query("PRAGMA journal_size_limit = 67108864;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA synchronous = NORMAL;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA wal_autocheckpoint = 1000;")
        .execute(&pool)
        .await?;

    // Bring any pre-existing database (created by older binaries via the
    // legacy ad-hoc bootstrap, before DB-001/#1191) up to the schema that
    // `migrations/0001_baseline.sql` expects. On a fresh database this also
    // creates the full schema. Either way, every table/column/index this
    // function creates is also declared (with `IF NOT EXISTS`) in
    // `migrations/0001_baseline.sql`, so the migration below is a no-op that
    // simply records "0001_baseline" as applied.
    bootstrap_legacy_schema(&pool).await?;

    // DB-001 (#1191): sqlx versioned migrations, tracked in `_sqlx_migrations`.
    // All schema changes from here on ship as new files in `gateway/migrations/`
    // (via `sqlx migrate add`) rather than new `ensure_*` helpers above.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("migration failed: {e}")))?;

    migrate_agent_tokens(&DbPool::Sqlite(pool.clone())).await?;

    check_schema_version(&pool).await?;

    Ok(pool)
}

/// Legacy ad-hoc schema bootstrap (pre-DB-001/#1191). Brings any database —
/// fresh or pre-existing — up to the schema captured in
/// `migrations/0001_baseline.sql`, so that `sqlx::migrate!()` (called right
/// after this in [`init_db`]) is always a no-op for the baseline migration.
/// Kept for backward compatibility with databases created by older binaries
/// that predate the `_sqlx_migrations` table; do not add new schema changes
/// here — add a new file under `gateway/migrations/` instead.
async fn bootstrap_legacy_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            plan TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .execute(pool)
    .await?;

    ensure_tenants_auto_respond_column(pool).await?;
    ensure_tenants_soc_autonomy_level_column(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            agent_key TEXT NOT NULL,
            agent_token TEXT NOT NULL,
            name TEXT NOT NULL,
            owner_team TEXT,
            owner_email TEXT,
            environment TEXT NOT NULL,
            framework TEXT,
            model_provider TEXT,
            model_name TEXT,
            purpose TEXT,
            risk_tier TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            UNIQUE (tenant_id, agent_key),
            UNIQUE (tenant_id, agent_token)
        );",
    )
    .execute(pool)
    .await?;

    ensure_agents_lifecycle_columns(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS skills (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            skill_key TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            auth_type TEXT,
            owner_team TEXT,
            default_risk TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            UNIQUE (tenant_id, skill_key)
        );",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS skill_actions (
            id TEXT PRIMARY KEY,
            skill_id TEXT NOT NULL,
            action_key TEXT NOT NULL,
            description TEXT,
            risk TEXT NOT NULL,
            mutates_state BOOLEAN NOT NULL DEFAULT 0,
            data_access TEXT,
            approval_required BOOLEAN NOT NULL DEFAULT 0,
            default_decision TEXT NOT NULL DEFAULT 'policy',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (skill_id) REFERENCES skills(id),
            UNIQUE (skill_id, action_key)
        );",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mcp_servers (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            server_key TEXT NOT NULL,
            name TEXT NOT NULL,
            owner_team TEXT,
            transport TEXT NOT NULL,
            source TEXT,
            trust_level TEXT NOT NULL,
            endpoint TEXT NOT NULL DEFAULT '',
            version TEXT,
            status TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            UNIQUE (tenant_id, server_key)
        );",
    )
    .execute(pool)
    .await?;

    ensure_mcp_server_endpoint_column(pool).await?;
    ensure_mcp_server_manifest_hash_column(pool).await?;
    ensure_mcp_server_inspection_enabled_column(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mcp_tools (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            server_id TEXT NOT NULL,
            tool_key TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            input_schema TEXT,
            risk TEXT NOT NULL,
            mutates_state BOOLEAN NOT NULL DEFAULT 0,
            approval_required BOOLEAN NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            FOREIGN KEY (server_id) REFERENCES mcp_servers(id),
            UNIQUE (tenant_id, server_id, tool_key)
        );",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            policy_key TEXT NOT NULL,
            name TEXT NOT NULL,
            language TEXT NOT NULL,
            body TEXT NOT NULL,
            version INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_by TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            UNIQUE (tenant_id, policy_key, version)
        );",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS decisions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            user_id TEXT,
            run_id TEXT,
            trace_id TEXT,
            skill TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT,
            input_json TEXT NOT NULL,
            decision TEXT NOT NULL,
            risk_score INTEGER,
            reason TEXT,
            matched_policy_ids TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        );",
    )
    .execute(pool)
    .await?;

    ensure_decisions_request_id_column(pool).await?;
    ensure_decisions_latency_ms_column(pool).await?;
    ensure_decisions_composite_risk_score_column(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            status TEXT NOT NULL,
            approver_group TEXT,
            approver_user_id TEXT,
            reason TEXT,
            original_skill_call TEXT NOT NULL,
            original_call_hash TEXT NOT NULL DEFAULT '',
            edited_skill_call TEXT,
            expires_at DATETIME,
            decided_at DATETIME,
            consumed_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            FOREIGN KEY (decision_id) REFERENCES decisions(id)
        );",
    )
    .execute(pool)
    .await?;

    ensure_approval_original_call_hash_column(pool).await?;
    ensure_approval_consumed_at_column(pool).await?;
    ensure_approval_callback_columns(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            agent_id TEXT,
            user_id TEXT,
            run_id TEXT,
            trace_id TEXT,
            span_id TEXT,
            skill TEXT,
            action TEXT,
            resource TEXT,
            event_json TEXT NOT NULL,
            input_hash TEXT,
            output_hash TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );",
    )
    .execute(pool)
    .await?;

    // #0106: archive table for old audit_events rows, identical schema (minus
    // the FK, since archived rows must outlive any later tenant deletion).
    // Populated by `archive_audit_events_older_than`.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_events_archive (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            agent_id TEXT,
            user_id TEXT,
            run_id TEXT,
            trace_id TEXT,
            span_id TEXT,
            skill TEXT,
            action TEXT,
            resource TEXT,
            event_json TEXT NOT NULL,
            input_hash TEXT,
            output_hash TEXT,
            created_at DATETIME NOT NULL,
            archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_archive_tenant ON audit_events_archive (tenant_id);",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS action_receipts (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            decision_id TEXT,
            ts TEXT NOT NULL,
            agent_id TEXT,
            user_id TEXT,
            run_id TEXT,
            trace_id TEXT,
            tool TEXT,
            action TEXT,
            resource TEXT,
            source_trust TEXT NOT NULL,
            decision TEXT NOT NULL,
            approver TEXT,
            action_hash TEXT,
            prev_receipt_hash TEXT NOT NULL,
            receipt_hash TEXT NOT NULL,
            canon_version TEXT NOT NULL DEFAULT '',
            signature TEXT,
            signer_public_key TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );",
    )
    .execute(pool)
    .await?;

    ensure_action_receipts_canon_version_column(pool).await?;

    // Create indexes for tenant_id to guarantee sub-millisecond query performance
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_skills_tenant ON skills (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_mcp_tools_tenant_server ON mcp_tools (tenant_id, server_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_decisions_tenant ON decisions (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approvals (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events (tenant_id);")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant ON action_receipts (tenant_id);",
    )
    .execute(pool)
    .await?;

    // Composite indexes matching the hot tenant-scoped list/query paths so the
    // filtered + `ORDER BY created_at DESC` listings stay index-driven instead of
    // table-scanning. Column order = filter prefix, then the sort column.
    // (#940) list_decisions: WHERE tenant_id [AND agent_id] [AND decision] ORDER BY created_at DESC
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_decisions_tenant_agent_created ON decisions (tenant_id, agent_id, created_at);",
    )
    .execute(pool)
    .await?;
    // (#941) list_pending_approvals: WHERE tenant_id AND status ORDER BY created_at DESC
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_approvals_tenant_status_created ON approvals (tenant_id, status, created_at);",
    )
    .execute(pool)
    .await?;
    // (#942) audit_events: WHERE tenant_id [AND event_type] ORDER BY created_at
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_type_created ON audit_events (tenant_id, event_type, created_at);",
    )
    .execute(pool)
    .await?;
    // (#943) list_action_receipts: WHERE tenant_id ORDER BY created_at DESC
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant_created ON action_receipts (tenant_id, created_at);",
    )
    .execute(pool)
    .await?;

    // ── Phase 5: SOC event indexer ────────────────────────────────────────────
    // soc_alerts: one persisted row per detection rule firing (detect::Alert).
    // Stores ids/summaries/hashes only — never raw payloads or secrets.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS soc_alerts (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL,
            rule            TEXT NOT NULL,
            severity        TEXT NOT NULL,
            agent_id        TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            summary         TEXT NOT NULL,
            created_at      TEXT NOT NULL
        );",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_soc_alerts_tenant ON soc_alerts (tenant_id);")
        .execute(pool)
        .await?;

    // soc_incidents: one persisted row per multi-event correlation incident
    // (correlate::Incident). source_event_ids is a JSON array of evidence ids.
    // `status` ('open'/'closed') and `closed_at` support the Phase 6 lifecycle.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS soc_incidents (
            id               TEXT PRIMARY KEY,
            tenant_id        TEXT NOT NULL,
            kind             TEXT NOT NULL,
            severity         TEXT NOT NULL,
            agent_id         TEXT NOT NULL,
            summary          TEXT NOT NULL,
            source_event_ids TEXT NOT NULL,
            opened_at        TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'open',
            closed_at        TEXT
        );",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_soc_incidents_tenant ON soc_incidents (tenant_id);",
    )
    .execute(pool)
    .await?;

    // Idempotent ALTER TABLE for existing DBs that pre-date the lifecycle columns.
    ensure_soc_incident_lifecycle_columns(pool).await?;

    // Idempotent ALTER TABLE for existing DBs that pre-date optional receipt signing.
    ensure_action_receipt_signature_columns(pool).await?;

    // DB-005 (#1195): single-row table tracking the schema version this DB
    // was last migrated to. Created here so a fresh DB starts at version 0
    // before `check_schema_version` bumps it to `CURRENT_SCHEMA_VERSION`.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_meta (
            id      INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        );",
    )
    .execute(pool)
    .await?;

    // SOC-007 (#1190): per-(tenant, agent) hourly action counts, used as the
    // rolling 7-day baseline for the behavioral-anomaly rate check.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_hourly_action_counts (
            tenant_id    TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            hour_bucket  TEXT NOT NULL,
            action_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (tenant_id, agent_id, hour_bucket)
        );",
    )
    .execute(pool)
    .await?;

    // SOC-007 (#1190): every (tool, action) an agent has ever been observed
    // calling — used to detect "agent used a tool/action it has never used
    // before" (a deterministic, threshold-free anomaly signal).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_known_tool_actions (
            tenant_id     TEXT NOT NULL,
            agent_id      TEXT NOT NULL,
            tool_key      TEXT NOT NULL,
            action_key    TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, agent_id, tool_key, action_key)
        );",
    )
    .execute(pool)
    .await?;

    // #1289: per-tenant overrides for the composite-risk-score weights. A
    // missing row means "use risk::RiskWeights::from_env()" — this table only
    // needs a row when a tenant wants to deviate from the env-configured
    // defaults.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_risk_weights (
            tenant_id TEXT PRIMARY KEY,
            environment_weight_mutating INTEGER NOT NULL,
            context_trust_penalty_trusted_internal_signed INTEGER NOT NULL,
            context_trust_penalty_trusted_internal_unsigned INTEGER NOT NULL,
            context_trust_penalty_semi_trusted_customer INTEGER NOT NULL,
            context_trust_penalty_untrusted_external INTEGER NOT NULL,
            context_trust_penalty_malicious_suspected INTEGER NOT NULL,
            context_trust_penalty_unknown INTEGER NOT NULL,
            mcp_trust_penalty INTEGER NOT NULL,
            anomaly_weight_pct INTEGER NOT NULL,
            approval_credit INTEGER NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_tenant_risk_weights_tenant_id ON tenant_risk_weights(tenant_id);",
    )
    .execute(pool)
    .await?;

    // #1296: per-tenant thresholds for auto-escalating an agent's risk_tier
    // after repeated denials. A missing row means "use the built-in default"
    // (5 denials / 60-minute window) — this table only needs a row when a
    // tenant wants to deviate from that default.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_risk_escalation_config (
            tenant_id TEXT PRIMARY KEY,
            denial_threshold INTEGER NOT NULL,
            window_minutes INTEGER NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// DB-005 (#1195): verify the on-disk schema version is one this binary
/// understands.
///
/// - No row yet (fresh DB, or a DB that pre-dates `schema_meta`): insert
///   [`CURRENT_SCHEMA_VERSION`] — migrations above have already brought the
///   schema up to date.
/// - On-disk version <= `CURRENT_SCHEMA_VERSION`: this binary's migrations
///   (already applied above) cover the gap; bump the stored version.
/// - On-disk version > `CURRENT_SCHEMA_VERSION`: a *newer* binary already
///   migrated this DB further than this binary knows how to handle. Refuse
///   to start (fail closed) with a clear error rather than risk undefined
///   behaviour against unrecognized schema.
async fn check_schema_version(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let existing: Option<i64> = sqlx::query_scalar("SELECT version FROM schema_meta WHERE id = 1")
        .fetch_optional(pool)
        .await?;

    match existing {
        Some(v) if v > CURRENT_SCHEMA_VERSION => Err(sqlx::Error::Protocol(format!(
            "database schema version {v} is newer than this binary supports \
             (max supported: {CURRENT_SCHEMA_VERSION}); refusing to start. \
             Upgrade the gateway binary before connecting to this database."
        ))),
        Some(v) if v < CURRENT_SCHEMA_VERSION => {
            sqlx::query("UPDATE schema_meta SET version = ? WHERE id = 1")
                .bind(CURRENT_SCHEMA_VERSION)
                .execute(pool)
                .await?;
            Ok(())
        }
        Some(_) => Ok(()),
        None => {
            sqlx::query("INSERT INTO schema_meta (id, version) VALUES (1, ?)")
                .bind(CURRENT_SCHEMA_VERSION)
                .execute(pool)
                .await?;
            Ok(())
        }
    }
}

/// Additive migration (#0072): caller-supplied idempotency key on each decision.
/// A repeat `POST /v1/authorize` with the same `(tenant_id, agent_id,
/// request_id)` is detected via [`get_decision_by_request_id`] and short-circuits
/// to the original decision instead of re-evaluating Cedar / writing a duplicate
/// audit event, approval, or receipt. The partial unique index only applies to
/// non-NULL request_ids, so callers that omit it are unaffected.
async fn ensure_decisions_request_id_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(decisions)")
            .fetch_all(pool)
            .await?;

    if !columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "request_id")
    {
        sqlx::query("ALTER TABLE decisions ADD COLUMN request_id TEXT")
            .execute(pool)
            .await?;
    }

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_tenant_agent_request_id
         ON decisions (tenant_id, agent_id, request_id)
         WHERE request_id IS NOT NULL",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Additive migration (#0081): per-decision evaluation latency, in
/// milliseconds, for SOC/perf dashboards. NULL on legacy rows and on
/// idempotent replays (#0072), which don't re-evaluate.
async fn ensure_decisions_latency_ms_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(decisions)")
            .fetch_all(pool)
            .await?;

    if !columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "latency_ms")
    {
        sqlx::query("ALTER TABLE decisions ADD COLUMN latency_ms INTEGER")
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Additive migration (#1289): advisory composite risk score, `0..=100`,
/// computed by `risk::compute_composite_risk_score`. NULL on legacy rows and
/// on idempotent replays that predate this column.
async fn ensure_decisions_composite_risk_score_column(
    pool: &SqlitePool,
) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(decisions)")
            .fetch_all(pool)
            .await?;

    if !columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "composite_risk_score")
    {
        sqlx::query("ALTER TABLE decisions ADD COLUMN composite_risk_score INTEGER")
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Additive migration (#0078-#0080): agent lifecycle columns surfaced in the SOC
/// UI and audit trail. `quarantined_at` records when an agent entered the
/// `quarantined` status (cleared on any other status change); `frozen_reason`
/// holds the operator-supplied reason for the most recent freeze (cleared on
/// unfreeze); `last_seen_at` is a heartbeat updated on every successful
/// `/v1/authorize` call. All three are nullable — NULL means "never set".
async fn ensure_agents_lifecycle_columns(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(agents)")
            .fetch_all(pool)
            .await?;

    let has = |name: &str| columns.iter().any(|(_, n, _, _, _, _)| n == name);

    if !has("quarantined_at") {
        sqlx::query("ALTER TABLE agents ADD COLUMN quarantined_at DATETIME")
            .execute(pool)
            .await?;
    }
    if !has("frozen_reason") {
        sqlx::query("ALTER TABLE agents ADD COLUMN frozen_reason TEXT")
            .execute(pool)
            .await?;
    }
    if !has("last_seen_at") {
        sqlx::query("ALTER TABLE agents ADD COLUMN last_seen_at DATETIME")
            .execute(pool)
            .await?;
    }
    if !has("force_approval") {
        sqlx::query("ALTER TABLE agents ADD COLUMN force_approval INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Additive migration (#1184): per-tenant kill switch for the SOC Response
/// Engine's auto-dispatch (Phase 4 completion). Defaults to enabled (`1`) so
/// the containment behaviour described in `respond.rs` is on by default;
/// tenants can opt out via `PATCH`-style tenant config.
async fn ensure_tenants_auto_respond_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(tenants)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "auto_respond_enabled")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE tenants ADD COLUMN auto_respond_enabled INTEGER NOT NULL DEFAULT 1")
        .execute(pool)
        .await?;
    Ok(())
}

/// Additive migration (#1185, SOC-002): per-tenant override for the SOC
/// Response Engine's autonomy level (`L0`-`L4`). `NULL` means "no override —
/// fall back to `AEGIS_SOC_AUTONOMY_LEVEL` (default `L1`)" — see
/// [`get_soc_autonomy_level`].
async fn ensure_tenants_soc_autonomy_level_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(tenants)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "soc_autonomy_level")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE tenants ADD COLUMN soc_autonomy_level TEXT")
        .execute(pool)
        .await?;
    Ok(())
}

async fn ensure_mcp_server_endpoint_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(mcp_servers)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "endpoint")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE mcp_servers ADD COLUMN endpoint TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;
    Ok(())
}

/// Additive migration: pin a per-server MCP tool-manifest hash so re-discovery can
/// detect drift (supply-chain / tool-hijack signal). Empty string means "not yet
/// pinned" (first discovery pins it). Never holds payloads — a hash only.
async fn ensure_mcp_server_manifest_hash_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(mcp_servers)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "manifest_hash")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE mcp_servers ADD COLUMN manifest_hash TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;
    Ok(())
}

/// Additive migration: per-server opt-in toggle for MCP response inspection
/// (#1333). Defaults to disabled (`0`) — inspection only runs once an
/// operator explicitly enables it for a server via `PATCH
/// /v1/mcp/servers/:server_key`.
async fn ensure_mcp_server_inspection_enabled_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(mcp_servers)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "inspection_enabled")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE mcp_servers ADD COLUMN inspection_enabled BOOLEAN NOT NULL DEFAULT 0")
        .execute(pool)
        .await?;
    Ok(())
}

/// Additive migration: record the canonicalization scheme on each receipt so the
/// hash chain is self-describing and a future scheme bump stays migratable. Empty
/// string on legacy rows. NOT part of `receipt_hash` (byte-parity untouched).
async fn ensure_action_receipts_canon_version_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(action_receipts)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "canon_version")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE action_receipts ADD COLUMN canon_version TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;
    Ok(())
}

async fn ensure_approval_original_call_hash_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(approvals)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "original_call_hash")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE approvals ADD COLUMN original_call_hash TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;
    Ok(())
}

async fn ensure_approval_consumed_at_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(approvals)")
            .fetch_all(pool)
            .await?;

    if columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "consumed_at")
    {
        return Ok(());
    }

    sqlx::query("ALTER TABLE approvals ADD COLUMN consumed_at DATETIME")
        .execute(pool)
        .await?;
    Ok(())
}

/// Idempotent migration: add `callback_url` (#1187/TASK-0082) and
/// `callback_secret_hash` (#1187/TASK-0083) to `approvals`. Both are
/// nullable — most approvals have no callback registered.
async fn ensure_approval_callback_columns(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(approvals)")
            .fetch_all(pool)
            .await?;

    let has = |name: &str| columns.iter().any(|(_, n, _, _, _, _)| n == name);

    if !has("callback_url") {
        sqlx::query("ALTER TABLE approvals ADD COLUMN callback_url TEXT")
            .execute(pool)
            .await?;
    }
    if !has("callback_secret_hash") {
        sqlx::query("ALTER TABLE approvals ADD COLUMN callback_secret_hash TEXT")
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Idempotent migration: add `status` and `closed_at` to `soc_incidents` when
/// upgrading an existing database that predates Phase 6. Uses PRAGMA table_info
/// to check for column presence before attempting ALTER TABLE — SQLite does not
/// support `ADD COLUMN IF NOT EXISTS`, so we guard it ourselves. Safe to call on
/// a fresh DB (where CREATE TABLE already includes the columns); the PRAGMA check
/// short-circuits before any ALTER is executed.
async fn ensure_soc_incident_lifecycle_columns(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(soc_incidents)")
            .fetch_all(pool)
            .await?;

    let has_status = columns.iter().any(|(_, name, _, _, _, _)| name == "status");
    let has_closed_at = columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "closed_at");

    if !has_status {
        sqlx::query("ALTER TABLE soc_incidents ADD COLUMN status TEXT NOT NULL DEFAULT 'open'")
            .execute(pool)
            .await?;
    }
    if !has_closed_at {
        sqlx::query("ALTER TABLE soc_incidents ADD COLUMN closed_at TEXT")
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Idempotent migration: add `signature` and `signer_public_key` (both nullable)
/// to `action_receipts` for optional Ed25519 receipt signing. These columns are
/// additive metadata stored ALONGSIDE the receipt; they are NOT part of
/// `receipt_hash` or the canonical body, so the byte-parity-locked hash chain is
/// unchanged. Existing rows stay NULL (unsigned) — no data loss. Uses PRAGMA
/// table_info to guard the ALTER (SQLite has no `ADD COLUMN IF NOT EXISTS`); safe
/// on a fresh DB where CREATE TABLE already includes the columns.
async fn ensure_action_receipt_signature_columns(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(action_receipts)")
            .fetch_all(pool)
            .await?;

    let has_signature = columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "signature");
    let has_signer_public_key = columns
        .iter()
        .any(|(_, name, _, _, _, _)| name == "signer_public_key");

    if !has_signature {
        sqlx::query("ALTER TABLE action_receipts ADD COLUMN signature TEXT")
            .execute(pool)
            .await?;
    }
    if !has_signer_public_key {
        sqlx::query("ALTER TABLE action_receipts ADD COLUMN signer_public_key TEXT")
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// On-disk size of the SQLite database file in bytes (#949), computed as
/// `page_count * page_size` via the corresponding `PRAGMA`s.
pub async fn get_database_size_bytes(pool: &DbPool) -> Result<i64, sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            let (page_count,): (i64,) = sqlx::query_as("PRAGMA page_count").fetch_one(p).await?;
            let (page_size,): (i64,) = sqlx::query_as("PRAGMA page_size").fetch_one(p).await?;
            Ok(page_count * page_size)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let (size,): (i64,) = sqlx::query_as("SELECT pg_database_size(current_database())")
                .fetch_one(p)
                .await?;
            Ok(size)
        }
    }
}

/// Row count for every user table in the database (#950), ordered by table
/// name. Reads table names from `sqlite_master`, excluding internal
/// `sqlite_*` tables.
pub async fn get_table_row_counts(
    pool: &DbPool,
) -> Result<Vec<aegis_api::models::TableRowCount>, sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            let tables: Vec<(String,)> = sqlx::query_as(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .fetch_all(p)
            .await?;

            let mut counts = Vec::with_capacity(tables.len());
            for (table,) in tables {
                let query = format!("SELECT COUNT(*) FROM \"{}\"", table);
                let (row_count,): (i64,) = sqlx::query_as(&query).fetch_one(p).await?;
                counts.push(aegis_api::models::TableRowCount { table, row_count });
            }
            Ok(counts)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let tables: Vec<(String,)> = sqlx::query_as(
                "SELECT table_name FROM information_schema.tables 
                 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                 ORDER BY table_name",
            )
            .fetch_all(p)
            .await?;

            let mut counts = Vec::with_capacity(tables.len());
            for (table,) in tables {
                let query = format!("SELECT COUNT(*) FROM \"{}\"", table);
                let (row_count,): (i64,) = sqlx::query_as(&query).fetch_one(p).await?;
                counts.push(aegis_api::models::TableRowCount { table, row_count });
            }
            Ok(counts)
        }
    }
}

/// Combined database-level monitoring snapshot (#949, #950).
pub async fn get_db_stats(pool: &DbPool) -> Result<aegis_api::models::DbStats, sqlx::Error> {
    let size_bytes = get_database_size_bytes(pool).await?;
    let tables = get_table_row_counts(pool).await?;
    Ok(aegis_api::models::DbStats { size_bytes, tables })
}

/// Write a consistent point-in-time copy of the database to `dest_path`
/// (#945) using SQLite's `VACUUM INTO`, which also compacts the copy. The
/// live database is untouched and remains available throughout.
pub async fn backup_database_to(pool: &DbPool, dest_path: &str) -> Result<(), sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query("VACUUM INTO ?")
                .bind(dest_path)
                .execute(p)
                .await?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(_) => Err(sqlx::Error::Configuration(
            "Backup database not supported on PostgreSQL backend".into(),
        )),
    }
}

/// Reclaim free space left behind by the audit-event archival (#0106) and
/// approval-cleanup (#0105) jobs' `DELETE`s, and defragment the database
/// file (#0061). Plain `VACUUM` rebuilds the whole file into a contiguous
/// copy and requires no other connection hold a transaction open, so this
/// is run on a periodic schedule (see `jobs::run_vacuum_job`) rather than on
/// the request hot path. `VACUUM` takes no bind parameters in SQLite.
pub async fn vacuum_database(pool: &DbPool) -> Result<(), sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query("VACUUM").execute(p).await?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(_) => {
            tracing::info!("PostgreSQL autovacuum is active; skipping manual VACUUM database job.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use uuid::Uuid;

    /// #906: unset env var falls back to sqlx's own built-in default.
    #[tokio::test]
    async fn statement_cache_capacity_from_env_defaults_when_unset() {
        let _guard = crate::db::test_utils::STATEMENT_CACHE_ENV_LOCK.lock().await;
        std::env::remove_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY");
        assert_eq!(
            statement_cache_capacity_from_env(),
            DEFAULT_STATEMENT_CACHE_CAPACITY
        );
    }

    /// #906: a configured value is read and parsed.
    #[tokio::test]
    async fn statement_cache_capacity_from_env_reads_configured_value() {
        let _guard = crate::db::test_utils::STATEMENT_CACHE_ENV_LOCK.lock().await;
        std::env::set_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY", "250");
        assert_eq!(statement_cache_capacity_from_env(), 250);
        std::env::remove_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY");
    }

    /// #906: `0` is a valid, meaningful value (disables caching) — not
    /// filtered out like the batch-size/interval env vars elsewhere.
    #[tokio::test]
    async fn statement_cache_capacity_from_env_allows_zero() {
        let _guard = crate::db::test_utils::STATEMENT_CACHE_ENV_LOCK.lock().await;
        std::env::set_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY", "0");
        assert_eq!(statement_cache_capacity_from_env(), 0);
        std::env::remove_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY");
    }

    /// #906: an unparseable value falls back to the default instead of
    /// failing startup.
    #[tokio::test]
    async fn statement_cache_capacity_from_env_falls_back_on_garbage_value() {
        let _guard = crate::db::test_utils::STATEMENT_CACHE_ENV_LOCK.lock().await;
        std::env::set_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY", "not-a-number");
        assert_eq!(
            statement_cache_capacity_from_env(),
            DEFAULT_STATEMENT_CACHE_CAPACITY
        );
        std::env::remove_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY");
    }

    /// #906: a custom (including zero) statement cache capacity doesn't
    /// break pool initialization or basic query execution — the cache
    /// capacity only affects whether SQLite re-parses a repeated statement,
    /// never correctness.
    #[tokio::test]
    async fn init_db_succeeds_with_custom_statement_cache_capacity() {
        let _guard = crate::db::test_utils::STATEMENT_CACHE_ENV_LOCK.lock().await;
        std::env::set_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY", "0");
        let pool = setup_pool("stmt_cache_capacity_zero").await;

        let (one,): (i64,) = sqlx::query_as("SELECT 1")
            .fetch_one(pool.sqlite_pool())
            .await
            .expect("a basic query should still succeed");
        assert_eq!(one, 1);
        // Run the same query again to exercise the (disabled) cache path
        // a second time — must still succeed identically.
        let (one_again,): (i64,) = sqlx::query_as("SELECT 1")
            .fetch_one(pool.sqlite_pool())
            .await
            .expect("a repeated query should still succeed with caching disabled");
        assert_eq!(one_again, 1);

        std::env::remove_var("AEGIS_DB_STATEMENT_CACHE_CAPACITY");
    }

    #[tokio::test]
    async fn retry_on_busy_retries_transient_busy_then_succeeds() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);

        let result: Result<&str, sqlx::Error> = retry_on_busy(3, || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(busy_error())
                } else {
                    Ok("ok")
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    /// #1151: a non-retryable error (e.g. constraint violation) propagates
    /// immediately without retrying.
    #[tokio::test]
    async fn retry_on_busy_propagates_non_retryable_error_immediately() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);

        let result: Result<&str, sqlx::Error> = retry_on_busy(3, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async move { Err(sqlx::Error::RowNotFound) }
        })
        .await;

        assert!(matches!(result, Err(sqlx::Error::RowNotFound)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// #1151: after `max_retries` exhausted retryable failures, the final
    /// error is returned.
    #[tokio::test]
    async fn retry_on_busy_gives_up_after_max_retries() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);

        let result: Result<&str, sqlx::Error> = retry_on_busy(3, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async move { Err(busy_error()) }
        })
        .await;

        assert!(result.is_err());
        // initial attempt + 3 retries = 4 total
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    /// #1164 (TEST-004, AC #2): a pool with `max_connections(1)` whose only
    /// connection is held open returns `Err(PoolTimedOut)` once
    /// `acquire_timeout` elapses, rather than hanging indefinitely or
    /// panicking. Wrapped in an outer `tokio::time::timeout` so the test
    /// itself fails loudly (instead of hanging the suite) if that contract
    /// is ever broken.
    #[tokio::test]
    async fn pool_acquire_times_out_gracefully_when_exhausted_not_panic() {
        use sqlx::sqlite::SqlitePoolOptions;
        use std::time::Duration;

        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/pool_exhausted_{}.db",
            Uuid::new_v4().simple()
        );
        let connection_options = sqlx::sqlite::SqliteConnectOptions::from_str(&db_url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_with(connection_options)
            .await
            .unwrap();

        // Hold the only connection open so the pool has zero capacity left.
        let _held_connection = pool.acquire().await.unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("a second acquire must resolve (err or ok) well within 2s, not hang");

        match result {
            Err(sqlx::Error::PoolTimedOut) => {}
            Err(e) => panic!("expected PoolTimedOut, got error: {e:?}"),
            Ok(_) => panic!("expected PoolTimedOut, got Ok"),
        }
    }

    /// #1164 (TEST-004, AC #3): opening a file that isn't a valid SQLite
    /// database (simulating WAL/page corruption) returns a graceful `Err`
    /// from `init_db` rather than panicking. The caller (`main()`) logs this
    /// via `tracing::error!` before propagating, satisfying "detects and
    /// logs error".
    #[tokio::test]
    async fn init_db_returns_error_not_panic_on_corrupted_database_file() {
        std::fs::create_dir_all("target").unwrap();
        let db_path = format!("target/corrupted_{}.db", Uuid::new_v4().simple());
        // A real SQLite file starts with the 16-byte magic header
        // "SQLite format 3\0". Garbage bytes here are reliably rejected by
        // SQLite as "file is not a database" without needing to construct a
        // byte-exact corrupted page layout.
        std::fs::write(&db_path, b"not a sqlite database, just garbage bytes").unwrap();

        let db_url = format!("sqlite://{}", db_path);
        let result = init_db(&db_url).await;

        assert!(result.is_err(), "expected init_db to return Err, got Ok");

        let _ = std::fs::remove_file(&db_path);
    }

    #[tokio::test]
    async fn composite_hot_path_indexes_exist() {
        let pool = setup_pool("composite_indexes").await;
        for name in [
            "idx_decisions_tenant_agent_created",
            "idx_approvals_tenant_status_created",
            "idx_audit_events_tenant_type_created",
            "idx_action_receipts_tenant_created",
        ] {
            let found: Option<(String,)> =
                sqlx::query_as("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?")
                    .bind(name)
                    .fetch_optional(pool.sqlite_pool())
                    .await
                    .unwrap();
            assert!(found.is_some(), "composite index {name} must be created");
        }
    }

    /// #0098: foreign key enforcement is enabled on every pooled connection,
    /// so an INSERT referencing a non-existent parent row (e.g. a skill under
    /// a tenant that doesn't exist) is rejected rather than silently allowed.
    #[tokio::test]
    async fn foreign_keys_pragma_is_enabled_and_enforced() {
        let pool = setup_pool("fk_pragma").await;

        let fk_enabled: (i64,) = sqlx::query_as("PRAGMA foreign_keys")
            .fetch_one(pool.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(fk_enabled.0, 1, "foreign_keys pragma must be ON");

        let result = sqlx::query(
            "INSERT INTO skills (id, tenant_id, skill_key, name, type) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind("nonexistent_tenant")
        .bind("orphan_skill")
        .bind("Orphan Skill")
        .bind("static")
        .execute(pool.sqlite_pool())
        .await;

        assert!(
            result.is_err(),
            "insert referencing a non-existent tenant must violate the FK constraint"
        );
    }

    /// #0108: re-applying migrations to an already-migrated database (e.g.
    /// after a restart, or a rollback to an older binary followed by an
    /// upgrade back) must not error and must preserve existing data. Every
    /// `ensure_*_column` migration checks `PRAGMA table_info` before
    /// `ALTER TABLE ... ADD COLUMN`, so re-running them is a no-op.
    #[tokio::test]
    async fn migrations_are_idempotent_on_existing_database() {
        let db_url = format!(
            "sqlite://target/migration_idempotent_{}.db",
            Uuid::new_v4().simple()
        );
        std::fs::create_dir_all("target").unwrap();

        let pool1 = init_db(&db_url).await.unwrap();
        register_tenant(&pool1, "tenant_mig", "Mig Tenant", "developer")
            .await
            .unwrap();
        pool1.close().await;

        // Re-run init_db (and thus run_migrations) against the same database
        // file, simulating a process restart against an already-migrated DB.
        let pool2 = init_db(&db_url).await.unwrap();
        let tenant = get_tenant_by_id(&pool2, "tenant_mig").await.unwrap();
        assert!(tenant.is_some(), "data must survive re-applied migrations");

        // Running the migration set a third time on the live pool must also
        // be a no-op (no duplicate-column or duplicate-table errors).
        bootstrap_legacy_schema(pool2.sqlite_pool()).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(pool2.sqlite_pool())
            .await
            .unwrap();
    }

    /// DB-001 (#1191): `init_db` must record the baseline migration in
    /// `_sqlx_migrations`, including for a database that was brought to the
    /// baseline schema by [`bootstrap_legacy_schema`] (i.e. every table
    /// already existed before `sqlx::migrate!()` ran).
    #[tokio::test]
    async fn init_db_records_baseline_migration() {
        let pool = setup_pool("sqlx_migrations_baseline").await;

        let rows: Vec<(i64, String, bool)> = sqlx::query_as(
            "SELECT version, description, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(pool.sqlite_pool())
        .await
        .unwrap();

        assert!(!rows.is_empty(), "expected at least one applied migration");
        let baseline = rows
            .iter()
            .find(|(version, _, _)| *version == 1)
            .expect("baseline migration (version 1) must be recorded");
        assert_eq!(baseline.1, "baseline");
        assert!(
            baseline.2,
            "baseline migration must be recorded as successful"
        );
        assert!(
            rows.iter().all(|(_, _, success)| *success),
            "all applied migrations must be recorded as successful"
        );
    }

    #[tokio::test]
    async fn health_check_succeeds_on_live_pool() {
        let pool = setup_pool("health_check").await;
        health_check(&pool)
            .await
            .expect("health_check must succeed against a live pool");

        // After the pool is closed the ping must fail (drives the /health 503 path).
        pool.close().await;
        assert!(health_check(&pool).await.is_err());
    }

    /// DB-005 (#1195): a fresh database is initialized at the current schema
    /// version.
    #[tokio::test]
    async fn fresh_db_is_stamped_with_current_schema_version() {
        let pool = setup_pool("schema_version_fresh").await;

        let version: i64 = sqlx::query_scalar("SELECT version FROM schema_meta WHERE id = 1")
            .fetch_one(pool.sqlite_pool())
            .await
            .unwrap();

        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    /// DB-005 (#1195): re-opening an up-to-date DB is a no-op (idempotent).
    #[tokio::test]
    async fn reopening_current_db_keeps_schema_version() {
        let db_url = format!(
            "sqlite://target/schema_version_reopen_{}.db",
            Uuid::new_v4().simple()
        );
        let pool = init_db(&db_url).await.unwrap();
        drop(pool);

        let pool = init_db(&db_url).await.unwrap();
        let version: i64 = sqlx::query_scalar("SELECT version FROM schema_meta WHERE id = 1")
            .fetch_one(pool.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    /// DB-005 (#1195): a DB stamped with a schema version *newer* than this
    /// binary supports must refuse to start (fail closed) with a clear error.
    #[tokio::test]
    async fn newer_schema_version_refuses_to_start() {
        let db_url = format!(
            "sqlite://target/schema_version_future_{}.db",
            Uuid::new_v4().simple()
        );
        // Bring the DB up to today's schema first.
        let pool = init_db(&db_url).await.unwrap();
        sqlx::query("UPDATE schema_meta SET version = ? WHERE id = 1")
            .bind(CURRENT_SCHEMA_VERSION + 1)
            .execute(pool.sqlite_pool())
            .await
            .unwrap();
        drop(pool);

        let result = init_db(&db_url).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("schema version"),
            "expected a schema version error, got: {err}"
        );
    }

    /// DB-005 (#1195): a DB created before `schema_meta` existed (no row) is
    /// transparently stamped with the current version on next open.
    #[tokio::test]
    async fn db_without_schema_meta_row_is_backfilled() {
        let pool = setup_pool("schema_version_backfill").await;

        // Simulate a pre-#1195 DB: drop the row that init_db just inserted.
        sqlx::query("DELETE FROM schema_meta WHERE id = 1")
            .execute(pool.sqlite_pool())
            .await
            .unwrap();

        check_schema_version(pool.sqlite_pool()).await.unwrap();

        let version: i64 = sqlx::query_scalar("SELECT version FROM schema_meta WHERE id = 1")
            .fetch_one(pool.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    /// #1192: no-op when encryption wasn't requested, regardless of the
    /// underlying SQLite build.
    #[tokio::test]
    async fn verify_encryption_or_fail_closed_is_noop_when_no_key_configured() {
        let pool = setup_pool("verify_encryption_noop").await;
        verify_encryption_or_fail_closed(pool.sqlite_pool(), false)
            .await
            .unwrap();
    }

    /// #1192: the dangerous case this whole check exists to catch — a key
    /// WAS configured (`AEGIS_DB_ENCRYPTION_KEY` set), but the binary is the
    /// plain-SQLite build every CI job and most local dev actually runs.
    /// `PRAGMA cipher_version` reports whether the LINKED LIBRARY is
    /// SQLCipher-capable at all — a build-time property, constant across
    /// every connection/test in this binary — so this test only makes sense
    /// (and is only meaningfully testing the real misconfiguration) in the
    /// default, non-`sqlcipher` build.
    #[cfg(not(feature = "sqlcipher"))]
    #[tokio::test]
    async fn verify_encryption_or_fail_closed_errors_when_key_configured_without_sqlcipher() {
        let pool = setup_pool("verify_encryption_no_cipher").await;
        let result = verify_encryption_or_fail_closed(pool.sqlite_pool(), true).await;
        assert!(result.is_err());
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("sqlcipher"),
            "error must explain the `sqlcipher` feature is required, got: {message}"
        );
    }

    /// #1192: only runs when actually built against SQLCipher
    /// (`cargo test --features sqlcipher -p aegis-storage`), proving the
    /// detection logic also passes cleanly in the configuration it's
    /// supposed to allow through.
    #[cfg(feature = "sqlcipher")]
    #[tokio::test]
    async fn verify_encryption_or_fail_closed_passes_with_real_sqlcipher() {
        let pool = setup_pool("verify_encryption_real_cipher").await;
        sqlx::query("PRAGMA key = 'test-encryption-key';")
            .execute(pool.sqlite_pool())
            .await
            .unwrap();
        verify_encryption_or_fail_closed(pool.sqlite_pool(), true)
            .await
            .unwrap();
    }

    // Deliberately no test exercises `init_db`/`init_db_with_busy_timeout`
    // with `AEGIS_DB_ENCRYPTION_KEY` set: that env var is process-global,
    // every test in this module calls `init_db`, and `cargo test` runs them
    // concurrently — so mutating it here (even guarded by a lock only this
    // test would respect) leaks into unrelated tests' connections and was
    // observed to make them fail intermittently with "file is not a
    // database". `verify_encryption_or_fail_closed`'s own unit tests above
    // cover the exact logic that matters without touching global env state;
    // the thin remaining wiring (reading the env var, quoting it into the
    // `key` pragma) is covered by review, not a flaky integration test.
}
