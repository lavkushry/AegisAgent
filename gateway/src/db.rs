use crate::models::*;
use chrono::{DateTime, Utc};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::str::FromStr;

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
pub async fn health_check(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(pool)
        .await
        .map(|_| ())
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

pub async fn init_db(db_url: &str) -> Result<SqlitePool, sqlx::Error> {
    // Enforce WAL mode and busy timeout on pool initialization
    let connection_options = sqlx::sqlite::SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5))
        // #0098: enforce FK constraints on every connection (SQLite defaults
        // this off per-connection; without it, ON DELETE/UPDATE actions and
        // referential integrity checks declared in the schema are silently
        // not enforced).
        .foreign_keys(true);

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

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .idle_timeout(std::time::Duration::from_secs(idle_timeout))
        .acquire_timeout(std::time::Duration::from_secs(acquire_timeout))
        .connect_with(connection_options)
        .await?;

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

    // Run migrations
    run_migrations(&pool).await?;

    migrate_agent_tokens(&pool).await?;

    check_schema_version(&pool).await?;

    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
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

/// Read the pinned MCP tool-manifest hash for a server (`""` if never pinned).
/// Tenant-scoped, parameterized.
pub async fn get_mcp_server_manifest_hash(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<String, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT manifest_hash FROM mcp_servers WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0).unwrap_or_default())
}

/// Pin (or re-pin) the MCP tool-manifest hash for a server. Tenant-scoped,
/// parameterized.
pub async fn set_mcp_server_manifest_hash(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    manifest_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE mcp_servers SET manifest_hash = ? WHERE tenant_id = ? AND server_key = ?")
        .bind(manifest_hash)
        .bind(tenant_id)
        .bind(server_key)
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

/// Atomically consume an APPROVED approval (single-use). Returns `true` only if
/// THIS call consumed it (one row updated); `false` if it was already consumed,
/// expired, not approved, or not found. The `consumed_at IS NULL` guard makes
/// concurrent double-consume safe — at most one UPDATE matches.
pub async fn consume_approval(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE approvals
             SET consumed_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'APPROVED' AND consumed_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(approval_id)
        .bind(now)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

// --- Multi-Tenant CRUD Operations ---

pub async fn get_tenant_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Option<TenantRecord>, sqlx::Error> {
    sqlx::query_as::<_, TenantRecord>("SELECT * FROM tenants WHERE id = ?")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
}

/// GDPR data-portability (#946): assemble the complete set of one tenant's
/// records into a [`TenantExport`]. Every query is `tenant_id`-scoped and
/// parameterized; rows are returned in full (no pagination cap) so the export is
/// complete. Read-only.
pub async fn export_tenant_data(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<TenantExport, sqlx::Error> {
    let tenant = get_tenant_by_id(pool, tenant_id).await?;

    let agents = sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let decisions = sqlx::query_as::<_, DecisionRecord>(
        "SELECT * FROM decisions WHERE tenant_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let approvals = sqlx::query_as::<_, ApprovalRecord>(
        "SELECT * FROM approvals WHERE tenant_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let action_receipts = sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT * FROM action_receipts WHERE tenant_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let audit_events = sqlx::query_as::<_, AuditEventRecord>(
        "SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mcp_servers = sqlx::query_as::<_, McpServerRecord>(
        "SELECT * FROM mcp_servers WHERE tenant_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    Ok(TenantExport {
        schema: "aegis-tenant-export-1".to_string(),
        tenant_id: tenant_id.to_string(),
        exported_at: Utc::now().to_rfc3339(),
        tenant,
        agents,
        decisions,
        approvals,
        action_receipts,
        audit_events,
        mcp_servers,
    })
}

/// Permanently delete every row owned by `tenant_id` (#947, GDPR right to
/// erasure), including the `tenants` row itself. Runs in a single
/// transaction, deleting child tables before their parents so that the
/// `FOREIGN KEY` constraints enforced by [`init_db`] are satisfied
/// throughout. Callers should call [`export_tenant_data`] first if a
/// portability copy is needed — this is irreversible.
pub async fn delete_tenant_data(pool: &SqlitePool, tenant_id: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // action_receipts, audit_events*, soc_alerts/incidents, approvals
    // reference decisions/tenants but nothing references them.
    sqlx::query("DELETE FROM action_receipts WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM audit_events WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM audit_events_archive WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM soc_alerts WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM soc_incidents WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM approvals WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    // decisions reference agents; agents and decisions both reference tenants.
    sqlx::query("DELETE FROM decisions WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    // mcp_tools references mcp_servers.
    sqlx::query("DELETE FROM mcp_tools WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mcp_servers WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    // skill_actions references skills (no direct tenant_id column).
    sqlx::query(
        "DELETE FROM skill_actions WHERE skill_id IN (SELECT id FROM skills WHERE tenant_id = ?)",
    )
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM skills WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM policies WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM agents WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM tenants WHERE id = ?")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn register_tenant(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    plan: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO tenants (id, name, plan) VALUES (?, ?, ?)")
        .bind(id)
        .bind(name)
        .bind(plan)
        .execute(pool)
        .await?;
    Ok(())
}

pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn get_agent_by_token(
    pool: &SqlitePool,
    tenant_id: &str,
    token: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    let hashed = hash_token(token);
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND agent_token = ? AND status != 'quarantined'",
    )
    .bind(tenant_id)
    .bind(hashed)
    .fetch_optional(pool)
    .await
}

pub async fn migrate_agent_tokens(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let agents = sqlx::query("SELECT id, agent_token FROM agents")
        .fetch_all(pool)
        .await?;

    for row in agents {
        use sqlx::Row;
        let id: String = row.get("id");
        let token: String = row.get("agent_token");

        let is_hash = token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit());
        if !is_hash {
            let hashed = hash_token(&token);
            sqlx::query("UPDATE agents SET agent_token = ? WHERE id = ?")
                .bind(hashed)
                .bind(id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

pub async fn get_agent_by_key(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_key: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>("SELECT * FROM agents WHERE tenant_id = ? AND agent_key = ?")
        .bind(tenant_id)
        .bind(agent_key)
        .fetch_optional(pool)
        .await
}

pub async fn list_agents(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND status != 'deleted' ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn get_agent_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND id = ? AND status != 'deleted'",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn insert_agent(pool: &SqlitePool, record: &AgentRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, owner_team, owner_email, environment, framework, model_provider, model_name, purpose, risk_tier, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.agent_key)
    .bind(&record.agent_token)
    .bind(&record.name)
    .bind(&record.owner_team)
    .bind(&record.owner_email)
    .bind(&record.environment)
    .bind(&record.framework)
    .bind(&record.model_provider)
    .bind(&record.model_name)
    .bind(&record.purpose)
    .bind(&record.risk_tier)
    .bind(&record.status)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_agent(pool: &SqlitePool, record: &AgentRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agents SET 
            name = ?, 
            owner_team = ?, 
            owner_email = ?, 
            environment = ?, 
            framework = ?, 
            model_provider = ?, 
            model_name = ?, 
            purpose = ?, 
            risk_tier = ?, 
            status = ?, 
            updated_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(&record.name)
    .bind(&record.owner_team)
    .bind(&record.owner_email)
    .bind(&record.environment)
    .bind(&record.framework)
    .bind(&record.model_provider)
    .bind(&record.model_name)
    .bind(&record.purpose)
    .bind(&record.risk_tier)
    .bind(&record.status)
    .bind(&record.tenant_id)
    .bind(&record.id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_policies(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<PolicyRecord>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRecord>(
        "SELECT id, tenant_id, policy_key, name, language, body, version, status, created_by, created_at
         FROM policies
         WHERE tenant_id = ?
         ORDER BY created_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub async fn get_policy_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    policy_id: &str,
) -> Result<Option<PolicyRecord>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRecord>(
        "SELECT id, tenant_id, policy_key, name, language, body, version, status, created_by, created_at
         FROM policies
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(policy_id)
    .fetch_optional(pool)
    .await
}

pub async fn insert_policy(pool: &SqlitePool, record: &PolicyRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO policies (id, tenant_id, policy_key, name, language, body, version, status, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.policy_key)
    .bind(&record.name)
    .bind(&record.language)
    .bind(&record.body)
    .bind(record.version)
    .bind(&record.status)
    .bind(&record.created_by)
    .bind(record.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_policy(pool: &SqlitePool, record: &PolicyRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE policies
         SET policy_key = ?, name = ?, language = ?, body = ?, version = ?, status = ?, created_by = ?, created_at = ?
         WHERE tenant_id = ? AND id = ?"
    )
    .bind(&record.policy_key)
    .bind(&record.name)
    .bind(&record.language)
    .bind(&record.body)
    .bind(record.version)
    .bind(&record.status)
    .bind(&record.created_by)
    .bind(record.created_at)
    .bind(&record.tenant_id)
    .bind(&record.id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_policy(
    pool: &SqlitePool,
    tenant_id: &str,
    policy_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM policies WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(policy_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_skill(
    pool: &SqlitePool,
    tenant_id: &str,
    skill_key: &str,
    name: &str,
    r#type: &str,
    auth_type: Option<&str>,
    owner_team: Option<&str>,
    default_risk: Option<&str>,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO skills (id, tenant_id, skill_key, name, type, auth_type, owner_team, default_risk)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id, skill_key) DO UPDATE SET name=excluded.name, type=excluded.type, auth_type=excluded.auth_type, owner_team=excluded.owner_team, default_risk=excluded.default_risk"
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(skill_key)
    .bind(name)
    .bind(r#type)
    .bind(auth_type)
    .bind(owner_team)
    .bind(default_risk)
    .execute(pool)
    .await?;

    let row: (String,) =
        sqlx::query_as("SELECT id FROM skills WHERE tenant_id = ? AND skill_key = ?")
            .bind(tenant_id)
            .bind(skill_key)
            .fetch_one(pool)
            .await?;

    Ok(row.0)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_skill_action(
    pool: &SqlitePool,
    skill_id: &str,
    action_key: &str,
    description: Option<&str>,
    risk: &str,
    mutates_state: bool,
    data_access: Option<&str>,
    approval_required: bool,
    default_decision: &str,
) -> Result<(), sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO skill_actions (id, skill_id, action_key, description, risk, mutates_state, data_access, approval_required, default_decision)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(skill_id, action_key) DO UPDATE SET description=excluded.description, risk=excluded.risk, mutates_state=excluded.mutates_state, data_access=excluded.data_access, approval_required=excluded.approval_required, default_decision=excluded.default_decision"
    )
    .bind(&id)
    .bind(skill_id)
    .bind(action_key)
    .bind(description)
    .bind(risk)
    .bind(mutates_state)
    .bind(data_access)
    .bind(approval_required)
    .bind(default_decision)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_skill_action(
    pool: &SqlitePool,
    tenant_id: &str,
    skill_key: &str,
    action_key: &str,
) -> Result<Option<(String, bool, bool, String)>, sqlx::Error> {
    sqlx::query_as::<_, (String, bool, bool, String)>(
        "SELECT sa.risk, sa.mutates_state, sa.approval_required, sa.default_decision
         FROM skill_actions sa
         JOIN skills s ON sa.skill_id = s.id
         WHERE s.tenant_id = ? AND s.skill_key = ? AND sa.action_key = ?",
    )
    .bind(tenant_id)
    .bind(skill_key)
    .bind(action_key)
    .fetch_optional(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_mcp_server(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    name: &str,
    owner_team: Option<&str>,
    transport: &str,
    source: Option<&str>,
    trust_level: &str,
    endpoint: &str,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO mcp_servers (id, tenant_id, server_key, name, owner_team, transport, source, trust_level, endpoint, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
         ON CONFLICT(tenant_id, server_key) DO UPDATE SET
            name=excluded.name,
            owner_team=excluded.owner_team,
            transport=excluded.transport,
            source=excluded.source,
            trust_level=excluded.trust_level,
            endpoint=excluded.endpoint,
            status='active'",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(server_key)
    .bind(name)
    .bind(owner_team)
    .bind(transport)
    .bind(source)
    .bind(trust_level)
    .bind(endpoint)
    .execute(pool)
    .await?;

    let row: (String,) =
        sqlx::query_as("SELECT id FROM mcp_servers WHERE tenant_id = ? AND server_key = ?")
            .bind(tenant_id)
            .bind(server_key)
            .fetch_one(pool)
            .await?;

    Ok(row.0)
}

pub async fn get_mcp_server_by_key(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Option<McpServerRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpServerRecord>(
        "SELECT * FROM mcp_servers WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .fetch_optional(pool)
    .await
}

pub async fn upsert_mcp_tool(
    pool: &SqlitePool,
    tenant_id: &str,
    server_id: &str,
    tool: &McpToolManifestItem,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let input_schema = tool.input_schema.as_ref().map(|schema| schema.to_string());

    sqlx::query(
        "INSERT INTO mcp_tools (id, tenant_id, server_id, tool_key, name, description, input_schema, risk, mutates_state, approval_required, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
         ON CONFLICT(tenant_id, server_id, tool_key) DO UPDATE SET
            name=excluded.name,
            description=excluded.description,
            input_schema=excluded.input_schema,
            risk=excluded.risk,
            mutates_state=excluded.mutates_state,
            approval_required=excluded.approval_required,
            status='pending',
            updated_at=CURRENT_TIMESTAMP",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(server_id)
    .bind(&tool.tool_key)
    .bind(&tool.name)
    .bind(&tool.description)
    .bind(&input_schema)
    .bind(&tool.risk)
    .bind(tool.mutates_state)
    .bind(tool.approval_required)
    .execute(pool)
    .await?;

    let row: (String,) = sqlx::query_as(
        "SELECT id FROM mcp_tools WHERE tenant_id = ? AND server_id = ? AND tool_key = ?",
    )
    .bind(tenant_id)
    .bind(server_id)
    .bind(&tool.tool_key)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn list_mcp_tools(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Vec<McpToolRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpToolRecord>(
        "SELECT mt.*
         FROM mcp_tools mt
         JOIN mcp_servers ms ON mt.server_id = ms.id AND mt.tenant_id = ms.tenant_id
         WHERE mt.tenant_id = ? AND ms.server_key = ?
         ORDER BY mt.tool_key ASC",
    )
    .bind(tenant_id)
    .bind(server_key)
    .fetch_all(pool)
    .await
}

pub async fn get_mcp_tool_by_key(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    tool_key: &str,
) -> Result<Option<McpToolRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpToolRecord>(
        "SELECT mt.*
         FROM mcp_tools mt
         JOIN mcp_servers ms ON mt.server_id = ms.id AND mt.tenant_id = ms.tenant_id
         WHERE mt.tenant_id = ? AND ms.server_key = ? AND mt.tool_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .bind(tool_key)
    .fetch_optional(pool)
    .await
}

pub async fn set_mcp_tool_status(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    tool_key: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE mcp_tools
         SET status = ?, updated_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ?
           AND tool_key = ?
           AND server_id = (SELECT id FROM mcp_servers WHERE tenant_id = ? AND server_key = ?)",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(tool_key)
    .bind(tenant_id)
    .bind(server_key)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn insert_decision(
    pool: &SqlitePool,
    record: &DecisionRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO decisions (id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.agent_id)
    .bind(&record.user_id)
    .bind(&record.run_id)
    .bind(&record.trace_id)
    .bind(&record.skill)
    .bind(&record.action)
    .bind(&record.resource)
    .bind(&record.input_json)
    .bind(&record.decision)
    .bind(record.risk_score)
    .bind(&record.reason)
    .bind(&record.matched_policy_ids)
    .bind(&record.request_id)
    .bind(record.latency_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Idempotency lookup (#0072): find a previously-recorded decision for the same
/// `(tenant_id, agent_id, request_id)`. Used by `/v1/authorize` to short-circuit
/// repeat requests instead of re-evaluating Cedar / writing duplicate side
/// effects (audit events, approvals, receipts).
pub async fn get_decision_by_request_id(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    request_id: &str,
) -> Result<Option<DecisionRecord>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRecord>(
        "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, created_at
         FROM decisions
         WHERE tenant_id = ? AND agent_id = ? AND request_id = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(request_id)
    .fetch_optional(pool)
    .await
}

/// Fetch the approval record (if any) created for a given decision. Used by the
/// idempotency replay path (#0072) to reconstruct `ApprovalResponseInfo` for a
/// `require_approval` decision without creating a second approval row.
pub async fn get_approval_by_decision_id(
    pool: &SqlitePool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<ApprovalRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRecord>(
        "SELECT * FROM approvals WHERE tenant_id = ? AND decision_id = ?",
    )
    .bind(tenant_id)
    .bind(decision_id)
    .fetch_optional(pool)
    .await
}

pub async fn list_decisions(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    agent_id: Option<&str>,
    decision: Option<&str>,
) -> Result<Vec<DecisionRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    sqlx::query_as::<_, DecisionRecord>(
        "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, created_at
         FROM decisions
         WHERE tenant_id = ?
           AND (? IS NULL OR agent_id = ?)
           AND (? IS NULL OR decision = ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(agent_id)
    .bind(decision)
    .bind(decision)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn get_decision_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<DecisionRecord>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRecord>(
        "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, created_at
         FROM decisions
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(decision_id)
    .fetch_optional(pool)
    .await
}

pub async fn insert_approval(
    pool: &SqlitePool,
    record: &ApprovalRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO approvals (id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, original_call_hash, edited_skill_call, expires_at, decided_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.decision_id)
    .bind(&record.status)
    .bind(&record.approver_group)
    .bind(&record.approver_user_id)
    .bind(&record.reason)
    .bind(&record.original_skill_call)
    .bind(&record.original_call_hash)
    .bind(&record.edited_skill_call)
    .bind(record.expires_at)
    .bind(record.decided_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_pending_approvals(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let now = Utc::now();
    sqlx::query_as::<_, ApprovalRecord>(
        "SELECT id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, original_call_hash, edited_skill_call, expires_at, decided_at, created_at
         FROM approvals
         WHERE tenant_id = ?
           AND status = 'created'
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(now)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// All tenant IDs, for jobs (e.g. the receipt chain integrity check, #0107)
/// that must run per-tenant rather than globally.
pub async fn list_all_tenant_ids(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT id FROM tenants")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Every receipt for a tenant, oldest-first (chain order). Unlike
/// `list_action_receipts`, this is unpaginated — used by the receipt chain
/// integrity check (#0107), which must walk the whole chain.
pub async fn list_action_receipts_chain_order(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, created_at
         FROM action_receipts
         WHERE tenant_id = ?
         ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub async fn list_action_receipts(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, created_at
         FROM action_receipts
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn get_approval_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<Option<ApprovalRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRecord>("SELECT * FROM approvals WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(approval_id)
        .fetch_optional(pool)
        .await
}

/// Apply an edit to a pending approval (#0130): the edited tool call is
/// re-hashed and that new hash becomes the approval's bound `action_hash`, so
/// any subsequent approve/consume is bound to the edited action, not the
/// original one.
pub async fn update_approval_edit(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
    user_id: &str,
    reason: Option<&str>,
    edited_call: &str,
    new_action_hash: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE approvals
         SET status = 'EDITED', approver_user_id = ?, reason = ?, edited_skill_call = ?,
             original_call_hash = ?, decided_at = ?
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(user_id)
    .bind(reason)
    .bind(edited_call)
    .bind(new_action_hash)
    .bind(now)
    .bind(tenant_id)
    .bind(approval_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_approval_status(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
    status: &str,
    user_id: &str,
    reason: Option<&str>,
    edited_call: Option<&str>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE approvals
         SET status = ?, approver_user_id = ?, reason = ?, edited_skill_call = ?, decided_at = ?
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(status)
    .bind(user_id)
    .bind(reason)
    .bind(edited_call)
    .bind(now)
    .bind(tenant_id)
    .bind(approval_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_audit_event(
    pool: &SqlitePool,
    record: &AuditEventRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.event_type)
    .bind(&record.agent_id)
    .bind(&record.user_id)
    .bind(&record.run_id)
    .bind(&record.trace_id)
    .bind(&record.span_id)
    .bind(&record.skill)
    .bind(&record.action)
    .bind(&record.resource)
    .bind(&record.event_json)
    .bind(&record.input_hash)
    .bind(&record.output_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Move `audit_events` rows older than `cutoff` into `audit_events_archive`
/// (#0106), then delete them from the live table. Runs as a single
/// transaction so a row is never lost or duplicated across the two tables.
/// Returns the number of rows archived.
pub async fn archive_audit_events_older_than(
    pool: &SqlitePool,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO audit_events_archive
            (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, created_at)
         SELECT id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, created_at
         FROM audit_events
         WHERE created_at < ?",
    )
    .bind(cutoff)
    .execute(&mut *tx)
    .await?;

    let result = sqlx::query("DELETE FROM audit_events WHERE created_at < ?")
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

/// Delete `approvals` rows older than `cutoff` whose status is no longer
/// actionable: already decided (`APPROVED`/`REJECTED`/`EDITED`) or still
/// `created` but past `expires_at` (#0105). Returns the number of rows
/// deleted. This keeps the `approvals` table bounded without removing
/// approvals a reviewer might still need to act on.
pub async fn delete_expired_approvals_older_than(
    pool: &SqlitePool,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "DELETE FROM approvals
         WHERE created_at < ?
           AND (status != 'created' OR (expires_at IS NOT NULL AND expires_at < ?))",
    )
    .bind(cutoff)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Atomically append a receipt to a tenant's hash chain (T-D hardening).
///
/// Reading the chain head and inserting the new (head-referencing) receipt happen
/// inside a single `BEGIN IMMEDIATE` transaction on one connection, so concurrent
/// appends for the same tenant are serialized at the writer and cannot fork the
/// chain (two receipts sharing one `prev_receipt_hash`). `BEGIN IMMEDIATE` takes the
/// SQLite write lock up front, so the head this txn reads is the head no other writer
/// can append past before it commits.
///
/// `build` receives the current head hash (`""` for genesis) and returns the
/// fully-formed, hashed receipt referencing it; the receipt-hash formula stays in the
/// caller so the hashed body remains byte-parity-locked. All access is tenant-scoped
/// and parameterized. Returns the record actually committed.
pub async fn append_action_receipt_atomic<F>(
    pool: &SqlitePool,
    tenant_id: &str,
    build: F,
) -> Result<ActionReceiptRecord, sqlx::Error>
where
    F: FnOnce(String) -> ActionReceiptRecord,
{
    let mut conn = pool.acquire().await?;

    // IMMEDIATE acquires the write lock now, serializing concurrent appenders so the
    // head read below can't be raced by another insert before this txn commits.
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    // Helper: roll back and surface the original error if any step fails mid-txn,
    // so we never leave a dangling write lock or a half-applied chain link.
    async fn rollback(conn: &mut sqlx::SqliteConnection) {
        let _ = sqlx::query("ROLLBACK").execute(conn).await;
    }

    let head: Option<(String,)> = match sqlx::query_as(
        "SELECT receipt_hash FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(h) => h,
        Err(e) => {
            rollback(&mut conn).await;
            return Err(e);
        }
    };
    let prev = head.map(|(h,)| h).unwrap_or_default();

    let record = build(prev);

    if let Err(e) = sqlx::query(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.decision_id)
    .bind(&record.ts)
    .bind(&record.agent_id)
    .bind(&record.user_id)
    .bind(&record.run_id)
    .bind(&record.trace_id)
    .bind(&record.tool)
    .bind(&record.action)
    .bind(&record.resource)
    .bind(&record.source_trust)
    .bind(&record.decision)
    .bind(&record.approver)
    .bind(&record.action_hash)
    .bind(&record.prev_receipt_hash)
    .bind(&record.receipt_hash)
    .bind(&record.canon_version)
    .bind(&record.signature)
    .bind(&record.signer_public_key)
    .execute(&mut *conn)
    .await
    {
        rollback(&mut conn).await;
        return Err(e);
    }

    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(record)
}

pub async fn get_action_receipt_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    receipt_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT * FROM action_receipts WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(receipt_id)
    .fetch_optional(pool)
    .await
}

pub async fn get_audit_events_by_run(
    pool: &SqlitePool,
    tenant_id: &str,
    run_id: &str,
) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    sqlx::query_as::<_, AuditEventRecord>(
        "SELECT * FROM audit_events WHERE tenant_id = ? AND run_id = ? ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .bind(run_id)
    .fetch_all(pool)
    .await
}

pub async fn get_all_audit_events(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    sqlx::query_as::<_, AuditEventRecord>(
        "SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

/// --- SOC Phase 4: Response API ---
///
/// Set an agent's operational status (active | frozen | revoked).
/// Frozen agents are denied on the next authorize call automatically (the
/// authorize handler re-reads `agents.status` on every request).
/// Parameterized and tenant-scoped — never touches another tenant's row.
/// Updates `agents.status` and the lifecycle columns (#0078-#0080) it implies:
/// `quarantined_at` is set to now when entering `quarantined` and cleared on any
/// other status; `frozen_reason` is cleared whenever the new status isn't
/// `frozen` (set separately via [`set_agent_frozen_reason`]).
pub async fn set_agent_status(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE agents SET status = ?, updated_at = CURRENT_TIMESTAMP,
         quarantined_at = CASE WHEN ? = 'quarantined' THEN CURRENT_TIMESTAMP ELSE NULL END,
         frozen_reason = CASE WHEN ? = 'frozen' THEN frozen_reason ELSE NULL END
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(status)
    .bind(status)
    .bind(status)
    .bind(tenant_id)
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Records the operator-supplied reason for a freeze (#0079). Tenant-scoped;
/// no-op if the agent doesn't belong to this tenant.
pub async fn set_agent_frozen_reason(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET frozen_reason = ? WHERE tenant_id = ? AND id = ?")
        .bind(reason)
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set or clear `agents.force_approval` (#1184, Phase 4 response engine).
/// While `true`, the authorize handler downgrades every otherwise-`allow`
/// decision for this agent to `require_approval` (set in `routes.rs`).
/// Tenant-scoped; no-op if the agent doesn't belong to this tenant.
pub async fn set_agent_force_approval(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    value: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET force_approval = ? WHERE tenant_id = ? AND id = ?")
        .bind(value)
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Returns `true` if the SOC Response Engine's auto-dispatch (#1184) is
/// enabled for `tenant_id`. Defaults to `true` (the column is `NOT NULL
/// DEFAULT 1`); an unknown tenant is treated as disabled (fail-safe — no
/// automated containment for a tenant the gateway can't find).
pub async fn is_auto_respond_enabled(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT auto_respond_enabled FROM tenants WHERE id = ?")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(v,)| v).unwrap_or(false))
}

/// Heartbeat (#0080): records the timestamp of an agent's most recent successful
/// `/v1/authorize` call. Tenant-scoped, parameterized, best-effort (callers
/// should not fail the request if this errors).
pub async fn touch_agent_last_seen(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agents SET last_seen_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Check whether an agent is currently active (not frozen or revoked).
/// Called by the authorize hot path — must be fast (indexed on tenant_id).
#[allow(dead_code)] // Reserved for authorize hot-path status check (PR-043 follow-up)
pub async fn is_agent_active(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM agents WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(agent_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(s,)| s == "active").unwrap_or(false))
}

// ── SOC-007 (#1190): behavioral baselining ────────────────────────────────────

/// Increment the action count for `(tenant_id, agent_id, hour_bucket)` and
/// return the new count. `hour_bucket` is an opaque, sortable string (e.g.
/// `"2026-06-10T12"`) — comparisons are purely lexicographic.
pub async fn increment_agent_hourly_count(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    hour_bucket: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO agent_hourly_action_counts (tenant_id, agent_id, hour_bucket, action_count)
         VALUES (?, ?, ?, 1)
         ON CONFLICT (tenant_id, agent_id, hour_bucket)
         DO UPDATE SET action_count = action_count + 1",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(hour_bucket)
    .execute(pool)
    .await?;

    let count: i64 = sqlx::query_scalar(
        "SELECT action_count FROM agent_hourly_action_counts
         WHERE tenant_id = ? AND agent_id = ? AND hour_bucket = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(hour_bucket)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Action counts for every hour bucket in `[since_bucket, current_bucket)` for
/// `(tenant_id, agent_id)` — the rolling baseline window, excluding the current
/// (still-accumulating) hour. Lexicographic string comparison works because
/// `hour_bucket` is zero-padded `YYYY-MM-DDTHH`.
pub async fn get_recent_hourly_counts(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    since_bucket: &str,
    current_bucket: &str,
) -> Result<Vec<i64>, sqlx::Error> {
    let counts: Vec<(i64,)> = sqlx::query_as(
        "SELECT action_count FROM agent_hourly_action_counts
         WHERE tenant_id = ? AND agent_id = ?
           AND hour_bucket >= ? AND hour_bucket < ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(since_bucket)
    .bind(current_bucket)
    .fetch_all(pool)
    .await?;

    Ok(counts.into_iter().map(|(c,)| c).collect())
}

/// Record that `(tenant_id, agent_id)` has been observed calling
/// `(tool_key, action_key)`. Returns `true` if this is the *first* time this
/// agent has used this tool/action (a deterministic novelty signal), `false`
/// if it was already known.
pub async fn record_known_tool_action(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
    action_key: &str,
    occurred_at: &str,
) -> Result<bool, sqlx::Error> {
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM agent_known_tool_actions
         WHERE tenant_id = ? AND agent_id = ? AND tool_key = ? AND action_key = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(tool_key)
    .bind(action_key)
    .fetch_optional(pool)
    .await?;

    if existing.is_some() {
        return Ok(false);
    }

    sqlx::query(
        "INSERT INTO agent_known_tool_actions
            (tenant_id, agent_id, tool_key, action_key, first_seen_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, agent_id, tool_key, action_key) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(tool_key)
    .bind(action_key)
    .bind(occurred_at)
    .execute(pool)
    .await?;

    Ok(true)
}

// ── SOC Phase 5: alert + incident persistence ─────────────────────────────────

/// Persist one detection alert. Tenant-scoped, parameterized. Best-effort: the
/// drain task logs errors but never panics on insert failure (design law 3).
/// Stores ids/summary/severity only — never raw payloads (redaction invariant).
pub async fn insert_soc_alert(
    pool: &SqlitePool,
    record: &SocAlertRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO soc_alerts (id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.rule)
    .bind(&record.severity)
    .bind(&record.agent_id)
    .bind(&record.source_event_id)
    .bind(&record.summary)
    .bind(&record.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist one correlation incident. Tenant-scoped, parameterized.
/// `source_event_ids` is pre-serialised JSON (never concatenated into SQL).
/// New incidents always start with `status='open'` and `closed_at=NULL`; the
/// lifecycle is advanced via [`close_soc_incident`].
pub async fn insert_soc_incident(
    pool: &SqlitePool,
    record: &SocIncidentRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO soc_incidents (id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.kind)
    .bind(&record.severity)
    .bind(&record.agent_id)
    .bind(&record.summary)
    .bind(&record.source_event_ids)
    .bind(&record.opened_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// List alerts for a tenant, newest-first, with pagination and optional equality filters.
/// `limit` is capped at [`SOC_MAX_LIMIT`]; `offset` defaults to 0.
/// `severity` and `agent_id` are optional equality filters.  The SQL string is
/// STATIC — optional filters use the `(? IS NULL OR col = ?)` pattern so no
/// concatenation ever occurs (CWE-89 safe).  Both filter binds are duplicated
/// because SQLite does not support referencing a positional placeholder twice.
/// Every query binds `tenant_id` first — cross-tenant isolation guaranteed (CWE-284).
pub async fn list_soc_alerts(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    severity: Option<&str>,
    agent_id: Option<&str>,
) -> Result<Vec<SocAlertRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    sqlx::query_as::<_, SocAlertRecord>(
        "SELECT id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at
         FROM soc_alerts
         WHERE tenant_id = ?
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(severity)
    .bind(severity)
    .bind(agent_id)
    .bind(agent_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// List incidents for a tenant, newest-first, with pagination and optional equality filters.
/// `limit` is capped at [`SOC_MAX_LIMIT`]; `offset` defaults to 0.
/// `status_filter` — optional equality filter (`"open"` or `"closed"`; `None` = all).
/// `severity` and `agent_id` — optional equality filters.
/// All optional filters use the `(? IS NULL OR col = ?)` pattern so the SQL string
/// stays STATIC — no concatenation occurs (CWE-89 safe). Every query binds
/// `tenant_id` first — cross-tenant isolation guaranteed (CWE-284).
pub async fn list_soc_incidents(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    status_filter: Option<&str>,
    severity: Option<&str>,
    agent_id: Option<&str>,
) -> Result<Vec<SocIncidentRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    sqlx::query_as::<_, SocIncidentRecord>(
        "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at
         FROM soc_incidents
         WHERE tenant_id = ?
           AND (? IS NULL OR status = ?)
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
         ORDER BY opened_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(status_filter)
    .bind(status_filter)
    .bind(severity)
    .bind(severity)
    .bind(agent_id)
    .bind(agent_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// Fetch a single SOC incident by id, scoped to the given tenant.
///
/// Returns `Ok(Some(_))` only when both `id` and `tenant_id` match — never
/// leaks another tenant's row.  The two binds are positional and parameterized;
/// no string concatenation occurs (CWE-89 / CWE-284).
pub async fn get_soc_incident(
    pool: &SqlitePool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<Option<SocIncidentRecord>, sqlx::Error> {
    sqlx::query_as::<_, SocIncidentRecord>(
        "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at
         FROM soc_incidents
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(incident_id)
    .fetch_optional(pool)
    .await
}

/// Close a SOC incident — flip its lifecycle status from `'open'` to `'closed'`
/// and stamp `closed_at` with the current RFC-3339 timestamp. Tenant-scoped and
/// parameterized (CWE-89 / CWE-284 safe). The `AND status != 'closed'` guard
/// makes the operation idempotent: a second close returns `false` without touching
/// the row, preserving the original `closed_at` timestamp.
///
/// Returns `true` if a row was updated (i.e. the incident existed, belonged to
/// this tenant, and was still open), `false` otherwise.
pub async fn close_soc_incident(
    pool: &SqlitePool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<bool, sqlx::Error> {
    let closed_at = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE soc_incidents
         SET status = 'closed', closed_at = ?
         WHERE tenant_id = ? AND id = ? AND status != 'closed'",
    )
    .bind(&closed_at)
    .bind(tenant_id)
    .bind(incident_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Aggregate SOC counts for a tenant — all in one call for the `/v1/soc/summary`
/// endpoint. Every COUNT query binds `tenant_id` first (CWE-284); all SQL strings
/// are static (CWE-89). `alerts_high` counts only alerts with `severity = 'high'`;
/// `incidents_open` / `incidents_closed` use the lifecycle `status` column.
pub async fn soc_summary(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<crate::models::SocSummary, sqlx::Error> {
    let (alerts_total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM soc_alerts WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let (alerts_high,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM soc_alerts WHERE tenant_id = ? AND severity = 'high'")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let (incidents_total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let (incidents_open,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = ? AND status = 'open'",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    let (incidents_closed,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = ? AND status = 'closed'",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    Ok(crate::models::SocSummary {
        alerts_total,
        alerts_high,
        incidents_total,
        incidents_open,
        incidents_closed,
    })
}

/// Quarantine an MCP server — all its tools become deny-by-default.
/// Sets `status = 'quarantined'` on the server; the authorize path checks this.
pub async fn set_mcp_server_status(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE mcp_servers SET status = ?
         WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(server_key)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_mcp_servers(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<McpServerRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpServerRecord>(
        "SELECT * FROM mcp_servers WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn update_mcp_server(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    name: Option<&str>,
    owner_team: Option<Option<&str>>,
    transport: Option<&str>,
    source: Option<Option<&str>>,
    trust_level: Option<&str>,
    endpoint: Option<&str>,
    status: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let mut query_str = "UPDATE mcp_servers SET ".to_string();
    let mut bindings = Vec::new();

    if let Some(n) = name {
        query_str.push_str("name = ?, ");
        bindings.push(Some(n.to_string()));
    }
    if let Some(ot) = owner_team {
        query_str.push_str("owner_team = ?, ");
        bindings.push(ot.map(|s| s.to_string()));
    }
    if let Some(t) = transport {
        query_str.push_str("transport = ?, ");
        bindings.push(Some(t.to_string()));
    }
    if let Some(s) = source {
        query_str.push_str("source = ?, ");
        bindings.push(s.map(|v| v.to_string()));
    }
    if let Some(tl) = trust_level {
        query_str.push_str("trust_level = ?, ");
        bindings.push(Some(tl.to_string()));
    }
    if let Some(ep) = endpoint {
        query_str.push_str("endpoint = ?, ");
        bindings.push(Some(ep.to_string()));
    }
    if let Some(st) = status {
        query_str.push_str("status = ?, ");
        bindings.push(Some(st.to_string()));
    }

    if bindings.is_empty() {
        return Ok(false);
    }
    query_str.truncate(query_str.len() - 2);

    query_str.push_str(" WHERE tenant_id = ? AND server_key = ?");

    let mut q = sqlx::query(&query_str);
    for val in bindings {
        q = q.bind(val);
    }
    q = q.bind(tenant_id).bind(server_key);

    let result = q.execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_tenant_stats(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<crate::models::TenantStats, sqlx::Error> {
    let (total_decisions,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM decisions WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let (decisions_allow,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM decisions WHERE tenant_id = ? AND decision = 'allow'")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let (decisions_deny,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM decisions WHERE tenant_id = ? AND decision = 'deny'")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let (decisions_require_approval,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM decisions WHERE tenant_id = ? AND decision = 'require_approval'",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    let (total_agents,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents WHERE tenant_id = ?")
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

    let (total_receipts,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    Ok(crate::models::TenantStats {
        total_decisions,
        decisions_allow,
        decisions_deny,
        decisions_require_approval,
        total_agents,
        total_receipts,
    })
}

/// On-disk size of the SQLite database file in bytes (#949), computed as
/// `page_count * page_size` via the corresponding `PRAGMA`s.
pub async fn get_database_size_bytes(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let (page_count,): (i64,) = sqlx::query_as("PRAGMA page_count").fetch_one(pool).await?;
    let (page_size,): (i64,) = sqlx::query_as("PRAGMA page_size").fetch_one(pool).await?;
    Ok(page_count * page_size)
}

/// Row count for every user table in the database (#950), ordered by table
/// name. Reads table names from `sqlite_master`, excluding internal
/// `sqlite_*` tables.
pub async fn get_table_row_counts(
    pool: &SqlitePool,
) -> Result<Vec<crate::models::TableRowCount>, sqlx::Error> {
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    let mut counts = Vec::with_capacity(tables.len());
    for (table,) in tables {
        let query = format!("SELECT COUNT(*) FROM \"{}\"", table);
        let (row_count,): (i64,) = sqlx::query_as(&query).fetch_one(pool).await?;
        counts.push(crate::models::TableRowCount { table, row_count });
    }
    Ok(counts)
}

/// Combined database-level monitoring snapshot (#949, #950).
pub async fn get_db_stats(pool: &SqlitePool) -> Result<crate::models::DbStats, sqlx::Error> {
    let size_bytes = get_database_size_bytes(pool).await?;
    let tables = get_table_row_counts(pool).await?;
    Ok(crate::models::DbStats { size_bytes, tables })
}

/// Write a consistent point-in-time copy of the database to `dest_path`
/// (#945) using SQLite's `VACUUM INTO`, which also compacts the copy. The
/// live database is untouched and remains available throughout.
pub async fn backup_database_to(pool: &SqlitePool, dest_path: &str) -> Result<(), sqlx::Error> {
    sqlx::query("VACUUM INTO ?")
        .bind(dest_path)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    async fn setup_pool(test_name: &str) -> SqlitePool {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        init_db(&db_url).await.unwrap()
    }

    /// Minimal `sqlx::error::DatabaseError` impl for simulating SQLite error
    /// codes (e.g. SQLITE_BUSY = "5") in `retry_on_busy` tests, without
    /// needing a live locked connection.
    #[derive(Debug)]
    struct MockDbError {
        code: &'static str,
    }

    impl std::fmt::Display for MockDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock db error code {}", self.code)
        }
    }

    impl std::error::Error for MockDbError {}

    impl sqlx::error::DatabaseError for MockDbError {
        fn message(&self) -> &str {
            "mock db error"
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.code.into())
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn busy_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(MockDbError { code: "5" }))
    }

    /// #1151: `retry_on_busy` retries a transient SQLITE_BUSY error with
    /// exponential backoff and succeeds once the lock clears.
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
                    .fetch_optional(&pool)
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
            .fetch_one(&pool)
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
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "insert referencing a non-existent tenant must violate the FK constraint"
        );
    }

    /// #0106: rows older than the cutoff are moved to audit_events_archive
    /// and removed from audit_events; recent rows are untouched.
    #[tokio::test]
    async fn archive_audit_events_older_than_moves_old_rows() {
        let pool = setup_pool("audit_archival").await;
        register_tenant(&pool, "tenant_archive", "Archive Tenant", "developer")
            .await
            .unwrap();

        let old_event = AuditEventRecord {
            id: "evt_old".to_string(),
            tenant_id: "tenant_archive".to_string(),
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
            created_at: Utc::now(),
        };
        let new_event = AuditEventRecord {
            id: "evt_new".to_string(),
            ..old_event.clone()
        };
        insert_audit_event(&pool, &old_event).await.unwrap();
        insert_audit_event(&pool, &new_event).await.unwrap();

        // Backdate evt_old so it falls before the cutoff.
        sqlx::query(
            "UPDATE audit_events SET created_at = '2000-01-01T00:00:00Z' WHERE id = 'evt_old'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let cutoff = Utc::now() - chrono::Duration::days(1);
        let archived = archive_audit_events_older_than(&pool, cutoff)
            .await
            .unwrap();
        assert_eq!(archived, 1);

        let remaining: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_events WHERE id = 'evt_old'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining.0, 0);

        let archived_row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_events_archive WHERE id = 'evt_old'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(archived_row.0, 1);

        let still_present: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_events WHERE id = 'evt_new'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(still_present.0, 1);
    }

    /// #949, #950: `get_db_stats` reports a non-zero on-disk database size
    /// and a row count entry for every core table, with `tenants` reflecting
    /// the one tenant registered below.
    #[tokio::test]
    async fn get_db_stats_reports_size_and_table_row_counts() {
        let pool = setup_pool("db_stats").await;
        register_tenant(&pool, "tenant_dbstats", "DB Stats Tenant", "developer")
            .await
            .unwrap();

        let stats = get_db_stats(&pool).await.unwrap();
        assert!(stats.size_bytes > 0);

        let tenants = stats
            .tables
            .iter()
            .find(|t| t.table == "tenants")
            .expect("tenants table present in db-stats");
        assert_eq!(tenants.row_count, 1);

        // Sanity-check a couple of other core tables are present.
        assert!(stats.tables.iter().any(|t| t.table == "decisions"));
        assert!(stats.tables.iter().any(|t| t.table == "approvals"));
    }

    /// #945: `backup_database_to` writes a consistent point-in-time copy of
    /// the database via `VACUUM INTO`. The copy is a standalone, openable
    /// SQLite file containing the same tenant rows as the live database.
    #[tokio::test]
    async fn backup_database_to_writes_openable_copy() {
        let pool = setup_pool("db_backup").await;
        register_tenant(&pool, "tenant_backup", "Backup Tenant", "developer")
            .await
            .unwrap();

        let dest_path = format!("target/backup_{}.db", Uuid::new_v4().simple());
        // VACUUM INTO refuses to overwrite an existing file.
        let _ = std::fs::remove_file(&dest_path);

        backup_database_to(&pool, &dest_path).await.unwrap();

        assert!(std::path::Path::new(&dest_path).exists());

        let backup_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&format!("sqlite://{}", dest_path))
            .await
            .unwrap();
        let tenants: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM tenants WHERE id = 'tenant_backup'")
                .fetch_all(&backup_pool)
                .await
                .unwrap();
        assert_eq!(tenants.len(), 1);

        backup_pool.close().await;
        let _ = std::fs::remove_file(&dest_path);
    }

    /// #0105: `delete_expired_approvals_older_than` removes approvals that are
    /// either already decided or pending-but-past-`expires_at`, as long as
    /// they were created before the cutoff. A still-pending, unexpired
    /// approval older than the cutoff is preserved (a reviewer might still
    /// act on it).
    #[tokio::test]
    async fn delete_expired_approvals_older_than_removes_stale_rows() {
        let pool = setup_pool("approval_cleanup").await;
        register_tenant(&pool, "tenant_cleanup", "Cleanup Tenant", "developer")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_cleanup', 'tenant_cleanup', 'agent_cleanup', 'token_cleanup', 'Cleanup Agent', 'dev', 'low', 'active')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let make_decision = |id: &str| DecisionRecord {
            id: id.to_string(),
            tenant_id: "tenant_cleanup".to_string(),
            agent_id: "agent_cleanup".to_string(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: None,
            input_json: "{}".to_string(),
            decision: "require_approval".to_string(),
            risk_score: Some(75),
            reason: None,
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            created_at: Utc::now(),
        };

        for id in [
            "dec_old_decided",
            "dec_old_expired",
            "dec_old_pending",
            "dec_new_decided",
        ] {
            insert_decision(&pool, &make_decision(id)).await.unwrap();
        }

        let make_approval =
            |id: &str, decision_id: &str, status: &str, expires_at: Option<DateTime<Utc>>| {
                ApprovalRecord {
                    id: id.to_string(),
                    tenant_id: "tenant_cleanup".to_string(),
                    decision_id: decision_id.to_string(),
                    status: status.to_string(),
                    approver_group: None,
                    approver_user_id: None,
                    reason: None,
                    original_skill_call: "{}".to_string(),
                    original_call_hash: "sha256:deadbeef".to_string(),
                    edited_skill_call: None,
                    expires_at,
                    decided_at: None,
                    created_at: Utc::now(),
                }
            };

        // Old + already decided -> should be deleted.
        insert_approval(
            &pool,
            &make_approval("appr_old_decided", "dec_old_decided", "APPROVED", None),
        )
        .await
        .unwrap();
        // Old + still "created" but past expires_at -> should be deleted.
        insert_approval(
            &pool,
            &make_approval(
                "appr_old_expired",
                "dec_old_expired",
                "created",
                Some(Utc::now() - chrono::Duration::days(1)),
            ),
        )
        .await
        .unwrap();
        // Old + still "created" and not expired -> must be preserved.
        insert_approval(
            &pool,
            &make_approval(
                "appr_old_pending",
                "dec_old_pending",
                "created",
                Some(Utc::now() + chrono::Duration::days(1)),
            ),
        )
        .await
        .unwrap();
        // Recently decided -> must be preserved (not old enough).
        insert_approval(
            &pool,
            &make_approval("appr_new_decided", "dec_new_decided", "APPROVED", None),
        )
        .await
        .unwrap();

        // Backdate everything except appr_new_decided so they fall before the cutoff.
        for id in ["appr_old_decided", "appr_old_expired", "appr_old_pending"] {
            sqlx::query("UPDATE approvals SET created_at = '2000-01-01T00:00:00Z' WHERE id = ?")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        let cutoff = Utc::now() - chrono::Duration::days(30);
        let deleted = delete_expired_approvals_older_than(&pool, cutoff)
            .await
            .unwrap();
        assert_eq!(deleted, 2);

        let remaining: Vec<String> = sqlx::query_scalar("SELECT id FROM approvals ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, vec!["appr_new_decided", "appr_old_pending"]);
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
        run_migrations(&pool2).await.unwrap();
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

    #[tokio::test]
    async fn mcp_tool_manifest_defaults_to_pending_and_is_tenant_scoped() {
        let pool = setup_pool("mcp_manifest").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        let server_id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        let tool = McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create issue".to_string(),
            description: Some("Create a GitHub issue".to_string()),
            input_schema: Some(serde_json::json!({"type": "object"})),
            risk: "medium".to_string(),
            mutates_state: true,
            approval_required: false,
        };
        upsert_mcp_tool(&pool, "tenant_a", &server_id, &tool)
            .await
            .unwrap();

        let tools = list_mcp_tools(&pool, "tenant_a", "github-mcp")
            .await
            .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].tool_key, "create_issue");
        assert_eq!(tools[0].status, "pending");
        assert_eq!(tools[0].risk, "medium");
        assert!(tools[0].mutates_state);

        let other_tenant_tools = list_mcp_tools(&pool, "tenant_b", "github-mcp")
            .await
            .unwrap();
        assert!(other_tenant_tools.is_empty());
    }

    #[tokio::test]
    async fn mcp_tool_status_updates_are_tenant_scoped() {
        let pool = setup_pool("mcp_status").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        let server_id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        let tool = McpToolManifestItem {
            tool_key: "merge_pull_request".to_string(),
            name: "Merge pull request".to_string(),
            description: None,
            input_schema: None,
            risk: "critical".to_string(),
            mutates_state: true,
            approval_required: true,
        };
        upsert_mcp_tool(&pool, "tenant_a", &server_id, &tool)
            .await
            .unwrap();

        let missing = set_mcp_tool_status(
            &pool,
            "tenant_b",
            "github-mcp",
            "merge_pull_request",
            "approved",
        )
        .await
        .unwrap();
        assert!(!missing);

        let updated = set_mcp_tool_status(
            &pool,
            "tenant_a",
            "github-mcp",
            "merge_pull_request",
            "approved",
        )
        .await
        .unwrap();
        assert!(updated);

        let tool = get_mcp_tool_by_key(&pool, "tenant_a", "github-mcp", "merge_pull_request")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tool.status, "approved");
    }

    // ── SOC Phase 5 DB tests ─────────────────────────────────────────────────

    fn make_alert(id: &str, tenant_id: &str) -> SocAlertRecord {
        SocAlertRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            rule: "confused_deputy_block".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_x".to_string(),
            source_event_id: format!("evt_{}", id),
            summary: "Test alert summary".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn make_incident(id: &str, tenant_id: &str) -> SocIncidentRecord {
        SocIncidentRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_y".to_string(),
            summary: "Test incident summary".to_string(),
            source_event_ids: serde_json::json!(["evt_1", "evt_2"]).to_string(),
            opened_at: chrono::Utc::now().to_rfc3339(),
            // DB always sets 'open' on insert; these fields are in the struct to
            // satisfy the type but the INSERT ignores them (uses literal defaults).
            status: "open".to_string(),
            closed_at: None,
        }
    }

    #[tokio::test]
    async fn soc_alerts_are_tenant_scoped() {
        let pool = setup_pool("soc_alerts_tenant").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // Insert one alert per tenant.
        insert_soc_alert(&pool, &make_alert("alert_a1", "tenant_a"))
            .await
            .unwrap();
        insert_soc_alert(&pool, &make_alert("alert_b1", "tenant_b"))
            .await
            .unwrap();

        let a_alerts = list_soc_alerts(&pool, "tenant_a", SOC_DEFAULT_LIMIT, 0, None, None)
            .await
            .unwrap();
        assert_eq!(a_alerts.len(), 1, "tenant_a should see only its own alert");
        assert_eq!(a_alerts[0].id, "alert_a1");

        let b_alerts = list_soc_alerts(&pool, "tenant_b", SOC_DEFAULT_LIMIT, 0, None, None)
            .await
            .unwrap();
        assert_eq!(b_alerts.len(), 1, "tenant_b should see only its own alert");
        assert_eq!(b_alerts[0].id, "alert_b1");
    }

    #[tokio::test]
    async fn soc_alerts_pagination_limit_offset() {
        let pool = setup_pool("soc_alerts_pagination").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        // Insert 5 alerts.
        for i in 0..5u32 {
            insert_soc_alert(&pool, &make_alert(&format!("al_{}", i), "tenant_a"))
                .await
                .unwrap();
        }

        let page1 = list_soc_alerts(&pool, "tenant_a", 3, 0, None, None)
            .await
            .unwrap();
        assert_eq!(page1.len(), 3);
        let page2 = list_soc_alerts(&pool, "tenant_a", 3, 3, None, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);

        // Hard cap: requesting more than SOC_MAX_LIMIT must not exceed it.
        let all = list_soc_alerts(&pool, "tenant_a", SOC_MAX_LIMIT + 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(all.len(), 5); // only 5 exist
    }

    #[tokio::test]
    async fn soc_incidents_are_tenant_scoped() {
        let pool = setup_pool("soc_incidents_tenant").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_a1", "tenant_a"))
            .await
            .unwrap();
        insert_soc_incident(&pool, &make_incident("inc_b1", "tenant_b"))
            .await
            .unwrap();

        let a_incs = list_soc_incidents(&pool, "tenant_a", SOC_DEFAULT_LIMIT, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(a_incs.len(), 1);
        assert_eq!(a_incs[0].id, "inc_a1");

        let b_incs = list_soc_incidents(&pool, "tenant_b", SOC_DEFAULT_LIMIT, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(b_incs.len(), 1);
        assert_eq!(b_incs[0].id, "inc_b1");
    }

    #[tokio::test]
    async fn soc_incidents_pagination_limit_offset() {
        let pool = setup_pool("soc_incidents_pagination").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        for i in 0..4u32 {
            insert_soc_incident(&pool, &make_incident(&format!("inc_{}", i), "tenant_a"))
                .await
                .unwrap();
        }

        let page1 = list_soc_incidents(&pool, "tenant_a", 2, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);
        let page2 = list_soc_incidents(&pool, "tenant_a", 2, 2, None, None, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        let page3 = list_soc_incidents(&pool, "tenant_a", 2, 4, None, None, None)
            .await
            .unwrap();
        assert!(page3.is_empty());
    }

    #[tokio::test]
    async fn soc_alert_source_event_ids_stored_correctly() {
        let pool = setup_pool("soc_alert_fields").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let record = SocAlertRecord {
            id: "alert_fields".to_string(),
            tenant_id: "tenant_a".to_string(),
            rule: "critical_deny".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_z".to_string(),
            source_event_id: "evt_z123".to_string(),
            summary: "Critical deny detected".to_string(),
            created_at: "2026-06-06T12:00:00Z".to_string(),
        };
        insert_soc_alert(&pool, &record).await.unwrap();

        let alerts = list_soc_alerts(&pool, "tenant_a", 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "critical_deny");
        assert_eq!(alerts[0].source_event_id, "evt_z123");
        assert_eq!(alerts[0].severity, "high");
    }

    #[tokio::test]
    async fn soc_incident_source_event_ids_json_round_trip() {
        let pool = setup_pool("soc_incident_json").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let ids = vec!["evt_1", "evt_2", "evt_3"];
        let source_event_ids_json = serde_json::to_string(&ids).unwrap();
        let record = SocIncidentRecord {
            id: "inc_json".to_string(),
            tenant_id: "tenant_a".to_string(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_q".to_string(),
            summary: "Deny storm detected".to_string(),
            source_event_ids: source_event_ids_json.clone(),
            opened_at: "2026-06-06T12:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        insert_soc_incident(&pool, &record).await.unwrap();

        let incs = list_soc_incidents(&pool, "tenant_a", 10, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].source_event_ids, source_event_ids_json);
        let parsed: Vec<String> = serde_json::from_str(&incs[0].source_event_ids).unwrap();
        assert_eq!(parsed, ids);
    }

    // ── get_soc_incident tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn get_soc_incident_returns_row_for_owning_tenant() {
        let pool = setup_pool("get_incident_owner").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let record = make_incident("inc_get_a", "tenant_a");
        insert_soc_incident(&pool, &record).await.unwrap();

        let result = get_soc_incident(&pool, "tenant_a", "inc_get_a")
            .await
            .unwrap();
        assert!(result.is_some(), "owning tenant must get the incident");
        let fetched = result.unwrap();
        assert_eq!(fetched.id, "inc_get_a");
        assert_eq!(fetched.kind, "deny_storm");
        assert_eq!(fetched.agent_id, "agent_y");
    }

    #[tokio::test]
    async fn get_soc_incident_returns_none_for_different_tenant() {
        let pool = setup_pool("get_incident_isolation").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // Insert under tenant_a.
        let record = make_incident("inc_iso", "tenant_a");
        insert_soc_incident(&pool, &record).await.unwrap();

        // tenant_b must NOT be able to retrieve tenant_a's incident.
        let result = get_soc_incident(&pool, "tenant_b", "inc_iso")
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "tenant_b must not see tenant_a's incident"
        );
    }

    #[tokio::test]
    async fn get_soc_incident_returns_none_for_unknown_id() {
        let pool = setup_pool("get_incident_missing").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let result = get_soc_incident(&pool, "tenant_a", "nonexistent_id")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    // ── Phase 6: incident lifecycle tests ────────────────────────────────────

    /// `get_soc_incident` round-trips `status` and `closed_at` correctly.
    #[tokio::test]
    async fn get_soc_incident_round_trips_status_and_closed_at() {
        let pool = setup_pool("inc_lifecycle_roundtrip").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let record = make_incident("inc_rt", "tenant_a");
        insert_soc_incident(&pool, &record).await.unwrap();

        let fetched = get_soc_incident(&pool, "tenant_a", "inc_rt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.status, "open");
        assert!(
            fetched.closed_at.is_none(),
            "closed_at must be NULL on open incidents"
        );
    }

    /// `close_soc_incident` flips status to 'closed' for the owning tenant.
    #[tokio::test]
    async fn close_soc_incident_flips_status_for_owning_tenant() {
        let pool = setup_pool("inc_close_owner").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_close_a", "tenant_a"))
            .await
            .unwrap();

        let closed = close_soc_incident(&pool, "tenant_a", "inc_close_a")
            .await
            .unwrap();
        assert!(closed, "owning tenant must be able to close its incident");

        let fetched = get_soc_incident(&pool, "tenant_a", "inc_close_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.status, "closed");
        assert!(
            fetched.closed_at.is_some(),
            "closed_at must be set after closing"
        );
    }

    /// `close_soc_incident` is a no-op (returns false) for a different tenant —
    /// cross-tenant isolation guarantee (CWE-284).
    #[tokio::test]
    async fn close_soc_incident_is_noop_for_different_tenant() {
        let pool = setup_pool("inc_close_isolation").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_iso_close", "tenant_a"))
            .await
            .unwrap();

        // tenant_b must NOT be able to close tenant_a's incident.
        let result = close_soc_incident(&pool, "tenant_b", "inc_iso_close")
            .await
            .unwrap();
        assert!(!result, "tenant_b must not close tenant_a's incident");

        // The incident must remain open.
        let fetched = get_soc_incident(&pool, "tenant_a", "inc_iso_close")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.status, "open");
        assert!(fetched.closed_at.is_none());
    }

    /// A second `close_soc_incident` call on an already-closed incident is
    /// idempotent — it returns `false` and leaves `closed_at` unchanged.
    #[tokio::test]
    async fn close_soc_incident_is_idempotent() {
        let pool = setup_pool("inc_close_idempotent").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_idem", "tenant_a"))
            .await
            .unwrap();

        let first = close_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap();
        assert!(first, "first close must succeed");

        let first_fetch = get_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap()
            .unwrap();
        let first_closed_at = first_fetch.closed_at.clone().unwrap();

        // Second close must return false and not change the timestamp.
        let second = close_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap();
        assert!(!second, "second close must be a no-op");

        let second_fetch = get_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second_fetch.status, "closed");
        assert_eq!(
            second_fetch.closed_at.unwrap(),
            first_closed_at,
            "closed_at must not change on a second close"
        );
    }

    /// `list_soc_incidents` with `status_filter=Some("open")` only returns open
    /// incidents; `Some("closed")` only returns closed ones.
    #[tokio::test]
    async fn list_soc_incidents_status_filter_works() {
        let pool = setup_pool("inc_status_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_open_1", "tenant_a"))
            .await
            .unwrap();
        insert_soc_incident(&pool, &make_incident("inc_open_2", "tenant_a"))
            .await
            .unwrap();
        insert_soc_incident(&pool, &make_incident("inc_closed_1", "tenant_a"))
            .await
            .unwrap();

        // Close one of the three incidents.
        close_soc_incident(&pool, "tenant_a", "inc_closed_1")
            .await
            .unwrap();

        let open_list = list_soc_incidents(&pool, "tenant_a", 50, 0, Some("open"), None, None)
            .await
            .unwrap();
        assert_eq!(open_list.len(), 2, "only two incidents should be open");
        assert!(open_list.iter().all(|i| i.status == "open"));

        let closed_list = list_soc_incidents(&pool, "tenant_a", 50, 0, Some("closed"), None, None)
            .await
            .unwrap();
        assert_eq!(closed_list.len(), 1, "only one incident should be closed");
        assert_eq!(closed_list[0].id, "inc_closed_1");
        assert!(closed_list[0].closed_at.is_some());

        let all_list = list_soc_incidents(&pool, "tenant_a", 50, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(all_list.len(), 3, "unfiltered list must return all three");
    }

    // ── SOC query layer: severity/agent_id filter + soc_summary tests ─────────

    fn make_alert_with(
        id: &str,
        tenant_id: &str,
        severity: &str,
        agent_id: &str,
    ) -> SocAlertRecord {
        SocAlertRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            rule: "test_rule".to_string(),
            severity: severity.to_string(),
            agent_id: agent_id.to_string(),
            source_event_id: format!("evt_{}", id),
            summary: format!("Alert {} summary", id),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn make_incident_with(
        id: &str,
        tenant_id: &str,
        severity: &str,
        agent_id: &str,
    ) -> SocIncidentRecord {
        SocIncidentRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "deny_storm".to_string(),
            severity: severity.to_string(),
            agent_id: agent_id.to_string(),
            summary: format!("Incident {} summary", id),
            source_event_ids: serde_json::json!(["evt_a"]).to_string(),
            opened_at: chrono::Utc::now().to_rfc3339(),
            status: "open".to_string(),
            closed_at: None,
        }
    }

    /// `list_soc_alerts` with `severity=Some("high")` returns only high-severity
    /// alerts for the tenant — and never another tenant's rows.
    #[tokio::test]
    async fn list_soc_alerts_severity_filter_and_isolation() {
        let pool = setup_pool("alerts_severity_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // Tenant A: 2 high, 1 medium.
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a_h1", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a_h2", "tenant_a", "high", "agent_2"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a_m1", "tenant_a", "medium", "agent_1"),
        )
        .await
        .unwrap();
        // Tenant B: 1 high — must never appear in tenant_a results.
        insert_soc_alert(
            &pool,
            &make_alert_with("al_b_h1", "tenant_b", "high", "agent_x"),
        )
        .await
        .unwrap();

        let high_a = list_soc_alerts(&pool, "tenant_a", 50, 0, Some("high"), None)
            .await
            .unwrap();
        assert_eq!(high_a.len(), 2, "tenant_a must see exactly 2 high alerts");
        assert!(high_a.iter().all(|a| a.severity == "high"));
        assert!(
            high_a.iter().all(|a| a.tenant_id == "tenant_a"),
            "isolation: no tenant_b rows"
        );

        let medium_a = list_soc_alerts(&pool, "tenant_a", 50, 0, Some("medium"), None)
            .await
            .unwrap();
        assert_eq!(medium_a.len(), 1);
        assert_eq!(medium_a[0].id, "al_a_m1");

        let all_a = list_soc_alerts(&pool, "tenant_a", 50, 0, None, None)
            .await
            .unwrap();
        assert_eq!(
            all_a.len(),
            3,
            "unfiltered must return all 3 tenant_a alerts"
        );
    }

    /// `list_soc_alerts` with `agent_id=Some(...)` returns only alerts matching
    /// that agent — and never another tenant's rows.
    #[tokio::test]
    async fn list_soc_alerts_agent_id_filter_and_isolation() {
        let pool = setup_pool("alerts_agent_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        insert_soc_alert(
            &pool,
            &make_alert_with("al_a1", "tenant_a", "high", "agent_target"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a2", "tenant_a", "low", "agent_other"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_b1", "tenant_b", "high", "agent_target"),
        )
        .await
        .unwrap();

        let target_alerts = list_soc_alerts(&pool, "tenant_a", 50, 0, None, Some("agent_target"))
            .await
            .unwrap();
        assert_eq!(target_alerts.len(), 1);
        assert_eq!(target_alerts[0].id, "al_a1");
        assert_eq!(target_alerts[0].tenant_id, "tenant_a");

        // Combined severity + agent_id filter.
        let combined =
            list_soc_alerts(&pool, "tenant_a", 50, 0, Some("high"), Some("agent_target"))
                .await
                .unwrap();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].id, "al_a1");
    }

    /// `list_soc_incidents` with `severity` and `agent_id` filters returns only
    /// matching incidents for the tenant.
    #[tokio::test]
    async fn list_soc_incidents_severity_and_agent_filters() {
        let pool = setup_pool("incidents_filters").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        insert_soc_incident(
            &pool,
            &make_incident_with("inc_a_h1", "tenant_a", "high", "agent_alpha"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("inc_a_h2", "tenant_a", "high", "agent_beta"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("inc_a_l1", "tenant_a", "low", "agent_alpha"),
        )
        .await
        .unwrap();
        // Tenant B — must be isolated.
        insert_soc_incident(
            &pool,
            &make_incident_with("inc_b_h1", "tenant_b", "high", "agent_alpha"),
        )
        .await
        .unwrap();

        let high_a = list_soc_incidents(&pool, "tenant_a", 50, 0, None, Some("high"), None)
            .await
            .unwrap();
        assert_eq!(high_a.len(), 2);
        assert!(high_a.iter().all(|i| i.severity == "high"));
        assert!(high_a.iter().all(|i| i.tenant_id == "tenant_a"));

        let alpha_a = list_soc_incidents(&pool, "tenant_a", 50, 0, None, None, Some("agent_alpha"))
            .await
            .unwrap();
        assert_eq!(alpha_a.len(), 2);
        assert!(alpha_a.iter().all(|i| i.agent_id == "agent_alpha"));

        // Status + severity combined.
        let open_high =
            list_soc_incidents(&pool, "tenant_a", 50, 0, Some("open"), Some("high"), None)
                .await
                .unwrap();
        assert_eq!(open_high.len(), 2);
    }

    /// `soc_summary` returns correct tenant-scoped aggregate counts and excludes
    /// another tenant's data.
    #[tokio::test]
    async fn soc_summary_counts_are_correct_and_isolated() {
        let pool = setup_pool("soc_summary_counts").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // Tenant A: 3 alerts (2 high, 1 medium); 3 incidents (2 open, 1 closed).
        insert_soc_alert(
            &pool,
            &make_alert_with("sa1", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("sa2", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("sa3", "tenant_a", "medium", "agent_2"),
        )
        .await
        .unwrap();

        insert_soc_incident(
            &pool,
            &make_incident_with("si1", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("si2", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        let inc_to_close = make_incident_with("si3", "tenant_a", "low", "agent_2");
        insert_soc_incident(&pool, &inc_to_close).await.unwrap();
        close_soc_incident(&pool, "tenant_a", "si3").await.unwrap();

        // Tenant B: 1 alert, 1 incident — must not affect tenant_a counts.
        insert_soc_alert(
            &pool,
            &make_alert_with("sb1", "tenant_b", "high", "agent_x"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("sib1", "tenant_b", "high", "agent_x"),
        )
        .await
        .unwrap();

        let summary = soc_summary(&pool, "tenant_a").await.unwrap();
        assert_eq!(summary.alerts_total, 3);
        assert_eq!(summary.alerts_high, 2);
        assert_eq!(summary.incidents_total, 3);
        assert_eq!(summary.incidents_open, 2);
        assert_eq!(summary.incidents_closed, 1);

        // Tenant B summary must not be contaminated by tenant_a data.
        let b_summary = soc_summary(&pool, "tenant_b").await.unwrap();
        assert_eq!(b_summary.alerts_total, 1);
        assert_eq!(b_summary.incidents_total, 1);
        assert_eq!(b_summary.incidents_open, 1);
        assert_eq!(b_summary.incidents_closed, 0);
    }

    /// DB-005 (#1195): a fresh database is initialized at the current schema
    /// version.
    #[tokio::test]
    async fn fresh_db_is_stamped_with_current_schema_version() {
        let pool = setup_pool("schema_version_fresh").await;

        let version: i64 = sqlx::query_scalar("SELECT version FROM schema_meta WHERE id = 1")
            .fetch_one(&pool)
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
            .fetch_one(&pool)
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
            .execute(&pool)
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
            .execute(&pool)
            .await
            .unwrap();

        check_schema_version(&pool).await.unwrap();

        let version: i64 = sqlx::query_scalar("SELECT version FROM schema_meta WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }
}
