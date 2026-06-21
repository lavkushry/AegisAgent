use super::hash_token;
use aegis_api::models::*;
use chrono::Utc;
use sqlx::SqlitePool;

/// Row shape for `tenant_risk_weights`, matching [`aegis_api::models::RiskWeights`]'s
/// field order. Factored out to satisfy `clippy::type_complexity`.
type RiskWeightsRow = (i32, i32, i32, i32, i32, i32, i32, i32, i32, i32);

/// #1289: read per-tenant composite-risk-score weights, falling back to
/// [`aegis_api::models::RiskWeights::from_env`] when no override row exists.
/// Tenant-scoped, parameterized.
pub async fn get_risk_weights(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<aegis_api::models::RiskWeights, sqlx::Error> {
    let row: Option<RiskWeightsRow> = sqlx::query_as(
        "SELECT environment_weight_mutating,
                context_trust_penalty_trusted_internal_signed,
                context_trust_penalty_trusted_internal_unsigned,
                context_trust_penalty_semi_trusted_customer,
                context_trust_penalty_untrusted_external,
                context_trust_penalty_malicious_suspected,
                context_trust_penalty_unknown,
                mcp_trust_penalty,
                anomaly_weight_pct,
                approval_credit
         FROM tenant_risk_weights WHERE tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        Some((
            environment_weight_mutating,
            context_trust_penalty_trusted_internal_signed,
            context_trust_penalty_trusted_internal_unsigned,
            context_trust_penalty_semi_trusted_customer,
            context_trust_penalty_untrusted_external,
            context_trust_penalty_malicious_suspected,
            context_trust_penalty_unknown,
            mcp_trust_penalty,
            anomaly_weight_pct,
            approval_credit,
        )) => aegis_api::models::RiskWeights {
            environment_weight_mutating,
            context_trust_penalty_trusted_internal_signed,
            context_trust_penalty_trusted_internal_unsigned,
            context_trust_penalty_semi_trusted_customer,
            context_trust_penalty_untrusted_external,
            context_trust_penalty_malicious_suspected,
            context_trust_penalty_unknown,
            mcp_trust_penalty,
            anomaly_weight_pct,
            approval_credit,
        },
        None => aegis_api::models::RiskWeights::from_env(),
    })
}

/// #1289: upsert per-tenant composite-risk-score weight overrides.
/// Tenant-scoped, parameterized.
pub async fn upsert_risk_weights(
    pool: &SqlitePool,
    tenant_id: &str,
    weights: &aegis_api::models::RiskWeights,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tenant_risk_weights (
            tenant_id,
            environment_weight_mutating,
            context_trust_penalty_trusted_internal_signed,
            context_trust_penalty_trusted_internal_unsigned,
            context_trust_penalty_semi_trusted_customer,
            context_trust_penalty_untrusted_external,
            context_trust_penalty_malicious_suspected,
            context_trust_penalty_unknown,
            mcp_trust_penalty,
            anomaly_weight_pct,
            approval_credit
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id) DO UPDATE SET
            environment_weight_mutating = excluded.environment_weight_mutating,
            context_trust_penalty_trusted_internal_signed = excluded.context_trust_penalty_trusted_internal_signed,
            context_trust_penalty_trusted_internal_unsigned = excluded.context_trust_penalty_trusted_internal_unsigned,
            context_trust_penalty_semi_trusted_customer = excluded.context_trust_penalty_semi_trusted_customer,
            context_trust_penalty_untrusted_external = excluded.context_trust_penalty_untrusted_external,
            context_trust_penalty_malicious_suspected = excluded.context_trust_penalty_malicious_suspected,
            context_trust_penalty_unknown = excluded.context_trust_penalty_unknown,
            mcp_trust_penalty = excluded.mcp_trust_penalty,
            anomaly_weight_pct = excluded.anomaly_weight_pct,
            approval_credit = excluded.approval_credit",
    )
    .bind(tenant_id)
    .bind(weights.environment_weight_mutating)
    .bind(weights.context_trust_penalty_trusted_internal_signed)
    .bind(weights.context_trust_penalty_trusted_internal_unsigned)
    .bind(weights.context_trust_penalty_semi_trusted_customer)
    .bind(weights.context_trust_penalty_untrusted_external)
    .bind(weights.context_trust_penalty_malicious_suspected)
    .bind(weights.context_trust_penalty_unknown)
    .bind(weights.mcp_trust_penalty)
    .bind(weights.anomaly_weight_pct)
    .bind(weights.approval_credit)
    .execute(pool)
    .await?;
    Ok(())
}

/// #1296: read per-tenant risk-escalation thresholds, falling back to
/// [`aegis_api::models::RiskEscalationConfig::default`] when no override
/// row exists. Tenant-scoped, parameterized.
pub async fn get_risk_escalation_config(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<aegis_api::models::RiskEscalationConfig, sqlx::Error> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT denial_threshold, window_minutes FROM tenant_risk_escalation_config WHERE tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        Some((denial_threshold, window_minutes)) => aegis_api::models::RiskEscalationConfig {
            denial_threshold,
            window_minutes,
        },
        None => aegis_api::models::RiskEscalationConfig::default(),
    })
}

/// #1296: upsert per-tenant risk-escalation thresholds. Tenant-scoped, parameterized.
pub async fn upsert_risk_escalation_config(
    pool: &SqlitePool,
    tenant_id: &str,
    config: &aegis_api::models::RiskEscalationConfig,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tenant_risk_escalation_config (tenant_id, denial_threshold, window_minutes)
         VALUES (?, ?, ?)
         ON CONFLICT(tenant_id) DO UPDATE SET
            denial_threshold = excluded.denial_threshold,
            window_minutes = excluded.window_minutes",
    )
    .bind(tenant_id)
    .bind(config.denial_threshold)
    .bind(config.window_minutes)
    .execute(pool)
    .await?;
    Ok(())
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

/// TASK-0093 (#939): create a tenant-managed API key. The plaintext key is
/// returned exactly once (caller must surface it to the user); only
/// `sha256(key)` is persisted, mirroring `hash_token` / `agents.agent_token`.
pub async fn create_api_key(
    pool: &SqlitePool,
    tenant_id: &str,
    name: &str,
) -> Result<(String, String), sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let key = format!(
        "aegis_key_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let key_hash = hash_token(&key);

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, key_hash, name, status) \
         VALUES (?, ?, ?, ?, 'active')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(&key_hash)
    .bind(name)
    .execute(pool)
    .await?;

    Ok((id, key))
}

/// TASK-0093 (#939): list a tenant's API keys, most recent first. `key_hash`
/// is included (it is not a secret); the plaintext key is never persisted.
pub async fn list_api_keys(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<ApiKeyRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeyRecord>(
        "SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

/// #1307 (AC#4): check whether `key_hash` matches an `active` API key for
/// `tenant_id`. Used by the approval-callback rate limiters to grant a
/// bypass for trusted automation holding a tenant-scoped API key (the
/// closest existing analogue to an "admin token" in this codebase — see
/// `create_api_key` / #939). Tenant-scoped and parameterized; fails closed
/// (returns `false`) for any non-`active` or unknown hash.
pub async fn is_active_api_key(
    pool: &SqlitePool,
    tenant_id: &str,
    key_hash: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT 1 FROM api_keys WHERE tenant_id = ? AND key_hash = ? AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(key_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// TASK-0093 (#939): revoke a tenant's API key. Returns `true` if a row was
/// updated.
pub async fn revoke_api_key(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE api_keys SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP \
         WHERE tenant_id = ? AND id = ? AND status != 'revoked'",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// All tenant IDs, for jobs (e.g. the receipt chain integrity check, #0107)
/// that must run per-tenant rather than globally.
pub async fn list_all_tenant_ids(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT id FROM tenants")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
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

/// Resolves the SOC Response Engine's autonomy level (#1185, SOC-002) for
/// `tenant_id`:
///
/// - `L0` — log only: no notify, no auto-respond.
/// - `L1` — notify only (default): decision/alert/incident notify as today,
///   but auto-respond is skipped.
/// - `L2` — notify + recommend: like `L1`, plus a logged "would respond
///   with..." recommendation (never executed).
/// - `L3` — auto-respond + notify: full Phase 4 behaviour (incl. auto-freeze
///   on `deny_storm`/`runaway`/`data_exfil_pattern`).
/// - `L4` — auto-respond + silent: Phase 4 actions execute, but the
///   resulting notifications are suppressed.
///
/// Precedence: per-tenant `tenants.soc_autonomy_level` override (if set to a
/// recognised `L0`-`L4` value) > `AEGIS_SOC_AUTONOMY_LEVEL` env var (if set
/// to a recognised value) > default `"L1"`. An unrecognised value at either
/// level is ignored (falls through), keeping the default fail-safe.
pub async fn get_soc_autonomy_level(pool: &SqlitePool, tenant_id: &str) -> String {
    const LEVELS: [&str; 5] = ["L0", "L1", "L2", "L3", "L4"];

    let row: Result<Option<(Option<String>,)>, sqlx::Error> =
        sqlx::query_as("SELECT soc_autonomy_level FROM tenants WHERE id = ?")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await;

    if let Ok(Some((Some(level),))) = row {
        let upper = level.to_uppercase();
        if LEVELS.contains(&upper.as_str()) {
            return upper;
        }
    }

    if let Ok(level) = std::env::var("AEGIS_SOC_AUTONOMY_LEVEL") {
        let upper = level.to_uppercase();
        if LEVELS.contains(&upper.as_str()) {
            return upper;
        }
    }

    "L1".to_string()
}

pub async fn get_tenant_stats(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<aegis_api::models::TenantStats, sqlx::Error> {
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

    // #1294: per-trust-level breakdown for the dashboard's Trust Level
    // Distribution chart. COALESCE groups pre-#1293 rows (NULL
    // root_trust_level) under "unknown" rather than leaving a NULL group key.
    let trust_level_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(root_trust_level, 'unknown') AS trust_level, COUNT(*) AS count \
         FROM decisions WHERE tenant_id = ? GROUP BY trust_level",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    let trust_level_breakdown = trust_level_rows
        .into_iter()
        .map(|(trust_level, count)| aegis_api::models::TrustLevelCount { trust_level, count })
        .collect();

    Ok(aegis_api::models::TenantStats {
        total_decisions,
        decisions_allow,
        decisions_deny,
        decisions_require_approval,
        total_agents,
        total_receipts,
        trust_level_breakdown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use crate::db::*;
    use uuid::Uuid;

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

    #[tokio::test]
    async fn upsert_soc_incident_does_not_merge_across_tenants_or_kinds() {
        let _guard = DEDUP_ENV_LOCK.lock().await;
        std::env::remove_var("AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS");

        let pool = setup_pool("upsert_no_merge").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        let first = make_incident("inc_a", "tenant_a");
        assert_eq!(
            upsert_soc_incident(&pool, &first).await.unwrap(),
            IncidentUpsertResult::Inserted
        );

        // Different tenant — must not merge.
        let other_tenant = make_incident("inc_b", "tenant_b");
        assert_eq!(
            upsert_soc_incident(&pool, &other_tenant).await.unwrap(),
            IncidentUpsertResult::Inserted
        );

        // Same tenant/agent, different kind — must not merge.
        let mut other_kind = make_incident("inc_c", "tenant_a");
        other_kind.kind = "runaway".to_string();
        assert_eq!(
            upsert_soc_incident(&pool, &other_kind).await.unwrap(),
            IncidentUpsertResult::Inserted
        );

        let a_incs = list_soc_incidents(&pool, "tenant_a", SOC_DEFAULT_LIMIT, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(a_incs.len(), 2);
    }

    #[tokio::test]
    async fn list_approvals_by_decision_ids_returns_only_matching_tenant_scoped_rows() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        register_tenant(&pool, "tenant_graph_perf", "Graph Perf Tenant", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_other", "Other Tenant", "developer")
            .await
            .unwrap();
        sqlx::query(
                "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
                 VALUES ('agent_graph_perf', 'tenant_graph_perf', 'agent_graph_perf', 'token_graph_perf', 'Graph Perf Agent', 'dev', 'low', 'active')",
            )
            .execute(&pool)
            .await
            .unwrap();

        insert_decision(&pool, &graph_perf_decision("dec_1", "tenant_graph_perf"))
            .await
            .unwrap();
        insert_decision(&pool, &graph_perf_decision("dec_2", "tenant_graph_perf"))
            .await
            .unwrap();
        insert_decision(&pool, &graph_perf_decision("dec_3", "tenant_graph_perf"))
            .await
            .unwrap();

        insert_approval(
            &pool,
            &graph_perf_approval("appr_1", "tenant_graph_perf", "dec_1"),
        )
        .await
        .unwrap();
        insert_approval(
            &pool,
            &graph_perf_approval("appr_2", "tenant_graph_perf", "dec_2"),
        )
        .await
        .unwrap();
        // Cross-tenant approval on the same decision_id string must never leak in.
        insert_approval(
            &pool,
            &graph_perf_approval("appr_x", "tenant_other", "dec_1"),
        )
        .await
        .unwrap();

        let ids = vec![
            "dec_1".to_string(),
            "dec_2".to_string(),
            "dec_3".to_string(),
        ];
        let map = list_approvals_by_decision_ids(&pool, "tenant_graph_perf", &ids)
            .await
            .unwrap();

        assert_eq!(map.len(), 2);
        assert_eq!(map.get("dec_1").unwrap().id, "appr_1");
        assert_eq!(map.get("dec_2").unwrap().id, "appr_2");
        assert!(!map.contains_key("dec_3"));
    }

    #[tokio::test]
    async fn list_action_receipts_by_decision_ids_returns_only_matching_tenant_scoped_rows() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        register_tenant(&pool, "tenant_graph_perf", "Graph Perf Tenant", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_other", "Other Tenant", "developer")
            .await
            .unwrap();
        sqlx::query(
                "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
                 VALUES ('agent_graph_perf', 'tenant_graph_perf', 'agent_graph_perf', 'token_graph_perf', 'Graph Perf Agent', 'dev', 'low', 'active')",
            )
            .execute(&pool)
            .await
            .unwrap();

        insert_decision(&pool, &graph_perf_decision("dec_1", "tenant_graph_perf"))
            .await
            .unwrap();
        insert_decision(&pool, &graph_perf_decision("dec_2", "tenant_graph_perf"))
            .await
            .unwrap();

        insert_test_receipt(
            &pool,
            &graph_perf_receipt("recv_1", "tenant_graph_perf", "dec_1"),
        )
        .await;
        // Cross-tenant receipt on the same decision_id string must never leak in.
        insert_test_receipt(
            &pool,
            &graph_perf_receipt("recv_x", "tenant_other", "dec_1"),
        )
        .await;

        let ids = vec!["dec_1".to_string(), "dec_2".to_string()];
        let map = list_action_receipts_by_decision_ids(&pool, "tenant_graph_perf", &ids)
            .await
            .unwrap();

        assert_eq!(map.len(), 1);
        assert_eq!(map.get("dec_1").unwrap().id, "recv_1");
        assert!(!map.contains_key("dec_2"));
    }

    /// #1294: `get_tenant_stats` groups decisions by `root_trust_level` for
    /// the dashboard's Trust Level Distribution chart. A `NULL`
    /// `root_trust_level` (pre-#1293 rows) groups under `"unknown"` rather
    /// than being dropped or panicking on a NULL group key.
    #[tokio::test]
    async fn get_tenant_stats_includes_trust_level_breakdown() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        register_tenant(
            &pool,
            "tenant_trust_breakdown",
            "Trust Breakdown Tenant",
            "developer",
        )
        .await
        .unwrap();
        sqlx::query(
                "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
                 VALUES ('agent_graph_perf', 'tenant_trust_breakdown', 'agent_graph_perf', 'token_trust_breakdown', 'Trust Breakdown Agent', 'dev', 'low', 'active')",
            )
            .execute(&pool)
            .await
            .unwrap();

        let mut signed = graph_perf_decision("dec_signed", "tenant_trust_breakdown");
        signed.root_trust_level = Some("trusted_internal_signed".to_string());
        insert_decision(&pool, &signed).await.unwrap();

        let mut untrusted = graph_perf_decision("dec_untrusted", "tenant_trust_breakdown");
        untrusted.root_trust_level = Some("untrusted_external".to_string());
        insert_decision(&pool, &untrusted).await.unwrap();

        let mut untrusted_2 = graph_perf_decision("dec_untrusted_2", "tenant_trust_breakdown");
        untrusted_2.root_trust_level = Some("untrusted_external".to_string());
        insert_decision(&pool, &untrusted_2).await.unwrap();

        // No root_trust_level set — must group under "unknown", not NULL.
        let legacy = graph_perf_decision("dec_legacy", "tenant_trust_breakdown");
        insert_decision(&pool, &legacy).await.unwrap();

        let stats = get_tenant_stats(&pool, "tenant_trust_breakdown")
            .await
            .unwrap();
        assert_eq!(stats.total_decisions, 4);

        let breakdown: std::collections::HashMap<String, i64> = stats
            .trust_level_breakdown
            .into_iter()
            .map(|t| (t.trust_level, t.count))
            .collect();
        assert_eq!(breakdown.get("trusted_internal_signed"), Some(&1));
        assert_eq!(breakdown.get("untrusted_external"), Some(&2));
        assert_eq!(breakdown.get("unknown"), Some(&1));
    }
}

/// Insert a tenant record.
pub async fn insert_tenant(pool: &SqlitePool, record: &TenantRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, auto_respond_enabled, auto_rotate_token_on_leak_enabled) \
         VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.name)
    .bind(&record.plan)
    .bind(record.auto_respond_enabled)
    .bind(record.auto_rotate_token_on_leak_enabled)
    .execute(pool)
    .await?;
    Ok(())
}

/// List all tenants.
pub async fn list_tenants(pool: &SqlitePool) -> Result<Vec<TenantRecord>, sqlx::Error> {
    sqlx::query_as::<_, TenantRecord>("SELECT * FROM tenants ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
}

/// Delete a tenant by ID, cascade deleting all other associated tables inside a transaction.
pub async fn delete_tenant_by_id(pool: &SqlitePool, tenant_id: &str) -> Result<bool, sqlx::Error> {
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM tenants WHERE id = ?")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

    if exists.is_none() {
        return Ok(false);
    }

    delete_tenant_data(pool, tenant_id).await?;
    Ok(true)
}

/// Set auto respond enable toggle for a tenant.
pub async fn set_tenant_auto_respond(
    pool: &SqlitePool,
    tenant_id: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE tenants SET auto_respond_enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set auto rotate token on leak toggle for a tenant.
pub async fn set_tenant_auto_rotate_token_on_leak(
    pool: &SqlitePool,
    tenant_id: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE tenants SET auto_rotate_token_on_leak_enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Fetch an API key record by id.
pub async fn get_api_key_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<ApiKeyRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeyRecord>("SELECT * FROM api_keys WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Insert an API key record.
pub async fn insert_api_key(pool: &SqlitePool, record: &ApiKeyRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, key_hash, name, status, created_at, revoked_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.key_hash)
    .bind(&record.name)
    .bind(&record.status)
    .bind(record.created_at)
    .bind(record.revoked_at)
    .execute(pool)
    .await?;
    Ok(())
}
