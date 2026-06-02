use crate::models::*;
use chrono::Utc;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::str::FromStr;

pub async fn init_db(db_url: &str) -> Result<SqlitePool, sqlx::Error> {
    // Enforce WAL mode and busy timeout on pool initialization
    let connection_options = sqlx::sqlite::SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connection_options)
        .await?;

    // Run migrations
    run_migrations(&pool).await?;

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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );",
    )
    .execute(pool)
    .await?;

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

/// Atomically consume an APPROVED approval (single-use). Returns `true` only if
/// THIS call consumed it (one row updated); `false` if it was already consumed,
/// expired, not approved, or not found. The `consumed_at IS NULL` guard makes
/// concurrent double-consume safe — at most one UPDATE matches.
pub async fn consume_approval(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<bool, sqlx::Error> {
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

pub async fn get_agent_by_token(
    pool: &SqlitePool,
    tenant_id: &str,
    token: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND agent_token = ? AND status != 'quarantined'",
    )
    .bind(tenant_id)
    .bind(token)
    .fetch_optional(pool)
    .await
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
        "INSERT INTO decisions (id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
    .bind(&record.risk_score)
    .bind(&record.reason)
    .bind(&record.matched_policy_ids)
    .execute(pool)
    .await?;
    Ok(())
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
    .bind(&record.expires_at)
    .bind(&record.decided_at)
    .execute(pool)
    .await?;
    Ok(())
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

pub async fn insert_action_receipt(
    pool: &SqlitePool,
    record: &ActionReceiptRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
    .execute(pool)
    .await?;
    Ok(())
}

/// Latest receipt hash for a tenant (chain head). Uses rowid for insertion order.
pub async fn get_latest_receipt_hash(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT receipt_hash FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(hash,)| hash))
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
}
