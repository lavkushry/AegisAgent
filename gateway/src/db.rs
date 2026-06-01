use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::str::FromStr;
use chrono::Utc;
use crate::models::*;

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
        );"
    ).execute(pool).await?;

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
        );"
    ).execute(pool).await?;

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
        );"
    ).execute(pool).await?;

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
        );"
    ).execute(pool).await?;

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
            version TEXT,
            status TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            UNIQUE (tenant_id, server_key)
        );"
    ).execute(pool).await?;

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
        );"
    ).execute(pool).await?;

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
        );"
    ).execute(pool).await?;

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
            edited_skill_call TEXT,
            expires_at DATETIME,
            decided_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id),
            FOREIGN KEY (decision_id) REFERENCES decisions(id)
        );"
    ).execute(pool).await?;

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
        );"
    ).execute(pool).await?;

    // Create indexes for tenant_id to guarantee sub-millisecond query performance
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents (tenant_id);").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_skills_tenant ON skills (tenant_id);").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers (tenant_id);").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_decisions_tenant ON decisions (tenant_id);").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approvals (tenant_id);").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events (tenant_id);").execute(pool).await?;

    Ok(())
}

// --- Multi-Tenant CRUD Operations ---

pub async fn get_tenant_by_id(pool: &SqlitePool, tenant_id: &str) -> Result<Option<TenantRecord>, sqlx::Error> {
    sqlx::query_as::<_, TenantRecord>("SELECT * FROM tenants WHERE id = ?")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
}

pub async fn register_tenant(pool: &SqlitePool, id: &str, name: &str, plan: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO tenants (id, name, plan) VALUES (?, ?, ?)")
        .bind(id)
        .bind(name)
        .bind(plan)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_agent_by_token(pool: &SqlitePool, token: &str) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>("SELECT * FROM agents WHERE agent_token = ? AND status != 'quarantined'")
        .bind(token)
        .fetch_optional(pool)
        .await
}

pub async fn get_agent_by_key(pool: &SqlitePool, tenant_id: &str, agent_key: &str) -> Result<Option<AgentRecord>, sqlx::Error> {
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

    let row: (String,) = sqlx::query_as("SELECT id FROM skills WHERE tenant_id = ? AND skill_key = ?")
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
         WHERE s.tenant_id = ? AND s.skill_key = ? AND sa.action_key = ?"
    )
    .bind(tenant_id)
    .bind(skill_key)
    .bind(action_key)
    .fetch_optional(pool)
    .await
}

pub async fn insert_decision(pool: &SqlitePool, record: &DecisionRecord) -> Result<(), sqlx::Error> {
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

pub async fn insert_approval(pool: &SqlitePool, record: &ApprovalRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO approvals (id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, edited_skill_call, expires_at, decided_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.decision_id)
    .bind(&record.status)
    .bind(&record.approver_group)
    .bind(&record.approver_user_id)
    .bind(&record.reason)
    .bind(&record.original_skill_call)
    .bind(&record.edited_skill_call)
    .bind(&record.expires_at)
    .bind(&record.decided_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_approval_by_id(pool: &SqlitePool, tenant_id: &str, approval_id: &str) -> Result<Option<ApprovalRecord>, sqlx::Error> {
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
         WHERE tenant_id = ? AND id = ?"
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

pub async fn insert_audit_event(pool: &SqlitePool, record: &AuditEventRecord) -> Result<(), sqlx::Error> {
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

pub async fn get_audit_events_by_run(pool: &SqlitePool, tenant_id: &str, run_id: &str) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    sqlx::query_as::<_, AuditEventRecord>("SELECT * FROM audit_events WHERE tenant_id = ? AND run_id = ? ORDER BY created_at ASC")
        .bind(tenant_id)
        .bind(run_id)
        .fetch_all(pool)
        .await
}

pub async fn get_all_audit_events(pool: &SqlitePool, tenant_id: &str) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    sqlx::query_as::<_, AuditEventRecord>("SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100")
        .bind(tenant_id)
        .fetch_all(pool)
        .await
}
