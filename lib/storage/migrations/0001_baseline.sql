-- DB-001 (#1191): baseline migration capturing the gateway's full schema as of
-- this migration's introduction (every table/column/index previously created by
-- the inline `run_migrations()` bootstrap, including all additive ALTER TABLE
-- columns that had accumulated via PRAGMA-guarded `ensure_*` helpers).
--
-- This migration is intentionally written with `IF NOT EXISTS` throughout so it
-- is a no-op on any database that was already brought to this schema by the
-- legacy bootstrap (`db::bootstrap_legacy_schema`, which still runs first on
-- every startup for backward compatibility — see db.rs). On a brand-new
-- database (legacy bootstrap also creates everything, so this remains a no-op
-- there too), this migration is what `sqlx::migrate!()` records in
-- `_sqlx_migrations`, establishing the baseline for all future migrations.
--
-- Going forward, schema changes are added as new numbered files in this
-- directory (`sqlx migrate add -r <name>`) and applied via `sqlx::migrate!()`
-- — no new `ensure_*`/PRAGMA helpers.

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auto_respond_enabled INTEGER NOT NULL DEFAULT 0,
    soc_autonomy_level TEXT
);

CREATE TABLE IF NOT EXISTS agents (
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
    quarantined_at DATETIME,
    frozen_reason TEXT,
    last_seen_at DATETIME,
    force_approval INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    UNIQUE (tenant_id, agent_key),
    UNIQUE (tenant_id, agent_token)
);

CREATE TABLE IF NOT EXISTS skills (
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
);

CREATE TABLE IF NOT EXISTS skill_actions (
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
);

CREATE TABLE IF NOT EXISTS mcp_servers (
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
    manifest_hash TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    UNIQUE (tenant_id, server_key)
);

CREATE TABLE IF NOT EXISTS mcp_tools (
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
);

CREATE TABLE IF NOT EXISTS policies (
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
);

CREATE TABLE IF NOT EXISTS decisions (
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
    request_id TEXT,
    latency_ms INTEGER,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS approvals (
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
    callback_url TEXT,
    callback_secret_hash TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (decision_id) REFERENCES decisions(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
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
);

-- #0106: archive table for old audit_events rows, identical schema (minus the
-- FK, since archived rows must outlive any later tenant deletion). Populated
-- by `archive_audit_events_older_than`.
CREATE TABLE IF NOT EXISTS audit_events_archive (
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
);
CREATE INDEX IF NOT EXISTS idx_audit_events_archive_tenant ON audit_events_archive (tenant_id);

CREATE TABLE IF NOT EXISTS action_receipts (
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
);

-- Tenant-scoped indexes (sub-millisecond tenant-partitioned lookups).
CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents (tenant_id);
CREATE INDEX IF NOT EXISTS idx_skills_tenant ON skills (tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers (tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tools_tenant_server ON mcp_tools (tenant_id, server_id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_decisions_tenant ON decisions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approvals (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant ON action_receipts (tenant_id);

-- Composite indexes matching hot tenant-scoped list/query paths so filtered +
-- `ORDER BY created_at DESC` listings stay index-driven.
-- (#940) list_decisions: WHERE tenant_id [AND agent_id] [AND decision] ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_decisions_tenant_agent_created ON decisions (tenant_id, agent_id, created_at);
-- (#941) list_pending_approvals: WHERE tenant_id AND status ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_status_created ON approvals (tenant_id, status, created_at);
-- (#942) audit_events: WHERE tenant_id [AND event_type] ORDER BY created_at
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_type_created ON audit_events (tenant_id, event_type, created_at);
-- (#943) list_action_receipts: WHERE tenant_id ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant_created ON action_receipts (tenant_id, created_at);

-- #0072: caller-supplied idempotency key on each decision. A repeat
-- `POST /v1/authorize` with the same `(tenant_id, agent_id, request_id)`
-- replays the original decision. The partial unique index only applies to
-- non-NULL request_ids.
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_tenant_agent_request_id
    ON decisions (tenant_id, agent_id, request_id)
    WHERE request_id IS NOT NULL;

-- ── Phase 5: SOC event indexer ───────────────────────────────────────────
-- soc_alerts: one persisted row per detection rule firing (detect::Alert).
-- Stores ids/summaries/hashes only — never raw payloads or secrets.
CREATE TABLE IF NOT EXISTS soc_alerts (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    rule            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    summary         TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_tenant ON soc_alerts (tenant_id);

-- soc_incidents: one persisted row per multi-event correlation incident
-- (correlate::Incident). source_event_ids is a JSON array of evidence ids.
-- `status` ('open'/'closed') and `closed_at` support the Phase 6 lifecycle.
CREATE TABLE IF NOT EXISTS soc_incidents (
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
);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_tenant ON soc_incidents (tenant_id);

-- DB-005 (#1195): single-row table tracking the schema version this DB was
-- last migrated to (separate from `_sqlx_migrations`, which tracks *which
-- migration files* have run — this tracks the binary-compatibility version
-- consumed by `db::check_schema_version`).
CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);

-- SOC-007 (#1190): per-(tenant, agent) hourly action counts, used as the
-- rolling 7-day baseline for the behavioral-anomaly rate check.
CREATE TABLE IF NOT EXISTS agent_hourly_action_counts (
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    hour_bucket  TEXT NOT NULL,
    action_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, agent_id, hour_bucket)
);

-- SOC-007 (#1190): every (tool, action) an agent has ever been observed
-- calling — used to detect "agent used a tool/action it has never used
-- before" (a deterministic, threshold-free anomaly signal).
CREATE TABLE IF NOT EXISTS agent_known_tool_actions (
    tenant_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    tool_key      TEXT NOT NULL,
    action_key    TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, tool_key, action_key)
);
