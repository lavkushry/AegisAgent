-- PostgreSQL baseline schema for AegisAgent gateway.
-- Consolidates all SQLite migrations up to playbooks.

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auto_respond_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    soc_autonomy_level TEXT,
    auto_rotate_token_on_leak_enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    quarantined_at TIMESTAMP WITH TIME ZONE,
    frozen_reason TEXT,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    force_approval BOOLEAN NOT NULL DEFAULT FALSE,
    signing_key TEXT,
    allowed_environments TEXT,
    mtls_cn TEXT,
    UNIQUE (tenant_id, agent_key),
    UNIQUE (tenant_id, agent_token)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

CREATE TABLE IF NOT EXISTS skills (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    skill_key TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    auth_type TEXT,
    owner_team TEXT,
    default_risk TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, skill_key)
);

CREATE TABLE IF NOT EXISTS skill_actions (
    id TEXT PRIMARY KEY,
    skill_id TEXT NOT NULL REFERENCES skills(id),
    action_key TEXT NOT NULL,
    description TEXT,
    risk TEXT NOT NULL,
    mutates_state BOOLEAN NOT NULL DEFAULT FALSE,
    data_access TEXT,
    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    default_decision TEXT NOT NULL DEFAULT 'policy',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (skill_id, action_key)
);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    server_key TEXT NOT NULL,
    name TEXT NOT NULL,
    owner_team TEXT,
    transport TEXT NOT NULL,
    source TEXT,
    trust_level TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    version TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    manifest_hash TEXT NOT NULL DEFAULT '',
    last_discovery_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (tenant_id, server_key)
);

CREATE TABLE IF NOT EXISTS mcp_tools (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    server_id TEXT NOT NULL REFERENCES mcp_servers(id),
    tool_key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    input_schema TEXT,
    risk TEXT NOT NULL,
    mutates_state BOOLEAN NOT NULL DEFAULT FALSE,
    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, server_id, tool_key)
);

CREATE TABLE IF NOT EXISTS mcp_manifest_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    server_id TEXT NOT NULL REFERENCES mcp_servers(id),
    manifest_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, server_id, manifest_hash)
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    policy_key TEXT NOT NULL,
    name TEXT NOT NULL,
    language TEXT NOT NULL,
    body TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (tenant_id, policy_key, version)
);

CREATE TABLE IF NOT EXISTS policy_versions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    policy_key TEXT NOT NULL,
    name TEXT NOT NULL,
    language TEXT NOT NULL,
    body TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    archived_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_audit_log (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    policy_id TEXT NOT NULL,
    policy_key TEXT NOT NULL,
    action TEXT NOT NULL,
    changed_by TEXT,
    body_hash TEXT NOT NULL,
    diff_summary TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rowid BIGSERIAL UNIQUE
);

CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    request_id TEXT,
    latency_ms INTEGER,
    composite_risk_score INTEGER,
    root_trust_level TEXT,
    parent_run_id TEXT,
    rowid BIGSERIAL UNIQUE
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    decision_id TEXT NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    approver_group TEXT,
    approver_user_id TEXT,
    reason TEXT,
    original_skill_call TEXT NOT NULL,
    original_call_hash TEXT NOT NULL DEFAULT '',
    edited_skill_call TEXT,
    effective_call_hash TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    decided_at TIMESTAMP WITH TIME ZONE,
    consumed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    callback_url TEXT,
    callback_secret_hash TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decision_id TEXT,
    approval_id TEXT,
    rowid BIGSERIAL UNIQUE
);

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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    archived_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decision_id TEXT,
    approval_id TEXT
);

CREATE TABLE IF NOT EXISTS action_receipts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
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
    signer_key_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rowid BIGSERIAL UNIQUE
);

CREATE TABLE IF NOT EXISTS agent_risk_scores (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
    decision_id TEXT NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    url TEXT NOT NULL,
    secret_hash TEXT,
    event_types TEXT NOT NULL DEFAULT '*',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivery_secret TEXT,
    min_severity TEXT NOT NULL DEFAULT 'info',
    format TEXT NOT NULL DEFAULT 'json',
    delivery_status TEXT NOT NULL DEFAULT 'healthy',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_delivery_at TIMESTAMP WITH TIME ZONE,
    last_success_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    rule_key TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    condition TEXT NOT NULL,
    summary_template TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, rule_key)
);

CREATE TABLE IF NOT EXISTS agent_tool_permissions (
    id          TEXT NOT NULL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tool_key    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (tenant_id, agent_id, tool_key)
);

CREATE TABLE IF NOT EXISTS audit_search_index (
    tenant_id TEXT NOT NULL,
    source_table TEXT NOT NULL,
    source_id TEXT NOT NULL,
    searchable_text TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS leader_lock (
    id TEXT NOT NULL PRIMARY KEY,
    holder_id TEXT NOT NULL,
    lease_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    acquired_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS response_playbooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  trigger_kind TEXT NOT NULL,
  trigger_severity TEXT NOT NULL,
  trigger_agent_id TEXT,
  trigger_environment TEXT,
  steps_json TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS soc_alerts (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    rule            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    summary         TEXT NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rowid           BIGSERIAL UNIQUE
);

CREATE TABLE IF NOT EXISTS soc_incidents (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    kind             TEXT NOT NULL,
    severity         TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    summary          TEXT NOT NULL,
    source_event_ids TEXT NOT NULL,
    opened_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status           TEXT NOT NULL DEFAULT 'open',
    closed_at        TIMESTAMP WITH TIME ZONE,
    rowid            BIGSERIAL UNIQUE
);

CREATE TABLE IF NOT EXISTS agent_hourly_action_counts (
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    hour_bucket  TEXT NOT NULL,
    action_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, agent_id, hour_bucket)
);

CREATE TABLE IF NOT EXISTS agent_known_tool_actions (
    tenant_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    tool_key      TEXT NOT NULL,
    action_key    TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, tool_key, action_key)
);

CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL PRIMARY KEY
);

-- Tenant-scoped indexes (sub-millisecond lookups).
CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents (tenant_id);
CREATE INDEX IF NOT EXISTS idx_skills_tenant ON skills (tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers (tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tools_tenant_server ON mcp_tools (tenant_id, server_id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_decisions_tenant ON decisions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approvals (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant ON action_receipts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_subs_tenant ON webhook_subscriptions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_risk_scores_tenant_agent ON agent_risk_scores (tenant_id, agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant_policy ON policy_versions (tenant_id, policy_id, version);
CREATE INDEX IF NOT EXISTS idx_agent_tool_perms_agent ON agent_tool_permissions(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_decision ON approvals (tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant_decision ON action_receipts (tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_decision ON audit_events (tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_log_tenant_created ON policy_audit_log (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_search_index_lookup ON audit_search_index (tenant_id, source_table, source_id);

-- Composite indexes.
CREATE INDEX IF NOT EXISTS idx_decisions_tenant_agent_created ON decisions (tenant_id, agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_status_created ON approvals (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_type_created ON audit_events (tenant_id, event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant_created ON action_receipts (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_response_playbooks_tenant ON response_playbooks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_tenant ON soc_alerts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_tenant ON soc_incidents (tenant_id);

-- Partial index for unique non-NULL request_id on decisions
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_tenant_agent_request_id
    ON decisions (tenant_id, agent_id, request_id)
    WHERE request_id IS NOT NULL;

-- Append-only triggers for policy_audit_log
CREATE OR REPLACE FUNCTION policy_audit_log_prevent_modify()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'policy_audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER policy_audit_log_no_update
BEFORE UPDATE ON policy_audit_log
FOR EACH ROW EXECUTE FUNCTION policy_audit_log_prevent_modify();

CREATE TRIGGER policy_audit_log_no_delete
BEFORE DELETE ON policy_audit_log
FOR EACH ROW EXECUTE FUNCTION policy_audit_log_prevent_modify();

-- FTS index triggers
CREATE OR REPLACE FUNCTION audit_events_fts_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_search_index (tenant_id, source_table, source_id, searchable_text)
  VALUES (
    NEW.tenant_id,
    'audit_events',
    NEW.id,
    COALESCE(NEW.event_type, '') || ' ' || COALESCE(NEW.skill, '') || ' ' ||
    COALESCE(NEW.action, '') || ' ' || COALESCE(NEW.resource, '') || ' ' ||
    COALESCE(NEW.agent_id, '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_fts_insert
AFTER INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION audit_events_fts_insert_fn();

CREATE OR REPLACE FUNCTION decisions_fts_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_search_index (tenant_id, source_table, source_id, searchable_text)
  VALUES (
    NEW.tenant_id,
    'decisions',
    NEW.id,
    COALESCE(NEW.skill, '') || ' ' || COALESCE(NEW.action, '') || ' ' ||
    COALESCE(NEW.resource, '') || ' ' || COALESCE(NEW.reason, '') || ' ' ||
    COALESCE(NEW.decision, '') || ' ' || COALESCE(NEW.agent_id, '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER decisions_fts_insert
AFTER INSERT ON decisions
FOR EACH ROW EXECUTE FUNCTION decisions_fts_insert_fn();
