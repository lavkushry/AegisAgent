-- Phase 2.4 (runtime control plane): first-class ban store. A ban blocks a
-- target (agent / fingerprint / image_digest / mcp_server / tool /
-- destination_domain / destination_ip / prompt_hash / behavior_signature / ...)
-- at every enforcement point (before sandbox start, authorize, tool call, MCP
-- call, egress, credential issuance). `is_banned` is the hot lookup:
--   status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now)
-- NULL expires_at = permanent / until-manual-review. Tenant-scoped; every
-- ban/revoke carries an actor + reason for the audit/receipt trail.
CREATE TABLE IF NOT EXISTS agent_bans (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    -- run | agent | tenant | organization
    scope TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    -- active | revoked
    status TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    revoked_at DATETIME,
    revoked_by TEXT
);
-- Hot enforcement lookup by target.
CREATE INDEX IF NOT EXISTS idx_agent_bans_tenant_target ON agent_bans(tenant_id, target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_agent_bans_tenant_status ON agent_bans(tenant_id, status);
