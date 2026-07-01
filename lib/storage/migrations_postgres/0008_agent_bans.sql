-- Phase 2.4 (runtime control plane): first-class ban store. See the SQLite
-- 0029 migration. `is_banned` = status='active' AND revoked_at IS NULL AND
-- (expires_at IS NULL OR expires_at > now).
CREATE TABLE IF NOT EXISTS agent_bans (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    scope TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_bans_tenant_target ON agent_bans(tenant_id, target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_agent_bans_tenant_status ON agent_bans(tenant_id, status);
