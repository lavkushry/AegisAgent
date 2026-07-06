-- Agent-to-MCP-server permission bindings (#1766, epic #1389).
CREATE TABLE IF NOT EXISTS agent_mcp_server_permissions (
    id          TEXT NOT NULL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    server_key  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, agent_id, server_key)
);

CREATE INDEX IF NOT EXISTS idx_agent_mcp_perms_agent ON agent_mcp_server_permissions(tenant_id, agent_id);