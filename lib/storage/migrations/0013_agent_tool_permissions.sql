-- Agent-to-tool permission bindings (#1390).
-- If any rows exist for an agent, only the listed tools may be called (fail-closed).
-- No rows = unrestricted (backwards-compatible with pre-#1390 agents).
CREATE TABLE agent_tool_permissions (
    id          TEXT NOT NULL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tool_key    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (tenant_id, agent_id, tool_key)
);

CREATE INDEX idx_agent_tool_perms_agent ON agent_tool_permissions(tenant_id, agent_id);
