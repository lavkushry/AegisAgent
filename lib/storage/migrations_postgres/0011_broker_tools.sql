-- Phase 6.2 (tool broker): broker tool registrations.
-- See the SQLite 0032 migration.
CREATE TABLE IF NOT EXISTS broker_tools (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_broker_tools_tenant_id ON broker_tools(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_broker_tools_tenant_tool_name
    ON broker_tools(tenant_id, tool_name);
