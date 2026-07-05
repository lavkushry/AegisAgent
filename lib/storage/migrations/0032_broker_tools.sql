-- Phase 6.2 (tool broker): `broker_tools` — a broker tool binds a
-- tenant-visible `tool_name` to a connector type and an *opaque* credential
-- reference. The credential itself never lives in this table (or anywhere
-- the gateway can hand to an agent); `credential_ref` is resolved inside the
-- broker at execution time (Phase 6.1 `CredentialResolver`). Tenant-scoped;
-- `(tenant_id, tool_name)` is unique so registration is idempotent per name.
CREATE TABLE IF NOT EXISTS broker_tools (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL DEFAULT '[]',
    -- active | disabled. Execution fails closed on anything but 'active'.
    status TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_broker_tools_tenant_id ON broker_tools(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_broker_tools_tenant_tool_name
    ON broker_tools(tenant_id, tool_name);
