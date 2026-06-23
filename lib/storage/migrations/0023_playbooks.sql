-- [FEATURE] YAML Playbook DSL (#1292): tenant-managed response playbooks.
-- Playbooks map trigger incident conditions (kind, severity, and optionally agent_id/environment)
-- to automated containment steps (e.g. freeze agent, quarantine MCP server, notify channels).
CREATE TABLE IF NOT EXISTS response_playbooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  trigger_kind TEXT NOT NULL,
  trigger_severity TEXT NOT NULL, -- JSON array of severities, e.g. ["high", "critical"]
  trigger_agent_id TEXT,          -- Optional trigger filter for agent_id
  trigger_environment TEXT,       -- Optional trigger filter for environment
  steps_json TEXT NOT NULL,       -- JSON array of playbook steps
  enabled BOOLEAN NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_response_playbooks_tenant ON response_playbooks(tenant_id);
