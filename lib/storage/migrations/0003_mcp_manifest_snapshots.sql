-- TASK-0090 (#936): historical audit trail of MCP tool-manifest snapshots.
--
-- `mcp_servers.manifest_hash` only stores the *current* pinned hash, so an
-- operator investigating a manifest-drift alert (`mcp_manifest_drift`) has no
-- record of what the manifest looked like before/after the change. This table
-- records one row per `POST /v1/mcp/servers/:server_key/tools` discovery call,
-- capturing the computed `mcp-manifest-1` hash and the raw discovered tool list
-- so drift can be diffed after the fact.
CREATE TABLE IF NOT EXISTS mcp_manifest_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  server_key TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mcp_manifest_snapshots_tenant_server
  ON mcp_manifest_snapshots(tenant_id, server_key, created_at);
