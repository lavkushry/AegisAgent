-- TASK-0093 (#939): tenant-managed API keys. Initial additive step toward
-- replacing the `tenant_<id>` bearer-token heuristic in the `TenantId`
-- extractor (routes.rs) with proper key-based authentication. Only the
-- SHA-256 hash of each key is stored; the plaintext key is returned exactly
-- once, at creation time (mirrors db::hash_token / agents.agent_token).
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  key_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  last_used_at DATETIME,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
