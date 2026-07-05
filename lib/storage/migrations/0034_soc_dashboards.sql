-- #1634: tenant-owned dashboard schemas for the in-app dashboard editor.
CREATE TABLE IF NOT EXISTS soc_dashboards (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  uid TEXT NOT NULL,
  title TEXT NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  schema_json TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, uid)
);

CREATE INDEX IF NOT EXISTS idx_soc_dashboards_tenant_id ON soc_dashboards(tenant_id);