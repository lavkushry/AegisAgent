-- #1627: tenant-scoped alerting settings (PostgreSQL).

CREATE TABLE IF NOT EXISTS soc_contact_points (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  channel_type TEXT NOT NULL,
  url TEXT,
  secret_hash TEXT,
  webhook_subscription_id TEXT,
  settings_json TEXT NOT NULL DEFAULT '{}',
  health_status TEXT NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  rowid BIGSERIAL UNIQUE,
  UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_soc_contact_points_tenant ON soc_contact_points(tenant_id);

CREATE TABLE IF NOT EXISTS soc_notification_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  matchers_json TEXT NOT NULL DEFAULT '{}',
  contact_point_ids_json TEXT NOT NULL DEFAULT '[]',
  group_by TEXT,
  repeat_interval_secs INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  rowid BIGSERIAL UNIQUE,
  UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_soc_notification_policies_tenant ON soc_notification_policies(tenant_id);

CREATE TABLE IF NOT EXISTS alert_silences (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rule_key TEXT,
  agent_id TEXT,
  comment TEXT,
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  created_by TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  rowid BIGSERIAL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_alert_silences_tenant ON alert_silences(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alert_silences_active ON alert_silences(tenant_id, status, ends_at);