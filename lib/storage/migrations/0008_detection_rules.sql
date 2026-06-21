-- TASK-0088 (#934): tenant-managed detection rules. First step toward
-- SOC-003 (#1186): a YAML-driven detection rule DSL loaded from this table,
-- replacing the hardcoded Rust functions in `detect.rs`. `condition` and
-- `summary_template` hold the YAML rule body; `enabled` lets operators
-- disable a rule without deleting it.
CREATE TABLE IF NOT EXISTS detection_rules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rule_key TEXT NOT NULL,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  condition TEXT NOT NULL,
  summary_template TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, rule_key)
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant ON detection_rules(tenant_id);
