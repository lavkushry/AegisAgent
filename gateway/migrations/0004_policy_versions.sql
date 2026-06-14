-- TASK-0091 (#937): audit trail of Cedar policy versions.
--
-- `PUT /v1/policies/:id` (routes::update_policy) overwrites the `policies`
-- row in place after incrementing `version`, so the previous body is lost —
-- there is no way to see what a policy looked like before an edit. This
-- table archives the pre-update row on every `PUT /v1/policies/:id` call,
-- giving operators a history of every prior version for audit/rollback.
CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  policy_key TEXT NOT NULL,
  name TEXT NOT NULL,
  language TEXT NOT NULL,
  body TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_by TEXT,
  created_at DATETIME NOT NULL,
  archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant_policy
  ON policy_versions(tenant_id, policy_id, version);
