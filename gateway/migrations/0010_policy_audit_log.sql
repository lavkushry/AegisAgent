-- #1312: tamper-evident, append-only transparency log for policy changes.
--
-- Every create/update/delete/rollback of a `policies` row appends one entry
-- here. Entries are hash-chained like `action_receipts` (`entry_hash` covers
-- `prev_hash`, so the chain can be re-verified end-to-end and any edit or
-- deletion of a historical entry breaks the chain). Triggers make the table
-- append-only at the SQLite level: UPDATE/DELETE on this table always fails.
CREATE TABLE IF NOT EXISTS policy_audit_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  policy_id TEXT NOT NULL,
  policy_key TEXT NOT NULL,
  action TEXT NOT NULL,
  changed_by TEXT,
  body_hash TEXT NOT NULL,
  diff_summary TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policy_audit_log_tenant_created
  ON policy_audit_log(tenant_id, created_at);

CREATE TRIGGER IF NOT EXISTS policy_audit_log_no_update
BEFORE UPDATE ON policy_audit_log
BEGIN
  SELECT RAISE(ABORT, 'policy_audit_log is append-only: UPDATE not permitted');
END;

CREATE TRIGGER IF NOT EXISTS policy_audit_log_no_delete
BEFORE DELETE ON policy_audit_log
BEGIN
  SELECT RAISE(ABORT, 'policy_audit_log is append-only: DELETE not permitted');
END;
