-- #1142: explicit monotonic rowid for cursor pagination on policy_audit_log.
ALTER TABLE policy_audit_log ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;