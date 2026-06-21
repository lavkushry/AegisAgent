-- #1301: link audit events to the authorization decision and (where
-- applicable) the approval they relate to, so operators/compliance can query
-- "every audit event for decision X" or "every audit event for approval Y".
ALTER TABLE audit_events ADD COLUMN decision_id TEXT;
ALTER TABLE audit_events ADD COLUMN approval_id TEXT;
ALTER TABLE audit_events_archive ADD COLUMN decision_id TEXT;
ALTER TABLE audit_events_archive ADD COLUMN approval_id TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_decision ON audit_events (tenant_id, decision_id);
