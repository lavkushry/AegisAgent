-- Phase 2.5 (runtime control plane): quarantine store. See the SQLite 0030
-- migration. is_quarantined = status='active' for (target_type, target_value).
CREATE TABLE IF NOT EXISTS quarantine_records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    incident_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP WITH TIME ZONE,
    released_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_target ON quarantine_records(tenant_id, target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_status ON quarantine_records(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_incident ON quarantine_records(tenant_id, incident_id);
