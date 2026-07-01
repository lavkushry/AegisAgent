-- Phase 2.5 (runtime control plane): quarantine store. Quarantine preserves
-- evidence while blocking further use of a target (agent / run / workspace /
-- file / mcp_server / tool / credential / destination / prompt_lineage). Unlike
-- a ban (which blocks), a quarantine also freezes the target for review and
-- attaches to an incident. `is_quarantined` is the enforcement lookup:
--   status='active' for the (target_type, target_value).
-- Lifecycle: active -> released | deleted (after admin review). Tenant-scoped;
-- every quarantine/release carries an actor + reason for the audit/receipt trail.
CREATE TABLE IF NOT EXISTS quarantine_records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    -- active | released | deleted
    status TEXT NOT NULL DEFAULT 'active',
    incident_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at DATETIME,
    released_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_target ON quarantine_records(tenant_id, target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_status ON quarantine_records(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_incident ON quarantine_records(tenant_id, incident_id);
