-- #1392: advisory investigation playbooks per incident (never enforcement).
CREATE TABLE IF NOT EXISTS investigation_playbooks (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    incident_id         TEXT NOT NULL,
    kind                TEXT NOT NULL,
    severity            TEXT NOT NULL,
    agent_id            TEXT NOT NULL,
    summary             TEXT NOT NULL,
    steps_json          TEXT NOT NULL,
    evidence_hints_json TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active',
    investigator_agent  TEXT NOT NULL,
    generated_at        TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (NOW()::TEXT),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_investigation_playbooks_tenant
    ON investigation_playbooks (tenant_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_investigation_playbook_per_incident
    ON investigation_playbooks (tenant_id, incident_id);