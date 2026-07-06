-- #1395: advisory threat hunt findings from proactive anomaly search (never enforcement).
CREATE TABLE IF NOT EXISTS threat_hunt_findings (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    finding_type    TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    title           TEXT NOT NULL,
    summary         TEXT NOT NULL,
    evidence_json   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',
    hunter_agent    TEXT NOT NULL,
    generated_at    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_findings_tenant
    ON threat_hunt_findings (tenant_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_hunt_open_unique
    ON threat_hunt_findings (tenant_id, agent_id, finding_type, fingerprint)
    WHERE status = 'open';