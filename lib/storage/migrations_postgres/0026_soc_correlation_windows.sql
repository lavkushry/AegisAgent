-- #1210: shared correlation sliding windows across gateway replicas when the
-- Postgres backend is active. SQLite (single-instance) mode keeps its
-- existing in-process HashMap and never touches this table -- it exists
-- only so multiple Postgres-backed replicas observe the same window for a
-- given (tenant_id, agent_id) pair instead of each tracking its own.
CREATE TABLE IF NOT EXISTS soc_correlation_windows (
    tenant_id                TEXT NOT NULL REFERENCES tenants(id),
    agent_id                 TEXT NOT NULL,
    ts_secs                  BIGINT NOT NULL,
    event_id                 TEXT NOT NULL,
    decision                 TEXT NOT NULL,
    tool                     TEXT NOT NULL,
    action                   TEXT NOT NULL,
    exfil_paired             BOOLEAN NOT NULL DEFAULT FALSE,
    trust_escalation_paired  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_soc_correlation_windows_key
    ON soc_correlation_windows (tenant_id, agent_id);
