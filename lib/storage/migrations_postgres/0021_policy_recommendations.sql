-- #1394: advisory policy recommendations from denied-action analysis (never auto-applied).
CREATE TABLE IF NOT EXISTS policy_recommendations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    agent_id        TEXT NOT NULL,
    tool_key        TEXT NOT NULL,
    action_key      TEXT NOT NULL,
    deny_count      INTEGER NOT NULL,
    window_days     INTEGER NOT NULL DEFAULT 30,
    sample_reason   TEXT,
    draft_cedar     TEXT NOT NULL,
    rationale       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    reviewer_note   TEXT,
    generated_at    TIMESTAMPTZ NOT NULL,
    advisor_agent   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_recommendations_tenant
    ON policy_recommendations (tenant_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_rec_pending_unique
    ON policy_recommendations (tenant_id, agent_id, tool_key, action_key)
    WHERE status = 'pending';