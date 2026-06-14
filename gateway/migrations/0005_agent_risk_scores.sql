-- TASK-0089 (#935): historical record of the risk score computed for every
-- /v1/authorize decision, per agent. Gives operators a trend line of an
-- agent's risk over time (rather than only the latest decision's score).
CREATE TABLE IF NOT EXISTS agent_risk_scores (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  decision_id TEXT NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
  score INTEGER NOT NULL,
  reason TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agent_risk_scores_tenant_agent
  ON agent_risk_scores(tenant_id, agent_id, created_at);
