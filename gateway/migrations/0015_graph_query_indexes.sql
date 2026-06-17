-- #1316: evidence graph query optimization.
-- `add_decision_subgraph` looks up the approval and receipt linked to each
-- decision via `WHERE tenant_id = ? AND decision_id = ?`. Without an index on
-- `decision_id`, each lookup falls back to scanning every row for the tenant.
-- For a 50-decision agent-graph request this is up to 100 unindexed scans.
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_decision ON approvals (tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_tenant_decision ON action_receipts (tenant_id, decision_id);
