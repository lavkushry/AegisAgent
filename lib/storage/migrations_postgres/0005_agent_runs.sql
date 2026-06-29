-- Phase 2.1 (runtime control plane): one row per controlled agent execution.
-- See the SQLite 0026 migration. `agent_id` NULL for anonymous/cage runs.
CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT,
    run_key TEXT NOT NULL,
    source_component TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE,
    root_trace_id TEXT,
    root_trust_level TEXT,
    policy_bundle_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant_started ON agent_runs(tenant_id, started_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_runs_tenant_run_key ON agent_runs(tenant_id, run_key);
