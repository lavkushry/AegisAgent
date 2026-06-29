-- Phase 2.1 (runtime control plane): the agent_run is the spine every runtime
-- event, control command, ban, and quarantine record references. One row per
-- controlled execution of an agent (known via SDK, or anonymous via the cage).
-- `agent_id` is NULL for anonymous/unknown agents; `policy_bundle_id` is NULL
-- until a versioned policy bundle is bound. Tenant-scoped; `run_key` is the
-- caller-stable idempotency key, unique per tenant.
CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT,
    run_key TEXT NOT NULL,
    source_component TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME,
    root_trace_id TEXT,
    root_trust_level TEXT,
    policy_bundle_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant_started ON agent_runs(tenant_id, started_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_runs_tenant_run_key ON agent_runs(tenant_id, run_key);
