-- Phase 2.2 (runtime control plane): high-volume runtime event log. See the
-- SQLite 0027 migration. `(tenant_id, event_id)` unique = idempotent ingest.
CREATE TABLE IF NOT EXISTS runtime_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    agent_id TEXT,
    run_id TEXT,
    sandbox_id TEXT,
    trace_id TEXT,
    parent_event_id TEXT,
    source_component TEXT NOT NULL,
    source_trust TEXT,
    decision TEXT,
    reason TEXT,
    action_hash TEXT,
    prompt_hash TEXT,
    request_hash TEXT,
    response_hash TEXT,
    receipt_id TEXT,
    receipt_hash TEXT,
    prev_receipt_hash TEXT,
    canonical_version TEXT,
    redaction_status TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_events_tenant_event ON runtime_events(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS idx_runtime_events_tenant_run ON runtime_events(tenant_id, run_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_runtime_events_tenant_trace ON runtime_events(tenant_id, trace_id);
