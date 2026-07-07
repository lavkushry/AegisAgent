-- Phase 7.1 (prompt/model capture): see the SQLite 0041 migration.
-- `(tenant_id, event_id)` unique = idempotent ingest.
CREATE TABLE IF NOT EXISTS prompt_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    run_id TEXT,
    trace_id TEXT,
    prompt_hash TEXT NOT NULL,
    redacted_prompt_preview TEXT,
    role TEXT,
    source_trust TEXT,
    model_provider TEXT,
    retention_policy TEXT,
    redaction_status TEXT NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_prompt_events_tenant_event ON prompt_events(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS idx_prompt_events_tenant_run ON prompt_events(tenant_id, run_id, created_at);
CREATE INDEX IF NOT EXISTS idx_prompt_events_tenant_trace ON prompt_events(tenant_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_prompt_events_tenant_prompt_hash ON prompt_events(tenant_id, prompt_hash);

CREATE TABLE IF NOT EXISTS model_call_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    run_id TEXT,
    trace_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    request_hash TEXT,
    response_hash TEXT,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    token_counts_json TEXT,
    status TEXT NOT NULL,
    redaction_status TEXT NOT NULL DEFAULT 'unknown',
    received_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_call_events_tenant_event ON model_call_events(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS idx_model_call_events_tenant_run ON model_call_events(tenant_id, run_id, received_at);
CREATE INDEX IF NOT EXISTS idx_model_call_events_tenant_trace ON model_call_events(tenant_id, trace_id);
